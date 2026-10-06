"""File parsing, URL validation, and ingestion pipeline."""

import hashlib
import logging
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".md", ".txt", ".rst"}
BINARY_THRESHOLD = 0.10  # >10% non-printable = binary
MAX_TOKENS_PER_FILE = 50_000


def is_allowed_file(path: Path) -> bool:
    return path.suffix.lower() in ALLOWED_EXTENSIONS


def validate_repo_url(url: str, host_allowlist: list[str]) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.hostname in host_allowlist and parsed.scheme in ("https", "http")
    except Exception:
        return False


def is_binary(data: bytes) -> bool:
    if not data:
        return False
    non_printable = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
    return (non_printable / len(data)) > BINARY_THRESHOLD


def parse_file(path: Path, max_size: int) -> str | None:
    """Read a file, applying size/binary/encoding checks.

    Returns content string or None if file should be skipped.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None

    if size > max_size:
        log.warning("Skipping oversized file (%d bytes): %s", size, path)
        return None

    raw = path.read_bytes()
    if is_binary(raw):
        log.warning("Skipping binary file: %s", path)
        return None

    content = None
    for encoding in ("utf-8", "latin-1"):
        try:
            content = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue

    if content is None:
        log.warning("Skipping file with unsupported encoding: %s", path)
        return None

    words = content.split()
    if len(words) > MAX_TOKENS_PER_FILE:
        log.warning(
            "Truncating file at %d tokens: %s",
            MAX_TOKENS_PER_FILE,
            path,
        )
        content = " ".join(words[:MAX_TOKENS_PER_FILE])

    return content


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_repo_available(url: str, timeout: int = 15) -> tuple[bool, str]:
    """Probe a remote without cloning.

    Uses ``git ls-remote --heads`` which fetches only the refs list (no
    objects) and is the cheapest way to verify a repository is reachable and
    authorised. Returns ``(ok, detail)``. On failure ``detail`` is a short
    error string suitable for a status line.
    """
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "--exit-code", url],
            capture_output=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    except OSError as exc:
        return False, f"git error: {exc}"

    if result.returncode == 0:
        return True, "ok"
    stderr = (result.stderr or b"").decode("utf-8", errors="replace").strip()
    # Pick a short, one-line reason — ls-remote prints multi-line on 404.
    for line in stderr.splitlines():
        line = line.strip()
        if line and not line.startswith("remote:"):
            return False, line[:160]
    # Exit 2 from ls-remote --exit-code means "remote reachable, no refs"
    # (empty repo). Treat as unreachable for ingestion purposes.
    if result.returncode == 2:
        return False, "empty repo (no refs)"
    return False, f"git exit {result.returncode}"


def clone_repo(url: str, dest: Path, timeout: int = 120) -> bool:
    """Shallow clone a repo. Returns True on success."""
    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                url,
                str(dest),
            ],
            capture_output=True,
            timeout=timeout,
            check=True,
        )
        return True
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        log.error("Failed to clone %s: %s", url, exc)
        return False


def check_repo_size(path: Path, max_size_mb: int) -> bool:
    """Check if cloned repo exceeds max size. Returns True if within limit."""
    if max_size_mb <= 0:
        return True
    try:
        result = subprocess.run(
            ["du", "-sm", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        size_mb = int(result.stdout.split()[0])
        if size_mb > max_size_mb:
            log.warning(
                "Repo too large (%d MB > %d MB): %s",
                size_mb,
                max_size_mb,
                path,
            )
            return False
        return True
    except Exception as exc:
        log.error("Failed to check repo size: %s", exc)
        return True  # Allow on error


def walk_repo_files(repo_path: Path) -> list[Path]:
    """Walk repo for allowed files, skipping symlinks."""
    files = []
    for root, dirs, filenames in os.walk(repo_path, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in filenames:
            fp = Path(root) / name
            if fp.is_symlink():
                continue
            if is_allowed_file(fp):
                files.append(fp)
    return files


def ingest_directory(
    directory: Path,
    source_repo: str,
    db,
    embedder,
    vector_index,
    tagger_fn,
    max_file_size: int,
) -> dict:
    """Ingest all allowed files from a directory into the index.

    Returns stats dict with files_processed, chunks_created, chunks_deduped.
    """
    import numpy as np

    from rag_builder.chunker import chunk_markdown

    stats = {
        "files_processed": 0,
        "chunks_created": 0,
        "chunks_deduped": 0,
        "errors": 0,
    }
    files = walk_repo_files(directory)

    for fp in files:
        text = parse_file(fp, max_file_size)
        if text is None:
            continue

        rel_path = str(fp.relative_to(directory))
        doc_hash = content_hash(text)

        doc_id = db.insert_document(source_repo, rel_path, text, doc_hash)
        chunks = chunk_markdown(text)
        stats["files_processed"] += 1

        for i, chunk in enumerate(chunks):
            tags = tagger_fn(chunk["content"], file_path=rel_path)
            chunk_id, is_new = db.insert_chunk(
                content_hash=chunk["content_hash"],
                content=chunk["content"],
                section_header=chunk["section_header"],
                domain_tags=tags,
                tag_source="auto",
                token_count=chunk["token_count"],
            )

            db.insert_instance(chunk_id, doc_id, chunk["section_header"], i)

            if is_new:
                try:
                    vec = embedder.embed(chunk["content"])
                    vector_index.add(
                        vec,
                        np.array([chunk_id], dtype=np.int64),
                    )
                    stats["chunks_created"] += 1
                except Exception as exc:
                    log.error(
                        "Embedding error for chunk %d: %s",
                        chunk_id,
                        exc,
                    )
                    stats["errors"] += 1
            else:
                stats["chunks_deduped"] += 1

    return stats


def estimate_directory(directory: Path, max_file_size: int) -> dict:
    """Dry-run estimate: count eligible files/bytes without reading full content."""
    files = walk_repo_files(directory)
    eligible_files = 0
    total_bytes = 0
    for fp in files:
        try:
            size = fp.stat().st_size
        except OSError:
            continue
        if size > max_file_size:
            continue
        eligible_files += 1
        total_bytes += size
    return {
        "candidate_files": len(files),
        "eligible_files": eligible_files,
        "total_bytes": total_bytes,
    }
