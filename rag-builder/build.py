#!/usr/bin/env python3
"""RAG / FAISS database builder for the writeup-search MCP server.

SAFETY: every destructive operation (clone, embed, FAISS write, SQLite write)
is gated behind ``--execute``. Without it, the tool runs in dry-run mode and
only prints what it *would* do.

Typical workflow
----------------
    # 1. Inspect plan (no writes, no network).
    python3 build.py ingest

    # 2. Ingest the full repos.yaml list into ./data/.
    python3 build.py ingest --execute

    # 3. Rebuild FAISS from SQLite (useful after schema / model change).
    python3 build.py rebuild --execute

    # 4. Point the MCP writeup-search server at the output.
    export WRITEUP_DB_DIR="$PWD/data"

Outputs
-------
``<data_dir>/metadata.db`` — SQLite with documents + chunks + FTS5.
``<data_dir>/index.faiss`` — FAISS IndexIDMap2(IndexFlatIP) at 384-dim.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path

# Make the sibling package importable regardless of cwd.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

log = logging.getLogger("rag-builder")


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #


def load_config(config_path: Path) -> dict:
    """Load YAML config. Resolves relative paths against config file location."""
    import yaml

    with open(config_path) as f:
        cfg = yaml.safe_load(f) or {}

    base = config_path.resolve().parent
    data_dir = Path(cfg.get("data_dir", "data"))
    if not data_dir.is_absolute():
        data_dir = base / data_dir
    cfg["_data_dir_resolved"] = data_dir

    return cfg


def _load_repo_urls(path: Path) -> list[str]:
    """Load the ``repos:`` list from a YAML file, accepting str or {url: ...}."""
    import yaml

    with open(path) as f:
        data = yaml.safe_load(f) or {}
    entries = data.get("repos", [])
    return [r["url"] if isinstance(r, dict) else r for r in entries]


def load_repos(repos_path: Path, skip_path: Path | None = None) -> tuple[list[str], list[str]]:
    """Load the repo list and apply ``repos-skipped.yaml`` as an exclusion set.

    Returns ``(active, skipped)``. ``skipped`` lists URLs that appeared in the
    main list *and* the skip list, so the caller can surface them in the plan.
    URLs only present in the skip file (never in the main list) are ignored.
    """
    urls = _load_repo_urls(repos_path)

    skip_set: set[str] = set()
    if skip_path and skip_path.exists():
        try:
            skip_set = set(_load_repo_urls(skip_path))
        except Exception as exc:  # noqa: BLE001
            log.warning("skip-list %s unreadable: %s", skip_path, exc)

    seen: set[str] = set()
    active: list[str] = []
    skipped: list[str] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        if url in skip_set:
            skipped.append(url)
        else:
            active.append(url)
    return active, skipped


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def cmd_status(args: argparse.Namespace, cfg: dict) -> int:
    """Print the current state of the index and config."""
    data_dir: Path = cfg["_data_dir_resolved"]
    db_path = data_dir / "metadata.db"
    idx_path = data_dir / "index.faiss"

    print("== rag-builder status ==")
    print(f"  config           : {args.config}")
    print(f"  repos            : {args.repos}")
    print(f"  data_dir         : {data_dir}")
    print(f"  embedding_model  : {cfg.get('embedding_model', 'all-MiniLM-L6-v2')}")
    print(f"  host_allowlist   : {cfg.get('host_allowlist', [])}")
    print(f"  max_file_size    : {cfg.get('max_file_size_bytes', 1_048_576)} bytes")
    print(f"  max_repo_size_mb : {cfg.get('max_repo_size_mb', 500)} MB")
    print()
    print(f"  metadata.db      : {_fmt_exists(db_path)}")
    print(f"  index.faiss      : {_fmt_exists(idx_path)}")

    if db_path.exists():
        try:
            from rag_builder.db import Database

            with Database(db_path) as db:
                docs = db.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
                chunks = db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
                repos = db.execute("SELECT COUNT(*) FROM repos").fetchone()[0]
                print(f"  documents        : {docs}")
                print(f"  chunks           : {chunks}")
                print(f"  repos ingested   : {repos}")
        except Exception as exc:  # noqa: BLE001
            print(f"  (db inspect failed: {exc})")
    return 0


def cmd_ingest(args: argparse.Namespace, cfg: dict) -> int:
    """Ingest all repos from repos.yaml (or a single --url)."""
    if args.url:
        urls = [args.url]
        skip_listed: list[str] = []
    else:
        skip_path = Path(args.skip_list) if args.skip_list else None
        # Auto-pick repos-skipped.yaml beside repos.yaml unless opted out.
        if skip_path is None and not args.no_skip_list:
            default_skip = Path(args.repos).with_name("repos-skipped.yaml")
            if default_skip.exists():
                skip_path = default_skip
        urls, skip_listed = load_repos(Path(args.repos), skip_path)

    if not urls and not skip_listed:
        print("[!] No repos to ingest. Check repos.yaml.")
        return 1

    host_allowlist = cfg.get("host_allowlist", ["github.com"])
    max_file_size = cfg.get("max_file_size_bytes", 1_048_576)
    max_repo_mb = cfg.get("max_repo_size_mb", 500)
    clone_timeout = cfg.get("clone_timeout_seconds", 120)
    data_dir: Path = cfg["_data_dir_resolved"]

    from rag_builder.ingest import (
        check_repo_available,
        check_repo_size,
        clone_repo,
        estimate_directory,
        ingest_directory,
        validate_repo_url,
    )

    print(f"== ingest ({'EXECUTE' if args.execute else 'DRY-RUN'}) ==")
    print(f"  data_dir : {data_dir}")
    print(f"  repos    : {len(urls) + len(skip_listed)} loaded"
          f"  ({len(skip_listed)} in skip list)")
    print()

    for u in skip_listed:
        print(f"  [skip]   {u}  (in repos-skipped.yaml)")

    # Pre-flight 1: URL shape + host_allowlist. Cheap, no network.
    invalid = [u for u in urls if not validate_repo_url(u, host_allowlist)]
    for u in invalid:
        print(f"  [skip]   {u}  (host not in allowlist)")
    valid = [u for u in urls if validate_repo_url(u, host_allowlist)]

    # Pre-flight 2: remote availability via `git ls-remote`. Opt-in, network.
    unreachable: list[tuple[str, str]] = []
    if args.check_remotes and valid:
        print()
        print(f"  probing {len(valid)} remote(s) with git ls-remote "
              f"(timeout={args.remote_timeout}s, workers={args.remote_workers})")
        reachable, unreachable = _probe_remotes(
            valid,
            timeout=args.remote_timeout,
            workers=args.remote_workers,
            probe=check_repo_available,
        )
        for u, why in unreachable:
            print(f"  [gone]   {u}  ({why})")
        valid = reachable

    if not args.execute:
        print()
        print(f"  {len(valid)} repo(s) would be cloned.")
        print(f"  {len(invalid)} invalid URL(s).")
        print(f"  {len(unreachable)} unreachable remote(s).")
        print(f"  {len(skip_listed)} in skip list.")
        print()
        print("DRY-RUN: nothing cloned, nothing embedded, nothing written.")
        print("Pass --execute to actually run the ingestion.")
        return 0

    # Real run: open DB + index + embedder lazily.
    from rag_builder.db import Database
    from rag_builder.embedder import Embedder
    from rag_builder.index import VectorIndex
    from rag_builder.tagger import auto_tag

    data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(data_dir / "metadata.db")
    embedder = Embedder(cfg.get("embedding_model", "all-MiniLM-L6-v2"))
    index = VectorIndex(data_dir / "index.faiss", dimension=embedder.dimension)

    results = []
    try:
        for i, url in enumerate(valid, 1):
            print(f"[{i}/{len(valid)}] {url}")
            with tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "repo"
                if not clone_repo(url, dest, timeout=clone_timeout):
                    print("           clone failed")
                    results.append({"url": url, "error": "clone failed"})
                    continue
                if not check_repo_size(dest, max_repo_mb):
                    print(f"           repo exceeds {max_repo_mb} MB cap")
                    results.append({"url": url, "error": "oversized repo"})
                    continue

                est = estimate_directory(dest, max_file_size)
                print(
                    f"           {est['eligible_files']}/{est['candidate_files']} eligible files"
                    f"  ({est['total_bytes'] // 1024} KiB)"
                )
                stats = ingest_directory(
                    dest,
                    url,
                    db,
                    embedder,
                    index,
                    auto_tag,
                    max_file_size,
                )
                print(
                    f"           files={stats['files_processed']}"
                    f"  chunks_created={stats['chunks_created']}"
                    f"  chunks_deduped={stats['chunks_deduped']}"
                    f"  errors={stats['errors']}"
                )
                db.execute(
                    "INSERT OR REPLACE INTO repos "
                    "(url, domain_tags, file_count, chunk_count) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        url,
                        json.dumps([]),
                        stats["files_processed"],
                        stats["chunks_created"],
                    ),
                )
                db.conn.commit()
                results.append({"url": url, **stats})

            # Persist FAISS after each repo so progress isn't lost on crash.
            index.save()
    finally:
        db.close()

    summary_path = data_dir / "bulk_ingest_results.json"
    total_files = sum(r.get("files_processed", 0) for r in results)
    total_chunks = sum(r.get("chunks_created", 0) for r in results)
    errors = sum(1 for r in results if "error" in r)
    summary = {
        "repos_processed": len(valid),
        "total_files": total_files,
        "total_chunks": total_chunks,
        "errors": errors,
        "details": results,
    }
    summary_path.write_text(json.dumps(summary, indent=2))
    print()
    print(f"done. summary -> {summary_path}")
    return 0


def cmd_rebuild(args: argparse.Namespace, cfg: dict) -> int:
    """Rebuild FAISS from SQLite (authoritative). Safe to re-run."""
    import numpy as np

    data_dir: Path = cfg["_data_dir_resolved"]
    db_path = data_dir / "metadata.db"
    idx_path = data_dir / "index.faiss"

    if not db_path.exists():
        print(f"[!] no metadata.db at {db_path}")
        return 1

    if not args.execute:
        from rag_builder.db import Database

        with Database(db_path) as db:
            chunks = db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        print(f"DRY-RUN rebuild: would re-embed {chunks} chunks, write {idx_path}.")
        print("Pass --execute to actually rebuild.")
        return 0

    from rag_builder.db import Database
    from rag_builder.embedder import Embedder
    from rag_builder.index import VectorIndex

    embedder = Embedder(cfg.get("embedding_model", "all-MiniLM-L6-v2"))
    tmp_path = data_dir / "index.faiss.tmp"
    if tmp_path.exists():
        tmp_path.unlink()
    new_index = VectorIndex(tmp_path, dimension=embedder.dimension)
    total = 0
    with Database(db_path) as db:
        chunk_ids = db.get_all_chunk_ids()
        batch = 256
        for i in range(0, len(chunk_ids), batch):
            ids = chunk_ids[i : i + batch]
            chunks = [db.get_chunk(cid) for cid in ids]
            texts = [c["content"] for c in chunks if c]
            ids_arr = np.array([c["id"] for c in chunks if c], dtype=np.int64)
            if texts:
                vecs = embedder.embed(texts)
                new_index.add(vecs, ids_arr)
                total += len(texts)
        new_index.save_to(tmp_path)
        with open(tmp_path, "rb") as f:
            os.fsync(f.fileno())
        os.replace(str(tmp_path), str(idx_path))
        db.execute(
            "INSERT OR REPLACE INTO schema_meta (key, value) VALUES (?, ?)",
            ("last_rebuild_at", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
        )
        db.conn.commit()
    print(f"rebuilt {total} vectors -> {idx_path}")
    return 0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _probe_remotes(
    urls: list[str],
    timeout: int,
    workers: int,
    probe,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Parallel ``git ls-remote`` availability check.

    Returns ``(reachable, unreachable)`` where each ``unreachable`` entry is
    ``(url, short_reason)``. Order of ``reachable`` follows the input.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[str, tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(probe, u, timeout): u for u in urls}
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                results[u] = fut.result()
            except Exception as exc:  # noqa: BLE001
                results[u] = (False, f"probe error: {exc}")

    reachable = [u for u in urls if results.get(u, (False, "?"))[0]]
    unreachable = [(u, results[u][1]) for u in urls if not results.get(u, (False, "?"))[0]]
    return reachable, unreachable


def _fmt_exists(path: Path) -> str:
    if not path.exists():
        return "MISSING"
    size = path.stat().st_size
    if size < 1024:
        return f"OK ({size} B)"
    if size < 1024**2:
        return f"OK ({size / 1024:.1f} KiB)"
    if size < 1024**3:
        return f"OK ({size / 1024**2:.1f} MiB)"
    return f"OK ({size / 1024**3:.2f} GiB)"


# --------------------------------------------------------------------------- #
# Arg parsing
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="build.py",
        description="Build the RAG/FAISS knowledge base for the writeup-search MCP server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Every destructive operation is gated behind --execute. Without it, "
            "the tool is read-only and prints what it would do."
        ),
    )
    p.add_argument(
        "--config",
        default=str(SCRIPT_DIR / "config.yaml"),
        help="path to config.yaml (default: ./config.yaml next to build.py)",
    )
    p.add_argument(
        "--repos",
        default=str(SCRIPT_DIR / "repos.yaml"),
        help="path to repos.yaml (default: ./repos.yaml next to build.py)",
    )
    p.add_argument(
        "--data-dir",
        help="override data_dir from config.yaml (where metadata.db + index.faiss are written)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="verbose logging")

    sub = p.add_subparsers(dest="cmd")
    sub.required = False  # default -> status

    sub.add_parser("status", help="show current index state (read-only)")

    ing = sub.add_parser("ingest", help="clone + index repos from repos.yaml")
    ing.add_argument("--url", help="ingest a single URL instead of repos.yaml")
    ing.add_argument(
        "--execute",
        action="store_true",
        help="actually clone + embed + write (default: dry-run).",
    )
    # --dry-run is the default, accept it explicitly so users don't get
    # argparse errors from the usage they expect.
    ing.add_argument(
        "--dry-run",
        action="store_true",
        help="alias for the default no-op behavior (kept for muscle memory)",
    )
    ing.add_argument(
        "--check-remotes",
        action="store_true",
        help="probe each URL with `git ls-remote` (opt-in; makes network calls)",
    )
    ing.add_argument(
        "--remote-timeout",
        type=int,
        default=15,
        help="per-repo timeout for --check-remotes (default 15s)",
    )
    ing.add_argument(
        "--remote-workers",
        type=int,
        default=16,
        help="parallel probes for --check-remotes (default 16)",
    )
    ing.add_argument(
        "--skip-list",
        help="override skip list YAML (default: repos-skipped.yaml next to repos.yaml)",
    )
    ing.add_argument(
        "--no-skip-list",
        action="store_true",
        help="ignore repos-skipped.yaml even if present",
    )

    reb = sub.add_parser("rebuild", help="rebuild FAISS from SQLite")
    reb.add_argument(
        "--execute",
        action="store_true",
        help="actually re-embed + write (default: dry-run).",
    )
    reb.add_argument("--dry-run", action="store_true", help="alias for the default")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[!] config not found: {config_path}", file=sys.stderr)
        return 2
    cfg = load_config(config_path)
    if args.data_dir:
        override = Path(args.data_dir).resolve()
        cfg["_data_dir_resolved"] = override

    cmd = args.cmd or "status"
    if cmd == "status":
        return cmd_status(args, cfg)
    if cmd == "ingest":
        if args.dry_run and args.execute:
            print("[!] --dry-run and --execute are mutually exclusive", file=sys.stderr)
            return 2
        return cmd_ingest(args, cfg)
    if cmd == "rebuild":
        if args.dry_run and args.execute:
            print("[!] --dry-run and --execute are mutually exclusive", file=sys.stderr)
            return 2
        return cmd_rebuild(args, cfg)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
