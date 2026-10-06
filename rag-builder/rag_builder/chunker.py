"""Hybrid markdown chunker — split on headers, fixed-size fallback."""

import hashlib
import re

HEADER_PATTERN = re.compile(r"^(#{1,3})\s+(.+)$", re.MULTILINE)
MAX_SECTION_TOKENS = 1000
CHUNK_SIZE_TOKENS = 500
CHUNK_OVERLAP_TOKENS = 100
MIN_CHUNK_TOKENS = 50


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: split on whitespace."""
    return len(text.split())


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _fixed_split(
    text: str,
    section_header: str | None,
    chunk_size: int = CHUNK_SIZE_TOKENS,
    overlap: int = CHUNK_OVERLAP_TOKENS,
) -> list[dict]:
    """Split text into fixed-size token chunks with overlap."""
    words = text.split()
    if not words:
        return []
    chunks = []
    start = 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunk_words = words[start:end]
        content = " ".join(chunk_words)
        chunks.append(
            {
                "content": content,
                "section_header": section_header,
                "token_count": len(chunk_words),
                "content_hash": _content_hash(content),
            }
        )
        if end >= len(words):
            break
        start = end - overlap
    return chunks


def chunk_markdown(text: str) -> list[dict]:
    """Split markdown into chunks using headers, with fixed-size fallback.

    Returns list of dicts with keys:
        content, section_header, token_count, content_hash
    """
    if not text or not text.strip():
        return []

    headers = list(HEADER_PATTERN.finditer(text))

    if not headers:
        return _fixed_split(text, section_header=None)

    sections = []
    for i, match in enumerate(headers):
        header_text = match.group(0)
        start = match.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[start:end].strip()
        sections.append((header_text, body))

    pre_header = text[: headers[0].start()].strip()
    if pre_header:
        sections.insert(0, (None, pre_header))

    raw_chunks = []
    for header, body in sections:
        full_content = f"{header}\n{body}" if header and body else (header or body)
        tokens = _estimate_tokens(full_content)

        if tokens > MAX_SECTION_TOKENS:
            raw_chunks.extend(_fixed_split(body, section_header=header))
        else:
            raw_chunks.append(
                {
                    "content": full_content,
                    "section_header": header,
                    "token_count": tokens,
                    "content_hash": _content_hash(full_content),
                }
            )

    merged = []
    i = 0
    while i < len(raw_chunks):
        chunk = raw_chunks[i]
        if (
            chunk["token_count"] < MIN_CHUNK_TOKENS
            and i + 1 < len(raw_chunks)
            and raw_chunks[i + 1]["token_count"] >= MIN_CHUNK_TOKENS
        ):
            next_chunk = raw_chunks[i + 1]
            combined = chunk["content"] + "\n" + next_chunk["content"]
            merged.append(
                {
                    "content": combined,
                    "section_header": next_chunk["section_header"],
                    "token_count": _estimate_tokens(combined),
                    "content_hash": _content_hash(combined),
                }
            )
            i += 2
        else:
            merged.append(chunk)
            i += 1

    return merged
