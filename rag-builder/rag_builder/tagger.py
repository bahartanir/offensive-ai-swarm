"""Auto-tagger for domain classification using path and content heuristics."""

import re

# Path-based classification: folder name -> tags
PATH_RULES: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"/web/", re.IGNORECASE), ["xss", "web"]),
    (re.compile(r"/xss/", re.IGNORECASE), ["xss", "web"]),
    (re.compile(r"/crypto/", re.IGNORECASE), ["crypto"]),
    (re.compile(r"/pwn/", re.IGNORECASE), ["pwn"]),
    (re.compile(r"/forensics/", re.IGNORECASE), ["forensics"]),
    (re.compile(r"/misc/", re.IGNORECASE), ["misc"]),
    (re.compile(r"/reverse/", re.IGNORECASE), ["reverse"]),
    (re.compile(r"/rev/", re.IGNORECASE), ["reverse"]),
    (re.compile(r"/sqli/", re.IGNORECASE), ["sqli", "web"]),
]

# Content-based classification: regex pattern -> tags
CONTENT_RULES: list[tuple[re.Pattern, list[str]]] = [
    (
        re.compile(
            r"<script>|XSS|alert\(|innerHTML|sanitizer|DOMPurify|onload=|onerror=",
            re.IGNORECASE,
        ),
        ["xss"],
    ),
    (
        re.compile(
            r"\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b|SQL.?injection|SQLi",
            re.IGNORECASE,
        ),
        ["sqli"],
    ),
    (
        re.compile(r"SSRF|server.side request", re.IGNORECASE),
        ["ssrf"],
    ),
    (
        re.compile(
            r"SSTI|template.injection|Jinja|Twig|\{\{.*\}\}",
            re.IGNORECASE,
        ),
        ["ssti"],
    ),
    (
        re.compile(
            r"buffer.overflow|ROP|shellcode|heap.exploit|format.string",
            re.IGNORECASE,
        ),
        ["pwn"],
    ),
    (
        re.compile(
            r"\bRSA\b|\bAES\b|cipher|modular.arithmetic|elliptic.curve",
            re.IGNORECASE,
        ),
        ["crypto"],
    ),
]


def auto_tag(content: str, file_path: str | None = None) -> list[str]:
    """Classify content by domain using path and content heuristics.

    Returns deduplicated sorted list of domain tags.
    """
    tags: set[str] = set()

    if file_path:
        normalized = file_path.replace("\\", "/")
        for pattern, labels in PATH_RULES:
            if pattern.search(normalized):
                tags.update(labels)

    for pattern, labels in CONTENT_RULES:
        if pattern.search(content):
            tags.update(labels)

    return sorted(tags)
