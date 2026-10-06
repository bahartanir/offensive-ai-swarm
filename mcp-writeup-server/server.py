#!/usr/bin/env python3
"""
Writeup Search MCP Server

Searches a bring-your-own bug-bounty / CTF writeup corpus via FAISS vector
search or SQLite keyword fallback. Agents query this for techniques, payloads,
and prior art during hunting and validation.

No writeup corpus is bundled with this repo (bulk-redistributing scraped
hacktivity violates most platform ToS). The `search_payloads` /
`search_techniques` tools work out of the box against the repo's
rules/payloads.md + skills/; `search_writeups` activates once you point the
server at your own metadata.db (+ optional index.faiss).

Setup:
    pip install mcp faiss-cpu sentence-transformers      # optional for semantic
    # Drop metadata.db (+ optionally index.faiss) into
    #   ~/.local/share/pentest-writeups/
    # or set WRITEUP_DB_DIR=/path/to/dir

Usage:
    python3 mcp-writeup-server/server.py --test     # Self-test
    python3 mcp-writeup-server/server.py             # Run as MCP server

MCP Tools:
    search_writeups   — Semantic search (FAISS) or keyword search (fallback)
    get_writeup       — Get full writeup by ID
    search_techniques — Search for specific technique/vuln class patterns
    search_payloads   — Search for payloads by vuln type in rules/payloads.md
"""

import json
import os
import re
import sqlite3
import sys
from pathlib import Path

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
if SERVER_DIR not in sys.path:
    sys.path.insert(0, SERVER_DIR)

# Data directory — configurable via env var
DATA_DIR = Path(os.environ.get("WRITEUP_DB_DIR",
    os.path.expanduser("~/.local/share/pentest-writeups")))

# Fix mpmath 1.3.0 / sympy 1.14.0 incompatibility:
# sympy imports mpf_ln from mpmath.libmp, but 1.3.0 only exports mpf_log
try:
    import mpmath.libmp
    if not hasattr(mpmath.libmp, 'mpf_ln') and hasattr(mpmath.libmp, 'mpf_log'):
        mpmath.libmp.mpf_ln = mpmath.libmp.mpf_log
except ImportError:
    pass

# Try FAISS imports
_faiss = None
_model = None
try:
    import faiss
    _faiss = faiss
except ImportError:
    pass

try:
    from sentence_transformers import SentenceTransformer
except ImportError:
    SentenceTransformer = None


class WriteupSearchEngine:
    """Search engine with FAISS (semantic) and SQLite (keyword) backends."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.db_path = data_dir / "metadata.db"
        self.index_path = data_dir / "index.faiss"
        self.index = None
        self.model = None
        self.db = None
        self.mode = "none"

        # Try loading FAISS index
        if _faiss and self.index_path.exists():
            try:
                self.index = _faiss.read_index(str(self.index_path))
                if SentenceTransformer:
                    self.model = SentenceTransformer("all-MiniLM-L6-v2")
                    self.mode = "faiss"
            except Exception as e:
                print(f"FAISS load failed: {e}", file=sys.stderr)

        # Try loading SQLite
        if self.db_path.exists():
            try:
                self.db = sqlite3.connect(str(self.db_path))
                self.db.row_factory = sqlite3.Row
                if self.mode != "faiss":
                    self.mode = "sqlite"
            except Exception as e:
                print(f"SQLite load failed: {e}", file=sys.stderr)

        # Fallback: search local .md files
        if self.mode == "none":
            self.mode = "local"

    def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search writeups using best available backend."""
        if self.mode == "faiss":
            return self._search_faiss(query, limit)
        elif self.mode == "sqlite":
            return self._search_sqlite(query, limit)
        else:
            return self._search_local(query, limit)

    def _search_faiss(self, query: str, limit: int) -> list[dict]:
        """Semantic search via FAISS."""
        embedding = self.model.encode([query])
        distances, indices = self.index.search(embedding, limit)

        results = []
        for i, (dist, idx) in enumerate(zip(distances[0], indices[0])):
            if idx == -1:
                continue
            # Get metadata from SQLite
            row = self._get_row_by_index(int(idx))
            if row:
                results.append({
                    "id": row.get("id", idx),
                    "title": row.get("title", f"Writeup #{idx}"),
                    "content": row.get("content", "")[:500],
                    "score": float(1 / (1 + dist)),
                    "source": row.get("source", ""),
                    "tags": row.get("tags", ""),
                })
        return results

    def _get_row_by_index(self, idx: int) -> dict:
        """Get a writeup row by FAISS index."""
        if not self.db:
            return {}
        try:
            cursor = self.db.execute(
                "SELECT * FROM writeups WHERE rowid = ? LIMIT 1",
                (idx + 1,)  # SQLite rowid is 1-indexed
            )
            row = cursor.fetchone()
            return dict(row) if row else {}
        except:
            # Try alternative table names
            try:
                tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                for table in tables:
                    tname = table[0]
                    cursor = self.db.execute(f"SELECT * FROM {tname} WHERE rowid = ? LIMIT 1", (idx + 1,))
                    row = cursor.fetchone()
                    if row:
                        return dict(row)
            except:
                pass
        return {}

    def _search_sqlite(self, query: str, limit: int) -> list[dict]:
        """Keyword search via SQLite."""
        results = []
        keywords = query.split()
        like_clauses = " AND ".join([f"content LIKE ?" for _ in keywords])
        params = [f"%{kw}%" for kw in keywords]

        # Try to find the right table and columns
        try:
            tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            for table in tables:
                tname = table[0]
                cols = [c[1] for c in self.db.execute(f"PRAGMA table_info({tname})").fetchall()]

                # Find text columns
                text_col = next((c for c in cols if c in ("content", "text", "body", "writeup")), None)
                title_col = next((c for c in cols if c in ("title", "name", "filename")), None)

                if text_col:
                    like_clauses = " AND ".join([f"{text_col} LIKE ?" for _ in keywords])
                    sql = f"SELECT * FROM {tname} WHERE {like_clauses} LIMIT ?"
                    cursor = self.db.execute(sql, params + [limit])
                    for row in cursor:
                        r = dict(row)
                        results.append({
                            "id": r.get("id", r.get("rowid", "")),
                            "title": r.get(title_col, "") if title_col else "",
                            "content": str(r.get(text_col, ""))[:500],
                            "score": 1.0,
                            "source": r.get("source", r.get("url", "")),
                            "tags": r.get("tags", r.get("category", "")),
                        })
                    break
        except Exception as e:
            print(f"SQLite search error: {e}", file=sys.stderr)
        return results

    def _search_local(self, query: str, limit: int) -> list[dict]:
        """Fallback: search local markdown files."""
        results = []
        cwd = Path.cwd()
        search_dirs = [
            cwd / "docs",
            cwd / "skills",
            cwd / "rules",
        ]
        keywords = [kw.lower() for kw in query.split() if len(kw) > 2]

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            for md_file in search_dir.rglob("*.md"):
                content = md_file.read_text()
                content_lower = content.lower()
                score = sum(1 for kw in keywords if kw in content_lower)
                if score >= min(2, len(keywords)):
                    results.append({
                        "id": str(md_file),
                        "title": md_file.stem,
                        "content": content[:500],
                        "score": score / len(keywords) if keywords else 0,
                        "source": str(md_file.relative_to(cwd)),
                        "tags": md_file.parent.name,
                    })

        results.sort(key=lambda x: -x["score"])
        return results[:limit]

    def get_writeup(self, writeup_id: str) -> dict:
        """Get full writeup content by ID."""
        if self.db:
            try:
                tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                for table in tables:
                    tname = table[0]
                    cursor = self.db.execute(f"SELECT * FROM {tname} WHERE id = ? OR rowid = ? LIMIT 1",
                                              (writeup_id, writeup_id))
                    row = cursor.fetchone()
                    if row:
                        return dict(row)
            except:
                pass

        # Try local file
        path = Path(writeup_id)
        if path.exists():
            return {"title": path.stem, "content": path.read_text(), "source": str(path)}

        return {"error": f"Writeup {writeup_id} not found"}

    # --- payload search internals ---
    #
    # The previous implementation did a blind substring match against the
    # first 50 chars of each section header and returned the raw section as
    # a dump. That missed aliases ("SSRF" vs "server-side request forgery"),
    # had no ranking when multiple sections matched, and gave hunters no
    # structure to work against.
    #
    # search_payloads now returns a "deep payload pack":
    #   * top 3 relevance-scored sections (title + body fingerprint)
    #   * an attack checklist of combination probes
    #   * candidate payloads pulled from the top sections (code fences + bullet backticks)
    #   * a mutation matrix (encoding/transport/context families)
    # Consumers (hunter agents) treat the output as a structured hunt plan.

    _VULN_ALIASES = {
        "cross site scripting": "xss",
        "cross-site scripting": "xss",
        "stored xss": "xss",
        "reflected xss": "xss",
        "dom xss": "xss",
        "blind xss": "xss",
        "sql injection": "sqli",
        "nosql injection": "nosql",
        "server-side request forgery": "ssrf",
        "server side request forgery": "ssrf",
        "remote code execution": "rce",
        "command injection": "rce",
        "auth bypass": "auth",
        "authentication bypass": "auth",
        "authorization": "idor",
        "broken access control": "idor",
        "template injection": "ssti",
        "server-side template injection": "ssti",
        "path traversal": "lfi",
        "local file inclusion": "lfi",
        "xml external entity": "xxe",
        "open redirect": "redirect",
    }

    @staticmethod
    def _normalize_vuln_type(vuln_type: str) -> str:
        lowered = vuln_type.strip().lower()
        return WriteupSearchEngine._VULN_ALIASES.get(lowered, lowered)

    @staticmethod
    def _parse_payload_sections(content: str) -> dict[str, str]:
        """Split payloads.md into {h2_title: body} segments."""
        sections: dict[str, str] = {}
        current: str | None = None
        bucket: list[str] = []
        for line in content.splitlines():
            if line.startswith("## "):
                if current and bucket:
                    sections[current] = "\n".join(bucket).strip()
                current = line[3:].strip()
                bucket = []
                continue
            if current is not None:
                bucket.append(line)
        if current and bucket:
            sections[current] = "\n".join(bucket).strip()
        return sections

    def _score_section(self, canonical: str, raw: str, title: str, body: str) -> float:
        """Relevance score for a section given normalized + raw vuln_type."""
        title_l = title.lower()
        body_l = body.lower()
        raw_l = raw.lower()
        score = 0.0
        if canonical and canonical in title_l:
            score += 5.0
        if raw_l and raw_l != canonical and raw_l in title_l:
            score += 3.0
        # Body signal: each term occurrence adds a little, capped so a spammy
        # section can't drown out a precise title match.
        body_hits = body_l.count(canonical) if canonical else 0
        score += min(body_hits, 10) * 0.3
        # Alias hits (e.g. searching "xss" should still pick up sections titled
        # "Cross-Site Scripting" if the body mentions both).
        for alias, target in self._VULN_ALIASES.items():
            if target == canonical and alias in body_l:
                score += 0.5
        return score

    @staticmethod
    def _extract_payload_lines(top_matches: list[tuple[float, str, str]]) -> list[str]:
        """Extract payload-looking lines (backtick-wrapped or inside code fences)."""
        payloads: list[str] = []
        for _, _, body in top_matches:
            in_fence = False
            for line in body.splitlines():
                stripped = line.strip()
                if stripped.startswith("```"):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    if stripped:
                        payloads.append(stripped)
                elif stripped.startswith("- `") and "`" in stripped[3:]:
                    # "- `payload`" bullet form
                    end = stripped.find("`", 3)
                    if end > 3:
                        payloads.append(stripped[3:end])
        # Dedupe while preserving order.
        seen: set[str] = set()
        return [p for p in payloads if not (p in seen or seen.add(p))]

    @staticmethod
    def _build_combo_candidates(canonical: str) -> list[str]:
        """Class-specific attack combinations. Feed hunter as a checklist."""
        base = [
            "baseline probe to confirm sink fires at all",
            "encoding ladder: raw → url → double-url → unicode → mixed-case",
            "cross-endpoint replay (every sibling endpoint under the same router)",
            "cross-role replay (unauth, low-priv, high-priv)",
            "HTTP method swap where endpoint accepts more than one verb",
        ]
        per_class = {
            "xss": [
                "source → sink trace in JS bundle before injecting",
                "stored XSS: plant once, harvest from sibling viewers + emails + exports",
                "CSP bypass check via trusted origins + nonce reuse",
            ],
            "sqli": [
                "differential response check at 0/1 ms delay boundary",
                "error-based vs blind boolean vs time-based — all three",
                "second-order injection: store then trigger via reporting/export",
            ],
            "ssrf": [
                "IP bypass table: decimal, octal, ipv6-mapped, DNS rebinding",
                "cloud metadata: AWS, GCP, Azure, Alibaba, DigitalOcean — try all",
                "protocol pivots: gopher, dict, file, ftp where allowed",
            ],
            "idor": [
                "method swap (GET → PUT/PATCH/DELETE)",
                "tenant switch header abuse (X-Org, Account-ID, tenant cookies)",
                "batch/GraphQL node() abuse",
            ],
            "ssti": [
                "non-dunder probe first (|attr('format')) to confirm primitive",
                "map is_safe_attribute blocklist per object type",
                "source-level obfuscation only AFTER regex filter confirmed",
            ],
            "rce": [
                "deserialize sinks: pickle / YAML.load / unserialize / marshalling",
                "template injection pivot to RCE chain",
                "command injection via shell metachars + IFS/newline tricks",
            ],
            "oauth": [
                "redirect_uri allowlist bypass (subdomain confusion, path, fragment)",
                "state + PKCE validation",
                "token confusion (access vs ID vs refresh)",
            ],
            "graphql": [
                "introspection on every endpoint + batched/persisted variants",
                "node() / relay ID for IDOR",
                "query depth + alias flooding",
            ],
        }
        return base + per_class.get(canonical, [])

    @staticmethod
    def _build_mutation_matrix(canonical: str) -> dict[str, list[str]]:
        """Mutation families to combine with every candidate payload."""
        matrix: dict[str, list[str]] = {
            # Single-layer encodings first, then stacked (multi-encoded in the
            # same payload). Stacking defeats WAFs that decode once — target
            # parsers typically decode twice.
            "encoding": [
                "raw", "url", "unicode-escape", "html-entity", "mixed-case",
                "double-url", "html-entity+url", "url+html-entity",
                "unicode-escape+url", "base64+url",
            ],
            "transport": ["query", "body-form", "body-json", "header", "cookie", "multipart"],
            "context": ["html-attr", "js-string", "url-param", "css", "svg", "markdown"],
        }
        per_class = {
            "ssrf": {"routing": ["ipv6-mapped", "decimal-ip", "octal-ip", "dns-rebind", "redirect-hop"]},
            "sqli": {"syntax": ["boolean", "time", "stacked", "union", "out-of-band"]},
            "idor": {"identifier": ["numeric", "uuid", "base64", "jwt-sub", "graphql-node"]},
            "ssti": {"object-type": ["function", "class", "method", "namespace", "joiner"]},
        }
        matrix.update(per_class.get(canonical, {}))
        return matrix

    def search_payloads(self, vuln_type: str) -> str:
        """Return a structured deep-payload pack for hunter agents."""
        payloads_path = Path.cwd() / "rules" / "payloads.md"
        if not payloads_path.exists():
            return "No payloads.md found."

        content = payloads_path.read_text()
        canonical = self._normalize_vuln_type(vuln_type)
        sections = self._parse_payload_sections(content)
        scored: list[tuple[float, str, str]] = []
        for title, body in sections.items():
            score = self._score_section(canonical, vuln_type, title, body)
            if score > 0:
                scored.append((score, title, body))
        scored.sort(key=lambda item: item[0], reverse=True)

        if not scored:
            available = ", ".join(sorted(sections))
            return (
                f"No payloads found for '{vuln_type}'. "
                f"Available sections: {available}"
            )

        top_matches = scored[:3]
        payload_candidates = self._extract_payload_lines(top_matches)
        combos = self._build_combo_candidates(canonical)
        mutations = self._build_mutation_matrix(canonical)

        out = [f"## Deep payload pack for {vuln_type}", ""]
        out.append("### Highest-confidence sections")
        for score, title, body in top_matches:
            preview = "\n".join(body.splitlines()[:18]).strip()
            out.append(f"\n#### {title} (score={score:.2f})\n{preview}")

        out.append("\n### Exhaustive attack checklist")
        out.extend(f"- [ ] {item}" for item in combos)

        if payload_candidates:
            out.append("\n### Candidate payloads to permute")
            out.extend(f"- `{line}`" for line in payload_candidates[:25])

        out.append("\n### Mutation matrix (combine with each payload)")
        for family, variants in mutations.items():
            out.append(f"- **{family}**: {', '.join(variants)}")

        return "\n".join(out)


# --- Self-test ---
if "--test" in sys.argv:
    print("=== Writeup Search MCP Server Self-Test ===")
    print(f"  Data dir: {DATA_DIR}")
    print(f"  metadata.db: {'exists' if (DATA_DIR / 'metadata.db').exists() else 'NOT FOUND'}")
    print(f"  index.faiss: {'exists' if (DATA_DIR / 'index.faiss').exists() else 'NOT FOUND'}")
    print(f"  FAISS lib: {'available' if _faiss else 'NOT INSTALLED (pip install faiss-cpu)'}")
    print(f"  SentenceTransformer: {'available' if SentenceTransformer else 'NOT INSTALLED (pip install sentence-transformers)'}")

    engine = WriteupSearchEngine(DATA_DIR)
    print(f"  Search mode: {engine.mode}")

    # Test local search
    results = engine.search("XSS WAF bypass", limit=3)
    print(f"  Test search 'XSS WAF bypass': {len(results)} results")
    for r in results[:3]:
        print(f"    [{r['score']:.2f}] {r['title'][:60]}")

    # Test payload search
    payloads = engine.search_payloads("SSTI")
    print(f"  Test payload search 'SSTI': {len(payloads)} chars")

    print(f"\n  Server ready in '{engine.mode}' mode.")
    if engine.mode == "local":
        print(f"  To enable FAISS: pip install faiss-cpu sentence-transformers")
        print(f"  Then place metadata.db + index.faiss in {DATA_DIR}")
    sys.exit(0)

# --- MCP Server ---
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError:
    print("MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

server = Server("writeup-search")
engine = WriteupSearchEngine(DATA_DIR)


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="search_writeups",
            description=f"Search {engine.mode} writeup database for techniques, vulns, and prior art. "
                        f"Use to find: how others exploited similar targets, bypass techniques for WAFs, "
                        f"chain ideas, and prior art for /dupcheck.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (vuln type, technique, target)"},
                    "limit": {"type": "integer", "description": "Max results (default 5)", "default": 5},
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="get_writeup",
            description="Get full writeup content by ID (from search_writeups results).",
            inputSchema={
                "type": "object",
                "properties": {
                    "writeup_id": {"type": "string", "description": "Writeup ID from search results"},
                },
                "required": ["writeup_id"],
            },
        ),
        Tool(
            name="search_techniques",
            description="Search for specific exploitation techniques by vuln class. "
                        "Returns techniques, payloads, and bypass methods from the knowledge base.",
            inputSchema={
                "type": "object",
                "properties": {
                    "vuln_class": {"type": "string", "description": "Vuln class: xss, ssrf, idor, ssti, sqli, jwt, deserialization, oauth, race, graphql, lfi, prototype-pollution, nosql"},
                },
                "required": ["vuln_class"],
            },
        ),
        Tool(
            name="search_payloads",
            description="Search the curated payload database for a specific vulnerability type. "
                        "Returns ready-to-use payloads with WAF bypass variants.",
            inputSchema={
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "Vulnerability type to search payloads for"},
                },
                "required": ["vuln_type"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "search_writeups":
        results = engine.search(arguments["query"], arguments.get("limit", 5))
        if not results:
            return [TextContent(type="text", text="No writeups found for this query.")]
        output = f"Found {len(results)} writeups (mode: {engine.mode}):\n\n"
        for r in results:
            output += f"**[{r['score']:.2f}] {r['title']}**\n"
            output += f"  Source: {r['source']}\n"
            if r['tags']:
                output += f"  Tags: {r['tags']}\n"
            output += f"  {r['content'][:300]}...\n\n"
        return [TextContent(type="text", text=output)]

    elif name == "get_writeup":
        result = engine.get_writeup(arguments["writeup_id"])
        if "error" in result:
            return [TextContent(type="text", text=result["error"])]
        content = result.get("content", "")
        title = result.get("title", "Unknown")
        return [TextContent(type="text", text=f"# {title}\n\n{content[:5000]}")]

    elif name == "search_techniques":
        # Search both writeup DB and local skills
        vuln_class = arguments["vuln_class"]
        results = engine.search(f"{vuln_class} exploitation technique bypass", limit=5)
        payloads = engine.search_payloads(vuln_class)

        output = f"## Techniques for {vuln_class}\n\n"
        if payloads and "No payloads found" not in payloads:
            output += f"### From payload database:\n{payloads[:2000]}\n\n"
        if results:
            output += f"### From writeup database ({len(results)} results):\n"
            for r in results:
                output += f"- [{r['score']:.2f}] {r['title']}: {r['content'][:200]}...\n"
        return [TextContent(type="text", text=output)]

    elif name == "search_payloads":
        result = engine.search_payloads(arguments["vuln_type"])
        return [TextContent(type="text", text=result)]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
