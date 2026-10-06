# rag-builder

FAISS / RAG database builder for the **writeup-search** MCP server shipped with
pentest-agents. Ports the core ingestion pipeline from
[HeXSS mcp-rag](../../../../Projects/HeXSS/agent/mcp-rag) so you can build your
own writeup corpus locally without redistributing scraped hacktivity.

> **Safety.** Every destructive action (git clone, embed, write to SQLite /
> FAISS) is gated behind `--execute`. Running `build.py` without it is always
> read-only and simply prints what it would do. This prevents accidental wipes
> of an existing index.

---

## Layout

```
rag-builder/
├── build.py              # CLI entry point (dry-run by default)
├── config.yaml           # verbatim copy of HeXSS config.yaml — edit freely
├── repos.yaml            # default list of repos to index
├── repos-skipped.yaml    # repos known to be too large / broken
├── rag_builder/          # core pipeline (chunker, embedder, db, index, ...)
└── data/                 # created on first --execute (git-ignored)
    ├── metadata.db       # SQLite: documents + chunks + FTS5
    └── index.faiss       # FAISS IndexIDMap2 (IndexFlatIP, 384-dim)
```

## Install

The builder pulls FAISS and sentence-transformers lazily — they are only
required when you actually run `--execute`. Use the `writeup-search-faiss`
extra from the project's `pyproject.toml`:

```bash
cd /root/Tools/pentest-agents-suite/pentest-agents
uv sync --extra writeup-search-faiss
```

Or, if you are not using uv:

```bash
pip install faiss-cpu sentence-transformers pyyaml numpy
```

## Usage

```bash
cd rag-builder

# 1. Inspect the plan — no network, no writes.
python3 build.py status
python3 build.py ingest                # dry-run by default

# 2. Pre-flight: probe every URL with `git ls-remote` (opt-in, network).
python3 build.py ingest --check-remotes

# 3. Actually clone + index every repo from repos.yaml into ./data/.
python3 build.py ingest --execute
python3 build.py ingest --execute --check-remotes   # skip unreachable first

# 4. Index a single repo.
python3 build.py ingest --url https://github.com/swisskyrepo/PayloadsAllTheThings.git --execute

# 5. Rebuild FAISS from SQLite (e.g. after swapping the embedding model).
python3 build.py rebuild --execute
```

### Skip list

`repos-skipped.yaml` (beside `repos.yaml`) is loaded automatically — any URL
listed there is dropped from the ingest plan with a `[skip]` annotation.
Flags:

| Flag             | Effect |
|------------------|--------|
| `--skip-list P`  | Use `P` instead of `repos-skipped.yaml`. |
| `--no-skip-list` | Ignore the skip file even if present. |

### Remote availability (`--check-remotes`)

Opt-in pre-flight. For each URL, runs `git ls-remote --heads --exit-code`
in a thread pool so 146 repos finish in ~5 s. Flags:

| Flag                   | Default | Effect |
|------------------------|---------|--------|
| `--check-remotes`      | off     | Enable the probe. |
| `--remote-timeout N`   | `15` s  | Per-repo git timeout. |
| `--remote-workers N`   | `16`    | Parallel probes. |

Unreachable repos are printed as `[gone] URL (reason)` and excluded from the
ingest plan. Reasons you may see: `repository not found`, `empty repo (no
refs)`, `timeout after 15s`, `Authentication failed`. Under `--execute`,
these repos are quietly skipped instead of wasting a clone attempt.

### Overrides

```bash
# Use a different config / repos file:
python3 build.py --config ./my-config.yaml --repos ./my-repos.yaml ingest

# Send output somewhere other than ./data/:
python3 build.py --data-dir ~/.local/share/pentest-writeups ingest --execute
```

### Hooking the MCP server

The writeup-search MCP server (`mcp-writeup-server/server.py`) reads its index
from `$WRITEUP_DB_DIR`, defaulting to `~/.local/share/pentest-writeups/`.
After a successful build, point it at the output:

```bash
export WRITEUP_DB_DIR="/root/Tools/pentest-agents-suite/pentest-agents/rag-builder/data"
python3 ../mcp-writeup-server/server.py --test
```

You can also set it in `.mcp.json`:

```json
{
  "mcpServers": {
    "writeup-search": {
      "command": "python3",
      "args": ["mcp-writeup-server/server.py"],
      "env": {
        "WRITEUP_DB_DIR": "/abs/path/to/rag-builder/data"
      }
    }
  }
}
```

## Config

`config.yaml` is a verbatim copy of the upstream HeXSS config. Edit to taste —
the most useful knobs:

| Field                  | Default                 | Notes |
|------------------------|-------------------------|-------|
| `data_dir`             | `data`                  | Resolved relative to `config.yaml`. |
| `embedding_model`      | `all-MiniLM-L6-v2`      | Must match whatever the MCP server loads. |
| `host_allowlist`       | `[github.com, gitlab.com]` | URLs outside the list are skipped. |
| `max_file_size_bytes`  | `10 MiB`                | Per-file ceiling. |
| `max_repo_size_mb`     | `1000`                  | Rejects mega-repos (e.g. sajjadium/ctf-archives = 34 GB). |
| `clone_timeout_seconds`| `300`                   | Passed to `git clone`. |

## Data flow

```
repos.yaml
    │
    ▼
  build.py ingest --execute
    │
    ▼
 clone --depth 1 → walk *.md|*.txt|*.rst → chunk (header-aware, 500 tok)
    │
    ▼
 SHA-256 dedup → SQLite chunks + chunk_instances (+ FTS5)
    │
    ▼
 sentence-transformers embed (L2-normalized) → FAISS IndexIDMap2(FlatIP)
    │
    ▼
 data/metadata.db + data/index.faiss
```

SQLite is the source of truth. FAISS is derived and can be rebuilt via
`build.py rebuild --execute`. Atomic swap (fsync + `os.replace`) keeps the
index crash-safe.

## Credit

The ingestion pipeline is a direct port of the MIT-licensed code in
`/root/Projects/HeXSS/agent/mcp-rag/mcp_rag/`. Only the CLI wrapper, safety
gates, and project wiring are new here.
