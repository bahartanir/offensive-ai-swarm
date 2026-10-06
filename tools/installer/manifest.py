"""Install-manifest tracking — enables clean uninstall.

Every file we create and every merge-point we touch is recorded in a JSON
manifest. Uninstall reads the manifest in reverse and undoes each action.
We never touch anything not in the manifest.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA_VERSION = 1


@dataclass
class FileEntry:
    path: str                 # absolute path
    sha256: str               # hash of what we wrote — lets uninstall detect user edits
    kind: str = "file"        # "file" (created by us) | "merge" (our keys inside a shared file)
    backup_path: str | None = None  # set when we replaced an existing file
    merge_keys: list[str] = field(default_factory=list)  # top-level JSON keys we added


@dataclass
class TargetEntry:
    target: str               # "claude_code" | "codex" | ...
    scope: str                # "global" | "project"
    installed_at: float
    pentest_agents_version: str
    files: list[FileEntry] = field(default_factory=list)


@dataclass
class Manifest:
    schema_version: int = SCHEMA_VERSION
    entries: list[TargetEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Disk I/O
# ---------------------------------------------------------------------------

def load(path: Path) -> Manifest:
    if not path.exists():
        return Manifest()
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = []
    for e in raw.get("entries", []):
        files = [FileEntry(**f) for f in e.get("files", [])]
        entries.append(TargetEntry(
            target=e["target"],
            scope=e["scope"],
            installed_at=e.get("installed_at", 0.0),
            pentest_agents_version=e.get("pentest_agents_version", "?"),
            files=files,
        ))
    return Manifest(
        schema_version=raw.get("schema_version", SCHEMA_VERSION),
        entries=entries,
    )


def save(manifest: Manifest, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": manifest.schema_version,
        "entries": [
            {
                "target": e.target,
                "scope": e.scope,
                "installed_at": e.installed_at,
                "pentest_agents_version": e.pentest_agents_version,
                "files": [asdict(f) for f in e.files],
            }
            for e in manifest.entries
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_target_entry(target: str, scope: str, version: str) -> TargetEntry:
    return TargetEntry(
        target=target, scope=scope, installed_at=time.time(),
        pentest_agents_version=version,
    )


def remove_entries_for(manifest: Manifest, target: str, scope: str) -> list[TargetEntry]:
    """Strip any previous entry for (target, scope) and return the removed ones."""
    to_remove = [e for e in manifest.entries if e.target == target and e.scope == scope]
    manifest.entries = [
        e for e in manifest.entries if not (e.target == target and e.scope == scope)
    ]
    return to_remove
