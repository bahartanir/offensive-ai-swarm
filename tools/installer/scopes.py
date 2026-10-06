"""Cross-platform path resolution for each target.

Every target has its own opinion about where user-scope vs project-scope
config lives. The helpers here give each target a single function to ask
for its canonical path on the current OS.
"""
from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Scope(str, Enum):
    GLOBAL = "global"   # user-scope: ~/.<tool>/
    PROJECT = "project"  # project-scope: ./<tool-dir>/

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Platform:
    name: str  # "linux" | "darwin" | "windows"

    @property
    def is_windows(self) -> bool:
        return self.name == "windows"

    @property
    def is_mac(self) -> bool:
        return self.name == "darwin"

    @property
    def is_linux(self) -> bool:
        return self.name == "linux"


def detect_platform() -> Platform:
    system = platform.system().lower()
    if system == "darwin":
        return Platform("darwin")
    if system == "windows":
        return Platform("windows")
    return Platform("linux")  # treat other POSIX as linux for config dirs


def home() -> Path:
    return Path(os.path.expanduser("~"))


def vscode_user_dir(plat: Platform | None = None) -> Path:
    """Path to VS Code's per-user config directory (holds settings.json, mcp.json)."""
    plat = plat or detect_platform()
    if plat.is_mac:
        return home() / "Library" / "Application Support" / "Code" / "User"
    if plat.is_windows:
        base = os.environ.get("APPDATA") or str(home() / "AppData" / "Roaming")
        return Path(base) / "Code" / "User"
    return home() / ".config" / "Code" / "User"


def codex_home() -> Path:
    override = os.environ.get("CODEX_HOME")
    return Path(override) if override else home() / ".codex"


def gemini_home() -> Path:
    return home() / ".gemini"


def claude_home() -> Path:
    return home() / ".claude"


def cursor_home() -> Path:
    return home() / ".cursor"


def windsurf_home() -> Path:
    # Windsurf (Codeium) stores per-user config under ~/.codeium/windsurf/.
    return home() / ".codeium" / "windsurf"


def openclaw_home() -> Path:
    # OpenClaw keeps user config, auth, and skills under ~/.openclaw/.
    # See https://docs.openclaw.ai/concepts/agent-workspace.
    return home() / ".openclaw"


def project_root(cwd: Path | None = None) -> Path:
    """Best-effort project root: nearest ancestor with .git, else cwd."""
    start = (cwd or Path.cwd()).resolve()
    for d in [start, *start.parents]:
        if (d / ".git").exists():
            return d
    return start


def manifest_path(scope: Scope, project: Path | None = None) -> Path:
    """Where we store the list of files we've written so uninstall is safe."""
    if scope is Scope.GLOBAL:
        base = Path(os.environ.get("XDG_CONFIG_HOME", home() / ".config"))
        return base / "pentest-agents" / "manifest.json"
    root = project or project_root()
    return root / ".pentest-agents" / "manifest.json"
