"""Target registry — add new targets here."""
from __future__ import annotations

from ..base import Target
from .claude_code import ClaudeCode
from .codex import CodexCli
from .copilot import VsCodeCopilot
from .cursor import Cursor
from .gemini import GeminiCli
from .openclaw import OpenClaw
from .windsurf import Windsurf

ALL_TARGETS: list[type[Target]] = [
    ClaudeCode,
    CodexCli,
    GeminiCli,
    Cursor,
    Windsurf,
    VsCodeCopilot,
    OpenClaw,
]


def by_id(target_id: str) -> type[Target] | None:
    for t in ALL_TARGETS:
        if t.id == target_id:
            return t
    return None


def all_ids() -> list[str]:
    return [t.id for t in ALL_TARGETS]
