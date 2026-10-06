"""End-of-run install report: one short table per target + overall summary."""
from __future__ import annotations

from dataclasses import dataclass, field

from .base import InstallResult


def _fmt_count(results: list[InstallResult]) -> str:
    ok = sum(1 for r in results if r.ok)
    return f"{ok}/{len(results)} ok"


@dataclass
class Report:
    results: list[InstallResult] = field(default_factory=list)

    def add(self, r: InstallResult) -> None:
        self.results.append(r)

    def render(self, dry_run: bool) -> str:
        heading = "DRY-RUN — no changes applied." if dry_run else "Install complete."
        lines = [
            f"\n{heading}\n",
            f"Targets: {_fmt_count(self.results)}",
            "",
        ]
        for r in self.results:
            status = "OK " if r.ok else "ERR"
            lines.append(
                f"  [{status}] {r.target:<14} scope={r.scope}  "
                f"wrote {len(r.files_written)} file(s), "
                f"merged {len(r.merges)} json-point(s), "
                f"skipped {len(r.files_skipped)}, "
                f"warnings {len(r.warnings)}, errors {len(r.errors)}"
            )
            for w in r.warnings:
                lines.append(f"      ! {w}")
            for e in r.errors:
                lines.append(f"      X {e}")
            for path, reason in r.files_skipped:
                lines.append(f"      - skip {path} — {reason}")
        lines.append("")
        return "\n".join(lines)

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.results)
