"""Abstract Target interface.

Each supported AI tool implements one subclass of Target. The CLI dispatches
uniformly across targets and scopes.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from . import manifest as manifest_mod
from .scopes import Scope
from .sources import SourceBundle


@dataclass
class InstallContext:
    """Everything a target needs to perform an install."""
    sources: SourceBundle
    scope: Scope
    project_root: Path   # only meaningful when scope == PROJECT
    dry_run: bool = False
    force: bool = False  # overwrite conflicting files instead of warning
    # When set, targets render to <render_root>/providers/<id>/ using
    # PathMode.RENDER instead of installing to project_root or scope home.
    render_root: Path | None = None
    # Scaffold owns generated provider files inside bounty workspaces and
    # refreshes them on every update. In that mode, backing up every changed
    # generated file would litter the workspace with hundreds of .pa-backup
    # files, so scaffold disables backups while the standalone installer keeps
    # the conservative default.
    backup_existing: bool = True


@dataclass
class InstallResult:
    target: str
    scope: Scope
    files_written: list[Path] = field(default_factory=list)
    files_skipped: list[tuple[Path, str]] = field(default_factory=list)  # (path, reason)
    merges: list[tuple[Path, list[str]]] = field(default_factory=list)   # (path, keys merged)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    entries_for_manifest: list[manifest_mod.FileEntry] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class DetectResult:
    target: str
    installed: bool
    version: str | None = None
    install_hint: str | None = None
    supported_scopes: tuple[Scope, ...] = (Scope.GLOBAL, Scope.PROJECT)


@dataclass
class VerifyResult:
    target: str
    scope: Scope
    files_present: int = 0
    files_missing: list[Path] = field(default_factory=list)
    files_drifted: list[Path] = field(default_factory=list)  # content changed since install
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.files_missing and not self.files_drifted


class Target(ABC):
    """Base class for every IDE/CLI plugin."""

    id: str = ""         # e.g. "claude_code", "codex"
    display_name: str = ""

    # ------------------------------------------------------------
    # Required API
    # ------------------------------------------------------------

    @abstractmethod
    def detect(self) -> DetectResult: ...

    @abstractmethod
    def install(self, ctx: InstallContext) -> InstallResult: ...

    def render(self, ctx: InstallContext) -> InstallResult:
        """Render provider output to <ctx.render_root>/providers/<id>/.

        Default implementation calls install() — subclasses with non-trivial
        install paths (Codex, Copilot, etc.) must override to redirect file
        destinations into the providers/ tree. ctx.render_root must be set.
        """
        if ctx.render_root is None:
            raise ValueError(f"{self.id}.render() requires ctx.render_root")
        return self.install(ctx)

    # Uninstall is shared — reads manifest, removes files/merges we wrote.
    def uninstall(self, scope: Scope, manifest_path: Path) -> InstallResult:
        result = InstallResult(target=self.id, scope=scope)
        manifest = manifest_mod.load(manifest_path)
        removed = manifest_mod.remove_entries_for(manifest, self.id, str(scope))
        if not removed:
            result.warnings.append(f"No manifest entry for {self.id}/{scope}")
            return result
        for entry in removed:
            for f in entry.files:
                p = Path(f.path)
                if f.kind == "file":
                    self._remove_file(p, result, backup_path=f.backup_path)
                elif f.kind == "merge":
                    self._unmerge_json(p, f.merge_keys, result)
        manifest_mod.save(manifest, manifest_path)
        return result

    def verify(self, scope: Scope, manifest_path: Path) -> VerifyResult:
        result = VerifyResult(target=self.id, scope=scope)
        manifest = manifest_mod.load(manifest_path)
        entries = [
            e for e in manifest.entries
            if e.target == self.id and e.scope == str(scope)
        ]
        if not entries:
            result.warnings.append("Not installed (no manifest entry)")
            return result
        for entry in entries:
            for f in entry.files:
                p = Path(f.path)
                if not p.exists():
                    result.files_missing.append(p)
                    continue
                result.files_present += 1
                if f.kind == "file":
                    got = manifest_mod.sha256_bytes(p.read_bytes())
                    if got != f.sha256:
                        result.files_drifted.append(p)
        return result

    # ------------------------------------------------------------
    # Helpers available to subclasses
    # ------------------------------------------------------------

    def _write_text(
        self,
        dest: Path,
        text: str,
        ctx: InstallContext,
        result: InstallResult,
    ) -> bool:
        """Write `text` to `dest`, respecting dry-run / force / manifest."""
        return self._write_bytes(dest, text.encode("utf-8"), ctx, result)

    def _write_bytes(
        self,
        dest: Path,
        data: bytes,
        ctx: InstallContext,
        result: InstallResult,
    ) -> bool:
        sha = manifest_mod.sha256_bytes(data)
        entry = manifest_mod.FileEntry(path=str(dest), sha256=sha, kind="file")

        if dest.exists():
            existing = dest.read_bytes()
            if existing == data:
                # idempotent — still record in manifest so uninstall works
                result.entries_for_manifest.append(entry)
                return True
            if not ctx.force:
                result.files_skipped.append(
                    (dest, "exists (use --force to overwrite)")
                )
                return False
            # Back up the existing file before overwriting — but only in
            # install mode. Render mode regenerates the providers/ tree
            # in-place; we don't want stray .pa-backup files committed.
            if ctx.render_root is None and ctx.backup_existing:
                backup = dest.with_suffix(dest.suffix + ".pa-backup")
                if not ctx.dry_run:
                    backup.write_bytes(existing)
                entry.backup_path = str(backup)

        if ctx.dry_run:
            result.files_written.append(dest)
            return True

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        result.files_written.append(dest)
        result.entries_for_manifest.append(entry)
        return True

    def _merge_json(
        self,
        dest: Path,
        patch: dict,
        top_key: str,
        ctx: InstallContext,
        result: InstallResult,
    ) -> None:
        """Merge `patch` into the `top_key` object of the JSON at `dest`.

        Creates the file if missing. Only keys under `top_key` are considered
        "ours" for uninstall — we never remove user keys at other top levels.
        """
        current: dict = {}
        if dest.exists():
            try:
                current = json.loads(dest.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                result.errors.append(f"{dest} is not valid JSON")
                return
        sub = dict(current.get(top_key) or {})
        our_keys = list(patch.keys())
        # Conflict detection
        for k in our_keys:
            if k in sub and sub[k] != patch[k] and not ctx.force:
                result.warnings.append(
                    f"{dest}:{top_key}.{k} already differs (use --force to overwrite)"
                )
        sub.update(patch)
        current[top_key] = sub

        rendered = json.dumps(current, indent=2) + "\n"
        if ctx.dry_run:
            result.merges.append((dest, our_keys))
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rendered, encoding="utf-8")
        result.merges.append((dest, our_keys))
        result.entries_for_manifest.append(manifest_mod.FileEntry(
            path=str(dest),
            sha256=manifest_mod.sha256_text(rendered),
            kind="merge",
            merge_keys=[f"{top_key}.{k}" for k in our_keys],
        ))

    # ----------------- uninstall helpers -----------------

    def _remove_file(
        self,
        path: Path,
        result: InstallResult,
        backup_path: str | None = None,
    ) -> None:
        if path.exists():
            path.unlink()
            result.files_written.append(path)  # reused as "touched"
        # Restore the user's original file if we backed one up on install.
        if backup_path:
            bp = Path(backup_path)
            if bp.exists():
                bp.rename(path)
        self._prune_empty_parents(path)

    def _prune_empty_parents(self, path: Path) -> None:
        """Remove empty directories upward from `path`, stopping at home/root.

        Guards against deleting anything at or above the user's home dir so
        we never remove e.g. ~/.claude/ itself if a user has other tooling
        writing into it.
        """
        stops = {Path.home(), Path("/"), Path.home().parent}
        current = path.parent
        while current not in stops and current.exists():
            try:
                if any(current.iterdir()):
                    break
                current.rmdir()
            except OSError:
                break
            current = current.parent

    def _unmerge_json(
        self,
        path: Path,
        keys: list[str],
        result: InstallResult,
    ) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            result.warnings.append(f"{path} is not valid JSON, skipping unmerge")
            return
        changed = False
        for dotted in keys:
            if "." not in dotted:
                continue
            top, _, leaf = dotted.partition(".")
            sub = data.get(top)
            if isinstance(sub, dict) and leaf in sub:
                sub.pop(leaf, None)
                changed = True
                if not sub:
                    data.pop(top, None)
        if changed:
            # If the whole file is now empty, delete it rather than leaving {}.
            if data == {}:
                path.unlink()
            else:
                path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result.merges.append((path, keys))
