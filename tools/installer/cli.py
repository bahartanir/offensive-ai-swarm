"""pentest-agents CLI entry point."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from . import manifest as manifest_mod
from . import sources as sources_mod
from .base import InstallContext, InstallResult
from .report import Report
from .scopes import Scope, project_root, manifest_path
from .targets import ALL_TARGETS, all_ids, by_id


def _repo_root_for_sources(cwd: Path) -> Path:
    """Where to read agents/commands/etc. from.

    When running via `python3 -m tools.installer` from the repo clone,
    this is the repo itself. When running via a published wheel, package
    data under pentest_agents_data/ holds the same files — we fall back
    to that location.
    """
    import importlib.util
    # 1. Current working directory, if it looks like the repo.
    if (cwd / ".claude" / "agents").exists():
        return cwd
    # 2. Parent of this installer package (repo clone layout).
    here = Path(__file__).resolve().parent.parent.parent
    if (here / ".claude" / "agents").exists():
        return here
    # 3. Installed package data (after pip install).
    spec = importlib.util.find_spec("pentest_agents_data")
    if spec is not None and spec.submodule_search_locations:
        data = Path(spec.submodule_search_locations[0])
        if (data / "agents").exists():
            return data.parent  # layout: <...>/pentest_agents_data/<subdirs>
    raise SystemExit(
        "Could not locate pentest-agents source material. "
        "Run the installer from a clone of the repo, or install via pipx."
    )


def _parse_target_list(value: str) -> list[str]:
    value = value.strip()
    if value == "all":
        return all_ids()
    requested = [v.strip() for v in value.split(",") if v.strip()]
    unknown = set(requested) - set(all_ids())
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown target(s): {', '.join(sorted(unknown))}. "
            f"known: {', '.join(all_ids())} or 'all'"
        )
    return requested


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pentest-agents",
        description=(
            "Install the pentest-agents framework into Claude Code and other "
            "AI coding tools. Each target gets the correct format for its "
            "current spec — agents, skills, commands, rules, and MCP servers."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument(
            "--targets", type=_parse_target_list, default=all_ids(),
            help="comma-separated target IDs or 'all' (default: all)",
        )
        sp.add_argument(
            "--scope", choices=[Scope.GLOBAL.value, Scope.PROJECT.value],
            default=Scope.PROJECT.value,
            help="install scope (default: project)",
        )
        sp.add_argument(
            "--project-root", type=Path, default=None,
            help="override project root (default: nearest git ancestor of cwd)",
        )

    sp_install = sub.add_parser("install", help="install into selected targets")
    add_common(sp_install)
    sp_install.add_argument("--dry-run", action="store_true")
    sp_install.add_argument("--force", action="store_true",
                            help="overwrite existing files / MCP entries")

    sp_uninstall = sub.add_parser("uninstall", help="reverse a previous install")
    add_common(sp_uninstall)

    sp_verify = sub.add_parser("verify", help="check installed files still match manifest")
    add_common(sp_verify)

    sub.add_parser("list", help="print supported targets and detection result")

    sp_render = sub.add_parser(
        "render",
        help="render providers/<id>/ for each target (committed to git)",
    )
    sp_render.add_argument(
        "--targets", type=_parse_target_list, default=all_ids(),
        help="comma-separated target IDs or 'all' (default: all)",
    )
    sp_render.add_argument(
        "--render-root", type=Path, default=None,
        help="output root (default: repo root); writes to <root>/providers/<id>/",
    )
    sp_render.add_argument(
        "--check", action="store_true",
        help="render to a temp dir and exit non-zero if it differs from on-disk",
    )

    return p


def _resolve_scope(ns) -> Scope:
    return Scope.GLOBAL if ns.scope == Scope.GLOBAL.value else Scope.PROJECT


def _cmd_list(_ns) -> int:
    for cls in ALL_TARGETS:
        inst = cls()
        det = inst.detect()
        state = f"v{det.version}" if det.version else (
            "installed" if det.installed else "not detected"
        )
        print(f"  {cls.id:<14} {cls.display_name:<24} [{state}]")
    return 0


def _cmd_install(ns) -> int:
    scope = _resolve_scope(ns)
    proj_root = ns.project_root or project_root()
    repo = _repo_root_for_sources(Path.cwd())
    sources = sources_mod.load(repo)
    print(f"Loaded sources from {repo} ({sources.summary()})")
    print(f"Scope: {scope}   Project: {proj_root}")
    print(f"Targets: {', '.join(ns.targets)}\n")

    report = Report()
    manifest = manifest_mod.load(manifest_path(scope, proj_root))
    for target_id in ns.targets:
        cls = by_id(target_id)
        if cls is None:
            continue
        target = cls()
        det = target.detect()
        if not det.installed and not ns.dry_run and not ns.force:
            print(f"[skip] {target_id}: not detected (hint: {det.install_hint}) "
                  f"— re-run with --force to install anyway")
            continue
        if scope not in det.supported_scopes:
            print(f"[skip] {target_id}: does not support --scope {scope}")
            continue
        ctx = InstallContext(
            sources=sources, scope=scope, project_root=proj_root,
            dry_run=ns.dry_run, force=ns.force,
        )
        result = target.install(ctx)
        report.add(result)
        if not ns.dry_run and result.entries_for_manifest:
            manifest_mod.remove_entries_for(manifest, target_id, str(scope))
            entry = manifest_mod.new_target_entry(target_id, str(scope), __version__)
            entry.files = list(result.entries_for_manifest)
            manifest.entries.append(entry)

    if not ns.dry_run:
        manifest_mod.save(manifest, manifest_path(scope, proj_root))

    print(report.render(dry_run=ns.dry_run))
    return 0 if report.ok else 1


def _cmd_uninstall(ns) -> int:
    scope = _resolve_scope(ns)
    proj_root = ns.project_root or project_root()
    mp = manifest_path(scope, proj_root)
    report = Report()
    for target_id in ns.targets:
        cls = by_id(target_id)
        if cls is None:
            continue
        target = cls()
        r = target.uninstall(scope, mp)
        report.add(r)
    # If the manifest is now empty, scrub it and its parent dir.
    if mp.exists():
        remaining = manifest_mod.load(mp)
        if not remaining.entries:
            mp.unlink()
            parent = mp.parent
            if parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
    print(report.render(dry_run=False))
    return 0


def _cmd_verify(ns) -> int:
    scope = _resolve_scope(ns)
    proj_root = ns.project_root or project_root()
    mp = manifest_path(scope, proj_root)
    all_ok = True
    for target_id in ns.targets:
        cls = by_id(target_id)
        if cls is None:
            continue
        target = cls()
        v = target.verify(scope, mp)
        status = "OK " if v.ok else "DRIFT"
        print(
            f"  [{status}] {target_id}  present={v.files_present} "
            f"missing={len(v.files_missing)} drifted={len(v.files_drifted)}"
        )
        for w in v.warnings:
            print(f"      ! {w}")
        for p in v.files_missing:
            print(f"      - missing: {p}")
        for p in v.files_drifted:
            print(f"      ~ drifted: {p}")
        all_ok = all_ok and v.ok
    return 0 if all_ok else 2


def _cmd_render(ns) -> int:
    repo = _repo_root_for_sources(Path.cwd())
    sources = sources_mod.load(repo)
    render_root = ns.render_root or repo

    if ns.check:
        return _cmd_render_check(ns, repo, sources)

    print(f"Loaded sources from {repo} ({sources.summary()})")
    print(f"Render root: {render_root}")
    print(f"Targets: {', '.join(ns.targets)}\n")

    report = Report()
    for target_id in ns.targets:
        if target_id == "claude_code":
            continue  # source target, no rendering needed
        cls = by_id(target_id)
        if cls is None:
            continue
        target = cls()
        ctx = InstallContext(
            sources=sources,
            scope=Scope.PROJECT,  # arbitrary — render uses render_root
            project_root=repo,
            render_root=render_root,
            force=True,  # render is always force-overwrite
        )
        result = target.render(ctx)
        report.add(result)

    print(report.render(dry_run=False))
    return 0 if report.ok else 1


def _cmd_render_check(ns, repo: Path, sources) -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for target_id in ns.targets:
            if target_id == "claude_code":
                continue
            cls = by_id(target_id)
            if cls is None:
                continue
            target = cls()
            ctx = InstallContext(
                sources=sources,
                scope=Scope.PROJECT,
                project_root=repo,
                render_root=tmp,
                force=True,
            )
            target.render(ctx)

        committed = repo / "providers"
        rendered = tmp / "providers"
        if not committed.exists():
            print(
                f"DRIFT: {committed} does not exist. Run "
                f"`pentest-agents render` to generate it."
            )
            return 1
        diffs = _dirs_diff(committed, rendered)
        if diffs:
            for d in diffs[:30]:
                print(f"  ~ {d}")
            if len(diffs) > 30:
                print(f"  ... and {len(diffs) - 30} more")
            print(
                f"\nDRIFT: {len(diffs)} file(s) differ. Run "
                f"`pentest-agents render --targets all`."
            )
            return 1
        print("OK: providers/ is in sync with .claude/ source.")
        return 0


def _dirs_diff(a: Path, b: Path) -> list[Path]:
    """Return relative paths that differ (presence or content)."""
    a_files = {p.relative_to(a) for p in a.rglob("*") if p.is_file()}
    b_files = {p.relative_to(b) for p in b.rglob("*") if p.is_file()}
    diffs: list[Path] = list(a_files ^ b_files)
    for rel in a_files & b_files:
        if (a / rel).read_bytes() != (b / rel).read_bytes():
            diffs.append(rel)
    return sorted(diffs)


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    if ns.command == "install":
        return _cmd_install(ns)
    if ns.command == "uninstall":
        return _cmd_uninstall(ns)
    if ns.command == "verify":
        return _cmd_verify(ns)
    if ns.command == "list":
        return _cmd_list(ns)
    if ns.command == "render":
        return _cmd_render(ns)
    return 2


if __name__ == "__main__":
    sys.exit(main())
