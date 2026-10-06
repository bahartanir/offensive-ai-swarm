"""OpenClaw target — personal AI assistant / autonomous agent runtime.

Verified against the OpenClaw documentation (April 2026) via
https://docs.openclaw.ai/llms.txt and its referenced pages:

  - Workspace root : ``~/.openclaw/workspace/``
                     (configurable via ``agents.defaults.workspace``)
  - Skills (managed): ``~/.openclaw/skills/<name>/SKILL.md``
                     (docs: "recommended location for third-party bundles")
  - Skills (project): ``<project>/.agents/skills/<name>/SKILL.md``
                     (AgentSkills-standard path)
  - Rules          : ``~/.openclaw/workspace/AGENTS.md`` (global)
                   | ``<project>/AGENTS.md``             (project)
  - MCP config     : ``~/.openclaw/openclaw.json`` → ``mcp.servers.<name>``
                     (JSON5; we write plain JSON which is a valid subset)

Notes
-----
OpenClaw has no native "subagent" concept — Claude-style agents are
rendered as skills (same degradation as Cursor / Windsurf). Slash commands
are gateway-native in OpenClaw and can't be user-authored via files today,
so we render our repo's commands as skills too — they show up as
``/skill <name>`` invocations.

Project scope never touches ``~/.openclaw/openclaw.json`` because that
file is user-level only; MCP install is therefore only wired when
``--scope global``. A warning is emitted in project mode so the user
knows to repeat the install globally if they want MCP.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .. import manifest as manifest_mod
from .. import translators
from ..base import DetectResult, InstallContext, InstallResult, Target
from ..scopes import Scope, openclaw_home


class OpenClaw(Target):
    id = "openclaw"
    display_name = "OpenClaw"

    def detect(self) -> DetectResult:
        # The docs-recommended install is ``npm i -g openclaw``; the binary
        # is ``openclaw`` on PATH. Fallback: the user's ``~/.openclaw/`` dir
        # gets created on first ``openclaw onboard``.
        found = shutil.which("openclaw") is not None or openclaw_home().exists()
        return DetectResult(
            target=self.id,
            installed=found,
            install_hint="npm install -g openclaw  (or https://openclaw.ai)",
        )

    # ----------------------------------------------------------------------
    def install(self, ctx: InstallContext) -> InstallResult:
        result = InstallResult(target=self.id, scope=ctx.scope)
        if ctx.render_root is not None:
            self._install_render(ctx, result)
        elif ctx.scope is Scope.GLOBAL:
            self._install_global(ctx, result)
        else:
            self._install_project(ctx, result)
        return result

    # ----------------------------------------------------------------------
    # RENDER — providers/openclaw/{AGENTS.md, .agents/skills/, openclaw.json}
    # ----------------------------------------------------------------------
    def _install_render(self, ctx: InstallContext, result: InstallResult) -> None:
        bundle = ctx.render_root / "providers" / "openclaw"
        self._install_skills(ctx, result, bundle / ".agents" / "skills")
        self._install_agents_md(ctx, result, bundle / "AGENTS.md")
        self._install_mcp(ctx, result, bundle / "openclaw.json")

    # ----------------------------------------------------------------------
    # GLOBAL
    # ----------------------------------------------------------------------
    def _install_global(self, ctx: InstallContext, result: InstallResult) -> None:
        home = openclaw_home()
        self._install_skills(ctx, result, home / "skills")
        self._install_agents_md(ctx, result, home / "workspace" / "AGENTS.md")
        self._install_mcp(ctx, result, home / "openclaw.json")

    # ----------------------------------------------------------------------
    # PROJECT
    # ----------------------------------------------------------------------
    def _install_project(self, ctx: InstallContext, result: InstallResult) -> None:
        # AgentSkills convention lives at <project>/.agents/skills/. AGENTS.md
        # sits at the repo root so Codex / Cursor / OpenClaw all read the same
        # file (byte-identical heading via translators.SHARED_AGENTS_MD_HEADING).
        self._install_skills(ctx, result, ctx.project_root / ".agents" / "skills")
        self._install_agents_md(ctx, result, ctx.project_root / "AGENTS.md")
        if ctx.sources.mcp_servers:
            result.warnings.append(
                "OpenClaw MCP configuration is global-only "
                "(~/.openclaw/openclaw.json). Re-run with --scope global "
                "to install the bounty-platforms + writeup-search servers."
            )

    # ----------------------------------------------------------------------
    # shared writers
    # ----------------------------------------------------------------------
    @staticmethod
    def _mode_for_install(ctx: InstallContext) -> "translators.PathMode":
        from ..scopes import Scope as _S
        if ctx.render_root is not None:
            return translators.PathMode.RENDER
        return (
            translators.PathMode.INSTALL_GLOBAL if ctx.scope is _S.GLOBAL
            else translators.PathMode.INSTALL_PROJECT
        )

    def _install_skills(self, ctx, result, skills_dir: Path) -> None:
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        # 1) Repo-native skills — pass through (body preprocessed).
        for skill in ctx.sources.skills:
            root = skills_dir / f"pentest-agents-{translators.slug(skill.name)}"
            source = (skill.source_dir or Path()) / "SKILL.md"
            raw = source.read_text(encoding="utf-8") if source.exists() else skill.body
            body = translators.preprocess_body(raw, mode, repo_root)
            self._write_text(root / "SKILL.md", body, ctx, result)
            for rel, data in skill.supporting_files.items():
                self._write_bytes(root / rel, data, ctx, result)

        # 2) Agents → skills. OpenClaw has no subagent runtime; render as
        #    playbook skills the main agent can follow.
        for agent in ctx.sources.agents:
            root = skills_dir / f"agent-{translators.slug(agent.name)}"
            self._write_text(
                root / "SKILL.md",
                translators.render_skill_from_agent(agent, mode, repo_root),
                ctx,
                result,
            )

        # 3) Slash commands → skills. OpenClaw commands are registered via
        #    the plugin SDK, not via markdown; skills are the user-space
        #    substitute. They show up as ``/skill <name>`` invocations.
        for cmd in ctx.sources.commands:
            root = skills_dir / f"cmd-{translators.slug(cmd.name)}"
            pairs: list[tuple[str, object]] = [
                ("name", cmd.name),
                ("description", cmd.description or cmd.name),
            ]
            frontmatter = translators._render_yaml_frontmatter(pairs)
            cmd_body = translators.preprocess_body(cmd.body, mode, repo_root)
            self._write_text(root / "SKILL.md", frontmatter + cmd_body, ctx, result)

    def _install_agents_md(self, ctx, result, dest: Path) -> None:
        # OpenClaw's AGENTS.md template (docs/reference/templates/AGENTS.md)
        # is short. 30 KB is well within the gateway's prompt budget and
        # matches what Codex / Cursor emit, so a single install for multiple
        # targets produces byte-identical content.
        source_agents = ctx.sources.repo_root / "AGENTS.md"
        if (
            ctx.render_root is None
            and ctx.scope is Scope.PROJECT
            and ctx.project_root.resolve() == ctx.sources.repo_root.resolve()
            and source_agents.exists()
        ):
            text = source_agents.read_text(encoding="utf-8")
        else:
            text = translators.workspace_agents_digest(
                ctx.sources.rules,
                heading=translators.SHARED_AGENTS_MD_HEADING,
                mode=self._mode_for_install(ctx),
                repo_root=ctx.sources.repo_root,
                max_chars=30_000,
            )
        self._write_text(dest, text, ctx, result)

    def _install_mcp(self, ctx, result, dest: Path) -> None:
        if not ctx.sources.mcp_servers:
            return
        in_render = ctx.render_root is not None
        repo_str = str(ctx.sources.repo_root)
        servers_patch: dict = {}
        for s in ctx.sources.mcp_servers:
            args = list(s.args)
            if in_render:
                args = [
                    a.replace(repo_str, "../..") if isinstance(a, str) else a
                    for a in args
                ]
            entry: dict = {}
            if s.is_stdio():
                entry["command"] = s.command
                if args:
                    entry["args"] = args
                if s.env:
                    entry["env"] = dict(s.env)
            if s.url:
                entry["url"] = s.url
                if s.transport and s.transport != "stdio":
                    entry["transport"] = s.transport
            servers_patch[s.name] = entry
        self._merge_nested_json(
            dest,
            ["mcp", "servers"],
            servers_patch,
            ctx,
            result,
        )

    # ----------------------------------------------------------------------
    # JSON helpers — OpenClaw's ``mcp.servers.*`` lives two levels deep, so
    # the base ``_merge_json`` (single-level) isn't enough.
    # ----------------------------------------------------------------------
    def _merge_nested_json(
        self,
        dest: Path,
        path: list[str],
        patch: dict,
        ctx: InstallContext,
        result: InstallResult,
    ) -> None:
        """Merge ``patch`` into ``dest`` at a nested dotted path.

        Uses the same conflict-detection + force-overwrite semantics as the
        base ``_merge_json``. Records a manifest entry whose ``merge_keys``
        are dotted paths like ``mcp.servers.<name>`` so uninstall can
        surgically strip only the keys we wrote.
        """
        current: dict = {}
        if dest.exists():
            try:
                current = json.loads(dest.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                # OpenClaw's config is JSON5 in general. If we can't parse
                # strict JSON we refuse to write rather than risk losing
                # comments / trailing commas that the user added by hand.
                result.errors.append(
                    f"{dest} is not strict JSON (OpenClaw allows JSON5 — "
                    "remove comments/trailing commas or edit by hand)."
                )
                return

        # Walk down to the nested container, creating empty dicts as we go.
        node = current
        for key in path[:-1]:
            nxt = node.get(key)
            if not isinstance(nxt, dict):
                nxt = {}
            node[key] = nxt
            node = nxt

        leaf_key = path[-1]
        sub = dict(node.get(leaf_key) or {})

        our_keys = list(patch.keys())
        for k in our_keys:
            if k in sub and sub[k] != patch[k] and not ctx.force:
                result.warnings.append(
                    f"{dest}:{'.'.join(path)}.{k} already differs "
                    f"(use --force to overwrite)"
                )
        sub.update(patch)
        node[leaf_key] = sub

        rendered = json.dumps(current, indent=2) + "\n"
        dotted = ".".join(path)
        full_keys = [f"{dotted}.{k}" for k in our_keys]

        if ctx.dry_run:
            result.merges.append((dest, full_keys))
            return

        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rendered, encoding="utf-8")
        result.merges.append((dest, full_keys))
        result.entries_for_manifest.append(
            manifest_mod.FileEntry(
                path=str(dest),
                sha256=manifest_mod.sha256_text(rendered),
                kind="merge",
                merge_keys=full_keys,
            )
        )

    # ----------------------------------------------------------------------
    # Uninstall — base class' ``_unmerge_json`` only handles ``<top>.<leaf>``
    # (two segments). OpenClaw needs three (``mcp.servers.<name>``), so we
    # override to walk arbitrary depth.
    # ----------------------------------------------------------------------
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
            parts = dotted.split(".")
            if len(parts) < 2:
                continue
            # Walk down to the container holding the leaf key.
            node = data
            stack: list[tuple[dict, str]] = []
            ok = True
            for p in parts[:-1]:
                if not isinstance(node, dict) or p not in node:
                    ok = False
                    break
                stack.append((node, p))
                node = node[p]
            if not ok or not isinstance(node, dict):
                continue
            leaf = parts[-1]
            if leaf in node:
                node.pop(leaf)
                changed = True
            # Collapse now-empty parents upward so we don't leave
            # ``{"mcp": {"servers": {}}}`` behind.
            while stack:
                parent, key = stack.pop()
                child = parent.get(key)
                if isinstance(child, dict) and not child:
                    parent.pop(key)
                else:
                    break
        if changed:
            if data == {}:
                path.unlink()
            else:
                path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            result.merges.append((path, keys))
