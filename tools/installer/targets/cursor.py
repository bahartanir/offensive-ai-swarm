"""Cursor target.

Verified against cursor.com/docs (April 2026):
  - Rules:     .cursor/rules/*.mdc (per file; frontmatter: description, globs,
               alwaysApply). User-scope rules are managed through the UI; no
               file path is published. We write project-scope rules only for
               scope=project; for scope=global we skip rules and rely on
               AGENTS.md instead (officially supported by Cursor).
  - MCP:       .cursor/mcp.json (project) | ~/.cursor/mcp.json (user)
               top-level key "mcpServers".
  - Subagents: none — we write skills under .cursor/skills/<name>/SKILL.md
               as the closest analogue.
  - Commands:  .cursor/commands/<name>.md (supported but being migrated to
               skills). We emit skills, which Cursor recommends.
  - AGENTS.md: supported at repo root; we write it as the portable fallback.

Do NOT emit .cursorrules — removed from current docs.
Do NOT emit custom modes — feature removed in Cursor 2.1.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..base import DetectResult, InstallContext, InstallResult, Target
from ..scopes import Scope, cursor_home
from .. import translators


class Cursor(Target):
    id = "cursor"
    display_name = "Cursor"

    def detect(self) -> DetectResult:
        # Cursor doesn't ship a PATH-exposed CLI by default on every OS;
        # look for its user config dir as the marker.
        home = cursor_home()
        found = home.exists() or shutil.which("cursor") is not None
        return DetectResult(
            target=self.id,
            installed=found,
            install_hint="https://cursor.com/downloads",
        )

    def install(self, ctx: InstallContext) -> InstallResult:
        result = InstallResult(target=self.id, scope=ctx.scope)
        if ctx.render_root is not None:
            # Render: behave like project install but redirect everything
            # under providers/cursor/.
            bundle = ctx.render_root / "providers" / "cursor"
            base = bundle / ".cursor"
            self._install_project_rules(ctx, result, base)
            self._install_skills(ctx, result, base)
            self._install_agents_md_at(ctx, result, bundle / "AGENTS.md")
            self._install_mcp(ctx, result, base / "mcp.json")
        elif ctx.scope is Scope.PROJECT:
            base = ctx.project_root / ".cursor"
            self._install_project_rules(ctx, result, base)
            self._install_skills(ctx, result, base)
            self._install_agents_md_at(ctx, result, ctx.project_root / "AGENTS.md")
            self._install_mcp(ctx, result, base / "mcp.json")
        else:
            base = cursor_home()
            self._install_skills(ctx, result, base)
            # No file-based user-scope rules — Cursor manages User Rules in UI.
            result.warnings.append(
                "User-scope Cursor rules are managed in the Cursor UI. "
                "Skills + MCP installed; paste rules/ content into Settings → Rules manually."
            )
            self._install_mcp(ctx, result, base / "mcp.json")
        return result

    @staticmethod
    def _mode_for_install(ctx: InstallContext) -> "translators.PathMode":
        if ctx.render_root is not None:
            return translators.PathMode.RENDER
        return (
            translators.PathMode.INSTALL_GLOBAL if ctx.scope is Scope.GLOBAL
            else translators.PathMode.INSTALL_PROJECT
        )

    # ---------------------------------------------------------------
    def _install_project_rules(self, ctx, result, base: Path) -> None:
        rules_dir = base / "rules"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for rule in ctx.sources.rules:
            dest = rules_dir / f"pentest-agents-{translators.slug(rule.name)}.mdc"
            text = translators.render_cursor_rule(
                rule, mode, repo_root,
                always_apply=(rule.name in ("hunting", "never-submit")),
            )
            self._write_text(dest, text, ctx, result)

    def _install_skills(self, ctx, result, base: Path) -> None:
        skills_dir = base / "skills"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        # Native skills shipped by the repo.
        for skill in ctx.sources.skills:
            root = skills_dir / f"pentest-agents-{translators.slug(skill.name)}"
            source = (skill.source_dir or Path()) / "SKILL.md"
            raw = source.read_text(encoding="utf-8") if source.exists() else skill.body
            body = translators.preprocess_body(raw, mode, repo_root)
            self._write_text(root / "SKILL.md", body, ctx, result)
            for rel, data in skill.supporting_files.items():
                self._write_bytes(root / rel, data, ctx, result)
        # Agents degrade to skills (Cursor has no subagents).
        for agent in ctx.sources.agents:
            root = skills_dir / f"agent-{translators.slug(agent.name)}"
            self._write_text(
                root / "SKILL.md",
                translators.render_skill_from_agent(agent, mode, repo_root),
                ctx, result,
            )
        # Commands also degrade to skills (Cursor is steering that way).
        for cmd in ctx.sources.commands:
            root = skills_dir / f"cmd-{translators.slug(cmd.name)}"
            cmd_body = translators.preprocess_body(cmd.body, mode, repo_root)
            text = (
                f"---\nname: {cmd.name}\ndescription: "
                f"{translators._yaml_scalar(cmd.description or cmd.name)}\n---\n\n"
                f"{cmd_body}"
            )
            self._write_text(root / "SKILL.md", text, ctx, result)

    def _install_agents_md_at(self, ctx, result, dest: Path) -> None:
        # Matches the Codex heading exactly so both targets write the same
        # bytes and neither drifts after the other rewrites it.
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
        patch = {}
        for s in ctx.sources.mcp_servers:
            args = list(s.args)
            if in_render:
                args = [
                    a.replace(repo_str, "../..") if isinstance(a, str) else a
                    for a in args
                ]
            entry: dict = {}
            if s.is_stdio():
                entry["type"] = "stdio"
                entry["command"] = s.command
                if args:
                    entry["args"] = args
            if s.url:
                entry["url"] = s.url
            if s.env:
                entry["env"] = dict(s.env)
            patch[s.name] = entry
        self._merge_json(dest, patch, "mcpServers", ctx, result)
