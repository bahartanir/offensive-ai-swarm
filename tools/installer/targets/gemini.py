"""Google Gemini CLI target.

Verified against the google-gemini/gemini-cli docs (April 2026):
  - Config:   ~/.gemini/settings.json (user) | .gemini/settings.json (project)
  - MCP:      settings.json → "mcpServers" key
  - Rules:    GEMINI.md at scope root (walks up tree, closer wins)
  - Agents:   ~/.gemini/agents/*.md | .gemini/agents/*.md (YAML frontmatter)
  - Commands: ~/.gemini/commands/*.toml | .gemini/commands/*.toml
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..base import DetectResult, InstallContext, InstallResult, Target
from ..scopes import Scope, gemini_home
from .. import translators


class GeminiCli(Target):
    id = "gemini"
    display_name = "Google Gemini CLI"

    def detect(self) -> DetectResult:
        found = shutil.which("gemini") is not None
        return DetectResult(
            target=self.id,
            installed=found,
            install_hint="npm install -g @google/gemini-cli",
        )

    def install(self, ctx: InstallContext) -> InstallResult:
        result = InstallResult(target=self.id, scope=ctx.scope)
        base = self._gemini_dir(ctx)
        self._install_gemini_md(ctx, result)
        self._install_agents(ctx, result, base)
        self._install_commands(ctx, result, base)
        self._install_mcp(ctx, result, base)
        return result

    # ---------------------------------------------------------------
    def _gemini_dir(self, ctx: InstallContext) -> Path:
        """Where the .gemini/ tree lives."""
        if ctx.render_root is not None:
            return ctx.render_root / "providers" / "gemini" / ".gemini"
        return gemini_home() if ctx.scope is Scope.GLOBAL else ctx.project_root / ".gemini"

    def _gemini_md_dest(self, ctx: InstallContext) -> Path:
        if ctx.render_root is not None:
            return ctx.render_root / "providers" / "gemini" / "GEMINI.md"
        if ctx.scope is Scope.GLOBAL:
            return gemini_home() / "GEMINI.md"
        return ctx.project_root / "GEMINI.md"

    def _install_gemini_md(self, ctx, result) -> None:
        text = translators.workspace_agents_digest(
            ctx.sources.rules,
            heading="# pentest-agents — persistent instructions for Gemini\n",
            mode=self._mode_for_install(ctx),
            repo_root=ctx.sources.repo_root,
            max_chars=None,
        )
        self._write_text(self._gemini_md_dest(ctx), text, ctx, result)

    @staticmethod
    def _mode_for_install(ctx: InstallContext) -> "translators.PathMode":
        if ctx.render_root is not None:
            return translators.PathMode.RENDER
        return (
            translators.PathMode.INSTALL_GLOBAL if ctx.scope is Scope.GLOBAL
            else translators.PathMode.INSTALL_PROJECT
        )

    def _install_agents(self, ctx, result, base: Path) -> None:
        agents_dir = base / "agents"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for agent in ctx.sources.agents:
            dest = agents_dir / f"{agent.name}.md"
            self._write_text(
                dest,
                translators.render_agent_for_gemini(agent, mode, repo_root),
                ctx, result,
            )

    def _install_commands(self, ctx, result, base: Path) -> None:
        commands_dir = base / "commands"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for cmd in ctx.sources.commands:
            dest = commands_dir / f"{cmd.name}.toml"
            self._write_text(
                dest,
                translators.render_gemini_command(cmd, mode, repo_root),
                ctx, result,
            )

    def _install_mcp(self, ctx, result, base: Path) -> None:
        if not ctx.sources.mcp_servers:
            return
        # Render mode: settings.json sits one dir above .gemini/, in the
        # bundle root (Gemini reads it from project root or ~/.gemini/).
        if ctx.render_root is not None:
            settings = ctx.render_root / "providers" / "gemini" / "settings.json"
        else:
            settings = base / "settings.json"
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
                entry["command"] = s.command
                if args:
                    entry["args"] = args
            if s.url:
                # Gemini uses `httpUrl` for streamable HTTP, `url` for SSE.
                entry["httpUrl" if s.transport == "http" else "url"] = s.url
            if s.env:
                entry["env"] = dict(s.env)
            patch[s.name] = entry
        self._merge_json(settings, patch, "mcpServers", ctx, result)
