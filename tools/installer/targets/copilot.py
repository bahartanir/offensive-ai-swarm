"""VS Code GitHub Copilot target (Agent Mode).

Verified against code.visualstudio.com/docs/copilot/* (April 2026, MCP GA as
of VS Code 1.102, Custom Agents renamed from 'chat modes' in ~1.106):

  - Instructions (general, always-on):  .github/copilot-instructions.md
  - Instructions (path-scoped):         .github/instructions/*.instructions.md
  - Prompts (slash commands):           .github/prompts/<name>.prompt.md
  - Custom agents:                      .github/agents/<name>.agent.md
  - MCP (workspace):                    .vscode/mcp.json
  - MCP (user profile):                 <user-data>/mcp.json

User-scope instruction/agent paths are not OS-absolute-path-documented by
Microsoft — the docs defer to the `MCP: Open User Configuration` command.
For scope=global we therefore only wire MCP (which HAS a documented
cross-platform user path) and skip per-user instructions/prompts/agents,
warning the user to paste those via VS Code commands if desired.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..base import DetectResult, InstallContext, InstallResult, Target
from ..scopes import Scope, vscode_user_dir
from .. import translators


class VsCodeCopilot(Target):
    id = "copilot"
    display_name = "VS Code GitHub Copilot"

    def detect(self) -> DetectResult:
        # Treat the presence of the `code` CLI OR the user data dir as install
        # evidence (headless servers may not have `code` on PATH).
        found = shutil.which("code") is not None or vscode_user_dir().exists()
        return DetectResult(
            target=self.id,
            installed=found,
            install_hint="https://code.visualstudio.com + GitHub Copilot extension",
        )

    def install(self, ctx: InstallContext) -> InstallResult:
        result = InstallResult(target=self.id, scope=ctx.scope)
        if ctx.render_root is not None:
            self._install_repo_instructions(ctx, result)
            self._install_prompts(ctx, result)
            self._install_custom_agents(ctx, result)
            self._install_mcp(ctx, result, self._mcp_dest(ctx))
        elif ctx.scope is Scope.PROJECT:
            self._install_repo_instructions(ctx, result)
            self._install_prompts(ctx, result)
            self._install_custom_agents(ctx, result)
            self._install_mcp(ctx, result, self._mcp_dest(ctx))
        else:
            # Only MCP has a documented cross-platform user path.
            self._install_mcp(ctx, result, vscode_user_dir() / "mcp.json")
            result.warnings.append(
                "VS Code user-scope instructions/prompts/agents don't have a "
                "documented OS-absolute path — wrote MCP only. Use "
                "Command Palette → 'Chat: New Prompt File' (User storage) "
                "to add prompts per user."
            )
        return result

    # ---------------------------------------------------------------
    def _github_dir(self, ctx: InstallContext) -> Path:
        """Where the .github/ subtree lives."""
        if ctx.render_root is not None:
            return ctx.render_root / "providers" / "copilot" / ".github"
        return ctx.project_root / ".github"

    def _mcp_dest(self, ctx: InstallContext) -> Path:
        if ctx.render_root is not None:
            return ctx.render_root / "providers" / "copilot" / ".vscode" / "mcp.json"
        return ctx.project_root / ".vscode" / "mcp.json"

    @staticmethod
    def _mode_for_install(ctx: InstallContext) -> "translators.PathMode":
        if ctx.render_root is not None:
            return translators.PathMode.RENDER
        return (
            translators.PathMode.INSTALL_GLOBAL if ctx.scope is Scope.GLOBAL
            else translators.PathMode.INSTALL_PROJECT
        )

    # ---------------------------------------------------------------
    def _install_repo_instructions(self, ctx, result) -> None:
        # The always-on one:
        gh = self._github_dir(ctx)
        dest = gh / "copilot-instructions.md"
        text = translators.workspace_agents_digest(
            ctx.sources.rules,
            heading="# pentest-agents — workspace instructions\n",
            mode=self._mode_for_install(ctx),
            repo_root=ctx.sources.repo_root,
            max_chars=None,
        )
        self._write_text(dest, text, ctx, result)

        # Per-rule path-scoped instructions (`**` applies everywhere).
        ins_dir = gh / "instructions"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for rule in ctx.sources.rules:
            dest = ins_dir / f"pentest-agents-{translators.slug(rule.name)}.instructions.md"
            self._write_text(
                dest,
                translators.render_copilot_instruction(rule, mode, repo_root),
                ctx, result,
            )

    def _install_prompts(self, ctx, result) -> None:
        prompts_dir = self._github_dir(ctx) / "prompts"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for cmd in ctx.sources.commands:
            dest = prompts_dir / f"{cmd.name}.prompt.md"
            self._write_text(
                dest,
                translators.render_copilot_prompt(cmd, mode, repo_root),
                ctx, result,
            )

    def _install_custom_agents(self, ctx, result) -> None:
        agents_dir = self._github_dir(ctx) / "agents"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        all_agent_names = [a.name for a in ctx.sources.agents]
        for agent in ctx.sources.agents:
            dest = agents_dir / f"{agent.name}.agent.md"
            self._write_text(
                dest,
                translators.render_agent_for_copilot(
                    agent, mode, repo_root, all_agent_names,
                ),
                ctx, result,
            )

    def _install_mcp(self, ctx, result, dest: Path) -> None:
        if not ctx.sources.mcp_servers:
            return
        in_render = ctx.render_root is not None
        repo_str = str(ctx.sources.repo_root)
        # VS Code's mcp.json uses a "servers" top-level key, NOT "mcpServers".
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
                entry["type"] = s.transport
                entry["url"] = s.url
            if s.env:
                entry["env"] = dict(s.env)
            patch[s.name] = entry
        self._merge_json(dest, patch, "servers", ctx, result)
