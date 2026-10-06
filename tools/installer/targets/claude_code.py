"""Claude Code target — 1:1 install of agents, skills, commands, MCP.

Path contract (verified April 2026 via https://code.claude.com/docs/en/):
  - Agents:   <scope>/.claude/agents/<name>.md        (YAML frontmatter)
  - Commands: <scope>/.claude/commands/<name>.md      (legacy but GA)
  - Skills:   <scope>/.claude/skills/<name>/SKILL.md  (preferred modern form)
  - MCP (project): .mcp.json at project root          (top-level mcpServers)
  - MCP (user):    ~/.claude.json                     (top-level mcpServers)
  - Rules:    CLAUDE.md at scope root                 (project root or ~/.claude/)
  - Settings: <scope>/.claude/settings.json           (hooks / permissions)

We do NOT write MCP into settings.json — the schema rejects it per current docs.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..base import DetectResult, InstallContext, InstallResult, Target
from ..scopes import Scope, claude_home


CLAUDE_MD_HEADER = """<!-- pentest-agents managed block — edit above/below, leave this block alone -->

# pentest-agents workspace

This workspace uses the pentest-agents framework. Agents, skills, and commands
are in `.claude/`. Two MCP servers are wired up: `bounty-platforms` and
`writeup-search`. See https://github.com/H-mmer/pentest-agents for the full
model.

"""


class ClaudeCode(Target):
    id = "claude_code"
    display_name = "Claude Code"

    def detect(self) -> DetectResult:
        found = shutil.which("claude") is not None
        return DetectResult(
            target=self.id,
            installed=found,
            install_hint="https://claude.com/product/claude-code",
        )

    # --------------------------------------------------------------
    def install(self, ctx: InstallContext) -> InstallResult:
        result = InstallResult(target=self.id, scope=ctx.scope)
        base = self._base_dir(ctx)
        self._install_agents(ctx, result, base)
        self._install_commands(ctx, result, base)
        self._install_skills(ctx, result, base)
        self._install_rules(ctx, result, base)
        self._install_mcp(ctx, result)
        return result

    # --------------------------------------------------------------
    def _base_dir(self, ctx: InstallContext) -> Path:
        if ctx.scope is Scope.GLOBAL:
            return claude_home()
        return ctx.project_root / ".claude"

    def _install_agents(self, ctx, result, base: Path) -> None:
        target_dir = base / "agents"
        for agent in ctx.sources.agents:
            dest = target_dir / f"{agent.name}.md"
            if agent.source_path is not None:
                text = agent.source_path.read_text(encoding="utf-8")
            else:
                text = agent.body
            self._write_text(dest, text, ctx, result)

    def _install_commands(self, ctx, result, base: Path) -> None:
        # Post-April-2026 Claude Code: commands and skills are unified.
        # Write as .claude/skills/<name>/SKILL.md (preferred modern form),
        # preserving the source's frontmatter (including
        # disable-model-invocation so the model doesn't auto-invoke a
        # user-only slash command).
        skills_dir = base / "skills"
        for cmd in ctx.sources.commands:
            dest = skills_dir / cmd.name / "SKILL.md"
            if cmd.source_path is not None:
                text = cmd.source_path.read_text(encoding="utf-8")
            else:
                text = cmd.body
            self._write_text(dest, text, ctx, result)

    def _install_skills(self, ctx, result, base: Path) -> None:
        skills_dir = base / "skills"
        for skill in ctx.sources.skills:
            skill_root = skills_dir / skill.name
            # SKILL.md
            source = (skill.source_dir or Path()) / "SKILL.md"
            text = (
                source.read_text(encoding="utf-8") if source.exists() else skill.body
            )
            self._write_text(skill_root / "SKILL.md", text, ctx, result)
            # supporting files — copy verbatim
            for rel, data in skill.supporting_files.items():
                self._write_bytes(skill_root / rel, data, ctx, result)

    def _install_rules(self, ctx, result, base: Path) -> None:
        # Claude reads CLAUDE.md at scope root. For global, that's ~/.claude/CLAUDE.md.
        # For project, that's <project>/CLAUDE.md (project root, NOT inside .claude/).
        claude_md = (
            base / "CLAUDE.md"
            if ctx.scope is Scope.GLOBAL
            else ctx.project_root / "CLAUDE.md"
        )
        source_claude = ctx.sources.repo_root / "CLAUDE.md"
        if (
            ctx.scope is Scope.PROJECT
            and ctx.project_root.resolve() == ctx.sources.repo_root.resolve()
            and source_claude.exists()
        ):
            text = source_claude.read_text(encoding="utf-8")
        elif ctx.scope is Scope.PROJECT:
            from tools.scaffold import _CUSTOM_NOTES_PLACEHOLDER, _generate_claude_md

            platform, program = _infer_workspace_identity(ctx.project_root)
            text = (
                _generate_claude_md(ctx.project_root, platform, program)
                + _CUSTOM_NOTES_PLACEHOLDER
            )
        else:
            pieces = [CLAUDE_MD_HEADER]
            for rule in ctx.sources.rules:
                pieces.append(f"## rules/{rule.name}\n\n{rule.body}\n")
            text = "".join(pieces)
        self._write_text(claude_md, text, ctx, result)

    def _install_mcp(self, ctx, result) -> None:
        if not ctx.sources.mcp_servers:
            return
        servers_patch = {}
        for s in ctx.sources.mcp_servers:
            entry: dict = {"type": s.transport}
            if s.command:
                entry["command"] = s.command
                entry["args"] = list(s.args)
            if s.url:
                entry["url"] = s.url
            if s.env:
                entry["env"] = dict(s.env)
            servers_patch[s.name] = entry

        dest = (
            Path.home() / ".claude.json"
            if ctx.scope is Scope.GLOBAL
            else ctx.project_root / ".mcp.json"
        )
        self._merge_json(dest, servers_patch, "mcpServers", ctx, result)


def _infer_workspace_identity(project_root: Path) -> tuple[str, str]:
    """Best-effort platform/program labels for a generic installer run."""
    platform = "bug bounty"
    program = project_root.name

    scope_yaml = project_root / "scope.yaml"
    if scope_yaml.exists():
        text = scope_yaml.read_text(encoding="utf-8", errors="replace")
        platform_match = re.search(r"^platform:\s*['\"]?([^'\"\n]+)['\"]?\s*$", text, re.M)
        program_match = re.search(r"^program:\s*['\"]?([^'\"\n]+)['\"]?\s*$", text, re.M)
        if platform_match:
            platform = platform_match.group(1).strip()
        if program_match:
            program = program_match.group(1).strip()
        return platform, program

    scope_txt = project_root / ".scope.txt"
    if scope_txt.exists():
        first = scope_txt.read_text(encoding="utf-8", errors="replace").splitlines()
        if first:
            line = first[0].lstrip("#").strip()
            if "—" in line:
                left, _, right = line.partition("—")
                platform = left.strip() or platform
                program = right.strip() or program
            elif "-" in line:
                left, _, right = line.partition("-")
                platform = left.strip() or platform
                program = right.strip() or program

    return platform, program
