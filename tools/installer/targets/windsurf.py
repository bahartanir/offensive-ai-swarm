"""Windsurf target.

Verified against docs.windsurf.com (April 2026):
  - Rules (project):  .windsurf/rules/*.md (per file; frontmatter 'trigger',
                      optional 'globs' + 'description'; ≤12,000 chars each)
  - Rules (global):   ~/.codeium/windsurf/memories/global_rules.md (single
                      file; no frontmatter; ≤6,000 chars)
  - MCP (user only):  ~/.codeium/windsurf/mcp_config.json
                      (docs don't publish a project-scope MCP path)
  - Workflows:        .windsurf/workflows/*.md — manual slash commands
  - Skills:           .windsurf/skills/<name>/SKILL.md — model-invoked
                      (YAML frontmatter: name + description)
  - Subagents:        not supported — agents degrade to skills.

The 12K/6K char caps are enforced by Windsurf, so we chunk conservatively.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..base import DetectResult, InstallContext, InstallResult, Target
from ..scopes import Scope, windsurf_home
from .. import translators


MAX_RULE_CHARS = 11_500   # leave 500-char headroom under the 12,000 cap
MAX_GLOBAL_RULE_CHARS = 5_500  # leave 500-char headroom under the 6,000 cap


class Windsurf(Target):
    id = "windsurf"
    display_name = "Windsurf"

    def detect(self) -> DetectResult:
        found = windsurf_home().exists() or shutil.which("windsurf") is not None
        return DetectResult(
            target=self.id,
            installed=found,
            install_hint="https://windsurf.com/download",
        )

    def install(self, ctx: InstallContext) -> InstallResult:
        result = InstallResult(target=self.id, scope=ctx.scope)
        if ctx.render_root is not None:
            bundle = ctx.render_root / "providers" / "windsurf"
            base = bundle / ".windsurf"
            self._install_project_rules(ctx, result, base)
            self._install_workflows(ctx, result, base)
            self._install_skills(ctx, result, base)
            self._install_agents_md_at(ctx, result, bundle / "AGENTS.md")
            self._install_mcp(ctx, result, dest=bundle / "mcp_config.json")
        elif ctx.scope is Scope.PROJECT:
            base = ctx.project_root / ".windsurf"
            self._install_project_rules(ctx, result, base)
            self._install_workflows(ctx, result, base)
            self._install_skills(ctx, result, base)
            if ctx.sources.mcp_servers:
                result.warnings.append(
                    "Windsurf MCP configuration is user-scope only "
                    "(~/.codeium/windsurf/mcp_config.json). Re-run with "
                    "--scope global to install the bounty-platforms + "
                    "writeup-search servers."
                )
        else:
            base = windsurf_home()
            self._install_global_rules(ctx, result)
            self._install_workflows(ctx, result, base)  # base/global_workflows/
            self._install_skills(ctx, result, base)
            self._install_mcp(ctx, result)
        return result

    def _install_agents_md_at(self, ctx, result, dest: Path) -> None:
        text = translators.workspace_agents_digest(
            ctx.sources.rules,
            heading=translators.SHARED_AGENTS_MD_HEADING,
            mode=self._mode_for_install(ctx),
            repo_root=ctx.sources.repo_root,
            max_chars=30_000,
        )
        self._write_text(dest, text, ctx, result)

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
            body = rule.body
            slug = translators.slug(rule.name)
            single = rules_dir / f"pentest-agents-{slug}.md"
            if len(body) <= MAX_RULE_CHARS:
                # File no longer needs chunking — clean up any stale chunked
                # variants from a previous render (e.g. file shrank below
                # the 12K cap or got merged).
                for stale in rules_dir.glob(f"pentest-agents-{slug}-*.md"):
                    if stale != single:
                        stale.unlink()
                text = translators.render_windsurf_rule(
                    rule, mode, repo_root, trigger="always_on",
                )
                self._write_text(single, text, ctx, result)
                continue
            # Chunk — also clean up the unchunked single-file variant if it
            # exists from a previous render where the file was still small.
            if single.exists():
                single.unlink()
            chunks = _chunk(body, MAX_RULE_CHARS)
            for idx, chunk in enumerate(chunks, 1):
                dest = rules_dir / f"pentest-agents-{slug}-{idx}.md"
                from ..sources import Rule
                sub = Rule(name=f"{rule.name}-{idx}", body=chunk, source_path=rule.source_path)
                self._write_text(
                    dest,
                    translators.render_windsurf_rule(
                        sub, mode, repo_root, trigger="always_on",
                    ),
                    ctx, result,
                )
            result.warnings.append(
                f"Rule '{rule.name}' split into {len(chunks)} files to fit Windsurf's 12K/file cap"
            )

    def _install_global_rules(self, ctx, result) -> None:
        dest = windsurf_home() / "memories" / "global_rules.md"
        text = translators.rules_digest(
            ctx.sources.rules,
            heading="# pentest-agents — Windsurf global rules\n",
            mode=self._mode_for_install(ctx),
            repo_root=ctx.sources.repo_root,
            max_chars=MAX_GLOBAL_RULE_CHARS,
        )
        self._write_text(dest, text, ctx, result)

    def _install_workflows(self, ctx, result, base: Path) -> None:
        # Project: .windsurf/workflows/  |  Global: ~/.codeium/windsurf/global_workflows/
        subdir = "workflows" if base.name == ".windsurf" else "global_workflows"
        workflows_dir = base / subdir
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for cmd in ctx.sources.commands:
            body = translators.preprocess_body(cmd.body, mode, repo_root)
            if len(body) > MAX_RULE_CHARS:
                body = body[:MAX_RULE_CHARS].rstrip() + "\n\n...[truncated]\n"
            # Workflows don't take frontmatter per current docs — plain MD only.
            text = f"# {cmd.description or cmd.name}\n\n{body}"
            dest = workflows_dir / f"pentest-agents-{translators.slug(cmd.name)}.md"
            self._write_text(dest, text, ctx, result)

    def _install_skills(self, ctx, result, base: Path) -> None:
        skills_dir = base / "skills"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        # Agents become skills (no subagents in Windsurf).
        for agent in ctx.sources.agents:
            root = skills_dir / f"agent-{translators.slug(agent.name)}"
            self._write_text(
                root / "SKILL.md",
                translators.render_skill_from_agent(agent, mode, repo_root),
                ctx, result,
            )
        # Native repo skills pass through (with body preprocessing).
        for skill in ctx.sources.skills:
            root = skills_dir / f"pentest-agents-{translators.slug(skill.name)}"
            source = (skill.source_dir or Path()) / "SKILL.md"
            raw = source.read_text(encoding="utf-8") if source.exists() else skill.body
            body = translators.preprocess_body(raw, mode, repo_root)
            self._write_text(root / "SKILL.md", body, ctx, result)
            for rel, data in skill.supporting_files.items():
                self._write_bytes(root / rel, data, ctx, result)

    def _install_mcp(self, ctx, result, dest: Path | None = None) -> None:
        if not ctx.sources.mcp_servers:
            return
        if dest is None:
            dest = windsurf_home() / "mcp_config.json"
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
                entry["serverUrl"] = s.url
            if s.env:
                entry["env"] = dict(s.env)
            patch[s.name] = entry
        self._merge_json(dest, patch, "mcpServers", ctx, result)
        if not in_render and ctx.scope is Scope.PROJECT:
            result.warnings.append(
                "Windsurf MCP config is user-scope only — wrote "
                f"{dest} regardless of --scope project"
            )


def _chunk(text: str, size: int) -> list[str]:
    chunks: list[str] = []
    lines = text.splitlines(keepends=True)
    buf = ""
    for line in lines:
        if len(buf) + len(line) > size and buf:
            chunks.append(buf)
            buf = ""
        buf += line
    if buf:
        chunks.append(buf)
    return chunks
