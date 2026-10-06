"""OpenAI Codex CLI target.

Verified against https://developers.openai.com/codex/ (May 2026):
  - Config: ~/.codex/config.toml (user) | .codex/config.toml (project)
  - MCP:    [mcp_servers.<name>] blocks inside config.toml
  - Rules:  AGENTS.md (walks up the tree; closer-to-cwd overrides)
  - Agents: ~/.codex/agents/<name>.toml | .codex/agents/<name>.toml
  - Skills: ~/.agents/skills/<name>/ (user) | <project>/.agents/skills/<name>/
            (the agentskills.io standard path; Codex picks up both scopes).
            Each skill is a directory holding SKILL.md (name + description
            frontmatter + body) and agents/openai.yaml. We set
            policy.allow_implicit_invocation = false on every skill so
            commands like /hunt and /submit only fire on explicit
            `$<name>` invocation — never via prompt-matching, which would
            be unsafe on a pentest workspace.

Custom prompts (`~/.codex/prompts/<name>.md`) were the previous mechanism
for reusable instructions and are deprecated by OpenAI in favor of skills.
We do not emit them.

We write TOML by hand — no deps.
"""
from __future__ import annotations

import shutil
from pathlib import Path

try:
    import tomllib  # Python 3.11+ stdlib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[import-not-found]

from ..base import DetectResult, InstallContext, InstallResult, Target, VerifyResult
from ..scopes import Scope, codex_home
from .. import translators
from .. import manifest as manifest_mod


class CodexCli(Target):
    id = "codex"
    display_name = "OpenAI Codex CLI"

    def detect(self) -> DetectResult:
        found = shutil.which("codex") is not None
        return DetectResult(
            target=self.id,
            installed=found,
            install_hint="npm install -g @openai/codex",
        )

    def install(self, ctx: InstallContext) -> InstallResult:
        result = InstallResult(target=self.id, scope=ctx.scope)
        base = self._codex_dir(ctx)
        # AGENTS.md
        self._install_agents_md(ctx, result)
        # Native subagents
        self._install_subagents(ctx, result, base)
        # Skills — replace the deprecated `~/.codex/prompts/` mechanism.
        # Project scope works for skills (unlike prompts), so each scope
        # writes to its proper .agents/skills/ tree.
        self._install_skills(ctx, result, self._skills_parent_dir(ctx))
        # config.toml with MCP entries
        self._install_config_toml(ctx, result, base)
        return result

    # ---------------------------------------------------------------
    # Path resolution — single source of truth for where each piece lands.
    # ---------------------------------------------------------------

    def _codex_dir(self, ctx: InstallContext) -> Path:
        """Where the .codex/ tree (agents, config.toml) goes."""
        if ctx.render_root is not None:
            return ctx.render_root / "providers" / "codex" / ".codex"
        return codex_home() if ctx.scope is Scope.GLOBAL else ctx.project_root / ".codex"

    def _agents_md_dest(self, ctx: InstallContext) -> Path:
        """Where AGENTS.md lands."""
        if ctx.render_root is not None:
            return ctx.render_root / "providers" / "codex" / "AGENTS.md"
        if ctx.scope is Scope.GLOBAL:
            return codex_home() / "AGENTS.md"
        return ctx.project_root / "AGENTS.md"

    def _skills_parent_dir(self, ctx: InstallContext) -> Path:
        """Parent of skills/ — the agentskills.io standard puts this at
        `.agents/` (not `.codex/`). Project scope: <project>/.agents/.
        Global scope: ~/.agents/. Render: providers/codex/.agents/.
        """
        if ctx.render_root is not None:
            return ctx.render_root / "providers" / "codex" / ".agents"
        if ctx.scope is Scope.GLOBAL:
            return Path.home() / ".agents"
        return ctx.project_root / ".agents"

    @staticmethod
    def _mode_for_install(ctx: InstallContext) -> "translators.PathMode":
        """Pick the right PathMode for the body preprocessor."""
        if ctx.render_root is not None:
            return translators.PathMode.RENDER
        return (
            translators.PathMode.INSTALL_GLOBAL if ctx.scope is Scope.GLOBAL
            else translators.PathMode.INSTALL_PROJECT
        )

    # ---------------------------------------------------------------
    def _install_agents_md(self, ctx, result) -> None:
        # Codex respects project_doc_max_bytes (default 32 KiB). Keep a margin.
        # The heading is shared with other AGENTS.md-reading targets so that
        # all co-installers write byte-identical content.
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
        self._write_text(self._agents_md_dest(ctx), text, ctx, result)

    def _install_subagents(self, ctx, result, base: Path) -> None:
        agents_dir = base / "agents"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for agent in ctx.sources.agents:
            dest = agents_dir / f"{agent.name}.toml"
            self._write_text(
                dest,
                translators.render_agent_for_codex(agent, mode, repo_root),
                ctx, result,
            )

    def _install_skills(self, ctx, result, base: Path) -> None:
        """Write each command as a Codex Skill under <base>/skills/<name>/.

        Layout per skill (per https://developers.openai.com/codex/skills
        and the agentskills.io spec):

            <base>/skills/<name>/
                SKILL.md            # name + description frontmatter, body
                agents/openai.yaml  # policy.allow_implicit_invocation: false

        The argument-hint from the source frontmatter is preserved as a
        skill metadata field — Codex doesn't read it today but it keeps
        the round-trip clean and tools that render the menu can use it.

        Implicit invocation is disabled on every skill so commands like
        /hunt and /submit only run on explicit `$<name>` — matching them
        to free-form prompts on a pentest workspace would be unsafe.
        """
        skills_dir = base / "skills"
        mode = self._mode_for_install(ctx)
        repo_root = ctx.sources.repo_root
        for cmd in ctx.sources.commands:
            skill_root = skills_dir / cmd.name
            body = translators.preprocess_body(cmd.body, mode, repo_root)
            # Use the shared YAML emitter so values containing ": ", "#",
            # brackets, etc. get double-quoted. Bare-string interpolation
            # breaks Codex's strict YAML parser on descriptions like
            # "Usage: /hunt target.com [...]".
            pairs: list[tuple[str, object]] = [("name", cmd.name)]
            if cmd.description:
                pairs.append(("description", cmd.description))
            if cmd.argument_hint:
                pairs.append(("argument-hint", cmd.argument_hint))
            frontmatter = translators._render_yaml_frontmatter(pairs)
            skill_md = frontmatter + "\n" + body
            self._write_text(skill_root / "SKILL.md", skill_md, ctx, result)

            openai_yaml = (
                "policy:\n"
                "  allow_implicit_invocation: false\n"
            )
            self._write_text(
                skill_root / "agents" / "openai.yaml",
                openai_yaml, ctx, result,
            )

    def _install_config_toml(self, ctx, result, base: Path) -> None:
        config = base / "config.toml"
        # Read existing content to preserve user config; merge only our
        # [mcp_servers.*] tables.
        existing = ""
        if config.exists():
            existing = config.read_text(encoding="utf-8")
            try:
                tomllib.loads(existing)
            except tomllib.TOMLDecodeError as e:
                result.errors.append(f"{config}: invalid TOML ({e})")
                return

        # Remove any previous [mcp_servers.<name>] block we're about to rewrite.
        names = [s.name for s in ctx.sources.mcp_servers]
        stripped = _strip_mcp_blocks(existing, names)

        # In render mode the bundle lives at <repo>/providers/codex/.
        # The MCP server scripts live at <repo>/mcp-*-server/server.py.
        # Sources.load() absolutizes those paths; rewrite them back to
        # ".." so the bundle stays portable inside the cloned repo.
        in_render = ctx.render_root is not None
        repo_str = str(ctx.sources.repo_root)

        # Build our blocks.
        blocks: list[str] = []
        for s in ctx.sources.mcp_servers:
            args = list(s.args)
            if in_render:
                args = [
                    a.replace(repo_str, "../..") if isinstance(a, str) else a
                    for a in args
                ]
            lines = [f"[mcp_servers.{s.name}]"]
            if s.is_stdio():
                lines.append(f'command = "{s.command}"')
                if args:
                    arr = ", ".join(f'"{a}"' for a in args)
                    lines.append(f"args = [{arr}]")
            if s.url:
                lines.append(f'url = "{s.url}"')
            # env_vars forwards parent-process env vars by name. Required
            # for the bounty-platforms server because Codex's MCP launcher
            # does not inherit the parent shell env by default — without
            # this, BUGCROWD_EMAIL etc. are invisible to the child and
            # the provider falls back to unauthenticated public scraping.
            if s.env_vars:
                arr = ", ".join(f'"{v}"' for v in s.env_vars)
                lines.append(f"env_vars = [{arr}]")
            if s.env:
                lines.append("")
                lines.append(f"[mcp_servers.{s.name}.env]")
                for k, v in s.env.items():
                    lines.append(f'{k} = "{v}"')
            blocks.append("\n".join(lines))

        new_text = stripped.rstrip()
        if new_text:
            new_text += "\n\n"
        new_text += "\n\n".join(blocks) + "\n"

        # Record via the base helper so uninstall reverses the write.
        # Because this file may contain other user data we record it as a
        # "merge" entry — but our surgical merge-keys are the full TOML
        # table names we touched.
        if ctx.dry_run:
            result.merges.append((config, [f"mcp_servers.{n}" for n in names]))
            return
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(new_text, encoding="utf-8")
        result.merges.append((config, [f"mcp_servers.{n}" for n in names]))
        result.entries_for_manifest.append(manifest_mod.FileEntry(
            path=str(config),
            sha256=manifest_mod.sha256_text(new_text),
            kind="merge",
            merge_keys=[f"toml:mcp_servers.{n}" for n in names],
        ))


    def uninstall(self, scope, manifest_path):  # type: ignore[override]
        # Delegate to the shared implementation, then fix up config.toml
        # (which isn't JSON and needs a TOML-aware strip instead of the
        # base class's JSON unmerge).
        manifest = manifest_mod.load(manifest_path)
        result = InstallResult(target=self.id, scope=scope)
        removed = manifest_mod.remove_entries_for(manifest, self.id, str(scope))
        if not removed:
            result.warnings.append(f"No manifest entry for {self.id}/{scope}")
            return result
        for entry in removed:
            for f in entry.files:
                p = __import__("pathlib").Path(f.path)
                if f.kind == "file":
                    self._remove_file(p, result, backup_path=f.backup_path)
                elif f.kind == "merge" and any(
                    k.startswith("toml:") for k in f.merge_keys
                ):
                    self._strip_toml_blocks(p, f.merge_keys, result)
                else:
                    self._unmerge_json(p, f.merge_keys, result)
        manifest_mod.save(manifest, manifest_path)
        self._prune_empty_dirs(scope, result)
        return result

    def _strip_toml_blocks(self, path, merge_keys, result):
        if not path.exists():
            return
        server_names = [
            k.split(":", 1)[1].split(".", 1)[1]
            for k in merge_keys if k.startswith("toml:mcp_servers.")
        ]
        text = path.read_text(encoding="utf-8")
        new = _strip_mcp_blocks(text, server_names).strip()
        if not new:
            path.unlink()
            self._prune_empty_parents(path)
        else:
            path.write_text(new + "\n", encoding="utf-8")
        result.merges.append((path, merge_keys))

    def _prune_empty_dirs(self, scope, result):
        pass  # handled by base._prune_empty_parents via file removals


def _strip_mcp_blocks(toml_text: str, server_names: list[str]) -> str:
    """Remove `[mcp_servers.<name>]` and `[mcp_servers.<name>.<sub>]` blocks.

    Leaves everything else (other user TOML, our previous non-target tables)
    intact.
    """
    if not toml_text:
        return ""
    lines = toml_text.splitlines()
    out: list[str] = []
    skipping = False
    prefixes = tuple(f"[mcp_servers.{n}" for n in server_names)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if stripped.startswith(prefixes):
                skipping = True
                continue
            skipping = False
        if skipping:
            continue
        out.append(line)
    # collapse trailing/leading blank runs
    text = "\n".join(out).strip("\n")
    return text + ("\n" if text else "")
