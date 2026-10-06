"""Format translators — convert Claude-format agents/commands/rules into
the schema each target expects.

Every translator is pure: input = Agent/Command/Rule plus target tag,
output = the rendered text we'll write to disk. No I/O here.
"""
from __future__ import annotations

import enum
import re
from pathlib import Path
from typing import Iterable

from .sources import Agent, Command, Rule


# ---------------------------------------------------------------------------
# Path / prose preprocessing — applied to every translator's body so the
# same .claude/ source can target Codex/Gemini/Cursor/etc. without manual
# edits per provider.
# ---------------------------------------------------------------------------

class PathMode(enum.Enum):
    """How to rewrite $CLAUDE_PROJECT_DIR references in agent/command bodies.

    RENDER             — rewrite to ".." (relative to providers/<id>/).
    INSTALL_PROJECT    — rewrite to absolute path of cloned pentest-agents repo.
    INSTALL_GLOBAL     — same as INSTALL_PROJECT (the source repo is the anchor).
    """
    RENDER = "render"
    INSTALL_PROJECT = "install_project"
    INSTALL_GLOBAL = "install_global"


def rewrite_paths(text: str, mode: PathMode, repo_root: Path) -> str:
    """Replace $CLAUDE_PROJECT_DIR references with the right anchor for the mode.

    Render mode: bundles live at <repo>/providers/<id>/, so the repo root
    is two levels up. Use '../..' so paths like 'tools/brain.py',
    'skills/hunt-rce/SKILL.md', and 'mcp-*-server/server.py' resolve from
    the repo root regardless of where inside the bundle the path appears.
    """
    if mode is PathMode.RENDER:
        replacement = "../.."
    else:
        replacement = str(repo_root)
    return text.replace("$CLAUDE_PROJECT_DIR", replacement)


# (Pattern, replacement) — applied in order. Plain-string substitution.
# Order matters: longer / more-specific patterns first so we don't leave
# fragments behind.
_CLAUDE_SUBSTITUTIONS: list[tuple[str, str]] = [
    # Tool-name swaps (run BEFORE brand swap so "the Agent tool" doesn't
    # become "the AI coding tool tool" via partial matches).
    ("the Agent tool", "the subagent dispatch tool"),
    ("the Task tool", "the subagent dispatch tool"),
    # Brand swaps.
    ("Claude Code", "the AI coding tool"),
    ("Claude Sonnet 4.5", "the model"),
    ("Claude Sonnet 4.6", "the model"),
    ("Claude Sonnet", "the model"),
    ("Claude Opus 4.6", "the model"),
    ("Claude Opus 4.7", "the model"),
    ("Claude Opus", "the model"),
    ("Claude Haiku", "the model"),
    ("Opus 4.7", "the model"),
    ("Opus 4.6", "the model"),
    ("Sonnet 4.6", "the model"),
    ("Sonnet 4.5", "the model"),
    # Inherited-model directives — these are Claude-specific dispatch
    # instructions that don't apply to other tools.
    ('`model: "inherit"`', ""),
    ('model: "inherit"', ""),
]


def strip_claude_prose(text: str) -> str:
    """Remove or rewrite Claude-specific phrasing from agent/command bodies.

    Idempotent: running twice produces the same output as running once.
    Plain-string substitution; order is significant (see table above).
    """
    out = text
    for pat, repl in _CLAUDE_SUBSTITUTIONS:
        out = out.replace(pat, repl)
    return out


def preprocess_body(text: str, mode: PathMode, repo_root: Path) -> str:
    """Apply all per-translator preprocessing in one place.

    Order matters: strip prose first (so the model-inherit directive is
    removed before any path rewriting), then rewrite paths.
    """
    return rewrite_paths(strip_claude_prose(text), mode, repo_root)


# ---------------------------------------------------------------------------
# YAML emission (stdlib-only — matches the subset our parser accepts)
# ---------------------------------------------------------------------------

def _yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "":
        return '""'
    # Quote if it contains characters that would confuse YAML/our parser.
    unsafe = any(ch in s for ch in ":#\n[]{},&*?|>'\"`")
    if unsafe or s.strip() != s:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def _yaml_list_inline(items: Iterable[str]) -> str:
    return ", ".join(items)


def _render_yaml_frontmatter(pairs: list[tuple[str, object]]) -> str:
    lines = ["---"]
    for k, v in pairs:
        if v is None or v == [] or v == "":
            continue
        if isinstance(v, list):
            # Inline comma-separated — matches the style the repo already uses
            # and what our own parser re-reads.
            lines.append(f"{k}: {_yaml_list_inline(str(x) for x in v)}")
        else:
            lines.append(f"{k}: {_yaml_scalar(v)}")
    lines.append("---")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# TOML emission (stdlib-only)
# ---------------------------------------------------------------------------

def _toml_string(s: str) -> str:
    if "\n" in s:
        esc = s.replace('\\', '\\\\').replace('"""', '\\"\\"\\"')
        return '"""\n' + esc + '\n"""'
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'


def _toml_array(xs: Iterable[str]) -> str:
    return "[" + ", ".join(_toml_string(x) for x in xs) + "]"


# ---------------------------------------------------------------------------
# Target-specific renderers
# ---------------------------------------------------------------------------

def render_agent_for_claude(agent: Agent) -> str:
    """Claude's own format — pass through with normalization."""
    pairs: list[tuple[str, object]] = [
        ("name", agent.name),
        ("description", agent.description),
    ]
    if agent.tools:
        pairs.append(("tools", agent.tools))
    if agent.model:
        pairs.append(("model", agent.model))
    if agent.color:
        pairs.append(("color", agent.color))
    if agent.memory:
        pairs.append(("memory", agent.memory))
    if agent.max_turns:
        pairs.append(("maxTurns", int(agent.max_turns)))
    return _render_yaml_frontmatter(pairs) + agent.body


def render_agent_for_codex(
    agent: Agent, mode: PathMode, repo_root: Path,
) -> str:
    """Codex TOML schema per https://developers.openai.com/codex/subagents .

    Required: name, description, developer_instructions.
    Optional we map: model_reasoning_effort (from `effort:` frontmatter).
    `model` is omitted unconditionally so Codex uses its default — Claude
    model IDs ("inherit", "claude-opus-4-6", "haiku", etc.) don't translate.
    Body is run through preprocess_body (strip Claude prose + rewrite paths).
    Codex-safe name: lowercase alphanumeric + underscore.
    """
    safe_name = agent.name.replace("-", "_")
    body = preprocess_body(agent.body.strip(), mode, repo_root)
    parts = [
        f"name = {_toml_string(safe_name)}",
        f"description = {_toml_string(agent.description or agent.name)}",
        f"developer_instructions = {_toml_string(body)}",
    ]
    if agent.effort in ("low", "medium", "high"):
        parts.append(f"model_reasoning_effort = {_toml_string(agent.effort)}")
    return "\n".join(parts) + "\n"


def render_agent_for_gemini(
    agent: Agent, mode: PathMode, repo_root: Path,
) -> str:
    """Gemini native subagent format — YAML frontmatter + body.

    Schema (April 2026): name, description, tools[], mcpServers, model,
    temperature, maxTurns, maxTime. tools "*" inherits the parent's
    toolset; an empty list would mean "no tools". Model is omitted —
    Gemini default is "inherit" which is what we want.
    """
    pairs: list[tuple[str, object]] = [
        ("name", agent.name),
        ("description", agent.description),
        ("tools", "*"),  # inherit parent's full toolset
    ]
    if agent.max_turns:
        pairs.append(("maxTurns", int(agent.max_turns)))
    body = preprocess_body(agent.body, mode, repo_root)
    return _render_yaml_frontmatter(pairs) + body


# Orchestrators — agents whose body explicitly dispatches other agents.
# Maintained as a small allowlist; missing names get no `agents:` field.
_COPILOT_ORCHESTRATORS = frozenset({
    "chain-builder",
    "correlator",
    "recon-ranker",
})

# Copilot enforces this on .agent.md body length.
_COPILOT_BODY_MAX = 30_000


def render_agent_for_copilot(
    agent: Agent, mode: PathMode, repo_root: Path,
    all_agent_names: list[str] | None = None,
) -> str:
    """VS Code Copilot custom-agent file format (.agent.md).

    Schema (verified May 2026): name, description, target, tools, agents
    (subagents), model, mcp, handoffs, hooks. Body capped at 30,000 chars.
    Orchestrators (chain-builder etc.) get an `agents:` list of siblings
    so Copilot wires the dispatch graph.
    """
    pairs: list[tuple[str, object]] = [
        ("name", agent.name),
        ("description", agent.description),
        ("target", "vscode"),
    ]
    if agent.name in _COPILOT_ORCHESTRATORS and all_agent_names:
        siblings = [n for n in all_agent_names if n != agent.name]
        if siblings:
            pairs.append(("agents", siblings))
    body = preprocess_body(agent.body, mode, repo_root)
    if len(body) > _COPILOT_BODY_MAX:
        body = body[:_COPILOT_BODY_MAX - 100].rstrip() + (
            "\n...[truncated for Copilot 30K cap]\n"
        )
    return _render_yaml_frontmatter(pairs) + body


def render_skill_from_agent(
    agent: Agent, mode: PathMode, repo_root: Path,
) -> str:
    """Degrade an agent into a Skill for targets without native subagents.

    Claude's subagents are full autonomous workers with their own tool
    set; Cursor/Windsurf "skills" are more like model-invoked playbooks.
    The best we can do is present the agent body as a playbook the main
    model can follow when the description matches.
    """
    pairs: list[tuple[str, object]] = [
        ("name", agent.name),
        ("description", agent.description),
    ]
    body = preprocess_body(agent.body, mode, repo_root)
    return _render_yaml_frontmatter(pairs) + body


def render_cursor_rule(
    rule: Rule, mode: PathMode, repo_root: Path,
    globs: list[str] | None = None,
    always_apply: bool = False,
) -> str:
    """Cursor .mdc format — description, globs, alwaysApply frontmatter."""
    pairs: list[tuple[str, object]] = [
        ("description", f"pentest-agents rule: {rule.name}"),
    ]
    if globs:
        pairs.append(("globs", globs))
    pairs.append(("alwaysApply", always_apply))
    return _render_yaml_frontmatter(pairs) + preprocess_body(rule.body, mode, repo_root)


def render_windsurf_rule(
    rule: Rule, mode: PathMode, repo_root: Path,
    trigger: str = "always_on",
) -> str:
    """Windsurf .windsurf/rules/*.md format.

    Each file ≤12K chars. Caller is responsible for chunking if needed.
    """
    pairs: list[tuple[str, object]] = [("trigger", trigger)]
    return _render_yaml_frontmatter(pairs) + preprocess_body(rule.body, mode, repo_root)


def render_copilot_instruction(
    rule: Rule, mode: PathMode, repo_root: Path,
    apply_to: str = "**",
) -> str:
    """VS Code Copilot `.instructions.md` — applyTo glob frontmatter."""
    pairs: list[tuple[str, object]] = [
        ("name", rule.name),
        ("description", f"pentest-agents rule: {rule.name}"),
        ("applyTo", apply_to),
    ]
    return _render_yaml_frontmatter(pairs) + preprocess_body(rule.body, mode, repo_root)


def render_gemini_command(
    cmd: Command, mode: PathMode, repo_root: Path,
) -> str:
    """Gemini custom commands are TOML with prompt + description."""
    prompt = preprocess_body(cmd.body.strip(), mode, repo_root)
    desc = cmd.description or cmd.name
    return (
        f"description = {_toml_string(desc)}\n"
        f"prompt = {_toml_string(prompt)}\n"
    )


def render_copilot_prompt(
    cmd: Command, mode: PathMode, repo_root: Path,
) -> str:
    """VS Code `.prompt.md` — frontmatter: description, argument-hint."""
    pairs: list[tuple[str, object]] = [
        ("name", cmd.name),
        ("description", cmd.description or cmd.name),
    ]
    if cmd.argument_hint:
        pairs.append(("argument-hint", cmd.argument_hint))
    return _render_yaml_frontmatter(pairs) + preprocess_body(cmd.body, mode, repo_root)


def _translate_model(claude_model: str, target: str) -> str | None:
    """Best-effort model-id translation. Returns None to omit (= default)."""
    if not claude_model:
        return None
    if target == "gemini":
        mapping = {
            "sonnet": "gemini-3-pro",
            "opus":   "gemini-3-pro",
            "haiku":  "gemini-3-flash",
        }
        return mapping.get(claude_model.lower())
    return None


# ---------------------------------------------------------------------------
# Rule digest — compact a pile of Rules into one persistent-context file.
# ---------------------------------------------------------------------------

SHARED_AGENTS_MD_HEADING = "# pentest-agents — persistent instructions\n"
"""Canonical AGENTS.md heading shared by every target that reads AGENTS.md.

Using the same heading (and the same rules_digest call) across targets lets
them write byte-identical content, which keeps install manifests coherent
when multiple targets all own the same file.
"""


_WORKSPACE_RULE_PRIORITY = (
    "hunting",
    "never-submit",
    "chain-table",
    "mistakes",
    "identities",
    "waf-bypass-protocol",
    "techniques",
    "vendor-status",
    "payloads",
)


def workspace_agents_digest(
    rules: list[Rule],
    heading: str = SHARED_AGENTS_MD_HEADING,
    mode: PathMode = PathMode.RENDER,
    repo_root: Path | None = None,
    max_chars: int | None = 30_000,
) -> str:
    """High-signal AGENTS.md for a bounty workspace/provider bundle.

    This is intentionally different from the repository root AGENTS.md. The
    root file tells agents how to maintain the framework; this digest tells
    AGENTS.md-reading clients how to operate inside a generated bug-bounty
    workspace. It keeps the action-critical workflow up front, then appends a
    prioritized rules digest until the target's context cap is reached.
    """
    if repo_root is None:
        repo_root = Path("/")

    preamble = f"""{heading.rstrip()}

## Authorized Security Testing Workspace

This workspace uses the pentest-agents framework for authorized bug bounty
research only. Verify scope and policy before testing. Stay inside
`scope.yaml` / `.scope.txt` and `policy.md`. Do not run destructive tests, DoS,
social engineering, or out-of-scope probing.

## Operating Discipline

- Read `rules/hunting.md` before every hunt.
- Run scope/policy checks before touching a target.
- Use `rules/never-submit.md` and the 7-Question Gate before writing reports.
- Chain weak primitives before reporting; standalone informational findings
  are not submissions.
- Read and update brain state with `tools/brain.py` so exhausted vectors stay
  exhausted and confirmed patterns compound.
- Persist PoCs, reports, screenshots, and evidence to disk. If a file does not
  exist, call it pending.
- Never hardcode platform identities or secrets. Use `rules/identities.md` and
  environment variables.

## Local Framework Assets

- `.codex/`, `.gemini/`, `.cursor/`, `.windsurf/`, `.github/`, `.agents/` —
  project-scoped provider assets generated by scaffold/installer.
- `.claude/agents/` and `.claude/skills/` — canonical Claude agents and
  slash-command skills.
- `rules/` and `skills/` — methodology, payloads, and class-specific playbooks.
- `tools/` — workspace-local CLI tools; run Python tools with `uv run python3`.
- `mcp-bounty-server/` and `mcp-writeup-server/` — platform/scope and writeup
  search MCP servers.

## Workflow

New program: `/sync` -> `/brain init` -> `/surface` -> `/hunt`
Returning: `/resume <target>` -> `/hunt` or `/autopilot --resume`
After confirming signal: `/validate` -> `/chain` -> `/report` -> `/dupcheck` -> `/submit` -> `/learn`
Batch triage: `/triage`

## Rules Digest

"""

    rules_by_name = {r.name: r for r in rules}
    ordered: list[Rule] = []
    seen: set[str] = set()
    for name in _WORKSPACE_RULE_PRIORITY:
        rule = rules_by_name.get(name)
        if rule is not None:
            ordered.append(rule)
            seen.add(rule.name)
    ordered.extend(r for r in rules if r.name not in seen)

    parts = [preamble]
    for rule in ordered:
        body = preprocess_body(rule.body, mode, repo_root)
        section = f"\n## {rule.name}\n\n{body}"
        if max_chars is not None and sum(len(p) for p in parts) + len(section) > max_chars:
            remaining = max_chars - sum(len(p) for p in parts)
            if remaining > 30:
                parts.append(section[:remaining - 20].rstrip() + "\n...[truncated]\n")
            break
        parts.append(section)

    out = "".join(parts).rstrip() + "\n"
    if max_chars is not None and len(out) > max_chars:
        out = out[:max_chars - 20].rstrip() + "\n...[truncated]\n"
    return out


def rules_digest(
    rules: list[Rule], heading: str,
    mode: PathMode = PathMode.RENDER,
    repo_root: Path | None = None,
    max_chars: int | None = None,
) -> str:
    """Flatten rules into a single Markdown doc (for CLAUDE.md, AGENTS.md,
    GEMINI.md, copilot-instructions.md, etc.).

    Each rule body is preprocessed (strip Claude prose, rewrite paths) so
    the resulting digest works in non-Claude environments.
    """
    if repo_root is None:
        repo_root = Path("/")  # never used in render mode; safe default
    parts = [heading.rstrip() + "\n"]
    for rule in rules:
        parts.append(f"\n## {rule.name}\n\n")
        body = preprocess_body(rule.body, mode, repo_root)
        if max_chars is not None and sum(len(p) for p in parts) + len(body) > max_chars:
            remaining = max_chars - sum(len(p) for p in parts)
            if remaining <= 0:
                break
            body = body[:remaining].rstrip() + "\n...[truncated]\n"
        parts.append(body)
    out = "".join(parts).rstrip() + "\n"
    if max_chars is not None and len(out) > max_chars:
        out = out[:max_chars - 20].rstrip() + "\n...[truncated]\n"
    return out


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
