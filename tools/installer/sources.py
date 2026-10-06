"""Load and parse the canonical source material the installer distributes.

Single source of truth = the repo itself. Agents live in .claude/agents/,
skills in skills/, commands in .claude/commands/, rules in rules/,
payloads in rules/payloads.md, MCP server definitions derived from
.claude/settings.json. Targets consume these and translate to their
own format.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class Agent:
    name: str
    description: str
    body: str
    tools: list[str] = field(default_factory=list)
    model: str | None = None
    color: str | None = None
    max_turns: int | None = None
    memory: str | None = None
    effort: str | None = None  # low | medium | high — maps to model_reasoning_effort on Codex
    raw_frontmatter: dict = field(default_factory=dict)
    source_path: Path | None = None


@dataclass
class Command:
    name: str
    description: str
    body: str
    argument_hint: str | None = None
    raw_frontmatter: dict = field(default_factory=dict)
    source_path: Path | None = None


@dataclass
class Skill:
    name: str
    description: str
    body: str
    supporting_files: dict[str, bytes] = field(default_factory=dict)
    source_dir: Path | None = None


@dataclass
class Rule:
    name: str
    body: str
    source_path: Path | None = None


@dataclass
class McpServer:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # Names of parent-process env vars to forward into the server's
    # environment. Read from the custom `forwardEnv` key in .mcp.json.
    # Codex needs this explicitly because its launcher does NOT inherit
    # the parent shell env by default — without it, BUGCROWD_EMAIL etc.
    # are invisible to the MCP child process and the bounty-platforms
    # provider silently falls back to unauthenticated public scraping.
    # Other targets (Claude Code, Gemini) inherit env automatically and
    # safely ignore this field.
    env_vars: list[str] = field(default_factory=list)
    url: str | None = None
    transport: str = "stdio"  # stdio | http | sse

    def is_stdio(self) -> bool:
        return self.transport == "stdio" and bool(self.command)


@dataclass
class SourceBundle:
    repo_root: Path
    agents: list[Agent]
    commands: list[Command]
    skills: list[Skill]
    rules: list[Rule]
    payloads: str  # body of rules/payloads.md
    mcp_servers: list[McpServer]

    def summary(self) -> str:
        return (
            f"{len(self.agents)} agents, {len(self.commands)} commands, "
            f"{len(self.skills)} skills, {len(self.rules)} rules, "
            f"{len(self.mcp_servers)} MCP servers, "
            f"{len(self.payloads)} payload chars"
        )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)


def split_frontmatter(text: str) -> tuple[dict, str]:
    """Return ({frontmatter dict}, body) for a Markdown doc with YAML frontmatter.

    Tiny hand-rolled YAML parser covering the shapes we actually emit:
    scalars, quoted strings, comma-separated inline lists, integers, booleans.
    No dependency on PyYAML — the installer stays stdlib-only.
    """
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    fm_text = match.group(1)
    body = text[match.end():]
    return _parse_simple_yaml(fm_text), body


def _parse_simple_yaml(text: str) -> dict:
    out: dict = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        out[key] = _coerce_yaml_value(value)
    return out


def _coerce_yaml_value(raw: str):
    if raw == "":
        return ""
    if (raw.startswith('"') and raw.endswith('"')) or (
        raw.startswith("'") and raw.endswith("'")
    ):
        return raw[1:-1]
    if raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    if "," in raw:
        return [p.strip() for p in raw.split(",") if p.strip()]
    return raw


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_agent(path: Path) -> Agent:
    fm, body = split_frontmatter(path.read_text(encoding="utf-8"))
    tools = fm.get("tools") or []
    if isinstance(tools, str):
        tools = [t.strip() for t in tools.split(",") if t.strip()]
    return Agent(
        name=str(fm.get("name") or path.stem),
        description=str(fm.get("description") or ""),
        body=body.strip() + "\n",
        tools=[str(t) for t in tools],
        model=fm.get("model"),
        color=fm.get("color"),
        max_turns=fm.get("maxTurns") or fm.get("max_turns"),
        memory=fm.get("memory"),
        effort=fm.get("effort"),
        raw_frontmatter=fm,
        source_path=path,
    )


def _load_command(path: Path) -> Command:
    fm, body = split_frontmatter(path.read_text(encoding="utf-8"))
    return Command(
        name=str(fm.get("name") or path.stem),
        description=str(fm.get("description") or ""),
        body=body.strip() + "\n",
        argument_hint=fm.get("argument-hint"),
        raw_frontmatter=fm,
        source_path=path,
    )


def _load_skill(skill_dir: Path) -> Skill | None:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return None
    fm, body = split_frontmatter(skill_md.read_text(encoding="utf-8"))
    supporting = {}
    for sub in skill_dir.rglob("*"):
        if sub == skill_md or sub.is_dir():
            continue
        rel = sub.relative_to(skill_dir).as_posix()
        supporting[rel] = sub.read_bytes()
    return Skill(
        name=str(fm.get("name") or skill_dir.name),
        description=str(fm.get("description") or ""),
        body=body.strip() + "\n",
        supporting_files=supporting,
        source_dir=skill_dir,
    )


def _load_rule(path: Path) -> Rule:
    return Rule(
        name=path.stem,
        body=path.read_text(encoding="utf-8"),
        source_path=path,
    )


def _absolutize_script_args(args: list[str], repo_root: Path) -> list[str]:
    """Rewrite relative .py/.sh script paths in args to be absolute.

    The repo's own settings.json uses paths like `mcp-bounty-server/server.py`
    that only resolve when cwd == repo root. When we install into another
    project those paths would break. Absolutize them once at load time.
    """
    out: list[str] = []
    for a in args:
        if isinstance(a, str) and not a.startswith("-") and (
            a.endswith(".py") or a.endswith(".sh") or "/" in a
        ):
            candidate = (repo_root / a).resolve()
            if candidate.exists():
                out.append(str(candidate))
                continue
        out.append(a)
    return out


def _load_mcp_from_file(path: Path, repo_root: Path) -> list[McpServer]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    raw = data.get("mcpServers") or {}
    servers: list[McpServer] = []
    for name, cfg in raw.items():
        if not isinstance(cfg, dict):
            continue
        transport = cfg.get("type") or ("http" if cfg.get("url") else "stdio")
        servers.append(
            McpServer(
                name=name,
                command=cfg.get("command"),
                args=_absolutize_script_args(list(cfg.get("args") or []), repo_root),
                env=dict(cfg.get("env") or {}),
                env_vars=list(cfg.get("forwardEnv") or []),
                url=cfg.get("url"),
                transport=transport,
            )
        )
    return servers


def load(repo_root: Path) -> SourceBundle:
    repo_root = repo_root.resolve()
    agents_dir = repo_root / ".claude" / "agents"
    claude_skills_dir = repo_root / ".claude" / "skills"
    legacy_commands_dir = repo_root / ".claude" / "commands"
    top_skills_dir = repo_root / "skills"
    rules_dir = repo_root / "rules"
    payloads_md = repo_root / "rules" / "payloads.md"

    agents = sorted(
        (_load_agent(p) for p in agents_dir.glob("*.md")),
        key=lambda a: a.name,
    ) if agents_dir.exists() else []

    # Commands: slash commands live as Claude Code skills under
    # .claude/skills/<name>/SKILL.md (post-April-2026 migration).
    # All entries here are slash commands by convention regardless of
    # disable-model-invocation — that flag only toggles Claude Code's
    # own model-auto-invocation; their semantic identity as slash
    # commands (with description, argument-hint, $ARGUMENTS body) is
    # what non-Claude providers (Codex prompts, Gemini commands,
    # Copilot prompts, etc.) need to install.
    # Pre-migration fallback: .claude/commands/<name>.md (legacy).
    commands: list[Command] = []
    if claude_skills_dir.exists():
        for sub in sorted(claude_skills_dir.iterdir()):
            skill_md = sub / "SKILL.md"
            if sub.is_dir() and skill_md.exists():
                fm, body = split_frontmatter(skill_md.read_text(encoding="utf-8"))
                commands.append(Command(
                    name=str(fm.get("name") or sub.name),
                    description=str(fm.get("description") or ""),
                    body=body.strip() + "\n",
                    argument_hint=fm.get("argument-hint"),
                    raw_frontmatter=fm,
                    source_path=skill_md,
                ))
    if not commands and legacy_commands_dir.exists():
        commands = sorted(
            (_load_command(p) for p in legacy_commands_dir.glob("*.md")),
            key=lambda c: c.name,
        )
    commands.sort(key=lambda c: c.name)

    # Skills: only the top-level skills/ directory (hunting-methodology,
    # hunt-rce, etc.). The .claude/skills/ entries are always commands —
    # see above. Avoiding double-classification keeps cursor / windsurf /
    # openclaw from emitting two copies of every slash command (one as
    # cmd-* and one as pentest-agents-*).
    skills: list[Skill] = []
    if top_skills_dir.exists():
        for sub in sorted(top_skills_dir.iterdir()):
            if sub.is_dir():
                skill = _load_skill(sub)
                if skill:
                    skills.append(skill)

    rules = sorted(
        (_load_rule(p) for p in rules_dir.glob("*.md")),
        key=lambda r: r.name,
    ) if rules_dir.exists() else []

    payloads = payloads_md.read_text(encoding="utf-8") if payloads_md.exists() else ""

    # Prefer .mcp.json (current Claude Code spec — project-scope shared),
    # fall back to .claude/settings.json (pre-April-2026 layout).
    mcp_servers = _load_mcp_from_file(repo_root / ".mcp.json", repo_root)
    if not mcp_servers:
        mcp_servers = _load_mcp_from_file(
            repo_root / ".claude" / "settings.json", repo_root
        )
    # Fallback to declaring the two in-repo MCP servers explicitly if settings
    # didn't list them (older or custom layout). We invoke them via
    # `uv run --with mcp <server>` so the MCP SDK gets provisioned into uv's
    # ephemeral venv — avoids requiring a system-wide `pip install mcp`.
    if not mcp_servers:
        bounty = repo_root / "mcp-bounty-server" / "server.py"
        writeup = repo_root / "mcp-writeup-server" / "server.py"
        if bounty.exists():
            mcp_servers.append(
                McpServer(
                    name="bounty-platforms",
                    command="uv",
                    args=["run", "--with", "mcp", str(bounty)],
                )
            )
        if writeup.exists():
            mcp_servers.append(
                McpServer(
                    name="writeup-search",
                    command="uv",
                    args=["run", "--with", "mcp", str(writeup)],
                )
            )

    return SourceBundle(
        repo_root=repo_root,
        agents=agents,
        commands=commands,
        skills=skills,
        rules=rules,
        payloads=payloads,
        mcp_servers=mcp_servers,
    )
