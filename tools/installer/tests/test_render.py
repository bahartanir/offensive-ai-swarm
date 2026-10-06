"""Render-mode tests — pre-render providers/<id>/ for inspection + commit."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def _run(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> tuple[int, str]:
    env = {**os.environ, **(env or {}), "PYTHONPATH": str(REPO)}
    proc = subprocess.run(
        [sys.executable, "-m", "tools.installer", *args],
        cwd=cwd, env=env, check=False, capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def test_render_codex_creates_providers_dir(tmp_path: Path):
    """`render --target codex --render-root tmp` writes to <tmp>/providers/codex/."""
    rc, log = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc == 0, log
    out = tmp_path / "providers" / "codex"
    assert (out / "AGENTS.md").exists()
    assert (out / ".codex" / "agents").exists()
    assert (out / ".codex" / "config.toml").exists()
    # Skills replaced the deprecated .codex/prompts/ tree.
    skills_dir = out / ".agents" / "skills"
    assert skills_dir.exists() and any(skills_dir.iterdir()), \
        "skills/ should exist with at least one skill folder"
    assert not (out / ".codex" / "prompts").exists(), \
        "deprecated .codex/prompts/ must not be emitted"


def test_render_codex_omits_model_in_subagents(tmp_path: Path):
    """No agent.toml should set the model field — Codex picks default."""
    rc, _ = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc == 0
    agents_dir = tmp_path / "providers" / "codex" / ".codex" / "agents"
    bad = []
    for f in agents_dir.glob("*.toml"):
        text = f.read_text(encoding="utf-8")
        # Lines starting with "model = " are forbidden (we omit unconditionally).
        # model_reasoning_effort is allowed and tested elsewhere.
        for line in text.splitlines():
            if line.startswith("model = "):
                bad.append(f.name)
                break
    assert not bad, f"these agents leaked a model field: {bad}"


def test_render_codex_strips_claude_prose(tmp_path: Path):
    rc, _ = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc == 0
    agents_dir = tmp_path / "providers" / "codex" / ".codex" / "agents"
    forbidden = [
        "Claude Code",
        "the Agent tool",
        "the Task tool",
        "$CLAUDE_PROJECT_DIR",
    ]
    leaks: list[tuple[str, str]] = []
    for f in agents_dir.glob("*.toml"):
        text = f.read_text(encoding="utf-8")
        for pat in forbidden:
            if pat in text:
                leaks.append((f.name, pat))
    assert not leaks, f"prose leaks: {leaks}"


def test_render_is_idempotent(tmp_path: Path):
    """Running render twice produces byte-identical output."""
    rc1, _ = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc1 == 0
    snap1 = sorted(
        (str(p.relative_to(tmp_path)), p.read_bytes())
        for p in (tmp_path / "providers").rglob("*") if p.is_file()
    )
    rc2, _ = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc2 == 0
    snap2 = sorted(
        (str(p.relative_to(tmp_path)), p.read_bytes())
        for p in (tmp_path / "providers").rglob("*") if p.is_file()
    )
    assert snap1 == snap2, "render is not idempotent"


def test_committed_providers_match_render():
    """The committed providers/ tree must match what `render` produces.

    If this fails, run: `python3 -m tools.installer render --targets all`
    and commit the result.
    """
    rc, log = _run(["render", "--check"], cwd=REPO)
    assert rc == 0, log


def _split_skill_frontmatter(text: str) -> list[str]:
    """Return the YAML frontmatter lines (between the two `---` fences).

    Returns [] if the file has no frontmatter — caller decides if that's
    a failure for the asset under test.
    """
    if not text.startswith("---\n"):
        return []
    rest = text[4:]
    end = rest.find("\n---")
    if end == -1:
        return []
    return rest[:end].splitlines()


def test_codex_skill_frontmatter_values_are_yaml_safe(tmp_path: Path):
    """Every SKILL.md value with unsafe YAML chars must be double-quoted.

    Regression: Codex's strict YAML parser rejects bare descriptions like
    `description: Usage: /hunt ...` because `": "` inside the value is
    parsed as a nested mapping key. _yaml_scalar must quote any value
    containing `:`, `#`, brackets, etc.
    """
    rc, _ = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc == 0
    skills_root = tmp_path / "providers" / "codex" / ".agents" / "skills"
    bad: list[tuple[str, str]] = []
    unsafe_chars = set(":#[]{},&*?|>`")
    for skill_md in skills_root.rglob("SKILL.md"):
        lines = _split_skill_frontmatter(skill_md.read_text(encoding="utf-8"))
        assert lines, f"missing frontmatter in {skill_md}"
        for line in lines:
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            value = value.lstrip()
            if not value or value.startswith('"'):
                continue  # quoted scalars are safe by construction
            if any(ch in value for ch in unsafe_chars):
                bad.append((str(skill_md.relative_to(skills_root)), line))
    assert not bad, (
        "Unquoted SKILL.md frontmatter values contain unsafe YAML chars; "
        f"these will fail Codex's parser:\n{bad}"
    )


def test_codex_config_emits_env_vars_passthrough(tmp_path: Path):
    """Codex MCP launcher does not inherit parent env by default; the
    bounty-platforms server needs an `env_vars = [...]` allowlist or it
    sees empty BUGCROWD_*/HACKERONE_* and silently falls back to
    unauthenticated public scraping (returning '0 in-scope' on engaged
    programs). Regression: the .codex/config.toml must emit env_vars.
    """
    rc, _ = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc == 0
    config = (tmp_path / "providers" / "codex" / ".codex" / "config.toml").read_text()
    # bounty-platforms must forward platform credential env vars.
    bounty_block = config.split("[mcp_servers.bounty-platforms]")[1].split("[mcp_servers.")[0]
    assert "env_vars =" in bounty_block, (
        f"bounty-platforms missing env_vars allowlist; "
        f"BUGCROWD_*/HACKERONE_* won't reach the MCP child process. Got:\n{bounty_block}"
    )
    for var in ("BUGCROWD_EMAIL", "BUGCROWD_PASSWORD", "BUGCROWD_TOTP_SECRET",
                "HACKERONE_USERNAME", "HACKERONE_TOKEN"):
        assert var in bounty_block, f"missing {var} in env_vars: {bounty_block}"


def test_codex_skill_frontmatter_parses_with_pyyaml(tmp_path: Path):
    """Bulletproof check: every SKILL.md frontmatter must round-trip
    through a real YAML parser.

    Skipped when PyYAML isn't installed (the project keeps zero runtime
    deps; install with `uv run --with pyyaml pytest` to exercise this).
    """
    yaml = __import__("pytest").importorskip("yaml")
    rc, _ = _run(
        ["render", "--targets", "codex", "--render-root", str(tmp_path)],
        cwd=REPO,
    )
    assert rc == 0
    skills_root = tmp_path / "providers" / "codex" / ".agents" / "skills"
    failures: list[tuple[str, str]] = []
    for skill_md in skills_root.rglob("SKILL.md"):
        lines = _split_skill_frontmatter(skill_md.read_text(encoding="utf-8"))
        try:
            data = yaml.safe_load("\n".join(lines))
        except yaml.YAMLError as e:  # pragma: no cover - covered by failures list
            failures.append((str(skill_md.relative_to(skills_root)), str(e)))
            continue
        if not isinstance(data, dict) or "name" not in data:
            failures.append((str(skill_md.relative_to(skills_root)), f"got {data!r}"))
    assert not failures, f"SKILL.md frontmatter failed YAML parse:\n{failures}"
