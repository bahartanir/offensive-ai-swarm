# pentest-agents Repository Maintenance

This file is for agents working on the `pentest-agents` repository itself.
It is not the bounty-workspace hunting brief. Bounty workspaces get their own
`CLAUDE.md` from `tools/scaffold.py`; non-Claude provider bundles get their
own generated instructions under `providers/<id>/`.

## Repository Role

Maintain the framework as a distributable product:

- Keep Claude Code source assets, non-Claude provider renderers, scaffolded
  workspace behavior, MCP servers, tests, and docs in sync.
- Treat `providers/` as generated output. Do not edit provider files by hand.
- Preserve the public-safety boundary: authorized testing only, no hardcoded
  researcher identities, no target-specific secrets, no real bounty evidence
  committed into framework source.
- Prefer complete fixes over patches that only repair the immediate symptom.

## Source Map

- `.claude/agents/` — canonical Claude Code subagent source.
- `.claude/skills/` — canonical slash-command skills.
- `skills/` — reusable methodology skills copied/rendered to providers.
- `rules/` — always-on methodology and guardrail source files.
- `tools/scaffold.py` — creates and updates bounty engagement workspaces.
- `tools/installer/` — cross-provider installer and renderer.
- `providers/` — generated provider bundles for Codex, Gemini, Cursor,
  Windsurf, Copilot, and OpenClaw.
- `mcp-bounty-server/` and `mcp-writeup-server/` — MCP integrations.
- `tests/` and `tools/installer/tests/` — regression coverage.
- `docs/providers.md`, `CONTRIBUTING.md`, and `README.md` — user-facing
  operating instructions.

## Generated Artifacts

When editing `.claude/`, `rules/`, `skills/`, `tools/installer/targets/`, or
`tools/installer/translators.py`, regenerate and verify provider output:

```bash
uv run python3 -m tools.installer render --targets all
uv run python3 -m tools.installer render --check
```

Commit source changes and the resulting `providers/` diff together.

Provider files are allowed to change only through the renderer. If a rendered
file looks wrong, fix the source material or translator, then re-render.

## Scaffold Contract

`tools/scaffold.py` owns bounty-workspace creation and update mode.

- It generates the workspace `CLAUDE.md`; root repository `CLAUDE.md` must
  never be copied into a bounty workspace.
- It generates a workspace `AGENTS.md` for AGENTS-reading tools such as Codex.
- It copies suite-owned assets into the workspace and prunes stale suite-owned
  agents, skills, and rules.
- It preserves user workspace state: scope, policy, findings, brain, recon,
  reports, evidence, and custom notes.
- It intentionally excludes `tools/installer/` from bounty workspaces because
  the installer is repository infrastructure, not engagement tooling.

When changing scaffold behavior, add or update tests that exercise create and
update mode against a temporary workspace, then run them:

```bash
PYTHONPATH=. uv run python3 -m pytest tests/test_scaffold.py -q
```

## Installer Contract

The installer reads canonical source material from the repository and emits
the native shape for each supported AI tool.

- Claude Code keeps native `.claude/` assets and installs a workspace brief,
  not this repository-maintenance file.
- Codex emits `.codex/agents/*.toml`, `.agents/skills/<name>/`, `AGENTS.md`,
  and MCP blocks in `.codex/config.toml`.
- Cursor, Windsurf, and OpenClaw degrade Claude agents into skills or rules
  when the target lacks native subagents.
- Copilot output must respect its file-size limits and explicit agent schema.
- Path placeholders must resolve correctly in render mode and install mode.
- Do not reintroduce deprecated Codex prompts; commands are Codex skills.

When changing installer behavior, run the installer tests:

```bash
PYTHONPATH=. uv run python3 -m pytest tools/installer/tests -q
```

## Testing Expectations

Use focused tests while editing and a broader check before finishing.

```bash
PYTHONPATH=. uv run python3 -m pytest tests -q
PYTHONPATH=. uv run python3 -m pytest tools/installer/tests -q
uv run python3 -m tools.installer render --check
```

If a change touches an MCP server, include that server's tests. If a change
touches scaffold behavior, include scaffold-specific tests. If a change alters
provider rendering, include drift detection.

## Documentation Expectations

Update docs in the same change when behavior changes:

- `README.md` for user workflows and quick-start commands.
- `docs/providers.md` for provider layout, install/render behavior, and limits.
- `CONTRIBUTING.md` for maintainer workflow.

Keep examples current. In particular, `tools/scaffold.py` no longer accepts
`--type`; do not add examples that use it.

## Security Hygiene

- Never hardcode platform usernames, email aliases, passwords, tokens, cookies,
  TOTP seeds, or target-specific account data.
- Use the env-var names in `rules/identities.md` when code needs platform
  identities.
- Do not commit generated reports, PoCs, screenshots, recordings, scan output,
  or target recon unless the file is intentionally sanitized framework sample
  data.
- Keep destructive filesystem and git operations out of automation unless the
  user explicitly requested them.

## Before You Finish

Check:

- Source and generated provider output agree.
- Tests cover the behavior you changed.
- Documentation no longer describes old behavior.
- No unrelated dirty work was reverted or overwritten.
- The final answer names the files changed and the verification run.
