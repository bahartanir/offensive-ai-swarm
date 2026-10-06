# pentest-agents Repository Maintenance

This file is for Codex and other AGENTS.md-reading tools working on the
`pentest-agents` repository itself. It is not the bounty-workspace brief.
Generated/scaffolded workspaces get their own `AGENTS.md`.

## Role

Maintain the framework as a distributable product:

- Keep `.claude/`, `rules/`, `skills/`, `tools/scaffold.py`,
  `tools/installer/`, provider bundles, MCP servers, tests, and docs aligned.
- Treat `providers/` as generated output. Fix source or translators, then
  re-render; do not hand-edit provider files.
- Keep bounty-workspace instructions separate from repository-maintenance
  instructions.
- Do not hardcode researcher identities, tokens, cookies, TOTP seeds, target
  account data, or real bounty evidence.

## Source Map

- `.claude/agents/` — canonical Claude Code subagents.
- `.claude/skills/` — canonical slash-command skills.
- `skills/` — reusable methodology skills.
- `rules/` — always-on methodology and guardrail source.
- `tools/scaffold.py` — creates and updates bounty workspaces.
- `tools/installer/` — cross-provider installer and renderer.
- `providers/` — generated non-Claude bundles.
- `mcp-bounty-server/`, `mcp-writeup-server/` — MCP integrations.
- `tests/`, `tools/installer/tests/` — regression coverage.

## Generated Output

After editing `.claude/`, `rules/`, `skills/`, or installer translators/targets:

```bash
uv run python3 -m tools.installer render --targets all
uv run python3 -m tools.installer render --check
```

Commit source changes and `providers/` changes together.

## Scaffold Contract

`tools/scaffold.py` owns bounty workspace create/update mode.

- Generate workspace `CLAUDE.md`; never copy this repository file there.
- Generate workspace `AGENTS.md` and project-scoped provider assets for Codex,
  Gemini, Cursor, Windsurf, Copilot, and OpenClaw.
- Generate provider assets from the copied workspace files so paths resolve to
  the bounty workspace, not the source checkout.
- Preserve user workspace state: scope, policy, findings, brain, recon,
  reports, evidence, and custom notes.
- Keep `tools/installer/` out of bounty workspaces.

## Verification

Use focused tests while editing and run the relevant broader checks before
finishing:

```bash
PYTHONPATH=. uv run python3 -m pytest tests -q
PYTHONPATH=. uv run python3 -m pytest tools/installer/tests -q
uv run python3 -m tools.installer render --check
```

Update `README.md`, `docs/providers.md`, and `CONTRIBUTING.md` when behavior
or maintainer workflow changes.

Keep examples current. `tools/scaffold.py` no longer accepts `--type`; do not
add examples that use it.

## Security Hygiene

- Never hardcode platform usernames, email aliases, passwords, tokens,
  cookies, TOTP seeds, or target-specific account data.
- Use the env-var names in `rules/identities.md` when code needs platform
  identities.
- Do not commit generated reports, PoCs, screenshots, recordings, scan
  output, or target recon unless the file is intentionally sanitized
  framework sample data.
- Keep destructive filesystem and git operations out of automation unless
  the user explicitly requested them.

## Before Finishing

- Source and generated provider output agree.
- Tests cover the behavior changed.
- Documentation no longer describes old behavior.
- No unrelated dirty work was reverted or overwritten.
- The final answer names the files changed and the verification run.
