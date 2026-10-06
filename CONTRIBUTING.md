# Contributing

Quick reference for development hygiene in this repo.

## Source of truth

- Root `CLAUDE.md` and `AGENTS.md` are for maintaining this repository.
  They must not be copied into bounty workspaces.
- `.claude/` is the source for agents and slash commands.
- `rules/` is the source for the methodology rule files (always-on
  guidance loaded by every hunter).
- `skills/` (top-level) is the source for the methodology skill bundles.
- `providers/` is **generated** — never edit it by hand.
- `tools/scaffold.py` generates bounty-workspace `CLAUDE.md`, `AGENTS.md`,
  and project-scoped provider assets from the copied workspace files.

## After editing `.claude/`, `rules/`, or `skills/`

Re-render the provider bundles:

```bash
python3 -m tools.installer render --targets all
```

This regenerates everything under `providers/`. Commit your source
change and the resulting `providers/` diff in the same commit.

## Drift check before opening a PR

```bash
python3 -m tools.installer render --check
```

Returns 0 if `providers/` matches what would be rendered now, 1 if
anything has drifted.

## Running the installer test suite

```bash
PYTHONPATH=. python3 -m pytest tools/installer/tests/ -v
```

Covers:
- round-trip install/uninstall for every target
- render-mode correctness (Codex skills, no deprecated prompts, no model leaks, no Claude
  prose leaks, idempotency)
- drift detection — `test_committed_providers_match_render` fails if
  someone edited `.claude/` without re-rendering

## No GitHub Actions

By project policy, this repo intentionally ships no CI. Drift is caught
by developer discipline (running `render --check` locally) and by the
pytest case above.

## Spec / plan files

Working specs and implementation plans live in
`docs/superpowers/specs/` and `docs/superpowers/plans/` — both are
gitignored. They're for the implementer's reference only and are not
shipped to community users.

## Adding a new provider

1. Verify the latest docs for the provider's agent/command/MCP format.
2. Add a `tools/installer/targets/<id>.py` subclass of `Target`, mirroring
   the path-resolution helper pattern used by the existing targets:
   `_<id>_dir(ctx)` returns the install dir; in render mode it returns
   `ctx.render_root / "providers" / <id>`. Each helper that emits files
   threads `mode = self._mode_for_install(ctx)` and `repo_root` through to
   the translator.
3. Register the target in `tools/installer/targets/__init__.py`.
4. Add a translator in `tools/installer/translators.py` if the provider
   has a non-standard format. Make sure to call `preprocess_body` on
   every agent/command/skill body and `rewrite_paths` on any path
   substitution.
5. Add a test in `tools/installer/tests/test_translators.py` that asserts
   no Claude-prose leakage and no `$CLAUDE_PROJECT_DIR` leakage.
6. Run `pentest-agents render --targets <id>` and commit the resulting
   `providers/<id>/` directory.
7. Update `README.md` and `docs/providers.md` with the new provider.
