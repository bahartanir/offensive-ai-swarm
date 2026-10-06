# providers/ — How to consume each provider bundle

The `providers/<id>/` tree mirrors what the installer would write into your
project for each non-Claude AI coding tool. Three ways to use it:

1. **Direct use:** `cd providers/<id> && <tool>`. Works as long as
   `providers/` lives inside the cloned repo (relative paths reach
   `../tools/`, `../rules/`, `../mcp-*-server/`).
2. **Run the installer:** `python3 -m tools.installer install --targets <id>
   --scope global` — copies the same content to your user-level config dir
   with absolute paths into the cloned repo.
3. **Inspect:** Just read the files. They're plain TOML / Markdown / JSON.

`tools/scaffold.py` now installs the project-scoped provider assets directly
into every bounty workspace after copying the suite files. That means a fresh
workspace is immediately usable from Claude Code, Codex, Gemini, Cursor,
Windsurf, Copilot, and OpenClaw without a second manual project install.
Provider paths are generated from the workspace copy, so MCP server and tool
references resolve inside the bounty workspace.

## Per-provider notes

### Codex (`providers/codex/`)

- **Subagents:** `.codex/agents/<name>.toml` (48 files). Required fields:
  `name`, `description`, `developer_instructions`. `model` is omitted
  unconditionally so Codex picks its default (currently `gpt-5.5`).
  Agents whose `.claude/` source has `effort: low|medium|high` get
  `model_reasoning_effort` set in the TOML — the rest leave it default.
- **Skills:** `.agents/skills/<name>/SKILL.md` (26 skills, one per
  command). Frontmatter: `name:`, `description:`, `argument-hint:`. Body
  uses `$1..$9` / `$ARGUMENTS` placeholders. Each skill folder also
  ships `agents/openai.yaml` pinning
  `policy.allow_implicit_invocation: false` so commands like `/hunt`
  and `/submit` only run on explicit `$<name>` — Codex will not
  prompt-match them. The installer writes to `~/.agents/skills/` for
  global scope and `<project>/.agents/skills/` for project scope; both
  are picked up by Codex per the agentskills.io standard.
  > Custom prompts (`~/.codex/prompts/<name>.md`) were the previous
  > mechanism for reusable instructions and are deprecated by OpenAI in
  > favor of skills. We do not emit them.
- **AGENTS.md:** capped at ~30 KiB (Codex's `project_doc_max_bytes`
  default is 32 KiB). This is the bounty-workspace brief, not the
  repository-maintenance `AGENTS.md` at the source checkout root.
- **MCP:** `.codex/config.toml` `[mcp_servers.bounty-platforms]` and
  `[mcp_servers.writeup-search]`. In the `providers/codex/` bundle the
  args use `../mcp-bounty-server/server.py`. The installer rewrites
  to absolute paths when installing.

### Gemini (`providers/gemini/`)

- **Subagents** (April 2026 feature): `.gemini/agents/<name>.md` with
  YAML frontmatter. `tools: "*"` so subagents inherit the parent's full
  toolset. `model` field omitted (Gemini default is "inherit" — what
  we want).
- **Commands:** `.gemini/commands/<name>.toml` (`description=`, `prompt=`).
- **MCP:** merged into `settings.json` under `mcpServers`.

### Cursor (`providers/cursor/`)

- No native subagents. All 48 agents are degraded to skills under
  `.cursor/skills/agent-<name>/SKILL.md`. They activate when the user's
  task matches the description — best-effort.
- All 26 commands also become skills under `.cursor/skills/cmd-<name>/`.
  Users can't type `/hunt` and have it execute; they describe what they
  want and the matching skill body is injected as context.
- Project rules live in `.cursor/rules/*.mdc`. The hunting and
  never-submit rules are `alwaysApply: true`; the rest match by topic.
- **MCP:** `.cursor/mcp.json`.

### Windsurf (`providers/windsurf/`)

- Same agents-as-skills approach as Cursor.
- Project install writes `.windsurf/rules/`, `.windsurf/workflows/`, and
  `.windsurf/skills/`. Windsurf's MCP config is user-scope only, so run the
  installer with `--scope global` once if you want Windsurf to launch the MCP
  servers automatically.
- **Per-file char limits:** 12 KiB (workspace), 6 KiB (global). The
  installer chunks larger rule bodies across multiple files when needed.
  Currently chunks: `hunting` (2 files), `mistakes` (7), `payloads` (7),
  `techniques` (2).
- Trigger: `model_decision` for agents-as-skills, `always_on` for the
  rules digest.

### Copilot (`providers/copilot/`)

- **Native agents:** `.github/agents/<name>.agent.md`. `target: vscode`
  is set in frontmatter. Body capped at 30,000 chars (Copilot's hard
  limit). Bodies that exceed get truncated with a marker.
- **Subagent linking:** orchestrator agents (`chain-builder`,
  `correlator`, `recon-ranker`) get `agents: [<sibling names>]` in
  frontmatter so Copilot wires the dispatch graph.
- **Prompts:** `.github/prompts/<name>.prompt.md` (26 files).
- **Instructions:** `.github/instructions/<name>.instructions.md` for
  per-rule scoped guidance.
- **MCP:** `.vscode/mcp.json`.

### OpenClaw (`providers/openclaw/`)

- Skills convention: `.agents/skills/<name>/SKILL.md`. Three categories:
  - `pentest-agents-<name>/` — repo-native skills (hunting-methodology,
    recon-methodology, etc.)
  - `agent-<name>/` — Claude agents degraded to skills
  - `cmd-<name>/` — slash commands degraded to skills
- **MCP:** OpenClaw MCP config is user-level only
  (`~/.openclaw/openclaw.json`); the bundle ships an `openclaw.json` at
  the root for inspection / manual installation.

## Re-rendering after `.claude/` edits

```bash
python3 -m tools.installer render --targets all
```

If you forget, the local pytest case `test_committed_providers_match_render`
will fail until you re-render.

## Drift check (no GitHub Actions)

```bash
python3 -m tools.installer render --check
```

Returns 0 if `providers/` matches what would be rendered now, 1 if
anything has drifted. This is a developer-discipline check — there's no
automated CI, by project policy.
