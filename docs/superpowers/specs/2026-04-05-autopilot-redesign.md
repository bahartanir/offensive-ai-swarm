# Autopilot Redesign, Workflow Fixes, Command/Agent Cleanup

Date: 2026-04-05

## Problem Statement

The current autopilot is a monolithic 80-turn agent that tries to do everything itself. It doesn't use subagents, doesn't auto-update the brain, skips writeup intelligence, and misses key workflow steps (surface ranking, dupcheck, chaining). Meanwhile, methodology rules are duplicated 3-5 times across commands, agents, and skills — causing drift and maintenance burden. The `/chain` command doesn't reliably dispatch the chain-builder agent.

## Architecture Decision

**Opus 4.6 [1M] orchestrator dispatching inherit-model subagents.**

The autopilot becomes a command (not an agent) running on whatever model the user chose — intended for Opus 4.6 with 1M context. It dispatches all testing work to specialized agents pinned to `model: "inherit"`. This gives:

- 1M context for the orchestrator to hold full engagement state
- The cyber use case permits Opus end-to-end; `model: "inherit"` lets subagents match whichever orchestrator model the user picks
- Clear separation: orchestrator decides, subagents execute

## 1. Autopilot Command

**File:** `.claude/commands/autopilot.md`

**Flags:**
- `--interactive` — pause after each validated finding for user review
- `--autonomous` — fully autonomous, no pauses, never auto-submits, produces ready-to-submit reports with PoCs and evidence
- `--20m-off` — disable 20-minute rotation timer on hunters
- `--resume` — continue from where a previous session left off (reads brain state)

### The Loop

```
SETUP:
  1. Read rules/hunting.md
  2. Read scope.yaml — verify all targets
  3. Read policy.md — extract ALL actionable constraints:
     - Required HTTP headers (X-Bug-Bounty, User-Agent, custom tracking)
     - Account creation rules (email domain, naming, company format)
     - Test environment setup (own instance, test properties, sandboxes)
     - Prohibited actions (DoS, social engineering, customer data)
     - Rate limiting expectations
     - N-day waiting periods, shared responsibility exclusions
     - Credential usage restrictions
  4. Format policy preamble for all subsequent agent dispatches
  5. brain.py brief — what do we already know?
  6. Store: scope, policy preamble, brain state as active context

RECON (skip if fresh recon < 7 days):
  7. Dispatch recon agent (model: inherit)
  8. Brain update with new endpoints/subdomains/tech stack

RANK:
  9. Dispatch /surface (recon-ranker agent, model: inherit)
  10. Get P1/P2/Kill prioritized list with curl commands

HUNT LOOP (for each P1 target):
  11. brain.py brief — what's tested on this target?
  12. Tech stack detection (curl fingerprinting)
  13. Map tech stack → candidate vuln classes
  14. For each vuln class (max 3 hunters in parallel):
      a. search_techniques for this vuln class (ENFORCED — must happen)
      b. search_payloads for this vuln class (ENFORCED — must happen)
      c. Dispatch specialized hunter agent (model: inherit)
         - Include: policy preamble + writeup intelligence + brain context
         - Apply 20-minute rotation (unless --20m-off)
      d. If hunter signals a DIFFERENT vuln class mid-hunt:
         → Adaptive re-search: search_techniques + search_payloads for new class
         → Dispatch appropriate specialized hunter for that class
      e. Brain update with results (tested vectors, endpoints, findings, exhausted)

  15. FLUSH CYCLE (every 3 subagent completions):
      a. Full brain update (all findings, endpoints, tech stack, exhausted)
      b. global_brain.py sync-from-local
      c. /surface re-rank (priorities may have shifted)
      d. Context checkpoint — if >60% usage:
         → Save full state to brain
         → Print progress summary
         → Recommend: "Run /autopilot --resume to continue"

  16. If finding discovered:
      a. /validate (dispatch validator agent — 7-Question Gate)
      b. If PASS:
         → /chain (dispatch chain-builder agent — extend the finding)
         → /dupcheck (check hacktivity before investing in report)
         → Dispatch poc-builder (model: inherit) — MUST capture evidence
         → Dispatch report-writer (model: inherit)
         → Dispatch quality-check (model: inherit) — must score ≥7
         → Brain update: confirmed finding with report path
      c. If KILL:
         → Brain update: exhausted vector with reason
         → Move on
      d. If CHAIN REQUIRED:
         → /chain first
         → Re-validate after chain attempt
      e. If DOWNGRADE:
         → Brain update with downgraded severity
         → Continue to report at lower severity
      f. Interactive mode: pause here, show finding to user
  
  17. After all vuln classes tested on target → mark target exhausted in brain
  18. Next P1 target → back to step 11

COMPLETION:
  19. Final brain sync (brain.py + global_brain.py)
  20. Final /surface (show remaining untested surface)
  21. Print summary:
      - Confirmed findings with report paths
      - Chains discovered
      - Targets exhausted
      - Targets remaining
      - Total agents dispatched, context usage
  22. "Run /submit <finding> to submit reports"
```

### Policy Preamble Enforcement

Every agent dispatched by the autopilot (and by /hunt, /chain, /pipeline, /fullscan, /quickscan) receives a policy preamble injected into its prompt:

```
POLICY CONSTRAINTS (VIOLATION = DISQUALIFICATION/BAN):
SCOPE AND POLICY MUST BE OBEYED AT ALL TIMES.

[Dynamically extracted from policy.md — program-specific, not templated]

ALL HTTP requests MUST include required headers.
ALL accounts MUST follow naming conventions.
ALL testing MUST stay within scope boundaries.
```

The preamble is extracted once during SETUP and included in every subsequent agent dispatch. No testing agent runs without it.

### Model Enforcement

Every `Agent` tool call from the autopilot MUST include `model: "inherit"`. The autopilot itself runs on the user's chosen model (Opus 4.6 [1M]).

### Writeup Intelligence Enforcement

Before dispatching ANY hunter agent, the autopilot MUST:
1. Call `search_techniques` MCP tool for the target vuln class
2. Call `search_payloads` MCP tool for the target vuln class
3. Include the results in the hunter agent's prompt

This is non-optional. If the MCP tools are unavailable, log a warning but continue — don't skip hunting entirely.

When a hunter reports a signal for a different vuln class than what it was dispatched for, the autopilot:
1. Calls `search_techniques` + `search_payloads` for the new class
2. Dispatches the appropriate specialized hunter with the new intelligence

## 2. Chain Command Fix

**File:** `.claude/commands/chain.md`

The command becomes a thin dispatcher:

```
1. Read brain for current finding context
2. If user provided bug description in $ARGUMENTS → use it
   Else → ask user to describe bug A
3. Read rules/chain-table.md (single source of truth for capability→next-bug table)
4. Read policy.md → format policy preamble
5. ALWAYS dispatch chain-builder agent (model: inherit) with:
   - Bug A description
   - Chain table from rules/chain-table.md
   - Policy preamble
   - Brain context (what's been tested, tech stack)
6. After agent returns:
   - brain.py record with chain results
   - If chain found → show to user with combined impact
   - If dead end → record exhausted chain attempt in brain
```

No inline chain logic. No capability table in the command. The command dispatches, the agent executes.

### New File: `rules/chain-table.md`

Extracted from current chain-builder agent. Contains:
- Capability → next-bug table (JS execution → cookie theft, SSRF → cloud metadata, etc.)
- Terminal impacts list (ATO, RCE, mass data exfil, etc.)
- Real chain examples (Renwa 9-link, S3→OAuth 4-link, etc.)
- Time box rules (20 min per link, max 3 failed candidates)

Single source of truth. Referenced by chain-builder agent and autopilot.

## 3. Pipeline Repurpose

**File:** `.claude/commands/pipeline.md`

Becomes "prepare the battlefield" — recon, scanning, and ranking. Stops before hunting.

```
Phase 0: SETUP
  - Read scope.yaml, verify targets
  - Read policy.md, extract constraints
  - brain.py init (if not exists) or brief (if exists)

Phase 1: RECON
  - Dispatch recon agent (model: inherit) with policy preamble
  - Brain update with results

Phase 2: SCANNING (parallel, max 3)
  - Dispatch vuln-scanner agent
  - Dispatch config-auditor agent  
  - Dispatch js-analyzer agent
  - Brain update with results

Phase 3: RANK
  - Dispatch /surface (recon-ranker agent)
  - Output P1/P2/Kill list

OUTPUT:
  "Battlefield ready. Run /hunt <target> or /autopilot to start hunting."
```

No Phase 3-4 hunting. No never-submit filtering (that's validator's job). No correlation (that's autopilot's or /correlate's job).

## 4. Command/Agent Cleanup

### Single Source of Truth

| Content | Location | Who references it |
|---------|----------|-------------------|
| 20 hunting rules | `rules/hunting.md` | autopilot, hunt, all hunters |
| Capability→chain table | `rules/chain-table.md` (NEW) | chain-builder agent, autopilot |
| Never-submit list + conditionally-valid | `rules/never-submit.md` (NEW) | validator agent |
| 7-Question Gate | Inlined in `validator.md` agent | validator is the executor |
| Policy constraints | `policy.md` (per-engagement) | all commands that dispatch testers |

### Commands → Thin Dispatchers

These commands get stripped of inline methodology and become pure dispatchers:

| Command | Dispatches | Inline logic removed |
|---------|-----------|---------------------|
| `/chain` | chain-builder agent | capability table, chain walk logic |
| `/hunt` | specialized hunter agents | methodology duplication from rules |
| `/surface` | recon-ranker agent | ranking logic |
| `/correlate` | correlator agent | chain pattern matching |
| `/triage` | validator agent (loop) | 7-Question Gate duplication |
| `/pipeline` | recon, scanners, ranker | Phase 3-4 hunting, never-submit filter |

### Commands That Stay As-Is

`/brain`, `/status`, `/cost`, `/evidence`, `/monitor`, `/new`, `/sync`, `/learn`, `/remember`, `/resume`, `/dupcheck`, `/submit`, `/report`, `/quality`, `/validate`, `/quickscan`, `/fullscan`, `/mindmap`

### Agent Changes

| Agent | Change |
|-------|--------|
| `autopilot.md` | Complete rewrite — lean orchestration instructions, not methodology |
| `chain-builder.md` | Remove chain table (reference rules/chain-table.md instead) |
| `validator.md` | Keep 7-Question Gate inlined. Reference rules/never-submit.md for the list. |
| All hunter agents | Add policy preamble requirement to Brain Integration section |

## 5. Brain Auto-Update Protocol

### After Every Subagent Completion

The autopilot parses the subagent's output and runs:

```bash
python3 tools/brain.py record <target> <status> <technique> "<details>"
```

Recording:
- New endpoints discovered
- Tech stack details
- Tested vectors + results (confirmed/exhausted/partial)
- Findings with severity
- Exhausted techniques with WHY they failed and how many variants tried

### Flush Cycle (Every 3 Subagent Completions)

```bash
python3 tools/global_brain.py sync-from-local    # Cross-engagement sync
```

Plus:
- Re-run `/surface` to re-rank priorities with new brain knowledge
- Context checkpoint — if >60% context used, save state and recommend `--resume`

### Resume Protocol

`/autopilot --resume` reads brain state to determine:
- Which targets are exhausted (skip)
- Which targets have been partially tested (continue from where we left off)
- Which P1 targets haven't been started (pick these up)
- What findings are confirmed but not yet reported

## 6. Evidence Protocol

- `poc-builder` agent ALWAYS captures evidence (screenshot + recording via `capture.py`)
- No other agent captures evidence
- Evidence paths verified with `ls` before referencing in reports
- poc-builder added to its prompt: "You MUST run `python3 tools/capture.py screenshot` and `python3 tools/capture.py record` as part of building every PoC. Evidence is not optional."

## 7. Hunt Command Updates

`/hunt` updated to:
1. Read policy.md → format preamble (ENFORCED)
2. Tech stack detection
3. `search_techniques` + `search_payloads` before dispatching any hunter (ENFORCED)
4. Dispatch specialized hunter with policy preamble + writeup intelligence
5. If hunter signals different vuln class → adaptive re-search + re-dispatch
6. After hunter completes → brain update
7. If finding → dispatch /validate, then /chain if PASS

## 8. Files Created/Modified

### New Files
- `rules/chain-table.md` — capability→next-bug table (extracted from chain-builder)
- `rules/never-submit.md` — never-submit list + conditionally-valid table (extracted from validator)

### Modified Files
- `.claude/commands/autopilot.md` — complete rewrite as orchestrator
- `.claude/commands/chain.md` — thin dispatcher
- `.claude/commands/pipeline.md` — recon-only, stops before hunting
- `.claude/commands/hunt.md` — add policy preamble, enforce writeup search
- `.claude/commands/triage.md` — strip inline gate, dispatch validator
- `.claude/agents/autopilot.md` — complete rewrite (lean orchestration)
- `.claude/agents/chain-builder.md` — reference rules/chain-table.md
- `.claude/agents/validator.md` — reference rules/never-submit.md for the list
- `.claude/agents/poc-builder.md` — add evidence capture requirement
- `CLAUDE.md` — update workflow section
