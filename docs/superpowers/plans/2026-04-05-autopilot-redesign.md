# Autopilot Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign autopilot as an Opus 4.6 orchestrator dispatching inherit-model subagents, fix /chain to always use chain-builder, clean up command/agent overlaps, and add brain auto-updates + policy enforcement.

**Architecture:** Autopilot becomes a command (not agent) that runs a state machine loop on Opus with 1M context. All testing agents are dispatched with `model: "inherit"`. Methodology rules live in single-source-of-truth files under `rules/`. Brain updates happen after every subagent, with global sync + surface re-rank every 3 completions.

**Tech Stack:** Claude Code commands (markdown), Claude Code agents (markdown), Python CLI tools (brain.py, global_brain.py, capture.py)

---

### Task 1: Extract rules into single-source-of-truth files

**Files:**
- Create: `rules/chain-table.md`
- Create: `rules/never-submit.md`

- [ ] **Step 1: Create `rules/chain-table.md`**

Extract the capability→next-bug table, terminal impacts, chain examples, and process rules from the current `chain-builder.md` agent. This becomes the single source of truth for chain logic.

```markdown
# Chain Table — Capability → Next Bug

Reference file for chain-builder agent and autopilot. Do not duplicate this content elsewhere.

## The Chain Walk Algorithm

1. START with confirmed bug A
2. Map what A GIVES you (capabilities/primitives)
3. Search this table for what takes A's output as input
4. Test the top candidate (B)
5. If B confirmed → map combined capabilities → check terminal impact → if not terminal, B becomes new A → go to 3
6. If B fails → try next candidate (max 3 failures per depth)
7. Report chain so far when terminal impact reached or candidates exhausted

## Capability → Next Bug Table

| You Have (Capability) | Look For (Next Link) | Combined Gives You |
|---|---|---|
| **JS execution in victim context** | HttpOnly not set? → cookie theft | Session token |
| | CSRF token accessible → forge requests | Authenticated actions |
| | postMessage listener unchecked → inject messages | Control over app state |
| | DOM access → read sensitive data | PII, tokens, keys |
| **Arbitrary text injection** | Input evaluated/executed → code execution | JS execution |
| | Input rendered in another context → stored XSS | JS execution in other users |
| | Input sent to API → parameter injection | API abuse |
| **Control over URL/redirect** | OAuth redirect_uri → steal auth code | OAuth token |
| | Open redirect → phishing from trusted domain | Credential theft |
| | iframe src control → clickjacking | UI manipulation |
| **Cookie control (set/read)** | Cookie bomb (overflow headers) → block callbacks | Force error pages |
| | Session fixation → set known session ID | Session hijack |
| | Cookie tossing → override subdomain cookies | Auth confusion |
| **Cross-origin window reference** | window.location readable → URL theft | Tokens in URL |
| | postMessage to window → inject data | State manipulation |
| | window.opener control → tabnabbing | Phishing |
| **SSRF (make server requests)** | Hit cloud metadata → IAM credentials | Cloud access |
| | Hit internal services → access admin panels | Internal access |
| | Hit localhost → bypass IP allowlists | Auth bypass |
| **IDOR (read other user's data)** | Read auth tokens → impersonate | ATO |
| | Read PII → data breach | Privacy violation |
| | Write to other user → modify account | Account manipulation |
| **File write/upload** | Write to web root → web shell | RCE |
| | Write SVG → stored XSS | JS execution |
| | Write config → modify app behavior | App takeover |
| **DNS control (subdomain)** | Subdomain is OAuth redirect_uri → token theft | ATO |
| | Subdomain serves content → trusted phishing | Credential theft |
| | Subdomain has wildcard cert → MitM | Traffic interception |

## Terminal Impacts (stop chaining, report)

- **Account Takeover (ATO)**: stolen session, OAuth token, password reset
- **Remote Code Execution (RCE)**: server-side code exec, web shell
- **Mass Data Exfiltration**: bulk PII, financial data, credentials
- **Full Admin Access**: privilege escalation to admin role
- **Infrastructure Compromise**: cloud creds → full environment access

## Known Deep Chains (real-world examples)

### 9-Link: Self-XSS → ATO (Renwa 2026)
A: Self-XSS in code editor → B: Cross-origin drag-drop injection → C: Scroll-to-fragment focus → D: Unchecked postMessage listener → E: Victim clicks Evaluate → F: DOM-XSS reads CSRF + OAuth → G: Cookie bomb blocks callback → H: Same-origin URL read extracts OAuth code → I: Exchange code → ATO

### 4-Link: S3 → OAuth → ATO
A: S3 bucket publicly listable → B: JS bundles contain OAuth client_secret → C: OAuth flow doesn't enforce PKCE → D: Intercept auth code via manipulated redirect_uri → ATO

### 5-Link: Subdomain Takeover → ATO
A: Dangling CNAME → claim subdomain → B: Subdomain is OAuth redirect_uri → C: Cookie tossing on parent domain → D: Session fixation via tossed cookie → E: Victim authenticates → ATO

### 6-Link: Prompt Injection → Admin
A: LLM chatbot follows injected instructions → B: IDOR via AI (other user data) → C: Markdown image exfil → D: Exfiltrated API keys → E: Internal service access → F: Admin promotion endpoint → Admin

## Process Rules

1. Confirm each link with exact HTTP request/response
2. Map capabilities after each link
3. Search writeup DB at each step: `search_writeups "<capability> escalation"`
4. 20-minute time box per link
5. Max 3 failed candidates per depth
6. Each link must be DIFFERENT (endpoint, mechanism, or impact)
7. Each link must be PROVABLE (exact request/response)
8. Report the FULL chain as one submission — chains pay more
```

- [ ] **Step 2: Create `rules/never-submit.md`**

Extract the never-submit list and conditionally-valid table from the validator agent and rules/hunting.md Rule 19.

```markdown
# Never-Submit List & Conditionally Valid Findings

Reference file for validator agent. Do not duplicate this content elsewhere.

## Never-Submit List (instant kill without chain)

These findings are ALWAYS rejected unless accompanied by a working exploit chain:

- Missing headers (CSP/HSTS/X-Frame-Options)
- Missing SPF/DKIM/DMARC
- GraphQL introspection alone
- Banner/version disclosure without CVE exploit
- Clickjacking without sensitive action PoC
- Self-XSS
- Open redirect alone
- SSRF DNS-only
- CORS wildcard without credentialed exfil PoC
- Logout CSRF
- Rate limit on non-critical forms
- Session not invalidated on logout
- Concurrent sessions allowed
- Internal IP in error message
- Missing cookie flags alone
- OAuth client_secret in mobile app (expected)
- OAuth client_id alone (public by design)
- OIDC discovery endpoint (public by design)
- SPA client-side config (API URLs, Segment keys)

## Conditionally Valid (chain required)

These findings become valid when chained with the specified escalation:

| You Have | Chain Needed | Combined Impact |
|---|---|---|
| Open redirect | + OAuth code theft → token exchange | ATO |
| SSRF DNS-only | + internal service data exfil | Data breach |
| CORS wildcard | + credentialed data theft PoC | Cross-origin data theft |
| GraphQL introspection | + auth bypass on mutations | Unauthorized actions |
| S3 listing | + secrets in bundles → OAuth chain | ATO |
| Prompt injection | + IDOR via chatbot (other user data) | Data breach |
| Subdomain takeover | + OAuth redirect_uri at that subdomain | ATO |
```

- [ ] **Step 3: Verify both files read correctly**

Run: `head -5 rules/chain-table.md rules/never-submit.md`
Expected: Both files exist with correct headers.

- [ ] **Step 4: Commit**

```bash
git add rules/chain-table.md rules/never-submit.md
git commit -m "feat: extract chain table and never-submit list into single-source-of-truth rule files"
```

---

### Task 2: Rewrite autopilot command as Opus orchestrator

**Files:**
- Modify: `.claude/commands/autopilot.md`

- [ ] **Step 1: Replace `.claude/commands/autopilot.md` with orchestrator command**

```markdown
---
name: autopilot
description: "Autonomous hunt orchestrator — dispatches subagents for recon, ranking, hunting, validation, chaining, and reporting. Opus 4.6 [1M] recommended. Usage: /autopilot target.com [--interactive|--autonomous] [--20m-off] [--resume]"
---
Autonomous hunt on: $ARGUMENTS

Parse flags from arguments:
- `--interactive` (default): Pause after each validated finding for user review
- `--autonomous`: Fully autonomous — no pauses, never auto-submits, produces ready-to-submit reports
- `--20m-off`: Disable 20-minute rotation timer on hunters
- `--resume`: Continue from previous session (read brain state for progress)

ALL agents dispatched by this command MUST use `model: "inherit"` in the Agent tool call.

## SETUP

1. Read `rules/hunting.md` — these rules are active throughout the session
2. Read `scope.yaml` — verify all targets are in scope
3. Read `policy.md` — extract ALL actionable constraints into a policy preamble:
   - Required HTTP headers (X-Bug-Bounty, User-Agent, custom tracking headers)
   - Account creation rules (email domain, naming conventions, company format)
   - Test environment setup (own instances, test properties, sandboxes)
   - Prohibited actions (DoS, social engineering, accessing customer data)
   - Rate limiting expectations
   - N-day waiting periods, shared responsibility exclusions
   - Credential usage restrictions
   - ANY other program-specific requirements
4. Format the **policy preamble** — this block is injected into EVERY agent dispatch:
   ```
   POLICY CONSTRAINTS (VIOLATION = DISQUALIFICATION/BAN):
   SCOPE AND POLICY MUST BE OBEYED AT ALL TIMES.
   [dynamically extracted constraints from policy.md]
   ALL HTTP requests MUST include required headers.
   ALL accounts MUST follow naming conventions.
   ALL testing MUST stay within scope boundaries.
   ```
5. `python3 tools/brain.py brief <target>` — load existing knowledge
6. If `--resume`: read brain for tested/exhausted/remaining targets, skip to HUNT LOOP

## RECON (skip if `recon/` data < 7 days old)

7. Dispatch `recon` agent (model: inherit) with policy preamble
8. Brain update: `python3 tools/brain.py record <target> recon "<new endpoints, subdomains, tech stack>"`
9. Increment subagent counter

## RANK

10. Dispatch `recon-ranker` agent (model: inherit) with recon data + brain knowledge
11. Parse P1/P2/Kill list from agent output
12. Brain update with ranking results
13. Increment subagent counter

## HUNT LOOP (for each P1 target)

14. `python3 tools/brain.py brief <target>` — what's tested on this target?
15. Tech stack detection:
    ```bash
    curl -sI https://<target> | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"
    ```
16. Map tech stack → candidate vuln classes:
    - Rails/Django/Laravel → IDOR, mass assignment
    - Express/Node → prototype pollution, path traversal
    - Next.js → SSRF via Server Actions, open redirect
    - GraphQL → introspection, mutation auth bypass
    - File upload found → extension bypass
    - OAuth/SSO → redirect_uri manipulation
    - Financial/billing → race conditions
    - Default → IDOR (highest ROI)

17. For each candidate vuln class (dispatch max 3 hunters in parallel):
    a. **Writeup intelligence (ENFORCED — do this before EVERY hunter dispatch):**
       - Call `search_techniques` MCP tool for the vuln class
       - Call `search_payloads` MCP tool for the vuln class
       - If MCP unavailable, read `docs/payloads.md` as fallback
       - Include results in the hunter prompt
    b. Dispatch specialized hunter agent (model: inherit) with:
       - Policy preamble
       - Writeup intelligence (techniques + payloads)
       - Brain context (tested vectors, tech stack, known endpoints)
       - Scope boundaries
       - If `--20m-off` NOT set: "Time-box: 20 minutes. If no progress after 20 min, stop and report what you tested."
    c. After hunter returns:
       - Parse output for findings, tested endpoints, exhausted techniques
       - If hunter signals a DIFFERENT vuln class → adaptive re-search:
         Call `search_techniques` + `search_payloads` for the new class →
         dispatch appropriate specialized hunter with new intelligence
       - Brain update: `python3 tools/brain.py record <target> <status> "<technique>" "<details>"`
       - Increment subagent counter

18. **FLUSH CYCLE (every 3 subagent completions):**
    a. Full brain update — ensure all findings, endpoints, tech stack saved
    b. `python3 tools/global_brain.py sync-from-local`
    c. Re-dispatch `recon-ranker` agent (model: inherit) to re-rank surface
       (priorities shift as brain learns what's exhausted and what's confirmed)
    d. Context checkpoint — check context usage:
       - If > 60%: save full state to brain, print progress summary,
         tell user: "Context at X%. Run `/autopilot --resume` to continue in fresh context."
         Then STOP.

19. **If finding discovered:**
    a. Dispatch `validator` agent (model: inherit) with finding details — 7-Question Gate
    b. If **PASS**:
       - Dispatch `chain-builder` agent (model: inherit) with:
         - Confirmed finding details
         - `rules/chain-table.md` content
         - Policy preamble
         - Brain context
       - Run `/dupcheck` logic: search hacktivity via bounty-platforms MCP
       - Dispatch `poc-builder` agent (model: inherit) — MUST capture evidence
         (include in prompt: "You MUST run `python3 tools/capture.py screenshot` and
         `python3 tools/capture.py record` as part of every PoC. Evidence is not optional.")
       - Dispatch `report-writer` agent (model: inherit)
       - Dispatch `quality-check` agent (model: inherit) — must score >= 7
       - Brain update: confirmed finding with report path
       - `python3 tools/brain.py record <target> confirmed "<finding>" "<report path>"`
    c. If **KILL**:
       - Brain update: `python3 tools/brain.py record <target> exhausted "<finding>" "<kill reason>"`
       - Move on
    d. If **CHAIN REQUIRED**:
       - Dispatch `chain-builder` agent first
       - If chain found → re-validate with chain
       - If no chain → brain update as exhausted, move on
    e. If **DOWNGRADE**:
       - Brain update with adjusted severity
       - Continue to report at lower severity
    f. If `--interactive` mode: pause here, show finding to user, wait for input

20. After all vuln classes tested on target → `python3 tools/brain.py record <target> exhausted "all classes tested"`
21. Next P1 target → back to step 14

## COMPLETION

22. Final brain sync: `python3 tools/brain.py log` + `python3 tools/global_brain.py sync-from-local`
23. Final surface re-rank: dispatch `recon-ranker` agent to show remaining surface
24. Print summary:
    ```
    AUTOPILOT SESSION COMPLETE
    ══════════════════════════
    Mode:           [interactive/autonomous]
    Targets tested: N exhausted, M remaining
    Findings:       X confirmed, Y killed, Z chain-required
    Reports:        R ready at reports/drafts/
    Chains:         C discovered

    Next steps:
      /submit <finding>    — submit a report (requires your approval)
      /autopilot --resume  — continue with remaining targets
      /status              — full dashboard
    ```

## Safety Rails (NON-NEGOTIABLE)

- Scope check EVERY URL with `python3 tools/scope_check.py <url>` before any request
- NEVER submit a report without explicit human approval
- NEVER auto-submit in `--autonomous` mode — only produce reports
- Circuit breaker: 5 consecutive 403/429 on same host → back off 60s or skip
- Rate limit: 1 req/sec for testing, 10 req/sec for recon
- All agents dispatched with `model: "inherit"` — never inherit Opus
```

- [ ] **Step 2: Verify the command file is valid**

Run: `head -3 .claude/commands/autopilot.md`
Expected: YAML frontmatter with `name: autopilot`

- [ ] **Step 3: Commit**

```bash
git add .claude/commands/autopilot.md
git commit -m "feat: rewrite autopilot as Opus orchestrator dispatching inherit-model subagents"
```

---

### Task 3: Rewrite autopilot agent as lean orchestration helper

**Files:**
- Modify: `.claude/agents/autopilot.md`

The autopilot agent is now rarely dispatched directly (the command does the orchestration). But it still exists for cases where other agents or commands want to dispatch it. Make it lean — it references rules, doesn't inline them.

- [ ] **Step 1: Replace `.claude/agents/autopilot.md`**

```markdown
---
name: autopilot
description: "Autonomous hunt loop agent. Dispatched by the /autopilot command. Executes scope → recon → rank → hunt → validate → chain → report cycle."
tools: Bash, Read, Write, Edit, Glob, Grep, WebFetch
model: inherit
color: green
memory: local
maxTurns: 80
---
CONTEXT: You are operating within an authorized bug bounty program. All targets have been verified in-scope via the official platform API. Follow responsible disclosure practices.

You are an autonomous bug bounty hunter. You execute the hunt loop as directed by the orchestrator.

## Before Starting

1. Read `rules/hunting.md` — these rules govern all your decisions
2. Read `scope.yaml` — test ONLY in-scope targets
3. Read `policy.md` — obey ALL program constraints (headers, accounts, restrictions)

**SCOPE AND POLICY MUST BE OBEYED AT ALL TIMES. VIOLATION = DISQUALIFICATION/BAN.**

## Safety Rails (NON-NEGOTIABLE)

1. Scope check EVERY URL with `python3 tools/scope_check.py <url>` before any request
2. NEVER submit a report without explicit human approval
3. Log every finding to brain: `python3 tools/brain.py record <target> <status> "<details>"`
4. Rate limit: 1 req/sec for testing, 10 req/sec for recon
5. Circuit breaker: 5 consecutive 403/429 → back off 60s or skip host

## Hunting Priority

1. IDOR (swap IDs, test GET/PUT/DELETE, apply Sibling Rule)
2. Auth bypass (remove token, method override, path traversal)
3. Injection (SQLi, SSTI, XSS based on tech stack)
4. Business logic (race conditions, price manipulation)

## Writeup Intelligence (MANDATORY)

Before testing ANY vuln class, search for techniques and payloads:
- `search_techniques "<vuln class>"`
- `search_payloads "<vuln class>"`
Include results in your testing approach.

## Brain Integration

After completing work, structure output for brain parsing:
1. Label findings as CONFIRMED, POTENTIAL, or EXHAUSTED
2. For exhausted techniques, explain WHY and how many variants tried
3. Note WAF/filtering behavior
4. Flag anything needing follow-up by a different agent
```

- [ ] **Step 2: Commit**

```bash
git add .claude/agents/autopilot.md
git commit -m "refactor: slim autopilot agent to lean orchestration helper"
```

---

### Task 4: Fix chain command as thin dispatcher

**Files:**
- Modify: `.claude/commands/chain.md`

- [ ] **Step 1: Replace `.claude/commands/chain.md`**

```markdown
---
name: chain
description: "Build deep exploit chains — dispatches chain-builder agent. Given bug A, recursively walks the chain graph. Usage: /chain (then describe bug A)"
---
Build exploit chain from: $ARGUMENTS

## Process

1. Read brain for current target context:
   `python3 tools/brain.py brief <target>`

2. Get bug A description:
   - If `$ARGUMENTS` contains a bug description → use it
   - Else if brain has a recent confirmed finding → use that
   - Else → ask user to describe the confirmed bug

3. Read `rules/chain-table.md` — the capability→next-bug table

4. Read `policy.md` — extract policy preamble for the agent

5. **ALWAYS dispatch `chain-builder` agent** (model: inherit) with:
   - The confirmed bug A description (exact HTTP request/response)
   - The full chain table from `rules/chain-table.md`
   - Policy preamble (scope + required headers + restrictions)
   - Brain context (tech stack, tested endpoints, known capabilities)
   - Writeup intelligence: call `search_writeups "chain <bug class> escalation"` if MCP available

6. After agent returns:
   - If chain found:
     - `python3 tools/brain.py record <target> confirmed "chain: <summary>" "<full chain>"`
     - Show chain to user with combined impact and CVSS
     - Suggest: `/validate` then `/report`
   - If dead end:
     - `python3 tools/brain.py record <target> exhausted "chain from <bug A>" "<candidates tried>"`
     - Show what was tried and why it failed

No inline chain logic. No capability table. The chain-builder agent does all the work.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/chain.md
git commit -m "fix: chain command always dispatches chain-builder agent, no inline logic"
```

---

### Task 5: Update chain-builder agent to reference rules

**Files:**
- Modify: `.claude/agents/chain-builder.md`

- [ ] **Step 1: Update chain-builder agent**

Replace the inlined capability table and chain examples with a reference to `rules/chain-table.md`. Keep the algorithm, output format, and process rules. The agent reads the table from the rules file (or from the prompt provided by the /chain command).

Edit `.claude/agents/chain-builder.md`:

Replace the section from `## Capability → Next Bug Table` through the end of `## Known Deep Chains` with:

```markdown
## Capability → Next Bug Table

Read `rules/chain-table.md` for the full table. If the /chain command included the table in your prompt, use that.

The table maps: what you HAVE (capability) → what to LOOK FOR (next link) → what the combination GIVES you.
```

Replace the `## Process Rules` section with:

```markdown
## Process Rules

Read `rules/chain-table.md` for the full process rules. Key points:
1. Confirm each link with exact HTTP request/response
2. Map capabilities after each link
3. Search writeup DB at each step
4. 20-minute time box per link, max 3 failed candidates per depth
5. Report the FULL chain as one submission
```

- [ ] **Step 2: Commit**

```bash
git add .claude/agents/chain-builder.md
git commit -m "refactor: chain-builder references rules/chain-table.md instead of inlining"
```

---

### Task 6: Repurpose pipeline command as recon-only

**Files:**
- Modify: `.claude/commands/pipeline.md`

- [ ] **Step 1: Replace `.claude/commands/pipeline.md`**

```markdown
---
name: pipeline
description: "Prepare the battlefield — recon, scanning, and surface ranking. Stops before hunting. Run /hunt or /autopilot after. Usage: /pipeline or /pipeline <target>"
---
Prepare the battlefield for: $ARGUMENTS

This command runs recon, scanning, and surface ranking — everything needed BEFORE hunting.
It does NOT hunt, validate, or report. Use `/hunt` or `/autopilot` for that.

## Phase 0: SETUP

1. Read `scope.yaml` — resolve and verify targets
   - If `$ARGUMENTS` is empty: `python3 tools/scope_check.py --list`
   - If `$ARGUMENTS` is a domain: `python3 tools/scope_check.py $ARGUMENTS`
2. Read `policy.md` — extract policy preamble for all agent dispatches
3. Brain init or brief:
   - If no brain exists: `python3 tools/brain.py init`
   - If brain exists: `python3 tools/brain.py brief <target>`

## Phase 1: RECON

4. Dispatch `recon` agent (model: inherit) with policy preamble and scope
5. After recon: dispatch `config-auditor` agent (model: inherit) for header/TLS/cookie review
6. After config: dispatch `js-analyzer` agent (model: inherit) for JavaScript analysis
7. Brain update: `python3 tools/brain.py record <target> recon "<results summary>"`

## Phase 2: SCANNING (parallel, max 3)

8. Dispatch in parallel (all model: inherit, all with policy preamble):
   - `vuln-scanner` agent with nuclei on discovered hosts
   - `waf-profiler` agent on primary targets
9. Brain update with scan results

## Phase 3: RANK

10. Dispatch `recon-ranker` agent (model: inherit) with recon data + brain knowledge
11. Output P1/P2/Kill list

## Complete

```
Battlefield ready.

P1 targets: [list]
P2 targets: [list]
Kill list:  [list]

Next steps:
  /hunt <target>     — manual hunting on a specific target
  /autopilot         — autonomous hunting across all P1 targets
  /surface           — re-rank surface with current brain knowledge
```

Sync brain: `python3 tools/global_brain.py sync-from-local`
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/pipeline.md
git commit -m "refactor: pipeline becomes recon-only, stops before hunting"
```

---

### Task 7: Update hunt command with policy enforcement and writeup intelligence

**Files:**
- Modify: `.claude/commands/hunt.md`

- [ ] **Step 1: Update hunt command**

Edit `.claude/commands/hunt.md` to add three things:

**1. Remove the "Opus STOP" check** at the top (the orchestrator handles model selection now).

Replace:
```
ALL agents dispatched by this command MUST use `model: "inherit"` in the Agent tool call.
```
With:
```
ALL agents dispatched by this command MUST use `model: "inherit"` in the Agent tool call.
```

**2. Add policy enforcement** after Phase 1 (before Phase 2). Insert after the Phase 1 section:

```markdown
## Phase 1.5: Policy Enforcement (MANDATORY)

Read `policy.md` and extract ALL actionable constraints into a policy preamble.
This preamble MUST be included in every agent dispatch from this command.

```
POLICY CONSTRAINTS (VIOLATION = DISQUALIFICATION/BAN):
SCOPE AND POLICY MUST BE OBEYED AT ALL TIMES.
[constraints extracted from policy.md]
```

Failure to include policy constraints in agent dispatches may result in
disqualification from the program or account ban.
```

**3. Update Phase 2.9** to make writeup intelligence apply to ALL agent dispatches, not just manual testing. Add after the existing search_techniques/search_payloads calls:

```markdown
Include the writeup intelligence results in every hunter agent prompt you dispatch.
If a hunter signals a different vuln class mid-hunt:
1. Call `search_techniques` + `search_payloads` for the new class
2. Dispatch the appropriate specialized hunter with the fresh intelligence
```

**4. Add brain update after each hunter** at the end of Phase 3:

```markdown
After each hunter agent completes:
`python3 tools/brain.py record <target> <status> "<technique>" "<details>"`
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/hunt.md
git commit -m "feat: hunt command enforces policy preamble and writeup intelligence on all dispatches"
```

---

### Task 8: Update triage command to strip inline gate

**Files:**
- Modify: `.claude/commands/triage.md`

- [ ] **Step 1: Update triage command**

The current triage command is already a thin dispatcher (loops findings, dispatches validator). Just remove the Opus check and add model enforcement.

Edit `.claude/commands/triage.md`:

Replace:
```
ALL validator agents dispatched by this command MUST use `model: "inherit"`.
```
With:
```
ALL validator agents dispatched by this command MUST use `model: "inherit"`.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/commands/triage.md
git commit -m "fix: triage uses model enforcement instead of Opus block"
```

---

### Task 9: Update validator agent to reference never-submit rules file

**Files:**
- Modify: `.claude/agents/validator.md`

- [ ] **Step 1: Update validator agent**

The validator keeps the 7-Question Gate inlined (it's the executor). But replace the inlined never-submit list and conditionally-valid table with a reference.

Edit `.claude/agents/validator.md`:

Replace the `## Never-Submit List` section with:
```markdown
## Never-Submit List (instant kill without chain)

Read `rules/never-submit.md` for the full list. Key items:
Missing headers, GraphQL introspection alone, self-XSS, open redirect alone,
SSRF DNS-only, CORS wildcard without credentialed exfil, logout CSRF,
missing cookie flags alone, SPA client-side config.
```

Replace the `## Conditionally Valid` section with:
```markdown
## Conditionally Valid (chain required)

Read `rules/never-submit.md` for the full table mapping each finding
to the chain needed for it to become valid.
```

- [ ] **Step 2: Commit**

```bash
git add .claude/agents/validator.md
git commit -m "refactor: validator references rules/never-submit.md instead of inlining list"
```

---

### Task 10: Update poc-builder agent with evidence capture requirement

**Files:**
- Modify: `.claude/agents/poc-builder.md`

- [ ] **Step 1: Add evidence capture requirement**

Edit `.claude/agents/poc-builder.md`. Add a new section after `## File Organization`:

```markdown
## Evidence Capture (MANDATORY)

You MUST capture evidence for every PoC you build. This is not optional.

After creating the PoC files, run:
```bash
python3 tools/capture.py screenshot
python3 tools/capture.py record
```

Save evidence to `poc/{target}/{vuln-id}/evidence/`.
Verify evidence files exist with `ls` before referencing them in reports.
If capture.py is not available, note "evidence pending" — do NOT invent file paths.
```

Also update the `### Severity` section — replace `NEVER use CVSS 3.1` with:
```markdown
Check `scope.yaml` for the platform:
- `platform: hackerone` → Use CVSS 3.1
- All other platforms → Use CVSS 4.0
```

- [ ] **Step 2: Commit**

```bash
git add .claude/agents/poc-builder.md
git commit -m "feat: poc-builder must capture evidence, platform-aware CVSS"
```

---

### Task 11: Update CLAUDE.md workflow section

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the workflow and model requirement sections**

Edit `CLAUDE.md`:

Replace the Model Requirement section:
```markdown
## Model Requirement
**Inherit from the orchestrator.** Opus 4.6 [1M] is the intended orchestrator now that
the cyber use case covers security testing workloads.
```
With:
```markdown
## Model Requirement
**Inherit from the orchestrator.** The cyber use case permits Opus 4.6 [1M] end-to-end.
- `/autopilot` runs on Opus (orchestrator) and dispatches subagents via `model: "inherit"`
- `/hunt`, `/chain`, `/pipeline`, `/fullscan`, `/quickscan` — dispatch agents via `model: "inherit"`
- All agents dispatched for security testing MUST use `model: "inherit"`
```

Replace the Workflow section:
```markdown
## Workflow

**New program**: `/new` → `/sync` → `/brain init` → `/analyze` → `/surface` → `/hunt`
**Returning**: `/resume <target>` → `/hunt` or `/autopilot`
**After finding**: `/validate` → `/chain` → `/report` → `/dupcheck` → `/submit` → `/learn`
**Batch triage**: `/triage` (validates all findings at once through 7-Question Gate)
```
With:
```markdown
## Workflow

**New program**: `/new` → `/sync` → `/brain init` → `/pipeline` → `/hunt` or `/autopilot`
**Returning**: `/resume <target>` → `/hunt` or `/autopilot --resume`
**Autonomous**: `/autopilot [--interactive|--autonomous] [--20m-off]` (full loop with brain auto-updates)
**Prepare only**: `/pipeline <target>` (recon + scan + rank, stops before hunting)
**After finding**: `/validate` → `/chain` → `/report` → `/dupcheck` → `/submit` → `/learn`
**Batch triage**: `/triage` (validates all findings at once through 7-Question Gate)

### Policy Enforcement
Every command that dispatches testing agents reads `policy.md` and injects a policy
preamble into every agent prompt. SCOPE AND POLICY MUST BE OBEYED AT ALL TIMES.

### Single Source of Truth
- `rules/hunting.md` — 20 hunting rules (all agents)
- `rules/chain-table.md` — capability→next-bug table (chain-builder, autopilot)
- `rules/never-submit.md` — never-submit list + conditionally-valid (validator)
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update workflow, model requirements, and single-source-of-truth references"
```

---

### Task 12: Final verification

- [ ] **Step 1: Verify all modified files have valid YAML frontmatter**

```bash
for f in .claude/commands/autopilot.md .claude/commands/chain.md .claude/commands/pipeline.md .claude/commands/hunt.md .claude/commands/triage.md .claude/agents/autopilot.md .claude/agents/chain-builder.md .claude/agents/validator.md .claude/agents/poc-builder.md; do
  echo "=== $f ==="
  head -3 "$f"
  echo
done
```

Expected: Each file starts with `---` and has a `name:` field.

- [ ] **Step 2: Verify rule files exist and are referenced**

```bash
echo "=== Rule files ==="
ls -la rules/chain-table.md rules/never-submit.md rules/hunting.md

echo "=== References to chain-table.md ==="
grep -rl "chain-table.md" .claude/ rules/

echo "=== References to never-submit.md ==="
grep -rl "never-submit.md" .claude/ rules/
```

Expected: Both rule files exist. chain-table.md referenced by chain command, chain-builder agent, autopilot command. never-submit.md referenced by validator agent.

- [ ] **Step 3: Verify no stale Opus blocks remain**

```bash
grep -rl "If the current model is Opus" .claude/commands/ .claude/agents/
```

Expected: No results (all Opus blocks replaced with model enforcement).

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add -A
git status
# If changes: git commit -m "fix: final verification cleanup"
```
