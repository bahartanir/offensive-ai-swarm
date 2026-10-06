#!/usr/bin/env python3
"""
scaffold.py — Create new engagement workspaces.

Usage:
    python3 tools/scaffold.py <platform> <program>
    python3 tools/scaffold.py hackerone tesla
    python3 tools/scaffold.py immunefi uniswap

Every workspace ships with the full agent + skill + tool inventory plus
project-scoped provider files for Codex, Gemini, Cursor, Windsurf, Copilot,
and OpenClaw. The generated CLAUDE.md / AGENTS.md are universal hunting
briefs with a surface-driven dispatch map (no per-template branching). The
hunter reads recon output and routes through the matching specialist
skill/agent.
"""

import argparse
import os
import shutil
import sys
from pathlib import Path
from datetime import datetime


_PROJECT_PROVIDER_TARGETS = (
    "codex",
    "gemini",
    "cursor",
    "windsurf",
    "copilot",
    "openclaw",
)


def _prune_stale_files(src_dir: Path, dst_dir: Path, glob: str = "*") -> int:
    """Delete files in dst_dir that no longer exist in src_dir.

    Used for suite-shared directories (e.g. .claude/agents/, rules/) where
    every file is owned by the suite, never the workspace. Returns count
    pruned.
    """
    if not src_dir.exists() or not dst_dir.exists():
        return 0
    src_names = {p.name for p in src_dir.glob(glob)}
    pruned = 0
    for f in dst_dir.glob(glob):
        if f.is_file() and f.name not in src_names:
            f.unlink()
            pruned += 1
    return pruned


def _prune_stale_subdirs(src_dir: Path, dst_dir: Path) -> int:
    """Delete subdirectories in dst_dir that no longer exist in src_dir.

    Used for suite-shared directories that contain per-skill or per-tool
    subdirectories (e.g. .claude/skills/, top-level skills/). Returns count
    pruned.
    """
    if not src_dir.exists() or not dst_dir.exists():
        return 0
    src_names = {p.name for p in src_dir.iterdir() if p.is_dir()}
    pruned = 0
    for d in dst_dir.iterdir():
        if d.is_dir() and d.name not in src_names:
            shutil.rmtree(d)
            pruned += 1
    return pruned


def _copy_shared_files(workspace: Path, suite_dir: Path):
    """Copy/update shared suite files (agents, commands, tools, MCP server, settings)."""
    import json as _json

    # What NOT to drop into a bounty workspace:
    # - tools/installer/  — multi-IDE installer; only needed at the suite root
    # - tools/installer/tests/, __pycache__, *.pyc — meta/test artefacts
    # - docs/assets/      — the project logo + README assets
    tools_ignore = shutil.ignore_patterns("installer", "__pycache__", "*.pyc")
    docs_ignore = shutil.ignore_patterns("assets", "__pycache__")

    # Scrub leftovers from pre-fix scaffolds (idempotent).
    for stale in (
        workspace / "tools" / "installer",
        workspace / "docs" / "assets",
        # Commands were migrated to skills in 2026-04 — remove the old dir
        # on workspaces scaffolded before the migration.
        workspace / ".claude" / "commands",
    ):
        if stale.exists() and stale.is_dir():
            shutil.rmtree(stale)

    # Copy agents (overwrite + prune — suite-shared, not user-modified).
    # shutil.copytree(dirs_exist_ok=True) doesn't remove files that no
    # longer exist in source, so we explicitly prune anything in the
    # workspace's .claude/agents/ that isn't in suite/.claude/agents/.
    # Stale examples: escalator.md, xss-{reflected,stored,dom}.md (merged
    # into xss-hunter), autopilot.md (migrated to a skill).
    agents_src = suite_dir / ".claude" / "agents"
    agents_dst = workspace / ".claude" / "agents"
    agents_dst.mkdir(parents=True, exist_ok=True)
    if agents_src.exists():
        shutil.copytree(agents_src, agents_dst, dirs_exist_ok=True)
        _prune_stale_files(agents_src, agents_dst, glob="*.md")

    # Copy Claude Code skills (overwrite + prune) — slash-command skills
    # in .claude/skills/<name>/SKILL.md. Each skill is a directory; prune
    # whole directories that no longer exist in source.
    claude_skills_src = suite_dir / ".claude" / "skills"
    claude_skills_dst = workspace / ".claude" / "skills"
    claude_skills_dst.mkdir(parents=True, exist_ok=True)
    if claude_skills_src.exists():
        shutil.copytree(claude_skills_src, claude_skills_dst, dirs_exist_ok=True)
        _prune_stale_subdirs(claude_skills_src, claude_skills_dst)

    # Copy CLI tools (overwrite) — exclude the installer package and its tests
    tools_src = suite_dir / "tools"
    if tools_src.exists():
        shutil.copytree(
            tools_src, workspace / "tools",
            dirs_exist_ok=True, ignore=tools_ignore,
        )

    # Copy MCP servers (overwrite)
    for mcp_dir_name in ["mcp-bounty-server", "mcp-writeup-server"]:
        mcp_src = suite_dir / mcp_dir_name
        if mcp_src.exists():
            shutil.copytree(mcp_src, workspace / mcp_dir_name, dirs_exist_ok=True)

    # Copy rules, wordlists, hooks, skills, docs. docs/ gets an ignore
    # filter since the project's README assets live there and bounty
    # workspaces don't need them.
    for dirname in ["rules", "wordlists", "hooks", "skills", "docs"]:
        src = suite_dir / dirname
        if src.exists():
            ignore = docs_ignore if dirname == "docs" else None
            shutil.copytree(
                src, workspace / dirname,
                dirs_exist_ok=True, ignore=ignore,
            )

    # Prune stale skill subdirectories (top-level skills/) and stale
    # rule files (rules/). Both are suite-shared; user work product
    # never lives in them. tools/ is intentionally not pruned because
    # users and agents drop target-specific scripts there.
    _prune_stale_subdirs(suite_dir / "skills", workspace / "skills")
    _prune_stale_files(suite_dir / "rules", workspace / "rules", glob="*.md")

    # Write .claude/settings.json with absolute paths (hooks + statusline;
    # MCP servers now live in .mcp.json per current Claude Code docs).
    settings_src = suite_dir / ".claude" / "settings.json"
    settings_dst = workspace / ".claude" / "settings.json"
    if settings_src.exists():
        settings = _json.loads(settings_src.read_text())

        # If existing settings.json has user customizations, preserve permissions
        if settings_dst.exists():
            try:
                existing = _json.loads(settings_dst.read_text())
                # Preserve user's custom permission rules
                if "permissions" in existing:
                    # Merge: keep user's extra allows, keep our base
                    user_allows = set(existing.get("permissions", {}).get("allow", []))
                    base_allows = set(settings.get("permissions", {}).get("allow", []))
                    settings["permissions"]["allow"] = sorted(base_allows | user_allows)
            except:
                pass

        # Leave $CLAUDE_PROJECT_DIR-based hook commands alone — they already
        # resolve correctly in the workspace session. Only normalize the
        # statusLine if it's still the bare "bash tools/..." form from an
        # older suite checkout, and only rewrite cost_hook invocations that
        # lack a $CLAUDE_PROJECT_DIR prefix. The shim-compatible `uv run
        # python3` form is enforced globally.
        statusline_cmd = settings.get("statusLine", {}).get("command", "")
        if statusline_cmd.startswith("bash tools/"):
            settings["statusLine"]["command"] = (
                "bash $CLAUDE_PROJECT_DIR/" + statusline_cmd[len("bash "):]
            )

        if "hooks" in settings:
            for matchers in settings["hooks"].values():
                for matcher in matchers:
                    for hook in matcher.get("hooks", []):
                        cmd = hook.get("command", "")
                        if hook.get("type") != "command":
                            continue
                        # Only rewrite legacy relative paths; leave
                        # $CLAUDE_PROJECT_DIR forms alone.
                        if "python3 tools/cost_hook.py" in cmd:
                            hook["command"] = cmd.replace(
                                "python3 tools/cost_hook.py",
                                "uv run python3 $CLAUDE_PROJECT_DIR/tools/cost_hook.py",
                            )

        settings_dst.write_text(_json.dumps(settings, indent=2) + "\n")

    # Write .mcp.json with absolute paths (project-scope MCP config — the
    # current Claude Code spec; read by any project-scope MCP-aware client).
    # Each server runs under `uv run --with mcp <abs-server.py>` so the MCP
    # SDK gets installed into uv's ephemeral venv — no system pip needed.
    mcp_src = suite_dir / ".mcp.json"
    mcp_dst = workspace / ".mcp.json"
    if mcp_src.exists():
        mcp = _json.loads(mcp_src.read_text())
        for name, script in (
            ("bounty-platforms", workspace / "mcp-bounty-server" / "server.py"),
            ("writeup-search",   workspace / "mcp-writeup-server" / "server.py"),
        ):
            if name in mcp.get("mcpServers", {}):
                mcp["mcpServers"][name]["command"] = "uv"
                mcp["mcpServers"][name]["args"] = [
                    "run", "--with", "mcp", str(script),
                ]
                mcp["mcpServers"][name].setdefault("env", {})
        mcp_dst.write_text(_json.dumps(mcp, indent=2) + "\n")

    # Ensure statusline is executable
    statusline_sh = workspace / "tools" / "pentest-statusline.sh"
    if statusline_sh.exists():
        statusline_sh.chmod(0o755)

    # Count what was copied
    agent_count = len(list(agents_dst.glob("*.md"))) if agents_dst.exists() else 0
    skill_count = (
        len([d for d in claude_skills_dst.iterdir() if d.is_dir() and (d / "SKILL.md").exists()])
        if claude_skills_dst.exists() else 0
    )
    tool_count = len(list((workspace / "tools").glob("*.py"))) + len(list((workspace / "tools").glob("*.sh"))) if (workspace / "tools").exists() else 0
    return agent_count, skill_count, tool_count


def _install_project_provider_assets(workspace: Path):
    """Install project-scoped provider assets into a scaffolded workspace.

    Scaffold first copies the suite assets into the workspace, then loads the
    installer sources from *that workspace*. That makes generated Codex/Gemini/
    Cursor/etc. paths point at the engagement workspace itself instead of the
    source checkout used to run scaffold.py.
    """
    from tools.installer import sources as sources_mod
    from tools.installer.base import InstallContext
    from tools.installer.scopes import Scope
    from tools.installer.targets import by_id

    bundle = sources_mod.load(workspace)
    written = 0
    merges = 0
    warnings: list[str] = []

    for target_id in _PROJECT_PROVIDER_TARGETS:
        cls = by_id(target_id)
        if cls is None:
            warnings.append(f"{target_id}: target not registered")
            continue
        target = cls()
        ctx = InstallContext(
            sources=bundle,
            scope=Scope.PROJECT,
            project_root=workspace,
            force=True,
            backup_existing=False,
        )
        result = target.install(ctx)
        if result.errors:
            joined = "; ".join(result.errors)
            raise RuntimeError(f"{target_id} provider install failed: {joined}")
        written += len(result.files_written)
        merges += len(result.merges)
        warnings.extend(f"{target_id}: {w}" for w in result.warnings)

    return written, merges, warnings


def _generate_claude_md(workspace: Path, platform: str, program: str) -> str:
    """Generate the CLAUDE.md hunting brief for a workspace.

    Universal — no per-template branching. Surface-driven dispatch via the
    Skill Dispatch Map; the hunter routes by what recon finds, not by what
    template the workspace was scaffolded from.
    """
    return f"""# Authorized Security Testing — {platform.title()} / {program}

## Authorization

This workspace is for **authorized bug bounty research** on the {program} program ({platform}). Targets verified in-scope via the official platform API before testing. Scope, policy, and safe-harbor in `scope.yaml` and `policy.md`. No destructive testing, no DoS, no data modification. Findings reported through the official platform.

## Model Requirement

**Inherit from the orchestrator.** Opus 4.7 [1M] is the intended orchestrator for this cyber use case. Subagents dispatched with `model: "inherit"`. SAST reasoning agents (`sast-flow-tracer`, `sast-gap-analyzer`) pin `model: "opus"` explicitly.

---

## The Hunting Bias (read BEFORE every hunt)

Your job is paying impact, not coverage. Decision-making, not checklists.

- **Validity ratio > volume.** N/A submissions hurt your ratio AND clog the program's queue. 1 mid-five-figure beats 5 informational.
- **Chain-first default.** Single-bug findings on H1 frequently pay $0–$500. Chains pay 10x. After confirming bug A, run `/chain` BEFORE `/report` unless impact is already terminal (RCE, full ATO, cross-tenant data dump).
- **First NO from the 7-Question Gate kills the finding.** Run `/validate` before drafting. Don't write a single line of report prose without PASS.
- **Read brain BEFORE testing.** `uv run python3 $CLAUDE_PROJECT_DIR/tools/brain.py brief <target>`. Skip EXHAUSTED vectors. Cross-target learning compounds when you record outcomes.
- **WAF block is not "not vulnerable".** Read `rules/waf-bypass-protocol.md` and work levels 1→7 with at least 3 payloads each before concluding.
- **Stop fast.** 5× consecutive 403/429 → circuit breaker triggers, back off 60s, switch endpoint.
- **Be ruthless about the never-submit list** (`rules/never-submit.md`). Don't even draft from it.

---

## Skill Dispatch Map

The `hunt-*` skills carry 700–1,100 lines each of methodology + 2024-2026 CVE catalog. **Route hunting through the matching specialist BEFORE generic enumeration** — it's how you avoid reinventing the wheel and submitting duplicates.

### Highest 2025-2026 meta — check FIRST after recon

| Signal in target | Dispatch |
|------------------|----------|
| RSC fingerprint (`__NEXT_DATA__`, `_next/static/`, `Server-Action:` header) | `rce-hunter` — CVE-2025-55182 candidate (CVSS 10.0, exploited in wild within 24h) |
| Chatbot / RAG / "AI assistant" / MCP server / model registry | `llm-ai-hunter` — OWASP LLM Top 10 v2025, FIRST priority on AI features |
| OAuth / OIDC / SAML / JWT in headers or login flow | `oauth-hunter` — 770-line skill, PKCE downgrade / alg confusion / SAML XSW |
| Multi-tenant SaaS (tenant ID in URL/header/query) | `idor-hunter` — OneUptime CVE-2026-30956 / Zitadel / Inforcer cross-tenant patterns |
| DOMPurify <3.1.3 in JS bundle | `xss-hunter` — Sub-technique C (mXSS bypass family) |

### Modern JS / framework

| Signal | Dispatch |
|--------|----------|
| React / Vue / Angular + sanitizer-in-bundle | `xss-hunter` — DOMPurify mXSS, framework sink inventory (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml`) |
| Trix / CKEditor / TinyMCE / Quill / Slate / Lexical rich-text | `xss-hunter` — Crown Jewel #7 (Trix mXSS H1 #2819573) |
| Markdown / wiki / comment renderer | `xss-hunter` — Sub-technique I (CVE-2024-21535 markdown-to-jsx family) |
| Prototype-pollution gadgets (lodash merge / `$.extend(true,...)`) | `xss-hunter` — Sub-technique E (Shopify lodash-merge pattern) |

### API / multi-tenant

| Signal | Dispatch |
|--------|----------|
| `Authorization: Bearer eyJ...` (JWT) | `oauth-hunter` subtype=jwt — alg confusion / `kid` / `jku` / `none` |
| `/graphql` endpoint or introspection enabled | `graphql-audit` + `idor-hunter` (field-level / nested-object pivots) |
| Tenant ID / org ID in path, header, or query | `idor-hunter` — cross-tenant first |
| Mass-assignment-prone endpoints (`PUT /users/me`, `PATCH /accounts/<id>`) | `business-logic` + `privilege-escalation` |
| Coupon / balance / credit / one-shot transitions | `race-condition` |
| Webhook / URL-import / file-from-URL features | `ssrf-hunter` |

### AI / ML

| Signal | Dispatch |
|--------|----------|
| MCP server endpoint advertised | `llm-ai-hunter` subtype=mcp |
| Model registry / inference endpoint (`/v1/models`, `/predict`, `Content-Type: ...+pickle`) | `llm-ai-hunter` subtype=model-server (BentoML CVE-2025-27520) |
| Chat UI that renders LLM output | `llm-ai-hunter` subtype=output-handling (LLM output → `innerHTML`) |
| Document upload that gets summarized / RAG-indexed | `llm-ai-hunter` subtype=indirect-injection / rag-poisoning |
| Agentic tool-use (LangChain REPL / PandasAgent / shell tools) | `llm-ai-hunter` subtype=tool-abuse (CVE-2025-68613) |

### Mobile

| Signal | Dispatch |
|--------|----------|
| APK / IPA in scope | Decompile (jadx / Hopper) + `apkleaks` / grep BEFORE network testing |
| WebView with `addJavascriptInterface` / JS bridge | `xss-hunter` + `privilege-escalation` (XSS → RCE escalation) |
| Mobile-only API endpoints from traffic capture | `idor-hunter`, `auth-tester` (often weaker than web equivalents) |
| Deep link / custom URL scheme / intent | `privilege-escalation` (intent hijacking, scheme confusion) |

### Smart contract / Web3

| Signal | Dispatch |
|--------|----------|
| Any Solidity / Vyper contract | `web3-auditor` + `web3-audit` skill (10 bug classes) |
| Proxy pattern (TransparentUpgradeable / UUPS) | `web3-auditor` — admin transfer + initializer protection |
| DEX / AMM / lending protocol | `web3-auditor` — flash-loan, oracle, accounting desync |
| TVL < $500K, recently audited, common patterns | Pre-dive kill signals — see `web3-audit` skill |

### Generic web (last resort, when nothing specific fires)

| Signal | Dispatch |
|--------|----------|
| Reflective query params | `xss-hunter` subtype=reflected |
| State-changing POST/PUT without CSRF token | `csrf-hunter` |
| Server-side URL fetch (webhook, import, preview) | `ssrf-hunter` |
| Template engine in response (`{{{{`, `${{`, `#{{`) | `ssti-hunter` |
| File upload | `file-upload` + `xss-hunter` (SVG XSS Sub-technique G) |
| File parameter / path-like input | `rce-hunter` (LFI, path traversal) |
| Login / session / password-reset / MFA | `auth-tester` |
| Cross-origin headers / CORS misconfig | `cors-hunter` |
| Open redirect parameter | `open-redirect` |
| Subdomain enumeration shows dangling CNAME | `subdomain-takeover` |

The `hunt-*` skills live at `$CLAUDE_PROJECT_DIR/skills/hunt-<class>/SKILL.md`:

- `hunt-rce` (1,135 lines)
- `hunt-idor` (969 lines)
- `hunt-xss` (968 lines)
- `hunt-oauth` (770 lines)
- `hunt-llm-ai` (930 lines)

---

## Dollar Meta — what's actually paying right now (2024-2026)

Verified disclosures with NVD CVEs / GHSA references / H1 hacktivity. Use as priority signals during recon — if you can fingerprint the vulnerable component, hunt it FIRST.

- **CVE-2025-55182** — React Server Components / RSC trust surface (CVSS 10.0, Vercel WAF-bypass program on H1, exploited in wild within 24h). Hunt every Next.js >=14.3.0-canary.77 / >=15.x / >=16.x.
- **CVE-2025-68613** — LangChain PythonREPLTool semantic RCE (CVSS 9.8). Indirect prompt injection in CSV/RAG context coerces agent into exec-able Python.
- **CVE-2025-27520 / 32375** — BentoML `deserialize_value()` unsafe pickle (CVSS 9.8). Hunt model registries, inference endpoints, `Content-Type: ...+pickle` accepting handlers.
- **CVE-2026-30956** — OneUptime tenant header bypass (CVSS 9.9). Multi-tenant SaaS pattern; check tenant ID validation in headers.
- **CVE-2026-40938** — Tekton git resolver `--upload-pack` argument injection (CVSS 9.4). GitOps controllers; CNCF parallel bounty programs.
- **CVE-2024-21626** — runc "Leaky Vessels" (CISA KEV, CVSS 8.6). Full host RCE from any pod with `runc exec`.
- **CVE-2025-1974** — ingress-nginx admission controller (CVSS 9.8). Pod-network attacker reads cluster-wide Secrets.
- **CVE-2025-25291 / 25292** — ruby-saml parser differentials (REXML vs Nokogiri). SAML authn bypass.
- **CVE-2025-67716** — Auth0 nextjs-auth0 returnTo XSS. 1-click ATO on enterprise SaaS using Auth0.
- **CVE-2024-47875 / 45801 / GHSA-h8r8-wccr-v5f2** — DOMPurify mXSS family. Direct from Cure53/Snyk + chained ATO across consumers.
- **CVE-2026-22817** — Hono JWT alg confusion. Any API using Hono auth middleware.
- **GHSA-jmr4-p576-v565** — listmonk admin-ATO via shared-content trigger (CVSS 8.0). Lower-priv stored XSS → public archive → admin renders → backdoor account.
- **H1 #2819573** — Trix Editor 2.1.8 mutation-based stored XSS. Every ActionText app inherits this.
- **GHSA-rch3-82jr-f9w9** — Jupyter Notebook 7.0.0-7.5.5 / JupyterLab through 4.5.6 (CVSS 8.4). REST API ATO via notebook XSS.
- **GHSA-537j-gqpc-p7fq** — n8n MCP OAuth `client_name` XSS (CVSS 8.8). Pattern repeats across Zapier / Make / Pipedream.

---

## Validity Gates

Hard rules — no overrides:

- `/validate` must return PASS before `/report` (7-Question Gate, first NO = KILL)
- `/quality` must score ≥7 before `/submit` (blocks if below)
- `/dupcheck` before `/submit` — H1 dup rate is your enemy
- `rules/never-submit.md` — informational findings don't get drafted, period
- CVSS policy: HackerOne uses CVSS 3.1, all other platforms use CVSS 4.0 (`cvss_version_guard.py` enforces)

---

## Failure Protocols

- **WAF block** → `rules/waf-bypass-protocol.md`, levels 1→7 with per-level evidence; record WAF profile in brain on full-ladder failure
- **Scope ambiguity** → `/scope <asset>` before `/hunt`
- **5× 403/429** → circuit breaker triggers, back off 60s, switch endpoint
- **Hallucinated file paths** → `file_path_guard.py` blocks them; verify with `ls` before referencing
- **Out-of-scope Bash command** → `scope_hook.py` blocks PreToolUse; reroute or revise scope.yaml

---

## Brain Integration (mandatory discipline)

Brain compounds across targets. Three rules:

1. **Before testing X**: `uv run python3 $CLAUDE_PROJECT_DIR/tools/brain.py brief <target>` — what's been tested, what's exhausted, which WAF is in front
2. **Per-endpoint**: `brain.py endpoints <target>` to see fine-grained coverage
3. **After every result**: label CONFIRMED / POTENTIAL / EXHAUSTED with attempt counts and failure reasons. `/remember` for cross-target patterns. `/learn <id> <status>` for paid-technique boost.

---

## Workflow (canonical paths, not lockstep)

```
New target:        /sync → /brain init → /surface → /hunt
Returning:         /resume <target> → /hunt or /autopilot
After confirm:     /validate → /chain (default) → /report → /dupcheck → /submit → /learn
Batch triage:      /triage  (7-Question Gate on all findings)
Autonomous:        /autopilot <target> [--paranoid|--normal|--yolo]
```

You will deviate from this. Recon screams P1 → skip surface ranking, hit `/hunt`. Found A → `/chain` before drafting. The order isn't sacred; the gates are.

---

## Active Agents (50)

**Hunters (specialist):** `xss-hunter`, `sqli-hunter`, `csrf-hunter`, `ssrf-hunter`, `ssti-hunter`, `idor-hunter`, `rce-hunter`, `xxe-hunter`, `file-upload`, `cors-hunter`, `subdomain-takeover`, `business-logic`, `race-condition`, `privilege-escalation`, `open-redirect`, `info-disclosure`, `oauth-hunter`, `llm-ai-hunter`, `auth-tester`

**Pipeline:** `validator`, `chain-builder`, `recon-ranker`, `correlator`, `quality-check`, `poc-builder`, `report-writer`, `scope-check`, `dast-devils-advocate`, `browser-verifier`

**Recon / infra:** `recon`, `vuln-scanner`, `config-auditor`, `cloud-recon`, `js-analyzer`, `waf-profiler`, `graphql-audit`, `nuclei-writer`, `browser-agent`, `browser-stealth-agent`

**Meta:** `brain`, `monitor`

**SAST:** `sast-file-ranker`, `sast-entry-mapper`, `sast-danger-mapper`, `sast-flow-tracer`, `sast-gap-analyzer`, `sast-devils-advocate`, `sast-hunter`, `sast-exploit-builder`

**Specialized:** `web3-auditor`

---

## Notes

- **Writeup search MCP**: `search_writeups`, `search_techniques`, `search_payloads` for prior art. 50K+ semantic search if you drop `metadata.db` + `index.faiss` into `~/.local/share/pentest-writeups/`.
- **Cost tracking**: SubagentStop hook auto-logs to `cost-tracking.json`; statusline shows live `$X.XX`.
- **Payload library**: `rules/payloads.md` (2,500 lines, 14 vuln classes including DeFi).
- **Methodology library**: `skills/` — 5 deep `hunt-*` skills + 6 reference skills.

Workspace created: {datetime.now().strftime('%Y-%m-%d')}
"""


_CUSTOM_NOTES_PLACEHOLDER = """
---

## Custom Notes

(Edit below this line — preserved across `/sync` and re-scaffolds.)
"""


def scaffold(platform: str, program: str, base_dir: str = None):
    """Create or update an engagement workspace.

    Universal template — every workspace gets the full agent + skill +
    tool inventory and a hunting-brief CLAUDE.md with surface-driven
    dispatch (no per-engagement type branching).
    """
    if base_dir is None:
        base_dir = os.path.expanduser(f"~/bounties/{platform}-{program}")

    workspace = Path(base_dir)
    suite_dir = Path(__file__).parent.parent.resolve()

    # --- UPDATE MODE: workspace already exists ---
    if workspace.exists():
        print(f"📦 Updating existing workspace: {workspace}")

        # Ensure all directories exist (recreate missing ones)
        dirs = [
            ".claude/agents", ".claude/skills",
            ".claude/agent-memory-local/brain/targets",
            ".claude/agent-memory-local/brain/techniques",
            ".claude/agent-memory-local/brain/patterns",
            ".claude/agent-memory-local/brain/sessions",
            "recon", "scans", "js-analysis", "poc", "reports", "reports/drafts",
            "evidence", "nuclei-templates/custom", "monitor",
        ]
        for d in dirs:
            (workspace / d).mkdir(parents=True, exist_ok=True)

        # Copy shared suite files (agents, skills, tools, MCP, settings, rules, etc.)
        agent_count, skill_count, tool_count = _copy_shared_files(workspace, suite_dir)

        # Regenerate CLAUDE.md (suite boilerplate — always stays current)
        # Preserve any "## Custom Notes" section from existing file. If the
        # marker appears multiple times (e.g. previous-run duplication bug),
        # take from the LAST occurrence so user-edited content survives.
        custom_notes = ""
        existing_claude = workspace / "CLAUDE.md"
        if existing_claude.exists():
            content = existing_claude.read_text()
            marker = "## Custom Notes"
            if marker in content:
                idx = content.rfind(marker)
                custom_notes = "\n---\n\n" + content[idx:]

        claude_md = _generate_claude_md(workspace, platform, program)
        # Always re-append a Custom Notes section: preserved one if the
        # workspace had it (with user edits), otherwise the empty
        # placeholder. Never duplicate.
        claude_md += custom_notes if custom_notes else _CUSTOM_NOTES_PLACEHOLDER
        (workspace / "CLAUDE.md").write_text(claude_md)

        provider_files, provider_merges, provider_warnings = (
            _install_project_provider_assets(workspace)
        )

        # Ensure brain skeleton files exist (don't overwrite if they have data)
        brain_dir = workspace / ".claude/agent-memory-local/brain"
        for fname, title in [("techniques/exhausted.md", "# Exhausted Techniques\n"),
                              ("techniques/effective.md", "# Effective Techniques\n"),
                              ("techniques/waf-bypasses.md", "# WAF Behavior\n"),
                              ("patterns/false-positives.md", "# False Positive Patterns\n"),
                              ("patterns/tech-stack-vulns.md", "# Tech Stack Patterns\n")]:
            f = brain_dir / fname
            if not f.exists():
                f.write_text(title)

        if not (brain_dir / "MEMORY.md").exists():
            (brain_dir / "MEMORY.md").write_text(f"# Brain — {program}\nCreated: {datetime.now().strftime('%Y-%m-%d')}\n")

        # Ensure .scope.txt exists
        if not (workspace / ".scope.txt").exists() and not (workspace / "scope.yaml").exists():
            (workspace / ".scope.txt").write_text(f"# {platform.title()} — {program}\n# Run /sync {platform} {program} to auto-populate\n\n# In Scope\n\n# Out of Scope\n")

        preserved = []
        for f in ["scope.yaml", "scope.md", ".scope.txt", "findings.json", "findings.md", "hacktivity.md", "policy.md"]:
            if (workspace / f).exists():
                preserved.append(f)

        print(f"\n✅ Workspace updated: {workspace}")
        print(f"   Updated: {agent_count} agents, {skill_count} skills/commands, {tool_count} tools")
        print(
            f"   Updated: {provider_files} provider files, "
            f"{provider_merges} provider config merges"
        )
        print(f"   Updated: CLAUDE.md, settings.json")
        print(f"   MCP server: {'yes' if (workspace / 'mcp-bounty-server' / 'server.py').exists() else 'no'}")
        print(f"   Statusline: {'yes' if (workspace / 'tools' / 'pentest-statusline.sh').exists() else 'no'}")
        for warning in provider_warnings[:6]:
            print(f"   Provider note: {warning}")
        if len(provider_warnings) > 6:
            print(f"   Provider note: ... and {len(provider_warnings) - 6} more")
        if preserved:
            print(f"   Preserved: {', '.join(preserved)}, brain/*, recon/*, evidence/*")
        return

    # --- CREATE MODE: new workspace ---
    print(f"🆕 Creating new workspace: {workspace}")

    # Create directory structure
    dirs = [
        ".claude/agents",
        ".claude/skills",
        ".claude/agent-memory-local/brain/targets",
        ".claude/agent-memory-local/brain/techniques",
        ".claude/agent-memory-local/brain/patterns",
        ".claude/agent-memory-local/brain/sessions",
        "recon", "scans", "js-analysis", "poc", "reports", "reports/drafts",
        "evidence", "nuclei-templates/custom",
    ]
    for d in dirs:
        (workspace / d).mkdir(parents=True, exist_ok=True)

    # Create CLAUDE.md (with an empty Custom Notes placeholder users can fill)
    (workspace / "CLAUDE.md").write_text(
        _generate_claude_md(workspace, platform, program) + _CUSTOM_NOTES_PLACEHOLDER
    )

    # Create scope template
    (workspace / ".scope.txt").write_text(f"""# {platform.title()} — {program}
# Run /sync {platform} {program} to auto-populate

# In Scope

# Out of Scope
""")

    # Initialize brain
    for fname, title in [("exhausted.md", "# Exhausted Techniques\n"), ("effective.md", "# Effective Techniques\n"), ("waf-bypasses.md", "# WAF Behavior\n")]:
        (workspace / ".claude/agent-memory-local/brain/techniques" / fname).write_text(title)
    for fname, title in [("false-positives.md", "# False Positive Patterns\n"), ("tech-stack-vulns.md", "# Tech Stack Patterns\n")]:
        (workspace / ".claude/agent-memory-local/brain/patterns" / fname).write_text(title)
    (workspace / ".claude/agent-memory-local/brain/MEMORY.md").write_text(f"""# Brain — {program}
Created: {datetime.now().strftime('%Y-%m-%d')}

## Active Targets
(run /sync to populate)

## Key Findings
(none yet)

## Exhausted Areas
(none yet)
""")
    (workspace / ".claude/agent-memory-local/brain/sessions" / f"{datetime.now().strftime('%Y-%m-%d')}.md").write_text(
        f"# Session Log — {datetime.now().strftime('%Y-%m-%d')}\n\n- {datetime.now().strftime('%H:%M')} Workspace created\n"
    )

    # Copy shared suite files
    agent_count, skill_count, tool_count = _copy_shared_files(workspace, suite_dir)
    provider_files, provider_merges, provider_warnings = _install_project_provider_assets(workspace)

    print(f"✅ Workspace created: {workspace}")
    print(f"   Copied: {agent_count} agents, {skill_count} skills/commands, {tool_count} tools")
    print(f"   Copied: {provider_files} provider files, {provider_merges} provider config merges")
    print(f"   MCP server: {'yes' if (workspace / 'mcp-bounty-server' / 'server.py').exists() else 'no'}")
    print(f"   Statusline: {'yes' if (workspace / 'tools' / 'pentest-statusline.sh').exists() else 'no'}")
    for warning in provider_warnings[:6]:
        print(f"   Provider note: {warning}")
    if len(provider_warnings) > 6:
        print(f"   Provider note: ... and {len(provider_warnings) - 6} more")
    print(f"\n   Next steps:")
    print(f"   cd {workspace}")
    print(f"   claude   # or: codex / gemini / cursor / windsurf / code / openclaw")
    print(f"   /sync {platform} {program}")
    print(f"   /brain init")
    print(f"   /status")


def main():
    # Hard-error on the deprecated --type flag so users notice the change.
    # Templates were a crude pre-recon guess; the universal CLAUDE.md routes
    # via the Skill Dispatch Map after recon. There is no per-engagement
    # branching anymore.
    deprecated = {"--type", "-t"}
    for arg in sys.argv[1:]:
        flag = arg.split("=", 1)[0]
        if flag in deprecated:
            print(
                "scaffold.py: --type / -t is no longer supported.\n"
                "  Workspaces are universal — the generated CLAUDE.md ships a\n"
                "  Skill Dispatch Map that routes through specialist hunters\n"
                "  based on what recon finds, regardless of target type.\n"
                "  Re-run without the --type flag.",
                file=sys.stderr,
            )
            sys.exit(2)

    parser = argparse.ArgumentParser(description="Scaffold a new pentest engagement workspace")
    parser.add_argument("platform", help="Bug bounty platform (hackerone, bugcrowd, etc.)")
    parser.add_argument("program", help="Program handle/slug")
    parser.add_argument("--dir", "-d", help="Custom workspace directory")
    parser.add_argument("--force", action="store_true", help="Overwrite existing workspace")
    args = parser.parse_args()

    scaffold(args.platform, args.program, args.dir)


if __name__ == "__main__":
    main()
