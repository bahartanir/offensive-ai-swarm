# Token Optimization Guide

pentest-ai agents are designed to give deep, methodology-driven responses. That depth costs tokens. This guide covers practical ways to reduce consumption without gutting the quality that makes these agents useful.

## How Token Consumption Works

When you invoke a pentest-ai agent, tokens are consumed in three places:

1. **System prompt** (the agent's `.md` file) is loaded once per conversation and stays in context for every message
2. **Your input** (prompts, pasted scan output, follow-up questions)
3. **Agent output** (analysis, commands, tables, recommendations)

The system prompt is the fixed cost. A single agent ranges from ~900 tokens (engagement-planner) to ~7,600 tokens (threat-modeler). The average is ~3,100 tokens per agent.

## Quick Wins

### 1. Use `--lite` mode during install

```bash
./install.sh --global --lite
```

Lite mode installs the same agents with two changes:
- Advisory-only agents (no Bash tool) use `model: haiku` instead of `model: sonnet`. Haiku is roughly 90% as capable for advisory tasks at a fraction of the cost.
- Tier 2 execution agents stay on Sonnet because tool-use accuracy matters when running commands against live targets.

### 2. Switch individual agents to Haiku

If you only want to change specific agents, edit the frontmatter:

```yaml
---
model: haiku
---
```

Good candidates for Haiku (advisory-only, no execution risk):
- `engagement-planner`
- `report-generator`
- `detection-engineer`
- `threat-modeler`
- `ctf-solver`
- `stig-analyst`
- `exploit-guide`
- `attack-planner`
- `forensics-analyst`
- `malware-analyst`

Keep on Sonnet (Tier 2 execution agents where tool-use accuracy is critical):
- `recon-advisor`
- `web-hunter`
- `vuln-scanner`
- `ad-attacker`
- `exploit-chainer`
- `poc-validator`
- `bizlogic-hunter`
- `swarm-orchestrator`

### 3. Be specific in your prompts

Vague prompts cause longer responses. Compare:

```
# Expensive: agent produces a full methodology walkthrough
"Help me with Active Directory attacks"

# Cheaper: agent gives you exactly what you need
"Show me the Impacket command for Kerberoasting service accounts in corp.local"
```

### 4. Keep conversations short and focused

Token cost grows with conversation length because the full history stays in context. For multi-phase engagements:

- Start a new Claude Code session for each phase (recon, exploitation, reporting)
- Paste only the relevant subset of scan output, not the full dump
- Use `/clear` between unrelated tasks in the same session

### 5. Avoid the swarm orchestrator for simple tasks

The swarm orchestrator coordinates multiple agents, which multiplies token usage. Use it for full engagements, not single-agent tasks. If you just need recon analysis, talk to `recon-advisor` directly.

## Lite Mode vs Standard Mode

| Aspect | Standard | Lite |
|--------|----------|------|
| Advisory agents | Sonnet | Haiku |
| Execution agents | Sonnet | Sonnet |
| Response quality | Full depth | Slightly condensed |
| Token cost | Baseline | ~40-60% reduction for advisory tasks |
| Best for | Professional engagements, training | Personal use, exploration, learning |

## Estimating Your Token Budget

Rough estimates for common workflows:

| Workflow | Tokens (approx) |
|----------|-----------------|
| Single agent, 5-message conversation | 15,000-30,000 |
| Recon analysis of Nmap output | 10,000-20,000 |
| Full attack chain planning | 30,000-60,000 |
| Swarm orchestration (full engagement) | 100,000-300,000 |
| Report generation from findings | 20,000-40,000 |

## Advanced: Custom Agent Trimming

If you need aggressive token reduction, you can trim the reference tables and examples from agent system prompts. The core methodology sections (behavioral rules, output format, scope enforcement) should stay intact. The reference tables (tool command syntax, MITRE ATT&CK mappings, example outputs) can be removed if you already know the tools.

See [CUSTOMIZATION.md](CUSTOMIZATION.md) for how to modify agent prompts.
