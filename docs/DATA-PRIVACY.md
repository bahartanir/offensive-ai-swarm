# Data Privacy & LLM Processing

## How pentest-ai Handles Data

pentest-ai agents are **plain Markdown files**. They contain no code, make no network calls, and collect no telemetry. The agents themselves are fully auditable. Open any `.md` file and read exactly what the agent knows and does.

However, when you use these agents through Claude Code, your prompts and any data you paste are sent to an LLM provider (Anthropic by default) for processing. This is important to understand for professional engagements.

## The Data Flow

```
You type a prompt
    ↓
Claude Code sends it to the LLM provider (Anthropic API)
    ↓
The provider processes it and returns a response
    ↓
Claude Code displays the response locally
```

**pentest-ai does not add any additional data transmission.** The data flow is identical to using Claude Code without pentest-ai installed. The agents only change *how* Claude responds, not *where* your data goes.

## What This Means for Professional Engagements

If you paste scan output, IP addresses, credentials, or client-specific data into Claude Code, that data is transmitted to the LLM provider. Depending on your client's policies, this may violate:

- Non-disclosure agreements (NDAs)
- Data handling requirements in your rules of engagement
- Client-specific "No Third-Party AI" policies
- Regulatory requirements (HIPAA, PCI-DSS, FedRAMP, etc.)

## Your Responsibilities

Before using pentest-ai on a client engagement:

1. **Check your ROE/SOW** for restrictions on third-party data processing or AI tool usage
2. **Understand your provider's data policy.** Review Anthropic's [data retention policy](https://www.anthropic.com/privacy) or your API provider's terms
3. **Redact sensitive data** before pasting. Remove or obfuscate client IPs, hostnames, credentials, PII, and proprietary information when possible
4. **Get explicit approval** from your client if their data will be processed by a third-party LLM

## Options for Sensitive Engagements

### Option 1: Anthropic API with Your Own Key (Recommended)

Use your own Anthropic API key instead of a Claude Pro/Max subscription. API usage has different data handling terms. Anthropic does not train on API inputs by default.

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Use Claude Code with your API key
claude
```

See Anthropic's [API data policy](https://www.anthropic.com/privacy) for current retention terms.

### Option 2: Data Redaction

Strip sensitive identifiers before pasting tool output:

- Replace real IPs with RFC 5737 documentation addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)
- Replace hostnames with generic labels (`DC01`, `WEBSERVER`, `DB-PROD`)
- Remove credentials, tokens, and API keys entirely
- Redact client names and internal project identifiers

The agents work on methodology and patterns. They don't need real IPs to give you useful guidance.

### Option 3: Local Models (Maximum Privacy)

For the highest data sensitivity, run a local LLM that never sends data off-machine. Claude Code supports third-party API-compatible providers:

```bash
# Example: Use a local model via Ollama with an OpenAI-compatible endpoint
# (Requires a compatible local model setup. Agent quality will vary with model capability)

# Install Ollama (https://ollama.ai)
ollama pull llama3

# Point Claude Code at your local endpoint
# See Claude Code docs for third-party provider configuration
```

**Note:** Local models will have significantly reduced capability compared to Claude Sonnet/Opus. Agent output quality depends heavily on model capability. For complex tasks (threat modeling, detection engineering, report generation), cloud models will produce substantially better results.

### Option 4: Air-Gapped Usage

Use the agents as **reference documents** without an LLM:

```bash
# Read any agent file directly for methodology reference
cat ~/.claude/agents/exploit-guide.md
cat ~/.claude/agents/detection-engineer.md
```

Each agent file contains detailed methodology, tool references, and frameworks that are useful as standalone reference material even without LLM processing.

## Summary

| Approach | Data Leaves Machine? | Agent Quality | Best For |
|----------|---------------------|---------------|----------|
| Claude Pro/Max | Yes (Anthropic) | Full | Personal research, CTFs, labs |
| Anthropic API key | Yes (Anthropic, no training) | Full | Professional engagements with API approval |
| Data redaction | Yes (but sanitized) | Full | Client work with strict data policies |
| Local models | No | Reduced | High-security / air-gapped environments |
| Reference only | No | N/A (manual) | Methodology reference, no LLM needed |

## Client Communication Template

If you need to discuss AI tool usage with a client, here is a starting point:

> During this engagement, we may use AI-assisted methodology tools to improve efficiency in planning, analysis, and reporting. These tools process prompts through [Anthropic's API / a locally-hosted model]. No automated scanning, exploitation, or system access is performed by the AI. We can provide details on data handling upon request, and we will [redact all client-identifiable data before processing / use only our enterprise API with zero data retention / use locally-hosted models exclusively] per your data handling requirements.

Adjust based on your actual setup and the client's requirements.
