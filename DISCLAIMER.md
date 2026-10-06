# Legal and Ethical Use Disclaimer

## Authorized Use Only

This toolkit is exclusively for the following purposes:

- **Authorized penetration testing** conducted under a signed statement of work, rules of engagement, or equivalent legal authorization
- **Red team exercises** performed with explicit organizational approval and defined scope
- **Security research** conducted in controlled lab environments or against systems you own
- **Defensive security operations** including detection engineering, threat modeling, and security assessment

## Authorization Requirements

Users MUST have proper written authorization before using these agents in any capacity. Acceptable forms of authorization include:

- A signed rules of engagement (ROE) document
- A formal scope of work or statement of work (SOW)
- Written authorization from the system owner
- A signed penetration testing agreement
- Equivalent legal authorization as recognized by your jurisdiction

If you do not have written authorization for the target systems, do not use these agents.

## User Responsibility

Users are solely responsible for:

- Ensuring compliance with all applicable local, state, national, and international laws and regulations
- Adhering to organizational policies, acceptable use policies, and codes of conduct
- Remaining within the defined scope of authorized engagements
- Properly handling and protecting any sensitive data encountered during testing
- Following responsible disclosure practices for any vulnerabilities discovered

## Limitation of Liability

The authors and contributors of this toolkit accept no liability for:

- Misuse of any kind, including but not limited to unauthorized access to systems or data
- Any damages, direct or indirect, resulting from the use of this toolkit
- Legal consequences arising from unauthorized or improper use
- Data loss, system damage, or service disruption caused by activities performed using guidance from these agents

## Recommended Qualifications

Users of this toolkit should hold one or more of the following certifications, or demonstrate equivalent competency through professional experience:

- OSCP (Offensive Security Certified Professional)
- GPEN (GIAC Penetration Tester)
- PenTest+ (CompTIA)
- CEH (Certified Ethical Hacker)
- CPTS (Certified Penetration Testing Specialist)
- GXPN (GIAC Exploit Researcher and Advanced Penetration Tester)

These certifications are recommended, not required, but users should possess a solid understanding of ethical hacking principles, legal boundaries, and professional standards before using these agents.

## What These Agents Do and Do Not Do

These agents provide methodology guidance, analysis, documentation assistance, and (for select agents) direct tool execution with user approval. They are designed to help experienced security professionals work more efficiently during authorized engagements.

### Tier 1 Agents (Advisory Mode)

Most agents provide methodology guidance only. They analyze output you paste, suggest commands, and generate documentation. They do not execute commands or interact with target systems.

### Tier 2 Agents (Execution Mode)

Some agents (marked with `Bash` in their tool list) can compose and execute reconnaissance, enumeration, and analysis commands against targets you have authorized. Every command requires your explicit approval through Claude Code's permission prompt. You see the full command before it runs. You are responsible for verifying that each command targets only in-scope systems.

Tier 2 agents enforce scope boundaries: they require you to declare an authorized scope before executing any commands, and they refuse to target anything outside that scope. This is a prompt-level safety check. Claude Code's per-command permission prompt is the hard safety gate.

### No agent, in any tier, will:

- Generate functional standalone exploit code or malware
- Bypass Claude Code's permission system
- Execute commands without showing them to you first
- Target systems outside the scope you declared
- Perform destructive actions (DoS, data deletion) unless explicitly authorized
- Run commands requiring elevated privileges without flagging it first

All offensive actions on target systems remain under your control. In Tier 2, the agent composes and executes commands, but you approve every one. In Tier 1, you run the tools yourself.

## Data Privacy & LLM Processing

When you use pentest-ai through Claude Code, your prompts and any data you provide are processed by a third-party LLM provider (Anthropic by default). **pentest-ai agents do not add any additional data transmission.** The data flow is identical to using Claude Code without these agents installed.

However, users must be aware:

- **Third-party processing:** Any data included in your prompts (scan output, IP addresses, findings) is sent to the LLM provider for processing
- **Sensitive data:** Users are responsible for redacting PII, internal credentials, client-identifiable information, and proprietary data before submission, unless they have verified the LLM provider's data retention and training policies
- **Client policies:** Check your rules of engagement and client NDAs for restrictions on third-party AI data processing before using this toolkit on professional engagements
- **Compliance:** Ensure usage complies with applicable regulations (HIPAA, PCI-DSS, FedRAMP, etc.)

For sensitive engagements, users are encouraged to:

1. Use Anthropic's API with your own key (API inputs are not used for training by default)
2. Redact client-specific data before pasting tool output
3. Use locally-hosted models to keep all data within the local perimeter
4. Review the LLM provider's current data retention and privacy policies

See [docs/DATA-PRIVACY.md](docs/DATA-PRIVACY.md) for detailed guidance, configuration options, and a client communication template.

## Responsible Disclosure

Users should follow responsible disclosure practices for any vulnerabilities discovered during authorized testing. This includes:

- Reporting findings to the system owner or designated point of contact within the agreed-upon timeframe
- Handling vulnerability details with appropriate confidentiality
- Following any disclosure procedures specified in the rules of engagement
- Considering coordinated disclosure through established channels (such as CERT/CC or vendor security teams) when appropriate

## Acceptance

By using this toolkit, you acknowledge that you have read, understood, and agree to the terms outlined in this disclaimer. If you do not agree with these terms, do not use this toolkit.
