# offensive-ai-swarm

**A modular Claude Code toolkit for penetration testing, security research, and offensive security workflows.**

`offensive-ai-swarm` provides a collection of specialized AI agents, skills, rules, and tooling designed to assist security professionals throughout the penetration testing lifecycle.

> ⚠️ **For authorized security testing only.**

---

## Overview

The project brings together specialized Claude Code agents and workflows for:

* 🔍 **Reconnaissance & OSINT**
* 🌐 **Web Application Security**
* ☁️ **Cloud & Infrastructure Security**
* 🏛️ **Active Directory & Windows Security**
* 🔴 **Red Team Operations**
* 🔬 **Source Code & SAST Analysis**
* 📱 **Mobile & Hardware Security**
* 🤖 **AI/LLM Security**
* 🧪 **Finding Validation & Analysis**
* 📊 **Security Reporting**
* 🎯 **Specialized Security Research**

The goal is to reduce repetitive work during security assessments while keeping the researcher in control of testing decisions and validation.

---

## Features

### Specialized AI Agents

Agents are designed for specific security tasks rather than relying on a single general-purpose assistant.

Examples include:

* Reconnaissance
* Attack surface analysis
* Web vulnerability research
* Cloud security assessment
* Active Directory analysis
* Source-code auditing
* Finding validation
* Exploit-chain analysis
* Security reporting

### Claude Code Skills

The repository includes reusable Claude Code skills that can be invoked directly from the command line.

Examples:

```text
/hunt
/recon
/pipeline
/validate
/sast
/triage
/report
/status
```

The exact available commands depend on the installed skills in `.claude/skills/`.

---

## Repository Structure

```text
offensive-ai-swarm/
│
├── .claude/
│   ├── agents/          # Specialized security agents
│   └── skills/          # Claude Code skills
│
├── rules/               # Security testing rules and guidance
├── tools/               # Supporting utilities and automation
├── wordlists/           # Security testing wordlists
├── docs/                # Documentation
├── examples/            # Example workflows and reports
│
├── install.sh           # Installation script
├── pyproject.toml       # Python project configuration
├── LICENSE
└── README.md
```

---

## Requirements

* [Claude Code](https://docs.anthropic.com/en/docs/claude-code)
* Python 3.11+
* `uv`

Additional dependencies may be required depending on the workflow or skill being used.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/bahartanir/offensive-ai-swarm.git
cd offensive-ai-swarm
```

Run the installation script:

```bash
./install.sh
```

Alternatively, install the components manually:

```bash
cp -r .claude/agents/* ~/.claude/agents/
cp -r .claude/skills/* ~/.claude/skills/
```

If Python tooling is required:

```bash
uv pip install -e .
```

---

## Example Workflow

A typical engagement can be organized around the following workflow:

```text
Target
  │
  ▼
Reconnaissance
  │
  ▼
Attack Surface Mapping
  │
  ▼
Vulnerability Research
  │
  ▼
Finding Validation
  │
  ▼
Exploit / Impact Analysis
  │
  ▼
Reporting
```

For example:

```text
/recon target.com
/pipeline target.com
/hunt target.com
/validate finding
/report
/status
```

Always validate AI-generated results manually before treating them as confirmed security findings.

---

## Design Philosophy

`offensive-ai-swarm` is designed around a few principles:

**Modular**

Each agent and skill focuses on a specific security task.

**Composable**

Multiple agents can be combined into larger assessment workflows.

**Researcher-in-the-loop**

AI-generated hypotheses and findings should be manually verified.

**Reusable**

Skills and rules can be reused across different authorized engagements.

**Tool-agnostic**

The framework is intended to work alongside existing security tooling rather than replace it.

---

## Security & Responsible Use

This project is intended **only for authorized security testing, research, and educational purposes**.

Do not use the toolkit against systems, applications, accounts, networks, or infrastructure without explicit authorization.

The user is responsible for ensuring that their use of this project complies with applicable laws, contracts, bug bounty program rules, and authorization boundaries.

See [DISCLAIMER.md](DISCLAIMER.md) for additional information.

---

## Contributing

Contributions, improvements, new agents, skills, rules, and documentation are welcome.

Before contributing, please ensure that submitted content does not include:

* Credentials or secrets
* Private customer information
* Unauthorized access mechanisms
* Malicious infrastructure
* Proprietary material without permission

---

## License

This project is licensed under the MIT License.

See [LICENSE](LICENSE) for details.
