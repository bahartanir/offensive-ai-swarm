# Agent Guide

## What Are Claude Code Subagents?

Claude Code subagents are specialized assistants defined by Markdown files placed in the `.claude/agents/` directory (project-level) or `~/.claude/agents/` (global). Each agent file contains two parts:

1. **YAML frontmatter** enclosed in `---` delimiters at the top of the file. This includes metadata fields such as `name`, `description`, `model`, and `tools` that tell Claude Code when and how to use the agent.
2. **System prompt content** below the frontmatter. This is the detailed instruction set that shapes the agent's behavior, expertise, and output format.

Claude Code reads the `description` field to determine when to route a task to a specific agent. When your prompt matches an agent's described domain, Claude delegates the task to that agent, which then responds using its specialized system prompt and permitted tools.

---

## Agent Details

### engagement-planner

**When it activates:** When you ask about planning, scoping, or organizing a penetration test or red team engagement.

**What it does:** Helps you define the scope, timeline, methodology, and rules of engagement for security assessments. Maps engagement objectives to MITRE ATT&CK techniques and provides structured planning documents.

**Example prompts:**

- "Plan an internal network pentest for a 500-endpoint Active Directory environment with a two-week timeline."
- "Create a rules of engagement template for an external web application assessment."
- "Map our engagement objectives to MITRE ATT&CK techniques for a cloud-focused red team exercise."
- "What should the scope exclusions look like for a healthcare organization pentest?"

**Tips for best results:** Provide details about the target environment size, technology stack, compliance requirements, and timeline constraints. The more context you give, the more tailored the plan will be.

---

### recon-advisor

**When it activates:** When you share scan output, ask about reconnaissance methodology, or need help analyzing enumeration data.

**What it does:** Analyzes output from reconnaissance tools (Nmap, BloodHound, enum4linux, etc.), identifies high-value targets, prioritizes attack vectors, and recommends next steps based on what the data reveals.

**Example prompts:**

- "Analyze this Nmap output and identify high-value targets for lateral movement. [paste output]"
- "Review this BloodHound data and identify the shortest path to Domain Admin."
- "I ran enum4linux against 10.0.0.5. Here are the results. What should I target next? [paste output]"
- "Prioritize these open services for an internal network assessment. [paste service list]"

**Tips for best results:** Paste actual tool output directly into your prompt. The agent works best when it can analyze real data rather than hypothetical scenarios. Include context about the engagement type (internal, external, web app) to get more relevant prioritization.

---

### exploit-guide

**When it activates:** When you ask about exploitation techniques, attack methodologies, or need guidance on a specific attack vector.

**What it does:** Provides step-by-step methodology guidance for exploitation techniques with a dual offensive/defensive perspective. For each technique, it covers the attack methodology, required tools, detection opportunities, and defensive mitigations.

**Example prompts:**

- "Walk me through Kerberoasting methodology and how blue teams can detect it."
- "Explain the methodology for NTLM relay attacks in a modern Active Directory environment."
- "How would I approach exploiting a misconfigured ADCS (Active Directory Certificate Services) instance?"
- "What is the methodology for Silver Ticket attacks and what artifacts do they leave?"

**Tips for best results:** Specify the target environment details (OS versions, patch levels, security tools in place) for more relevant guidance. Ask about detection alongside exploitation to get the full offensive/defensive picture.

---

### detection-engineer

**When it activates:** When you ask about creating detection rules, building alerts, or writing queries for security monitoring platforms.

**What it does:** Generates detection rules in multiple formats including Sigma (platform-agnostic), Splunk SPL, and KQL (Microsoft Sentinel/Defender). Rules include descriptions, severity ratings, MITRE ATT&CK mappings, and tuning recommendations.

**Example prompts:**

- "Create a detection rule for DCSync attacks in Sigma and Splunk SPL format."
- "Write a KQL query to detect Kerberoasting activity in Microsoft Sentinel."
- "Build a Sigma rule for detecting suspicious scheduled task creation used for persistence."
- "Create a detection rule for LSASS memory access that minimizes false positives."

**Tips for best results:** Specify the detection platform you are using (Splunk, Sentinel, Elastic, etc.) and any constraints such as available log sources. Mention if you need tuning guidance to reduce false positives in specific environments.

---

### stig-analyst

**When it activates:** When you ask about STIG (Security Technical Implementation Guide) compliance, specific STIG IDs, or need remediation or justification guidance.

**What it does:** Analyzes specific STIG requirements, provides GPO-based and command-line remediation steps, helps write keep-open (risk acceptance) justifications, and explains the security impact of findings.

**Example prompts:**

- "Analyze V-220768 and provide GPO remediation steps."
- "Write a keep-open justification for V-254243 where the application requires the insecure configuration."
- "What are the CAT I STIG findings most commonly found in Windows Server 2022 environments?"
- "Explain the security impact of V-220712 and provide both GPO and PowerShell remediation."

**Tips for best results:** Reference specific STIG IDs (V-XXXXXX format) for the most precise guidance. Provide context about why a finding cannot be remediated if you need a keep-open justification, as the quality of the justification depends on the business context.

---

### report-generator

**When it activates:** When you ask about writing penetration test reports, formatting findings, or producing executive summaries.

**What it does:** Helps structure and write professional penetration test reports including executive summaries, methodology sections, individual findings with severity ratings, evidence formatting, and remediation recommendations.

**Example prompts:**

- "Format these findings into a professional pentest report with executive summary and remediation priorities."
- "Write an executive summary for a pentest that found 3 critical, 7 high, and 12 medium findings on an internal network."
- "Structure this finding as a professional report entry: we obtained Domain Admin via Kerberoasting a service account with a weak password."
- "Create a remediation roadmap section that prioritizes fixes by effort and impact."

**Tips for best results:** Provide the raw finding details including the vulnerability, evidence, affected systems, and business impact. The more detail you provide, the more polished the report output will be. Specify the audience (technical team vs. executive leadership) for appropriate tone and detail level.

---

## Workflow Chaining

The agents are designed to work together across the phases of a complete engagement. Here is how to chain them for maximum effectiveness:

### Phase 1: Planning

Start with `engagement-planner` to define scope, rules of engagement, and methodology. This sets the foundation for the entire assessment.

```
Plan a two-week internal penetration test for Acme Corp's corporate network.
The scope includes 10.0.0.0/8 and all Active Directory domains. Exclude the
10.0.50.0/24 production database subnet.
```

### Phase 2: Reconnaissance Analysis

After running your recon tools, feed the output to `recon-advisor` for analysis.

```
Here is the Nmap scan output for the first three subnets. Identify high-value
targets and recommend an attack path. [paste output]
```

### Phase 3: Exploitation Methodology

For each identified attack vector, consult `exploit-guide` for methodology guidance.

```
The recon phase identified several SPNs for service accounts. Walk me through
Kerberoasting these accounts and what detection I should expect.
```

### Phase 4: Detection Engineering

After testing is complete, use `detection-engineer` to produce detection rules for the techniques you successfully used.

```
During testing I successfully performed Kerberoasting, DCSync, and Golden Ticket
attacks. Create Sigma rules for detecting each of these techniques.
```

### Phase 5: Compliance Mapping

If the engagement includes compliance requirements, use `stig-analyst` to map findings to STIG controls.

```
Map the Active Directory findings from our assessment to relevant STIG controls
and provide remediation steps for each.
```

### Phase 6: Report Generation

Finally, use `report-generator` to compile everything into a professional deliverable.

```
Compile the following findings into a professional penetration test report.
Include an executive summary, methodology section, and findings ranked by
severity with remediation recommendations. [paste findings]
```

---

## General Tips

- **Be specific.** Vague prompts produce vague results. Include environment details, tool names, version numbers, and specific objectives.
- **Paste real tool output.** The agents are designed to analyze actual data. Copy and paste Nmap scans, BloodHound output, error messages, and configuration files directly into your prompts.
- **Provide engagement context.** Tell the agent whether this is an internal test, external test, web application assessment, red team exercise, or compliance audit. Context shapes the response.
- **Iterate.** If the first response does not cover what you need, follow up with more specific questions. The agents maintain conversation context and can refine their output.
- **Chain agents deliberately.** The output from one agent often serves as ideal input for the next. Copy relevant output from one agent's response and paste it into your next prompt for the following phase.
