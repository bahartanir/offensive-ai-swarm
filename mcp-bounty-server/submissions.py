"""Report submission models and helpers for bug bounty platforms."""

from dataclasses import dataclass, field
from typing import Optional
from models import Platform, Severity


@dataclass
class ReportSubmission:
    """Unified report submission format across all platforms."""
    title: str
    severity: Severity
    description: str  # Full vulnerability description (markdown)
    steps_to_reproduce: str  # Numbered reproduction steps
    impact: str  # Impact statement
    vulnerability_type: str  # CWE or platform-specific vuln type
    asset: str  # The in-scope asset this affects
    cvss_vector: str = ""  # CVSS 4.0 vector string
    poc_files: list[str] = field(default_factory=list)  # Paths to PoC files
    evidence_files: list[str] = field(default_factory=list)  # Paths to screenshots/recordings
    remediation: str = ""  # Fix recommendation
    references: list[str] = field(default_factory=list)  # CWE/CVE/OWASP refs


@dataclass
class SubmissionResult:
    """Result of a report submission attempt."""
    success: bool
    report_id: Optional[str] = None
    report_url: Optional[str] = None
    status: str = ""  # submitted, draft, error
    message: str = ""
    platform: Optional[Platform] = None


# HackerOne weakness IDs mapped from common CWE
# See: https://hackerone.com/vulnerability-rating-taxonomy
H1_WEAKNESS_MAP = {
    "XSS": "60",  # Cross-site Scripting (XSS) - Reflected
    "XSS-Stored": "61",  # Cross-site Scripting (XSS) - Stored
    "XSS-DOM": "62",  # Cross-site Scripting (XSS) - DOM
    "SQLI": "67",  # SQL Injection
    "CSRF": "57",  # Cross-Site Request Forgery
    "SSRF": "75",  # Server-Side Request Forgery
    "IDOR": "55",  # Insecure Direct Object Reference
    "Auth-Bypass": "27",  # Authentication Bypass
    "Info-Disclosure": "18",  # Information Disclosure
    "Open-Redirect": "38",  # Open Redirect
    "RCE": "70",  # Remote Code Execution
    "XXE": "63",  # XML External Entities (XXE)
    "File-Upload": "39",  # Unrestricted File Upload
    "CORS": "58",  # CORS Misconfiguration
    "Subdomain-Takeover": "145",  # Subdomain Takeover
    "Business-Logic": "28",  # Business Logic Errors
    "Race-Condition": "29",  # Race Condition
    "Privilege-Escalation": "26",  # Privilege Escalation
}

# Bugcrowd VRT (Vulnerability Rating Taxonomy) categories
# See: https://bugcrowd.com/vulnerability-rating-taxonomy
BC_VRT_MAP = {
    "XSS": "cross_site_scripting_xss.reflected_xss",
    "XSS-Stored": "cross_site_scripting_xss.stored_xss",
    "XSS-DOM": "cross_site_scripting_xss.dom_based_xss",
    "SQLI": "server_side_injection.sql_injection",
    "CSRF": "cross_site_request_forgery_csrf",
    "SSRF": "server_side_injection.ssrf",
    "IDOR": "broken_access_control.idor",
    "Auth-Bypass": "broken_authentication.authentication_bypass",
    "Info-Disclosure": "sensitive_data_exposure",
    "Open-Redirect": "unvalidated_redirects_and_forwards.open_redirect",
    "RCE": "server_side_injection.remote_code_execution_rce",
    "Subdomain-Takeover": "server_security_misconfiguration.subdomain_takeover",
}

SEVERITY_TO_H1 = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.NONE: "none",
    Severity.INFO: "none",
}


def format_h1_report_body(report: ReportSubmission) -> str:
    """Format report body for HackerOne's markdown format."""
    body = f"""## Summary
{report.description}

## Steps to Reproduce
{report.steps_to_reproduce}

## Impact
{report.impact}"""

    if report.remediation:
        body += f"\n\n## Remediation\n{report.remediation}"

    if report.references:
        body += "\n\n## References\n" + "\n".join(f"- {r}" for r in report.references)

    if report.cvss_vector:
        # HackerOne uses CVSS 3.1; version is in the vector prefix
        body += f"\n\n## CVSS\n`{report.cvss_vector}`"

    return body


def format_bc_report_body(report: ReportSubmission) -> str:
    """Format report body for Bugcrowd's submission format."""
    poc_line = "See attached files." if report.poc_files else "Included in steps above."
    body = (
        f"**Description**\n{report.description}\n\n"
        f"**Steps to Reproduce**\n{report.steps_to_reproduce}\n\n"
        f"**Impact**\n{report.impact}\n\n"
        f"**Proof of Concept**\n{poc_line}"
    )
    if report.remediation:
        body += f"\n\n**Remediation**\n{report.remediation}"
    if report.cvss_vector:
        body += f"\n\n**CVSS**: `{report.cvss_vector}`"
    return body


def format_generic_report_body(report: ReportSubmission) -> str:
    """Format report body for platforms with simple text submission."""
    body = f"""# {report.title}

## Severity: {report.severity.value.upper()}
## Asset: {report.asset}
## Type: {report.vulnerability_type}

## Description
{report.description}

## Steps to Reproduce
{report.steps_to_reproduce}

## Impact
{report.impact}"""

    if report.remediation:
        body += f"\n\n## Remediation\n{report.remediation}"
    if report.cvss_vector:
        body += f"\n\n## CVSS 4.0\n`{report.cvss_vector}`"
    if report.references:
        body += "\n\n## References\n" + "\n".join(f"- {r}" for r in report.references)

    return body
