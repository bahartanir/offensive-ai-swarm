"""Report submission handlers for each platform.

Handles the platform-specific API calls for creating reports.
Each handler takes a ReportSubmission and returns a SubmissionResult.
"""

import json
import mimetypes
import re
import secrets
from base64 import b64encode
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote

from models import Platform
from submissions import (
    ReportSubmission, SubmissionResult,
    H1_WEAKNESS_MAP, SEVERITY_TO_H1,
    format_h1_report_body, format_generic_report_body,
)


# --- HTTP helpers (stdlib only) ---


def _post_json(url: str, headers: dict, body: dict, timeout: int = 30) -> dict:
    data = json.dumps(body).encode()
    req = Request(url, data=data, headers={**headers, "Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        return {"error": True, "status": e.code, "message": error_body}
    except URLError as e:
        return {"error": True, "status": 0, "message": str(e.reason)}


def _build_multipart_body(
    files: list[tuple[str, bytes, str]], boundary: str
) -> bytes:
    """Build a multipart/form-data body where each file is sent under name 'files[]'.

    files: list of (filename, content_bytes, mime_type) tuples.
    """
    parts: list[bytes] = []
    for filename, content, mime in files:
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="files[]"; '
            f'filename="{filename}"\r\n'.encode()
        )
        parts.append(f"Content-Type: {mime}\r\n\r\n".encode())
        parts.append(content)
        parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


def _post_multipart(
    url: str,
    headers: dict,
    files: list[tuple[str, bytes, str]],
    timeout: int = 60,
) -> dict:
    """POST multipart/form-data with each file under the 'files[]' field."""
    boundary = "h1mcp" + secrets.token_hex(16)
    body = _build_multipart_body(files, boundary)
    req_headers = {
        **{k: v for k, v in headers.items() if k.lower() != "content-type"},
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    req = Request(url, data=body, headers=req_headers, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        return {"error": True, "status": e.code, "message": error_body}
    except URLError as e:
        return {"error": True, "status": 0, "message": str(e.reason)}


def _read_attachments(
    paths: list[str],
) -> tuple[list[tuple[str, bytes, str]], list[str]]:
    """Load files for upload. Returns (files, missing_paths).

    Missing files are skipped, not raised — submission should not be aborted
    just because one screenshot path was wrong. The caller decides what to do
    with the missing list.
    """
    files: list[tuple[str, bytes, str]] = []
    missing: list[str] = []
    for raw in paths:
        path = Path(raw).expanduser()
        if not path.is_file():
            missing.append(str(path))
            continue
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        files.append((path.name, path.read_bytes(), mime))
    return files, missing


# --- HackerOne ---

H1_BASE = "https://api.hackerone.com/v1"


def _h1_auth_header(username: str, token: str) -> dict:
    creds = b64encode(f"{username}:{token}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "Accept": "application/json"}


def _h1_create_intent(
    headers: dict, team_handle: str, report: ReportSubmission, weakness_id: int,
) -> dict:
    """POST /v1/hackers/report_intents — returns the response dict."""
    body = {
        "data": {
            "type": "report-intent",
            "attributes": {
                "team_handle": team_handle,
                "title": report.title,
                "vulnerability_information": format_h1_report_body(report),
                "impact": report.impact,
                "severity_rating": SEVERITY_TO_H1.get(report.severity, "medium"),
                "weakness_id": weakness_id,
            },
        }
    }
    return _post_json(f"{H1_BASE}/hackers/report_intents", headers, body)


def _h1_upload_attachments(
    headers: dict, intent_id: str, files: list[tuple[str, bytes, str]],
) -> dict:
    """POST /v1/hackers/report_intents/{id}/attachments (multipart, files[])."""
    return _post_multipart(
        f"{H1_BASE}/hackers/report_intents/{quote(intent_id)}/attachments",
        headers,
        files,
    )


def _h1_submit_intent(headers: dict, intent_id: str) -> dict:
    """POST /v1/hackers/report_intents/{id}/submit — converts intent to report."""
    return _post_json(
        f"{H1_BASE}/hackers/report_intents/{quote(intent_id)}/submit",
        headers,
        {},
    )


def _h1_result(result: dict, success_message: str) -> SubmissionResult:
    """Normalize a successful H1 response into a SubmissionResult.

    Handles two shapes: a `report` data object (direct POST), or a
    `report-intent` data object whose relationships.report.data.id holds
    the final report id (intent submit response).
    """
    if result.get("error"):
        return SubmissionResult(
            success=False, status="error",
            message=f"HackerOne API error {result.get('status')}: {result.get('message', '')}",
            platform=Platform.HACKERONE,
        )

    data = result.get("data", {})
    report_id = ""
    if data.get("type") == "report":
        report_id = str(data.get("id", ""))
    else:
        rel = data.get("relationships", {}).get("report", {}).get("data", {}) or {}
        report_id = str(rel.get("id", "")) or str(data.get("id", ""))

    return SubmissionResult(
        success=True,
        report_id=report_id,
        report_url=f"https://hackerone.com/reports/{report_id}" if report_id else None,
        status="submitted",
        message=success_message,
        platform=Platform.HACKERONE,
    )


def _submit_h1_direct(
    report: ReportSubmission, team_handle: str, headers: dict, weakness_id: int,
) -> SubmissionResult:
    """No-attachment path: POST /v1/hackers/reports directly."""
    body = {
        "data": {
            "type": "report",
            "attributes": {
                "team_handle": team_handle,
                "title": report.title,
                "vulnerability_information": format_h1_report_body(report),
                "severity_rating": SEVERITY_TO_H1.get(report.severity, "medium"),
                "impact": report.impact,
            },
            "relationships": {
                "weakness": {"data": {"type": "weakness", "id": weakness_id}},
            },
        }
    }
    result = _post_json(f"{H1_BASE}/hackers/reports", headers, body)
    return _h1_result(result, "Report submitted successfully to HackerOne")


def _submit_h1_via_intent(
    report: ReportSubmission,
    team_handle: str,
    headers: dict,
    weakness_id: int,
    attachment_paths: list[str],
) -> SubmissionResult:
    """Attachment path: create intent -> upload files -> submit intent."""
    intent_resp = _h1_create_intent(headers, team_handle, report, weakness_id)
    if intent_resp.get("error"):
        return SubmissionResult(
            success=False, status="error",
            message=(
                f"HackerOne report_intent creation failed "
                f"(status {intent_resp.get('status')}): {intent_resp.get('message', '')}"
            ),
            platform=Platform.HACKERONE,
        )

    intent_id = str(intent_resp.get("data", {}).get("id", ""))
    if not intent_id:
        return SubmissionResult(
            success=False, status="error",
            message=f"HackerOne report_intent response missing data.id: {intent_resp}",
            platform=Platform.HACKERONE,
        )

    files, missing = _read_attachments(attachment_paths)
    warnings: list[str] = []
    if missing:
        warnings.append(f"Skipped missing attachment paths: {', '.join(missing)}")

    if files:
        upload_resp = _h1_upload_attachments(headers, intent_id, files)
        if upload_resp.get("error"):
            warnings.append(
                f"Attachment upload failed "
                f"(status {upload_resp.get('status')}): "
                f"{upload_resp.get('message', '')}. "
                f"Intent {intent_id} will be submitted without these files."
            )

    submit_resp = _h1_submit_intent(headers, intent_id)
    if submit_resp.get("error"):
        return SubmissionResult(
            success=False, status="error",
            report_id=intent_id,
            message=(
                f"HackerOne intent {intent_id} created but submit failed "
                f"(status {submit_resp.get('status')}): {submit_resp.get('message', '')}. "
                f"Recover the draft from your HackerOne dashboard."
            ),
            platform=Platform.HACKERONE,
        )

    final = _h1_result(submit_resp, "Report submitted to HackerOne via report_intent")
    if warnings:
        final.message = final.message + "\n\nWarnings:\n" + "\n".join(f"- {w}" for w in warnings)
    return final


def submit_hackerone(
    report: ReportSubmission,
    program_handle: str,
    username: str,
    token: str,
) -> SubmissionResult:
    """Submit a report to HackerOne via their hacker API.

    With attachments, uses the documented `report_intent` flow:
    POST /v1/hackers/report_intents -> POST attachments -> POST submit.
    Without attachments, uses the simpler direct POST /v1/hackers/reports.
    """
    headers = _h1_auth_header(username, token)
    weakness_id = int(H1_WEAKNESS_MAP.get(report.vulnerability_type, "18"))

    attachment_paths = list(report.poc_files) + list(report.evidence_files)
    if not attachment_paths:
        return _submit_h1_direct(report, program_handle, headers, weakness_id)
    return _submit_h1_via_intent(
        report, program_handle, headers, weakness_id, attachment_paths,
    )


# --- Bugcrowd ---

def submit_bugcrowd(
    report: ReportSubmission,
    program_handle: str,
    token: str = "",
) -> SubmissionResult:
    """Bugcrowd does not have a public researcher submission API.

    Saves a draft report locally and returns the manual submission
    URL where the researcher can paste the report content.
    """
    draft_path = save_draft(report, "bugcrowd", program_handle)
    submit_url = f"https://bugcrowd.com/{program_handle}/submissions/new"
    return SubmissionResult(
        success=False,
        status="draft_saved",
        message=(
            f"Bugcrowd has no researcher submission API.\n"
            f"Draft saved to: {draft_path}\n"
            f"Submit manually at: {submit_url}\n"
            f"Copy the report content from the draft file."
        ),
        platform=Platform.BUGCROWD,
    )


# --- Intigriti ---

def submit_intigriti(
    report: ReportSubmission,
    program_handle: str,
    token: str = "",
) -> SubmissionResult:
    """Intigriti's researcher API is read-only — no submission endpoint exists.

    Confirmed against the official Swagger spec at
    https://api.intigriti.com/external/researcher/swagger/v1.0/swagger.json
    which exposes only GET endpoints (programs, payouts, program activities).
    Submissions go through the SPA at app.intigriti.com with cookie auth.

    Mirrors the Bugcrowd handler: save a draft locally and surface the
    program's web URL where the researcher pastes the content.
    """
    draft_path = save_draft(report, "intigriti", program_handle)
    submit_url = (
        f"https://app.intigriti.com/researcher/program-redirect/"
        f"{quote(program_handle)}"
    )
    return SubmissionResult(
        success=False,
        status="draft_saved",
        message=(
            f"Intigriti's researcher API is read-only — no submission API.\n"
            f"Draft saved to: {draft_path}\n"
            f"Submit manually at: {submit_url}\n"
            f"On the program page, click 'Submit a finding' and paste the draft."
        ),
        platform=Platform.INTIGRITI,
    )


# --- YesWeHack ---

def submit_yeswehack(
    report: ReportSubmission,
    program_handle: str,
    token: str,
) -> SubmissionResult:
    """Submit a report to YesWeHack."""
    body = {
        "title": report.title,
        "description": format_generic_report_body(report),
        "scope": report.asset,
        "cvss_vector": report.cvss_vector,
        "severity": report.severity.value,
        "vulnerability_type": report.vulnerability_type,
    }

    result = _post_json(
        f"https://api.yeswehack.com/programs/{quote(program_handle)}/reports",
        {"Authorization": f"Bearer {token}", "Accept": "application/json"},
        body,
    )

    if result.get("error"):
        return SubmissionResult(
            success=False, status="error",
            message=f"YesWeHack API error: {result.get('message', '')}",
            platform=Platform.YESWEHACK,
        )

    report_id = result.get("id", "")
    return SubmissionResult(
        success=True, report_id=str(report_id), status="submitted",
        message="Report submitted to YesWeHack",
        platform=Platform.YESWEHACK,
    )


# --- Dispatcher ---

SUBMIT_HANDLERS = {
    "hackerone": submit_hackerone,
    "bugcrowd": submit_bugcrowd,
    "intigriti": submit_intigriti,
    "yeswehack": submit_yeswehack,
}


def _filename_slug(value: str, fallback: str = "report", max_len: int = 80) -> str:
    """Return a single safe filename segment.

    Report titles often include paths such as `/search`; those must become
    filename text, not subdirectories under reports/drafts.
    """
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip(".-_")
    return (slug or fallback)[:max_len].rstrip(".-_") or fallback


def save_draft(report: ReportSubmission, platform: str, program: str, target_dir: str = ".") -> str:
    """Save a report as a local draft file for review before submission."""
    draft_dir = Path(target_dir) / "reports" / "drafts"
    draft_dir.mkdir(parents=True, exist_ok=True)

    platform_slug = _filename_slug(platform, "platform", max_len=40)
    program_slug = _filename_slug(program, "program", max_len=80)
    title_slug = _filename_slug(report.title, "report", max_len=50)
    draft_path = draft_dir / f"{platform_slug}-{program_slug}-{title_slug}.md"

    content = format_generic_report_body(report)
    meta = f"""---
platform: {platform}
program: {program}
severity: {report.severity.value}
vulnerability_type: {report.vulnerability_type}
asset: {report.asset}
cvss_vector: {report.cvss_vector}
status: draft
---

"""
    draft_path.write_text(meta + content)
    return str(draft_path)
