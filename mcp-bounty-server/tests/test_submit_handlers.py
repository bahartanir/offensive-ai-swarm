"""Tests for submit_handlers — focus on the H1 attachment flow that previously
silently dropped poc_files/evidence_files.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch


def _load_handlers_module():
    server_dir = Path(__file__).resolve().parents[1]
    if str(server_dir) not in sys.path:
        sys.path.insert(0, str(server_dir))
    spec = importlib.util.spec_from_file_location(
        "submit_handlers_under_test", server_dir / "submit_handlers.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_report(tmp_path, *, poc_files=None, evidence_files=None):
    submissions = __import__("submissions")
    models = __import__("models")
    return submissions.ReportSubmission(
        title="Reflected XSS in /search",
        severity=models.Severity.HIGH,
        description="The `q` parameter reflects without encoding.",
        steps_to_reproduce="1. GET /search?q=<svg/onload=alert(1)>",
        impact="Session theft via JS exec on victim browsers.",
        vulnerability_type="XSS",
        asset="https://example.com/search",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        poc_files=list(poc_files or []),
        evidence_files=list(evidence_files or []),
    )


class _FakeResponse:
    """Minimal urlopen response stand-in."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _capture_urlopen(call_log: list, responses: list[bytes]):
    """Build a urlopen replacement that logs each call and returns canned
    bodies in order. Each entry in `responses` becomes the next response.
    """
    iter_resp = iter(responses)

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        # Capture the request shape so tests can assert on it.
        body = req.data
        headers = dict(req.header_items())
        call_log.append({
            "url": req.full_url,
            "method": req.get_method(),
            "headers": headers,
            "body": body,
        })
        try:
            payload = next(iter_resp)
        except StopIteration as e:
            raise AssertionError(
                f"urlopen called more times than canned responses provided "
                f"(extra call to {req.full_url})"
            ) from e
        return _FakeResponse(payload)

    return fake_urlopen


# ---------------------------------------------------------------------------
# Direct path (no attachments) — preserves prior behavior
# ---------------------------------------------------------------------------


def test_submit_hackerone_direct_post_when_no_attachments(tmp_path):
    handlers = _load_handlers_module()
    report = _make_report(tmp_path)

    direct_response = json.dumps({
        "data": {"type": "report", "id": "9001"},
    }).encode()

    calls: list = []
    with patch.object(handlers, "urlopen", _capture_urlopen(calls, [direct_response])):
        result = handlers.submit_hackerone(
            report=report, program_handle="acme", username="api-user", token="t0ken",
        )

    assert result.success is True
    assert result.report_id == "9001"
    assert result.report_url == "https://hackerone.com/reports/9001"
    assert len(calls) == 1
    assert calls[0]["url"] == "https://api.hackerone.com/v1/hackers/reports"
    body = json.loads(calls[0]["body"])
    assert body["data"]["attributes"]["team_handle"] == "acme"
    assert "Authorization" in {k.title() for k in calls[0]["headers"]}


# ---------------------------------------------------------------------------
# Intent path — main attachment fix
# ---------------------------------------------------------------------------


def test_submit_hackerone_intent_flow_uploads_files_and_submits(tmp_path):
    handlers = _load_handlers_module()
    poc_path = tmp_path / "exploit.html"
    poc_path.write_bytes(b"<script>alert(1)</script>")
    screenshot = tmp_path / "screenshot.png"
    screenshot.write_bytes(b"\x89PNG\r\n\x1a\nfakepng")
    report = _make_report(tmp_path, poc_files=[str(poc_path)], evidence_files=[str(screenshot)])

    intent_response = json.dumps({
        "data": {"type": "report-intent", "id": "intent-42"},
    }).encode()
    upload_response = json.dumps({
        "data": [{"type": "attachment", "id": "att-1"}, {"type": "attachment", "id": "att-2"}],
    }).encode()
    submit_response = json.dumps({
        "data": {
            "type": "report-intent",
            "id": "intent-42",
            "relationships": {"report": {"data": {"type": "report", "id": "12345"}}},
        }
    }).encode()

    calls: list = []
    with patch.object(handlers, "urlopen", _capture_urlopen(
        calls, [intent_response, upload_response, submit_response],
    )):
        result = handlers.submit_hackerone(
            report=report, program_handle="acme", username="api-user", token="t0ken",
        )

    assert result.success is True, result.message
    assert result.report_id == "12345"
    assert result.report_url == "https://hackerone.com/reports/12345"

    # Three calls in the expected order.
    assert [c["url"] for c in calls] == [
        "https://api.hackerone.com/v1/hackers/report_intents",
        "https://api.hackerone.com/v1/hackers/report_intents/intent-42/attachments",
        "https://api.hackerone.com/v1/hackers/report_intents/intent-42/submit",
    ]

    # First call: JSON intent body with our attributes.
    intent_body = json.loads(calls[0]["body"])
    assert intent_body["data"]["type"] == "report-intent"
    assert intent_body["data"]["attributes"]["team_handle"] == "acme"
    assert intent_body["data"]["attributes"]["title"].startswith("Reflected XSS")

    # Second call: multipart with both files under name="files[]".
    upload_headers = {k.lower(): v for k, v in calls[1]["headers"].items()}
    assert upload_headers["content-type"].startswith("multipart/form-data; boundary=")
    multipart_body = calls[1]["body"]
    assert b'name="files[]"; filename="exploit.html"' in multipart_body
    assert b'name="files[]"; filename="screenshot.png"' in multipart_body
    assert b"<script>alert(1)</script>" in multipart_body
    assert b"\x89PNG" in multipart_body

    # Third call: empty JSON submit body.
    assert json.loads(calls[2]["body"]) == {}


def test_submit_hackerone_intent_flow_skips_missing_files_with_warning(tmp_path):
    handlers = _load_handlers_module()
    real_poc = tmp_path / "real.html"
    real_poc.write_bytes(b"<html>poc</html>")
    missing = str(tmp_path / "ghost.png")  # never created
    report = _make_report(tmp_path, poc_files=[str(real_poc), missing])

    responses = [
        json.dumps({"data": {"type": "report-intent", "id": "i1"}}).encode(),
        json.dumps({"data": [{"type": "attachment", "id": "a1"}]}).encode(),
        json.dumps({"data": {
            "type": "report-intent",
            "id": "i1",
            "relationships": {"report": {"data": {"type": "report", "id": "55"}}},
        }}).encode(),
    ]
    calls: list = []
    with patch.object(handlers, "urlopen", _capture_urlopen(calls, responses)):
        result = handlers.submit_hackerone(
            report=report, program_handle="acme", username="u", token="t",
        )

    assert result.success is True
    assert "Skipped missing attachment paths" in result.message
    assert "ghost.png" in result.message
    # Only the real file should have been uploaded.
    multipart_body = calls[1]["body"]
    assert b'filename="real.html"' in multipart_body
    assert b'filename="ghost.png"' not in multipart_body


def test_submit_hackerone_intent_flow_continues_when_attachment_upload_fails(tmp_path):
    """Upload failure should warn but still submit — the intent still has the
    report body and is more valuable submitted than abandoned.
    """
    from urllib.error import HTTPError
    handlers = _load_handlers_module()
    poc = tmp_path / "p.html"
    poc.write_bytes(b"x")
    report = _make_report(tmp_path, poc_files=[str(poc)])

    intent_response = json.dumps({"data": {"type": "report-intent", "id": "iX"}}).encode()
    submit_response = json.dumps({"data": {
        "type": "report-intent",
        "id": "iX",
        "relationships": {"report": {"data": {"type": "report", "id": "77"}}},
    }}).encode()

    iter_calls = iter([
        ("ok", intent_response),
        ("fail", HTTPError(
            url="https://api.hackerone.com/v1/hackers/report_intents/iX/attachments",
            code=413, msg="Payload Too Large", hdrs=None,
            fp=io.BytesIO(b'{"errors":[{"detail":"too big"}]}'),
        )),
        ("ok", submit_response),
    ])
    calls: list = []

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        kind, payload = next(iter_calls)
        calls.append({"url": req.full_url, "method": req.get_method()})
        if kind == "fail":
            raise payload
        return _FakeResponse(payload)

    with patch.object(handlers, "urlopen", fake_urlopen):
        result = handlers.submit_hackerone(
            report=report, program_handle="acme", username="u", token="t",
        )

    assert result.success is True, result.message
    assert result.report_id == "77"
    assert "Attachment upload failed" in result.message
    assert "413" in result.message


def test_submit_hackerone_intent_flow_propagates_intent_creation_failure(tmp_path):
    from urllib.error import HTTPError
    handlers = _load_handlers_module()
    poc = tmp_path / "p.html"
    poc.write_bytes(b"x")
    report = _make_report(tmp_path, poc_files=[str(poc)])

    err = HTTPError(
        url="https://api.hackerone.com/v1/hackers/report_intents",
        code=422, msg="Unprocessable", hdrs=None,
        fp=io.BytesIO(b'{"errors":[{"detail":"team_handle is invalid"}]}'),
    )

    def fake_urlopen(_req, timeout=None):  # noqa: ARG001
        raise err

    with patch.object(handlers, "urlopen", fake_urlopen):
        result = handlers.submit_hackerone(
            report=report, program_handle="bad-handle", username="u", token="t",
        )

    assert result.success is False
    assert "report_intent creation failed" in result.message
    assert "422" in result.message


def test_submit_hackerone_intent_flow_preserves_intent_id_when_submit_fails(tmp_path):
    from urllib.error import HTTPError
    handlers = _load_handlers_module()
    poc = tmp_path / "p.html"
    poc.write_bytes(b"x")
    report = _make_report(tmp_path, poc_files=[str(poc)])

    intent_response = json.dumps({"data": {"type": "report-intent", "id": "intent-zzz"}}).encode()
    upload_response = json.dumps({"data": [{"id": "a1", "type": "attachment"}]}).encode()
    submit_err = HTTPError(
        url="https://api.hackerone.com/v1/hackers/report_intents/intent-zzz/submit",
        code=500, msg="Internal", hdrs=None,
        fp=io.BytesIO(b'{"errors":[{"detail":"oops"}]}'),
    )

    iter_calls = iter([("ok", intent_response), ("ok", upload_response), ("fail", submit_err)])

    def fake_urlopen(_req, timeout=None):  # noqa: ARG001
        kind, payload = next(iter_calls)
        if kind == "fail":
            raise payload
        return _FakeResponse(payload)

    with patch.object(handlers, "urlopen", fake_urlopen):
        result = handlers.submit_hackerone(
            report=report, program_handle="acme", username="u", token="t",
        )

    assert result.success is False
    assert result.report_id == "intent-zzz"  # operator can recover the draft
    assert "submit failed" in result.message
    assert "intent-zzz" in result.message


# ---------------------------------------------------------------------------
# Multipart body builder — direct unit test of the helper
# ---------------------------------------------------------------------------


def test_build_multipart_body_uses_files_array_field_name():
    handlers = _load_handlers_module()
    body = handlers._build_multipart_body(
        files=[
            ("a.txt", b"hello", "text/plain"),
            ("b.png", b"\x89PNG", "image/png"),
        ],
        boundary="BOUND123",
    )
    assert b"--BOUND123\r\n" in body
    assert b'name="files[]"; filename="a.txt"' in body
    assert b'name="files[]"; filename="b.png"' in body
    assert b"Content-Type: text/plain\r\n\r\nhello\r\n" in body
    assert body.endswith(b"--BOUND123--\r\n")


# ---------------------------------------------------------------------------
# Other platforms must remain untouched by the H1 changes
# ---------------------------------------------------------------------------


def test_submit_intigriti_saves_manual_draft_with_safe_filename(tmp_path, monkeypatch):
    handlers = _load_handlers_module()
    report = _make_report(tmp_path)
    monkeypatch.chdir(tmp_path)

    calls: list = []
    with patch.object(handlers, "urlopen", _capture_urlopen(calls, [])):
        result = handlers.submit_intigriti(
            report=report, program_handle="acme", token="bearer-tok",
        )

    assert result.success is False
    assert result.status == "draft_saved"
    assert "app.intigriti.com/researcher/program-redirect/acme" in result.message
    assert calls == []
    draft = tmp_path / "reports" / "drafts" / "intigriti-acme-reflected-xss-in-search.md"
    assert draft.exists()
