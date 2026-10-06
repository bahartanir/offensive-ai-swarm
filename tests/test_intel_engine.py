"""Tests for tools.intel_engine parsers and deep-hunt matrix helpers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import intel_engine  # noqa: E402


# --- bounty parsing ---------------------------------------------------------


def test_parse_bounty_supports_k_suffix() -> None:
    assert intel_engine._parse_bounty("$7.5k") == 7500


def test_parse_bounty_supports_m_suffix() -> None:
    assert intel_engine._parse_bounty("1.5M USD") == 1_500_000


def test_parse_bounty_supports_euro_and_gbp() -> None:
    assert intel_engine._parse_bounty("€1,200") == 1200
    assert intel_engine._parse_bounty("£2k") == 2000


def test_parse_bounty_returns_zero_for_noise() -> None:
    assert intel_engine._parse_bounty("unknown") == 0
    assert intel_engine._parse_bounty(None) == 0
    assert intel_engine._parse_bounty("") == 0


# --- vuln classification ----------------------------------------------------


def test_extract_vuln_detects_bola_as_idor() -> None:
    title = "Broken Object Level Authorization on invoice export endpoint"
    assert intel_engine._extract_vuln_type(title) == "IDOR"


def test_extract_vuln_detects_ssti() -> None:
    assert intel_engine._extract_vuln_type("Jinja2 template injection via comment") == "SSTI"


def test_extract_vuln_is_none_for_unrelated_titles() -> None:
    assert intel_engine._extract_vuln_type("Typo in documentation") is None


def test_extract_vuln_distinguishes_word_boundary() -> None:
    # The old substring-based implementation matched "rce" inside "forcefully".
    assert intel_engine._extract_vuln_type("Forcefully logged out on password reset") == "Auth Bypass"


# --- path extraction --------------------------------------------------------


def test_extract_paths_finds_multiple_candidates() -> None:
    paths = intel_engine._extract_paths(
        "XSS on /app/search and IDOR at /api/v2/users/123/profile"
    )
    assert "/app/search" in paths
    assert "/api/v2/users/123/profile" in paths


def test_extract_paths_ignores_protocol_double_slash() -> None:
    # URLs like https://example.com/foo should not surface "//example.com/foo".
    paths = intel_engine._extract_paths("see https://example.com/foo for details")
    assert not any(p.startswith("//") for p in paths)


# --- attack matrix ---------------------------------------------------------


def test_build_attack_matrix_cartesian_product_for_xss() -> None:
    profile = intel_engine._default_attack_matrix()["xss"]
    expected = len(profile["vectors"]) * len(profile["encodings"]) * len(profile["bypasses"])
    combos = intel_engine.build_attack_matrix("xss", limit=expected + 100)
    assert len(combos) == expected


def test_build_attack_matrix_includes_stacked_encodings() -> None:
    """Every web class must offer at least one stacked-encoding entry so
    hunters attempt multi-layered payloads (e.g. html-entity then URL)
    that defeat WAFs whose decoder only runs once."""
    for cls in ("xss", "sqli", "ssrf", "idor"):
        encs = intel_engine._default_attack_matrix()[cls]["encodings"]
        stacked = [e for e in encs if "+" in e or e == "double-url"]
        assert stacked, f"{cls} has no stacked encodings: {encs}"


def test_build_attack_matrix_respects_limit() -> None:
    combos = intel_engine.build_attack_matrix("ssrf", limit=10)
    assert len(combos) == 10


def test_build_attack_matrix_returns_empty_for_unknown_class() -> None:
    assert intel_engine.build_attack_matrix("nonexistent", limit=20) == []


def test_build_attack_matrix_covers_ssti_and_oauth() -> None:
    # SSTI and OAuth were added on top of PR #13's original 4 classes.
    assert intel_engine.build_attack_matrix("ssti", limit=1)
    assert intel_engine.build_attack_matrix("oauth", limit=1)


# --- autonomy class hypotheses ----------------------------------------------


def test_recommend_vuln_classes_prefers_stack_and_roi_signals() -> None:
    intel = {
        "by_vuln_type": {"IDOR": 4, "SSRF": 1},
        "vuln_roi": [{"vuln": "IDOR", "avg": 6000, "count_paid": 3}],
        "top_paths": {"/api/users/123/orders": 2},
    }
    ranked = intel_engine.recommend_vuln_classes(
        tech_stack="rails graphql",
        intel=intel,
        exhausted=set(),
        limit=5,
    )
    assert ranked, "expected ranked hypotheses"
    assert ranked[0]["vuln_class"] == "idor"
    assert ranked[0]["score"] > ranked[-1]["score"]


def test_recommend_vuln_classes_penalizes_exhausted() -> None:
    intel = {"by_vuln_type": {"IDOR": 3}}
    ranked = intel_engine.recommend_vuln_classes(
        tech_stack="rails",
        intel=intel,
        exhausted={"idor"},
        limit=8,
    )
    idor = next((r for r in ranked if r["vuln_class"] == "idor"), None)
    assert idor is not None
    assert idor["exhausted"] is True
    assert any("exhausted penalty" in reason for reason in idor["reasons"])


# --- telemetry + budget ------------------------------------------------------


def test_record_hunt_outcome_and_telemetry_adjustment() -> None:
    telemetry = intel_engine._default_telemetry_state()
    telemetry = intel_engine.record_hunt_outcome(
        vuln_class="idor",
        result="confirmed",
        attempts=30,
        elapsed_minutes=12,
        telemetry=telemetry,
    )
    delta, reasons = intel_engine.telemetry_adjustment("idor", telemetry)
    assert delta > 0
    assert reasons


def test_record_hunt_outcome_potential_counts_as_partial() -> None:
    """`record-outcome --result potential` must increment the partial bucket.

    The CLI accepts `potential` as a choice; before this fix it was mapped to
    itself (not in RESULT_ALIASES), so `events` incremented but no bucket did,
    and `telemetry_adjustment` later penalised the class with a -4 delta."""
    telemetry = intel_engine._default_telemetry_state()
    telemetry = intel_engine.record_hunt_outcome(
        vuln_class="idor",
        result="potential",
        attempts=5,
        telemetry=telemetry,
    )
    cls = telemetry["by_class"]["idor"]
    assert cls["events"] == 1
    assert cls["partial"] == 1
    assert cls["confirmed"] == 0
    assert cls["killed"] == 0
    # Also check it mutates the totals, not just the class entry.
    assert telemetry["totals"]["partial"] == 1


def test_canonicalize_vuln_label_handles_hyphen_and_underscore_forms() -> None:
    """Brain exhaustion markers use `prototype-pollution` / `race_condition`
    form; the canonicalizer must match them even though its rules use the
    spaced form. Before the fix these returned None and exhaustion penalties
    never fired for those classes."""
    assert intel_engine._canonicalize_vuln_label("prototype-pollution") == "prototype-pollution"
    assert intel_engine._canonicalize_vuln_label("prototype_pollution") == "prototype-pollution"
    assert intel_engine._canonicalize_vuln_label("race-condition") == "race-condition"
    assert intel_engine._canonicalize_vuln_label("race_condition") == "race-condition"
    assert intel_engine._canonicalize_vuln_label("auth-bypass") == "auth-bypass"
    assert intel_engine._canonicalize_vuln_label("file-upload") == "file-upload"
    assert intel_engine._canonicalize_vuln_label("open-redirect") == "open-redirect"
    assert intel_engine._canonicalize_vuln_label("info-disclosure") == "info-disclosure"
    assert intel_engine._canonicalize_vuln_label("business-logic") == "business-logic"


def test_allocate_class_budget_distributes_by_score() -> None:
    budgets = intel_engine.allocate_class_budget(
        [
            {"vuln_class": "idor", "display": "IDOR", "score": 80.0},
            {"vuln_class": "ssrf", "display": "SSRF", "score": 20.0},
        ],
        total_minutes=100,
        total_tokens=10000,
    )
    assert len(budgets) == 2
    assert budgets[0]["budget_minutes"] > budgets[1]["budget_minutes"]
    assert budgets[0]["budget_tokens"] > budgets[1]["budget_tokens"]


def test_evaluate_exhaustion_gate_enforces_quality_bar() -> None:
    ok, reason = intel_engine.evaluate_exhaustion_gate(
        attempts=26,
        combos_tested=10,
        combos_remaining=3,
        encoding_steps=4,
        differential_evidence=True,
    )
    assert ok is True
    assert "passed" in reason

    ok2, reason2 = intel_engine.evaluate_exhaustion_gate(
        attempts=8,
        combos_tested=2,
        combos_remaining=20,
        encoding_steps=1,
        differential_evidence=False,
    )
    assert ok2 is False
    assert "attempt floor" in reason2


# --- chain + evidence --------------------------------------------------------


def test_suggest_chain_steps_prioritizes_terminal_paths() -> None:
    suggestions = intel_engine.suggest_chain_steps(
        capabilities=["IDOR read", "SSRF"],
        known=set(),
        limit=10,
    )
    assert suggestions
    assert any(row["terminal_impact"] for row in suggestions)


def test_evidence_sufficiency_score_decisions() -> None:
    strong = intel_engine.evidence_sufficiency_score(
        has_http_pair=True,
        has_readback=True,
        has_browser_verification=True,
        reliability_runs=5,
        reliability_hits=5,
        has_harm_artifact=True,
        chain_depth=2,
    )
    assert strong["decision"] == "PASS"

    weak = intel_engine.evidence_sufficiency_score(
        has_http_pair=False,
        has_readback=False,
        has_browser_verification=False,
        reliability_runs=2,
        reliability_hits=0,
        has_harm_artifact=False,
        chain_depth=1,
    )
    assert weak["decision"] == "KILL"


# --- persistence safety ------------------------------------------------------


def test_save_telemetry_uses_atomic_write(tmp_path: Path) -> None:
    """save_telemetry must not leave a half-written file on mid-write crash.

    We verify the tmp sibling lands via atomic_write_text by confirming the
    final file is valid JSON even when the destination already exists.
    """
    telemetry_file = tmp_path / "t.json"
    telemetry_file.write_text('{"legacy": true}')  # pre-existing content
    state = intel_engine._default_telemetry_state()
    intel_engine.save_telemetry(state, telemetry_file)
    assert json.loads(telemetry_file.read_text()) == state
    # The tmp sidecar should NOT linger after a successful write.
    assert not (tmp_path / "t.json.tmp").exists()


def test_load_telemetry_quarantines_corrupt_file(tmp_path: Path, capsys) -> None:
    """Corrupt telemetry must be preserved, not silently overwritten.

    Before the fix, the prior `try/except JSONDecodeError: pass` path
    returned an empty state and the next save wiped every accumulated
    outcome. Now the corrupt file is moved aside with a warning."""
    bad = tmp_path / "t.json"
    bad.write_text("{not valid json")
    state = intel_engine.load_telemetry(bad)
    # Returns the default state...
    assert state == intel_engine._default_telemetry_state()
    # ...but the corrupt file is preserved, not gone.
    quarantined = list(tmp_path.glob("t.json.corrupt-*"))
    assert len(quarantined) == 1, "corrupt telemetry must be preserved"
    captured = capsys.readouterr()
    assert "corrupt" in captured.err.lower()


def test_load_telemetry_handles_wrong_shape(tmp_path: Path) -> None:
    bad = tmp_path / "t.json"
    bad.write_text('["a", "list", "not", "dict"]')
    state = intel_engine.load_telemetry(bad)
    assert state == intel_engine._default_telemetry_state()


def test_load_intel_quarantines_corrupt_file(tmp_path: Path) -> None:
    bad = tmp_path / "intel.json"
    bad.write_text("{oops")
    intel = intel_engine._load_intel(bad)
    assert intel == {}
    assert list(tmp_path.glob("intel.json.corrupt-*"))


# --- chain-plan JSON shape guard --------------------------------------------


def test_show_chain_plan_rejects_list_shaped_nodes(tmp_path: Path, capsys) -> None:
    """A capability graph where `nodes` is a list must not crash; before the
    fix, `.items()` raised AttributeError mid-CLI and the traceback leaked."""
    graph_file = tmp_path / "cap.json"
    graph_file.write_text(json.dumps({"version": 1, "nodes": [], "edges": []}))
    code = intel_engine.show_chain_plan(graph_file)
    out = capsys.readouterr().out
    assert code == 2, "corrupt-shape exit code distinguishes from empty-suggestions (1)"
    assert "nodes" in out.lower()


def test_show_chain_plan_rejects_non_object_root(tmp_path: Path, capsys) -> None:
    graph_file = tmp_path / "cap.json"
    graph_file.write_text(json.dumps(["not", "an", "object"]))
    code = intel_engine.show_chain_plan(graph_file)
    out = capsys.readouterr().out
    assert code == 2
    assert "graph shape" in out.lower()


def test_show_chain_plan_handles_malformed_node_entries(tmp_path: Path) -> None:
    """Malformed individual node entries (e.g. null) should not crash the planner."""
    graph_file = tmp_path / "cap.json"
    graph_file.write_text(
        json.dumps({"version": 1, "nodes": {"ssrf": None, "js-execution": {"label": "JS"}}, "edges": []})
    )
    # Must not raise; exit code depends on whether suggestions exist.
    code = intel_engine.show_chain_plan(graph_file)
    assert code in (0, 1)


# --- autonomous surface ranking ---------------------------------------------


def test_score_surface_endpoint_promotes_high_value_dynamic_routes() -> None:
    row = intel_engine.score_surface_endpoint("https://api.example.com/v1/users/123/orders")
    assert row["bucket"] in {"P1", "P2"}
    assert row["score"] > 0


def test_score_surface_endpoint_demotes_static_marketing() -> None:
    row = intel_engine.score_surface_endpoint("https://www.example.com/blog/logo.png")
    assert row["bucket"] == "Kill"
    assert row["score"] < 0


def test_rank_surface_deduplicates_and_orders_by_score() -> None:
    ranked = intel_engine.rank_surface(
        [
            "https://api.example.com/v1/users/123/orders",
            "https://api.example.com/v1/users/123/orders",
            "https://www.example.com/blog/logo.png",
        ],
        tech_stack="rails",
        limit=10,
    )
    assert len(ranked) == 2
    assert ranked[0]["score"] >= ranked[1]["score"]


# --- suggest_for_tech -------------------------------------------------------


def test_suggest_for_tech_deduplicates(capsys) -> None:
    intel_engine.suggest_for_tech("Rails with GraphQL and rails")
    out = capsys.readouterr().out
    assert out.count("[rails] → IDOR") == 1


# --- analyze_hacktivity ----------------------------------------------------


def test_analyze_hacktivity_extracts_roi_and_paths(tmp_path: Path, monkeypatch) -> None:
    data = "\n".join(
        [
            "- [HIGH] ($5,000) IDOR on /api/users",
            "- [CRIT] ($12k) SSRF in /import/fetch",
            "- [MED] ($1,000) CORS misconfiguration on /auth/callback",
        ]
    )
    hacktivity = tmp_path / "hacktivity.md"
    hacktivity.write_text(data)
    monkeypatch.chdir(tmp_path)
    intel = intel_engine.analyze_hacktivity(hacktivity)
    assert intel["total_reports"] == 3
    assert intel["vuln_roi"], "expected ROI entries for paid reports"
    assert "/api/users" in intel["top_paths"]


# --- show_matrix CLI -------------------------------------------------------


def test_show_matrix_reports_unknown_class(capsys) -> None:
    code = intel_engine.show_matrix("jwt", limit=10)
    out = capsys.readouterr().out
    assert code == 1
    assert "No matrix profile" in out
