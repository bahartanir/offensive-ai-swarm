#!/usr/bin/env bash
# Integration tests: multi-engagement workflow, handoff, and migrate
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FINDINGS="$SCRIPT_DIR/findings.sh"
HANDOFF="$SCRIPT_DIR/handoff.sh"
MIGRATE="$SCRIPT_DIR/migrate.sh"
TEST_DB="/tmp/pentest-ai-integ-$$.db"
PASS=0
FAIL=0
TOTAL=0

export PENTEST_AI_DB="$TEST_DB"

cleanup() { rm -f "$TEST_DB"; }
trap cleanup EXIT

assert_contains() {
    local label="$1" output="$2" expected="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$output" | grep -q "$expected"; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected: $expected)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== pentest-ai integration tests ==="
echo ""

# ─── multi-engagement isolation ────────────────────────────────────────
echo "--- multi-engagement isolation ---"
export PENTEST_AI_ENGAGEMENT="eng-a"
bash "$FINDINGS" init eng-a --client "Client A" --type external >/dev/null
bash "$FINDINGS" add host 10.1.1.1 --agent "recon" >/dev/null
bash "$FINDINGS" add vuln "Vuln A" --severity high --host 10.1.1.1 --agent "scanner" >/dev/null

export PENTEST_AI_ENGAGEMENT="eng-b"
bash "$FINDINGS" init eng-b --client "Client B" --type internal >/dev/null
bash "$FINDINGS" add host 192.168.1.1 --agent "recon" >/dev/null
bash "$FINDINGS" add vuln "Vuln B" --severity critical --host 192.168.1.1 --agent "scanner" >/dev/null

# Verify isolation
export PENTEST_AI_ENGAGEMENT="eng-a"
out=$(bash "$FINDINGS" list hosts)
assert_contains "eng-a only has its host" "$out" "10.1.1.1"
TOTAL=$((TOTAL + 1))
if echo "$out" | grep -q "192.168.1.1"; then
    echo "  FAIL: eng-a should not see eng-b hosts"
    FAIL=$((FAIL + 1))
else
    echo "  PASS: eng-a does not see eng-b hosts"
    PASS=$((PASS + 1))
fi

out=$(bash "$FINDINGS" list vulns)
assert_contains "eng-a only has its vuln" "$out" "Vuln A"

export PENTEST_AI_ENGAGEMENT="eng-b"
out=$(bash "$FINDINGS" list vulns)
assert_contains "eng-b only has its vuln" "$out" "Vuln B"

# ─── handoff report ───────────────────────────────────────────────────
echo "--- handoff report ---"
export PENTEST_AI_ENGAGEMENT="eng-a"
out=$(bash "$HANDOFF")
assert_contains "handoff has title" "$out" "Engagement Handoff: eng-a"
assert_contains "handoff has hosts section" "$out" "Hosts"
assert_contains "handoff has vulns section" "$out" "Vulnerabilities"

# ─── migrate ───────────────────────────────────────────────────────────
echo "--- migrate ---"
export PENTEST_AI_ENGAGEMENT="eng-a"
out=$(bash "$MIGRATE")
assert_contains "migrate reports up to date" "$out" "up to date"

# ─── engagements list ─────────────────────────────────────────────────
echo "--- engagements ---"
out=$(bash "$FINDINGS" engagements)
assert_contains "lists eng-a" "$out" "eng-a"
assert_contains "lists eng-b" "$out" "eng-b"
assert_contains "shows client" "$out" "Client A"

# ─── export json validity ─────────────────────────────────────────────
echo "--- export json ---"
export PENTEST_AI_ENGAGEMENT="eng-a"
out=$(bash "$FINDINGS" export)
TOTAL=$((TOTAL + 1))
if echo "$out" | python3 -m json.tool >/dev/null 2>&1; then
    echo "  PASS: export produces valid JSON"
    PASS=$((PASS + 1))
else
    echo "  FAIL: export JSON is invalid"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
