#!/usr/bin/env bash
# Unit tests for findings.sh CLI
# Tests each command in isolation with a temporary database

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FINDINGS="$SCRIPT_DIR/findings.sh"
TEST_DB="/tmp/pentest-ai-test-$$.db"
PASS=0
FAIL=0
TOTAL=0

export PENTEST_AI_DB="$TEST_DB"
export PENTEST_AI_ENGAGEMENT="test-engagement"

cleanup() { rm -f "$TEST_DB"; }
trap cleanup EXIT

assert_contains() {
    local label="$1" output="$2" expected="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$output" | grep -q "$expected"; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label"
        echo "    Expected to contain: $expected"
        echo "    Got: $output"
        FAIL=$((FAIL + 1))
    fi
}

assert_exit_zero() {
    local label="$1"
    shift
    TOTAL=$((TOTAL + 1))
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (exit code $?)"
        FAIL=$((FAIL + 1))
    fi
}

assert_exit_nonzero() {
    local label="$1"
    shift
    TOTAL=$((TOTAL + 1))
    if "$@" >/dev/null 2>&1; then
        echo "  FAIL: $label (expected failure but got success)"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    fi
}

echo "=== pentest-ai findings.sh unit tests ==="
echo ""

# ─── help ──────────────────────────────────────────────────────────────
echo "--- help ---"
out=$(bash "$FINDINGS" --help 2>&1)
assert_contains "help shows usage" "$out" "findings.sh"
assert_contains "help lists commands" "$out" "init"

# ─── init ──────────────────────────────────────────────────────────────
echo "--- init ---"
out=$(bash "$FINDINGS" init test-engagement --client "Test Corp" --type "internal" --scope "10.0.0.0/24")
assert_contains "init creates engagement" "$out" "Engagement 'test-engagement' created"

out=$(bash "$FINDINGS" engagements)
assert_contains "engagement appears in list" "$out" "test-engagement"
assert_contains "client recorded" "$out" "Test Corp"

# ─── use ───────────────────────────────────────────────────────────────
echo "--- use ---"
out=$(bash "$FINDINGS" use test-engagement)
assert_contains "use prints export" "$out" "export PENTEST_AI_ENGAGEMENT"

assert_exit_nonzero "use nonexistent engagement fails" bash "$FINDINGS" use nonexistent-eng

# ─── add host ──────────────────────────────────────────────────────────
echo "--- add host ---"
out=$(bash "$FINDINGS" add host 10.0.0.1 --hostname "dc01.test.local" --os "Windows Server 2022" --role "DC" --agent "recon-advisor")
assert_contains "add host succeeds" "$out" "Host added: 10.0.0.1"
assert_contains "host has id" "$out" "id="

out=$(bash "$FINDINGS" add host 10.0.0.5 --hostname "web01" --os "Ubuntu" --role "Web")
assert_contains "second host added" "$out" "Host added: 10.0.0.5"

# ─── add service ───────────────────────────────────────────────────────
echo "--- add service ---"
out=$(bash "$FINDINGS" add service 10.0.0.1 445 --service "SMB" --proto tcp)
assert_contains "add service succeeds" "$out" "Service added: 10.0.0.1:445"

out=$(bash "$FINDINGS" add service 10.0.0.5 80 --service "HTTP" --version "nginx/1.24")
assert_contains "add service with version" "$out" "Service added: 10.0.0.5:80"

assert_exit_nonzero "add service to unknown host fails" bash "$FINDINGS" add service 10.0.0.99 22

# ─── add vuln ──────────────────────────────────────────────────────────
echo "--- add vuln ---"
out=$(bash "$FINDINGS" add vuln "Test SQLi" --severity critical --host 10.0.0.5 --cve "CVE-2024-0001" --cvss 9.8 --agent "vuln-scanner" --desc "Test vulnerability")
assert_contains "add vuln succeeds" "$out" "\[critical\] Test SQLi"

out=$(bash "$FINDINGS" add vuln "Missing Headers" --severity low --host 10.0.0.5 --agent "web-hunter")
assert_contains "add low vuln" "$out" "\[low\] Missing Headers"

assert_exit_nonzero "add vuln without severity fails" bash "$FINDINGS" add vuln "No Severity"
assert_exit_nonzero "add vuln with bad severity fails" bash "$FINDINGS" add vuln "Bad Sev" --severity extreme

# ─── add cred ──────────────────────────────────────────────────────────
echo "--- add cred ---"
out=$(bash "$FINDINGS" add cred "admin" "password123" --type cleartext --domain "test.local" --source "brute_force" --access "domain_admin" --agent "credential-tester")
assert_contains "add cred succeeds" "$out" "Credential added: admin"

assert_exit_nonzero "add cred without type fails" bash "$FINDINGS" add cred "user" "pass"

# ─── add chain ─────────────────────────────────────────────────────────
echo "--- add chain ---"
out=$(bash "$FINDINGS" add chain "Test Chain" --score 85 --steps "step1 -> step2" --mitre "T1558.003")
assert_contains "add chain succeeds" "$out" "Chain added: Test Chain"

# ─── log ───────────────────────────────────────────────────────────────
echo "--- log ---"
out=$(bash "$FINDINGS" log "recon-advisor" "scan" "Scanned 10.0.0.0/24")
assert_contains "log succeeds" "$out" "Logged: \[recon-advisor\] scan"

# ─── update ────────────────────────────────────────────────────────────
echo "--- update ---"
out=$(bash "$FINDINGS" update vuln 1 --status confirmed --confirmed-by "poc-validator")
assert_contains "update vuln succeeds" "$out" "Vuln 1 updated"

out=$(bash "$FINDINGS" update chain 1 --status validated --score 90)
assert_contains "update chain succeeds" "$out" "Chain 1 updated"

out=$(bash "$FINDINGS" update host 1 --os "Windows Server 2025" --status "compromised")
assert_contains "update host succeeds" "$out" "Host 1 updated"

# ─── list ──────────────────────────────────────────────────────────────
echo "--- list ---"
out=$(bash "$FINDINGS" list hosts)
assert_contains "list hosts shows ip" "$out" "10.0.0.1"
assert_contains "list hosts shows hostname" "$out" "dc01.test.local"

out=$(bash "$FINDINGS" list services)
assert_contains "list services shows port" "$out" "445"

out=$(bash "$FINDINGS" list vulns)
assert_contains "list vulns shows title" "$out" "Test SQLi"

out=$(bash "$FINDINGS" list vulns --severity critical)
assert_contains "list vulns filter by severity" "$out" "Test SQLi"

out=$(bash "$FINDINGS" list creds)
assert_contains "list creds shows user" "$out" "admin"

out=$(bash "$FINDINGS" list chains)
assert_contains "list chains shows name" "$out" "Test Chain"

out=$(bash "$FINDINGS" list log)
assert_contains "list log shows entry" "$out" "recon-advisor"

# ─── get ───────────────────────────────────────────────────────────────
echo "--- get ---"
out=$(bash "$FINDINGS" get vuln 1)
assert_contains "get vuln shows title" "$out" "Test SQLi"
assert_contains "get vuln shows confirmed status" "$out" "confirmed"

out=$(bash "$FINDINGS" get host 10.0.0.1)
assert_contains "get host by ip" "$out" "dc01.test.local"

out=$(bash "$FINDINGS" get host 1)
assert_contains "get host by id" "$out" "dc01.test.local"

out=$(bash "$FINDINGS" get chain 1)
assert_contains "get chain shows name" "$out" "Test Chain"

# ─── stats ─────────────────────────────────────────────────────────────
echo "--- stats ---"
out=$(bash "$FINDINGS" stats)
assert_contains "stats shows hosts count" "$out" "Hosts:"
assert_contains "stats shows vulns count" "$out" "Vulns:"
assert_contains "stats shows confirmed" "$out" "Confirmed:"

# ─── export ────────────────────────────────────────────────────────────
echo "--- export ---"
out=$(bash "$FINDINGS" export)
assert_contains "export produces json" "$out" '"engagement"'
assert_contains "export contains hosts" "$out" '"hosts"'
assert_contains "export contains vulns" "$out" '"vulns"'

# ─── summary ───────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
