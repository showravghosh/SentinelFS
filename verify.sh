#!/usr/bin/env bash
# Milestone verification: runs the documented example traces and checks decisions.
#
# The pattern is EXEC -> EXEC -> WRITE. SPAWN was removed from the v1 alphabet
# after the Phase 2 feasibility study; see docs/phase2-findings.md section 4.1.
set -u
cd "$(dirname "$0")"

POLICY=examples/protect_shadow.sfs
failures=0

run() {
    local label="$1" expected="$2"
    shift 2
    echo "--- $label"
    local output
    output=$(python3 -m sentinelfs.cli run "$POLICY" --trace "$@")
    echo "$output"
    local decision
    decision=$(echo "$output" | awk '/^Decision:/ {print $2}')
    if [[ "$decision" == "$expected" ]]; then
        echo "    OK: expected $expected, got $decision"
    else
        echo "    FAIL: expected $expected, got $decision"
        failures=$((failures + 1))
    fi
    echo
}

echo "=== COMPILE ==="
python3 -m sentinelfs.cli compile "$POLICY"
echo

echo "=== TRACE EXECUTION ==="

run 'full matching sequence' DENY \
    'EXEC("/usr/bin/python3")' 'EXEC("/bin/bash")' 'WRITE("/etc/shadow")'

run 'prefix only' ALLOW \
    'EXEC("/usr/bin/python3")'

run 'wrong final target' ALLOW \
    'EXEC("/usr/bin/python3")' 'EXEC("/bin/bash")' 'WRITE("/tmp/test.txt")'

run 'noise interleaved' DENY \
    'OPEN("/var/log/syslog")' 'EXEC("/usr/bin/python3")' 'OPEN("/var/log/syslog")' \
    'EXEC("/bin/bash")' 'WRITE("/etc/shadow")'

run 'out of order' ALLOW \
    'EXEC("/bin/bash")' 'EXEC("/usr/bin/python3")' 'WRITE("/etc/shadow")'

echo "==========================================="
if [[ $failures -eq 0 ]]; then
    echo " ALL CHECKS PASSED"
else
    echo " $failures CHECK(S) FAILED"
fi
echo "==========================================="
exit $failures
