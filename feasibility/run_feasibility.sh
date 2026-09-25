#!/usr/bin/env bash
# SentinelFS Phase 2 - feasibility study runner.
#
# Starts the observation probe, runs a ground-truth workload, stops the probe,
# and leaves both records side by side for comparison.
#
# Must be run as root (the probe needs CAP_BPF/CAP_PERFMON). The workload itself
# is run as the invoking user, not as root.
#
# Usage:  sudo ./run_feasibility.sh [scenario ...]

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
PROBE="$HERE/probe.bt"
WORKLOAD="$HERE/groundtruth.py"
RUN_AS="${SUDO_USER:-$(id -un)}"

if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root (try: sudo $0)" >&2
    exit 1
fi

command -v bpftrace >/dev/null || { echo "error: bpftrace not installed" >&2; exit 1; }

mkdir -p "$OUT"
chown "$RUN_AS" "$OUT" 2>/dev/null || true

SCENARIOS=("$@")
if [[ ${#SCENARIOS[@]} -eq 0 ]]; then
    SCENARIOS=(attack_chain interleaved ordering volume)
fi

echo "==========================================================="
echo " SentinelFS Phase 2 - Linux Event-Observation Feasibility"
echo "==========================================================="
echo " kernel:     $(uname -r)"
echo " bpftrace:   $(bpftrace --version 2>&1 | head -1)"
echo " workload user: $RUN_AS"
echo " scenarios:  ${SCENARIOS[*]}"
echo "==========================================================="
echo

for scenario in "${SCENARIOS[@]}"; do
    echo "-----------------------------------------------------------"
    echo ">>> SCENARIO: $scenario"
    echo "-----------------------------------------------------------"

    events_file="$OUT/observed-$scenario.jsonl"
    truth_file="$OUT/truth-$scenario.json"
    probe_log="$OUT/probe-$scenario.log"

    rm -f "$events_file" "$truth_file" "$probe_log"

    echo "[1/4] starting probe..."
    bpftrace "$PROBE" >"$events_file" 2>"$probe_log" &
    probe_pid=$!

    # Wait for the probe to report that its programs are attached.
    ready=0
    for _ in $(seq 1 100); do
        if grep -q '"rec":"start"' "$events_file" 2>/dev/null; then
            ready=1
            break
        fi
        if ! kill -0 "$probe_pid" 2>/dev/null; then
            echo "      PROBE FAILED TO START. Output:"
            sed 's/^/      /' "$probe_log"
            break
        fi
        sleep 0.1
    done

    if [[ $ready -ne 1 ]]; then
        echo "      probe not ready; skipping scenario"
        kill -INT "$probe_pid" 2>/dev/null
        wait "$probe_pid" 2>/dev/null
        continue
    fi
    echo "      probe attached (pid $probe_pid)"

    echo "[2/4] running ground-truth workload as $RUN_AS..."
    extra=()
    case "$scenario" in
        volume)   extra=(--count 2000) ;;
        ordering) extra=(--rounds 100) ;;
    esac
    runuser -u "$RUN_AS" -- python3 "$WORKLOAD" "$scenario" \
        --out "$truth_file" "${extra[@]}" 2>&1 | sed 's/^/      /'

    echo "[3/4] stopping probe..."
    sleep 1
    kill -INT "$probe_pid" 2>/dev/null
    wait "$probe_pid" 2>/dev/null

    echo "[4/4] results:"
    observed=$(grep -c '"rec":"event"' "$events_file" 2>/dev/null || echo 0)
    echo "      observed events (all processes): $observed"
    if [[ -s "$probe_log" ]]; then
        echo "      probe diagnostics:"
        sed 's/^/        /' "$probe_log" | head -10
    fi
    chown "$RUN_AS" "$events_file" "$truth_file" "$probe_log" 2>/dev/null || true
    echo
done

chown -R "$RUN_AS" "$OUT" 2>/dev/null || true

echo "==========================================================="
echo " Raw data written to: $OUT"
echo " Next: python3 $HERE/analyse.py"
echo "==========================================================="
