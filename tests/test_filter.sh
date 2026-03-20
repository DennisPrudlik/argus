#!/usr/bin/env bash
# Integration test for argus kernel-side filtering.
# Must be run as root inside the Lima VM (or any Linux with BPF support).
# Usage: sudo bash tests/test_filter.sh [path/to/argus]

set -euo pipefail

ARGUS=${1:-./argus}
PASS=0
FAIL=0

die() { echo "ERROR: $*" >&2; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "this test must run as root (sudo)"
}

require_binary() {
    [ -x "$ARGUS" ] || die "argus binary not found at $ARGUS — run 'make' first"
}

check() {
    local desc=$1 result=$2
    if [ "$result" -eq 0 ]; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s\n" "$desc"
        FAIL=$((FAIL + 1))
    fi
}

# ── helpers ─────────────────────────────────────────────────────────────────

start_argus() {
    # $@ = argus args; writes JSON to $OUTFILE; returns PID in $ARGUS_PID
    OUTFILE=$(mktemp /tmp/argus_test_XXXXXX.json)
    "$ARGUS" "$@" --json >"$OUTFILE" 2>/dev/null &
    ARGUS_PID=$!
    sleep 0.4   # give BPF programs time to attach
}

stop_argus() {
    kill "$ARGUS_PID" 2>/dev/null || true
    wait "$ARGUS_PID" 2>/dev/null || true
}

# Count events in $OUTFILE matching a jq filter
count_events() {
    python3 - "$OUTFILE" "$1" <<'PY'
import sys, json
outfile, field_filter = sys.argv[1], sys.argv[2]
count = 0
with open(outfile) as f:
    for line in f:
        line = line.strip()
        if not line or '"DROP"' in line:
            continue
        try:
            e = json.loads(line)
            k, v = field_filter.split("=", 1)
            if str(e.get(k, "")) == v:
                count += 1
        except Exception:
            pass
print(count)
PY
}

# ── test 1: --pid filter ─────────────────────────────────────────────────────

echo ""
echo "Test 1: --pid filter"

MY_PID=$$
start_argus --pid "$MY_PID"

# Generate OPEN event from our own PID using shell file-descriptor (no subprocess)
exec 3</etc/hostname
exec 3<&-

# Generate events from a different PID (background subshell) to verify filtering
OTHER_OUT=$(mktemp)
bash -c "sleep 0.05; ls /tmp >/dev/null 2>&1" &
OTHER_PID=$!
wait "$OTHER_PID" 2>/dev/null || true

sleep 0.5
stop_argus

# Verify: all events should have pid == MY_PID
WRONG=$(python3 - "$OUTFILE" "$MY_PID" <<'PY'
import sys, json
outfile = sys.argv[1]
expected_pid = int(sys.argv[2])
wrong = 0
with open(outfile) as f:
    for line in f:
        line = line.strip()
        if not line or '"DROP"' in line:
            continue
        try:
            e = json.loads(line)
            if e.get("pid", expected_pid) != expected_pid:
                wrong += 1
        except Exception:
            pass
print(wrong)
PY
)
check "--pid produces no events from other PIDs" "$WRONG"

# Verify: we captured at least one event from our PID
GOT=$(count_events "pid=$MY_PID")
if [ "$GOT" -gt 0 ]; then
    check "--pid captures events from the target PID" 0
else
    check "--pid captures events from the target PID (got 0 events)" 1
fi

rm -f "$OUTFILE" "$OTHER_OUT"

# ── test 2: --comm filter ─────────────────────────────────────────────────────

echo ""
echo "Test 2: --comm filter"

start_argus --comm ls

ls /tmp >/dev/null 2>&1   # trigger matching event
sleep 0.3
stop_argus

# Verify: at least one event with comm=ls
GOT_LS=$(count_events "comm=ls")
check "--comm captures events for matching comm" "$([ "$GOT_LS" -gt 0 ] && echo 0 || echo 1)"

# Verify: no events with a different comm
WRONG_COMM=$(python3 - "$OUTFILE" <<'PY'
import sys, json
wrong = 0
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line or '"DROP"' in line:
            continue
        try:
            e = json.loads(line)
            if e.get("comm", "ls") != "ls":
                wrong += 1
        except Exception:
            pass
print(wrong)
PY
)
check "--comm produces no events from other comms" "$WRONG_COMM"
rm -f "$OUTFILE"

# ── test 3: --events filter (event type selection) ────────────────────────────

echo ""
echo "Test 3: --events EXEC-only filter"

start_argus --events EXEC

bash -c "ls /tmp >/dev/null 2>&1"   # triggers EXEC and OPEN
sleep 0.4
stop_argus

# Should have EXEC events
GOT_EXEC=$(count_events "type=EXEC")
# Should have no OPEN events
GOT_OPEN=$(count_events "type=OPEN")
check "--events EXEC: EXEC events captured"      "$([ "$GOT_EXEC" -gt 0 ] && echo 0 || echo 1)"
check "--events EXEC: no OPEN events delivered"  "$GOT_OPEN"
rm -f "$OUTFILE"

# ── test 4: --exclude path ────────────────────────────────────────────────────

echo ""
echo "Test 4: --exclude /proc"

start_argus --events OPEN --exclude /proc

# Read a file in /proc (should be filtered) and one in /etc (should pass)
cat /proc/version    >/dev/null 2>&1 || true
cat /etc/hostname    >/dev/null 2>&1 || true
sleep 0.4
stop_argus

PROC_EVENTS=$(python3 - "$OUTFILE" <<'PY'
import sys, json
count = 0
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line or '"DROP"' in line:
            continue
        try:
            e = json.loads(line)
            if e.get("filename","").startswith("/proc"):
                count += 1
        except Exception:
            pass
print(count)
PY
)
check "--exclude /proc: no /proc OPEN events in output" "$PROC_EVENTS"
rm -f "$OUTFILE"

# ── results ───────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════"
printf "Results: %d passed, %d failed\n" "$PASS" "$FAIL"
echo "════════════════════════════════════"
[ "$FAIL" -eq 0 ]
