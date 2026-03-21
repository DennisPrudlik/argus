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

require_root
require_binary

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

count_drops() {
    python3 - "$OUTFILE" <<'PY'
import sys, json
total = 0
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            e = json.loads(line)
            if e.get("type") == "DROP":
                total += e.get("count", 0)
        except Exception:
            pass
print(total)
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

GOT=$(count_events "pid=$MY_PID")
if [ "$GOT" -gt 0 ]; then
    check "--pid captures events from the target PID" 0
else
    check "--pid captures events from the target PID (got 0 events)" 1
fi

rm -f "$OUTFILE"

# ── test 2: --comm filter ─────────────────────────────────────────────────────

echo ""
echo "Test 2: --comm filter"

start_argus --comm ls

ls /tmp >/dev/null 2>&1   # trigger matching event
sleep 0.3
stop_argus

GOT_LS=$(count_events "comm=ls")
check "--comm captures events for matching comm" "$([ "$GOT_LS" -gt 0 ] && echo 0 || echo 1)"

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

GOT_EXEC=$(count_events "type=EXEC")
GOT_OPEN=$(count_events "type=OPEN")
check "--events EXEC: EXEC events captured"      "$([ "$GOT_EXEC" -gt 0 ] && echo 0 || echo 1)"
check "--events EXEC: no OPEN events delivered"  "$GOT_OPEN"
rm -f "$OUTFILE"

# ── test 4: --exclude path ────────────────────────────────────────────────────

echo ""
echo "Test 4: --exclude /proc"

start_argus --events OPEN --exclude /proc

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

# ── test 5: UNLINK events ─────────────────────────────────────────────────────

echo ""
echo "Test 5: UNLINK events"

TMP_UNLINK=$(mktemp /tmp/argus_unlink_XXXXXX)
start_argus --events UNLINK

rm -f "$TMP_UNLINK"
sleep 0.4
stop_argus

GOT_UNLINK=$(count_events "type=UNLINK")
check "--events UNLINK: UNLINK events captured" "$([ "$GOT_UNLINK" -gt 0 ] && echo 0 || echo 1)"
rm -f "$OUTFILE"

# ── test 6: RENAME events ─────────────────────────────────────────────────────

echo ""
echo "Test 6: RENAME events"

TMP_SRC=$(mktemp /tmp/argus_rename_src_XXXXXX)
TMP_DST=$(mktemp -u /tmp/argus_rename_dst_XXXXXX)
start_argus --events RENAME

mv "$TMP_SRC" "$TMP_DST"
sleep 0.4
stop_argus

GOT_RENAME=$(count_events "type=RENAME")
check "--events RENAME: RENAME events captured" "$([ "$GOT_RENAME" -gt 0 ] && echo 0 || echo 1)"
rm -f "$TMP_DST" "$OUTFILE"

# ── test 7: CHMOD events ──────────────────────────────────────────────────────

echo ""
echo "Test 7: CHMOD events"

TMP_CHMOD=$(mktemp /tmp/argus_chmod_XXXXXX)
start_argus --events CHMOD

chmod 644 "$TMP_CHMOD"
sleep 0.4
stop_argus

GOT_CHMOD=$(count_events "type=CHMOD")
check "--events CHMOD: CHMOD events captured" "$([ "$GOT_CHMOD" -gt 0 ] && echo 0 || echo 1)"
rm -f "$TMP_CHMOD" "$OUTFILE"

# ── test 8: BIND events ───────────────────────────────────────────────────────

echo ""
echo "Test 8: BIND events"

start_argus --events BIND

# Bind and immediately close a TCP socket on a high port
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19877))
s.close()
" 2>/dev/null || true
sleep 0.4
stop_argus

GOT_BIND=$(count_events "type=BIND")
check "--events BIND: BIND events captured" "$([ "$GOT_BIND" -gt 0 ] && echo 0 || echo 1)"
rm -f "$OUTFILE"

# ── test 9: PTRACE events ─────────────────────────────────────────────────────

echo ""
echo "Test 9: PTRACE events"

start_argus --events PTRACE

# Trigger ptrace via strace (available on CI) or a minimal compiled caller
if command -v strace >/dev/null 2>&1; then
    strace -e trace=read /bin/true 2>/dev/null || true
else
    # Compile and run a minimal ptrace(PTRACE_TRACEME) caller
    TMP_PTRACE=$(mktemp /tmp/argus_ptrace_XXXXXX)
    cat > "${TMP_PTRACE}.c" <<'CSRC'
#include <sys/ptrace.h>
int main(void) { ptrace(0, 0, (void*)0, (void*)0); return 0; }
CSRC
    if gcc -o "$TMP_PTRACE" "${TMP_PTRACE}.c" 2>/dev/null; then
        "$TMP_PTRACE" 2>/dev/null || true
    fi
    rm -f "$TMP_PTRACE" "${TMP_PTRACE}.c"
fi
sleep 0.4
stop_argus

GOT_PTRACE=$(count_events "type=PTRACE")
check "--events PTRACE: PTRACE events captured" "$([ "$GOT_PTRACE" -gt 0 ] && echo 0 || echo 1)"
rm -f "$OUTFILE"

# ── test 10: --rate-limit drops ───────────────────────────────────────────────

echo ""
echo "Test 10: --rate-limit drops"

start_argus --rate-limit 3 --comm cat --events OPEN

# Generate many OPEN events from cat in rapid succession
# Each cat invocation opens 3-4 files; 50 invocations ≈ 150-200 OPEN events without rate limiting.
# With rate-limit 3 per second we expect ≤ ~15 events over ~0.5 s window.
for i in $(seq 1 50); do
    cat /etc/hostname >/dev/null 2>&1
done
sleep 0.4
stop_argus

# Rate-limit drops at the BPF layer are silently discarded (not ring-buffer overflow),
# so no DROP event is emitted. Verify instead that we received far fewer events than
# generated (rate limiting is working).
OPEN_COUNT=$(count_events "type=OPEN")
check "--rate-limit: fewer events received than generated (rate limited)" \
    "$([ "$OPEN_COUNT" -lt 50 ] && echo 0 || echo 1)"
rm -f "$OUTFILE"

# ── test 11: --forward E2E ────────────────────────────────────────────────────

echo ""
echo "Test 11: --forward TCP streaming"

FWD_PORT=19879
FWD_OUT=$(mktemp /tmp/argus_fwd_XXXXXX)

# Python TCP receiver — accepts one connection, drains until EOF, writes to file
python3 - "$FWD_PORT" "$FWD_OUT" &
PY_FWD_PID=$!
cat <<'PYEOF' >/tmp/argus_fwd_receiver.py
import socket, sys
port = int(sys.argv[1])
out  = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port))
s.listen(1)
s.settimeout(5)
try:
    c, _ = s.accept()
    data = b''
    c.settimeout(1)
    while True:
        try:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        except Exception:
            break
    c.close()
except Exception:
    pass
s.close()
with open(out, 'wb') as f:
    f.write(data)
PYEOF

kill "$PY_FWD_PID" 2>/dev/null || true
python3 /tmp/argus_fwd_receiver.py "$FWD_PORT" "$FWD_OUT" &
PY_FWD_PID=$!
sleep 0.3

# Run argus with --forward pointed at our receiver
OUTFILE=$(mktemp /tmp/argus_test_XXXXXX.json)
"$ARGUS" --forward "127.0.0.1:$FWD_PORT" --events EXEC --json >"$OUTFILE" 2>/dev/null &
ARGUS_PID=$!
sleep 0.5

ls /tmp >/dev/null 2>&1

sleep 0.4
kill "$ARGUS_PID" 2>/dev/null || true
wait "$ARGUS_PID" 2>/dev/null || true
wait "$PY_FWD_PID" 2>/dev/null || true

FWD_EXEC=$(python3 - "$FWD_OUT" <<'PY'
import sys, json
count = 0
try:
    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                e = json.loads(line)
                if e.get("type") == "EXEC":
                    count += 1
            except Exception:
                pass
except Exception:
    pass
print(count)
PY
)
check "--forward: EXEC events delivered to TCP receiver" \
    "$([ "$FWD_EXEC" -gt 0 ] && echo 0 || echo 1)"
rm -f "$OUTFILE" "$FWD_OUT" /tmp/argus_fwd_receiver.py

# ── test 12: --rules alert firing ─────────────────────────────────────────────

echo ""
echo "Test 12: --rules alert on matching event"

RULES_FILE=$(mktemp /tmp/argus_rules_XXXXXX.json)
TMP_CHMOD2=$(mktemp /tmp/argus_chmod2_XXXXXX)

cat >"$RULES_FILE" <<'JSON'
[
  {
    "name": "integration-chmod-rule",
    "severity": "HIGH",
    "type": "CHMOD",
    "message": "chmod on {filename} by {comm}"
  }
]
JSON

OUTFILE=$(mktemp /tmp/argus_test_XXXXXX.json)
"$ARGUS" --rules "$RULES_FILE" --events CHMOD --json >"$OUTFILE" 2>/dev/null &
ARGUS_PID=$!
sleep 0.5

chmod 777 "$TMP_CHMOD2"

sleep 0.4
kill "$ARGUS_PID" 2>/dev/null || true
wait "$ARGUS_PID" 2>/dev/null || true

# In JSON mode, ALERT events are emitted as {"type":"ALERT",...} lines in stdout.
RULE_HITS=$(grep -c '"integration-chmod-rule"' "$OUTFILE" 2>/dev/null || true)
check "--rules: alert fired for matching CHMOD event" \
    "$([ "${RULE_HITS:-0}" -gt 0 ] && echo 0 || echo 1)"
rm -f "$OUTFILE" "$RULES_FILE" "$TMP_CHMOD2"

# ── test 13: --output file persistence ────────────────────────────────────────

echo ""
echo "Test 13: --output writes events to file"

OUT_FILE=$(mktemp /tmp/argus_outfile_XXXXXX)

"$ARGUS" --output "$OUT_FILE" --events EXEC --json &
ARGUS_PID=$!
sleep 0.5

ls /tmp >/dev/null 2>&1

sleep 0.4
kill "$ARGUS_PID" 2>/dev/null || true
wait "$ARGUS_PID" 2>/dev/null || true

FILE_EXECS=$(python3 - "$OUT_FILE" <<'PY'
import sys, json
count = 0
try:
    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                e = json.loads(line)
                if e.get("type") == "EXEC":
                    count += 1
            except Exception:
                pass
except Exception:
    pass
print(count)
PY
)
check "--output: EXEC events written to output file" \
    "$([ "$FILE_EXECS" -gt 0 ] && echo 0 || echo 1)"
rm -f "$OUT_FILE"

# ── results ───────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════"
printf "Results: %d passed, %d failed\n" "$PASS" "$FAIL"
echo "════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ]
