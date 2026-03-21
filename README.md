# Argus

A lightweight Linux kernel telemetry tool built on eBPF. Traces process execution, file opens, network connections, file deletions/renames/permission changes, socket binds, and ptrace calls system-wide with minimal overhead. Every event carries process ancestry (`systemd→sshd→bash→curl`) and the container cgroup name for immediate container attribution.

## Requirements

- Linux kernel **5.8+** with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- Root or `CAP_BPF` + `CAP_PERFMON`

### Build dependencies

```sh
# Ubuntu / Debian
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev linux-tools-common linux-tools-generic

# Fedora / RHEL
sudo dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel bpftool
```

Verify BTF is available on your kernel:

```sh
ls /sys/kernel/btf/vmlinux
```

## Install

```sh
git clone https://github.com/DennisPrudlik/argus
cd argus
make
```

The build produces a single binary: `argus`.

Build steps performed by `make`:
1. Generates `vmlinux.h` from the running kernel's BTF via `bpftool`
2. Compiles `argus.bpf.c` to a BPF ELF object with `clang`
3. Generates `argus.skel.h` (libbpf skeleton) via `bpftool`
4. Compiles the userspace loader `argus` with `gcc`

### System-wide install

```sh
sudo make install      # installs binary, systemd unit, tmpfiles.d, and logrotate config
sudo make uninstall    # removes all of the above
```

### Packages

Build a native package for deployment on other machines:

```sh
# Debian / Ubuntu (.deb) — requires dpkg-deb
make deb
# → argus_0.1.0_x86_64.deb

# Fedora / RHEL (.rpm) — requires rpmbuild
make rpm
# → ~/rpmbuild/RPMS/.../argus-0.1.0-1.x86_64.rpm
```

Both packages install the binary to `/usr/local/bin/argus` and include the systemd unit, tmpfiles.d config, and logrotate config.

To run as a persistent daemon:

```sh
sudo systemd-tmpfiles --create        # creates /var/log/argus/ (done once)
sudo systemctl daemon-reload
sudo systemctl enable --now argus
journalctl -u argus -f                # live log
cat /var/log/argus/events.jsonl       # persistent JSONL output
```

The service writes JSON to `/var/log/argus/events.jsonl`, drops privileges to `nobody` after attach, and restarts automatically on failure. Log rotation is configured via the installed `logrotate` config (daily, 14 days, compressed).

## Usage

```sh
sudo ./argus [OPTIONS]
```

| Option | Description |
|---|---|
| `--config <path>` | Load config file (see [Config file](#config-file)) |
| `--pid <pid>` | Only trace this PID (enforced in kernel) |
| `--follow <pid>` | Trace PID and all descendant processes (BPF fork tracking) |
| `--comm <name>` | Only trace this process name (enforced in kernel) |
| `--path <str>` | Only show file events whose path contains this string (userspace) |
| `--exclude <pfx>` | Exclude file events (OPEN, UNLINK, RENAME, CHMOD) whose path starts with this prefix (repeatable) |
| `--events <list>` | Comma-separated event types: `EXEC,OPEN,EXIT,CONNECT,UNLINK,RENAME,CHMOD,BIND,PTRACE` |
| `--rate-limit <n>` | Drop events after N per second per process name (0 = off, kernel-enforced) |
| `--ringbuf <kb>` | Ring buffer size in KB (default: 256) |
| `--summary <secs>` | Rolling summary every N seconds instead of per-event output |
| `--output <path>` | Write event stream to file instead of stdout (opened in append mode) |
| `--syslog` | Emit events to syslog (`LOG_DAEMON`) instead of stdout |
| `--rules <path>` | Load alert rules from JSON file (see [Alert rules](#alert-rules)) |
| `--forward <host:port>` | Stream JSON events to a remote TCP listener (see [Forwarding](#forwarding)) |
| `--baseline <path>` | Detect anomalies against a learnt profile (see [Baseline mode](#baseline--anomaly-mode)) |
| `--baseline-learn <secs>` | Learn a baseline profile for N seconds |
| `--baseline-out <path>` | File to write the learnt baseline profile (default: `baseline.json`) |
| `--json` | Emit newline-delimited JSON instead of a text table |
| `--no-drop-privs` | Stay root after attach (not recommended) |
| `--config-check` | Validate config file(s) and print active settings, then exit |
| `--version` | Print version and exit |
| `--help` | Show usage |

### Examples

```sh
# Trace everything
sudo ./argus

# Watch only curl activity
sudo ./argus --comm curl

# Watch a specific PID and all its children recursively
sudo ./argus --follow 1234

# Watch a specific PID (no children)
sudo ./argus --pid 1234

# Watch file opens under /etc, excluding /proc and /sys noise
sudo ./argus --events OPEN --path /etc --exclude /proc --exclude /sys

# Security-focused: file deletions, permission changes, and process injection
sudo ./argus --events UNLINK,RENAME,CHMOD,PTRACE --json

# Detect server-side network binds
sudo ./argus --events BIND --json | jq 'select(.lport < 1024)'

# Limit noisy processes to 100 events/sec each
sudo ./argus --rate-limit 100

# Rolling 10-second summary
sudo ./argus --summary 10

# Only trace EXEC and CONNECT, JSON output
sudo ./argus --events EXEC,CONNECT --json

# JSON output, pipe into jq
sudo ./argus --json | jq 'select(.type == "EXEC")'

# Show only container events (non-empty cgroup)
sudo ./argus --json | jq 'select(.cgroup != "")'

# Use a config file
sudo ./argus --config /etc/argus/config.json

# Reload config without restarting
sudo kill -HUP $(pidof argus)

# Write events to a persistent file instead of stdout
sudo ./argus --json --output /var/log/argus/events.jsonl

# Emit all events to syslog (daemon facility)
sudo ./argus --syslog

# Load alert rules and emit alerts to stderr (text) or inline (JSON)
sudo ./argus --rules /etc/argus/rules.json --json

# Combine: daemon mode with rules
sudo ./argus --syslog --rules /etc/argus/rules.json

# Forward all events to a remote SIEM over TCP
sudo ./argus --forward siem.internal:9000 --json

# Forward + local file copy simultaneously
sudo ./argus --forward siem.internal:9000 --output /var/log/argus/events.jsonl --json

# IPv6 receiver
sudo ./argus --forward '[::1]:9000'

# Learn a baseline for 1 hour, then use it for anomaly detection
sudo ./argus --baseline-learn 3600 --baseline-out /etc/argus/baseline.json
sudo ./argus --baseline /etc/argus/baseline.json --json
```

## Output

### Text

```
Tracing via eBPF (EXEC,OPEN,EXIT,CONNECT,UNLINK,RENAME,CHMOD,BIND,PTRACE)... Ctrl-C to stop.

TYPE   PID     PPID    UID   GID   COMM              CGROUP                    LINEAGE                           DETAIL
-----  ------  ------  ----  ----  ----------------  ------------------------  --------------------------------  ------
EXEC   3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 /usr/bin/curl example.com
OPEN   3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 [OK] /etc/ssl/certs/ca-certificates.crt
CONN   3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 [OK] 93.184.216.34:443
EXIT   3821    3820    1000  1000  curl              -                         systemd→sshd→bash                 exit_code=0
UNLNK  4102    4100    0     0     rm                docker-abc123.scope       systemd→containerd→sh             [OK] /tmp/secret.key
PTRC   8801    8800    0     0     gdb               -                         systemd→sshd→bash                 [OK] req=16 target_pid=3821
```

### JSON (`--json`)

One object per line, suitable for `jq`, log shippers, or SIEMs:

```json
{"type":"EXEC","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":41238,"success":true,"filename":"/usr/bin/curl","args":"example.com"}
{"type":"OPEN","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":9812,"success":true,"filename":"/etc/ssl/certs/ca-certificates.crt"}
{"type":"CONNECT","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":2301,"success":true,"family":2,"daddr":"93.184.216.34","hostname":"example.com","dport":443}
{"type":"EXIT","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":0,"success":true,"exit_code":0}
{"type":"UNLINK","pid":4102,"ppid":4100,"uid":0,"gid":0,"comm":"rm","cgroup":"docker-abc123.scope","lineage":"systemd→containerd→sh","duration_ns":312,"success":true,"filename":"/tmp/secret.key"}
{"type":"PTRACE","pid":8801,"ppid":8800,"uid":0,"gid":0,"comm":"gdb","cgroup":"","lineage":"systemd→sshd→bash","duration_ns":88,"success":true,"ptrace_req":16,"target_pid":3821}
```

If the ring buffer fills under load, a drop warning is emitted:

```
[WARNING: 14 event(s) dropped — ring buffer full]
```

In `--json` mode this appears inline as `{"type":"DROP","count":14}`.

## Event Types

| Type | Tracepoint | Key Fields |
|---|---|---|
| `EXEC` | `syscalls/sys_{enter,exit}_execve` | `filename`, `args`, `duration_ns` |
| `OPEN` | `syscalls/sys_{enter,exit}_openat` | `filename`, `success`, `duration_ns` |
| `EXIT` | `sched/sched_process_exit` | `exit_code` |
| `CONNECT` | `syscalls/sys_{enter,exit}_connect` | `family`, `daddr`, `dport`, `success` |
| `UNLINK` | `syscalls/sys_{enter,exit}_unlinkat` | `filename`, `success` |
| `RENAME` | `syscalls/sys_{enter,exit}_renameat2` | `filename` (old), `new_path`, `success` |
| `CHMOD` | `syscalls/sys_{enter,exit}_fchmodat` | `filename`, `mode`, `success` |
| `BIND` | `syscalls/sys_{enter,exit}_bind` | `family`, `laddr`, `lport`, `success` |
| `PTRACE` | `syscalls/sys_{enter,exit}_ptrace` | `ptrace_req`, `target_pid`, `success` |

All events include: `pid`, `ppid`, `uid`, `gid`, `comm`, `cgroup`, `lineage`.

The `cgroup` field contains the leaf cgroup name. For Docker containers this is the container scope name (e.g. `docker-abc123.scope`); for Kubernetes pods it is the container ID. Empty string on host processes.

### Summary mode (`--summary N`)

Instead of per-event lines, print a rolling summary every N seconds:

```
════════════════════════════════════════════════════════
 10s summary
  EXEC      47  bash(21)  python3(14)  sh(12)
  OPEN    1823  nginx(891)  python3(512)  bash(420)
  CONNECT    9  curl(6)  wget(3)
  EXIT      44
════════════════════════════════════════════════════════
```

## Config file

Argus loads `/etc/argus/config.json` then `~/.config/argus/config.json` on startup (if present), with later values overriding earlier ones. CLI flags always take final precedence. All keys are optional.

```json
{
    "pid": 0,
    "follow_pid": 0,
    "comm": "",
    "path": "",
    "exclude_paths": ["/proc", "/sys", "/dev"],
    "event_types": ["EXEC", "OPEN", "EXIT", "CONNECT", "UNLINK", "RENAME", "CHMOD", "BIND", "PTRACE"],
    "ring_buffer_kb": 256,
    "summary_interval": 0,
    "rate_limit_per_comm": 0,
    "output_path": "",
    "syslog": false,
    "rules": "",
    "forward": "",
    "baseline": "",
    "baseline_out": "",
    "baseline_learn_secs": 0
}
```

A config file is the recommended way to run argus as a persistent daemon — set `exclude_paths` to suppress `/proc`/`/sys` noise, `event_types` to limit which tracepoints are attached, and `rate_limit_per_comm` to prevent any single process from flooding the ring buffer. Changes take effect immediately on `SIGHUP` without restarting.

## Kernel-side filtering

`--pid` and `--comm` filters are pushed into BPF maps before any programs attach. The kernel drops non-matching events before they reach the ring buffer — filtered runs have near-zero overhead even on noisy hosts. `--path` and `--exclude` are evaluated in userspace after delivery. `--events` prevents the unused BPF programs from loading entirely.

`--rate-limit N` enforces a per-comm sliding-window token bucket inside the BPF programs: once a process name emits more than N events per second, further events from that comm are silently dropped until the next 1-second window opens. Useful to prevent a single noisy process (e.g. a busy web server) from saturating the ring buffer.

## PID subtree tracking (`--follow`)

`--follow <pid>` traces a process and all its descendants — children, grandchildren, and so on — dynamically as they are spawned. The BPF `sched_process_fork` tracepoint propagates the tracked set: whenever a fork/clone is observed from a followed PID, the child is added to the `follow_pids` BPF map automatically. When a followed process exits, it is removed from the map.

This is useful for tracing the complete activity of a service tree without knowing all its PIDs in advance:

```sh
# Trace nginx and every worker process it spawns
sudo ./argus --follow $(pidof nginx | awk '{print $1}')

# Trace a shell session and everything it runs
sudo ./argus --follow $$
```

Unlike `--pid` (which is a static allowlist), `--follow` tracks process trees dynamically. Both can be combined: `--pid` for a static set, `--follow` for a subtree.

## DNS reverse-lookup

CONNECT and BIND events automatically include a reverse-DNS hostname lookup. Results are cached in a 512-entry table with a 300-second TTL so `getnameinfo()` is only called once per unique address per window.

**Text output:**
```
CONN   3821    3820    1000  1000  curl   -   systemd→bash   [OK] example.com (93.184.216.34):443
```

**JSON output** — adds a `hostname` field next to `daddr`/`laddr`:
```json
{"type":"CONNECT",...,"daddr":"93.184.216.34","hostname":"example.com","dport":443}
```

When reverse resolution fails (no PTR record), `hostname` equals the dotted-decimal address and the text output shows the IP only.

## Baseline / anomaly mode

Argus can learn the normal behaviour of each process name over a time window and then alert on deviations. This is useful for detecting unexpected outbound connections, new binaries executing under a web server, or unusual file access patterns.

### Learning

```sh
# Learn for 1 hour and write the profile
sudo ./argus --baseline-learn 3600 --baseline-out /etc/argus/baseline.json
```

The profile records per-comm:
- `exec_targets` — filenames of every successful `execve`
- `connect_dests` — `addr:port` pairs from every successful `connect`
- `open_paths` — filenames of every successful `open`

### Detection

```sh
sudo ./argus --baseline /etc/argus/baseline.json --json
```

Each new event is checked against the learnt profile for its `comm`. If an EXEC target, CONNECT destination, or OPEN path has not been seen before, an anomaly alert is emitted:

**Text mode (stderr):**
```
[ANOMALY] comm=nginx           pid=4102    new_connect_dest: 198.51.100.5:4444
```

**JSON mode (inline):**
```json
{"type":"ANOMALY","severity":"HIGH","comm":"nginx","pid":4102,"what":"new_connect_dest","value":"198.51.100.5:4444"}
```

Baseline detection and alert rules run simultaneously — combine both for defence-in-depth.

## Config reload (SIGHUP)

Send `SIGHUP` to reload config files without restarting:

```sh
sudo kill -HUP $(pidof argus)
# or
sudo systemctl reload argus
```

On SIGHUP, argus re-reads `/etc/argus/config.json` and `~/.config/argus/config.json` and immediately updates the BPF filter maps (pid/comm allowlists, rate limit), the userspace filters (path, excludes), and reloads the alert rules file. The event type mask and ring buffer size remain fixed for the lifetime of the process — changing those requires a restart.

## Alert rules

Argus can evaluate a set of detection rules against every event and emit alerts for matches. Load rules with `--rules <path>` or set the `rules` key in the config file.

### Rule file format

A JSON array of rule objects. All match fields are optional — omit to match any value:

```json
[
    {
        "name":          "World-writable chmod",
        "severity":      "high",
        "type":          "CHMOD",
        "mode_mask":     2,
        "message":       "{comm} made {filename} world-writable (mode=0{mode})"
    },
    {
        "name":          "Ptrace injection attempt",
        "severity":      "critical",
        "type":          "PTRACE",
        "message":       "{comm} (pid={pid}) traced pid={target_pid} req={ptrace_req}"
    },
    {
        "name":          "Root file deletion",
        "severity":      "medium",
        "type":          "UNLINK",
        "uid":           0,
        "message":       "root deleted {filename}"
    },
    {
        "name":          "Suspicious shadow access",
        "severity":      "high",
        "path_contains": "/etc/shadow",
        "message":       "{comm} (uid={uid}) accessed {filename}"
    },
    {
        "name":          "Netcat execution",
        "severity":      "low",
        "type":          "EXEC",
        "comm":          "nc",
        "message":       "netcat started by pid={ppid} lineage={comm}"
    }
]
```

### Rule fields

| Field | Type | Description |
|---|---|---|
| `name` | string | Rule name — required, shown in alert output |
| `severity` | string | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `type` | string | Event type to match (`EXEC`, `OPEN`, `CHMOD`, etc.); omit to match all |
| `comm` | string | Exact process name match; omit to match any |
| `uid` | int | Exact UID match; `-1` or omit to match any |
| `path_contains` | string | Substring match on `filename`; omit to match any |
| `mode_mask` | int | CHMOD only: fire if `(mode & mode_mask) != 0` |
| `message` | string | Alert message with `{variable}` substitution |

### Message template variables

`{comm}` `{pid}` `{ppid}` `{uid}` `{gid}` `{cgroup}` `{filename}` `{args}` `{new_path}` `{mode}` `{target_pid}` `{ptrace_req}` `{daddr}` `{dport}` `{laddr}` `{lport}`

### Alert output

**Text mode** — alerts go to stderr so the event table on stdout stays clean:
```
[ALERT:high] World-writable chmod: chmod made /etc/cron.d/job world-writable (mode=0777)
[ALERT:critical] Ptrace injection attempt: gdb (pid=8801) traced pid=3821 req=16
```

**JSON mode** — alerts appear inline in the event stream:
```json
{"type":"ALERT","severity":"high","rule":"World-writable chmod","pid":4102,"ppid":4100,"uid":0,"comm":"chmod","message":"chmod made /etc/cron.d/job world-writable (mode=0777)"}
```

**Syslog mode** — alerts are sent at the appropriate priority (`LOG_INFO` through `LOG_CRIT`):
```
argus[1234]: ALERT:high rule=World-writable chmod pid=4102 comm=chmod chmod made /etc/cron.d/job world-writable
```

Rules are reloaded on `SIGHUP` — edit the rules file and send HUP to deploy new detections without restarting argus.

## Output modes

| Flag | Description |
|---|---|
| *(default)* | Text table to stdout |
| `--json` | Newline-delimited JSON to stdout (or `--output` file) |
| `--output <path>` | Append event stream to file; compatible with `--json` |
| `--syslog` | All events go to `syslog(LOG_DAEMON)`; overrides `--json` and `--output` |

`--output` opens the file in append mode so it survives log rotation. The systemd service uses stdout redirection by default; `--output` is most useful when running argus outside of systemd.

## Forwarding

`--forward host:port` streams every matched event as newline-delimited JSON over a persistent TCP connection.  The remote listener receives the same JSON objects produced by `--json`; `{"type":"DROP","count":N}` records are forwarded whenever the ring buffer drops events.

```sh
# Any TCP listener works — netcat for quick testing
nc -lk 9000

# Production: Vector, Logstash, Fluent Bit, Loki, custom receiver
sudo ./argus --forward siem.internal:9000

# IPv6
sudo ./argus --forward '[::1]:9000'
```

### Reliability behaviour

| Condition | Behaviour |
|---|---|
| Remote unreachable at startup | Non-fatal warning; retries with exponential backoff (1 s → 2 s → … → 30 s) |
| Connection lost mid-run | Reconnects automatically with same backoff |
| Send buffer full (slow receiver) | Event dropped and counted; drop count sent as `{"type":"DROP","count":N}` on next reconnect |
| `SIGHUP` | Reconnects and reloads config; forward address fixed for the lifetime of the process |

### Combining output modes

`--forward` is independent of `--output`, `--syslog`, and `--json` — they can all be active at once:

```sh
# Forward to SIEM, write local copy, show human-readable table on stdout
sudo ./argus --forward siem.internal:9000 \
             --output /var/log/argus/events.jsonl \
             --json
```

In this configuration:
- **stdout** — JSON stream (or text table without `--json`)
- **`--output` file** — JSON stream appended to disk
- **`--forward` socket** — JSON stream to remote receiver
- **`--syslog`** — if also set, overrides stdout and `--output`; forwarding continues independently

### Config file

```json
{
    "forward": "siem.internal:9000"
}
```

### Receiver example (Python)

```python
import socket, json

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('', 9000))
srv.listen(1)
print("waiting for argus...")
conn, addr = srv.accept()
print(f"connected: {addr}")
buf = ""
for chunk in iter(lambda: conn.recv(4096).decode(), ""):
    buf += chunk
    while '\n' in buf:
        line, buf = buf.split('\n', 1)
        if line:
            event = json.loads(line)
            print(event.get('type'), event.get('comm'), event.get('pid'))
```

## Security

After all BPF programs are attached and the ring buffer file descriptor is open, argus drops from root to `nobody` (uid 65534) so the event loop runs with minimal privilege. All open file descriptors remain valid after the privilege drop.

To keep root throughout (e.g. for debugging), pass `--no-drop-privs`.

## Process lineage

At startup, argus scans `/proc` to pre-populate the ancestry cache with all currently running processes before any BPF programs attach. This eliminates the cold-start gap where pre-existing processes would show `?` for their lineage. The `lineage` field shows the ancestor chain from the oldest known ancestor down to the immediate parent (e.g. `systemd→sshd→bash`).

## Development environment

If you are on macOS or a machine without a compatible Linux kernel, use the included Lima VM config to get a full Ubuntu 22.04 environment with all dependencies pre-installed:

```sh
# Install Lima (macOS)
brew install lima

# Start the VM (first run downloads Ubuntu 22.04, ~5 min)
limactl start --name=argus lima/argus.yaml

# Open a shell inside the VM
limactl shell argus

# Build and run (your working directory is auto-mounted)
cd ~/path/to/argus
make
sudo ./argus
```

The Lima VM uses Apple's Virtualization Framework (`vmType: vz`) on Apple Silicon for near-native performance. Your macOS home directory is mounted read-write inside the VM at the same path, so edits in VS Code are immediately visible inside the VM.

To connect VS Code directly to the VM via Remote SSH, add the Lima SSH config:

```sh
limactl show-ssh --format config argus >> ~/.ssh/config
# Then connect to host "lima-argus" in VS Code Remote SSH
```

## Testing

```sh
# Unit tests — no root, no kernel required
make test

# Unit tests with AddressSanitizer + UBSan
make test-asan

# Integration tests — requires root and a built argus binary
make test-integration
```

Unit tests cover `event_matches` filter logic (pid, comm, path, excludes, event mask), the lineage cache (chain building, tombstone deletion, buffer truncation), the alert rules engine (rule loading, field matching, message template expansion, JSON alert output), and TCP forwarding (address parsing, live TCP send/receive, NDJSON framing, drop reporting). Integration tests start argus against live kernel events and verify: `--pid`, `--comm`, `--events`, `--exclude`, each of the 5 new event types (UNLINK, RENAME, CHMOD, BIND, PTRACE), `--rate-limit` drop behaviour, `--forward` TCP delivery, `--rules` alert firing, and `--output` file persistence.

## Performance tuning

**Ring buffer size** — The default 256 KB is enough for most workloads. On busy servers (many short-lived processes or high file open rates) you may see drop warnings. Increase with `--ringbuf 1024` or via the config file. The kernel requires the size to be a power-of-2 multiple of the page size; libbpf rounds up automatically.

**Kernel-side vs userspace filters** — `--pid` and `--comm` are enforced inside the BPF programs before events enter the ring buffer, so they add near-zero overhead even on noisy hosts. `--path`, `--exclude`, and `--events` are cheaper than running with no filter at all (`--events` prevents unused BPF programs from loading entirely) but still copy events to userspace first.

**Summary mode** — `--summary 60` trades per-event latency for dramatically lower output volume on high-event-rate hosts. Recommended for long-running daemon deployments where detailed event streams would flood the log.

## Troubleshooting

**`error: failed to open BPF skeleton`** — The binary cannot load the embedded BPF object. Ensure you're running as root (or have `CAP_BPF` + `CAP_PERFMON`) and that the kernel is 5.8+.

**`ls: cannot access '/sys/kernel/btf/vmlinux': No such file or directory`** — Your kernel was built without BTF. On Ubuntu, install `linux-image-$(uname -r)` from the main repository (not a custom kernel). Check with `zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF`.

**BPF verifier error on load** — Usually seen on kernels older than 5.15 with strict verifier bounds checking. The `#pragma unroll` arg-capture loop in `argus.bpf.c` is already tuned for 5.15. If you hit this on an even older kernel, reduce `ARGUS_MAX_ARGS` in `argus.bpf.c` and rebuild.

**`warning: could not drop privileges`** — The `nobody` user does not exist on this system. Argus continues as root. Add the user with `useradd -r -s /sbin/nologin nobody` or pass `--no-drop-privs` to suppress the warning.

**High drop rate** — Increase `--ringbuf` and/or add `--pid` / `--comm` / `--events` filters to reduce event volume. Drop counts appear in text output as `[WARNING: N event(s) dropped]` and inline in JSON as `{"type":"DROP","count":N}`.

**Validate your config before deploying:**

```sh
./argus --config /etc/argus/config.json --config-check
```

## CI

Every push and pull request to `main` runs the full test suite on GitHub Actions across two kernel versions (`ubuntu-latest` and `ubuntu-22.04` / kernel 5.15 LTS). Each run installs all build dependencies, verifies BTF availability, builds the binary, and runs unit, ASAN, and integration tests.

## Repository layout

```
argus.bpf.c          eBPF kernel programs (execve, openat, connect, unlinkat, renameat2,
                       fchmodat, bind, ptrace, sched_process_exit, sched_process_fork)
argus.c              Userspace loader, ring buffer consumer, CLI
output.c/h           Text, JSON, and syslog formatting; filtering; summary mode;
                       file output (--output) support; DNS hostname in CONNECT/BIND
rules.c/h            Alert rule engine: JSON rule loading, event matching, alert emission
forward.c/h          TCP event forwarding: non-blocking send, reconnect with backoff
dns.c/h              Reverse-DNS lookup cache (512 entries, 300 s TTL)
baseline.c/h         Baseline / anomaly detection: learn per-comm profiles, alert on deviations
lineage.c/h          Userspace process ancestry cache
config.c/h           JSON config file parser
argus.h              Shared event struct, type definitions, TRACE_* bitmasks
argus.spec           RPM spec file (make rpm)
argus.service        systemd service unit
argus.tmpfiles       systemd-tmpfiles config for /var/log/argus pre-creation
argus.logrotate      logrotate config (daily, 14 days, compressed)
tests/               Unit tests (test_lineage.c, test_output.c, test_rules.c,
                       test_forward.c) and integration test (test_filter.sh — 13 scenarios)
lima/                Lima VM config for development on non-Linux hosts
.devcontainer/       VS Code Dev Container config (alternative to Lima)
.github/workflows/   GitHub Actions CI (ubuntu-latest + ubuntu-22.04 matrix)
Makefile             Build entry point (targets: all, test, test-asan, test-integration,
                       install, deb, rpm, clean)
```
