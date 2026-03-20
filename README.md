# Argus

A lightweight Linux kernel telemetry tool built on eBPF. Traces process execution, file opens, network connections, and process exits system-wide with minimal overhead, with per-event process ancestry (`systemd→sshd→bash→curl`).

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

## Usage

```sh
sudo ./argus [OPTIONS]
```

| Option | Description |
|---|---|
| `--config <path>` | Load config file (see [Config file](#config-file)) |
| `--pid <pid>` | Only trace this PID (enforced in kernel) |
| `--comm <name>` | Only trace this process name (enforced in kernel) |
| `--path <str>` | Only show file events whose path contains this string (userspace) |
| `--exclude <pfx>` | Exclude OPEN events whose path starts with this prefix (repeatable) |
| `--events <list>` | Comma-separated event types to trace: `EXEC,OPEN,EXIT,CONNECT` |
| `--ringbuf <kb>` | Ring buffer size in KB (default: 256) |
| `--summary <secs>` | Rolling summary every N seconds instead of per-event output |
| `--json` | Emit newline-delimited JSON instead of a text table |
| `--help` | Show usage |

### Examples

```sh
# Trace everything
sudo ./argus

# Watch only curl activity
sudo ./argus --comm curl

# Watch a specific PID
sudo ./argus --pid 1234

# Watch file opens under /etc, excluding /proc and /sys noise
sudo ./argus --events OPEN --path /etc --exclude /proc --exclude /sys

# Rolling 10-second summary
sudo ./argus --summary 10

# Only trace EXEC and CONNECT, JSON output
sudo ./argus --events EXEC,CONNECT --json

# JSON output, pipe into jq
sudo ./argus --json | jq 'select(.type == "EXEC")'

# Use a config file
sudo ./argus --config /etc/argus/config.json
```

## Output

### Text

```
Tracing via eBPF (EXEC, OPEN, EXIT, CONNECT)... Ctrl-C to stop.

TYPE   PID     PPID    UID   GID   COMM              LINEAGE                           DETAIL
-----  ------  ------  ----  ----  ----------------  --------------------------------  ------
EXEC   3821    3820    1000  1000  curl              systemd→sshd→bash                 /usr/bin/curl example.com
OPEN   3821    3820    1000  1000  curl              systemd→sshd→bash                 [OK] /etc/ssl/certs/ca-certificates.crt
CONN   3821    3820    1000  1000  curl              systemd→sshd→bash                 [OK] 93.184.216.34:443
EXIT   3821    3820    1000  1000  curl              systemd→sshd→bash                 exit_code=0
```

### JSON (`--json`)

One object per line, suitable for `jq`, log shippers, or SIEMs:

```json
{"type":"EXEC","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","lineage":"systemd→sshd→bash","duration_ns":41238,"success":true,"filename":"/usr/bin/curl","args":"example.com"}
{"type":"OPEN","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","lineage":"systemd→sshd→bash","duration_ns":9812,"success":true,"filename":"/etc/ssl/certs/ca-certificates.crt"}
{"type":"CONNECT","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","lineage":"systemd→sshd→bash","duration_ns":2301,"success":true,"family":2,"daddr":"93.184.216.34","dport":443}
{"type":"EXIT","pid":3821,"ppid":3820,"uid":1000,"gid":1000,"comm":"curl","lineage":"systemd→sshd→bash","duration_ns":0,"success":true,"exit_code":0}
```

If the ring buffer fills under load, a drop warning is emitted:

```
[WARNING: 14 event(s) dropped — ring buffer full]
```

In `--json` mode this appears inline as `{"type":"DROP","count":14}`.

## Event Types

| Type | Tracepoint | Fields |
|---|---|---|
| `EXEC` | `syscalls/sys_{enter,exit}_execve` | `filename`, `args`, `duration_ns` |
| `OPEN` | `syscalls/sys_{enter,exit}_openat` | `filename`, `success`, `duration_ns` |
| `EXIT` | `sched/sched_process_exit` | `exit_code` |
| `CONNECT` | `syscalls/sys_{enter,exit}_connect` | `family`, `daddr`, `dport`, `success`, `duration_ns` |

All events include: `pid`, `ppid`, `uid`, `gid`, `comm`, `lineage`.

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

Argus loads `~/.config/argus/config.json` then `/etc/argus/config.json` on startup (if present). CLI flags always override file values. All keys are optional.

```json
{
    "pid": 0,
    "comm": "",
    "path": "",
    "exclude_paths": ["/proc", "/sys", "/dev"],
    "event_types": ["EXEC", "OPEN", "EXIT", "CONNECT"],
    "ring_buffer_kb": 256,
    "summary_interval": 0
}
```

A config file is the recommended way to run argus as a persistent daemon — set `exclude_paths` to suppress `/proc`/`/sys` noise and `event_types` to limit which tracepoints are attached.

## Kernel-side filtering

`--pid` and `--comm` filters are pushed into BPF maps before any programs attach. The kernel drops non-matching events before they reach the ring buffer — filtered runs have near-zero overhead even on noisy hosts. `--path` and `--exclude` are evaluated in userspace after delivery. `--events` prevents the unused BPF programs from loading entirely.

## Process lineage

Argus maintains a userspace process ancestry cache updated on every `EXEC` and `EXIT`. The `lineage` field shows the ancestor chain from the oldest known ancestor down to the immediate parent (e.g. `systemd→sshd→bash`). Processes that were already running when argus started show `?` until they exec again — this is a cold-start limitation of the tracepoint approach.

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

# Integration tests — requires root and a built argus binary
make test-integration
```

Unit tests cover `event_matches` filter logic (pid, comm, path, excludes, event mask) and the lineage cache (chain building, tombstone deletion, buffer truncation). Integration tests start argus with `--pid`, `--comm`, `--events`, and `--exclude` filters against live kernel events and verify only matching events appear in the output.

## Repository layout

```
argus.bpf.c     eBPF kernel programs (execve, openat, connect, sched_process_exit)
argus.c         Userspace loader, ring buffer consumer, CLI
output.c/h      Text and JSON formatting, filtering, summary mode
lineage.c/h     Userspace process ancestry cache
config.c/h      JSON config file parser
argus.h         Shared event struct, type definitions, TRACE_* bitmasks
tests/          Unit tests (test_lineage.c, test_output.c) and integration test (test_filter.sh)
lima/           Lima VM config for development on non-Linux hosts
.devcontainer/  VS Code Dev Container config (alternative to Lima)
Makefile        Build entry point (targets: all, test, test-integration, clean)
```
