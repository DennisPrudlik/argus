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
| `--pid <pid>` | Only show events from this PID (enforced in kernel) |
| `--comm <name>` | Only show events from processes with this name (enforced in kernel) |
| `--path <str>` | Only show file events whose path contains this string (userspace) |
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

# Watch file opens under /etc
sudo ./argus --path /etc

# JSON output, pipe into jq
sudo ./argus --json | jq 'select(.type == "EXEC")'

# Filter by comm, JSON output
sudo ./argus --comm nginx --json
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

## Kernel-side filtering

`--pid` and `--comm` filters are pushed into BPF maps before any programs attach. The kernel drops non-matching events before they reach the ring buffer — filtered runs have near-zero overhead even on noisy hosts. `--path` is evaluated in userspace after delivery.

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

## Repository layout

```
argus.bpf.c     eBPF kernel programs (execve, openat, connect, sched_process_exit)
argus.c         Userspace loader, ring buffer consumer, CLI
output.c/h      Text and JSON formatting, event filtering
lineage.c/h     Userspace process ancestry cache
argus.h         Shared event struct and type definitions
lima/           Lima VM config for development on non-Linux hosts
.devcontainer/  VS Code Dev Container config (alternative to Lima)
Makefile        Build entry point
```
