# Argus

Argus is a small cross-platform process and file activity tracer.

The project uses a platform-native backend on each operating system:

- **Linux**: eBPF + libbpf
- **macOS**: Endpoint Security Framework (ESF)

Its goal is to provide a lightweight CLI for observing process execution, file opens, process exits, and—on Linux—outbound network connects, with either human-readable or newline-delimited JSON output.

## Project Goal

Argus is intended to be a simple systems-observability tool for:

- watching what processes execute
- seeing which files are opened
- tracking process exits and exit codes
- capturing outbound network connect attempts where supported
- filtering events down to a specific process, command name, or path substring
- producing output that is easy to read live or pipe into other tools

## Implemented Features

### Shared user-facing features

- Text table output for interactive terminal use
- Newline-delimited JSON output via `--json`
- Event filtering by:
  - PID via `--pid`
  - process name via `--comm`
  - file path substring via `--path`
- Graceful shutdown with `Ctrl-C`
- Unified event model in `argus.h`

### Linux backend (`argus`)

Implemented with eBPF tracepoints and a libbpf userspace loader.

Currently captures:

- `EXEC`: `execve` entry/exit, including executable path and collected argv tail
- `OPEN`: `openat` entry/exit, including target filename and success/failure
- `EXIT`: process exit, including exit code
- `CONNECT`: IPv4/IPv6 outbound `connect()` activity, including destination address and port

Implementation details already present:

- Ring buffer delivery from kernel to userspace
- Per-event duration tracking for `EXEC`, `OPEN`, and `CONNECT`
- Parent PID, UID, GID, and command name capture
- IPv4 and IPv6 destination formatting in output

### macOS backend (`argus_esf`)

Implemented with the Endpoint Security Framework.

Currently captures:

- `EXEC`: process execution notifications, including executable path and arguments
- `OPEN`: file open notifications
- `EXIT`: process exit notifications and exit status

Current macOS limitations already documented in code:

- `CONNECT` is **not** implemented through ESF
- Network monitoring on macOS would require a separate Network Extension-based implementation
- The ESF binary must be code-signed with the proper entitlement and run as root
- `duration_ns` is always `0` on macOS because the current implementation uses notify events

## Event Types

Argus currently defines these event types in `argus.h`:

- `EVENT_EXEC`
- `EVENT_OPEN`
- `EVENT_EXIT`
- `EVENT_CONNECT`

## Build

The `Makefile` selects the backend based on `uname -s`.

### macOS

Build:

```sh
make
```

This builds `argus_esf`.

After building, the binary must be signed before use:

```sh
codesign --entitlements argus.entitlements -s "Developer ID" argus_esf
```

### Linux

Build:

```sh
make
```

This builds:

- `vmlinux.h` from kernel BTF
- `argus.bpf.o`
- `argus.skel.h`
- `argus`

Linux build dependencies implied by the source and `Makefile` include:

- `clang`
- `bpftool`
- `libbpf`
- `libelf`
- `zlib`
- kernel BTF available at `/sys/kernel/btf/vmlinux`

## Usage

### Linux

```sh
sudo ./argus
sudo ./argus --json
sudo ./argus --pid 1234
sudo ./argus --comm curl
sudo ./argus --path /etc/
```

### macOS

```sh
sudo ./argus_esf
sudo ./argus_esf --json
sudo ./argus_esf --pid 1234
sudo ./argus_esf --comm Finder
sudo ./argus_esf --path /Applications/
```

## Output Modes

### Text output

The default text output prints a compact table with:

- event type
- PID / PPID
- UID / GID
- command name
- event-specific details

### JSON output

`--json` emits one JSON object per line, suitable for piping into tools like `jq` or log collectors.

## Repository Layout

- `argus.bpf.c`: Linux eBPF programs
- `argus.c`: Linux userspace loader and CLI
- `argus_esf.c`: macOS Endpoint Security backend and CLI
- `output.c` / `output.h`: shared filtering and output formatting
- `argus.h`: shared event definitions
- `argus.entitlements`: macOS Endpoint Security entitlement file
- `Makefile`: platform-aware build entry point

## Current Status

What is already implemented today:

- cross-platform CLI structure
- shared event schema
- Linux eBPF tracing backend
- macOS ESF tracing backend
- text and JSON output modes
- runtime filtering for PID, command name, and path

What is not yet implemented:

- macOS network connect monitoring
- packaging/install workflow
- persisted logging or remote export
- tests and benchmark coverage
