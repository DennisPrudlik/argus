FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    # Build toolchain
    clang \
    llvm \
    gcc \
    make \
    # BPF libraries
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    # bpftool (versioned path under linux-tools-generic)
    linux-tools-common \
    linux-tools-generic \
    # Useful for inspecting maps / programs at runtime
    bpftrace \
    strace \
    # General utilities
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# linux-tools-generic installs bpftool under a versioned path like
# /usr/lib/linux-tools/<kver>/bpftool — symlink it to a stable location.
RUN bpf=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null | head -1) && \
    [ -n "$bpf" ] && ln -sf "$bpf" /usr/local/bin/bpftool || true
