CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS     := -g -Wall -I.

.PHONY: all clean test test-unit test-integration

all: argus

# 1. Generate vmlinux.h from the running kernel's BTF
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2. Compile the BPF program to BPF ELF
argus.bpf.o: argus.bpf.c vmlinux.h argus.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 3. Generate the libbpf skeleton header
argus.skel.h: argus.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 4. Compile the userspace loader
argus: argus.c output.c lineage.c config.c output.h lineage.h config.h argus.skel.h argus.h
	$(CC) $(CFLAGS) -o $@ argus.c output.c lineage.c config.c -lbpf -lelf -lz

# ── unit tests (no BPF, no root) ──────────────────────────────────────────────
tests/test_lineage: tests/test_lineage.c lineage.c lineage.h argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_lineage.c lineage.c

tests/test_output: tests/test_output.c output.c lineage.c output.h lineage.h argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_output.c output.c lineage.c

test-unit: tests/test_lineage tests/test_output
	@echo "── lineage ──────────────────────────────────"
	@./tests/test_lineage
	@echo "── output / filter ──────────────────────────"
	@./tests/test_output

# ── integration test (requires root + built argus binary) ────────────────────
test-integration: argus
	@echo "── filter integration ───────────────────────"
	sudo bash tests/test_filter.sh ./argus

# Run unit tests only (no root required)
test: test-unit

clean:
	rm -f argus argus.bpf.o argus.skel.h vmlinux.h \
	      tests/test_lineage tests/test_output
