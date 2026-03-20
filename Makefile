CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS     := -g -Wall -I.

PREFIX      ?= /usr/local
BINDIR       = $(DESTDIR)$(PREFIX)/bin
UNITDIR      = $(DESTDIR)/etc/systemd/system
TMPFILESDIR  = $(DESTDIR)/usr/lib/tmpfiles.d
LOGROTATEDIR = $(DESTDIR)/etc/logrotate.d

.PHONY: all clean test test-unit test-integration test-asan install uninstall

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

# ── ASAN / UBSan unit tests ───────────────────────────────────────────────
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

tests/test_lineage_asan: tests/test_lineage.c lineage.c lineage.h argus.h
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_lineage.c lineage.c

tests/test_output_asan: tests/test_output.c output.c lineage.c output.h lineage.h argus.h
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_output.c output.c lineage.c

test-asan: tests/test_lineage_asan tests/test_output_asan
	@echo "── lineage (ASAN) ───────────────────────────────"
	@./tests/test_lineage_asan
	@echo "── output / filter (ASAN) ───────────────────────"
	@./tests/test_output_asan

# Run unit tests only (no root required)
test: test-unit

install: argus
	install -Dm755 argus               $(BINDIR)/argus
	install -Dm644 argus.service       $(UNITDIR)/argus.service
	install -Dm644 argus.tmpfiles      $(TMPFILESDIR)/argus.conf
	install -Dm644 argus.logrotate     $(LOGROTATEDIR)/argus
	@echo "Run: systemd-tmpfiles --create && systemctl daemon-reload && systemctl enable --now argus"

uninstall:
	rm -f $(BINDIR)/argus $(UNITDIR)/argus.service \
	      $(TMPFILESDIR)/argus.conf $(LOGROTATEDIR)/argus

clean:
	rm -f argus argus.bpf.o argus.skel.h vmlinux.h \
	      tests/test_lineage tests/test_output \
	      tests/test_lineage_asan tests/test_output_asan
