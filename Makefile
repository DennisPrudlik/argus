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

VERSION     := $(shell grep 'ARGUS_VERSION' argus.h | sed 's/.*"\(.*\)".*/\1/')
ARCH_PKG    := $(shell uname -m)

.PHONY: all clean test test-unit test-integration test-asan install uninstall deb rpm

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
argus: argus.c output.c lineage.c config.c rules.c forward.c dns.c baseline.c \
       output.h lineage.h config.h rules.h forward.h dns.h baseline.h \
       argus.skel.h argus.h
	$(CC) $(CFLAGS) -o $@ argus.c output.c lineage.c config.c rules.c \
	    forward.c dns.c baseline.c -lbpf -lelf -lz

# ── unit tests (no BPF, no root) ──────────────────────────────────────────────

# dns.c is linked into any test that uses output.c (dns_lookup is called there)
COMMON_SRCS = output.c lineage.c dns.c
COMMON_HDRS = output.h lineage.h dns.h argus.h

tests/test_lineage: tests/test_lineage.c lineage.c lineage.h argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_lineage.c lineage.c

tests/test_output: tests/test_output.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_output.c $(COMMON_SRCS)

tests/test_rules: tests/test_rules.c rules.c $(COMMON_SRCS) \
                  rules.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_rules.c rules.c $(COMMON_SRCS)

tests/test_forward: tests/test_forward.c forward.c $(COMMON_SRCS) \
                    forward.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_forward.c forward.c $(COMMON_SRCS)

test-unit: tests/test_lineage tests/test_output tests/test_rules tests/test_forward
	@echo "── lineage ──────────────────────────────────"
	@./tests/test_lineage
	@echo "── output / filter ──────────────────────────"
	@./tests/test_output
	@echo "── alert rules ──────────────────────────────"
	@./tests/test_rules
	@echo "── forwarding ───────────────────────────────"
	@./tests/test_forward

# ── integration test (requires root + built argus binary) ────────────────────
test-integration: argus
	@echo "── filter integration ───────────────────────"
	sudo bash tests/test_filter.sh ./argus

# ── ASAN / UBSan unit tests ───────────────────────────────────────────────
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

tests/test_lineage_asan: tests/test_lineage.c lineage.c lineage.h argus.h
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_lineage.c lineage.c

tests/test_output_asan: tests/test_output.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_output.c $(COMMON_SRCS)

tests/test_rules_asan: tests/test_rules.c rules.c $(COMMON_SRCS) \
                       rules.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_rules.c rules.c $(COMMON_SRCS)

tests/test_forward_asan: tests/test_forward.c forward.c $(COMMON_SRCS) \
                         forward.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_forward.c forward.c $(COMMON_SRCS)

test-asan: tests/test_lineage_asan tests/test_output_asan tests/test_rules_asan tests/test_forward_asan
	@echo "── lineage (ASAN) ───────────────────────────────"
	@./tests/test_lineage_asan
	@echo "── output / filter (ASAN) ───────────────────────"
	@./tests/test_output_asan
	@echo "── alert rules (ASAN) ───────────────────────────"
	@./tests/test_rules_asan
	@echo "── forwarding (ASAN) ────────────────────────────"
	@./tests/test_forward_asan

# Run unit tests only (no root required)
test: test-unit

# ── packaging ──────────────────────────────────────────────────────────────────

# Debian/Ubuntu package — requires dpkg-deb
deb: argus
	rm -rf pkg/deb
	mkdir -p pkg/deb/DEBIAN
	mkdir -p pkg/deb$(BINDIR)
	mkdir -p pkg/deb$(UNITDIR)
	mkdir -p pkg/deb$(TMPFILESDIR)
	mkdir -p pkg/deb$(LOGROTATEDIR)
	install -m755 argus            pkg/deb$(BINDIR)/argus
	install -m644 argus.service    pkg/deb$(UNITDIR)/argus.service
	install -m644 argus.tmpfiles   pkg/deb$(TMPFILESDIR)/argus.conf
	install -m644 argus.logrotate  pkg/deb$(LOGROTATEDIR)/argus
	printf 'Package: argus\nVersion: $(VERSION)\nSection: security\nPriority: optional\nArchitecture: $(ARCH_PKG)\nDepends: libbpf0\nMaintainer: argus project\nDescription: eBPF-based syscall telemetry daemon\n argus monitors process execution, file access, network connections\n and security-relevant syscalls via eBPF tracepoints.\n' \
	    > pkg/deb/DEBIAN/control
	dpkg-deb --build pkg/deb argus_$(VERSION)_$(ARCH_PKG).deb
	rm -rf pkg/deb
	@echo "Built: argus_$(VERSION)_$(ARCH_PKG).deb"

# RPM package — requires rpmbuild
rpm: argus argus.spec
	mkdir -p ~/rpmbuild/{SPECS,SOURCES,BUILD,RPMS,SRPMS,BUILDROOT}
	cp argus.spec ~/rpmbuild/SPECS/argus.spec
	rpmbuild -bb \
	    --define "_bindir $(PREFIX)/bin" \
	    --define "version $(VERSION)" \
	    ~/rpmbuild/SPECS/argus.spec
	@echo "RPM built in ~/rpmbuild/RPMS/"

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
	      tests/test_lineage tests/test_output tests/test_rules tests/test_forward \
	      tests/test_lineage_asan tests/test_output_asan tests/test_rules_asan tests/test_forward_asan
	rm -rf pkg/
