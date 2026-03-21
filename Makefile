CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS     := -g -Wall -I.

# Optional OpenSSL — detected automatically via pkg-config; used for TLS forwarding
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifneq ($(OPENSSL_LIBS),)
CFLAGS += -DHAVE_OPENSSL $(shell pkg-config --cflags openssl 2>/dev/null)
endif

# Seccomp — present on Linux kernels; gracefully absent on non-Linux
HAVE_SECCOMP := $(shell test -f /usr/include/linux/seccomp.h && echo yes)
# (seccomp.c guards itself with #ifdef __linux__ so no extra CFLAGS needed)

PREFIX      ?= /usr/local
BINDIR       = $(DESTDIR)$(PREFIX)/bin
UNITDIR      = $(DESTDIR)/etc/systemd/system
TMPFILESDIR  = $(DESTDIR)/usr/lib/tmpfiles.d
LOGROTATEDIR = $(DESTDIR)/etc/logrotate.d
MANDIR       = $(DESTDIR)$(PREFIX)/share/man/man8

VERSION     := $(shell grep 'ARGUS_VERSION' argus.h | sed 's/.*"\(.*\)".*/\1/')
ARCH_PKG    := $(shell uname -m)

.PHONY: all clean test test-unit test-integration test-asan install uninstall deb rpm man

all: argus argus-server

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
argus: argus.c output.c lineage.c config.c rules.c forward.c dns.c \
       baseline.c seccomp.c metrics.c fim.c ldpreload.c threatintel.c \
       output.h lineage.h config.h rules.h forward.h dns.h baseline.h \
       seccomp.h metrics.h fim.h ldpreload.h threatintel.h argus.skel.h argus.h
	$(CC) $(CFLAGS) -o $@ argus.c output.c lineage.c config.c rules.c \
	    forward.c dns.c baseline.c seccomp.c metrics.c \
	    fim.c ldpreload.c threatintel.c \
	    -lbpf -lelf -lz -lpthread -lm $(OPENSSL_LIBS)

# 5. Fleet aggregator — no BPF dependency
argus-server: argus-server.c argus.h
	$(CC) $(CFLAGS) -o $@ argus-server.c

# ── unit tests (no BPF, no root) ──────────────────────────────────────────────

# dns.c is linked into any test that uses output.c (dns_lookup is called there)
# metrics.c is included because rules.c and baseline.c now call metrics_*
# fim.c, ldpreload.c, threatintel.c are included for tests that use them
COMMON_SRCS = output.c lineage.c dns.c metrics.c
COMMON_HDRS = output.h lineage.h dns.h metrics.h argus.h

tests/test_lineage: tests/test_lineage.c lineage.c lineage.h argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_lineage.c lineage.c

tests/test_output: tests/test_output.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_output.c $(COMMON_SRCS) -lpthread

tests/test_rules: tests/test_rules.c rules.c $(COMMON_SRCS) \
                  rules.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_rules.c rules.c $(COMMON_SRCS) -lpthread -lbpf

tests/test_forward: tests/test_forward.c forward.c $(COMMON_SRCS) \
                    forward.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_forward.c forward.c $(COMMON_SRCS) -lpthread $(OPENSSL_LIBS)

tests/test_baseline: tests/test_baseline.c baseline.c $(COMMON_SRCS) \
                     baseline.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) -o $@ tests/test_baseline.c baseline.c $(COMMON_SRCS) -lpthread

tests/test_metrics: tests/test_metrics.c metrics.c argus.h metrics.h
	$(CC) $(CFLAGS) -o $@ tests/test_metrics.c metrics.c -lpthread

tests/test_fim: tests/test_fim.c fim.c fim.h argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_fim.c fim.c

tests/test_netcorr: tests/test_netcorr.c threatintel.c threatintel.h argus.h
	$(CC) $(CFLAGS) -o $@ tests/test_netcorr.c threatintel.c -lpthread -lbpf -lm

test-unit: tests/test_lineage tests/test_output tests/test_rules \
           tests/test_forward tests/test_baseline tests/test_metrics \
           tests/test_fim tests/test_netcorr
	@echo "── lineage ──────────────────────────────────"
	@./tests/test_lineage
	@echo "── output / filter ──────────────────────────"
	@./tests/test_output
	@echo "── alert rules ──────────────────────────────"
	@./tests/test_rules
	@echo "── forwarding ───────────────────────────────"
	@./tests/test_forward
	@echo "── baseline / anomaly ───────────────────────"
	@./tests/test_baseline
	@echo "── metrics ──────────────────────────────────"
	@./tests/test_metrics
	@echo "── FIM ──────────────────────────────────────"
	@./tests/test_fim
	@echo "── DNS correlation / entropy ────────────────"
	@./tests/test_netcorr

# ── integration test (requires root + built argus binary) ────────────────────
test-integration: argus
	@echo "── filter integration ───────────────────────"
	sudo bash tests/test_filter.sh ./argus

# ── ASAN / UBSan unit tests ───────────────────────────────────────────────
ASAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer

tests/test_lineage_asan: tests/test_lineage.c lineage.c lineage.h argus.h
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_lineage.c lineage.c

tests/test_output_asan: tests/test_output.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_output.c $(COMMON_SRCS) -lpthread

tests/test_rules_asan: tests/test_rules.c rules.c $(COMMON_SRCS) \
                       rules.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_rules.c rules.c $(COMMON_SRCS) -lpthread -lbpf

tests/test_forward_asan: tests/test_forward.c forward.c $(COMMON_SRCS) \
                         forward.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_forward.c forward.c $(COMMON_SRCS) -lpthread $(OPENSSL_LIBS)

tests/test_baseline_asan: tests/test_baseline.c baseline.c $(COMMON_SRCS) \
                          baseline.h $(COMMON_HDRS)
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_baseline.c baseline.c $(COMMON_SRCS) -lpthread

tests/test_metrics_asan: tests/test_metrics.c metrics.c argus.h metrics.h
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ tests/test_metrics.c metrics.c -lpthread

test-asan: tests/test_lineage_asan tests/test_output_asan tests/test_rules_asan \
           tests/test_forward_asan tests/test_baseline_asan tests/test_metrics_asan
	@echo "── lineage (ASAN) ───────────────────────────────"
	@./tests/test_lineage_asan
	@echo "── output / filter (ASAN) ───────────────────────"
	@./tests/test_output_asan
	@echo "── alert rules (ASAN) ───────────────────────────"
	@./tests/test_rules_asan
	@echo "── forwarding (ASAN) ────────────────────────────"
	@./tests/test_forward_asan
	@echo "── baseline / anomaly (ASAN) ────────────────────"
	@./tests/test_baseline_asan
	@echo "── metrics (ASAN) ───────────────────────────────"
	@./tests/test_metrics_asan

# Run unit tests only (no root required)
test: test-unit

# ── packaging ──────────────────────────────────────────────────────────────────

# Debian/Ubuntu package — requires dpkg-deb
deb: argus argus-server
	rm -rf pkg/deb
	mkdir -p pkg/deb/DEBIAN
	mkdir -p pkg/deb$(BINDIR)
	mkdir -p pkg/deb$(UNITDIR)
	mkdir -p pkg/deb$(TMPFILESDIR)
	mkdir -p pkg/deb$(LOGROTATEDIR)
	install -m755 argus            pkg/deb$(BINDIR)/argus
	install -m755 argus-server     pkg/deb$(BINDIR)/argus-server
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

man: argus.8
	gzip -k argus.8 -c > argus.8.gz

install: argus argus-server
	install -Dm755 argus               $(BINDIR)/argus
	install -Dm755 argus-server        $(BINDIR)/argus-server
	install -Dm644 argus.service       $(UNITDIR)/argus.service
	install -Dm644 argus.tmpfiles      $(TMPFILESDIR)/argus.conf
	install -Dm644 argus.logrotate     $(LOGROTATEDIR)/argus
	install -Dm644 argus.8             $(MANDIR)/argus.8
	@echo "Run: systemd-tmpfiles --create && systemctl daemon-reload && systemctl enable --now argus"

uninstall:
	rm -f $(BINDIR)/argus $(BINDIR)/argus-server \
	      $(UNITDIR)/argus.service \
	      $(TMPFILESDIR)/argus.conf $(LOGROTATEDIR)/argus $(MANDIR)/argus.8

clean:
	rm -f argus argus-server argus.bpf.o argus.skel.h vmlinux.h argus.8.gz \
	      tests/test_lineage tests/test_output tests/test_rules tests/test_forward \
	      tests/test_baseline tests/test_metrics tests/test_fim tests/test_netcorr \
	      tests/test_lineage_asan tests/test_output_asan tests/test_rules_asan \
	      tests/test_forward_asan tests/test_baseline_asan tests/test_metrics_asan
	rm -rf pkg/
