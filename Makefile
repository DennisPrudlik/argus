CLANG   ?= clang
CC      ?= gcc
BPFTOOL ?= bpftool

OS := $(shell uname -s)

ifeq ($(OS),Darwin)
# ── macOS: Endpoint Security Framework ───────────────────────────────────────
CFLAGS := -g -Wall -I.

.PHONY: all clean

all: argus_esf

argus_esf: argus_esf.c output.c output.h argus.h
	$(CLANG) $(CFLAGS) -o $@ argus_esf.c output.c \
		-framework EndpointSecurity -lbsm
	@echo ""
	@echo "NOTE: sign the binary before running:"
	@echo "  codesign --entitlements argus.entitlements -s 'Developer ID' argus_esf"

clean:
	rm -f argus_esf

else
# ── Linux: eBPF + libbpf ─────────────────────────────────────────────────────
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS     := -g -Wall -I.

.PHONY: all clean

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
argus: argus.c output.c output.h argus.skel.h argus.h
	$(CC) $(CFLAGS) -o $@ argus.c output.c -lbpf -lelf -lz

clean:
	rm -f argus argus.bpf.o argus.skel.h vmlinux.h

endif
