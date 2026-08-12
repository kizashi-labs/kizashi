# eBPF programs Makefile
# Requires: clang >= 12, libbpf-dev, linux-headers
#
# Usage:
#   make all      - compile all eBPF programs
#   make clean    - remove compiled objects
#   make vmlinux  - generate vmlinux.h from running kernel (requires bpftool)

CLANG    ?= clang
CFLAGS   := -O2 -g -Wall -target bpf
ARCH     := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu \
            -I/usr/include \
            -I.

BPF_PROGS := process_monitor.bpf.o \
             network_monitor.bpf.o \
             file_monitor.bpf.o \
             tls_monitor.bpf.o

all: vmlinux.h $(BPF_PROGS)

vmlinux.h:
	@echo "Generating vmlinux.h from running kernel..."
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "WARNING: bpftool not found. Using pre-generated vmlinux.h"; \
		touch vmlinux.h; \
	fi

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@
	@echo "Compiled: $@"

# Strip debug info for smaller binary (optional)
strip: $(BPF_PROGS)
	llvm-strip -g $^

# Verify with bpftool
verify: $(BPF_PROGS)
	@for prog in $^; do \
		echo "Verifying $$prog..."; \
		bpftool prog load $$prog /sys/fs/bpf/test_$$(basename $$prog .o) && \
		bpftool prog delete pinned /sys/fs/bpf/test_$$(basename $$prog .o); \
	done

clean:
	rm -f *.bpf.o vmlinux.h

.PHONY: all clean strip verify
