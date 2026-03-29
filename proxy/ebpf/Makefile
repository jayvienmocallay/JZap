# =============================================================================
# JZap (ShieldProxy) — eBPF/XDP Program Build
# Requires: clang, llvm, linux-headers, libbpf-dev, bpftool
# Target: Linux kernel 5.10+ with BPF CO-RE
# =============================================================================

CLANG     ?= clang
LLC       ?= llc
OPT       ?= opt
STRIP     ?= llvm-strip
BPFTOOL   ?= bpftool

ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERN_SRC  ?= /usr/src/linux-headers-$(shell uname -r)

BPF_CFLAGS := -g -O2 \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I$(SRC_DIR) \
	-I$(KERN_SRC)/include \
	-I$(KERN_SRC)/include/uapi \
	-I/usr/include/bpf \
	-Wall -Werror

SRC_DIR   := src
BUILD_DIR := build
INSTALL_DIR ?= /opt/jzap/ebpf

# Explicitly list all XDP programs
PROGRAMS  := blocklist ratelimit amplification geo_filter
OBJECTS   := $(patsubst %,$(BUILD_DIR)/%.o,$(PROGRAMS))

.PHONY: all clean headers install verify

all: $(BUILD_DIR) $(OBJECTS)
	@echo "[JZap] eBPF programs compiled successfully"
	@echo "[JZap] Programs: $(PROGRAMS)"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ---------------------------------------------------------------------------
# Generate vmlinux.h for BPF CO-RE (requires bpftool with BTF support)
# This extracts kernel type information from the running kernel's BTF data,
# enabling type-safe access to kernel structures without kernel headers.
# ---------------------------------------------------------------------------
headers: $(SRC_DIR)/vmlinux.h

$(SRC_DIR)/vmlinux.h:
	@echo "[JZap] Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "[JZap] vmlinux.h generated at $@"

# ---------------------------------------------------------------------------
# Compile each .c source in src/ to a BPF .o object in build/
# ---------------------------------------------------------------------------
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/common.h | $(BUILD_DIR)
	@echo "[JZap] Compiling $< → $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(STRIP) -g $@
	@echo "[JZap] Built $@"

# ---------------------------------------------------------------------------
# Install compiled BPF objects to deployment directory
# ---------------------------------------------------------------------------
install: all
	@echo "[JZap] Installing eBPF programs to $(INSTALL_DIR)/"
	mkdir -p $(INSTALL_DIR)
	cp $(OBJECTS) $(INSTALL_DIR)/
	@echo "[JZap] Installed: $(notdir $(OBJECTS))"

# ---------------------------------------------------------------------------
# Verify eBPF programs are valid ELF objects with BPF sections
# ---------------------------------------------------------------------------
verify: $(OBJECTS)
	@for obj in $(OBJECTS); do \
		echo "[JZap] Verifying $$obj..."; \
		llvm-objdump -S $$obj > /dev/null 2>&1 && echo "  OK" || echo "  FAILED"; \
	done

# ---------------------------------------------------------------------------
# Clean build artifacts
# ---------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)
	@echo "[JZap] Cleaned eBPF build artifacts"
