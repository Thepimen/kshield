# ==============================================================================
# kshield - Makefile
# ==============================================================================

CLANG ?= clang
BPFTOOL ?= bpftool
GO ?= go

CFLAGS := -O2 -g -Wall -Werror \
	-target bpf \
	-D__TARGET_ARCH_x86 \
	-I./bpf \
	-I./bpf/headers

BPF_SRC := bpf/kshield.bpf.c
BPF_OBJ := bpf/kshield.bpf.o
BIN_DIR := bin
BIN_NAME := $(BIN_DIR)/kshield

.PHONY: all vmlinux bpf generate build run test clean setup help simulate-attack

all: build

help:
	@echo "kshield build targets:"
	@echo "  make setup           - Verify and install Linux/WSL2 prerequisites"
	@echo "  make vmlinux         - Generate vmlinux.h from running kernel BTF"
	@echo "  make bpf             - Compile eBPF C program to ELF object (.o)"
	@echo "  make generate        - Run bpf2go code generation"
	@echo "  make build           - Build the kshield agent binary (bin/kshield)"
	@echo "  make run             - Run kshield with root privileges"
	@echo "  make test            - Execute Go test suite"
	@echo "  make simulate-attack - Trigger sample events for live sensor testing"
	@echo "  make clean           - Remove build artifacts and compiled objects"

setup:
	@chmod +x scripts/setup_env.sh
	@./scripts/setup_env.sh

vmlinux:
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "[!] Error: /sys/kernel/btf/vmlinux not found. Is BTF enabled?"; \
		exit 1; \
	fi
	@mkdir -p bpf/headers
	@echo "[*] Extracting vmlinux.h from /sys/kernel/btf/vmlinux..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
	@echo "[✓] bpf/headers/vmlinux.h generated."

bpf: $(BPF_SRC)
	@if [ ! -f bpf/headers/vmlinux.h ]; then \
		$(MAKE) vmlinux; \
	fi
	@mkdir -p $(dir $(BPF_OBJ))
	@echo "[*] Compiling eBPF C program with Clang..."
	$(CLANG) $(CFLAGS) -c $< -o $(BPF_OBJ)
	@echo "[✓] eBPF bytecode compiled: $(BPF_OBJ)"

generate:
	@echo "[*] Running bpf2go code generation..."
	cd internal/bpf && $(GO) generate ./...

build: bpf
	@mkdir -p $(BIN_DIR)
	@echo "[*] Building kshield user-space agent..."
	$(GO) build -ldflags="-s -w" -o $(BIN_NAME) ./cmd/kshield
	@echo "[✓] Binary built: $(BIN_NAME)"

run: build
	@echo "[*] Starting kshield (requires root)..."
	sudo $(BIN_NAME) -config config/rules.yaml -bpf-obj $(BPF_OBJ) -format table

test:
	@echo "[*] Running unit and integration tests..."
	$(GO) test -v -race ./...

simulate-attack:
	@echo "[*] Simulating attack behaviors for kshield validation..."
	@echo "1. Testing sensitive file access (/etc/shadow)..."
	-head -n 1 /etc/shadow 2>/dev/null || true
	@echo "2. Testing interactive subshell execution..."
	-bash -c "sh -i -c 'exit'" 2>/dev/null || true
	@echo "3. Testing connection to suspicious port 4444..."
	-nc -z -w 1 127.0.0.1 4444 2>/dev/null || true
	@echo "[✓] Simulated events dispatched."

clean:
	@rm -rf $(BIN_DIR)
	@rm -f $(BPF_OBJ) internal/bpf/*.o internal/bpf/*_bpfel.go internal/bpf/*_bpfeb.go
	@echo "[✓] Clean complete."
