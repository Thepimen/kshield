#!/usr/bin/env bash
# ==============================================================================
# kshield - Environment Verification and Setup Script
# Target: Ubuntu 24.04 LTS / WSL 2 (Kernel 5.15+ / 6.x with BTF enabled)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

echo -e "${BOLD}====================================================${NC}"
echo -e "${BOLD}   kshield eBPF Runtime Environment Checker         ${NC}"
echo -e "${BOLD}====================================================${NC}"

# 1. Kernel Version and BTF Support Check
info "Checking Linux Kernel version and BTF support..."
KERNEL_VER=$(uname -r)
info "Detected Kernel: ${KERNEL_VER}"

if [ -f "/sys/kernel/btf/vmlinux" ]; then
    ok "BTF enabled (/sys/kernel/btf/vmlinux exists)."
else
    warn "Kernel BTF file /sys/kernel/btf/vmlinux was NOT found!"
    warn "If you are on WSL 2, make sure you are using a modern kernel with CONFIG_DEBUG_INFO_BTF=y."
    warn "You can update WSL kernel with 'wsl --update' in Windows PowerShell."
fi

# 2. Check /sys/fs/bpf Mount
info "Checking BPF virtual filesystem..."
if mountpoint -q /sys/fs/bpf; then
    ok "BPF filesystem is mounted at /sys/fs/bpf."
else
    warn "/sys/fs/bpf is not mounted. Attempting to mount..."
    sudo mount -t bpf bpf /sys/fs/bpf || warn "Could not mount /sys/fs/bpf (may require root privileges)."
fi

# 3. Detect and Install Toolchain Dependencies
info "Verifying required toolchain packages..."
MISSING_PKGS=()

for pkg in clang llvm bpftool libbpf-dev make gcc pkg-config git curl; do
    if ! command -v "$pkg" &>/dev/null && ! dpkg -s "$pkg" &>/dev/null 2>&1; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    warn "The following packages are missing: ${MISSING_PKGS[*]}"
    info "Installing dependencies via apt-get..."
    sudo apt-get update
    sudo apt-get install -y \
        clang \
        llvm \
        libbpf-dev \
        linux-tools-common \
        linux-tools-generic \
        make \
        gcc \
        pkg-config \
        git \
        curl
else
    ok "All system build tools are present."
fi

# 4. Check bpftool availability
if ! command -v bpftool &>/dev/null; then
    # Try linux-tools specific binary if available
    TOOL_PATH=$(find /usr/lib/linux-tools/ -name bpftool 2>/dev/null | head -n 1 || true)
    if [ -n "$TOOL_PATH" ] && [ -x "$TOOL_PATH" ]; then
        info "Found bpftool at ${TOOL_PATH}, linking to /usr/local/bin/bpftool..."
        sudo ln -sf "$TOOL_PATH" /usr/local/bin/bpftool
    else
        warn "bpftool binary not directly found on PATH. Install bpftool or linux-tools-$(uname -r)."
    fi
fi

# 5. Check Go Installation
info "Checking Go toolchain (Go 1.22+ required)..."
if command -v go &>/dev/null; then
    GO_VER=$(go version | awk '{print $3}')
    ok "Go is installed: ${GO_VER}"
else
    warn "Go is not installed or not in PATH."
    info "To install Go 1.22+: visit https://go.dev/dl/ or run:"
    info "  curl -OL https://go.dev/dl/go1.22.4.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz"
fi

# 6. Extract vmlinux.h if BTF is present and bpftool exists
if [ -f "/sys/kernel/btf/vmlinux" ] && command -v bpftool &>/dev/null; then
    info "Generating fresh vmlinux.h from running kernel BTF..."
    mkdir -p bpf/headers
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
    ok "vmlinux.h successfully updated."
fi

echo -e "\n${GREEN}${BOLD}✓ Environment verification complete.${NC}\n"
