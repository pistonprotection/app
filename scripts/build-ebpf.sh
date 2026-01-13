#!/usr/bin/env bash
# =============================================================================
# PistonProtection - Build eBPF Programs
# =============================================================================
#
# This script builds the XDP/eBPF programs required for packet filtering.
#
# Usage:
#   ./scripts/build-ebpf.sh             # Build in debug mode
#   ./scripts/build-ebpf.sh --release   # Build in release mode
#   ./scripts/build-ebpf.sh --install   # Install to /opt/pistonprotection/ebpf
#
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
EBPF_DIR="$ROOT_DIR/ebpf"

# Default options
RELEASE_MODE=false
INSTALL=false
INSTALL_DIR="/opt/pistonprotection/ebpf"
NIGHTLY_TOOLCHAIN="nightly-2026-01-10"

# Print colored message
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print help
print_help() {
    cat << EOF
PistonProtection eBPF Build Script

Usage: $0 [OPTIONS]

Options:
    --release           Build in release mode (optimized)
    --install           Install eBPF programs to $INSTALL_DIR
    --install-dir DIR   Custom installation directory
    --toolchain TC      Nightly toolchain version (default: $NIGHTLY_TOOLCHAIN)
    --help, -h          Show this help message

Requirements:
    - Rust nightly toolchain with rust-src component
    - LLVM and Clang
    - bpf-linker

Examples:
    $0                          # Build debug
    $0 --release                # Build release
    $0 --release --install      # Build and install
EOF
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --release)
                RELEASE_MODE=true
                shift
                ;;
            --install)
                INSTALL=true
                shift
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --toolchain)
                NIGHTLY_TOOLCHAIN="$2"
                shift 2
                ;;
            --help|-h)
                print_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done
}

# Check and install dependencies
check_dependencies() {
    log_info "Checking eBPF build dependencies..."

    # Check for Rust
    if ! command -v rustup &> /dev/null; then
        log_error "rustup not found. Please install Rust via rustup."
        exit 1
    fi

    # Check/install nightly toolchain
    if ! rustup show | grep -q "$NIGHTLY_TOOLCHAIN"; then
        log_info "Installing Rust $NIGHTLY_TOOLCHAIN toolchain..."
        rustup install "$NIGHTLY_TOOLCHAIN"
    fi

    # Check/install rust-src component
    if ! rustup component list --toolchain "$NIGHTLY_TOOLCHAIN" | grep -q "rust-src (installed)"; then
        log_info "Installing rust-src component..."
        rustup component add rust-src --toolchain "$NIGHTLY_TOOLCHAIN"
    fi

    # Check for LLVM/Clang
    if ! command -v clang &> /dev/null; then
        log_error "clang not found. Please install LLVM/Clang."
        echo "  Ubuntu/Debian: sudo apt install llvm clang"
        echo "  Fedora/RHEL:   sudo dnf install llvm clang"
        echo "  macOS:         brew install llvm"
        exit 1
    fi

    # Check/install bpf-linker
    if ! command -v bpf-linker &> /dev/null; then
        log_info "Installing bpf-linker..."

        # bpf-linker requires specific LLVM setup
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS specific
            export LLVM_SYS_170_PREFIX="$(brew --prefix llvm)"
        fi

        cargo +"$NIGHTLY_TOOLCHAIN" install bpf-linker --locked
    fi

    log_success "All dependencies satisfied"
}

# Build eBPF programs
build_ebpf() {
    log_info "Building eBPF programs..."

    cd "$EBPF_DIR"

    local cargo_args=(
        "+$NIGHTLY_TOOLCHAIN"
        "build"
        "--target" "bpfel-unknown-none"
        "-Z" "build-std=core"
    )

    if $RELEASE_MODE; then
        cargo_args+=("--release")
        log_info "Building in release mode..."
    else
        log_info "Building in debug mode..."
    fi

    # Set environment for BPF target
    export CARGO_CFG_BPF_TARGET_ARCH="x86_64"

    # Run build
    cargo "${cargo_args[@]}"

    # Determine output directory
    local output_dir="$EBPF_DIR/target/bpfel-unknown-none"
    if $RELEASE_MODE; then
        output_dir="$output_dir/release"
    else
        output_dir="$output_dir/debug"
    fi

    # List built programs
    log_info "Built eBPF programs:"
    for prog in "$output_dir"/*; do
        if [[ -f "$prog" ]] && file "$prog" | grep -q "BPF\|ELF"; then
            local size
            size=$(du -h "$prog" | cut -f1)
            echo "  - $(basename "$prog") ($size)"
        fi
    done

    log_success "eBPF programs built successfully"
}

# Install eBPF programs
install_ebpf() {
    log_info "Installing eBPF programs to $INSTALL_DIR..."

    # Determine source directory
    local source_dir="$EBPF_DIR/target/bpfel-unknown-none"
    if $RELEASE_MODE; then
        source_dir="$source_dir/release"
    else
        source_dir="$source_dir/debug"
    fi

    # Create installation directory
    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_info "Creating installation directory..."
        sudo mkdir -p "$INSTALL_DIR"
    fi

    # Copy programs
    local installed=0
    for prog in "$source_dir"/*; do
        if [[ -f "$prog" ]] && file "$prog" | grep -q "BPF\|ELF"; then
            local name
            name=$(basename "$prog")
            sudo cp "$prog" "$INSTALL_DIR/$name"
            sudo chmod 644 "$INSTALL_DIR/$name"
            log_info "Installed: $name"
            ((installed++))
        fi
    done

    if [[ $installed -eq 0 ]]; then
        log_warning "No eBPF programs found to install"
    else
        log_success "Installed $installed eBPF program(s) to $INSTALL_DIR"
    fi
}

# Verify eBPF programs
verify_programs() {
    log_info "Verifying eBPF programs..."

    local source_dir="$EBPF_DIR/target/bpfel-unknown-none"
    if $RELEASE_MODE; then
        source_dir="$source_dir/release"
    else
        source_dir="$source_dir/debug"
    fi

    # Check with llvm-objdump if available
    if command -v llvm-objdump &> /dev/null; then
        for prog in "$source_dir"/*; do
            if [[ -f "$prog" ]] && file "$prog" | grep -q "BPF\|ELF"; then
                local name
                name=$(basename "$prog")
                log_info "Sections in $name:"
                llvm-objdump -h "$prog" 2>/dev/null | grep -E "^\s+[0-9]+" | awk '{print "  - " $2 " (" $3 " bytes)"}'
            fi
        done
    fi

    log_success "eBPF programs verified"
}

# Main function
main() {
    parse_args "$@"

    log_info "PistonProtection eBPF Build"
    log_info "Toolchain: $NIGHTLY_TOOLCHAIN"

    check_dependencies
    build_ebpf
    verify_programs

    if $INSTALL; then
        install_ebpf
    fi

    echo ""
    log_success "eBPF build completed!"

    if ! $INSTALL; then
        echo ""
        echo "To install the programs, run:"
        echo "  $0 --release --install"
    fi
}

main "$@"
