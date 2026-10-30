# syntax=docker/dockerfile:1.7

# =============================================================================
# PistonProtection Worker Service
# Multi-stage build with eBPF support
# =============================================================================

ARG DEBIAN_VERSION=bookworm

# -----------------------------------------------------------------------------
# Stage 1: Chef - Dependency caching with nightly Rust
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION} AS chef

# Install rustup and nightly toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly-2026-01-10 \
    && rustup component add rustfmt clippy

RUN cargo install cargo-chef --locked
WORKDIR /app

# -----------------------------------------------------------------------------
# Stage 2: Planner - Create recipe for dependencies
# -----------------------------------------------------------------------------
FROM chef AS planner

COPY services/Cargo.toml services/Cargo.lock ./
COPY services/common ./common
COPY services/proto ./proto
COPY services/gateway ./gateway
COPY services/config-mgr ./config-mgr
COPY services/metrics ./metrics
COPY services/worker ./worker
COPY services/auth ./auth
COPY proto ../proto

RUN cargo chef prepare --recipe-path recipe.json

# -----------------------------------------------------------------------------
# Stage 3: Builder - Build dependencies and application
# -----------------------------------------------------------------------------
FROM chef AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    libprotobuf-dev \
    pkg-config \
    libssl-dev \
    llvm \
    clang \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Build dependencies (cached)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source and build application
COPY services/Cargo.toml services/Cargo.lock ./
COPY services/common ./common
COPY services/proto ./proto
COPY services/gateway ./gateway
COPY services/config-mgr ./config-mgr
COPY services/metrics ./metrics
COPY services/worker ./worker
COPY services/auth ./auth
COPY proto ../proto

# Build arguments for versioning
ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown

RUN cargo build --release --package pistonprotection-worker && \
    strip /app/target/release/worker

# -----------------------------------------------------------------------------
# Stage 4: eBPF Builder - Build eBPF programs
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION} AS ebpf-builder

WORKDIR /app

# Install rustup and nightly toolchain with rust-src (required for -Z build-std)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    build-essential \
    zstd \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly-2026-01-10 \
    && rustup component add rust-src

# Install the published static binary to avoid coupling the build to system LLVM.
ARG BPF_LINKER_VERSION=0.12.0
ARG TARGETARCH
RUN case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
        amd64) bpf_linker_arch=x86_64 ;; \
        arm64) bpf_linker_arch=aarch64 ;; \
        *) echo "Unsupported architecture: ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL \
        "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-${bpf_linker_arch}-unknown-linux-musl.tar.zst" \
        -o /tmp/bpf-linker.tar.zst \
    && tar --zstd -xf /tmp/bpf-linker.tar.zst -C /usr/local/cargo/bin \
    && rm /tmp/bpf-linker.tar.zst \
    && bpf-linker --version

# Copy eBPF source
COPY ebpf ./ebpf

WORKDIR /app/ebpf

# Build eBPF programs (toolchain is already nightly-2026-01-10)
RUN cargo build \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

# -----------------------------------------------------------------------------
# Stage 5: Runtime - Minimal production image with eBPF support
# -----------------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION}-slim AS runtime

# Install runtime dependencies for eBPF
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libbpf1 \
    libelf1 \
    iproute2 \
    ethtool \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create directories
RUN mkdir -p /opt/pistonprotection/ebpf /var/lib/pistonprotection

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/worker /usr/local/bin/

# Copy eBPF programs
COPY --from=ebpf-builder /app/ebpf/target/bpfel-unknown-none/release/xdp_filter /opt/pistonprotection/ebpf/
COPY --from=ebpf-builder /app/ebpf/target/bpfel-unknown-none/release/xdp_ratelimit /opt/pistonprotection/ebpf/
COPY --from=ebpf-builder /app/ebpf/target/bpfel-unknown-none/release/xdp_minecraft /opt/pistonprotection/ebpf/

# Metadata
ARG VERSION=0.0.0
ARG GIT_COMMIT=unknown

LABEL org.opencontainers.image.title="PistonProtection Worker" \
      org.opencontainers.image.description="XDP/eBPF worker for PistonProtection DDoS protection platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.vendor="PistonProtection" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/pistonprotection/app"

# Expose ports
# 8080 - HTTP API
# 9090 - gRPC API
# 9091 - Metrics
EXPOSE 8080 9090 9091

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Environment variables
ENV RUST_LOG=info \
    RUST_BACKTRACE=0 \
    EBPF_PROGRAMS_PATH=/opt/pistonprotection/ebpf

# Worker needs CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_BPF for eBPF operations
# Must run as root for eBPF
USER root

ENTRYPOINT ["/usr/local/bin/worker"]
