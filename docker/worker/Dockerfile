FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Install protobuf compiler and eBPF tools
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    llvm \
    clang \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY services/Cargo.toml services/Cargo.lock ./
COPY services/common ./common
COPY services/proto ./proto
COPY services/worker ./worker
COPY proto ../proto

# Build the worker service
RUN cargo build --release --package pistonprotection-worker

# Build eBPF programs
FROM rust:1.82-bookworm AS ebpf-builder

WORKDIR /app

RUN rustup install nightly && \
    rustup component add rust-src --toolchain nightly

RUN cargo +nightly install bpf-linker

COPY ebpf ./ebpf

WORKDIR /app/ebpf

RUN cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libbpf1 \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pistonprotection-worker /usr/local/bin/
COPY --from=ebpf-builder /app/ebpf/target/bpfel-unknown-none/release/*.o /opt/pistonprotection/ebpf/

ENV EBPF_PROGRAMS_PATH=/opt/pistonprotection/ebpf

EXPOSE 8080 9090

# Worker needs to run as root for eBPF
USER 0:0

ENTRYPOINT ["/usr/local/bin/pistonprotection-worker"]
