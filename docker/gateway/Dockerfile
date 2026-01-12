FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Install protobuf compiler
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY services/Cargo.toml services/Cargo.lock ./
COPY services/common ./common
COPY services/proto ./proto
COPY services/gateway ./gateway
COPY proto ../proto

# Build the gateway service
RUN cargo build --release --package pistonprotection-gateway

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pistonprotection-gateway /usr/local/bin/

EXPOSE 8080 9090 9091

USER 1000:1000

ENTRYPOINT ["/usr/local/bin/pistonprotection-gateway"]
