FROM rust:1.82-bookworm AS builder

WORKDIR /app

# Copy operator source
COPY operator/Cargo.toml operator/Cargo.lock ./
COPY operator/src ./src

# Build the operator
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pistonprotection-operator /usr/local/bin/

EXPOSE 8080

USER 1000:1000

ENTRYPOINT ["/usr/local/bin/pistonprotection-operator"]
