# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PistonProtection is an enterprise-grade, self-hostable DDoS protection platform. It provides Layer 4 and Layer 7 filtering using eBPF/XDP for line-rate packet processing, deployed on Kubernetes with Cilium CNI.

## Build and Development Commands

### Quick Start
```bash
make deps      # Install Rust toolchain + frontend dependencies
make dev       # Start local development environment (docker-compose)
```

### Build Commands
```bash
make build                  # Build all components (debug)
make build-release          # Build all components (release)
make build-services         # Build Rust services only
make build-ebpf             # Build eBPF programs
make build-frontend         # Build frontend (pnpm install && pnpm build)
```

### Test Commands
```bash
make test                   # Run all tests
make test-unit              # Run unit tests only
make test-integration       # Run integration tests
make test-services          # Run Rust service tests (cd services && cargo test)
make test-operator          # Run operator tests (cd operator && cargo test)
make test-frontend          # Run frontend tests (cd frontend && pnpm test)
```

### Lint and Format
```bash
make lint                   # Run all linters
make lint-rust              # Rust: cargo clippy --all-targets --all-features -- -D warnings
make lint-frontend          # Frontend: pnpm lint
make format                 # Format all code (cargo fmt + prettier)
```

### Docker and Helm
```bash
make docker-build           # Build all Docker images
make helm-lint              # Lint Helm chart
make helm-template          # Render Helm templates
```

## Architecture

### Backend Services (Rust workspace at `/services`)
- **gateway** - API Gateway, HTTP/gRPC routing and proxy
- **config-mgr** - Configuration management and distribution
- **metrics** - Metrics collection and aggregation
- **auth** - Authentication service
- **worker** - XDP/eBPF packet filtering worker
- **common** - Shared libraries
- **proto** - Protobuf/gRPC definitions

Services communicate via gRPC with protobuf. Key dependencies: tokio, tonic, sqlx (Postgres), redis, aya (eBPF).

### Kubernetes Operator (`/operator`)
Standalone Rust project using `kube-rs` for Kubernetes reconciliation. Manages custom CRDs for Backend resources.

### eBPF Programs (`/ebpf`)
XDP filter programs written in Rust using aya. Compiled with `cargo +nightly build --target bpfel-unknown-none -Z build-std=core`.

### Frontend (`/frontend`)
TanStack Start (React meta-framework) with:
- shadcn/ui (Base UI theme) for components
- TanStack Router for routing
- TanStack Query for data fetching
- Tailwind CSS v4 for styling
- Vite for bundling

Commands: `pnpm dev` (port 3000), `pnpm build`, `pnpm lint`

### Infrastructure
- **Helm chart** at `/charts/pistonprotection`
- **Docker configs** at `/docker`
- **Observability stack**: Prometheus, Grafana, Loki at `/observability`

## Key Patterns

### Rust Services
- Workspace-level dependencies in `services/Cargo.toml`
- gRPC services with tonic, health checks via `tonic-health`
- Postgres via sqlx, Redis via deadpool-redis
- Structured logging with tracing, metrics with prometheus crate

### Frontend
- Use pnpm (not npm/yarn)
- shadcn/ui components from `@base-ui/react`
- File-based routing in `src/routes/`

### Commit Messages
Follow Conventional Commits: `<type>(<scope>): <description>`
Types: feat, fix, docs, style, refactor, test, chore

## Protocol Support
L7 filtering for: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), Minecraft Java Edition, Minecraft Bedrock Edition (RakNet), generic TCP/UDP
