# Repository instructions

These instructions apply to coding agents working in this repository.

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

## React conventions

- Use PascalCase for React component names. Match the existing component filename convention.
- Use kebab-case for new hook and utility filenames, unless this repository documents another convention.
- Use stable domain identities as React keys. Do not use array indexes as keys.
- Use an existing `generateN` helper or stable placeholder IDs for fixed skeleton slots.
- Keep page structure, headings, navigation, labels, and independent content mounted while data loads.
- Show skeletons only for unresolved values, rows, and permission-dependent actions. Do not block a page on its slowest query.

## Tailwind spacing

- Use `gap-*` utilities for spacing between elements. Do not use `space-*` utilities.

## shadcn/ui

- For shadcn/ui work, use the `shadcn` skill and component documentation.
- Compose existing shadcn/ui components before writing custom primitives. Use `Field`, `InputGroup`, and `Item` where appropriate.
- Fix application consumers before changing `components/ui`. Change a shared primitive only for a demonstrated component defect.

## Design skills

- For visual design work, use `frontend-design` and `uncodixfy`.

## Drizzle migrations

- Edit the schema referenced by `frontend/drizzle.config.ts` first.
- From `frontend/`, run `pnpm exec drizzle-kit generate --name <migration-name>`.
- Treat `frontend/drizzle/` SQL and metadata as generated output. Do not hand-edit them.
- Commit generated migration artifacts together, exactly as Drizzle produces them.
- Check the deployment workflow before applying migrations. Do not assume a push applies them automatically.

## Organization access

- Resolve application access from explicit organization IDs or slugs.
- Do not use Better Auth active-organization session state to determine application access.

## Fumadocs content

- Keep collection paths and front matter consistent with `frontend/source.config.ts`.
- Use `.md` for plain content and `.mdx` when imports or React components are needed.
- Use the front-matter title as the page heading. Start body sections at `##`.
- Register shared MDX components through the existing component registry. Extract reusable components instead of long inline JSX.
- Use registered Fumadocs components for callouts, related links, tabs, steps, FAQs, and API tables.
- Give each `Tab` an explicit `value`. Use stable heading anchors when other pages link to them.
- Use descriptive links, language-tagged code fences, and useful image alt text.
- Preview changed pages and check links, code blocks, tables, and images before publishing.
- For YouTube embeds, reuse the existing component when available. Use `/embed/VIDEO_ID` with a clear title.
- Keep video embeds responsive at 16:9. Include a text summary and do not autoplay.
