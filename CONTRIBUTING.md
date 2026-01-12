# Contributing to PistonProtection

Thank you for your interest in contributing to PistonProtection! This guide will help you get started.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Rust 1.75+ (stable and nightly for eBPF)
- Node.js 20+
- pnpm 9+
- Docker
- Kubernetes (minikube, k3d, or kind for local development)
- Helm 3.x

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/pistonprotection/pistonprotection.git
   cd pistonprotection
   ```

2. **Install Rust toolchain**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup install nightly
   rustup component add rust-src --toolchain nightly
   cargo install bpf-linker
   ```

3. **Install Node.js dependencies**
   ```bash
   cd frontend
   pnpm install
   ```

4. **Start local Kubernetes cluster**
   ```bash
   k3d cluster create pistonprotection --api-port 6443
   ```

5. **Install development dependencies**
   ```bash
   helm repo add bitnami https://charts.bitnami.com/bitnami
   helm install postgresql bitnami/postgresql -n pistonprotection --create-namespace
   helm install redis bitnami/redis -n pistonprotection
   ```

### Running Services Locally

**Backend services:**
```bash
cd services
cargo run --package pistonprotection-gateway
```

**Frontend:**
```bash
cd frontend
pnpm dev
```

**eBPF programs (requires root):**
```bash
cd ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core
```

## Development Workflow

### Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions/updates

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `style` - Formatting
- `refactor` - Code restructuring
- `test` - Tests
- `chore` - Maintenance

Example:
```
feat(worker): add QUIC protocol support

Implemented QUIC protocol detection and filtering in the XDP layer.
Supports connection ID validation and version negotiation.

Closes #123
```

### Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add/update tests
5. Run lints and tests
6. Submit a pull request

#### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Commit messages follow conventions
- [ ] CI passes

## Code Style

### Rust

Follow the [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/):

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

### TypeScript/React

Use Prettier and ESLint:

```bash
pnpm lint
pnpm format
```

### Commit Hooks

We use pre-commit hooks. Install them:

```bash
cargo install cargo-husky
```

## Testing

### Unit Tests

```bash
# Rust
cargo test --all-features

# Frontend
pnpm test
```

### Integration Tests

```bash
# Start test environment
./scripts/test-env.sh up

# Run integration tests
cargo test --package integration-tests

# Cleanup
./scripts/test-env.sh down
```

### E2E Tests

```bash
cd frontend
pnpm test:e2e
```

## Architecture

### Services

| Service | Purpose |
|---------|---------|
| gateway | API gateway, HTTP/gRPC routing |
| worker | XDP/eBPF packet filtering |
| config-mgr | Configuration distribution |
| metrics | Metrics aggregation |
| operator | Kubernetes reconciliation |

### eBPF Programs

| Program | Purpose |
|---------|---------|
| xdp_filter | Main packet filtering |
| xdp_ratelimit | Rate limiting |
| xdp_minecraft | Minecraft protocol validation |

### Frontend

- TanStack Start (React meta-framework)
- TanStack Query (data fetching)
- TanStack Form (form handling)
- shadcn/ui (UI components)

## Documentation

- Keep documentation up to date with code changes
- Use clear, concise language
- Include code examples where helpful
- Update API documentation for endpoint changes

## Release Process

1. Update version in `Cargo.toml` and `package.json`
2. Update `CHANGELOG.md`
3. Create a release PR
4. After merge, tag the release
5. CI automatically builds and publishes

## Getting Help

- [GitHub Issues](https://github.com/pistonprotection/pistonprotection/issues)
- [Discord](https://discord.gg/pistonprotection)
- [Documentation](https://docs.pistonprotection.io)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
