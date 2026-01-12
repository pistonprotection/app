# PistonProtection

**Enterprise-Grade DDoS Protection Platform**

PistonProtection is a comprehensive, self-hostable DDoS protection solution built on modern cloud-native technologies. It provides advanced Layer 4 and Layer 7 filtering using eBPF/XDP for line-rate packet processing.

## Features

### Protection Capabilities
- **Layer 4 Protection**: TCP, UDP, QUIC flood mitigation
- **Layer 7 Protocol Filtering**:
  - HTTP/1.1, HTTP/2, HTTP/3 (QUIC)
  - Minecraft Java Edition
  - Minecraft Bedrock Edition (RakNet)
  - Generic TCP/UDP applications
- **Adaptive Rate Limiting**: Per-IP, per-subnet, and global rate limiting
- **GeoIP Blocking**: Block or allow traffic by country
- **Bot Detection**: Advanced challenge-response for L7 protocols

### Infrastructure
- **eBPF/XDP Filtering**: Line-rate packet processing at the NIC driver level
- **Kubernetes Native**: Built on Cilium with custom operators
- **Horizontal Scaling**: Automatic worker node scaling based on traffic
- **Multi-Region**: Support for anycast routing and global load balancing

### Management Dashboard
- **Real-Time Metrics**: Live attack visualization and traffic analytics
- **Configuration UI**: Easy-to-use protection rule management
- **Multi-Tenant**: Organization-based access control
- **API Access**: Full REST and gRPC API for automation

### Observability
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Pre-built dashboards for traffic analysis
- **Loki**: Centralized log aggregation

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Internet Traffic                          │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Anycast Edge Network                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Worker    │  │   Worker    │  │   Worker    │    ...       │
│  │   Node 1    │  │   Node 2    │  │   Node 3    │              │
│  │  (XDP/eBPF) │  │  (XDP/eBPF) │  │  (XDP/eBPF) │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Control Plane (Kubernetes)                    │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │    Gateway     │  │  Config Mgr    │  │   Metrics      │     │
│  │    Service     │  │    Service     │  │   Collector    │     │
│  └────────────────┘  └────────────────┘  └────────────────┘     │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │   PostgreSQL   │  │     Redis      │  │   Prometheus   │     │
│  └────────────────┘  └────────────────┘  └────────────────┘     │
│                                                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │    Grafana     │  │     Loki       │  │   Dashboard    │     │
│  └────────────────┘  └────────────────┘  └────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Kubernetes cluster (k0s, k3s, or managed)
- Helm 3.x
- kubectl configured

### Installation

```bash
# Add PistonProtection Helm repository
helm repo add pistonprotection https://charts.pistonprotection.io
helm repo update

# Install with default configuration
helm install pistonprotection pistonprotection/pistonprotection \
  --namespace pistonprotection \
  --create-namespace

# Install with custom values
helm install pistonprotection pistonprotection/pistonprotection \
  --namespace pistonprotection \
  --create-namespace \
  -f values.yaml
```

### Cilium Requirements

PistonProtection requires Cilium as the CNI with specific configuration:

```bash
cilium install --version "1.16.0" \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="${CONTROLLER_IP}" \
  --set k8sServicePort=6443 \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set l2announcements.enabled=true \
  --set cni.chainingMode=portmap \
  --set cni.externalRouting=true \
  --set encryption.enabled=true \
  --set encryption.type=wireguard \
  --set encryption.nodeEncryption=true \
  --set cni.enableRouteMTUForCNIChaining=true \
  --set MTU=1366
```

## Project Structure

```
pistonprotection/
├── frontend/           # Dashboard (TanStack Start + shadcn/ui)
├── services/           # Rust backend services
│   ├── gateway/        # API Gateway and proxy
│   ├── config-mgr/     # Configuration management
│   ├── metrics/        # Metrics collection and aggregation
│   ├── auth/           # Authentication service
│   └── common/         # Shared libraries
├── ebpf/               # eBPF/XDP programs
│   ├── filters/        # Protocol-specific filters
│   ├── maps/           # eBPF maps definitions
│   └── loader/         # Userspace loader
├── operator/           # Kubernetes operator
├── proto/              # Protobuf definitions
├── charts/             # Helm charts
├── docs/               # Documentation
└── deploy/             # Deployment configurations
```

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Protocol Filters](docs/filters.md)
- [Development Guide](docs/development.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Support

- [Discord Community](https://discord.gg/pistonprotection)
- [GitHub Issues](https://github.com/PistonProtection/pistonprotection/issues)
- [Documentation](https://docs.pistonprotection.io)
