# Installation Guide

This guide covers the installation of PistonProtection in various environments.

## Prerequisites

### System Requirements

- **Kubernetes**: 1.28+ (k0s, k3s, EKS, GKE, AKS)
- **Helm**: 3.x
- **CNI**: Cilium 1.14+ (recommended) or any CNI with eBPF support
- **Kernel**: Linux 5.10+ with BTF support

### Worker Node Requirements

Worker nodes that run XDP/eBPF filters need:
- Linux kernel 5.10+ with BTF (BPF Type Format)
- Network interface cards that support XDP
- CAP_BPF and CAP_NET_ADMIN capabilities

### Hardware Recommendations

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Control Plane CPU | 2 cores | 4 cores |
| Control Plane RAM | 4 GB | 8 GB |
| Worker CPU | 2 cores | 8 cores |
| Worker RAM | 2 GB | 8 GB |
| Worker Network | 1 Gbps | 10 Gbps+ |

## Quick Installation

### Using Helm

```bash
# Add the PistonProtection Helm repository
helm repo add pistonprotection https://charts.pistonprotection.io
helm repo update

# Create namespace
kubectl create namespace pistonprotection

# Install with default configuration
helm install pistonprotection pistonprotection/pistonprotection \
  --namespace pistonprotection

# Wait for pods to be ready
kubectl -n pistonprotection get pods -w
```

### Custom Installation

Create a `values.yaml` file with your configuration:

```yaml
# values.yaml
global:
  storageClass: "fast-storage"

gateway:
  replicaCount: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi

worker:
  nodeSelector:
    pistonprotection.io/worker: "true"
  resources:
    requests:
      cpu: 1000m
      memory: 1Gi

postgresql:
  enabled: true
  auth:
    postgresPassword: "your-secure-password"
    password: "your-secure-password"

redis:
  enabled: true
  auth:
    password: "your-secure-password"

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: protect.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
          service: frontend
        - path: /api
          pathType: Prefix
          service: gateway
  tls:
    - secretName: pistonprotection-tls
      hosts:
        - protect.yourdomain.com
```

Install with custom values:

```bash
helm install pistonprotection pistonprotection/pistonprotection \
  --namespace pistonprotection \
  -f values.yaml
```

## Cilium Setup

PistonProtection works best with Cilium CNI. Here's the recommended configuration:

```bash
cilium install --version "1.16.0" \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="${KUBERNETES_API_SERVER}" \
  --set k8sServicePort=6443 \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set l2announcements.enabled=true \
  --set encryption.enabled=true \
  --set encryption.type=wireguard \
  --set encryption.nodeEncryption=true
```

## Worker Node Setup

### Label Worker Nodes

Mark nodes that should run the XDP filters:

```bash
kubectl label nodes <node-name> pistonprotection.io/worker=true
```

### Verify eBPF Support

Check kernel support:

```bash
# Check kernel version
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check XDP support
ip link show
```

## Database Setup

### Using Built-in PostgreSQL

The chart includes PostgreSQL by default. For production, configure persistence:

```yaml
postgresql:
  enabled: true
  primary:
    persistence:
      enabled: true
      size: 50Gi
      storageClass: "fast-storage"
```

### External PostgreSQL

```yaml
postgresql:
  enabled: false
  external:
    host: "your-postgres-host.com"
    port: 5432
    database: "pistonprotection"
    username: "pistonprotection"
    password: "your-password"
```

## Redis Setup

### Using Built-in Redis

```yaml
redis:
  enabled: true
  master:
    persistence:
      enabled: true
      size: 10Gi
```

### External Redis

```yaml
redis:
  enabled: false
  external:
    host: "your-redis-host.com"
    port: 6379
    password: "your-password"
```

## Verification

### Check Installation

```bash
# Check all pods are running
kubectl -n pistonprotection get pods

# Check services
kubectl -n pistonprotection get svc

# Check CRDs are installed
kubectl get crd | grep pistonprotection

# View operator logs
kubectl -n pistonprotection logs -l app.kubernetes.io/component=operator -f
```

### Access Dashboard

```bash
# Port forward the frontend
kubectl -n pistonprotection port-forward svc/pistonprotection-frontend 3000:3000

# Access at http://localhost:3000
```

## Upgrading

```bash
# Update Helm repository
helm repo update

# Upgrade the release
helm upgrade pistonprotection pistonprotection/pistonprotection \
  --namespace pistonprotection \
  -f values.yaml

# Verify upgrade
kubectl -n pistonprotection rollout status deployment/pistonprotection-gateway
```

## Uninstallation

```bash
# Uninstall the Helm release
helm uninstall pistonprotection --namespace pistonprotection

# Delete CRDs (optional, removes all custom resources)
kubectl delete crd ddosprotections.pistonprotection.io
kubectl delete crd filterrules.pistonprotection.io

# Delete namespace
kubectl delete namespace pistonprotection
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod events
kubectl -n pistonprotection describe pod <pod-name>

# Check logs
kubectl -n pistonprotection logs <pod-name>
```

### Worker Not Loading eBPF

```bash
# Check worker logs
kubectl -n pistonprotection logs -l app.kubernetes.io/component=worker

# Verify bpf filesystem is mounted
kubectl -n pistonprotection exec -it <worker-pod> -- mount | grep bpf

# Check capabilities
kubectl -n pistonprotection exec -it <worker-pod> -- capsh --print
```

### Database Connection Issues

```bash
# Test database connectivity
kubectl -n pistonprotection exec -it <gateway-pod> -- \
  psql -h pistonprotection-postgresql -U pistonprotection -d pistonprotection
```

## Next Steps

- [Configuration Reference](configuration.md) - Detailed configuration options
- [API Documentation](api.md) - REST and gRPC API reference
- [Creating Protection Rules](filters.md) - Set up DDoS protection
