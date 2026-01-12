#!/usr/bin/env bash
# =============================================================================
# PistonProtection - Minikube Deployment Script
# =============================================================================
#
# This script deploys PistonProtection to a local Minikube cluster for testing.
#
# Prerequisites:
#   - minikube installed and configured
#   - kubectl installed
#   - helm 3.x installed
#   - docker installed
#
# Usage:
#   ./scripts/minikube-deploy.sh setup      # Create minikube cluster
#   ./scripts/minikube-deploy.sh deploy     # Deploy PistonProtection
#   ./scripts/minikube-deploy.sh test       # Run integration tests
#   ./scripts/minikube-deploy.sh teardown   # Delete everything
#   ./scripts/minikube-deploy.sh status     # Show deployment status
#   ./scripts/minikube-deploy.sh logs       # View logs
#
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Configuration
MINIKUBE_PROFILE="pistonprotection"
MINIKUBE_CPUS="${MINIKUBE_CPUS:-4}"
MINIKUBE_MEMORY="${MINIKUBE_MEMORY:-8192}"
MINIKUBE_DISK="${MINIKUBE_DISK:-40g}"
MINIKUBE_DRIVER="${MINIKUBE_DRIVER:-docker}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-1.29.0}"

NAMESPACE="pistonprotection"
RELEASE_NAME="pp"
CHART_PATH="$ROOT_DIR/charts/pistonprotection"

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

log_step() {
    echo -e "\n${CYAN}==> $1${NC}"
}

# Print help
print_help() {
    cat << EOF
PistonProtection Minikube Deployment Script

Usage: $0 COMMAND [OPTIONS]

Commands:
    setup           Create and configure minikube cluster
    deploy          Deploy PistonProtection to cluster
    test            Run integration tests
    teardown        Delete minikube cluster
    status          Show deployment status
    logs            View component logs
    dashboard       Open Kubernetes dashboard
    shell SERVICE   Open shell in pod
    port-forward    Forward ports for local access

Options:
    --profile NAME      Minikube profile name (default: $MINIKUBE_PROFILE)
    --cpus N           Number of CPUs (default: $MINIKUBE_CPUS)
    --memory MB        Memory in MB (default: $MINIKUBE_MEMORY)
    --driver DRIVER    Minikube driver (default: $MINIKUBE_DRIVER)

Environment Variables:
    MINIKUBE_CPUS      Number of CPUs for minikube
    MINIKUBE_MEMORY    Memory in MB for minikube
    MINIKUBE_DISK      Disk size for minikube
    MINIKUBE_DRIVER    Minikube driver (docker, kvm2, virtualbox, etc.)
    KUBERNETES_VERSION Kubernetes version to use

Examples:
    $0 setup                            # Setup minikube cluster
    $0 deploy                           # Deploy PistonProtection
    $0 test                             # Run integration tests
    $0 logs gateway                     # View gateway logs
    $0 shell gateway                    # Shell into gateway pod
    $0 port-forward                     # Forward all ports
    $0 teardown                         # Delete everything

Port Forwards (after running port-forward):
    Frontend:    http://localhost:3000
    Gateway:     http://localhost:8080
    Grafana:     http://localhost:3001
    Prometheus:  http://localhost:9099
EOF
}

# Check required tools
check_prerequisites() {
    log_step "Checking prerequisites"

    local missing=0

    for cmd in minikube kubectl helm docker; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "$cmd not found. Please install it."
            missing=1
        else
            echo -e "  ${GREEN}[ok]${NC} $cmd"
        fi
    done

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

# Setup minikube cluster
cmd_setup() {
    check_prerequisites

    log_step "Creating minikube cluster: $MINIKUBE_PROFILE"

    # Check if cluster already exists
    if minikube status -p "$MINIKUBE_PROFILE" &> /dev/null; then
        log_warning "Cluster $MINIKUBE_PROFILE already exists"
        read -p "Delete and recreate? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            minikube delete -p "$MINIKUBE_PROFILE"
        else
            log_info "Using existing cluster"
            minikube start -p "$MINIKUBE_PROFILE"
            return 0
        fi
    fi

    # Create cluster
    log_info "Starting minikube with $MINIKUBE_CPUS CPUs, ${MINIKUBE_MEMORY}MB RAM"

    minikube start \
        -p "$MINIKUBE_PROFILE" \
        --driver="$MINIKUBE_DRIVER" \
        --cpus="$MINIKUBE_CPUS" \
        --memory="$MINIKUBE_MEMORY" \
        --disk-size="$MINIKUBE_DISK" \
        --kubernetes-version="v$KUBERNETES_VERSION" \
        --container-runtime=containerd \
        --addons=metrics-server,ingress,ingress-dns,storage-provisioner \
        --embed-certs=true \
        --wait=all

    # Set kubectl context
    kubectl config use-context "$MINIKUBE_PROFILE"

    log_step "Installing Cilium CNI"

    # Install Cilium for advanced networking (required for our network policies)
    helm repo add cilium https://helm.cilium.io/ || true
    helm repo update

    helm upgrade --install cilium cilium/cilium \
        --namespace kube-system \
        --set kubeProxyReplacement=disabled \
        --set hostServices.enabled=false \
        --set externalIPs.enabled=true \
        --set nodePort.enabled=true \
        --set hostPort.enabled=true \
        --set bpf.masquerade=false \
        --set image.pullPolicy=IfNotPresent \
        --wait

    log_step "Installing cert-manager"

    # Install cert-manager for TLS
    helm repo add jetstack https://charts.jetstack.io || true
    helm repo update

    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.crds.yaml

    helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace cert-manager \
        --create-namespace \
        --set installCRDs=false \
        --set image.pullPolicy=IfNotPresent \
        --wait

    log_step "Creating namespace and secrets"

    # Create namespace
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # Label namespace for monitoring
    kubectl label namespace "$NAMESPACE" monitoring=enabled --overwrite

    log_success "Minikube cluster ready!"
    echo ""
    echo "Next steps:"
    echo "  1. Build Docker images: $0 build-images"
    echo "  2. Deploy PistonProtection: $0 deploy"
    echo "  3. Run tests: $0 test"
}

# Build Docker images inside minikube
cmd_build_images() {
    log_step "Building Docker images in minikube"

    # Use minikube's docker daemon
    eval $(minikube docker-env -p "$MINIKUBE_PROFILE")

    log_info "Building service images..."

    # Build services
    docker build -t pistonprotection/gateway:dev -f "$ROOT_DIR/docker/Dockerfile.gateway" "$ROOT_DIR"
    docker build -t pistonprotection/worker:dev -f "$ROOT_DIR/docker/Dockerfile.worker" "$ROOT_DIR"
    docker build -t pistonprotection/config-mgr:dev -f "$ROOT_DIR/docker/Dockerfile.config-mgr" "$ROOT_DIR"
    docker build -t pistonprotection/metrics:dev -f "$ROOT_DIR/docker/Dockerfile.metrics" "$ROOT_DIR"
    docker build -t pistonprotection/auth:dev -f "$ROOT_DIR/docker/Dockerfile.auth" "$ROOT_DIR"
    docker build -t pistonprotection/operator:dev -f "$ROOT_DIR/docker/Dockerfile.operator" "$ROOT_DIR"
    docker build -t pistonprotection/frontend:dev -f "$ROOT_DIR/docker/Dockerfile.frontend" "$ROOT_DIR"

    log_success "Docker images built successfully"

    # Reset docker env
    eval $(minikube docker-env -u)
}

# Deploy PistonProtection
cmd_deploy() {
    log_step "Deploying PistonProtection to minikube"

    # Ensure we're using the right context
    kubectl config use-context "$MINIKUBE_PROFILE"

    # Create values file for minikube
    local values_file="$ROOT_DIR/charts/pistonprotection/values-minikube.yaml"

    if [[ ! -f "$values_file" ]]; then
        log_info "Creating minikube values file..."
        cat > "$values_file" << 'EOF'
# PistonProtection Minikube Values
# Optimized for local development and testing

global:
  imagePullPolicy: IfNotPresent
  storageClass: standard

# Use local images
gateway:
  image:
    repository: pistonprotection/gateway
    tag: dev
    pullPolicy: Never
  replicas: 1
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi

worker:
  image:
    repository: pistonprotection/worker
    tag: dev
    pullPolicy: Never
  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 1000m
      memory: 1Gi

configMgr:
  image:
    repository: pistonprotection/config-mgr
    tag: dev
    pullPolicy: Never
  replicas: 1

metrics:
  image:
    repository: pistonprotection/metrics
    tag: dev
    pullPolicy: Never
  replicas: 1

auth:
  image:
    repository: pistonprotection/auth
    tag: dev
    pullPolicy: Never
  replicas: 1

operator:
  image:
    repository: pistonprotection/operator
    tag: dev
    pullPolicy: Never
  replicas: 1

frontend:
  image:
    repository: pistonprotection/frontend
    tag: dev
    pullPolicy: Never
  replicas: 1

# PostgreSQL
postgresql:
  enabled: true
  auth:
    username: pistonprotection
    password: devpassword123
    database: pistonprotection
  primary:
    persistence:
      size: 1Gi

# Redis
redis:
  enabled: true
  architecture: standalone
  auth:
    enabled: false
  master:
    persistence:
      size: 500Mi

# ClickHouse
clickhouse:
  enabled: true
  auth:
    username: default
    password: devpassword123
  database: analytics
  persistence:
    enabled: true
    size: 2Gi

# Ingress
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: pistonprotection.local
      paths:
        - path: /
          pathType: Prefix
          service: frontend
        - path: /api
          pathType: Prefix
          service: gateway

# Service Monitor (if Prometheus is installed)
serviceMonitor:
  enabled: false

# Disable HPA for local dev
autoscaling:
  enabled: false

# Network policies
networkPolicies:
  enabled: false
EOF
    fi

    log_info "Installing Helm chart..."

    helm upgrade --install "$RELEASE_NAME" "$CHART_PATH" \
        --namespace "$NAMESPACE" \
        --create-namespace \
        --values "$values_file" \
        --wait \
        --timeout 10m

    log_step "Waiting for pods to be ready"

    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="$RELEASE_NAME" \
        -n "$NAMESPACE" \
        --timeout=300s || true

    log_success "PistonProtection deployed!"

    cmd_status
}

# Show deployment status
cmd_status() {
    log_step "Deployment Status"

    kubectl config use-context "$MINIKUBE_PROFILE" &> /dev/null

    echo -e "\n${CYAN}Pods:${NC}"
    kubectl get pods -n "$NAMESPACE" -o wide

    echo -e "\n${CYAN}Services:${NC}"
    kubectl get svc -n "$NAMESPACE"

    echo -e "\n${CYAN}Ingress:${NC}"
    kubectl get ingress -n "$NAMESPACE"

    echo -e "\n${CYAN}Custom Resources:${NC}"
    kubectl get backends,ddosprotections,filterrules -n "$NAMESPACE" 2>/dev/null || echo "No custom resources found"

    echo -e "\n${CYAN}Minikube IP:${NC} $(minikube ip -p "$MINIKUBE_PROFILE")"
}

# View logs
cmd_logs() {
    local service="${1:-}"
    local follow="${2:-}"

    kubectl config use-context "$MINIKUBE_PROFILE" &> /dev/null

    if [[ -z "$service" ]]; then
        log_info "Viewing all logs (use '$0 logs <service>' for specific service)"
        kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/instance="$RELEASE_NAME" --all-containers --tail=100
    else
        local selector="app.kubernetes.io/component=$service"
        if [[ "$follow" == "-f" ]] || [[ "$follow" == "--follow" ]]; then
            kubectl logs -n "$NAMESPACE" -l "$selector" -f --all-containers
        else
            kubectl logs -n "$NAMESPACE" -l "$selector" --all-containers --tail=100
        fi
    fi
}

# Open shell in pod
cmd_shell() {
    local service="${1:-gateway}"

    kubectl config use-context "$MINIKUBE_PROFILE" &> /dev/null

    local pod
    pod=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/component=$service" -o jsonpath='{.items[0].metadata.name}')

    if [[ -z "$pod" ]]; then
        log_error "No pod found for service: $service"
        exit 1
    fi

    log_info "Opening shell in $pod..."
    kubectl exec -it -n "$NAMESPACE" "$pod" -- /bin/sh || kubectl exec -it -n "$NAMESPACE" "$pod" -- /bin/bash
}

# Port forward
cmd_port_forward() {
    log_step "Setting up port forwards"

    kubectl config use-context "$MINIKUBE_PROFILE" &> /dev/null

    log_info "Starting port forwards in background..."

    # Kill any existing port forwards
    pkill -f "kubectl.*port-forward.*$NAMESPACE" || true

    # Frontend
    kubectl port-forward -n "$NAMESPACE" svc/"$RELEASE_NAME"-frontend 3000:80 &

    # Gateway
    kubectl port-forward -n "$NAMESPACE" svc/"$RELEASE_NAME"-gateway 8080:8080 &

    # Prometheus (if exists)
    kubectl port-forward -n "$NAMESPACE" svc/"$RELEASE_NAME"-metrics 9099:9090 2>/dev/null &

    echo ""
    log_success "Port forwards active!"
    echo ""
    echo "Access URLs:"
    echo "  Frontend:    http://localhost:3000"
    echo "  Gateway API: http://localhost:8080"
    echo "  Metrics:     http://localhost:9099"
    echo ""
    echo "Press Ctrl+C to stop port forwarding"

    # Wait for Ctrl+C
    wait
}

# Run integration tests
cmd_test() {
    log_step "Running integration tests"

    kubectl config use-context "$MINIKUBE_PROFILE" &> /dev/null

    # Get gateway service URL
    local gateway_url
    gateway_url="http://$(minikube ip -p "$MINIKUBE_PROFILE"):$(kubectl get svc -n "$NAMESPACE" "$RELEASE_NAME"-gateway -o jsonpath='{.spec.ports[0].nodePort}')"

    log_info "Testing gateway at: $gateway_url"

    echo ""
    echo "=== Health Check ==="
    curl -s "$gateway_url/health" | jq . || echo "Gateway health check failed"

    echo ""
    echo "=== API Version ==="
    curl -s "$gateway_url/api/v1/version" | jq . || echo "Version endpoint failed"

    echo ""
    echo "=== Create Test Backend ==="

    # Create a test backend CR
    kubectl apply -n "$NAMESPACE" -f - << 'EOF'
apiVersion: pistonprotection.io/v1alpha1
kind: DDoSProtection
metadata:
  name: test-protection
spec:
  backends:
    - name: test-server
      address: "httpbin.org:80"
      protocol: http
  protectionLevel: 3
  replicas: 1
  rateLimit:
    ppsPerIp: 1000
    burst: 5000
    globalPps: 100000
    windowSeconds: 1
EOF

    log_info "Waiting for CR to be processed..."
    sleep 5

    echo ""
    echo "=== Backend Status ==="
    kubectl get ddosprotections -n "$NAMESPACE" -o yaml

    echo ""
    echo "=== Pod Logs (last 20 lines) ==="
    kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/component=gateway --tail=20 || true

    log_success "Integration tests completed"
}

# Open dashboard
cmd_dashboard() {
    log_info "Opening Kubernetes dashboard..."
    minikube dashboard -p "$MINIKUBE_PROFILE"
}

# Teardown
cmd_teardown() {
    log_warning "This will delete the minikube cluster: $MINIKUBE_PROFILE"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Deleting minikube cluster..."

        # Kill port forwards
        pkill -f "kubectl.*port-forward.*$NAMESPACE" || true

        minikube delete -p "$MINIKUBE_PROFILE"

        log_success "Cluster deleted"
    else
        log_info "Teardown cancelled"
    fi
}

# Main function
main() {
    if [[ $# -eq 0 ]]; then
        print_help
        exit 0
    fi

    local command="$1"
    shift

    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --profile)
                MINIKUBE_PROFILE="$2"
                shift 2
                ;;
            --cpus)
                MINIKUBE_CPUS="$2"
                shift 2
                ;;
            --memory)
                MINIKUBE_MEMORY="$2"
                shift 2
                ;;
            --driver)
                MINIKUBE_DRIVER="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done

    case "$command" in
        setup)
            cmd_setup "$@"
            ;;
        build-images)
            cmd_build_images "$@"
            ;;
        deploy)
            cmd_deploy "$@"
            ;;
        status)
            cmd_status "$@"
            ;;
        logs)
            cmd_logs "$@"
            ;;
        shell)
            cmd_shell "$@"
            ;;
        port-forward|pf)
            cmd_port_forward "$@"
            ;;
        test)
            cmd_test "$@"
            ;;
        dashboard)
            cmd_dashboard "$@"
            ;;
        teardown)
            cmd_teardown "$@"
            ;;
        help|--help|-h)
            print_help
            ;;
        *)
            log_error "Unknown command: $command"
            print_help
            exit 1
            ;;
    esac
}

main "$@"
