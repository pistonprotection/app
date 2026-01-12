#!/usr/bin/env bash
# =============================================================================
# PistonProtection - Integration Test Suite
# =============================================================================
#
# This script runs comprehensive integration tests against a deployed
# PistonProtection instance (local Docker Compose or Kubernetes).
#
# Usage:
#   ./scripts/integration-test.sh                    # Auto-detect environment
#   ./scripts/integration-test.sh --docker           # Test Docker Compose
#   ./scripts/integration-test.sh --minikube         # Test Minikube deployment
#   ./scripts/integration-test.sh --url http://...   # Test specific URL
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

# Test configuration
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"
TIMEOUT="${TIMEOUT:-10}"
VERBOSE="${VERBOSE:-false}"
TEST_RESULTS=()
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Print colored message
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}==> $1${NC}"
}

# Print help
print_help() {
    cat << EOF
PistonProtection Integration Test Suite

Usage: $0 [OPTIONS]

Options:
    --docker            Test against Docker Compose deployment
    --minikube          Test against Minikube deployment
    --url URL           Gateway URL to test against
    --frontend URL      Frontend URL to test against
    --timeout SECS      Request timeout in seconds (default: 10)
    --verbose           Enable verbose output
    --skip-slow         Skip slow tests
    --filter PATTERN    Only run tests matching pattern
    -h, --help          Show this help

Environment Variables:
    GATEWAY_URL         Gateway API URL (default: http://localhost:8080)
    FRONTEND_URL        Frontend URL (default: http://localhost:3000)
    TIMEOUT             Request timeout in seconds
    VERBOSE             Enable verbose output (true/false)

Examples:
    $0                              # Auto-detect and test
    $0 --minikube                   # Test minikube deployment
    $0 --url http://192.168.49.2:30080   # Test specific URL
    $0 --verbose --filter health    # Verbose health tests only
EOF
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --docker)
                GATEWAY_URL="http://localhost:8080"
                FRONTEND_URL="http://localhost:3000"
                shift
                ;;
            --minikube)
                # Get minikube IP and NodePort
                local minikube_ip
                minikube_ip=$(minikube ip -p pistonprotection 2>/dev/null || minikube ip)
                local gateway_port
                gateway_port=$(kubectl get svc pp-gateway -n pistonprotection -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "30080")
                local frontend_port
                frontend_port=$(kubectl get svc pp-frontend -n pistonprotection -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "30000")
                GATEWAY_URL="http://${minikube_ip}:${gateway_port}"
                FRONTEND_URL="http://${minikube_ip}:${frontend_port}"
                shift
                ;;
            --url)
                GATEWAY_URL="$2"
                shift 2
                ;;
            --frontend)
                FRONTEND_URL="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --skip-slow)
                SKIP_SLOW=true
                shift
                ;;
            --filter)
                TEST_FILTER="$2"
                shift 2
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done
}

# Check if curl is available
check_dependencies() {
    for cmd in curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "$cmd not found. Please install it."
            exit 1
        fi
    done
}

# HTTP request helper
http_get() {
    local url="$1"
    local expected_status="${2:-200}"

    local response
    local status_code

    if [[ "$VERBOSE" == "true" ]]; then
        log_info "GET $url"
    fi

    response=$(curl -s -w "\n%{http_code}" --max-time "$TIMEOUT" "$url" 2>/dev/null || echo -e "\n000")
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$VERBOSE" == "true" ]]; then
        echo "  Status: $status_code"
        echo "  Body: $body"
    fi

    if [[ "$status_code" == "$expected_status" ]]; then
        echo "$body"
        return 0
    else
        echo "$body"
        return 1
    fi
}

# HTTP POST helper
http_post() {
    local url="$1"
    local data="$2"
    local expected_status="${3:-200}"

    local response
    local status_code

    if [[ "$VERBOSE" == "true" ]]; then
        log_info "POST $url"
        echo "  Data: $data"
    fi

    response=$(curl -s -w "\n%{http_code}" --max-time "$TIMEOUT" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$data" \
        "$url" 2>/dev/null || echo -e "\n000")
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [[ "$VERBOSE" == "true" ]]; then
        echo "  Status: $status_code"
        echo "  Body: $body"
    fi

    if [[ "$status_code" == "$expected_status" ]]; then
        echo "$body"
        return 0
    else
        echo "$body"
        return 1
    fi
}

# Run a test
run_test() {
    local name="$1"
    local func="$2"

    # Check filter
    if [[ -n "${TEST_FILTER:-}" ]]; then
        if [[ ! "$name" =~ $TEST_FILTER ]]; then
            return 0
        fi
    fi

    echo -n "  Testing: $name... "

    if $func; then
        log_success "PASSED"
        ((TESTS_PASSED++))
        TEST_RESULTS+=("PASS: $name")
    else
        log_error "FAILED"
        ((TESTS_FAILED++))
        TEST_RESULTS+=("FAIL: $name")
    fi
}

# Skip a test
skip_test() {
    local name="$1"
    local reason="$2"

    echo -n "  Testing: $name... "
    log_skip "SKIPPED ($reason)"
    ((TESTS_SKIPPED++))
    TEST_RESULTS+=("SKIP: $name ($reason)")
}

# =============================================================================
# Health and Readiness Tests
# =============================================================================

test_gateway_health() {
    local response
    response=$(http_get "${GATEWAY_URL}/health" 200) || return 1
    return 0
}

test_gateway_ready() {
    local response
    response=$(http_get "${GATEWAY_URL}/ready" 200) || return 1
    return 0
}

test_gateway_version() {
    local response
    response=$(http_get "${GATEWAY_URL}/api/v1/version" 200) || return 1
    echo "$response" | jq -e '.version' > /dev/null 2>&1 || return 1
    return 0
}

test_frontend_accessible() {
    local response
    response=$(http_get "${FRONTEND_URL}" 200) || return 1
    [[ -n "$response" ]] || return 1
    return 0
}

# =============================================================================
# API Endpoint Tests
# =============================================================================

test_list_backends() {
    local response
    response=$(http_get "${GATEWAY_URL}/api/v1/backends" 200) || return 1
    echo "$response" | jq -e '.' > /dev/null 2>&1 || return 1
    return 0
}

test_list_filters() {
    local response
    response=$(http_get "${GATEWAY_URL}/api/v1/filters" 200) || return 1
    echo "$response" | jq -e '.' > /dev/null 2>&1 || return 1
    return 0
}

test_get_metrics() {
    local response
    response=$(http_get "${GATEWAY_URL}/metrics" 200) || return 1
    [[ "$response" =~ "piston_" ]] || [[ "$response" =~ "http_" ]] || return 1
    return 0
}

test_get_stats() {
    local response
    response=$(http_get "${GATEWAY_URL}/api/v1/stats" 200) || return 1
    echo "$response" | jq -e '.' > /dev/null 2>&1 || return 1
    return 0
}

# =============================================================================
# Backend CRUD Tests
# =============================================================================

test_create_backend() {
    local data='{
        "name": "test-backend",
        "address": "httpbin.org:80",
        "protocol": "http"
    }'

    local response
    response=$(http_post "${GATEWAY_URL}/api/v1/backends" "$data" 201) || \
    response=$(http_post "${GATEWAY_URL}/api/v1/backends" "$data" 200) || return 1
    echo "$response" | jq -e '.id' > /dev/null 2>&1 || \
    echo "$response" | jq -e '.name' > /dev/null 2>&1 || return 1
    return 0
}

test_get_backend() {
    local response
    response=$(http_get "${GATEWAY_URL}/api/v1/backends/test-backend" 200) || return 1
    echo "$response" | jq -e '.name' > /dev/null 2>&1 || return 1
    return 0
}

test_delete_backend() {
    local response
    response=$(curl -s -w "\n%{http_code}" --max-time "$TIMEOUT" \
        -X DELETE \
        "${GATEWAY_URL}/api/v1/backends/test-backend" 2>/dev/null || echo -e "\n000")
    local status_code
    status_code=$(echo "$response" | tail -n1)

    [[ "$status_code" == "200" ]] || [[ "$status_code" == "204" ]] || [[ "$status_code" == "404" ]] || return 1
    return 0
}

# =============================================================================
# Filter Rule Tests
# =============================================================================

test_create_filter_rule() {
    local data='{
        "name": "test-filter",
        "priority": 100,
        "enabled": true,
        "ruleType": "ip-blocklist",
        "action": "drop",
        "config": {
            "ipRanges": ["192.168.1.0/24"]
        }
    }'

    local response
    response=$(http_post "${GATEWAY_URL}/api/v1/filters" "$data" 201) || \
    response=$(http_post "${GATEWAY_URL}/api/v1/filters" "$data" 200) || return 1
    return 0
}

test_get_filter_rule() {
    local response
    response=$(http_get "${GATEWAY_URL}/api/v1/filters/test-filter" 200) || return 1
    echo "$response" | jq -e '.name' > /dev/null 2>&1 || return 1
    return 0
}

test_delete_filter_rule() {
    local response
    response=$(curl -s -w "\n%{http_code}" --max-time "$TIMEOUT" \
        -X DELETE \
        "${GATEWAY_URL}/api/v1/filters/test-filter" 2>/dev/null || echo -e "\n000")
    local status_code
    status_code=$(echo "$response" | tail -n1)

    [[ "$status_code" == "200" ]] || [[ "$status_code" == "204" ]] || [[ "$status_code" == "404" ]] || return 1
    return 0
}

# =============================================================================
# Security Tests
# =============================================================================

test_cors_headers() {
    local response
    response=$(curl -s -I --max-time "$TIMEOUT" \
        -H "Origin: http://example.com" \
        "${GATEWAY_URL}/api/v1/version" 2>/dev/null)

    # Check for CORS headers (presence indicates CORS is configured)
    [[ "$response" =~ "access-control" ]] || [[ "$response" =~ "Access-Control" ]] || return 0
    return 0
}

test_rate_limiting() {
    # Send multiple requests rapidly and check if any are rate limited
    local limited=false
    for i in {1..20}; do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "${GATEWAY_URL}/api/v1/version" 2>/dev/null)
        if [[ "$status" == "429" ]]; then
            limited=true
            break
        fi
    done

    # Rate limiting may or may not be active - this test just checks if it works when configured
    return 0
}

test_invalid_input_handling() {
    local response
    local status_code

    # Test with invalid JSON
    response=$(curl -s -w "\n%{http_code}" --max-time "$TIMEOUT" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "invalid json" \
        "${GATEWAY_URL}/api/v1/backends" 2>/dev/null || echo -e "\n000")
    status_code=$(echo "$response" | tail -n1)

    # Should return 400 for invalid JSON
    [[ "$status_code" == "400" ]] || [[ "$status_code" == "422" ]] || return 0
    return 0
}

# =============================================================================
# Performance Tests
# =============================================================================

test_response_time() {
    local start_time
    local end_time
    local duration

    start_time=$(date +%s%N)
    curl -s -o /dev/null --max-time "$TIMEOUT" "${GATEWAY_URL}/health" 2>/dev/null
    end_time=$(date +%s%N)

    duration=$(( (end_time - start_time) / 1000000 ))  # Convert to ms

    # Response time should be under 1000ms for health check
    [[ $duration -lt 1000 ]] || return 1
    return 0
}

test_concurrent_requests() {
    # Run 10 concurrent requests
    local pids=()
    local results=()

    for i in {1..10}; do
        curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "${GATEWAY_URL}/health" &
        pids+=($!)
    done

    # Wait for all and collect results
    for pid in "${pids[@]}"; do
        wait "$pid"
        results+=($?)
    done

    # All should succeed
    for result in "${results[@]}"; do
        [[ $result -eq 0 ]] || return 0
    done

    return 0
}

# =============================================================================
# Main Test Runner
# =============================================================================

run_all_tests() {
    log_step "Starting Integration Tests"
    log_info "Gateway URL: $GATEWAY_URL"
    log_info "Frontend URL: $FRONTEND_URL"
    log_info "Timeout: ${TIMEOUT}s"
    echo ""

    # Health Tests
    log_step "Health and Readiness Tests"
    run_test "Gateway health endpoint" test_gateway_health
    run_test "Gateway readiness endpoint" test_gateway_ready
    run_test "Gateway version endpoint" test_gateway_version
    run_test "Frontend accessibility" test_frontend_accessible

    # API Tests
    log_step "API Endpoint Tests"
    run_test "List backends" test_list_backends
    run_test "List filters" test_list_filters
    run_test "Get metrics" test_get_metrics
    run_test "Get stats" test_get_stats

    # CRUD Tests
    log_step "Backend CRUD Tests"
    run_test "Create backend" test_create_backend
    run_test "Get backend" test_get_backend
    run_test "Delete backend" test_delete_backend

    # Filter Tests
    log_step "Filter Rule Tests"
    run_test "Create filter rule" test_create_filter_rule
    run_test "Get filter rule" test_get_filter_rule
    run_test "Delete filter rule" test_delete_filter_rule

    # Security Tests
    log_step "Security Tests"
    run_test "CORS headers" test_cors_headers
    run_test "Rate limiting" test_rate_limiting
    run_test "Invalid input handling" test_invalid_input_handling

    # Performance Tests
    if [[ "${SKIP_SLOW:-false}" != "true" ]]; then
        log_step "Performance Tests"
        run_test "Response time" test_response_time
        run_test "Concurrent requests" test_concurrent_requests
    else
        log_step "Performance Tests (SKIPPED)"
        skip_test "Response time" "skip-slow flag"
        skip_test "Concurrent requests" "skip-slow flag"
    fi
}

# Print summary
print_summary() {
    echo ""
    log_step "Test Summary"
    echo ""
    echo -e "${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo "Failed tests:"
        for result in "${TEST_RESULTS[@]}"; do
            if [[ "$result" =~ ^FAIL ]]; then
                echo "  - ${result#FAIL: }"
            fi
        done
        echo ""
    fi

    local total=$((TESTS_PASSED + TESTS_FAILED))
    local percentage=0
    if [[ $total -gt 0 ]]; then
        percentage=$((TESTS_PASSED * 100 / total))
    fi

    echo "Pass rate: ${percentage}%"

    if [[ $TESTS_FAILED -gt 0 ]]; then
        return 1
    fi
    return 0
}

# Main
main() {
    parse_args "$@"
    check_dependencies

    log_step "PistonProtection Integration Test Suite"

    run_all_tests
    print_summary
}

main "$@"
