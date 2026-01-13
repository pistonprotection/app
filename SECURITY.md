# Security Policy

## Supported Versions

PistonProtection is actively maintained. Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in PistonProtection, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email security concerns to: security@pistonprotection.io
3. Include as much detail as possible:
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 7 days
- **Resolution Timeline**: Critical vulnerabilities will be addressed within 30 days
- **Disclosure**: We coordinate disclosure timing with the reporter

### Scope

The following are in scope for security reports:

- PistonProtection core services (gateway, auth, config-mgr, metrics, worker)
- eBPF/XDP filter programs
- Frontend application
- Kubernetes operator
- Official Docker images
- Official Helm charts

### Out of Scope

- Issues in third-party dependencies (report to upstream)
- Social engineering attacks
- Physical attacks
- Issues requiring physical access to infrastructure

## Security Measures

### Authentication & Authorization

- JWT-based authentication with configurable expiration
- Role-based access control (RBAC) for organizations
- API key support for programmatic access
- Session management with secure token handling

### Network Security

- All internal service communication uses mTLS
- External API endpoints require HTTPS
- Rate limiting at gateway level
- IP-based access controls

### Data Protection

- Passwords hashed using Argon2id
- Sensitive configuration encrypted at rest
- Database connections use TLS
- No plaintext storage of secrets

### eBPF/XDP Security

- All eBPF programs verified by kernel
- XDP programs operate in isolated context
- No user-space data access from eBPF
- Memory-safe Rust implementation via Aya

### Infrastructure Security

- Kubernetes RBAC for operator
- Pod security contexts enforced
- Network policies for service isolation
- Secrets managed via Kubernetes Secrets or external vaults

## Security Hardening Guide

### Kubernetes Deployment

1. **Enable Pod Security Standards**
   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: pistonprotection
     labels:
       pod-security.kubernetes.io/enforce: restricted
   ```

2. **Configure Network Policies**
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny
   spec:
     podSelector: {}
     policyTypes:
       - Ingress
       - Egress
   ```

3. **Use Read-Only Root Filesystem**
   ```yaml
   securityContext:
     readOnlyRootFilesystem: true
     runAsNonRoot: true
     runAsUser: 65534
   ```

### Database Security

1. Use dedicated database users with minimal privileges
2. Enable TLS for all database connections
3. Regularly rotate database credentials
4. Enable query logging for audit purposes

### Secret Management

1. Use Kubernetes Secrets with encryption at rest
2. Consider external secret managers (HashiCorp Vault, AWS Secrets Manager)
3. Rotate secrets regularly
4. Never commit secrets to version control

### Monitoring & Audit

1. Enable audit logging in Kubernetes
2. Monitor authentication failures
3. Set up alerts for unusual traffic patterns
4. Retain logs for compliance requirements

## Security Updates

Security updates are released as patch versions. Subscribe to our security advisories:

- GitHub Security Advisories: https://github.com/pistonprotection/app/security/advisories
- Release Notes: https://github.com/pistonprotection/app/releases

## Acknowledgments

We thank the following security researchers for responsible disclosure:

*No acknowledgments yet*

---

Last updated: January 2026
