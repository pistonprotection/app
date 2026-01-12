# API Documentation

PistonProtection provides both REST and gRPC APIs for programmatic access.

## Authentication

All API requests require authentication using Bearer tokens:

```bash
curl -H "Authorization: Bearer <your-api-token>" \
  https://api.pistonprotection.io/v1/backends
```

API tokens can be generated from the dashboard under Settings > API Keys.

## REST API

Base URL: `https://api.pistonprotection.io/v1`

### Backends

#### List Backends

```http
GET /v1/backends
```

Response:
```json
{
  "backends": [
    {
      "id": "backend-123",
      "name": "mc.example.com",
      "address": "192.168.1.100:25565",
      "protocol": "minecraft-java",
      "status": "healthy",
      "enabled": true,
      "createdAt": "2024-01-15T10:30:00Z",
      "stats": {
        "requests": 1234567,
        "blocked": 45678,
        "latency": 12
      }
    }
  ],
  "total": 1
}
```

#### Create Backend

```http
POST /v1/backends
Content-Type: application/json

{
  "name": "mc.example.com",
  "address": "192.168.1.100:25565",
  "protocol": "minecraft-java",
  "enabled": true,
  "rateLimit": {
    "ppsPerIp": 1000,
    "burst": 2000
  }
}
```

#### Get Backend

```http
GET /v1/backends/{id}
```

#### Update Backend

```http
PUT /v1/backends/{id}
Content-Type: application/json

{
  "name": "mc.example.com",
  "address": "192.168.1.100:25565",
  "enabled": true
}
```

#### Delete Backend

```http
DELETE /v1/backends/{id}
```

### Filter Rules

#### List Filter Rules

```http
GET /v1/filters
```

Response:
```json
{
  "rules": [
    {
      "id": "rule-123",
      "name": "Block Known Botnets",
      "type": "ip_blocklist",
      "action": "drop",
      "priority": 100,
      "enabled": true,
      "config": {
        "ipRanges": ["185.220.101.0/24", "45.155.205.0/24"]
      },
      "matches": 45678
    }
  ],
  "total": 1
}
```

#### Create Filter Rule

```http
POST /v1/filters
Content-Type: application/json

{
  "name": "Block Specific IPs",
  "type": "ip_blocklist",
  "action": "drop",
  "priority": 100,
  "config": {
    "ipRanges": ["1.2.3.4", "5.6.7.0/24"]
  }
}
```

Rule Types:
- `ip_blocklist` - Block specific IPs/CIDRs
- `ip_allowlist` - Allow specific IPs (bypass other rules)
- `rate_limit` - Rate limit traffic
- `geo_block` - Block by geographic location
- `protocol_validation` - Validate protocol format
- `syn_flood` - SYN flood protection
- `udp_amplification` - UDP amplification protection

Actions:
- `drop` - Silently drop packets
- `allow` - Allow through (whitelist)
- `ratelimit` - Apply rate limiting
- `log` - Log only (no action)
- `challenge` - Send challenge (L7 only)

#### Update Filter Rule

```http
PUT /v1/filters/{id}
```

#### Delete Filter Rule

```http
DELETE /v1/filters/{id}
```

### Metrics

#### Get Current Metrics

```http
GET /v1/metrics
```

Query Parameters:
- `backendId` - Filter by backend

Response:
```json
{
  "totalRequests": 5678901,
  "blockedRequests": 234567,
  "passedRequests": 5444334,
  "bytesIn": 12345678901,
  "bytesOut": 9876543210,
  "avgLatency": 0.8,
  "activeConnections": 12345,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Get Metrics History

```http
GET /v1/metrics/history
```

Query Parameters:
- `backendId` - Filter by backend
- `from` - Start timestamp (ISO 8601)
- `to` - End timestamp (ISO 8601)
- `resolution` - Data resolution (1m, 5m, 1h, 1d)

### IP Management

#### Block IP

```http
POST /v1/ips/block
Content-Type: application/json

{
  "ip": "1.2.3.4",
  "reason": "Manual block - suspicious activity",
  "expiresAt": "2024-01-20T00:00:00Z"
}
```

#### Unblock IP

```http
DELETE /v1/ips/block/{ip}
```

#### Allow IP

```http
POST /v1/ips/allow
Content-Type: application/json

{
  "ip": "10.0.0.0/8",
  "reason": "Internal network"
}
```

### Users (Admin)

#### List Users

```http
GET /v1/admin/users
```

#### Create User

```http
POST /v1/admin/users
Content-Type: application/json

{
  "email": "user@example.com",
  "name": "John Doe",
  "role": "admin"
}
```

Roles:
- `owner` - Full access
- `admin` - Manage backends and rules
- `member` - View only

## gRPC API

PistonProtection also provides a gRPC API for high-performance integrations.

### Connection

```
grpc://api.pistonprotection.io:9090
```

### Protobuf Definitions

See [`proto/`](../proto/) directory for complete protobuf definitions.

```protobuf
service BackendService {
  rpc ListBackends(ListBackendsRequest) returns (ListBackendsResponse);
  rpc GetBackend(GetBackendRequest) returns (Backend);
  rpc CreateBackend(CreateBackendRequest) returns (Backend);
  rpc UpdateBackend(UpdateBackendRequest) returns (Backend);
  rpc DeleteBackend(DeleteBackendRequest) returns (google.protobuf.Empty);
}

service FilterService {
  rpc ListFilters(ListFiltersRequest) returns (ListFiltersResponse);
  rpc CreateFilter(CreateFilterRequest) returns (FilterRule);
  rpc UpdateFilter(UpdateFilterRequest) returns (FilterRule);
  rpc DeleteFilter(DeleteFilterRequest) returns (google.protobuf.Empty);
}

service MetricsService {
  rpc GetMetrics(GetMetricsRequest) returns (Metrics);
  rpc StreamMetrics(StreamMetricsRequest) returns (stream Metrics);
}
```

### Example: Go Client

```go
package main

import (
    "context"
    "log"

    pb "github.com/pistonprotection/pistonprotection/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/metadata"
)

func main() {
    conn, err := grpc.Dial("api.pistonprotection.io:9090", grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := pb.NewBackendServiceClient(conn)

    // Add authentication
    ctx := metadata.AppendToOutgoingContext(
        context.Background(),
        "authorization", "Bearer <your-api-token>",
    )

    // List backends
    resp, err := client.ListBackends(ctx, &pb.ListBackendsRequest{})
    if err != nil {
        log.Fatal(err)
    }

    for _, backend := range resp.Backends {
        log.Printf("Backend: %s (%s)", backend.Name, backend.Status)
    }
}
```

### Example: Rust Client

```rust
use pistonprotection_proto::backend_service_client::BackendServiceClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = tonic::transport::Channel::from_static("http://api.pistonprotection.io:9090")
        .connect()
        .await?;

    let mut client = BackendServiceClient::with_interceptor(channel, |mut req: Request<()>| {
        req.metadata_mut().insert(
            "authorization",
            "Bearer <your-api-token>".parse().unwrap(),
        );
        Ok(req)
    });

    let response = client.list_backends(Request::new(ListBackendsRequest {})).await?;

    for backend in response.into_inner().backends {
        println!("Backend: {} ({})", backend.name, backend.status);
    }

    Ok(())
}
```

## Rate Limits

API rate limits:

| Tier | Requests/min | Burst |
|------|--------------|-------|
| Free | 60 | 10 |
| Pro | 600 | 50 |
| Enterprise | Unlimited | - |

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests per minute
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Unix timestamp when limit resets

## Error Responses

Errors follow RFC 7807 (Problem Details):

```json
{
  "type": "https://api.pistonprotection.io/errors/validation",
  "title": "Validation Error",
  "status": 400,
  "detail": "IP address '1.2.3.4.5' is not valid",
  "instance": "/v1/filters"
}
```

Common error codes:
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Rate Limited
- `500` - Internal Server Error

## Webhooks

Configure webhooks to receive events:

```http
POST /v1/webhooks
Content-Type: application/json

{
  "url": "https://your-service.com/webhook",
  "events": ["attack.detected", "backend.down", "rule.triggered"],
  "secret": "your-webhook-secret"
}
```

Events:
- `attack.detected` - DDoS attack detected
- `attack.mitigated` - Attack mitigated
- `backend.up` - Backend came online
- `backend.down` - Backend went offline
- `rule.triggered` - Filter rule matched

Webhook payload:
```json
{
  "id": "event-123",
  "type": "attack.detected",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "attackType": "syn_flood",
    "sourceIps": ["1.2.3.4", "5.6.7.8"],
    "pps": 100000,
    "bandwidth": "500 Mbps"
  }
}
```

Webhook signature verification:
```python
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```
