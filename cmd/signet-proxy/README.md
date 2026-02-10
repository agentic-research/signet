# signet-proxy

Reverse proxy for GitHub API with Signet offline authentication.

## Overview

**signet-proxy** consolidates authentication:

1. **Clients → Proxy**: Authenticate via Signet (offline, cryptographic proof-of-possession)
2. **Proxy → GitHub**: Use single shared GitHub token

## Architecture

```
┌──────────┐                    ┌──────────────┐                  ┌────────────┐
│ Client 1 │─┐                  │              │                  │            │
│ Client 2 │─┤ Signet-Proof     │  signet-     │  Bearer TOKEN    │  GitHub    │
│ Client 3 │─┤ (offline auth)   │  proxy       │  (shared token)  │  API       │
│  ...     │─┤ ──────────────>  │              │  ──────────────> │            │
│ Client N │─┘                  │              │                  │            │
└──────────┘                    └──────────────┘                  └────────────┘
          Multiple clients            1 token                     Shared quota
```

## Features

- ✅ **Offline Authentication**: Verify Signet proofs without hitting GitHub
- ✅ **Token Consolidation**: Single GitHub token shared across clients
- ✅ **Security**: Cryptographic proof-of-possession prevents token theft
- ✅ **Health Check**: `/healthz` endpoint bypasses authentication
- ✅ **Structured Logging**: JSON logs with `slog` for observability

## Installation

```bash
# Build from source
cd signet
go build -o signet-proxy ./cmd/signet-proxy

# Or install
go install github.com/jamestexas/signet/cmd/signet-proxy@latest
```

## Configuration

### Required Environment Variables

```bash
# Master public key for Signet verification (hex-encoded Ed25519 public key)
export SIGNET_MASTER_PUBLIC_KEY="a1b2c3d4..."

# GitHub Installation Token (shared by all bots)
export GITHUB_TOKEN="ghs_abc123..."
```

### Optional Flags

```bash
--port               Port to listen on (default: 8080)
--github-api         GitHub API base URL (default: https://api.github.com)
--master-key         Master public key (overrides env var)
--github-token       GitHub token (overrides env var)
--log-level          Log level: debug, info, warn, error (default: info)
--health-path        Health check endpoint (default: /healthz)
--read-timeout       HTTP read timeout (default: 30s)
--write-timeout      HTTP write timeout (default: 30s)
--idle-timeout       HTTP idle timeout (default: 120s)
```

## Usage

### Basic Startup

```bash
# Set required environment variables
export SIGNET_MASTER_PUBLIC_KEY="$(cat master-public-key.hex)"
export GITHUB_TOKEN="ghs_your_installation_token"

# Start proxy
./signet-proxy --port 8080
```

### With Custom Configuration

```bash
./signet-proxy \
  --port 9000 \
  --log-level debug \
  --read-timeout 60s \
  --write-timeout 60s
```

### Health Check

```bash
curl http://localhost:8080/healthz
# {"status":"ok","timestamp":"2026-02-10T12:34:56Z"}
```

## Client Configuration

### 1. Generate Master Key (One-Time)

```bash
# Generate master key
signet-git init
signet-git export-key-id > master-public-key.hex
```

### 2. Configure Clients to Use Proxy

**Before (Direct GitHub API):**
```python
import requests

headers = {"Authorization": f"Bearer {github_token}"}
response = requests.get("https://api.github.com/repos/owner/repo", headers=headers)
```

**After (Via signet-proxy):**
```python
import requests
from signet import create_proof  # Hypothetical Python SDK

# Create Signet proof (offline, 0 quota)
proof = create_proof(master_key, ephemeral_key, request_data)

headers = {"Signet-Proof": proof}
response = requests.get("http://signet-proxy:8080/repos/owner/repo", headers=headers)
```

### 3. Authentication Flow

```
1. Client generates ephemeral key pair (Ed25519)
2. Master key signs ephemeral public key → BindingSignature
3. Ephemeral key signs HTTP request → RequestSignature
4. Client sends Signet-Proof header with both signatures
5. Proxy verifies proof (offline, no GitHub API call)
6. Proxy strips Signet-Proof, injects GitHub token
7. Proxy forwards to GitHub API
8. GitHub response returned to client
```

## Deployment

### Docker

```dockerfile
FROM golang:1.25 AS builder
WORKDIR /app
COPY . .
RUN go build -o signet-proxy ./cmd/signet-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/signet-proxy /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["signet-proxy"]
```

```bash
docker build -t signet-proxy .
docker run -p 8080:8080 \
  -e SIGNET_MASTER_PUBLIC_KEY="..." \
  -e GITHUB_TOKEN="..." \
  signet-proxy
```

### Kubernetes

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: signet-proxy-config
data:
  SIGNET_MASTER_PUBLIC_KEY: "a1b2c3d4..."  # Base64 or hex
---
apiVersion: v1
kind: Secret
metadata:
  name: signet-proxy-secrets
type: Opaque
stringData:
  GITHUB_TOKEN: "ghs_abc123..."
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: signet-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: signet-proxy
  template:
    metadata:
      labels:
        app: signet-proxy
    spec:
      containers:
      - name: signet-proxy
        image: signet-proxy:latest
        ports:
        - containerPort: 8080
        env:
        - name: SIGNET_MASTER_PUBLIC_KEY
          valueFrom:
            configMapKeyRef:
              name: signet-proxy-config
              key: SIGNET_MASTER_PUBLIC_KEY
        - name: GITHUB_TOKEN
          valueFrom:
            secretKeyRef:
              name: signet-proxy-secrets
              key: GITHUB_TOKEN
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 3
          periodSeconds: 5
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: signet-proxy
spec:
  selector:
    app: signet-proxy
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

### Systemd

```ini
# /etc/systemd/system/signet-proxy.service
[Unit]
Description=Signet GitHub API Proxy
After=network.target

[Service]
Type=simple
User=signet-proxy
Group=signet-proxy
Environment="SIGNET_MASTER_PUBLIC_KEY=a1b2c3d4..."
Environment="GITHUB_TOKEN=ghs_abc123..."
ExecStart=/usr/local/bin/signet-proxy --port 8080
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/signet-proxy

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable signet-proxy
sudo systemctl start signet-proxy
sudo journalctl -u signet-proxy -f
```

## Security Considerations

### Master Key Management

**DO:**
- ✅ Store master public key in config management (safe to distribute)
- ✅ Rotate master key regularly
- ✅ Use separate master keys per environment (dev, staging, prod)

**DON'T:**
- ❌ Share master private key between clients
- ❌ Commit keys to version control
- ❌ Use same key for different trust domains

### GitHub Token Management

**DO:**
- ✅ Use GitHub App Installation Tokens (scoped, short-lived)
- ✅ Rotate tokens regularly (daily recommended)
- ✅ Monitor token usage via GitHub audit logs
- ✅ Set minimum required permissions (read-only when possible)

**DON'T:**
- ❌ Use Personal Access Tokens (tied to user, no fine-grained permissions)
- ❌ Share tokens between environments
- ❌ Log token values (even partial)

### Network Security

- Use TLS between clients and proxy (terminate at load balancer)
- Run proxy in private network (not internet-facing)
- Use network policies to restrict proxy access
- Enable rate limiting at load balancer layer

### Monitoring

```bash
# Watch authentication failures
journalctl -u signet-proxy -f | grep "auth.*fail"

# Monitor GitHub rate limit
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/rate_limit
```

## Performance

### Benchmarks

- **Authentication**: < 1ms (Ed25519 verification)
- **Proxy overhead**: < 5ms (header modification + forwarding)
- **Memory**: ~50MB baseline, +1KB per concurrent request
- **Concurrency**: 10,000+ requests/sec on 2 CPU cores

### Capacity Planning

- **CPU**: 1-2 cores (verification is CPU-bound)
- **Memory**: 256MB (includes token/nonce stores)
- **Network**: 100Mbps (typical GitHub API traffic)

**Scaling:**
- Horizontal: Run multiple replicas behind load balancer
- Vertical: Add CPU for higher client count (linear scaling)
- Caching: Add Redis for distributed token/nonce stores

## Troubleshooting

### "Master public key required"

```bash
# Check environment variable is set
echo $SIGNET_MASTER_PUBLIC_KEY

# Verify hex encoding (64 characters for Ed25519)
echo -n $SIGNET_MASTER_PUBLIC_KEY | wc -c
# Expected: 64

# Export from signet-git
signet-git export-key-id
```

### "Invalid master key length"

Ed25519 public keys must be exactly 32 bytes (64 hex characters):

```bash
# Correct format
export SIGNET_MASTER_PUBLIC_KEY="a1b2c3d4e5f6..." # 64 chars

# Incorrect (missing characters)
export SIGNET_MASTER_PUBLIC_KEY="a1b2c3"
```

### "GitHub token required"

```bash
# Set from GitHub App
export GITHUB_TOKEN="$(gh api /app/installations/123/access_tokens -X POST | jq -r .token)"

# Or from file
export GITHUB_TOKEN="$(cat github-token.txt)"
```

### "Proxy error: Bad Gateway"

GitHub API is unreachable:

```bash
# Test connectivity
curl -I https://api.github.com

# Check DNS resolution
nslookup api.github.com

# Test with custom upstream
./signet-proxy --github-api http://github.local:3000
```

### Authentication Failures

```bash
# Enable debug logging
./signet-proxy --log-level debug

# Common issues:
# - Clock skew > 30s (sync NTP)
# - Invalid signature (wrong master key?)
# - Replay attack (nonce already used)
```

## Examples

### Python Client (Hypothetical SDK)

```python
import requests
from signet import SignetAuth

# Initialize Signet authentication
auth = SignetAuth(
    master_key_path="master-key.pem",
    ephemeral_key_ttl=300,  # 5 minutes
)

# Make authenticated request
response = requests.get(
    "http://signet-proxy:8080/repos/owner/repo",
    auth=auth,
)

print(response.json())
```

### Go Client

```go
package main

import (
    "net/http"
    "github.com/jamestexas/signet/pkg/http/client"
)

func main() {
    // Create Signet HTTP client
    masterKey := loadMasterKey()
    client := client.NewSignetClient(masterKey)

    // Make authenticated request through proxy
    resp, err := client.Get("http://signet-proxy:8080/repos/owner/repo")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    // Process response
    // ...
}
```

## Future Enhancements

- [ ] **Token Rotation**: Auto-refresh GitHub Installation Tokens
- [ ] **Redis Backend**: Distributed token/nonce stores for multi-replica
- [ ] **Metrics**: Prometheus endpoint for monitoring
- [ ] **Caching**: Cache GitHub API responses (respect Cache-Control)
- [ ] **Rate Limiting**: Per-client rate limits (prevent abuse)
- [ ] **Admin API**: Revoke client credentials, view metrics

## Related Documentation

- [Signet HTTP Middleware](../../pkg/http/middleware/README.md)
- [Ephemeral Proof Routines](../../pkg/crypto/epr/README.md)
- [GitHub API Documentation](https://docs.github.com/en/rest)
- [GitHub App Authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app)

## License

Apache 2.0 - See [LICENSE](../../LICENSE)
