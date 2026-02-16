# Deploy moat-drawbridge to Fly.io

## Context

Drawbridge is a Go WebSocket relay server for Moat's push notifications. It currently has no deployment config. We need to containerize it and deploy to Fly.io.

The app listens on HTTP (`:8080` by default without TLS) or HTTPS (`:443` with autocert). Fly.io terminates TLS at its edge, so we should run the app in **non-TLS mode** (`RELAY_TLS=false`) and let Fly handle certificates.

## Files to Create

### 1. `moat-drawbridge/Dockerfile`

Multi-stage build:
- **Build stage**: `golang:1.23-alpine` (Go 1.25.7 isn't on Docker Hub yet — use latest stable; adjust if needed), copy `go.mod`, `go.sum`, download deps, copy source, `go build -o drawbridge .`
- **Run stage**: `alpine:latest` with ca-certificates, copy binary, expose port 8080, `CMD ["./drawbridge"]`

### 2. `moat-drawbridge/fly.toml`

```toml
app = "moat-drawbridge"
primary_region = "ams"

[build]

[env]
  RELAY_TLS = "false"
  RELAY_ADDR = ":8080"
  LOG_FORMAT = "json"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 1

[[http_service.checks]]
  path = "/health"
  interval = "15s"
  timeout = "5s"
  grace_period = "10s"
```

### 3. `moat-drawbridge/.dockerignore`

Ignore the pre-built binary, test files, plan docs, and certs directory.

## Deployment Steps

1. Install `flyctl` if not already installed
2. `cd moat-drawbridge`
3. `fly launch` (or `fly apps create moat-drawbridge` if app name is taken)
4. `fly deploy`
5. Verify with `curl https://moat-drawbridge.fly.dev/health`

## Key Decisions

- **No TLS in app** — Fly.io terminates TLS and provides automatic certs. The app runs plain HTTP on 8080.
- **WebSocket support** — Fly.io natively supports WebSocket connections on its HTTP service, no special config needed.
- **Single machine with auto-stop** — Keeps costs low; auto-starts on incoming requests. `min_machines_running = 1` ensures at least one instance is always up (important for persistent WebSocket connections).
- **Health checks** — Uses the existing `/health` endpoint.

## Verification

1. `fly deploy` succeeds
2. `curl https://moat-drawbridge.fly.dev/health` returns JSON with uptime info
3. WebSocket connection to `wss://moat-drawbridge.fly.dev/ws` works from a client
