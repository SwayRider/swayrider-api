# swayrider-api

API gateway for the SwayRider platform. It is the single externally reachable entry point — all client traffic passes through it before reaching any backend service.

## Architecture

| Interface | Port | Purpose |
|-----------|------|---------|
| HTTP | 8080 | REST API (clients) |

There is no gRPC port. `swayrider-api` calls downstream services over gRPC but does not expose a gRPC interface itself.

### Responsibilities

- **JWT validation** — verifies access tokens using public keys fetched from authservice (refreshed every `JWT_KEYS_REFRESH_INTERVAL_SECS` seconds, default 5 min; supports key rotation)
- **Rate limiting** — per-IP sliding window for public/auth endpoints; per-user sliding window for authenticated endpoints (unauthenticated requests to user-scoped endpoints are limited per IP); backed by Redis
- **Circuit breakers** — one per downstream service; opens after 5 consecutive failures
- **Auth proxy** — `POST /api/v1/auth/*` → gRPC → authservice; sets/clears `access_token` and `refresh_token` cookies for web clients; returns tokens in the response body for mobile clients
- **Region proxy** — `POST /api/v1/region/*` → gRPC → regionservice (requires an access token)
- **Tiles proxy** — `/v1/tiles/*` → HTTP reverse proxy → tilesservice; user cookies are not forwarded — the gateway injects its own service token
- **Web proxy** — `/web/*` → HTTP reverse proxy → authservice web server; the gateway's `/web` namespace is mapped onto authservice's own `WEB_PATH_PREFIX` (see `AUTHSERVICE_WEB_PATH_PREFIX` below); only the `access_token` cookie is forwarded (authservice's static pages read it to render logged-in state), all other cookies are dropped
- **CORS** — configured via `CORS_ALLOWED_ORIGINS`; `AllowCredentials: true` for cookie-based web clients

### Dependencies

| Service | Purpose | Required scope |
|---------|---------|----------------|
| **authservice** | JWT public key discovery; service token issuance | — |
| **routerservice** | Route calculation (async queue) | `routing:execute` |
| **searchservice** | Geocoding (async queue) | `search:execute` |
| **regionservice** | Spatial queries (direct gRPC proxy) | `region:query` |
| **tilesservice** | Vector tile serving (HTTP reverse proxy) | `tiles:serve` |
| **Redis** | Rate limiting; async job queue | — |

The gateway obtains a single service client token from authservice (covering all four scopes) and uses it for all downstream calls. See `infra/dev-mini/layer-20/swayrider-api-register/init.sh`.

### Proxy chain

```
Client (HTTPS)
  → HAProxy (TCP passthrough)
  → Traefik (TLS termination)
  → swayrider-api :8080
      ├─ /api/v1/auth/*    → gRPC → authservice :8081
      ├─ /api/v1/region/*  → gRPC → regionservice :8081
      ├─ /api/v1/route/*   → Redis queue → worker → routerservice :8081 (Plan 04)
      ├─ /api/v1/search/*  → Redis queue → worker → searchservice :8081 (Plan 04)
      ├─ /v1/tiles/*       → HTTP → tilesservice :8080
      └─ /web/*            → HTTP → authservice :8000
```

Only the immediate peer is checked for proxy-header trust, so if additional append-only proxies sit in front of Traefik (e.g. an Apache/nginx), list their CIDRs in `TRUSTED_PROXIES` too for the client IP to resolve past them — the set must only contain proxies you control.

## Configuration

All configuration is via environment variables. Copy `env.example` to `.env` and fill in the values.

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_PORT` | `8080` | HTTP listen port |
| `LOG_LEVEL` | `info` | Log level |

### Downstream services

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHSERVICE_HOST` | `localhost` | |
| `AUTHSERVICE_PORT` | `8081` | |
| `AUTHSERVICE_WEB_PORT` | `8000` | authservice's static web server (HTTP) |
| `AUTHSERVICE_WEB_PATH_PREFIX` | `/web` | Path prefix authservice's web server mounts its pages under — must match its `WEB_PATH_PREFIX` |
| `ROUTERSERVICE_HOST` | `localhost` | |
| `ROUTERSERVICE_PORT` | `8081` | |
| `SEARCHSERVICE_HOST` | `localhost` | |
| `SEARCHSERVICE_PORT` | `8081` | |
| `REGIONSERVICE_HOST` | `localhost` | |
| `REGIONSERVICE_PORT` | `8081` | |
| `TILESSERVICE_HOST` | `localhost` | |
| `TILESSERVICE_PORT` | `8080` | HTTP port (tiles has no gRPC) |

### Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `localhost` | |
| `REDIS_PORT` | `6379` | |

### Service client credentials

| Variable | Default | Description |
|----------|---------|-------------|
| `SWAYRIDER_API_CLIENT_ID` | — | Client ID from authservice |
| `SWAYRIDER_API_CLIENT_SECRET` | — | Client secret from authservice |

Required scopes: `region:query routing:execute search:execute tiles:serve`

In the dev stack, registration is fully automated by `infra/dev-mini/layer-20/swayrider-api-register/init.sh`. The script detects scope changes on each compose-up and re-registers if needed. To force a reset:

```bash
FORCE_REREGISTER=true docker compose -f infra/dev-mini/layer-20/compose.yml up --force-recreate swayrider-api-register
docker compose -f infra/dev-mini/layer-30/compose.yml restart swayrider-api
```

For manual registration:
```bash
swctl auth create-service-client \
  --auth-host localhost --auth-port 34101 \
  --user admin@example.com --password <pw> \
  swayrider-api region:query routing:execute search:execute tiles:serve
```

Set the returned `clientId` and `clientSecret` as `SWAYRIDER_API_CLIENT_ID` and `SWAYRIDER_API_CLIENT_SECRET`.

### Background refresh

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVICE_TOKEN_REFRESH_TIMEOUT` | `15` | Upper bound (seconds) on a single service-token refresh attempt. If the call doesn't return in time it is abandoned (before it only failed **silently** and could wedge the refresh loop forever) and retried on the next cycle |
| `JWT_KEYS_REFRESH_TIMEOUT` | `15` | Upper bound (seconds) on a single public-key fetch from authservice |
| `JWT_KEYS_REFRESH_INTERVAL` | `300` | How often (seconds) the cached JWT verification public keys are refetched from authservice; bounds how long it takes to pick up a rotated key or stop trusting a revoked one |

Both refresh loops (service token, JWT public keys) bound every fetch attempt with their own timeout, recover from panics and relaunch the background goroutine, and log an error if they haven't succeeded for longer than the configured refresh interval — a stall is always visible in the logs instead of silent. The JWT public-key cache is the shared `swlib/jwtkeys.Cache`, also used by every backend gRPC service (mailservice, regionservice, routerservice, searchservice) that verifies JWTs.

### Rate limits

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_IP_AUTH` | `10` | Requests/min per IP on login, register, password-reset, verify-email, mfa-verify |
| `RATE_LIMIT_IP_PUBLIC` | `600` | Requests/min per IP on tiles, health, public-keys |
| `RATE_LIMIT_IP_API` | `60` | Requests/min per IP on unauthenticated requests to per-user endpoints (refresh, logout, reset-password, check-password-strength, and floods aimed at protected endpoints) |
| `RATE_LIMIT_USER_API` | `300` | Requests/min per user on general authenticated endpoints |
| `RATE_LIMIT_USER_EXPENSIVE` | `20` | Requests/min per user on route and search endpoints |
| `RATE_LIMIT_DEGRADE_MODE` | `memory` | Behavior when Redis is unreachable: `memory` (in-process fallback with same limits, per instance) or `deny` (fail closed, 429 everything) |
| `RATE_LIMIT_DEGRADE_THRESHOLD` | `3` | Consecutive Redis failures before the limiter degrades (fail-open below this) |
| `RATE_LIMIT_REDIS_PROBE_SECONDS` | `15` | How often the limiter probes Redis for recovery while degraded |

When Redis is down, the rate limiter **does not silently disable throttling** (it previously failed open on every error, which the security review flagged). It degrades: after `RATE_LIMIT_DEGRADE_THRESHOLD` consecutive failures it either limits against an in-process sliding window with the same limits (`memory`, default — state is per-instance, so effective limits multiply by replica count while degraded) or rejects every limited request with 429 (`deny`). Redis is probed on `RATE_LIMIT_REDIS_PROBE_SECONDS` and the limiter recovers automatically. State transitions (degrade/recover) are logged; a limiter error in the middleware fails closed (429) rather than letting the request through unthrottled.

### Async job queue

| Variable | Default | Description |
|----------|---------|-------------|
| `ROUTE_WORKER_COUNT` | `5` | Goroutines draining the routing stream |
| `SEARCH_WORKER_COUNT` | `10` | Goroutines draining the search stream |
| `QUEUE_MAX_DEPTH` | `500` | Max pending messages across routing/search streams combined |
| `RESULT_TTL_SECONDS` | `300` | How long (seconds) completed job results are kept in Redis |

### Cookie namespace

| Variable | Default | Description |
|----------|---------|-------------|
| `COOKIE_NAMESPACE` | `com.hevanto-it.swayrider` | Prefix applied to all cookie names |

### Request body limits

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_BODY_BYTES` | `1048576` (1 MiB) | Maximum request body size. Larger bodies are rejected with `413 Payload Too Large` before they can be read into memory |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | Comma-separated list of allowed origins |

`AllowCredentials` is always `true` (required for cookie-based auth). Wildcard origins are not supported — a bare `*` (or empty) entry is rejected at startup with a fatal error rather than silently enabling credentialed requests from any origin.

### Trusted proxies

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTED_PROXIES` | — | Comma-separated CIDRs of reverse proxies (e.g. the Traefik container) whose `X-Forwarded-For` / `X-Forwarded-Proto` headers are honored |

Requests whose immediate peer is inside `TRUSTED_PROXIES` have their client IP read from `X-Forwarded-For` (rightmost non-proxy entry — proxies append) and the cookie `Secure` flag derived from `X-Forwarded-Proto`. Requests from any other peer are treated as direct connections: the headers are ignored and the peer address (`RemoteAddr`) is used, so a client can never spoof the IP used for rate limiting or force insecure cookies. **Empty (default) = trust no one.** In the dev stack, Traefik's container IP is pinned to `10.10.0.2` and `TRUSTED_PROXIES=10.10.0.2/32` is set in `layer-30`; the direct dev port (`34000`) is intentionally *not* trusted — WireGuard dev connections arrive from the docker gateway and are rate-limited by that address.

### Forwarded user identity (trust chain)

The gateway authenticates end users and calls downstream services with its own scoped service token. On the asynchronous route/search paths it additionally forwards the submitting user's identity as gRPC metadata, so downstream services can attribute work to the original caller:

| Metadata | Meaning | Forwarded by |
|---|---|---|
| `x-user-id` | Submitting user's ID | route, search workers |
| `x-account-level` | Submitting user's account level | route, search workers |
| `x-is-admin` | Whether the user is an admin | route, search workers (currently unread downstream — reserved) |
| `x-user-verified` | Whether the user's email is verified | route, search workers (currently unread downstream — reserved) |

The region endpoints forward **no** user identity.

Downstream services resolve these via `security.ResolveUserID` / `security.ResolveAccountLevel` (swlib), which consult the metadata **only** when the caller holds a valid service token with the scopes the endpoint requires (`AuthInterceptor` enforces this before claims are placed in context).

**Trust model:** the metadata is *not* authentication. Any holder of a service token with the relevant scopes — in practice only this gateway's service client, scoped to `region:query routing:execute search:execute tiles:serve` — can set `x-user-*` to arbitrary values, including another user's ID. Downstream services must treat the forwarded identity as a hint about the original caller, never as verified identity, and must never use it alone to authorize privileged operations.

## API Reference

### Health

#### GET /health

Liveness check.

```bash
curl http://localhost:8080/health
# → 200 {"status":"ok","service":"swayrider-api"}
```

---

### Auth — `/api/v1/auth/*`

The gateway proxies these endpoints to authservice over gRPC. On login, register, and refresh it also sets `access_token` and `refresh_token` cookies (web clients); tokens are always returned in the response body too (mobile clients). When an account has MFA enabled, login returns `mfa_required: true` plus a one-time `mfa_token` challenge and sets **no** cookies — the caller completes the second factor via `POST /api/v1/auth/mfa/verify`, which then issues the token pair (and cookies) exactly like a completed login. On login, refresh, and mfa-verify the gateway additionally forwards the resolved client IP (from `TRUSTED_PROXIES`-gated `X-Forwarded-For`) to authservice as `x-orig-ip` gRPC metadata; authservice stores it on the refresh token as a soft anomaly signal for audit — it is logged on mismatch, never used to reject a refresh.

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| `/health` | GET | — | Liveness check |
| `/api/v1/auth/login` | POST | — | Rate limited (IP) |
| `/api/v1/auth/register` | POST | — | Rate limited (IP) |
| `/api/v1/auth/refresh` | POST | Refresh token | Cookie or request body |
| `/api/v1/auth/logout` | POST | Access token | Clears cookies |
| `/api/v1/auth/request-password-reset` | POST | — | Rate limited (IP) |
| `/api/v1/auth/reset-password` | POST | — | |
| `/api/v1/auth/verify-email` | POST | — | |
| `/api/v1/auth/change-password` | POST | Access token | |
| `/api/v1/auth/check-password-strength` | POST | — | |
| `/api/v1/auth/public-keys` | GET | — | Served from gateway key cache |
| `/api/v1/auth/whoami` | GET | Access token | Full user info from authservice |
| `/api/v1/auth/me` | GET | Access token | Claims from JWT (no gRPC call) |
| `/api/v1/auth/mfa/setup` | POST | Access token | Start enrollment → secret + otpauth URL + QR PNG |
| `/api/v1/auth/mfa/enable` | POST | Access token | Verify one code → enable + backup codes |
| `/api/v1/auth/mfa/disable` | POST | Access token | Disable (requires password) |
| `/api/v1/auth/mfa/status` | GET | Access token | MFA enabled? |
| `/api/v1/auth/mfa/verify` | POST | — | Complete second factor → tokens; rate limited (IP) |
| `/api/v1/auth/mfa/backup-codes` | POST | Access token | Regenerate backup codes (requires password) |
| `/api/v1/region/*` | POST | **Access token** | All region endpoints require user JWT |
| `/api/v1/route` | POST | **Access token** | SSE streaming |
| `/api/v1/search` | POST | **Access token** | SSE streaming |
| `/api/v1/search/reverse` | POST | **Access token** | SSE streaming |
| `/api/v1/search/autocomplete` | POST | **Access token** | SSE streaming |
| `/v1/tiles/*` | GET | **Access token** | Proxy injects service token to tilesservice |

Nine additional `/api/v1/auth/admin/*` endpoints (create-admin, change-account-type, whois, create-service-client, delete-service-client, list-service-clients, invite-user, revoke-invite, list-invites) require Admin access — see [Admin](#admin) below.

#### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret","remember_me":false}'
# → 200 {"access_token":"...","refresh_token":"..."}
# Sets access_token and refresh_token cookies for web clients.
# When the account has MFA enabled, instead:
# → 200 {"mfa_required":true,"mfa_token":"..."}  (no cookies)
# then complete the second factor:
curl -X POST http://localhost:8080/api/v1/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{"mfa_token":"...","code":"123456"}'
# → 200 {"access_token":"...","refresh_token":"..."} + cookies
```

#### Refresh

```bash
# Mobile: token in body
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"...","remember_me":false}'

# Web: token from cookie (sent automatically by browser)
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  --cookie "refresh_token=..."
```

#### Admin

All proxy directly to authservice over gRPC and require an admin access token.

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/api/v1/auth/admin/create-admin` | POST | |
| `/api/v1/auth/admin/change-account-type` | POST | |
| `/api/v1/auth/admin/whois` | POST | |
| `/api/v1/auth/admin/create-service-client` | POST | |
| `/api/v1/auth/admin/delete-service-client` | POST | |
| `/api/v1/auth/admin/list-service-clients` | GET | |
| `/api/v1/auth/admin/invite-user` | POST | |
| `/api/v1/auth/admin/revoke-invite` | POST | |
| `/api/v1/auth/admin/list-invites` | GET | |

---

### Region — `/api/v1/region/*`

All region endpoints require an access token. They proxy directly to regionservice over gRPC.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/region/search-point` | POST | Regions containing a coordinate |
| `/api/v1/region/search-box` | POST | Regions intersecting a bounding box |
| `/api/v1/region/search-radius` | POST | Regions within a radius |
| `/api/v1/region/find-crossing-locations` | POST | Border crossing points |
| `/api/v1/region/find-region-path` | POST | Region sequence for a cross-border route |
| `/api/v1/region/find-route-region-paths` | POST | Region sequence for a multi-waypoint route |

```bash
curl -X POST http://localhost:8080/api/v1/region/search-point \
  -H "Content-Type: application/json" \
  -d '{"location":{"lat":48.85,"lon":2.35},"include_extended":false}'
# → 200 {"CoreRegions":["france"],"ExtendedRegions":[]}
```

---

### Tiles — `/v1/tiles/*`

HTTP reverse proxy to tilesservice. No authentication required.

```bash
curl http://localhost:8080/v1/tiles/styles
```

---

### Web — `/web/*`

HTTP reverse proxy to the authservice web server (login pages, email verification, password reset). The gateway owns the public `/web` namespace and maps it onto the path authservice's web server actually mounts under — its `WEB_PATH_PREFIX`, configured here as `AUTHSERVICE_WEB_PATH_PREFIX`. With the default `/web` on both sides the forwarded path is unchanged (`/web/reset-password` → `/web/reset-password`); if authservice is configured with a different prefix, set `AUTHSERVICE_WEB_PATH_PREFIX` to match so the pages keep working.

```bash
curl http://localhost:8080/web/reset-password?u=...&t=...
```

---

## Building

```bash
# From the repo root (go.work resolves siblings locally)
go build ./swayrider-api/...

# Generate protobuf code first if protos changed
cd protos && make
```

## Running

```bash
cp env.example .env
# Edit .env

go run ./cmd/swayrider-api
```

## Docker

```bash
# From swayrider-api/
make container-build
```

Tagging follows the same branch-based convention as other SwayRider services:

| Branch / state | Tags applied |
|----------------|--------------|
| Version-tagged commit (`v1.2.3`) | `v1.2.3`, `latest` |
| `main` (untagged) | `v{last}-{date}-dev-b{N}`, `dev-latest` |
| Other branch | `v{last}-{branch}-b{N}` |
| Detached HEAD | `v{last}-{sha}-b{N}` |

Non-release builds get an incrementing build number (`-b{N}`) so repeated builds of the same branch don't overwrite each other. The number comes from querying the registry for the highest existing `-b{N}` tag on the same base tag and adding 1; the build fails if the registry can't be reached. Release builds are immutable and never get a build number.

```bash
# Also push dev-latest on a release tag or any other branch
FORCE_DEV_LATEST=1 make container-build
```

Or, across all services at once, `tools/containerbuild.py --dev-latest`.

## Development

Start the full dev stack (see [infra repo](https://github.com/SwayRider/infra)):

```bash
cd infra/dev-mini
docker compose -f layer-00/compose.yaml up -d   # Traefik, PostgreSQL, Elasticsearch, Redis
docker compose -f layer-10/compose.yaml up -d   # Valhalla, Pelias
docker compose -f layer-20/compose.yml  up -d   # Backend services
```

Then run swayrider-api locally:

```bash
cd swayrider-api
go run ./cmd/swayrider-api
```

Development port: `8080` (direct) or via Traefik on `30080`.
