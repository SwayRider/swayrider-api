# swayrider-api

API gateway for the SwayRider platform. It is the single externally reachable entry point — all client traffic passes through it before reaching any backend service.

## Architecture

| Interface | Port | Purpose |
|-----------|------|---------|
| HTTP | 8080 | REST API (clients) |

There is no gRPC port. `swayrider-api` calls downstream services over gRPC but does not expose a gRPC interface itself.

### Responsibilities

- **JWT validation** — verifies access tokens using public keys fetched from authservice (hourly refresh, supports key rotation)
- **Rate limiting** — per-IP sliding window for public/auth endpoints; per-user sliding window for authenticated endpoints; backed by Redis
- **Circuit breakers** — one per downstream service; opens after 5 consecutive failures
- **Auth proxy** — `POST /api/v1/auth/*` → gRPC → authservice; sets/clears `access_token` and `refresh_token` cookies for web clients; returns tokens in the response body for mobile clients
- **Region proxy** — `POST /api/v1/region/*` → gRPC → regionservice (public endpoints, no auth required)
- **Tiles proxy** — `/v1/tiles/*` → HTTP reverse proxy → tilesservice
- **Web proxy** — `/web/*` → HTTP reverse proxy → authservice web server (strips `/web` prefix)
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

### Rate limits

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_IP_AUTH` | `10` | Requests/min per IP on login, register, password-reset |
| `RATE_LIMIT_IP_PUBLIC` | `600` | Requests/min per IP on tiles, health, public-keys |
| `RATE_LIMIT_USER_API` | `300` | Requests/min per user on general authenticated endpoints |
| `RATE_LIMIT_USER_EXPENSIVE` | `20` | Requests/min per user on route and search endpoints |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173` | Comma-separated list of allowed origins |

`AllowCredentials` is always `true` (required for cookie-based auth). Wildcard origins are not supported.

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

The gateway proxies these endpoints to authservice over gRPC. On login, register, and refresh it also sets `access_token` and `refresh_token` cookies (web clients); tokens are always returned in the response body too (mobile clients).

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
| `/api/v1/region/*` | POST | **Access token** | All region endpoints require user JWT |
| `/api/v1/route` | POST | **Access token** | SSE streaming |
| `/api/v1/search` | POST | **Access token** | SSE streaming |
| `/api/v1/search/reverse` | POST | **Access token** | SSE streaming |
| `/v1/tiles/*` | GET | **Access token** | Proxy injects service token to tilesservice |

#### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret","remember_me":false}'
# → 200 {"access_token":"...","refresh_token":"..."}
# Sets access_token and refresh_token cookies for web clients.
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

---

### Region — `/api/v1/region/*`

All region endpoints are public (no authentication required). They proxy directly to regionservice over gRPC.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/region/search-point` | POST | Regions containing a coordinate |
| `/api/v1/region/search-box` | POST | Regions intersecting a bounding box |
| `/api/v1/region/search-radius` | POST | Regions within a radius |
| `/api/v1/region/find-crossing-locations` | POST | Border crossing points |
| `/api/v1/region/find-region-path` | POST | Region sequence for a cross-border route |

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

HTTP reverse proxy to the authservice web server (login pages, email verification, password reset). The `/web` prefix is stripped before forwarding.

```bash
curl http://localhost:8080/web/verify-email?token=...
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
| `main` (untagged) | `v{last}-{date}-dev`, `dev-latest` |
| Other branch | `v{last}-{branch}` |

```bash
# Also push dev-latest on a release tag
FORCE_DEV_LATEST=1 make container-build
```

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
