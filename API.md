# SwayRider API

> **Note:** `api/openapi.yaml` is the authoritative machine-readable specification for this API.
> It is served at `GET /api/openapi.yaml` by the running service. This document is a
> human-friendly companion — when there is a discrepancy, the YAML is correct.

## Overview

The public-facing HTTP API is served by `swayrider-api` on port **8080**. It is the single entry point for mobile and web clients. Requests are reverse-proxied to backend microservices (authservice, regionservice, routerservice, searchservice, tilesservice) behind the scenes.

### Middleware Chain

Every request passes through this middleware pipeline (innermost first):

```
mux  →  BodyLimit  →  RateLimit  →  Logging  →  Auth  →  CORS
```

| Middleware | Responsibility |
|---|---|
| **CORS** | Configurable allowed origins, methods (`GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`), headers (`Authorization`, `Content-Type`), credentials allowed. `CORS_ALLOWED_ORIGINS` entries are whitespace-trimmed, and a bare `*` or empty entry is rejected at startup (wildcard + credentials is an invalid or unsafe combination) |
| **BodyLimit** | Bounds every request body to `MAX_BODY_BYTES` (default 1 MiB); larger bodies are rejected with `413 Payload Too Large` |
| **Auth** | Extracts JWT from `Authorization: Bearer` header or `access_token` cookie and stores claims in context. Does **not** reject unauthenticated requests — individual handlers or downstream middleware decide. Also extracts `refresh_token` cookie, client IP, and secure flag. Client IP comes from `X-Forwarded-For` and the secure flag from `X-Forwarded-Proto`, but **only** when the request's immediate peer is a proxy in `TRUSTED_PROXIES`; otherwise the peer address (`RemoteAddr`) is used and the request is treated as insecure — forged headers can never spoof rate-limit keys or cookie security. |
| **Logging** | Logs every request: method, path, status code, duration (ms), IP, user ID |
| **RateLimit** | Redis-based sliding window rate limiting (60s window). If Redis is unreachable the limiter **degrades** instead of failing open: it serves requests from an in-process sliding window with the same limits (`RATE_LIMIT_DEGRADE_MODE=memory`, default) or rejects every limited request with 429 (`deny`), probing Redis periodically for recovery. A limiter error in this middleware always fails closed (429). |

### Authentication

- **Access token** (JWT, RS256-signed, 15-minute TTL): Carries user identity. Sent as `Authorization: Bearer <token>` header **or** as a namespaced `access_token` HTTP-only cookie (base64-encoded).
- **Refresh token** (64-byte random, 30-day TTL, single-use, bound to IP + User-Agent): Sent as a namespaced `refresh_token` HTTP-only cookie scoped to `/api/v1/auth/refresh`, or in the request body.
- **Service client token** (JWT, RS256-signed, scoped): Used for service-to-service calls. Obtained via `POST /api/v1/auth/token` on the authservice directly.

### Rate Limiting

Rate limits are configured per-class via environment variables. Defaults apply if not set:

| Class | Key | Applies To |
|---|---|---|
| `auth` | Client IP | `/api/v1/auth/login`, `/api/v1/auth/register`, `/api/v1/auth/request-password-reset`, `/api/v1/auth/verify-email` |
| `public` | Client IP | `/health`, `/v1/tiles/*`, `/api/v1/auth/public-keys` |
| `expensive` | User ID, or IP when unauthenticated | `/api/v1/route`, `/api/v1/search*` |
| `api` | User ID, or IP when unauthenticated | All other endpoints (refresh, logout, reset-password, check-password-strength, region, admin, `/web/*`, …) |

---

## Endpoints

### Health

#### `GET /health`

- **Security:** Public (no auth required)
- **Rate limit class:** `public`
- **Response (200):**
  ```json
  {
    "status": "ok",
    "service": "swayrider-api"
  }
  ```

---

### Auth — Public Endpoints

These endpoints are registered directly on the mux without `RequireVerifiedUser` or `RequireAdmin` middleware. The Auth middleware still runs (injects claims if a token is present), but these handlers work with or without authentication.

#### `POST /api/v1/auth/login`

Authenticate with email and password. Returns access + refresh token pair. Sets both as HTTP-only cookies scoped to `/` (access) and `/api/v1/auth/refresh` (refresh).

- **Security:** Public
- **Rate limit class:** `auth`
- **Request:**
  ```json
  {
    "email": "user@example.com",
    "password": "securePassword123!",
    "remember_me": false
  }
  ```
- **Response (200):**
  ```json
  {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "64-byte-hex-string"
  }
  ```
- **Errors:** 401 (invalid credentials), 429 (rate limit)

#### `POST /api/v1/auth/register`

Create a new user account.

- **Security:** Public
- **Rate limit class:** `auth`
- **Request:**
  ```json
  {
    "email": "user@example.com",
    "password": "securePassword123!",
    "verification_url": "https://example.com/verify"
  }
  ```
- **Response (200):**
  ```json
  {
    "user_id": "uuid-string",
    "message": "user created"
  }
  ```
- **Errors:** 400 (invalid input), 409 (already exists), 429 (rate limit)

#### `POST /api/v1/auth/refresh`

Exchange a refresh token for a new access + refresh token pair (token rotation). Accepts refresh token from the `refresh_token` cookie (set by login) or from the request body.

- **Security:** Public (valid refresh token required)
- **Request (cookie):** No body needed — reads `refresh_token` cookie from context
- **Request (body):**
  ```json
  {
    "refresh_token": "64-byte-hex-string",
    "remember_me": false
  }
  ```
- **Response (200):**
  ```json
  {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "64-byte-hex-string"
  }
  ```
- **Errors:** 400 (missing token), 401 (invalid/expired/revoked token)

#### `POST /api/v1/auth/logout`

Invalidate the current refresh token. Accepts token from cookie or request body. Clears auth cookies.

- **Security:** Public (valid refresh token required)
- **Request (cookie):** No body needed
- **Request (body):**
  ```json
  {
    "refresh_token": "64-byte-hex-string"
  }
  ```
- **Response:** 204 No Content
- **Errors:** 401 (invalid token)

#### `POST /api/v1/auth/request-password-reset`

Initiate the password reset flow. Always returns 204 to prevent email enumeration.

- **Security:** Public
- **Rate limit class:** `auth`
- **Request:**
  ```json
  {
    "email": "user@example.com",
    "reset_url": "https://example.com/reset-password"
  }
  ```
- **Response:** 204 No Content
- **Errors:** 429 (rate limit)

#### `POST /api/v1/auth/reset-password`

Complete the password reset with a token received via email.

- **Security:** Public
- **Request:**
  ```json
  {
    "user_id": "uuid-string",
    "token": "reset-token-string",
    "new_password": "newSecurePassword123!"
  }
  ```
- **Response (200):**
  ```json
  {
    "message": "password updated"
  }
  ```
- **Errors:** 400 (invalid/expired token)

#### `POST /api/v1/auth/verify-email`

Request a new verification email to be sent.

- **Security:** Public
- **Rate limit class:** `auth`
- **Request:**
  ```json
  {
    "email": "user@example.com",
    "verification_url": "https://example.com/verify"
  }
  ```
- **Response:** 204 No Content

#### `POST /api/v1/auth/change-password`

Change the authenticated user's password. Requires a valid JWT (extracted from `Authorization` header or cookie by the Auth middleware).

- **Security:** Valid JWT required (email may be unverified)
- **Request:**
  ```json
  {
    "old_password": "currentPassword",
    "new_password": "newSecurePassword123!"
  }
  ```
- **Response (200):**
  ```json
  {
    "message": "password changed"
  }
  ```
- **Errors:** 401 (missing/invalid JWT), 400 (wrong old password)

#### `POST /api/v1/auth/check-password-strength`

Validate password strength without creating an account.

- **Security:** Public
- **Request:**
  ```json
  {
    "password": "testPassword123!"
  }
  ```
- **Response (200):**
  ```json
  {
    "is_strong": true,
    "message": "Password is strong"
  }
  ```

#### `GET /api/v1/auth/public-keys`

Retrieve the cached JWT RS256 public verification keys. No downstream gRPC call — returns the in-memory cache.

- **Security:** Public
- **Rate limit class:** `public`
- **Response (200):**
  ```json
  {
    "keys": [
      "-----BEGIN PUBLIC KEY-----\nMIIBIj...\n-----END PUBLIC KEY-----"
    ]
  }
  ```

#### `GET /api/v1/auth/whoami`

Get information about the currently authenticated user (makes a gRPC call to authservice).

- **Security:** Valid JWT required (email may be unverified)
- **Response (200):**
  ```json
  {
    "user_id": "uuid-string",
    "email": "user@example.com",
    "is_verified": true,
    "is_admin": false,
    "account_type": "free"
  }
  ```
- **Errors:** 401 (missing/invalid JWT)

#### `GET /api/v1/auth/me`

Get the authenticated user's claims directly from the JWT (no downstream gRPC call). Returns data parsed from the token itself.

- **Security:** Valid JWT required
- **Response (200):**
  ```json
  {
    "user_id": "uuid-string",
    "email": "user@example.com",
    "email_verified": true
  }
  ```
- **Errors:** 401 (missing/invalid JWT)

---

### Route

#### `POST /api/v1/route`

Plan a route between two coordinates. Uses **Server-Sent Events (SSE)** for async delivery.

- **Security:** Verified user required — `RequireVerifiedUser` middleware (401 if no JWT, 403 if email not verified)
- **Rate limit class:** `expensive` (per user)
- **Request:**
  ```json
  {
    "from": { "lat": 51.05, "lon": 3.72 },
    "to": { "lat": 48.85, "lon": 2.35 },
    "waypoints": [
      { "lat": 50.5, "lon": 3.5, "type": "via" }
    ],
    "vehicle": "car",
    "unit": "kilometers",
    "language": "en-US",
    "options": {
      "avoidTollRoads": false,
      "avoidHighways": false,
      "avoidFerries": false,
      "scenicPreference": 0,
      "highwayAvoidance": 0,
      "tollAvoidance": 0,
      "unpavedHandling": "neutral"
    }
  }
  ```

**`vehicle` values:** `car`, `motorscooter`, `motorcycle`

**Waypoint `type` values:** `break` (default — split route into legs, allow u-turns), `through` (no u-turns, no leg split), `via` (allow u-turns, no leg split)

- **SSE response:** See [SSE Protocol](#sse-protocol) below.
  - Event `queued`: `{"job_id": "...", "queue_position": 5}`
  - Event `result`: Route result object with trip, legs, maneuvers, summary
  - Event `error`: `{"error": "..."}`
- **Errors:** 401/403 (auth), 429 (queue full, `Retry-After: 30`), 500 (internal)

---

### Search

#### `POST /api/v1/search`

Forward geocoding — search for locations by text query. Uses **SSE** for async delivery.

- **Security:** Verified user required
- **Rate limit class:** `expensive` (per user)
- **Request:**
  ```json
  {
    "text": "Ghent",
    "viewport": {
      "bottomLeft": { "lat": 50.5, "lon": 3.0 },
      "topRight": { "lat": 51.5, "lon": 4.5 }
    },
    "focusPoint": { "lat": 51.05, "lon": 3.72 },
    "size": 10,
    "language": "en"
  }
  ```
- **SSE response:** See [SSE Protocol](#sse-protocol).
  - Event `result`:
  ```json
  [
    {
      "label": "Ghent, Flanders, Belgium",
      "locality": "Ghent",
      "region": "Flanders",
      "country": "Belgium",
      "confidence": 0.99,
      "layer": "locality",
      "lat": 51.05,
      "lon": 3.72,
      "street": "",
      "houseNumber": "",
      "id": "pelias-id",
      "localAdmin": "Gent",
      "countryCode": "BE",
      "name": "Ghent"
    }
  ]
  ```

#### `POST /api/v1/search/reverse`

Reverse geocoding — find addresses for a coordinate. Uses **SSE** for async delivery.

- **Security:** Verified user required
- **Rate limit class:** `expensive` (per user)
- **Request:**
  ```json
  {
    "lat": 51.05,
    "lon": 3.72,
    "size": 5,
    "language": "en"
  }
  ```
- **SSE response:** Same `SearchItem[]` format as search.

---

### Region

All region endpoints require a verified user. They are synchronous (not SSE) — the gateway forwards the request to a worker pool and returns the response directly.

#### `POST /api/v1/region/search-point`

Find which regions contain a coordinate.

- **Security:** Verified user required
- **Request:**
  ```json
  {
    "location": { "lat": 51.05, "lon": 3.72 },
    "include_extended": false
  }
  ```
- **Response (200):**
  ```json
  {
    "core_regions": ["be"],
    "extended_regions": []
  }
  ```

#### `POST /api/v1/region/search-box`

Find which regions intersect a bounding box.

- **Security:** Verified user required
- **Request:**
  ```json
  {
    "box": {
      "bottom_left": { "lat": 50.0, "lon": 2.0 },
      "top_right": { "lat": 52.0, "lon": 5.0 }
    },
    "include_extended": false
  }
  ```
- **Response (200):**
  ```json
  {
    "core_regions": ["be", "nl", "fr"],
    "extended_regions": []
  }
  ```

#### `POST /api/v1/region/search-radius`

Find which regions are within a radius of a point.

- **Security:** Verified user required
- **Request:**
  ```json
  {
    "location": { "lat": 51.05, "lon": 3.72 },
    "radius_km": 50.0,
    "include_extended": false
  }
  ```
- **Response (200):**
  ```json
  {
    "core_regions": ["be"],
    "extended_regions": []
  }
  ```

#### `POST /api/v1/region/find-crossing-locations`

Find border crossings between two regions along a general direction.

- **Security:** Verified user required
- **Request:**
  ```json
  {
    "from_region": "be",
    "to_region": "fr",
    "from_location": { "lat": 51.05, "lon": 3.72 },
    "to_location": { "lat": 48.85, "lon": 2.35 },
    "limit": 3,
    "config": {
      "type": "simple",
      "road_type_order": ["MOTORWAY", "TRUNK", "PRIMARY", "SECONDARY"],
      "road_type_delta": 10000,
      "drop_distance": 1000
    }
  }
  ```

  **`config.type`:** `"simple"` (default) or `"advanced"`

  **`road_type_order` values:** `MOTORWAY`, `TRUNK`, `PRIMARY`, `SECONDARY`

- **Response (200):**
  ```json
  {
    "crossings": [
      {
        "from_region": "be",
        "to_region": "fr",
        "road_type": "MOTORWAY",
        "location": { "lat": 50.75, "lon": 3.2 },
        "osm_id": 123456789
      }
    ]
  }
  ```

#### `POST /api/v1/region/find-region-path`

Find a path of contiguous regions from one region to another.

- **Security:** Verified user required
- **Request:**
  ```json
  {
    "from_region": "be",
    "to_region": "es"
  }
  ```
- **Response (200):**
  ```json
  {
    "path": ["be", "fr", "es"]
  }
  ```

#### `POST /api/v1/region/find-route-region-paths`

Find all corridor-constrained region paths for a polyline (route shape).

- **Security:** Verified user required
- **Request:**
  ```json
  {
    "waypoints": [
      { "lat": 51.05, "lon": 3.72 },
      { "lat": 48.85, "lon": 2.35 }
    ],
    "width_km": 10.0
  }
  ```
- **Response (200):**
  ```json
  {
    "paths": [
      ["be", "fr"],
      ["be", "lu", "fr"]
    ]
  }
  ```

---

### Tiles

#### `GET /v1/tiles/{path}`

Reverse proxy to `tilesservice`. Injects a service client token with `tiles:serve` scope into the `Authorization` header. All endpoints under `/v1/tiles/` are proxied.

- **Security:** Verified user required (`RequireVerifiedUser` middleware)
- **Rate limit class:** `public` (IP-based)
- **Path:** Anything under `/v1/tiles/` — the full path is forwarded to tilesservice.

For the full tiles sub-API, see the upstream service:
- `GET /v1/tiles/ping` — Health check (public)
- `GET /v1/tiles/styles` — List map styles (requires `tiles:serve` scope)
- `GET /v1/tiles/styles/{name}` — Serve a MapLibre GL style (requires `tiles:serve` scope)
- `GET /v1/tiles/{tileset}/{z}/{x}/{y}` — Serve MVT vector tile (requires `tiles:serve` scope)

---

### Auth — Admin Endpoints

All admin endpoints require a valid JWT with `is_admin=true`. The `RequireAdmin` middleware returns **401** if no JWT is present and **403** if the user is not an admin.

#### `POST /api/v1/auth/admin/create-admin`

Create a new admin user.

- **Security:** Admin required
- **Request:**
  ```json
  {
    "email": "admin@example.com",
    "password": "securePassword123!"
  }
  ```
- **Response (200):**
  ```json
  {
    "user_id": "uuid-string",
    "message": "admin created"
  }
  ```

#### `POST /api/v1/auth/admin/change-account-type`

Change a user's account level.

- **Security:** Admin required
- **Request:**
  ```json
  {
    "userId": "uuid-string",
    "accountType": "premium"
  }
  ```
- **Response (200):**
  ```json
  {
    "message": "account type updated"
  }
  ```
- **Notes:** Account type is a free-form string (e.g. `"free"`, `"standard"`, `"premium"`).

#### `POST /api/v1/auth/admin/whois`

Look up any user by email or user ID.

- **Security:** Admin required
- **Request:**
  ```json
  {
    "email": "user@example.com"
  }
  ```
  or
  ```json
  {
    "userId": "uuid-string"
  }
  ```
- **Response (200):**
  ```json
  {
    "user_id": "uuid-string",
    "email": "user@example.com",
    "is_verified": true,
    "is_admin": false,
    "account_type": "free"
  }
  ```
- **Errors:** 400 (neither email nor userId provided)

#### `POST /api/v1/auth/admin/create-service-client`

Register a new service-to-service client. Returns the generated client ID and secret.

- **Security:** Admin required
- **Request:**
  ```json
  {
    "name": "my-service",
    "description": "Service for doing X",
    "scopes": ["email:send", "region:query"]
  }
  ```
- **Response (200):**
  ```json
  {
    "client_id": "svc-generated-id",
    "client_secret": "generated-secret"
  }
  ```

#### `POST /api/v1/auth/admin/delete-service-client`

Remove a service client.

- **Security:** Admin required
- **Request:**
  ```json
  {
    "clientId": "svc-client-id"
  }
  ```
- **Response (200):**
  ```json
  {
    "message": "service client deleted"
  }
  ```

#### `GET /api/v1/auth/admin/list-service-clients`

List all registered service clients with pagination.

- **Security:** Admin required
- **Query params:** `page` (int, default 1), `pageSize` (int, default 20)
- **Response (200):**
  ```json
  {
    "clients": [
      {
        "client_id": "svc-id",
        "name": "my-service",
        "description": "Service for doing X",
        "scopes": ["email:send", "region:query"]
      }
    ],
    "num_clients": 1
  }
  ```

#### `POST /api/v1/auth/admin/invite-user`

Add an email to the registration invite list. Only effective when `REGISTRATION_MODE=invite_only`.

- **Security:** Admin required
- **Request:**
  ```json
  {
    "email": "invited@example.com"
  }
  ```
- **Response (200):**
  ```json
  {
    "message": "user invited"
  }
  ```

#### `POST /api/v1/auth/admin/revoke-invite`

Remove an email from the registration invite list.

- **Security:** Admin required
- **Request:**
  ```json
  {
    "email": "invited@example.com"
  }
  ```
- **Response (200):**
  ```json
  {
    "message": "invite revoked"
  }
  ```

#### `GET /api/v1/auth/admin/list-invites`

List pending registration invites with pagination.

- **Security:** Admin required
- **Query params:** `page` (int, default 1), `pageSize` (int, default 20), `registered` (bool, optional — filter by registration status)
- **Response (200):**
  ```json
  {
    "invites": [
      {
        "id": "uuid-string",
        "email": "invited@example.com",
        "created_at": "2026-06-01T12:00:00Z",
        "registered": false
      }
    ],
    "num_invites": 1
  }
  ```

---

### Web Pages

#### `GET /web/{path}`
#### `GET /web/`

Reverse proxy to `authservice`'s embedded web server (HTTP port configured via `AUTHSERVICE_WEB_PORT`, default 8000). Serves HTML pages for email verification and password reset flows. The gateway maps its `/web` namespace onto the path authservice mounts under (`AUTHSERVICE_WEB_PATH_PREFIX`, default `/web` — must match authservice's `WEB_PATH_PREFIX`).

- **Security:** Public (no auth middleware)
- **Available pages:** `/web/verify-user`, `/web/reset-password`, `/web/register`, `/web/registration-complete`, `/web/`, `/web/index.html`

---

## SSE Protocol

The route (`/api/v1/route`) and search (`/api/v1/search`, `/api/v1/search/reverse`) endpoints deliver results asynchronously via **Server-Sent Events (SSE)**.

### Flow

1. Client sends a `POST` request with the operation payload as JSON body.
2. Server validates auth, enqueues the job, and responds with `Content-Type: text/event-stream`.
3. Server sends events as the job progresses.

Results are scoped to the submitting user: the gateway verifies the stored result's owner (the authenticated user who enqueued the job) before emitting it, so a result cannot be read via a leaked `job_id`. Jobs also carry the submitting user's identity downstream as gRPC metadata (`x-user-id`, `x-account-level`, …) — see the README's "Forwarded user identity (trust chain)" section; downstream services must not treat that metadata as authentication.

### Event Types

| Event | Description | Data |
|---|---|---|
| `queued` | Job accepted into queue | `{"job_id": "...", "queue_position": N}` |
| `result` | Operation completed successfully | Operation-specific result JSON |
| `error` | Operation failed | `{"error": "..."}` |

### Example

```
event: queued
data: {"job_id":"abc123","queue_position":3}

event: result
data: {"trip":{...},"summary":{...}}

event: error
data: {"error":"no route found"}
```

---

## Error Codes

| Status | Meaning | Typical Causes |
|---|---|---|
| **200** | Success | — |
| **204** | Success (no content) | Password reset request, logout, verify email |
| **400** | Bad Request | Invalid JSON body, missing required fields, invalid token format |
| **401** | Unauthorized | Missing/invalid/expired JWT, invalid credentials |
| **403** | Forbidden | Authenticated but not admin, email not verified |
| **404** | Not Found | User/entity not found |
| **409** | Conflict | User already exists, failed precondition |
| **429** | Too Many Requests | Rate limit exceeded, queue full (with `Retry-After` header) |
| **500** | Internal Server Error | Downstream service failure, unexpected error |
| **503** | Service Unavailable | Missing JWT keys, downstream unavailable |

Errors are returned as JSON:
```json
{
  "error": "descriptive error message"
}
```

## Endpoint Summary

| Method | Path | Security | Rate Limit |
|--------|------|----------|------------|
| `GET` | `/health` | Public | `public` |
| `POST` | `/api/v1/auth/login` | Public | `auth` |
| `POST` | `/api/v1/auth/register` | Public | `auth` |
| `POST` | `/api/v1/auth/refresh` | Public | `api` |
| `POST` | `/api/v1/auth/logout` | Public | `api` |
| `POST` | `/api/v1/auth/request-password-reset` | Public | `auth` |
| `POST` | `/api/v1/auth/reset-password` | Public | `api` |
| `POST` | `/api/v1/auth/verify-email` | Public | `auth` |
| `POST` | `/api/v1/auth/change-password` | JWT required | `api` |
| `POST` | `/api/v1/auth/check-password-strength` | Public | `api` |
| `GET` | `/api/v1/auth/public-keys` | Public | `public` |
| `GET` | `/api/v1/auth/whoami` | JWT required | `api` |
| `GET` | `/api/v1/auth/me` | JWT required | `api` |
| `POST` | `/api/v1/route` | Verified user | `expensive` |
| `POST` | `/api/v1/search` | Verified user | `expensive` |
| `POST` | `/api/v1/search/reverse` | Verified user | `expensive` |
| `POST` | `/api/v1/region/search-point` | Verified user | `api` |
| `POST` | `/api/v1/region/search-box` | Verified user | `api` |
| `POST` | `/api/v1/region/search-radius` | Verified user | `api` |
| `POST` | `/api/v1/region/find-crossing-locations` | Verified user | `api` |
| `POST` | `/api/v1/region/find-region-path` | Verified user | `api` |
| `POST` | `/api/v1/region/find-route-region-paths` | Verified user | `api` |
| `(any)` | `/v1/tiles/*` | Verified user (proxy) | `public` |
| `(any)` | `/web/*` | Public (proxy) | `api` |
| `POST` | `/api/v1/auth/admin/create-admin` | Admin | `api` |
| `POST` | `/api/v1/auth/admin/change-account-type` | Admin | `api` |
| `POST` | `/api/v1/auth/admin/whois` | Admin | `api` |
| `POST` | `/api/v1/auth/admin/create-service-client` | Admin | `api` |
| `POST` | `/api/v1/auth/admin/delete-service-client` | Admin | `api` |
| `GET` | `/api/v1/auth/admin/list-service-clients` | Admin | `api` |
| `POST` | `/api/v1/auth/admin/invite-user` | Admin | `api` |
| `POST` | `/api/v1/auth/admin/revoke-invite` | Admin | `api` |
| `GET` | `/api/v1/auth/admin/list-invites` | Admin | `api` |
