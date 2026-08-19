# Deep Review — `swayrider-api`

Date: 2026-08-16
Scope: `swayrider-api` (main, config, middleware, rate limiter, JWT key cache, service-token manager, circuit breakers, queue/SSE, and all handlers).
Method: static review only. **No code changes were made.**

---

## Summary

`swayrider-api` is a well-structured gateway: clean middleware chain (Auth → Logging → RateLimit → mux), centralized authorization wrappers (`RequireAdmin` / `RequireVerifiedUser`), rotating-key JWT verification, scoped service-token management, per-class rate limiting, circuit breakers, and a Redis-Streams job queue with SSE delivery. The architecture is sound. The issues below are concentrated in four areas: **rate-limiting gaps**, **trust of client-supplied proxy headers**, **leakage of tokens/error details**, and **a service-token refresh loop that can silently wedge forever** (#4 — confirmed already happening in the dev environment, not theoretical).

---

## High

### 1. ~~Rate limiting silently skips all unauthenticated "api"-class requests~~ — FIXED 2026-08-17
`internal/middleware/ratelimit.go`

**Fix:** The classifier and the limiter switch were reworked so **every** request is limited. `verify-email` (and `forgot-password`) moved into the `auth` class (per-IP); unauthenticated requests to per-user (`api`/`expensive`) endpoints — `refresh`, `logout`, `reset-password`, `check-password-strength`, and token-less floods aimed at protected endpoints — are now limited per IP via `RATE_LIMIT_IP_API` instead of falling through to `allowed = true`; and the `default` branch fails closed (unknown class → deny) rather than allow. Covered by `TestEndpointClass`, `TestRateLimitAuthClassLimitsPerIP`, `TestRateLimitUnauthenticatedPerUserClassLimitsPerIP`, and `TestRateLimitDeniedReturns429` in `internal/middleware/ratelimit_test.go`.

The `default` branch of the classifier is `return "api", true` (per-user), and the switch falls through to `allowed = true` whenever `perUser && authed` is false:

```go
case perUser && authed:
    ... per-user limit ...
default:
    allowed = true
```

Consequence: **any unauthenticated request to an endpoint that isn't in the `auth` or `public` class is never rate-limited.** That includes:

- `POST /api/v1/auth/verify-email` — sends email to *any* address, unlimited → email-bombing vector.
- `POST /api/v1/auth/reset-password` — token submission, unthrottled (256-bit token makes brute force impractical, but still wrong).
- `POST /api/v1/auth/refresh`, `logout`, `check-password-strength` — unthrottled.
- `whoami`, `me`, all admin/region/route/search endpoints — unauthenticated requests get 401/403 from the auth wrappers, but they're **not throttled**, so the rate limiter gives no protection against unauthenticated flooding.

Only `login`, `register`, `request-password-reset` (auth class) and `health`, `tiles`, `public-keys` (public class) are actually limited per IP. `verify-email` in particular should be in the `auth` class but isn't.

### 2. ~~Client IP is taken from a spoofable header with no trusted-proxy check~~ — FIXED 2026-08-17
`internal/middleware/auth.go` `clientIP()`

**Fix:** `Auth()` now takes a trusted-proxy set parsed once at startup from the new `TRUSTED_PROXIES` config (comma-separated CIDRs, default empty = trust no one; wired in `internal/config/config.go` and `internal/server/server.go`). Only requests whose immediate TCP peer is inside the set have `X-Forwarded-For`/`X-Forwarded-Proto` honored; the client IP is then the **rightmost** XFF entry that is not itself a trusted proxy (correct for `internet → apache → traefik → api` chains), and `SecureKey` is derived from `X-Forwarded-Proto` only for trusted peers. From any other peer the headers are ignored and `RemoteAddr` is used — a forged header can no longer spoof rate-limit keys or force `Secure: false` cookies. Infra pins Traefik to `10.10.0.2` in both `layer-00` files and sets `TRUSTED_PROXIES=10.10.0.2/32` in `layer-30`; the direct dev port `34000` is intentionally *not* trusted — WireGuard dev connections arrive from the docker gateway and are rate-limited by that address. Covered by `internal/middleware/auth_test.go` (untrusted-peer spoofing, single/chained XFF, multi-proxy chains, IPv6, Secure-flag matrix); docs updated in `env.example`, `README.md`, `API.md`.

```go
if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
    ... return first value ...
}
```

The comment says "trust X-Forwarded-For from Traefik", but the code trusts it unconditionally. The service binds `:8080` directly (no TLS, no source-IP restriction). If it is reachable without going through Traefik (which is true in the dev stack, and true in any misconfiguration), an attacker can send a fresh `X-Forwarded-For` per request and **completely bypass the IP-based `auth`/`public` rate limits** — including the 10/min login throttling. Combined with the authservice having no rate limiting of its own, this erodes the platform's brute-force protection. The `SecureKey` flag (`X-Forwarded-Proto`) is derived the same way, so a direct client can also force `Secure: false` on issued cookies.

### 3. ~~Rate limiter fails open and discards the error~~ - FIXED 2026-08-17
`internal/ratelimit/limiter.go`, `internal/middleware/ratelimit.go`

```go
if _, err := pipe.Exec(ctx); err != nil {
    return true, err   // allow on Redis error
}
...
_ = err   // fail open on Redis error (Allow already does this)
```

When Redis is down, **all rate limiting is disabled** for every request. This is an explicit "fail open" choice, but for an externally-reachable security boundary it deserves a deliberate review — an attacker who can degrade Redis (or just during a Redis outage) gets unlimited requests. Fail-closed (or at least a local in-process fallback limiter) is worth considering.

### 4. ~~Service-token refresh can silently wedge forever after one transient failure — confirmed happening right now~~ - FIXED 2026-08-17
`internal/servicetoken/manager.go`

```go
func (m *Manager) Start(ctx context.Context) {
	m.refresh()
	go func() {
		for {
			m.mu.RLock()
			ttl := time.Until(m.expiry) - 3*time.Minute
			m.mu.RUnlock()
			if ttl < 0 {
				ttl = 30 * time.Second
			}
			select {
			case <-time.After(ttl):
				m.refresh()
			case <-ctx.Done():
				return
			}
		}
	}()
}
```

The retry math here is fine in isolation (`ctx` is `context.Background()`, so it never cancels; a failed refresh correctly reschedules for 30s later once the cached token is near/past expiry). The problem is one layer down: nothing bounds the goroutine as a whole. Each downstream call inside `refresh()` → `authclient.Client.GetToken()` is individually wrapped in a 5s context deadline (`grpcclients/authclient/config.go`), but `GetToken` first calls `CheckConnection()`/`Ping()`, and if a call anywhere in that chain gets stuck instead of returning (even briefly, e.g. during a connectivity blip to authservice), the entire background goroutine blocks *inside* `m.refresh()` and never returns to the loop — so it never logs again, success or failure, and never retries again. The rest of the process is unaffected (no crash, no restart), which is exactly what makes this invisible.

Since `Token()` just returns whatever is cached, every consumer of `tokenMgr.Token` — `NewTilesProxy`, `NewRegionHandler`, and the route/search worker pools (`NewRouteProcessFn`, `NewSearchProcessFn`) — keeps injecting that same stale token into every proxied or queued call, forever, with zero error surfaced anywhere in swayrider-api's own logs.

**Confirmed in the dev environment (not hypothetical):** `sw-dev-swayrider-api` has been running continuously ("Up 4 weeks", no restart) since before 2026-07-14. `docker logs sw-dev-swayrider-api | grep "service token"` shows a clean ~12-minute refresh cadence for weeks, then:
```
2026/07/14 07:23:58  service token refreshed, expires at 2026-07-14T07:38:58Z
2026/07/14 07:32:07  ERROR failed to refresh service token: ... dial tcp 10.10.1.3:8081: connect: connection refused
```
— and nothing since. Every tiles/region/route/search call proxied through this gateway has been running on a token that expired over four weeks ago, which is the confirmed root cause of the map-tile-loading failures reported against the mobile client.

This is currently listed only as a one-line "can be stale" caveat under Low/consistency below — that undersells it substantially. The actual failure mode isn't transient staleness self-healing on the next tick; it's a permanent, silent, unrecoverable-without-a-process-restart outage of every downstream service the gateway depends on, triggered by one ordinary network blip.

**Fix**: don't let a single stuck call wedge the loop indefinitely — give `m.refresh()` its own bounded timeout independent of whatever `authclient` does internally (e.g. run the call in a child goroutine and `select` against `time.After`), recover from a panic and relaunch the background goroutine if it ever dies, and log/alert when "time since last successful refresh" exceeds the token TTL so a stall is visible instead of silent.

---

## Medium

### 5. ~~No request-body size limit~~ - FIXED 2026-08-17
`internal/handlers/auth.go` `decodeBody()` uses `json.NewDecoder(r.Body).Decode(dst)` with no `http.MaxBytesReader` and no `ContentLength` check (confirmed: zero hits for `MaxBytesReader`/`LimitReader`/`http.Timeout` in the module). Public JSON endpoints (`login`, `register`, `reset-password`, `route`, `search`, region) can be sent arbitrarily large bodies, a straightforward memory-exhaustion DoS vector.

### 6. Raw gRPC error text is returned to clients; status mapping is substring-based - FIXED 2026-08-17
`internal/handlers/auth.go` `grpcStatus()` / `errBody()`

```go
func errBody(err error) map[string]string { return map[string]string{"error": err.Error()} }
```

`err.Error()` for a gRPC failure is `rpc error: code = X desc = Y`, so the full downstream `desc` is echoed to the client — leaking internal detail (SQL errors, service internals, and the authservice's enumeration messages like "user with email X already exists"). Status codes are derived via `strings.Contains(msg, "NotFound")` etc., which is fragile (any message containing those words is misclassified). `queue.GrpcErrToJobError` has the same pattern. Consider mapping from `status.Code(err)` and returning sanitized messages.

### 7. ~~CORS `AllowCredentials: true` + configurable origins~~ - FIXED 2026-08-17
`internal/server/server.go`

`AllowCredentials` is hard-coded `true` and origins come from `CORS_ALLOWED_ORIGINS` (default `http://localhost:5173`). The README claims "wildcard origins are not supported", but the code passes the list straight to `rs/cors`. If anyone sets `CORS_ALLOWED_ORIGINS=*`, credentialed cross-origin requests become allowed (rs/cors reflects the origin when credentials are enabled), which undermines CSRF protection for cookie-authenticated web clients. Worth an explicit config guard or validation.

### ~~8. Reverse proxies forward the `access_token` cookie downstream~~ - FIXED 2026-08-17
`internal/handlers/tiles.go`, `internal/handlers/web.go`

`httputil.NewSingleHostReverseProxy` copies all request headers, including `Cookie`. The `access_token` cookie is scoped to `/`, so the browser sends it to `/v1/tiles/*` and `/web/*`, and the proxies forward it to tilesservice and the authservice web server. The tiles proxy overrides `Authorization`, but the user's access token still reaches downstream services that don't need it. Low-severity (short TTL, internal trust), but an avoidable token-scope leak.

### 9. ~~Job results are retrievable without authorization~~ - FIXED 2026-08-17
`internal/sse/hub.go`, `internal/queue/worker.go`

Results are cached at `sw:result:{jobID}` and published on `sw:done:{jobID}`. `WaitForResult` looks them up by `jobID` alone — there is no check that the requesting user owns the job. `jobID` is a UUID (unguessable in practice), but if a job ID leaks (logs, referer, shared caches) any client can read another user's full route/search result (which is location PII) for up to `RESULT_TTL_SECONDS` (300s).

### 10. ~~User identity is forwarded downstream as unauthenticated metadata~~ — FIXED 2026-08-17 (documented & audited)
`internal/queue/result.go` `UserMetadataCtx()`, `swlib/security/context.go`, `swayrider-api/README.md`

**Fix:** The trust chain is now documented and audited instead of implicit. The gateway forwards `x-user-id`, `x-account-level`, `x-is-admin`, `x-user-verified` only on the route/search worker paths (region forwards none). Downstream resolution (`ResolveUserID` / `ResolveAccountLevel`) consults the metadata only when the caller holds a verified service token with the endpoint's required scopes — `AuthInterceptor` enforces this before claims enter context — and the doc comments now state that the metadata is a gateway-forwarded hint, never authentication, and must not alone authorize privileged operations. `ResolveAccountLevel` was normalized to the same explicit service-caller guard as `ResolveUserID`, and tests lock the invariant that a user-JWT caller can never resolve to forged `x-user-*` metadata. Audit findings: `ResolveUserID` / `ResolveAccountLevel` currently have **no callers** in any downstream service (the impersonation surface is latent, not live), and `x-is-admin` / `x-user-verified` are write-only — forwarded but unread, kept as reserved. The only service client holding the `region:query routing:execute search:execute tiles:serve` scopes is the gateway itself. Documented in `swayrider-api/README.md` ("Forwarded user identity (trust chain)").

The gateway forwards `x-user-id`, `x-account-level`, `x-is-admin`, `x-user-verified` as gRPC metadata alongside its own scoped service token, and (in `swlib/security`) downstream services resolve the "user" from those headers when the caller holds a service token. This means **any holder of a routing/search-scoped service token can impersonate any user** by setting `x-user-id`. That's the inherent cost of the gateway-forwarded-identity pattern, and it's fine *if* the gateway's token is the only one with those scopes and downstream services never trust the metadata unless the caller is authenticated — but it's a trust-chain property worth documenting and auditing explicitly.

### 11. ~~Login logs the email address (PII)~~ — FIXED 2026-08-17
`internal/handlers/auth.go`

**Fix:** Login logs now write a deterministic SHA-256 prefix (`email_hash`) instead of the raw address, keeping repeated attempts against the same account correlatable for forensics without storing PII or leaving an account-existence enumeration trail. The logged downstream error was already non-enumerating (authservice returns a uniform "invalid email or password"). Covered by `TestEmailHash_*` in `internal/handlers/auth_test.go`.

`lg.Infof("login ok email=%s ip=%s", ...)` and `lg.Warnf("login failed email=%s ...")` write raw email addresses at info/warn level. In addition to PII retention concerns, failed-login logs are effectively an account-existence enumeration trail for anyone with log access.

---

## Low / consistency

- **README vs. code — region endpoints.** The README says region endpoints are "public (no auth required)"; `routes.go` and `API.md` say (and enforce) *verified user required*. The code is stricter, so no vulnerability — but the README is misleading for a security-relevant surface.
- **`/web` prefix handling.** README/API.md state the proxy "strips the `/web` prefix"; the code does not rewrite the path. It works only because the authservice web server mounts its routes under `/web`. Doc/code mismatch; a change to `WEB_PATH_PREFIX` would silently break it.
- **`Refresh` drops `remember_me` for cookie-based tokens.** When the refresh token comes from the cookie, `rememberMe` stays `false`, so the refreshed cookie reverts to the 2-hour default TTL rather than the 30-day "remember me" lifetime.
- **Workers ACK even on error** (`defer XAck` in `processMessage`) — no retry or dead-letter queue, so transient failures (including an open circuit breaker) permanently drop jobs.
- **HTTP proxies use default transports** — no dial/response timeouts on the tiles/web reverse proxies.
- **SSE hard 30s timeout** even if the job is still running (result remains in Redis but the client is told "timeout").
- **`/api/v1/auth/me`** returns `email_verified: null` for non-user tokens.
- **`/api/v1/search/autocomplete`** exists in routes but is absent from the API.md endpoint summary (doc drift).

---

## Positive observations

- Clear, well-layered middleware; authorization centralized in `RequireAdmin`/`RequireVerifiedUser` plus handler-level JWT checks (no endpoint accidentally unauthenticated).
- JWT verification against a key cache that refreshes hourly and supports rotation (tries all valid keys).
- Scoped service token auto-refreshed 3 minutes before expiry.
- Per-class rate limiting (auth/public/expensive/api) and queue-depth limiting (`QUEUE_MAX_DEPTH` → 429 + `Retry-After`).
- Per-service circuit breakers (open after 5 consecutive failures, half-open probing).
- Redis Streams consumer groups for reliable worker fan-out.
- `SameSite=Strict` cookies; refresh cookie path-scoped to `/api/v1/auth/refresh`.
- Public keys served from cache without a downstream call.
- User identity fields on queued jobs are derived from verified JWT claims, not from client input.

---

## Suggested fix order

1. **#4** — confirmed live outage, not theoretical: restart `swayrider-api` now to recover the wedged service token, then fix the refresh loop so a single stuck call can't wedge it again silently.
2. **#1** — make `verify-email` (and the other public `api`-class endpoints) actually rate-limited (per-IP), and rework the classifier so unauthenticated requests can't fall through to `allowed = true`.
3. **#2** — only trust `X-Forwarded-For`/`X-Forwarded-Proto` from the known proxy, or strip them and rely on `RemoteAddr`.
4. **#5** — add `http.MaxBytesReader` (or equivalent) to `decodeBody`.
5. **#6** — map errors via `status.Code(err)` and sanitize client-facing messages.
6. **#3 / #7 / #9** — decide on fail-open vs. fail-closed rate limiting; validate CORS origins; scope job-result reads to the owning user.
