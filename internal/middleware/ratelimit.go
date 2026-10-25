package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

// RateLimiter is satisfied by *ratelimit.Limiter.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

// ExtensionClass is the rate-limit class of an extension route: its own name
// and budgets, separate from every built-in class.
type ExtensionClass struct {
	Name       string
	UserPerMin int  // per signed-in user
	IPPerMin   int  // per IP, for callers that are not signed in
	PerIPOnly  bool // always count per IP, whether or not the caller is signed in
}

type RateLimitConfig struct {
	// Extension, when set, is asked first whether a request belongs to an
	// extension route; such requests use that route's class instead of the
	// built-in ones.
	Extension func(*http.Request) (ExtensionClass, bool)

	IPAuth        int // per-IP limit for the auth class (login, register, password flows)
	IPPublic      int // per-IP limit for the public class (health, public-keys)
	IPAPI         int // per-IP limit for unauthenticated requests to per-user (api/expensive) endpoints
	UserAPI       int // per-user limit for the api class
	UserExpensive int // per-user limit for the expensive class (route, search)
	UserReroute   int // per-user limit for the reroute class (a new route after leaving one)
	UserTiles     int // per-user limit for the tiles class (map tiles, styles, glyphs, sprites)
}

// RateLimit applies sliding-window rate limits based on the request path and auth state.
//
// Every request is limited. Classes that are inherently per-IP (auth, public) always
// limit by IP. Classes that are per-user (api, expensive, tiles) limit by user when the
// request is authenticated and by IP when it is not — so unauthenticated requests
// (verify-email, refresh, reset-password, or floods aimed at protected endpoints)
// can never bypass the limiter by simply omitting a token.
func RateLimit(limiter RateLimiter, cfg RateLimitConfig, l *log.Logger) func(http.Handler) http.Handler {
	lg := l.Derive(log.WithComponent("ratelimit"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			path := r.URL.Path

			ip, _ := security.GetOrigIp(ctx)
			claims, authed := security.GetClaims(ctx)

			class, perUser := endpointClass(path)

			var allowed bool
			var err error

			var ext ExtensionClass
			isExt := false
			if cfg.Extension != nil {
				ext, isExt = cfg.Extension(r)
			}

			switch {
			case isExt:
				class = "ext:" + ext.Name
				if authed && !ext.PerIPOnly {
					allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:%s:user:%s", class, claims.Subject), ext.UserPerMin, time.Minute)
				} else {
					allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:%s:ip:%s", class, ip), ext.IPPerMin, time.Minute)
				}
			case class == "auth":
				allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:auth:ip:%s", ip), cfg.IPAuth, time.Minute)
			case class == "public":
				allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:pub:ip:%s", ip), cfg.IPPublic, time.Minute)
			case perUser && authed:
				userID := claims.Subject
				limit := cfg.UserAPI
				switch class {
				case "expensive":
					limit = cfg.UserExpensive
				case "reroute":
					limit = cfg.UserReroute
				case "tiles":
					limit = cfg.UserTiles
				}
				allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:%s:user:%s", class, userID), limit, time.Minute)
			case perUser:
				// Unauthenticated request to a per-user endpoint: still limit per IP so
				// the limiter can't be bypassed by omitting a token.
				allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:%s:ip:%s", class, ip), cfg.IPAPI, time.Minute)
			default:
				// Unknown class — fail closed rather than allow unthrottled.
				lg.Errorf("rate limit: unknown class %q, denying request", class)
				allowed = false
			}

			if err != nil {
				// Fail closed on limiter errors (e.g. deny degrade mode): a
				// broken rate limiter must not disable throttling.
				lg.Warnf("rate limit check failed class=%s ip=%s path=%s: %v", class, ip, path, err)
			}

			if err != nil || !allowed {
				userID := "-"
				if authed {
					userID = claims.Subject
				}
				lg.Warnf("rate limit exceeded class=%s ip=%s user=%s path=%s", class, ip, userID, path)
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// endpointClass returns the rate-limit class and whether it applies per user (true) or per IP (false).
func endpointClass(path string) (class string, perUser bool) {
	switch {
	case path == "/api/v1/auth/login",
		path == "/api/v1/auth/register",
		path == "/api/v1/auth/request-password-reset",
		path == "/api/v1/auth/forgot-password",
		path == "/api/v1/auth/verify-email",
		// Verifies email+password like login, so it belongs in the same
		// class as request-password-reset/login rather than the default
		// per-user "api" class (this endpoint is unauthenticated).
		path == "/api/v1/auth/mfa/reset/request",
		// MFA verify is the TOTP brute-force surface — the per-challenge
		// attempt counter and the per-user "mfa" throttle scope live in
		// authservice, but this per-IP class bounds repeated guesses across
		// challenges (an attacker can loop successful password logins).
		path == "/api/v1/auth/mfa/verify":
		return "auth", false
	case path == "/health",
		path == "/api/v1/auth/public-keys":
		return "public", false
	case strings.HasPrefix(path, "/v1/tiles/"):
		// A map view fires dozens of requests (tiles, style, glyph ranges, sprite), so tiles get
		// their own generous per-user budget instead of sharing the per-IP public class with
		// /health. Unauthenticated tile requests fall into the stricter per-IP api budget.
		return "tiles", true
	case path == "/api/v1/route/reroute":
		// A new route after leaving one has its own budget so that a rider who
		// needs it is not locked out by route planning, and vice versa.
		return "reroute", true
	case strings.HasPrefix(path, "/api/v1/route"),
		strings.HasPrefix(path, "/api/v1/search"):
		return "expensive", true
	default:
		return "api", true
	}
}
