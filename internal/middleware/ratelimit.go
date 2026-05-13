package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/swayrider/swlib/security"
)

// RateLimiter is satisfied by *ratelimit.Limiter.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

type RateLimitConfig struct {
	IPAuth        int
	IPPublic      int
	UserAPI       int
	UserExpensive int
}

// RateLimit applies sliding-window rate limits based on the request path and auth state.
func RateLimit(limiter RateLimiter, cfg RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			path := r.URL.Path

			ip, _ := security.GetOrigIp(ctx)
			claims, authed := security.GetClaims(ctx)

			class, perUser := endpointClass(path)

			var allowed bool
			var err error

			switch {
			case class == "auth":
				allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:auth:ip:%s", ip), cfg.IPAuth, time.Minute)
			case class == "public":
				allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:pub:ip:%s", ip), cfg.IPPublic, time.Minute)
			case perUser && authed:
				userID := claims.Subject
				limit := cfg.UserAPI
				if class == "expensive" {
					limit = cfg.UserExpensive
				}
				allowed, err = limiter.Allow(ctx, fmt.Sprintf("rl:%s:user:%s", class, userID), limit, time.Minute)
			default:
				allowed = true
			}

			_ = err // fail open on Redis error (Allow already does this)

			if !allowed {
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
		path == "/api/v1/auth/forgot-password":
		return "auth", false
	case path == "/health",
		strings.HasPrefix(path, "/v1/tiles/"),
		path == "/api/v1/auth/public-keys":
		return "public", false
	case strings.HasPrefix(path, "/api/v1/route"),
		strings.HasPrefix(path, "/api/v1/search"):
		return "expensive", true
	default:
		return "api", true
	}
}
