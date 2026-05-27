package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swlib/security"
)

// RequireAdmin returns 401 if there are no valid claims, 403 if the user is
// not an admin. Must be used downstream of the Auth middleware.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := security.GetClaims(r.Context())
		if !ok || claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		userClaims, ok := claims.SwayRiderClaims.(*jwt.SwayRiderUserClaims)
		if !ok || !userClaims.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// KeyCache is satisfied by *jwtkeys.Cache.
type KeyCache interface {
	Verify(token string) (*jwt.Claims, error)
}

// Auth extracts and validates the JWT from the request.
// Claims (or nil) and the raw token are stored in context.
// Handlers decide whether authentication is required.
func Auth(keyCache KeyCache) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Bearer header takes precedence over cookie (mobile vs web).
			token := ""
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			} else if cookie, err := r.Cookie("access_token"); err == nil {
				token = cookie.Value
			}

			if token != "" {
				if claims, err := keyCache.Verify(token); err == nil {
					ctx = context.WithValue(ctx, security.ClaimsKey, claims)
					ctx = context.WithValue(ctx, security.JwtKey, token)
				}
			}

			// Refresh token from cookie is used by the refresh endpoint.
			if cookie, err := r.Cookie("refresh_token"); err == nil {
				ctx = context.WithValue(ctx, security.RefreshKey, cookie.Value)
			}

			// Detect HTTPS from the downstream proxy header.
			ctx = context.WithValue(ctx, security.SecureKey, r.Header.Get("X-Forwarded-Proto") == "https")

			// Client IP — trust X-Forwarded-For from Traefik.
			ip := clientIP(r)
			ctx = context.WithValue(ctx, security.OrigIpKey, ip)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireUser returns 401 if the request has no valid JWT claims in context.
// It must be used downstream of the Auth middleware.
func RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := security.GetClaims(r.Context()); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireVerifiedUser returns 401 if there are no valid claims and 403 if the
// user's email is not verified. Must be used downstream of the Auth middleware.
func RequireVerifiedUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := security.GetClaims(r.Context())
		if !ok || claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.EmailVerified == nil || !*claims.EmailVerified {
			http.Error(w, "forbidden: email not verified", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.Index(xff, ","); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr.
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}
