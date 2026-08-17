package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/swayrider/swlib/http/cookies"
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
//
// trustedProxies lists the CIDRs of reverse proxies (e.g. the Traefik
// container) whose X-Forwarded-For / X-Forwarded-Proto headers are honored.
// Only requests whose immediate TCP peer is inside one of these CIDRs have
// those headers trusted; any other request is treated as a direct connection
// and uses RemoteAddr, so a client can never spoof its IP for rate limiting
// or force cookies to be issued without the Secure flag.
func Auth(keyCache KeyCache, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Bearer header takes precedence over cookie (mobile vs web).
			token := ""
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			} else if cookie, err := r.Cookie(cookies.FullCookieName("access_token")); err == nil {
				if b, err := cookies.DecodeValue(cookie); err == nil {
					token = string(b)
				}
			}

			if token != "" {
				if claims, err := keyCache.Verify(token); err == nil {
					ctx = context.WithValue(ctx, security.ClaimsKey, claims)
					ctx = context.WithValue(ctx, security.JwtKey, token)
				}
			}

			// Refresh token from cookie is used by the refresh endpoint.
			if cookie, err := r.Cookie(cookies.FullCookieName("refresh_token")); err == nil {
				if b, err := cookies.DecodeValue(cookie); err == nil {
					ctx = context.WithValue(ctx, security.RefreshKey, string(b))
				}
			}

			// Client IP — only trust X-Forwarded-For when the immediate peer is
			// a trusted proxy; otherwise the peer address is used.
			peer := peerIP(r)
			ctx = context.WithValue(ctx, security.OrigIpKey, clientIP(r, peer, trustedProxies))

			// Detect HTTPS from the proxy header, but only when the peer is a
			// trusted proxy. The service itself terminates no TLS, so without a
			// trusted proxy the request is considered insecure.
			secure := r.TLS != nil || (isTrustedProxy(peer, trustedProxies) &&
				strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
			ctx = context.WithValue(ctx, security.SecureKey, secure)

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

// peerIP returns the host portion of r.RemoteAddr (the immediate TCP peer).
func peerIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// isTrustedProxy reports whether ip falls inside one of the trusted proxy CIDRs.
func isTrustedProxy(ip string, trusted []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// clientIP returns the client IP used for rate limiting and logging.
//
// When the immediate peer is a trusted proxy, the client IP is read from
// X-Forwarded-For: proxies append the peer they saw to the header, so the
// rightmost entry that is not itself a trusted proxy is the client (this also
// handles chains such as internet → apache → traefik → api, where apache and
// traefik are both in the trusted set). When the peer is not a trusted proxy
// (a direct connection that bypassed the proxy), X-Forwarded-For is ignored
// entirely and the peer address is used — a forged header can never spoof the
// IP used for rate limiting.
func clientIP(r *http.Request, peer string, trusted []*net.IPNet) string {
	if !isTrustedProxy(peer, trusted) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	entries := strings.Split(xff, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(entries[i])
		if ip == "" || isTrustedProxy(ip, trusted) {
			continue
		}
		return ip
	}
	return peer
}
