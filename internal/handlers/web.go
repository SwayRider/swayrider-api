package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/swayrider/swlib/http/cookies"
	"github.com/swayrider/swlib/security"
)

// webGatewayPrefix is the public URL namespace the gateway serves the auth
// web pages under (mounted in internal/server/routes.go). It is part of the
// gateway's API surface and intentionally hardcoded, like /v1/tiles/.
const webGatewayPrefix = "/web"

// mapWebPath maps a path in the gateway's /web namespace onto the path
// authservice's web server mounts its pages under (its WEB_PATH_PREFIX).
//
// The gateway's mux only routes paths matching "/web/" here, so path always
// starts with the gateway prefix. The remainder is appended to authservice's
// prefix, which may itself be "/" (pages served at the web server root).
func mapWebPath(path, authWebPrefix string) string {
	rest := strings.TrimPrefix(path, webGatewayPrefix)
	return strings.TrimRight(authWebPrefix, "/") + rest
}

// NewWebProxy proxies /web/* to authservice's web server.
//
// The gateway owns the public /web namespace and forwards the request to
// authservice's static web server, which mounts its pages under its own
// configured WEB_PATH_PREFIX. With the default prefix (/web) the outbound
// path is unchanged; the two prefixes are decoupled via
// AUTHSERVICE_WEB_PATH_PREFIX so a change to authservice's prefix no longer
// silently breaks the proxy.
//
// All pages under /web are public — they serve emailed verification, reset,
// and registration links that must be reachable without a JWT token.
// Authservice's own web server enforces its own security (e.g. the reset-mfa
// page's password re-verification), so the gateway only needs to forward.
func NewWebProxy(host string, port int, authWebPrefix string) http.Handler {
	registerWebPublicEndpoints()

	target, _ := url.Parse(fmt.Sprintf("http://%s:%d", host, port))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = newProxyTransport()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = mapWebPath(r2.URL.Path, authWebPrefix)
		if r2.URL.RawPath != "" {
			r2.URL.RawPath = mapWebPath(r2.URL.RawPath, authWebPrefix)
		}
		// The web server is public; the only cookie it consumes is the
		// access_token cookie (used to render logged-in state on the static
		// pages). Everything else is dropped rather than forwarded downstream.
		stripCookies(r2, cookies.FullCookieName("access_token"))
		proxy.ServeHTTP(w, r2)
	})
}

// registerWebPublicEndpoints marks all web pages under /web as publicly
// accessible so the gateway's auth middleware doesn't 401 anonymous visitors
// before the request ever reaches the web proxy.
func registerWebPublicEndpoints() {
	pages := []string{
		webGatewayPrefix + "/",
		webGatewayPrefix + "/index.html",
		webGatewayPrefix + "/verify-user",
		webGatewayPrefix + "/reset-password",
		webGatewayPrefix + "/reset-mfa",
		webGatewayPrefix + "/register",
		webGatewayPrefix + "/registration-complete",
	}
	for _, p := range pages {
		security.PublicEndpoint(p)
	}
}
