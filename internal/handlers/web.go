package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/swayrider/swlib/http/cookies"
)

// NewWebProxy proxies /web/* to authservice's web server.
func NewWebProxy(host string, port int) http.Handler {
	target, _ := url.Parse(fmt.Sprintf("http://%s:%d", host, port))
	proxy := httputil.NewSingleHostReverseProxy(target)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		// The web server is public; the only cookie it consumes is the
		// access_token cookie (used to render logged-in state on the static
		// pages). Everything else is dropped rather than forwarded downstream.
		stripCookies(r2, cookies.FullCookieName("access_token"))
		proxy.ServeHTTP(w, r2)
	})
}
