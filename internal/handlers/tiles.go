package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func NewTilesProxy(host string, port int, token func() string) http.Handler {
	target, _ := url.Parse(fmt.Sprintf("http://%s:%d", host, port))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = newProxyTransport()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		// The gateway authenticates tile requests itself (RequireVerifiedUser)
		// and injects its own service token below; the user's cookies are not
		// needed by tilesservice and must not be forwarded downstream.
		stripCookies(r2)
		r2.Header.Set("Authorization", "Bearer "+token())
		proxy.ServeHTTP(w, r2)
	})
}
