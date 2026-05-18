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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.Header.Set("Authorization", "Bearer "+token())
		proxy.ServeHTTP(w, r2)
	})
}
