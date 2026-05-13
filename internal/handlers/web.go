package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// NewWebProxy proxies /web/* to authservice's web server, stripping the /web prefix.
func NewWebProxy(host string, port int) http.Handler {
	target, _ := url.Parse(fmt.Sprintf("http://%s:%d", host, port))
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Rewrite the request path before forwarding.
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/web")
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
	}
	return proxy
}
