package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewWebProxy proxies /web/* to authservice's web server.
func NewWebProxy(host string, port int) http.Handler {
	target, _ := url.Parse(fmt.Sprintf("http://%s:%d", host, port))
	return httputil.NewSingleHostReverseProxy(target)
}
