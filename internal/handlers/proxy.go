package handlers

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// newProxyTransport returns the http.Transport shared by the HTTP reverse
// proxies (tiles, web). The httputil default transport has no dial or
// response-header timeouts, so a stuck downstream service can pin a request
// goroutine indefinitely. These bounds turn that into a fast 502.
func newProxyTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}
}

// stripCookies removes browser cookies from an outbound proxy request.
//
// Downstream services are authenticated by the gateway itself (the tiles
// proxy injects its own service token; the web server is public), so
// forwarding the user's cookies is an avoidable token-scope leak — most
// importantly the `access_token` cookie, which is scoped to "/" and would
// otherwise reach services that never asked for it.
//
// With no keep names the entire Cookie header is dropped. Otherwise only the
// named cookies survive (used for /web/*, where authservice's static pages
// read the access_token cookie to render logged-in state).
func stripCookies(r *http.Request, keep ...string) {
	if len(keep) == 0 {
		r.Header.Del("Cookie")
		return
	}

	keepSet := make(map[string]bool, len(keep))
	for _, k := range keep {
		keepSet[k] = true
	}

	kept := make([]string, 0, len(r.Header.Values("Cookie")))
	for _, line := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name := pair
			if i := strings.IndexByte(pair, '='); i >= 0 {
				name = pair[:i]
			}
			if keepSet[strings.TrimSpace(name)] {
				kept = append(kept, pair)
			}
		}
	}

	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}
