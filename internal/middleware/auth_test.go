package middleware

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swlib/security"
)

type fakeKeyCache struct{}

func (fakeKeyCache) Verify(token string) (*jwt.Claims, error) {
	return nil, errors.New("invalid token")
}

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c, err)
		}
		nets = append(nets, ipnet)
	}
	return nets
}

func newRequestWithPeer(peer, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = peer
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIPUntrustedPeerIgnoresXFF(t *testing.T) {
	trusted := mustCIDRs(t, "10.10.0.2/32")

	// Direct connection with a forged header: the header must be ignored.
	r := newRequestWithPeer("203.0.113.7:4000", "1.2.3.4")
	if got := clientIP(r, peerIP(r), trusted); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want peer %q", got, "203.0.113.7")
	}

	// No trusted proxies configured at all: same result.
	r = newRequestWithPeer("203.0.113.7:4000", "1.2.3.4")
	if got := clientIP(r, peerIP(r), nil); got != "203.0.113.7" {
		t.Errorf("clientIP with nil trusted = %q, want peer %q", got, "203.0.113.7")
	}
}

func TestClientIPTrustedPeerUsesXFF(t *testing.T) {
	trusted := mustCIDRs(t, "10.10.0.2/32")
	r := newRequestWithPeer("10.10.0.2:50000", "203.0.113.7")
	if got := clientIP(r, peerIP(r), trusted); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want XFF %q", got, "203.0.113.7")
	}
}

func TestClientIPTrustedPeerTakesRightmostEntry(t *testing.T) {
	trusted := mustCIDRs(t, "10.10.0.2/32")

	// Traefik appends the client IP it saw, so a client-supplied leading entry
	// must never win.
	r := newRequestWithPeer("10.10.0.2:50000", "1.2.3.4, 203.0.113.7")
	if got := clientIP(r, peerIP(r), trusted); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want rightmost XFF %q", got, "203.0.113.7")
	}
}

func TestClientIPMultiProxyChain(t *testing.T) {
	// internet → apache (10.20.0.0/24) → traefik (10.10.0.2) → api
	trusted := mustCIDRs(t, "10.20.0.0/24", "10.10.0.2/32")
	r := newRequestWithPeer("10.10.0.2:50000", "203.0.113.7, 10.20.0.5")
	if got := clientIP(r, peerIP(r), trusted); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want %q", got, "203.0.113.7")
	}
}

func TestClientIPFallbacks(t *testing.T) {
	trusted := mustCIDRs(t, "10.10.0.2/32")

	// Trusted peer, no XFF header → peer.
	r := newRequestWithPeer("10.10.0.2:50000", "")
	if got := clientIP(r, peerIP(r), trusted); got != "10.10.0.2" {
		t.Errorf("clientIP without XFF = %q, want peer %q", got, "10.10.0.2")
	}

	// Every XFF entry is a trusted proxy → fall back to peer.
	trusted = mustCIDRs(t, "10.10.0.0/24")
	r = newRequestWithPeer("10.10.0.2:50000", "10.10.0.2, 10.10.0.3")
	if got := clientIP(r, peerIP(r), trusted); got != "10.10.0.2" {
		t.Errorf("clientIP all-trusted XFF = %q, want peer %q", got, "10.10.0.2")
	}
}

func TestClientIPIPv6(t *testing.T) {
	// Trust the specific peer prefix only, so the XFF entry stays untrusted.
	trusted := mustCIDRs(t, "2001:db8:1::/48")

	// IPv6 peer with bracketed port handling.
	r := newRequestWithPeer("[2001:db8:1::1]:8080", "2001:db8:2::99")
	if got := clientIP(r, peerIP(r), nil); got != "2001:db8:1::1" {
		t.Errorf("clientIP ipv6 untrusted = %q, want peer %q", got, "2001:db8:1::1")
	}
	if got := clientIP(r, peerIP(r), trusted); got != "2001:db8:2::99" {
		t.Errorf("clientIP ipv6 trusted = %q, want XFF %q", got, "2001:db8:2::99")
	}
}

func TestAuthMiddlewareSetsIPAndSecure(t *testing.T) {
	trusted := mustCIDRs(t, "10.10.0.2/32")

	run := func(r *http.Request) (ip string, secure bool) {
		t.Helper()
		h := Auth(fakeKeyCache{}, trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _ = security.GetOrigIp(r.Context())
			secure, _ = security.GetSecure(r.Context())
		}))
		h.ServeHTTP(httptest.NewRecorder(), r)
		return ip, secure
	}

	// Trusted peer: XFF honored, X-Forwarded-Proto https → Secure.
	r := newRequestWithPeer("10.10.0.2:50000", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "https")
	if ip, secure := run(r); ip != "203.0.113.7" || !secure {
		t.Errorf("trusted peer: ip=%q secure=%v, want 203.0.113.7 true", ip, secure)
	}

	// Trusted peer with proto http → not secure.
	r = newRequestWithPeer("10.10.0.2:50000", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "http")
	if ip, secure := run(r); ip != "203.0.113.7" || secure {
		t.Errorf("trusted peer proto http: ip=%q secure=%v, want 203.0.113.7 false", ip, secure)
	}

	// Untrusted (direct) peer: forged XFF and forged https header are both ignored.
	r = newRequestWithPeer("203.0.113.7:4000", "1.2.3.4")
	r.Header.Set("X-Forwarded-Proto", "https")
	if ip, secure := run(r); ip != "203.0.113.7" || secure {
		t.Errorf("untrusted peer: ip=%q secure=%v, want 203.0.113.7 false", ip, secure)
	}
}
