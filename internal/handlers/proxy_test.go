package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/swayrider/swlib/http/cookies"
)

// --- stripCookies ---

func TestStripCookies_DropsAll(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Header.Set("Cookie", "a=1; b=2")

	stripCookies(req)

	if got := req.Header.Get("Cookie"); got != "" {
		t.Errorf("Cookie = %q, want empty", got)
	}
}

func TestStripCookies_KeepsOnlyNamed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Header.Set("Cookie", "a=1; com.sw.keep=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0==; b=2")

	stripCookies(req, "com.sw.keep")

	if got, want := req.Header.Get("Cookie"), "com.sw.keep=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0=="; got != want {
		t.Errorf("Cookie = %q, want %q", got, want)
	}
}

func TestStripCookies_KeepsOnlyNamedAcrossMultipleHeaderLines(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Header.Add("Cookie", "a=1; com.sw.keep=keepval")
	req.Header.Add("Cookie", "b=2")

	stripCookies(req, "com.sw.keep")

	if got, want := req.Header.Get("Cookie"), "com.sw.keep=keepval"; got != want {
		t.Errorf("Cookie = %q, want %q", got, want)
	}
}

func TestStripCookies_NoKeptCookiesRemovesHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Header.Set("Cookie", "a=1; b=2")

	stripCookies(req, "com.sw.keep")

	if got := req.Header.Get("Cookie"); got != "" {
		t.Errorf("Cookie = %q, want empty", got)
	}
}

func TestStripCookies_NoCookieHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)

	stripCookies(req, "com.sw.keep")

	if got := req.Header.Get("Cookie"); got != "" {
		t.Errorf("Cookie = %q, want empty", got)
	}
}

// --- NewTilesProxy ---

func TestTilesProxy_DropsCookiesAndInjectsServiceToken(t *testing.T) {
	var backendReq *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendReq = r
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	host, port := proxyTarget(t, backend.URL)
	proxy := NewTilesProxy(host, port, func() string { return "svc-token" })

	req := httptest.NewRequest(http.MethodGet, "http://gateway/v1/tiles/1/2/3.pbf", nil)
	req.Header.Set("Cookie", cookies.FullCookieName("access_token")+"=userjwt; foo=bar")
	req.Header.Set("X-Custom", "v")

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if backendReq == nil {
		t.Fatal("backend never received the request")
	}
	if got := backendReq.Header.Get("Cookie"); got != "" {
		t.Errorf("backend Cookie = %q, want empty", got)
	}
	if got, want := backendReq.Header.Get("Authorization"), "Bearer svc-token"; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	if got, want := backendReq.Header.Get("X-Custom"), "v"; got != want {
		t.Errorf("X-Custom = %q, want %q", got, want)
	}
	if got, want := backendReq.URL.Path, "/v1/tiles/1/2/3.pbf"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

// --- NewWebProxy ---

func TestWebProxy_ForwardsOnlyAccessTokenCookie(t *testing.T) {
	cookies.SetNamespace("proxy.test")
	defer cookies.SetNamespace("com.hevanto-it.swayrider")

	accessName := cookies.FullCookieName("access_token")
	refreshName := cookies.FullCookieName("refresh_token")

	var backendReq *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendReq = r
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	host, port := proxyTarget(t, backend.URL)
	// Default authservice prefix (/web): the outbound path is unchanged.
	proxy := NewWebProxy(host, port, "/web")

	req := httptest.NewRequest(http.MethodGet, "http://gateway/web/reset-password?t=abc", nil)
	req.Header.Set("Cookie", accessName+"=userjwt; foo=bar; "+refreshName+"=refresh")

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if backendReq == nil {
		t.Fatal("backend never received the request")
	}
	if got, want := backendReq.Header.Get("Cookie"), accessName+"=userjwt"; got != want {
		t.Errorf("backend Cookie = %q, want %q", got, want)
	}
	if got, want := backendReq.URL.Path, "/web/reset-password"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestWebProxy_MapsGatewayPrefixToAuthServicePrefix(t *testing.T) {
	var backendReq *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendReq = r
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	host, port := proxyTarget(t, backend.URL)

	tests := []struct {
		name     string
		prefix   string
		inPath   string
		wantPath string
	}{
		{"non-default authservice prefix", "/app", "/web/reset-password", "/app/reset-password"},
		{"root authservice prefix", "/", "/web/verify-user", "/verify-user"},
		{"empty authservice prefix", "", "/web/register", "/register"},
		{"index page", "/app", "/web/", "/app/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backendReq = nil
			proxy := NewWebProxy(host, port, tt.prefix)

			req := httptest.NewRequest(http.MethodGet, "http://gateway"+tt.inPath, nil)
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if backendReq == nil {
				t.Fatal("backend never received the request")
			}
			if got, want := backendReq.URL.Path, tt.wantPath; got != want {
				t.Errorf("path = %q, want %q", got, want)
			}
		})
	}
}

func TestMapWebPath(t *testing.T) {
	tests := []struct {
		path, prefix, want string
	}{
		{"/web/reset-password", "/web", "/web/reset-password"},
		{"/web/reset-password", "/app", "/app/reset-password"},
		{"/web/reset-password", "/", "/reset-password"},
		{"/web/", "/web", "/web/"},
		{"/web/verify-user", "", "/verify-user"},
	}
	for _, tt := range tests {
		if got := mapWebPath(tt.path, tt.prefix); got != tt.want {
			t.Errorf("mapWebPath(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestNewProxyTransport_HasTimeouts(t *testing.T) {
	tr := newProxyTransport()
	if tr.ResponseHeaderTimeout <= 0 {
		t.Errorf("ResponseHeaderTimeout = %v, want > 0", tr.ResponseHeaderTimeout)
	}
	if tr.DialContext == nil {
		t.Error("DialContext is nil, want a bounded dialer")
	}
	if tr.TLSHandshakeTimeout <= 0 {
		t.Errorf("TLSHandshakeTimeout = %v, want > 0", tr.TLSHandshakeTimeout)
	}
}

// proxyTarget splits a test-server URL into the host and port that the
// proxies expect (they build their own target URL from host:port).
func proxyTarget(t *testing.T, rawURL string) (host string, port int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port from %q: %v", rawURL, err)
	}
	return u.Hostname(), p
}
