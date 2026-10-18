package middleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/swayrider/swlib/jwt"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

type allowCall struct {
	key    string
	limit  int
	window time.Duration
}

type fakeLimiter struct {
	mu    sync.Mutex
	calls []allowCall
	allow bool
	err   error
}

func (f *fakeLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, allowCall{key: key, limit: limit, window: window})
	return f.allow, f.err
}

func (f *fakeLimiter) lastCall() allowCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return allowCall{}
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeLimiter) numCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeLimiter) callAt(i int) allowCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[i]
}

func newRateLimitHarness() (*fakeLimiter, http.Handler) {
	fl := &fakeLimiter{allow: true}
	cfg := RateLimitConfig{
		IPAuth:        10,
		IPPublic:      600,
		IPAPI:         60,
		UserAPI:       300,
		UserExpensive: 20,
		UserReroute:   12,
		UserTiles:     3000,
	}
	h := RateLimit(fl, cfg, log.New())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	return fl, h
}

func requestWithIP(path, ip string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	ctx := context.WithValue(r.Context(), security.OrigIpKey, ip)
	return r.WithContext(ctx)
}

func requestWithUser(path, ip, userID string) *http.Request {
	r := requestWithIP(path, ip)
	claims := &jwt.Claims{}
	claims.Subject = userID
	claims.SwayRiderClaims = jwt.NewSwayRiderUserClaims(false, "standard")
	ctx := context.WithValue(r.Context(), security.ClaimsKey, claims)
	return r.WithContext(ctx)
}

func doRequest(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestEndpointClass(t *testing.T) {
	tests := []struct {
		path        string
		wantClass   string
		wantPerUser bool
	}{
		{"/api/v1/auth/login", "auth", false},
		{"/api/v1/auth/register", "auth", false},
		{"/api/v1/auth/request-password-reset", "auth", false},
		{"/api/v1/auth/verify-email", "auth", false},
		{"/api/v1/auth/mfa/verify", "auth", false},
		{"/api/v1/auth/mfa/reset/request", "auth", false},
		{"/health", "public", false},
		{"/v1/tiles/foo/bar", "tiles", true},
		{"/v1/tiles/styles/classic/light", "tiles", true},
		{"/v1/tiles/fonts/Noto%20Sans%20Regular/0-255.pbf", "tiles", true},
		{"/api/v1/auth/public-keys", "public", false},
		{"/api/v1/auth/refresh", "api", true},
		{"/api/v1/auth/reset-password", "api", true},
		{"/api/v1/auth/check-password-strength", "api", true},
		{"/api/v1/auth/me", "api", true},
		{"/api/v1/auth/admin/whois", "api", true},
		{"/api/v1/region/search-point", "api", true},
		{"/api/v1/auth/mfa/setup", "api", true},
		{"/api/v1/auth/mfa/enable", "api", true},
		{"/api/v1/auth/mfa/disable", "api", true},
		{"/api/v1/auth/mfa/status", "api", true},
		{"/api/v1/auth/mfa/backup-codes", "api", true},
		{"/web/", "api", true},
		{"/api/v1/route", "expensive", true},
		{"/api/v1/route/rejoin", "reroute", true},
		{"/api/v1/search", "expensive", true},
		{"/api/v1/search/autocomplete", "expensive", true},
	}
	for _, tt := range tests {
		class, perUser := endpointClass(tt.path)
		if class != tt.wantClass || perUser != tt.wantPerUser {
			t.Errorf("endpointClass(%q) = (%q, %v), want (%q, %v)",
				tt.path, class, perUser, tt.wantClass, tt.wantPerUser)
		}
	}
}

func TestRateLimitAuthClassLimitsPerIP(t *testing.T) {
	fl, h := newRateLimitHarness()

	rec := doRequest(h, requestWithIP("/api/v1/auth/verify-email", "1.2.3.4"))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-email unauthenticated: status = %d, want 200", rec.Code)
	}
	call := fl.lastCall()
	if call.key != "rl:auth:ip:1.2.3.4" {
		t.Errorf("verify-email key = %q, want %q", call.key, "rl:auth:ip:1.2.3.4")
	}
	if call.limit != 10 {
		t.Errorf("verify-email limit = %d, want %d (auth class)", call.limit, 10)
	}

	// An authenticated request to an auth-class endpoint is still keyed per IP.
	doRequest(h, requestWithUser("/api/v1/auth/login", "1.2.3.4", "user-1"))
	if fl.numCalls() != 2 {
		t.Fatalf("expected 2 limiter calls, got %d", fl.numCalls())
	}
	call = fl.lastCall()
	if call.key != "rl:auth:ip:1.2.3.4" {
		t.Errorf("login key = %q, want per-IP %q", call.key, "rl:auth:ip:1.2.3.4")
	}
}

func TestRateLimitUnauthenticatedPerUserClassLimitsPerIP(t *testing.T) {
	tests := []struct {
		path string
		key  string
	}{
		{"/api/v1/auth/refresh", "rl:api:ip:1.2.3.4"},
		{"/api/v1/auth/reset-password", "rl:api:ip:1.2.3.4"},
		{"/api/v1/auth/check-password-strength", "rl:api:ip:1.2.3.4"},
		{"/api/v1/region/search-point", "rl:api:ip:1.2.3.4"},
		{"/api/v1/auth/admin/whois", "rl:api:ip:1.2.3.4"},
		{"/api/v1/route", "rl:expensive:ip:1.2.3.4"},
		{"/api/v1/search", "rl:expensive:ip:1.2.3.4"},
	}
	for _, tt := range tests {
		fl, h := newRateLimitHarness()
		rec := doRequest(h, requestWithIP(tt.path, "1.2.3.4"))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s unauthenticated: status = %d, want 200", tt.path, rec.Code)
		}
		call := fl.lastCall()
		if call.key != tt.key {
			t.Errorf("%s key = %q, want %q", tt.path, call.key, tt.key)
		}
		if call.limit != 60 {
			t.Errorf("%s limit = %d, want %d (IPAPI)", tt.path, call.limit, 60)
		}
	}
}

func TestRateLimitDistinctIPsGetDistinctKeys(t *testing.T) {
	fl, h := newRateLimitHarness()

	doRequest(h, requestWithIP("/api/v1/auth/refresh", "1.2.3.4"))
	doRequest(h, requestWithIP("/api/v1/auth/refresh", "5.6.7.8"))

	first := fl.callAt(0).key
	second := fl.callAt(1).key
	if first == second {
		t.Errorf("distinct IPs share key %q", first)
	}
}

func TestRateLimitAuthenticatedPerUserClassLimitsPerUser(t *testing.T) {
	fl, h := newRateLimitHarness()

	rec := doRequest(h, requestWithUser("/api/v1/auth/me", "1.2.3.4", "user-123"))
	if rec.Code != http.StatusOK {
		t.Fatalf("me authenticated: status = %d, want 200", rec.Code)
	}
	call := fl.lastCall()
	if call.key != "rl:api:user:user-123" {
		t.Errorf("me key = %q, want %q", call.key, "rl:api:user:user-123")
	}
	if call.limit != 300 {
		t.Errorf("me limit = %d, want %d (UserAPI)", call.limit, 300)
	}

	fl2, h2 := newRateLimitHarness()
	doRequest(h2, requestWithUser("/api/v1/route", "1.2.3.4", "user-123"))
	call = fl2.lastCall()
	if call.key != "rl:expensive:user:user-123" {
		t.Errorf("route key = %q, want %q", call.key, "rl:expensive:user:user-123")
	}
	if call.limit != 20 {
		t.Errorf("route limit = %d, want %d (UserExpensive)", call.limit, 20)
	}

	// Getting back on a route has its own budget and its own key.
	fl3, h3 := newRateLimitHarness()
	doRequest(h3, requestWithUser("/api/v1/route/rejoin", "1.2.3.4", "user-123"))
	call = fl3.lastCall()
	if call.key != "rl:reroute:user:user-123" {
		t.Errorf("rejoin key = %q, want %q", call.key, "rl:reroute:user:user-123")
	}
	if call.limit != 12 {
		t.Errorf("rejoin limit = %d, want %d (UserReroute)", call.limit, 12)
	}
}

func TestRateLimitDeniedReturns429(t *testing.T) {
	fl, h := newRateLimitHarness()
	fl.allow = false

	rec := doRequest(h, requestWithIP("/api/v1/auth/refresh", "1.2.3.4"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q, want %q", rec.Header().Get("Retry-After"), "60")
	}
}

// A limiter error (e.g. deny degrade mode with Redis down) must fail closed,
// not silently allow the request through unthrottled.
func TestRateLimitFailsClosedOnLimiterError(t *testing.T) {
	fl, h := newRateLimitHarness()
	fl.err = errors.New("rate limiter degraded: redis unavailable")

	rec := doRequest(h, requestWithIP("/api/v1/auth/refresh", "1.2.3.4"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q, want %q", rec.Header().Get("Retry-After"), "60")
	}
}

func TestRateLimitPublicClassLimitsPerIP(t *testing.T) {
	fl, h := newRateLimitHarness()

	doRequest(h, requestWithIP("/health", "1.2.3.4"))
	call := fl.lastCall()
	if call.key != "rl:pub:ip:1.2.3.4" {
		t.Errorf("health key = %q, want %q", call.key, "rl:pub:ip:1.2.3.4")
	}
	if call.limit != 600 {
		t.Errorf("health limit = %d, want %d (IPPublic)", call.limit, 600)
	}
}

// Map traffic has its own per-user budget: every tiles path (tiles, styles, glyphs, sprites,
// TileJSON) is the same class, keyed by user, and none of it counts against the per-IP public class.
func TestRateLimitTilesClassLimitsPerUser(t *testing.T) {
	for _, path := range []string{
		"/v1/tiles/planet/12/2097/1373",
		"/v1/tiles/styles",
		"/v1/tiles/styles/classic/3/light",
		"/v1/tiles/fonts/Noto%20Sans%20Regular/0-255.pbf",
		"/v1/tiles/sprites/light@2x.png",
		"/v1/tiles/planet/tiles.json",
		"/v1/tiles/ping",
	} {
		fl, h := newRateLimitHarness()
		doRequest(h, requestWithUser(path, "1.2.3.4", "user-123"))
		call := fl.lastCall()
		if call.key != "rl:tiles:user:user-123" {
			t.Errorf("%s: key = %q, want %q", path, call.key, "rl:tiles:user:user-123")
		}
		if call.limit != 3000 {
			t.Errorf("%s: limit = %d, want %d (UserTiles)", path, call.limit, 3000)
		}
	}
}

// Two users behind one IP (a NAT, an office) do not share a budget.
func TestRateLimitTilesClassIsPerUserNotPerIP(t *testing.T) {
	fl, h := newRateLimitHarness()
	doRequest(h, requestWithUser("/v1/tiles/planet/1/0/0", "9.9.9.9", "alice"))
	doRequest(h, requestWithUser("/v1/tiles/planet/1/0/0", "9.9.9.9", "bob"))
	if a, b := fl.callAt(0).key, fl.callAt(1).key; a == b || a != "rl:tiles:user:alice" || b != "rl:tiles:user:bob" {
		t.Errorf("keys = %q and %q", a, b)
	}
}

// Without a token the request is limited per IP with the api budget (and the gateway answers 401
// anyway), so a flood of anonymous tile requests is throttled hard.
func TestRateLimitTilesUnauthenticatedFallsBackToIP(t *testing.T) {
	fl, h := newRateLimitHarness()
	doRequest(h, requestWithIP("/v1/tiles/planet/1/0/0", "1.2.3.4"))
	call := fl.lastCall()
	if call.key != "rl:tiles:ip:1.2.3.4" {
		t.Errorf("key = %q, want %q", call.key, "rl:tiles:ip:1.2.3.4")
	}
	if call.limit != 60 {
		t.Errorf("limit = %d, want %d (IPAPI)", call.limit, 60)
	}
}

// Tiles no longer share the per-IP public class with /health and the public keys.
func TestRateLimitPublicClassExcludesTiles(t *testing.T) {
	for _, path := range []string{"/health", "/api/v1/auth/public-keys"} {
		fl, h := newRateLimitHarness()
		doRequest(h, requestWithUser(path, "1.2.3.4", "user-123"))
		if call := fl.lastCall(); call.key != "rl:pub:ip:1.2.3.4" || call.limit != 600 {
			t.Errorf("%s: %q limit %d", path, call.key, call.limit)
		}
	}
	for _, path := range []string{"/v1/tiles/ping", "/v1/tiles/planet/0/0/0"} {
		class, perUser := endpointClass(path)
		if class != "tiles" || !perUser {
			t.Errorf("%s: class %q perUser %v", path, class, perUser)
		}
	}
}

// A throttled map answers 429 with Retry-After like every other class.
func TestRateLimitTilesDeniedReturns429(t *testing.T) {
	fl, h := newRateLimitHarness()
	fl.allow = false
	rec := doRequest(h, requestWithUser("/v1/tiles/planet/1/0/0", "1.2.3.4", "user-123"))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("status %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}
