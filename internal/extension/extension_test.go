package extension

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/swayrider/swayrider-api/internal/middleware"
	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swlib/security"
)

func validRoute() Route {
	return Route{
		Name:         "example",
		Path:         "/api/v1/example",
		Methods:      []string{http.MethodPost},
		Upstream:     "http://example:8080",
		Auth:         AuthUser,
		MaxBodyBytes: 1024,
		Timeout:      time.Second,
		RateLimit:    RateLimit{UserPerMin: 10, IPPerMin: 5},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Route)
		wantErr string // empty: valid
	}{
		{"valid", func(r *Route) {}, ""},
		{"prefix path", func(r *Route) { r.Path = "/api/v1/example/" }, ""},
		{"no name", func(r *Route) { r.Name = "" }, "name is required"},
		{"path outside api", func(r *Route) { r.Path = "/example" }, "must start with"},
		{"bare api prefix", func(r *Route) { r.Path = "/api/v1/" }, "must start with"},
		{"reserved auth", func(r *Route) { r.Path = "/api/v1/auth/login" }, "reserved"},
		{"reserved route", func(r *Route) { r.Path = "/api/v1/route/" }, "reserved"},
		{"reserved search", func(r *Route) { r.Path = "/api/v1/search" }, "reserved"},
		{"similar but not reserved", func(r *Route) { r.Path = "/api/v1/routes" }, ""},
		{"path traversal", func(r *Route) { r.Path = "/api/v1/a/../auth" }, "not allowed"},
		{"wildcard", func(r *Route) { r.Path = "/api/v1/{x}" }, "not allowed"},
		{"no methods", func(r *Route) { r.Methods = nil }, "method"},
		{"bad method", func(r *Route) { r.Methods = []string{"TRACE"} }, "not allowed"},
		{"upstream not url", func(r *Route) { r.Upstream = "example" }, "http(s) URL"},
		{"upstream scheme", func(r *Route) { r.Upstream = "ftp://example" }, "http(s) URL"},
		{"upstream with path", func(r *Route) { r.Upstream = "http://example/x" }, "must not contain"},
		{"upstream credentials", func(r *Route) { r.Upstream = "http://u:p@example" }, "must not contain"},
		{"bad auth", func(r *Route) { r.Auth = "anyone" }, "auth must be"},
		{"forward without auth", func(r *Route) { r.Auth = AuthNone; r.ForwardAuthorization = true }, "forward_authorization"},
		{"no body limit", func(r *Route) { r.MaxBodyBytes = 0 }, "max_body_bytes"},
		{"no ip limit", func(r *Route) { r.RateLimit.IPPerMin = 0 }, "ip_per_min"},
		{"no user limit", func(r *Route) { r.RateLimit.UserPerMin = 0 }, "user_per_min"},
		{"none needs no user limit", func(r *Route) { r.Auth = AuthNone; r.RateLimit.UserPerMin = 0 }, ""},
		{"no timeout", func(r *Route) { r.Timeout = 0 }, "timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRoute()
			tt.mutate(&r)
			err := Validate([]Route{r})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRejectsDuplicates(t *testing.T) {
	a, b := validRoute(), validRoute()
	if err := Validate([]Route{a, b}); err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("duplicate name: error = %v", err)
	}
	b.Name = "other"
	if err := Validate([]Route{a, b}); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("duplicate pattern: error = %v", err)
	}
	b.Methods = []string{http.MethodPut}
	if err := Validate([]Route{a, b}); err != nil {
		t.Fatalf("same path with another method should be fine: %v", err)
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "routes.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	routes, err := Load(writeFile(t, `
routes:
  - name: example
    path: /api/v1/example
    methods: [POST]
    upstream: http://example:8080
    auth: user
    forward_authorization: true
    max_body_bytes: 10485760
    rate_limit: { user_per_min: 10, ip_per_min: 20 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Timeout != defaultTimeout || !routes[0].ForwardAuthorization {
		t.Fatalf("routes = %+v", routes)
	}

	if _, err := Load(writeFile(t, "routes:\n  - name: x\n    typo_field: 1\n")); err == nil {
		t.Fatal("unknown field should be rejected")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file should be an error")
	}
	if _, err := Load(writeFile(t, "routes:\n  - name: x\n")); err == nil {
		t.Fatal("an invalid route should be an error")
	}
}

// --- request handling ---------------------------------------------------

func withClaims(h http.Handler, subject string, verified, admin bool, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subject != "" {
			claims := &jwt.Claims{}
			claims.Subject = subject
			claims.EmailVerified = &verified
			claims.SwayRiderClaims = jwt.NewSwayRiderUserClaims(admin, "standard")
			ctx := context.WithValue(r.Context(), security.ClaimsKey, claims)
			ctx = context.WithValue(ctx, security.JwtKey, token)
			r = r.WithContext(ctx)
		}
		h.ServeHTTP(w, r)
	})
}

type upstreamCall struct {
	method, path string
	header       http.Header
	body         string
}

func newUpstream(t *testing.T, status int) (*httptest.Server, *[]upstreamCall) {
	t.Helper()
	var calls []upstreamCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, upstreamCall{r.Method, r.URL.Path, r.Header.Clone(), string(body)})
		w.WriteHeader(status)
		_, _ = w.Write([]byte("upstream says hi"))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func newHandler(t *testing.T, breakers Breaker, routes ...Route) *http.ServeMux {
	t.Helper()
	set, err := NewSet(routes, breakers)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := set.Register(mux); err != nil {
		t.Fatal(err)
	}
	return mux
}

func do(h http.Handler, method, path, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if mutate != nil {
		mutate(r)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestAuthLevels(t *testing.T) {
	up, calls := newUpstream(t, http.StatusOK)
	mk := func(auth string) Route {
		r := validRoute()
		r.Name, r.Auth, r.Upstream = auth, auth, up.URL
		r.Path = "/api/v1/" + auth
		return r
	}
	mux := newHandler(t, nil, mk(AuthNone), mk(AuthUser), mk(AuthAdmin))

	tests := []struct {
		name            string
		path            string
		subject         string
		verified, admin bool
		want            int
	}{
		{"none, anonymous", "/api/v1/none", "", false, false, 200},
		{"user, anonymous", "/api/v1/user", "", false, false, 401},
		{"user, unverified", "/api/v1/user", "u1", false, false, 403},
		{"user, verified", "/api/v1/user", "u1", true, false, 200},
		{"admin, anonymous", "/api/v1/admin", "", false, false, 401},
		{"admin, plain user", "/api/v1/admin", "u1", true, false, 403},
		{"admin, admin", "/api/v1/admin", "a1", true, true, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(*calls)
			h := withClaims(mux, tt.subject, tt.verified, tt.admin, "tok")
			rec := do(h, http.MethodPost, tt.path, "x", nil)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			reached := len(*calls) > before
			if reached != (tt.want == 200) {
				t.Fatalf("upstream reached = %v for status %d", reached, rec.Code)
			}
		})
	}
}

func TestProxiesRequestAndResponse(t *testing.T) {
	up, calls := newUpstream(t, http.StatusCreated)
	r := validRoute()
	r.Upstream = up.URL
	mux := newHandler(t, nil, r)

	rec := do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example", "payload", nil)

	if rec.Code != http.StatusCreated || rec.Body.String() != "upstream says hi" {
		t.Fatalf("response = %d %q", rec.Code, rec.Body.String())
	}
	c := (*calls)[0]
	if c.method != http.MethodPost || c.path != "/api/v1/example" || c.body != "payload" {
		t.Fatalf("upstream saw %+v", c)
	}
}

func TestOnlyConfiguredMethodsAreServed(t *testing.T) {
	up, calls := newUpstream(t, http.StatusOK)
	r := validRoute()
	r.Upstream = up.URL
	mux := newHandler(t, nil, r)

	rec := do(withClaims(mux, "u1", true, false, "tok"), http.MethodGet, "/api/v1/example", "", nil)

	if rec.Code != http.StatusMethodNotAllowed || len(*calls) != 0 {
		t.Fatalf("GET: status = %d, upstream calls = %d", rec.Code, len(*calls))
	}
}

func TestPrefixRoute(t *testing.T) {
	up, calls := newUpstream(t, http.StatusOK)
	r := validRoute()
	r.Path = "/api/v1/example/"
	r.Upstream = up.URL
	mux := newHandler(t, nil, r)

	rec := do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example/a/b", "", nil)

	if rec.Code != 200 || (*calls)[0].path != "/api/v1/example/a/b" {
		t.Fatalf("status = %d, calls = %+v", rec.Code, *calls)
	}
}

func TestForwardsOnlyTheVerifiedToken(t *testing.T) {
	up, calls := newUpstream(t, http.StatusOK)
	r := validRoute()
	r.Upstream = up.URL
	r.ForwardAuthorization = true
	mux := newHandler(t, nil, r)

	do(withClaims(mux, "u1", true, false, "verified-token"), http.MethodPost, "/api/v1/example", "", func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer something-else")
		req.Header.Set("Cookie", "access_token=secret")
		req.Header.Set("X-SwayRider-User-Id", "attacker")
		req.Header.Set("X-Forwarded-User", "attacker")
		req.Header.Set("X-Auth-Request-User", "attacker")
		req.Header.Set("X-User-Id", "attacker")
		req.Header.Set("Content-Type", "application/gzip")
	})

	h := (*calls)[0].header
	if got := h.Get("Authorization"); got != "Bearer verified-token" {
		t.Errorf("Authorization = %q, want the verified token", got)
	}
	for _, name := range []string{"Cookie", "X-Swayrider-User-Id", "X-Forwarded-User", "X-Auth-Request-User", "X-User-Id"} {
		if v := h.Get(name); v != "" {
			t.Errorf("%s reached the upstream: %q", name, v)
		}
	}
	if h.Get("Content-Type") != "application/gzip" {
		t.Errorf("Content-Type was not passed on")
	}
}

func TestNoCredentialsWithoutForwarding(t *testing.T) {
	up, calls := newUpstream(t, http.StatusOK)
	r := validRoute()
	r.Upstream = up.URL
	r.ForwardAuthorization = false
	mux := newHandler(t, nil, r)

	do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example", "", func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer tok")
	})

	if got := (*calls)[0].header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none", got)
	}
}

func TestUnreachableUpstreamIs502(t *testing.T) {
	up, _ := newUpstream(t, http.StatusOK)
	url := up.URL
	up.Close()
	r := validRoute()
	r.Upstream = url
	mux := newHandler(t, nil, r)

	rec := do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example", "", nil)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestSlowUpstreamIs504(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	r := validRoute()
	r.Upstream = slow.URL
	r.Timeout = 50 * time.Millisecond
	mux := newHandler(t, nil, r)

	rec := do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example", "", nil)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", rec.Code)
	}
}

type fakeBreaker struct {
	open  bool
	calls atomic.Int32
}

func (f *fakeBreaker) Execute(_ string, fn func() error) error {
	f.calls.Add(1)
	if f.open {
		return gobreaker.ErrOpenState
	}
	return fn()
}

func TestOpenBreakerReturns503WithoutCallingUpstream(t *testing.T) {
	up, calls := newUpstream(t, http.StatusOK)
	r := validRoute()
	r.Upstream = up.URL
	fb := &fakeBreaker{open: true}
	mux := newHandler(t, fb, r)

	rec := do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example", "", nil)

	if rec.Code != http.StatusServiceUnavailable || len(*calls) != 0 {
		t.Fatalf("status = %d, upstream calls = %d", rec.Code, len(*calls))
	}
}

func TestBreakerSeesUpstreamFailures(t *testing.T) {
	up, _ := newUpstream(t, http.StatusServiceUnavailable)
	r := validRoute()
	r.Upstream = up.URL
	var failed error
	mux := newHandler(t, breakerFunc(func(_ string, fn func() error) error {
		failed = fn()
		return failed
	}), r)

	rec := do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example", "", nil)

	if failed == nil {
		t.Fatal("a 503 from the upstream should count as a failure")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("the upstream's answer should still reach the caller, got %d", rec.Code)
	}
}

type breakerFunc func(string, func() error) error

func (f breakerFunc) Execute(service string, fn func() error) error { return f(service, fn) }

func TestClientErrorsDoNotTripTheBreaker(t *testing.T) {
	up, _ := newUpstream(t, http.StatusBadRequest)
	r := validRoute()
	r.Upstream = up.URL
	failed := errors.New("not called")
	mux := newHandler(t, breakerFunc(func(_ string, fn func() error) error {
		failed = fn()
		return failed
	}), r)

	do(withClaims(mux, "u1", true, false, "tok"), http.MethodPost, "/api/v1/example", "", nil)

	if failed != nil {
		t.Fatalf("a 400 is the caller's fault, not a failure: %v", failed)
	}
}

func TestRegisterReportsClashesInsteadOfPanicking(t *testing.T) {
	r := validRoute()
	set, err := NewSet([]Route{r}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/example", func(http.ResponseWriter, *http.Request) {})

	if err := set.Register(mux); err == nil || !strings.Contains(err.Error(), "example") {
		t.Fatalf("error = %v, want a clash report naming the route", err)
	}
}

func TestNilSetIsHarmless(t *testing.T) {
	var set *Set
	r := httptest.NewRequest(http.MethodPost, "/api/v1/example", nil)
	if _, ok := set.Match(r); ok {
		t.Error("nil set matched")
	}
	if _, ok := set.BodyLimit(r); ok {
		t.Error("nil set has a body limit")
	}
	if _, ok := set.RateClass(r); ok {
		t.Error("nil set has a rate class")
	}
	if err := set.Register(http.NewServeMux()); err != nil {
		t.Error(err)
	}
	if len(set.Names()) != 0 || len(set.Describe()) != 0 {
		t.Error("nil set lists routes")
	}
}

func TestMatchPrefersTheMostSpecificPath(t *testing.T) {
	broad, narrow := validRoute(), validRoute()
	broad.Name, broad.Path = "broad", "/api/v1/example/"
	narrow.Name, narrow.Path = "narrow", "/api/v1/example/special/"
	set, err := NewSet([]Route{broad, narrow}, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, ok := set.Match(httptest.NewRequest(http.MethodPost, "/api/v1/example/special/x", nil))
	if !ok || got.Name != "narrow" {
		t.Fatalf("matched %q (%v), want narrow", got.Name, ok)
	}
	got, _ = set.Match(httptest.NewRequest(http.MethodPost, "/api/v1/example/other", nil))
	if got.Name != "broad" {
		t.Fatalf("matched %q, want broad", got.Name)
	}
}

func TestBodyLimitAndRateClassFollowTheRoute(t *testing.T) {
	r := validRoute()
	r.MaxBodyBytes = 4096
	set, err := NewSet([]Route{r}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/example", nil)

	if limit, ok := set.BodyLimit(req); !ok || limit != 4096 {
		t.Errorf("body limit = %d (%v)", limit, ok)
	}
	class, ok := set.RateClass(req)
	if !ok || class.Name != "example" || class.UserPerMin != 10 || class.IPPerMin != 5 || class.PerIPOnly {
		t.Errorf("rate class = %+v (%v)", class, ok)
	}
	other := httptest.NewRequest(http.MethodPost, "/api/v1/route", nil)
	if _, ok := set.BodyLimit(other); ok {
		t.Error("a built-in path got an extension body limit")
	}
}

func TestOversizedUploadIs413AndRouteLimitOverridesTheDefault(t *testing.T) {
	up, calls := newUpstream(t, http.StatusOK)
	r := validRoute()
	r.Upstream = up.URL
	r.MaxBodyBytes = 2048
	set, err := NewSet([]Route{r}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := set.Register(mux); err != nil {
		t.Fatal(err)
	}
	// The gateway-wide limit is 1 KiB; the route allows 2 KiB.
	chain := withClaims(middleware.BodyLimitWith(1024, set.BodyLimit)(mux), "u1", true, false, "tok")

	rec := do(chain, http.MethodPost, "/api/v1/example", strings.Repeat("x", 1500), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("1500 bytes: status = %d, want 200 (route limit is 2048)", rec.Code)
	}

	*calls = nil
	rec = do(chain, http.MethodPost, "/api/v1/example", strings.Repeat("x", 4096), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("4096 bytes: status = %d, want 413", rec.Code)
	}
}
