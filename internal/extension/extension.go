// Package extension lets an operator add proxied routes to the gateway with a
// configuration file, without changing the gateway's code.
//
// Each route forwards one path to an upstream HTTP service. The gateway keeps
// doing what it does for its own endpoints: it authenticates the caller,
// applies a rate limit and a body-size limit, and shuts the route off with a
// circuit breaker when the upstream keeps failing.
//
// The feature is off unless EXTENSION_ROUTES_FILE is set.
package extension

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sony/gobreaker"
	"github.com/swayrider/swayrider-api/internal/middleware"
	"github.com/swayrider/swlib/security"
	"gopkg.in/yaml.v3"
)

// Authentication levels a route can require of its callers.
const (
	AuthNone  = "none"  // anyone; limited per IP
	AuthUser  = "user"  // a signed-in user with a verified email
	AuthAdmin = "admin" // an administrator
)

const defaultTimeout = 30 * time.Second

// reservedPrefixes belong to the gateway's own endpoints; extension routes
// may not use them.
var reservedPrefixes = []string{
	"/api/v1/auth",
	"/api/v1/route",
	"/api/v1/search",
	"/api/v1/region",
	"/v1/tiles",
	"/web",
	"/health",
	"/api/openapi.yaml",
}

var allowedMethods = map[string]bool{
	http.MethodGet:    true,
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodDelete: true,
}

// RateLimit bounds how often a route may be called, per minute.
type RateLimit struct {
	UserPerMin int `yaml:"user_per_min"` // signed-in callers, counted per user
	IPPerMin   int `yaml:"ip_per_min"`   // anonymous callers, counted per IP
}

// Route is one proxied path.
type Route struct {
	// Name labels the route in logs and names its rate-limit class and
	// circuit breaker.
	Name string `yaml:"name"`
	// Path is matched exactly, or as a prefix when it ends with "/". It is
	// passed to the upstream unchanged.
	Path    string   `yaml:"path"`
	Methods []string `yaml:"methods"`
	// Upstream is the base URL of the service (scheme, host and optional
	// port; no path).
	Upstream string `yaml:"upstream"`
	// Auth is one of none, user or admin.
	Auth string `yaml:"auth"`
	// ForwardAuthorization passes the caller's bearer token to the upstream so
	// it can identify the user. Without it the upstream gets no credentials.
	ForwardAuthorization bool          `yaml:"forward_authorization"`
	MaxBodyBytes         int64         `yaml:"max_body_bytes"`
	Timeout              time.Duration `yaml:"timeout"`
	RateLimit            RateLimit     `yaml:"rate_limit"`
}

type file struct {
	Routes []Route `yaml:"routes"`
}

// Load reads and validates a routes file.
func Load(path string) ([]Route, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read extension routes: %w", err)
	}
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse extension routes %s: %w", path, err)
	}
	for i := range f.Routes {
		if f.Routes[i].Timeout == 0 {
			f.Routes[i].Timeout = defaultTimeout
		}
	}
	if err := Validate(f.Routes); err != nil {
		return nil, fmt.Errorf("extension routes %s: %w", path, err)
	}
	return f.Routes, nil
}

// Validate reports the first problem in routes. A route that would be unsafe
// or ambiguous stops the gateway from starting rather than being skipped.
func Validate(routes []Route) error {
	names := map[string]bool{}
	patterns := map[string]string{}
	for i, r := range routes {
		where := fmt.Sprintf("route %d (%q)", i+1, r.Name)
		if r.Name == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		if names[r.Name] {
			return fmt.Errorf("%s: duplicate name", where)
		}
		names[r.Name] = true

		if err := validatePath(r.Path); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if len(r.Methods) == 0 {
			return fmt.Errorf("%s: at least one method is required", where)
		}
		for _, m := range r.Methods {
			if !allowedMethods[m] {
				return fmt.Errorf("%s: method %q is not allowed (GET, POST, PUT, DELETE)", where, m)
			}
			key := m + " " + r.Path
			if other, dup := patterns[key]; dup {
				return fmt.Errorf("%s: %s is already used by route %q", where, key, other)
			}
			patterns[key] = r.Name
		}
		if err := validateUpstream(r.Upstream); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		switch r.Auth {
		case AuthNone, AuthUser, AuthAdmin:
		default:
			return fmt.Errorf("%s: auth must be none, user or admin, got %q", where, r.Auth)
		}
		if r.ForwardAuthorization && r.Auth == AuthNone {
			return fmt.Errorf("%s: forward_authorization needs auth user or admin", where)
		}
		if r.MaxBodyBytes <= 0 {
			return fmt.Errorf("%s: max_body_bytes must be set", where)
		}
		if r.Timeout <= 0 {
			return fmt.Errorf("%s: timeout must be positive", where)
		}
		if r.RateLimit.IPPerMin <= 0 {
			return fmt.Errorf("%s: rate_limit.ip_per_min must be set", where)
		}
		if r.Auth != AuthNone && r.RateLimit.UserPerMin <= 0 {
			return fmt.Errorf("%s: rate_limit.user_per_min must be set", where)
		}
	}
	return nil
}

func validatePath(p string) error {
	const base = "/api/v1/"
	if !strings.HasPrefix(p, base) || len(p) == len(base) {
		return fmt.Errorf("path %q must start with %s and name a resource", p, base)
	}
	if strings.ContainsAny(p, " ?#{}*") || strings.Contains(p, "..") || strings.Contains(p, "//") {
		return fmt.Errorf("path %q contains characters that are not allowed", p)
	}
	for _, reserved := range reservedPrefixes {
		if p == reserved || strings.HasPrefix(p, reserved+"/") {
			return fmt.Errorf("path %q is reserved for the gateway's own endpoints", p)
		}
	}
	return nil
}

func validateUpstream(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("upstream %q must be an http(s) URL with a host", raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("upstream %q must not contain a path, query or credentials", raw)
	}
	return nil
}

// Breaker is satisfied by *circuitbreaker.Registry.
type Breaker interface {
	Execute(service string, fn func() error) error
}

// Set is the configured routes. The zero value and a nil *Set have no routes.
type Set struct {
	routes   []Route
	breakers Breaker
}

// NewSet validates routes and returns the set. breakers may be nil.
func NewSet(routes []Route, breakers Breaker) (*Set, error) {
	if err := Validate(routes); err != nil {
		return nil, err
	}
	return &Set{routes: routes, breakers: breakers}, nil
}

// Names lists the route names, for registering circuit breakers.
func (s *Set) Names() []string {
	if s == nil {
		return nil
	}
	names := make([]string, len(s.routes))
	for i, r := range s.routes {
		names[i] = r.Name
	}
	return names
}

// Match returns the route that serves r, preferring the most specific path.
func (s *Set) Match(r *http.Request) (Route, bool) {
	if s == nil {
		return Route{}, false
	}
	var best Route
	found := false
	for _, route := range s.routes {
		if !matchesPath(route.Path, r.URL.Path) || !hasMethod(route.Methods, r.Method) {
			continue
		}
		if !found || len(route.Path) > len(best.Path) {
			best, found = route, true
		}
	}
	return best, found
}

func matchesPath(pattern, path string) bool {
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, pattern)
	}
	return path == pattern
}

func hasMethod(methods []string, m string) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

// BodyLimit is a middleware.BodyLimitFunc override: the route's own limit for
// a matching request.
func (s *Set) BodyLimit(r *http.Request) (int64, bool) {
	route, ok := s.Match(r)
	if !ok {
		return 0, false
	}
	return route.MaxBodyBytes, true
}

// RateClass is a middleware.RateLimitConfig.Extension hook: the route's own
// rate-limit class for a matching request.
func (s *Set) RateClass(r *http.Request) (middleware.ExtensionClass, bool) {
	route, ok := s.Match(r)
	if !ok {
		return middleware.ExtensionClass{}, false
	}
	return middleware.ExtensionClass{
		Name:       route.Name,
		UserPerMin: route.RateLimit.UserPerMin,
		IPPerMin:   route.RateLimit.IPPerMin,
		PerIPOnly:  route.Auth == AuthNone,
	}, true
}

// Register adds the routes to mux. A route that clashes with one already on
// the mux is reported as an error instead of panicking.
func (s *Set) Register(mux *http.ServeMux) (err error) {
	if s == nil {
		return nil
	}
	var current Route
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("extension route %q: %v", current.Name, rec)
		}
	}()
	for _, route := range s.routes {
		current = route
		h := s.handler(route)
		for _, m := range route.Methods {
			mux.Handle(m+" "+route.Path, h)
		}
	}
	return nil
}

func (s *Set) handler(route Route) http.Handler {
	target, _ := url.Parse(route.Upstream) // validated
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			prepareUpstreamRequest(pr.Out, pr.In, route.ForwardAuthorization)
		},
		Transport: newTransport(route.Timeout),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var tooBig *http.MaxBytesError
			switch {
			case errors.As(err, &tooBig):
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			case errors.Is(err, context.DeadlineExceeded):
				http.Error(w, "upstream timed out", http.StatusGatewayTimeout)
			default:
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
			}
		},
	}

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), route.Timeout)
		defer cancel()
		r = r.WithContext(ctx)

		if s.breakers == nil {
			proxy.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		err := s.breakers.Execute(route.Name, func() error {
			proxy.ServeHTTP(rec, r)
			if rec.status >= http.StatusBadGateway {
				return fmt.Errorf("upstream status %d", rec.status)
			}
			return nil
		})
		if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		}
	})

	switch route.Auth {
	case AuthUser:
		h = middleware.RequireVerifiedUser(h)
	case AuthAdmin:
		h = middleware.RequireAdmin(h)
	}
	return h
}

// prepareUpstreamRequest decides what the upstream gets to see of the
// caller's request.
//
// Cookies are dropped, and so is every header that looks like a claim about
// who the caller is: the upstream must learn the identity from the verified
// bearer token, never from something the client typed.
func prepareUpstreamRequest(out, in *http.Request, forwardAuthorization bool) {
	out.Header.Del("Cookie")
	out.Header.Del("Authorization")
	for name := range out.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-swayrider-") || strings.HasPrefix(lower, "x-forwarded-user") ||
			strings.HasPrefix(lower, "x-auth-") || lower == "x-user-id" || lower == "x-remote-user" {
			out.Header.Del(name)
		}
	}
	if forwardAuthorization {
		// The gateway has verified this token (header or cookie).
		if token, ok := in.Context().Value(security.JwtKey).(string); ok && token != "" {
			out.Header.Set("Authorization", "Bearer "+token)
		}
	}
}

func newTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush keeps streaming responses working through the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Describe returns one line per route, for the startup log.
func (s *Set) Describe() []string {
	if s == nil {
		return nil
	}
	lines := make([]string, 0, len(s.routes))
	for _, r := range s.routes {
		methods := append([]string(nil), r.Methods...)
		sort.Strings(methods)
		lines = append(lines, fmt.Sprintf("%s %s %s -> %s (auth=%s)",
			r.Name, strings.Join(methods, ","), r.Path, r.Upstream, r.Auth))
	}
	return lines
}
