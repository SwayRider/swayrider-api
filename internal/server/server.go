package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/cors"
	"github.com/swayrider/swayrider-api/internal/circuitbreaker"
	"github.com/swayrider/swayrider-api/internal/config"
	"github.com/swayrider/swayrider-api/internal/handlers"
	"github.com/swayrider/swayrider-api/internal/middleware"
	"github.com/swayrider/swayrider-api/internal/ratelimit"
	"github.com/swayrider/swlib/jwtkeys"
	log "github.com/swayrider/swlib/logger"
)

type Server struct {
	cfg      *config.Config
	l        *log.Logger
	auth     *handlers.AuthHandler
	region   *handlers.RegionHandler
	route    *handlers.RouteHandler
	search   *handlers.SearchHandler
	tiles    http.Handler
	web      http.Handler
	keyCache *jwtkeys.Cache
	limiter  *ratelimit.Limiter
	breakers *circuitbreaker.Registry
}

func New(
	cfg *config.Config,
	l *log.Logger,
	auth *handlers.AuthHandler,
	region *handlers.RegionHandler,
	route *handlers.RouteHandler,
	search *handlers.SearchHandler,
	tiles http.Handler,
	web http.Handler,
	keyCache *jwtkeys.Cache,
	limiter *ratelimit.Limiter,
	breakers *circuitbreaker.Registry,
) *Server {
	return &Server{
		cfg:      cfg,
		l:        l.Derive(log.WithComponent("server")),
		auth:     auth,
		region:   region,
		route:    route,
		search:   search,
		tiles:    tiles,
		web:      web,
		keyCache: keyCache,
		limiter:  limiter,
		breakers: breakers,
	}
}

func (s *Server) Run(ctx context.Context) {
	lg := s.l.Derive(log.WithFunction("Run"))

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	rateCfg := middleware.RateLimitConfig{
		IPAuth:        s.cfg.RateLimitIPAuth,
		IPPublic:      s.cfg.RateLimitIPPublic,
		IPAPI:         s.cfg.RateLimitIPAPI,
		UserAPI:       s.cfg.RateLimitUserAPI,
		UserExpensive: s.cfg.RateLimitUserExpensive,
	}

	// Middleware chain (innermost first): mux → bodyLimit → rateLimit → logging → auth → cors
	handler := middleware.Auth(s.keyCache, parseTrustedProxies(s.cfg.TrustedProxies, lg))(
		middleware.Logging(s.l)(
			middleware.RateLimit(s.limiter, rateCfg, s.l)(
				middleware.BodyLimit(s.cfg.MaxBodyBytes)(mux),
			),
		),
	)

	allowedOrigins, err := normalizeCORSOrigins(s.cfg.CORSAllowedOrigins)
	if err != nil {
		lg.Fatalf("invalid CORS configuration: %v", err)
	}

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(handler)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.cfg.HTTPPort),
		Handler: corsHandler,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lg.Errorf("server error: %v", err)
			os.Exit(1)
		}
	}()

	lg.Infof("listening on :%d", s.cfg.HTTPPort)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-quit:
		lg.Infoln("shutdown signal received")
	case <-ctx.Done():
		lg.Infoln("context cancelled, shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		lg.Errorf("graceful shutdown error: %v", err)
	} else {
		lg.Infoln("shutdown complete")
	}
}

// normalizeCORSOrigins trims whitespace from each configured origin (the env
// helper splits on commas without trimming, so "a, b" would otherwise produce
// a never-matching " b" entry) and validates the list.
//
// AllowCredentials is always enabled, so a bare "*" — which rs/cors would
// turn into "reflect every origin with credentials" — or an empty entry is a
// misconfiguration. It fails startup rather than silently opening credentialed
// cross-origin access. Explicit patterns (e.g. "https://*.example.com") are
// allowed; rs/cors scopes them to the pattern.
func normalizeCORSOrigins(origins []string) ([]string, error) {
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o == "" {
			return nil, errors.New("CORS_ALLOWED_ORIGINS contains an empty entry")
		}
		if o == "*" {
			return nil, errors.New("CORS_ALLOWED_ORIGINS must not contain \"*\" while AllowCredentials is enabled")
		}
		out = append(out, o)
	}
	return out, nil
}

// parseTrustedProxies converts the configured TRUSTED_PROXIES CIDRs into
// *net.IPNet values. Invalid entries are logged and skipped — an empty result
// means no proxy headers are trusted, which is the secure default.
func parseTrustedProxies(cidrs []string, lg *log.Logger) []*net.IPNet {
	var trusted []*net.IPNet
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			lg.Errorf("invalid TRUSTED_PROXIES entry %q, ignoring: %v", c, err)
			continue
		}
		trusted = append(trusted, ipnet)
	}
	return trusted
}
