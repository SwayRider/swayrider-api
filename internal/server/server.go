package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/cors"
	"github.com/swayrider/swayrider-api/internal/circuitbreaker"
	"github.com/swayrider/swayrider-api/internal/config"
	"github.com/swayrider/swayrider-api/internal/handlers"
	"github.com/swayrider/swayrider-api/internal/jwtkeys"
	"github.com/swayrider/swayrider-api/internal/middleware"
	"github.com/swayrider/swayrider-api/internal/ratelimit"
)

type Server struct {
	cfg      *config.Config
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
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	rateCfg := middleware.RateLimitConfig{
		IPAuth:        s.cfg.RateLimitIPAuth,
		IPPublic:      s.cfg.RateLimitIPPublic,
		UserAPI:       s.cfg.RateLimitUserAPI,
		UserExpensive: s.cfg.RateLimitUserExpensive,
	}

	// Middleware chain (innermost first): mux → rateLimit → auth → cors
	handler := middleware.Auth(s.keyCache)(
		middleware.RateLimit(s.limiter, rateCfg)(mux),
	)

	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   s.cfg.CORSAllowedOrigins,
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
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}()

	fmt.Printf("swayrider-api listening on :%d\n", s.cfg.HTTPPort)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-quit:
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "graceful shutdown error: %v\n", err)
	}
}
