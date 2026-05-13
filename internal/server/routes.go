package server

import (
	"net/http"

	"github.com/swayrider/swayrider-api/internal/handlers"
)

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health
	mux.HandleFunc("GET /health", handlers.Health)

	// Auth
	auth := s.auth
	mux.HandleFunc("POST /api/v1/auth/login", auth.Login)
	mux.HandleFunc("POST /api/v1/auth/register", auth.Register)
	mux.HandleFunc("POST /api/v1/auth/refresh", auth.Refresh)
	mux.HandleFunc("POST /api/v1/auth/logout", auth.Logout)
	mux.HandleFunc("POST /api/v1/auth/request-password-reset", auth.RequestPasswordReset)
	mux.HandleFunc("POST /api/v1/auth/reset-password", auth.ResetPassword)
	mux.HandleFunc("POST /api/v1/auth/verify-email", auth.VerifyEmail)
	mux.HandleFunc("POST /api/v1/auth/change-password", auth.ChangePassword)
	mux.HandleFunc("POST /api/v1/auth/check-password-strength", auth.CheckPasswordStrength)
	mux.HandleFunc("GET /api/v1/auth/public-keys", auth.PublicKeys)
	mux.HandleFunc("GET /api/v1/auth/whoami", auth.WhoAmI)
	mux.HandleFunc("GET /api/v1/auth/me", auth.Me)

	// Region (all public)
	region := s.region
	mux.HandleFunc("POST /api/v1/region/search-point", region.SearchPoint)
	mux.HandleFunc("POST /api/v1/region/search-box", region.SearchBox)
	mux.HandleFunc("POST /api/v1/region/search-radius", region.SearchRadius)
	mux.HandleFunc("POST /api/v1/region/find-crossing-locations", region.FindCrossingLocations)
	mux.HandleFunc("POST /api/v1/region/find-region-path", region.FindRegionPath)

	// Tiles — HTTP reverse proxy (public, no auth)
	mux.Handle("/v1/tiles/", s.tiles)

	// Auth web pages — HTTP reverse proxy (strip /web prefix)
	mux.Handle("/web/", s.web)
}
