package server

import (
	"net/http"

	"github.com/swayrider/swayrider-api/internal/handlers"
	"github.com/swayrider/swayrider-api/internal/middleware"
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

	// Route (async SSE)
	mux.HandleFunc("POST /api/v1/route", s.route.Route)

	// Search (async SSE)
	mux.HandleFunc("POST /api/v1/search", s.search.Search)
	mux.HandleFunc("POST /api/v1/search/reverse", s.search.ReverseGeocode)

	// Region — requires authenticated user
	region := s.region
	mux.Handle("POST /api/v1/region/search-point", middleware.RequireUser(http.HandlerFunc(region.SearchPoint)))
	mux.Handle("POST /api/v1/region/search-box", middleware.RequireUser(http.HandlerFunc(region.SearchBox)))
	mux.Handle("POST /api/v1/region/search-radius", middleware.RequireUser(http.HandlerFunc(region.SearchRadius)))
	mux.Handle("POST /api/v1/region/find-crossing-locations", middleware.RequireUser(http.HandlerFunc(region.FindCrossingLocations)))
	mux.Handle("POST /api/v1/region/find-region-path", middleware.RequireUser(http.HandlerFunc(region.FindRegionPath)))

	// Tiles — HTTP reverse proxy, requires authenticated user
	mux.Handle("/v1/tiles/", middleware.RequireUser(s.tiles))

	// Auth web pages — HTTP reverse proxy (strip /web prefix)
	mux.Handle("/web/", s.web)
}
