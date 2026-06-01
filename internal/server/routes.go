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

	// Route (async SSE) — requires verified user
	mux.Handle("POST /api/v1/route", middleware.RequireVerifiedUser(http.HandlerFunc(s.route.Route)))

	// Search (async SSE) — requires verified user
	mux.Handle("POST /api/v1/search", middleware.RequireVerifiedUser(http.HandlerFunc(s.search.Search)))
	mux.Handle("POST /api/v1/search/reverse", middleware.RequireVerifiedUser(http.HandlerFunc(s.search.ReverseGeocode)))

	// Region — requires verified user
	region := s.region
	mux.Handle("POST /api/v1/region/search-point", middleware.RequireVerifiedUser(http.HandlerFunc(region.SearchPoint)))
	mux.Handle("POST /api/v1/region/search-box", middleware.RequireVerifiedUser(http.HandlerFunc(region.SearchBox)))
	mux.Handle("POST /api/v1/region/search-radius", middleware.RequireVerifiedUser(http.HandlerFunc(region.SearchRadius)))
	mux.Handle("POST /api/v1/region/find-crossing-locations", middleware.RequireVerifiedUser(http.HandlerFunc(region.FindCrossingLocations)))
	mux.Handle("POST /api/v1/region/find-region-path", middleware.RequireVerifiedUser(http.HandlerFunc(region.FindRegionPath)))

	// Tiles — HTTP reverse proxy, requires verified user
	mux.Handle("/v1/tiles/", middleware.RequireVerifiedUser(s.tiles))

	// Auth — admin only
	mux.Handle("POST /api/v1/auth/admin/create-admin", middleware.RequireAdmin(http.HandlerFunc(auth.CreateAdmin)))
	mux.Handle("POST /api/v1/auth/admin/change-account-type", middleware.RequireAdmin(http.HandlerFunc(auth.ChangeAccountType)))
	mux.Handle("POST /api/v1/auth/admin/whois", middleware.RequireAdmin(http.HandlerFunc(auth.WhoIs)))
	mux.Handle("POST /api/v1/auth/admin/create-service-client", middleware.RequireAdmin(http.HandlerFunc(auth.CreateServiceClient)))
	mux.Handle("POST /api/v1/auth/admin/delete-service-client", middleware.RequireAdmin(http.HandlerFunc(auth.DeleteServiceClient)))
	mux.Handle("GET /api/v1/auth/admin/list-service-clients", middleware.RequireAdmin(http.HandlerFunc(auth.ListServiceClients)))
	mux.Handle("POST /api/v1/auth/admin/invite-user", middleware.RequireAdmin(http.HandlerFunc(auth.InviteUser)))
	mux.Handle("POST /api/v1/auth/admin/revoke-invite", middleware.RequireAdmin(http.HandlerFunc(auth.RevokeInvite)))
	mux.Handle("GET /api/v1/auth/admin/list-invites", middleware.RequireAdmin(http.HandlerFunc(auth.ListInvites)))

	// Auth web pages — HTTP reverse proxy (strip /web prefix)
	mux.Handle("/web/", s.web)
}
