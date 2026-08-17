package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/swayrider/grpcclients/authclient"
	"github.com/swayrider/swlib/http/cookies"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

// AuthClient is satisfied by *authclient.Client.
type AuthClient interface {
	Login(email, password string, rememberMe bool, info ...authclient.ClientInfo) (accessToken, refreshToken string, err error)
	Register(email, password, verificationUrl string) (userId, message string, err error)
	Refresh(refreshToken string, rememberMe bool, info ...authclient.ClientInfo) (newAccessToken, newRefreshToken string, err error)
	Logout(refreshToken string) error
	RequestPasswordReset(email, resetUrl string) error
	ResetPassword(userId, token, newPassword string) (message string, err error)
	VerifyEmail(email, verificationUrl string) error
	ChangePassword(accessToken, oldPassword, newPassword string) (message string, err error)
	CheckPasswordStrength(password string) (isStrong bool, message string, err error)
	WhoAmI(accessToken string, userCtor authclient.UserCtor) (authclient.User, error)

	// Admin methods
	CreateAdmin(accessToken, email, password string) (userId, message string, err error)
	ChangeAccountType(accessToken, userId, accountType string) (message string, err error)
	WhoIs(accessToken string, lookup authclient.WhoIsOneOf, userCtor authclient.UserCtor) (authclient.User, error)
	CreateServiceClient(accessToken, name, description string, scopes []string) (clientId, clientSecret string, err error)
	DeleteServiceClient(accessToken, clientId string) (message string, err error)
	ListServiceClients(accessToken string, page, pageSize int, ctor authclient.ServiceClientCtor) ([]authclient.ServiceClient, int32, error)
	InviteUser(accessToken, email string) (message string, err error)
	RevokeInvite(accessToken, email string) (message string, err error)
	ListInvites(accessToken string, page, pageSize int, registered *bool, ctor authclient.InviteCtor) ([]authclient.Invite, int32, error)
}

// KeysProvider is satisfied by *jwtkeys.Cache.
type KeysProvider interface {
	Keys() []string
}

type AuthHandler struct {
	client AuthClient
	keys   KeysProvider
	l      *log.Logger
}

func NewAuthHandler(client AuthClient, keys KeysProvider, l *log.Logger) *AuthHandler {
	return &AuthHandler{
		client: client,
		keys:   keys,
		l:      l.Derive(log.WithComponent("auth")),
	}
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func setAuthCookies(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	opts := cookies.NewCookieOptsFromContext(r.Context())
	opts.SetSameSite(http.SameSiteStrictMode)

	http.SetCookie(w, cookies.NewServerCookie("access_token", []byte(accessToken), opts))

	refreshOpts := opts
	refreshOpts.SetPath("/api/v1/auth/refresh")
	http.SetCookie(w, cookies.NewServerCookie("refresh_token", []byte(refreshToken), refreshOpts))
}

func clearAuthCookies(w http.ResponseWriter) {
	opts := cookies.NewCookieOpts()
	opts.SetSameSite(http.SameSiteStrictMode)

	http.SetCookie(w, cookies.ClearCookie("access_token", opts))

	refreshOpts := opts
	refreshOpts.SetPath("/api/v1/auth/refresh")
	http.SetCookie(w, cookies.ClearCookie("refresh_token", refreshOpts))
}

// --- handlers ---

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	lg := h.l.Derive(log.WithFunction("Login"))
	var req struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		RememberMe bool   `json:"remember_me"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	ip, _ := security.GetOrigIp(r.Context())
	accessToken, refreshToken, err := h.client.Login(
		req.Email, req.Password, req.RememberMe,
		authclient.ClientInfo{IP: ip},
	)
	if err != nil {
		lg.Warnf("login failed email=%s ip=%s err=%v", req.Email, ip, err)
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	lg.Infof("login ok email=%s ip=%s", req.Email, ip)
	setAuthCookies(w, r, accessToken, refreshToken)
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email           string `json:"email"`
		Password        string `json:"password"`
		VerificationURL string `json:"verification_url"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	userID, message, err := h.client.Register(req.Email, req.Password, req.VerificationURL)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id": userID,
		"message": message,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Accept refresh token from cookie (web) or request body (mobile).
	refreshToken, _ := security.GetRefreshToken(r.Context())
	rememberMe := false

	if refreshToken == "" {
		var req struct {
			RefreshToken string `json:"refresh_token"`
			RememberMe   bool   `json:"remember_me"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			refreshToken = req.RefreshToken
			rememberMe = req.RememberMe
		}
	}

	if refreshToken == "" {
		http.Error(w, "refresh token required", http.StatusBadRequest)
		return
	}

	ip, _ := security.GetOrigIp(r.Context())
	newAccess, newRefresh, err := h.client.Refresh(
		refreshToken, rememberMe,
		authclient.ClientInfo{IP: ip},
	)
	if err != nil {
		h.l.Derive(log.WithFunction("Refresh")).Warnf("token refresh failed: %v", err)
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	setAuthCookies(w, r, newAccess, newRefresh)
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  newAccess,
		"refresh_token": newRefresh,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	refreshToken, _ := security.GetRefreshToken(r.Context())
	if refreshToken == "" {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			refreshToken = req.RefreshToken
		}
	}

	if err := h.client.Logout(refreshToken); err != nil {
		h.l.Derive(log.WithFunction("Logout")).Warnf("logout failed: %v", err)
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		ResetURL string `json:"reset_url"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := h.client.RequestPasswordReset(req.Email, req.ResetURL); err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID      string `json:"user_id"`
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	message, err := h.client.ResetPassword(req.UserID, req.Token, req.NewPassword)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": message})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email           string `json:"email"`
		VerificationURL string `json:"verification_url"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := h.client.VerifyEmail(req.Email, req.VerificationURL); err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	message, err := h.client.ChangePassword(token, req.OldPassword, req.NewPassword)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": message})
}

func (h *AuthHandler) CheckPasswordStrength(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	isStrong, message, err := h.client.CheckPasswordStrength(req.Password)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"is_strong": isStrong,
		"message":   message,
	})
}

func (h *AuthHandler) WhoAmI(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := h.client.WhoAmI(token, func(userID, email string, isVerified, isAdmin bool, accountType string) authclient.User {
		return whoAmIUser{userID, email, isVerified, isAdmin, accountType}
	})
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      user.UserId(),
		"email":        user.Email(),
		"is_verified":  user.IsVerified(),
		"is_admin":     user.IsAdmin(),
		"account_type": user.AccountType(),
	})
}

// Me returns the authenticated user's claims directly without a gRPC call.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := security.GetClaims(r.Context())
	if !ok || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": claims.Subject,
		"email":   func() any {
			if claims.Email != nil {
				return *claims.Email
			}
			return nil
		}(),
		"email_verified": claims.EmailVerified,
	})
}

// PublicKeys returns the cached JWT public keys (no downstream call).
func (h *AuthHandler) PublicKeys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": h.keys.Keys(),
	})
}

// --- internal types ---

type whoAmIUser struct {
	userID      string
	email       string
	isVerified  bool
	isAdmin     bool
	accountType string
}

func (u whoAmIUser) UserId() string      { return u.userID }
func (u whoAmIUser) Email() string       { return u.email }
func (u whoAmIUser) IsVerified() bool    { return u.isVerified }
func (u whoAmIUser) IsAdmin() bool       { return u.isAdmin }
func (u whoAmIUser) AccountType() string { return u.accountType }

// grpcStatus maps gRPC error messages to HTTP status codes.
func grpcStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "NotFound"):
		return http.StatusNotFound
	case strings.Contains(msg, "AlreadyExists"):
		return http.StatusConflict
	case strings.Contains(msg, "PermissionDenied"):
		return http.StatusForbidden
	case strings.Contains(msg, "Unauthenticated"):
		return http.StatusUnauthorized
	case strings.Contains(msg, "InvalidArgument"):
		return http.StatusBadRequest
	case strings.Contains(msg, "ResourceExhausted"):
		return http.StatusTooManyRequests
	case strings.Contains(msg, "FailedPrecondition"):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func errBody(err error) map[string]string {
	return map[string]string{"error": err.Error()}
}
