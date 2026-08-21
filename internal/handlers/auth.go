package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/swayrider/grpcclients/authclient"
	"github.com/swayrider/swlib/http/cookies"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthClient is satisfied by *authclient.Client.
type AuthClient interface {
	Login(email, password string, rememberMe bool, info ...authclient.ClientInfo) (accessToken, refreshToken string, mfaRequired bool, mfaToken string, err error)
	Register(email, password, verificationUrl string) (userId, message string, err error)
	Refresh(refreshToken string, rememberMe bool, info ...authclient.ClientInfo) (newAccessToken, newRefreshToken string, err error)
	Logout(refreshToken string) error
	RequestPasswordReset(email, resetUrl string) error
	ResetPassword(userId, token, newPassword string) (message string, err error)
	VerifyEmail(email, verificationUrl string) error
	ChangePassword(accessToken, oldPassword, newPassword string) (message string, err error)
	CheckPasswordStrength(password string) (isStrong bool, message string, err error)
	WhoAmI(accessToken string, userCtor authclient.UserCtor) (authclient.User, error)

	// MFA
	SetupMFA(accessToken string) (secret, otpauthURL, qrPNGBase64 string, err error)
	EnableMFA(accessToken, code string) (backupCodes []string, err error)
	DisableMFA(accessToken, password string) error
	GetMFAStatus(accessToken string) (enabled bool, err error)
	VerifyMFA(mfaToken, code string, rememberMe bool, info ...authclient.ClientInfo) (accessToken, refreshToken string, err error)
	GenerateBackupCodes(accessToken, password string) (backupCodes []string, err error)

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
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
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
	accessToken, refreshToken, mfaRequired, mfaToken, err := h.client.Login(
		req.Email, req.Password, req.RememberMe,
		authclient.ClientInfo{IP: ip},
	)
	if err != nil {
		lg.Warnf("login failed email_hash=%s ip=%s err=%v", emailHash(req.Email), ip, err)
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	lg.Infof("login ok email_hash=%s ip=%s", emailHash(req.Email), ip)
	if mfaRequired {
		// No cookies — the user must complete the second factor first.
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_token":    mfaToken,
		})
		return
	}
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
		writeError(w, h.l, err)
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
		writeError(w, h.l, err)
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
		writeError(w, h.l, err)
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
		writeError(w, h.l, err)
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
		writeError(w, h.l, err)
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
		writeError(w, h.l, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"is_strong": isStrong,
		"message":   message,
	})
}

func (h *AuthHandler) MfaSetup(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secret, otpauthURL, qrPNGBase64, err := h.client.SetupMFA(token)
	if err != nil {
		writeError(w, h.l, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":        secret,
		"otpauth_url":   otpauthURL,
		"qr_png_base64": qrPNGBase64,
	})
}

func (h *AuthHandler) MfaEnable(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	backupCodes, err := h.client.EnableMFA(token, req.Code)
	if err != nil {
		writeError(w, h.l, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"backup_codes": backupCodes,
	})
}

func (h *AuthHandler) MfaDisable(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := h.client.DisableMFA(token, req.Password); err != nil {
		writeError(w, h.l, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) MfaStatus(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	enabled, err := h.client.GetMFAStatus(token)
	if err != nil {
		writeError(w, h.l, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": enabled,
	})
}

func (h *AuthHandler) MfaVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MfaToken   string `json:"mfa_token"`
		Code       string `json:"code"`
		RememberMe bool   `json:"remember_me"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	ip, _ := security.GetOrigIp(r.Context())
	accessToken, refreshToken, err := h.client.VerifyMFA(
		req.MfaToken, req.Code, req.RememberMe,
		authclient.ClientInfo{IP: ip},
	)
	if err != nil {
		h.l.Derive(log.WithFunction("MfaVerify")).Warnf("mfa verify failed: %v", err)
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	setAuthCookies(w, r, accessToken, refreshToken)
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (h *AuthHandler) MfaBackupCodes(w http.ResponseWriter, r *http.Request) {
	token, ok := security.GetJwt(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	backupCodes, err := h.client.GenerateBackupCodes(token, req.Password)
	if err != nil {
		writeError(w, h.l, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"backup_codes": backupCodes,
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
		writeError(w, h.l, err)
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
		"email": func() any {
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

// emailHash returns a stable, non-reversible fingerprint of an email address
// for logs. Raw addresses are never written to logs — they are PII, and a
// failed-login log would otherwise double as an account-existence enumeration
// trail for anyone with log access. The deterministic hash keeps repeated
// attempts against the same account correlatable for forensics without
// revealing the address.
func emailHash(email string) string {
	sum := sha256.Sum256([]byte(email))
	return fmt.Sprintf("%x", sum[:8])
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

// grpcStatus maps gRPC status codes to HTTP status codes.
func grpcStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch status.Code(err) {
	case codes.NotFound:
		return http.StatusNotFound
	case codes.AlreadyExists:
		return http.StatusConflict
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.FailedPrecondition:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// breachedPasswordPrefix matches authservice's ErrBreachedPasswordPrefix
// (authservice/internal/server/breached_checker.go). The prefix is the
// contract between the two services; the tail may carry detail (e.g. the
// breach count) and must not be matched.
const breachedPasswordPrefix = "password has appeared in a known data breach"

// passwordReusedPrefix matches authservice's ErrPasswordReusedPrefix
// (authservice/internal/server/password_history.go).
const passwordReusedPrefix = "password has been used before"

// errBody returns a sanitized error body: a generic per-code message plus a
// stable machine-readable code. The downstream error text is never echoed to
// the client — it can contain SQL errors, service internals, or
// account-enumeration details. Password rejections additionally carry a
// "reason" so clients can offer a precise hint without matching on message
// text.
func errBody(err error) map[string]any {
	body := map[string]any{
		"error": genericMessage(err),
		"code":  status.Code(err).String(),
	}
	if s, ok := status.FromError(err); ok {
		switch {
		case strings.HasPrefix(s.Message(), "password is too weak"):
			body["reason"] = "weak_password"
		case strings.HasPrefix(s.Message(), breachedPasswordPrefix):
			body["reason"] = "breached_password"
		case strings.HasPrefix(s.Message(), passwordReusedPrefix):
			body["reason"] = "password_reused"
		}
	}
	return body
}

// genericMessage returns the safe client-facing message for a gRPC error.
// Non-gRPC errors (connection failures, etc.) map to a generic internal error.
func genericMessage(err error) string {
	switch status.Code(err) {
	case codes.NotFound:
		return "not found"
	case codes.AlreadyExists:
		return "already exists"
	case codes.PermissionDenied:
		return "permission denied"
	case codes.Unauthenticated:
		return "unauthenticated"
	case codes.InvalidArgument:
		return "invalid argument"
	case codes.ResourceExhausted:
		return "resource exhausted"
	case codes.FailedPrecondition:
		return "failed precondition"
	default:
		return "internal error"
	}
}

// writeError logs the full downstream error (which is never sent to the
// client) and writes the sanitized error response.
func writeError(w http.ResponseWriter, l *log.Logger, err error) {
	l.Errorf("request failed: %v", err)
	writeJSON(w, grpcStatus(err), errBody(err))
}
