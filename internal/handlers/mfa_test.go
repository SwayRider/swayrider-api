package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swayrider/grpcclients/authclient"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stubAuthClient is a minimal AuthClient for handler tests: the MFA and Login
// methods are configurable, everything else is a no-op returning zero values.
type stubAuthClient struct {
	loginFn        func(email, password string, rememberMe bool, info ...authclient.ClientInfo) (accessToken, refreshToken string, mfaRequired bool, mfaToken string, err error)
	setupMFAFn     func(accessToken string) (secret, otpauthURL, qrPNGBase64 string, err error)
	enableMFAFn    func(accessToken, code string) (backupCodes []string, err error)
	disableMFAFn   func(accessToken, password string) error
	getMFAStatusFn func(accessToken string) (enabled bool, err error)
	verifyMFAFn    func(mfaToken, code string, rememberMe bool, info ...authclient.ClientInfo) (accessToken, refreshToken string, err error)
	backupCodesFn  func(accessToken, password string) (backupCodes []string, err error)
}

func (s *stubAuthClient) Login(email, password string, rememberMe bool, info ...authclient.ClientInfo) (accessToken, refreshToken string, mfaRequired bool, mfaToken string, err error) {
	if s.loginFn != nil {
		return s.loginFn(email, password, rememberMe, info...)
	}
	return
}
func (s *stubAuthClient) Register(email, password, verificationUrl string) (userId, message string, err error) {
	return
}
func (s *stubAuthClient) Refresh(refreshToken string, rememberMe bool, info ...authclient.ClientInfo) (newAccessToken, newRefreshToken string, err error) {
	return
}
func (s *stubAuthClient) Logout(refreshToken string) error                  { return nil }
func (s *stubAuthClient) RequestPasswordReset(email, resetUrl string) error { return nil }
func (s *stubAuthClient) ResetPassword(userId, token, newPassword string) (string, error) {
	return "", nil
}
func (s *stubAuthClient) VerifyEmail(email, verificationUrl string) error { return nil }
func (s *stubAuthClient) ChangePassword(accessToken, oldPassword, newPassword string) (string, error) {
	return "", nil
}
func (s *stubAuthClient) CheckPasswordStrength(password string) (bool, string, error) {
	return true, "", nil
}
func (s *stubAuthClient) WhoAmI(accessToken string, userCtor authclient.UserCtor) (authclient.User, error) {
	return nil, nil
}
func (s *stubAuthClient) CreateAdmin(accessToken, email, password string) (string, string, error) {
	return "", "", nil
}
func (s *stubAuthClient) ChangeAccountType(accessToken, userId, accountType string) (string, error) {
	return "", nil
}
func (s *stubAuthClient) WhoIs(accessToken string, lookup authclient.WhoIsOneOf, userCtor authclient.UserCtor) (authclient.User, error) {
	return nil, nil
}
func (s *stubAuthClient) CreateServiceClient(accessToken, name, description string, scopes []string) (string, string, error) {
	return "", "", nil
}
func (s *stubAuthClient) DeleteServiceClient(accessToken, clientId string) (string, error) {
	return "", nil
}
func (s *stubAuthClient) ListServiceClients(accessToken string, page, pageSize int, ctor authclient.ServiceClientCtor) ([]authclient.ServiceClient, int32, error) {
	return nil, 0, nil
}
func (s *stubAuthClient) InviteUser(accessToken, email string) (string, error) { return "", nil }
func (s *stubAuthClient) RevokeInvite(accessToken, email string) (string, error) {
	return "", nil
}
func (s *stubAuthClient) ListInvites(accessToken string, page, pageSize int, registered *bool, ctor authclient.InviteCtor) ([]authclient.Invite, int32, error) {
	return nil, 0, nil
}

func (s *stubAuthClient) SetupMFA(accessToken string) (secret, otpauthURL, qrPNGBase64 string, err error) {
	if s.setupMFAFn != nil {
		return s.setupMFAFn(accessToken)
	}
	return
}
func (s *stubAuthClient) EnableMFA(accessToken, code string) (backupCodes []string, err error) {
	if s.enableMFAFn != nil {
		return s.enableMFAFn(accessToken, code)
	}
	return
}
func (s *stubAuthClient) DisableMFA(accessToken, password string) error {
	if s.disableMFAFn != nil {
		return s.disableMFAFn(accessToken, password)
	}
	return nil
}
func (s *stubAuthClient) GetMFAStatus(accessToken string) (enabled bool, err error) {
	if s.getMFAStatusFn != nil {
		return s.getMFAStatusFn(accessToken)
	}
	return
}
func (s *stubAuthClient) VerifyMFA(mfaToken, code string, rememberMe bool, info ...authclient.ClientInfo) (accessToken, refreshToken string, err error) {
	if s.verifyMFAFn != nil {
		return s.verifyMFAFn(mfaToken, code, rememberMe, info...)
	}
	return
}
func (s *stubAuthClient) GenerateBackupCodes(accessToken, password string) (backupCodes []string, err error) {
	if s.backupCodesFn != nil {
		return s.backupCodesFn(accessToken, password)
	}
	return
}

func newMFAHandler(client AuthClient) *AuthHandler {
	return NewAuthHandler(client, nil, log.New())
}

// authedRequest injects a raw JWT into the request context, as the gateway's
// Auth middleware does, so the management handlers' security.GetJwt succeeds.
func authedRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	ctx := context.WithValue(r.Context(), security.JwtKey, "test-jwt")
	return r.WithContext(ctx)
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v (body %q)", err, rec.Body.String())
	}
	return body
}

func hasSetCookie(rec *httptest.ResponseRecorder) bool {
	return len(rec.Result().Cookies()) > 0
}

func TestLogin_MfaRequired_ReturnsChallengeWithoutCookies(t *testing.T) {
	stub := &stubAuthClient{
		loginFn: func(email, password string, rememberMe bool, info ...authclient.ClientInfo) (string, string, bool, string, error) {
			return "", "", true, "challenge-token-123", nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(
		`{"email":"user@example.com","password":"secret","remember_me":false}`))
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := jsonBody(t, rec)
	if body["mfa_required"] != true {
		t.Errorf("mfa_required = %v, want true", body["mfa_required"])
	}
	if body["mfa_token"] != "challenge-token-123" {
		t.Errorf("mfa_token = %v, want %q", body["mfa_token"], "challenge-token-123")
	}
	if _, ok := body["access_token"]; ok {
		t.Errorf("access_token must not be present when MFA is required")
	}
	if _, ok := body["refresh_token"]; ok {
		t.Errorf("refresh_token must not be present when MFA is required")
	}
	if hasSetCookie(rec) {
		t.Errorf("no cookies may be set before the second factor completes, got %v", rec.Result().Cookies())
	}
}

func TestLogin_MfaNotRequired_SetsCookiesAndTokens(t *testing.T) {
	stub := &stubAuthClient{
		loginFn: func(email, password string, rememberMe bool, info ...authclient.ClientInfo) (string, string, bool, string, error) {
			return "access-token", "refresh-token", false, "", nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(
		`{"email":"user@example.com","password":"secret"}`))
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := jsonBody(t, rec)
	if body["access_token"] != "access-token" || body["refresh_token"] != "refresh-token" {
		t.Errorf("unexpected token body: %v", body)
	}
	if _, ok := body["mfa_required"]; ok {
		t.Errorf("mfa_required must be absent for non-MFA login")
	}
	if !hasSetCookie(rec) {
		t.Error("expected access_token and refresh_token cookies")
	}
}

func TestMfaVerify_Success_SetsCookiesAndTokens(t *testing.T) {
	stub := &stubAuthClient{
		verifyMFAFn: func(mfaToken, code string, rememberMe bool, info ...authclient.ClientInfo) (string, string, error) {
			return "access-token", "refresh-token", nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", strings.NewReader(
		`{"mfa_token":"challenge-token-123","code":"123456","remember_me":true}`))
	h.MfaVerify(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := jsonBody(t, rec)
	if body["access_token"] != "access-token" || body["refresh_token"] != "refresh-token" {
		t.Errorf("unexpected token body: %v", body)
	}
	if !hasSetCookie(rec) {
		t.Error("expected access_token and refresh_token cookies")
	}
}

func TestMfaVerify_Failure_Sanitized401NoCookies(t *testing.T) {
	stub := &stubAuthClient{
		verifyMFAFn: func(mfaToken, code string, rememberMe bool, info ...authclient.ClientInfo) (string, string, error) {
			return "", "", status.Error(codes.Unauthenticated, "invalid authentication code")
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", strings.NewReader(
		`{"mfa_token":"challenge-token-123","code":"000000"}`))
	h.MfaVerify(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	body := jsonBody(t, rec)
	if strings.Contains(rec.Body.String(), "invalid authentication code") {
		t.Errorf("response echoes downstream error text: %s", rec.Body.String())
	}
	if body["error"] != "unauthenticated" {
		t.Errorf("error = %v, want %q", body["error"], "unauthenticated")
	}
	if body["code"] != "Unauthenticated" {
		t.Errorf("code = %v, want %q", body["code"], "Unauthenticated")
	}
	if hasSetCookie(rec) {
		t.Errorf("no cookies may be set on a failed verify, got %v", rec.Result().Cookies())
	}
}

func TestMfaSetup_ReturnsSecretURLAndQR(t *testing.T) {
	stub := &stubAuthClient{
		setupMFAFn: func(accessToken string) (string, string, string, error) {
			if accessToken != "test-jwt" {
				t.Errorf("accessToken = %q, want %q", accessToken, "test-jwt")
			}
			return "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "otpauth://totp/SwayRider:user@example.com?secret=ABC", "aGVsbG8=", nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	h.MfaSetup(rec, authedRequest(http.MethodPost, "/api/v1/auth/mfa/setup"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := jsonBody(t, rec)
	if body["secret"] != "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" {
		t.Errorf("secret = %v", body["secret"])
	}
	if body["otpauth_url"] != "otpauth://totp/SwayRider:user@example.com?secret=ABC" {
		t.Errorf("otpauth_url = %v", body["otpauth_url"])
	}
	if body["qr_png_base64"] != "aGVsbG8=" {
		t.Errorf("qr_png_base64 = %v", body["qr_png_base64"])
	}
}

func TestMfaEnable_ReturnsBackupCodes(t *testing.T) {
	stub := &stubAuthClient{
		enableMFAFn: func(accessToken, code string) ([]string, error) {
			if code != "123456" {
				t.Errorf("code = %q, want %q", code, "123456")
			}
			return []string{"ABCD-EFGH", "JKLM-NOPQ"}, nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enable", strings.NewReader(`{"code":"123456"}`))
	h.MfaEnable(rec, authedRequestWithBody(req))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := jsonBody(t, rec)
	codes, ok := body["backup_codes"].([]any)
	if !ok || len(codes) != 2 {
		t.Fatalf("backup_codes = %v, want 2 codes", body["backup_codes"])
	}
	if codes[0] != "ABCD-EFGH" || codes[1] != "JKLM-NOPQ" {
		t.Errorf("backup_codes = %v", codes)
	}
}

func TestMfaDisable_Returns204(t *testing.T) {
	var gotPassword string
	stub := &stubAuthClient{
		disableMFAFn: func(accessToken, password string) error {
			gotPassword = password
			return nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", strings.NewReader(`{"password":"secret"}`))
	h.MfaDisable(rec, authedRequestWithBody(req))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if gotPassword != "secret" {
		t.Errorf("password = %q, want %q", gotPassword, "secret")
	}
}

func TestMfaStatus_ReturnsEnabled(t *testing.T) {
	stub := &stubAuthClient{
		getMFAStatusFn: func(accessToken string) (bool, error) {
			return true, nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	h.MfaStatus(rec, authedRequest(http.MethodGet, "/api/v1/auth/mfa/status"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := jsonBody(t, rec)
	if body["enabled"] != true {
		t.Errorf("enabled = %v, want true", body["enabled"])
	}
}

func TestMfaBackupCodes_ReturnsNewCodes(t *testing.T) {
	stub := &stubAuthClient{
		backupCodesFn: func(accessToken, password string) ([]string, error) {
			return []string{"NEW1-CODE", "NEW2-CODE"}, nil
		},
	}
	h := newMFAHandler(stub)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/backup-codes", strings.NewReader(`{"password":"secret"}`))
	h.MfaBackupCodes(rec, authedRequestWithBody(req))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := jsonBody(t, rec)
	codes, ok := body["backup_codes"].([]any)
	if !ok || len(codes) != 2 {
		t.Fatalf("backup_codes = %v, want 2 codes", body["backup_codes"])
	}
}

func TestMfaManagement_RequiresJwt(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(h *AuthHandler, rec *httptest.ResponseRecorder)
	}{
		{"setup", func(h *AuthHandler, rec *httptest.ResponseRecorder) {
			h.MfaSetup(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/setup", nil))
		}},
		{"enable", func(h *AuthHandler, rec *httptest.ResponseRecorder) {
			h.MfaEnable(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enable", strings.NewReader(`{"code":"123456"}`)))
		}},
		{"disable", func(h *AuthHandler, rec *httptest.ResponseRecorder) {
			h.MfaDisable(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", strings.NewReader(`{"password":"x"}`)))
		}},
		{"status", func(h *AuthHandler, rec *httptest.ResponseRecorder) {
			h.MfaStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/mfa/status", nil))
		}},
		{"backup-codes", func(h *AuthHandler, rec *httptest.ResponseRecorder) {
			h.MfaBackupCodes(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/backup-codes", strings.NewReader(`{"password":"x"}`)))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newMFAHandler(&stubAuthClient{})
			rec := httptest.NewRecorder()
			tt.invoke(h, rec)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 without a JWT", rec.Code)
			}
		})
	}
}

// authedRequestWithBody is authedRequest for requests that already carry a body.
func authedRequestWithBody(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), security.JwtKey, "test-jwt")
	return r.WithContext(ctx)
}
