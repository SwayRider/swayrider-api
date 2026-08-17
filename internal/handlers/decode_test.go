package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeBody_ValidJSON(t *testing.T) {
	var dst struct {
		Email string `json:"email"`
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"a@b.c"}`))
	rec := httptest.NewRecorder()

	if !decodeBody(rec, req, &dst) {
		t.Fatalf("decodeBody returned false, want true")
	}
	if dst.Email != "a@b.c" {
		t.Errorf("email = %q, want %q", dst.Email, "a@b.c")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestDecodeBody_MalformedJSON(t *testing.T) {
	var dst struct{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":`))
	rec := httptest.NewRecorder()

	if decodeBody(rec, req, &dst) {
		t.Fatalf("decodeBody returned true, want false")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDecodeBody_OversizedBodyIs413(t *testing.T) {
	// Simulate what the BodyLimit middleware installs. Valid JSON (a long
	// string value) larger than the limit must surface *http.MaxBytesError.
	var dst struct {
		Email string `json:"email"`
	}
	body := `{"email":"` + strings.Repeat("a", 4096) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, 1024)
	rec := httptest.NewRecorder()

	if decodeBody(rec, req, &dst) {
		t.Fatalf("decodeBody returned true, want false")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}
