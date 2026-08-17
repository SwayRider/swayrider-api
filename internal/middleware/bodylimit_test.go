package middleware

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readAllHandler mimics the handlers' decode path: it reads the body and maps
// *http.MaxBytesError to 413, anything else to 200.
func readAllHandler(w http.ResponseWriter, r *http.Request) {
	_, err := io.ReadAll(r.Body)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func TestBodyLimit_AllowsSmallBody(t *testing.T) {
	h := BodyLimit(1024)(http.HandlerFunc(readAllHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"a@b.c"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBodyLimit_RejectsOversizedBody(t *testing.T) {
	h := BodyLimit(1024)(http.HandlerFunc(readAllHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/route", strings.NewReader(strings.Repeat("x", 4096)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestBodyLimit_ChunkedBodyStillBounded(t *testing.T) {
	h := BodyLimit(1024)(http.HandlerFunc(readAllHandler))

	// Chunked transfer: no Content-Length, so the limit must come from
	// MaxBytesReader, not from a header check.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/route", strings.NewReader(strings.Repeat("x", 2048)))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestBodyLimit_ZeroDisablesLimit(t *testing.T) {
	h := BodyLimit(0)(http.HandlerFunc(readAllHandler))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/route", strings.NewReader(strings.Repeat("x", 8192)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (limit disabled)", rec.Code, http.StatusOK)
	}
}
