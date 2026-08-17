package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/cors"
)

func TestNormalizeCORSOrigins(t *testing.T) {
	tests := []struct {
		name    string
		origins []string
		want    []string
		wantErr bool
	}{
		{"single origin", []string{"http://localhost:5173"}, []string{"http://localhost:5173"}, false},
		{"multiple origins", []string{"http://a.com", "https://b.com"}, []string{"http://a.com", "https://b.com"}, false},
		{"trims whitespace", []string{" http://a.com ", "https://b.com"}, []string{"http://a.com", "https://b.com"}, false},
		{"explicit pattern allowed", []string{"https://*.example.com"}, []string{"https://*.example.com"}, false},
		{"wildcard rejected", []string{"*"}, nil, true},
		{"wildcard among others rejected", []string{"http://a.com", "*"}, nil, true},
		{"empty entry rejected", []string{"http://a.com", ""}, nil, true},
		{"only empty rejected", []string{""}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeCORSOrigins(tt.origins)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeCORSOrigins(%v) = %v, want error", tt.origins, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeCORSOrigins(%v) returned unexpected error: %v", tt.origins, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeCORSOrigins(%v) = %v, want %v", tt.origins, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizeCORSOrigins(%v) = %v, want %v", tt.origins, got, tt.want)
				}
			}
		})
	}
}

func corsHandler(allowedOrigins []string) http.Handler {
	return cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func TestCORS_AllowedOriginReflectedWithCredentials(t *testing.T) {
	h := corsHandler([]string{"http://localhost:5173"})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Errorf("ACAO = %q, want %q", rec.Header().Get("Access-Control-Allow-Origin"), "http://localhost:5173")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("ACAC = %q, want %q", rec.Header().Get("Access-Control-Allow-Credentials"), "true")
	}
}

func TestCORS_DisallowedOriginGetsNoAllowOrigin(t *testing.T) {
	h := corsHandler([]string{"http://localhost:5173"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/public-keys", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q, want empty (browser must block the response)", got)
	}
}

// TestCORS_WildcardWithCredentials documents why normalizeCORSOrigins must
// reject a bare "*": rs/cors v1.11 emits Access-Control-Allow-Origin: * and
// Access-Control-Allow-Credentials: true together, which the Fetch spec makes
// browsers reject — so a wildcard config silently breaks every credentialed
// cross-origin request. (Older rs/cors versions reflected the origin instead,
// which with credentials allows any site to send cookies.) Either way the
// configuration is broken or dangerous, which is exactly what the startup
// validation forbids.
func TestCORS_WildcardWithCredentials(t *testing.T) {
	h := corsHandler([]string{"*"})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("ACAO = %q, want %q", got, "*")
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC = %q, want %q", got, "true")
	}
}
