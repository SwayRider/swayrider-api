package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	log "github.com/swayrider/swlib/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func TestGrpcStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, http.StatusOK},
		{"not found", status.Error(codes.NotFound, "no such user"), http.StatusNotFound},
		{"already exists", status.Error(codes.AlreadyExists, "user exists"), http.StatusConflict},
		{"permission denied", status.Error(codes.PermissionDenied, "nope"), http.StatusForbidden},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad token"), http.StatusUnauthorized},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad input"), http.StatusBadRequest},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "slow down"), http.StatusTooManyRequests},
		{"failed precondition", status.Error(codes.FailedPrecondition, "not ready"), http.StatusConflict},
		{"internal", status.Error(codes.Internal, "boom"), http.StatusInternalServerError},
		{"plain error", errors.New("dial tcp: connection refused"), http.StatusInternalServerError},
		// A message containing the old keyword must NOT be misclassified.
		{"message contains NotFound word", status.Error(codes.InvalidArgument, "NotFound is not a status here"), http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := grpcStatus(tt.err); got != tt.want {
				t.Errorf("grpcStatus(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestErrBody_SanitizesRawText(t *testing.T) {
	err := status.Error(codes.Internal, "sql: table users does not exist: failed to query")
	body := errBody(err)
	if strings.Contains(body["error"].(string), "sql") {
		t.Errorf("error message leaks internal detail: %q", body["error"])
	}
	if body["error"] != "internal error" {
		t.Errorf("error = %q, want %q", body["error"], "internal error")
	}
	if body["code"] != "Internal" {
		t.Errorf("code = %v, want %q", body["code"], "Internal")
	}
}

func TestErrBody_WeakPasswordReason(t *testing.T) {
	err := status.Error(codes.InvalidArgument, "password is too weak: needs at least 8 characters")
	body := errBody(err)
	if body["reason"] != "weak_password" {
		t.Errorf("reason = %v, want %q", body["reason"], "weak_password")
	}
	if body["error"] != "invalid argument" {
		t.Errorf("error = %v, want %q", body["error"], "invalid argument")
	}
}

func TestErrBody_BreachedPasswordReason(t *testing.T) {
	err := status.Error(codes.InvalidArgument, "password has appeared in a known data breach (found 12 times)")
	body := errBody(err)
	if body["reason"] != "breached_password" {
		t.Errorf("reason = %v, want %q", body["reason"], "breached_password")
	}
	if body["error"] != "invalid argument" {
		t.Errorf("error = %v, want %q", body["error"], "invalid argument")
	}
}

func TestErrBody_PasswordReusedReason(t *testing.T) {
	err := status.Error(codes.InvalidArgument, "password has been used before: choose a password you have not used recently")
	body := errBody(err)
	if body["reason"] != "password_reused" {
		t.Errorf("reason = %v, want %q", body["reason"], "password_reused")
	}
	if body["error"] != "invalid argument" {
		t.Errorf("error = %v, want %q", body["error"], "invalid argument")
	}
}

func TestErrBody_NoReasonForOtherErrors(t *testing.T) {
	err := status.Error(codes.InvalidArgument, "email address is not valid")
	if _, ok := errBody(err)["reason"]; ok {
		t.Errorf("unexpected reason for non-weak-password error")
	}
}

func TestErrBody_ReasonNeedsExactPrefix(t *testing.T) {
	// The prefix is the contract — a message that mentions breach data
	// without starting with the exact prefix must not be classified.
	err := status.Error(codes.InvalidArgument, "validation failed: breach data unavailable")
	if _, ok := errBody(err)["reason"]; ok {
		t.Errorf("unexpected reason for message without the breach prefix")
	}
}

func TestErrBody_PlainError(t *testing.T) {
	body := errBody(errors.New("dial tcp 10.0.0.1:8081: connect: connection refused"))
	if body["error"] != "internal error" {
		t.Errorf("error = %v, want %q", body["error"], "internal error")
	}
	if body["code"] != "Unknown" {
		t.Errorf("code = %v, want %q", body["code"], "Unknown")
	}
}

func TestWriteError_LogsButDoesNotEcho(t *testing.T) {
	h := NewAuthHandler(nil, nil, log.New())
	raw := "rpc error: code = Internal desc = secret database internals"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)

	// writeError needs a request only via errBody/grpcStatus, which don't use
	// it, so a bare recorder is enough — but run through decodeBody's writer
	// shape via writeJSON anyway.
	_ = req
	writeError(rec, h.l, errors.New(raw))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if strings.Contains(rec.Body.String(), "secret database internals") {
		t.Errorf("response echoes internal error text: %s", rec.Body.String())
	}
}
