package queue

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGrpcErrToJobError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantMsg    string
		wantNil    bool
	}{
		{"nil", nil, 0, "", true},
		{"not found", status.Error(codes.NotFound, "no route found"), 5, "not found", false},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad coordinates"), 3, "invalid argument", false},
		{"unavailable", status.Error(codes.Unavailable, "routerservice down"), 14, "service unavailable", false},
		{"deadline exceeded", status.Error(codes.DeadlineExceeded, "took too long"), 4, "deadline exceeded", false},
		{"permission denied", status.Error(codes.PermissionDenied, "forbidden"), 7, "permission denied", false},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad token"), 16, "unauthenticated", false},
		{"internal", status.Error(codes.Internal, "sql: exploded"), 13, "internal error", false},
		{"plain error", errors.New("dial tcp: connection refused"), 2, "internal error", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			je := GrpcErrToJobError(tt.err)
			if tt.wantNil {
				if je != nil {
					t.Fatalf("GrpcErrToJobError(%v) = %+v, want nil", tt.err, je)
				}
				return
			}
			if je == nil {
				t.Fatalf("GrpcErrToJobError(%v) = nil, want non-nil", tt.err)
			}
			if je.Code != tt.wantCode {
				t.Errorf("Code = %d, want %d", je.Code, tt.wantCode)
			}
			if je.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", je.Message, tt.wantMsg)
			}
			if je.Message != "" && je.Message != tt.wantMsg {
				t.Errorf("Message leaks raw text: %q", je.Message)
			}
		})
	}
}

func TestGrpcErrToJobError_DoesNotLeakRawText(t *testing.T) {
	je := GrpcErrToJobError(status.Error(codes.Internal, "postgres: constraint violation on table users"))
	if je.Message == "" || strings.Contains(je.Message, "postgres") {
		t.Errorf("Message leaks internal detail: %q", je.Message)
	}
}
