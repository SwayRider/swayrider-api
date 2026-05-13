package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"
)

// Job holds the decoded fields of a Redis stream message.
type Job struct {
	JobID        string
	Payload      string // JSON-encoded request DTO
	UserID       string
	AccountLevel string
	IsAdmin      string // "true" | "false"
	UserVerified string // "true" | "false"
}

// JobResult is stored in Redis and published on the result channel.
type JobResult struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   *JobError       `json:"error,omitempty"`
}

// JobError carries a gRPC-style status code and message.
type JobError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RouteResult is the serialisable output of a successful routing job.
type RouteResult struct {
	DistanceMeters  float64     `json:"distanceMeters"`
	DurationSeconds float64     `json:"durationSeconds"`
	Steps           []RouteStep `json:"steps"`
}

// RouteStep is one leg instruction within a RouteResult.
type RouteStep struct {
	Instruction     string  `json:"instruction"`
	DistanceMeters  float64 `json:"distanceMeters"`
	DurationSeconds float64 `json:"durationSeconds"`
}

// SearchItem is one result within a successful search or reverse-geocode job.
type SearchItem struct {
	Label       string  `json:"label"`
	Locality    string  `json:"locality"`
	Region      string  `json:"region"`
	Country     string  `json:"country"`
	Confidence  float64 `json:"confidence"`
	Layer       string  `json:"layer"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Street      string  `json:"street,omitempty"`
	HouseNumber string  `json:"houseNumber,omitempty"`
	Id          string  `json:"id,omitempty"`
	LocalAdmin  string  `json:"localAdmin,omitempty"`
	CountryCode string  `json:"countryCode,omitempty"`
	Name        string  `json:"name,omitempty"`
}

// UserMetadataCtx adds the job's user identity fields as outgoing gRPC metadata
// without replacing any metadata already present in ctx.
func UserMetadataCtx(ctx context.Context, job Job) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"x-user-id", job.UserID,
		"x-account-level", job.AccountLevel,
		"x-is-admin", job.IsAdmin,
		"x-user-verified", job.UserVerified,
	))
}

func parseJob(values map[string]interface{}) Job {
	str := func(v interface{}) string {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return Job{
		JobID:        str(values["job_id"]),
		Payload:      str(values["payload"]),
		UserID:       str(values["user_id"]),
		AccountLevel: str(values["account_level"]),
		IsAdmin:      str(values["is_admin"]),
		UserVerified: str(values["user_verified"]),
	}
}

func GrpcErrToJobError(err error) *JobError {
	if err == nil {
		return nil
	}
	msg := err.Error()
	code := 13 // INTERNAL
	switch {
	case strings.Contains(msg, "NotFound"):
		code = 5
	case strings.Contains(msg, "InvalidArgument"):
		code = 3
	case strings.Contains(msg, "Unavailable"):
		code = 14
	case strings.Contains(msg, "DeadlineExceeded"):
		code = 4
	case strings.Contains(msg, "PermissionDenied"):
		code = 7
	case strings.Contains(msg, "Unauthenticated"):
		code = 16
	}
	return &JobError{Code: code, Message: msg}
}
