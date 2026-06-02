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

// RouteResult mirrors the full Valhalla trip response structure.
type RouteResult struct {
	Trip TripResult `json:"trip"`
}

type TripResult struct {
	Status        int              `json:"status"`
	StatusMessage string           `json:"status_message"`
	Units         string           `json:"units"`
	Language      string           `json:"language"`
	Locations     []LocationResult `json:"locations"`
	Legs          []LegResult      `json:"legs"`
	Summary       SummaryResult    `json:"summary"`
}

type LocationResult struct {
	Lat              float64  `json:"lat"`
	Lon              float64  `json:"lon"`
	Type             string   `json:"type,omitempty"`
	Heading          *int     `json:"heading,omitempty"`
	SideOfStreet     string   `json:"side_of_steet,omitempty"`
	DateTime         string   `json:"datetime,omitempty"`
	OriginalIndex    *int     `json:"original_index,omitempty"`
	TimeZoneOffset   *string  `json:"time_zone_offset,omitempty"`
	TimeZoneName     *string  `json:"time_zone_name,omitempty"`
}

type LegResult struct {
	Shape             string           `json:"shape"`
	Maneuvers         []ManeuverResult `json:"maneuvers"`
	Summary           SummaryResult    `json:"summary"`
	Elevation         []float64        `json:"elevation,omitempty"`
	ElevationInterval *float64         `json:"elevation_interval,omitempty"`
}

type ManeuverResult struct {
	Type                               int                `json:"type"`
	Instruction                        string             `json:"instruction"`
	VerbalTransitionAlertInstruction   string             `json:"verbal_transition_alert_instruction,omitempty"`
	VerbalPreTransitionInstruction     string             `json:"verbal_pre_transition_instruction,omitempty"`
	VerbalPostTransitionInstruction    string             `json:"verbal_post_transition_instruction,omitempty"`
	StreetNames                        []string           `json:"street_names,omitempty"`
	BeginStreetNames                   []string           `json:"begin_street_names,omitempty"`
	Time                               float64            `json:"time"`
	Length                             float64            `json:"length"`
	BeginShapeIndex                    int                `json:"begin_shape_index"`
	EndShapeIndex                      int                `json:"end_shape_index"`
	Toll                               *bool              `json:"toll,omitempty"`
	Highway                            *bool              `json:"highway,omitempty"`
	Rough                              *bool              `json:"rough,omitempty"`
	Gate                               *bool              `json:"gate,omitempty"`
	Ferry                              *bool              `json:"ferry,omitempty"`
	Sign                               *SignResult        `json:"sign,omitempty"`
	RoundaboutExitCount                *int               `json:"roundabout_exit_count,omitempty"`
	DepartInstruction                  *string            `json:"depart_instruction,omitempty"`
	VerbalDepartInstruction            *string            `json:"verbal_depart_instruction,omitempty"`
	ArriveInstruction                  *string            `json:"arrive_instruction,omitempty"`
	VerbalArriveInstruction            *string            `json:"verbal_arrive_instruction,omitempty"`
	VerbalMultiCue                     *bool              `json:"verbal_multi_cue,omitempty"`
	TravelMode                         string             `json:"travel_mode"`
	TravelType                          string             `json:"travel_type"`
	BearingBefore                      int                `json:"bearing_before"`
	BearingAfter                       int                `json:"bearing_after"`
	Lanes                              []TurnLaneResult   `json:"lanes,omitempty"`
}

type SummaryResult struct {
	Time        float64       `json:"time"`
	Length      float64       `json:"length"`
	HasToll     bool          `json:"has_toll"`
	HasHighway  bool          `json:"has_highway"`
	HasFerry    bool          `json:"has_ferry"`
	BoundingBox *BBoxResult   `json:"bounding_box,omitempty"`
}

type BBoxResult struct {
	MinLat float64 `json:"min_lat"`
	MinLon float64 `json:"min_lon"`
	MaxLat float64 `json:"max_lat"`
	MaxLon float64 `json:"max_lon"`
}

type SignResult struct {
	ExitNumberElements []SignElementResult `json:"exit_number_elements,omitempty"`
	ExitBranchElements []SignElementResult `json:"exit_branch_elements,omitempty"`
	ExitTowardElements []SignElementResult `json:"exit_toward_elements,omitempty"`
	ExitNameElements   []SignElementResult `json:"exit_name_elements,omitempty"`
}

type SignElementResult struct {
	Text            string `json:"text"`
	ConsecutiveCount *int  `json:"consecutive_count,omitempty"`
}

type TurnLaneResult struct {
	Directions int     `json:"directions"`
	Valid      *uint32 `json:"valid,omitempty"`
	Active     *uint32 `json:"active,omitempty"`
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
