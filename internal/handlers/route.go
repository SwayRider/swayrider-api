package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/swayrider/grpcclients/routerclient"
	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swlib/security"
	"github.com/swayrider/swayrider-api/internal/queue"
	"github.com/swayrider/swayrider-api/internal/sse"
)

// RouteRequest is the JSON body accepted by POST /api/v1/route.
type RouteRequest struct {
	From    RouteCoord   `json:"from"`
	To      RouteCoord   `json:"to"`
	Vehicle string       `json:"vehicle"`
	Options RouteOptions `json:"options"`
}

// RouteCoord is a lat/lon pair.
type RouteCoord struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// RouteOptions carries optional routing preferences.
type RouteOptions struct {
	AvoidTollRoads   bool    `json:"avoidTollRoads"`
	AvoidHighways    bool    `json:"avoidHighways"`
	AvoidFerries     bool    `json:"avoidFerries"`
	ScenicPreference float64 `json:"scenicPreference"`
	HighwayAvoidance float64 `json:"highwayAvoidance"`
	TollAvoidance    float64 `json:"tollAvoidance"`
	UnpavedHandling  string  `json:"unpavedHandling"`
}

// RouteHandler handles POST /api/v1/route via SSE.
type RouteHandler struct {
	producer *queue.Producer
	hub      *sse.Hub
}

func NewRouteHandler(producer *queue.Producer, hub *sse.Hub) *RouteHandler {
	return &RouteHandler{producer: producer, hub: hub}
}

func (h *RouteHandler) Route(w http.ResponseWriter, r *http.Request) {
	claims, ok := security.GetClaims(r.Context())
	if !ok || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req RouteRequest
	if !decodeBody(w, r, &req) {
		return
	}

	userClaims, _ := claims.SwayRiderClaims.(*jwt.SwayRiderUserClaims)
	accountLevel := ""
	isAdmin := false
	if userClaims != nil {
		accountLevel = userClaims.AccountLevel
		isAdmin = userClaims.IsAdmin
	}
	userVerified := claims.EmailVerified != nil && *claims.EmailVerified

	payload, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	jobID, err := h.producer.Enqueue(r.Context(), queue.StreamRouting, queue.Job{
		Payload:      string(payload),
		UserID:       claims.Subject,
		AccountLevel: accountLevel,
		IsAdmin:      fmt.Sprintf("%t", isAdmin),
		UserVerified: fmt.Sprintf("%t", userVerified),
	})
	if errors.Is(err, queue.ErrQueueFull) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "queue full", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	depth, _ := h.producer.QueueDepth(r.Context(), queue.StreamRouting)
	writeSSEEvent(w, "queued", fmt.Sprintf(`{"job_id":%q,"queue_position":%d}`, jobID, depth))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	h.hub.WaitForResult(r.Context(), w, jobID)
}

// NewRouteProcessFn returns the worker ProcessFn for routing jobs.
// breaker wraps the gRPC call for circuit-breaking.
func NewRouteProcessFn(client *routerclient.Client, token func() string, breaker BreakerExecutor) queue.ProcessFn {
	return func(ctx context.Context, job queue.Job) (json.RawMessage, error) {
		var req RouteRequest
		if err := json.Unmarshal([]byte(job.Payload), &req); err != nil {
			return nil, err
		}

		query := routerclient.RouteQuery{
			From:    routerclient.Coordinate{Latitude: req.From.Lat, Longitude: req.From.Lon},
			To:      routerclient.Coordinate{Latitude: req.To.Lat, Longitude: req.To.Lon},
			Vehicle: req.Vehicle,
			StandardRoutingOptions: routerclient.StandardRoutingOptions{
				AvoidTollRoads:   req.Options.AvoidTollRoads,
				AvoidHighways:    req.Options.AvoidHighways,
				AvoidFerries:     req.Options.AvoidFerries,
				ScenicPreference: req.Options.ScenicPreference,
				HighwayAvoidance: req.Options.HighwayAvoidance,
				TollAvoidance:    req.Options.TollAvoidance,
				UnpavedHandling:  req.Options.UnpavedHandling,
			},
		}

		userCtx := queue.UserMetadataCtx(ctx, job)

		var result queue.RouteResult
		err := breaker.Execute("routerservice", func() error {
			route, err := client.RouteWithContext(userCtx, token(), query, newRoute, newRouteStep)
			if err != nil {
				return err
			}
			result = toRouteResult(route)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
}

// --- concrete implementations of routerclient interfaces ---

type routeImpl struct {
	distanceMeters float64
	duration       time.Duration
	steps          []routerclient.RouteStep
}

func (r *routeImpl) DistanceInMeters() float64        { return r.distanceMeters }
func (r *routeImpl) Duration() time.Duration           { return r.duration }
func (r *routeImpl) Steps() []routerclient.RouteStep   { return r.steps }
func (r *routeImpl) AddStep(s routerclient.RouteStep)  { r.steps = append(r.steps, s) }

type routeStepImpl struct {
	instruction    string
	distanceMeters float64
	duration       time.Duration
	coord          routerclient.Coordinate
}

func (s *routeStepImpl) Instruction() string                { return s.instruction }
func (s *routeStepImpl) DistanceInMeters() float64          { return s.distanceMeters }
func (s *routeStepImpl) Duration() time.Duration             { return s.duration }
func (s *routeStepImpl) Coordinate() routerclient.Coordinate { return s.coord }

func newRoute(distanceMeters float64, duration time.Duration) routerclient.Route {
	return &routeImpl{distanceMeters: distanceMeters, duration: duration}
}

func newRouteStep(instruction string, distanceMeters float64, duration time.Duration, coord routerclient.Coordinate) routerclient.RouteStep {
	return &routeStepImpl{
		instruction:    instruction,
		distanceMeters: distanceMeters,
		duration:       duration,
		coord:          coord,
	}
}

func toRouteResult(route routerclient.Route) queue.RouteResult {
	steps := make([]queue.RouteStep, 0, len(route.Steps()))
	for _, s := range route.Steps() {
		steps = append(steps, queue.RouteStep{
			Instruction:     s.Instruction(),
			DistanceMeters:  s.DistanceInMeters(),
			DurationSeconds: s.Duration().Seconds(),
		})
	}
	return queue.RouteResult{
		DistanceMeters:  route.DistanceInMeters(),
		DurationSeconds: route.Duration().Seconds(),
		Steps:           steps,
	}
}

func writeSSEEvent(w http.ResponseWriter, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}

// BreakerExecutor is satisfied by *circuitbreaker.Registry.
type BreakerExecutor interface {
	Execute(name string, fn func() error) error
}
