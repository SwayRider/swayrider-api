package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/swayrider/grpcclients/routerclient"
	"github.com/swayrider/protos/router/v1"
	"github.com/swayrider/swlib/jwt"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
	"github.com/swayrider/swayrider-api/internal/queue"
	"github.com/swayrider/swayrider-api/internal/sse"
)

// RouteRequest is the JSON body accepted by POST /api/v1/route.
type RouteRequest struct {
	From      RouteCoord       `json:"from"`
	To        RouteCoord       `json:"to"`
	Waypoints []RouteWaypoint  `json:"waypoints,omitempty"`
	Vehicle   string           `json:"vehicle"`
	Unit      string           `json:"unit,omitempty"`
	Language  string           `json:"language,omitempty"`
	Options   RouteOptions     `json:"options"`
}

// RouteCoord is a lat/lon pair.
type RouteCoord struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// RouteWaypoint is an intermediate point on the route.
type RouteWaypoint struct {
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
	Type string  `json:"type,omitempty"`
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
	l        *log.Logger
}

func NewRouteHandler(producer *queue.Producer, hub *sse.Hub, l *log.Logger) *RouteHandler {
	return &RouteHandler{
		producer: producer,
		hub:      hub,
		l:        l.Derive(log.WithComponent("route")),
	}
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

	lg := h.l.Derive(log.WithFunction("Route"))

	jobID, err := h.producer.Enqueue(r.Context(), queue.StreamRouting, queue.Job{
		Payload:      string(payload),
		UserID:       claims.Subject,
		AccountLevel: accountLevel,
		IsAdmin:      fmt.Sprintf("%t", isAdmin),
		UserVerified: fmt.Sprintf("%t", userVerified),
	})
	if errors.Is(err, queue.ErrQueueFull) {
		lg.Warnf("queue full user=%s", claims.Subject)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "queue full", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		lg.Errorf("enqueue failed user=%s err=%v", claims.Subject, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	lg.Infof("route enqueued job_id=%s user=%s from=%.4f,%.4f to=%.4f,%.4f vehicle=%s",
		jobID, claims.Subject, req.From.Lat, req.From.Lon, req.To.Lat, req.To.Lon, req.Vehicle)

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

		waypoints := make([]routerclient.Waypoint, len(req.Waypoints))
		for i, wp := range req.Waypoints {
			waypoints[i] = routerclient.Waypoint{
				Coordinate: routerclient.Coordinate{Latitude: wp.Lat, Longitude: wp.Lon},
				Type:       wp.Type,
			}
		}

		query := routerclient.RouteQuery{
			From:      routerclient.Coordinate{Latitude: req.From.Lat, Longitude: req.From.Lon},
			To:        routerclient.Coordinate{Latitude: req.To.Lat, Longitude: req.To.Lon},
			Waypoints: waypoints,
			Vehicle:   req.Vehicle,
			Unit:      req.Unit,
			Language:  req.Language,
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
			resp, err := client.RouteRaw(userCtx, token(), query)
			if err != nil {
				return err
			}
			result = toRouteResult(resp.Trip)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
}

func toRouteResult(trip *routerv1.Trip) queue.RouteResult {
	return queue.RouteResult{
		Trip: toTripResult(trip),
	}
}

func toTripResult(trip *routerv1.Trip) queue.TripResult {
	r := queue.TripResult{
		Status:        int(trip.Status),
		StatusMessage: trip.StatusMessage,
		Language:      trip.Language,
	}
	switch trip.Unit {
	case routerv1.Unit_U_IMPERIAL:
		r.Units = "miles"
	default:
		r.Units = "kilometers"
	}
	for _, loc := range trip.Locations {
		r.Locations = append(r.Locations, toLocationResult(loc))
	}
	for _, leg := range trip.Legs {
		r.Legs = append(r.Legs, toLegResult(leg))
	}
	r.Summary = toSummaryResult(trip.Summary)
	return r
}

func toLocationResult(loc *routerv1.RouteLocationReturned) queue.LocationResult {
	r := queue.LocationResult{
		Lat: loc.Location.Lat,
		Lon: loc.Location.Lon,
	}
	switch loc.Type {
	case routerv1.LocationType_L_THROUGH:
		r.Type = "through"
	case routerv1.LocationType_L_VIA:
		r.Type = "via"
	case routerv1.LocationType_L_BREAK_THROUGH:
		r.Type = "break_through"
	default:
		r.Type = "break"
	}
	if loc.SideOfStreet != nil {
		switch *loc.SideOfStreet {
		case routerv1.SideOfStreet_SS_LEFT:
			r.SideOfStreet = "left"
		case routerv1.SideOfStreet_SS_RIGHT:
			r.SideOfStreet = "right"
		}
	}
	if loc.DateTime != nil {
		r.DateTime = loc.DateTime.AsTime().Format(time.RFC3339)
	}
	if loc.PreferredHeading != nil {
		v := int(*loc.PreferredHeading)
		r.Heading = &v
	}
	r.TimeZoneOffset = loc.TimeZoneOffset
	r.TimeZoneName = loc.TimeZoneName
	return r
}

func toLegResult(leg *routerv1.Leg) queue.LegResult {
	r := queue.LegResult{
		Shape:             leg.Shape,
		Elevation:         leg.Elevation,
		ElevationInterval: leg.ElevationInterval,
	}
	for _, m := range leg.Maneuvers {
		r.Maneuvers = append(r.Maneuvers, toManeuverResult(m))
	}
	r.Summary = toSummaryResult(leg.Summary)
	return r
}

func toManeuverResult(m *routerv1.Maneuver) queue.ManeuverResult {
	r := queue.ManeuverResult{
		Type:                             int(m.Type),
		Instruction:                      m.Instruction,
		VerbalTransitionAlertInstruction: m.VerbalTransitionAlertInstruction,
		VerbalPreTransitionInstruction:   m.VerbalPreTransitionInstruction,
		VerbalPostTransitionInstruction:  m.VerbalPostTransitionInstruction,
		StreetNames:                      m.StreetNames,
		BeginStreetNames:                 m.BeginStreetNames,
		Time:                             m.Time,
		Length:                           m.Length,
		BeginShapeIndex:                  int(m.BeginShapeIndex),
		EndShapeIndex:                    int(m.EndShapeIndex),
		Toll:                             m.Toll,
		Highway:                          m.Highway,
		Rough:                            m.Rough,
		Gate:                             m.Gate,
		Ferry:                            m.Ferry,
		RoundaboutExitCount:              func() *int { if m.RoundaboutExitCount != nil { v := int(*m.RoundaboutExitCount); return &v }; return nil }(),
		DepartInstruction:                m.DepartInstruction,
		VerbalDepartInstruction:          m.VerbalDepartInstruction,
		ArriveInstruction:                m.ArriveInstruction,
		VerbalArriveInstruction:          m.VerbalArriveInstruction,
		VerbalMultiCue:                   m.VerbalMultiCue,
		BearingBefore:                    int(m.BearingBefore),
		BearingAfter:                     int(m.BearingAfter),
	}
	if m.Sign != nil {
		r.Sign = toSignResult(m.Sign)
	}
	switch m.TravelMode {
	case routerv1.TravelMode_TM_PEDESTRIAN:
		r.TravelMode = "pedestrian"
	case routerv1.TravelMode_TM_BICYCLE:
		r.TravelMode = "bicycle"
	case routerv1.TravelMode_TM_TRANSIT:
		r.TravelMode = "transit"
	default:
		r.TravelMode = "drive"
	}
	switch m.TravelType {
	case routerv1.TravelType_TT_MOTORSCOOTER:
		r.TravelType = "motorscooter"
	case routerv1.TravelType_TT_MOTORCYCLE:
		r.TravelType = "motorcycle"
	case routerv1.TravelType_TT_TRUCK:
		r.TravelType = "truck"
	case routerv1.TravelType_TT_BUS:
		r.TravelType = "bus"
	case routerv1.TravelType_TT_FOOT:
		r.TravelType = "foot"
	case routerv1.TravelType_TT_WHEELCHAIR:
		r.TravelType = "wheelchair"
	case routerv1.TravelType_TT_ROAD:
		r.TravelType = "road"
	case routerv1.TravelType_TT_HYBRID:
		r.TravelType = "hybrid"
	case routerv1.TravelType_TT_CROSS:
		r.TravelType = "cross"
	case routerv1.TravelType_TT_MOUNTAIN:
		r.TravelType = "mountain"
	case routerv1.TravelType_TT_TRAM:
		r.TravelType = "tram"
	case routerv1.TravelType_TT_METRO:
		r.TravelType = "metro"
	case routerv1.TravelType_TT_RAIL:
		r.TravelType = "rail"
	case routerv1.TravelType_TT_FERRY:
		r.TravelType = "ferry"
	case routerv1.TravelType_TT_CABLE_CAR:
		r.TravelType = "cable_car"
	case routerv1.TravelType_TT_GONDOLA:
		r.TravelType = "gondola"
	case routerv1.TravelType_TT_FUNICULAR:
		r.TravelType = "funicular"
	default:
		r.TravelType = "car"
	}
	for _, lane := range m.Lanes {
		r.Lanes = append(r.Lanes, queue.TurnLaneResult{
			Directions: int(lane.Directions),
			Valid:      lane.Valid,
			Active:     lane.Active,
		})
	}
	return r
}

func toSummaryResult(s *routerv1.Summary) queue.SummaryResult {
	r := queue.SummaryResult{
		Time:       s.Time,
		Length:     s.Length,
		HasToll:    s.HasToll,
		HasHighway: s.HasHighway,
		HasFerry:   s.HasFerry,
	}
	if s.BoundingBox != nil {
		r.BoundingBox = &queue.BBoxResult{
			MinLat: s.BoundingBox.BottomLeft.Lat,
			MinLon: s.BoundingBox.BottomLeft.Lon,
			MaxLat: s.BoundingBox.TopRight.Lat,
			MaxLon: s.BoundingBox.TopRight.Lon,
		}
	}
	return r
}

func toSignResult(s *routerv1.Sign) *queue.SignResult {
	r := &queue.SignResult{}
	for _, e := range s.ExitNumberElements {
		r.ExitNumberElements = append(r.ExitNumberElements, toSignElementResult(e))
	}
	for _, e := range s.ExitBranchElements {
		r.ExitBranchElements = append(r.ExitBranchElements, toSignElementResult(e))
	}
	for _, e := range s.ExitTowardElements {
		r.ExitTowardElements = append(r.ExitTowardElements, toSignElementResult(e))
	}
	for _, e := range s.ExitNameElements {
		r.ExitNameElements = append(r.ExitNameElements, toSignElementResult(e))
	}
	return r
}

func toSignElementResult(e *routerv1.SignElement) queue.SignElementResult {
	r := queue.SignElementResult{Text: e.Text}
	if e.ConsecutiveCount != nil {
		v := int(*e.ConsecutiveCount)
		r.ConsecutiveCount = &v
	}
	return r
}

func writeSSEEvent(w http.ResponseWriter, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}

// BreakerExecutor is satisfied by *circuitbreaker.Registry.
type BreakerExecutor interface {
	Execute(name string, fn func() error) error
}
