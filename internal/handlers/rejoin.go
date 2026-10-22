package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"

	"github.com/swayrider/grpcclients/routerclient"
	routerv1 "github.com/swayrider/protos/router/v1"
	"github.com/swayrider/swayrider-api/internal/queue"
	"github.com/swayrider/swayrider-api/internal/sse"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

const (
	maxRejoinPoints         = 6
	maxExclusionPolygons    = 6
	maxExclusionPoints      = 40
	maxExclusionExtentMeter = 2000.0
)

// RejoinRequest is the JSON body accepted by POST /api/v1/route/rejoin: a
// normal route request describing the fresh route from the rider's position
// to the remaining stops, plus the points of the original route to rejoin.
type RejoinRequest struct {
	RouteRequest

	// FromHeading is the rider's direction of travel in degrees clockwise
	// from north, FromHeadingTolerance how far a road may deviate from it
	// (default 45).
	FromHeading          *int `json:"fromHeading,omitempty"`
	FromHeadingTolerance *int `json:"fromHeadingTolerance,omitempty"`

	// Exclusions are areas the route must not pass through (suspected
	// closures), as rings of lat/lon points.
	Exclusions [][]RouteCoord `json:"exclusions,omitempty"`

	// Rejoin lists the points of the original route that can be rejoined.
	Rejoin []RejoinPointRequest `json:"rejoin"`
}

// RejoinPointRequest is one point of the original route.
type RejoinPointRequest struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
	// Heading is the direction of the original route at the point.
	Heading int `json:"heading"`
	// RemainingSeconds is the travel time left on the original route after
	// the point.
	RemainingSeconds float64 `json:"remainingSeconds"`
}

const defaultFromHeadingTolerance = 45

func validCoord(c RouteCoord) bool {
	return !math.IsNaN(c.Lat) && !math.IsNaN(c.Lon) &&
		c.Lat >= -90 && c.Lat <= 90 && c.Lon >= -180 && c.Lon <= 180
}

// validate checks the rejoin-specific fields. The route fields are
// validated downstream by routerservice.
func (r RejoinRequest) validate() error {
	if r.FromHeading != nil && (*r.FromHeading < 0 || *r.FromHeading > 359) {
		return errors.New("fromHeading must be 0-359")
	}
	if r.FromHeadingTolerance != nil && (*r.FromHeadingTolerance < 1 || *r.FromHeadingTolerance > 180) {
		return errors.New("fromHeadingTolerance must be 1-180")
	}
	if len(r.Rejoin) > maxRejoinPoints {
		return fmt.Errorf("at most %d rejoin points", maxRejoinPoints)
	}
	for i, p := range r.Rejoin {
		if !validCoord(RouteCoord{Lat: p.Lat, Lon: p.Lon}) {
			return fmt.Errorf("rejoin[%d]: invalid coordinate", i)
		}
		if p.Heading < 0 || p.Heading > 359 {
			return fmt.Errorf("rejoin[%d]: heading must be 0-359", i)
		}
		if p.RemainingSeconds < 0 || math.IsNaN(p.RemainingSeconds) || math.IsInf(p.RemainingSeconds, 0) {
			return fmt.Errorf("rejoin[%d]: invalid remainingSeconds", i)
		}
	}
	if len(r.Exclusions) > maxExclusionPolygons {
		return fmt.Errorf("at most %d exclusions", maxExclusionPolygons)
	}
	for i, ring := range r.Exclusions {
		if len(ring) < 3 || len(ring) > maxExclusionPoints {
			return fmt.Errorf("exclusions[%d]: needs 3-%d points", i, maxExclusionPoints)
		}
		minLat, maxLat, minLon, maxLon := 90.0, -90.0, 180.0, -180.0
		for _, c := range ring {
			if !validCoord(c) {
				return fmt.Errorf("exclusions[%d]: invalid coordinate", i)
			}
			minLat, maxLat = math.Min(minLat, c.Lat), math.Max(maxLat, c.Lat)
			minLon, maxLon = math.Min(minLon, c.Lon), math.Max(maxLon, c.Lon)
		}
		if distanceMeters(minLat, minLon, maxLat, maxLon) > maxExclusionExtentMeter {
			return fmt.Errorf("exclusions[%d]: larger than %.0f m", i, maxExclusionExtentMeter)
		}
	}
	return nil
}

// distanceMeters is the haversine distance between two coordinates.
func distanceMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371008.8
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat, dLon := rad(lat2-lat1), rad(lon2-lon1)
	h := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadius * math.Asin(math.Min(1, math.Sqrt(h)))
}

// RejoinHandler handles POST /api/v1/route/rejoin via SSE. Rejoin jobs go to
// their own stream so they never wait behind route planning.
type RejoinHandler struct {
	producer *queue.Producer
	hub      *sse.Hub
	l        *log.Logger
}

func NewRejoinHandler(producer *queue.Producer, hub *sse.Hub, l *log.Logger) *RejoinHandler {
	return &RejoinHandler{
		producer: producer,
		hub:      hub,
		l:        l.Derive(log.WithComponent("rejoin")),
	}
}

func (h *RejoinHandler) Rejoin(w http.ResponseWriter, r *http.Request) {
	claims, ok := security.GetClaims(r.Context())
	if !ok || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req RejoinRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	streamJob(w, r, h.producer, h.hub, queue.StreamRerouting, req, claims, h.l.Derive(log.WithFunction("Rejoin")),
		fmt.Sprintf("from=%.4f,%.4f to=%.4f,%.4f points=%d exclusions=%d",
			req.From.Lat, req.From.Lon, req.To.Lat, req.To.Lon, len(req.Rejoin), len(req.Exclusions)))
}

// routeQuery turns the request into the routerclient query for the fresh
// route.
func (r RejoinRequest) routeQuery() routerclient.RouteQuery {
	query := routerclient.RouteQuery{
		From:     routerclient.Coordinate{Latitude: r.From.Lat, Longitude: r.From.Lon},
		To:       routerclient.Coordinate{Latitude: r.To.Lat, Longitude: r.To.Lon},
		Vehicle:  r.Vehicle,
		Unit:     r.Unit,
		Language: r.Language,
		StandardRoutingOptions: routerclient.StandardRoutingOptions{
			AvoidTollRoads:   r.Options.AvoidTollRoads,
			AvoidHighways:    r.Options.AvoidHighways,
			AvoidFerries:     r.Options.AvoidFerries,
			ScenicPreference: r.Options.ScenicPreference,
			HighwayAvoidance: r.Options.HighwayAvoidance,
			TollAvoidance:    r.Options.TollAvoidance,
			UnpavedHandling:  r.Options.UnpavedHandling,
		},
	}
	for _, wp := range r.Waypoints {
		query.Waypoints = append(query.Waypoints, routerclient.Waypoint{
			Coordinate: routerclient.Coordinate{Latitude: wp.Lat, Longitude: wp.Lon},
			Type:       wp.Type,
		})
	}
	if r.FromHeading != nil {
		heading := *r.FromHeading
		tolerance := defaultFromHeadingTolerance
		if r.FromHeadingTolerance != nil {
			tolerance = *r.FromHeadingTolerance
		}
		query.FromHeading = &heading
		query.FromHeadingTolerance = &tolerance
	}
	for _, ring := range r.Exclusions {
		var polygon []routerclient.Coordinate
		for _, c := range ring {
			polygon = append(polygon, routerclient.Coordinate{Latitude: c.Lat, Longitude: c.Lon})
		}
		query.ExcludePolygons = append(query.ExcludePolygons, polygon)
	}
	return query
}

func (r RejoinRequest) rejoinQuery() routerclient.RejoinQuery {
	query := routerclient.RejoinQuery{Fresh: r.routeQuery()}
	for _, p := range r.Rejoin {
		query.Points = append(query.Points, routerclient.RejoinPoint{
			Coordinate:       routerclient.Coordinate{Latitude: p.Lat, Longitude: p.Lon},
			Heading:          p.Heading,
			RemainingSeconds: p.RemainingSeconds,
		})
	}
	return query
}

// NewRejoinProcessFn returns the worker ProcessFn for rejoin jobs.
func NewRejoinProcessFn(client *routerclient.Client, token func() string, breaker BreakerExecutor) queue.ProcessFn {
	return func(ctx context.Context, job queue.Job) (json.RawMessage, error) {
		var req RejoinRequest
		if err := json.Unmarshal([]byte(job.Payload), &req); err != nil {
			return nil, err
		}

		userCtx := queue.UserMetadataCtx(ctx, job)

		var result queue.RejoinResult
		err := breaker.Execute("routerservice", func() error {
			resp, err := client.RejoinRaw(userCtx, token(), req.rejoinQuery())
			if err != nil {
				return err
			}
			result = toRejoinResult(resp)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
}

func toRejoinResult(resp *routerv1.RejoinResponse) queue.RejoinResult {
	result := queue.RejoinResult{
		Choice: "fresh",
		Trip:   toTripResult(resp.Trip),
	}
	if resp.Kind == routerv1.RejoinKind_RJ_REJOIN {
		result.Choice = "rejoin"
		result.RejoinIndex = int(resp.RejoinIndex)
	}
	return result
}
