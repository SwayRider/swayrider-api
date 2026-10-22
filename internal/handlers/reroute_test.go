package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

func intPtr(v int) *int { return &v }

func validRerouteRequest() RerouteRequest {
	return RerouteRequest{
		RouteRequest: RouteRequest{
			From:    RouteCoord{Lat: 51, Lon: 4},
			To:      RouteCoord{Lat: 52, Lon: 5},
			Vehicle: "motorcycle",
			Unit:    "km",
		},
		FromHeading:          intPtr(90),
		FromHeadingTolerance: intPtr(30),
		Exclusions: [][]RouteCoord{
			{{Lat: 51.0, Lon: 4.0}, {Lat: 51.0, Lon: 4.001}, {Lat: 51.001, Lon: 4.001}},
		},
	}
}

func TestRerouteRequestValidate(t *testing.T) {
	if err := validRerouteRequest().validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := (RerouteRequest{}).validate(); err != nil {
		t.Fatalf("a request without heading and exclusions is valid: %v", err)
	}

	bigRing := make([]RouteCoord, 41)
	for i := range bigRing {
		bigRing[i] = RouteCoord{Lat: 51, Lon: 4 + float64(i)*1e-5}
	}
	cases := map[string]func(*RerouteRequest){
		"heading too high":    func(r *RerouteRequest) { r.FromHeading = intPtr(360) },
		"negative heading":    func(r *RerouteRequest) { r.FromHeading = intPtr(-1) },
		"tolerance zero":      func(r *RerouteRequest) { r.FromHeadingTolerance = intPtr(0) },
		"tolerance too high":  func(r *RerouteRequest) { r.FromHeadingTolerance = intPtr(181) },
		"too many exclusions": func(r *RerouteRequest) { r.Exclusions = make([][]RouteCoord, maxExclusionPolygons+1) },
		"ring of two points":  func(r *RerouteRequest) { r.Exclusions = [][]RouteCoord{{{Lat: 51, Lon: 4}, {Lat: 51, Lon: 4.1}}} },
		"ring too long":       func(r *RerouteRequest) { r.Exclusions = [][]RouteCoord{bigRing} },
		"ring too large": func(r *RerouteRequest) {
			r.Exclusions = [][]RouteCoord{{{Lat: 51, Lon: 4}, {Lat: 51, Lon: 4.1}, {Lat: 51.1, Lon: 4.1}}}
		},
		"ring bad coordinate": func(r *RerouteRequest) {
			r.Exclusions = [][]RouteCoord{{{Lat: 51, Lon: 4}, {Lat: 51, Lon: 200}, {Lat: 51.1, Lon: 4.1}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRerouteRequest()
			mutate(&r)
			if err := r.validate(); err == nil {
				t.Error("want a validation error")
			}
		})
	}
}

func TestRerouteRequestJSONFlattensRouteFields(t *testing.T) {
	body := `{"from":{"lat":51,"lon":4},"to":{"lat":52,"lon":5},"vehicle":"motorcycle","fromHeading":90}`
	var req RerouteRequest
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatal(err)
	}
	if req.From.Lat != 51 || req.Vehicle != "motorcycle" || *req.FromHeading != 90 {
		t.Fatalf("decoded wrongly: %+v", req)
	}
}

func TestRerouteRouteQuery(t *testing.T) {
	req := validRerouteRequest()
	req.Waypoints = []RouteWaypoint{{Lat: 51.5, Lon: 4.5, Type: "through"}}
	query := req.routeQuery()

	if query.From.Latitude != 51 || query.To.Longitude != 5 || len(query.Waypoints) != 1 {
		t.Errorf("stops: %+v", query)
	}
	if query.FromHeading == nil || *query.FromHeading != 90 ||
		query.FromHeadingTolerance == nil || *query.FromHeadingTolerance != 30 {
		t.Errorf("heading: %v tolerance %v", query.FromHeading, query.FromHeadingTolerance)
	}
	if len(query.ExcludePolygons) != 1 || len(query.ExcludePolygons[0]) != 3 {
		t.Errorf("exclusions: %v", query.ExcludePolygons)
	}
}

func TestRerouteRouteQueryDefaultsTolerance(t *testing.T) {
	req := validRerouteRequest()
	req.FromHeadingTolerance = nil
	if tol := req.routeQuery().FromHeadingTolerance; tol == nil || *tol != defaultFromHeadingTolerance {
		t.Errorf("tolerance: %v", tol)
	}

	req.FromHeading = nil
	query := req.routeQuery()
	if query.FromHeading != nil || query.FromHeadingTolerance != nil {
		t.Error("without a heading neither heading nor tolerance is sent")
	}
}
