package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	routerv1 "github.com/swayrider/protos/router/v1"
)

func intPtr(v int) *int { return &v }

func validRejoinRequest() RejoinRequest {
	return RejoinRequest{
		RouteRequest: RouteRequest{
			From:    RouteCoord{Lat: 51, Lon: 4},
			To:      RouteCoord{Lat: 52, Lon: 5},
			Vehicle: "motorcycle",
			Unit:    "km",
		},
		FromHeading:          intPtr(90),
		FromHeadingTolerance: intPtr(30),
		Rejoin: []RejoinPointRequest{
			{Lat: 51.1, Lon: 4.1, Heading: 90, RemainingSeconds: 600},
		},
		Exclusions: [][]RouteCoord{
			{{Lat: 51.0, Lon: 4.0}, {Lat: 51.0, Lon: 4.001}, {Lat: 51.001, Lon: 4.001}},
		},
	}
}

func TestRejoinRequestValidate(t *testing.T) {
	if err := validRejoinRequest().validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	bigRing := make([]RouteCoord, 41)
	for i := range bigRing {
		bigRing[i] = RouteCoord{Lat: 51, Lon: 4 + float64(i)*1e-5}
	}
	cases := map[string]func(*RejoinRequest){
		"heading too high":    func(r *RejoinRequest) { r.FromHeading = intPtr(360) },
		"negative heading":    func(r *RejoinRequest) { r.FromHeading = intPtr(-1) },
		"tolerance zero":      func(r *RejoinRequest) { r.FromHeadingTolerance = intPtr(0) },
		"tolerance too high":  func(r *RejoinRequest) { r.FromHeadingTolerance = intPtr(181) },
		"point heading":       func(r *RejoinRequest) { r.Rejoin[0].Heading = 400 },
		"point latitude":      func(r *RejoinRequest) { r.Rejoin[0].Lat = 95 },
		"negative remaining":  func(r *RejoinRequest) { r.Rejoin[0].RemainingSeconds = -5 },
		"too many points":     func(r *RejoinRequest) { r.Rejoin = make([]RejoinPointRequest, maxRejoinPoints+1) },
		"too many exclusions": func(r *RejoinRequest) { r.Exclusions = make([][]RouteCoord, maxExclusionPolygons+1) },
		"ring of two points":  func(r *RejoinRequest) { r.Exclusions = [][]RouteCoord{{{Lat: 51, Lon: 4}, {Lat: 51, Lon: 4.1}}} },
		"ring too long":       func(r *RejoinRequest) { r.Exclusions = [][]RouteCoord{bigRing} },
		"ring too large": func(r *RejoinRequest) {
			r.Exclusions = [][]RouteCoord{{{Lat: 51, Lon: 4}, {Lat: 51, Lon: 4.1}, {Lat: 51.1, Lon: 4.1}}}
		},
		"ring bad coordinate": func(r *RejoinRequest) {
			r.Exclusions = [][]RouteCoord{{{Lat: 51, Lon: 4}, {Lat: 51, Lon: 200}, {Lat: 51.1, Lon: 4.1}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRejoinRequest()
			mutate(&r)
			if err := r.validate(); err == nil {
				t.Error("want a validation error")
			}
		})
	}
}

func TestRejoinRequestJSONFlattensRouteFields(t *testing.T) {
	body := `{"from":{"lat":51,"lon":4},"to":{"lat":52,"lon":5},"vehicle":"motorcycle",
		"fromHeading":90,"rejoin":[{"lat":51.1,"lon":4.1,"heading":90,"remainingSeconds":600}]}`
	var req RejoinRequest
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatal(err)
	}
	if req.From.Lat != 51 || req.Vehicle != "motorcycle" || len(req.Rejoin) != 1 || *req.FromHeading != 90 {
		t.Fatalf("decoded wrongly: %+v", req)
	}
}

func TestRejoinRouteQuery(t *testing.T) {
	req := validRejoinRequest()
	req.Waypoints = []RouteWaypoint{{Lat: 51.5, Lon: 4.5, Type: "through"}}
	query := req.rejoinQuery()

	fresh := query.Fresh
	if fresh.From.Latitude != 51 || fresh.To.Longitude != 5 || len(fresh.Waypoints) != 1 {
		t.Errorf("stops: %+v", fresh)
	}
	if fresh.FromHeading == nil || *fresh.FromHeading != 90 ||
		fresh.FromHeadingTolerance == nil || *fresh.FromHeadingTolerance != 30 {
		t.Errorf("heading: %v tolerance %v", fresh.FromHeading, fresh.FromHeadingTolerance)
	}
	if len(fresh.ExcludePolygons) != 1 || len(fresh.ExcludePolygons[0]) != 3 {
		t.Errorf("exclusions: %v", fresh.ExcludePolygons)
	}
	if len(query.Points) != 1 || query.Points[0].Heading != 90 || query.Points[0].RemainingSeconds != 600 ||
		query.Points[0].Coordinate.Latitude != 51.1 {
		t.Errorf("points: %+v", query.Points)
	}
}

func TestRejoinRouteQueryDefaultsTolerance(t *testing.T) {
	req := validRejoinRequest()
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

func TestToRejoinResult(t *testing.T) {
	trip := &routerv1.Trip{Summary: &routerv1.Summary{Time: 120}}

	got := toRejoinResult(&routerv1.RejoinResponse{Kind: routerv1.RejoinKind_RJ_REJOIN, RejoinIndex: 2, Trip: trip})
	if got.Choice != "rejoin" || got.RejoinIndex != 2 || got.Trip.Summary.Time != 120 {
		t.Errorf("rejoin: %+v", got)
	}

	got = toRejoinResult(&routerv1.RejoinResponse{Kind: routerv1.RejoinKind_RJ_FRESH, Trip: trip})
	if got.Choice != "fresh" || got.RejoinIndex != 0 {
		t.Errorf("fresh: %+v", got)
	}
}
