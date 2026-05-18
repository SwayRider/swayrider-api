package handlers

import (
	"context"
	"net/http"

	"github.com/swayrider/grpcclients/regionclient"
)

// RegionClient is satisfied by *regionclient.Client.
type RegionClient interface {
	SearchPoint(ctx context.Context, token string, location regionclient.Coordinate, includeExtended bool) (regionclient.RegionList, error)
	SearchBox(ctx context.Context, token string, boundingBox regionclient.BoundingBox, includeExtended bool) (regionclient.RegionList, error)
	SearchRadius(ctx context.Context, token string, location regionclient.Coordinate, radiusKm float64, includeExtended bool) (regionclient.RegionList, error)
	FindCrossingLocations(ctx context.Context, token string, fromRegion, toRegion string, fromLoc, toLoc regionclient.Coordinate, cfg regionclient.BorderCrossingConfig, limit int) ([]regionclient.BorderCrossing, error)
	FindRegionPath(ctx context.Context, token string, fromRegion, toRegion string) ([]string, error)
}

type RegionHandler struct {
	client RegionClient
	token  func() string
}

func NewRegionHandler(client RegionClient, token func() string) *RegionHandler {
	return &RegionHandler{client: client, token: token}
}

func (h *RegionHandler) SearchPoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Location struct {
			Lat float64 `json:"lat"`
			Lon float64 `json:"lon"`
		} `json:"location"`
		IncludeExtended bool `json:"include_extended"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	result, err := h.client.SearchPoint(
		r.Context(),
		h.token(),
		regionclient.Coordinate{Latitude: req.Location.Lat, Longitude: req.Location.Lon},
		req.IncludeExtended,
	)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *RegionHandler) SearchBox(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Box struct {
			BottomLeft struct {
				Lat float64 `json:"lat"`
				Lon float64 `json:"lon"`
			} `json:"bottom_left"`
			TopRight struct {
				Lat float64 `json:"lat"`
				Lon float64 `json:"lon"`
			} `json:"top_right"`
		} `json:"box"`
		IncludeExtended bool `json:"include_extended"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	result, err := h.client.SearchBox(
		r.Context(),
		h.token(),
		regionclient.BoundingBox{
			BottomLeft: regionclient.Coordinate{Latitude: req.Box.BottomLeft.Lat, Longitude: req.Box.BottomLeft.Lon},
			TopRight:   regionclient.Coordinate{Latitude: req.Box.TopRight.Lat, Longitude: req.Box.TopRight.Lon},
		},
		req.IncludeExtended,
	)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *RegionHandler) SearchRadius(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Location struct {
			Lat float64 `json:"lat"`
			Lon float64 `json:"lon"`
		} `json:"location"`
		RadiusKm        float64 `json:"radius_km"`
		IncludeExtended bool    `json:"include_extended"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	result, err := h.client.SearchRadius(
		r.Context(),
		h.token(),
		regionclient.Coordinate{Latitude: req.Location.Lat, Longitude: req.Location.Lon},
		req.RadiusKm,
		req.IncludeExtended,
	)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *RegionHandler) FindCrossingLocations(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromRegion string `json:"from_region"`
		ToRegion   string `json:"to_region"`
		FromLoc    struct {
			Lat float64 `json:"lat"`
			Lon float64 `json:"lon"`
		} `json:"from_location"`
		ToLoc struct {
			Lat float64 `json:"lat"`
			Lon float64 `json:"lon"`
		} `json:"to_location"`
		Limit  int `json:"limit"`
		Config struct {
			Type          string   `json:"type"`
			RoadTypeOrder []string `json:"road_type_order"`
			RoadTypeDelta float64  `json:"road_type_delta"`
			DropDistance  float64  `json:"drop_distance"`
		} `json:"config"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	cfg := buildCrossingConfig(req.Config.Type, req.Config.RoadTypeOrder, req.Config.RoadTypeDelta, req.Config.DropDistance)

	crossings, err := h.client.FindCrossingLocations(
		r.Context(),
		h.token(),
		req.FromRegion, req.ToRegion,
		regionclient.Coordinate{Latitude: req.FromLoc.Lat, Longitude: req.FromLoc.Lon},
		regionclient.Coordinate{Latitude: req.ToLoc.Lat, Longitude: req.ToLoc.Lon},
		cfg,
		req.Limit,
	)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, crossings)
}

func (h *RegionHandler) FindRegionPath(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromRegion string `json:"from_region"`
		ToRegion   string `json:"to_region"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	path, err := h.client.FindRegionPath(r.Context(), h.token(), req.FromRegion, req.ToRegion)
	if err != nil {
		writeJSON(w, grpcStatus(err), errBody(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path})
}

func buildCrossingConfig(typ string, roadTypes []string, delta, drop float64) regionclient.BorderCrossingConfig {
	rts := make([]regionclient.RoadType, 0, len(roadTypes))
	for _, rt := range roadTypes {
		rts = append(rts, regionclient.RoadType(rt))
	}
	if typ == "advanced" {
		return regionclient.BorderCrossingAdvancedConfig{
			Definitions: []regionclient.BorderCrossingDefinition{{
				RoadTypeOrder: rts,
				RoadTypeDelta: delta,
				DropDistance:  drop,
			}},
		}
	}
	return regionclient.BorderCrossingSimpleConfig{
		RoadTypeOrder: rts,
		RoadTypeDelta: delta,
		DropDistance:  drop,
	}
}
