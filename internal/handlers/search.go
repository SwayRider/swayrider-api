package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/swayrider/grpcclients/searchclient"
	"github.com/swayrider/swlib/jwt"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
	"github.com/swayrider/swayrider-api/internal/queue"
	"github.com/swayrider/swayrider-api/internal/sse"
)

// SearchRequest is the JSON body accepted by POST /api/v1/search.
type SearchRequest struct {
	Text       string        `json:"text"`
	Viewport   SearchBBox    `json:"viewport"`
	FocusPoint *SearchCoord  `json:"focusPoint,omitempty"`
	Size       int32         `json:"size"`
	Language   string        `json:"language"`
}

// ReverseGeocodeRequest is the JSON body accepted by POST /api/v1/search/reverse.
type ReverseGeocodeRequest struct {
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Size     int32   `json:"size"`
	Language string  `json:"language"`
}

// AutocompleteRequest is the JSON body accepted by POST /api/v1/search/autocomplete.
type AutocompleteRequest struct {
	Text       string      `json:"text"`
	FocusPoint SearchCoord `json:"focusPoint"`
	Size       int32       `json:"size"`
	Language   string      `json:"language"`
}

// SearchCoord is a lat/lon pair used in search requests.
type SearchCoord struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// SearchBBox is a bounding box used in search viewport.
type SearchBBox struct {
	BottomLeft SearchCoord `json:"bottomLeft"`
	TopRight   SearchCoord `json:"topRight"`
}

// SearchHandler handles search endpoints.
type SearchHandler struct {
	producer *queue.Producer
	hub      *sse.Hub
	client   *searchclient.Client
	token    func() string
	breaker  BreakerExecutor
	l        *log.Logger
}

func NewSearchHandler(
	producer *queue.Producer,
	hub *sse.Hub,
	client *searchclient.Client,
	token func() string,
	breaker BreakerExecutor,
	l *log.Logger,
) *SearchHandler {
	return &SearchHandler{
		producer: producer,
		hub:      hub,
		client:   client,
		token:    token,
		breaker:  breaker,
		l:        l.Derive(log.WithComponent("search")),
	}
}

func (h *SearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	var parsed SearchRequest
	h.enqueueAndStream(w, r, queue.StreamSearch, "search", func() (string, error) {
		if err := json.NewDecoder(r.Body).Decode(&parsed); err != nil {
			return "", err
		}
		b, err := json.Marshal(struct {
			Kind string        `json:"kind"`
			Req  SearchRequest `json:"req"`
		}{"search", parsed})
		return string(b), err
	}, func(userID, jobID string) {
		h.l.Derive(log.WithFunction("Search")).Infof(
			"search enqueued job_id=%s user=%s text=%q", jobID, userID, parsed.Text)
	})
}

func (h *SearchHandler) ReverseGeocode(w http.ResponseWriter, r *http.Request) {
	var parsed ReverseGeocodeRequest
	h.enqueueAndStream(w, r, queue.StreamSearch, "reverse", func() (string, error) {
		if err := json.NewDecoder(r.Body).Decode(&parsed); err != nil {
			return "", err
		}
		b, err := json.Marshal(struct {
			Kind string                `json:"kind"`
			Req  ReverseGeocodeRequest `json:"req"`
		}{"reverse", parsed})
		return string(b), err
	}, func(userID, jobID string) {
		h.l.Derive(log.WithFunction("ReverseGeocode")).Infof(
			"reverse geocode enqueued job_id=%s user=%s lat=%.4f lon=%.4f", jobID, userID, parsed.Lat, parsed.Lon)
	})
}

func (h *SearchHandler) Autocomplete(w http.ResponseWriter, r *http.Request) {
	lg := h.l.Derive(log.WithFunction("Autocomplete"))

	claims, ok := security.GetClaims(r.Context())
	if !ok || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req AutocompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	query := searchclient.AutocompleteQuery{
		Text:       req.Text,
		FocusPoint: searchclient.Coordinate{Latitude: req.FocusPoint.Lat, Longitude: req.FocusPoint.Lon},
		Size:       req.Size,
		Language:   req.Language,
	}

	var items []queue.SearchItem
	err := h.breaker.Execute("searchservice", func() error {
		results, err := h.client.AutocompleteWithContext(r.Context(), h.token(), query, newSearchResult)
		if err != nil {
			return err
		}
		items = toSearchItems(results)
		return nil
	})
	if err != nil {
		lg.Errorf("autocomplete failed user=%s err=%v", claims.Subject, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	lg.Debugf("autocomplete user=%s text=%q results=%d", claims.Subject, req.Text, len(items))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(items); err != nil {
		lg.Errorf("encode autocomplete response: %v", err)
	}
}

func (h *SearchHandler) enqueueAndStream(
	w http.ResponseWriter,
	r *http.Request,
	stream string,
	kind string,
	buildPayload func() (string, error),
	logEnqueued func(userID, jobID string),
) {
	lg := h.l.Derive(log.WithFunction(kind))

	claims, ok := security.GetClaims(r.Context())
	if !ok || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	payload, err := buildPayload()
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
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

	jobID, err := h.producer.Enqueue(r.Context(), stream, queue.Job{
		Payload:      payload,
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

	logEnqueued(claims.Subject, jobID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	depth, _ := h.producer.QueueDepth(r.Context(), stream)
	writeSSEEvent(w, "queued", fmt.Sprintf(`{"job_id":%q,"queue_position":%d}`, jobID, depth))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	h.hub.WaitForResult(r.Context(), w, jobID)
}

// NewSearchProcessFn returns the worker ProcessFn for search/reverse-geocode jobs.
func NewSearchProcessFn(client *searchclient.Client, token func() string, breaker BreakerExecutor) queue.ProcessFn {
	return func(ctx context.Context, job queue.Job) (json.RawMessage, error) {
		// The payload wraps both search and reverse-geocode requests under a "kind" discriminant.
		var envelope struct {
			Kind string          `json:"kind"`
			Req  json.RawMessage `json:"req"`
		}
		if err := json.Unmarshal([]byte(job.Payload), &envelope); err != nil {
			return nil, err
		}

		userCtx := queue.UserMetadataCtx(ctx, job)

		switch envelope.Kind {
		case "search":
			var req SearchRequest
			if err := json.Unmarshal(envelope.Req, &req); err != nil {
				return nil, err
			}
			return runSearch(userCtx, client, token, breaker, req)
		case "reverse":
			var req ReverseGeocodeRequest
			if err := json.Unmarshal(envelope.Req, &req); err != nil {
				return nil, err
			}
			return runReverseGeocode(userCtx, client, token, breaker, req)
		default:
			return nil, fmt.Errorf("unknown search kind: %s", envelope.Kind)
		}
	}
}

func runSearch(ctx context.Context, client *searchclient.Client, token func() string, breaker BreakerExecutor, req SearchRequest) (json.RawMessage, error) {
	query := searchclient.SearchQuery{
		Text: req.Text,
		Viewport: searchclient.BoundingBox{
			BottomLeft: searchclient.Coordinate{Latitude: req.Viewport.BottomLeft.Lat, Longitude: req.Viewport.BottomLeft.Lon},
			TopRight:   searchclient.Coordinate{Latitude: req.Viewport.TopRight.Lat, Longitude: req.Viewport.TopRight.Lon},
		},
		Size:     req.Size,
		Language: req.Language,
	}
	if req.FocusPoint != nil {
		query.FocusPoint = &searchclient.Coordinate{Latitude: req.FocusPoint.Lat, Longitude: req.FocusPoint.Lon}
	}

	var items []queue.SearchItem
	err := breaker.Execute("searchservice", func() error {
		results, err := client.SearchWithContext(ctx, token(), query, newSearchResult)
		if err != nil {
			return err
		}
		items = toSearchItems(results)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(items)
}

func runReverseGeocode(ctx context.Context, client *searchclient.Client, token func() string, breaker BreakerExecutor, req ReverseGeocodeRequest) (json.RawMessage, error) {
	query := searchclient.ReverseGeocodeQuery{
		Point:    searchclient.Coordinate{Latitude: req.Lat, Longitude: req.Lon},
		Size:     req.Size,
		Language: req.Language,
	}

	var items []queue.SearchItem
	err := breaker.Execute("searchservice", func() error {
		results, err := client.ReverseGeocodeWithContext(ctx, token(), query, newSearchResult)
		if err != nil {
			return err
		}
		items = toSearchItems(results)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(items)
}

// --- concrete implementation of searchclient.SearchResult ---

type searchResultImpl struct {
	label, locality, region, country string
	confidence                        float64
	layer                             string
	lat, lon                          float64
	street, houseNumber               string
	id, localAdmin, countryCode, name string
}

func (s *searchResultImpl) Label() string       { return s.label }
func (s *searchResultImpl) Locality() string    { return s.locality }
func (s *searchResultImpl) Region() string      { return s.region }
func (s *searchResultImpl) Country() string     { return s.country }
func (s *searchResultImpl) Confidence() float64 { return s.confidence }
func (s *searchResultImpl) Layer() string       { return s.layer }
func (s *searchResultImpl) Lat() float64        { return s.lat }
func (s *searchResultImpl) Lon() float64        { return s.lon }
func (s *searchResultImpl) Street() string      { return s.street }
func (s *searchResultImpl) HouseNumber() string { return s.houseNumber }
func (s *searchResultImpl) Id() string          { return s.id }
func (s *searchResultImpl) LocalAdmin() string  { return s.localAdmin }
func (s *searchResultImpl) CountryCode() string { return s.countryCode }
func (s *searchResultImpl) Name() string        { return s.name }

func newSearchResult(
	label, locality, region, country string,
	confidence float64,
	layer string,
	lat, lon float64,
	street, housenumber, id, localadmin, countryCode, name string,
) searchclient.SearchResult {
	return &searchResultImpl{
		label: label, locality: locality, region: region, country: country,
		confidence: confidence, layer: layer, lat: lat, lon: lon,
		street: street, houseNumber: housenumber, id: id,
		localAdmin: localadmin, countryCode: countryCode, name: name,
	}
}

func toSearchItems(results []searchclient.SearchResult) []queue.SearchItem {
	items := make([]queue.SearchItem, 0, len(results))
	for _, r := range results {
		items = append(items, queue.SearchItem{
			Label:       r.Label(),
			Locality:    r.Locality(),
			Region:      r.Region(),
			Country:     r.Country(),
			Confidence:  r.Confidence(),
			Layer:       r.Layer(),
			Lat:         r.Lat(),
			Lon:         r.Lon(),
			Street:      r.Street(),
			HouseNumber: r.HouseNumber(),
			Id:          r.Id(),
			LocalAdmin:  r.LocalAdmin(),
			CountryCode: r.CountryCode(),
			Name:        r.Name(),
		})
	}
	return items
}
