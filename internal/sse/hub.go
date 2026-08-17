package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swayrider-api/internal/queue"
)

// notFoundEvent is the SSE error event sent when a result cannot be delivered.
// "not found" is used (rather than "permission denied") for both ownership
// mismatches and malformed payloads, so a caller cannot distinguish them and
// cannot probe whether a job exists.
const notFoundEvent = `{"code":5,"message":"not found"}`

// Hub waits for job results via Redis pub/sub and writes SSE events to the response.
type Hub struct {
	redis *redis.Client
	l     *log.Logger
}

func New(rdb *redis.Client, l *log.Logger) *Hub {
	return &Hub{
		redis: rdb,
		l:     l.Derive(log.WithComponent("sse")),
	}
}

// WaitForResult subscribes to the result channel for jobID, writes an SSE
// "result" event when the worker finishes, and closes when done or timed out.
// The caller must have already written SSE headers and flushed the "queued" event.
//
// userID is the authenticated user who submitted the job. Results are only
// delivered to that user: the stored/published payload is a StoredResult
// envelope, and the result is emitted only when its owner matches userID.
func (h *Hub) WaitForResult(ctx context.Context, w http.ResponseWriter, jobID, userID string) {
	lg := h.l.Derive(log.WithFunction("WaitForResult"))

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeSSEEvent(w, "error", `{"code":13,"message":"streaming not supported"}`)
		return
	}

	sub := h.redis.Subscribe(ctx, "sw:done:"+jobID)
	defer func() { _ = sub.Close() }()

	// Check if the worker already finished before we subscribed.
	if existing, err := h.redis.Get(ctx, "sw:result:"+jobID).Result(); err == nil {
		if data, ok := resultForUser([]byte(existing), userID); ok {
			lg.Debugf("result from cache job_id=%s", jobID)
			writeSSEEvent(w, "result", string(data))
			flusher.Flush()
			return
		}
		// The result exists but belongs to someone else (or is malformed) —
		// refuse without revealing that the job exists.
		lg.Warnf("result not delivered job_id=%s user=%s", jobID, userID)
		writeSSEEvent(w, "error", notFoundEvent)
		flusher.Flush()
		return
	}

	timeout := time.After(30 * time.Second)
	ch := sub.Channel()

	for {
		select {
		case msg := <-ch:
			if data, ok := resultForUser([]byte(msg.Payload), userID); ok {
				writeSSEEvent(w, "result", string(data))
				flusher.Flush()
				return
			}
			lg.Warnf("result not delivered job_id=%s user=%s", jobID, userID)
			writeSSEEvent(w, "error", notFoundEvent)
			flusher.Flush()
			return
		case <-timeout:
			lg.Warnf("SSE timeout job_id=%s", jobID)
			writeSSEEvent(w, "error", `{"code":4,"message":"timeout"}`)
			flusher.Flush()
			return
		case <-ctx.Done():
			return
		}
	}
}

// resultForUser returns the raw result JSON from a StoredResult envelope if it
// belongs to userID. It returns false for both a malformed payload and an
// ownership mismatch — deliberately indistinguishable, so callers cannot probe
// whether a job exists.
func resultForUser(payload []byte, userID string) (json.RawMessage, bool) {
	var st queue.StoredResult
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, false
	}
	if st.UserID != userID {
		return nil, false
	}
	return st.Result, true
}

func writeSSEEvent(w http.ResponseWriter, event, data string) {
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}
