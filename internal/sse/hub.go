package sse

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// Hub waits for job results via Redis pub/sub and writes SSE events to the response.
type Hub struct {
	redis *redis.Client
}

func New(rdb *redis.Client) *Hub {
	return &Hub{redis: rdb}
}

// WaitForResult subscribes to the result channel for jobID, writes an SSE
// "result" event when the worker finishes, and closes when done or timed out.
// The caller must have already written SSE headers and flushed the "queued" event.
func (h *Hub) WaitForResult(ctx context.Context, w http.ResponseWriter, jobID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeSSEEvent(w, "error", `{"code":13,"message":"streaming not supported"}`)
		return
	}

	sub := h.redis.Subscribe(ctx, "sw:done:"+jobID)
	defer sub.Close()

	// Check if the worker already finished before we subscribed.
	if existing, err := h.redis.Get(ctx, "sw:result:"+jobID).Result(); err == nil {
		writeSSEEvent(w, "result", existing)
		flusher.Flush()
		return
	}

	timeout := time.After(30 * time.Second)
	ch := sub.Channel()

	for {
		select {
		case msg := <-ch:
			writeSSEEvent(w, "result", msg.Payload)
			flusher.Flush()
			return
		case <-timeout:
			writeSSEEvent(w, "error", `{"code":4,"message":"timeout"}`)
			flusher.Flush()
			return
		case <-ctx.Done():
			return
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
}
