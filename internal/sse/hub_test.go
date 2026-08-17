package sse

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/swayrider/swayrider-api/internal/queue"
	log "github.com/swayrider/swlib/logger"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// newTestHub starts an in-memory Redis and a Hub over it.
func newTestHub(t *testing.T) (*Hub, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, log.New()), mr
}

func storedEnvelope(t *testing.T, userID, result string) string {
	t.Helper()
	b, err := json.Marshal(queue.StoredResult{UserID: userID, Result: json.RawMessage(result)})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(b)
}

// seedResult stores a cached result envelope in the in-memory Redis.
func seedResult(t *testing.T, mr *miniredis.Miniredis, jobID, payload string) {
	t.Helper()
	if err := mr.Set("sw:result:"+jobID, payload); err != nil {
		t.Fatalf("seed result: %v", err)
	}
}

func TestResultForUser(t *testing.T) {
	payload := storedEnvelope(t, "user-1", `{"success":true,"data":{"x":1}}`)

	if _, ok := resultForUser([]byte(payload), "user-1"); !ok {
		t.Error("resultForUser rejected the owner")
	}
	if _, ok := resultForUser([]byte(payload), "user-2"); ok {
		t.Error("resultForUser accepted a non-owner")
	}
	if _, ok := resultForUser([]byte("not-json"), "user-1"); ok {
		t.Error("resultForUser accepted a malformed payload")
	}
	if _, ok := resultForUser([]byte(`{"result":{"success":true}}`), "user-1"); ok {
		t.Error("resultForUser accepted a payload without user_id")
	}
}

func TestWaitForResult_DeliversOwnedCachedResult(t *testing.T) {
	h, mr := newTestHub(t)
	seedResult(t, mr, "job-1", storedEnvelope(t, "user-1", `{"success":true,"data":{"x":1}}`))

	rec := httptest.NewRecorder()
	h.WaitForResult(context.Background(), rec, "job-1", "user-1")

	body := rec.Body.String()
	if !strings.Contains(body, "event: result") {
		t.Errorf("missing result event: %q", body)
	}
	if !strings.Contains(body, `{"success":true,"data":{"x":1}}`) {
		t.Errorf("result payload missing from stream: %q", body)
	}
	if strings.Contains(body, "user_id") {
		t.Errorf("envelope owner leaked into client stream: %q", body)
	}
}

func TestWaitForResult_RefusesCachedResultForOtherUser(t *testing.T) {
	h, mr := newTestHub(t)
	seedResult(t, mr, "job-1", storedEnvelope(t, "user-1", `{"success":true,"data":{"x":1}}`))

	rec := httptest.NewRecorder()
	h.WaitForResult(context.Background(), rec, "job-1", "user-2")

	body := rec.Body.String()
	if !strings.Contains(body, "event: error") || !strings.Contains(body, "not found") {
		t.Errorf("expected not-found error event: %q", body)
	}
	if strings.Contains(body, "event: result") {
		t.Errorf("result leaked to a non-owner: %q", body)
	}
}

func TestWaitForResult_RefusesMalformedCachedResult(t *testing.T) {
	h, mr := newTestHub(t)
	seedResult(t, mr, "job-1", "not-json")

	rec := httptest.NewRecorder()
	h.WaitForResult(context.Background(), rec, "job-1", "user-1")

	body := rec.Body.String()
	if !strings.Contains(body, "event: error") || !strings.Contains(body, "not found") {
		t.Errorf("expected not-found error event: %q", body)
	}
	if strings.Contains(body, "event: result") {
		t.Errorf("malformed result delivered: %q", body)
	}
}

func TestWaitForResult_DeliversOwnedPublishedResult(t *testing.T) {
	h, mr := newTestHub(t)
	pub := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = pub.Close() })

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.WaitForResult(context.Background(), rec, "job-2", "user-1")
	}()

	waitForSubscriber(t, pub, "sw:done:job-2")
	pub.Publish(context.Background(), "sw:done:job-2", storedEnvelope(t, "user-1", `{"success":true,"data":{"y":2}}`))
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, "event: result") {
		t.Errorf("missing result event: %q", body)
	}
	if !strings.Contains(body, `{"success":true,"data":{"y":2}}`) {
		t.Errorf("result payload missing from stream: %q", body)
	}
	if strings.Contains(body, "user_id") {
		t.Errorf("envelope owner leaked into client stream: %q", body)
	}
}

func TestWaitForResult_RefusesPublishedResultForOtherUser(t *testing.T) {
	h, mr := newTestHub(t)
	pub := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = pub.Close() })

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.WaitForResult(context.Background(), rec, "job-2", "user-2")
	}()

	waitForSubscriber(t, pub, "sw:done:job-2")
	pub.Publish(context.Background(), "sw:done:job-2", storedEnvelope(t, "user-1", `{"success":true,"data":{"y":2}}`))
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, "event: error") || !strings.Contains(body, "not found") {
		t.Errorf("expected not-found error event: %q", body)
	}
	if strings.Contains(body, "event: result") {
		t.Errorf("result leaked to a non-owner: %q", body)
	}
}

// waitForSubscriber blocks until a subscriber is registered on the channel,
// so the subsequent Publish is guaranteed to be received.
func waitForSubscriber(t *testing.T, rdb *redis.Client, channel string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		n, err := rdb.PubSubNumSub(context.Background(), channel).Result()
		if err == nil && n[channel] >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for subscriber on %s", channel)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
