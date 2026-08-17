package ratelimit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakePipeline simulates a Redis pipeline that can fail.
type fakePipeline struct {
	mu     sync.Mutex
	execOK bool
	count  int64
}

func (p *fakePipeline) Exec(ctx context.Context) ([]redis.Cmder, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.execOK {
		return nil, errors.New("connection refused")
	}
	return nil, nil
}

func (p *fakePipeline) ZRemRangeByScore(ctx context.Context, key, min, max string) *redis.IntCmd {
	return redis.NewIntResult(0, nil)
}

func (p *fakePipeline) ZAdd(ctx context.Context, key string, members ...redis.Z) *redis.IntCmd {
	return redis.NewIntResult(1, nil)
}

func (p *fakePipeline) ZCard(ctx context.Context, key string) *redis.IntCmd {
	p.mu.Lock()
	defer p.mu.Unlock()
	return redis.NewIntResult(p.count, nil)
}

func (p *fakePipeline) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	return redis.NewBoolResult(true, nil)
}

// fakeRedis simulates a Redis client whose pipeline may be down.
type fakeRedis struct {
	pipe *fakePipeline
	up   bool
}

func (f *fakeRedis) Pipeline() pipeline { return f.pipe }

func (f *fakeRedis) Ping(ctx context.Context) *redis.StatusCmd {
	if f.up {
		return redis.NewStatusResult("PONG", nil)
	}
	return redis.NewStatusResult("", errors.New("connection refused"))
}

// newTestLimiter builds a limiter over the fake Redis with defaults that make
// degrade/probe behavior deterministic.
func newTestLimiter(fr *fakeRedis) *Limiter {
	return newLimiter(fr, Options{
		DegradeMode:      DegradeModeMemory,
		DegradeThreshold: 2,
		ProbeInterval:    time.Hour, // never auto-probe within a test
	})
}

func TestAllowUsesRedisWhenHealthy(t *testing.T) {
	fr := &fakeRedis{pipe: &fakePipeline{execOK: true, count: 0}, up: true}
	l := newTestLimiter(fr)

	ok, err := l.Allow(context.Background(), "k", 5, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allowed under limit")
	}
	if l.isDegraded() {
		t.Fatal("limiter should not be degraded on success")
	}
}

func TestDegradesAfterThresholdAndServesFromFallback(t *testing.T) {
	fr := &fakeRedis{pipe: &fakePipeline{execOK: false}, up: false}
	l := newTestLimiter(fr)

	// First failure: below threshold, fails open.
	ok, err := l.Allow(context.Background(), "k", 5, time.Minute)
	if err != nil {
		t.Fatalf("below threshold: unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("below threshold should fail open")
	}
	if l.isDegraded() {
		t.Fatal("should not degrade before threshold")
	}

	// Second failure: hits threshold, degrades, falls back to memory.
	ok, err = l.Allow(context.Background(), "k", 5, time.Minute)
	if err != nil {
		t.Fatalf("degrade transition: unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("first fallback request should be allowed")
	}
	if !l.isDegraded() {
		t.Fatal("limiter should be degraded after threshold")
	}

	// Fallback enforces limits per key.
	for i := 0; i < 4; i++ {
		if ok, _ := l.Allow(context.Background(), "k", 5, time.Minute); !ok {
			t.Fatalf("fallback request %d: expected allowed", i)
		}
	}
	if ok, _ := l.Allow(context.Background(), "k", 5, time.Minute); ok {
		t.Fatal("expected denied once fallback limit is reached")
	}
}

func TestDenyModeFailsClosed(t *testing.T) {
	fr := &fakeRedis{pipe: &fakePipeline{execOK: false}, up: false}
	l := newLimiter(fr, Options{
		DegradeMode:      DegradeModeDeny,
		DegradeThreshold: 1,
		ProbeInterval:    time.Hour,
	})

	_, err := l.Allow(context.Background(), "k", 5, time.Minute)
	if !errors.Is(err, ErrDegraded) {
		t.Fatalf("expected ErrDegraded, got %v", err)
	}
	if !l.isDegraded() {
		t.Fatal("limiter should be degraded in deny mode after failure")
	}
}

func TestRecoversWhenRedisComesBack(t *testing.T) {
	fr := &fakeRedis{pipe: &fakePipeline{execOK: false}, up: false}
	l := newLimiter(fr, Options{
		DegradeMode:      DegradeModeMemory,
		DegradeThreshold: 1,
		ProbeInterval:    time.Millisecond,
	})

	// Degrade immediately.
	if _, err := l.Allow(context.Background(), "k", 5, time.Minute); err != nil {
		t.Fatalf("degrade: unexpected error: %v", err)
	}
	if !l.isDegraded() {
		t.Fatal("expected degraded")
	}

	// Redis comes back; wait for the probe interval to elapse.
	fr.pipe.execOK = true
	fr.up = true
	time.Sleep(5 * time.Millisecond)

	// Next Allow probes and recovers, then uses Redis.
	ok, err := l.Allow(context.Background(), "k", 5, time.Minute)
	if err != nil {
		t.Fatalf("recovery: unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected allowed after recovery")
	}
	if l.isDegraded() {
		t.Fatal("limiter should be healthy after successful probe")
	}
}

func TestProbeGatedByInterval(t *testing.T) {
	fr := &fakeRedis{pipe: &fakePipeline{execOK: false}, up: false}
	l := newLimiter(fr, Options{
		DegradeMode:      DegradeModeMemory,
		DegradeThreshold: 1,
		ProbeInterval:    time.Hour, // no probe within test duration
	})

	if _, err := l.Allow(context.Background(), "k", 5, time.Minute); err != nil {
		t.Fatalf("degrade: unexpected error: %v", err)
	}

	// Redis comes back but the probe interval hasn't elapsed — still degraded.
	fr.pipe.execOK = true
	fr.up = true

	if ok, _ := l.Allow(context.Background(), "k", 5, time.Minute); !ok {
		t.Fatal("fallback should serve the request while waiting for probe")
	}
	if !l.isDegraded() {
		t.Fatal("should remain degraded until probe interval elapses")
	}
}
