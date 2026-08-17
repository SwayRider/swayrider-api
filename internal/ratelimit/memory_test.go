package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryAllowWithinLimit(t *testing.T) {
	m := NewMemory(100)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		ok, err := m.Allow(ctx, "rl:auth:ip:1.2.3.4", 5, time.Minute)
		if err != nil {
			t.Fatalf("Allow #%d: unexpected error: %v", i, err)
		}
		if !ok {
			t.Fatalf("Allow #%d: expected allowed, got denied", i)
		}
	}
}

func TestMemoryDeniesOverLimit(t *testing.T) {
	m := NewMemory(100)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if ok, _ := m.Allow(ctx, "k", 3, time.Minute); !ok {
			t.Fatalf("Allow #%d: expected allowed", i)
		}
	}
	ok, err := m.Allow(ctx, "k", 3, time.Minute)
	if err != nil {
		t.Fatalf("Allow: unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected denied over limit")
	}
}

func TestMemoryWindowSlides(t *testing.T) {
	m := NewMemory(100)
	ctx := context.Background()
	window := 30 * time.Millisecond

	if ok, _ := m.Allow(ctx, "k", 1, window); !ok {
		t.Fatal("first request should be allowed")
	}
	if ok, _ := m.Allow(ctx, "k", 1, window); ok {
		t.Fatal("second request inside window should be denied")
	}

	time.Sleep(window + 20*time.Millisecond)
	if ok, _ := m.Allow(ctx, "k", 1, window); !ok {
		t.Fatal("request after window elapsed should be allowed again")
	}
}

func TestMemoryDistinctKeysIndependent(t *testing.T) {
	m := NewMemory(100)
	ctx := context.Background()

	// First request to key A is allowed (limit 1); the rest are denied.
	if ok, _ := m.Allow(ctx, "rl:auth:ip:1.2.3.4", 1, time.Minute); !ok {
		t.Fatal("key A first request: expected allowed")
	}
	for i := 0; i < 4; i++ {
		if ok, _ := m.Allow(ctx, "rl:auth:ip:1.2.3.4", 1, time.Minute); ok {
			t.Fatalf("key A request #%d: expected denied after first", i+1)
		}
	}
	if ok, _ := m.Allow(ctx, "rl:auth:ip:5.6.7.8", 1, time.Minute); !ok {
		t.Fatal("distinct key should have its own window")
	}
}

func TestMemoryEvictsOldestWhenFull(t *testing.T) {
	m := NewMemory(2)
	ctx := context.Background()

	// Sleep between touches so lastTouch timestamps are distinct and the LRU
	// eviction is deterministic (millisecond clock granularity otherwise ties).
	if ok, _ := m.Allow(ctx, "a", 1, time.Minute); !ok {
		t.Fatal("key a first: expected allowed")
	}
	time.Sleep(2 * time.Millisecond)
	if ok, _ := m.Allow(ctx, "b", 1, time.Minute); !ok {
		t.Fatal("key b first: expected allowed")
	}
	time.Sleep(2 * time.Millisecond)
	if ok, _ := m.Allow(ctx, "a", 1, time.Minute); ok {
		t.Fatal("key a second: expected denied (limit 1)")
	}

	// Keyspace is full (2 keys); inserting "c" evicts the least-recently-used
	// key ("b", touched before "a" was re-touched).
	if ok, _ := m.Allow(ctx, "c", 1, time.Minute); !ok {
		t.Fatal("key c: expected allowed after eviction")
	}

	if got := len(m.keys); got != 2 {
		t.Fatalf("keyspace size = %d, want 2", got)
	}

	// "b" was evicted, so it starts a fresh window.
	if ok, _ := m.Allow(ctx, "b", 1, time.Minute); !ok {
		t.Fatal("evicted key should have a fresh window")
	}
}
