package ratelimit

import (
	"context"
	"sync"
	"time"
)

// memoryLimiter is a purely in-process sliding-window rate limiter used as a
// fallback while Redis is unavailable. It mirrors the Redis pipeline semantics
// (prune entries older than the window, count what remains, expire idle keys)
// so that the security boundary keeps working — at reduced, per-instance
// fidelity — during an outage.
//
// It is NOT a replacement for the Redis limiter: state is per-process, so in a
// multi-replica deployment the effective limits multiply by the replica count
// while degraded. The Redis path remains the single source of truth when healthy.
type memoryLimiter struct {
	mu   sync.Mutex
	keys map[string]*memoryWindow

	maxKeys int // hard cap on distinct keys; oldest entries evicted when exceeded
}

// memoryWindow is the state for a single rate-limit key: the timestamps of
// recent requests plus the last time the key was touched (for idle eviction).
type memoryWindow struct {
	times     []int64 // request timestamps (ms), oldest first
	lastTouch int64   // ms since epoch of the last access
}

// NewMemory returns a fallback limiter that tracks at most maxKeys distinct
// keys before evicting the oldest entries.
func NewMemory(maxKeys int) *memoryLimiter {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &memoryLimiter{
		keys:    make(map[string]*memoryWindow),
		maxKeys: maxKeys,
	}
}

// Allow records the request for key and reports whether it stays within limit
// requests per window. It never returns an error — on a full keyspace it
// evicts rather than fails.
func (m *memoryLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	now := time.Now().UnixMilli()
	windowStart := now - window.Milliseconds()

	m.mu.Lock()
	defer m.mu.Unlock()

	w, ok := m.keys[key]
	if !ok {
		if len(m.keys) >= m.maxKeys {
			m.evictOldest()
		}
		w = &memoryWindow{lastTouch: now}
		m.keys[key] = w
	}

	// Prune entries outside the window and append the new request.
	kept := w.times[:0]
	for _, ts := range w.times {
		if ts >= windowStart {
			kept = append(kept, ts)
		}
	}
	w.times = append(kept, now)
	w.lastTouch = now

	return int64(len(w.times)) <= int64(limit), nil
}

// evictOldest removes the single least-recently-used key. Called while m.mu
// is held, with a keyspace at capacity.
func (m *memoryLimiter) evictOldest() {
	var victim string
	var oldest int64
	first := true
	for k, w := range m.keys {
		if first || w.lastTouch < oldest {
			first = false
			victim = k
			oldest = w.lastTouch
		}
	}
	if victim != "" {
		delete(m.keys, victim)
	}
}
