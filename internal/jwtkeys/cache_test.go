package jwtkeys

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/swayrider/swlib/logger"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

const (
	modeOK = iota
	modeErr
	modeBlock
	modePanic
)

// fakeFetcher simulates authclient behavior: success, error, a call that
// blocks forever, or a panic.
type fakeFetcher struct {
	mu    sync.Mutex
	mode  int
	keys  []string
	err   error
	block chan struct{}
	calls int
}

func (f *fakeFetcher) PublicKeys() ([]string, error) {
	f.mu.Lock()
	f.calls++
	mode := f.mode
	block := f.block
	keys, err := f.keys, f.err
	f.mu.Unlock()

	switch mode {
	case modeErr:
		return nil, err
	case modeBlock:
		<-block
		return keys, nil
	case modePanic:
		panic("boom")
	default:
		return keys, nil
	}
}

func (f *fakeFetcher) set(mode int, keys []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
	f.keys = keys
	f.err = err
}

func newTestCache(f *fakeFetcher) *Cache {
	return New(f, 50*time.Millisecond, log.New())
}

func TestCache_RefreshSuccess(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modeOK, []string{"key-1"}, nil)
	c := newTestCache(f)
	c.Start(context.Background())

	keys := c.Keys()
	if len(keys) != 1 || keys[0] != "key-1" {
		t.Errorf("Keys() = %v, want [key-1]", keys)
	}
}

func TestCache_RefreshErrorKeepsKeysAndRecovers(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modeOK, []string{"key-1"}, nil)
	c := newTestCache(f)
	c.Start(context.Background())

	// A failed refresh must not clear the cached keys.
	f.set(modeErr, nil, errors.New("authservice down"))
	c.refresh()
	if keys := c.Keys(); len(keys) != 1 || keys[0] != "key-1" {
		t.Errorf("Keys() = %v, want cached [key-1] preserved", keys)
	}

	// A later successful refresh replaces them.
	f.set(modeOK, []string{"key-2"}, nil)
	c.refresh()
	if keys := c.Keys(); len(keys) != 1 || keys[0] != "key-2" {
		t.Errorf("Keys() = %v, want [key-2]", keys)
	}
}

func TestCache_StuckCallDoesNotBlockRefresh(t *testing.T) {
	f := &fakeFetcher{}
	blocked := make(chan struct{})
	f.mu.Lock()
	f.mode = modeBlock
	f.keys = []string{"key-1"}
	f.block = blocked
	f.mu.Unlock()

	c := newTestCache(f)
	start := time.Now()
	c.Start(context.Background()) // initial refresh must time out, not hang
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Start() blocked for %v; refresh timeout not honored", elapsed)
	}
	if keys := c.Keys(); len(keys) != 0 {
		t.Fatalf("Keys() = %v, want empty (fetch never completed)", keys)
	}

	// Unblock the stuck call; a later refresh must succeed.
	close(blocked)
	f.set(modeOK, []string{"key-2"}, nil)
	c.refresh()
	if keys := c.Keys(); len(keys) != 1 || keys[0] != "key-2" {
		t.Errorf("Keys() = %v, want [key-2] after recovery", keys)
	}
}

func TestCache_PanicInFetchDoesNotCrash(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modePanic, nil, nil)
	c := newTestCache(f)
	c.Start(context.Background()) // must return, not crash the process

	if keys := c.Keys(); len(keys) != 0 {
		t.Fatalf("Keys() = %v, want empty after panicking fetch", keys)
	}

	// A later successful refresh must work.
	f.set(modeOK, []string{"key-3"}, nil)
	c.refresh()
	if keys := c.Keys(); len(keys) != 1 || keys[0] != "key-3" {
		t.Errorf("Keys() = %v, want [key-3] after recovery", keys)
	}
}

func TestCache_StaleKeysAreReported(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modeOK, []string{"key-1"}, nil)
	c := newTestCache(f)
	c.Start(context.Background())

	// Simulate a long stall: last successful refresh was hours ago, and the
	// next refresh fails.
	c.mu.Lock()
	c.lastSuccess = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()
	f.set(modeErr, nil, errors.New("down"))
	c.refresh()

	c.mu.RLock()
	stale := c.staleLogged
	c.mu.RUnlock()
	if !stale {
		t.Errorf("stale keys were never reported")
	}

	// Recovery clears the flag.
	f.set(modeOK, []string{"key-2"}, nil)
	c.refresh()
	c.mu.RLock()
	stale = c.staleLogged
	c.mu.RUnlock()
	if stale {
		t.Errorf("stale flag not cleared after recovery")
	}
}