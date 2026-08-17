package servicetoken

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
	mu         sync.Mutex
	mode       int
	token      string
	validUntil time.Time
	err        error
	block      chan struct{}
	calls      int
}

func (f *fakeFetcher) GetToken(clientId, clientSecret string, scopes []string) (string, []string, time.Time, error) {
	f.mu.Lock()
	f.calls++
	mode := f.mode
	block := f.block
	token, validUntil, err := f.token, f.validUntil, f.err
	f.mu.Unlock()

	switch mode {
	case modeErr:
		return "", nil, time.Time{}, err
	case modeBlock:
		<-block
		return token, nil, validUntil, nil
	case modePanic:
		panic("boom")
	default:
		return token, nil, validUntil, nil
	}
}

func (f *fakeFetcher) set(mode int, token string, validUntil time.Time, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
	f.token = token
	f.validUntil = validUntil
	f.err = err
}

func (f *fakeFetcher) numCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newTestManager(f *fakeFetcher) *Manager {
	m := New(f, "client-id", "client-secret", []string{"region:query"}, 50*time.Millisecond, log.New())
	m.retryDelay = 10 * time.Millisecond
	return m
}

func TestManager_RefreshSuccess(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modeOK, "tok-1", time.Now().Add(15*time.Minute), nil)
	m := newTestManager(f)
	m.Start(context.Background())

	if got := m.Token(); got != "tok-1" {
		t.Errorf("Token() = %q, want %q", got, "tok-1")
	}
}

func TestManager_RefreshErrorKeepsLoopAliveAndRecovers(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modeErr, "", time.Time{}, errors.New("authservice down"))
	m := newTestManager(f)
	m.Start(context.Background())

	if got := m.Token(); got != "" {
		t.Fatalf("Token() = %q, want empty after failed refresh", got)
	}

	// Switch to success; the loop must retry on its own and pick it up.
	f.set(modeOK, "tok-2", time.Now().Add(15*time.Minute), nil)
	deadline := time.Now().Add(2 * time.Second)
	for m.Token() != "tok-2" {
		if time.Now().After(deadline) {
			t.Fatalf("token never recovered after authservice came back")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManager_StuckCallDoesNotWedgeLoop(t *testing.T) {
	f := &fakeFetcher{}
	blocked := make(chan struct{})
	f.mu.Lock()
	f.mode = modeBlock
	f.token = "tok-1"
	f.validUntil = time.Now().Add(15 * time.Minute)
	f.block = blocked
	f.mu.Unlock()

	m := newTestManager(f)
	start := time.Now()
	m.Start(context.Background()) // initial refresh must time out, not hang
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Start() blocked for %v; refresh timeout not honored", elapsed)
	}
	if got := m.Token(); got != "" {
		t.Fatalf("Token() = %q, want empty (fetch never completed)", got)
	}

	// Unblock the stuck call; the loop must recover on the next retry.
	close(blocked)
	f.set(modeOK, "tok-2", time.Now().Add(15*time.Minute), nil)
	deadline := time.Now().Add(2 * time.Second)
	for m.Token() != "tok-2" {
		if time.Now().After(deadline) {
			t.Fatalf("token never recovered after stuck call unblocked")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManager_PanicInFetchDoesNotKillRefresh(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modePanic, "", time.Time{}, nil)
	m := newTestManager(f)
	m.Start(context.Background())

	if got := m.Token(); got != "" {
		t.Fatalf("Token() = %q, want empty after panicking fetch", got)
	}

	// The loop must still be alive and recover once the fetcher behaves.
	f.set(modeOK, "tok-3", time.Now().Add(15*time.Minute), nil)
	deadline := time.Now().Add(2 * time.Second)
	for m.Token() != "tok-3" {
		if time.Now().After(deadline) {
			t.Fatalf("token never recovered after panicking fetch")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManager_StaleTokenIsReported(t *testing.T) {
	f := &fakeFetcher{}
	// Token that is already past expiry; staleness must be flagged once
	// refresh starts failing.
	f.set(modeOK, "tok-1", time.Now().Add(-time.Minute), nil)
	m := newTestManager(f)
	m.Start(context.Background())

	f.set(modeErr, "", time.Time{}, errors.New("down"))
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.RLock()
		stale := m.staleLogged
		m.mu.RUnlock()
		if stale {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stale token was never reported")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManager_StaleFlagClearsOnRecovery(t *testing.T) {
	f := &fakeFetcher{}
	f.set(modeOK, "tok-1", time.Now().Add(-time.Minute), nil)
	m := newTestManager(f)
	m.Start(context.Background())

	f.set(modeErr, "", time.Time{}, errors.New("down"))
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.RLock()
		stale := m.staleLogged
		m.mu.RUnlock()
		if stale {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stale token was never reported")
		}
		time.Sleep(5 * time.Millisecond)
	}

	f.set(modeOK, "tok-2", time.Now().Add(15*time.Minute), nil)
	deadline = time.Now().Add(2 * time.Second)
	for {
		m.mu.RLock()
		token, stale := m.token, m.staleLogged
		m.mu.RUnlock()
		if token == "tok-2" && !stale {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("token did not recover and clear the stale flag")
		}
		time.Sleep(5 * time.Millisecond)
	}
}