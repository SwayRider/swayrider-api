package jwtkeys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/jwt"
)

// PublicKeyFetcher is satisfied by *authclient.Client.
type PublicKeyFetcher interface {
	PublicKeys() ([]string, error)
}

const refreshInterval = time.Hour

type Cache struct {
	mu           sync.RWMutex
	keys         []string
	lastSuccess  time.Time
	staleLogged  bool      // true once the long-stale keys have been reported
	lastStaleLog time.Time // last time the stale error was logged (re-logged hourly)

	fetcher PublicKeyFetcher
	l       *log.Logger

	// refreshTimeout hard-bounds a single key fetch so a stuck gRPC call can't
	// wedge the background refresh loop.
	refreshTimeout time.Duration
}

func New(fetcher PublicKeyFetcher, refreshTimeout time.Duration, l *log.Logger) *Cache {
	return &Cache{
		fetcher:        fetcher,
		l:              l.Derive(log.WithComponent("jwtkeys")),
		refreshTimeout: refreshTimeout,
	}
}

func (c *Cache) Start(ctx context.Context) {
	c.refresh()
	go c.run(ctx)
}

// run is the refresh loop. If it ever dies (panic), it is relaunched after a
// short delay so a single panic cannot permanently kill key refresh.
func (c *Cache) run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			c.l.Errorf("public key refresh loop panicked, restarting: %v", r)
			time.Sleep(time.Minute)
			if ctx.Err() == nil {
				go c.run(ctx)
			}
		}
	}()

	t := time.NewTicker(refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.refresh()
		case <-ctx.Done():
			return
		}
	}
}

type keysResult struct {
	keys []string
	err  error
}

// refresh fetches the public keys. The fetch runs in a child goroutine and is
// abandoned if it exceeds refreshTimeout, so a stuck call can't block the
// loop: the next tick simply retries. A panic inside the fetch is converted
// into an error instead of crashing the process.
func (c *Cache) refresh() {
	lg := c.l.Derive(log.WithFunction("refresh"))

	ch := make(chan keysResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- keysResult{err: fmt.Errorf("panic in public key fetch: %v", r)}
			}
		}()
		keys, err := c.fetcher.PublicKeys()
		ch <- keysResult{keys: keys, err: err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			lg.Warnf("failed to refresh public keys: %v", res.err)
			c.noteStale()
			return
		}
		if len(res.keys) == 0 {
			lg.Warnln("authservice returned no public keys")
			c.noteStale()
			return
		}
		c.mu.Lock()
		c.keys = res.keys
		c.lastSuccess = time.Now()
		c.staleLogged = false
		c.mu.Unlock()
		lg.Infof("refreshed %d public key(s)", len(res.keys))
	case <-time.After(c.refreshTimeout):
		lg.Warnf("public key refresh timed out after %s; will retry", c.refreshTimeout)
		c.noteStale()
	}
}

// noteStale reports (once per stale episode, re-logged hourly) that public
// keys have not refreshed successfully for longer than the refresh interval.
// This is the stall that used to be completely silent.
func (c *Cache) noteStale() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.lastSuccess.IsZero() && time.Since(c.lastSuccess) < refreshInterval {
		return
	}
	now := time.Now()
	if !c.staleLogged || now.Sub(c.lastStaleLog) >= time.Hour {
		c.staleLogged = true
		c.lastStaleLog = now
		c.l.Errorf("public keys have not refreshed successfully for over an hour; JWT verification may fail until it recovers")
	}
}

// Keys returns a snapshot of the current public keys (PEM-encoded).
func (c *Cache) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, len(c.keys))
	copy(out, c.keys)
	return out
}

// Verify tries each cached key until one validates the token.
func (c *Cache) Verify(token string) (*jwt.Claims, error) {
	c.mu.RLock()
	keys := make([]string, len(c.keys))
	copy(keys, c.keys)
	c.mu.RUnlock()

	if len(keys) == 0 {
		return nil, errors.New("no public keys available")
	}
	var lastErr error
	for _, key := range keys {
		claims, err := jwt.VerifyToken(token, key, jwt.VerifyDefault)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	return nil, lastErr
}