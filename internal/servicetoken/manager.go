package servicetoken

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/swayrider/swlib/logger"
)

// TokenFetcher is satisfied by *authclient.Client.
type TokenFetcher interface {
	GetToken(clientId, clientSecret string, scopes []string) (accessToken string, grantedScopes []string, validUntil time.Time, err error)
}

type Manager struct {
	mu           sync.RWMutex
	token        string
	expiry       time.Time
	staleLogged  bool      // true once the expired token has been reported
	lastStaleLog time.Time // last time the stale-token error was logged (re-logged hourly)

	clientID     string
	clientSecret string
	scopes       []string
	fetcher      TokenFetcher
	l            *log.Logger

	// refreshTimeout hard-bounds a single refresh attempt so a stuck gRPC
	// call can never wedge the background loop.
	refreshTimeout time.Duration
	// retryDelay is how long to wait before retrying when the cached token is
	// near or past expiry. 30s in production; tests shorten it.
	retryDelay time.Duration
}

func New(fetcher TokenFetcher, clientID, clientSecret string, scopes []string, refreshTimeout time.Duration, l *log.Logger) *Manager {
	return &Manager{
		fetcher:        fetcher,
		clientID:       clientID,
		clientSecret:   clientSecret,
		scopes:         scopes,
		l:              l.Derive(log.WithComponent("servicetoken")),
		refreshTimeout: refreshTimeout,
		retryDelay:     30 * time.Second,
	}
}

func (m *Manager) Start(ctx context.Context) {
	m.refresh()
	go m.run(ctx)
}

// run is the refresh loop. If it ever dies (panic), it is relaunched after a
// short delay so a single panic cannot permanently kill token refresh.
func (m *Manager) run(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			m.l.Errorf("service token refresh loop panicked, restarting: %v", r)
			time.Sleep(m.retryDelay)
			if ctx.Err() == nil {
				go m.run(ctx)
			}
		}
	}()

	for {
		m.mu.RLock()
		expiry := m.expiry
		m.mu.RUnlock()

		// Zero expiry means no token has ever been fetched — retry quickly.
		// time.Until on the zero time would overflow int64 into a huge
		// positive duration, silently stalling the loop forever.
		ttl := m.retryDelay
		if !expiry.IsZero() {
			if until := time.Until(expiry) - 3*time.Minute; until > 0 {
				ttl = until
			}
		}

		select {
		case <-time.After(ttl):
			m.refresh()
		case <-ctx.Done():
			return
		}
	}
}

type tokenResult struct {
	token      string
	validUntil time.Time
	err        error
}

// refresh fetches a new token. The fetch runs in a child goroutine and is
// abandoned if it exceeds refreshTimeout, so a stuck call can't block the
// loop: the next tick simply retries. A panic inside the fetch is converted
// into an error instead of crashing the process.
func (m *Manager) refresh() {
	lg := m.l.Derive(log.WithFunction("refresh"))

	ch := make(chan tokenResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- tokenResult{err: fmt.Errorf("panic in token fetch: %v", r)}
			}
		}()
		token, _, validUntil, err := m.fetcher.GetToken(m.clientID, m.clientSecret, m.scopes)
		ch <- tokenResult{token: token, validUntil: validUntil, err: err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			lg.Errorf("failed to refresh service token: %v", res.err)
			m.noteStale()
			return
		}
		m.mu.Lock()
		m.token = res.token
		m.expiry = res.validUntil
		m.staleLogged = false
		m.mu.Unlock()
		lg.Infof("service token refreshed, expires at %s", res.validUntil.UTC().Format(time.RFC3339))
	case <-time.After(m.refreshTimeout):
		lg.Warnf("service token refresh timed out after %s; will retry", m.refreshTimeout)
		m.noteStale()
	}
}

// noteStale reports (once per stale episode, re-logged hourly) that the cached
// token has passed its expiry while refresh keeps failing. This is the stall
// that used to be completely silent.
func (m *Manager) noteStale() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !time.Now().After(m.expiry) {
		return
	}
	now := time.Now()
	if !m.staleLogged || now.Sub(m.lastStaleLog) >= time.Hour {
		m.staleLogged = true
		m.lastStaleLog = now
		m.l.Errorf("service token expired at %s and refresh keeps failing; downstream calls are failing until it recovers", m.expiry.UTC().Format(time.RFC3339))
	}
}

// Token returns the current cached service client token.
func (m *Manager) Token() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.token
}