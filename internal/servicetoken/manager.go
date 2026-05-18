package servicetoken

import (
	"context"
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
	clientID     string
	clientSecret string
	scopes       []string
	fetcher      TokenFetcher
	l            *log.Logger
}

func New(fetcher TokenFetcher, clientID, clientSecret string, scopes []string, l *log.Logger) *Manager {
	return &Manager{
		fetcher:      fetcher,
		clientID:     clientID,
		clientSecret: clientSecret,
		scopes:       scopes,
		l:            l.Derive(log.WithComponent("servicetoken")),
	}
}

func (m *Manager) Start(ctx context.Context) {
	m.refresh()
	go func() {
		for {
			m.mu.RLock()
			ttl := time.Until(m.expiry) - 3*time.Minute
			m.mu.RUnlock()
			if ttl < 0 {
				ttl = 30 * time.Second
			}
			select {
			case <-time.After(ttl):
				m.refresh()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (m *Manager) refresh() {
	lg := m.l.Derive(log.WithFunction("refresh"))
	token, _, validUntil, err := m.fetcher.GetToken(m.clientID, m.clientSecret, m.scopes)
	if err != nil {
		lg.Errorf("failed to refresh service token: %v", err)
		return
	}
	m.mu.Lock()
	m.token = token
	m.expiry = validUntil
	m.mu.Unlock()
	lg.Infof("service token refreshed, expires at %s", validUntil.UTC().Format(time.RFC3339))
}

// Token returns the current cached service client token.
func (m *Manager) Token() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.token
}
