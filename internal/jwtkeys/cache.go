package jwtkeys

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/jwt"
)

// PublicKeyFetcher is satisfied by *authclient.Client.
type PublicKeyFetcher interface {
	PublicKeys() ([]string, error)
}

type Cache struct {
	mu      sync.RWMutex
	keys    []string
	fetcher PublicKeyFetcher
	l       *log.Logger
}

func New(fetcher PublicKeyFetcher, l *log.Logger) *Cache {
	return &Cache{
		fetcher: fetcher,
		l:       l.Derive(log.WithComponent("jwtkeys")),
	}
}

func (c *Cache) Start(ctx context.Context) {
	c.refresh()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				c.refresh()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *Cache) refresh() {
	lg := c.l.Derive(log.WithFunction("refresh"))
	keys, err := c.fetcher.PublicKeys()
	if err != nil {
		lg.Warnf("failed to refresh public keys: %v", err)
		return
	}
	if len(keys) == 0 {
		lg.Warnln("authservice returned no public keys")
		return
	}
	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	lg.Infof("refreshed %d public key(s)", len(keys))
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
