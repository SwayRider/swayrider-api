package jwtkeys

import (
	"context"
	"errors"
	"sync"
	"time"

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
}

func New(fetcher PublicKeyFetcher) *Cache {
	return &Cache{fetcher: fetcher}
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
	keys, err := c.fetcher.PublicKeys()
	if err != nil || len(keys) == 0 {
		return
	}
	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
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
