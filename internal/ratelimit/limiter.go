package ratelimit

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	log "github.com/swayrider/swlib/logger"
)

// ErrDegraded is returned by Allow when the limiter is in deny mode and Redis
// is unavailable. Callers should treat it as a hard denial.
var ErrDegraded = errors.New("rate limiter degraded: redis unavailable")

// Degrade modes.
const (
	DegradeModeMemory = "memory" // fall back to an in-process limiter (default)
	DegradeModeDeny   = "deny"   // deny all requests while Redis is down
)

// pipeline is the subset of redis.Pipeliner the limiter uses.
type pipeline interface {
	Exec(ctx context.Context) ([]redis.Cmder, error)
	ZRemRangeByScore(ctx context.Context, key, min, max string) *redis.IntCmd
	ZAdd(ctx context.Context, key string, members ...redis.Z) *redis.IntCmd
	ZCard(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
}

// redisClient is the subset of *redis.Client the limiter needs. A narrow
// interface keeps the degradation logic testable with a fake.
type redisClient interface {
	Pipeline() pipeline
	Ping(ctx context.Context) *redis.StatusCmd
}

// clientAdapter narrows *redis.Client to the interface above.
type clientAdapter struct{ c *redis.Client }

func (a *clientAdapter) Pipeline() pipeline { return a.c.Pipeline() }

func (a *clientAdapter) Ping(ctx context.Context) *redis.StatusCmd { return a.c.Ping(ctx) }

// Options configures the limiter's Redis-degradation behavior.
type Options struct {
	DegradeMode      string        // DegradeModeMemory (default) or DegradeModeDeny
	DegradeThreshold int           // consecutive Redis failures before degrading (default 3)
	ProbeInterval    time.Duration // how often to probe Redis while degraded (default 15s)
	MaxMemoryKeys    int           // fallback keyspace cap (default 100k)
	Logger           *log.Logger
}

// Limiter enforces sliding-window rate limits backed by Redis. When Redis
// becomes unavailable it degrades instead of silently disabling throttling:
//   - memory mode (default): requests are limited against an in-process window
//     with the same limits, and Redis is probed periodically for recovery;
//   - deny mode: every limited request is denied (ErrDegraded) until Redis
//     recovers.
type Limiter struct {
	redis         redisClient
	fallback      *memoryLimiter
	mode          string
	threshold     int
	probeInterval time.Duration
	lg            *log.Logger

	mu                  sync.Mutex
	consecutiveFailures int
	degraded            bool
	lastProbe           time.Time
}

// New builds a limiter over a Redis client with the given options.
func New(client *redis.Client, opts Options) *Limiter {
	return newLimiter(&clientAdapter{c: client}, opts)
}

func newLimiter(rc redisClient, opts Options) *Limiter {
	mode := opts.DegradeMode
	if mode != DegradeModeDeny {
		mode = DegradeModeMemory
	}
	threshold := opts.DegradeThreshold
	if threshold <= 0 {
		threshold = 3
	}
	interval := opts.ProbeInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	lg := opts.Logger
	if lg == nil {
		lg = log.New()
	}
	lg = lg.Derive(log.WithComponent("ratelimit"))

	return &Limiter{
		redis:         rc,
		fallback:      NewMemory(opts.MaxMemoryKeys),
		mode:          mode,
		threshold:     threshold,
		probeInterval: interval,
		lg:            lg,
	}
}

// Allow checks whether the key is within limit requests per window.
// Returns true if the request is allowed, false if rate-limited.
// It never fails open indefinitely: a Redis outage degrades the limiter (see
// the type comment) rather than disabling throttling for every request.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if l.isDegraded() {
		return l.degradedAllow(ctx, key, limit, window)
	}
	return l.redisAllow(ctx, key, limit, window)
}

func (l *Limiter) isDegraded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.degraded
}

func (l *Limiter) redisAllow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	now := time.Now().UnixMilli()
	windowStart := now - window.Milliseconds()
	reqID := uuid.NewString()

	pipe := l.redis.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: reqID})
	countCmd := pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, window+time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		return l.onRedisError(ctx, key, limit, window)
	}
	return countCmd.Val() <= int64(limit), nil
}

// onRedisError counts consecutive Redis failures and, once the threshold is
// reached, puts the limiter into degraded mode. Below the threshold the
// current request fails open (a transient blip shouldn't deny traffic).
func (l *Limiter) onRedisError(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	l.mu.Lock()
	l.consecutiveFailures++
	degraded := l.consecutiveFailures >= l.threshold
	if degraded {
		l.degraded = true
		l.consecutiveFailures = 0
	}
	l.mu.Unlock()

	if !degraded {
		return true, nil
	}

	l.lg.Warnf("rate limiter degraded after %d consecutive redis failures (mode=%s)", l.threshold, l.mode)
	return l.degradedAllow(ctx, key, limit, window)
}

// degradedAllow serves the request while Redis is down: probe for recovery on
// the configured interval, then either deny (deny mode) or fall back to the
// in-process limiter (memory mode).
func (l *Limiter) degradedAllow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if l.tryProbe(ctx) {
		return l.redisAllow(ctx, key, limit, window)
	}
	if l.mode == DegradeModeDeny {
		return false, ErrDegraded
	}
	return l.fallback.Allow(ctx, key, limit, window)
}

// tryProbe attempts a Redis ping at most once per probeInterval. On success it
// marks the limiter healthy again and returns true. The ping runs outside the
// mutex so a slow Redis never blocks concurrent Allow calls.
func (l *Limiter) tryProbe(ctx context.Context) bool {
	l.mu.Lock()
	if time.Since(l.lastProbe) < l.probeInterval {
		l.mu.Unlock()
		return false
	}
	l.lastProbe = time.Now()
	l.mu.Unlock()

	if err := l.redis.Ping(ctx).Err(); err != nil {
		return false
	}

	l.mu.Lock()
	l.degraded = false
	l.consecutiveFailures = 0
	l.mu.Unlock()
	l.lg.Warnf("rate limiter recovered, redis reachable again")
	return true
}
