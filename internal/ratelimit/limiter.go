package ratelimit

import (
	"context"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Limiter struct {
	redis *redis.Client
}

func New(client *redis.Client) *Limiter {
	return &Limiter{redis: client}
}

// Allow checks whether the key is within limit requests per window.
// Returns true if the request is allowed, false if rate-limited.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	now := time.Now().UnixMilli()
	windowStart := now - window.Milliseconds()
	reqID := uuid.NewString()

	pipe := l.redis.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: reqID})
	countCmd := pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, window+time.Second)
	if _, err := pipe.Exec(ctx); err != nil {
		// On Redis error, allow the request (fail open).
		return true, err
	}
	return countCmd.Val() <= int64(limit), nil
}
