package queue

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	StreamRouting = "sw:jobs:routing"
	StreamSearch  = "sw:jobs:search"
	GroupName     = "workers"
)

// ErrQueueFull is returned when the stream has reached its depth limit.
var ErrQueueFull = errors.New("queue full")

// Producer enqueues jobs onto Redis Streams.
type Producer struct {
	redis    *redis.Client
	maxDepth int64
}

func NewProducer(rdb *redis.Client, maxDepth int) *Producer {
	return &Producer{redis: rdb, maxDepth: int64(maxDepth)}
}

// Bootstrap creates the consumer groups (and streams) if they don't exist yet.
// BUSYGROUP errors are silently ignored.
func (p *Producer) Bootstrap(ctx context.Context) {
	for _, stream := range []string{StreamRouting, StreamSearch} {
		p.redis.XGroupCreateMkStream(ctx, stream, GroupName, "0")
	}
}

// Enqueue adds a job to the named stream and returns the assigned job ID.
// Returns ErrQueueFull when the stream has reached maxDepth.
func (p *Producer) Enqueue(ctx context.Context, stream string, job Job) (string, error) {
	depth, err := p.redis.XLen(ctx, stream).Result()
	if err != nil {
		return "", err
	}
	if depth >= p.maxDepth {
		return "", ErrQueueFull
	}

	jobID := uuid.NewString()
	_, err = p.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: stream,
		Values: map[string]any{
			"job_id":        jobID,
			"payload":       job.Payload,
			"user_id":       job.UserID,
			"account_level": job.AccountLevel,
			"is_admin":      job.IsAdmin,
			"user_verified": job.UserVerified,
			"enqueued_at":   strconv.FormatInt(time.Now().UnixMilli(), 10),
		},
	}).Result()
	return jobID, err
}

// QueueDepth returns the current number of messages in the stream.
func (p *Producer) QueueDepth(ctx context.Context, stream string) (int64, error) {
	return p.redis.XLen(ctx, stream).Result()
}
