package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ProcessFn processes a decoded job and returns JSON-encoded result data.
type ProcessFn func(ctx context.Context, job Job) (json.RawMessage, error)

// WorkerConfig configures a WorkerPool.
type WorkerConfig struct {
	Redis     *redis.Client
	Stream    string
	Count     int
	Process   ProcessFn
	ResultTTL time.Duration
}

// WorkerPool drains a Redis Stream with a fixed number of goroutines.
type WorkerPool struct {
	cfg WorkerConfig
}

func NewWorkerPool(cfg WorkerConfig) *WorkerPool {
	return &WorkerPool{cfg: cfg}
}

// Start launches the worker goroutines. They run until ctx is cancelled.
func (wp *WorkerPool) Start(ctx context.Context) {
	for i := 0; i < wp.cfg.Count; i++ {
		go wp.runWorker(ctx, fmt.Sprintf("worker-%d", i))
	}
}

func (wp *WorkerPool) runWorker(ctx context.Context, workerID string) {
	for {
		if ctx.Err() != nil {
			return
		}
		msgs, err := wp.cfg.Redis.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    GroupName,
			Consumer: workerID,
			Streams:  []string{wp.cfg.Stream, ">"},
			Count:    1,
			Block:    5 * time.Second,
		}).Result()
		if err != nil {
			// redis.Nil means BLOCK timeout — no messages available
			continue
		}
		if len(msgs) == 0 || len(msgs[0].Messages) == 0 {
			continue
		}
		for _, msg := range msgs[0].Messages {
			wp.processMessage(ctx, msg)
		}
	}
}

func (wp *WorkerPool) processMessage(ctx context.Context, msg redis.XMessage) {
	// Always ACK, even on error, so the message isn't re-delivered forever.
	defer wp.cfg.Redis.XAck(ctx, wp.cfg.Stream, GroupName, msg.ID)

	job := parseJob(msg.Values)

	var result JobResult
	data, err := wp.cfg.Process(ctx, job)
	if err != nil {
		result = JobResult{
			Success: false,
			Error:   GrpcErrToJobError(err),
		}
	} else {
		result = JobResult{
			Success: true,
			Data:    data,
		}
	}

	payload, _ := json.Marshal(result)
	payloadStr := string(payload)
	wp.cfg.Redis.Set(ctx, "sw:result:"+job.JobID, payloadStr, wp.cfg.ResultTTL)
	wp.cfg.Redis.Publish(ctx, "sw:done:"+job.JobID, payloadStr)
}
