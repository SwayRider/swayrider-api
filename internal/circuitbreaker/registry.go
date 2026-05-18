package circuitbreaker

import (
	"time"

	"github.com/sony/gobreaker"
	log "github.com/swayrider/swlib/logger"
)

type Registry struct {
	breakers map[string]*gobreaker.CircuitBreaker
}

func New(services []string, l *log.Logger) *Registry {
	lg := l.Derive(log.WithComponent("circuitbreaker"))
	r := &Registry{breakers: make(map[string]*gobreaker.CircuitBreaker, len(services))}
	for _, name := range services {
		n := name
		r.breakers[n] = gobreaker.NewCircuitBreaker(gobreaker.Settings{
			Name:        n,
			MaxRequests: 1,
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				if counts.ConsecutiveFailures >= 5 {
					return true
				}
				if counts.Requests >= 10 {
					return counts.TotalFailures*100/counts.Requests > 50
				}
				return false
			},
			OnStateChange: func(name string, from, to gobreaker.State) {
				switch to {
				case gobreaker.StateOpen:
					lg.Warnf("circuit breaker %s opened (was %s)", name, from)
				case gobreaker.StateHalfOpen:
					lg.Infof("circuit breaker %s half-open, probing", name)
				case gobreaker.StateClosed:
					lg.Infof("circuit breaker %s closed (was %s)", name, from)
				}
			},
		})
	}
	return r
}

// Execute runs fn through the named circuit breaker.
// Returns gobreaker.ErrOpenState when the breaker is open.
func (r *Registry) Execute(service string, fn func() error) error {
	cb, ok := r.breakers[service]
	if !ok {
		return fn()
	}
	_, err := cb.Execute(func() (any, error) {
		return nil, fn()
	})
	return err
}
