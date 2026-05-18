package middleware

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swlib/security"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Logging logs every HTTP request: method, path, status, duration, IP, and user ID (if authenticated).
// Must be placed inside the Auth middleware so that claims are available in context.
func Logging(l *log.Logger) func(http.Handler) http.Handler {
	lg := l.Derive(log.WithComponent("http"))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			ctx := r.Context()
			userID := "-"
			if claims, ok := security.GetClaims(ctx); ok && claims != nil {
				userID = claims.Subject
			}
			ip, _ := security.GetOrigIp(ctx)

			lg.Infof("%s %s %d %s ip=%s user=%s",
				r.Method, r.URL.Path, rec.status,
				fmt.Sprintf("%dms", time.Since(start).Milliseconds()),
				ip, userID,
			)
		})
	}
}
