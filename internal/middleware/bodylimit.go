package middleware

import "net/http"

// BodyLimit bounds the request body of every request with http.MaxBytesReader.
// Once the limit is exceeded, further reads return *http.MaxBytesError (which
// handlers map to 413), so an arbitrarily large JSON body can never be read
// into memory. The limit applies uniformly — including to the direct
// json.NewDecoder call sites in the handlers and the reverse proxies — so a
// single misconfigured handler can't bypass it.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return BodyLimitWith(maxBytes, nil)
}

// BodyLimitWith is BodyLimit with a per-request override: when override
// returns a limit for a request (ok is true) that limit applies instead of
// maxBytes. Used for routes that legitimately take bigger bodies than the
// gateway-wide default.
func BodyLimitWith(maxBytes int64, override func(*http.Request) (limit int64, ok bool)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := maxBytes
			if override != nil {
				if l, ok := override(r); ok {
					limit = l
				}
			}
			if limit > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}
