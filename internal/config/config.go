package config

import (
	"time"

	"github.com/swayrider/swlib/env"
)

type Config struct {
	HTTPPort int
	LogLevel string

	AuthServiceHost   string
	AuthServicePort   int
	RouterServiceHost string
	RouterServicePort int
	SearchServiceHost string
	SearchServicePort int
	RegionServiceHost string
	RegionServicePort int
	TilesServiceHost  string
	TilesServicePort  int

	RedisHost string
	RedisPort int

	ClientID     string
	ClientSecret string

	RouteWorkerCount  int
	SearchWorkerCount int
	QueueMaxDepth     int
	ResultTTLSeconds  int

	RateLimitIPAuth        int
	RateLimitIPPublic      int
	RateLimitIPAPI         int
	RateLimitUserAPI       int
	RateLimitUserExpensive int

	// Rate limit Redis-degradation behavior.
	RateLimitDegradeMode      string // "memory" (default) or "deny"
	RateLimitDegradeThreshold int    // consecutive Redis failures before degrading
	RateLimitProbeSeconds     int    // how often to probe Redis while degraded

	CORSAllowedOrigins []string

	// TrustedProxies lists the CIDRs of reverse proxies (e.g. Traefik) whose
	// X-Forwarded-For / X-Forwarded-Proto headers are honored. Empty (the
	// default) means no proxy headers are trusted — only RemoteAddr is used.
	TrustedProxies []string

	CookieNamespace string

	// ServiceTokenRefreshTimeout hard-bounds a single service-token refresh
	// attempt so a stuck gRPC call can never wedge the background refresh
	// loop (and with it every downstream call).
	ServiceTokenRefreshTimeout time.Duration

	// JWTKeysRefreshTimeout hard-bounds a single public-key fetch for the
	// same reason.
	JWTKeysRefreshTimeout time.Duration
}

func Load() *Config {
	return &Config{
		HTTPPort: env.GetAsInt("HTTP_PORT", 8080),
		LogLevel: env.Get("LOG_LEVEL", "info"),

		AuthServiceHost:   env.Get("AUTHSERVICE_HOST", "localhost"),
		AuthServicePort:   env.GetAsInt("AUTHSERVICE_PORT", 8081),
		RouterServiceHost: env.Get("ROUTERSERVICE_HOST", "localhost"),
		RouterServicePort: env.GetAsInt("ROUTERSERVICE_PORT", 8081),
		SearchServiceHost: env.Get("SEARCHSERVICE_HOST", "localhost"),
		SearchServicePort: env.GetAsInt("SEARCHSERVICE_PORT", 8081),
		RegionServiceHost: env.Get("REGIONSERVICE_HOST", "localhost"),
		RegionServicePort: env.GetAsInt("REGIONSERVICE_PORT", 8081),
		TilesServiceHost:  env.Get("TILESSERVICE_HOST", "localhost"),
		TilesServicePort:  env.GetAsInt("TILESSERVICE_PORT", 8080),

		RedisHost: env.Get("REDIS_HOST", "localhost"),
		RedisPort: env.GetAsInt("REDIS_PORT", 6379),

		ClientID:     env.Get("SWAYRIDER_API_CLIENT_ID", ""),
		ClientSecret: env.Get("SWAYRIDER_API_CLIENT_SECRET", ""),

		RouteWorkerCount:  env.GetAsInt("ROUTE_WORKER_COUNT", 5),
		SearchWorkerCount: env.GetAsInt("SEARCH_WORKER_COUNT", 10),
		QueueMaxDepth:     env.GetAsInt("QUEUE_MAX_DEPTH", 500),
		ResultTTLSeconds:  env.GetAsInt("RESULT_TTL_SECONDS", 300),

		RateLimitIPAuth:        env.GetAsInt("RATE_LIMIT_IP_AUTH", 10),
		RateLimitIPPublic:      env.GetAsInt("RATE_LIMIT_IP_PUBLIC", 600),
		RateLimitIPAPI:         env.GetAsInt("RATE_LIMIT_IP_API", 60),
		RateLimitUserAPI:       env.GetAsInt("RATE_LIMIT_USER_API", 300),
		RateLimitUserExpensive: env.GetAsInt("RATE_LIMIT_USER_EXPENSIVE", 20),

		RateLimitDegradeMode:      env.Get("RATE_LIMIT_DEGRADE_MODE", "memory"),
		RateLimitDegradeThreshold: env.GetAsInt("RATE_LIMIT_DEGRADE_THRESHOLD", 3),
		RateLimitProbeSeconds:     env.GetAsInt("RATE_LIMIT_REDIS_PROBE_SECONDS", 15),

		CORSAllowedOrigins: env.GetAsStringArr("CORS_ALLOWED_ORIGINS", "http://localhost:5173"),

		TrustedProxies: env.GetAsStringArr("TRUSTED_PROXIES", ""),

		CookieNamespace: env.Get("COOKIE_NAMESPACE", "com.hevanto-it.swayrider"),

		ServiceTokenRefreshTimeout: time.Duration(env.GetAsInt("SERVICE_TOKEN_REFRESH_TIMEOUT", 15)) * time.Second,
		JWTKeysRefreshTimeout:      time.Duration(env.GetAsInt("JWT_KEYS_REFRESH_TIMEOUT", 15)) * time.Second,
	}
}
