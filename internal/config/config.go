package config

import "github.com/swayrider/swlib/env"

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
	RateLimitUserAPI       int
	RateLimitUserExpensive int

	CORSAllowedOrigins []string
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
		RateLimitUserAPI:       env.GetAsInt("RATE_LIMIT_USER_API", 300),
		RateLimitUserExpensive: env.GetAsInt("RATE_LIMIT_USER_EXPENSIVE", 20),

		CORSAllowedOrigins: env.GetAsStringArr("CORS_ALLOWED_ORIGINS", "http://localhost:5173"),
	}
}
