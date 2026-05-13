package main

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
	"github.com/swayrider/grpcclients/authclient"
	"github.com/swayrider/grpcclients/regionclient"
	"github.com/swayrider/swlib/jwt"
	"github.com/swayrider/swayrider-api/internal/circuitbreaker"
	"github.com/swayrider/swayrider-api/internal/config"
	"github.com/swayrider/swayrider-api/internal/handlers"
	"github.com/swayrider/swayrider-api/internal/jwtkeys"
	"github.com/swayrider/swayrider-api/internal/ratelimit"
	"github.com/swayrider/swayrider-api/internal/server"
	"github.com/swayrider/swayrider-api/internal/servicetoken"
)

func main() {
	jwt.Configure("SwayRider", "SwayRider")

	cfg := config.Load()
	ctx := context.Background()

	// gRPC clients
	authCltIface, err := authclient.New(func() (string, int) {
		return cfg.AuthServiceHost, cfg.AuthServicePort
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "authclient: %v\n", err)
		os.Exit(1)
	}
	authClt := authCltIface.(*authclient.Client)

	regionCltIface, err := regionclient.New(func() (string, int) {
		return cfg.RegionServiceHost, cfg.RegionServicePort
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "regionclient: %v\n", err)
		os.Exit(1)
	}
	regionClt := regionCltIface.(*regionclient.Client)

	// Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort),
	})

	// JWT key cache
	keyCache := jwtkeys.New(authClt)
	keyCache.Start(ctx)

	// Service token manager (for Plan 04 workers; initialised here so the token
	// is ready when workers start).
	_ = servicetoken.New(
		authClt,
		cfg.ClientID,
		cfg.ClientSecret,
		[]string{"routing:execute", "search:execute"},
	)

	// Rate limiter + circuit breakers
	limiter := ratelimit.New(redisClient)
	breakers := circuitbreaker.New([]string{"authservice", "routerservice", "searchservice", "regionservice"})

	// Handlers
	authHandler := handlers.NewAuthHandler(authClt, keyCache)
	regionHandler := handlers.NewRegionHandler(regionClt)
	tilesProxy := handlers.NewTilesProxy(cfg.TilesServiceHost, cfg.TilesServicePort)
	webProxy := handlers.NewWebProxy(cfg.AuthServiceHost, 8000)

	srv := server.New(cfg, authHandler, regionHandler, tilesProxy, webProxy, keyCache, limiter, breakers)
	srv.Run(ctx)
}
