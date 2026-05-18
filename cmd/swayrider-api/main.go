package main

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/swayrider/grpcclients/authclient"
	"github.com/swayrider/grpcclients/regionclient"
	"github.com/swayrider/grpcclients/routerclient"
	"github.com/swayrider/grpcclients/searchclient"
	"github.com/swayrider/swlib/jwt"
	log "github.com/swayrider/swlib/logger"
	"github.com/swayrider/swayrider-api/internal/circuitbreaker"
	"github.com/swayrider/swayrider-api/internal/config"
	"github.com/swayrider/swayrider-api/internal/handlers"
	"github.com/swayrider/swayrider-api/internal/jwtkeys"
	"github.com/swayrider/swayrider-api/internal/queue"
	"github.com/swayrider/swayrider-api/internal/ratelimit"
	"github.com/swayrider/swayrider-api/internal/server"
	"github.com/swayrider/swayrider-api/internal/servicetoken"
	"github.com/swayrider/swayrider-api/internal/sse"
)

func main() {
	jwt.Configure("SwayRider", "SwayRider")

	cfg := config.Load()

	lg := log.New(log.WithComponent("swayrider-api"))
	if err := log.SetLogLevel(cfg.LogLevel); err != nil {
		lg.Warnf("invalid LOG_LEVEL %q, defaulting to info: %v", cfg.LogLevel, err)
	}

	ctx := context.Background()

	// gRPC clients
	authCltIface, err := authclient.New(func() (string, int) {
		return cfg.AuthServiceHost, cfg.AuthServicePort
	})
	if err != nil {
		lg.Fatalf("authclient: %v", err)
	}
	authClt := authCltIface.(*authclient.Client)

	regionCltIface, err := regionclient.New(func() (string, int) {
		return cfg.RegionServiceHost, cfg.RegionServicePort
	})
	if err != nil {
		lg.Fatalf("regionclient: %v", err)
	}
	regionClt := regionCltIface.(*regionclient.Client)

	routerCltIface, err := routerclient.New(func() (string, int) {
		return cfg.RouterServiceHost, cfg.RouterServicePort
	})
	if err != nil {
		lg.Fatalf("routerclient: %v", err)
	}
	routerClt := routerCltIface.(*routerclient.Client)

	searchCltIface, err := searchclient.New(func() (string, int) {
		return cfg.SearchServiceHost, cfg.SearchServicePort
	})
	if err != nil {
		lg.Fatalf("searchclient: %v", err)
	}
	searchClt := searchCltIface.(*searchclient.Client)

	// Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.RedisHost, cfg.RedisPort),
	})

	// JWT key cache
	keyCache := jwtkeys.New(authClt, lg)
	keyCache.Start(ctx)

	// Service token manager — fetches and refreshes the gateway's own token.
	tokenMgr := servicetoken.New(
		authClt,
		cfg.ClientID,
		cfg.ClientSecret,
		[]string{"routing:execute", "search:execute"},
		lg,
	)
	tokenMgr.Start(ctx)

	// Rate limiter + circuit breakers
	limiter := ratelimit.New(redisClient)
	breakers := circuitbreaker.New([]string{"authservice", "routerservice", "searchservice", "regionservice"}, lg)

	// Queue producer + consumer group bootstrap
	producer := queue.NewProducer(redisClient, cfg.QueueMaxDepth)
	producer.Bootstrap(ctx)

	// SSE hub
	hub := sse.New(redisClient, lg)

	// Worker pools
	resultTTL := time.Duration(cfg.ResultTTLSeconds) * time.Second

	routeWorkers := queue.NewWorkerPool(queue.WorkerConfig{
		Redis:     redisClient,
		Stream:    queue.StreamRouting,
		Count:     cfg.RouteWorkerCount,
		Process:   handlers.NewRouteProcessFn(routerClt, tokenMgr.Token, breakers),
		ResultTTL: resultTTL,
		Logger:    lg,
	})
	routeWorkers.Start(ctx)

	searchWorkers := queue.NewWorkerPool(queue.WorkerConfig{
		Redis:     redisClient,
		Stream:    queue.StreamSearch,
		Count:     cfg.SearchWorkerCount,
		Process:   handlers.NewSearchProcessFn(searchClt, tokenMgr.Token, breakers),
		ResultTTL: resultTTL,
		Logger:    lg,
	})
	searchWorkers.Start(ctx)

	// Handlers
	authHandler := handlers.NewAuthHandler(authClt, keyCache, lg)
	regionHandler := handlers.NewRegionHandler(regionClt)
	routeHandler := handlers.NewRouteHandler(producer, hub, lg)
	searchHandler := handlers.NewSearchHandler(producer, hub, lg)
	tilesProxy := handlers.NewTilesProxy(cfg.TilesServiceHost, cfg.TilesServicePort)
	webProxy := handlers.NewWebProxy(cfg.AuthServiceHost, 8000)

	srv := server.New(cfg, lg, authHandler, regionHandler, routeHandler, searchHandler, tilesProxy, webProxy, keyCache, limiter, breakers)
	srv.Run(ctx)
}
