package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/websocket/v2"
	"github.com/redis/go-redis/v9"
	"github.com/trustshield/backend/gateway/internal/config"
	"github.com/trustshield/backend/gateway/internal/handler"
	"github.com/trustshield/backend/gateway/internal/service/deepscan"
	"github.com/trustshield/backend/gateway/internal/service/fastpath"
	"github.com/trustshield/backend/gateway/internal/transport/ws"
)

func main() {
	cfg := config.LoadConfig()

	// 1. Initialize Redis Client for Hot Cache & Bloom Filters
	var rdb *redis.Client
	redisAddr := fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort)
	rdb = redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     cfg.RedisPassword,
		DB:           0,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	})

	ctxPing, cancelPing := context.WithTimeout(context.Background(), 2*time.Second)
	if err := rdb.Ping(ctxPing).Err(); err != nil {
		log.Printf("[Gateway Warning] Redis at %s not responding (%v). Operating with in-memory fallback.", redisAddr, err)
	} else {
		log.Printf("[+] Successfully connected to Redis Bloom/Cache tier at %s", redisAddr)
	}
	cancelPing()

	// 2. Instantiate Core Services
	wsHub := ws.NewHub()
	fastPath := fastpath.NewFastPathEvaluator(rdb)
	orchestrator := deepscan.NewOrchestrator(cfg, fastPath, wsHub)
	scanHandler := handler.NewScanHandler(fastPath, orchestrator, wsHub)

	// 3. Configure High-Performance Fiber Gateway
	app := fiber.New(fiber.Config{
		AppName:      "TrustShield API Gateway & Dual-Lane Router v2.0",
		ServerHeader: "TrustShield-Gateway",
		BodyLimit:    int(cfg.MaxBodyBytes), // 10MB strict limit
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	})

	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: cfg.CorsAllowedOrigins,
		AllowHeaders: "Origin, Content-Type, Accept, Authorization, X-Tenant-Id, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Extensions",
		AllowMethods: "GET, POST, OPTIONS",
	}))

	// 4. Register Health & Info Endpoints
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":      "healthy",
			"service":     "api-gateway",
			"lane":        "dual-lane-orchestrator",
			"environment": cfg.Environment,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	// 5. Register Dual-Lane REST Endpoints
	api := app.Group("/api/v1")
	{
		api.Post("/scan/fast-path", scanHandler.FastPathScan)
		api.Post("/scan", scanHandler.InitiateDeepScan)
		api.Get("/scan/history", scanHandler.GetScanHistory)
		api.Get("/scan/:id", scanHandler.GetScanReport)
	}

	// 6. Register WebSocket Stream Upgrade Endpoint
	app.Use("/ws", func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})
	app.Get("/ws/scans/:id", scanHandler.WebSocketUpgrade())

	// 7. Graceful Shutdown Management
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-shutdownChan
		log.Println("[*] Initiating graceful shutdown of TrustShield Gateway...")
		_ = app.Shutdown()
	}()

	log.Printf("[+] TrustShield API Gateway listening on port :%s (Payload Limit: %d MB)", cfg.Port, cfg.MaxBodyBytes/(1024*1024))
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Printf("[*] Server terminated: %v", err)
	}
}
