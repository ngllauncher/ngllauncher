package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)
)

type Config struct {
	Server struct {
		Port         int    `yaml:"port"`
		ReadTimeout  int    `yaml:"readTimeout"`
		WriteTimeout int    `yaml:"writeTimeout"`
	} `yaml:"server"`
	RateLimit struct {
		Requests int   `yaml:"requests"`
		Window   int64 `yaml:"window"`
	} `yaml:"rateLimit"`
	Services struct {
		Auth     string `yaml:"auth"`
		Twitter  string `yaml:"twitter"`
		Blockchain string `yaml:"blockchain"`
		Storage  string `yaml:"storage"`
	} `yaml:"services"`
	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
}

type Service struct {
	config *Config
	logger *zap.Logger
	redis  *redis.Client
	router *gin.Engine
}

func NewService(config *Config) (*Service, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addr,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	return &Service{
		config: config,
		logger: logger,
		redis:  redisClient,
		router: router,
	}, nil
}

func (s *Service) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthCheck)

	// Metrics endpoint
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// API routes
	api := s.router.Group("/api/v1")
	{
		api.Use(s.rateLimiter())
		api.Use(s.authMiddleware())

		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/login", s.handleLogin)
			auth.POST("/register", s.handleRegister)
			auth.POST("/refresh", s.handleRefreshToken)
		}

		// Twitter routes
		twitter := api.Group("/twitter")
		{
			twitter.GET("/tweets", s.handleGetTweets)
			twitter.POST("/tweets", s.handleCreateTweet)
			twitter.GET("/analytics", s.handleGetAnalytics)
		}

		// Blockchain routes
		blockchain := api.Group("/blockchain")
		{
			blockchain.POST("/deploy", s.handleDeployContract)
			blockchain.GET("/status/:id", s.handleGetDeploymentStatus)
			blockchain.GET("/transactions", s.handleGetTransactions)
		}

		// Storage routes
		storage := api.Group("/storage")
		{
			storage.POST("/upload", s.handleUpload)
			storage.GET("/files/:id", s.handleGetFile)
			storage.DELETE("/files/:id", s.handleDeleteFile)
		}
	}
}

func (s *Service) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func (s *Service) rateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := fmt.Sprintf("rate_limit:%s", c.ClientIP())
		count, err := s.redis.Incr(context.Background(), key).Result()
		if err != nil {
			s.logger.Error("failed to increment rate limit counter", zap.Error(err))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if count == 1 {
			s.redis.Expire(context.Background(), key, time.Duration(s.config.RateLimit.Window)*time.Second)
		}

		if count > int64(s.config.RateLimit.Requests) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		c.Next()
	}
}

func (s *Service) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Validate token with auth service
		// Implementation details...

		c.Next()
	}
}

func (s *Service) Start() error {
	s.setupRoutes()

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Server.Port),
		Handler:      s.router,
		ReadTimeout:  time.Duration(s.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Server.WriteTimeout) * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Fatal("failed to start server", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	s.logger.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	return nil
}

func main() {
	// Load configuration
	configFile, err := os.Open("config/config.yaml")
	if err != nil {
		log.Fatalf("failed to open config file: %v", err)
	}
	defer configFile.Close()

	var config Config
	if err := yaml.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatalf("failed to decode config: %v", err)
	}

	// Register Prometheus metrics
	prometheus.MustRegister(httpRequestsTotal)

	// Create and start service
	service, err := NewService(&config)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	if err := service.Start(); err != nil {
		log.Fatalf("failed to start service: %v", err)
	}
} 