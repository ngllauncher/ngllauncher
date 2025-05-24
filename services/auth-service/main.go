package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	authAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"method", "status"},
	)
)

type Config struct {
	Server struct {
		Port         int    `yaml:"port"`
		ReadTimeout  int    `yaml:"readTimeout"`
		WriteTimeout int    `yaml:"writeTimeout"`
	} `yaml:"server"`
	JWT struct {
		Secret           string        `yaml:"secret"`
		AccessTokenTTL   time.Duration `yaml:"accessTokenTTL"`
		RefreshTokenTTL  time.Duration `yaml:"refreshTokenTTL"`
		SigningMethod    string        `yaml:"signingMethod"`
	} `yaml:"jwt"`
	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		DBName   string `yaml:"dbname"`
		SSLMode  string `yaml:"sslmode"`
	} `yaml:"database"`
	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
	OAuth struct {
		Twitter struct {
			ClientID     string `yaml:"clientId"`
			ClientSecret string `yaml:"clientSecret"`
			CallbackURL  string `yaml:"callbackUrl"`
		} `yaml:"twitter"`
		Discord struct {
			ClientID     string `yaml:"clientId"`
			ClientSecret string `yaml:"clientSecret"`
			CallbackURL  string `yaml:"callbackUrl"`
		} `yaml:"discord"`
	} `yaml:"oauth"`
}

type User struct {
	gorm.Model
	Email        string `gorm:"uniqueIndex"`
	PasswordHash string
	Username     string `gorm:"uniqueIndex"`
	Role         string
	OAuthID      string
	OAuthProvider string
	LastLogin    time.Time
	IsActive     bool
	Metadata     map[string]interface{} `gorm:"type:jsonb"`
}

type Service struct {
	config *Config
	logger *zap.Logger
	db     *gorm.DB
	redis  *redis.Client
	router *gin.Engine
}

func NewService(config *Config) (*Service, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Initialize database
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Database.Host,
		config.Database.Port,
		config.Database.User,
		config.Database.Password,
		config.Database.DBName,
		config.Database.SSLMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto migrate schema
	if err := db.AutoMigrate(&User{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initialize Redis
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
		db:     db,
		redis:  redisClient,
		router: router,
	}, nil
}

func (s *Service) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthCheck)

	// Metrics endpoint
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Auth routes
	auth := s.router.Group("/api/v1/auth")
	{
		auth.POST("/register", s.handleRegister)
		auth.POST("/login", s.handleLogin)
		auth.POST("/refresh", s.handleRefreshToken)
		auth.POST("/logout", s.handleLogout)
		auth.GET("/verify", s.handleVerifyToken)
		auth.POST("/password/reset", s.handlePasswordReset)
		auth.POST("/password/change", s.handlePasswordChange)
	}

	// OAuth routes
	oauth := s.router.Group("/api/v1/oauth")
	{
		oauth.GET("/twitter", s.handleTwitterAuth)
		oauth.GET("/twitter/callback", s.handleTwitterCallback)
		oauth.GET("/discord", s.handleDiscordAuth)
		oauth.GET("/discord/callback", s.handleDiscordCallback)
	}
}

func (s *Service) generateTokens(user *User) (string, string, error) {
	// Generate access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID,
		"role": user.Role,
		"exp":  time.Now().Add(s.config.JWT.AccessTokenTTL).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)

	// Store refresh token in Redis
	ctx := context.Background()
	err = s.redis.Set(ctx, fmt.Sprintf("refresh_token:%s", refreshToken), user.ID, s.config.JWT.RefreshTokenTTL).Err()
	if err != nil {
		return "", "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return accessTokenString, refreshToken, nil
}

func (s *Service) handleRegister(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		Username string `json:"username" binding:"required,min=3"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("failed to hash password", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Create user
	user := &User{
		Email:        input.Email,
		PasswordHash: string(hashedPassword),
		Username:     input.Username,
		Role:         "user",
		IsActive:     true,
		Metadata:     make(map[string]interface{}),
	}

	if err := s.db.Create(user).Error; err != nil {
		s.logger.Error("failed to create user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Generate tokens
	accessToken, refreshToken, err := s.generateTokens(user)
	if err != nil {
		s.logger.Error("failed to generate tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func (s *Service) handleLogin(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := s.db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		authAttemptsTotal.WithLabelValues("login", "failed").Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		authAttemptsTotal.WithLabelValues("login", "failed").Inc()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Update last login
	user.LastLogin = time.Now()
	s.db.Save(&user)

	// Generate tokens
	accessToken, refreshToken, err := s.generateTokens(&user)
	if err != nil {
		s.logger.Error("failed to generate tokens", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	authAttemptsTotal.WithLabelValues("login", "success").Inc()

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": gin.H{
			"id":       user.ID,
			"email":    user.Email,
			"username": user.Username,
			"role":     user.Role,
		},
	})
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
	prometheus.MustRegister(authAttemptsTotal)

	// Create and start service
	service, err := NewService(&config)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	if err := service.Start(); err != nil {
		log.Fatalf("failed to start service: %v", err)
	}
} 