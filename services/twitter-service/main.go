package main

import (
	"context"
	"encoding/json"
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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	tweetsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tweets_processed_total",
			Help: "Total number of tweets processed",
		},
		[]string{"status"},
	)

	tweetProcessingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "tweet_processing_duration_seconds",
			Help:    "Time spent processing tweets",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)
)

type Config struct {
	Server struct {
		Port         int    `yaml:"port"`
		ReadTimeout  int    `yaml:"readTimeout"`
		WriteTimeout int    `yaml:"writeTimeout"`
	} `yaml:"server"`
	Twitter struct {
		APIKey       string `yaml:"apiKey"`
		APISecret    string `yaml:"apiSecret"`
		AccessToken  string `yaml:"accessToken"`
		AccessSecret string `yaml:"accessSecret"`
		StreamRules  []string `yaml:"streamRules"`
	} `yaml:"twitter"`
	MongoDB struct {
		URI      string `yaml:"uri"`
		Database string `yaml:"database"`
	} `yaml:"mongodb"`
	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
	Analytics struct {
		UpdateInterval int `yaml:"updateInterval"`
		RetentionDays  int `yaml:"retentionDays"`
	} `yaml:"analytics"`
}

type Tweet struct {
	ID        string    `bson:"_id,omitempty"`
	Text      string    `bson:"text"`
	AuthorID  string    `bson:"author_id"`
	CreatedAt time.Time `bson:"created_at"`
	Metrics   struct {
		RetweetCount int `bson:"retweet_count"`
		ReplyCount   int `bson:"reply_count"`
		LikeCount    int `bson:"like_count"`
		QuoteCount   int `bson:"quote_count"`
	} `bson:"metrics"`
	Entities struct {
		Hashtags     []string `bson:"hashtags"`
		Mentions     []string `bson:"mentions"`
		Urls         []string `bson:"urls"`
		Media        []string `bson:"media"`
		Symbols      []string `bson:"symbols"`
		Polls        []string `bson:"polls"`
		Annotations  []string `bson:"annotations"`
	} `bson:"entities"`
	Context struct {
		ConversationID string   `bson:"conversation_id"`
		ReferencedTweets []string `bson:"referenced_tweets"`
	} `bson:"context"`
	Sentiment struct {
		Score     float64 `bson:"score"`
		Magnitude float64 `bson:"magnitude"`
		Label     string  `bson:"label"`
	} `bson:"sentiment"`
	Metadata map[string]interface{} `bson:"metadata"`
}

type Service struct {
	config *Config
	logger *zap.Logger
	mongo  *mongo.Client
	redis  *redis.Client
	router *gin.Engine
}

func NewService(config *Config) (*Service, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Initialize MongoDB
	mongoClient, err := mongo.Connect(context.Background(), options.Client().ApplyURI(config.MongoDB.URI))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongodb: %w", err)
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
		mongo:  mongoClient,
		redis:  redisClient,
		router: router,
	}, nil
}

func (s *Service) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthCheck)

	// Metrics endpoint
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Twitter routes
	twitter := s.router.Group("/api/v1/twitter")
	{
		twitter.GET("/tweets", s.handleGetTweets)
		twitter.GET("/tweets/:id", s.handleGetTweet)
		twitter.POST("/tweets", s.handleCreateTweet)
		twitter.GET("/analytics", s.handleGetAnalytics)
		twitter.GET("/stream", s.handleStreamTweets)
		twitter.GET("/search", s.handleSearchTweets)
		twitter.GET("/users/:id/tweets", s.handleGetUserTweets)
		twitter.GET("/trends", s.handleGetTrends)
	}
}

func (s *Service) processTweet(tweet *Tweet) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		tweetProcessingDuration.WithLabelValues("process").Observe(duration)
	}()

	// Store in MongoDB
	collection := s.mongo.Database(s.config.MongoDB.Database).Collection("tweets")
	_, err := collection.InsertOne(context.Background(), tweet)
	if err != nil {
		tweetsProcessedTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("failed to store tweet: %w", err)
	}

	// Update Redis cache
	tweetKey := fmt.Sprintf("tweet:%s", tweet.ID)
	tweetJSON, err := json.Marshal(tweet)
	if err != nil {
		return fmt.Errorf("failed to marshal tweet: %w", err)
	}

	err = s.redis.Set(context.Background(), tweetKey, tweetJSON, 24*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to cache tweet: %w", err)
	}

	// Update analytics
	err = s.updateAnalytics(tweet)
	if err != nil {
		return fmt.Errorf("failed to update analytics: %w", err)
	}

	tweetsProcessedTotal.WithLabelValues("success").Inc()
	return nil
}

func (s *Service) updateAnalytics(tweet *Tweet) error {
	// Update hashtag counts
	for _, hashtag := range tweet.Entities.Hashtags {
		key := fmt.Sprintf("analytics:hashtags:%s", hashtag)
		err := s.redis.Incr(context.Background(), key).Err()
		if err != nil {
			return fmt.Errorf("failed to update hashtag count: %w", err)
		}
	}

	// Update user metrics
	userKey := fmt.Sprintf("analytics:users:%s", tweet.AuthorID)
	pipe := s.redis.Pipeline()
	pipe.HIncrBy(context.Background(), userKey, "tweets", 1)
	pipe.HIncrBy(context.Background(), userKey, "likes", int64(tweet.Metrics.LikeCount))
	pipe.HIncrBy(context.Background(), userKey, "retweets", int64(tweet.Metrics.RetweetCount))
	pipe.HIncrBy(context.Background(), userKey, "replies", int64(tweet.Metrics.ReplyCount))
	_, err := pipe.Exec(context.Background())
	if err != nil {
		return fmt.Errorf("failed to update user metrics: %w", err)
	}

	return nil
}

func (s *Service) handleGetTweets(c *gin.Context) {
	var tweets []Tweet
	collection := s.mongo.Database(s.config.MongoDB.Database).Collection("tweets")
	
	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetLimit(100)

	cursor, err := collection.Find(context.Background(), bson.M{}, opts)
	if err != nil {
		s.logger.Error("failed to fetch tweets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	defer cursor.Close(context.Background())

	if err := cursor.All(context.Background(), &tweets); err != nil {
		s.logger.Error("failed to decode tweets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, tweets)
}

func (s *Service) handleGetAnalytics(c *gin.Context) {
	// Get top hashtags
	hashtagKeys, err := s.redis.Keys(context.Background(), "analytics:hashtags:*").Result()
	if err != nil {
		s.logger.Error("failed to get hashtag keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	hashtagCounts := make(map[string]int64)
	for _, key := range hashtagKeys {
		count, err := s.redis.Get(context.Background(), key).Int64()
		if err != nil {
			continue
		}
		hashtag := key[len("analytics:hashtags:"):]
		hashtagCounts[hashtag] = count
	}

	// Get user metrics
	userKeys, err := s.redis.Keys(context.Background(), "analytics:users:*").Result()
	if err != nil {
		s.logger.Error("failed to get user keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userMetrics := make(map[string]map[string]int64)
	for _, key := range userKeys {
		metrics, err := s.redis.HGetAll(context.Background(), key).Result()
		if err != nil {
			continue
		}
		userID := key[len("analytics:users:"):]
		userMetrics[userID] = make(map[string]int64)
		for k, v := range metrics {
			userMetrics[userID][k], _ = strconv.ParseInt(v, 10, 64)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"hashtags": hashtagCounts,
		"users":    userMetrics,
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
	prometheus.MustRegister(tweetsProcessedTotal)
	prometheus.MustRegister(tweetProcessingDuration)

	// Create and start service
	service, err := NewService(&config)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	if err := service.Start(); err != nil {
		log.Fatalf("failed to start service: %v", err)
	}
} 