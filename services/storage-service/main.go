package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var (
	fileOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "file_operations_total",
			Help: "Total number of file operations",
		},
		[]string{"operation", "status"},
	)

	fileOperationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "file_operation_duration_seconds",
			Help:    "Time spent on file operations",
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
	AWS struct {
		Region          string `yaml:"region"`
		AccessKeyID     string `yaml:"accessKeyId"`
		SecretAccessKey string `yaml:"secretAccessKey"`
		BucketName      string `yaml:"bucketName"`
	} `yaml:"aws"`
	MongoDB struct {
		URI      string `yaml:"uri"`
		Database string `yaml:"database"`
	} `yaml:"mongodb"`
	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
	Storage struct {
		MaxFileSize    int64  `yaml:"maxFileSize"`
		AllowedTypes   []string `yaml:"allowedTypes"`
		TempDir        string `yaml:"tempDir"`
		RetentionDays  int    `yaml:"retentionDays"`
	} `yaml:"storage"`
}

type File struct {
	ID          string    `bson:"_id,omitempty"`
	Name        string    `bson:"name"`
	Size        int64     `bson:"size"`
	Type        string    `bson:"type"`
	Path        string    `bson:"path"`
	Owner       string    `bson:"owner"`
	UploadedAt  time.Time `bson:"uploaded_at"`
	ExpiresAt   time.Time `bson:"expires_at"`
	IsPublic    bool      `bson:"is_public"`
	Metadata    map[string]interface{} `bson:"metadata"`
}

type Service struct {
	config *Config
	logger *zap.Logger
	s3     *s3.Client
	mongo  *mongo.Client
	redis  *redis.Client
	router *gin.Engine
}

func NewService(config *Config) (*Service, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Initialize AWS S3 client
	awsConfig, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(config.AWS.Region),
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     config.AWS.AccessKeyID,
				SecretAccessKey: config.AWS.SecretAccessKey,
			}, nil
		})),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(awsConfig)

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

	// Create temp directory if it doesn't exist
	if err := os.MkdirAll(config.Storage.TempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	return &Service{
		config: config,
		logger: logger,
		s3:     s3Client,
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

	// Storage routes
	storage := s.router.Group("/api/v1/storage")
	{
		storage.POST("/upload", s.handleUpload)
		storage.GET("/files/:id", s.handleGetFile)
		storage.DELETE("/files/:id", s.handleDeleteFile)
		storage.GET("/files", s.handleListFiles)
		storage.POST("/files/:id/share", s.handleShareFile)
		storage.GET("/files/:id/metadata", s.handleGetFileMetadata)
	}
}

func (s *Service) uploadFile(ctx context.Context, file *File, reader io.Reader) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		fileOperationDuration.WithLabelValues("upload").Observe(duration)
	}()

	// Upload to S3
	_, err := s.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.config.AWS.BucketName),
		Key:    aws.String(file.Path),
		Body:   reader,
	})
	if err != nil {
		fileOperationsTotal.WithLabelValues("upload", "error").Inc()
		return fmt.Errorf("failed to upload file to S3: %w", err)
	}

	// Store metadata in MongoDB
	collection := s.mongo.Database(s.config.MongoDB.Database).Collection("files")
	_, err = collection.InsertOne(ctx, file)
	if err != nil {
		fileOperationsTotal.WithLabelValues("upload", "error").Inc()
		return fmt.Errorf("failed to store file metadata: %w", err)
	}

	// Cache file metadata in Redis
	fileKey := fmt.Sprintf("file:%s", file.ID)
	fileJSON, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("failed to marshal file metadata: %w", err)
	}

	err = s.redis.Set(ctx, fileKey, fileJSON, 24*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to cache file metadata: %w", err)
	}

	fileOperationsTotal.WithLabelValues("upload", "success").Inc()
	return nil
}

func (s *Service) handleUpload(c *gin.Context) {
	// Get file from request
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
		return
	}
	defer file.Close()

	// Check file size
	if header.Size > s.config.Storage.MaxFileSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File too large"})
		return
	}

	// Check file type
	fileType := header.Header.Get("Content-Type")
	isAllowed := false
	for _, t := range s.config.Storage.AllowedTypes {
		if t == fileType {
			isAllowed = true
			break
		}
	}
	if !isAllowed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File type not allowed"})
		return
	}

	// Create file record
	fileID := uuid.New().String()
	filePath := fmt.Sprintf("%s/%s", fileID, header.Filename)
	
	fileRecord := &File{
		ID:         fileID,
		Name:       header.Filename,
		Size:       header.Size,
		Type:       fileType,
		Path:       filePath,
		Owner:      c.GetString("user_id"), // From auth middleware
		UploadedAt: time.Now(),
		ExpiresAt:  time.Now().AddDate(0, 0, s.config.Storage.RetentionDays),
		IsPublic:   false,
		Metadata:   make(map[string]interface{}),
	}

	// Upload file
	if err := s.uploadFile(c.Request.Context(), fileRecord, file); err != nil {
		s.logger.Error("failed to upload file", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file"})
		return
	}

	c.JSON(http.StatusCreated, fileRecord)
}

func (s *Service) handleGetFile(c *gin.Context) {
	fileID := c.Param("id")
	collection := s.mongo.Database(s.config.MongoDB.Database).Collection("files")

	var file File
	err := collection.FindOne(c.Request.Context(), bson.M{"_id": fileID}).Decode(&file)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
			return
		}
		s.logger.Error("failed to fetch file", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Check if user has access to the file
	if !file.IsPublic && file.Owner != c.GetString("user_id") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Get file from S3
	result, err := s.s3.GetObject(c.Request.Context(), &s3.GetObjectInput{
		Bucket: aws.String(s.config.AWS.BucketName),
		Key:    aws.String(file.Path),
	})
	if err != nil {
		s.logger.Error("failed to get file from S3", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get file"})
		return
	}
	defer result.Body.Close()

	// Set headers
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file.Name))
	c.Header("Content-Type", file.Type)
	c.Header("Content-Length", fmt.Sprintf("%d", file.Size))

	// Stream file to response
	io.Copy(c.Writer, result.Body)
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
	prometheus.MustRegister(fileOperationsTotal)
	prometheus.MustRegister(fileOperationDuration)

	// Create and start service
	service, err := NewService(&config)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	if err := service.Start(); err != nil {
		log.Fatalf("failed to start service: %v", err)
	}
} 