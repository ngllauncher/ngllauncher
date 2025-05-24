package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
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
	contractDeploymentsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "contract_deployments_total",
			Help: "Total number of smart contract deployments",
		},
		[]string{"status"},
	)

	transactionProcessingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "transaction_processing_duration_seconds",
			Help:    "Time spent processing blockchain transactions",
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
	Blockchain struct {
		NetworkURL    string `yaml:"networkUrl"`
		PrivateKey    string `yaml:"privateKey"`
		GasLimit      uint64 `yaml:"gasLimit"`
		GasPrice      int64  `yaml:"gasPrice"`
		Confirmations int64  `yaml:"confirmations"`
	} `yaml:"blockchain"`
	MongoDB struct {
		URI      string `yaml:"uri"`
		Database string `yaml:"database"`
	} `yaml:"mongodb"`
	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
}

type Contract struct {
	Address     string    `bson:"address"`
	Name        string    `bson:"name"`
	Type        string    `bson:"type"`
	Owner       string    `bson:"owner"`
	DeployedAt  time.Time `bson:"deployed_at"`
	Network     string    `bson:"network"`
	ABI         string    `bson:"abi"`
	Bytecode    string    `bson:"bytecode"`
	Metadata    map[string]interface{} `bson:"metadata"`
}

type Transaction struct {
	Hash        string    `bson:"hash"`
	From        string    `bson:"from"`
	To          string    `bson:"to"`
	Value       string    `bson:"value"`
	GasUsed     uint64    `bson:"gas_used"`
	GasPrice    string    `bson:"gas_price"`
	Status      string    `bson:"status"`
	BlockNumber uint64    `bson:"block_number"`
	Timestamp   time.Time `bson:"timestamp"`
	Input       string    `bson:"input"`
	Metadata    map[string]interface{} `bson:"metadata"`
}

type Service struct {
	config     *Config
	logger     *zap.Logger
	ethClient  *ethclient.Client
	mongo      *mongo.Client
	redis      *redis.Client
	router     *gin.Engine
	privateKey *ecdsa.PrivateKey
}

func NewService(config *Config) (*Service, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Initialize Ethereum client
	ethClient, err := ethclient.Dial(config.Blockchain.NetworkURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ethereum network: %w", err)
	}

	// Initialize private key
	privateKey, err := crypto.HexToECDSA(config.Blockchain.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
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
		config:     config,
		logger:     logger,
		ethClient:  ethClient,
		mongo:      mongoClient,
		redis:      redisClient,
		router:     router,
		privateKey: privateKey,
	}, nil
}

func (s *Service) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthCheck)

	// Metrics endpoint
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Blockchain routes
	blockchain := s.router.Group("/api/v1/blockchain")
	{
		blockchain.POST("/contracts/deploy", s.handleDeployContract)
		blockchain.GET("/contracts/:address", s.handleGetContract)
		blockchain.GET("/contracts", s.handleListContracts)
		blockchain.POST("/transactions", s.handleSendTransaction)
		blockchain.GET("/transactions/:hash", s.handleGetTransaction)
		blockchain.GET("/transactions", s.handleListTransactions)
		blockchain.GET("/balance/:address", s.handleGetBalance)
		blockchain.GET("/gas-price", s.handleGetGasPrice)
		blockchain.GET("/network-status", s.handleGetNetworkStatus)
	}
}

func (s *Service) deployContract(ctx context.Context, name, contractType, abi, bytecode string) (*Contract, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		transactionProcessingDuration.WithLabelValues("deploy").Observe(duration)
	}()

	// Create auth
	auth, err := bind.NewKeyedTransactorWithChainID(s.privateKey, big.NewInt(1)) // Replace with actual chain ID
	if err != nil {
		return nil, fmt.Errorf("failed to create auth: %w", err)
	}

	// Set gas price
	gasPrice, err := s.ethClient.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}
	auth.GasPrice = gasPrice

	// Set gas limit
	auth.GasLimit = s.config.Blockchain.GasLimit

	// Deploy contract
	address, tx, _, err := bind.DeployContract(auth, abi, bytecode, s.ethClient)
	if err != nil {
		contractDeploymentsTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("failed to deploy contract: %w", err)
	}

	// Wait for transaction to be mined
	receipt, err := bind.WaitMined(ctx, s.ethClient, tx)
	if err != nil {
		contractDeploymentsTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("failed to wait for transaction: %w", err)
	}

	if receipt.Status == 0 {
		contractDeploymentsTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("contract deployment failed")
	}

	// Create contract record
	contract := &Contract{
		Address:    address.Hex(),
		Name:       name,
		Type:       contractType,
		Owner:      crypto.PubkeyToAddress(s.privateKey.PublicKey).Hex(),
		DeployedAt: time.Now(),
		Network:    "ethereum",
		ABI:        abi,
		Bytecode:   bytecode,
		Metadata:   make(map[string]interface{}),
	}

	// Store in MongoDB
	collection := s.mongo.Database(s.config.MongoDB.Database).Collection("contracts")
	_, err = collection.InsertOne(ctx, contract)
	if err != nil {
		return nil, fmt.Errorf("failed to store contract: %w", err)
	}

	contractDeploymentsTotal.WithLabelValues("success").Inc()
	return contract, nil
}

func (s *Service) handleDeployContract(c *gin.Context) {
	var input struct {
		Name        string `json:"name" binding:"required"`
		Type        string `json:"type" binding:"required"`
		ABI         string `json:"abi" binding:"required"`
		Bytecode    string `json:"bytecode" binding:"required"`
		Constructor []byte `json:"constructor"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	contract, err := s.deployContract(c.Request.Context(), input.Name, input.Type, input.ABI, input.Bytecode)
	if err != nil {
		s.logger.Error("failed to deploy contract", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deploy contract"})
		return
	}

	c.JSON(http.StatusCreated, contract)
}

func (s *Service) handleGetContract(c *gin.Context) {
	address := c.Param("address")
	collection := s.mongo.Database(s.config.MongoDB.Database).Collection("contracts")

	var contract Contract
	err := collection.FindOne(c.Request.Context(), bson.M{"address": address}).Decode(&contract)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "Contract not found"})
			return
		}
		s.logger.Error("failed to fetch contract", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, contract)
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
	prometheus.MustRegister(contractDeploymentsTotal)
	prometheus.MustRegister(transactionProcessingDuration)

	// Create and start service
	service, err := NewService(&config)
	if err != nil {
		log.Fatalf("failed to create service: %v", err)
	}

	if err := service.Start(); err != nil {
		log.Fatalf("failed to start service: %v", err)
	}
} 