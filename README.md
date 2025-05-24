# NGLlauncher

A microservices-based backend platform with authentication, Twitter integration, blockchain operations, and file storage capabilities.

## Prerequisites

- Docker and Docker Compose
- Go 1.21 or later
- Make (optional, but recommended)
- Git

## Project Structure

```
.
├── services/
│   ├── api-gateway/
│   ├── auth-service/
│   ├── twitter-service/
│   ├── blockchain-service/
│   └── storage-service/
├── prometheus/
├── grafana/
├── jaeger/
└── docker-compose.yml
```

## Setup Instructions

### 1. Clone and Initialize

```bash
# Clone the repository
git clone https://github.com/ngllauncher/ngllauncher.git
cd ngllauncher

# Create necessary directories
mkdir -p services/{api-gateway,auth-service,twitter-service,blockchain-service,storage-service}/config
mkdir -p prometheus grafana/dashboards grafana/provisioning/{datasources,dashboards} jaeger
```

### 2. Configure Services

```bash
# Copy configuration files
cp configs/api-gateway.yaml services/api-gateway/config/config.yaml
cp configs/auth-service.yaml services/auth-service/config/config.yaml
cp configs/twitter-service.yaml services/twitter-service/config/config.yaml
cp configs/blockchain-service.yaml services/blockchain-service/config/config.yaml
cp configs/storage-service.yaml services/storage-service/config/config.yaml

# Update configuration values
# Edit each config.yaml file and replace placeholder values with your actual credentials
```

### 3. Build Services

```bash
# Build all services
for service in api-gateway auth-service twitter-service blockchain-service storage-service; do
    cd services/$service
    go mod download
    go build -o $service
    cd ../..
done
```

### 4. Start Infrastructure Services

```bash
# Start databases and message broker
docker-compose up -d postgres mongodb redis

# Wait for databases to be ready
sleep 10

# Initialize databases
docker-compose exec postgres psql -U postgres -d auth_service -f /docker-entrypoint-initdb.d/init.sql
```

### 5. Start Monitoring Stack

```bash
# Start monitoring services
docker-compose up -d prometheus grafana jaeger

# Wait for services to be ready
sleep 5

# Configure Grafana dashboards
curl -X POST -H "Content-Type: application/json" -d @grafana/dashboards/services.json http://admin:admin@localhost:3000/api/dashboards/db
curl -X POST -H "Content-Type: application/json" -d @grafana/dashboards/databases.json http://admin:admin@localhost:3000/api/dashboards/db
```

### 6. Start Core Services

```bash
# Start core services
docker-compose up -d auth-service twitter-service blockchain-service storage-service

# Wait for services to be ready
sleep 5

# Verify services are running
curl http://localhost:8081/health  # Auth service
curl http://localhost:8082/health  # Twitter service
curl http://localhost:8083/health  # Blockchain service
curl http://localhost:8084/health  # Storage service
```

### 7. Start API Gateway

```bash
# Start API Gateway
docker-compose up -d api-gateway

# Verify API Gateway is running
curl http://localhost:8080/health
```

### 8. Verify Deployment

```bash
# Check all services are running
docker-compose ps

# Check logs for any errors
docker-compose logs --tail=100

# Access monitoring interfaces
echo "Grafana: http://localhost:3000 (admin/admin)"
echo "Prometheus: http://localhost:9090"
echo "Jaeger: http://localhost:16686"
```

## Accessing Services

- API Gateway: http://localhost:8080
- Auth Service: http://localhost:8081
- Twitter Service: http://localhost:8082
- Blockchain Service: http://localhost:8083
- Storage Service: http://localhost:8084
- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090
- Jaeger: http://localhost:16686

## Development

### Running Tests

```bash
# Run tests for all services
for service in api-gateway auth-service twitter-service blockchain-service storage-service; do
    cd services/$service
    go test ./...
    cd ../..
done
```

### Adding New Services

1. Create a new directory in `services/`
2. Copy the service template
3. Update `docker-compose.yml`
4. Add service configuration
5. Update API Gateway routes

## Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database logs
   docker-compose logs postgres mongodb
   
   # Verify database connectivity
   docker-compose exec postgres pg_isready
   docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')"
   ```

2. **Service Health Checks**
   ```bash
   # Check service health
   curl http://localhost:8080/health
   
   # Check service logs
   docker-compose logs -f [service-name]
   ```

3. **Monitoring Issues**
   ```bash
   # Check Prometheus targets
   curl http://localhost:9090/api/v1/targets
   
   # Check Grafana datasources
   curl http://admin:admin@localhost:3000/api/datasources
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 