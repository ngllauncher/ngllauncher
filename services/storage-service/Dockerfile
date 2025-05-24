# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o storage-service ./main.go

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata clamav-daemon

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/storage-service .

# Copy config files
COPY config/config.yaml ./config/

# Create necessary directories
RUN mkdir -p /tmp/storage-service && \
    chown -R appuser:appuser /tmp/storage-service

# Create non-root user
RUN adduser -D -g '' appuser
USER appuser

# Expose ports
EXPOSE 8080 9090

# Set environment variables
ENV GIN_MODE=release

# Run the application
CMD ["./storage-service"] 