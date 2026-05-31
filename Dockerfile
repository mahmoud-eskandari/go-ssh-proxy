# Builder stage
FROM golang:1.26-alpine AS builder

# Build arguments
ARG VERSION=dev
ARG BUILD_DATE
ARG GIT_COMMIT

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags "-extldflags '-static' -X main.version=${VERSION}" \
    -o go-ssh-proxy .

# Runner stage
FROM alpine:latest

# Install ca-certificates for HTTPS support
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/go-ssh-proxy .

# Copy default config file (optional, can be overridden with volume mount)
COPY --from=builder /build/config.yaml .

# Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose SSH port (default 2222, can be overridden)
EXPOSE 2222

# Entry point
ENTRYPOINT ["/app/go-ssh-proxy"]

# Default command - uses config.yaml, can be overridden
CMD ["-config=config.yaml"]
