# ==============================================================================
# TrustShield API Gateway Dockerfile
# Monorepo Build Context: ./backend
# ==============================================================================

FROM golang:1.22-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates

# Copy module files and shared dependencies
COPY go.mod go.sum* ./
COPY shared ./shared
COPY gateway ./gateway

# Build binary
WORKDIR /app/gateway
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/gateway-bin ./cmd/gateway

# Production runtime stage
FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata curl
WORKDIR /app

COPY --from=builder /app/gateway-bin /app/gateway

EXPOSE 8000
ENTRYPOINT ["/app/gateway"]
