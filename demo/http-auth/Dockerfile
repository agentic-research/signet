# Multi-stage build for Signet HTTP Auth Demo
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build both server and client
RUN go build -o demo-server ./demo/http-auth/server/main.go
RUN go build -o demo-client ./demo/http-auth/client/main.go

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binaries from builder
COPY --from=builder /build/demo-server /app/
COPY --from=builder /build/demo-client /app/

# Expose server port
EXPOSE 8080

# Default to running the server
CMD ["/app/demo-server"]
