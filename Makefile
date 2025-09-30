.PHONY: all build test integration-test clean docker-build docker-test docker-shell

# Default target
all: build

# Build the signet-commit binary
build:
	go build -o signet-commit ./cmd/signet-commit

# Run unit tests
test:
	go test -v ./...

# Run integration test locally (requires permissions)
integration-test-local: build
	./test_integration.sh

# Build Docker image for testing
docker-build:
	docker build -t signet-test -f Dockerfile.test .

# Run integration test in Docker (no privileged escalation)
docker-test: docker-build
	docker run --rm signet-test

# Interactive shell in test container for debugging
docker-shell: docker-build
	docker run --rm -it -v "$(PWD):/workspace" -w /workspace signet-test bash

# Integration test in Docker (builds for Linux, runs in isolated container)
integration-test: docker-build
	docker run --rm signet-test

# Clean build artifacts
clean:
	rm -f signet-commit
	rm -rf /tmp/signet-test-*
	rm -rf /tmp/verify-test*
	rm -rf /tmp/test-verify*
	rm -rf /tmp/gitsign-test

# Quick rebuild and test cycle
quick: clean build integration-test

# Install to /usr/local/bin (requires sudo)
install: build
	@echo "Installing to /usr/local/bin (requires sudo)..."
	sudo cp signet-commit /usr/local/bin/
	@echo "Installed successfully"

# Format code
fmt:
	go fmt ./...
	gofmt -s -w .

# Run linters
lint:
	golangci-lint run ./...

# Run security scan
security:
	gosec ./...

help:
	@echo "Available targets:"
	@echo "  make build              - Build the signet-commit binary"
	@echo "  make test               - Run unit tests"
	@echo "  make integration-test   - Run integration test in Docker"
	@echo "  make docker-shell       - Open shell in test container"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make install            - Install to /usr/local/bin (requires sudo)"
	@echo "  make fmt                - Format code"
	@echo "  make lint               - Run linters"
	@echo "  make help               - Show this help"
