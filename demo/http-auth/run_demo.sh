#!/bin/bash

echo "🚀 Signet HTTP Authentication Demo"
echo "=================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Build the server
echo -e "${YELLOW}Building server...${NC}"
go build -o server main.go || { echo -e "${RED}Failed to build server${NC}"; exit 1; }

# Build the client
echo -e "${YELLOW}Building client...${NC}"
go build -o client client/main.go || { echo -e "${RED}Failed to build client${NC}"; exit 1; }

# Start the server in background
echo -e "${GREEN}Starting Signet auth server on :8080...${NC}"
./server &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Run the client demo
echo ""
echo -e "${GREEN}Running client demonstration...${NC}"
echo ""
./client

# Cleanup
echo ""
echo -e "${YELLOW}Stopping server...${NC}"
kill $SERVER_PID 2>/dev/null

echo ""
echo -e "${GREEN}✅ Demo complete!${NC}"
echo ""
echo "Key takeaways:"
echo "  1. HTTP requests require Signet-Proof headers (not just bearer tokens)"
echo "  2. Replayed requests with same timestamp are rejected"
echo "  3. Each JTI tracks its own monotonic timestamp sequence"
echo "  4. This prevents token theft - stolen proofs can't be replayed!"