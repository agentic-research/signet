#!/bin/bash

echo "🚀 Signet HTTP Authentication Demo"
echo "=================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Docker is available and user preference
USE_DOCKER=false
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    if [[ "$1" == "--local" ]]; then
        echo -e "${YELLOW}Running locally (--local flag provided)${NC}"
        USE_DOCKER=false
    else
        echo -e "${GREEN}Docker detected. Using Docker for demo.${NC}"
        echo -e "${YELLOW}Use './run_demo.sh --local' to run without Docker${NC}"
        echo ""
        USE_DOCKER=true
    fi
else
    echo -e "${YELLOW}Docker not found. Running locally.${NC}"
    USE_DOCKER=false
fi

if $USE_DOCKER; then
    # Docker-based execution
    echo -e "${GREEN}Building and running with Docker Compose...${NC}"

    # Navigate to the project root (two levels up from demo/http-auth)
    cd ../.. || exit 1

    # Run docker-compose from the http-auth directory context
    docker-compose -f demo/http-auth/docker-compose.yml up --build --abort-on-container-exit

    # Cleanup
    echo ""
    echo -e "${YELLOW}Cleaning up Docker containers...${NC}"
    docker-compose -f demo/http-auth/docker-compose.yml down

else
    # Local execution
    echo -e "${YELLOW}Building server...${NC}"
    go build -o demo-server server/main.go || { echo -e "${RED}Failed to build server${NC}"; exit 1; }

    echo -e "${YELLOW}Building client...${NC}"
    go build -o demo-client client/main.go || { echo -e "${RED}Failed to build client${NC}"; exit 1; }

    # Start the server in background
    echo -e "${GREEN}Starting Signet auth server on :8080...${NC}"
    ./demo-server &
    SERVER_PID=$!

    # Wait for server to start
    sleep 2

    # Run the client demo
    echo ""
    echo -e "${GREEN}Running client demonstration...${NC}"
    echo ""
    ./demo-client

    # Cleanup
    echo ""
    echo -e "${YELLOW}Stopping server...${NC}"
    kill $SERVER_PID 2>/dev/null

    # Clean up binaries
    rm -f demo-server demo-client
fi

echo ""
echo -e "${GREEN}✅ Demo complete!${NC}"
echo ""
echo "Key takeaways:"
echo "  1. ✅ Full two-step cryptographic verification (master→ephemeral→request)"
echo "  2. ✅ Token-based ephemeral key binding with CBOR encoding"
echo "  3. ❌ Replay attacks are blocked (same token + timestamp)"
echo "  4. ✅ Different tokens are independent (different purposes)"
echo "  5. ✅ Purpose-specific ephemeral keys enforcement"
echo ""
echo "The demo showcases Signet's proof-of-possession protocol replacing bearer tokens!"
