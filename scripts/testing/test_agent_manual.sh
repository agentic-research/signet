#!/bin/bash
# Manual integration test for signet-agent using grpcurl
# This script starts the agent and calls ListIdentities to verify it works

set -e

SOCKET_PATH="/tmp/signet-agent-manual-test.sock"

echo "=== Signet Agent Manual Test ==="
echo

# Clean up old socket
rm -f "$SOCKET_PATH"

# Build the agent
echo "[1/5] Building signet-agent..."
go build -o signet-agent ./cmd/signet-agent
echo "✓ Build complete"
echo

# Start the agent in the background with test mode enabled
echo "[2/5] Starting signet-agent on $SOCKET_PATH..."
SIGNET_SOCKET="$SOCKET_PATH" SIGNET_TEST_MODE=1 ./signet-agent &
AGENT_PID=$!

# Clean up function
cleanup() {
    echo
    echo "[5/5] Cleaning up..."
    if kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    rm -f "$SOCKET_PATH"
    echo "✓ Cleanup complete"
}
trap cleanup EXIT

# Wait for socket to be ready
echo "[3/5] Waiting for agent to be ready..."
for i in {1..10}; do
    if [ -S "$SOCKET_PATH" ]; then
        echo "✓ Agent is ready"
        break
    fi
    sleep 0.5
done

if [ ! -S "$SOCKET_PATH" ]; then
    echo "✗ Error: Socket was not created"
    exit 1
fi
echo

# Check if grpcurl is installed
if ! command -v grpcurl &> /dev/null; then
    echo "⚠ grpcurl is not installed. Install with:"
    echo "  brew install grpcurl"
    echo
    echo "Showing proto file contents instead:"
    cat pkg/agent/api/v1/agent.proto
    exit 0
fi

# Call ListIdentities using grpcurl
echo "[4/5] Calling ListIdentities via grpcurl..."
grpcurl -plaintext -import-path . -proto pkg/agent/api/v1/agent.proto \
    "unix://$SOCKET_PATH" \
    signet.agent.v1.SignetAgent/ListIdentities

echo
echo "=== Test Complete ==="
