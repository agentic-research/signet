package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/jamestexas/signet/pkg/agent/api/v1"
)

// NewClient connects to the Signet agent via its Unix socket and returns a gRPC client.
// It checks the SIGNET_AUTH_SOCK environment variable for the socket path.
func NewClient(ctx context.Context) (pb.SignetAgentClient, error) {
	socketPath := os.Getenv("SIGNET_AUTH_SOCK")
	if socketPath == "" {
		return nil, fmt.Errorf("agent not running: SIGNET_AUTH_SOCK environment variable not set")
	}

	// Use a context with a short timeout for the initial connection.
	connCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		connCtx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Block until the connection is established.
	)

	if err != nil {
		return nil, fmt.Errorf("failed to connect to signet agent: %w", err)
	}

	return pb.NewSignetAgentClient(conn), nil
}

// unixDialer is a custom dialer for gRPC to connect to Unix sockets.
func unixDialer(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "unix", addr)
}
