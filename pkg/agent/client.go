package agent

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/jamestexas/signet/pkg/agent/api/v1"
)

// NewClient connects to the Signet agent via its Unix socket and returns a gRPC client
// and a cleanup function. The caller MUST call the cleanup function when done to avoid
// leaking the connection.
//
// The provided context is used only for the initial connection establishment (2s timeout).
// Individual RPC calls should use their own context with appropriate timeouts:
//
//	client, cleanup, err := agent.NewClient(ctx)
//	if err != nil {
//	    return err
//	}
//	defer cleanup()
//
//	// Use per-RPC timeout
//	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
//	defer cancel()
//	resp, err := client.ListIdentities(rpcCtx, &emptypb.Empty{})
func NewClient(ctx context.Context) (pb.SignetAgentClient, func(), error) {
	socketPath := os.Getenv("SIGNET_AUTH_SOCK")
	if socketPath == "" {
		return nil, nil, fmt.Errorf("agent not running: SIGNET_AUTH_SOCK environment variable not set")
	}

	// Use a context with a short timeout for the initial connection only.
	// This does NOT affect individual RPC timeouts.
	connCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		connCtx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Block until the connection is established.
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to signet agent: %w", err)
	}

	cleanup := func() {
		conn.Close()
	}

	return pb.NewSignetAgentClient(conn), cleanup, nil
}
