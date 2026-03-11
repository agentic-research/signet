package agent

import (
	"context"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/agentic-research/signet/pkg/agent/api/v1"
)

// AgentClient wraps a gRPC client connection and implements io.Closer.
// This ensures proper resource cleanup even during panics.
type AgentClient struct {
	pb.SignetAgentClient
	conn *grpc.ClientConn
}

// Close closes the underlying gRPC connection.
func (c *AgentClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// NewClient connects to the Signet agent via its Unix socket and returns an AgentClient.
// The caller MUST call Close() when done to avoid leaking the connection.
//
// The provided context is used only for the initial connection establishment (2s timeout).
// Individual RPC calls should use their own context with appropriate timeouts:
//
//	client, err := agent.NewClient(ctx)
//	if err != nil {
//	    return err
//	}
//	defer client.Close()
//
//	// Use per-RPC timeout
//	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
//	defer cancel()
//	resp, err := client.ListIdentities(rpcCtx, &emptypb.Empty{})
func NewClient(ctx context.Context) (*AgentClient, error) {
	socketPath := os.Getenv("SIGNET_AUTH_SOCK")
	if socketPath == "" {
		return nil, fmt.Errorf("agent not running: SIGNET_AUTH_SOCK environment variable not set")
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
		return nil, fmt.Errorf("failed to connect to signet agent: %w", err)
	}

	return &AgentClient{
		SignetAgentClient: pb.NewSignetAgentClient(conn),
		conn:              conn,
	}, nil
}
