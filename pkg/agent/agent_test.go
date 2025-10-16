package agent_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jamestexas/signet/pkg/agent"
	pb "github.com/jamestexas/signet/pkg/agent/api/v1"
)

func TestListIdentities(t *testing.T) {
	// Create a temporary socket path for this test
	socketPath := fmt.Sprintf("/tmp/signet-agent-test-%d.sock", os.Getpid())
	defer os.RemoveAll(socketPath)

	// Start the gRPC server
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on socket: %v", err)
	}
	defer listener.Close()

	grpcServer := grpc.NewServer()
	server, err := agent.NewServerForTesting()
	if err != nil {
		t.Fatalf("failed to create agent server: %v", err)
	}
	pb.RegisterSignetAgentServer(grpcServer, server)

	// Start server in background
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()
	defer grpcServer.GracefulStop()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("failed to connect to agent: %v", err)
	}
	defer conn.Close()

	client := pb.NewSignetAgentClient(conn)

	// Call ListIdentities
	resp, err := client.ListIdentities(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListIdentities failed: %v", err)
	}

	// Verify the response
	if len(resp.Identities) == 0 {
		t.Fatal("expected at least one identity, got zero")
	}

	t.Logf("Found %d identities:", len(resp.Identities))
	for i, identity := range resp.Identities {
		t.Logf("  [%d] ID: %s", i, identity.Id)
		t.Logf("      Comment: %s", identity.Comment)

		// Verify fields are populated
		if identity.Id == "" {
			t.Errorf("identity %d has empty ID", i)
		}
		if identity.Comment == "" {
			t.Errorf("identity %d has empty comment", i)
		}
	}

	// Verify we got the expected dummy identities
	expectedIDs := map[string]bool{
		"sha256:abc123def456": false,
		"sha256:789xyz012uvw": false,
	}

	for _, identity := range resp.Identities {
		if _, ok := expectedIDs[identity.Id]; ok {
			expectedIDs[identity.Id] = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected identity with ID %s not found", id)
		}
	}
}
