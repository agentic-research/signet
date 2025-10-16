package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	agent_server "github.com/jamestexas/signet/pkg/agent"
	pb "github.com/jamestexas/signet/pkg/agent/api/v1"
)

// TODO: Make this configurable
const defaultSocketPath = "/tmp/signet-agent.sock"

func main() {
	// Allow socket path to be configured via environment variable
	socketPath := os.Getenv("SIGNET_SOCKET")
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	// Clean up the socket file on startup, in case of a previous crash.
	if err := os.RemoveAll(socketPath); err != nil {
		log.Fatalf("failed to remove old socket: %v", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("failed to listen on socket: %v", err)
	}

	// Set socket permissions to be user-only.
	if err := os.Chmod(socketPath, 0600); err != nil {
		log.Fatalf("failed to set socket permissions: %v", err)
	}

	grpcServer := grpc.NewServer()

	// Create and register the agent server implementation.
	// TODO: Load keys and other resources needed by the server here.
	server, err := agent_server.NewServer()
	if err != nil {
		log.Fatalf("failed to create agent server: %v", err)
	}
	pb.RegisterSignetAgentServer(grpcServer, server)

	// Start serving gRPC requests.
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	fmt.Printf("Signet agent listening on %s\n", socketPath)
	fmt.Printf("Run `export SIGNET_AUTH_SOCK=%s` to use the agent.\n", socketPath)

	// Wait for a shutdown signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down agent...")
	grpcServer.GracefulStop()
}
