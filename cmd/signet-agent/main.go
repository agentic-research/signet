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

	// Set umask to ensure socket is created with secure permissions (0600)
	// This prevents a race condition between Listen() and Chmod()
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)

	// Try to create the listener, handling EADDRINUSE by removing stale socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		// If socket already exists, try removing it once
		if os.IsExist(err) {
			if removeErr := os.RemoveAll(socketPath); removeErr != nil {
				log.Fatalf("failed to remove stale socket: %v", removeErr)
			}
			// Retry after removal
			listener, err = net.Listen("unix", socketPath)
		}
		if err != nil {
			log.Fatalf("failed to listen on socket: %v", err)
		}
	}

	// Ensure socket and listener are cleaned up on exit
	defer func() {
		listener.Close()
		os.RemoveAll(socketPath)
	}()

	// Create gRPC server with message size limits to prevent DoS
	const maxMsgSize = 4 * 1024 * 1024 // 4MB
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
	)

	// Create and register the agent server implementation.
	// TODO: Load keys and other resources needed by the server here.
	var server *agent_server.Server

	// Use test mode if SIGNET_TEST_MODE is set (for testing only)
	if os.Getenv("SIGNET_TEST_MODE") == "1" {
		server, err = agent_server.NewServerForTesting()
	} else {
		server, err = agent_server.NewServer()
	}

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
