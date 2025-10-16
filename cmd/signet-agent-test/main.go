// Package main provides a test version of the signet-agent for manual testing.
// This binary uses the NewServerForTesting() constructor with dummy identities.
// DO NOT use this in production.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	agent_server "github.com/jamestexas/signet/pkg/agent"
	pb "github.com/jamestexas/signet/pkg/agent/api/v1"
)

const defaultSocketPath = "/tmp/signet-agent.sock"

func main() {
	// Allow socket path to be configured via environment variable
	socketPath := os.Getenv("SIGNET_SOCKET")
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	// Set umask to ensure socket is created with secure permissions (0600)
	oldMask := syscall.Umask(0077)
	defer syscall.Umask(oldMask)

	// Remove any stale socket before attempting to create a new one
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to remove stale socket: %v", err)
	}

	// Create the Unix domain socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("failed to listen on socket %s: %v", socketPath, err)
	}

	// Ensure socket and listener are cleaned up on exit
	defer func() {
		listener.Close()
		os.Remove(socketPath)
	}()

	// Create gRPC server with security-focused settings
	const maxMsgSize = 256 * 1024 // 256KB
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	// Use the TESTING server with dummy identities
	server, err := agent_server.NewServerForTesting()
	if err != nil {
		log.Fatalf("failed to create test agent server: %v", err)
	}
	pb.RegisterSignetAgentServer(grpcServer, server)

	// Start serving gRPC requests
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	fmt.Printf("TEST Signet agent listening on %s\n", socketPath)
	fmt.Printf("Run `export SIGNET_AUTH_SOCK=%s` to use the agent.\n", socketPath)
	fmt.Printf("\n⚠️  WARNING: This is a TEST agent with dummy identities. DO NOT use in production!\n\n")

	// Wait for a shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down test agent...")
	grpcServer.GracefulStop()
}
