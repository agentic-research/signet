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

	agent_server "github.com/agentic-research/signet/pkg/agent"
	pb "github.com/agentic-research/signet/pkg/agent/api/v1"
)

const defaultSocketPath = "/tmp/signet-agent.sock"

func main() {
	// Allow socket path to be configured via environment variable
	socketPath := os.Getenv("SIGNET_SOCKET")
	if socketPath == "" {
		socketPath = defaultSocketPath
	}

	// Set umask to ensure socket is created with secure permissions (0600)
	oldMask := syscall.Umask(0o077)
	defer syscall.Umask(oldMask)

	// Create the Unix domain socket listener
	// If it fails with "address already in use", check if socket is stale
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		// Only try to remove if we get "address already in use"
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "bind: address already in use" {
			// Test if the socket is stale by attempting to connect
			testConn, testErr := net.Dial("unix", socketPath)
			if testErr != nil {
				// Socket is stale (no process listening), safe to remove
				if removeErr := os.Remove(socketPath); removeErr != nil {
					log.Fatalf("failed to remove stale socket: %v", removeErr)
				}
				// Retry listen after removing stale socket
				listener, err = net.Listen("unix", socketPath)
				if err != nil {
					log.Fatalf("failed to listen on socket %s after cleanup: %v", socketPath, err)
				}
			} else {
				// Another agent is running
				_ = testConn.Close()
				log.Fatalf("another signet-agent is already running on %s", socketPath)
			}
		} else {
			log.Fatalf("failed to listen on socket %s: %v", socketPath, err)
		}
	}

	// Verify socket permissions immediately after listen (before accepting connections)
	info, err := os.Stat(socketPath)
	if err != nil {
		_ = listener.Close()
		log.Fatalf("failed to stat socket: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0o600 {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		log.Fatalf("socket has incorrect permissions %o (expected 0600)", mode)
	}

	// Ensure socket and listener are cleaned up on exit
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
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
	server := agent_server.NewServerForTesting()
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

	// Attempt graceful shutdown with timeout
	shutdownDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(shutdownDone)
	}()

	// Wait up to 5 seconds for graceful shutdown
	shutdownTimer := time.NewTimer(5 * time.Second)
	select {
	case <-shutdownDone:
		shutdownTimer.Stop()
		fmt.Println("Test agent shutdown complete")
	case <-shutdownTimer.C:
		fmt.Println("Graceful shutdown timeout, forcing stop...")
		grpcServer.Stop()
	}
}
