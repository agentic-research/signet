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

func main() {
	// Allow socket path to be configured via environment variable.
	// If not set, generate a randomized path in a user-private directory
	// to prevent local attackers from pre-creating the socket.
	socketPath := os.Getenv("SIGNET_SOCKET")
	if socketPath == "" {
		var err error
		socketPath, err = agent_server.DefaultSocketPath()
		if err != nil {
			log.Fatalf("failed to determine socket path: %v", err)
		}
	}

	// Set umask to ensure socket is created with secure permissions (0600)
	// This prevents a race condition between Listen() and Chmod()
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
	const maxMsgSize = 256 * 1024 // 256KB (sufficient for signing operations)
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
		// Keepalive settings to detect and close broken connections
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second, // Ping client if no activity for 30s
			Timeout: 10 * time.Second, // Wait 10s for ping response
		}),
		// Enforcement policy to close connections that violate keepalive
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second, // Min time between client pings
			PermitWithoutStream: true,            // Allow pings without active streams
		}),
	)

	// Create and register the agent server implementation.
	// TODO: Load keys and other resources needed by the server here.
	server := agent_server.NewServer()
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
		fmt.Println("Agent shutdown complete")
	case <-shutdownTimer.C:
		fmt.Println("Graceful shutdown timeout, forcing stop...")
		grpcServer.Stop()
	}
}
