package agent

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jamestexas/signet/pkg/agent/api/v1"
)

// Server implements the SignetAgent gRPC service.
// It holds the resources needed to perform signing operations,
// such as loaded keys and an OIDC token cache.
type Server struct {
	pb.UnimplementedSignetAgentServer

	// identities holds the list of available signing identities
	identities []*pb.Identity

	// TODO: Add fields for key management (e.g., a map of loaded signers)
	// and a cache for OIDC tokens.
}

// NewServer creates a new instance of the agent server.
// For production use - loads real keys from keystore.
func NewServer() *Server {
	// TODO: Initialize key storage and OIDC token cache here.
	// TODO: Load real keys from ~/.signet/keys/ or hardware tokens

	return &Server{
		identities: make([]*pb.Identity, 0),
	}
}

// NewServerForTesting creates a server with dummy test identities.
// This should only be used in tests.
func NewServerForTesting() *Server {
	dummyIdentities := []*pb.Identity{
		{
			Id:      "sha256:abc123def456",
			Comment: "Test Ed25519 key from ~/.signet/keys/id_ed25519",
		},
		{
			Id:      "sha256:789xyz012uvw",
			Comment: "Hardware-backed ECDSA P-256 key (Touch ID)",
		},
	}

	return &Server{
		identities: dummyIdentities,
	}
}

// Sign performs a signing operation using a loaded key.
func (s *Server) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	// Check context cancellation early
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request canceled")
	default:
	}

	// Validate input
	const maxDataSize = 256 * 1024 // 256KB limit
	if len(req.Data) > maxDataSize {
		return nil, status.Errorf(codes.InvalidArgument, "data size %d exceeds maximum %d", len(req.Data), maxDataSize)
	}

	// Validate key_id format if provided
	if req.KeyId != "" && len(req.KeyId) > 100 { // Reasonable limit for key ID
		return nil, status.Error(codes.InvalidArgument, "invalid key_id format")
	}

	// TODO: Implement the signing logic:
	// 1. Select the correct key (default or from req.KeyId).
	// 2. Check context before expensive OIDC operations
	// 3. Check for a cached OIDC token.
	// 4. If no valid token, perform OIDC flow to get one and cache it.
	// 5. Use the OIDC token to mint a Signet certificate.
	// 6. Construct the COSE Sign1 payload with the certificate and req.Data.
	// 7. Sign the payload with the selected key.
	//    SECURITY: Use lifecycle.WithSecureValueResult for key operations:
	//    signature, err := lifecycle.WithSecureValueResult(privateKey, zeroizer,
	//        func(key *ed25519.PrivateKey) ([]byte, error) {
	//            return ed25519.Sign(*key, payload), nil
	//        },
	//    )
	// 8. Return the COSE envelope in the response.
	// SECURITY: Never log key material or sensitive data from req.Data

	return nil, status.Errorf(codes.Unimplemented, "method Sign not implemented")
}

// ListIdentities returns the list of keys available to the agent.
func (s *Server) ListIdentities(ctx context.Context, req *emptypb.Empty) (*pb.ListIdentitiesResponse, error) {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request canceled")
	default:
	}

	// Return the list of identities loaded in the server
	return &pb.ListIdentitiesResponse{
		Identities: s.identities,
	}, nil
}
