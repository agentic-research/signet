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
func NewServer() (*Server, error) {
	// TODO: Initialize key storage and OIDC token cache here.

	// Initialize with some dummy identities for testing
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
	}, nil
}

// Sign performs a signing operation using a loaded key.
func (s *Server) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	// TODO: Implement the signing logic:
	// 1. Select the correct key (default or from req.KeyId).
	// 2. Check for a cached OIDC token.
	// 3. If no valid token, perform OIDC flow to get one and cache it.
	// 4. Use the OIDC token to mint a Signet certificate.
	// 5. Construct the COSE Sign1 payload with the certificate and req.Data.
	// 6. Sign the payload with the selected key.
	// 7. Return the COSE envelope in the response.

	return nil, status.Errorf(codes.Unimplemented, "method Sign not implemented")
}

// ListIdentities returns the list of keys available to the agent.
func (s *Server) ListIdentities(ctx context.Context, req *emptypb.Empty) (*pb.ListIdentitiesResponse, error) {
	// Return the list of identities loaded in the server
	return &pb.ListIdentitiesResponse{
		Identities: s.identities,
	}, nil
}
