package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// githubUser is the subset of GitHub's /user API response needed for identity.
type githubUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

const (
	githubAPIUserURL      = "https://api.github.com/user"
	githubValidateTimeout = 10 * time.Second
	maxAgentNameLen       = 128
	maxScopeLen           = 512
)

// handleRegister handles POST /api/cert/register for GitHub PAT-based registration.
// This endpoint validates a GitHub Personal Access Token, extracts the user's
// identity, and issues a client certificate bound to the provided public key.
//
// When agent_name is provided, the certificate includes OIDAgentName and
// OIDScope extensions for agent-scoped identity (per docs/design/004-bridge-certs.md).
//
// Request:
//
//	Authorization: Bearer <github_pat>
//	Body: { "public_key": "<PEM>", "agent_name": "<optional>", "scope": "<optional>" }
//
// Response:
//
//	{ "certificate": "<PEM>", "expires_at": "<RFC3339>" }
//
// SECURITY FEATURES:
//   - Request size limiting (prevents DoS via large payloads)
//   - Context timeouts (prevents hanging on slow GitHub API)
//   - Generic error messages (prevents information disclosure)
//   - Public key validation (prevents weak/degenerate keys)
//   - Trust policy check (enforces organizational provisioning)
//   - Rate limiting (applied by caller via middleware)
func (s *OIDCServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// SECURITY: Limit request body size to 1MB
	const maxRequestSize = 1 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	// Extract Bearer token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}
	ghToken := strings.TrimPrefix(authHeader, "Bearer ")
	if ghToken == "" {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req struct {
		PublicKey string `json:"public_key"`
		AgentName string `json:"agent_name,omitempty"`
		Scope     string `json:"scope,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.logger.Warn("Request body too large", "remote_addr", r.RemoteAddr)
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.logger.Error("Failed to parse request", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.PublicKey == "" {
		http.Error(w, "public_key is required", http.StatusBadRequest)
		return
	}

	// Scope requires agent_name (matches client-side guard in auth_register.go)
	if req.AgentName == "" && req.Scope != "" {
		http.Error(w, "scope requires agent_name", http.StatusBadRequest)
		return
	}

	// Field-level size limits (defense-in-depth within the 1MB body limit)
	if len(req.AgentName) > maxAgentNameLen {
		http.Error(w, "agent_name too long", http.StatusBadRequest)
		return
	}
	if len(req.Scope) > maxScopeLen {
		http.Error(w, "scope too long", http.StatusBadRequest)
		return
	}

	// Parse PEM-encoded public key
	deviceKey, err := parsePEMPublicKey([]byte(req.PublicKey))
	if err != nil {
		s.logger.Error("Invalid public key", "error", err, "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid public_key", http.StatusBadRequest)
		return
	}

	// SECURITY: Context timeout for GitHub API validation
	validateCtx, cancel := context.WithTimeout(ctx, githubValidateTimeout)
	defer cancel()

	ghUser, err := validateGitHubPAT(validateCtx, ghToken)
	if err != nil {
		// Generic error — don't leak validation details
		s.logger.Error("GitHub token validation failed",
			"error", err,
			"remote_addr", r.RemoteAddr,
		)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	s.logger.Info("GitHub token validated",
		"login", ghUser.Login,
		"id", ghUser.ID,
		"agent_name", req.AgentName,
	)

	// Build subject from GitHub user ID (matches OIDC subject pattern)
	subject := fmt.Sprintf("github-%d", ghUser.ID)

	// Trust policy bundle check (ADR-011) — same gate as /callback and /exchange-token.
	// In bootstrap mode (no bundle configured), this allows all subjects.
	if _, err := s.policyChecker.CheckSubject(ctx, subject); err != nil {
		s.logger.Warn("Policy check denied registration",
			"subject", subject,
			"login", ghUser.Login,
			"error", err,
		)
		http.Error(w, "Denied by policy", http.StatusForbidden)
		return
	}

	// Build claims — fallback to noreply email if GitHub email is private
	email := ghUser.Email
	if email == "" {
		email = ghUser.Login + "@users.noreply.github.com"
	}
	name := ghUser.Name
	if name == "" {
		name = ghUser.Login
	}
	claims := Claims{
		Email:   email,
		Subject: subject,
		Name:    name,
	}

	// Build agent identity (nil for human certs)
	var agent *AgentIdentity
	if req.AgentName != "" {
		agent = &AgentIdentity{
			Name:  req.AgentName,
			Scope: req.Scope,
		}
	}

	// Mint certificate
	certPEM, err := s.authority.mintClientCertificateWithAgent(claims, deviceKey, agent)
	if err != nil {
		s.logger.Error("Failed to mint certificate",
			"error", err,
			"login", ghUser.Login,
		)
		http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
		return
	}

	// Extract expiry from minted cert for response
	block, _ := pem.Decode(certPEM)
	if block == nil {
		s.logger.Error("mintClientCertificateWithAgent returned invalid PEM")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.logger.Error("Failed to parse minted certificate", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Response format matches certResponse expected by CLI (auth_login.go)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"certificate": string(certPEM),
		"expires_at":  cert.NotAfter.Format(time.RFC3339),
	}); err != nil {
		s.logger.Error("Failed to encode response", "error", err)
	}

	s.logger.Info("Client certificate issued via register",
		"login", ghUser.Login,
		"subject", subject,
		"agent_name", req.AgentName,
		"serial", cert.SerialNumber,
		"expires", cert.NotAfter,
	)
}

// validateGitHubPAT calls GitHub's /user API to validate a PAT and extract identity.
// Returns the authenticated user's profile or an error if the token is invalid.
func validateGitHubPAT(ctx context.Context, token string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "signet-authority/1.0")

	client := &http.Client{Timeout: githubValidateTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if user.ID == 0 || user.Login == "" {
		return nil, fmt.Errorf("incomplete GitHub user response")
	}
	return &user, nil
}

// parsePEMPublicKey decodes a PEM-encoded public key and validates it.
// Supports ECDSA P-256 (WebCrypto/OpenSSL SPKI) and Ed25519 keys.
// Delegates to parsePublicKeyBytes (authority_identity.go) for key validation.
func parsePEMPublicKey(pemData []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
	return parsePublicKeyBytes(block.Bytes)
}
