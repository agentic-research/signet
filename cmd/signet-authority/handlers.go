package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCServer handles OIDC authentication and certificate issuance
type OIDCServer struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	authority    *Authority
	logger       *slog.Logger
	config       *Config
}

// SessionData represents data stored in the session cookie
type SessionData struct {
	State     string `json:"state"`
	DeviceKey string `json:"device_key"`
	CreatedAt int64  `json:"created_at"`
}

// NewOIDCServer initializes the server and its handlers
func NewOIDCServer(config *Config, authority *Authority, logger *slog.Logger) (*OIDCServer, error) {
	// Create a new OIDC provider
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.OIDCProviderURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create a new token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.OIDCClientID,
	})

	// Configure OAuth2
	oauth2Config := oauth2.Config{
		ClientID:     config.OIDCClientID,
		ClientSecret: config.OIDCClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	return &OIDCServer{
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
		authority:    authority,
		logger:       logger,
		config:       config,
	}, nil
}

// handleLogin handles GET /login
// It kicks off the OIDC authentication flow
func (s *OIDCServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Extract the device public key from the query parameter
	deviceKeyParam := r.URL.Query().Get("device_key")
	if deviceKeyParam == "" {
		s.logger.Error("Missing device_key parameter")
		http.Error(w, "device_key parameter is required", http.StatusBadRequest)
		return
	}

	// Decode the base64-URL-encoded public key
	deviceKeyBytes, err := base64.RawURLEncoding.DecodeString(deviceKeyParam)
	if err != nil {
		s.logger.Error("Failed to decode device key", "error", err)
		http.Error(w, "Invalid device_key format", http.StatusBadRequest)
		return
	}

	// Validate the key length (Ed25519 public key is 32 bytes)
	if len(deviceKeyBytes) != ed25519.PublicKeySize {
		s.logger.Error("Invalid device key size", "size", len(deviceKeyBytes))
		http.Error(w, "Invalid device_key size", http.StatusBadRequest)
		return
	}

	// Generate a random state for CSRF protection
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		s.logger.Error("Failed to generate state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Create session data
	sessionData := SessionData{
		State:     state,
		DeviceKey: deviceKeyParam,
		CreatedAt: time.Now().Unix(),
	}

	// Encode session data
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		s.logger.Error("Failed to encode session data", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store session data in a secure HTTP cookie
	cookie := &http.Cookie{
		Name:     "signet_session",
		Value:    base64.RawURLEncoding.EncodeToString(sessionJSON),
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   r.TLS != nil, // Use Secure flag if HTTPS
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Redirect to the OIDC provider
	authURL := s.oauth2Config.AuthCodeURL(state)
	s.logger.Info("Redirecting to OIDC provider",
		"state", state,
		"auth_url", authURL,
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback handles GET /callback
// This is where the OIDC provider redirects after authentication
func (s *OIDCServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get the session cookie
	cookie, err := r.Cookie("signet_session")
	if err != nil {
		s.logger.Error("Missing session cookie", "error", err)
		http.Error(w, "Session expired or invalid", http.StatusUnauthorized)
		return
	}

	// Decode session data
	sessionJSON, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		s.logger.Error("Failed to decode session cookie", "error", err)
		http.Error(w, "Invalid session data", http.StatusUnauthorized)
		return
	}

	var sessionData SessionData
	if err := json.Unmarshal(sessionJSON, &sessionData); err != nil {
		s.logger.Error("Failed to parse session data", "error", err)
		http.Error(w, "Invalid session data", http.StatusUnauthorized)
		return
	}

	// Check session age (max 5 minutes)
	if time.Now().Unix()-sessionData.CreatedAt > 300 {
		s.logger.Error("Session expired")
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}

	// Verify state parameter (CSRF protection)
	state := r.URL.Query().Get("state")
	if state != sessionData.State {
		s.logger.Error("State mismatch", "expected", sessionData.State, "got", state)
		http.Error(w, "Invalid state parameter", http.StatusUnauthorized)
		return
	}

	// Exchange authorization code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		s.logger.Error("Missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		s.logger.Error("Failed to exchange authorization code", "error", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusUnauthorized)
		return
	}

	// Extract the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		s.logger.Error("Missing ID token")
		http.Error(w, "Missing ID token", http.StatusUnauthorized)
		return
	}

	// Verify the ID token
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.logger.Error("Failed to verify ID token", "error", err)
		http.Error(w, "Invalid ID token", http.StatusUnauthorized)
		return
	}

	// Extract claims
	var claims struct {
		Email   string `json:"email"`
		Subject string `json:"sub"`
		Name    string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		s.logger.Error("Failed to extract claims", "error", err)
		http.Error(w, "Failed to extract claims", http.StatusInternalServerError)
		return
	}

	// Decode the device public key
	deviceKeyBytes, err := base64.RawURLEncoding.DecodeString(sessionData.DeviceKey)
	if err != nil {
		s.logger.Error("Failed to decode device key from session", "error", err)
		http.Error(w, "Invalid device key in session", http.StatusInternalServerError)
		return
	}

	devicePublicKey := ed25519.PublicKey(deviceKeyBytes)

	// Mint the client certificate
	certPEM, err := s.authority.MintClientCertificate(
		Claims{
			Email:   claims.Email,
			Subject: claims.Subject,
			Name:    claims.Name,
		},
		devicePublicKey,
	)
	if err != nil {
		s.logger.Error("Failed to mint certificate", "error", err)
		http.Error(w, "Failed to issue certificate", http.StatusInternalServerError)
		return
	}

	// Clear the session cookie
	clearCookie := &http.Cookie{
		Name:     "signet_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, clearCookie)

	// Return the certificate
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="client-cert.pem"`)
	w.WriteHeader(http.StatusOK)
	w.Write(certPEM)

	s.logger.Info("Successfully issued certificate",
		"email", claims.Email,
		"subject", claims.Subject,
	)
}

// handleHealthz handles GET /healthz
func (s *OIDCServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}
