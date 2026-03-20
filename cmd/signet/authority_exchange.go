package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/agentic-research/signet/pkg/cli/styles"
	"github.com/spf13/cobra"
)

var (
	exchangeAuthorityURL string
	exchangeToken        string
	exchangeOutput       string
	exchangeAuto         bool
	exchangeKeyOutput    string
)

var exchangeGitHubTokenCmd = &cobra.Command{
	Use:   "exchange-github-token",
	Short: "Exchange a GitHub Actions OIDC token for a bridge certificate",
	Long: `Exchange a GitHub Actions OIDC token for a Signet bridge certificate.

This command is designed for use in GitHub Actions workflows. It exchanges
the workflow's ambient OIDC credentials for a short-lived Signet bridge
certificate that can be used for artifact signing.

` + styles.Success.Render("Modes:") + `
  --token   Provide an explicit OIDC token string
  --auto    Auto-detect GitHub Actions environment variables`,
	Example: `  # With explicit token
  signet authority exchange-github-token \
    --authority-url https://signet-authority.example.com \
    --token "$GITHUB_OIDC_TOKEN" \
    --output ~/.signet/bridge-cert.pem

  # With ambient detection in GitHub Actions
  signet authority exchange-github-token \
    --authority-url https://signet-authority.example.com \
    --auto \
    --output ~/.signet/bridge-cert.pem`,
	RunE: runExchangeGitHubToken,
}

func init() {
	f := exchangeGitHubTokenCmd.Flags()
	f.StringVar(&exchangeAuthorityURL, "authority-url", "", "Signet authority server URL (required)")
	f.StringVar(&exchangeToken, "token", "", "GitHub OIDC token")
	f.StringVar(&exchangeOutput, "output", "", "Output path for bridge certificate PEM (required)")
	f.BoolVar(&exchangeAuto, "auto", false, "Auto-detect GitHub Actions OIDC environment")
	f.StringVar(&exchangeKeyOutput, "key-output", "", "Output path for ephemeral private key (default: <output-dir>/ephemeral-key.pem)")

	_ = exchangeGitHubTokenCmd.MarkFlagRequired("authority-url")
	_ = exchangeGitHubTokenCmd.MarkFlagRequired("output")

	authorityCmd.AddCommand(exchangeGitHubTokenCmd)
}

func runExchangeGitHubToken(cmd *cobra.Command, _ []string) error {
	token, err := resolveOIDCToken()
	if err != nil {
		return err
	}

	// Generate ephemeral Ed25519 keypair with zeroization on exit
	ephPub, ephPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}
	defer zeroKey(ephPriv)

	ephPubB64 := base64.RawURLEncoding.EncodeToString(ephPub)

	// POST to authority
	reqBody, err := json.Marshal(map[string]string{
		"token":         token,
		"ephemeral_key": ephPubB64,
		"provider_hint": "github-actions",
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := exchangeAuthorityURL + "/exchange-token"
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("authority unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token rejected (HTTP %d): %s", resp.StatusCode, bytes.TrimSpace(body))
	}

	// Parse response — authority may return JSON with a certificate field
	// or raw PEM depending on implementation phase.
	certPEM := extractCertPEM(body)
	if certPEM == nil {
		return fmt.Errorf("invalid response: no certificate in authority reply")
	}

	// Ensure output directory exists
	outDir := filepath.Dir(exchangeOutput)
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write certificate
	if err := os.WriteFile(exchangeOutput, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write ephemeral private key
	keyPath := exchangeKeyOutput
	if keyPath == "" {
		keyPath = filepath.Join(outDir, "ephemeral-key.pem")
	}
	// Ensure key output directory exists (may differ from cert output dir)
	if keyDir := filepath.Dir(keyPath); keyDir != outDir {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return fmt.Errorf("failed to create key output directory: %w", err)
		}
	}
	keyPEM, err := marshalEd25519PrivateKey(ephPriv)
	if err != nil {
		return fmt.Errorf("failed to marshal ephemeral key: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write ephemeral key: %w", err)
	}
	// Zeroize PEM bytes after writing
	for i := range keyPEM {
		keyPEM[i] = 0
	}

	// Status to stderr only (stdout purity)
	fmt.Fprintln(os.Stderr, styles.Success.Render("✓")+" Bridge certificate saved")
	fmt.Fprintln(os.Stderr, styles.Subtle.Render("  Cert: ")+styles.Code.Render(exchangeOutput))
	fmt.Fprintln(os.Stderr, styles.Subtle.Render("  Key:  ")+styles.Code.Render(keyPath))
	return nil
}

// resolveOIDCToken returns the OIDC token from --token flag or --auto env detection.
func resolveOIDCToken() (string, error) {
	if exchangeToken != "" {
		return exchangeToken, nil
	}
	if !exchangeAuto {
		return "", fmt.Errorf("either --token or --auto is required")
	}

	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return "", fmt.Errorf("--auto requires GitHub Actions environment (ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN must be set)")
	}

	// Append audience parameter using proper URL parsing
	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("invalid OIDC request URL: %w", err)
	}
	q := parsedURL.Query()
	q.Set("audience", exchangeAuthorityURL)
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to build OIDC request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC token request failed (HTTP %d)", resp.StatusCode)
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse OIDC token response: %w", err)
	}
	if result.Value == "" {
		return "", fmt.Errorf("empty OIDC token in response")
	}
	return result.Value, nil
}

// extractCertPEM extracts a PEM certificate from the authority response body.
// It handles both raw PEM responses and JSON responses with a "certificate" field.
func extractCertPEM(body []byte) []byte {
	// Try raw PEM first
	if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
		return body
	}

	// Try JSON envelope
	var envelope struct {
		Certificate string `json:"certificate"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Certificate != "" {
		pemBytes := []byte(envelope.Certificate)
		if block, _ := pem.Decode(pemBytes); block != nil && block.Type == "CERTIFICATE" {
			return pemBytes
		}
	}
	return nil
}

// marshalEd25519PrivateKey encodes an Ed25519 private key as PKCS#8 PEM.
// Zeroizes intermediate DER bytes after PEM encoding.
func marshalEd25519PrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	// Zeroize DER after encoding
	for i := range der {
		der[i] = 0
	}
	return pemBytes, nil
}

// zeroKey overwrites an Ed25519 private key with zeros.
func zeroKey(key ed25519.PrivateKey) {
	for i := range key {
		key[i] = 0
	}
}
