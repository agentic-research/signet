package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/keys"
)

const (
	githubOIDCRequestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	githubOIDCRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	maxEnrollmentResponseSize = 1 << 20
)

type enrollConfig struct {
	AuthorityURL string
	Audience     string
	HTTPClient   *http.Client
	Getenv       func(string) string
}

type enrollment struct {
	Signer                *keys.Ed25519Signer
	SigningCertificatePEM []byte
	CABundlePEM           []byte
	PublicKeyPEM          []byte
	AuthorityURL          string
	Identity              string
	ExpiresAt             time.Time
}

func (e *enrollment) Destroy() {
	if e != nil && e.Signer != nil {
		e.Signer.Destroy()
	}
}

type certPairResponse struct {
	Certificates struct {
		MTLS    string `json:"mtls"`
		Signing string `json:"signing"`
	} `json:"certificates"`
	Identity  string   `json:"identity"`
	Scopes    []string `json:"scopes"`
	ExpiresAt int64    `json:"expires_at"`
	Binding   string   `json:"binding"`
	Authority struct {
		Epoch int    `json:"epoch"`
		KeyID string `json:"key_id"`
	} `json:"authority"`
}

func enrollGitHubSession(ctx context.Context, cfg enrollConfig) (*enrollment, error) {
	authorityURL, err := validateAuthorityURL(cfg.AuthorityURL)
	if err != nil {
		return nil, err
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("OIDC audience is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	oidcToken, err := fetchGitHubOIDCToken(ctx, client, getenv, cfg.Audience)
	if err != nil {
		return nil, err
	}

	mtlsPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral mTLS key: %w", err)
	}
	defer mtlsPrivate.D.SetInt64(0)

	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral signing key: %w", err)
	}
	signer := keys.NewEd25519Signer(signingPrivate)
	keepSigner := false
	defer func() {
		if !keepSigner {
			signer.Destroy()
		}
	}()

	mtlsSPKI, err := x509.MarshalPKIXPublicKey(&mtlsPrivate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal ephemeral mTLS public key: %w", err)
	}
	signingSPKI, err := x509.MarshalPKIXPublicKey(signingPublic)
	if err != nil {
		return nil, fmt.Errorf("marshal ephemeral signing public key: %w", err)
	}
	mtlsPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mtlsSPKI})
	signingPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: signingSPKI})

	oidcHash := sha256.Sum256([]byte(oidcToken))
	bindingInput := make([]byte, 0, len(mtlsSPKI)+len(signingSPKI)+sha256.Size)
	bindingInput = append(bindingInput, mtlsSPKI...)
	bindingInput = append(bindingInput, signingSPKI...)
	bindingInput = append(bindingInput, oidcHash[:]...)
	binding := sha256.Sum256(bindingInput)

	r, s, err := ecdsa.Sign(rand.Reader, mtlsPrivate, binding[:])
	if err != nil {
		return nil, fmt.Errorf("create mTLS proof of possession: %w", err)
	}
	mtlsProof := make([]byte, 64)
	r.FillBytes(mtlsProof[:32])
	s.FillBytes(mtlsProof[32:])
	signingProof, err := signer.Sign(rand.Reader, binding[:], crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("create signing proof of possession: %w", err)
	}

	requestBody, err := json.Marshal(map[string]any{
		"public_keys": map[string]string{
			"mtls":    string(mtlsPEM),
			"signing": string(signingPEM),
		},
		"proofs": map[string]string{
			"mtls":    base64.RawURLEncoding.EncodeToString(mtlsProof),
			"signing": base64.RawURLEncoding.EncodeToString(signingProof),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode certificate exchange: %w", err)
	}

	certURL := appendAuthorityPath(authorityURL, "/cert/gha")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, certURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("build certificate exchange request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+oidcToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "sigstore-kms-signet")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("exchange GitHub OIDC token at %s: %w", certURL, err)
	}
	responseBytes, readErr := readBoundedResponse(response, maxEnrollmentResponseSize)
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certificate exchange failed (HTTP %d): %s", response.StatusCode, strings.TrimSpace(string(responseBytes)))
	}
	var certResponse certPairResponse
	if err := json.Unmarshal(responseBytes, &certResponse); err != nil {
		return nil, fmt.Errorf("decode certificate exchange response: %w", err)
	}
	if certResponse.Certificates.Signing == "" || certResponse.Identity == "" || certResponse.ExpiresAt == 0 {
		return nil, fmt.Errorf("certificate exchange response is missing signing certificate metadata")
	}

	caURL := appendAuthorityPath(authorityURL, "/.well-known/ca-bundle.pem")
	caRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build CA bundle request: %w", err)
	}
	caRequest.Header.Set("Accept", "application/x-pem-file")
	caRequest.Header.Set("User-Agent", "sigstore-kms-signet")
	caResponse, err := client.Do(caRequest)
	if err != nil {
		return nil, fmt.Errorf("fetch authority CA bundle from %s: %w", caURL, err)
	}
	caPEM, readErr := readBoundedResponse(caResponse, maxEnrollmentResponseSize)
	if readErr != nil {
		return nil, readErr
	}
	if caResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authority CA bundle failed (HTTP %d): %s", caResponse.StatusCode, strings.TrimSpace(string(caPEM)))
	}

	leafPEM := []byte(certResponse.Certificates.Signing)
	leaf, err := validateEnrollmentCertificate(leafPEM, caPEM, signingPublic, certResponse.Identity, time.Now())
	if err != nil {
		return nil, err
	}
	responseExpiry := time.Unix(certResponse.ExpiresAt, 0)
	if responseExpiry.After(leaf.NotAfter.Add(time.Second)) || responseExpiry.Before(leaf.NotAfter.Add(-time.Second)) {
		return nil, fmt.Errorf("certificate exchange expiry does not match signing certificate")
	}

	keepSigner = true
	return &enrollment{
		Signer:                signer,
		SigningCertificatePEM: append([]byte(nil), leafPEM...),
		CABundlePEM:           append([]byte(nil), caPEM...),
		PublicKeyPEM:          append([]byte(nil), signingPEM...),
		AuthorityURL:          authorityURL.String(),
		Identity:              certResponse.Identity,
		ExpiresAt:             leaf.NotAfter,
	}, nil
}

func fetchGitHubOIDCToken(ctx context.Context, client *http.Client, getenv func(string) string, audience string) (string, error) {
	requestURL := getenv(githubOIDCRequestURLEnv)
	requestToken := getenv(githubOIDCRequestTokenEnv)
	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("GitHub Actions ambient OIDC is unavailable; grant the job permissions: id-token: write")
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse GitHub OIDC request URL: %w", err)
	}
	query := parsed.Query()
	query.Set("audience", audience)
	parsed.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", fmt.Errorf("build GitHub OIDC request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+requestToken)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("request GitHub OIDC token: %w", err)
	}
	responseBytes, readErr := readBoundedResponse(response, maxEnrollmentResponseSize)
	if readErr != nil {
		return "", readErr
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub OIDC token request failed (HTTP %d): %s", response.StatusCode, strings.TrimSpace(string(responseBytes)))
	}
	var tokenResponse struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(responseBytes, &tokenResponse); err != nil {
		return "", fmt.Errorf("decode GitHub OIDC token response: %w", err)
	}
	if tokenResponse.Value == "" {
		return "", fmt.Errorf("GitHub OIDC token response is empty")
	}
	return tokenResponse.Value, nil
}

func validateAuthorityURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse authority URL: %w", err)
	}
	if parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("authority URL must be an absolute HTTP(S) URL without userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("authority URL must not contain a query or fragment")
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("authority URL must use HTTPS unless it targets localhost")
		}
	}
	return parsed, nil
}

func appendAuthorityPath(authority *url.URL, suffix string) string {
	copyURL := *authority
	copyURL.Path = strings.TrimRight(copyURL.Path, "/") + suffix
	return copyURL.String()
}

func readBoundedResponse(response *http.Response, maximum int64) ([]byte, error) {
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("HTTP response exceeds %d bytes", maximum)
	}
	return data, nil
}

func validateEnrollmentCertificate(leafPEM, caPEM []byte, signingPublic ed25519.PublicKey, identity string, now time.Time) (*x509.Certificate, error) {
	leafBlock, rest := pem.Decode(leafPEM)
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("authority returned invalid signing certificate PEM")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing certificate: %w", err)
	}
	leafPublic, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing certificate public key is not Ed25519")
	}
	if len(leafPublic) != len(signingPublic) || subtle.ConstantTimeCompare(leafPublic, signingPublic) != 1 {
		return nil, fmt.Errorf("signing certificate public key does not match ephemeral signing key")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("signing certificate is not currently valid")
	}
	identityFound := false
	for _, uri := range leaf.URIs {
		if uri.String() == identity {
			identityFound = true
			break
		}
	}
	if !identityFound {
		return nil, fmt.Errorf("signing certificate does not contain issued identity %q", identity)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	remaining := caPEM
	caCount := 0
	for len(remaining) > 0 {
		block, next := pem.Decode(remaining)
		if block == nil {
			if strings.TrimSpace(string(remaining)) != "" {
				return nil, fmt.Errorf("authority returned invalid CA bundle PEM")
			}
			break
		}
		remaining = next
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("authority CA bundle contains %q PEM block", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse authority CA certificate: %w", err)
		}
		if !certificate.IsCA {
			return nil, fmt.Errorf("authority CA bundle contains a non-CA certificate")
		}
		roots.AddCert(certificate)
		intermediates.AddCert(certificate)
		caCount++
	}
	if caCount == 0 {
		return nil, fmt.Errorf("authority CA bundle is empty")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("verify signing certificate against authority CA bundle: %w", err)
	}
	return leaf, nil
}
