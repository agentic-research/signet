package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ctLogConfig names the Static CT API log whose SCTs signet requires on the
// authority's certificates (signet-c0d32e). A nil *ctLogConfig means no log
// is configured, and signing keeps today's behaviour: no CT log in the
// trusted root and SCTs ignored at verify.
type ctLogConfig struct {
	// URL is the log's base URL, as cosign's --ctfe url= expects it.
	URL string
	// PublicKeyDER is the log's ECDSA P-256 key as SPKI DER, the value
	// notme pins (base64) as CT_LOG_KEY. Its SHA-256 is the log id.
	PublicKeyDER []byte
	// StartTime is when the log key became valid; cosign requires it.
	StartTime time.Time
}

// parseCTLogConfig turns the three CT log settings into a config. All three
// empty means no log (nil, nil). Any other mix fails closed: a URL without a
// key, or a key without a URL, would otherwise sign with SCT checking off
// while the operator believes it is on.
func parseCTLogConfig(rawURL, publicKey, startTime string) (*ctLogConfig, error) {
	rawURL = strings.TrimSpace(rawURL)
	publicKey = strings.TrimSpace(publicKey)
	startTime = strings.TrimSpace(startTime)
	if rawURL == "" && publicKey == "" && startTime == "" {
		return nil, nil
	}
	var missing []string
	if rawURL == "" {
		missing = append(missing, "--ct-log-url")
	}
	if publicKey == "" {
		missing = append(missing, "--ct-log-public-key")
	}
	if startTime == "" {
		missing = append(missing, "--ct-log-start-time")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("CT log is half-configured: missing %s (set all three CT log settings, or none)", strings.Join(missing, ", "))
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse --ct-log-url: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("--ct-log-url must use https, got %q", parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("--ct-log-url must name a host")
	}
	// cosign's service specification is a comma-separated key=value list.
	if strings.Contains(rawURL, ",") {
		return nil, fmt.Errorf("--ct-log-url must not contain a comma")
	}

	der, err := base64.StdEncoding.Strict().DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("--ct-log-public-key must be base64 SPKI DER: %w", err)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("--ct-log-public-key is not an SPKI public key: %w", err)
	}
	// The Static CT API signs SCTs and checkpoints with ECDSA P-256 only.
	ecKey, ok := parsedKey.(*ecdsa.PublicKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("--ct-log-public-key must be an ECDSA P-256 key")
	}

	start, err := time.Parse(time.RFC3339, startTime)
	if err != nil {
		return nil, fmt.Errorf("--ct-log-start-time must be RFC 3339: %w", err)
	}

	return &ctLogConfig{URL: rawURL, PublicKeyDER: der, StartTime: start.UTC()}, nil
}

// cosignSpec writes the log key as PEM into dir and returns cosign's
// `--ctfe=url=...,public-key=...,start-time=...` argument.
func (c *ctLogConfig) cosignSpec(dir string) (string, error) {
	keyPath := filepath.Join(dir, "ct-log.pub")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: c.PublicKeyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", fmt.Errorf("write temporary CT log public key: %w", err)
	}
	return "--ctfe=url=" + c.URL +
		",public-key=" + keyPath +
		",start-time=" + c.StartTime.Format(time.RFC3339), nil
}
