package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/agentic-research/signet/pkg/cli/keystore"
)

// authorityPubkey* flags are CLI-only state for `signet authority pubkey`.
var (
	pubkeyURL     string
	pubkeyURLPath string
	pubkeyTimeout time.Duration
)

// authorityPubkeyCmd prints the authority's master Ed25519 public key as
// base64-encoded raw bytes. Consumers (cloister `INTERLACE_ROOT_PUBKEY`,
// notme verifiers) pin this value as their trust anchor.
//
// Two modes:
//
//   - **Local (default):** load from this machine's keystore (OS keyring, or
//     $XDG_CONFIG_HOME/signet/master.key when XDG_CONFIG_HOME is set).
//   - **Remote (--url):** fetch /.well-known/ca-bundle.pem from a running
//     authority — local Go binary OR remote notme worker — and extract
//     the master pubkey from the X.509 CA certificate.
//
// Output: base64-standard-encoded 32-byte Ed25519 raw pubkey, one line, no
// header/footer. Designed to be embedded in shell-glue like
// `INTERLACE_ROOT_PUBKEY=$(signet authority pubkey)`.
var authorityPubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Print the authority's master public key as base64",
	Long: `Print the master Ed25519 public key (base64-encoded raw bytes) that
downstream verifiers (cloister, notme consumers) pin as their trust anchor
(INTERLACE_ROOT_PUBKEY).

By default loads the key from this machine's keystore: the OS keyring, or
$XDG_CONFIG_HOME/signet/master.key when XDG_CONFIG_HOME is set.

With --url, fetches /.well-known/ca-bundle.pem from a running authority
(local Go binary OR remote notme worker), parses the X.509 CA certificate,
and extracts the public key. Use this when bootstrapping a cloister
.env.local from an authority you don't control directly.`,
	Example: `  # Local mode: read from this machine's keystore
  signet authority pubkey

  # Remote mode: fetch from a running authority
  signet authority pubkey --url http://localhost:8080
  signet authority pubkey --url https://auth.notme.bot

  # Wire into a cloister dev bootstrap
  echo "INTERLACE_ROOT_PUBKEY=$(signet authority pubkey)" >> .env.local`,
	RunE:          runAuthorityPubkey,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	authorityPubkeyCmd.Flags().StringVar(&pubkeyURL, "url", "", "Fetch from a running authority (e.g. http://localhost:8080, https://auth.notme.bot)")
	authorityPubkeyCmd.Flags().StringVar(&pubkeyURLPath, "path", "/.well-known/ca-bundle.pem", "URL path to fetch the CA bundle PEM from")
	authorityPubkeyCmd.Flags().DurationVar(&pubkeyTimeout, "timeout", 5*time.Second, "HTTP timeout for --url mode")
	authorityCmd.AddCommand(authorityPubkeyCmd)
}

func runAuthorityPubkey(cmd *cobra.Command, _ []string) error {
	var pubkey []byte
	var err error
	if pubkeyURL == "" {
		pubkey, err = pubkeyFromLocalKeystore()
		if err != nil {
			return fmt.Errorf("local keystore: %w", err)
		}
	} else {
		pubkey, err = pubkeyFromURL(cmd.Context(), pubkeyURL, pubkeyURLPath, pubkeyTimeout)
		if err != nil {
			return fmt.Errorf("fetch from %s: %w", pubkeyURL, err)
		}
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pubkey))
	return nil
}

// pubkeyFromLocalKeystore reads the master Ed25519 public key from the
// active keystore (XDG file or OS keyring, controlled by the existing
// keystore-routing rules) and returns its 32 raw bytes.
func pubkeyFromLocalKeystore() ([]byte, error) {
	signer, err := keystore.LoadMasterKeySecure()
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("master key is not Ed25519 (got %T)", signer.Public())
	}
	return []byte(pub), nil
}

// pubkeyFromURL fetches the CA bundle PEM from a running authority,
// parses the embedded X.509 certificate, and returns the certificate's
// Ed25519 public key as 32 raw bytes.
//
// Body size is capped at 1 MiB — a legitimate CA bundle PEM is well under
// 4 KiB; the cap is a defense against a hostile authority streaming
// arbitrary bytes into the parser.
func pubkeyFromURL(ctx context.Context, base, urlPath string, timeout time.Duration) ([]byte, error) {
	full := strings.TrimRight(base, "/") + urlPath
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", full, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", full, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("response is not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is not Ed25519 (got %T)", cert.PublicKey)
	}
	return []byte(pub), nil
}
