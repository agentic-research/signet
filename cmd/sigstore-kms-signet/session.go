package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentic-research/signet/pkg/crypto/keys"
)

const (
	sessionSocketEnv     = "SIGNET_KMS_SESSION_SOCKET"
	sessionTokenEnv      = "SIGNET_KMS_SESSION_TOKEN"
	sessionBaseURL       = "http://signet-kms-session"
	sessionPublicKeyPath = "/v1/public-key"
	sessionSignPath      = "/v1/sign"
	sessionHashHeader    = "X-Signet-Signer-Hash"
)

type kmsSession struct {
	dir        string
	socketPath string
	token      string
	server     *http.Server
	listener   net.Listener
	signer     *keys.Ed25519Signer
	closeOnce  sync.Once
	closeErr   error
}

func startKMSSession(signer *keys.Ed25519Signer) (*kmsSession, error) {
	if signer == nil {
		return nil, fmt.Errorf("session signer is required")
	}

	cleanupSigner := true
	defer func() {
		if cleanupSigner {
			signer.Destroy()
		}
	}()

	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("session signer public key is not Ed25519")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal session public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	dir, err := os.MkdirTemp("", "signet-kms-session-")
	if err != nil {
		return nil, fmt.Errorf("create session directory: %w", err)
	}
	cleanupDir := true
	defer func() {
		if cleanupDir {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure session directory: %w", err)
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate session capability: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	for i := range tokenBytes {
		tokenBytes[i] = 0
	}

	socketPath := filepath.Join(dir, "kms.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on session socket: %w", err)
	}
	cleanupListener := true
	defer func() {
		if cleanupListener {
			_ = listener.Close()
		}
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return nil, fmt.Errorf("secure session socket: %w", err)
	}

	mux := http.NewServeMux()
	authorized := func(request *http.Request) bool {
		got := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		return len(got) == len(token) && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
	}
	mux.HandleFunc(sessionPublicKeyPath, func(response http.ResponseWriter, request *http.Request) {
		if !authorized(request) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		if request.Method != http.MethodGet {
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = response.Write(pubPEM)
	})
	mux.HandleFunc(sessionSignPath, func(response http.ResponseWriter, request *http.Request) {
		if !authorized(request) {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		if request.Method != http.MethodPost {
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		message, err := io.ReadAll(io.LimitReader(request.Body, maxSignMessageSize+1))
		if err != nil {
			http.Error(response, "read signing request", http.StatusBadRequest)
			return
		}
		if len(message) > maxSignMessageSize {
			http.Error(response, "message too large", http.StatusRequestEntityTooLarge)
			return
		}
		var signerOpts crypto.SignerOpts = crypto.Hash(0)
		switch request.Header.Get(sessionHashHeader) {
		case "", "none":
		case "sha512":
			signerOpts = &ed25519.Options{Hash: crypto.SHA512}
		default:
			http.Error(response, "unsupported signer hash", http.StatusBadRequest)
			return
		}
		signatureBytes, err := signer.Sign(rand.Reader, message, signerOpts)
		if err != nil {
			http.Error(response, "signing failed", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "application/octet-stream")
		_, _ = response.Write(signatureBytes)
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	session := &kmsSession{
		dir:        dir,
		socketPath: socketPath,
		token:      token,
		server:     server,
		listener:   listener,
		signer:     signer,
	}
	go func() {
		_ = server.Serve(listener)
	}()

	cleanupSigner = false
	cleanupDir = false
	cleanupListener = false
	return session, nil
}

func (s *kmsSession) SocketPath() string {
	return s.socketPath
}

func (s *kmsSession) Token() string {
	return s.token
}

func (s *kmsSession) Close() error {
	s.closeOnce.Do(func() {
		if err := s.server.Close(); err != nil && err != http.ErrServerClosed {
			s.closeErr = err
		}
		_ = s.listener.Close()
		s.signer.Destroy()
		s.token = ""
		if err := os.RemoveAll(s.dir); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

type sessionSigner struct {
	publicKey ed25519.PublicKey
	client    *http.Client
	token     string
}

func newSessionSigner(socketPath, token string) (*sessionSigner, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("%s is required for signet://session", sessionSocketEnv)
	}
	if token == "" {
		return nil, fmt.Errorf("%s is required for signet://session", sessionTokenEnv)
	}

	client := newSessionHTTPClient(socketPath)
	request, err := http.NewRequest(http.MethodGet, sessionBaseURL+sessionPublicKeyPath, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("connect to Signet KMS session: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signet KMS session public key failed: HTTP %d", response.StatusCode)
	}
	publicPEM, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil {
		return nil, fmt.Errorf("read session public key: %w", err)
	}
	block, _ := pem.Decode(publicPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("session returned invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse session public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("session public key is not Ed25519")
	}

	return &sessionSigner{
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		client:    client,
		token:     token,
	}, nil
}

func newSessionHTTPClient(socketPath string) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}

func (s *sessionSigner) Public() crypto.PublicKey {
	return append(ed25519.PublicKey(nil), s.publicKey...)
}

func (s *sessionSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := crypto.Hash(0)
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	if hashFunc != crypto.Hash(0) && hashFunc != crypto.SHA512 {
		return nil, fmt.Errorf("session Ed25519 signer does not support %s", hashFunc)
	}
	if hashFunc == crypto.SHA512 && len(message) != crypto.SHA512.Size() {
		return nil, fmt.Errorf("Ed25519ph requires a %d-byte SHA-512 digest", crypto.SHA512.Size())
	}
	request, err := http.NewRequest(http.MethodPost, sessionBaseURL+sessionSignPath, bytes.NewReader(message))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+s.token)
	request.Header.Set("Content-Type", "application/octet-stream")
	if hashFunc == crypto.SHA512 {
		request.Header.Set(sessionHashHeader, "sha512")
	} else {
		request.Header.Set(sessionHashHeader, "none")
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("signet KMS session signing request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return nil, fmt.Errorf("signet KMS session signing failed: HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	signatureBytes, err := io.ReadAll(io.LimitReader(response.Body, ed25519.SignatureSize+1))
	if err != nil {
		return nil, fmt.Errorf("read session signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("session returned invalid Ed25519 signature length")
	}
	if hashFunc == crypto.SHA512 {
		if err := ed25519.VerifyWithOptions(
			s.publicKey,
			message,
			signatureBytes,
			&ed25519.Options{Hash: crypto.SHA512},
		); err != nil {
			return nil, fmt.Errorf("session returned invalid Ed25519ph signature: %w", err)
		}
	} else if !ed25519.Verify(s.publicKey, message, signatureBytes) {
		return nil, fmt.Errorf("session returned invalid Ed25519 signature")
	}
	return signatureBytes, nil
}

func (s *sessionSigner) Destroy() {
	if transport, ok := s.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	s.token = ""
}
