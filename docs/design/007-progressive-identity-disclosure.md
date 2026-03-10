# 007: Progressive Identity Disclosure

**Status**: Draft
**Author**: James Gardner
**Date**: 2026-02-10
**Supersedes**: N/A
**Related**: [002-linked-key-pop.md](./002-linked-key-pop.md), [006-revocation.md](./006-revocation.md)

## Problem Statement

Signet currently conflates two distinct identity concepts under a single master key:

1. **Machine Authentication**: Proving a request comes from an authorized service/workstation
   - Used for: HTTP auth, service-to-service communication, API requests
   - Needs: Proof of possession, replay protection, revocation
   - Should NOT leak: User personally identifiable information (PII)

2. **User Attribution**: Proving WHO authored specific work
   - Used for: Git commits, signed documents, audit trails
   - Needs: Human-readable identity (email), public verification, accountability
   - Requirements: GitHub "Verified" badges, legal attribution, compliance

**The Tension**:
- If master key = user identity → HTTP requests leak user emails unnecessarily (privacy issue)
- If master key = machine identity → Git commits don't get GitHub verification (usability issue)

**Current Behavior**: Users must choose between privacy (machine-only) or GitHub integration (user attribution), but cannot have both.

## Design Goals

1. **Progressive Disclosure**: Start simple (machine identity), opt-in to complexity (user attribution)
2. **Privacy by Default**: HTTP auth never leaks user identity unless explicitly required
3. **GitHub Compatible**: Support verified badges without compromising architecture
4. **Backward Compatible**: Existing Level 0 workflows continue to work unchanged
5. **Clear Separation**: Machine capability ≠ User accountability
6. **Offline-First**: All levels work without network connectivity for signing

## Solution: Layered Identity Architecture

### Overview

```
Machine Master Key (base identity, always present)
    │
    ├─> HTTP Auth: Machine proof only
    │   └─> Authenticated as: "workstation-alice-mbp"
    │
    ├─> Service-to-Service: Machine identity
    │   └─> Authenticated as: "api-service-prod"
    │
    └─> Git Commits: Machine + Optional User Attribution
        └─> Bridge Cert (alice@company.com) [OPTIONAL]
            └─> Ephemeral Cert (5 min)
                └─> Commit signature
```

### Identity Layers

**Layer 1: Machine Identity** (always present)
- Master key stored in OS keyring
- Identified by: DID or machine hostname
- Used for: All cryptographic operations
- Privacy: No user PII

**Layer 2: User Attribution Overlay** (optional)
- Bridge certificate with email address
- Signed by machine master key
- Used for: Git commits only
- Storage: `~/.signet/git/bridge-cert.pem`

## Progressive Disclosure Levels

### Level 0: "It Just Works" (Machine Identity Only)

**Setup:**
```bash
signet-git init
git config --global gpg.format x509
git config --global gpg.x509.program signet-git
git commit -S -m "fix bug"
```

**What You Get:**
- ✅ Cryptographically signed commits
- ✅ Local verification works (`git log --show-signature`)
- ✅ Offline-first
- ✅ Sub-millisecond signing
- ✅ Privacy preserved (no user email)
- ❌ No GitHub "Verified" badge

**Certificate Chain:**
```
Master Key (10yr CA, DID: did:key:z6Mkr...)
    └─> Ephemeral Cert (5min, CN: "Signet Ephemeral")
        └─> Commit Signature
```

**Who Uses This:**
- Privacy-conscious developers
- Internal company repos with custom verification
- Air-gapped environments
- Developers who don't need GitHub badges

---

### Level 1: User Attribution (Local Verification)

**Setup:**
```bash
signet-git init --email alice@company.com
git commit -S -m "fix bug"
git log --show-signature
```

**What You Get:**
- ✅ Everything from Level 0
- ✅ Email in bridge certificate (user attribution)
- ✅ Local git shows "alice@company.com signed"
- ✅ Self-hosted Git platforms can verify
- ❌ No GitHub badge (cert not uploaded)

**Certificate Chain:**
```
Master Key (10yr CA, DID: did:key:z6Mkr...)
    └─> Bridge Cert (1yr, CN: alice@company.com, Email: alice@company.com)
        └─> Ephemeral Cert (5min, signed by bridge)
            └─> Commit Signature
```

**Who Uses This:**
- Teams using git's built-in verification
- Self-hosted GitLab/Gitea instances
- Developers testing before uploading to GitHub
- Hybrid environments (some repos public, some private)

---

### Level 2: GitHub Integration (Public Verification)

**Setup:**
```bash
signet-git init --email alice@company.com
signet-git export-bridge-cert > bridge.pem

# Upload bridge.pem to GitHub Settings → SSH and GPG keys
git commit -S -m "fix bug"
git push
```

**What You Get:**
- ✅ Everything from Level 1
- ✅ Green "Verified" badge on GitHub
- ✅ Public proof of authorship
- ✅ Commit history shows verified badges

**GitHub Verification Flow:**
1. GitHub extracts CMS signature from commit
2. Finds certificate chain: ephemeral + bridge
3. Verifies ephemeral cert signed by bridge cert
4. Checks bridge cert fingerprint against uploaded cert
5. Validates email in bridge cert matches commit author
6. Displays "Verified" badge

**Who Uses This:**
- Open source maintainers
- Teams requiring GitHub badges for compliance
- Public repositories needing visible verification
- Developers working across public/private repos

---

### Level 3: Enterprise PKI (Future)

**Setup:**
```bash
# Company-issued bridge cert via OIDC
signet-git init --oidc https://company.okta.com

# Automated provisioning:
# - Fetches user email from OIDC claims
# - Creates bridge cert with corporate CA
# - Auto-rotates yearly
# - Revocation via company CA bundle
```

**What You Get:**
- ✅ Everything from Level 2
- ✅ Centralized identity management
- ✅ Automated rotation/revocation
- ✅ Compliance-friendly audit trails
- ✅ Integration with corporate SSO

**Who Uses This:**
- Large enterprises with PKI infrastructure
- Regulated industries (finance, healthcare)
- Companies requiring centralized key management
- Organizations with compliance mandates

**Note**: Level 3 is future work, not included in initial implementation.

## Technical Architecture

### File Structure

```
~/.signet/
├── master.key              # Machine identity (keyring or file)
├── config.json             # Machine configuration
│   {
│     "issuer_did": "did:key:z6Mkr...",
│     "machine_id": "workstation-alice-mbp",
│     "cert_validity_minutes": 5
│   }
│
└── git/                    # Git-specific overlay (OPTIONAL)
    ├── bridge-cert.pem     # User attribution cert (Level 1+)
    ├── bridge-key.pem      # Bridge cert private key
    └── config.json         # Git user configuration
        {
          "user_email": "alice@company.com",
          "bridge_cert_validity_days": 365
        }
```

### Certificate Architecture

**Level 0 (Machine Only):**
```
┌─────────────────────────────────────┐
│ Master Key (CA)                     │
│ CN: did:key:z6Mkr...                │
│ Validity: 10 years                  │
│ IsCA: true                          │
└──────────────┬──────────────────────┘
               │ signs
               ▼
┌─────────────────────────────────────┐
│ Ephemeral Cert                      │
│ CN: "Signet Ephemeral"              │
│ Validity: 5 minutes                 │
│ ExtKeyUsage: CodeSigning            │
└──────────────┬──────────────────────┘
               │ signs
               ▼
         Git Commit Data
```

**Level 1+ (User Attribution):**
```
┌─────────────────────────────────────┐
│ Master Key (CA)                     │
│ CN: did:key:z6Mkr...                │
│ Validity: 10 years                  │
│ IsCA: true                          │
└──────────────┬──────────────────────┘
               │ signs
               ▼
┌─────────────────────────────────────┐
│ Bridge Cert (Intermediate CA)       │
│ CN: alice@company.com               │
│ EmailAddresses: [alice@company.com] │  ← GitHub reads this
│ Validity: 1 year                    │
│ IsCA: true                          │  ← Can sign ephemeral certs
└──────────────┬──────────────────────┘
               │ signs
               ▼
┌─────────────────────────────────────┐
│ Ephemeral Cert                      │
│ CN: alice@company.com               │
│ Validity: 5 minutes                 │
│ ExtKeyUsage: CodeSigning            │
└──────────────┬──────────────────────┘
               │ signs
               ▼
         Git Commit Data
```

### Code Structure

#### New File: `pkg/git/identity.go`

```go
package git

import (
    "crypto/x509"
    "github.com/agentic-research/signet/pkg/crypto/keys"
)

// Identity represents a signing identity with optional user attribution.
type Identity struct {
    // Machine identity (always present, Level 0+)
    MasterKey *keys.Ed25519Signer
    MachineID string // "workstation-alice-mbp" or DID

    // User attribution overlay (optional, Level 1+)
    UserEmail  string              // "alice@company.com"
    BridgeCert *x509.Certificate   // Certificate with email
    BridgeKey  *keys.SecurePrivateKey
}

// Level returns the identity disclosure level (0, 1, or 2).
func (i *Identity) Level() int {
    if i.BridgeCert == nil {
        return 0 // Machine only
    }
    // Level 1 vs 2 determined by whether cert is uploaded to GitHub
    // (we can't detect this locally, so return 1)
    return 1 // User attribution present
}

// HasUserAttribution returns true if user attribution is configured.
func (i *Identity) HasUserAttribution() bool {
    return i.UserEmail != "" && i.BridgeCert != nil
}

// LoadIdentity loads the signing identity from configuration.
func LoadIdentity(cfg *config.Config) (*Identity, error) {
    // Always load machine master key (Level 0)
    masterKey, err := keystore.LoadMasterKeySecure()
    if err != nil {
        // Fallback to insecure file-based storage
        masterKey, err = keystore.LoadMasterKeyInsecure(cfg.Home)
        if err != nil {
            return nil, fmt.Errorf("failed to load master key: %w", err)
        }
    }

    identity := &Identity{
        MasterKey: masterKey,
        MachineID: cfg.IssuerDID,
    }

    // Try to load user attribution overlay (Level 1+)
    gitConfigPath := filepath.Join(cfg.Home, "git", "config.json")
    if fileExists(gitConfigPath) {
        gitCfg, err := loadGitConfig(gitConfigPath)
        if err != nil {
            // Non-fatal: just means Level 0
            return identity, nil
        }

        // Load bridge certificate and key
        bridgeCertPath := filepath.Join(cfg.Home, "git", "bridge-cert.pem")
        bridgeKeyPath := filepath.Join(cfg.Home, "git", "bridge-key.pem")

        if fileExists(bridgeCertPath) && fileExists(bridgeKeyPath) {
            identity.UserEmail = gitCfg.UserEmail
            identity.BridgeCert, err = loadCertificate(bridgeCertPath)
            if err != nil {
                return nil, fmt.Errorf("failed to load bridge cert: %w", err)
            }
            identity.BridgeKey, err = loadBridgeKey(bridgeKeyPath)
            if err != nil {
                return nil, fmt.Errorf("failed to load bridge key: %w", err)
            }
        }
    }

    return identity, nil
}
```

#### Updated: `pkg/git/sign.go`

```go
func SignCommit(cfg *config.Config, localUser string, statusFd int) error {
    // Load identity (machine + optional user attribution)
    identity, err := LoadIdentity(cfg)
    if err != nil {
        return fmt.Errorf("failed to load identity: %w", err)
    }

    // Read commit data from stdin
    commitData, err := io.ReadAll(os.Stdin)
    if err != nil {
        return fmt.Errorf("failed to read commit data: %w", err)
    }

    // Route to appropriate signing method based on identity level
    if identity.HasUserAttribution() {
        return signWithUserAttribution(identity, commitData, statusFd)
    }
    return signWithMachineIdentity(identity, commitData, statusFd)
}

// signWithMachineIdentity signs using only the machine master key (Level 0).
func signWithMachineIdentity(identity *Identity, data []byte, statusFd int) error {
    return withMasterKey(cfg, func(masterKey *keys.Ed25519Signer) error {
        ca := attestx509.NewLocalCA(masterKey, identity.MachineID)
        certValidity := 5 * time.Minute

        cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(certValidity)
        if err != nil {
            return fmt.Errorf("failed to generate ephemeral cert: %w", err)
        }
        defer secEphemeralKey.Destroy()

        // Sign with CMS (no intermediate certs)
        return signAndOutput(data, cert, secEphemeralKey.Key(), nil, statusFd)
    })
}

// signWithUserAttribution signs using bridge cert chain (Level 1+).
func signWithUserAttribution(identity *Identity, data []byte, statusFd int) error {
    // Create LocalCA using the BRIDGE cert as the issuer
    ca := attestx509.NewLocalCA(
        identity.BridgeKey, // Bridge key acts as CA for ephemeral certs
        identity.UserEmail,
    )

    certValidity := 5 * time.Minute

    // Generate ephemeral cert signed by bridge cert
    cert, _, secEphemeralKey, err := ca.IssueCodeSigningCertificateSecure(certValidity)
    if err != nil {
        return fmt.Errorf("failed to generate ephemeral cert: %w", err)
    }
    defer secEphemeralKey.Destroy()

    // Sign with CMS, including bridge cert in chain
    intermediateCerts := []*x509.Certificate{identity.BridgeCert}
    return signAndOutput(data, cert, secEphemeralKey.Key(), intermediateCerts, statusFd)
}

// signAndOutput creates CMS signature and writes to stdout.
func signAndOutput(data []byte, cert *x509.Certificate, privateKey ed25519.PrivateKey,
                   intermediateCerts []*x509.Certificate, statusFd int) error {
    // Emit BEGIN_SIGNING status
    if statusFd > 0 {
        statusFile := os.NewFile(uintptr(statusFd), "status")
        if statusFile != nil {
            fmt.Fprintln(statusFile, "[GNUPG:] BEGIN_SIGNING")
        }
    }

    // Create CMS signature
    opts := cms.SignOptions{
        IntermediateCerts: intermediateCerts, // nil for Level 0, [bridgeCert] for Level 1+
    }

    signature, err := cms.SignDataWithOptions(data, cert, privateKey, opts)
    if err != nil {
        return fmt.Errorf("failed to sign commit: %w", err)
    }

    // Emit SIG_CREATED status
    if statusFd > 0 {
        statusFile := os.NewFile(uintptr(statusFd), "status")
        if statusFile != nil {
            timestamp := time.Now().Unix()
            fpr := certHexFingerprint(cert)
            fmt.Fprintf(statusFile, "[GNUPG:] SIG_CREATED D 22 8 00 %d %s\n", timestamp, fpr)
        }
    }

    // Output PEM-encoded signature
    pemBlock := &pem.Block{
        Type:  "SIGNED MESSAGE",
        Bytes: signature,
    }
    return pem.Encode(os.Stdout, pemBlock)
}
```

#### New File: `pkg/attest/x509/bridge.go`

```go
package x509

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "fmt"
    "math/big"
    "time"
)

// IssueBridgeCertificate creates a bridge certificate for user attribution.
//
// The bridge certificate:
// - Contains user email in Subject CN and EmailAddresses SAN
// - Is signed by the master key (machine identity)
// - Can issue ephemeral certificates (IsCA: true)
// - Has longer validity (1 year default) for GitHub upload
// - Enables GitHub "Verified" badges when uploaded
//
// Returns the certificate, DER bytes, and a secure private key wrapper.
// The private key is independent from the master key to enable rotation.
func (ca *LocalCA) IssueBridgeCertificate(email string, validityDays int) (*x509.Certificate, []byte, *keys.SecurePrivateKey, error) {
    // Generate new key pair for bridge cert (NOT the master key)
    // This enables independent rotation of bridge cert without rotating master
    bridgePub, bridgePriv, err := keys.GenerateSecureKeyPair()
    if err != nil {
        return nil, nil, nil, fmt.Errorf("failed to generate bridge key: %w", err)
    }

    var ownershipTransferred bool
    defer func() {
        if !ownershipTransferred {
            bridgePriv.Destroy()
        }
    }()

    // Generate serial number
    serialNumber, err := GenerateSerialNumber()
    if err != nil {
        return nil, nil, nil, err
    }

    now := time.Now()
    notAfter := now.Add(time.Duration(validityDays) * 24 * time.Hour)

    // Create bridge certificate template
    template := &x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            CommonName:   email,
            Organization: []string{"Signet"},
        },
        EmailAddresses: []string{email}, // CRITICAL: GitHub reads this
        NotBefore:      now.Add(-24 * time.Hour), // Clock skew tolerance
        NotAfter:       notAfter,

        // Bridge cert is an intermediate CA
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        IsCA:                  true, // Can sign ephemeral certs
        BasicConstraintsValid: true,
        MaxPathLen:            0, // Can only sign end-entity certs, not other CAs

        // Subject/Authority Key IDs (required for cert chain validation)
        SubjectKeyId: generateSubjectKeyID(bridgePub),
    }

    // Create CA template (master key)
    issuerTemplate := ca.CreateCACertificateTemplate()
    if issuerTemplate == nil {
        return nil, nil, nil, fmt.Errorf("failed to create CA template")
    }
    issuerTemplate.SubjectKeyId = generateSubjectKeyID(ca.masterKey.Public())
    template.AuthorityKeyId = issuerTemplate.SubjectKeyId

    // Master key signs bridge cert
    certDER, err := x509.CreateCertificate(
        rand.Reader,
        template,       // Bridge cert being created
        issuerTemplate, // Master key CA
        bridgePub,      // Bridge cert public key
        ca.masterKey,   // Master key private key signs
    )
    if err != nil {
        return nil, nil, nil, fmt.Errorf("failed to create bridge certificate: %w", err)
    }

    // Parse certificate
    cert, err := x509.ParseCertificate(certDER)
    if err != nil {
        return nil, nil, nil, err
    }

    ownershipTransferred = true
    return cert, certDER, bridgePriv, nil
}
```

#### Updated: `cmd/signet-git/main.go`

```go
func initCmd() *cobra.Command {
    var userEmail string
    var bridgeValidityDays int

    cmd := &cobra.Command{
        Use:   "init",
        Short: "Initialize Signet configuration",
        Long: `Initialize Signet by generating a master key and storing it securely.

Identity Levels:
  Level 0 (default): Machine identity only - privacy-focused, no GitHub badges
  Level 1: Add user attribution with --email - local verification + GitHub badges`,
        Example: `  # Level 0: Machine identity only (privacy-focused)
  signet-git init

  # Level 1: User attribution for GitHub verification
  signet-git init --email alice@company.com
  signet-git export-bridge-cert > bridge.pem
  # Upload bridge.pem to GitHub Settings → GPG Keys

  # Force re-initialization
  signet-git init --force`,
        RunE:          runInit,
        SilenceUsage:  true,
        SilenceErrors: true,
    }

    cmd.Flags().BoolVar(&initInsecureFlag, "insecure", false, "Use file-based storage (testing only)")
    cmd.Flags().BoolVar(&forceFlag, "force", false, "Force re-initialization")
    cmd.Flags().StringVar(&userEmail, "email", "", "User email for attribution (enables GitHub verification)")
    cmd.Flags().IntVar(&bridgeValidityDays, "bridge-validity-days", 365, "Bridge certificate validity in days")

    return cmd
}

func runInit(cmd *cobra.Command, args []string) error {
    cfg := getConfig()

    // Initialize machine master key (Level 0)
    if initInsecureFlag {
        if err := keystore.InitializeInsecure(cfg.Home, forceFlag); err != nil {
            return fmt.Errorf("insecure initialization failed: %w", err)
        }
        fmt.Println(styles.Success.Render("✓") + " Machine identity initialized (insecure file storage)")
    } else {
        if err := keystore.InitializeSecure(forceFlag); err != nil {
            return fmt.Errorf("initialization failed: %w", err)
        }
        fmt.Println(styles.Success.Render("✓") + " Machine identity initialized")
    }

    // If email provided, create user attribution overlay (Level 1+)
    userEmail := cmd.Flag("email").Value.String()
    if userEmail != "" {
        bridgeValidityDays, _ := cmd.Flags().GetInt("bridge-validity-days")

        if err := createUserAttribution(cfg, userEmail, bridgeValidityDays); err != nil {
            return fmt.Errorf("failed to create user attribution: %w", err)
        }

        fmt.Println(styles.Success.Render("✓") + " User attribution configured: " + userEmail)
        fmt.Println()
        fmt.Println("Next steps for GitHub verification:")
        fmt.Println("  1. Export bridge certificate:")
        fmt.Println("     $ signet-git export-bridge-cert > bridge.pem")
        fmt.Println("  2. Upload to GitHub Settings → SSH and GPG keys")
        fmt.Println("  3. Commits will show 'Verified' badges")
    } else {
        fmt.Println()
        fmt.Println("Git commits will be signed with machine identity.")
        fmt.Println("To enable GitHub 'Verified' badges, re-run with --email:")
        fmt.Println("  $ signet-git init --email your@email.com --force")
    }

    return nil
}

func createUserAttribution(cfg *config.Config, email string, validityDays int) error {
    // Load machine master key
    masterKey, err := keystore.LoadMasterKeySecure()
    if err != nil {
        masterKey, err = keystore.LoadMasterKeyInsecure(cfg.Home)
        if err != nil {
            return err
        }
    }

    // Create bridge certificate
    ca := attestx509.NewLocalCA(masterKey, cfg.IssuerDID)
    bridgeCert, bridgeDER, bridgeKey, err := ca.IssueBridgeCertificate(email, validityDays)
    if err != nil {
        return err
    }
    defer bridgeKey.Destroy()

    // Create git config directory
    gitDir := filepath.Join(cfg.Home, "git")
    if err := os.MkdirAll(gitDir, 0700); err != nil {
        return fmt.Errorf("failed to create git directory: %w", err)
    }

    // Save bridge certificate (PEM)
    certPath := filepath.Join(gitDir, "bridge-cert.pem")
    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: bridgeDER,
    })
    if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
        return fmt.Errorf("failed to write bridge cert: %w", err)
    }

    // Save bridge private key (PEM, encrypted?)
    keyPath := filepath.Join(gitDir, "bridge-key.pem")
    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PRIVATE KEY",
        Bytes: bridgeKey.Key(),
    })
    if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
        return fmt.Errorf("failed to write bridge key: %w", err)
    }

    // Save git configuration
    gitConfig := map[string]interface{}{
        "user_email":               email,
        "bridge_cert_validity_days": validityDays,
        "created_at":               time.Now().Format(time.RFC3339),
    }
    configPath := filepath.Join(gitDir, "config.json")
    configJSON, _ := json.MarshalIndent(gitConfig, "", "  ")
    if err := os.WriteFile(configPath, configJSON, 0600); err != nil {
        return fmt.Errorf("failed to write git config: %w", err)
    }

    return nil
}

func exportBridgeCertCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "export-bridge-cert",
        Short: "Export the user attribution certificate for GitHub",
        Long: `Export the bridge certificate for uploading to GitHub.

The bridge certificate contains your email and enables GitHub "Verified" badges.

Upload steps:
  1. Run this command and copy the output
  2. Go to https://github.com/settings/keys
  3. Click "New GPG Key"
  4. Paste the certificate and save

After uploading, your signed commits will show "Verified" badges on GitHub.`,
        Example: `  # Export certificate
  signet-git export-bridge-cert > bridge.pem

  # Or copy directly
  signet-git export-bridge-cert | pbcopy  # macOS
  signet-git export-bridge-cert | xclip   # Linux`,
        RunE:          runExportBridgeCert,
        SilenceUsage:  true,
        SilenceErrors: true,
    }
}

func runExportBridgeCert(cmd *cobra.Command, args []string) error {
    cfg := getConfig()

    // Check if user attribution exists
    certPath := filepath.Join(cfg.Home, "git", "bridge-cert.pem")
    if !fileExists(certPath) {
        return fmt.Errorf("bridge certificate not found\n\n" +
            "User attribution not configured. Run:\n" +
            "  signet-git init --email your@email.com --force")
    }

    // Read and output certificate (already in PEM format)
    certPEM, err := os.ReadFile(certPath)
    if err != nil {
        return fmt.Errorf("failed to read bridge certificate: %w", err)
    }

    // Output raw PEM (no styling for machine-readable output)
    fmt.Print(string(certPEM))
    return nil
}
```

### HTTP Middleware: Always Level 0

**Critical**: HTTP authentication NEVER uses user attribution overlay.

```go
// pkg/http/middleware/signet.go

// SignetMiddleware always uses machine master key verification.
// User attribution (email) is NEVER exposed in HTTP requests.
//
// This preserves privacy - API requests are authenticated as machines,
// not individuals.
func SignetMiddleware(opts ...Option) func(http.Handler) http.Handler {
    config := &Config{
        // Configuration uses machine public key only
        MasterKey: nil, // Set via WithMasterKey()
        // ...
    }

    // Apply options
    for _, opt := range opts {
        opt(config)
    }

    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Verify proof of possession using machine master key
            // NEVER checks or exposes user email

            token, err := extractToken(r)
            if err != nil {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }

            // Verify master key signed ephemeral key
            if err := verifyMasterKeySignature(token, config.MasterKey); err != nil {
                http.Error(w, "invalid master signature", http.StatusUnauthorized)
                return
            }

            // Verify ephemeral key signed request
            if err := verifyEphemeralSignature(token, r); err != nil {
                http.Error(w, "invalid request signature", http.StatusUnauthorized)
                return
            }

            // Authenticated as MACHINE (not user)
            // Set context with machine ID, not user email
            ctx := context.WithValue(r.Context(), "signet.machine_id", token.IssuerID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

## User Experience Flows

### Flow 1: Privacy-Focused Developer (Level 0)

**Persona**: Alex, solo developer on personal projects, doesn't care about GitHub badges.

```bash
# One-time setup
$ signet-git init
✓ Machine identity initialized

$ git config --global gpg.format x509
$ git config --global gpg.x509.program signet-git

# Daily workflow
$ git commit -S -m "fix authentication bug"
[main f3a2b1c] fix authentication bug

$ git push
# Commits signed, verifiable locally, no GitHub badge
```

**Experience**: Zero friction, maximum privacy, works offline.

---

### Flow 2: Open Source Maintainer (Level 2)

**Persona**: Jordan, maintains popular OSS project, needs GitHub badges for contributor trust.

```bash
# One-time setup
$ signet-git init --email jordan@example.com
✓ Machine identity initialized
✓ User attribution configured: jordan@example.com

Next steps for GitHub verification:
  1. Export bridge certificate:
     $ signet-git export-bridge-cert > bridge.pem
  2. Upload to GitHub Settings → SSH and GPG keys
  3. Commits will show 'Verified' badges

$ signet-git export-bridge-cert > bridge.pem

# Upload bridge.pem to GitHub
# (Opens browser: https://github.com/settings/keys)

$ git config --global gpg.format x509
$ git config --global gpg.x509.program signet-git

# Daily workflow
$ git commit -S -m "add feature X"
[main a1b2c3d] add feature X

$ git push
# Commits show green "Verified" badge on GitHub
```

**Experience**: One-time 2-minute setup, then transparent verification.

---

### Flow 3: Hybrid Developer (Level 1 → Level 2 Progressive)

**Persona**: Sam, works on both private company repos and public OSS.

```bash
# Day 1: Start with machine identity
$ signet-git init
✓ Machine identity initialized

$ git commit -S -m "internal tool update"
# Signed, verifiable locally, no badge needed

# Day 30: Joins OSS project, wants GitHub badges
$ signet-git init --email sam@company.com --force
✓ User attribution configured: sam@company.com

Next steps for GitHub verification:
  1. Export bridge certificate:
     $ signet-git export-bridge-cert > bridge.pem
  2. Upload to GitHub Settings → SSH and GPG keys
  3. Commits will show 'Verified' badges

$ signet-git export-bridge-cert > bridge.pem
# Upload to GitHub

# Now works for both private and public repos
$ cd ~/work/internal-project
$ git commit -S -m "fix"
# Signed with user attribution, verifiable locally

$ cd ~/oss/public-project
$ git commit -S -m "feature"
$ git push
# Shows "Verified" badge on GitHub
```

**Experience**: Smooth upgrade path, no re-learning, backward compatible.

---

### Flow 4: Enterprise Developer (Future Level 3)

**Persona**: Morgan, works at BigCorp with SSO and centralized PKI.

```bash
# One-time setup (automated via IT)
$ signet-git init --oidc https://bigcorp.okta.com
Opening browser for authentication...
✓ Authenticated as morgan@bigcorp.com
✓ Bridge certificate provisioned (expires: 2027-02-10)
✓ Auto-renewal enabled

# Daily workflow (identical to other levels)
$ git commit -S -m "implement payment API"
[main x1y2z3] implement payment API

# Certificate auto-rotates yearly
# Revocation handled by corporate CA
# Compliance logs sent to security team
```

**Experience**: Zero manual setup, enterprise-grade security, transparent to developer.

## Migration Path

### Existing Users (Already on Level 0)

No action required. Existing workflows continue to work unchanged.

```bash
# Current setup (pre-007)
$ signet-git init
$ git commit -S -m "message"

# Post-007 (identical behavior)
$ signet-git init
$ git commit -S -m "message"
```

**Compatibility**: 100% backward compatible. No breaking changes.

### Users Wanting GitHub Badges

```bash
# Upgrade from Level 0 → Level 1+
$ signet-git init --email your@email.com --force
✓ User attribution configured: your@email.com

$ signet-git export-bridge-cert > bridge.pem
# Upload to GitHub

# All future commits now show "Verified" badges
```

**Migration Time**: < 2 minutes

### Rollback

```bash
# Remove user attribution, return to Level 0
$ rm -rf ~/.signet/git/
$ git commit -S -m "message"
# Back to machine-only signing
```

**Safety**: User attribution is purely additive. Removing it reverts to Level 0.

## Security Considerations

### Threat Model

**Level 0 (Machine Only):**
- Attacker gains access to workstation → Can sign as machine
- Mitigation: OS keyring protection, short-lived ephemeral certs
- Impact: Limited to machine identity (no user PII exposure)

**Level 1+ (User Attribution):**
- Attacker gains access to workstation → Can sign as user
- Mitigation: OS keyring + separate bridge key, 1-year rotation
- Impact: Can impersonate user on GitHub (same as stolen GPG key)

**Additional Protections:**
- Bridge cert rotation (yearly recommended)
- Separate bridge key (can rotate without rotating master)
- GitHub provides revocation (delete uploaded cert)
- Audit trail via git history

### Privacy

**HTTP Middleware (Always Level 0):**
- ✅ Never exposes user email in API requests
- ✅ Authenticated as machine ID only
- ✅ Privacy preserved even with Level 1+ git config

**Git Commits (Level-dependent):**
- Level 0: No user PII (machine ID only)
- Level 1+: User email in bridge cert (opt-in)

### Key Management

**Master Key:**
- Storage: OS keyring (Keychain on macOS)
- Lifetime: 10 years (rotatable)
- Purpose: Root of trust for machine identity

**Bridge Key:**
- Storage: `~/.signet/git/bridge-key.pem` (file-based)
- Lifetime: 1 year (configurable)
- Purpose: User attribution only
- Rotation: Independent from master key

**Ephemeral Key:**
- Storage: Memory only (zeroized after use)
- Lifetime: 5 minutes
- Purpose: Single commit/request signature

## Open Questions

1. **Bridge Key Storage**: Should bridge key also use OS keyring?
   - Pro: Better security (hardware-backed on macOS)
   - Con: More complexity, file-based is simpler
   - **Decision**: Start with file-based, add keyring option later

2. **Automatic Bridge Cert Rotation**: Should we auto-rotate bridge certs?
   - Pro: Better security hygiene
   - Con: User must re-upload to GitHub
   - **Decision**: Manual rotation initially, explore automation in Level 3

3. **Multiple User Identities**: Support multiple bridge certs (work vs. personal)?
   - Pro: Flexibility for developers with multiple email addresses
   - Con: Complexity in cert selection logic
   - **Decision**: Defer to future work, single email for v1

4. **GitHub CLI Integration**: Auto-upload bridge cert via `gh` CLI?
   - Pro: Frictionless Level 0 → Level 2 upgrade
   - Con: Dependency on GitHub CLI
   - **Decision**: Offer as optional enhancement, not required

5. **Bridge Cert Revocation**: How to handle compromised bridge certs?
   - Current: User deletes cert from GitHub (instant revocation)
   - Future: Support CRL/OCSP for enterprise (Level 3)
   - **Decision**: GitHub-based revocation sufficient for v1

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)
- [ ] Create `pkg/git/identity.go` with Identity struct
- [ ] Implement `LoadIdentity()` function
- [ ] Add `IssueBridgeCertificate()` to `pkg/attest/x509/bridge.go`
- [ ] Update `pkg/git/sign.go` to route based on identity level

### Phase 2: CLI Commands (Week 1)
- [ ] Add `--email` flag to `signet-git init`
- [ ] Implement `createUserAttribution()` helper
- [ ] Create `export-bridge-cert` subcommand
- [ ] Update help text and examples

### Phase 3: Testing (Week 2)
- [ ] Unit tests for bridge certificate generation
- [ ] Integration test: Level 0 signing
- [ ] Integration test: Level 1+ signing with bridge cert
- [ ] GitHub verification test (manual, in Docker)

### Phase 4: Documentation (Week 2)
- [ ] Update README.md with progressive disclosure levels
- [ ] Create docs/github-verification.md guide
- [ ] Add troubleshooting guide for cert upload
- [ ] Update ARCHITECTURE.md with identity model

### Phase 5: GitHub CLI Integration (Future)
- [ ] Add `--github-auto` flag for automatic upload
- [ ] Integrate with `gh` CLI for cert upload
- [ ] Auto-detect GitHub email from git config

## Success Metrics

- **Level 0 Adoption**: Existing users see no changes (0 breakage reports)
- **Level 1+ Adoption**: 30% of new users opt-in to `--email` flag
- **GitHub Verification**: 100% success rate for badge display after upload
- **Documentation**: < 5 support questions per week on GitHub verification
- **Performance**: No measurable impact on signing speed (< 1ms overhead)

## Alternatives Considered

### Alternative 1: Separate Binaries
Create `signet-git-machine` and `signet-git-user` as separate binaries.

**Rejected**: Too much duplication, confusing for users, violates DRY.

### Alternative 2: Always Include Email
Force users to provide email during `signet-git init`.

**Rejected**: Violates privacy-by-default principle, doesn't support machine-only use cases.

### Alternative 3: Automatic GitHub Detection
Auto-detect GitHub email from `git config user.email` and create bridge cert.

**Rejected**: Surprising behavior (implicit user attribution), doesn't support privacy use case.

### Alternative 4: OIDC-Only Attribution
Only support user attribution via OIDC (Level 3), skip manual bridge cert.

**Rejected**: Too high barrier to entry, doesn't support offline workflows.

## Conclusion

Progressive identity disclosure solves the fundamental tension between privacy (machine authentication) and accountability (user attribution) by making them orthogonal concerns.

**Key Principles:**
1. **Default to privacy**: Machine identity by default
2. **Opt-in to attribution**: User chooses to add email
3. **Clear separation**: HTTP auth never leaks user identity
4. **Backward compatible**: Existing workflows unchanged
5. **GitHub compatible**: Full support for verified badges

This design enables signet to serve both privacy-focused developers (Level 0) and open source maintainers needing GitHub verification (Level 2) without compromising either use case.

## References

- [002: Linked-Key Proof-of-Possession](./002-linked-key-pop.md)
- [006: Token Revocation](./006-revocation.md)
- [GitHub GPG Signature Verification](https://docs.github.com/en/authentication/managing-commit-signature-verification)
- [RFC 5280: X.509 Certificate Profiles](https://datatracker.ietf.org/doc/html/rfc5280)
- [OpenPGP Best Practices](https://riseup.net/en/security/message-security/openpgp/best-practices)
