package policy

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/agentic-research/signet/pkg/lifecycle"
)

// ed25519Zeroizer securely zeros an Ed25519 private key.
var ed25519Zeroizer = func(key *ed25519.PrivateKey) {
	for i := range *key {
		(*key)[i] = 0
	}
}

// Compiler maintains staging state and produces signed trust policy bundles.
// SCIM events (or direct API calls) mutate the staging state, then Compile()
// produces a new signed bundle with an incremented seqno.
//
// The staging state is NOT the source of truth — the signed bundle is.
// If staging is lost, the IdP performs a full SCIM sync to reconstruct it.
//
// The signing key is wrapped in lifecycle.SecureValue for zeroization on Destroy().
type Compiler struct {
	mu      sync.RWMutex
	epoch   uint64
	seqno   uint64
	signKey *lifecycle.SecureValue[ed25519.PrivateKey]

	subjects map[string]*Subject
	groups   map[string]*Group
}

// NewCompiler creates a new bundle compiler with the given signing key.
// Call Destroy() when done to zeroize the key material.
func NewCompiler(signKey ed25519.PrivateKey) *Compiler {
	return &Compiler{
		signKey:  lifecycle.New(signKey, ed25519Zeroizer),
		epoch:    1,
		seqno:    0,
		subjects: make(map[string]*Subject),
		groups:   make(map[string]*Group),
	}
}

// Destroy zeroizes the signing key. The compiler cannot sign after this.
func (c *Compiler) Destroy() {
	c.signKey.Destroy()
}

// AddSubject provisions a subject (SCIM POST /Users equivalent).
func (c *Compiler) AddSubject(subjectID string, groups []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subjects[subjectID] = &Subject{
		Active: true,
		Groups: append([]string(nil), groups...), // defensive copy
	}
}

// DeactivateSubject soft-revokes a subject (SCIM PATCH active=false).
func (c *Compiler) DeactivateSubject(subjectID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.subjects[subjectID]; ok {
		s.Active = false
	}
}

// RemoveSubject deprovisions a subject and bumps epoch (SCIM DELETE /Users).
// Epoch bump invalidates all certs from prior epoch.
func (c *Compiler) RemoveSubject(subjectID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.subjects, subjectID)
	c.epoch++
}

// SetSubjectGroups updates group memberships (SCIM PATCH).
func (c *Compiler) SetSubjectGroups(subjectID string, groups []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.subjects[subjectID]; ok {
		s.Groups = append([]string(nil), groups...) // defensive copy
	}
}

// DefineGroup creates or updates a group (SCIM POST/PATCH /Groups).
func (c *Compiler) DefineGroup(name string, capTokens []uint64, maxCertTTL uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.groups[name] = &Group{
		CapTokens:  append([]uint64(nil), capTokens...), // defensive copy
		MaxCertTTL: maxCertTTL,
	}
}

// RemoveGroup removes a group. No epoch bump — certs age out naturally.
func (c *Compiler) RemoveGroup(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.groups, name)
}

// Compile produces a new signed trust policy bundle from the current staging state.
// Increments seqno on each compilation.
func (c *Compiler) Compile() (*TrustPolicyBundle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seqno++

	// Snapshot the staging state (defensive copy)
	subjects := make(map[string]*Subject, len(c.subjects))
	for k, v := range c.subjects {
		cp := *v
		cp.Groups = append([]string(nil), v.Groups...)
		subjects[k] = &cp
	}

	groups := make(map[string]*Group, len(c.groups))
	for k, v := range c.groups {
		cp := *v
		cp.CapTokens = append([]uint64(nil), v.CapTokens...)
		groups[k] = &cp
	}

	bundle := &TrustPolicyBundle{
		Epoch:    c.epoch,
		Seqno:    c.seqno,
		Subjects: subjects,
		Groups:   groups,
		IssuedAt: uint64(time.Now().Unix()),
	}

	// Sign using the loan pattern — key never escapes SecureValue
	var signErr error
	if err := c.signKey.Use(func(key *ed25519.PrivateKey) error {
		signErr = bundle.Sign(*key)
		return signErr
	}); err != nil {
		return nil, fmt.Errorf("sign bundle: %w", err)
	}

	return bundle, nil
}

// Snapshot returns the current epoch and seqno (for diagnostics/health checks).
func (c *Compiler) Snapshot() (epoch, seqno uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.epoch, c.seqno
}
