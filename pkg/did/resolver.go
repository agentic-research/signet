package did

import (
	"context"
	"crypto"
	"errors"
	"time"
)

// DID represents a Decentralized Identifier
type DID struct {
	// Method is the DID method (e.g., "git", "web", "key")
	Method string

	// ID is the method-specific identifier
	ID string

	// Fragment is the optional fragment (e.g., "#key-1")
	Fragment string
}

// Document represents a DID Document containing public keys and service endpoints
type Document struct {
	// Context defines the JSON-LD context
	Context []string `json:"@context"`

	// ID is the DID this document represents
	ID string `json:"id"`

	// VerificationMethod contains public keys
	VerificationMethod []VerificationMethod `json:"verificationMethod"`

	// Authentication lists methods for authentication
	Authentication []string `json:"authentication,omitempty"`

	// AssertionMethod lists methods for assertions
	AssertionMethod []string `json:"assertionMethod,omitempty"`

	// KeyAgreement lists methods for key agreement
	KeyAgreement []string `json:"keyAgreement,omitempty"`

	// CapabilityInvocation lists methods for capability invocation
	CapabilityInvocation []string `json:"capabilityInvocation,omitempty"`

	// CapabilityDelegation lists methods for capability delegation
	CapabilityDelegation []string `json:"capabilityDelegation,omitempty"`

	// Service contains service endpoints
	Service []Service `json:"service,omitempty"`

	// Created timestamp
	Created *time.Time `json:"created,omitempty"`

	// Updated timestamp
	Updated *time.Time `json:"updated,omitempty"`
}

// VerificationMethod represents a public key in a DID Document
type VerificationMethod struct {
	// ID is the identifier for this key
	ID string `json:"id"`

	// Type specifies the key type
	Type string `json:"type"`

	// Controller is the DID that controls this key
	Controller string `json:"controller"`

	// PublicKeyJwk contains the key in JWK format
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk,omitempty"`

	// PublicKeyMultibase contains the key in multibase format
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`

	// PublicKeyPem contains the key in PEM format
	PublicKeyPem string `json:"publicKeyPem,omitempty"`
}

// Service represents a service endpoint in a DID Document
type Service struct {
	// ID is the identifier for this service
	ID string `json:"id"`

	// Type specifies the service type
	Type string `json:"type"`

	// ServiceEndpoint is the endpoint URL or data
	ServiceEndpoint interface{} `json:"serviceEndpoint"`
}

// Resolver defines the interface for DID resolution
type Resolver interface {
	// Resolve resolves a DID to its document
	Resolve(ctx context.Context, did string) (*Document, error)

	// ResolveWithOptions resolves with specific options
	ResolveWithOptions(ctx context.Context, did string, options *ResolutionOptions) (*ResolutionResult, error)

	// GetSupportedMethods returns the DID methods this resolver supports
	GetSupportedMethods() []string
}

// ResolutionOptions contains options for DID resolution
type ResolutionOptions struct {
	// Accept specifies preferred representation formats
	Accept string

	// NoCache bypasses any caching
	NoCache bool

	// VerifySignature verifies document signatures if present
	VerifySignature bool
}

// ResolutionResult contains the result of DID resolution
type ResolutionResult struct {
	// Document is the resolved DID Document
	Document *Document

	// Metadata about the resolution
	Metadata *ResolutionMetadata

	// DocumentMetadata about the document
	DocumentMetadata *DocumentMetadata
}

// ResolutionMetadata contains metadata about the resolution process
type ResolutionMetadata struct {
	// ContentType of the resolved document
	ContentType string

	// Duration of the resolution
	Duration time.Duration

	// Error if resolution failed
	Error string

	// Cached indicates if result was from cache
	Cached bool
}

// DocumentMetadata contains metadata about the DID Document
type DocumentMetadata struct {
	// Created timestamp
	Created *time.Time

	// Updated timestamp
	Updated *time.Time

	// VersionId of the document
	VersionId string

	// Deactivated indicates if the DID is deactivated
	Deactivated bool
}

// MultiMethodResolver combines multiple method-specific resolvers
type MultiMethodResolver struct {
	resolvers map[string]Resolver
}

// NewMultiMethodResolver creates a resolver supporting multiple methods
func NewMultiMethodResolver() *MultiMethodResolver {
	// Implementation will follow
	return nil
}

// RegisterResolver registers a resolver for a specific method
func (mmr *MultiMethodResolver) RegisterResolver(method string, resolver Resolver) {
	// Implementation will follow
}

// Resolve implements the Resolver interface
func (mmr *MultiMethodResolver) Resolve(ctx context.Context, did string) (*Document, error) {
	// Implementation will follow
	return nil, nil
}

// ResolveWithOptions implements the Resolver interface
func (mmr *MultiMethodResolver) ResolveWithOptions(ctx context.Context, did string, options *ResolutionOptions) (*ResolutionResult, error) {
	// Implementation will follow
	return nil, nil
}

// GetSupportedMethods implements the Resolver interface
func (mmr *MultiMethodResolver) GetSupportedMethods() []string {
	// Implementation will follow
	return nil
}

// ParseDID parses a DID string into its components
func ParseDID(did string) (*DID, error) {
	// Implementation will follow
	return nil, nil
}

// GetPublicKey extracts a public key from a DID Document
func (doc *Document) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	// Implementation will follow
	return nil, nil
}

// GetVerificationMethod retrieves a verification method by ID
func (doc *Document) GetVerificationMethod(methodID string) (*VerificationMethod, error) {
	// Implementation will follow
	return nil, nil
}

// Common errors
var (
	// ErrInvalidDID indicates the DID format is invalid
	ErrInvalidDID = errors.New("invalid DID format")

	// ErrMethodNotSupported indicates the DID method is not supported
	ErrMethodNotSupported = errors.New("DID method not supported")

	// ErrDocumentNotFound indicates the DID Document was not found
	ErrDocumentNotFound = errors.New("DID Document not found")

	// ErrKeyNotFound indicates the requested key was not found
	ErrKeyNotFound = errors.New("verification method not found in document")
)