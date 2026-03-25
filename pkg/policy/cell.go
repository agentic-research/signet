package policy

import "strings"

// PolicyStatement defines access control rules with Allow and Deny lists.
// Supports hierarchical permission strings (e.g., "gcp:storage:objects:get")
// and wildcards (e.g., "storage:*") following the Dewey Decimal System approach.
type PolicyStatement struct {
	Allow []string `cbor:"1,keyasint"`
	Deny  []string `cbor:"2,keyasint"`
}

// IsAllowed checks if the given action is permitted by this policy.
// Returns true if the action is in the Allow list and not in the Deny list.
// Deny rules take precedence over Allow rules.
// Supports wildcard matching (e.g., "storage:*" matches "storage:read").
func (p *PolicyStatement) IsAllowed(action string) bool {
	// First check if explicitly denied
	// Deny takes precedence over allow
	for _, pattern := range p.Deny {
		if matchesPattern(action, pattern) {
			return false
		}
	}

	// Then check if allowed
	for _, pattern := range p.Allow {
		if matchesPattern(action, pattern) {
			return true
		}
	}

	// Default deny
	return false
}

// matchesPattern checks if an action matches a permission pattern.
// Supports:
// - Exact match: "read" matches "read"
// - Wildcard suffix: "storage:*" matches "storage:read", "storage:write"
// - Full wildcard: "*" matches anything
func matchesPattern(action, pattern string) bool {
	// Exact match
	if action == pattern {
		return true
	}

	// Full wildcard
	if pattern == "*" {
		return true
	}

	// Wildcard suffix: "storage:*"
	if prefix, ok := strings.CutSuffix(pattern, ":*"); ok {
		if strings.HasPrefix(action, prefix+":") {
			return true
		}
	}

	return false
}

// SignetAuthCell is the fundamental unit of authority in the hierarchical IAM system.
// It uses a Unix-style permission model (Owner/Group/Other) with hierarchical
// permission strings inspired by the Dewey Decimal System.
type SignetAuthCell struct {
	// Resource identifies the resource this cell governs (e.g., "gcp:storage:bucket-name")
	Resource string `cbor:"1,keyasint"`

	// Owner is the public key or identifier of the cell owner
	Owner []byte `cbor:"2,keyasint"`

	// Group is the public key or identifier of the group (optional)
	Group []byte `cbor:"3,keyasint"`

	// OwnerPermissions defines what the owner can do with this resource
	OwnerPermissions PolicyStatement `cbor:"4,keyasint"`

	// GroupPermissions defines what group members can do with this resource
	GroupPermissions PolicyStatement `cbor:"5,keyasint"`

	// OtherPermissions defines what others (non-owner, non-group) can do
	OtherPermissions PolicyStatement `cbor:"6,keyasint"`

	// Signature is the cryptographic signature over this cell
	// The signature should be verifiable using the Owner's public key
	Signature []byte `cbor:"7,keyasint"`
}
