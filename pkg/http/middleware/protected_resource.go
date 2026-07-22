package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// WellKnownProtectedResourcePath is the well-known URI for OAuth 2.0 Protected
// Resource Metadata (RFC 9728 §3). A resource server whose resource identifier
// is a host (the common case for an MCP/API endpoint) serves the document here.
//
// RFC 9728 also defines a path-insertion form for resource identifiers that
// carry a path component; that form is intentionally NOT handled here — this
// middleware serves the host-level document, which is correct when the resource
// identifier is the deployment origin. A resource with a path component should
// mount ProtectedResourceMetadataHandler at the inserted path itself.
const WellKnownProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ProtectedResourceMetadata is the OAuth 2.0 Protected Resource Metadata
// document (RFC 9728 §2). Only `Resource` is REQUIRED by the spec; every other
// field is OPTIONAL and omitted from the JSON when empty.
//
// This is what lets a cold OAuth/MCP client discover WHICH authorization server
// to authenticate against after a 401 — the resource-server half of the
// discovery chain whose authorization-server half is RFC 8414 metadata.
type ProtectedResourceMetadata struct {
	// Resource is the protected resource's resource identifier (RFC 9728 §2,
	// REQUIRED). Per §3.3 it MUST be identical to the identifier a client used
	// to reach this document, so it is validated as a non-empty absolute URL.
	Resource string `json:"resource"`

	// AuthorizationServers lists the AS issuer identifiers a client may use to
	// obtain a token for this resource (e.g. "https://auth.notme.bot"). OPTIONAL.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`

	// BearerMethodsSupported lists how a bearer token may be presented
	// (e.g. "header"). OPTIONAL.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// DPoPSigningAlgValuesSupported lists JWS `alg` values this resource server
	// accepts on DPoP proof JWTs (RFC 9449). OPTIONAL. Publishing it is how a
	// client learns the proof algorithm instead of guessing — the same interop
	// footgun that broke a downstream verifier by assuming the wrong alg.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// DPoPBoundAccessTokensRequired states whether this resource ALWAYS requires
	// DPoP-bound access tokens. OPTIONAL; the RFC 9728 default is false, so it
	// is emitted only when true to keep the document minimal.
	DPoPBoundAccessTokensRequired bool `json:"dpop_bound_access_tokens_required,omitempty"`

	// ResourceDocumentation is an optional human-readable docs URL. OPTIONAL.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// validate enforces the one RFC 9728 invariant that matters for correctness:
// `resource` is present and is an absolute URL. A relative or empty resource
// identifier makes the §3.3 "identical to the identifier used" check
// unsatisfiable for every client.
func (m *ProtectedResourceMetadata) validate() error {
	if m == nil {
		return nil
	}
	if strings.TrimSpace(m.Resource) == "" {
		return fmt.Errorf("protected resource metadata: `resource` is required (RFC 9728 §2)")
	}
	if !strings.HasPrefix(m.Resource, "https://") && !strings.HasPrefix(m.Resource, "http://") {
		return fmt.Errorf("protected resource metadata: `resource` must be an absolute URL, got %q", m.Resource)
	}
	return nil
}

// challenge builds the WWW-Authenticate value that points a client at this
// resource's metadata document (RFC 9728 §5.1):
//
//	Bearer resource_metadata="https://host/.well-known/oauth-protected-resource"
//
// The metadata URL is the host-level well-known path under the resource
// identifier's origin (see WellKnownProtectedResourcePath). Returns "" if no
// metadata is configured, so the caller can skip setting the header.
func (m *ProtectedResourceMetadata) challenge() string {
	if m == nil {
		return ""
	}
	origin := strings.TrimRight(m.Resource, "/")
	// Trim any path component to the origin so the well-known suffix lands at
	// host root (the host-level form documented above).
	if i := strings.Index(origin, "://"); i >= 0 {
		if slash := strings.Index(origin[i+3:], "/"); slash >= 0 {
			origin = origin[:i+3+slash]
		}
	}
	url := origin + WellKnownProtectedResourcePath
	return fmt.Sprintf("Bearer resource_metadata=%q", url)
}

// ProtectedResourceMetadataHandler returns an http.Handler that serves the
// RFC 9728 document as application/json. It is exported so a service can mount
// it explicitly (e.g. at a path-inserted location) rather than relying on the
// middleware's built-in interception. The handler is unauthenticated by design
// — RFC 9728 metadata is public (it is a map, not a key).
func ProtectedResourceMetadataHandler(m *ProtectedResourceMetadata) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(m)
	})
}
