package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtectedResourceMetadata_Validate(t *testing.T) {
	tests := []struct {
		name    string
		meta    *ProtectedResourceMetadata
		wantErr bool
	}{
		{"nil is fine (feature off)", nil, false},
		{"empty resource rejected", &ProtectedResourceMetadata{Resource: ""}, true},
		{"whitespace resource rejected", &ProtectedResourceMetadata{Resource: "   "}, true},
		{"relative resource rejected", &ProtectedResourceMetadata{Resource: "/mcp"}, true},
		{"bare host without scheme rejected", &ProtectedResourceMetadata{Resource: "mcp.example.com"}, true},
		{"scheme-only (no host) rejected", &ProtectedResourceMetadata{Resource: "https://"}, true},
		{"query rejected (LOW-1)", &ProtectedResourceMetadata{Resource: "https://host?x=y"}, true},
		{"fragment rejected (LOW-1)", &ProtectedResourceMetadata{Resource: "https://host#frag"}, true},
		{"userinfo rejected (LOW-1)", &ProtectedResourceMetadata{Resource: "https://u:p@host"}, true},
		{"CRLF rejected (header-injection guard)", &ProtectedResourceMetadata{Resource: "https://host\r\nX-Injected: 1"}, true},
		{"https absolute accepted", &ProtectedResourceMetadata{Resource: "https://mcp.example.com"}, false},
		{"http absolute accepted", &ProtectedResourceMetadata{Resource: "http://localhost:8080"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.meta.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProtectedResourceMetadata_Challenge(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{
			"host root",
			"https://mcp.example.com",
			`Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`,
		},
		{
			"trailing slash trimmed",
			"https://mcp.example.com/",
			`Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`,
		},
		{
			"path component trimmed to origin (host-level well-known)",
			"https://example.com/mcp",
			`Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
		},
		{
			"port preserved",
			"http://localhost:8080",
			`Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (&ProtectedResourceMetadata{Resource: tt.resource}).challenge()
			if got != tt.want {
				t.Fatalf("challenge()\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
	if got := (*ProtectedResourceMetadata)(nil).challenge(); got != "" {
		t.Fatalf("nil challenge() = %q, want empty", got)
	}
}

func TestProtectedResourceMetadataHandler(t *testing.T) {
	m := &ProtectedResourceMetadata{
		Resource:                      "https://mcp.example.com",
		AuthorizationServers:          []string{"https://auth.notme.bot"},
		BearerMethodsSupported:        []string{"header"},
		DPoPSigningAlgValuesSupported: []string{"ES256"},
		DPoPBoundAccessTokensRequired: true,
	}
	h := ProtectedResourceMetadataHandler(m)

	t.Run("GET returns the RFC 9728 document", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WellKnownProtectedResourcePath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("content-type = %q", ct)
		}
		// Public by design — a cold client with no credential must be able to read it.
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("metadata must be CORS-public")
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("body not JSON: %v", err)
		}
		if got["resource"] != "https://mcp.example.com" {
			t.Fatalf("resource = %v", got["resource"])
		}
		if got["dpop_bound_access_tokens_required"] != true {
			t.Fatalf("dpop_bound_access_tokens_required = %v", got["dpop_bound_access_tokens_required"])
		}
	})

	t.Run("omitempty drops false + empty fields", func(t *testing.T) {
		min := &ProtectedResourceMetadata{Resource: "https://x.example.com"}
		rec := httptest.NewRecorder()
		ProtectedResourceMetadataHandler(min).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		body := rec.Body.String()
		for _, absent := range []string{"authorization_servers", "dpop_bound_access_tokens_required", "resource_documentation"} {
			if strings.Contains(body, absent) {
				t.Fatalf("expected %q omitted, body=%s", absent, body)
			}
		}
	})

	t.Run("HEAD ok, no body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/", nil))
		if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Fatalf("HEAD status=%d bodyLen=%d", rec.Code, rec.Body.Len())
		}
	})

	t.Run("POST rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST status = %d, want 405", rec.Code)
		}
	})
}

func TestSignetMiddleware_ProtectedResource(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw, err := SignetMiddleware(WithProtectedResourceMetadata(ProtectedResourceMetadata{
		Resource:             "https://mcp.example.com",
		AuthorizationServers: []string{"https://auth.notme.bot"},
	}))
	if err != nil {
		t.Fatalf("build middleware: %v", err)
	}
	h := mw(next)

	t.Run("metadata endpoint is served WITHOUT a Signet-Proof header", func(t *testing.T) {
		// The whole point of discovery: reachable by a client that holds no
		// credential yet. No Signet-Proof header is set here.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WellKnownProtectedResourcePath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("metadata status = %d, want 200 (must be pre-auth)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "auth.notme.bot") {
			t.Fatalf("metadata missing authorization_servers: %s", rec.Body.String())
		}
	})

	t.Run("401 carries the WWW-Authenticate resource_metadata challenge", func(t *testing.T) {
		// A normal protected request with no proof → 401 → must point the client
		// at discovery.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/some/protected/path", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		challenge := rec.Header().Get("WWW-Authenticate")
		want := `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`
		if challenge != want {
			t.Fatalf("WWW-Authenticate\n got: %s\nwant: %s", challenge, want)
		}
	})

	t.Run("no metadata configured ⇒ no WWW-Authenticate on 401 (opt-in)", func(t *testing.T) {
		bare, err := SignetMiddleware()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		rec := httptest.NewRecorder()
		bare(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("unexpected WWW-Authenticate when feature off: %q", got)
		}
	})
}

func TestSignetMiddleware_RejectsInvalidProtectedResource(t *testing.T) {
	// A relative resource identifier is a config error, not a silent no-op.
	_, err := SignetMiddleware(WithProtectedResourceMetadata(ProtectedResourceMetadata{Resource: "/mcp"}))
	if err == nil {
		t.Fatal("expected construction to fail on a relative resource identifier")
	}
}
