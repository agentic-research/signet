package main

import (
	"net/url"
	"testing"
)

// The enforced OIDC audience is deployment-specific (signet-e6e2d1): the
// in-repo Go authority verifies audience == its own URL — the convention
// oidc-signing.yml exercises on every main push — while the notme Worker
// enforces "notme.bot". These tests pin the resolution rule: the audience
// defaults to the authority URL, --audience overrides it, and it can never
// be empty.

func TestOIDCTokenRequestURL_PreservesQueryAndSetsAudience(t *testing.T) {
	got, err := oidcTokenRequestURL("https://token.actions.example/req?api-version=2", "http://localhost:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result does not parse: %v", err)
	}
	if aud := parsed.Query().Get("audience"); aud != "http://localhost:8080" {
		t.Fatalf("audience = %q, want the authority URL", aud)
	}
	if v := parsed.Query().Get("api-version"); v != "2" {
		t.Fatalf("existing query parameter lost: api-version = %q", v)
	}
}

func TestOIDCTokenRequestURL_Override(t *testing.T) {
	got, err := oidcTokenRequestURL("https://token.actions.example/req", "custom.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parsed, _ := url.Parse(got)
	if aud := parsed.Query().Get("audience"); aud != "custom.example" {
		t.Fatalf("audience = %q, want %q", aud, "custom.example")
	}
}

func TestOIDCTokenRequestURL_EmptyAudienceRejected(t *testing.T) {
	if _, err := oidcTokenRequestURL("https://token.actions.example/req", ""); err == nil {
		t.Fatal("empty audience must be rejected")
	}
}

func TestOIDCTokenRequestURL_InvalidURLRejected(t *testing.T) {
	if _, err := oidcTokenRequestURL("://not-a-url", "http://localhost:8080"); err == nil {
		t.Fatal("invalid request URL must be rejected")
	}
}

// The flag default is empty, which resolveOIDCToken resolves to the
// authority URL — preserving the in-repo Go authority convention that
// oidc-signing.yml depends on. A non-empty default (e.g. notme.bot) would
// break every self-hosted authority whose verifier pins its own URL.
func TestExchangeAudienceFlagDefaultsToAuthorityURL(t *testing.T) {
	flag := exchangeGitHubTokenCmd.Flags().Lookup("audience")
	if flag == nil {
		t.Fatal("exchange-github-token must expose an --audience flag")
	}
	if flag.DefValue != "" {
		t.Fatalf("--audience default = %q, want empty (resolved to the authority URL at request time)", flag.DefValue)
	}

	if got := resolveExchangeAudience("", "http://localhost:8080"); got != "http://localhost:8080" {
		t.Fatalf("resolveExchangeAudience(\"\", authority) = %q, want the authority URL", got)
	}
	if got := resolveExchangeAudience("notme.bot", "https://auth.notme.bot"); got != "notme.bot" {
		t.Fatalf("resolveExchangeAudience(override, authority) = %q, want the override", got)
	}
}
