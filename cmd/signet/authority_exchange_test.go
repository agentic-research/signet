package main

import (
	"net/url"
	"testing"
)

// The authority (notme Worker) enforces GHA_CERT_AUDIENCE = "notme.bot".
// Historically this command requested tokens with audience set to the
// authority URL, which the authority rejects (signet-e6e2d1). These tests pin
// the corrected behavior: default audience is notme.bot, overridable, never
// empty, and never the authority URL implicitly.

func TestOIDCTokenRequestURL_DefaultAudience(t *testing.T) {
	got, err := oidcTokenRequestURL("https://token.actions.example/req?api-version=2", defaultExchangeAudience)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result does not parse: %v", err)
	}
	if aud := parsed.Query().Get("audience"); aud != "notme.bot" {
		t.Fatalf("audience = %q, want %q", aud, "notme.bot")
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
	if _, err := oidcTokenRequestURL("://not-a-url", defaultExchangeAudience); err == nil {
		t.Fatal("invalid request URL must be rejected")
	}
}

func TestExchangeAudienceFlagDefault(t *testing.T) {
	flag := exchangeGitHubTokenCmd.Flags().Lookup("audience")
	if flag == nil {
		t.Fatal("exchange-github-token must expose an --audience flag")
	}
	if flag.DefValue != "notme.bot" {
		t.Fatalf("--audience default = %q, want %q (the authority's enforced audience)", flag.DefValue, "notme.bot")
	}
}
