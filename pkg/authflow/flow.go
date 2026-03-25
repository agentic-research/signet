// Package authflow provides a pluggable auth flow registry for the signet authority.
//
// Each auth flow (browser OAuth, token exchange, device flow, k8s projected tokens)
// registers itself with the DefaultRegistry via init(). The authority mounts all
// registered flows onto its HTTP mux at startup.
//
// Adding a new flow: create a new package under pkg/authflow/, implement the Flow
// interface, and call DefaultRegistry.Register() in init(). Import the package in
// cmd/signet/authority_flows.go for side effects.
package authflow

import "net/http"

// Flow represents a pluggable authentication flow that can issue certificates.
// Each flow handles its own HTTP mechanics (redirects, polling, single POST, etc.)
// but shares the authority's core infrastructure via Deps.
type Flow interface {
	// Name returns the flow's unique identifier (e.g., "browser", "exchange", "device").
	Name() string

	// Routes returns the HTTP routes this flow needs mounted on the authority mux.
	Routes() []Route
}

// Route maps a URL pattern to an HTTP handler.
type Route struct {
	// Pattern is the URL pattern (e.g., "/login", "/exchange-token").
	Pattern string

	// Handler is the HTTP handler for this route.
	Handler http.Handler

	// RateLimited controls whether the authority's rate limiter wraps this handler.
	RateLimited bool
}
