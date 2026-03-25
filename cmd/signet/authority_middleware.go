package main

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrapped, r)

		logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// rateLimiterEntry wraps a rate limiter with last access tracking
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// rateLimiter implements per-IP rate limiting to prevent abuse
type rateLimiter struct {
	limiters      map[string]*rateLimiterEntry
	mu            sync.RWMutex
	r             rate.Limit    // requests per second
	b             int           // burst size
	maxEntries    int           // cap to prevent memory exhaustion from spoofed IPs
	rejectLimiter *rate.Limiter // shared zero-allowance limiter for over-capacity requests
}

// newRateLimiter creates a new per-IP rate limiter
// r is the rate (requests per second), b is the burst size
func newRateLimiter(r rate.Limit, b int) *rateLimiter {
	return &rateLimiter{
		limiters:      make(map[string]*rateLimiterEntry),
		r:             r,
		b:             b,
		maxEntries:    100000,
		rejectLimiter: rate.NewLimiter(0, 0),
	}
}

// getLimiter returns the rate limiter for a given IP address
func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.RLock()
	entry, exists := rl.limiters[ip]
	rl.mu.RUnlock()

	if exists {
		// Update last access time (requires write lock for thread safety)
		rl.mu.Lock()
		entry.lastAccess = time.Now()
		rl.mu.Unlock()
		return entry.limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists := rl.limiters[ip]; exists {
		entry.lastAccess = time.Now()
		return entry.limiter
	}

	// Reject new IPs if the map is at capacity (prevents memory exhaustion)
	if rl.maxEntries > 0 && len(rl.limiters) >= rl.maxEntries {
		return rl.rejectLimiter
	}

	// Create new entry with current timestamp
	entry = &rateLimiterEntry{
		limiter:    rate.NewLimiter(rl.r, rl.b),
		lastAccess: time.Now(),
	}
	rl.limiters[ip] = entry
	return entry.limiter
}

// cleanup removes stale entries from the rate limiter map
// This should be called periodically to prevent memory leaks
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Remove entries that haven't been accessed in the last 10 minutes
	// This prevents unbounded memory growth while keeping active limiters
	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, entry := range rl.limiters {
		if entry.lastAccess.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
}

// getClientIP extracts the client IP using the configured trusted proxy header.
// If no trusted header is configured, falls back to RemoteAddr (safest default).
// Configure trusted_proxy_header in authority config:
//   - "CF-Connecting-IP" for Cloudflare
//   - "X-Real-IP" for nginx
//   - "" (default) for direct connections
func getClientIP(r *http.Request, trustedHeader string) string {
	if trustedHeader != "" {
		if val := r.Header.Get(trustedHeader); val != "" {
			// For X-Forwarded-For style headers, take only the first IP
			raw := val
			if first, _, found := strings.Cut(val, ","); found {
				raw = first
			}
			raw = strings.TrimSpace(raw)
			// Validate it looks like an IP before trusting it
			if addr, err := netip.ParseAddr(raw); err == nil {
				return addr.String()
			}
			// Malformed header value — fall through to RemoteAddr
		}
	}

	// Fall back to direct connection IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// rateLimitMiddleware applies per-IP rate limiting to HTTP handlers
func rateLimitMiddleware(rl *rateLimiter, logger *slog.Logger, trustedProxyHeader string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r, trustedProxyHeader)

		// Check if request is allowed
		limiter := rl.getLimiter(ip)
		if !limiter.Allow() {
			logger.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
