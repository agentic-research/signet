package middleware

import "time"

// Settings represents runtime configuration for Signet middleware.
// This struct is designed to be loaded from YAML/TOML configuration files
// and environment variables. See issue #23 for full configuration system design.
//
// Future Configuration System Design:
//   - Load from YAML/TOML files (e.g., /etc/signet/config.yaml)
//   - Override with environment variables (e.g., SIGNET_MAX_REQUEST_SIZE)
//   - Validate on startup with clear error messages
//   - Support hot reload for safe settings (log levels, timeouts)
//
// Example YAML configuration:
//
//	security:
//	  max_request_size: 1048576  # 1MB
//	  clock_skew: 30s
//	  chunked_timeout: 30s
//	storage:
//	  token_store: redis
//	  redis_url: redis://localhost:6379
//	observability:
//	  metrics_enabled: true
//	  log_level: info
//	  tracing_enabled: true
type Settings struct {
	// Security settings
	Security SecuritySettings

	// Storage settings
	Storage StorageSettings

	// Observability settings
	Observability ObservabilitySettings

	// Network settings
	Network NetworkSettings
}

// SecuritySettings controls security-related middleware behavior.
type SecuritySettings struct {
	// MaxRequestSize limits request body size to prevent DoS attacks.
	// Default: 1MB (1048576 bytes)
	// Environment variable: SIGNET_MAX_REQUEST_SIZE
	MaxRequestSize int64 `yaml:"max_request_size" toml:"max_request_size" env:"SIGNET_MAX_REQUEST_SIZE" default:"1048576"`

	// ClockSkew is the maximum allowed time difference between client and server.
	// Default: 30 seconds
	// Environment variable: SIGNET_CLOCK_SKEW
	ClockSkew time.Duration `yaml:"clock_skew" toml:"clock_skew" env:"SIGNET_CLOCK_SKEW" default:"30s"`

	// MaxTokensPerUser limits tokens per user to prevent resource exhaustion.
	// Default: 100
	// Environment variable: SIGNET_MAX_TOKENS_PER_USER
	MaxTokensPerUser int `yaml:"max_tokens_per_user" toml:"max_tokens_per_user" env:"SIGNET_MAX_TOKENS_PER_USER" default:"100"`
}

// StorageSettings controls token and nonce storage backends.
type StorageSettings struct {
	// TokenStoreType specifies the token storage backend.
	// Options: "memory", "redis", "postgres", "dynamodb"
	// Default: "memory"
	// Environment variable: SIGNET_TOKEN_STORE
	TokenStoreType string `yaml:"token_store" toml:"token_store" env:"SIGNET_TOKEN_STORE" default:"memory"`

	// NonceStoreType specifies the nonce storage backend.
	// Options: "memory", "redis"
	// Default: "memory"
	// Environment variable: SIGNET_NONCE_STORE
	NonceStoreType string `yaml:"nonce_store" toml:"nonce_store" env:"SIGNET_NONCE_STORE" default:"memory"`

	// CleanupInterval determines how often expired tokens/nonces are removed.
	// Default: 5 minutes
	// Environment variable: SIGNET_CLEANUP_INTERVAL
	CleanupInterval time.Duration `yaml:"cleanup_interval" toml:"cleanup_interval" env:"SIGNET_CLEANUP_INTERVAL" default:"5m"`

	// RedisURL is the connection string for Redis storage backends.
	// Example: "redis://localhost:6379/0"
	// Environment variable: SIGNET_REDIS_URL
	RedisURL string `yaml:"redis_url" toml:"redis_url" env:"SIGNET_REDIS_URL"`

	// PostgresURL is the connection string for PostgreSQL storage.
	// Example: "postgres://user:pass@localhost/signet?sslmode=require"
	// Environment variable: SIGNET_POSTGRES_URL
	PostgresURL string `yaml:"postgres_url" toml:"postgres_url" env:"SIGNET_POSTGRES_URL"`
}

// ObservabilitySettings controls monitoring and logging.
type ObservabilitySettings struct {
	// MetricsEnabled determines whether to emit Prometheus/StatsD metrics.
	// Default: true
	// Environment variable: SIGNET_METRICS_ENABLED
	MetricsEnabled bool `yaml:"metrics_enabled" toml:"metrics_enabled" env:"SIGNET_METRICS_ENABLED" default:"true"`

	// LogLevel controls logging verbosity.
	// Options: "debug", "info", "warn", "error"
	// Default: "info"
	// Environment variable: SIGNET_LOG_LEVEL
	LogLevel string `yaml:"log_level" toml:"log_level" env:"SIGNET_LOG_LEVEL" default:"info"`

	// TracingEnabled determines whether to emit distributed tracing spans.
	// Default: false
	// Environment variable: SIGNET_TRACING_ENABLED
	TracingEnabled bool `yaml:"tracing_enabled" toml:"tracing_enabled" env:"SIGNET_TRACING_ENABLED" default:"false"`

	// TracingProvider specifies the tracing backend.
	// Options: "opentelemetry", "jaeger", "zipkin"
	// Default: "opentelemetry"
	// Environment variable: SIGNET_TRACING_PROVIDER
	TracingProvider string `yaml:"tracing_provider" toml:"tracing_provider" env:"SIGNET_TRACING_PROVIDER" default:"opentelemetry"`
}

// NetworkSettings controls network-level behavior.
type NetworkSettings struct {
	// ChunkedTransferTimeout limits the total time for reading chunked request bodies.
	// This prevents DoS attacks via slow-drip chunked transfers that bypass
	// Content-Length checks. Set to 0 to disable timeout.
	//
	// Background (Issue #28 enhancement):
	//   - Current DoS fix only validates Content-Length header
	//   - Chunked transfers don't have Content-Length
	//   - Attacker can send infinite chunks slowly to exhaust connections
	//   - This timeout closes the connection if chunks take too long
	//
	// Default: 30 seconds
	// Environment variable: SIGNET_CHUNKED_TIMEOUT
	//
	// Future Implementation (tracked in issue #23):
	//   - Add io.ReadCloser wrapper with deadline
	//   - Monitor total read time, not individual chunk time
	//   - Emit metrics on timeout events
	ChunkedTransferTimeout time.Duration `yaml:"chunked_timeout" toml:"chunked_timeout" env:"SIGNET_CHUNKED_TIMEOUT" default:"30s"`

	// ReadHeaderTimeout limits time to read request headers.
	// Default: 10 seconds
	// Environment variable: SIGNET_READ_HEADER_TIMEOUT
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" toml:"read_header_timeout" env:"SIGNET_READ_HEADER_TIMEOUT" default:"10s"`

	// WriteTimeout limits time to write response.
	// Default: 30 seconds
	// Environment variable: SIGNET_WRITE_TIMEOUT
	WriteTimeout time.Duration `yaml:"write_timeout" toml:"write_timeout" env:"SIGNET_WRITE_TIMEOUT" default:"30s"`

	// IdleTimeout limits time for keep-alive connections.
	// Default: 90 seconds
	// Environment variable: SIGNET_IDLE_TIMEOUT
	IdleTimeout time.Duration `yaml:"idle_timeout" toml:"idle_timeout" env:"SIGNET_IDLE_TIMEOUT" default:"90s"`
}

// DefaultSettings returns a Settings instance with sensible defaults.
// This is the baseline configuration that can be overridden via files/env vars.
func DefaultSettings() *Settings {
	return &Settings{
		Security: SecuritySettings{
			MaxRequestSize:   1 * 1024 * 1024, // 1MB
			ClockSkew:        30 * time.Second,
			MaxTokensPerUser: 100,
		},
		Storage: StorageSettings{
			TokenStoreType:  "memory",
			NonceStoreType:  "memory",
			CleanupInterval: 5 * time.Minute,
		},
		Observability: ObservabilitySettings{
			MetricsEnabled:  true,
			LogLevel:        "info",
			TracingEnabled:  false,
			TracingProvider: "opentelemetry",
		},
		Network: NetworkSettings{
			ChunkedTransferTimeout: 30 * time.Second,
			ReadHeaderTimeout:      10 * time.Second,
			WriteTimeout:           30 * time.Second,
			IdleTimeout:            90 * time.Second,
		},
	}
}

// Validate checks if the settings are valid.
// Returns an error if any setting is invalid or incompatible.
//
// Future Implementation (issue #23):
//   - Validate MaxRequestSize > 0 and < 100MB
//   - Validate ClockSkew >= 0 and <= 5 minutes
//   - Validate storage backends are available
//   - Check Redis/Postgres URLs are parseable
//   - Validate log levels are recognized
//   - Ensure timeout values are reasonable
func (s *Settings) Validate() error {
	// Placeholder for future validation logic
	// See issue #23 for comprehensive validation requirements
	return nil
}

// ApplyToConfig applies Settings to the middleware Config struct.
// This bridges the gap between file-based Settings and runtime Config.
//
// Future Implementation (issue #23):
//   - Map Settings fields to Config fields
//   - Instantiate storage backends based on Settings
//   - Configure logger based on LogLevel
//   - Set up metrics/tracing exporters
//
// Example usage:
//
//	settings := LoadSettings("config.yaml")
//	config := &Config{...}
//	settings.ApplyToConfig(config)
func (s *Settings) ApplyToConfig(config *Config) error {
	// Placeholder for future implementation
	// Will be implemented when configuration system is built (issue #23)
	config.ClockSkew = s.Security.ClockSkew
	return nil
}
