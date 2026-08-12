package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// RequiredSecrets lists all environment variables that must be set in production.
var RequiredSecrets = []string{
	"DATABASE_URL",
	"JWT_SECRET",
}

// SecretConfig holds validated application secrets.
type SecretConfig struct {
	DatabaseURL string
	// AppDatabaseURL is the runtime application connection string. When set it
	// should point at the non-superuser edr_app role so PostgreSQL RLS is
	// actually enforced for tenant isolation (see migration 325 and
	// docs/security/マルチテナント分離ハードニング.md). When empty, callers fall
	// back to DatabaseURL (the owner role), preserving current behavior.
	// Migrations always run via DatabaseURL because they need owner/DDL rights.
	AppDatabaseURL string
	JWTSecret      string
	NATSUrl        string
	GRPCPort       string
	HTTPPort       string
	TLSCertFile    string
	TLSKeyFile     string
}

// LoadAndValidate loads secrets from environment and validates them.
func LoadAndValidate() (*SecretConfig, error) {
	cfg := &SecretConfig{
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		AppDatabaseURL: os.Getenv("APP_DATABASE_URL"),
		JWTSecret:      os.Getenv("JWT_SECRET"),
		NATSUrl:        getEnvDefault("NATS_URL", "nats://localhost:4222"),
		GRPCPort:       getEnvDefault("GRPC_PORT", "9090"),
		HTTPPort:       getEnvDefault("HTTP_PORT", "8080"),
		TLSCertFile:    os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:     os.Getenv("TLS_KEY_FILE"),
	}

	var errs []string

	if cfg.DatabaseURL == "" {
		errs = append(errs, "DATABASE_URL is required")
	}

	if cfg.JWTSecret == "" {
		errs = append(errs, "JWT_SECRET is required")
	} else if len(cfg.JWTSecret) < 32 {
		errs = append(errs, "JWT_SECRET must be at least 32 characters")
	}

	// Reject known-weak and default values
	weakSecrets := []string{
		"dev-secret", "secret", "changeme", "change-me", "change_me",
		"password", "your-secret-key", "jwt_secret", "supersecret",
		"dev-jwt-secret-change-in-production-32chars",
		"in-production", "in_production", "example",
	}
	lowerSecret := strings.ToLower(cfg.JWTSecret)
	for _, w := range weakSecrets {
		if strings.Contains(lowerSecret, w) {
			errs = append(errs, fmt.Sprintf("JWT_SECRET contains a known-weak value (%q) — set a strong random secret", w))
			break
		}
	}

	// Ensure sufficient character diversity (entropy check)
	chars := make(map[rune]struct{})
	for _, c := range cfg.JWTSecret {
		chars[c] = struct{}{}
	}
	if len(chars) < 8 {
		errs = append(errs, "JWT_SECRET has insufficient entropy (fewer than 8 unique characters)")
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("configuration errors:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return cfg, nil
}

// Validate checks config without loading — for testing.
func (c *SecretConfig) Validate() error {
	if c.DatabaseURL == "" {
		return errors.New("DatabaseURL is empty")
	}
	if len(c.JWTSecret) < 32 {
		return errors.New("JWTSecret is too short (min 32 chars)")
	}
	return nil
}

func getEnvDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
