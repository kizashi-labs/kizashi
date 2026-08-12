package config

import (
	"strings"
	"testing"
)

// ─── RequiredSecrets ──────────────────────────────────────────────────────────

func TestRequiredSecrets_ContainsDatabaseURL(t *testing.T) {
	found := false
	for _, s := range RequiredSecrets {
		if s == "DATABASE_URL" {
			found = true
		}
	}
	if !found {
		t.Error("RequiredSecrets に DATABASE_URL が含まれていません")
	}
}

func TestRequiredSecrets_ContainsJWTSecret(t *testing.T) {
	found := false
	for _, s := range RequiredSecrets {
		if s == "JWT_SECRET" {
			found = true
		}
	}
	if !found {
		t.Error("RequiredSecrets に JWT_SECRET が含まれていません")
	}
}

// ─── SecretConfig.Validate ────────────────────────────────────────────────────

func TestValidate_EmptyDatabaseURL_ReturnsError(t *testing.T) {
	c := &SecretConfig{
		DatabaseURL: "",
		JWTSecret:   "this-is-a-long-enough-secret-key!!", // 32+ chars
	}
	if err := c.Validate(); err == nil {
		t.Error("DatabaseURL が空の場合はエラーを返すべきです")
	}
}

func TestValidate_ShortJWTSecret_ReturnsError(t *testing.T) {
	c := &SecretConfig{
		DatabaseURL: "postgres://localhost/edr",
		JWTSecret:   "short", // < 32 chars
	}
	if err := c.Validate(); err == nil {
		t.Error("JWTSecret が32文字未満の場合はエラーを返すべきです")
	}
}

func TestValidate_ValidConfig_ReturnsNil(t *testing.T) {
	c := &SecretConfig{
		DatabaseURL: "postgres://localhost/edr",
		JWTSecret:   "this-is-a-long-enough-secret-key!!", // 32+ chars
	}
	if err := c.Validate(); err != nil {
		t.Errorf("有効な設定でエラーが返りました: %v", err)
	}
}

func TestValidate_ExactlyShortSecret_ReturnsError(t *testing.T) {
	c := &SecretConfig{
		DatabaseURL: "postgres://localhost/edr",
		JWTSecret:   strings.Repeat("a", 31), // 31 chars = too short
	}
	if err := c.Validate(); err == nil {
		t.Error("31文字の JWTSecret はエラーを返すべきです")
	}
}

func TestValidate_Exactly32Chars_IsValid(t *testing.T) {
	c := &SecretConfig{
		DatabaseURL: "postgres://localhost/edr",
		JWTSecret:   strings.Repeat("x", 32), // exactly 32
	}
	if err := c.Validate(); err != nil {
		t.Errorf("32文字の JWTSecret は有効なはずです: %v", err)
	}
}

// ─── getEnvDefault ────────────────────────────────────────────────────────────

func TestGetEnvDefault_UnsetKey_ReturnsDefault(t *testing.T) {
	// 存在しない環境変数
	got := getEnvDefault("__NON_EXISTENT_KEY_XYZ__", "fallback-value")
	if got != "fallback-value" {
		t.Errorf("getEnvDefault (未設定): got %q, want fallback-value", got)
	}
}

func TestGetEnvDefault_SetKey_ReturnsEnvValue(t *testing.T) {
	t.Setenv("__TEST_ENV_KEY__", "custom-value")
	got := getEnvDefault("__TEST_ENV_KEY__", "fallback-value")
	if got != "custom-value" {
		t.Errorf("getEnvDefault (設定済み): got %q, want custom-value", got)
	}
}

// ─── LoadAndValidate ──────────────────────────────────────────────────────────

func TestLoadAndValidate_MissingBothVars_ReturnsError(t *testing.T) {
	// 環境変数を空にする
	t.Setenv("DATABASE_URL", "")
	t.Setenv("JWT_SECRET", "")
	_, err := LoadAndValidate()
	if err == nil {
		t.Error("必須変数なしはエラーを返すべきです")
	}
}

func TestLoadAndValidate_MissingDatabaseURL_ReturnsError(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("JWT_SECRET", "this-is-a-strong-and-long-secret-key-1234!")
	_, err := LoadAndValidate()
	if err == nil {
		t.Error("DATABASE_URL なしはエラーを返すべきです")
	}
}

func TestLoadAndValidate_ShortJWTSecret_ReturnsError(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/edr")
	t.Setenv("JWT_SECRET", "tooshort")
	_, err := LoadAndValidate()
	if err == nil {
		t.Error("短い JWT_SECRET はエラーを返すべきです")
	}
}

func TestLoadAndValidate_WeakSecret_ReturnsError(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/edr")
	t.Setenv("JWT_SECRET", "dev-secret-that-is-long-enough-for-test")
	_, err := LoadAndValidate()
	if err == nil {
		t.Error("弱いシークレット (dev-secret を含む) はエラーを返すべきです")
	}
}

func TestLoadAndValidate_HyphenatedChangeme_ReturnsError(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/edr")
	t.Setenv("JWT_SECRET", "change-me-in-production-at-least-32-chars")
	_, err := LoadAndValidate()
	if err == nil {
		t.Error("弱いシークレット (change-me を含む) はエラーを返すべきです")
	}
}

func TestLoadAndValidate_LowEntropySecret_ReturnsError(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/edr")
	// 32文字だが全て同一文字 → エントロピー不足
	t.Setenv("JWT_SECRET", strings.Repeat("a", 40))
	_, err := LoadAndValidate()
	if err == nil {
		t.Error("エントロピー不足のシークレットはエラーを返すべきです")
	}
}

func TestLoadAndValidate_ValidConfig_ReturnsConfig(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/edr")
	// 強いシークレット: 32文字以上 + 多様な文字 + 弱ワードなし
	t.Setenv("JWT_SECRET", "Str0ng!R@nd0m#Secr3t$Key%2026&Long")
	cfg, err := LoadAndValidate()
	if err != nil {
		t.Fatalf("有効な設定でエラーが返りました: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg が nil です")
	}
	if cfg.DatabaseURL != "postgres://localhost/edr" {
		t.Errorf("DatabaseURL: got %q", cfg.DatabaseURL)
	}
}

func TestLoadAndValidate_DefaultPorts(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/edr")
	t.Setenv("JWT_SECRET", "Str0ng!R@nd0m#Secr3t$Key%2026&Long")
	t.Setenv("GRPC_PORT", "")
	t.Setenv("HTTP_PORT", "")
	cfg, err := LoadAndValidate()
	if err != nil {
		t.Fatalf("LoadAndValidate: %v", err)
	}
	if cfg.GRPCPort != "9090" {
		t.Errorf("デフォルト GRPCPort: got %q, want 9090", cfg.GRPCPort)
	}
	if cfg.HTTPPort != "8080" {
		t.Errorf("デフォルト HTTPPort: got %q, want 8080", cfg.HTTPPort)
	}
}
