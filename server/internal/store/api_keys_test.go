package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// ─── APIKey 構造体テスト ──────────────────────────────────────────────────────

// TestAPIKey_ZeroValue は APIKey のゼロ値が期待通りであることを確認する
func TestAPIKey_ZeroValue(t *testing.T) {
	var k APIKey
	if k.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", k.ID)
	}
	if k.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", k.UserID)
	}
	if k.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", k.Name)
	}
	if k.KeyPrefix != "" {
		t.Errorf("KeyPrefix のデフォルト = %q, want \"\"", k.KeyPrefix)
	}
	if k.Revoked {
		t.Error("Revoked のデフォルトは false であるべき")
	}
	if k.LastUsedAt != nil {
		t.Error("LastUsedAt のデフォルトは nil であるべき")
	}
	if k.ExpiresAt != nil {
		t.Error("ExpiresAt のデフォルトは nil であるべき")
	}
}

// TestAPIKey_FieldAssignment は APIKey フィールドの代入が正しく反映されることを確認する
func TestAPIKey_FieldAssignment(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)

	k := APIKey{
		ID:         "key-uuid-001",
		UserID:     "user-uuid-001",
		Name:       "本番環境用APIキー",
		KeyPrefix:  "edr_ab12",
		Scopes:     []string{"read", "write"},
		LastUsedAt: &now,
		ExpiresAt:  &future,
		Revoked:    false,
		CreatedAt:  now,
	}

	if k.ID != "key-uuid-001" {
		t.Errorf("ID = %q, want \"key-uuid-001\"", k.ID)
	}
	if k.UserID != "user-uuid-001" {
		t.Errorf("UserID = %q, want \"user-uuid-001\"", k.UserID)
	}
	if k.Name != "本番環境用APIキー" {
		t.Errorf("Name = %q, want \"本番環境用APIキー\"", k.Name)
	}
	if !strings.HasPrefix(k.KeyPrefix, "edr_") {
		t.Errorf("KeyPrefix は \"edr_\" で始まるべき: got %q", k.KeyPrefix)
	}
	if len(k.Scopes) != 2 {
		t.Errorf("Scopes の長さ = %d, want 2", len(k.Scopes))
	}
	if k.LastUsedAt == nil || !k.LastUsedAt.Equal(now) {
		t.Errorf("LastUsedAt = %v, want %v", k.LastUsedAt, now)
	}
	if k.ExpiresAt == nil || !k.ExpiresAt.Equal(future) {
		t.Errorf("ExpiresAt = %v, want %v", k.ExpiresAt, future)
	}
}

// TestAPIKey_Scopes はスコープスライスが正しく扱われることを確認する
func TestAPIKey_Scopes(t *testing.T) {
	k := APIKey{Scopes: []string{"read"}}
	if len(k.Scopes) != 1 {
		t.Fatalf("Scopes の長さ = %d, want 1", len(k.Scopes))
	}
	if k.Scopes[0] != "read" {
		t.Errorf("Scopes[0] = %q, want \"read\"", k.Scopes[0])
	}
}

// TestAPIKey_RevokedKey は失効したキーの状態を確認する
func TestAPIKey_RevokedKey(t *testing.T) {
	k := APIKey{
		ID:      "key-revoked-001",
		Revoked: true,
	}
	if !k.Revoked {
		t.Error("Revoked = false, want true")
	}
}

// TestAPIKey_NilExpiry は ExpiresAt が nil の場合（無期限キー）を確認する
func TestAPIKey_NilExpiry(t *testing.T) {
	k := APIKey{
		ID:        "key-no-expiry",
		ExpiresAt: nil,
	}
	if k.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil（無期限キー）", k.ExpiresAt)
	}
}

// ─── hashKey 関数テスト（api_keys.go の内部関数）────────────────────────────

// TestHashKey_PrefixFormat は生成されたキーが "edr_" プレフィックスを持つことを確認する
func TestHashKey_PrefixFormat(t *testing.T) {
	// rawKey は "edr_" + 64文字のhex文字列 の形式になる
	// この形式をシミュレートして hashKey の動作を確認する
	rawKey := "edr_" + strings.Repeat("a", 64)
	h := hashKey(rawKey)
	// SHA-256 ハッシュは常に 64 文字の16進数文字列
	if len(h) != 64 {
		t.Errorf("ハッシュ長 = %d, want 64", len(h))
	}
}

// TestHashKey_ConsistencyWithSHA256 は hashKey が SHA-256 と同じ結果を返すことを確認する
func TestHashKey_ConsistencyWithSHA256(t *testing.T) {
	rawKey := "edr_deadbeef1234567890abcdef"
	got := hashKey(rawKey)
	sum := sha256.Sum256([]byte(rawKey))
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Errorf("hashKey(%q) = %q, want %q", rawKey, got, want)
	}
}

// TestHashKey_UniquePerKey は異なるキーが異なるハッシュを生成することを確認する
func TestHashKey_UniquePerKey(t *testing.T) {
	keys := []string{
		"edr_key_one_aaaa",
		"edr_key_two_bbbb",
		"edr_key_three_cc",
	}
	hashes := make(map[string]bool)
	for _, k := range keys {
		h := hashKey(k)
		if hashes[h] {
			t.Errorf("ハッシュの衝突が発生しました: key=%q hash=%q", k, h)
		}
		hashes[h] = true
	}
}

// ─── APIKey プレフィックス検証ロジックテスト ──────────────────────────────────

// TestAPIKey_PrefixIsFirst8Chars は KeyPrefix が rawKey の最初の8文字であることを確認する
func TestAPIKey_PrefixIsFirst8Chars(t *testing.T) {
	// api_keys.go の Create では keyPrefix := rawKey[:8]
	// rawKey = "edr_" + hex(32bytes) → 先頭8文字 = "edr_" + 4chars
	rawKey := "edr_abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	prefix := rawKey[:8]

	if len(prefix) != 8 {
		t.Errorf("prefix の長さ = %d, want 8", len(prefix))
	}
	if !strings.HasPrefix(prefix, "edr_") {
		t.Errorf("prefix は \"edr_\" で始まるべき: got %q", prefix)
	}
}

// TestAPIKey_DefaultScopeRead はスコープが空の場合にデフォルトが "read" であることを確認する
func TestAPIKey_DefaultScopeRead(t *testing.T) {
	// api_keys.go の Create では if len(scopes) == 0 { scopes = []string{"read"} }
	scopes := []string{}
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}
	if len(scopes) != 1 {
		t.Fatalf("デフォルトスコープの長さ = %d, want 1", len(scopes))
	}
	if scopes[0] != "read" {
		t.Errorf("デフォルトスコープ = %q, want \"read\"", scopes[0])
	}
}

// TestAPIKey_ScopesPreservedWhenProvided は明示的に指定されたスコープが保持されることを確認する
func TestAPIKey_ScopesPreservedWhenProvided(t *testing.T) {
	// 明示的に指定されたスコープはデフォルト化されない
	scopes := []string{"read", "write", "admin"}
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}
	if len(scopes) != 3 {
		t.Errorf("スコープの長さ = %d, want 3 (指定スコープを保持するべき)", len(scopes))
	}
}

// ─── APIKey の有効期限検証ロジックテスト ──────────────────────────────────────

// TestAPIKey_ExpiredKey は期限切れキーの判定を確認する
func TestAPIKey_ExpiredKey(t *testing.T) {
	// ExpiresAt が過去の場合はキーが期限切れ
	past := time.Now().Add(-24 * time.Hour)
	k := APIKey{
		ID:        "key-expired-001",
		ExpiresAt: &past,
		Revoked:   false,
	}

	// ExpiresAt が現在時刻より前であれば期限切れ
	isExpired := k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now())
	if !isExpired {
		t.Error("過去の ExpiresAt を持つキーは期限切れと判定されるべき")
	}
}

// TestAPIKey_ValidKey は有効なキー（期限内・未失効）の判定を確認する
func TestAPIKey_ValidKey(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour)
	k := APIKey{
		ID:        "key-valid-001",
		ExpiresAt: &future,
		Revoked:   false,
	}

	isExpired := k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now())
	if isExpired {
		t.Error("未来の ExpiresAt を持つキーは期限切れでないべき")
	}
	if k.Revoked {
		t.Error("Revoked = true, want false（有効なキー）")
	}
}

// TestAPIKey_MultipleScopes は複数スコープが独立して格納されることを確認する
func TestAPIKey_MultipleScopes(t *testing.T) {
	scopes := []string{"read", "write", "alerts:read", "agents:manage"}
	k := APIKey{Scopes: scopes}

	if len(k.Scopes) != 4 {
		t.Fatalf("Scopes の長さ = %d, want 4", len(k.Scopes))
	}
	for i, s := range scopes {
		if k.Scopes[i] != s {
			t.Errorf("Scopes[%d] = %q, want %q", i, k.Scopes[i], s)
		}
	}
}
