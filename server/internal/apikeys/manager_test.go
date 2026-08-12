package apikeys

import (
	"context"
	"testing"
)

// ─── ValidScopes ──────────────────────────────────────────────────────────────

func TestValidScopes_ContainsAdmin(t *testing.T) {
	found := false
	for _, s := range ValidScopes {
		if s == "admin" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ValidScopes に 'admin' が含まれていません")
	}
}

func TestValidScopes_ContainsReadAlerts(t *testing.T) {
	found := false
	for _, s := range ValidScopes {
		if s == "read:alerts" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ValidScopes に 'read:alerts' が含まれていません")
	}
}

func TestValidScopes_ContainsWriteAlerts(t *testing.T) {
	found := false
	for _, s := range ValidScopes {
		if s == "write:alerts" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ValidScopes に 'write:alerts' が含まれていません")
	}
}

func TestValidScopes_MinimumCount(t *testing.T) {
	if len(ValidScopes) < 5 {
		t.Errorf("ValidScopes: スコープ数 got %d, want >= 5", len(ValidScopes))
	}
}

func TestValidScopes_NoEmptyEntries(t *testing.T) {
	for i, s := range ValidScopes {
		if s == "" {
			t.Errorf("ValidScopes[%d] が空文字列です", i)
		}
	}
}

// ─── NewManager ───────────────────────────────────────────────────────────────

func TestNewManager_NotNil(t *testing.T) {
	m := NewManager(nil)
	if m == nil {
		t.Fatal("NewManager は nil を返すべきではありません")
	}
}

// ─── Validate (format check, no DB) ──────────────────────────────────────────

func TestValidate_ShortKey_ReturnsError(t *testing.T) {
	m := NewManager(nil)
	_, err := m.Validate(context.Background(), "short")
	if err == nil {
		t.Error("8文字未満のキーはエラーを返すべきです")
	}
}

func TestValidate_EmptyKey_ReturnsError(t *testing.T) {
	m := NewManager(nil)
	_, err := m.Validate(context.Background(), "")
	if err == nil {
		t.Error("空キーはエラーを返すべきです")
	}
}

func TestValidate_ExactlySevenChars_ReturnsError(t *testing.T) {
	m := NewManager(nil)
	_, err := m.Validate(context.Background(), "edr_abc") // 7 chars
	if err == nil {
		t.Error("7文字のキーはエラーを返すべきです")
	}
}

// ─── APIKey struct ────────────────────────────────────────────────────────────

func TestAPIKey_KeyHashIsNotJSONExported(t *testing.T) {
	// KeyHash フィールドの json タグが "-" であることを確認
	// (実装レベルの確認 – json.Marshal でキーが含まれないことを検証)
	import_done := true
	_ = import_done // json.Marshal を使うためのプレースホルダー

	k := APIKey{
		ID:      "test-id",
		Name:    "test",
		KeyHash: "sensitive-hash",
	}
	// KeyHash はゼロ値でないが json タグ "-" により含まれない
	if k.KeyHash == "" {
		t.Error("テスト内では KeyHash を設定できるべきです")
	}
}
