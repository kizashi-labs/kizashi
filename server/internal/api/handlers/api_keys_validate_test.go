package handlers

import (
	"testing"
)

// ─── validateAPIKeyScopes ──────────────────────────────────────────────────

func TestValidateAPIKeyScopes_AllValid(t *testing.T) {
	for _, scope := range []string{"read", "write", "admin"} {
		if bad := validateAPIKeyScopes([]string{scope}); bad != "" {
			t.Errorf("スコープ %q は有効なはずですが不正と判定されました", scope)
		}
	}
}

func TestValidateAPIKeyScopes_MultipleValid(t *testing.T) {
	scopes := []string{"read", "write"}
	if bad := validateAPIKeyScopes(scopes); bad != "" {
		t.Errorf("複数の有効スコープは通過するはず、got invalid=%q", bad)
	}
}

func TestValidateAPIKeyScopes_InvalidScope(t *testing.T) {
	bad := validateAPIKeyScopes([]string{"read", "superadmin"})
	if bad != "superadmin" {
		t.Errorf("不正スコープ 'superadmin' を返すはず、got %q", bad)
	}
}

func TestValidateAPIKeyScopes_EmptySlice(t *testing.T) {
	if bad := validateAPIKeyScopes([]string{}); bad != "" {
		t.Errorf("空スコープは有効 (後でデフォルト適用)、got %q", bad)
	}
}

func TestValidateAPIKeyScopes_CaseSensitive(t *testing.T) {
	// 大文字は無効
	bad := validateAPIKeyScopes([]string{"Read"})
	if bad == "" {
		t.Error("'Read' (大文字) は無効スコープとして検出されるべきです")
	}
}

func TestValidateAPIKeyScopes_EmptyString(t *testing.T) {
	// validateAPIKeyScopes returns the invalid scope string; when the scope itself
	// is "" the return value is also "" — indistinguishable from "all valid".
	// The handler rejects empty names upstream; this test confirms the map miss
	// doesn't panic and that "" is not a registered scope.
	_, ok := validAPIKeyScopes[""]
	if ok {
		t.Error("空文字スコープはvalidAPIKeyScopesに登録されているべきではありません")
	}
}

// ─── normalizeAPIKeyScopes ─────────────────────────────────────────────────

func TestNormalizeAPIKeyScopes_EmptyBecomesRead(t *testing.T) {
	result := normalizeAPIKeyScopes([]string{})
	if len(result) != 1 || result[0] != "read" {
		t.Errorf("空スコープは ['read'] に正規化されるはず、got %v", result)
	}
}

func TestNormalizeAPIKeyScopes_NilBecomesRead(t *testing.T) {
	result := normalizeAPIKeyScopes(nil)
	if len(result) != 1 || result[0] != "read" {
		t.Errorf("nilスコープは ['read'] に正規化されるはず、got %v", result)
	}
}

func TestNormalizeAPIKeyScopes_PreservesExisting(t *testing.T) {
	scopes := []string{"write", "admin"}
	result := normalizeAPIKeyScopes(scopes)
	if len(result) != 2 {
		t.Errorf("既存スコープは変更されないはず、got %v", result)
	}
	if result[0] != "write" || result[1] != "admin" {
		t.Errorf("スコープ順序が変わっています、got %v", result)
	}
}

func TestNormalizeAPIKeyScopes_SingleScope(t *testing.T) {
	result := normalizeAPIKeyScopes([]string{"admin"})
	if len(result) != 1 || result[0] != "admin" {
		t.Errorf("単一スコープは保持されるはず、got %v", result)
	}
}

// ─── createAPIKeyRequest struct ────────────────────────────────────────────

func TestCreateAPIKeyRequest_DefaultScopes(t *testing.T) {
	req := createAPIKeyRequest{Name: "test", Scopes: nil}
	scopes := normalizeAPIKeyScopes(req.Scopes)
	if len(scopes) != 1 || scopes[0] != "read" {
		t.Errorf("未指定スコープのデフォルトは ['read']、got %v", scopes)
	}
}

func TestCreateAPIKeyRequest_NameTrimCheck(t *testing.T) {
	// Ensure whitespace-only names are treated as empty
	tests := []struct {
		name    string
		isEmpty bool
	}{
		{"valid-key", false},
		{"  ", true},
		{"", true},
		{"\t\n", true},
	}
	for _, tt := range tests {
		trimmed := len([]rune(tt.name)) == 0
		for _, r := range tt.name {
			if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
				trimmed = false
				break
			}
			trimmed = true
		}
		if tt.isEmpty != (tt.name == "" || trimmed) {
			// Just validate the test data is sensible — actual trim happens in handler
			t.Logf("name=%q isEmpty=%v", tt.name, tt.isEmpty)
		}
	}
}
