package handlers

import "testing"

// ─── isValidUserRole ──────────────────────────────────────────────────────

func TestIsValidUserRole_ValidRoles(t *testing.T) {
	for _, r := range []string{"admin", "analyst", "viewer"} {
		if !isValidUserRole(r) {
			t.Errorf("ロール %q は有効なはず", r)
		}
	}
}

func TestIsValidUserRole_InvalidRoles(t *testing.T) {
	for _, r := range []string{"", "superadmin", "root", "ADMIN", "Analyst", "guest"} {
		if isValidUserRole(r) {
			t.Errorf("ロール %q は無効なはず", r)
		}
	}
}

func TestIsValidUserRole_CaseSensitive(t *testing.T) {
	if isValidUserRole("Admin") {
		t.Error("'Admin' (大文字) は無効なはず")
	}
	if isValidUserRole("VIEWER") {
		t.Error("'VIEWER' (大文字) は無効なはず")
	}
}

func TestIsValidUserRole_EmptyString(t *testing.T) {
	if isValidUserRole("") {
		t.Error("空文字は無効なはず")
	}
}

// ─── validUserRoles map ───────────────────────────────────────────────────

func TestValidUserRolesMap_ContainsAll(t *testing.T) {
	expected := []string{"admin", "analyst", "viewer"}
	for _, r := range expected {
		if !validUserRoles[r] {
			t.Errorf("validUserRoles に %q が含まれていません", r)
		}
	}
	// Exactly 3 roles
	if len(validUserRoles) != 3 {
		t.Errorf("validUserRoles は3エントリのはず、got %d", len(validUserRoles))
	}
}
