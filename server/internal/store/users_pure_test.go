package store

import (
	"strings"
	"testing"
	"time"
)

// ─── UserRow 構造体フィールドテスト ──────────────────────────────────────────

// TestUserRow_DefaultBoolFields は UserRow の bool フィールドのゼロ値を確認する
func TestUserRow_DefaultBoolFields(t *testing.T) {
	var u UserRow
	// 新規ゼロ値では MFAEnabled・IsActive・MustChangePassword はすべて false
	if u.MFAEnabled {
		t.Error("MFAEnabled のデフォルトは false であるべき")
	}
	if u.IsActive {
		t.Error("IsActive のデフォルトは false であるべき")
	}
	if u.MustChangePassword {
		t.Error("MustChangePassword のデフォルトは false であるべき")
	}
}

// TestUserRow_RoleFieldAssignment はロールフィールドが正しく設定・取得できることを確認する
func TestUserRow_RoleFieldAssignment(t *testing.T) {
	roles := []string{"admin", "analyst", "viewer", "operator"}
	for _, role := range roles {
		u := UserRow{Role: role}
		if u.Role != role {
			t.Errorf("Role = %q, want %q", u.Role, role)
		}
	}
}

// TestUserRow_EmailFieldAssignment はメールフィールドへの代入が正確であることを確認する
func TestUserRow_EmailFieldAssignment(t *testing.T) {
	emails := []struct {
		input string
		valid bool
	}{
		{"user@example.com", true},
		{"admin@company.org", true},
		{"invalid-no-at-sign", false},
		{"", false},
	}
	for _, tc := range emails {
		u := UserRow{Email: tc.input}
		hasAt := strings.Contains(u.Email, "@")
		if tc.valid && !hasAt {
			t.Errorf("有効なメール %q は '@' を含むべき", tc.input)
		}
		if !tc.valid && tc.input != "" && hasAt {
			t.Errorf("無効なメール %q は '@' を含まないべき", tc.input)
		}
	}
}

// TestUserRow_LastLoginNilByDefault は LastLogin フィールドがデフォルトで nil であることを確認する
func TestUserRow_LastLoginNilByDefault(t *testing.T) {
	var u UserRow
	if u.LastLogin != nil {
		t.Error("LastLogin のデフォルトは nil であるべき")
	}
}

// TestUserRow_LastLoginCanBeSet は LastLogin に time.Time ポインタを設定できることを確認する
func TestUserRow_LastLoginCanBeSet(t *testing.T) {
	now := time.Now()
	u := UserRow{LastLogin: &now}
	if u.LastLogin == nil {
		t.Fatal("LastLogin に値を設定した後は nil でないべき")
	}
	if !u.LastLogin.Equal(now) {
		t.Errorf("LastLogin = %v, want %v", u.LastLogin, now)
	}
}

// TestUserRow_TenantIDEmptyByDefault は TenantID のデフォルトが空文字列であることを確認する
func TestUserRow_TenantIDEmptyByDefault(t *testing.T) {
	var u UserRow
	if u.TenantID != "" {
		t.Errorf("TenantID のデフォルトは空文字列であるべき: got %q", u.TenantID)
	}
}

// TestUserRow_MFAEnabledToggle は MFAEnabled フラグを切り替えられることを確認する
func TestUserRow_MFAEnabledToggle(t *testing.T) {
	u := UserRow{MFAEnabled: false}
	u.MFAEnabled = true
	if !u.MFAEnabled {
		t.Error("MFAEnabled を true に設定後は true であるべき")
	}
	u.MFAEnabled = false
	if u.MFAEnabled {
		t.Error("MFAEnabled を false に戻した後は false であるべき")
	}
}

// ─── ロール検証ヘルパーテスト ────────────────────────────────────────────────

// isValidUserRole は既知のロールかどうかを判定する純粋関数（テスト内インライン定義）
func isValidUserRole(role string) bool {
	switch role {
	case "admin", "analyst", "viewer", "operator":
		return true
	}
	return false
}

// TestIsValidUserRole_KnownRolesAreValid は既知ロールがすべて有効と判定されることを確認する
func TestIsValidUserRole_KnownRolesAreValid(t *testing.T) {
	validRoles := []string{"admin", "analyst", "viewer", "operator"}
	for _, r := range validRoles {
		if !isValidUserRole(r) {
			t.Errorf("ロール %q は有効であるべき", r)
		}
	}
}

// TestIsValidUserRole_UnknownRolesAreInvalid は不明ロールが無効と判定されることを確認する
func TestIsValidUserRole_UnknownRolesAreInvalid(t *testing.T) {
	invalidRoles := []string{"superuser", "root", "god", "", "ADMIN", "Admin"}
	for _, r := range invalidRoles {
		if isValidUserRole(r) {
			t.Errorf("ロール %q は無効であるべき", r)
		}
	}
}

// TestIsValidUserRole_CaseSensitive はロール判定が大文字小文字を区別することを確認する
func TestIsValidUserRole_CaseSensitive(t *testing.T) {
	// "ADMIN" は "admin" と異なり、無効であるべき
	if isValidUserRole("ADMIN") {
		t.Error("ロール判定は大文字小文字を区別するべき ('ADMIN' は無効)")
	}
	if isValidUserRole("Analyst") {
		t.Error("ロール判定は大文字小文字を区別するべき ('Analyst' は無効)")
	}
}

// ─── GenerateBackupCodes 純粋ロジックテスト ──────────────────────────────────

// TestGenerateBackupCodes_ReturnsCorrectCount は要求件数のコードを返すことを確認する
func TestGenerateBackupCodes_ReturnsCorrectCount(t *testing.T) {
	codes, err := GenerateBackupCodes(8)
	if err != nil {
		t.Fatalf("GenerateBackupCodes(8) エラー: %v", err)
	}
	if len(codes) != 8 {
		t.Errorf("コード数 = %d, want 8", len(codes))
	}
}

// TestGenerateBackupCodes_CodesAreHexFormat は各コードが8文字の16進数であることを確認する
func TestGenerateBackupCodes_CodesAreHexFormat(t *testing.T) {
	codes, err := GenerateBackupCodes(5)
	if err != nil {
		t.Fatalf("GenerateBackupCodes(5) エラー: %v", err)
	}
	for _, code := range codes {
		// 4バイト → 8文字の16進数
		if len(code) != 8 {
			t.Errorf("コード長 = %d, want 8: code=%q", len(code), code)
		}
		for _, c := range code {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("コード %q に不正な文字: %q", code, string(c))
			}
		}
	}
}

// TestGenerateBackupCodes_CodesAreUnique は生成コードが重複していないことを確認する
func TestGenerateBackupCodes_CodesAreUnique(t *testing.T) {
	codes, err := GenerateBackupCodes(10)
	if err != nil {
		t.Fatalf("GenerateBackupCodes(10) エラー: %v", err)
	}
	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Errorf("重複コードが生成された: %q", code)
		}
		seen[code] = true
	}
}

// TestGenerateBackupCodes_ZeroCountReturnsEmptySlice は n=0 で空スライスが返ることを確認する
func TestGenerateBackupCodes_ZeroCountReturnsEmptySlice(t *testing.T) {
	codes, err := GenerateBackupCodes(0)
	if err != nil {
		t.Fatalf("GenerateBackupCodes(0) エラー: %v", err)
	}
	if len(codes) != 0 {
		t.Errorf("コード数 = %d, want 0", len(codes))
	}
}

// TestGenerateBackupCodes_TwoCallsProduceDifferentCodes は2回呼び出しで異なるコードが生成されることを確認する
func TestGenerateBackupCodes_TwoCallsProduceDifferentCodes(t *testing.T) {
	codes1, _ := GenerateBackupCodes(4)
	codes2, _ := GenerateBackupCodes(4)
	allSame := true
	for i := range codes1 {
		if codes1[i] != codes2[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("2回の呼び出しが全て同じコードを返した（ランダム性がない）")
	}
}
