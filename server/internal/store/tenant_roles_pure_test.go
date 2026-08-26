package store

import (
	"testing"
)

// ─── roleWeight マップテスト ──────────────────────────────────────────────────

// TestRoleWeight_KnownRolesExist は既知のロールが roleWeight に定義されていることを確認する
func TestRoleWeight_KnownRolesExist(t *testing.T) {
	// roleWeight はパッケージレベルの変数として直接アクセスできる
	knownRoles := []string{"tenant_admin", "analyst", "viewer"}
	for _, role := range knownRoles {
		if _, ok := roleWeight[role]; !ok {
			t.Errorf("ロール %q が roleWeight に定義されていない", role)
		}
	}
}

// TestRoleWeight_AdminHasHighestWeight は tenant_admin が最も高い重みを持つことを確認する
func TestRoleWeight_AdminHasHighestWeight(t *testing.T) {
	adminWeight := roleWeight["tenant_admin"]
	for role, weight := range roleWeight {
		if role != "tenant_admin" && weight >= adminWeight {
			t.Errorf("ロール %q の重み %d は tenant_admin の %d 以上であってはならない", role, weight, adminWeight)
		}
	}
}

// TestRoleWeight_ViewerHasLowestWeight は viewer が最も低い重みを持つことを確認する
func TestRoleWeight_ViewerHasLowestWeight(t *testing.T) {
	viewerWeight := roleWeight["viewer"]
	for role, weight := range roleWeight {
		if role != "viewer" && weight <= viewerWeight {
			t.Errorf("ロール %q の重み %d は viewer の %d 以下であってはならない", role, weight, viewerWeight)
		}
	}
}

// TestRoleWeight_OrderIsCorrect はロールの優先順位が正しいことを確認する
// 期待順序: tenant_admin (3) > analyst (2) > viewer (1)
func TestRoleWeight_OrderIsCorrect(t *testing.T) {
	adminW := roleWeight["tenant_admin"]
	analystW := roleWeight["analyst"]
	viewerW := roleWeight["viewer"]

	if adminW <= analystW {
		t.Errorf("tenant_admin (%d) は analyst (%d) より高い重みを持つべき", adminW, analystW)
	}
	if analystW <= viewerW {
		t.Errorf("analyst (%d) は viewer (%d) より高い重みを持つべき", analystW, viewerW)
	}
	if adminW <= viewerW {
		t.Errorf("tenant_admin (%d) は viewer (%d) より高い重みを持つべき", adminW, viewerW)
	}
}

// TestRoleWeight_UnknownRoleNotDefined は未知のロールが roleWeight に含まれないことを確認する
func TestRoleWeight_UnknownRoleNotDefined(t *testing.T) {
	unknownRoles := []string{"superadmin", "guest", "operator", "admin", ""}
	for _, role := range unknownRoles {
		if _, ok := roleWeight[role]; ok {
			t.Errorf("未知のロール %q が roleWeight に定義されている（想定外）", role)
		}
	}
}

// ─── ロール権限比較ロジックテスト ─────────────────────────────────────────────

// hasRolePure は **本物を呼びます。**
//
// 以前ここには HasRole の比較を書き写したものが置いてありました。
// 測りました (2026-08-11): 製品側の `>=` を `<=` に変えても、**落ちる検査は
// ありませんでした** —— viewer が tenant_admin の要件を満たし、
// tenant_admin が満たさなくなっても緑のままです。試していたのは、
// 検査自身の写しです。
//
// 2つ目の戻り値（比較が成立したか）は、写しにしかない区別でした。
// 本物は「知らないロールは満たさない」で false を返します。
func hasRolePure(currentRole, requiredRole string) (bool, bool) {
	_, requiredOk := roleWeight[requiredRole]
	_, currentOk := roleWeight[currentRole]
	if !requiredOk || !currentOk {
		return false, false
	}
	return roleAtLeast(currentRole, requiredRole), true
}

// 知らないロールを、強い方に倒さないこと。
//
// **roleAtLeast は本物の判定です。** 知らない値が来たときに true を
// 返すと、綴りを間違えたロール名がすべての要件を満たします。
func TestRoleAtLeastRefusesUnknownRoles(t *testing.T) {
	for _, tc := range []struct{ current, required string }{
		{"superadmin", "viewer"},
		{"tenant_admin", "superadmin"},
		{"", "viewer"},
		{"viewer", ""},
	} {
		if roleAtLeast(tc.current, tc.required) {
			t.Errorf("roleAtLeast(%q, %q) = true。**知らないロールを"+
				"満たしていることにしています**", tc.current, tc.required)
		}
	}
}

// 順序が、強い方から弱い方へ効くこと。**反転していないこと。**
func TestRoleAtLeastIsNotInverted(t *testing.T) {
	if !roleAtLeast("tenant_admin", "viewer") {
		t.Error("tenant_admin が viewer の要件を満たしていません")
	}
	if roleAtLeast("viewer", "tenant_admin") {
		t.Error("**viewer が tenant_admin の要件を満たしています。** " +
			"判定が反転しています")
	}
	if !roleAtLeast("analyst", "analyst") {
		t.Error("同じロールが自分の要件を満たしていません")
	}
}

// TestHasRolePure_AdminMeetsAllRequirements は tenant_admin が全ロール要件を満たすことを確認する
func TestHasRolePure_AdminMeetsAllRequirements(t *testing.T) {
	requirements := []string{"tenant_admin", "analyst", "viewer"}
	for _, req := range requirements {
		ok, valid := hasRolePure("tenant_admin", req)
		if !valid {
			t.Errorf("tenant_admin vs %q: 有効な比較であるべき", req)
			continue
		}
		if !ok {
			t.Errorf("tenant_admin は %q の要件を満たすべき", req)
		}
	}
}

// TestHasRolePure_ViewerOnlyMeetsViewerRequirement は viewer が viewer 要件のみ満たすことを確認する
func TestHasRolePure_ViewerOnlyMeetsViewerRequirement(t *testing.T) {
	cases := []struct {
		required string
		expected bool
	}{
		{"viewer", true},
		{"analyst", false},
		{"tenant_admin", false},
	}
	for _, tc := range cases {
		ok, valid := hasRolePure("viewer", tc.required)
		if !valid {
			t.Errorf("viewer vs %q: 有効な比較であるべき", tc.required)
			continue
		}
		if ok != tc.expected {
			t.Errorf("viewer has %q = %v, want %v", tc.required, ok, tc.expected)
		}
	}
}

// TestHasRolePure_AnalystMeetsAnalystAndViewer は analyst が analyst と viewer の要件を満たすことを確認する
func TestHasRolePure_AnalystMeetsAnalystAndViewer(t *testing.T) {
	cases := []struct {
		required string
		expected bool
	}{
		{"viewer", true},
		{"analyst", true},
		{"tenant_admin", false},
	}
	for _, tc := range cases {
		ok, valid := hasRolePure("analyst", tc.required)
		if !valid {
			t.Errorf("analyst vs %q: 有効な比較であるべき", tc.required)
			continue
		}
		if ok != tc.expected {
			t.Errorf("analyst has %q = %v, want %v", tc.required, ok, tc.expected)
		}
	}
}

// TestHasRolePure_UnknownCurrentRole は未知の現在ロールが false を返すことを確認する
func TestHasRolePure_UnknownCurrentRole(t *testing.T) {
	ok, valid := hasRolePure("superadmin", "viewer")
	if valid {
		t.Error("未知の current ロールは有効な比較として扱われるべきでない")
	}
	if ok {
		t.Error("未知の current ロールは false を返すべき")
	}
}

// TestHasRolePure_UnknownRequiredRole は未知の required ロールが false を返すことを確認する
func TestHasRolePure_UnknownRequiredRole(t *testing.T) {
	ok, valid := hasRolePure("tenant_admin", "superadmin")
	if valid {
		t.Error("未知の required ロールは有効な比較として扱われるべきでない")
	}
	if ok {
		t.Error("未知の required ロールは false を返すべき")
	}
}

// ─── TenantRole 構造体テスト ──────────────────────────────────────────────────

// TestTenantRole_ZeroValue は TenantRole のゼロ値が期待通りであることを確認する
func TestTenantRole_ZeroValue(t *testing.T) {
	var r TenantRole
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.TenantID != "" {
		t.Errorf("TenantID のデフォルト = %q, want \"\"", r.TenantID)
	}
	if r.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", r.UserID)
	}
	if r.Role != "" {
		t.Errorf("Role のデフォルト = %q, want \"\"", r.Role)
	}
	if r.GrantedBy != "" {
		t.Errorf("GrantedBy のデフォルト = %q, want \"\"", r.GrantedBy)
	}
}

// TestTenantRole_FieldAssignment は TenantRole のフィールド代入を確認する
func TestTenantRole_FieldAssignment(t *testing.T) {
	r := TenantRole{
		ID:        "role-001",
		TenantID:  "tenant-abc",
		UserID:    "user-xyz",
		Role:      "analyst",
		GrantedBy: "admin-user-001",
		CreatedAt: "2024-01-15T10:00:00Z",
	}

	if r.TenantID != "tenant-abc" {
		t.Errorf("TenantID = %q, want \"tenant-abc\"", r.TenantID)
	}
	if r.Role != "analyst" {
		t.Errorf("Role = %q, want \"analyst\"", r.Role)
	}
	if r.GrantedBy != "admin-user-001" {
		t.Errorf("GrantedBy = %q, want \"admin-user-001\"", r.GrantedBy)
	}
}

// TestTenantRole_GrantedByIsOptional は GrantedBy フィールドが省略可能であることを確認する
func TestTenantRole_GrantedByIsOptional(t *testing.T) {
	// GrantedBy は空文字列として表現する（JSON では omitempty）
	r := TenantRole{
		TenantID: "tenant-001",
		UserID:   "user-001",
		Role:     "viewer",
	}
	if r.GrantedBy != "" {
		t.Errorf("GrantedBy のデフォルトは空文字列であるべき: got %q", r.GrantedBy)
	}
}

// TestTenantRole_ValidRolesFromWeight は roleWeight のキーが有効なロール値であることを確認する
func TestTenantRole_ValidRolesFromWeight(t *testing.T) {
	for role := range roleWeight {
		r := TenantRole{Role: role}
		// roleWeight に存在するロールは有効なロール値である
		if _, ok := roleWeight[r.Role]; !ok {
			t.Errorf("ロール %q は roleWeight に含まれるべき", r.Role)
		}
	}
}
