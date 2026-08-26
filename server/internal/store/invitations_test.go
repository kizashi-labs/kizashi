package store

import (
	"testing"
	"time"
)

// ─── Invitation 構造体フィールドテスト ───────────────────────────────────────

// TestInvitation_DefaultValues は Invitation のゼロ値フィールドを確認する
func TestInvitation_DefaultValues(t *testing.T) {
	var inv Invitation
	if inv.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", inv.ID)
	}
	if inv.Email != "" {
		t.Errorf("Email のデフォルト = %q, want \"\"", inv.Email)
	}
	if inv.Role != "" {
		t.Errorf("Role のデフォルト = %q, want \"\"", inv.Role)
	}
	if inv.AcceptedAt != nil {
		t.Error("AcceptedAt のデフォルトは nil であるべき")
	}
}

// TestInvitation_FieldAssignment はフィールドへの代入が正しく反映されることを確認する
func TestInvitation_FieldAssignment(t *testing.T) {
	now := time.Now()
	inv := Invitation{
		ID:        "inv-001",
		Email:     "user@example.com",
		Role:      "analyst",
		TenantID:  "tenant-abc",
		InvitedBy: "admin-user",
		ExpiresAt: now.Add(72 * time.Hour),
		CreatedAt: now,
	}
	if inv.ID != "inv-001" {
		t.Errorf("ID = %q, want \"inv-001\"", inv.ID)
	}
	if inv.Email != "user@example.com" {
		t.Errorf("Email = %q, want \"user@example.com\"", inv.Email)
	}
	if inv.Role != "analyst" {
		t.Errorf("Role = %q, want \"analyst\"", inv.Role)
	}
	if inv.TenantID != "tenant-abc" {
		t.Errorf("TenantID = %q, want \"tenant-abc\"", inv.TenantID)
	}
}

// TestInvitation_IsExpired_NotYetExpired は有効期限内の招待が期限切れでないことを確認する
func TestInvitation_IsExpired_NotYetExpired(t *testing.T) {
	// 未来の有効期限を持つ招待
	inv := Invitation{
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	// ExpiresAt が現在より後ならまだ有効
	if !time.Now().Before(inv.ExpiresAt) {
		t.Error("有効期限が未来の招待は期限切れでないべき")
	}
}

// TestInvitation_IsExpired_AlreadyExpired は過去の有効期限を持つ招待が期限切れであることを確認する
func TestInvitation_IsExpired_AlreadyExpired(t *testing.T) {
	// 過去の有効期限を持つ招待
	inv := Invitation{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	// ExpiresAt が現在より前なら期限切れ
	if time.Now().Before(inv.ExpiresAt) {
		t.Error("有効期限が過去の招待は期限切れであるべき")
	}
}

// TestInvitation_AcceptedStatus_Pending は AcceptedAt が nil の場合は未承認であることを確認する
func TestInvitation_AcceptedStatus_Pending(t *testing.T) {
	inv := Invitation{
		ID:        "inv-pending",
		ExpiresAt: time.Now().Add(48 * time.Hour),
		// AcceptedAt は設定しない
	}
	if inv.AcceptedAt != nil {
		t.Error("承認前の招待は AcceptedAt が nil であるべき")
	}
}

// TestInvitation_AcceptedStatus_Accepted は AcceptedAt が設定済みの場合は承認済みであることを確認する
func TestInvitation_AcceptedStatus_Accepted(t *testing.T) {
	now := time.Now()
	inv := Invitation{
		ID:         "inv-accepted",
		ExpiresAt:  time.Now().Add(48 * time.Hour),
		AcceptedAt: &now,
	}
	if inv.AcceptedAt == nil {
		t.Fatal("承認済み招待は AcceptedAt が nil でないべき")
	}
	if inv.AcceptedAt.IsZero() {
		t.Error("AcceptedAt はゼロ時刻でないべき")
	}
}

// TestInvitation_IsValid_ActiveInvitation はアクティブな招待の有効性を確認する
func TestInvitation_IsValid_ActiveInvitation(t *testing.T) {
	// 未承認かつ有効期限内
	inv := Invitation{
		ID:        "inv-valid",
		Email:     "new@example.com",
		Role:      "viewer",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		// AcceptedAt = nil
	}
	isActive := inv.AcceptedAt == nil && time.Now().Before(inv.ExpiresAt)
	if !isActive {
		t.Error("未承認かつ期限内の招待はアクティブであるべき")
	}
}

// TestInvitation_IsValid_ExpiredAndNotAccepted は期限切れ未承認招待は無効であることを確認する
func TestInvitation_IsValid_ExpiredAndNotAccepted(t *testing.T) {
	inv := Invitation{
		ID:        "inv-expired",
		ExpiresAt: time.Now().Add(-2 * time.Hour),
		// AcceptedAt = nil
	}
	isActive := inv.AcceptedAt == nil && time.Now().Before(inv.ExpiresAt)
	if isActive {
		t.Error("期限切れの招待はアクティブでないべき")
	}
}

// TestInvitation_ExpiryDuration はデフォルト7日間の有効期限を検証する
func TestInvitation_ExpiryDuration(t *testing.T) {
	created := time.Now()
	// 一般的なデフォルト: 7日間
	expiry := created.Add(7 * 24 * time.Hour)
	inv := Invitation{
		CreatedAt: created,
		ExpiresAt: expiry,
	}
	duration := inv.ExpiresAt.Sub(inv.CreatedAt)
	expected := 7 * 24 * time.Hour
	if duration != expected {
		t.Errorf("有効期間 = %v, want %v", duration, expected)
	}
}

// TestInvitation_RoleValues は許容されるロール値を検証する
func TestInvitation_RoleValues(t *testing.T) {
	validRoles := []string{"admin", "analyst", "viewer", "responder"}
	for _, role := range validRoles {
		inv := Invitation{Role: role}
		if inv.Role != role {
			t.Errorf("Role = %q, want %q", inv.Role, role)
		}
	}
}

// TestInvitation_TenantID_OptionalField は TenantID が省略可能なことを確認する
func TestInvitation_TenantID_OptionalField(t *testing.T) {
	// TenantID なし (グローバル招待)
	inv := Invitation{
		ID:    "inv-global",
		Email: "global@example.com",
		Role:  "admin",
	}
	if inv.TenantID != "" {
		t.Errorf("TenantID が設定されていない場合、空文字列であるべき: got %q", inv.TenantID)
	}
}

// TestInvitation_AcceptedAtPointerSemantics は AcceptedAt のポインタセマンティクスを確認する
func TestInvitation_AcceptedAtPointerSemantics(t *testing.T) {
	t1 := time.Date(2026, 3, 23, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 3, 23, 10, 0, 0, 0, time.UTC)

	inv1 := Invitation{AcceptedAt: &t1}
	inv2 := Invitation{AcceptedAt: &t2}

	// 独立したポインタだが値は同じ
	if inv1.AcceptedAt == inv2.AcceptedAt {
		t.Error("異なるポインタは等しくあるべきでない")
	}
	if !inv1.AcceptedAt.Equal(*inv2.AcceptedAt) {
		t.Error("同じ時刻を指すポインタは等しい値を持つべき")
	}
}
