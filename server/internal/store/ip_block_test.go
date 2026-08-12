package store

import (
	"testing"
	"time"
)

// TestIPBlockEntry_ZeroValue は IPBlockEntry のゼロ値が期待通りであることを確認する
func TestIPBlockEntry_ZeroValue(t *testing.T) {
	var e IPBlockEntry
	if e.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", e.ID)
	}
	if e.EntryType != "" {
		t.Errorf("EntryType のデフォルト = %q, want \"\"", e.EntryType)
	}
	if e.HitCount != 0 {
		t.Errorf("HitCount のデフォルト = %d, want 0", e.HitCount)
	}
	if e.ExpiresAt != nil {
		t.Error("ExpiresAt のデフォルトは nil であるべき")
	}
	if e.IsExpired {
		t.Error("IsExpired のデフォルトは false であるべき")
	}
}

// TestIPBlockEntry_FieldAssignment は IPBlockEntry のフィールド代入が正しく反映されることを確認する
func TestIPBlockEntry_FieldAssignment(t *testing.T) {
	addedBy := "user-uuid-001"
	expires := time.Now().Add(24 * time.Hour)
	e := IPBlockEntry{
		ID:          "ipb-001",
		IPOrCIDR:    "10.0.0.0/8",
		EntryType:   "allow",
		Description: "社内ネットワーク",
		HitCount:    42,
		ExpiresAt:   &expires,
		AddedBy:     &addedBy,
	}

	if e.IPOrCIDR != "10.0.0.0/8" {
		t.Errorf("IPOrCIDR = %q, want \"10.0.0.0/8\"", e.IPOrCIDR)
	}
	if e.EntryType != "allow" {
		t.Errorf("EntryType = %q, want \"allow\"", e.EntryType)
	}
	if e.HitCount != 42 {
		t.Errorf("HitCount = %d, want 42", e.HitCount)
	}
	if e.ExpiresAt == nil || !e.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", e.ExpiresAt, expires)
	}
	if e.AddedBy == nil || *e.AddedBy != addedBy {
		t.Errorf("AddedBy = %v, want %q", e.AddedBy, addedBy)
	}
}

// TestIPBlockEntry_KnownEntryTypes は許可される entry_type の値を確認する
func TestIPBlockEntry_KnownEntryTypes(t *testing.T) {
	for _, entryType := range []string{"block", "allow"} {
		e := IPBlockEntry{EntryType: entryType}
		if e.EntryType != entryType {
			t.Errorf("EntryType = %q, want %q", e.EntryType, entryType)
		}
	}
}
