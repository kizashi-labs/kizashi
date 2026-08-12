package tenant

import (
	"testing"
)

// ─── NewStore ─────────────────────────────────────────────────────────────────

func TestNewStore_NotNil(t *testing.T) {
	s := NewStore(nil)
	if s == nil {
		t.Fatal("NewStore は nil を返すべきではありません")
	}
}

func TestNewStore_PoolNil(t *testing.T) {
	s := NewStore(nil)
	if s.pool != nil {
		t.Error("pool=nil で作成したとき pool は nil であるべきです")
	}
}

// ─── Organization 構造体フィールド ────────────────────────────────────────────

func TestOrganization_Fields(t *testing.T) {
	org := &Organization{
		ID:         "org-1",
		Name:       "Acme Corp",
		Slug:       "acme-corp",
		Plan:       "enterprise",
		AgentLimit: 1000,
		UserLimit:  50,
		Enabled:    true,
	}
	if org.Name != "Acme Corp" {
		t.Errorf("Name: got %q, want Acme Corp", org.Name)
	}
	if org.Slug != "acme-corp" {
		t.Errorf("Slug: got %q, want acme-corp", org.Slug)
	}
	if org.Plan != "enterprise" {
		t.Errorf("Plan: got %q, want enterprise", org.Plan)
	}
	if org.AgentLimit != 1000 {
		t.Errorf("AgentLimit: got %d, want 1000", org.AgentLimit)
	}
}

// ─── OrgSettings 構造体フィールド ─────────────────────────────────────────────

func TestOrgSettings_Fields(t *testing.T) {
	settings := OrgSettings{
		AllowSSO:      true,
		RetentionDays: 90,
		LogoURL:       "https://example.com/logo.png",
		PrimaryColor:  "#1a73e8",
	}
	if !settings.AllowSSO {
		t.Error("AllowSSO: got false, want true")
	}
	if settings.RetentionDays != 90 {
		t.Errorf("RetentionDays: got %d, want 90", settings.RetentionDays)
	}
}

// ─── OrgSettings デフォルト値 ─────────────────────────────────────────────────

func TestOrgSettings_DefaultValues(t *testing.T) {
	settings := OrgSettings{}
	if settings.AllowSSO {
		t.Error("デフォルト AllowSSO: got true, want false")
	}
	if settings.RetentionDays != 0 {
		t.Errorf("デフォルト RetentionDays: got %d, want 0", settings.RetentionDays)
	}
}

// ─── OrgStats 構造体フィールド ─────────────────────────────────────────────────

func TestOrgStats_Fields(t *testing.T) {
	stats := &OrgStats{
		AgentCount:    42,
		UserCount:     10,
		AlertCount30d: 150,
		StorageMB:     2048,
	}
	if stats.AgentCount != 42 {
		t.Errorf("AgentCount: got %d, want 42", stats.AgentCount)
	}
	if stats.StorageMB != 2048 {
		t.Errorf("StorageMB: got %d, want 2048", stats.StorageMB)
	}
}

// ─── scanRow (invalid scan → error) ──────────────────────────────────────────

type failScanner struct{}

func (f *failScanner) Scan(_ ...interface{}) error {
	return errScanFail
}

// errScanFail はダミーエラー
var errScanFail = scanError("scan failed")

type scanError string

func (e scanError) Error() string { return string(e) }

func TestScanRow_ScanError_ReturnsError(t *testing.T) {
	s := NewStore(nil)
	_, err := s.scanRow(&failScanner{})
	if err == nil {
		t.Error("Scan エラー時は error を返すべきです")
	}
}

// ─── Organization Enabled フラグ ──────────────────────────────────────────────

func TestOrganization_EnabledDefault(t *testing.T) {
	org := &Organization{}
	if org.Enabled {
		t.Error("デフォルト Enabled: got true, want false")
	}
}

// ─── Organization ゼロ値確認 ──────────────────────────────────────────────────

func TestOrganization_ZeroValue(t *testing.T) {
	org := Organization{}
	if org.ID != "" {
		t.Errorf("ID ゼロ値: got %q, want empty", org.ID)
	}
	if org.AgentLimit != 0 {
		t.Errorf("AgentLimit ゼロ値: got %d, want 0", org.AgentLimit)
	}
}
