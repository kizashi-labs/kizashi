package agentconfig

import (
	"context"
	"testing"
)

// ─── DefaultProfiles ─────────────────────────────────────────────────────────

func TestDefaultProfiles_ReturnsThreeProfiles(t *testing.T) {
	profiles := DefaultProfiles()
	if len(profiles) != 3 {
		t.Errorf("DefaultProfiles: got %d profiles, want 3", len(profiles))
	}
}

func TestDefaultProfiles_ContainsWindowsLinuxMacOS(t *testing.T) {
	profiles := DefaultProfiles()
	osTypes := map[string]bool{}
	for _, p := range profiles {
		osTypes[p.OSType] = true
	}
	for _, os := range []string{"windows", "linux", "macos"} {
		if !osTypes[os] {
			t.Errorf("DefaultProfiles: OSType %q が含まれていません", os)
		}
	}
}

func TestDefaultProfiles_AllHaveIsDefault(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if !p.IsDefault {
			t.Errorf("DefaultProfiles: %s の IsDefault が false です", p.OSType)
		}
	}
}

func TestDefaultProfiles_AllHaveIDs(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if p.ID == "" {
			t.Errorf("DefaultProfiles: %s の ID が空です", p.OSType)
		}
	}
}

func TestDefaultProfiles_WindowsHasRegistryMonitor(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if p.OSType == "windows" {
			if !p.Config.EnableRegistryMonitor {
				t.Error("Windows プロファイル: EnableRegistryMonitor は true であるべきです")
			}
		}
	}
}

func TestDefaultProfiles_LinuxNoRegistryMonitor(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if p.OSType == "linux" {
			if p.Config.EnableRegistryMonitor {
				t.Error("Linux プロファイル: EnableRegistryMonitor は false であるべきです")
			}
		}
	}
}

func TestDefaultProfiles_MacOSNoRegistryMonitor(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if p.OSType == "macos" {
			if p.Config.EnableRegistryMonitor {
				t.Error("macOS プロファイル: EnableRegistryMonitor は false であるべきです")
			}
		}
	}
}

func TestDefaultProfiles_CollectionIntervalIs60(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if p.Config.CollectionIntervalSec != 60 {
			t.Errorf("%s: CollectionIntervalSec got %d, want 60", p.OSType, p.Config.CollectionIntervalSec)
		}
	}
}

func TestDefaultProfiles_HeartbeatIs30(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if p.Config.HeartbeatIntervalSec != 30 {
			t.Errorf("%s: HeartbeatIntervalSec got %d, want 30", p.OSType, p.Config.HeartbeatIntervalSec)
		}
	}
}

func TestDefaultProfiles_HasFileMonitorPaths(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if len(p.Config.FileMonitorPaths) == 0 {
			t.Errorf("%s: FileMonitorPaths が空です", p.OSType)
		}
	}
}

func TestDefaultProfiles_TimestampsNotZero(t *testing.T) {
	for _, p := range DefaultProfiles() {
		if p.CreatedAt.IsZero() {
			t.Errorf("%s: CreatedAt がゼロ値です", p.OSType)
		}
		if p.UpdatedAt.IsZero() {
			t.Errorf("%s: UpdatedAt がゼロ値です", p.OSType)
		}
	}
}

// ─── CreateProfile (pool=nil) ─────────────────────────────────────────────────

func TestCreateProfile_NilPool_ReturnsProfile(t *testing.T) {
	s := NewStore(nil)
	p := &Profile{Name: "Test", Config: AgentConfig{LogLevel: "debug"}}
	got, err := s.CreateProfile(context.Background(), p)
	if err != nil {
		t.Fatalf("CreateProfile: 予期しないエラー: %v", err)
	}
	if got == nil {
		t.Fatal("CreateProfile: nil が返却されました")
	}
}

func TestCreateProfile_NilPool_SetsID(t *testing.T) {
	s := NewStore(nil)
	p := &Profile{Name: "AutoID"}
	got, _ := s.CreateProfile(context.Background(), p)
	if got.ID == "" {
		t.Error("CreateProfile: ID が自動設定されるべきです")
	}
}

func TestCreateProfile_NilPool_PreservesExistingID(t *testing.T) {
	s := NewStore(nil)
	p := &Profile{ID: "my-id", Name: "Named"}
	got, _ := s.CreateProfile(context.Background(), p)
	if got.ID != "my-id" {
		t.Errorf("CreateProfile: ID got %q, want my-id", got.ID)
	}
}

func TestCreateProfile_NilPool_DefaultsOSTypeToAll(t *testing.T) {
	s := NewStore(nil)
	p := &Profile{Name: "NoOS"}
	got, _ := s.CreateProfile(context.Background(), p)
	if got.OSType != "all" {
		t.Errorf("CreateProfile: OSType got %q, want all", got.OSType)
	}
}

func TestCreateProfile_NilPool_SetsTimestamps(t *testing.T) {
	s := NewStore(nil)
	p := &Profile{Name: "Timestamps"}
	got, _ := s.CreateProfile(context.Background(), p)
	if got.CreatedAt.IsZero() {
		t.Error("CreateProfile: CreatedAt がゼロ値です")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("CreateProfile: UpdatedAt がゼロ値です")
	}
}

// ─── ListProfiles (pool=nil) ──────────────────────────────────────────────────

func TestListProfiles_NilPool_ReturnsDefaults(t *testing.T) {
	s := NewStore(nil)
	profiles, err := s.ListProfiles(context.Background())
	if err != nil {
		t.Fatalf("ListProfiles: 予期しないエラー: %v", err)
	}
	if len(profiles) != 3 {
		t.Errorf("ListProfiles (pool=nil): got %d, want 3", len(profiles))
	}
}

// ─── GetDefaultProfile (pool=nil) ────────────────────────────────────────────

func TestGetDefaultProfile_NilPool_Windows(t *testing.T) {
	s := NewStore(nil)
	p, err := s.GetDefaultProfile(context.Background(), "windows")
	if err != nil {
		t.Fatalf("GetDefaultProfile windows: 予期しないエラー: %v", err)
	}
	if p.OSType != "windows" {
		t.Errorf("GetDefaultProfile windows: OSType got %q, want windows", p.OSType)
	}
}

func TestGetDefaultProfile_NilPool_Linux(t *testing.T) {
	s := NewStore(nil)
	p, err := s.GetDefaultProfile(context.Background(), "linux")
	if err != nil {
		t.Fatalf("GetDefaultProfile linux: 予期しないエラー: %v", err)
	}
	if p.OSType != "linux" {
		t.Errorf("GetDefaultProfile linux: OSType got %q, want linux", p.OSType)
	}
}

func TestGetDefaultProfile_NilPool_MacOS(t *testing.T) {
	s := NewStore(nil)
	p, err := s.GetDefaultProfile(context.Background(), "macos")
	if err != nil {
		t.Fatalf("GetDefaultProfile macos: 予期しないエラー: %v", err)
	}
	if p.OSType != "macos" {
		t.Errorf("GetDefaultProfile macos: OSType got %q, want macos", p.OSType)
	}
}

func TestGetDefaultProfile_NilPool_UnknownOS_ReturnsError(t *testing.T) {
	s := NewStore(nil)
	_, err := s.GetDefaultProfile(context.Background(), "unknown-os")
	if err == nil {
		t.Error("未知のOSタイプはエラーを返すべきです")
	}
}

// ─── UpdateProfile (pool=nil) ─────────────────────────────────────────────────

func TestUpdateProfile_NilPool_SetsID(t *testing.T) {
	s := NewStore(nil)
	updates := &Profile{Name: "Updated", OSType: "linux"}
	got, err := s.UpdateProfile(context.Background(), "target-id", updates)
	if err != nil {
		t.Fatalf("UpdateProfile: 予期しないエラー: %v", err)
	}
	if got.ID != "target-id" {
		t.Errorf("UpdateProfile: ID got %q, want target-id", got.ID)
	}
}

// ─── DeleteProfile (pool=nil) ─────────────────────────────────────────────────

func TestDeleteProfile_NilPool_ReturnsNil(t *testing.T) {
	s := NewStore(nil)
	if err := s.DeleteProfile(context.Background(), "any-id"); err != nil {
		t.Errorf("DeleteProfile (pool=nil): 予期しないエラー: %v", err)
	}
}

// ─── GetProfile (pool=nil) ────────────────────────────────────────────────────

func TestGetProfile_NilPool_ReturnsError(t *testing.T) {
	s := NewStore(nil)
	_, err := s.GetProfile(context.Background(), "any-id")
	if err == nil {
		t.Error("GetProfile (pool=nil): エラーを返すべきです")
	}
}
