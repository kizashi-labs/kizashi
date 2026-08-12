package backup

import (
	"testing"
)

// ─── NewManager ───────────────────────────────────────────────────────────────

func TestNewManager_NotNil(t *testing.T) {
	m := NewManager(nil, "/tmp/test-backups")
	if m == nil {
		t.Fatal("NewManager は nil を返すべきではありません")
	}
}

func TestNewManager_BackupDirSet(t *testing.T) {
	m := NewManager(nil, "/tmp/test-backups")
	if m.backupDir != "/tmp/test-backups" {
		t.Errorf("backupDir: got %q, want /tmp/test-backups", m.backupDir)
	}
}

func TestNewManager_DefaultBackupDir_WhenEmpty(t *testing.T) {
	m := NewManager(nil, "")
	if m.backupDir == "" {
		t.Error("空 backupDir 指定時はデフォルト値が設定されるべきです")
	}
}

func TestNewManager_PoolNil(t *testing.T) {
	m := NewManager(nil, "/tmp/test-backups")
	if m.pool != nil {
		t.Error("pool=nil で作成したとき pool は nil であるべきです")
	}
}

// ─── EnsureBackupDir ──────────────────────────────────────────────────────────

func TestEnsureBackupDir_ValidDir_NoError(t *testing.T) {
	m := NewManager(nil, t.TempDir())
	if err := m.EnsureBackupDir(); err != nil {
		t.Fatalf("EnsureBackupDir: 予期しないエラー: %v", err)
	}
}

// ─── SaveToFile ───────────────────────────────────────────────────────────────

func TestSaveToFile_ValidData_NoError(t *testing.T) {
	m := NewManager(nil, t.TempDir())
	path, err := m.SaveToFile([]byte(`{"test":true}`))
	if err != nil {
		t.Fatalf("SaveToFile: 予期しないエラー: %v", err)
	}
	if path == "" {
		t.Error("SaveToFile: パスが空です")
	}
}

func TestSaveToFile_PathContainsBackupDir(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(nil, dir)
	path, _ := m.SaveToFile([]byte(`{}`))
	if len(path) < len(dir) {
		t.Errorf("SaveToFile: パスが backupDir を含んでいません: %q", path)
	}
}

// ─── BackupManifest 構造体フィールド ──────────────────────────────────────────

func TestBackupManifest_Fields(t *testing.T) {
	manifest := BackupManifest{
		ID:          "bkp-001",
		Version:     "1.0.0",
		RecordCount: map[string]int{"rules": 10, "agents": 5},
	}
	if manifest.ID != "bkp-001" {
		t.Errorf("ID: got %q, want bkp-001", manifest.ID)
	}
	if manifest.RecordCount["rules"] != 10 {
		t.Errorf("RecordCount[rules]: got %d, want 10", manifest.RecordCount["rules"])
	}
}
