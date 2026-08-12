package handlers

import (
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// validateBackupFormat のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateBackupFormat_Valid(t *testing.T) {
	// 有効なフォーマット値はエラーなく通過する
	validFormats := []string{"sql", "custom", "tar", "plain"}
	for _, f := range validFormats {
		t.Run(f, func(t *testing.T) {
			format := f
			got := validateBackupFormat(&format)
			if got != "" {
				t.Errorf("validateBackupFormat(%q) = %q, want \"\"", f, got)
			}
		})
	}
}

func TestValidateBackupFormat_Invalid(t *testing.T) {
	// 無効なフォーマット値はエラーメッセージを返す
	tests := []struct {
		input string
	}{
		{"json"},
		{"xml"},
		{"gz"},
		{"zip"},
		{"binary"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			format := tc.input
			got := validateBackupFormat(&format)
			if got == "" {
				t.Errorf("validateBackupFormat(%q): エラーが期待されましたが nil でした", tc.input)
			}
		})
	}
}

func TestValidateBackupFormat_EmptyDefaultsToSQL(t *testing.T) {
	// 空文字列のフォーマットはデフォルト "sql" に補完される
	format := ""
	msg := validateBackupFormat(&format)
	if msg != "" {
		t.Errorf("validateBackupFormat(\"\") = %q, want \"\"", msg)
	}
	if format != "sql" {
		t.Errorf("空フォーマットのデフォルト値 = %q, want \"sql\"", format)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateBackupSchedule のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateBackupSchedule_Valid(t *testing.T) {
	// 有効なスケジュール値はエラーなく通過する
	validSchedules := []string{"hourly", "daily", "weekly", "monthly"}
	for _, s := range validSchedules {
		t.Run(s, func(t *testing.T) {
			schedule := s
			got := validateBackupSchedule(&schedule)
			if got != "" {
				t.Errorf("validateBackupSchedule(%q) = %q, want \"\"", s, got)
			}
		})
	}
}

func TestValidateBackupSchedule_Invalid(t *testing.T) {
	// 無効なスケジュール値はエラーメッセージを返す
	invalid := []string{"minutely", "yearly", "biweekly", "never", "always"}
	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			schedule := s
			got := validateBackupSchedule(&schedule)
			if got == "" {
				t.Errorf("validateBackupSchedule(%q): エラーが期待されましたが nil でした", s)
			}
		})
	}
}

func TestValidateBackupSchedule_EmptyDefaultsToDaily(t *testing.T) {
	// 空文字列のスケジュールはデフォルト "daily" に補完される
	schedule := ""
	msg := validateBackupSchedule(&schedule)
	if msg != "" {
		t.Errorf("validateBackupSchedule(\"\") = %q, want \"\"", msg)
	}
	if schedule != "daily" {
		t.Errorf("空スケジュールのデフォルト値 = %q, want \"daily\"", schedule)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// backupFilenameFromTime のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestBackupFilenameFromTime_Format(t *testing.T) {
	// 生成されるファイル名が "backup_YYYYMMDD_HHMMSS.sql" の形式であることを確認
	ts := time.Date(2024, 3, 15, 9, 5, 30, 0, time.UTC)
	got := backupFilenameFromTime(ts)
	want := "backup_20240315_090530.sql"
	if got != want {
		t.Errorf("backupFilenameFromTime() = %q, want %q", got, want)
	}
}

func TestBackupFilenameFromTime_PrefixAndSuffix(t *testing.T) {
	// 常に "backup_" プレフィックスと ".sql" サフィックスを持つ
	ts := time.Now()
	got := backupFilenameFromTime(ts)
	if !strings.HasPrefix(got, "backup_") {
		t.Errorf("ファイル名が 'backup_' で始まっていません: %q", got)
	}
	if !strings.HasSuffix(got, ".sql") {
		t.Errorf("ファイル名が '.sql' で終わっていません: %q", got)
	}
}

func TestBackupFilenameFromTime_UTCConversion(t *testing.T) {
	// タイムゾーンに関わらず UTC 表現を使用する
	jst := time.FixedZone("JST", 9*60*60)
	ts := time.Date(2024, 1, 1, 12, 0, 0, 0, jst) // JST 正午 = UTC 03:00
	got := backupFilenameFromTime(ts)
	want := "backup_20240101_030000.sql"
	if got != want {
		t.Errorf("backupFilenameFromTime(JST) = %q, want %q", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// isBackupFile のテスト
// ─────────────────────────────────────────────────────────────────────────────

func TestIsBackupFile_Valid(t *testing.T) {
	// バックアップファイルのパターンに一致する名前
	valid := []string{
		"backup_20240101_120000.sql",
		"backup_20231231_235959.sql",
		"backup_20240315_090530.sql",
	}
	for _, name := range valid {
		t.Run(name, func(t *testing.T) {
			if !isBackupFile(name) {
				t.Errorf("isBackupFile(%q) = false, want true", name)
			}
		})
	}
}

func TestIsBackupFile_Invalid(t *testing.T) {
	// バックアップファイルパターンに一致しない名前
	invalid := []string{
		"",
		"etc/passwd",
		"dump.sql",
		"backup.tar",
		"backup_20240101_120000.tar.gz",
		"mydb_backup.sql",
	}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			if isBackupFile(name) {
				t.Errorf("isBackupFile(%q) = true, want false", name)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// validateFilename との組み合わせテスト (バックアップ専用パターン確認)
// ─────────────────────────────────────────────────────────────────────────────

func TestBackupFilenameRoundtrip(t *testing.T) {
	// backupFilenameFromTime で生成したファイル名は validateFilename を通過し
	// かつ isBackupFile で有効と判定される
	h := &BackupHandler{backupDir: "/tmp/backups"}
	ts := time.Date(2024, 6, 1, 8, 0, 0, 0, time.UTC)
	name := backupFilenameFromTime(ts)

	if err := h.validateFilename(name); err != nil {
		t.Errorf("validateFilename(生成ファイル名 %q) = %v, want nil", name, err)
	}
	if !isBackupFile(name) {
		t.Errorf("isBackupFile(生成ファイル名 %q) = false, want true", name)
	}
}
