package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// BackupHandler manages pg_dump backup files.
type BackupHandler struct {
	databaseURL string
	backupDir   string
}

// NewBackupHandler creates a new BackupHandler.
func NewBackupHandler(databaseURL, backupDir string) *BackupHandler {
	return &BackupHandler{databaseURL: databaseURL, backupDir: backupDir}
}

// backupInfo holds metadata about a backup file.
type backupInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// List returns all backup files in the backup directory.
// GET /api/v1/admin/backups
func (h *BackupHandler) List(c *gin.Context) {
	if err := os.MkdirAll(h.backupDir, 0750); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "バックアップディレクトリにアクセスできません"})
		return
	}
	entries, err := os.ReadDir(h.backupDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "バックアップ一覧の取得に失敗しました"})
		return
	}
	var backups []backupInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupInfo{
			Name:      e.Name(),
			Size:      info.Size(),
			CreatedAt: info.ModTime().UTC(),
		})
	}
	if backups == nil {
		backups = []backupInfo{}
	}
	c.JSON(http.StatusOK, gin.H{"backups": backups})
}

// Create triggers a pg_dump asynchronously.
// POST /api/v1/admin/backups
func (h *BackupHandler) Create(c *gin.Context) {
	if err := os.MkdirAll(h.backupDir, 0750); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "バックアップディレクトリの作成に失敗しました"})
		return
	}
	filename := fmt.Sprintf("backup_%s.sql", time.Now().UTC().Format("20060102_150405"))
	outPath := filepath.Join(h.backupDir, filename)

	go func() {
		// Use a context with a generous timeout so the goroutine is bounded.
		bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		// Parse DATABASE_URL to extract individual connection parameters.
		// This avoids issues with special characters (e.g. '@' in passwords)
		// being misinterpreted in the connection URI.
		cmd := h.buildPgDumpCmd(bgCtx, outPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Error("バックアップに失敗しました", "file", outPath, "error", err, "output", string(output))
			os.Remove(outPath)
		} else {
			slog.Info("バックアップが完了しました", "file", outPath)
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message":  "バックアップを開始しました",
		"filename": filename,
	})
}

// Delete removes a backup file by name.
// DELETE /api/v1/admin/backups/:name
func (h *BackupHandler) Delete(c *gin.Context) {
	name := c.Param("name")
	if err := h.validateFilename(name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	path := filepath.Join(h.backupDir, name)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "バックアップファイルが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "バックアップの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "バックアップを削除しました"})
}

// Download streams a backup file as an attachment.
// GET /api/v1/admin/backups/:name/download
func (h *BackupHandler) Download(c *gin.Context) {
	name := c.Param("name")
	if err := h.validateFilename(name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	path := filepath.Join(h.backupDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "バックアップファイルが見つかりません"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+name)
	c.Header("Content-Type", "application/octet-stream")
	c.File(path)
}

// validateFilename ensures the filename contains no path traversal.
func (h *BackupHandler) validateFilename(name string) error {
	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return fmt.Errorf("無効なファイル名です")
	}
	if name == "" {
		return fmt.Errorf("ファイル名は必須です")
	}
	return nil
}

// buildPgDumpCmd constructs a pg_dump command using individual flags parsed from
// the DATABASE_URL. This handles passwords that contain special URL characters
// like '@' or '#' which would break the connection URI when passed directly.
func (h *BackupHandler) buildPgDumpCmd(ctx context.Context, outPath string) *exec.Cmd {
	u, err := url.Parse(h.databaseURL)
	if err != nil {
		// Fallback: pass the URL directly via --dbname (handles some edge cases better)
		return exec.CommandContext(ctx, "pg_dump", "--dbname="+h.databaseURL, "-f", outPath)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	dbname := strings.TrimPrefix(u.Path, "/")
	user := u.User.Username()
	password, _ := u.User.Password()

	cmd := exec.CommandContext(ctx, "pg_dump",
		"-h", host,
		"-p", port,
		"-U", user,
		"-d", dbname,
		"-f", outPath,
	)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+password)
	return cmd
}

// validBackupFormats は許可されたバックアップフォーマットの集合です。
var validBackupFormats = map[string]struct{}{
	"sql":    {},
	"custom": {},
	"tar":    {},
	"plain":  {},
}

// validBackupSchedules は許可されたバックアップスケジュール間隔の集合です。
var validBackupSchedules = map[string]struct{}{
	"hourly":  {},
	"daily":   {},
	"weekly":  {},
	"monthly": {},
}

// validateBackupFormat はバックアップフォーマット文字列を検証します。
// 空の場合はデフォルト値 "sql" を設定します。
func validateBackupFormat(format *string) string {
	if *format == "" {
		*format = "sql"
	}
	if _, ok := validBackupFormats[*format]; !ok {
		return "format は sql/custom/tar/plain のいずれかを指定してください"
	}
	return ""
}

// validateBackupSchedule はバックアップスケジュール文字列を検証します。
// 空の場合はデフォルト値 "daily" を設定します。
func validateBackupSchedule(schedule *string) string {
	if *schedule == "" {
		*schedule = "daily"
	}
	if _, ok := validBackupSchedules[*schedule]; !ok {
		return "schedule は hourly/daily/weekly/monthly のいずれかを指定してください"
	}
	return ""
}

// backupFilenameFromTime はタイムスタンプからバックアップファイル名を生成します。
// 形式: backup_YYYYMMDD_HHMMSS.sql
func backupFilenameFromTime(t time.Time) string {
	return fmt.Sprintf("backup_%s.sql", t.UTC().Format("20060102_150405"))
}

// isBackupFile はファイル名がバックアップファイルのパターンに一致するか判定します。
// "backup_" プレフィックスと ".sql" サフィックスを持つファイルのみ有効です。
func isBackupFile(name string) bool {
	return strings.HasPrefix(name, "backup_") && strings.HasSuffix(name, ".sql")
}
