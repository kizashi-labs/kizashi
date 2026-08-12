package handlers

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/backup"
	"github.com/gin-gonic/gin"
)

// ConfigBackupHandler provides JSON config backup and restore endpoints.
// It is distinct from the existing BackupHandler (which wraps pg_dump SQL backups).
type ConfigBackupHandler struct {
	mgr *backup.Manager
}

// NewConfigBackupHandler creates a new ConfigBackupHandler.
func NewConfigBackupHandler(mgr *backup.Manager) *ConfigBackupHandler {
	return &ConfigBackupHandler{mgr: mgr}
}

// CreateBackup dumps configuration tables to JSON and returns a downloadable file.
// POST /api/v1/admin/backup/create
func (h *ConfigBackupHandler) CreateBackup(c *gin.Context) {
	manifest, data, err := h.mgr.CreateBackup(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	filename := fmt.Sprintf("backup-%s.json", time.Now().UTC().Format("20060102-150405"))
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "application/json")
	c.Header("X-Backup-ID", manifest.ID)
	c.Header("X-Backup-Size", fmt.Sprintf("%d", manifest.SizeBytes))
	c.Data(http.StatusOK, "application/json", data)
}

// RestoreBackup accepts a JSON backup upload and restores config tables.
// POST /api/v1/admin/backup/restore
func (h *ConfigBackupHandler) RestoreBackup(c *gin.Context) {
	// Accept both multipart file upload and raw JSON body
	var data []byte
	var err error

	file, _, fileErr := c.Request.FormFile("file")
	if fileErr == nil {
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, 50*1024*1024)) // 50 MB limit
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read uploaded file"})
			return
		}
	} else {
		data, err = io.ReadAll(io.LimitReader(c.Request.Body, 50*1024*1024))
		if err != nil || len(data) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no backup data provided"})
			return
		}
	}

	result, err := h.mgr.RestoreBackup(c.Request.Context(), data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "restore failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "restore completed",
		"tables_restored":  result.TablesRestored,
		"records_restored": result.RecordsRestored,
		"warnings":         result.Warnings,
	})
}

// ListBackups lists backup manifests stored in the database.
// GET /api/v1/admin/backup/list
func (h *ConfigBackupHandler) ListBackups(c *gin.Context) {
	manifests, err := h.mgr.ListBackups(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list backups"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"backups": manifests, "total": len(manifests)})
}
