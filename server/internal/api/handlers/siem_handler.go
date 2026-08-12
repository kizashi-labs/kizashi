package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/siem"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// SIEMHandler manages SIEM target configuration.
type SIEMHandler struct {
	Store     *store.SIEMStore
	Forwarder *siem.Forwarder
	Publisher *nats.Conn // optional: signals detection engine to reload
}

// NewSIEMHandler creates a new SIEMHandler.
func NewSIEMHandler(s *store.SIEMStore, f *siem.Forwarder) *SIEMHandler {
	return &SIEMHandler{Store: s, Forwarder: f}
}

// List returns all SIEM targets.
// GET /api/v1/siem/targets
func (h *SIEMHandler) List(c *gin.Context) {
	targets, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SIEMターゲットの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": targets})
}

// Create adds a new SIEM target.
// POST /api/v1/siem/targets
func (h *SIEMHandler) Create(c *gin.Context) {
	var t store.SIEMTarget
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエスト: " + err.Error()})
		return
	}
	if t.Port == 0 {
		t.Port = 514
	}
	if t.Protocol == "" {
		t.Protocol = "udp"
	}
	if t.IndexName == "" {
		t.IndexName = "main"
	}

	out, err := h.Store.Create(c.Request.Context(), &t)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SIEMターゲットの作成に失敗しました"})
		return
	}
	h.reloadForwarder(c)
	c.JSON(http.StatusCreated, out)
}

// Update modifies a SIEM target.
// PUT /api/v1/siem/targets/:id
func (h *SIEMHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var t store.SIEMTarget
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエスト"})
		return
	}
	out, err := h.Store.Update(c.Request.Context(), id, &t)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SIEMターゲットの更新に失敗しました"})
		return
	}
	h.reloadForwarder(c)
	c.JSON(http.StatusOK, out)
}

// Delete removes a SIEM target.
// DELETE /api/v1/siem/targets/:id
func (h *SIEMHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "SIEMターゲットの削除に失敗しました"})
		return
	}
	h.reloadForwarder(c)
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// TestForward sends a test alert to a specific SIEM target.
// POST /api/v1/siem/targets/:id/test
func (h *SIEMHandler) TestForward(c *gin.Context) {
	id := c.Param("id")
	targets, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ターゲット取得に失敗しました"})
		return
	}

	var target *store.SIEMTarget
	for _, t := range targets {
		if t.ID == id {
			target = t
			break
		}
	}
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "ターゲットが見つかりません"})
		return
	}

	testID := uuid.New().String()
	testAlert := &siem.AlertPayload{
		ID:        testID,
		AgentID:   fmt.Sprintf("test-agent-%s", testID[:8]),
		Hostname:  fmt.Sprintf("test-host-%s", testID[:8]),
		OS:        "linux",
		RuleName:  "SIEM接続テスト",
		Severity:  50,
		Status:    "open",
		CreatedAt: time.Now(),
	}

	siemTarget := &siem.Target{
		ID:          target.ID,
		Name:        target.Name,
		Type:        target.Type,
		Host:        target.Host,
		Port:        target.Port,
		Protocol:    target.Protocol,
		Token:       target.Token,
		TLSEnabled:  target.TLSEnabled,
		IndexName:   target.IndexName,
		Enabled:     true,
		MinSeverity: 0,
	}

	// Create a temporary forwarder for the test so min_severity=0 applies
	tf := siem.NewForwarder()
	tf.LoadTargets([]*siem.Target{siemTarget})
	tf.Forward(c.Request.Context(), testAlert)

	c.JSON(http.StatusOK, gin.H{"message": "テストアラートを送信しました"})
}

// reloadForwarder refreshes the in-memory forwarder after DB changes
// and signals the detection engine to reload via NATS.
func (h *SIEMHandler) reloadForwarder(c *gin.Context) {
	if h.Forwarder != nil {
		targets, err := h.Store.List(c.Request.Context())
		if err == nil {
			siemTargets := make([]*siem.Target, len(targets))
			for i, t := range targets {
				siemTargets[i] = &siem.Target{
					ID:              t.ID,
					Name:            t.Name,
					Type:            t.Type,
					Host:            t.Host,
					Port:            t.Port,
					Protocol:        t.Protocol,
					Token:           t.Token,
					TLSEnabled:      t.TLSEnabled,
					IndexName:       t.IndexName,
					Enabled:         t.Enabled,
					MinSeverity:     t.MinSeverity,
					FilterRules:     t.FilterRules,
					FilterHostnames: t.FilterHostnames,
					FilterMitre:     t.FilterMitre,
				}
			}
			h.Forwarder.LoadTargets(siemTargets)
		}
	}
	if h.Publisher != nil {
		if err := h.Publisher.Publish("siem.targets.updated", nil); err != nil {
			slog.Warn("NATS publish failed", "subject", "siem.targets.updated", "error", err)
		}
	}
}
