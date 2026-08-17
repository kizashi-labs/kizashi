package handlers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/intel"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// ThreatFeedHandler manages threat intelligence feed endpoints.
type ThreatFeedHandler struct {
	Store     *store.ThreatFeedStore
	IOCStore  *store.IOCStore
	Publisher IOCPublisher // optional; signals detection engine to reload IOC cache
}

func NewThreatFeedHandler(feeds *store.ThreatFeedStore, ioc *store.IOCStore) *ThreatFeedHandler {
	return &ThreatFeedHandler{Store: feeds, IOCStore: ioc}
}

func (h *ThreatFeedHandler) publishInvalidate() {
	if h.Publisher != nil {
		if err := h.Publisher.Publish("ioc.invalidate", []byte("{}")); err != nil {
			slog.Warn("NATS publish failed", "subject", "ioc.invalidate", "error", err)
		}
	}
}

// List returns all configured feeds.
// GET /api/v1/threat-feeds
func (h *ThreatFeedHandler) List(c *gin.Context) {
	feeds, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "フィード一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": feeds, "total": len(feeds)})
}

// Create adds a new feed.
// POST /api/v1/threat-feeds
func (h *ThreatFeedHandler) Create(c *gin.Context) {
	var req struct {
		Name              string            `json:"name"               binding:"required"`
		URL               string            `json:"url"                binding:"required"`
		FeedType          string            `json:"feed_type"`
		IOCType           string            `json:"ioc_type"           binding:"required"`
		SourceFormat      string            `json:"source_format"`
		APIKey            string            `json:"api_key"`
		Description       string            `json:"description"`
		IsActive          bool              `json:"is_active"`
		SyncIntervalHours int               `json:"sync_interval_hours"`
		Headers           map[string]string `json:"headers"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, url, ioc_type は必須です"})
		return
	}
	if req.FeedType == "" {
		req.FeedType = "txt"
	}
	if req.SyncIntervalHours == 0 {
		req.SyncIntervalHours = 24
	}

	f := &store.ThreatFeed{
		Name:              req.Name,
		URL:               req.URL,
		FeedType:          req.FeedType,
		IOCType:           req.IOCType,
		SourceFormat:      req.SourceFormat,
		APIKey:            req.APIKey,
		Description:       req.Description,
		IsActive:          req.IsActive,
		SyncIntervalHours: req.SyncIntervalHours,
		Headers:           req.Headers,
	}
	id, err := h.Store.Insert(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "フィードの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "フィードを作成しました", "id": id})
}

// Update replaces a feed configuration.
// PUT /api/v1/threat-feeds/:id
func (h *ThreatFeedHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name              string            `json:"name"               binding:"required"`
		URL               string            `json:"url"                binding:"required"`
		FeedType          string            `json:"feed_type"`
		IOCType           string            `json:"ioc_type"           binding:"required"`
		SourceFormat      string            `json:"source_format"`
		APIKey            string            `json:"api_key"`
		Description       string            `json:"description"`
		IsActive          bool              `json:"is_active"`
		SyncIntervalHours int               `json:"sync_interval_hours"`
		Headers           map[string]string `json:"headers"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if req.SyncIntervalHours == 0 {
		req.SyncIntervalHours = 24
	}
	f := &store.ThreatFeed{
		ID:                id,
		Name:              req.Name,
		URL:               req.URL,
		FeedType:          req.FeedType,
		IOCType:           req.IOCType,
		SourceFormat:      req.SourceFormat,
		APIKey:            req.APIKey,
		Description:       req.Description,
		IsActive:          req.IsActive,
		SyncIntervalHours: req.SyncIntervalHours,
		Headers:           req.Headers,
	}
	if err := h.Store.Update(c.Request.Context(), f); err != nil {
		if errors.Is(err, store.ErrThreatFeedNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "フィードが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "フィードの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "フィードを更新しました", "id": id})
}

// Delete removes a feed.
// DELETE /api/v1/threat-feeds/:id
func (h *ThreatFeedHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrThreatFeedNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "フィードが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "フィードの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "フィードを削除しました", "id": id})
}

// Toggle enables or disables a feed.
// PUT /api/v1/threat-feeds/:id/toggle
func (h *ThreatFeedHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if err := h.Store.SetActive(c.Request.Context(), id, req.IsActive); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "フィードの更新に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "フィードを更新しました", "id": id, "is_active": req.IsActive})
}

// Sync immediately triggers a sync for a specific feed.
// POST /api/v1/threat-feeds/:id/sync
func (h *ThreatFeedHandler) Sync(c *gin.Context) {
	id := c.Param("id")
	feeds, err := h.Store.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "フィードの取得に失敗しました"})
		return
	}
	var target *store.ThreatFeed
	for _, f := range feeds {
		if f.ID == id {
			target = f
			break
		}
	}
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "フィードが見つかりません"})
		return
	}

	count, err := syncFeed(c.Request.Context(), target, h.IOCStore)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("同期に失敗しました: %v", err)})
		return
	}
	// **同期は済んでいて、残るのは記録だけです。** 落ちると画面の
	// 「最終同期」が止まったまま、IOC だけが増えます。
	if err := h.Store.MarkSynced(c.Request.Context(), id, count); err != nil {
		metrics.BackgroundFailed("threat_feed_sync", err,
			"フィードの同期完了を記録できませんでした。画面の最終同期が止まって見えます",
			"feed_id", id, "imported", count)
	}
	if count > 0 {
		h.publishInvalidate()
	}
	c.JSON(http.StatusOK, gin.H{"message": "同期完了", "imported": count})
}

// SyncFeedExternal is the exported version for use from main.go goroutine.
func SyncFeedExternal(ctx context.Context, f *store.ThreatFeed, iocStore *store.IOCStore) (int, error) {
	return syncFeed(ctx, f, iocStore)
}

// knownImporterFormats are source_format values handled by the intel.FeedImporter.
var knownImporterFormats = map[string]bool{
	"otx_reputation":    true,
	"urlhaus_csv":       true,
	"malwarebazaar_csv": true,
	"feodo_csv":         true,
	"misp_json":         true,
}

// syncFeed fetches a feed URL and imports IOCs into the IOC store.
func syncFeed(ctx context.Context, f *store.ThreatFeed, iocStore *store.IOCStore) (int, error) {
	// Use the enhanced importer for known structured feed formats.
	if knownImporterFormats[f.SourceFormat] {
		importer := intel.NewFeedImporter()
		feedEntries, err := importer.Import(ctx, f.URL, f.SourceFormat, f.APIKey)
		if err != nil {
			return 0, fmt.Errorf("feed import: %w", err)
		}
		entries := make([]*store.IOCEntry, 0, len(feedEntries))
		for _, e := range feedEntries {
			if e.Value == "" {
				continue
			}
			desc := fmt.Sprintf("Auto-imported from %s [source:%s threat:%s]", f.Name, e.Source, e.Threat)
			entries = append(entries, &store.IOCEntry{
				Type:        e.Type,
				Value:       e.Value,
				Description: desc,
				Severity:    7,
			})
		}
		if len(entries) == 0 {
			return 0, nil
		}
		inserted, err := iocStore.BulkInsert(ctx, entries)
		if err != nil {
			return 0, fmt.Errorf("bulk insert: %w", err)
		}
		slog.Info("脅威フィード同期完了(拡張インポーター)", "feed", f.Name, "format", f.SourceFormat, "imported", inserted, "total_parsed", len(feedEntries))
		return inserted, nil
	}

	// Fall through to plain CSV/TXT logic for unrecognised formats.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range f.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "EDR-Platform/1.0 ThreatFeedSync")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // max 10MB
	if err != nil {
		return 0, err
	}

	var values []string
	switch f.FeedType {
	case "csv":
		values = parseCSVFeed(string(body))
	default: // txt — one IOC per line
		values = parseTxtFeed(string(body))
	}

	entries := make([]*store.IOCEntry, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		entries = append(entries, &store.IOCEntry{
			Type:        f.IOCType,
			Value:       v,
			Description: "Auto-imported from " + f.Name,
			Severity:    7, // default: high severity (scale 1-10)
		})
	}

	inserted, err := iocStore.BulkInsert(ctx, entries)
	if err != nil {
		return 0, fmt.Errorf("bulk insert: %w", err)
	}
	slog.Info("脅威フィード同期完了", "feed", f.Name, "imported", inserted, "total_parsed", len(values))
	return inserted, nil
}

func parseTxtFeed(body string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Handle "value # comment" format
		if idx := strings.Index(line, "#"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func parseCSVFeed(body string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Take first column
		parts := strings.SplitN(line, ",", 2)
		val := strings.TrimSpace(strings.Trim(parts[0], "\""))
		if val != "" {
			out = append(out, val)
		}
	}
	return out
}
