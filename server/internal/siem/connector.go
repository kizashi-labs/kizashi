// Webhook-based SIEM integration supporting Splunk HEC, QRadar, Elastic, Generic webhook.
package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SIEMConfig holds configuration for one SIEM integration target.
type SIEMConfig struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // splunk, qradar, elastic, webhook
	URL       string    `json:"url"`
	APIKey    string    `json:"api_key,omitempty"`
	IndexName string    `json:"index_name,omitempty"`
	Enabled   bool      `json:"enabled"`
	Format    string    `json:"format"` // json, cef, leef
	BatchSize int       `json:"batch_size"`
	LastSent  time.Time `json:"last_sent,omitempty"`
	SentCount int64     `json:"sent_count"`
}

// CEFEvent represents a Common Event Format event.
type CEFEvent struct {
	Version       string
	DeviceVendor  string
	DeviceProduct string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      string
	Extensions    map[string]string
}

// SIEMStats summarises connector activity.
type SIEMStats struct {
	ConfigsCount int       `json:"configs_count"`
	EnabledCount int       `json:"enabled_count"`
	TotalSent    int64     `json:"total_sent"`
	LastSent     time.Time `json:"last_sent,omitempty"`
}

// Connector manages multiple SIEM configurations and routes alerts.
type Connector struct {
	mu         sync.RWMutex
	configs    map[string]*SIEMConfig
	pool       *pgxpool.Pool
	httpClient *http.Client
	totalSent  int64
	lastSent   time.Time
}

// NewConnector creates a new Connector backed by the given pool.
func NewConnector(pool *pgxpool.Pool) *Connector {
	return &Connector{
		configs: make(map[string]*SIEMConfig),
		pool:    pool,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// LoadFromDB loads all SIEM configs from the database.
func (c *Connector) LoadFromDB(ctx context.Context) error {
	if c.pool == nil {
		return nil
	}
	rows, err := c.pool.Query(ctx, `
		SELECT id, name, siem_type, url, COALESCE(api_key,''), COALESCE(index_name,''),
		       enabled, COALESCE(format,'json'), COALESCE(batch_size,100), last_sent, sent_count
		FROM siem_configs
		ORDER BY created_at
	`)
	if err != nil {
		slog.Debug("siem connector: could not load configs", "error", err)
		return nil
	}
	defer rows.Close()

	c.mu.Lock()
	defer c.mu.Unlock()
	for rows.Next() {
		var cfg SIEMConfig
		var lastSent *time.Time
		if err := rows.Scan(&cfg.ID, &cfg.Name, &cfg.Type, &cfg.URL, &cfg.APIKey,
			&cfg.IndexName, &cfg.Enabled, &cfg.Format, &cfg.BatchSize, &lastSent, &cfg.SentCount); err != nil {
			continue
		}
		if lastSent != nil {
			cfg.LastSent = *lastSent
		}
		c.configs[cfg.ID] = &cfg
	}
	slog.Info("siem connector: loaded configs", "count", len(c.configs))
	return nil
}

// AddConfig persists a new SIEM config to the DB and in-memory map.
func (c *Connector) AddConfig(cfg *SIEMConfig) error {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.Format == "" {
		cfg.Format = "json"
	}
	if c.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := c.pool.QueryRow(ctx, `
			INSERT INTO siem_configs (name, siem_type, url, api_key, index_name, enabled, format, batch_size)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING id`,
			cfg.Name, cfg.Type, cfg.URL, cfg.APIKey, cfg.IndexName,
			cfg.Enabled, cfg.Format, cfg.BatchSize,
		).Scan(&cfg.ID)
		if err != nil {
			return fmt.Errorf("insert siem config: %w", err)
		}
	}
	c.mu.Lock()
	c.configs[cfg.ID] = cfg
	c.mu.Unlock()
	return nil
}

// UpdateConfig updates an existing config by ID.
func (c *Connector) UpdateConfig(id string, updated *SIEMConfig) error {
	if c.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.pool.Exec(ctx, `
			UPDATE siem_configs
			SET name=$1, siem_type=$2, url=$3, api_key=$4, index_name=$5,
			    enabled=$6, format=$7, batch_size=$8, updated_at=NOW()
			WHERE id=$9`,
			updated.Name, updated.Type, updated.URL, updated.APIKey, updated.IndexName,
			updated.Enabled, updated.Format, updated.BatchSize, id)
		if err != nil {
			return fmt.Errorf("update siem config: %w", err)
		}
	}
	updated.ID = id
	c.mu.Lock()
	if old, ok := c.configs[id]; ok {
		updated.SentCount = old.SentCount
		updated.LastSent = old.LastSent
	}
	c.configs[id] = updated
	c.mu.Unlock()
	return nil
}

// DeleteConfig removes a config by ID.
func (c *Connector) DeleteConfig(id string) error {
	if c.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := c.pool.Exec(ctx, `DELETE FROM siem_configs WHERE id=$1`, id)
		if err != nil {
			return fmt.Errorf("delete siem config: %w", err)
		}
	}
	c.mu.Lock()
	delete(c.configs, id)
	c.mu.Unlock()
	return nil
}

// GetConfigs returns a slice of all known configs.
func (c *Connector) GetConfigs() []*SIEMConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*SIEMConfig, 0, len(c.configs))
	for _, cfg := range c.configs {
		out = append(out, cfg)
	}
	return out
}

// GetConfig returns one config by ID.
func (c *Connector) GetConfig(id string) (*SIEMConfig, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cfg, ok := c.configs[id]
	return cfg, ok
}

// SendAlert dispatches an alert to all enabled SIEM configs.
func (c *Connector) SendAlert(ctx context.Context, alert map[string]interface{}) error {
	c.mu.RLock()
	cfgs := make([]*SIEMConfig, 0, len(c.configs))
	for _, cfg := range c.configs {
		if cfg.Enabled {
			cfgs = append(cfgs, cfg)
		}
	}
	c.mu.RUnlock()

	for _, cfg := range cfgs {
		if err := c.sendOne(ctx, cfg, alert); err != nil {
			slog.Warn("siem connector: send failed", "config", cfg.Name, "error", err)
		}
	}
	return nil
}

// SendBatch sends a batch of alerts to all enabled SIEM configs.
func (c *Connector) SendBatch(ctx context.Context, alerts []map[string]interface{}) error {
	for _, alert := range alerts {
		_ = c.SendAlert(ctx, alert)
	}
	return nil
}

func (c *Connector) sendOne(ctx context.Context, cfg *SIEMConfig, alert map[string]interface{}) error {
	var body []byte
	var contentType string

	switch strings.ToLower(cfg.Format) {
	case "cef":
		body = []byte(c.FormatCEF(alert))
		contentType = "text/plain"
	case "leef":
		body = []byte(c.FormatLEEF(alert))
		contentType = "text/plain"
	default:
		var err error
		// Wrap for Splunk HEC format if type is splunk
		if strings.ToLower(cfg.Type) == "splunk" {
			payload := map[string]interface{}{
				"event": alert,
				"index": cfg.IndexName,
				"time":  float64(time.Now().UnixNano()) / 1e9,
			}
			body, err = json.Marshal(payload)
		} else {
			body, err = json.Marshal(alert)
		}
		if err != nil {
			return fmt.Errorf("marshal alert: %w", err)
		}
		contentType = "application/json"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if cfg.APIKey != "" {
		switch strings.ToLower(cfg.Type) {
		case "splunk":
			req.Header.Set("Authorization", "Splunk "+cfg.APIKey)
		case "elastic":
			req.Header.Set("Authorization", "ApiKey "+cfg.APIKey)
		default:
			req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("SIEM returned %d", resp.StatusCode)
	}

	// Update stats.
	atomic.AddInt64(&c.totalSent, 1)
	c.mu.Lock()
	cfg.SentCount++
	cfg.LastSent = time.Now()
	c.lastSent = cfg.LastSent
	c.mu.Unlock()

	if c.pool != nil {
		go func(id string) {
			tctx, tcancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer tcancel()
			_, _ = c.pool.Exec(tctx,
				`UPDATE siem_configs SET sent_count = sent_count + 1, last_sent = NOW() WHERE id = $1`, id)
		}(cfg.ID)
	}

	return nil
}

// FormatCEF returns the alert in Common Event Format (CEF) string.
func (c *Connector) FormatCEF(alert map[string]interface{}) string {
	sig := getString(alert, "id", "0")
	name := getString(alert, "rule_name", "EDR Alert")
	sev := getString(alert, "severity", "5")
	hostname := getString(alert, "hostname", "unknown")
	agentID := getString(alert, "agent_id", "")
	status := getString(alert, "status", "open")
	ts := time.Now().UTC().Format(time.RFC3339)

	ext := fmt.Sprintf("src=%s dst=%s deviceExternalId=%s cs1=%s cs1Label=status rt=%s",
		hostname, hostname, agentID, status, ts)

	return fmt.Sprintf("CEF:0|EDRPlatform|EDR|1.0|%s|%s|%s|%s", sig, name, sev, ext)
}

// FormatLEEF returns the alert in Log Event Extended Format (LEEF) string.
func (c *Connector) FormatLEEF(alert map[string]interface{}) string {
	sig := getString(alert, "id", "0")
	name := getString(alert, "rule_name", "EDR Alert")
	sev := getString(alert, "severity", "5")
	hostname := getString(alert, "hostname", "unknown")
	agentID := getString(alert, "agent_id", "")

	return fmt.Sprintf("LEEF:2.0|EDRPlatform|EDR|1.0|%s|src=%s\tdevTimeFormat=ISO 8601\tcat=%s\tsev=%s\tusrName=%s",
		sig, hostname, name, sev, agentID)
}

// TestConnector sends a test event to the given config, returning (success, message).
func (c *Connector) TestConnector(ctx context.Context, configID string) (bool, string) {
	cfg, ok := c.GetConfig(configID)
	if !ok {
		return false, "config not found"
	}

	testAlert := map[string]interface{}{
		"id":        "test-event-0000",
		"rule_name": "SIEM Connector Test",
		"severity":  5,
		"hostname":  "test-host",
		"agent_id":  "test-agent",
		"status":    "test",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	start := time.Now()
	err := c.sendOne(ctx, cfg, testAlert)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return false, fmt.Sprintf("error: %v (latency: %dms)", err, latency)
	}
	return true, fmt.Sprintf("ok (latency: %dms)", latency)
}

// GetStats returns connector statistics.
func (c *Connector) GetStats() SIEMStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stats := SIEMStats{
		ConfigsCount: len(c.configs),
		TotalSent:    atomic.LoadInt64(&c.totalSent),
		LastSent:     c.lastSent,
	}
	for _, cfg := range c.configs {
		if cfg.Enabled {
			stats.EnabledCount++
		}
	}
	return stats
}

func getString(m map[string]interface{}, key, def string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return def
}
