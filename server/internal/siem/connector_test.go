package siem

import (
	"context"
	"strings"
	"testing"
)

// ─── NewConnector ─────────────────────────────────────────────────────────────

func TestNewConnector_NotNil(t *testing.T) {
	c := NewConnector(nil)
	if c == nil {
		t.Fatal("NewConnector は nil を返すべきではありません")
	}
}

func TestNewConnector_HasHTTPClient(t *testing.T) {
	c := NewConnector(nil)
	if c.httpClient == nil {
		t.Error("httpClient が nil です")
	}
}

func TestNewConnector_ConfigsMapInitialized(t *testing.T) {
	c := NewConnector(nil)
	if c.configs == nil {
		t.Error("configs マップが初期化されていません")
	}
}

// ─── AddConfig ────────────────────────────────────────────────────────────────

func TestAddConfig_NilPool_NoError(t *testing.T) {
	c := NewConnector(nil)
	cfg := &SIEMConfig{ID: "cfg1", Name: "Splunk", Type: "splunk", URL: "http://splunk:8088"}
	if err := c.AddConfig(cfg); err != nil {
		t.Fatalf("AddConfig: 予期しないエラー: %v", err)
	}
}

func TestAddConfig_DefaultBatchSize(t *testing.T) {
	c := NewConnector(nil)
	cfg := &SIEMConfig{ID: "cfg1", Name: "Test", BatchSize: 0}
	_ = c.AddConfig(cfg)
	if cfg.BatchSize != 100 {
		t.Errorf("デフォルト BatchSize: got %d, want 100", cfg.BatchSize)
	}
}

func TestAddConfig_DefaultFormat(t *testing.T) {
	c := NewConnector(nil)
	cfg := &SIEMConfig{ID: "cfg1", Name: "Test"}
	_ = c.AddConfig(cfg)
	if cfg.Format != "json" {
		t.Errorf("デフォルト Format: got %q, want json", cfg.Format)
	}
}

func TestAddConfig_PreservesExplicitBatchSize(t *testing.T) {
	c := NewConnector(nil)
	cfg := &SIEMConfig{ID: "cfg1", Name: "Test", BatchSize: 50}
	_ = c.AddConfig(cfg)
	if cfg.BatchSize != 50 {
		t.Errorf("BatchSize: got %d, want 50", cfg.BatchSize)
	}
}

// ─── GetConfig / GetConfigs ───────────────────────────────────────────────────

func TestGetConfig_Found(t *testing.T) {
	c := NewConnector(nil)
	_ = c.AddConfig(&SIEMConfig{ID: "cfg1", Name: "Elastic"})
	cfg, ok := c.GetConfig("cfg1")
	if !ok {
		t.Fatal("GetConfig: 追加した設定が見つかりません")
	}
	if cfg.Name != "Elastic" {
		t.Errorf("GetConfig: Name got %q, want Elastic", cfg.Name)
	}
}

func TestGetConfig_NotFound(t *testing.T) {
	c := NewConnector(nil)
	_, ok := c.GetConfig("nonexistent")
	if ok {
		t.Error("GetConfig: 存在しない ID は false を返すべきです")
	}
}

func TestGetConfigs_Empty(t *testing.T) {
	c := NewConnector(nil)
	if len(c.GetConfigs()) != 0 {
		t.Errorf("GetConfigs (空): got %d, want 0", len(c.GetConfigs()))
	}
}

func TestGetConfigs_AfterAdd(t *testing.T) {
	c := NewConnector(nil)
	_ = c.AddConfig(&SIEMConfig{ID: "a", Name: "A"})
	_ = c.AddConfig(&SIEMConfig{ID: "b", Name: "B"})
	if len(c.GetConfigs()) != 2 {
		t.Errorf("GetConfigs: got %d, want 2", len(c.GetConfigs()))
	}
}

// ─── UpdateConfig ─────────────────────────────────────────────────────────────

func TestUpdateConfig_NilPool_UpdatesInMemory(t *testing.T) {
	c := NewConnector(nil)
	_ = c.AddConfig(&SIEMConfig{ID: "cfg1", Name: "Original"})
	updated := &SIEMConfig{Name: "Updated", Type: "elastic", Format: "json", BatchSize: 50}
	if err := c.UpdateConfig("cfg1", updated); err != nil {
		t.Fatalf("UpdateConfig: 予期しないエラー: %v", err)
	}
	cfg, _ := c.GetConfig("cfg1")
	if cfg.Name != "Updated" {
		t.Errorf("UpdateConfig: Name got %q, want Updated", cfg.Name)
	}
}

func TestUpdateConfig_SetsID(t *testing.T) {
	c := NewConnector(nil)
	_ = c.AddConfig(&SIEMConfig{ID: "cfg1", Name: "Test"})
	updated := &SIEMConfig{Name: "NewName"}
	_ = c.UpdateConfig("cfg1", updated)
	if updated.ID != "cfg1" {
		t.Errorf("UpdateConfig: ID got %q, want cfg1", updated.ID)
	}
}

// ─── DeleteConfig ─────────────────────────────────────────────────────────────

func TestDeleteConfig_RemovesFromMemory(t *testing.T) {
	c := NewConnector(nil)
	_ = c.AddConfig(&SIEMConfig{ID: "cfg1", Name: "Test"})
	if err := c.DeleteConfig("cfg1"); err != nil {
		t.Fatalf("DeleteConfig: 予期しないエラー: %v", err)
	}
	_, ok := c.GetConfig("cfg1")
	if ok {
		t.Error("DeleteConfig: 削除後も設定が存在しています")
	}
}

// ─── GetStats ─────────────────────────────────────────────────────────────────

func TestGetStats_Empty(t *testing.T) {
	c := NewConnector(nil)
	stats := c.GetStats()
	if stats.ConfigsCount != 0 {
		t.Errorf("GetStats (空): ConfigsCount got %d, want 0", stats.ConfigsCount)
	}
}

func TestGetStats_CountsEnabledConfigs(t *testing.T) {
	c := NewConnector(nil)
	_ = c.AddConfig(&SIEMConfig{ID: "a", Enabled: true})
	_ = c.AddConfig(&SIEMConfig{ID: "b", Enabled: false})
	_ = c.AddConfig(&SIEMConfig{ID: "cc", Enabled: true})
	stats := c.GetStats()
	if stats.ConfigsCount != 3 {
		t.Errorf("ConfigsCount: got %d, want 3", stats.ConfigsCount)
	}
	if stats.EnabledCount != 2 {
		t.Errorf("EnabledCount: got %d, want 2", stats.EnabledCount)
	}
}

// ─── LoadFromDB (pool=nil) ────────────────────────────────────────────────────

func TestLoadFromDB_NilPool_ReturnsNil(t *testing.T) {
	c := NewConnector(nil)
	if err := c.LoadFromDB(context.Background()); err != nil {
		t.Errorf("LoadFromDB (pool=nil): 予期しないエラー: %v", err)
	}
}

// ─── FormatCEF ────────────────────────────────────────────────────────────────

func TestFormatCEF_StartsWithCEF(t *testing.T) {
	c := NewConnector(nil)
	result := c.FormatCEF(map[string]interface{}{
		"id":        "alert-123",
		"rule_name": "Suspicious Process",
		"severity":  "8",
		"hostname":  "workstation01",
	})
	if !strings.HasPrefix(result, "CEF:") {
		t.Errorf("FormatCEF: got %q, want prefix 'CEF:'", result)
	}
}

func TestFormatCEF_ContainsRuleName(t *testing.T) {
	c := NewConnector(nil)
	result := c.FormatCEF(map[string]interface{}{
		"rule_name": "Malware Detected",
	})
	if !strings.Contains(result, "Malware Detected") {
		t.Errorf("FormatCEF: rule_name が含まれていません: %s", result)
	}
}

func TestFormatCEF_DefaultValues(t *testing.T) {
	c := NewConnector(nil)
	result := c.FormatCEF(map[string]interface{}{})
	// デフォルト rule_name = "EDR Alert"
	if !strings.Contains(result, "EDR Alert") {
		t.Errorf("FormatCEF: デフォルト rule_name が含まれていません: %s", result)
	}
}

// ─── FormatLEEF ───────────────────────────────────────────────────────────────

func TestFormatLEEF_StartsWithLEEF(t *testing.T) {
	c := NewConnector(nil)
	result := c.FormatLEEF(map[string]interface{}{
		"id":        "alert-456",
		"rule_name": "Network Anomaly",
		"severity":  "6",
	})
	if !strings.HasPrefix(result, "LEEF:") {
		t.Errorf("FormatLEEF: got %q, want prefix 'LEEF:'", result)
	}
}

func TestFormatLEEF_ContainsRuleName(t *testing.T) {
	c := NewConnector(nil)
	result := c.FormatLEEF(map[string]interface{}{
		"rule_name": "Lateral Movement",
	})
	if !strings.Contains(result, "Lateral Movement") {
		t.Errorf("FormatLEEF: rule_name が含まれていません: %s", result)
	}
}

// ─── getString ────────────────────────────────────────────────────────────────

func TestGetString_KeyExists_ReturnsValue(t *testing.T) {
	m := map[string]interface{}{"key": "value"}
	if got := getString(m, "key", "default"); got != "value" {
		t.Errorf("getString: got %q, want value", got)
	}
}

func TestGetString_KeyMissing_ReturnsDefault(t *testing.T) {
	m := map[string]interface{}{}
	if got := getString(m, "missing", "fallback"); got != "fallback" {
		t.Errorf("getString: got %q, want fallback", got)
	}
}

func TestGetString_IntValue_FormattedAsString(t *testing.T) {
	m := map[string]interface{}{"severity": 8}
	if got := getString(m, "severity", "0"); got != "8" {
		t.Errorf("getString int: got %q, want 8", got)
	}
}
