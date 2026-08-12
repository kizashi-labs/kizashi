package config

import (
	"os"
	"path/filepath"
	"testing"
)

// ─── helpers ─────────────────────────────────────────────────

func writeTOML(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "agent.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTOML: %v", err)
	}
	return path
}

const minimalValidTOML = `
[agent]
id = "agent-001"

[server]
url = "https://edr.example.com"
`

// ─── defaultConfig ────────────────────────────────────────────

func TestDefaultConfig_HasExpectedValues(t *testing.T) {
	cfg := defaultConfig()

	if cfg == nil {
		t.Fatal("defaultConfig returned nil")
	}
	// Collection defaults
	if !cfg.Collection.ProcessMonitoring {
		t.Error("ProcessMonitoring should be true by default")
	}
	if !cfg.Collection.NetworkMonitoring {
		t.Error("NetworkMonitoring should be true by default")
	}
	if !cfg.Collection.FileMonitoring {
		t.Error("FileMonitoring should be true by default")
	}
	if cfg.Collection.EventBatchIntervalMS <= 0 {
		t.Errorf("EventBatchIntervalMS = %d, want > 0", cfg.Collection.EventBatchIntervalMS)
	}
	if cfg.Collection.MaxEventsPerSecond <= 0 {
		t.Errorf("MaxEventsPerSecond = %d, want > 0", cfg.Collection.MaxEventsPerSecond)
	}
	// Response defaults
	if !cfg.Response.AutoResponseEnabled {
		t.Error("AutoResponseEnabled should be true by default")
	}
	// Logging defaults
	if cfg.Logging.Level == "" {
		t.Error("Logging.Level should not be empty by default")
	}
	// Server defaults
	if cfg.Server.GRPCPort <= 0 {
		t.Errorf("Server.GRPCPort = %d, want > 0", cfg.Server.GRPCPort)
	}
}

// ─── validate ────────────────────────────────────────────────

func TestValidate_MissingAgentID(t *testing.T) {
	cfg := defaultConfig()
	cfg.Agent.ID = ""
	cfg.Server.URL = "https://edr.example.com"

	err := validate(cfg)
	if err == nil {
		t.Error("expected error for missing agent ID, got nil")
	}
}

func TestValidate_MissingServerURL(t *testing.T) {
	cfg := defaultConfig()
	cfg.Agent.ID = "agent-001"
	cfg.Server.URL = ""

	err := validate(cfg)
	if err == nil {
		t.Error("expected error for missing server URL, got nil")
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := defaultConfig()
	cfg.Agent.ID = "agent-001"
	cfg.Server.URL = "https://edr.example.com"

	err := validate(cfg)
	if err != nil {
		t.Errorf("validate error: %v", err)
	}
}

func TestValidate_BothMissing(t *testing.T) {
	cfg := defaultConfig()
	cfg.Agent.ID = ""
	cfg.Server.URL = ""

	err := validate(cfg)
	if err == nil {
		t.Error("expected error when both agent.id and server.url are empty")
	}
}

// ─── Manager.Load ─────────────────────────────────────────────

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := writeTOML(t, dir, minimalValidTOML)

	m := NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatalf("Load error: %v", err)
	}

	cfg := m.Get()
	if cfg == nil {
		t.Fatal("Get returned nil after Load")
	}
	if cfg.Agent.ID != "agent-001" {
		t.Errorf("Agent.ID = %q, want %q", cfg.Agent.ID, "agent-001")
	}
	if cfg.Server.URL != "https://edr.example.com" {
		t.Errorf("Server.URL = %q, want %q", cfg.Server.URL, "https://edr.example.com")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	m := NewManager("/nonexistent/path/agent.toml")
	err := m.Load()
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := writeTOML(t, dir, "this is not [[[ valid toml")

	m := NewManager(path)
	err := m.Load()
	if err == nil {
		t.Error("expected error for invalid TOML, got nil")
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			"missing agent id",
			`[server]
url = "https://edr.example.com"`,
		},
		{
			"missing server url",
			`[agent]
id = "agent-001"`,
		},
		{
			"both missing",
			`[logging]
level = "info"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTOML(t, dir, tc.content)
			m := NewManager(path)
			err := m.Load()
			if err == nil {
				t.Error("expected validation error, got nil")
			}
		})
	}
}

func TestLoad_FullConfig(t *testing.T) {
	content := `
[agent]
id = "agent-full"
hostname = "myhost"

[server]
url = "https://edr.example.com"
grpc_port = 9090
connect_timeout_sec = 30

[collection]
process_monitoring = true
file_monitoring = false
network_monitoring = true
max_events_per_second = 500

[logging]
level = "debug"
max_size_mb = 100
`
	dir := t.TempDir()
	path := writeTOML(t, dir, content)
	m := NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	cfg := m.Get()
	if cfg.Agent.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want %q", cfg.Agent.Hostname, "myhost")
	}
	if cfg.Collection.MaxEventsPerSecond != 500 {
		t.Errorf("MaxEventsPerSecond = %d, want 500", cfg.Collection.MaxEventsPerSecond)
	}
	if cfg.Collection.FileMonitoring {
		t.Error("FileMonitoring should be false per config")
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "debug")
	}
}

// ─── Manager.Version ─────────────────────────────────────────

func TestVersion_IncrementsOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := writeTOML(t, dir, minimalValidTOML)
	m := NewManager(path)

	v0 := m.Version()
	if err := m.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	v1 := m.Version()

	if v1 <= v0 {
		t.Errorf("version did not increment: %d -> %d", v0, v1)
	}

	if err := m.Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	v2 := m.Version()
	if v2 <= v1 {
		t.Errorf("version did not increment on second load: %d -> %d", v1, v2)
	}
}

func TestVersion_InitiallyZero(t *testing.T) {
	m := NewManager("/nonexistent")
	if m.Version() != 0 {
		t.Errorf("initial Version = %d, want 0", m.Version())
	}
}

// ─── Manager.Get ─────────────────────────────────────────────

func TestGet_NilBeforeLoad(t *testing.T) {
	m := NewManager("/nonexistent")
	cfg := m.Get()
	if cfg != nil {
		t.Error("Get before Load should return nil")
	}
}

// ─── Manager.ApplyRemote ─────────────────────────────────────

func TestApplyRemote_OverridesCollection(t *testing.T) {
	dir := t.TempDir()
	path := writeTOML(t, dir, minimalValidTOML)
	m := NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	remote := &RemoteConfig{
		ProcessMonitoring:    false,
		FileMonitoring:       false,
		NetworkMonitoring:    false,
		MonitoredPaths:       []string{"/opt/app"},
		ExcludedPaths:        []string{"/tmp"},
		ExcludedProcesses:    []string{"cron"},
		EventBatchIntervalMS: 1000,
		AutoResponseEnabled:  false,
	}

	vBefore := m.Version()
	m.ApplyRemote(remote)
	vAfter := m.Version()

	if vAfter <= vBefore {
		t.Errorf("version did not increment after ApplyRemote: %d -> %d", vBefore, vAfter)
	}

	cfg := m.Get()
	if cfg.Collection.ProcessMonitoring {
		t.Error("ProcessMonitoring should be false after remote override")
	}
	if cfg.Collection.EventBatchIntervalMS != 1000 {
		t.Errorf("EventBatchIntervalMS = %d, want 1000", cfg.Collection.EventBatchIntervalMS)
	}
	if cfg.Response.AutoResponseEnabled {
		t.Error("AutoResponseEnabled should be false after remote override")
	}
}

func TestApplyRemote_BeforeLoad_IsNoop(t *testing.T) {
	m := NewManager("/nonexistent")
	// Should not panic when current is nil.
	remote := &RemoteConfig{ProcessMonitoring: true}
	m.ApplyRemote(remote)

	// current is still nil.
	if m.Get() != nil {
		t.Error("Get should still be nil after ApplyRemote with no loaded config")
	}
}

func TestApplyRemote_MultipleRemoteUpdates(t *testing.T) {
	dir := t.TempDir()
	path := writeTOML(t, dir, minimalValidTOML)
	m := NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	for i, enabled := range []bool{true, false, true} {
		m.ApplyRemote(&RemoteConfig{NetworkMonitoring: enabled})
		cfg := m.Get()
		if cfg.Collection.NetworkMonitoring != enabled {
			t.Errorf("iteration %d: NetworkMonitoring = %v, want %v", i, cfg.Collection.NetworkMonitoring, enabled)
		}
	}
}

// ─── Config struct field coverage ────────────────────────────

func TestFIMConfig_Fields(t *testing.T) {
	fim := FIMConfig{Enabled: true, IntervalSec: 60}
	if !fim.Enabled {
		t.Error("Enabled should be true")
	}
	if fim.IntervalSec != 60 {
		t.Errorf("IntervalSec = %d, want 60", fim.IntervalSec)
	}
}

func TestServerConfig_CertPins(t *testing.T) {
	s := ServerConfig{
		URL:      "https://example.com",
		GRPCPort: 9090,
		CertPins: []string{"abc123", "def456"},
	}
	if len(s.CertPins) != 2 {
		t.Errorf("CertPins len = %d, want 2", len(s.CertPins))
	}
}
