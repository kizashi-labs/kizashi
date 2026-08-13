// Package config handles agent configuration loading and hot-reload.
package config

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the full agent configuration.
type Config struct {
	Agent      AgentConfig      `toml:"agent"`
	Server     ServerConfig     `toml:"server"`
	Collection CollectionConfig `toml:"collection"`
	Response   ResponseConfig   `toml:"response"`
	Logging    LoggingConfig    `toml:"logging"`
	Quarantine QuarantineConfig `toml:"quarantine"`
	FIM        FIMConfig        `toml:"fim"`
}

// FIMConfig controls the File Integrity Monitoring collector.
type FIMConfig struct {
	// Enabled activates the FIM polling collector.
	// Can also be set via the FIM_ENABLED=true environment variable.
	Enabled bool `toml:"enabled"`
	// IntervalSec is the polling interval in seconds (default 60).
	IntervalSec int `toml:"interval_sec"`
}

type AgentConfig struct {
	ID       string `toml:"id"`
	Hostname string `toml:"hostname"`
}

type ServerConfig struct {
	URL               string `toml:"url"`
	CACert            string `toml:"ca_cert"`
	ClientCert        string `toml:"client_cert"`
	ClientKey         string `toml:"client_key"`
	GRPCPort          int    `toml:"grpc_port"`
	IngestionGRPCPort int    `toml:"ingestion_grpc_port"`
	ConnectTimeoutSec int    `toml:"connect_timeout_sec"`
	// CertPins is a list of SHA-256 SPKI fingerprints (base64-std).
	// If non-empty, the server leaf certificate must match one of these pins.
	// Generate with: openssl x509 -noout -pubkey -in server.crt | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
	CertPins []string `toml:"cert_pins"`
}

type CollectionConfig struct {
	ProcessMonitoring     bool     `toml:"process_monitoring"`
	FileMonitoring        bool     `toml:"file_monitoring"`
	NetworkMonitoring     bool     `toml:"network_monitoring"`
	DNSMonitoring         bool     `toml:"dns_monitoring"`
	RegistryMonitoring    bool     `toml:"registry_monitoring"`
	AuthMonitoring        bool     `toml:"auth_monitoring"`
	YARAScanOnExec        bool     `toml:"yara_scan_on_exec"`
	EventBatchIntervalMS  int      `toml:"event_batch_interval_ms"`
	ConfigPollIntervalSec int      `toml:"config_poll_interval_sec"`
	LocalBufferSizeMB     int      `toml:"local_buffer_size_mb"`
	MonitoredPaths        []string `toml:"monitored_paths"`
	ExcludedPaths         []string `toml:"excluded_paths"`
	ExcludedProcesses     []string `toml:"excluded_processes"`
	MaxEventsPerSecond    int      `toml:"max_events_per_second"`
}

type ResponseConfig struct {
	AutoResponseEnabled bool `toml:"auto_response_enabled"`
}

type LoggingConfig struct {
	Level      string `toml:"level"`
	File       string `toml:"file"`
	MaxSizeMB  int    `toml:"max_size_mb"`
	MaxBackups int    `toml:"max_backups"`
}

type QuarantineConfig struct {
	Dir string `toml:"dir"`
}

// Manager handles config loading and hot-reload.
type Manager struct {
	mu       sync.RWMutex
	current  *Config
	filePath string
	version  uint64
}

func NewManager(filePath string) *Manager {
	return &Manager{filePath: filePath}
}

// Load reads and parses the config file.
func (m *Manager) Load() error {
	cfg := defaultConfig()

	data, err := os.ReadFile(m.filePath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if err := validate(cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	m.mu.Lock()
	m.current = cfg
	m.version++
	m.mu.Unlock()

	return nil
}

// Get returns the current config (safe for concurrent use).
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Version returns the current config version (increments on each reload).
func (m *Manager) Version() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// ApplyRemote merges server-pushed config updates.
// Server config takes precedence over local file for collection settings.
func (m *Manager) ApplyRemote(remote *RemoteConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.current == nil {
		return
	}

	c := *m.current // shallow copy

	// Apply remote collection settings
	c.Collection.ProcessMonitoring = remote.ProcessMonitoring
	c.Collection.FileMonitoring = remote.FileMonitoring
	c.Collection.NetworkMonitoring = remote.NetworkMonitoring
	c.Collection.DNSMonitoring = remote.DNSMonitoring
	c.Collection.MonitoredPaths = remote.MonitoredPaths
	c.Collection.ExcludedPaths = remote.ExcludedPaths
	c.Collection.ExcludedProcesses = remote.ExcludedProcesses
	c.Collection.EventBatchIntervalMS = remote.EventBatchIntervalMS
	c.Response.AutoResponseEnabled = remote.AutoResponseEnabled

	m.current = &c
	m.version++
}

// RemoteConfig is the subset pushed from the server.
type RemoteConfig struct {
	ProcessMonitoring    bool
	FileMonitoring       bool
	NetworkMonitoring    bool
	DNSMonitoring        bool
	MonitoredPaths       []string
	ExcludedPaths        []string
	ExcludedProcesses    []string
	EventBatchIntervalMS int
	AutoResponseEnabled  bool
}

// WatchFile polls the config file for changes and reloads when modified.
func (m *Manager) WatchFile(interval time.Duration, onChange func()) {
	var lastMod time.Time

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(m.filePath)
		if err != nil {
			continue
		}
		if info.ModTime().After(lastMod) {
			lastMod = info.ModTime()
			if err := m.Load(); err == nil && onChange != nil {
				onChange()
			}
		}
	}
}

func validate(c *Config) error {
	if c.Agent.ID == "" {
		return fmt.Errorf("agent.id は必須です")
	}
	if c.Server.URL == "" {
		return fmt.Errorf("server.url は必須です")
	}
	return nil
}

func defaultConfig() *Config {
	return &Config{
		Collection: CollectionConfig{
			ProcessMonitoring:     true,
			FileMonitoring:        true,
			NetworkMonitoring:     true,
			DNSMonitoring:         true,
			RegistryMonitoring:    true,
			AuthMonitoring:        true,
			YARAScanOnExec:        true,
			EventBatchIntervalMS:  500,
			ConfigPollIntervalSec: 300,
			LocalBufferSizeMB:     100,
			MaxEventsPerSecond:    1000,
		},
		Response: ResponseConfig{
			AutoResponseEnabled: true,
		},
		Logging: LoggingConfig{
			Level:      "info",
			MaxSizeMB:  50,
			MaxBackups: 3,
		},
		Server: ServerConfig{
			GRPCPort:          9090,
			IngestionGRPCPort: 9091,
			ConnectTimeoutSec: 30,
		},
	}
}
