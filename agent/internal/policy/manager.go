// Package policy manages dynamic security policies received from the EDR server.
// Policies can be updated without restarting the agent.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/scanner"
)

// PolicyType identifies the type of policy being managed.
type PolicyType string

const (
	PolicyYARA       PolicyType = "yara_rules"
	PolicySigma      PolicyType = "sigma_rules"
	PolicyIOC        PolicyType = "ioc_list"
	PolicyExclusion  PolicyType = "exclusions"
	PolicyResponse   PolicyType = "response_actions"
	PolicyCollection PolicyType = "collection_config"
)

// Policy represents a security policy received from the server.
type Policy struct {
	Type      PolicyType      `json:"type"`
	Version   string          `json:"version"`
	Content   json.RawMessage `json:"content"`
	UpdatedAt time.Time       `json:"updated_at"`
	Checksum  string          `json:"checksum"`
}

// CollectionConfig defines what events to collect.
type CollectionConfig struct {
	ProcessEvents  bool     `json:"process_events"`
	NetworkEvents  bool     `json:"network_events"`
	FileEvents     bool     `json:"file_events"`
	DNSEvents      bool     `json:"dns_events"`
	RegistryEvents bool     `json:"registry_events"`
	WatchDirs      []string `json:"watch_dirs"`
	ExcludePaths   []string `json:"exclude_paths"`
	ExcludeProcs   []string `json:"exclude_processes"`
	MaxCPUPct      float64  `json:"max_cpu_pct"`
	MaxMemMB       int      `json:"max_mem_mb"`
	SamplingRate   float64  `json:"sampling_rate"` // 0.0-1.0
}

// DefaultCollectionConfig returns sensible defaults.
func DefaultCollectionConfig() CollectionConfig {
	return CollectionConfig{
		ProcessEvents:  true,
		NetworkEvents:  true,
		FileEvents:     true,
		DNSEvents:      true,
		RegistryEvents: true,
		WatchDirs: []string{
			"/home", "/tmp", "/var/tmp", "/etc",
			"/usr/local/bin", "/usr/bin",
		},
		ExcludePaths: []string{
			"/proc", "/sys", "/dev",
			"*.log", "*.tmp",
		},
		ExcludeProcs: []string{
			"sshd", "cron", "systemd",
		},
		MaxCPUPct:    5.0,
		MaxMemMB:     256,
		SamplingRate: 1.0,
	}
}

// IOCList holds indicators of compromise for local matching.
type IOCList struct {
	IPAddresses []string `json:"ip_addresses"`
	Domains     []string `json:"domains"`
	FileHashes  []string `json:"file_hashes"` // SHA256
	URLs        []string `json:"urls"`
	Version     string   `json:"version"`
}

// ExclusionList defines what not to alert on.
type ExclusionList struct {
	Paths        []string `json:"paths"`
	ProcessNames []string `json:"process_names"`
	IPRanges     []string `json:"ip_ranges"`
	RuleIDs      []string `json:"rule_ids"`
}

// Manager handles dynamic policy updates and notifies subscribers.
type Manager struct {
	mu sync.RWMutex

	// Current policies
	yaraRules  string
	sigmaRules string
	iocList    IOCList
	exclusions ExclusionList
	collection CollectionConfig

	// Compiled scanner
	yaraScanner *scanner.YARAScanner

	// Version tracking
	versions map[PolicyType]string

	// Subscribers notified on policy change
	subscribers []chan PolicyType

	// Persistence: save/load from disk
	policyDir string
}

// NewManager creates a policy manager with defaults.
func NewManager(policyDir string) *Manager {
	m := &Manager{
		versions:    make(map[PolicyType]string),
		collection:  DefaultCollectionConfig(),
		yaraScanner: scanner.NewYARAScanner(),
		policyDir:   policyDir,
	}
	return m
}

// Subscribe returns a channel that receives policy type when a policy is updated.
func (m *Manager) Subscribe() <-chan PolicyType {
	ch := make(chan PolicyType, 10)
	m.mu.Lock()
	m.subscribers = append(m.subscribers, ch)
	m.mu.Unlock()
	return ch
}

// notify sends policy update notification to all subscribers.
func (m *Manager) notify(ptype PolicyType) {
	for _, ch := range m.subscribers {
		select {
		case ch <- ptype:
		default:
		}
	}
}

// ApplyPolicy processes a policy update from the server.
func (m *Manager) ApplyPolicy(p Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if version changed
	if current, ok := m.versions[p.Type]; ok && current == p.Version {
		slog.Debug("policy already at current version", "type", p.Type, "version", p.Version)
		return nil
	}

	var applyErr error

	switch p.Type {
	case PolicyYARA:
		var content struct {
			Rules string `json:"rules"`
		}
		if err := json.Unmarshal(p.Content, &content); err != nil {
			return err
		}
		// Hot-reload YARA rules
		newScanner := scanner.NewYARAScanner()
		if err := newScanner.LoadRules(content.Rules); err != nil {
			return fmt.Errorf("compile YARA rules: %w", err)
		}
		m.yaraScanner = newScanner
		m.yaraRules = content.Rules
		slog.Info("YARA rules updated",
			"version", p.Version,
			"rule_count", newScanner.RuleCount())

	case PolicySigma:
		var content struct {
			Rules string `json:"rules"`
		}
		if err := json.Unmarshal(p.Content, &content); err != nil {
			return err
		}
		m.sigmaRules = content.Rules
		slog.Info("Sigma rules updated", "version", p.Version)

	case PolicyIOC:
		var iocs IOCList
		if err := json.Unmarshal(p.Content, &iocs); err != nil {
			return err
		}
		m.iocList = iocs
		slog.Info("IOC list updated",
			"version", p.Version,
			"ips", len(iocs.IPAddresses),
			"domains", len(iocs.Domains),
			"hashes", len(iocs.FileHashes))

	case PolicyExclusion:
		var excl ExclusionList
		if err := json.Unmarshal(p.Content, &excl); err != nil {
			return err
		}
		m.exclusions = excl
		slog.Info("Exclusion list updated", "version", p.Version)

	case PolicyCollection:
		var cfg CollectionConfig
		if err := json.Unmarshal(p.Content, &cfg); err != nil {
			return err
		}
		m.collection = cfg
		slog.Info("Collection config updated", "version", p.Version)
	}

	if applyErr == nil {
		m.versions[p.Type] = p.Version
		go m.notify(p.Type)
	}

	return applyErr
}

// GetYARAScanner returns the current compiled YARA scanner (thread-safe).
func (m *Manager) GetYARAScanner() *scanner.YARAScanner {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.yaraScanner
}

// GetCollectionConfig returns the current collection configuration.
func (m *Manager) GetCollectionConfig() CollectionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.collection
}

// GetIOCList returns the current IOC list.
func (m *Manager) GetIOCList() IOCList {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.iocList
}

// GetExclusions returns the current exclusion list.
func (m *Manager) GetExclusions() ExclusionList {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.exclusions
}

// IsExcluded checks if a path or process should be excluded from monitoring.
func (m *Manager) IsExcluded(path, processName string) bool {
	m.mu.RLock()
	excl := m.exclusions
	m.mu.RUnlock()

	for _, p := range excl.Paths {
		if matchGlob(p, path) {
			return true
		}
	}
	for _, proc := range excl.ProcessNames {
		if proc == processName {
			return true
		}
	}
	return false
}

func matchGlob(pattern, s string) bool {
	if pattern == s {
		return true
	}
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:]
		return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(s) >= len(prefix) && s[:len(prefix)] == prefix
	}
	return false
}

// RunPeriodicRefresh periodically requests policy refresh from the server.
// refreshFn is called to trigger a policy sync.
func (m *Manager) RunPeriodicRefresh(ctx context.Context, interval time.Duration, refreshFn func(ctx context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := refreshFn(ctx); err != nil {
				slog.Warn("policy refresh failed", "err", err)
			}
		}
	}
}
