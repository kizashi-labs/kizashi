package policy

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── DefaultCollectionConfig ──────────────────────────────────

func TestDefaultCollectionConfig(t *testing.T) {
	cfg := DefaultCollectionConfig()

	if !cfg.ProcessEvents {
		t.Error("ProcessEvents should be true by default")
	}
	if !cfg.NetworkEvents {
		t.Error("NetworkEvents should be true by default")
	}
	if !cfg.FileEvents {
		t.Error("FileEvents should be true by default")
	}
	if !cfg.DNSEvents {
		t.Error("DNSEvents should be true by default")
	}
	if cfg.SamplingRate != 1.0 {
		t.Errorf("SamplingRate = %v, want 1.0", cfg.SamplingRate)
	}
	if cfg.MaxCPUPct <= 0 {
		t.Errorf("MaxCPUPct = %v, want > 0", cfg.MaxCPUPct)
	}
	if cfg.MaxMemMB <= 0 {
		t.Errorf("MaxMemMB = %v, want > 0", cfg.MaxMemMB)
	}
	if len(cfg.WatchDirs) == 0 {
		t.Error("WatchDirs should be non-empty by default")
	}
	if len(cfg.ExcludePaths) == 0 {
		t.Error("ExcludePaths should be non-empty by default")
	}
}

// ─── NewManager ───────────────────────────────────────────────

func TestNewManager_Defaults(t *testing.T) {
	tests := []struct {
		name      string
		policyDir string
	}{
		{"temp dir", t.TempDir()},
		{"empty dir string", ""},
		{"relative path", "./policies"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(tc.policyDir)
			if m == nil {
				t.Fatal("NewManager returned nil")
			}
			// Should start with default collection config.
			cfg := m.GetCollectionConfig()
			if !cfg.ProcessEvents {
				t.Error("default config should have ProcessEvents=true")
			}
			// IOC list should be empty.
			iocs := m.GetIOCList()
			if len(iocs.IPAddresses) != 0 || len(iocs.Domains) != 0 {
				t.Error("initial IOC list should be empty")
			}
			// Exclusion list should be empty.
			excl := m.GetExclusions()
			if len(excl.Paths) != 0 || len(excl.ProcessNames) != 0 {
				t.Error("initial exclusion list should be empty")
			}
		})
	}
}

// ─── Subscribe / notify ───────────────────────────────────────

func TestSubscribe_ReceivesNotification(t *testing.T) {
	m := NewManager(t.TempDir())
	ch := m.Subscribe()

	// Apply an IOC policy to trigger notification.
	iocs := IOCList{IPAddresses: []string{"1.2.3.4"}, Version: "v1"}
	raw, _ := json.Marshal(iocs)
	p := Policy{Type: PolicyIOC, Version: "v1", Content: raw, UpdatedAt: time.Now()}

	if err := m.ApplyPolicy(p); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}

	select {
	case pt := <-ch:
		if pt != PolicyIOC {
			t.Errorf("received PolicyType = %q, want %q", pt, PolicyIOC)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timed out waiting for policy notification")
	}
}

func TestSubscribe_MultipleSubscribers(t *testing.T) {
	m := NewManager(t.TempDir())
	ch1 := m.Subscribe()
	ch2 := m.Subscribe()

	excl := ExclusionList{Paths: []string{"/tmp"}}
	raw, _ := json.Marshal(excl)
	p := Policy{Type: PolicyExclusion, Version: "v1", Content: raw, UpdatedAt: time.Now()}

	if err := m.ApplyPolicy(p); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}

	for i, ch := range []<-chan PolicyType{ch1, ch2} {
		select {
		case pt := <-ch:
			if pt != PolicyExclusion {
				t.Errorf("subscriber %d received %q, want %q", i+1, pt, PolicyExclusion)
			}
		case <-time.After(500 * time.Millisecond):
			t.Errorf("subscriber %d timed out", i+1)
		}
	}
}

// ─── ApplyPolicy ─────────────────────────────────────────────

func TestApplyPolicy_IOCList(t *testing.T) {
	tests := []struct {
		name    string
		iocList IOCList
	}{
		{
			"ips and domains",
			IOCList{IPAddresses: []string{"10.0.0.1", "10.0.0.2"}, Domains: []string{"evil.com"}, Version: "v1"},
		},
		{
			"hashes only",
			IOCList{FileHashes: []string{"abc123", "def456"}, Version: "v2"},
		},
		{
			"empty list",
			IOCList{Version: "v3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(t.TempDir())
			raw, _ := json.Marshal(tc.iocList)
			p := Policy{Type: PolicyIOC, Version: tc.iocList.Version, Content: raw, UpdatedAt: time.Now()}

			if err := m.ApplyPolicy(p); err != nil {
				t.Fatalf("ApplyPolicy: %v", err)
			}

			got := m.GetIOCList()
			if len(got.IPAddresses) != len(tc.iocList.IPAddresses) {
				t.Errorf("IPAddresses len = %d, want %d", len(got.IPAddresses), len(tc.iocList.IPAddresses))
			}
			if len(got.Domains) != len(tc.iocList.Domains) {
				t.Errorf("Domains len = %d, want %d", len(got.Domains), len(tc.iocList.Domains))
			}
		})
	}
}

func TestApplyPolicy_Exclusions(t *testing.T) {
	tests := []struct {
		name string
		excl ExclusionList
	}{
		{"paths only", ExclusionList{Paths: []string{"/tmp", "/dev"}}},
		{"procs only", ExclusionList{ProcessNames: []string{"systemd", "cron"}}},
		{"mixed", ExclusionList{Paths: []string{"/sys"}, ProcessNames: []string{"sshd"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(t.TempDir())
			raw, _ := json.Marshal(tc.excl)
			p := Policy{Type: PolicyExclusion, Version: "v1", Content: raw, UpdatedAt: time.Now()}

			if err := m.ApplyPolicy(p); err != nil {
				t.Fatalf("ApplyPolicy: %v", err)
			}

			got := m.GetExclusions()
			if len(got.Paths) != len(tc.excl.Paths) {
				t.Errorf("Paths len = %d, want %d", len(got.Paths), len(tc.excl.Paths))
			}
			if len(got.ProcessNames) != len(tc.excl.ProcessNames) {
				t.Errorf("ProcessNames len = %d, want %d", len(got.ProcessNames), len(tc.excl.ProcessNames))
			}
		})
	}
}

func TestApplyPolicy_CollectionConfig(t *testing.T) {
	m := NewManager(t.TempDir())
	cfg := CollectionConfig{
		ProcessEvents: false,
		NetworkEvents: true,
		FileEvents:    false,
		SamplingRate:  0.5,
		MaxCPUPct:     3.0,
	}
	raw, _ := json.Marshal(cfg)
	p := Policy{Type: PolicyCollection, Version: "v1", Content: raw, UpdatedAt: time.Now()}

	if err := m.ApplyPolicy(p); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}

	got := m.GetCollectionConfig()
	if got.ProcessEvents != cfg.ProcessEvents {
		t.Errorf("ProcessEvents = %v, want %v", got.ProcessEvents, cfg.ProcessEvents)
	}
	if got.SamplingRate != cfg.SamplingRate {
		t.Errorf("SamplingRate = %v, want %v", got.SamplingRate, cfg.SamplingRate)
	}
}

func TestApplyPolicy_SameVersionSkipped(t *testing.T) {
	m := NewManager(t.TempDir())
	ch := m.Subscribe()

	iocs := IOCList{IPAddresses: []string{"1.2.3.4"}, Version: "v1"}
	raw, _ := json.Marshal(iocs)
	p := Policy{Type: PolicyIOC, Version: "v1", Content: raw, UpdatedAt: time.Now()}

	// First apply.
	if err := m.ApplyPolicy(p); err != nil {
		t.Fatalf("first ApplyPolicy: %v", err)
	}
	// Drain first notification.
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
	}

	// Second apply with same version should be a no-op (no notification).
	if err := m.ApplyPolicy(p); err != nil {
		t.Fatalf("second ApplyPolicy: %v", err)
	}

	select {
	case pt := <-ch:
		t.Errorf("unexpected notification %q for same-version policy", pt)
	case <-time.After(100 * time.Millisecond):
		// Correct: no notification for duplicate version.
	}
}

func TestApplyPolicy_InvalidJSON_ReturnsError(t *testing.T) {
	tests := []struct {
		name    string
		ptype   PolicyType
		content []byte
	}{
		{"bad IOC json", PolicyIOC, []byte("{not valid json")},
		{"bad exclusion json", PolicyExclusion, []byte("[not an object]")},
		{"bad collection json", PolicyCollection, []byte("null null")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(t.TempDir())
			p := Policy{Type: tc.ptype, Version: "v1", Content: tc.content, UpdatedAt: time.Now()}
			err := m.ApplyPolicy(p)
			if err == nil {
				t.Error("expected error for invalid JSON, got nil")
			}
		})
	}
}

// ─── matchGlob ───────────────────────────────────────────────

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		// Exact matches
		{"exact match", "/etc/passwd", "/etc/passwd", true},
		{"exact no match", "/etc/passwd", "/etc/shadow", false},
		// Prefix wildcard
		{"wildcard suffix .log", "*.log", "system.log", true},
		{"wildcard suffix .tmp", "*.tmp", "file.tmp", true},
		{"wildcard suffix no match", "*.log", "system.txt", false},
		// Suffix wildcard (prefix match)
		{"prefix /tmp/", "/tmp/*", "/tmp/evil.sh", true},
		{"prefix /etc/ match", "/etc/*", "/etc/hosts", true},
		{"prefix no match", "/tmp/*", "/var/tmp/evil.sh", false},
		// No wildcard, different strings
		{"no wildcard different", "abc", "def", false},
		// Empty pattern
		{"empty pattern exact", "", "", true},
		{"empty pattern non-empty input", "", "something", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchGlob(tc.pattern, tc.input)
			if got != tc.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
			}
		})
	}
}

// ─── IsExcluded ───────────────────────────────────────────────

func TestIsExcluded(t *testing.T) {
	tests := []struct {
		name        string
		exclusions  ExclusionList
		path        string
		processName string
		want        bool
	}{
		{
			"excluded path exact",
			ExclusionList{Paths: []string{"/proc"}},
			"/proc", "",
			true,
		},
		{
			"excluded path wildcard",
			ExclusionList{Paths: []string{"*.log"}},
			"system.log", "",
			true,
		},
		{
			"excluded process name",
			ExclusionList{ProcessNames: []string{"sshd"}},
			"/usr/bin/sshd", "sshd",
			true,
		},
		{
			"not excluded",
			ExclusionList{Paths: []string{"/proc"}, ProcessNames: []string{"sshd"}},
			"/etc/hosts", "nginx",
			false,
		},
		{
			"empty exclusion list",
			ExclusionList{},
			"/etc/passwd", "bash",
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(t.TempDir())
			raw, _ := json.Marshal(tc.exclusions)
			p := Policy{Type: PolicyExclusion, Version: "v1", Content: raw, UpdatedAt: time.Now()}
			if err := m.ApplyPolicy(p); err != nil {
				t.Fatalf("ApplyPolicy: %v", err)
			}

			got := m.IsExcluded(tc.path, tc.processName)
			if got != tc.want {
				t.Errorf("IsExcluded(%q, %q) = %v, want %v", tc.path, tc.processName, got, tc.want)
			}
		})
	}
}

// ─── GetYARAScanner ───────────────────────────────────────────

func TestGetYARAScanner_NotNil(t *testing.T) {
	m := NewManager(t.TempDir())
	s := m.GetYARAScanner()
	if s == nil {
		t.Error("GetYARAScanner returned nil")
	}
}

func TestGetYARAScanner_InitiallyEmpty(t *testing.T) {
	m := NewManager(t.TempDir())
	s := m.GetYARAScanner()
	if s.RuleCount() != 0 {
		t.Errorf("initial rule count = %d, want 0", s.RuleCount())
	}
}

// ─── PolicyType constants ────────────────────────────────────

func TestPolicyTypeConstants(t *testing.T) {
	types := []PolicyType{
		PolicyYARA, PolicySigma, PolicyIOC,
		PolicyExclusion, PolicyResponse, PolicyCollection,
	}

	seen := make(map[PolicyType]bool)
	for _, pt := range types {
		if seen[pt] {
			t.Errorf("duplicate PolicyType value: %q", pt)
		}
		seen[pt] = true
		if pt == "" {
			t.Error("empty PolicyType constant")
		}
	}
}
