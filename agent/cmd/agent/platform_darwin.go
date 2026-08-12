//go:build darwin

package main

import (
	"time"

	"os/exec"
	"strings"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/config"
	"github.com/edr-platform/agent/internal/platform/darwin"
)

// osVersionString returns the macOS product version string.
func osVersionString() string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "macOS"
	}
	return "macOS " + strings.TrimSpace(string(out))
}

// macOS platform implementations using:
//   - Process monitoring: ps polling (no CGo required)
//   - File monitoring:    fswatch / polling fallback
//   - Network monitoring: lsof-based connection tracking
//   - DNS monitoring:     tcpdump passive capture (requires root)
//   - Isolation:          pf (Packet Filter) anchor rules
//
// Note: Endpoint Security Framework (ESF) integration — which provides
// kernel-level events without polling — requires CGo and a signed
// System Extension. ESF support is tracked as a separate task.

func newPlatformIsolation(cfg *config.Config) collector.IsolationManager {
	return darwin.NewPFIsolationManager(cfg.Server.URL)
}

func newPlatformProcessMgr() collector.ProcessManager {
	return darwin.NewDarwinProcessManager()
}

func newPlatformQuarantine(cfg *config.Config) collector.FileQuarantine {
	return darwin.NewDarwinFileQuarantine(cfg.Quarantine.Dir)
}

func newPlatformProcessCollector() collector.ProcessCollector {
	return darwin.NewDarwinProcessCollector()
}

func newPlatformFileCollector() collector.FileCollector {
	// nil = use default monitored directories from config
	return darwin.NewDarwinFileCollector(nil)
}

func newPlatformNetworkCollector() collector.NetworkCollector {
	return darwin.NewDarwinNetworkCollector()
}

func newPlatformDNSCollector() collector.DNSCollector {
	// "" = default interface (en0); falls back gracefully if tcpdump
	// is unavailable or lacks permissions.
	return darwin.NewDarwinDNSCollector("")
}

// Registry monitoring is Windows-only; return nil so the caller skips it.
func newPlatformRegistryCollector() collector.RegistryCollector {
	return nil
}

// Auth monitoring on Darwin streams the unified log (log stream) for
// sshd/sudo/su activity — SSH logins, privilege escalation, and their failures.
func newPlatformAuthCollector() collector.AuthCollector {
	return darwin.NewDarwinAuthCollector()
}

// waitPlatformShutdown is a no-op here: only the Windows ETW collectors own
// process-external state (registered trace sessions) that outlives the agent.
func waitPlatformShutdown(time.Duration) {}
