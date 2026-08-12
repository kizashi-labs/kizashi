//go:build linux

package main

import (
	"time"

	"os"
	"strings"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/config"
	"github.com/edr-platform/agent/internal/platform/linux"
)

// osVersionString reads PRETTY_NAME from /etc/os-release.
func osVersionString() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(v, `"`)
		}
	}
	return "Linux"
}

func newPlatformIsolation(cfg *config.Config) collector.IsolationManager {
	return linux.NewIPTablesIsolationManager(cfg.Server.URL)
}

func newPlatformProcessMgr() collector.ProcessManager {
	return linux.NewLinuxProcessManager()
}

func newPlatformQuarantine(cfg *config.Config) collector.FileQuarantine {
	return linux.NewLinuxFileQuarantine(cfg.Quarantine.Dir)
}

func newPlatformProcessCollector() collector.ProcessCollector {
	return linux.NewEBPFProcessCollector()
}

func newPlatformFileCollector() collector.FileCollector {
	return linux.NewInotifyFileCollector()
}

func newPlatformNetworkCollector() collector.NetworkCollector {
	// Prefers eBPF connect tracing (captures connection attempts incl. failed/scan
	// connections that /proc/net polling misses); degrades to polling without the
	// ebpf tag or on unsupported kernels.
	return linux.NewEBPFNetworkCollector()
}

// newPlatformTLSSensor returns the eBPF TLS-handshake fingerprint sensor (JA3/JA3S).
// It requires the "ebpf" build tag; without it the sensor's Start is a no-op.
func newPlatformTLSSensor() tlsSensorStarter {
	return linux.NewTLSHandshakeSensor()
}

func newPlatformDNSCollector() collector.DNSCollector {
	return linux.NewRawDNSCollector()
}

// Registry monitoring is Windows-only; return nil so the caller skips it.
func newPlatformRegistryCollector() collector.RegistryCollector {
	return nil
}

// Auth monitoring tails /var/log/auth.log (or /var/log/secure) for SSH/sudo/su
// login, privilege-escalation and failure events.
func newPlatformAuthCollector() collector.AuthCollector {
	return linux.NewLinuxAuthCollector()
}

// waitPlatformShutdown is a no-op here: only the Windows ETW collectors own
// process-external state (registered trace sessions) that outlives the agent.
func waitPlatformShutdown(time.Duration) {}
