//go:build !linux && !windows && !darwin

// platform_stubs.go provides factory functions that delegate to platform-specific
// implementations selected at compile time via build tags.
package main

import (
	"time"

	"context"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/config"
)

// These functions are implemented per-platform.
// Build with: GOOS=linux go build -tags linux ./cmd/agent
//             GOOS=windows go build -tags windows ./cmd/agent
//             GOOS=darwin go build -tags darwin ./cmd/agent

func newPlatformIsolation(cfg *config.Config) collector.IsolationManager {
	return newIsolationManager(cfg)
}

func newPlatformProcessMgr() collector.ProcessManager {
	return newProcessManager()
}

func newPlatformQuarantine(cfg *config.Config) collector.FileQuarantine {
	return newFileQuarantine(cfg.Quarantine.Dir)
}

func newPlatformProcessCollector() collector.ProcessCollector {
	return newProcessCollector()
}

func newPlatformFileCollector() collector.FileCollector {
	return newFileCollector()
}

func newPlatformNetworkCollector() collector.NetworkCollector {
	return newNetworkCollector()
}

func newPlatformDNSCollector() collector.DNSCollector {
	return newDNSCollector()
}

func newPlatformRegistryCollector() collector.RegistryCollector {
	return newRegistryCollector()
}

func newPlatformAuthCollector() collector.AuthCollector {
	return newAuthCollector()
}

// ─── Stub implementations (replaced by platform build) ────────

type stubIsolation struct{}

func (s *stubIsolation) Isolate([]string, []uint16) error { return nil }
func (s *stubIsolation) Unisolate() error                 { return nil }
func (s *stubIsolation) IsIsolated() bool                 { return false }

type stubProcessMgr struct{}

func (s *stubProcessMgr) Kill(pid uint32) error { return nil }

type stubQuarantine struct{}

func (s *stubQuarantine) Quarantine(path string) (string, error) { return "", nil }
func (s *stubQuarantine) Restore(id, path string) error          { return nil }
func (s *stubQuarantine) List() ([]collector.QuarantinedFile, error) {
	return nil, nil
}

type stubProcessCollector struct{}

func (s *stubProcessCollector) Start(_ context.Context, _ chan<- collector.ProcessEvent) error {
	return nil
}
func (s *stubProcessCollector) Stop() error { return nil }

type stubFileCollector struct{}

func (s *stubFileCollector) Start(_ context.Context, _ chan<- collector.FileEvent) error {
	return nil
}
func (s *stubFileCollector) Stop() error            { return nil }
func (s *stubFileCollector) SetPaths(_, _ []string) {}

type stubNetworkCollector struct{}

func (s *stubNetworkCollector) Start(_ context.Context, _ chan<- collector.NetworkEvent) error {
	return nil
}
func (s *stubNetworkCollector) Stop() error { return nil }

type stubDNSCollector struct{}

func (s *stubDNSCollector) Start(_ context.Context, _ chan<- collector.DNSEvent) error {
	return nil
}
func (s *stubDNSCollector) Stop() error { return nil }

// osVersionString is a stub; real implementations live in the platform files.
func osVersionString() string { return "unknown" }

// Default stub factory functions — overridden by platform-specific files
// (platform_linux.go, platform_windows.go, platform_darwin.go)

func newIsolationManager(_ *config.Config) collector.IsolationManager {
	return &stubIsolation{}
}
func newProcessManager() collector.ProcessManager {
	return &stubProcessMgr{}
}
func newFileQuarantine(_ string) collector.FileQuarantine {
	return &stubQuarantine{}
}
func newProcessCollector() collector.ProcessCollector {
	return &stubProcessCollector{}
}
func newFileCollector() collector.FileCollector {
	return &stubFileCollector{}
}
func newNetworkCollector() collector.NetworkCollector {
	return &stubNetworkCollector{}
}
func newDNSCollector() collector.DNSCollector {
	return &stubDNSCollector{}
}

func newRegistryCollector() collector.RegistryCollector {
	return nil
}

func newAuthCollector() collector.AuthCollector {
	return nil
}

// waitPlatformShutdown is a no-op off Windows: only the ETW collectors own
// process-external state that outlives the agent.
func waitPlatformShutdown(time.Duration) {}
