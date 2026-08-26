//go:build windows

// Package windows provides Windows-specific EDR collectors:
//   - ETWProcessCollector / WindowsProcessCollector (process lifecycle via ETW + Toolhelp32)
//   - WindowsNetworkCollector (TCP/UDP via IP Helper API)
//   - WindowsFileCollector (filesystem changes via ReadDirectoryChangesW)
//   - WindowsRegistryCollector (registry changes via RegNotifyChangeKeyValue)
//   - WindowsDNSCollector (DNS queries via raw socket)
//   - WFPIsolationManager (network isolation via Windows Firewall)
//   - WindowsProcessManager (process termination)
//   - WindowsFileQuarantine (file quarantine)
package windows

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// PlatformCollectors bundles all Windows-specific collectors behind the
// platform-agnostic collector interfaces.
type PlatformCollectors struct {
	Process  collector.ProcessCollector
	Network  collector.NetworkCollector
	File     collector.FileCollector
	Registry collector.RegistryCollector
	DNS      collector.DNSCollector
}

// NewPlatformCollectors instantiates all Windows platform collectors.
func NewPlatformCollectors() *PlatformCollectors {
	return &PlatformCollectors{
		Process:  NewWindowsProcessCollector(),
		Network:  NewWindowsNetworkCollector(),
		File:     NewWindowsFileCollector(),
		Registry: NewWindowsRegistryCollector(),
		DNS:      NewWindowsDNSCollector(),
	}
}

// Start launches all collectors concurrently with the provided event channels.
func (pc *PlatformCollectors) Start(
	ctx context.Context,
	procOut chan<- collector.ProcessEvent,
	netOut chan<- collector.NetworkEvent,
	fileOut chan<- collector.FileEvent,
	regOut chan<- collector.RegistryEvent,
	dnsOut chan<- collector.DNSEvent,
) error {
	if err := pc.Process.Start(ctx, procOut); err != nil {
		return err
	}
	if err := pc.Network.Start(ctx, netOut); err != nil {
		return err
	}
	if err := pc.File.Start(ctx, fileOut); err != nil {
		return err
	}
	if err := pc.Registry.Start(ctx, regOut); err != nil {
		return err
	}
	if err := pc.DNS.Start(ctx, dnsOut); err != nil {
		// DNS collector requires elevated privileges; non-fatal
		_ = err
	}
	return nil
}

// Stop shuts down all collectors.
func (pc *PlatformCollectors) Stop() {
	pc.Process.Stop()  //nolint:errcheck
	pc.Network.Stop()  //nolint:errcheck
	pc.File.Stop()     //nolint:errcheck
	pc.Registry.Stop() //nolint:errcheck
	pc.DNS.Stop()      //nolint:errcheck
}
