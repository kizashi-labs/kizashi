//go:build windows

package main

import (
	"time"

	"fmt"
	"log/slog"

	syswin "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/config"
	winplatform "github.com/edr-platform/agent/internal/platform/windows"
)

// osVersionString returns a human-readable Windows version string.
// Uses RtlGetVersion (kernel syscall) as primary — no registry or admin required.
func osVersionString() string {
	// Primary: kernel version via RtlGetVersion (always works, no permissions needed)
	if v := kernelVersion(); v != "" {
		return v
	}

	// Fallback: Windows registry
	if v := registryVersion(); v != "" {
		return v
	}

	return "Windows"
}

// kernelVersion reads the OS version from the Windows kernel via RtlGetVersion.
// This bypasses compatibility shims and always returns the true OS version.
func kernelVersion() string {
	info := syswin.RtlGetVersion()
	if info == nil {
		return ""
	}

	build := info.BuildNumber
	// ProductType: 1=Workstation, 2=DomainController, 3=Server
	isServer := info.ProductType != 1

	switch {
	case build >= 26100:
		if isServer {
			return fmt.Sprintf("Windows Server 2025 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 11 24H2 (Build %d)", build)
	case build >= 22621:
		if isServer {
			return fmt.Sprintf("Windows Server 2022 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 11 22H2 (Build %d)", build)
	case build >= 22000:
		if isServer {
			return fmt.Sprintf("Windows Server 2022 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 11 (Build %d)", build)
	case build >= 20348:
		return fmt.Sprintf("Windows Server 2022 (Build %d)", build)
	case build >= 19045:
		if isServer {
			return fmt.Sprintf("Windows Server 2019 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 10 22H2 (Build %d)", build)
	case build >= 19044:
		if isServer {
			return fmt.Sprintf("Windows Server 2019 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 10 21H2 (Build %d)", build)
	case build >= 19041:
		if isServer {
			return fmt.Sprintf("Windows Server 2019 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 10 20H1 (Build %d)", build)
	case build >= 17763:
		if isServer {
			return fmt.Sprintf("Windows Server 2019 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 10 1809 (Build %d)", build)
	case build >= 14393:
		if isServer {
			return fmt.Sprintf("Windows Server 2016 (Build %d)", build)
		}
		return fmt.Sprintf("Windows 10 1607 (Build %d)", build)
	default:
		return fmt.Sprintf("Windows (Build %d)", build)
	}
}

// registryVersion reads the OS version from the Windows registry.
func registryVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE)
	if err != nil {
		slog.Warn("osVersion: registry open failed", "error", err)
		return ""
	}
	defer k.Close()

	product, _, _ := k.GetStringValue("ProductName")
	display, _, _ := k.GetStringValue("DisplayVersion")
	if display == "" {
		display, _, _ = k.GetStringValue("ReleaseId")
	}
	if product == "" {
		return ""
	}
	if display != "" {
		return fmt.Sprintf("%s %s", product, display)
	}
	return product
}

func newPlatformIsolation(cfg *config.Config) collector.IsolationManager {
	return winplatform.NewWFPIsolationManager()
}

func newPlatformProcessMgr() collector.ProcessManager {
	return winplatform.NewWindowsProcessManager()
}

func newPlatformQuarantine(cfg *config.Config) collector.FileQuarantine {
	return winplatform.NewWindowsFileQuarantine(cfg.Quarantine.Dir)
}

func newPlatformProcessCollector() collector.ProcessCollector {
	// Real-time NT-Kernel-Logger ETW (PPID + in-kernel CommandLine, gap-free)
	// is now the DEFAULT: it captures short-lived processes the polling
	// collector misses, and startETW falls back to polling automatically on
	// any failure (non-admin, session error), so no endpoint regresses. Set
	// EDR_AGENT_ETW_PROCESS=0 to force the legacy polling path. (Registry and
	// the other heavier ETW sensors stay opt-in via EDR_AGENT_ETW — see
	// newPlatformRegistryCollector.)
	return winplatform.NewETWProcessCollector()
}

func newPlatformFileCollector() collector.FileCollector {
	return winplatform.NewWindowsFileCollector()
}

// newPlatformImageLoadCollector returns the ETW image-load collector (additive
// sensor: default ON, opt-out via EDR_AGENT_ETW_SENSORS=0; no-op if the ETW
// session can't start). DLL side-loading visibility (T1574.001/.002).
func newPlatformImageLoadCollector() collector.ImageLoadCollector {
	return winplatform.NewETWImageLoadCollector()
}

// newPlatformScriptCollector returns the ETW PowerShell ScriptBlock collector
// (additive sensor: default ON, opt-out via EDR_AGENT_ETW_SENSORS=0; no-op if
// the ETW session can't start). Fileless-script visibility (T1059.001).
func newPlatformScriptCollector() collector.ScriptContentCollector {
	return winplatform.NewETWScriptCollector()
}

// newPlatformRemoteThreadCollector returns the ETW CreateRemoteThread injection
// collector (additive sensor: default ON, opt-out via EDR_AGENT_ETW_SENSORS=0;
// no-op if the ETW session can't start). T1055 visibility.
func newPlatformRemoteThreadCollector() remoteThreadStarter {
	return winplatform.NewETWRemoteThreadCollector()
}

// newPlatformTLSSensor returns the raw-socket JA3 TLS-handshake sniffer (opt-in;
// needs admin for the raw socket). Process attribution is unavailable via raw socket.
func newPlatformTLSSensor() tlsSensorStarter {
	return winplatform.NewWindowsTLSSensor()
}

// newPlatformPSModuleCollector returns the ETW PowerShell Module Logging (4103)
// collector (additive sensor: default ON, opt-out via EDR_AGENT_ETW_SENSORS=0;
// no-op if the ETW session can't start). Supplies Payload / ContextInfo for
// SigmaHQ ps_module rules (T1059.001).
func newPlatformPSModuleCollector() psModuleStarter {
	return winplatform.NewETWPSModuleCollector()
}

// newPlatformWMIActivityCollector returns the ETW WMI-Activity collector
// (additive sensor: default ON, opt-out via EDR_AGENT_ETW_SENSORS=0; no-op if
// the ETW session can't start). Supplies the SigmaHQ wmi_event fields for
// T1546.003 (event-subscription persistence) and T1047 (remote WMI execution).
//
// ⚠️ NOT LIVE-VERIFIED — see the note on ETWWMIActivityCollector.
func newPlatformWMIActivityCollector() wmiActivityStarter {
	return winplatform.NewETWWMIActivityCollector()
}

// newPlatformNamedPipeCollector returns the ETW named-pipe creation collector
// (additive sensor: default ON, opt-out via EDR_AGENT_ETW_SENSORS=0; no-op if
// the ETW session can't start). Supplies PipeName for SigmaHQ pipe_created rules
// (Cobalt Strike named-pipe C2).
func newPlatformNamedPipeCollector() namedPipeStarter {
	return winplatform.NewETWPipeCollector()
}

// newPlatformEventLogClearCollector returns the audit-log-clear collector
// (Security EID 1102 / System EID 104 → T1070.001). Always on; polling is
// read-only and fails quietly without Security-channel (admin) access.
func newPlatformEventLogClearCollector() eventLogClearStarter {
	return winplatform.NewWindowsEventLogClearCollector()
}

// newPlatformServiceInstallCollector returns the service-install collector
// (System EID 7045 → T1543.003). Always on; polling is read-only over the
// System log.
func newPlatformServiceInstallCollector() serviceInstallStarter {
	return winplatform.NewWindowsServiceInstallCollector()
}

func newPlatformNetworkCollector() collector.NetworkCollector {
	return winplatform.NewWindowsNetworkCollector()
}

func newPlatformDNSCollector() collector.DNSCollector {
	return winplatform.NewWindowsDNSCollector()
}

// newPlatformRegistryCollector returns the ETW Kernel-Registry collector when
// EDR_AGENT_ETW is opted in (value-name / acting-process / value-data depth),
// otherwise the proven RegNotifyChangeKeyValue collector (key-level only). The
// ETW collector falls back to a no-op internally if its session can't start, but
// gating here keeps the default build on the mature path.
func newPlatformRegistryCollector() collector.RegistryCollector {
	if winplatform.ETWProcessEnabled() {
		return winplatform.NewETWRegistryCollector()
	}
	return winplatform.NewWindowsRegistryCollector()
}

func newPlatformAuthCollector() collector.AuthCollector {
	return winplatform.NewWindowsAuthCollector()
}

// waitPlatformShutdown blocks until the Windows ETW supervisors have stopped
// their sessions. Without this the process exits while they are still tearing
// down, leaving "NT Kernel Logger" and EDR-Agent-* sessions registered — and a
// leaked session is not merely untidy: the next start can fail on it, with
// nothing in the agent log to say why (validation host, 2026-08-05).
func waitPlatformShutdown(timeout time.Duration) {
	winplatform.WaitETWSupervisors(timeout)
}
