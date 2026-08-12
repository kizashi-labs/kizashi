//go:build windows && prevention

package protection

import (
	"os"

	syswin "golang.org/x/sys/windows"
)

// Detect (Windows, prevention build) classifies the host's pre-execution
// prevention tier from the KizashiPrevention kernel driver's live state — the
// Windows counterpart of the Linux eBPF LSM detection. It is reported each
// heartbeat so the fleet's prevention readiness shows up in the same dashboard
// (server-side ProtectionModeSummary / PreventionReadinessCard; no server
// changes). See docs/Windowsカーネル防御PoC手順.md and
// docs/design/Windows・macOS実行前防御と改ざん防止設計.md.
//
//   - enforce : driver loaded AND EDR_PREVENTION_ENFORCE=1 (kernel denies blocked
//     image creation with STATUS_ACCESS_DENIED);
//   - observe : driver loaded but audit/fail-open, OR driver not loaded (the agent
//     still observes via ETW + reactive polling kill, but does not pre-exec block).
func Detect() Capabilities {
	loaded := driverLoaded()
	enforce := os.Getenv("EDR_PREVENTION_ENFORCE") == "1"

	switch {
	case loaded && enforce:
		return Capabilities{
			Mode:          ModeEnforce,
			KernelVersion: "windows",
			Reason:        "KizashiPrevention driver loaded; EDR_PREVENTION_ENFORCE=1 — kernel pre-execution deny active",
		}
	case loaded:
		return Capabilities{
			Mode:          ModeObserve,
			KernelVersion: "windows",
			Reason:        "KizashiPrevention driver loaded in audit mode (fail-open); set EDR_PREVENTION_ENFORCE=1 to enforce",
		}
	default:
		return Capabilities{
			Mode:          ModeObserve,
			KernelVersion: "windows",
			Reason:        "KizashiPrevention driver not loaded — observe via ETW + reactive polling kill (no in-kernel prevention)",
		}
	}
}

// driverLoaded reports whether the KizashiPrevention control device can be
// opened (i.e. the driver is loaded). A read handle is enough; it is closed
// immediately.
func driverLoaded() bool {
	h, err := syswin.CreateFile(
		syswin.StringToUTF16Ptr(`\\.\KizashiPrevention`),
		syswin.GENERIC_READ, 0, nil, syswin.OPEN_EXISTING, 0, 0)
	if err != nil {
		return false
	}
	_ = syswin.CloseHandle(h)
	return true
}
