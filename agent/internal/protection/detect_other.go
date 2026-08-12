//go:build !linux && !(windows && prevention)

package protection

import "runtime"

// Detect on non-Linux (and Windows without the prevention build tag) reports
// observe: in-kernel LSM prevention is a Linux-only capability (eBPF LSM / KRSI).
// Windows/macOS observe via their platform sensors (ETW / ESF) but cannot
// pre-execution-block through this mechanism. The Windows kernel-driver
// prevention path is gated behind `-tags prevention` and has its own Detect
// (detect_windows_prevention.go).
func Detect() Capabilities {
	return Capabilities{
		Mode:          ModeObserve,
		KernelVersion: runtime.GOOS,
		Reason:        "kernel LSM prevention is Linux-only; " + runtime.GOOS + " observes via platform sensors without in-kernel prevention",
	}
}
