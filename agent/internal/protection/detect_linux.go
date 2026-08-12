//go:build linux

package protection

import (
	"os"
	"strings"
)

// Detect probes the running Linux kernel for eBPF LSM prevention capability.
// It is read-only and never blocks: it reads kernel version, BTF presence, and
// the active LSM list, then classifies the host (Ph1 — no enforcement).
func Detect() Capabilities {
	release := readTrim("/proc/sys/kernel/osrelease")
	major, minor := parseKernelVersion(release)

	_, errBTF := os.Stat("/sys/kernel/btf/vmlinux")
	btf := errBTF == nil

	bpfLSM := false
	if lsm := readTrim("/sys/kernel/security/lsm"); lsm != "" {
		for _, m := range strings.Split(lsm, ",") {
			if strings.TrimSpace(m) == "bpf" {
				bpfLSM = true
				break
			}
		}
	}

	mode := decideMode(major, minor, btf, bpfLSM)
	return Capabilities{
		Mode:          mode,
		KernelVersion: release,
		KernelMajor:   major,
		KernelMinor:   minor,
		BTF:           btf,
		BPFLSM:        bpfLSM,
		Reason:        reasonFor(mode, major, minor, btf, bpfLSM),
	}
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
