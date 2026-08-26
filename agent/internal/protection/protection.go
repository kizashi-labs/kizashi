// Package protection detects the host's kernel-level protection capability and
// classifies it into a Mode (enforce / observe / poll). This is Ph1 of the Linux
// prevention roadmap: DETECT and REPORT only — nothing is blocked here.
// See docs/design/Linux改ざん防止と実行前防御設計.md (§3-1, Ph1) and
// docs/Linuxカーネル防御検証ランブック.md (Ph0, the eBPF LSM that enforce mode drives).
package protection

import (
	"fmt"
	"strings"
)

// Mode is the protection capability tier of the host.
type Mode string

const (
	// ModeEnforce: eBPF LSM (KRSI) is usable — the host is capable of in-kernel
	// pre-execution prevention and tamper protection. Requires kernel >= 5.13,
	// BTF present, and `bpf` active in the kernel LSM list (lsm=bpf at boot).
	ModeEnforce Mode = "enforce"

	// ModeObserve: eBPF works but LSM prevention does not — observe + reactive
	// kill only (today's behavior). Kernel >= 5.8 with BTF, but `bpf` is not in
	// the active LSM list (so bprm_check_security cannot be attached).
	ModeObserve Mode = "observe"

	// ModePoll: no eBPF — /proc polling fallback (oldest kernels / no BTF).
	ModePoll Mode = "poll"
)

// Capabilities is the detected host protection capability, reported to the
// server via the heartbeat so the fleet's prevention readiness is visible.
type Capabilities struct {
	Mode          Mode   `json:"mode"`
	KernelVersion string `json:"kernel_version"`
	KernelMajor   int    `json:"-"`
	KernelMinor   int    `json:"-"`
	BTF           bool   `json:"btf"`
	BPFLSM        bool   `json:"bpf_lsm"`
	Reason        string `json:"reason"`
}

func (c Capabilities) String() string {
	return fmt.Sprintf("mode=%s kernel=%q btf=%t bpf_lsm=%t — %s",
		c.Mode, c.KernelVersion, c.BTF, c.BPFLSM, c.Reason)
}

// decideMode applies the capability ladder (設計 §6 の互換性マトリクス). Pure
// logic, kept separate from OS probing so it is unit-testable on any platform.
func decideMode(major, minor int, btf, bpfLSM bool) Mode {
	atLeast := func(maj, min int) bool {
		return major > maj || (major == maj && minor >= min)
	}
	switch {
	case btf && bpfLSM && atLeast(5, 13):
		return ModeEnforce
	case btf && atLeast(5, 8):
		return ModeObserve
	default:
		return ModePoll
	}
}

// reasonFor explains the decision in one human-readable line — including, for
// non-enforce modes, what is missing to reach enforce (no silent caps, per the
// project's reporting philosophy).
func reasonFor(mode Mode, major, minor int, btf, bpfLSM bool) string {
	switch mode {
	case ModeEnforce:
		return "eBPF LSM usable: bpf active in LSM list, kernel >= 5.13, BTF present"
	case ModeObserve:
		switch {
		case !bpfLSM:
			return "eBPF ok but bpf not in active LSM list — boot with lsm=...,bpf to enable enforce"
		case !(major > 5 || (major == 5 && minor >= 13)):
			return "eBPF ok but kernel < 5.13 — enforce lower bound not met"
		default:
			return "eBPF ok, LSM prevention unavailable"
		}
	default: // ModePoll
		if !btf {
			return "no BTF (/sys/kernel/btf/vmlinux) — CO-RE eBPF unavailable, /proc polling"
		}
		return "kernel < 5.8 — eBPF ring buffer unavailable, /proc polling"
	}
}

// parseKernelVersion extracts major.minor from a uname release such as
// "6.12.0-124.38.1.el10_1.x86_64" or "5.15.0-91-generic".
func parseKernelVersion(release string) (major, minor int) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	return leadingInt(parts[0]), leadingInt(parts[1])
}

// leadingInt parses the leading run of ASCII digits (stops at the first
// non-digit), so "12" and "15-generic" both yield their numeric prefix.
func leadingInt(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
