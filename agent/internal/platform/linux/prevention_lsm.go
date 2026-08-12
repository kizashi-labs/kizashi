//go:build linux && ebpf && prevention

// Package linux — Ph0 PoC loader for the eBPF LSM exec-prevention program.
//
// Build/run only with `-tags "ebpf prevention"` on a `lsm=bpf`-enabled host. The
// bpf2go-generated objects (preventionlsm_bpf*.go/.o) do NOT exist until
// `go generate` runs on a clang+BTF host — see docs/Linuxカーネル防御検証ランブック.md.
// This file is intentionally NOT referenced by the production agent (cmd/agent);
// it is driven only by cmd/prevention-poc for on-VM validation.
package linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "ebpf prevention" -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" PreventionLSM ../../../ebpf/prevention_lsm.bpf.c

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const preventionMaxPathLen = 256

// Per-path blocklist modes (blocked_paths map value, mirrors prevention_lsm.bpf.c).
const (
	// PathModeAudit: report matches but never deny (alert-action rules).
	PathModeAudit uint8 = 1
	// PathModeEnforce: deny when the global enforce switch is on (block-action rules).
	PathModeEnforce uint8 = 2
)

// PreventionDecision is one decision emitted by the LSM hook.
type PreventionDecision struct {
	PID      uint32
	UID      uint32
	Blocked  bool
	Enforced bool // true = exec was actually denied (-EPERM); false = audit-only
	Filename string
}

// LoadAndRunPreventionLSM loads the eBPF LSM program, attaches it to
// bprm_check_security, seeds the blocklist with the given absolute binary paths,
// sets audit/enforce mode, and streams decisions to out until ctx is cancelled.
//
// enforce=false → audit mode: blocklisted execs are reported but ALLOWED (the
// mandatory pre-promotion measurement step, 設計 §4-3). enforce=true → the exec
// is denied with -EPERM.
func LoadAndRunPreventionLSM(ctx context.Context, blockedPaths []string, enforce bool, out chan<- PreventionDecision) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	objs := &PreventionLSMObjects{}
	if err := LoadPreventionLSMObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF LSM objects (is the kernel built with CONFIG_BPF_LSM and booted with lsm=bpf?): %w", err)
	}
	defer objs.Close()

	// Attach to the LSM hook. This is the step that fails loudly when `lsm=bpf`
	// is missing from the kernel command line.
	lk, err := link.AttachLSM(link.LSMOptions{Program: objs.CheckExec})
	if err != nil {
		return fmt.Errorf("attach lsm/bprm_check_security (check `cat /sys/kernel/security/lsm` includes bpf): %w", err)
	}
	defer lk.Close()

	// Seed the blocklist as enforce-eligible (mode 2) so this PoC's enforce flag
	// actually denies; in audit mode (enforce=false → global switch 0) mode-2
	// paths are reported but allowed.
	for _, p := range blockedPaths {
		var key [preventionMaxPathLen]byte
		copy(key[:], p) // copy truncates at 256 and leaves the rest zeroed
		if err := objs.BlockedPaths.Put(key, PathModeEnforce); err != nil {
			return fmt.Errorf("seed blocklist entry %q: %w", p, err)
		}
	}

	// Set audit/enforce mode at config index 0.
	enforceVal := uint8(0)
	if enforce {
		enforceVal = 1
	}
	if err := objs.PreventionConfig.Put(uint32(0), enforceVal); err != nil {
		return fmt.Errorf("set enforce flag: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.PreventionEvents)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		dec, ok := parsePreventionEvent(record.RawSample)
		if !ok {
			continue
		}
		select {
		case out <- dec:
		case <-ctx.Done():
			return nil
		}
	}
}

// parsePreventionEvent decodes the C struct prevention_event from raw ring-buffer
// bytes. Offsets mirror prevention_lsm.bpf.c exactly (u32 align):
//
//	pid[0:4] uid[4:8] blocked[8] enforced[9] filename[10:266]
func parsePreventionEvent(raw []byte) (PreventionDecision, bool) {
	const minLen = 10 + preventionMaxPathLen // 266
	if len(raw) < minLen {
		return PreventionDecision{}, false
	}
	return PreventionDecision{
		PID:      binary.NativeEndian.Uint32(raw[0:4]),
		UID:      binary.NativeEndian.Uint32(raw[4:8]),
		Blocked:  raw[8] != 0,
		Enforced: raw[9] != 0,
		Filename: nullTerminated(raw[10:minLen]),
	}, true
}
