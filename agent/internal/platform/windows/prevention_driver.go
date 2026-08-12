//go:build windows && prevention

// Package windows provides the Windows kernel-driver client for the agent's
// pre-execution prevention path — the Windows counterpart of the Linux eBPF LSM
// runner (internal/platform/linux). It talks to the KizashiPrevention driver
// (agent/driver/windows/prevention) over its control-device IOCTLs: push a
// blocklist + the global enforce switch, and pull the driver's block decisions.
//
// Mirrors the audit→enforce / fail-open / per-path-mode model. Gated behind the
// `prevention` build tag so the default Windows agent build is unaffected and
// does not require the driver. See docs/Windowsカーネル防御PoC手順.md.
package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

	syswin "golang.org/x/sys/windows"
)

// Per-path mode (mirrors driver PREV_MODE_* and Linux PathModeAudit/Enforce).
const (
	PathModeAudit   uint8 = 1 // report only, never deny
	PathModeEnforce uint8 = 2 // deny when the global enforce switch is on
)

const (
	devicePath  = `\\.\KizashiPrevention`
	prevMaxPath = 260
)

// CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, fn, METHOD_BUFFERED=0, FILE_WRITE_ACCESS=2)
func ctl(fn uint32) uint32 { return (0x22 << 16) | (2 << 14) | (fn << 2) | 0 }

var (
	ioctlSetEnforce  = ctl(0x801)
	ioctlAddRule     = ctl(0x802)
	ioctlClearRules  = ctl(0x803)
	ioctlGetDecision = ctl(0x804)
	ioctlSetInject   = ctl(0x808) // SET_INJECT_AUDIT
	ioctlGetInject   = ctl(0x809) // GET_INJECT
)

// injectRemoteThread is the sentinel Access value the driver uses for a
// remote-thread creation (vs a VM_WRITE/CREATE_THREAD handle open).
const injectRemoteThread = 0xFFFFFFFF

// InjectDecision is one cross-process injection attempt (M2): the injector
// (sender) opened an injection-capable handle to, or created a remote thread in,
// the target. Audit only.
type InjectDecision struct {
	TargetPID    int
	SenderPID    int
	Access       uint32
	RemoteThread bool
}

// PreventionDecision is one block decision pulled from the driver's ring.
type PreventionDecision struct {
	PID      int
	Filename string // NT image path the driver saw (e.g. \??\C:\...\x.exe)
	Enforced bool   // true = creation actually denied (STATUS_ACCESS_DENIED)
}

// PreventionRunner is the user-mode client of the KizashiPrevention driver.
type PreventionRunner struct {
	h syswin.Handle
}

// NewPreventionRunner returns a runner with no open handle yet.
func NewPreventionRunner() *PreventionRunner { return &PreventionRunner{h: syswin.InvalidHandle} }

// Start opens the driver control device. Returns an error if the driver is not
// loaded (the agent then stays in observe mode, like the Linux non-LSM path).
func (r *PreventionRunner) Start() error {
	h, err := syswin.CreateFile(
		syswin.StringToUTF16Ptr(devicePath),
		syswin.GENERIC_READ|syswin.GENERIC_WRITE, 0, nil,
		syswin.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("open %s (driver loaded?): %w", devicePath, err)
	}
	r.h = h
	return nil
}

// Close releases the device handle.
func (r *PreventionRunner) Close() error {
	if r.h != syswin.InvalidHandle {
		err := syswin.CloseHandle(r.h)
		r.h = syswin.InvalidHandle
		return err
	}
	return nil
}

func (r *PreventionRunner) ioctl(code uint32, in, out []byte) (uint32, error) {
	var ret uint32
	var inP, outP *byte
	if len(in) > 0 {
		inP = &in[0]
	}
	if len(out) > 0 {
		outP = &out[0]
	}
	err := syswin.DeviceIoControl(r.h, code, inP, uint32(len(in)), outP, uint32(len(out)), &ret, nil)
	return ret, err
}

// SetEnforce flips the driver's global enforce switch (fail-open when false).
func (r *PreventionRunner) SetEnforce(on bool) error {
	cfg := make([]byte, 4)
	if on {
		binary.LittleEndian.PutUint32(cfg, 1)
	}
	_, err := r.ioctl(ioctlSetEnforce, cfg, nil)
	return err
}

// ProcessImageName returns the base image name (e.g. "csrss.exe") of a PID, or ""
// if it can't be opened. Used by the injection-audit consumer to allowlist
// trusted system/security injectors (which legitimately open cross-process
// handles constantly) and cut M2 false positives.
func ProcessImageName(pid uint32) string {
	h, err := syswin.OpenProcess(syswin.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer syswin.CloseHandle(h)
	buf := make([]uint16, 260)
	n := uint32(len(buf))
	if err := syswin.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	full := syswin.UTF16ToString(buf[:n])
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == '\\' || full[i] == '/' {
			return full[i+1:]
		}
	}
	return full
}

// ProcessParentPID returns the parent PID (InheritedFromUniqueProcessId) of a
// process, or 0 if it can't be opened/read. Used by the M2 injection-audit
// consumer to suppress the benign case where a process creates the INITIAL thread
// of a child it just spawned — that is normal process creation, not a
// CreateRemoteThread injection (Sysmon EID8 excludes it too). When the target's
// parent is the sender, it is a launch, not an injection.
func ProcessParentPID(pid uint32) uint32 {
	h, err := syswin.OpenProcess(syswin.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer syswin.CloseHandle(h)
	return readParentPID(h)
}

// SetInjectAudit enables/disables M2 cross-process injection auditing (audit
// only — handle opens with injection-capable access + remote-thread creation).
func (r *PreventionRunner) SetInjectAudit(on bool) error {
	cfg := make([]byte, 4)
	if on {
		binary.LittleEndian.PutUint32(cfg, 1)
	}
	_, err := r.ioctl(ioctlSetInject, cfg, nil)
	return err
}

// RunInject polls the driver's injection ring every 500ms and forwards each
// decision on out until ctx is cancelled (PREV_TAMPER_DECISION shape = 4×u32).
func (r *PreventionRunner) RunInject(ctx context.Context, out chan<- InjectDecision) {
	buf := make([]byte, 16)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := r.ioctl(ioctlGetInject, nil, buf)
				if err != nil || n < 16 {
					break
				}
				access := binary.LittleEndian.Uint32(buf[12:])
				d := InjectDecision{
					TargetPID:    int(binary.LittleEndian.Uint32(buf[0:])),
					SenderPID:    int(binary.LittleEndian.Uint32(buf[4:])),
					Access:       access,
					RemoteThread: access == injectRemoteThread,
				}
				select {
				case out <- d:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// buildRule mirrors C struct PREV_RULE { u16 PathLen; u32 Mode; wchar Path[260]; }
// (PathLen@0, pad@2, Mode@4, Path@8) → 8 + 260*2 bytes.
func buildRule(suffix string, mode uint8) []byte {
	u := utf16.Encode([]rune(suffix))
	if len(u) > prevMaxPath-1 {
		u = u[:prevMaxPath-1]
	}
	buf := make([]byte, 8+prevMaxPath*2)
	binary.LittleEndian.PutUint16(buf[0:], uint16(len(u)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(mode))
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[8+i*2:], c)
	}
	return buf
}

// UpdateBlocklist replaces the driver's rule set with entries (match suffix → mode).
func (r *PreventionRunner) UpdateBlocklist(entries map[string]uint8) error {
	if _, err := r.ioctl(ioctlClearRules, nil, nil); err != nil {
		return fmt.Errorf("clear rules: %w", err)
	}
	for suffix, mode := range entries {
		if suffix == "" {
			continue
		}
		if _, err := r.ioctl(ioctlAddRule, buildRule(suffix, mode), nil); err != nil {
			return fmt.Errorf("add rule %q: %w", suffix, err)
		}
	}
	return nil
}

// Run polls the driver's decision ring every 500ms and forwards each decision on
// out until ctx is cancelled. GET_DECISION returns an error (ERROR_NO_MORE_ITEMS)
// when the ring is empty, which ends the per-tick drain.
func (r *PreventionRunner) Run(ctx context.Context, out chan<- PreventionDecision) {
	buf := make([]byte, 12+prevMaxPath*2) // sizeof(PREV_DECISION)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := r.ioctl(ioctlGetDecision, nil, buf)
				if err != nil || n < 12 {
					break // ring empty (NO_MORE_ENTRIES) or short read
				}
				pid := binary.LittleEndian.Uint32(buf[0:])
				enforced := binary.LittleEndian.Uint32(buf[8:]) == 1
				pw := make([]uint16, 0, prevMaxPath)
				for i := 0; i < prevMaxPath; i++ {
					c := binary.LittleEndian.Uint16(buf[12+i*2:])
					if c == 0 {
						break
					}
					pw = append(pw, c)
				}
				d := PreventionDecision{PID: int(pid), Filename: string(utf16.Decode(pw)), Enforced: enforced}
				select {
				case out <- d:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
