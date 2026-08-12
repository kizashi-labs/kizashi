//go:build linux && ebpf && prevention

package linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "ebpf prevention" -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" TamperLSM ../../../ebpf/tamper_lsm.bpf.c

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// TamperDecision is one agent-kill attempt observed by the task_kill LSM hook.
type TamperDecision struct {
	TargetPID  uint32 // the protected (agent) tgid
	SenderPID  uint32
	SenderUID  uint32
	Sig        int32
	Enforced   bool // true = the signal was denied (-EPERM); false = audit-only
	SenderComm string
}

// TamperRunner loads the agent self-protection LSM (task_kill) and reports/denies
// attempts to kill protected PIDs. Mirrors PreventionRunner. Build/run only with
// `-tags "ebpf prevention"` on an lsm=bpf host.
type TamperRunner struct {
	objs *TamperLSMObjects
	lk   link.Link
	rd   *ringbuf.Reader
}

// NewTamperRunner returns an unstarted runner.
func NewTamperRunner() *TamperRunner { return &TamperRunner{} }

// Start loads the eBPF LSM objects, attaches to task_kill, and opens the ring
// buffer. Returns an error on hosts without BPF LSM (caller falls back to
// observe — no tamper protection).
func (t *TamperRunner) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &TamperLSMObjects{}
	if err := LoadTamperLSMObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF tamper objects: %w", err)
	}
	lk, err := link.AttachLSM(link.LSMOptions{Program: objs.CheckKill})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach lsm/task_kill: %w", err)
	}
	rd, err := ringbuf.NewReader(objs.TamperEvents)
	if err != nil {
		lk.Close()
		objs.Close()
		return fmt.Errorf("open ring buffer: %w", err)
	}
	t.objs = objs
	t.lk = lk
	t.rd = rd
	return nil
}

// SetEnforce switches between audit (false: report only) and enforce (true: deny
// kills to enforce-eligible protected PIDs with -EPERM). Fail-open default false.
func (t *TamperRunner) SetEnforce(enforce bool) error {
	v := uint8(0)
	if enforce {
		v = 1
	}
	return t.objs.TamperConfig.Put(uint32(0), v)
}

// ProtectPID registers a tgid to protect with the given mode (PathModeAudit or
// PathModeEnforce).
func (t *TamperRunner) ProtectPID(tgid uint32, mode uint8) error {
	return t.objs.ProtectedPids.Put(tgid, mode)
}

// SetDisarm toggles the disarm flag (tamper_config index 1). When disarmed,
// kills to protected PIDs are reported but ALLOWED even under enforce — the
// escape hatch for legitimate stop/update/uninstall (avoids self-lock).
func (t *TamperRunner) SetDisarm(disarm bool) error {
	v := uint8(0)
	if disarm {
		v = 1
	}
	return t.objs.TamperConfig.Put(uint32(1), v)
}

// Run streams tamper decisions to out until ctx is cancelled.
func (t *TamperRunner) Run(ctx context.Context, out chan<- TamperDecision) {
	go func() {
		<-ctx.Done()
		t.rd.Close()
	}()
	for {
		record, err := t.rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		dec, ok := parseTamperEvent(record.RawSample)
		if !ok {
			continue
		}
		select {
		case out <- dec:
		case <-ctx.Done():
			return
		}
	}
}

// Close detaches the LSM program and releases resources.
func (t *TamperRunner) Close() {
	if t.rd != nil {
		t.rd.Close()
	}
	if t.lk != nil {
		t.lk.Close()
	}
	if t.objs != nil {
		t.objs.Close()
	}
}

// parseTamperEvent decodes the C struct tamper_event. Offsets mirror
// tamper_lsm.bpf.c (4-byte aligned):
//
//	target[0:4] sender[4:8] uid[8:12] sig[12:16] enforced[16] pad[17:20] comm[20:36]
func parseTamperEvent(raw []byte) (TamperDecision, bool) {
	const minLen = 36
	if len(raw) < minLen {
		return TamperDecision{}, false
	}
	return TamperDecision{
		TargetPID:  binary.NativeEndian.Uint32(raw[0:4]),
		SenderPID:  binary.NativeEndian.Uint32(raw[4:8]),
		SenderUID:  binary.NativeEndian.Uint32(raw[8:12]),
		Sig:        int32(binary.NativeEndian.Uint32(raw[12:16])),
		Enforced:   raw[16] != 0,
		SenderComm: nullTerminated(raw[20:minLen]),
	}, true
}
