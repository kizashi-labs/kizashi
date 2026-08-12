//go:build linux && ebpf && prevention

package linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "ebpf prevention" -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" CredAccessLSM ../../../ebpf/credaccess_lsm.bpf.c

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// CredAccessEvent is one cross-process ptrace/memory access observed by the
// ptrace_access_check LSM hook — a process attempting to read another process's
// memory (gdb -p, /proc/<pid>/mem, process_vm_readv). It maps to a
// credential_access telemetry event (T1003 / T1055).
type CredAccessEvent struct {
	TracerPID  uint32
	TracerUID  uint32
	TargetPID  uint32
	Mode       uint32
	TracerComm string
	TargetComm string
}

// CredAccessRunner loads the ptrace_access_check LSM (audit-only) and streams
// cross-process memory accesses. Mirrors TamperRunner. Build/run only with
// `-tags "ebpf prevention"` on an lsm=bpf host.
type CredAccessRunner struct {
	objs *CredAccessLSMObjects
	lk   link.Link
	rd   *ringbuf.Reader
}

// NewCredAccessRunner returns an unstarted runner.
func NewCredAccessRunner() *CredAccessRunner { return &CredAccessRunner{} }

// Start loads the eBPF LSM objects, attaches to ptrace_access_check, and opens
// the ring buffer. Returns an error on hosts without BPF LSM (caller falls back
// to no credential-access telemetry).
func (c *CredAccessRunner) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &CredAccessLSMObjects{}
	if err := LoadCredAccessLSMObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF credaccess objects: %w", err)
	}
	lk, err := link.AttachLSM(link.LSMOptions{Program: objs.CheckPtrace})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach lsm/ptrace_access_check: %w", err)
	}
	rd, err := ringbuf.NewReader(objs.CredaccessEvents)
	if err != nil {
		lk.Close()
		objs.Close()
		return fmt.Errorf("open ring buffer: %w", err)
	}
	c.objs = objs
	c.lk = lk
	c.rd = rd
	return nil
}

// Run streams credential-access events to out until ctx is cancelled.
func (c *CredAccessRunner) Run(ctx context.Context, out chan<- CredAccessEvent) {
	go func() {
		<-ctx.Done()
		c.rd.Close()
	}()
	for {
		record, err := c.rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		ev, ok := parseCredAccessEvent(record.RawSample)
		if !ok {
			continue
		}
		// Drop benign /proc readers (ps, runc, landscape-sysinfo, …) at the source:
		// they trip ptrace_access_check with no real credential theft and, on a
		// container host, are the single largest event source.
		if isBenignCredTracer(ev.TracerComm) {
			credNoiseFiltered.Add(1)
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// Close detaches the LSM program and releases resources.
func (c *CredAccessRunner) Close() {
	if c.rd != nil {
		c.rd.Close()
	}
	if c.lk != nil {
		c.lk.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
}

// parseCredAccessEvent decodes the C struct credaccess_event. Offsets mirror
// credaccess_lsm.bpf.c (4-byte aligned):
//
//	tracer_pid[0:4] tracer_uid[4:8] target_pid[8:12] mode[12:16]
//	tracer_comm[16:32] target_comm[32:48]
func parseCredAccessEvent(raw []byte) (CredAccessEvent, bool) {
	const minLen = 48
	if len(raw) < minLen {
		return CredAccessEvent{}, false
	}
	return CredAccessEvent{
		TracerPID:  binary.NativeEndian.Uint32(raw[0:4]),
		TracerUID:  binary.NativeEndian.Uint32(raw[4:8]),
		TargetPID:  binary.NativeEndian.Uint32(raw[8:12]),
		Mode:       binary.NativeEndian.Uint32(raw[12:16]),
		TracerComm: nullTerminated(raw[16:32]),
		TargetComm: nullTerminated(raw[32:minLen]),
	}, true
}
