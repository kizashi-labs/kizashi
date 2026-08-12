//go:build linux && ebpf

package linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags ebpf -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" FilelessMonitor ../../../ebpf/fileless_monitor.bpf.c

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FilelessEvent is one fileless-execution signal from the tracepoint sensor.
// Kind: 1 = memfd_create (staging), 2 = execveat(AT_EMPTY_PATH) (fileless exec).
type FilelessEvent struct {
	PID  uint32
	Kind uint32
	Comm string
}

// FilelessRunner loads fileless_monitor.bpf.c and streams fileless-execution
// signals (memfd_create + execveat AT_EMPTY_PATH). Report-only — it attaches
// tracepoints only, with no LSM hook and no way to deny a syscall, so it belongs
// in the standard `-tags ebpf` build alongside ProcessMonitor/NetworkMonitor
// rather than the enforcement-gated `prevention` tier.
type FilelessRunner struct {
	objs *FilelessMonitorObjects
	lk1  link.Link
	lk2  link.Link
	rd   *ringbuf.Reader
}

// NewFilelessRunner returns an unstarted runner.
func NewFilelessRunner() *FilelessRunner { return &FilelessRunner{} }

// Start loads the eBPF objects and attaches the execveat + memfd_create
// tracepoints. Returns an error on kernels without the tracepoints (caller falls
// back to no fileless telemetry).
func (r *FilelessRunner) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &FilelessMonitorObjects{}
	if err := LoadFilelessMonitorObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF fileless objects: %w", err)
	}
	lk1, err := link.Tracepoint("syscalls", "sys_enter_execveat", objs.HandleExecveat, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach execveat tracepoint: %w", err)
	}
	lk2, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", objs.HandleMemfd, nil)
	if err != nil {
		lk1.Close()
		objs.Close()
		return fmt.Errorf("attach memfd_create tracepoint: %w", err)
	}
	rd, err := ringbuf.NewReader(objs.FilelessEvents)
	if err != nil {
		lk1.Close()
		lk2.Close()
		objs.Close()
		return fmt.Errorf("open ring buffer: %w", err)
	}
	r.objs = objs
	r.lk1 = lk1
	r.lk2 = lk2
	r.rd = rd
	return nil
}

// Run streams events to out until ctx is cancelled.
func (r *FilelessRunner) Run(ctx context.Context, out chan<- FilelessEvent) {
	go func() {
		<-ctx.Done()
		r.rd.Close()
	}()
	for {
		record, err := r.rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		ev, ok := parseFilelessEvent(record.RawSample)
		if !ok {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// Close detaches the tracepoints and releases resources.
func (r *FilelessRunner) Close() {
	if r.rd != nil {
		r.rd.Close()
	}
	if r.lk1 != nil {
		r.lk1.Close()
	}
	if r.lk2 != nil {
		r.lk2.Close()
	}
	if r.objs != nil {
		r.objs.Close()
	}
}

// parseFilelessEvent decodes struct fileless_event (24 bytes packed):
//
//	pid[0:4] kind[4:8] comm[8:24]
func parseFilelessEvent(raw []byte) (FilelessEvent, bool) {
	const minLen = 24
	if len(raw) < minLen {
		return FilelessEvent{}, false
	}
	return FilelessEvent{
		PID:  binary.NativeEndian.Uint32(raw[0:4]),
		Kind: binary.NativeEndian.Uint32(raw[4:8]),
		Comm: nullTerminated(raw[8:minLen]),
	}, true
}
