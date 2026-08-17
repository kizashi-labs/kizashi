//go:build linux && ebpf

// Linux shared-object (.so) load monitor via an eBPF uprobe on dlopen — the
// Linux counterpart to the Windows image_load ETW collector (DLL/SO
// side-loading, T1574.006).
//
// This used to sit behind an extra `solib` build tag because the bpf2go objects
// (LibraryMonitor*) had never been generated. Nothing in the repository built
// with that tag, so no shipped agent ever emitted image_load on Linux — the
// event type simply read zero, which is indistinguishable from "nothing
// happened". The generated bindings are committed now (as ProcessMonitor's
// always were), so the plain `-tags ebpf` build carries this collector.
//
// Measured before shipping it (verification EC2, 300s): 14 dlopen calls, 0.05/s,
// ≈4k/day/host — under 2% of the process-event volume on the same host. Volume
// was never the reason this was gated.
//
// What it does and does not see: only dlopen. Libraries resolved by ld.so at
// program start are NOT reported, so this is not equivalent to the Windows ETW
// image_load stream. It covers the runtime-load half of side-loading (plugins,
// PAM/NSS modules, anything an already-running process pulls in).
package linux

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// libcCandidates are the usual C-library locations whose dlopen we uprobe.
var libcCandidates = []string{
	"/lib/x86_64-linux-gnu/libc.so.6",
	"/lib64/libc.so.6",
	"/usr/lib/x86_64-linux-gnu/libc.so.6",
	"/usr/lib64/libc.so.6",
	"/lib/libc.so.6",
}

// ebpfLibraryEvent mirrors struct library_event in library_monitor.bpf.c.
// Field order and sizes must match it exactly — the ring-buffer record is read
// with binary.Read, so a mismatch shifts every field silently.
type ebpfLibraryEvent struct {
	TimestampNs uint64
	Pid         uint32
	Uid         uint32
	Path        [256]byte
	Comm        [16]byte
}

// EBPFLibraryCollector implements collector.ImageLoadCollector on Linux using
// an eBPF uprobe on dlopen.
type EBPFLibraryCollector struct {
	cancel context.CancelFunc
}

func NewEBPFLibraryCollector() *EBPFLibraryCollector { return &EBPFLibraryCollector{} }

func (c *EBPFLibraryCollector) Start(ctx context.Context, out chan<- collector.ImageLoadEvent) error {
	// The `solib` build tag is itself the opt-in; run unconditionally when wired.
	ctx, c.cancel = context.WithCancel(ctx)
	go func() {
		if err := c.run(ctx, out); err != nil {
			// Best-effort: no polling equivalent for dlopen.
			fmt.Println("ebpf library monitor:", err)
		}
	}()
	return nil
}

func (c *EBPFLibraryCollector) run(ctx context.Context, out chan<- collector.ImageLoadEvent) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &LibraryMonitorObjects{}
	if err := LoadLibraryMonitorObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	ex, libc, err := openLibc()
	if err != nil {
		return err
	}
	up, err := ex.Uprobe("dlopen", objs.HandleDlopen, nil)
	if err != nil {
		return fmt.Errorf("attach dlopen uprobe on %s: %w", libc, err)
	}
	defer up.Close()

	rd, err := ringbuf.NewReader(objs.LibEvents)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()
	go func() { <-ctx.Done(); rd.Close() }()

	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		if len(record.RawSample) < int(unsafe.Sizeof(ebpfLibraryEvent{})) {
			continue
		}
		var raw ebpfLibraryEvent
		if err := binary.Read(unsafeReader(record.RawSample), binary.NativeEndian, &raw); err != nil {
			continue
		}
		path := nullTerminated(raw.Path[:])
		if path == "" {
			continue
		}
		// ProcessName is the LOADER (sshd, a service, a shell), read from the BPF
		// side's comm. It used to be soBaseName(path) — the loaded object's own
		// name — which left the "who loaded it" half of side-loading unanswerable.
		// Fall back to the basename only if comm came back empty, so the field is
		// never blank.
		procName := nullTerminated(raw.Comm[:])
		if procName == "" {
			procName = soBaseName(path)
		}
		evt := collector.ImageLoadEvent{
			ID:              uuid.New().String(),
			Timestamp:       time.Unix(0, int64(raw.TimestampNs)),
			ImagePath:       path,
			PID:             raw.Pid,
			ProcessName:     procName,
			SignatureStatus: "unknown", // Linux has no Authenticode; path-based rules apply
		}
		select {
		case out <- evt:
		case <-ctx.Done():
			return nil
		}
	}
}

func (c *EBPFLibraryCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func openLibc() (*link.Executable, string, error) {
	for _, p := range libcCandidates {
		if ex, err := link.OpenExecutable(p); err == nil {
			return ex, p, nil
		}
	}
	return nil, "", fmt.Errorf("no libc found among %v", libcCandidates)
}

func soBaseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
