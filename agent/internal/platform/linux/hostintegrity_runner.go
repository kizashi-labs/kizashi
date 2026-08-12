//go:build linux && ebpf && prevention

package linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "ebpf prevention" -cc clang -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" HostIntegrityMonitor ../../../ebpf/hostintegrity_monitor.bpf.c

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// HostIntegrityKind identifies which syscall a HostIntegrityEvent came from.
type HostIntegrityKind uint32

const (
	HostIntegrityInitModule  HostIntegrityKind = 1 // init_module
	HostIntegrityFinitModule HostIntegrityKind = 2 // finit_module
	HostIntegrityUnshare     HostIntegrityKind = 3 // unshare
	HostIntegritySetns       HostIntegrityKind = 4 // setns
	HostIntegrityCapset      HostIntegrityKind = 5 // capset
)

// HostIntegrityEvent is one syscall-level host-integrity signal: kernel module
// load (T1547.006), namespace manipulation (T1611), or capability change
// (T1548.001).
type HostIntegrityEvent struct {
	PID         uint32
	Kind        HostIntegrityKind
	Comm        string
	CommandLine string // best-effort /proc/<pid>/cmdline at signal time, may be empty
}

// HostIntegrityRunner loads hostintegrity_monitor.bpf.c and streams
// init_module/finit_module/unshare/setns/capset signals. Report-only. Mirrors
// the other eBPF runners; build/run only with `-tags "ebpf prevention"`.
type HostIntegrityRunner struct {
	objs  *HostIntegrityMonitorObjects
	links []link.Link
	rd    *ringbuf.Reader
}

// NewHostIntegrityRunner returns an unstarted runner.
func NewHostIntegrityRunner() *HostIntegrityRunner { return &HostIntegrityRunner{} }

// Start loads the eBPF objects and attaches all five tracepoints. Returns an
// error on kernels missing a tracepoint (caller falls back to no host-integrity
// telemetry) — attachment is all-or-nothing so a partial sensor never runs.
func (r *HostIntegrityRunner) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &HostIntegrityMonitorObjects{}
	if err := LoadHostIntegrityMonitorObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF hostintegrity objects: %w", err)
	}

	links := make([]link.Link, 0, 5)
	closeAll := func() {
		for _, lk := range links {
			lk.Close()
		}
		objs.Close()
	}

	lk, err := link.Tracepoint("syscalls", "sys_enter_init_module", objs.HandleInitModule, nil)
	if err != nil {
		closeAll()
		return fmt.Errorf("attach init_module tracepoint: %w", err)
	}
	links = append(links, lk)

	lk, err = link.Tracepoint("syscalls", "sys_enter_finit_module", objs.HandleFinitModule, nil)
	if err != nil {
		closeAll()
		return fmt.Errorf("attach finit_module tracepoint: %w", err)
	}
	links = append(links, lk)

	lk, err = link.Tracepoint("syscalls", "sys_enter_unshare", objs.HandleUnshare, nil)
	if err != nil {
		closeAll()
		return fmt.Errorf("attach unshare tracepoint: %w", err)
	}
	links = append(links, lk)

	lk, err = link.Tracepoint("syscalls", "sys_enter_setns", objs.HandleSetns, nil)
	if err != nil {
		closeAll()
		return fmt.Errorf("attach setns tracepoint: %w", err)
	}
	links = append(links, lk)

	lk, err = link.Tracepoint("syscalls", "sys_enter_capset", objs.HandleCapset, nil)
	if err != nil {
		closeAll()
		return fmt.Errorf("attach capset tracepoint: %w", err)
	}
	links = append(links, lk)

	rd, err := ringbuf.NewReader(objs.HostintegrityEvents)
	if err != nil {
		closeAll()
		return fmt.Errorf("open ring buffer: %w", err)
	}

	r.objs = objs
	r.links = links
	r.rd = rd
	return nil
}

// Run streams events to out until ctx is cancelled. unshare/setns/capset
// signals from known container-runtime processes (runc/containerd-shim/crun/
// conmon — the same source-side allowlist the process/credaccess sensors use)
// are dropped here: those three syscalls are routine on every container
// start/exec, and without this filter they would flood exactly like the
// process-event runtime noise did before PR #470. init_module/finit_module are
// never legitimately called by a container workload, so they are never
// filtered. Surviving events are enriched with a best-effort command line
// before being sent — real triage context even though the syscall itself
// cannot be spoofed by choosing a different CLI wrapper.
func (r *HostIntegrityRunner) Run(ctx context.Context, out chan<- HostIntegrityEvent) {
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
		ev, ok := parseHostIntegrityEvent(record.RawSample)
		if !ok {
			continue
		}
		isNamespaceOrCap := ev.Kind == HostIntegrityUnshare || ev.Kind == HostIntegritySetns || ev.Kind == HostIntegrityCapset
		if isNamespaceOrCap && isRuntimeNoiseProc(ev.Comm) {
			hostIntegrityNoiseFiltered.Add(1)
			continue
		}
		// capset has a benign-caller allowlist: sshd/sudo/ip adjust their own
		// capabilities as designed and, measured live, produced ~90% of capset
		// events on an idle host.
		if ev.Kind == HostIntegrityCapset && isBenignCapsetProc(ev.Comm) {
			hostIntegrityNoiseFiltered.Add(1)
			continue
		}
		// unshare/setns likewise: the container daemons manage namespaces as their
		// core function (dockerd fired every ~30-60s on an idle host). A real
		// container breakout comes from a shell/interpreter/nsenter, not from
		// dockerd itself, so the T1611 signal survives.
		if (ev.Kind == HostIntegrityUnshare || ev.Kind == HostIntegritySetns) && isBenignNamespaceProc(ev.Comm) {
			hostIntegrityNoiseFiltered.Add(1)
			continue
		}
		// Kernel-module loads (T1547.006) are never filtered by process name —
		// nothing routine should be loading a module.
		ev.CommandLine = readProcCmdline(ev.PID, ev.Comm)
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// Close detaches the tracepoints and releases resources.
func (r *HostIntegrityRunner) Close() {
	if r.rd != nil {
		r.rd.Close()
	}
	for _, lk := range r.links {
		lk.Close()
	}
	if r.objs != nil {
		r.objs.Close()
	}
}

// parseHostIntegrityEvent decodes struct hostintegrity_event (24 bytes packed):
//
//	pid[0:4] kind[4:8] comm[8:24]
func parseHostIntegrityEvent(raw []byte) (HostIntegrityEvent, bool) {
	const minLen = 24
	if len(raw) < minLen {
		return HostIntegrityEvent{}, false
	}
	return HostIntegrityEvent{
		PID:  binary.NativeEndian.Uint32(raw[0:4]),
		Kind: HostIntegrityKind(binary.NativeEndian.Uint32(raw[4:8])),
		Comm: nullTerminated(raw[8:minLen]),
	}, true
}
