//go:build linux && ebpf

package linux

// file_ebpf_collector.go — eBPF-backed file collector.
//
// The inotify collector (file_collector.go) reports file changes but CANNOT name the
// acting process — inotify carries no pid/comm. That leaves every file event with an
// empty process_name/pid, which makes the server-side ransomware mass-modification
// detector (FileBurstScorer, keyed per process) inert on Linux. This collector loads
// file_monitor.bpf.c instead: its ring-buffer events carry the acting pid AND comm, so
// FileEvents finally arrive attributed and the ransomware behavior detection works on
// real telemetry. If the eBPF program cannot load/attach (older kernel, no BTF), it
// transparently falls back to the inotify collector so file monitoring is never lost.
//
// Built/run only with `-tags ebpf`. High-volume note: the openat tracepoint fires for
// every file open system-wide; events are filtered in userspace to the configured
// monitored paths before emission to bound downstream load.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/telemetry"
)

// File actions — mirror the FILE_* constants in ebpf/file_monitor.bpf.c.
const (
	fileActOpen   = 1
	fileActCreate = 2
	fileActWrite  = 3
	fileActDelete = 4
	fileActRename = 5
)

// rawFileEvent mirrors `struct file_event` in ebpf/file_monitor.bpf.c byte-for-byte
// (built with -D__TARGET_ARCH_x86, little-endian). Field order and the explicit pad
// MUST match the C struct or binary.Read will misparse.
type rawFileEvent struct {
	TimestampNs uint64
	PID         uint32
	UID         uint32
	Action      uint8
	_           [3]uint8
	Comm        [16]byte
	Path        [256]byte
	OldPath     [256]byte
	Ret         int32
	Flags       int32
	Mode        int32
}

// EBPFFileCollector implements collector.FileCollector using the file_monitor eBPF
// program (openat tracepoints + vfs_unlink/vfs_rename kprobes). It carries the acting
// process (pid + comm), unlike the inotify collector.
type EBPFFileCollector struct {
	mu        sync.Mutex
	monitored []string
	excluded  []string

	objs  *FileMonitorObjects
	links []link.Link
	rd    *ringbuf.Reader

	// dropped counts events this collector could not hand to the pipeline. See
	// the EmitFile call below for why the send is not a bare channel write.
	dropped atomic.Uint64

	fallback collector.FileCollector // inotify, used only if the eBPF load fails
}

// NewEBPFFileCollector returns an unstarted eBPF file collector.
func NewEBPFFileCollector() *EBPFFileCollector { return &EBPFFileCollector{} }

// SetPaths records the monitored/excluded roots used to filter events in userspace.
func (c *EBPFFileCollector) SetPaths(monitored, excluded []string) {
	c.mu.Lock()
	c.monitored, c.excluded = monitored, excluded
	fb := c.fallback
	c.mu.Unlock()
	if fb != nil {
		fb.SetPaths(monitored, excluded)
	}
}

// Start loads and attaches the eBPF program and streams attributed FileEvents to out.
// On any load/attach failure it falls back to the inotify collector so file monitoring
// continues (degraded — without process attribution).
func (c *EBPFFileCollector) Start(ctx context.Context, out chan<- collector.FileEvent) error {
	if err := c.startEBPF(ctx, out); err != nil {
		// Record the degradation BEFORE starting the fallback: this sensor is the
		// one that was silently dead on 2026-08-03, and it was invisible to the
		// fleet precisely because it never registered a mode. An unregistered
		// sensor cannot make telemetry.Aggregate() pessimistic, so the endpoint
		// kept reporting "ebpf" while its file events carried no process at all.
		degradeToPolling(telemetrySensorFile, err,
			"ファイルイベントに pid/プロセス名が付かず、ランサムウェア検知がプロセスを特定できません")
		slog.Warn("[file_monitor] eBPF ファイル監視の起動に失敗、inotify にフォールバックします（プロセス帰属なし）", "error", err)
		fb := NewInotifyFileCollector()
		c.mu.Lock()
		fb.SetPaths(c.monitored, c.excluded)
		c.fallback = fb
		c.mu.Unlock()
		return fb.Start(ctx, out)
	}
	telemetry.Set(telemetrySensorFile, telemetry.ModeEBPF, "")
	slog.Info("[file_monitor] eBPF ファイル監視を起動しました（pid/プロセス名を付与）")
	return nil
}

func (c *EBPFFileCollector) startEBPF(ctx context.Context, out chan<- collector.FileEvent) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	objs := &FileMonitorObjects{}
	if err := LoadFileMonitorObjects(objs, nil); err != nil {
		return err
	}
	var links []link.Link
	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenatEnter, nil)
	if err != nil {
		objs.Close()
		return err
	}
	links = append(links, tpEnter)
	tpExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleOpenatExit, nil)
	if err != nil {
		closeLinks(links)
		objs.Close()
		return err
	}
	links = append(links, tpExit)
	// kprobes are best-effort — a kernel missing them still yields openat writes.
	if kp, err := link.Kprobe("vfs_unlink", objs.HandleVfsUnlink, nil); err == nil {
		links = append(links, kp)
	}
	if kp, err := link.Kprobe("vfs_rename", objs.HandleVfsRename, nil); err == nil {
		links = append(links, kp)
	}
	rd, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		closeLinks(links)
		objs.Close()
		return err
	}
	c.objs, c.links, c.rd = objs, links, rd
	go c.run(ctx, out)
	return nil
}

func (c *EBPFFileCollector) run(ctx context.Context, out chan<- collector.FileEvent) {
	go func() { <-ctx.Done(); c.rd.Close() }()
	want := binary.Size(rawFileEvent{})
	for {
		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(rec.RawSample) < want {
			continue
		}
		var e rawFileEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		action := fileActionString(e.Action)
		if action == "" {
			continue // FILE_OPEN (a read/open) — not a change, must not count
		}
		path := cString(e.Path[:])
		if path == "" || isRuntimeNoisePath(path) || !c.pathAllowed(path) {
			continue
		}
		// ID and Timestamp are REQUIRED, not cosmetic: ingestion derives the
		// JetStream dedup message-ID from the event ID (eventMsgID), falling back to
		// agent+type+timestamp-second+batch-index when the ID is empty. A burst of
		// events emitted in the same second with no ID therefore collapses to one
		// message-ID and JetStream (Duplicates: 5m) silently drops all but the first
		// — the rows still land in the DB (event_id defaults to a fresh uuid), so the
		// loss is invisible there while the detection engine sees a single event.
		// That is exactly what made a 70-file ransomware burst fail to fire.
		evt := collector.FileEvent{
			ID:          uuid.New().String(),
			Timestamp:   time.Now(),
			Path:        path,
			OldPath:     cString(e.OldPath[:]),
			Action:      action,
			PID:         e.PID,
			ProcessName: cString(e.Comm[:]),
		}
		// Hand off through EmitFile rather than writing to the channel directly.
		//
		// Two things were wrong with the bare `select { case out <- evt: ... }`
		// this replaces. First, a full channel blocked the ring-buffer reader
		// until a consumer drained it — and the moment the queue backs up is
		// exactly a file-operation burst, which is what the T1486 detector needs;
		// stalling here lets the kernel ring buffer overflow and lose events with
		// no record that anything was lost. EmitFile bounds the wait and COUNTS
		// what it could not deliver.
		//
		// Second, the per-action tallies live in EmitFile. `-tags ebpf` selects
		// THIS collector (file_collector_select_ebpf.go), so every production
		// Linux endpoint took a path the instrumentation did not cover: the
		// counters stayed empty and the periodic [file-stats] line never printed,
		// which is precisely the "does this sensor ever emit a delete?" question
		// they exist to answer.
		collector.EmitFile(ctx, out, evt, &c.dropped)
		if ctx.Err() != nil {
			return
		}
	}
}

// pathAllowed keeps only events under a monitored root (and not under an excluded
// one). With no monitored roots configured it falls back to defaultMonitoredRoots —
// the same scope the inotify collector watches — rather than allowing everything.
// That fallback is essential, not cosmetic: inotify only ever reports paths it holds
// a watch on, whereas this collector receives EVERY write-open on the host, so an
// allow-all default would silently widen file monitoring to service data directories
// (container, database and broker state) and flood the pipeline with churn.
func (c *EBPFFileCollector) pathAllowed(path string) bool {
	c.mu.Lock()
	mon, exc := c.monitored, c.excluded
	c.mu.Unlock()
	for _, e := range exc {
		if e != "" && strings.HasPrefix(path, e) {
			return false
		}
	}
	if len(mon) == 0 {
		mon = defaultMonitoredRoots
	}
	for _, m := range mon {
		if m != "" && strings.HasPrefix(path, m) {
			return true
		}
	}
	return false
}

// Stop detaches the eBPF program (or stops the inotify fallback).
func (c *EBPFFileCollector) Stop() error {
	if c.fallback != nil {
		return c.fallback.Stop()
	}
	if c.rd != nil {
		c.rd.Close()
	}
	closeLinks(c.links)
	if c.objs != nil {
		c.objs.Close()
	}
	return nil
}

func closeLinks(ls []link.Link) {
	for _, l := range ls {
		if l != nil {
			l.Close()
		}
	}
}

// fileActionString maps the eBPF FILE_* action to the collector's action vocabulary
// (identical to the inotify collector: modify/create/delete/rename). Returns "" for
// FILE_OPEN so a plain open/read never counts as a change.
func fileActionString(a uint8) string {
	switch a {
	case fileActWrite:
		return "modify"
	case fileActCreate:
		return "create"
	case fileActDelete:
		return "delete"
	case fileActRename:
		return "rename"
	default:
		return ""
	}
}

// cString reads a NUL-terminated C string out of a fixed-size byte field.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

var _ = fileActOpen // documented constant; open events are intentionally dropped
