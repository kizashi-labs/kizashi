//go:build windows

package windows

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	etw "github.com/0xrawsec/golang-etw/etw"
	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

const (
	// kernelProcessGUID is the Microsoft-Windows-Kernel-Process (manifest) ETW
	// provider. Still used by the image-load collector. The process collector
	// itself now uses the NT Kernel Logger (see startETW), because the manifest
	// ProcessStart event does NOT carry CommandLine — its absence forced a
	// post-hoc OpenProcess/PEB read that races (and loses) for short-lived
	// processes.
	kernelProcessGUID = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"

	// NT Kernel Logger Process events are MOF/classic: the opcode (not an
	// EventID) distinguishes start from end. Its ProcessStart carries the
	// CommandLine captured in-kernel at creation, so it is present even for
	// very short-lived processes.
	kpOpcodeStart = 1
	kpOpcodeEnd   = 2
)

// reestablishBackoff is how long the kernel-session supervisor waits before
// re-opening the NT Kernel Logger after it was stopped out from under us.
const reestablishBackoff = 5 * time.Second

// ETWProcessCollector implements ProcessCollector using ETW on Windows.
type ETWProcessCollector struct {
	cancel context.CancelFunc
	out    chan<- collector.ProcessEvent

	mu          sync.Mutex // guards etwSession/etwConsumer (supervisor vs teardown)
	etwSession  *etw.RealTimeSession
	etwConsumer *etw.Consumer
}

func NewETWProcessCollector() *ETWProcessCollector {
	return &ETWProcessCollector{}
}

func (c *ETWProcessCollector) Start(ctx context.Context, out chan<- collector.ProcessEvent) error {
	c.out = out
	ctx, c.cancel = context.WithCancel(ctx)

	// readCommandLine reads each process's PEB via OpenProcess(PROCESS_VM_READ);
	// SeDebugPrivilege is required to open processes owned by other users, else
	// CommandLine comes back empty for them. Enable it once before enrichment.
	EnableSeDebugPrivilege()

	// Real-time ETW (NT Kernel Logger) captures every process start/stop with no
	// polling gaps and the parent PID + in-kernel CommandLine (present even for
	// very short-lived processes the polling collector misses). It attempts to
	// start by DEFAULT and falls back to polling automatically on any failure
	// (non-admin, session error), so the default is safe on every endpoint. Set
	// EDR_AGENT_ETW_PROCESS=0 to force the legacy polling path.
	if etwProcessEnabled() {
		if err := c.startETW(ctx); err != nil {
			slog.Warn("ETWプロセス監視を開始できませんでした。ポーリングにフォールバックします", "error", err)
		} else {
			slog.Info("ETWプロセス監視を開始しました (NT Kernel Logger)")
			return nil
		}
	}
	go c.pollProcessEvents(ctx)
	return nil
}

// etwEnabled reports whether the OPT-IN ETW sensors (registry, image-load,
// script, remote-thread, named-pipe, PS-module) are enabled. These remain
// opt-in via EDR_AGENT_ETW: unlike the process collector, the ETW registry
// collector degrades to a no-op (not the mature RegNotify path) if its session
// can't start, so it stays gated to avoid regressing non-admin endpoints.
func etwEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EDR_AGENT_ETW"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// etwProcessEnabled reports whether the real-time ETW process collector should
// attempt to start. It defaults ON (opt-OUT) because startETW falls back to
// polling automatically on any failure, so ETW is a safe default that only
// upgrades visibility (real-time, gap-free, PPID + in-kernel CommandLine). Set
// EDR_AGENT_ETW_PROCESS to 0/false/no/off to force the legacy polling path.
func etwProcessEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EDR_AGENT_ETW_PROCESS"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// ETWProcessEnabled reports whether the opt-in ETW sensors are enabled. It gates
// the registry collector's wiring (and mirrors etwEnabled); the process
// collector no longer depends on it (it defaults to ETW — see etwProcessEnabled).
func ETWProcessEnabled() bool { return etwEnabled() }

// etwSensorsEnabled reports whether the ADDITIVE ETW sensors — remote-thread
// injection, image-load/DLL side-loading, PowerShell ScriptBlock, PowerShell
// Module-logging, and named-pipe creation — should start. Unlike the registry
// collector (which would REPLACE the mature RegNotify path) and the
// auth/dns/network ETW transports (which swap an already-working collector),
// these five are PURELY ADDITIVE: each is the only sensor for its technique
// (T1055, T1574.001/.002, T1059.001, and Cobalt-Strike named-pipe C2), and each
// degrades to a no-op if its ETW session can't start (e.g. non-admin), so there
// is no path to regress. They therefore default ON (opt-OUT) to close a large
// default-coverage gap that previously required EDR_AGENT_ETW=1. Set
// EDR_AGENT_ETW_SENSORS to 0/false/no/off to disable them; the broader
// EDR_AGENT_ETW=1 still force-enables everything (including registry/transport).
func etwSensorsEnabled() bool {
	if etwEnabled() {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EDR_AGENT_ETW_SENSORS"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// enrichProcessFromHandle fills CommandLine, Username, file hashes and (if the
// ETW event lacked it) the image path for a live process by opening a handle.
// Best-effort: a process that already exited is left with only its event-derived
// fields. Mirrors the polling collector's per-process enrichment so process
// telemetry under ETW is a superset of polling (same fields + real-time + PPID).
func enrichProcessFromHandle(evt *collector.ProcessEvent) {
	// PROCESS_VM_READ is required for readCommandLine to read the PEB. Fall back to
	// limited rights (image/user/hashes only, no command line) for protected
	// processes where VM_READ is denied — matching the polling collector.
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, evt.PID)
	if err != nil {
		handle, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, evt.PID)
		if err != nil {
			return
		}
	}
	defer windows.CloseHandle(handle)

	// Resolve the full image path from the live process. The NT Kernel Logger
	// reports ImageFileName as a bare basename ("proc.exe") for many processes,
	// and a bare basename resolves against the agent service's CWD (System32) when
	// read from disk — so file-based enrichment (hashes, PE VERSIONINFO) silently
	// fails for any binary OUTSIDE System32, exactly the renamed-binary / LOLBin
	// case in user/temp dirs that PE version info is meant to catch (verified on a
	// live box 2026-07-02: System32 procs got OriginalFileName, a renamed exe in
	// C:\Users did not). Upgrade a bare basename to the resolved full path; the
	// server's basename fallback still covers the handle-less short-lived case
	// where ImagePath necessarily stays a basename.
	if evt.ImagePath == "" || !strings.ContainsAny(evt.ImagePath, `\/`) {
		var buf [windows.MAX_PATH]uint16
		size := uint32(windows.MAX_PATH)
		if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err == nil {
			evt.ImagePath = windows.UTF16ToString(buf[:size])
		}
	}
	if evt.CommandLine == "" {
		evt.CommandLine = readCommandLine(handle)
	}
	if evt.Username == "" || evt.IntegrityLevel == "" || evt.LogonID == "" {
		var token windows.Token
		if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err == nil {
			defer token.Close()
			if evt.Username == "" {
				if user, err := token.GetTokenUser(); err == nil {
					if account, domain, _, err := user.User.Sid.LookupAccount(""); err == nil {
						evt.Username = domain + "\\" + account
					}
				}
			}
			if evt.IntegrityLevel == "" {
				evt.IntegrityLevel = tokenIntegrityLevel(token)
			}
			if evt.LogonID == "" {
				evt.LogonID = tokenLogonID(token)
			}
		}
	}
	if evt.ImagePath != "" {
		evt.Hashes = computeHashes(evt.ImagePath)
	}
	if evt.ProcessName == "" {
		evt.ProcessName = filepath_base(evt.ImagePath)
	}
}

// imagePathFromCommandLine extracts argv[0] (the image path) from a Windows
// command line. The NT Kernel Logger captures CommandLine in-kernel at process
// creation, and its argv[0] is the full image path — a race-free source when the
// event's ImageFileName is only a basename and the process handle can't be queried
// for the full path. Returns "" unless argv[0] looks like a real path (contains a
// separator), so a bare "proc.exe arg" command line is not mistaken for a path.
func imagePathFromCommandLine(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	var path string
	if cmd[0] == '"' {
		if end := strings.IndexByte(cmd[1:], '"'); end >= 0 {
			path = cmd[1 : 1+end]
		} else {
			return "" // unbalanced quote
		}
	} else if sp := strings.IndexByte(cmd, ' '); sp >= 0 {
		path = cmd[:sp]
	} else {
		path = cmd
	}
	if !strings.ContainsAny(path, `\/`) {
		return "" // bare basename, not a resolvable path
	}
	return path
}

// startETW opens the NT Kernel Logger with the PROCESS flag and streams its
// ProcessStart/End events. Unlike Microsoft-Windows-Kernel-Process (manifest),
// the kernel logger's ProcessStart event carries the full CommandLine captured
// in-kernel at creation — so even a process that exits microseconds later still
// reports its command line (no OpenProcess/PEB race). Any failure is returned
// so the caller can fall back to polling.
//
// The kernel logger is a singleton "NT Kernel Logger" session; the library's
// Start() transparently stops a pre-existing one. Network/DNS/image-load
// collectors use separate manifest-provider sessions, so they do not conflict.
func (c *ETWProcessCollector) startETW(ctx context.Context) error {
	// Establish synchronously so the caller can fall back to polling if ETW is
	// unavailable on this host (the first failure is returned).
	if err := c.establishKernelSession(ctx); err != nil {
		return err
	}
	// Supervise: the NT Kernel Logger is a singleton, so any other tool that
	// opens it (a diagnostic harness, another agent) transparently stops OUR
	// session and the ProcessTrace loop returns. Without recovery this
	// permanently silences process telemetry — observed 2026-06-25 when
	// etw-verify's kernel session stopped the production agent's, leaving only
	// file events flowing until a manual service restart. Re-establish until Stop.
	GoSupervised(func() { c.superviseKernelSession(ctx) })
	return nil
}

// establishKernelSession opens the NT Kernel Logger (PROCESS flag) and starts a
// consumer feeding handleKernelProcessEvent. On success the session/consumer are
// stored under mu for the supervisor and teardown to manage.
func (c *ETWProcessCollector) establishKernelSession(ctx context.Context) error {
	session := etw.NewKernelRealTimeSession(etw.EVENT_TRACE_FLAG_PROCESS)
	if err := session.Start(); err != nil {
		return fmt.Errorf("start kernel logger (process): %w", err)
	}

	consumer := etw.NewRealTimeConsumer(ctx).FromSessions(session)
	consumer.EventCallback = func(e *etw.Event) error {
		c.handleKernelProcessEvent(e)
		return nil
	}
	if err := consumer.Start(); err != nil {
		_ = session.Stop()
		return fmt.Errorf("start consumer: %w", err)
	}

	c.mu.Lock()
	c.etwSession = session
	c.etwConsumer = consumer
	c.mu.Unlock()
	return nil
}

// superviseKernelSession keeps the kernel-logger session alive for the life of
// ctx. consumer.Wait() (the embedded WaitGroup) unblocks when ProcessTrace
// returns — i.e. the session was stopped, whether by our own Stop() or by an
// external takeover of the singleton kernel logger. On an unexpected stop it
// re-establishes after a short backoff; on ctx cancel it tears down and exits.
func (c *ETWProcessCollector) superviseKernelSession(ctx context.Context) {
	for {
		c.mu.Lock()
		consumer := c.etwConsumer
		c.mu.Unlock()

		// No live consumer (a prior re-establish failed) — retry with backoff.
		if consumer == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(reestablishBackoff):
			}
			if err := c.establishKernelSession(ctx); err != nil {
				slog.Warn("ETWプロセスセッションの再確立に失敗しました。リトライします", "error", err)
			}
			continue
		}

		traceEnded := make(chan struct{})
		go func() { consumer.Wait(); close(traceEnded) }()

		select {
		case <-ctx.Done():
			c.teardownETW()
			return
		case <-traceEnded:
			if ctx.Err() != nil {
				c.teardownETW()
				return
			}
			// Unexpected stop. teardownETW clears etwConsumer so the next loop
			// iteration re-establishes via the consumer==nil branch.
			slog.Warn("ETWプロセスセッションが外部要因で停止しました。再確立します")
			c.teardownETW()
		}
	}
}

// teardownETW stops and clears the current session/consumer. Idempotent and safe
// to call on an already-stopped session (errors are ignored).
func (c *ETWProcessCollector) teardownETW() {
	c.mu.Lock()
	consumer, session := c.etwConsumer, c.etwSession
	c.etwSession, c.etwConsumer = nil, nil
	c.mu.Unlock()

	if consumer != nil {
		_ = consumer.Stop()
	}
	if session != nil {
		_ = session.Stop()
	}
}

// kpPropDumpOnce logs the property keys of the first ProcessStart event so the
// MOF field mapping below can be confirmed against the live kernel schema.
var kpPropDumpOnce sync.Once

// handleKernelProcessEvent converts an NT Kernel Logger Process event (MOF)
// into a ProcessEvent. The event is keyed by opcode (start/end), and its
// ProcessStart carries CommandLine directly — so unlike the manifest provider
// the command line is present without any OpenProcess/PEB read, even for
// short-lived processes. Enrichment is still used to add Username and file
// hashes (and to backfill any field the event lacked) for live processes.
func (c *ETWProcessCollector) handleKernelProcessEvent(e *etw.Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("ETWイベント処理でパニックを回復しました", "panic", r)
		}
	}()

	switch e.System.Opcode.Value {
	case kpOpcodeStart:
		kpPropDumpOnce.Do(func() {
			keys := make([]string, 0, len(e.EventData))
			for k := range e.EventData {
				keys = append(keys, k)
			}
			slog.Info("[kernel-process] ProcessStart プロパティ確認", "keys", strings.Join(keys, ","))
		})

		evt := collector.ProcessEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			PID:       kpUint32(e, "ProcessId"),
			PPID:      kpUint32(e, "ParentId"),
			Action:    "create",
		}
		if img, ok := e.GetPropertyString("ImageFileName"); ok && img != "" {
			evt.ImagePath = img
			evt.ProcessName = filepath_base(img)
		}
		if cl, ok := e.GetPropertyString("CommandLine"); ok && cl != "" {
			evt.CommandLine = cl // captured in-kernel at creation — no race
		}
		// Enrich Username and file hashes (and backfill ImagePath/CommandLine only
		// if the event lacked them) for live processes. CommandLine already comes
		// from the kernel event, so a short-lived process keeps its command line
		// even when the OpenProcess enrichment below fails because it has exited.
		enrichProcessFromHandle(&evt)
		// Last-resort full-path resolution. The kernel ProcessStart event's
		// ImageFileName is frequently a bare basename, and QueryFullProcessImageName
		// (tried in enrichProcessFromHandle) was observed to fail for freshly-created
		// interactive-session processes even when the handle opened — leaving the
		// image as a basename that resolves against the agent service's CWD
		// (System32), so file-based enrichment silently misses any binary elsewhere
		// (the renamed-binary / LOLBin case in user/temp dirs). The in-kernel
		// CommandLine carries the image full path as argv[0] with no handle/query
		// race, so derive it from there. Verified on a live box 2026-07-02: a renamed
		// notepad in C:\Users got only a basename+empty PE until this fallback.
		if evt.ImagePath == "" || !strings.ContainsAny(evt.ImagePath, `\/`) {
			if p := imagePathFromCommandLine(evt.CommandLine); p != "" {
				evt.ImagePath = p
				if evt.Hashes == (collector.FileHashes{}) {
					evt.Hashes = computeHashes(p)
				}
			}
		}
		// PE VERSIONINFO reads from the image on disk (not the process handle), so
		// it works even for a process that has already exited — as long as the
		// kernel event gave us the image path. Kept out of enrichProcessFromHandle
		// so a failed OpenProcess (protected/exited process) does not skip it.
		enrichVersionInfo(&evt)
		select {
		case c.out <- evt:
		default:
		}
	case kpOpcodeEnd:
		evt := collector.ProcessEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			PID:       kpUint32(e, "ProcessId"),
			Action:    "terminate",
		}
		select {
		case c.out <- evt:
		default:
		}
	}
}

// kpUint32 reads a numeric MOF property as uint32 (0 if absent/unparseable).
func kpUint32(e *etw.Event, name string) uint32 {
	s, ok := e.GetPropertyString(name)
	if !ok {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// pollProcessEvents uses Windows Management Instrumentation (WMI) to
// monitor process creation/termination events. This is a fallback for
// environments where ETW session creation requires elevated privileges.
func (c *ETWProcessCollector) pollProcessEvents(ctx context.Context) {
	// Track known PIDs to detect new processes
	known := make(map[uint32]bool)

	// Seed with current processes
	procs, _ := enumProcesses()
	for _, pid := range procs {
		known[pid] = true
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := enumProcesses()
			if err != nil {
				continue
			}

			currentSet := make(map[uint32]bool)
			for _, pid := range current {
				currentSet[pid] = true
				if !known[pid] {
					// New process detected
					if evt, err := buildProcessEvent(pid, "create"); err == nil {
						select {
						case c.out <- evt:
						default:
						}
					}
				}
			}

			for pid := range known {
				if !currentSet[pid] {
					evt := collector.ProcessEvent{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						PID:       pid,
						Action:    "terminate",
					}
					select {
					case c.out <- evt:
					default:
					}
				}
			}

			known = currentSet
		}
	}
}

func (c *ETWProcessCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────

func enumProcesses() ([]uint32, error) {
	var pids [4096]uint32
	var bytesReturned uint32

	ntdll := windows.NewLazySystemDLL("psapi.dll")
	enumProc := ntdll.NewProc("EnumProcesses")

	ret, _, err := enumProc.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)*4),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 {
		return nil, err
	}

	count := bytesReturned / 4
	result := make([]uint32, count)
	copy(result, pids[:count])
	return result, nil
}

func buildProcessEvent(pid uint32, action string) (collector.ProcessEvent, error) {
	evt := collector.ProcessEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		PID:       pid,
		Action:    action,
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return evt, err
	}
	defer windows.CloseHandle(handle)

	// Get image path
	var buf [windows.MAX_PATH]uint16
	size := uint32(windows.MAX_PATH)
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err == nil {
		evt.ImagePath = windows.UTF16ToString(buf[:size])
	}

	// Get username via token
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if user, err := token.GetTokenUser(); err == nil {
			if account, domain, _, err := user.User.Sid.LookupAccount(""); err == nil {
				evt.Username = domain + "\\" + account
			}
		}
	}

	// Compute file hashes
	if evt.ImagePath != "" {
		evt.Hashes = computeHashes(evt.ImagePath)
	}

	evt.ProcessName = filepath_base(evt.ImagePath)
	return evt, nil
}

func computeHashes(path string) collector.FileHashes {
	f, err := os.Open(path)
	if err != nil {
		return collector.FileHashes{}
	}
	defer f.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()

	w := io.MultiWriter(md5h, sha1h, sha256h)
	if _, err := io.Copy(w, f); err != nil {
		return collector.FileHashes{}
	}

	return collector.FileHashes{
		MD5:    fmt.Sprintf("%x", md5h.Sum(nil)),
		SHA1:   fmt.Sprintf("%x", sha1h.Sum(nil)),
		SHA256: fmt.Sprintf("%x", sha256h.Sum(nil)),
	}
}

func filepath_base(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' || path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
