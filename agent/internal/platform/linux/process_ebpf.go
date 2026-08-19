//go:build linux

package linux

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/telemetry"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// EBPFProcessCollector implements ProcessCollector using eBPF on Linux.
// Falls back to procfs polling on kernels < 5.4.
type EBPFProcessCollector struct {
	cancel  context.CancelFunc
	useEBPF bool
}

func NewEBPFProcessCollector() *EBPFProcessCollector {
	c := &EBPFProcessCollector{}
	c.useEBPF, _ = isEBPFSupported()
	return c
}

func (c *EBPFProcessCollector) Start(ctx context.Context, out chan<- collector.ProcessEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)

	if c.useEBPF {
		return c.startEBPF(ctx, out)
	}
	degradeToPolling(telemetrySensorProcess, errEBPFUnsupported,
		"200ms未満で終了する短命プロセスがスナップショットに現れず、argv/実行を取りこぼします")
	go c.pollProcFS(ctx, out)
	return nil
}

// startEBPF loads and attaches eBPF programs using cilium/ebpf library.
// When built with the "ebpf" tag, it calls LoadAndRunEBPFProcessMonitor via
// the bridge. On error (or when the tag is absent) it falls back to pollProcFS.
func (c *EBPFProcessCollector) startEBPF(ctx context.Context, out chan<- collector.ProcessEvent) error {
	telemetry.Set(telemetrySensorProcess, telemetry.ModeEBPF, "")
	err := runEBPFProcessMonitor(ctx, out)
	if err == nil {
		return nil
	}
	// A cancelled context is an orderly shutdown, not a degradation.
	if ctx.Err() != nil {
		return nil
	}
	// eBPF unavailable or failed to load — degrade, and say so. This used to be
	// silent on the stub build, which is how a dead eBPF consumer could ship
	// unnoticed.
	degradeToPolling(telemetrySensorProcess, err,
		"200ms未満で終了する短命プロセスがスナップショットに現れず、argv/実行を取りこぼします")
	go c.pollProcFS(ctx, out)
	return nil
}

// pollProcFS monitors processes via /proc filesystem.
func (c *EBPFProcessCollector) pollProcFS(ctx context.Context, out chan<- collector.ProcessEvent) {
	known := make(map[uint32]procInfo)

	// Seed existing processes and send initial snapshot
	procs, _ := scanProcFS()
	for pid, info := range procs {
		known[pid] = info // track for terminate detection even if we skip emit
		if isRuntimeNoiseProc(info.comm) || isRuntimeNoiseCmd(info.cmdline) {
			procNoiseFiltered.Add(1)
			continue
		}
		evt := buildLinuxProcessEvent(pid, info, "create")
		if !sendProcEvent(ctx, out, evt) {
			return
		}
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := scanProcFS()
			if err != nil {
				continue
			}

			// New processes
			for pid, info := range current {
				if _, exists := known[pid]; !exists {
					if isRuntimeNoiseProc(info.comm) || isRuntimeNoiseCmd(info.cmdline) {
						procNoiseFiltered.Add(1)
						continue
					}
					evt := buildLinuxProcessEvent(pid, info, "create")
					if !sendProcEvent(ctx, out, evt) {
						return
					}
				}
			}

			// Terminated processes. The terminate event carries no comm, so use the
			// last-known procInfo to drop terminates for runtime-noise processes we
			// never emitted a create for (keeps the pair symmetric).
			for pid, info := range known {
				if _, exists := current[pid]; !exists {
					if isRuntimeNoiseProc(info.comm) || isRuntimeNoiseCmd(info.cmdline) {
						procNoiseFiltered.Add(1)
						continue
					}
					evt := collector.ProcessEvent{
						ID:        uuid.New().String(),
						Timestamp: time.Now(),
						PID:       pid,
						Action:    "terminate",
					}
					if !sendProcEvent(ctx, out, evt) {
						return
					}
				}
			}

			known = current
		}
	}
}

// sendProcEvent delivers a process event with backpressure instead of silently
// dropping it. The previous non-blocking `select { case out <- evt: default: }`
// discarded events whenever the downstream sender was momentarily behind — a
// silent, unmetered loss that put a hidden ceiling on Linux process-telemetry
// (and therefore detection) coverage under bursts. Blocking here matches the
// eBPF fast-path (ebpf_loader.go) and yields to ctx cancellation so shutdown is
// never blocked. Returns false when ctx is done, signalling the caller to stop.
func sendProcEvent(ctx context.Context, out chan<- collector.ProcessEvent, evt collector.ProcessEvent) bool {
	select {
	case out <- evt:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *EBPFProcessCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────

type procInfo struct {
	comm    string
	cmdline string
	exe     string
	ppid    uint32
	uid     uint32
}

func scanProcFS() (map[uint32]procInfo, error) {
	result := make(map[uint32]procInfo)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}

		info := procInfo{}

		// Read comm (process name)
		if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			info.comm = strings.TrimSpace(string(comm))
		}

		// Read cmdline
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			info.cmdline = strings.ReplaceAll(string(cmdline), "\x00", " ")
		}

		// Read exe symlink
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			info.exe = exe
		}

		// Read ppid from status
		if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
			lines := strings.Split(string(status), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PPid:") {
					fmt.Sscanf(strings.TrimPrefix(line, "PPid:"), "%d", &info.ppid)
				}
				if strings.HasPrefix(line, "Uid:") {
					fmt.Sscanf(strings.TrimPrefix(line, "Uid:"), "%d", &info.uid)
				}
			}
		}

		result[pid] = info
	}

	return result, nil
}

func buildLinuxProcessEvent(pid uint32, info procInfo, action string) collector.ProcessEvent {
	evt := collector.ProcessEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		PID:         pid,
		PPID:        info.ppid,
		ProcessName: info.comm,
		CommandLine: info.cmdline,
		ImagePath:   info.exe,
		Action:      action,
	}

	// Resolve username from UID
	evt.Username = resolveUID(info.uid)

	// Compute hashes for executed binary
	if info.exe != "" {
		evt.Hashes = computeLinuxHashes(info.exe)
	}

	// Collect dynamic-linker injection env vars (LD_PRELOAD etc.) for new
	// processes — the basis for T1574.006 detection.
	if action == "create" {
		evt.EnvVars = readProcSuspiciousEnv(pid)
	}

	return evt
}

// suspiciousEnvPrefixes are dynamic-linker / loader injection vectors worth
// surfacing for detection (T1574.006 / T1068). The full environment is NOT
// collected — only these security-relevant variables.
var suspiciousEnvPrefixes = []string{"LD_PRELOAD=", "LD_LIBRARY_PATH=", "LD_AUDIT=", "GCONV_PATH="}

// readProcSuspiciousEnv reads /proc/<pid>/environ (NUL-separated KEY=VALUE) and
// returns only the security-relevant variables. Best-effort: returns nil if the
// process already exited or environ is unreadable.
func readProcSuspiciousEnv(pid uint32) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || len(data) == 0 {
		return nil
	}
	var out []string
	for _, kv := range bytes.Split(data, []byte{0}) {
		s := string(kv)
		for _, p := range suspiciousEnvPrefixes {
			if strings.HasPrefix(s, p) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// passwdCache caches uid→username mappings to avoid reading /etc/passwd on
// every process event (which would trigger inotify access events and false-positive alerts).
var passwdCache struct {
	sync.RWMutex
	entries  map[uint32]string
	loadedAt time.Time
	ttl      time.Duration
}

func resolveUID(uid uint32) string {
	const cacheTTL = 5 * time.Minute

	passwdCache.RLock()
	if passwdCache.entries != nil && time.Since(passwdCache.loadedAt) < cacheTTL {
		if name, ok := passwdCache.entries[uid]; ok {
			passwdCache.RUnlock()
			return name
		}
		passwdCache.RUnlock()
		return fmt.Sprintf("uid:%d", uid)
	}
	passwdCache.RUnlock()

	// Rebuild cache (write lock).
	passwdCache.Lock()
	defer passwdCache.Unlock()

	// Double-checked locking: another goroutine may have refreshed while we waited.
	if passwdCache.entries != nil && time.Since(passwdCache.loadedAt) < cacheTTL {
		if name, ok := passwdCache.entries[uid]; ok {
			return name
		}
		return fmt.Sprintf("uid:%d", uid)
	}

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return fmt.Sprintf("uid:%d", uid)
	}

	newEntries := make(map[uint32]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		var u uint32
		if _, err := fmt.Sscanf(fields[2], "%d", &u); err == nil {
			newEntries[u] = fields[0]
		}
	}
	passwdCache.entries = newEntries
	passwdCache.loadedAt = time.Now()

	if name, ok := newEntries[uid]; ok {
		return name
	}
	return fmt.Sprintf("uid:%d", uid)
}

func computeLinuxHashes(path string) collector.FileHashes {
	const maxSize = 50 * 1024 * 1024
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		// 空のハッシュと「取れなかった」は、イベントに載ると同じ姿です。
		// サーバのハッシュ IOC 照合は、一致しなかったのではなく照合する
		// ものが無かったのに、黙って通ります。Windows 側と同じ形で、
		// **片方だけ直すと、直っていない側が直った顔をします。**
		slog.Debug("ファイルのハッシュを取れませんでした。"+
			"このイベントはハッシュ無しで送られ、ハッシュ IOC には当たりません",
			"path", path, "error", err)
		return collector.FileHashes{}
	}
	defer f.Close()

	h1 := md5.New()
	h2 := sha1.New()
	h3 := sha256.New()
	w := io.MultiWriter(h1, h2, h3)

	if _, err := io.Copy(w, io.LimitReader(f, maxSize)); err != nil {
		// 空のハッシュと「取れなかった」は、イベントに載ると同じ姿です。
		// サーバのハッシュ IOC 照合は、一致しなかったのではなく照合する
		// ものが無かったのに、黙って通ります。Windows 側と同じ形で、
		// **片方だけ直すと、直っていない側が直った顔をします。**
		slog.Debug("ファイルのハッシュを取れませんでした。"+
			"このイベントはハッシュ無しで送られ、ハッシュ IOC には当たりません",
			"path", path, "error", err)
		return collector.FileHashes{}
	}

	return collector.FileHashes{
		MD5:    fmt.Sprintf("%x", h1.Sum(nil)),
		SHA1:   fmt.Sprintf("%x", h2.Sum(nil)),
		SHA256: fmt.Sprintf("%x", h3.Sum(nil)),
	}
}

// isEBPFSupported reports whether this kernel supports CO-RE eBPF (>= 5.4),
// and whether that could be determined at all.
//
// 以前は bool 1つで、**確認できなかったときも false を返していました。**
// uname が失敗したのはカーネルが古いからではなく、確認できなかっただけです。
// それが「非対応」になると、eBPF の経路が丸ごと黙って使われません ——
// プロセス・ネットワーク・ファイル・ライブラリの監視が、対応カーネルの上でも
// 落ちます。バージョン文字列を読めなかったときも同じで、Sscanf の戻り値を
// 捨てていたので major/minor が 0 のまま「5.4 未満」に化けていました。
//
// 呼び出し側の既定は今までどおり「使わない」です。変わるのは、
// **なぜ使わないのかが言えるようになったこと**だけです。
func isEBPFSupported() (supported, known bool) {
	var uname unameResult
	if err := syscallUname(&uname); err != nil {
		slog.Warn("カーネル版数を取得できませんでした。eBPF が使えるかを"+
			"判定できないため、使わずに続行します（非対応と判定したわけでは"+
			"ありません）", "error", err)
		return false, false
	}
	release := string(bytes.TrimRight(uname.Release[:], "\x00"))
	var major, minor int
	if n, err := fmt.Sscanf(release, "%d.%d", &major, &minor); n < 2 || err != nil {
		slog.Warn("カーネル版数を読み取れませんでした。eBPF が使えるかを"+
			"判定できないため、使わずに続行します", "release", release)
		return false, false
	}
	return major > 5 || (major == 5 && minor >= 4), true
}

type unameResult struct {
	Sysname    [65]byte
	Nodename   [65]byte
	Release    [65]byte
	Version    [65]byte
	Machine    [65]byte
	Domainname [65]byte
}

func syscallUname(buf *unameResult) error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return err
	}
	// unix.Utsname fields are [65]int8 on amd64 but [65]byte on arm64.
	// Use unsafe reinterpretation to handle both without type assertions.
	copy(buf.Sysname[:], unsafe.Slice((*byte)(unsafe.Pointer(&uts.Sysname[0])), len(uts.Sysname)))
	copy(buf.Nodename[:], unsafe.Slice((*byte)(unsafe.Pointer(&uts.Nodename[0])), len(uts.Nodename)))
	copy(buf.Release[:], unsafe.Slice((*byte)(unsafe.Pointer(&uts.Release[0])), len(uts.Release)))
	copy(buf.Version[:], unsafe.Slice((*byte)(unsafe.Pointer(&uts.Version[0])), len(uts.Version)))
	copy(buf.Machine[:], unsafe.Slice((*byte)(unsafe.Pointer(&uts.Machine[0])), len(uts.Machine)))
	copy(buf.Domainname[:], unsafe.Slice((*byte)(unsafe.Pointer(&uts.Domainname[0])), len(uts.Domainname)))
	return nil
}

// ebpfUsable is the "just give me a bool" form, for construction sites that
// cannot branch on the distinction. 判定できなかったことは isEBPFSupported が
// 記録済みなので、ここで握り潰しているのは値だけで、事実ではありません。
func ebpfUsable() bool {
	supported, _ := isEBPFSupported()
	return supported
}
