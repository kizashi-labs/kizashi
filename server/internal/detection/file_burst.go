// Package detection — file_burst.go: ransomware-style mass file-operation burst
// detection (T1486 Data Encrypted for Impact).
//
// The destructive phase of ransomware is a RATE phenomenon: one process rewrites,
// renames, or deletes hundreds of files in seconds. Extension/tooling rules (the
// existing ".locked"-style sequence rule) miss novel families and intermittent
// extensions; this detector keys purely off the file-operation RATE per process,
// so it fires on the behavior itself regardless of the extension used or whether
// the tool is known. Only destructive operations (modify/overwrite/rename/delete)
// are counted — reads and plain creates are excluded so ordinary I/O (compilers,
// installers producing new files) does not trip it. Mirrors NetworkScanDetector's
// structure (sliding window, per-key state, fire-then-dedup, injected clock).
package detection

import (
	"fmt"
	"strings"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
	"github.com/edr-platform/server/internal/metrics"
)

const (
	// fileBurstWindow is the sliding window over which distinct destructively-
	// touched files are counted per process.
	fileBurstWindow = 30 * time.Second
	// fileBurstMinFiles is the number of distinct files one process must
	// destructively modify within the window to trip the alert. Set high enough
	// that ordinary bulk operations (a build, an installer, a backup restore)
	// stay under it while active encryption — which is far faster and broader —
	// crosses it.
	fileBurstMinFiles = 60
	// fileBurstHostWindow is the window used when the telemetry carries NO process
	// identity. No file collector populates FileEvent.ProcessName/PID today —
	// Linux (inotify), macOS (FSEvents) and Windows (ReadDirectoryChangesW) all
	// report the path and the operation but not the actor — so in production every
	// file event on a host lands in ONE shared bucket. A per-host bucket sees the
	// combined churn of every process at once, which broke this detector BOTH ways
	// on a real endpoint: ordinary background churn (Windows Update, Defender,
	// installers) crossed the per-process threshold repeatedly, and the resulting
	// dedup cooldown then SUPPRESSED a genuine 140-file encryption burst that
	// arrived minutes later. Counting alone cannot separate the two, but RATE
	// CONCENTRATION can: active encryption rewrites files an order of magnitude
	// faster than background churn. So when the actor is unknown we require the
	// same file count within a far tighter window.
	fileBurstHostWindow = 5 * time.Second
	// fileBurstDedup suppresses repeat alerts for the same key after firing.
	fileBurstDedup = 5 * time.Minute
	// fileBurstEscalateFactor lets a burst re-fire DURING the dedup cooldown when
	// it has grown this many times beyond the count that last fired. Without it a
	// small earlier alert on a shared key silences every later, larger one — the
	// exact failure observed in production, where the real burst never alerted
	// because background noise had already fired the host's only bucket.
	fileBurstEscalateFactor = 2
	// fileBurstMaxKeys bounds memory (tracked processes).
	fileBurstMaxKeys = 8192
)

type fileBurstState struct {
	paths     map[string]int64 // file path -> last destructive-op unix seconds
	lastAlert int64
	lastCount int // distinct-file count at the last fire, for escalation
}

// FileBurstScorer is a stateful, concurrency-safe ransomware mass-modification
// detector. Construct with newFileBurstScorer; feed every file event to Observe.
type FileBurstScorer struct {
	mu   sync.Mutex
	keys map[string]*fileBurstState
}

func newFileBurstScorer() *FileBurstScorer {
	return &FileBurstScorer{keys: make(map[string]*fileBurstState)}
}

// IsDestructiveFileAction reports whether a file action mutates or destroys
// existing data (the ransomware signature). Plain "create" and "read"/"open" are
// excluded so ordinary file production does not trip the detector. Matching is
// case-insensitive and substring-based to tolerate telemetry variants
// ("modify"/"modified"/"write"/"WriteFile", "rename"/"renamed", "delete"/"unlink").
//
// Exported because internal/threatgraph needs the same answer when it decides
// whether a process merely read a file or changed it. It previously compared
// the action against the literals "write"/"create"/"delete", none of which
// ingestion ever writes — it writes the proto enum name, e.g.
// "FILE_ACTION_MODIFY" — so every file edge in the graph was "accessed".
func IsDestructiveFileAction(action string) bool {
	a := strings.ToLower(action)
	switch {
	case strings.Contains(a, "modif"), strings.Contains(a, "write"), strings.Contains(a, "overwrit"),
		strings.Contains(a, "renam"), strings.Contains(a, "delet"), strings.Contains(a, "unlink"),
		strings.Contains(a, "truncat"), strings.Contains(a, "encrypt"):
		return true
	default:
		return false
	}
}

// systemChurnPrefixes are OS/package/service-owned trees whose constant rewriting is
// normal operation, not impact. Ransomware is defined by what it destroys — user and
// business DATA — so counting these paths only manufactures false positives.
//
// This filter is keyed on the PATH rather than on the process name deliberately: a
// process allowlist ("ignore systemd/dpkg/…") would be trivially bypassed by naming a
// dropper `systemd`, whereas an attacker cannot hold data to ransom without touching
// the data. Excluding these trees costs almost nothing in coverage — a real encryption
// run that reaches /etc has invariably already swept /home, /srv or the share it was
// after — and removes the entire class of service-churn false positives (observed live:
// systemd rewriting 60 files in 30s raised a severity-9 ransomware alert).
var systemChurnPrefixes = []string{
	// Linux / Unix
	"/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/",
	"/var/lib/", "/var/log/", "/var/cache/", "/var/spool/", "/var/run/",
	"/run/", "/proc/", "/sys/", "/dev/", "/snap/", "/tmp/", "/var/tmp/",
	// Windows
	`c:\windows\`, `c:\program files\`, `c:\program files (x86)\`, `c:\programdata\`,
}

// isSystemChurnPath reports whether path lives in an OS/service-owned tree that must
// not contribute to the ransomware burst count. Matching is case-insensitive so the
// Windows prefixes hold regardless of how the agent cased the path.
func isSystemChurnPath(path string) bool {
	p := strings.ToLower(path)
	for _, pre := range systemChurnPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Observe records one file operation and returns a T1486 match when one process
// has destructively touched fileBurstMinFiles distinct files within the window.
// Non-destructive actions, empty paths, and OS/service-owned paths (see
// systemChurnPrefixes) are ignored. now is injected for deterministic tests.
func (d *FileBurstScorer) Observe(agentID, platform, procName, path, action string, now time.Time) []*detectionrules.RuleMatch {
	// Count every offer at the detector boundary, before any filtering. Without
	// this, "the events never reached the detector" and "they reached it and the
	// window never filled" look identical from outside the process — which is
	// exactly where a live experiment stalled (see metrics.FileBurstObservations).
	label := action
	if label == "" {
		label = "unknown"
	}
	plat := metrics.PlatformLabel(platform)
	if path == "" {
		metrics.FileBurstObservations.WithLabelValues(plat, label, "ignored_path").Inc()
		return nil
	}
	// 名前はこちらの公開版。threatgraph/graph.go が
	// detection.IsDestructiveFileAction を呼んでいるので、小文字に戻すと
	// パッケージ外から消える。ラベルは main の platform 付き 3 つ。
	if !IsDestructiveFileAction(action) {
		metrics.FileBurstObservations.WithLabelValues(plat, label, "ignored_action").Inc()
		return nil
	}
	// System churn (package manager caches, browser profiles, log rotation …) is
	// filtered here rather than left to the threshold: it is high-rate by nature
	// and would fill the window on its own. Counted under its own reason so the
	// instrumentation above still distinguishes "never arrived" from "arrived and
	// was deliberately dropped".
	if isSystemChurnPath(path) {
		metrics.FileBurstObservations.WithLabelValues(plat, label, "ignored_churn").Inc()
		return nil
	}
	metrics.FileBurstObservations.WithLabelValues(plat, label, "counted").Inc()
	// No collector populates the actor for file events yet, so an empty procName is
	// the PRODUCTION norm, not an edge case: the key degenerates to one bucket per
	// host. Track that explicitly and score it on rate concentration instead of raw
	// count (see fileBurstHostWindow).
	src := procName
	hostScoped := src == ""
	if hostScoped {
		src = "不明"
	}
	window := fileBurstWindow
	if hostScoped {
		window = fileBurstHostWindow
	}
	key := agentID + "|" + src
	nu := now.Unix()
	winSec := int64(window / time.Second)

	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.keys) > fileBurstMaxKeys {
		d.evictStale(nu, winSec*4)
	}
	st := d.keys[key]
	if st == nil {
		st = &fileBurstState{paths: make(map[string]int64)}
		d.keys[key] = st
	}
	for p, ts := range st.paths {
		if nu-ts > winSec {
			delete(st.paths, p)
		}
	}
	st.paths[path] = nu

	n := len(st.paths)
	scope := "process"
	if hostScoped {
		scope = "host"
	}
	metrics.FileBurstBucketPaths.WithLabelValues(plat, scope).Set(float64(n))
	if n < fileBurstMinFiles {
		return nil
	}
	// Suppress repeats on the same key, but never let an earlier smaller burst
	// silence a materially larger one — that is how the real encryption burst got
	// lost behind background noise on a shared host bucket.
	if nu-st.lastAlert < int64(fileBurstDedup/time.Second) && n < st.lastCount*fileBurstEscalateFactor {
		return nil
	}
	st.lastAlert = nu
	st.lastCount = n
	subject := fmt.Sprintf("プロセス '%s'", src)
	if hostScoped {
		subject = "ホスト全体(プロセス特定不可)"
	}
	// Count the distinct directories the burst spans. Context, not a gate:
	// ransomware traversing a user's data tree hits many directories, so a wide
	// spread strengthens the hypothesis, while a burst confined to one directory (a
	// single-folder encryptor, or a benign bulk rewrite) is still reported — the file
	// count alone already crossed the threshold. Reported in the description only:
	// the title deliberately carries no observed values so the rule keeps a stable
	// identity for dedup and suppression.
	dirs := map[string]struct{}{}
	for p := range st.paths {
		dirs[fileParentDir(p)] = struct{}{}
	}
	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "ランサムウェアの疑い: ファイル大量改変バースト",
		RuleType: "heuristic",
		// Severity 8, deliberately one below the default auto-isolate threshold (9).
		// A high destructive-file rate on its own is NOT specific enough to isolate a
		// host on: the FP soak of a purely benign 20-host fleet produced 38 of these,
		// every one of them ordinary work — `go` and `docker` builds, `node`, `restic`
		// and `rsync` backups, `find`, `robocopy.exe`, and Defender's own MsMpEng.exe.
		// The rate signal is still worth an alert (novel ransomware families that skip
		// shadow-copy deletion would show up here and nowhere else), but the decision
		// to cut a host off the network needs corroboration. That is what the fourth
		// correlator axis below provides: paired with recovery-inhibition, defense
		// tampering or ACL staging, this same burst escalates to severity 10 and does
		// isolate. Benign builds and backups never produce those other axes.
		Severity: 8,
		Title:    fmt.Sprintf("[HEURISTIC] ランサムウェアの疑い: %s が%d秒内に多数のファイルを破壊的操作", subject, winSec),
		Description: fmt.Sprintf("%s が%d秒以内に%d個の異なるファイルを%dディレクトリにまたがって改変/リネーム/削除。拡張子やツールに依存せずファイル操作のレートで判定するため、既知シグネチャの無いランサムウェアの暗号化フェーズにも反応(T1486)。",
			subject, winSec, n, len(dirs)),
		MITRETags: []string{"T1486"},
	}}
}

// fileParentDir returns the directory portion of a path, tolerating both '/' and '\'
// separators (file telemetry may originate on Linux or Windows). Returns "" for a bare
// filename so directory-spread context degrades gracefully.
func fileParentDir(p string) string {
	i := strings.LastIndexAny(p, `/\`)
	if i <= 0 {
		return ""
	}
	return p[:i]
}

func (d *FileBurstScorer) evictStale(nowUnix, maxAgeSec int64) {
	for k, st := range d.keys {
		var newest int64
		for _, ts := range st.paths {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(d.keys, k)
		}
	}
}
