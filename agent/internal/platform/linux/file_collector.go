//go:build linux

package linux

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// InotifyFileCollector implements collector.FileCollector using Linux inotify.
type InotifyFileCollector struct {
	monitored []string
	filter    *collector.PathFilter
	fd        int
	watchDirs map[int32]string // watch descriptor → path
	budget    int              // max directories to watch (from the kernel limit)
	dropped   atomic.Uint64    // events lost to a saturated send queue
}

// NewInotifyFileCollector creates a new inotify-based file collector.
func NewInotifyFileCollector() *InotifyFileCollector {
	return &InotifyFileCollector{
		watchDirs: make(map[int32]string),
	}
}

// SetPaths sets monitored and excluded paths. Excluded paths are enforced in
// readEvents before an event is hashed or emitted.
func (c *InotifyFileCollector) SetPaths(monitored, excluded []string) {
	c.monitored = monitored
	c.filter = collector.NewPathFilter(excluded)
}

// Start begins monitoring filesystem events and sends them to out.
func (c *InotifyFileCollector) Start(ctx context.Context, out chan<- collector.FileEvent) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify init: %w", err)
	}
	c.fd = fd
	if c.budget == 0 {
		c.budget = inotifyWatchBudget()
	}

	paths := c.monitored
	if len(paths) == 0 {
		paths = []string{
			"/etc", "/tmp", "/var/tmp", "/home", "/root",
			"/usr/bin", "/usr/sbin", "/bin", "/sbin",
		}
	}

	const mask = watchMask
	// IN_ACCESS is intentionally excluded from the broad directory watches: watching
	// reads of /etc/passwd generates thousands of false-positive alerts because the
	// agent itself reads the file for UID resolution on every process event.

	// inotify watches a SINGLE directory — it does not recurse. Watching only the
	// configured roots therefore made every subdirectory invisible: `/home` was
	// watched but `/home/<user>/Documents/` was not, which is precisely where
	// ransomware encrypts. Measured on a live endpoint (2026-08-01): a 70-file
	// modify+rename burst inside a /tmp SUBDIRECTORY produced zero file events,
	// while the same operations directly in /tmp were reported correctly.
	// Walk each root and watch every directory under it.
	for _, path := range paths {
		c.addWatchTree(path, mask)
	}

	// Sensitive-file READ auditing (T1003.008 / T1087.001 / T1552.004): add IN_ACCESS
	// watches on a TIGHT allowlist of high-value files. These are not read by the agent
	// (unlike /etc/passwd), so a read is a genuine credential-theft signal rather than
	// noise — closing the "reads are invisible" sensor gap without the FP flood.
	for _, path := range accessWatchPaths() {
		wd, err := unix.InotifyAddWatch(fd, path, unix.IN_ACCESS)
		if err != nil {
			continue // file may not exist on this host
		}
		c.watchDirs[int32(wd)] = path
	}

	slog.Info("inotify 監視を開始しました",
		"監視ディレクトリ数", len(c.watchDirs), "上限", c.budget)

	go c.readEvents(ctx, out)
	return nil
}

// sensitiveReadPaths are credential-bearing files whose READS are security-relevant and
// which the agent itself never reads, so IN_ACCESS on them is high-signal/low-noise.
var sensitiveReadPaths = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/security/opasswd",
}

// accessWatchPaths returns the files to watch for reads: the fixed credential files plus
// SSH private keys discovered in root's and every user's ~/.ssh (existing files only —
// keys created after startup are not retroactively watched). Public keys (.pub) are
// skipped. A read of a private key is a credential-theft signal (T1552.004).
func accessWatchPaths() []string {
	paths := append([]string{}, sensitiveReadPaths...)
	for _, glob := range []string{"/root/.ssh/id_*", "/home/*/.ssh/id_*"} {
		matches, err := filepath.Glob(glob)
		if err != nil {
			continue
		}
		for _, m := range matches {
			if strings.HasSuffix(m, ".pub") {
				continue
			}
			paths = append(paths, m)
		}
	}
	return paths
}

func (c *InotifyFileCollector) readEvents(ctx context.Context, out chan<- collector.FileEvent) {
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Read(c.fd, buf)
		if err != nil {
			if err == unix.EAGAIN {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			// fd closed or other error
			return
		}

		offset := 0
		for offset < n {
			if offset+unix.SizeofInotifyEvent > n {
				break
			}

			event := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))

			nameLen := int(event.Len)
			nameStart := offset + unix.SizeofInotifyEvent

			var name string
			if nameLen > 0 && nameStart+nameLen <= n {
				// Trim null bytes from name
				nameBytes := buf[nameStart : nameStart+nameLen]
				for i, b := range nameBytes {
					if b == 0 {
						nameBytes = nameBytes[:i]
						break
					}
				}
				name = string(nameBytes)
			}

			offset += unix.SizeofInotifyEvent + nameLen

			dirPath, ok := c.watchDirs[event.Wd]
			if !ok {
				continue
			}

			fullPath := filepath.Join(dirPath, name)

			// Drop ephemeral container/runtime churn before it enters the pipeline.
			// It carries no detection value but dominates the file-event stream on
			// container hosts (measured 2026-07-13: runc exec fifos alone were ~67%
			// of this host's file events), starving the detection engine's JetStream
			// consumer of throughput. /tmp stays visible for malware staging — only
			// the known-noise prefixes are filtered.
			if isRuntimeNoisePath(fullPath) {
				continue
			}

			// Enforce excluded_paths BEFORE hashing. This also carries the agent's
			// own spool directory (see collector.SelfExclusions): emitting events
			// for the spool feeds them back into the spool, which amplifies without
			// bound whenever the agent is offline.
			if c.filter.Excluded(fullPath) {
				continue
			}

			// A directory created after startup must be watched too, or everything
			// written inside it is invisible — exactly how an attacker's staging or
			// encryption directory would escape the sensor.
			if event.Mask&unix.IN_ISDIR != 0 &&
				event.Mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
				c.addWatchTree(fullPath, watchMask)
			}
			// A watch removed by the kernel (directory deleted/unmounted) leaves a
			// stale map entry that would mis-resolve a recycled watch descriptor.
			if event.Mask&(unix.IN_IGNORED|unix.IN_DELETE_SELF) != 0 {
				delete(c.watchDirs, event.Wd)
			}

			action := inotifyMaskToAction(event.Mask)

			evt := collector.FileEvent{
				ID:        uuid.New().String(),
				Timestamp: time.Now(),
				Path:      fullPath,
				Action:    action,
			}

			// Compute hashes for new or modified files
			if action == "create" || action == "modify" {
				evt.Hashes = hashFile(fullPath)
				if info, err := os.Stat(fullPath); err == nil {
					evt.FileSize = info.Size()
				}
			}

			// Never drop silently: a burst is exactly when the queue backs up, and
			// a burst is exactly what the ransomware detector needs. See EmitFile.
			collector.EmitFile(ctx, out, evt, &c.dropped)
		}
	}
}

// watchMask is the inotify event set for directory watches. IN_ISDIR arrives as a
// flag alongside these, letting readEvents pick up directories created at runtime.
const watchMask = unix.IN_CREATE | unix.IN_MODIFY | unix.IN_DELETE |
	unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_ATTRIB

// watchSkipComponents are path fragments whose subtrees are enormous and carry no
// detection value. Measured on a live endpoint (2026-08-01): the Go module cache
// alone consumed the ENTIRE watch budget during the startup walk, leaving /root,
// /usr/bin, /usr/sbin and every runtime-created directory unwatched — the
// ransomware burst in /tmp was invisible purely because a build cache had eaten
// the budget first. Package/build caches are write-once artifact stores; an
// attacker encrypting user documents does not touch them.
var watchSkipComponents = []string{
	"/go/pkg/mod", "/.cache/", "/node_modules/", "/.git/", "/.npm/",
	"/.cargo/registry", "/.rustup", "/site-packages/", "/__pycache__",
	"/.venv/", "/var/lib/docker", "/var/lib/containerd", "/snap/",
	"/.gradle/", "/.m2/repository", "/.pyenv/", "/.nvm/",
	"/tmp/go-build", "/.ccache/", "/target/debug/", "/target/release/",
}

// isWatchSkippable reports whether a directory belongs to a high-cardinality,
// low-value tree that must not consume the watch budget.
func isWatchSkippable(path string) bool {
	p := path + "/"
	for _, c := range watchSkipComponents {
		if strings.Contains(p, c) {
			return true
		}
	}
	return false
}

// inotifyWatchBudget returns how many directories we may watch, derived from the
// kernel's per-user limit rather than a fixed guess. A hardcoded cap that is far
// below the kernel limit throws away coverage for no reason; one above it makes
// every ADD_WATCH fail with ENOSPC. Leave headroom for other inotify users.
func inotifyWatchBudget() int {
	const fallback = 8192
	b, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches")
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return fallback
	}
	if budget := n * 4 / 5; budget >= 1024 {
		return budget
	}
	return 1024
}

// addWatchTree watches root and every directory beneath it. Excluded and known-noise
// paths are skipped, as are directories we cannot read. Reaching the watch budget is
// logged — a truncated watch set means real blind spots, which must never be silent.
func (c *InotifyFileCollector) addWatchTree(root string, mask uint32) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip it, keep walking the rest
		}
		if !d.IsDir() {
			return nil
		}
		if isRuntimeNoisePath(p) || isWatchSkippable(p) || (c.filter != nil && c.filter.Excluded(p)) {
			return filepath.SkipDir
		}
		if len(c.watchDirs) >= c.budget {
			slog.Warn("inotify 監視上限に達しました。以降のディレクトリは監視されません(検知の死角になります)",
				"上限", c.budget, "打ち切り位置", p)
			return filepath.SkipAll
		}
		wd, werr := unix.InotifyAddWatch(c.fd, p, mask)
		if werr != nil {
			return nil
		}
		c.watchDirs[int32(wd)] = p
		return nil
	})
}

// Stop closes the inotify file descriptor.
func (c *InotifyFileCollector) Stop() error {
	if c.fd > 0 {
		return unix.Close(c.fd)
	}
	return nil
}

// runtimeNoisePrefixes are ephemeral container/runtime paths whose filesystem churn
// has no detection value but floods the file-event stream. runc/crun/containerd
// create a fresh fifo per container exec (e.g. /tmp/runc-processNNN), and the agent
// writes its own log under /tmp — all self-generated noise. Filtering them at the
// source cuts pipeline volume (bandwidth, storage, and detection-engine load) while
// keeping /tmp visible for actual malware staging.
var runtimeNoisePrefixes = []string{
	"/tmp/runc-",               // runc exec fifos: /tmp/runc-processNNN
	"/tmp/crun-",               // crun equivalent
	"/tmp/containerd-",         // containerd shim temp
	"/tmp/kizashi-agent.log", // the agent's own log file
	// Compiler scratch trees. Measured on a live endpoint (2026-08-01): a single
	// `go build` wrote 120 files in 30s and tripped the ransomware rate detector.
	// The detector's premise — "ordinary bulk operations stay under the threshold"
	// — is simply false for builds, which write-then-rename thousands of objects.
	// These are ephemeral, tool-owned scratch directories, so filtering them at the
	// source removes the false positive without touching any user-data path.
	// (Same trade-off already accepted for the runc/crun fifos above: an attacker
	// staging here would be missed by THIS sensor, while process/network sensors
	// still see them.)
	"/tmp/go-build",
	"/tmp/cc",     // cc/gcc temporaries: /tmp/ccXXXXXX.o
	"/tmp/ccache", // ccache scratch
}

// isRuntimeNoisePath reports whether path is known container/runtime noise (see
// runtimeNoisePrefixes) that should be dropped before emitting a file event.
func isRuntimeNoisePath(path string) bool {
	for _, p := range runtimeNoisePrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// hashFile computes MD5, SHA1, and SHA256 of a file (up to 50 MB).
func hashFile(path string) collector.FileHashes {
	const maxSize = 50 * 1024 * 1024
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return collector.FileHashes{}
	}
	defer f.Close()

	h1 := md5.New()
	h2 := sha1.New()
	h3 := sha256.New()
	w := io.MultiWriter(h1, h2, h3)

	lr := io.LimitReader(f, maxSize)
	if _, err := io.Copy(w, lr); err != nil {
		return collector.FileHashes{}
	}

	return collector.FileHashes{
		MD5:    fmt.Sprintf("%x", h1.Sum(nil)),
		SHA1:   fmt.Sprintf("%x", h2.Sum(nil)),
		SHA256: fmt.Sprintf("%x", h3.Sum(nil)),
	}
}

// inotifyMaskToAction converts an inotify mask to an action string.
func inotifyMaskToAction(mask uint32) string {
	switch {
	case mask&unix.IN_CREATE != 0:
		return "create"
	case mask&unix.IN_DELETE != 0:
		return "delete"
	case mask&unix.IN_MOVED_FROM != 0, mask&unix.IN_MOVED_TO != 0:
		return "rename"
	case mask&unix.IN_ATTRIB != 0:
		return "attrib"
	case mask&unix.IN_ACCESS != 0:
		return "access"
	default:
		return "modify"
	}
}
