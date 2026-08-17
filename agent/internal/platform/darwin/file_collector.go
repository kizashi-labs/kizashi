//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// DarwinFileCollector monitors file system events on macOS.
// Uses fswatch (FSEvents-based) if available, falls back to polling.
// For production: use FSEvents API directly via CGo or
//
//	Apple's Endpoint Security Framework.
type DarwinFileCollector struct {
	mu        sync.RWMutex
	cancel    context.CancelFunc
	monitored []string
	filter    *collector.PathFilter
}

func NewDarwinFileCollector(watchDirs []string) *DarwinFileCollector {
	if len(watchDirs) == 0 {
		watchDirs = []string{
			"/Users",
			"/tmp",
			"/var/tmp",
			"/Applications",
			"/Library/LaunchDaemons",
			"/Library/LaunchAgents",
			// /etc は Linux の既定監視パス（linux/file_collector.go）には最初から
			// 入っていたが、こちらには無かった。非対称に気づいたのは、migration 386 で
			// `macOS Sudoers or Passwd Modification`（/etc/sudoers・/etc/passwd を
			// TargetFilename で見る）を入れようとして、**フィールドは解決するのに
			// 値が永久に来ない**ことが分かったため。
			//
			// macOS の /etc は書き込み頻度が低く、Linux で既に同じ範囲を見ている
			// 実績があるので、ノイズ増は小さいと判断した。
			"/etc",
		}
	}
	return &DarwinFileCollector{monitored: watchDirs}
}

// SetPaths sets monitored and excluded paths.
func (c *DarwinFileCollector) SetPaths(monitored []string, excluded []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(monitored) > 0 {
		c.monitored = monitored
	}
	c.filter = collector.NewPathFilter(excluded)
}

func (c *DarwinFileCollector) Start(ctx context.Context, out chan<- collector.FileEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)

	// Try fswatch first (brew install fswatch)
	if hasFswatch() {
		go c.runFswatch(ctx, out)
		return nil
	}

	// Fallback: poll
	go c.pollDirs(ctx, out)
	return nil
}

func (c *DarwinFileCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func hasFswatch() bool {
	_, err := exec.LookPath("fswatch")
	return err == nil
}

// runFswatch uses fswatch to monitor FSEvents in real-time.
func (c *DarwinFileCollector) runFswatch(ctx context.Context, out chan<- collector.FileEvent) {
	c.mu.RLock()
	watchDirs := c.monitored
	c.mu.RUnlock()

	args := []string{
		"--recursive",
		"--event=Created",
		"--event=Updated",
		"--event=Removed",
		"--event=Renamed",
		"--event=MovedFrom",
		"--event=MovedTo",
		"--format=%f %p", // flags path
		"--batch-marker",
		"--latency=0.5",
	}
	args = append(args, watchDirs...)

	cmd := exec.CommandContext(ctx, "fswatch", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		go c.pollDirs(ctx, out)
		return
	}
	if err := cmd.Start(); err != nil {
		go c.pollDirs(ctx, out)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill() //nolint:errcheck
			return
		default:
		}

		line := scanner.Text()
		if line == "NoOp" || line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}

		flags := parts[0]
		path := parts[1]

		action := flagsToAction(flags)
		if action == "" {
			continue
		}

		// Skip system noise
		if c.shouldSkipPath(path) {
			continue
		}

		hashes := collector.FileHashes{}
		var fileSize int64
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			fileSize = fi.Size()
			if fileSize < 50*1024*1024 { // hash files < 50MB
				hashes = hashFile(path)
			}
		}

		evt := collector.FileEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Path:      path,
			Action:    action,
			Hashes:    hashes,
			FileSize:  fileSize,
		}

		select {
		case out <- evt:
		case <-ctx.Done():
			return
		}
	}
}

func flagsToAction(flags string) string {
	switch {
	case strings.Contains(flags, "Created"):
		return "create"
	case strings.Contains(flags, "Removed"):
		return "delete"
	case strings.Contains(flags, "Renamed"),
		strings.Contains(flags, "MovedFrom"),
		strings.Contains(flags, "MovedTo"):
		return "rename"
	case strings.Contains(flags, "Updated"):
		return "modify"
	default:
		return ""
	}
}

func (c *DarwinFileCollector) shouldSkipPath(path string) bool {
	// Check excluded list. This carries the agent's own spool directory (see
	// collector.SelfExclusions) in addition to operator-configured paths.
	c.mu.RLock()
	filter := c.filter
	c.mu.RUnlock()
	if filter.Excluded(path) {
		return true
	}

	// Built-in noise filters
	noisePatterns := []string{
		".DS_Store",
		"/private/var/folders/",
		"/.Spotlight-",
		"/Library/Caches/",
	}
	for _, s := range noisePatterns {
		if strings.Contains(path, s) {
			return true
		}
	}
	return false
}

// pollDirs is a fallback file monitor using periodic directory scanning.
func (c *DarwinFileCollector) pollDirs(ctx context.Context, out chan<- collector.FileEvent) {
	type fileInfo struct {
		modTime time.Time
		size    int64
	}
	seen := make(map[string]fileInfo)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			dirs := c.monitored
			c.mu.RUnlock()

			for _, dir := range dirs {
				filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
					if err != nil || d.IsDir() || c.shouldSkipPath(path) {
						return nil
					}

					fi, err := d.Info()
					if err != nil {
						return nil
					}

					prev, exists := seen[path]
					current := fileInfo{modTime: fi.ModTime(), size: fi.Size()}

					if !exists {
						// New file
						hashes := hashFile(path)
						evt := collector.FileEvent{
							ID:        uuid.New().String(),
							Timestamp: time.Now(),
							Path:      path,
							Action:    "create",
							Hashes:    hashes,
							FileSize:  fi.Size(),
						}
						select {
						case out <- evt:
						case <-ctx.Done():
							return filepath.SkipAll
						}
					} else if prev.modTime != current.modTime {
						// Modified
						hashes := hashFile(path)
						evt := collector.FileEvent{
							ID:        uuid.New().String(),
							Timestamp: time.Now(),
							Path:      path,
							Action:    "modify",
							Hashes:    hashes,
							FileSize:  fi.Size(),
						}
						select {
						case out <- evt:
						case <-ctx.Done():
							return filepath.SkipAll
						}
					}

					seen[path] = current
					return nil
				})
			}
		}
	}
}

func hashFile(path string) collector.FileHashes {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		// 空のハッシュと「取れなかった」は、イベントに載ると同じ姿です。
		// Windows / Linux と同じ形で、**3つ目のプラットフォームでした。**
		// 片方だけ直すと、直っていない側が直った顔をします。
		slog.Debug("ファイルのハッシュを取れませんでした。"+
			"このイベントはハッシュ無しで送られ、ハッシュ IOC には当たりません",
			"path", path, "error", err)
		return collector.FileHashes{}
	}
	defer f.Close()

	r := io.LimitReader(f, 50*1024*1024)
	h1 := md5.New()
	h2 := sha1.New()
	h3 := sha256.New()
	mw := io.MultiWriter(h1, h2, h3)

	if _, err := io.Copy(mw, r); err != nil {
		// 空のハッシュと「取れなかった」は、イベントに載ると同じ姿です。
		// Windows / Linux と同じ形で、**3つ目のプラットフォームでした。**
		// 片方だけ直すと、直っていない側が直った顔をします。
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
