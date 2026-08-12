// Package collector provides event collection components for the EDR agent.
// fim_collector.go implements File Integrity Monitoring (FIM) via SHA-256 polling.
// No inotify/cgo is used — the collector hashes watched files on a configurable
// interval and emits an event whenever a hash changes, a file is created, or a
// file is deleted.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FIMRule describes a path to watch and optional exclusion glob patterns.
type FIMRule struct {
	// Path is the file or directory to monitor.
	Path string
	// Recursive, when true, descends into sub-directories.
	Recursive bool
	// Exclude is a list of glob patterns (matched against the full file path).
	// Files that match any pattern are silently skipped.
	Exclude []string
}

// FIMCollector polls a set of paths on a fixed interval, hashes each file with
// SHA-256, and sends a fim_change event whenever the hash differs from the
// previous scan (or when files appear / disappear).
type FIMCollector struct {
	sender   EventSender
	agentID  string
	rules    []FIMRule
	interval time.Duration
	// hashes maps absolute file path → last known SHA-256 hex string.
	// An entry with value "" means the file existed but could not be read.
	hashes map[string]string
}

// NewFIMCollector creates a FIMCollector with the platform default rules.
// interval controls how often paths are scanned; pass 0 to use 60s.
func NewFIMCollector(sender EventSender, agentID string, interval time.Duration) *FIMCollector {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &FIMCollector{
		sender:   sender,
		agentID:  agentID,
		rules:    defaultFIMRules(),
		interval: interval,
		hashes:   make(map[string]string),
	}
}

// AddRule appends an extra FIMRule at runtime (e.g. from server-pushed config).
func (f *FIMCollector) AddRule(r FIMRule) {
	f.rules = append(f.rules, r)
}

// Run blocks until ctx is cancelled, scanning watched paths every interval.
func (f *FIMCollector) Run(ctx context.Context) {
	// Perform an initial scan to seed the hash map (no events emitted).
	f.seedHashes()

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.scan(ctx)
		}
	}
}

// seedHashes performs the first scan without emitting events, establishing
// the baseline state for subsequent comparisons.
func (f *FIMCollector) seedHashes() {
	paths := f.expandRules()
	for _, p := range paths {
		h, err := hashFile(p)
		if err != nil {
			// Permission errors etc. — record empty string as sentinel.
			f.hashes[p] = ""
			continue
		}
		f.hashes[p] = h
	}
}

// scan compares current file hashes with the previous scan and emits events.
func (f *FIMCollector) scan(ctx context.Context) {
	current := f.expandRules()
	currentSet := make(map[string]struct{}, len(current))
	for _, p := range current {
		currentSet[p] = struct{}{}
	}

	// Check for modified / created files.
	for _, p := range current {
		h, err := hashFile(p)
		if err != nil {
			if !os.IsPermission(err) && !os.IsNotExist(err) {
				slog.Warn("[fim] ファイルハッシュ取得失敗", "path", p, "error", err)
			} else if os.IsPermission(err) {
				slog.Warn("[fim] ファイル読み取り権限なし", "path", p)
			}
			// Track as empty hash so we notice if it later becomes readable.
			f.hashes[p] = ""
			continue
		}

		prev, known := f.hashes[p]
		if !known {
			// File did not exist in last scan — created.
			f.emitEvent(ctx, p, "created", "", h)
		} else if prev != h {
			// Hash changed — modified (or previously unreadable and now readable).
			f.emitEvent(ctx, p, "modified", prev, h)
		}
		f.hashes[p] = h
	}

	// Check for deleted files (were in previous scan, not in current).
	for p, prevHash := range f.hashes {
		if _, exists := currentSet[p]; !exists {
			f.emitEvent(ctx, p, "deleted", prevHash, "")
			delete(f.hashes, p)
		}
	}
}

// expandRules walks all FIMRules and returns the full list of file paths to
// be scanned this tick.  Directories are walked; exclusion patterns are applied.
func (f *FIMCollector) expandRules() []string {
	var paths []string
	seen := make(map[string]struct{})

	addPath := func(p string, exclude []string) {
		if isExcluded(p, exclude) {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}

	for _, rule := range f.rules {
		// A rule Path may contain shell-glob metacharacters (e.g.
		// "/home/*/.ssh/authorized_keys") so a single rule covers every user's
		// home without hard-coding usernames. Glob expands only to paths that
		// currently exist; a file that appears later (an attacker creating
		// authorized_keys) is picked up on the next scan and reported as
		// "created" by scan(). Non-glob paths pass through unchanged.
		for _, base := range expandGlob(rule.Path) {
			info, err := os.Stat(base)
			if err != nil {
				// Path doesn't exist or is inaccessible — skip silently.
				continue
			}

			if !info.IsDir() {
				addPath(base, rule.Exclude)
				continue
			}

			// Directory — walk it.
			walkFn := func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					slog.Warn("[fim] ディレクトリ走査エラー", "path", path, "error", walkErr)
					return nil // keep walking
				}
				if d.IsDir() {
					if !rule.Recursive && path != base {
						return filepath.SkipDir
					}
					return nil
				}
				addPath(path, rule.Exclude)
				return nil
			}

			if err := filepath.WalkDir(base, walkFn); err != nil {
				slog.Warn("[fim] WalkDir エラー", "path", base, "error", err)
			}
		}
	}

	return paths
}

// expandGlob returns the concrete paths a rule Path refers to. If the path
// contains glob metacharacters it is expanded with filepath.Glob (empty result
// when nothing matches); otherwise the literal path is returned as-is.
func expandGlob(p string) []string {
	if !strings.ContainsAny(p, "*?[") {
		return []string{p}
	}
	matches, err := filepath.Glob(p)
	if err != nil || len(matches) == 0 {
		return nil
	}
	return matches
}

// fimChangePayload is JSON-serialised into the event ID field.
type fimChangePayload struct {
	Path       string `json:"path"`
	ChangeType string `json:"change_type"` // created | modified | deleted
	OldHash    string `json:"old_hash,omitempty"`
	NewHash    string `json:"new_hash,omitempty"`
}

// emitEvent constructs and sends a single FIM change event.
func (f *FIMCollector) emitEvent(ctx context.Context, path, changeType, oldHash, newHash string) {
	payload := fimChangePayload{
		Path:       path,
		ChangeType: changeType,
		OldHash:    oldHash,
		NewHash:    newHash,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[fim] イベントのシリアライズに失敗しました", "path", path, "error", err)
		return
	}

	// Encode as "fim_change:<uuid>:<json>" into the ID field — same pattern as
	// resource_collector.go which stores structured data in the event ID.
	eventID := fmt.Sprintf("fim_change:%s:%s", newEventID(), string(data))

	evt := &v1.Event{
		Id:        eventID,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_FILE,
	}

	batch := &v1.EventBatch{
		AgentId: f.agentID,
		Events:  []*v1.Event{evt},
	}

	if err := f.sender.SendEvents(ctx, batch); err != nil {
		slog.Warn("[fim] イベント送信失敗", "path", path, "change", changeType, "error", err)
	} else {
		slog.Info("[fim] ファイル変更を検出しました",
			"path", path,
			"change", changeType,
		)
	}
}

// ── Helpers ───────────────────────────────────────────────────

// hashFile reads a file and returns its SHA-256 hex digest.
// Errors (including permission errors) are returned to the caller.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isExcluded reports whether path matches any of the provided glob patterns.
// Pattern matching uses filepath.Match (shell glob syntax).
func isExcluded(path string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
		// Also try matching on just the base name.
		matched, err = filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
		// Try a prefix/suffix match for directory patterns.
		if strings.HasPrefix(path, pattern) {
			return true
		}
	}
	return false
}
