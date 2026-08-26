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

	"github.com/edr-platform/agent/internal/telemetry"
	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fimSensor は telemetry に登録する名前です。
const fimSensor = "fim"

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

	// unreadable — 今このスキャンで開けなかったパス。
	//
	// **「変更なし」と「読めなかった」は別の事実です。** FIM が何も
	// 言わないことは、画面では「そのファイルは変わっていない」と読まれ
	// ます。読みに行けなかった場合も、今までまったく同じ姿でした。
	unreadable map[string]struct{}

	// blocked — 見に行けなかった監視対象のルート。
	//
	// 存在しないのではなく、**stat / walk が失敗した**パスです。この
	// 区別が要るのは削除判定のためです —— 見に行けなかっただけの
	// ディレクトリ配下のファイルを「削除された」と報告すると、
	// `/usr/bin` の1回の失敗で 1000 件以上の偽の削除が出ます。
	blocked []string
}

// NewFIMCollector creates a FIMCollector with the platform default rules.
// interval controls how often paths are scanned; pass 0 to use 60s.
func NewFIMCollector(sender EventSender, agentID string, interval time.Duration) *FIMCollector {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &FIMCollector{
		sender:     sender,
		agentID:    agentID,
		rules:      defaultFIMRules(),
		interval:   interval,
		hashes:     make(map[string]string),
		unreadable: make(map[string]struct{}),
	}
}

// AddRule appends an extra FIMRule at runtime (e.g. from server-pushed config).

// ancestorIsNotADirectory reports whether the reason we could not stat path is
// that something along the way is a FILE, not that path is absent.
//
// **os.IsNotExist だけでは足りない。** POSIX はこの場合 ENOTDIR を返すので
// 「無い」と区別が付くが、Windows は ERROR_PATH_NOT_FOUND を返し、Go は
// これを IsNotExist(true) に写す。つまり同じ状況が Linux では「見に行けない」、
// Windows では「無い」に見える。
//
// 「無い」と読むと配下のファイルが currentSet から落ち、**見に行けなかった
// だけで一斉削除として報告される** —— 監視対象が消されたのか、経路が
// 差し替わっただけなのかを取り違える。祖先を辿って確かめる。
func ancestorIsNotADirectory(path string) bool {
	for {
		parent := filepath.Dir(path)
		if parent == path {
			return false
		}
		info, err := os.Lstat(parent)
		if err == nil {
			return !info.IsDir()
		}
		if !os.IsNotExist(err) {
			// 見に行けない祖先。これも「無い」ではない。
			return true
		}
		path = parent
	}
}

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
		h, err := hashFileFn(p)
		if err != nil {
			// Permission errors etc. — record empty string as sentinel.
			f.hashes[p] = ""
			f.unreadable[p] = struct{}{}
			continue
		}
		f.hashes[p] = h
	}
	f.reportCoverage()
}

// reportCoverage — 見に行けなかった対象を、端末の外に出します。
//
// **ログに1行出すだけでは足りません。** このキャンペーンで直してきた
// 形と同じで、agent のローカルログは SOC の画面に出ません。読めなかった
// ファイルがあるあいだ、FIM は「変更なし」と見分けがつかない沈黙を返し
// 続けます。
//
// 存在しないパスは数えません。**`/etc/ld.so.preload` が無いのは正常で、
// 攻撃はそれを「作る」ことです** —— 作られれば created で出ます。
// ここで報告するのは「見に行ったのに読めなかった」ものだけです。
func (f *FIMCollector) reportCoverage() {
	if len(f.unreadable) == 0 && len(f.blocked) == 0 {
		// 健全なときは登録しません。**FIM は設計上ポーリングであって、
		// 劣化ではありません。** ここで poll を登録すると、全 Linux 端末の
		// 集約が poll に倒れ、本物の劣化がその中に埋もれます。
		//
		// 前回の失敗は消します。**直らない赤は、赤でないのと同じです。**
		telemetry.Forget(fimSensor)
		return
	}
	telemetry.Set(fimSensor, telemetry.ModeFailed,
		fmt.Sprintf("読めないファイル %d 件 / 見に行けない対象 %d 件",
			len(f.unreadable), len(f.blocked)))
	slog.Warn("[fim] 監視対象の一部を見られていません。"+
		"**この範囲では「変更なし」と「見ていない」の区別がつきません**",
		"unreadable", len(f.unreadable), "blocked", len(f.blocked))
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
		h, err := hashFileFn(p)
		if err != nil {
			if !os.IsPermission(err) && !os.IsNotExist(err) {
				slog.Warn("[fim] ファイルハッシュ取得失敗", "path", p, "error", err)
			} else if os.IsPermission(err) {
				slog.Warn("[fim] ファイル読み取り権限なし", "path", p)
			}
			f.unreadable[p] = struct{}{}
			// **前回のハッシュは残します。**
			//
			// 以前はここで無条件に "" を書いていました。基準値が消えるので、
			// あとで読めるように戻ったとき —— 中身がまったく同じでも ——
			// `prev("") != h` となって「変更」が上がります。`/etc/shadow`
			// のような、いちばん信用されている経路での偽陽性です。
			// 中身が本当に変わっていた場合も、`old_hash` が空になるので
			// 「何から何に変わったか」が分からなくなります。
			//
			// 一度も読めていないパスにだけ番人役の "" を置きます
			// （seedHashes と同じ意味）。
			if _, known := f.hashes[p]; !known {
				f.hashes[p] = ""
			}
			continue
		}
		delete(f.unreadable, p)

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
		if _, exists := currentSet[p]; exists {
			continue
		}
		// **見に行けなかっただけのパスを「削除」と言いません。**
		//
		// currentSet は expandRules が作ります。stat や walk が失敗した
		// 対象は、以前そこで黙って continue していたので、配下のファイルが
		// まるごと currentSet から落ちました。すると このループが全部を
		// 「削除された」として送り、基準値まで消します。次のスキャンでは
		// それが全部「作成された」として上がります。
		//
		// `/usr/bin` の1回の失敗で、この端末では **1065 件の偽の削除 →
		// 1065 件の偽の作成** になります。実際には何も起きていません。
		if f.isBlocked(p) {
			continue
		}
		f.emitEvent(ctx, p, "deleted", prevHash, "")
		delete(f.hashes, p)
		delete(f.unreadable, p)
	}

	f.reportCoverage()
}

// isBlocked reports whether p sits under a watch target this scan could not
// look at (as opposed to one that is confirmed absent).
func (f *FIMCollector) isBlocked(p string) bool {
	for _, base := range f.blocked {
		if p == base || strings.HasPrefix(p, base+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// expandRules walks all FIMRules and returns the full list of file paths to
// be scanned this tick.  Directories are walked; exclusion patterns are applied.
func (f *FIMCollector) expandRules() []string {
	var paths []string
	seen := make(map[string]struct{})
	// **毎回作り直します。** 前回見に行けなかったものを持ち越すと、
	// 権限が戻ったあとも削除が永久に報告されなくなります。
	f.blocked = nil

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
				// **「無い」と「見に行けない」を分けます。**
				//
				// 以前はどちらも黙って continue でした。無いのは正常です
				// —— `/etc/ld.so.preload` が無いのが普通で、攻撃はそれを
				// 作ることです（作られれば次のスキャンで created が出ます）。
				//
				// それ以外の失敗は「見に行ったのに見られなかった」です。
				// 黙って飛ばすと、配下のファイルが currentSet から落ちて
				// 削除として報告され、基準値まで消えます。
				if !os.IsNotExist(err) || ancestorIsNotADirectory(base) {
					f.blocked = append(f.blocked, base)
					slog.Warn("[fim] 監視対象を見に行けません。"+
						"**この配下は「変更なし」ではなく「見ていない」です**",
						"path", base, "error", err)
				}
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
					// 走査に失敗した枝の配下も「見ていない」です。
					// 削除として報告しないよう控えておきます。
					if !os.IsNotExist(walkErr) || ancestorIsNotADirectory(path) {
						f.blocked = append(f.blocked, path)
					}
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

// hashFileFn is the reader the collector actually calls.
//
// **差し替えられるようにしてあるのは、検査のためです。** 読めない
// ファイルの扱いがこの変更の中身ですが、テストは root で走るので
// chmod では読めなくなりません。実環境が必ず成功する条件では、
// 失敗の分岐は一度も通りません —— このキャンペーンで
// `readVmRSSFn` のときに同じことに当たりました。
//
// 既定が本物であることは `TestTheDefaultFIMHashReaderIsTheRealOne`
// が留めます。**差し替え口を作って既定を留めないと、製品が常に
// 「読めた」を返す実装に置き換わっても検査は緑のままです。**
var hashFileFn = hashFile

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
