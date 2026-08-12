package tamper

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SpoolFileName is the JSON-Lines file the watchdog appends tamper findings to
// and the agent drains on start.
//
// The watchdog has no gRPC client — it supervises the process that owns the
// connection — so it cannot report a finding itself. Persisting to a spool and
// letting the agent send it on its next start costs a few seconds of latency and
// keeps the watchdog thin. It also survives the case that matters most: the
// finding is written precisely when the agent is not running.
const SpoolFileName = "tamper-spool.jsonl"

const (
	// maxSpoolEntries bounds the spool so a pathological restart loop cannot grow
	// it without limit. The agent drains on every start, so in normal operation
	// the file holds one or two lines; this is a backstop, not a working size.
	// An unbounded on-disk spool is a failure mode this codebase has already hit
	// once (P5-2).
	maxSpoolEntries = 200
	// maxSpoolBytes bounds the file by size as well as by line count, because a
	// corrupted or hand-edited file can be one enormous line.
	maxSpoolBytes = 256 * 1024
	// drainingSuffix marks the spool while the agent reads it, so findings the
	// watchdog appends during a drain land in a fresh file rather than being
	// deleted unread.
	drainingSuffix = ".draining"
)

// Append writes one finding to the spool in dataDir, creating it if needed.
//
// Callers are the watchdog (agent death) and, on paths where sending fails, the
// agent itself. Entries beyond the cap evict the oldest, so the most recent
// findings always survive: during a restart loop the newest death is the one that
// explains the current state.
func Append(dataDir string, p Payload) error {
	if dataDir == "" {
		return fmt.Errorf("tamper: スプールのディレクトリが未指定です")
	}
	line, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("tamper: ペイロードのシリアライズに失敗しました: %w", err)
	}
	if bytes.ContainsRune(line, '\n') {
		// json.Marshal never emits a raw newline, but the spool format depends on
		// it, so assert rather than silently write a line that breaks parsing.
		return fmt.Errorf("tamper: ペイロードに改行が含まれています")
	}

	path := filepath.Join(dataDir, SpoolFileName)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("tamper: スプールのディレクトリ作成に失敗しました: %w", err)
	}

	existing, err := readLines(path)
	if err != nil {
		return err
	}
	existing = append(existing, string(line))
	existing = evictOldest(existing)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(existing, "\n")+"\n"), 0600); err != nil {
		return fmt.Errorf("tamper: スプールの書き込みに失敗しました: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("tamper: スプールの差し替えに失敗しました: %w", err)
	}
	return nil
}

// Drain reads and removes every spooled finding in dataDir.
//
// The file is renamed before being read, so a finding the watchdog appends
// mid-drain goes to a new spool file instead of being deleted unread. A missing
// spool is the normal case and returns no findings and no error.
//
// Unparseable lines are skipped rather than failing the drain: one corrupt line
// must not strand the valid findings next to it. The count of skipped lines is
// returned so the caller can log it — silently dropping them would look exactly
// like "there was no tampering".
func Drain(dataDir string) (found []Payload, skipped int, err error) {
	if dataDir == "" {
		return nil, 0, nil
	}
	path := filepath.Join(dataDir, SpoolFileName)
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return nil, 0, nil
	}

	staging := path + drainingSuffix
	// A leftover staging file means a previous drain died mid-way. Fold it in by
	// removing it only after a successful read below; renaming onto it is fine.
	if err := os.Rename(path, staging); err != nil {
		return nil, 0, fmt.Errorf("tamper: スプールの取り出しに失敗しました: %w", err)
	}

	lines, err := readLines(staging)
	if err != nil {
		return nil, 0, err
	}

	for _, line := range lines {
		var p Payload
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			skipped++
			continue
		}
		if p.TamperType == "" {
			// A well-formed JSON object that is not a finding. Treat as corrupt
			// rather than emitting an event with an empty type, which no rule
			// selects on and which reads as a product bug in the alert list.
			skipped++
			continue
		}
		found = append(found, p)
	}

	if err := os.Remove(staging); err != nil && !os.IsNotExist(err) {
		// The findings were read successfully; failing to unlink only risks a
		// duplicate on the next drain, which is preferable to losing them.
		return found, skipped, fmt.Errorf("tamper: スプールの削除に失敗しました: %w", err)
	}
	return found, skipped, nil
}

// readLines returns the non-empty lines of path, or nil if it does not exist.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tamper: スプールの読み込みに失敗しました: %w", err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	// A single spooled finding is well under 64 KiB, but the default 64 KiB token
	// cap would silently truncate a corrupted file into fragments that then parse
	// as garbage. Raise it to the file cap so oversized lines are surfaced as
	// unparseable instead.
	sc.Buffer(make([]byte, 0, 64*1024), maxSpoolBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("tamper: スプールの走査に失敗しました: %w", err)
	}
	return lines, nil
}

// evictOldest trims lines to the entry and byte caps, dropping from the front.
func evictOldest(lines []string) []string {
	if len(lines) > maxSpoolEntries {
		lines = lines[len(lines)-maxSpoolEntries:]
	}
	total := 0
	for _, l := range lines {
		total += len(l) + 1
	}
	for total > maxSpoolBytes && len(lines) > 1 {
		total -= len(lines[0]) + 1
		lines = lines[1:]
	}
	return lines
}
