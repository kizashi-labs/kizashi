package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// ── scanCanceller ────────────────────────────────────────────────

func TestScanCanceller_StopWithNoScan(t *testing.T) {
	var c scanCanceller
	if c.stop() {
		t.Error("stop() with no running scan should return false")
	}
}

func TestScanCanceller_BeginThenStop(t *testing.T) {
	var c scanCanceller
	ctx, release := c.begin()
	defer release()

	if !c.stop() {
		t.Fatal("stop() should report a running scan")
	}
	select {
	case <-ctx.Done():
		// cancelled as expected
	default:
		t.Error("scan context should be cancelled after stop()")
	}
}

func TestScanCanceller_BeginSupersedesPrior(t *testing.T) {
	var c scanCanceller
	ctx1, release1 := c.begin()
	defer release1()
	ctx2, release2 := c.begin() // a new scan supersedes scan 1
	defer release2()

	select {
	case <-ctx1.Done():
		// prior scan cancelled by the new begin()
	default:
		t.Error("starting a new scan should cancel the prior one")
	}
	select {
	case <-ctx2.Done():
		t.Error("the newly started scan should not be cancelled")
	default:
	}
}

// ── scanFilesWithCancel ──────────────────────────────────────────

func TestScanFilesWithCancel_FullScanCountsRegularFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), 10)
	writeFile(t, filepath.Join(dir, "b.txt"), 10)
	writeFile(t, filepath.Join(dir, "c.bin"), 10)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "sub", "d.txt"), 10)

	scanned, matched, matches, cancelled := scanFilesWithCancel(
		context.Background(), []string{dir}, 64*1024,
		func(path string, _ os.FileInfo) ([]scanMatch, bool) {
			if filepath.Base(path) == "c.bin" {
				return []scanMatch{{File: path, Rule: "TestRule"}}, true
			}
			return nil, true
		})

	if cancelled {
		t.Error("a completed scan should not be marked cancelled")
	}
	if scanned != 4 {
		t.Errorf("scanned = %d, want 4 (regular files only; directories excluded)", scanned)
	}
	if matched != 1 || len(matches) != 1 {
		t.Errorf("matched = %d / matches = %d, want 1 / 1", matched, len(matches))
	}
}

func TestScanFilesWithCancel_SkipsOversizeAndUncounted(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "small.txt"), 10)
	writeFile(t, filepath.Join(dir, "big.txt"), 200) // excluded by maxSize
	writeFile(t, filepath.Join(dir, "err.txt"), 10)  // scanFile reports not-counted

	scanned, matched, _, cancelled := scanFilesWithCancel(
		context.Background(), []string{dir}, 100,
		func(path string, _ os.FileInfo) ([]scanMatch, bool) {
			if filepath.Base(path) == "err.txt" {
				return nil, false // e.g. ScanFile error → not counted
			}
			return nil, true
		})

	if cancelled {
		t.Error("should not be cancelled")
	}
	if scanned != 1 {
		t.Errorf("scanned = %d, want 1 (big.txt over size, err.txt not counted)", scanned)
	}
	if matched != 0 {
		t.Errorf("matched = %d, want 0", matched)
	}
}

func TestScanFilesWithCancel_AbortsOnCancel(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("f%02d.txt", i)), 10)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	count := 0
	scanned, _, _, cancelled := scanFilesWithCancel(
		ctx, []string{dir}, 64*1024,
		func(_ string, _ os.FileInfo) ([]scanMatch, bool) {
			mu.Lock()
			count++
			if count == 3 {
				cancel() // request stop mid-walk
			}
			mu.Unlock()
			return nil, true
		})

	if !cancelled {
		t.Error("scan interrupted mid-walk should be marked cancelled")
	}
	if scanned >= 20 {
		t.Errorf("scanned = %d, want < 20 (walk should abort early)", scanned)
	}
}
