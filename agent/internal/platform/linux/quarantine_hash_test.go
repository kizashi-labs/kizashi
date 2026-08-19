//go:build linux

package linux

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Quarantine hashed the sample after stripping its permissions:
//
//	mv path -> destPath
//	chmod 000 destPath
//	chown root:root destPath
//	hashes := computeLinuxHashes(destPath)   <- unreadable by now
//
// computeLinuxHashes answers an unreadable file with an empty FileHashes{} and
// no error, so the index entry was written with no hash and Quarantine still
// reported success. Root bypasses mode 000, which is why this works wherever
// the agent runs privileged and nowhere else. Verified directly on a mode-000
// file: open() succeeds at euid 0 and returns "permission denied" at euid
// 65534.
//
// The hash is the sample's identity. Without it a responder cannot look the
// file up, correlate it across endpoints, or prove which file was taken —
// while the console shows the quarantine as successful.
//
// These tests run as whatever user `go test` runs as, so they cannot rely on
// the permission check firing. Instead they stub runCommand and assert the
// ordering directly: the hash has to be taken before anything is done to the
// file that could make it unreadable.

// fakeQuarantineShell records the commands Quarantine issues and lets a test
// react to them.
type fakeQuarantineShell struct {
	calls []string
	on    func(name string, args ...string) error
}

func (f *fakeQuarantineShell) run(name string, args ...string) error {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.on != nil {
		return f.on(name, args...)
	}
	return nil
}

// installShell swaps runCommand for the duration of the test.
func installShell(t *testing.T, f *fakeQuarantineShell) {
	t.Helper()
	prev := runCommand
	runCommand = f.run
	t.Cleanup(func() { runCommand = prev })
}

// quarantineWithSample builds a quarantine over a temp dir holding one sample.
func quarantineWithSample(t *testing.T, contents string) (*LinuxFileQuarantine, string) {
	t.Helper()
	dir := t.TempDir()
	sample := filepath.Join(dir, "evil.bin")
	if err := os.WriteFile(sample, []byte(contents), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	return NewLinuxFileQuarantine(dir), sample
}

// TestTheQuarantineHashIsTakenWhileTheFileIsReadable is the core gate.
//
// The stub performs the move for real, and at the moment chmod is issued it
// renames the file away. If the hash is computed before the chmod step it is
// present; if it is computed after — as it was — the file is gone by then and
// the entry is stored with no hash. This is deterministic and does not depend
// on the privileges of the test runner.
func TestTheQuarantineHashIsTakenWhileTheFileIsReadable(t *testing.T) {
	q, sample := quarantineWithSample(t, "malicious payload")

	var moved string
	shell := &fakeQuarantineShell{}
	shell.on = func(name string, args ...string) error {
		switch name {
		case "mv":
			moved = args[1]
			return os.Rename(args[0], args[1])
		case "chmod":
			// Stand in for "the file is no longer readable from here on".
			return os.Rename(moved, moved+".locked")
		}
		return nil
	}
	installShell(t, shell)

	id, err := q.Quarantine(sample)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	entry, ok := q.index[id]
	if !ok {
		t.Fatalf("no index entry for %s", id)
	}
	if entry.Hashes.SHA256 == "" {
		t.Errorf("the quarantined sample was recorded with no SHA-256. The hash is "+
			"taken after the file has been made unreadable, and computeLinuxHashes "+
			"answers that with an empty result and no error, so the quarantine "+
			"reports success while the sample loses its identity. Commands issued: %v",
			shell.calls)
	}
	if entry.Hashes.MD5 == "" || entry.Hashes.SHA1 == "" {
		t.Errorf("entry is missing MD5/SHA1: %+v", entry.Hashes)
	}
	if entry.OriginalPath != sample {
		t.Errorf("OriginalPath = %q, want %q", entry.OriginalPath, sample)
	}
}

// TestTheHashIsOfTheQuarantinedContent. Hashing the right file at the right
// time is the whole point; a hash of the wrong bytes is worse than none.
func TestTheHashIsOfTheQuarantinedContent(t *testing.T) {
	const payload = "malicious payload"
	q, sample := quarantineWithSample(t, payload)

	shell := &fakeQuarantineShell{}
	shell.on = func(name string, args ...string) error {
		if name == "mv" {
			return os.Rename(args[0], args[1])
		}
		return nil
	}
	installShell(t, shell)

	id, err := q.Quarantine(sample)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	got := q.index[id].Hashes.SHA256
	if got == "" {
		t.Fatal("no hash recorded")
	}
	// Recomputed from an independent copy of the same bytes.
	tmp := filepath.Join(t.TempDir(), "ref")
	if err := os.WriteFile(tmp, []byte(payload), 0o600); err != nil {
		t.Fatalf("write ref: %v", err)
	}
	if ref := computeLinuxHashes(tmp).SHA256; ref != got {
		t.Errorf("recorded SHA-256 %s is not the hash of the quarantined bytes (%s)",
			got, ref)
	}
}

// TestTheHashIsTakenBeforeThePermissionsAreStripped pins the ordering by value
// rather than by presence, which is a stronger signal than the rename above: at
// the moment chmod is issued the stub empties the file, so a hash taken
// afterwards is the hash of nothing. Both a hash of the payload and a hash of
// an empty file are non-empty strings, so only comparing them distinguishes the
// two orderings.
func TestTheHashIsTakenBeforeThePermissionsAreStripped(t *testing.T) {
	const payload = "malicious payload"
	q, sample := quarantineWithSample(t, payload)

	var moved string
	shell := &fakeQuarantineShell{}
	shell.on = func(name string, args ...string) error {
		switch name {
		case "mv":
			moved = args[1]
			return os.Rename(args[0], args[1])
		case "chmod":
			return os.WriteFile(moved, nil, 0o600)
		}
		return nil
	}
	installShell(t, shell)

	id, err := q.Quarantine(sample)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	ref := filepath.Join(t.TempDir(), "ref")
	if err := os.WriteFile(ref, []byte(payload), 0o600); err != nil {
		t.Fatalf("write ref: %v", err)
	}
	wantSHA := computeLinuxHashes(ref).SHA256

	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	emptySHA := computeLinuxHashes(empty).SHA256

	got := q.index[id].Hashes.SHA256
	switch got {
	case wantSHA:
		// correct: hashed while the sample was intact
	case emptySHA:
		t.Error("the recorded hash is the hash of an empty file: the sample is " +
			"hashed after the step that changes it, so the quarantine entry " +
			"identifies nothing")
	default:
		t.Errorf("SHA-256 = %q, want %q", got, wantSHA)
	}
}

// TestQuarantineStillStripsPermissions is the floor: the reorder must not have
// dropped the protection the chmod provides.
func TestQuarantineStillStripsPermissions(t *testing.T) {
	q, sample := quarantineWithSample(t, "payload")

	shell := &fakeQuarantineShell{}
	shell.on = func(name string, args ...string) error {
		if name == "mv" {
			return os.Rename(args[0], args[1])
		}
		return nil
	}
	installShell(t, shell)

	if _, err := q.Quarantine(sample); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	var sawChmod000, sawChown bool
	for _, c := range shell.calls {
		if strings.HasPrefix(c, "chmod 000 ") {
			sawChmod000 = true
		}
		if strings.HasPrefix(c, "chown root:root ") {
			sawChown = true
		}
	}
	if !sawChmod000 {
		t.Error("the quarantined file's permissions are never stripped, so it stays " +
			"executable where it was put")
	}
	if !sawChown {
		t.Error("the quarantined file is never chowned to root")
	}
}

// TestAnUnhashableSampleIsReportedNotSwallowed. computeLinuxHashes answers an
// unreadable file with an empty result and no error, so nothing above it can
// tell "hashed successfully" from "could not read the file". Whatever the
// reason, an entry with no hash has to be visible in the log — that silence is
// what let the original ordering bug survive.
func TestAnUnhashableSampleIsReportedNotSwallowed(t *testing.T) {
	q, sample := quarantineWithSample(t, "payload")

	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// The move "succeeds" without moving anything, so destPath is not there to
	// hash — the same observable state as a file the agent may not read.
	shell := &fakeQuarantineShell{}
	installShell(t, shell)

	id, err := q.Quarantine(sample)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if q.index[id].Hashes.SHA256 != "" {
		t.Fatal("the sample was somehow hashed; this test no longer exercises the " +
			"unhashable path")
	}
	if !strings.Contains(logged.String(), "ハッシュ") {
		t.Errorf("a quarantine entry was written with no hash and nothing was "+
			"logged. Log output: %q", logged.String())
	}
}

// TestAFailedMoveIsNotRecordedAsQuarantined. Recording an entry for a file that
// was never moved tells the responder a sample is held that is not.
func TestAFailedMoveIsNotRecordedAsQuarantined(t *testing.T) {
	q, sample := quarantineWithSample(t, "payload")

	shell := &fakeQuarantineShell{}
	shell.on = func(name string, args ...string) error {
		if name == "mv" {
			return os.ErrPermission
		}
		return nil
	}
	installShell(t, shell)

	if _, err := q.Quarantine(sample); err == nil {
		t.Error("Quarantine reported success after the move failed")
	}
	if len(q.index) != 0 {
		t.Errorf("%d entries recorded for a file that was never moved", len(q.index))
	}
}
