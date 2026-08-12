package backup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestBackupRestore is the core ransomware-rollback flow: back up the pre-image, let the
// file be overwritten, then restore the original content.
func TestBackupRestore(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "store"), 0)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "report.docx")
	writeFile(t, victim, "ORIGINAL CONTENT")

	ref, err := s.Backup(victim)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Simulate ransomware overwriting the file.
	writeFile(t, victim, "ENCRYPTED!!!")
	if read(t, victim) != "ENCRYPTED!!!" {
		t.Fatal("precondition: file should be overwritten")
	}

	if err := s.Restore(ref, victim); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := read(t, victim); got != "ORIGINAL CONTENT" {
		t.Fatalf("restore content = %q, want ORIGINAL CONTENT", got)
	}
}

// TestEvict removes a backup and its bytes.
func TestEvict(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "store"), 0)
	f := filepath.Join(dir, "f")
	writeFile(t, f, "abc")
	ref, _ := s.Backup(f)
	if s.Len() != 1 || s.TotalBytes() != 3 {
		t.Fatalf("after backup: len=%d bytes=%d", s.Len(), s.TotalBytes())
	}
	s.Evict(ref)
	if s.Len() != 0 || s.TotalBytes() != 0 {
		t.Fatalf("after evict: len=%d bytes=%d", s.Len(), s.TotalBytes())
	}
	if err := s.Restore(ref, f); err == nil {
		t.Fatal("restore of evicted ref should fail")
	}
}

// TestQuotaEvictsOldest: exceeding the byte quota drops the oldest backups first.
func TestQuotaEvictsOldest(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "store"), 10) // 10-byte quota
	mk := func(name, content string) string {
		p := filepath.Join(dir, name)
		writeFile(t, p, content)
		ref, err := s.Backup(p)
		if err != nil {
			t.Fatalf("backup %s: %v", name, err)
		}
		return ref
	}
	old := mk("a", "AAAAA") // 5 bytes
	_ = mk("b", "BBBBB")    // 5 bytes → total 10 (at quota)
	_ = mk("c", "CCCCC")    // 5 bytes → total 15 > 10 → evict oldest (a)

	if s.TotalBytes() > 10 {
		t.Fatalf("quota not enforced: total=%d", s.TotalBytes())
	}
	// The oldest (a) should have been evicted.
	if err := s.Restore(old, filepath.Join(dir, "a")); err == nil {
		t.Fatal("oldest backup should have been evicted under quota pressure")
	}
}

// TestBackupRefusesSymlink: a symlinked source is refused (TOCTOU guard). Unix-only
// (symlink semantics / O_NOFOLLOW).
func TestBackupRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	dir := t.TempDir()
	s, _ := NewStore(filepath.Join(dir, "store"), 0)
	real := filepath.Join(dir, "real")
	writeFile(t, real, "secret")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := s.Backup(link); err != ErrSymlink {
		t.Fatalf("backup of symlink should return ErrSymlink, got %v", err)
	}
}

// TestPersistIndex: a new Store over the same dir sees prior backups (index survives).
func TestPersistIndex(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	s1, _ := NewStore(store, 0)
	f := filepath.Join(dir, "f")
	writeFile(t, f, "keepme")
	ref, _ := s1.Backup(f)

	s2, err := NewStore(store, 0) // reopen
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 1 || s2.TotalBytes() != 6 {
		t.Fatalf("reopened store: len=%d bytes=%d", s2.Len(), s2.TotalBytes())
	}
	writeFile(t, f, "changed")
	if err := s2.Restore(ref, f); err != nil {
		t.Fatalf("restore after reopen: %v", err)
	}
	if read(t, f) != "keepme" {
		t.Fatal("restore after reopen should recover original content")
	}
}
