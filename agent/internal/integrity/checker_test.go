package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ─── hashFile ─────────────────────────────────────────────────

func TestHashFile_KnownContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty file", ""},
		{"hello world", "hello world"},
		{"binary-like content", "\x00\x01\x02\x03\xff\xfe"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "integrity-test-*")
			if err != nil {
				t.Fatalf("CreateTemp: %v", err)
			}
			path := f.Name()
			defer os.Remove(path)

			if _, err := f.WriteString(tc.content); err != nil {
				f.Close()
				t.Fatalf("WriteString: %v", err)
			}
			f.Close()

			hash, err := hashFile(path)
			if err != nil {
				t.Fatalf("hashFile error: %v", err)
			}

			// SHA-256 hex strings are always 64 hex characters.
			if len(hash) != 64 {
				t.Errorf("hash length = %d, want 64", len(hash))
			}
		})
	}
}

func TestHashFile_EmptyFileKnownHash(t *testing.T) {
	// SHA-256 of an empty byte sequence is a well-known constant.
	const emptyFileSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	f, err := os.CreateTemp("", "integrity-empty-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	hash, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}
	if hash != emptyFileSHA256 {
		t.Errorf("empty file hash = %q, want %q", hash, emptyFileSHA256)
	}
}

func TestHashFile_SameContentSameHash(t *testing.T) {
	content := "deterministic content for hashing"

	write := func() string {
		f, err := os.CreateTemp("", "integrity-hash-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer os.Remove(f.Name())
		f.WriteString(content)
		f.Close()
		h, err := hashFile(f.Name())
		if err != nil {
			t.Fatalf("hashFile: %v", err)
		}
		return h
	}

	h1 := write()
	h2 := write()

	if h1 != h2 {
		t.Errorf("same content produced different hashes: %q vs %q", h1, h2)
	}
}

func TestHashFile_DifferentContentDifferentHash(t *testing.T) {
	contents := []string{"content-A", "content-B", "content-C"}
	hashes := make(map[string]bool)

	for _, c := range contents {
		f, err := os.CreateTemp("", "integrity-diff-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer os.Remove(f.Name())
		f.WriteString(c)
		f.Close()

		h, err := hashFile(f.Name())
		if err != nil {
			t.Fatalf("hashFile(%q): %v", c, err)
		}
		if hashes[h] {
			t.Errorf("collision: content %q produced an already-seen hash %q", c, h)
		}
		hashes[h] = true
	}
}

func TestHashFile_NonExistentFile(t *testing.T) {
	_, err := hashFile("/nonexistent/path/to/file.bin")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

// ─── readStoredHash / writeHash ───────────────────────────────

func TestWriteAndReadHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"normal 64-char hex", "a3f1b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5f6"},
		{"all zeros", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"uppercase hex", "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, hashFileName)

			if err := writeHash(path, tc.hash); err != nil {
				t.Fatalf("writeHash error: %v", err)
			}

			got, err := readStoredHash(path)
			if err != nil {
				t.Fatalf("readStoredHash error: %v", err)
			}

			if got != tc.hash {
				t.Errorf("readStoredHash = %q, want %q", got, tc.hash)
			}
		})
	}
}

func TestReadStoredHash_NotExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.sha256")

	_, err := readStoredHash(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestWriteHash_CreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	// Use a deeply nested path that doesn't exist yet.
	path := filepath.Join(dir, "a", "b", "c", hashFileName)

	hash := "deadbeef00000000000000000000000000000000000000000000000000000000"
	if err := writeHash(path, hash); err != nil {
		t.Fatalf("writeHash error: %v", err)
	}

	got, err := readStoredHash(path)
	if err != nil {
		t.Fatalf("readStoredHash error: %v", err)
	}
	if got != hash {
		t.Errorf("got %q, want %q", got, hash)
	}
}

// ─── Check ───────────────────────────────────────────────────

func TestCheck_FirstRun_StoresHash(t *testing.T) {
	dir := t.TempDir()

	// First run: no hash file exists → should persist and return nil.
	if err := Check(dir); err != nil {
		t.Fatalf("Check (first run) error: %v", err)
	}

	// Hash file should now exist.
	hashPath := filepath.Join(dir, hashFileName)
	if _, err := os.Stat(hashPath); err != nil {
		t.Errorf("expected hash file at %s to exist: %v", hashPath, err)
	}
}

func TestCheck_SecondRun_MatchingHash(t *testing.T) {
	dir := t.TempDir()

	// First run persists hash.
	if err := Check(dir); err != nil {
		t.Fatalf("Check (first run) error: %v", err)
	}

	// Second run with same binary → should match.
	if err := Check(dir); err != nil {
		t.Fatalf("Check (second run, same binary) error: %v", err)
	}
}

func TestCheck_TamperedHash_ReturnsErrTampered(t *testing.T) {
	dir := t.TempDir()

	// First run to create the hash file.
	if err := Check(dir); err != nil {
		t.Fatalf("Check (first run) error: %v", err)
	}

	// Overwrite the stored hash with a bogus value.
	hashPath := filepath.Join(dir, hashFileName)
	bogus := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := os.WriteFile(hashPath, []byte(bogus), 0600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	err := Check(dir)
	if !errors.Is(err, ErrTampered) {
		t.Errorf("expected ErrTampered, got: %v", err)
	}
}

func TestErrTampered_IsDistinct(t *testing.T) {
	if ErrTampered == nil {
		t.Fatal("ErrTampered should not be nil")
	}
	if errors.Is(ErrTampered, os.ErrNotExist) {
		t.Error("ErrTampered should not equal os.ErrNotExist")
	}
}

// ─── Update ───────────────────────────────────────────────────

func TestUpdate_OverwritesStoredHash(t *testing.T) {
	dir := t.TempDir()

	// Perform a first check to create initial hash.
	if err := Check(dir); err != nil {
		t.Fatalf("initial Check: %v", err)
	}

	// Overwrite with a bogus hash to simulate tampering.
	hashPath := filepath.Join(dir, hashFileName)
	if err := os.WriteFile(hashPath, []byte("0000000000000000000000000000000000000000000000000000000000000000"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Update should rewrite the correct hash.
	if err := Update(dir); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Now Check should succeed.
	if err := Check(dir); err != nil {
		t.Errorf("Check after Update: %v", err)
	}
}

func TestUpdate_CreatesHashFile(t *testing.T) {
	dir := t.TempDir()

	if err := Update(dir); err != nil {
		t.Fatalf("Update on fresh dir: %v", err)
	}

	hashPath := filepath.Join(dir, hashFileName)
	data, err := os.ReadFile(hashPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) != 64 {
		t.Errorf("stored hash length = %d, want 64", len(data))
	}
}
