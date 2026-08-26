package uninstallguard

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// testGuard builds guard material with a cheap KDF cost. The production 600k
// iterations are deliberately slow; paying that in every subtest would make the
// package's tests take minutes for no added confidence, since the iteration
// count is carried in the file and honoured by Verify.
func testGuard(t *testing.T, password string) *Guard {
	t.Helper()
	salt := []byte("0123456789abcdef")
	digest, err := Derive(password, salt, 1)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return &Guard{
		Version:    1,
		Algorithm:  "pbkdf2-hmac-sha256",
		Iterations: 1,
		SaltB64:    base64.StdEncoding.EncodeToString(salt),
		DigestB64:  base64.StdEncoding.EncodeToString(digest),
		UpdatedAt:  time.Now().UTC(),
	}
}

// TestDeriveKnownAnswer pins this side of the cross-module contract.
//
// The server derives the digest (server/internal/api/handlers) and this package
// verifies against it, with no shared code between them. If either side changes
// its hash, key length or encoding, nothing fails to build and nothing fails in
// CI — the symptom appears in the field as "the correct uninstall password is
// rejected on every endpoint". The identical vector is asserted server-side.
//
// Vector: PBKDF2-HMAC-SHA256, password "correct horse battery staple",
// salt "0123456789abcdef", 1000 iterations, 32-byte key, standard base64.
func TestDeriveKnownAnswer(t *testing.T) {
	const want = "yqSq2SygY1sB4EcH9f2FG0JTMES+wqLsOT5YmiRBplI="

	got, err := Derive("correct horse battery staple", []byte("0123456789abcdef"), 1000)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if enc := base64.StdEncoding.EncodeToString(got); enc != want {
		t.Fatalf("KDF known-answer mismatch:\n got  %s\n want %s\n"+
			"This must match the server's derivation, or every endpoint rejects the "+
			"correct uninstall password with no error on either side.", enc, want)
	}
	if len(got) != keyLen || keyLen != 32 {
		t.Errorf("key length = %d (keyLen=%d); the server derives 32 bytes", len(got), keyLen)
	}
}

func TestVerifyAcceptsCorrectAndRejectsWrong(t *testing.T) {
	g := testGuard(t, "correct horse battery staple")

	if err := g.Verify("correct horse battery staple"); err != nil {
		t.Errorf("correct password rejected: %v", err)
	}
	for _, wrong := range []string{
		"",
		"correct horse battery stapl",
		"correct horse battery staple ",
		"CORRECT HORSE BATTERY STAPLE",
	} {
		if err := g.Verify(wrong); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("Verify(%q) = %v, want ErrWrongPassword", wrong, err)
		}
	}
}

func TestNewGuardRoundTrips(t *testing.T) {
	g, err := NewGuard("s3cret-fleet-password", time.Now())
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	if g.Iterations != iterations {
		t.Errorf("Iterations = %d, want %d", g.Iterations, iterations)
	}
	if err := g.Verify("s3cret-fleet-password"); err != nil {
		t.Errorf("round trip failed: %v", err)
	}
}

func TestNewGuardRejectsEmptyPassword(t *testing.T) {
	for _, pw := range []string{"", "   ", "\t\n"} {
		if _, err := NewGuard(pw, time.Now()); err == nil {
			t.Errorf("NewGuard(%q) succeeded; an empty password protects nothing", pw)
		}
	}
}

func TestSaltIsFreshPerGuard(t *testing.T) {
	// Each call must draw a new salt, so the same password never derives the
	// same digest twice.
	//
	// This is not about isolating endpoints from each other — the uninstall
	// password is tenant-wide, so cracking any one endpoint's digest yields the
	// password everywhere regardless of salting. What a fresh salt buys is that
	// the digest cannot be looked up in a precomputed table, which is the
	// realistic attack against a human-chosen password.
	a, err := NewGuard("same-password", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewGuard("same-password", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if a.SaltB64 == b.SaltB64 {
		t.Error("two guards share a salt; salts must be random per guard")
	}
	if a.DigestB64 == b.DigestB64 {
		t.Error("two guards for the same password share a digest; the salt is not being mixed in")
	}
}

func TestLoadMissingReportsNoGuard(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if !errors.Is(err, ErrNoGuard) {
		t.Errorf("Load on an empty dir = %v, want ErrNoGuard", err)
	}
}

// TestLoadCorruptIsNotTreatedAsUnprotected is the important negative case.
// Callers allow the uninstall on ErrNoGuard, so if a damaged file also produced
// ErrNoGuard then truncating one file would bypass the password entirely —
// far cheaper for an attacker than guessing it.
func TestLoadCorruptIsNotTreatedAsUnprotected(t *testing.T) {
	cases := map[string]string{
		"truncated json":  `{"version":1,"salt":"AAAA"`,
		"empty file":      ``,
		"missing digest":  `{"version":1,"salt":"AAAA"}`,
		"missing salt":    `{"version":1,"digest":"AAAA"}`,
		"not json at all": `neutralised`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(Path(dir), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(dir)
			if err == nil {
				t.Fatal("corrupt guard loaded without error")
			}
			if errors.Is(err, ErrNoGuard) {
				t.Error("corrupt guard reported as ErrNoGuard — callers would allow the uninstall")
			}
		})
	}
}

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")
	g, err := NewGuard("fleet-password", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, g); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := got.Verify("fleet-password"); err != nil {
		t.Errorf("loaded guard rejected the correct password: %v", err)
	}

	// The guard file must not be world-readable: a digest anyone can copy is a
	// digest anyone can brute-force at their leisure, off the endpoint.
	// Windows does not model POSIX bits, so assert only where they are real.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(Path(dir))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("guard file mode = %04o, want 0600", perm)
		}
	}
}

func TestSaveIsAtomic(t *testing.T) {
	// A second Save must replace the first completely, leaving no partial file
	// and no temp files behind for Load to trip over.
	dir := t.TempDir()
	first, _ := NewGuard("old-password", time.Now())
	second, _ := NewGuard("new-password", time.Now())
	if err := Save(dir, first); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, second); err != nil {
		t.Fatal(err)
	}

	g, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Verify("new-password"); err != nil {
		t.Errorf("rotation did not take effect: %v", err)
	}
	if err := g.Verify("old-password"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("old password still accepted after rotation: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only the guard file, found %v", names)
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := Remove(dir); err != nil {
		t.Errorf("Remove on a missing guard should succeed, got %v", err)
	}
	g, _ := NewGuard("pw", time.Now())
	if err := Save(dir, g); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrNoGuard) {
		t.Errorf("guard still present after Remove: %v", err)
	}
}

// TestGuardFileHoldsNoPlaintext guards against a refactor that stores the
// password "for convenience". The file lives on the endpoint being defended.
func TestGuardFileHoldsNoPlaintext(t *testing.T) {
	const password = "a-very-distinctive-password-value"
	dir := t.TempDir()
	g, err := NewGuard(password, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, g); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if containsBytes(raw, []byte(password)) {
		t.Fatal("the guard file contains the uninstall password in plaintext")
	}
	// And it must still be valid JSON with the documented shape.
	var decoded Guard
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("guard file is not valid JSON: %v", err)
	}
	if decoded.Algorithm != "pbkdf2-hmac-sha256" {
		t.Errorf("Algorithm = %q, want the file to describe its own KDF", decoded.Algorithm)
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
