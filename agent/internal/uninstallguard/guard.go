// Package uninstallguard makes removing the agent require a secret the endpoint
// user does not have.
//
// This is the difference between an EDR that reports tampering and one that
// resists it. Detection-only self-protection tells you afterwards that the agent
// was uninstalled; every mid-tier commercial EDR instead refuses the uninstall
// unless the operator supplies a password held by the SOC. The attacker's first
// move on a compromised endpoint — with local administrator, which they usually
// have — is to remove the sensor, and an alert about it arrives only if the
// agent still had a moment to send one.
//
// The design constraints that shape everything here:
//
//   - It must work offline. Cutting the network is free and comes before the
//     uninstall attempt, so verification cannot be a server round trip. The
//     material to check a password against lives on disk.
//   - Local root can read that file. This is not a secret-hiding scheme and
//     pretending otherwise would be dishonest: a determined root user can read
//     the digest, delete the binaries by hand, and skip the uninstaller
//     entirely. What the guard buys is that the *supported* removal path
//     requires the secret, that brute-forcing the digest is expensive, and that
//     every refusal is reported. Making removal actually impossible for root
//     needs the kernel paths (Linux LSM / Windows driver), which is a different
//     layer.
//   - A wrong guess must be as informative as a right one, to the SOC. Failed
//     attempts are the signal worth having.
package uninstallguard

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GuardFileName is the on-disk name of the guard material, kept next to the
// agent config (root/SYSTEM-only, 0600).
const GuardFileName = "uninstall.guard"

// iterations for PBKDF2-HMAC-SHA256.
//
// The threat is offline brute force by someone who has read the guard file, so
// the cost has to sit where a human-chosen password is still expensive to guess
// but a legitimate uninstall does not feel stuck. 600k is the OWASP 2023
// recommendation for PBKDF2-HMAC-SHA256 and costs a few hundred milliseconds
// once, at uninstall time — a cost paid on a path taken maybe once per endpoint
// per year.
const iterations = 600_000

const keyLen = 32

// ErrNoGuard means no guard material is installed, so uninstalling is not
// password-protected on this endpoint. Callers must treat this as "allow":
// making an unprovisioned agent impossible to remove would strand every
// endpoint that enrolled before the policy existed.
var ErrNoGuard = errors.New("uninstall guard not provisioned")

// ErrWrongPassword means guard material exists and the supplied password does
// not match it.
var ErrWrongPassword = errors.New("uninstall password does not match")

// Guard is the on-disk material. It holds a PBKDF2 digest, never the password.
//
// The server also only ever stores this digest; the plaintext exists once, in
// the console, at the moment an administrator sets it. A stolen server database
// therefore does not yield the uninstall password for the fleet.
type Guard struct {
	// Version allows the KDF to be changed later without misreading old files.
	Version int `json:"version"`
	// Algorithm is informational but explicit, so a file found on an endpoint
	// during an investigation is self-describing.
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"iterations"`
	SaltB64    string `json:"salt"`
	DigestB64  string `json:"digest"`
	// UpdatedAt records when the tenant password was last rotated, so an
	// operator can tell whether an endpoint has picked up a rotation.
	UpdatedAt time.Time `json:"updated_at"`
}

// Derive computes the PBKDF2 digest of password with salt. Exported because the
// server derives the same value when an administrator sets the password — the
// two must agree exactly or every endpoint rejects the correct password.
func Derive(password string, salt []byte, iters int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iters, keyLen)
}

// NewGuard builds guard material for password with a fresh random salt.
func NewGuard(password string, now time.Time) (*Guard, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("uninstall password must not be empty")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	digest, err := Derive(password, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("derive digest: %w", err)
	}
	return &Guard{
		Version:    1,
		Algorithm:  "pbkdf2-hmac-sha256",
		Iterations: iterations,
		SaltB64:    base64.StdEncoding.EncodeToString(salt),
		DigestB64:  base64.StdEncoding.EncodeToString(digest),
		UpdatedAt:  now.UTC(),
	}, nil
}

// Verify reports whether password matches the guard.
//
// The comparison is constant-time. That matters less here than in a network
// service — the attacker already holds the file — but a timing-variable compare
// in a security check is the kind of detail that gets flagged in a customer
// audit, and there is no cost to getting it right.
func (g *Guard) Verify(password string) error {
	if g == nil {
		return ErrNoGuard
	}
	salt, err := base64.StdEncoding.DecodeString(g.SaltB64)
	if err != nil {
		return fmt.Errorf("guard file has an unreadable salt: %w", err)
	}
	want, err := base64.StdEncoding.DecodeString(g.DigestB64)
	if err != nil {
		return fmt.Errorf("guard file has an unreadable digest: %w", err)
	}
	iters := g.Iterations
	if iters <= 0 {
		iters = iterations
	}
	got, err := Derive(password, salt, iters)
	if err != nil {
		return fmt.Errorf("derive digest: %w", err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// Path returns the guard file path for a data directory.
func Path(dataDir string) string { return filepath.Join(dataDir, GuardFileName) }

// Load reads the guard material from dataDir. It returns ErrNoGuard when no
// guard is installed.
//
// A file that exists but cannot be parsed is an error, not ErrNoGuard: silently
// treating corruption as "no protection configured" would turn a damaged file
// into an uninstall bypass, and damaging a file is easier than guessing a
// password.
func Load(dataDir string) (*Guard, error) {
	data, err := os.ReadFile(Path(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoGuard
	}
	if err != nil {
		return nil, fmt.Errorf("read guard file: %w", err)
	}
	var g Guard
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("guard file is corrupt (refusing to treat this as unprotected): %w", err)
	}
	if g.SaltB64 == "" || g.DigestB64 == "" {
		return nil, errors.New("guard file is missing its salt or digest (refusing to treat this as unprotected)")
	}
	return &g, nil
}

// Save writes guard material to dataDir with owner-only permissions.
//
// The write is atomic (temp file + rename) so an interrupted policy update
// cannot leave a truncated guard file behind — which Load would reject, making
// the endpoint impossible to uninstall through the supported path until an
// operator intervened.
func Save(dataDir string, g *Guard) error {
	if g == nil {
		return errors.New("nil guard")
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("encode guard: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create guard directory: %w", err)
	}
	final := Path(dataDir)
	tmp, err := os.CreateTemp(dataDir, GuardFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp guard file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp guard file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp guard file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp guard file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp guard file: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("install guard file: %w", err)
	}
	return nil
}

// Remove deletes the guard material. Called after an authorised uninstall so a
// later reinstall starts from the policy the server hands it, not a stale
// digest from a previous tenant password.
func Remove(dataDir string) error {
	err := os.Remove(Path(dataDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
