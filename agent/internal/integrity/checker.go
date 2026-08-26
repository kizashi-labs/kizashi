// Package integrity provides binary self-integrity checking to detect tampering.
// On first run the agent's own SHA-256 hash is stored in the data directory.
// On subsequent startups the hash is recomputed and compared; a mismatch
// indicates the binary may have been replaced or modified.
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const hashFileName = "agent.sha256"

// ErrTampered is returned when the binary hash does not match the stored value.
var ErrTampered = errors.New("binary integrity check failed: hash mismatch")

// Check verifies the running binary against the stored hash in dataDir.
//
//   - First run (no stored hash): computes and persists the hash, returns nil.
//   - Subsequent runs: recomputes hash and compares.  Returns ErrTampered on
//     mismatch so the caller can alert and/or terminate.
func Check(dataDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("integrity: resolve executable path: %w", err)
	}

	current, err := hashFile(exe)
	if err != nil {
		return fmt.Errorf("integrity: hash binary: %w", err)
	}

	hashPath := filepath.Join(dataDir, hashFileName)
	stored, err := readStoredHash(hashPath)
	if errors.Is(err, os.ErrNotExist) {
		// First run — persist the hash and return OK.
		if writeErr := writeHash(hashPath, current); writeErr != nil {
			slog.Warn("整合性ハッシュの保存に失敗しました", "error", writeErr)
		} else {
			slog.Info("エージェントの整合性ハッシュを保存しました", "hash", current[:16]+"...")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("integrity: read stored hash: %w", err)
	}

	if current != stored {
		slog.Error("エージェントバイナリの改ざんを検知しました",
			"stored_hash", stored[:16]+"...",
			"current_hash", current[:16]+"...",
		)
		return ErrTampered
	}

	slog.Debug("エージェント整合性チェック: OK", "hash", current[:16]+"...")
	return nil
}

// Update overwrites the stored hash with the current binary's hash.
// Call this after a legitimate agent update.
func Update(dataDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("integrity: resolve executable: %w", err)
	}
	hash, err := hashFile(exe)
	if err != nil {
		return err
	}
	return writeHash(filepath.Join(dataDir, hashFileName), hash)
}

// ─── helpers ──────────────────────────────────────────────────

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

func readStoredHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeHash(path string, hash string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hash), 0600)
}
