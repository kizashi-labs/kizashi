package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultQuarantineDir = "/var/edr/quarantine"

// FileQuarantine moves suspicious files to a secure quarantine location.
type FileQuarantine struct {
	quarantineDir string
}

// NewFileQuarantine creates a new FileQuarantine.
func NewFileQuarantine(dir string) (*FileQuarantine, error) {
	if dir == "" {
		dir = defaultQuarantineDir
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("検疫ディレクトリ作成失敗 %s: %w", dir, err)
	}
	return &FileQuarantine{quarantineDir: dir}, nil
}

// QuarantineResult contains information about a quarantined file.
type QuarantineResult struct {
	OriginalPath   string
	QuarantinePath string
	SHA256         string
	Size           int64
	QuarantinedAt  time.Time
}

// Quarantine moves a file to quarantine and returns metadata.
func (q *FileQuarantine) Quarantine(ctx context.Context, filePath string) (*QuarantineResult, error) {
	_ = ctx

	// Open with O_NOFOLLOW: the kernel rejects the open if filePath is a symlink,
	// closing the TOCTOU window that a prior Lstat check would leave open.
	f, err := openFileNoFollow(filePath)
	if err != nil {
		return nil, fmt.Errorf("ファイルオープン失敗: %w", err)
	}

	// fstat on the open fd — immune to concurrent path substitution.
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("ファイル情報取得失敗: %w", err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("通常ファイル以外の検疫は許可されていません: %s", filePath)
	}

	// Hash via the open fd to avoid reopening the path.
	hash, size, err := hashReader(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}

	// Destination: quarantine/<timestamp>_<hash>.quarantine
	timestamp := time.Now().Format("20060102_150405")
	destName := fmt.Sprintf("%s_%s.quarantine", timestamp, hash[:16])
	destPath := filepath.Join(q.quarantineDir, destName)

	// Move file
	if err := moveFile(filePath, destPath); err != nil {
		return nil, fmt.Errorf("failed to move file to quarantine: %w", err)
	}

	// Post-move check: if destPath is not a regular file (e.g. symlink placed by a
	// concurrent attacker during the rename), remove and fail rather than leaving a
	// dangerous entry in the quarantine directory.
	if dfi, lerr := os.Lstat(destPath); lerr == nil && !dfi.Mode().IsRegular() {
		os.Remove(destPath) //nolint:errcheck
		return nil, fmt.Errorf("検疫先がファイルではありません (レース検出): %s", destPath)
	}

	// Restrict permissions on quarantined file
	if err := os.Chmod(destPath, 0400); err != nil {
		slog.Warn("検疫ファイルのパーミッション設定失敗", "path", destPath, "error", err)
	}

	return &QuarantineResult{
		OriginalPath:   filePath,
		QuarantinePath: destPath,
		SHA256:         hash,
		Size:           size,
		QuarantinedAt:  time.Now(),
	}, nil
}

// Restore moves a quarantined file back to its original location.
func (q *FileQuarantine) Restore(ctx context.Context, quarantinePath, originalPath string) error {
	_ = ctx

	// Verify quarantinePath is inside the quarantine directory to prevent directory traversal.
	cleanQuarantine, err := filepath.EvalSymlinks(q.quarantineDir)
	if err != nil {
		cleanQuarantine = filepath.Clean(q.quarantineDir)
	}
	cleanSrc := filepath.Clean(quarantinePath)
	if !strings.HasPrefix(cleanSrc, cleanQuarantine+string(filepath.Separator)) {
		return fmt.Errorf("検疫パスが検疫ディレクトリ外です: %s", quarantinePath)
	}

	if err := os.MkdirAll(filepath.Dir(originalPath), 0755); err != nil {
		return fmt.Errorf("復元先ディレクトリ作成失敗: %w", err)
	}
	return moveFile(quarantinePath, originalPath)
}

// hashReader computes SHA256 of r, returning the hex digest and byte count.
func hashReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	size, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// moveFile moves src to dst, handling cross-device moves.
func moveFile(src, dst string) error {
	// Try rename first (same filesystem)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}

	// Cross-device: copy then delete
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		os.Remove(dst) //nolint:errcheck
		return err
	}

	out.Close()
	in.Close()
	return os.Remove(src)
}
