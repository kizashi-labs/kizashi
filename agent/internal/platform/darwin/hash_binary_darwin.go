//go:build darwin

package darwin

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/edr-platform/agent/internal/collector"
)

// hashBinary computes MD5/SHA1/SHA256 for the executable at an absolute path,
// reading at most 100MB. Shared by the ps-polling (!esf) and ESF collectors —
// it lived in the !esf-only file before, so the ESF build failed to link it.
func hashBinary(path string) collector.FileHashes {
	if path == "" || !filepath.IsAbs(path) {
		return collector.FileHashes{}
	}
	f, err := os.Open(path)
	if err != nil {
		return collector.FileHashes{}
	}
	defer f.Close()

	// Limit to 100MB
	r := io.LimitReader(f, 100*1024*1024)

	h1 := md5.New()
	h2 := sha1.New()
	h3 := sha256.New()
	mw := io.MultiWriter(h1, h2, h3)

	if _, err := io.Copy(mw, r); err != nil {
		return collector.FileHashes{}
	}

	return collector.FileHashes{
		MD5:    fmt.Sprintf("%x", h1.Sum(nil)),
		SHA1:   fmt.Sprintf("%x", h2.Sum(nil)),
		SHA256: fmt.Sprintf("%x", h3.Sum(nil)),
	}
}
