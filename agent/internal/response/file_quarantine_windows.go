//go:build windows

package response

import "os"

// openFileNoFollow opens path for reading.
// Windows has no O_NOFOLLOW equivalent; this falls back to os.Open.
// Symlink protection is best-effort on this platform.
func openFileNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
