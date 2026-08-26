//go:build !windows

package response

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openFileNoFollow opens path for reading with O_NOFOLLOW.
// If path is a symlink (or becomes one between our caller's Lstat and this
// call), the kernel returns ELOOP instead of following the link, eliminating
// the TOCTOU window that a plain os.Open would leave open.
func openFileNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("シンボリックリンクの操作は許可されていません: %s", path)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
