//go:build unix

package backup

import "syscall"

// oNoFollow makes open* fail if the final path component is a symlink (TOCTOU guard),
// available on unix-like systems.
const oNoFollow = syscall.O_NOFOLLOW
