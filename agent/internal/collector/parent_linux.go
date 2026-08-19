//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// lookupProcess names a live process from /proc.
//
// /proc/<pid>/exe is the authoritative image path but is a symlink the agent may
// not be allowed to read (a process running as another user, or one whose
// binary was deleted). /proc/<pid>/comm is always readable and always present,
// so it is the fallback rather than the other way round: a parent named
// "bash" is far more use than a parent named "".
func lookupProcess(pid uint32) (name, image string) {
	base := "/proc/" + strconv.FormatUint(uint64(pid), 10)

	if target, err := os.Readlink(base + "/exe"); err == nil && target != "" {
		// A deleted binary reads back as "/usr/bin/foo (deleted)".
		image = strings.TrimSuffix(target, " (deleted)")
		name = filepath.Base(image)
	}

	if name == "" {
		if b, err := os.ReadFile(base + "/comm"); err == nil {
			name = strings.TrimSpace(string(b))
		}
	}
	return name, image
}
