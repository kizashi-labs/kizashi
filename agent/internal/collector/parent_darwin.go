//go:build darwin

package collector

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// lookupProcess names a live process with `ps`, matching how the darwin process
// collector enumerates processes in the first place (no cgo, no private APIs).
//
// This is the slow path by design. The resolver answers from its cache for
// every process the agent watched start, which on macOS is all of them after
// the first poll — `ps` is only reached for a parent that predates the agent.
func lookupProcess(pid uint32) (name, image string) {
	out, err := exec.Command("ps", "-p", strconv.FormatUint(uint64(pid), 10),
		"-o", "comm=").Output()
	if err != nil {
		return "", ""
	}
	// `comm` is the executable path on macOS, unlike Linux where it is the
	// truncated name.
	image = strings.TrimSpace(string(out))
	if image == "" {
		return "", ""
	}
	return filepath.Base(image), image
}
