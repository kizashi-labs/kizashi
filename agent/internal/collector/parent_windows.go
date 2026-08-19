//go:build windows

package collector

import (
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// lookupProcess names a live process via QueryFullProcessImageName, the same
// call the Windows process collector uses for the process's own image.
//
// PROCESS_QUERY_LIMITED_INFORMATION is deliberately the only right requested:
// it is granted for processes the agent could not otherwise open (a protected
// process, or one running as another user), and it is sufficient for the image
// path. Asking for more would fail on exactly the processes worth naming.
func lookupProcess(pid uint32) (name, image string) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	size := uint32(windows.MAX_PATH)
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", ""
	}
	image = syscall.UTF16ToString(buf[:size])
	if image == "" {
		return "", ""
	}
	return filepath.Base(image), image
}
