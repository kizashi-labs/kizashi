//go:build windows

package collector

import (
	"os"
	"path/filepath"
)

// listDevices enumerates removable drives on Windows by probing drive letters
// A–Z for accessible root paths.  No WMI, no cgo — pure stdlib.
// Only drives whose root directory is stat-able are reported; this catches
// newly inserted USB storage volumes (SD cards, thumb drives, etc.).
// Vendor/product details are not available without WMI, so they are left empty.
func listDevices() ([]DeviceInfo, error) {
	var devices []DeviceInfo

	// Probe all possible drive letters.
	for c := 'A'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		// filepath.Glob on a drive root is the cheapest way to test accessibility.
		matches, err := filepath.Glob(root + "*")
		if err != nil || matches == nil {
			// Drive letter not present or not accessible — skip.
			continue
		}

		// Confirm the root itself is stat-able (rules out phantom drive letters).
		if _, err := os.Stat(root); err != nil {
			continue
		}

		devices = append(devices, DeviceInfo{
			ID:   root,
			Name: root,
			Type: "storage",
		})
	}

	return devices, nil
}
