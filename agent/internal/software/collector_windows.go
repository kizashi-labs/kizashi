//go:build windows

package software

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// SoftwareEntry represents one installed application.
type SoftwareEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor"`
	InstallDate string `json:"install_date"`
	InstallPath string `json:"install_path"`
}

// Collect returns installed software from the Windows registry.
// Reads both the 64-bit and 32-bit (WOW6432Node) uninstall keys.
func Collect() []SoftwareEntry {
	seen := make(map[string]bool)
	var entries []SoftwareEntry

	keys := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	for _, keyPath := range keys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}

		for _, sub := range subkeys {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			name, _, _ := sk.GetStringValue("DisplayName")
			version, _, _ := sk.GetStringValue("DisplayVersion")
			vendor, _, _ := sk.GetStringValue("Publisher")
			installDate, _, _ := sk.GetStringValue("InstallDate")
			installPath, _, _ := sk.GetStringValue("InstallLocation")
			systemComponent, _, _ := sk.GetIntegerValue("SystemComponent")
			releaseType, _, _ := sk.GetStringValue("ReleaseType")
			sk.Close()

			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			// Skip Windows system components and update packages
			if systemComponent == 1 {
				continue
			}
			if strings.Contains(strings.ToLower(releaseType), "update") {
				continue
			}

			dedup := strings.ToLower(name + "|" + version)
			if seen[dedup] {
				continue
			}
			seen[dedup] = true

			entries = append(entries, SoftwareEntry{
				Name:        name,
				Version:     strings.TrimSpace(version),
				Vendor:      strings.TrimSpace(vendor),
				InstallDate: strings.TrimSpace(installDate),
				InstallPath: strings.TrimSpace(installPath),
			})
		}
	}

	return entries
}
