//go:build !windows

package software

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
)

// SoftwareEntry represents one installed application.
type SoftwareEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor"`
	InstallDate string `json:"install_date"`
	InstallPath string `json:"install_path"`
}

// Collect returns installed software on Linux via rpm or dpkg.
func Collect() []SoftwareEntry {
	if entries := collectRPM(); len(entries) > 0 {
		return entries
	}
	return collectDPKG()
}

// collectRPM queries installed packages on rpm-based distros (RHEL, Amazon Linux, Fedora).
func collectRPM() []SoftwareEntry {
	out, err := exec.Command("rpm", "-qa", "--queryformat",
		"%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME:date}\n").Output()
	if err != nil {
		return nil
	}

	var entries []SoftwareEntry
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 4)
		if len(parts) < 2 {
			continue
		}
		e := SoftwareEntry{
			Name:    parts[0],
			Version: parts[1],
		}
		if len(parts) >= 3 {
			e.Vendor = parts[2]
		}
		if len(parts) >= 4 {
			e.InstallDate = parts[3]
		}
		entries = append(entries, e)
	}
	return entries
}

// collectDPKG queries installed packages on dpkg-based distros (Debian, Ubuntu).
func collectDPKG() []SoftwareEntry {
	out, err := exec.Command("dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Maintainer}\n").Output()
	if err != nil {
		return nil
	}

	var entries []SoftwareEntry
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), "\t", 3)
		if len(parts) < 2 {
			continue
		}
		e := SoftwareEntry{
			Name:    parts[0],
			Version: parts[1],
		}
		if len(parts) >= 3 {
			e.Vendor = parts[2]
		}
		entries = append(entries, e)
	}
	return entries
}
