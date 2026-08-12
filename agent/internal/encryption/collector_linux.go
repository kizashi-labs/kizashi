//go:build linux

package encryption

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
)

// Probe detects LUKS/dm-crypt disk encryption on Linux via lsblk.
//
// lsblk reports a device TYPE of "crypt" for any active dm-crypt/LUKS mapping.
// If at least one crypt device is present the endpoint is treated as encrypted.
func Probe() Status {
	out, err := exec.Command("lsblk", "-rno", "TYPE,NAME").Output()
	if err != nil {
		return Status{Encrypted: false, Method: "LUKS", Details: "lsblk unavailable"}
	}

	var cryptDevs []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 1 && fields[0] == "crypt" {
			if len(fields) >= 2 {
				cryptDevs = append(cryptDevs, fields[1])
			} else {
				cryptDevs = append(cryptDevs, "crypt")
			}
		}
	}

	if len(cryptDevs) == 0 {
		return Status{Encrypted: false, Method: "LUKS", Details: "no dm-crypt devices"}
	}
	return Status{
		Encrypted: true,
		Method:    "LUKS",
		Details:   strings.Join(cryptDevs, ","),
	}
}
