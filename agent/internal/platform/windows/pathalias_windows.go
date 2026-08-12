//go:build windows && prevention

package windows

import (
	"strings"

	syswin "golang.org/x/sys/windows"
)

// PathAliases returns the NT-image-path suffix forms an absolute DOS path may
// appear as in a process-create callback, so a single blocklist rule matches
// regardless of how the loader spelled the path:
//
//   - the DOS path itself      — the callback often reports "\??\" + DOS path,
//     so the DOS path is a suffix of it;
//   - its long-name form       — GetLongPathName, in case the rule was written
//     with 8.3 short names;
//   - its 8.3 short-name form  — GetShortPathName, in case the launcher used a
//     short path (e.g. "...\ADMINI~1\..." as seen in W0 testing);
//   - its \Device\HarddiskVolumeN form — QueryDosDevice on the drive letter, for
//     callbacks that report the volume-device NT path instead of "\??\C:".
//
// Long/short forms are only available for files that currently exist; missing
// files yield just the input. Results are deduped (case-insensitive) with case
// otherwise preserved. This is the W2 NT→DOS normalization that replaces the W1
// bare suffix heuristic for absolute-path rules. See docs/Windowsカーネル防御PoC手順.md.
func PathAliases(dosPath string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	add := func(s string) {
		if s == "" {
			return
		}
		k := strings.ToLower(s)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}

	add(dosPath)
	add(longPath(dosPath))
	add(shortPath(dosPath))
	add(volumeDevicePath(dosPath))
	return out
}

// longPath resolves p to its long-name form (GetLongPathName). "" if it fails
// (e.g. the file does not exist).
func longPath(p string) string {
	return resolvePath(p, syswin.GetLongPathName)
}

// shortPath resolves p to its 8.3 short-name form (GetShortPathName). "" on failure.
func shortPath(p string) string {
	return resolvePath(p, syswin.GetShortPathName)
}

// resolvePath calls a GetLong/ShortPathName-style API with growth-on-truncation.
func resolvePath(p string, fn func(*uint16, *uint16, uint32) (uint32, error)) string {
	in, err := syswin.UTF16PtrFromString(p)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 600)
	n, err := fn(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return ""
	}
	if int(n) > len(buf) { // buffer too small: n is the required length
		buf = make([]uint16, n)
		n, err = fn(in, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			return ""
		}
	}
	return syswin.UTF16ToString(buf[:n])
}

// volumeDevicePath rewrites "X:\rest" to its "\Device\HarddiskVolumeN\rest" form
// using QueryDosDevice on the drive letter. "" if p is not drive-letter rooted or
// the query fails.
func volumeDevicePath(p string) string {
	if len(p) < 2 || p[1] != ':' {
		return ""
	}
	drive, err := syswin.UTF16PtrFromString(p[:2]) // "C:"
	if err != nil {
		return ""
	}
	buf := make([]uint16, 600)
	n, err := syswin.QueryDosDevice(drive, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return ""
	}
	target := syswin.UTF16ToString(buf[:n]) // e.g. \Device\HarddiskVolume3
	return target + p[2:]                   // + "\rest"
}
