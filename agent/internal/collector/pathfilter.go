package collector

import (
	"path/filepath"
	"runtime"
	"strings"
)

// PathFilter reports whether a filesystem path lies under one of a set of excluded
// directory prefixes. It backs the `excluded_paths` collection setting for every
// file collector.
//
// Matching is directory-boundary aware: an exclusion of "/var/lib/edr-agent" drops
// "/var/lib/edr-agent/quarantine/x.buf" but keeps "/var/lib/edr-agent-backup" — a
// naive strings.HasPrefix would silently blind the sensor to the sibling directory.
// On Windows the comparison is case-insensitive and separators are normalised, so a
// watcher reporting "C:/ProgramData/EDRAgent" still matches an exclusion configured
// as `C:\ProgramData\EDRAgent`.
//
// The zero value (and a nil *PathFilter) excludes nothing, so collectors can call
// Excluded unconditionally.
type PathFilter struct {
	prefixes []string
}

// NewPathFilter builds a filter from excluded directory prefixes. Empty entries are
// ignored. Returns nil when nothing is excluded.
func NewPathFilter(excluded []string) *PathFilter {
	prefixes := make([]string, 0, len(excluded))
	for _, e := range excluded {
		if n := normalizePath(e); n != "" {
			prefixes = append(prefixes, n)
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	return &PathFilter{prefixes: prefixes}
}

// Excluded reports whether path is the excluded directory itself or lies beneath it.
func (f *PathFilter) Excluded(path string) bool {
	if f == nil || len(f.prefixes) == 0 {
		return false
	}
	p := normalizePath(path)
	if p == "" {
		return false
	}
	for _, prefix := range f.prefixes {
		if p == prefix {
			return true
		}
		if len(p) > len(prefix) && strings.HasPrefix(p, prefix) &&
			p[len(prefix)] == filepath.Separator {
			return true
		}
	}
	return false
}

// normalizePath canonicalises a path for prefix comparison: trailing separators are
// dropped so "C:\dir\" and "C:\dir" compare equal. On Windows, forward slashes are
// folded to backslashes and the result is lowercased, because the filesystem is
// case-insensitive and ReadDirectoryChangesW does not guarantee the casing or the
// separator style used in configuration. On POSIX the path is left as-is: a
// backslash is a legal filename character there and must not be rewritten.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if runtime.GOOS == "windows" {
		p = strings.ReplaceAll(p, "/", `\`)
		p = strings.ToLower(p)
	}
	for len(p) > 1 && p[len(p)-1] == filepath.Separator {
		p = p[:len(p)-1]
	}
	return p
}

// SelfExclusions returns the directories the agent itself writes to, given the
// configured quarantine directory and log file path. Callers append the result to
// the operator-configured excluded paths before handing them to a file collector.
//
// This is not an optimisation — it prevents a self-sustaining feedback loop. The
// offline spool lives at <quarantine>/buffer/*.buf, and on Windows the default watch
// roots include C:\ProgramData with subtree watching enabled, which contains the
// spool. Every event the agent cannot ship is written to the spool; that write is
// picked up as a file event, hashed (MD5+SHA1+SHA256), and queued; queuing it while
// still offline produces another spool write. The loop amplifies until the host runs
// out of CPU or disk. Measured on the Windows validation host: 187,474 of 194,396
// file events in 24h (96.4%) were the agent's own files, and the host hung three
// times (2026-07-26, 07-31, 08-01), taking RDP and SSM down with it.
//
// The agent's program directory is deliberately NOT excluded: the agent does not
// write there, and blinding it would hand an attacker a safe place to stage payloads.
func SelfExclusions(quarantineDir, logFile string) []string {
	var out []string
	if quarantineDir != "" {
		out = append(out, quarantineDir)
	}
	if logFile != "" {
		out = append(out, filepath.Dir(logFile))
	}
	return out
}
