package collector

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestPathFilterNilAndEmpty(t *testing.T) {
	if NewPathFilter(nil) != nil {
		t.Fatal("NewPathFilter(nil) should return nil")
	}
	if NewPathFilter([]string{"", "  "}) == nil {
		// "  " is non-empty after normalisation, so a filter is expected here.
		t.Fatal("whitespace entry should still produce a filter")
	}
	var f *PathFilter
	if f.Excluded("/anything") {
		t.Fatal("nil filter must exclude nothing")
	}
	if (&PathFilter{}).Excluded("/anything") {
		t.Fatal("zero filter must exclude nothing")
	}
}

func TestPathFilterDirectoryBoundary(t *testing.T) {
	// The regression this guards: a naive strings.HasPrefix would also drop the
	// "-backup" sibling, blinding the sensor to a directory nobody excluded.
	base := "/var/lib/edr-agent"
	if runtime.GOOS == "windows" {
		base = `C:\ProgramData\EDRAgent\quarantine`
	}
	f := NewPathFilter([]string{base})

	excluded := []string{
		base,
		filepath.Join(base, "buffer", "00000000000000939621.buf"),
		filepath.Join(base, "nested", "deep", "file.txt"),
	}
	for _, p := range excluded {
		if !f.Excluded(p) {
			t.Errorf("expected %q to be excluded", p)
		}
	}

	kept := []string{
		base + "-backup/file.txt",
		base + "2/file.txt",
		"/some/other/path",
	}
	if runtime.GOOS == "windows" {
		kept = []string{
			base + `-backup\file.txt`,
			base + `2\file.txt`,
			`C:\Windows\System32\cmd.exe`,
		}
	}
	for _, p := range kept {
		if f.Excluded(p) {
			t.Errorf("expected %q to be kept", p)
		}
	}
}

func TestPathFilterTrailingSeparator(t *testing.T) {
	base := "/var/lib/edr-agent/"
	probe := "/var/lib/edr-agent/quarantine/buffer/x.buf"
	if runtime.GOOS == "windows" {
		base = `C:\ProgramData\EDRAgent\`
		probe = `C:\ProgramData\EDRAgent\quarantine\buffer\x.buf`
	}
	if !NewPathFilter([]string{base}).Excluded(probe) {
		t.Errorf("trailing separator in exclusion must not defeat matching: %q vs %q", base, probe)
	}
}

func TestPathFilterWindowsCaseAndSeparator(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case-insensitive/separator folding is Windows-only")
	}
	// ReadDirectoryChangesW reports whatever casing and separator style the
	// filesystem hands back; the exclusion is written by an operator.
	f := NewPathFilter([]string{`C:\ProgramData\EDRAgent\quarantine`})
	for _, p := range []string{
		`c:\programdata\edragent\quarantine\buffer\x.buf`,
		`C:/ProgramData/EDRAgent/quarantine/buffer/x.buf`,
		`C:\PROGRAMDATA\EDRAGENT\QUARANTINE\BUFFER\X.BUF`,
	} {
		if !f.Excluded(p) {
			t.Errorf("expected %q to be excluded", p)
		}
	}
}

func TestPathFilterPOSIXIsCaseSensitive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only semantics")
	}
	f := NewPathFilter([]string{"/var/lib/edr-agent"})
	if f.Excluded("/var/lib/EDR-Agent/x") {
		t.Error("POSIX paths are case-sensitive; differing case must not be excluded")
	}
	// A backslash is a legal POSIX filename character and must not be folded.
	if f.Excluded(`/var/lib\edr-agent/x`) {
		t.Error("backslash must not be treated as a separator on POSIX")
	}
}

func TestPathFilterMultiplePrefixes(t *testing.T) {
	dirs := []string{"/var/lib/edr-agent/quarantine", "/var/log/edr-agent"}
	probe := "/var/log/edr-agent/agent.log"
	miss := "/etc/passwd"
	if runtime.GOOS == "windows" {
		dirs = []string{`C:\ProgramData\EDRAgent\quarantine`, `C:\ProgramData\EDRAgent\logs`}
		probe = `C:\ProgramData\EDRAgent\logs\agent.log`
		miss = `C:\Windows\System32\drivers\etc\hosts`
	}
	f := NewPathFilter(dirs)
	if !f.Excluded(probe) {
		t.Errorf("expected %q to be excluded", probe)
	}
	if f.Excluded(miss) {
		t.Errorf("expected %q to be kept", miss)
	}
}

func TestSelfExclusions(t *testing.T) {
	got := SelfExclusions("/var/lib/edr-agent/quarantine", "/var/log/edr-agent/agent.log")
	want := []string{"/var/lib/edr-agent/quarantine", filepath.Dir("/var/log/edr-agent/agent.log")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}

	// The spool is the loop's source; it must fall inside the returned exclusions.
	f := NewPathFilter(got)
	spool := filepath.Join("/var/lib/edr-agent/quarantine", "buffer", "00000000000000939621.buf")
	if !f.Excluded(spool) {
		t.Errorf("spool file %q must be excluded", spool)
	}

	if len(SelfExclusions("", "")) != 0 {
		t.Error("empty inputs must yield no exclusions")
	}
	if len(SelfExclusions("/q", "")) != 1 {
		t.Error("missing log file must not drop the quarantine exclusion")
	}
}
