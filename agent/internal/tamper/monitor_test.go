package tamper

import (
	"os"
	"path/filepath"
	"testing"
)

// newTestMonitor returns a monitor collecting findings into the returned slice
// pointer. Tests drive checkOnce directly rather than Run, so no ticker is
// involved and the test does not sleep.
func newTestMonitor(t *testing.T) (*Monitor, *[]Payload) {
	t.Helper()
	var got []Payload
	m := NewMonitor(func(p Payload) { got = append(got, p) })
	return m, &got
}

func TestMonitorReportsModifiedConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "agent.toml")
	if err := os.WriteFile(cfg, []byte("server = \"a\"\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	m, got := newTestMonitor(t)
	m.WatchConfig(cfg)
	m.takeBaseline()

	m.checkOnce()
	if len(*got) != 0 {
		t.Fatalf("unmodified config reported %d findings, want 0", len(*got))
	}

	if err := os.WriteFile(cfg, []byte("server = \"attacker\"\n"), 0600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	m.checkOnce()

	if len(*got) != 1 {
		t.Fatalf("modified config reported %d findings, want 1", len(*got))
	}
	f := (*got)[0]
	if f.TamperType != TypeConfigModified {
		t.Errorf("TamperType = %q, want %q", f.TamperType, TypeConfigModified)
	}
	if f.Component != ComponentConfig {
		t.Errorf("Component = %q, want %q", f.Component, ComponentConfig)
	}
	if f.Path != cfg {
		t.Errorf("Path = %q, want %q", f.Path, cfg)
	}
	if f.ExpectedHash == "" || f.ActualHash == "" || f.ExpectedHash == f.ActualHash {
		t.Errorf("expected two differing digests, got expected=%q actual=%q", f.ExpectedHash, f.ActualHash)
	}

	// Repeats are suppressed: the fiftieth copy of "this file changed" tells an
	// analyst nothing the first did not, and it would crowd out everything else.
	m.checkOnce()
	if len(*got) != 1 {
		t.Errorf("repeat check reported again (%d findings), want the first only", len(*got))
	}
}

func TestMonitorReportsDeletedBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "edr-agent")
	if err := os.WriteFile(bin, []byte("ELF..."), 0700); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	m, got := newTestMonitor(t)
	m.WatchBinary(bin)
	m.takeBaseline()

	if err := os.Remove(bin); err != nil {
		t.Fatalf("remove binary: %v", err)
	}
	m.checkOnce()

	if len(*got) != 1 {
		t.Fatalf("deleted binary reported %d findings, want 1", len(*got))
	}
	f := (*got)[0]
	if f.TamperType != TypeBinaryModified {
		t.Errorf("TamperType = %q, want %q", f.TamperType, TypeBinaryModified)
	}
	if f.ActualHash != "" {
		t.Errorf("ActualHash = %q, want empty (the file could not be read)", f.ActualHash)
	}
	if f.ExpectedHash == "" {
		t.Error("ExpectedHash is empty; the baseline digest should still be reported")
	}
}

// A file that could not be fingerprinted at start is skipped rather than
// reported as modified on the next pass. Reporting it would be a finding that no
// evidence supports.
func TestMonitorSkipsFileMissingAtBaseline(t *testing.T) {
	m, got := newTestMonitor(t)
	m.WatchConfig(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	m.takeBaseline()
	m.checkOnce()

	if len(*got) != 0 {
		t.Fatalf("reported %d findings for a file that never existed, want 0", len(*got))
	}
}

func TestMonitorReportsMissingWatchdog(t *testing.T) {
	m, got := newTestMonitor(t)
	// PID 1 exists on every platform the agent runs on, so use an implausible one
	// to represent a supervisor that is gone. processAlive answers false for it on
	// both Unix and Windows.
	m.WatchWatchdog(1 << 30)
	m.checkOnce()

	if len(*got) != 1 {
		t.Fatalf("missing watchdog reported %d findings, want 1", len(*got))
	}
	f := (*got)[0]
	if f.TamperType != TypeWatchdogMissing {
		t.Errorf("TamperType = %q, want %q", f.TamperType, TypeWatchdogMissing)
	}
	if f.Component != ComponentWatchdog {
		t.Errorf("Component = %q, want %q", f.Component, ComponentWatchdog)
	}
}

// An agent started without a watchdog (container, development run) must not
// report a supervisor that was never there.
func TestMonitorWithoutWatchdogPIDStaysQuiet(t *testing.T) {
	m, got := newTestMonitor(t)
	m.WatchWatchdog(0)
	m.checkOnce()

	if len(*got) != 0 {
		t.Fatalf("reported %d findings with no watchdog configured, want 0", len(*got))
	}
}

func TestProcessAliveRecognisesThisProcess(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Error("processAlive says the running test process is not alive")
	}
	if processAlive(0) {
		t.Error("processAlive(0) should be false")
	}
}

func TestWatchdogPIDFromEnv(t *testing.T) {
	t.Setenv(WatchdogPIDEnv, "12345")
	if got := WatchdogPIDFromEnv(); got != 12345 {
		t.Errorf("WatchdogPIDFromEnv = %d, want 12345", got)
	}

	// Anything that is not a plain positive integer disables the check rather
	// than producing a bogus PID to watch.
	for _, bad := range []string{"", "abc", "-1", "12a", "9999999999999"} {
		t.Setenv(WatchdogPIDEnv, bad)
		if got := WatchdogPIDFromEnv(); got != 0 {
			t.Errorf("WatchdogPIDFromEnv(%q) = %d, want 0", bad, got)
		}
	}
}
