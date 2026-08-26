package behavioral

import (
	"testing"
	"time"
)

func TestComputeMetric(t *testing.T) {
	samples := []float64{10, 20, 30, 40, 50}
	m := computeMetric(samples)
	if m.Mean != 30 {
		t.Errorf("expected mean 30, got %f", m.Mean)
	}
	if m.Min != 10 {
		t.Errorf("expected min 10, got %f", m.Min)
	}
	if m.Max != 50 {
		t.Errorf("expected max 50, got %f", m.Max)
	}
	if m.Count != 5 {
		t.Errorf("expected count 5, got %d", m.Count)
	}
	if m.StdDev <= 0 {
		t.Error("expected positive std dev")
	}
}

func TestDetectAnomalyNoBaseline(t *testing.T) {
	engine := NewEngine(nil)
	result := engine.DetectAnomaly("unknown-agent", "process", 100.0, nil)
	if result != nil {
		t.Error("expected nil for unknown agent")
	}
}

func TestCheckProcessAnomaly(t *testing.T) {
	engine := NewEngine(nil)

	// No baseline — should return nil
	result := engine.CheckProcessAnomaly("agent-1", "mimikatz.exe", "/tmp/mimikatz.exe")
	if result != nil {
		t.Error("expected nil for agent without baseline")
	}

	// Add baseline with typical processes
	baseline := &AgentBaseline{
		AgentID:   "agent-1",
		UpdatedAt: time.Now(),
		Metrics:   make(map[ActivityCategory]*BaselineMetric),
		TypicalProcesses: map[string]float64{
			"explorer.exe": 1.0,
			"chrome.exe":   5.0,
			"notepad.exe":  0.5,
			"svchost.exe":  10.0,
			"lsass.exe":    1.0,
			"winlogon.exe": 0.2,
		},
		TypicalDomains: make(map[string]float64),
		TypicalPorts:   make(map[int]float64),
	}
	engine.mu.Lock()
	engine.baselines["agent-1"] = baseline
	engine.mu.Unlock()

	// Known process — no anomaly (even from a suspicious path: known-good name).
	known := engine.CheckProcessAnomaly("agent-1", "explorer.exe", `C:\Windows\explorer.exe`)
	if known != nil {
		t.Error("known process should not be anomalous")
	}

	// Unknown process from a suspicious drop location — should be anomalous.
	unknown := engine.CheckProcessAnomaly("agent-1", "mimikatz.exe", `C:\Users\v\AppData\Local\Temp\mimikatz.exe`)
	if unknown == nil {
		t.Fatal("unknown process from a staging dir should be flagged as anomalous")
	}
	if unknown.Score <= 0 {
		t.Error("anomaly score should be positive")
	}

	// Unknown process from a system path — NOT anomalous (benign long-tail tool).
	sys := engine.CheckProcessAnomaly("agent-1", "rundll32.exe", `C:\Windows\System32\rundll32.exe`)
	if sys != nil {
		t.Errorf("unknown process from a system path should not be flagged, got %+v", sys)
	}
}

func TestIsLinuxKernelThread(t *testing.T) {
	kernel := []string{
		"kworker/u4:1", "kworker/u4:2", "kworker/0:0-events",
		"kworker/u4:0-ext4-rsv-", "[kworker/u4:1]", "ksoftirqd/0",
		"migration/1", "rcu_sched", "rcu_preempt", "kthreadd",
		"kswapd0", "khugepaged", "jbd2/nvme0n1p1-8", "irq/24-pciehp",
		"ext4-rsv-conversion", " [ksoftirqd/3] ",
	}
	for _, n := range kernel {
		if !isLinuxKernelThread(n) {
			t.Errorf("expected %q to be classified as a kernel thread", n)
		}
	}

	userland := []string{
		"bash", "mimikatz.exe", "sshd", "systemd", "python3",
		"kubelet", "kine", "", "worker", "my-kworker-app",
	}
	for _, n := range userland {
		if isLinuxKernelThread(n) {
			t.Errorf("expected %q NOT to be classified as a kernel thread", n)
		}
	}
}

func TestCheckProcessAnomalySkipsKernelThreads(t *testing.T) {
	engine := NewEngine(nil)
	baseline := &AgentBaseline{
		AgentID:   "agent-k",
		UpdatedAt: time.Now(),
		Metrics:   make(map[ActivityCategory]*BaselineMetric),
		TypicalProcesses: map[string]float64{
			"sshd": 1.0, "bash": 5.0, "systemd": 2.0,
			"cron": 0.5, "dockerd": 1.0, "containerd": 1.0,
		},
		TypicalDomains: make(map[string]float64),
		TypicalPorts:   make(map[int]float64),
	}
	engine.mu.Lock()
	engine.baselines["agent-k"] = baseline
	engine.mu.Unlock()

	// Fresh kworker suffixes must never flag, even though they are "unseen".
	// (Kernel threads carry no image_path; passing one anyway must not matter —
	// the kernel-thread gate runs before the location gate.)
	for _, kw := range []string{"kworker/u4:1", "kworker/0:0-events", "[kworker/u8:3-mm_percpu_wq]"} {
		if a := engine.CheckProcessAnomaly("agent-k", kw, ""); a != nil {
			t.Errorf("kernel thread %q should not be flagged, got %+v", kw, a)
		}
	}

	// A genuine unknown userspace process dropped in /tmp is still flagged.
	if a := engine.CheckProcessAnomaly("agent-k", "nc", "/tmp/nc"); a == nil {
		t.Error("unknown userspace process from /tmp should still be flagged")
	}
}

func TestIsSuspiciousExecPath(t *testing.T) {
	suspicious := []string{
		"/tmp/dropper", "/tmp/xmrig", "/tmp/edr_v7_585473/kworker",
		"/var/tmp/x", "/dev/shm/payload", "/run/shm/y", "/run/user/1000/z",
		"/home/ubuntu/evil", "/root/stage.sh", "/mnt/usb/mal", "/media/cdrom/x",
		`C:\Users\v\AppData\Local\Temp\evil.exe`,
		`C:\Windows\Temp\beacon.exe`, `C:\Users\Public\x.exe`,
		"c:/users/v/downloads/setup.exe", `C:\ProgramData\x\y.exe`,
	}
	for _, p := range suspicious {
		if !isSuspiciousExecPath(p) {
			t.Errorf("expected %q to be a suspicious exec path", p)
		}
	}

	// Benign: system dirs, container/runtime artifacts, truncated telemetry,
	// bare comm names, and empty paths must all be treated as NOT suspicious —
	// these are exactly the observed FP long-tail.
	benign := []string{
		"/usr/bin/chmod", "/usr/local/bin/psql", "/bin/rm", "/usr/sbin/cron",
		"/usr/lib/openssh/sftp-server", "/etc/update-motd.d/92-unattended-upgrades",
		"/usr/local/go/pkg/tool/linux_amd64/compile", "/snap/core/x",
		"/proc/self/fd/6", "/moby/abc123/bin/sh", "/runc",
		"/usr/bin8", "/proc/se8", "/etc/upd8", // truncated image_path telemetry
		"chmod", "runc", "wget", "landscape-sysin", "", "  ",
		`C:\Windows\System32\svchost.exe`, `C:\Program Files\app\app.exe`,
	}
	for _, p := range benign {
		if isSuspiciousExecPath(p) {
			t.Errorf("expected %q NOT to be a suspicious exec path", p)
		}
	}
}

func TestCheckProcessAnomalyLocationGate(t *testing.T) {
	engine := NewEngine(nil)
	baseline := &AgentBaseline{
		AgentID:   "agent-l",
		UpdatedAt: time.Now(),
		Metrics:   make(map[ActivityCategory]*BaselineMetric),
		TypicalProcesses: map[string]float64{
			"sshd": 1.0, "bash": 5.0, "systemd": 2.0,
			"cron": 0.5, "dockerd": 1.0, "containerd": 1.0,
		},
		TypicalDomains: make(map[string]float64),
		TypicalPorts:   make(map[int]float64),
	}
	engine.mu.Lock()
	engine.baselines["agent-l"] = baseline
	engine.mu.Unlock()

	// Benign short-lived userland tools from system paths must NOT flag, even
	// though they are unseen — this is the FP long-tail we are suppressing.
	benignFromSystem := []struct{ name, img string }{
		{"chmod", "/usr/bin/chmod"},
		{"rm", "/bin/rm"},
		{"landscape-sysin", "/usr/bin/python3.10"},
		{"92-unattended-u", "/etc/update-motd.d/92-unattended-upgrades"},
		{"sftp-server", "/usr/lib/openssh/sftp-server"},
		{"psql", "/usr/local/bin/psql"},
		{"expr", "expr"}, // unresolved bare comm
		{"who", ""},      // no image_path at all
		{"compile", "/usr/local/go/pkg/tool/linux_amd64/compile"},
	}
	for _, c := range benignFromSystem {
		if a := engine.CheckProcessAnomaly("agent-l", c.name, c.img); a != nil {
			t.Errorf("benign %q from %q should not flag, got %+v", c.name, c.img, a)
		}
	}

	// Dropped/staged payloads from suspicious dirs MUST flag — including a
	// coreutil name masquerading in /tmp (which a name allowlist would miss).
	dropped := []struct{ name, img string }{
		{"dropper", "/tmp/dropper"},
		{"xmrig", "/tmp/xmrig"},
		{"kworker", "/tmp/edr_v7_585473/kworker"}, // masquerade: kernel-thread name in /tmp
		{"chmod", "/tmp/chmod"},                   // renamed/copied coreutil in a drop dir
		{"evil", "/home/ubuntu/.cache/evil"},
	}
	for _, c := range dropped {
		if a := engine.CheckProcessAnomaly("agent-l", c.name, c.img); a == nil {
			t.Errorf("dropped payload %q from %q should flag", c.name, c.img)
		}
	}
}

func TestEventTypeToCategory(t *testing.T) {
	cases := map[string]ActivityCategory{
		"process": CategoryProcess,
		"network": CategoryNetwork,
		"file":    CategoryFile,
		"auth":    CategoryAuth,
		"dns":     CategoryDNS,
		"unknown": CategoryProcess,
	}
	for input, expected := range cases {
		got := eventTypeToCategory(input)
		if got != expected {
			t.Errorf("eventTypeToCategory(%s) = %s, want %s", input, got, expected)
		}
	}
}
