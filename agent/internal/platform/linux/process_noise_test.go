//go:build linux

package linux

import "testing"

func TestIsRuntimeNoiseProc(t *testing.T) {
	noise := []string{
		"runc",
		"runc:[2:INIT]",
		"runc:[1:CHILD]",
		"crun",
		"crun:[1:CHILD]",
		"conmon",
		"containerd-shim",
		"containerd-shim", // containerd-shim-runc-v2 truncates to this at 15 bytes
	}
	for _, c := range noise {
		if !isRuntimeNoiseProc(c) {
			t.Errorf("expected comm %q to be filtered as runtime noise", c)
		}
	}

	// Real workload processes — including ones that merely share a prefix — must
	// NOT be filtered, so in-container threat visibility is preserved.
	keep := []string{
		"bash",
		"python3",
		"xmrig",
		"sshd",
		"runcloud",   // starts with "runc" but is not the runtime
		"runner",     // shared prefix, unrelated
		"containerd", // the long-lived daemon, not a per-exec shim
		"",           // unknown/empty comm is never noise
	}
	for _, c := range keep {
		if isRuntimeNoiseProc(c) {
			t.Errorf("expected comm %q NOT to be filtered", c)
		}
	}
}

func TestIsRuntimeNoiseCmd(t *testing.T) {
	if !isRuntimeNoiseCmd("runc init") {
		t.Error(`expected "runc init" to be filtered`)
	}
	for _, c := range []string{"", "runc", "runc initialize", "runc init --foo", "my runc init", "python init"} {
		if isRuntimeNoiseCmd(c) {
			t.Errorf("expected cmdline %q NOT to be filtered", c)
		}
	}
}

func TestIsBenignCredTracer(t *testing.T) {
	benign := []string{
		"ps", "pgrep", "pidof", "runc", "runc:[1:CHILD]", "crun",
		"conmon", "containerd", "containerd-shim", "landscape-sysin",
		"systemd-journal", "systemd",
		"needrestart", "systemctl", "systemd-detect-", "cloud-id",
	}
	for _, c := range benign {
		if !isBenignCredTracer(c) {
			t.Errorf("expected tracer %q to be allowlisted", c)
		}
	}
	// A real credential-dumping tracer must still raise the event. Lookalikes of
	// allowlisted names must not slip through either — matching is exact, not prefix.
	for _, c := range []string{
		"mimipenguin", "gdb", "python3", "psql", "", "psx",
		"systemd-evil", "needrestarter", "systemctl-x",
	} {
		if isBenignCredTracer(c) {
			t.Errorf("expected tracer %q NOT to be allowlisted", c)
		}
	}
}

func TestIsBenignCapsetProc(t *testing.T) {
	// The processes measured producing routine capset traffic on the
	// verification host (sshd privilege separation, sudo dropping privileges,
	// iproute2 raising CAP_NET_ADMIN).
	for _, c := range []string{"sshd", "sudo", "ip"} {
		if !isBenignCapsetProc(c) {
			t.Errorf("expected capset caller %q to be allowlisted", c)
		}
	}
	// A process raising its own capabilities is the T1548.001 signal and must
	// still surface. Lookalikes must not slip through — matching is exact, not
	// prefix — and setcap is deliberately left un-allowlisted.
	for _, c := range []string{
		"bash", "python3", "xmrig", "", "setcap",
		"sshd-evil", "sudoedit", "ipx",
	} {
		if isBenignCapsetProc(c) {
			t.Errorf("expected capset caller %q NOT to be allowlisted", c)
		}
	}
}

func TestIsBenignNamespaceProc(t *testing.T) {
	// Container daemons manage namespaces continuously (dockerd fired every
	// ~30-60s on an idle verification host).
	for _, c := range []string{"dockerd", "containerd"} {
		if !isBenignNamespaceProc(c) {
			t.Errorf("expected namespace caller %q to be allowlisted", c)
		}
	}
	// A real container breakout comes from a shell/interpreter/nsenter — those
	// must still surface. Matching is exact, not prefix.
	for _, c := range []string{
		"nsenter", "unshare", "bash", "python3", "",
		"dockerd-evil", "containerd-x",
	} {
		if isBenignNamespaceProc(c) {
			t.Errorf("expected namespace caller %q NOT to be allowlisted", c)
		}
	}
}
