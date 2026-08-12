//go:build linux

package linux

import "testing"

func TestIsRuntimeNoisePath(t *testing.T) {
	noise := []string{
		"/tmp/runc-process1243962630",
		"/tmp/runc-process3648936501",
		"/tmp/crun-abc",
		"/tmp/containerd-shim-xyz",
		"/tmp/kizashi-agent.log",
	}
	for _, p := range noise {
		if !isRuntimeNoisePath(p) {
			t.Errorf("expected %q to be filtered as runtime noise", p)
		}
	}

	// Real, detection-relevant paths under /tmp (and elsewhere) must NOT be filtered.
	keep := []string{
		"/tmp/dropper.sh",
		"/tmp/xmrig",
		"/tmp/.hidden",
		"/tmp/runcfg", // not a runc fifo — different prefix
		"/etc/ld.so.preload",
		"/home/user/.ssh/authorized_keys",
		"/var/tmp/payload",
	}
	for _, p := range keep {
		if isRuntimeNoisePath(p) {
			t.Errorf("expected %q NOT to be filtered", p)
		}
	}
}
