package detection

import "testing"

// The Linux side-loading rule exists because the Windows one cannot serve Linux:
// it requires SignatureStatus unsigned/invalid, and the Linux collector reports
// "unknown" for every .so (there is no Authenticode). Before the eBPF dlopen
// collector was taken off its `solib` build tag, nothing emitted image_load on
// Linux at all, so neither rule had any input — the event type read zero, which
// is indistinguishable from "no side-loading happened".
//
// These cases pin both halves: the rule fires on a world-writable path, and it
// stays quiet on the ordinary library loads that make up the entire measured
// baseline (verification EC2, 300s: 14 dlopen calls, all PAM modules from /lib).
func TestLinuxSharedObjectSideLoadingRule(t *testing.T) {
	const title = "Shared Object Loaded From World-Writable Path (Linux Side-Loading)"

	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)

	// Go through flattenNormalizedEvent rather than handing EvaluateEvent a map
	// directly: the snake_case → Sigma field aliasing (image_loaded → ImageLoaded)
	// happens there, so a test that skips it proves nothing about the rule as
	// deployed. The envelope shape is what ingestion publishes for image_load
	// (a flat data map — Format 3).
	fires := func(t *testing.T, proc, loaded string) bool {
		t.Helper()
		flat := flattenNormalizedEvent(map[string]interface{}{
			"type": "image_load",
			"data": map[string]interface{}{
				"process_name":     proc,
				"image_loaded":     loaded,
				"signature_status": "unknown", // what the Linux collector always reports
			},
		})
		for _, m := range e.EvaluateEvent(flat) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	t.Run("fires on world-writable paths", func(t *testing.T) {
		cases := []struct{ proc, loaded string }{
			{"sshd", "/tmp/libpayload.so"},
			{"nginx", "/var/tmp/evil.so.1"},
			{"python3", "/dev/shm/inject.so"},
			{"bash", "/run/shm/stage2.so"},
		}
		for _, c := range cases {
			if !fires(t, c.proc, c.loaded) {
				t.Errorf("rule did not fire for %s loading %s", c.proc, c.loaded)
			}
		}
	})

	// Every entry here appeared in the live baseline, or is the reason /home was
	// deliberately left out of the selector: venvs, conda, node native modules and
	// cargo builds all dlopen from a home directory as a matter of course, and a
	// rule that fires on those is the non-discriminating kind this codebase has
	// had to walk back before.
	t.Run("stays quiet on ordinary loads", func(t *testing.T) {
		cases := []struct{ proc, loaded string }{
			{"sshd", "/lib/x86_64-linux-gnu/security/pam_unix.so"},
			{"sshd", "/lib/x86_64-linux-gnu/security/pam_systemd.so"},
			{"python3", "libm.so.6"},
			{"python3", "/home/ubuntu/.venv/lib/python3.12/site-packages/numpy/core/_multiarray_umath.so"},
			{"node", "/home/ubuntu/app/node_modules/better-sqlite3/build/Release/better_sqlite3.node.so"},
			{"cargo", "/home/ubuntu/target/debug/deps/libfoo.so"},
		}
		for _, c := range cases {
			if fires(t, c.proc, c.loaded) {
				t.Errorf("rule fired on a benign load: %s loading %s", c.proc, c.loaded)
			}
		}
	})
}
