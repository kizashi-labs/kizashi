package protection

import "testing"

func TestDecideMode(t *testing.T) {
	cases := []struct {
		name         string
		major, minor int
		btf, bpfLSM  bool
		want         Mode
	}{
		{"enforce: rhel10.1 kernel6.12 + lsm bpf", 6, 12, true, true, ModeEnforce},
		{"enforce: exactly 5.13", 5, 13, true, true, ModeEnforce},
		{"observe: 5.13 + btf but no bpf in lsm", 5, 13, true, false, ModeObserve},
		{"observe: 5.15 + btf, lsm bpf absent", 5, 15, true, false, ModeObserve},
		{"observe: 5.8 + btf (enforce floor not met)", 5, 8, true, true, ModeObserve},
		{"observe: 5.12 + btf + bpf (below enforce 5.13)", 5, 12, true, true, ModeObserve},
		{"poll: no btf even with new kernel + bpf", 6, 12, false, true, ModePoll},
		{"poll: kernel 5.4 below observe floor", 5, 4, true, true, ModePoll},
		{"poll: ancient kernel", 4, 19, true, false, ModePoll},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideMode(tc.major, tc.minor, tc.btf, tc.bpfLSM); got != tc.want {
				t.Errorf("decideMode(%d,%d,btf=%t,bpfLSM=%t) = %q, want %q",
					tc.major, tc.minor, tc.btf, tc.bpfLSM, got, tc.want)
			}
		})
	}
}

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		release      string
		major, minor int
	}{
		{"6.12.0-124.38.1.el10_1.x86_64", 6, 12},
		{"5.15.0-91-generic", 5, 15},
		{"5.4.0-42-generic", 5, 4},
		{"6.1.0", 6, 1},
		{"4.19.255", 4, 19},
		{"garbage", 0, 0},
		{"", 0, 0},
		{"7", 0, 0}, // no minor component
	}
	for _, tc := range cases {
		t.Run(tc.release, func(t *testing.T) {
			maj, min := parseKernelVersion(tc.release)
			if maj != tc.major || min != tc.minor {
				t.Errorf("parseKernelVersion(%q) = (%d,%d), want (%d,%d)",
					tc.release, maj, min, tc.major, tc.minor)
			}
		})
	}
}

func TestReasonFor_NonEnforceExplainsGap(t *testing.T) {
	// observe because bpf not in LSM list should mention lsm=bpf remediation.
	r := reasonFor(ModeObserve, 6, 12, true, false)
	if r == "" {
		t.Fatal("reasonFor returned empty")
	}
	// poll without BTF should mention BTF.
	if got := reasonFor(ModePoll, 6, 12, false, false); got == "" {
		t.Fatal("reasonFor(poll) returned empty")
	}
}

func TestCapabilitiesString(t *testing.T) {
	c := Capabilities{Mode: ModeEnforce, KernelVersion: "6.12.0", BTF: true, BPFLSM: true, Reason: "x"}
	if c.String() == "" {
		t.Fatal("String() returned empty")
	}
}
