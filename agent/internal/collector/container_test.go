package collector

import "testing"

// container_id, privileged and host_network were read by
// server/internal/cloudruntime off process events and collected by nothing, so
// privileged-container detection, host-network detection and the "containers
// monitored" count were structurally zero. All three are kernel state, so the
// endpoint can answer them from /proc without a runtime API — but the parsing
// is per-runtime and easy to get subtly wrong in either direction, and both
// directions are silent: a missed container means no detection, a host process
// mislabelled as contained means false positives on every privileged-shell
// rule. Both are pinned here.

// The headline: every runtime's cgroup layout yields the container ID.
func TestTheContainerIDIsFoundForEveryRuntimeLayout(t *testing.T) {
	const id = "3f2b1c8a9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
	for _, tc := range []struct{ name, cgroup string }{
		{"docker (cgroup v1)", "12:devices:/docker/" + id},
		{"docker (cgroup v2)", "0::/docker/" + id},
		{"containerd / CRI", "0::/kubepods.slice/kubepods-burstable.slice/" +
			"kubepods-burstable-pod123.slice/cri-containerd-" + id + ".scope"},
		{"podman", "0::/machine.slice/libpod-" + id + ".scope"},
		{"crio", "0::/kubepods.slice/crio-" + id + ".scope"},
		{"multi-line, id on a later line",
			"0::/init.scope\n12:devices:/docker/" + id},
	} {
		got := containerIDFromCgroup(tc.cgroup)
		if got != id {
			t.Errorf("%s: コンテナIDが取れません (got %q)。"+
				"このランタイムのコンテナは検知対象から丸ごと外れます", tc.name, got)
		}
	}
}

// A host process must not be labelled as contained. A false container ID would
// put ordinary host activity in front of every container rule.
func TestAHostProcessIsNotLabelledAsContained(t *testing.T) {
	for _, tc := range []struct{ name, cgroup string }{
		{"systemd user session", "0::/user.slice/user-1000.slice/session-3.scope"},
		{"systemd service", "0::/system.slice/sshd.service"},
		{"root cgroup", "0::/"},
		{"empty", ""},
		{"malformed", "not-a-cgroup-line"},
		{"short hex that is not an id", "0::/docker/abc123"},
		{"64 chars but not hex", "0::/docker/" +
			"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	} {
		if got := containerIDFromCgroup(tc.cgroup); got != "" {
			t.Errorf("%s: ホストのプロセスにコンテナID %q を付けました。"+
				"通常のホスト活動がコンテナルールの対象になります", tc.name, got)
		}
	}
}

// A privileged container keeps the full capability set; an ordinary one is
// dropped to a small subset.
func TestPrivilegedIsDistinguishedFromAnOrdinaryContainer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		capEff string
		want   bool
	}{
		// Real values, as /proc/<pid>/status prints them.
		{"privileged (5.8+ full set)", "000001ffffffffff", true},
		{"privileged (4.x full set)", "0000003fffffffff", true},
		{"docker default (14 caps)", "00000000a80425fb", false},
		{"dropped to nothing", "0000000000000000", false},
		{"unreadable", "", false},
		{"garbage", "not-hex", false},
	} {
		if got := capEffIsPrivileged(tc.capEff); got != tc.want {
			t.Errorf("%s (CapEff=%s): privileged = %v, want %v。"+
				"特権コンテナ内のシェル起動はこのフラグだけで判定します",
				tc.name, tc.capEff, got, tc.want)
		}
	}
}

// The privileged test must survive a kernel that grows CAP_LAST_CAP. An exact
// mask comparison would stop matching on the next kernel, silently.
func TestPrivilegedSurvivesAGrowingCapabilitySet(t *testing.T) {
	// A hypothetical future kernel with more capabilities than any today.
	if !capEffIsPrivileged("00000fffffffffff") {
		t.Error("将来のカーネルの完全な権限セットを特権と判定できません。" +
			"CAP_LAST_CAP はカーネル毎に増えるため、" +
			"特定バージョンのマスクとの一致で判定してはいけません")
	}
}

// CapEff is pulled out of the surrounding status file, which has dozens of
// other lines including several other Cap* fields.
func TestCapEffIsReadFromTheStatusFile(t *testing.T) {
	const status = `Name:	bash
Uid:	0	0	0	0
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
Seccomp:	0
`
	if got := capEffFromStatus(status); got != "000001ffffffffff" {
		t.Errorf("CapEff = %q", got)
	}
	if got := capEffFromStatus("Name:\tbash\n"); got != "" {
		t.Errorf("CapEff が無いのに %q を返しました", got)
	}
	// CapPrm/CapBnd must not be mistaken for CapEff — only the effective set
	// says what the process can do right now.
	const dropped = "CapPrm:\t000001ffffffffff\nCapEff:\t0000000000000000\n"
	if capEffIsPrivileged(capEffFromStatus(dropped)) {
		t.Error("CapEff がゼロなのに特権と判定しました。" +
			"CapPrm や CapBnd と取り違えています")
	}
}

// InContainer is the one place callers ask the question, and it must key on the
// ID rather than on the flags: a non-privileged container on its own network is
// still a container.
func TestInContainerKeysOnTheID(t *testing.T) {
	if (ContainerContext{}).InContainer() {
		t.Error("ゼロ値をコンテナ内と判定しました")
	}
	if !(ContainerContext{ID: "x"}).InContainer() {
		t.Error("IDがあるのにコンテナ内と判定されません")
	}
	if (ContainerContext{Privileged: true, HostNetwork: true}).InContainer() {
		t.Error("IDが無いのにコンテナ内と判定しました。" +
			"フラグだけではコンテナかどうかは決まりません")
	}
}

// EnrichProcess must actually consult the container lookup. The parsing above
// has its own tests and the call site in the batching loop has its own, but
// with a direct call to containerContextOf nothing covers the wire between
// them — deleting that one line passes every other test in this package and in
// the server, and every process event silently loses its containment.
func TestEnrichProcessReadsTheContainerContext(t *testing.T) {
	const id = "5555666677778888999900001111222233334444555566667777888899990000"

	r := NewParentResolver()
	var askedFor uint32
	r.containerOf = func(pid uint32) ContainerContext {
		askedFor = pid
		return ContainerContext{ID: id, Privileged: true}
	}

	evt := &ProcessEvent{PID: 4242, ProcessName: "bash"}
	r.EnrichProcess(evt)

	if askedFor != 4242 {
		t.Errorf("コンテナ情報を pid %d について問い合わせました (want 4242)", askedFor)
	}
	if evt.Container.ID != id {
		t.Errorf("コンテナIDがイベントに入っていません: %q。"+
			"プロセスイベントは全てコンテナ情報を失い、"+
			"コンテナ検知は直す前と同じく全滅します", evt.Container.ID)
	}
	if !evt.Container.Privileged {
		t.Error("特権フラグがイベントに入っていません")
	}
}

// A collector that already knows the containment keeps its answer, matching how
// the parent is handled.
func TestEnrichProcessDoesNotOverwriteKnownContainment(t *testing.T) {
	r := NewParentResolver()
	r.containerOf = func(uint32) ContainerContext {
		return ContainerContext{ID: "wrong"}
	}

	evt := &ProcessEvent{PID: 1, Container: ContainerContext{ID: "right"}}
	r.EnrichProcess(evt)

	if evt.Container.ID != "right" {
		t.Errorf("既知のコンテナ情報を上書きしました: %q", evt.Container.ID)
	}
}
