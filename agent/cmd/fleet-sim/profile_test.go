package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realProfileDir is the committed profile set the soak actually runs with.
const realProfileDir = "../../../tests/fpsoak/profiles"

// TestRealProfilesLoad is the guard that matters most for this tool: the
// committed profiles must parse and validate. A profile that silently fails to
// load would make a soak measure fewer host classes than it reports — and since
// fewer benign edge cases means fewer alerts, the run would look *better*, not
// broken. Validation failures have to surface here, not as a suspiciously clean
// scorecard.
func TestRealProfilesLoad(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("committed profiles failed to load: %v", err)
	}
	if len(profiles) < 5 {
		t.Fatalf("expected at least 5 committed profiles, got %d", len(profiles))
	}

	sawWindows, sawLinux, sawDarwin := false, false, false
	for _, p := range profiles {
		if err := p.Validate(); err != nil {
			t.Errorf("profile %q failed validation: %v", p.Name, err)
		}
		if p.Rates.Total() <= 0 {
			t.Errorf("profile %q has zero total rate", p.Name)
		}
		switch p.OS {
		case "windows":
			sawWindows = true
		case "linux":
			sawLinux = true
		case "darwin":
			sawDarwin = true
		}
	}
	// darwin was missing from this set until 2026-08-13, and the absence was
	// invisible: DB Sigma rules carrying platform=['macos'] are dropped by
	// rules.PlatformMatchesEvent before evaluation, so a soak with no darwin host
	// reports every macOS rule as "0 false positives" — indistinguishable, on the
	// scorecard, from a rule that is quiet because it is precise. migration 386
	// added 9 macOS-only rules and the soak that followed measured none of them
	// (P4-12). An OS with no host in this set is an OS the gate cannot see.
	if !sawWindows || !sawLinux || !sawDarwin {
		t.Errorf("profile set must cover Windows, Linux and macOS (windows=%v linux=%v darwin=%v)",
			sawWindows, sawLinux, sawDarwin)
	}
}

// TestRealProfilesCoverFPFrontier pins the reason this profile set exists. A
// soak assembled only from quiet desktop noise reports ~0 false positives and
// proves nothing; the value comes from benign behaviour that looks like an
// attack. These are the specific stateful detectors shipped in July 2026
// (discovery / lateral_fanout / file_burst / exfil_volume), and the profile set
// must keep exercising all of them.
func TestRealProfilesCoverFPFrontier(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	var (
		discoveryBurst bool // ≥4 distinct discovery commands from one host
		lateralFanout  bool // one host → many hosts on remote-admin ports
		fileBurst      bool // one process deleting many files
		externalBulk   bool // large cumulative send to a non-RFC1918 destination
		internalBulk   bool // same volume to RFC1918 — must stay silent
	)

	discoveryVerbs := []string{"whoami", "systeminfo", "ipconfig", "net user", "nltest", "tasklist"}
	adminPorts := map[int]bool{3389: true, 5985: true, 5986: true, 445: true, 22: true}

	for _, p := range profiles {
		for _, proc := range p.Processes {
			hits := 0
			for _, verb := range discoveryVerbs {
				for _, cl := range proc.CommandLines {
					if containsFold(cl, verb) {
						hits++
						break
					}
				}
			}
			if hits >= 4 {
				discoveryBurst = true
			}
		}
		for _, spec := range p.Files {
			for _, a := range spec.Actions {
				if a == "delete" && len(spec.Paths) > 0 {
					fileBurst = true
				}
			}
		}
		for _, spec := range p.Network {
			adminPort := false
			for _, port := range spec.Ports {
				if adminPorts[port] {
					adminPort = true
				}
			}
			if adminPort && len(spec.Hosts) >= 8 {
				lateralFanout = true
			}
			if len(spec.BytesSentRange) == 2 && spec.BytesSentRange[1] >= 1_000_000_000 {
				if anyExternal(spec.Hosts) {
					externalBulk = true
				} else {
					internalBulk = true
				}
			}
		}
	}

	checks := []struct {
		name string
		ok   bool
	}{
		{"discovery burst (≥4 discovery verbs from one benign process)", discoveryBurst},
		{"lateral fan-out (admin ports to ≥8 hosts)", lateralFanout},
		{"file burst (bulk deletes)", fileBurst},
		{"bulk send to an external destination", externalBulk},
		{"bulk send to an internal destination (silent control)", internalBulk},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("profile set no longer exercises the FP frontier: %s", c.name)
		}
	}
}

func TestValidateRejectsRateWithoutSpec(t *testing.T) {
	p := &Profile{
		Name: "x", OS: "linux", Users: []string{"u"}, Subnet: "10.0.0.0/24",
		Rates: Rates{Process: 10},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected an error: process rate is set but no [[processes]] exist")
	}
	if !containsFold(err.Error(), "無音") {
		t.Errorf("error should name the silent-output failure, got: %v", err)
	}
}

func TestValidateRejectsRegistryOnNonWindows(t *testing.T) {
	p := &Profile{
		Name: "x", OS: "linux", Users: []string{"u"}, Subnet: "10.0.0.0/24",
		Rates:    Rates{Registry: 10},
		Registry: []RegistrySpec{{Weight: 1, Keys: []string{"k"}, Actions: []string{"modify"}}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected registry events on a Linux profile to be rejected")
	}
}

func TestValidateRejectsBadSpecs(t *testing.T) {
	base := func() *Profile {
		return &Profile{
			Name: "x", OS: "linux", Users: []string{"u"}, Subnet: "10.0.0.0/24",
			Rates:     Rates{Process: 1, Network: 1},
			Processes: []ProcessSpec{{Weight: 1, Name: "p", CommandLines: []string{"p"}}},
			Network: []NetworkSpec{{
				Weight: 1, Hosts: []string{"1.2.3.4"}, Ports: []int{443},
			}},
		}
	}

	cases := map[string]func(*Profile){
		"zero weight":         func(p *Profile) { p.Processes[0].Weight = 0 },
		"empty cmdlines":      func(p *Profile) { p.Processes[0].CommandLines = nil },
		"inverted byte range": func(p *Profile) { p.Network[0].BytesSentRange = []int64{100, 1} },
		"one-element range":   func(p *Profile) { p.Network[0].BytesRecvRange = []int64{100} },
		"negative rate":       func(p *Profile) { p.Rates.File = -1 },
		"empty subnet":        func(p *Profile) { p.Subnet = "" },
		"no users":            func(p *Profile) { p.Users = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(p)
			if err := p.Validate(); err == nil {
				t.Errorf("expected validation to reject %s", name)
			}
		})
	}
}

func TestLoadProfilesRejectsDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	body := `
name = "dup"
os = "linux"
subnet = "10.0.0.0/24"
users = ["u"]
[rates]
process = 1
[[processes]]
weight = 1
name = "sh"
cmdlines = ["sh"]
`
	for _, f := range []string{"a.toml", "b.toml"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadProfiles(dir); err == nil {
		t.Fatal("expected duplicate profile names to be rejected")
	}
}

func TestLoadProfilesRejectsEmptyDir(t *testing.T) {
	if _, err := LoadProfiles(t.TempDir()); err == nil {
		t.Fatal("expected an empty profile directory to be an error, not an empty fleet")
	}
}

// TestAllocateFleetGuaranteesEveryProfile is the regression guard for the floor
// in AllocateFleet: without it, the low-weight noisy profiles (it-admin at 8,
// backup-server at 4) round to zero on a small run and the soak quietly stops
// measuring the behaviour it was built for.
func TestAllocateFleetGuaranteesEveryProfile(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, n := range []int{len(profiles), 10, 20, 50, 200, 1000} {
		got := AllocateFleet(profiles, n)
		if len(got) != n {
			t.Fatalf("n=%d: allocated %d hosts", n, len(got))
		}
		counts := map[string]int{}
		for _, p := range got {
			counts[p.Name]++
		}
		for _, p := range profiles {
			if counts[p.Name] == 0 {
				t.Errorf("n=%d: profile %q got no hosts", n, p.Name)
			}
		}
	}
}

func TestAllocateFleetRespectsWeights(t *testing.T) {
	profiles := []*Profile{
		{Name: "heavy", FleetWeight: 90},
		{Name: "light", FleetWeight: 10},
	}
	got := AllocateFleet(profiles, 100)
	counts := map[string]int{}
	for _, p := range got {
		counts[p.Name]++
	}
	// 2 hosts go to the per-profile floor, the remaining 98 split 90:10.
	if counts["heavy"] <= counts["light"]*5 {
		t.Errorf("weighting not applied: heavy=%d light=%d", counts["heavy"], counts["light"])
	}
	if counts["heavy"]+counts["light"] != 100 {
		t.Errorf("allocation does not sum to n: %v", counts)
	}
}

func TestAllocateFleetIsDeterministic(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	first := AllocateFleet(profiles, 137)
	for i := 0; i < 5; i++ {
		again := AllocateFleet(profiles, 137)
		for j := range first {
			if first[j].Name != again[j].Name {
				t.Fatalf("allocation is not deterministic at host %d: %q vs %q",
					j, first[j].Name, again[j].Name)
			}
		}
	}
}

func TestAllocateFleetSmallerThanProfileCount(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := AllocateFleet(profiles, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(got))
	}
}

// TestMacProfileMakesWave3RulesMeasurable pins the reason macbook.toml exists.
//
// Adding a darwin host is necessary but not sufficient: the macOS rules from
// migration 386 key on specific Image suffixes and CommandLine/TargetFilename
// substrings, so a darwin profile made only of Chrome and Slack would clear the
// platform gate and still measure nothing. The rules would stay at zero and the
// scorecard would keep reading as "quiet", which is exactly the misreading
// P4-12 records.
//
// Each check below mirrors one rule's selector *structure* — Image suffix and
// CommandLine substring have to come from the SAME process spec, because that is
// how Sigma evaluates them. A drift in either half fails here.
//
// The pairing with server/internal/detection/dark_technique_wave3_test.go is
// deliberate and the two halves are load-bearing together:
//
//	that test   given an event of this shape, the rule fires
//	this test   the benign fleet actually produces an event of that shape
//
// Neither alone establishes that the soak measures the rule.
func TestMacProfileMakesWave3RulesMeasurable(t *testing.T) {
	profiles, err := LoadProfiles(realProfileDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// 名前で取る。"最初の darwin" で取ると mac-workstation.toml が先に見つかり、
	// 第 3 波のために作られた macbook.toml ではなくそちらを検査してしまう
	// (mac-workstation の files は Safari のキャッシュと履歴の 2 spec だけで、
	// plist も .zshrc も /etc も持たない)。失敗メッセージは「macbook.toml が」と
	// 言うのに実際は別のファイルを見ている、という最悪の形になっていた。
	var mac *Profile
	for _, p := range profiles {
		if p.Name == "macbook" {
			mac = p
			break
		}
	}
	if mac == nil {
		t.Fatal("macbook.toml が読み込まれていない。macOS 専用ルールは platform ゲートで " +
			"評価対象から外れ、スコアカードでは静かなルールと区別がつかない")
	}
	if mac.OS != "darwin" {
		t.Fatalf("macbook.toml の os が %q になっている。darwin でなければ macOS ルールは "+
			"platform ゲートで落ちる", mac.OS)
	}

	// Positive coverage: benign activity that reaches each rule's selectors.
	covered := []struct {
		rule string
		ok   bool
	}{
		{
			"macOS System and Owner Discovery",
			procImageCmd(mac, []string{"/system_profiler", "/sw_vers", "/whoami", "/id", "/hostname"}, nil),
		},
		{
			"macOS Security Software Discovery",
			procImageCmd(mac,
				[]string{"/ps", "/pgrep", "/csrutil", "/spctl"},
				[]string{"csrutil status", "spctl --status", "LittleSnitch", "CrowdStrike", "santad"}),
		},
		{
			"macOS Kernel Extension Load",
			procImageCmd(mac, []string{"/kextload", "/kextutil"}, nil) ||
				procImageCmd(mac, []string{"/kmutil"}, []string{"load"}),
		},
		{
			// mac-workstation.toml (#736) との一本化で移してきた分。
			"Remote Access via VNC Server or Client",
			procImageCmd(mac, []string{"/vncviewer", "/x11vnc", "/vncserver", "/tigervncserver"}, nil),
		},
		{
			"Unix System Shutdown or Reboot",
			procImageCmd(mac, []string{"/shutdown", "/reboot", "/poweroff", "/halt"}, nil),
		},
		{
			"macOS Data Exfiltration via curl or scp Upload",
			anyCmdline(mac, func(cl string) bool {
				if strings.Contains(cl, "scp ") {
					return true
				}
				return containsFold(cl, "curl") && containsAny(cl,
					" -F ", " --form", " -T ", " --upload-file", " --data-binary @", " -d @")
			}),
		},
		{
			"Exfiltration to Cloud Storage via Native CLI",
			anyCmdline(mac, func(cl string) bool {
				return containsFold(cl, "aws") && containsFold(cl, "s3") &&
					containsAny(cl, " cp ", " sync ", "put-object")
			}),
		},
		{
			"Credential Harvesting from Shell or DB History",
			anyCmdline(mac, func(cl string) bool {
				return containsAny(cl, "cat", "less", "more", "grep", "head", "tail", "strings") &&
					containsAny(cl, ".bash_history", ".zsh_history", ".mysql_history", ".psql_history")
			}),
		},
		{
			"macOS Launch Agent or Daemon plist File Creation",
			anyFilePath(mac, func(p string) bool {
				return containsAny(p, "/Library/LaunchAgents/", "/Library/LaunchDaemons/") &&
					strings.HasSuffix(p, ".plist")
			}),
		},
		{
			"macOS Shell Startup File Modification",
			anyFilePath(mac, func(p string) bool {
				return hasAnySuffix(p, "/.zshrc", "/.zprofile", "/.bash_profile", "/.bashrc", "/.profile")
			}),
		},
		{
			// この 1 件だけは収集側の変更とセットである。migration 386 の PR で
			// darwin/file_collector.go の既定監視パスに /etc を足すまで、ここは
			// フィールドが解決するのに値が永久に来ない状態だった。
			"macOS Sudoers or Passwd Modification",
			anyFilePath(mac, func(p string) bool {
				return containsAny(p, "/etc/sudoers", "/etc/passwd")
			}),
		},
	}
	for _, c := range covered {
		if !c.ok {
			t.Errorf("macbook.toml が %q のセレクタに届かなくなった——"+
				"ルールは評価されるが決して鳴らず、スコアカード上は「精度が高い」と"+
				"区別がつかない", c.rule)
		}
	}

	// Negative controls. The soak's ground truth is structural: every alert this
	// fleet raises is a false positive BY CONSTRUCTION. That holds only while the
	// profile contains nothing an analyst would call an attack. These are the four
	// wave-3 rules deliberately left unmeasured (see macbook.toml's header) —
	// writing the behaviour in to buy coverage would not measure their FP rate, it
	// would relabel a true positive as one.
	forbidden := []struct {
		what   string
		needle []string
	}{
		{"SIP/ファイアウォールの無効化", []string{"csrutil disable", "--setglobalstate off", "--setglobalstate 0", "boot-args"}},
		{"リバースシェル", []string{"/dev/tcp/", "/dev/udp/", "bash -i", "zsh -i", "-e /bin/bash", "-e /bin/sh", "-e /bin/zsh"}},
		{"匿名アップローダへの送信", []string{"transfer.sh", "0x0.st", "file.io", "ix.io", "termbin.com", "anonfiles", "gofile.io"}},
		// VNC は「クライアントで社内へ繋ぐ」正規操作として入れてある (vncviewer)。
		// 禁止するのは**認証なしで待ち受ける側**——業務端末が -nopw で VNC サーバを
		// 上げる正当な理由は無い。
		{"認証なし VNC サーバの待ち受け", []string{"-rfbport", "-nopw", "x11vnc -display"}},
	}
	for _, f := range forbidden {
		if anyCmdline(mac, func(cl string) bool { return containsAny(cl, f.needle...) }) {
			t.Errorf("macbook.toml に %s が入っている。良性フリートに攻撃相当の挙動を"+
				"書くと、FP ソークの前提（このフリートのアラートは定義上すべて誤検知）"+
				"そのものが崩れる", f.what)
		}
	}

	// The controls above only prove something if a present string would be found.
	// Without this, a typo in containsAny would make every forbidden check pass.
	if !anyCmdline(mac, func(cl string) bool { return containsAny(cl, "csrutil status") }) {
		t.Error("対照が効いていない: 実在する文字列 'csrutil status' を検出できていないので、" +
			"上の禁止チェックが通ったことに意味が無い")
	}

	// 精度の対照。macOS Security Software Discovery は tooling (/ps /pgrep /csrutil
	// /spctl) **and** products (CrowdStrike, santad, …) を要求する。tooling 側だけに
	// 当たって products 側に当たらない入力が無いと、条件の and が or に退化していても
	// ソークでは気づけない——どちらの実装でも「鳴る」からである。
	//
	// mac-workstation.toml (#736) から移してきた pgrep がその役をする。
	products := []string{"LittleSnitch", "CrowdStrike", "falcon", "SentinelOne",
		"sentineld", "CarbonBlack", "santad", "BlockBlock", "KnockKnock"}
	toolingOnly := false
	for _, proc := range mac.Processes {
		if !hasAnySuffix(proc.Path, "/ps", "/pgrep") {
			continue
		}
		for _, cl := range proc.CommandLines {
			if !containsAny(cl, products...) {
				toolingOnly = true
			}
		}
	}
	if !toolingOnly {
		t.Error("tooling セレクタには当たるが products セレクタには当たらない入力が無い。" +
			"macOS Security Software Discovery の `tooling and products` が and として" +
			"効いているかを、このプロファイルでは確かめられない")
	}
}

// ─── helpers ──────────────────────────────────────────────────

// procImageCmd reports whether one process spec has both an image path ending in
// any of imageSuffixes and (when cmdSubstrings is non-empty) a command line
// containing any of them. Both from the same spec, as Sigma evaluates them.
func procImageCmd(p *Profile, imageSuffixes, cmdSubstrings []string) bool {
	for _, proc := range p.Processes {
		if !hasAnySuffix(proc.Path, imageSuffixes...) {
			continue
		}
		if len(cmdSubstrings) == 0 {
			return true
		}
		for _, cl := range proc.CommandLines {
			if containsAny(cl, cmdSubstrings...) {
				return true
			}
		}
	}
	return false
}

func anyCmdline(p *Profile, match func(string) bool) bool {
	for _, proc := range p.Processes {
		for _, cl := range proc.CommandLines {
			if match(cl) {
				return true
			}
		}
	}
	return false
}

func anyFilePath(p *Profile, match func(string) bool) bool {
	for _, spec := range p.Files {
		for _, path := range spec.Paths {
			if match(path) {
				return true
			}
		}
	}
	return false
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func anyExternal(hosts []string) bool {
	for _, h := range hosts {
		ip := net.ParseIP(h)
		if ip == nil {
			continue
		}
		if !ip.IsPrivate() && !ip.IsLoopback() {
			return true
		}
	}
	return false
}
