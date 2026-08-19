//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// netshRecorder captures the argv the restore path would hand to netsh. The
// property under test is which policy gets written back, and that cannot be
// observed by actually running netsh without changing the test machine's
// firewall.
type netshRecorder struct{ calls []string }

func (r *netshRecorder) run(args ...string) error {
	r.calls = append(r.calls, strings.Join(args, " "))
	return nil
}

func (r *netshRecorder) ran(want string) bool {
	for _, c := range r.calls {
		if c == want {
			return true
		}
	}
	return false
}

// The regression this guards: Windows blocks inbound by default, and unisolate
// used to write allowinbound unconditionally, so one isolate/unisolate cycle
// left every profile accepting inbound connections permanently.
func TestRestoreFirewallPolicyPutsBackBlockInbound(t *testing.T) {
	snap := fwSnapshot{
		"domainprofile":  {Enabled: 1, Inbound: 1, Outbound: 0},
		"privateprofile": {Enabled: 1, Inbound: 1, Outbound: 0},
		"publicprofile":  {Enabled: 1, Inbound: 1, Outbound: 0},
	}
	r := &netshRecorder{}
	if errs := restoreFirewallPolicy(snap, r.run); len(errs) != 0 {
		t.Fatalf("復元でエラー: %v", errs)
	}

	for _, p := range []string{"domainprofile", "privateprofile", "publicprofile"} {
		want := "advfirewall set " + p + " firewallpolicy blockinbound,allowoutbound"
		if !r.ran(want) {
			t.Errorf("既定ポリシーが復元されていない\n want: %s\n  got: %v", want, r.calls)
		}
	}
	for _, c := range r.calls {
		if strings.Contains(c, "allowinbound") {
			t.Errorf("受信許可を書き戻してはならない: %s", c)
		}
		if strings.Contains(c, "allprofiles") {
			t.Errorf("プロファイルごとに復元すべき（allprofiles では個別の設定が潰れる）: %s", c)
		}
	}
}

// A host that had the firewall switched off must come back switched off.
func TestRestoreFirewallPolicyPutsBackDisabledFirewall(t *testing.T) {
	r := &netshRecorder{}
	restoreFirewallPolicy(fwSnapshot{"publicprofile": {Enabled: 0, Inbound: 1, Outbound: 0}}, r.run)

	if !r.ran("advfirewall set publicprofile state off") {
		t.Fatalf("無効だったファイアウォールが有効のまま残る: %v", r.calls)
	}
}

// blockinboundalways is a distinct third state. Collapsing it to blockinbound
// would re-enable every allow rule the operator had chosen to suppress.
func TestRestoreFirewallPolicyPreservesBlockInboundAlways(t *testing.T) {
	r := &netshRecorder{}
	restoreFirewallPolicy(fwSnapshot{
		"domainprofile": {Enabled: 1, Inbound: 1, Outbound: 0, NoExceptions: 1},
	}, r.run)

	if !r.ran("advfirewall set domainprofile firewallpolicy blockinboundalways,allowoutbound") {
		t.Fatalf("blockinboundalways が保存されていない: %v", r.calls)
	}
}

// Policy must be written before state: flipping a profile off first would drop
// the firewall for the gap between the two commands.
func TestRestoreFirewallPolicyOrdersPolicyBeforeState(t *testing.T) {
	r := &netshRecorder{}
	restoreFirewallPolicy(fwSnapshot{"publicprofile": {Enabled: 1, Inbound: 1}}, r.run)

	if len(r.calls) != 2 {
		t.Fatalf("プロファイルあたり2コマンドのはず: %v", r.calls)
	}
	if !strings.Contains(r.calls[0], "firewallpolicy") || !strings.Contains(r.calls[1], "state") {
		t.Fatalf("policy → state の順でなければならない: %v", r.calls)
	}
}

// An outbound-blocking profile is unusual but legitimate, and isolation must
// not be the thing that opens it.
func TestRestoreFirewallPolicyPutsBackBlockOutbound(t *testing.T) {
	r := &netshRecorder{}
	restoreFirewallPolicy(fwSnapshot{"privateprofile": {Enabled: 1, Inbound: 1, Outbound: 1}}, r.run)

	if !r.ran("advfirewall set privateprofile firewallpolicy blockinbound,blockoutbound") {
		t.Fatalf("送信ブロックが復元されていない: %v", r.calls)
	}
}

// Isolation outlives the agent process, so the snapshot has to survive a
// restart — otherwise an agent bounce between isolate and unisolate loses the
// only record of what the policy was.
func TestFirewallPolicyRoundTripsThroughDisk(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())

	want := fwSnapshot{
		"domainprofile": {Enabled: 1, Inbound: 1, Outbound: 0, NoExceptions: 1},
		"publicprofile": {Enabled: 0, Inbound: 0, Outbound: 1},
	}
	if err := saveFirewallPolicy(want); err != nil {
		t.Fatalf("保存に失敗: %v", err)
	}

	got := loadFirewallPolicy()
	if len(got) != len(want) {
		t.Fatalf("復元されたプロファイル数が違う: got %d, want %d", len(got), len(want))
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v, want %+v", k, got[k], w)
		}
	}

	clearFirewallPolicyState()
	if loadFirewallPolicy() != nil {
		t.Error("解除後もスナップショットが残っている")
	}
}

// No snapshot must mean "leave the policy alone", never "write allow".
func TestLoadFirewallPolicyReturnsNilWhenAbsentOrCorrupt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)

	if got := loadFirewallPolicy(); got != nil {
		t.Fatalf("ファイルが無いのに値を返した: %+v", got)
	}

	path := filepath.Join(dir, "EDRAgent", "isolation-firewall-policy.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"{", "{}", ""} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := loadFirewallPolicy(); got != nil {
			t.Errorf("壊れた内容 %q から値を返した: %+v", body, got)
		}
	}
}

// The live reader must not invent a policy that leaves the host open: whatever
// the registry says, an absent value has to fall back to Windows' own default
// of blocked inbound.
func TestReadFirewallPolicyDefaultsToBlockedInbound(t *testing.T) {
	snap, err := readFirewallPolicy()
	if err != nil {
		t.Fatalf("読み取りに失敗: %v", err)
	}
	if len(snap) != len(fwProfiles) {
		t.Fatalf("3プロファイル分そろっていない: %+v", snap)
	}
	if fwDefaultInbound != 1 {
		t.Error("受信の既定はブロックでなければならない")
	}
}
