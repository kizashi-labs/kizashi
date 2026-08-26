package detection

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeContainmentLookup struct {
	recent   bool
	err      error
	calls    int
	gotAgent string
	gotWin   time.Duration
}

func (f *fakeContainmentLookup) RecentContainment(_ context.Context, agentID string, within time.Duration) (bool, error) {
	f.calls++
	f.gotAgent = agentID
	f.gotWin = within
	return f.recent, f.err
}

func fwAlert() *StoredAlert {
	return &StoredAlert{
		AgentID:  "11111111-1111-1111-1111-111111111111",
		Title:    "[SIGMA] New Firewall Rule Added Via Netsh.EXE",
		RuleName: "New Firewall Rule Added Via Netsh.EXE",
	}
}

// The loop this exists to break: containment adds firewall rules, and the
// firewall-modification rule then alerts on them.
func TestSuppressesFirewallAlertRightAfterOurOwnContainment(t *testing.T) {
	lookup := &fakeContainmentLookup{recent: true}
	s := NewSelfRemediationSuppressor(lookup)

	if !s.IsSelfInflicted(context.Background(), fwAlert()) {
		t.Fatal("自分の隔離に由来するアラートが抑止されていない")
	}
	if lookup.gotAgent != fwAlert().AgentID {
		t.Errorf("照会したエージェントが違う: %s", lookup.gotAgent)
	}
	if lookup.gotWin != selfRemediationWindow {
		t.Errorf("窓が違う: %v", lookup.gotWin)
	}
}

// The security property. Naming a firewall rule EDR-ISOLATE-… must not buy an
// attacker anything, so suppression requires that WE dispatched containment —
// a state an attacker cannot arrange.
func TestDoesNotSuppressWithoutRecentContainment(t *testing.T) {
	s := NewSelfRemediationSuppressor(&fakeContainmentLookup{recent: false})

	if s.IsSelfInflicted(context.Background(), fwAlert()) {
		t.Fatal("封じ込めを送出していないのに抑止した — 検知回避の穴になる")
	}
}

// Everything that is not a firewall change stays visible even inside the window:
// containing a host must not blind us to what it does next.
func TestDoesNotSuppressUnrelatedAlertsInsideTheWindow(t *testing.T) {
	lookup := &fakeContainmentLookup{recent: true}
	s := NewSelfRemediationSuppressor(lookup)

	for _, a := range []*StoredAlert{
		{AgentID: "a", Title: "[SIGMA] LSASS Access via Task Manager or Comsvcs", RuleName: "LSASS Access"},
		{AgentID: "a", Title: "[HEURISTIC] ランサムウェアの疑い", RuleName: "ransomware"},
		{AgentID: "a", Title: "[PROC-CORRELATION] 稼働中インプラントの疑い", RuleName: "proc correlation"},
	} {
		if s.IsSelfInflicted(context.Background(), a) {
			t.Errorf("無関係なアラートを抑止した: %s", a.Title)
		}
	}
	if lookup.calls != 0 {
		t.Errorf("種別で足切りできていない（DBを%d回引いた）", lookup.calls)
	}
}

// A lookup failure must fail open. Dropping alerts because the database could
// not answer would turn a database problem into a detection outage.
func TestFailsOpenWhenLookupErrors(t *testing.T) {
	s := NewSelfRemediationSuppressor(&fakeContainmentLookup{err: errors.New("db down")})

	if s.IsSelfInflicted(context.Background(), fwAlert()) {
		t.Fatal("照会失敗時に抑止した — 検知を止める方向に倒れている")
	}
}

// A nil suppressor is the "not configured" state and must be safe to call, since
// both engines invoke it unconditionally.
func TestNilSuppressorNeverSuppresses(t *testing.T) {
	var s *SelfRemediationSuppressor
	if s.IsSelfInflicted(context.Background(), fwAlert()) {
		t.Fatal("nil が抑止した")
	}
	if NewSelfRemediationSuppressor(nil) != nil {
		t.Fatal("lookup が nil なら nil を返すべき（無言の no-op を作らない）")
	}
}

// An alert with no agent cannot be attributed to a containment action.
func TestDoesNotSuppressWhenAgentUnknown(t *testing.T) {
	lookup := &fakeContainmentLookup{recent: true}
	s := NewSelfRemediationSuppressor(lookup)

	a := fwAlert()
	a.AgentID = ""
	if s.IsSelfInflicted(context.Background(), a) {
		t.Fatal("エージェント不明のアラートを抑止した")
	}
	if lookup.calls != 0 {
		t.Error("エージェント不明でDBを引いた")
	}
}

func TestDescribesFirewallChange(t *testing.T) {
	cases := []struct {
		title string
		want  bool
	}{
		{"[SIGMA] New Firewall Rule Added Via Netsh.EXE", true},
		{"[SIGMA] Firewall Rule Deleted Via Netsh.EXE", true},
		{"[SIGMA] Windows Firewall Disabled via Netsh", true},
		{"[SIGMA] ファイアウォール規則の追加", true},
		{"[SIGMA] Internal Proxy via netsh portproxy", true},
		{"[SIGMA] SAM Database Dump via reg.exe", false},
		{"[MEMORY] 不審な実行メモリ領域: powershell.exe", false},
		{"", false},
	}
	for _, c := range cases {
		got := describesFirewallChange(&StoredAlert{Title: c.title})
		if got != c.want {
			t.Errorf("%q: got %v, want %v", c.title, got, c.want)
		}
	}
}
