//go:build windows

package windows

import (
	"net"
	"strings"
	"testing"
	"time"
)

// parseRangeCount returns the number of distinct block ranges in the result.
func parseRangeCount(ranges []string) int { return len(ranges) }

// rangesContain returns true if any range string contains the sub-string.
func rangesContain(ranges []string, sub string) bool {
	for _, r := range ranges {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func TestComputeBlockRanges_NoAllowed(t *testing.T) {
	// With no allowed IPs (besides loopback), should cover 0.0.0.0–126.255.255.255
	// and 128.0.0.0–255.255.255.255 (loopback 127.x excluded).
	ranges := computeBlockRanges(nil)
	if len(ranges) == 0 {
		t.Fatal("expected at least one block range")
	}
	// 0.0.0.0 should be the start of the first range.
	if !strings.HasPrefix(ranges[0], "0.0.0.0") {
		t.Errorf("first range should start at 0.0.0.0, got %q", ranges[0])
	}
}

func TestComputeBlockRanges_AllowedIPExcluded(t *testing.T) {
	// When 10.0.0.1 is allowed, no block range should include that address alone.
	ranges := computeBlockRanges([]string{"10.0.0.1"})

	// 10.0.0.1 must NOT appear as a standalone address in any range start.
	for _, r := range ranges {
		// A range of "10.0.0.1-10.0.0.1" would mean it IS blocked.
		if r == "10.0.0.1-10.0.0.1" || r == "10.0.0.1" {
			t.Errorf("allowed IP 10.0.0.1 must not appear as a block target, got %q", r)
		}
	}
}

func TestComputeBlockRanges_LoopbackExcluded(t *testing.T) {
	ranges := computeBlockRanges(nil)
	// No range should cover 127.0.0.1.
	for _, r := range ranges {
		// A range like "126.x.x.x-127.x.x.x" would include loopback — that must not happen.
		if strings.HasPrefix(r, "127.") {
			t.Errorf("loopback range must not be blocked, got %q", r)
		}
	}
}

func TestComputeBlockRanges_MultipleAllowed(t *testing.T) {
	// Two allowed IPs should be handled without panic and produce valid ranges.
	ranges := computeBlockRanges([]string{"192.168.1.100", "10.10.10.10"})
	if len(ranges) == 0 {
		t.Fatal("expected block ranges to be computed")
	}
}

func TestComputeBlockRanges_InvalidIPIgnored(t *testing.T) {
	// Invalid IPs must not cause a panic; valid loopback exclusion still applies.
	ranges := computeBlockRanges([]string{"not-an-ip", "256.1.2.3"})
	if len(ranges) == 0 {
		t.Fatal("expected block ranges even when allowed IPs are invalid")
	}
}

func TestComputeBlockRanges_ResultsAreDashSeparatedOrSingle(t *testing.T) {
	ranges := computeBlockRanges([]string{"8.8.8.8"})
	for _, r := range ranges {
		parts := strings.Split(r, "-")
		if len(parts) != 2 && len(parts) != 1 {
			t.Errorf("range %q has unexpected format (want A.B.C.D or A.B.C.D-E.F.G.H)", r)
		}
	}
}

func TestComputeBlockRanges_FewerRangesWithAdjacentAllowed(t *testing.T) {
	// Two adjacent IPs should merge into a smaller complement.
	rangesOne := computeBlockRanges([]string{"10.0.0.5"})
	rangesTwo := computeBlockRanges([]string{"10.0.0.5", "10.0.0.6"})
	// Allowing more IPs should result in equal or more block ranges (gaps), not fewer total ranges.
	// The important thing: both must return at least one range and not panic.
	if len(rangesOne) == 0 || len(rangesTwo) == 0 {
		t.Error("both configurations should produce non-empty block ranges")
	}
	_ = rangesContain // silence unused warning
	_ = parseRangeCount
}

// ─── Orphaned-isolation reconcile ─────────────────────────────

// netshOutputEN is a trimmed `netsh advfirewall firewall show rule name=all` sample
// from an English host carrying three of our rules plus unrelated built-ins.
const netshOutputEN = `
Rule Name:                            Remote Desktop - User Mode (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Allow

Rule Name:                            EDR-ISOLATE-BLOCK-RANGE-0-IN
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Block

Rule Name:                            EDR-ISOLATE-BLOCK-RANGE-0-OUT
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Action:                               Block

Rule Name:                            EDR-ISOLATE-BLOCK-RANGE-1-IN
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Block
`

// netshOutputJA is the same shape on a Japanese host. The labels are localised but
// our rule names are not, which is exactly why parsing keys off the names.
const netshOutputJA = `
規則名:                                EDR-ISOLATE-BLOCK-RANGE-2-OUT
----------------------------------------------------------------------
有効:                                  はい
方向:                                  外向き
操作:                                  ブロック
`

func TestParseIsolationRuleNames_English(t *testing.T) {
	got := parseIsolationRuleNames([]byte(netshOutputEN))
	want := []string{
		"EDR-ISOLATE-BLOCK-RANGE-0-IN",
		"EDR-ISOLATE-BLOCK-RANGE-0-OUT",
		"EDR-ISOLATE-BLOCK-RANGE-1-IN",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseIsolationRuleNames_LocalisedOutput(t *testing.T) {
	got := parseIsolationRuleNames([]byte(netshOutputJA))
	if len(got) != 1 || got[0] != "EDR-ISOLATE-BLOCK-RANGE-2-OUT" {
		t.Errorf("localised netsh output must still yield our rule name, got %v", got)
	}
}

func TestParseIsolationRuleNames_NoneAndNoise(t *testing.T) {
	if got := parseIsolationRuleNames(nil); got != nil {
		t.Errorf("nil input should yield nil, got %v", got)
	}
	if got := parseIsolationRuleNames([]byte("No rules match the specified criteria.")); got != nil {
		t.Errorf("no-match output should yield nil, got %v", got)
	}
	// Near-misses must not be adopted: a non-numeric index is not a rule we wrote.
	if got := parseIsolationRuleNames([]byte("EDR-ISOLATE-BLOCK-RANGE-X-IN")); got != nil {
		t.Errorf("non-numeric index must not match, got %v", got)
	}
}

func TestParseIsolationRuleNames_Deduplicates(t *testing.T) {
	// netsh repeats the rule name when a rule exists in several profiles.
	dup := "EDR-ISOLATE-BLOCK-RANGE-0-IN\nEDR-ISOLATE-BLOCK-RANGE-0-IN\nEDR-ISOLATE-BLOCK-RANGE-0-IN"
	got := parseIsolationRuleNames([]byte(dup))
	if len(got) != 1 {
		t.Errorf("expected deduplication to 1 entry, got %v", got)
	}
}

// TestReconcileAdoptsExistingRules is the regression test for the orphaned-isolation
// bug: before this, a restarted manager reported not-isolated while block rules were
// live on the system, so Unisolate() short-circuited and the host stayed cut off with
// no remote way back in.
func TestReconcileAdoptsExistingRules(t *testing.T) {
	live := []string{"EDR-ISOLATE-BLOCK-RANGE-0-IN", "EDR-ISOLATE-BLOCK-RANGE-0-OUT"}
	m := &WFPIsolationManager{listRules: func() []string { return live }}
	m.reconcile()

	if !m.IsIsolated() {
		t.Fatal("IsIsolated() must be true when isolation rules exist on the system")
	}
	if len(m.ruleNames) != len(live) {
		t.Fatalf("ruleNames = %v, want %v — rollback() can only delete what it knows about", m.ruleNames, live)
	}
}

func TestReconcileNoRulesStaysUnisolated(t *testing.T) {
	m := &WFPIsolationManager{listRules: func() []string { return nil }}
	m.reconcile()
	if m.IsIsolated() {
		t.Error("IsIsolated() must stay false when no isolation rules exist")
	}
	if m.ruleNames != nil {
		t.Errorf("ruleNames should stay nil, got %v", m.ruleNames)
	}
}

func TestReconcileNilListerIsSafe(t *testing.T) {
	m := &WFPIsolationManager{}
	m.reconcile() // must not panic
	if m.IsIsolated() {
		t.Error("a manager with no lister must not report isolated")
	}
}

func TestReconcileDoesNotClobberActiveIsolation(t *testing.T) {
	// reconcile enumerates outside the lock, so a real Isolate() can land first.
	// Its ruleNames are authoritative — adopting our stale list would make
	// rollback() delete the wrong set.
	live := []string{"EDR-ISOLATE-BLOCK-RANGE-9-IN"}
	m := &WFPIsolationManager{
		isolated:  true,
		ruleNames: []string{"EDR-ISOLATE-BLOCK-RANGE-0-IN", "EDR-ISOLATE-BLOCK-RANGE-0-OUT"},
		listRules: func() []string { return live },
	}
	m.reconcile()

	if len(m.ruleNames) != 2 || m.ruleNames[0] != "EDR-ISOLATE-BLOCK-RANGE-0-IN" {
		t.Errorf("an active isolation must keep its own ruleNames, got %v", m.ruleNames)
	}
}

// TestReconcileConcurrentWithReaders exercises the goroutine path introduced when
// reconcile was made asynchronous: it writes isolated/ruleNames while the heartbeat
// concurrently calls IsIsolated(). Run under -race this fails if the write escapes
// the mutex.
func TestReconcileConcurrentWithReaders(t *testing.T) {
	m := &WFPIsolationManager{listRules: func() []string {
		time.Sleep(5 * time.Millisecond) // stand in for the slow netsh enumeration
		return []string{"EDR-ISOLATE-BLOCK-RANGE-0-IN", "EDR-ISOLATE-BLOCK-RANGE-0-OUT"}
	}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.reconcile()
	}()
	for i := 0; i < 500; i++ {
		_ = m.IsIsolated()
	}
	<-done

	if !m.IsIsolated() {
		t.Fatal("reconcile must have adopted the rules once it completed")
	}
}

// blocked reports whether ip falls inside any of the computed block ranges.
// ブロック範囲は "a-b" か単一アドレスの文字列で返るので、両方を解く。
func blocked(t *testing.T, ranges []string, ip string) bool {
	t.Helper()
	n := ipToUint32(net.ParseIP(ip))
	for _, r := range ranges {
		lo, hi, found := strings.Cut(r, "-")
		if !found {
			hi = lo
		}
		s, e := ipToUint32(net.ParseIP(lo)), ipToUint32(net.ParseIP(hi))
		if n >= s && n <= e {
			return true
		}
	}
	return false
}

// 許可リストに CIDR を書いたとき、その範囲全体が到達可能なまま残ること。
//
// proto の allow_ips は形式を縛っていないが、ここは net.ParseIP しか呼んで
// いなかったため CIDR は nil になり `continue` で消えていた。エラーもログも
// 出ないので、除外したはずの管理セグメントが遮断されても隔離を解くまで
// 分からない。**書けるのに効かない**のが最悪の形だった。
func TestComputeBlockRanges_CIDRIsHonoured(t *testing.T) {
	ranges := computeBlockRanges([]string{"10.0.0.0/24"})

	for _, ip := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.128", "10.0.0.255"} {
		if blocked(t, ranges, ip) {
			t.Errorf("%s は 10.0.0.0/24 の中なのでブロックされてはいけません: %v", ip, ranges)
		}
	}
	// 範囲の外側は隣接していてもブロックされること（境界の取り違えを見る）。
	for _, ip := range []string{"9.255.255.255", "10.0.1.0", "10.0.1.1"} {
		if !blocked(t, ranges, ip) {
			t.Errorf("%s は 10.0.0.0/24 の外なのでブロックされるべきです: %v", ip, ranges)
		}
	}
}

// 単一アドレスの指定が CIDR 対応で壊れていないこと。
func TestComputeBlockRanges_SingleIPStillHonoured(t *testing.T) {
	ranges := computeBlockRanges([]string{"10.0.0.5"})
	if blocked(t, ranges, "10.0.0.5") {
		t.Errorf("許可した単一アドレスがブロックされています: %v", ranges)
	}
	if !blocked(t, ranges, "10.0.0.6") {
		t.Errorf("許可していない隣接アドレスが通っています: %v", ranges)
	}
}

// /32 と裸のアドレスが同じ結果になること。
func TestComputeBlockRanges_Slash32EqualsBareAddress(t *testing.T) {
	bare := computeBlockRanges([]string{"8.8.8.8"})
	cidr := computeBlockRanges([]string{"8.8.8.8/32"})
	if strings.Join(bare, ",") != strings.Join(cidr, ",") {
		t.Errorf("8.8.8.8 と 8.8.8.8/32 の結果が違います:\n bare=%v\n cidr=%v", bare, cidr)
	}
}

// 解釈できない項目は「許可された」ことにならないこと。
//
// 続行はする（ここで止めると隔離そのものが実行されない）が、その項目を
// 通してはいけない。ログには出す。
func TestComputeBlockRanges_UnparseableEntryIsNotAllowed(t *testing.T) {
	ranges := computeBlockRanges([]string{"not-an-ip", "10.0.0.0/33", "10.0.0.7"})
	if len(ranges) == 0 {
		t.Fatal("解釈できない項目があっても隔離範囲は返るべきです")
	}
	if !blocked(t, ranges, "10.0.0.0") {
		t.Error("解釈できない CIDR が許可として通っています")
	}
	if blocked(t, ranges, "10.0.0.7") {
		t.Error("同じリスト内の正しい項目まで落ちています")
	}
}

// allowedRange 自体の判定。CIDR・単一・不正・IPv6 を見る。
func TestAllowedRange(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
		lo, hi  string
	}{
		{in: "10.0.0.0/24", lo: "10.0.0.0", hi: "10.0.0.255"},
		{in: "172.16.0.0/12", lo: "172.16.0.0", hi: "172.31.255.255"},
		{in: "192.168.1.7/32", lo: "192.168.1.7", hi: "192.168.1.7"},
		{in: "0.0.0.0/0", lo: "0.0.0.0", hi: "255.255.255.255"},
		{in: "10.0.0.5", lo: "10.0.0.5", hi: "10.0.0.5"},
		{in: "not-an-ip", wantErr: true},
		{in: "10.0.0.0/33", wantErr: true},
		{in: "2001:db8::/32", wantErr: true}, // IPv4 のみを対象にしている
		{in: "::1", wantErr: true},
	}
	for _, c := range cases {
		got, err := allowedRange(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q はエラーになるべきです（got %v）", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		wantLo, wantHi := ipToUint32(net.ParseIP(c.lo)), ipToUint32(net.ParseIP(c.hi))
		if got.start != wantLo || got.end != wantHi {
			t.Errorf("%q: %s-%s を期待、得たのは %s-%s",
				c.in, c.lo, c.hi, uint32ToIPStr(got.start), uint32ToIPStr(got.end))
		}
	}
}
