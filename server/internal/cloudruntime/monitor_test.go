package cloudruntime

import (
	"context"
	"testing"
)

// ─── NewMonitor ───────────────────────────────────────────────────────────────

func TestNewMonitor_NotNil(t *testing.T) {
	m := NewMonitor(nil)
	if m == nil {
		t.Fatal("NewMonitor は nil を返すべきではありません")
	}
}

func TestNewMonitor_PoolNil(t *testing.T) {
	m := NewMonitor(nil)
	if m.pool != nil {
		t.Error("pool=nil で作成したとき pool は nil であるべきです")
	}
}

// ─── DetectRuntimeThreats (pool=nil) ─────────────────────────────────────────

func TestDetectRuntimeThreats_NilPool_ReturnsEmpty(t *testing.T) {
	m := NewMonitor(nil)
	threats, err := m.DetectRuntimeThreats(context.Background(), 24)
	if err != nil {
		t.Fatalf("DetectRuntimeThreats (pool=nil): 予期しないエラー: %v", err)
	}
	if len(threats) != 0 {
		t.Errorf("DetectRuntimeThreats (pool=nil): got %d threats, want 0", len(threats))
	}
}

// ─── GetRuntimeStats (pool=nil) ───────────────────────────────────────────────

func TestGetRuntimeStats_NilPool_ByTypeInitialized(t *testing.T) {
	m := NewMonitor(nil)
	stats := m.GetRuntimeStats(context.Background())
	if stats.ByType == nil {
		t.Error("GetRuntimeStats (pool=nil): ByType は初期化されているべきです")
	}
}

func TestGetRuntimeStats_NilPool_TotalThreatsZero(t *testing.T) {
	m := NewMonitor(nil)
	stats := m.GetRuntimeStats(context.Background())
	if stats.TotalThreats != 0 {
		t.Errorf("GetRuntimeStats (pool=nil): TotalThreats got %d, want 0", stats.TotalThreats)
	}
}

// ─── classifyRuntimeThreat ────────────────────────────────────────────────────

func TestClassifyRuntimeThreat_Xmrig_IsCryptoMining(t *testing.T) {
	threatType, _, mitre, severity := classifyRuntimeThreat("xmrig", "", false, false)
	if threatType != "crypto_mining" {
		t.Errorf("xmrig threatType: got %q, want crypto_mining", threatType)
	}
	if mitre != "T1496" {
		t.Errorf("xmrig MITRE: got %q, want T1496", mitre)
	}
	if severity != 8 {
		t.Errorf("xmrig severity: got %d, want 8", severity)
	}
}

func TestClassifyRuntimeThreat_CmdlineXmrig_IsCryptoMining(t *testing.T) {
	threatType, _, _, _ := classifyRuntimeThreat("worker", "xmrig --pool stratum+tcp://pool.example.com", false, false)
	if threatType != "crypto_mining" {
		t.Errorf("xmrig cmdline: got %q, want crypto_mining", threatType)
	}
}

func TestClassifyRuntimeThreat_ContainerEscape(t *testing.T) {
	threatType, _, mitre, severity := classifyRuntimeThreat("bash", "cat /proc/1/root/etc/passwd", false, false)
	if threatType != "container_escape" {
		t.Errorf("container escape: got %q, want container_escape", threatType)
	}
	if mitre != "T1611" {
		t.Errorf("container escape MITRE: got %q, want T1611", mitre)
	}
	if severity != 9 {
		t.Errorf("container escape severity: got %d, want 9", severity)
	}
}

func TestClassifyRuntimeThreat_PrivilegedShell(t *testing.T) {
	threatType, _, mitre, severity := classifyRuntimeThreat("bash", "", true, false)
	if threatType != "privilege_escalation" {
		t.Errorf("privileged bash: got %q, want privilege_escalation", threatType)
	}
	if mitre != "T1078" {
		t.Errorf("privileged bash MITRE: got %q, want T1078", mitre)
	}
	if severity != 7 {
		t.Errorf("privileged bash severity: got %d, want 7", severity)
	}
}

func TestClassifyRuntimeThreat_HostNetwork(t *testing.T) {
	threatType, _, mitre, severity := classifyRuntimeThreat("nc", "nc -lvp 4444", false, true)
	if threatType != "unusual_process" {
		t.Errorf("host network: got %q, want unusual_process", threatType)
	}
	if mitre != "T1205" {
		t.Errorf("host network MITRE: got %q, want T1205", mitre)
	}
	if severity != 6 {
		t.Errorf("host network severity: got %d, want 6", severity)
	}
}

func TestClassifyRuntimeThreat_Default_IsUnusual(t *testing.T) {
	threatType, _, mitre, severity := classifyRuntimeThreat("unknownproc", "some args", false, false)
	if threatType != "unusual_process" {
		t.Errorf("default: got %q, want unusual_process", threatType)
	}
	if mitre != "T1059" {
		t.Errorf("default MITRE: got %q, want T1059", mitre)
	}
	if severity != 5 {
		t.Errorf("default severity: got %d, want 5", severity)
	}
}

// ─── containsAny ──────────────────────────────────────────────────────────────

func TestContainsAny_Found_ReturnsTrue(t *testing.T) {
	if !containsAny("hello world", []string{"world"}) {
		t.Error("containsAny: 含まれる文字列で true を返すべきです")
	}
}

func TestContainsAny_NotFound_ReturnsFalse(t *testing.T) {
	if containsAny("hello world", []string{"xyz"}) {
		t.Error("containsAny: 含まれない文字列で false を返すべきです")
	}
}

func TestContainsAny_EmptySubs_ReturnsFalse(t *testing.T) {
	if containsAny("hello", []string{}) {
		t.Error("containsAny: 空サブ文字列リストで false を返すべきです")
	}
}

func TestContainsAny_MultipleMatches_ReturnsTrue(t *testing.T) {
	if !containsAny("xmrig --pool stratum+tcp://", []string{"minerd", "stratum+tcp"}) {
		t.Error("containsAny: 複数の候補で一致する場合 true を返すべきです")
	}
}

func TestContainsAny_EmptyString_ReturnsFalse(t *testing.T) {
	if containsAny("", []string{"sub"}) {
		t.Error("containsAny: 空文字列で false を返すべきです")
	}
}
