package store

import (
	"strings"
	"testing"
	"time"
)

// ─── buildAlertWhere tests ───────────────────────────────────────────────────

func TestBuildAlertWhere_NoFilters(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{})
	if clause != "" {
		t.Fatalf("フィルターなしはWHERE句なしのはず、got %q", clause)
	}
	if len(args) != 0 {
		t.Fatalf("引数なしのはず、got %v", args)
	}
}

func TestBuildAlertWhere_StatusOnly(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{Status: "open"})
	if !strings.HasPrefix(clause, "WHERE") {
		t.Fatalf("WHERE句で開始するはずです、got %q", clause)
	}
	if !strings.Contains(clause, "al.status = $1") {
		t.Fatalf("status条件が含まれるはずです、got %q", clause)
	}
	if len(args) != 1 || args[0] != "open" {
		t.Fatalf("引数が{open}のはずです、got %v", args)
	}
}

func TestBuildAlertWhere_SeverityOnly(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{Severity: 3})
	if !strings.Contains(clause, "al.severity >= $1") {
		t.Fatalf("severity条件が含まれるはずです、got %q", clause)
	}
	if len(args) != 1 || args[0] != 3 {
		t.Fatalf("引数が{3}のはずです、got %v", args)
	}
}

func TestBuildAlertWhere_ZeroSeverityIgnored(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{Severity: 0})
	if clause != "" {
		t.Fatalf("severity=0はフィルター対象外のはずです、got %q", clause)
	}
	if len(args) != 0 {
		t.Fatalf("引数なしのはずです、got %v", args)
	}
}

func TestBuildAlertWhere_MultipleFilters(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{
		Status:   "open",
		Severity: 2,
	})
	if !strings.Contains(clause, "AND") {
		t.Fatalf("複数フィルターはANDで結合されるはずです、got %q", clause)
	}
	if len(args) != 2 {
		t.Fatalf("引数が2つのはずです、got %d: %v", len(args), args)
	}
}

func TestBuildAlertWhere_SearchWrapsWithWildcard(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{Search: "malware"})
	if !strings.Contains(clause, "ILIKE") {
		t.Fatalf("検索はILIKEを使うはずです、got %q", clause)
	}
	if len(args) != 1 {
		t.Fatalf("引数が1つのはずです、got %v", args)
	}
	if args[0] != "%malware%" {
		t.Fatalf("検索はワイルドカードで囲まれるはずです、got %q", args[0])
	}
}

func TestBuildAlertWhere_MITRETechPrefix(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{MITRETech: "T1059"})
	if !strings.Contains(clause, "ILIKE") {
		t.Fatalf("MITRE技術はILIKEを使うはずです、got %q", clause)
	}
	if len(args) != 1 || args[0] != "T1059%" {
		t.Fatalf("MITREはプレフィックス検索のはずです、got %v", args)
	}
}

func TestBuildAlertWhere_FromTime(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clause, args := buildAlertWhere(AlertFilter{FromTime: &from})
	if !strings.Contains(clause, "al.created_at >= $1") {
		t.Fatalf("from時刻条件が含まれるはずです、got %q", clause)
	}
	if len(args) != 1 {
		t.Fatalf("引数が1つのはずです、got %v", args)
	}
}

func TestBuildAlertWhere_ToTime(t *testing.T) {
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	clause, args := buildAlertWhere(AlertFilter{ToTime: &to})
	if !strings.Contains(clause, "al.created_at <= $1") {
		t.Fatalf("to時刻条件が含まれるはずです、got %q", clause)
	}
	if len(args) != 1 {
		t.Fatalf("引数が1つのはずです、got %v", args)
	}
}

func TestBuildAlertWhere_AgentID(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{AgentID: "agent-uuid"})
	if !strings.Contains(clause, "al.agent_id = $1") {
		t.Fatalf("agent_id条件が含まれるはずです、got %q", clause)
	}
	if len(args) != 1 || args[0] != "agent-uuid" {
		t.Fatalf("引数が{agent-uuid}のはずです、got %v", args)
	}
}

func TestBuildAlertWhere_AllFilters(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	clause, args := buildAlertWhere(AlertFilter{
		Status:    "open",
		AgentID:   "agent-1",
		Severity:  3,
		Search:    "powershell",
		MITRETech: "T1059",
		FromTime:  &from,
		ToTime:    &to,
	})
	if !strings.HasPrefix(clause, "WHERE") {
		t.Fatalf("WHERE句で開始するはずです")
	}
	// 条件数: status, agent_id, severity, search, mitre, from, to = 7
	// ただしsearchは引数1つで条件1つ
	if len(args) != 7 {
		t.Fatalf("引数が7つのはずです、got %d: %v", len(args), args)
	}
}
