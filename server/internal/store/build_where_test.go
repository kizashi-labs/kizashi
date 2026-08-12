package store

import (
	"strings"
	"testing"
	"time"
)

// ─── buildAlertWhere ──────────────────────────────────────────────────────────

func TestBuildAlertWhere_EmptyFilter(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{})
	if clause != "" {
		t.Errorf("空フィルターのWHERE句は空文字列のはず: got %q", clause)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターの引数は空のはず: got %v", args)
	}
}

func TestBuildAlertWhere_StatusFilter(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{Status: "open"})
	if !strings.HasPrefix(clause, "WHERE") {
		t.Errorf("WHERE句で始まるべき: %q", clause)
	}
	if !strings.Contains(clause, "al.status = $1") {
		t.Errorf("status条件が含まれるべき: %q", clause)
	}
	if len(args) != 1 || args[0] != "open" {
		t.Errorf("args = %v, want [open]", args)
	}
}

func TestBuildAlertWhere_SeverityFilter(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{Severity: 7})
	if !strings.Contains(clause, "al.severity >= $1") {
		t.Errorf("severity条件が含まれるべき: %q", clause)
	}
	if len(args) != 1 || args[0] != 7 {
		t.Errorf("args = %v, want [7]", args)
	}
}

func TestBuildAlertWhere_SeverityZeroIgnored(t *testing.T) {
	// Severity=0 は無視される
	clause, _ := buildAlertWhere(AlertFilter{Severity: 0})
	if strings.Contains(clause, "severity") {
		t.Errorf("Severity=0 は条件に含まれるべきでない: %q", clause)
	}
}

func TestBuildAlertWhere_SearchFilter(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{Search: "malware"})
	if !strings.Contains(clause, "ILIKE") {
		t.Errorf("ILIKE検索条件が含まれるべき: %q", clause)
	}
	if len(args) != 1 {
		t.Fatalf("args の数 = %d, want 1", len(args))
	}
	searchArg, ok := args[0].(string)
	if !ok {
		t.Fatalf("args[0] は string のはず")
	}
	if !strings.Contains(searchArg, "malware") {
		t.Errorf("検索引数に 'malware' が含まれるべき: %q", searchArg)
	}
}

func TestBuildAlertWhere_MultipleFilters_BuildWhere(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{
		Status:   "open",
		Severity: 5,
		AgentID:  "agent-uuid-123",
	})
	if !strings.Contains(clause, "AND") {
		t.Errorf("複数条件はANDで結合されるべき: %q", clause)
	}
	if len(args) != 3 {
		t.Errorf("引数は3個のはず: got %d", len(args))
	}
}

func TestBuildAlertWhere_FromTimeFilter(t *testing.T) {
	now := time.Now()
	clause, args := buildAlertWhere(AlertFilter{FromTime: &now})
	if !strings.Contains(clause, "al.created_at >= $1") {
		t.Errorf("FromTime条件が含まれるべき: %q", clause)
	}
	if len(args) != 1 {
		t.Errorf("引数は1個のはず: got %d", len(args))
	}
}

func TestBuildAlertWhere_ToTimeFilter(t *testing.T) {
	now := time.Now()
	clause, args := buildAlertWhere(AlertFilter{ToTime: &now})
	if !strings.Contains(clause, "al.created_at <= $1") {
		t.Errorf("ToTime条件が含まれるべき: %q", clause)
	}
	if len(args) != 1 {
		t.Errorf("引数は1個のはず: got %d", len(args))
	}
}

func TestBuildAlertWhere_TimeRangeFilter(t *testing.T) {
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()
	clause, args := buildAlertWhere(AlertFilter{FromTime: &from, ToTime: &to})
	if !strings.Contains(clause, "created_at >= $1") {
		t.Errorf("FromTime条件が含まれるべき: %q", clause)
	}
	if !strings.Contains(clause, "created_at <= $2") {
		t.Errorf("ToTime条件が$2であるべき: %q", clause)
	}
	if len(args) != 2 {
		t.Errorf("引数は2個のはず: got %d", len(args))
	}
}

func TestBuildAlertWhere_MITRETechFilter(t *testing.T) {
	clause, args := buildAlertWhere(AlertFilter{MITRETech: "T1059"})
	if !strings.Contains(clause, "mitre_technique") {
		t.Errorf("MITRE条件が含まれるべき: %q", clause)
	}
	if len(args) != 1 {
		t.Errorf("引数は1個のはず: got %d", len(args))
	}
	techArg, ok := args[0].(string)
	if !ok {
		t.Fatal("args[0] は string のはず")
	}
	if !strings.HasPrefix(techArg, "T1059") {
		t.Errorf("MITRE引数は 'T1059' で始まるべき: %q", techArg)
	}
}

func TestBuildAlertWhere_AgentIDFilter(t *testing.T) {
	agentID := "550e8400-e29b-41d4-a716-446655440000"
	clause, args := buildAlertWhere(AlertFilter{AgentID: agentID})
	if !strings.Contains(clause, "al.agent_id = $1") {
		t.Errorf("agent_id条件が含まれるべき: %q", clause)
	}
	if len(args) != 1 || args[0] != agentID {
		t.Errorf("args = %v, want [%s]", args, agentID)
	}
}
