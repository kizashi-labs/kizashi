package store

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─── AgentFilter 構造体テスト ─────────────────────────────────────────────────

// TestAgentFilter_ZeroValue は AgentFilter のゼロ値を確認する
func TestAgentFilter_ZeroValue(t *testing.T) {
	var f AgentFilter
	if f.OSType != "" {
		t.Errorf("OSType のデフォルト = %q, want \"\"", f.OSType)
	}
	if f.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", f.Status)
	}
	if f.GroupID != "" {
		t.Errorf("GroupID のデフォルト = %q, want \"\"", f.GroupID)
	}
	if f.Search != "" {
		t.Errorf("Search のデフォルト = %q, want \"\"", f.Search)
	}
	if f.Limit != 0 {
		t.Errorf("Limit のデフォルト = %d, want 0", f.Limit)
	}
	if f.Offset != 0 {
		t.Errorf("Offset のデフォルト = %d, want 0", f.Offset)
	}
}

// TestAgentFilter_FieldAssignment はフィールド代入が正しく反映されることを確認する
func TestAgentFilter_FieldAssignment(t *testing.T) {
	f := AgentFilter{
		OSType:  "windows",
		Status:  "online",
		GroupID: "group-uuid-001",
		Search:  "dc-server",
		Limit:   50,
		Offset:  100,
	}
	if f.OSType != "windows" {
		t.Errorf("OSType = %q, want \"windows\"", f.OSType)
	}
	if f.Status != "online" {
		t.Errorf("Status = %q, want \"online\"", f.Status)
	}
	if f.GroupID != "group-uuid-001" {
		t.Errorf("GroupID = %q, want \"group-uuid-001\"", f.GroupID)
	}
	if f.Search != "dc-server" {
		t.Errorf("Search = %q, want \"dc-server\"", f.Search)
	}
	if f.Limit != 50 {
		t.Errorf("Limit = %d, want 50", f.Limit)
	}
	if f.Offset != 100 {
		t.Errorf("Offset = %d, want 100", f.Offset)
	}
}

// ─── buildAgentWhere ライクなロジックテスト（ListAgents内の条件ビルダー）─────
// ListAgentsはDB呼び出しを含むため直接テストできないが、
// フィルターが生成する条件の文字列を手動で再現してテストする

// buildAgentWhereConditions は agents.go の ListAgents 内と同じロジックで
// WHERE句の条件リストと引数を構築するヘルパー（テスト専用）
func buildAgentWhereConditions(filter AgentFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	i := 1

	if filter.OSType != "" {
		conditions = append(conditions, fmt.Sprintf("os_type = $%d", i))
		args = append(args, filter.OSType)
		i++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", i))
		args = append(args, filter.Status)
		i++
	}
	if filter.GroupID != "" {
		conditions = append(conditions, fmt.Sprintf("group_id = $%d", i))
		args = append(args, filter.GroupID)
		i++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(hostname ILIKE $%d OR ...)", i))
		args = append(args, "%"+filter.Search+"%")
	}
	return conditions, args
}

// TestAgentFilter_EmptyFilterProducesNoClauses は空フィルターが条件なしになることを確認する
func TestAgentFilter_EmptyFilterProducesNoClauses(t *testing.T) {
	clauses, args := buildAgentWhereConditions(AgentFilter{})
	if len(clauses) != 0 {
		t.Errorf("空フィルターは条件なしのはず: got %v", clauses)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestAgentFilter_OSTypeProducesClause はOSTypeフィルターが条件を生成することを確認する
func TestAgentFilter_OSTypeProducesClause(t *testing.T) {
	clauses, args := buildAgentWhereConditions(AgentFilter{OSType: "linux"})
	if len(clauses) != 1 {
		t.Fatalf("OSTypeフィルターは1条件のはず: got %v", clauses)
	}
	if !strings.Contains(clauses[0], "os_type") {
		t.Errorf("条件に os_type が含まれるべき: %q", clauses[0])
	}
	if len(args) != 1 || args[0] != "linux" {
		t.Errorf("引数 = %v, want [linux]", args)
	}
}

// TestAgentFilter_SearchWrapsWithWildcards は検索文字列がワイルドカードで囲まれることを確認する
func TestAgentFilter_SearchWrapsWithWildcards(t *testing.T) {
	_, args := buildAgentWhereConditions(AgentFilter{Search: "webserver"})
	if len(args) != 1 {
		t.Fatalf("引数は1つのはず: got %v", args)
	}
	searchArg, ok := args[0].(string)
	if !ok {
		t.Fatalf("引数はstringのはず")
	}
	if !strings.HasPrefix(searchArg, "%") || !strings.HasSuffix(searchArg, "%") {
		t.Errorf("検索引数は%%で囲まれるべき: %q", searchArg)
	}
	if !strings.Contains(searchArg, "webserver") {
		t.Errorf("検索引数に元の文字列が含まれるべき: %q", searchArg)
	}
}

// TestAgentFilter_MultipleConditionsAreAggregated は複数フィルターが条件を累積することを確認する
func TestAgentFilter_MultipleConditionsAreAggregated(t *testing.T) {
	clauses, args := buildAgentWhereConditions(AgentFilter{
		OSType:  "windows",
		Status:  "isolated",
		GroupID: "grp-001",
	})
	if len(clauses) != 3 {
		t.Errorf("3フィルターは3条件のはず: got %d: %v", len(clauses), clauses)
	}
	if len(args) != 3 {
		t.Errorf("3フィルターは3引数のはず: got %d: %v", len(args), args)
	}
}

// ─── AgentRow 構造体テスト ────────────────────────────────────────────────────

// TestAgentRow_DefaultValues は AgentRow のゼロ値を確認する
func TestAgentRow_DefaultValues(t *testing.T) {
	var a AgentRow
	if a.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", a.ID)
	}
	if a.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", a.Status)
	}
	if a.LastSeen != nil {
		t.Errorf("LastSeen のデフォルトは nil であるべき")
	}
	if a.GroupID != nil {
		t.Errorf("GroupID のデフォルトは nil であるべき")
	}
	if a.PolicyID != nil {
		t.Errorf("PolicyID のデフォルトは nil であるべき")
	}
	if a.TLSThumbprint != nil {
		t.Errorf("TLSThumbprint のデフォルトは nil であるべき")
	}
	if a.IsolatedAt != nil {
		t.Errorf("IsolatedAt のデフォルトは nil であるべき")
	}
	if a.Tags != nil {
		// Tags はnil スライスが期待される
		if len(a.Tags) != 0 {
			t.Errorf("Tags のデフォルトは空のはず")
		}
	}
}

// TestAgentRow_FieldAssignment はフィールド代入が正しく動作することを確認する
func TestAgentRow_FieldAssignment(t *testing.T) {
	now := time.Now()
	groupID := "group-abc"
	policyID := "policy-xyz"
	thumbprint := "aa:bb:cc:dd"
	isolatedReason := "Suspicious activity detected"
	isolatedBy := "admin@example.com"

	a := AgentRow{
		ID:             "agent-001",
		Hostname:       "win-workstation-01",
		OSType:         "windows",
		OSVersion:      "Windows 11",
		AgentVersion:   "2.0.0",
		IPAddresses:    []string{"192.168.1.10", "10.0.0.5"},
		Status:         "online",
		LastSeen:       &now,
		EnrolledAt:     now,
		GroupID:        &groupID,
		PolicyID:       &policyID,
		ConfigVersion:  3,
		TLSThumbprint:  &thumbprint,
		Tags:           []string{"production", "critical"},
		IsolatedAt:     &now,
		IsolatedReason: &isolatedReason,
		IsolatedBy:     &isolatedBy,
	}

	if a.ID != "agent-001" {
		t.Errorf("ID = %q, want \"agent-001\"", a.ID)
	}
	if a.Hostname != "win-workstation-01" {
		t.Errorf("Hostname = %q, want \"win-workstation-01\"", a.Hostname)
	}
	if a.OSType != "windows" {
		t.Errorf("OSType = %q, want \"windows\"", a.OSType)
	}
	if len(a.IPAddresses) != 2 {
		t.Errorf("IPAddresses の長さ = %d, want 2", len(a.IPAddresses))
	}
	if a.IPAddresses[0] != "192.168.1.10" {
		t.Errorf("IPAddresses[0] = %q, want \"192.168.1.10\"", a.IPAddresses[0])
	}
	if a.ConfigVersion != 3 {
		t.Errorf("ConfigVersion = %d, want 3", a.ConfigVersion)
	}
	if len(a.Tags) != 2 {
		t.Errorf("Tags の長さ = %d, want 2", len(a.Tags))
	}
	if a.GroupID == nil || *a.GroupID != groupID {
		t.Errorf("GroupID = %v, want %q", a.GroupID, groupID)
	}
	if a.IsolatedReason == nil || *a.IsolatedReason != isolatedReason {
		t.Errorf("IsolatedReason = %v, want %q", a.IsolatedReason, isolatedReason)
	}
}

// TestAgentRow_IPAddresses はIPアドレスの複数値を扱えることを確認する
func TestAgentRow_IPAddresses(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "192.168.1.1"}
	a := AgentRow{IPAddresses: ips}
	if len(a.IPAddresses) != 3 {
		t.Fatalf("IPAddresses の長さ = %d, want 3", len(a.IPAddresses))
	}
	for i, ip := range ips {
		if a.IPAddresses[i] != ip {
			t.Errorf("IPAddresses[%d] = %q, want %q", i, a.IPAddresses[i], ip)
		}
	}
}

// ─── AgentGroup 構造体テスト ──────────────────────────────────────────────────

// TestAgentGroup_DefaultValues は AgentGroup のゼロ値を確認する
func TestAgentGroup_DefaultValues(t *testing.T) {
	var g AgentGroup
	if g.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", g.ID)
	}
	if g.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", g.Name)
	}
	if g.AgentCount != 0 {
		t.Errorf("AgentCount のデフォルト = %d, want 0", g.AgentCount)
	}
}

// TestAgentGroup_FieldAssignment は AgentGroup フィールドの代入を確認する
func TestAgentGroup_FieldAssignment(t *testing.T) {
	now := time.Now()
	g := AgentGroup{
		ID:          "group-001",
		Name:        "Production Servers",
		Description: "本番環境サーバーグループ",
		AgentCount:  15,
		CreatedAt:   now,
	}
	if g.ID != "group-001" {
		t.Errorf("ID = %q, want \"group-001\"", g.ID)
	}
	if g.Name != "Production Servers" {
		t.Errorf("Name = %q, want \"Production Servers\"", g.Name)
	}
	if g.Description != "本番環境サーバーグループ" {
		t.Errorf("Description = %q, want \"本番環境サーバーグループ\"", g.Description)
	}
	if g.AgentCount != 15 {
		t.Errorf("AgentCount = %d, want 15", g.AgentCount)
	}
	if !g.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", g.CreatedAt, now)
	}
}

// TestAgentGroup_ZeroAgentCount はエージェントのいないグループが正しく表現されることを確認する
func TestAgentGroup_ZeroAgentCount(t *testing.T) {
	g := AgentGroup{
		ID:         "empty-group",
		Name:       "Empty Group",
		AgentCount: 0,
	}
	if g.AgentCount != 0 {
		t.Errorf("AgentCount = %d, want 0", g.AgentCount)
	}
}

// ─── AgentRow アイソレーション状態テスト ──────────────────────────────────────

// TestAgentRow_IsolatedState はアイソレーション状態のAgentRowを確認する
func TestAgentRow_IsolatedState(t *testing.T) {
	isolatedAt := time.Now().Add(-30 * time.Minute)
	reason := "Ransomware suspected"
	by := "soc-analyst"

	a := AgentRow{
		Status:         "isolated",
		IsolatedAt:     &isolatedAt,
		IsolatedReason: &reason,
		IsolatedBy:     &by,
	}

	if a.Status != "isolated" {
		t.Errorf("Status = %q, want \"isolated\"", a.Status)
	}
	if a.IsolatedAt == nil {
		t.Fatal("IsolatedAt はnil でないべき")
	}
	if !a.IsolatedAt.Equal(isolatedAt) {
		t.Errorf("IsolatedAt = %v, want %v", *a.IsolatedAt, isolatedAt)
	}
	if a.IsolatedReason == nil || *a.IsolatedReason != reason {
		t.Errorf("IsolatedReason = %v, want %q", a.IsolatedReason, reason)
	}
	if a.IsolatedBy == nil || *a.IsolatedBy != by {
		t.Errorf("IsolatedBy = %v, want %q", a.IsolatedBy, by)
	}
}

// TestAgentRow_OnlineStateHasNilIsolationFields はオンライン状態ではアイソレーションフィールドがnilであることを確認する
func TestAgentRow_OnlineStateHasNilIsolationFields(t *testing.T) {
	a := AgentRow{Status: "online"}
	if a.IsolatedAt != nil {
		t.Error("オンライン状態では IsolatedAt は nil であるべき")
	}
	if a.IsolatedReason != nil {
		t.Error("オンライン状態では IsolatedReason は nil であるべき")
	}
	if a.IsolatedBy != nil {
		t.Error("オンライン状態では IsolatedBy は nil であるべき")
	}
}
