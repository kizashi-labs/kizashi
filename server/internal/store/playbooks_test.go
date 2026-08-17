package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── PlaybookConditions 構造体テスト ──────────────────────────────────────────

// TestPlaybookConditions_ZeroValue は PlaybookConditions のゼロ値が期待通りであることを確認する
func TestPlaybookConditions_ZeroValue(t *testing.T) {
	var c PlaybookConditions
	if c.MinSeverity != 0 {
		t.Errorf("MinSeverity のデフォルト = %d, want 0", c.MinSeverity)
	}
	if c.MaxSeverity != 0 {
		t.Errorf("MaxSeverity のデフォルト = %d, want 0", c.MaxSeverity)
	}
	if c.RuleName != "" {
		t.Errorf("RuleName のデフォルト = %q, want \"\"", c.RuleName)
	}
	if c.Hostname != "" {
		t.Errorf("Hostname のデフォルト = %q, want \"\"", c.Hostname)
	}
	if c.MITRETechnique != "" {
		t.Errorf("MITRETechnique のデフォルト = %q, want \"\"", c.MITRETechnique)
	}
	if c.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", c.Status)
	}
}

// TestPlaybookConditions_SeverityRange は MinSeverity と MaxSeverity の境界値を確認する
func TestPlaybookConditions_SeverityRange(t *testing.T) {
	cases := []struct {
		min, max int
		valid    bool
	}{
		{1, 10, true},
		{5, 5, true}, // min == max は同一レベルのみマッチ
		{3, 7, true},
		{0, 0, true}, // 0 は「未設定」を表す
	}
	for _, tc := range cases {
		c := PlaybookConditions{MinSeverity: tc.min, MaxSeverity: tc.max}
		if c.MinSeverity != tc.min || c.MaxSeverity != tc.max {
			t.Errorf("Severity範囲 (%d-%d) の設定に失敗", tc.min, tc.max)
		}
	}
}

// TestPlaybookConditions_JSONRoundTrip は PlaybookConditions が JSON に正しく変換されることを確認する
func TestPlaybookConditions_JSONRoundTrip(t *testing.T) {
	original := PlaybookConditions{
		MinSeverity:    3,
		MaxSeverity:    10,
		RuleName:       "mimikatz",
		Hostname:       "workstation-01",
		MITRETechnique: "T1003",
		Status:         "new",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("JSON マーシャルに失敗: %v", err)
	}

	var decoded PlaybookConditions
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON アンマーシャルに失敗: %v", err)
	}

	if decoded.MinSeverity != original.MinSeverity {
		t.Errorf("MinSeverity = %d, want %d", decoded.MinSeverity, original.MinSeverity)
	}
	if decoded.RuleName != original.RuleName {
		t.Errorf("RuleName = %q, want %q", decoded.RuleName, original.RuleName)
	}
	if decoded.MITRETechnique != original.MITRETechnique {
		t.Errorf("MITRETechnique = %q, want %q", decoded.MITRETechnique, original.MITRETechnique)
	}
}

// ─── PlaybookAction 構造体テスト ──────────────────────────────────────────────

// TestPlaybookAction_ZeroValue は PlaybookAction のゼロ値を確認する
func TestPlaybookAction_ZeroValue(t *testing.T) {
	var a PlaybookAction
	if a.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", a.Type)
	}
	if a.Title != "" {
		t.Errorf("Title のデフォルト = %q, want \"\"", a.Title)
	}
	if a.Severity != 0 {
		t.Errorf("Severity のデフォルト = %d, want 0", a.Severity)
	}
	if a.Message != "" {
		t.Errorf("Message のデフォルト = %q, want \"\"", a.Message)
	}
	if a.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", a.UserID)
	}
}

// TestPlaybookAction_KnownTypes は既知のアクションタイプが正しく設定できることを確認する
// "isolate_endpoint" | "create_incident" | "notify" | "assign_alert" の4つが標準
func TestPlaybookAction_KnownTypes(t *testing.T) {
	knownTypes := []string{
		"isolate_endpoint",
		"create_incident",
		"notify",
		"assign_alert",
	}
	for _, at := range knownTypes {
		a := PlaybookAction{Type: at}
		if a.Type != at {
			t.Errorf("Type = %q, want %q", a.Type, at)
		}
	}
}

// TestPlaybookAction_CreateIncidentFields は create_incident アクションの必須フィールドを確認する
func TestPlaybookAction_CreateIncidentFields(t *testing.T) {
	a := PlaybookAction{
		Type:     "create_incident",
		Title:    "自動インシデント作成",
		Severity: 8,
	}
	if a.Type != "create_incident" {
		t.Errorf("Type = %q, want \"create_incident\"", a.Type)
	}
	if a.Title == "" {
		t.Error("create_incident では Title が設定されるべき")
	}
	if a.Severity == 0 {
		t.Error("create_incident では Severity が設定されるべき")
	}
}

// TestPlaybookAction_NotifyFields は notify アクションの必須フィールドを確認する
func TestPlaybookAction_NotifyFields(t *testing.T) {
	a := PlaybookAction{
		Type:    "notify",
		Message: "セキュリティアラートが検出されました",
	}
	if a.Type != "notify" {
		t.Errorf("Type = %q, want \"notify\"", a.Type)
	}
	if a.Message == "" {
		t.Error("notify では Message が設定されるべき")
	}
}

// TestPlaybookAction_AssignAlertFields は assign_alert アクションの必須フィールドを確認する
func TestPlaybookAction_AssignAlertFields(t *testing.T) {
	a := PlaybookAction{
		Type:   "assign_alert",
		UserID: "analyst-user-uuid",
	}
	if a.Type != "assign_alert" {
		t.Errorf("Type = %q, want \"assign_alert\"", a.Type)
	}
	if a.UserID == "" {
		t.Error("assign_alert では UserID が設定されるべき")
	}
}

// TestPlaybookAction_JSONRoundTrip は PlaybookAction の JSON ラウンドトリップを確認する
func TestPlaybookAction_JSONRoundTrip(t *testing.T) {
	original := PlaybookAction{
		Type:     "create_incident",
		Title:    "Critical Alert Detected",
		Severity: 9,
		Message:  "Automated incident created",
		UserID:   "user-001",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("JSON マーシャルに失敗: %v", err)
	}

	var decoded PlaybookAction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON アンマーシャルに失敗: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("Type = %q, want %q", decoded.Type, original.Type)
	}
	if decoded.Title != original.Title {
		t.Errorf("Title = %q, want %q", decoded.Title, original.Title)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity = %d, want %d", decoded.Severity, original.Severity)
	}
}

// ─── Playbook 構造体テスト ─────────────────────────────────────────────────────

// TestPlaybook_ZeroValue は Playbook のゼロ値を確認する
func TestPlaybook_ZeroValue(t *testing.T) {
	var p Playbook
	if p.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", p.ID)
	}
	if p.IsActive {
		t.Error("IsActive のデフォルトは false であるべき")
	}
	if p.RunCount != 0 {
		t.Errorf("RunCount のデフォルト = %d, want 0", p.RunCount)
	}
	if p.LastRunAt != nil {
		t.Errorf("LastRunAt のデフォルトは nil であるべき")
	}
	if p.CreatedBy != nil {
		t.Errorf("CreatedBy のデフォルトは nil であるべき")
	}
}

// TestPlaybook_ActionsSlice は Playbook の Actions スライス操作を確認する
func TestPlaybook_ActionsSlice(t *testing.T) {
	p := Playbook{
		ID:   "pb-001",
		Name: "Critical Alert Response",
		Actions: []PlaybookAction{
			{Type: "isolate_endpoint"},
			{Type: "create_incident", Title: "Critical Incident", Severity: 9},
			{Type: "notify", Message: "Critical alert triggered"},
		},
	}

	if len(p.Actions) != 3 {
		t.Errorf("Actions 件数 = %d, want 3", len(p.Actions))
	}
	if p.Actions[0].Type != "isolate_endpoint" {
		t.Errorf("Actions[0].Type = %q, want \"isolate_endpoint\"", p.Actions[0].Type)
	}
	if p.Actions[1].Severity != 9 {
		t.Errorf("Actions[1].Severity = %d, want 9", p.Actions[1].Severity)
	}
}

// TestPlaybook_RunCountIncrement は RunCount のインクリメントロジックを確認する
func TestPlaybook_RunCountIncrement(t *testing.T) {
	p := Playbook{ID: "pb-002", RunCount: 0}

	// 実行ごとに RunCount が増加する
	for expected := 1; expected <= 5; expected++ {
		p.RunCount++
		if p.RunCount != expected {
			t.Errorf("RunCount = %d, want %d", p.RunCount, expected)
		}
	}
}

// TestPlaybook_LastRunAtUpdate は LastRunAt の更新を確認する
func TestPlaybook_LastRunAtUpdate(t *testing.T) {
	p := Playbook{ID: "pb-003"}
	if p.LastRunAt != nil {
		t.Error("初期状態では LastRunAt は nil であるべき")
	}

	now := time.Now()
	p.LastRunAt = &now
	if p.LastRunAt == nil {
		t.Fatal("実行後は LastRunAt が nil でないべき")
	}
	if !p.LastRunAt.Equal(now) {
		t.Errorf("LastRunAt = %v, want %v", *p.LastRunAt, now)
	}
}

// ─── PlaybookRun 構造体テスト ─────────────────────────────────────────────────

// TestPlaybookRun_ZeroValue は PlaybookRun のゼロ値を確認する
func TestPlaybookRun_ZeroValue(t *testing.T) {
	var r PlaybookRun
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Success {
		t.Error("Success のデフォルトは false であるべき")
	}
	if r.ErrorMsg != "" {
		t.Errorf("ErrorMsg のデフォルト = %q, want \"\"", r.ErrorMsg)
	}
	if r.ActionsRun != nil {
		t.Errorf("ActionsRun のデフォルトは nil であるべき: got %v", r.ActionsRun)
	}
}

// TestPlaybookRun_SuccessfulRun は成功した実行記録のフィールドを確認する
func TestPlaybookRun_SuccessfulRun(t *testing.T) {
	now := time.Now()
	r := PlaybookRun{
		ID:         "run-001",
		PlaybookID: "pb-001",
		AlertID:    "alert-abc",
		ActionsRun: []PlaybookAction{
			{Type: "isolate_endpoint"},
		},
		Success: true,
		RanAt:   now,
	}

	if !r.Success {
		t.Error("成功フラグが true であるべき")
	}
	if r.ErrorMsg != "" {
		t.Errorf("成功時に ErrorMsg は空であるべき: got %q", r.ErrorMsg)
	}
	if len(r.ActionsRun) != 1 {
		t.Errorf("ActionsRun 件数 = %d, want 1", len(r.ActionsRun))
	}
}

// TestPlaybookRun_FailedRun は失敗した実行記録のフィールドを確認する
func TestPlaybookRun_FailedRun(t *testing.T) {
	r := PlaybookRun{
		ID:         "run-002",
		PlaybookID: "pb-001",
		AlertID:    "alert-xyz",
		Success:    false,
		ErrorMsg:   "エンドポイントへの接続がタイムアウトしました",
	}

	if r.Success {
		t.Error("失敗フラグが false であるべき")
	}
	if r.ErrorMsg == "" {
		t.Error("失敗時に ErrorMsg が設定されるべき")
	}
}

// ─── containsStr と条件マッチングロジックテスト ──────────────────────────────

// playbookMatchesSeverity は **本物を呼びます。**
//
// 以前ここには `matches` の重要度の部分を書き写したものが置いてあり、
// そちらだけが試されていました。**プレイブックが動くかどうかの判定です**
// —— 条件が合わなければ、自動対応は一度も走りません。走らなかったことは、
// 画面では「対応が要らなかった」と同じ姿になります。
//
// 他の条件は空にして呼びます（空 = 指定なし）。
func playbookMatchesSeverity(cond PlaybookConditions, severity int) bool {
	return cond.matches(severity, "", "", "", "")
}

// TestPlaybookMatchesSeverity_InRange は範囲内の severity がマッチすることを確認する
func TestPlaybookMatchesSeverity_InRange(t *testing.T) {
	cond := PlaybookConditions{MinSeverity: 5, MaxSeverity: 10}
	cases := []struct {
		severity int
		want     bool
	}{
		{5, true},
		{7, true},
		{10, true},
		{4, false},
		{11, false},
	}
	for _, tc := range cases {
		got := playbookMatchesSeverity(cond, tc.severity)
		if got != tc.want {
			t.Errorf("severity=%d: got %v, want %v", tc.severity, got, tc.want)
		}
	}
}

// TestPlaybookMatchesSeverity_NoRange は MinSeverity=MaxSeverity=0 のとき全 severity がマッチすることを確認する
func TestPlaybookMatchesSeverity_NoRange(t *testing.T) {
	cond := PlaybookConditions{} // 未設定
	for _, sev := range []int{1, 5, 10, 100} {
		if !playbookMatchesSeverity(cond, sev) {
			t.Errorf("範囲未設定のとき severity=%d はマッチするべき", sev)
		}
	}
}

// TestContainsStr_PlaybookRuleName はルール名の部分一致を確認する
func TestContainsStr_PlaybookRuleName(t *testing.T) {
	// Playbook の条件マッチングで使用される containsStr の動作を確認する
	cases := []struct {
		ruleName  string
		condition string
		want      bool
	}{
		{"mimikatz_credential_dump", "mimikatz", true},
		{"ransomware_filecrypt", "RANSOMWARE", true}, // 大文字小文字無視
		{"lateral_movement_psexec", "psexec", true},
		{"benign_activity", "malware", false},
	}
	for _, tc := range cases {
		got := containsStr(tc.ruleName, tc.condition)
		if got != tc.want {
			t.Errorf("containsStr(%q, %q) = %v, want %v", tc.ruleName, tc.condition, got, tc.want)
		}
	}
}

// ─── Playbook 条件マッチングの複合テスト ─────────────────────────────────────

// playbookMatchesAll は **本物を呼びます。**
func playbookMatchesAll(cond PlaybookConditions, severity int, ruleName, hostname, mitreTechnique, status string) bool {
	return cond.matches(severity, ruleName, hostname, mitreTechnique, status)
}

// TestPlaybookMatchesAll_AllConditions は全条件が一致するアラートがマッチすることを確認する
func TestPlaybookMatchesAll_AllConditions(t *testing.T) {
	cond := PlaybookConditions{
		MinSeverity:    7,
		RuleName:       "mimikatz",
		Hostname:       "workstation",
		MITRETechnique: "T1003",
		Status:         "new",
	}
	matched := playbookMatchesAll(cond, 9, "mimikatz_dump", "workstation-01", "T1003.001", "new")
	if !matched {
		t.Error("全条件一致のアラートはマッチするべき")
	}
}

// TestPlaybookMatchesAll_SeverityMismatch は severity がミスマッチのときマッチしないことを確認する
func TestPlaybookMatchesAll_SeverityMismatch(t *testing.T) {
	cond := PlaybookConditions{MinSeverity: 8}
	if playbookMatchesAll(cond, 5, "any_rule", "any_host", "", "") {
		t.Error("MinSeverity=8 のとき severity=5 はマッチしないべき")
	}
}

// TestPlaybookMatchesAll_StatusMismatch は Status が完全一致しないときマッチしないことを確認する
func TestPlaybookMatchesAll_StatusMismatch(t *testing.T) {
	cond := PlaybookConditions{Status: "new"}
	// "investigating" は "new" と一致しない
	if playbookMatchesAll(cond, 5, "", "", "", "investigating") {
		t.Error("Status ミスマッチのときマッチしないべき")
	}
}

// ─── Playbook 表示名ロジックテスト ───────────────────────────────────────────

// TestPlaybook_CreatedByName は作成者表示名の取得ロジックを確認する
func TestPlaybook_CreatedByName(t *testing.T) {
	// フルネームが優先、なければメール、なければ空文字
	cases := []struct {
		fullName string
		email    string
		want     string
	}{
		{"Alice Tanaka", "alice@example.com", "Alice Tanaka"},
		{"", "bob@example.com", "bob@example.com"},
		{"", "", ""},
	}

	for _, tc := range cases {
		got := ""
		if tc.fullName != "" {
			got = tc.fullName
		} else if tc.email != "" {
			got = tc.email
		}
		if !strings.Contains(got, tc.want) && got != tc.want {
			t.Errorf("作成者表示名: got %q, want %q", got, tc.want)
		}
	}
}
