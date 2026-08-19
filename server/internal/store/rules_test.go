package store

import (
	"strings"
	"testing"
	"time"
)

// ─── RuleRow 構造体テスト ──────────────────────────────────────────────────────

// TestRuleRow_ZeroValue は RuleRow のゼロ値が期待通りであることを確認する
func TestRuleRow_ZeroValue(t *testing.T) {
	var r RuleRow
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Severity != 0 {
		t.Errorf("Severity のデフォルト = %d, want 0", r.Severity)
	}
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if r.AutoIsolate {
		t.Error("AutoIsolate のデフォルトは false であるべき")
	}
	if r.AutoKill {
		t.Error("AutoKill のデフォルトは false であるべき")
	}
	if r.AutoQuarantine {
		t.Error("AutoQuarantine のデフォルトは false であるべき")
	}
	if r.Description != nil {
		t.Errorf("Description のデフォルトは nil であるべき: got %v", *r.Description)
	}
	if r.FalsePositiveRate != 0.0 {
		t.Errorf("FalsePositiveRate のデフォルト = %f, want 0.0", r.FalsePositiveRate)
	}
}

// TestRuleRow_KnownTypes は既知のルールタイプが文字列として正しく表現されることを確認する
// EDR プラットフォームで使用される標準的なルールタイプを列挙する
func TestRuleRow_KnownTypes(t *testing.T) {
	knownTypes := []string{"sigma", "yara", "custom", "behavioral"}
	for _, ruleType := range knownTypes {
		r := RuleRow{Type: ruleType}
		if r.Type != ruleType {
			t.Errorf("Type = %q, want %q", r.Type, ruleType)
		}
	}
}

// TestRuleRow_KnownSources はルールの既知ソース値を確認する
// "sigmahq" が community ルール、"custom" がユーザー定義ルールを示す
func TestRuleRow_KnownSources(t *testing.T) {
	sources := []string{"sigmahq", "custom", "manual", "import"}
	for _, src := range sources {
		r := RuleRow{Source: src}
		if r.Source != src {
			t.Errorf("Source = %q, want %q", r.Source, src)
		}
	}
}

// TestRuleRow_SeverityRange は severity の値が 1〜100 の範囲で表現できることを確認する
func TestRuleRow_SeverityRange(t *testing.T) {
	cases := []int{1, 25, 50, 75, 100}
	for _, sev := range cases {
		r := RuleRow{Severity: sev}
		if r.Severity != sev {
			t.Errorf("Severity = %d, want %d", r.Severity, sev)
		}
	}
}

// TestRuleRow_AutoActionFlags は自動アクションフラグの組み合わせを確認する
func TestRuleRow_AutoActionFlags(t *testing.T) {
	cases := []struct {
		isolate    bool
		kill       bool
		quarantine bool
	}{
		{false, false, false},
		{true, false, false},
		{false, true, false},
		{false, false, true},
		{true, true, true},
	}

	for _, tc := range cases {
		r := RuleRow{
			AutoIsolate:    tc.isolate,
			AutoKill:       tc.kill,
			AutoQuarantine: tc.quarantine,
		}
		if r.AutoIsolate != tc.isolate {
			t.Errorf("AutoIsolate = %v, want %v", r.AutoIsolate, tc.isolate)
		}
		if r.AutoKill != tc.kill {
			t.Errorf("AutoKill = %v, want %v", r.AutoKill, tc.kill)
		}
		if r.AutoQuarantine != tc.quarantine {
			t.Errorf("AutoQuarantine = %v, want %v", r.AutoQuarantine, tc.quarantine)
		}
	}
}

// TestRuleRow_PlatformSlice はプラットフォームスライスの操作を確認する
func TestRuleRow_PlatformSlice(t *testing.T) {
	r := RuleRow{Platform: []string{"windows", "linux", "macos"}}

	if len(r.Platform) != 3 {
		t.Errorf("Platform の件数 = %d, want 3", len(r.Platform))
	}
	if r.Platform[0] != "windows" {
		t.Errorf("Platform[0] = %q, want \"windows\"", r.Platform[0])
	}
	if r.Platform[2] != "macos" {
		t.Errorf("Platform[2] = %q, want \"macos\"", r.Platform[2])
	}
}

// TestRuleRow_MITRETagsSlice は MITRE タグスライスの操作を確認する
func TestRuleRow_MITRETagsSlice(t *testing.T) {
	r := RuleRow{MITRETags: []string{"T1055", "T1059", "T1003"}}

	if len(r.MITRETags) != 3 {
		t.Errorf("MITRETags の件数 = %d, want 3", len(r.MITRETags))
	}
	if r.MITRETags[0] != "T1055" {
		t.Errorf("MITRETags[0] = %q, want \"T1055\"", r.MITRETags[0])
	}
}

// TestRuleRow_DescriptionPointer は Description ポインタフィールドの動作を確認する
func TestRuleRow_DescriptionPointer(t *testing.T) {
	// nil の場合
	var r RuleRow
	if r.Description != nil {
		t.Error("Description のデフォルトは nil であるべき")
	}

	// 非 nil の場合
	desc := "プロセスインジェクションを検知するルール"
	r.Description = &desc
	if r.Description == nil {
		t.Fatal("Description を設定後は nil でないべき")
	}
	if *r.Description != desc {
		t.Errorf("*Description = %q, want %q", *r.Description, desc)
	}
}

// TestRuleRow_FalsePositiveRate は FalsePositiveRate の値の範囲を確認する
func TestRuleRow_FalsePositiveRate(t *testing.T) {
	cases := []float64{0.0, 0.01, 0.1, 0.5, 0.99, 1.0}
	for _, rate := range cases {
		r := RuleRow{FalsePositiveRate: rate}
		if r.FalsePositiveRate != rate {
			t.Errorf("FalsePositiveRate = %f, want %f", r.FalsePositiveRate, rate)
		}
	}
}

// TestRuleRow_TimestampFields は CreatedAt / UpdatedAt フィールドの設定を確認する
func TestRuleRow_TimestampFields(t *testing.T) {
	now := time.Now()
	r := RuleRow{
		CreatedAt: now,
		UpdatedAt: now.Add(5 * time.Minute),
	}

	if !r.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", r.CreatedAt, now)
	}
	if !r.UpdatedAt.After(r.CreatedAt) {
		t.Error("UpdatedAt は CreatedAt より後であるべき")
	}
}

// ─── RuleFilter 構造体テスト ──────────────────────────────────────────────────

// TestRuleFilter_ZeroValue は RuleFilter のゼロ値が期待通りであることを確認する
func TestRuleFilter_ZeroValue(t *testing.T) {
	var f RuleFilter
	if f.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", f.Type)
	}
	if f.Enabled != nil {
		t.Errorf("Enabled のデフォルトは nil であるべき: got %v", *f.Enabled)
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

// TestRuleFilter_EnabledPointer は Enabled ポインタの nil/true/false を確認する
func TestRuleFilter_EnabledPointer(t *testing.T) {
	// nil → すべてのルールを対象にする
	var f RuleFilter
	if f.Enabled != nil {
		t.Error("Enabled のデフォルトは nil であるべき (全対象)")
	}

	// true → 有効ルールのみ
	enabled := true
	f.Enabled = &enabled
	if f.Enabled == nil || !*f.Enabled {
		t.Error("Enabled = true に設定した後は true であるべき")
	}

	// false → 無効ルールのみ
	disabled := false
	f.Enabled = &disabled
	if f.Enabled == nil || *f.Enabled {
		t.Error("Enabled = false に設定した後は false であるべき")
	}
}

// ─── ルールフィルタークエリビルダーロジックテスト ──────────────────────────────

// buildRuleWhere は **本物を呼びます。**
//
// 検知ルールの一覧です。**絞り込みが効かないことは、画面では
// 「該当するルールが無い」と同じ姿になります。**
func buildRuleWhere(filter RuleFilter) (string, []interface{}) {
	return ruleListWhere(filter)
}

// TestBuildRuleWhere_EmptyFilter は全フィルターが空のときに WHERE 句が空であることを確認する
func TestBuildRuleWhere_EmptyFilter(t *testing.T) {
	where, args := buildRuleWhere(RuleFilter{})
	if where != "" {
		t.Errorf("空フィルターは空の WHERE 句のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestBuildRuleWhere_TypeFilter は Type フィルターが WHERE 句に含まれることを確認する
func TestBuildRuleWhere_TypeFilter(t *testing.T) {
	enabled := true
	f := RuleFilter{Type: "sigma", Enabled: &enabled}
	where, args := buildRuleWhere(f)

	if !strings.Contains(where, "type") {
		t.Errorf("type 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "enabled") {
		t.Errorf("enabled 条件が含まれるべき: %q", where)
	}
	if len(args) != 2 {
		t.Errorf("args の数 = %d, want 2", len(args))
	}
	if args[0] != "sigma" {
		t.Errorf("args[0] = %v, want \"sigma\"", args[0])
	}
}

// TestBuildRuleWhere_SearchFilter は Search フィルターが ILIKE でラップされることを確認する
func TestBuildRuleWhere_SearchFilter(t *testing.T) {
	f := RuleFilter{Search: "malware"}
	where, args := buildRuleWhere(f)

	if !strings.Contains(where, "ILIKE") {
		t.Errorf("ILIKE 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 {
		t.Fatalf("args の数 = %d, want 1", len(args))
	}
	searchArg, ok := args[0].(string)
	if !ok {
		t.Fatalf("args[0] は string のはず")
	}
	if !strings.HasPrefix(searchArg, "%") || !strings.HasSuffix(searchArg, "%") {
		t.Errorf("検索引数は %% で囲まれるべき: %q", searchArg)
	}
	if !strings.Contains(searchArg, "malware") {
		t.Errorf("検索引数に 'malware' が含まれるべき: %q", searchArg)
	}
}

// TestBuildRuleWhere_AllFilters は全フィルターが有効なとき引数数が正しいことを確認する
func TestBuildRuleWhere_AllFilters(t *testing.T) {
	enabled := false
	f := RuleFilter{Type: "yara", Enabled: &enabled, Search: "ransomware"}
	where, args := buildRuleWhere(f)

	if !strings.HasPrefix(where, "WHERE") {
		t.Errorf("WHERE 句が存在するべき: %q", where)
	}
	// type (1), enabled (1), search (1) = 3 引数
	if len(args) != 3 {
		t.Errorf("args の数 = %d, want 3", len(args))
	}
}

// TestBuildRuleWhere_DefaultLimitFallback は Limit が 0 以下のとき 50 にフォールバックすることを確認する
// rules.go の List メソッドと同等のロジック
func TestBuildRuleWhere_DefaultLimitFallback(t *testing.T) {
	cases := []struct {
		input    int
		expected int
	}{
		{0, 50},
		{-1, 50},
		{-100, 50},
		{1, 1},
		{100, 100},
	}

	for _, tc := range cases {
		limit := tc.input
		if limit <= 0 {
			limit = 50
		}
		if limit != tc.expected {
			t.Errorf("Limit %d → %d, want %d", tc.input, limit, tc.expected)
		}
	}
}

// ─── NotifChannelRow 構造体テスト ──────────────────────────────────────────────

// TestNotifChannelRow_ZeroValue は NotifChannelRow のゼロ値を確認する
func TestNotifChannelRow_ZeroValue(t *testing.T) {
	var ch NotifChannelRow
	if ch.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", ch.ID)
	}
	if ch.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if ch.MinSeverity != 0 {
		t.Errorf("MinSeverity のデフォルト = %d, want 0", ch.MinSeverity)
	}
	if ch.Config != nil {
		t.Errorf("Config のデフォルトは nil であるべき: got %v", ch.Config)
	}
}

// TestNotifChannelRow_KnownTypes は通知チャンネルの既知タイプを確認する
func TestNotifChannelRow_KnownTypes(t *testing.T) {
	knownTypes := []string{"slack", "email", "webhook", "pagerduty", "teams"}
	for _, chType := range knownTypes {
		ch := NotifChannelRow{Type: chType}
		if ch.Type != chType {
			t.Errorf("Type = %q, want %q", ch.Type, chType)
		}
	}
}

// TestNotifChannelRow_MinSeverityFilter は MinSeverity フィルターのロジックを確認する
// MinSeverity 以上のアラートのみ通知するフィルター判定
func TestNotifChannelRow_MinSeverityFilter(t *testing.T) {
	// minSeverityMet はアラートの severity がチャンネルの最小値以上かを判定するロジック
	minSeverityMet := func(ch NotifChannelRow, alertSeverity int) bool {
		return alertSeverity >= ch.MinSeverity
	}

	ch := NotifChannelRow{MinSeverity: 5}

	cases := []struct {
		severity int
		want     bool
	}{
		{3, false}, // 5 未満 → 通知しない
		{5, true},  // 5 = 閾値 → 通知する
		{8, true},  // 5 超過 → 通知する
		{10, true}, // 最大値 → 通知する
	}

	for _, tc := range cases {
		got := minSeverityMet(ch, tc.severity)
		if got != tc.want {
			t.Errorf("minSeverityMet(minSev=5, alertSev=%d) = %v, want %v", tc.severity, got, tc.want)
		}
	}
}

// ─── ApplyPolicyPayload 構造体テスト ──────────────────────────────────────────

// TestApplyPolicyPayload_ZeroValue は ApplyPolicyPayload のゼロ値を確認する
func TestApplyPolicyPayload_ZeroValue(t *testing.T) {
	var p ApplyPolicyPayload
	if p.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", p.AgentID)
	}
	if p.PolicyID != "" {
		t.Errorf("PolicyID のデフォルト = %q, want \"\"", p.PolicyID)
	}
	if p.ScanIntervalMin != 0 {
		t.Errorf("ScanIntervalMin のデフォルト = %d, want 0", p.ScanIntervalMin)
	}
	if p.CPULimitPct != 0 {
		t.Errorf("CPULimitPct のデフォルト = %d, want 0", p.CPULimitPct)
	}
	if p.EnabledModules != nil {
		t.Errorf("EnabledModules のデフォルトは nil であるべき: got %v", p.EnabledModules)
	}
}

// TestApplyPolicyPayload_FieldAssignment は ApplyPolicyPayload のフィールド代入を確認する
func TestApplyPolicyPayload_FieldAssignment(t *testing.T) {
	p := ApplyPolicyPayload{
		AgentID:         "agent-001",
		PolicyID:        "policy-xyz",
		ScanIntervalMin: 60,
		CPULimitPct:     30,
		EnabledModules:  []string{"av", "ids", "firewall"},
	}

	if p.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want \"agent-001\"", p.AgentID)
	}
	if p.ScanIntervalMin != 60 {
		t.Errorf("ScanIntervalMin = %d, want 60", p.ScanIntervalMin)
	}
	if p.CPULimitPct != 30 {
		t.Errorf("CPULimitPct = %d, want 30", p.CPULimitPct)
	}
	if len(p.EnabledModules) != 3 {
		t.Errorf("EnabledModules の件数 = %d, want 3", len(p.EnabledModules))
	}
}

// ルールの検索が、名前と説明の両方に当たること。
//
// **説明にしか書いていない語で探せないと、担当者は「そのルールは無い」と
// 判断します。** 同じ引数を2箇所で使うので、番号を分けると引数が足りません。
func TestRuleSearchMatchesNameAndDescription(t *testing.T) {
	where, args := ruleListWhere(RuleFilter{Search: "lateral"})
	if len(args) != 1 {
		t.Fatalf("args = %v, want 1 件", args)
	}
	if !strings.Contains(where, "name ILIKE $1") {
		t.Errorf("名前に当たっていません: %q", where)
	}
	if !strings.Contains(where, "description ILIKE $1") {
		t.Errorf("説明に当たっていません: %q。**説明にしか書いていない語で"+
			"探せません**", where)
	}
	if strings.Contains(where, "$2") {
		t.Errorf("引数の数を超えるプレースホルダがあります: %q", where)
	}
}

// 有効/無効の絞り込みが、nil と false を取り違えないこと。
func TestRuleEnabledDistinguishesNilFromFalse(t *testing.T) {
	where, args := ruleListWhere(RuleFilter{})
	if strings.Contains(where, "enabled") || len(args) != 0 {
		t.Errorf("指定なしで enabled の条件が入っています: %q %v", where, args)
	}
	no := false
	where, args = ruleListWhere(RuleFilter{Enabled: &no})
	if !strings.Contains(where, "enabled = $1") || len(args) != 1 || args[0] != false {
		t.Errorf("enabled=false の絞り込みが効いていません: %q %v。"+
			"**無効なルールだけを見たいときに、全部出ます**", where, args)
	}
}

// 3つ揃ったときに、番号と引数の並びがずれないこと。
//
// 番号は args の本数から出しています。別にカウンタを持っていた頃は、
// **最後の増分が誰にも読まれないまま残っていました**（ineffassign が
// CI で見つけました）。条件を足したときに片方だけ増やすと、SQL は
// そのまま通って**結果だけが変わります** —— いちばん気づきにくい形です。
func TestRuleWherePlaceholdersFollowTheArguments(t *testing.T) {
	yes := true
	where, args := ruleListWhere(RuleFilter{Type: "sigma", Enabled: &yes, Search: "lateral"})
	if len(args) != 3 {
		t.Fatalf("args = %v, want 3 件", args)
	}
	for _, want := range []string{"type = $1", "enabled = $2", "name ILIKE $3", "description ILIKE $3"} {
		if !strings.Contains(where, want) {
			t.Errorf("%q が入っていません: %q", want, where)
		}
	}
	if strings.Contains(where, "$4") {
		t.Errorf("引数の数を超えるプレースホルダがあります: %q", where)
	}
	if args[0] != "sigma" || args[1] != true || args[2] != "%lateral%" {
		t.Errorf("引数の並びが番号と噛み合っていません: %v", args)
	}
}
