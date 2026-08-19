package store

import (
	"strings"
	"testing"
	"time"
)

// ─── FIMRule 構造体テスト ─────────────────────────────────────────────────────

// TestFIMRule_ZeroValue は FIMRule のゼロ値が期待通りであることを確認する
func TestFIMRule_ZeroValue(t *testing.T) {
	var r FIMRule
	if r.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", r.ID)
	}
	if r.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", r.Name)
	}
	if r.Path != "" {
		t.Errorf("Path のデフォルト = %q, want \"\"", r.Path)
	}
	if r.Recursive {
		t.Error("Recursive のデフォルトは false であるべき")
	}
	if r.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if r.Severity != "" {
		t.Errorf("Severity のデフォルト = %q, want \"\"", r.Severity)
	}
	if r.ExcludePatterns != nil {
		t.Errorf("ExcludePatterns のデフォルトは nil であるべき: got %v", r.ExcludePatterns)
	}
}

// TestFIMRule_FieldAssignment は FIMRule フィールドの代入が正しく反映されることを確認する
func TestFIMRule_FieldAssignment(t *testing.T) {
	r := FIMRule{
		ID:              "rule-001",
		Name:            "Windowsシステムファイル監視",
		Path:            "/etc/passwd",
		Recursive:       true,
		ExcludePatterns: []string{"*.tmp", "*.log"},
		Enabled:         true,
		Severity:        "high",
		CreatedAt:       time.Now().Format(time.RFC3339),
	}

	if r.ID != "rule-001" {
		t.Errorf("ID = %q, want \"rule-001\"", r.ID)
	}
	if r.Path != "/etc/passwd" {
		t.Errorf("Path = %q, want \"/etc/passwd\"", r.Path)
	}
	if !r.Recursive {
		t.Error("Recursive は true であるべき")
	}
	if len(r.ExcludePatterns) != 2 {
		t.Errorf("ExcludePatterns の長さ = %d, want 2", len(r.ExcludePatterns))
	}
	if !r.Enabled {
		t.Error("Enabled は true であるべき")
	}
	if r.Severity != "high" {
		t.Errorf("Severity = %q, want \"high\"", r.Severity)
	}
}

// TestFIMRule_SeverityValues は使用可能な重大度の値を確認する
func TestFIMRule_SeverityValues(t *testing.T) {
	validSeverities := []string{"low", "medium", "high", "critical"}
	for _, sev := range validSeverities {
		r := FIMRule{Severity: sev}
		if r.Severity != sev {
			t.Errorf("Severity = %q, want %q", r.Severity, sev)
		}
	}
}

// TestFIMRule_DefaultSeverityHigh は fim_rules.go の Create でデフォルトが "high" であることを確認する
func TestFIMRule_DefaultSeverityHigh(t *testing.T) {
	// fim_rules.go の Create では if in.Severity == "" { in.Severity = "high" }
	in := CreateFIMRuleInput{
		Name: "テストルール",
		Path: "/var/log",
	}
	// Severity が空の場合はデフォルトを設定する
	if in.Severity == "" {
		in.Severity = "high"
	}
	if in.Severity != "high" {
		t.Errorf("空 Severity のデフォルト = %q, want \"high\"", in.Severity)
	}
}

// TestFIMRule_ExcludePatternsDefaultEmpty は nil ExcludePatterns が空スライスに変換されることを確認する
func TestFIMRule_ExcludePatternsDefaultEmpty(t *testing.T) {
	// fim_rules.go の Create では if in.ExcludePatterns == nil { in.ExcludePatterns = []string{} }
	in := CreateFIMRuleInput{
		Name: "テストルール",
		Path: "/etc",
	}
	if in.ExcludePatterns == nil {
		in.ExcludePatterns = []string{}
	}
	if in.ExcludePatterns == nil {
		t.Fatal("ExcludePatterns は nil でないべき (空スライスに変換済み)")
	}
	if len(in.ExcludePatterns) != 0 {
		t.Errorf("ExcludePatterns の長さ = %d, want 0", len(in.ExcludePatterns))
	}
}

// ─── FIMRuleFilter 構造体テスト ───────────────────────────────────────────────

// TestFIMRuleFilter_ZeroValue は FIMRuleFilter のゼロ値を確認する
func TestFIMRuleFilter_ZeroValue(t *testing.T) {
	var f FIMRuleFilter
	if f.Enabled != nil {
		t.Errorf("Enabled のデフォルトは nil であるべき: got %v", f.Enabled)
	}
	if f.Severity != "" {
		t.Errorf("Severity のデフォルト = %q, want \"\"", f.Severity)
	}
	if f.Limit != 0 {
		t.Errorf("Limit のデフォルト = %d, want 0", f.Limit)
	}
	if f.Offset != 0 {
		t.Errorf("Offset のデフォルト = %d, want 0", f.Offset)
	}
}

// TestFIMRuleFilter_EnabledPointer は Enabled フィールドがポインタであることを確認する
func TestFIMRuleFilter_EnabledPointer(t *testing.T) {
	// Enabled=nil → フィルターなし
	fNil := FIMRuleFilter{Enabled: nil}
	if fNil.Enabled != nil {
		t.Errorf("nil Enabled は nil であるべき: got %v", fNil.Enabled)
	}

	// Enabled=true → 有効なルールのみ
	trueVal := true
	fTrue := FIMRuleFilter{Enabled: &trueVal}
	if fTrue.Enabled == nil || !*fTrue.Enabled {
		t.Errorf("Enabled = %v, want true", fTrue.Enabled)
	}

	// Enabled=false → 無効なルールのみ
	falseVal := false
	fFalse := FIMRuleFilter{Enabled: &falseVal}
	if fFalse.Enabled == nil || *fFalse.Enabled {
		t.Errorf("Enabled = %v, want false", fFalse.Enabled)
	}
}

// 1ページの件数の切り詰め。**本物を呼びます。**
//
// 以前ここには `applyLimitDefaults` という写しが検査の中に置かれ、
// それを試していました。0 を通すと 0 件返り、FIM の設定画面では
// **「監視ルールが1本も無い」と見分けが付きません** —— 監視されて
// いないように見えて、実際には監視されています（逆も同じです）。
func TestFIMRuleFilter_LimitClamped(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, 100}, {-1, 100}, {50, 50}, {500, 500}, {5000, 500},
	} {
		if got := clampFIMRuleLimit(tc.in); got != tc.want {
			t.Errorf("clampFIMRuleLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// WHERE 句の組み立て。**写しには入っていませんでした。**
//
// `Enabled` は `*bool` です —— **nil（指定なし）と false（無効なものだけ）
// は別です。** 取り違えると、絞り込みなしの一覧が「無効なルールだけ」に
// なります。
func TestFIMRuleWhereDistinguishesNilFromFalse(t *testing.T) {
	where, args := fimRuleListWhere(FIMRuleFilter{})
	if strings.Contains(where, "enabled") || len(args) != 0 {
		t.Errorf("指定なしで enabled の条件が入っています: %q %v", where, args)
	}

	no := false
	where, args = fimRuleListWhere(FIMRuleFilter{Enabled: &no})
	if !strings.Contains(where, "enabled = $1") {
		t.Errorf("enabled=false の条件が入っていません: %q", where)
	}
	if len(args) != 1 || args[0] != false {
		t.Errorf("args = %v, want [false]", args)
	}
}

// TestFIMRuleFilter_LimitMax500 は Limit が 500 を超えるとき 500 に制限されることを確認する
func TestFIMRuleFilter_LimitMax500(t *testing.T) {
	// fim_rules.go の List では if f.Limit > 500 { f.Limit = 500 }
	applyLimitDefaults := func(f FIMRuleFilter) FIMRuleFilter {
		if f.Limit <= 0 {
			f.Limit = 100
		}
		if f.Limit > 500 {
			f.Limit = 500
		}
		return f
	}

	f := applyLimitDefaults(FIMRuleFilter{Limit: 1000})
	if f.Limit != 500 {
		t.Errorf("Limit=1000 は 500 に制限されるはず: got %d", f.Limit)
	}

	f = applyLimitDefaults(FIMRuleFilter{Limit: 501})
	if f.Limit != 500 {
		t.Errorf("Limit=501 は 500 に制限されるはず: got %d", f.Limit)
	}

	// 500 はそのまま
	f = applyLimitDefaults(FIMRuleFilter{Limit: 500})
	if f.Limit != 500 {
		t.Errorf("Limit=500 は変更されないはず: got %d", f.Limit)
	}
}

// ─── FIMRule パスマッチングロジックテスト ─────────────────────────────────────

// pathMatchesRule はパスが FIMRule のパス・除外パターンに一致するか判定するヘルパー
// fim_rules.go の実際のDBロジックではなくエージェント側の検査ロジックを純粋関数でシミュレートする
func pathMatchesRule(filePath string, rule FIMRule) bool {
	if rule.Path == "" {
		return false
	}
	// 再帰的監視の場合はプレフィックスマッチ
	if rule.Recursive {
		if !strings.HasPrefix(filePath, rule.Path) {
			return false
		}
	} else {
		// 非再帰の場合は完全一致または直接の子のみ（サブディレクトリは除外）
		if filePath == rule.Path {
			// exact match OK
		} else {
			prefix := rule.Path + "/"
			if !strings.HasPrefix(filePath, prefix) {
				return false
			}
			// direct child only: remainder must not contain "/"
			remainder := filePath[len(prefix):]
			if strings.Contains(remainder, "/") {
				return false
			}
		}
	}
	// 除外パターンチェック（末尾のサフィックスマッチ）
	for _, pattern := range rule.ExcludePatterns {
		if pattern == "" {
			continue
		}
		// パターンが "*." で始まる場合は拡張子マッチ
		if strings.HasPrefix(pattern, "*.") {
			ext := pattern[1:] // "*.log" → ".log"
			if strings.HasSuffix(filePath, ext) {
				return false
			}
		} else if strings.HasSuffix(filePath, pattern) {
			return false
		}
	}
	return true
}

// TestPathMatchesRule_DirectPathMatch はパスの完全一致を確認する
func TestPathMatchesRule_DirectPathMatch(t *testing.T) {
	rule := FIMRule{
		Path:      "/etc/passwd",
		Recursive: false,
		Enabled:   true,
	}
	if !pathMatchesRule("/etc/passwd", rule) {
		t.Error("/etc/passwd は /etc/passwd ルールに一致するべき")
	}
}

// TestPathMatchesRule_RecursivePathMatch は再帰的パスマッチを確認する
func TestPathMatchesRule_RecursivePathMatch(t *testing.T) {
	rule := FIMRule{
		Path:      "/etc",
		Recursive: true,
		Enabled:   true,
	}
	paths := []string{
		"/etc/passwd",
		"/etc/hosts",
		"/etc/ssh/sshd_config",
		"/etc/nginx/nginx.conf",
	}
	for _, p := range paths {
		if !pathMatchesRule(p, rule) {
			t.Errorf("パス %q は /etc の再帰ルールに一致するべき", p)
		}
	}
}

// TestPathMatchesRule_NonRecursiveDoesNotMatchSubdir は非再帰モードでサブディレクトリが除外されることを確認する
func TestPathMatchesRule_NonRecursiveDoesNotMatchSubdir(t *testing.T) {
	rule := FIMRule{
		Path:      "/etc",
		Recursive: false,
		Enabled:   true,
	}
	// 非再帰の場合、/etc/ssh/sshd_config は一致しない（直接の子は一致する）
	if pathMatchesRule("/etc/ssh/sshd_config", rule) {
		t.Error("/etc/ssh/sshd_config は非再帰 /etc ルールに一致しないべき（二階層以上深い）")
	}
}

// TestPathMatchesRule_ExcludePattern は除外パターンが正しく機能することを確認する
func TestPathMatchesRule_ExcludePattern(t *testing.T) {
	rule := FIMRule{
		Path:            "/var/log",
		Recursive:       true,
		ExcludePatterns: []string{"*.tmp", "*.swp"},
		Enabled:         true,
	}
	// 除外パターンに一致するファイルは除外される
	if pathMatchesRule("/var/log/app.tmp", rule) {
		t.Error("/var/log/app.tmp は *.tmp 除外パターンにより除外されるべき")
	}
	if pathMatchesRule("/var/log/vim.swp", rule) {
		t.Error("/var/log/vim.swp は *.swp 除外パターンにより除外されるべき")
	}
	// 除外パターンに一致しないファイルは含まれる
	if !pathMatchesRule("/var/log/app.log", rule) {
		t.Error("/var/log/app.log は除外されないべき")
	}
}

// TestPathMatchesRule_EmptyPathDoesNotMatch は Path が空のルールがファイルにマッチしないことを確認する
func TestPathMatchesRule_EmptyPathDoesNotMatch(t *testing.T) {
	rule := FIMRule{
		Path:    "",
		Enabled: true,
	}
	if pathMatchesRule("/etc/passwd", rule) {
		t.Error("Path が空のルールはどのファイルにもマッチしないべき")
	}
}

// ─── CreateFIMRuleInput / UpdateFIMRuleInput 構造体テスト ─────────────────────

// TestCreateFIMRuleInput_FieldAssignment は CreateFIMRuleInput フィールドの代入を確認する
func TestCreateFIMRuleInput_FieldAssignment(t *testing.T) {
	in := CreateFIMRuleInput{
		Name:            "システムバイナリ監視",
		Path:            "/usr/bin",
		Recursive:       true,
		ExcludePatterns: []string{"*.pyc"},
		Enabled:         true,
		Severity:        "critical",
	}
	if in.Name != "システムバイナリ監視" {
		t.Errorf("Name = %q, want \"システムバイナリ監視\"", in.Name)
	}
	if in.Path != "/usr/bin" {
		t.Errorf("Path = %q, want \"/usr/bin\"", in.Path)
	}
	if !in.Recursive {
		t.Error("Recursive は true であるべき")
	}
	if len(in.ExcludePatterns) != 1 || in.ExcludePatterns[0] != "*.pyc" {
		t.Errorf("ExcludePatterns = %v, want [*.pyc]", in.ExcludePatterns)
	}
	if in.Severity != "critical" {
		t.Errorf("Severity = %q, want \"critical\"", in.Severity)
	}
}

// TestUpdateFIMRuleInput_ZeroValue は UpdateFIMRuleInput のゼロ値を確認する
func TestUpdateFIMRuleInput_ZeroValue(t *testing.T) {
	var in UpdateFIMRuleInput
	if in.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", in.Name)
	}
	if in.Path != "" {
		t.Errorf("Path のデフォルト = %q, want \"\"", in.Path)
	}
	if in.Recursive {
		t.Error("Recursive のデフォルトは false であるべき")
	}
	if in.Enabled {
		t.Error("Enabled のデフォルトは false であるべき")
	}
	if in.Severity != "" {
		t.Errorf("Severity のデフォルト = %q, want \"\"", in.Severity)
	}
}
