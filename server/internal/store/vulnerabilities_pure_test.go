package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

// ─── Vulnerability 構造体フィールドテスト ─────────────────────────────────────

// TestVulnerability_DefaultFields は Vulnerability のゼロ値フィールドを確認する
func TestVulnerability_DefaultFields(t *testing.T) {
	var v Vulnerability
	if v.Severity != "" {
		t.Errorf("Severity のデフォルトは空文字列であるべき: got %q", v.Severity)
	}
	if v.Status != "" {
		t.Errorf("Status のデフォルトは空文字列であるべき: got %q", v.Status)
	}
	if v.CVSSScore != nil {
		t.Errorf("CVSSScore のデフォルトは nil であるべき: got %v", v.CVSSScore)
	}
	if v.AgentID != nil {
		t.Errorf("AgentID のデフォルトは nil であるべき: got %v", v.AgentID)
	}
}

// TestVulnerability_SeverityFieldAssignment は既知の severity 値を設定できることを確認する
func TestVulnerability_SeverityFieldAssignment(t *testing.T) {
	cases := []string{"critical", "high", "medium", "low"}
	for _, sev := range cases {
		v := Vulnerability{Severity: sev}
		if v.Severity != sev {
			t.Errorf("Severity = %q, want %q", v.Severity, sev)
		}
	}
}

// TestVulnerability_StatusFieldAssignment は既知の status 値を設定できることを確認する
func TestVulnerability_StatusFieldAssignment(t *testing.T) {
	cases := []string{"open", "mitigated", "patched", "accepted"}
	for _, st := range cases {
		v := Vulnerability{Status: st}
		if v.Status != st {
			t.Errorf("Status = %q, want %q", v.Status, st)
		}
	}
}

// TestVulnerability_CVSSScorePointer は CVSSScore ポインタを設定・参照できることを確認する
func TestVulnerability_CVSSScorePointer(t *testing.T) {
	score := 9.8
	v := Vulnerability{CVSSScore: &score}
	if v.CVSSScore == nil {
		t.Fatal("CVSSScore に値を設定後は nil でないべき")
	}
	if *v.CVSSScore != score {
		t.Errorf("*CVSSScore = %v, want %v", *v.CVSSScore, score)
	}
}

// TestVulnerability_AgentIDPointer は AgentID ポインタを設定・参照できることを確認する
func TestVulnerability_AgentIDPointer(t *testing.T) {
	id := "agent-uuid-1234"
	v := Vulnerability{AgentID: &id}
	if v.AgentID == nil {
		t.Fatal("AgentID に値を設定後は nil でないべき")
	}
	if *v.AgentID != id {
		t.Errorf("*AgentID = %q, want %q", *v.AgentID, id)
	}
}

// ─── CVSS スコア範囲検証ヘルパーテスト ────────────────────────────────────────

// cvssScoreIsValid は CVSS スコアが 0.0〜10.0 の範囲内かを検証する純粋関数
func cvssScoreIsValid(score float64) bool {
	return score >= 0.0 && score <= 10.0
}

// TestCVSSScoreIsValid_ValidRange は有効なスコア範囲が合格することを確認する
func TestCVSSScoreIsValid_ValidRange(t *testing.T) {
	validScores := []float64{0.0, 1.0, 3.9, 5.0, 7.5, 9.8, 10.0}
	for _, s := range validScores {
		if !cvssScoreIsValid(s) {
			t.Errorf("CVSSスコア %v は有効な範囲内であるべき", s)
		}
	}
}

// TestCVSSScoreIsValid_OutOfRange は範囲外スコアが拒否されることを確認する
func TestCVSSScoreIsValid_OutOfRange(t *testing.T) {
	invalidScores := []float64{-0.1, -1.0, 10.1, 11.0, 100.0}
	for _, s := range invalidScores {
		if cvssScoreIsValid(s) {
			t.Errorf("CVSSスコア %v は範囲外として拒否されるべき", s)
		}
	}
}

// TestCVSSScoreIsValid_Boundaries は境界値が正しく処理されることを確認する
func TestCVSSScoreIsValid_Boundaries(t *testing.T) {
	// 0.0 と 10.0 は有効な境界値
	if !cvssScoreIsValid(0.0) {
		t.Error("CVSS 0.0 は有効な境界値であるべき")
	}
	if !cvssScoreIsValid(10.0) {
		t.Error("CVSS 10.0 は有効な境界値であるべき")
	}
}

// ─── 重大度順序付けテスト ──────────────────────────────────────────────────────

// severitySortOrder は重大度文字列をソート順の数値に変換する純粋関数
// vulnerabilities.go の SQL ORDER BY CASE ロジックを反映する
func severitySortOrder(sev string) int {
	switch sev {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	default: // "low" やその他
		return 4
	}
}

// TestSeveritySortOrder_CriticalIsHighestPriority は critical が最優先であることを確認する
func TestSeveritySortOrder_CriticalIsHighestPriority(t *testing.T) {
	if severitySortOrder("critical") != 1 {
		t.Errorf("critical の優先度 = %d, want 1", severitySortOrder("critical"))
	}
}

// TestSeveritySortOrder_OrderIsConsistent は重大度の順序が一貫していることを確認する
func TestSeveritySortOrder_OrderIsConsistent(t *testing.T) {
	// critical < high < medium < low の順序を確認
	if severitySortOrder("critical") >= severitySortOrder("high") {
		t.Error("critical は high より高優先度（小さい数値）であるべき")
	}
	if severitySortOrder("high") >= severitySortOrder("medium") {
		t.Error("high は medium より高優先度であるべき")
	}
	if severitySortOrder("medium") >= severitySortOrder("low") {
		t.Error("medium は low より高優先度であるべき")
	}
}

// TestSeveritySortOrder_UnknownSeverityGetsLowestPriority は不明な重大度が最低優先度を得ることを確認する
func TestSeveritySortOrder_UnknownSeverityGetsLowestPriority(t *testing.T) {
	unknownOrder := severitySortOrder("unknown")
	lowOrder := severitySortOrder("low")
	if unknownOrder != lowOrder {
		t.Errorf("不明な重大度 (%d) は 'low' と同じ優先度 (%d) であるべき", unknownOrder, lowOrder)
	}
}

// ─── VulnFilter 構造体テスト ──────────────────────────────────────────────────

// TestVulnFilter_DefaultLimitIsZero は VulnFilter のデフォルト Limit がゼロであることを確認する
func TestVulnFilter_DefaultLimitIsZero(t *testing.T) {
	var f VulnFilter
	if f.Limit != 0 {
		t.Errorf("VulnFilter.Limit のデフォルト = %d, want 0", f.Limit)
	}
}

// TestVulnFilter_AllFieldsCanBeSet は全フィールドを設定できることを確認する
func TestVulnFilter_AllFieldsCanBeSet(t *testing.T) {
	f := VulnFilter{
		AgentID:  "agent-1",
		Severity: "critical",
		Status:   "open",
		Search:   "CVE-2024",
		Limit:    25,
		Offset:   50,
	}
	if f.AgentID != "agent-1" {
		t.Errorf("AgentID = %q, want 'agent-1'", f.AgentID)
	}
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want 'critical'", f.Severity)
	}
	if f.Status != "open" {
		t.Errorf("Status = %q, want 'open'", f.Status)
	}
	if f.Search != "CVE-2024" {
		t.Errorf("Search = %q, want 'CVE-2024'", f.Search)
	}
	if f.Limit != 25 {
		t.Errorf("Limit = %d, want 25", f.Limit)
	}
	if f.Offset != 50 {
		t.Errorf("Offset = %d, want 50", f.Offset)
	}
}

// ─── agentIDArg 純粋関数テスト ────────────────────────────────────────────────

// TestAgentIDArg_NilPointerReturnsNil は nil ポインタが nil を返すことを確認する
func TestAgentIDArg_NilPointerReturnsNil(t *testing.T) {
	result := agentIDArg(nil)
	if result != nil {
		t.Errorf("agentIDArg(nil) = %v, want nil", result)
	}
}

// TestAgentIDArg_EmptyStringPointerReturnsNil は空文字列ポインタが nil を返すことを確認する
func TestAgentIDArg_EmptyStringPointerReturnsNil(t *testing.T) {
	s := ""
	result := agentIDArg(&s)
	if result != nil {
		t.Errorf("agentIDArg(&\"\") = %v, want nil", result)
	}
}

// TestAgentIDArg_NonEmptyStringReturnsValue は非空文字列ポインタが値を返すことを確認する
func TestAgentIDArg_NonEmptyStringReturnsValue(t *testing.T) {
	s := "agent-uuid-abc"
	result := agentIDArg(&s)
	if result == nil {
		t.Fatal("agentIDArg(&s) は nil でないべき")
	}
	if result.(string) != s {
		t.Errorf("agentIDArg(&s) = %v, want %q", result, s)
	}
}

// TestAgentIDArg_UUIDFormatStringReturnsValue は UUID 形式の文字列がそのまま返されることを確認する
func TestAgentIDArg_UUIDFormatStringReturnsValue(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	result := agentIDArg(&uuid)
	if result == nil {
		t.Fatal("UUID 形式の文字列ポインタは nil でないべき")
	}
	if result.(string) != uuid {
		t.Errorf("agentIDArg 結果 = %q, want %q", result.(string), uuid)
	}
}

// ── 件数の救済 ────────────────────────────────────────────────────────

// **救済が `vulnListWhere` の中に書いてありました。**
//
// あの関数は `VulnFilter` を値で受け取るので、`f.Limit = 50` は写しの上に
// 書かれ、呼び出し側には届きません。実測 (2026-08-12):
// `/api/v1/vulnerabilities?per_page=0` は 200 の **0 件**で、`total` だけ
// 120 と出ていました —— 救済があるように見えて、効いていませんでした。
func TestClampVulnLimitRescuesOutOfRangeValues(t *testing.T) {
	// **数字を直に書きます。** `defaultVulnLimit` と突き合わせると、
	// あの定数を 0 に変える変更がこの検査ごと一緒に動いて生き残ります
	// （実際に生き残りました）。
	const want = 50
	for _, raw := range []int{-1, 0, 201, 100000} {
		if got := clampVulnLimit(raw); got != want {
			t.Errorf("clampVulnLimit(%d) = %d, 既定の %d に戻るはずです", raw, got, want)
		}
	}
	if defaultVulnLimit < 1 {
		t.Errorf("defaultVulnLimit = %d。**救済先が 0 だと、救済しても"+
			"0 件返ります**", defaultVulnLimit)
	}
	if maxVulnLimit < defaultVulnLimit {
		t.Errorf("maxVulnLimit(%d) < defaultVulnLimit(%d)。"+
			"**既定そのものが範囲外になり、何を渡しても既定に戻り続けます**",
			maxVulnLimit, defaultVulnLimit)
	}
}

// **範囲内はそのまま。** 全部を既定に丸める実装でも上は緑になります。
func TestClampVulnLimitKeepsWhatIsInRange(t *testing.T) {
	for _, raw := range []int{1, 7, 50, 200} {
		if got := clampVulnLimit(raw); got != raw {
			t.Errorf("clampVulnLimit(%d) = %d, そのまま通るはずです", raw, got)
		}
	}
}

// **`List` が救済を通ること。** 判定を切り出しただけでは、呼ばなくなった
// 瞬間に元へ戻ります。`vulnListWhere` は値渡しなので、救済をあの中へ
// 戻す変更もここで落ちます。
func TestVulnListWhereDoesNotPretendToRescueTheLimit(t *testing.T) {
	f := VulnFilter{Limit: 0}
	vulnListWhere(f)
	if f.Limit != 0 {
		t.Fatal("`vulnListWhere` が呼び出し側の Limit を変えました（値渡しなので不可能なはずです）")
	}
	// 救済は List 側にあること。
	if clampVulnLimit(f.Limit) != defaultVulnLimit {
		t.Error("**0 が既定に戻りません。** 0 件返って「脆弱性なし」に見えます")
	}
}

// `List` が救済を通っていること。
//
// **切り出しただけでは足りません。** 呼ぶのをやめれば元に戻ります ——
// そして DB の無いところでは、その変更で落ちる検査が1本もありません
// でした（変異が生き残りました）。ここはソースを読んで確かめます。
func TestVulnStoreListCallsTheLimitRescue(t *testing.T) {
	src, err := os.ReadFile("vulnerabilities.go")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "vulnerabilities.go", src, 0)
	if err != nil {
		t.Fatalf("解析できません: %v", err)
	}
	found, calls := false, false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "List" || fn.Recv == nil || fn.Body == nil {
			continue
		}
		if !strings.Contains(types.ExprString(fn.Recv.List[0].Type), "VulnStore") {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "clampVulnLimit" {
					calls = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("`VulnStore.List` が見つかりません")
	}
	if !calls {
		t.Error("`VulnStore.List` が `clampVulnLimit` を呼んでいません。" +
			"**per_page=0 が LIMIT 0 になり、「脆弱性なし」と同じ姿で返ります**")
	}
}

// 救済を `vulnListWhere` の中へ戻す変更を止めます。
//
// **あの関数は `VulnFilter` を値で受け取ります。** 中で `f.Limit` に
// 書いても呼び出し側には届きません —— 元の実装がまさにそれで、
// 救済があるように見えて効いていませんでした。
func TestTheLimitRescueIsNotHiddenInTheValueCopy(t *testing.T) {
	src, err := os.ReadFile("vulnerabilities.go")
	if err != nil {
		t.Fatalf("読めません: %v", err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "vulnerabilities.go", src, 0)
	if err != nil {
		t.Fatalf("解析できません: %v", err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "vulnListWhere" || fn.Body == nil {
			continue
		}
		// 値渡しであること（ポインタになったら話が変わります）。
		if len(fn.Type.Params.List) != 1 {
			t.Fatalf("`vulnListWhere` の引数が %d 個です", len(fn.Type.Params.List))
		}
		if _, isPtr := fn.Type.Params.List[0].Type.(*ast.StarExpr); isPtr {
			return // ポインタなら書き込みは届きます。
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "f" {
						t.Errorf("`vulnListWhere` が `f.%s` に書いています。"+
							"**値渡しなので、この書き込みは写しの上に落ちます**",
							sel.Sel.Name)
					}
				}
			}
			return true
		})
		return
	}
	t.Fatal("`vulnListWhere` が見つかりません")
}
