package store

import (
	"strings"
	"testing"
	"time"
)

// ─── IOCEntry 構造体テスト ─────────────────────────────────────────────────────

// TestIOCEntry_ZeroValue は IOCEntry のゼロ値が期待通りであることを確認する
func TestIOCEntry_ZeroValue(t *testing.T) {
	var e IOCEntry
	if e.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", e.ID)
	}
	if e.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", e.Type)
	}
	if e.Value != "" {
		t.Errorf("Value のデフォルト = %q, want \"\"", e.Value)
	}
	if e.Severity != 0 {
		t.Errorf("Severity のデフォルト = %d, want 0", e.Severity)
	}
	if e.IsActive {
		t.Error("IsActive のデフォルトは false であるべき")
	}
	if e.AddedBy != nil {
		t.Error("AddedBy のデフォルトは nil であるべき")
	}
}

// TestIOCEntry_FieldAssignment は IOCEntry のフィールド代入が正しく反映されることを確認する
func TestIOCEntry_FieldAssignment(t *testing.T) {
	addedBy := "user-uuid-001"
	now := time.Now()
	e := IOCEntry{
		ID:          "ioc-001",
		Type:        "ip",
		Value:       "198.51.100.1",
		Description: "悪意のあるIPアドレス",
		Severity:    8,
		IsActive:    true,
		AddedBy:     &addedBy,
		AddedByName: "analyst@example.com",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if e.ID != "ioc-001" {
		t.Errorf("ID = %q, want \"ioc-001\"", e.ID)
	}
	if e.Type != "ip" {
		t.Errorf("Type = %q, want \"ip\"", e.Type)
	}
	if e.Value != "198.51.100.1" {
		t.Errorf("Value = %q, want \"198.51.100.1\"", e.Value)
	}
	if e.Severity != 8 {
		t.Errorf("Severity = %d, want 8", e.Severity)
	}
	if !e.IsActive {
		t.Error("IsActive は true であるべき")
	}
	if e.AddedBy == nil || *e.AddedBy != addedBy {
		t.Errorf("AddedBy = %v, want %q", e.AddedBy, addedBy)
	}
}

// TestIOCEntry_KnownTypes は既知の IOC タイプが文字列として正しく表現されることを確認する
func TestIOCEntry_KnownTypes(t *testing.T) {
	// EDRプラットフォームで使用される標準的なIOCタイプを確認する
	knownTypes := []string{"ip", "domain", "hash", "url", "email"}
	for _, iocType := range knownTypes {
		e := IOCEntry{Type: iocType}
		if e.Type != iocType {
			t.Errorf("Type = %q, want %q", e.Type, iocType)
		}
	}
}

// TestIOCEntry_SeverityRange は severity の値が 1〜10 の範囲で表現できることを確認する
func TestIOCEntry_SeverityRange(t *testing.T) {
	for sev := 1; sev <= 10; sev++ {
		e := IOCEntry{Severity: sev}
		if e.Severity != sev {
			t.Errorf("Severity = %d, want %d", e.Severity, sev)
		}
	}
}

// TestIOCEntry_AddedByNilByDefault は AddedBy フィールドのデフォルトが nil であることを確認する
func TestIOCEntry_AddedByNilByDefault(t *testing.T) {
	e := IOCEntry{Type: "hash", Value: "abc123"}
	if e.AddedBy != nil {
		t.Errorf("AddedBy のデフォルトは nil であるべき: got %v", *e.AddedBy)
	}
}

// ─── IOCStats 構造体テスト ─────────────────────────────────────────────────────

// TestIOCStats_ZeroValue は IOCStats のゼロ値が期待通りであることを確認する
func TestIOCStats_ZeroValue(t *testing.T) {
	var s IOCStats
	if s.Total != 0 {
		t.Errorf("Total のデフォルト = %d, want 0", s.Total)
	}
	if s.Active != 0 {
		t.Errorf("Active のデフォルト = %d, want 0", s.Active)
	}
	if s.Alerts7d != 0 {
		t.Errorf("Alerts7d のデフォルト = %d, want 0", s.Alerts7d)
	}
	if s.ByType != nil {
		t.Errorf("ByType のデフォルトは nil であるべき: got %v", s.ByType)
	}
}

// TestIOCStats_ByTypeMapInitialization は ByType マップの初期化を確認する
func TestIOCStats_ByTypeMapInitialization(t *testing.T) {
	s := IOCStats{ByType: make(map[string]int)}
	s.ByType["ip"] = 5
	s.ByType["domain"] = 3
	s.ByType["hash"] = 12

	if s.ByType["ip"] != 5 {
		t.Errorf("ByType[ip] = %d, want 5", s.ByType["ip"])
	}
	if s.ByType["domain"] != 3 {
		t.Errorf("ByType[domain] = %d, want 3", s.ByType["domain"])
	}
	if s.ByType["hash"] != 12 {
		t.Errorf("ByType[hash] = %d, want 12", s.ByType["hash"])
	}
}

// TestIOCStats_TotalAndActiveAggregation は Total と Active の集計ロジックを確認する
func TestIOCStats_TotalAndActiveAggregation(t *testing.T) {
	s := IOCStats{ByType: make(map[string]int)}

	// 手動で集計をシミュレートする
	entries := []struct {
		iocType string
		total   int
		active  int
	}{
		{"ip", 10, 8},
		{"domain", 5, 5},
		{"hash", 20, 15},
	}

	for _, row := range entries {
		s.ByType[row.iocType] = row.total
		s.Total += row.total
		s.Active += row.active
	}

	if s.Total != 35 {
		t.Errorf("Total = %d, want 35", s.Total)
	}
	if s.Active != 28 {
		t.Errorf("Active = %d, want 28", s.Active)
	}
	if len(s.ByType) != 3 {
		t.Errorf("ByType の件数 = %d, want 3", len(s.ByType))
	}
}

// ─── IOCTopHit 構造体テスト ───────────────────────────────────────────────────

// TestIOCTopHit_ZeroValue は IOCTopHit のゼロ値を確認する
func TestIOCTopHit_ZeroValue(t *testing.T) {
	var h IOCTopHit
	if h.Value != "" {
		t.Errorf("Value のデフォルト = %q, want \"\"", h.Value)
	}
	if h.Type != "" {
		t.Errorf("Type のデフォルト = %q, want \"\"", h.Type)
	}
	if h.HitCount != 0 {
		t.Errorf("HitCount のデフォルト = %d, want 0", h.HitCount)
	}
}

// TestIOCTopHit_FieldAssignment は IOCTopHit フィールドの代入を確認する
func TestIOCTopHit_FieldAssignment(t *testing.T) {
	now := time.Now()
	h := IOCTopHit{
		Value:    "malicious.example.com",
		Type:     "domain",
		HitCount: 42,
		LastSeen: now,
	}
	if h.Value != "malicious.example.com" {
		t.Errorf("Value = %q, want \"malicious.example.com\"", h.Value)
	}
	if h.Type != "domain" {
		t.Errorf("Type = %q, want \"domain\"", h.Type)
	}
	if h.HitCount != 42 {
		t.Errorf("HitCount = %d, want 42", h.HitCount)
	}
	if !h.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", h.LastSeen, now)
	}
}

// ─── nilIfEmpty ヘルパー（IOC 側の利用）──────────────────────────────────────

// TestNilIfEmpty_IOCAddedBy は IOCEntry.AddedBy フィールドへの nil 変換を確認する
func TestNilIfEmpty_IOCAddedBy(t *testing.T) {
	// AddedBy が空のとき nilIfEmpty は nil を返す（DB に NULL を挿入するため）
	empty := ""
	result := nilIfEmpty(&empty)
	if result != nil {
		t.Errorf("空の AddedBy は nil を返すべき: got %v", result)
	}

	// AddedBy が非空のとき nilIfEmpty はそのまま返す
	userID := "user-abc-123"
	result = nilIfEmpty(&userID)
	if result == nil {
		t.Fatal("非空の AddedBy は nil でないべき")
	}
	if result.(string) != userID {
		t.Errorf("result = %v, want %q", result, userID)
	}
}

// ─── IOC クエリビルダー ロジックテスト ────────────────────────────────────────

// buildIOCWhere は **本物を呼びます。**
//
// 以前ここには List の組み立てを書き写したものが置いてありました。
// 写しを試しても、製品の側は無傷のまま壊せます。
func buildIOCWhere(iocType, search string, activeOnly bool) (string, []interface{}) {
	return iocListWhere(iocType, search, activeOnly)
}

// **値を取らない条件が、プレースホルダの番号を進めないこと。**
// `is_active` は値を取りません。ここで番号を進めると、そのあとの
// `search` が $2 を指すのに引数は1つしかなく、**一覧が丸ごと落ちます。**
func TestIOCPlaceholdersStayInStepWithArgs(t *testing.T) {
	where, args := iocListWhere("ip", "1.2.3", true)
	if len(args) != 2 {
		t.Fatalf("args = %v, want 2 件", args)
	}
	if !strings.Contains(where, "$1") || !strings.Contains(where, "$2") {
		t.Errorf("$1 と $2 が揃っていません: %q", where)
	}
	if strings.Contains(where, "$3") {
		t.Errorf("引数の数を超えるプレースホルダがあります: %q", where)
	}
	// is_active だけのとき、引数は増えません。
	where, args = iocListWhere("", "", true)
	if len(args) != 0 || strings.Contains(where, "$") {
		t.Errorf("activeOnly だけで引数/プレースホルダが増えています: %q %v",
			where, args)
	}
}

// TestBuildIOCWhere_EmptyFilter は全てのフィルターが空の場合の WHERE 句を確認する
func TestBuildIOCWhere_EmptyFilter(t *testing.T) {
	where, args := buildIOCWhere("", "", false)
	if where != "WHERE 1=1" {
		t.Errorf("空フィルターは \"WHERE 1=1\" のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestBuildIOCWhere_TypeFilter は iocType フィルターが条件を追加することを確認する
func TestBuildIOCWhere_TypeFilter(t *testing.T) {
	where, args := buildIOCWhere("ip", "", false)
	if !strings.Contains(where, "i.type") {
		t.Errorf("type 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "ip" {
		t.Errorf("args = %v, want [ip]", args)
	}
}

// TestBuildIOCWhere_ActiveOnlyFilter は activeOnly フラグが is_active 条件を追加することを確認する
func TestBuildIOCWhere_ActiveOnlyFilter(t *testing.T) {
	where, args := buildIOCWhere("", "", true)
	if !strings.Contains(where, "is_active = TRUE") {
		t.Errorf("is_active 条件が含まれるべき: %q", where)
	}
	// activeOnly はプレースホルダーを使わないので引数は空
	if len(args) != 0 {
		t.Errorf("activeOnly は引数を追加しないはず: got %v", args)
	}
}

// TestBuildIOCWhere_SearchFilter は search が ILIKE 条件をワイルドカード付きで追加することを確認する
func TestBuildIOCWhere_SearchFilter(t *testing.T) {
	where, args := buildIOCWhere("", "malware", false)
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

// TestBuildIOCWhere_AllFilters は全フィルターが組み合わさったときの引数数を確認する
func TestBuildIOCWhere_AllFilters(t *testing.T) {
	where, args := buildIOCWhere("domain", "evil", true)
	if !strings.Contains(where, "i.type") {
		t.Errorf("type 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "is_active = TRUE") {
		t.Errorf("is_active 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "ILIKE") {
		t.Errorf("ILIKE 条件が含まれるべき: %q", where)
	}
	// type と search の 2 つのプレースホルダーがある
	if len(args) != 2 {
		t.Errorf("type+search フィルターは引数 2 個のはず: got %d (%v)", len(args), args)
	}
}
