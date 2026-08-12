package store

import (
	"strings"
	"testing"
	"time"
)

// ─── ハントクエリバリデーションヘルパー ──────────────────────────────────────

// validHuntQueryTypes は使用可能なクエリタイプの一覧を返す
func validHuntQueryTypes() []string {
	return []string{"sql", "eql", "yara", "sigma", "kql", "lucene"}
}

// isValidHuntQueryType はクエリタイプが有効かどうかを判定する
func isValidHuntQueryType(queryType string) bool {
	for _, v := range validHuntQueryTypes() {
		if v == queryType {
			return true
		}
	}
	return false
}

// huntQueryIsNonEmpty はクエリ文字列が空でないか確認する
func huntQueryIsNonEmpty(query string) bool {
	return strings.TrimSpace(query) != ""
}

// huntQueryExceedsMaxLength はクエリが最大長を超えているか確認する（最大 65536 文字）
func huntQueryExceedsMaxLength(query string) bool {
	return len(query) > 65536
}

// huntNameIsValid はハントクエリの名前が有効か確認する（空でなく、255文字以下）
func huntNameIsValid(name string) bool {
	return len(strings.TrimSpace(name)) > 0 && len(name) <= 255
}

// filterSharedHuntQueries は共有フラグが true のクエリのみ返す
func filterSharedHuntQueries(queries []SavedHuntQuery) []SavedHuntQuery {
	var result []SavedHuntQuery
	for _, q := range queries {
		if q.IsShared {
			result = append(result, q)
		}
	}
	if result == nil {
		result = []SavedHuntQuery{}
	}
	return result
}

// filterHuntQueriesByType はクエリタイプでフィルタリングする
func filterHuntQueriesByType(queries []SavedHuntQuery, queryType string) []SavedHuntQuery {
	var result []SavedHuntQuery
	for _, q := range queries {
		if q.QueryType == queryType {
			result = append(result, q)
		}
	}
	if result == nil {
		result = []SavedHuntQuery{}
	}
	return result
}

// filterHuntQueriesByTag は指定タグを含むクエリのみ返す
func filterHuntQueriesByTag(queries []SavedHuntQuery, tag string) []SavedHuntQuery {
	var result []SavedHuntQuery
	for _, q := range queries {
		for _, t := range q.Tags {
			if t == tag {
				result = append(result, q)
				break
			}
		}
	}
	if result == nil {
		result = []SavedHuntQuery{}
	}
	return result
}

// huntQueryOwnedBy は指定ユーザーが作成したクエリかどうかを確認する
func huntQueryOwnedBy(q *SavedHuntQuery, userID string) bool {
	return q.CreatedBy != nil && *q.CreatedBy == userID
}

// ─── SavedHuntQuery 構造体テスト ──────────────────────────────────────────────

// TestSavedHuntQuery_ZeroValue は SavedHuntQuery のゼロ値フィールドを確認する
func TestSavedHuntQuery_ZeroValue(t *testing.T) {
	// 全フィールドのデフォルト値を確認する
	var q SavedHuntQuery
	if q.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", q.ID)
	}
	if q.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", q.Name)
	}
	if q.Query != "" {
		t.Errorf("Query のデフォルト = %q, want \"\"", q.Query)
	}
	if q.QueryType != "" {
		t.Errorf("QueryType のデフォルト = %q, want \"\"", q.QueryType)
	}
	if q.IsShared {
		t.Error("IsShared のデフォルトは false であるべき")
	}
	if q.RunCount != 0 {
		t.Errorf("RunCount のデフォルト = %d, want 0", q.RunCount)
	}
	if q.Description != nil {
		t.Error("Description のデフォルトは nil であるべき")
	}
	if q.CreatedBy != nil {
		t.Error("CreatedBy のデフォルトは nil であるべき")
	}
	if q.LastRunAt != nil {
		t.Error("LastRunAt のデフォルトは nil であるべき")
	}
	if q.Tags != nil {
		t.Errorf("Tags のデフォルトは nil であるべき: got %v", q.Tags)
	}
}

// TestSavedHuntQuery_FieldAssignment は SavedHuntQuery のフィールド代入を確認する
func TestSavedHuntQuery_FieldAssignment(t *testing.T) {
	// 全フィールドへの代入が正しく反映されるか確認する
	desc := "ランサムウェアの初期侵入を検出するクエリ"
	createdBy := "analyst-001"
	now := time.Now()
	lastRun := now.Add(-time.Hour)

	q := SavedHuntQuery{
		ID:          "hunt-001",
		Name:        "ランサムウェア検出クエリ",
		Description: &desc,
		Query:       "SELECT * FROM processes WHERE name LIKE '%ransomware%'",
		QueryType:   "sql",
		Tags:        []string{"ransomware", "initial_access"},
		CreatedBy:   &createdBy,
		IsShared:    true,
		RunCount:    12,
		LastRunAt:   &lastRun,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if q.ID != "hunt-001" {
		t.Errorf("ID = %q, want \"hunt-001\"", q.ID)
	}
	if q.Description == nil || *q.Description != desc {
		t.Errorf("Description = %v, want %q", q.Description, desc)
	}
	if q.QueryType != "sql" {
		t.Errorf("QueryType = %q, want \"sql\"", q.QueryType)
	}
	if !q.IsShared {
		t.Error("IsShared は true であるべき")
	}
	if q.RunCount != 12 {
		t.Errorf("RunCount = %d, want 12", q.RunCount)
	}
	if len(q.Tags) != 2 {
		t.Errorf("Tags の長さ = %d, want 2", len(q.Tags))
	}
	if q.CreatedBy == nil || *q.CreatedBy != createdBy {
		t.Errorf("CreatedBy = %v, want %q", q.CreatedBy, createdBy)
	}
	if q.LastRunAt == nil || !q.LastRunAt.Equal(lastRun) {
		t.Errorf("LastRunAt が期待値と一致しない")
	}
}

// TestIsValidHuntQueryType_KnownTypes は既知のクエリタイプが全て有効と判定されることを確認する
func TestIsValidHuntQueryType_KnownTypes(t *testing.T) {
	// 定義済みの全クエリタイプが有効と判定されるか確認する
	for _, qt := range validHuntQueryTypes() {
		if !isValidHuntQueryType(qt) {
			t.Errorf("有効なクエリタイプ %q が無効と判定された", qt)
		}
	}
}

// TestIsValidHuntQueryType_UnknownTypes は未知のクエリタイプが拒否されることを確認する
func TestIsValidHuntQueryType_UnknownTypes(t *testing.T) {
	// 定義されていないクエリタイプは拒否される
	unknownTypes := []string{"SQL", "Sigma", "splunk", "xql", "", "osquery"}
	for _, qt := range unknownTypes {
		if isValidHuntQueryType(qt) {
			t.Errorf("未知のクエリタイプ %q が有効と判定された", qt)
		}
	}
}

// TestHuntQueryIsNonEmpty_NonEmptyQuery は空でないクエリが有効と判定されることを確認する
func TestHuntQueryIsNonEmpty_NonEmptyQuery(t *testing.T) {
	// 実際のクエリ文字列が有効と判定されるか確認する
	validQueries := []string{
		"SELECT * FROM processes",
		"process where process.name == 'cmd.exe'",
		"rule malware { strings: $a = \"suspicious\" condition: $a }",
	}
	for _, q := range validQueries {
		if !huntQueryIsNonEmpty(q) {
			t.Errorf("クエリ %q は空でないと判定されるべき", q)
		}
	}
}

// TestHuntQueryIsNonEmpty_EmptyOrWhitespace は空またはホワイトスペースのみのクエリが無効と判定されることを確認する
func TestHuntQueryIsNonEmpty_EmptyOrWhitespace(t *testing.T) {
	// 空文字やスペースのみは無効
	invalidQueries := []string{"", "   ", "\t", "\n", "  \t  "}
	for _, q := range invalidQueries {
		if huntQueryIsNonEmpty(q) {
			t.Errorf("クエリ %q は空と判定されるべき", q)
		}
	}
}

// TestHuntQueryExceedsMaxLength_WithinLimit は許容範囲内のクエリが上限超過しないことを確認する
func TestHuntQueryExceedsMaxLength_WithinLimit(t *testing.T) {
	// 正常なクエリは上限超過しない
	normalQuery := strings.Repeat("x", 1000)
	if huntQueryExceedsMaxLength(normalQuery) {
		t.Errorf("1000文字のクエリは上限超過すべきでない")
	}
}

// TestHuntQueryExceedsMaxLength_ExceedsLimit は最大長を超えるクエリが上限超過と判定されることを確認する
func TestHuntQueryExceedsMaxLength_ExceedsLimit(t *testing.T) {
	// 65537文字は上限超過
	tooLongQuery := strings.Repeat("a", 65537)
	if !huntQueryExceedsMaxLength(tooLongQuery) {
		t.Error("65537文字のクエリは上限超過と判定されるべき")
	}
}

// TestHuntQueryExceedsMaxLength_ExactLimit は正確に最大長のクエリが上限超過しないことを確認する
func TestHuntQueryExceedsMaxLength_ExactLimit(t *testing.T) {
	// 65536文字はぴったり上限なので超過しない
	exactLimitQuery := strings.Repeat("b", 65536)
	if huntQueryExceedsMaxLength(exactLimitQuery) {
		t.Error("65536文字のクエリは上限超過すべきでない（ぴったり上限）")
	}
}

// TestHuntNameIsValid_ValidNames は有効な名前の検証を確認する
func TestHuntNameIsValid_ValidNames(t *testing.T) {
	// 有効な名前は空でなく、255文字以下
	validNames := []string{"My Hunt", "APT Detection", strings.Repeat("a", 255)}
	for _, name := range validNames {
		if !huntNameIsValid(name) {
			t.Errorf("名前 %q は有効であるべき", name)
		}
	}
}

// TestHuntNameIsValid_InvalidNames は無効な名前が拒否されることを確認する
func TestHuntNameIsValid_InvalidNames(t *testing.T) {
	// 空文字、スペースのみ、256文字以上は無効
	invalidNames := []string{"", "   ", strings.Repeat("x", 256)}
	for _, name := range invalidNames {
		if huntNameIsValid(name) {
			t.Errorf("名前 %q は無効であるべき", name)
		}
	}
}

// TestFilterSharedHuntQueries_FiltersCorrectly は共有クエリのフィルタリングを確認する
func TestFilterSharedHuntQueries_FiltersCorrectly(t *testing.T) {
	// IsShared=true のクエリのみが返されることを確認する
	queries := []SavedHuntQuery{
		{ID: "q1", IsShared: true},
		{ID: "q2", IsShared: false},
		{ID: "q3", IsShared: true},
		{ID: "q4", IsShared: false},
	}
	shared := filterSharedHuntQueries(queries)
	if len(shared) != 2 {
		t.Errorf("共有クエリ数 = %d, want 2", len(shared))
	}
	for _, q := range shared {
		if !q.IsShared {
			t.Errorf("非共有クエリ %q がフィルタ結果に含まれている", q.ID)
		}
	}
}

// TestFilterSharedHuntQueries_EmptyInput は空入力が空スライスを返すことを確認する
func TestFilterSharedHuntQueries_EmptyInput(t *testing.T) {
	// 空スライス入力は空スライスを返す
	result := filterSharedHuntQueries([]SavedHuntQuery{})
	if len(result) != 0 {
		t.Errorf("空入力から空出力のはず: got %d items", len(result))
	}
}

// TestFilterHuntQueriesByType_FiltersCorrectly はクエリタイプによるフィルタリングを確認する
func TestFilterHuntQueriesByType_FiltersCorrectly(t *testing.T) {
	// 指定のクエリタイプのみが返されることを確認する
	queries := []SavedHuntQuery{
		{ID: "q1", QueryType: "sql"},
		{ID: "q2", QueryType: "yara"},
		{ID: "q3", QueryType: "sql"},
		{ID: "q4", QueryType: "eql"},
	}
	sqlQueries := filterHuntQueriesByType(queries, "sql")
	if len(sqlQueries) != 2 {
		t.Errorf("sql クエリ数 = %d, want 2", len(sqlQueries))
	}
	for _, q := range sqlQueries {
		if q.QueryType != "sql" {
			t.Errorf("フィルタ結果に sql 以外のクエリ %q が含まれている", q.QueryType)
		}
	}
}

// TestFilterHuntQueriesByTag_FiltersCorrectly はタグによるフィルタリングを確認する
func TestFilterHuntQueriesByTag_FiltersCorrectly(t *testing.T) {
	// 指定タグを含むクエリのみが返されることを確認する
	queries := []SavedHuntQuery{
		{ID: "q1", Tags: []string{"ransomware", "lateral_movement"}},
		{ID: "q2", Tags: []string{"exfiltration"}},
		{ID: "q3", Tags: []string{"ransomware", "execution"}},
	}
	result := filterHuntQueriesByTag(queries, "ransomware")
	if len(result) != 2 {
		t.Errorf("ransomware タグクエリ数 = %d, want 2", len(result))
	}
}

// TestHuntQueryOwnedBy_OwnedQuery はクエリが指定ユーザーに帰属することを確認する
func TestHuntQueryOwnedBy_OwnedQuery(t *testing.T) {
	// CreatedBy が一致する場合は帰属している
	userID := "user-abc"
	q := &SavedHuntQuery{CreatedBy: &userID}
	if !huntQueryOwnedBy(q, "user-abc") {
		t.Error("クエリは user-abc に帰属するべき")
	}
}

// TestHuntQueryOwnedBy_NotOwned はクエリが指定ユーザーに帰属しないことを確認する
func TestHuntQueryOwnedBy_NotOwned(t *testing.T) {
	// CreatedBy が異なる場合は帰属しない
	userID := "user-abc"
	q := &SavedHuntQuery{CreatedBy: &userID}
	if huntQueryOwnedBy(q, "user-xyz") {
		t.Error("クエリは user-xyz に帰属すべきでない")
	}
}

// TestHuntQueryOwnedBy_NilCreatedBy は CreatedBy が nil の場合は帰属しないことを確認する
func TestHuntQueryOwnedBy_NilCreatedBy(t *testing.T) {
	// CreatedBy が nil のクエリはどのユーザーにも帰属しない
	q := &SavedHuntQuery{CreatedBy: nil}
	if huntQueryOwnedBy(q, "user-abc") {
		t.Error("CreatedBy が nil のクエリはどのユーザーにも帰属すべきでない")
	}
}

// TestHuntQueryCols_ContainsRequiredColumns は huntQueryCols 定数を確認する
func TestHuntQueryCols_ContainsRequiredColumns(t *testing.T) {
	// huntQueryCols が必須カラムを含むか検証する
	requiredCols := []string{"query_type", "is_shared", "run_count", "last_run_at", "tags"}
	for _, col := range requiredCols {
		if !strings.Contains(huntQueryCols, col) {
			t.Errorf("huntQueryCols に %q が含まれていない", col)
		}
	}
}

// TestSavedHuntQuery_TagsCanBeEmpty は Tags が空スライスとして設定できることを確認する
func TestSavedHuntQuery_TagsCanBeEmpty(t *testing.T) {
	// タグなしのクエリでも空スライスとして正しく扱われる
	q := SavedHuntQuery{
		Name:      "タグなしクエリ",
		QueryType: "kql",
		Tags:      []string{},
	}
	if q.Tags == nil {
		t.Error("Tags は nil でなく空スライスであるべき")
	}
	if len(q.Tags) != 0 {
		t.Errorf("Tags の長さ = %d, want 0", len(q.Tags))
	}
}
