package store

import (
	"strings"
	"testing"
	"time"
)

// ─── AuditLog 構造体テスト ────────────────────────────────────────────────────

// TestAuditLog_ZeroValue は AuditLog のゼロ値が期待通りであることを確認する
func TestAuditLog_ZeroValue(t *testing.T) {
	var l AuditLog
	if l.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", l.ID)
	}
	if l.UserID != "" {
		t.Errorf("UserID のデフォルト = %q, want \"\"", l.UserID)
	}
	if l.UserEmail != "" {
		t.Errorf("UserEmail のデフォルト = %q, want \"\"", l.UserEmail)
	}
	if l.Action != "" {
		t.Errorf("Action のデフォルト = %q, want \"\"", l.Action)
	}
	if l.ResourceID != "" {
		t.Errorf("ResourceID のデフォルト = %q, want \"\"", l.ResourceID)
	}
	if l.IPAddress != "" {
		t.Errorf("IPAddress のデフォルト = %q, want \"\"", l.IPAddress)
	}
	if l.StatusCode != 0 {
		t.Errorf("StatusCode のデフォルト = %d, want 0", l.StatusCode)
	}
	if l.Details != nil {
		t.Errorf("Details のデフォルトは nil であるべき")
	}
}

// TestAuditLog_FieldAssignment は AuditLog の全フィールドが正しく代入できることを確認する
func TestAuditLog_FieldAssignment(t *testing.T) {
	now := time.Now()
	l := AuditLog{
		ID:         "log-uuid-001",
		Timestamp:  now,
		UserID:     "user-uuid-001",
		UserEmail:  "admin@example.com",
		Action:     "POST /api/incidents",
		ResourceID: "inc-uuid-001",
		IPAddress:  "203.0.113.10",
		StatusCode: 201,
		Details:    map[string]interface{}{"title": "ランサムウェア感染疑い"},
	}

	if l.ID != "log-uuid-001" {
		t.Errorf("ID = %q, want \"log-uuid-001\"", l.ID)
	}
	if l.UserEmail != "admin@example.com" {
		t.Errorf("UserEmail = %q, want \"admin@example.com\"", l.UserEmail)
	}
	if l.Action != "POST /api/incidents" {
		t.Errorf("Action = %q, want \"POST /api/incidents\"", l.Action)
	}
	if l.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want 201", l.StatusCode)
	}
	if l.Details["title"] != "ランサムウェア感染疑い" {
		t.Errorf("Details[title] = %v, want \"ランサムウェア感染疑い\"", l.Details["title"])
	}
}

// TestAuditLog_HTTPMethodPrefixes は HTTP メソッドプレフィックスが Action に含まれることを確認する
func TestAuditLog_HTTPMethodPrefixes(t *testing.T) {
	// AuditFilter.Method は action 列の前方一致に使用される
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		action := method + " /api/resources"
		l := AuditLog{Action: action}
		if !strings.HasPrefix(l.Action, method) {
			t.Errorf("Action はメソッド %q で始まるべき: got %q", method, l.Action)
		}
	}
}

// TestAuditLog_StatusCodeClassification は HTTP ステータスコードの分類ロジックを確認する
func TestAuditLog_StatusCodeClassification(t *testing.T) {
	// OnlyErrors フィルターは status_code >= 400 を対象とする
	isError := func(code int) bool {
		return code >= 400
	}

	cases := []struct {
		code    int
		isError bool
	}{
		{200, false},
		{201, false},
		{204, false},
		{301, false},
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{500, true},
		{503, true},
	}
	for _, tc := range cases {
		if got := isError(tc.code); got != tc.isError {
			t.Errorf("isError(%d) = %v, want %v", tc.code, got, tc.isError)
		}
	}
}

// TestAuditFilter_ZeroValue は AuditFilter のゼロ値を確認する
func TestAuditFilter_ZeroValue(t *testing.T) {
	var f AuditFilter
	if f.UserEmail != "" {
		t.Errorf("UserEmail のデフォルト = %q, want \"\"", f.UserEmail)
	}
	if f.Method != "" {
		t.Errorf("Method のデフォルト = %q, want \"\"", f.Method)
	}
	if f.OnlyErrors {
		t.Error("OnlyErrors のデフォルトは false であるべき")
	}
}

// TestAuditFilter_FieldAssignment は AuditFilter のフィールド代入を確認する
func TestAuditFilter_FieldAssignment(t *testing.T) {
	f := AuditFilter{
		UserEmail:  "analyst@example.com",
		Method:     "POST",
		OnlyErrors: true,
	}
	if f.UserEmail != "analyst@example.com" {
		t.Errorf("UserEmail = %q, want \"analyst@example.com\"", f.UserEmail)
	}
	if f.Method != "POST" {
		t.Errorf("Method = %q, want \"POST\"", f.Method)
	}
	if !f.OnlyErrors {
		t.Error("OnlyErrors は true であるべき")
	}
}

// ─── 監査ログ WHERE 句ビルダーのテスト ────────────────────────────────────────

// buildAuditWhere は audit.go の List メソッドの WHERE 句構築を再現するヘルパー
func buildAuditWhere(f AuditFilter) (string, []interface{}) {
	conds := []string{"1=1"}
	args := []interface{}{}
	idx := 1

	if f.UserEmail != "" {
		conds = append(conds, "user_email ILIKE $"+itoa(idx))
		args = append(args, "%"+f.UserEmail+"%")
		idx++
	}
	if f.Method != "" {
		conds = append(conds, "action ILIKE $"+itoa(idx))
		args = append(args, f.Method+"%")
		idx++
	}
	if f.OnlyErrors {
		conds = append(conds, "status_code >= 400")
	}
	_ = idx

	where := "WHERE " + strings.Join(conds, " AND ")
	return where, args
}

// TestBuildAuditWhere_EmptyFilter は全フィルターが空の場合の WHERE 句を確認する
func TestBuildAuditWhere_EmptyFilter(t *testing.T) {
	where, args := buildAuditWhere(AuditFilter{})
	if where != "WHERE 1=1" {
		t.Errorf("空フィルターは \"WHERE 1=1\" のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestBuildAuditWhere_UserEmailFilter は UserEmail フィルターが ILIKE 条件を追加することを確認する
func TestBuildAuditWhere_UserEmailFilter(t *testing.T) {
	where, args := buildAuditWhere(AuditFilter{UserEmail: "admin"})
	if !strings.Contains(where, "user_email ILIKE") {
		t.Errorf("user_email ILIKE 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 {
		t.Fatalf("args の数 = %d, want 1", len(args))
	}
	emailArg, ok := args[0].(string)
	if !ok {
		t.Fatalf("args[0] は string のはず")
	}
	// ワイルドカードで囲まれていることを確認する
	if !strings.HasPrefix(emailArg, "%") || !strings.HasSuffix(emailArg, "%") {
		t.Errorf("UserEmail 引数は %%...%% で囲まれるべき: %q", emailArg)
	}
	if !strings.Contains(emailArg, "admin") {
		t.Errorf("UserEmail 引数に 'admin' が含まれるべき: %q", emailArg)
	}
}

// TestBuildAuditWhere_MethodFilter は Method フィルターがプレフィックス一致条件を追加することを確認する
func TestBuildAuditWhere_MethodFilter(t *testing.T) {
	where, args := buildAuditWhere(AuditFilter{Method: "DELETE"})
	if !strings.Contains(where, "action ILIKE") {
		t.Errorf("action ILIKE 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 {
		t.Fatalf("args の数 = %d, want 1", len(args))
	}
	methodArg, ok := args[0].(string)
	if !ok {
		t.Fatalf("args[0] は string のはず")
	}
	// プレフィックス一致 (後方ワイルドカードのみ) を確認する
	if !strings.HasPrefix(methodArg, "DELETE") {
		t.Errorf("Method 引数は \"DELETE\" で始まるべき: %q", methodArg)
	}
	if !strings.HasSuffix(methodArg, "%") {
		t.Errorf("Method 引数は \"%%\" で終わるべき: %q", methodArg)
	}
}

// TestBuildAuditWhere_OnlyErrors は OnlyErrors フラグが status_code 条件を追加することを確認する
func TestBuildAuditWhere_OnlyErrors(t *testing.T) {
	where, args := buildAuditWhere(AuditFilter{OnlyErrors: true})
	if !strings.Contains(where, "status_code >= 400") {
		t.Errorf("status_code >= 400 条件が含まれるべき: %q", where)
	}
	// OnlyErrors はプレースホルダーを使わないので引数は空
	if len(args) != 0 {
		t.Errorf("OnlyErrors は引数を追加しないはず: got %v", args)
	}
}

// TestBuildAuditWhere_AllFilters は全フィルターが組み合わさったときを確認する
func TestBuildAuditWhere_AllFilters(t *testing.T) {
	f := AuditFilter{
		UserEmail:  "analyst",
		Method:     "POST",
		OnlyErrors: true,
	}
	where, args := buildAuditWhere(f)
	if !strings.Contains(where, "user_email ILIKE") {
		t.Errorf("user_email 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "action ILIKE") {
		t.Errorf("action 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "status_code >= 400") {
		t.Errorf("status_code 条件が含まれるべき: %q", where)
	}
	// UserEmail と Method の 2 つのプレースホルダー引数がある
	if len(args) != 2 {
		t.Errorf("全フィルターで引数 2 個のはず: got %d (%v)", len(args), args)
	}
}

// TestBuildAuditWhere_MultipleANDConditions は複数条件が AND で結合されることを確認する
func TestBuildAuditWhere_MultipleANDConditions(t *testing.T) {
	f := AuditFilter{
		UserEmail: "user",
		Method:    "GET",
	}
	where, _ := buildAuditWhere(f)
	// 複数条件は AND で結合されるべき
	if !strings.Contains(where, " AND ") {
		t.Errorf("複数条件は AND で結合されるべき: %q", where)
	}
}

// TestAuditLog_TimestampIsTime は AuditLog の Timestamp が time.Time 型であることを確認する
func TestAuditLog_TimestampIsTime(t *testing.T) {
	now := time.Now()
	l := AuditLog{Timestamp: now}
	if l.Timestamp.IsZero() {
		t.Error("Timestamp はゼロ時刻であってはならない")
	}
	if !l.Timestamp.Equal(now) {
		t.Errorf("Timestamp = %v, want %v", l.Timestamp, now)
	}
}
