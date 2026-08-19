package store

import (
	"strings"
	"testing"
	"time"
)

// ─── Incident 構造体テスト ────────────────────────────────────────────────────

// TestIncident_ZeroValue は Incident のゼロ値が期待通りであることを確認する
func TestIncident_ZeroValue(t *testing.T) {
	var inc Incident
	if inc.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", inc.ID)
	}
	if inc.Title != "" {
		t.Errorf("Title のデフォルト = %q, want \"\"", inc.Title)
	}
	if inc.Severity != 0 {
		t.Errorf("Severity のデフォルト = %d, want 0", inc.Severity)
	}
	if inc.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", inc.Status)
	}
	if inc.AssignedTo != nil {
		t.Errorf("AssignedTo のデフォルトは nil であるべき")
	}
	if inc.CreatedBy != nil {
		t.Errorf("CreatedBy のデフォルトは nil であるべき")
	}
	if inc.ResolvedAt != nil {
		t.Errorf("ResolvedAt のデフォルトは nil であるべき")
	}
	if inc.AlertCount != 0 {
		t.Errorf("AlertCount のデフォルト = %d, want 0", inc.AlertCount)
	}
}

// TestIncident_ValidStatuses は有効なインシデントステータス値を確認する
func TestIncident_ValidStatuses(t *testing.T) {
	// EDRプラットフォームで使用される標準的なインシデントステータスの検証
	validStatuses := []string{"open", "in_progress", "resolved", "closed"}
	for _, status := range validStatuses {
		inc := Incident{Status: status}
		if inc.Status != status {
			t.Errorf("Status = %q, want %q", inc.Status, status)
		}
	}
}

// TestIncident_SeverityRange はインシデントの深刻度が 1〜10 の範囲で設定できることを確認する
func TestIncident_SeverityRange(t *testing.T) {
	for sev := 1; sev <= 10; sev++ {
		inc := Incident{Severity: sev}
		if inc.Severity != sev {
			t.Errorf("Severity = %d, want %d", inc.Severity, sev)
		}
	}
}

// TestIncident_ResolvedAtSetOnResolution はインシデント解決時に ResolvedAt が設定されることを確認する
func TestIncident_ResolvedAtSetOnResolution(t *testing.T) {
	now := time.Now()
	inc := Incident{
		Status:     "resolved",
		ResolvedAt: &now,
	}
	if inc.ResolvedAt == nil {
		t.Fatal("resolved ステータスのとき ResolvedAt は nil でないべき")
	}
	// 解決時刻がゼロでないことを確認する
	if inc.ResolvedAt.IsZero() {
		t.Error("ResolvedAt はゼロ時刻であってはならない")
	}
}

// TestIncident_ResolvedAtNilWhenOpen はオープン状態のインシデントで ResolvedAt が nil であることを確認する
func TestIncident_ResolvedAtNilWhenOpen(t *testing.T) {
	inc := Incident{Status: "open"}
	if inc.ResolvedAt != nil {
		t.Error("open ステータスのとき ResolvedAt は nil であるべき")
	}
}

// TestIncident_AssignedToFieldBehavior は AssignedTo のポインタ動作を確認する
func TestIncident_AssignedToFieldBehavior(t *testing.T) {
	// 担当者なしの場合
	inc := Incident{}
	if inc.AssignedTo != nil {
		t.Error("未割り当てのとき AssignedTo は nil であるべき")
	}

	// 担当者ありの場合
	userID := "user-uuid-001"
	inc.AssignedTo = &userID
	if inc.AssignedTo == nil {
		t.Fatal("担当者設定後、AssignedTo は nil でないべき")
	}
	if *inc.AssignedTo != userID {
		t.Errorf("*AssignedTo = %q, want %q", *inc.AssignedTo, userID)
	}
}

// TestIncident_FieldAssignment は Incident の全フィールドが正しく代入できることを確認する
func TestIncident_FieldAssignment(t *testing.T) {
	now := time.Now()
	assignedTo := "user-uuid-001"
	createdBy := "user-uuid-002"
	resolvedAt := now.Add(2 * time.Hour)

	inc := Incident{
		ID:             "inc-001",
		Title:          "ランサムウェア感染疑い",
		Description:    "複数のホストで不審なプロセスを検出",
		Severity:       9,
		Status:         "in_progress",
		AssignedTo:     &assignedTo,
		AssignedToName: "analyst@example.com",
		CreatedBy:      &createdBy,
		CreatedByName:  "admin@example.com",
		AlertCount:     5,
		CreatedAt:      now,
		UpdatedAt:      now,
		ResolvedAt:     &resolvedAt,
	}

	if inc.ID != "inc-001" {
		t.Errorf("ID = %q, want \"inc-001\"", inc.ID)
	}
	if inc.Severity != 9 {
		t.Errorf("Severity = %d, want 9", inc.Severity)
	}
	if inc.AlertCount != 5 {
		t.Errorf("AlertCount = %d, want 5", inc.AlertCount)
	}
	if *inc.AssignedTo != assignedTo {
		t.Errorf("*AssignedTo = %q, want %q", *inc.AssignedTo, assignedTo)
	}
}

// ─── IncidentAlert 構造体テスト ───────────────────────────────────────────────

// TestIncidentAlert_ZeroValue は IncidentAlert のゼロ値を確認する
func TestIncidentAlert_ZeroValue(t *testing.T) {
	var a IncidentAlert
	if a.AlertID != "" {
		t.Errorf("AlertID のデフォルト = %q, want \"\"", a.AlertID)
	}
	if a.Severity != 0 {
		t.Errorf("Severity のデフォルト = %d, want 0", a.Severity)
	}
	if a.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", a.Status)
	}
	if a.Hostname != "" {
		t.Errorf("Hostname のデフォルト = %q, want \"\"", a.Hostname)
	}
}

// TestIncidentAlert_FieldAssignment は IncidentAlert フィールド代入を確認する
func TestIncidentAlert_FieldAssignment(t *testing.T) {
	now := time.Now()
	a := IncidentAlert{
		AlertID:   "alert-uuid-001",
		Title:     "不審なプロセス検出",
		Severity:  7,
		Status:    "open",
		Hostname:  "WORKSTATION-01",
		CreatedAt: now,
		LinkedAt:  now,
	}
	if a.AlertID != "alert-uuid-001" {
		t.Errorf("AlertID = %q, want \"alert-uuid-001\"", a.AlertID)
	}
	if a.Severity != 7 {
		t.Errorf("Severity = %d, want 7", a.Severity)
	}
	if a.Hostname != "WORKSTATION-01" {
		t.Errorf("Hostname = %q, want \"WORKSTATION-01\"", a.Hostname)
	}
}

// ─── IncidentNote 構造体テスト ────────────────────────────────────────────────

// TestIncidentNote_ZeroValue は IncidentNote のゼロ値を確認する
func TestIncidentNote_ZeroValue(t *testing.T) {
	var n IncidentNote
	if n.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", n.ID)
	}
	if n.IncidentID != "" {
		t.Errorf("IncidentID のデフォルト = %q, want \"\"", n.IncidentID)
	}
	if n.UserID != nil {
		t.Error("UserID のデフォルトは nil であるべき")
	}
	if n.Body != "" {
		t.Errorf("Body のデフォルト = %q, want \"\"", n.Body)
	}
}

// TestIncidentNote_BodyNotEmpty はノートの本文が空でない場合を確認する
func TestIncidentNote_BodyNotEmpty(t *testing.T) {
	n := IncidentNote{
		ID:         "note-001",
		IncidentID: "inc-001",
		Body:       "初回トリアージ完了。悪意あるPowerShellスクリプトを確認。",
	}
	if strings.TrimSpace(n.Body) == "" {
		t.Error("Body は空でないべき")
	}
}

// TestIncidentNote_UserIDPointerBehavior は UserID ポインタの動作を確認する
func TestIncidentNote_UserIDPointerBehavior(t *testing.T) {
	// システムノートはユーザーIDなし
	sysNote := IncidentNote{Body: "自動検出: ルールが発火しました"}
	if sysNote.UserID != nil {
		t.Error("システムノートの UserID は nil であるべき")
	}

	// ユーザーノートはユーザーIDあり
	uid := "user-uuid-999"
	userNote := IncidentNote{
		UserID:   &uid,
		UserName: "analyst@example.com",
		Body:     "手動で調査中",
	}
	if userNote.UserID == nil || *userNote.UserID != uid {
		t.Errorf("UserID = %v, want %q", userNote.UserID, uid)
	}
}

// ─── インシデントフィルタービルダーのテスト ────────────────────────────────────

// buildIncidentWhere は **本物を呼びます。**
//
// 以前ここには List の組み立てを書き写したものが置いてありましたが、
// **`"active"` の分岐がありませんでした** —— 一覧の既定の絞り込みが、
// 写しには存在しないまま「確かめた」ことになっていました。
func buildIncidentWhere(status string) (string, []interface{}) {
	return incidentListWhere(status)
}

// **写しに無かった分岐。** "active" は「対応が必要」を意味し、
// 解決済み・クローズ済みを外します。値を取らない条件なので、引数は
// 増えません —— ここで引数を1つ足すと、LIMIT のプレースホルダがずれて
// 一覧が丸ごと落ちます。
func TestIncidentActiveExpandsToSeveralStatuses(t *testing.T) {
	where, args := incidentListWhere("active")
	for _, want := range []string{"open", "investigating", "contained"} {
		if !strings.Contains(where, "'"+want+"'") {
			t.Errorf("active に %q が含まれていません: %q", want, where)
		}
	}
	for _, notWant := range []string{"resolved", "closed"} {
		if strings.Contains(where, "'"+notWant+"'") {
			t.Errorf("active に %q が含まれています: %q", notWant, where)
		}
	}
	if len(args) != 0 {
		t.Errorf("args = %v, want 空。**値を取らない条件です** —— "+
			"引数を足すと LIMIT のプレースホルダがずれます", args)
	}
	if strings.Contains(where, "$") {
		t.Errorf("プレースホルダが入っています: %q", where)
	}
}

// TestBuildIncidentWhere_EmptyStatus はステータスフィルターなしの WHERE 句を確認する
func TestBuildIncidentWhere_EmptyStatus(t *testing.T) {
	where, args := buildIncidentWhere("")
	if where != "WHERE 1=1" {
		t.Errorf("空ステータスは \"WHERE 1=1\" のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空ステータスは引数なしのはず: got %v", args)
	}
}

// TestBuildIncidentWhere_WithStatus はステータスフィルターが WHERE 句に追加されることを確認する
func TestBuildIncidentWhere_WithStatus(t *testing.T) {
	where, args := buildIncidentWhere("open")
	if !strings.Contains(where, "i.status = $1") {
		t.Errorf("status 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "open" {
		t.Errorf("args = %v, want [open]", args)
	}
}

// TestBuildIncidentWhere_ResolvedStatus はresolved ステータスフィルターを確認する
func TestBuildIncidentWhere_ResolvedStatus(t *testing.T) {
	where, args := buildIncidentWhere("resolved")
	if !strings.Contains(where, "status") {
		t.Errorf("status 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "resolved" {
		t.Errorf("args = %v, want [resolved]", args)
	}
}

// TestIncident_ClosedAndResolvedSetResolvedAt はclosedとresolvedのとき
// resolved_at が更新対象になることをロジックで確認する
func TestIncident_ClosedAndResolvedSetResolvedAt(t *testing.T) {
	// Update メソッドのロジックを反映したヘルパー
	shouldSetResolvedAt := func(status string) bool {
		return status == "resolved" || status == "closed"
	}

	cases := []struct {
		status string
		want   bool
	}{
		{"resolved", true},
		{"closed", true},
		{"open", false},
		{"in_progress", false},
	}
	for _, tc := range cases {
		if got := shouldSetResolvedAt(tc.status); got != tc.want {
			t.Errorf("shouldSetResolvedAt(%q) = %v, want %v", tc.status, got, tc.want)
		}
	}
}
