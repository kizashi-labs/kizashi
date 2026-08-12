package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─── SoftwareEntry 構造体テスト ───────────────────────────────────────────────

// TestSoftwareEntry_ZeroValue は SoftwareEntry のゼロ値が期待通りであることを確認する
func TestSoftwareEntry_ZeroValue(t *testing.T) {
	var sw SoftwareEntry
	if sw.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", sw.ID)
	}
	if sw.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", sw.AgentID)
	}
	if sw.Name != "" {
		t.Errorf("Name のデフォルト = %q, want \"\"", sw.Name)
	}
	if sw.Version != "" {
		t.Errorf("Version のデフォルト = %q, want \"\"", sw.Version)
	}
	if sw.Vendor != "" {
		t.Errorf("Vendor のデフォルト = %q, want \"\"", sw.Vendor)
	}
	if sw.InstallDate != "" {
		t.Errorf("InstallDate のデフォルト = %q, want \"\"", sw.InstallDate)
	}
	if sw.InstallPath != "" {
		t.Errorf("InstallPath のデフォルト = %q, want \"\"", sw.InstallPath)
	}
}

// TestSoftwareEntry_FieldAssignment は SoftwareEntry の全フィールド代入を確認する
func TestSoftwareEntry_FieldAssignment(t *testing.T) {
	now := time.Now()
	sw := SoftwareEntry{
		ID:          "sw-001",
		AgentID:     "agent-abc",
		Name:        "Microsoft Visual C++ Runtime",
		Version:     "14.32.31332",
		Vendor:      "Microsoft Corporation",
		InstallDate: "2025-06-15",
		InstallPath: "C:/Program Files/Microsoft/VC",
		ReportedAt:  now,
	}

	if sw.ID != "sw-001" {
		t.Errorf("ID = %q, want \"sw-001\"", sw.ID)
	}
	if sw.Name != "Microsoft Visual C++ Runtime" {
		t.Errorf("Name = %q, want \"Microsoft Visual C++ Runtime\"", sw.Name)
	}
	if sw.Version != "14.32.31332" {
		t.Errorf("Version = %q, want \"14.32.31332\"", sw.Version)
	}
	if sw.Vendor != "Microsoft Corporation" {
		t.Errorf("Vendor = %q, want \"Microsoft Corporation\"", sw.Vendor)
	}
	if !sw.ReportedAt.Equal(now) {
		t.Errorf("ReportedAt = %v, want %v", sw.ReportedAt, now)
	}
}

// TestSoftwareEntry_JSONSerialization は SoftwareEntry の JSON シリアライズを確認する
func TestSoftwareEntry_JSONSerialization(t *testing.T) {
	sw := SoftwareEntry{
		ID:      "sw-json-001",
		AgentID: "agent-xyz",
		Name:    "OpenSSL",
		Version: "3.0.2",
		Vendor:  "OpenSSL Project",
	}

	data, err := json.Marshal(sw)
	if err != nil {
		t.Fatalf("JSON マーシャルに失敗: %v", err)
	}

	var decoded SoftwareEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON アンマーシャルに失敗: %v", err)
	}

	if decoded.ID != sw.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, sw.ID)
	}
	if decoded.Name != sw.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, sw.Name)
	}
	if decoded.Version != sw.Version {
		t.Errorf("Version = %q, want %q", decoded.Version, sw.Version)
	}
}

// TestSoftwareEntry_VersionComparison はバージョン文字列の比較ロジックを確認する
// セキュリティパッチ適用状況の判定に使用する
func TestSoftwareEntry_VersionComparison(t *testing.T) {
	// バージョン文字列の単純な辞書順比較
	cases := []struct {
		current    string
		fixed      string
		needsPatch bool // current < fixed なら true
	}{
		{"3.0.1", "3.0.2", true},
		{"3.0.2", "3.0.2", false},
		{"3.1.0", "3.0.2", false},
		{"2.9.9", "3.0.0", true},
	}

	// バージョン比較ロジック（単純なドット区切り数値比較）
	compareVersions := func(v1, v2 string) int {
		p1 := strings.Split(v1, ".")
		p2 := strings.Split(v2, ".")
		maxLen := len(p1)
		if len(p2) > maxLen {
			maxLen = len(p2)
		}
		for i := 0; i < maxLen; i++ {
			n1, n2 := 0, 0
			if i < len(p1) {
				fmt.Sscanf(p1[i], "%d", &n1)
			}
			if i < len(p2) {
				fmt.Sscanf(p2[i], "%d", &n2)
			}
			if n1 < n2 {
				return -1
			}
			if n1 > n2 {
				return 1
			}
		}
		return 0
	}

	for _, tc := range cases {
		needsPatch := compareVersions(tc.current, tc.fixed) < 0
		if needsPatch != tc.needsPatch {
			t.Errorf("compareVersions(%q, %q) needsPatch: got %v, want %v",
				tc.current, tc.fixed, needsPatch, tc.needsPatch)
		}
	}
}

// ─── SoftwareDiff 構造体テスト ────────────────────────────────────────────────

// TestSoftwareDiff_ZeroValue は SoftwareDiff のゼロ値を確認する
func TestSoftwareDiff_ZeroValue(t *testing.T) {
	var d SoftwareDiff
	if d.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", d.ID)
	}
	if d.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", d.AgentID)
	}
	if d.DiffDate != "" {
		t.Errorf("DiffDate のデフォルト = %q, want \"\"", d.DiffDate)
	}
	if d.AddedCount != 0 {
		t.Errorf("AddedCount のデフォルト = %d, want 0", d.AddedCount)
	}
	if d.RemovedCount != 0 {
		t.Errorf("RemovedCount のデフォルト = %d, want 0", d.RemovedCount)
	}
	if d.Added != nil {
		t.Errorf("Added のデフォルトは nil であるべき")
	}
	if d.Removed != nil {
		t.Errorf("Removed のデフォルトは nil であるべき")
	}
}

// TestSoftwareDiff_FieldAssignment は SoftwareDiff の全フィールド代入を確認する
func TestSoftwareDiff_FieldAssignment(t *testing.T) {
	now := time.Now()
	added := json.RawMessage(`[{"name":"curl","version":"7.88.1"}]`)
	removed := json.RawMessage(`[{"name":"openssl","version":"1.1.1"}]`)

	d := SoftwareDiff{
		ID:           "diff-001",
		AgentID:      "agent-abc",
		DiffDate:     "2026-03-23",
		Added:        added,
		Removed:      removed,
		AddedCount:   1,
		RemovedCount: 1,
		CreatedAt:    now,
	}

	if d.ID != "diff-001" {
		t.Errorf("ID = %q, want \"diff-001\"", d.ID)
	}
	if d.DiffDate != "2026-03-23" {
		t.Errorf("DiffDate = %q, want \"2026-03-23\"", d.DiffDate)
	}
	if d.AddedCount != 1 {
		t.Errorf("AddedCount = %d, want 1", d.AddedCount)
	}
	if d.RemovedCount != 1 {
		t.Errorf("RemovedCount = %d, want 1", d.RemovedCount)
	}
	if string(d.Added) != string(added) {
		t.Errorf("Added = %s, want %s", d.Added, added)
	}
}

// TestSoftwareDiff_ChangeClassification はソフトウェア変更の分類ロジックを確認する
// AddedCount と RemovedCount の組み合わせで変更種別を判定する
func TestSoftwareDiff_ChangeClassification(t *testing.T) {
	// 変更分類ロジックのピュア実装
	classifyChange := func(addedCount, removedCount int) string {
		switch {
		case addedCount > 0 && removedCount == 0:
			return "install_only"
		case addedCount == 0 && removedCount > 0:
			return "uninstall_only"
		case addedCount > 0 && removedCount > 0:
			return "update_or_mixed"
		default:
			return "no_change"
		}
	}

	cases := []struct {
		added, removed int
		want           string
	}{
		{3, 0, "install_only"},
		{0, 2, "uninstall_only"},
		{1, 1, "update_or_mixed"},
		{0, 0, "no_change"},
		{5, 3, "update_or_mixed"},
	}

	for _, tc := range cases {
		got := classifyChange(tc.added, tc.removed)
		if got != tc.want {
			t.Errorf("classifyChange(%d, %d) = %q, want %q", tc.added, tc.removed, got, tc.want)
		}
	}
}

// TestSoftwareDiff_AddedRemovedJSON は Added/Removed フィールドが JSON として扱われることを確認する
func TestSoftwareDiff_AddedRemovedJSON(t *testing.T) {
	addedItems := []map[string]string{
		{"name": "curl", "version": "8.0.0"},
		{"name": "wget", "version": "1.21.3"},
	}
	removedItems := []map[string]string{
		{"name": "telnet", "version": "0.17"},
	}

	addedJSON, err := json.Marshal(addedItems)
	if err != nil {
		t.Fatalf("Added JSON マーシャルに失敗: %v", err)
	}
	removedJSON, err := json.Marshal(removedItems)
	if err != nil {
		t.Fatalf("Removed JSON マーシャルに失敗: %v", err)
	}

	d := SoftwareDiff{
		Added:        addedJSON,
		Removed:      removedJSON,
		AddedCount:   len(addedItems),
		RemovedCount: len(removedItems),
	}

	// JSON アンマーシャルして内容を確認する
	var decodedAdded []map[string]string
	if err := json.Unmarshal(d.Added, &decodedAdded); err != nil {
		t.Fatalf("Added アンマーシャルに失敗: %v", err)
	}
	if len(decodedAdded) != 2 {
		t.Errorf("Added 件数 = %d, want 2", len(decodedAdded))
	}
	if decodedAdded[0]["name"] != "curl" {
		t.Errorf("Added[0].name = %q, want \"curl\"", decodedAdded[0]["name"])
	}

	if d.AddedCount != len(decodedAdded) {
		t.Errorf("AddedCount (%d) と実際の件数 (%d) が一致しない", d.AddedCount, len(decodedAdded))
	}
}

// TestSoftwareDiff_DiffDateFormat は DiffDate の日付フォーマットを確認する
// "YYYY-MM-DD" 形式が期待される
func TestSoftwareDiff_DiffDateFormat(t *testing.T) {
	isValidDiffDate := func(date string) bool {
		if len(date) != 10 {
			return false
		}
		if date[4] != '-' || date[7] != '-' {
			return false
		}
		return true
	}

	validDates := []string{"2026-03-23", "2026-01-01", "2025-12-31"}
	for _, date := range validDates {
		if !isValidDiffDate(date) {
			t.Errorf("有効な日付フォーマット %q が無効と判定されました", date)
		}
	}

	invalidDates := []string{"20260323", "2026/03/23", "03-23-2026", ""}
	for _, date := range invalidDates {
		if isValidDiffDate(date) {
			t.Errorf("無効な日付フォーマット %q が有効と判定されました", date)
		}
	}
}

// ─── ソフトウェア脆弱性スコアリングロジックテスト ─────────────────────────────

// cvssScoreToSeverity は CVSS スコアを severity ラベルに変換するピュア関数
// CVSS v3.1 の標準スコアリングに基づく
func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0.0:
		return "low"
	default:
		return "none"
	}
}

// TestCVSSScoreToSeverity_Critical は CVSS 9.0以上が "critical" になることを確認する
func TestCVSSScoreToSeverity_Critical(t *testing.T) {
	scores := []float64{9.0, 9.5, 10.0}
	for _, score := range scores {
		got := cvssScoreToSeverity(score)
		if got != "critical" {
			t.Errorf("cvssScoreToSeverity(%v) = %q, want \"critical\"", score, got)
		}
	}
}

// TestCVSSScoreToSeverity_High は CVSS 7.0〜8.9 が "high" になることを確認する
func TestCVSSScoreToSeverity_High(t *testing.T) {
	scores := []float64{7.0, 7.5, 8.0, 8.9}
	for _, score := range scores {
		got := cvssScoreToSeverity(score)
		if got != "high" {
			t.Errorf("cvssScoreToSeverity(%v) = %q, want \"high\"", score, got)
		}
	}
}

// TestCVSSScoreToSeverity_Medium は CVSS 4.0〜6.9 が "medium" になることを確認する
func TestCVSSScoreToSeverity_Medium(t *testing.T) {
	scores := []float64{4.0, 5.0, 6.0, 6.9}
	for _, score := range scores {
		got := cvssScoreToSeverity(score)
		if got != "medium" {
			t.Errorf("cvssScoreToSeverity(%v) = %q, want \"medium\"", score, got)
		}
	}
}

// TestCVSSScoreToSeverity_Low は CVSS 0.1〜3.9 が "low" になることを確認する
func TestCVSSScoreToSeverity_Low(t *testing.T) {
	scores := []float64{0.1, 1.0, 2.5, 3.9}
	for _, score := range scores {
		got := cvssScoreToSeverity(score)
		if got != "low" {
			t.Errorf("cvssScoreToSeverity(%v) = %q, want \"low\"", score, got)
		}
	}
}

// TestCVSSScoreToSeverity_None は CVSS 0.0 が "none" になることを確認する
func TestCVSSScoreToSeverity_None(t *testing.T) {
	got := cvssScoreToSeverity(0.0)
	if got != "none" {
		t.Errorf("cvssScoreToSeverity(0.0) = %q, want \"none\"", got)
	}
}

// TestCVSSScoreToSeverity_BoundaryValues は境界値での severity を確認する
func TestCVSSScoreToSeverity_BoundaryValues(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{3.9, "low"},
		{4.0, "medium"},
		{6.9, "medium"},
		{7.0, "high"},
		{8.9, "high"},
		{9.0, "critical"},
	}
	for _, tc := range cases {
		got := cvssScoreToSeverity(tc.score)
		if got != tc.want {
			t.Errorf("cvssScoreToSeverity(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// ─── Vulnerability 構造体テスト ──────────────────────────────────────────────

// TestVulnerability_ZeroValue は Vulnerability のゼロ値を確認する
func TestVulnerability_ZeroValue(t *testing.T) {
	var v Vulnerability
	if v.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", v.ID)
	}
	if v.CVEID != "" {
		t.Errorf("CVEID のデフォルト = %q, want \"\"", v.CVEID)
	}
	if v.Severity != "" {
		t.Errorf("Severity のデフォルト = %q, want \"\"", v.Severity)
	}
	if v.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", v.Status)
	}
	if v.CVSSScore != nil {
		t.Errorf("CVSSScore のデフォルトは nil であるべき: got %v", *v.CVSSScore)
	}
	if v.AgentID != nil {
		t.Errorf("AgentID のデフォルトは nil であるべき")
	}
}

// TestVulnerability_KnownSeverities は既知の severity 値を確認する
// "critical" | "high" | "medium" | "low" の4つが標準
func TestVulnerability_KnownSeverities(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		v := Vulnerability{Severity: sev}
		if v.Severity != sev {
			t.Errorf("Severity = %q, want %q", v.Severity, sev)
		}
	}
}

// TestVulnerability_KnownStatuses は既知のステータス値を確認する
// "open" | "mitigated" | "patched" | "accepted" の4つが標準
func TestVulnerability_KnownStatuses(t *testing.T) {
	statuses := []string{"open", "mitigated", "patched", "accepted"}
	for _, status := range statuses {
		v := Vulnerability{Status: status}
		if v.Status != status {
			t.Errorf("Status = %q, want %q", v.Status, status)
		}
	}
}

// TestVulnerability_CVSSScoreField は CVSSScore ポインタフィールドの操作を確認する
func TestVulnerability_CVSSScoreField(t *testing.T) {
	// CVSSScore が nil の場合
	v := Vulnerability{CVEID: "CVE-2024-12345"}
	if v.CVSSScore != nil {
		t.Error("CVSSScore のデフォルトは nil であるべき")
	}

	// CVSSScore を設定した場合
	score := 9.8
	v.CVSSScore = &score
	if v.CVSSScore == nil {
		t.Fatal("CVSSScore が設定されているべき")
	}
	if *v.CVSSScore != 9.8 {
		t.Errorf("*CVSSScore = %v, want 9.8", *v.CVSSScore)
	}

	// severity ラベルへの変換
	sev := cvssScoreToSeverity(*v.CVSSScore)
	if sev != "critical" {
		t.Errorf("CVSS 9.8 は critical であるべき: got %q", sev)
	}
}

// TestVulnerability_CVEIDFormat は CVE-ID の形式バリデーションを確認する
func TestVulnerability_CVEIDFormat(t *testing.T) {
	// CVE-ID の形式：CVE-YYYY-NNNNN
	isValidCVEID := func(cveID string) bool {
		if len(cveID) < 9 {
			return false
		}
		if !strings.HasPrefix(cveID, "CVE-") {
			return false
		}
		parts := strings.Split(cveID[4:], "-")
		return len(parts) == 2 && len(parts[0]) == 4 && len(parts[1]) >= 4
	}

	validIDs := []string{
		"CVE-2024-12345",
		"CVE-2023-99999",
		"CVE-2021-44228", // Log4Shell
	}
	for _, id := range validIDs {
		if !isValidCVEID(id) {
			t.Errorf("有効な CVE-ID %q が無効と判定されました", id)
		}
	}

	invalidIDs := []string{
		"",
		"CVE-2024",
		"cve-2024-12345", // 小文字は無効
		"2024-12345",
	}
	for _, id := range invalidIDs {
		if isValidCVEID(id) {
			t.Errorf("無効な CVE-ID %q が有効と判定されました", id)
		}
	}
}

// ─── VulnFilter 構造体テスト ──────────────────────────────────────────────────

// TestVulnFilter_ZeroValue は VulnFilter のゼロ値を確認する
func TestVulnFilter_ZeroValue(t *testing.T) {
	var f VulnFilter
	if f.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", f.AgentID)
	}
	if f.Severity != "" {
		t.Errorf("Severity のデフォルト = %q, want \"\"", f.Severity)
	}
	if f.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", f.Status)
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

// TestVulnFilter_DefaultLimit は Limit が 0 のときデフォルト値が適用されることを確認する
func TestVulnFilter_DefaultLimit(t *testing.T) {
	// VulnStore.List 内のロジック：f.Limit == 0 のとき 50 に設定
	applyDefaultLimit := func(f VulnFilter) VulnFilter {
		if f.Limit == 0 {
			f.Limit = 50
		}
		return f
	}

	f := VulnFilter{}
	f = applyDefaultLimit(f)
	if f.Limit != 50 {
		t.Errorf("デフォルト Limit = %d, want 50", f.Limit)
	}

	// 明示的に設定された Limit は変更されない
	f2 := VulnFilter{Limit: 25}
	f2 = applyDefaultLimit(f2)
	if f2.Limit != 25 {
		t.Errorf("明示的 Limit = %d, want 25", f2.Limit)
	}
}

// buildVulnWhere は VulnStore.List の WHERE 句構築を再現するヘルパー
func buildVulnWhere(f VulnFilter) (string, []interface{}) {
	where := "WHERE 1=1"
	args := []interface{}{}
	i := 1

	if f.AgentID != "" {
		where += fmt.Sprintf(" AND v.agent_id = $%d::uuid", i)
		args = append(args, f.AgentID)
		i++
	}
	if f.Severity != "" {
		where += fmt.Sprintf(" AND v.severity = $%d", i)
		args = append(args, f.Severity)
		i++
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND v.status = $%d", i)
		args = append(args, f.Status)
		i++
	}
	if f.Search != "" {
		where += fmt.Sprintf(" AND (v.cve_id ILIKE $%d OR v.title ILIKE $%d OR v.affected_package ILIKE $%d)", i, i, i)
		args = append(args, "%"+f.Search+"%")
		i++
	}
	_ = i
	return where, args
}

// TestBuildVulnWhere_EmptyFilter は全フィルターが空のとき "WHERE 1=1" であることを確認する
func TestBuildVulnWhere_EmptyFilter(t *testing.T) {
	where, args := buildVulnWhere(VulnFilter{})
	if where != "WHERE 1=1" {
		t.Errorf("空フィルターは \"WHERE 1=1\" のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestBuildVulnWhere_SeverityFilter は severity フィルターが条件を追加することを確認する
func TestBuildVulnWhere_SeverityFilter(t *testing.T) {
	f := VulnFilter{Severity: "critical"}
	where, args := buildVulnWhere(f)
	if !strings.Contains(where, "v.severity") {
		t.Errorf("severity 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "critical" {
		t.Errorf("args = %v, want [critical]", args)
	}
}

// TestBuildVulnWhere_SearchFilter は search フィルターが3列に ILIKE 条件を生成することを確認する
func TestBuildVulnWhere_SearchFilter(t *testing.T) {
	f := VulnFilter{Search: "log4j"}
	where, args := buildVulnWhere(f)
	if !strings.Contains(where, "v.cve_id ILIKE") {
		t.Errorf("cve_id ILIKE 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "v.title ILIKE") {
		t.Errorf("title ILIKE 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "v.affected_package ILIKE") {
		t.Errorf("affected_package ILIKE 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 {
		t.Fatalf("Search フィルターは引数 1 件のはず: got %d", len(args))
	}
	if args[0].(string) != "%log4j%" {
		t.Errorf("args[0] = %q, want \"%%log4j%%\"", args[0])
	}
}

// TestBuildVulnWhere_AllFilters は全フィルターが組み合わさったとき引数数が正しいことを確認する
func TestBuildVulnWhere_AllFilters(t *testing.T) {
	f := VulnFilter{
		AgentID:  "agent-001",
		Severity: "high",
		Status:   "open",
		Search:   "openssl",
	}
	where, args := buildVulnWhere(f)
	if !strings.Contains(where, "v.agent_id") {
		t.Errorf("agent_id 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "v.severity") {
		t.Errorf("severity 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "v.status") {
		t.Errorf("status 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "ILIKE") {
		t.Errorf("ILIKE 条件が含まれるべき: %q", where)
	}
	// agent_id(1) + severity(1) + status(1) + search(1) = 4 引数
	if len(args) != 4 {
		t.Errorf("全フィルターで引数 4 件のはず: got %d (%v)", len(args), args)
	}
}
