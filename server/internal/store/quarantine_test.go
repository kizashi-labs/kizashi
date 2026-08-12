package store

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ─── QuarantinedFile 構造体テスト ─────────────────────────────────────────────

// TestQuarantinedFile_ZeroValue は QuarantinedFile のゼロ値が期待通りであることを確認する
func TestQuarantinedFile_ZeroValue(t *testing.T) {
	var f QuarantinedFile
	if f.ID != "" {
		t.Errorf("ID のデフォルト = %q, want \"\"", f.ID)
	}
	if f.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", f.AgentID)
	}
	if f.OriginalPath != "" {
		t.Errorf("OriginalPath のデフォルト = %q, want \"\"", f.OriginalPath)
	}
	// すべてのポインタフィールドはデフォルトで nil
	if f.AlertID != nil {
		t.Errorf("AlertID のデフォルトは nil であるべき: got %v", *f.AlertID)
	}
	if f.FileSize != nil {
		t.Errorf("FileSize のデフォルトは nil であるべき: got %v", *f.FileSize)
	}
	if f.HashMD5 != nil {
		t.Errorf("HashMD5 のデフォルトは nil であるべき: got %v", *f.HashMD5)
	}
	if f.HashSHA256 != nil {
		t.Errorf("HashSHA256 のデフォルトは nil であるべき: got %v", *f.HashSHA256)
	}
	if f.RestoredAt != nil {
		t.Errorf("RestoredAt のデフォルトは nil であるべき: got %v", *f.RestoredAt)
	}
	if f.RestoredBy != nil {
		t.Errorf("RestoredBy のデフォルトは nil であるべき: got %v", *f.RestoredBy)
	}
}

// TestQuarantinedFile_IsRestored は復元済み判定ロジックを確認する
// RestoredAt が nil でなければ「復元済み」
func TestQuarantinedFile_IsRestored(t *testing.T) {
	// 復元前：RestoredAt は nil
	qf := QuarantinedFile{ID: "q-001"}
	if qf.RestoredAt != nil {
		t.Error("復元前は RestoredAt が nil であるべき")
	}

	// 復元後：RestoredAt に時刻を設定
	now := time.Now()
	qf.RestoredAt = &now
	if qf.RestoredAt == nil {
		t.Error("復元後は RestoredAt が nil でないべき")
	}
}

// TestQuarantinedFile_FieldAssignment は QuarantinedFile の全フィールド代入を確認する
func TestQuarantinedFile_FieldAssignment(t *testing.T) {
	now := time.Now()
	alertID := "alert-abc"
	size := int64(4096)
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	restoredBy := "analyst@example.com"

	f := QuarantinedFile{
		ID:            "q-001",
		AgentID:       "agent-xyz",
		AlertID:       &alertID,
		OriginalPath:  "/tmp/malware.exe",
		FileSize:      &size,
		HashMD5:       &md5,
		HashSHA256:    &sha256,
		QuarantinedAt: now,
		RestoredAt:    &now,
		RestoredBy:    &restoredBy,
	}

	if f.ID != "q-001" {
		t.Errorf("ID = %q, want \"q-001\"", f.ID)
	}
	if f.OriginalPath != "/tmp/malware.exe" {
		t.Errorf("OriginalPath = %q, want \"/tmp/malware.exe\"", f.OriginalPath)
	}
	if *f.AlertID != alertID {
		t.Errorf("*AlertID = %q, want %q", *f.AlertID, alertID)
	}
	if *f.FileSize != size {
		t.Errorf("*FileSize = %d, want %d", *f.FileSize, size)
	}
	if *f.HashMD5 != md5 {
		t.Errorf("*HashMD5 = %q, want %q", *f.HashMD5, md5)
	}
	if *f.HashSHA256 != sha256 {
		t.Errorf("*HashSHA256 = %q, want %q", *f.HashSHA256, sha256)
	}
	if *f.RestoredBy != restoredBy {
		t.Errorf("*RestoredBy = %q, want %q", *f.RestoredBy, restoredBy)
	}
}

// TestQuarantinedFile_FileSizeValues はファイルサイズの各種値を確認する
func TestQuarantinedFile_FileSizeValues(t *testing.T) {
	cases := []int64{0, 1, 1024, 1 << 20, 1 << 30}
	for _, size := range cases {
		s := size
		f := QuarantinedFile{FileSize: &s}
		if *f.FileSize != size {
			t.Errorf("*FileSize = %d, want %d", *f.FileSize, size)
		}
	}
}

// ─── QuarantineFilter 構造体テスト ────────────────────────────────────────────

// TestQuarantineFilter_ZeroValue は QuarantineFilter のゼロ値を確認する
func TestQuarantineFilter_ZeroValue(t *testing.T) {
	var f QuarantineFilter
	if f.AgentID != "" {
		t.Errorf("AgentID のデフォルト = %q, want \"\"", f.AgentID)
	}
	if f.Search != "" {
		t.Errorf("Search のデフォルト = %q, want \"\"", f.Search)
	}
	if f.Status != "" {
		t.Errorf("Status のデフォルト = %q, want \"\"", f.Status)
	}
}

// TestQuarantineFilter_ValidStatusValues は有効な Status 値を確認する
// "quarantined", "restored", "" の 3 つが有効
func TestQuarantineFilter_ValidStatusValues(t *testing.T) {
	validStatuses := []string{"quarantined", "restored", ""}
	for _, status := range validStatuses {
		f := QuarantineFilter{Status: status}
		if f.Status != status {
			t.Errorf("Status = %q, want %q", f.Status, status)
		}
	}
}

// TestQuarantineFilter_StatusToSQLCondition は Status 値が SQL 条件に変換されることを確認する
// quarantine.go の List メソッド内のロジックを再現する
func TestQuarantineFilter_StatusToSQLCondition(t *testing.T) {
	cases := []struct {
		status    string
		wantCond  string
		wantEmpty bool
	}{
		{"quarantined", "restored_at IS NULL", false},
		{"restored", "restored_at IS NOT NULL", false},
		{"", "", true},
	}

	for _, tc := range cases {
		var cond string
		if tc.status == "quarantined" {
			cond = "restored_at IS NULL"
		} else if tc.status == "restored" {
			cond = "restored_at IS NOT NULL"
		}

		if tc.wantEmpty && cond != "" {
			t.Errorf("Status=%q のとき条件が空のはず: got %q", tc.status, cond)
		}
		if !tc.wantEmpty && cond != tc.wantCond {
			t.Errorf("Status=%q の条件 = %q, want %q", tc.status, cond, tc.wantCond)
		}
	}
}

// ─── 検疫クエリビルダーロジックテスト ────────────────────────────────────────

// buildQuarantineWhere は quarantine.go の List メソッドの WHERE 句構築を再現する
func buildQuarantineWhere(f QuarantineFilter) (string, []interface{}) {
	conds := []string{"1=1"}
	args := []interface{}{}
	i := 1

	if f.AgentID != "" {
		conds = append(conds, fmt.Sprintf("agent_id = $%d", i))
		args = append(args, f.AgentID)
		i++
	}
	if f.Search != "" {
		conds = append(conds, fmt.Sprintf("(original_path ILIKE $%d OR hash_sha256 ILIKE $%d)", i, i))
		args = append(args, "%"+f.Search+"%")
		i++
	}
	if f.Status == "quarantined" {
		conds = append(conds, "restored_at IS NULL")
	} else if f.Status == "restored" {
		conds = append(conds, "restored_at IS NOT NULL")
	}
	_ = i

	where := "WHERE " + conds[0]
	for _, c := range conds[1:] {
		where += " AND " + c
	}
	return where, args
}

// TestBuildQuarantineWhere_EmptyFilter は全フィルターが空のとき "WHERE 1=1" であることを確認する
func TestBuildQuarantineWhere_EmptyFilter(t *testing.T) {
	where, args := buildQuarantineWhere(QuarantineFilter{})
	if where != "WHERE 1=1" {
		t.Errorf("空フィルターは \"WHERE 1=1\" のはず: got %q", where)
	}
	if len(args) != 0 {
		t.Errorf("空フィルターは引数なしのはず: got %v", args)
	}
}

// TestBuildQuarantineWhere_AgentIDFilter は AgentID フィルターが条件を追加することを確認する
func TestBuildQuarantineWhere_AgentIDFilter(t *testing.T) {
	f := QuarantineFilter{AgentID: "agent-001"}
	where, args := buildQuarantineWhere(f)

	if !strings.Contains(where, "agent_id") {
		t.Errorf("agent_id 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 || args[0] != "agent-001" {
		t.Errorf("args = %v, want [agent-001]", args)
	}
}

// TestBuildQuarantineWhere_SearchFilter は Search フィルターが両列に ILIKE 条件を生成することを確認する
func TestBuildQuarantineWhere_SearchFilter(t *testing.T) {
	f := QuarantineFilter{Search: "malware"}
	where, args := buildQuarantineWhere(f)

	if !strings.Contains(where, "original_path ILIKE") {
		t.Errorf("original_path ILIKE 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "hash_sha256 ILIKE") {
		t.Errorf("hash_sha256 ILIKE 条件が含まれるべき: %q", where)
	}
	if len(args) != 1 {
		t.Fatalf("args の数 = %d, want 1", len(args))
	}
	if args[0].(string) != "%malware%" {
		t.Errorf("args[0] = %q, want \"%%malware%%\"", args[0])
	}
}

// TestBuildQuarantineWhere_StatusQuarantined は Status="quarantined" が IS NULL 条件を追加することを確認する
func TestBuildQuarantineWhere_StatusQuarantined(t *testing.T) {
	f := QuarantineFilter{Status: "quarantined"}
	where, _ := buildQuarantineWhere(f)

	if !strings.Contains(where, "restored_at IS NULL") {
		t.Errorf("quarantined フィルターは IS NULL 条件を含むべき: %q", where)
	}
}

// TestBuildQuarantineWhere_StatusRestored は Status="restored" が IS NOT NULL 条件を追加することを確認する
func TestBuildQuarantineWhere_StatusRestored(t *testing.T) {
	f := QuarantineFilter{Status: "restored"}
	where, _ := buildQuarantineWhere(f)

	if !strings.Contains(where, "restored_at IS NOT NULL") {
		t.Errorf("restored フィルターは IS NOT NULL 条件を含むべき: %q", where)
	}
}

// TestBuildQuarantineWhere_AllFilters は全フィルターが組み合わさったとき引数数が正しいことを確認する
func TestBuildQuarantineWhere_AllFilters(t *testing.T) {
	f := QuarantineFilter{
		AgentID: "agent-abc",
		Search:  "trojan",
		Status:  "quarantined",
	}
	where, args := buildQuarantineWhere(f)

	if !strings.Contains(where, "agent_id") {
		t.Errorf("agent_id 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "ILIKE") {
		t.Errorf("ILIKE 条件が含まれるべき: %q", where)
	}
	if !strings.Contains(where, "restored_at IS NULL") {
		t.Errorf("restored_at IS NULL 条件が含まれるべき: %q", where)
	}
	// AgentID (1) + Search (1) = 2 引数（Status はプレースホルダーなし）
	if len(args) != 2 {
		t.Errorf("args の数 = %d, want 2", len(args))
	}
}

// ─── ハッシュ値バリデーションロジックテスト ─────────────────────────────────

// isValidSHA256 は SHA-256 ハッシュが正しい形式かを確認するピュア関数
func isValidSHA256(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// TestIsValidSHA256_ValidHash は有効な SHA-256 ハッシュで true を返すことを確認する
func TestIsValidSHA256_ValidHash(t *testing.T) {
	valid := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if !isValidSHA256(valid) {
		t.Errorf("有効な SHA-256 ハッシュで false が返されました: %q", valid)
	}
}

// TestIsValidSHA256_TooShort は短すぎるハッシュで false を返すことを確認する
func TestIsValidSHA256_TooShort(t *testing.T) {
	if isValidSHA256("abc123") {
		t.Error("短すぎるハッシュは false を返すべき")
	}
}

// TestIsValidSHA256_InvalidChars は不正な文字を含むハッシュで false を返すことを確認する
func TestIsValidSHA256_InvalidChars(t *testing.T) {
	// 64 文字だが 'g' が含まれる（16 進数でない）
	invalid := "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if isValidSHA256(invalid) {
		t.Error("不正な文字を含むハッシュは false を返すべき")
	}
}

// TestIsValidSHA256_EmptyString は空文字列で false を返すことを確認する
func TestIsValidSHA256_EmptyString(t *testing.T) {
	if isValidSHA256("") {
		t.Error("空文字列は false を返すべき")
	}
}

// TestIsValidSHA256_UpperCaseValid は大文字の有効なハッシュで true を返すことを確認する
func TestIsValidSHA256_UpperCaseValid(t *testing.T) {
	upper := strings.ToUpper("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if !isValidSHA256(upper) {
		t.Errorf("大文字の SHA-256 ハッシュは有効であるべき: %q", upper)
	}
}

// ─── 検疫ファイルパスバリデーションロジックテスト ────────────────────────────

// isValidQuarantinePath は検疫対象のファイルパスが有効かを確認するピュア関数
// 空パス、相対パスは無効とみなす
func isValidQuarantinePath(path string) bool {
	if path == "" {
		return false
	}
	return strings.HasPrefix(path, "/") || (len(path) >= 3 && path[1] == ':')
}

// TestIsValidQuarantinePath_AbsoluteUnixPath は絶対 Unix パスが有効であることを確認する
func TestIsValidQuarantinePath_AbsoluteUnixPath(t *testing.T) {
	paths := []string{"/tmp/malware.exe", "/var/log/evil.sh", "/usr/bin/backdoor"}
	for _, p := range paths {
		if !isValidQuarantinePath(p) {
			t.Errorf("絶対 Unix パスは有効であるべき: %q", p)
		}
	}
}

// TestIsValidQuarantinePath_WindowsPath は Windows 絶対パスが有効であることを確認する
func TestIsValidQuarantinePath_WindowsPath(t *testing.T) {
	paths := []string{"C:/Windows/Temp/evil.dll", "D:/malware/trojan.exe"}
	for _, p := range paths {
		if !isValidQuarantinePath(p) {
			t.Errorf("Windows パスは有効であるべき: %q", p)
		}
	}
}

// TestIsValidQuarantinePath_EmptyPath は空パスが無効であることを確認する
func TestIsValidQuarantinePath_EmptyPath(t *testing.T) {
	if isValidQuarantinePath("") {
		t.Error("空パスは無効であるべき")
	}
}

// TestIsValidQuarantinePath_RelativePath は相対パスが無効であることを確認する
func TestIsValidQuarantinePath_RelativePath(t *testing.T) {
	relativePaths := []string{"tmp/malware.exe", "malware.exe", "./backdoor"}
	for _, p := range relativePaths {
		if isValidQuarantinePath(p) {
			t.Errorf("相対パスは無効であるべき: %q", p)
		}
	}
}
