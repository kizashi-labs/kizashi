package handlers

import "testing"

// ─── containsSubstr ───────────────────────────────────────────────────────────
// events_handler.go で定義された大文字小文字区別ありの部分文字列検索

func TestContainsSubstr_BasicMatch(t *testing.T) {
	if !containsSubstr("powershell.exe", "powershell") {
		t.Error("'powershell.exe' は 'powershell' を含むべき")
	}
}

func TestContainsSubstr_NoMatch(t *testing.T) {
	if containsSubstr("cmd.exe", "powershell") {
		t.Error("'cmd.exe' は 'powershell' を含まないべき")
	}
}

func TestContainsSubstr_EmptySubstring(t *testing.T) {
	// 空文字列はすべての文字列に含まれる
	if !containsSubstr("anything", "") {
		t.Error("空サブ文字列は常にマッチするべき")
	}
}

func TestContainsSubstr_EmptyString(t *testing.T) {
	// 空の文字列に非空のサブ文字列は含まれない
	if containsSubstr("", "abc") {
		t.Error("空文字列は 'abc' を含まないべき")
	}
}

func TestContainsSubstr_BothEmpty(t *testing.T) {
	if !containsSubstr("", "") {
		t.Error("空文字列は空文字列を含むべき")
	}
}

func TestContainsSubstr_ExactMatch(t *testing.T) {
	if !containsSubstr("malware", "malware") {
		t.Error("完全一致はマッチするべき")
	}
}

func TestContainsSubstr_SubLongerThanString(t *testing.T) {
	if containsSubstr("ab", "abcdef") {
		t.Error("サブ文字列が文字列より長い場合は false を返すべき")
	}
}

func TestContainsSubstr_CaseSensitive(t *testing.T) {
	// containsSubstr は大文字小文字を区別する
	if containsSubstr("Malware", "malware") {
		t.Error("大文字小文字を区別するので 'Malware' != 'malware'")
	}
}

func TestContainsSubstr_MatchAtStart(t *testing.T) {
	if !containsSubstr("powershell -enc base64", "powershell") {
		t.Error("先頭でのマッチを検出すべき")
	}
}

func TestContainsSubstr_MatchAtEnd(t *testing.T) {
	if !containsSubstr("/tmp/malware", "malware") {
		t.Error("末尾でのマッチを検出すべき")
	}
}

func TestContainsSubstr_MatchInMiddle(t *testing.T) {
	if !containsSubstr("C:\\Windows\\System32\\cmd.exe", "System32") {
		t.Error("中間のマッチを検出すべき")
	}
}

func TestContainsSubstr_SingleChar(t *testing.T) {
	if !containsSubstr("abc", "b") {
		t.Error("単一文字のマッチを検出すべき")
	}
}

func TestContainsSubstr_SingleCharNoMatch(t *testing.T) {
	if containsSubstr("abc", "d") {
		t.Error("存在しない単一文字はマッチしないべき")
	}
}

// ─── イベントフィルタ検証ヘルパー (インライン純粋関数テスト) ─────────────────

func TestEventTypeValidation(t *testing.T) {
	// events_handler.go のイベントタイプフィルタロジックを反映
	validEventTypes := map[string]bool{
		"process": true, "file": true, "network": true,
		"registry": true, "dns": true, "auth": true,
	}
	isValidType := func(t string) bool { return validEventTypes[t] }

	for _, et := range []string{"process", "file", "network", "registry", "dns", "auth"} {
		if !isValidType(et) {
			t.Errorf("イベントタイプ %q は有効なはず", et)
		}
	}
	for _, et := range []string{"", "unknown", "PROCESS", "kernel"} {
		if isValidType(et) {
			t.Errorf("イベントタイプ %q は無効なはず", et)
		}
	}
}

func TestEventTimeRangeValidation(t *testing.T) {
	// 時間範囲 (minutes) のバリデーション: 1–10080 (7日)
	clampTimeRange := func(v int) int {
		if v <= 0 {
			return 60
		}
		if v > 10080 {
			return 10080
		}
		return v
	}

	tests := []struct {
		input int
		want  int
	}{
		{0, 60},
		{-1, 60},
		{60, 60},
		{1440, 1440},
		{10080, 10080},
		{10081, 10080},
		{99999, 10080},
	}
	for _, tc := range tests {
		got := clampTimeRange(tc.input)
		if got != tc.want {
			t.Errorf("clampTimeRange(%d) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestEventPageSizeValidation(t *testing.T) {
	// ページサイズ: 1–200
	clampPageSize := func(v int) int {
		if v <= 0 {
			return 50
		}
		if v > 200 {
			return 200
		}
		return v
	}

	tests := []struct {
		input int
		want  int
	}{
		{0, 50},
		{-10, 50},
		{50, 50},
		{100, 100},
		{200, 200},
		{201, 200},
		{9999, 200},
	}
	for _, tc := range tests {
		got := clampPageSize(tc.input)
		if got != tc.want {
			t.Errorf("clampPageSize(%d) = %d, want %d", tc.input, got, tc.want)
		}
	}
}
