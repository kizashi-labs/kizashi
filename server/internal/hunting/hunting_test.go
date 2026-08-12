package hunting

import (
	"strings"
	"testing"
)

// ─── parseLast ────────────────────────────────────────────────────────────────

func TestParseLast_ValidValues(t *testing.T) {
	cases := []struct {
		input    string
		contains string
	}{
		{"15m", "minutes"},
		{"1h", "hour"},
		{"6h", "hours"},
		{"24h", "hours"},
		{"1d", "hours"},
		{"7d", "days"},
		{"30d", "days"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseLast(tc.input)
			if err != nil {
				t.Fatalf("parseLast(%q): 予期しないエラー: %v", tc.input, err)
			}
			if !strings.Contains(got, tc.contains) {
				t.Errorf("parseLast(%q) = %q, want contains %q", tc.input, got, tc.contains)
			}
		})
	}
}

func TestParseLast_InvalidValue(t *testing.T) {
	_, err := parseLast("2w")
	if err == nil {
		t.Error("未サポートの時間範囲はエラーを返すべきです")
	}
}

func TestParseLast_CaseInsensitive(t *testing.T) {
	got, err := parseLast("1H")
	if err != nil {
		t.Fatalf("大文字の入力でエラー: %v", err)
	}
	if !strings.Contains(got, "hour") {
		t.Errorf("parseLast(1H) = %q, want contains \"hour\"", got)
	}
}

func TestParseLast_TrimsWhitespace(t *testing.T) {
	got, err := parseLast("  7d  ")
	if err != nil {
		t.Fatalf("空白付きの入力でエラー: %v", err)
	}
	if !strings.Contains(got, "days") {
		t.Errorf("parseLast(\"  7d  \") = %q, want contains \"days\"", got)
	}
}

// ─── parseRawData ──────────────────────────────────────────────────────────────

func TestParseRawData_ValidJSON(t *testing.T) {
	data := []byte(`{"process_name":"cmd.exe","pid":1234}`)
	result := parseRawData(data)
	if result["process_name"] != "cmd.exe" {
		t.Errorf("process_name: got %v, want cmd.exe", result["process_name"])
	}
}

func TestParseRawData_EmptyBytes(t *testing.T) {
	result := parseRawData(nil)
	if result == nil {
		t.Error("空バイトでもnilでないmapを返すべきです")
	}
	if len(result) != 0 {
		t.Errorf("空バイトは空mapを返すべきです: got %v", result)
	}
}

func TestParseRawData_InvalidJSON_ReturnsRaw(t *testing.T) {
	data := []byte("not-json")
	result := parseRawData(data)
	if _, ok := result["_raw"]; !ok {
		t.Error("不正なJSONは _raw キーを持つmapを返すべきです")
	}
	if result["_raw"] != "not-json" {
		t.Errorf("_raw: got %v, want not-json", result["_raw"])
	}
}

func TestParseRawData_EmptyJSON(t *testing.T) {
	result := parseRawData([]byte(`{}`))
	if result == nil {
		t.Error("空JSONオブジェクトでもnilでないmapを返すべきです")
	}
}

// ─── buildSQL ─────────────────────────────────────────────────────────────────

func TestBuildSQL_BasicQuery_NoError(t *testing.T) {
	q := &HuntingQuery{Limit: 10}
	sql, args, err := buildSQL(q)
	if err != nil {
		t.Fatalf("基本クエリのSQL生成でエラー: %v", err)
	}
	if !strings.Contains(sql, "FROM events") {
		t.Errorf("SQLにFROM eventsが含まれていません: %s", sql)
	}
	_ = args
}

func TestBuildSQL_EventTypeFilter(t *testing.T) {
	q := &HuntingQuery{
		EventTypes: []string{"process", "network"},
		Limit:      10,
	}
	sql, args, err := buildSQL(q)
	if err != nil {
		t.Fatalf("EventTypeフィルターのSQL生成でエラー: %v", err)
	}
	if !strings.Contains(sql, "event_type IN") {
		t.Errorf("SQLにevent_type INが含まれていません: %s", sql)
	}
	if len(args) < 2 {
		t.Errorf("EventType×2のときargsは2以上のはずです: got %d", len(args))
	}
}

func TestBuildSQL_UnknownFilterFieldSkipped(t *testing.T) {
	q := &HuntingQuery{
		Filters: []QueryFilter{
			{Field: "malicious_injection_field'; DROP TABLE events; --", Operator: "eq", Value: "x"},
		},
		Limit: 10,
	}
	sql, _, err := buildSQL(q)
	if err != nil {
		t.Fatalf("不明フィールドのSQL生成でエラー: %v", err)
	}
	// 不明フィールドはホワイトリストにないのでSQLに含まれないはず
	if strings.Contains(sql, "DROP TABLE") {
		t.Error("SQLインジェクション: 不明フィールドがSQLに含まれてしまっています")
	}
}

func TestBuildSQL_LimitCappedAt1000(t *testing.T) {
	q := &HuntingQuery{Limit: 99999}
	sql, _, err := buildSQL(q)
	if err != nil {
		t.Fatalf("SQL生成でエラー: %v", err)
	}
	if strings.Contains(sql, "99999") {
		t.Error("LIMIT 99999 はそのままSQLに入るべきではありません（1000にキャップされるはず）")
	}
}

func TestBuildSQL_OrderByAsc(t *testing.T) {
	q := &HuntingQuery{Limit: 10, OrderBy: "asc"}
	sql, _, err := buildSQL(q)
	if err != nil {
		t.Fatalf("SQL生成でエラー: %v", err)
	}
	if !strings.Contains(sql, "ASC") {
		t.Errorf("OrderBy=asc のとき SQL に ASC が含まれるはずです: %s", sql)
	}
}

func TestBuildSQL_InvalidLast_ReturnsError(t *testing.T) {
	q := &HuntingQuery{
		TimeRange: TimeRange{Last: "bad-interval"},
		Limit:     10,
	}
	_, _, err := buildSQL(q)
	if err == nil {
		t.Error("無効なLast値はエラーを返すべきです")
	}
}

func TestBuildSQL_KnownFilter_Eq(t *testing.T) {
	q := &HuntingQuery{
		Filters: []QueryFilter{
			{Field: "event_type", Operator: "eq", Value: "process"},
		},
		Limit: 10,
	}
	sql, args, err := buildSQL(q)
	if err != nil {
		t.Fatalf("既知フィールドのSQL生成でエラー: %v", err)
	}
	if !strings.Contains(sql, "= $") {
		t.Errorf("eq オペレーターは = $N の形式になるはずです: %s", sql)
	}
	if len(args) == 0 {
		t.Error("フィルター引数がargsに追加されるべきです")
	}
}
