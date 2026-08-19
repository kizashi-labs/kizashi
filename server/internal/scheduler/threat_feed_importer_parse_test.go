package scheduler

// 脅威フィード取り込みのパース処理。
//
// importAll / importFeed は外部 HTTP を叩くためテストしづらいが、取り込んだ
// 本文を解釈する部分は純粋処理として切り出されている。ここが壊れるとフィードを
// 取得できていても IOC が 1 件も登録されないため、パーサ単体で確かめる。
//
// doUpsert=false で呼ぶと DB に触らないので、件数の判定だけを対象にできる。

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func feedImporterPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB-backed importer tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestImportCSV_CountsAndSkips(t *testing.T) {
	imp := &ThreatFeedImporter{}
	ctx := context.Background()

	body := `# コメント行は無視される

203.0.113.10,ip,high,既知の C2
example.invalid,domain,medium
d41d8cd98f00b204e9800998ecf8427e,hash
,ip,high,インジケータが空なので無視
列が1つだけなので無視
`
	got := imp.importCSV(ctx, body, "test-source", "feed-1", false)
	if got != 3 {
		t.Errorf("取り込み件数 = %d, want 3 (コメント/空行/空インジケータ/列不足を除く)", got)
	}
}

func TestImportCSV_EmptyBody(t *testing.T) {
	imp := &ThreatFeedImporter{}
	if got := imp.importCSV(context.Background(), "", "s", "f", false); got != 0 {
		t.Errorf("空本文の件数 = %d, want 0", got)
	}
}

func TestImportJSON_AcceptsIndicatorAndValueKeys(t *testing.T) {
	imp := &ThreatFeedImporter{}
	ctx := context.Background()

	// indicator と value のどちらでも拾えること、どちらも無い要素は飛ばすこと。
	body := `[
		{"indicator":"203.0.113.11","type":"ip","severity":"high"},
		{"value":"bad.example.invalid","type":"domain"},
		{"type":"ip","severity":"low"},
		{"indicator":"","value":""}
	]`
	if got := imp.importJSON(ctx, body, "test-source", "feed-1", false); got != 2 {
		t.Errorf("取り込み件数 = %d, want 2", got)
	}
}

func TestImportJSON_InvalidBodyReturnsZero(t *testing.T) {
	imp := &ThreatFeedImporter{}
	if got := imp.importJSON(context.Background(), "{not json", "s", "f", false); got != 0 {
		t.Errorf("不正 JSON の件数 = %d, want 0", got)
	}
	// オブジェクト（配列でない）も 0 件として扱う。
	if got := imp.importJSON(context.Background(), `{"indicator":"x"}`, "s", "f", false); got != 0 {
		t.Errorf("配列でない JSON の件数 = %d, want 0", got)
	}
}

func TestCountSTIXIndicators(t *testing.T) {
	imp := &ThreatFeedImporter{}

	bundle := `{
		"type":"bundle",
		"objects":[
			{"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.12']"},
			{"type":"malware","name":"x"},
			{"type":"indicator","pattern":"[domain-name:value = 'bad.example.invalid']"},
			"文字列要素は無視される"
		]
	}`
	if got := imp.countSTIXIndicators(context.Background(), bundle); got != 2 {
		t.Errorf("indicator 数 = %d, want 2", got)
	}
	if got := imp.countSTIXIndicators(context.Background(), "{not json"); got != 0 {
		t.Errorf("不正 JSON の indicator 数 = %d, want 0", got)
	}
	if got := imp.countSTIXIndicators(context.Background(), `{"type":"bundle"}`); got != 0 {
		t.Errorf("objects 無しの indicator 数 = %d, want 0", got)
	}
}

func TestCountLines_SkipsBlankAndComments(t *testing.T) {
	imp := &ThreatFeedImporter{}

	body := "203.0.113.13\n\n# コメント\n  \nbad.example.invalid\n"
	if got := imp.countLines(body); got != 2 {
		t.Errorf("行数 = %d, want 2", got)
	}
	if got := imp.countLines(""); got != 0 {
		t.Errorf("空本文の行数 = %d, want 0", got)
	}
}

// TestUpsertIOC_WritesAndDedupes は実 DB への書き込み経路。
// 以前は存在しない iocs テーブルへ INSERT していて、エラーを握りつぶすため
// 1 件も保存されていなかった。(ioc_type, value) の一意制約で重複しないことも見る。
func TestUpsertIOC_WritesAndDedupes(t *testing.T) {
	pool := feedImporterPool(t)
	imp := &ThreatFeedImporter{pool: pool}
	ctx := context.Background()

	const value = "203.0.113.99"
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM threat_intel_iocs WHERE value = $1`, value)
	}
	cleanup()
	t.Cleanup(cleanup)

	imp.upsertIOC(ctx, value, "ip", "high", "importer-itest", "テスト用")
	imp.upsertIOC(ctx, value, "ip", "high", "importer-itest", "テスト用")

	var n, severity int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*), COALESCE(MAX(severity),0) FROM threat_intel_iocs WHERE value = $1`,
		value).Scan(&n, &severity); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 1 {
		t.Errorf("件数 = %d, want 1 (ON CONFLICT で重複しないはず)", n)
	}
	// "high" は 1–10 スケールの 7 に写る。文字列のまま入れると型エラーで落ちる。
	if severity != 7 {
		t.Errorf("severity = %d, want 7 (\"high\" の写像)", severity)
	}
}

// TestIOCSeverityToInt は深刻度文字列の写像。未知の値は列のデフォルトと同じ 5。
func TestIOCSeverityToInt(t *testing.T) {
	cases := map[string]int{
		"critical": 9, "CRITICAL": 9, " high ": 7, "medium": 5,
		"low": 3, "info": 1, "informational": 1,
		"": 5, "なんらかの未知の値": 5,
	}
	for in, want := range cases {
		if got := iocSeverityToInt(in); got != want {
			t.Errorf("iocSeverityToInt(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestImportCSV_UpsertsToDB は doUpsert=true の経路を実 DB で通す。
func TestImportCSV_UpsertsToDB(t *testing.T) {
	pool := feedImporterPool(t)
	imp := &ThreatFeedImporter{pool: pool}
	ctx := context.Background()

	const v1, v2 = "203.0.113.97", "203.0.113.98"
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM threat_intel_iocs WHERE value IN ($1,$2)`, v1, v2)
	}
	cleanup()
	t.Cleanup(cleanup)

	body := v1 + ",ip,high,one\n" + v2 + ",ip,medium,two\n"
	if got := imp.importCSV(ctx, body, "importer-itest", "feed-1", true); got != 2 {
		t.Fatalf("取り込み件数 = %d, want 2", got)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM threat_intel_iocs WHERE value IN ($1,$2)`, v1, v2).Scan(&n); err != nil {
		t.Fatalf("件数確認: %v", err)
	}
	if n != 2 {
		t.Errorf("DB に入った件数 = %d, want 2", n)
	}
}
