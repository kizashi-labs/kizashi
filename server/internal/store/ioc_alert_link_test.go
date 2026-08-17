package store

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IOC alerts carry no structured back-reference to the indicator that produced
// them — alerts has no ioc_id, rule_id is uuid-typed and left NULL on this
// path, and the value is written to neither raw_event nor a column of its own.
// The only durable link is the alert title. Two separate defects followed from
// that, both measured against a database holding one IOC alert from each of the
// two producers for the same indicator:
//
//	                                      before             after
//	IOCStats.Alerts7d                     0  (22P02)         2
//	TopHits hit_count                     1                  2
//
// Alerts7d matched `rule_id = 'ioc-match'`. rule_id is uuid, so the comparison
// failed with 22P02 on every call and the row was scanned with `_ =` — the
// count has always been 0. The sentinel it looked for was removed from the
// producer some time ago precisely because it made the INSERT fail; nothing
// updated the reader and nothing said so.
//
// TopHits ran, but knew only the English prefix written by server-api
// (AlertPipeline.createAlertFromIOC). server-detect's Engine writes 「既知IOC検出: 」
// for the same indicator into the same table, so TopHits undercounted by
// exactly the share of traffic the detection engine handled — silently, and in
// a way that looks like the indicator is simply less active.
//
// Both prefixes are now defined once in ioc.go and both producers build their
// titles from those constants.

func iocLinkPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedIOCFromBothProducers registers one indicator and one alert from each of
// the two producers. The indicator value is unique per test so the counts stay
// exact on a database other packages are writing to.
func seedIOCFromBothProducers(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	value := "ioc-link-" + uuid.NewString() + ".test"

	if _, err := pool.Exec(ctx,
		`INSERT INTO ioc_entries (type,value,description,severity,is_active)
		 VALUES ('domain',$1,'ioc link fixture',7,true)`, value); err != nil {
		t.Fatalf("seed ioc_entries: %v", err)
	}
	for _, title := range []string{
		IOCAlertTitlePrefixEN + value, // server-api
		IOCAlertTitlePrefixJA + value, // server-detect
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO alerts (severity,status,title,description,created_at)
			 VALUES (7,'open',$1,'',NOW() - INTERVAL '1 day')`, title); err != nil {
			t.Fatalf("seed alert %q: %v", title, err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE title LIKE '%' || $1`, value)
		_, _ = pool.Exec(c, `DELETE FROM ioc_entries WHERE value = $1`, value)
	})
	return value
}

// The headline: an IOC alert is counted. The statement this replaced could not
// run at all, so Alerts7d was 0 on every deployment that has ever existed.
func TestIOCStatsCountsAlertsFromBothProducers(t *testing.T) {
	pool := iocLinkPool(t)
	s := &IOCStore{pool: pool}

	before, err := s.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats (before): %v", err)
	}
	seedIOCFromBothProducers(t, pool)
	after, err := s.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats (after): %v", err)
	}

	// Floor, not equality: the database is shared with other packages.
	if got := after.Alerts7d - before.Alerts7d; got < 2 {
		t.Errorf("直近7日のIOCアラートが %d 件しか増えていません (2件以上を期待)。"+
			"server-api と server-detect の両方が同じ alerts テーブルに書きます — "+
			"片方のプレフィックスしか見ないと件数が半分になります", got)
	}
}

// A failed count must be reported. `_ =` on this row is what let a statement
// that could never run look like a deployment with no IOC activity.
//
// This is asserted structurally rather than by cancelling a context. Stats runs
// an earlier query, so a cancelled context makes Stats return an error whatever
// this row does — the count could go back to `_ =` and the by-type query alone
// would keep such a test green. That is the same shape as the defect: one
// statement's failure standing in for another's silence.
func TestIOCStatsDoesNotDiscardTheAlertCountError(t *testing.T) {
	b, err := os.ReadFile("ioc.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := stripStoreComments(string(b))

	start := strings.Index(src, "stats.Alerts7d")
	if start < 0 {
		t.Fatal("Alerts7d を数える箇所が見つかりません")
	}
	// The statement and its handling, back to the start of its own line.
	stmt := src[strings.LastIndex(src[:start], "\n\t"):]
	if end := strings.Index(stmt, "\n\n"); end > 0 {
		stmt = stmt[:end]
	}

	if strings.Contains(stmt, "_ = s.pool") {
		t.Error("IOCアラート件数の取得エラーを捨てています。" +
			"「IOCアラート0件」と「数えられなかった」は別の事実で、" +
			"後者を前者として報告したために 22P02 が何年も表に出ませんでした")
	}
	if !strings.Contains(stmt, "count IOC alerts") {
		t.Error("取得失敗が固有のメッセージで報告されていません")
	}
}

// And the count is reported through Stats' error return at all — a helper that
// logged and carried on would satisfy the scan above.
func TestIOCStatsReturnsAnErrorToItsCaller(t *testing.T) {
	pool := iocLinkPool(t)
	s := &IOCStore{pool: pool}

	dead, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Stats(dead); err == nil {
		t.Error("クエリ失敗時にエラーが返りませんでした")
	}
}

// TopHits must attribute hits from both producers to the same indicator.
func TestTopHitsSeesBothProducers(t *testing.T) {
	pool := iocLinkPool(t)
	s := &IOCStore{pool: pool}
	value := seedIOCFromBothProducers(t, pool)

	hits, err := s.TopHits(context.Background(), 200)
	if err != nil {
		t.Fatalf("TopHits: %v", err)
	}
	found := false
	for _, h := range hits {
		if h.Value != value {
			continue
		}
		found = true
		if h.HitCount != 2 {
			t.Errorf("%s のヒット数が %d 件です (2件を期待)。"+
				"server-detect が書いた「%s」形式のアラートが数えられていません",
				value, h.HitCount, IOCAlertTitlePrefixJA)
		}
	}
	if !found {
		t.Errorf("%s が上位IOCに現れませんでした", value)
	}
}

// Both producers must build their titles from the shared constants. A literal
// prefix in a producer does not fail anywhere — it makes IOC statistics go
// quietly to zero for whichever service owns that copy, which is exactly how
// TopHits came to see only half the traffic.
func TestBothIOCProducersUseTheSharedPrefixes(t *testing.T) {
	for _, tc := range []struct {
		file  string
		usage string
	}{
		{"alert_pipeline.go", "store.IOCAlertTitlePrefixEN"},
		{"engine.go", "store.IOCAlertTitlePrefixJA"},
	} {
		path := filepath.Join("..", "detection", tc.file)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		src := stripStoreComments(string(b))

		if !strings.Contains(src, tc.usage) {
			t.Errorf("%s が %s を使っていません", tc.file, tc.usage)
		}
		for _, literal := range []string{IOCAlertTitlePrefixEN, IOCAlertTitlePrefixJA} {
			if strings.Contains(src, `"`+literal) {
				t.Errorf("%s がプレフィックス %q を直接書いています。"+
					"store の定数を使ってください — 片方だけ変わると"+
					"エラーは出ずにIOC統計が 0 になります", tc.file, literal)
			}
		}
	}
}

// And the readers must go through the constants too, so a change to a prefix
// moves producer and reader together.
func TestIOCReadersMatchOnTheSharedPrefixes(t *testing.T) {
	b, err := os.ReadFile("ioc.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := stripStoreComments(string(b))

	if regexp.MustCompile(`rule_id\s*=\s*'`).MatchString(src) {
		t.Error("alerts.rule_id を文字列リテラルと比較しています。" +
			"rule_id は uuid で、この比較は 22P02 で失敗します")
	}
	// The literal may appear exactly once each: in the const declaration.
	for _, literal := range []string{IOCAlertTitlePrefixEN, IOCAlertTitlePrefixJA} {
		if n := strings.Count(src, `"`+literal+`"`); n != 1 {
			t.Errorf("プレフィックス %q が %d 箇所に現れます (定数宣言の1箇所のみであるべき)",
				literal, n)
		}
	}
}

// stripStoreComments removes Go comments before a source scan, so a comment
// quoting the code it replaced is not mistaken for that code.
func stripStoreComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`(?m)(^|[^:])//.*$`).ReplaceAllString(src, "$1")
}
