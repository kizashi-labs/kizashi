package scorecard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Every control in this package is scored from a COUNT or an aggregate, and
// every one of those queries used to be written
//
//	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM hardening_baselines`).Scan(&n)
//
// which leaves n at zero when the query fails. Zero was already a meaningful
// answer for each control, so a failure arrived as a finding. Measured by
// running the real scorer against a context whose every query fails:
//
//	                 healthy   every query failing
//	NIST CSF          42.5            35.3
//	ISO 27001         50.0            46.9
//	returned error     nil             nil
//
// Seven points and three points, with 23 of 25 NIST controls carrying specific
// findings — "No hardening baselines configured, non_compliant", "0 Sigma
// detection rules enabled, non_compliant". These reports are read by auditors,
// and nothing in one said the difference was an outage.
//
// Two things made it that hard to see:
//
//   - not_assessed was averaged in at its score of zero, so the two controls
//     that DID check their error were penalised for it — Identify fell 51.1 to
//     21.1 on a database that had not changed. Marking failures honestly made
//     the score worse, which is the wrong incentive to build in.
//   - Nine controls carried fixed scores (NIST Recover's 60/55/65/50, ISO's
//     flat 55 for nineteen clauses) with evidence that admitted as much:
//     "Recovery plan documentation not linked to system". Those were averaged in
//     as findings too. Partway through this fix, once the queries started
//     reporting failures, they were the only controls left standing and a
//     completely dead database scored 58.1 — better than a working one.
//
// So: a query failure leaves the control not_assessed with the reason recorded,
// unassessed controls are excluded from the average rather than counted as zero,
// controls with no evidence source are not scored at all, and a scorecard where
// nothing could be assessed is an error rather than a number.
//
// These tests pin all four. The source scan at the bottom stops the original
// shape coming back one query at a time.

func honestyPool(t *testing.T) *pgxpool.Pool {
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

// deadContext is a context every query fails under. It stands in for the
// outages this file is about — a dropped connection, a statement timeout, a
// revoked grant — without needing to break the shared test database.
func deadContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// byID indexes controls for comparison between two runs.
func byID(controls []*Control) map[string]*Control {
	m := make(map[string]*Control, len(controls))
	for _, c := range controls {
		m[c.ID] = c
	}
	return m
}

// ─── A failure is not a finding ───────────────────────────────────────────────

// The headline: when nothing can be read, nothing is claimed.
func TestADeadDatabaseProducesNoFindings(t *testing.T) {
	pool := honestyPool(t)
	s := NewScorer(pool)

	for _, tc := range []struct {
		name string
		calc func(context.Context) (*Scorecard, error)
	}{
		{"NIST_CSF", s.CalculateNISTCSF},
		{"ISO27001", s.CalculateISO27001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, err := tc.calc(deadContext())
			if !errors.Is(err, ErrNothingAssessed) {
				t.Fatalf("全クエリが失敗したのに err=%v。期待は ErrNothingAssessed —"+
					"呼び出し側が障害とスコアを区別できません", err)
			}
			if sc.AssessedControls != 0 {
				t.Errorf("assessed_controls=%d、期待は0", sc.AssessedControls)
			}
			if sc.TotalControls != len(sc.Controls) {
				t.Errorf("total_controls=%d、コントロール数は%d", sc.TotalControls, len(sc.Controls))
			}
			if sc.OverallScore != 0 {
				t.Errorf("何も評価できていないのに総合スコア %.1f が出ています", sc.OverallScore)
			}
			if len(sc.CategoryScores) != 0 {
				t.Errorf("何も評価できていないのにカテゴリスコアがあります: %v", sc.CategoryScores)
			}

			for _, c := range sc.Controls {
				if c.Status != StatusNotAssessed {
					t.Errorf("%s: クエリが失敗したのに status=%q score=%.0f evidence=%q — "+
						"障害が指摘事項として報告されています", c.ID, c.Status, c.Score, c.Evidence)
				}
				if c.Score != 0 {
					t.Errorf("%s: 未評価なのに score=%.0f が残っています", c.ID, c.Score)
				}
				if c.Evidence == "" {
					t.Errorf("%s: 未評価の理由が空です", c.ID)
				}
			}
		})
	}
}

// The reason must survive to the caller, or "not assessed" is just a shrug.
// Only the controls whose query actually ran and failed carry an Error; the ones
// with no evidence source at all carry the reason in Evidence instead.
func TestAFailedQueryRecordsWhyItFailed(t *testing.T) {
	pool := honestyPool(t)
	sc, _ := NewScorer(pool).CalculateNISTCSF(deadContext())

	// These are the controls backed by a query. Each must name its failure.
	backed := []string{
		"ID.AM-1", "ID.AM-2", "ID.AM-5", "ID.RA-1", "ID.RA-5",
		"PR.AC-1", "PR.DS-1", "PR.IP-1", "PR.IP-3", "PR.PT-1",
		"DE.AE-1", "DE.AE-3", "DE.CM-1", "DE.CM-4", "DE.DP-4",
		"RS.RP-1", "RS.CO-2", "RS.AN-1", "RS.MI-1", "RS.IM-1",
		"RC.RP-2",
	}
	idx := byID(sc.Controls)
	for _, id := range backed {
		c, ok := idx[id]
		if !ok {
			t.Fatalf("%s がスコアカードにありません", id)
		}
		if c.Error == "" {
			t.Errorf("%s: クエリが失敗したのに error が空です — "+
				"「データが無い」と「読めなかった」が区別できません", id)
		}
	}

	// And the ones with no evidence source must NOT claim a query failed.
	for _, id := range []string{"RC.RP-1", "RC.IM-1", "RC.CO-3", "RC.CO-1"} {
		c, ok := idx[id]
		if !ok {
			t.Fatalf("%s がスコアカードにありません", id)
		}
		if c.Error != "" {
			t.Errorf("%s: 証跡クエリを持たないコントロールに error=%q が付いています", id, c.Error)
		}
	}
}

// ─── A failure moves coverage, not the score ──────────────────────────────────

// This is the property that makes honest failure reporting affordable. Losing
// one control's evidence must not change what the surviving controls say.
//
// Both scorecards are derived from a SINGLE read of the database. Scoring twice
// and comparing looks equivalent and is not: TEST_DATABASE_URL is shared, other
// packages run concurrently under `go test ./...`, and a row appearing in
// `users` between the two reads moved PR.AC-1 from non_compliant to partial —
// a failure that pointed at the code and was caused by the fixture.
func TestLosingOneControlDoesNotMoveTheOthers(t *testing.T) {
	pool := honestyPool(t)
	s := NewScorer(pool)
	ctx := context.Background()

	controls := s.scoreIdentify(ctx)
	controls = append(controls, s.scoreProtect(ctx)...)
	controls = append(controls, s.scoreDetect(ctx)...)
	controls = append(controls, s.scoreRespond(ctx)...)
	controls = append(controls, s.scoreRecover(ctx)...)

	// Two scorecards over the same evidence: one intact, one with a single
	// control's result taken away.
	full := &Scorecard{Framework: "NIST_CSF", CategoryScores: map[string]float64{}}
	degraded := &Scorecard{Framework: "NIST_CSF", CategoryScores: map[string]float64{}}
	for _, c := range controls {
		copyA, copyB := *c, *c
		full.Controls = append(full.Controls, &copyA)
		degraded.Controls = append(degraded.Controls, &copyB)
	}
	s.calculateScores(full)
	if full.AssessedControls == 0 {
		t.Fatal("healthy database assessed nothing — the fixture is wrong")
	}

	lost := byID(degraded.Controls)["DE.CM-4"]
	if lost == nil {
		t.Fatal("DE.CM-4 not produced")
	}
	if !lost.assessed() {
		t.Fatal("DE.CM-4 was not assessed on a healthy database — the fixture is wrong")
	}
	unassessed(errors.New("simulated outage"), "detection rules could not be read", lost)
	s.calculateScores(degraded)

	if degraded.AssessedControls != full.AssessedControls-1 {
		t.Errorf("assessed_controls が %d から %d に。期待は1件だけ減ること",
			full.AssessedControls, degraded.AssessedControls)
	}

	// Every other control is untouched.
	fullIdx := byID(full.Controls)
	for _, c := range degraded.Controls {
		if c.ID == "DE.CM-4" {
			continue
		}
		before := fullIdx[c.ID]
		if before == nil {
			t.Errorf("%s が healthy 側にありません", c.ID)
			continue
		}
		if c.Status != before.Status || c.Score != before.Score {
			t.Errorf("%s が %s/%.0f から %s/%.0f に変わりました — "+
				"別のコントロールの障害が波及しています",
				c.ID, before.Status, before.Score, c.Status, c.Score)
		}
	}

	// And every category except the one that lost a control keeps its score.
	for cat, score := range full.CategoryScores {
		if cat == "Detect" {
			continue
		}
		if got := degraded.CategoryScores[cat]; got != score {
			t.Errorf("%s カテゴリのスコアが %.4f から %.4f に動きました。"+
				"失敗したのは Detect のコントロールです", cat, score, got)
		}
	}
	if degraded.CategoryScores["Detect"] == full.CategoryScores["Detect"] {
		t.Error("評価対象から外れたのに Detect のスコアが変わっていません — 除外が効いていません")
	}
}

// The specific regression: unassessed controls must not be averaged in at zero.
func TestUnassessedControlsAreNotScoredAsZero(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		CategoryScores: map[string]float64{},
		Controls: []*Control{
			{ID: "A", Category: "X", Weight: 1, Score: 80, Status: StatusCompliant},
			{ID: "B", Category: "X", Weight: 1, Score: 0, Status: StatusNotAssessed},
		},
	}
	s.calculateScores(sc)

	if sc.OverallScore != 80 {
		t.Errorf("総合スコアが %.1f。期待は80 — 未評価のコントロールが0点として平均に入っています",
			sc.OverallScore)
	}
	if sc.AssessedControls != 1 || sc.TotalControls != 2 {
		t.Errorf("assessed=%d total=%d、期待は 1/2", sc.AssessedControls, sc.TotalControls)
	}
}

// unassessed must clear whatever the control was carrying. Every call site
// today happens before the control is scored, so a stale score cannot currently
// reach the response — but that is an accident of ordering, and the field it
// would leave behind is a compliance score with a not_assessed status beside it.
func TestUnassessedClearsAScoreAlreadyRecorded(t *testing.T) {
	c := &Control{ID: "X", Score: 85, Status: StatusCompliant, Evidence: "12 endpoints encrypted"}
	unassessed(errors.New("connection refused"), "endpoint encryption state could not be read", c)

	if c.Score != 0 {
		t.Errorf("未評価にしたのに score=%.0f が残っています。"+
			"not_assessed と併記されたスコアは読む側にとって矛盾です", c.Score)
	}
	if c.Status != StatusNotAssessed {
		t.Errorf("status=%q、期待は not_assessed", c.Status)
	}
	if c.Evidence != "endpoint encryption state could not be read" {
		t.Errorf("evidence=%q。古い証跡が残っています", c.Evidence)
	}
	if c.Error != "connection refused" {
		t.Errorf("error=%q、期待は connection refused", c.Error)
	}
}

// A category where nothing could be assessed is absent, not zero. Zero renders
// as a failing posture on the dashboard.
func TestAWhollyUnassessedCategoryIsAbsentNotZero(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		CategoryScores: map[string]float64{},
		Controls: []*Control{
			{ID: "A", Category: "Kept", Weight: 1, Score: 70, Status: StatusPartial},
			{ID: "B", Category: "Lost", Weight: 1, Score: 0, Status: StatusNotAssessed},
		},
	}
	s.calculateScores(sc)

	if _, present := sc.CategoryScores["Lost"]; present {
		t.Errorf("全て未評価のカテゴリが %.1f として報告されています",
			sc.CategoryScores["Lost"])
	}
	if sc.CategoryScores["Kept"] != 70 {
		t.Errorf("Kept=%.1f、期待は70", sc.CategoryScores["Kept"])
	}
}

// ─── A score with no measurement behind it is not a score ─────────────────────

// The nine controls that carried fixed numbers. If any regains one, a dead
// database starts outscoring a live one again.
func TestControlsWithNoEvidenceSourceAreNotScored(t *testing.T) {
	pool := honestyPool(t)

	for _, id := range []string{"RC.RP-1", "RC.IM-1", "RC.CO-3", "RC.CO-1"} {
		c := recoverControl(t, pool, id)
		if c.Status != StatusNotAssessed {
			t.Errorf("%s: 証跡が無いのに status=%q score=%.0f。"+
				"固定値は測定結果ではありません", id, c.Status, c.Score)
		}
		if c.Score != 0 {
			t.Errorf("%s: 未評価なのに score=%.0f", id, c.Score)
		}
		if c.Evidence == "" {
			t.Errorf("%s: 評価できない理由が書かれていません", id)
		}
	}

	// ISO's nineteen. Spot-check the clauses this platform holds no data for.
	for _, id := range []string{"A.5.1.1", "A.6.2.2", "A.10.1.2", "A.18.2.2"} {
		c := isoControl(t, pool, id)
		if c.Status != StatusNotAssessed {
			t.Errorf("%s: 証跡が無いのに status=%q score=%.0f — "+
				"ISO27001 の大半が固定値 55 でした", id, c.Status, c.Score)
		}
		if !strings.Contains(c.Evidence, "manual") {
			t.Errorf("%s: evidence=%q。手動評価が必要である旨が読み取れません", id, c.Evidence)
		}
	}
}

// A healthy database must outscore a broken one. This is the check that would
// have caught the state this fix passed through partway.
func TestAHealthyDatabaseAssessesMoreThanADeadOne(t *testing.T) {
	pool := honestyPool(t)
	s := NewScorer(pool)

	healthy, err := s.CalculateNISTCSF(context.Background())
	if err != nil {
		t.Fatalf("healthy: %v", err)
	}
	dead, _ := s.CalculateNISTCSF(deadContext())

	if healthy.AssessedControls <= dead.AssessedControls {
		t.Errorf("健全なDBの評価済み %d件 <= 死んだDBの %d件",
			healthy.AssessedControls, dead.AssessedControls)
	}
	if dead.OverallScore > healthy.OverallScore {
		t.Errorf("死んだDBの総合スコア %.1f が健全なDBの %.1f を上回っています",
			dead.OverallScore, healthy.OverallScore)
	}
}

// ─── A real zero is a finding ─────────────────────────────────────────────────

// The inverse mistake. ID.AM-2 used to leave itself not_assessed whenever the
// software inventory was empty, while carrying the evidence "0 software packages
// inventoried" — a real answer reported as never having looked.
func TestAnEmptyInventoryIsAFindingNotASkippedCheck(t *testing.T) {
	pool := honestyPool(t)
	ctx := context.Background()

	var swCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM endpoint_software`).Scan(&swCount); err != nil {
		t.Fatalf("read software inventory: %v", err)
	}

	var got *Control
	for _, c := range NewScorer(pool).scoreIdentify(ctx) {
		if c.ID == "ID.AM-2" {
			got = c
		}
	}
	if got == nil {
		t.Fatal("ID.AM-2 not produced")
	}
	if got.Status == StatusNotAssessed {
		t.Errorf("ソフトウェアインベントリを %d件 読めたのに status=not_assessed です。"+
			"ゼロは「測っていない」ではなく指摘事項です", swCount)
	}
	if got.Error != "" {
		t.Errorf("クエリが成功したのに error=%q", got.Error)
	}
}

// ─── Unassessed controls never become advice ──────────────────────────────────

// An unassessed control scores 0, which beats every real finding in a
// worst-first sort. It used to head the recommendations on a failed query.
func TestRecommendationsIgnoreUnassessedControls(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		Controls: []*Control{
			{Name: "Outage", Category: "Protect", Weight: 1, Score: 0, Status: StatusNotAssessed},
			{Name: "Real Gap", Category: "Detect", Weight: 1, Score: 20, Status: StatusNonCompliant},
		},
	}
	recs := s.GetRecommendations(sc)
	if len(recs) != 1 {
		t.Fatalf("推奨事項が %d件: %v", len(recs), recs)
	}
	if !strings.Contains(recs[0], "Real Gap") {
		t.Errorf("推奨事項が %q。未評価のコントロールが実際の指摘より優先されています", recs[0])
	}
}

// When nothing was assessed, the advice is to fix the platform — not to
// congratulate the customer on being compliant.
func TestNothingAssessedIsNotReportedAsCompliant(t *testing.T) {
	s := NewScorer(nil)
	sc := &Scorecard{
		Controls: []*Control{
			{Name: "A", Category: "X", Weight: 1, Status: StatusNotAssessed},
			{Name: "B", Category: "X", Weight: 1, Status: StatusNotAssessed},
		},
	}
	recs := s.GetRecommendations(sc)
	if len(recs) != 1 {
		t.Fatalf("推奨事項が %d件: %v", len(recs), recs)
	}
	if strings.Contains(recs[0], "All assessed controls are compliant") {
		t.Errorf("何も評価できていないのに「全て準拠」と報告されました: %q", recs[0])
	}
	if !strings.Contains(strings.ToLower(recs[0]), "assessed") {
		t.Errorf("評価できなかった旨が伝わりません: %q", recs[0])
	}
}

// ─── Source gate ──────────────────────────────────────────────────────────────

// discardedQueryRe matches a database call whose error is thrown away. It is the
// exact shape every defect above was written in.
var discardedQueryRe = regexp.MustCompile(`(?m)^\s*_(?:, _)? = \w+(?:\.\w+)*\.(Query|QueryRow|Exec)\(`)

// knownDiscardedQueries is empty and must stay so. It held twenty-seven entries
// when this gate was written — every control in the file — and between them they
// let a completely dead database report a NIST CSF score of 35.3 with twenty-three
// named compliance findings.
var knownDiscardedQueries = map[string]bool{}

// TestNoQueryErrorIsDiscardedInThisPackage is the gate.
func TestNoQueryErrorIsDiscardedInThisPackage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no source files found — the scan is broken and this test would pass vacuously")
	}

	found := map[string]bool{}
	var problems []string
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		scanned++
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if !discardedQueryRe.MatchString(line) {
				continue
			}
			key := f + ": " + strings.TrimSpace(line)
			found[key] = true
			if !knownDiscardedQueries[key] {
				problems = append(problems, fmt.Sprintf("%s:%d: %s", f, i+1, strings.TrimSpace(line)))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no non-test source scanned — the gate would pass vacuously")
	}

	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("クエリのエラーを破棄しています。失敗が0件として集計され、"+
			"コンプライアンス上の指摘事項として報告されます。"+
			"countOf を使い、失敗時は unassessed を呼んでください: %s", p)
	}

	// Ratchet: an entry that is no longer found must go.
	for key := range knownDiscardedQueries {
		if !found[key] {
			t.Errorf("knownDiscardedQueries still lists %q, but the scan no longer "+
				"finds it. Delete the entry.", key)
		}
	}
}

// TestTheDiscardedQueryScanWorks stops the gate passing because the regex
// stopped matching.
func TestTheDiscardedQueryScanWorks(t *testing.T) {
	for _, bad := range []string{
		"\t_ = s.pool.QueryRow(ctx, `SELECT 1`).Scan(&n)",
		"\t_, _ = pool.Exec(ctx, `DELETE FROM x`)",
		"\t\t_ = h.db.Query(ctx, q)",
	} {
		if !discardedQueryRe.MatchString(bad) {
			t.Errorf("破棄パターンを検出できませんでした: %q", bad)
		}
	}
	for _, ok := range []string{
		"\tn, err := s.countOf(ctx, `SELECT 1`)",
		"\tif err := s.pool.QueryRow(ctx, q).Scan(&n); err != nil {",
		"\t_ = someOtherThing.Compute()",
		"\t_ = fmt.Sprintf(\"QueryRow(\")",
	} {
		if discardedQueryRe.MatchString(ok) {
			t.Errorf("正常なコードを破棄として検出しました: %q", ok)
		}
	}
}
