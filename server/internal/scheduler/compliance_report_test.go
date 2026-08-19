package scheduler

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

// The compliance section of a scheduled report had three defects at once, and
// Postgres could only report the first:
//
//	SELECT setting_value  →  the column is `value`             (42703, whole statement rejected)
//	WHERE key = 'compliance_status'  →  'admin.compliance.status'  (no such row)
//	Scan(&complianceStatus) into a string  →  the value is a jsonb object
//
// The error was swallowed into a fallback string, so every scheduled compliance
// report ever emailed said "コンプライアンスデータなし" — including to the
// auditors these reports are scheduled for. Fixing only the column name leaves
// the section blank for the second reason, which is why this test seeds through
// the key the console actually writes.

func complianceReportPool(t *testing.T) *pgxpool.Pool {
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

// The headline: a scheduled compliance report carries the assessment.
func TestAScheduledComplianceReportCarriesTheAssessment(t *testing.T) {
	pool := complianceReportPool(t)
	ctx := context.Background()

	// system_settings is keyed by a single primary key, so this fixture takes
	// over the real row and puts it back afterwards rather than inventing a key
	// the reader would not look at.
	var prior []byte
	hadPrior := pool.QueryRow(ctx,
		`SELECT value FROM system_settings WHERE key = $1`, complianceStatusSettingKey).
		Scan(&prior) == nil

	assessment, _ := json.Marshal(map[string]any{
		"nist_csf":      map[string]string{"ID.AM": "implemented", "ID.BE": "partial", "PR.AC": "implemented"},
		"iso_27001":     map[string]string{"A.5": "not_implemented"},
		"last_assessed": "2026-01-02T03:04:05Z",
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		complianceStatusSettingKey, assessment); err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		if hadPrior {
			_, _ = pool.Exec(c, `UPDATE system_settings SET value=$2 WHERE key=$1`,
				complianceStatusSettingKey, prior)
			return
		}
		_, _ = pool.Exec(c, `DELETE FROM system_settings WHERE key=$1`, complianceStatusSettingKey)
	})

	// Through the generator, not by re-issuing its query.
	s := NewReportScheduler(nil, pool)
	body, err := s.generateReport(ctx, &store.ReportSchedule{
		Name:       "fixture-" + uuid.NewString()[:8],
		ReportType: "compliance",
		Frequency:  "weekly",
	})
	if err != nil {
		t.Fatalf("generateReport: %v", err)
	}

	if strings.Contains(body, "コンプライアンスデータなし") {
		t.Fatalf("レポートがコンプライアンス状況を取得できていません:\n%s\n"+
			"列名は value (setting_value ではない)、キーは %q です",
			body, complianceStatusSettingKey)
	}
	for _, want := range []string{
		"NIST CSF (3管理策)",
		"実装済み 2件",
		"一部実装 1件",
		"ISO 27001 (1管理策)",
		"未実装 1件",
		"2026-01-02T03:04:05Z",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("レポートに %q がありません:\n%s", want, body)
		}
	}

	// And the raw JSON must not be pasted in. The stored object holds one entry
	// per control — dumping it is not a report.
	if strings.Contains(body, "nist_csf") || strings.Contains(body, "ID.AM") {
		t.Errorf("レポートに JSON がそのまま出ています:\n%s", body)
	}
}

// An assessment that has never been made must say so rather than render an
// empty framework list, and a malformed value must not crash the scheduled send.
func TestAnUnassessedOrMalformedStatusFallsBackCleanly(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"empty object", `{}`},
		{"frameworks present but empty", `{"nist_csf":{},"iso_27001":{}}`},
		{"not the expected shape", `"just a string"`},
		{"not json at all", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := summarizeComplianceStatus(context.Background(), []byte(tc.raw))
			if !strings.Contains(got, "コンプライアンスデータなし") {
				t.Errorf("評価が無い/読めない場合の出力 = %q。"+
					"空の枠だけを出すと「評価したが該当なし」に読めます", got)
			}
		})
	}
}

// The reader's key must stay equal to the writer's. They are constants in two
// packages with no compile-time link between them, and this is exactly how the
// section came to read a key nothing writes: divergence produces an empty
// section, never an error.
func TestTheReportReadsTheKeyTheConsoleWrites(t *testing.T) {
	b, err := os.ReadFile("../api/handlers/compliance_status_handler.go")
	if err != nil {
		t.Fatalf("read compliance_status_handler.go: %v", err)
	}
	want := `complianceStatusKey = "` + complianceStatusSettingKey + `"`
	if !strings.Contains(string(b), want) {
		t.Errorf("コンプライアンス状況の書き込み先キーが %q と一致しません。"+
			"読み手と書き手でキーがずれても、この節は空になるだけでエラーは出ません",
			complianceStatusSettingKey)
	}
}

// A control state the console adds later must still be counted. Dropping an
// unrecognised state would quietly shrink the total, which is the shape of
// error nobody notices in a report.
func TestAnUnrecognisedControlStateIsStillCounted(t *testing.T) {
	got := summarizeComplianceStatus(context.Background(), []byte(
		`{"nist_csf":{"ID.AM":"implemented","ID.BE":"compensating"}}`))

	if !strings.Contains(got, "NIST CSF (2管理策)") {
		t.Errorf("管理策の総数が合いません: %q", got)
	}
	if !strings.Contains(got, "compensating 1件") {
		t.Errorf("未知の状態が落ちています: %q。"+
			"数えられない状態は総数からも消えるので、"+
			"読んだ人は管理策が減ったと解釈します", got)
	}
}
