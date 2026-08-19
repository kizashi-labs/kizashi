package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The billing-grace and licence-expiry notifiers each carried their own copy of
// "which administrators should be emailed", and both filtered on users.active —
// a column no migration creates. The column is is_active. Measured against a
// database holding exactly one enabled admin with an address:
//
//	                          before                     after
//	billing grace notifier    0 recipients, 42703        1 recipient
//	licence expiry notifier   0 recipients, 42703        1 recipient
//
// Neither notice has ever reached anyone by email. Both are warnings whose only
// value is arriving before a deadline — the grace notice precedes an automatic
// downgrade to Free and its agent cap, the licence notice precedes expiry.
//
// The billing notifier also folded the failure into the empty case:
//
//	if err != nil || len(recipients) == 0 {
//	    slog.Info("billing grace notifier: no admin recipients", "error", err)
//
// so a query that could not run was logged as a deployment with nobody to
// notify, at Info.
//
// The statement now exists once. Duplication is what let the two copies drift
// and what would have let one be repaired without the other — which is exactly
// what happened midway through this fix, when the measurement harness still held
// a stale inline copy and reported the licence notifier as broken after it had
// been repaired.

func recipientsPool(t *testing.T) *pgxpool.Pool {
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

// seedUser inserts one user and removes it afterwards.
func seedUser(t *testing.T, pool *pgxpool.Pool, email, role string, active bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (email, password_hash, full_name, role, is_active)
		VALUES ($1, 'x', 'Recipient Fixture', $2, $3)
		ON CONFLICT (email) DO UPDATE SET role = $2, is_active = $3`,
		email, role, active); err != nil {
		t.Fatalf("seed %s: %v", email, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE email = $1`, email)
	})
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// The headline: an enabled admin with an address is a recipient.
func TestAnEnabledAdminIsANotificationRecipient(t *testing.T) {
	pool := recipientsPool(t)
	seedUser(t, pool, "recipient-enabled-admin@example.test", "admin", true)

	got, err := adminRecipients(context.Background(), pool)
	if err != nil {
		t.Fatalf("adminRecipients: %v", err)
	}
	if !has(got, "recipient-enabled-admin@example.test") {
		t.Errorf("有効な管理者が通知先に含まれていません (%d件取得)。"+
			"users の有効フラグは is_active です — active は存在しません", len(got))
	}
}

// And the filters still filter: a disabled admin and an enabled non-admin are
// both excluded, so the gate above cannot be passing by selecting everyone.
func TestOnlyEnabledAdminsAreRecipients(t *testing.T) {
	pool := recipientsPool(t)
	seedUser(t, pool, "recipient-disabled-admin@example.test", "admin", false)
	seedUser(t, pool, "recipient-enabled-analyst@example.test", "analyst", true)

	got, err := adminRecipients(context.Background(), pool)
	if err != nil {
		t.Fatalf("adminRecipients: %v", err)
	}
	if has(got, "recipient-disabled-admin@example.test") {
		t.Error("無効化された管理者が通知先に含まれています")
	}
	if has(got, "recipient-enabled-analyst@example.test") {
		t.Error("管理者でないユーザーが通知先に含まれています")
	}
}

// A failure must be reported, not returned as an empty recipient list. An empty
// list means "nobody to notify", which is a different fact and was the one
// reported for years.
func TestAFailedLookupIsAnErrorNotAnEmptyList(t *testing.T) {
	pool := recipientsPool(t)
	dead, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := adminRecipients(dead, pool)
	if err == nil {
		t.Error("クエリ失敗時にエラーが返りませんでした。" +
			"空のリストは「通知先がいない」という別の事実です")
	}
	if len(got) != 0 {
		t.Errorf("失敗時に %d 件返しました", len(got))
	}
}

// Both notifiers must go through the one helper. Two copies of this statement
// are what let one be fixed while the other stayed broken.
func TestBothNotifiersShareOneRecipientQuery(t *testing.T) {
	var withOwnQuery []string
	for _, f := range []string{
		"billing_grace_notifier.go",
		"license_expiry_notifier.go",
	} {
		b, err := os.ReadFile(filepath.Join(".", f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		if !strings.Contains(src, "adminRecipients(ctx") {
			t.Errorf("%s が共通の adminRecipients を呼んでいません", f)
		}
		if regexp.MustCompile(`(?i)SELECT\s+email\s+FROM\s+users`).MatchString(src) {
			withOwnQuery = append(withOwnQuery, f)
		}
	}
	for _, f := range withOwnQuery {
		t.Errorf("%s が管理者メールのクエリを自前で持っています。"+
			"重複は片方だけが修正される原因になります", f)
	}
}

// The billing notifier must not fold a lookup failure back into the empty case.
func TestTheBillingNotifierSeparatesFailureFromNobodyToNotify(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(".", "billing_grace_notifier.go"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := stripComments(string(b))

	if regexp.MustCompile(`err != nil \|\| len\(recipients\) == 0`).MatchString(src) {
		t.Error("クエリ失敗と「通知先ゼロ」が同じ分岐にまとめられています。" +
			"前者は障害、後者は環境の事実で、対応が異なります")
	}
	if !strings.Contains(src, "could not read admin recipients") {
		t.Error("取得失敗が固有のメッセージで報告されていません")
	}
}

// stripComments removes Go comments before a source scan, so a comment quoting
// the code it replaced is not mistaken for that code.
func stripComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`(?m)(^|[^:])//.*$`).ReplaceAllString(src, "$1")
}

// ─── Scheduled hunting ────────────────────────────────────────────────────────

// saved_hunt_queries has no `scheduled` column, no migration creates one, and
// nothing in this repository can set it: the store's INSERT and UPDATE name
// name, description, query, query_type, tags, created_by and is_shared, and
// there is no UI. HuntScheduler is nonetheless registered in cmd/api and ticks
// every 15 minutes, taking its "column missing, skip" branch every time.
//
// That branch logged at Debug, which in a normal configuration is silent — a
// worker that has never executed a single hunt, and no way to tell from
// outside. It reports once at Warn now.
//
// This test pins the reporting, not the feature. Whether scheduled hunting
// should be finished or removed is a product decision; either way a scheduler
// that cannot run must say so.
func TestTheHuntSchedulerReportsThatItCannotRun(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(".", "hunt_scheduler.go"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := stripComments(string(b))

	guard := src[strings.Index(src, "if !hasScheduled || !hasLastRun"):]
	end := strings.Index(guard, "\n\t}")
	if end > 0 {
		guard = guard[:end]
	}

	if strings.Contains(guard, "slog.Debug") {
		t.Error("スケジュールハントが実行不能である事実が Debug ログのままです。" +
			"通常のログ設定では何も出ず、ワーカーが一度も動いていないことが外から分かりません")
	}
	if !strings.Contains(guard, "slog.Warn") {
		t.Error("実行不能である事実が Warn 以上で報告されていません")
	}
	if !strings.Contains(guard, "warnUnavailable.Do") {
		t.Error("15分ごとに同じ警告が出ます。一度だけ報告してください")
	}
}

// And the column really is absent, so the warning is not describing a state
// that has quietly been fixed elsewhere.
func TestScheduledHuntingHasNoBackingColumn(t *testing.T) {
	pool := recipientsPool(t)

	var exists bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='saved_hunt_queries'
			  AND column_name='scheduled')`).Scan(&exists); err != nil {
		t.Fatalf("column check: %v", err)
	}
	if exists {
		t.Error("saved_hunt_queries.scheduled が存在します。" +
			"定期ハントが有効化されたのであれば、hunt_scheduler の警告と " +
			"このテストを削除し、書き込み側 (store の INSERT/UPDATE) の対応を確認してください")
	}
}
