package handlers_test

// cspm-enhanced の 4 本が DB を引かず固定値を返していた件の再発防止。
//
// 修正前:
//
//	GET  /admin/cspm-enhanced/accounts        … 3 アカウントを捏造
//	GET  /admin/cspm-enhanced/findings        … 所見 3 件を捏造。id は uuid.New()
//	POST /admin/cspm-enhanced/accounts/:id/scan … 何もせず scan_status:"scanning"
//	GET  /admin/cspm-enhanced/stats           … total_findings:47 / CIS 86.3%
//
// どれもクラウドに接続していないので、返していた数字に裏付けは無い。
// ここで押さえるのは 4 点:
//  1. スキャナ未実装を「開始しました」と言わない (501)
//  2. 集計が実際に cspm_findings の増減に追従する
//  3. 所見の id が実 id で、呼ぶたびに変わらない (捏造時は毎回別 UUID だった)
//  4. 解釈できない絞り込みを黙って握り潰して 0 件にしない (400)

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
)

type cspmStatsBody struct {
	TotalAccounts int      `json:"total_accounts"`
	TotalFindings int      `json:"total_findings"`
	Critical      int      `json:"critical"`
	High          int      `json:"high"`
	Medium        int      `json:"medium"`
	Low           int      `json:"low"`
	AvgScore      *float64 `json:"avg_posture_score"`
	ByProvider    []struct {
		Provider     string   `json:"provider"`
		PostureScore *float64 `json:"posture_score"`
		Critical     int      `json:"critical"`
		High         int      `json:"high"`
	} `json:"by_provider"`
	ComplianceOpenFindings []struct {
		Framework    string `json:"framework"`
		OpenFindings int    `json:"open_findings"`
	} `json:"compliance_open_findings"`
	DataAvailable bool `json:"data_available"`
}

type cspmFindingsBody struct {
	Findings []struct {
		ID            string `json:"id"`
		CloudProvider string `json:"cloud_provider"`
		CheckID       string `json:"check_id"`
		Severity      string `json:"severity"`
		Status        string `json:"status"`
	} `json:"findings"`
	Total int `json:"total"`
}

func cspmCall(t *testing.T, pool *pgxpool.Pool, method, target string, out interface{}) int {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, target, nil)

	h := handlers.NewCSPMEnhancedHandler(pool)
	switch {
	case target == "/accounts":
		h.ListAccounts(c)
	case target == "/stats":
		h.GetStats(c)
	default:
		h.ListFindings(c)
	}

	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("レスポンスが JSON として読めない: %v (body=%s)", err, w.Body.String())
		}
	}
	return w.Code
}

// startScan は 1 アカウントに対してスキャン開始を呼ぶ。
func startScan(t *testing.T, pool *pgxpool.Pool, accountUUID, role string, out interface{}) int {
	t.Helper()
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/scan", nil)
	c.Params = gin.Params{{Key: "id", Value: accountUUID}}
	if role != "" {
		c.Set("role", role)
	}
	handlers.NewCSPMEnhancedHandler(pool).StartScan(c)

	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("レスポンスが JSON として読めない: %v (body=%s)", err, w.Body.String())
		}
	}
	return w.Code
}

type scanStartBody struct {
	Code       string `json:"code"`
	Error      string `json:"error"`
	ScanStatus string `json:"scan_status"`
}

// 引受ロールが未設定のアカウントは検査しようがない。
// ここで 200 と scan_status:"scanning" を返すと、設定漏れが
// 「スキャン中」に見えたまま永久に完了しない。
func TestCSPMEnhanced_StartScanWithoutCredentialsDoesNotClaimToRun(t *testing.T) {
	pool := testPool(t)
	accountUUID := seedCSPM(t, pool, "aws")

	var body scanStartBody
	code := startScan(t, pool, accountUUID, "admin", &body)

	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (引受ロールが無い)", code)
	}
	if body.Code != "cspm_credentials_not_configured" {
		t.Errorf("code = %q, want cspm_credentials_not_configured", body.Code)
	}
	if body.ScanStatus != "" {
		t.Errorf("scan_status = %q — 開始していないので状態を名乗らない", body.ScanStatus)
	}

	// DB 側も scanning になっていないこと。
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(scan_status, '') FROM cspm_accounts WHERE id = $1::uuid`,
		accountUUID).Scan(&status); err != nil {
		t.Fatalf("scan_status の確認に失敗: %v", err)
	}
	if status == "scanning" {
		t.Error("実行していないのに scan_status が scanning になっている")
	}
}

// AWS 以外のスキャナはまだ無い。「未対応」と「設定漏れ」は打ち手が違うので
// 応答を分ける。
func TestCSPMEnhanced_StartScanUnsupportedProvider(t *testing.T) {
	pool := testPool(t)
	accountUUID := seedCSPM(t, pool, "alibaba")

	var body scanStartBody
	code := startScan(t, pool, accountUUID, "admin", &body)

	if code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501 (alibaba のスキャナは無い)", code)
	}
	if body.Code != "cspm_scanner_not_implemented" {
		t.Errorf("code = %q, want cspm_scanner_not_implemented", body.Code)
	}
	if body.ScanStatus != "" {
		t.Errorf("scan_status = %q — 実行していないので状態を名乗らない", body.ScanStatus)
	}
}

// 引受ロールの登録は顧客クラウドへの読み取り権限に直結する。閲覧専用は弾く。
func TestCSPMEnhanced_ViewerCannotStartScanOrSetCredentials(t *testing.T) {
	pool := testPool(t)
	accountUUID := seedCSPM(t, pool, "aws")

	if code := startScan(t, pool, accountUUID, "viewer", nil); code != http.StatusForbidden {
		t.Errorf("viewer の scan = %d, want 403", code)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/credentials",
		strings.NewReader(`{"role_arn":"arn:aws:iam::123456789012:role/x","external_id":"e"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: accountUUID}}
	c.Set("role", "viewer")
	handlers.NewCSPMEnhancedHandler(pool).SetCredentials(c)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer の credentials = %d, want 403", w.Code)
	}
}

// 外部 ID の無いロールは ARN を知っている誰でも引き受けられる。登録時に弾く。
func TestCSPMEnhanced_SetCredentialsRejectsMissingExternalID(t *testing.T) {
	pool := testPool(t)
	accountUUID := seedCSPM(t, pool, "aws")

	for _, body := range []string{
		`{"role_arn":"arn:aws:iam::123456789012:role/x"}`,
		`{"role_arn":"","external_id":"e"}`,
		`{"role_arn":"not-an-arn","external_id":"e"}`,
	} {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPut, "/credentials", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: accountUUID}}
		c.Set("role", "admin")
		handlers.NewCSPMEnhancedHandler(pool).SetCredentials(c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s → status = %d, want 400", body, w.Code)
		}
	}
}

// seedCSPM は取り込み済みの状態を 1 アカウント分作る。
// provider は他のテストと衝突しにくい alibaba を使う。
func seedCSPM(t *testing.T, pool *pgxpool.Pool, provider string) string {
	t.Helper()
	ctx := context.Background()

	const accountKey = "cspm-enhanced-itest-0001"
	cleanup := func() {
		if _, err := pool.Exec(ctx, `
			DELETE FROM cspm_findings
			 WHERE account_id IN (SELECT id FROM cspm_accounts WHERE account_id = $1)`,
			accountKey); err != nil {
			t.Errorf("後片付けに失敗しました (cspm_findings): %v", err)
		}
		if _, err := pool.Exec(ctx,
			`DELETE FROM cspm_accounts WHERE account_id = $1`, accountKey); err != nil {
			t.Errorf("後片付けに失敗しました (cspm_accounts): %v", err)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	var accountUUID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO cspm_accounts
		    (cloud_provider, account_id, account_name, posture_score, scan_status, last_scanned_at)
		VALUES ($2, $1, 'cspm itest', 88.5, 'completed', NOW())
		RETURNING id::text`, accountKey, provider).Scan(&accountUUID); err != nil {
		t.Skipf("cspm_accounts が使えない: %v", err)
	}

	// 未対応 2 件 (critical / high) と、解決済み 1 件。数えてよいのは前 2 件。
	for _, f := range []struct{ check, sev, status string }{
		{"itest-crit", "critical", "open"},
		{"itest-high", "high", "open"},
		{"itest-done", "critical", "resolved"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO cspm_findings
			    (account_id, resource_type, resource_id, resource_name, region,
			     check_id, check_name, severity, status, compliance_frameworks)
			VALUES ($1::uuid, 'Bucket', 'res-'||$2, 'itest', 'ap-northeast-1',
			        $2, 'itest check', $3, $4, ARRAY['CIS-ITEST'])`,
			accountUUID, f.check, f.sev, f.status); err != nil {
			t.Fatalf("seed cspm_findings (%s): %v", f.check, err)
		}
	}
	return accountUUID
}

// 集計が実データの増減に追従することを、投入前後の差分で確かめる。
// 表を共有しているため絶対値では見ない。
func TestCSPMEnhanced_StatsFollowDatabase(t *testing.T) {
	pool := testPool(t)

	var before cspmStatsBody
	if code := cspmCall(t, pool, http.MethodGet, "/stats", &before); code != http.StatusOK {
		t.Fatalf("stats (投入前) status = %d", code)
	}

	seedCSPM(t, pool, "alibaba")

	var after cspmStatsBody
	if code := cspmCall(t, pool, http.MethodGet, "/stats", &after); code != http.StatusOK {
		t.Fatalf("stats (投入後) status = %d", code)
	}

	// 固定値を返していた頃は、何を入れても 47 / 9 / 28 のままだった。
	if got := after.TotalFindings - before.TotalFindings; got != 2 {
		t.Errorf("total_findings の増分 = %d, want 2 (resolved の 1 件は数えない)", got)
	}
	if got := after.Critical - before.Critical; got != 1 {
		t.Errorf("critical の増分 = %d, want 1 (resolved の critical を数えていないか)", got)
	}
	if got := after.High - before.High; got != 1 {
		t.Errorf("high の増分 = %d, want 1", got)
	}
	if got := after.TotalAccounts - before.TotalAccounts; got != 1 {
		t.Errorf("total_accounts の増分 = %d, want 1", got)
	}
	if !after.DataAvailable {
		t.Error("所見を入れたのに data_available=false")
	}

	// 準拠率ではなく未対応件数。分母 (評価した総項目数) を持っていないため、
	// 「CIS 86.3% 準拠」のような率は算出できない。
	found := false
	for _, f := range after.ComplianceOpenFindings {
		if f.Framework == "CIS-ITEST" {
			found = true
			if f.OpenFindings != 2 {
				t.Errorf("CIS-ITEST の open_findings = %d, want 2", f.OpenFindings)
			}
		}
	}
	if !found {
		t.Error("compliance_open_findings に CIS-ITEST が無い — 枠組み別の集計が実データを見ていない")
	}

	// posture_score は 0〜100。捏造時は 7.6 のような 10 点満点で、
	// /cloud-security 側の 100 点満点と桁が合っていなかった。
	if after.AvgScore == nil {
		t.Error("スキャン済みアカウントがあるのに avg_posture_score が null")
	} else if *after.AvgScore < 0 || *after.AvgScore > 100 {
		t.Errorf("avg_posture_score = %v — 0〜100 の範囲外", *after.AvgScore)
	}
}

// 所見の id が実 id で、呼ぶたびに変わらないこと。
// 捏造していた頃は uuid.New() を返していたため、画面から所見を選んで
// 抑止・解決といった操作に進めなかった。
func TestCSPMEnhanced_FindingIDsAreRealAndStable(t *testing.T) {
	pool := testPool(t)
	accountUUID := seedCSPM(t, pool, "alibaba")

	var first cspmFindingsBody
	if code := cspmCall(t, pool, http.MethodGet,
		"/findings?provider=alibaba&status=open", &first); code != http.StatusOK {
		t.Fatalf("findings status = %d", code)
	}
	if first.Total < 2 {
		t.Fatalf("total = %d, want 2 以上 (投入した未対応 2 件が見えていない)", first.Total)
	}

	var second cspmFindingsBody
	if code := cspmCall(t, pool, http.MethodGet,
		"/findings?provider=alibaba&status=open", &second); code != http.StatusOK {
		t.Fatalf("findings (2 回目) status = %d", code)
	}

	ids := map[string]bool{}
	for _, f := range first.Findings {
		ids[f.ID] = true
		if f.Status != "open" {
			t.Errorf("status=open で絞ったのに %q が返った", f.Status)
		}
	}
	for _, f := range second.Findings {
		if !ids[f.ID] {
			t.Errorf("2 回目で id が変わった (%s) — 実 id を返していない", f.ID)
		}
	}

	// 返した id が本当に cspm_findings の行を指しているか。
	for _, f := range first.Findings {
		if f.CheckID != "itest-crit" && f.CheckID != "itest-high" {
			continue
		}
		var n int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM cspm_findings WHERE id = $1::uuid AND account_id = $2::uuid`,
			f.ID, accountUUID).Scan(&n); err != nil {
			t.Fatalf("id の照合に失敗: %v", err)
		}
		if n != 1 {
			t.Errorf("id %s に対応する行が %d 件 — 実在しない id を返している", f.ID, n)
		}
	}
}

// 解釈できない絞り込みは 400。黙って 0 件を返すと「所見が無い」と読めてしまう。
func TestCSPMEnhanced_UnknownFilterIsRejected(t *testing.T) {
	pool := testPool(t)

	for _, target := range []string{
		"/findings?severity=urgent",
		"/findings?status=closed",
		"/findings?provider=oracle",
	} {
		if code := cspmCall(t, pool, http.MethodGet, target, nil); code != http.StatusBadRequest {
			t.Errorf("%s の status = %d, want 400 (0 件と区別できない)", target, code)
		}
	}
}
