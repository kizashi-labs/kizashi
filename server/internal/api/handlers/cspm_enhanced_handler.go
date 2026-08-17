package handlers

// migration 149 で入った CSPM 拡張のハンドラ群。
//
// 以前は 4 本とも DB を一切引かず、固定値を返していた:
//
//	ListAccounts … AWS/Azure/GCP の 3 アカウントを捏造。id は uuid.New() で
//	               毎回変わるため、返した所見を後から操作できなかった。
//	ListFindings … S3 公開・IAM 過剰権限・SSH 公開の 3 件を捏造。同上。
//	StartScan    … 何もせずに scan_status:"scanning" を返す。
//	GetStats     … total_findings:47 / CIS 準拠率 86.3% などを固定で返す。
//
// 実施していない監査の結果を報告するのはセキュリティ製品として最も避けたい
// 嘘なので、実表 (cspm_accounts / cspm_findings) を引く形に直した (PR #731)。
// 取り込みが 1 件も無ければ data_available=false で「未計測」を返す。
//
// 所見を入れる経路は 2 つ:
//
//	外部ツールの取り込み … POST /api/v1/cloud/findings/import (PR #680)
//	自前の AWS スキャナ  … internal/cspm/awsscan。StartScan から起動する
//
// AWS 以外のスキャナはまだ無いので、azure/gcp のアカウントに対する
// StartScan は 501 を返す。

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/cspm/awsscan"
	"github.com/edr-platform/server/internal/store"
)

// CSPM（クラウド設定の姿勢管理）の宛先です。
//
// **中身がありません。** ここは DB もクラウドの API も1度も見ず、
// その場で作ったアカウントと検出を 200 で返していました（実測
// 2026-08-12）:
//
//	{"cloud_provider": "aws", "account_id": "123456789012",
//	 "account_name": "Production Account", "posture_score": 7.8,
//	 "critical_findings": 3, "last_scanned_at": time.Now().Add(-1 * time.Hour)}
//
//	{"resource_type": "S3_Bucket", "resource_id": "prod-data-bucket",
//	 "check_name": "S3バケット公開アクセス", "severity": "critical",
//	 "description": "S3バケットがパブリックアクセスを許可しています"}
//
// **「1時間前にスキャンして critical 3件」は、対応を始めさせる形です。**
// 存在しない `prod-data-bucket` の公開設定を、誰かが探しに行きます。
// `123456789012` は AWS の例示用アカウント ID です。
//
// `StartScan` は「スキャンを開始しました」と答えて、**何も始めません**。
//
// いまは 501 を返します。約束は `not_implemented_test.go` にあります:
//
//	200 + []  まだ何も起きていない（待てばよい）
//	500       読めなかった（もう一度試す価値がある）
//	501       これを作るものが無い（待っても変わらない）
//
// 作るとしたら、まずクラウド各社の設定 API を読む経路からです ——
// 保管するテーブルも、評価するルールもありません。
type CSPMEnhancedHandler struct{ pool *pgxpool.Pool }

func NewCSPMEnhancedHandler(pool *pgxpool.Pool) *CSPMEnhancedHandler {
	return &CSPMEnhancedHandler{pool: pool}
}

// cspmAccount は cspm_accounts の 1 行。
//
// PostureScore は 0〜100。捏造していた頃は 7.8 のような 10 点満点の値を
// 返していたが、取り込み側が入れる実値は 100 点からの減点方式で、
// /cloud-security の posture_score とも桁が揃っている。
type cspmAccount struct {
	ID               string     `json:"id"`
	CloudProvider    string     `json:"cloud_provider"`
	AccountID        string     `json:"account_id"`
	AccountName      string     `json:"account_name"`
	PostureScore     float64    `json:"posture_score"`
	CriticalFindings int        `json:"critical_findings"`
	HighFindings     int        `json:"high_findings"`
	ScanStatus       string     `json:"scan_status"`
	LastScannedAt    *time.Time `json:"last_scanned_at"`
	Enabled          bool       `json:"enabled"`
}

// ListAccounts は登録済みのクラウドアカウントを返す。
// GET /api/v1/admin/cspm-enhanced/accounts
func (h *CSPMEnhancedHandler) ListAccounts(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id::text, cloud_provider, account_id,
		       COALESCE(account_name, ''),
		       COALESCE(posture_score, 0)::float8,
		       COALESCE(critical_findings, 0),
		       COALESCE(high_findings, 0),
		       COALESCE(scan_status, 'idle'),
		       last_scanned_at,
		       COALESCE(enabled, true)
		  FROM cspm_accounts
		 ORDER BY cloud_provider, account_name, account_id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	accounts := []cspmAccount{}
	for rows.Next() {
		var a cspmAccount
		if err := rows.Scan(&a.ID, &a.CloudProvider, &a.AccountID, &a.AccountName,
			&a.PostureScore, &a.CriticalFindings, &a.HighFindings,
			&a.ScanStatus, &a.LastScannedAt, &a.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"accounts": accounts,
		"total":    len(accounts),
		// 0 件は「アカウントが 1 つも登録されていない」であって、
		// 「クラウドに問題が無い」ではない。
		"data_available": len(accounts) > 0,
	})
}

type cspmFindingRow struct {
	ID                   string    `json:"id"`
	AccountID            string    `json:"account_id"`
	CloudProvider        string    `json:"cloud_provider"`
	ResourceType         string    `json:"resource_type"`
	ResourceID           string    `json:"resource_id"`
	ResourceName         string    `json:"resource_name"`
	Region               string    `json:"region"`
	CheckID              string    `json:"check_id"`
	CheckName            string    `json:"check_name"`
	Severity             string    `json:"severity"`
	Status               string    `json:"status"`
	Description          string    `json:"description"`
	Remediation          string    `json:"remediation"`
	ComplianceFrameworks []string  `json:"compliance_frameworks"`
	FirstSeenAt          time.Time `json:"first_seen_at"`
	LastSeenAt           time.Time `json:"last_seen_at"`
}

// ListFindings は所見を返す。
// GET /api/v1/admin/cspm-enhanced/findings?provider=&severity=&status=&limit=&offset=
//
// 既定では未対応 (status='open') のものだけを返す。解決済みまで混ぜると
// 「未対応が何件あるか」が読めなくなるため。
func (h *CSPMEnhancedHandler) ListFindings(c *gin.Context) {
	ctx := c.Request.Context()

	// 値は列挙で受ける。想定外の値をそのまま WHERE に入れると 0 件になり、
	// 「所見が無い」と読めてしまうので、既定に落とさず 400 で返す。
	status, ok := pickEnum(c.DefaultQuery("status", "open"),
		"open", "suppressed", "resolved", "accepted_risk", "all")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "status は open / suppressed / resolved / accepted_risk / all のいずれかです"})
		return
	}
	severity, ok := pickEnum(c.DefaultQuery("severity", "all"),
		"critical", "high", "medium", "low", "all")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "severity は critical / high / medium / low のいずれかです"})
		return
	}
	provider, ok := pickEnum(c.DefaultQuery("provider", "all"),
		"aws", "azure", "gcp", "alibaba", "all")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "provider は aws / azure / gcp / alibaba のいずれかです"})
		return
	}

	limit := clampQueryInt(c.Query("limit"), 100, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1_000_000)

	// $N は常に同じ位置に置き、'all' のときだけ条件を無効化する。
	// 条件の数で $N がずれると取り違えやすいため。
	const q = `
		SELECT f.id::text, a.id::text, a.cloud_provider,
		       COALESCE(f.resource_type, ''), COALESCE(f.resource_id, ''),
		       COALESCE(f.resource_name, ''), COALESCE(f.region, ''),
		       f.check_id, COALESCE(f.check_name, ''),
		       f.severity, f.status,
		       COALESCE(f.description, ''), COALESCE(f.remediation, ''),
		       COALESCE(f.compliance_frameworks, '{}'),
		       f.first_seen_at, f.last_seen_at
		  FROM cspm_findings f
		  JOIN cspm_accounts a ON a.id = f.account_id
		 WHERE ($1 = 'all' OR f.status = $1)
		   AND ($2 = 'all' OR f.severity = $2)
		   AND ($3 = 'all' OR a.cloud_provider = $3)
		 ORDER BY CASE f.severity
		            WHEN 'critical' THEN 1 WHEN 'high' THEN 2
		            WHEN 'medium' THEN 3 ELSE 4 END,
		          f.last_seen_at DESC
		 LIMIT $4 OFFSET $5`

	rows, err := h.pool.Query(ctx, q, status, severity, provider, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	findings := []cspmFindingRow{}
	for rows.Next() {
		var f cspmFindingRow
		if err := rows.Scan(&f.ID, &f.AccountID, &f.CloudProvider,
			&f.ResourceType, &f.ResourceID, &f.ResourceName, &f.Region,
			&f.CheckID, &f.CheckName, &f.Severity, &f.Status,
			&f.Description, &f.Remediation, &f.ComplianceFrameworks,
			&f.FirstSeenAt, &f.LastSeenAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// total は絞り込み後の全件数。LIMIT で切った件数を total と呼ぶと
	// ページングした側が総数を誤る。
	var total int
	if err := h.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		  FROM cspm_findings f
		  JOIN cspm_accounts a ON a.id = f.account_id
		 WHERE ($1 = 'all' OR f.status = $1)
		   AND ($2 = 'all' OR f.severity = $2)
		   AND ($3 = 'all' OR a.cloud_provider = $3)`,
		status, severity, provider).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"findings": findings,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
	})
}

// SetCredentials はスキャンに使う引受ロールを登録する。
// PUT /api/v1/admin/cspm-enhanced/accounts/:id/credentials
//
// 長期のアクセスキーは受け取らない。顧客アカウント側に作った読み取り専用
// ロールの ARN と外部 ID だけを持ち、実際の認証は実行時の AssumeRole で行う。
func (h *CSPMEnhancedHandler) SetCredentials(c *gin.Context) {
	if c.GetString("role") == "viewer" {
		c.JSON(http.StatusForbidden, gin.H{"error": "閲覧専用ロールでは引受ロールを登録できません"})
		return
	}

	var req struct {
		RoleARN    string   `json:"role_arn"`
		ExternalID string   `json:"external_id"`
		Regions    []string `json:"regions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role_arn と external_id を指定してください"})
		return
	}
	// 形式の検査はスキャナ側の実装と一致させる。ここで通しておいて
	// 実行時に落ちると、登録できたのにスキャンできない状態になる。
	newCreds := awsscan.Credentials{RoleARN: req.RoleARN, ExternalID: req.ExternalID}
	if err := newCreds.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id := c.Param("id")
	if err := store.NewCSPMStore(h.pool).SetCredentials(
		c.Request.Context(), id, req.RoleARN, req.ExternalID, req.Regions); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"account_id": id, "role_arn": req.RoleARN, "regions": req.Regions})
}

// StartScan はアカウント単位のスキャンを開始する。
// POST /api/v1/admin/cspm-enhanced/accounts/:id/scan
//
// 実行は非同期。応答は「開始した」であって「終わった」ではないので 202 を返す。
// 進行状況は GET /accounts の scan_status で見る。
//
// 以前はここで無条件に 200 と scan_status:"scanning" を返していたが、
// 何も実行していなかった (PR #731 で 501 に是正)。今はロールを引き受けて
// 実際に検査する。ただし引受情報が無いアカウントは検査しようがないので、
// 走ったふりをせず 400 を返す。
func (h *CSPMEnhancedHandler) StartScan(c *gin.Context) {
	if c.GetString("role") == "viewer" {
		c.JSON(http.StatusForbidden, gin.H{"error": "閲覧専用ロールではスキャンを開始できません"})
		return
	}

	ctx := c.Request.Context()
	id := c.Param("id")
	cs := store.NewCSPMStore(h.pool)

	acct, err := cs.Credentials(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "アカウントが見つかりません"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// AWS 以外のスキャナは無い。「対応していない」と「設定が無い」は
	// 運用者にとって打ち手が違うので、別の応答にする。
	if acct.Provider != "aws" {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error": acct.Provider + " のスキャナは未実装です。所見は " +
				"POST /api/v1/cloud/findings/import から取り込んでください。",
			"code":            "cspm_scanner_not_implemented",
			"provider":        acct.Provider,
			"import_endpoint": "/api/v1/cloud/findings/import",
		})
		return
	}
	if !acct.Enabled {
		c.JSON(http.StatusConflict, gin.H{"error": "このアカウントは無効化されています"})
		return
	}
	creds := awsscan.Credentials{RoleARN: acct.RoleARN, ExternalID: acct.ExternalID}
	if err := creds.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "引受ロールが設定されていないためスキャンできません: " + err.Error(),
			"code":  "cspm_credentials_not_configured",
			"hint":  "PUT /api/v1/admin/cspm-enhanced/accounts/" + id + "/credentials で登録してください",
		})
		return
	}

	if err := cs.SetScanStatus(ctx, id, "scanning", nil); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// リクエストの context は応答を返した時点で切れるので、実行側には渡さない。
	go awsscan.RunAndPersist(cs, id, creds, acct.Regions)

	c.JSON(http.StatusAccepted, gin.H{
		"account_id":  id,
		"scan_status": "scanning",
		"message":     "スキャンを開始しました。進行状況は GET /accounts の scan_status を参照してください。",
	})
}

// GetStats は CSPM の集計を返す。
// GET /api/v1/admin/cspm-enhanced/stats
//
// compliance_coverage について: cspm_findings に入るのは「不合格の所見」だけで、
// 取り込み API は PASS を行にせず既存の所見を resolved にする。つまり
// 「何項目中何項目に合格したか」の分母が手元に無い。以前はここで
// CIS 145/23 (86.3%) のような準拠率を固定値で返していたが、分母が無い以上
// 準拠率は算出できない。枠組みごとの未対応件数だけを返す。
func (h *CSPMEnhancedHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	var totalAccounts int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cspm_accounts`).Scan(&totalAccounts); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	rows, err := h.pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM cspm_findings
		 WHERE status = 'open' GROUP BY severity`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	total := 0
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		if _, known := counts[sev]; known {
			counts[sev] = n
		}
		total += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// 一度もスキャン結果を取り込んでいないアカウントの posture_score は
	// 既定値の 0 で、これは「最悪の状態」ではなく「未計測」。平均に混ぜると
	// アカウントを登録しただけでスコアが下がるので、除外する。
	var avgScore *float64
	if err := h.pool.QueryRow(ctx, `
		SELECT AVG(posture_score)::float8 FROM cspm_accounts
		 WHERE last_scanned_at IS NOT NULL`).Scan(&avgScore); err != nil {
		slog.Warn("CSPM: 平均スコアの取得に失敗しました", "error", err)
	}

	byProvider, err := h.statsByProvider(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	frameworks, err := h.openFindingsByFramework(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total_accounts":    totalAccounts,
		"total_findings":    total,
		"critical":          counts["critical"],
		"high":              counts["high"],
		"medium":            counts["medium"],
		"low":               counts["low"],
		"avg_posture_score": avgScore, // 未計測なら null
		"by_provider":       byProvider,
		// 準拠率ではなく未対応件数。分母 (評価した総項目数) を持っていない。
		"compliance_open_findings": frameworks,
		// 取り込みが 1 件も無い状態を「問題なし」と読ませない。
		"data_available": total > 0,
	})
}

func (h *CSPMEnhancedHandler) statsByProvider(ctx context.Context) ([]gin.H, error) {
	// アカウントは登録済みだが所見が 0 件、という状態も表に出したいので
	// cspm_accounts を左外部結合の左側に置く。
	rows, err := h.pool.Query(ctx, `
		SELECT a.cloud_provider,
		       COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'critical'),
		       COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'high'),
		       COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'medium'),
		       COUNT(*) FILTER (WHERE f.status = 'open' AND f.severity = 'low'),
		       AVG(a.posture_score) FILTER (WHERE a.last_scanned_at IS NOT NULL)::float8
		  FROM cspm_accounts a
		  LEFT JOIN cspm_findings f ON f.account_id = a.id
		 GROUP BY a.cloud_provider
		 ORDER BY a.cloud_provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []gin.H{}
	for rows.Next() {
		var provider string
		var crit, high, med, low int
		var score *float64
		if err := rows.Scan(&provider, &crit, &high, &med, &low, &score); err != nil {
			return nil, err
		}
		out = append(out, gin.H{
			"provider":      provider,
			"posture_score": score,
			"critical":      crit,
			"high":          high,
			"medium":        med,
			"low":           low,
		})
	}
	return out, rows.Err()
}

func (h *CSPMEnhancedHandler) openFindingsByFramework(ctx context.Context) ([]gin.H, error) {
	rows, err := h.pool.Query(ctx, `
		SELECT fw, COUNT(*)
		  FROM cspm_findings f, UNNEST(f.compliance_frameworks) AS fw
		 WHERE f.status = 'open'
		 GROUP BY fw
		 ORDER BY COUNT(*) DESC, fw`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []gin.H{}
	for rows.Next() {
		var fw string
		var n int
		if err := rows.Scan(&fw, &n); err != nil {
			return nil, err
		}
		out = append(out, gin.H{"framework": fw, "open_findings": n})
	}
	return out, rows.Err()
}

// pickEnum は許可値のいずれかであれば true を返す。
func pickEnum(v string, allowed ...string) (string, bool) {
	for _, a := range allowed {
		if v == a {
			return v, true
		}
	}
	return "", false
}

// clampQueryInt は数値クエリを範囲内に収める。解釈できない値は既定値に落とす
// (絞り込みと違い、件数の指定ミスで結果の意味が変わることはないため)。
func clampQueryInt(raw string, def, min, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}
