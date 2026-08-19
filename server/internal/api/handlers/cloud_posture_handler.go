package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CloudPostureHandler provides cloud security posture endpoints for the /cloud-security page.
// GET  /api/v1/cloud/posture?provider=aws|azure|gcp
// POST /api/v1/cloud/scan
type CloudPostureHandler struct {
	pool *pgxpool.Pool
}

func NewCloudPostureHandler(pool *pgxpool.Pool) *CloudPostureHandler {
	return &CloudPostureHandler{pool: pool}
}

func (h *CloudPostureHandler) tableExists(c *gin.Context, name string) bool {
	return tableIsThere(c.Request.Context(), h.pool, name)
}

type cloudPostureResponse struct {
	Provider           string                   `json:"provider"`
	PostureScore       float64                  `json:"posture_score"`
	Findings           map[string]int           `json:"findings"`
	Compliance         map[string]float64       `json:"compliance"`
	Misconfigurations  []map[string]interface{} `json:"misconfigurations"`
	TopRiskyResources  []map[string]interface{} `json:"top_risky_resources"`
	ResourcesMonitored int                      `json:"resources_monitored"`
	LastScanned        string                   `json:"last_scanned"`

	// DataAvailable は「CSPM のデータが 1 件でも入っているか」。
	// これが false のとき posture_score と compliance は未計測を意味する 0 で、
	// 「100% 準拠」ではない。詳細は GetPosture のコメントを参照。
	DataAvailable bool `json:"data_available"`
}

// cspmSource は CSPM 所見の取得元テーブルと、その実スキーマに合わせた
// クエリの組み合わせ。テーブルごとに列名が全く違うため、呼び出し側で
// テーブル名だけ差し替える (以前の実装) ことはできない。
type cspmSource struct {
	name     string
	countSQL string // provider を $1 に取り、(severity, count) を返す
	listSQL  string // provider を $1 に取り、所見を重大度順に返す
}

// cspmSources は取得元の候補。上から順に「実際に行があるもの」を採用する。
//
// cspm_findings に provider 列は無い。プロバイダは cspm_accounts.cloud_provider
// 側にあるため結合が要る。所見の文言も finding ではなく check_name。
// cloud_misconfigurations は別スキーマで、資源は workload_id / workload_name、
// 文言は issue_type / description に入っている。
var cspmSources = []cspmSource{
	{
		name: "cspm_findings",
		countSQL: `SELECT f.severity, COUNT(*)
		           FROM cspm_findings f
		           JOIN cspm_accounts a ON a.id = f.account_id
		           WHERE a.cloud_provider = $1 AND f.status = 'open'
		           GROUP BY f.severity`,
		listSQL: `SELECT f.id::text,
		                 COALESCE(f.resource_type, 'unknown'),
		                 COALESCE(f.resource_name, f.resource_id),
		                 COALESCE(NULLIF(f.check_name, ''), f.check_id),
		                 f.severity,
		                 COALESCE(f.region, 'global'),
		                 f.status,
		                 COALESCE(f.remediation, '')
		          FROM cspm_findings f
		          JOIN cspm_accounts a ON a.id = f.account_id
		          WHERE a.cloud_provider = $1 AND f.status = 'open'
		          ORDER BY CASE f.severity
		                     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
		                     WHEN 'medium' THEN 3 ELSE 4 END,
		                   f.last_seen_at DESC
		          LIMIT 20`,
	},
	{
		name: "cloud_misconfigurations",
		countSQL: `SELECT severity, COUNT(*)
		           FROM cloud_misconfigurations
		           WHERE provider = $1 AND status = 'open'
		           GROUP BY severity`,
		listSQL: `SELECT id::text,
		                 COALESCE(NULLIF(issue_type, ''), 'misconfiguration'),
		                 COALESCE(NULLIF(workload_name, ''), workload_id),
		                 COALESCE(NULLIF(description, ''), issue_type),
		                 severity,
		                 COALESCE(region, 'global'),
		                 status,
		                 remediation
		          FROM cloud_misconfigurations
		          WHERE provider = $1 AND status = 'open'
		          ORDER BY CASE severity
		                     WHEN 'critical' THEN 1 WHEN 'high' THEN 2
		                     WHEN 'medium' THEN 3 ELSE 4 END,
		                   created_at DESC
		          LIMIT 20`,
	},
}

// GetPosture returns the cloud security posture for a given provider.
// GET /api/v1/cloud/posture?provider=aws
//
// 「所見 0 件」と「まだ一度も計測していない」を区別する。
//
// 以前はこの区別が無く、所見が 0 件なら compliance を 100/100/100、
// posture_score を 100 として返していた。ところが実際には発行していた
// SQL が全て実行時エラーになっており (cspm_findings に provider 列も
// finding 列も無い)、エラーは `_ =` と `if err == nil` で捨てられていた。
// 結果として画面には「CIS 100% / SOC 2 100% / ISO 27001 100%、
// スコア 100 点 (A 判定)」— つまりクエリが壊れているという事実が
// 「完全に準拠している」という最も安心できる表示に化けていた。
// セキュリティ製品としては最悪の壊れ方なので、未計測は未計測として返す。
//
// cspm_findings / cspm_accounts への書き込みは PR #680 の取り込み API
// (POST /api/v1/cloud/findings/import) が行う。クラウドへ接続して自分で
// 検査する処理は依然として無いので、外部 CSPM ツールの結果を取り込むまでは
// data_available=false になる。
func (h *CloudPostureHandler) GetPosture(c *gin.Context) {
	provider := c.DefaultQuery("provider", "aws")
	ctx := c.Request.Context()

	resp := cloudPostureResponse{
		Provider:          provider,
		PostureScore:      0,
		Findings:          map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		Compliance:        map[string]float64{"cis": 0, "soc2": 0, "iso27001": 0},
		Misconfigurations: []map[string]interface{}{},
		TopRiskyResources: []map[string]interface{}{},
		LastScanned:       time.Now().UTC().Format(time.RFC3339),
		DataAvailable:     false,
	}

	// 行がある取得元を採用する。テーブルの存在だけで選ぶと、空の
	// cspm_findings が常に勝ってしまい cloud_misconfigurations に
	// 到達できない (以前の実装がこれだった)。
	for _, src := range cspmSources {
		if !h.tableExists(c, src.name) {
			continue
		}
		counts, err := h.severityCounts(ctx, src, provider)
		if err != nil {
			slog.Warn("CSPM: 重大度集計に失敗しました", "table", src.name, "provider", provider, "error", err)
			continue
		}
		total := counts["critical"] + counts["high"] + counts["medium"] + counts["low"]
		if total == 0 {
			continue
		}

		resp.DataAvailable = true
		resp.Findings = counts
		resp.ResourcesMonitored = total

		// スコアは 100 点から重大度ごとに減点する概算。
		penalty := float64(counts["critical"])*5 + float64(counts["high"])*2 +
			float64(counts["medium"])*0.5 + float64(counts["low"])*0.1
		score := 100.0 - penalty
		if score < 0 {
			score = 0
		}
		resp.PostureScore = score
		resp.Compliance = map[string]float64{
			"cis":      score * 0.95,
			"soc2":     score * 0.90,
			"iso27001": score * 0.85,
		}

		if mis, err := h.topMisconfigurations(ctx, src, provider); err != nil {
			slog.Warn("CSPM: 設定不備一覧の取得に失敗しました", "table", src.name, "provider", provider, "error", err)
		} else {
			resp.Misconfigurations = mis
		}
		break
	}

	c.JSON(http.StatusOK, resp)
}

// severityCounts は重大度ごとの未対応件数を返す。以前は重大度ごとに
// 5 回問い合わせていたが、1 回で足りる。
func (h *CloudPostureHandler) severityCounts(ctx context.Context, src cspmSource, provider string) (map[string]int, error) {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	rows, err := h.pool.Query(ctx, src.countSQL, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		if _, known := counts[sev]; known {
			counts[sev] = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

func (h *CloudPostureHandler) topMisconfigurations(ctx context.Context, src cspmSource, provider string) ([]map[string]interface{}, error) {
	rows, err := h.pool.Query(ctx, src.listSQL, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []map[string]interface{}{}
	for rows.Next() {
		var id, rt, rid, finding, sev, region, status, remediation string
		if err := rows.Scan(&id, &rt, &rid, &finding, &sev, &region, &status, &remediation); err != nil {
			return nil, err
		}
		steps := []string{}
		if remediation != "" {
			steps = append(steps, remediation)
		}
		out = append(out, map[string]interface{}{
			// 以前は generateShortID() で毎回違う ID を返していたため、
			// 再取得のたびに React の key が変わっていた。実 ID を返す。
			"id":                id,
			"resource_type":     rt,
			"resource_id":       rid,
			"finding":           finding,
			"severity":          sev,
			"region":            region,
			"status":            status,
			"remediation_steps": steps,
			"cli_command":       "",
		})
	}
	return out, rows.Err()
}

// TriggerScan は CSPM スキャンの実行要求を受ける。
// POST /api/v1/cloud/scan
//
// スキャナは未実装。このリポジトリには cspm_findings / cspm_accounts /
// cloud_misconfigurations に書き込む経路が存在せず、クラウドへ接続する
// コードも無い。
//
// それにもかかわらず、以前はここで 200 と status:"running" を返していた。
// 画面側はそれを受けて進捗バーを 100% まで進め、最後に緑で
// 「スキャン完了 — 全プロバイダーのポスチャーを更新しました」と表示していた。
// 実際には AWS にも Azure にも GCP にも一度も接続していない。
//
// 実施していない監査を「実施した」と報告するのは、セキュリティ製品として
// 最も避けるべき嘘なので、未実装であることをそのまま返す。
// スキャナが入ったらこのハンドラを実装に差し替える。
func (h *CloudPostureHandler) TriggerScan(c *gin.Context) {
	// 設定済みアカウント数は運用者への手がかりとして返す。
	// 取れなくてもスキャンが未実装である事実は変わらないので、失敗しても続ける。
	var accounts int
	if err := h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM cspm_accounts WHERE enabled`).Scan(&accounts); err != nil {
		slog.Warn("CSPM: アカウント数の取得に失敗しました", "error", err)
		accounts = -1
	}

	c.JSON(http.StatusNotImplemented, gin.H{
		// apiFetch は非 2xx のとき error フィールドをそのまま例外メッセージにする。
		"error":               "CSPM スキャナは未実装です。クラウドに接続して設定を検査する処理がまだ入っていないため、スキャンは実行されません。",
		"code":                "cspm_scanner_not_implemented",
		"accounts_configured": accounts,
	})
}

// ── どの表から、どの列で読むか ────────────────────────────────────────────

// postureSource は、姿勢管理の数字をどの表のどの列から取るかを持ちます。
//
// **表を差し替えるだけでは足りません。** cspm_findings と
// cloud_misconfigurations は、同じことを別の列名で持っています。
type postureSource struct {
	from         string // FROM 句（結合を含みます）
	provider     string // クラウド事業者の列
	severity     string
	status       string
	resourceType string
	resourceID   string
	finding      string // 見出しになる一文
	region       string
}

// cloudPostureSource は、在る方の表に合わせた読み方を返します。
//
// 判定を関数に出しているのは、**この環境に PostgreSQL が無く、実行では
// 一度も確かめられないから**です。列名の対応そのものを検査で留めます。
func cloudPostureSource(exists func(string) bool) postureSource {
	switch {
	case exists("cspm_findings"):
		// provider は findings 側にありません。account 経由で辿ります。
		return postureSource{
			from: `cspm_findings f JOIN cspm_accounts a ON a.id = f.account_id`,
			// cloud_provider は 'aws'/'azure'/'gcp'/'alibaba' で、
			// クエリ引数の綴りと同じです。
			provider:     "a.cloud_provider",
			severity:     "f.severity",
			status:       "f.status",
			resourceType: "COALESCE(f.resource_type,'unknown')",
			resourceID:   "COALESCE(f.resource_id,'')",
			// `finding` 列はありません。見出しは check_name です。
			finding: "COALESCE(NULLIF(f.check_name,''), f.description, '')",
			region:  "COALESCE(f.region,'global')",
		}
	case exists("cloud_misconfigurations"):
		return postureSource{
			from:     `cloud_misconfigurations`,
			provider: "provider",
			severity: "severity",
			status:   "status",
			// resource_type / resource_id はありません。ワークロードが
			// いちばん近い単位です。
			resourceType: "COALESCE(NULLIF(issue_type,''),'unknown')",
			resourceID:   "COALESCE(NULLIF(workload_name,''), workload_id, '')",
			finding:      "COALESCE(NULLIF(description,''), issue_type, '')",
			region:       "COALESCE(region,'global')",
		}
	}
	return postureSource{}
}
