package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FIMPageHandler provides non-admin FIM endpoints used by the frontend /fim page.
// GET    /api/v1/fim/suspicious
// GET    /api/v1/fim/ignore-rules
// POST   /api/v1/fim/ignore-rules
// DELETE /api/v1/fim/ignore-rules/:id
type FIMPageHandler struct {
	pool *pgxpool.Pool
}

func NewFIMPageHandler(pool *pgxpool.Pool) *FIMPageHandler {
	return &FIMPageHandler{pool: pool}
}

func (h *FIMPageHandler) tableExists(c *gin.Context, name string) bool {
	return tableIsThere(c.Request.Context(), h.pool, name)
}

// ListSuspicious returns high-risk FIM events from the last 24 hours.
// GET /api/v1/fim/suspicious
func (h *FIMPageHandler) ListSuspicious(c *gin.Context) {
	ctx := c.Request.Context()

	type SuspiciousFile struct {
		ID          string   `json:"id"`
		FilePath    string   `json:"file_path"`
		ChangeType  string   `json:"change_type"`
		AgentID     string   `json:"agent_id"`
		AgentName   string   `json:"agent_name"`
		Timestamp   string   `json:"timestamp"`
		RiskScore   int      `json:"risk_score"`
		RiskReasons []string `json:"risk_reasons"`
	}

	var files []SuspiciousFile

	// Try fim_events table.
	if h.tableExists(c, "fim_events") {
		rows, err := h.pool.Query(ctx, `
			SELECT fe.id::text,
			       fe.file_path,
			       fe.change_type,
			       fe.agent_id::text,
			       COALESCE(a.hostname, ''),
			       fe.created_at,
			       COALESCE(fe.risk_score, 0)
			FROM fim_events fe
			LEFT JOIN agents a ON a.id = fe.agent_id
			WHERE fe.risk_score >= 70
			   OR fe.file_path LIKE '%system32%'
			   OR fe.file_path LIKE '%passwd%'
			   OR fe.file_path LIKE '%shadow%'
			ORDER BY fe.created_at DESC LIMIT 200`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var f SuspiciousFile
				var ts time.Time
				if rows.Scan(&f.ID, &f.FilePath, &f.ChangeType, &f.AgentID, &f.AgentName, &ts, &f.RiskScore) == nil {
					f.Timestamp = ts.Format(time.RFC3339)
					f.RiskReasons = deriveRiskReasons(f.FilePath, f.ChangeType)
					files = append(files, f)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("ListSuspicious: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
		}
	}

	// フォールバックの条件は「テーブルが無いこと」ではなく「行が取れなかったこと」
	// です。fim_events はマイグレーションが作りますが書き込むコードがどこにも
	// 無く、tableExists は常に true を返すため、実データのある events 側の分岐に
	// 一度も到達していませんでした。テーブルの有無はデータの有無ではありません。
	if len(files) == 0 && h.tableExists(c, "events") {
		// Fall back to generic events.
		// events の実際の列は event_id / event_type / time / raw_data (migration 002)。
		// id / type / created_at / event_data / data はいずれも存在せず、このクエリは
		// 毎回失敗していた。さらに event_type の CHECK 制約は
		// ('process','file','network','dns','registry','auth') しか許さないため、
		// 'file_integrity' は仮に列名が正しくても 1 件も一致しない値だった。
		// ファイル系イベントは 'file' として入るので、そちらを拾う。
		rows, err := h.pool.Query(ctx, `
			-- 変更種別のキーは change_type ではなく operation で、値は
			-- FileEvent.Action の enum 名 (FILE_ACTION_CREATE など) です。
			-- change_type は存在しないため COALESCE の既定値 'modified' が
			-- 常に採用されており、deriveRiskReasons の "System file deleted" は
			-- 一度も付きませんでした。
			SELECT event_id::text,
			       COALESCE(raw_data->>'path', ''),
			       CASE raw_data->>'operation'
			           WHEN 'FILE_ACTION_CREATE'  THEN 'created'
			           WHEN 'FILE_ACTION_MODIFY'  THEN 'modified'
			           WHEN 'FILE_ACTION_DELETE'  THEN 'deleted'
			           WHEN 'FILE_ACTION_RENAME'  THEN 'renamed'
			           WHEN 'FILE_ACTION_EXECUTE' THEN 'executed'
			           ELSE 'modified'
			       END,
			       COALESCE(agent_id::text, ''),
			       time
			FROM events
			WHERE event_type='file' AND COALESCE(raw_data->>'path', '') != ''
			ORDER BY time DESC LIMIT 200`)
		if err != nil {
			slog.Warn("fim: イベントからのファイル一覧導出に失敗", "error", err)
		}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var f SuspiciousFile
				var ts time.Time
				if rows.Scan(&f.ID, &f.FilePath, &f.ChangeType, &f.AgentID, &ts) == nil {
					f.Timestamp = ts.Format(time.RFC3339)
					f.RiskScore = 75
					f.RiskReasons = deriveRiskReasons(f.FilePath, f.ChangeType)
					files = append(files, f)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("ListSuspicious: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
		}
	}

	if files == nil {
		files = []SuspiciousFile{}
	}
	c.JSON(http.StatusOK, gin.H{"data": files, "total": len(files)})
}

// deriveRiskReasons builds human-readable risk reasons from path/change type.
func deriveRiskReasons(path, changeType string) []string {
	var reasons []string
	if changeType == "deleted" {
		reasons = append(reasons, "System file deleted")
	}
	for _, pattern := range []string{"system32", "passwd", "shadow", "sudoers", "cron", "startup", "boot"} {
		if len(path) > 0 {
			for i := 0; i <= len(path)-len(pattern); i++ {
				if path[i:i+len(pattern)] == pattern {
					reasons = append(reasons, "Sensitive path: "+pattern)
					break
				}
			}
		}
	}
	if len(reasons) == 0 {
		reasons = []string{"Anomalous change detected"}
	}
	return reasons
}

// ListIgnoreRules returns FIM ignore rules.
// GET /api/v1/fim/ignore-rules
func (h *FIMPageHandler) ListIgnoreRules(c *gin.Context) {
	ctx := c.Request.Context()

	type IgnoreRule struct {
		ID        string `json:"id"`
		Pattern   string `json:"pattern"`
		Enabled   bool   `json:"enabled"`
		CreatedAt string `json:"created_at"`
	}

	if !h.tableExists(c, "fim_ignore_rules") {
		c.JSON(http.StatusOK, gin.H{"data": []IgnoreRule{}, "total": 0})
		return
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id::text, pattern, enabled, created_at FROM fim_ignore_rules ORDER BY created_at DESC`)
	if err != nil {
		ReadFailure(c, err, gin.H{"data": []IgnoreRule{}, "total": 0})
		return
	}
	defer rows.Close()

	var rules []IgnoreRule
	for rows.Next() {
		var r IgnoreRule
		var ts time.Time
		if rows.Scan(&r.ID, &r.Pattern, &r.Enabled, &ts) == nil {
			r.CreatedAt = ts.Format(time.RFC3339)
			rules = append(rules, r)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListIgnoreRules: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, gin.H{"data": []IgnoreRule{}, "total": 0})
		return
	}
	if rules == nil {
		rules = []IgnoreRule{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rules, "total": len(rules)})
}

// CreateIgnoreRule adds a new FIM ignore rule.
// POST /api/v1/fim/ignore-rules
func (h *FIMPageHandler) CreateIgnoreRule(c *gin.Context) {
	var in struct {
		Pattern string `json:"pattern" binding:"required"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.tableExists(c, "fim_ignore_rules") {
		// **除外ルールは追加されていません。** 追加したつもりのファイルから、
		// FIM のアラートが出続けます。
		FeatureNotInstalled(c, "FIM 除外ルールの追加")
		return
	}

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO fim_ignore_rules (pattern) VALUES ($1) RETURNING id`, in.Pattern).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "ignore rule added"})
}

// DeleteIgnoreRule removes a FIM ignore rule.
// DELETE /api/v1/fim/ignore-rules/:id
func (h *FIMPageHandler) DeleteIgnoreRule(c *gin.Context) {
	id := c.Param("id")
	if h.tableExists(c, "fim_ignore_rules") {
		if _, err := h.pool.Exec(c.Request.Context(), `DELETE FROM fim_ignore_rules WHERE id=$1`, id); !WriteOK(c, err) {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "rule deleted"})
}
