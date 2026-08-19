package handlers

import (
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ReportExportHandler streams CSV exports of alerts and compliance data.
type ReportExportHandler struct {
	pool *pgxpool.Pool
}

// NewReportExportHandler creates a new ReportExportHandler.
func NewReportExportHandler(pool *pgxpool.Pool) *ReportExportHandler {
	return &ReportExportHandler{pool: pool}
}

// ExportAlerts streams a CSV of alerts filtered by time range and severity.
// GET /api/v1/reports/export/alerts?since=RFC3339&until=RFC3339&severity=&format=csv
func (h *ReportExportHandler) ExportAlerts(c *gin.Context) {
	sinceStr := c.Query("since")
	untilStr := c.Query("until")
	severity := c.Query("severity")

	since := time.Time{}
	until := time.Now()
	var err error
	if sinceStr != "" {
		since, err = time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "since パラメータが無効です"})
			return
		}
	}
	if untilStr != "" {
		until, err = time.Parse(time.RFC3339, untilStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "until パラメータが無効です"})
			return
		}
	}

	args := []interface{}{}
	idx := 1
	where := "WHERE 1=1"
	if !since.IsZero() {
		where += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, since)
		idx++
	}
	where += fmt.Sprintf(" AND created_at <= $%d", idx)
	args = append(args, until)
	idx++
	if severity != "" {
		where += fmt.Sprintf(" AND severity::text = $%d", idx)
		args = append(args, severity)
		idx++
	}

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id::text, COALESCE(title,''), COALESCE(severity::text,''),
		       COALESCE(status,''), COALESCE(agent_id::text,''),
		       COALESCE(mitre_technique,''), created_at
		FROM alerts `+where+` ORDER BY created_at DESC`,
		args...,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アラートの取得に失敗しました"})
		return
	}
	defer rows.Close()

	filename := fmt.Sprintf("alerts_%s.csv", time.Now().Format("20060102_150405"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename="+filename)

	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"id", "title", "severity", "status", "agent_id", "mitre_technique", "created_at"})

	for rows.Next() {
		var id, title, sev, status, agentID, mitre string
		var createdAt time.Time
		if err := rows.Scan(&id, &title, &sev, &status, &agentID, &mitre, &createdAt); err != nil {
			continue
		}
		_ = w.Write([]string{id, title, sev, status, agentID, mitre, createdAt.Format(time.RFC3339)})
	}
	if err := rows.Err(); err != nil {
		// **ここは 500 に切り替えられません。** CSV を書きながら流すので、
		// 失敗した時点で 200 とヘッダは相手に渡っています。
		// 書き換えの道具はここも「番人に揃える」対象に入れましたが、
		// `TestStreamingCSVExportsCallTheIncompleteMarker` が拾いました。
		slog.Error("CSV export: rows.Err", "error", err)
		markCSVIncomplete(w, err)
	}
	w.Flush()
}

// ExportCompliance streams a CSV of compliance scores.
// GET /api/v1/reports/export/compliance?framework=CIS&format=csv
func (h *ReportExportHandler) ExportCompliance(c *gin.Context) {
	framework := c.Query("framework")

	args := []interface{}{}
	idx := 1
	where := "WHERE 1=1"
	if framework != "" {
		where += fmt.Sprintf(" AND framework = $%d", idx)
		args = append(args, framework)
		idx++
	}
	_ = idx // suppress unused warning

	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT COALESCE(agent_id::text,''), COALESCE(framework,''),
		       COALESCE(score,0), COALESCE(passed_checks,0), COALESCE(total_checks,0),
		       computed_at
		FROM compliance_scores `+where+` ORDER BY computed_at DESC`,
		args...,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コンプライアンスデータの取得に失敗しました"})
		return
	}
	defer rows.Close()

	filename := fmt.Sprintf("compliance_%s.csv", time.Now().Format("20060102_150405"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename="+filename)

	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"agent_id", "framework", "score", "passed", "total", "computed_at"})

	for rows.Next() {
		var agentID, fw string
		var score float64
		var passed, total int
		var computedAt time.Time
		if err := rows.Scan(&agentID, &fw, &score, &passed, &total, &computedAt); err != nil {
			continue
		}
		_ = w.Write([]string{
			agentID, fw,
			fmt.Sprintf("%.2f", score),
			fmt.Sprintf("%d", passed),
			fmt.Sprintf("%d", total),
			computedAt.Format(time.RFC3339),
		})
	}
	if err := rows.Err(); err != nil {
		// **ここは 500 に切り替えられません。** CSV を書きながら流すので、
		// 失敗した時点で 200 とヘッダは相手に渡っています。
		// 書き換えの道具はここも「番人に揃える」対象に入れましたが、
		// `TestStreamingCSVExportsCallTheIncompleteMarker` が拾いました。
		slog.Error("CSV export: rows.Err", "error", err)
		markCSVIncomplete(w, err)
	}
	w.Flush()
}

// markCSVIncomplete は、途中で切れた CSV にそのことを書き込みます。
//
// **この2つは書きながら流します。** ヘッダも最初の行も、行の読み出しが
// 失敗するより前に相手へ渡っています。だから 500 に切り替えられません
// —— 状態コードはもう出てしまっています。
//
// できるのは、ファイル自身に書くことだけです。**何も書かないと、
// 途中までの CSV が全件として保存されます。** 表計算で開いたときに
// いちばん下に出る位置に、データとして読めない印を置きます。
//
// 買い切りの解ではありません。**流しながら書く経路は、途中で失敗しても
// 状態コードで伝えられません。** 溜めてから書く形に変えるのが本筋で、
// それは件数の上限とセットで決める話なので `docs/判断待ちの一覧.md` に
// 置いてあります。
func markCSVIncomplete(w *csv.Writer, err error) {
	_ = w.Write([]string{"#INCOMPLETE",
		"読み出しが途中で失敗しました。この CSV は全件ではありません",
		err.Error()})
}
