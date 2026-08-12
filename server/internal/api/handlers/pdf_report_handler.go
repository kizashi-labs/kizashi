package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PDFReportHandler generates HTML-based reports that can be printed to PDF.
// For true server-side PDF generation, add: go get github.com/chromedp/chromedp
// or use wkhtmltopdf. This implementation returns styled HTML with print CSS.
type PDFReportHandler struct {
	pool *pgxpool.Pool
}

func NewPDFReportHandler(pool *pgxpool.Pool) *PDFReportHandler {
	return &PDFReportHandler{pool: pool}
}

var reportHTML = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>{{.Title}}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 12px; color: #333; }
  .header { background: #1a1a2e; color: white; padding: 24px; margin-bottom: 24px; }
  .header h1 { font-size: 22px; margin-bottom: 4px; }
  .header p { color: #aaa; font-size: 12px; }
  .section { margin: 0 24px 24px; }
  .section h2 { font-size: 14px; border-bottom: 2px solid #e8002d; padding-bottom: 6px; margin-bottom: 12px; color: #1a1a2e; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-card { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 12px; text-align: center; }
  .stat-card .value { font-size: 24px; font-weight: bold; color: #1a1a2e; }
  .stat-card .label { font-size: 11px; color: #666; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 11px; }
  th { background: #f1f3f5; padding: 8px; text-align: left; border-bottom: 2px solid #dee2e6; }
  td { padding: 6px 8px; border-bottom: 1px solid #f1f3f5; }
  tr:nth-child(even) { background: #f8f9fa; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: bold; }
  .badge-critical { background: #ffe0e0; color: #c00; }
  .badge-high { background: #fff0e0; color: #e65; }
  .badge-medium { background: #fffbe0; color: #a80; }
  .badge-low { background: #e0f0ff; color: #06c; }
  .footer { margin: 24px; padding-top: 12px; border-top: 1px solid #dee2e6; font-size: 10px; color: #999; text-align: center; }
  @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>
</head>
<body>
<div class="header">
  <h1>Kizashi — {{.Title}}</h1>
  <p>生成日時: {{.GeneratedAt}} | 対象期間: {{.Period}}</p>
</div>
<div class="section">
  <div class="stats">
    <div class="stat-card"><div class="value">{{.TotalAlerts}}</div><div class="label">総アラート数</div></div>
    <div class="stat-card"><div class="value">{{.CriticalAlerts}}</div><div class="label">クリティカル</div></div>
    <div class="stat-card"><div class="value">{{.OpenAlerts}}</div><div class="label">未対処</div></div>
    <div class="stat-card"><div class="value">{{.OnlineAgents}}</div><div class="label">オンラインエージェント</div></div>
  </div>
</div>
<div class="section">
  <h2>直近のアラート</h2>
  <table>
    <tr><th>タイトル</th><th>重大度</th><th>ステータス</th><th>ソース</th><th>発生日時</th></tr>
    {{range .Alerts}}
    <tr>
      <td>{{.Title}}</td>
      <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
      <td>{{.Status}}</td>
      <td>{{.Source}}</td>
      <td>{{.CreatedAt}}</td>
    </tr>
    {{end}}
  </table>
</div>
<div class="footer">EDR Platform 自動生成レポート | Kizashi Protection Platform</div>
</body>
</html>`))

type reportData struct {
	Title          string
	GeneratedAt    string
	Period         string
	TotalAlerts    int
	CriticalAlerts int
	OpenAlerts     int
	OnlineAgents   int
	Alerts         []alertRow
}

type alertRow struct {
	Title     string
	Severity  string
	Status    string
	Source    string
	CreatedAt string
}

// GenerateHTML handles GET /api/v1/reports/html
// Returns an HTML report suitable for browser printing to PDF
func (h *PDFReportHandler) GenerateHTML(c *gin.Context) {
	period := c.DefaultQuery("period", "7d")
	intervalMap := map[string]string{
		"24h": "24 hours", "7d": "7 days", "30d": "30 days", "90d": "90 days",
	}
	interval, ok := intervalMap[period]
	if !ok {
		interval = "7 days"
	}
	periodLabel := map[string]string{
		"24h": "過去24時間", "7d": "過去7日間", "30d": "過去30日間", "90d": "過去90日間",
	}[period]

	data := reportData{
		Title:       "セキュリティレポート",
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Period:      periodLabel,
	}

	// Fetch stats
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - ($1 || ' ')::INTERVAL`, interval,
	).Scan(&data.TotalAlerts)
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND created_at >= NOW() - ($1 || ' ')::INTERVAL`, interval,
	).Scan(&data.CriticalAlerts)
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM alerts WHERE status='open'`,
	).Scan(&data.OpenAlerts)
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM agents WHERE status='online'`,
	).Scan(&data.OnlineAgents)

	// Fetch recent alerts
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT title, severity, status, source, created_at FROM alerts
         WHERE created_at >= NOW() - ($1 || ' ')::INTERVAL
         ORDER BY created_at DESC LIMIT 50`, interval,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var row alertRow
			var createdAt time.Time
			if err := rows.Scan(&row.Title, &row.Severity, &row.Status, &row.Source, &createdAt); err == nil {
				row.CreatedAt = createdAt.Format("2006-01-02 15:04")
				data.Alerts = append(data.Alerts, row)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var buf bytes.Buffer
	if err := reportHTML.Execute(&buf, data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "レポート生成に失敗しました"})
		return
	}

	filename := fmt.Sprintf("edr-report-%s.html", time.Now().Format("20060102"))
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("Content-Type", "text/html; charset=utf-8")
	_, _ = c.Writer.Write(buf.Bytes())
}
