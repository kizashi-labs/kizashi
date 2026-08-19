package handlers

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DNSSecurityHandler handles DNS security monitoring endpoints.
// GET  /api/v1/dns/alerts
// GET  /api/v1/dns/queries
// GET  /api/v1/dns/blocklist
// DELETE /api/v1/dns/blocklist/:id
// GET  /api/v1/dns/stats
type DNSSecurityHandler struct {
	pool *pgxpool.Pool
}

func NewDNSSecurityHandler(pool *pgxpool.Pool) *DNSSecurityHandler {
	return &DNSSecurityHandler{pool: pool}
}

func (h *DNSSecurityHandler) tableExists(c *gin.Context, name string) bool {
	return tableIsThere(c.Request.Context(), h.pool, name)
}

// ListAlerts returns recent suspicious DNS alerts.
// GET /api/v1/dns/alerts
func (h *DNSSecurityHandler) ListAlerts(c *gin.Context) {
	ctx := c.Request.Context()

	type DNSAlert struct {
		ID         string  `json:"id"`
		Domain     string  `json:"domain"`
		QueryType  string  `json:"query_type"`
		ClientIP   string  `json:"client_ip"`
		AgentID    *string `json:"agent_id"`
		Threat     string  `json:"threat_type"`
		Confidence int     `json:"confidence"`
		Blocked    bool    `json:"blocked"`
		Timestamp  string  `json:"timestamp"`
	}

	// Try dns_alerts table first; fall back to deriving from events.
	if h.tableExists(c, "dns_alerts") {
		rows, err := h.pool.Query(ctx, `
			SELECT id::text, domain, COALESCE(query_type,'A'), client_ip,
			       agent_id::text, threat_type, confidence, blocked, created_at
			FROM dns_alerts ORDER BY created_at DESC LIMIT 200`)
		if err == nil {
			defer rows.Close()
			var alerts []DNSAlert
			for rows.Next() {
				var a DNSAlert
				var ts time.Time
				if rows.Scan(&a.ID, &a.Domain, &a.QueryType, &a.ClientIP,
					&a.AgentID, &a.Threat, &a.Confidence, &a.Blocked, &ts) == nil {
					a.Timestamp = ts.Format(time.RFC3339)
					alerts = append(alerts, a)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("ListAlerts: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
			// 行が取れた場合だけここで返します。dns_alerts はマイグレーションが
			// 作りますが書き込むコードがどこにも無く、tableExists は常に true を
			// 返すため、以前は無条件に空配列を返して events 側の分岐に一度も
			// 到達していませんでした。テーブルの有無はデータの有無ではありません。
			if len(alerts) > 0 {
				c.JSON(http.StatusOK, gin.H{"alerts": alerts})
				return
			}
		}
	}

	// Fall back: derive from generic events table.
	var alerts []DNSAlert
	if h.tableExists(c, "events") {
		// events の実際の列は event_id / agent_id / event_type / time / raw_data
		// (migration 002)。id / type / created_at / event_data / data / metadata は
		// いずれも存在せず、このクエリは毎回失敗していた。err は下で握りつぶされる
		// ため、DNS セキュリティ画面は常に「アラート 0 件」に見えていた。
		// クライアントIPは raw_data には入りません。DnsEvent に送信元IPの
		// フィールドが無いためで、src_ip は常に空でした。DNS を引いたのは
		// エージェント自身なので、正しい値は agents.ip_addresses です。
		// 複数IPを持つ端末ではどのインターフェイスから引いたかは分からないため
		// 先頭を採ります (この画面の目的は「どの端末が引いたか」であり、
		// 端末の特定には agent_id も併せて返しています)。
		rows, err := h.pool.Query(ctx, `
			SELECT e.event_id::text, COALESCE(e.raw_data->>'query', ''),
			       COALESCE(e.raw_data->>'query_type', 'A'),
			       -- ip_addresses は inet[] なので text に落としてから既定値を
			       -- 当てます。COALESCE(..., '') のままだと '' が inet として
			       -- 解釈され 22P02 で文ごと失敗します。
			       COALESCE(host(a.ip_addresses[1]), ''),
			       e.agent_id::text, e.time
			FROM events e
			LEFT JOIN agents a ON a.id = e.agent_id
			WHERE e.event_type='dns' AND (e.raw_data->>'is_suspicious')::boolean = true
			ORDER BY e.time DESC LIMIT 200`)
		if err != nil {
			slog.Warn("dns security: イベントからのアラート導出に失敗", "error", err)
		}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var a DNSAlert
				var ts time.Time
				if rows.Scan(&a.ID, &a.Domain, &a.QueryType, &a.ClientIP, &a.AgentID, &ts) == nil {
					a.Threat = "suspicious_domain"
					a.Confidence = 70
					a.Timestamp = ts.Format(time.RFC3339)
					alerts = append(alerts, a)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("ListAlerts: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
		}
	}
	if alerts == nil {
		alerts = []DNSAlert{}
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

// ListQueries returns top queried domains.
// GET /api/v1/dns/queries
func (h *DNSSecurityHandler) ListQueries(c *gin.Context) {
	ctx := c.Request.Context()

	type TopDomain struct {
		Domain     string `json:"domain"`
		QueryCount int    `json:"query_count"`
		UniqueIPs  int    `json:"unique_ips"`
		Category   string `json:"category"`
		Reputation string `json:"reputation"`
	}

	if h.tableExists(c, "dns_queries") {
		rows, err := h.pool.Query(ctx, `
			SELECT domain, COUNT(*) AS query_count,
			       COUNT(DISTINCT client_ip) AS unique_ips,
			       COALESCE(MAX(category),'unknown'),
			       COALESCE(MAX(reputation),'unknown')
			FROM dns_queries
			GROUP BY domain
			ORDER BY query_count DESC LIMIT 100`)
		if err == nil {
			defer rows.Close()
			var domains []TopDomain
			for rows.Next() {
				var d TopDomain
				if rows.Scan(&d.Domain, &d.QueryCount, &d.UniqueIPs, &d.Category, &d.Reputation) == nil {
					domains = append(domains, d)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("ListQueries: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
			if domains == nil {
				domains = []TopDomain{}
			}
			c.JSON(http.StatusOK, gin.H{"domains": domains})
			return
		}
	}

	// Derive from events
	var domains []TopDomain
	if h.tableExists(c, "events") {
		// 上と同じ列名の取り違え。上位ドメイン一覧も常に空だった。
		rows, err := h.pool.Query(ctx, `
			SELECT COALESCE(raw_data->>'query', ''),
			       COUNT(*) AS cnt
			FROM events WHERE event_type='dns' AND COALESCE(raw_data->>'query', '') != ''
			GROUP BY 1 ORDER BY cnt DESC LIMIT 100`)
		if err != nil {
			slog.Warn("dns security: 上位ドメインの集計に失敗", "error", err)
		}
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var d TopDomain
				if rows.Scan(&d.Domain, &d.QueryCount) == nil {
					d.UniqueIPs = 1
					d.Category = "unknown"
					d.Reputation = "unknown"
					domains = append(domains, d)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("ListQueries: rows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
		}
	}
	if domains == nil {
		domains = []TopDomain{}
	}
	c.JSON(http.StatusOK, gin.H{"domains": domains})
}

// ListBlocklist returns DNS blocklist entries.
// GET /api/v1/dns/blocklist
func (h *DNSSecurityHandler) ListBlocklist(c *gin.Context) {
	ctx := c.Request.Context()

	type BlocklistEntry struct {
		ID        string `json:"id"`
		Domain    string `json:"domain"`
		Reason    string `json:"reason"`
		AddedBy   string `json:"added_by"`
		CreatedAt string `json:"created_at"`
	}

	if !h.tableExists(c, "dns_blocklist") {
		c.JSON(http.StatusOK, gin.H{"entries": []BlocklistEntry{}})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, domain, COALESCE(reason,''), COALESCE(added_by,'system'), created_at
		FROM dns_blocklist ORDER BY created_at DESC`)
	if err != nil {
		ReadFailure(c, err, gin.H{"entries": []BlocklistEntry{}})
		return
	}
	defer rows.Close()

	var entries []BlocklistEntry
	for rows.Next() {
		var e BlocklistEntry
		var ts time.Time
		if rows.Scan(&e.ID, &e.Domain, &e.Reason, &e.AddedBy, &ts) == nil {
			e.CreatedAt = ts.Format(time.RFC3339)
			entries = append(entries, e)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("ListBlocklist: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
		c.JSON(http.StatusOK, gin.H{"entries": []BlocklistEntry{}})
		return
	}
	if entries == nil {
		entries = []BlocklistEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

// DeleteBlocklistEntry removes a domain from the blocklist.
// DELETE /api/v1/dns/blocklist/:id
func (h *DNSSecurityHandler) DeleteBlocklistEntry(c *gin.Context) {
	id := c.Param("id")
	if h.tableExists(c, "dns_blocklist") {
		if _, err := h.pool.Exec(c.Request.Context(), `DELETE FROM dns_blocklist WHERE id=$1`, id); !WriteOK(c, err) {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "entry removed"})
}

// GetStats returns aggregate DNS security statistics.
// GET /api/v1/dns/stats
// dnsStatQuery — カードの1枚ぶん。
type dnsStatQuery struct {
	key  string
	sql  string
	when bool // そのテーブルが在るときだけ数えます
}

func (h *DNSSecurityHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	stats := gin.H{
		"queries_today":        0,
		"blocked_today":        0,
		"unique_domains":       0,
		"malicious_detected":   0,
		"dga_detected":         0,
		"dns_tunneling_alerts": 0,
	}

	// **数えられなかった 0 を、そのまま画面のカードに出していました。**
	// 「ブロック 0件」「悪性ドメイン 0件」は SOC にとって「見るべきものが
	// 無い」という答えであって、「答えられなかった」ではありません ——
	// `ReadFailure` の説明にある「最も安心できる形をした嘘」の、
	// 1行読み版です。
	//
	// `ReadFailure` は「本当に無い」（テーブル未作成 42P01 / 行なし）
	// だけ従来どおり 0 の並びを返し、それ以外は 500 にします。
	// `COUNT(*)` に行なしはあり得ないので、ここに残るのは本当の失敗です。
	hasQueries := h.tableExists(c, "dns_queries")
	hasAlerts := h.tableExists(c, "dns_alerts")
	for _, q := range []dnsStatQuery{
		{"queries_today", `SELECT COUNT(*) FROM dns_queries WHERE created_at > NOW()-INTERVAL '24h'`, hasQueries},
		{"blocked_today", `SELECT COUNT(*) FROM dns_queries WHERE blocked=true AND created_at > NOW()-INTERVAL '24h'`, hasQueries},
		{"unique_domains", `SELECT COUNT(DISTINCT domain) FROM dns_queries`, hasQueries},
		{"malicious_detected", `SELECT COUNT(*) FROM dns_alerts WHERE threat_type='malicious_domain' AND created_at > NOW()-INTERVAL '24h'`, hasAlerts},
		{"dga_detected", `SELECT COUNT(*) FROM dns_alerts WHERE threat_type='dga' AND created_at > NOW()-INTERVAL '24h'`, hasAlerts},
		{"dns_tunneling_alerts", `SELECT COUNT(*) FROM dns_alerts WHERE threat_type='dns_tunneling' AND created_at > NOW()-INTERVAL '24h'`, hasAlerts},
	} {
		if !q.when {
			continue
		}
		var n int
		if err := h.pool.QueryRow(ctx, q.sql).Scan(&n); err != nil {
			ReadFailure(c, err, stats)
			return
		}
		stats[q.key] = n
	}

	c.JSON(http.StatusOK, stats)
}
