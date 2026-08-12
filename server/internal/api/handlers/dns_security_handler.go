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
	var ok bool
	_ = h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, name).Scan(&ok)
	return ok
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
			if alerts == nil {
				alerts = []DNSAlert{}
			}
			c.JSON(http.StatusOK, gin.H{"alerts": alerts})
			return
		}
	}

	// Fall back: derive from generic events table.
	var alerts []DNSAlert
	if h.tableExists(c, "events") {
		// events の実際の列は event_id / agent_id / event_type / time / raw_data
		// (migration 002)。id / type / created_at / event_data / data / metadata は
		// いずれも存在せず、このクエリは毎回失敗していた。err は下で握りつぶされる
		// ため、DNS セキュリティ画面は常に「アラート 0 件」に見えていた。
		rows, err := h.pool.Query(ctx, `
			SELECT event_id::text, COALESCE(raw_data->>'domain', ''),
			       COALESCE(raw_data->>'query_type', 'A'),
			       COALESCE(raw_data->>'src_ip', ''),
			       agent_id::text, time
			FROM events
			WHERE event_type='dns' AND raw_data->>'malicious' = 'true'
			ORDER BY time DESC LIMIT 200`)
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
			SELECT COALESCE(raw_data->>'domain', ''),
			       COUNT(*) AS cnt
			FROM events WHERE event_type='dns' AND COALESCE(raw_data->>'domain', '') != ''
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
		c.JSON(http.StatusOK, gin.H{"entries": []BlocklistEntry{}})
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
		_, _ = h.pool.Exec(c.Request.Context(), `DELETE FROM dns_blocklist WHERE id=$1`, id)
	}
	c.JSON(http.StatusOK, gin.H{"message": "entry removed"})
}

// GetStats returns aggregate DNS security statistics.
// GET /api/v1/dns/stats
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

	if h.tableExists(c, "dns_queries") {
		var total, blocked int
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dns_queries WHERE created_at > NOW()-INTERVAL '24h'`).Scan(&total)
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dns_queries WHERE blocked=true AND created_at > NOW()-INTERVAL '24h'`).Scan(&blocked)
		var unique int
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(DISTINCT domain) FROM dns_queries`).Scan(&unique)
		stats["queries_today"] = total
		stats["blocked_today"] = blocked
		stats["unique_domains"] = unique
	}

	if h.tableExists(c, "dns_alerts") {
		var malicious, dga, tunneling int
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dns_alerts WHERE threat_type='malicious_domain' AND created_at > NOW()-INTERVAL '24h'`).Scan(&malicious)
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dns_alerts WHERE threat_type='dga' AND created_at > NOW()-INTERVAL '24h'`).Scan(&dga)
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dns_alerts WHERE threat_type='dns_tunneling' AND created_at > NOW()-INTERVAL '24h'`).Scan(&tunneling)
		stats["malicious_detected"] = malicious
		stats["dga_detected"] = dga
		stats["dns_tunneling_alerts"] = tunneling
	}

	c.JSON(http.StatusOK, stats)
}
