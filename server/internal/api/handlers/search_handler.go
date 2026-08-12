package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SearchHandler provides global cross-entity search.
type SearchHandler struct {
	Pool *pgxpool.Pool
}

func NewSearchHandler(pool *pgxpool.Pool) *SearchHandler {
	return &SearchHandler{Pool: pool}
}

// Search performs a global search across alerts, agents, incidents, IOCs, rules, vulnerabilities,
// software, saved hunts, and playbooks.
// GET /api/v1/search?q=<query>&limit=10
func (h *SearchHandler) Search(c *gin.Context) {
	q := c.Query("q")
	if len(q) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "検索クエリは2文字以上必要です"})
		return
	}
	limit := 8
	ctx := c.Request.Context()
	like := "%" + q + "%"

	type Result struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Title    string `json:"title"`
		Subtitle string `json:"subtitle,omitempty"`
		Severity int    `json:"severity,omitempty"`
		Status   string `json:"status,omitempty"`
	}

	var results []Result

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"results": results, "total": 0})
		return
	}

	// Alerts
	//
	// alerts に agent_hostname / rule_name 列は無い。ホスト名は agents、
	// ルール名は rules から JOIN で引く (store/alerts.go の GetAlert と同じ形)。
	rows, err := h.Pool.Query(ctx, `
		SELECT al.id::text, al.title, COALESCE(ag.hostname,''), al.severity, al.status
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		WHERE al.title ILIKE $1 OR r.name ILIKE $1 OR ag.hostname ILIKE $1
		ORDER BY al.created_at DESC LIMIT $2`, like, limit)
	if err != nil {
		// 検索は他の種別を返せるので中断しない。ただし黙って空を返すと
		// 「アラートが 1 件も引っかからない」だけの症状になり気付けない
		// (この列違いが長く残った理由がまさにそれ)。
		slog.Warn("search: alerts query failed", "error", err)
	}
	if err == nil {
		for rows.Next() {
			var r Result
			r.Type = "alert"
			if err := rows.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Severity, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows.Close()
	}

	// Agents (endpoints)
	rows2, err := h.Pool.Query(ctx, `
		SELECT id::text, hostname,
		       COALESCE(os_type,'') || ' · ' || COALESCE(array_to_string(ip_addresses,', '),''),
		       status
		FROM agents
		WHERE hostname ILIKE $1 OR os_type ILIKE $1 OR os_version ILIKE $1
		   OR EXISTS (SELECT 1 FROM unnest(ip_addresses) ip WHERE ip::text ILIKE $1)
		ORDER BY last_seen DESC NULLS LAST LIMIT $2`, like, limit)
	if err == nil {
		for rows2.Next() {
			var r Result
			r.Type = "agent"
			if err := rows2.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows2.Close()
	}

	// Incidents
	rows3, err := h.Pool.Query(ctx, `
		SELECT id::text, title, COALESCE(description,''), status
		FROM incidents
		WHERE title ILIKE $1 OR description ILIKE $1
		ORDER BY created_at DESC LIMIT $2`, like, limit)
	if err == nil {
		for rows3.Next() {
			var r Result
			r.Type = "incident"
			if err := rows3.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows3.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows3.Close()
	}

	// IOCs
	rows4, err := h.Pool.Query(ctx, `
		SELECT id::text, value, COALESCE(description,''), type
		FROM ioc_entries
		WHERE value ILIKE $1 OR description ILIKE $1
		ORDER BY created_at DESC LIMIT $2`, like, limit)
	if err == nil {
		for rows4.Next() {
			var r Result
			r.Type = "ioc"
			if err := rows4.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows4.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows4.Close()
	}

	// Rules
	rows5, err := h.Pool.Query(ctx, `
		SELECT id::text, name, COALESCE(description,''),
		       CASE WHEN enabled THEN 'enabled' ELSE 'disabled' END
		FROM rules
		WHERE name ILIKE $1 OR description ILIKE $1 OR content ILIKE $1
		ORDER BY updated_at DESC LIMIT $2`, like, limit)
	if err == nil {
		for rows5.Next() {
			var r Result
			r.Type = "rule"
			if err := rows5.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows5.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows5.Close()
	}

	// CVEs / Vulnerabilities
	rows6, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT v.id::text, v.cve_id || ': ' || v.title,
		       COALESCE(a.hostname,'') || ' · ' || v.severity,
		       v.status
		FROM vulnerabilities v
		LEFT JOIN agents a ON a.id = v.agent_id
		WHERE v.cve_id ILIKE $1 OR v.title ILIKE $1 OR v.affected_package ILIKE $1
		ORDER BY v.detected_at DESC LIMIT %d`, limit), like)
	if err == nil {
		for rows6.Next() {
			var r Result
			r.Type = "vulnerability"
			if err := rows6.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows6.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows6.Close()
	}

	// Software inventory
	rows7, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT si.id::text,
		       si.name || COALESCE(' ' || si.version, ''),
		       COALESCE(a.hostname,'') || COALESCE(' · ' || si.vendor, ''),
		       ''
		FROM endpoint_software si
		LEFT JOIN agents a ON a.id = si.agent_id
		WHERE si.name ILIKE $1 OR si.vendor ILIKE $1
		ORDER BY si.reported_at DESC LIMIT %d`, limit), like)
	if err == nil {
		for rows7.Next() {
			var r Result
			r.Type = "software"
			if err := rows7.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows7.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows7.Close()
	}

	// Saved hunts
	rows8, err := h.Pool.Query(ctx, `
		SELECT id::text, name, COALESCE(description,''), ''
		FROM saved_hunts
		WHERE name ILIKE $1 OR description ILIKE $1
		ORDER BY last_run DESC NULLS LAST LIMIT $2`, like, limit)
	if err == nil {
		for rows8.Next() {
			var r Result
			r.Type = "hunt"
			if err := rows8.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows8.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows8.Close()
	}

	// Playbooks
	rows9, err := h.Pool.Query(ctx, `
		SELECT id::text, name, COALESCE(description,''),
		       CASE WHEN is_active THEN 'active' ELSE 'inactive' END
		FROM playbooks
		WHERE name ILIKE $1 OR description ILIKE $1
		ORDER BY updated_at DESC LIMIT $2`, like, limit)
	if err == nil {
		for rows9.Next() {
			var r Result
			r.Type = "playbook"
			if err := rows9.Scan(&r.ID, &r.Title, &r.Subtitle, &r.Status); err == nil {
				results = append(results, r)
			}
		}
		if err := rows9.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows9.Close()
	}

	if results == nil {
		results = []Result{}
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "total": len(results)})
}
