package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UEBAHandler provides User & Entity Behavior Analytics endpoints.
type UEBAHandler struct {
	Pool *pgxpool.Pool
}

func NewUEBAHandler(pool *pgxpool.Pool) *UEBAHandler {
	return &UEBAHandler{Pool: pool}
}

// Summary returns UEBA anomaly signals.
// GET /api/v1/ueba/summary?hours=168
func (h *UEBAHandler) Summary(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "168"))
	if hours < 1 || hours > 720 {
		hours = 168
	}
	ctx := c.Request.Context()

	type UserAnomaly struct {
		Username     string   `json:"username"`
		TotalLogins  int      `json:"total_logins"`
		FailedLogins int      `json:"failed_logins"`
		FailRate     float64  `json:"fail_rate"`
		UniqueHosts  int      `json:"unique_hosts"`
		RiskScore    int      `json:"risk_score"`
		Signals      []string `json:"signals"`
	}

	type EntityAnomaly struct {
		AgentID    string   `json:"agent_id"`
		Hostname   string   `json:"hostname"`
		AlertCount int      `json:"alert_count"`
		AuthFails  int      `json:"auth_fails"`
		NewProcs   int      `json:"new_procs"`
		NetConns   int      `json:"net_conns"`
		RiskScore  int      `json:"risk_score"`
		Signals    []string `json:"signals"`
	}

	type RareProcess struct {
		Image     string `json:"image"`
		Count     int    `json:"count"`
		AgentID   string `json:"agent_id"`
		Hostname  string `json:"hostname"`
		FirstSeen string `json:"first_seen"`
	}

	type NewHost struct {
		AgentID   string `json:"agent_id"`
		Hostname  string `json:"hostname"`
		OS        string `json:"os"`
		FirstSeen string `json:"first_seen"`
	}

	var userAnomalies []UserAnomaly
	var entityAnomalies []EntityAnomaly
	var rareProcesses []RareProcess
	var newHosts []NewHost

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{
			"user_anomalies":   []UserAnomaly{},
			"entity_anomalies": []EntityAnomaly{},
			"rare_processes":   []RareProcess{},
			"new_hosts":        []NewHost{},
			"summary":          gin.H{"high_risk_users": 0, "high_risk_entities": 0},
		})
		return
	}

	// ── User anomalies from auth events ───────────────────
	rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT
			COALESCE(raw_data->>'username','unknown') AS username,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE raw_data->>'success'='false') AS fails,
			COUNT(DISTINCT agent_id) AS unique_hosts
		FROM events
		WHERE event_type = 'auth'
		  AND "time" >= NOW() - INTERVAL '%d hours'
		GROUP BY 1
		HAVING COUNT(*) >= 2
		ORDER BY fails DESC, total DESC
		LIMIT 20`, hours))
	if err == nil {
		for rows.Next() {
			var u UserAnomaly
			if err := rows.Scan(&u.Username, &u.TotalLogins, &u.FailedLogins, &u.UniqueHosts); err != nil {
				continue
			}

			if u.TotalLogins > 0 {
				u.FailRate = float64(u.FailedLogins) / float64(u.TotalLogins) * 100
			}

			// Calculate risk score & signals
			score := 0
			var signals []string

			if u.FailedLogins > 50 {
				score += 40
				signals = append(signals, fmt.Sprintf("大量認証失敗 (%d回)", u.FailedLogins))
			}
			if u.FailedLogins > 10 {
				score += 20
			}
			if u.FailRate > 80 {
				score += 30
				signals = append(signals, "認証失敗率 >80%")
			}
			if u.UniqueHosts > 5 {
				score += 20
				signals = append(signals, fmt.Sprintf("多数ホストへのアクセス (%d台)", u.UniqueHosts))
			}
			if u.UniqueHosts > 10 {
				score += 20
				signals = append(signals, "横移動の可能性")
			}
			if u.Username == "administrator" || u.Username == "root" || u.Username == "admin" {
				score += 10
				signals = append(signals, "特権アカウントの使用")
			}

			u.RiskScore = min100(score)
			if len(signals) == 0 {
				signals = []string{}
			}
			u.Signals = signals

			if u.RiskScore > 0 || u.FailedLogins > 5 {
				userAnomalies = append(userAnomalies, u)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows.Close()
	}

	// ── Entity (agent) anomalies ──────────────────────────
	rows2, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT
			a.id::text, a.hostname,
			COALESCE(al.cnt,0) AS alert_cnt,
			COALESCE(auth.fail_cnt,0) AS auth_fails,
			COALESCE(proc.proc_cnt,0) AS proc_cnt,
			COALESCE(net.net_cnt,0) AS net_cnt
		FROM agents a
		LEFT JOIN (
			SELECT agent_id, COUNT(*) AS cnt FROM alerts
			WHERE created_at >= NOW()-INTERVAL '%d hours' AND status NOT IN ('resolved','false_positive')
			GROUP BY 1
		) al ON al.agent_id::text = a.id::text
		LEFT JOIN (
			SELECT agent_id, COUNT(*) AS fail_cnt FROM events
			WHERE event_type='auth' AND raw_data->>'success'='false'
			  AND "time" >= NOW()-INTERVAL '%d hours'
			GROUP BY 1
		) auth ON auth.agent_id::text = a.id::text
		LEFT JOIN (
			SELECT agent_id, COUNT(DISTINCT raw_data->>'image_path') AS proc_cnt FROM events
			WHERE event_type='process'
			  AND "time" >= NOW()-INTERVAL '%d hours'
			GROUP BY 1
		) proc ON proc.agent_id::text = a.id::text
		LEFT JOIN (
			SELECT agent_id, COUNT(*) AS net_cnt FROM events
			WHERE event_type='network'
			  AND "time" >= NOW()-INTERVAL '%d hours'
			GROUP BY 1
		) net ON net.agent_id::text = a.id::text
		WHERE a.status NOT IN ('offline', 'inactive')
		ORDER BY al.cnt DESC NULLS LAST, auth.fail_cnt DESC NULLS LAST
		LIMIT 20`, hours, hours, hours, hours))
	if err == nil {
		for rows2.Next() {
			var e EntityAnomaly
			if err := rows2.Scan(&e.AgentID, &e.Hostname, &e.AlertCount, &e.AuthFails, &e.NewProcs, &e.NetConns); err != nil {
				continue
			}

			score := 0
			var signals []string

			if e.AlertCount > 20 {
				score += 40
				signals = append(signals, fmt.Sprintf("大量アラート (%d件)", e.AlertCount))
			}
			if e.AlertCount > 5 {
				score += 20
			}
			if e.AuthFails > 30 {
				score += 30
				signals = append(signals, fmt.Sprintf("認証失敗多発 (%d回)", e.AuthFails))
			}
			if e.AuthFails > 10 {
				score += 10
			}
			if e.NetConns > 1000 {
				score += 20
				signals = append(signals, "異常な外部接続数")
			}
			if e.NewProcs > 200 {
				score += 10
				signals = append(signals, "多数の異なるプロセス実行")
			}

			e.RiskScore = min100(score)
			if len(signals) == 0 {
				signals = []string{}
			}
			e.Signals = signals

			if e.RiskScore > 0 {
				entityAnomalies = append(entityAnomalies, e)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows2.Close()
	}

	// ── Rare processes (seen on few hosts) ────────────────
	rows3, err := h.Pool.Query(ctx, fmt.Sprintf(`
		WITH proc_counts AS (
			SELECT
				raw_data->>'image_path' AS image,
				COUNT(DISTINCT agent_id) AS host_count,
				MIN("time")::text AS first_seen,
				-- uuid には max 集約が無い (function max(uuid) does not exist)。
				-- 代表として 1 台選べればよいので text にしてから取る。
				MAX(agent_id::text) AS sample_agent
			FROM events
			WHERE event_type = 'process'
			  AND raw_data->>'image_path' IS NOT NULL
			  AND raw_data->>'image_path' != ''
			  AND "time" >= NOW() - INTERVAL '%d hours'
			GROUP BY 1
		)
		SELECT p.image, p.host_count, p.sample_agent, COALESCE(a.hostname, p.sample_agent), p.first_seen
		FROM proc_counts p
		LEFT JOIN agents a ON a.id::text = p.sample_agent
		WHERE p.host_count = 1
		  AND p.image NOT LIKE '%%:\\Windows\\System32%%'
		  AND p.image NOT LIKE '%%:\\Program Files%%'
		  AND p.image NOT LIKE '/usr/bin/%%'
		  AND p.image NOT LIKE '/usr/sbin/%%'
		ORDER BY p.first_seen DESC
		LIMIT 15`, hours))
	if err == nil {
		for rows3.Next() {
			var r RareProcess
			if err := rows3.Scan(&r.Image, &r.Count, &r.AgentID, &r.Hostname, &r.FirstSeen); err == nil {
				rareProcesses = append(rareProcesses, r)
			}
		}
		if err := rows3.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows3.Close()
	}

	// ── New hosts (enrolled recently) ─────────────────────
	rows4, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT id::text, hostname, COALESCE(os_type,''), enrolled_at::text
		FROM agents
		WHERE enrolled_at >= NOW() - INTERVAL '%d hours'
		ORDER BY enrolled_at DESC LIMIT 10`, hours))
	if err == nil {
		for rows4.Next() {
			var h NewHost
			if err := rows4.Scan(&h.AgentID, &h.Hostname, &h.OS, &h.FirstSeen); err == nil {
				newHosts = append(newHosts, h)
			}
		}
		if err := rows4.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows4.Close()
	}

	if userAnomalies == nil {
		userAnomalies = []UserAnomaly{}
	}
	if entityAnomalies == nil {
		entityAnomalies = []EntityAnomaly{}
	}
	if rareProcesses == nil {
		rareProcesses = []RareProcess{}
	}
	if newHosts == nil {
		newHosts = []NewHost{}
	}

	highRiskUsers := 0
	highRiskEntities := 0
	for _, u := range userAnomalies {
		if u.RiskScore >= 50 {
			highRiskUsers++
		}
	}
	for _, e := range entityAnomalies {
		if e.RiskScore >= 50 {
			highRiskEntities++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"user_anomalies":   userAnomalies,
		"entity_anomalies": entityAnomalies,
		"rare_processes":   rareProcesses,
		"new_hosts":        newHosts,
		"summary": gin.H{
			"high_risk_users":    highRiskUsers,
			"high_risk_entities": highRiskEntities,
			"rare_process_count": len(rareProcesses),
			"new_host_count":     len(newHosts),
		},
	})
}

func min100(v int) int {
	if v > 100 {
		return 100
	}
	if v < 0 {
		return 0
	}
	return v
}
