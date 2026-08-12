package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	edrsync "github.com/edr-platform/server/internal/sync"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IngestHandler receives alerts from external agents (Wazuh, etc.).
type IngestHandler struct {
	Pool        *pgxpool.Pool
	IngestToken string // shared secret for webhook auth
}

func NewIngestHandler(pool *pgxpool.Pool, token string) *IngestHandler {
	return &IngestHandler{Pool: pool, IngestToken: token}
}

// WazuhAlert receives a Wazuh custom-integration alert.
// POST /api/v1/ingest/wazuh?token=<token>
func (h *IngestHandler) WazuhAlert(c *gin.Context) {
	// Token validation
	token := c.Query("token")
	if h.IngestToken != "" && token != h.IngestToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	var payload edrsync.WazuhAlertPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	ctx := c.Request.Context()

	// The webhook payload has no OS field, so derive one from the alert's
	// indirect signals; "unknown" when they say nothing.
	osType := edrsync.OSTypeFromAlert(&payload)

	// Ensure agent exists
	agentID, err := h.upsertAgent(ctx, payload.Agent.Name, payload.Agent.IP, osType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "agent upsert failed"})
		return
	}

	// Map severity
	severity := edrsync.WazuhLevelToSeverity(payload.Rule.Level)

	// MITRE fields
	var tactic, technique string
	if len(payload.Rule.MITRE.Tactic) > 0 {
		tactic = payload.Rule.MITRE.Tactic[0]
	}
	if len(payload.Rule.MITRE.Technique) > 0 {
		technique = payload.Rule.MITRE.Technique[0]
	}

	// Raw data as JSONB
	rawJSON, _ := json.Marshal(payload)

	// Parse timestamp
	ts := time.Now()
	if payload.Timestamp != "" {
		if t, err := time.Parse("2006-01-02T15:04:05.000-0700", payload.Timestamp); err == nil {
			ts = t
		} else if t, err := time.Parse(time.RFC3339, payload.Timestamp); err == nil {
			ts = t
		}
	}

	// Insert alert
	//
	// alerts に agent_hostname / agent_os / rule_name / mitre_tactic /
	// raw_data という列は無い。以前はこの 5 つに書こうとしていたため
	// INSERT が毎回 `column "agent_hostname" of relation "alerts" does not
	// exist` で落ち、**Wazuh 連携の POST は常に 500 だった**。
	//
	// 対応付け:
	//   agent_hostname / agent_os  agents 側が持つ (直前の upsertAgent)。
	//                              表示は agent_id の JOIN で引く。
	//   rule_name                  列が無いので description に残す。
	//                              捨てると Wazuh のどのルールが鳴ったのか
	//                              追えなくなる。
	//   mitre_tactic               列が無い。タクティクはテクニックから
	//                              引けるので raw_event の payload に残す。
	//   raw_data                   実在の列は raw_event (text)。
	description := "Wazuh Rule " + payload.Rule.ID
	if tactic != "" {
		description += " (" + tactic + ")"
	}

	var alertID string
	err = h.Pool.QueryRow(ctx, `
		INSERT INTO alerts (
			agent_id, title, description, severity, status,
			mitre_technique, raw_event, source, created_at, updated_at
		) VALUES (
			$1::uuid, $2, $3, $4, 'open',
			$5, $6, 'wazuh', $7, $7
		) RETURNING id::text`,
		agentID,
		payload.Rule.Description,
		description,
		severity,
		technique,
		string(rawJSON), ts,
	).Scan(&alertID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"alert_id": alertID, "severity": severity})
}

// upsertAgent ensures an agent record exists, returns its UUID.
//
// osType must be one of the canonical values (windows/linux/darwin/unknown) —
// anything else violates agents_os_type_check and drops the alert. Pass the
// result of edrsync.OSTypeFromAlert. When the row already exists, an
// "unknown" os_type is upgraded in place once a later alert reveals the real
// OS; a known os_type is never overwritten (in particular never downgraded
// back to "unknown").
func (h *IngestHandler) upsertAgent(ctx context.Context, hostname, ip, osType string) (string, error) {
	if osType == "" {
		osType = edrsync.OSTypeUnknown
	}

	var id string
	// Try existing
	_ = h.Pool.QueryRow(ctx,
		`SELECT id::text FROM agents WHERE hostname = $1 LIMIT 1`, hostname).Scan(&id)
	if id != "" {
		// update last_seen, status and (if still unknown) os_type.
		// 'isolated' is a containment state, not a liveness state — a host
		// under network isolation is *expected* to keep reporting. Clobbering
		// it with 'online' would silently lift the quarantine on the first
		// inbound Wazuh alert. Same guard as store.AgentStore.UpdateLastSeen.
		_, _ = h.Pool.Exec(ctx, `
			UPDATE agents
			   SET last_seen  = NOW(),
			       status     = CASE WHEN status = 'isolated'
			                         THEN 'isolated' ELSE 'online' END,
			       os_type    = CASE WHEN os_type = 'unknown' AND $2 <> 'unknown'
			                         THEN $2 ELSE os_type END,
			       updated_at = NOW()
			 WHERE hostname = $1`, hostname, osType)
		return id, nil
	}

	// Insert new — sanitize the IP so a missing/CIDR/"any" address cannot fail
	// the inet cast and take the whole alert down with it.
	ipVal := edrsync.SanitizeIP(ip)

	err := h.Pool.QueryRow(ctx, `
		INSERT INTO agents (hostname, ip_addresses, os_type, status, last_seen, source)
		VALUES ($1, ARRAY[$2::inet], $3, 'online', NOW(), 'wazuh')
		RETURNING id::text`, hostname, ipVal, osType).Scan(&id)
	return id, err
}

// WazuhStatus returns ingest statistics.
// GET /api/v1/ingest/wazuh/status
func (h *IngestHandler) WazuhStatus(c *gin.Context) {
	ctx := c.Request.Context()
	var total, last24h, wazuhAgents int
	if h.Pool != nil {
		_ = h.Pool.QueryRow(ctx,
			`SELECT COUNT(*), COUNT(*) FILTER (WHERE created_at >= NOW()-INTERVAL '24 hours')
			 FROM alerts WHERE source = 'wazuh'`).Scan(&total, &last24h)
		_ = h.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM agents WHERE source = 'wazuh'`).Scan(&wazuhAgents)
	}
	c.JSON(http.StatusOK, gin.H{
		"total_alerts": total,
		"alerts_24h":   last24h,
		"wazuh_agents": wazuhAgents,
		"token_set":    h.IngestToken != "",
	})
}
