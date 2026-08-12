package handlers

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AlertClassifierHandler provides rule-based MITRE ATT&CK tactic classification.
type AlertClassifierHandler struct {
	pool *pgxpool.Pool
}

// NewAlertClassifierHandler creates a new AlertClassifierHandler.
func NewAlertClassifierHandler(pool *pgxpool.Pool) *AlertClassifierHandler {
	return &AlertClassifierHandler{pool: pool}
}

// tacticsMap maps MITRE ATT&CK tactic IDs to keyword triggers.
var tacticsMap = map[string][]string{
	"TA0001": {"phishing", "spearphish", "attachment", "macro"},
	"TA0002": {"powershell", "cmd.exe", "wscript", "cscript", "mshta", "shellcode"},
	"TA0003": {"registry", "startup", "scheduled task", "autorun", "persistence"},
	"TA0004": {"mimikatz", "privilege", "escalat", "bypass uac", "admin"},
	"TA0005": {"obfuscat", "encode", "base64", "packed", "inject"},
	"TA0006": {"credential", "password", "lsass", "hash dump", "kerberos"},
	"TA0007": {"net user", "whoami", "ipconfig", "systeminfo", "discovery"},
	"TA0008": {"lateral", "psexec", "wmi", "rdp", "smb"},
	"TA0009": {"exfil", "compress", "archive", "zip", "encrypt"},
	"TA0011": {"beacon", "cobalt", "c2", "command and control", "dns tunnel"},
	"TA0040": {"ransomware", "wiper", "destruct", "encrypt files"},
}

// detectTactics checks text against tacticsMap and returns matched tactic IDs.
func detectTactics(text string) []string {
	lower := strings.ToLower(text)
	seen := make(map[string]bool)
	var tactics []string
	for tactic, keywords := range tacticsMap {
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				if !seen[tactic] {
					seen[tactic] = true
					tactics = append(tactics, tactic)
				}
				break
			}
		}
	}
	return tactics
}

// ClassifyAlert handles POST /api/v1/alerts/:id/classify.
// It classifies a single alert by its title and description using MITRE ATT&CK rules.
func (h *AlertClassifierHandler) ClassifyAlert(c *gin.Context) {
	alertID := c.Param("id")
	ctx := c.Request.Context()

	// Check if alerts table exists.
	var tableExists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'alerts'
		)`,
	).Scan(&tableExists)
	if !tableExists {
		c.JSON(http.StatusOK, gin.H{
			"alert_id":         alertID,
			"detected_tactics": []string{},
			"updated":          false,
		})
		return
	}

	// Fetch alert title + description.
	var title, description string
	err := h.pool.QueryRow(ctx,
		`SELECT COALESCE(title,''), COALESCE(description,'') FROM alerts WHERE id::text = $1`,
		alertID,
	).Scan(&title, &description)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}

	tactics := detectTactics(title + " " + description)

	// Update mitre_technique with the primary detected tactic.
	updated := false
	if len(tactics) > 0 {
		_, updateErr := h.pool.Exec(ctx,
			`UPDATE alerts SET mitre_technique = $1 WHERE id::text = $2 AND (mitre_technique IS NULL OR mitre_technique = '')`,
			tactics[0], // 最初に検出されたタクティクスをプライマリとして設定
			alertID,
		)
		if updateErr == nil {
			updated = true
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"alert_id":         alertID,
		"detected_tactics": tactics,
		"updated":          updated,
	})
}

// BulkClassify handles POST /api/v1/alerts/classify-batch.
// Body: {"limit": 100} — classifies up to N untagged alerts.
func (h *AlertClassifierHandler) BulkClassify(c *gin.Context) {
	var req struct {
		Limit int `json:"limit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}

	ctx := c.Request.Context()

	// Check if alerts table exists.
	var tableExists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'alerts'
		)`,
	).Scan(&tableExists)
	if !tableExists {
		c.JSON(http.StatusOK, gin.H{"processed": 0, "classified": 0, "skipped": 0})
		return
	}

	// Query for alerts where mitre_technique is not yet set.
	query := `SELECT id::text, COALESCE(title,''), COALESCE(description,'')
	          FROM alerts
	          WHERE mitre_technique IS NULL OR mitre_technique = ''
	          LIMIT $1`

	rows, err := h.pool.Query(ctx, query, req.Limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query alerts"})
		return
	}
	defer rows.Close()

	type alertRow struct {
		id          string
		title       string
		description string
	}
	var alerts []alertRow
	for rows.Next() {
		var a alertRow
		if scanErr := rows.Scan(&a.id, &a.title, &a.description); scanErr == nil {
			alerts = append(alerts, a)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	rows.Close()

	processed := len(alerts)
	classified := 0
	skipped := 0

	for _, a := range alerts {
		tactics := detectTactics(a.title + " " + a.description)
		if len(tactics) == 0 {
			skipped++
			continue
		}
		_, updateErr := h.pool.Exec(ctx,
			`UPDATE alerts SET mitre_technique = $1 WHERE id::text = $2 AND (mitre_technique IS NULL OR mitre_technique = '')`,
			tactics[0],
			a.id,
		)
		if updateErr == nil {
			classified++
		} else {
			skipped++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"processed":  processed,
		"classified": classified,
		"skipped":    skipped,
	})
}
