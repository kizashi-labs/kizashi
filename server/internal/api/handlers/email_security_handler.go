package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EmailSecurityHandler provides email security integration endpoints.
type EmailSecurityHandler struct {
	pool *pgxpool.Pool
}

// NewEmailSecurityHandler creates a new EmailSecurityHandler.
func NewEmailSecurityHandler(pool *pgxpool.Pool) *EmailSecurityHandler {
	return &EmailSecurityHandler{pool: pool}
}

func (h *EmailSecurityHandler) tableExists(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='email_security_events')`).Scan(&exists)
	return exists
}

// ListEvents — GET /email/events
func (h *EmailSecurityHandler) ListEvents(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"events": []interface{}{}, "total": 0})
		return
	}

	ctx := c.Request.Context()

	verdictFilter := c.Query("verdict")
	threatFilter := c.Query("threat_type")
	senderFilter := c.Query("sender")
	fromDate := c.Query("from")
	toDate := c.Query("to")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	query := `SELECT id, message_id, sender, recipients, subject, threat_type, verdict,
		confidence_score, attachments, urls, action_taken, received_at, analyzed_at
		FROM email_security_events WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if verdictFilter != "" {
		query += " AND verdict = $" + strconv.Itoa(argIdx)
		args = append(args, verdictFilter)
		argIdx++
	}
	if threatFilter != "" {
		query += " AND threat_type = $" + strconv.Itoa(argIdx)
		args = append(args, threatFilter)
		argIdx++
	}
	if senderFilter != "" {
		query += " AND sender ILIKE $" + strconv.Itoa(argIdx)
		args = append(args, "%"+senderFilter+"%")
		argIdx++
	}
	if fromDate != "" {
		query += " AND received_at >= $" + strconv.Itoa(argIdx)
		args = append(args, fromDate)
		argIdx++
	}
	if toDate != "" {
		query += " AND received_at <= $" + strconv.Itoa(argIdx)
		args = append(args, toDate)
		argIdx++
	}

	query += " ORDER BY received_at DESC LIMIT $" + strconv.Itoa(argIdx) + " OFFSET $" + strconv.Itoa(argIdx+1)
	args = append(args, pageSize, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type EmailEvent struct {
		ID              string          `json:"id"`
		MessageID       string          `json:"message_id"`
		Sender          string          `json:"sender"`
		Recipients      json.RawMessage `json:"recipients"`
		Subject         string          `json:"subject"`
		ThreatType      string          `json:"threat_type"`
		Verdict         string          `json:"verdict"`
		ConfidenceScore int             `json:"confidence_score"`
		Attachments     json.RawMessage `json:"attachments"`
		URLs            json.RawMessage `json:"urls"`
		ActionTaken     string          `json:"action_taken"`
		ReceivedAt      string          `json:"received_at"`
		AnalyzedAt      string          `json:"analyzed_at"`
	}

	var events []EmailEvent
	for rows.Next() {
		var e EmailEvent
		var receivedAt, analyzedAt time.Time
		if err := rows.Scan(
			&e.ID, &e.MessageID, &e.Sender, &e.Recipients, &e.Subject,
			&e.ThreatType, &e.Verdict, &e.ConfidenceScore, &e.Attachments, &e.URLs,
			&e.ActionTaken, &receivedAt, &analyzedAt,
		); err != nil {
			continue
		}
		e.ReceivedAt = receivedAt.Format(time.RFC3339)
		e.AnalyzedAt = analyzedAt.Format(time.RFC3339)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	if events == nil {
		events = []EmailEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": len(events), "page": page, "page_size": pageSize})
}

// GetEvent — GET /email/events/:id
func (h *EmailSecurityHandler) GetEvent(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "table not found"})
		return
	}

	ctx := c.Request.Context()
	id := c.Param("id")

	row := h.pool.QueryRow(ctx, `
		SELECT id, message_id, sender, recipients, subject, threat_type, verdict,
		confidence_score, attachments, urls, action_taken, received_at, analyzed_at
		FROM email_security_events WHERE id = $1`, id)

	var e struct {
		ID              string          `json:"id"`
		MessageID       string          `json:"message_id"`
		Sender          string          `json:"sender"`
		Recipients      json.RawMessage `json:"recipients"`
		Subject         string          `json:"subject"`
		ThreatType      string          `json:"threat_type"`
		Verdict         string          `json:"verdict"`
		ConfidenceScore int             `json:"confidence_score"`
		Attachments     json.RawMessage `json:"attachments"`
		URLs            json.RawMessage `json:"urls"`
		ActionTaken     string          `json:"action_taken"`
		ReceivedAt      string          `json:"received_at"`
		AnalyzedAt      string          `json:"analyzed_at"`
	}

	var receivedAt, analyzedAt time.Time
	if err := row.Scan(
		&e.ID, &e.MessageID, &e.Sender, &e.Recipients, &e.Subject,
		&e.ThreatType, &e.Verdict, &e.ConfidenceScore, &e.Attachments, &e.URLs,
		&e.ActionTaken, &receivedAt, &analyzedAt,
	); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}
	e.ReceivedAt = receivedAt.Format(time.RFC3339)
	e.AnalyzedAt = analyzedAt.Format(time.RFC3339)

	c.JSON(http.StatusOK, e)
}

// AnalyzeEmail — POST /email/analyze
func (h *EmailSecurityHandler) AnalyzeEmail(c *gin.Context) {
	var body struct {
		Sender      string `json:"sender"`
		Subject     string `json:"subject"`
		BodyText    string `json:"body_text"`
		Attachments []struct {
			Name string `json:"name"`
			Hash string `json:"hash"`
		} `json:"attachments"`
		URLs []string `json:"urls"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	verdict := "clean"
	threatType := "none"
	confidenceScore := 0
	var threatIndicators []string

	// Check sender domain against known phishing patterns
	phishingDomains := []string{"paypa1.com", "arnazon.com", "g00gle.com", "micros0ft.com", "secure-login", "account-verify"}
	senderLower := strings.ToLower(body.Sender)
	for _, domain := range phishingDomains {
		if strings.Contains(senderLower, domain) {
			verdict = "phishing"
			threatType = "phishing"
			confidenceScore += 80
			threatIndicators = append(threatIndicators, "フィッシングドメインが検出されました: "+domain)
			break
		}
	}

	// Check URLs for suspicious TLDs
	suspiciousTLDs := []string{".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".download"}
	for _, url := range body.URLs {
		urlLower := strings.ToLower(url)
		for _, tld := range suspiciousTLDs {
			if strings.Contains(urlLower, tld) {
				if verdict == "clean" {
					verdict = "spam"
					threatType = "suspicious_url"
				}
				confidenceScore += 40
				threatIndicators = append(threatIndicators, "不審なTLDを含むURLが検出されました: "+url)
				break
			}
		}
		// Check for IP-based URLs
		if strings.Contains(urlLower, "http://") && strings.Contains(urlLower[7:], "/") {
			// simple heuristic: direct IP URLs
		}
	}

	// Check attachment extensions
	maliciousExtensions := []string{".exe", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".scr", ".jar", ".msi", ".hta"}
	for _, att := range body.Attachments {
		attLower := strings.ToLower(att.Name)
		for _, ext := range maliciousExtensions {
			if strings.HasSuffix(attLower, ext) {
				verdict = "malware"
				threatType = "malicious_attachment"
				confidenceScore += 90
				threatIndicators = append(threatIndicators, "不審な添付ファイルが検出されました: "+att.Name)
				break
			}
		}
	}

	// Cap confidence score
	if confidenceScore > 100 {
		confidenceScore = 100
	}

	if threatIndicators == nil {
		threatIndicators = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"verdict":           verdict,
		"threat_type":       threatType,
		"confidence_score":  confidenceScore,
		"threat_indicators": threatIndicators,
		"analyzed_at":       time.Now().Format(time.RFC3339),
	})
}

// IngestEvent — POST /email/ingest
func (h *EmailSecurityHandler) IngestEvent(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "email security tables not initialized"})
		return
	}

	var events []struct {
		MessageID       string          `json:"message_id" binding:"required"`
		Sender          string          `json:"sender" binding:"required"`
		Recipients      json.RawMessage `json:"recipients"`
		Subject         string          `json:"subject"`
		ThreatType      string          `json:"threat_type"`
		Verdict         string          `json:"verdict"`
		ConfidenceScore int             `json:"confidence_score"`
		Attachments     json.RawMessage `json:"attachments"`
		URLs            json.RawMessage `json:"urls"`
		ActionTaken     string          `json:"action_taken"`
		ReceivedAt      *string         `json:"received_at"`
	}

	if err := c.ShouldBindJSON(&events); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	inserted := 0

	for _, e := range events {
		if e.ThreatType == "" {
			e.ThreatType = "none"
		}
		if e.Verdict == "" {
			e.Verdict = "clean"
		}
		if e.ActionTaken == "" {
			e.ActionTaken = "delivered"
		}
		if e.Recipients == nil {
			e.Recipients = json.RawMessage("[]")
		}
		if e.Attachments == nil {
			e.Attachments = json.RawMessage("[]")
		}
		if e.URLs == nil {
			e.URLs = json.RawMessage("[]")
		}

		var receivedAt interface{}
		if e.ReceivedAt != nil {
			receivedAt = *e.ReceivedAt
		} else {
			receivedAt = time.Now()
		}

		_, err := h.pool.Exec(ctx, `
			INSERT INTO email_security_events
			(message_id, sender, recipients, subject, threat_type, verdict, confidence_score,
			 attachments, urls, action_taken, received_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			e.MessageID, e.Sender, e.Recipients, e.Subject, e.ThreatType, e.Verdict,
			e.ConfidenceScore, e.Attachments, e.URLs, e.ActionTaken, receivedAt,
		)
		if err == nil {
			inserted++
		}
	}

	c.JSON(http.StatusOK, gin.H{"inserted": inserted, "total": len(events)})
}

// GetFrontendStats — GET /email/stats (フロントエンド向け形式)
func (h *EmailSecurityHandler) GetFrontendStats(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"analyzed_today": 0, "threats_blocked": 0,
			"phishing_attempts": 0, "malware_attachments": 0,
		})
		return
	}
	ctx := c.Request.Context()
	var analyzed, blocked, phishing, malware int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_security_events WHERE DATE(received_at)=CURRENT_DATE`).Scan(&analyzed)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_security_events WHERE verdict IN ('malicious','suspicious') AND DATE(received_at)=CURRENT_DATE`).Scan(&blocked)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_security_events WHERE threat_type='phishing' AND DATE(received_at)=CURRENT_DATE`).Scan(&phishing)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_security_events WHERE threat_type='malware' AND DATE(received_at)=CURRENT_DATE`).Scan(&malware)
	c.JSON(http.StatusOK, gin.H{
		"analyzed_today":      analyzed,
		"threats_blocked":     blocked,
		"phishing_attempts":   phishing,
		"malware_attachments": malware,
	})
}

// ListThreats — GET /email/threats
func (h *EmailSecurityHandler) ListThreats(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"emails": []interface{}{}})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT id::text, received_at, sender, subject, threat_type,
		       confidence_score, action_taken,
		       COALESCE(attachments::text, '[]'), COALESCE(urls::text, '[]')
		FROM email_security_events
		ORDER BY received_at DESC LIMIT 100
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"emails": []interface{}{}})
		return
	}
	defer rows.Close()

	type ThreatEmail struct {
		ID          string          `json:"id"`
		Timestamp   string          `json:"timestamp"`
		Sender      string          `json:"sender"`
		Subject     string          `json:"subject"`
		ThreatType  string          `json:"threat_type"`
		RiskScore   int             `json:"risk_score"`
		Action      string          `json:"action"`
		SPF         bool            `json:"spf"`
		DKIM        bool            `json:"dkim"`
		DMARC       bool            `json:"dmarc"`
		BodyPreview string          `json:"body_preview"`
		Attachments json.RawMessage `json:"attachments"`
		URLs        json.RawMessage `json:"urls"`
	}

	var emails []ThreatEmail
	for rows.Next() {
		var e ThreatEmail
		var ts time.Time
		var attachments, urls string
		if err := rows.Scan(&e.ID, &ts, &e.Sender, &e.Subject, &e.ThreatType,
			&e.RiskScore, &e.Action, &attachments, &urls); err != nil {
			continue
		}
		e.Timestamp = ts.Format(time.RFC3339)
		e.Action = mapAction(e.Action)
		e.Attachments = json.RawMessage(attachments)
		e.URLs = json.RawMessage(urls)
		emails = append(emails, e)
	}
	if emails == nil {
		emails = []ThreatEmail{}
	}
	c.JSON(http.StatusOK, gin.H{"emails": emails})
}

func mapAction(a string) string {
	switch a {
	case "block", "blocked", "reject":
		return "blocked"
	case "quarantine", "quarantined":
		return "quarantined"
	default:
		return "delivered"
	}
}

// ListAttachments — GET /email/attachments
func (h *EmailSecurityHandler) ListAttachments(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"attachments": []interface{}{}})
		return
	}
	ctx := c.Request.Context()
	// attachments カラムから個別ファイルを展開
	rows, err := h.pool.Query(ctx, `
		SELECT gen_random_uuid()::text,
		       att->>'filename',
		       COALESCE(att->>'type', 'unknown'),
		       COALESCE((att->>'size_kb')::int, 0),
		       COALESCE(att->>'sha256', ''),
		       verdict,
		       confidence_score,
		       0, 0
		FROM email_security_events,
		     jsonb_array_elements(CASE jsonb_typeof(attachments) WHEN 'array' THEN attachments ELSE '[]'::jsonb END) AS att
		WHERE verdict != 'clean'
		ORDER BY received_at DESC
		LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"attachments": []interface{}{}})
		return
	}
	defer rows.Close()

	type Attachment struct {
		ID           string `json:"id"`
		Filename     string `json:"filename"`
		Type         string `json:"type"`
		SizeKB       int    `json:"size_kb"`
		SHA256       string `json:"sha256"`
		Verdict      string `json:"verdict"`
		SandboxScore int    `json:"sandbox_score"`
		AVDetections int    `json:"av_detections"`
		AVTotal      int    `json:"av_total"`
	}

	var list []Attachment
	for rows.Next() {
		var a Attachment
		if err := rows.Scan(&a.ID, &a.Filename, &a.Type, &a.SizeKB, &a.SHA256,
			&a.Verdict, &a.SandboxScore, &a.AVDetections, &a.AVTotal); err != nil {
			continue
		}
		list = append(list, a)
	}
	if list == nil {
		list = []Attachment{}
	}
	c.JSON(http.StatusOK, gin.H{"attachments": list})
}

// ListURLScans — GET /email/urls
func (h *EmailSecurityHandler) ListURLScans(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"scans": []interface{}{}})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT gen_random_uuid()::text,
		       u->>'url',
		       CASE verdict WHEN 'malicious' THEN 'malicious' WHEN 'suspicious' THEN 'suspicious' ELSE 'clean' END,
		       received_at,
		       analyzed_at
		FROM email_security_events,
		     jsonb_array_elements(CASE jsonb_typeof(urls) WHEN 'array' THEN urls ELSE '[]'::jsonb END) AS u
		WHERE jsonb_typeof(urls) = 'array' AND jsonb_array_length(urls) > 0
		ORDER BY received_at DESC
		LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"scans": []interface{}{}})
		return
	}
	defer rows.Close()

	type URLScan struct {
		ID         string   `json:"id"`
		URL        string   `json:"url"`
		Status     string   `json:"status"`
		Categories []string `json:"categories"`
		FirstSeen  string   `json:"first_seen"`
		ScanDate   string   `json:"scan_date"`
		Redirects  int      `json:"redirects"`
	}

	var list []URLScan
	for rows.Next() {
		var s URLScan
		var firstSeen, scanDate time.Time
		if err := rows.Scan(&s.ID, &s.URL, &s.Status, &firstSeen, &scanDate); err != nil {
			continue
		}
		s.FirstSeen = firstSeen.Format(time.RFC3339)
		s.ScanDate = scanDate.Format(time.RFC3339)
		s.Categories = []string{}
		list = append(list, s)
	}
	if list == nil {
		list = []URLScan{}
	}
	c.JSON(http.StatusOK, gin.H{"scans": list})
}

// ListSenders — GET /email/senders
func (h *EmailSecurityHandler) ListSenders(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"senders": []interface{}{}})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT gen_random_uuid()::text,
		       CASE WHEN POSITION('@' IN sender) > 0
		            THEN SUBSTRING(sender FROM POSITION('@' IN sender)+1)
		            ELSE sender END AS domain,
		       AVG(confidence_score)::int AS rep,
		       CASE MAX(verdict)
		           WHEN 'malicious' THEN 'malicious'
		           WHEN 'suspicious' THEN 'suspicious'
		           ELSE 'legitimate' END AS category,
		       COUNT(*) AS volume,
		       MAX(received_at),
		       false, false
		FROM email_security_events
		GROUP BY domain
		ORDER BY volume DESC
		LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"senders": []interface{}{}})
		return
	}
	defer rows.Close()

	type Sender struct {
		ID              string `json:"id"`
		Domain          string `json:"domain"`
		ReputationScore int    `json:"reputation_score"`
		Category        string `json:"category"`
		VolumePerDay    int    `json:"volume_per_day"`
		LastSeen        string `json:"last_seen"`
		SPFCompliant    bool   `json:"spf_compliant"`
		DKIMCompliant   bool   `json:"dkim_compliant"`
	}

	var list []Sender
	for rows.Next() {
		var s Sender
		var lastSeen time.Time
		if err := rows.Scan(&s.ID, &s.Domain, &s.ReputationScore, &s.Category,
			&s.VolumePerDay, &lastSeen, &s.SPFCompliant, &s.DKIMCompliant); err != nil {
			continue
		}
		s.LastSeen = lastSeen.Format(time.RFC3339)
		list = append(list, s)
	}
	if list == nil {
		list = []Sender{}
	}
	c.JSON(http.StatusOK, gin.H{"senders": list})
}

// GetStats — GET /email/stats (内部用・旧形式)
func (h *EmailSecurityHandler) GetStats(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{
			"events_today": 0, "events_week": 0,
			"by_verdict": gin.H{}, "top_senders": []interface{}{}, "top_threat_types": []interface{}{},
		})
		return
	}

	ctx := c.Request.Context()

	type TopSender struct {
		Sender string `json:"sender"`
		Count  int    `json:"count"`
	}
	type ThreatTypeCount struct {
		ThreatType string `json:"threat_type"`
		Count      int    `json:"count"`
	}

	var eventsToday, eventsWeek int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_security_events WHERE DATE(received_at)=CURRENT_DATE`).Scan(&eventsToday)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_security_events WHERE received_at >= NOW() - INTERVAL '7 days'`).Scan(&eventsWeek)

	// By verdict
	verdictRows, _ := h.pool.Query(ctx, `
		SELECT verdict, COUNT(*) FROM email_security_events
		GROUP BY verdict ORDER BY COUNT(*) DESC`)
	byVerdict := map[string]int{}
	if verdictRows != nil {
		for verdictRows.Next() {
			var verdict string
			var count int
			if err := verdictRows.Scan(&verdict, &count); err == nil {
				byVerdict[verdict] = count
			}
		}
		if err := verdictRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		verdictRows.Close()
	}

	// Top senders
	var topSenders []TopSender
	senderRows, _ := h.pool.Query(ctx, `
		SELECT sender, COUNT(*) as cnt FROM email_security_events
		GROUP BY sender ORDER BY cnt DESC LIMIT 10`)
	if senderRows != nil {
		for senderRows.Next() {
			var s TopSender
			if err := senderRows.Scan(&s.Sender, &s.Count); err == nil {
				topSenders = append(topSenders, s)
			}
		}
		if err := senderRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		senderRows.Close()
	}

	// Top threat types
	var topThreatTypes []ThreatTypeCount
	threatRows, _ := h.pool.Query(ctx, `
		SELECT threat_type, COUNT(*) as cnt FROM email_security_events
		WHERE threat_type != 'none'
		GROUP BY threat_type ORDER BY cnt DESC LIMIT 10`)
	if threatRows != nil {
		for threatRows.Next() {
			var t ThreatTypeCount
			if err := threatRows.Scan(&t.ThreatType, &t.Count); err == nil {
				topThreatTypes = append(topThreatTypes, t)
			}
		}
		if err := threatRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		threatRows.Close()
	}

	if topSenders == nil {
		topSenders = []TopSender{}
	}
	if topThreatTypes == nil {
		topThreatTypes = []ThreatTypeCount{}
	}

	c.JSON(http.StatusOK, gin.H{
		"events_today":     eventsToday,
		"events_week":      eventsWeek,
		"by_verdict":       byVerdict,
		"top_senders":      topSenders,
		"top_threat_types": topThreatTypes,
	})
}

// GetThreatTrend — GET /email/trend
func (h *EmailSecurityHandler) GetThreatTrend(c *gin.Context) {
	if !h.tableExists(c) {
		c.JSON(http.StatusOK, gin.H{"trend": []interface{}{}})
		return
	}

	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx, `
		SELECT DATE(received_at) as day, verdict, COUNT(*) as cnt
		FROM email_security_events
		WHERE received_at >= NOW() - INTERVAL '30 days'
		GROUP BY day, verdict
		ORDER BY day ASC, verdict ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type TrendEntry struct {
		Day     string `json:"day"`
		Verdict string `json:"verdict"`
		Count   int    `json:"count"`
	}

	var trend []TrendEntry
	for rows.Next() {
		var e TrendEntry
		var day time.Time
		if err := rows.Scan(&day, &e.Verdict, &e.Count); err != nil {
			continue
		}
		e.Day = day.Format("2006-01-02")
		trend = append(trend, e)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	if trend == nil {
		trend = []TrendEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"trend": trend})
}

// Stats — GET /admin/email-security/stats (migration 170 schema)
func (h *EmailSecurityHandler) Stats(c *gin.Context) {
	var total, phishing, malware, blocked int
	if err := h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE event_type='phishing'),
		       COUNT(*) FILTER (WHERE event_type='malware'),
		       COUNT(*) FILTER (WHERE action_taken='blocked')
		FROM email_security_events
		WHERE created_at >= NOW() - INTERVAL '24 hours'
	`).Scan(&total, &phishing, &malware, &blocked); err != nil {
		slog.Warn("email security: 集計クエリに失敗しました", "error", err)
	}
	var policies int
	if err := h.pool.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM email_security_policies WHERE enabled=true`).Scan(&policies); err != nil {
		slog.Warn("email security: 集計クエリに失敗しました", "error", err)
	}
	c.JSON(http.StatusOK, gin.H{
		"events_24h":      total,
		"phishing_24h":    phishing,
		"malware_24h":     malware,
		"blocked_24h":     blocked,
		"active_policies": policies,
	})
}

// ListPolicies — GET /admin/email-security/policies (migration 170 schema)
func (h *EmailSecurityHandler) ListPolicies(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, COALESCE(description,''), policy_type, action, priority, enabled, created_at
		FROM email_security_policies ORDER BY priority, name
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"policies": []any{}})
		return
	}
	defer rows.Close()

	type Policy struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		PolicyType  string `json:"policy_type"`
		Action      string `json:"action"`
		Priority    int    `json:"priority"`
		Enabled     bool   `json:"enabled"`
		CreatedAt   string `json:"created_at"`
	}
	var list []Policy
	for rows.Next() {
		var p Policy
		var createdAt time.Time
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.PolicyType, &p.Action, &p.Priority, &p.Enabled, &createdAt); err != nil {
			continue
		}
		p.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if list == nil {
		list = []Policy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": list})
}
