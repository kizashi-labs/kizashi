package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/notification"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PhishingHandler serves the /admin/phishing-simulator page: awareness-training
// templates and campaigns. Campaigns send real tracked emails via SMTP; per-user
// open/click/report state lives in phishing_recipients and is aggregated at
// request time.
type PhishingHandler struct {
	pool *pgxpool.Pool
}

func NewPhishingHandler(pool *pgxpool.Pool) *PhishingHandler {
	return &PhishingHandler{pool: pool}
}

const maxPhishingRecipients = 200

// newPhishingToken returns an unguessable token for tracking URLs.
func newPhishingToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func requestBaseURL(c *gin.Context) string {
	proto := c.GetHeader("X-Forwarded-Proto")
	if proto == "" {
		if c.Request.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	return proto + "://" + c.Request.Host
}

// ─── Templates ──────────────────────────────────────────────────────

// ListTemplates handles GET /api/v1/admin/phishing/templates
func (h *PhishingHandler) ListTemplates(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID, ok := TenantOrAbort(c)
	if !ok {
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id, name, category, difficulty, industry_tags,
		       from_name, from_email, subject, body
		FROM phishing_templates
		WHERE tenant_id = NULLIF($1,'')::uuid
		ORDER BY created_at DESC`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	out := []gin.H{}
	for rows.Next() {
		var (
			id, name, category, difficulty, fromName, fromEmail, subject, body string
			tags                                                               json.RawMessage
		)
		if err := rows.Scan(&id, &name, &category, &difficulty, &tags,
			&fromName, &fromEmail, &subject, &body); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "name": name, "category": category, "difficulty": difficulty,
			"industry_tags": tags, "from_name": fromName, "from_email": fromEmail,
			"subject": subject, "body": body,
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, out)
}

// CreateTemplate handles POST /api/v1/admin/phishing/templates
func (h *PhishingHandler) CreateTemplate(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID, ok := TenantOrAbort(c)
	if !ok {
		return
	}

	var req struct {
		Name         string `json:"name"`
		Category     string `json:"category"`
		Difficulty   string `json:"difficulty"`
		IndustryTags string `json:"industry_tags"` // comma-separated from the form
		FromName     string `json:"from_name"`
		FromEmail    string `json:"from_email"`
		Subject      string `json:"subject"`
		Body         string `json:"body"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "テンプレート名は必須です"})
		return
	}
	if req.Category == "" {
		req.Category = "credential_harvest"
	}
	if req.Difficulty == "" {
		req.Difficulty = "medium"
	}

	tags := []string{}
	for _, t := range strings.Split(req.IndustryTags, ",") {
		if v := strings.TrimSpace(t); v != "" {
			tags = append(tags, v)
		}
	}
	tagsJSON, _ := json.Marshal(tags)

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO phishing_templates
		    (tenant_id, name, category, difficulty, industry_tags, from_name, from_email, subject, body)
		VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6, $7, $8, $9)
		RETURNING id`,
		tenantID, req.Name, req.Category, req.Difficulty, tagsJSON,
		req.FromName, req.FromEmail, req.Subject, req.Body).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": id, "name": req.Name, "category": req.Category, "difficulty": req.Difficulty,
		"industry_tags": tags, "from_name": req.FromName, "from_email": req.FromEmail,
		"subject": req.Subject, "body": req.Body,
	})
}

// ─── Campaigns ──────────────────────────────────────────────────────

// ListCampaigns handles GET /api/v1/admin/phishing/campaigns. Counts and the
// per-recipient results array are derived from phishing_recipients.
func (h *PhishingHandler) ListCampaigns(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID, ok := TenantOrAbort(c)
	if !ok {
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT c.id, c.name, COALESCE(c.template_id::text,''), c.template_name, c.status, c.start_date,
		       COUNT(r.id)                              AS targets,
		       COUNT(r.id) FILTER (WHERE r.sent)        AS sent,
		       COUNT(r.id) FILTER (WHERE r.clicked)     AS clicked,
		       COUNT(r.id) FILTER (WHERE r.reported)    AS reported
		FROM phishing_campaigns c
		LEFT JOIN phishing_recipients r ON r.campaign_id = c.id
		WHERE c.tenant_id = NULLIF($1,'')::uuid
		GROUP BY c.id, c.name, c.template_id, c.template_name, c.status, c.start_date
		ORDER BY c.start_date DESC`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	campaigns := []gin.H{}
	idIndex := map[string]int{}
	for rows.Next() {
		var (
			id, name, templateID, templateName, status string
			startDate                                  time.Time
			targets, sent, clicked, reported           int
		)
		if err := rows.Scan(&id, &name, &templateID, &templateName, &status, &startDate,
			&targets, &sent, &clicked, &reported); err != nil {
			continue
		}
		idIndex[id] = len(campaigns)
		campaigns = append(campaigns, gin.H{
			"id": id, "name": name, "template_id": templateID, "template_name": templateName,
			"status": status, "targets_count": targets, "sent_count": sent,
			"clicked_count": clicked, "reported_count": reported,
			"start_date": startDate, "results": []gin.H{},
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Attach per-recipient results.
	rRows, err := h.pool.Query(ctx, `
		SELECT campaign_id::text, id::text, email, department, opened, clicked, reported, sent_at, clicked_at
		FROM phishing_recipients
		WHERE tenant_id = NULLIF($1,'')::uuid
		ORDER BY created_at ASC`, tenantID)
	if err == nil {
		defer rRows.Close()
		results := map[string][]gin.H{}
		for rRows.Next() {
			var (
				campaignID, id, email, department string
				opened, clicked, reported         bool
				sentAt, clickedAt                 *time.Time
			)
			if rRows.Scan(&campaignID, &id, &email, &department, &opened, &clicked, &reported, &sentAt, &clickedAt) != nil {
				continue
			}
			var ttc *int
			if sentAt != nil && clickedAt != nil {
				s := int(clickedAt.Sub(*sentAt).Seconds())
				if s < 0 {
					s = 0
				}
				ttc = &s
			}
			results[campaignID] = append(results[campaignID], gin.H{
				"id": id, "email": email, "department": department,
				"opened": opened, "clicked": clicked, "reported": reported,
				"time_to_click_seconds": ttc,
			})
		}
		if err := rRows.Err(); err != nil {
			slog.Warn("ListCampaigns: rRows の読み取りが途中で終わりました。この区画は不完全です", "error", err)
		}
		for cid, idx := range idIndex {
			if rs, ok := results[cid]; ok {
				campaigns[idx]["results"] = rs
			}
		}
	}

	c.JSON(http.StatusOK, campaigns)
}

// CreateCampaign handles POST /api/v1/admin/phishing/campaigns. Creates the
// campaign + recipients, then sends tracked emails in the background.
func (h *PhishingHandler) CreateCampaign(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID, ok := TenantOrAbort(c)
	if !ok {
		return
	}

	var req struct {
		Name         string   `json:"name"`
		TemplateID   string   `json:"template_id"`
		TargetType   string   `json:"target_type"`
		Departments  []string `json:"departments"`
		CustomEmails string   `json:"custom_emails"`
		ScheduledAt  string   `json:"scheduled_at"`
		LandingPage  string   `json:"landing_page"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "キャンペーン名は必須です"})
		return
	}

	// Resolve template (name + content) for display and for sending.
	var templateName, fromName, fromEmail, subject, body string
	var templateIDArg interface{}
	if req.TemplateID != "" {
		templateIDArg = req.TemplateID
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT name, from_name, from_email, subject, body
			 FROM phishing_templates WHERE id = $1::uuid AND tenant_id = NULLIF($2,'')::uuid`,
			req.TemplateID, tenantID).Scan(&templateName, &fromName, &fromEmail, &subject, &body)) {
			return
		}
	}

	// Build the recipient list. Only a custom email list is meaningful without an
	// employee directory integration (all/department resolve to no recipients).
	emails := []string{}
	if req.TargetType == "custom_list" {
		for _, line := range strings.Split(req.CustomEmails, "\n") {
			if v := strings.TrimSpace(line); v != "" && strings.Contains(v, "@") {
				emails = append(emails, v)
				if len(emails) >= maxPhishingRecipients {
					break
				}
			}
		}
	}

	startDate := parseScheduledAt(req.ScheduledAt)
	status := "scheduled"
	if len(emails) > 0 {
		status = "running"
	}

	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO phishing_campaigns
		    (tenant_id, name, template_id, template_name, status, targets_count, start_date, results, landing_page)
		VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, '[]'::jsonb, $8)
		RETURNING id`,
		tenantID, req.Name, templateIDArg, templateName, status, len(emails), startDate, req.LandingPage).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Create recipient rows with tracking tokens.
	type recip struct{ id, email, token string }
	recipients := make([]recip, 0, len(emails))
	for _, email := range emails {
		token := newPhishingToken()
		var rid string
		if err := h.pool.QueryRow(ctx, `
			INSERT INTO phishing_recipients (tenant_id, campaign_id, email, token)
			VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id`,
			tenantID, id, email, token).Scan(&rid); err != nil {
			// 宛先が1件、キャンペーンから静かに抜けます。応答の件数は
			// 入った分だけなので整合して見えますが、依頼した人が入れた
			// はずの相手は訓練を受けません。
			metrics.BackgroundFailed("phishing_recipient", err,
				"フィッシング訓練の宛先を登録できませんでした", "email", email)
			continue
		}
		recipients = append(recipients, recip{id: rid, email: email, token: token})
	}

	// Send in the background so the request returns promptly. Uses the SMTP
	// channel configured under /notifications; if none is configured, recipients
	// remain unsent (status stays as-is) — honest, no fake "sent".
	cfg, smtpOK := h.loadSMTPConfig(ctx)
	sending := smtpOK && len(recipients) > 0
	if sending {
		baseURL := requestBaseURL(c)
		go func() {
			bgCtx := context.Background()
			host := cfg["smtp_host"]
			port := cfg["smtp_port"]
			if port == "" {
				port = "587"
			}
			user := firstNonEmpty(cfg["smtp_username"], cfg["username"])
			pass := firstNonEmpty(cfg["smtp_password"], cfg["password"])
			envFrom := firstNonEmpty(fromEmail, cfg["from_address"], cfg["from"])
			senderName := firstNonEmpty(fromName, cfg["sender_name"], "IT")
			fromHeader := fmt.Sprintf("%s <%s>", senderName, envFrom)
			subj := firstNonEmpty(subject, req.Name)
			for _, r := range recipients {
				html := buildTrackedBody(body, baseURL, r.token)
				if err := notification.SendHTMLMail(host, port, user, pass, fromHeader, envFrom, []string{r.email}, subj, html); err != nil {
					slog.Warn("phishing email send failed", "email", r.email, "error", err)
					continue
				}
				if _, err := h.pool.Exec(bgCtx, `UPDATE phishing_recipients SET sent=TRUE, sent_at=NOW() WHERE id=$1::uuid`, r.id); !WriteOK(c, err) {
					return
				}
			}
		}()
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id, "name": req.Name, "template_id": req.TemplateID, "template_name": templateName,
		"status": status, "targets_count": len(emails), "sent_count": 0,
		"clicked_count": 0, "reported_count": 0, "start_date": startDate, "results": []any{},
		"sending":    sending,
		"smtp_ready": smtpOK,
	})
}

// buildTrackedBody injects an open-tracking pixel and rewrites the template's
// placeholder links to the click-tracking URL.
func buildTrackedBody(body, baseURL, token string) string {
	clickURL := baseURL + "/api/v1/phishing/track/click/" + token
	openURL := baseURL + "/api/v1/phishing/track/open/" + token
	out := strings.ReplaceAll(body, `href="#"`, `href="`+clickURL+`"`)
	if !strings.Contains(out, clickURL) {
		out += `<p><a href="` + clickURL + `">詳細を確認する</a></p>`
	}
	out += `<img src="` + openURL + `" width="1" height="1" style="display:none" alt="">`
	return out
}

// loadSMTPConfig returns the first configured email channel's settings.
func (h *PhishingHandler) loadSMTPConfig(ctx context.Context) (map[string]string, bool) {
	var raw []byte
	if err := h.pool.QueryRow(ctx,
		`SELECT config FROM notification_channels WHERE type = 'email' LIMIT 1`).Scan(&raw); err != nil {
		return nil, false
	}
	var cfg map[string]string
	if json.Unmarshal(raw, &cfg) != nil || cfg["smtp_host"] == "" {
		return nil, false
	}
	return cfg, true
}

// ─── Public tracking endpoints (no auth) ────────────────────────────

// 1x1 transparent GIF.
var trackingPixel = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
	0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02,
	0x44, 0x01, 0x00, 0x3b,
}

// TrackOpen handles GET /api/v1/phishing/track/open/:token
func (h *PhishingHandler) TrackOpen(c *gin.Context) {
	token := c.Param("token")
	if _, err := h.pool.Exec(c.Request.Context(),
		`UPDATE phishing_recipients SET opened = TRUE, opened_at = COALESCE(opened_at, NOW()) WHERE token = $1`, token); !WriteOK(c, err) {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "image/gif", trackingPixel)
}

// TrackClick handles GET /api/v1/phishing/track/click/:token
func (h *PhishingHandler) TrackClick(c *gin.Context) {
	ctx := c.Request.Context()
	token := c.Param("token")
	if _, err := h.pool.Exec(ctx, `
			UPDATE phishing_recipients
			SET clicked = TRUE, clicked_at = COALESCE(clicked_at, NOW()),
			    opened = TRUE, opened_at = COALESCE(opened_at, NOW())
			WHERE token = $1`, token); !WriteOK(c, err) {
		return
	}

	var landing string
	if !ReadOK(c, h.pool.QueryRow(ctx, `
			SELECT COALESCE(c.landing_page, '')
			FROM phishing_recipients r JOIN phishing_campaigns c ON c.id = r.campaign_id
			WHERE r.token = $1`, token).Scan(&landing)) {
		return
	}
	if landing != "" {
		c.Redirect(http.StatusFound, landing)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(awarenessPage))
}

// TrackReport handles GET/POST /api/v1/phishing/track/report/:token
func (h *PhishingHandler) TrackReport(c *gin.Context) {
	token := c.Param("token")
	if _, err := h.pool.Exec(c.Request.Context(),
		`UPDATE phishing_recipients SET reported = TRUE, reported_at = COALESCE(reported_at, NOW()) WHERE token = $1`, token); !WriteOK(c, err) {
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8",
		[]byte(`<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>報告完了</title></head><body style="font-family:sans-serif;max-width:560px;margin:40px auto;padding:0 16px"><h2>報告ありがとうございます</h2><p>このメールはフィッシング訓練でした。不審なメールを見抜き報告する正しい対応です。</p></body></html>`))
}

const awarenessPage = `<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><title>セキュリティ意識向上トレーニング</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:40px auto;padding:0 16px;color:#222">
<h2 style="color:#c0001f">⚠ これはフィッシング訓練でした</h2>
<p>先ほどクリックしたリンクは、セキュリティ意識向上のための<strong>訓練メール</strong>に含まれるものでした。実際の攻撃であれば、認証情報の窃取やマルウェア感染につながる可能性があります。</p>
<ul style="line-height:1.8">
<li>送信元アドレスとリンク先URLを必ず確認する</li>
<li>不審なメールは添付やリンクを開かず、IT/セキュリティ部門へ報告する</li>
<li>心当たりのない「至急」「パスワード期限切れ」等の誘導に注意する</li>
</ul>
<p style="color:#666;font-size:13px">この結果はトレーニング目的でのみ記録されます。</p>
</body></html>`

// ─── Analytics ──────────────────────────────────────────────────────

// GetStats handles GET /api/v1/admin/phishing/stats — aggregates recipient-level
// tracking into the analytics shape. Empty/zero series when no data exists.
func (h *PhishingHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	tenantID, ok := TenantOrAbort(c)
	if !ok {
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT c.template_name, c.start_date, r.department, r.sent, r.clicked, r.reported, r.email
		FROM phishing_recipients r
		JOIN phishing_campaigns c ON c.id = r.campaign_id
		WHERE r.tenant_id = NULLIF($1,'')::uuid`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	monthSent := make([]int, 12)
	monthClicked := make([]int, 12)
	templateClicks := map[string]int{}
	type deptAgg struct{ targets, clicked, reported int }
	deptStats := map[string]*deptAgg{}
	offenderClicks := map[string]int{}
	offenderDept := map[string]string{}

	for rows.Next() {
		var (
			templateName, department, email string
			startDate                       time.Time
			sent, clicked, reported         bool
		)
		if err := rows.Scan(&templateName, &startDate, &department, &sent, &clicked, &reported, &email); err != nil {
			continue
		}
		mi := int(startDate.Month()) - 1
		if mi >= 0 && mi < 12 {
			if sent {
				monthSent[mi]++
			}
			if clicked {
				monthClicked[mi]++
			}
		}
		if clicked && templateName != "" {
			templateClicks[templateName]++
		}
		if department == "" {
			department = "(未分類)"
		}
		d := deptStats[department]
		if d == nil {
			d = &deptAgg{}
			deptStats[department] = d
		}
		d.targets++
		if clicked {
			d.clicked++
			offenderClicks[email]++
			offenderDept[email] = department
		}
		if reported {
			d.reported++
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	rate := func(num, den int) int {
		if den == 0 {
			return 0
		}
		return int(float64(num) / float64(den) * 100.0)
	}

	monthly := make([]int, 12)
	for i := 0; i < 12; i++ {
		monthly[i] = rate(monthClicked[i], monthSent[i])
	}

	departments := []gin.H{}
	for name, d := range deptStats {
		cr := rate(d.clicked, d.targets)
		departments = append(departments, gin.H{
			"department": name, "targets": d.targets,
			"click_rate": cr, "reported_rate": rate(d.reported, d.targets),
			"last_click_rate": cr,
		})
	}
	sort.Slice(departments, func(i, j int) bool {
		return departments[i]["department"].(string) < departments[j]["department"].(string)
	})

	type tt struct {
		name  string
		count int
	}
	tops := []tt{}
	for name, cnt := range templateClicks {
		tops = append(tops, tt{name, cnt})
	}
	sort.Slice(tops, func(i, j int) bool { return tops[i].count > tops[j].count })
	topTemplates := []gin.H{}
	for i, t := range tops {
		if i >= 5 {
			break
		}
		topTemplates = append(topTemplates, gin.H{"template_name": t.name, "click_count": t.count})
	}

	repeatOffenders := []gin.H{}
	for email, cnt := range offenderClicks {
		if cnt >= 3 {
			repeatOffenders = append(repeatOffenders, gin.H{
				"email": email, "department": offenderDept[email],
				"click_count": cnt, "campaigns": []string{},
			})
		}
	}
	sort.Slice(repeatOffenders, func(i, j int) bool {
		return repeatOffenders[i]["click_count"].(int) > repeatOffenders[j]["click_count"].(int)
	})

	c.JSON(http.StatusOK, gin.H{
		"monthly_click_rates": monthly,
		"departments":         departments,
		"top_templates":       topTemplates,
		"repeat_offenders":    repeatOffenders,
	})
}
