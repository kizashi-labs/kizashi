package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// owaspFinding is a single OWASP Top 10 security finding from a passive scan.
type owaspFinding struct {
	VulnType      string
	Severity      string
	OWASPCategory string
	Description   string
	Remediation   string
}

// scanHTTPClient performs passive header/redirect checks — no active fuzzing.
var scanHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse // don't follow redirects; we inspect them
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // intentional for scanner
	},
}

// runOWASPScan performs a passive OWASP-based security scan against targetURL
// and returns a list of findings plus the number of endpoints discovered.
// It never sends mutation requests — only HEAD/GET.
func runOWASPScan(ctx context.Context, targetURL string) (findings []owaspFinding, endpointsFound int) {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		findings = append(findings, owaspFinding{
			VulnType:      "invalid_target",
			Severity:      "info",
			OWASPCategory: "A05:2021",
			Description:   "ターゲットURLが無効です: " + targetURL,
			Remediation:   "有効なURLを指定してください (例: https://api.example.com)",
		})
		return findings, 0
	}

	// ── Probe 1: GET base URL ─────────────────────────────────────────────
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return findings, 0
	}
	req.Header.Set("Origin", "https://evil.example.com") // CORS probe
	resp, err := scanHTTPClient.Do(req)
	if err != nil {
		return findings, 0
	}
	defer resp.Body.Close()
	endpointsFound++

	// ── A02: Cryptographic Failures — no HTTPS ────────────────────────────
	if strings.ToLower(parsed.Scheme) != "https" {
		findings = append(findings, owaspFinding{
			VulnType:      "no_https",
			Severity:      "high",
			OWASPCategory: "A02:2021",
			Description:   "HTTP接続が使用されています。通信が平文で傍受される可能性があります。",
			Remediation:   "TLS/HTTPSを強制し、HSTSヘッダーを設定してください。",
		})
	}

	hdrs := resp.Header

	// ── A05: HSTS missing ─────────────────────────────────────────────────
	if hdrs.Get("Strict-Transport-Security") == "" && strings.ToLower(parsed.Scheme) == "https" {
		findings = append(findings, owaspFinding{
			VulnType:      "missing_hsts",
			Severity:      "medium",
			OWASPCategory: "A05:2021",
			Description:   "Strict-Transport-Security (HSTS) ヘッダーがありません。",
			Remediation:   "Strict-Transport-Security: max-age=31536000; includeSubDomains を設定してください。",
		})
	}

	// ── A05: X-Content-Type-Options missing ──────────────────────────────
	if hdrs.Get("X-Content-Type-Options") == "" {
		findings = append(findings, owaspFinding{
			VulnType:      "missing_xcto",
			Severity:      "low",
			OWASPCategory: "A05:2021",
			Description:   "X-Content-Type-Options ヘッダーがありません。MIMEスニッフィング攻撃のリスクがあります。",
			Remediation:   "X-Content-Type-Options: nosniff を設定してください。",
		})
	}

	// ── A05: X-Frame-Options missing ─────────────────────────────────────
	if hdrs.Get("X-Frame-Options") == "" && hdrs.Get("Content-Security-Policy") == "" {
		findings = append(findings, owaspFinding{
			VulnType:      "missing_xfo",
			Severity:      "medium",
			OWASPCategory: "A05:2021",
			Description:   "X-Frame-Options ヘッダーがありません。クリックジャッキング攻撃のリスクがあります。",
			Remediation:   "X-Frame-Options: DENY または CSP frame-ancestors を設定してください。",
		})
	}

	// ── A05: Content-Security-Policy missing ─────────────────────────────
	if hdrs.Get("Content-Security-Policy") == "" {
		findings = append(findings, owaspFinding{
			VulnType:      "missing_csp",
			Severity:      "medium",
			OWASPCategory: "A05:2021",
			Description:   "Content-Security-Policy (CSP) ヘッダーがありません。XSSリスクが高まります。",
			Remediation:   "適切なCSPポリシーを設定してください (例: default-src 'self')。",
		})
	}

	// ── A05: Server version disclosure ───────────────────────────────────
	if srv := hdrs.Get("Server"); srv != "" && (strings.Contains(srv, "/") || strings.Contains(strings.ToLower(srv), "apache") || strings.Contains(strings.ToLower(srv), "nginx") || strings.Contains(strings.ToLower(srv), "iis")) {
		findings = append(findings, owaspFinding{
			VulnType:      "server_disclosure",
			Severity:      "low",
			OWASPCategory: "A05:2021",
			Description:   fmt.Sprintf("サーバーバージョンが公開されています: %q", srv),
			Remediation:   "ServerTokens Prod / server_tokens off でバージョン情報を非表示にしてください。",
		})
	}
	if xpb := hdrs.Get("X-Powered-By"); xpb != "" {
		findings = append(findings, owaspFinding{
			VulnType:      "xpoweredby_disclosure",
			Severity:      "low",
			OWASPCategory: "A05:2021",
			Description:   fmt.Sprintf("X-Powered-By ヘッダーが公開されています: %q", xpb),
			Remediation:   "X-Powered-By ヘッダーを削除してください。",
		})
	}

	// ── A01: CORS misconfiguration ────────────────────────────────────────
	if acao := hdrs.Get("Access-Control-Allow-Origin"); acao == "*" {
		findings = append(findings, owaspFinding{
			VulnType:      "cors_wildcard",
			Severity:      "high",
			OWASPCategory: "A01:2021",
			Description:   "Access-Control-Allow-Origin: * が設定されています。任意のオリジンからのリクエストを許可しています。",
			Remediation:   "許可するオリジンを明示的に指定し、ワイルドカードを避けてください。",
		})
	} else if acao != "" && acao == req.Header.Get("Origin") {
		// Origin reflection — server echoes back the attacker's origin
		findings = append(findings, owaspFinding{
			VulnType:      "cors_origin_reflection",
			Severity:      "high",
			OWASPCategory: "A01:2021",
			Description:   "CORSオリジンリフレクション: サーバーがリクエストのOriginをそのまま返しています。",
			Remediation:   "許可するオリジンをホワイトリストで管理し、リフレクションを避けてください。",
		})
	}

	// ── A02: Permissions-Policy / Feature-Policy ──────────────────────────
	if hdrs.Get("Permissions-Policy") == "" && hdrs.Get("Feature-Policy") == "" {
		findings = append(findings, owaspFinding{
			VulnType:      "missing_permissions_policy",
			Severity:      "low",
			OWASPCategory: "A05:2021",
			Description:   "Permissions-Policy ヘッダーがありません。ブラウザ機能が制限されていません。",
			Remediation:   "Permissions-Policy: camera=(), microphone=(), geolocation=() などを設定してください。",
		})
	}

	// ── Probe 2: Check for exposed sensitive paths ────────────────────────
	sensitivePaths := []struct {
		path     string
		label    string
		category string
	}{
		{"/.env", ".env ファイル", "A01:2021"},
		{"/config.json", "config.json", "A01:2021"},
		{"/api/v1/debug", "デバッグエンドポイント", "A01:2021"},
		{"/metrics", "メトリクスエンドポイント", "A09:2021"},
		{"/health", "ヘルスチェックエンドポイント", "A09:2021"},
	}

	base := parsed.Scheme + "://" + parsed.Host
	for _, sp := range sensitivePaths {
		probeURL := base + sp.path
		preq, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			continue
		}
		presp, err := scanHTTPClient.Do(preq)
		if err != nil {
			continue
		}
		presp.Body.Close()
		endpointsFound++

		if presp.StatusCode == http.StatusOK {
			findings = append(findings, owaspFinding{
				VulnType:      "exposed_path",
				Severity:      "high",
				OWASPCategory: sp.category,
				Description:   fmt.Sprintf("機密パスが公開されています: %s (HTTP %d)", sp.path, presp.StatusCode),
				Remediation:   sp.label + " へのアクセスを認証またはIP制限で保護してください。",
			})
		}
	}

	return findings, endpointsFound
}

// APISecurityHandler manages API endpoint discovery, vulnerability tracking, and scanning.
type APISecurityHandler struct {
	pool *pgxpool.Pool
}

func NewAPISecurityHandler(pool *pgxpool.Pool) *APISecurityHandler {
	return &APISecurityHandler{pool: pool}
}

// ListEndpoints GET /endpoints — filter by service, auth_type, is_public
func (h *APISecurityHandler) ListEndpoints(c *gin.Context) {
	service := c.Query("service")
	authType := c.Query("auth_type")
	isPublic := c.Query("is_public")

	query := `SELECT id, service_name, method, path, COALESCE(auth_type,''), rate_limit,
	           is_public, risk_score, last_scanned, created_at, updated_at
	          FROM api_endpoints WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if service != "" {
		query += fmt.Sprintf(" AND service_name=$%d", argIdx)
		args = append(args, service)
		argIdx++
	}
	if authType != "" {
		query += fmt.Sprintf(" AND auth_type=$%d", argIdx)
		args = append(args, authType)
		argIdx++
	}
	if isPublic == "true" {
		query += fmt.Sprintf(" AND is_public=$%d", argIdx)
		args = append(args, true)
		argIdx++
	} else if isPublic == "false" {
		query += fmt.Sprintf(" AND is_public=$%d", argIdx)
		args = append(args, false)
		argIdx++
	}
	query += " ORDER BY created_at DESC LIMIT 500"

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Endpoint struct {
		ID          string     `json:"id"`
		ServiceName string     `json:"service_name"`
		Method      string     `json:"method"`
		Path        string     `json:"path"`
		AuthType    string     `json:"auth_type"`
		RateLimit   *int       `json:"rate_limit"`
		IsPublic    bool       `json:"is_public"`
		RiskScore   int        `json:"risk_score"`
		LastScanned *time.Time `json:"last_scanned"`
		CreatedAt   time.Time  `json:"created_at"`
		UpdatedAt   time.Time  `json:"updated_at"`
	}
	endpoints := []Endpoint{}
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.ID, &e.ServiceName, &e.Method, &e.Path, &e.AuthType,
			&e.RateLimit, &e.IsPublic, &e.RiskScore, &e.LastScanned, &e.CreatedAt, &e.UpdatedAt); err != nil {
			continue
		}
		endpoints = append(endpoints, e)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, endpoints)
}

// CreateEndpoint POST /endpoints
func (h *APISecurityHandler) CreateEndpoint(c *gin.Context) {
	var req struct {
		ServiceName string `json:"service_name" binding:"required"`
		Method      string `json:"method" binding:"required"`
		Path        string `json:"path" binding:"required"`
		AuthType    string `json:"auth_type"`
		RateLimit   *int   `json:"rate_limit"`
		IsPublic    bool   `json:"is_public"`
		RiskScore   int    `json:"risk_score"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO api_endpoints (service_name, method, path, auth_type, rate_limit, is_public, risk_score)
		 VALUES ($1, $2, $3, NULLIF($4,''), $5, $6, $7) RETURNING id`,
		req.ServiceName, req.Method, req.Path, req.AuthType, req.RateLimit, req.IsPublic, req.RiskScore,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// UpdateEndpoint PUT /endpoints/:id
func (h *APISecurityHandler) UpdateEndpoint(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		ServiceName string `json:"service_name"`
		Method      string `json:"method"`
		Path        string `json:"path"`
		AuthType    string `json:"auth_type"`
		RateLimit   *int   `json:"rate_limit"`
		IsPublic    *bool  `json:"is_public"`
		RiskScore   *int   `json:"risk_score"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE api_endpoints
		 SET service_name=COALESCE(NULLIF($1,''), service_name),
		     method=COALESCE(NULLIF($2,''), method),
		     path=COALESCE(NULLIF($3,''), path),
		     auth_type=COALESCE(NULLIF($4,''), auth_type),
		     rate_limit=COALESCE($5, rate_limit),
		     is_public=COALESCE($6, is_public),
		     risk_score=COALESCE($7, risk_score),
		     updated_at=NOW()
		 WHERE id=$8`,
		req.ServiceName, req.Method, req.Path, req.AuthType, req.RateLimit, req.IsPublic, req.RiskScore, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// DeleteEndpoint DELETE /endpoints/:id
func (h *APISecurityHandler) DeleteEndpoint(c *gin.Context) {
	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(), `DELETE FROM api_endpoints WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ListVulnerabilities GET /vulnerabilities — filter by severity, vuln_type, status
func (h *APISecurityHandler) ListVulnerabilities(c *gin.Context) {
	severity := c.Query("severity")
	vulnType := c.Query("vuln_type")
	status := c.Query("status")

	query := `SELECT v.id, v.endpoint_id, e.service_name, e.method, e.path,
	           v.vuln_type, v.severity, COALESCE(v.description,''), COALESCE(v.remediation,''),
	           v.status, COALESCE(v.owasp_category,''), v.created_at
	          FROM api_vulnerabilities v
	          JOIN api_endpoints e ON e.id = v.endpoint_id
	          WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if severity != "" {
		query += fmt.Sprintf(" AND v.severity=$%d", argIdx)
		args = append(args, severity)
		argIdx++
	}
	if vulnType != "" {
		query += fmt.Sprintf(" AND v.vuln_type=$%d", argIdx)
		args = append(args, vulnType)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND v.status=$%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	query += " ORDER BY v.created_at DESC LIMIT 200"

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Vuln struct {
		ID            string    `json:"id"`
		EndpointID    string    `json:"endpoint_id"`
		ServiceName   string    `json:"service_name"`
		Method        string    `json:"method"`
		Path          string    `json:"path"`
		VulnType      string    `json:"vuln_type"`
		Severity      string    `json:"severity"`
		Description   string    `json:"description"`
		Remediation   string    `json:"remediation"`
		Status        string    `json:"status"`
		OWASPCategory string    `json:"owasp_category"`
		CreatedAt     time.Time `json:"created_at"`
	}
	vulns := []Vuln{}
	for rows.Next() {
		var v Vuln
		if err := rows.Scan(&v.ID, &v.EndpointID, &v.ServiceName, &v.Method, &v.Path,
			&v.VulnType, &v.Severity, &v.Description, &v.Remediation,
			&v.Status, &v.OWASPCategory, &v.CreatedAt); err != nil {
			continue
		}
		vulns = append(vulns, v)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, vulns)
}

// UpdateVulnStatus PATCH /vulnerabilities/:id/status
func (h *APISecurityHandler) UpdateVulnStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE api_vulnerabilities SET status=$1 WHERE id=$2`, req.Status, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ListScans GET /scans
func (h *APISecurityHandler) ListScans(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, target_url, scan_type, status, endpoints_found, vulns_found,
		        started_at, completed_at, created_at
		 FROM api_scan_jobs ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Scan struct {
		ID             string     `json:"id"`
		TargetURL      string     `json:"target_url"`
		ScanType       string     `json:"scan_type"`
		Status         string     `json:"status"`
		EndpointsFound int        `json:"endpoints_found"`
		VulnsFound     int        `json:"vulns_found"`
		StartedAt      *time.Time `json:"started_at"`
		CompletedAt    *time.Time `json:"completed_at"`
		CreatedAt      time.Time  `json:"created_at"`
	}
	scans := []Scan{}
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.TargetURL, &s.ScanType, &s.Status,
			&s.EndpointsFound, &s.VulnsFound, &s.StartedAt, &s.CompletedAt, &s.CreatedAt); err != nil {
			continue
		}
		scans = append(scans, s)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusOK, scans)
}

// StartScan POST /scans — creates the job row, then runs a real OWASP passive
// scan (runOWASPScan) in a background goroutine and persists the findings.
func (h *APISecurityHandler) StartScan(c *gin.Context) {
	var req struct {
		TargetURL string `json:"target_url" binding:"required"`
		ScanType  string `json:"scan_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ScanType == "" {
		req.ScanType = "passive"
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO api_scan_jobs (target_url, scan_type, status, started_at)
		 VALUES ($1, $2, 'running', NOW()) RETURNING id`,
		req.TargetURL, req.ScanType,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Background goroutine: run real OWASP passive scan, then persist results.
	pool := h.pool
	scanID := id
	targetURL := req.TargetURL
	go func() {
		scanCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		findings, endpointsFound := runOWASPScan(scanCtx, targetURL)

		// Check whether api_vulnerabilities table exists before inserting.
		var vulnTableExists bool
		if err := pool.QueryRow(scanCtx,
			`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='api_vulnerabilities')`,
		).Scan(&vulnTableExists); err != nil {
			slog.Warn("api_security: api_vulnerabilities テーブル確認に失敗しました", "error", err)
		}

		// Check whether api_endpoints table exists for the endpoint_id FK.
		var epTableExists bool
		if err := pool.QueryRow(scanCtx,
			`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='api_endpoints')`,
		).Scan(&epTableExists); err != nil {
			slog.Warn("api_security: api_endpoints テーブル確認に失敗しました", "error", err)
		}

		vulnsFound := 0
		if vulnTableExists && epTableExists && len(findings) > 0 {
			// Create a synthetic api_endpoint representing the scanned target.
			var epID string
			if err := pool.QueryRow(scanCtx,
				`INSERT INTO api_endpoints (service_name, method, path, is_public, risk_score)
				 VALUES ('scan-target', 'GET', $1, true, 0)
				 ON CONFLICT DO NOTHING
				 RETURNING id`,
				targetURL,
			).Scan(&epID); err != nil {
				slog.Warn("api_security: api_endpoint 挿入に失敗しました", "error", err)
			}

			if epID == "" {
				// Endpoint already exists — look it up.
				if err := pool.QueryRow(scanCtx,
					`SELECT id FROM api_endpoints WHERE path=$1 LIMIT 1`, targetURL,
				).Scan(&epID); err != nil {
					slog.Warn("api_security: api_endpoint 検索に失敗しました", "error", err)
				}
			}

			if epID != "" {
				for _, f := range findings {
					_, err := pool.Exec(scanCtx,
						`INSERT INTO api_vulnerabilities
						   (endpoint_id, vuln_type, severity, description, remediation, owasp_category, status)
						 VALUES ($1, $2, $3, $4, $5, $6, 'open')`,
						epID, f.VulnType, f.Severity, f.Description, f.Remediation, f.OWASPCategory,
					)
					if err == nil {
						vulnsFound++
					}
				}
			}
		} else {
			vulnsFound = len(findings)
		}

		_, _ = pool.Exec(scanCtx,
			`UPDATE api_scan_jobs
			 SET status='completed', endpoints_found=$1, vulns_found=$2, completed_at=NOW()
			 WHERE id=$3`,
			endpointsFound, vulnsFound, scanID)
	}()

	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "running"})
}

// GetScan GET /scans/:id
func (h *APISecurityHandler) GetScan(c *gin.Context) {
	id := c.Param("id")
	type Scan struct {
		ID             string     `json:"id"`
		TargetURL      string     `json:"target_url"`
		ScanType       string     `json:"scan_type"`
		Status         string     `json:"status"`
		EndpointsFound int        `json:"endpoints_found"`
		VulnsFound     int        `json:"vulns_found"`
		StartedAt      *time.Time `json:"started_at"`
		CompletedAt    *time.Time `json:"completed_at"`
		CreatedAt      time.Time  `json:"created_at"`
	}
	var s Scan
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, target_url, scan_type, status, endpoints_found, vulns_found,
		        started_at, completed_at, created_at
		 FROM api_scan_jobs WHERE id=$1`, id,
	).Scan(&s.ID, &s.TargetURL, &s.ScanType, &s.Status,
		&s.EndpointsFound, &s.VulnsFound, &s.StartedAt, &s.CompletedAt, &s.CreatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	c.JSON(http.StatusOK, s)
}

// GetStats GET /stats — endpoint counts by auth_type, vuln counts by OWASP, risk distribution
func (h *APISecurityHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Endpoint counts by auth_type
	type AuthCount struct {
		AuthType string `json:"auth_type"`
		Count    int    `json:"count"`
	}
	authCounts := []AuthCount{}
	rows, err := h.pool.Query(ctx,
		`SELECT COALESCE(auth_type,'none'), COUNT(*) FROM api_endpoints GROUP BY auth_type ORDER BY COUNT(*) DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ac AuthCount
			if err := rows.Scan(&ac.AuthType, &ac.Count); err == nil {
				authCounts = append(authCounts, ac)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// Vuln counts by OWASP category
	type OWASPCount struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	owaspCounts := []OWASPCount{}
	rows2, err := h.pool.Query(ctx,
		`SELECT COALESCE(owasp_category,'unknown'), COUNT(*)
		 FROM api_vulnerabilities WHERE status='open'
		 GROUP BY owasp_category ORDER BY COUNT(*) DESC`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var oc OWASPCount
			if err := rows2.Scan(&oc.Category, &oc.Count); err == nil {
				owaspCounts = append(owaspCounts, oc)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// Risk distribution (buckets: 0-25 low, 26-50 medium, 51-75 high, 76-100 critical)
	type RiskBucket struct {
		Bucket string `json:"bucket"`
		Count  int    `json:"count"`
	}
	riskDist := []RiskBucket{}
	rows3, err := h.pool.Query(ctx,
		`SELECT
		   CASE WHEN risk_score <= 25 THEN 'low'
		        WHEN risk_score <= 50 THEN 'medium'
		        WHEN risk_score <= 75 THEN 'high'
		        ELSE 'critical' END as bucket,
		   COUNT(*)
		 FROM api_endpoints
		 GROUP BY 1 ORDER BY 2 DESC`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var rb RiskBucket
			if err := rows3.Scan(&rb.Bucket, &rb.Count); err == nil {
				riskDist = append(riskDist, rb)
			}
		}
		if err := rows3.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	var totalEndpoints, publicEndpoints, openVulns, totalScans int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_public) FROM api_endpoints`).
		Scan(&totalEndpoints, &publicEndpoints)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_vulnerabilities WHERE status='open'`).
		Scan(&openVulns)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_scan_jobs`).
		Scan(&totalScans)

	c.JSON(http.StatusOK, gin.H{
		"total_endpoints":   totalEndpoints,
		"public_endpoints":  publicEndpoints,
		"open_vulns":        openVulns,
		"total_scans":       totalScans,
		"by_auth_type":      authCounts,
		"by_owasp":          owaspCounts,
		"risk_distribution": riskDist,
	})
}

// ListEvents GET /admin/api-security/events — migration 168
func (h *APISecurityHandler) ListEvents(c *gin.Context) {
	eventType := c.Query("event_type")
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT e.id, COALESCE(ep.service_name,'unknown'), COALESCE(ep.path,''), e.event_type,
		       COALESCE(e.source_ip::text,''), COALESCE(e.status_code::text,''),
		       e.risk_score, e.created_at
		FROM api_security_events e
		LEFT JOIN api_endpoints ep ON ep.id = e.endpoint_id
		WHERE ($1 = '' OR e.event_type = $1)
		ORDER BY e.created_at DESC LIMIT 100
	`, eventType)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"events": []any{}})
		return
	}
	defer rows.Close()

	type Event struct {
		ID          string `json:"id"`
		ServiceName string `json:"service_name"`
		Path        string `json:"path"`
		EventType   string `json:"event_type"`
		SourceIP    string `json:"source_ip"`
		StatusCode  string `json:"status_code"`
		RiskScore   int    `json:"risk_score"`
		CreatedAt   string `json:"created_at"`
	}
	var list []Event
	for rows.Next() {
		var ev Event
		var createdAt time.Time
		if err := rows.Scan(&ev.ID, &ev.ServiceName, &ev.Path, &ev.EventType,
			&ev.SourceIP, &ev.StatusCode, &ev.RiskScore, &createdAt); err != nil {
			continue
		}
		ev.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, ev)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if list == nil {
		list = []Event{}
	}
	c.JSON(http.StatusOK, gin.H{"events": list})
}

// Stats GET /admin/api-security/stats — migration 168
func (h *APISecurityHandler) Stats(c *gin.Context) {
	var totalEndpoints, highRisk int
	// api_endpoints に risk_level / enabled 列は無い。リスクは risk_score
	// (0-100) で、区分はこのファイルの一覧クエリと同じ <=25 low / <=50 medium /
	// <=75 high / それ以上 critical。high 以上 = risk_score > 50。
	if err := h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE risk_score > 50)
		FROM api_endpoints
	`).Scan(&totalEndpoints, &highRisk); err != nil {
		slog.Warn("api_security: endpoint stats query failed", "error", err)
	}

	var totalEvents, authFailures, rateLimited int
	if err := h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE event_type='auth_failure'),
		       COUNT(*) FILTER (WHERE event_type='rate_limit')
		FROM api_security_events
		WHERE created_at >= NOW() - INTERVAL '24 hours'
	`).Scan(&totalEvents, &authFailures, &rateLimited); err != nil {
		slog.Warn("api security: 集計クエリに失敗しました", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"total_endpoints":   totalEndpoints,
		"high_risk":         highRisk,
		"events_24h":        totalEvents,
		"auth_failures_24h": authFailures,
		"rate_limited_24h":  rateLimited,
	})
}
