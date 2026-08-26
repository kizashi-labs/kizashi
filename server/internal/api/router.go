// Package api provides the REST API server.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	nethttppprof "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/api/handlers"
	mw "github.com/edr-platform/server/internal/api/middleware"
	"github.com/edr-platform/server/internal/auth"
	"github.com/edr-platform/server/internal/license"
	"github.com/edr-platform/server/internal/metrics"
	apimw "github.com/edr-platform/server/internal/middleware"
	"github.com/edr-platform/server/internal/ml"
	"github.com/edr-platform/server/internal/notification"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Server holds all API dependencies.
type Server struct {
	router      *gin.Engine
	handlers    *Handlers
	wsHub       *notification.WebSocketHub
	auditStore  *store.AuditStore
	rateLimiter *auth.RateLimiter
	pool        *pgxpool.Pool
	apiKeyStore *store.APIKeyStore
	licMgr      *license.Manager
}

// Handlers bundles all route handler implementations.
type Handlers struct {
	noncoreHandlers
	agents         *handlers.AgentHandler
	alerts         *handlers.AlertHandler
	events         *handlers.EventHandler
	auth           *handlers.AuthHandler
	settings       *handlers.SettingsHandler
	users          *handlers.UsersHandler
	ingest         *handlers.IngestHandler
	download       *handlers.DownloadHandler
	sessions       *handlers.SessionHandler
	emailMFA       *handlers.EmailMFAHandler
	passwordPolicy *handlers.PasswordPolicyHandler
	passwordReset  *handlers.PasswordResetHandler

	// WebSocket real-time handler
	WebSocket *handlers.WebSocketHandler

	// New exported handlers (added without changing NewHandlers signature)
	Docs            *handlers.DocsHandler
	Dashboard       *handlers.DashboardHandler
	Installer       *handlers.InstallerHandler
	AlertAction     *handlers.AlertActionHandler
	EmailVerify     *handlers.EmailVerificationHandler
	UserPreferences *handlers.UserPreferencesHandler
	DetailedHealth  *handlers.DetailedHealthHandler
	AgentConfig     *handlers.AgentConfigHandler
	// UninstallProtection owns the tenant uninstall password and the record of
	// attempts to remove agents. Assigned after NewHandlers rather than added to
	// its positional parameter list, like the other late additions here.
	DashboardStats *handlers.DashboardStatsHandler

	Session *handlers.SessionHandler

	// Task #372: Incident Playbook Management

	// Task #373: Cloud Asset Inventory

	// Task #374: DLP Rules Management

	// Task #378: Asset Criticality Scoring

	// Task #380: Honeypot/Deception Management

	// Task #381: Container/Kubernetes Workload Monitoring

	// Task #382: Malware Sandbox Integration

	// Task #387: SOC Workflow Automation

	// Task #389: Zero Trust Access Policy Management

	// Task #394: Privileged Access Management

	// Task #397: Email Security Integration

	// XDR Cross-Domain Detection Engine

	// Zero Trust Engine (in-memory)

	// Task #403: Asset Discovery

	// Task #404: Security Awareness Training

	// Task #407: Vulnerability Remediation Tracking

	// Task #411: Third-Party/Supply Chain Risk Management

	// Task #413: Wireless/IoT Security Monitoring

	// Task #414: Incident Response Automation (SOAR-lite)

	// Task #417: SOC Shift Handover System

	// Task #421: Patch Management System

	// Task #423: Security Knowledge Base

	// Task #427: Privacy/GDPR Compliance Management

	// Task #430: Agent Auto-Remediation Engine

	// Task #431: Security Metrics Historical API

	// Task #432: Password Policy Management (pool-based)
	PasswordPolicy *handlers.PasswordPolicyHandler

	// Task #433: OAuth2/OIDC Client Management

	// Task #440: PagerDuty/OpsGenie Alerting Integration

	// Task #441: Service Account Management

	// Task #442: Feature Flags Management

	// Task #443: Endpoint Tagging System

	// Task #450: Alert Digest Email Scheduler

	// Task #451: TAXII 2.1 Server

	// Task #452: Agent Auto-Enrollment Approval Workflow
	Enrollment *handlers.EnrollmentHandler

	// Multi-Tenant Enhanced Management

	// Log Analysis

	// Migration 116: Deception Technology

	// Migration 117: Ransomware Protection

	// Migration 118: Data Classification

	// Migration 119: Security KPIs

	// Migration 254: Adversary Emulation

	// Migration 255: Network Segmentation

	// Migration 259: Data Retention Policies

	// Migration 260: Endpoint Groups

	// Migration 120: Attack Surface Management

	// Migration 121: UEBA (extended endpoints backed by ueba_anomalies/ueba_baselines)

	// Migration 122: AI Alert Triage

	// Migration 229: Capacity Planning

	// Migration 261: Incident Response Drills

	// Migration 262: Phishing Simulator

	// Migration 263: Penetration Testing

	// Migration 264: Chaos Engineering

	// Migration 123: Container Security Policies

	// Migration 124: API Security

	// Migration 125: Cloud-Native SIEM

	// Migration 126: Compliance Evidence

	// Migration 127: Security Metrics Reports

	// Migration 128: Cloud Identity Federation

	// Migration 129: Deception Network (Honeynet)

	// Migration 130: Incident Pattern Recognition

	// Migration 131: Breach & Attack Simulation

	// Migration 132: Threat Context Enrichment

	// Migration 133: Autonomous Response

	// Migration 134: Compliance Workflow

	// Migration 135: Predictive Analytics

	// Migration 136: Forensics Automation

	// Migration 137: Supply Chain Risk

	// Migration 138: Enhanced Orchestration

	// Migration 139: Threat Hunting Campaigns

	// Migration 140: Compliance Auto-Remediation

	// Migration 141: Zero Trust Network Access

	// Migration 142: Security Data Warehouse

	// Migration 143: Endpoint Encryption Management

	// Migration 144: Patch Automation

	// Migration 145: Security Governance

	// Migration 146: Network Threat Analytics

	// Migration 148: Identity Threat Detection & Response

	// Migration 149: CSPM Enhanced

	// Migration 150: Risk Scoring Engine

	// Migration 151: Automation Enhanced

	// Migration 152: Alert Routing

	// Migration 153: Security Assessment

	// Migration 154: Digital Risk Protection

	// Migration 155: Training Management

	// Migration 156: Quarantine Actions

	// Migration 157: Security SLA

	// Migration 158: Threat Simulation

	// Migration 161: Vulnerability Findings

	// Migration 164: Network Topology

	// Migration 166: Security Metrics History

	// Migration 167: Mobile Device Management

	// Migration 231: Full MDM (profiles, commands, apps, integrations)

	// Migration 232: MDM enrollment tokens + iOS protocol endpoints

	// Migration 170: Email Security (additional schema)
	// (EmailSecurity field already declared above at Task #397)

	// Migration 171: Endpoint Hardening

	// Migration 172: Security Awareness Training

	// ML-based Behavioral Analysis
	MLAnalytics *ml.MLHandler

	// ML Seed / Admin training endpoints

	// Production readiness: liveness/readiness/status probes
	Health *handlers.HealthHandler

	// Threat Hunting Query Engine

	// Migration 177: Threat Intelligence Feed Manager

	// Report Generator (structured on-demand reports)

	// Agent Configuration Profiles

	// Security Scorecard (NIST CSF / ISO 27001)

	// Multi-tenant management lives on TenantHandler (/tenants) and
	// MultiTenantHandler (/admin/tenants), both of which read the `tenants`
	// table every tenant_id foreign key points at. There was a third handler
	// here backed by a parallel `organizations` table that nothing referenced;
	// migration 380 removed it.

	// Migration 183: AI Assistant (Claude integration)

	// Migration 183: GeoIP Threat Map

	// Migration 184: Structured Audit Log v2

	// Migration 179: Sigma Rules Management API

	// Migration 180: Alert Suppression Engine

	// Migration 181: SIEM Webhook Connector

	// Migration 182: Agent Auto-Update Manager

	// Migration 189: Alert Watchlist

	// Migration 190: License Management

	// Migration 236: Auto-update tracking (Phase 1)

	// System Status & Performance
	System *handlers.SystemHandler

	// Network Traffic Analysis

	// Memory Forensics (Migration 194)

	// Cloud Workload Runtime Protection

	// Detection Performance Metrics

	// Staged curate of SigmaHQ-synced rules

	// Mobile Threat Defense (MTD) on-device verdict ingest

	// Endpoint Compliance Checker

	// Migration 185-188: User Management, API Keys Manager, Webhook Dispatcher, Config Backup

	// Migration 192: Process Tree API

	// Migration 192: Attack Timeline API

	// Migration 192: AD/LDAP Identity Integration

	// Migration 193: Admin Scheduled Reports

	// L-6: AI Auto-Investigation

	// L-7: Compliance Auto-Evaluation (CIS/NIST/SOC2)

	// M-3: Mobile Push Token

	// Phase 3: Stripe Billing

	// Phase 5: Support Tickets

	// Batch 6: Admin Compliance Status (NIST CSF + ISO 27001)

	// Behavioral Baseline (endpoint-facing)

	// Ops Report
	OpsReport *handlers.OpsReportHandler

	// B-01: RBAC Roles & Permissions

	// B-02: Access Review

	// B-03: Risk Register

	// B-05: Automation Workflows

	// B-07: Feed Analytics

	// B-04: Insider Threat

	// B-06: IoT/OT Security

	// B-08: Network Anomalies

	// B-09: Cloud Workload Security

	// C-02: TIP Integration

	// C: Integration config settings

	// A: DNS Security page

	// A: Cloud Security Posture page

	// A: Network Traffic stats

	// A: FIM page (suspicious files + ignore rules)

	// A: Dark Web monitoring page

	// A: Software Vulnerability inventory (endpoint_software heuristic fallback)

	// Platform upgrade management (real data: version from ldflags, DB history)

	// User profile: login-history, api-activity, notification-prefs
	UserProfile *handlers.UserProfileHandler

	// Remediation Engine (auto-rollback, exclusion list, webhook actions)

	// 有償版だけが持つハンドラ。公開版には実装パッケージが無いので、
	// 別ファイル(handlers_commercial.go)に切り出して丸ごと外せるようにする。
	// 埋め込みなので参照は s.handlers.X のまま変わらない。
	commercialHandlers
}

// NewHandlers constructs a Handlers bundle from individual handler instances.
// SetUninstallGuardProvider wires the uninstall-password material into agent
// heartbeat responses.
//
// A setter because the agents handler is held in an unexported field and
// NewHandlers already takes an unwieldy positional list; adding one more
// parameter to it for a late feature would touch every call site, including the
// registration test that constructs all 277 handlers.
func (h *Handlers) SetUninstallGuardProvider(f func(*gin.Context) map[string]any) {
	if h.agents != nil {
		h.agents.UninstallGuardProvider = f
	}
}

func NewHandlers(
	agents *handlers.AgentHandler,
	alerts *handlers.AlertHandler,
	events *handlers.EventHandler,
	auth *handlers.AuthHandler,
	settings *handlers.SettingsHandler,
	users *handlers.UsersHandler,
	ingest *handlers.IngestHandler,
	download *handlers.DownloadHandler,
	sessions *handlers.SessionHandler,
	emailMFA *handlers.EmailMFAHandler,
	passwordPolicy *handlers.PasswordPolicyHandler,
	passwordReset *handlers.PasswordResetHandler,
) *Handlers {
	return &Handlers{
		agents:         agents,
		alerts:         alerts,
		events:         events,
		auth:           auth,
		settings:       settings,
		users:          users,
		ingest:         ingest,
		download:       download,
		sessions:       sessions,
		emailMFA:       emailMFA,
		passwordPolicy: passwordPolicy,
		passwordReset:  passwordReset,
	}
}

func NewServer(h *Handlers, wsHub *notification.WebSocketHub, auditStore *store.AuditStore, pool *pgxpool.Pool, licMgr *license.Manager, apiKeyStore ...*store.APIKeyStore) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Trust private networks (Docker/internal proxies) so X-Forwarded-For is used for ClientIP
	_ = r.SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	r.Use(gin.Recovery())
	r.Use(mw.SecurityHeaders())
	r.Use(mw.RequestID())
	r.Use(mw.StructuredLogger())
	r.Use(corsMiddleware())
	r.Use(requestLogger())
	r.Use(metricsMiddleware())
	r.Use(otelMiddleware())
	r.Use(mw.MetricsMiddleware())
	r.Use(mw.SlowQueryLogger(2 * time.Second))
	// Reject request bodies larger than 10 MB to prevent resource exhaustion.
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 10<<20)
		c.Next()
	})

	// 10 auth attempts per 5 min per IP
	rl := auth.NewRateLimiter(10, 5*time.Minute)

	s := &Server{router: r, handlers: h, wsHub: wsHub, auditStore: auditStore, rateLimiter: rl, pool: pool, licMgr: licMgr}
	if len(apiKeyStore) > 0 {
		s.apiKeyStore = apiKeyStore[0]
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	api := s.router.Group("/api/v1")

	// ─── Public Routes ────────────────────────────────────────
	//
	// **認証前の経路は、テナントが決まる前に走ります**（鶏と卵）。いまは
	// RLS のエスケープ節（`app.tenant_id` が未設定なら全行）がこれらを
	// 通していますが、**それは「設定し忘れた接続」も同じように通します。**
	// 名乗りに変えて、全テナントを見るのがどの経路なのかを残します
	// （migration 450 / system_access_ledger_test.go）。
	//
	// 張るのは **4 表 (agents / alerts / incidents / users) に触る経路だけ**
	// です。触らない経路（health / metrics / docs / installer など）には
	// 張りません —— 要らない権利を配ると、名乗りが既定に戻ります。
	sysAccess := mw.SystemAccessMiddleware()

	// 監査: 変異リクエストを audit_logs へ。auth 群にも張るのは、**ログイン試行
	// （成功も失敗も）を監査に残すため** —— 総当たりの痕跡が、これまでどの台帳にも
	// 残っていなかった。本文の写しは middleware 側が /auth/ と password 系で伏せる。
	var auditLog gin.HandlerFunc
	if s.pool != nil {
		auditLog = apimw.NewAuditLogger(s.pool).Middleware()
	}

	auth := api.Group("/auth")
	auth.Use(s.rateLimiter.Middleware())
	auth.Use(mw.StrictRateLimit())
	if auditLog != nil {
		auth.Use(auditLog)
	}
	// users を引きます。**テナントは利用者を引いて初めて決まります。**
	auth.Use(sysAccess)
	{
		auth.POST("/login", s.handlers.auth.Login)
		auth.POST("/refresh", s.handlers.auth.Refresh)
		auth.POST("/logout", s.handlers.auth.Logout)
		auth.POST("/mfa/verify", s.handlers.auth.VerifyMFA)
		// Real-time password validation (no auth required — used by signup/change-password UIs)
		if s.handlers.passwordPolicy != nil {
			auth.POST("/password-policy/validate", s.handlers.passwordPolicy.ValidatePassword)
		}
	}

	// MFA setup/disable requires authentication
	authProtected := api.Group("/auth")
	authProtected.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
	// **ここは認証済みなのに、テナントを ctx に載せていませんでした。**
	// `tenantMiddleware` は `protected` にしか付いておらず、MFA の設定・
	// 解除・メール確認は `users` を**テナント無しで**読み書きしていました
	// （いまは RLS のエスケープ節が通しています）。
	//
	// 名乗り (`sysAccess`) ではなく、テナントを張るのが正解です ——
	// **認証済みの要求は、誰のものか分かっています。** `authMiddleware` が
	// JWT / APIキーから `tenant_id` を ctx に入れているので、ここで拾えます。
	//
	// 絞る向きにしか動きません。JWT がテナントを持たない配備（単一テナント）
	// では、いままでどおり張られません —— そこは `protected` と同じ状態です。
	authProtected.Use(s.tenantMiddleware())
	{
		authProtected.POST("/mfa/setup", s.handlers.auth.SetupMFA)
		authProtected.POST("/mfa/confirm", s.handlers.auth.ConfirmMFA)
		authProtected.POST("/mfa/disable", s.handlers.auth.DisableMFA)
		authProtected.GET("/mfa/backup-codes", s.handlers.auth.GetBackupCodes)
		authProtected.POST("/mfa/backup-codes/regenerate", s.handlers.auth.RegenerateBackupCodes)
	}

	// ─── Protected Routes ─────────────────────────────────────
	protected := api.Group("/")
	protected.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
	protected.Use(mw.APIRateLimit())
	if auditLog != nil {
		protected.Use(auditLog)
	}
	protected.Use(s.tenantMiddleware())
	protected.Use(viewerReadOnlyMiddleware())

	// Agents (Endpoints)
	agents := protected.Group("/agents")
	{
		agents.GET("", s.handlers.agents.List)
		agents.GET("/:id", s.handlers.agents.Get)
		agents.PUT("/:id", s.handlers.agents.Update)
		agents.PATCH("/:id", s.handlers.agents.Update)
		agents.DELETE("/:id", s.handlers.agents.Delete)
		agents.POST("/:id/isolate", s.handlers.agents.Isolate)
		agents.POST("/:id/unisolate", s.handlers.agents.Unisolate)
		agents.GET("/:id/events", s.handlers.events.ListByAgent)
		agents.GET("/:id/processes", s.handlers.agents.GetProcesses)
		agents.GET("/:id/process-stats", s.handlers.agents.GetProcessStats)
		agents.POST("/:id/scan", s.handlers.agents.TriggerScan)
		agents.POST("/:id/scan/cancel", s.handlers.agents.TriggerScanCancel)
		agents.POST("/:id/kill-process", s.handlers.agents.KillProcess)
		agents.POST("/:id/quarantine-file", s.handlers.agents.QuarantineFile)
		agents.POST("/:id/restore-file", s.handlers.agents.RestoreFile)
		agents.GET("/:id/response-history", s.handlers.agents.GetResponseHistory)
		agents.GET("/:id/risk-score", s.handlers.agents.RiskScore)
		agents.GET("/:id/timeline", s.handlers.events.AgentTimeline)
	}
	// Risk scores for top-risk agents
	protected.GET("/agents/risk-scores", s.handlers.agents.RiskScores)

	// Risk scores across all agents (must be outside /:id group to avoid param conflict)
	protected.GET("/agents-risk-scores", s.handlers.agents.RiskScores)

	// Fleet kernel-protection (eBPF LSM) readiness summary — enforce/observe/poll
	// breakdown reported via heartbeat protection_mode. Hyphenated path avoids the
	// /agents/:id param conflict (same pattern as agents-risk-scores).
	protected.GET("/agents-protection-summary", s.handlers.agents.ProtectionSummary)
	// UEBA behavioral-anomaly risk board — top agents by alerts.anomaly_score.
	protected.GET("/agents-anomaly-board", s.handlers.agents.AnomalyBoard)

	// Agent Groups
	groups := protected.Group("/groups")
	{
		groups.GET("", s.handlers.agents.ListGroups)
		groups.POST("", s.handlers.agents.CreateGroup)
		groups.GET("/:id", s.handlers.agents.GetGroup)
		groups.PUT("/:id", s.handlers.agents.UpdateGroup)
		groups.DELETE("/:id", s.handlers.agents.DeleteGroup)
	}

	// Alerts
	alerts := protected.Group("/alerts")
	{
		alerts.GET("", s.handlers.alerts.List)
		alerts.GET("/stats", s.handlers.alerts.Stats)
		alerts.GET("/export", mw.HeavyOperationRateLimit(), s.handlers.alerts.Export)
		alerts.GET("/mitre-stats", s.handlers.alerts.MITREStats)
		alerts.GET("/geo-stats", s.handlers.alerts.GeoStats)
		alerts.GET("/kill-chain-stats", s.handlers.alerts.KillChainStats)
		alerts.GET("/:id", s.handlers.alerts.Get)
		alerts.PUT("/:id", s.handlers.alerts.Update)
		alerts.PUT("/:id/assign", s.handlers.alerts.Assign)
		alerts.GET("/:id/related", s.handlers.alerts.Related)
		alerts.GET("/:id/history", s.handlers.alerts.StatusHistory)
		alerts.GET("/:id/graph", s.handlers.alerts.Graph)
		alerts.GET("/:id/comments", s.handlers.alerts.ListComments)
		alerts.POST("/:id/comments", s.handlers.alerts.AddComment)
		alerts.POST("/bulk-update", mw.BulkWriteRateLimit(), s.handlers.alerts.BulkUpdate)
		// AI-powered actions (Professional plan required)
	}
	// Alert per-record action endpoints
	if s.handlers.AlertAction != nil {
		alerts.POST("/:id/status", s.handlers.AlertAction.UpdateStatus)
		alerts.POST("/:id/enrich", s.handlers.AlertAction.Enrich)
	}

	// Events (raw data)
	events := protected.Group("/events")
	{
		events.GET("", s.handlers.events.List)
		events.GET("/dns", s.handlers.events.ListDNS)
		events.GET("/network-stats", s.handlers.events.NetworkStats)
		events.GET("/file-stats", s.handlers.events.FileStats)
		events.GET("/auth-stats", s.handlers.events.AuthStats)
		events.GET("/:id", s.handlers.events.Get)
		events.POST("/search", s.handlers.events.Search)
		events.GET("/timeline", s.handlers.events.Timeline)
	}

	// Ops Report (frontend dashboard summary — intentionally NOT gated by
	// FeatureReports; it's the data source for the home dashboard tile that
	// Free users also see, not a downloadable report).
	if s.handlers.OpsReport != nil {
		protected.GET("/reports/ops-report", s.handlers.OpsReport.GetReport)
	}

	// Notifications
	notif := protected.Group("/notifications")
	{
		notif.GET("/channels", s.handlers.settings.ListChannels)
		notif.POST("/channels", s.handlers.settings.CreateChannel)
		notif.PUT("/channels/:id", s.handlers.settings.UpdateChannel)
		notif.DELETE("/channels/:id", s.handlers.settings.DeleteChannel)
		notif.POST("/channels/:id/test", s.handlers.settings.TestChannel)

		// Unread notification count — open critical alerts + new incidents in last 24h
		notif.GET("/unread", func(c *gin.Context) {
			if s.pool == nil {
				c.JSON(http.StatusOK, gin.H{"count": 0, "urgent_alerts": 0, "new_incidents": 0})
				return
			}
			ctx := c.Request.Context()
			var urgentAlerts, newIncidents int
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM alerts
					 WHERE severity >= 9 AND status = 'open'
					   AND created_at >= NOW() - INTERVAL '24 hours'`,
			).Scan(&urgentAlerts)) {
				return
			}
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM incidents
					 WHERE status IN ('open', 'investigating')
					   AND created_at >= NOW() - INTERVAL '24 hours'`,
			).Scan(&newIncidents)) {
				return
			}
			total := urgentAlerts + newIncidents
			c.JSON(http.StatusOK, gin.H{
				"count":         total,
				"urgent_alerts": urgentAlerts,
				"new_incidents": newIncidents,
			})
		})
	}

	// Settings (admin only)
	settings := protected.Group("/settings")
	settings.Use(adminMiddleware())
	{
		settings.GET("", s.handlers.settings.Get)
		settings.PUT("", s.handlers.settings.Update)
		settings.POST("/enrollment-token", s.handlers.settings.RegenerateToken)
		// デイリーブリーフィング設定ステータスとテスト送信
		settings.GET("/briefing/status", s.briefingStatusHandler())
		settings.POST("/briefing/test", s.briefingTestHandler())
	}

	// Audit log (admin only)
	if s.auditStore != nil {
		auditGroup := protected.Group("/audit")
		auditGroup.Use(adminMiddleware())
		auditGroup.GET("", s.auditListHandler())
	}

	// Users (current user always accessible; list readable by all; create/update/delete are admin-only)
	users := protected.Group("/users")
	{
		users.GET("/me", s.handlers.users.Me)
		users.PATCH("/me", s.handlers.users.UpdateMe)
		users.PUT("/:id/password", s.handlers.users.UpdatePassword)
		users.GET("", s.handlers.users.List) // readable by all authenticated users (e.g. for assignment)

		// User profile endpoints (login history, API activity, notification prefs)
		if s.handlers.UserProfile != nil {
			users.GET("/me/login-history", s.handlers.UserProfile.LoginHistory)
			users.GET("/me/api-activity", s.handlers.UserProfile.APIActivity)
			users.GET("/me/notification-prefs", s.handlers.UserProfile.GetNotificationPrefs)
			users.PUT("/me/notification-prefs", s.handlers.UserProfile.UpdateNotificationPrefs)
		}
	}
	usersAdmin := protected.Group("/users")
	usersAdmin.Use(adminMiddleware())
	{
		usersAdmin.POST("", s.handlers.users.Create)
		usersAdmin.PUT("/:id", s.handlers.users.Update)
		usersAdmin.DELETE("/:id", s.handlers.users.Deactivate)
	}

	// Session Management (legacy /sessions routes)
	if s.handlers.sessions != nil {
		sessions := protected.Group("/sessions")
		{
			sessions.GET("", s.handlers.sessions.ListSessions)
			sessions.DELETE("", s.handlers.sessions.RevokeAllSessions)
			sessions.DELETE("/:id", s.handlers.sessions.RevokeSession)
		}
	}

	// Session Management v2 (/auth/sessions + /admin/sessions)
	if s.handlers.Session != nil {
		authSess := protected.Group("/auth/sessions")
		{
			authSess.GET("", s.handlers.Session.ListSessions)
			authSess.DELETE("/:id", s.handlers.Session.RevokeSession)
			authSess.DELETE("", s.handlers.Session.RevokeAllSessions)
		}
		adminSess := protected.Group("/admin")
		adminSess.Use(adminMiddleware())
		{
			adminSess.GET("/sessions", s.handlers.Session.ListAllSessions)
			adminSess.DELETE("/sessions/:id", s.handlers.Session.AdminRevokeSession)
			adminSess.DELETE("/users/:id/sessions", s.handlers.Session.AdminRevokeUserSessions)
		}
	}

	// Password Reset (public routes)
	if s.handlers.passwordReset != nil {
		pwReset := api.Group("/auth/password-reset")
		pwReset.Use(s.rateLimiter.Middleware())
		pwReset.Use(sysAccess) // users（メールアドレスから利用者を引きます）
		{
			pwReset.POST("/request", s.handlers.passwordReset.RequestReset)
			pwReset.POST("/confirm", s.handlers.passwordReset.ConfirmReset)
		}
	}

	// Email MFA
	if s.handlers.emailMFA != nil {
		emailMFAPublic := api.Group("/auth/mfa/email")
		emailMFAPublic.Use(s.rateLimiter.Middleware())
		emailMFAPublic.Use(sysAccess) // users（ログインの途中で、まだテナントが決まっていません）
		{
			emailMFAPublic.POST("/send", s.handlers.emailMFA.SendOTP)
			emailMFAPublic.POST("/verify", s.handlers.emailMFA.VerifyOTP)
		}
		emailMFAProtected := authProtected.Group("/mfa/email")
		{
			emailMFAProtected.POST("/enable", s.handlers.emailMFA.EnableEmailMFA)
			emailMFAProtected.POST("/disable", s.handlers.emailMFA.DisableEmailMFA)
		}
	}

	// Dashboard summary
	protected.GET("/dashboard", s.handlers.alerts.Dashboard)

	// Security posture summary (calculated from real DB data)
	protected.GET("/security-posture", func(c *gin.Context) {
		ctx := c.Request.Context()
		score := 100

		if s.pool != nil {
			// Deduct points for recent critical/high alerts (last 7 days)
			var critCount, highCount int
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND created_at > NOW() - INTERVAL '7 days' AND status NOT IN ('resolved','false_positive')`).Scan(&critCount)) {
				return
			}
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM alerts WHERE severity >= 7 AND severity < 9 AND created_at > NOW() - INTERVAL '7 days' AND status NOT IN ('resolved','false_positive')`).Scan(&highCount)) {
				return
			}

			critDeduct := critCount * 5
			if critDeduct > 30 {
				critDeduct = 30
			}
			highDeduct := highCount * 2
			if highDeduct > 15 {
				highDeduct = 15
			}
			score -= critDeduct + highDeduct

			// Deduct for low agent coverage
			var total, online int
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&total)) {
				return
			}
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents WHERE status = 'online'`).Scan(&online)) {
				return
			}
			if total > 0 {
				coverage := online * 100 / total
				if coverage < 80 {
					score -= 20
				} else if coverage < 90 {
					score -= 10
				}
			}

			// Deduct for offline agents.
			// 'inactive'(30日以上未確認の退役扱い)も可視性の欠落という点では
			// 同じなので減点対象に含める。
			var offline int
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents WHERE status IN ('offline', 'inactive')`).Scan(&offline)) {
				return
			}
			if offline > 5 {
				score -= 5
			}
		}

		if score < 0 {
			score = 0
		}
		grade := "A"
		switch {
		case score < 50:
			grade = "D"
		case score < 65:
			grade = "C"
		case score < 80:
			grade = "B"
		}
		riskLevel := "low"
		if score < 65 {
			riskLevel = "high"
		} else if score < 80 {
			riskLevel = "medium"
		}

		c.JSON(http.StatusOK, gin.H{
			"score":        score,
			"grade":        grade,
			"trend":        0,
			"risk_level":   riskLevel,
			"categories":   []interface{}{},
			"last_updated": time.Now().UTC().Format(time.RFC3339),
		})
	})

	// Dashboard widget layout persistence
	if s.handlers.Dashboard != nil {
		db := protected.Group("/dashboard")
		db.GET("/layout", s.handlers.Dashboard.GetLayout)
		db.PUT("/layout", s.handlers.Dashboard.SaveLayout)
	}

	// Dashboard statistics (time-series and KPI endpoints)
	if s.handlers.DashboardStats != nil {
		protected.GET("/dashboard/alert-trend", s.handlers.DashboardStats.AlertTrend)
		protected.GET("/dashboard/top-endpoints", s.handlers.DashboardStats.TopEndpoints)
		protected.GET("/dashboard/detection-rate", s.handlers.DashboardStats.DetectionRate)
		protected.GET("/dashboard/summary", s.handlers.DashboardStats.Summary)
	}

	// WebSocket / SSE endpoints — JWT required (token accepted via ?token= for EventSource)
	if s.wsHub != nil {
		jwtMw := authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore)
		s.router.GET("/ws/alerts",
			jwtMw,
			func(c *gin.Context) { s.wsHub.HandleAlerts(c.Writer, c.Request) },
		)
		s.router.GET("/ws/agents/:id/events",
			jwtMw,
			func(c *gin.Context) { s.wsHub.HandleAgentEvents(c.Writer, c.Request) },
		)
		s.router.GET("/ws/cloud",
			jwtMw,
			func(c *gin.Context) { s.wsHub.HandleCloudEvents(c.Writer, c.Request) },
		)
		s.router.GET("/ws/billing",
			jwtMw,
			func(c *gin.Context) { s.wsHub.HandleBillingEvents(c.Writer, c.Request) },
		)
	}

	// True WebSocket endpoint — gorilla/websocket, JWT already applied by protected group
	if s.handlers.WebSocket != nil {
		protected.GET("/ws", s.handlers.WebSocket.Handle)
	}

	// Ingest endpoints (public, token-auth only)
	if s.handlers.ingest != nil {
		ingestGroup := api.Group("/ingest")
		ingestGroup.Use(sysAccess) // agents / alerts（外部の取り込み。トークン認証のみ）
		ingestGroup.POST("/wazuh", s.handlers.ingest.WazuhAlert)
		ingestGroup.GET("/wazuh/status", s.handlers.ingest.WazuhStatus)
	}

	// Agent heartbeat — public endpoint, no JWT required (agent-facing)
	api.POST("/agents/:id/heartbeat", sysAccess, s.handlers.agents.Heartbeat)

	// Agent disk-encryption status report — public endpoint, no JWT required (agent-facing).
	// Persists one row per agent into endpoint_encryption (upsert); the compliance
	// scorer's PR.DS-1 (data-at-rest protection) control counts these rows.
	if s.pool != nil {
		api.POST("/agents/:id/encryption/report", sysAccess, func(c *gin.Context) {
			agentID := c.Param("id")
			var req struct {
				Encrypted bool   `json:"encrypted"`
				Method    string `json:"method"`
				Details   string `json:"details"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
				return
			}
			if _, err := s.pool.Exec(c.Request.Context(), `
				INSERT INTO endpoint_encryption (agent_id, encrypted, method, details, reported_at)
				VALUES ($1::uuid, $2, $3, $4, NOW())
				ON CONFLICT (agent_id) DO UPDATE
				SET encrypted = EXCLUDED.encrypted, method = EXCLUDED.method,
				    details = EXCLUDED.details, reported_at = NOW()`,
				agentID, req.Encrypted, req.Method, req.Details); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "暗号化ステータスの更新に失敗しました"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "暗号化ステータスを更新しました"})
		})
	}

	// Agent hardening baseline report — public endpoint, no JWT required (agent-facing).
	// Persists into the 171 hardening_* schema (shared with the admin
	// endpoint-hardening UI and read by the compliance scorer's PR.IP-1 control):
	// a find-or-create hardening_baselines row per benchmark (with the check
	// definitions as checks JSONB), plus one per-agent hardening_assessments row
	// carrying the score and the per-check results as findings JSONB.
	if s.pool != nil {
		api.POST("/agents/:id/hardening/report", sysAccess, func(c *gin.Context) {
			agentID := c.Param("id")
			var req struct {
				Benchmark string `json:"benchmark"`
				Checks    []struct {
					ID      string `json:"id"`
					Title   string `json:"title"`
					Passed  bool   `json:"passed"`
					Details string `json:"details"`
				} `json:"checks"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
				return
			}
			if req.Benchmark == "" {
				req.Benchmark = "agent builtin"
			}

			passed := 0
			checkDefs := make([]map[string]any, 0, len(req.Checks))
			findings := make([]map[string]any, 0, len(req.Checks))
			for _, ck := range req.Checks {
				if ck.Passed {
					passed++
				}
				checkDefs = append(checkDefs, map[string]any{"id": ck.ID, "title": ck.Title})
				findings = append(findings, map[string]any{
					"id": ck.ID, "title": ck.Title, "passed": ck.Passed, "details": ck.Details,
				})
			}
			total := len(req.Checks)
			failed := total - passed
			score := 0.0
			if total > 0 {
				score = float64(passed) / float64(total) * 100
			}
			checksJSON, _ := json.Marshal(checkDefs)
			findingsJSON, _ := json.Marshal(findings)

			ctx := c.Request.Context()
			tx, err := s.pool.Begin(ctx)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "ハードニング結果の保存に失敗しました"})
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()

			// os_type for the baseline policy (constrained to windows/linux/macos/all).
			var osType string
			if !handlers.ReadOK(c, tx.QueryRow(ctx, `SELECT COALESCE(os_type,'') FROM agents WHERE id=$1::uuid`, agentID).Scan(&osType)) {
				return
			}
			switch osType {
			case "windows", "linux", "macos", "all":
			case "darwin":
				osType = "macos"
			default:
				osType = "all"
			}

			// Find-or-create the baseline policy for this benchmark.
			var baselineID string
			if err := tx.QueryRow(ctx, `
				INSERT INTO hardening_baselines (name, description, os_type, framework, version, checks, enabled)
				VALUES ($1, 'Agent builtin hardening checks', $2, 'cis', 'v1', $3::jsonb, true)
				ON CONFLICT (name) DO UPDATE
				SET checks = EXCLUDED.checks, os_type = EXCLUDED.os_type, updated_at = NOW()
				RETURNING id`,
				req.Benchmark, osType, string(checksJSON)).Scan(&baselineID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "ハードニング結果の保存に失敗しました"})
				return
			}

			// Replace this agent's prior assessment for this baseline with the new run.
			if _, err := tx.Exec(ctx,
				`DELETE FROM hardening_assessments WHERE agent_id = $1::uuid AND baseline_id = $2`,
				agentID, baselineID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "ハードニング結果の保存に失敗しました"})
				return
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO hardening_assessments
				  (baseline_id, agent_id, passed_checks, failed_checks, skipped_checks, score, status, findings, assessed_at)
				VALUES ($1, $2::uuid, $3, $4, 0, $5, 'completed', $6::jsonb, NOW())`,
				baselineID, agentID, passed, failed, score, string(findingsJSON)); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "ハードニング結果の保存に失敗しました"})
				return
			}
			if err := tx.Commit(ctx); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "ハードニング結果の保存に失敗しました"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "ハードニング評価を更新しました", "passed": passed, "total": total})
		})
	}

	// Agent scan results report — public endpoint, no JWT required (agent-facing)
	api.POST("/agents/:id/scan-results", sysAccess, s.handlers.agents.ReportScanResults)

	// Agent quarantine completion report — public endpoint (agent-facing).
	// The protected /quarantine POST is for human/UI callers; the agent
	// posts here so it can authenticate via mTLS / agent-id without a JWT.
	api.POST("/agents/:id/quarantine-result", sysAccess, s.handlers.agents.ReportQuarantineResult)

	// Health check (unauthenticated)
	s.router.GET("/health", func(c *gin.Context) {
		resp := gin.H{"status": "ok", "time": time.Now()}
		if s.pool != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
			defer cancel()
			if err := s.pool.Ping(ctx); err != nil {
				resp["status"] = "degraded"
				resp["db"] = "unreachable"
				c.JSON(http.StatusServiceUnavailable, resp)
				return
			}
			resp["db"] = "ok"
		}
		c.JSON(http.StatusOK, resp)
	})

	// Detailed health check (unauthenticated — includes DB latency, memory, goroutines)
	if s.handlers.DetailedHealth != nil {
		// **公開経路ですが、agents / alerts / incidents を数えます**
		// （`SELECT COUNT(*) FROM agents WHERE status='online'` ほか 3 本）。
		// テナントを跨ぐ集計なので名乗りが要ります。同じハンドラ群でも
		// uptime / dependencies / incidents は 4 表に触りません。
		s.router.GET("/api/v1/health/detailed", sysAccess, s.handlers.DetailedHealth.DetailedHealth)
		s.router.GET("/api/v1/health/uptime", s.handlers.DetailedHealth.GetUptimeStats)
		s.router.GET("/api/v1/health/dependencies", s.handlers.DetailedHealth.GetDependencies)
		s.router.GET("/api/v1/health/incidents", s.handlers.DetailedHealth.GetIncidentHistory)
	}

	// Production readiness probes (unauthenticated — for k8s liveness/readiness)
	if s.handlers.Health != nil {
		s.router.GET("/healthz", s.handlers.Health.Live)
		s.router.GET("/readyz", s.handlers.Health.Ready)
		s.router.GET("/api/v1/status", s.handlers.Health.Status)
	}

	// pprof profiling endpoints (only when ENABLE_PPROF=true)
	if os.Getenv("ENABLE_PPROF") == "true" {
		pprofGroup := s.router.Group("/debug/pprof")
		pprofGroup.GET("/", gin.WrapF(nethttppprof.Index))
		pprofGroup.GET("/cmdline", gin.WrapF(nethttppprof.Cmdline))
		pprofGroup.GET("/profile", gin.WrapF(nethttppprof.Profile))
		pprofGroup.GET("/symbol", gin.WrapF(nethttppprof.Symbol))
		pprofGroup.GET("/trace", gin.WrapF(nethttppprof.Trace))
		pprofGroup.GET("/heap", gin.WrapH(nethttppprof.Handler("heap")))
		pprofGroup.GET("/goroutine", gin.WrapH(nethttppprof.Handler("goroutine")))
		pprofGroup.GET("/allocs", gin.WrapH(nethttppprof.Handler("allocs")))
	}

	// Prometheus-compatible metrics (unauthenticated; bind to loopback in prod)
	s.router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// OpenAPI spec (unauthenticated)
	s.router.Static("/docs", "./docs")
	s.router.GET("/api/v1/openapi.yaml", func(c *gin.Context) {
		c.File("./docs/openapi.yaml")
	})

	// Agent binary downloads (unauthenticated — binaries are not sensitive, tokens handle auth)
	if s.handlers.download != nil {
		s.router.GET("/api/v1/agents/download", s.handlers.download.GetBinary)
		s.router.GET("/api/v1/agents/download/checksum", s.handlers.download.GetChecksum)
	}

	// OpenAPI / Swagger UI
	handlers.RegisterDocsRoutes(s.router)
	if s.handlers.Docs != nil {
		s.router.GET("/api/v1/docs", s.handlers.Docs.ServeUI)
		s.router.GET("/api/v1/docs/openapi.yaml", s.handlers.Docs.ServeSpec)
	}

	// Agent Installer Scripts
	if s.handlers.Installer != nil {
		installer := api.Group("/installer")
		installer.GET("/linux/:arch", s.handlers.Installer.LinuxInstaller)
		installer.GET("/windows/:arch", s.handlers.Installer.WindowsInstaller)
		installer.GET("/download/:os/:arch", s.handlers.Installer.Download)
		installer.GET("/script", s.handlers.Installer.GenerateInstallScript)
		installer.GET("/script/:os/:arch", s.handlers.Installer.GenerateInstallScript)

		// Token management — admin only (uses protected group)
		installerAdmin := protected.Group("/admin/installer")
		installerAdmin.GET("/tokens", s.handlers.Installer.ListTokens)
		installerAdmin.POST("/tokens", s.handlers.Installer.CreateToken)
		installerAdmin.DELETE("/tokens/:id", s.handlers.Installer.RevokeToken)
	}

	// 有償版だけが持つ経路。中身はビルドタグで切り替わる
	// （routes_commercial.go / routes_commercial_oss.go）。
	s.registerCommercialRoutes(api, protected)

	// Email Verification (send requires auth; confirm is public)
	if s.handlers.EmailVerify != nil {
		// Public: token confirm (linked from email)
		evPublic := api.Group("/auth/email-verification")
		evPublic.Use(sysAccess) // users（確認トークンから利用者を引きます）
		evPublic.POST("/confirm", s.handlers.EmailVerify.ConfirmVerification)

		// Protected: send verification email and check status
		evProtected := authProtected.Group("/email-verification")
		{
			evProtected.POST("/send", s.handlers.EmailVerify.SendVerification)
			evProtected.GET("/status", s.handlers.EmailVerify.GetStatus)
		}
	}

	// User Preferences
	if s.handlers.UserPreferences != nil {
		protected.GET("/user/preferences", s.handlers.UserPreferences.Get)
		protected.PUT("/user/preferences", s.handlers.UserPreferences.Update)
	}
	// Agent Config Schema & Per-Agent Overrides
	if s.handlers.AgentConfig != nil {
		s.router.GET("/api/v1/agent-config/schema", s.handlers.AgentConfig.GetSchema)
		agents.GET("/:id/effective-config", s.handlers.AgentConfig.GetEffective)
		agents.PUT("/:id/config-override", s.handlers.AgentConfig.UpdateOverride)
	}

	// Response Cache admin endpoints
	{
		cacheAdmin := protected.Group("/admin/cache")
		cacheAdmin.Use(adminMiddleware())
		cacheAdmin.GET("/stats", mw.CacheStats())
		cacheAdmin.DELETE("", mw.CacheClear())
	}

	// Example: cache read-heavy dashboard stats for 30 seconds
	// protected.GET("/dashboard/stats", mw.CacheMiddleware(30*time.Second), s.handlers.DashboardStats.Summary)

	// Password Policy Management (pool-based, Task #432)
	if s.handlers.PasswordPolicy != nil {
		ppAdmin := protected.Group("/admin/password-policy")
		ppAdmin.Use(adminMiddleware())
		{
			ppAdmin.GET("", s.handlers.PasswordPolicy.Get)
			ppAdmin.PUT("", s.handlers.PasswordPolicy.Update)
			ppAdmin.POST("/validate", s.handlers.PasswordPolicy.ValidatePassword)
			ppAdmin.GET("/history", s.handlers.PasswordPolicy.GetHistory)
		}
	}

	// Agent Auto-Enrollment (Task #452)
	if s.handlers.Enrollment != nil {
		// Public enrollment request endpoint — guarded by agent limit.
		api.POST("/enrollment/request", sysAccess, apimw.EnforceAgentLimit(s.licMgr), s.handlers.Enrollment.RequestEnrollment)
		// Admin enrollment management
		enrollAdmin := protected.Group("/admin/enrollment")
		enrollAdmin.Use(adminMiddleware())
		{
			enrollAdmin.GET("/requests", s.handlers.Enrollment.ListRequests)
			// Approve also creates an agent — enforce agent limit.
			enrollAdmin.POST("/requests/:id/approve", apimw.EnforceAgentLimit(s.licMgr), s.handlers.Enrollment.ApproveRequest)
			enrollAdmin.POST("/requests/:id/deny", s.handlers.Enrollment.DenyRequest)
			enrollAdmin.GET("/rules", s.handlers.Enrollment.ListRules)
			enrollAdmin.POST("/rules", s.handlers.Enrollment.CreateRule)
			enrollAdmin.DELETE("/rules/:id", s.handlers.Enrollment.DeleteRule)
		}
	}

	// ML-based Behavioral Analysis (Professional plan required, admin only)
	if s.handlers.MLAnalytics != nil {
		adminML := protected.Group("/admin")
		adminML.Use(apimw.RequireFeature(s.licMgr, license.FeatureMLDetection))
		adminML.Use(adminMiddleware())
		adminML.GET("/ml/ueba-scores", s.handlers.MLAnalytics.GetUEBAScores)
		adminML.POST("/ml/analyze-lineage", s.handlers.MLAnalytics.AnalyzeProcessLineage)
		adminML.POST("/ml/anomaly-score", s.handlers.MLAnalytics.AnomalyScore)
	}

	// /admin/organizations, /org/current and /org/settings were removed with
	// migration 380. They served a parallel `organizations` table that no
	// foreign key pointed at, so the agent, user and alert counts they reported
	// were structurally zero and an organization created through them could
	// never own anything. Tenant management is /admin/tenants.

	// System Status & Performance (admin only)
	if s.handlers.System != nil {
		sys := protected.Group("/admin/system")
		sys.Use(adminMiddleware())
		{
			sys.GET("/status", s.handlers.System.Status)
			sys.GET("/db-stats", s.handlers.System.DBStats)
			sys.POST("/cache/flush", s.handlers.System.FlushCache)
		}
	}

	// Platform upgrade management (real data handler)
	s.registerPlatformUpgradeRoutes(protected)

	// A: Security posture summary alias (security-posture page calls /security-posture/summary)
	// Handled by the same inline function as /security-posture, just forward the score calc.
	protected.GET("/security-posture/summary", func(c *gin.Context) {
		ctx := c.Request.Context()
		score := 100
		if s.pool != nil {
			var critical, high int
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE severity >= 9 AND status='open'`).Scan(&critical)) {
				return
			}
			if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE severity >= 7 AND severity < 9 AND status='open'`).Scan(&high)) {
				return
			}
			score = 100 - (critical * 5) - (high * 2)
			if score < 0 {
				score = 0
			}
		}
		grade := "A"
		if score < 90 {
			grade = "B"
		}
		if score < 75 {
			grade = "C"
		}
		if score < 60 {
			grade = "D"
		}
		if score < 40 {
			grade = "F"
		}
		// Build 30-day trend points
		trend30d := make([]gin.H, 30)
		for i := 0; i < 30; i++ {
			trend30d[i] = gin.H{
				"date":  time.Now().UTC().AddDate(0, 0, i-29).Format("2006-01-02"),
				"score": score,
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"overall_score": score,
			"grade":         grade,
			"trend":         0,
			"domain_scores": gin.H{
				"endpoint": score, "network": score,
				"identity": score, "data": score, "cloud": score,
			},
			"critical_findings": []interface{}{},
			"coverage_metrics": gin.H{
				"agent_coverage": 0, "vuln_scan_coverage": 0, "patched_sla": 0,
				"mfa_coverage": 0, "encrypted_data": 0, "log_retention": 0,
			},
			"recent_improvements": []interface{}{},
			"open_risks":          []interface{}{},
			"compliance_heatmap":  []interface{}{},
			"trend_30d":           trend30d,
		})
	})

	// A: Threat models save endpoint (for /threat-modeling page)
	protected.POST("/threat-models", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "threat model saved"})
	})

	// A: Certificate monitoring (for /cert-monitor page)
	{
		certAdmin := protected.Group("/admin/certificates")
		certAdmin.Use(adminMiddleware())
		certAdmin.GET("", func(c *gin.Context) {
			type CertEntry struct {
				ID            string `json:"id"`
				Domain        string `json:"domain"`
				Issuer        string `json:"issuer"`
				ExpiresAt     string `json:"expires_at"`
				DaysRemaining int    `json:"days_remaining"`
				Status        string `json:"status"`
				Port          int    `json:"port"`
				LastChecked   string `json:"last_checked"`
			}
			rows, err := s.pool.Query(c.Request.Context(), `
				SELECT id::text, domain, COALESCE(issuer,''),
				       COALESCE(expires_at, NOW()), port, status, last_checked,
				       EXTRACT(DAY FROM (COALESCE(expires_at, NOW()) - NOW()))::INT
				FROM monitored_certificates
				ORDER BY expires_at ASC NULLS LAST LIMIT 200`)
			if err != nil {
				handlers.ReadFailure(c, err, gin.H{"data": []CertEntry{}, "total": 0})
				return
			}
			defer rows.Close()
			var list []CertEntry
			for rows.Next() {
				var e CertEntry
				var expiresAt, lastChecked time.Time
				if scanErr := rows.Scan(&e.ID, &e.Domain, &e.Issuer,
					&expiresAt, &e.Port, &e.Status, &lastChecked, &e.DaysRemaining); scanErr != nil {
					continue
				}
				e.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
				e.LastChecked = lastChecked.UTC().Format(time.RFC3339)
				list = append(list, e)
			}
			// 部分結果を完全な一覧として返さない（handlers/rows_guard.go 参照）
			if err := rows.Err(); err != nil {
				slog.Error("証明書一覧の走査に失敗しました", "error", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
				return
			}
			if list == nil {
				list = []CertEntry{}
			}
			c.JSON(http.StatusOK, gin.H{"data": list, "total": len(list)})
		})
		certAdmin.POST("", func(c *gin.Context) {
			var req struct {
				Domain string `json:"domain" binding:"required"`
				Port   int    `json:"port"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if req.Port == 0 {
				req.Port = 443
			}
			var id string
			err := s.pool.QueryRow(c.Request.Context(),
				`INSERT INTO monitored_certificates (domain, port) VALUES ($1,$2) RETURNING id::text`,
				req.Domain, req.Port).Scan(&id)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "証明書の登録に失敗しました"})
				return
			}
			c.JSON(http.StatusCreated, gin.H{"id": id, "domain": req.Domain, "port": req.Port})
		})
		// The console has offered edit and delete buttons for monitored
		// certificates since the page was written, and neither route existed: both
		// answered 404, and the page discards mutation errors, so an operator
		// pressing them saw the dialog close and nothing change.
		certAdmin.PUT("/:id", func(c *gin.Context) {
			id := c.Param("id")
			if _, err := uuid.Parse(id); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "IDの形式が不正です"})
				return
			}
			var req struct {
				Domain string `json:"domain" binding:"required"`
				Port   int    `json:"port"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if req.Port == 0 {
				req.Port = 443
			}
			// Changing what is monitored invalidates what was last observed about
			// it. Leaving expires_at and issuer in place would attribute the old
			// host's certificate to the new one until the next daily check.
			tag, err := s.pool.Exec(c.Request.Context(), `
				UPDATE monitored_certificates
				SET domain = $2, port = $3,
				    issuer = CASE WHEN domain = $2 AND port = $3 THEN issuer ELSE '' END,
				    expires_at = CASE WHEN domain = $2 AND port = $3 THEN expires_at ELSE NULL END,
				    status = CASE WHEN domain = $2 AND port = $3 THEN status ELSE 'valid' END
				WHERE id = $1::uuid`, id, req.Domain, req.Port)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "証明書の更新に失敗しました"})
				return
			}
			if tag.RowsAffected() == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "証明書が見つかりません"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"id": id, "domain": req.Domain, "port": req.Port})
		})
		certAdmin.DELETE("/:id", func(c *gin.Context) {
			id := c.Param("id")
			if _, err := uuid.Parse(id); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "IDの形式が不正です"})
				return
			}
			tag, err := s.pool.Exec(c.Request.Context(),
				`DELETE FROM monitored_certificates WHERE id = $1::uuid`, id)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "証明書の削除に失敗しました"})
				return
			}
			if tag.RowsAffected() == 0 {
				c.JSON(http.StatusNotFound, gin.H{"error": "証明書が見つかりません"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"deleted": id})
		})
	}

	// ── Dark Web Monitoring routes ─────────────────────────────
	s.darkwebRoutes(protected)

	// A: SOC SLA metrics
	protected.GET("/soc/sla", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"stats": gin.H{
				"achievement_rate":  0,
				"breached_today":    0,
				"at_risk":           0,
				"avg_response_time": "-",
			},
			"priority_breakdown": []interface{}{},
			"daily_bars":         []interface{}{},
			"breach_reasons":     []interface{}{},
			"tickets":            []interface{}{},
			"config": gin.H{
				"critical_hours":      4,
				"high_hours":          8,
				"medium_hours":        24,
				"low_hours":           72,
				"business_hours_only": false,
				"escalate_75":         true,
				"escalate_90":         true,
				"escalate_breach":     true,
			},
		})
	})

	// A: Threat Graph (admin page - process/file/network relationship graph)
	{
		tg := protected.Group("/admin/threat-graph")
		tg.GET("/stats", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"process": 0, "file": 0, "network": 0, "agent": 0, "alert": 0,
				"total_nodes": 0, "total_edges": 0,
			})
		})
		tg.GET("/subgraph", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"root_id": "", "max_depth": 0, "nodes": []interface{}{}, "edges": []interface{}{},
			})
		})
		tg.POST("/build", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "no data"})
		})
	}

	// A: Software vulnerabilities endpoint (for /software page)
	protected.GET("/software/vulnerabilities", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"vulns": []interface{}{}})
	})

	// Free 版が同梱しないルート群（公開版は routes_noncore.go を no-op に差し替える）
	s.registerNoncoreRoutes(api, protected)
}

// auditListHandler serves GET /api/v1/audit for admins.
func (s *Server) auditListHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
		if page < 1 {
			page = 1
		}
		if perPage < 1 || perPage > 200 {
			perPage = 50
		}
		offset := (page - 1) * perPage
		filter := store.AuditFilter{
			UserEmail:  c.Query("user"),
			Method:     c.Query("method"),
			OnlyErrors: c.Query("errors") == "1",
		}
		logs, total, err := s.auditStore.List(c.Request.Context(), perPage, offset, filter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "監査ログの取得に失敗しました"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"logs":     logs,
			"total":    total,
			"page":     page,
			"per_page": perPage,
			"has_more": (page * perPage) < total,
		})
	}
}

func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

// ─── Platform upgrade stubs ───────────────────────────────────────────────────
// These endpoints serve the /admin/platform-upgrade page.

// ─── Middleware ───────────────────────────────────────────────

func authMiddleware(jwtSecret string, blocklist *auth.TokenBlocklist, userCache *auth.UserStatusCache, apiKeyStore *store.APIKeyStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractBearerToken(c)
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
			return
		}

		// **認証はテナントが決まる前に走ります。** 鶏と卵で、誰なのかを
		// `users` に聞くまでテナントは分かりません。
		//
		// ここは 2 か所とも `users` に届きます:
		//
		//	FindByKey        `LEFT JOIN users` で鍵の持ち主のテナントを引く
		//	userCache.IsActive  `SELECT is_active FROM users WHERE id = $1`
		//
		// **`users` の抜け道を落とすと、この 2 本がテナント無しで 0 行に
		// なります。** そして `IsActive` は行が無いことを「削除された利用者」
		// と読むので（`pgx.ErrNoRows` → false）、**認証済みの要求が全部
		// 「アカウントが無効化されています」で弾かれ、ログには実在しない
		// 削除ユーザーを探させる誤診が残ります。**
		//
		// **`authCtx` は要求の ctx に戻しません。** 戻すと、この先の
		// ハンドラ全部が全テナントで走ります。ここで使うのは認証の 2 本だけ。
		authCtx := store.WithSystemAccess(c.Request.Context())

		// API key auth: tokens starting with "edr_" are API keys, not JWTs.
		if len(tokenStr) > 4 && tokenStr[:4] == "edr_" && apiKeyStore != nil {
			apiKey, err := apiKeyStore.FindByKey(authCtx, tokenStr)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "無効なAPIキーです"})
				return
			}
			// Update last_used_at asynchronously to avoid blocking the request.
			keyID := apiKey.ID
			go func() {
				if err := apiKeyStore.UpdateLastUsed(context.Background(), keyID); err != nil {
					slog.Warn("api key last_used update failed", "key_id", keyID, "error", err)
				}
			}()
			c.Set("user_id", apiKey.UserID)
			c.Set("user_role", "api_key")
			// 鍵の持ち主のテナント。**以前はここが無条件に "" でした。**
			//
			// 空のテナントは「テナント分離の無い配備」として扱われます ——
			// アプリ層の防御（ensureAgentInTenant）は素通しし、RLS の方針は
			// `app.tenant_id` が空なら全テナント可として扱い、
			// TenantMiddleware は空を ctx に入れないのでその状態が続きます。
			// **結果として、APIキーはあらゆるテナントに届いていました。**
			// 実測で、テナントを名乗らない隔離が他テナントの端末に通りました。
			//
			// 持ち主が引けなかったときは空のままです。その場合は
			// 「分からない」として拒否される側に倒れます。
			c.Set("tenant_id", apiKey.TenantID)
			c.Set("api_key_id", apiKey.ID)
			c.Set("api_key_scopes", apiKey.Scopes)
			c.Next()
			return
		}

		claims, err := parseJWT(tokenStr, jwtSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "無効なトークンです"})
			return
		}

		// Check server-side revocation (logout)
		if blocklist != nil && blocklist.IsRevoked(claims.JTI) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "トークンは無効化されています。再ログインしてください"})
			return
		}

		// Check user active status (account deactivation takes effect within ~5 min)
		if userCache != nil && claims.UserID != "admin" {
			if !userCache.IsActive(authCtx, claims.UserID) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "アカウントが無効化されています"})
				return
			}
		}

		c.Set("user_id", claims.UserID)
		c.Set("user_role", claims.Role)
		c.Set("tenant_id", claims.TenantID)
		c.Set("jti", claims.JTI) // for session tracking / revocation
		c.Next()
	}
}

func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("user_role")
		if role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "管理者権限が必要です"})
			return
		}
		c.Next()
	}
}

// viewerReadOnlyMiddleware blocks viewer-role users from write operations (POST/PUT/PATCH/DELETE).
func viewerReadOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("user_role")
		if role == "viewer" {
			method := c.Request.Method
			if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "閲覧専用ロールのため、書き込み操作は許可されていません"})
				return
			}
		}
		c.Next()
	}
}

// tenantScopedAdminMiddleware allows global admins (role=admin) to access any tenant,
// and tenant_admins to access only their own tenant (matched by :id param).
func (s *Server) tenantScopedAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("user_role")
		// Global admin can access any tenant
		if role == "admin" {
			c.Next()
			return
		}

		userID, _ := c.Get("user_id")
		tenantID := c.Param("id")
		if tenantID == "" || userID == nil || s.pool == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "アクセス権限がありません"})
			return
		}

		// Check tenant_roles for tenant_admin
		var tenantRole string
		err := s.pool.QueryRow(c.Request.Context(),
			`SELECT role FROM tenant_roles WHERE tenant_id=$1 AND user_id=$2`,
			tenantID, userID,
		).Scan(&tenantRole)
		if err != nil || tenantRole != "tenant_admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "テナント管理者権限が必要です"})
			return
		}
		c.Next()
	}
}

func corsMiddleware() gin.HandlerFunc {
	// ALLOWED_ORIGINS: comma-separated list of allowed origins.
	// Defaults to "*" when empty (dev). Set explicitly in production.
	// Example: ALLOWED_ORIGINS=https://edr.example.com
	rawOrigins := os.Getenv("ALLOWED_ORIGINS")
	var allowedSet map[string]struct{}
	if rawOrigins != "" && rawOrigins != "*" {
		allowedSet = make(map[string]struct{})
		for _, o := range strings.Split(rawOrigins, ",") {
			allowedSet[strings.TrimSpace(o)] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if allowedSet != nil {
			if _, ok := allowedSet[origin]; ok {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}
			// If origin not allowed, don't set the header → browser blocks it.
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func requestLogger() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/health", "/metrics"},
	})
}

func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		metrics.HTTPRequests.Add(1)
		if c.Writer.Status() >= 400 {
			metrics.HTTPErrors.Add(1)
		}
	}
}

// otelMiddleware wraps each request in an OpenTelemetry span.
// When no OTEL exporter is configured, the global provider is a no-op and
// this middleware has effectively zero overhead.
func otelMiddleware() gin.HandlerFunc {
	tracer := otel.Tracer("edr-api")
	return func(c *gin.Context) {
		spanName := c.Request.Method + " " + c.FullPath()
		ctx, span := tracer.Start(c.Request.Context(), spanName,
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
		)
		defer span.End()

		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.route", c.FullPath()),
			attribute.String("http.url", c.Request.URL.String()),
			attribute.String("http.client_ip", c.ClientIP()),
			attribute.String("http.user_agent", c.Request.UserAgent()),
		)

		// Propagate auth context into span when available.
		if userID, exists := c.Get("user_id"); exists {
			if uid, ok := userID.(string); ok && uid != "" {
				span.SetAttributes(attribute.String("enduser.id", uid))
			}
		}
		if tenantID, exists := c.Get("tenant_id"); exists {
			if tid, ok := tenantID.(string); ok && tid != "" {
				span.SetAttributes(attribute.String("edr.tenant_id", tid))
			}
		}

		c.Request = c.Request.WithContext(ctx)
		c.Next()

		status := c.Writer.Status()
		span.SetAttributes(attribute.Int("http.status_code", status))
		if status >= 500 {
			span.SetStatus(otelcodes.Error, http.StatusText(status))
		}
	}
}

// tenantMiddleware propagates tenant_id from the JWT context into the HTTP
// request context using store.TenantContextKey. The pgxpool PrepareConn
// hook in store.Connect reads this value and calls set_config('app.tenant_id')
// on every connection acquired during the request, enabling PostgreSQL RLS
// without modifying individual query handlers.
func (s *Server) tenantMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.Next()
			return
		}
		tid, _ := tenantID.(string)
		if tid == "" {
			c.Next()
			return
		}
		// Embed tenant_id into the request context so pgxpool.PrepareConn
		// can set app.tenant_id on every connection this request uses.
		ctx := context.WithValue(c.Request.Context(), store.TenantContextKey{}, tid)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func extractBearerToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if len(header) > 7 && header[:7] == "Bearer " {
		return header[7:]
	}
	// Fallback: ?token= query param (for EventSource / SSE where custom headers are not possible)
	if t := c.Query("token"); t != "" {
		return t
	}
	return ""
}

// JWTClaims holds the parsed JWT payload (used by middleware).
type JWTClaims struct {
	UserID   string
	Role     string
	JTI      string // JWT ID — used for server-side revocation
	TenantID string // empty for non-tenant tokens
}

// parseJWT validates a token string and returns its claims.
func parseJWT(tokenStr, secret string) (*JWTClaims, error) {
	type rawClaims struct {
		UserID   string `json:"user_id"`
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenStr, &rawClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	rc, ok := token.Claims.(*rawClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}

	return &JWTClaims{UserID: rc.UserID, Role: rc.Role, JTI: rc.ID, TenantID: rc.TenantID}, nil
}

// briefingStatusHandler returns the current daily briefing delivery configuration status.
// GET /api/v1/settings/briefing/status
func (s *Server) briefingStatusHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"slack_enabled":   os.Getenv("BRIEFING_SLACK_WEBHOOK_URL") != "",
			"webhook_enabled": os.Getenv("BRIEFING_WEBHOOK_URL") != "",
			"email_enabled":   os.Getenv("BRIEFING_EMAIL_TO") != "",
			"email_to":        os.Getenv("BRIEFING_EMAIL_TO"),
			"smtp_host":       os.Getenv("BRIEFING_SMTP_HOST"),
			"hour":            8,
		})
	}
}

// briefingTestHandler immediately collects and logs a briefing summary (no external delivery).
// POST /api/v1/settings/briefing/test
func (s *Server) briefingTestHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベース接続が利用できません"})
			return
		}
		ctx := c.Request.Context()

		var urgentAlerts, openIncidents, newAlertsToday int
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE severity >= 7 AND status = 'open'`).Scan(&urgentAlerts)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating','contained')`).Scan(&openIncidents)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE created_at >= CURRENT_DATE`).Scan(&newAlertsToday)) {
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":          "テストブリーフィングを生成しました（外部送信はしていません）",
			"urgent_alerts":    urgentAlerts,
			"open_incidents":   openIncidents,
			"new_alerts_today": newAlertsToday,
			"slack_enabled":    os.Getenv("BRIEFING_SLACK_WEBHOOK_URL") != "",
			"email_enabled":    os.Getenv("BRIEFING_EMAIL_TO") != "",
		})
	}
}

// ── Dark Web Monitoring ───────────────────────────────────────────────────────

func (s *Server) darkwebRoutes(rg *gin.RouterGroup) {
	dw := rg.Group("/threat-intel/darkweb")
	{
		// 検知結果
		dw.GET("/findings", s.darkwebFindingsHandler())
		// 監視キーワード管理
		dw.GET("/monitors", s.darkwebMonitorListHandler())
		dw.POST("/monitors", s.darkwebMonitorCreateHandler())
		dw.DELETE("/monitors/:id", s.darkwebMonitorDeleteHandler())
		// ランサムウェアサイト一覧
		dw.GET("/sites", s.darkwebSitesHandler())
		// 統計・ステータス
		dw.GET("/status", s.darkwebStatusHandler())
	}
}

func (s *Server) darkwebFindingsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}})
			return
		}
		rows, err := s.pool.Query(c.Request.Context(),
			`SELECT id, source, group_name, severity, title, description, monitor_value, alerted, found_at
			 FROM darkweb_findings ORDER BY found_at DESC LIMIT 100`)
		if err != nil {
			handlers.ReadFailure(c, err, gin.H{"findings": []interface{}{}})
			return
		}
		defer rows.Close()
		type finding struct {
			ID           string  `json:"id"`
			Source       string  `json:"source"`
			GroupName    *string `json:"group_name"`
			Severity     int     `json:"severity"`
			Title        string  `json:"title"`
			Description  *string `json:"description"`
			MonitorValue *string `json:"monitor_value"`
			Alerted      bool    `json:"alerted"`
			FoundAt      string  `json:"found_at"`
		}
		var findings []finding
		for rows.Next() {
			var f finding
			var t time.Time
			if err := rows.Scan(&f.ID, &f.Source, &f.GroupName, &f.Severity,
				&f.Title, &f.Description, &f.MonitorValue, &f.Alerted, &t); err == nil {
				f.FoundAt = t.Format(time.RFC3339)
				findings = append(findings, f)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("darkwebFindingsHandler: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
			c.JSON(http.StatusOK, gin.H{"findings": []interface{}{}})
			return
		}
		if findings == nil {
			findings = []finding{}
		}
		c.JSON(http.StatusOK, gin.H{"findings": findings, "total": len(findings)})
	}
}

func (s *Server) darkwebMonitorListHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusOK, gin.H{"monitors": []interface{}{}})
			return
		}
		rows, err := s.pool.Query(c.Request.Context(),
			`SELECT id, monitor_type, value, enabled, created_at FROM darkweb_monitors ORDER BY created_at DESC`)
		if err != nil {
			handlers.ReadFailure(c, err, gin.H{"monitors": []interface{}{}})
			return
		}
		defer rows.Close()
		type mon struct {
			ID          string `json:"id"`
			MonitorType string `json:"monitor_type"`
			Value       string `json:"value"`
			Enabled     bool   `json:"enabled"`
			CreatedAt   string `json:"created_at"`
		}
		var monitors []mon
		for rows.Next() {
			var m mon
			var t time.Time
			if rows.Scan(&m.ID, &m.MonitorType, &m.Value, &m.Enabled, &t) == nil {
				m.CreatedAt = t.Format(time.RFC3339)
				monitors = append(monitors, m)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("darkwebMonitorListHandler: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
			c.JSON(http.StatusOK, gin.H{"monitors": []interface{}{}})
			return
		}
		if monitors == nil {
			monitors = []mon{}
		}
		c.JSON(http.StatusOK, gin.H{"monitors": monitors})
	}
}

func (s *Server) darkwebMonitorCreateHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベースが利用できません"})
			return
		}
		var req struct {
			MonitorType string `json:"monitor_type" binding:"required"`
			Value       string `json:"value" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Value == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "monitor_type と value は必須です"})
			return
		}
		if req.MonitorType != "domain" && req.MonitorType != "email" && req.MonitorType != "keyword" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "monitor_type は domain/email/keyword のいずれかです"})
			return
		}
		var id string
		err := s.pool.QueryRow(c.Request.Context(),
			`INSERT INTO darkweb_monitors (monitor_type, value)
			 VALUES ($1, $2)
			 ON CONFLICT (monitor_type, value) DO UPDATE SET enabled = TRUE
			 RETURNING id`,
			req.MonitorType, req.Value,
		).Scan(&id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存に失敗しました"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"id": id, "message": "監視対象を追加しました"})
	}
}

func (s *Server) darkwebMonitorDeleteHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベースが利用できません"})
			return
		}
		id := c.Param("id")
		tag, err := s.pool.Exec(c.Request.Context(),
			`DELETE FROM darkweb_monitors WHERE id = $1`, id)
		if err != nil || tag.RowsAffected() == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
	}
}

func (s *Server) darkwebSitesHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusOK, gin.H{"sites": []interface{}{}})
			return
		}
		rows, err := s.pool.Query(c.Request.Context(),
			`SELECT group_name, onion_url, is_active, fail_count, last_alive_at, last_checked_at
			 FROM darkweb_ransomware_sites
			 WHERE onion_url != '__cache__'
			 ORDER BY group_name ASC`)
		if err != nil {
			handlers.ReadFailure(c, err, gin.H{"sites": []interface{}{}})
			return
		}
		defer rows.Close()
		type site struct {
			GroupName   string  `json:"group_name"`
			OnionURL    string  `json:"onion_url"`
			IsActive    bool    `json:"is_active"`
			FailCount   int     `json:"fail_count"`
			LastAliveAt *string `json:"last_alive_at"`
			LastChecked *string `json:"last_checked_at"`
		}
		var sites []site
		for rows.Next() {
			var sv site
			var lastAlive, lastChecked *time.Time
			if rows.Scan(&sv.GroupName, &sv.OnionURL, &sv.IsActive, &sv.FailCount, &lastAlive, &lastChecked) == nil {
				if lastAlive != nil {
					s := lastAlive.Format(time.RFC3339)
					sv.LastAliveAt = &s
				}
				if lastChecked != nil {
					s := lastChecked.Format(time.RFC3339)
					sv.LastChecked = &s
				}
				sites = append(sites, sv)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("darkwebSitesHandler: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
			c.JSON(http.StatusOK, gin.H{"sites": []interface{}{}})
			return
		}
		if sites == nil {
			sites = []site{}
		}
		c.JSON(http.StatusOK, gin.H{"sites": sites, "total": len(sites)})
	}
}

func (s *Server) darkwebStatusHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusOK, gin.H{"enabled": false})
			return
		}
		ctx := c.Request.Context()
		var totalSites, activeSites, totalFindings, totalMonitors int
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM darkweb_ransomware_sites WHERE onion_url != '__cache__'`).Scan(&totalSites)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM darkweb_ransomware_sites WHERE is_active = TRUE AND onion_url != '__cache__'`).Scan(&activeSites)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM darkweb_findings`).Scan(&totalFindings)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM darkweb_monitors WHERE enabled = TRUE`).Scan(&totalMonitors)) {
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"enabled":        true,
			"total_sites":    totalSites,
			"active_sites":   activeSites,
			"total_findings": totalFindings,
			"total_monitors": totalMonitors,
		})
	}
}

// ── Saved searches ────────────────────────────────────────────────────────────

type savedSearch struct {
	ID        string         `json:"id"`
	UserID    string         `json:"user_id"`
	Name      string         `json:"name"`
	Query     string         `json:"query"`
	Filters   map[string]any `json:"filters"`
	Page      string         `json:"page"`
	CreatedAt string         `json:"created_at"`
}

func (s *Server) savedSearchListHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusOK, gin.H{"items": []interface{}{}})
			return
		}
		userID := jwtUserID(c)
		rows, err := s.pool.Query(c.Request.Context(),
			`SELECT id, user_id, name, query, filters, page, created_at
			 FROM saved_searches WHERE user_id = $1 ORDER BY created_at DESC`, userID)
		if err != nil {
			handlers.ReadFailure(c, err, gin.H{"items": []interface{}{}})
			return
		}
		defer rows.Close()
		var items []savedSearch
		for rows.Next() {
			var ss savedSearch
			var filters []byte
			var createdAt time.Time
			if err := rows.Scan(&ss.ID, &ss.UserID, &ss.Name, &ss.Query, &filters, &ss.Page, &createdAt); err != nil {
				continue
			}
			ss.CreatedAt = createdAt.Format(time.RFC3339)
			if len(filters) > 0 {
				_ = json.Unmarshal(filters, &ss.Filters)
			}
			items = append(items, ss)
		}
		// 部分結果を完全な一覧として返さない（handlers/rows_guard.go 参照）
		if err := rows.Err(); err != nil {
			slog.Error("保存済み検索の走査に失敗しました", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "データの取得に失敗しました"})
			return
		}
		if items == nil {
			items = []savedSearch{}
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}

func (s *Server) savedSearchCreateHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベースが利用できません"})
			return
		}
		var req struct {
			Name    string         `json:"name" binding:"required"`
			Query   string         `json:"query"`
			Filters map[string]any `json:"filters"`
			Page    string         `json:"page"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name は必須です"})
			return
		}
		if req.Page == "" {
			req.Page = "alerts"
		}
		filtersJSON, _ := json.Marshal(req.Filters)
		userID := jwtUserID(c)
		var id string
		err := s.pool.QueryRow(c.Request.Context(),
			`INSERT INTO saved_searches (user_id, name, query, filters, page)
			 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			userID, req.Name, req.Query, filtersJSON, req.Page,
		).Scan(&id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存に失敗しました"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"id": id, "message": "保存しました"})
	}
}

// jwtUserID extracts the authenticated user ID from the gin context (set by JWT middleware).
func jwtUserID(c *gin.Context) string {
	if v, ok := c.Get("user_id"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return "anonymous"
}

func (s *Server) savedSearchDeleteHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベースが利用できません"})
			return
		}
		id := c.Param("id")
		userID := jwtUserID(c)
		tag, err := s.pool.Exec(c.Request.Context(),
			`DELETE FROM saved_searches WHERE id = $1 AND user_id = $2`, id, userID)
		if err != nil || tag.RowsAffected() == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "見つかりません"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
	}
}

// ── Adoption Metrics handler ──────────────────────────────────────────────────

func (s *Server) adoptionMetricsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusOK, gin.H{"error": "データベースが利用できません"})
			return
		}
		ctx := c.Request.Context()
		var totalAgents, onlineAgents, offlineAgents int
		var totalAlerts, openAlerts, criticalAlerts int
		var totalIncidents, darkwebFindings int
		// offline には 'inactive'(30日以上未確認の退役扱い)も含める。除外すると
		// total にだけ計上されてどのバケットにも現れないホストが生まれ、
		// total ≠ online + offline + isolated となってサマリの辻褄が合わなくなる。
		// 「退役ホストを触らない」判断が要る経路(heartbeat_monitor / autoupdate 等)
		// とは異なり、ここは単なる死活サマリなので offline 側に寄せる。
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='online'), COUNT(*) FILTER (WHERE status IN ('offline','inactive')) FROM agents`).
			Scan(&totalAgents, &onlineAgents, &offlineAgents)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='open'), COUNT(*) FILTER (WHERE severity>=9 AND status='open') FROM alerts`).
			Scan(&totalAlerts, &openAlerts, &criticalAlerts)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating','contained')`).Scan(&totalIncidents)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM darkweb_findings`).Scan(&darkwebFindings)) {
			return
		}
		var weeklyAlerts, weeklyResolved int
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '7 days'`).Scan(&weeklyAlerts)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE status='resolved' AND updated_at >= NOW() - INTERVAL '7 days'`).Scan(&weeklyResolved)) {
			return
		}
		var totalYara, enabledYara, totalRules, enabledRules int
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM yara_rules`).Scan(&totalYara, &enabledYara)) {
			return
		}
		if !handlers.ReadOK(c, s.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE enabled) FROM rules`).Scan(&totalRules, &enabledRules)) {
			return
		}
		type dayCount struct {
			Date  string `json:"date"`
			Count int    `json:"count"`
		}
		rows, trendErr := s.pool.Query(ctx, `SELECT DATE(created_at), COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '7 days' GROUP BY 1 ORDER BY 1 ASC`)
		var trend []dayCount
		if trendErr != nil {
			slog.Warn("adoptionMetrics: 7日間のトレンドを取得できませんでした", "error", trendErr)
		} else if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var d dayCount
				var t time.Time
				if rows.Scan(&t, &d.Count) == nil {
					d.Date = t.Format("01/02")
					trend = append(trend, d)
				}
			}
			// 途中で終わった走査は、その日のアラートが0件だったのと
			// 同じグラフになります。
			if err := rows.Err(); err != nil {
				slog.Error("adoptionMetrics: トレンドの走査が途中で終わりました。"+
					"グラフの一部の日が0件として描画されます", "error", err)
			}
		}
		if trend == nil {
			trend = []dayCount{}
		}
		c.JSON(http.StatusOK, gin.H{
			"agents":      gin.H{"total": totalAgents, "online": onlineAgents, "offline": offlineAgents},
			"alerts":      gin.H{"total": totalAlerts, "open": openAlerts, "critical": criticalAlerts, "weekly_new": weeklyAlerts, "weekly_resolved": weeklyResolved},
			"incidents":   gin.H{"active": totalIncidents},
			"darkweb":     gin.H{"findings": darkwebFindings},
			"rules":       gin.H{"yara_total": totalYara, "yara_enabled": enabledYara, "sigma_total": totalRules, "sigma_enabled": enabledRules},
			"alert_trend": trend,
		})
	}
}

// ── YARA Scan Job handlers ────────────────────────────────────────────────────

func (s *Server) yaraScanRequestHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "データベースが利用できません"})
			return
		}
		var req struct {
			AgentID  string `json:"agent_id"`
			ScanPath string `json:"scan_path"`
		}
		_ = c.ShouldBindJSON(&req)
		if req.ScanPath == "" {
			req.ScanPath = "/"
		}
		var id string
		var err error
		if req.AgentID != "" {
			err = s.pool.QueryRow(c.Request.Context(),
				`INSERT INTO yara_scan_jobs (agent_id, scan_path) VALUES ($1::uuid, $2) RETURNING id`,
				req.AgentID, req.ScanPath,
			).Scan(&id)
		} else {
			err = s.pool.QueryRow(c.Request.Context(),
				`INSERT INTO yara_scan_jobs (scan_path) VALUES ($1) RETURNING id`, req.ScanPath,
			).Scan(&id)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "スキャンジョブの作成に失敗しました"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"id": id, "message": "スキャンジョブを作成しました", "scan_path": req.ScanPath})
	}
}

func (s *Server) yaraScanJobsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.pool == nil {
			c.JSON(http.StatusOK, gin.H{"jobs": []interface{}{}})
			return
		}
		rows, err := s.pool.Query(c.Request.Context(), `
			SELECT j.id, j.agent_id, a.hostname, j.scan_path, j.status,
			       j.match_count, j.requested_at, j.started_at, j.completed_at, j.error_msg
			FROM yara_scan_jobs j
			LEFT JOIN agents a ON a.id = j.agent_id
			ORDER BY j.requested_at DESC LIMIT 50`)
		if err != nil {
			handlers.ReadFailure(c, err, gin.H{"jobs": []interface{}{}})
			return
		}
		defer rows.Close()
		type scanJob struct {
			ID          string  `json:"id"`
			AgentID     *string `json:"agent_id"`
			Hostname    *string `json:"hostname"`
			ScanPath    string  `json:"scan_path"`
			Status      string  `json:"status"`
			MatchCount  int     `json:"match_count"`
			RequestedAt string  `json:"requested_at"`
			StartedAt   *string `json:"started_at"`
			CompletedAt *string `json:"completed_at"`
			ErrorMsg    *string `json:"error_msg"`
		}
		var jobs []scanJob
		for rows.Next() {
			var j scanJob
			var reqAt time.Time
			var startAt, compAt *time.Time
			if err := rows.Scan(&j.ID, &j.AgentID, &j.Hostname, &j.ScanPath, &j.Status,
				&j.MatchCount, &reqAt, &startAt, &compAt, &j.ErrorMsg); err == nil {
				j.RequestedAt = reqAt.Format(time.RFC3339)
				if startAt != nil {
					s := startAt.Format(time.RFC3339)
					j.StartedAt = &s
				}
				if compAt != nil {
					s := compAt.Format(time.RFC3339)
					j.CompletedAt = &s
				}
				jobs = append(jobs, j)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("yaraScanJobsHandler: 結果セットの読み取りが途中で終わりました。応答は不完全です", "error", err)
			c.JSON(http.StatusOK, gin.H{"jobs": []interface{}{}})
			return
		}
		if jobs == nil {
			jobs = []scanJob{}
		}
		c.JSON(http.StatusOK, gin.H{"jobs": jobs, "total": len(jobs)})
	}
}
