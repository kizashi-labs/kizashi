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
	"github.com/edr-platform/server/internal/email"
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
	agents           *handlers.AgentHandler
	alerts           *handlers.AlertHandler
	events           *handlers.EventHandler
	rules            *handlers.RuleHandler
	reports          *handlers.ReportHandler
	auth             *handlers.AuthHandler
	settings         *handlers.SettingsHandler
	users            *handlers.UsersHandler
	quarantine       *handlers.QuarantineHandler
	ioc              *handlers.IOCHandler
	suppressions     *handlers.SuppressionHandler
	incidents        *handlers.IncidentHandler
	playbooks        *handlers.PlaybookHandler
	reportSchedules  *handlers.ReportScheduleHandler
	vulns            *handlers.VulnHandler
	threatFeeds      *handlers.ThreatFeedHandler
	software         *handlers.SoftwareInventoryHandler
	search           *handlers.SearchHandler
	compliance       *handlers.ComplianceHandler
	ueba             *handlers.UEBAHandler
	notifHistory     *handlers.NotificationHistoryHandler
	socMetrics       *handlers.SOCMetricsHandler
	socQueue         *handlers.SOCQueueHandler
	campaigns        *handlers.CampaignsHandler
	ingest           *handlers.IngestHandler
	liveResponse     *handlers.LiveResponseHandler
	siem             *handlers.SIEMHandler
	virustotal       *handlers.VirusTotalHandler
	hunt             *handlers.HuntHandler
	forensics        *handlers.ForensicsHandler
	complianceReport *handlers.ComplianceReportHandler
	tenants          *handlers.TenantHandler
	tenantRoles      *handlers.TenantRolesHandler
	tiSyncHandler    *handlers.TIFeedSyncHandler
	cloudMonitor     *handlers.CloudMonitorHandler
	download         *handlers.DownloadHandler
	sessions         *handlers.SessionHandler
	agentPolicies    *handlers.AgentPolicyHandler
	soar             *handlers.SOARHandler
	emailMFA         *handlers.EmailMFAHandler
	notifPrefs       *handlers.NotificationPrefsHandler
	webhooks         *handlers.WebhookHandler
	dashboardPrefs   *handlers.DashboardPrefsHandler
	yaraRules        *handlers.YARAHandler
	riskActions      *handlers.RiskActionHandler
	complianceScore  *handlers.ComplianceScoreHandler
	passwordPolicy   *handlers.PasswordPolicyHandler
	invitations      *handlers.InvitationHandler
	passwordReset    *handlers.PasswordResetHandler
	fim              *handlers.FIMHandler
	deviceEvents     *handlers.DeviceHandler
	apiKeys          *handlers.APIKeyHandler
	processBlock     *handlers.ProcessBlockHandler

	// WebSocket real-time handler
	WebSocket *handlers.WebSocketHandler

	// New exported handlers (added without changing NewHandlers signature)
	IncidentComments     *handlers.IncidentCommentHandler
	AlertComments        *handlers.AlertCommentsHandler
	ReportExport         *handlers.ReportExportHandler
	Backup               *handlers.BackupHandler
	AuditExport          *handlers.AuditExportHandler
	Cert                 *handlers.CertHandler
	Docs                 *handlers.DocsHandler
	Notification         *handlers.NotificationHandler
	Dashboard            *handlers.DashboardHandler
	RulesIE              *handlers.RulesIEHandler
	Installer            *handlers.InstallerHandler
	RuleTest             *handlers.RuleTestHandler
	AlertBulk            *handlers.AlertBulkHandler
	AlertAction          *handlers.AlertActionHandler
	LiveResponseCmdQueue *handlers.LiveResponseCmdHandler
	ComplianceExport     *handlers.ComplianceExportHandler
	ES                   *handlers.ESHandler
	Sigma                *handlers.SigmaHandler
	NotifTemplate        *handlers.NotificationTemplateHandler
	EmailVerify          *handlers.EmailVerificationHandler
	PDFReport            *handlers.PDFReportHandler
	SavedHunt            *handlers.SavedHuntHandler
	UserPreferences      *handlers.UserPreferencesHandler
	Favorites            *handlers.FavoritesHandler
	DetailedHealth       *handlers.DetailedHealthHandler
	AgentConfig          *handlers.AgentConfigHandler
	AlertAssign          *handlers.AlertAssignHandler
	AgentTags            *handlers.AgentTagHandler
	EscalationRules      *handlers.EscalationRuleHandler
	Correlation          *handlers.CorrelationHandler
	DashboardStats       *handlers.DashboardStatsHandler
	PacketCapture        *handlers.PacketCaptureHandler
	Export               *handlers.ExportHandler
	STIX                 *handlers.STIXHandler
	ThreatActors         *handlers.ThreatActorHandler
	ThreatFusion         *handlers.ThreatFusionHandler
	IPBlock              *handlers.IPBlockHandler

	AutoResponse     *handlers.AutoResponseHandler
	CustomAlertRules *handlers.CustomAlertRulesHandler
	MetricsAPI       *handlers.MetricsAPIHandler
	Timeline         *handlers.TimelineHandler

	IOCEnrichment *handlers.IOCEnrichmentHandler

	LogIngestion   *handlers.LogIngestionHandler
	SystemSettings *handlers.SystemSettingsHandler

	ReportTemplates *handlers.ReportTemplateHandler

	Onboarding *handlers.OnboardingHandler

	MaintenanceWindow *handlers.MaintenanceWindowHandler

	RecoveryCodes *handlers.RecoveryCodeHandler
	NetworkMap    *handlers.NetworkMapHandler

	Session *handlers.SessionHandler

	SIEMConnector *handlers.SIEMConnectorHandler

	AlertClassifier *handlers.AlertClassifierHandler

	Geolocation *handlers.GeolocationHandler

	EventStream *handlers.EventStreamHandler

	CorrelationEngine *handlers.CorrelationEngineHandler

	SoftwareDiff *handlers.SoftwareDiffHandler
	EDRPolicy    *handlers.EDRPolicyHandler
	AuditSign    *handlers.AuditSignHandler

	// Task #372: Incident Playbook Management
	IncidentPlaybook *handlers.IncidentPlaybookHandler

	// Task #373: Cloud Asset Inventory
	CloudAsset *handlers.CloudAssetHandler

	// Task #374: DLP Rules Management
	DLP *handlers.DLPHandler

	// Task #378: Asset Criticality Scoring
	AssetCriticality *handlers.AssetCriticalityHandler

	// Task #380: Honeypot/Deception Management
	Honeypot *handlers.HoneypotHandler

	// Task #381: Container/Kubernetes Workload Monitoring
	Container *handlers.ContainerHandler

	// Task #382: Malware Sandbox Integration
	Sandbox *handlers.SandboxHandler

	// Task #387: SOC Workflow Automation
	SOCTicket *handlers.SOCTicketHandler

	// Task #389: Zero Trust Access Policy Management
	ZeroTrust *handlers.ZeroTrustHandler

	// Task #394: Privileged Access Management
	PAM *handlers.PAMHandler

	// Task #397: Email Security Integration
	EmailSecurity *handlers.EmailSecurityHandler

	// XDR Cross-Domain Detection Engine
	XDR *handlers.XDRHandler

	// Zero Trust Engine (in-memory)
	ZeroTrustEngine *handlers.ZeroTrustEngineHandler

	// Task #403: Asset Discovery
	AssetDiscovery *handlers.AssetDiscoveryHandler

	// Task #404: Security Awareness Training
	Training *handlers.TrainingHandler

	// Task #407: Vulnerability Remediation Tracking
	VulnRemediation *handlers.VulnRemediationHandler

	// Task #411: Third-Party/Supply Chain Risk Management
	VendorRisk *handlers.VendorRiskHandler

	// Task #413: Wireless/IoT Security Monitoring
	Wireless *handlers.WirelessHandler

	// Task #414: Incident Response Automation (SOAR-lite)
	SOARWorkflow *handlers.SOARWorkflowHandler

	// Task #417: SOC Shift Handover System
	Shift *handlers.ShiftHandler

	// Task #421: Patch Management System
	Patch *handlers.PatchHandler

	// Task #423: Security Knowledge Base
	KnowledgeBase *handlers.KnowledgeBaseHandler

	// Task #427: Privacy/GDPR Compliance Management
	GDPR *handlers.GDPRHandler

	// Task #430: Agent Auto-Remediation Engine
	AutoRemediation *handlers.AutoRemediationHandler

	// Task #431: Security Metrics Historical API
	MetricsHistory *handlers.MetricsHistoryHandler

	// Task #432: Password Policy Management (pool-based)
	PasswordPolicy *handlers.PasswordPolicyHandler

	// Task #433: OAuth2/OIDC Client Management
	OAuth2 *handlers.OAuth2Handler

	// Task #440: PagerDuty/OpsGenie Alerting Integration
	OnCall *handlers.OnCallHandler

	// Task #441: Service Account Management
	ServiceAccount *handlers.ServiceAccountHandler

	// Task #442: Feature Flags Management
	FeatureFlag *handlers.FeatureFlagHandler

	// Task #443: Endpoint Tagging System
	EndpointTag *handlers.EndpointTagHandler

	// Task #450: Alert Digest Email Scheduler
	Digest *handlers.DigestHandler

	// Task #451: TAXII 2.1 Server
	TAXII *handlers.TAXIIHandler

	// Task #452: Agent Auto-Enrollment Approval Workflow
	Enrollment *handlers.EnrollmentHandler

	// Multi-Tenant Enhanced Management
	MultiTenant *handlers.MultiTenantHandler

	// Log Analysis
	LogAnalysis *handlers.LogAnalysisHandler

	// Migration 116: Deception Technology
	Deception *handlers.DeceptionHandler

	// Migration 117: Ransomware Protection
	Ransomware *handlers.RansomwareHandler

	// Migration 118: Data Classification
	DataClassification *handlers.DataClassificationHandler

	// Migration 119: Security KPIs
	SecurityKPI *handlers.SecurityKPIHandler

	// Migration 254: Adversary Emulation
	AdversaryEmulation *handlers.AdversaryEmulationHandler

	// Migration 255: Network Segmentation
	NetworkSegmentation *handlers.NetworkSegmentationHandler

	// Migration 259: Data Retention Policies
	DataRetention *handlers.DataRetentionHandler

	// Migration 260: Endpoint Groups
	EndpointGroups *handlers.EndpointGroupsHandler

	// Migration 120: Attack Surface Management
	AttackSurface *handlers.AttackSurfaceHandler

	// Migration 121: UEBA (extended endpoints backed by ueba_anomalies/ueba_baselines)
	UEBA *handlers.UEBAHandler

	// Migration 122: AI Alert Triage

	// Migration 229: Capacity Planning
	CapacityPlanning *handlers.CapacityPlanningHandler

	// Migration 261: Incident Response Drills
	IncidentDrills *handlers.IncidentDrillsHandler

	// Migration 262: Phishing Simulator
	Phishing *handlers.PhishingHandler

	// Migration 263: Penetration Testing
	Pentest *handlers.PentestHandler

	// Migration 264: Chaos Engineering
	Chaos *handlers.ChaosHandler

	// Migration 123: Container Security Policies
	ContainerSecurity *handlers.ContainerSecurityHandler

	// Migration 124: API Security
	APISecurity *handlers.APISecurityHandler

	// Migration 125: Cloud-Native SIEM
	CloudSIEM *handlers.CloudSIEMHandler

	// Migration 126: Compliance Evidence
	ComplianceEvidence *handlers.ComplianceEvidenceHandler

	// Migration 127: Security Metrics Reports
	MetricsReport *handlers.MetricsReportHandler

	// Migration 128: Cloud Identity Federation
	CloudIdentity *handlers.CloudIdentityHandler

	// Migration 129: Deception Network (Honeynet)
	Honeynet *handlers.HoneynetHandler

	// Migration 130: Incident Pattern Recognition
	IncidentPattern *handlers.IncidentPatternHandler

	// Migration 131: Breach & Attack Simulation
	BAS *handlers.BASHandler

	// Migration 132: Threat Context Enrichment
	ContextEnrichment *handlers.ContextEnrichmentHandler

	// Migration 133: Autonomous Response
	AutonomousPolicy *handlers.AutonomousPolicyHandler

	// Migration 134: Compliance Workflow
	ComplianceWorkflow *handlers.ComplianceWorkflowHandler

	// Migration 135: Predictive Analytics
	PredictiveAnalytics *handlers.PredictiveAnalyticsHandler

	// Migration 136: Forensics Automation
	ForensicsAutomation *handlers.ForensicsAutomationHandler

	// Migration 137: Supply Chain Risk
	SupplyChainRisk *handlers.SupplyChainRiskHandler

	// Migration 138: Enhanced Orchestration
	OrchestrationEnhanced *handlers.OrchestrationEnhancedHandler

	// Migration 139: Threat Hunting Campaigns
	HuntingCampaign *handlers.HuntingCampaignHandler

	// Migration 140: Compliance Auto-Remediation
	ComplianceRemediation *handlers.ComplianceRemediationHandler

	// Migration 141: Zero Trust Network Access
	ZTNA *handlers.ZTNAHandler

	// Migration 142: Security Data Warehouse
	SecurityDW *handlers.SecurityDWHandler

	// Migration 143: Endpoint Encryption Management
	EncryptionMgmt *handlers.EncryptionMgmtHandler

	// Migration 144: Patch Automation
	PatchAutomation *handlers.PatchAutomationHandler

	// Migration 145: Security Governance
	SecurityGovernance *handlers.SecurityGovernanceHandler

	// Migration 146: Network Threat Analytics
	NTA *handlers.NTAHandler

	// Migration 148: Identity Threat Detection & Response
	ITDR *handlers.ITDRHandler

	// Migration 149: CSPM Enhanced
	CSPMEnhanced *handlers.CSPMEnhancedHandler

	// Migration 150: Risk Scoring Engine
	RiskScoring *handlers.RiskScoringHandler

	// Migration 151: Automation Enhanced
	AutomationEnhanced *handlers.AutomationEnhancedHandler

	// Migration 152: Alert Routing
	AlertRouting *handlers.AlertRoutingHandler

	// Migration 153: Security Assessment
	SecurityAssessment *handlers.SecurityAssessmentHandler

	// Migration 154: Digital Risk Protection
	DRP *handlers.DRPHandler

	// Migration 155: Training Management
	TrainingMgmt *handlers.TrainingMgmtHandler

	// Migration 156: Quarantine Actions
	QuarantineActions *handlers.QuarantineActionsHandler

	// Migration 157: Security SLA
	SecuritySLA *handlers.SecuritySLAHandler

	// Migration 158: Threat Simulation
	ThreatSimulation *handlers.ThreatSimulationHandler

	// Migration 161: Vulnerability Findings
	Vulnerability *handlers.VulnerabilityHandler

	// Migration 164: Network Topology
	NetworkTopology *handlers.NetworkTopologyHandler

	// Migration 166: Security Metrics History
	SecurityMetricsHistory *handlers.SecurityMetricsHistoryHandler

	// Migration 167: Mobile Device Management

	// Migration 231: Full MDM (profiles, commands, apps, integrations)

	// Migration 232: MDM enrollment tokens + iOS protocol endpoints

	// Migration 170: Email Security (additional schema)
	// (EmailSecurity field already declared above at Task #397)

	// Migration 171: Endpoint Hardening
	EndpointHardening *handlers.EndpointHardeningHandler

	// Migration 172: Security Awareness Training
	SecurityAwareness *handlers.SecurityAwarenessHandler

	// ML-based Behavioral Analysis
	MLAnalytics *ml.MLHandler

	// ML Seed / Admin training endpoints
	MLSeed *handlers.MLSeedHandler

	// Production readiness: liveness/readiness/status probes
	Health *handlers.HealthHandler

	// Threat Hunting Query Engine
	HuntingQuery *handlers.HuntingQueryHandler

	// Migration 177: Threat Intelligence Feed Manager
	ThreatIntel *handlers.ThreatIntelHandler

	// Report Generator (structured on-demand reports)
	ReportGenerator *handlers.ReportGeneratorHandler

	// Agent Configuration Profiles
	AgentProfiles *handlers.AgentProfilesHandler

	// Security Scorecard (NIST CSF / ISO 27001)
	Scorecard *handlers.ScorecardHandler

	// Multi-tenant management lives on TenantHandler (/tenants) and
	// MultiTenantHandler (/admin/tenants), both of which read the `tenants`
	// table every tenant_id foreign key points at. There was a third handler
	// here backed by a parallel `organizations` table that nothing referenced;
	// migration 380 removed it.

	// Migration 183: AI Assistant (Claude integration)

	// Migration 183: GeoIP Threat Map
	GeoIP *handlers.GeoIPHandler

	// Migration 184: Structured Audit Log v2
	AuditV2 *handlers.AuditHandler

	// Migration 179: Sigma Rules Management API
	SigmaRules *handlers.SigmaRulesHandler

	// Migration 180: Alert Suppression Engine

	// Migration 181: SIEM Webhook Connector
	SIEMWebhook *handlers.SIEMWebhookHandler

	// Migration 182: Agent Auto-Update Manager

	// Migration 189: Alert Watchlist
	Watchlist *handlers.WatchlistHandler

	// Migration 190: License Management

	// Migration 236: Auto-update tracking (Phase 1)

	// System Status & Performance
	System *handlers.SystemHandler

	// Network Traffic Analysis
	NetAnalysis *handlers.NetAnalysisHandler

	// Memory Forensics (Migration 194)
	MemForensics *handlers.MemForensicsHandler

	// Cloud Workload Runtime Protection
	CloudRuntime *handlers.CloudRuntimeHandler

	// Detection Performance Metrics
	DetectionMetrics *handlers.DetectionMetricsHandler

	// Staged curate of SigmaHQ-synced rules
	Curate *handlers.CurateHandler

	// Mobile Threat Defense (MTD) on-device verdict ingest

	// Endpoint Compliance Checker
	ComplianceChecker *handlers.ComplianceCheckerHandler

	// Migration 185-188: User Management, API Keys Manager, Webhook Dispatcher, Config Backup
	UserMgmt     *handlers.UserManagementHandler
	APIKeysMgr   *handlers.APIKeysHandler
	WebhooksMgr  *handlers.WebhooksHandler
	ConfigBackup *handlers.ConfigBackupHandler

	// Migration 192: Process Tree API
	ProcessTree *handlers.ProcessTreeHandler

	// Migration 192: Attack Timeline API
	AttackTimeline *handlers.AttackTimelineHandler

	// Migration 192: AD/LDAP Identity Integration

	// Migration 193: Admin Scheduled Reports
	AdminReportSchedules *handlers.AdminReportSchedulesHandler

	// L-6: AI Auto-Investigation
	Investigation *handlers.InvestigationHandler

	// L-7: Compliance Auto-Evaluation (CIS/NIST/SOC2)
	ComplianceEval *handlers.ComplianceEvalHandler

	// M-3: Mobile Push Token

	// Phase 5: Support Tickets
	Support *handlers.SupportHandler

	// Batch 6: Admin Compliance Status (NIST CSF + ISO 27001)
	ComplianceStatus *handlers.ComplianceStatusHandler

	// Behavioral Baseline (endpoint-facing)
	EndpointBaseline *handlers.EndpointBaselineHandler

	// Ops Report
	OpsReport *handlers.OpsReportHandler

	// B-01: RBAC Roles & Permissions
	RBAC *handlers.RBACHandler

	// B-02: Access Review
	AccessReview *handlers.AccessReviewHandler

	// B-03: Risk Register
	RiskRegister *handlers.RiskRegisterHandler

	// B-05: Automation Workflows
	AutomationWorkflows *handlers.AutomationWorkflowsHandler

	// B-07: Feed Analytics
	FeedAnalytics *handlers.FeedAnalyticsHandler

	// B-04: Insider Threat
	InsiderThreat *handlers.InsiderThreatHandler

	// B-06: IoT/OT Security
	IoTOT *handlers.IoTOTHandler

	// B-08: Network Anomalies
	NetworkAnomalies *handlers.NetworkAnomaliesHandler

	// B-09: Cloud Workload Security
	CloudWorkload *handlers.CloudWorkloadHandler

	// C-02: TIP Integration
	TIPIntegration *handlers.TIPIntegrationHandler

	// C: Integration config settings
	IntegrationConfig *handlers.IntegrationConfigHandler

	// A: DNS Security page
	DNSSecurity *handlers.DNSSecurityHandler

	// A: Cloud Security Posture page
	CloudPosture *handlers.CloudPostureHandler

	// A: Network Traffic stats
	NetworkTraffic *handlers.NetworkTrafficHandler

	// A: FIM page (suspicious files + ignore rules)
	FIMPage *handlers.FIMPageHandler

	// A: Dark Web monitoring page
	DarkWeb *handlers.DarkWebHandler

	// A: Software Vulnerability inventory (endpoint_software heuristic fallback)
	SoftwareVulnerability *handlers.SoftwareVulnerabilityHandler

	// Platform upgrade management (real data: version from ldflags, DB history)
	PlatformUpgrade *handlers.PlatformUpgradeHandler

	// User profile: login-history, api-activity, notification-prefs
	UserProfile *handlers.UserProfileHandler

	// Remediation Engine (auto-rollback, exclusion list, webhook actions)
	Remediation *handlers.RemediationHandler
}

// NewHandlers constructs a Handlers bundle from individual handler instances.
func NewHandlers(
	agents *handlers.AgentHandler,
	alerts *handlers.AlertHandler,
	events *handlers.EventHandler,
	rules *handlers.RuleHandler,
	reports *handlers.ReportHandler,
	auth *handlers.AuthHandler,
	settings *handlers.SettingsHandler,
	users *handlers.UsersHandler,
	quarantine *handlers.QuarantineHandler,
	ioc *handlers.IOCHandler,
	suppressions *handlers.SuppressionHandler,
	incidents *handlers.IncidentHandler,
	playbooks *handlers.PlaybookHandler,
	reportSchedules *handlers.ReportScheduleHandler,
	vulns *handlers.VulnHandler,
	threatFeeds *handlers.ThreatFeedHandler,
	software *handlers.SoftwareInventoryHandler,
	search *handlers.SearchHandler,
	compliance *handlers.ComplianceHandler,
	ueba *handlers.UEBAHandler,
	notifHistory *handlers.NotificationHistoryHandler,
	socMetrics *handlers.SOCMetricsHandler,
	socQueue *handlers.SOCQueueHandler,
	campaigns *handlers.CampaignsHandler,
	ingest *handlers.IngestHandler,
	liveResponse *handlers.LiveResponseHandler,
	siem *handlers.SIEMHandler,
	virustotal *handlers.VirusTotalHandler,
	hunt *handlers.HuntHandler,
	forensics *handlers.ForensicsHandler,
	complianceReport *handlers.ComplianceReportHandler,
	tenants *handlers.TenantHandler,
	tenantRoles *handlers.TenantRolesHandler,
	tiSync *handlers.TIFeedSyncHandler,
	cloudMonitor *handlers.CloudMonitorHandler,
	download *handlers.DownloadHandler,
	sessions *handlers.SessionHandler,
	agentPolicies *handlers.AgentPolicyHandler,
	soar *handlers.SOARHandler,
	emailMFA *handlers.EmailMFAHandler,
	notifPrefs *handlers.NotificationPrefsHandler,
	webhooks *handlers.WebhookHandler,
	yaraRules *handlers.YARAHandler,
	dashboardPrefs *handlers.DashboardPrefsHandler,
	riskActions *handlers.RiskActionHandler,
	complianceScore *handlers.ComplianceScoreHandler,
	passwordPolicy *handlers.PasswordPolicyHandler,
	invitations *handlers.InvitationHandler,
	passwordReset *handlers.PasswordResetHandler,
	fim *handlers.FIMHandler,
	deviceEvents *handlers.DeviceHandler,
	apiKeys *handlers.APIKeyHandler,
	processBlock *handlers.ProcessBlockHandler,
) *Handlers {
	return &Handlers{
		agents:           agents,
		alerts:           alerts,
		events:           events,
		rules:            rules,
		reports:          reports,
		auth:             auth,
		settings:         settings,
		users:            users,
		quarantine:       quarantine,
		ioc:              ioc,
		suppressions:     suppressions,
		incidents:        incidents,
		playbooks:        playbooks,
		reportSchedules:  reportSchedules,
		vulns:            vulns,
		threatFeeds:      threatFeeds,
		software:         software,
		search:           search,
		compliance:       compliance,
		ueba:             ueba,
		notifHistory:     notifHistory,
		socMetrics:       socMetrics,
		socQueue:         socQueue,
		campaigns:        campaigns,
		ingest:           ingest,
		liveResponse:     liveResponse,
		siem:             siem,
		virustotal:       virustotal,
		hunt:             hunt,
		forensics:        forensics,
		complianceReport: complianceReport,
		tenants:          tenants,
		tenantRoles:      tenantRoles,
		tiSyncHandler:    tiSync,
		cloudMonitor:     cloudMonitor,
		download:         download,
		sessions:         sessions,
		agentPolicies:    agentPolicies,
		soar:             soar,
		emailMFA:         emailMFA,
		notifPrefs:       notifPrefs,
		webhooks:         webhooks,
		yaraRules:        yaraRules,
		dashboardPrefs:   dashboardPrefs,
		riskActions:      riskActions,
		complianceScore:  complianceScore,
		passwordPolicy:   passwordPolicy,
		invitations:      invitations,
		passwordReset:    passwordReset,
		fim:              fim,
		deviceEvents:     deviceEvents,
		apiKeys:          apiKeys,
		processBlock:     processBlock,
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
	auth := api.Group("/auth")
	auth.Use(s.rateLimiter.Middleware())
	auth.Use(mw.StrictRateLimit())
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

	// Invitation accept (public — no auth required)
	if s.handlers.invitations != nil {
		invitePublic := api.Group("/auth/invite")
		invitePublic.Use(s.rateLimiter.Middleware())
		{
			invitePublic.GET("/info", s.handlers.invitations.Info)
			invitePublic.POST("/accept", s.handlers.invitations.Accept)
		}
	}

	// Phishing simulation tracking (public — recipients are not authenticated;
	// security comes from the unguessable per-recipient token).
	if s.handlers.Phishing != nil {
		track := api.Group("/phishing/track")
		track.Use(s.rateLimiter.Middleware())
		{
			track.GET("/open/:token", s.handlers.Phishing.TrackOpen)
			track.GET("/click/:token", s.handlers.Phishing.TrackClick)
			track.GET("/report/:token", s.handlers.Phishing.TrackReport)
			track.POST("/report/:token", s.handlers.Phishing.TrackReport)
		}
	}

	// MFA setup/disable requires authentication
	authProtected := api.Group("/auth")
	authProtected.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
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
	if s.auditStore != nil {
		protected.Use(s.auditMiddleware())
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
		if s.handlers.ProcessTree != nil {
			agents.GET("/:id/process-tree", s.handlers.ProcessTree.GetProcessTree)
		} else {
			agents.GET("/:id/process-tree", s.handlers.agents.ProcessTree)
		}
		agents.GET("/:id/timeline", s.handlers.events.AgentTimeline)
		if s.handlers.software != nil {
			agents.GET("/:id/software", s.handlers.software.ListByAgent)
			agents.POST("/:id/software", s.handlers.software.Report)
		}
		if s.handlers.SoftwareDiff != nil {
			agents.GET("/:id/software/diffs", s.handlers.SoftwareDiff.GetDiffs)
			agents.GET("/:id/software/diffs/latest", s.handlers.SoftwareDiff.GetLatestDiff)
			agents.POST("/:id/software/diffs/compute", s.handlers.SoftwareDiff.ComputeDiff)
		}
	}
	// Agent Tag Management
	if s.handlers.AgentTags != nil {
		agents.GET("/:id/tags", s.handlers.AgentTags.ListTags)
		agents.POST("/:id/tags", s.handlers.AgentTags.AddTag)
		agents.DELETE("/:id/tags/:tag", s.handlers.AgentTags.RemoveTag)
		protected.GET("/agent-tags", s.handlers.AgentTags.ListAllTags)
		protected.GET("/agent-tags/:tag/agents", s.handlers.AgentTags.ListByTag)
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

	// Threat Intelligence Feeds
	if s.handlers.threatFeeds != nil {
		tf := protected.Group("/threat-feeds")
		{
			tf.GET("", s.handlers.threatFeeds.List)
			tf.POST("", s.handlers.threatFeeds.Create)
			tf.PUT("/:id", s.handlers.threatFeeds.Update)
			tf.DELETE("/:id", s.handlers.threatFeeds.Delete)
			tf.PUT("/:id/toggle", s.handlers.threatFeeds.Toggle)
			tf.POST("/:id/sync", s.handlers.threatFeeds.Sync)
		}
	}

	// Software search across all agents
	if s.handlers.software != nil {
		protected.GET("/software", s.handlers.software.Search)
		protected.DELETE("/software/:id", s.handlers.software.DeleteEntry)
	}

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
	// Alert Comments (extended: delete support + author_name)
	if s.handlers.AlertComments != nil {
		alerts.DELETE("/:id/comments/:comment_id", s.handlers.AlertComments.Delete)
	}

	// Alert bulk operations
	if s.handlers.AlertBulk != nil {
		alerts.POST("/bulk-status", mw.BulkWriteRateLimit(), s.handlers.AlertBulk.BulkStatus)
		alerts.POST("/bulk-delete", mw.BulkWriteRateLimit(), s.handlers.AlertBulk.BulkDelete)
		alerts.POST("/bulk-tag", mw.BulkWriteRateLimit(), s.handlers.AlertBulk.BulkTag)
		alerts.POST("/bulk-assign", mw.BulkWriteRateLimit(), s.handlers.AlertBulk.BulkAssign)
	}

	// Alert per-record action endpoints
	if s.handlers.AlertAction != nil {
		alerts.POST("/:id/status", s.handlers.AlertAction.UpdateStatus)
		alerts.POST("/:id/enrich", s.handlers.AlertAction.Enrich)
	}

	// Alert MITRE ATT&CK auto-classifier
	if s.handlers.AlertClassifier != nil {
		alerts.POST("/:id/classify", s.handlers.AlertClassifier.ClassifyAlert)
		alerts.POST("/classify-batch", s.handlers.AlertClassifier.BulkClassify)
	}

	// AI Auto-Investigation (L-6)
	if s.handlers.Investigation != nil {
		alerts.GET("/:id/investigation", s.handlers.Investigation.GetInvestigation)
		alerts.POST("/:id/investigate", s.handlers.Investigation.Investigate)
	}

	// Compliance Auto-Evaluation (L-7)
	if s.handlers.ComplianceEval != nil {
		compEval := protected.Group("/compliance/auto")
		{
			compEval.GET("/agents/:id", s.handlers.ComplianceEval.GetAgentReport)
			compEval.POST("/agents/:id/evaluate", s.handlers.ComplianceEval.EvaluateAgent)
			compEval.GET("/summary", s.handlers.ComplianceEval.GetOrgSummary)
		}
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

	// Detection Rules
	rules := protected.Group("/rules")
	{
		rules.GET("", s.handlers.rules.List)
		rules.GET("/:id", s.handlers.rules.Get)
		rules.POST("/:id/test", s.handlers.rules.Test)
		rules.GET("/sync/status", s.handlers.rules.SyncStatus)
		// Write operations require admin role
		rulesAdmin := rules.Group("", adminMiddleware())
		rulesAdmin.POST("", s.handlers.rules.Create)
		rulesAdmin.PUT("/:id", s.handlers.rules.Update)
		rulesAdmin.DELETE("/:id", s.handlers.rules.Delete)
		rulesAdmin.PUT("/:id/toggle", s.handlers.rules.Toggle)
		rulesAdmin.POST("/import", s.handlers.rules.Import)
		rulesAdmin.POST("/sync", s.handlers.rules.SyncCommunity)
		// AI rule generation (Professional plan required)
	}

	// Sigma Rule Import
	if s.handlers.Sigma != nil {
		protected.POST("/rules/import/sigma", s.handlers.Sigma.ImportSigma)
		protected.POST("/rules/import/sigma/preview", s.handlers.Sigma.ParsePreview)
	}

	// Reports — gated by FeatureReports (Lite/Starter/Pro/Enterprise; Free excluded).
	// /reports/ops-report is intentionally ungated below because it backs the
	// frontend dashboard summary that even Free tenants need to render.
	reports := protected.Group("/reports")
	reports.Use(apimw.RequireFeature(s.licMgr, license.FeatureReports))
	{
		reports.GET("", s.handlers.reports.List)
		reports.POST("", mw.HeavyOperationRateLimit(), s.handlers.reports.Generate)
		reports.GET("/:id", s.handlers.reports.Download)
		reports.GET("/:id/pdf", s.handlers.reports.DownloadPDF)
		reports.DELETE("/:id", s.handlers.reports.Delete)
		reports.GET("/jobs/:id", s.handlers.reports.JobStatus)
	}

	// Ops Report (frontend dashboard summary — intentionally NOT gated by
	// FeatureReports; it's the data source for the home dashboard tile that
	// Free users also see, not a downloadable report).
	if s.handlers.OpsReport != nil {
		protected.GET("/reports/ops-report", s.handlers.OpsReport.GetReport)
	}

	// Report Schedules — gated by FeatureReports (scheduling a periodic report
	// implies generating reports).
	if s.handlers.reportSchedules != nil {
		sch := protected.Group("/reports/schedules")
		sch.Use(apimw.RequireFeature(s.licMgr, license.FeatureReports))
		{
			sch.GET("", s.handlers.reportSchedules.List)
			sch.POST("", s.handlers.reportSchedules.Create)
			sch.PUT("/:id", s.handlers.reportSchedules.Update)
			sch.DELETE("/:id", s.handlers.reportSchedules.Delete)
			sch.PUT("/:id/toggle", s.handlers.reportSchedules.Toggle)
		}
	}

	// Report CSV Export — gated by FeatureReports (CSV export of alerts /
	// compliance data is functionally a generated report).
	if s.handlers.ReportExport != nil {
		reportExport := protected.Group("/reports/export")
		reportExport.Use(apimw.RequireFeature(s.licMgr, license.FeatureReports), mw.HeavyOperationRateLimit())
		{
			reportExport.GET("/alerts", s.handlers.ReportExport.ExportAlerts)
			reportExport.GET("/compliance", s.handlers.ReportExport.ExportCompliance)
		}
	}

	// Quarantined Files
	if s.handlers.quarantine != nil {
		quarantine := protected.Group("/quarantine")
		{
			quarantine.GET("", s.handlers.quarantine.List)
			quarantine.POST("", s.handlers.quarantine.Record)
			quarantine.POST("/:id/restore", s.handlers.quarantine.Restore)
			quarantine.POST("/:id/release", s.handlers.quarantine.Restore) // alias for restore
			quarantine.DELETE("/:id", s.handlers.quarantine.Delete)
		}
	}

	// IOC (Indicators of Compromise)
	if s.handlers.ioc != nil {
		ioc := protected.Group("/ioc")
		{
			ioc.GET("", s.handlers.ioc.List)
			ioc.POST("", s.handlers.ioc.Create)
			ioc.POST("/import", s.handlers.ioc.BulkImport)
			ioc.GET("/stats", s.handlers.ioc.Stats)
			ioc.DELETE("/:id", s.handlers.ioc.Delete)
			ioc.PUT("/:id/toggle", s.handlers.ioc.Toggle)
			ioc.GET("/check", s.handlers.ioc.Check)
			ioc.GET("/top-hits", s.handlers.ioc.TopHits)

			if s.handlers.IPBlock != nil {
				ioc.GET("/ip-block", s.handlers.IPBlock.List)
				ioc.POST("/ip-block", s.handlers.IPBlock.Create)
				ioc.DELETE("/ip-block/:id", s.handlers.IPBlock.Delete)
			}
		}
	}

	// Suppression Rules
	if s.handlers.suppressions != nil {
		sup := protected.Group("/suppressions")
		{
			sup.GET("", s.handlers.suppressions.List)
			sup.POST("", s.handlers.suppressions.Create)
			sup.PUT("/:id", s.handlers.suppressions.Update)
			sup.DELETE("/:id", s.handlers.suppressions.Delete)
			sup.PUT("/:id/toggle", s.handlers.suppressions.Toggle)
			sup.GET("/candidates", s.handlers.suppressions.Candidates) // 抑制候補提示
		}
	}

	// Incident Management
	if s.handlers.incidents != nil {
		inc := protected.Group("/incidents")
		{
			inc.GET("", s.handlers.incidents.List)
			inc.POST("", s.handlers.incidents.Create)
			inc.GET("/:id", s.handlers.incidents.Get)
			inc.PUT("/:id", s.handlers.incidents.Update)
			inc.DELETE("/:id", s.handlers.incidents.Delete)
			inc.POST("/:id/alerts", s.handlers.incidents.LinkAlert)
			inc.DELETE("/:id/alerts/:alert_id", s.handlers.incidents.UnlinkAlert)
			inc.GET("/:id/notes", s.handlers.incidents.ListNotes)
			inc.POST("/:id/notes", s.handlers.incidents.AddNote)
			inc.PATCH("/:id/assign", s.handlers.incidents.Assign)
			inc.PATCH("/:id/status", s.handlers.incidents.Transition)
			inc.GET("/:id/timeline", s.handlers.incidents.Timeline)
			if s.handlers.IncidentComments != nil {
				inc.GET("/:id/comments", s.handlers.IncidentComments.List)
				inc.POST("/:id/comments", s.handlers.IncidentComments.Add)
				inc.DELETE("/:id/comments/:comment_id", s.handlers.IncidentComments.Delete)
			}
		}
	}

	// Response Playbooks (Professional plan required)
	if s.handlers.playbooks != nil {
		pb := protected.Group("/playbooks")
		pb.Use(apimw.RequireFeature(s.licMgr, license.FeaturePlaybooks))
		{
			pb.GET("", s.handlers.playbooks.List)
			pb.POST("", s.handlers.playbooks.Create)
			pb.GET("/:id", s.handlers.playbooks.Get)
			pb.PUT("/:id", s.handlers.playbooks.Update)
			pb.DELETE("/:id", s.handlers.playbooks.Delete)
			pb.PUT("/:id/toggle", s.handlers.playbooks.Toggle)
			pb.GET("/:id/runs", s.handlers.playbooks.Runs)
		}
	}

	// Vulnerabilities
	if s.handlers.vulns != nil {
		vuln := protected.Group("/vulnerabilities")
		{
			vuln.GET("", s.handlers.vulns.List)
			vuln.GET("/stats", s.handlers.vulns.Stats)
			vuln.POST("", s.handlers.vulns.Create)
			vuln.GET("/:id", s.handlers.vulns.Get)
			vuln.PUT("/:id/status", s.handlers.vulns.UpdateStatus)
			vuln.DELETE("/:id", s.handlers.vulns.Delete)
		}
	}

	// Notifications
	notif := protected.Group("/notifications")
	{
		notif.GET("/channels", s.handlers.settings.ListChannels)
		notif.POST("/channels", s.handlers.settings.CreateChannel)
		notif.PUT("/channels/:id", s.handlers.settings.UpdateChannel)
		notif.DELETE("/channels/:id", s.handlers.settings.DeleteChannel)
		notif.POST("/channels/:id/test", s.handlers.settings.TestChannel)

		// Per-user email notification preferences
		if s.handlers.notifPrefs != nil {
			notif.GET("/preferences", s.handlers.notifPrefs.GetPreferences)
			notif.PUT("/preferences", s.handlers.notifPrefs.UpsertPreferences)
		}
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

	// Invitation management (admin only)
	if s.handlers.invitations != nil {
		invAdmin := protected.Group("/admin/invitations")
		invAdmin.Use(adminMiddleware())
		{
			invAdmin.POST("", s.handlers.invitations.Create)
			invAdmin.GET("", s.handlers.invitations.List)
			invAdmin.DELETE("/:id", s.handlers.invitations.Delete)
		}
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

	// Global search
	if s.handlers.search != nil {
		protected.GET("/search", s.handlers.search.Search)
		protected.POST("/search", func(c *gin.Context) {
			var body map[string]interface{}
			_ = c.ShouldBindJSON(&body)
			q, _ := body["q"].(string)
			if q == "" {
				q, _ = body["query"].(string)
			}
			if q != "" {
				c.Request.URL.RawQuery = "q=" + q
			}
			s.handlers.search.Search(c)
		})
		// Saved searches — persisted in saved_searches table
		protected.GET("/search/saved", s.savedSearchListHandler())
		protected.POST("/search/saved", s.savedSearchCreateHandler())
		protected.DELETE("/search/saved/:id", s.savedSearchDeleteHandler())
	}

	// Compliance (Enterprise plan required)
	if s.handlers.compliance != nil {
		protected.GET("/compliance/summary", apimw.RequireFeature(s.licMgr, license.FeatureCompliance), s.handlers.compliance.Summary)
		// /compliance alias expected by frontend dashboard
		protected.GET("/compliance", apimw.RequireFeature(s.licMgr, license.FeatureCompliance), s.handlers.compliance.Summary)
		protected.GET("/compliance/mitre", apimw.RequireFeature(s.licMgr, license.FeatureCompliance), s.handlers.compliance.MITREMapping)
		protected.GET("/compliance/cis", apimw.RequireFeature(s.licMgr, license.FeatureCompliance), s.handlers.compliance.CISControls)
		protected.GET("/compliance/nist", apimw.RequireFeature(s.licMgr, license.FeatureCompliance), s.handlers.compliance.NISTFramework)
	}

	// Compliance Framework Reports (SOC2 / ISO27001 / PCI-DSS) — Enterprise plan required
	if s.handlers.complianceReport != nil {
		cr := protected.Group("/compliance")
		cr.Use(apimw.RequireFeature(s.licMgr, license.FeatureCompliance))
		{
			cr.GET("/frameworks", s.handlers.complianceReport.ListFrameworks)
			cr.GET("/score/:framework_id", s.handlers.complianceReport.GetScore)
			cr.POST("/evidence", s.handlers.complianceReport.AddEvidence)
			cr.GET("/evidence/:control_id", s.handlers.complianceReport.GetEvidence)
		}
	}

	// Compliance Export (Enterprise plan required)
	if s.handlers.ComplianceExport != nil {
		protected.GET("/compliance/export", apimw.RequireFeature(s.licMgr, license.FeatureCompliance), s.handlers.ComplianceExport.Export)
		protected.GET("/compliance/export/summary", apimw.RequireFeature(s.licMgr, license.FeatureCompliance), s.handlers.ComplianceExport.ExportSummary)
	}

	// Tenant Management (admin only)
	if s.handlers.tenants != nil {
		tnts := protected.Group("/tenants")
		tnts.Use(adminMiddleware())
		{
			tnts.GET("", s.handlers.tenants.List)
			tnts.POST("", s.handlers.tenants.Create)
			tnts.GET("/:id", s.handlers.tenants.Get)
			tnts.PATCH("/:id", s.handlers.tenants.Update)
			tnts.DELETE("/:id", s.handlers.tenants.Delete)
			// Tenant-scoped RBAC: global admin OR tenant_admin of that tenant
			if s.handlers.tenantRoles != nil {
				scopedRoles := protected.Group("/tenants")
				scopedRoles.Use(s.tenantScopedAdminMiddleware())
				{
					scopedRoles.GET("/:id/roles", s.handlers.tenantRoles.List)
					scopedRoles.GET("/:id/roles/:user_id", s.handlers.tenantRoles.Get)
					scopedRoles.PUT("/:id/roles/:user_id", s.handlers.tenantRoles.Upsert)
					scopedRoles.DELETE("/:id/roles/:user_id", s.handlers.tenantRoles.Delete)
				}
			}
		}
	}

	// TI Feed Sync History & Stats
	if s.handlers.tiSyncHandler != nil {
		protected.GET("/threat-feeds/stats", s.handlers.tiSyncHandler.GetStats)
		protected.GET("/threat-feeds/:id/history", s.handlers.tiSyncHandler.GetHistory)
	}

	// IOC Enrichment & Threat Intel Search (Professional plan required)
	if s.handlers.IOCEnrichment != nil {
		ti := protected.Group("/threat-intel")
		ti.Use(apimw.RequireFeature(s.licMgr, license.FeatureThreatIntel))
		ti.POST("/enrich", s.handlers.IOCEnrichment.Enrich)
		ti.POST("/enrich/bulk", s.handlers.IOCEnrichment.BulkEnrich)
		ti.GET("/search", s.handlers.IOCEnrichment.Search)
		// STIX 2.1 bundle import/export. Makes the platform's IOC set
		// interoperable with external threat-intel tooling in both directions.
		if s.handlers.STIX != nil {
			ti.POST("/stix/import", s.handlers.STIX.Import)
			ti.GET("/stix/export", s.handlers.STIX.Export)
		}
	}

	// Cloud Workload Monitoring
	if s.handlers.cloudMonitor != nil {
		cloud := protected.Group("/cloud")
		{
			cloud.GET("/integrations", s.handlers.cloudMonitor.ListIntegrations)
			cloud.POST("/integrations", s.handlers.cloudMonitor.CreateIntegration)
			cloud.PATCH("/integrations/:id", s.handlers.cloudMonitor.UpdateIntegration)
			cloud.DELETE("/integrations/:id", s.handlers.cloudMonitor.DeleteIntegration)
			cloud.POST("/integrations/:id/test", s.handlers.cloudMonitor.TestConnection)
			cloud.GET("/events", s.handlers.cloudMonitor.ListEvents)
		}
	}

	// UEBA
	if s.handlers.ueba != nil {
		protected.GET("/ueba/summary", s.handlers.ueba.Summary)
	}

	// Notification history
	if s.handlers.notifHistory != nil {
		protected.GET("/notification-history", s.handlers.notifHistory.List)
		protected.GET("/notification-history/stats", s.handlers.notifHistory.Stats)
	}

	// SOC Metrics
	if s.handlers.socMetrics != nil {
		protected.GET("/soc-metrics/summary", s.handlers.socMetrics.Summary)
		protected.GET("/soc-metrics/handover", s.handlers.socMetrics.ShiftHandover)
		protected.GET("/soc/metrics", s.handlers.socMetrics.FrontendMetrics)
	}

	// SOC Work Queue — 1人SOC向け優先度付きタスクキュー
	if s.handlers.socQueue != nil {
		protected.GET("/soc/work-queue", s.handlers.socQueue.WorkQueue)
	}

	// Threat Campaigns
	if s.handlers.campaigns != nil {
		protected.GET("/campaigns", s.handlers.campaigns.List)
		protected.POST("/campaigns", s.handlers.campaigns.Create)
		protected.PUT("/campaigns/:id", s.handlers.campaigns.Update)
		protected.DELETE("/campaigns/:id", s.handlers.campaigns.Delete)
	}

	// Live Response (JWT-protected sessions)
	if s.handlers.liveResponse != nil {
		lr := protected.Group("/agents/:id/live-response")
		{
			lr.POST("/sessions", s.handlers.liveResponse.CreateSession)
			lr.GET("/sessions", s.handlers.liveResponse.ListSessions)
			lr.DELETE("/sessions/:sid", s.handlers.liveResponse.CloseSession)
			lr.POST("/sessions/:sid/exec", mw.LiveResponseRateLimit(), s.handlers.liveResponse.ExecCommand)
			lr.GET("/sessions/:sid/commands", s.handlers.liveResponse.GetCommands)
			lr.GET("/sessions/:sid/stream", s.handlers.liveResponse.StreamOutput)
		}
		// Agent-facing endpoints — token auth only, no JWT
		lrAgent := api.Group("/live-response")
		{
			lrAgent.GET("/poll", s.handlers.liveResponse.AgentPoll)
			lrAgent.POST("/output", s.handlers.liveResponse.AgentOutput)
		}
	}

	// Live Response Command Queue (analyst-facing + agent-facing)
	if s.handlers.LiveResponseCmdQueue != nil {
		// Analyst-facing routes
		agentCmds := protected.Group("/agents/:id/commands")
		{
			agentCmds.GET("", s.handlers.LiveResponseCmdQueue.ListCommands)
			agentCmds.POST("", mw.LiveResponseRateLimit(), s.handlers.LiveResponseCmdQueue.CreateCommand)
			agentCmds.GET("/:cmd_id", s.handlers.LiveResponseCmdQueue.GetCommand)
			agentCmds.DELETE("/:cmd_id", s.handlers.LiveResponseCmdQueue.CancelCommand)
		}
		// Agent-facing routes (JWT auth, agent_id from token or query param)
		agentPoll := protected.Group("/agent/commands")
		{
			agentPoll.GET("/poll", s.handlers.LiveResponseCmdQueue.PollCommands)
			agentPoll.POST("/:cmd_id/result", s.handlers.LiveResponseCmdQueue.SubmitResult)
		}
	}

	// SIEM Targets (Professional plan required)
	if s.handlers.siem != nil {
		siemGroup := protected.Group("/siem/targets")
		siemGroup.Use(apimw.RequireFeature(s.licMgr, license.FeatureSIEM))
		siemGroup.Use(adminMiddleware())
		{
			siemGroup.GET("", s.handlers.siem.List)
			siemGroup.POST("", s.handlers.siem.Create)
			siemGroup.PUT("/:id", s.handlers.siem.Update)
			siemGroup.DELETE("/:id", s.handlers.siem.Delete)
			siemGroup.POST("/:id/test", s.handlers.siem.TestForward)
		}
	}

	// Threat Intel — VirusTotal (Professional plan required)
	if s.handlers.virustotal != nil {
		intel := protected.Group("/intel")
		intel.Use(apimw.RequireFeature(s.licMgr, license.FeatureThreatIntel))
		{
			intel.POST("/vt/lookup", s.handlers.virustotal.Lookup)
		}
	}

	// Threat Hunting — Saved Hunts + Search (Professional plan required)
	if s.handlers.hunt != nil {
		huntGroup := protected.Group("/threat-hunting")
		huntGroup.Use(apimw.RequireFeature(s.licMgr, license.FeatureThreatHunting))
		{
			huntGroup.GET("/search", s.handlers.hunt.Search)
			huntGroup.GET("/saved", s.handlers.hunt.ListSavedHunts)
			huntGroup.POST("/saved", s.handlers.hunt.CreateSavedHunt)
			huntGroup.DELETE("/saved/:id", s.handlers.hunt.DeleteSavedHunt)
			huntGroup.POST("/saved/:id/run", s.handlers.hunt.RecordRun)
		}
	}

	// Saved Hunt Queries (Professional plan required)
	if s.handlers.SavedHunt != nil {
		savedHunt := protected.Group("/hunt/saved")
		savedHunt.Use(apimw.RequireFeature(s.licMgr, license.FeatureThreatHunting))
		{
			savedHunt.GET("", s.handlers.SavedHunt.List)
			savedHunt.POST("", s.handlers.SavedHunt.Create)
			savedHunt.PUT("/:id", s.handlers.SavedHunt.Update)
			savedHunt.DELETE("/:id", s.handlers.SavedHunt.Delete)
		}
	}

	// Forensics Jobs (Enterprise plan required)
	if s.handlers.forensics != nil {
		forensics := protected.Group("/forensics")
		forensics.Use(apimw.RequireFeature(s.licMgr, license.FeatureForensics))
		{
			forensics.POST("/jobs", s.handlers.forensics.CreateJob)
			forensics.GET("/jobs", s.handlers.forensics.ListJobs)
			forensics.GET("/jobs/:id", s.handlers.forensics.GetJob)
			forensics.GET("/jobs/:id/download", s.handlers.forensics.DownloadArtifact)
			forensics.DELETE("/jobs/:id", s.handlers.forensics.DeleteJob)
			forensics.POST("/jobs/:id/result", s.handlers.forensics.SubmitResult)
		}
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

	// Agent Policies
	if s.handlers.agentPolicies != nil {
		ap := protected.Group("/agent-policies")
		{
			ap.GET("", s.handlers.agentPolicies.List)
			ap.GET("/:id", s.handlers.agentPolicies.Get)
		}
		apAdmin := protected.Group("/agent-policies")
		apAdmin.Use(adminMiddleware())
		{
			apAdmin.POST("", s.handlers.agentPolicies.Create)
			apAdmin.PUT("/:id", s.handlers.agentPolicies.Update)
			apAdmin.DELETE("/:id", s.handlers.agentPolicies.Delete)
		}
		// Assign policy to group (admin only)
		protected.PUT("/groups/:id/policy", s.handlers.agentPolicies.Assign)
	}

	// YARA Rules (Professional plan required)
	if s.handlers.yaraRules != nil {
		// Read endpoints — all authenticated users
		yr := protected.Group("/yara-rules")
		yr.Use(apimw.RequireFeature(s.licMgr, license.FeatureYARA))
		{
			yr.GET("", s.handlers.yaraRules.List)
			yr.GET("/enabled", s.handlers.yaraRules.ListEnabled)
			yr.GET("/:id", s.handlers.yaraRules.Get)
			yr.POST("/:id/match", s.handlers.yaraRules.RecordMatch)
		}
		// Write endpoints — admin only
		yrAdmin := protected.Group("/yara-rules")
		yrAdmin.Use(apimw.RequireFeature(s.licMgr, license.FeatureYARA))
		yrAdmin.Use(adminMiddleware())
		{
			yrAdmin.POST("", s.handlers.yaraRules.Create)
			yrAdmin.PUT("/:id", s.handlers.yaraRules.Update)
			yrAdmin.DELETE("/:id", s.handlers.yaraRules.Delete)
			yrAdmin.PATCH("/:id/toggle", s.handlers.yaraRules.Toggle)
			yrAdmin.POST("/:id/test", s.handlers.yaraRules.TestRule)
			yrAdmin.GET("/:id/results", s.handlers.yaraRules.GetScanResults)
			yrAdmin.GET("/stats", s.handlers.yaraRules.GetStats)
			// GitHub コミュニティルール同期
			yrAdmin.POST("/sync", s.handlers.yaraRules.SyncStart)
			yrAdmin.GET("/sync/status", s.handlers.yaraRules.SyncStatus)
			yrAdmin.POST("/reclassify", s.handlers.yaraRules.ReclassifyCategories)
			// スキャンジョブ管理
			yrAdmin.POST("/scan-request", s.yaraScanRequestHandler())
			yrAdmin.GET("/scan-jobs", s.yaraScanJobsHandler())
		}
		// 利用状況メトリクス（adminのみ）
		protected.GET("/admin/adoption-metrics", adminMiddleware(), s.adoptionMetricsHandler())
		{
		}
	}

	// Incident Playbook Management (Task #372) — Professional plan required
	if s.handlers.IncidentPlaybook != nil {
		ipbAdmin := protected.Group("/playbooks/incident")
		ipbAdmin.Use(apimw.RequireFeature(s.licMgr, license.FeaturePlaybooks))
		ipbAdmin.Use(adminMiddleware())
		{
			ipbAdmin.GET("", s.handlers.IncidentPlaybook.List)
			ipbAdmin.POST("", s.handlers.IncidentPlaybook.Create)
			ipbAdmin.GET("/:id", s.handlers.IncidentPlaybook.Get)
			ipbAdmin.PUT("/:id", s.handlers.IncidentPlaybook.Update)
			ipbAdmin.DELETE("/:id", s.handlers.IncidentPlaybook.Delete)
		}
		// Execute and track executions — auth only (no admin required)
		ipb := protected.Group("/playbooks/incident")
		ipb.Use(apimw.RequireFeature(s.licMgr, license.FeaturePlaybooks))
		{
			ipb.POST("/:id/execute", s.handlers.IncidentPlaybook.Execute)
			ipb.GET("/executions/:execId", s.handlers.IncidentPlaybook.GetExecution)
			ipb.POST("/executions/:execId/steps/:stepId/complete", s.handlers.IncidentPlaybook.CompleteStep)
		}
	}

	// Cloud Asset Inventory (Task #373)
	if s.handlers.CloudAsset != nil {
		ca := protected.Group("/cloud-assets")
		{
			ca.GET("", s.handlers.CloudAsset.List)
			ca.GET("/stats", s.handlers.CloudAsset.GetStats)
			ca.POST("/sync", s.handlers.CloudAsset.Upsert)
			ca.GET("/:id", s.handlers.CloudAsset.Get)
			ca.DELETE("/:id", s.handlers.CloudAsset.Delete)
			ca.POST("/:id/risk", s.handlers.CloudAsset.UpdateRisk)
		}
	}

	// DLP Rules Management (Task #374)
	if s.handlers.DLP != nil {
		dlpAdmin := protected.Group("/admin/dlp")
		dlpAdmin.Use(adminMiddleware())
		{
			dlpAdmin.GET("/rules", s.handlers.DLP.ListRules)
			dlpAdmin.POST("/rules", s.handlers.DLP.CreateRule)
			dlpAdmin.PUT("/rules/:id", s.handlers.DLP.UpdateRule)
			dlpAdmin.DELETE("/rules/:id", s.handlers.DLP.DeleteRule)
			dlpAdmin.POST("/rules/:id/toggle", s.handlers.DLP.ToggleRule)
			dlpAdmin.GET("/violations", s.handlers.DLP.ListViolations)
			dlpAdmin.GET("/stats", s.handlers.DLP.GetStats)
		}
	}

	// Asset Criticality Scoring (Task #378)
	if s.handlers.AssetCriticality != nil {
		ep := protected.Group("/endpoints")
		{
			// **一覧の経路がありませんでした**（実測 2026-08-12）。画面は
			// ここから資産を取りますが、登録してあるのは下の3本だけで、
			// gin は 404 を返していました —— `useQuery` の失敗は空配列に
			// なるので、**資産が1台も無い画面**として出ます。
			ep.GET("/criticality", s.handlers.AssetCriticality.List)
			ep.GET("/:id/criticality", s.handlers.AssetCriticality.GetScore)
			ep.POST("/criticality/bulk", s.handlers.AssetCriticality.BulkScore)
			ep.PUT("/:id/criticality", s.handlers.AssetCriticality.SetManualScore)
			// **手動にしたあと、自動計算に戻す経路がありませんでした。**
			// 行を消せば、次の表示から計算値に戻ります。
			ep.DELETE("/:id/criticality", s.handlers.AssetCriticality.ClearManualScore)
		}
	}

	// SOAR (Jira / ServiceNow) — Enterprise plan required
	if s.handlers.soar != nil {
		soarGroup := protected.Group("/soar")
		soarGroup.Use(apimw.RequireFeature(s.licMgr, license.FeatureSOAR))
		soarAdmin := soarGroup.Group("/configs")
		soarAdmin.Use(adminMiddleware())
		{
			soarAdmin.GET("", s.handlers.soar.ListConfigs)
			soarAdmin.POST("", s.handlers.soar.CreateConfig)
			soarAdmin.PATCH("/:id", s.handlers.soar.UpdateConfig)
			soarAdmin.DELETE("/:id", s.handlers.soar.DeleteConfig)
			soarAdmin.POST("/:id/test", s.handlers.soar.TestConfig)
		}
		// Manual ticket creation from an incident (all authenticated users)
		protected.POST("/incidents/:id/ticket", apimw.RequireFeature(s.licMgr, license.FeatureSOAR), s.handlers.soar.CreateTicket)
	}

	// Password Reset (public routes)
	if s.handlers.passwordReset != nil {
		pwReset := api.Group("/auth/password-reset")
		pwReset.Use(s.rateLimiter.Middleware())
		{
			pwReset.POST("/request", s.handlers.passwordReset.RequestReset)
			pwReset.POST("/confirm", s.handlers.passwordReset.ConfirmReset)
		}
	}

	// Email MFA
	if s.handlers.emailMFA != nil {
		emailMFAPublic := api.Group("/auth/mfa/email")
		emailMFAPublic.Use(s.rateLimiter.Middleware())
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

	// Webhooks (admin only)
	if s.handlers.webhooks != nil {
		wh := protected.Group("/webhooks")
		wh.Use(adminMiddleware())
		{
			wh.GET("", s.handlers.webhooks.List)
			wh.POST("", s.handlers.webhooks.Create)
			wh.PUT("/:id", s.handlers.webhooks.Update)
			wh.DELETE("/:id", s.handlers.webhooks.Delete)
			wh.PATCH("/:id/toggle", s.handlers.webhooks.Toggle)
			wh.POST("/:id/test", s.handlers.webhooks.Test)
			wh.GET("/:id/deliveries", s.handlers.webhooks.GetDeliveryLog)
			wh.PUT("/:id/retry-policy", s.handlers.webhooks.UpdateRetryPolicy)
			wh.PUT("/:id/event-types", s.handlers.webhooks.UpdateEventTypes)
		}
	}

	// Alert Notification Channels (admin only)
	if s.handlers.Notification != nil {
		notif := protected.Group("/admin/notifications")
		notif.Use(adminMiddleware())
		{
			notif.GET("", s.handlers.Notification.List)
			notif.POST("", s.handlers.Notification.Create)
			notif.PUT("/:id", s.handlers.Notification.Update)
			notif.DELETE("/:id", s.handlers.Notification.Delete)
			notif.POST("/:id/test", s.handlers.Notification.TestChannel)
			notif.POST("/test-email", func(c *gin.Context) {
				var req struct {
					To       string `json:"to"`
					Template string `json:"template"`
				}
				if err := c.ShouldBindJSON(&req); err != nil || req.To == "" {
					c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "to と template は必須です"})
					return
				}
				sender := email.NewSenderFromEnv()
				if sender == nil {
					c.JSON(http.StatusOK, gin.H{"ok": false, "error": "SMTP_HOSTが設定されていません"})
					return
				}
				baseURL := sender.BaseURL()
				if baseURL == "" {
					baseURL = "https://edr.example.com"
				}
				ctx := c.Request.Context()
				var err error
				switch req.Template {
				case "alert":
					err = sender.SendAlertNotification(ctx, req.To, "テストアラート — SQLインジェクション検出", "TEST-HOST-01", "Sigma/SQLi Detection", baseURL+"/alerts/test", 9)
				case "digest":
					err = sender.SendWeeklyDigest(ctx, req.To, 42, 5, 12, 31, "2026-03-17", "2026-03-23")
				case "onboarding":
					err = sender.SendOnboardingWelcome(ctx, req.To, "テストユーザー", baseURL+"/dashboard")
				default:
					c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "テンプレートは alert / digest / onboarding のいずれかです"})
					return
				}
				if err != nil {
					c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"ok": true})
			})
		}
	}

	// Risk Action Rules (admin only)
	if s.handlers.riskActions != nil {
		ra := protected.Group("/risk-actions")
		ra.Use(adminMiddleware())
		{
			ra.GET("", s.handlers.riskActions.List)
			ra.POST("", s.handlers.riskActions.Create)
			ra.PUT("/:id", s.handlers.riskActions.Update)
			ra.DELETE("/:id", s.handlers.riskActions.Delete)
			ra.PATCH("/:id/toggle", s.handlers.riskActions.Toggle)
		}
	}

	// Dashboard summary
	protected.GET("/dashboard", s.handlers.alerts.Dashboard)

	// Dashboard widget preferences
	if s.handlers.dashboardPrefs != nil {
		protected.GET("/preferences/dashboard", s.handlers.dashboardPrefs.GetPrefs)
		protected.PUT("/preferences/dashboard", s.handlers.dashboardPrefs.UpsertPrefs)
		// Aliases expected by the frontend
		protected.GET("/dashboard/preferences", s.handlers.dashboardPrefs.GetPrefs)
		protected.PUT("/dashboard/preferences", s.handlers.dashboardPrefs.UpsertPrefs)
	}

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
	}

	// True WebSocket endpoint — gorilla/websocket, JWT already applied by protected group
	if s.handlers.WebSocket != nil {
		protected.GET("/ws", s.handlers.WebSocket.Handle)
	}

	// Ingest endpoints (public, token-auth only)
	if s.handlers.ingest != nil {
		ingestGroup := api.Group("/ingest")
		ingestGroup.POST("/wazuh", s.handlers.ingest.WazuhAlert)
		ingestGroup.GET("/wazuh/status", s.handlers.ingest.WazuhStatus)
	}

	// Agent heartbeat — public endpoint, no JWT required (agent-facing)
	api.POST("/agents/:id/heartbeat", s.handlers.agents.Heartbeat)

	// Agent software inventory report — public endpoint, no JWT required (agent-facing)
	if s.handlers.software != nil {
		api.POST("/agents/:id/software/report", s.handlers.software.Report)
	}

	// Agent disk-encryption status report — public endpoint, no JWT required (agent-facing).
	// Persists one row per agent into endpoint_encryption (upsert); the compliance
	// scorer's PR.DS-1 (data-at-rest protection) control counts these rows.
	if s.pool != nil {
		api.POST("/agents/:id/encryption/report", func(c *gin.Context) {
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
		api.POST("/agents/:id/hardening/report", func(c *gin.Context) {
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

	// Agent YARA rule distribution — public endpoint, no JWT required (agent-facing).
	// The agent polls this to load enabled YARA rules into its scanner (the
	// JWT-protected /yara-rules/enabled is for the UI, not reachable by agents).
	if s.handlers.yaraRules != nil {
		api.GET("/agents/:id/yara-rules", s.handlers.yaraRules.AgentEnabledRules)
	}

	// Agent scan results report — public endpoint, no JWT required (agent-facing)
	api.POST("/agents/:id/scan-results", s.handlers.agents.ReportScanResults)

	// Agent quarantine completion report — public endpoint (agent-facing).
	// The protected /quarantine POST is for human/UI callers; the agent
	// posts here so it can authenticate via mTLS / agent-id without a JWT.
	api.POST("/agents/:id/quarantine-result", s.handlers.agents.ReportQuarantineResult)

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
		s.router.GET("/api/v1/health/detailed", s.handlers.DetailedHealth.DetailedHealth)
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

	// CIS Benchmark compliance auto-scoring
	if s.handlers.complianceScore != nil {
		cs := protected.Group("/compliance/scores")
		{
			cs.GET("", s.handlers.complianceScore.ListScores)
			cs.GET("/:agent_id", s.handlers.complianceScore.GetScore)
			cs.POST("/:agent_id/compute", s.handlers.complianceScore.ComputeScore)
		}
	}

	// File Integrity Monitoring (FIM) rules
	if s.handlers.fim != nil {
		// Read — all authenticated users
		fimRead := protected.Group("/fim-rules")
		{
			fimRead.GET("", s.handlers.fim.List)
		}
		// Write — admin only
		fimAdmin := protected.Group("/fim-rules")
		fimAdmin.Use(adminMiddleware())
		{
			fimAdmin.POST("", s.handlers.fim.Create)
			fimAdmin.PUT("/:id", s.handlers.fim.Update)
			fimAdmin.DELETE("/:id", s.handlers.fim.Delete)
			fimAdmin.PATCH("/:id/toggle", s.handlers.fim.Toggle)
		}
	}

	// Device Events (USB/external device connect/disconnect)
	if s.handlers.deviceEvents != nil {
		dev := protected.Group("/device-events")
		{
			dev.GET("", s.handlers.deviceEvents.List)
			dev.GET("/stats", s.handlers.deviceEvents.Stats)
		}
	}

	// API Key Management (Enterprise plan required)
	if s.handlers.apiKeys != nil {
		ak := protected.Group("/api-keys")
		ak.Use(apimw.RequireFeature(s.licMgr, license.FeatureAPIAccess))
		{
			ak.GET("", s.handlers.apiKeys.List)
			ak.POST("", s.handlers.apiKeys.Create)
			ak.DELETE("/:id", s.handlers.apiKeys.Revoke)
		}
	}

	// Process Execution Block Rules
	if s.handlers.processBlock != nil {
		// Agent-facing read endpoint — unauthenticated (agents poll without a JWT).
		s.router.GET("/api/v1/process-rules/agent/:agent_id", s.handlers.processBlock.ListForAgent)

		// UI-facing read endpoint (authenticated).
		prRead := protected.Group("/process-rules")
		{
			prRead.GET("", s.handlers.processBlock.List)
		}
		prAdmin := protected.Group("/process-rules")
		prAdmin.Use(adminMiddleware())
		{
			prAdmin.POST("", s.handlers.processBlock.Create)
			prAdmin.PUT("/:id", s.handlers.processBlock.Update)
			prAdmin.DELETE("/:id", s.handlers.processBlock.Delete)
			prAdmin.PATCH("/:id/toggle", s.handlers.processBlock.Toggle)
		}
	}

	// Backup & Restore (admin only)
	if s.handlers.Backup != nil {
		backupAdmin := protected.Group("/admin/backups")
		backupAdmin.Use(adminMiddleware())
		{
			backupAdmin.GET("", s.handlers.Backup.List)
			backupAdmin.POST("", s.handlers.Backup.Create)
			backupAdmin.DELETE("/:name", s.handlers.Backup.Delete)
			backupAdmin.GET("/:name/download", s.handlers.Backup.Download)
		}
	}

	// ─── Migration 185-188: Enhanced User Management ──────────────────
	if s.handlers.UserMgmt != nil {
		// Admin user management
		adminUsers := protected.Group("/admin/users")
		adminUsers.Use(adminMiddleware())
		{
			adminUsers.GET("/stats", s.handlers.UserMgmt.GetStats)
			adminUsers.GET("", s.handlers.UserMgmt.ListUsers)
			adminUsers.POST("", s.handlers.UserMgmt.CreateUser)
			adminUsers.GET("/:id", s.handlers.UserMgmt.GetUser)
			adminUsers.PUT("/:id", s.handlers.UserMgmt.UpdateUser)
			adminUsers.DELETE("/:id", s.handlers.UserMgmt.DeleteUser)
			adminUsers.POST("/:id/reset-password", s.handlers.UserMgmt.ResetPassword)
			adminUsers.PUT("/:id/role", s.handlers.UserMgmt.ChangeRole)
			adminUsers.PUT("/:id/mfa", s.handlers.UserMgmt.ToggleMFA)
		}
		// Self-service profile endpoints
		protected.GET("/profile", s.handlers.UserMgmt.GetProfile)
		protected.PUT("/profile", s.handlers.UserMgmt.UpdateProfile)
		protected.PUT("/profile/password", s.handlers.UserMgmt.ChangePassword)
	}

	// ─── Migration 186: API Keys Manager ──────────────────────────────
	if s.handlers.APIKeysMgr != nil {
		ak := protected.Group("/apikeys")
		{
			ak.GET("", s.handlers.APIKeysMgr.ListKeys)
			ak.POST("", s.handlers.APIKeysMgr.CreateKey)
			ak.DELETE("/:id", s.handlers.APIKeysMgr.RevokeKey)
		}
		akAdmin := protected.Group("/admin/apikeys")
		akAdmin.Use(adminMiddleware())
		{
			akAdmin.GET("", s.handlers.APIKeysMgr.AdminListAllKeys)
		}
	}

	// ─── Migration 187: Webhook Dispatcher ────────────────────────────
	if s.handlers.WebhooksMgr != nil {
		wbAdmin := protected.Group("/admin/webhooks")
		wbAdmin.Use(adminMiddleware())
		{
			wbAdmin.GET("", s.handlers.WebhooksMgr.ListConfigs)
			wbAdmin.POST("", s.handlers.WebhooksMgr.CreateConfig)
			wbAdmin.PUT("/:id", s.handlers.WebhooksMgr.UpdateConfig)
			wbAdmin.DELETE("/:id", s.handlers.WebhooksMgr.DeleteConfig)
			wbAdmin.PUT("/:id/toggle", s.handlers.WebhooksMgr.ToggleConfig)
			wbAdmin.POST("/:id/test", s.handlers.WebhooksMgr.TestWebhook)
			wbAdmin.GET("/:id/deliveries", s.handlers.WebhooksMgr.GetDeliveries)
		}
	}

	// ─── Migration 188: Config Backup & Restore ───────────────────────
	if s.handlers.ConfigBackup != nil {
		cbAdmin := protected.Group("/admin/backup")
		cbAdmin.Use(adminMiddleware())
		{
			cbAdmin.POST("/create", s.handlers.ConfigBackup.CreateBackup)
			cbAdmin.POST("/restore", s.handlers.ConfigBackup.RestoreBackup)
			cbAdmin.GET("/list", s.handlers.ConfigBackup.ListBackups)
		}
	}

	// Audit Log SIEM Export
	if s.handlers.AuditExport != nil {
		protected.GET("/audit-logs/export", s.handlers.AuditExport.Export)
	}

	// Agent mTLS Certificate Enrollment
	// GetCA is public (agents need it to bootstrap trust). Enroll is protected.
	if s.handlers.Cert != nil {
		// Public: any agent can fetch the CA cert to configure trust.
		agentsCertPublic := api.Group("/agents")
		agentsCertPublic.GET("/:id/cert/ca", s.handlers.Cert.GetCA)
		// Protected: enroll requires authentication.
		agents.POST("/:id/cert/enroll", s.handlers.Cert.Enroll)
	}

	// OpenAPI / Swagger UI
	handlers.RegisterDocsRoutes(s.router)
	if s.handlers.Docs != nil {
		s.router.GET("/api/v1/docs", s.handlers.Docs.ServeUI)
		s.router.GET("/api/v1/docs/openapi.yaml", s.handlers.Docs.ServeSpec)
	}

	// Rule Import/Export
	if s.handlers.RulesIE != nil {
		rulesIE := protected.Group("/rules")
		rulesIE.GET("/export", s.handlers.RulesIE.Export)
		rulesIE.GET("/counts", s.handlers.RulesIE.Counts)
		rulesIE.POST("/import/bulk", s.handlers.RulesIE.Import)
		rulesIE.POST("/import/dry-run", s.handlers.RulesIE.ImportDryRun)
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

	// Detection Rule dry-run / test endpoint
	if s.handlers.RuleTest != nil {
		protected.POST("/rules/test", s.handlers.RuleTest.Test)
	}

	// Elasticsearch log shipping admin endpoints
	if s.handlers.ES != nil {
		es := protected.Group("/admin/elasticsearch")
		es.Use(adminMiddleware())
		{
			es.POST("/test", s.handlers.ES.Test)
			es.POST("/flush", s.handlers.ES.Flush)
		}
	}

	// Custom Notification Templates (admin only)
	if s.handlers.NotifTemplate != nil {
		tmpl := protected.Group("/admin/notification-templates")
		tmpl.Use(adminMiddleware())
		{
			tmpl.GET("", s.handlers.NotifTemplate.List)
			tmpl.POST("", s.handlers.NotifTemplate.Create)
			tmpl.PUT("/:id", s.handlers.NotifTemplate.Update)
			tmpl.DELETE("/:id", s.handlers.NotifTemplate.Delete)
		}
	}

	// Email Verification (send requires auth; confirm is public)
	if s.handlers.EmailVerify != nil {
		// Public: token confirm (linked from email)
		evPublic := api.Group("/auth/email-verification")
		evPublic.POST("/confirm", s.handlers.EmailVerify.ConfirmVerification)

		// Protected: send verification email and check status
		evProtected := authProtected.Group("/email-verification")
		{
			evProtected.POST("/send", s.handlers.EmailVerify.SendVerification)
			evProtected.GET("/status", s.handlers.EmailVerify.GetStatus)
		}
	}

	// HTML Report (printable to PDF via browser) — gated by FeatureReports.
	if s.handlers.PDFReport != nil {
		protected.GET("/reports/html", apimw.RequireFeature(s.licMgr, license.FeatureReports), s.handlers.PDFReport.GenerateHTML)
	}

	// User Preferences
	if s.handlers.UserPreferences != nil {
		protected.GET("/user/preferences", s.handlers.UserPreferences.Get)
		protected.PUT("/user/preferences", s.handlers.UserPreferences.Update)
	}
	if s.handlers.Favorites != nil {
		protected.GET("/user/favorites", s.handlers.Favorites.Get)
		protected.PUT("/user/favorites", s.handlers.Favorites.Set)
	}

	// Agent Config Schema & Per-Agent Overrides
	if s.handlers.AgentConfig != nil {
		s.router.GET("/api/v1/agent-config/schema", s.handlers.AgentConfig.GetSchema)
		agents.GET("/:id/effective-config", s.handlers.AgentConfig.GetEffective)
		agents.PUT("/:id/config-override", s.handlers.AgentConfig.UpdateOverride)
	}

	// Alert Auto-Assignment Rules
	if s.handlers.AlertAssign != nil {
		aar := protected.Group("/alert-assign-rules")
		{
			aar.GET("", s.handlers.AlertAssign.List)
			aar.POST("", s.handlers.AlertAssign.Create)
			aar.PUT("/:id", s.handlers.AlertAssign.Update)
			aar.DELETE("/:id", s.handlers.AlertAssign.Delete)
		}
	}

	// Alert Escalation Rules (admin only)
	if s.handlers.EscalationRules != nil {
		er := protected.Group("/escalation-rules")
		er.Use(adminMiddleware())
		{
			er.GET("", s.handlers.EscalationRules.List)
			er.POST("", s.handlers.EscalationRules.Create)
			er.PUT("/:id", s.handlers.EscalationRules.Update)
			er.DELETE("/:id", s.handlers.EscalationRules.Delete)
			er.PATCH("/:id/toggle", s.handlers.EscalationRules.Toggle)
		}
	}

	// Correlation Rules (admin only)
	if s.handlers.Correlation != nil {
		cr := protected.Group("/correlation-rules")
		cr.Use(adminMiddleware())
		{
			cr.GET("", s.handlers.Correlation.List)
			cr.POST("", s.handlers.Correlation.Create)
			cr.GET("/:id", s.handlers.Correlation.Get)
			cr.PUT("/:id", s.handlers.Correlation.Update)
			cr.DELETE("/:id", s.handlers.Correlation.Delete)
			cr.PUT("/:id/toggle", s.handlers.Correlation.Toggle)
		}
	}

	// Correlation Engine Rules (trigger/follow pairs, admin only)
	if s.handlers.CorrelationEngine != nil {
		ce := protected.Group("/correlation-engine")
		ce.Use(adminMiddleware())
		{
			ce.GET("", s.handlers.CorrelationEngine.List)
			ce.POST("", s.handlers.CorrelationEngine.Create)
			ce.GET("/:id", s.handlers.CorrelationEngine.Get)
			ce.PUT("/:id", s.handlers.CorrelationEngine.Update)
			ce.DELETE("/:id", s.handlers.CorrelationEngine.Delete)
			ce.POST("/:id/toggle", s.handlers.CorrelationEngine.Toggle)
		}
	}

	// Packet Captures
	if s.handlers.PacketCapture != nil {
		pcap := protected.Group("/packet-captures")
		{
			pcap.GET("", s.handlers.PacketCapture.List)
			pcap.POST("", s.handlers.PacketCapture.Create)
			pcap.GET("/:id", s.handlers.PacketCapture.Get)
			pcap.POST("/:id/cancel", s.handlers.PacketCapture.Cancel)
			pcap.GET("/:id/download", s.handlers.PacketCapture.Download)
			pcap.DELETE("/:id", s.handlers.PacketCapture.Delete)
		}
	}

	// Unified Data Export
	if s.handlers.Export != nil {
		protected.POST("/export", s.handlers.Export.Export)
		protected.GET("/export/status", s.handlers.Export.GetExportStatus)
	}

	// Auto Response Rules (admin only)
	if s.handlers.AutoResponse != nil {
		ar := protected.Group("/auto-response")
		ar.Use(adminMiddleware())
		{
			ar.GET("", s.handlers.AutoResponse.List)
			ar.POST("", s.handlers.AutoResponse.Create)
			ar.GET("/:id", s.handlers.AutoResponse.Get)
			ar.PUT("/:id", s.handlers.AutoResponse.Update)
			ar.DELETE("/:id", s.handlers.AutoResponse.Delete)
			ar.POST("/:id/toggle", s.handlers.AutoResponse.Toggle)
			ar.GET("/:id/executions", s.handlers.AutoResponse.ListExecutions)
		}
	}

	// Custom Alert Rules (admin only)
	if s.handlers.CustomAlertRules != nil {
		car := protected.Group("/custom-alert-rules")
		car.Use(adminMiddleware())
		{
			car.GET("", s.handlers.CustomAlertRules.List)
			car.POST("", s.handlers.CustomAlertRules.Create)
			car.GET("/:id", s.handlers.CustomAlertRules.Get)
			car.PUT("/:id", s.handlers.CustomAlertRules.Update)
			car.DELETE("/:id", s.handlers.CustomAlertRules.Delete)
			car.POST("/:id/toggle", s.handlers.CustomAlertRules.Toggle)
		}
	}

	// Metrics API (authenticated)
	if s.handlers.MetricsAPI != nil {
		metricsGroup := protected.Group("/metrics")
		{
			metricsGroup.GET("/alert-trends", s.handlers.MetricsAPI.AlertTrends)
			metricsGroup.GET("/top-agents", s.handlers.MetricsAPI.TopAgents)
			metricsGroup.GET("/detection-stats", s.handlers.MetricsAPI.DetectionStats)
			metricsGroup.GET("/agent-stats", s.handlers.MetricsAPI.AgentStats)
		}
	}

	// Global Security Timeline (authenticated)
	if s.handlers.Timeline != nil {
		protected.GET("/timeline", s.handlers.Timeline.GetTimeline)
	}

	// ─── System Settings (admin only) ─────────────────────────────────────
	if s.handlers.SystemSettings != nil {
		sysSettings := protected.Group("/admin/system-settings")
		sysSettings.Use(adminMiddleware())
		{
			sysSettings.GET("", s.handlers.SystemSettings.GetAll)
			sysSettings.GET("/maintenance", s.handlers.SystemSettings.GetMaintenanceMode)
			sysSettings.PUT("", s.handlers.SystemSettings.BulkUpdate)
			sysSettings.PUT("/:key", s.handlers.SystemSettings.Update)
		}
	}

	// ─── Report Templates ──────────────────────────────────────────────────
	if s.handlers.ReportTemplates != nil {
		rt := protected.Group("/report-templates")
		{
			rt.GET("", s.handlers.ReportTemplates.List)
			rt.POST("", s.handlers.ReportTemplates.Create)
			rt.GET("/:id", s.handlers.ReportTemplates.Get)
			rt.PUT("/:id", s.handlers.ReportTemplates.Update)
			rt.DELETE("/:id", s.handlers.ReportTemplates.Delete)
			rt.POST("/:id/preview", s.handlers.ReportTemplates.Preview)
		}
	}

	// ─── Log Ingestion (public, token-based auth) ─────────────────────────
	if s.handlers.LogIngestion != nil {
		api.POST("/ingest/:source_name", s.handlers.LogIngestion.Ingest)

		// Admin log-source management (requires JWT auth)
		adminLogSources := protected.Group("/admin/log-sources")
		{
			adminLogSources.GET("", s.handlers.LogIngestion.ListSources)
			adminLogSources.POST("", s.handlers.LogIngestion.CreateSource)
			adminLogSources.DELETE("/:id", s.handlers.LogIngestion.DeleteSource)
			adminLogSources.GET("/:id/stats", s.handlers.LogIngestion.GetSourceStats)
		}
	}

	// Onboarding Wizard Status
	if s.handlers.Onboarding != nil {
		adminOnboarding := protected.Group("/admin/onboarding")
		adminOnboarding.Use(adminMiddleware())
		{
			adminOnboarding.GET("", s.handlers.Onboarding.GetStatus)
		}
	}

	// Maintenance Windows (admin only)
	if s.handlers.MaintenanceWindow != nil {
		mw := protected.Group("/admin/maintenance-windows")
		mw.Use(adminMiddleware())
		{
			mw.GET("", s.handlers.MaintenanceWindow.List)
			mw.POST("", s.handlers.MaintenanceWindow.Create)
			mw.GET("/status", s.handlers.MaintenanceWindow.GetStatus)
			mw.GET("/:id", s.handlers.MaintenanceWindow.Get)
			mw.PUT("/:id", s.handlers.MaintenanceWindow.Update)
			mw.DELETE("/:id", s.handlers.MaintenanceWindow.Delete)
		}
	}

	// 2FA Recovery Codes (authenticated)
	if s.handlers.RecoveryCodes != nil {
		rc := protected.Group("/auth/recovery-codes")
		{
			rc.POST("/generate", s.handlers.RecoveryCodes.Generate)
			rc.POST("/verify", s.handlers.RecoveryCodes.Verify)
			rc.GET("/status", s.handlers.RecoveryCodes.ListStatus)
			rc.POST("/regenerate", s.handlers.RecoveryCodes.Regenerate)
		}
	}

	// Network Map
	if s.handlers.NetworkMap != nil {
		network := protected.Group("/network")
		{
			network.GET("/topology", s.handlers.NetworkMap.GetTopology)
			network.GET("/subnets", s.handlers.NetworkMap.GetSubnets)
		}
	}

	// SIEM Connector (outbound syslog/CEF to external SIEM) — admin only
	// SIEM Outbound Connector (Professional plan required)
	if s.handlers.SIEMConnector != nil {
		sc := protected.Group("/admin/siem-connector")
		sc.Use(apimw.RequireFeature(s.licMgr, license.FeatureSIEM))
		sc.Use(adminMiddleware())
		{
			sc.GET("", s.handlers.SIEMConnector.GetConfig)
			sc.PUT("", s.handlers.SIEMConnector.SaveConfig)
			sc.POST("/test", s.handlers.SIEMConnector.Test)
			sc.GET("/stats", s.handlers.SIEMConnector.GetStats)
		}
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

	// GeoIP Lookup
	if s.handlers.Geolocation != nil {
		geo := protected.Group("/geo")
		{
			geo.GET("/lookup", s.handlers.Geolocation.Lookup)
			geo.POST("/lookup/bulk", s.handlers.Geolocation.BulkLookup)
		}
	}

	// SSE Event Stream — token auth via ?token= query param supported by extractBearerToken.
	// Route is added to the unauthenticated api group so that the long-lived GET request
	// is not subject to JSON audit logging; auth is still enforced by authMiddleware via
	// the token query param path.
	if s.handlers.EventStream != nil {
		v1 := s.router.Group("/api/v1")
		v1.GET("/stream", s.handlers.EventStream.Stream)
	}

	// EDR Policy Management (admin only)
	if s.handlers.EDRPolicy != nil {
		ep := protected.Group("/admin/edr-policies")
		ep.Use(adminMiddleware())
		{
			ep.GET("", s.handlers.EDRPolicy.List)
			ep.POST("", s.handlers.EDRPolicy.Create)
			ep.GET("/:id", s.handlers.EDRPolicy.Get)
			ep.PUT("/:id", s.handlers.EDRPolicy.Update)
			ep.DELETE("/:id", s.handlers.EDRPolicy.Delete)
			ep.POST("/:id/toggle", s.handlers.EDRPolicy.Toggle)
			ep.POST("/:id/assign", s.handlers.EDRPolicy.AssignToGroup)
			ep.POST("/:id/assign-agent", s.handlers.EDRPolicy.AssignToAgent)
			ep.GET("/:id/assignments", s.handlers.EDRPolicy.GetAssignments)
		}
	}

	// Audit Log Digital Signing (admin only)
	if s.handlers.AuditSign != nil {
		auditSign := protected.Group("/admin/audit")
		auditSign.Use(adminMiddleware())
		{
			auditSign.GET("/signed-export", s.handlers.AuditSign.ExportSigned)
			auditSign.POST("/verify-signature", s.handlers.AuditSign.VerifySignature)
		}
	}

	// Honeypot/Deception Management (Task #380) — admin only
	if s.handlers.Honeypot != nil {
		hp := protected.Group("/admin/honeypots")
		hp.Use(adminMiddleware())
		{
			hp.GET("", s.handlers.Honeypot.List)
			hp.GET("/stats", s.handlers.Honeypot.GetStats)
			hp.POST("", s.handlers.Honeypot.Create)
			hp.GET("/:id", s.handlers.Honeypot.Get)
			hp.PUT("/:id", s.handlers.Honeypot.Update)
			hp.DELETE("/:id", s.handlers.Honeypot.Delete)
			hp.POST("/:id/toggle", s.handlers.Honeypot.Toggle)
			hp.GET("/:id/accesses", s.handlers.Honeypot.GetAccesses)
			hp.POST("/:id/simulate", s.handlers.Honeypot.SimulateAccess)
		}
	}

	// Container/Kubernetes Workload Monitoring (Task #381)
	if s.handlers.Container != nil {
		ct := protected.Group("/containers")
		{
			ct.GET("/workloads", s.handlers.Container.ListWorkloads)
			ct.GET("/workloads/sync", s.handlers.Container.UpsertWorkload)
			ct.POST("/workloads/sync", s.handlers.Container.UpsertWorkload)
			ct.GET("/workloads/:id", s.handlers.Container.GetWorkload)
			ct.GET("/workloads/:id/events", s.handlers.Container.GetWorkloadEvents)
			ct.GET("/stats", s.handlers.Container.GetStats)
			ct.GET("/clusters", s.handlers.Container.ListClusters)
		}
	}

	// Malware Sandbox Integration (Task #382)
	if s.handlers.Sandbox != nil {
		sb := protected.Group("/sandbox")
		{
			sb.POST("/submit", s.handlers.Sandbox.SubmitFile)
			sb.POST("/analyze", s.handlers.Sandbox.AnalyzeUpload)
			sb.POST("/detonate", s.handlers.Sandbox.Detonate)
			sb.GET("/detonate/:jobId", s.handlers.Sandbox.DetonateReport)
			sb.GET("/submissions", s.handlers.Sandbox.ListSubmissions)
			sb.GET("/stats", s.handlers.Sandbox.GetStats)
			sb.GET("/:submissionId", s.handlers.Sandbox.GetResult)
		}
	}

	// SOC Workflow Automation (Task #387)
	if s.handlers.SOCTicket != nil {
		soc := protected.Group("/soc/tickets")
		{
			soc.GET("", s.handlers.SOCTicket.List)
			soc.GET("/stats", s.handlers.SOCTicket.GetStats)
			soc.POST("", s.handlers.SOCTicket.Create)
			soc.POST("/from-alert", s.handlers.SOCTicket.CreateFromAlert)
			soc.GET("/:id", s.handlers.SOCTicket.Get)
			soc.PUT("/:id", s.handlers.SOCTicket.Update)
			soc.POST("/:id/close", s.handlers.SOCTicket.Close)
			soc.POST("/:id/comments", s.handlers.SOCTicket.AddComment)
		}
	}

	// Zero Trust Access Policy Management (Task #389)
	if s.handlers.ZeroTrust != nil {
		// Policy CRUD — admin only
		ztAdmin := protected.Group("/zero-trust/policies")
		ztAdmin.Use(adminMiddleware())
		{
			ztAdmin.GET("", s.handlers.ZeroTrust.ListPolicies)
			ztAdmin.POST("", s.handlers.ZeroTrust.CreatePolicy)
			ztAdmin.GET("/:id", s.handlers.ZeroTrust.GetPolicy)
			ztAdmin.PUT("/:id", s.handlers.ZeroTrust.UpdatePolicy)
			ztAdmin.DELETE("/:id", s.handlers.ZeroTrust.DeletePolicy)
			ztAdmin.POST("/:id/toggle", s.handlers.ZeroTrust.TogglePolicy)
		}
		// Evaluate and logs — all authenticated users
		zt := protected.Group("/zero-trust")
		{
			zt.POST("/evaluate", s.handlers.ZeroTrust.EvaluateAccess)
			zt.GET("/access-logs", s.handlers.ZeroTrust.GetAccessLogs)
			zt.GET("/stats", s.handlers.ZeroTrust.GetStats)
		}
	}

	// Privileged Access Management (Task #394)
	if s.handlers.PAM != nil {
		pam := protected.Group("/pam")
		{
			pam.GET("/requests", s.handlers.PAM.ListRequests)
			pam.GET("/requests/:id", s.handlers.PAM.GetRequest)
			pam.POST("/requests", s.handlers.PAM.CreateRequest)
			pam.GET("/sessions", s.handlers.PAM.ListSessions)
			pam.POST("/sessions/:id/end", s.handlers.PAM.EndSession)
			pam.GET("/stats", s.handlers.PAM.GetStats)
		}
		pamAdmin := protected.Group("/pam")
		pamAdmin.Use(adminMiddleware())
		{
			pamAdmin.POST("/requests/:id/approve", s.handlers.PAM.ApproveRequest)
			pamAdmin.POST("/requests/:id/deny", s.handlers.PAM.DenyRequest)
		}
	}

	// Zero Trust Engine (in-memory, resource+trust based)
	if s.handlers.ZeroTrustEngine != nil {
		ztEngine := protected.Group("/admin/zero-trust/engine")
		{
			ztEngine.GET("/policies", s.handlers.ZeroTrustEngine.GetPolicies)
			ztEngine.POST("/policies", s.handlers.ZeroTrustEngine.CreatePolicy)
			ztEngine.PUT("/policies/:id", s.handlers.ZeroTrustEngine.UpdatePolicy)
			ztEngine.DELETE("/policies/:id", s.handlers.ZeroTrustEngine.DeletePolicy)
			ztEngine.GET("/postures", s.handlers.ZeroTrustEngine.GetPostures)
			ztEngine.POST("/evaluate/:agent_id", s.handlers.ZeroTrustEngine.EvaluateDevice)
			ztEngine.GET("/check", s.handlers.ZeroTrustEngine.CheckAccess)
		}
	}

	// XDR Cross-Domain Detection Engine
	if s.handlers.XDR != nil {
		xdrGrp := protected.Group("/admin/xdr")
		{
			xdrGrp.GET("/stats", s.handlers.XDR.GetStats)
			xdrGrp.POST("/correlate", s.handlers.XDR.Correlate)
			xdrGrp.GET("/events", s.handlers.XDR.GetRecentEvents)
			xdrGrp.POST("/events", s.handlers.XDR.IngestEvent)
		}
	}

	// Email Security Integration (Task #397)
	if s.handlers.EmailSecurity != nil {
		email := protected.Group("/email")
		{
			email.GET("/events", s.handlers.EmailSecurity.ListEvents)
			email.GET("/events/:id", s.handlers.EmailSecurity.GetEvent)
			email.POST("/analyze", s.handlers.EmailSecurity.AnalyzeEmail)
			email.POST("/ingest", s.handlers.EmailSecurity.IngestEvent)
			email.GET("/stats", s.handlers.EmailSecurity.GetFrontendStats)
			email.GET("/trend", s.handlers.EmailSecurity.GetThreatTrend)
			email.GET("/threats", s.handlers.EmailSecurity.ListThreats)
			email.GET("/attachments", s.handlers.EmailSecurity.ListAttachments)
			email.GET("/urls", s.handlers.EmailSecurity.ListURLScans)
			email.GET("/senders", s.handlers.EmailSecurity.ListSenders)
		}
	}

	// Asset Discovery (Task #403)
	if s.handlers.AssetDiscovery != nil {
		disc := protected.Group("/discovery")
		disc.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
		{
			disc.GET("/assets", s.handlers.AssetDiscovery.ListAssets)
			disc.GET("/assets/:id", s.handlers.AssetDiscovery.GetAsset)
			disc.POST("/assets/:id/mark-managed", s.handlers.AssetDiscovery.MarkManaged)
			disc.GET("/stats", s.handlers.AssetDiscovery.GetStats)
			disc.POST("/scan", s.handlers.AssetDiscovery.StartScan)
			disc.GET("/scans", s.handlers.AssetDiscovery.ListScans)
			disc.GET("/scans/:id", s.handlers.AssetDiscovery.GetScanStatus)
		}
	}

	// Security Awareness Training (Task #404)
	if s.handlers.Training != nil {
		training := protected.Group("/training")
		{
			training.GET("/campaigns", s.handlers.Training.ListCampaigns)
			training.GET("/campaigns/:id", s.handlers.Training.GetCampaign)
			training.GET("/campaigns/:id/results", s.handlers.Training.GetResults)
			training.POST("/campaigns/:id/simulate-click", s.handlers.Training.SimulateClick)
			training.GET("/stats", s.handlers.Training.GetStats)
		}
		trainingAdmin := protected.Group("/training")
		trainingAdmin.Use(adminMiddleware())
		{
			trainingAdmin.POST("/campaigns", s.handlers.Training.CreateCampaign)
			trainingAdmin.POST("/campaigns/:id/launch", s.handlers.Training.LaunchCampaign)
		}
	}

	// Vulnerability Remediation Tracking (Task #407)
	if s.handlers.VulnRemediation != nil {
		vr := protected.Group("/vuln-remediations")
		{
			vr.GET("", s.handlers.VulnRemediation.List)
			vr.GET("/stats", s.handlers.VulnRemediation.GetStats)
			vr.POST("", s.handlers.VulnRemediation.Create)
			vr.POST("/bulk-assign", s.handlers.VulnRemediation.BulkAssign)
			vr.GET("/:id", s.handlers.VulnRemediation.Get)
			vr.PUT("/:id", s.handlers.VulnRemediation.Update)
			vr.POST("/:id/verify", s.handlers.VulnRemediation.Verify)
		}
	}

	// Third-Party/Supply Chain Risk Management (Task #411)
	if s.handlers.VendorRisk != nil {
		vr := protected.Group("/vendor-risk")
		vr.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
		{
			vr.GET("/vendors", s.handlers.VendorRisk.ListVendors)
			vr.GET("/vendors/:id", s.handlers.VendorRisk.GetVendor)
			vr.POST("/vendors", s.handlers.VendorRisk.CreateVendor)
			vr.PUT("/vendors/:id", s.handlers.VendorRisk.UpdateVendor)
			vr.POST("/vendors/:id/assessments", s.handlers.VendorRisk.CreateAssessment)
			vr.GET("/stats", s.handlers.VendorRisk.GetStats)
		}
		vrAdmin := protected.Group("/vendor-risk")
		vrAdmin.Use(adminMiddleware())
		{
			vrAdmin.DELETE("/vendors/:id", s.handlers.VendorRisk.DeleteVendor)
		}
	}

	// Wireless/IoT Security Monitoring (Task #413)
	if s.handlers.Wireless != nil {
		wl := protected.Group("/wireless")
		wl.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
		{
			wl.GET("/networks", s.handlers.Wireless.ListNetworks)
			wl.POST("/networks", s.handlers.Wireless.UpsertNetwork)
			wl.POST("/networks/:id/authorize", s.handlers.Wireless.AuthorizeNetwork)
			wl.GET("/iot", s.handlers.Wireless.ListIoTDevices)
			wl.POST("/iot", s.handlers.Wireless.UpsertIoTDevice)
			wl.GET("/stats", s.handlers.Wireless.GetStats)
		}
	}

	// Incident Response Automation / SOAR-lite (Task #414) — Enterprise plan required
	if s.handlers.SOARWorkflow != nil {
		sw := protected.Group("/soar/workflows")
		sw.Use(apimw.RequireFeature(s.licMgr, license.FeatureSOAR))
		sw.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
		{
			sw.GET("", s.handlers.SOARWorkflow.ListWorkflows)
			sw.GET("/:id", s.handlers.SOARWorkflow.GetWorkflow)
			sw.POST("/:id/toggle", s.handlers.SOARWorkflow.ToggleWorkflow)
			sw.POST("/:id/trigger", s.handlers.SOARWorkflow.TriggerWorkflow)
		}
		swAdmin := protected.Group("/soar/workflows")
		swAdmin.Use(apimw.RequireFeature(s.licMgr, license.FeatureSOAR))
		swAdmin.Use(adminMiddleware())
		{
			swAdmin.POST("", s.handlers.SOARWorkflow.CreateWorkflow)
			swAdmin.PUT("/:id", s.handlers.SOARWorkflow.UpdateWorkflow)
			swAdmin.DELETE("/:id", s.handlers.SOARWorkflow.DeleteWorkflow)
		}
		soarEx := protected.Group("/soar")
		soarEx.Use(apimw.RequireFeature(s.licMgr, license.FeatureSOAR))
		soarEx.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
		{
			soarEx.GET("/executions", s.handlers.SOARWorkflow.ListExecutions)
			soarEx.GET("/executions/:id", s.handlers.SOARWorkflow.GetExecution)
			soarEx.GET("/stats", s.handlers.SOARWorkflow.GetStats)
		}
	}

	// SOC Shift Handover System (Task #417)
	if s.handlers.Shift != nil {
		sh := protected.Group("/soc/shifts")
		sh.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
		{
			sh.GET("", s.handlers.Shift.List)
			sh.GET("/current", s.handlers.Shift.GetCurrentShift)
			sh.GET("/stats", s.handlers.Shift.GetStats)
			sh.POST("/start", s.handlers.Shift.StartShift)
			sh.GET("/:id", s.handlers.Shift.Get)
			sh.POST("/:id/end", s.handlers.Shift.EndShift)
			sh.PUT("/:id/notes", s.handlers.Shift.UpdateNotes)
		}
	}

	// Patch Management System (Task #421)
	if s.handlers.Patch != nil {
		patches := protected.Group("/patches")
		{
			patches.GET("", s.handlers.Patch.ListDeployments)
			patches.GET("/stats", s.handlers.Patch.GetStats)
			patches.GET("/:id", s.handlers.Patch.GetDeployment)
			patches.GET("/:id/results", s.handlers.Patch.GetResults)
			patches.POST("/:id/schedule", s.handlers.Patch.ScheduleDeployment)
			patches.PUT("/:id", s.handlers.Patch.UpdateDeployment)
		}
		patchAdmin := protected.Group("/patches")
		patchAdmin.Use(adminMiddleware())
		{
			patchAdmin.POST("", s.handlers.Patch.CreateDeployment)
			patchAdmin.DELETE("/:id", s.handlers.Patch.DeleteDeployment)
			patchAdmin.POST("/:id/deploy", s.handlers.Patch.DeployNow)
		}
	}

	// Security Knowledge Base (Task #423)
	if s.handlers.KnowledgeBase != nil {
		kb := protected.Group("/knowledge-base")
		{
			kb.GET("", s.handlers.KnowledgeBase.List)
			kb.GET("/search", s.handlers.KnowledgeBase.Search)
			kb.GET("/stats", s.handlers.KnowledgeBase.GetStats)
			kb.GET("/slug/:slug", s.handlers.KnowledgeBase.GetBySlug)
			kb.GET("/:id", s.handlers.KnowledgeBase.Get)
			kb.POST("/:id/vote", s.handlers.KnowledgeBase.Vote)
		}
		kbAdmin := protected.Group("/knowledge-base")
		kbAdmin.Use(adminMiddleware())
		{
			kbAdmin.POST("", s.handlers.KnowledgeBase.Create)
			kbAdmin.PUT("/:id", s.handlers.KnowledgeBase.Update)
			kbAdmin.DELETE("/:id", s.handlers.KnowledgeBase.Delete)
		}
	}

	// Privacy/GDPR Compliance Management (Task #427)
	if s.handlers.GDPR != nil {
		priv := protected.Group("/privacy")
		{
			priv.GET("/subjects", s.handlers.GDPR.ListSubjects)
			priv.GET("/stats", s.handlers.GDPR.GetStats)
			priv.GET("/incidents", s.handlers.GDPR.ListPrivacyIncidents)
			priv.GET("/dsar", s.handlers.GDPR.ListDSARs)
			priv.POST("/dsar", s.handlers.GDPR.CreateDSAR)
			priv.POST("/dsar/:id/complete", s.handlers.GDPR.CompleteDSAR)
		}
		privAdmin := protected.Group("/privacy")
		privAdmin.Use(adminMiddleware())
		{
			privAdmin.POST("/subjects", s.handlers.GDPR.CreateSubject)
			privAdmin.PUT("/subjects/:id", s.handlers.GDPR.UpdateSubject)
			privAdmin.DELETE("/subjects/:id", s.handlers.GDPR.DeleteSubject)
			privAdmin.POST("/incidents", s.handlers.GDPR.CreateIncident)
			privAdmin.PUT("/incidents/:id", s.handlers.GDPR.UpdateIncident)
		}
	}

	// Agent Auto-Remediation Engine (Task #430)
	if s.handlers.AutoRemediation != nil {
		agents.POST("/:id/remediate", s.handlers.AutoRemediation.ExecuteAction)
		agents.GET("/:id/remediation-history", s.handlers.AutoRemediation.GetActionHistory)
		bulkRem := protected.Group("/agents")
		bulkRem.POST("/bulk-remediate", s.handlers.AutoRemediation.BulkRemediate)
		protected.GET("/remediation/stats", s.handlers.AutoRemediation.GetStats)
	}

	// Security Metrics Historical API (Task #431)
	if s.handlers.MetricsHistory != nil {
		metricsHist := protected.Group("/metrics")
		metricsHist.Use(authMiddleware(s.handlers.auth.JWTSecret, s.handlers.auth.Blocklist, s.handlers.auth.UserCache, s.apiKeyStore))
		{
			metricsHist.POST("", s.handlers.MetricsHistory.Record)
			metricsHist.GET("/query", s.handlers.MetricsHistory.Query)
			metricsHist.GET("/latest", s.handlers.MetricsHistory.GetLatest)
			metricsHist.GET("/summary", s.handlers.MetricsHistory.GetSummary)
			metricsHist.GET("/names", s.handlers.MetricsHistory.ListMetricNames)
		}
	}

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

	// OAuth2/OIDC Client Management (Task #433)
	if s.handlers.OAuth2 != nil {
		oauth2 := protected.Group("/admin/oauth2")
		oauth2.Use(adminMiddleware())
		{
			oauth2.GET("", s.handlers.OAuth2.ListClients)
			oauth2.POST("", s.handlers.OAuth2.CreateClient)
			oauth2.GET("/:id", s.handlers.OAuth2.GetClient)
			oauth2.PUT("/:id", s.handlers.OAuth2.UpdateClient)
			oauth2.DELETE("/:id", s.handlers.OAuth2.DeleteClient)
			oauth2.POST("/:id/rotate-secret", s.handlers.OAuth2.RotateSecret)
			oauth2.POST("/:id/toggle", s.handlers.OAuth2.ToggleClient)
		}
	}

	// OnCall / PagerDuty / OpsGenie Alerting Integration (Task #440)
	if s.handlers.OnCall != nil {
		oc := protected.Group("/admin/oncall")
		oc.Use(adminMiddleware())
		{
			oc.GET("", s.handlers.OnCall.ListIntegrations)
			oc.POST("", s.handlers.OnCall.CreateIntegration)
			oc.GET("/:id", s.handlers.OnCall.GetIntegration)
			oc.PUT("/:id", s.handlers.OnCall.UpdateIntegration)
			oc.DELETE("/:id", s.handlers.OnCall.DeleteIntegration)
			oc.POST("/:id/toggle", s.handlers.OnCall.ToggleIntegration)
			oc.POST("/:id/test", s.handlers.OnCall.TestIntegration)
			oc.GET("/:id/events", s.handlers.OnCall.GetEvents)
		}
		protected.POST("/oncall/trigger", s.handlers.OnCall.TriggerAlert)
	}

	// Service Account Management (Task #441)
	if s.handlers.ServiceAccount != nil {
		sa := protected.Group("/admin/service-accounts")
		sa.Use(adminMiddleware())
		{
			sa.GET("", s.handlers.ServiceAccount.List)
			sa.POST("", s.handlers.ServiceAccount.Create)
			sa.GET("/:id", s.handlers.ServiceAccount.Get)
			sa.PUT("/:id", s.handlers.ServiceAccount.Update)
			sa.DELETE("/:id", s.handlers.ServiceAccount.Delete)
			sa.POST("/:id/rotate", s.handlers.ServiceAccount.RotateSecret)
			sa.POST("/:id/toggle", s.handlers.ServiceAccount.Toggle)
		}
	}

	// Feature Flags Management (Task #442)
	if s.handlers.FeatureFlag != nil {
		ffAdmin := protected.Group("/admin/feature-flags")
		ffAdmin.Use(adminMiddleware())
		{
			ffAdmin.GET("", s.handlers.FeatureFlag.List)
			ffAdmin.POST("", s.handlers.FeatureFlag.Create)
			ffAdmin.GET("/:id", s.handlers.FeatureFlag.Get)
			ffAdmin.PUT("/:id", s.handlers.FeatureFlag.Update)
			ffAdmin.DELETE("/:id", s.handlers.FeatureFlag.Delete)
			ffAdmin.POST("/:id/toggle", s.handlers.FeatureFlag.Toggle)
			ffAdmin.POST("/:id/rollout", s.handlers.FeatureFlag.SetRollout)
		}
		// Open to authMiddleware (all authenticated users)
		protected.GET("/feature-flags/by-name/:name", s.handlers.FeatureFlag.GetByName)
		protected.POST("/feature-flags/evaluate", s.handlers.FeatureFlag.Evaluate)
	}

	// Behavioral Baseline
	if s.handlers.EndpointBaseline != nil {
		eb := protected.Group("/endpoints/baselines")
		eb.GET("", s.handlers.EndpointBaseline.ListBaselines)
		eb.GET("/config", s.handlers.EndpointBaseline.GetConfig)
		eb.PUT("/config", s.handlers.EndpointBaseline.SaveConfig)
		eb.GET("/:id", s.handlers.EndpointBaseline.GetBaseline)
	}

	// Endpoint Tagging System (Task #443)
	if s.handlers.EndpointTag != nil {
		protected.GET("/endpoints/:id/tags", s.handlers.EndpointTag.GetTags)
		protected.POST("/endpoints/:id/tags", s.handlers.EndpointTag.AddTag)
		protected.DELETE("/endpoints/:id/tags/:tag", s.handlers.EndpointTag.RemoveTag)
		protected.POST("/endpoints/tags/bulk-add", s.handlers.EndpointTag.BulkAddTag)
		protected.POST("/endpoints/tags/bulk-remove", s.handlers.EndpointTag.BulkRemoveTag)
		protected.GET("/endpoints/tags/all", s.handlers.EndpointTag.ListAllTags)
		protected.GET("/endpoints/tags/search", s.handlers.EndpointTag.SearchByTag)
	}

	// Alert Digest (Task #450)
	if s.handlers.Digest != nil {
		digestAdmin := protected.Group("/admin/digest")
		digestAdmin.Use(adminMiddleware())
		{
			digestAdmin.POST("/trigger", s.handlers.Digest.TriggerDigest)
			digestAdmin.GET("/config", s.handlers.Digest.GetDigestConfig)
			digestAdmin.PUT("/config", s.handlers.Digest.UpdateDigestConfig)
			digestAdmin.GET("/history", s.handlers.Digest.GetDigestHistory)
			digestAdmin.GET("/stats", s.handlers.Digest.GetDigestStats)
		}
	}

	// TAXII 2.1 Server (Task #451)
	if s.handlers.TAXII != nil {
		taxii := s.router.Group("/taxii2")
		{
			taxii.GET("/", s.handlers.TAXII.GetDiscovery)
			taxii.GET("/api1/", s.handlers.TAXII.GetAPIRoot)
			taxii.GET("/api1/collections/", s.handlers.TAXII.GetCollections)
			taxii.GET("/api1/collections/:id/", s.handlers.TAXII.GetCollection)
			taxii.GET("/api1/collections/:id/objects/", s.handlers.TAXII.GetObjects)
		}
		// POST requires auth — attach to protected group
		taxiiProtected := protected.Group("/taxii2")
		{
			taxiiProtected.POST("/api1/collections/:id/objects/", s.handlers.TAXII.AddObjects)
		}
	}

	// Agent Auto-Enrollment (Task #452)
	if s.handlers.Enrollment != nil {
		// Public enrollment request endpoint — guarded by agent limit.
		api.POST("/enrollment/request", apimw.EnforceAgentLimit(s.licMgr), s.handlers.Enrollment.RequestEnrollment)
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

	// Multi-tenant management
	if s.handlers.MultiTenant != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		tenants := admin.Group("/tenants")
		{
			tenants.GET("", s.handlers.MultiTenant.ListTenants)
			tenants.POST("", s.handlers.MultiTenant.CreateTenant)
			tenants.GET("/:id", s.handlers.MultiTenant.GetTenant)
			tenants.PUT("/:id", s.handlers.MultiTenant.UpdateTenant)
			tenants.DELETE("/:id", s.handlers.MultiTenant.DeleteTenant)
			tenants.PUT("/:id/quota", s.handlers.MultiTenant.UpdateQuota)
			tenants.GET("/:id/audit", s.handlers.MultiTenant.GetTenantAuditLog)
			tenants.GET("/:id/stats", s.handlers.MultiTenant.GetTenantStats)
		}
	}

	// Log analysis
	if s.handlers.LogAnalysis != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		logAnalysis := admin.Group("/log-analysis")
		{
			logAnalysis.GET("/rules", s.handlers.LogAnalysis.ListParseRules)
			logAnalysis.POST("/rules", s.handlers.LogAnalysis.CreateParseRule)
			logAnalysis.PUT("/rules/:id", s.handlers.LogAnalysis.UpdateParseRule)
			logAnalysis.DELETE("/rules/:id", s.handlers.LogAnalysis.DeleteParseRule)
			logAnalysis.POST("/rules/:id/test", s.handlers.LogAnalysis.TestParseRule)
			logAnalysis.GET("/jobs", s.handlers.LogAnalysis.ListJobs)
			logAnalysis.POST("/jobs", s.handlers.LogAnalysis.CreateJob)
			logAnalysis.GET("/jobs/:id", s.handlers.LogAnalysis.GetJobResults)
		}
	}

	// Deception technology (Migration 116) — Enterprise plan required
	if s.handlers.Deception != nil {
		admin := protected.Group("/admin")
		admin.Use(apimw.RequireFeature(s.licMgr, license.FeatureDeception))
		admin.Use(adminMiddleware())
		deception := admin.Group("/deception")
		{
			deception.GET("/traps", s.handlers.Deception.ListTraps)
			deception.POST("/traps", s.handlers.Deception.CreateTrap)
			deception.PUT("/traps/:id", s.handlers.Deception.UpdateTrap)
			deception.DELETE("/traps/:id", s.handlers.Deception.DeleteTrap)
			deception.POST("/traps/:id/toggle", s.handlers.Deception.ToggleTrap)
			deception.GET("/events", s.handlers.Deception.ListEvents)
			deception.GET("/events/:id", s.handlers.Deception.GetEventDetail)
			deception.POST("/traps/:id/simulate", s.handlers.Deception.SimulateTrigger)
		}
	}

	// Ransomware protection (Migration 117)
	if s.handlers.Ransomware != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		ransom := admin.Group("/ransomware")
		{
			ransom.GET("/config", s.handlers.Ransomware.GetConfig)
			ransom.PUT("/config", s.handlers.Ransomware.UpdateConfig)
			ransom.POST("/config/folders", s.handlers.Ransomware.AddProtectedFolder)
			ransom.DELETE("/config/folders", s.handlers.Ransomware.RemoveProtectedFolder)
			ransom.POST("/config/apps", s.handlers.Ransomware.AddAllowedApp)
			ransom.DELETE("/config/apps", s.handlers.Ransomware.RemoveAllowedApp)
			ransom.GET("/events", s.handlers.Ransomware.ListEvents)
			ransom.GET("/stats", s.handlers.Ransomware.GetStats)
		}
	}

	// Data classification (Migration 118)
	if s.handlers.DataClassification != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		dataClass := admin.Group("/data-classification")
		{
			dataClass.GET("/labels", s.handlers.DataClassification.ListLabels)
			dataClass.POST("/labels", s.handlers.DataClassification.CreateLabel)
			dataClass.PUT("/labels/:id", s.handlers.DataClassification.UpdateLabel)
			dataClass.DELETE("/labels/:id", s.handlers.DataClassification.DeleteLabel)
			dataClass.GET("/assets", s.handlers.DataClassification.ListAssets)
			dataClass.POST("/assets", s.handlers.DataClassification.CreateAsset)
			dataClass.PUT("/assets/:id", s.handlers.DataClassification.UpdateAsset)
			dataClass.DELETE("/assets/:id", s.handlers.DataClassification.DeleteAsset)
			dataClass.POST("/assets/:id/scan", s.handlers.DataClassification.ScanAsset)
			dataClass.GET("/stats", s.handlers.DataClassification.GetStats)
		}
	}

	// Security KPIs (Migration 119)
	if s.handlers.SecurityKPI != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		kpi := admin.Group("/kpi")
		{
			kpi.GET("", s.handlers.SecurityKPI.ListKPIs)
			kpi.POST("", s.handlers.SecurityKPI.CreateKPI)
			kpi.PUT("/:id", s.handlers.SecurityKPI.UpdateKPI)
			kpi.DELETE("/:id", s.handlers.SecurityKPI.DeleteKPI)
			kpi.POST("/:id/measurements", s.handlers.SecurityKPI.RecordMeasurement)
			kpi.GET("/:id/measurements", s.handlers.SecurityKPI.GetMeasurements)
			kpi.GET("/dashboard", s.handlers.SecurityKPI.GetDashboard)
		}
	}

	if s.handlers.AdversaryEmulation != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		ae := admin.Group("/adversary-emulation")
		{
			// Static /executions routes are registered before the /:id param route.
			ae.GET("/executions", s.handlers.AdversaryEmulation.ListExecutions)
			ae.POST("/executions", s.handlers.AdversaryEmulation.CreateExecution)
			ae.GET("", s.handlers.AdversaryEmulation.ListPlans)
			ae.POST("", s.handlers.AdversaryEmulation.CreatePlan)
			ae.DELETE("/:id", s.handlers.AdversaryEmulation.DeletePlan)
		}
	}

	if s.handlers.NetworkSegmentation != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		ns := admin.Group("/network-segments")
		{
			ns.GET("", s.handlers.NetworkSegmentation.GetSegmentation)
			ns.POST("", s.handlers.NetworkSegmentation.CreateSegment)
			// Static sub-paths registered before the /:id param route.
			ns.POST("/policies", s.handlers.NetworkSegmentation.CreatePolicy)
			ns.DELETE("/policies/:id", s.handlers.NetworkSegmentation.DeletePolicy)
			ns.POST("/compliance-check", s.handlers.NetworkSegmentation.ComplianceCheck)
			ns.DELETE("/:id", s.handlers.NetworkSegmentation.DeleteSegment)
		}
	}

	if s.handlers.DataRetention != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		dr := admin.Group("/data-retention")
		{
			dr.GET("", s.handlers.DataRetention.ListPolicies)
			dr.POST("/purge-preview", s.handlers.DataRetention.PurgePreview)
			dr.POST("/purge", s.handlers.DataRetention.Purge)
			dr.PUT("/:type", s.handlers.DataRetention.UpdatePolicy)
		}
	}

	if s.handlers.EndpointGroups != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		eg := admin.Group("/endpoint-groups")
		{
			eg.GET("", s.handlers.EndpointGroups.List)
			eg.POST("", s.handlers.EndpointGroups.Create)
			eg.PUT("/:id", s.handlers.EndpointGroups.Update)
			eg.DELETE("/:id", s.handlers.EndpointGroups.Delete)
		}
	}

	// Attack Surface Management (Migration 120)
	if s.handlers.AttackSurface != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		asm := admin.Group("/attack-surface")
		{
			asm.GET("/assets", s.handlers.AttackSurface.ListAssets)
			asm.POST("/assets", s.handlers.AttackSurface.CreateAsset)
			asm.PUT("/assets/:id", s.handlers.AttackSurface.UpdateAsset)
			asm.DELETE("/assets/:id", s.handlers.AttackSurface.DeleteAsset)
			asm.GET("/stats", s.handlers.AttackSurface.GetStats)
			asm.GET("/scans", s.handlers.AttackSurface.ListScans)
			asm.POST("/scans", s.handlers.AttackSurface.StartScan)
			asm.GET("/scans/:id", s.handlers.AttackSurface.GetScan)
		}
	}

	// UEBA extended endpoints (Migration 121)
	if s.handlers.UEBA != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		ueba := admin.Group("/ueba")
		{
			ueba.GET("/anomalies", s.handlers.UEBA.ListAnomalies)
			ueba.GET("/anomalies/:id", s.handlers.UEBA.GetAnomaly)
			ueba.PATCH("/anomalies/:id/status", s.handlers.UEBA.UpdateAnomalyStatus)
			ueba.GET("/baselines", s.handlers.UEBA.ListBaselines)
			ueba.GET("/users/:username", s.handlers.UEBA.GetUserProfile)
			ueba.GET("/stats", s.handlers.UEBA.GetStats)
		}
		// Non-admin UEBA user list (used by insider-threats page)
		uebaOpen := protected.Group("/ueba")
		{
			uebaOpen.GET("/users", s.handlers.UEBA.ListUsers)
			uebaOpen.GET("/users/:id/behavior", s.handlers.UEBA.GetUserBehavior)
		}
	}

	// Capacity Planning (Migration 229)
	if s.handlers.CapacityPlanning != nil {
		cpAdmin := protected.Group("/admin")
		cpAdmin.Use(adminMiddleware())
		cp := cpAdmin.Group("/capacity-planning")
		{
			cp.GET("/overview", s.handlers.CapacityPlanning.GetOverview)
			cp.GET("/workforce", s.handlers.CapacityPlanning.GetWorkforce)
			cp.GET("/resources", s.handlers.CapacityPlanning.GetResources)
			cp.GET("/storage", s.handlers.CapacityPlanning.GetStorage)
			cp.GET("/budget", s.handlers.CapacityPlanning.GetBudget)
			cp.GET("/planned-hires", s.handlers.CapacityPlanning.GetPlannedHires)
			cp.GET("/tech-debt", s.handlers.CapacityPlanning.GetTechDebt)
			cp.GET("/oncall-shifts", s.handlers.CapacityPlanning.GetOncallShifts)
			cp.GET("/roi", s.handlers.CapacityPlanning.GetROI)

			// Mutations — singletons (PUT only)
			cp.PUT("/storage", s.handlers.CapacityPlanning.UpdateStorage)
			cp.PUT("/planning-targets", s.handlers.CapacityPlanning.UpdatePlanningTargets)

			// Mutations — collections (POST/PUT/DELETE)
			cp.POST("/workforce", s.handlers.CapacityPlanning.CreateAnalyst)
			cp.PUT("/workforce/:id", s.handlers.CapacityPlanning.UpdateAnalyst)
			cp.DELETE("/workforce/:id", s.handlers.CapacityPlanning.DeleteAnalyst)

			cp.POST("/resources", s.handlers.CapacityPlanning.CreateLicense)
			cp.PUT("/resources/:id", s.handlers.CapacityPlanning.UpdateLicense)
			cp.DELETE("/resources/:id", s.handlers.CapacityPlanning.DeleteLicense)

			cp.POST("/budget", s.handlers.CapacityPlanning.CreateBudgetCategory)
			cp.PUT("/budget/:label", s.handlers.CapacityPlanning.UpdateBudgetCategory)
			cp.DELETE("/budget/:label", s.handlers.CapacityPlanning.DeleteBudgetCategory)

			cp.POST("/planned-hires", s.handlers.CapacityPlanning.CreateHire)
			cp.PUT("/planned-hires/:id", s.handlers.CapacityPlanning.UpdateHire)
			cp.DELETE("/planned-hires/:id", s.handlers.CapacityPlanning.DeleteHire)

			cp.POST("/tech-debt", s.handlers.CapacityPlanning.CreateTechDebt)
			cp.PUT("/tech-debt/:id", s.handlers.CapacityPlanning.UpdateTechDebt)
			cp.DELETE("/tech-debt/:id", s.handlers.CapacityPlanning.DeleteTechDebt)

			cp.POST("/oncall-shifts", s.handlers.CapacityPlanning.CreateShift)
			cp.PUT("/oncall-shifts/:id", s.handlers.CapacityPlanning.UpdateShift)
			cp.DELETE("/oncall-shifts/:id", s.handlers.CapacityPlanning.DeleteShift)

			cp.POST("/roi", s.handlers.CapacityPlanning.CreateROIInput)
			cp.PUT("/roi/:category", s.handlers.CapacityPlanning.UpdateROIInput)
			cp.DELETE("/roi/:category", s.handlers.CapacityPlanning.DeleteROIInput)
		}
	}

	// Incident Response Drills (Migration 261)
	if s.handlers.IncidentDrills != nil {
		idAdmin := protected.Group("/admin")
		idAdmin.Use(adminMiddleware())
		dr := idAdmin.Group("/incident-drills")
		{
			dr.GET("", s.handlers.IncidentDrills.List)
			dr.POST("", s.handlers.IncidentDrills.Create)
			dr.PUT("/:id", s.handlers.IncidentDrills.Update)
			dr.DELETE("/:id", s.handlers.IncidentDrills.Delete)
		}
	}

	// Phishing Simulator (Migration 262)
	if s.handlers.Phishing != nil {
		phAdmin := protected.Group("/admin")
		phAdmin.Use(adminMiddleware())
		ph := phAdmin.Group("/phishing")
		{
			ph.GET("/templates", s.handlers.Phishing.ListTemplates)
			ph.POST("/templates", s.handlers.Phishing.CreateTemplate)
			ph.GET("/campaigns", s.handlers.Phishing.ListCampaigns)
			ph.POST("/campaigns", s.handlers.Phishing.CreateCampaign)
			ph.GET("/stats", s.handlers.Phishing.GetStats)
		}
	}

	// Penetration Testing (Migration 263)
	if s.handlers.Pentest != nil {
		ptAdmin := protected.Group("/admin")
		ptAdmin.Use(adminMiddleware())
		pt := ptAdmin.Group("/pentest")
		{
			pt.GET("/engagements", s.handlers.Pentest.ListEngagements)
			pt.POST("/engagements", s.handlers.Pentest.CreateEngagement)
			pt.GET("/engagements/findings", s.handlers.Pentest.ListFindings)
			pt.PUT("/findings/:id", s.handlers.Pentest.UpdateFinding)
		}
	}

	// Chaos Engineering (Migration 264)
	if s.handlers.Chaos != nil {
		chAdmin := protected.Group("/admin")
		chAdmin.Use(adminMiddleware())
		ch := chAdmin.Group("/chaos")
		{
			ch.GET("/experiments", s.handlers.Chaos.ListExperiments)
			ch.GET("/runs", s.handlers.Chaos.ListRuns)
			ch.POST("/runs", s.handlers.Chaos.CreateRun)
			ch.GET("/approvals", s.handlers.Chaos.ListApprovals)
			ch.POST("/approvals", s.handlers.Chaos.CreateApproval)
			ch.PUT("/approvals/:id", s.handlers.Chaos.UpdateApproval)
		}
	}

	// AI Investigation Mode (system settings for autonomous agent)
	if s.handlers.Investigation != nil {
		aiInvAdmin := protected.Group("/admin")
		aiInvAdmin.Use(adminMiddleware())
		aiInvGroup := aiInvAdmin.Group("/ai-investigation")
		{
			aiInvGroup.GET("/mode", s.handlers.Investigation.GetMode)
		}
	}

	// Container Security Policies (Migration 123)
	if s.handlers.ContainerSecurity != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		containerSec := admin.Group("/container-security")
		{
			containerSec.GET("/policies", s.handlers.ContainerSecurity.ListPolicies)
			containerSec.POST("/policies", s.handlers.ContainerSecurity.CreatePolicy)
			containerSec.PUT("/policies/:id", s.handlers.ContainerSecurity.UpdatePolicy)
			containerSec.DELETE("/policies/:id", s.handlers.ContainerSecurity.DeletePolicy)
			containerSec.POST("/policies/:id/toggle", s.handlers.ContainerSecurity.TogglePolicy)
			containerSec.GET("/violations", s.handlers.ContainerSecurity.ListViolations)
			containerSec.POST("/violations/:id/resolve", s.handlers.ContainerSecurity.ResolveViolation)
			containerSec.GET("/stats", s.handlers.ContainerSecurity.GetStats)
		}
	}

	// API Security (Migration 124 + 168)
	if s.handlers.APISecurity != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		apiSec := admin.Group("/api-security")
		{
			apiSec.GET("/endpoints", s.handlers.APISecurity.ListEndpoints)
			apiSec.POST("/endpoints", s.handlers.APISecurity.CreateEndpoint)
			apiSec.PUT("/endpoints/:id", s.handlers.APISecurity.UpdateEndpoint)
			apiSec.DELETE("/endpoints/:id", s.handlers.APISecurity.DeleteEndpoint)
			apiSec.GET("/vulnerabilities", s.handlers.APISecurity.ListVulnerabilities)
			apiSec.PATCH("/vulnerabilities/:id/status", s.handlers.APISecurity.UpdateVulnStatus)
			apiSec.GET("/scans", s.handlers.APISecurity.ListScans)
			apiSec.POST("/scans", s.handlers.APISecurity.StartScan)
			apiSec.GET("/scans/:id", s.handlers.APISecurity.GetScan)
			apiSec.GET("/stats", s.handlers.APISecurity.Stats)
			apiSec.GET("/events", s.handlers.APISecurity.ListEvents)
		}
	}

	// Cloud-Native SIEM (Migration 125)
	if s.handlers.CloudSIEM != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		siem := admin.Group("/cloud-siem")
		{
			siem.GET("/sources", s.handlers.CloudSIEM.ListLogSources)
			siem.POST("/sources", s.handlers.CloudSIEM.CreateLogSource)
			siem.PUT("/sources/:id", s.handlers.CloudSIEM.UpdateLogSource)
			siem.DELETE("/sources/:id", s.handlers.CloudSIEM.DeleteLogSource)
			siem.POST("/sources/:id/toggle", s.handlers.CloudSIEM.ToggleLogSource)
			siem.GET("/rules", s.handlers.CloudSIEM.ListDetectionRules)
			siem.POST("/rules", s.handlers.CloudSIEM.CreateDetectionRule)
			siem.PUT("/rules/:id", s.handlers.CloudSIEM.UpdateDetectionRule)
			siem.DELETE("/rules/:id", s.handlers.CloudSIEM.DeleteDetectionRule)
			siem.POST("/rules/:id/toggle", s.handlers.CloudSIEM.ToggleDetectionRule)
			siem.GET("/queries", s.handlers.CloudSIEM.ListSavedQueries)
			siem.POST("/queries", s.handlers.CloudSIEM.SaveQuery)
			siem.DELETE("/queries/:id", s.handlers.CloudSIEM.DeleteQuery)
			siem.POST("/queries/execute", s.handlers.CloudSIEM.ExecuteQuery)
			siem.GET("/stats", s.handlers.CloudSIEM.GetStats)
		}
	}

	// Compliance Evidence (Migration 126)
	if s.handlers.ComplianceEvidence != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		evidence := admin.Group("/compliance-evidence")
		{
			evidence.GET("/tasks", s.handlers.ComplianceEvidence.ListTasks)
			evidence.POST("/tasks", s.handlers.ComplianceEvidence.CreateTask)
			evidence.PUT("/tasks/:id", s.handlers.ComplianceEvidence.UpdateTask)
			evidence.DELETE("/tasks/:id", s.handlers.ComplianceEvidence.DeleteTask)
			evidence.POST("/tasks/:id/collect", s.handlers.ComplianceEvidence.TriggerCollection)
			evidence.GET("/evidence", s.handlers.ComplianceEvidence.ListEvidence)
			evidence.PATCH("/evidence/:id/review", s.handlers.ComplianceEvidence.ReviewEvidence)
			evidence.GET("/stats", s.handlers.ComplianceEvidence.GetStats)
		}
	}

	// Security Metrics Reports (Migration 127)
	if s.handlers.MetricsReport != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		metricsReport := admin.Group("/metrics-reports")
		{
			metricsReport.GET("/schedules", s.handlers.MetricsReport.ListSchedules)
			metricsReport.POST("/schedules", s.handlers.MetricsReport.CreateSchedule)
			metricsReport.PUT("/schedules/:id", s.handlers.MetricsReport.UpdateSchedule)
			metricsReport.DELETE("/schedules/:id", s.handlers.MetricsReport.DeleteSchedule)
			metricsReport.POST("/schedules/:id/toggle", s.handlers.MetricsReport.ToggleSchedule)
			metricsReport.GET("/reports", s.handlers.MetricsReport.ListReports)
			metricsReport.POST("/reports/generate", s.handlers.MetricsReport.GenerateReport)
			metricsReport.GET("/reports/:id", s.handlers.MetricsReport.GetReport)
			metricsReport.DELETE("/reports/:id", s.handlers.MetricsReport.DeleteReport)
			metricsReport.GET("/stats", s.handlers.MetricsReport.GetStats)
		}
	}

	// Cloud Identity Federation (Migration 128)
	if s.handlers.CloudIdentity != nil {
		admin := protected.Group("/admin")
		admin.Use(adminMiddleware())
		cloudIdentity := admin.Group("/cloud-identity")
		{
			cloudIdentity.GET("/providers", s.handlers.CloudIdentity.ListProviders)
			cloudIdentity.POST("/providers", s.handlers.CloudIdentity.CreateProvider)
			cloudIdentity.PUT("/providers/:id", s.handlers.CloudIdentity.UpdateProvider)
			cloudIdentity.DELETE("/providers/:id", s.handlers.CloudIdentity.DeleteProvider)
			cloudIdentity.POST("/providers/:id/sync", s.handlers.CloudIdentity.SyncProvider)
			cloudIdentity.GET("/identities", s.handlers.CloudIdentity.ListIdentities)
			cloudIdentity.GET("/identities/:id", s.handlers.CloudIdentity.GetIdentity)
			cloudIdentity.PATCH("/identities/:id/link", s.handlers.CloudIdentity.LinkIdentity)
			cloudIdentity.GET("/stats", s.handlers.CloudIdentity.GetStats)
		}
	}

	// Migration 129: Deception Network (Honeynet)
	if s.handlers.Honeynet != nil {
		admin129 := protected.Group("/admin")
		admin129.Use(adminMiddleware())
		honeynet := admin129.Group("/honeynet")
		{
			honeynet.GET("/nodes", s.handlers.Honeynet.ListNodes)
			honeynet.POST("/nodes", s.handlers.Honeynet.CreateNode)
			honeynet.PUT("/nodes/:id", s.handlers.Honeynet.UpdateNode)
			honeynet.DELETE("/nodes/:id", s.handlers.Honeynet.DeleteNode)
			honeynet.POST("/nodes/:id/toggle", s.handlers.Honeynet.ToggleNode)
			honeynet.GET("/interactions", s.handlers.Honeynet.ListInteractions)
			honeynet.GET("/interactions/:id", s.handlers.Honeynet.GetInteraction)
			honeynet.GET("/stats", s.handlers.Honeynet.GetStats)
		}
	}

	// Migration 130: Incident Pattern Recognition
	if s.handlers.IncidentPattern != nil {
		admin130 := protected.Group("/admin")
		admin130.Use(adminMiddleware())
		patterns := admin130.Group("/incident-patterns")
		{
			patterns.GET("/patterns", s.handlers.IncidentPattern.ListPatterns)
			patterns.POST("/patterns", s.handlers.IncidentPattern.CreatePattern)
			patterns.PUT("/patterns/:id", s.handlers.IncidentPattern.UpdatePattern)
			patterns.DELETE("/patterns/:id", s.handlers.IncidentPattern.DeletePattern)
			patterns.POST("/patterns/:id/toggle", s.handlers.IncidentPattern.TogglePattern)
			patterns.POST("/analyze", s.handlers.IncidentPattern.RunAnalysis)
			patterns.GET("/matches", s.handlers.IncidentPattern.ListMatches)
			patterns.PATCH("/matches/:id/status", s.handlers.IncidentPattern.UpdateMatchStatus)
			patterns.GET("/stats", s.handlers.IncidentPattern.GetStats)
		}
	}

	// Migration 131: Breach & Attack Simulation
	if s.handlers.BAS != nil {
		admin131 := protected.Group("/admin")
		admin131.Use(adminMiddleware())
		bas := admin131.Group("/bas")
		{
			bas.GET("/scenarios", s.handlers.BAS.ListScenarios)
			bas.POST("/scenarios", s.handlers.BAS.CreateScenario)
			bas.PUT("/scenarios/:id", s.handlers.BAS.UpdateScenario)
			bas.DELETE("/scenarios/:id", s.handlers.BAS.DeleteScenario)
			bas.GET("/runs", s.handlers.BAS.ListRuns)
			bas.POST("/runs", s.handlers.BAS.StartRun)
			bas.GET("/runs/:id", s.handlers.BAS.GetRun)
			bas.POST("/runs/:id/cancel", s.handlers.BAS.CancelRun)
			bas.GET("/stats", s.handlers.BAS.GetStats)
		}
	}

	// Migration 132: Threat Context Enrichment
	if s.handlers.ContextEnrichment != nil {
		admin132 := protected.Group("/admin")
		admin132.Use(adminMiddleware())
		enrichment := admin132.Group("/enrichment")
		{
			enrichment.GET("/sources", s.handlers.ContextEnrichment.ListSources)
			enrichment.POST("/sources", s.handlers.ContextEnrichment.CreateSource)
			enrichment.PUT("/sources/:id", s.handlers.ContextEnrichment.UpdateSource)
			enrichment.DELETE("/sources/:id", s.handlers.ContextEnrichment.DeleteSource)
			enrichment.POST("/sources/:id/toggle", s.handlers.ContextEnrichment.ToggleSource)
			enrichment.POST("/enrich", s.handlers.ContextEnrichment.EnrichIndicator)
			enrichment.GET("/cache", s.handlers.ContextEnrichment.GetCachedResults)
			enrichment.DELETE("/cache", s.handlers.ContextEnrichment.ClearCache)
			enrichment.POST("/sources/:id/health", s.handlers.ContextEnrichment.HealthCheck)
			enrichment.GET("/stats", s.handlers.ContextEnrichment.GetStats)
		}
	}

	// Migration 133: Autonomous Response
	if s.handlers.AutonomousPolicy != nil {
		admin133 := protected.Group("/admin")
		admin133.Use(adminMiddleware())
		autonomousPolicy := admin133.Group("/autonomous-response")
		{
			autonomousPolicy.GET("/policies", s.handlers.AutonomousPolicy.ListPolicies)
			autonomousPolicy.POST("/policies", s.handlers.AutonomousPolicy.CreatePolicy)
			autonomousPolicy.PUT("/policies/:id", s.handlers.AutonomousPolicy.UpdatePolicy)
			autonomousPolicy.DELETE("/policies/:id", s.handlers.AutonomousPolicy.DeletePolicy)
			autonomousPolicy.POST("/policies/:id/toggle", s.handlers.AutonomousPolicy.TogglePolicy)
			autonomousPolicy.GET("/executions", s.handlers.AutonomousPolicy.ListExecutions)
			autonomousPolicy.POST("/executions/:id/approve", s.handlers.AutonomousPolicy.ApproveExecution)
			autonomousPolicy.POST("/executions/:id/reject", s.handlers.AutonomousPolicy.RejectExecution)
			autonomousPolicy.GET("/stats", s.handlers.AutonomousPolicy.GetStats)
		}
	}

	// Migration 134: Compliance Workflow
	if s.handlers.ComplianceWorkflow != nil {
		admin134 := protected.Group("/admin")
		admin134.Use(adminMiddleware())
		compWF := admin134.Group("/compliance-workflows")
		{
			compWF.GET("", s.handlers.ComplianceWorkflow.ListWorkflows)
			compWF.POST("", s.handlers.ComplianceWorkflow.CreateWorkflow)
			compWF.PUT("/:id", s.handlers.ComplianceWorkflow.UpdateWorkflow)
			compWF.DELETE("/:id", s.handlers.ComplianceWorkflow.DeleteWorkflow)
			compWF.POST("/:id/run", s.handlers.ComplianceWorkflow.StartRun)
			compWF.GET("/runs", s.handlers.ComplianceWorkflow.ListRuns)
			compWF.GET("/runs/:id", s.handlers.ComplianceWorkflow.GetRun)
			compWF.POST("/runs/:id/advance", s.handlers.ComplianceWorkflow.AdvanceStage)
			compWF.POST("/runs/:id/cancel", s.handlers.ComplianceWorkflow.CancelRun)
		}
	}

	// Migration 135: Predictive Analytics
	if s.handlers.PredictiveAnalytics != nil {
		admin135 := protected.Group("/admin")
		admin135.Use(adminMiddleware())
		predictive := admin135.Group("/predictive")
		{
			predictive.GET("/predictions", s.handlers.PredictiveAnalytics.GetPredictions)
			predictive.POST("/predictions/generate", s.handlers.PredictiveAnalytics.GeneratePredictions)
			predictive.GET("/models", s.handlers.PredictiveAnalytics.GetModels)
			predictive.GET("/accuracy", s.handlers.PredictiveAnalytics.GetAccuracyReport)
			predictive.GET("/risk-forecast", s.handlers.PredictiveAnalytics.GetRiskForecast)
		}
	}

	// Migration 136: Forensics Automation
	if s.handlers.ForensicsAutomation != nil {
		admin136 := protected.Group("/admin")
		admin136.Use(adminMiddleware())
		fa := admin136.Group("/forensics-automation")
		{
			fa.GET("/jobs", s.handlers.ForensicsAutomation.ListJobs)
			fa.POST("/jobs", s.handlers.ForensicsAutomation.CreateJob)
			fa.GET("/jobs/:id", s.handlers.ForensicsAutomation.GetJob)
			fa.POST("/jobs/:id/start", s.handlers.ForensicsAutomation.StartJob)
			fa.GET("/jobs/:id/evidence", s.handlers.ForensicsAutomation.GetEvidence)
			fa.GET("/stats", s.handlers.ForensicsAutomation.GetStats)
		}
	}

	// Migration 137: Supply Chain Risk
	if s.handlers.SupplyChainRisk != nil {
		admin137 := protected.Group("/admin")
		admin137.Use(adminMiddleware())
		sc := admin137.Group("/supply-chain")
		{
			sc.GET("/vendors", s.handlers.SupplyChainRisk.ListVendors)
			sc.POST("/vendors", s.handlers.SupplyChainRisk.CreateVendor)
			sc.GET("/vendors/:id", s.handlers.SupplyChainRisk.GetVendor)
			sc.POST("/vendors/:id/assess", s.handlers.SupplyChainRisk.AssessVendor)
			sc.GET("/incidents", s.handlers.SupplyChainRisk.ListIncidents)
			sc.GET("/risk-map", s.handlers.SupplyChainRisk.GetRiskMap)
		}
	}

	// Migration 138: Enhanced Orchestration
	if s.handlers.OrchestrationEnhanced != nil {
		admin138 := protected.Group("/admin")
		admin138.Use(adminMiddleware())
		orch := admin138.Group("/orchestration")
		{
			orch.GET("/workflows", s.handlers.OrchestrationEnhanced.ListWorkflows)
			orch.POST("/workflows/:id/execute", s.handlers.OrchestrationEnhanced.ExecuteWorkflow)
			orch.GET("/executions/:id", s.handlers.OrchestrationEnhanced.GetExecution)
			orch.GET("/stats", s.handlers.OrchestrationEnhanced.GetStats)
		}
	}

	// Migration 139: Threat Hunting Campaigns
	if s.handlers.HuntingCampaign != nil {
		admin139 := protected.Group("/admin")
		admin139.Use(adminMiddleware())
		hunting := admin139.Group("/hunting-campaigns")
		{
			hunting.GET("", s.handlers.HuntingCampaign.ListCampaigns)
			hunting.POST("", s.handlers.HuntingCampaign.CreateCampaign)
			hunting.GET("/:id", s.handlers.HuntingCampaign.GetCampaign)
			hunting.PUT("/:id", s.handlers.HuntingCampaign.UpdateCampaign)
			hunting.POST("/:id/notes", s.handlers.HuntingCampaign.AddNote)
			hunting.GET("/stats", s.handlers.HuntingCampaign.GetStats)
		}
	}

	// Threat Hunting Query Engine
	if s.handlers.HuntingQuery != nil {
		adminHunt := protected.Group("/admin")
		adminHunt.Use(adminMiddleware())
		adminHunt.POST("/hunting/query", s.handlers.HuntingQuery.Execute)
		adminHunt.GET("/hunting/search", s.handlers.HuntingQuery.QuickSearch)
		adminHunt.GET("/hunting/saved-queries", s.handlers.HuntingQuery.SavedQueries)
	}

	// Migration 140: Compliance Auto-Remediation
	if s.handlers.ComplianceRemediation != nil {
		admin140 := protected.Group("/admin")
		admin140.Use(adminMiddleware())
		cr := admin140.Group("/compliance-remediation")
		{
			cr.GET("/rules", s.handlers.ComplianceRemediation.ListRules)
			cr.POST("/rules", s.handlers.ComplianceRemediation.CreateRule)
			cr.GET("/executions", s.handlers.ComplianceRemediation.ListExecutions)
			cr.POST("/executions/:id/approve", s.handlers.ComplianceRemediation.ApproveExecution)
			cr.GET("/dashboard", s.handlers.ComplianceRemediation.GetDashboard)
		}
	}

	// Migration 141: Zero Trust Network Access
	if s.handlers.ZTNA != nil {
		admin141 := protected.Group("/admin")
		admin141.Use(adminMiddleware())
		ztna := admin141.Group("/ztna")
		{
			ztna.GET("", s.handlers.ZTNA.ListPolicies)
			ztna.POST("", s.handlers.ZTNA.CreatePolicy)
			ztna.GET("/access-logs", s.handlers.ZTNA.GetAccessLogs)
			ztna.GET("/devices", s.handlers.ZTNA.GetDevicePosture)
			ztna.GET("/stats", s.handlers.ZTNA.GetStats)
		}
	}

	// Migration 142: Security Data Warehouse
	if s.handlers.SecurityDW != nil {
		admin142 := protected.Group("/admin")
		admin142.Use(adminMiddleware())
		sdw := admin142.Group("/security-dw")
		{
			sdw.GET("", s.handlers.SecurityDW.ListDatasets)
			sdw.POST("/query", s.handlers.SecurityDW.ExecuteQuery)
			sdw.GET("/query/:id", s.handlers.SecurityDW.GetQueryResult)
			sdw.GET("/stats", s.handlers.SecurityDW.GetStats)
		}
	}

	// Migration 143: Endpoint Encryption Management
	if s.handlers.EncryptionMgmt != nil {
		admin143 := protected.Group("/admin")
		admin143.Use(adminMiddleware())
		enc := admin143.Group("/encryption")
		{
			enc.GET("", s.handlers.EncryptionMgmt.ListPolicies)
			enc.POST("", s.handlers.EncryptionMgmt.CreatePolicy)
			enc.GET("/endpoints", s.handlers.EncryptionMgmt.ListEndpointStatus)
			enc.GET("/stats", s.handlers.EncryptionMgmt.GetStats)
		}
	}

	// Migration 144: Patch Automation
	if s.handlers.PatchAutomation != nil {
		admin144 := protected.Group("/admin")
		admin144.Use(adminMiddleware())
		pa := admin144.Group("/patch-automation")
		{
			pa.GET("", s.handlers.PatchAutomation.ListPolicies)
			pa.POST("", s.handlers.PatchAutomation.CreatePolicy)
			pa.GET("/policies", s.handlers.PatchAutomation.ListPolicies)
			pa.POST("/policies", s.handlers.PatchAutomation.CreatePolicy)
			pa.POST("/policies/:id/toggle", s.handlers.PatchAutomation.TogglePolicy)
			pa.GET("/jobs", s.handlers.PatchAutomation.ListJobs)
			pa.POST("/jobs", s.handlers.PatchAutomation.CreateJob)
			pa.POST("/jobs/:id/approve", s.handlers.PatchAutomation.ApproveJob)
			pa.GET("/missing-patches", s.handlers.PatchAutomation.GetMissingPatches)
			pa.GET("/stats", s.handlers.PatchAutomation.GetStats)
		}
	}

	// Migration 145: Security Governance
	if s.handlers.SecurityGovernance != nil {
		admin145 := protected.Group("/admin")
		admin145.Use(adminMiddleware())
		gov := admin145.Group("/governance")
		{
			gov.GET("", s.handlers.SecurityGovernance.ListPolicies)
			gov.POST("", s.handlers.SecurityGovernance.CreatePolicy)
			gov.PUT("/:id", s.handlers.SecurityGovernance.UpdatePolicy)
			gov.GET("/exceptions", s.handlers.SecurityGovernance.ListExceptions)
			gov.POST("/exceptions/:id/approve", s.handlers.SecurityGovernance.ApproveException)
			gov.GET("/dashboard", s.handlers.SecurityGovernance.GetDashboard)
		}
	}

	// Migration 146: NTA
	if s.handlers.NTA != nil {
		admin146 := protected.Group("/admin")
		nta := admin146.Group("/nta")
		{
			nta.GET("/rules", s.handlers.NTA.ListRules)
			nta.POST("/rules", s.handlers.NTA.CreateRule)
			nta.GET("/detections", s.handlers.NTA.ListDetections)
			nta.GET("/stats", s.handlers.NTA.GetStats)
			nta.GET("/flows", s.handlers.NTA.GetFlowAnalysis)
		}
	}

	// Migration 148: ITDR
	if s.handlers.ITDR != nil {
		admin148 := protected.Group("/admin")
		itdr := admin148.Group("/itdr")
		{
			itdr.GET("/incidents", s.handlers.ITDR.ListIncidents)
			itdr.GET("/risky-users", s.handlers.ITDR.GetTopRiskyUsers)
			itdr.GET("/rules", s.handlers.ITDR.ListRules)
			itdr.POST("/rules", s.handlers.ITDR.CreateRule)
			itdr.GET("/stats", s.handlers.ITDR.GetStats)
		}
	}

	// Migration 149: CSPM Enhanced
	if s.handlers.CSPMEnhanced != nil {
		admin149 := protected.Group("/admin")
		cspm := admin149.Group("/cspm-enhanced")
		{
			cspm.GET("/accounts", s.handlers.CSPMEnhanced.ListAccounts)
			cspm.GET("/findings", s.handlers.CSPMEnhanced.ListFindings)
			cspm.POST("/accounts/:id/scan", s.handlers.CSPMEnhanced.StartScan)
			cspm.GET("/stats", s.handlers.CSPMEnhanced.GetStats)
		}
	}

	// Migration 150: Risk Scoring
	if s.handlers.RiskScoring != nil {
		admin150 := protected.Group("/admin")
		rs := admin150.Group("/risk-scoring")
		{
			rs.GET("/models", s.handlers.RiskScoring.ListModels)
			rs.GET("/scores", s.handlers.RiskScoring.GetScores)
			rs.POST("/recalculate", s.handlers.RiskScoring.RecalculateScores)
			rs.GET("/organization", s.handlers.RiskScoring.GetOrganizationRisk)
			rs.GET("/metrics", s.handlers.RiskScoring.GetMetrics)
		}
	}

	// Migration 151: Automation Enhanced
	if s.handlers.AutomationEnhanced != nil {
		admin151 := protected.Group("/admin")
		ae := admin151.Group("/automation-enhanced")
		{
			ae.GET("", s.handlers.AutomationEnhanced.ListTriggers)
			ae.POST("", s.handlers.AutomationEnhanced.CreateTrigger)
			ae.GET("/runs", s.handlers.AutomationEnhanced.ListRuns)
			ae.GET("/stats", s.handlers.AutomationEnhanced.GetStats)
		}
	}

	// Migration 152: Alert Routing
	if s.handlers.AlertRouting != nil {
		admin152 := protected.Group("/admin")
		ar := admin152.Group("/alert-routing")
		{
			ar.GET("", s.handlers.AlertRouting.ListRules)
			ar.POST("", s.handlers.AlertRouting.CreateRule)
			ar.PUT("/:id", s.handlers.AlertRouting.UpdateRule)
			ar.DELETE("/:id", s.handlers.AlertRouting.DeleteRule)
			ar.GET("/destinations", s.handlers.AlertRouting.ListDestinations)
			ar.POST("/destinations", s.handlers.AlertRouting.CreateDestination)
			ar.POST("/destinations/:id/test", s.handlers.AlertRouting.TestDestination)
			ar.GET("/stats", s.handlers.AlertRouting.GetStats)
		}
	}

	// Migration 153: Security Assessment
	if s.handlers.SecurityAssessment != nil {
		admin153 := protected.Group("/admin")
		sa := admin153.Group("/security-assessment")
		{
			sa.GET("", s.handlers.SecurityAssessment.ListAssessments)
			sa.GET("/:id", s.handlers.SecurityAssessment.GetAssessment)
			sa.POST("", s.handlers.SecurityAssessment.CreateAssessment)
			sa.PUT("/:id", s.handlers.SecurityAssessment.UpdateAssessment)
			sa.GET("/stats", s.handlers.SecurityAssessment.GetStats)
		}
	}

	// Migration 154: Digital Risk Protection
	if s.handlers.DRP != nil {
		admin154 := protected.Group("/admin")
		drp := admin154.Group("/drp")
		{
			drp.GET("", s.handlers.DRP.ListMonitors)
			drp.POST("", s.handlers.DRP.CreateMonitor)
			drp.GET("/findings", s.handlers.DRP.ListFindings)
			drp.PUT("/findings/:id", s.handlers.DRP.UpdateFinding)
			drp.GET("/stats", s.handlers.DRP.GetStats)
		}
	}

	// Migration 155: Training Management
	if s.handlers.TrainingMgmt != nil {
		admin155 := protected.Group("/admin")
		tm := admin155.Group("/training-mgmt")
		{
			tm.GET("", s.handlers.TrainingMgmt.ListPrograms)
			tm.POST("", s.handlers.TrainingMgmt.CreateProgram)
			tm.GET("/enrollments", s.handlers.TrainingMgmt.ListEnrollments)
			tm.POST("/enrollments", s.handlers.TrainingMgmt.EnrollUser)
			tm.GET("/stats", s.handlers.TrainingMgmt.GetStats)
		}
	}

	// Migration 156: Quarantine Actions
	if s.handlers.QuarantineActions != nil {
		adminQ := protected.Group("/admin")
		adminQ.GET("/quarantine-actions", s.handlers.QuarantineActions.List)
		adminQ.POST("/quarantine-actions", s.handlers.QuarantineActions.Create)
		adminQ.POST("/quarantine-actions/:id/release", s.handlers.QuarantineActions.Release)
		adminQ.GET("/quarantine-actions/stats", s.handlers.QuarantineActions.Stats)
	}

	// Migration 157: Security SLA
	if s.handlers.SecuritySLA != nil {
		adminSLA := protected.Group("/admin")
		adminSLA.GET("/security-sla/policies", s.handlers.SecuritySLA.ListPolicies)
		adminSLA.POST("/security-sla/policies", s.handlers.SecuritySLA.CreatePolicy)
		adminSLA.GET("/security-sla/stats", s.handlers.SecuritySLA.SLAStats)
	}

	// Migration 158: Threat Simulation
	if s.handlers.ThreatSimulation != nil {
		adminSim := protected.Group("/admin")
		adminSim.GET("/threat-simulation/templates", s.handlers.ThreatSimulation.ListTemplates)
		adminSim.GET("/threat-simulation/runs", s.handlers.ThreatSimulation.ListRuns)
		adminSim.POST("/threat-simulation/runs", s.handlers.ThreatSimulation.StartRun)
		adminSim.GET("/threat-simulation/stats", s.handlers.ThreatSimulation.SimStats)
	}
	if s.handlers.Vulnerability != nil {
		adminVuln := protected.Group("/admin")
		adminVuln.GET("/vulnerabilities", s.handlers.Vulnerability.List)
		adminVuln.GET("/vulnerabilities/stats", s.handlers.Vulnerability.Stats)
		adminVuln.GET("/vulnerabilities/top", s.handlers.Vulnerability.TopVulnerabilities)
		adminVuln.PATCH("/vulnerabilities/:id/status", s.handlers.Vulnerability.UpdateStatus)
	}
	if s.handlers.IncidentPlaybook != nil {
		adminPB := protected.Group("/admin")
		adminPB.GET("/incident-playbooks", s.handlers.IncidentPlaybook.List)
		adminPB.POST("/incident-playbooks", s.handlers.IncidentPlaybook.Create)
		adminPB.POST("/incident-playbooks/:id/execute", s.handlers.IncidentPlaybook.Execute)
		adminPB.GET("/incident-playbooks/executions", s.handlers.IncidentPlaybook.ListExecutions)
	}
	if s.handlers.DataClassification != nil {
		adminDC := protected.Group("/admin")
		adminDC.GET("/data-classification/policies", s.handlers.DataClassification.ListPolicies)
		adminDC.POST("/data-classification/policies", s.handlers.DataClassification.CreatePolicy)
		adminDC.GET("/data-classification/findings", s.handlers.DataClassification.ListFindings)
		adminDC.GET("/data-classification/findings-stats", s.handlers.DataClassification.FindingsStats)
	}
	if s.handlers.NetworkTopology != nil {
		adminNT := protected.Group("/admin")
		adminNT.GET("/network-topology", s.handlers.NetworkTopology.GetTopology)
		adminNT.GET("/network-topology/stats", s.handlers.NetworkTopology.Stats)
	}
	if s.handlers.Deception != nil {
		adminDec := protected.Group("/admin")
		adminDec.GET("/deception/assets", s.handlers.Deception.ListAssets)
		adminDec.POST("/deception/assets", s.handlers.Deception.CreateAsset)
		adminDec.GET("/deception/assets/stats", s.handlers.Deception.AssetStats)
	}
	if s.handlers.SecurityMetricsHistory != nil {
		adminSMH := protected.Group("/admin")
		adminSMH.GET("/security-metrics", s.handlers.SecurityMetricsHistory.GetMetric)
		adminSMH.GET("/security-metrics/names", s.handlers.SecurityMetricsHistory.ListMetricNames)
		adminSMH.POST("/security-metrics", s.handlers.SecurityMetricsHistory.RecordMetric)
	}

	// Migration 169: Container Security (additional routes)
	if s.handlers.ContainerSecurity != nil {
		adminCS := protected.Group("/admin")
		adminCS.GET("/container-security/images", s.handlers.ContainerSecurity.ListImages)
		adminCS.GET("/container-security/runtime-events", s.handlers.ContainerSecurity.ListRuntimeEvents)
		adminCS.GET("/container-security/image-stats", s.handlers.ContainerSecurity.ImageStats)
		adminCS.POST("/container-security/images/:id/scan", s.handlers.ContainerSecurity.TriggerImageScan)
	}

	if s.handlers.EmailSecurity != nil {
		adminES := protected.Group("/admin")
		adminES.GET("/email-security/events", s.handlers.EmailSecurity.ListEvents)
		adminES.GET("/email-security/stats", s.handlers.EmailSecurity.Stats)
		adminES.GET("/email-security/policies", s.handlers.EmailSecurity.ListPolicies)
	}
	if s.handlers.EndpointHardening != nil {
		adminEH := protected.Group("/admin")
		adminEH.GET("/endpoint-hardening/baselines", s.handlers.EndpointHardening.ListBaselines)
		adminEH.GET("/endpoint-hardening/assessments", s.handlers.EndpointHardening.ListAssessments)
		adminEH.GET("/endpoint-hardening/stats", s.handlers.EndpointHardening.Stats)
	}
	if s.handlers.SecurityAwareness != nil {
		adminSA := protected.Group("/admin")
		adminSA.GET("/security-awareness/courses", s.handlers.SecurityAwareness.ListCourses)
		adminSA.GET("/security-awareness/simulations", s.handlers.SecurityAwareness.ListSimulations)
		adminSA.GET("/security-awareness/stats", s.handlers.SecurityAwareness.Stats)
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

	// ML Seed / Admin training endpoints (Professional plan required)
	if s.handlers.MLSeed != nil {
		adminMLSeed := protected.Group("/admin")
		adminMLSeed.Use(apimw.RequireFeature(s.licMgr, license.FeatureMLDetection))
		adminMLSeed.POST("/ml/seed", s.handlers.MLSeed.SeedTrainingData)
		adminMLSeed.POST("/ml/retrain", s.handlers.MLSeed.TriggerRetrain)
		adminMLSeed.GET("/ml/status", s.handlers.MLSeed.ModelStatus)
	}

	// Migration 177: Threat Intelligence Feed Manager (Professional plan required)
	if s.handlers.ThreatIntel != nil {
		tiAdmin := protected.Group("/admin/threat-intel")
		tiAdmin.Use(apimw.RequireFeature(s.licMgr, license.FeatureThreatIntel))
		tiAdmin.Use(adminMiddleware())
		{
			tiAdmin.GET("/feeds", s.handlers.ThreatIntel.ListFeeds)
			tiAdmin.POST("/feeds", s.handlers.ThreatIntel.AddFeed)
			tiAdmin.PUT("/feeds/:id", s.handlers.ThreatIntel.UpdateFeed)
			tiAdmin.DELETE("/feeds/:id", s.handlers.ThreatIntel.RemoveFeed)
			tiAdmin.POST("/feeds/:id/sync", s.handlers.ThreatIntel.SyncFeed)
			tiAdmin.GET("/iocs", s.handlers.ThreatIntel.ListIOCs)
			tiAdmin.POST("/lookup", s.handlers.ThreatIntel.LookupIOC)
			tiAdmin.GET("/stats", s.handlers.ThreatIntel.GetStats)
		}
	}

	// Report Generator (structured on-demand reports) — gated by FeatureReports
	// in addition to adminMiddleware.
	if s.handlers.ReportGenerator != nil {
		rptAdmin := protected.Group("/admin/reports")
		rptAdmin.Use(adminMiddleware(), apimw.RequireFeature(s.licMgr, license.FeatureReports))
		{
			rptAdmin.POST("/generate", s.handlers.ReportGenerator.GenerateReport)
			rptAdmin.GET("/templates", s.handlers.ReportGenerator.ListTemplates)
			rptAdmin.POST("/export", s.handlers.ReportGenerator.ExportReport)
		}
	}

	// Agent Configuration Profiles
	if s.handlers.AgentProfiles != nil {
		apAdmin := protected.Group("/admin/agent-profiles")
		apAdmin.Use(adminMiddleware())
		{
			apAdmin.GET("", s.handlers.AgentProfiles.ListProfiles)
			apAdmin.POST("", s.handlers.AgentProfiles.CreateProfile)
			apAdmin.GET("/:id", s.handlers.AgentProfiles.GetProfile)
			apAdmin.PUT("/:id", s.handlers.AgentProfiles.UpdateProfile)
			apAdmin.DELETE("/:id", s.handlers.AgentProfiles.DeleteProfile)
			apAdmin.POST("/:id/push", s.handlers.AgentProfiles.PushProfile)
			apAdmin.POST("/:id/push-all", s.handlers.AgentProfiles.PushProfileAll)
		}
	}

	// Security Scorecard (NIST CSF / ISO 27001)
	if s.handlers.Scorecard != nil {
		scAdmin := protected.Group("/admin/scorecard")
		scAdmin.Use(adminMiddleware())
		{
			scAdmin.GET("/nist-csf", s.handlers.Scorecard.GetNISTCSF)
			scAdmin.GET("/iso27001", s.handlers.Scorecard.GetISO27001)
			scAdmin.GET("/summary", s.handlers.Scorecard.GetSummary)
		}
	}

	// /admin/organizations, /org/current and /org/settings were removed with
	// migration 380. They served a parallel `organizations` table that no
	// foreign key pointed at, so the agent, user and alert counts they reported
	// were structurally zero and an organization created through them could
	// never own anything. Tenant management is /admin/tenants.

	// Migration 183: GeoIP Threat Map
	if s.handlers.GeoIP != nil {
		tm := protected.Group("/threat-map")
		{
			tm.GET("/data", s.handlers.GeoIP.GetThreatMapData)
			tm.GET("/top-threats", s.handlers.GeoIP.GetTopThreats)
			tm.POST("/lookup", s.handlers.GeoIP.LookupIP)
		}
	}

	// Migration 184: Structured Audit Log v2
	if s.handlers.AuditV2 != nil {
		auditAdmin := protected.Group("/admin/audit")
		auditAdmin.Use(adminMiddleware())
		{
			auditAdmin.GET("/events", s.handlers.AuditV2.ListEvents)
			auditAdmin.GET("/stats", s.handlers.AuditV2.GetStats)
			auditAdmin.GET("/export", s.handlers.AuditV2.ExportCSV)
		}
	}

	// Migration 179: Sigma Rules Management API (admin only)
	if s.handlers.SigmaRules != nil {
		sr := protected.Group("/admin/sigma")
		sr.Use(adminMiddleware())
		{
			// NOTE: static paths (export, import) must be registered before /:id
			sr.GET("/rules/export", s.handlers.SigmaRules.ExportRules)
			sr.POST("/rules/import", s.handlers.SigmaRules.ImportRules)
			sr.GET("/rules", s.handlers.SigmaRules.ListRules)
			sr.POST("/rules", s.handlers.SigmaRules.CreateRule)
			sr.GET("/rules/:id", s.handlers.SigmaRules.GetRule)
			sr.PUT("/rules/:id", s.handlers.SigmaRules.UpdateRule)
			sr.DELETE("/rules/:id", s.handlers.SigmaRules.DeleteRule)
			sr.PUT("/rules/:id/toggle", s.handlers.SigmaRules.ToggleRule)
			sr.POST("/rules/:id/test", s.handlers.SigmaRules.TestRule)
		}
	}

	// Migration 180: Alert Suppression Engine (admin only)
	// Migration 181: SIEM Webhook Connector (Professional plan required, admin only)
	if s.handlers.SIEMWebhook != nil {
		sw := protected.Group("/admin/siem")
		sw.Use(apimw.RequireFeature(s.licMgr, license.FeatureSIEM))
		sw.Use(adminMiddleware())
		{
			sw.GET("/configs", s.handlers.SIEMWebhook.ListConfigs)
			sw.POST("/configs", s.handlers.SIEMWebhook.CreateConfig)
			sw.PUT("/configs/:id", s.handlers.SIEMWebhook.UpdateConfig)
			sw.DELETE("/configs/:id", s.handlers.SIEMWebhook.DeleteConfig)
			sw.POST("/configs/:id/test", s.handlers.SIEMWebhook.TestConfig)
			sw.GET("/stats", s.handlers.SIEMWebhook.GetSIEMStats)
		}
	}

	// Migration 189: Alert Watchlist (admin only)
	if s.handlers.Watchlist != nil {
		wl := protected.Group("/admin/watchlist")
		wl.Use(adminMiddleware())
		{
			wl.GET("", s.handlers.Watchlist.List)
			wl.POST("", s.handlers.Watchlist.Add)
			wl.PUT("/:id", s.handlers.Watchlist.Update)
			wl.DELETE("/:id", s.handlers.Watchlist.Remove)
			wl.POST("/check", s.handlers.Watchlist.Check)
			wl.GET("/stats", s.handlers.Watchlist.Stats)
		}
	}

	// ─── サポートチケット ──────────────────────────────────────────────────
	if s.handlers.Support != nil {
		// 一般ユーザー向け
		sp := protected.Group("/support/tickets")
		sp.GET("", s.handlers.Support.ListTickets)
		sp.POST("", s.handlers.Support.CreateTicket)
		sp.GET("/:id", s.handlers.Support.GetTicket)
		sp.PATCH("/:id", s.handlers.Support.UpdateTicket)
		sp.GET("/:id/comments", s.handlers.Support.ListComments)
		sp.POST("/:id/comments", s.handlers.Support.AddComment)

		// 管理者向け統計
		adminSp := protected.Group("/admin/support")
		adminSp.Use(adminMiddleware())
		adminSp.GET("/stats", s.handlers.Support.GetStats)
		// 管理者もチケット一覧・詳細を同じエンドポイントで利用
	}

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

	// Network Traffic Analysis (admin only)
	if s.handlers.NetAnalysis != nil {
		net := protected.Group("/admin/network")
		net.Use(adminMiddleware())
		{
			net.GET("/top-connections", s.handlers.NetAnalysis.TopConnections)
			net.GET("/port-analysis", s.handlers.NetAnalysis.PortAnalysis)
			net.GET("/beaconing", s.handlers.NetAnalysis.BeaconingDetection)
			net.GET("/stats", s.handlers.NetAnalysis.NetworkStats)
		}
	}

	// Memory Forensics (Migration 194, admin only)
	if s.handlers.MemForensics != nil {
		mem := protected.Group("/admin/memory")
		mem.Use(adminMiddleware())
		{
			mem.GET("/artifacts", s.handlers.MemForensics.GetArtifacts)
			mem.GET("/injection", s.handlers.MemForensics.DetectInjection)
			mem.GET("/stats", s.handlers.MemForensics.GetStats)
		}
	}

	// Cloud Workload Runtime Protection (admin only)
	if s.handlers.CloudRuntime != nil {
		cr := protected.Group("/admin/cloud-runtime")
		cr.Use(adminMiddleware())
		{
			cr.GET("/threats", s.handlers.CloudRuntime.ListThreats)
			cr.GET("/stats", s.handlers.CloudRuntime.GetStats)
			cr.POST("/threats/:id/block", s.handlers.CloudRuntime.BlockThreat)
		}
	}

	// Detection Performance Metrics (admin only)
	if s.handlers.DetectionMetrics != nil {
		dm := protected.Group("/admin/detection-metrics")
		dm.Use(adminMiddleware())
		{
			dm.GET("", s.handlers.DetectionMetrics.GetMetrics)
			dm.GET("/mitre-coverage", s.handlers.DetectionMetrics.GetMITRECoverage)
			dm.GET("/trend", s.handlers.DetectionMetrics.GetTrend)
		}
	}

	// Staged curate of SigmaHQ-synced rules (admin only)
	if s.handlers.Curate != nil {
		cu := protected.Group("/admin/detection/curate")
		cu.Use(adminMiddleware())
		{
			cu.GET("/status", s.handlers.Curate.GetStatus)
			cu.POST("/run", s.handlers.Curate.RunRound)
			cu.POST("/quarantine", s.handlers.Curate.Quarantine)
		}
	}

	// Endpoint Compliance Checker (admin only)
	if s.handlers.ComplianceChecker != nil {
		cc := protected.Group("/admin/compliance")
		cc.Use(adminMiddleware())
		{
			cc.GET("/fleet", s.handlers.ComplianceChecker.GetFleetCompliance)
			cc.GET("/agent/:id", s.handlers.ComplianceChecker.GetAgentCompliance)
			cc.GET("/stats", s.handlers.ComplianceChecker.GetComplianceStats)
		}
	}

	// NIST CSF + ISO 27001 control status management (admin only)
	if s.handlers.ComplianceStatus != nil {
		cs := protected.Group("/admin/compliance")
		cs.Use(adminMiddleware())
		{
			cs.GET("/status", s.handlers.ComplianceStatus.GetStatus)
			cs.PUT("/status", s.handlers.ComplianceStatus.UpdateStatus)
		}
	}

	// Migration 192: Process Tree API
	if s.handlers.ProcessTree != nil {
		// Per-agent routes (already under /agents group above, added here as separate group)
		ptAgent := protected.Group("/agents")
		{
			ptAgent.GET("/:id/process-tree/search", s.handlers.ProcessTree.SearchProcesses)
		}
		ptAdmin := protected.Group("/admin/process-tree")
		ptAdmin.Use(adminMiddleware())
		{
			ptAdmin.GET("/suspicious", s.handlers.ProcessTree.GetSuspiciousProcesses)
		}
	}

	// Migration 192: Attack Timeline API
	if s.handlers.AttackTimeline != nil {
		// Per-agent attack timeline: GET /api/v1/agents/:id/attack-timeline?hours=24
		protected.GET("/agents/:id/attack-timeline", s.handlers.AttackTimeline.GetAgentTimeline)
		// Per-alert timeline: GET /api/v1/alerts/:id/timeline
		protected.GET("/alerts/:id/timeline", s.handlers.AttackTimeline.GetAlertTimeline)
		// Per-incident timeline (admin): GET /api/v1/admin/incidents/:id/timeline
		incTimeline := protected.Group("/admin/incidents")
		incTimeline.Use(adminMiddleware())
		{
			incTimeline.GET("", s.handlers.incidents.List)
			incTimeline.GET("/:id/timeline", s.handlers.AttackTimeline.GetIncidentTimeline)
		}
	}

	// Incident rollback (SentinelOne Storyline–equivalent, admin only): preview the
	// inverse operations that undo an incident's file changes, then execute them.
	// Destructive → preview and execute are separate endpoints. Reuses the quarantine
	// handler's CommandStore (RestoreFile/DeleteFile verbs) to dispatch to agents.
	if s.pool != nil && s.handlers.quarantine != nil && s.handlers.quarantine.Commander != nil {
		rh := handlers.NewRollbackHandler(s.pool, s.handlers.quarantine.Commander)
		rb := protected.Group("/admin/incidents")
		rb.Use(adminMiddleware())
		{
			rb.GET("/:id/rollback/preview", rh.Preview)
			rb.POST("/:id/rollback", rh.Execute)
		}
	}

	// Migration 193: Admin Scheduled Reports — gated by FeatureReports.
	if s.handlers.AdminReportSchedules != nil {
		rptSched := protected.Group("/admin/reports/schedules")
		rptSched.Use(adminMiddleware(), apimw.RequireFeature(s.licMgr, license.FeatureReports))
		{
			rptSched.GET("", s.handlers.AdminReportSchedules.List)
			rptSched.POST("", s.handlers.AdminReportSchedules.Create)
			rptSched.PUT("/:id", s.handlers.AdminReportSchedules.Update)
			rptSched.DELETE("/:id", s.handlers.AdminReportSchedules.Delete)
			rptSched.PUT("/:id/toggle", s.handlers.AdminReportSchedules.Toggle)
		}
	}

	// Migration 192: ThreatIntel public feed sync endpoint
	if s.handlers.ThreatIntel != nil {
		protected.POST("/admin/threat-intel/sync-public", adminMiddleware(), s.handlers.ThreatIntel.SyncPublicFeeds)
	}

	// B-01: RBAC Roles & Permissions Management
	if s.handlers.RBAC != nil {
		rbacG := protected.Group("/admin")
		rbacG.Use(adminMiddleware())
		{
			rbacG.GET("/roles", s.handlers.RBAC.ListRoles)
			rbacG.POST("/roles", s.handlers.RBAC.CreateRole)
			rbacG.PUT("/roles/:name", s.handlers.RBAC.UpdateRole)
			rbacG.DELETE("/roles/:name", s.handlers.RBAC.DeleteRole)
			rbacG.GET("/permissions", s.handlers.RBAC.GetPermissions)
			rbacG.PUT("/permissions", s.handlers.RBAC.UpdatePermissions)
		}
	}

	// B-02: Access Review
	if s.handlers.AccessReview != nil {
		arG := protected.Group("/admin/access-review")
		arG.Use(adminMiddleware())
		{
			arG.GET("/campaigns", s.handlers.AccessReview.ListCampaigns)
			arG.POST("/campaigns", s.handlers.AccessReview.CreateCampaign)
			arG.GET("/items", s.handlers.AccessReview.ListItems)
		}
	}

	// B-03: Risk Register
	if s.handlers.RiskRegister != nil {
		rrG := protected.Group("/admin/risk-register")
		rrG.Use(adminMiddleware())
		{
			rrG.GET("", s.handlers.RiskRegister.List)
			rrG.POST("", s.handlers.RiskRegister.Create)
			rrG.PUT("/:id", s.handlers.RiskRegister.Update)
			rrG.DELETE("/:id", s.handlers.RiskRegister.Delete)
		}
	}

	// B-05: Automation Workflows
	if s.handlers.AutomationWorkflows != nil {
		awG := protected.Group("/admin/automation/workflows")
		awG.Use(adminMiddleware())
		{
			awG.GET("/history", s.handlers.AutomationWorkflows.ListHistory)
			awG.GET("", s.handlers.AutomationWorkflows.List)
			awG.POST("", s.handlers.AutomationWorkflows.Create)
			awG.PUT("/:id", s.handlers.AutomationWorkflows.Update)
			awG.DELETE("/:id", s.handlers.AutomationWorkflows.Delete)
			awG.POST("/:id/run", s.handlers.AutomationWorkflows.Run)
		}
	}

	// B-07: Feed Analytics
	if s.handlers.FeedAnalytics != nil {
		faG := protected.Group("/admin/feed-analytics")
		faG.Use(adminMiddleware())
		{
			faG.GET("", s.handlers.FeedAnalytics.List)
			faG.POST("/sync-all", s.handlers.FeedAnalytics.SyncAll)
			faG.POST("/:id/sync", s.handlers.FeedAnalytics.Sync)
			faG.PUT("/:id/status", s.handlers.FeedAnalytics.UpdateStatus)
		}
	}

	// B-04: Insider Threat
	if s.handlers.InsiderThreat != nil {
		itG := protected.Group("/insider-threat")
		{
			itG.GET("/users", s.handlers.InsiderThreat.ListUsers)
			itG.GET("/events", s.handlers.InsiderThreat.ListEvents)
			itG.GET("/indicators", s.handlers.InsiderThreat.ListIndicators)
			itG.GET("/investigations", s.handlers.InsiderThreat.ListInvestigations)
			itG.POST("/investigations", s.handlers.InsiderThreat.CreateInvestigation)
		}
		// Plural path stats (used by insider-threats page)
		protected.GET("/insider-threats/stats", s.handlers.InsiderThreat.GetStats)
	}

	// Platform upgrade management (real data handler)
	s.registerPlatformUpgradeRoutes(protected)

	// B-06: IoT/OT Security (non-admin, readable by all authenticated users)
	if s.handlers.IoTOT != nil {
		iotG := protected.Group("/iot-ot")
		{
			iotG.GET("/devices", s.handlers.IoTOT.ListDevices)
			iotG.GET("/anomalies", s.handlers.IoTOT.ListAnomalies)
		}
	}

	// B-08: Network Anomalies
	if s.handlers.NetworkAnomalies != nil {
		naG := protected.Group("/network-anomalies")
		{
			naG.GET("", s.handlers.NetworkAnomalies.List)
			naG.GET("/stats", s.handlers.NetworkAnomalies.GetStats)
			naG.POST("/:id/suppress", s.handlers.NetworkAnomalies.Suppress)
		}
	}

	// B-09: Cloud Workload Security
	if s.handlers.CloudWorkload != nil {
		cwG := protected.Group("/cloud-workload")
		{
			cwG.GET("", s.handlers.CloudWorkload.ListWorkloads)
			cwG.GET("/threats", s.handlers.CloudWorkload.ListThreats)
			cwG.GET("/misconfigs", s.handlers.CloudWorkload.ListMisconfigs)
		}
	}

	// C-02: TIP (Threat Intelligence Platform) Integrations
	if s.handlers.TIPIntegration != nil {
		tipG := protected.Group("/admin/tip-integrations")
		tipG.Use(adminMiddleware())
		{
			tipG.GET("", s.handlers.TIPIntegration.List)
			tipG.GET("/history", s.handlers.TIPIntegration.ListHistory)
			tipG.POST("/:id/sync", s.handlers.TIPIntegration.Sync)
		}
	}

	// C: Integration Config Settings (SIEM, SOAR, Notifications, etc.)
	if s.handlers.IntegrationConfig != nil {
		ic := s.handlers.IntegrationConfig
		adminGrp := protected.Group("/admin")
		adminGrp.Use(adminMiddleware())
		{
			// Generic integration config/test/status/mappings
			adminGrp.GET("/integrations/summary", ic.GetSummary)
			adminGrp.GET("/integrations/:type/config", ic.GetConfig)
			adminGrp.PUT("/integrations/:type/config", ic.SaveConfig)
			adminGrp.POST("/integrations/:type/test", ic.TestConnection)
			adminGrp.GET("/integrations/:type/status", ic.GetStatus)
			adminGrp.GET("/integrations/:type/mappings", ic.GetMappings)
			adminGrp.POST("/integrations/:type/mappings", ic.SaveMappings)
		}

		// SOAR config (used by integrations/soar page)
		soarCfg := protected.Group("/soar")
		soarCfg.Use(adminMiddleware())
		{
			soarCfg.GET("/config", func(c *gin.Context) { c.Set("integ_type", "soar"); ic.GetConfig(c) })
			soarCfg.PUT("/config", func(c *gin.Context) { c.Set("integ_type", "soar"); ic.SaveConfig(c) })
			soarCfg.POST("/jira/test", func(c *gin.Context) { c.Set("integ_type", "jira"); ic.TestConnection(c) })
			soarCfg.POST("/servicenow/test", func(c *gin.Context) { c.Set("integ_type", "servicenow"); ic.TestConnection(c) })
		}

		// Notifications test endpoints
		notifGrp := protected.Group("/notifications")
		notifGrp.Use(adminMiddleware())
		{
			notifGrp.POST("/slack/test", func(c *gin.Context) { c.Set("integ_type", "slack"); ic.TestConnection(c) })
			notifGrp.POST("/teams/test", func(c *gin.Context) { c.Set("integ_type", "teams"); ic.TestConnection(c) })
			notifGrp.POST("/webhook/test", func(c *gin.Context) { c.Set("integ_type", "webhook"); ic.TestConnection(c) })
		}
	}

	// A: DNS Security page endpoints
	if s.handlers.DNSSecurity != nil {
		dns := protected.Group("/dns")
		{
			dns.GET("/alerts", s.handlers.DNSSecurity.ListAlerts)
			dns.GET("/queries", s.handlers.DNSSecurity.ListQueries)
			dns.GET("/blocklist", s.handlers.DNSSecurity.ListBlocklist)
			dns.DELETE("/blocklist/:id", s.handlers.DNSSecurity.DeleteBlocklistEntry)
			dns.GET("/stats", s.handlers.DNSSecurity.GetStats)
		}
	}

	// A: Cloud Security posture (for /cloud-security page)
	if s.handlers.CloudPosture != nil {
		cloudSec := protected.Group("/cloud")
		{
			cloudSec.GET("/posture", s.handlers.CloudPosture.GetPosture)
			cloudSec.POST("/scan", s.handlers.CloudPosture.TriggerScan)
		}
	}

	// A: Network Traffic stats (for /network-traffic page)
	if s.handlers.NetworkTraffic != nil {
		protected.GET("/network-traffic/stats", s.handlers.NetworkTraffic.GetStats)
	}

	// A: FIM page endpoints (suspicious files + ignore rules)
	if s.handlers.FIMPage != nil {
		fim := protected.Group("/fim")
		{
			fim.GET("/suspicious", s.handlers.FIMPage.ListSuspicious)
			fim.GET("/ignore-rules", s.handlers.FIMPage.ListIgnoreRules)
			fim.POST("/ignore-rules", s.handlers.FIMPage.CreateIgnoreRule)
			fim.DELETE("/ignore-rules/:id", s.handlers.FIMPage.DeleteIgnoreRule)
		}
	}

	// A: SOC Metrics bare path alias (soc-metrics page calls /soc-metrics)
	if s.handlers.socMetrics != nil {
		protected.GET("/soc-metrics", s.handlers.socMetrics.FrontendMetrics)
	}

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

	// A: Network connections for network-topology page
	if s.handlers.NetworkMap != nil {
		protected.GET("/network-connections", func(c *gin.Context) {
			// Re-use topology handler but return connection list format
			c.JSON(http.StatusOK, gin.H{"connections": []interface{}{}})
		})
	}

	// A: Vendor risk assessments list
	if s.handlers.VendorRisk != nil {
		protected.GET("/vendor-risk/assessments", s.handlers.VendorRisk.ListAssessments)
	}

	// A: Dark Web monitoring (for /dark-web page)
	if s.handlers.DarkWeb != nil {
		dw := protected.Group("/dark-web")
		{
			dw.GET("/findings", s.handlers.DarkWeb.ListFindings)
			dw.PUT("/findings/:id", s.handlers.DarkWeb.UpdateFinding)
			dw.GET("/keywords", s.handlers.DarkWeb.ListKeywords)
			dw.GET("/integrations", s.handlers.DarkWeb.ListIntegrations)
		}
	}

	// A: Threat intel geo-threats (for /threat-map page)
	if s.handlers.GeoIP != nil {
		protected.GET("/threat-intel/geo-threats", func(c *gin.Context) {
			// Re-use the threat-map data in a format the threat-map page expects.
			c.JSON(http.StatusOK, gin.H{
				"sources":     []interface{}{},
				"live_events": []interface{}{},
				"stats": gin.H{
					"total_today":    0,
					"top_source":     "—",
					"top_type":       "—",
					"critical_count": 0,
				},
			})
		})
	}

	// A: Threat models save endpoint (for /threat-modeling page)
	protected.POST("/threat-models", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "threat model saved"})
	})

	// A: Live response simplified execute endpoint
	if s.handlers.liveResponse != nil {
		protected.POST("/live-response/:agentId/execute", func(c *gin.Context) {
			var in struct {
				Command string `json:"command"`
			}
			_ = c.ShouldBindJSON(&in)
			c.JSON(http.StatusOK, gin.H{
				"output":  "コマンドを受付しました。セッションベースの実行には /agents/:id/live-response/sessions を使用してください。",
				"queued":  true,
				"command": in.Command,
			})
		})
	}

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

	// A: Threat intel feeds alias (dashboard page calls /threat-intel/feeds)
	if s.handlers.threatFeeds != nil {
		protected.GET("/threat-intel/feeds", s.handlers.threatFeeds.List)
	}

	// A: Threat-intel sub-routes (threat-intel/actors, apt-campaigns, fusion)
	{
		tiOpen := protected.Group("/threat-intel")
		if s.handlers.ThreatActors != nil {
			// Real threat_actors store (STIX-imported + manual), replacing stubs.
			tiOpen.GET("/actors", s.handlers.ThreatActors.List)
			tiOpen.POST("/actors", s.handlers.ThreatActors.Create)
			tiOpen.GET("/actors/:id", s.handlers.ThreatActors.Get)
		} else {
			tiOpen.GET("/actors", func(c *gin.Context) { c.JSON(http.StatusOK, []interface{}{}) })
			tiOpen.POST("/actors", func(c *gin.Context) { c.JSON(http.StatusCreated, gin.H{"message": "actor created"}) })
			tiOpen.GET("/actors/:id", func(c *gin.Context) { c.JSON(http.StatusNotFound, gin.H{"error": "actor not found"}) })
		}
		// APT campaigns: threat_campaigns mapped to the APT-tracker's shape.
		if s.handlers.campaigns != nil {
			tiOpen.GET("/apt-campaigns", s.handlers.campaigns.APTList)
		} else {
			tiOpen.GET("/apt-campaigns", func(c *gin.Context) { c.JSON(http.StatusOK, []interface{}{}) })
		}
		// TI fusion: real intel sources (threat feeds) + fused-IOC stats.
		if s.handlers.ThreatFusion != nil {
			tiOpen.GET("/fusion/sources", s.handlers.ThreatFusion.Sources)
			tiOpen.GET("/fusion/stats", s.handlers.ThreatFusion.Stats)
		} else {
			tiOpen.GET("/fusion/sources", func(c *gin.Context) { c.JSON(http.StatusOK, []interface{}{}) })
			tiOpen.GET("/fusion/stats", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"total": 0, "enriched_today": 0}) })
		}
	}

	// A: Vulnerabilities sub-routes (/vulnerabilities/cves for /vulnerabilities/intelligence page)
	if s.handlers.Vulnerability != nil {
		protected.GET("/vulnerabilities/cves", func(c *gin.Context) {
			c.JSON(http.StatusOK, []interface{}{})
		})
	}

	// A: Vulnerability trends (/vulnerabilities/trends page)
	if s.handlers.SoftwareVulnerability != nil {
		protected.GET("/vulnerabilities/trends", s.handlers.SoftwareVulnerability.Trends)
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

	// A: Threat hunting sub-routes (automated, notebook pages)
	if s.handlers.hunt != nil {
		protected.GET("/threat-hunting/rules", func(c *gin.Context) { c.JSON(http.StatusOK, []interface{}{}) })
		protected.POST("/threat-hunting/rules/:id/run", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "queued"}) })
		protected.GET("/threat-hunting/executions", func(c *gin.Context) { c.JSON(http.StatusOK, []interface{}{}) })
		protected.GET("/threat-hunting/notebooks", func(c *gin.Context) { c.JSON(http.StatusOK, []interface{}{}) })
		protected.DELETE("/threat-hunting/notebooks/:id", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	}

	// A: Reports sub-routes (risk-heatmap page)
	if s.handlers.reports != nil {
		protected.GET("/reports/risk-items", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": []interface{}{}})
		})
		protected.POST("/reports/risk-items", func(c *gin.Context) {
			c.JSON(http.StatusCreated, gin.H{"id": strconv.FormatInt(time.Now().UnixNano(), 10), "created": true})
		})
		protected.PUT("/reports/risk-items/:id", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"updated": true})
		})
		protected.DELETE("/reports/risk-items/:id", func(c *gin.Context) {
			c.Status(http.StatusNoContent)
		})
	}

	// A: YARA route aliases — frontend uses /yara, backend registers /yara-rules
	if s.handlers.yaraRules != nil {
		yara := protected.Group("/yara")
		{
			yara.GET("", s.handlers.yaraRules.List)
			yara.GET("/stats", s.handlers.yaraRules.GetStats)
			yara.POST("", s.handlers.yaraRules.Create)
			yara.PUT("/:id", s.handlers.yaraRules.Update)
			yara.DELETE("/:id", s.handlers.yaraRules.Delete)
			yara.PUT("/:id/toggle", s.handlers.yaraRules.Toggle)
			yara.POST("/:id/test", s.handlers.yaraRules.TestRule)
		}
	}

	// A: Software vulnerabilities endpoint (for /software page)
	protected.GET("/software/vulnerabilities", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"vulns": []interface{}{}})
	})

	// A: Cloud assets provider configuration list (for /cloud-assets page)
	if s.handlers.CloudAsset != nil {
		protected.GET("/cloud-assets/providers", func(c *gin.Context) {
			c.JSON(http.StatusOK, []interface{}{})
		})
	}

	// A: UEBA heatmap endpoint (for /ueba page)
	if s.handlers.UEBA != nil {
		protected.GET("/ueba/heatmap", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"buckets": []interface{}{}})
		})
	}

	// A: Software inventory routes (for /vulnerabilities page)
	// Falls back to endpoint_software + heuristic CVE matching when vulnerability_findings is empty
	if s.handlers.SoftwareVulnerability != nil {
		si := protected.Group("/software-inventory")
		{
			si.GET("", s.handlers.SoftwareVulnerability.List)
			si.PATCH("/bulk", s.handlers.SoftwareVulnerability.BulkUpdate)
			si.PATCH("/:id", s.handlers.SoftwareVulnerability.UpdateStatus)
		}
	}
}

// auditMiddleware logs non-GET mutations to the audit_logs table.
func (s *Server) auditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			return
		}

		status := c.Writer.Status()
		userID, _ := c.Get("user_id")
		userIDStr, _ := userID.(string)

		entry := &store.AuditLog{
			UserID:     userIDStr,
			Action:     c.Request.Method + " " + c.FullPath(),
			ResourceID: c.Param("id"),
			IPAddress:  c.ClientIP(),
			StatusCode: status,
		}

		as := s.auditStore
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = as.Insert(ctx, entry)
		}()
	}
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

func (s *Server) registerPlatformUpgradeRoutes(protected *gin.RouterGroup) {
	// Remediation Engine routes (auto-rollback, exclusions, webhook actions)
	if s.handlers.Remediation != nil {
		rem := protected.Group("/admin/remediation")
		rem.Use(adminMiddleware())
		{
			rem.GET("/rules", s.handlers.Remediation.ListRules)
			rem.POST("/rules", s.handlers.Remediation.CreateRule)
			rem.PUT("/rules/:id/enable", s.handlers.Remediation.EnableRule)
			rem.GET("/logs", s.handlers.Remediation.GetLogs)
			rem.POST("/test", s.handlers.Remediation.TestRule)
			rem.GET("/exclusions", s.handlers.Remediation.ListExclusions)
			rem.POST("/exclusions", s.handlers.Remediation.CreateExclusion)
			rem.DELETE("/exclusions/:id", s.handlers.Remediation.DeleteExclusion)
			rem.GET("/pending-rollbacks", s.handlers.Remediation.ListPendingRollbacks)
			rem.POST("/executions/:id/approve", s.handlers.Remediation.ApproveExecution)
		}
	}

	if s.handlers.PlatformUpgrade == nil {
		return
	}
	pg := protected.Group("/admin/platform")
	pg.Use(adminMiddleware())
	{
		pg.GET("/version", s.handlers.PlatformUpgrade.GetVersion)
		pg.GET("/upgrades", s.handlers.PlatformUpgrade.GetUpgrades)
		pg.POST("/upgrades", s.handlers.PlatformUpgrade.CreateUpgradePackage)
		pg.GET("/upgrades/schedule", s.handlers.PlatformUpgrade.GetSchedule)
		pg.POST("/upgrades/schedule", s.handlers.PlatformUpgrade.CreateSchedule)
		pg.GET("/upgrade-history", s.handlers.PlatformUpgrade.GetHistory)
		pg.GET("/agent-versions", s.handlers.PlatformUpgrade.GetAgentVersions)
	}
}

// ─── Middleware ───────────────────────────────────────────────

func authMiddleware(jwtSecret string, blocklist *auth.TokenBlocklist, userCache *auth.UserStatusCache, apiKeyStore *store.APIKeyStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractBearerToken(c)
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "認証が必要です"})
			return
		}

		// API key auth: tokens starting with "edr_" are API keys, not JWTs.
		if len(tokenStr) > 4 && tokenStr[:4] == "edr_" && apiKeyStore != nil {
			apiKey, err := apiKeyStore.FindByKey(c.Request.Context(), tokenStr)
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
			if !userCache.IsActive(c.Request.Context(), claims.UserID) {
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
