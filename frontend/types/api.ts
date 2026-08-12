// API type definitions for the EDR platform frontend

// ─── Common ───────────────────────────────────────────────────

export type Platform = 'windows' | 'linux' | 'darwin' | 'ios' | 'android'
// 'inactive' = 30日以上未確認で DeadAgentCleanup が退役扱いにした状態
// (migration 315/330 で status の CHECK に追加)。AgentStatusBadge は既に対応済み。
export type AgentStatus = 'online' | 'offline' | 'isolated' | 'error' | 'inactive'
export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false_positive' | 'auto_resolved'
export type AlertSeverity = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10
export type UserRole = 'admin' | 'analyst' | 'viewer'
export type RuleType = 'yara' | 'sigma' | 'behavioral'
export type EventType = 'process' | 'file' | 'network' | 'dns' | 'registry' | 'auth'

// ─── Agent ────────────────────────────────────────────────────

export interface Agent {
  id: string
  hostname: string
  os_type: Platform
  os_version: string
  agent_version: string
  ip_addresses: string[]
  status: AgentStatus
  last_seen: string // ISO timestamp
  enrolled_at: string
  group_id?: string
  policy_id?: string
  tags: string[]
  isolated_at?: string
  isolated_reason?: string
  isolated_by?: string
  cpu_model?: string
  total_memory_mb?: number
}

export interface AgentGroup {
  id: string
  name: string
  description?: string
  agent_count: number
  created_at: string
}

// ─── Alert ────────────────────────────────────────────────────

export interface Alert {
  id: string
  rule_id?: string
  rule_name?: string
  agent_id: string
  agent_hostname: string
  agent_os: Platform
  severity: AlertSeverity
  status: AlertStatus
  title: string
  description?: string
  anomaly_score?: number
  mitre_technique?: string
  // AI Analysis
  ai_analyzed: boolean
  ai_is_threat?: boolean
  ai_severity?: AlertSeverity
  ai_confidence?: number
  ai_threat_name?: string
  ai_summary?: string
  ai_report?: string
  ai_attack_chain?: string[]
  ai_mitre_tags?: string[]
  // Assignment
  assigned_to?: string
  assigned_to_name?: string
  comment_count?: number
  resolved_at?: string
  created_at: string
  updated_at: string
  // Included relations
  comments?: AlertComment[]
  related_events?: Event[]
}

export interface AlertComment {
  id: string
  alert_id: string
  user_id: string
  user_name: string
  content: string
  created_at: string
}

export interface AlertStats {
  total: number
  open: number
  investigating: number
  resolved: number
  false_positive: number
  by_severity: Record<string, number>
  by_os: Record<Platform, number>
  today_count: number
  trend_24h: number // percentage change vs previous 24h
}

export interface DashboardSummary {
  agents: {
    total: number
    online: number
    offline: number
    isolated: number
  }
  alerts: AlertStats
  top_threatened_agents: TopThreatenedAgent[]
  recent_alerts: Alert[]
  event_timeline: EventTimelinePoint[]
}

export interface TopThreatenedAgent {
  agent_id: string
  hostname: string
  alert_count: number
  max_severity: number
}

export interface EventTimelinePoint {
  bucket: string // ISO timestamp (hourly)
  process_events: number
  file_events: number
  network_events: number
  alert_count: number
}

// ─── Event ────────────────────────────────────────────────────

export interface Event {
  time: string
  agent_id: string
  event_id: string
  event_type: EventType
  severity: number
  anomaly_score: number
  raw_data: ProcessEventData | FileEventData | NetworkEventData | DnsEventData
  rule_matches?: string[]
  alert_id?: string
}

export interface ProcessEventData {
  pid: number
  ppid: number
  process_name: string
  command_line: string
  image_path: string
  username: string
  action: string
  hashes?: { md5: string; sha256: string }
}

export interface FileEventData {
  path: string
  old_path?: string
  action: string
  pid: number
  process_name: string
  file_size: number
  hashes?: { sha256: string }
}

export interface NetworkEventData {
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: string
  direction: string
  bytes_sent: number
  bytes_recv: number
  pid: number
  process_name: string
  hostname?: string
  country_code?: string
}

export interface DnsEventData {
  query: string
  query_type: string
  answers: string[]
  pid: number
  process_name: string
  is_suspicious: boolean
}

// ─── Detection Rule ───────────────────────────────────────────

export interface Rule {
  id: string
  name: string
  type: RuleType
  platform: Platform[]
  severity: AlertSeverity
  content: string
  enabled: boolean
  source: 'community' | 'custom' | 'threat-intel' | 'ai-generated'
  mitre_tags?: string[]
  auto_isolate: boolean
  auto_kill: boolean
  auto_quarantine: boolean
  description?: string
  false_positive_rate: number
  created_by?: string
  created_at: string
  updated_at: string
}

// ─── AI Analysis ──────────────────────────────────────────────

export interface ThreatAnalysis {
  alert_id: string
  is_threat: boolean
  is_false_positive: boolean
  severity: number
  confidence: number
  threat_name?: string
  attack_techniques: MITRETechnique[]
  attack_chain: string[]
  recommended_actions: RecommendedAction[]
  auto_response?: AutoResponseDecision
  summary: string
  detailed_report: string
  analyzed_at: string
}

export interface MITRETechnique {
  id: string  // e.g. "T1059.001"
  name: string
}

export interface RecommendedAction {
  action: string
  target?: string
  priority: 'immediate' | 'high' | 'normal'
  reason: string
}

export interface AutoResponseDecision {
  should_isolate: boolean
  should_kill_process: boolean
  kill_pid?: number
  should_quarantine: boolean
  quarantine_path?: string
  reasoning: string
}

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  timestamp?: string
}

// ─── Response Actions ─────────────────────────────────────────

export interface ResponseActionLog {
  id: string
  alert_id?: string
  agent_id: string
  agent_hostname?: string
  action_type: string
  target?: string
  reason?: string
  executed_by: string
  success: boolean
  error_msg?: string
  executed_at: string
}

// ─── API Response Wrappers ────────────────────────────────────

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  has_more: boolean
}

export interface ApiError {
  error: string
  code?: string
}

// ─── YARA Rules ──────────────────────────────────────────────
export interface YARARule {
  id: string
  name: string
  category: string
  severity: string
  content: string
  description?: string
  enabled: boolean
  match_count: number
  last_matched?: string
  created_at: string
  updated_at: string
}

// ─── API Keys ────────────────────────────────────────────────
export interface APIKey {
  id: string
  name: string
  prefix: string
  scopes: string[]
  last_used?: string
  expires_at?: string
  revoked: boolean
  created_at: string
}

// ─── SSO Config ──────────────────────────────────────────────
export interface SSOConfig {
  id: string
  name: string
  provider: 'saml' | 'oidc'
  enabled: boolean
  default_role: string
  idp_sso_url?: string
  idp_cert?: string
  discovery_url?: string
  client_id?: string
  attribute_mapping?: Record<string, string>
  created_at: string
}

// ─── Process Block Rules ─────────────────────────────────────
export interface ProcessBlockRule {
  id: string
  name: string
  process_name: string
  rule_type: 'allow' | 'deny'
  scope: 'all' | 'group' | 'agent'
  scope_id?: string
  action: 'alert' | 'block' | 'alert_and_block'
  enabled: boolean
  severity: 'low' | 'medium' | 'high' | 'critical'
  created_at: string
  updated_at: string
}

// ─── Alert Assign Rules ──────────────────────────────────────
export interface AlertAssignRule {
  id: string
  name: string
  priority: number
  conditions: { severity_match?: string[]; rule_id_match?: string[] }
  assignee_id: string
  enabled: boolean
  created_at: string
}

// ─── Escalation Rules ────────────────────────────────────────
export interface EscalationRule {
  id: string
  name: string
  severity_min: number
  unresolved_mins: number
  escalate_to: string
  notify_channel?: string
  enabled: boolean
  created_at: string
  updated_at: string
}

// ─── Saved Hunt Queries ──────────────────────────────────────
export interface SavedHuntQuery {
  id: string
  name: string
  description?: string
  query: string
  query_type: 'sql' | 'kql' | 'yara' | 'sigma'
  tags: string[]
  is_shared: boolean
  created_by: string
  run_count: number
  last_run_at?: string
  created_at: string
  updated_at: string
}

// ─── Backup ──────────────────────────────────────────────────
export interface Backup {
  id: string
  filename: string
  size_bytes: number
  status: 'pending' | 'running' | 'completed' | 'failed'
  created_at: string
  completed_at?: string
  error?: string
}

// ─── Forensic Artifacts ──────────────────────────────────────
export interface ForensicArtifact {
  id: string
  agent_id: string
  hostname: string
  artifact_type: string
  file_name: string
  file_size: number
  sha256: string
  status: 'pending' | 'collecting' | 'ready' | 'failed'
  collected_at?: string
  created_at: string
}

// ─── Dashboard Stats ─────────────────────────────────────────
export interface AlertTrendDay {
  date: string
  count: number
  critical: number
}

export interface DetectionRate {
  total_alerts_7d: number
  resolved_7d: number
  resolution_rate: number
  avg_resolution_hours: number
  open_critical: number
}

// ─── User Preferences ────────────────────────────────────────
export interface UserPreferences {
  theme: 'dark' | 'light' | 'system'
  language: string
  timezone: string
  alerts_per_page: number
  default_severity_filter: string
  email_notifications: boolean
  notification_sound: boolean
  dashboard_layout?: string
}

// ─── Notification Template ───────────────────────────────────
export interface NotificationTemplate {
  id: string
  name: string
  channel_type: string
  subject_template: string
  body_template: string
  enabled: boolean
  created_at: string
}
