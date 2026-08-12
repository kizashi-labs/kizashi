'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Clock, TrendingUp, Database, Lock,
  AlertTriangle, User, ChevronRight, Filter, X,
  Search, Activity, UserX, Eye, BarChart2,
  Minus, ArrowUp, ArrowDown, Calendar
} from 'lucide-react'
import Link from 'next/link'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ─────────────────────────────────────────────────────────────────────

type ThreatType = 'after_hours' | 'privilege_escalation' | 'bulk_data' | 'failed_login'
type Severity = 'low' | 'medium' | 'high' | 'critical'

interface InsiderThreatAlert {
  id: string
  threat_type: ThreatType
  title: string
  description: string
  user_id: string
  username: string
  department: string
  timestamp: string
  severity: Severity
  ip_address: string
  resource: string
  details: Record<string, unknown>
}

interface UEBAUser {
  id: string
  username: string
  full_name: string
  department: string
  risk_score: number
  risk_factors: string[]
  last_anomaly: string
  risk_trend: 'up' | 'down' | 'stable'
  activity_baseline?: number[]  // 24 hourly avg
}

interface UserAction {
  action: string
  resource: string
  timestamp: string
  ip_address: string
  anomaly_score: number
}

interface UserBehavior {
  user: UEBAUser
  hourly_activity: number[][]  // 7 days x 24 hours
  recent_actions: UserAction[]
  risk_score: number
}

interface AlertStats {
  alerts_this_week: number
  after_hours_today: number
  privilege_escalations: number
  bulk_data_events: number
}

// ── Mock Data ─────────────────────────────────────────────────────────────────

const MOCK_STATS: AlertStats = {
  alerts_this_week: 23,
  after_hours_today: 7,
  privilege_escalations: 4,
  bulk_data_events: 12,
}

const MOCK_ALERTS: InsiderThreatAlert[] = [
  {
    id: 'it-001',
    threat_type: 'bulk_data',
    title: '大量データダウンロードを検知',
    description: '通常の100倍を超えるデータアクセスを検出。過去1時間で4.2GBのファイルをダウンロード。',
    user_id: 'u-001',
    username: 'tanaka.kenji',
    department: '営業部',
    timestamp: '2026-03-18T09:23:00Z',
    severity: 'critical',
    ip_address: '192.168.1.45',
    resource: '/shares/confidential/contracts/',
    details: { files_downloaded: 342, total_size_mb: 4302, duration_minutes: 18 },
  },
  {
    id: 'it-002',
    threat_type: 'privilege_escalation',
    title: '権限昇格の試みを検出',
    description: '通常業務では不要な管理者権限へのアクセスを試みた。4回の失敗後に成功。',
    user_id: 'u-002',
    username: 'suzuki.hiroshi',
    department: 'IT部',
    timestamp: '2026-03-18T08:45:00Z',
    severity: 'high',
    ip_address: '192.168.1.102',
    resource: 'Active Directory / Domain Admins',
    details: { failed_attempts: 4, escalated_to: 'Domain Admins', duration_seconds: 127 },
  },
  {
    id: 'it-003',
    threat_type: 'after_hours',
    title: '時間外アクセスを検知',
    description: '深夜02:30に機密サーバーへのログインを検出。該当ユーザーは夜間勤務の予定なし。',
    user_id: 'u-003',
    username: 'yamada.akiko',
    department: '財務部',
    timestamp: '2026-03-18T02:33:00Z',
    severity: 'high',
    ip_address: '203.0.113.78',
    resource: 'finance-server-01',
    details: { access_time: '02:33', external_ip: true, vpn_used: false },
  },
  {
    id: 'it-004',
    threat_type: 'failed_login',
    title: '連続ログイン失敗を検出',
    description: '15分以内に52回のログイン失敗。複数のアカウントに対するブルートフォース攻撃の可能性。',
    user_id: 'u-004',
    username: 'unknown',
    department: '不明',
    timestamp: '2026-03-18T07:12:00Z',
    severity: 'critical',
    ip_address: '45.33.32.156',
    resource: 'VPN Gateway / RDP',
    details: { failed_attempts: 52, target_accounts: 8, duration_minutes: 15 },
  },
  {
    id: 'it-005',
    threat_type: 'bulk_data',
    title: '機密文書への異常アクセス',
    description: 'M&A関連の機密文書フォルダに通常の20倍のアクセス。情報漏洩リスクあり。',
    user_id: 'u-005',
    username: 'nakamura.jun',
    department: '経営企画部',
    timestamp: '2026-03-17T16:55:00Z',
    severity: 'medium',
    ip_address: '192.168.2.33',
    resource: '/shares/MA-project/confidential/',
    details: { files_accessed: 89, unique_documents: 62, share_attempts: 3 },
  },
  {
    id: 'it-006',
    threat_type: 'after_hours',
    title: '休日の機密システムアクセス',
    description: '祝日に本社外IPから内部システムへ接続。正規業務目的の確認が必要。',
    user_id: 'u-001',
    username: 'tanaka.kenji',
    department: '営業部',
    timestamp: '2026-03-16T14:22:00Z',
    severity: 'low',
    ip_address: '126.253.102.45',
    resource: 'CRM System / Customer Data',
    details: { holiday: '春分の日', external_ip: true, accessed_records: 156 },
  },
]

const MOCK_RISK_USERS: UEBAUser[] = [
  {
    id: 'u-001',
    username: 'tanaka.kenji',
    full_name: '田中 健二',
    department: '営業部',
    risk_score: 78,
    risk_factors: ['大量データアクセス', '時間外アクセス', '異常なファイルコピー'],
    last_anomaly: '2026-03-18T09:23:00Z',
    risk_trend: 'up',
  },
  {
    id: 'u-002',
    username: 'suzuki.hiroshi',
    full_name: '鈴木 浩',
    department: 'IT部',
    risk_score: 65,
    risk_factors: ['権限昇格試行', '未承認ソフトウェアインストール'],
    last_anomaly: '2026-03-18T08:45:00Z',
    risk_trend: 'stable',
  },
  {
    id: 'u-003',
    username: 'yamada.akiko',
    full_name: '山田 明子',
    department: '財務部',
    risk_score: 52,
    risk_factors: ['時間外アクセス', '外部IPからのログイン'],
    last_anomaly: '2026-03-18T02:33:00Z',
    risk_trend: 'down',
  },
]

const MOCK_USERS_LIST = [
  { id: 'u-001', username: 'tanaka.kenji', full_name: '田中 健二', department: '営業部' },
  { id: 'u-002', username: 'suzuki.hiroshi', full_name: '鈴木 浩', department: 'IT部' },
  { id: 'u-003', username: 'yamada.akiko', full_name: '山田 明子', department: '財務部' },
  { id: 'u-004', username: 'nakamura.jun', full_name: '中村 潤', department: '経営企画部' },
  { id: 'u-005', username: 'kobayashi.yui', full_name: '小林 唯', department: '人事部' },
]

const MOCK_USER_BEHAVIOR: UserBehavior = {
  user: m(MOCK_RISK_USERS)[0],
  hourly_activity: Array.from({ length: 7 }, (_, day) =>
    Array.from({ length: 24 }, (_, hour) => {
      // Normal hours 9-18, spikes on day 4 (after hours)
      if (day === 4 && (hour === 2 || hour === 3)) return 8 + Math.floor(Math.random() * 6)
      if (hour >= 9 && hour <= 18) return Math.floor(Math.random() * 5)
      return Math.random() > 0.85 ? Math.floor(Math.random() * 3) : 0
    })
  ),
  recent_actions: [
    { action: 'FILE_DOWNLOAD', resource: '/shares/confidential/contracts/Q1-2026.xlsx', timestamp: '2026-03-18T09:23:00Z', ip_address: '192.168.1.45', anomaly_score: 0.94 },
    { action: 'FILE_DOWNLOAD', resource: '/shares/confidential/contracts/Q2-2026.xlsx', timestamp: '2026-03-18T09:21:00Z', ip_address: '192.168.1.45', anomaly_score: 0.91 },
    { action: 'DIR_LIST', resource: '/shares/confidential/M&A/', timestamp: '2026-03-18T09:18:00Z', ip_address: '192.168.1.45', anomaly_score: 0.72 },
    { action: 'FILE_READ', resource: '/shares/HR/salary-2026.csv', timestamp: '2026-03-18T08:55:00Z', ip_address: '192.168.1.45', anomaly_score: 0.65 },
    { action: 'LOGIN', resource: 'CRM System', timestamp: '2026-03-18T08:30:00Z', ip_address: '192.168.1.45', anomaly_score: 0.12 },
    { action: 'LOGIN', resource: 'VPN Gateway', timestamp: '2026-03-16T14:22:00Z', ip_address: '126.253.102.45', anomaly_score: 0.78 },
    { action: 'FILE_READ', resource: '/shares/customer/list-all.xlsx', timestamp: '2026-03-15T17:40:00Z', ip_address: '192.168.1.45', anomaly_score: 0.55 },
    { action: 'LOGOUT', resource: 'File Server', timestamp: '2026-03-15T18:02:00Z', ip_address: '192.168.1.45', anomaly_score: 0.04 },
  ],
  risk_score: 78,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const THREAT_TYPE_CONFIG: Record<ThreatType, { label: string; icon: React.ReactNode; color: string; bg: string }> = {
  after_hours: {
    label: '時間外アクセス',
    icon: <Clock className="w-5 h-5" />,
    color: 'text-amber-400',
    bg: 'bg-amber-500/10 border-amber-500/30',
  },
  privilege_escalation: {
    label: '権限昇格',
    icon: <TrendingUp className="w-5 h-5" />,
    color: 'text-orange-400',
    bg: 'bg-orange-500/10 border-orange-500/30',
  },
  bulk_data: {
    label: '大量データアクセス',
    icon: <Database className="w-5 h-5" />,
    color: 'text-blue-400',
    bg: 'bg-blue-500/10 border-blue-500/30',
  },
  failed_login: {
    label: 'ログイン失敗',
    icon: <Lock className="w-5 h-5" />,
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/30',
  },
}

const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; dot: string }> = {
  critical: { label: 'クリティカル', color: 'bg-red-500/20 text-red-300 border border-red-500/30', dot: 'bg-red-400' },
  high:     { label: '高',           color: 'bg-orange-500/20 text-orange-300 border border-orange-500/30', dot: 'bg-orange-400' },
  medium:   { label: '中',           color: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30', dot: 'bg-yellow-400' },
  low:      { label: '低',           color: 'bg-green-500/20 text-green-300 border border-green-500/30', dot: 'bg-green-400' },
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts)
    return d.toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  } catch { return ts }
}

function getRiskColor(score: number): string {
  if (score >= 75) return 'text-red-400'
  if (score >= 50) return 'text-orange-400'
  if (score >= 25) return 'text-yellow-400'
  return 'text-green-400'
}

function getRiskBgColor(score: number): string {
  if (score >= 75) return 'bg-red-500'
  if (score >= 50) return 'bg-orange-500'
  if (score >= 25) return 'bg-yellow-500'
  return 'bg-green-500'
}

// ── Activity Heatmap ──────────────────────────────────────────────────────────

function ActivityHeatmap({ data, baseline }: { data: number[][], baseline: number[] }) {
  const days = ['月', '火', '水', '木', '金', '土', '日']
  const maxVal = Math.max(...data.flat(), 1)

  const getCellColor = (dayIdx: number, hourIdx: number, value: number): string => {
    if (value === 0) return 'fill-[#1e2d42]'
    const baselineHour = baseline[hourIdx] ?? 0
    const isAnomaly = value > baselineHour * 2.5 && value >= 3
    if (isAnomaly) return 'fill-red-500'
    const intensity = Math.min(value / maxVal, 1)
    if (intensity > 0.7) return 'fill-blue-400'
    if (intensity > 0.4) return 'fill-blue-500/70'
    return 'fill-blue-600/40'
  }

  const cellW = 20
  const cellH = 20
  const gap = 2
  const labelW = 20
  const labelH = 20
  const svgW = labelW + 24 * (cellW + gap) + 10
  const svgH = labelH + 7 * (cellH + gap) + 10

  return (
    <div className="overflow-x-auto">
      <svg width={svgW} height={svgH} className="block">
        {/* Hour labels */}
        {[0, 3, 6, 9, 12, 15, 18, 21].map(h => (
          <text
            key={h}
            x={labelW + h * (cellW + gap) + cellW / 2}
            y={labelH - 4}
            textAnchor="middle"
            className="fill-[#7d92b0]"
            fontSize={9}
          >
            {h}
          </text>
        ))}
        {/* Day labels */}
        {days.map((day, di) => (
          <text
            key={day}
            x={labelW - 4}
            y={labelH + di * (cellH + gap) + cellH / 2 + 4}
            textAnchor="end"
            className="fill-[#7d92b0]"
            fontSize={9}
          >
            {day}
          </text>
        ))}
        {/* Cells */}
        {data.map((row, di) =>
          row.map((val, hi) => (
            <rect
              key={`${di}-${hi}`}
              x={labelW + hi * (cellW + gap)}
              y={labelH + di * (cellH + gap)}
              width={cellW}
              height={cellH}
              rx={3}
              className={getCellColor(di, hi, val)}
            />
          ))
        )}
      </svg>
      <div className="flex items-center gap-4 mt-2 text-xs text-[#7d92b0]">
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-blue-500/70 inline-block" /> 通常アクティビティ
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-red-500 inline-block" /> 異常検知
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-[#1e2d42] inline-block border border-[#1e2d42]" /> 非アクティブ
        </span>
      </div>
    </div>
  )
}

// ── Risk Gauge ────────────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const angle = (score / 100) * 180 - 90
  const rad = (angle * Math.PI) / 180
  const cx = 80, cy = 80, r = 60
  const needleX = cx + r * 0.7 * Math.cos(rad)
  const needleY = cy + r * 0.7 * Math.sin(rad)

  const arcPath = (startDeg: number, endDeg: number, color: string, innerR: number = 50, outerR: number = 65) => {
    const toRad = (d: number) => ((d - 90) * Math.PI) / 180
    const x1 = cx + outerR * Math.cos(toRad(startDeg))
    const y1 = cy + outerR * Math.sin(toRad(startDeg))
    const x2 = cx + outerR * Math.cos(toRad(endDeg))
    const y2 = cy + outerR * Math.sin(toRad(endDeg))
    const xi1 = cx + innerR * Math.cos(toRad(startDeg))
    const yi1 = cy + innerR * Math.sin(toRad(startDeg))
    const xi2 = cx + innerR * Math.cos(toRad(endDeg))
    const yi2 = cy + innerR * Math.sin(toRad(endDeg))
    const large = endDeg - startDeg > 180 ? 1 : 0
    return (
      <path
        key={`${startDeg}-${endDeg}`}
        d={`M ${x1} ${y1} A ${outerR} ${outerR} 0 ${large} 1 ${x2} ${y2} L ${xi2} ${yi2} A ${innerR} ${innerR} 0 ${large} 0 ${xi1} ${yi1} Z`}
        fill={color}
        opacity={0.7}
      />
    )
  }

  return (
    <div className="flex flex-col items-center">
      <svg width={160} height={100} viewBox="0 0 160 100">
        {arcPath(-90, -18, '#22c55e')}
        {arcPath(-18, 54, '#eab308')}
        {arcPath(54, 90, '#f97316')}
        {arcPath(54, 90, '#ef4444', 50, 65)}
        {/* Actually distribute evenly: 0-25 green, 25-50 yellow, 50-75 orange, 75-100 red */}
        {arcPath(-90, -45, '#22c55e')}
        {arcPath(-45, 0, '#eab308')}
        {arcPath(0, 45, '#f97316')}
        {arcPath(45, 90, '#ef4444')}
        <line
          x1={cx} y1={cy}
          x2={needleX} y2={needleY}
          stroke="white" strokeWidth={2.5} strokeLinecap="round"
        />
        <circle cx={cx} cy={cy} r={5} fill="white" />
        <text x={cx} y={cy + 20} textAnchor="middle" fill="white" fontSize={20} fontWeight="bold">
          {score}
        </text>
        <text x={cx} y={cy + 32} textAnchor="middle" fill="#7d92b0" fontSize={9}>
          リスクスコア
        </text>
      </svg>
      <p className={`text-sm font-semibold ${getRiskColor(score)}`}>
        {score >= 75 ? '高リスク' : score >= 50 ? '中リスク' : score >= 25 ? '低リスク' : '安全'}
      </p>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function InsiderThreatsPage() {
  const [activeTab, setActiveTab] = useState<'alerts' | 'behavior' | 'risk_users'>('alerts')
  const [threatTypeFilter, setThreatTypeFilter] = useState<string>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [dateRange, setDateRange] = useState<string>('7d')
  const [selectedUserId, setSelectedUserId] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState('')

  // Stats query
  const { data: statsData } = useQuery<AlertStats>({
    queryKey: ['insider-threat-stats'],
    queryFn: () => apiFetch('/api/v1/insider-threats/stats'),
    staleTime: 30_000,
    retry: false,
  })
  const stats = statsData ?? m(MOCK_STATS)

  // Alerts query
  const { data: alertsData } = useQuery<{ items: InsiderThreatAlert[] }>({
    queryKey: ['insider-threat-alerts', threatTypeFilter, severityFilter, dateRange],
    queryFn: () => apiFetch(`/api/v1/alerts?source=insider_threat_detector&threat_type=${threatTypeFilter}&severity=${severityFilter}&range=${dateRange}`),
    staleTime: 30_000,
    retry: false,
  })
  const alerts = alertsData?.items ?? m(MOCK_ALERTS)

  // UEBA users for dropdown
  const { data: usersData } = useQuery<{ items: typeof MOCK_USERS_LIST }>({
    queryKey: ['ueba-users-list'],
    queryFn: () => apiFetch('/api/v1/ueba/users'),
    staleTime: 60_000,
    retry: false,
  })
  const usersList = usersData?.items ?? m(MOCK_USERS_LIST)

  // Risk users
  const { data: riskUsersData } = useQuery<{ items: UEBAUser[] }>({
    queryKey: ['ueba-risk-users'],
    queryFn: () => apiFetch('/api/v1/ueba/users?sort=risk_score&limit=10'),
    staleTime: 30_000,
    retry: false,
  })
  const riskUsers = riskUsersData?.items ?? m(MOCK_RISK_USERS)

  // User behavior
  const { data: behaviorData } = useQuery<UserBehavior>({
    queryKey: ['ueba-user-behavior', selectedUserId],
    queryFn: () => apiFetch(`/api/v1/ueba/users/${selectedUserId}/behavior`),
    enabled: !!selectedUserId,
    staleTime: 30_000,
    retry: false,
  })
  const behavior = behaviorData ?? (selectedUserId ? MOCK_USER_BEHAVIOR : null)

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      if (threatTypeFilter !== 'all' && a.threat_type !== threatTypeFilter) return false
      if (severityFilter !== 'all' && a.severity !== severityFilter) return false
      if (searchQuery && !a.username.includes(searchQuery) && !a.title.includes(searchQuery)) return false
      return true
    })
  }, [alerts, threatTypeFilter, severityFilter, searchQuery])

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">内部脅威検知</h1>
        <p className="text-[#7d92b0] mt-1 text-sm">
          異常な権限昇格・時間外アクセス・大量データアクセスの検知
        </p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '今週のアラート', value: stats.alerts_this_week, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-400', bg: 'bg-red-500/10' },
          { label: '今日の時間外イベント', value: stats.after_hours_today, icon: <Clock className="w-5 h-5" />, color: 'text-amber-400', bg: 'bg-amber-500/10' },
          { label: '権限昇格', value: stats.privilege_escalations, icon: <TrendingUp className="w-5 h-5" />, color: 'text-orange-400', bg: 'bg-orange-500/10' },
          { label: '大量アクセスイベント', value: stats.bulk_data_events, icon: <Database className="w-5 h-5" />, color: 'text-blue-400', bg: 'bg-blue-500/10' },
        ].map(({ label, value, icon, color, bg }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${bg} ${color}`}>{icon}</div>
              <div>
                <p className="text-[#7d92b0] text-xs">{label}</p>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {[
          { id: 'alerts', label: 'アラート' },
          { id: 'behavior', label: 'ユーザー行動分析' },
          { id: 'risk_users', label: 'リスクユーザー' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-[#1d2f4a] text-white'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Alerts Tab ── */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2 text-[#7d92b0] text-sm">
              <Filter className="w-4 h-4" />
              <span>フィルター:</span>
            </div>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0]" />
              <input
                type="text"
                placeholder="ユーザー名・タイトル検索..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white placeholder-[#7d92b0] focus:outline-none focus:border-[#7d92b0]/50 w-48"
              />
            </div>
            <select
              value={threatTypeFilter}
              onChange={e => setThreatTypeFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50"
            >
              <option value="all">脅威タイプ: すべて</option>
              <option value="after_hours">時間外アクセス</option>
              <option value="privilege_escalation">権限昇格</option>
              <option value="bulk_data">大量データアクセス</option>
              <option value="failed_login">ログイン失敗</option>
            </select>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50"
            >
              <option value="all">重要度: すべて</option>
              <option value="critical">クリティカル</option>
              <option value="high">高</option>
              <option value="medium">中</option>
              <option value="low">低</option>
            </select>
            <select
              value={dateRange}
              onChange={e => setDateRange(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50"
            >
              <option value="1d">過去24時間</option>
              <option value="7d">過去7日間</option>
              <option value="30d">過去30日間</option>
            </select>
            {(threatTypeFilter !== 'all' || severityFilter !== 'all' || searchQuery) && (
              <button
                onClick={() => { setThreatTypeFilter('all'); setSeverityFilter('all'); setSearchQuery('') }}
                className="flex items-center gap-1 px-2 py-1.5 text-xs text-[#7d92b0] hover:text-white"
              >
                <X className="w-3.5 h-3.5" /> クリア
              </button>
            )}
            <span className="text-[#7d92b0] text-sm ml-auto">{filteredAlerts.length} 件</span>
          </div>

          {/* Alert Cards */}
          {filteredAlerts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-[#7d92b0]">
              <Shield className="w-12 h-12 mb-4 opacity-30" />
              <p className="text-lg font-medium">現在検知された内部脅威はありません</p>
              <p className="text-sm mt-1 opacity-70">フィルターを変更するか、後で再確認してください</p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredAlerts.map(alert => {
                const typeConf = THREAT_TYPE_CONFIG[alert.threat_type]
                const sevConf = SEVERITY_CONFIG[alert.severity]
                return (
                  <div
                    key={alert.id}
                    className={`bg-[#0d1220] border rounded-lg overflow-hidden flex ${typeConf.bg}`}
                  >
                    {/* Color strip */}
                    <div className={`w-1 flex-shrink-0 ${
                      alert.severity === 'critical' ? 'bg-red-500' :
                      alert.severity === 'high' ? 'bg-orange-500' :
                      alert.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                    }`} />
                    <div className="flex-1 p-4">
                      <div className="flex items-start gap-4">
                        {/* Icon */}
                        <div className={`p-2 rounded-lg flex-shrink-0 mt-0.5 ${typeConf.color} bg-[#070d19]`}>
                          {typeConf.icon}
                        </div>
                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-4">
                            <div>
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${typeConf.color} bg-[#070d19]`}>
                                  {typeConf.label}
                                </span>
                                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sevConf.color}`}>
                                  <span className={`inline-block w-1.5 h-1.5 rounded-full ${sevConf.dot} mr-1`} />
                                  {sevConf.label}
                                </span>
                              </div>
                              <h3 className="text-white font-semibold">{alert.title}</h3>
                              <p className="text-[#7d92b0] text-sm mt-1">{alert.description}</p>
                            </div>
                            <div className="flex flex-col items-end gap-2 flex-shrink-0">
                              <span className="text-[#7d92b0] text-xs whitespace-nowrap">
                                {formatTimestamp(alert.timestamp)}
                              </span>
                              <Link
                                href={`/timeline?user=${alert.user_id}`}
                                className="flex items-center gap-1 px-3 py-1.5 bg-[#1d2f4a] hover:bg-[#243a5e] text-white text-xs rounded transition-colors"
                              >
                                <Eye className="w-3.5 h-3.5" />
                                調査
                              </Link>
                            </div>
                          </div>
                          <div className="flex items-center gap-4 mt-2 text-xs text-[#7d92b0]">
                            <span className="flex items-center gap-1">
                              <User className="w-3.5 h-3.5" />
                              {alert.username}
                              {alert.department && <span className="text-[#3d5068]">({alert.department})</span>}
                            </span>
                            <span className="font-mono">{alert.ip_address}</span>
                            <span className="truncate max-w-[200px] font-mono text-[#3d5068]">{alert.resource}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Behavior Analysis Tab ── */}
      {activeTab === 'behavior' && (
        <div className="space-y-6">
          {/* User Selector */}
          <div className="flex items-center gap-3">
            <label className="text-[#7d92b0] text-sm font-medium">分析対象ユーザー:</label>
            <select
              value={selectedUserId}
              onChange={e => setSelectedUserId(e.target.value)}
              className="px-3 py-2 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50 w-72"
            >
              <option value="">ユーザーを選択してください...</option>
              {usersList.map(u => (
                <option key={u.id} value={u.id}>
                  {u.full_name} ({u.username}) - {u.department}
                </option>
              ))}
            </select>
          </div>

          {!selectedUserId ? (
            <div className="flex flex-col items-center justify-center py-20 text-[#7d92b0]">
              <Activity className="w-12 h-12 mb-4 opacity-30" />
              <p className="text-lg font-medium">ユーザーを選択してください</p>
              <p className="text-sm mt-1 opacity-70">上のドロップダウンから分析するユーザーを選択します</p>
            </div>
          ) : behavior ? (
            <div className="grid grid-cols-3 gap-6">
              {/* Left: Heatmap + Timeline */}
              <div className="col-span-2 space-y-6">
                {/* Heatmap */}
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                  <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-blue-400" />
                    アクティビティヒートマップ（過去7日間）
                  </h3>
                  <ActivityHeatmap
                    data={behavior.hourly_activity}
                    baseline={Array(24).fill(2)}
                  />
                </div>

                {/* Recent Actions Table */}
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                  <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                    <Clock className="w-4 h-4 text-amber-400" />
                    最近の操作ログ
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42]">
                          <th className="text-left pb-2 pr-4">操作</th>
                          <th className="text-left pb-2 pr-4">リソース</th>
                          <th className="text-left pb-2 pr-4">日時</th>
                          <th className="text-left pb-2 pr-4">IPアドレス</th>
                          <th className="text-left pb-2">異常スコア</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1e2d42]">
                        {behavior.recent_actions.map((action, i) => (
                          <tr key={i} className={`${action.anomaly_score > 0.7 ? 'bg-red-500/5' : ''}`}>
                            <td className="py-2 pr-4">
                              <span className="font-mono text-xs bg-[#070d19] px-2 py-0.5 rounded text-blue-300">
                                {action.action}
                              </span>
                            </td>
                            <td className="py-2 pr-4 font-mono text-xs text-[#7d92b0] max-w-[200px] truncate">
                              {action.resource}
                            </td>
                            <td className="py-2 pr-4 text-[#7d92b0] text-xs whitespace-nowrap">
                              {formatTimestamp(action.timestamp)}
                            </td>
                            <td className="py-2 pr-4 font-mono text-xs text-[#7d92b0]">
                              {action.ip_address}
                            </td>
                            <td className="py-2">
                              <div className="flex items-center gap-2">
                                <div className="w-20 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${
                                      action.anomaly_score > 0.7 ? 'bg-red-500' :
                                      action.anomaly_score > 0.4 ? 'bg-orange-500' : 'bg-green-500'
                                    }`}
                                    style={{ width: `${action.anomaly_score * 100}%` }}
                                  />
                                </div>
                                <span className={`text-xs font-mono ${
                                  action.anomaly_score > 0.7 ? 'text-red-400' :
                                  action.anomaly_score > 0.4 ? 'text-orange-400' : 'text-green-400'
                                }`}>
                                  {(action.anomaly_score * 100).toFixed(0)}%
                                </span>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Right: Risk Gauge + User Info */}
              <div className="space-y-4">
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                  <h3 className="text-white font-semibold mb-4 text-center">リスクスコアゲージ</h3>
                  <RiskGauge score={behavior.risk_score} />
                </div>
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                  <h3 className="text-white font-semibold mb-3">ユーザー情報</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-[#7d92b0]">ユーザー名</span>
                      <span className="text-white font-mono">{behavior.user.username}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#7d92b0]">氏名</span>
                      <span className="text-white">{behavior.user.full_name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#7d92b0]">部署</span>
                      <span className="text-white">{behavior.user.department}</span>
                    </div>
                    <div className="pt-2 border-t border-[#1e2d42]">
                      <p className="text-[#7d92b0] text-xs mb-2">リスク要因</p>
                      <div className="flex flex-wrap gap-1">
                        {behavior.user.risk_factors.map((f, i) => (
                          <span key={i} className="text-xs bg-red-500/10 text-red-300 border border-red-500/20 px-2 py-0.5 rounded-full">
                            {f}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* ── Risk Users Tab ── */}
      {activeTab === 'risk_users' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2d42]">
            <h3 className="text-white font-semibold">リスクユーザーランキング</h3>
            <p className="text-[#7d92b0] text-xs mt-0.5">スコアが高いユーザーを優先的に調査してください</p>
          </div>
          <div className="divide-y divide-[#1e2d42]">
            {riskUsers.map((user, index) => (
              <div key={user.id} className="px-5 py-4 flex items-center gap-5 hover:bg-[#0d1830]/40 transition-colors">
                {/* Rank */}
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${
                  index === 0 ? 'bg-red-500/20 text-red-400' :
                  index === 1 ? 'bg-orange-500/20 text-orange-400' :
                  index === 2 ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-[#1e2d42] text-[#7d92b0]'
                }`}>
                  {index + 1}
                </div>

                {/* Avatar + Name */}
                <div className="flex items-center gap-3 w-48 flex-shrink-0">
                  <div className="w-9 h-9 rounded-full bg-gradient-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                    {user.full_name[0]}
                  </div>
                  <div className="min-w-0">
                    <p className="text-white text-sm font-medium truncate">{user.full_name}</p>
                    <p className="text-[#7d92b0] text-xs truncate">{user.department}</p>
                  </div>
                </div>

                {/* Risk Score */}
                <div className="flex-shrink-0 w-16 text-center">
                  <p className={`text-3xl font-bold tabular-nums ${getRiskColor(user.risk_score)}`}>
                    {user.risk_score}
                  </p>
                  <div className="w-full h-1 bg-[#1e2d42] rounded-full mt-1 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${getRiskBgColor(user.risk_score)}`}
                      style={{ width: `${user.risk_score}%` }}
                    />
                  </div>
                </div>

                {/* Risk Factors */}
                <div className="flex-1 flex flex-wrap gap-1">
                  {user.risk_factors.map((f, i) => (
                    <span key={i} className="text-xs bg-[#1e2d42] text-[#7d92b0] px-2 py-0.5 rounded-full">
                      {f}
                    </span>
                  ))}
                </div>

                {/* Last Anomaly */}
                <div className="text-xs text-[#7d92b0] w-28 flex-shrink-0 text-right">
                  <p>最終異常:</p>
                  <p className="text-white">{formatTimestamp(user.last_anomaly)}</p>
                </div>

                {/* Trend */}
                <div className="flex-shrink-0 w-8 flex justify-center">
                  {user.risk_trend === 'up'     && <ArrowUp   className="w-5 h-5 text-red-400" />}
                  {user.risk_trend === 'down'   && <ArrowDown className="w-5 h-5 text-green-400" />}
                  {user.risk_trend === 'stable' && <Minus     className="w-5 h-5 text-[#7d92b0]" />}
                </div>

                {/* Action */}
                <button
                  onClick={() => { setSelectedUserId(user.id); setActiveTab('behavior') }}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1d2f4a] hover:bg-[#243a5e] text-white text-xs rounded transition-colors flex-shrink-0"
                >
                  <Search className="w-3.5 h-3.5" />
                  調査開始
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
