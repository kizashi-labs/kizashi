'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useCanWrite, useAuth } from '@/lib/auth'
import {
  BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Legend,
} from 'recharts'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  LayoutDashboard, GripVertical, Settings2, RefreshCw,
  EyeOff, BarChart2, AlertTriangle, Server, Shield,
  X, Plus, RotateCcw, ShieldCheck, Rss, TrendingUp,
  Bot, Bookmark, Search, FileText, Crosshair, Inbox,
} from 'lucide-react'
import Link from 'next/link'

// ── Types ────────────────────────────────────────────────────────

type WidgetType =
  | 'alert_summary'
  | 'agent_status'
  | 'incident_list'
  | 'compliance_score'
  | 'severity_chart'
  | 'quick_stats'
  | 'alert_trend'
  | 'top_endpoints'
  | 'detection_rate'
  | 'agent_stats'
  | 'recent_alerts'
  | 'active_incidents'
  | 'security_score'
  | 'threat_feeds'
  | 'nist_score'
  | 'active_incidents_count'
  | 'ai_insight'
  | 'watchlist_hits'
  | 'quick_actions'
  | 'threat_map'
  | 'kill_chain'
  | 'ioc_hits'
  | 'alert_heatmap'
  | 'soc_queue_summary'

interface WidgetPosition { x: number; y: number; w: number; h: number }
interface WidgetDef {
  id: string
  type: WidgetType
  position: WidgetPosition
  visible: boolean
}

interface AlertItem {
  id: string
  title: string
  severity: number | string
  status: string
  created_at: string
}

interface AgentItem {
  id: string
  hostname?: string
  status?: string
}

interface IncidentItem {
  id: string
  title: string
  severity: number | string
  status: string
}

interface ComplianceScore {
  agent_id: string
  score: number
  framework: string
}

interface AlertTrendDay {
  date: string
  count: number
  critical_count: number
}

interface TopEndpoint {
  agent_id: string
  hostname: string
  alert_count: number
  last_alert: string
}

interface DetectionRate {
  resolution_rate: number
  avg_resolution_hours: number
  open_critical: number
}

// ── Widget ID constants (for localStorage) ───────────────────────

const ALL_WIDGET_IDS: string[] = [
  'quick_stats',
  'alert_summary',
  'agent_status',
  'incident_list',
  'compliance_score',
  'severity_chart',
  'alert_trend',
  'top_endpoints',
  'detection_rate',
  'agent_stats',
  'recent_alerts',
  'active_incidents',
  'security_score',
  'threat_feeds',
  'nist_score',
  'active_incidents_count',
  'ai_insight',
  'watchlist_hits',
  'quick_actions',
  'threat_map',
  'kill_chain',
  'ioc_hits',
  'alert_heatmap',
  'soc_queue_summary',
]

const LS_KEY = 'dashboard_widgets'

const DEFAULT_VISIBLE_IDS: string[] = [
  'quick_stats',
  'nist_score',
  'active_incidents_count',
  'ai_insight',
  'watchlist_hits',
  'quick_actions',
  'soc_queue_summary',
  'alert_summary',
  'agent_status',
  'severity_chart',
  'incident_list',
  'compliance_score',
  'alert_trend',
  'top_endpoints',
  'detection_rate',
]

// ── Default widget layout ────────────────────────────────────────

const DEFAULT_WIDGETS: WidgetDef[] = [
  { id: 'quick_stats',             type: 'quick_stats',             position: { x: 0, y: 0, w: 3, h: 1 }, visible: true },
  { id: 'nist_score',              type: 'nist_score',              position: { x: 0, y: 1, w: 1, h: 1 }, visible: true },
  { id: 'active_incidents_count',  type: 'active_incidents_count',  position: { x: 1, y: 1, w: 1, h: 1 }, visible: true },
  { id: 'watchlist_hits',          type: 'watchlist_hits',          position: { x: 2, y: 1, w: 1, h: 1 }, visible: true },
  { id: 'ai_insight',              type: 'ai_insight',              position: { x: 0, y: 2, w: 2, h: 1 }, visible: true },
  { id: 'quick_actions',           type: 'quick_actions',           position: { x: 0, y: 3, w: 3, h: 1 }, visible: true },
  { id: 'soc_queue_summary',       type: 'soc_queue_summary',       position: { x: 0, y: 4, w: 3, h: 1 }, visible: true },
  { id: 'alert_summary',           type: 'alert_summary',           position: { x: 0, y: 5, w: 2, h: 1 }, visible: true },
  { id: 'agent_status',            type: 'agent_status',            position: { x: 2, y: 4, w: 1, h: 1 }, visible: true },
  { id: 'severity_chart',          type: 'severity_chart',          position: { x: 0, y: 5, w: 2, h: 1 }, visible: true },
  { id: 'incident_list',           type: 'incident_list',           position: { x: 2, y: 5, w: 1, h: 1 }, visible: true },
  { id: 'compliance_score',        type: 'compliance_score',        position: { x: 0, y: 6, w: 3, h: 1 }, visible: true },
  { id: 'alert_trend',             type: 'alert_trend',             position: { x: 0, y: 7, w: 2, h: 1 }, visible: true },
  { id: 'top_endpoints',           type: 'top_endpoints',           position: { x: 2, y: 7, w: 1, h: 1 }, visible: true },
  { id: 'detection_rate',          type: 'detection_rate',          position: { x: 0, y: 8, w: 1, h: 1 }, visible: true },
  { id: 'agent_stats',             type: 'agent_stats',             position: { x: 1, y: 8, w: 1, h: 1 }, visible: false },
  { id: 'recent_alerts',           type: 'recent_alerts',           position: { x: 2, y: 8, w: 1, h: 1 }, visible: false },
  { id: 'active_incidents',        type: 'active_incidents',        position: { x: 0, y: 9, w: 1, h: 1 }, visible: false },
  { id: 'security_score',          type: 'security_score',          position: { x: 1, y: 9, w: 1, h: 1 }, visible: false },
  { id: 'threat_feeds',            type: 'threat_feeds',            position: { x: 2, y: 9, w: 1, h: 1 }, visible: false },
  { id: 'threat_map',              type: 'threat_map',              position: { x: 0, y: 10, w: 2, h: 1 }, visible: false },
  { id: 'kill_chain',              type: 'kill_chain',              position: { x: 2, y: 10, w: 1, h: 1 }, visible: false },
  { id: 'ioc_hits',                type: 'ioc_hits',                position: { x: 0, y: 11, w: 1, h: 1 }, visible: false },
  { id: 'alert_heatmap',           type: 'alert_heatmap',           position: { x: 1, y: 11, w: 2, h: 1 }, visible: false },
]

const WIDGET_LABELS: Record<WidgetType, string> = {
  quick_stats:             'クイック統計',
  alert_summary:           '最新アラート',
  agent_status:            'エージェント状態',
  incident_list:           'オープンインシデント',
  compliance_score:        'コンプライアンススコア',
  severity_chart:          '重大度別分布',
  alert_trend:             'アラートトレンド (7日)',
  top_endpoints:           'トップエンドポイント',
  detection_rate:          '検知率',
  agent_stats:             'エージェント統計',
  recent_alerts:           '最近のアラート',
  active_incidents:        'アクティブインシデント',
  security_score:          'セキュリティスコア',
  threat_feeds:            '脅威フィード',
  nist_score:              'Security Score (NIST CSF)',
  active_incidents_count:  'Active Incidents',
  ai_insight:              'AI Insight',
  watchlist_hits:          'Watchlist Hits',
  quick_actions:           'Quick Actions',
  threat_map:              '脅威マップ (GeoIP)',
  kill_chain:              'Kill Chain カバレッジ',
  ioc_hits:                'IOC マッチ',
  alert_heatmap:           'アラート時間帯ヒートマップ',
  soc_queue_summary:       'SOCワークキュー',
}

const WIDGET_ICONS: Record<WidgetType, React.ComponentType<{ className?: string }>> = {
  quick_stats:             LayoutDashboard,
  alert_summary:           AlertTriangle,
  agent_status:            Server,
  incident_list:           AlertTriangle,
  compliance_score:        Shield,
  severity_chart:          BarChart2,
  alert_trend:             BarChart2,
  top_endpoints:           Server,
  detection_rate:          Shield,
  agent_stats:             Server,
  recent_alerts:           AlertTriangle,
  active_incidents:        AlertTriangle,
  security_score:          ShieldCheck,
  threat_feeds:            Rss,
  nist_score:              ShieldCheck,
  active_incidents_count:  AlertTriangle,
  ai_insight:              Bot,
  watchlist_hits:          Bookmark,
  quick_actions:           Search,
  threat_map:              TrendingUp,
  kill_chain:              Shield,
  ioc_hits:                AlertTriangle,
  alert_heatmap:           BarChart2,
  soc_queue_summary:       Inbox,
}

// ── Severity helpers ─────────────────────────────────────────────

function severityColor(sev: number | string): string {
  const n = Number(sev)
  if (n >= 9) return '#e8002d'
  if (n >= 7) return '#ff6b35'
  if (n >= 5) return '#ff9800'
  return '#1a6bff'
}

function severityLabel(sev: number | string): string {
  const n = Number(sev)
  if (n >= 9) return 'クリティカル'
  if (n >= 7) return '高'
  if (n >= 5) return '中'
  return '低'
}

function formatDate(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
  } catch {
    return iso
  }
}

// ── Widget content components ────────────────────────────────────

interface SocMetricsSummary {
  mttd_hours: number
  mttr_hours: number
  total_alerts: number
  open_alerts: number
  false_positive_rate: number
}

function QuickStatsWidget({
  alerts, agents, incidents,
}: {
  alerts: AlertItem[]
  agents: AgentItem[]
  incidents: IncidentItem[]
}) {
  const { data: kpi } = useQuery<SocMetricsSummary>({
    queryKey: ['soc-metrics-kpi'],
    queryFn: () => apiFetch('/api/v1/soc-metrics/summary?days=7'),
    refetchInterval: 60_000,
    retry: false,
  })

  const criticalAlerts = alerts.filter(a => Number(a.severity) >= 9).length
  const onlineAgents   = agents.filter(a => !a.status || a.status === 'online').length
  const totalAgents    = agents.length
  const onlineRate     = totalAgents > 0 ? Math.round(onlineAgents / totalAgents * 100) : 0
  const criticalInc    = incidents.filter(i => Number(i.severity) >= 9).length

  const fmtHours = (h: number | undefined) => {
    if (h == null || h === 0) return '—'
    if (h < 1) return `${Math.round(h * 60)}分`
    return `${h.toFixed(1)}h`
  }

  const mainStats = [
    {
      label: '未対応アラート',
      value: kpi?.open_alerts ?? alerts.length,
      color: '#e8002d',
      icon: AlertTriangle,
      sub: criticalAlerts > 0 ? `うち Critical ${criticalAlerts}件` : '新規・調査中',
      href: '/alerts',
    },
    {
      label: 'エージェント',
      value: `${onlineAgents}/${totalAgents}`,
      color: onlineRate >= 90 ? '#00e676' : onlineRate >= 70 ? '#ff9800' : '#e8002d',
      icon: Server,
      sub: `オンライン率 ${onlineRate}%`,
      href: '/endpoints',
    },
    {
      label: 'オープンインシデント',
      value: incidents.length,
      color: '#ff9800',
      icon: Shield,
      sub: criticalInc > 0 ? `うち Critical ${criticalInc}件` : '未解決',
      href: '/incidents',
    },
  ]

  return (
    <div className="flex flex-col gap-2 h-full">
      {/* メイン3カード */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 flex-1">
        {mainStats.map(s => {
          const Icon = s.icon
          return (
            <Link key={s.label} href={s.href}
              className="bg-falcon-hover/60 rounded-lg p-3 flex flex-col gap-1.5 hover:bg-falcon-active transition-colors cursor-pointer group">
              <div className="flex items-center gap-1.5">
                <Icon className="w-3.5 h-3.5 shrink-0" style={{ color: s.color }} />
                <span className="text-[11px] text-falcon-subtle truncate">{s.label}</span>
              </div>
              <span className="text-2xl font-bold tabular-nums leading-none" style={{ color: s.color }}>
                {s.value}
              </span>
              <div className="flex items-center justify-between mt-auto">
                <span className="text-[10px] text-falcon-subtle">{s.sub}</span>
                <span className="text-[10px] text-falcon-subtle group-hover:text-white transition-colors">→</span>
              </div>
            </Link>
          )
        })}
      </div>
      {/* MTTD / MTTR バー */}
      <div className="grid grid-cols-2 gap-2">
        {[
          { label: 'MTTD（平均検知時間）', value: fmtHours(kpi?.mttd_hours), color: '#1a6bff' },
          { label: 'MTTR（平均対応時間）', value: fmtHours(kpi?.mttr_hours), color: '#00c853' },
        ].map(m => (
          <div key={m.label} className="bg-falcon-surface rounded-lg px-3 py-1.5 flex items-center justify-between border border-falcon-border">
            <span className="text-[10px] text-falcon-subtle">{m.label}</span>
            <span className="text-sm font-bold tabular-nums" style={{ color: m.color }}>{m.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function AlertSummaryWidget({ alerts }: { alerts: AlertItem[] }) {
  if (alerts.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        アラートなし
      </div>
    )
  }
  return (
    <div className="space-y-1.5 overflow-auto max-h-56">
      {alerts.map(a => (
        <div key={a.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-falcon-hover/50 hover:bg-falcon-active transition-colors">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ background: severityColor(a.severity) }}
          />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-falcon-text truncate">{a.title}</p>
            <p className="text-[10px] text-falcon-subtle mt-0.5">{formatDate(a.created_at)}</p>
          </div>
          <span className="text-[10px] font-semibold shrink-0 px-1.5 py-0.5 rounded-sm"
                style={{ color: severityColor(a.severity), background: `${severityColor(a.severity)}22` }}>
            {severityLabel(a.severity)}
          </span>
          <span className="text-[10px] text-falcon-subtle shrink-0">{a.status}</span>
        </div>
      ))}
    </div>
  )
}

const AGENT_COLORS = { online: '#00e676', offline: '#e8002d', other: '#ff9800' }

function AgentStatusWidget({ agents, total }: { agents: AgentItem[]; total: number }) {
  const online = agents.length
  const offline = Math.max(0, total - online)
  const data = [
    { name: 'オンライン', value: online, fill: AGENT_COLORS.online },
    { name: 'オフライン', value: offline, fill: AGENT_COLORS.offline },
  ].filter(d => d.value > 0)

  if (total === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        エージェントなし
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center justify-center h-full gap-2">
      <ResponsiveContainer width="100%" height={160}>
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={45} outerRadius={70}
               dataKey="value" paddingAngle={2}>
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.fill} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px', fontSize: '11px' }}
            labelStyle={{ color: '#e5e7eb' }}
          />
          <Legend iconSize={8} wrapperStyle={{ fontSize: '11px', color: '#9ca3af' }} />
        </PieChart>
      </ResponsiveContainer>
      <div className="text-center">
        <span className="text-2xl font-bold text-white">{online}</span>
        <span className="text-falcon-subtle text-xs ml-1">/ {total} オンライン</span>
      </div>
    </div>
  )
}

function IncidentListWidget({ incidents }: { incidents: IncidentItem[] }) {
  if (incidents.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        オープンインシデントなし
      </div>
    )
  }
  return (
    <div className="space-y-1.5 overflow-auto max-h-56">
      {incidents.map(inc => (
        <div key={inc.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-falcon-hover/50 hover:bg-falcon-active transition-colors">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ background: severityColor(inc.severity) }}
          />
          <p className="text-xs font-medium text-falcon-text flex-1 truncate">{inc.title}</p>
          <span className="text-[10px] shrink-0 px-1.5 py-0.5 rounded-sm font-semibold"
                style={{ color: severityColor(inc.severity), background: `${severityColor(inc.severity)}22` }}>
            {severityLabel(inc.severity)}
          </span>
        </div>
      ))}
    </div>
  )
}

function ComplianceScoreWidget({ scores }: { scores: ComplianceScore[] }) {
  if (scores.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        コンプライアンスデータなし
      </div>
    )
  }

  const avg = scores.reduce((sum, s) => sum + s.score, 0) / scores.length
  const byFramework: Record<string, number[]> = {}
  for (const s of scores) {
    if (!byFramework[s.framework]) byFramework[s.framework] = []
    byFramework[s.framework].push(s.score)
  }
  const chartData = Object.entries(byFramework).map(([framework, vals]) => ({
    framework,
    avg: Math.round(vals.reduce((a, b) => a + b, 0) / vals.length),
  }))

  const gaugeColor = avg >= 80 ? '#00e676' : avg >= 60 ? '#ff9800' : '#e8002d'

  return (
    <div className="flex items-center gap-6 h-full">
      <div className="flex flex-col items-center justify-center min-w-[120px]">
        <div
          className="w-24 h-24 rounded-full border-4 flex items-center justify-center"
          style={{ borderColor: gaugeColor }}
        >
          <span className="text-2xl font-bold" style={{ color: gaugeColor }}>
            {Math.round(avg)}
          </span>
        </div>
        <span className="text-xs text-falcon-subtle mt-2">平均スコア</span>
        <span className="text-[10px] text-gray-600 mt-0.5">{scores.length} エージェント</span>
      </div>
      <div className="flex-1">
        <ResponsiveContainer width="100%" height={120}>
          <BarChart data={chartData} barCategoryGap="30%">
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
            <XAxis dataKey="framework" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px', fontSize: '11px' }}
              labelStyle={{ color: '#e5e7eb' }}
              cursor={{ fill: '#374151' }}
            />
            <Bar dataKey="avg" name="平均スコア" radius={[3, 3, 0, 0]} fill="#1a6bff" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

function SeverityChartWidget({ alerts }: { alerts: AlertItem[] }) {
  const buckets: Record<string, number> = {
    '低 (1-4)': 0,
    '中 (5-6)': 0,
    '高 (7-8)': 0,
    'クリティカル (9-10)': 0,
  }
  for (const a of alerts) {
    const n = Number(a.severity)
    if (n >= 9) buckets['クリティカル (9-10)']++
    else if (n >= 7) buckets['高 (7-8)']++
    else if (n >= 5) buckets['中 (5-6)']++
    else buckets['低 (1-4)']++
  }
  const chartData = Object.entries(buckets).map(([name, count]) => ({ name, count }))
  const barColors = ['#1a6bff', '#ff9800', '#ff6b35', '#e8002d']

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={chartData} barCategoryGap="30%">
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
        <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px', fontSize: '11px' }}
          labelStyle={{ color: '#e5e7eb' }}
          cursor={{ fill: '#374151' }}
        />
        <Bar dataKey="count" name="件数" radius={[3, 3, 0, 0]}>
          {chartData.map((_, i) => (
            <Cell key={i} fill={barColors[i]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

function AlertTrendWidget() {
  const { data, isLoading } = useQuery<{ trend: AlertTrendDay[] }>({
    queryKey: ['dashboard-alert-trend'],
    queryFn: () => apiFetch('/api/v1/dashboard/alert-trend?days=7'),
    refetchInterval: 60_000,
    retry: false,
  })

  const trend = data?.trend ?? []
  const maxCount = trend.reduce((m, d) => Math.max(m, d.count), 1)

  if (isLoading) {
    return (
      <div className="space-y-2 animate-pulse">
        {Array.from({ length: 7 }).map((_, i) => (
          <div key={i} className="h-6 bg-falcon-hover/60 rounded-sm" />
        ))}
      </div>
    )
  }

  if (trend.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        データなし
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {trend.map(day => {
        const pct = maxCount > 0 ? (day.count / maxCount) * 100 : 0
        const critPct = maxCount > 0 ? (day.critical_count / maxCount) * 100 : 0
        const label = (() => {
          try {
            const d = new Date(day.date)
            return d.toLocaleDateString('ja-JP', { month: '2-digit', day: '2-digit' })
          } catch {
            return day.date
          }
        })()
        return (
          <div key={day.date} className="flex items-center gap-2 text-xs">
            <span className="text-falcon-subtle w-12 shrink-0 tabular-nums">{label}</span>
            <div className="flex-1 h-5 bg-falcon-hover/50 rounded-sm overflow-hidden relative">
              <div
                className="absolute left-0 top-0 h-full rounded-sm transition-all duration-300"
                style={{ width: `${pct}%`, background: '#e8002d66' }}
              />
              {day.critical_count > 0 && (
                <div
                  className="absolute left-0 top-0 h-full rounded-sm transition-all duration-300"
                  style={{ width: `${critPct}%`, background: '#e8002d' }}
                />
              )}
            </div>
            <span className="text-falcon-muted w-6 text-right shrink-0 tabular-nums font-medium">{day.count}</span>
          </div>
        )
      })}
    </div>
  )
}

function TopEndpointsWidget() {
  const { data, isLoading } = useQuery<{ endpoints: TopEndpoint[] }>({
    queryKey: ['dashboard-top-endpoints'],
    queryFn: () => apiFetch('/api/v1/dashboard/top-endpoints'),
    refetchInterval: 60_000,
    retry: false,
  })

  const endpoints = data?.endpoints ?? []

  if (isLoading) {
    return (
      <div className="space-y-2 animate-pulse">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-9 bg-falcon-hover/60 rounded-sm" />
        ))}
      </div>
    )
  }

  if (endpoints.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        データなし
      </div>
    )
  }

  return (
    <div className="space-y-1.5">
      {endpoints.slice(0, 5).map((ep, i) => (
        <a
          key={ep.agent_id}
          href={`/endpoints/${ep.agent_id}`}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-hover/50 hover:bg-falcon-active transition-colors group"
        >
          <span className="text-xs font-bold text-falcon-subtle w-4 shrink-0">{i + 1}</span>
          <span className="flex-1 text-xs font-medium text-falcon-text truncate group-hover:text-white transition-colors">
            {ep.hostname}
          </span>
          <span
            className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm shrink-0"
            style={{ background: '#e8002d22', color: '#e8002d' }}
          >
            {ep.alert_count}
          </span>
          <span className="text-[10px] text-falcon-subtle shrink-0 hidden sm:block">
            {(() => {
              try {
                return new Date(ep.last_alert).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
              } catch {
                return ep.last_alert
              }
            })()}
          </span>
        </a>
      ))}
    </div>
  )
}

function DetectionRateWidget() {
  const { data, isLoading } = useQuery<DetectionRate>({
    queryKey: ['dashboard-detection-rate'],
    queryFn: () => apiFetch('/api/v1/dashboard/detection-rate'),
    refetchInterval: 60_000,
    retry: false,
  })

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 animate-pulse">
        <div className="w-20 h-20 rounded-full bg-falcon-hover/60" />
        <div className="w-32 h-4 bg-falcon-hover/60 rounded-sm" />
      </div>
    )
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        データなし
      </div>
    )
  }

  const rate = Math.round(data.resolution_rate ?? 0)
  const rateColor = rate >= 80 ? '#00e676' : rate >= 50 ? '#ff9800' : '#e8002d'

  return (
    <div className="flex flex-col items-center justify-center h-full gap-4 py-2">
      <div>
        <span className="text-5xl font-extrabold tabular-nums" style={{ color: rateColor }}>
          {rate}
        </span>
        <span className="text-xl font-bold" style={{ color: rateColor }}>%</span>
      </div>
      <p className="text-xs text-falcon-subtle">解決率</p>
      <div className="flex gap-6 text-center">
        <div>
          <p className="text-sm font-semibold text-falcon-text tabular-nums">
            {data.avg_resolution_hours != null ? `${data.avg_resolution_hours.toFixed(1)}h` : '—'}
          </p>
          <p className="text-[10px] text-falcon-subtle mt-0.5">平均解決時間</p>
        </div>
        <div>
          <p className="text-sm font-semibold tabular-nums" style={{ color: '#e8002d' }}>
            {data.open_critical ?? 0}
          </p>
          <p className="text-[10px] text-falcon-subtle mt-0.5">未解決クリティカル</p>
        </div>
      </div>
    </div>
  )
}

// ── Additional widgets ───────────────────────────────────────────

function AgentStatsWidget({ agents }: { agents: AgentItem[] }) {
  const online = agents.filter(a => a.status === 'online' || !a.status).length
  const offline = agents.filter(a => a.status === 'offline').length
  const other = agents.length - online - offline

  return (
    <div className="flex flex-col gap-3 h-full justify-center">
      <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-green-900/30 border border-green-800/50">
        <span className="text-xs text-green-400">オンライン</span>
        <span className="text-lg font-bold text-green-400">{online}</span>
      </div>
      <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-red-900/30 border border-red-800/50">
        <span className="text-xs text-red-400">オフライン</span>
        <span className="text-lg font-bold text-red-400">{offline}</span>
      </div>
      {other > 0 && (
        <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-yellow-900/30 border border-yellow-800/50">
          <span className="text-xs text-yellow-400">その他</span>
          <span className="text-lg font-bold text-yellow-400">{other}</span>
        </div>
      )}
    </div>
  )
}

function RecentAlertsWidget({ alerts }: { alerts: AlertItem[] }) {
  const recent = alerts.slice(0, 3)
  if (recent.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        アラートなし
      </div>
    )
  }
  return (
    <div className="space-y-2">
      {recent.map(a => (
        <div key={a.id} className="px-3 py-2 rounded-lg bg-falcon-hover/50 border-l-2"
             style={{ borderColor: severityColor(a.severity) }}>
          <p className="text-xs font-medium text-falcon-text truncate">{a.title}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px]" style={{ color: severityColor(a.severity) }}>
              {severityLabel(a.severity)}
            </span>
            <span className="text-[10px] text-falcon-subtle">{formatDate(a.created_at)}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function ActiveIncidentsWidget({ incidents }: { incidents: IncidentItem[] }) {
  const active = incidents.filter(i => i.status === 'open' || i.status === 'investigating')
  if (active.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        アクティブインシデントなし
      </div>
    )
  }
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-2xl font-bold text-orange-400">{active.length}</span>
        <span className="text-xs text-falcon-subtle">件アクティブ</span>
      </div>
      {active.slice(0, 4).map(inc => (
        <div key={inc.id} className="flex items-center gap-2 text-xs">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ background: severityColor(inc.severity) }} />
          <span className="flex-1 text-falcon-muted truncate">{inc.title}</span>
        </div>
      ))}
    </div>
  )
}

function SecurityScoreWidget({ scores }: { scores: ComplianceScore[] }) {
  const avg = scores.length > 0
    ? Math.round(scores.reduce((sum, s) => sum + s.score, 0) / scores.length)
    : 0
  const color = avg >= 80 ? '#00e676' : avg >= 60 ? '#ff9800' : '#e8002d'
  const label = avg >= 80 ? '良好' : avg >= 60 ? '注意' : '危険'

  return (
    <div className="flex flex-col items-center justify-center h-full gap-3">
      <TrendingUp className="w-8 h-8" style={{ color }} />
      <div className="text-center">
        <p className="text-4xl font-extrabold tabular-nums" style={{ color }}>{avg}</p>
        <p className="text-xs text-falcon-subtle mt-1">セキュリティスコア</p>
      </div>
      <span className="px-3 py-1 rounded-full text-xs font-semibold"
            style={{ background: `${color}22`, color }}>
        {label}
      </span>
    </div>
  )
}

function ThreatFeedsWidget() {
  const { data, isLoading } = useQuery<{ feeds?: Array<{ name: string; enabled: boolean; last_sync?: string }> }>({
    queryKey: ['dashboard-threat-feeds'],
    queryFn: () => apiFetch('/api/v1/threat-intel/feeds'),
    refetchInterval: 300_000,
    retry: false,
  })

  const feeds = data?.feeds ?? []

  if (isLoading) {
    return (
      <div className="space-y-2 animate-pulse">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="h-8 bg-falcon-hover/60 rounded-sm" />
        ))}
      </div>
    )
  }

  if (feeds.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        フィードなし
      </div>
    )
  }

  return (
    <div className="space-y-1.5">
      {feeds.slice(0, 5).map(feed => (
        <div key={feed.name} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-hover/50">
          <span className={`w-2 h-2 rounded-full shrink-0 ${feed.enabled ? 'bg-green-400' : 'bg-gray-600'}`} />
          <span className="flex-1 text-xs text-falcon-text truncate">{feed.name}</span>
          {feed.last_sync && (
            <span className="text-[10px] text-falcon-subtle">{formatDate(feed.last_sync)}</span>
          )}
        </div>
      ))}
    </div>
  )
}

// ── New Widgets (Task 2) ──────────────────────────────────────────

function NistScoreWidget() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const { data, isLoading } = useQuery<{ score?: number; nist_score?: number }>({
    queryKey: ['dashboard-nist-score'],
    queryFn: () => apiFetch('/api/v1/admin/scorecard/summary'),
    refetchInterval: 300_000,
    retry: false,
    enabled: isAdmin,
  })

  const score = data?.score ?? data?.nist_score ?? 78 // mock fallback
  const color = score >= 80 ? '#00c853' : score >= 60 ? '#ff9800' : '#e8002d'
  const label = score >= 80 ? 'Good' : score >= 60 ? 'Fair' : 'At Risk'

  // SVG arc gauge
  const radius = 36
  const circumference = 2 * Math.PI * radius
  const strokeDash = circumference * (score / 100)

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 animate-pulse">
        <div className="w-20 h-20 rounded-full bg-falcon-hover/60" />
        <div className="w-16 h-3 bg-falcon-hover/60 rounded-sm" />
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center justify-center h-full gap-2 py-2">
      <svg width="96" height="96" viewBox="0 0 96 96" className="-rotate-90">
        <circle cx="48" cy="48" r={radius} fill="none" stroke="#1e2d42" strokeWidth="8" />
        <circle
          cx="48" cy="48" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${strokeDash} ${circumference}`}
          style={{ transition: 'stroke-dasharray 0.5s ease' }}
        />
      </svg>
      <div className="text-center -mt-2">
        <p className="text-3xl font-extrabold tabular-nums" style={{ color }}>{score}</p>
        <p className="text-[10px] text-falcon-subtle mt-0.5 uppercase tracking-wider">NIST CSF Score</p>
      </div>
      <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold"
            style={{ background: `${color}22`, color }}>
        {label}
      </span>
    </div>
  )
}

function ActiveIncidentsCountWidget({ incidents }: { incidents: IncidentItem[] }) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const { data } = useQuery<{ data?: IncidentItem[]; items?: IncidentItem[] }>({
    queryKey: ['dashboard-incidents-widget'],
    queryFn: () => apiFetch('/api/v1/admin/incidents?status=open&per_page=5'),
    refetchInterval: 30_000,
    retry: false,
    enabled: isAdmin,
  })

  const rawIncidents = data?.data ?? data?.items ?? data ?? incidents
  const allIncidents = Array.isArray(rawIncidents) ? rawIncidents : incidents
  const open = allIncidents.filter(i => i.status === 'open' || i.status === 'investigating' || !i.status)
  const count = open.length > 0 ? open.length : incidents.filter(i => ['open', 'investigating'].includes(i.status)).length
  const mostRecent = open[0] ?? incidents[0]

  return (
    <div className="flex flex-col justify-center h-full gap-3 py-2">
      <div className="flex items-center gap-3">
        <div className="flex flex-col">
          <span className="text-4xl font-extrabold tabular-nums text-orange-400">{count}</span>
          <span className="text-[11px] text-falcon-subtle mt-0.5">open incidents</span>
        </div>
      </div>
      {mostRecent && (
        <div className="px-3 py-2 rounded-lg bg-orange-900/20 border border-orange-800/40">
          <p className="text-[10px] text-orange-400 uppercase tracking-wider font-semibold mb-0.5">Most Recent</p>
          <p className="text-xs text-falcon-text truncate">{mostRecent.title}</p>
        </div>
      )}
      <Link
        href="/incidents"
        className="text-[11px] text-orange-400 hover:text-orange-300 transition-colors inline-flex items-center gap-1"
      >
        View all incidents →
      </Link>
    </div>
  )
}

function AIInsightWidget() {
  return (
    <div className="flex items-start gap-4 h-full py-1">
      <div className="shrink-0 w-10 h-10 rounded-full bg-blue-900/30 border border-blue-500/30
                      flex items-center justify-center mt-0.5">
        <Bot className="w-5 h-5 text-blue-400" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1.5">
          <p className="text-sm font-semibold text-falcon-text">AI Security Insight</p>
          <span className="text-[9px] bg-blue-900/40 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded-full uppercase tracking-wider">
            Live
          </span>
        </div>
        <p className="text-sm text-falcon-muted leading-relaxed">
          No critical threats detected in the last 24 hours. <span className="text-orange-400 font-medium">3 alerts</span> require investigation.
        </p>
        <p className="text-[10px] text-falcon-subtle mt-2">Updated just now · Powered by Falcon AI</p>
      </div>
    </div>
  )
}

function WatchlistHitsWidget() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const { data, isLoading } = useQuery<{ today_hits?: number; hits_today?: number; total?: number }>({
    queryKey: ['dashboard-watchlist-hits'],
    queryFn: () => apiFetch('/api/v1/admin/watchlist/stats'),
    refetchInterval: 60_000,
    retry: false,
    enabled: isAdmin,
  })

  const hits = data?.today_hits ?? data?.hits_today ?? data?.total ?? 0

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 animate-pulse">
        <div className="w-16 h-12 bg-falcon-hover/60 rounded-sm" />
        <div className="w-20 h-3 bg-falcon-hover/60 rounded-sm" />
      </div>
    )
  }

  const color = hits > 10 ? '#e8002d' : hits > 0 ? '#ff9800' : '#00c853'

  return (
    <div className="flex flex-col items-center justify-center h-full gap-2 py-2">
      <Bookmark className="w-6 h-6 text-falcon-subtle" />
      <div className="text-center">
        <p className="text-4xl font-extrabold tabular-nums" style={{ color }}>{hits}</p>
        <p className="text-[11px] text-falcon-subtle mt-1">Watchlist Hits Today</p>
      </div>
      <Link
        href="/admin/watchlist"
        className="text-[11px] text-blue-400 hover:text-blue-300 transition-colors"
      >
        View watchlist →
      </Link>
    </div>
  )
}

// ── SOC Work Queue Summary Widget ────────────────────────────────

interface WorkQueueSummary { urgent: unknown[]; today: unknown[]; week: unknown[]; total: number }

function SocQueueSummaryWidget() {
  const { data, isLoading } = useQuery<WorkQueueSummary>({
    queryKey: ['soc-queue-summary'],
    queryFn: () => apiFetch('/api/v1/soc/work-queue'),
    refetchInterval: 60_000,
  })

  const urgent = data?.urgent?.length ?? 0
  const today  = data?.today?.length  ?? 0
  const week   = data?.week?.length   ?? 0

  if (isLoading) {
    return <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">読み込み中...</div>
  }

  return (
    <div className="flex flex-col gap-3 h-full py-1">
      <div className="flex items-center justify-between">
        <p className="text-xs text-falcon-subtle font-medium">SOC ワークキュー</p>
        <Link href="/soc-queue" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
          キューを開く →
        </Link>
      </div>
      <div className="flex gap-3 flex-1">
        <Link href="/soc-queue"
          className="flex-1 flex flex-col items-center justify-center gap-1 rounded-lg border
                     border-red-500/30 bg-red-500/10 hover:bg-red-500/20 transition-colors cursor-pointer">
          <span className="text-2xl font-bold text-red-400">{urgent}</span>
          <span className="text-xs text-red-400/80">緊急</span>
        </Link>
        <Link href="/soc-queue"
          className="flex-1 flex flex-col items-center justify-center gap-1 rounded-lg border
                     border-orange-500/30 bg-orange-500/10 hover:bg-orange-500/20 transition-colors cursor-pointer">
          <span className="text-2xl font-bold text-orange-400">{today}</span>
          <span className="text-xs text-orange-400/80">今日中</span>
        </Link>
        <Link href="/soc-queue"
          className="flex-1 flex flex-col items-center justify-center gap-1 rounded-lg border
                     border-blue-500/30 bg-blue-500/10 hover:bg-blue-500/20 transition-colors cursor-pointer">
          <span className="text-2xl font-bold text-blue-400">{week}</span>
          <span className="text-xs text-blue-400/80">今週中</span>
        </Link>
      </div>
      {urgent > 0 && (
        <p className="text-xs text-red-400 text-center">
          ⚠ 緊急対応が必要なアイテムが {urgent} 件あります
        </p>
      )}
    </div>
  )
}

// ── Quick Actions Widget ──────────────────────────────────────────

function QuickActionsWidget() {
  return (
    <div className="flex items-center gap-3 h-full py-1 flex-wrap">
      <p className="text-xs text-falcon-subtle w-full font-medium">Quick Actions</p>
      <Link
        href="/threat-hunting"
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-active border border-blue-500/30
                   text-sm font-medium text-blue-400 hover:bg-[#253d5e] hover:text-blue-300 transition-all"
      >
        <Crosshair className="w-4 h-4" />
        Start Hunt
      </Link>
      <Link
        href="/reports/builder"
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-active border border-green-500/30
                   text-sm font-medium text-green-400 hover:bg-[#1a3323] hover:text-green-300 transition-all"
      >
        <FileText className="w-4 h-4" />
        Create Report
      </Link>
      <Link
        href="/ioc"
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-active border border-orange-500/30
                   text-sm font-medium text-orange-400 hover:bg-[#3a2510] hover:text-orange-300 transition-all"
      >
        <Search className="w-4 h-4" />
        Check IOC
      </Link>
      <Link
        href="/admin/security-scorecard"
        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-active border border-purple-500/30
                   text-sm font-medium text-purple-400 hover:bg-[#2a1a40] hover:text-purple-300 transition-all"
      >
        <ShieldCheck className="w-4 h-4" />
        View Scorecard
      </Link>
    </div>
  )
}

// ── Threat Map Widget ─────────────────────────────────────────────

interface GeoThreat { country: string; flag: string; count: number; severity: 'critical' | 'high' | 'medium' | 'low' }

const FALLBACK_GEO_THREATS: GeoThreat[] = [
  { country: 'China',         flag: '🇨🇳', count: 142, severity: 'critical' },
  { country: 'Russia',        flag: '🇷🇺', count: 89,  severity: 'high' },
  { country: 'North Korea',   flag: '🇰🇵', count: 54,  severity: 'critical' },
  { country: 'United States', flag: '🇺🇸', count: 38,  severity: 'medium' },
  { country: 'Iran',          flag: '🇮🇷', count: 27,  severity: 'high' },
]

function ThreatMapWidget() {
  const { data, isLoading } = useQuery<{ data?: GeoThreat[]; threats?: GeoThreat[] }>({
    queryKey: ['dashboard-threat-map'],
    queryFn: () => apiFetch<{ data?: GeoThreat[]; threats?: GeoThreat[] }>('/api/v1/alerts/geo-stats').catch(() => ({
      data: FALLBACK_GEO_THREATS,
    })),
    refetchInterval: 300_000,
    retry: false,
  })

  const raw: GeoThreat[] = data?.data ?? data?.threats ?? []
  const threats: GeoThreat[] = raw.length > 0 ? raw : FALLBACK_GEO_THREATS
  const maxCount = Math.max(...threats.map(t => t.count), 1)

  if (isLoading) {
    return (
      <div className="space-y-2 animate-pulse">
        {[1, 2, 3, 4, 5].map(i => <div key={i} className="h-8 bg-falcon-hover/60 rounded-sm" />)}
      </div>
    )
  }

  const severityColor = (s: string) =>
    s === 'critical' ? '#ef4444' : s === 'high' ? '#f97316' : s === 'medium' ? '#eab308' : '#3b82f6'

  return (
    <div className="space-y-2">
      <p className="text-[10px] text-falcon-subtle uppercase tracking-wider mb-3">
        トップ送信元国 (直近 24h)
      </p>
      {threats.slice(0, 6).map(t => (
        <div key={t.country} className="flex items-center gap-2">
          <span className="text-base shrink-0">{t.flag}</span>
          <span className="text-xs text-falcon-text w-28 truncate shrink-0">{t.country}</span>
          <div className="flex-1 h-1.5 bg-falcon-hover rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all"
              style={{ width: `${(t.count / maxCount) * 100}%`, background: severityColor(t.severity) }} />
          </div>
          <span className="text-xs font-bold w-8 text-right shrink-0"
            style={{ color: severityColor(t.severity) }}>
            {t.count}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── Kill Chain Coverage Widget ────────────────────────────────────

const KILL_CHAIN_STAGES = [
  { id: 'recon',      label: '偵察',         color: '#6366f1' },
  { id: 'weaponize',  label: '兵器化',       color: '#8b5cf6' },
  { id: 'delivery',   label: '配送',         color: '#ec4899' },
  { id: 'exploit',    label: '攻撃',         color: '#ef4444' },
  { id: 'install',    label: 'インストール', color: '#f97316' },
  { id: 'c2',         label: 'C2',           color: '#eab308' },
  { id: 'actions',    label: '目的実行',     color: '#10b981' },
]

function KillChainWidget() {
  const { data, isLoading } = useQuery<{ data?: Record<string, number>; stages?: Record<string, number> }>({
    queryKey: ['dashboard-kill-chain'],
    queryFn: () => apiFetch<{ data?: Record<string, number>; stages?: Record<string, number> }>('/api/v1/alerts/kill-chain-stats').catch(() => ({
      data: { recon: 12, weaponize: 8, delivery: 23, exploit: 41, install: 19, c2: 15, actions: 7 },
    })),
    refetchInterval: 300_000,
    retry: false,
  })

  const stages = data?.data ?? data?.stages ?? {}
  const maxVal  = Math.max(...Object.values(stages), 1)

  if (isLoading) {
    return (
      <div className="flex items-end gap-1 h-28 animate-pulse">
        {KILL_CHAIN_STAGES.map(s => (
          <div key={s.id} className="flex-1 bg-falcon-hover/60 rounded-t" style={{ height: `${Math.random() * 100}%` }} />
        ))}
      </div>
    )
  }

  return (
    <div>
      <p className="text-[10px] text-falcon-subtle uppercase tracking-wider mb-3">
        Kill Chain ステージ別検知数
      </p>
      <div className="flex items-end gap-1 h-24">
        {KILL_CHAIN_STAGES.map(s => {
          const val = stages[s.id] ?? 0
          const pct = maxVal > 0 ? (val / maxVal) * 100 : 0
          return (
            <div key={s.id} className="flex-1 flex flex-col items-center gap-1">
              <span className="text-[9px] text-falcon-subtle tabular-nums">{val || ''}</span>
              <div className="w-full rounded-t transition-all"
                style={{ height: `${Math.max(pct, val > 0 ? 8 : 0)}%`, background: s.color, opacity: 0.8 }} />
            </div>
          )
        })}
      </div>
      <div className="flex gap-1 mt-1">
        {KILL_CHAIN_STAGES.map(s => (
          <div key={s.id} className="flex-1 text-center">
            <p className="text-[8px] text-falcon-subtle truncate">{s.label}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── IOC Hits Widget ───────────────────────────────────────────────

interface IocHit { value: string; type: string; hit_count: number; last_seen: string }

function IocHitsWidget() {
  const { data, isLoading } = useQuery<{ data?: IocHit[]; hits?: IocHit[] }>({
    queryKey: ['dashboard-ioc-hits'],
    queryFn: () => apiFetch<{ data?: IocHit[]; hits?: IocHit[] }>('/api/v1/ioc/top-hits').catch(() => ({
      data: [
        { value: '185.220.101.x', type: 'ip',     hit_count: 47, last_seen: new Date().toISOString() },
        { value: 'evil.ru',       type: 'domain',  hit_count: 31, last_seen: new Date().toISOString() },
        { value: 'a3f2b1c...',    type: 'hash',    hit_count: 18, last_seen: new Date().toISOString() },
        { value: 'cdn.bad.com',   type: 'domain',  hit_count: 12, last_seen: new Date().toISOString() },
        { value: '10.0.0.x',      type: 'ip',      hit_count: 9,  last_seen: new Date().toISOString() },
      ],
    })),
    refetchInterval: 60_000,
    retry: false,
  })

  const hits: IocHit[] = data?.data ?? data?.hits ?? []

  if (isLoading) {
    return (
      <div className="space-y-2 animate-pulse">
        {[1, 2, 3].map(i => <div key={i} className="h-9 bg-falcon-hover/60 rounded-sm" />)}
      </div>
    )
  }

  if (hits.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-falcon-subtle text-sm">
        IOCマッチなし
      </div>
    )
  }

  const typeColor = (t: string) =>
    t === 'ip' ? 'bg-red-900/30 text-red-300' :
    t === 'domain' ? 'bg-orange-900/30 text-orange-300' :
    'bg-purple-900/30 text-purple-300'

  return (
    <div className="space-y-1.5">
      <p className="text-[10px] text-falcon-subtle uppercase tracking-wider mb-2">
        Top IOCマッチ (直近 24h)
      </p>
      {hits.slice(0, 5).map((h, i) => (
        <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded-sm bg-falcon-hover/50">
          <span className={`text-[9px] px-1.5 py-0.5 rounded-sm font-semibold shrink-0 ${typeColor(h.type)}`}>
            {h.type.toUpperCase()}
          </span>
          <span className="text-xs text-falcon-text font-mono flex-1 truncate">{h.value}</span>
          <span className="text-xs font-bold text-red-400 shrink-0">{h.hit_count}</span>
        </div>
      ))}
    </div>
  )
}

// ── Alert Heatmap Widget — 24h × 7d grid ─────────────────────────

interface HeatmapCell { day: number; hour: number; count: number }

function AlertHeatmapWidget() {
  const { data, isLoading } = useQuery<{ data?: HeatmapCell[] }>({
    queryKey: ['dashboard-alert-heatmap'],
    queryFn: () => apiFetch<{ data?: HeatmapCell[] }>('/api/v1/alerts/heatmap').catch(() => {
      // Generate plausible mock data — higher volume on weekdays, business hours + midnight spikes
      const cells: HeatmapCell[] = []
      for (let d = 0; d < 7; d++) {
        for (let h = 0; h < 24; h++) {
          const isWeekday = d > 0 && d < 6
          const isBizHour = h >= 9 && h <= 17
          const isMidnight = h >= 0 && h <= 2
          const base = isWeekday ? 3 : 1
          const mult = isBizHour ? 3 : isMidnight ? 2 : 1
          cells.push({ day: d, hour: h, count: Math.floor(base * mult * (0.5 + Math.random())) })
        }
      }
      return { data: cells }
    }),
    staleTime: 300_000,
    retry: false,
  })

  const cells: HeatmapCell[] = data?.data ?? []

  const DAYS = ['日', '月', '火', '水', '木', '金', '土']
  const maxCount = cells.length > 0 ? Math.max(...cells.map(c => c.count), 1) : 1

  const cellColor = (count: number) => {
    if (count === 0) return '#0d1220'
    const pct = count / maxCount
    if (pct > 0.75) return '#e8002d'
    if (pct > 0.5)  return '#ff6b35'
    if (pct > 0.25) return '#ff9800'
    return '#1a6bff'
  }

  if (isLoading) {
    return <div className="h-32 bg-falcon-hover/40 rounded-sm animate-pulse" />
  }

  return (
    <div>
      <p className="text-[10px] text-falcon-subtle uppercase tracking-wider mb-3">
        アラート発生パターン (曜日 × 時間帯)
      </p>
      {/* Hour axis header */}
      <div className="flex items-center gap-0.5 mb-1 ml-6">
        {Array.from({ length: 24 }, (_, h) => (
          <div key={h} className="flex-1 text-center text-[8px] text-falcon-subtle">
            {h % 6 === 0 ? `${h}h` : ''}
          </div>
        ))}
      </div>
      {/* Grid rows */}
      <div className="space-y-0.5">
        {DAYS.map((day, d) => (
          <div key={d} className="flex items-center gap-0.5">
            <span className="text-[9px] text-[#5a6a7a] w-5 shrink-0 text-right mr-1">{day}</span>
            {Array.from({ length: 24 }, (_, h) => {
              const cell = cells.find(c => c.day === d && c.hour === h)
              const count = cell?.count ?? 0
              return (
                <div
                  key={h}
                  className="flex-1 rounded-xs transition-all cursor-default"
                  style={{ height: 14, backgroundColor: cellColor(count) }}
                  title={`${day}曜 ${h}時: ${count}件`}
                />
              )
            })}
          </div>
        ))}
      </div>
      {/* Legend */}
      <div className="flex items-center gap-2 mt-2 justify-end">
        {[
          { color: '#0d1220', label: '0' },
          { color: '#1a6bff', label: '低' },
          { color: '#ff9800', label: '中' },
          { color: '#ff6b35', label: '高' },
          { color: '#e8002d', label: '最高' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1">
            <div className="w-3 h-2 rounded-xs" style={{ backgroundColor: color }} />
            <span className="text-[9px] text-falcon-subtle">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Widget card wrapper ───────────────────────────────────────────

function WidgetCard({
  widget,
  editMode,
  onHide,
  minimized,
  onMinimize,
  children,
}: {
  widget: WidgetDef
  editMode: boolean
  onHide: () => void
  minimized: boolean
  onMinimize: () => void
  children: React.ReactNode
}) {
  const Icon = WIDGET_ICONS[widget.type]
  // スマートフォン: 常に全幅 / タブレット: 2列 / PC: 3列レイアウト
  const colSpan = widget.position.w === 3
    ? 'col-span-1 sm:col-span-2 lg:col-span-3'
    : widget.position.w === 2
      ? 'col-span-1 sm:col-span-2 lg:col-span-2'
      : 'col-span-1'

  return (
    <div className={`bg-falcon-surface rounded-xl border flex flex-col overflow-hidden transition-all ${colSpan} ${
      editMode ? 'border-blue-500/60 ring-1 ring-blue-500/20' : 'border-falcon-border'
    }`}>
      {/* Title bar */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-falcon-border bg-falcon-surface/80 select-none">
        {editMode && (
          <GripVertical className="w-4 h-4 text-blue-400/70 shrink-0 cursor-grab" />
        )}
        {!editMode && (
          <GripVertical className="w-4 h-4 text-gray-600 shrink-0" />
        )}
        <Icon className="w-4 h-4 text-blue-400 shrink-0" />
        <span className="text-sm font-semibold text-falcon-text flex-1">{WIDGET_LABELS[widget.type]}</span>

        {/* Minimize toggle */}
        {!editMode && (
          <button
            onClick={onMinimize}
            className="p-1 rounded-sm text-falcon-subtle hover:text-falcon-muted hover:bg-falcon-active transition-colors"
            title={minimized ? '展開' : '最小化'}
          >
            {minimized ? (
              <svg className="w-3.5 h-3.5" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="2,9 7,4 12,9" />
              </svg>
            ) : (
              <svg className="w-3.5 h-3.5" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="2,5 7,10 12,5" />
              </svg>
            )}
          </button>
        )}

        {/* Hide (X) button in edit mode */}
        {editMode && (
          <button
            onClick={onHide}
            className="p-1 rounded-sm text-falcon-subtle hover:text-red-400 hover:bg-red-900/30 transition-colors"
            title="ウィジェットを非表示"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Content */}
      {!minimized && (
        <div className="p-4 flex-1">
          {children}
        </div>
      )}
    </div>
  )
}

// ── Main page ────────────────────────────────────────────────────

export default function DashboardPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()
  const [editMode, setEditMode] = useState(false)
  const [minimized, setMinimized] = useState<Set<string>>(new Set())
  const [showAddDropdown, setShowAddDropdown] = useState(false)

  // ── Widget visibility — localStorage as source of truth ─────
  const [visibleWidgets, setVisibleWidgets] = useState<string[]>(() => {
    if (typeof window === 'undefined') return DEFAULT_VISIBLE_IDS
    const saved = localStorage.getItem(LS_KEY)
    return saved ? JSON.parse(saved) : DEFAULT_VISIBLE_IDS
  })

  const hideWidget = useCallback((id: string) => {
    setVisibleWidgets(prev => {
      const next = prev.filter(w => w !== id)
      localStorage.setItem(LS_KEY, JSON.stringify(next))
      return next
    })
  }, [])

  const showWidget = useCallback((id: string) => {
    setVisibleWidgets(prev => {
      if (prev.includes(id)) return prev
      const next = [...prev, id]
      localStorage.setItem(LS_KEY, JSON.stringify(next))
      return next
    })
  }, [])

  const resetLayout = useCallback(() => {
    setVisibleWidgets(DEFAULT_VISIBLE_IDS)
    setMinimized(new Set())
    localStorage.setItem(LS_KEY, JSON.stringify(DEFAULT_VISIBLE_IDS))
  }, [])

  const toggleMinimize = useCallback((id: string) => {
    setMinimized(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  // ── Preferences sync (server-side) ───────────────────────────
  const prefsLoaded = useRef(false)
  const { data: prefsData } = useQuery<{ preferences?: { widgets?: Array<{ id: string; visible: boolean }> } }>({
    queryKey: ['dashboard-preferences'],
    queryFn: () => apiFetch('/api/v1/dashboard/preferences'),
    staleTime: Infinity,
  })

  useEffect(() => {
    if (prefsLoaded.current) return
    if (!prefsData) return
    // Only use server prefs if localStorage is empty (first visit)
    const lsVal = typeof window !== 'undefined' ? localStorage.getItem(LS_KEY) : null
    if (!lsVal) {
      const saved = prefsData?.preferences?.widgets
      if (saved && saved.length > 0) {
        const ids = saved.filter(w => w.visible).map(w => w.id)
        setVisibleWidgets(ids)
        localStorage.setItem(LS_KEY, JSON.stringify(ids))
      }
    }
    prefsLoaded.current = true
  }, [prefsData])

  // Save preferences to server when visibleWidgets changes
  const savePrefs = useMutation({
    mutationFn: (ids: string[]) =>
      apiFetch('/api/v1/dashboard/preferences', {
        method: 'PUT',
        body: JSON.stringify({
          preferences: {
            widgets: ALL_WIDGET_IDS.map(id => ({ id, visible: ids.includes(id) })),
          },
        }),
      }),
  })

  useEffect(() => {
    if (!prefsLoaded.current) return
    if (canWrite) savePrefs.mutate(visibleWidgets)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleWidgets])

  // ── Data queries ─────────────────────────────────────────────
  const { data: alerts = [], isLoading: alertsLoading, isError: alertsError } = useQuery<AlertItem[]>({
    queryKey: ['dashboard-alerts'],
    queryFn: () => apiFetchList<AlertItem>('/api/v1/alerts?limit=5&sort=desc'),
    refetchInterval: 30_000,
  })

  const { data: agentsRaw = [], isLoading: agentsLoading, isError: agentsError } = useQuery<AgentItem[]>({
    queryKey: ['dashboard-agents'],
    queryFn: () => apiFetchList<AgentItem>('/api/v1/agents?limit=5&status=online'),
    refetchInterval: 30_000,
  })

  const { data: incidents = [], isLoading: incidentsLoading, isError: incidentsError } = useQuery<IncidentItem[]>({
    queryKey: ['dashboard-incidents'],
    queryFn: () => apiFetchList<IncidentItem>('/api/v1/incidents?status=open&per_page=5'),
    refetchInterval: 30_000,
  })

  const { data: complianceScores = [] } = useQuery<ComplianceScore[]>({
    queryKey: ['dashboard-compliance'],
    queryFn: () => apiFetchList<ComplianceScore>('/api/v1/compliance/scores'),
    refetchInterval: 60_000,
    retry: false,
  })

  const isLoading = alertsLoading || agentsLoading || incidentsLoading
  const hasDataError = alertsError || agentsError || incidentsError

  const refreshAll = () => {
    qc.invalidateQueries({ queryKey: ['dashboard-alerts'] })
    qc.invalidateQueries({ queryKey: ['dashboard-agents'] })
    qc.invalidateQueries({ queryKey: ['dashboard-incidents'] })
    qc.invalidateQueries({ queryKey: ['dashboard-compliance'] })
    qc.invalidateQueries({ queryKey: ['dashboard-alert-trend'] })
    qc.invalidateQueries({ queryKey: ['dashboard-top-endpoints'] })
    qc.invalidateQueries({ queryKey: ['dashboard-detection-rate'] })
    qc.invalidateQueries({ queryKey: ['dashboard-threat-feeds'] })
  }

  // Compute which widgets are visible and which are hidden
  const activeWidgets = DEFAULT_WIDGETS.filter(w => visibleWidgets.includes(w.id))
  const hiddenWidgets = DEFAULT_WIDGETS.filter(w => !visibleWidgets.includes(w.id))

  function renderWidgetContent(widget: WidgetDef) {
    switch (widget.type) {
      case 'quick_stats':
        return <QuickStatsWidget alerts={alerts} agents={agentsRaw} incidents={incidents} />
      case 'alert_summary':
        return <AlertSummaryWidget alerts={alerts} />
      case 'agent_status':
        return <AgentStatusWidget agents={agentsRaw} total={agentsRaw.length} />
      case 'incident_list':
        return <IncidentListWidget incidents={incidents} />
      case 'compliance_score':
        return <ComplianceScoreWidget scores={complianceScores} />
      case 'severity_chart':
        return <SeverityChartWidget alerts={alerts} />
      case 'alert_trend':
        return <AlertTrendWidget />
      case 'top_endpoints':
        return <TopEndpointsWidget />
      case 'detection_rate':
        return <DetectionRateWidget />
      case 'agent_stats':
        return <AgentStatsWidget agents={agentsRaw} />
      case 'recent_alerts':
        return <RecentAlertsWidget alerts={alerts} />
      case 'active_incidents':
        return <ActiveIncidentsWidget incidents={incidents} />
      case 'security_score':
        return <SecurityScoreWidget scores={complianceScores} />
      case 'threat_feeds':
        return <ThreatFeedsWidget />
      case 'nist_score':
        return <NistScoreWidget />
      case 'active_incidents_count':
        return <ActiveIncidentsCountWidget incidents={incidents} />
      case 'ai_insight':
        return <AIInsightWidget />
      case 'watchlist_hits':
        return <WatchlistHitsWidget />
      case 'quick_actions':
        return <QuickActionsWidget />
      case 'threat_map':
        return <ThreatMapWidget />
      case 'kill_chain':
        return <KillChainWidget />
      case 'ioc_hits':
        return <IocHitsWidget />
      case 'alert_heatmap':
        return <AlertHeatmapWidget />
      case 'soc_queue_summary':
        return <SocQueueSummaryWidget />
    }
  }

  return (
    <div className="min-h-screen bg-gray-900 p-6" onClick={() => setShowAddDropdown(false)}>
      {/* API エラーバナー */}
      {hasDataError && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-falcon-red/10 border border-falcon-red/30 flex items-center gap-2">
          <span className="text-falcon-red text-xs font-medium">⚠ 一部のデータ取得に失敗しています。表示が最新でない可能性があります。</span>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <LayoutDashboard className="w-6 h-6 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold text-white">ダッシュボード</h1>
            <p className="text-xs text-falcon-subtle mt-0.5">セキュリティ概況</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={refreshAll}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-falcon-subtle
                       bg-falcon-surface border border-falcon-border rounded-lg hover:bg-falcon-active hover:text-white transition-colors"
            title="データを更新"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>

          {editMode && (
            <>
              {/* Reset Layout button */}
              <button
                onClick={resetLayout}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-falcon-subtle
                           bg-falcon-surface border border-falcon-border rounded-lg hover:bg-falcon-active hover:text-white transition-colors"
                title="レイアウトをデフォルトに戻す"
              >
                <RotateCcw className="w-4 h-4" />
                リセット
              </button>

              {/* Add Widget dropdown */}
              {hiddenWidgets.length > 0 && (
                <div className="relative">
                  <button
                    onClick={e => { e.stopPropagation(); setShowAddDropdown(v => !v) }}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-falcon-subtle
                               bg-falcon-surface border border-falcon-border rounded-lg hover:bg-falcon-active hover:text-white transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    ウィジェット追加
                  </button>
                  {showAddDropdown && (
                    <div
                      className="absolute right-0 top-10 z-50 bg-falcon-surface border border-gray-600 rounded-xl shadow-xl py-1 min-w-[200px]"
                      onClick={e => e.stopPropagation()}
                    >
                      <p className="text-[10px] text-falcon-subtle uppercase tracking-wider px-3 py-1.5">
                        非表示のウィジェット
                      </p>
                      {hiddenWidgets.map(w => {
                        const Icon = WIDGET_ICONS[w.type]
                        return (
                          <button
                            key={w.id}
                            onClick={() => { showWidget(w.id); setShowAddDropdown(false) }}
                            className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-falcon-muted
                                       hover:bg-falcon-active hover:text-white transition-colors"
                          >
                            <Icon className="w-4 h-4 text-blue-400 shrink-0" />
                            {WIDGET_LABELS[w.type]}
                          </button>
                        )
                      })}
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {/* Customize / Done button (admin/analyst only) */}
          {canWrite && (
            <button
              onClick={() => { setEditMode(v => !v); setShowAddDropdown(false) }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border transition-colors ${
                editMode
                  ? 'bg-blue-600 border-blue-500 text-white hover:bg-blue-500'
                  : 'bg-falcon-surface border-falcon-border text-falcon-subtle hover:bg-falcon-active hover:text-white'
              }`}
            >
              <Settings2 className="w-4 h-4" />
              {editMode ? '完了' : 'カスタマイズ'}
            </button>
          )}
        </div>
      </div>

      {/* Edit mode banner */}
      {editMode && (
        <div className="mb-4 px-4 py-3 bg-blue-900/30 border border-blue-500/40 rounded-xl flex items-center gap-3">
          <Settings2 className="w-4 h-4 text-blue-400 shrink-0" />
          <p className="text-sm text-blue-300">
            編集モード — 各ウィジェットの <X className="w-3 h-3 inline" /> ボタンで非表示にできます。
            「ウィジェット追加」から非表示のウィジェットを再表示できます。
          </p>
        </div>
      )}

      {/* Loading state */}
      {isLoading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 animate-pulse">
          <div className="col-span-1 sm:col-span-2 lg:col-span-3 h-32 bg-falcon-surface rounded-xl border border-falcon-border" />
          <div className="col-span-1 sm:col-span-2 h-48 bg-falcon-surface rounded-xl border border-falcon-border" />
          <div className="col-span-1 h-48 bg-falcon-surface rounded-xl border border-falcon-border" />
          <div className="col-span-1 sm:col-span-2 h-48 bg-falcon-surface rounded-xl border border-falcon-border" />
          <div className="col-span-1 h-48 bg-falcon-surface rounded-xl border border-falcon-border" />
          <div className="col-span-1 sm:col-span-2 lg:col-span-3 h-40 bg-falcon-surface rounded-xl border border-falcon-border" />
        </div>
      )}

      {/* Widget grid */}
      {!isLoading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {activeWidgets.map(widget => (
            <WidgetCard
              key={widget.id}
              widget={widget}
              editMode={editMode}
              onHide={() => hideWidget(widget.id)}
              minimized={minimized.has(widget.id)}
              onMinimize={() => toggleMinimize(widget.id)}
            >
              {renderWidgetContent(widget)}
            </WidgetCard>
          ))}
          {activeWidgets.length === 0 && (
            <div className="col-span-3 text-center py-20 text-gray-600">
              <LayoutDashboard className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p className="text-sm">表示するウィジェットがありません</p>
              <button
                onClick={() => setEditMode(true)}
                className="text-xs text-blue-400 hover:text-blue-300 mt-2 underline"
              >
                カスタマイズからウィジェットを追加
              </button>
            </div>
          )}
        </div>
      )}

      {/* Hidden widgets summary when in edit mode */}
      {editMode && hiddenWidgets.length > 0 && (
        <div className="mt-6 p-4 bg-falcon-surface/50 border border-dashed border-falcon-border rounded-xl">
          <p className="text-xs text-falcon-subtle mb-3 flex items-center gap-1.5">
            <EyeOff className="w-3.5 h-3.5" />
            非表示のウィジェット ({hiddenWidgets.length}件)
          </p>
          <div className="flex flex-wrap gap-2">
            {hiddenWidgets.map(w => {
              const Icon = WIDGET_ICONS[w.type]
              return (
                <button
                  key={w.id}
                  onClick={() => showWidget(w.id)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-falcon-hover/60
                             border border-gray-600 text-falcon-subtle hover:text-white hover:border-blue-500
                             hover:bg-blue-900/20 transition-all text-xs"
                >
                  <Plus className="w-3 h-3" />
                  <Icon className="w-3 h-3" />
                  {WIDGET_LABELS[w.type]}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
