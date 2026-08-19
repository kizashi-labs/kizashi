'use client'

import { useState, useMemo } from 'react'
import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { USE_MOCK } from '@/lib/mock'
import {
  TrendingDown, AlertTriangle, Shield, Server,
  Info, ChevronRight, RefreshCw,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface AlertItem {
  id: string
  severity?: string | number
  status?: string
  agent_id?: string
  created_at?: string
  timestamp?: string
}

interface AlertsResponse {
  data?: AlertItem[]
  items?: AlertItem[]
}

interface AgentItem {
  id: string
  hostname: string
  status?: string
  last_seen?: string
  metadata?: { cpu_usage?: number; alert_count?: number }
  alert_count?: number
  risk_score?: number
}

interface AgentsResponse {
  data?: AgentItem[]
  items?: AgentItem[]
}

interface ComplianceSummary {
  score?: number
  violations?: number
  compliant?: number
  total?: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TOOLTIP_STYLE = {
  backgroundColor: '#1f2937',
  border: '1px solid #374151',
  borderRadius: 8,
  color: '#fff',
  fontSize: 12,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeSeverity(s: string | number | undefined): string {
  if (s === undefined || s === null) return 'unknown'
  const str = String(s).toLowerCase()
  if (str === 'critical' || str === '4') return 'critical'
  if (str === 'high'     || str === '3') return 'high'
  if (str === 'medium'   || str === '2') return 'medium'
  if (str === 'low'      || str === '1') return 'low'
  return 'unknown'
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}

function calcOrgRiskScore(
  criticalAlerts: number,
  highAlerts: number,
  mediumAlerts: number,
  lowAlerts: number
): number {
  const maxPossible = 10 * 40 + 20 * 25 + 30 * 10 + 50 * 5 // reference ceiling
  const raw = criticalAlerts * 40 + highAlerts * 25 + mediumAlerts * 10 + lowAlerts * 5
  return clamp(Math.round((raw / maxPossible) * 100), 0, 100)
}

function calcAgentRiskScore(agent: AgentItem, agentAlertCount: number): number {
  let score = 0
  if (agent.status === 'offline') score += 30
  else if (agent.status === 'warning') score += 15
  const cpu = agent.metadata?.cpu_usage ?? 0
  if (cpu > 90) score += 20
  else if (cpu > 70) score += 10
  score += Math.min(agentAlertCount * 8, 50)
  const lastSeen = agent.last_seen ? new Date(agent.last_seen) : null
  if (lastSeen) {
    const hoursAgo = (Date.now() - lastSeen.getTime()) / (1000 * 60 * 60)
    if (hoursAgo > 48) score += 20
    else if (hoursAgo > 24) score += 10
  }
  return clamp(score, 0, 100)
}

function riskLabel(score: number): string {
  if (score <= 30)  return '低リスク'
  if (score <= 60)  return '中リスク'
  if (score <= 80)  return '高リスク'
  return '重大リスク'
}

function riskColor(score: number): string {
  if (score <= 30)  return '#22c55e'  // green-500
  if (score <= 60)  return '#eab308'  // yellow-500
  if (score <= 80)  return '#f97316'  // orange-500
  return '#ef4444'                     // red-500
}

function riskTailwindText(score: number): string {
  if (score <= 30)  return 'text-green-400'
  if (score <= 60)  return 'text-yellow-400'
  if (score <= 80)  return 'text-orange-400'
  return 'text-red-400'
}

function riskTailwindBg(score: number): string {
  if (score <= 30)  return 'bg-green-500'
  if (score <= 60)  return 'bg-yellow-500'
  if (score <= 80)  return 'bg-orange-500'
  return 'bg-red-500'
}

function formatLastSeen(s?: string): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('ja-JP', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

// ─── SVG Gauge ────────────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  // Arc from -210deg to 30deg (240deg sweep) as a semicircle gauge
  const radius = 80
  const cx = 100
  const cy = 100
  const startAngle = -210
  const endAngle = 30
  const sweepDeg = endAngle - startAngle // 240
  const filled = (score / 100) * sweepDeg

  function polarToCartesian(angle: number) {
    const rad = (angle * Math.PI) / 180
    return {
      x: cx + radius * Math.cos(rad),
      y: cy + radius * Math.sin(rad),
    }
  }

  function arcPath(start: number, end: number) {
    const s = polarToCartesian(start)
    const e = polarToCartesian(end)
    const large = end - start > 180 ? 1 : 0
    return `M ${s.x} ${s.y} A ${radius} ${radius} 0 ${large} 1 ${e.x} ${e.y}`
  }

  const color = riskColor(score)

  return (
    <svg viewBox="0 0 200 160" className="w-52 h-44">
      {/* Track */}
      <path
        d={arcPath(startAngle, endAngle)}
        fill="none"
        stroke="#374151"
        strokeWidth={14}
        strokeLinecap="round"
      />
      {/* Filled arc */}
      {score > 0 && (
        <path
          d={arcPath(startAngle, startAngle + filled)}
          fill="none"
          stroke={color}
          strokeWidth={14}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${color}80)` }}
        />
      )}
      {/* Score text */}
      <text
        x={cx}
        y={cy + 8}
        textAnchor="middle"
        dominantBaseline="middle"
        fill={color}
        fontSize={32}
        fontWeight="bold"
        fontFamily="monospace"
      >
        {score}
      </text>
      {/* Label */}
      <text
        x={cx}
        y={cy + 36}
        textAnchor="middle"
        fill="#9ca3af"
        fontSize={11}
      >
        {riskLabel(score)}
      </text>
      {/* Scale labels */}
      <text x={14} y={140} fill="#6b7280" fontSize={9}>0</text>
      <text x={180} y={140} fill="#6b7280" fontSize={9}>100</text>
    </svg>
  )
}

// ─── Breakdown Bar ────────────────────────────────────────────────────────────

function BreakdownBar({
  label, score, description,
}: {
  label: string
  score: number
  description?: string
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-sm text-gray-300">{label}</span>
        <span className={`text-sm font-bold ${riskTailwindText(score)}`}>{score}</span>
      </div>
      <div className="h-2.5 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${riskTailwindBg(score)}`}
          style={{ width: `${score}%` }}
        />
      </div>
      {description && (
        <p className="text-xs text-gray-500">{description}</p>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function RiskScorePage() {
  const [showCriteria, setShowCriteria] = useState(false)

  // ── Queries ──

  const { data: alertsRaw, isLoading: alertsLoading, refetch: refetchAlerts } = useQuery<
    AlertsResponse | AlertItem[]
  >({
    queryKey: ['risk-alerts'],
    queryFn: () => apiFetch('/api/v1/alerts?status=open&limit=500'),
    refetchInterval: 60_000,
  })

  const { data: agentsRaw, isLoading: agentsLoading, refetch: refetchAgents } = useQuery<
    AgentsResponse | AgentItem[]
  >({
    queryKey: ['risk-agents'],
    queryFn: () => apiFetch('/api/v1/agents?limit=200'),
    refetchInterval: 60_000,
  })

  const { data: complianceRaw } = useQuery<ComplianceSummary>({
    queryKey: ['risk-compliance'],
    queryFn: () => apiFetch('/api/v1/compliance/summary'),
    retry: false,
    refetchInterval: 120_000,
  })

  const isLoading = alertsLoading || agentsLoading

  // ── Normalize ──

  const alerts: AlertItem[] = useMemo(() => {
    if (!alertsRaw) return []
    if (Array.isArray(alertsRaw)) return alertsRaw
    return (alertsRaw as AlertsResponse).data ?? (alertsRaw as AlertsResponse).items ?? []
  }, [alertsRaw])

  const agents: AgentItem[] = useMemo(() => {
    if (!agentsRaw) return []
    if (Array.isArray(agentsRaw)) return agentsRaw
    return (agentsRaw as AgentsResponse).data ?? (agentsRaw as AgentsResponse).items ?? []
  }, [agentsRaw])

  // ── Alert counts by severity ──

  const alertCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 }
    alerts.forEach(a => {
      const sev = normalizeSeverity(a.severity)
      if (sev in counts) counts[sev as keyof typeof counts]++
    })
    return counts
  }, [alerts])

  // ── Overall risk score ──

  const orgRiskScore = useMemo(
    () => calcOrgRiskScore(
      alertCounts.critical, alertCounts.high,
      alertCounts.medium, alertCounts.low
    ),
    [alertCounts]
  )

  // ── Mock 30-day trend (realistic looking historical data) ──

  // 30日間のリスク推移。
  //
  // 以前はこれを「今のスコア - 30 + 経過日数」に乱数を足して作っていました。
  // 過去のスコアはどこにも記録されていないので、線は毎回違う形で描かれます。
  // 右肩の傾きは、この画面を開いた人にとっては「上がってきている」という
  // 事実です。誰も測っていません。
  const trendData = useMemo(() => {
    if (!USE_MOCK) return []
    const now = new Date()
    return Array.from({ length: 30 }, (_, i) => {
      const d = new Date(now)
      d.setDate(d.getDate() - (29 - i))
      const base = Math.max(10, orgRiskScore - 30 + i)
      const noise = Math.round((Math.random() - 0.5) * 12)
      return {
        date: `${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`,
        score: clamp(base + noise, 0, 100),
      }
    })
  }, [orgRiskScore])

  // ── Per-agent alert counts ──

  const agentAlertCounts = useMemo(() => {
    const map: Record<string, number> = {}
    alerts.forEach(a => {
      if (a.agent_id) map[a.agent_id] = (map[a.agent_id] ?? 0) + 1
    })
    return map
  }, [alerts])

  // ── Agent risk scores (top 10) ──

  const topRiskAgents = useMemo(() => {
    return agents
      .map(agent => ({
        ...agent,
        computedRisk: calcAgentRiskScore(agent, agentAlertCounts[agent.id] ?? agent.alert_count ?? 0),
        openAlerts: agentAlertCounts[agent.id] ?? agent.alert_count ?? 0,
      }))
      .sort((a, b) => b.computedRisk - a.computedRisk)
      .slice(0, 10)
  }, [agents, agentAlertCounts])

  // ── Breakdown scores ──

  const offlineAgents   = agents.filter(a => a.status === 'offline').length
  const warningAgents   = agents.filter(a => a.status === 'warning').length
  const endpointRisk    = clamp(offlineAgents * 15 + warningAgents * 8, 0, 100)

  const alertRisk       = clamp(alertCounts.critical * 20 + alertCounts.high * 10, 0, 100)

  const complianceScore = complianceRaw?.score ?? null
  const complianceViolations = complianceRaw?.violations ?? 0
  const complianceRisk  = complianceScore !== null
    ? clamp(100 - complianceScore, 0, 100)
    : clamp(complianceViolations * 5, 0, 100)

  // Mock IOC matches count (would come from a real endpoint)
  const iocMatches      = 0
  const threatIntelRisk = clamp(iocMatches * 25, 0, 100)

  // ── Risk factors ──

  const riskFactors = [
    {
      label: `未対処のクリティカルアラート: ${alertCounts.critical}件`,
      impact: 'critical' as const,
      value: alertCounts.critical,
    },
    {
      label: `オフラインエージェント: ${offlineAgents}件`,
      impact: 'high' as const,
      value: offlineAgents,
    },
    {
      label: `コンプライアンス違反: ${complianceViolations}件`,
      impact: 'medium' as const,
      value: complianceViolations,
    },
    {
      label: `最近の脅威インテリジェンスマッチ: ${iocMatches}件`,
      impact: 'high' as const,
      value: iocMatches,
    },
  ]

  const impactStyle = {
    critical: 'bg-red-900/40 text-red-300 border-red-700/40',
    high:     'bg-orange-900/40 text-orange-300 border-orange-700/40',
    medium:   'bg-yellow-900/40 text-yellow-300 border-yellow-700/40',
  }

  const impactLabel = {
    critical: '重大',
    high:     '高',
    medium:   '中',
  }

  // ─────────────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-900 p-6 space-y-6">
      <PageDataUnavailable />

      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-red-700 rounded-lg flex items-center justify-center shrink-0">
            <TrendingDown className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">リスクスコア</h1>
            <p className="text-xs text-gray-400">
              組織全体のセキュリティリスクをスコア化して可視化します
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCriteria(v => !v)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white text-sm transition-colors"
          >
            <Info className="w-3.5 h-3.5" />
            計算基準を表示
          </button>
          <button
            onClick={() => { refetchAlerts(); refetchAgents() }}
            disabled={isLoading}
            className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors disabled:opacity-40"
            title="更新"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ── Criteria Panel ── */}
      {showCriteria && (
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Info className="w-4 h-4 text-blue-400" />
            リスクスコア計算基準
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm text-gray-300">
            <div>
              <p className="text-gray-400 text-xs mb-1 font-medium">組織全体スコア</p>
              <code className="text-xs text-green-300 bg-gray-900 px-2 py-1 rounded-sm block">
                (critical×40 + high×25 + medium×10 + low×5) / maxScore × 100
              </code>
            </div>
            <div>
              <p className="text-gray-400 text-xs mb-1 font-medium">エージェント個別スコア</p>
              <ul className="text-xs text-gray-400 space-y-0.5">
                <li>• オフライン状態: +30</li>
                <li>• 警告状態: +15</li>
                <li>• CPU 90%超: +20 / 70%超: +10</li>
                <li>• アラート数 ×8 (上限50)</li>
                <li>• 48h以上未通信: +20</li>
              </ul>
            </div>
          </div>
          <div className="mt-3 flex gap-4 text-xs">
            <span className="text-green-400">0–30: 低リスク</span>
            <span className="text-yellow-400">31–60: 中リスク</span>
            <span className="text-orange-400">61–80: 高リスク</span>
            <span className="text-red-400">81–100: 重大リスク</span>
          </div>
        </div>
      )}

      {/* ── Loading ── */}
      {isLoading && (
        <div className="flex justify-center items-center py-20">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" />
          <span className="ml-3 text-gray-400 text-sm">データを読み込み中...</span>
        </div>
      )}

      {!isLoading && (
        <>
          {/* ── Top row: Gauge + Breakdown ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Overall Gauge */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
              <h2 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
                <Shield className="w-4 h-4 text-red-400" />
                組織全体リスクスコア
              </h2>
              <p className="text-xs text-gray-500 mb-4">現在のオープンアラートに基づいて算出</p>
              <div className="flex flex-col items-center gap-3">
                <RiskGauge score={orgRiskScore} />
                <div className="grid grid-cols-2 gap-3 w-full text-center text-xs">
                  <div className="bg-gray-900 rounded-lg p-2 border border-gray-700">
                    <p className="text-red-300 font-bold text-lg">{alertCounts.critical}</p>
                    <p className="text-gray-500">クリティカル</p>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-2 border border-gray-700">
                    <p className="text-orange-300 font-bold text-lg">{alertCounts.high}</p>
                    <p className="text-gray-500">高</p>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-2 border border-gray-700">
                    <p className="text-yellow-300 font-bold text-lg">{alertCounts.medium}</p>
                    <p className="text-gray-500">中</p>
                  </div>
                  <div className="bg-gray-900 rounded-lg p-2 border border-gray-700">
                    <p className="text-blue-300 font-bold text-lg">{alertCounts.low}</p>
                    <p className="text-gray-500">低</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Risk Breakdown by Category */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
              <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                カテゴリ別リスク内訳
              </h2>
              <div className="space-y-5">
                <BreakdownBar
                  label="エンドポイントリスク"
                  score={endpointRisk}
                  description={`オフライン: ${offlineAgents}件 / 警告: ${warningAgents}件`}
                />
                <BreakdownBar
                  label="アラートリスク"
                  score={alertRisk}
                  description={`クリティカル: ${alertCounts.critical}件 / 高: ${alertCounts.high}件`}
                />
                <BreakdownBar
                  label="コンプライアンスリスク"
                  score={complianceRisk}
                  description={
                    complianceScore !== null
                      ? `コンプライアンススコア: ${complianceScore}%`
                      : complianceViolations > 0
                      ? `違反: ${complianceViolations}件`
                      : 'データなし'
                  }
                />
                <BreakdownBar
                  label="脅威インテリジェンスリスク"
                  score={threatIntelRisk}
                  description={`IOCマッチ: ${iocMatches}件`}
                />
              </div>
            </div>
          </div>

          {/* ── Risk Trend Chart ── */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
            <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-red-400" />
              リスクスコアトレンド（過去30日）
            </h2>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis
                  dataKey="date"
                  tick={{ fill: '#9CA3AF', fontSize: 10 }}
                  interval={4}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: '#9CA3AF', fontSize: 10 }}
                />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  labelStyle={{ color: '#fff' }}
                  formatter={(value) => [`${value}`, 'リスクスコア']}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, fill: '#ef4444' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* ── Bottom row: Top Risk Agents + Risk Factors ── */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

            {/* Top At-Risk Agents */}
            <div className="xl:col-span-2 bg-gray-800 rounded-xl border border-gray-700 p-5">
              <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Server className="w-4 h-4 text-blue-400" />
                リスク上位エージェント（Top 10）
              </h2>
              {topRiskAgents.length === 0 ? (
                <p className="text-gray-500 text-sm text-center py-8">エージェントデータなし</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-700 text-gray-500 text-xs">
                        <th className="pb-2 pr-3 text-left font-medium w-8">順</th>
                        <th className="pb-2 pr-3 text-left font-medium">ホスト名</th>
                        <th className="pb-2 pr-3 text-left font-medium w-36">リスクスコア</th>
                        <th className="pb-2 pr-3 text-left font-medium">アラート</th>
                        <th className="pb-2 pr-3 text-left font-medium">ステータス</th>
                        <th className="pb-2 pr-3 text-left font-medium">最終通信</th>
                        <th className="pb-2 text-left font-medium"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {topRiskAgents.map((agent, i) => {
                        const statusStyle =
                          agent.status === 'online'
                            ? 'bg-green-900/40 text-green-300'
                            : agent.status === 'offline'
                            ? 'bg-red-900/40 text-red-300'
                            : agent.status === 'warning'
                            ? 'bg-yellow-900/40 text-yellow-300'
                            : 'bg-gray-700 text-gray-400'
                        return (
                          <tr
                            key={agent.id}
                            className="border-b border-gray-700 last:border-0 hover:bg-gray-700/30 transition-colors"
                          >
                            <td className="py-2.5 pr-3 text-gray-500 text-xs font-mono">
                              {i + 1}
                            </td>
                            <td className="py-2.5 pr-3 text-white text-xs font-medium">
                              {agent.hostname}
                            </td>
                            <td className="py-2.5 pr-3">
                              <div className="flex items-center gap-2">
                                <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${riskTailwindBg(agent.computedRisk)}`}
                                    style={{ width: `${agent.computedRisk}%` }}
                                  />
                                </div>
                                <span className={`text-xs font-bold w-8 text-right ${riskTailwindText(agent.computedRisk)}`}>
                                  {agent.computedRisk}
                                </span>
                              </div>
                            </td>
                            <td className="py-2.5 pr-3">
                              <span className={`text-xs font-medium ${agent.openAlerts > 0 ? 'text-orange-300' : 'text-gray-500'}`}>
                                {agent.openAlerts}
                              </span>
                            </td>
                            <td className="py-2.5 pr-3">
                              <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${statusStyle}`}>
                                {agent.status ?? '—'}
                              </span>
                            </td>
                            <td className="py-2.5 pr-3 text-gray-400 text-xs whitespace-nowrap">
                              {formatLastSeen(agent.last_seen)}
                            </td>
                            <td className="py-2.5">
                              <Link
                                href={`/agents/${agent.id}`}
                                className="flex items-center gap-0.5 text-blue-400 hover:text-blue-300 text-xs transition-colors whitespace-nowrap"
                              >
                                詳細
                                <ChevronRight className="w-3 h-3" />
                              </Link>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Risk Factors Card */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
              <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                リスク要因
              </h2>
              <div className="space-y-3">
                {riskFactors.map((factor, i) => (
                  <div
                    key={i}
                    className={`flex items-start gap-3 p-3 rounded-lg border ${impactStyle[factor.impact]}`}
                  >
                    <div className="flex-1 text-xs leading-snug">{factor.label}</div>
                    <span className={`shrink-0 text-xs px-1.5 py-0.5 rounded-sm border ${impactStyle[factor.impact]}`}>
                      {impactLabel[factor.impact]}
                    </span>
                  </div>
                ))}
              </div>
              <div className="mt-5 pt-4 border-t border-gray-700 space-y-2">
                <p className="text-xs text-gray-500">凡例</p>
                <div className="flex flex-col gap-1.5 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500 shrink-0" />
                    <span className="text-gray-400">重大 — 即時対応が必要</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-orange-500 shrink-0" />
                    <span className="text-gray-400">高 — 早急な対応を推奨</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 shrink-0" />
                    <span className="text-gray-400">中 — 計画的な対応</span>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </>
      )}
    </div>
  )
}
