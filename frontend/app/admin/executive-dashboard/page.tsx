'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { useRouter } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  BarChart2, Shield, AlertTriangle, Clock, Users,
  Activity, TrendingUp, Download, RefreshCw, CheckCircle,
  ChevronRight, Zap,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface AgentStats {
  total: number
  online: number
  offline: number
}

interface DetectionStats {
  total_detections: number
  resolution_rate: number
  avg_resolution_hours: number
  open_incidents: number
}

interface VulnStats {
  total: number
  critical: number
  high: number
  open: number
}

interface Alert {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  agent_hostname: string
  created_at: string
  status: string
}

interface ExecDashboardData {
  agentStats: AgentStats
  detectionStats: DetectionStats
  vulnStats: VulnStats
  recentAlerts: Alert[]
}

interface TrendPoint {
  date: string
  count: number
  critical: number
}

interface MITRETechnique {
  technique: string
  count: number
  max_severity: number
}

interface ComplianceFrameworkDetail {
  id: string
  name: string
  score: number
}

interface ComplianceSummaryResp {
  overall: number
  framework_details: ComplianceFrameworkDetail[]
  metrics?: {
    critical_vulns?: number
    total_agents?: number
    online_agents?: number
    open_critical?: number
    enabled_playbooks?: number
    total_playbooks?: number
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function securityScore(data: ExecDashboardData): number {
  const agentScore = (data.agentStats.online / Math.max(data.agentStats.total, 1)) * 25
  const resolutionScore = (data.detectionStats.resolution_rate / 100) * 25
  const vulnScore = Math.max(0, 25 - data.vulnStats.critical * 2 - data.vulnStats.high * 0.5)
  const slaScore = Math.max(0, 25 - data.detectionStats.open_incidents * 1.5)
  return Math.round(agentScore + resolutionScore + vulnScore + slaScore)
}

function scoreColor(score: number): string {
  if (score >= 80) return 'text-green-400'
  if (score >= 60) return 'text-yellow-400'
  return 'text-red-400'
}

function slaCompliance(data: ExecDashboardData): number {
  return Math.round(data.detectionStats.resolution_rate)
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

// Convert ISO date string "2026-04-03" → day-of-week label
function dateToDayLabel(dateStr: string): string {
  const days = ['日', '月', '火', '水', '木', '金', '土']
  const d = new Date(dateStr)
  return days[d.getDay()]
}

function severityToColor(maxSev: number): string {
  if (maxSev >= 9) return 'bg-red-500'
  if (maxSev >= 7) return 'bg-orange-500'
  if (maxSev >= 5) return 'bg-yellow-500'
  return 'bg-blue-500'
}

function buildRecommendations(
  vulnStats: VulnStats,
  agentStats: AgentStats,
  detectionStats: DetectionStats,
  compliance?: ComplianceSummaryResp,
): { priority: string; text: string; href: string }[] {
  const recs: { priority: string; text: string; href: string }[] = []

  if (vulnStats.critical > 0) {
    recs.push({
      priority: 'critical',
      text: `重大な脆弱性 ${vulnStats.critical} 件を優先的にパッチ適用してください`,
      href: '/software',
    })
  }
  const offline = agentStats.total - agentStats.online
  if (offline > 0) {
    recs.push({
      priority: offline > 10 ? 'high' : 'medium',
      text: `オフラインのエージェント ${offline} 台を確認・再登録してください`,
      href: '/endpoints',
    })
  }
  if (detectionStats.open_incidents > 0) {
    recs.push({
      priority: detectionStats.open_incidents > 5 ? 'high' : 'medium',
      text: `オープンなインシデント ${detectionStats.open_incidents} 件を確認・対応してください`,
      href: '/incidents',
    })
  }
  if (vulnStats.high > 0) {
    recs.push({
      priority: 'medium',
      text: `高深刻度の脆弱性 ${vulnStats.high} 件のリスク評価と対応計画を策定してください`,
      href: '/software',
    })
  }
  if (compliance) {
    const lowScoreFw = (compliance.framework_details ?? []).filter(fw => fw.score < 70)
    if (lowScoreFw.length > 0) {
      recs.push({
        priority: 'low',
        text: `コンプライアンス達成率が低いフレームワーク（${lowScoreFw.map(f => f.name).join('、')}）の改善に取り組んでください`,
        href: '/admin/security-scorecard',
      })
    }
  }
  return recs
}

// ─── Badge Components ─────────────────────────────────────────────────────────

function AlertSeverityBadge({ severity }: { severity: Alert['severity'] }) {
  const map = {
    critical: 'bg-red-900/50 text-red-300 border border-red-700/50',
    high: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
    medium: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
    low: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  }
  const labels = { critical: '重大', high: '高', medium: '中', low: '低' }
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium uppercase ${map[severity]}`}>
      {labels[severity]}
    </span>
  )
}

function AlertStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open: 'bg-red-900/30 text-red-300',
    in_progress: 'bg-blue-900/30 text-blue-300',
    resolved: 'bg-green-900/30 text-green-300',
  }
  const labels: Record<string, string> = { open: 'オープン', in_progress: '対応中', resolved: '解決済み' }
  const cls = map[status] ?? 'bg-falcon-border text-falcon-muted'
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium ${cls}`}>
      {labels[status] ?? status}
    </span>
  )
}

function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    critical: 'bg-red-900/40 text-red-300 border border-red-700/40',
    high: 'bg-orange-900/30 text-orange-300 border border-orange-700/30',
    medium: 'bg-yellow-900/30 text-yellow-300 border border-yellow-700/30',
    low: 'bg-blue-900/30 text-blue-300 border border-blue-700/30',
  }
  const labels: Record<string, string> = { critical: '重大', high: '高', medium: '中', low: '低' }
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[11px] font-semibold uppercase ${map[priority] ?? ''}`}>
      {labels[priority] ?? priority}
    </span>
  )
}

function SkeletonCard() {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 animate-pulse">
      <div className="h-3 bg-falcon-border rounded-sm w-24 mb-3" />
      <div className="h-10 bg-falcon-border rounded-sm w-16 mb-2" />
      <div className="h-2 bg-falcon-border rounded-sm w-20" />
    </div>
  )
}

// ─── Bar Chart (pure div) ─────────────────────────────────────────────────────

function RiskTrendChart({ data }: { data: { day: string; count: number }[] }) {
  const maxCount = Math.max(...data.map(d => d.count), 1)
  return (
    <div className="flex items-end gap-2 h-24">
      {data.map((item, i) => {
        const pct = (item.count / maxCount) * 100
        return (
          <div key={i} className="flex-1 flex flex-col items-center gap-1">
            <span className="text-[10px] text-falcon-muted">{item.count}</span>
            <div className="w-full flex items-end" style={{ height: 72 }}>
              <div
                className="w-full rounded-t bg-linear-to-t from-falcon-red to-[#ff3355] opacity-80 hover:opacity-100 transition-opacity"
                style={{ height: `${pct}%` }}
              />
            </div>
            <span className="text-[10px] text-falcon-muted">{item.day}</span>
          </div>
        )
      })}
    </div>
  )
}

// ─── Compliance Progress Bar ──────────────────────────────────────────────────

function ComplianceBar({ name, pct }: { name: string; pct: number }) {
  const color = pct >= 85 ? 'bg-green-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm text-white font-medium">{name}</span>
        <span className={`text-sm font-bold ${pct >= 85 ? 'text-green-400' : pct >= 70 ? 'text-yellow-400' : 'text-red-400'}`}>
          {pct}%
        </span>
      </div>
      <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ExecutiveDashboardPage() {
  const router = useRouter()
  const EMPTY_DATA: ExecDashboardData = {
    agentStats: { total: 0, online: 0, offline: 0 },
    detectionStats: { total_detections: 0, resolution_rate: 0, avg_resolution_hours: 0, open_incidents: 0 },
    vulnStats: { total: 0, critical: 0, high: 0, open: 0 },
    recentAlerts: [],
  }

  const { data, isLoading, dataUpdatedAt, refetch } = useQuery<ExecDashboardData>({
    queryKey: ['exec-dashboard'],
    queryFn: async () => {
      const EMPTY = EMPTY_DATA
      const [agentStats, detectionStats, vulnStats, alertsResp] = await Promise.all([
        apiFetch<AgentStats>('/api/v1/metrics/agent-stats').catch(() => EMPTY.agentStats),
        apiFetch<DetectionStats>('/api/v1/metrics/detection-stats').catch(() => EMPTY.detectionStats),
        apiFetch<VulnStats>('/api/v1/admin/vulnerabilities/stats').catch(() => EMPTY.vulnStats),
        apiFetch<{ data?: Alert[]; alerts?: Alert[] }>('/api/v1/alerts?severity=critical&limit=5').catch(() => ({ alerts: [] })),
      ])
      return {
        agentStats: (agentStats && 'online' in agentStats) ? agentStats as AgentStats : EMPTY.agentStats,
        detectionStats: (detectionStats && 'total_detections' in detectionStats) ? detectionStats as DetectionStats : EMPTY.detectionStats,
        vulnStats: (vulnStats && 'critical' in vulnStats) ? vulnStats as VulnStats : EMPTY.vulnStats,
        recentAlerts: (alertsResp as any)?.alerts ?? (alertsResp as any)?.data ?? [],
      }
    },
    retry: false,
    staleTime: 60_000,
  })

  const { data: trendResp } = useQuery<{ trend: TrendPoint[] }>({
    queryKey: ['exec-alert-trend'],
    queryFn: () => apiFetch<{ trend: TrendPoint[] }>('/api/v1/dashboard/alert-trend?days=7').catch(() => ({ trend: [] as TrendPoint[] })),
    staleTime: 60_000,
  })

  const { data: mitreResp } = useQuery<{ techniques: MITRETechnique[] }>({
    queryKey: ['exec-mitre-stats'],
    queryFn: () => apiFetch<{ techniques: MITRETechnique[] }>('/api/v1/alerts/mitre-stats').catch(() => ({ techniques: [] as MITRETechnique[] })),
    staleTime: 60_000,
  })

  const { data: complianceResp } = useQuery<ComplianceSummaryResp>({
    queryKey: ['exec-compliance-summary'],
    queryFn: () => apiFetch<ComplianceSummaryResp>('/api/v1/compliance/summary').catch(() => ({ overall: 0, framework_details: [] as ComplianceFrameworkDetail[] })),
    staleTime: 60_000,
  })

  const d = data ?? EMPTY_DATA
  const score = securityScore(d)
  const sla = slaCompliance(d)
  const lastUpdated = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
    : '—'

  // Trend data: convert API dates to day-of-week labels
  const trendData: { day: string; count: number }[] = (trendResp?.trend ?? []).map(p => ({
    day: dateToDayLabel(p.date),
    count: p.count,
  }))

  // Threat landscape from MITRE stats (top 3)
  const threatLandscape = (mitreResp?.techniques ?? []).slice(0, 3).map(t => ({
    name: t.technique,
    count: t.count,
    color: severityToColor(t.max_severity),
  }))

  // Compliance frameworks from real data
  const complianceFrameworks = (complianceResp?.framework_details ?? []).map(fw => ({
    name: fw.name,
    pct: fw.score,
  }))

  // Recommendations from real data
  const recommendations = buildRecommendations(d.vulnStats, d.agentStats, d.detectionStats, complianceResp)

  const KPI_CARDS = [
    {
      label: 'セキュリティスコア',
      value: isLoading ? '—' : String(score),
      sub: score >= 80 ? '良好な状態' : score >= 60 ? '要注意' : 'リスクあり',
      icon: Shield,
      color: isLoading ? 'text-falcon-muted' : scoreColor(score),
      bg: 'border-falcon-border',
    },
    {
      label: 'アクティブ脅威',
      value: isLoading ? '—' : String(d.detectionStats.open_incidents),
      sub: 'オープンインシデント',
      icon: AlertTriangle,
      color: d.detectionStats.open_incidents > 5 ? 'text-red-400' : 'text-orange-400',
      bg: 'border-orange-700/30 bg-orange-900/5',
    },
    {
      label: 'オープン脆弱性',
      value: isLoading ? '—' : String(d.vulnStats.open),
      sub: `重大 ${d.vulnStats.critical} 件`,
      icon: Zap,
      color: d.vulnStats.critical > 0 ? 'text-red-400' : 'text-yellow-400',
      bg: 'border-red-700/20',
    },
    {
      label: 'SLAコンプライアンス',
      value: isLoading ? '—' : `${sla}%`,
      sub: '解決率',
      icon: CheckCircle,
      color: sla >= 90 ? 'text-green-400' : sla >= 75 ? 'text-yellow-400' : 'text-red-400',
      bg: 'border-green-700/20',
    },
    {
      label: 'オンラインエージェント',
      value: isLoading ? '—' : `${d.agentStats.online}`,
      sub: `合計 ${d.agentStats.total} 台中`,
      icon: Users,
      color: 'text-blue-400',
      bg: 'border-blue-700/20',
    },
    {
      label: '平均対応時間',
      value: isLoading ? '—' : `${d.detectionStats.avg_resolution_hours}時間`,
      sub: '平均解決時間',
      icon: Clock,
      color: d.detectionStats.avg_resolution_hours <= 4 ? 'text-green-400' : 'text-yellow-400',
      bg: 'border-falcon-border',
    },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* ヘッダー */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <BarChart2 className="w-6 h-6 text-falcon-red" />
            エグゼクティブセキュリティダッシュボード
          </h1>
          <p className="text-falcon-muted text-sm mt-1">
            最終更新:{' '}
            <span className="text-white">{lastUpdated}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-2 bg-falcon-surface border border-falcon-border hover:border-[#2a3f5c] text-falcon-muted hover:text-white text-sm rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
          <button className="flex items-center gap-2 px-4 py-2 bg-falcon-border hover:bg-[#253650] text-white text-sm font-medium rounded-lg transition-colors border border-[#2a3f5c]">
            <Download className="w-4 h-4" />
            PDFエクスポート
          </button>
        </div>
      </div>

      {/* KPIカード — 3 + 3グリッド */}
      {isLoading ? (
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => <SkeletonCard key={i} />)}
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
          {KPI_CARDS.map(card => (
            <div key={card.label} className={`bg-falcon-surface border rounded-xl p-5 ${card.bg}`}>
              <div className="flex items-center justify-between mb-3">
                <p className="text-xs text-falcon-muted uppercase tracking-wider font-medium">{card.label}</p>
                <card.icon className={`w-5 h-5 ${card.color}`} />
              </div>
              <p className={`text-4xl font-black tracking-tight ${card.color}`}>{card.value}</p>
              <p className="text-xs text-falcon-muted mt-1">{card.sub}</p>
            </div>
          ))}
        </div>
      )}

      {/* 中段: リスクトレンド + 脅威ランドスケープ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* リスクトレンド */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-white font-semibold text-sm">リスクトレンド</h2>
              <p className="text-falcon-muted text-xs mt-0.5">日次アラート件数 — 過去7日間</p>
            </div>
            <TrendingUp className="w-4 h-4 text-falcon-muted" />
          </div>
          {trendData.length > 0 ? (
            <RiskTrendChart data={trendData} />
          ) : (
            <div className="flex items-center justify-center h-24 text-falcon-muted text-sm">
              データなし
            </div>
          )}
        </div>

        {/* 脅威ランドスケープ */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-white font-semibold text-sm">脅威ランドスケープ</h2>
              <p className="text-falcon-muted text-xs mt-0.5">MITREテクニック別アラート（過去30日）</p>
            </div>
            <Activity className="w-4 h-4 text-falcon-muted" />
          </div>
          <div className="grid grid-cols-1 gap-3">
            {threatLandscape.length > 0 ? (
              threatLandscape.map(threat => (
                <div key={threat.name} className="bg-[#070d19] border border-falcon-border rounded-lg p-4 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${threat.color}`} />
                    <span className="text-white text-sm font-medium">{threat.name}</span>
                  </div>
                  <span className="text-2xl font-bold text-white">{threat.count}</span>
                </div>
              ))
            ) : (
              <div className="flex items-center justify-center h-20 text-falcon-muted text-sm">
                MITREテクニックデータなし
              </div>
            )}
          </div>
        </div>
      </div>

      {/* コンプライアンスサマリー */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-white font-semibold text-sm">コンプライアンスサマリー</h2>
            <p className="text-falcon-muted text-xs mt-0.5">アクティブなコントロール全体のフレームワーク達成率</p>
          </div>
          <CheckCircle className="w-4 h-4 text-falcon-muted" />
        </div>
        {complianceFrameworks.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {complianceFrameworks.map(fw => (
              <ComplianceBar key={fw.name} name={fw.name} pct={fw.pct} />
            ))}
          </div>
        ) : (
          <div className="flex items-center justify-center h-16 text-falcon-muted text-sm">
            コンプライアンスデータを読み込み中...
          </div>
        )}
      </div>

      {/* 最近の高優先度アラート */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-falcon-border flex items-center justify-between">
          <div>
            <h2 className="text-white font-semibold text-sm">最近の高優先度アラート</h2>
            <p className="text-falcon-muted text-xs mt-0.5">直近の重大・高重大度アラート5件</p>
          </div>
          <Link
            href="/alerts"
            className="flex items-center gap-1 text-xs text-falcon-muted hover:text-white transition-colors"
          >
            すべて表示 <ChevronRight className="w-3.5 h-3.5" />
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border">
                {['タイトル', '重大度', 'エージェント', '時間', 'ステータス'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="animate-pulse border-b border-falcon-border">
                    {[260, 80, 100, 100, 80].map((w, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-3 bg-falcon-border rounded-sm" style={{ width: w }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : d.recentAlerts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-falcon-muted text-sm">
                    重大・高重大度のアラートはありません
                  </td>
                </tr>
              ) : d.recentAlerts.map(alert => (
                <tr key={alert.id} className="hover:bg-[#0a1428] transition-colors">
                  <td className="px-4 py-3 text-white max-w-[280px]">
                    <span className="block truncate" title={alert.title}>{alert.title}</span>
                  </td>
                  <td className="px-4 py-3">
                    <AlertSeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-4 py-3 text-falcon-muted text-xs font-mono whitespace-nowrap">{alert.agent_hostname}</td>
                  <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{formatDate(alert.created_at)}</td>
                  <td className="px-4 py-3">
                    <AlertStatusBadge status={alert.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 推奨事項 */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <h2 className="text-white font-semibold text-sm">推奨事項</h2>
          <span className="px-2 py-0.5 rounded-full bg-falcon-border text-falcon-muted text-[11px] font-medium">
            {recommendations.length} 件のアクション
          </span>
        </div>
        <div className="space-y-3">
          {recommendations.length === 0 ? (
            <div className="flex items-center justify-center h-16 text-falcon-muted text-sm">
              現在、対応が必要な推奨事項はありません
            </div>
          ) : recommendations.map((rec, idx) => (
            <a
              key={idx}
              href={rec.href}
              className="flex items-start gap-3 p-3.5 bg-[#070d19] border border-falcon-border rounded-lg hover:border-[#2a3f5c] hover:bg-[#0a1428] transition-colors cursor-pointer select-none no-underline"
            >
              <div className="shrink-0 mt-0.5">
                <PriorityBadge priority={rec.priority} />
              </div>
              <p className="text-falcon-muted text-sm leading-relaxed">{rec.text}</p>
              <ChevronRight className="w-4 h-4 text-[#4a6080] shrink-0 mt-0.5 ml-auto" />
            </a>
          ))}
        </div>
      </div>
    </div>
  )
}
