'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { USE_MOCK } from '@/lib/mock'
import {
  TrendingUp, TrendingDown, Calendar, Download, AlertTriangle,
  CheckCircle2, Clock, Target, BarChart2, Filter, ChevronDown,
  ExternalLink, Minus,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type Period = '30d' | '90d' | '180d'
type Severity = 'critical' | 'high' | 'medium' | 'low'

interface MonthlyData {
  month: string
  new_vulns: number
  remediated: number
}

interface SeverityMonth {
  month: string
  critical: number
  high: number
  medium: number
  low: number
}

interface CvssHistogram {
  range: string
  count: number
}

interface TopCVE {
  cve_id: string
  name: string
  affected_assets: number
  cvss_score: number
  first_seen: string
  remediated_count: number
  status: 'open' | 'in_progress' | 'remediated'
}

interface AssetRisk {
  hostname: string
  total_score: number
  trend: 'better' | 'worse' | 'stable'
  vuln_count: number
}

interface AgeBucket {
  label: string
  count: number
}

interface RemVelocity {
  severity: Severity
  avg_days: number
  sla_days: number
}

interface TrendData {
  kpi: { new_vulns: number; remediated: number; mttr_days: number; sla_compliance: number }
  monthly: MonthlyData[]
  severity_monthly: SeverityMonth[]
  cvss_histogram: CvssHistogram[]
  top_cves: TopCVE[]
  asset_risks: AssetRisk[]
  age_buckets: AgeBucket[]
  rem_velocity: RemVelocity[]
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const MONTHS_6 = ['2025-10', '2025-11', '2025-12', '2026-01', '2026-02', '2026-03']
const MONTHS_3 = MONTHS_6.slice(3)
const MONTHS_1 = MONTHS_6.slice(5)

function makeMockData(period: Period): TrendData {
  const months = period === '30d' ? MONTHS_1 : period === '90d' ? MONTHS_3 : MONTHS_6
  return {
    kpi: {
      new_vulns: period === '30d' ? 47 : period === '90d' ? 134 : 312,
      remediated: period === '30d' ? 38 : period === '90d' ? 109 : 278,
      mttr_days: period === '30d' ? 12.4 : period === '90d' ? 14.7 : 16.2,
      sla_compliance: period === '30d' ? 84.6 : period === '90d' ? 79.3 : 73.1,
    },
    monthly: months.map((m, i) => ({
      month: m,
      new_vulns: [52, 48, 41, 47, 38, 47][i + (6 - months.length)],
      remediated: [35, 42, 38, 44, 41, 38][i + (6 - months.length)],
    })),
    severity_monthly: months.map((m, i) => ({
      month: m,
      critical: [8, 5, 7, 6, 4, 5][i + (6 - months.length)],
      high: [14, 12, 10, 13, 11, 14][i + (6 - months.length)],
      medium: [20, 22, 18, 20, 16, 20][i + (6 - months.length)],
      low: [10, 9, 6, 8, 7, 8][i + (6 - months.length)],
    })),
    cvss_histogram: [
      { range: '0.1-1.0', count: 3 },
      { range: '1.1-2.0', count: 5 },
      { range: '2.1-3.0', count: 8 },
      { range: '3.1-4.0', count: 14 },
      { range: '4.1-5.0', count: 22 },
      { range: '5.1-6.0', count: 31 },
      { range: '6.1-7.0', count: 28 },
      { range: '7.1-8.0', count: 19 },
      { range: '8.1-9.0', count: 11 },
      { range: '9.1-10.0', count: 7 },
    ],
    top_cves: [
      { cve_id: 'CVE-2021-44228', name: 'Log4Shell (Apache Log4j2 RCE)', affected_assets: 23, cvss_score: 10.0, first_seen: '2025-12-10', remediated_count: 18, status: 'in_progress' },
      { cve_id: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset Attack', affected_assets: 15, cvss_score: 7.5, first_seen: '2025-10-11', remediated_count: 12, status: 'in_progress' },
      { cve_id: 'CVE-2024-21762', name: 'Fortinet FortiOS SSL VPN RCE', affected_assets: 8, cvss_score: 9.8, first_seen: '2026-01-08', remediated_count: 5, status: 'open' },
      { cve_id: 'CVE-2023-23397', name: 'Microsoft Outlook Privilege Escalation', affected_assets: 34, cvss_score: 9.8, first_seen: '2025-11-14', remediated_count: 30, status: 'in_progress' },
      { cve_id: 'CVE-2024-3400', name: 'PAN-OS GlobalProtect Command Injection', affected_assets: 4, cvss_score: 10.0, first_seen: '2026-02-12', remediated_count: 2, status: 'open' },
      { cve_id: 'CVE-2023-34362', name: 'MOVEit Transfer SQL Injection', affected_assets: 7, cvss_score: 9.8, first_seen: '2025-10-05', remediated_count: 7, status: 'remediated' },
      { cve_id: 'CVE-2024-1709', name: 'ConnectWise ScreenConnect Auth Bypass', affected_assets: 11, cvss_score: 10.0, first_seen: '2026-01-20', remediated_count: 8, status: 'in_progress' },
      { cve_id: 'CVE-2023-48795', name: 'Terrapin SSH Protocol Downgrade', affected_assets: 19, cvss_score: 5.9, first_seen: '2025-12-18', remediated_count: 14, status: 'in_progress' },
      { cve_id: 'CVE-2024-23897', name: 'Jenkins CLI Path Traversal / RCE', affected_assets: 6, cvss_score: 9.8, first_seen: '2026-01-24', remediated_count: 3, status: 'open' },
      { cve_id: 'CVE-2023-29357', name: 'Microsoft SharePoint Privilege Escalation', affected_assets: 12, cvss_score: 9.8, first_seen: '2025-11-20', remediated_count: 12, status: 'remediated' },
    ],
    asset_risks: [
      { hostname: 'srv-prod-01', total_score: 94.2, trend: 'worse', vuln_count: 12 },
      { hostname: 'srv-prod-02', total_score: 87.5, trend: 'stable', vuln_count: 9 },
      { hostname: 'WIN-DC01', total_score: 82.1, trend: 'better', vuln_count: 7 },
      { hostname: 'web-front-03', total_score: 78.8, trend: 'worse', vuln_count: 15 },
      { hostname: 'db-mysql-01', total_score: 71.3, trend: 'better', vuln_count: 6 },
      { hostname: 'vpn-gateway-01', total_score: 68.9, trend: 'stable', vuln_count: 4 },
      { hostname: 'k8s-node-01', total_score: 64.4, trend: 'better', vuln_count: 8 },
      { hostname: 'mail-srv-01', total_score: 58.7, trend: 'worse', vuln_count: 11 },
      { hostname: 'devops-jenkins', total_score: 52.1, trend: 'stable', vuln_count: 5 },
      { hostname: 'nas-backup-01', total_score: 44.6, trend: 'better', vuln_count: 3 },
    ],
    age_buckets: [
      { label: '0-7日', count: 24 },
      { label: '8-30日', count: 58 },
      { label: '31-90日', count: 87 },
      { label: '90日以上', count: 43 },
    ],
    rem_velocity: [
      { severity: 'critical', avg_days: 4.2, sla_days: 3 },
      { severity: 'high', avg_days: 11.8, sla_days: 7 },
      { severity: 'medium', avg_days: 28.4, sla_days: 30 },
      { severity: 'low', avg_days: 72.1, sla_days: 90 },
    ],
  }
}

function makeEmptyData(period: Period): TrendData {
  const months = period === '30d' ? MONTHS_1 : period === '90d' ? MONTHS_3 : MONTHS_6
  return {
    kpi: { new_vulns: 0, remediated: 0, mttr_days: 0, sla_compliance: 0 },
    monthly: months.map(m => ({ month: m, new_vulns: 0, remediated: 0 })),
    severity_monthly: months.map(m => ({ month: m, critical: 0, high: 0, medium: 0, low: 0 })),
    cvss_histogram: [],
    top_cves: [],
    asset_risks: [],
    age_buckets: [],
    rem_velocity: [],
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityColor(s: Severity): string {
  return s === 'critical' ? 'text-red-400' : s === 'high' ? 'text-orange-400' : s === 'medium' ? 'text-yellow-400' : 'text-blue-400'
}

function severityBg(s: Severity): string {
  return s === 'critical' ? 'bg-red-500' : s === 'high' ? 'bg-orange-500' : s === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
}

function statusBadge(status: TopCVE['status']) {
  if (status === 'open') return 'bg-red-500/10 border-red-500/30 text-red-400'
  if (status === 'in_progress') return 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
  return 'bg-green-500/10 border-green-500/30 text-green-400'
}

function statusLabel(status: TopCVE['status']) {
  return status === 'open' ? '未対応' : status === 'in_progress' ? '対応中' : '修正済'
}

function cvssColor(score: number) {
  if (score >= 9) return 'text-red-400'
  if (score >= 7) return 'text-orange-400'
  if (score >= 4) return 'text-yellow-400'
  return 'text-green-400'
}

function trendIcon(trend: AssetRisk['trend']) {
  if (trend === 'worse') return <TrendingUp className="w-3.5 h-3.5 text-red-400" />
  if (trend === 'better') return <TrendingDown className="w-3.5 h-3.5 text-green-400" />
  return <Minus className="w-3.5 h-3.5 text-falcon-muted" />
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function VulnerabilityTrendsPage() {
  const [period, setPeriod] = useState<Period>('90d')
  const [customFrom, setCustomFrom] = useState('')
  const [customTo, setCustomTo] = useState('')
  const [showCustom, setShowCustom] = useState(false)

  const { data: apiData } = useQuery<TrendData>({
    queryKey: ['vuln-trends', period],
    queryFn: () => apiFetch(`/api/v1/vulnerabilities/trends?period=${period}`),
    retry: false,
  })

  const data: TrendData = useMemo(() => apiData ?? (USE_MOCK ? makeMockData(period) : makeEmptyData(period)), [apiData, period])

  // 30-day daily mock data
  const daily30 = useMemo(() => {
    if (period !== '30d') return []
    return Array.from({ length: 30 }, (_, i) => {
      const d = new Date()
      d.setDate(d.getDate() - (29 - i))
      return {
        date: d.toISOString().slice(5, 10), // MM-DD
        new_vulns: Math.floor(Math.random() * 8) + 1,
        remediated: Math.floor(Math.random() * 6) + 1,
      }
    })
  }, [period])

  const maxDaily = daily30.length > 0 ? Math.max(...daily30.map(d => Math.max(d.new_vulns, d.remediated))) : 1
  const maxMonthly = Math.max(...data.monthly.map(m => Math.max(m.new_vulns, m.remediated)))
  const maxCvss = Math.max(...data.cvss_histogram.map(h => h.count))
  const maxAge = Math.max(...data.age_buckets.map(b => b.count))

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-muted">
      {/* ── Header ─────────────────────────────────────────── */}
      <div className="border-b border-falcon-border px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-falcon-red/10 border border-falcon-red/20 flex items-center justify-center">
              <TrendingUp className="w-5 h-5 text-falcon-red" />
            </div>
            <div>
              <h1 className="text-white text-xl font-bold tracking-tight">脆弱性トレンド分析</h1>
              <p className="text-xs text-falcon-muted mt-0.5">期間別の脆弱性推移・修正状況を分析</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Period selector */}
            <div className="flex items-center gap-1 bg-falcon-surface border border-falcon-border rounded-lg p-1">
              {(['30d', '90d', '180d'] as Period[]).map(p => (
                <button
                  key={p}
                  onClick={() => { setPeriod(p); setShowCustom(false) }}
                  className={`px-3 py-1.5 rounded-sm text-xs font-medium transition-colors ${period === p && !showCustom ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}
                >
                  {p === '30d' ? '30日' : p === '90d' ? '90日' : '180日'}
                </button>
              ))}
              <button
                onClick={() => setShowCustom(!showCustom)}
                className={`flex items-center gap-1 px-3 py-1.5 rounded-sm text-xs transition-colors ${showCustom ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}
              >
                <Calendar className="w-3 h-3" />
                カスタム
              </button>
            </div>
            <button
              onClick={() => {
                const blob = new Blob(
                  [JSON.stringify({ period, generated_at: new Date().toISOString(), ...data }, null, 2)],
                  { type: 'application/json' }
                )
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = `vuln-trends-${period}-${new Date().toISOString().slice(0, 10)}.json`
                a.click()
                URL.revokeObjectURL(url)
              }}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-surface border border-falcon-border text-xs text-falcon-muted hover:text-white transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              JSONエクスポート
            </button>
          </div>
        </div>
        {showCustom && (
          <div className="flex items-center gap-3 mt-3">
            <label className="text-xs text-falcon-muted">開始日</label>
            <input type="date" value={customFrom} onChange={e => setCustomFrom(e.target.value)}
              className="px-3 py-1.5 text-xs bg-falcon-surface border border-falcon-border rounded-sm text-white focus:outline-hidden focus:border-falcon-muted" />
            <label className="text-xs text-falcon-muted">終了日</label>
            <input type="date" value={customTo} onChange={e => setCustomTo(e.target.value)}
              className="px-3 py-1.5 text-xs bg-falcon-surface border border-falcon-border rounded-sm text-white focus:outline-hidden focus:border-falcon-muted" />
            <button className="px-3 py-1.5 text-xs bg-falcon-red text-white rounded-sm hover:bg-[#c0001f] transition-colors">適用</button>
          </div>
        )}
      </div>

      <div className="p-6 space-y-6">
        {/* ── KPI Row ──────────────────────────────────────── */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: '新規脆弱性', value: data.kpi.new_vulns, unit: '件', icon: AlertTriangle, color: 'text-falcon-red', trend: 'up' },
            { label: '修正済み', value: data.kpi.remediated, unit: '件', icon: CheckCircle2, color: 'text-green-400', trend: 'down' },
            { label: 'MTTR', value: data.kpi.mttr_days.toFixed(1), unit: '日', icon: Clock, color: 'text-orange-400', trend: 'up' },
            { label: 'SLAコンプライアンス', value: data.kpi.sla_compliance.toFixed(1), unit: '%', icon: Target, color: 'text-blue-400', trend: 'stable' },
          ].map(({ label, value, unit, icon: Icon, color }) => (
            <div key={label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-4 h-4 ${color}`} />
                <span className="text-xs text-falcon-muted">{label}</span>
              </div>
              <p className={`text-2xl font-bold ${color} font-mono`}>
                {value}<span className="text-sm ml-1 opacity-70">{unit}</span>
              </p>
            </div>
          ))}
        </div>

        {/* ── 30-day Daily Chart (only for 30d period) ─────── */}
        {period === '30d' && daily30.length > 0 && (
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-1 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-falcon-red" />
              30日間 日次CVEトレンド
            </h2>
            <p className="text-[10px] text-falcon-subtle mb-4">過去30日間の日次脆弱性検出・修正推移</p>
            <div className="flex items-end gap-0.5 h-28 overflow-hidden">
              {daily30.map((d, idx) => {
                const newH = Math.round((d.new_vulns / maxDaily) * 100)
                const remH = Math.round((d.remediated / maxDaily) * 100)
                const showLabel = idx % 5 === 0 || idx === 29
                return (
                  <div key={d.date} className="flex-1 flex flex-col items-center gap-0" style={{ minWidth: 0 }}>
                    <div className="flex items-end gap-px w-full h-24">
                      <div
                        className="flex-1 rounded-t bg-falcon-red/60 hover:bg-falcon-red transition-colors"
                        style={{ height: `${newH}%`, minHeight: d.new_vulns > 0 ? '2px' : '0' }}
                        title={`${d.date} 新規: ${d.new_vulns}`}
                      />
                      <div
                        className="flex-1 rounded-t bg-green-500/60 hover:bg-green-500 transition-colors"
                        style={{ height: `${remH}%`, minHeight: d.remediated > 0 ? '2px' : '0' }}
                        title={`${d.date} 修正: ${d.remediated}`}
                      />
                    </div>
                    <span className="text-[8px] text-falcon-subtle mt-0.5 leading-none" style={{ opacity: showLabel ? 1 : 0 }}>
                      {d.date}
                    </span>
                  </div>
                )
              })}
            </div>
            <div className="flex items-center gap-4 mt-2">
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-xs bg-falcon-red/60" /><span className="text-xs text-falcon-muted">新規</span></div>
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-xs bg-green-500/60" /><span className="text-xs text-falcon-muted">修正済</span></div>
            </div>
          </div>
        )}

        {/* ── Monthly Bar Chart ────────────────────────────── */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h2 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-falcon-red" />
            月別 新規 vs 修正
          </h2>
          <div className="flex items-end gap-4 h-40">
            {data.monthly.map(m => {
              const newH = Math.round((m.new_vulns / maxMonthly) * 100)
              const remH = Math.round((m.remediated / maxMonthly) * 100)
              return (
                <div key={m.month} className="flex-1 flex flex-col items-center gap-1">
                  <div className="flex items-end gap-1 w-full h-32">
                    <div className="flex-1 flex items-end justify-center">
                      <div
                        className="w-full rounded-t bg-falcon-red/70 hover:bg-falcon-red transition-colors relative group"
                        style={{ height: `${newH}%`, minHeight: '4px' }}
                      >
                        <span className="absolute -top-5 left-1/2 -translate-x-1/2 text-[10px] text-falcon-red opacity-0 group-hover:opacity-100 whitespace-nowrap">{m.new_vulns}</span>
                      </div>
                    </div>
                    <div className="flex-1 flex items-end justify-center">
                      <div
                        className="w-full rounded-t bg-green-500/70 hover:bg-green-500 transition-colors relative group"
                        style={{ height: `${remH}%`, minHeight: '4px' }}
                      >
                        <span className="absolute -top-5 left-1/2 -translate-x-1/2 text-[10px] text-green-400 opacity-0 group-hover:opacity-100 whitespace-nowrap">{m.remediated}</span>
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] text-falcon-subtle">{m.month.slice(5)}</span>
                </div>
              )
            })}
          </div>
          <div className="flex items-center gap-4 mt-2">
            <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-xs bg-falcon-red/70" /><span className="text-xs text-falcon-muted">新規</span></div>
            <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-xs bg-green-500/70" /><span className="text-xs text-falcon-muted">修正済</span></div>
          </div>
        </div>

        {/* ── Severity Distribution & CVSS Histogram ──────── */}
        <div className="grid grid-cols-2 gap-4">
          {/* Severity over time (stacked area approximation) */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-4">深刻度別 月次分布</h2>
            <div className="space-y-2">
              {data.severity_monthly.map(sm => {
                const total = sm.critical + sm.high + sm.medium + sm.low
                const critW = Math.round((sm.critical / total) * 100)
                const highW = Math.round((sm.high / total) * 100)
                const medW = Math.round((sm.medium / total) * 100)
                const lowW = 100 - critW - highW - medW
                return (
                  <div key={sm.month} className="flex items-center gap-2">
                    <span className="text-[10px] text-falcon-subtle w-10">{sm.month.slice(5)}</span>
                    <div className="flex-1 flex h-5 rounded-sm overflow-hidden gap-0.5">
                      <div className="bg-red-500/80 transition-all" style={{ width: `${critW}%` }} title={`Critical: ${sm.critical}`} />
                      <div className="bg-orange-500/80 transition-all" style={{ width: `${highW}%` }} title={`High: ${sm.high}`} />
                      <div className="bg-yellow-500/80 transition-all" style={{ width: `${medW}%` }} title={`Medium: ${sm.medium}`} />
                      <div className="bg-blue-500/80 transition-all" style={{ width: `${lowW}%` }} title={`Low: ${sm.low}`} />
                    </div>
                    <span className="text-[10px] text-falcon-subtle w-6 text-right">{total}</span>
                  </div>
                )
              })}
            </div>
            <div className="flex items-center gap-3 mt-3">
              {([['Critical', 'bg-red-500/80'], ['High', 'bg-orange-500/80'], ['Medium', 'bg-yellow-500/80'], ['Low', 'bg-blue-500/80']] as [string, string][]).map(([label, cls]) => (
                <div key={label} className="flex items-center gap-1"><div className={`w-2.5 h-2.5 rounded-xs ${cls}`} /><span className="text-[10px] text-falcon-muted">{label}</span></div>
              ))}
            </div>
          </div>

          {/* CVSS Histogram */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-4">CVSSスコア分布</h2>
            <div className="flex items-end gap-1 h-32">
              {data.cvss_histogram.map(bucket => {
                const h = Math.round((bucket.count / maxCvss) * 100)
                const score = parseFloat(bucket.range.split('-')[0])
                const color = score >= 9 ? 'bg-red-500/80 hover:bg-red-500' : score >= 7 ? 'bg-orange-500/80 hover:bg-orange-500' : score >= 4 ? 'bg-yellow-500/80 hover:bg-yellow-500' : 'bg-blue-500/80 hover:bg-blue-500'
                return (
                  <div key={bucket.range} className="flex-1 flex flex-col items-center gap-1">
                    <div
                      className={`w-full rounded-t ${color} transition-colors relative group`}
                      style={{ height: `${h}%`, minHeight: '4px' }}
                    >
                      <span className="absolute -top-5 left-1/2 -translate-x-1/2 text-[10px] text-white opacity-0 group-hover:opacity-100 whitespace-nowrap">{bucket.count}</span>
                    </div>
                  </div>
                )
              })}
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-[9px] text-falcon-subtle">0.1</span>
              <span className="text-[9px] text-falcon-subtle">10.0</span>
            </div>
            <p className="text-[10px] text-falcon-subtle mt-1">CVSSスコア範囲</p>
          </div>
        </div>

        {/* ── Top 10 CVEs ──────────────────────────────────── */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-falcon-border">
            <h2 className="text-white font-semibold text-sm">最多検出 CVE Top 10</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['CVE ID', '名称', '影響資産', 'CVSSスコア', '初検出日', '修正数', 'ステータス'].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left text-falcon-subtle font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border/50">
                {data.top_cves.map(cve => (
                  <tr key={cve.cve_id} className="hover:bg-[#0a1628] transition-colors">
                    <td className="px-3 py-2.5">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-blue-400 hover:text-blue-300 font-mono"
                      >
                        {cve.cve_id}
                        <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                      </a>
                    </td>
                    <td className="px-3 py-2.5 text-falcon-muted max-w-[200px] truncate" title={cve.name}>{cve.name}</td>
                    <td className="px-3 py-2.5 text-center">
                      <span className="font-bold text-white">{cve.affected_assets}</span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`font-bold font-mono ${cvssColor(cve.cvss_score)}`}>{cve.cvss_score.toFixed(1)}</span>
                    </td>
                    <td className="px-3 py-2.5 text-falcon-subtle font-mono whitespace-nowrap">{cve.first_seen}</td>
                    <td className="px-3 py-2.5 text-center">
                      <span className="text-green-400 font-mono">{cve.remediated_count}</span>
                      <span className="text-falcon-subtle"> / {cve.affected_assets}</span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-2 py-0.5 rounded-sm border text-[10px] font-medium ${statusBadge(cve.status)}`}>{statusLabel(cve.status)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Asset Risk Trends & Age Analysis ─────────────── */}
        <div className="grid grid-cols-2 gap-4">
          {/* Asset risk trends */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-falcon-border">
              <h2 className="text-white font-semibold text-sm">エンドポイントリスクトレンド</h2>
            </div>
            <div className="divide-y divide-falcon-border/50">
              {data.asset_risks.map((asset, idx) => (
                <div key={asset.hostname} className="flex items-center gap-3 px-4 py-2.5 hover:bg-[#0a1628] transition-colors">
                  <span className="text-falcon-subtle text-xs w-4">{idx + 1}</span>
                  <span className="font-mono text-white text-xs flex-1 truncate">{asset.hostname}</span>
                  <div className="flex items-center gap-1 w-32">
                    <div className="flex-1 h-1.5 bg-[#070d19] rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${asset.total_score >= 80 ? 'bg-red-500' : asset.total_score >= 60 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                        style={{ width: `${asset.total_score}%` }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-falcon-muted w-8 text-right">{asset.total_score.toFixed(0)}</span>
                  </div>
                  <span className="text-falcon-subtle text-[10px] w-8 text-right">{asset.vuln_count}件</span>
                  <div className="w-5 flex justify-end">{trendIcon(asset.trend)}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Age analysis */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-4">脆弱性経過日数分析</h2>
            <div className="space-y-3">
              {data.age_buckets.map(bucket => {
                const pct = Math.round((bucket.count / maxAge) * 100)
                const colors = ['bg-green-500', 'bg-yellow-500', 'bg-orange-500', 'bg-red-500']
                const idx = data.age_buckets.indexOf(bucket)
                return (
                  <div key={bucket.label} className="flex items-center gap-3">
                    <span className="text-xs text-falcon-muted w-16">{bucket.label}</span>
                    <div className="flex-1 h-6 bg-[#070d19] rounded-sm overflow-hidden relative">
                      <div
                        className={`h-full ${colors[idx]} transition-all rounded-sm`}
                        style={{ width: `${pct}%` }}
                      />
                      <span className="absolute left-2 top-1/2 -translate-y-1/2 text-[10px] text-white font-bold mix-blend-difference">{bucket.count}件</span>
                    </div>
                    <span className="text-xs text-falcon-subtle w-6 text-right">{pct}%</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* ── Remediation Velocity ─────────────────────────── */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h2 className="text-white font-semibold text-sm mb-4">修正速度 vs SLA目標</h2>
          <div className="grid grid-cols-4 gap-4">
            {data.rem_velocity.map(rv => {
              const pct = Math.min(Math.round((rv.avg_days / (rv.sla_days * 1.5)) * 100), 100)
              const slaPct = Math.min(Math.round((rv.sla_days / (rv.sla_days * 1.5)) * 100), 100)
              const overSla = rv.avg_days > rv.sla_days
              return (
                <div key={rv.severity} className="bg-[#070d19] rounded-xl p-4 border border-falcon-border">
                  <div className="flex items-center justify-between mb-3">
                    <span className={`text-xs font-bold uppercase ${severityColor(rv.severity)}`}>{rv.severity}</span>
                    {overSla
                      ? <span className="text-[10px] text-red-400 flex items-center gap-0.5"><AlertTriangle className="w-3 h-3" /> SLA超過</span>
                      : <span className="text-[10px] text-green-400 flex items-center gap-0.5"><CheckCircle2 className="w-3 h-3" /> SLA達成</span>
                    }
                  </div>
                  <p className={`text-xl font-bold font-mono mb-1 ${overSla ? 'text-red-400' : 'text-green-400'}`}>
                    {rv.avg_days.toFixed(1)}<span className="text-xs text-falcon-subtle ml-1">日</span>
                  </p>
                  <p className="text-[10px] text-falcon-subtle mb-3">SLA目標: {rv.sla_days}日</p>
                  <div className="relative h-3 bg-falcon-surface rounded-full overflow-hidden">
                    <div
                      className={`absolute top-0 left-0 h-full rounded-full ${severityBg(rv.severity)} opacity-80`}
                      style={{ width: `${pct}%` }}
                    />
                    <div
                      className="absolute top-0 h-full w-0.5 bg-white/50"
                      style={{ left: `${slaPct}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
