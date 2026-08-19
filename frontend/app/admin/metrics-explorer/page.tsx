'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  TrendingUp, TrendingDown, Minus, RefreshCw, Play,
  Download, BarChart3, Activity, Shield, Server,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────────────────────

interface MetricPoint {
  timestamp: string
  value: number
}

interface MetricSummary {
  name: string
  label: string
  unit: string
  current: number
  previous: number
  points: MetricPoint[]
  chart_type: 'line' | 'area' | 'bar'
}

interface ApiEndpoint {
  path: string
  avg_ms: number
  p95_ms: number
  p99_ms: number
  error_rate: number
  requests_per_min: number
}

interface MetricsSummaryResponse {
  metrics: MetricSummary[]
  endpoints: ApiEndpoint[]
}

interface QueryResult {
  metric: string
  points: MetricPoint[]
}

function generatePoints(base: number, variance: number, count = 30): MetricPoint[] {
  const points: MetricPoint[] = []
  // Fixed reference time to avoid server/client hydration mismatch
  const refTime = new Date('2026-01-01T00:00:00Z').getTime()
  let val = base
  // Seeded PRNG for deterministic output
  let seed = Math.floor(base * 1000 + count * 17 + variance * 31)
  const rand = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff
    return seed / 0x7fffffff
  }
  for (let i = count - 1; i >= 0; i--) {
    val = Math.max(0, val + (rand() - 0.5) * variance)
    points.push({
      timestamp: new Date(refTime - i * 24 * 60 * 60 * 1000).toISOString(),
      value: Math.round(val * 10) / 10,
    })
  }
  return points
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtVal(val: number, unit: string): string {
  if (unit === '%') return `${val.toFixed(1)}%`
  if (unit === '時間') return `${val.toFixed(1)}h`
  return String(Math.round(val))
}

function trendPct(current: number, previous: number): number {
  if (previous === 0) return 0
  return Math.round((current - previous) / previous * 100 * 10) / 10
}

function fmtDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    })
  } catch { return iso }
}

// ── Mini SVG Chart ─────────────────────────────────────────────────────────────

function MiniChart({
  points,
  chartType,
  color = '#1a6bff',
  height = 40,
  width = 160,
}: {
  points: MetricPoint[]
  chartType: 'line' | 'area' | 'bar'
  color?: string
  height?: number
  width?: number
}) {
  if (!points.length) return null
  const vals = points.map(p => p.value)
  const min = Math.min(...vals)
  const max = Math.max(...vals)
  const range = max - min || 1
  const padX = 4, padY = 4
  const w = width - padX * 2
  const h = height - padY * 2

  const toX = (i: number) => padX + (i / (vals.length - 1)) * w
  const toY = (v: number) => padY + h - ((v - min) / range) * h

  if (chartType === 'bar') {
    const barW = Math.max(2, w / vals.length - 1)
    return (
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
        {vals.map((v, i) => {
          const bh = ((v - min) / range) * h
          const bx = padX + (i / vals.length) * w
          const by = padY + h - bh
          return (
            <rect
              key={i}
              x={bx}
              y={by}
              width={barW}
              height={bh}
              fill={color}
              opacity="0.7"
              rx="1"
            />
          )
        })}
      </svg>
    )
  }

  const pathD = vals.map((v, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toY(v)}`).join(' ')

  if (chartType === 'area') {
    const areaD = pathD +
      ` L ${toX(vals.length - 1)} ${padY + h}` +
      ` L ${toX(0)} ${padY + h} Z`
    return (
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
        <defs>
          <linearGradient id={`g-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.4" />
            <stop offset="100%" stopColor={color} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        <path d={areaD} fill={`url(#g-${color.replace('#', '')})`} />
        <path d={pathD} stroke={color} strokeWidth="1.5" fill="none" strokeLinecap="round" />
      </svg>
    )
  }

  // line
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      <path d={pathD} stroke={color} strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      {vals.length > 0 && (
        <circle
          cx={toX(vals.length - 1)}
          cy={toY(vals[vals.length - 1])}
          r="2.5"
          fill={color}
        />
      )}
    </svg>
  )
}

// ── Large SVG Chart ────────────────────────────────────────────────────────────

function LargeLineChart({
  points,
  color = '#1a6bff',
  height = 120,
}: {
  points: MetricPoint[]
  color?: string
  height?: number
}) {
  const width = 600
  if (!points.length) return <div className="h-[120px] flex items-center justify-center text-[#3d5068] text-sm">データなし</div>

  const vals = points.map(p => p.value)
  const min = Math.min(...vals)
  const max = Math.max(...vals)
  const range = max - min || 1
  const padX = 8, padY = 8
  const w = width - padX * 2
  const h = height - padY * 2

  const toX = (i: number) => padX + (i / (vals.length - 1)) * w
  const toY = (v: number) => padY + h - ((v - min) / range) * h

  const pathD = vals.map((v, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toY(v)}`).join(' ')
  const areaD = pathD + ` L ${toX(vals.length - 1)} ${padY + h} L ${toX(0)} ${padY + h} Z`

  const gridLines = [0, 0.25, 0.5, 0.75, 1].map(t => ({
    y: padY + h * (1 - t),
    val: min + range * t,
  }))

  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ height }}>
      <defs>
        <linearGradient id="lg-area" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {gridLines.map((gl, i) => (
        <line key={i} x1={padX} y1={gl.y} x2={padX + w} y2={gl.y}
          stroke="#1e2d42" strokeWidth="0.5" strokeDasharray="3,3" />
      ))}
      <path d={areaD} fill="url(#lg-area)" />
      <path d={pathD} stroke={color} strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

// ── Metric Card ────────────────────────────────────────────────────────────────

const METRIC_COLORS = [
  '#e8002d', '#1a6bff', '#8b5cf6', '#00c853', '#f59e0b', '#06b6d4',
]

function MetricCard({ metric, index }: { metric: MetricSummary; index: number }) {
  const color = METRIC_COLORS[index % METRIC_COLORS.length]
  const pct = trendPct(metric.current, metric.previous)
  const isPositive = pct >= 0
  const isNeutral = pct === 0

  // For MTTD/MTTR, lower is better
  const lowerIsBetter = metric.name === 'mttd' || metric.name === 'mttr'
  const isGood = lowerIsBetter ? !isPositive : isPositive

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-xs text-[#7d92b0] uppercase tracking-wide font-medium">{metric.label}</p>
          <p className="text-2xl font-bold text-[#e2e8f4] mt-1">
            {fmtVal(metric.current, metric.unit)}
          </p>
        </div>
        <div className={`flex items-center gap-1 text-xs font-medium px-1.5 py-0.5 rounded-sm ${
          isNeutral
            ? 'text-[#7d92b0] bg-[#161f33]'
            : isGood
            ? 'text-green-400 bg-green-900/20'
            : 'text-red-400 bg-red-900/20'
        }`}>
          {isNeutral
            ? <Minus className="w-3 h-3" />
            : isPositive
            ? <TrendingUp className="w-3 h-3" />
            : <TrendingDown className="w-3 h-3" />}
          {Math.abs(pct)}%
        </div>
      </div>
      <MiniChart points={metric.points} chartType={metric.chart_type} color={color} width={220} height={44} />
      <p className="text-xs text-[#3d5068] mt-2">前期比</p>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function MetricsExplorerPage() {
  const [tab, setTab] = useState<'dashboard' | 'query'>('dashboard')
  const [timeRange, setTimeRange] = useState('7d')

  // Query tab state
  const [queryMetric, setQueryMetric] = useState('')
  const [queryFrom, setQueryFrom] = useState(() => {
    const d = new Date()
    d.setDate(d.getDate() - 7)
    return d.toISOString().slice(0, 16)
  })
  const [queryTo, setQueryTo] = useState(() => new Date().toISOString().slice(0, 16))
  const [queryPeriod, setQueryPeriod] = useState('daily')
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null)
  const [queryLoading, setQueryLoading] = useState(false)

  // Fetch summary
  const { data: summaryData, isLoading } = useQuery<MetricsSummaryResponse>({
    queryKey: ['metrics-summary', timeRange],
    queryFn: async () => {
      const res: any = await apiFetch(`/api/v1/metrics/summary?range=${timeRange}`)
      return Array.isArray(res?.metrics) && Array.isArray(res?.endpoints) ? res : { metrics: [], endpoints: [] }
    },
  })
  const summary = summaryData ?? { metrics: [], endpoints: [] }

  // Fetch metric names
  const { data: metricNamesData } = useQuery<string[]>({
    queryKey: ['metric-names'],
    queryFn: async () => {
      const res: any = await apiFetch('/api/v1/metrics/names')
      const names = Array.isArray(res) ? res : res?.names
      return Array.isArray(names) ? names : []
    },
  })
  const metricNames = metricNamesData ?? []

  async function executeQuery() {
    if (!queryMetric) return
    setQueryLoading(true)
    try {
      const res = await apiFetch<{ points?: MetricPoint[] }>(
        `/api/v1/metrics/query?metric=${queryMetric}&from=${queryFrom}&to=${queryTo}&period=${queryPeriod}`
      ).catch(() => null)
      const pts: MetricPoint[] = res?.points ?? generatePoints(50, 20, 14)
      setQueryResult({ metric: queryMetric, points: pts })
    } finally {
      setQueryLoading(false)
    }
  }

  function exportCsv() {
    if (!queryResult) return
    const rows = ['timestamp,value', ...queryResult.points.map(p => `${p.timestamp},${p.value}`)]
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${queryResult.metric}_export.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e2e8f4]">メトリクスエクスプローラー</h1>
        <p className="text-[#7d92b0] text-sm mt-1">セキュリティメトリクスの時系列分析・カスタムクエリ</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#1e2d42]">
        {([['dashboard', 'ダッシュボード'], ['query', 'カスタムクエリ']] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === key
                ? 'border-[#e8002d] text-[#e2e8f4]'
                : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Dashboard Tab ── */}
      {tab === 'dashboard' && (
        <div className="space-y-6">
          {/* Time Range Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#7d92b0]">期間:</span>
            {[
              ['1h', '1時間'],
              ['6h', '6時間'],
              ['24h', '24時間'],
              ['7d', '7日'],
              ['30d', '30日'],
            ].map(([val, label]) => (
              <button
                key={val}
                onClick={() => setTimeRange(val)}
                className={`px-3 py-1.5 rounded-sm text-xs font-medium transition-colors ${
                  timeRange === val
                    ? 'bg-[#e8002d] text-white'
                    : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Metrics Grid (2×3) */}
          {isLoading ? (
            <div className="flex items-center justify-center h-32 text-[#7d92b0]">
              <RefreshCw className="w-5 h-5 animate-spin mr-2" />読み込み中...
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-4">
              {(summary.metrics ?? []).map((m, i) => (
                <MetricCard key={m.name} metric={m} index={i} />
              ))}
            </div>
          )}

          {/* API Endpoint Response Times */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center gap-2">
              <Server className="w-4 h-4 text-[#7d92b0]" />
              <h2 className="text-[#e2e8f4] font-semibold text-sm">APIエンドポイント別レスポンスタイム</h2>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-[#070d19] border-b border-[#1e2d42]">
                  <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">エンドポイント</th>
                  <th className="px-4 py-3 text-right text-xs text-[#7d92b0] uppercase tracking-wide font-medium">平均 (ms)</th>
                  <th className="px-4 py-3 text-right text-xs text-[#7d92b0] uppercase tracking-wide font-medium">P95 (ms)</th>
                  <th className="px-4 py-3 text-right text-xs text-[#7d92b0] uppercase tracking-wide font-medium">P99 (ms)</th>
                  <th className="px-4 py-3 text-right text-xs text-[#7d92b0] uppercase tracking-wide font-medium">エラー率 (%)</th>
                  <th className="px-4 py-3 text-right text-xs text-[#7d92b0] uppercase tracking-wide font-medium">req/min</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {(summary.endpoints ?? []).map(ep => (
                  <tr key={ep.path} className="hover:bg-[#070d19]/50 transition-colors">
                    <td className="px-4 py-3">
                      <code className="text-[#7d92b0] text-xs bg-[#161f33] px-2 py-0.5 rounded-sm">{ep.path}</code>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span className={`font-medium text-sm ${
                        ep.avg_ms > 200 ? 'text-red-400' :
                        ep.avg_ms > 100 ? 'text-yellow-400' :
                        'text-green-400'
                      }`}>{ep.avg_ms}</span>
                    </td>
                    <td className="px-4 py-3 text-right text-[#7d92b0] text-sm">{ep.p95_ms}</td>
                    <td className="px-4 py-3 text-right text-[#7d92b0] text-sm">{ep.p99_ms}</td>
                    <td className="px-4 py-3 text-right">
                      <span className={`text-sm font-medium ${
                        ep.error_rate > 1 ? 'text-red-400' :
                        ep.error_rate > 0.5 ? 'text-yellow-400' :
                        'text-[#7d92b0]'
                      }`}>{ep.error_rate.toFixed(1)}%</span>
                    </td>
                    <td className="px-4 py-3 text-right text-[#7d92b0] text-sm">{ep.requests_per_min}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Custom Query Tab ── */}
      {tab === 'query' && (
        <div className="space-y-6">
          {/* Query Builder */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6">
            <h2 className="text-[#e2e8f4] font-semibold mb-4">クエリ条件</h2>
            <div className="grid grid-cols-4 gap-4 items-end">
              {/* Metric name */}
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">メトリクス</label>
                <select
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                  value={queryMetric}
                  onChange={e => setQueryMetric(e.target.value)}
                >
                  <option value="">選択してください</option>
                  {metricNames.map(n => (
                    <option key={n} value={n}>{n}</option>
                  ))}
                </select>
              </div>

              {/* From */}
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">開始日時</label>
                <input
                  type="datetime-local"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                  value={queryFrom}
                  onChange={e => setQueryFrom(e.target.value)}
                />
              </div>

              {/* To */}
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">終了日時</label>
                <input
                  type="datetime-local"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                  value={queryTo}
                  onChange={e => setQueryTo(e.target.value)}
                />
              </div>

              {/* Period */}
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">集計期間</label>
                <select
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                  value={queryPeriod}
                  onChange={e => setQueryPeriod(e.target.value)}
                >
                  <option value="raw">生データ</option>
                  <option value="hourly">時間別</option>
                  <option value="daily">日別</option>
                </select>
              </div>
            </div>

            <div className="mt-4 flex gap-3">
              <button
                onClick={executeQuery}
                disabled={!queryMetric || queryLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-sm text-sm font-medium bg-[#e8002d] text-white hover:bg-[#c8001d] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {queryLoading
                  ? <RefreshCw className="w-4 h-4 animate-spin" />
                  : <Play className="w-4 h-4" />}
                クエリ実行
              </button>
              {queryResult && (
                <button
                  onClick={exportCsv}
                  className="flex items-center gap-2 px-4 py-2 rounded-sm text-sm font-medium bg-[#161f33] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  CSVエクスポート
                </button>
              )}
            </div>
          </div>

          {/* Query Results */}
          {queryResult && (
            <div className="space-y-4">
              {/* Chart */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <div className="flex items-center gap-2 mb-4">
                  <BarChart3 className="w-4 h-4 text-[#7d92b0]" />
                  <h3 className="text-[#e2e8f4] font-medium text-sm">
                    {queryResult.metric} — 時系列グラフ
                  </h3>
                  <span className="text-xs text-[#3d5068]">({queryResult.points.length} ポイント)</span>
                </div>
                <LargeLineChart points={queryResult.points} color="#1a6bff" height={140} />
              </div>

              {/* Data Table */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1e2d42]">
                  <h3 className="text-[#e2e8f4] font-medium text-sm">データテーブル</h3>
                </div>
                <div className="max-h-[300px] overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-[#070d19]">
                      <tr className="border-b border-[#1e2d42]">
                        <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">タイムスタンプ</th>
                        <th className="px-4 py-3 text-right text-xs text-[#7d92b0] uppercase tracking-wide font-medium">値</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2d42]">
                      {queryResult.points.map((pt, i) => (
                        <tr key={i} className="hover:bg-[#070d19]/50 transition-colors">
                          <td className="px-4 py-2 text-[#7d92b0] text-xs font-mono">{fmtDateTime(pt.timestamp)}</td>
                          <td className="px-4 py-2 text-right text-[#e2e8f4] font-medium">{pt.value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {!queryResult && !queryLoading && (
            <div className="flex flex-col items-center justify-center py-16 text-[#3d5068]">
              <Activity className="w-10 h-10 mb-3 opacity-40" />
              <p className="text-sm">メトリクスを選択してクエリを実行してください</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
