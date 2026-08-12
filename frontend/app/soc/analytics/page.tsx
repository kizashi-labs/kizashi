'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BarChart3, Clock, TrendingUp, TrendingDown,
  Users, CheckCircle2, XCircle, AlertTriangle,
  Target, Zap, Shield, ChevronRight, Download,
  Activity, Filter, Award, Bot,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

type Period = 'today' | 'week' | 'month' | 'quarter'

interface KPI {
  mttd_min: number
  mttr_min: number
  mttc_min: number
  alert_to_incident_ratio: number
  false_positive_rate: number
  mttd_delta: number
  mttr_delta: number
  mttc_delta: number
}

interface AlertFlowNode {
  source: string
  severity: string
  disposition: string
  count: number
}

interface DayMetric {
  date: string
  alert_volume: number
  capacity_utilization: number
  backlog: number
}

interface Analyst {
  id: string
  name: string
  tier: 'L1' | 'L2' | 'L3'
  alerts_handled: number
  median_triage_min: number
  escalation_rate: number
  fp_rate: number
  availability_hours: number
}

interface Rule {
  id: string
  name: string
  true_positive_rate: number
  total_alerts: number
  suppressed: number
}

interface Tool {
  name: string
  usage_count: number
  avg_session_min: number
}

interface SOCAnalytics {
  kpi: KPI
  alert_flow: AlertFlowNode[]
  daily_metrics: DayMetric[]
  analysts: Analyst[]
  quality: {
    timeline_accuracy: number
    evidence_completeness: number
    rca_completion: number
    pir_completion: number
  }
  efficiency: {
    automation_rate: number
    rules: Rule[]
    tools: Tool[]
  }
}

// ── Mock Data ──────────────────────────────────────────────────────────────

function generateDailyMetrics(days: number): DayMetric[] {
  const today = new Date('2026-03-18')
  return Array.from({ length: days }, (_, i) => {
    const d = new Date(today)
    d.setDate(d.getDate() - (days - 1 - i))
    const weekday = d.getDay()
    const isWeekend = weekday === 0 || weekday === 6
    const baseVol = isWeekend ? 120 : 380
    return {
      date: d.toISOString().split('T')[0],
      alert_volume: Math.floor(baseVol + (Math.random() - 0.5) * 80),
      capacity_utilization: Math.floor((isWeekend ? 35 : 72) + (Math.random() - 0.5) * 20),
      backlog: Math.floor(Math.max(0, (isWeekend ? 8 : 24) + (Math.random() - 0.5) * 16)),
    }
  })
}

const MOCK_DATA: SOCAnalytics = {
  kpi: {
    mttd_min: 8.4,
    mttr_min: 42.1,
    mttc_min: 94.7,
    alert_to_incident_ratio: 0.034,
    false_positive_rate: 18.2,
    mttd_delta: -1.2,
    mttr_delta: -5.8,
    mttc_delta: +3.1,
  },
  alert_flow: [
    { source: 'EDR', severity: 'critical', disposition: 'escalated', count: 42 },
    { source: 'EDR', severity: 'high', disposition: 'resolved', count: 180 },
    { source: 'EDR', severity: 'medium', disposition: 'false_positive', count: 95 },
    { source: 'EDR', severity: 'low', disposition: 'suppressed', count: 340 },
    { source: 'SIEM', severity: 'critical', disposition: 'escalated', count: 18 },
    { source: 'SIEM', severity: 'high', disposition: 'resolved', count: 92 },
    { source: 'SIEM', severity: 'medium', disposition: 'false_positive', count: 64 },
    { source: 'SIEM', severity: 'low', disposition: 'suppressed', count: 210 },
    { source: 'Network', severity: 'high', disposition: 'resolved', count: 55 },
    { source: 'Network', severity: 'medium', disposition: 'false_positive', count: 88 },
    { source: 'Network', severity: 'low', disposition: 'suppressed', count: 420 },
    { source: 'Email', severity: 'critical', disposition: 'escalated', count: 12 },
    { source: 'Email', severity: 'high', disposition: 'resolved', count: 48 },
    { source: 'Email', severity: 'medium', disposition: 'false_positive', count: 120 },
    { source: 'Cloud', severity: 'high', disposition: 'resolved', count: 38 },
    { source: 'Cloud', severity: 'medium', disposition: 'suppressed', count: 95 },
  ],
  daily_metrics: generateDailyMetrics(60),
  analysts: [
    { id: 'a1', name: '田中 健一', tier: 'L2', alerts_handled: 284, median_triage_min: 6.2, escalation_rate: 8.4, fp_rate: 12.1, availability_hours: 160 },
    { id: 'a2', name: '鈴木 美咲', tier: 'L1', alerts_handled: 412, median_triage_min: 8.8, escalation_rate: 14.2, fp_rate: 22.5, availability_hours: 168 },
    { id: 'a3', name: '佐藤 大輔', tier: 'L3', alerts_handled: 98, median_triage_min: 3.1, escalation_rate: 2.0, fp_rate: 5.2, availability_hours: 120 },
    { id: 'a4', name: '山田 花子', tier: 'L2', alerts_handled: 256, median_triage_min: 7.4, escalation_rate: 9.8, fp_rate: 15.3, availability_hours: 152 },
    { id: 'a5', name: '伊藤 拓也', tier: 'L1', alerts_handled: 380, median_triage_min: 9.2, escalation_rate: 16.5, fp_rate: 24.8, availability_hours: 160 },
    { id: 'a6', name: '渡辺 さくら', tier: 'L2', alerts_handled: 310, median_triage_min: 6.8, escalation_rate: 10.1, fp_rate: 13.7, availability_hours: 148 },
  ],
  quality: {
    timeline_accuracy: 78.4,
    evidence_completeness: 84.2,
    rca_completion: 62.1,
    pir_completion: 54.8,
  },
  efficiency: {
    automation_rate: 41.3,
    rules: [
      { id: 'r1', name: 'Mimikatz検出', true_positive_rate: 94.2, total_alerts: 180, suppressed: 12 },
      { id: 'r2', name: 'ランサムウェア動作パターン', true_positive_rate: 91.5, total_alerts: 94, suppressed: 5 },
      { id: 'r3', name: 'コマンド&コントロール通信', true_positive_rate: 88.7, total_alerts: 240, suppressed: 28 },
      { id: 'r4', name: 'PowerShell難読化', true_positive_rate: 76.3, total_alerts: 382, suppressed: 91 },
      { id: 'r5', name: 'ラテラルムーブメント', true_positive_rate: 71.8, total_alerts: 156, suppressed: 18 },
      { id: 'r6', name: '異常なログイン', true_positive_rate: 64.2, total_alerts: 520, suppressed: 186 },
      { id: 'r7', name: 'DLPポリシー違反', true_positive_rate: 58.9, total_alerts: 284, suppressed: 115 },
      { id: 'r8', name: 'ポートスキャン検出', true_positive_rate: 52.1, total_alerts: 448, suppressed: 214 },
      { id: 'r9', name: '大量データ転送', true_positive_rate: 48.4, total_alerts: 312, suppressed: 161 },
      { id: 'r10', name: 'SMB異常通信', true_positive_rate: 44.7, total_alerts: 198, suppressed: 108 },
    ],
    tools: [
      { name: 'VirusTotal', usage_count: 842, avg_session_min: 4.2 },
      { name: 'ライブレスポンス', usage_count: 384, avg_session_min: 28.5 },
      { name: 'フォレンジクス', usage_count: 156, avg_session_min: 94.2 },
      { name: 'サンドボックス', usage_count: 290, avg_session_min: 18.7 },
      { name: 'MITRE ATT&CK', usage_count: 612, avg_session_min: 8.1 },
      { name: 'IOC検索', usage_count: 1240, avg_session_min: 3.4 },
      { name: 'パケット分析', usage_count: 98, avg_session_min: 42.8 },
    ],
  },
}

const EMPTY_SOC_ANALYTICS: SOCAnalytics = {
  kpi: { mttd_min: 0, mttr_min: 0, mttc_min: 0, alert_to_incident_ratio: 0, false_positive_rate: 0, mttd_delta: 0, mttr_delta: 0, mttc_delta: 0 },
  alert_flow: [],
  daily_metrics: [],
  analysts: [],
  quality: { timeline_accuracy: 0, evidence_completeness: 0, rca_completion: 0, pir_completion: 0 },
  efficiency: { automation_rate: 0, rules: [], tools: [] },
}

// ── Helpers ────────────────────────────────────────────────────────────────

const dispositionColor: Record<string, string> = {
  resolved: 'bg-green-500/20 text-green-300',
  escalated: 'bg-[#e8002d]/20 text-[#e8002d]',
  false_positive: 'bg-amber-500/20 text-amber-300',
  suppressed: 'bg-[#7d92b0]/20 text-[#7d92b0]',
}

const dispositionLabel: Record<string, string> = {
  resolved: '解決',
  escalated: 'エスカレーション',
  false_positive: 'フォールスポジティブ',
  suppressed: '抑制',
}

const tierColor: Record<string, string> = {
  L1: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  L2: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  L3: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
}

function formatMin(min: number): string {
  if (min < 60) return `${min.toFixed(1)}分`
  const h = Math.floor(min / 60)
  const m = Math.round(min % 60)
  return `${h}時間${m}分`
}

// ── SVG Line Chart ─────────────────────────────────────────────────────────

function LineChart({
  data,
  keys,
  colors,
  height = 80,
  labels,
}: {
  data: Record<string, number>[]
  keys: string[]
  colors: string[]
  height?: number
  labels?: string[]
}) {
  const w = 600
  const h = height
  const pad = { l: 8, r: 8, t: 8, b: 8 }
  const innerW = w - pad.l - pad.r
  const innerH = h - pad.t - pad.b

  const allVals = data.flatMap(d => keys.map(k => d[k] as number))
  const minV = Math.min(...allVals) * 0.9
  const maxV = Math.max(...allVals) * 1.05
  const range = maxV - minV || 1

  const pts = (key: string) =>
    data.map((d, i) => {
      const x = pad.l + (i / (data.length - 1)) * innerW
      const y = pad.t + innerH - ((d[key] as number - minV) / range) * innerH
      return `${x.toFixed(1)},${y.toFixed(1)}`
    }).join(' ')

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" style={{ height }}>
      {keys.map((key, ki) => (
        <g key={key}>
          <polyline
            points={pts(key)}
            fill="none"
            stroke={colors[ki]}
            strokeWidth="1.5"
            strokeLinejoin="round"
          />
        </g>
      ))}
    </svg>
  )
}

// ── Sankey-style Flow ──────────────────────────────────────────────────────

function AlertFlowSection({ flow }: { flow: AlertFlowNode[] }) {
  const sources = [...new Set(flow.map(f => f.source))]
  const severities = ['critical', 'high', 'medium', 'low']
  const dispositions = ['escalated', 'resolved', 'false_positive', 'suppressed']
  const total = flow.reduce((a, f) => a + f.count, 0)

  const sourceTotal = (s: string) => flow.filter(f => f.source === s).reduce((a, f) => a + f.count, 0)
  const dispositionTotal = (d: string) => flow.filter(f => f.disposition === d).reduce((a, f) => a + f.count, 0)
  const severityTotal = (s: string) => flow.filter(f => f.severity === s).reduce((a, f) => a + f.count, 0)

  const sevColor: Record<string, string> = {
    critical: '#e8002d',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#6b7280',
  }

  return (
    <div className="grid grid-cols-3 gap-4">
      {/* Sources */}
      <div>
        <p className="text-[#7d92b0] text-xs mb-2 font-medium">アラートソース</p>
        <div className="space-y-1.5">
          {sources.map(s => {
            const t = sourceTotal(s)
            return (
              <div key={s} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-white font-medium">{s}</span>
                  <span className="text-[#7d92b0]">{t.toLocaleString()}</span>
                </div>
                <div className="h-1 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div className="h-full bg-blue-400 rounded-full" style={{ width: `${t / total * 100}%` }} />
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Severities */}
      <div>
        <p className="text-[#7d92b0] text-xs mb-2 font-medium">重大度</p>
        <div className="space-y-1.5">
          {severities.map(s => {
            const t = severityTotal(s)
            return (
              <div key={s} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2">
                <div className="flex justify-between text-xs mb-1">
                  <span className="font-medium" style={{ color: sevColor[s] }}>
                    {s === 'critical' ? 'クリティカル' : s === 'high' ? '高' : s === 'medium' ? '中' : '低'}
                  </span>
                  <span className="text-[#7d92b0]">{t.toLocaleString()}</span>
                </div>
                <div className="h-1 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${t / total * 100}%`, backgroundColor: sevColor[s] }} />
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Dispositions */}
      <div>
        <p className="text-[#7d92b0] text-xs mb-2 font-medium">処理結果</p>
        <div className="space-y-1.5">
          {dispositions.map(d => {
            const t = dispositionTotal(d)
            return (
              <div key={d} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2">
                <div className="flex justify-between text-xs mb-1">
                  <span className={`font-medium ${dispositionColor[d].split(' ')[1]}`}>{dispositionLabel[d]}</span>
                  <span className="text-[#7d92b0]">{t.toLocaleString()}</span>
                </div>
                <div className="h-1 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div className={`h-full rounded-full ${dispositionColor[d].split(' ')[0]}`} style={{ width: `${t / total * 100}%` }} />
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function SOCAnalyticsPage() {
  const [period, setPeriod] = useState<Period>('month')
  const [activeSection, setActiveSection] = useState<'flow' | 'analyst' | 'quality' | 'efficiency'>('flow')

  const { data, isError } = useQuery<SOCAnalytics>({
    queryKey: ['soc-analytics', period],
    queryFn: () => apiFetch(`/api/v1/soc/analytics?period=${period}`),
    staleTime: 120_000,
  })

  const analytics: SOCAnalytics = isError || !data ? EMPTY_SOC_ANALYTICS : data
  const { kpi, daily_metrics, analysts, quality, efficiency, alert_flow } = analytics

  const periodDays = { today: 1, week: 7, month: 30, quarter: 90 }
  const slicedMetrics = daily_metrics.slice(-periodDays[period])

  const velocityPoints = useMemo(() =>
    slicedMetrics.map((d, i) => ({
      velocity: Math.round(d.alert_volume / (d.capacity_utilization / 100 * 8) * 10) / 10,
    })),
    [slicedMetrics]
  )

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(analytics, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `soc-analytics-${period}-${new Date().toISOString().split('T')[0]}.json`
    a.click()
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 flex items-center justify-center">
            <BarChart3 className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">SOC運用分析</h1>
            <p className="text-[#7d92b0] text-sm">SOC Operations Analytics Dashboard</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Period selector */}
          <div className="flex bg-[#0d1220] border border-[#1e2d42] rounded-lg p-0.5">
            {(['today', 'week', 'month', 'quarter'] as Period[]).map(p => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-all ${
                  period === p ? 'bg-[#e8002d] text-white' : 'text-[#7d92b0] hover:text-white'
                }`}
              >
                {p === 'today' ? '本日' : p === 'week' ? '週次' : p === 'month' ? '月次' : '四半期'}
              </button>
            ))}
          </div>
          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-[#7d92b0] hover:text-white text-xs rounded-lg transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            エクスポート
          </button>
        </div>
      </div>

      {/* ── KPI Summary Row ── */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          {
            label: 'MTTD', sublabel: '平均検知時間',
            value: formatMin(kpi.mttd_min),
            delta: kpi.mttd_delta,
            icon: Clock,
            color: 'text-blue-400',
          },
          {
            label: 'MTTR', sublabel: '平均対応時間',
            value: formatMin(kpi.mttr_min),
            delta: kpi.mttr_delta,
            icon: Activity,
            color: 'text-purple-400',
          },
          {
            label: 'MTTC', sublabel: '平均封じ込め時間',
            value: formatMin(kpi.mttc_min),
            delta: kpi.mttc_delta,
            icon: Shield,
            color: 'text-amber-400',
          },
          {
            label: 'Alert→Incident', sublabel: 'インシデント転換率',
            value: `${(kpi.alert_to_incident_ratio * 100).toFixed(1)}%`,
            delta: null,
            icon: Target,
            color: 'text-green-400',
          },
          {
            label: 'FP率', sublabel: 'フォールスポジティブ',
            value: `${kpi.false_positive_rate.toFixed(1)}%`,
            delta: null,
            icon: XCircle,
            color: 'text-[#e8002d]',
          },
        ].map(({ label, sublabel, value, delta, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-1.5">
                <Icon className={`w-3.5 h-3.5 ${color}`} />
                <span className="text-[#7d92b0] text-xs font-medium">{label}</span>
              </div>
              {delta !== null && (
                <span className={`text-xs font-bold flex items-center gap-0.5 ${delta < 0 ? 'text-green-400' : 'text-[#e8002d]'}`}>
                  {delta < 0 ? <TrendingDown className="w-3 h-3" /> : <TrendingUp className="w-3 h-3" />}
                  {Math.abs(delta).toFixed(1)}
                </span>
              )}
            </div>
            <p className="text-white font-bold text-xl mt-2">{value}</p>
            <p className="text-[#3d5068] text-xs mt-0.5">{sublabel}</p>
          </div>
        ))}
      </div>

      {/* ── Section Tabs ── */}
      <div className="flex gap-0 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1">
        {[
          { id: 'flow' as const, label: 'アラートフロー', icon: Activity },
          { id: 'analyst' as const, label: 'アナリスト効率', icon: Users },
          { id: 'quality' as const, label: 'インシデント品質', icon: CheckCircle2 },
          { id: 'efficiency' as const, label: '運用効率化', icon: Zap },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveSection(id)}
            className={`flex-1 flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
              activeSection === id
                ? 'bg-[#1d2f4a] text-white'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            <Icon className="w-4 h-4" />
            <span className="hidden sm:inline">{label}</span>
          </button>
        ))}
      </div>

      {/* ── Alert Flow Section ── */}
      {activeSection === 'flow' && (
        <div className="space-y-6">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Activity className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">アラートフロー分析</h2>
              <span className="text-[#7d92b0] text-xs ml-auto">
                総アラート: {alert_flow.reduce((a, f) => a + f.count, 0).toLocaleString()}
              </span>
            </div>
            <AlertFlowSection flow={alert_flow} />
          </div>

          {/* Volume vs Capacity */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-[#e8002d]" />
                <h2 className="text-white font-semibold">アラート量 vs 処理能力</h2>
              </div>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-blue-400 inline-block" />アラート量</span>
                <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-amber-400 inline-block" />能力使用率%</span>
              </div>
            </div>
            <LineChart
              data={slicedMetrics.map(d => ({ alert_volume: d.alert_volume, capacity_utilization: d.capacity_utilization }))}
              keys={['alert_volume', 'capacity_utilization']}
              colors={['#60a5fa', '#f59e0b']}
              height={80}
            />
            <div className="flex justify-between mt-1">
              <span className="text-[#3d5068] text-xs">{slicedMetrics[0]?.date}</span>
              <span className="text-[#3d5068] text-xs">{slicedMetrics[slicedMetrics.length - 1]?.date}</span>
            </div>
          </div>

          {/* Triage Backlog */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Clock className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">トリアージバックログトレンド</h2>
            </div>
            <LineChart
              data={slicedMetrics.map(d => ({ backlog: d.backlog }))}
              keys={['backlog']}
              colors={['#e8002d']}
              height={60}
            />
            <div className="flex justify-between mt-1">
              <span className="text-[#3d5068] text-xs">{slicedMetrics[0]?.date}</span>
              <span className="text-[#3d5068] text-xs">{slicedMetrics[slicedMetrics.length - 1]?.date}</span>
            </div>
            <p className="text-[#7d92b0] text-xs mt-2">
              現在のバックログ: <span className="text-white font-medium">{slicedMetrics[slicedMetrics.length - 1]?.backlog}件</span>
              　平均: <span className="text-white font-medium">{Math.round(slicedMetrics.reduce((a, d) => a + d.backlog, 0) / slicedMetrics.length)}件</span>
            </p>
          </div>
        </div>
      )}

      {/* ── Analyst Efficiency Section ── */}
      {activeSection === 'analyst' && (
        <div className="space-y-6">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
              <Users className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">アナリスト別パフォーマンス</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['アナリスト', 'ティア', '処理件数', '中央値トリアージ', 'エスカレーション率', 'FP率', '稼働時間'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {[...analysts].sort((a, b) => b.alerts_handled - a.alerts_handled).map(a => (
                    <tr key={a.id} className="hover:bg-[#0a1020] transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center text-white text-xs font-bold">
                            {a.name[0]}
                          </div>
                          <span className="text-white text-sm">{a.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex px-2 py-0.5 rounded border text-xs font-medium ${tierColor[a.tier]}`}>{a.tier}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-white text-sm font-medium">{a.alerts_handled}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm ${a.median_triage_min < 8 ? 'text-green-400' : a.median_triage_min < 12 ? 'text-amber-400' : 'text-[#e8002d]'}`}>
                          {a.median_triage_min}分
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm ${a.escalation_rate < 10 ? 'text-green-400' : a.escalation_rate < 15 ? 'text-amber-400' : 'text-[#e8002d]'}`}>
                          {a.escalation_rate}%
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm ${a.fp_rate < 15 ? 'text-green-400' : a.fp_rate < 20 ? 'text-amber-400' : 'text-[#e8002d]'}`}>
                          {a.fp_rate}%
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[#7d92b0] text-sm">{a.availability_hours}h</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Team Velocity */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">チーム処理速度トレンド</h2>
              <span className="text-[#7d92b0] text-xs ml-auto">アラート/人時</span>
            </div>
            <LineChart
              data={velocityPoints}
              keys={['velocity']}
              colors={['#a78bfa']}
              height={70}
            />
          </div>

          {/* Skill Utilization */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Award className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">スキル活用状況</h2>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {[
                { tier: 'L1', label: '初期トリアージ', categories: ['マルウェア', 'フィッシング', '不審ログイン'], color: 'text-blue-400' },
                { tier: 'L2', label: '深掘り調査', categories: ['APT', 'ランサムウェア', 'ラテラルムーブ'], color: 'text-purple-400' },
                { tier: 'L3', label: '高度分析・フォレンジクス', categories: ['ゼロデイ', 'サプライチェーン', '標的型攻撃'], color: 'text-amber-400' },
              ].map(({ tier, label, categories, color }) => (
                <div key={tier} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <span className={`font-bold text-lg ${color}`}>{tier}</span>
                    <span className="text-[#7d92b0] text-xs">{label}</span>
                  </div>
                  <div className="space-y-1.5">
                    {categories.map(cat => (
                      <div key={cat} className="flex items-center gap-2">
                        <ChevronRight className="w-3 h-3 text-[#3d5068] flex-shrink-0" />
                        <span className="text-[#7d92b0] text-sm">{cat}</span>
                      </div>
                    ))}
                  </div>
                  <div className="mt-3 pt-3 border-t border-[#1e2d42]">
                    <p className="text-xs text-[#7d92b0]">担当アナリスト: <span className={`font-medium ${color}`}>{analysts.filter(a => a.tier === tier).length}名</span></p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Incident Quality Section ── */}
      {activeSection === 'quality' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'タイムライン精度', value: quality.timeline_accuracy, desc: '完全なタイムラインを持つインシデント', icon: Activity },
              { label: '証拠完全性', value: quality.evidence_completeness, desc: '必要な証拠が収集されたインシデント', icon: CheckCircle2 },
              { label: 'RCA完了率', value: quality.rca_completion, desc: '根本原因が記録されたインシデント', icon: Target },
              { label: 'PIR完了率', value: quality.pir_completion, desc: 'SLA内にPIRが完了したインシデント', icon: Award },
            ].map(({ label, value, desc, icon: Icon }) => {
              const color = value >= 80 ? '#22c55e' : value >= 60 ? '#f59e0b' : '#e8002d'
              return (
                <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <Icon className="w-4 h-4" style={{ color }} />
                    <span className="text-[#7d92b0] text-xs">{label}</span>
                  </div>
                  <div className="flex items-end gap-2 mb-3">
                    <span className="text-white font-bold text-3xl">{value.toFixed(1)}</span>
                    <span style={{ color }} className="text-lg font-medium mb-0.5">%</span>
                  </div>
                  <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden mb-2">
                    <div className="h-full rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
                  </div>
                  <p className="text-[#3d5068] text-xs">{desc}</p>
                </div>
              )
            })}
          </div>

          {/* Radar-like chart approximation */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">インシデント品質スコアカード</h2>
            </div>
            <div className="space-y-3">
              {[
                { label: 'タイムライン精度', value: quality.timeline_accuracy, target: 90 },
                { label: '証拠完全性スコア', value: quality.evidence_completeness, target: 95 },
                { label: 'RCA完了率', value: quality.rca_completion, target: 80 },
                { label: 'PIR完了率 (SLA内)', value: quality.pir_completion, target: 75 },
                { label: '平均インシデントクオリティ', value: (quality.timeline_accuracy + quality.evidence_completeness + quality.rca_completion + quality.pir_completion) / 4, target: 85 },
              ].map(({ label, value, target }) => {
                const color = value >= target ? '#22c55e' : value >= target * 0.8 ? '#f59e0b' : '#e8002d'
                return (
                  <div key={label} className="flex items-center gap-4">
                    <span className="text-[#7d92b0] text-sm w-48 flex-shrink-0">{label}</span>
                    <div className="flex-1 h-3 bg-[#1e2d42] rounded-full overflow-hidden relative">
                      <div className="h-full rounded-full transition-all" style={{ width: `${value}%`, backgroundColor: color }} />
                      {/* Target line */}
                      <div
                        className="absolute top-0 bottom-0 w-0.5 bg-white/40"
                        style={{ left: `${target}%` }}
                      />
                    </div>
                    <div className="flex items-center gap-2 w-24 text-right">
                      <span className="font-medium text-sm" style={{ color }}>{value.toFixed(1)}%</span>
                      <span className="text-[#3d5068] text-xs">目標 {target}%</span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Efficiency Section ── */}
      {activeSection === 'efficiency' && (
        <div className="space-y-6">
          {/* Automation Rate */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Bot className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">自動化率</h2>
            </div>
            <div className="flex items-center gap-6">
              <div className="relative w-24 h-24 flex-shrink-0">
                <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                  <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1e2d42" strokeWidth="3" />
                  <circle
                    cx="18" cy="18" r="15.9" fill="none"
                    stroke="#e8002d"
                    strokeWidth="3"
                    strokeDasharray={`${efficiency.automation_rate} ${100 - efficiency.automation_rate}`}
                    strokeDashoffset="0"
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-white font-bold text-xl">{efficiency.automation_rate.toFixed(0)}%</span>
                </div>
              </div>
              <div>
                <p className="text-white font-semibold text-lg mb-1">自動処理率 {efficiency.automation_rate.toFixed(1)}%</p>
                <p className="text-[#7d92b0] text-sm">全アラートの {efficiency.automation_rate.toFixed(1)}% が自動的に処理されています</p>
                <p className="text-[#3d5068] text-sm mt-1">目標: 60% <span className="text-amber-400 ml-2">改善余地あり</span></p>
              </div>
            </div>
          </div>

          {/* Top Rules */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
              <Filter className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">ルール有効性 (トップ10)</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ルール名', 'TP率', '総アラート', '抑制数', '抑制率'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {efficiency.rules.map((r, i) => {
                    const suppressionRate = ((r.suppressed / r.total_alerts) * 100).toFixed(1)
                    const color = r.true_positive_rate >= 80 ? '#22c55e' : r.true_positive_rate >= 60 ? '#f59e0b' : '#e8002d'
                    return (
                      <tr key={r.id} className="hover:bg-[#0a1020] transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="text-[#3d5068] text-xs w-5">{i + 1}</span>
                            <span className="text-white text-sm">{r.name}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div className="h-full rounded-full" style={{ width: `${r.true_positive_rate}%`, backgroundColor: color }} />
                            </div>
                            <span className="text-sm font-medium" style={{ color }}>{r.true_positive_rate}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3"><span className="text-white text-sm">{r.total_alerts}</span></td>
                        <td className="px-4 py-3"><span className="text-[#7d92b0] text-sm">{r.suppressed}</span></td>
                        <td className="px-4 py-3">
                          <span className={`text-sm ${Number(suppressionRate) > 40 ? 'text-amber-400' : 'text-[#7d92b0]'}`}>
                            {suppressionRate}%
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Tool Usage */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <Zap className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">ツール使用統計</h2>
            </div>
            <div className="space-y-3">
              {[...efficiency.tools].sort((a, b) => b.usage_count - a.usage_count).map(t => {
                const maxUsage = Math.max(...efficiency.tools.map(x => x.usage_count))
                return (
                  <div key={t.name} className="flex items-center gap-4">
                    <span className="text-[#7d92b0] text-sm w-32 flex-shrink-0">{t.name}</span>
                    <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                      <div
                        className="h-full bg-[#e8002d]/60 rounded-full"
                        style={{ width: `${(t.usage_count / maxUsage) * 100}%` }}
                      />
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-white font-medium w-12 text-right">{(t.usage_count ?? 0).toLocaleString()}</span>
                      <span className="text-[#3d5068] w-16">avg {t.avg_session_min}分</span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
