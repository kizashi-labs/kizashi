'use client'

import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  TrendingUp, DollarSign, ShieldOff, BarChart3,
  AlertTriangle, Users, Cpu, Target
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface InvestmentCategory {
  name: string
  budget: number
  actual: number
  yoyChange: number
  roi: number
}

interface PreventedIncident {
  type: string
  count: number
  valueSaved: number
  icon: React.ElementType
  color: string
}

interface BenchmarkRow {
  metric: string
  ours: string
  industry: string
  topQuartile: string
  weWin: boolean
}

const MONTHLY_ROI = [420, 450, 380, 510, 490, 530, 480, 515, 560, 490, 515, 515]
const MONTHS = ['1月', '2月', '3月', '4月', '5月', '6月', '7月', '8月', '9月', '10月', '11月', '12月']

const BENCHMARK_ROWS: BenchmarkRow[] = [
  { metric: 'セキュリティ投資率 (IT予算比)', ours: '18.4%', industry: '14.2%', topQuartile: '22.1%', weWin: true },
  { metric: 'MTTD (平均検知時間)', ours: '4.2時間', industry: '8.7時間', topQuartile: '2.1時間', weWin: true },
  { metric: 'MTTR (平均対応時間)', ours: '6.8時間', industry: '12.4時間', topQuartile: '3.5時間', weWin: true },
  { metric: 'インシデント件数/年', ours: '124件', industry: '198件', topQuartile: '87件', weWin: true },
  { metric: 'SOC効率 (自動化率)', ours: '67%', industry: '52%', topQuartile: '78%', weWin: true },
  { metric: 'コスト/エンドポイント', ours: '¥12,400', industry: '¥15,800', topQuartile: '¥9,200', weWin: true },
]

// ─── Section 1: Investment Breakdown ─────────────────────────────────────────

function InvestmentBreakdown({ data }: { data: InvestmentCategory[] }) {
  const total = data.reduce((s, d) => s + d.actual, 0)
  const colors = ['bg-blue-500', 'bg-emerald-500', 'bg-amber-500', 'bg-purple-500', 'bg-red-500', 'bg-[#7d92b0]']
  const textColors = ['text-blue-400', 'text-emerald-400', 'text-amber-400', 'text-purple-400', 'text-red-400', 'text-[#7d92b0]']

  return (
    <div className="p-4 rounded-lg bg-[#0d1220] border border-[#1e2d42] space-y-4">
      <h2 className="text-white font-semibold text-lg">投資内訳</h2>

      {/* Stacked bar */}
      <div className="h-8 flex rounded-lg overflow-hidden gap-0.5">
        {data.map((d, i) => (
          <div
            key={d.name}
            className={`${colors[i]} transition-all`}
            style={{ width: `${(d.actual / total) * 100}%` }}
            title={`${d.name}: ¥${d.actual}M`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-3">
        {data.map((d, i) => (
          <div key={d.name} className="flex items-center gap-1.5">
            <div className={`w-3 h-3 rounded-xs ${colors[i]}`} />
            <span className="text-xs text-[#7d92b0]">{d.name}</span>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="rounded-lg border border-[#1e2d42] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42] bg-[#070d19]">
              {['カテゴリ', '予算 (¥M)', '実績 (¥M)', '前年比', 'ROI'].map(h => (
                <th key={h} className="px-4 py-2.5 text-left text-[#7d92b0] font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.map((d, i) => (
              <tr key={d.name} className={`border-b border-[#1e2d42] hover:bg-[#0d1220]/40 ${i % 2 === 0 ? '' : 'bg-[#070d19]/50'}`}>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${colors[i]}`} />
                    <span className={textColors[i]}>{d.name}</span>
                  </div>
                </td>
                <td className="px-4 py-2.5 text-[#7d92b0]">¥{d.budget}M</td>
                <td className="px-4 py-2.5 text-white font-medium">¥{d.actual}M</td>
                <td className="px-4 py-2.5">
                  <span className={d.yoyChange >= 0 ? 'text-emerald-400' : 'text-red-400'}>
                    {d.yoyChange >= 0 ? '+' : ''}{d.yoyChange}%
                  </span>
                </td>
                <td className="px-4 py-2.5">
                  <span className="text-blue-400 font-semibold">{d.roi}%</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Section 2: Prevented Incidents ──────────────────────────────────────────

function PreventedIncidents({ incidents }: { incidents: PreventedIncident[] }) {
  return (
    <div className="p-4 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
      <h2 className="text-white font-semibold text-lg mb-4">防止したインシデント (過去12ヶ月)</h2>
      <div className="grid grid-cols-2 gap-4">
        {incidents.map(inc => (
          <div key={inc.type} className={`p-4 rounded-lg border ${inc.color}`}>
            <div className="flex items-start gap-3">
              <inc.icon className={`w-8 h-8 mt-0.5 ${inc.color.split(' ')[0]}`} />
              <div className="flex-1">
                <p className="text-white font-semibold text-sm">{inc.type}</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">防止件数</p>
                <p className={`text-3xl font-bold ${inc.color.split(' ')[0]}`}>{(inc.count ?? 0).toLocaleString()}件</p>
                <div className="mt-2 pt-2 border-t border-white/10">
                  <p className="text-xs text-[#7d92b0]">推定損失回避額</p>
                  <p className="text-white font-bold text-lg">¥{inc.valueSaved}M相当</p>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Section 3: ROI Trend ────────────────────────────────────────────────────

function RoiTrend() {
  const maxVal = Math.max(...MONTHLY_ROI)
  const avgVal = Math.round(MONTHLY_ROI.reduce((s, v) => s + v, 0) / MONTHLY_ROI.length)
  const avgPct = (avgVal / maxVal) * 100

  return (
    <div className="p-4 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-white font-semibold text-lg">ROIトレンド (12ヶ月)</h2>
        <span className="text-sm text-[#7d92b0]">平均: <span className="text-white font-semibold">{avgVal}%</span></span>
      </div>

      <div className="relative">
        {/* Average reference line */}
        <div
          className="absolute left-0 right-0 border-t border-dashed border-[#7d92b0]/40 pointer-events-none"
          style={{ bottom: `${avgPct}%`, top: 'auto' }}
        >
          <span className="absolute right-0 -top-4 text-xs text-[#7d92b0]/70">avg {avgVal}%</span>
        </div>

        {/* Bars */}
        <div className="flex items-end gap-1.5 h-40">
          {MONTHLY_ROI.map((v, i) => (
            <div key={MONTHS[i]} className="flex-1 flex flex-col items-center gap-1">
              <span className="text-xs text-[#7d92b0]">{v}%</span>
              <div
                className={`w-full rounded-t transition-all ${v >= avgVal ? 'bg-[#e8002d]' : 'bg-[#e8002d]/40'}`}
                style={{ height: `${(v / maxVal) * 100}px` }}
              />
              <span className="text-xs text-[#7d92b0] whitespace-nowrap">{MONTHS[i]}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Section 4: Benchmarking ─────────────────────────────────────────────────

function Benchmarking({ rows }: { rows: BenchmarkRow[] }) {
  return (
    <div className="p-4 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
      <h2 className="text-white font-semibold text-lg mb-4">業界ベンチマーク比較</h2>
      <div className="rounded-lg border border-[#1e2d42] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42] bg-[#070d19]">
              {['メトリクス', '自社', '業界平均', 'トップ四分位'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-[#7d92b0] font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={row.metric} className={`border-b border-[#1e2d42] hover:bg-[#0d1220]/40 ${i % 2 === 0 ? '' : 'bg-[#070d19]/50'}`}>
                <td className="px-4 py-3 text-[#7d92b0]">{row.metric}</td>
                <td className="px-4 py-3">
                  <span className={`font-semibold ${row.weWin ? 'text-emerald-400' : 'text-white'}`}>
                    {row.ours}
                    {row.weWin && <span className="ml-1.5 text-xs bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded-sm">優</span>}
                  </span>
                </td>
                <td className="px-4 py-3 text-white">{row.industry}</td>
                <td className="px-4 py-3 text-[#7d92b0]">{row.topQuartile}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SecurityRoiPage() {
  const { data: investments = [] } = useQuery({
    queryKey: ['security-roi-investments'],
    queryFn: () =>
      apiFetchList<InvestmentCategory>('/api/v1/security/roi/investments'),
  })

  const { data: prevented = [] } = useQuery({
    queryKey: ['security-roi-prevented'],
    queryFn: () =>
      apiFetchList<PreventedIncident>('/api/v1/security/roi/prevented'),
  })

  const stats = [
    { label: '総投資額', value: '¥145,000,000', icon: DollarSign, color: 'text-blue-400' },
    { label: '防止した損失', value: '¥892,000,000', icon: ShieldOff, color: 'text-emerald-400' },
    { label: 'ROI', value: '515%', icon: TrendingUp, color: 'text-[#e8002d]' },
    { label: 'リスク削減率', value: '67%', icon: BarChart3, color: 'text-amber-400' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      <PageDataUnavailable />
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <TrendingUp className="w-8 h-8 text-[#e8002d]" />
          <div>
            <h1 className="text-2xl font-bold">セキュリティROI分析</h1>
            <p className="text-[#7d92b0] text-sm">セキュリティ投資の費用対効果・リスク削減効果の可視化</p>
          </div>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-4 gap-4">
          {stats.map(s => (
            <div key={s.label} className="p-5 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
              <div className="flex items-center gap-2 mb-3">
                <s.icon className={`w-5 h-5 ${s.color}`} />
                <span className="text-xs text-[#7d92b0]">{s.label}</span>
              </div>
              <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Four sections */}
        <InvestmentBreakdown data={investments} />
        <PreventedIncidents incidents={prevented} />
        <RoiTrend />
        <Benchmarking rows={BENCHMARK_ROWS} />
      </div>
    </div>
  )
}
