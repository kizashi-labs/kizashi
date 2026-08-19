'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { USE_MOCK } from '@/lib/mock'
import {
  Award, TrendingUp, TrendingDown, Minus, Download,
  ChevronDown, ArrowUp, ArrowDown, Star, BarChart3,
  CheckCircle, AlertCircle, Building2, Shield,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type ComparisonTarget = 'industry_average' | 'top_quartile' | 'last_year' | 'custom'
type Industry = 'financial' | 'healthcare' | 'manufacturing' | 'retail' | 'government'

interface CategoryBenchmark {
  key: string
  label: string
  our_score: number
  benchmark_score: number
  delta: number
  percentile: number
  trend: 'up' | 'down' | 'flat'
  yoy_change: number
  recommended_action?: string
}

interface BenchmarkData {
  overall_our: number
  overall_benchmark: number
  overall_delta: number
  overall_percentile: number
  categories: CategoryBenchmark[]
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const CATEGORIES_BASE = [
  { key: 'endpoint_detection', label: 'エンドポイント検出' },
  { key: 'network_monitoring', label: 'ネットワーク監視' },
  { key: 'identity_management', label: 'ID管理' },
  { key: 'vulnerability_management', label: '脆弱性管理' },
  { key: 'incident_response', label: 'インシデント対応' },
  { key: 'compliance', label: 'コンプライアンス' },
  { key: 'threat_intelligence', label: '脅威インテリジェンス' },
  { key: 'data_protection', label: 'データ保護' },
  { key: 'cloud_security', label: 'クラウドセキュリティ' },
  { key: 'security_awareness', label: 'セキュリティ意識向上' },
  { key: 'third_party_risk', label: 'サードパーティリスク' },
  { key: 'security_operations', label: 'セキュリティ運用' },
]

const OUR_SCORES = [82, 71, 78, 65, 88, 74, 69, 76, 63, 58, 55, 80]

const BENCHMARK_DATA: Record<ComparisonTarget, Record<Industry, number[]>> = {
  industry_average: {
    financial:     [78, 75, 80, 72, 82, 85, 74, 79, 70, 65, 62, 76],
    healthcare:    [72, 68, 75, 65, 76, 80, 65, 82, 58, 60, 55, 70],
    manufacturing: [68, 65, 70, 60, 72, 70, 60, 68, 55, 52, 50, 65],
    retail:        [65, 62, 68, 58, 70, 68, 58, 65, 60, 55, 52, 62],
    government:    [75, 72, 80, 70, 80, 90, 72, 78, 65, 62, 58, 74],
  },
  top_quartile: {
    financial:     [92, 90, 93, 88, 95, 97, 91, 93, 88, 82, 80, 91],
    healthcare:    [88, 85, 91, 84, 92, 95, 87, 92, 82, 78, 76, 88],
    manufacturing: [85, 82, 87, 80, 88, 88, 82, 85, 78, 75, 72, 84],
    retail:        [82, 80, 84, 78, 86, 85, 80, 82, 80, 74, 70, 82],
    government:    [90, 88, 93, 86, 93, 97, 90, 91, 83, 80, 78, 90],
  },
  last_year: {
    financial:     [75, 66, 73, 60, 83, 70, 63, 70, 56, 50, 48, 74],
    healthcare:    [75, 66, 73, 60, 83, 70, 63, 70, 56, 50, 48, 74],
    manufacturing: [75, 66, 73, 60, 83, 70, 63, 70, 56, 50, 48, 74],
    retail:        [75, 66, 73, 60, 83, 70, 63, 70, 56, 50, 48, 74],
    government:    [75, 66, 73, 60, 83, 70, 63, 70, 56, 50, 48, 74],
  },
  custom: {
    financial:     [80, 72, 79, 68, 85, 80, 72, 78, 67, 62, 58, 78],
    healthcare:    [80, 72, 79, 68, 85, 80, 72, 78, 67, 62, 58, 78],
    manufacturing: [80, 72, 79, 68, 85, 80, 72, 78, 67, 62, 58, 78],
    retail:        [80, 72, 79, 68, 85, 80, 72, 78, 67, 62, 58, 78],
    government:    [80, 72, 79, 68, 85, 80, 72, 78, 67, 62, 58, 78],
  },
}

const TRENDS: ('up' | 'down' | 'flat')[] = ['up', 'up', 'flat', 'up', 'up', 'down', 'up', 'flat', 'up', 'up', 'up', 'flat']
const YOY = [7, 5, 5, 5, 5, 4, 6, 6, 7, 8, 7, 6]

const RECOMMENDED_ACTIONS: Record<string, string> = {
  vulnerability_management: 'パッチサイクルを月次から週次に短縮し、CVSSスコア7以上を優先',
  cloud_security: 'CSPM/CWPPツールの導入とクラウドセキュリティポスチャー評価の実施',
  security_awareness: '月次フィッシングシミュレーション訓練の実施と意識向上プログラムの強化',
  third_party_risk: 'サードパーティリスク評価フレームワークの整備と定期的なベンダー審査',
  threat_intelligence: 'TIフィード拡充とSOCとの統合強化、自動エンリッチメントの実装',
  network_monitoring: 'NDRソリューションの導入とEast-Westトラフィックの可視化',
}

function buildBenchmarkData(comparison: ComparisonTarget, industry: Industry): BenchmarkData {
  const benchScores = BENCHMARK_DATA[comparison][industry]
  const categories: CategoryBenchmark[] = CATEGORIES_BASE.map((cat, i) => {
    const our = OUR_SCORES[i]
    const bench = benchScores[i]
    const delta = our - bench
    const lastYearOur = our - YOY[i]
    const percentile = Math.min(99, Math.max(1, Math.round(50 + delta * 1.8 + Math.random() * 5)))
    return {
      key: cat.key, label: cat.label,
      our_score: our, benchmark_score: bench,
      delta, percentile, trend: TRENDS[i],
      yoy_change: YOY[i],
      recommended_action: delta < 0 ? RECOMMENDED_ACTIONS[cat.key] : undefined,
    }
  })

  const overallOur = Math.round(OUR_SCORES.reduce((s, v) => s + v, 0) / OUR_SCORES.length)
  const overallBench = Math.round(benchScores.reduce((s, v) => s + v, 0) / benchScores.length)
  return {
    overall_our: overallOur, overall_benchmark: overallBench,
    overall_delta: overallOur - overallBench,
    overall_percentile: Math.min(99, Math.round(50 + (overallOur - overallBench) * 1.5)),
    categories,
  }
}

// ─── Radar Chart SVG ──────────────────────────────────────────────────────────

function RadarChart({ data }: { data: BenchmarkData }) {
  const size = 280
  const cx = size / 2
  const cy = size / 2
  const r = 100
  const cats = data.categories.slice(0, 8)
  const n = cats.length
  const maxScore = 100

  const getPoint = (angle: number, val: number) => {
    const a = angle - Math.PI / 2
    const rv = (val / maxScore) * r
    return { x: cx + rv * Math.cos(a), y: cy + rv * Math.sin(a) }
  }

  const angles = cats.map((_, i) => (i * 2 * Math.PI) / n)

  const ourPoly = cats.map((c, i) => getPoint(angles[i], c.our_score))
  const benchPoly = cats.map((c, i) => getPoint(angles[i], c.benchmark_score))

  const toPath = (pts: { x: number; y: number }[]) =>
    pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ') + ' Z'

  const gridLevels = [25, 50, 75, 100]

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="overflow-visible">
      {/* Grid */}
      {gridLevels.map(level => {
        const pts = angles.map(a => getPoint(a, level))
        return (
          <polygon key={level} points={pts.map(p => `${p.x},${p.y}`).join(' ')}
            fill="none" stroke="#1e2d42" strokeWidth="1" />
        )
      })}
      {/* Axis lines */}
      {angles.map((angle, i) => {
        const outer = getPoint(angle, 100)
        return <line key={i} x1={cx} y1={cy} x2={outer.x} y2={outer.y} stroke="#1e2d42" strokeWidth="1" />
      })}
      {/* Benchmark polygon */}
      <path d={toPath(benchPoly)} fill="rgba(125,146,176,0.1)" stroke="#7d92b0" strokeWidth="1.5" strokeDasharray="4,2" />
      {/* Our polygon */}
      <path d={toPath(ourPoly)} fill="rgba(232,0,45,0.15)" stroke="#e8002d" strokeWidth="2" />
      {/* Data points */}
      {ourPoly.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r="4" fill="#e8002d" stroke="#070d19" strokeWidth="1.5" />
      ))}
      {/* Labels */}
      {cats.map((c, i) => {
        const lp = getPoint(angles[i], 118)
        const anchor = lp.x < cx - 5 ? 'end' : lp.x > cx + 5 ? 'start' : 'middle'
        return (
          <text key={i} x={lp.x} y={lp.y} textAnchor={anchor} dominantBaseline="middle"
            fontSize="9" fill="#7d92b0" className="font-sans">
            {c.label.length > 8 ? c.label.slice(0, 7) + '…' : c.label}
          </text>
        )
      })}
    </svg>
  )
}

// ─── Score Display ────────────────────────────────────────────────────────────

function ScoreRing({ score, label, color }: { score: number; label: string; color: string }) {
  const r = 44
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r={r} fill="none" stroke="#1e2d42" strokeWidth="8" />
          <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="8"
            strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease' }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-white font-bold text-2xl leading-none">{score}</span>
          <span className="text-[#7d92b0] text-[10px] mt-0.5">/ 100</span>
        </div>
      </div>
      <span className="text-[#7d92b0] text-xs text-center">{label}</span>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function BenchmarkPage() {
  const [comparison, setComparison] = useState<ComparisonTarget>('industry_average')
  const [industry, setIndustry] = useState<Industry>('financial')
  const [showExportMenu, setShowExportMenu] = useState(false)

  const benchQ = useQuery<BenchmarkData>({
    queryKey: ['benchmark', comparison, industry],
    queryFn: () => apiFetch(`/api/v1/reports/benchmark?comparison=${comparison}&industry=${industry}`),
    retry: 1,
  })

  // 同業他社との比較。API が返さないときは、定数の「他社スコア」に
  // 乱数のパーセンタイルを足したものを描いていました。「上位78%」は
  // 経営に報告される数字です。誰とも比較していません。
  const EMPTY_BENCHMARK: BenchmarkData = {
    overall_our: 0,
    overall_benchmark: 0,
    overall_delta: 0,
    overall_percentile: 0,
    categories: [],
  }
  const data = useMemo(
    () => benchQ.data ?? (USE_MOCK ? buildBenchmarkData(comparison, industry) : EMPTY_BENCHMARK),
    [benchQ.data, comparison, industry] // eslint-disable-line react-hooks/exhaustive-deps
  )

  const strengths = useMemo(() => [...data.categories].filter(c => c.delta > 0).sort((a, b) => b.delta - a.delta).slice(0, 3), [data])
  const gaps = useMemo(() => [...data.categories].filter(c => c.delta < 0).sort((a, b) => a.delta - b.delta).slice(0, 3), [data])

  const compLabel: Record<ComparisonTarget, string> = {
    industry_average: '業界平均',
    top_quartile: 'トップ25%',
    last_year: '昨年比',
    custom: 'カスタム',
  }

  const industryLabel: Record<Industry, string> = {
    financial: '金融', healthcare: 'ヘルスケア', manufacturing: '製造', retail: '小売', government: '官公庁',
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-linear-to-br from-[#e8002d]/20 to-[#e8002d]/5 border border-[#e8002d]/30 flex items-center justify-center">
            <Award className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">セキュリティベンチマーク比較</h1>
            <p className="text-[#7d92b0] text-sm">業界標準との比較分析とギャップ特定</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Comparison selector */}
          <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1">
            {(['industry_average', 'top_quartile', 'last_year', 'custom'] as ComparisonTarget[]).map(c => (
              <button key={c} onClick={() => setComparison(c)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${comparison === c ? 'bg-[#e8002d] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
                {compLabel[c]}
              </button>
            ))}
          </div>
          {/* Industry selector */}
          <select value={industry} onChange={e => setIndustry(e.target.value as Industry)}
            className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-3 py-2 text-sm text-[#7d92b0] focus:outline-hidden">
            {(Object.entries(industryLabel) as [Industry, string][]).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
          {/* Export */}
          <div className="relative">
            <button onClick={() => setShowExportMenu(v => !v)}
              className="flex items-center gap-2 px-4 py-2 bg-[#0d1220] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-[#7d92b0] hover:text-white rounded-xl text-sm transition-colors">
              <Download className="w-4 h-4" />ベンチマーク報告書
            </button>
            {showExportMenu && (
              <div className="absolute right-0 top-full mt-1 bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden z-10 min-w-[160px] shadow-2xl">
                {['PDF形式', 'Excel形式', 'PowerPoint形式'].map(fmt => (
                  <button key={fmt} onClick={() => setShowExportMenu(false)}
                    className="w-full text-left px-4 py-2.5 text-sm text-[#7d92b0] hover:bg-[#1e2d42] hover:text-white transition-colors">{fmt}</button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Overall Score */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 mb-6">
        <h2 className="text-white font-semibold text-sm mb-6 flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-[#e8002d]" />総合スコア比較
        </h2>
        <div className="flex items-center justify-center gap-16">
          <ScoreRing score={data.overall_our} label="自組織スコア" color="#e8002d" />
          <div className="flex flex-col items-center gap-2">
            <div className={`flex items-center gap-1 px-4 py-2 rounded-xl border ${
              data.overall_delta >= 0 ? 'bg-green-900/20 border-green-700/40' : 'bg-red-900/20 border-red-700/40'
            }`}>
              {data.overall_delta >= 0
                ? <ArrowUp className="w-5 h-5 text-green-400" />
                : <ArrowDown className="w-5 h-5 text-red-400" />}
              <span className={`text-2xl font-bold ${data.overall_delta >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                {data.overall_delta >= 0 ? '+' : ''}{data.overall_delta}
              </span>
            </div>
            <span className="text-[#7d92b0] text-xs">vs {compLabel[comparison]}</span>
            <div className="flex items-center gap-1 text-xs text-[#7d92b0]">
              <Star className="w-3 h-3 text-yellow-400" />
              <span className="text-white font-medium">{data.overall_percentile}パーセンタイル</span>
            </div>
          </div>
          <ScoreRing score={data.overall_benchmark} label={compLabel[comparison]} color="#7d92b0" />
        </div>
      </div>

      <div className="grid grid-cols-3 gap-5 mb-5">
        {/* Radar Chart */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 flex flex-col items-center">
          <h2 className="text-white font-semibold text-sm mb-4 self-start flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#e8002d]" />レーダーチャート
          </h2>
          <RadarChart data={data} />
          <div className="flex items-center gap-5 mt-3 text-xs">
            <div className="flex items-center gap-1.5"><div className="w-3 h-0.5 bg-[#e8002d]" /><span className="text-[#7d92b0]">自組織</span></div>
            <div className="flex items-center gap-1.5"><div className="w-3 h-0.5 bg-[#7d92b0] border-dashed" style={{ borderTop: '1.5px dashed #7d92b0', height: 0 }} /><span className="text-[#7d92b0]">{compLabel[comparison]}</span></div>
          </div>
        </div>

        {/* Strengths */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <h2 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-green-400" />強みカテゴリ Top 3
          </h2>
          <div className="space-y-3">
            {strengths.map((c, i) => (
              <div key={c.key} className="bg-green-900/10 border border-green-700/20 rounded-xl p-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-green-400 text-xs font-bold w-5">#{i + 1}</span>
                  <span className="text-white text-sm font-medium">{c.label}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#7d92b0]">自組織: <span className="text-white font-medium">{c.our_score}</span></span>
                  <span className="text-green-400 font-medium">+{c.delta} pts</span>
                  <span className="text-[#7d92b0]">{c.percentile}%ile</span>
                </div>
                <div className="mt-2 w-full bg-[#1e2d42] rounded-full h-1.5">
                  <div className="bg-green-500 h-1.5 rounded-full" style={{ width: `${c.our_score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Gaps */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <h2 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-[#e8002d]" />改善が必要なカテゴリ
          </h2>
          <div className="space-y-3">
            {gaps.map((c, i) => (
              <div key={c.key} className="bg-red-900/10 border border-red-700/20 rounded-xl p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-red-400 text-xs font-bold w-5">#{i + 1}</span>
                  <span className="text-white text-sm font-medium">{c.label}</span>
                  <span className="ml-auto text-red-400 text-xs font-medium">{c.delta} pts</span>
                </div>
                {c.recommended_action && (
                  <p className="text-[#7d92b0] text-xs leading-relaxed mb-2">{c.recommended_action}</p>
                )}
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#7d92b0]">自組織: <span className="text-white">{c.our_score}</span></span>
                  <span className="text-[#7d92b0]">目標: <span className="text-white">{c.benchmark_score}</span></span>
                  <span className="text-[#7d92b0]">{c.percentile}%ile</span>
                </div>
                <div className="mt-2 relative w-full bg-[#1e2d42] rounded-full h-1.5">
                  <div className="bg-red-500 h-1.5 rounded-full" style={{ width: `${c.our_score}%` }} />
                  <div className="absolute top-0 h-full w-0.5 bg-[#7d92b0]" style={{ left: `${c.benchmark_score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Category Comparison Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden mb-5">
        <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
          <Building2 className="w-4 h-4 text-[#e8002d]" />
          <h2 className="text-white font-semibold text-sm">カテゴリ別スコア比較 — {industryLabel[industry]} 業界</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['カテゴリ', '自組織', compLabel[comparison], '差分', 'パーセンタイル', 'トレンド', '前年比'].map(h => (
                <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.categories.map(c => (
              <tr key={c.key} className="border-b border-[#1e2d42]/50 hover:bg-[#0a1320] transition-colors">
                <td className="px-4 py-3 text-white font-medium">{c.label}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 bg-[#1e2d42] rounded-full h-1.5">
                      <div className={`h-1.5 rounded-full ${c.delta >= 0 ? 'bg-green-500' : 'bg-red-500'}`}
                        style={{ width: `${c.our_score}%` }} />
                    </div>
                    <span className="text-white font-medium w-6 text-right">{c.our_score}</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-[#7d92b0]">{c.benchmark_score}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1">
                    {c.delta > 0 ? <ArrowUp className="w-3.5 h-3.5 text-green-400" /> :
                      c.delta < 0 ? <ArrowDown className="w-3.5 h-3.5 text-red-400" /> :
                        <Minus className="w-3.5 h-3.5 text-[#7d92b0]" />}
                    <span className={`font-semibold text-xs ${c.delta > 0 ? 'text-green-400' : c.delta < 0 ? 'text-red-400' : 'text-[#7d92b0]'}`}>
                      {c.delta > 0 ? '+' : ''}{c.delta}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-medium ${c.percentile >= 75 ? 'text-green-400' : c.percentile >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {c.percentile}%ile
                  </span>
                </td>
                <td className="px-4 py-3">
                  {c.trend === 'up' ? <TrendingUp className="w-4 h-4 text-green-400" /> :
                    c.trend === 'down' ? <TrendingDown className="w-4 h-4 text-red-400" /> :
                      <Minus className="w-4 h-4 text-[#7d92b0]" />}
                </td>
                <td className="px-4 py-3">
                  <span className="text-green-400 text-xs font-medium">+{c.yoy_change}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* YoY Progress */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h2 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-[#e8002d]" />前年比進捗 (12ヶ月変化)
        </h2>
        <div className="grid grid-cols-3 gap-3">
          {data.categories.map(c => (
            <div key={c.key} className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[#7d92b0] text-xs">{c.label}</span>
                <span className="text-green-400 text-xs font-medium">+{c.yoy_change}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#3d5068] text-xs w-8 text-right">{c.our_score - c.yoy_change}</span>
                <div className="flex-1 relative h-2 bg-[#1e2d42] rounded-full">
                  <div className="absolute left-0 top-0 h-full bg-[#1e2d42] rounded-full" style={{ width: `${c.our_score - c.yoy_change}%` }} />
                  <div className="absolute top-0 h-full bg-green-500 rounded-r-full" style={{ left: `${c.our_score - c.yoy_change}%`, width: `${c.yoy_change}%` }} />
                </div>
                <span className="text-white text-xs font-medium w-6">{c.our_score}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
