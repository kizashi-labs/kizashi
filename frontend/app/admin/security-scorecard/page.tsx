'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BarChart3, RefreshCw, CheckCircle, AlertTriangle, XCircle, MinusCircle,
  ChevronRight, TrendingUp, Shield, Eye, Zap, RotateCcw,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type Framework = 'NIST CSF' | 'ISO 27001'
type ControlStatus = 'Compliant' | 'Partial' | 'Non-compliant' | 'Not assessed'

interface CategoryScore {
  name: string
  score: number
  icon: React.ReactNode
  color: string
}

interface Control {
  id: string
  name: string
  category: string
  status: ControlStatus
  score: number
}

interface ScorecardData {
  // null when no control could be assessed — every compliance evidence query
  // failed. The API answers 503 in that case. This used to fall back to
  // `overall_score: 0`, which the gauge renders in red as a failing posture, so
  // a database outage was displayed to an auditor as the worst possible result.
  overall_score: number | null
  categories: { name: string; score: number }[]
  controls: Control[]
  recommendations: string[]
  assessed_controls: number
  total_controls: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<ControlStatus, { label: string; className: string; icon: React.ReactNode }> = {
  Compliant: {
    label: '準拠',
    className: 'bg-green-500/15 text-green-400 border-green-500/30',
    icon: <CheckCircle className="w-3 h-3" />,
  },
  Partial: {
    label: '一部準拠',
    className: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    icon: <AlertTriangle className="w-3 h-3" />,
  },
  'Non-compliant': {
    label: '非準拠',
    className: 'bg-red-500/15 text-red-400 border-red-500/30',
    icon: <XCircle className="w-3 h-3" />,
  },
  'Not assessed': {
    label: '未評価',
    className: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
    icon: <MinusCircle className="w-3 h-3" />,
  },
}

const NIST_ICONS: Record<string, React.ReactNode> = {
  Identify: <Eye className="w-5 h-5" />,
  Protect: <Shield className="w-5 h-5" />,
  Detect: <BarChart3 className="w-5 h-5" />,
  Respond: <Zap className="w-5 h-5" />,
  Recover: <RotateCcw className="w-5 h-5" />,
}

const scoreColor = (s: number) =>
  s >= 80 ? 'text-green-400' : s >= 60 ? 'text-yellow-400' : 'text-red-400'

const scoreBgColor = (s: number) =>
  s >= 80 ? 'bg-green-400' : s >= 60 ? 'bg-yellow-400' : 'bg-red-400'

const scoreRingColor = (s: number) =>
  s >= 80 ? '#34d399' : s >= 60 ? '#fbbf24' : '#f87171'

// Map the backend's snake/lower-case control status to the UI's labels.
const STATUS_MAP: Record<string, ControlStatus> = {
  compliant: 'Compliant',
  partial: 'Partial',
  non_compliant: 'Non-compliant',
  not_assessed: 'Not assessed',
}

// The scorecard API returns { overall_score, category_scores: {cat: number},
// controls: [{id,name,category,status,score}], recommendations }. Adapt it to the
// shape this page renders (a `categories` array and Title-case statuses).
// Previously the page guarded on a `categories` field the API never returns, so
// every response fell back to an empty scorecard (overall score shown as 0).
function adaptScorecard(raw: Record<string, unknown>): ScorecardData {
  const catScores = (raw.category_scores ?? {}) as Record<string, number>
  const categories = Object.entries(catScores).map(([name, score]) => ({
    name,
    score: Math.round(Number(score) || 0),
  }))
  const controls: Control[] = (Array.isArray(raw.controls) ? raw.controls : []).map((c: Record<string, unknown>) => ({
    id: String(c.id ?? ''),
    name: String(c.name ?? ''),
    category: String(c.category ?? ''),
    score: Math.round(Number(c.score) || 0),
    status: STATUS_MAP[String(c.status)] ?? 'Not assessed',
  }))
  const assessed = Number(raw.assessed_controls) || 0
  return {
    // A score is only reported when something was measured. `Number(x) || 0`
    // cannot tell a real zero from a missing field, so coverage decides.
    overall_score: assessed > 0 ? Math.round(Number(raw.overall_score) || 0) : null,
    categories,
    controls,
    recommendations: Array.isArray(raw.recommendations) ? (raw.recommendations as string[]) : [],
    assessed_controls: assessed,
    total_controls: Number(raw.total_controls) || controls.length,
  }
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function SecurityScorecardPage() {
  const [framework, setFramework] = useState<Framework>('NIST CSF')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')

  // A scorecard that could not be fetched has no score, not a score of zero.
  const EMPTY_SCORECARD: ScorecardData = {
    overall_score: null,
    categories: [],
    controls: [],
    recommendations: [],
    assessed_controls: 0,
    total_controls: 0,
  }

  const nistQuery = useQuery<ScorecardData>({
    queryKey: ['scorecard-nist'],
    queryFn: async () => {
      const res = await apiFetch('/api/v1/admin/scorecard/nist-csf')
      if (res && typeof res === 'object' && 'controls' in res) return adaptScorecard(res as Record<string, unknown>)
      return EMPTY_SCORECARD
    },
    staleTime: 60_000,
    retry: false,
  })

  const isoQuery = useQuery<ScorecardData>({
    queryKey: ['scorecard-iso'],
    queryFn: async () => {
      const res = await apiFetch('/api/v1/admin/scorecard/iso27001')
      if (res && typeof res === 'object' && 'controls' in res) return adaptScorecard(res as Record<string, unknown>)
      return EMPTY_SCORECARD
    },
    staleTime: 60_000,
    retry: false,
  })

  const isLoading = framework === 'NIST CSF' ? nistQuery.isLoading : isoQuery.isLoading
  const data = (framework === 'NIST CSF' ? nistQuery.data : isoQuery.data) ?? EMPTY_SCORECARD

  const categories = data.categories
  const controls = categoryFilter === 'all' ? data.controls : data.controls.filter(c => c.category === categoryFilter)

  // Gauge ring - uses SVG-like approach with conic-gradient
  const score = data.overall_score
  const circumference = 2 * Math.PI * 54
  const dashoffset = score === null ? circumference : circumference * (1 - score / 100)

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      <PageDataUnavailable />
      {/* ヘッダー */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <BarChart3 className="w-7 h-7 text-purple-400" />
            セキュリティスコアカード
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            セキュリティフレームワーク全体のコンプライアンス状況
          </p>
        </div>
        <div className="flex gap-1 bg-zinc-900 border border-zinc-800 rounded-lg p-1">
          {(['NIST CSF', 'ISO 27001'] as Framework[]).map(f => (
            <button
              key={f}
              onClick={() => { setFramework(f); setCategoryFilter('all') }}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                framework === f ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-6 h-6 text-zinc-500 animate-spin" />
        </div>
      )}

      <div className="grid grid-cols-3 gap-6 mb-6">
        {/* 総合スコアゲージ */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 flex flex-col items-center justify-center">
          <h2 className="text-zinc-400 text-sm font-medium mb-4">総合スコア</h2>
          <div className="relative w-36 h-36">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="54" fill="none" stroke="#27272a" strokeWidth="10" />
              <circle
                cx="60" cy="60" r="54"
                fill="none"
                stroke={score === null ? '#3f3f46' : scoreRingColor(score)}
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={dashoffset}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 0.8s ease' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={`text-3xl font-bold ${score === null ? 'text-zinc-500' : scoreColor(score)}`}>
                {score === null ? '—' : score}
              </span>
              <span className="text-zinc-500 text-xs">{score === null ? '未計測' : '/ 100'}</span>
            </div>
          </div>
          <div className="mt-4 text-center">
            {score === null ? (
              <span className="text-sm font-semibold text-zinc-500">評価できた項目がありません</span>
            ) : (
              <span className={`text-sm font-semibold ${scoreColor(score)}`}>
                {score >= 80 ? '良好' : score >= 60 ? '普通' : '要改善'}
              </span>
            )}
            <p className="text-zinc-600 text-xs mt-1">{framework}</p>
            {data.total_controls > 0 && (
              <p className="text-zinc-600 text-xs mt-1 tabular-nums">
                {data.assessed_controls}/{data.total_controls} 項目を評価
              </p>
            )}
          </div>
        </div>

        {/* カテゴリスコア */}
        <div className="col-span-2 bg-zinc-900 border border-zinc-800 rounded-lg p-5">
          <h2 className="text-zinc-400 text-sm font-medium mb-4">カテゴリスコア</h2>
          <div className="grid grid-cols-2 gap-3">
            {categories.map(cat => (
              <div
                key={cat.name}
                onClick={() => setCategoryFilter(categoryFilter === cat.name ? 'all' : cat.name)}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  categoryFilter === cat.name
                    ? 'border-zinc-600 bg-zinc-800'
                    : 'border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/50'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5">
                    <span className="text-zinc-500">
                      {framework === 'NIST CSF' ? NIST_ICONS[cat.name] : <Shield className="w-4 h-4" />}
                    </span>
                    <span className="text-zinc-300 text-sm font-medium truncate max-w-[110px]">{cat.name}</span>
                  </div>
                  <span className={`text-sm font-bold ${scoreColor(cat.score)}`}>{cat.score}</span>
                </div>
                <div className="h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${scoreBgColor(cat.score)}`}
                    style={{ width: `${cat.score}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* コントロールテーブル */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg mb-6">
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
          <div className="flex items-center gap-2">
            <h2 className="text-zinc-100 font-semibold">コントロール</h2>
            {categoryFilter !== 'all' && (
              <span className="px-2 py-0.5 rounded-sm bg-zinc-700 text-zinc-300 text-xs">
                {categoryFilter}
                <button onClick={() => setCategoryFilter('all')} className="ml-1.5 text-zinc-500 hover:text-zinc-300">×</button>
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-zinc-500">
            {(['Compliant', 'Partial', 'Non-compliant', 'Not assessed'] as ControlStatus[]).map(s => {
              const count = data.controls.filter(c => c.status === s && (categoryFilter === 'all' || c.category === categoryFilter)).length
              return (
                <span key={s} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border ${STATUS_CONFIG[s].className}`}>
                  {STATUS_CONFIG[s].icon}
                  {count}
                </span>
              )
            })}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800">
                {['ID', 'コントロール名', 'カテゴリ', 'ステータス', 'スコア'].map(h => (
                  <th key={h} className="text-left px-5 py-3 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {controls.map((ctrl, i) => (
                <tr key={ctrl.id} className={`border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors ${i % 2 === 0 ? '' : 'bg-zinc-950/20'}`}>
                  <td className="px-5 py-3 font-mono text-zinc-400 text-xs whitespace-nowrap">{ctrl.id}</td>
                  <td className="px-5 py-3 text-zinc-300 text-sm">{ctrl.name}</td>
                  <td className="px-5 py-3 text-zinc-500 text-xs">{ctrl.category}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[11px] font-medium border ${STATUS_CONFIG[ctrl.status].className}`}>
                      {STATUS_CONFIG[ctrl.status].icon}
                      {STATUS_CONFIG[ctrl.status].label}
                    </span>
                  </td>
                  <td className="px-5 py-3 w-36">
                    {ctrl.score > 0 ? (
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${scoreBgColor(ctrl.score)}`}
                            style={{ width: `${ctrl.score}%` }}
                          />
                        </div>
                        <span className={`text-xs font-medium w-7 text-right ${scoreColor(ctrl.score)}`}>{ctrl.score}</span>
                      </div>
                    ) : (
                      <span className="text-zinc-600 text-xs">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 推奨事項 */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
        <div className="flex items-center gap-2 mb-4">
          <TrendingUp className="w-5 h-5 text-blue-400" />
          <h2 className="text-zinc-100 font-semibold">推奨事項</h2>
        </div>
        <ol className="space-y-3">
          {data.recommendations.map((rec, i) => (
            <li key={i} className="flex items-start gap-3 p-3 rounded-lg bg-zinc-800/40 border border-zinc-800">
              <span className="shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 text-xs font-bold flex items-center justify-center">
                {i + 1}
              </span>
              <span className="text-zinc-300 text-sm flex-1">{rec}</span>
              <ChevronRight className="w-4 h-4 text-zinc-600 shrink-0 mt-0.5" />
            </li>
          ))}
        </ol>
      </div>
    </div>
  )
}
