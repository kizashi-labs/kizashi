'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BarChart2, TrendingUp, TrendingDown, Download, RefreshCw,
  ArrowUp, ArrowDown, Minus, CheckCircle, AlertCircle,
} from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

interface CategoryScore {
  category: string
  score_a: number
  score_b: number
  delta: number
  weight: number
}

interface HistoryPoint {
  month: string
  score_a: number
  score_b: number
}

interface Recommendation {
  id: string
  category: string
  title: string
  impact: number
  effort: 'low' | 'medium' | 'high'
  description: string
}

interface ScorecardData {
  period_a: string
  period_b: string
  overall_a: number
  overall_b: number
  delta: number
  categories: CategoryScore[]
  history: HistoryPoint[]
  recommendations: Recommendation[]
}

// ─── Empty / Mock Data ────────────────────────────────────────────────────────

const EMPTY_SCORECARD: ScorecardData = {
  period_a: '-', period_b: '-',
  overall_a: 0, overall_b: 0, delta: 0,
  categories: [], history: [], recommendations: [],
}
// ─── Score Circle ─────────────────────────────────────────────────────────────

function ScoreCircle({ score, label, color }: { score: number; label: string; color: string }) {
  const radius = 54
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  const getGrade = (s: number) => {
    if (s >= 90) return { grade: 'A', color: '#22c55e' }
    if (s >= 80) return { grade: 'B', color: '#3b82f6' }
    if (s >= 70) return { grade: 'C', color: '#f59e0b' }
    if (s >= 60) return { grade: 'D', color: '#f97316' }
    return { grade: 'F', color: '#e8002d' }
  }

  const { grade, color: gradeColor } = getGrade(score)

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36">
        <svg className="w-36 h-36 -rotate-90" viewBox="0 0 128 128">
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#1e2d42" strokeWidth="12" />
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold text-white">{score}</span>
          <span className="text-sm font-semibold" style={{ color: gradeColor }}>{grade}</span>
        </div>
      </div>
      <span className="text-sm text-falcon-muted">{label}</span>
    </div>
  )
}

// ─── Score Bar ────────────────────────────────────────────────────────────────

function ScoreBar({ score, color }: { score: number; color: string }) {
  const getColor = (s: number) => {
    if (s >= 80) return '#22c55e'
    if (s >= 70) return '#3b82f6'
    if (s >= 60) return '#f59e0b'
    return '#e8002d'
  }
  const barColor = color || getColor(score)
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-2 bg-falcon-border rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${score}%`, backgroundColor: barColor }}
        />
      </div>
      <span className="text-white text-sm font-semibold w-8 text-right">{score}</span>
    </div>
  )
}

// ─── SVG Line Chart ───────────────────────────────────────────────────────────

function LineChart({ data }: { data: HistoryPoint[] }) {
  const width = 560
  const height = 200
  const padding = { top: 20, right: 20, bottom: 40, left: 40 }
  const chartW = width - padding.left - padding.right
  const chartH = height - padding.top - padding.bottom

  const allScores = data.flatMap(d => [d.score_a, d.score_b])
  const minScore = Math.min(...allScores) - 5
  const maxScore = Math.max(...allScores) + 5

  const xScale = (i: number) => padding.left + (i / (data.length - 1)) * chartW
  const yScale = (v: number) => padding.top + chartH - ((v - minScore) / (maxScore - minScore)) * chartH

  const pathA = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xScale(i)} ${yScale(d.score_a)}`).join(' ')
  const pathB = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${xScale(i)} ${yScale(d.score_b)}`).join(' ')

  const yTicks = [minScore, minScore + (maxScore - minScore) / 2, maxScore].map(v => Math.round(v))

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full">
      {/* Grid lines */}
      {yTicks.map(t => (
        <g key={t}>
          <line
            x1={padding.left} y1={yScale(t)}
            x2={width - padding.right} y2={yScale(t)}
            stroke="#1e2d42" strokeWidth="1" strokeDasharray="4,4"
          />
          <text x={padding.left - 6} y={yScale(t) + 4} fill="#7d92b0" fontSize="10" textAnchor="end">{t}</text>
        </g>
      ))}
      {/* X axis labels */}
      {data.map((d, i) => (
        <text key={i} x={xScale(i)} y={height - 8} fill="#7d92b0" fontSize="10" textAnchor="middle">
          {d.month.slice(5)}月
        </text>
      ))}
      {/* Lines */}
      <path d={pathA} fill="none" stroke="#3b82f6" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      <path d={pathB} fill="none" stroke="#22c55e" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      {/* Dots */}
      {data.map((d, i) => (
        <g key={i}>
          <circle cx={xScale(i)} cy={yScale(d.score_a)} r="4" fill="#3b82f6" />
          <circle cx={xScale(i)} cy={yScale(d.score_b)} r="4" fill="#22c55e" />
        </g>
      ))}
    </svg>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SecurityScorecardPage() {
  const [periodA, setPeriodA] = useState('2025-12')
  const [periodB, setPeriodB] = useState('2026-01')

  const { data, isLoading, refetch } = useQuery<ScorecardData>({
    queryKey: ['security-scorecard', periodA, periodB],
    queryFn: () =>
      apiFetch<ScorecardData>(`/api/v1/reports/security-scorecard?period_a=${periodA}&period_b=${periodB}`)
        .catch(() => EMPTY_SCORECARD),
  })

  const scorecard = data ?? EMPTY_SCORECARD

  const effortLabel: Record<string, { label: string; color: string }> = {
    low:    { label: '低',   color: '#22c55e' },
    medium: { label: '中',   color: '#f59e0b' },
    high:   { label: '高',   color: '#e8002d' },
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-falcon-surface border border-falcon-border">
            <BarChart2 className="w-6 h-6 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">セキュリティスコアカード比較</h1>
            <p className="text-sm text-falcon-muted mt-0.5">期間別セキュリティスコアの比較・分析</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-red transition-colors text-sm"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
          <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red text-white text-sm font-medium hover:bg-[#cc0027] transition-colors">
            <Download className="w-4 h-4" />
            PDF出力
          </button>
        </div>
      </div>

      {/* Period Selector */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="text-falcon-muted text-sm font-medium">比較期間:</span>
          <div className="flex items-center gap-2">
            <label className="text-falcon-muted text-sm">期間 A</label>
            <input
              type="month"
              value={periodA}
              onChange={e => setPeriodA(e.target.value)}
              className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-1.5 text-white text-sm focus:outline-hidden focus:border-falcon-red"
            />
          </div>
          <span className="text-falcon-muted font-bold">vs</span>
          <div className="flex items-center gap-2">
            <label className="text-falcon-muted text-sm">期間 B</label>
            <input
              type="month"
              value={periodB}
              onChange={e => setPeriodB(e.target.value)}
              className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-1.5 text-white text-sm focus:outline-hidden focus:border-falcon-red"
            />
          </div>
          <button
            onClick={() => refetch()}
            className="px-4 py-1.5 rounded-lg bg-falcon-red text-white text-sm font-medium hover:bg-[#cc0027] transition-colors"
          >
            比較実行
          </button>
        </div>
      </div>

      {/* Overall Score Comparison */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-6">総合スコア比較</h2>
        <div className="flex items-center justify-center gap-16 flex-wrap">
          <ScoreCircle score={scorecard.overall_a} label={`${periodA} (期間A)`} color="#3b82f6" />
          <div className="flex flex-col items-center gap-2">
            {scorecard.delta > 0 ? (
              <TrendingUp className="w-10 h-10 text-green-400" />
            ) : scorecard.delta < 0 ? (
              <TrendingDown className="w-10 h-10 text-red-400" />
            ) : (
              <Minus className="w-10 h-10 text-falcon-muted" />
            )}
            <span
              className={`text-2xl font-bold ${
                scorecard.delta > 0 ? 'text-green-400' : scorecard.delta < 0 ? 'text-red-400' : 'text-falcon-muted'
              }`}
            >
              {scorecard.delta > 0 ? '+' : ''}{scorecard.delta}
            </span>
            <span className="text-xs text-falcon-muted">スコア変化</span>
          </div>
          <ScoreCircle score={scorecard.overall_b} label={`${periodB} (期間B)`} color="#22c55e" />
        </div>

        {/* Overall progress bars summary */}
        <div className="mt-6 grid grid-cols-2 gap-4 max-w-xl mx-auto">
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-falcon-muted">
              <span>期間A スコア</span>
              <span>{scorecard.overall_a} / 100</span>
            </div>
            <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
              <div className="h-full bg-blue-500 rounded-full" style={{ width: `${scorecard.overall_a}%` }} />
            </div>
          </div>
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-falcon-muted">
              <span>期間B スコア</span>
              <span>{scorecard.overall_b} / 100</span>
            </div>
            <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
              <div className="h-full bg-green-500 rounded-full" style={{ width: `${scorecard.overall_b}%` }} />
            </div>
          </div>
        </div>
      </div>

      {/* Category Breakdown Table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-falcon-border">
          <h2 className="text-lg font-semibold text-white">カテゴリ別スコア比較</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-falcon-border">
                <th className="text-left px-4 py-3 text-falcon-muted text-xs font-medium uppercase tracking-wider">カテゴリ</th>
                <th className="text-left px-4 py-3 text-falcon-muted text-xs font-medium uppercase tracking-wider">ウェイト</th>
                <th className="px-4 py-3 text-falcon-muted text-xs font-medium uppercase tracking-wider text-center">期間A スコア</th>
                <th className="px-4 py-3 text-falcon-muted text-xs font-medium uppercase tracking-wider text-center">期間B スコア</th>
                <th className="px-4 py-3 text-falcon-muted text-xs font-medium uppercase tracking-wider text-center">変化</th>
              </tr>
            </thead>
            <tbody>
              {scorecard.categories.map((cat, idx) => (
                <tr key={idx} className="border-b border-falcon-border hover:bg-[#070d19] transition-colors">
                  <td className="px-4 py-3 text-white text-sm font-medium">{cat.category}</td>
                  <td className="px-4 py-3 text-falcon-muted text-sm">{cat.weight}%</td>
                  <td className="px-4 py-3">
                    <ScoreBar score={cat.score_a} color="#3b82f6" />
                  </td>
                  <td className="px-4 py-3">
                    <ScoreBar score={cat.score_b} color="#22c55e" />
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span
                      className={`inline-flex items-center gap-1 text-sm font-semibold ${
                        cat.delta > 0 ? 'text-green-400' : cat.delta < 0 ? 'text-red-400' : 'text-falcon-muted'
                      }`}
                    >
                      {cat.delta > 0 ? <ArrowUp className="w-3 h-3" /> : cat.delta < 0 ? <ArrowDown className="w-3 h-3" /> : <Minus className="w-3 h-3" />}
                      {cat.delta > 0 ? '▲' : cat.delta < 0 ? '▼' : '―'}{Math.abs(cat.delta)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Score History Chart */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">スコア推移 (6ヶ月)</h2>
          <div className="flex items-center gap-4 text-xs text-falcon-muted">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-0.5 bg-blue-500 rounded-sm" />
              <span>期間A トレンド</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-0.5 bg-green-500 rounded-sm" />
              <span>期間B トレンド</span>
            </div>
          </div>
        </div>
        <LineChart data={scorecard.history} />
      </div>

      {/* Recommendations */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-falcon-border">
          <h2 className="text-lg font-semibold text-white">90点達成のための改善提案</h2>
          <p className="text-sm text-falcon-muted mt-1">以下の対策を実施することでスコアが向上します</p>
        </div>
        <div className="divide-y divide-falcon-border">
          {scorecard.recommendations.map(rec => (
            <div key={rec.id} className="p-4 hover:bg-[#070d19] transition-colors">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="mt-0.5">
                    {rec.impact >= 8 ? (
                      <CheckCircle className="w-5 h-5 text-red-400" />
                    ) : (
                      <AlertCircle className="w-5 h-5 text-yellow-400" />
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-white text-sm font-medium">{rec.title}</span>
                      <span className="text-xs px-2 py-0.5 rounded-full bg-falcon-border text-falcon-muted">{rec.category}</span>
                    </div>
                    <p className="text-sm text-falcon-muted mt-1">{rec.description}</p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-falcon-muted">インパクト:</span>
                    <span className="text-sm font-bold text-white">{rec.impact}/10</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="text-xs text-falcon-muted">工数:</span>
                    <span
                      className="text-xs font-semibold"
                      style={{ color: effortLabel[rec.effort].color }}
                    >
                      {effortLabel[rec.effort].label}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Loading overlay */}
      {isLoading && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6 flex items-center gap-3">
            <RefreshCw className="w-5 h-5 text-falcon-red animate-spin" />
            <span className="text-white">データを読み込み中...</span>
          </div>
        </div>
      )}
    </div>
  )
}
