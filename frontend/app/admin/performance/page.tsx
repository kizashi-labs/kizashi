'use client'

import { useState, useEffect, useCallback } from 'react'
import { getStoredVitals, clearStoredVitals, type VitalEntry } from '@/lib/vitals'
import { Activity, Zap, RefreshCw, Trash2, CheckCircle, AlertTriangle, XCircle, BarChart3, Clock, MousePointer, Layout, Globe } from 'lucide-react'

// ── Types ───────────────────────────────────────────────────────

interface VitalSummary {
  name: string
  value: number | null
  rating: VitalEntry['rating'] | 'unknown'
  unit: string
  description: string
  icon: React.ElementType
  good: number
  poor: number
}

// ── Helpers ─────────────────────────────────────────────────────

function formatValue(value: number | null, unit: string): string {
  if (value === null) return '—'
  if (unit === 'ms') return `${Math.round(value)}ms`
  if (unit === 'score') return value.toFixed(3)
  return `${Math.round(value)}${unit}`
}

function RatingBadge({ rating }: { rating: VitalEntry['rating'] | 'unknown' }) {
  const map = {
    good:              { label: '良好', cls: 'bg-emerald-900/30 text-emerald-300 border-emerald-700/40', icon: CheckCircle },
    'needs-improvement': { label: '改善が必要', cls: 'bg-yellow-900/30 text-yellow-300 border-yellow-700/40', icon: AlertTriangle },
    poor:              { label: '不良', cls: 'bg-red-900/30 text-red-400 border-red-700/40', icon: XCircle },
    unknown:           { label: '計測中…', cls: 'bg-falcon-border text-falcon-muted border-falcon-border', icon: Activity },
  }
  const { label, cls, icon: Icon } = map[rating]
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold border ${cls}`}>
      <Icon className="w-3 h-3" />
      {label}
    </span>
  )
}

function GaugeBar({ value, good, poor, max }: { value: number | null; good: number; poor: number; max: number }) {
  if (value === null) {
    return <div className="h-2 bg-falcon-border rounded-full" />
  }
  const pct = Math.min((value / max) * 100, 100)
  const color = value <= good ? '#22c55e' : value <= poor ? '#f59e0b' : '#e8002d'
  return (
    <div className="relative h-2 bg-falcon-border rounded-full overflow-hidden">
      {/* Good zone */}
      <div className="absolute inset-y-0 left-0 bg-emerald-900/30" style={{ width: `${(good / max) * 100}%` }} />
      {/* Current value */}
      <div className="absolute inset-y-0 left-0 rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  )
}

// ── Main Component ───────────────────────────────────────────────

export default function PerformancePage() {
  const [vitals, setVitals] = useState<VitalEntry[]>([])
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const refresh = useCallback(() => {
    setVitals(getStoredVitals())
    setLastUpdated(new Date())
  }, [])

  const handleClear = () => {
    clearStoredVitals()
    setVitals([])
  }

  useEffect(() => {
    refresh()
    // Listen for live vital events
    const handler = () => refresh()
    window.addEventListener('edr:vital', handler)
    return () => window.removeEventListener('edr:vital', handler)
  }, [refresh])

  // Compute latest value per metric
  const latestByName = vitals.reduce<Record<string, VitalEntry>>((acc, v) => {
    if (!acc[v.name] || v.timestamp > acc[v.name].timestamp) acc[v.name] = v
    return acc
  }, {})

  const summaries: VitalSummary[] = [
    {
      name: 'LCP',
      value: latestByName['LCP']?.value ?? null,
      rating: latestByName['LCP']?.rating ?? 'unknown',
      unit: 'ms',
      description: 'Largest Contentful Paint — 最大コンテンツの表示時間',
      icon: Zap,
      good: 2500,
      poor: 4000,
    },
    {
      name: 'FCP',
      value: latestByName['FCP']?.value ?? null,
      rating: latestByName['FCP']?.rating ?? 'unknown',
      unit: 'ms',
      description: 'First Contentful Paint — 最初のコンテンツ表示時間',
      icon: Globe,
      good: 1800,
      poor: 3000,
    },
    {
      name: 'CLS',
      value: latestByName['CLS']?.value ?? null,
      rating: latestByName['CLS']?.rating ?? 'unknown',
      unit: 'score',
      description: 'Cumulative Layout Shift — レイアウトのずれ',
      icon: Layout,
      good: 0.1,
      poor: 0.25,
    },
    {
      name: 'INP',
      value: latestByName['INP']?.value ?? null,
      rating: latestByName['INP']?.rating ?? 'unknown',
      unit: 'ms',
      description: 'Interaction to Next Paint — インタラクション応答時間',
      icon: MousePointer,
      good: 200,
      poor: 500,
    },
    {
      name: 'TTFB',
      value: latestByName['TTFB']?.value ?? null,
      rating: latestByName['TTFB']?.rating ?? 'unknown',
      unit: 'ms',
      description: 'Time to First Byte — サーバー最初のバイトまでの時間',
      icon: Clock,
      good: 800,
      poor: 1800,
    },
  ]

  const goodCount = summaries.filter(s => s.rating === 'good').length
  const totalMeasured = summaries.filter(s => s.rating !== 'unknown').length
  const overallScore = totalMeasured > 0 ? Math.round((goodCount / totalMeasured) * 100) : null

  // History grouped by metric
  const historyByMetric = vitals.reduce<Record<string, VitalEntry[]>>((acc, v) => {
    if (!acc[v.name]) acc[v.name] = []
    acc[v.name].push(v)
    return acc
  }, {})

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">フロントエンドパフォーマンス</h1>
          <p className="text-sm text-falcon-muted mt-1">
            Core Web Vitals のリアルタイム計測 — 現在のブラウザセッション
          </p>
        </div>
        <div className="flex items-center gap-2">
          {lastUpdated && (
            <span className="text-xs text-falcon-subtle">
              更新: {lastUpdated.toLocaleTimeString('ja-JP')}
            </span>
          )}
          <button
            onClick={refresh}
            className="flex items-center gap-1.5 text-xs text-falcon-muted hover:text-white border border-falcon-border hover:border-[#2d3f55] px-3 py-1.5 rounded-lg transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            更新
          </button>
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 text-xs text-falcon-muted hover:text-red-400 border border-falcon-border hover:border-red-900/50 px-3 py-1.5 rounded-lg transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            クリア
          </button>
        </div>
      </div>

      {/* Overall score */}
      <div className="bg-[#0a1628] border border-falcon-border rounded-xl p-5 flex items-center gap-6">
        <div className="text-center w-24 shrink-0">
          <div className={`text-5xl font-bold ${overallScore === null ? 'text-falcon-subtle' : overallScore >= 80 ? 'text-emerald-400' : overallScore >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
            {overallScore === null ? '—' : overallScore}
          </div>
          <div className="text-xs text-falcon-subtle mt-1">総合スコア</div>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2">
            <BarChart3 className="w-4 h-4 text-falcon-muted" />
            <span className="text-sm font-semibold text-white">Core Web Vitals サマリー</span>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="text-emerald-400">● 良好: {summaries.filter(s => s.rating === 'good').length}</span>
            <span className="text-yellow-400">● 改善が必要: {summaries.filter(s => s.rating === 'needs-improvement').length}</span>
            <span className="text-red-400">● 不良: {summaries.filter(s => s.rating === 'poor').length}</span>
            <span className="text-falcon-subtle">● 計測中: {summaries.filter(s => s.rating === 'unknown').length}</span>
          </div>
          <p className="text-xs text-falcon-subtle mt-2">
            ページをリロード・ナビゲートするとデータが蓄積されます。計測はクライアントサイドのみ（本番では analytics サービスへの送信を推奨）。
          </p>
        </div>
      </div>

      {/* Vital cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {summaries.map(({ name, value, rating, unit, description, icon: Icon, good, poor }) => {
          const max = unit === 'score' ? poor * 3 : poor * 2
          return (
            <div key={name} className="bg-[#0a1628] border border-falcon-border rounded-xl p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 bg-falcon-border rounded-lg flex items-center justify-center">
                    <Icon className="w-4 h-4 text-falcon-muted" />
                  </div>
                  <div>
                    <div className="text-sm font-bold text-white">{name}</div>
                    <div className="text-xs text-falcon-subtle truncate max-w-[150px]">{description.split('—')[0].trim()}</div>
                  </div>
                </div>
                <RatingBadge rating={rating} />
              </div>

              <div className="mb-3">
                <div className={`text-3xl font-bold ${rating === 'good' ? 'text-emerald-400' : rating === 'needs-improvement' ? 'text-yellow-400' : rating === 'poor' ? 'text-red-400' : 'text-falcon-subtle'}`}>
                  {formatValue(value, unit)}
                </div>
              </div>

              <GaugeBar value={value} good={good} poor={poor} max={max} />

              <div className="flex justify-between text-[10px] text-falcon-subtle mt-1">
                <span>良好 ≤ {formatValue(good, unit)}</span>
                <span>不良 &gt; {formatValue(poor, unit)}</span>
              </div>

              {/* Mini history */}
              {historyByMetric[name] && historyByMetric[name].length > 1 && (
                <div className="mt-3 pt-3 border-t border-falcon-border">
                  <div className="text-xs text-falcon-subtle mb-1.5">計測履歴 ({historyByMetric[name].length}件)</div>
                  <div className="flex items-end gap-0.5 h-6">
                    {historyByMetric[name].slice(-20).map((v, i) => {
                      const pct = Math.min((v.value / max) * 100, 100)
                      const color = v.rating === 'good' ? '#22c55e' : v.rating === 'needs-improvement' ? '#f59e0b' : '#e8002d'
                      return (
                        <div
                          key={i}
                          className="flex-1 rounded-xs transition-all"
                          style={{ height: `${Math.max(pct, 5)}%`, backgroundColor: color, opacity: 0.7 }}
                          title={formatValue(v.value, unit)}
                        />
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Thresholds reference */}
      <div className="bg-[#0a1628] border border-falcon-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-white mb-3">Google Core Web Vitals 基準値</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-falcon-muted">
            <thead>
              <tr className="text-falcon-subtle border-b border-falcon-border">
                <th className="text-left py-2 pr-4">指標</th>
                <th className="text-left py-2 pr-4">説明</th>
                <th className="text-left py-2 pr-4 text-emerald-400">良好</th>
                <th className="text-left py-2 pr-4 text-yellow-400">改善が必要</th>
                <th className="text-left py-2 text-red-400">不良</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {summaries.map(s => (
                <tr key={s.name}>
                  <td className="py-2 pr-4 font-bold text-white">{s.name}</td>
                  <td className="py-2 pr-4 text-falcon-subtle">{s.description.split('—')[1]?.trim()}</td>
                  <td className="py-2 pr-4 text-emerald-400">≤ {formatValue(s.good, s.unit)}</td>
                  <td className="py-2 pr-4 text-yellow-400">≤ {formatValue(s.poor, s.unit)}</td>
                  <td className="py-2 text-red-400">&gt; {formatValue(s.poor, s.unit)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {vitals.length === 0 && (
        <div className="text-center py-12 text-falcon-subtle">
          <Activity className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">データを収集中です。ページを操作してください。</p>
          <p className="text-xs mt-1">LCP・FCP は自動計測、CLS はレイアウトシフト時、INP はインタラクション時に記録されます。</p>
        </div>
      )}
    </div>
  )
}
