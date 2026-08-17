'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Plus, X, TrendingUp, TrendingDown, Minus, BarChart2 } from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

interface MetricPoint {
  id: string
  name: string
  value: number
  unit: string
  recorded_at: string
}

interface MetricNames {
  names: string[]
}

interface RecordForm {
  name: string
  value: string
  unit: string
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function barColor(metric: string): string {
  if (metric.includes('alert') || metric.includes('incident')) return 'bg-falcon-red'
  if (metric.includes('block') || metric.includes('threat')) return 'bg-amber-500'
  return 'bg-[#3d87f5]'
}

function formatLabel(iso: string, period: string): string {
  try {
    const d = new Date(iso)
    if (period === '1d') return d.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })
    return d.toLocaleDateString('ja-JP', { month: '2-digit', day: '2-digit' })
  } catch { return iso }
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function SecurityMetricsPage() {
  const queryClient = useQueryClient()
  const [period, setPeriod] = useState<'1d' | '7d' | '30d'>('7d')
  const [selectedMetric, setSelectedMetric] = useState('alert_count')
  const [showRecordModal, setShowRecordModal] = useState(false)
  const [recordForm, setRecordForm] = useState<RecordForm>({ name: '', value: '', unit: '' })

  // ── Queries ──────────────────────────────────────────────────────────────────

  const { data: namesData } = useQuery<MetricNames>({
    queryKey: ['security-metric-names'],
    queryFn: () => apiFetch<MetricNames>('/api/v1/admin/security-metrics/names').catch(() => ({} as MetricNames)),
  })

  const { data: metricsData, isLoading: metricsLoading } = useQuery<{ metrics: MetricPoint[] }>({
    queryKey: ['security-metrics', selectedMetric, period],
    // No mock fallback: a security dashboard must never show fabricated values.
    // On error/no data, show an honest empty state. The API returns each point as
    // {metric_name, metric_value, metric_unit, recorded_at}, so adapt the field
    // names to this page's MetricPoint (otherwise value/unit read as undefined).
    queryFn: async () => {
      try {
        const res = await apiFetch<{ metrics?: Record<string, unknown>[] }>(
          `/api/v1/admin/security-metrics?name=${selectedMetric}&period=${period}`,
        )
        const metrics: MetricPoint[] = (res?.metrics ?? []).map((m, i) => ({
          id: String(m.id ?? `${selectedMetric}-${i}`),
          name: String(m.metric_name ?? m.name ?? selectedMetric),
          value: Number(m.metric_value ?? m.value ?? 0),
          unit: String(m.metric_unit ?? m.unit ?? ''),
          recorded_at: String(m.recorded_at ?? ''),
        }))
        return { metrics }
      } catch {
        return { metrics: [] }
      }
    },
  })

  const recordMutation = useMutation({
    mutationFn: (data: RecordForm) =>
      apiFetch('/api/v1/admin/security-metrics', {
        method: 'POST',
        body: JSON.stringify({ ...data, value: parseFloat(data.value) }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-metrics'] })
      setShowRecordModal(false)
      setRecordForm({ name: '', value: '', unit: '' })
    },
  })

  // ── Derived ───────────────────────────────────────────────────────────────────

  const points = metricsData?.metrics ?? []
  const values = points.map((p) => p.value)
  const maxVal = Math.max(...values, 1)
  const minVal = values.length ? Math.min(...values) : 0
  const avgVal = values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0
  const currentVal = values[values.length - 1] ?? 0
  const firstVal = values[0] ?? currentVal
  const trendUp = currentVal > firstVal
  const trendDown = currentVal < firstVal
  const unit = points[0]?.unit ?? ''

  const trendPct = useMemo(() => {
    if (!firstVal) return 0
    return (((currentVal - firstVal) / firstVal) * 100).toFixed(1)
  }, [currentVal, firstVal])

  const color = barColor(selectedMetric)

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* ヘッダー */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BarChart2 className="w-7 h-7 text-falcon-red" />
            セキュリティメトリクス
          </h1>
          <p className="text-falcon-muted text-sm mt-0.5">トレンド分析 &amp; KPIトラッキング</p>
        </div>
        <div className="flex items-center gap-3">
          {/* 期間セレクター */}
          <div className="flex bg-falcon-surface border border-falcon-border rounded-lg p-0.5">
            {(['1d', '7d', '30d'] as const).map((p) => (
              <button
                key={p}
                onClick={() => setPeriod(p)}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  period === p ? 'bg-falcon-red text-white' : 'text-falcon-muted hover:text-white'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
          <button
            onClick={() => setShowRecordModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] rounded-lg text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" /> メトリクスを記録
          </button>
        </div>
      </div>

      <div className="flex gap-6">
        {/* サイドバー: メトリクスチップ */}
        <div className="w-52 shrink-0">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-3">
            <p className="text-falcon-muted text-xs font-medium mb-3 uppercase tracking-wider">利用可能なメトリクス</p>
            <div className="flex flex-col gap-1.5">
              {(namesData?.names ?? []).map((name) => (
                <button
                  key={name}
                  onClick={() => setSelectedMetric(name)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium text-left transition-colors ${
                    selectedMetric === name
                      ? 'bg-falcon-red text-white'
                      : 'bg-[#070d19] border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-red'
                  }`}
                >
                  {name.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* メインコンテンツ */}
        <div className="flex-1 min-w-0 space-y-4">
          {/* 現在値ヒーローカード */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 flex items-center justify-between">
            <div>
              <p className="text-falcon-muted text-sm capitalize mb-1">{selectedMetric.replace(/_/g, ' ')}</p>
              <div className="flex items-end gap-3">
                <span className="text-4xl font-bold text-white">{currentVal.toFixed(currentVal % 1 === 0 ? 0 : 1)}</span>
                <span className="text-falcon-muted text-lg mb-1">{unit}</span>
              </div>
            </div>
            <div className="text-right">
              <div className={`flex items-center gap-1 justify-end text-lg font-semibold ${
                trendUp ? 'text-red-400' : trendDown ? 'text-green-400' : 'text-falcon-muted'
              }`}>
                {trendUp ? <TrendingUp className="w-5 h-5" /> : trendDown ? <TrendingDown className="w-5 h-5" /> : <Minus className="w-5 h-5" />}
                <span>{trendUp ? '+' : ''}{trendPct}%</span>
              </div>
              <p className="text-falcon-muted text-xs mt-1">最初のデータポイントとの比較</p>
            </div>
          </div>

          {/* 統計カード */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: '最小値', value: minVal.toFixed(1), color: 'text-blue-400' },
              { label: '最大値', value: maxVal.toFixed(1), color: 'text-orange-400' },
              { label: '平均', value: avgVal.toFixed(1), color: 'text-purple-400' },
              { label: 'データポイント', value: String(points.length), color: 'text-white' },
            ].map((s) => (
              <div key={s.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-3">
                <p className="text-falcon-muted text-xs mb-0.5">{s.label}</p>
                <p className={`text-xl font-bold ${s.color}`}>{s.value} <span className="text-xs text-falcon-muted">{unit}</span></p>
              </div>
            ))}
          </div>

          {/* バーチャート */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-4">
              {selectedMetric.replace(/_/g, ' ')} — {period} トレンド
            </h2>
            {metricsLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 7 }).map((_, i) => (
                  <div key={i} className="h-8 bg-falcon-border rounded-sm animate-pulse" />
                ))}
              </div>
            ) : points.length === 0 ? (
              <div className="py-10 text-center text-falcon-muted text-sm">
                データがありません。このメトリクスはまだ記録されていません（「記録」または自動収集で蓄積されます）。
              </div>
            ) : (
              <div className="space-y-1.5">
                {points.map((pt) => {
                  const pct = maxVal > 0 ? (pt.value / maxVal) * 100 : 0
                  return (
                    <div key={pt.id} className="flex items-center gap-3">
                      <span className="text-falcon-muted text-xs w-16 shrink-0 text-right">{formatLabel(pt.recorded_at, period)}</span>
                      <div className="flex-1 bg-[#070d19] rounded-full h-5 overflow-hidden">
                        <div
                          className={`h-full ${color} rounded-full transition-all`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-white text-xs w-20 shrink-0">
                        {pt.value.toFixed(pt.value % 1 === 0 ? 0 : 1)} {unit}
                      </span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 記録モーダル */}
      {showRecordModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
              <h2 className="text-white font-semibold">メトリクスを記録</h2>
              <button onClick={() => setShowRecordModal(false)} className="text-falcon-muted hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="px-6 py-4 space-y-4">
              <div>
                <label className="block text-falcon-muted text-xs mb-1">メトリクス名</label>
                <input
                  value={recordForm.name}
                  onChange={(e) => setRecordForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="例: alert_count"
                  list="metric-names-list"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red"
                />
                <datalist id="metric-names-list">
                  {(namesData?.names ?? []).map((n) => <option key={n} value={n} />)}
                </datalist>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-falcon-muted text-xs mb-1">値</label>
                  <input
                    value={recordForm.value}
                    onChange={(e) => setRecordForm((f) => ({ ...f, value: e.target.value }))}
                    placeholder="例: 42"
                    type="number"
                    className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red"
                  />
                </div>
                <div>
                  <label className="block text-falcon-muted text-xs mb-1">単位</label>
                  <input
                    value={recordForm.unit}
                    onChange={(e) => setRecordForm((f) => ({ ...f, unit: e.target.value }))}
                    placeholder="例: alerts, %, hours"
                    className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red"
                  />
                </div>
              </div>
            </div>
            <div className="px-6 py-4 border-t border-falcon-border flex gap-3 justify-end">
              <button
                onClick={() => setShowRecordModal(false)}
                className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => recordMutation.mutate(recordForm)}
                disabled={!recordForm.name || !recordForm.value || recordMutation.isPending}
                className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
              >
                {recordMutation.isPending ? '保存中…' : 'メトリクスを保存'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
