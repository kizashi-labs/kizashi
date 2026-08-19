'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Target, Plus, Pencil, Trash2, X, TrendingUp, TrendingDown,
  Minus, Download, RefreshCw, ChevronDown, AlertTriangle,
  CheckCircle, BarChart2, Edit3,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { usePersist, SaveFailed } from '@/lib/persist'

// ─── Types ────────────────────────────────────────────────────────────────────

type KPICategory = 'detection' | 'response' | 'prevention' | 'compliance' | 'risk'
type KPIDirection = 'lower' | 'higher'
type KPIStatus = 'on_track' | 'warning' | 'off_track' | 'no_data'

interface KPIMeasurement {
  id: string
  kpi_id: string
  value: number
  period: string
  notes: string
  created_at: string
}

interface KPI {
  id: string
  name: string
  description: string
  category: KPICategory
  unit: string
  target_value: number
  warning_threshold: number
  current_value: number
  direction: KPIDirection
  status: KPIStatus
  achievement_pct: number
  trend: 'up' | 'down' | 'flat'
  last_updated: string
}

function gradeFromScore(score: number): { letter: string; color: string } {
  if (score >= 95) return { letter: 'A+', color: 'text-green-400' }
  if (score >= 90) return { letter: 'A',  color: 'text-green-400' }
  if (score >= 80) return { letter: 'B',  color: 'text-blue-400' }
  if (score >= 70) return { letter: 'C',  color: 'text-amber-400' }
  return { letter: 'D', color: 'text-red-400' }
}

function achievementColor(pct: number): string {
  if (pct >= 100) return '#22c55e'
  if (pct >= 80) return '#f59e0b'
  return '#ef4444'
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) return null
  const min = Math.min(...values), max = Math.max(...values)
  const range = max - min || 1
  const w = 60, h = 20
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w
    const y = h - ((v - min) / range) * h
    return `${x},${y}`
  }).join(' ')
  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function RingChart({ pct, color, size = 48 }: { pct: number; color: string; size?: number }) {
  const r = (size - 6) / 2
  const circ = 2 * Math.PI * r
  const clamped = Math.min(pct, 100)
  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e2d42" strokeWidth={4} />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={4}
        strokeDasharray={`${(clamped / 100) * circ} ${circ}`} strokeLinecap="round" />
    </svg>
  )
}

// ─── Modals ───────────────────────────────────────────────────────────────────

function KPIModal({ kpi, onClose, onSave }: { kpi?: KPI; onClose: () => void; onSave: (d: Partial<KPI>) => void }) {
  const [form, setForm] = useState({
    name: kpi?.name ?? '',
    description: kpi?.description ?? '',
    category: (kpi?.category ?? 'detection') as KPICategory,
    unit: kpi?.unit ?? '',
    target_value: kpi?.target_value ?? 0,
    warning_threshold: kpi?.warning_threshold ?? 0,
    direction: (kpi?.direction ?? 'lower') as KPIDirection,
  })
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">{kpi ? 'KPIを編集' : '新規KPI追加'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4 max-h-[60vh] overflow-y-auto">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">KPI名</label>
            <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">カテゴリ</label>
              <select value={form.category} onChange={e => setForm(p => ({ ...p, category: e.target.value as KPICategory }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                {(Object.keys(CATEGORY_LABELS) as KPICategory[]).map(c => <option key={c} value={c}>{CATEGORY_LABELS[c]}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">単位</label>
              <input value={form.unit} onChange={e => setForm(p => ({ ...p, unit: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">目標値</label>
              <input type="number" value={form.target_value} onChange={e => setForm(p => ({ ...p, target_value: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">警告閾値</label>
              <input type="number" value={form.warning_threshold} onChange={e => setForm(p => ({ ...p, warning_threshold: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">改善方向</label>
            <select value={form.direction} onChange={e => setForm(p => ({ ...p, direction: e.target.value as KPIDirection }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50">
              <option value="lower">低いほど良い</option>
              <option value="higher">高いほど良い</option>
            </select>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] transition-colors">キャンセル</button>
          <button onClick={() => { onSave(form); onClose() }}
            className="px-4 py-2 rounded-lg text-sm bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

function KPIDetailModal({ kpi, measurements, onClose, onAddMeasurement, onDeleteMeasurement }: {
  kpi: KPI; measurements: KPIMeasurement[]
  onClose: () => void
  onAddMeasurement: (kpiId: string, d: { value: number; period: string; notes: string }) => void
  onDeleteMeasurement: (kpiId: string, measurementId: string) => void
}) {
  const [form, setForm] = useState({ value: '', period: new Date().toISOString().slice(0, 7), notes: '' })
  const color = achievementColor(kpi.achievement_pct)
  const maxVal = Math.max(...measurements.map(m => m.value), kpi.target_value, 1)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[85vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42] shrink-0">
          <h2 className="text-white font-semibold">{kpi.name} — 詳細</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-5">
          {/* History Chart */}
          <div>
            <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">6ヶ月推移</h3>
            <div className="flex items-end gap-2 h-24 bg-[#070d19] rounded-lg p-3 relative">
              {/* Target line */}
              <div className="absolute left-3 right-3 border-t border-dashed border-green-500/40"
                style={{ bottom: `${(kpi.target_value / maxVal) * 100}%` }}>
                <span className="absolute right-0 -top-4 text-[9px] text-green-400">目標 {kpi.target_value}{kpi.unit}</span>
              </div>
              {/* Warning threshold line */}
              <div className="absolute left-3 right-3 border-t border-dashed border-amber-500/40"
                style={{ bottom: `${(kpi.warning_threshold / maxVal) * 100}%` }}>
                <span className="absolute right-0 -top-4 text-[9px] text-amber-400">警告 {kpi.warning_threshold}{kpi.unit}</span>
              </div>
              {measurements.slice(-6).map(m => (
                <div key={m.id} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full rounded-xs transition-all" style={{ height: `${(m.value / maxVal) * 80}%`, backgroundColor: color, minHeight: 4 }} />
                  <span className="text-[8px] text-[#3d5068] truncate">{m.period.slice(5)}</span>
                </div>
              ))}
              {measurements.length === 0 && <div className="w-full text-center text-xs text-[#3d5068] self-center">データなし</div>}
            </div>
          </div>

          {/* Add measurement */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
            <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">測定値を追加</h3>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">値 ({kpi.unit})</label>
                <input type="number" value={form.value} onChange={e => setForm(p => ({ ...p, value: e.target.value }))}
                  className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">期間</label>
                <input type="month" value={form.period} onChange={e => setForm(p => ({ ...p, period: e.target.value }))}
                  className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">メモ</label>
                <input value={form.notes} onChange={e => setForm(p => ({ ...p, notes: e.target.value }))}
                  className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
              </div>
            </div>
            <button onClick={() => { if (form.value) { onAddMeasurement(kpi.id, { value: Number(form.value), period: form.period, notes: form.notes }); setForm(p => ({ ...p, value: '' })) } }}
              className="mt-3 px-3 py-1.5 rounded-lg text-xs bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium transition-colors">追加</button>
          </div>

          {/* History table */}
          <div>
            <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">測定履歴</h3>
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['期間','値','メモ','操作'].map(h => <th key={h} className="px-3 py-2 text-left text-[#7d92b0]">{h}</th>)}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {measurements.map(m => (
                  <tr key={m.id} className="hover:bg-[#070d19]/50">
                    <td className="px-3 py-2 text-white">{m.period}</td>
                    <td className="px-3 py-2 font-mono text-white">{m.value} {kpi.unit}</td>
                    <td className="px-3 py-2 text-[#7d92b0]">{m.notes || '—'}</td>
                    <td className="px-3 py-2">
                      <button onClick={() => onDeleteMeasurement(kpi.id, m.id)}
                        className="p-1 rounded-sm hover:bg-red-900/20 text-[#7d92b0] hover:text-red-400 transition-colors">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
                {measurements.length === 0 && (
                  <tr><td colSpan={4} className="px-3 py-4 text-center text-[#3d5068]">測定値がありません</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

function BulkTargetModal({ kpis, onClose, onSave }: { kpis: KPI[]; onClose: () => void; onSave: (updates: Array<{ id: string; target_value: number }>) => void }) {
  const [targets, setTargets] = useState<Record<string, string>>(Object.fromEntries(kpis.map(k => [k.id, String(k.target_value)])))
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">KPI目標値を一括更新</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-3 max-h-[50vh] overflow-y-auto">
          {kpis.map(k => (
            <div key={k.id} className="flex items-center gap-3">
              <span className="text-sm text-white flex-1">{k.name}</span>
              <input type="number" value={targets[k.id]} onChange={e => setTargets(p => ({ ...p, [k.id]: e.target.value }))}
                className="w-24 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-white text-sm text-right focus:outline-hidden focus:border-[#e8002d]/50" />
              <span className="text-xs text-[#7d92b0] w-8">{k.unit}</span>
            </div>
          ))}
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] transition-colors">キャンセル</button>
          <button onClick={() => { onSave(kpis.map(k => ({ id: k.id, target_value: Number(targets[k.id]) }))); onClose() }}
            className="px-4 py-2 rounded-lg text-sm bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium transition-colors">更新</button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

const CATEGORY_LABELS: Record<KPICategory, string> = {
  detection: '検知', response: '対応', prevention: '予防', compliance: 'コンプライアンス', risk: 'リスク',
}
const CATEGORY_COLORS: Record<KPICategory, string> = {
  detection: 'bg-red-500/10 text-red-400 border-red-500/30',
  response: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  prevention: 'bg-green-500/10 text-green-400 border-green-500/30',
  compliance: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  risk: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
}
const STATUS_CONFIG: Record<KPIStatus, { label: string; color: string; badge: string; bg: string }> = {
  on_track: { label: '達成', color: 'text-green-400', badge: 'bg-green-500/10 text-green-400 border-green-500/30', bg: 'bg-green-500/10' },
  warning: { label: '注意', color: 'text-yellow-400', badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', bg: 'bg-yellow-500/10' },
  off_track: { label: '未達', color: 'text-red-400', badge: 'bg-red-500/10 text-red-400 border-red-500/30', bg: 'bg-red-500/10' },
  no_data: { label: 'データなし', color: 'text-[#7d92b0]', badge: 'bg-[#7d92b0]/10 text-[#7d92b0] border-[#7d92b0]/30', bg: 'bg-[#7d92b0]/10' },
}

export default function KPIDashboardPage() {
  const qc = useQueryClient()
  const [categoryFilter, setCategoryFilter] = useState<'all' | KPICategory>('all')
  const [showKPIModal, setShowKPIModal] = useState(false)
  const [editingKPI, setEditingKPI] = useState<KPI | undefined>()
  const [detailKPI, setDetailKPI] = useState<KPI | undefined>()
  const [showBulkModal, setShowBulkModal] = useState(false)
  const [measurements, setMeasurements] = useState<Record<string, KPIMeasurement[]>>({})
  const { persist, saveError } = usePersist()

  const { data: kpis = [] } = useQuery<KPI[]>({
    queryKey: ['kpis'],
    queryFn: () => apiFetchList<KPI>('/api/v1/admin/kpi'),
  })

  const saveKPI = useMutation({
    mutationFn: (d: Partial<KPI> & { id?: string }) =>
      d.id ? apiFetch(`/api/v1/admin/kpi/${d.id}`, { method: 'PUT', body: JSON.stringify(d) })
           : apiFetch('/api/v1/admin/kpi', { method: 'POST', body: JSON.stringify(d) }),
    onSettled: () => qc.invalidateQueries({ queryKey: ['kpis'] }),
  })

  const deleteKPI = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/kpi/${id}`, { method: 'DELETE' }),
    onSettled: () => qc.invalidateQueries({ queryKey: ['kpis'] }),
  })

  async function addMeasurement(kpiId: string, d: { value: number; period: string; notes: string }) {
    const m: KPIMeasurement = { id: `m-${Date.now()}`, kpi_id: kpiId, ...d, created_at: new Date().toISOString() }
    if (await persist('KPIの実績値', `/api/v1/admin/kpi/${kpiId}/measurements`, { method: 'POST', body: JSON.stringify(d) })) {
      setMeasurements(prev => ({ ...prev, [kpiId]: [...(prev[kpiId] ?? []), m] }))
    }
  }

  function deleteMeasurement(kpiId: string, measurementId: string) {
    setMeasurements(prev => ({ ...prev, [kpiId]: (prev[kpiId] ?? []).filter(m => m.id !== measurementId) }))
  }

  const filtered = categoryFilter === 'all' ? kpis : kpis.filter(k => k.category === categoryFilter)
  const scored = kpis.filter(k => k.status !== 'no_data')
  const avgAchievement = scored.length > 0 ? Math.round(scored.reduce((s, k) => s + (k.achievement_pct ?? 0), 0) / scored.length) : 0
  const grade = gradeFromScore(avgAchievement)

  const categories: Array<'all' | KPICategory> = ['all', 'detection', 'response', 'prevention', 'compliance', 'risk']

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      <PageDataUnavailable />
      <SaveFailed error={saveError} />
      {/* Header */}
      <div className="border-b border-[#1e2d42] px-8 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <Target className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">セキュリティKPIダッシュボード</h1>
              <p className="text-xs text-[#7d92b0] mt-0.5">セキュリティ指標の目標達成状況を追跡・管理</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setShowBulkModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/50 transition-colors">
              <Edit3 className="w-4 h-4" /> KPI目標更新
            </button>
            <button className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/50 transition-colors">
              <Download className="w-4 h-4" /> エクスポート
            </button>
            <button onClick={() => { setEditingKPI(undefined); setShowKPIModal(true) }}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors">
              <Plus className="w-4 h-4" /> KPI追加
            </button>
          </div>
        </div>
      </div>

      <div className="px-8 py-6 space-y-6">
        {/* Overall Health Score */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 flex items-center gap-8">
          <div className="relative shrink-0">
            <RingChart pct={avgAchievement} color={achievementColor(avgAchievement)} size={100} />
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-2xl font-black ${grade.color}`}>{grade.letter}</span>
            </div>
          </div>
          <div>
            <p className="text-sm text-[#7d92b0]">総合セキュリティスコア</p>
            <p className="text-5xl font-black text-white mt-1">{avgAchievement}<span className="text-2xl text-[#7d92b0]">%</span></p>
            <div className="flex gap-3 mt-3">
              <span className="text-xs text-green-400">{kpis.filter(k => k.status === 'on_track').length} 達成中</span>
              <span className="text-xs text-amber-400">{kpis.filter(k => k.status === 'warning').length} 警告</span>
              <span className="text-xs text-red-400">{kpis.filter(k => k.status === 'off_track').length} 未達</span>
            </div>
          </div>
        </div>

        {/* Category Tabs */}
        <div className="flex gap-1 flex-wrap">
          {categories.map(c => (
            <button key={c} onClick={() => setCategoryFilter(c)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${categoryFilter === c ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}>
              {c === 'all' ? 'すべて' : CATEGORY_LABELS[c]}
            </button>
          ))}
        </div>

        {/* KPI Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(k => {
            const color = achievementColor(k.achievement_pct ?? 0)
            const statusCfg = STATUS_CONFIG[k.status] ?? STATUS_CONFIG.no_data
            const kpiMeasurements = measurements[k.id] ?? []
            const sparkValues = kpiMeasurements.slice(-3).map(m => m.value)
            return (
              <div key={k.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 hover:border-[#7d92b0]/30 transition-colors">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 rounded-sm text-[10px] font-semibold border ${CATEGORY_COLORS[k.category]}`}>
                        {CATEGORY_LABELS[k.category]}
                      </span>
                      <span className={`px-2 py-0.5 rounded-sm text-[10px] font-semibold border ${statusCfg.bg} ${statusCfg.color}`}>
                        {statusCfg.label}
                      </span>
                    </div>
                    <h3 className="text-white font-semibold">{k.name}</h3>
                    <p className="text-xs text-[#7d92b0] mt-0.5 truncate">{k.description}</p>
                  </div>
                  <div className="shrink-0 ml-2">
                    <RingChart pct={k.achievement_pct} color={color} size={52} />
                  </div>
                </div>

                <div className="flex items-end justify-between">
                  <div>
                    <p className="text-2xl font-bold text-white">{k.current_value ?? '—'} <span className="text-sm font-normal text-[#7d92b0]">{k.unit}</span></p>
                    <p className="text-xs text-[#7d92b0] mt-0.5">目標: {k.target_value} {k.unit}</p>
                    <div className="flex items-center gap-1 mt-1">
                      {k.trend === 'up' ? <TrendingUp className={`w-3.5 h-3.5 ${k.direction === 'higher' ? 'text-green-400' : 'text-red-400'}`} />
                        : k.trend === 'down' ? <TrendingDown className={`w-3.5 h-3.5 ${k.direction === 'lower' ? 'text-green-400' : 'text-red-400'}`} />
                        : <Minus className="w-3.5 h-3.5 text-[#7d92b0]" />}
                      <span className="text-xs" style={{ color }}>{k.achievement_pct}% 達成</span>
                    </div>
                  </div>
                  {sparkValues.length >= 2 && (
                    <div className="opacity-70">
                      <Sparkline values={sparkValues} color={color} />
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 mt-4 pt-3 border-t border-[#1e2d42]">
                  <button onClick={() => setDetailKPI(k)}
                    className="flex-1 py-1.5 rounded-lg text-xs text-[#7d92b0] hover:text-white bg-[#070d19] hover:bg-[#1e2d42] border border-[#1e2d42] transition-colors">詳細</button>
                  <button onClick={() => { setEditingKPI(k); setShowKPIModal(true) }}
                    className="p-1.5 rounded-lg text-[#7d92b0] hover:text-white bg-[#070d19] hover:bg-[#1e2d42] border border-[#1e2d42] transition-colors">
                    <Pencil className="w-3.5 h-3.5" />
                  </button>
                  <button onClick={() => deleteKPI.mutate(k.id)}
                    className="p-1.5 rounded-lg text-[#7d92b0] hover:text-red-400 bg-[#070d19] hover:bg-red-900/20 border border-[#1e2d42] transition-colors">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Modals */}
      {showKPIModal && (
        <KPIModal kpi={editingKPI} onClose={() => setShowKPIModal(false)}
          onSave={d => saveKPI.mutate(editingKPI ? { ...d, id: editingKPI.id } : d)} />
      )}
      {detailKPI && (
        <KPIDetailModal kpi={detailKPI} measurements={measurements[detailKPI.id] ?? []}
          onClose={() => setDetailKPI(undefined)} onAddMeasurement={addMeasurement} onDeleteMeasurement={deleteMeasurement} />
      )}
      {showBulkModal && (
        <BulkTargetModal kpis={kpis} onClose={() => setShowBulkModal(false)}
          onSave={updates => updates.forEach(u => saveKPI.mutate(u))} />
      )}
    </div>
  )
}
