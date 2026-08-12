'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Flag, LayoutList, LayoutGrid, Plus, Edit2, Trash2, ToggleLeft,
  ToggleRight, Sliders, ChevronDown, ChevronUp, X, Check, AlertTriangle,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────

interface FeatureFlag {
  id: string
  name: string
  description: string
  enabled: boolean
  rollout_percentage: number
  target_roles: string[]
  metadata?: Record<string, unknown>
  protected?: boolean
  created_at: string
  updated_at: string
}

interface FlagsResponse {
  flags: FeatureFlag[]
  total: number
}

interface EvaluateRequest {
  flag_name: string
  user_id: string
  role: string
}

interface EvaluateResponse {
  enabled: boolean
  reason: string
}

// ── Helpers ────────────────────────────────────────────────────

function getStatus(flag: FeatureFlag): 'enabled' | 'disabled' | 'partial' {
  if (!flag.enabled) return 'disabled'
  if (flag.rollout_percentage === 100) return 'enabled'
  if (flag.rollout_percentage > 0) return 'partial'
  return 'enabled'
}

const STATUS_LABELS = { enabled: '有効', disabled: '無効', partial: '部分展開' }
const STATUS_COLORS = {
  enabled: 'bg-green-500/10 text-green-400 border-green-500/30',
  disabled: 'bg-red-500/10 text-[#e8002d] border-red-500/30',
  partial: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
}

const ROLES = ['admin', 'analyst', 'viewer']

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('ja-JP', { year: 'numeric', month: 'short', day: 'numeric' })
}

// ── Donut SVG ─────────────────────────────────────────────────

function DonutChart({ pct }: { pct: number }) {
  const r = 20
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ
  return (
    <svg width={52} height={52} viewBox="0 0 52 52" className="rotate-[-90deg]">
      <circle cx={26} cy={26} r={r} fill="none" stroke="#1e2d42" strokeWidth={6} />
      <circle
        cx={26} cy={26} r={r} fill="none"
        stroke={pct === 100 ? '#22c55e' : pct > 0 ? '#eab308' : '#e8002d'}
        strokeWidth={6}
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeLinecap="round"
      />
      <text
        x={26} y={26} textAnchor="middle" dominantBaseline="middle"
        className="rotate-90" style={{ transform: 'rotate(90deg)', transformOrigin: '26px 26px' }}
        fill="#e2e8f4" fontSize={10} fontWeight={700}
      >
        {pct}%
      </text>
    </svg>
  )
}

// ── Modal Base ─────────────────────────────────────────────────

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  )
}

// ── Flag Form ──────────────────────────────────────────────────

interface FlagFormState {
  name: string
  description: string
  enabled: boolean
  rollout_percentage: number
  target_roles: string[]
  metadata: string
}

const defaultForm = (): FlagFormState => ({
  name: '',
  description: '',
  enabled: false,
  rollout_percentage: 0,
  target_roles: [],
  metadata: '',
})

function FlagForm({
  initial,
  onSubmit,
  onCancel,
  submitting,
}: {
  initial?: FlagFormState
  onSubmit: (f: FlagFormState) => void
  onCancel: () => void
  submitting?: boolean
}) {
  const [form, setForm] = useState<FlagFormState>(initial ?? defaultForm())
  const [nameError, setNameError] = useState('')

  const set = <K extends keyof FlagFormState>(k: K, v: FlagFormState[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = () => {
    if (!/^[a-zA-Z0-9_]+$/.test(form.name)) {
      setNameError('英数字・アンダースコアのみ使用可能です')
      return
    }
    setNameError('')
    onSubmit(form)
  }

  const toggleRole = (role: string) =>
    set('target_roles', form.target_roles.includes(role)
      ? form.target_roles.filter(r => r !== role)
      : [...form.target_roles, role])

  return (
    <div className="space-y-4">
      {/* Name */}
      <div>
        <label className="block text-xs text-[#7d92b0] mb-1">フラグ名 <span className="text-[#e8002d]">*</span></label>
        <input
          value={form.name}
          onChange={e => set('name', e.target.value)}
          placeholder="my_feature_flag"
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white font-mono placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
        />
        {nameError && <p className="text-xs text-[#e8002d] mt-1">{nameError}</p>}
      </div>

      {/* Description */}
      <div>
        <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
        <input
          value={form.description}
          onChange={e => set('description', e.target.value)}
          placeholder="機能の説明"
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
        />
      </div>

      {/* Enabled toggle */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-[#7d92b0]">有効化</span>
        <button
          type="button"
          onClick={() => set('enabled', !form.enabled)}
          className={`relative w-11 h-6 rounded-full transition-colors ${form.enabled ? 'bg-green-500' : 'bg-[#1e2d42]'}`}
        >
          <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-[#e2e8f4] shadow transition-transform ${form.enabled ? 'translate-x-5' : ''}`} />
        </button>
      </div>

      {/* Rollout slider */}
      <div>
        <label className="block text-xs text-[#7d92b0] mb-2">
          ロールアウト率 — <span className="text-white font-medium">{form.rollout_percentage}% のユーザーに有効</span>
        </label>
        <input
          type="range" min={0} max={100}
          value={form.rollout_percentage}
          onChange={e => set('rollout_percentage', Number(e.target.value))}
          className="w-full accent-[#e8002d]"
        />
        <div className="flex justify-between text-[10px] text-[#3d5068] mt-0.5">
          <span>0%</span><span>50%</span><span>100%</span>
        </div>
      </div>

      {/* Target roles */}
      <div>
        <label className="block text-xs text-[#7d92b0] mb-2">対象ロール</label>
        <div className="flex gap-3">
          {ROLES.map(role => (
            <label key={role} className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={form.target_roles.includes(role)}
                onChange={() => toggleRole(role)}
                className="accent-[#e8002d]"
              />
              <span className="text-xs text-[#e2e8f4]">{role}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Metadata */}
      <div>
        <label className="block text-xs text-[#7d92b0] mb-1">メタデータ (JSON, 任意)</label>
        <textarea
          value={form.metadata}
          onChange={e => set('metadata', e.target.value)}
          rows={3}
          placeholder='{"key": "value"}'
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-xs text-white font-mono placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 resize-none"
        />
      </div>

      <div className="flex gap-2 justify-end pt-2">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded hover:border-[#7d92b0]/40 transition-colors"
        >
          キャンセル
        </button>
        <button
          onClick={handleSubmit}
          disabled={submitting}
          className="px-4 py-2 text-xs text-white bg-[#e8002d] hover:bg-[#c8001f] rounded transition-colors disabled:opacity-50"
        >
          {submitting ? '保存中...' : '保存'}
        </button>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────

export default function FeatureFlagsPage() {
  const qc = useQueryClient()
  const [view, setView] = useState<'list' | 'card'>('list')
  const [showCreate, setShowCreate] = useState(false)
  const [editFlag, setEditFlag] = useState<FeatureFlag | null>(null)
  const [deleteFlag, setDeleteFlag] = useState<FeatureFlag | null>(null)
  const [rolloutFlag, setRolloutFlag] = useState<FeatureFlag | null>(null)
  const [rolloutPct, setRolloutPct] = useState(0)
  const [evalOpen, setEvalOpen] = useState(false)
  const [evalForm, setEvalForm] = useState<EvaluateRequest>({ flag_name: '', user_id: '', role: 'analyst' })
  const [evalResult, setEvalResult] = useState<EvaluateResponse | null>(null)

  // ── Queries ──────────────────────────────────────────────────

  const { data, isLoading } = useQuery<FlagsResponse>({
    queryKey: ['feature-flags'],
    queryFn: async () => {
      try {
        return await apiFetch<FlagsResponse>('/api/v1/admin/feature-flags')
      } catch {
        return { flags: [], total: 0 }
      }
    },
  })

  const flags = data?.flags ?? []

  // ── Stats ─────────────────────────────────────────────────────

  const stats = useMemo(() => {
    const total = flags.length
    const enabled = flags.filter(f => f.enabled && f.rollout_percentage === 100).length
    const disabled = flags.filter(f => !f.enabled).length
    const partial = flags.filter(f => f.enabled && f.rollout_percentage > 0 && f.rollout_percentage < 100).length
    return { total, enabled, disabled, partial }
  }, [flags])

  // ── Mutations ─────────────────────────────────────────────────

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch<FeatureFlag>(`/api/v1/admin/feature-flags/${id}/toggle`, { method: 'POST' }),
    onMutate: async (id) => {
      await qc.cancelQueries({ queryKey: ['feature-flags'] })
      const prev = qc.getQueryData<FlagsResponse>(['feature-flags'])
      qc.setQueryData<FlagsResponse>(['feature-flags'], old => old ? {
        ...old,
        flags: old.flags.map(f => f.id === id ? { ...f, enabled: !f.enabled } : f),
      } : old)
      return { prev }
    },
    onError: (_e, _id, ctx) => { if (ctx?.prev) qc.setQueryData(['feature-flags'], ctx.prev) },
    onSettled: () => qc.invalidateQueries({ queryKey: ['feature-flags'] }),
  })

  const createMutation = useMutation({
    mutationFn: (body: Omit<FlagFormState, 'metadata'> & { metadata?: unknown }) =>
      apiFetch<FeatureFlag>('/api/v1/admin/feature-flags', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setShowCreate(false) },
    onError: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setShowCreate(false) },
  })

  const editMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: unknown }) =>
      apiFetch<FeatureFlag>(`/api/v1/admin/feature-flags/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setEditFlag(null) },
    onError: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setEditFlag(null) },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/feature-flags/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setDeleteFlag(null) },
    onError: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setDeleteFlag(null) },
  })

  const rolloutMutation = useMutation({
    mutationFn: ({ id, pct }: { id: string; pct: number }) =>
      apiFetch(`/api/v1/admin/feature-flags/${id}/rollout`, { method: 'POST', body: JSON.stringify({ rollout_percentage: pct }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setRolloutFlag(null) },
    onError: () => { qc.invalidateQueries({ queryKey: ['feature-flags'] }); setRolloutFlag(null) },
  })

  const evaluateMutation = useMutation({
    mutationFn: (req: EvaluateRequest) =>
      apiFetch<EvaluateResponse>('/api/v1/admin/feature-flags/evaluate', { method: 'POST', body: JSON.stringify(req) }),
    onSuccess: (res) => setEvalResult(res),
    onError: () => setEvalResult({ enabled: false, reason: '評価エラーが発生しました (モック: フラグが見つかりません)' }),
  })

  // ── Handlers ─────────────────────────────────────────────────

  const handleCreate = (form: FlagFormState) => {
    let meta: unknown = undefined
    if (form.metadata.trim()) {
      try { meta = JSON.parse(form.metadata) } catch { /* ignore */ }
    }
    createMutation.mutate({ ...form, metadata: meta })
  }

  const handleEdit = (form: FlagFormState) => {
    if (!editFlag) return
    let meta: unknown = undefined
    if (form.metadata.trim()) {
      try { meta = JSON.parse(form.metadata) } catch { /* ignore */ }
    }
    editMutation.mutate({ id: editFlag.id, body: { ...form, metadata: meta } })
  }

  // ── Render helpers ────────────────────────────────────────────

  const StatCard = ({ label, value, color }: { label: string; value: number; color: string }) => (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
      <p className="text-[#7d92b0] text-xs mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )

  // ── List Row ───────────────────────────────────────────────────

  const FlagRow = ({ flag }: { flag: FeatureFlag }) => {
    const status = getStatus(flag)
    return (
      <tr className="hover:bg-[#0a1628] transition-colors group">
        <td className="px-4 py-3">
          <span className="font-mono text-sm text-white">{flag.name}</span>
          {flag.protected && (
            <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded bg-[#e8002d]/10 text-[#e8002d] border border-[#e8002d]/20 uppercase">保護</span>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-[#7d92b0] max-w-[200px] truncate">{flag.description}</td>
        <td className="px-4 py-3">
          <span className={`text-[11px] px-2 py-0.5 rounded-full border font-medium ${STATUS_COLORS[status]}`}>
            {STATUS_LABELS[status]}
          </span>
        </td>
        <td className="px-4 py-3 w-[140px]">
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${flag.rollout_percentage === 100 ? 'bg-green-500' : flag.rollout_percentage > 0 ? 'bg-yellow-500' : 'bg-[#3d5068]'}`}
                style={{ width: `${flag.rollout_percentage}%` }}
              />
            </div>
            <span className="text-xs text-[#7d92b0] w-8 text-right">{flag.rollout_percentage}%</span>
          </div>
        </td>
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-1">
            {flag.target_roles.map(r => (
              <span key={r} className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]">{r}</span>
            ))}
          </div>
        </td>
        <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{fmtDate(flag.created_at)}</td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1">
            {/* Toggle */}
            <button
              onClick={() => toggleMutation.mutate(flag.id)}
              disabled={toggleMutation.isPending}
              title={flag.enabled ? '無効化' : '有効化'}
              className="p-1.5 rounded hover:bg-[#1e2d42] transition-colors"
            >
              {flag.enabled
                ? <ToggleRight className="w-4 h-4 text-green-400" />
                : <ToggleLeft className="w-4 h-4 text-[#3d5068]" />}
            </button>
            {/* Rollout */}
            <button
              onClick={() => { setRolloutFlag(flag); setRolloutPct(flag.rollout_percentage) }}
              title="ロールアウト設定"
              className="p-1.5 rounded hover:bg-[#1e2d42] transition-colors text-[#7d92b0] hover:text-white"
            >
              <Sliders className="w-3.5 h-3.5" />
            </button>
            {/* Edit */}
            <button
              onClick={() => setEditFlag(flag)}
              className="p-1.5 rounded hover:bg-[#1e2d42] transition-colors text-[#7d92b0] hover:text-white"
            >
              <Edit2 className="w-3.5 h-3.5" />
            </button>
            {/* Delete */}
            <button
              onClick={() => !flag.protected && setDeleteFlag(flag)}
              disabled={flag.protected}
              className="p-1.5 rounded hover:bg-[#1e2d42] transition-colors text-[#7d92b0] hover:text-[#e8002d] disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </td>
      </tr>
    )
  }

  // ── Card ───────────────────────────────────────────────────────

  const FlagCard = ({ flag }: { flag: FeatureFlag }) => {
    const status = getStatus(flag)
    return (
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 flex flex-col gap-4">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm text-white font-semibold">{flag.name}</span>
              {flag.protected && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#e8002d]/10 text-[#e8002d] border border-[#e8002d]/20 uppercase">保護</span>
              )}
              <span className={`text-[11px] px-2 py-0.5 rounded-full border font-medium ${STATUS_COLORS[status]}`}>
                {STATUS_LABELS[status]}
              </span>
            </div>
            <p className="text-xs text-[#7d92b0] mt-1 line-clamp-2">{flag.description}</p>
          </div>
          <DonutChart pct={flag.rollout_percentage} />
        </div>

        <div className="flex flex-wrap gap-1">
          <span className="text-[10px] text-[#3d5068]">対象:</span>
          {flag.target_roles.map(r => (
            <span key={r} className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]">{r}</span>
          ))}
        </div>

        <div className="flex items-center justify-between border-t border-[#1e2d42] pt-3">
          <div className="flex items-center gap-1">
            <button
              onClick={() => toggleMutation.mutate(flag.id)}
              disabled={toggleMutation.isPending}
              className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full border transition-colors ${
                flag.enabled
                  ? 'bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20'
                  : 'bg-[#1e2d42] border-[#1e2d42] text-[#7d92b0] hover:text-white'
              }`}
            >
              {flag.enabled ? <ToggleRight className="w-3.5 h-3.5" /> : <ToggleLeft className="w-3.5 h-3.5" />}
              {flag.enabled ? '有効' : '無効'}
            </button>
            <button
              onClick={() => { setRolloutFlag(flag); setRolloutPct(flag.rollout_percentage) }}
              className="p-1.5 rounded hover:bg-[#1e2d42] transition-colors text-[#7d92b0] hover:text-white"
            >
              <Sliders className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={() => setEditFlag(flag)} className="p-1.5 rounded hover:bg-[#1e2d42] transition-colors text-[#7d92b0] hover:text-white">
              <Edit2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => !flag.protected && setDeleteFlag(flag)}
              disabled={flag.protected}
              className="p-1.5 rounded hover:bg-[#1e2d42] transition-colors text-[#7d92b0] hover:text-[#e8002d] disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ── Render ────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] p-6">

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
              <Flag className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h1 className="text-xl font-bold text-white">フィーチャーフラグ</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">機能のON/OFF・段階的ロールアウトの管理</p>
        </div>
        <div className="flex items-center gap-2">
          {/* View toggle */}
          <div className="flex items-center bg-[#0d1220] border border-[#1e2d42] rounded p-0.5">
            <button
              onClick={() => setView('list')}
              className={`p-1.5 rounded transition-colors ${view === 'list' ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
            >
              <LayoutList className="w-4 h-4" />
            </button>
            <button
              onClick={() => setView('card')}
              className={`p-1.5 rounded transition-colors ${view === 'card' ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
            >
              <LayoutGrid className="w-4 h-4" />
            </button>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-3 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded transition-colors"
          >
            <Plus className="w-4 h-4" />
            フラグ作成
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <StatCard label="総フラグ数" value={stats.total} color="text-white" />
        <StatCard label="有効" value={stats.enabled} color="text-green-400" />
        <StatCard label="無効" value={stats.disabled} color="text-[#e8002d]" />
        <StatCard label="部分展開" value={stats.partial} color="text-yellow-400" />
      </div>

      {/* Main content */}
      {isLoading ? (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-12 text-center text-[#7d92b0] text-sm">読み込み中...</div>
      ) : view === 'list' ? (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['フラグ名', '説明', 'ステータス', 'ロールアウト', '対象ロール', '作成日', 'アクション'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {flags.map(f => <FlagRow key={f.id} flag={f} />)}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {flags.map(f => <FlagCard key={f.id} flag={f} />)}
        </div>
      )}

      {/* Evaluate panel */}
      <div className="mt-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg">
        <button
          onClick={() => setEvalOpen(o => !o)}
          className="w-full flex items-center justify-between px-5 py-4 text-sm font-semibold text-white hover:bg-[#0a1628] transition-colors rounded-lg"
        >
          <span className="flex items-center gap-2">
            <Flag className="w-4 h-4 text-[#e8002d]" />
            フラグ評価テスト
          </span>
          {evalOpen ? <ChevronUp className="w-4 h-4 text-[#7d92b0]" /> : <ChevronDown className="w-4 h-4 text-[#7d92b0]" />}
        </button>

        {evalOpen && (
          <div className="px-5 pb-5 border-t border-[#1e2d42] pt-4 space-y-4">
            <div className="flex flex-wrap gap-3">
              {/* Flag name */}
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#7d92b0]">フラグ名</label>
                <select
                  value={evalForm.flag_name}
                  onChange={e => setEvalForm(f => ({ ...f, flag_name: e.target.value }))}
                  className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50 w-48"
                >
                  <option value="">選択...</option>
                  {flags.map(f => <option key={f.id} value={f.name}>{f.name}</option>)}
                </select>
              </div>
              {/* User ID */}
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#7d92b0]">ユーザーID</label>
                <input
                  value={evalForm.user_id}
                  onChange={e => setEvalForm(f => ({ ...f, user_id: e.target.value }))}
                  placeholder="user-123"
                  className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 w-40"
                />
              </div>
              {/* Role */}
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#7d92b0]">ロール</label>
                <select
                  value={evalForm.role}
                  onChange={e => setEvalForm(f => ({ ...f, role: e.target.value }))}
                  className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50"
                >
                  {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1 justify-end">
                <button
                  onClick={() => evaluateMutation.mutate(evalForm)}
                  disabled={!evalForm.flag_name || !evalForm.user_id || evaluateMutation.isPending}
                  className="px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm rounded transition-colors disabled:opacity-50"
                >
                  {evaluateMutation.isPending ? '評価中...' : '評価'}
                </button>
              </div>
            </div>

            {evalResult && (
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 flex items-start gap-3">
                {evalResult.enabled ? (
                  <Check className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <X className="w-5 h-5 text-[#e8002d] flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <span className={`text-sm font-semibold ${evalResult.enabled ? 'text-green-400' : 'text-[#e8002d]'}`}>
                    {evalResult.enabled ? 'YES — 有効' : 'NO — 無効'}
                  </span>
                  <p className="text-xs text-[#7d92b0] mt-1">{evalResult.reason}</p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Modals ─────────────────────────────────────────────── */}

      {/* Create */}
      {showCreate && (
        <Modal title="フラグ作成" onClose={() => setShowCreate(false)}>
          <FlagForm
            onSubmit={handleCreate}
            onCancel={() => setShowCreate(false)}
            submitting={createMutation.isPending}
          />
        </Modal>
      )}

      {/* Edit */}
      {editFlag && (
        <Modal title={`フラグ編集: ${editFlag.name}`} onClose={() => setEditFlag(null)}>
          <FlagForm
            initial={{
              name: editFlag.name,
              description: editFlag.description,
              enabled: editFlag.enabled,
              rollout_percentage: editFlag.rollout_percentage,
              target_roles: editFlag.target_roles,
              metadata: editFlag.metadata ? JSON.stringify(editFlag.metadata, null, 2) : '',
            }}
            onSubmit={handleEdit}
            onCancel={() => setEditFlag(null)}
            submitting={editMutation.isPending}
          />
        </Modal>
      )}

      {/* Delete confirm */}
      {deleteFlag && (
        <Modal title="フラグ削除" onClose={() => setDeleteFlag(null)}>
          <div className="space-y-4">
            <div className="flex items-start gap-3 p-3 rounded-lg bg-[#e8002d]/5 border border-[#e8002d]/20">
              <AlertTriangle className="w-5 h-5 text-[#e8002d] flex-shrink-0 mt-0.5" />
              <p className="text-sm text-[#e2e8f4]">
                フラグ <span className="font-mono font-semibold">{deleteFlag.name}</span> を削除しますか？この操作は元に戻せません。
              </p>
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setDeleteFlag(null)} className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded hover:border-[#7d92b0]/40 transition-colors">
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteFlag.id)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-xs text-white bg-[#e8002d] hover:bg-[#c8001f] rounded transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Rollout */}
      {rolloutFlag && (
        <Modal title={`ロールアウト設定: ${rolloutFlag.name}`} onClose={() => setRolloutFlag(null)}>
          <div className="space-y-5">
            <div>
              <p className="text-xs text-[#7d92b0] mb-3">
                ロールアウト率 — <span className="text-white font-semibold">{rolloutPct}% のユーザーに有効</span>
              </p>
              <input
                type="range" min={0} max={100}
                value={rolloutPct}
                onChange={e => setRolloutPct(Number(e.target.value))}
                className="w-full accent-[#e8002d]"
              />
              <div className="flex justify-between text-[10px] text-[#3d5068] mt-1">
                <span>0% (全無効)</span>
                <span className="text-yellow-400">50%</span>
                <span>100% (全有効)</span>
              </div>
            </div>
            <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${rolloutPct === 100 ? 'bg-green-500' : rolloutPct > 0 ? 'bg-yellow-500' : 'bg-[#3d5068]'}`}
                style={{ width: `${rolloutPct}%` }}
              />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setRolloutFlag(null)} className="px-4 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded hover:border-[#7d92b0]/40 transition-colors">
                キャンセル
              </button>
              <button
                onClick={() => rolloutMutation.mutate({ id: rolloutFlag.id, pct: rolloutPct })}
                disabled={rolloutMutation.isPending}
                className="px-4 py-2 text-xs text-white bg-[#e8002d] hover:bg-[#c8001f] rounded transition-colors disabled:opacity-50"
              >
                {rolloutMutation.isPending ? '更新中...' : '更新'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
