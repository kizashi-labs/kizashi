'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Layers, X, ChevronUp, ChevronDown, CheckSquare, Square,
  Filter, Save, Trash2, Tag, AlertTriangle, UserCheck,
  XCircle, TrendingUp, ShieldOff, ChevronLeft, ChevronRight,
  Search, Calendar, RefreshCw, Loader2,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Alert {
  id: string
  title: string
  severity: number
  status: string
  agent_id?: string
  agent_hostname?: string
  assigned_to?: string
  created_at: string
  tags?: string[]
}

interface AlertsResponse {
  data: Alert[]
  total: number
  page: number
  per_page: number
}

interface FilterPreset {
  id: string
  name: string
  filters: FilterState
}

interface FilterState {
  severities: number[]
  statuses: string[]
  agent: string
  dateFrom: string
  dateTo: string
  search: string
}

interface SortState {
  column: string
  direction: 'asc' | 'desc'
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_LABELS: Record<number, string> = {
  1: 'INFO',
  2: 'LOW',
  3: 'MEDIUM',
  4: 'HIGH',
  5: 'CRITICAL',
}

const SEVERITY_COLORS: Record<number, string> = {
  1: 'bg-slate-700 text-slate-300',
  2: 'bg-blue-900/60 text-blue-300',
  3: 'bg-yellow-900/60 text-yellow-300',
  4: 'bg-orange-900/60 text-orange-300',
  5: 'bg-red-900/60 text-red-400',
}

const STATUS_LABELS: Record<string, string> = {
  open: 'オープン',
  closed: 'クローズ',
  in_progress: '対応中',
  false_positive: '誤検知',
}

const STATUS_COLORS: Record<string, string> = {
  open: 'text-red-400',
  closed: 'text-slate-400',
  in_progress: 'text-yellow-400',
  false_positive: 'text-slate-500',
}

const DEFAULT_FILTER: FilterState = {
  severities: [],
  statuses: [],
  agent: '',
  dateFrom: '',
  dateTo: '',
  search: '',
}

const DEFAULT_PRESETS: FilterPreset[] = [
  {
    id: 'critical-open',
    name: 'Critical Open',
    filters: { ...DEFAULT_FILTER, severities: [5], statuses: ['open'] },
  },
  {
    id: 'unassigned-high',
    name: 'Unassigned High',
    filters: { ...DEFAULT_FILTER, severities: [4, 5], statuses: ['open'] },
  },
  {
    id: 'todays-alerts',
    name: "Today's Alerts",
    filters: {
      ...DEFAULT_FILTER,
      dateFrom: new Date().toISOString().split('T')[0],
      dateTo: new Date().toISOString().split('T')[0],
    },
  },
]

const PRESETS_KEY = 'edr_triage_presets'
const PER_PAGE = 50

// ─── Helper: load/save presets ────────────────────────────────────────────────

function loadPresets(): FilterPreset[] {
  if (typeof window === 'undefined') return DEFAULT_PRESETS
  try {
    const raw = localStorage.getItem(PRESETS_KEY)
    if (!raw) return DEFAULT_PRESETS
    const saved: FilterPreset[] = JSON.parse(raw)
    // Merge: defaults first, then user-saved (by id dedup)
    const merged = [...DEFAULT_PRESETS]
    for (const p of saved) {
      if (!merged.find(x => x.id === p.id)) merged.push(p)
    }
    return merged
  } catch {
    return DEFAULT_PRESETS
  }
}

function savePresets(presets: FilterPreset[]) {
  // Only save non-default presets to localStorage
  const custom = presets.filter(p => !DEFAULT_PRESETS.find(d => d.id === p.id))
  localStorage.setItem(PRESETS_KEY, JSON.stringify(custom))
}

// ─── Severity Badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: number }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] font-bold uppercase tracking-wide ${SEVERITY_COLORS[severity] ?? 'bg-slate-700 text-slate-300'}`}>
      {SEVERITY_LABELS[severity] ?? `SEV${severity}`}
    </span>
  )
}

// ─── Resolution Note Modal ────────────────────────────────────────────────────

function ResolutionModal({
  count,
  onConfirm,
  onCancel,
}: {
  count: number
  onConfirm: (note: string) => void
  onCancel: () => void
}) {
  const [note, setNote] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-md shadow-xl">
        <h3 className="text-white font-semibold text-lg mb-1">アラートをクローズ</h3>
        <p className="text-[#7d92b0] text-sm mb-4">{count} 件のアラートをクローズします。解決メモを入力してください。</p>
        <textarea
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm text-[#e2e8f4] text-sm p-3 resize-none focus:outline-hidden focus:border-[#e8002d]/50 h-28"
          placeholder="解決メモ（任意）"
          value={note}
          onChange={e => setNote(e.target.value)}
        />
        <div className="flex gap-3 mt-4 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onConfirm(note)}
            className="px-4 py-2 text-sm text-white bg-[#e8002d] hover:bg-[#c0001f] rounded-sm transition-colors"
          >
            クローズ実行
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Tag Input Modal ──────────────────────────────────────────────────────────

function TagModal({
  count,
  onConfirm,
  onCancel,
}: {
  count: number
  onConfirm: (tag: string) => void
  onCancel: () => void
}) {
  const [tag, setTag] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-sm shadow-xl">
        <h3 className="text-white font-semibold text-lg mb-1">タグを追加</h3>
        <p className="text-[#7d92b0] text-sm mb-4">{count} 件のアラートにタグを追加します。</p>
        <input
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm text-[#e2e8f4] text-sm p-2 focus:outline-hidden focus:border-[#e8002d]/50"
          placeholder="タグ名を入力..."
          value={tag}
          onChange={e => setTag(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && tag.trim()) onConfirm(tag.trim()) }}
        />
        <div className="flex gap-3 mt-4 justify-end">
          <button onClick={onCancel} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => tag.trim() && onConfirm(tag.trim())}
            className="px-4 py-2 text-sm text-white bg-[#1a6bff] hover:bg-[#0044cc] rounded-sm transition-colors"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Assign To Modal ──────────────────────────────────────────────────────────

function AssignModal({
  count,
  onConfirm,
  onCancel,
}: {
  count: number
  onConfirm: (userId: string) => void
  onCancel: () => void
}) {
  const [userId, setUserId] = useState('')
  const { data: users } = useQuery<{ users: { id: string; full_name: string; email: string }[] }>({
    queryKey: ['users-list'],
    queryFn: () => apiFetch('/api/v1/users'),
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-sm shadow-xl">
        <h3 className="text-white font-semibold text-lg mb-1">担当者を割り当て</h3>
        <p className="text-[#7d92b0] text-sm mb-4">{count} 件のアラートに担当者を割り当てます。</p>
        <select
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm text-[#e2e8f4] text-sm p-2 focus:outline-hidden focus:border-[#e8002d]/50"
          value={userId}
          onChange={e => setUserId(e.target.value)}
        >
          <option value="">ユーザーを選択...</option>
          {users?.users?.map(u => (
            <option key={u.id} value={u.id}>{u.full_name || u.email}</option>
          ))}
        </select>
        <div className="flex gap-3 mt-4 justify-end">
          <button onClick={onCancel} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => userId && onConfirm(userId)}
            className="px-4 py-2 text-sm text-white bg-[#1a6bff] hover:bg-[#0044cc] rounded-sm transition-colors"
          >
            割り当て
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Save Preset Modal ────────────────────────────────────────────────────────

function SavePresetModal({
  onConfirm,
  onCancel,
}: {
  onConfirm: (name: string) => void
  onCancel: () => void
}) {
  const [name, setName] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-full max-w-sm shadow-xl">
        <h3 className="text-white font-semibold text-lg mb-1">フィルタープリセットを保存</h3>
        <p className="text-[#7d92b0] text-sm mb-4">現在のフィルター条件をプリセットとして保存します。</p>
        <input
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm text-[#e2e8f4] text-sm p-2 focus:outline-hidden focus:border-[#e8002d]/50"
          placeholder="プリセット名を入力..."
          value={name}
          onChange={e => setName(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && name.trim()) onConfirm(name.trim()) }}
        />
        <div className="flex gap-3 mt-4 justify-end">
          <button onClick={onCancel} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => name.trim() && onConfirm(name.trim())}
            className="px-4 py-2 text-sm text-white bg-[#1a6bff] hover:bg-[#0044cc] rounded-sm transition-colors"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Column sort header ───────────────────────────────────────────────────────

function SortHeader({
  label,
  column,
  sort,
  onSort,
  className,
}: {
  label: string
  column: string
  sort: SortState
  onSort: (col: string) => void
  className?: string
}) {
  const active = sort.column === column
  return (
    <th
      className={`px-3 py-2 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide cursor-pointer select-none hover:text-[#e2e8f4] transition-colors ${className ?? ''}`}
      onClick={() => onSort(column)}
    >
      <span className="flex items-center gap-1">
        {label}
        {active ? (
          sort.direction === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
        ) : (
          <span className="w-3 h-3 opacity-0 group-hover:opacity-40"><ChevronUp className="w-3 h-3" /></span>
        )}
      </span>
    </th>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function TriagePage() {
  const queryClient = useQueryClient()

  // ── State ──────────────────────────────────────────────────────────────────
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTER)
  const [sort, setSort] = useState<SortState>({ column: 'created_at', direction: 'desc' })
  const [page, setPage] = useState(1)
  const [presets, setPresets] = useState<FilterPreset[]>(DEFAULT_PRESETS)
  const [modal, setModal] = useState<'close' | 'tag' | 'assign' | 'save_preset' | null>(null)

  // Load presets from localStorage once on mount
  useEffect(() => {
    setPresets(loadPresets())
  }, [])

  // ── Build query params ─────────────────────────────────────────────────────
  const queryParams = useMemo(() => {
    const p = new URLSearchParams()
    p.set('page', String(page))
    p.set('per_page', String(PER_PAGE))
    p.set('sort_by', sort.column)
    p.set('sort_dir', sort.direction)
    if (filters.severities.length) p.set('severity', filters.severities.join(','))
    if (filters.statuses.length) p.set('status', filters.statuses.join(','))
    if (filters.agent) p.set('agent_id', filters.agent)
    if (filters.dateFrom) p.set('date_from', filters.dateFrom)
    if (filters.dateTo) p.set('date_to', filters.dateTo)
    if (filters.search) p.set('search', filters.search)
    return p.toString()
  }, [page, sort, filters])

  // ── Data fetch ─────────────────────────────────────────────────────────────
  const { data, isLoading, isFetching } = useQuery<AlertsResponse>({
    queryKey: ['triage-alerts', queryParams],
    queryFn: () => apiFetch(`/api/v1/alerts?${queryParams}`),
    staleTime: 15_000,
  })

  const { data: agentsData } = useQuery<{ data: { id: string; hostname: string }[] }>({
    queryKey: ['agents-list-triage'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=200'),
    staleTime: 60_000,
  })
  const agentOptions = agentsData?.data ?? []

  const alerts = data?.data ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  // ── Batch mutation ─────────────────────────────────────────────────────────
  const batchMutation = useMutation({
    mutationFn: async (payload: {
      ids: string[]
      action: string
      user_id?: string
      note?: string
      tag?: string
    }) => {
      try {
        return await apiFetch('/api/v1/alerts/batch', {
          method: 'PUT',
          body: JSON.stringify(payload),
        })
      } catch (err: unknown) {
        // If batch endpoint returns 404, fall back to individual mutations
        const msg = err instanceof Error ? err.message : String(err)
        if (msg.includes('404') || msg.includes('HTTP 404')) {
          return Promise.all(
            payload.ids.map(id =>
              apiFetch(`/api/v1/alerts/${id}`, {
                method: 'PUT',
                body: JSON.stringify({
                  action: payload.action,
                  user_id: payload.user_id,
                  note: payload.note,
                  tag: payload.tag,
                }),
              })
            )
          )
        }
        throw err
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['triage-alerts'] })
      setSelected(new Set())
      setModal(null)
    },
  })

  // ── Selection helpers ──────────────────────────────────────────────────────
  const allIds = useMemo(() => alerts.map(a => a.id), [alerts])
  const allSelected = allIds.length > 0 && allIds.every(id => selected.has(id))
  const someSelected = allIds.some(id => selected.has(id)) && !allSelected

  const toggleAll = useCallback(() => {
    if (allSelected) {
      setSelected(prev => {
        const next = new Set(prev)
        allIds.forEach(id => next.delete(id))
        return next
      })
    } else {
      setSelected(prev => {
        const next = new Set(prev)
        allIds.forEach(id => next.add(id))
        return next
      })
    }
  }, [allIds, allSelected])

  const toggleOne = useCallback((id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  // ── Sort handler ───────────────────────────────────────────────────────────
  const handleSort = useCallback((col: string) => {
    setSort(prev =>
      prev.column === col
        ? { column: col, direction: prev.direction === 'asc' ? 'desc' : 'asc' }
        : { column: col, direction: 'asc' }
    )
    setPage(1)
  }, [])

  // ── Filter change → reset page ─────────────────────────────────────────────
  const updateFilter = useCallback(<K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters(prev => ({ ...prev, [key]: value }))
    setPage(1)
    setSelected(new Set())
  }, [])

  // ── Presets ────────────────────────────────────────────────────────────────
  const applyPreset = useCallback((preset: FilterPreset) => {
    setFilters(preset.filters)
    setPage(1)
    setSelected(new Set())
  }, [])

  const handleSavePreset = useCallback((name: string) => {
    const newPreset: FilterPreset = {
      id: `custom-${Date.now()}`,
      name,
      filters: { ...filters },
    }
    const updated = [...presets, newPreset]
    setPresets(updated)
    savePresets(updated)
    setModal(null)
  }, [filters, presets])

  const deletePreset = useCallback((id: string) => {
    if (DEFAULT_PRESETS.find(p => p.id === id)) return // Can't delete defaults
    const updated = presets.filter(p => p.id !== id)
    setPresets(updated)
    savePresets(updated)
  }, [presets])

  // ── Batch actions ──────────────────────────────────────────────────────────
  const selectedIds = useMemo(() => Array.from(selected), [selected])

  const handleEscalate = () => {
    batchMutation.mutate({ ids: selectedIds, action: 'escalate' })
  }

  const handleFalsePositive = () => {
    batchMutation.mutate({ ids: selectedIds, action: 'false_positive' })
  }

  // ── Severity multi-select helper ───────────────────────────────────────────
  const toggleSeverity = (sev: number) => {
    const cur = filters.severities
    updateFilter('severities', cur.includes(sev) ? cur.filter(s => s !== sev) : [...cur, sev])
  }

  const toggleStatus = (status: string) => {
    const cur = filters.statuses
    updateFilter('statuses', cur.includes(status) ? cur.filter(s => s !== status) : [...cur, status])
  }

  // ── Format date ────────────────────────────────────────────────────────────
  const formatDate = (iso: string) => {
    if (!iso) return '-'
    const d = new Date(iso)
    return d.toLocaleString('ja-JP', { dateStyle: 'short', timeStyle: 'short' })
  }

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-screen bg-[#070d19] overflow-hidden">
      <PageDataUnavailable />

      {/* ── Left Sidebar: Filter Presets ─────────────────────────────────── */}
      <aside className="w-56 shrink-0 bg-[#0d1220] border-r border-[#1e2d42] flex flex-col overflow-hidden">
        <div className="p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2 mb-3">
            <Filter className="w-4 h-4 text-[#e8002d]" />
            <span className="text-[#e2e8f4] text-sm font-semibold">フィルタープリセット</span>
          </div>
          <button
            onClick={() => setModal('save_preset')}
            className="w-full flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs text-[#7d92b0] border border-[#1e2d42] hover:border-[#7d92b0]/40 hover:text-[#e2e8f4] transition-colors"
          >
            <Save className="w-3 h-3" />
            現在のフィルターを保存
          </button>
        </div>
        <nav className="flex-1 overflow-y-auto p-2 space-y-0.5">
          {presets.map(preset => {
            const isDefault = DEFAULT_PRESETS.find(d => d.id === preset.id)
            return (
              <div key={preset.id} className="group flex items-center gap-1">
                <button
                  onClick={() => applyPreset(preset)}
                  className="flex-1 text-left px-3 py-2 rounded-sm text-xs text-[#7d92b0] hover:bg-[#19253d] hover:text-[#e2e8f4] transition-colors truncate"
                >
                  {preset.name}
                </button>
                {!isDefault && (
                  <button
                    onClick={() => deletePreset(preset.id)}
                    className="opacity-0 group-hover:opacity-100 p-1 text-[#3d5068] hover:text-[#e8002d] transition-all"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                )}
              </div>
            )
          })}
        </nav>
      </aside>

      {/* ── Main Area ────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* ── Page Header ────────────────────────────────────────────────── */}
        <div className="bg-[#0d1220] border-b border-[#1e2d42] px-6 py-4 shrink-0">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-sm bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
              <Layers className="w-4 h-4 text-white" />
            </div>
            <div>
              <h1 className="text-white font-bold text-lg leading-none">アラートトリアージ</h1>
              <p className="text-[#7d92b0] text-xs mt-0.5">
                {isLoading ? '読み込み中...' : `${total.toLocaleString()} 件のアラート`}
              </p>
            </div>
            {isFetching && !isLoading && (
              <Loader2 className="w-4 h-4 text-[#7d92b0] animate-spin ml-2" />
            )}
          </div>

          {/* ── Filter Bar ───────────────────────────────────────────────── */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
            {/* Search */}
            <div className="relative lg:col-span-2">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
              <input
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm pl-8 pr-3 py-1.5 text-sm text-[#e2e8f4] placeholder:text-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                placeholder="タイトル、エージェント名で検索..."
                value={filters.search}
                onChange={e => updateFilter('search', e.target.value)}
              />
            </div>

            {/* Agent */}
            <select
              className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#e8002d]/50"
              value={filters.agent}
              onChange={e => { updateFilter('agent', e.target.value); setPage(1) }}
            >
              <option value="">すべてのエージェント</option>
              {agentOptions.map(a => (
                <option key={a.id} value={a.id}>{a.hostname}</option>
              ))}
            </select>

            {/* Date From */}
            <div className="relative">
              <Calendar className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
              <input
                type="date"
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm pl-8 pr-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#e8002d]/50"
                value={filters.dateFrom}
                onChange={e => updateFilter('dateFrom', e.target.value)}
              />
            </div>

            {/* Date To */}
            <div className="relative">
              <Calendar className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
              <input
                type="date"
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm pl-8 pr-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#e8002d]/50"
                value={filters.dateTo}
                onChange={e => updateFilter('dateTo', e.target.value)}
              />
            </div>
          </div>

          {/* Severity + Status chips */}
          <div className="flex flex-wrap gap-2 mt-2">
            <div className="flex gap-1">
              <span className="text-[#7d92b0] text-xs self-center mr-1">深刻度:</span>
              {[5, 4, 3, 2, 1].map(sev => (
                <button
                  key={sev}
                  onClick={() => toggleSeverity(sev)}
                  className={`px-2 py-0.5 rounded-sm text-[10px] font-bold uppercase transition-all border ${
                    filters.severities.includes(sev)
                      ? 'border-[#e8002d]/60 opacity-100 ' + SEVERITY_COLORS[sev]
                      : 'border-[#1e2d42] opacity-50 ' + SEVERITY_COLORS[sev]
                  }`}
                >
                  {SEVERITY_LABELS[sev]}
                </button>
              ))}
            </div>
            <div className="flex gap-1 ml-4">
              <span className="text-[#7d92b0] text-xs self-center mr-1">ステータス:</span>
              {Object.entries(STATUS_LABELS).map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => toggleStatus(key)}
                  className={`px-2 py-0.5 rounded-sm text-[10px] font-medium transition-all border ${
                    filters.statuses.includes(key)
                      ? 'border-[#1a6bff]/60 bg-[#1a6bff]/20 text-white'
                      : 'border-[#1e2d42] text-[#7d92b0]'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            {(filters.severities.length > 0 || filters.statuses.length > 0 || filters.search || filters.agent || filters.dateFrom || filters.dateTo) && (
              <button
                onClick={() => { setFilters(DEFAULT_FILTER); setPage(1) }}
                className="ml-auto flex items-center gap-1 text-xs text-[#7d92b0] hover:text-[#e8002d] transition-colors"
              >
                <X className="w-3 h-3" />
                フィルタークリア
              </button>
            )}
          </div>
        </div>

        {/* ── Sticky Action Bar ─────────────────────────────────────────── */}
        {selected.size > 0 && (
          <div className="shrink-0 bg-[#0d1220] border-b border-[#e8002d]/30 px-6 py-2 flex items-center gap-3 flex-wrap">
            <span className="text-[#e8002d] font-semibold text-sm">
              {selected.size} 件選択中
            </span>
            <div className="flex items-center gap-2 flex-wrap">

              {/* Assign */}
              <button
                onClick={() => setModal('assign')}
                disabled={batchMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-medium bg-[#1a6bff]/20 text-[#1a6bff] border border-[#1a6bff]/30 hover:bg-[#1a6bff]/30 transition-colors disabled:opacity-50"
              >
                <UserCheck className="w-3.5 h-3.5" />
                担当者割り当て
              </button>

              {/* Close */}
              <button
                onClick={() => setModal('close')}
                disabled={batchMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-medium bg-slate-700/50 text-slate-300 border border-slate-600/30 hover:bg-slate-700 transition-colors disabled:opacity-50"
              >
                <XCircle className="w-3.5 h-3.5" />
                クローズ
              </button>

              {/* Escalate */}
              <button
                onClick={handleEscalate}
                disabled={batchMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-medium bg-orange-900/30 text-orange-400 border border-orange-700/30 hover:bg-orange-900/50 transition-colors disabled:opacity-50"
              >
                <TrendingUp className="w-3.5 h-3.5" />
                エスカレート
              </button>

              {/* Add Tag */}
              <button
                onClick={() => setModal('tag')}
                disabled={batchMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-medium bg-purple-900/30 text-purple-400 border border-purple-700/30 hover:bg-purple-900/50 transition-colors disabled:opacity-50"
              >
                <Tag className="w-3.5 h-3.5" />
                タグ追加
              </button>

              {/* False Positive */}
              <button
                onClick={handleFalsePositive}
                disabled={batchMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-medium bg-yellow-900/30 text-yellow-400 border border-yellow-700/30 hover:bg-yellow-900/50 transition-colors disabled:opacity-50"
              >
                <ShieldOff className="w-3.5 h-3.5" />
                誤検知
              </button>

              {/* Refresh */}
              <button
                onClick={() => queryClient.invalidateQueries({ queryKey: ['triage-alerts'] })}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-medium text-[#7d92b0] border border-[#1e2d42] hover:text-[#e2e8f4] transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                更新
              </button>
            </div>

            {batchMutation.isPending && (
              <Loader2 className="w-4 h-4 text-[#7d92b0] animate-spin ml-2" />
            )}
            {batchMutation.isError && (
              <span className="text-[#e8002d] text-xs flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                操作に失敗しました
              </span>
            )}

            <button
              onClick={() => setSelected(new Set())}
              className="ml-auto text-[#7d92b0] hover:text-[#e8002d] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* ── Table ─────────────────────────────────────────────────────── */}
        <div className="flex-1 overflow-auto">
          <table className="w-full border-collapse text-sm">
            <thead className="sticky top-0 z-10 bg-[#0d1220] border-b border-[#1e2d42]">
              <tr>
                {/* Checkbox column */}
                <th className="px-3 py-2 w-10">
                  <button
                    onClick={toggleAll}
                    className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                  >
                    {allSelected ? (
                      <CheckSquare className="w-4 h-4 text-[#e8002d]" />
                    ) : someSelected ? (
                      <CheckSquare className="w-4 h-4 text-[#e8002d] opacity-50" />
                    ) : (
                      <Square className="w-4 h-4" />
                    )}
                  </button>
                </th>
                <SortHeader label="深刻度" column="severity" sort={sort} onSort={handleSort} className="w-24" />
                <SortHeader label="タイトル" column="title" sort={sort} onSort={handleSort} />
                <SortHeader label="エージェント" column="agent_hostname" sort={sort} onSort={handleSort} className="w-40" />
                <SortHeader label="ステータス" column="status" sort={sort} onSort={handleSort} className="w-28" />
                <SortHeader label="作成日時" column="created_at" sort={sort} onSort={handleSort} className="w-36" />
                <SortHeader label="担当者" column="assigned_to" sort={sort} onSort={handleSort} className="w-32" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]/60">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-20 text-center text-[#7d92b0]">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto mb-2 text-[#e8002d]" />
                    <p className="text-sm">読み込み中...</p>
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-20 text-center text-[#7d92b0]">
                    <ShieldOff className="w-10 h-10 mx-auto mb-3 opacity-30" />
                    <p className="text-sm">アラートが見つかりません</p>
                    <p className="text-xs mt-1 opacity-60">フィルター条件を変更してください</p>
                  </td>
                </tr>
              ) : (
                alerts.map(alert => {
                  const isSelected = selected.has(alert.id)
                  return (
                    <tr
                      key={alert.id}
                      className={`group transition-colors cursor-pointer ${
                        isSelected
                          ? 'bg-[#1d2f4a]/60 hover:bg-[#1d2f4a]'
                          : 'hover:bg-[#19253d]/50'
                      }`}
                      onClick={() => toggleOne(alert.id)}
                    >
                      <td className="px-3 py-2.5 w-10" onClick={e => { e.stopPropagation(); toggleOne(alert.id) }}>
                        {isSelected ? (
                          <CheckSquare className="w-4 h-4 text-[#e8002d]" />
                        ) : (
                          <Square className="w-4 h-4 text-[#3d5068] group-hover:text-[#7d92b0]" />
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="text-[#e2e8f4] font-medium line-clamp-1">{alert.title}</span>
                        {alert.tags && alert.tags.length > 0 && (
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            {alert.tags.slice(0, 3).map(tag => (
                              <span key={tag} className="px-1.5 py-0 rounded-sm text-[9px] bg-purple-900/40 text-purple-400 border border-purple-700/20">
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-[#7d92b0] text-xs truncate max-w-[160px]">
                        {alert.agent_hostname || alert.agent_id?.slice(0, 8) || '-'}
                      </td>
                      <td className="px-3 py-2.5">
                        <span className={`text-xs font-medium ${STATUS_COLORS[alert.status] ?? 'text-[#7d92b0]'}`}>
                          {STATUS_LABELS[alert.status] ?? alert.status}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 text-[#7d92b0] text-xs">
                        {formatDate(alert.created_at)}
                      </td>
                      <td className="px-3 py-2.5 text-[#7d92b0] text-xs truncate max-w-[128px]">
                        {alert.assigned_to || <span className="text-[#3d5068]">未割り当て</span>}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* ── Pagination ────────────────────────────────────────────────── */}
        <div className="shrink-0 bg-[#0d1220] border-t border-[#1e2d42] px-6 py-3 flex items-center justify-between">
          <span className="text-[#7d92b0] text-xs">
            {total > 0
              ? `${((page - 1) * PER_PAGE + 1).toLocaleString()}–${Math.min(page * PER_PAGE, total).toLocaleString()} / ${total.toLocaleString()} 件`
              : '0 件'
            }
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-sm border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-1">
              {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
                let p: number
                if (totalPages <= 7) {
                  p = i + 1
                } else if (page <= 4) {
                  p = i + 1
                } else if (page >= totalPages - 3) {
                  p = totalPages - 6 + i
                } else {
                  p = page - 3 + i
                }
                return (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    className={`w-7 h-7 rounded-sm text-xs font-medium transition-colors ${
                      p === page
                        ? 'bg-[#e8002d] text-white'
                        : 'text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#19253d]'
                    }`}
                  >
                    {p}
                  </button>
                )
              })}
            </div>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="p-1.5 rounded-sm border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* ── Modals ────────────────────────────────────────────────────────── */}
      {modal === 'close' && (
        <ResolutionModal
          count={selected.size}
          onConfirm={note => batchMutation.mutate({ ids: selectedIds, action: 'close', note })}
          onCancel={() => setModal(null)}
        />
      )}
      {modal === 'tag' && (
        <TagModal
          count={selected.size}
          onConfirm={tag => batchMutation.mutate({ ids: selectedIds, action: 'tag', tag })}
          onCancel={() => setModal(null)}
        />
      )}
      {modal === 'assign' && (
        <AssignModal
          count={selected.size}
          onConfirm={userId => batchMutation.mutate({ ids: selectedIds, action: 'assign', user_id: userId })}
          onCancel={() => setModal(null)}
        />
      )}
      {modal === 'save_preset' && (
        <SavePresetModal
          onConfirm={handleSavePreset}
          onCancel={() => setModal(null)}
        />
      )}
    </div>
  )
}
