'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  CalendarClock, Plus, Pencil, Trash2, X,
  ToggleLeft, ToggleRight, AlertTriangle,
  CheckCircle, Clock, RefreshCw, ChevronLeft, ChevronRight,
  Calendar, List
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────

interface MaintenanceWindow {
  id: string
  name: string
  description: string
  start_time: string
  end_time: string
  recurring: boolean
  recurrence_pattern: string
  suppress_alerts: boolean
  suppress_notifications: boolean
  affected_agents: string[]
  affected_groups: string[]
  enabled: boolean
  created_by?: string
  created_at: string
  updated_at: string
}

interface WindowsResponse {
  data: MaintenanceWindow[]
  total: number
}

interface StatusResponse {
  active: boolean
  current_window: MaintenanceWindow | null
}

// ── Helpers ──────────────────────────────────────────────────────────

const DAYS_OF_WEEK = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']
const DAY_LABELS: Record<string, string> = {
  sunday: '日', monday: '月', tuesday: '火', wednesday: '水',
  thursday: '木', friday: '金', saturday: '土',
}
const RECURRENCE_OPTIONS = [
  { value: 'daily', label: '毎日' },
  { value: 'weekly', label: '毎週' },
  { value: 'monthly', label: '毎月' },
]

function formatDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (ms <= 0) return '—'
  const totalMins = Math.floor(ms / 60000)
  const h = Math.floor(totalMins / 60)
  const m = totalMins % 60
  if (h === 0) return `${m}m`
  if (m === 0) return `${h}h`
  return `${h}h ${m}m`
}

function formatDateTime(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function toLocalDatetimeValue(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function fromLocalDatetimeValue(local: string): string {
  if (!local) return ''
  return new Date(local).toISOString()
}

function calcDurationFromStrings(start: string, end: string): string {
  if (!start || !end) return '—'
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (ms <= 0 || isNaN(ms)) return '—'
  const totalMins = Math.floor(ms / 60000)
  const h = Math.floor(totalMins / 60)
  const m = totalMins % 60
  if (h === 0) return `${m}m`
  if (m === 0) return `${h}h`
  return `${h}h ${m}m`
}

function recurrenceLabel(pattern: string): string {
  if (!pattern) return '—'
  if (pattern === 'daily') return '毎日'
  if (pattern.startsWith('weekly:')) {
    const day = pattern.split(':')[1]
    return `毎週${DAY_LABELS[day] ?? day}曜日`
  }
  if (pattern.startsWith('monthly:')) {
    const day = pattern.split(':')[1]
    return `毎月${day}日`
  }
  return pattern
}

// ── Default form ─────────────────────────────────────────────────────

const nowPlus1h = () => {
  const d = new Date()
  d.setMinutes(0, 0, 0)
  return d
}

function defaultForm() {
  const start = nowPlus1h()
  const end = new Date(start)
  end.setHours(end.getHours() + 2)
  const pad = (n: number) => String(n).padStart(2, '0')
  const fmt = (d: Date) =>
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  return {
    name: '',
    description: '',
    start_time: fmt(start),
    end_time: fmt(end),
    recurring: false,
    recurrence_type: 'daily' as 'daily' | 'weekly' | 'monthly',
    recurrence_day_of_week: 'monday',
    recurrence_day_of_month: '1',
    suppress_alerts: true,
    suppress_notifications: true,
    scope: 'all' as 'all' | 'groups' | 'agents',
    affected_groups_text: '',
    affected_agents_text: '',
    enabled: true,
  }
}

type FormState = ReturnType<typeof defaultForm>

// ── Toggle component ──────────────────────────────────────────────────

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
        value ? 'bg-falcon-red' : 'bg-falcon-border'
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-falcon-text transition-transform ${
          value ? 'translate-x-4' : 'translate-x-1'
        }`}
      />
    </button>
  )
}

// ── Main component ────────────────────────────────────────────────────

export default function MaintenanceWindowsPage() {
  const queryClient = useQueryClient()
  const [view, setView] = useState<'list' | 'calendar'>('list')
  const [modalOpen, setModalOpen] = useState(false)
  const [editingWindow, setEditingWindow] = useState<MaintenanceWindow | null>(null)
  const [form, setForm] = useState<FormState>(defaultForm())
  const [formError, setFormError] = useState('')
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [calendarDate, setCalendarDate] = useState(() => new Date())

  // ── Data fetching ──────────────────────────────────────────────────

  const { data: agentsData } = useQuery<{ data: { id: string; hostname: string }[] }>({
    queryKey: ['agents-for-mw'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=500'),
    staleTime: 60_000,
  })
  const agentsList = agentsData?.data ?? []

  const { data: statusData, isLoading: statusLoading } = useQuery<StatusResponse>({
    queryKey: ['maintenance-windows-status'],
    queryFn: () => apiFetch('/api/v1/admin/maintenance-windows/status'),
    refetchInterval: 30_000,
  })

  const { data: windowsData, isLoading: windowsLoading } = useQuery<WindowsResponse>({
    queryKey: ['maintenance-windows'],
    queryFn: () => apiFetch('/api/v1/admin/maintenance-windows'),
  })

  const windows = windowsData?.data ?? []

  // ── Mutations ──────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/admin/maintenance-windows', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows'] })
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows-status'] })
      setModalOpen(false)
    },
    onError: () => setFormError('作成に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/admin/maintenance-windows/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows'] })
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows-status'] })
      setModalOpen(false)
    },
    onError: () => setFormError('更新に失敗しました'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/maintenance-windows/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows'] })
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows-status'] })
      setDeleteConfirm(null)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: (w: MaintenanceWindow) =>
      apiFetch(`/api/v1/admin/maintenance-windows/${w.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          ...w,
          start_time: w.start_time,
          end_time: w.end_time,
          enabled: !w.enabled,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows'] })
      queryClient.invalidateQueries({ queryKey: ['maintenance-windows-status'] })
    },
  })

  // ── Form helpers ───────────────────────────────────────────────────

  const buildRecurrencePattern = (f: FormState): string => {
    if (!f.recurring) return ''
    if (f.recurrence_type === 'daily') return 'daily'
    if (f.recurrence_type === 'weekly') return `weekly:${f.recurrence_day_of_week}`
    if (f.recurrence_type === 'monthly') return `monthly:${f.recurrence_day_of_month}`
    return ''
  }

  const parseRecurrencePattern = (pattern: string) => {
    if (!pattern || pattern === 'daily') return { recurrence_type: 'daily' as const, dow: 'monday', dom: '1' }
    if (pattern.startsWith('weekly:')) return { recurrence_type: 'weekly' as const, dow: pattern.split(':')[1], dom: '1' }
    if (pattern.startsWith('monthly:')) return { recurrence_type: 'monthly' as const, dow: 'monday', dom: pattern.split(':')[1] }
    return { recurrence_type: 'daily' as const, dow: 'monday', dom: '1' }
  }

  const openCreate = () => {
    setEditingWindow(null)
    setForm(defaultForm())
    setFormError('')
    setModalOpen(true)
  }

  const openEdit = (w: MaintenanceWindow) => {
    setEditingWindow(w)
    const { recurrence_type, dow, dom } = parseRecurrencePattern(w.recurrence_pattern)
    const affectedAgents = (w.affected_agents ?? []).join(', ')
    const affectedGroups = (w.affected_groups ?? []).join(', ')
    const scope: FormState['scope'] = affectedAgents ? 'agents' : affectedGroups ? 'groups' : 'all'
    setForm({
      name: w.name,
      description: w.description,
      start_time: toLocalDatetimeValue(w.start_time),
      end_time: toLocalDatetimeValue(w.end_time),
      recurring: w.recurring,
      recurrence_type,
      recurrence_day_of_week: dow,
      recurrence_day_of_month: dom,
      suppress_alerts: w.suppress_alerts,
      suppress_notifications: w.suppress_notifications,
      scope,
      affected_groups_text: affectedGroups,
      affected_agents_text: affectedAgents,
      enabled: w.enabled,
    })
    setFormError('')
    setModalOpen(true)
  }

  const handleSubmit = () => {
    if (!form.name.trim()) { setFormError('名前は必須です'); return }
    if (!form.start_time) { setFormError('開始日時は必須です'); return }
    if (!form.end_time) { setFormError('終了日時は必須です'); return }
    const startISO = fromLocalDatetimeValue(form.start_time)
    const endISO = fromLocalDatetimeValue(form.end_time)
    if (new Date(endISO) <= new Date(startISO)) {
      setFormError('終了日時は開始日時より後である必要があります')
      return
    }
    const affectedAgents = form.scope === 'agents'
      ? form.affected_agents_text.split(',').map(s => s.trim()).filter(Boolean)
      : []
    const affectedGroups = form.scope === 'groups'
      ? form.affected_groups_text.split(',').map(s => s.trim()).filter(Boolean)
      : []

    const body = {
      name: form.name.trim(),
      description: form.description.trim(),
      start_time: startISO,
      end_time: endISO,
      recurring: form.recurring,
      recurrence_pattern: buildRecurrencePattern(form),
      suppress_alerts: form.suppress_alerts,
      suppress_notifications: form.suppress_notifications,
      affected_agents: affectedAgents,
      affected_groups: affectedGroups,
      enabled: form.enabled,
    }
    if (editingWindow) {
      updateMutation.mutate({ id: editingWindow.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending

  // ── Upcoming windows ───────────────────────────────────────────────

  const now = new Date()
  const upcoming = useMemo(() =>
    windows
      .filter(w => w.enabled && new Date(w.start_time) > now)
      .sort((a, b) => new Date(a.start_time).getTime() - new Date(b.start_time).getTime())
      .slice(0, 3),
    [windows] // eslint-disable-line react-hooks/exhaustive-deps
  )

  // ── Calendar helpers ───────────────────────────────────────────────

  const calYear = calendarDate.getFullYear()
  const calMonth = calendarDate.getMonth()
  const firstDayOfMonth = new Date(calYear, calMonth, 1).getDay()
  const daysInMonth = new Date(calYear, calMonth + 1, 0).getDate()
  const calendarCells = Array.from({ length: 42 }, (_, i) => {
    const dayNum = i - firstDayOfMonth + 1
    return dayNum >= 1 && dayNum <= daysInMonth ? dayNum : null
  })

  const windowsOnDay = (day: number): MaintenanceWindow[] => {
    const date = new Date(calYear, calMonth, day)
    return windows.filter(w => {
      const s = new Date(w.start_time)
      const e = new Date(w.end_time)
      return s.getFullYear() === calYear && s.getMonth() === calMonth && s.getDate() === day ||
             (s <= date && e >= date)
    })
  }

  const prevMonth = () => setCalendarDate(d => new Date(d.getFullYear(), d.getMonth() - 1, 1))
  const nextMonth = () => setCalendarDate(d => new Date(d.getFullYear(), d.getMonth() + 1, 1))

  const MONTH_LABELS = ['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月']
  const DAY_HEADERS = ['日','月','火','水','木','金','土']

  // ── Status banner ──────────────────────────────────────────────────

  const isActive = statusData?.active ?? false
  const currentWindow = statusData?.current_window ?? null

  return (
    <div className="min-h-screen bg-[#070d19] p-6">

      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
              <CalendarClock className="w-4 h-4 text-falcon-red" />
            </div>
            <h1 className="text-xl font-bold text-white">メンテナンスウィンドウ</h1>
          </div>
          <p className="text-falcon-muted text-sm ml-11">
            計画メンテナンス期間を設定し、アラートと通知を抑制します
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* View toggle */}
          <div className="flex bg-falcon-surface border border-falcon-border rounded-sm overflow-hidden">
            <button
              onClick={() => setView('list')}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors ${
                view === 'list' ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'
              }`}
            >
              <List className="w-3.5 h-3.5" /> リスト
            </button>
            <button
              onClick={() => setView('calendar')}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors ${
                view === 'calendar' ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'
              }`}
            >
              <Calendar className="w-3.5 h-3.5" /> カレンダー
            </button>
          </div>
          <button
            onClick={openCreate}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            新規作成
          </button>
        </div>
      </div>

      {/* ── Status Banner ──────────────────────────────────────── */}
      {!statusLoading && (
        <div className={`mb-6 rounded-lg border p-4 flex items-center gap-4 ${
          isActive
            ? 'bg-falcon-red/10 border-falcon-red/40'
            : 'bg-falcon-green/10 border-falcon-green/30'
        }`}>
          {isActive ? (
            <AlertTriangle className="w-6 h-6 text-falcon-red shrink-0" />
          ) : (
            <CheckCircle className="w-6 h-6 text-falcon-green shrink-0" />
          )}
          <div className="flex-1 min-w-0">
            <p className={`text-base font-bold ${isActive ? 'text-falcon-red' : 'text-falcon-green'}`}>
              {isActive ? 'メンテナンス中' : '通常稼働中'}
            </p>
            {isActive && currentWindow && (
              <p className="text-xs text-falcon-muted mt-0.5 truncate">
                現在のウィンドウ: <span className="text-white">{currentWindow.name}</span>
                {' '}— 終了予定: {formatDateTime(currentWindow.end_time)}
              </p>
            )}
            {!isActive && (
              <p className="text-xs text-falcon-muted mt-0.5">
                アクティブなメンテナンスウィンドウはありません
              </p>
            )}
          </div>
          {isActive && currentWindow && (
            <div className="flex items-center gap-2 text-xs text-falcon-muted">
              <Clock className="w-3.5 h-3.5" />
              <span>{formatDuration(currentWindow.start_time, currentWindow.end_time)}</span>
            </div>
          )}
        </div>
      )}

      {/* ── Upcoming Section ───────────────────────────────────── */}
      {upcoming.length > 0 && (
        <div className="mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <h2 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Clock className="w-4 h-4 text-falcon-muted" />
            直近のメンテナンスウィンドウ
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {upcoming.map(w => (
              <div key={w.id} className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
                <p className="text-xs font-semibold text-white truncate">{w.name}</p>
                <p className="text-[10px] text-falcon-muted mt-1">
                  {formatDateTime(w.start_time)}
                </p>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-[10px] text-falcon-subtle">
                    所要時間: {formatDuration(w.start_time, w.end_time)}
                  </span>
                  {w.recurring && (
                    <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded-sm">
                      繰り返し
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Calendar View ──────────────────────────────────────── */}
      {view === 'calendar' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden mb-6">
          {/* Calendar header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-falcon-border">
            <button
              onClick={prevMonth}
              className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-sm font-semibold text-white">
              {calYear}年 {MONTH_LABELS[calMonth]}
            </span>
            <button
              onClick={nextMonth}
              className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
          {/* Day headers */}
          <div className="grid grid-cols-7 border-b border-falcon-border">
            {DAY_HEADERS.map((d, i) => (
              <div
                key={d}
                className={`py-2 text-center text-xs font-medium ${
                  i === 0 ? 'text-falcon-red' : i === 6 ? 'text-blue-400' : 'text-falcon-muted'
                }`}
              >
                {d}
              </div>
            ))}
          </div>
          {/* Calendar grid */}
          <div className="grid grid-cols-7">
            {calendarCells.map((day, idx) => {
              const isToday = day !== null &&
                new Date().getFullYear() === calYear &&
                new Date().getMonth() === calMonth &&
                new Date().getDate() === day
              const dayWindows = day !== null ? windowsOnDay(day) : []
              return (
                <div
                  key={idx}
                  className={`min-h-[80px] p-1.5 border-b border-r border-falcon-border ${
                    day === null ? 'bg-[#070d19]/50' : 'bg-transparent'
                  }`}
                >
                  {day !== null && (
                    <>
                      <span className={`text-xs font-medium inline-flex items-center justify-center w-5 h-5 rounded-full ${
                        isToday
                          ? 'bg-falcon-red text-white'
                          : 'text-falcon-muted'
                      }`}>
                        {day}
                      </span>
                      <div className="mt-1 space-y-0.5">
                        {dayWindows.slice(0, 3).map(w => (
                          <div
                            key={w.id}
                            title={w.name}
                            className={`text-[9px] rounded px-1 py-0.5 truncate cursor-pointer ${
                              w.enabled
                                ? 'bg-falcon-red/20 text-falcon-red border border-falcon-red/30'
                                : 'bg-falcon-border text-falcon-subtle border border-falcon-border'
                            }`}
                            onClick={() => openEdit(w)}
                          >
                            {w.name}
                          </div>
                        ))}
                        {dayWindows.length > 3 && (
                          <span className="text-[8px] text-falcon-subtle">+{dayWindows.length - 3}</span>
                        )}
                      </div>
                    </>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── List View ──────────────────────────────────────────── */}
      {view === 'list' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-falcon-border flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">ウィンドウ一覧</h2>
            <span className="text-xs text-falcon-muted">{windows.length} 件</span>
          </div>

          {windowsLoading ? (
            <div className="p-8 text-center text-falcon-muted text-sm">読み込み中...</div>
          ) : windows.length === 0 ? (
            <div className="p-10 text-center">
              <CalendarClock className="w-8 h-8 text-falcon-subtle mx-auto mb-3" />
              <p className="text-falcon-muted text-sm">メンテナンスウィンドウが登録されていません</p>
              <button
                onClick={openCreate}
                className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-falcon-red/10 hover:bg-falcon-red/20 text-falcon-red text-sm rounded-sm border border-falcon-red/30 transition-colors"
              >
                <Plus className="w-4 h-4" /> 最初のウィンドウを作成
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['名前', '開始日時', '終了日時', '所要時間', '繰り返し', 'アラート抑制', '通知抑制', '有効', '操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {windows.map(w => {
                    const activeNow = w.enabled &&
                      new Date(w.start_time) <= now && new Date(w.end_time) >= now
                    return (
                      <tr key={w.id} className={`hover:bg-[#0a1628] transition-colors ${activeNow ? 'bg-falcon-red/5' : ''}`}>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {activeNow && (
                              <span className="w-1.5 h-1.5 rounded-full bg-falcon-red shrink-0 animate-pulse" />
                            )}
                            <div>
                              <p className="text-sm font-medium text-white">{w.name}</p>
                              {w.description && (
                                <p className="text-xs text-falcon-subtle truncate max-w-[200px]">{w.description}</p>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">
                          {formatDateTime(w.start_time)}
                        </td>
                        <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">
                          {formatDateTime(w.end_time)}
                        </td>
                        <td className="px-4 py-3 text-xs text-falcon-muted">
                          {formatDuration(w.start_time, w.end_time)}
                        </td>
                        <td className="px-4 py-3">
                          {w.recurring ? (
                            <div className="flex items-center gap-1">
                              <RefreshCw className="w-3 h-3 text-blue-400" />
                              <span className="text-xs text-blue-400">{recurrenceLabel(w.recurrence_pattern)}</span>
                            </div>
                          ) : (
                            <span className="text-xs text-falcon-subtle">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs ${w.suppress_alerts ? 'text-falcon-green' : 'text-falcon-subtle'}`}>
                            {w.suppress_alerts ? '有効' : '無効'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs ${w.suppress_notifications ? 'text-falcon-green' : 'text-falcon-subtle'}`}>
                            {w.suppress_notifications ? '有効' : '無効'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => toggleMutation.mutate(w)}
                            disabled={toggleMutation.isPending}
                            className="flex items-center gap-1 text-xs transition-colors"
                            title={w.enabled ? '無効にする' : '有効にする'}
                          >
                            {w.enabled ? (
                              <span className="flex items-center gap-1 text-green-400 hover:text-green-300">
                                <ToggleRight className="w-4 h-4" /> 有効
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-falcon-muted hover:text-white">
                                <ToggleLeft className="w-4 h-4" /> 無効
                              </span>
                            )}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => openEdit(w)}
                              className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
                              title="編集"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => setDeleteConfirm(w.id)}
                              className="p-1.5 rounded-sm text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10 transition-colors"
                              title="削除"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Create/Edit Modal ───────────────────────────────────── */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
            {/* Modal header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border shrink-0">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <CalendarClock className="w-4 h-4 text-falcon-red" />
                {editingWindow ? 'メンテナンスウィンドウを編集' : '新規メンテナンスウィンドウ'}
              </h2>
              <button
                onClick={() => setModalOpen(false)}
                className="p-1 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal body */}
            <div className="px-5 py-4 space-y-5 overflow-y-auto flex-1">

              {/* Name */}
              <div>
                <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                  名前 <span className="text-falcon-red">*</span>
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="例: 週次定期メンテナンス"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-medium text-falcon-muted mb-1.5">説明</label>
                <textarea
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="メンテナンス内容の詳細..."
                  rows={2}
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 resize-none"
                />
              </div>

              {/* Date/time row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                    開始日時 <span className="text-falcon-red">*</span>
                  </label>
                  <input
                    type="datetime-local"
                    value={form.start_time}
                    onChange={e => setForm(f => ({ ...f, start_time: e.target.value }))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 scheme-dark"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                    終了日時 <span className="text-falcon-red">*</span>
                  </label>
                  <input
                    type="datetime-local"
                    value={form.end_time}
                    onChange={e => setForm(f => ({ ...f, end_time: e.target.value }))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 scheme-dark"
                  />
                </div>
              </div>

              {/* Duration calculator */}
              <div className="flex items-center gap-2 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2">
                <Clock className="w-3.5 h-3.5 text-falcon-muted" />
                <span className="text-xs text-falcon-muted">所要時間:</span>
                <span className="text-xs font-semibold text-white">
                  {calcDurationFromStrings(
                    fromLocalDatetimeValue(form.start_time),
                    fromLocalDatetimeValue(form.end_time),
                  )}
                </span>
              </div>

              {/* Recurring toggle */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-falcon-muted">繰り返し</p>
                  <p className="text-[10px] text-falcon-subtle">定期的なメンテナンスウィンドウを設定します</p>
                </div>
                <Toggle value={form.recurring} onChange={v => setForm(f => ({ ...f, recurring: v }))} />
              </div>

              {/* Recurrence pattern */}
              {form.recurring && (
                <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4 space-y-3">
                  <label className="block text-xs font-medium text-falcon-muted">繰り返しパターン</label>
                  <div className="flex gap-2 flex-wrap">
                    {RECURRENCE_OPTIONS.map(opt => (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => setForm(f => ({ ...f, recurrence_type: opt.value as FormState['recurrence_type'] }))}
                        className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                          form.recurrence_type === opt.value
                            ? 'bg-falcon-red/20 text-falcon-red border-falcon-red/40'
                            : 'text-falcon-muted border-falcon-border hover:border-falcon-muted/40'
                        }`}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                  {form.recurrence_type === 'weekly' && (
                    <div>
                      <label className="block text-xs font-medium text-falcon-muted mb-2">曜日</label>
                      <div className="flex gap-1.5 flex-wrap">
                        {DAYS_OF_WEEK.map(day => (
                          <button
                            key={day}
                            type="button"
                            onClick={() => setForm(f => ({ ...f, recurrence_day_of_week: day }))}
                            className={`w-8 h-8 text-xs rounded border transition-colors ${
                              form.recurrence_day_of_week === day
                                ? 'bg-falcon-red/20 text-falcon-red border-falcon-red/40'
                                : 'text-falcon-muted border-falcon-border hover:border-falcon-muted/40'
                            }`}
                          >
                            {DAY_LABELS[day]}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  {form.recurrence_type === 'monthly' && (
                    <div>
                      <label className="block text-xs font-medium text-falcon-muted mb-1.5">日 (1〜31)</label>
                      <input
                        type="number"
                        min={1}
                        max={31}
                        value={form.recurrence_day_of_month}
                        onChange={e => setForm(f => ({ ...f, recurrence_day_of_month: e.target.value }))}
                        className="w-24 bg-falcon-surface border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50"
                      />
                    </div>
                  )}
                </div>
              )}

              {/* Suppress options */}
              <div className="space-y-3">
                <p className="text-xs font-medium text-falcon-muted">抑制オプション</p>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-white">アラート抑制</p>
                    <p className="text-[10px] text-falcon-subtle">メンテナンス中はアラートを抑制します</p>
                  </div>
                  <Toggle
                    value={form.suppress_alerts}
                    onChange={v => setForm(f => ({ ...f, suppress_alerts: v }))}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-white">通知抑制</p>
                    <p className="text-[10px] text-falcon-subtle">メンテナンス中はメール/Slack通知を抑制します</p>
                  </div>
                  <Toggle
                    value={form.suppress_notifications}
                    onChange={v => setForm(f => ({ ...f, suppress_notifications: v }))}
                  />
                </div>
              </div>

              {/* Affected scope */}
              <div className="space-y-3">
                <p className="text-xs font-medium text-falcon-muted">対象スコープ</p>
                <div className="flex gap-3 flex-wrap">
                  {[
                    { value: 'all', label: 'すべてのエージェント' },
                    { value: 'groups', label: '特定のグループ' },
                    { value: 'agents', label: '特定のエージェント' },
                  ].map(opt => (
                    <label key={opt.value} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="scope"
                        value={opt.value}
                        checked={form.scope === opt.value}
                        onChange={() => setForm(f => ({ ...f, scope: opt.value as FormState['scope'] }))}
                        className="accent-falcon-red"
                      />
                      <span className="text-xs text-falcon-muted">{opt.label}</span>
                    </label>
                  ))}
                </div>
                {form.scope === 'groups' && (
                  <input
                    type="text"
                    value={form.affected_groups_text}
                    onChange={e => setForm(f => ({ ...f, affected_groups_text: e.target.value }))}
                    placeholder="group1, group2, ..."
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                  />
                )}
                {form.scope === 'agents' && (
                  <div className="border border-falcon-border rounded-sm p-2 max-h-40 overflow-y-auto bg-[#070d19] space-y-1">
                    {agentsList.length === 0 ? (
                      <p className="text-xs text-falcon-subtle px-1">エージェントなし</p>
                    ) : agentsList.map(a => {
                      const selected = form.affected_agents_text.split(',').map(s => s.trim()).includes(a.id)
                      return (
                        <label key={a.id} className="flex items-center gap-2 px-1 py-0.5 rounded-sm hover:bg-falcon-border cursor-pointer">
                          <input
                            type="checkbox"
                            checked={selected}
                            onChange={e => {
                              const current = form.affected_agents_text.split(',').map(s => s.trim()).filter(Boolean)
                              const next = e.target.checked ? [...current, a.id] : current.filter(id => id !== a.id)
                              setForm(f => ({ ...f, affected_agents_text: next.join(', ') }))
                            }}
                            className="accent-falcon-red"
                          />
                          <span className="text-xs text-white">{a.hostname}</span>
                        </label>
                      )
                    })}
                  </div>
                )}
              </div>

              {/* Enabled */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-falcon-muted">有効</p>
                  <p className="text-[10px] text-falcon-subtle">無効にすると一時的にスキップされます</p>
                </div>
                <Toggle value={form.enabled} onChange={v => setForm(f => ({ ...f, enabled: v }))} />
              </div>

              {formError && (
                <div className="flex items-center gap-2 bg-falcon-red/10 border border-falcon-red/30 rounded-sm px-3 py-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-falcon-red shrink-0" />
                  <p className="text-xs text-falcon-red">{formError}</p>
                </div>
              )}
            </div>

            {/* Modal footer */}
            <div className="px-5 py-4 border-t border-falcon-border flex justify-end gap-3 shrink-0">
              <button
                onClick={() => setModalOpen(false)}
                className="px-4 py-2 text-sm text-falcon-muted hover:text-white rounded-sm border border-falcon-border hover:border-falcon-muted/40 transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleSubmit}
                disabled={isPending}
                className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {isPending ? '保存中...' : editingWindow ? '更新' : '作成'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete Confirm Modal ────────────────────────────────── */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-full bg-falcon-red/10 flex items-center justify-center shrink-0">
                <Trash2 className="w-4 h-4 text-falcon-red" />
              </div>
              <h2 className="text-base font-semibold text-white">ウィンドウを削除しますか？</h2>
            </div>
            <p className="text-sm text-falcon-muted mb-5 ml-11">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-falcon-muted hover:text-white rounded-sm border border-falcon-border transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
