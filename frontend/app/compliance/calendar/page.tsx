'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  CalendarDays, ChevronLeft, ChevronRight, Plus, Edit2, Trash2,
  X, CheckCircle, AlertTriangle, Clock, RefreshCw, Filter,
  Shield, FileCheck, RotateCcw, AlertCircle, Circle
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────────

type EventCategory = 'audit' | 'certification' | 'regulatory' | 'internal'
type EventStatus = 'upcoming' | 'overdue' | 'completed'
type RecurringPeriod = 'annual' | 'quarterly' | 'monthly'

interface ComplianceEvent {
  id: string
  title: string
  category: EventCategory
  due_date: string
  assignee: string
  status: EventStatus
  notes: string
  recurring: boolean
  recurring_period?: RecurringPeriod
  completed_at?: string
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const today = new Date()
const fmt = (d: Date) => d.toISOString().split('T')[0]
const addDays = (d: Date, n: number) => { const r = new Date(d); r.setDate(r.getDate() + n); return r }
const addMonths = (d: Date, n: number) => { const r = new Date(d); r.setMonth(r.getMonth() + n); return r }

const MOCK_EVENTS: ComplianceEvent[] = [
  {
    id: 'ce-001',
    title: 'SOC2 Type II 年次監査',
    category: 'audit',
    due_date: fmt(addDays(today, 15)),
    assignee: '山田 太郎',
    status: 'upcoming',
    notes: 'BigFour監査法人によるSOC2 Type II準拠審査。証跡収集・ドキュメント整備が必要。',
    recurring: true,
    recurring_period: 'annual',
  },
  {
    id: 'ce-002',
    title: 'ISO 27001 認証更新',
    category: 'certification',
    due_date: fmt(addDays(today, -3)),
    assignee: '鈴木 花子',
    status: 'overdue',
    notes: 'ISO 27001:2022への移行審査。ISMS管理策の見直しが完了していること。',
    recurring: true,
    recurring_period: 'annual',
  },
  {
    id: 'ce-003',
    title: 'GDPR データ処理レビュー',
    category: 'regulatory',
    due_date: fmt(addDays(today, 5)),
    assignee: '田中 次郎',
    status: 'upcoming',
    notes: 'EUデータ主体の個人情報処理記録の年次レビューおよびDPIA更新。',
    recurring: true,
    recurring_period: 'annual',
  },
  {
    id: 'ce-004',
    title: '四半期ペネトレーションテスト',
    category: 'audit',
    due_date: fmt(addDays(today, 28)),
    assignee: '伊藤 三郎',
    status: 'upcoming',
    notes: '外部セキュリティベンダーによるWebアプリ・インフラのペネトレーションテスト。',
    recurring: true,
    recurring_period: 'quarterly',
  },
  {
    id: 'ce-005',
    title: 'TLS証明書更新 (*.example.com)',
    category: 'certification',
    due_date: fmt(addDays(today, 2)),
    assignee: '渡辺 四郎',
    status: 'upcoming',
    notes: 'ワイルドカード証明書の更新。Let\'s Encryptから商用CAへの移行も検討中。',
    recurring: true,
    recurring_period: 'annual',
  },
  {
    id: 'ce-006',
    title: 'PCI DSS 準拠スキャン',
    category: 'regulatory',
    due_date: fmt(addDays(today, -8)),
    assignee: '中村 五郎',
    status: 'overdue',
    notes: 'QSAによる四半期脆弱性スキャンおよびASVスキャンレポートの提出。',
    recurring: true,
    recurring_period: 'quarterly',
  },
  {
    id: 'ce-007',
    title: 'セキュリティポリシー年次改訂',
    category: 'internal',
    due_date: fmt(addDays(today, 45)),
    assignee: '小林 六子',
    status: 'upcoming',
    notes: '情報セキュリティポリシー・規程類の年次見直しと役員承認取得。',
    recurring: true,
    recurring_period: 'annual',
  },
  {
    id: 'ce-008',
    title: 'インシデント対応訓練',
    category: 'internal',
    due_date: fmt(addDays(today, -15)),
    assignee: '加藤 七郎',
    status: 'completed',
    notes: 'ランサムウェア感染シナリオによるテーブルトップ演習。全SOCメンバー参加。',
    recurring: true,
    recurring_period: 'quarterly',
    completed_at: fmt(addDays(today, -17)),
  },
  {
    id: 'ce-009',
    title: 'クラウドセキュリティ評価 (AWS)',
    category: 'audit',
    due_date: fmt(addDays(today, 60)),
    assignee: '松本 八郎',
    status: 'upcoming',
    notes: 'AWS Well-Architectedレビューおよびセキュリティピラーの評価実施。',
    recurring: false,
  },
  {
    id: 'ce-010',
    title: 'プライバシーポリシー更新',
    category: 'regulatory',
    due_date: fmt(addDays(today, -5)),
    assignee: '井上 九子',
    status: 'completed',
    notes: '改正個人情報保護法対応のプライバシーポリシー改訂・公表。',
    recurring: false,
    completed_at: fmt(addDays(today, -6)),
  },
  {
    id: 'ce-011',
    title: 'ベンダーリスク評価',
    category: 'internal',
    due_date: fmt(addDays(today, 10)),
    assignee: '木村 十郎',
    status: 'upcoming',
    notes: '主要クラウドベンダー・SaaSプロバイダーの年次セキュリティ評価アンケート送付・回収。',
    recurring: true,
    recurring_period: 'annual',
  },
  {
    id: 'ce-012',
    title: 'ISMS内部監査',
    category: 'audit',
    due_date: fmt(addDays(today, 20)),
    assignee: '林 幸子',
    status: 'upcoming',
    notes: 'ISO 27001要求事項に基づく内部監査の実施。不適合発見時は是正計画策定。',
    recurring: true,
    recurring_period: 'annual',
  },
]

// ── Helpers ────────────────────────────────────────────────────────────────────

const CATEGORY_LABELS: Record<EventCategory, string> = {
  audit: '監査',
  certification: '認証',
  regulatory: '規制対応',
  internal: '内部',
}

const CATEGORY_COLORS: Record<EventCategory, string> = {
  audit: 'bg-blue-500/20 text-blue-400',
  certification: 'bg-purple-500/20 text-purple-400',
  regulatory: 'bg-orange-500/20 text-orange-400',
  internal: 'bg-[#4a6fa5]/20 text-[#4a6fa5]',
}

const STATUS_LABELS: Record<EventStatus, string> = {
  upcoming: '予定',
  overdue: '期限超過',
  completed: '完了',
}

const STATUS_COLORS: Record<EventStatus, string> = {
  upcoming: 'bg-blue-500/20 text-blue-400',
  overdue: 'bg-falcon-red/20 text-falcon-red',
  completed: 'bg-green-500/20 text-green-400',
}

// Dot color for calendar
const eventDotColor = (event: ComplianceEvent) => {
  if (event.status === 'completed') return '#22c55e'
  if (event.status === 'overdue') return '#e8002d'
  const dueDate = new Date(event.due_date)
  const diff = Math.ceil((dueDate.getTime() - today.getTime()) / 86400000)
  if (diff <= 7) return '#f97316'
  return '#3b82f6'
}

function nextOccurrence(event: ComplianceEvent): string {
  const base = new Date(event.due_date)
  if (event.recurring_period === 'annual') {
    base.setFullYear(base.getFullYear() + 1)
  } else if (event.recurring_period === 'quarterly') {
    base.setMonth(base.getMonth() + 3)
  } else if (event.recurring_period === 'monthly') {
    base.setMonth(base.getMonth() + 1)
  }
  return fmt(base)
}

// ── Add/Edit Modal ─────────────────────────────────────────────────────────────

const EMPTY_EVENT: Omit<ComplianceEvent, 'id' | 'status' | 'completed_at'> = {
  title: '',
  category: 'audit',
  due_date: fmt(today),
  assignee: '',
  notes: '',
  recurring: false,
  recurring_period: 'annual',
}

function EventModal({
  onClose, onSave, initial
}: {
  onClose: () => void
  onSave: (data: typeof EMPTY_EVENT) => void
  initial?: typeof EMPTY_EVENT
}) {
  const [form, setForm] = useState(initial ?? EMPTY_EVENT)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-lg"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-lg">イベント追加</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">イベントタイトル</label>
            <input
              value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
              placeholder="SOC2監査など"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-falcon-muted text-xs mb-1 block">カテゴリー</label>
              <select
                value={form.category}
                onChange={e => setForm(f => ({ ...f, category: e.target.value as EventCategory }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
              >
                <option value="audit">監査</option>
                <option value="certification">認証</option>
                <option value="regulatory">規制対応</option>
                <option value="internal">内部</option>
              </select>
            </div>
            <div>
              <label className="text-falcon-muted text-xs mb-1 block">期限日</label>
              <input
                type="date"
                value={form.due_date}
                onChange={e => setForm(f => ({ ...f, due_date: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
              />
            </div>
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">担当者</label>
            <input
              value={form.assignee}
              onChange={e => setForm(f => ({ ...f, assignee: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
              placeholder="担当者名"
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs mb-1 block">メモ</label>
            <textarea
              value={form.notes}
              onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
              rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5] resize-none"
              placeholder="追加メモ・詳細"
            />
          </div>
          <div>
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={form.recurring}
                onChange={e => setForm(f => ({ ...f, recurring: e.target.checked }))}
                className="accent-falcon-red"
              />
              <span className="text-falcon-muted text-sm">繰り返しイベント</span>
            </label>
            {form.recurring && (
              <select
                value={form.recurring_period}
                onChange={e => setForm(f => ({ ...f, recurring_period: e.target.value as RecurringPeriod }))}
                className="mt-2 w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
              >
                <option value="annual">年次</option>
                <option value="quarterly">四半期</option>
                <option value="monthly">月次</option>
              </select>
            )}
          </div>
        </div>
        <div className="px-6 py-4 border-t border-falcon-border flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => { onSave(form); onClose() }}
            disabled={!form.title || !form.due_date}
            className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c0001f] text-white rounded-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Calendar Grid ──────────────────────────────────────────────────────────────

function MonthCalendar({
  year, month, events, onDaySelect, selectedDay
}: {
  year: number
  month: number
  events: ComplianceEvent[]
  onDaySelect: (day: number | null) => void
  selectedDay: number | null
}) {
  const firstDay = new Date(year, month, 1).getDay() // 0=Sun
  const daysInMonth = new Date(year, month + 1, 0).getDate()
  const todayDate = today.getDate()
  const isCurrentMonth = today.getFullYear() === year && today.getMonth() === month

  // Build event map by day
  const eventsByDay = useMemo(() => {
    const map: Record<number, ComplianceEvent[]> = {}
    events.forEach(ev => {
      const d = new Date(ev.due_date)
      if (d.getFullYear() === year && d.getMonth() === month) {
        const day = d.getDate()
        if (!map[day]) map[day] = []
        map[day].push(ev)
      }
    })
    return map
  }, [events, year, month])

  const cells: (number | null)[] = [
    ...Array(firstDay).fill(null),
    ...Array.from({ length: daysInMonth }, (_, i) => i + 1),
  ]
  // Pad to 6 rows
  while (cells.length < 42) cells.push(null)

  return (
    <div>
      <div className="grid grid-cols-7 mb-1">
        {['日', '月', '火', '水', '木', '金', '土'].map(d => (
          <div key={d} className="text-center text-xs text-falcon-subtle py-2">{d}</div>
        ))}
      </div>
      <div className="grid grid-cols-7 gap-0.5">
        {cells.map((day, i) => {
          if (!day) return <div key={i} className="h-16 bg-[#070d19]/30 rounded-sm" />
          const evs = eventsByDay[day] ?? []
          const isToday = isCurrentMonth && day === todayDate
          const isSelected = selectedDay === day
          return (
            <div
              key={i}
              onClick={() => onDaySelect(isSelected ? null : day)}
              className={`h-16 p-1 rounded cursor-pointer transition-colors border
                ${isSelected
                  ? 'bg-falcon-active border-[#4a6fa5]'
                  : isToday
                    ? 'bg-falcon-red/10 border-falcon-red/40'
                    : 'bg-falcon-surface border-falcon-border hover:bg-falcon-hover'
                }`}
            >
              <p className={`text-xs font-medium mb-1 ${
                isToday ? 'text-falcon-red' : isSelected ? 'text-white' : 'text-falcon-muted'
              }`}>
                {day}
              </p>
              <div className="flex flex-wrap gap-0.5">
                {evs.slice(0, 3).map((ev, j) => (
                  <div
                    key={j}
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: eventDotColor(ev) }}
                    title={ev.title}
                  />
                ))}
                {evs.length > 3 && (
                  <span className="text-[9px] text-falcon-subtle">+{evs.length - 3}</span>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ComplianceCalendarPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'calendar' | 'list'>('calendar')
  const [calYear, setCalYear] = useState(today.getFullYear())
  const [calMonth, setCalMonth] = useState(today.getMonth())
  const [selectedDay, setSelectedDay] = useState<number | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [filterCategory, setFilterCategory] = useState<EventCategory | ''>('')
  const [filterStatus, setFilterStatus] = useState<EventStatus | ''>('')

  // Fetch events
  const { data: eventsData, isError } = useQuery<ComplianceEvent[]>({
    queryKey: ['compliance-calendar-events'],
    queryFn: () => apiFetch('/api/v1/compliance/events'),
    retry: 1,
  })
  const events = isError ? m(MOCK_EVENTS) : (eventsData ?? m(MOCK_EVENTS))

  // Create mutation
  const createMut = useMutation({
    mutationFn: (data: typeof EMPTY_EVENT) => apiFetch('/api/v1/compliance/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-calendar-events'] }),
  })

  // Complete mutation
  const completeMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/compliance/events/${id}/complete`, {
      method: 'POST',
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-calendar-events'] }),
  })

  // Delete mutation
  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/compliance/events/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-calendar-events'] }),
  })

  // Stats
  const thisMonth = events.filter(e => {
    const d = new Date(e.due_date)
    return d.getFullYear() === today.getFullYear() && d.getMonth() === today.getMonth()
  })
  const overdueCount = events.filter(e => e.status === 'overdue').length
  const dueThisWeek = events.filter(e => {
    const d = new Date(e.due_date)
    const diff = Math.ceil((d.getTime() - today.getTime()) / 86400000)
    return diff >= 0 && diff <= 7 && e.status !== 'completed'
  }).length
  const completedThisMonth = thisMonth.filter(e => e.status === 'completed').length

  // Calendar month events
  const thisMonthEvents = events.filter(e => {
    const d = new Date(e.due_date)
    return d.getFullYear() === calYear && d.getMonth() === calMonth
  })

  // Selected day events
  const selectedDayEvents = selectedDay
    ? events.filter(e => {
        const d = new Date(e.due_date)
        return d.getFullYear() === calYear && d.getMonth() === calMonth && d.getDate() === selectedDay
      })
    : []

  // Filtered list
  const filteredEvents = events.filter(e => {
    if (filterCategory && e.category !== filterCategory) return false
    if (filterStatus && e.status !== filterStatus) return false
    return true
  })

  const prevMonth = () => {
    if (calMonth === 0) { setCalMonth(11); setCalYear(y => y - 1) }
    else setCalMonth(m => m - 1)
    setSelectedDay(null)
  }
  const nextMonth = () => {
    if (calMonth === 11) { setCalMonth(0); setCalYear(y => y + 1) }
    else setCalMonth(m => m + 1)
    setSelectedDay(null)
  }

  const monthNames = ['1月', '2月', '3月', '4月', '5月', '6月', '7月', '8月', '9月', '10月', '11月', '12月']

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {showAddModal && (
        <EventModal
          onClose={() => setShowAddModal(false)}
          onSave={data => createMut.mutate(data)}
        />
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <CalendarDays className="w-6 h-6 text-falcon-red" />
            コンプライアンスカレンダー
          </h1>
          <p className="text-falcon-muted text-sm mt-1">監査・規制対応・証明書更新の期限管理</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white rounded-sm text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          イベント追加
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '今月のイベント', value: thisMonth.length, icon: CalendarDays, color: 'text-blue-400' },
          { label: '期限超過', value: overdueCount, icon: AlertCircle, color: 'text-falcon-red' },
          { label: '今週の期限', value: dueThisWeek, icon: Clock, color: 'text-orange-400' },
          { label: '今月完了', value: completedThisMonth, icon: CheckCircle, color: 'text-green-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-falcon-muted text-xs">{label}</span>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-falcon-border">
        {([['calendar', 'カレンダービュー'], ['list', 'イベント一覧']] as const).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === id
                ? 'text-white border-falcon-red'
                : 'text-falcon-muted border-transparent hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Calendar View */}
      {activeTab === 'calendar' && (
        <div className="flex gap-6">
          {/* Main calendar */}
          <div className="flex-1">
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 mb-4">
              {/* Month navigation */}
              <div className="flex items-center justify-between mb-4">
                <button
                  onClick={prevMonth}
                  className="p-2 text-falcon-muted hover:text-white hover:bg-falcon-border rounded-sm transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <h2 className="text-white font-semibold text-lg">
                  {calYear}年 {monthNames[calMonth]}
                </h2>
                <button
                  onClick={nextMonth}
                  className="p-2 text-falcon-muted hover:text-white hover:bg-falcon-border rounded-sm transition-colors"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>

              <MonthCalendar
                year={calYear}
                month={calMonth}
                events={events}
                onDaySelect={setSelectedDay}
                selectedDay={selectedDay}
              />
            </div>

            {/* Legend */}
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-3">
              <div className="flex items-center gap-6 flex-wrap">
                <span className="text-falcon-muted text-xs font-medium">凡例:</span>
                {[
                  { color: '#e8002d', label: '期限超過' },
                  { color: '#f97316', label: '今週期限' },
                  { color: '#3b82f6', label: '予定' },
                  { color: '#22c55e', label: '完了' },
                ].map(({ color, label }) => (
                  <div key={label} className="flex items-center gap-1.5 text-xs text-falcon-muted">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                    {label}
                  </div>
                ))}
              </div>
            </div>

            {/* Selected day events */}
            {selectedDay && (
              <div className="mt-4 bg-falcon-surface border border-falcon-border rounded-lg p-4">
                <h3 className="text-white font-semibold mb-3">
                  {calYear}年{monthNames[calMonth]}{selectedDay}日 のイベント
                </h3>
                {selectedDayEvents.length === 0 ? (
                  <p className="text-falcon-subtle text-sm">この日のイベントはありません</p>
                ) : (
                  <div className="space-y-2">
                    {selectedDayEvents.map(ev => (
                      <div key={ev.id} className="flex items-center justify-between p-3 bg-[#070d19] rounded-sm border border-falcon-border">
                        <div>
                          <p className="text-white text-sm font-medium">{ev.title}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={`px-1.5 py-0.5 rounded-sm text-xs ${CATEGORY_COLORS[ev.category]}`}>
                              {CATEGORY_LABELS[ev.category]}
                            </span>
                            <span className="text-xs text-falcon-subtle">{ev.assignee}</span>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded-sm text-xs ${STATUS_COLORS[ev.status]}`}>
                          {STATUS_LABELS[ev.status]}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Side panel: monthly summary */}
          <div className="w-72 shrink-0">
            <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
              <h3 className="text-white font-semibold mb-3 text-sm">
                今月のサマリー
                <span className="ml-2 text-xs text-falcon-muted">({thisMonthEvents.length}件)</span>
              </h3>
              {thisMonthEvents.length === 0 ? (
                <p className="text-falcon-subtle text-sm">今月のイベントはありません</p>
              ) : (
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {thisMonthEvents
                    .sort((a, b) => new Date(a.due_date).getTime() - new Date(b.due_date).getTime())
                    .map(ev => (
                      <div key={ev.id} className="p-2.5 bg-[#070d19] rounded-sm border border-falcon-border">
                        <div className="flex items-start justify-between gap-2">
                          <p className="text-sm text-white font-medium leading-tight">{ev.title}</p>
                          <span className={`px-1.5 py-0.5 rounded-sm text-[10px] whitespace-nowrap shrink-0 ${STATUS_COLORS[ev.status]}`}>
                            {STATUS_LABELS[ev.status]}
                          </span>
                        </div>
                        <div className="flex items-center justify-between mt-1.5">
                          <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${CATEGORY_COLORS[ev.category]}`}>
                            {CATEGORY_LABELS[ev.category]}
                          </span>
                          <span className="text-[10px] text-falcon-subtle">
                            {new Date(ev.due_date).getDate()}日
                          </span>
                        </div>
                      </div>
                    ))
                  }
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* List View */}
      {activeTab === 'list' && (
        <div>
          {/* Filters */}
          <div className="flex items-center gap-3 mb-4">
            <Filter className="w-4 h-4 text-falcon-muted" />
            <select
              value={filterCategory}
              onChange={e => setFilterCategory(e.target.value as EventCategory | '')}
              className="bg-falcon-surface border border-falcon-border rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden"
            >
              <option value="">すべてのカテゴリー</option>
              <option value="audit">監査</option>
              <option value="certification">認証</option>
              <option value="regulatory">規制対応</option>
              <option value="internal">内部</option>
            </select>
            <select
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value as EventStatus | '')}
              className="bg-falcon-surface border border-falcon-border rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden"
            >
              <option value="">すべてのステータス</option>
              <option value="upcoming">予定</option>
              <option value="overdue">期限超過</option>
              <option value="completed">完了</option>
            </select>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['イベントタイトル', 'カテゴリー', '期限日', '担当者', 'ステータス', 'メモ', '操作'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-falcon-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredEvents
                  .sort((a, b) => new Date(a.due_date).getTime() - new Date(b.due_date).getTime())
                  .map(ev => {
                    const dueDate = new Date(ev.due_date)
                    const isOverdue = ev.status === 'overdue'
                    return (
                      <tr key={ev.id} className="border-b border-falcon-border hover:bg-[#070d19] transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="text-white font-medium">{ev.title}</span>
                            {ev.recurring && (
                              <span title="繰り返しイベント"><RotateCcw className="w-3 h-3 text-falcon-subtle" /></span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs ${CATEGORY_COLORS[ev.category]}`}>
                            {CATEGORY_LABELS[ev.category]}
                          </span>
                        </td>
                        <td className={`px-4 py-3 text-sm font-medium ${isOverdue ? 'text-falcon-red' : 'text-falcon-muted'}`}>
                          {dueDate.toLocaleDateString('ja-JP', { year: 'numeric', month: 'short', day: 'numeric' })}
                        </td>
                        <td className="px-4 py-3 text-falcon-muted">{ev.assignee}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs ${STATUS_COLORS[ev.status]}`}>
                            {STATUS_LABELS[ev.status]}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-[200px]">
                          <p className="text-falcon-muted text-xs truncate" title={ev.notes}>
                            {ev.notes || '-'}
                          </p>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            <button className="p-1.5 text-falcon-muted hover:text-white hover:bg-falcon-border rounded-sm transition-colors" title="編集">
                              <Edit2 className="w-3.5 h-3.5" />
                            </button>
                            {ev.status !== 'completed' && (
                              <button
                                onClick={() => completeMut.mutate(ev.id)}
                                className="p-1.5 text-falcon-muted hover:text-green-400 hover:bg-green-400/10 rounded-sm transition-colors"
                                title="完了にする"
                              >
                                <CheckCircle className="w-3.5 h-3.5" />
                              </button>
                            )}
                            <button
                              onClick={() => deleteMut.mutate(ev.id)}
                              className="p-1.5 text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10 rounded-sm transition-colors"
                              title="削除"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                {filteredEvents.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-falcon-subtle text-sm">
                      イベントが見つかりません
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
