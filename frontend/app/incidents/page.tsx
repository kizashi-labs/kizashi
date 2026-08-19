'use client'

import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { DataUnavailable } from '@/components/DataUnavailable'
import { useCanWrite } from '@/lib/auth'
import { useRouter } from 'next/navigation'
import {
  Siren, Plus, X, ChevronRight, Search, Download,
  LayoutList, Columns, Layers, RefreshCw,
} from 'lucide-react'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Incident {
  id: string
  title: string
  description: string
  severity: number
  status: string
  assigned_to: string
  assigned_to_name: string
  created_by_name: string
  alert_count: number
  created_at: string
  updated_at: string
  resolved_at?: string
}

interface IncidentResponse {
  data: Incident[]
  incidents?: Incident[]
  total: number
  has_more: boolean
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STATUS_OPTIONS = ['', 'open', 'investigating', 'contained', 'resolved', 'closed']

const STATUS_LABELS: Record<string, string> = {
  '': 'すべて',
  open: '未対応',
  investigating: '調査中',
  contained: '封じ込め済み',
  resolved: '解決済み',
  closed: 'クローズ',
}

const STATUS_COLORS: Record<string, string> = {
  open: 'bg-red-900/50 text-red-300',
  investigating: 'bg-orange-900/50 text-orange-300',
  contained: 'bg-yellow-900/50 text-yellow-300',
  resolved: 'bg-green-900/50 text-green-300',
  closed: 'bg-[#161f33] text-[#8899aa]',
}

// Kanban board columns (4 main statuses)
const KANBAN_COLUMNS: { status: string; label: string; borderColor: string; headerBg: string; badgeBg: string }[] = [
  {
    status: 'open',
    label: '未対応',
    borderColor: 'border-t-blue-500',
    headerBg: 'bg-blue-900/20',
    badgeBg: 'bg-blue-900/60 text-blue-300',
  },
  {
    status: 'investigating',
    label: '調査中',
    borderColor: 'border-t-yellow-500',
    headerBg: 'bg-yellow-900/20',
    badgeBg: 'bg-yellow-900/60 text-yellow-300',
  },
  {
    status: 'contained',
    label: '封じ込め済み',
    borderColor: 'border-t-orange-500',
    headerBg: 'bg-orange-900/20',
    badgeBg: 'bg-orange-900/60 text-orange-300',
  },
  {
    status: 'resolved',
    label: '解決済み',
    borderColor: 'border-t-green-500',
    headerBg: 'bg-green-900/20',
    badgeBg: 'bg-green-900/60 text-green-300',
  },
]

const SEVERITY_BANDS = [
  { label: 'クリティカル', min: 9, max: 10, color: 'text-red-400', bg: 'bg-red-900/20 border-red-900/40' },
  { label: '高',           min: 7, max: 8,  color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-900/40' },
  { label: '中',           min: 5, max: 6,  color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-900/40' },
  { label: '低',           min: 1, max: 4,  color: 'text-blue-400',   bg: 'bg-blue-900/20 border-blue-900/40' },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function severityColor(s: number) {
  if (s >= 9) return 'text-red-400'
  if (s >= 7) return 'text-orange-400'
  if (s >= 5) return 'text-yellow-400'
  return 'text-blue-400'
}

function severityBg(s: number) {
  if (s >= 9) return 'bg-red-900/40 border-red-700'
  if (s >= 7) return 'bg-orange-900/40 border-orange-700'
  if (s >= 5) return 'bg-yellow-900/40 border-yellow-700'
  return 'bg-blue-900/40 border-blue-700'
}

function severityLabel(s: number) {
  if (s >= 9) return 'クリティカル'
  if (s >= 7) return '高'
  if (s >= 5) return '中'
  return '低'
}

function severityBadgeStyle(s: number) {
  if (s >= 9) return 'bg-red-900/60 text-red-300 border border-red-700/50'
  if (s >= 7) return 'bg-orange-900/60 text-orange-300 border border-orange-700/50'
  if (s >= 5) return 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50'
  return 'bg-blue-900/60 text-blue-300 border border-blue-700/50'
}

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  } catch {
    return iso
  }
}

// SLA閾値（時間）: Critical=4h, High=24h, Medium=72h, Low=168h
const SLA_HOURS: Record<string, number> = { critical: 4, high: 24, medium: 72, low: 168 }

function slaHours(severity: number): number {
  if (severity >= 9) return SLA_HOURS.critical
  if (severity >= 7) return SLA_HOURS.high
  if (severity >= 5) return SLA_HOURS.medium
  return SLA_HOURS.low
}

function SLAIndicator({ severity, createdAt }: { severity: number; createdAt: string }) {
  const elapsed = (Date.now() - new Date(createdAt).getTime()) / 3_600_000
  const limit = slaHours(severity)
  const pct = Math.min(elapsed / limit * 100, 100)
  const remaining = limit - elapsed

  let barColor = 'bg-green-500'
  let textColor = 'text-green-400'
  let label = ''

  if (pct >= 100) {
    barColor = 'bg-red-500'
    textColor = 'text-red-400'
    label = `${Math.floor(elapsed - limit)}h超過`
  } else if (pct >= 75) {
    barColor = 'bg-orange-500'
    textColor = 'text-orange-400'
    label = `残${remaining < 1 ? `${Math.round(remaining * 60)}分` : `${remaining.toFixed(0)}h`}`
  } else {
    label = `残${remaining < 1 ? `${Math.round(remaining * 60)}分` : `${remaining.toFixed(0)}h`}`
  }

  return (
    <div className="mt-2">
      <div className="flex items-center justify-between mb-0.5">
        <span className="text-[9px] text-[#3d5068]">SLA</span>
        <span className={`text-[9px] font-medium ${textColor}`}>{label}</span>
      </div>
      <div className="h-1 bg-[#1e2d42] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Kanban Card
// ---------------------------------------------------------------------------

interface KanbanCardProps {
  incident: Incident
  onDragStart: () => void
  onClick: () => void
}

function KanbanCard({ incident, onDragStart, onClick }: KanbanCardProps) {
  return (
    <div
      draggable
      onDragStart={onDragStart}
      onClick={onClick}
      className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3 cursor-grab active:cursor-grabbing hover:border-[#2d4060] transition-all select-none group"
    >
      {/* Title */}
      <p className="text-sm font-medium text-white leading-snug line-clamp-2 mb-2 group-hover:text-blue-100 transition-colors">
        {incident.title}
      </p>

      {/* Severity badge */}
      <div className="flex items-center gap-1.5 mb-2 flex-wrap">
        <span className={`text-[10px] px-1.5 py-0.5 rounded-sm font-semibold ${severityBadgeStyle(incident.severity)}`}>
          {severityLabel(incident.severity)} ({incident.severity})
        </span>
      </div>

      {/* Meta info */}
      <div className="space-y-1">
        {incident.assigned_to_name && (
          <div className="flex items-center gap-1.5 text-[11px] text-[#7d92b0]">
            <span className="w-4 h-4 rounded-full bg-[#1e2d42] flex items-center justify-center text-[9px] font-bold text-white shrink-0">
              {incident.assigned_to_name.charAt(0).toUpperCase()}
            </span>
            <span className="truncate">{incident.assigned_to_name}</span>
          </div>
        )}
        <div className="flex items-center justify-between text-[10px] text-[#5a6a7a]">
          <span>{fmtDate(incident.created_at)}</span>
          {incident.alert_count > 0 && (
            <span className="flex items-center gap-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" />
              {incident.alert_count} alert{incident.alert_count !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>
      {/* SLA インジケーター（open/investigating のみ表示）*/}
      {(incident.status === 'open' || incident.status === 'investigating') && (
        <SLAIndicator severity={incident.severity} createdAt={incident.created_at} />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Kanban Column
// ---------------------------------------------------------------------------

interface KanbanColumnProps {
  col: typeof KANBAN_COLUMNS[number]
  incidents: Incident[]
  dragId: string | null
  setDragId: (id: string | null) => void
  onDrop: (status: string) => void
  onCardClick: (id: string) => void
  isDragOver: boolean
  setDragOverCol: (status: string | null) => void
}

function KanbanColumn({
  col, incidents, dragId, setDragId, onDrop, onCardClick, isDragOver, setDragOverCol,
}: KanbanColumnProps) {
  return (
    <div
      className={`flex flex-col min-w-[240px] flex-1 rounded-xl border border-[#1e2d42] border-t-4 ${col.borderColor}
                  transition-colors ${isDragOver ? 'bg-[#0d1a2d] border-[#2d4060]' : 'bg-[#070d19]'}`}
      onDragOver={(e) => { e.preventDefault(); setDragOverCol(col.status) }}
      onDragLeave={() => setDragOverCol(null)}
      onDrop={(e) => { e.preventDefault(); setDragOverCol(null); onDrop(col.status) }}
    >
      {/* Column Header */}
      <div className={`flex items-center justify-between px-3 py-2.5 rounded-t-lg ${col.headerBg}`}>
        <span className="text-sm font-semibold text-white">{col.label}</span>
        <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${col.badgeBg}`}>
          {incidents.length}
        </span>
      </div>

      {/* Drop zone / Cards */}
      <div className="flex-1 p-2 space-y-2 min-h-[120px]">
        {incidents.length === 0 && (
          <div className={`flex items-center justify-center h-20 rounded-lg border border-dashed
                           transition-colors text-xs
                           ${isDragOver
                             ? 'border-[#4a6080] text-[#7d92b0] bg-[#0d1a2d]'
                             : 'border-[#1e2d42] text-[#3a4a5a]'}`}>
            {isDragOver ? 'Drop here' : 'No incidents'}
          </div>
        )}
        {incidents.map(inc => (
          <KanbanCard
            key={inc.id}
            incident={inc}
            onDragStart={() => setDragId(inc.id)}
            onClick={() => onCardClick(inc.id)}
          />
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Kanban Board (full view)
// ---------------------------------------------------------------------------

interface KanbanBoardProps {
  incidents: Incident[]
  swimlanes: boolean
  onMoveIncident: (id: string, newStatus: string) => void
  onCardClick: (id: string) => void
}

function KanbanBoard({ incidents, swimlanes, onMoveIncident, onCardClick }: KanbanBoardProps) {
  const [dragId, setDragId] = useState<string | null>(null)
  const [dragOverCol, setDragOverCol] = useState<string | null>(null)

  const handleDrop = (status: string) => {
    if (dragId) {
      onMoveIncident(dragId, status)
      setDragId(null)
    }
  }

  if (!swimlanes) {
    // Flat board
    return (
      <div className="flex gap-3 overflow-x-auto pb-4">
        {KANBAN_COLUMNS.map(col => {
          const colIncidents = incidents.filter(i => i.status === col.status)
          return (
            <KanbanColumn
              key={col.status}
              col={col}
              incidents={colIncidents}
              dragId={dragId}
              setDragId={setDragId}
              onDrop={handleDrop}
              onCardClick={onCardClick}
              isDragOver={dragOverCol === col.status}
              setDragOverCol={setDragOverCol}
            />
          )
        })}
      </div>
    )
  }

  // Swimlane board — rows by severity band
  return (
    <div className="space-y-4 overflow-x-auto pb-4">
      {SEVERITY_BANDS.map(band => {
        const bandIncidents = incidents.filter(i => i.severity >= band.min && i.severity <= band.max)
        if (bandIncidents.length === 0) return null
        return (
          <div key={band.label} className={`rounded-xl border ${band.bg} p-3`}>
            {/* Swimlane header */}
            <div className="flex items-center gap-2 mb-3">
              <span className={`text-xs font-bold uppercase tracking-wider ${band.color}`}>{band.label}</span>
              <span className="text-xs text-[#5a6a7a]">({bandIncidents.length} incidents)</span>
            </div>
            <div className="flex gap-3">
              {KANBAN_COLUMNS.map(col => {
                const colIncidents = bandIncidents.filter(i => i.status === col.status)
                return (
                  <KanbanColumn
                    key={col.status}
                    col={col}
                    incidents={colIncidents}
                    dragId={dragId}
                    setDragId={setDragId}
                    onDrop={handleDrop}
                    onCardClick={onCardClick}
                    isDragOver={dragOverCol === `${band.label}-${col.status}`}
                    setDragOverCol={(s) => setDragOverCol(s ? `${band.label}-${s}` : null)}
                  />
                )
              })}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export default function IncidentsPage() {
  const router = useRouter()
  const qc = useQueryClient()
  const canWrite = useCanWrite()

  // View state
  const [viewMode, setViewMode] = useState<'list' | 'board'>('list')
  const [swimlanes, setSwimlanes] = useState(false)

  // List view state
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)

  // Create form state
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ title: '', description: '', severity: 7, status: 'open' })

  // ---------------------------------------------------------------------------
  // Data fetching
  // ---------------------------------------------------------------------------

  const { data, isLoading, error, refetch } = useQuery<IncidentResponse>({
    queryKey: ['incidents', statusFilter, page],
    queryFn: () => {
      const params = new URLSearchParams()
      if (statusFilter) params.set('status', statusFilter)
      params.set('page', String(page))
      params.set('per_page', '20')
      return apiFetch(`/api/v1/incidents?${params}`)
    },
    refetchInterval: 30000,
  })

  // For board view we fetch all incidents without status filter
  const { data: boardData } = useQuery<IncidentResponse>({
    queryKey: ['incidents-board'],
    queryFn: () => apiFetch(`/api/v1/incidents?per_page=200`),
    enabled: viewMode === 'board',
    refetchInterval: 30000,
  })

  const rawListIncidents = data?.data ?? data?.incidents ?? []
  const allListIncidents = search
    ? rawListIncidents.filter(i => i.title.toLowerCase().includes(search.toLowerCase()))
    : rawListIncidents

  const boardIncidents: Incident[] = boardData?.data ?? boardData?.incidents ?? []

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/incidents', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incidents-board'] })
      setShowForm(false)
      setForm({ title: '', description: '', severity: 7, status: 'open' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      apiFetch(`/api/v1/incidents/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incidents-board'] })
    },
  })

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault()
    createMutation.mutate(form)
  }

  const handleMoveIncident = (id: string, newStatus: string) => {
    if (!canWrite) return
    const inc = boardIncidents.find(i => i.id === id)
    if (!inc || inc.status === newStatus) return
    updateMutation.mutate({ id, status: newStatus })
  }

  function exportCSV() {
    if (allListIncidents.length === 0) return
    const headers = ['id', 'title', 'severity', 'status', 'assigned_to', 'alert_count', 'created_at']
    const rows = allListIncidents.map(i => [
      i.id, i.title, i.severity,
      STATUS_LABELS[i.status] ?? i.status,
      i.assigned_to_name ?? '',
      i.alert_count,
      i.created_at,
    ])
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `incidents-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="p-6 min-h-screen bg-[#070d19]">
      <PageSaveFailed className="mb-4" />
      <div className={viewMode === 'board' ? 'max-w-full' : 'max-w-5xl mx-auto'}>

        {/* ------------------------------------------------------------------ */}
        {/* Header                                                               */}
        {/* ------------------------------------------------------------------ */}
        <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <Siren className="text-red-400" size={24} />
            <h1 className="text-2xl font-bold text-white">インシデント管理</h1>
            <span className="text-sm text-[#7d92b0]">({data?.total ?? 0}件)</span>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Swimlane toggle (board only) */}
            {viewMode === 'board' && (
              <button
                onClick={() => setSwimlanes(v => !v)}
                className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                  swimlanes
                    ? 'bg-indigo-600 text-white'
                    : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'
                }`}
                title="Toggle swimlanes by severity"
              >
                <Layers size={14} />
                Swimlanes
              </button>
            )}

            {/* List / Board toggle */}
            <div className="flex bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <button
                onClick={() => setViewMode('list')}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm transition-colors ${
                  viewMode === 'list'
                    ? 'bg-[#e8002d] text-white'
                    : 'text-[#7d92b0] hover:text-white'
                }`}
              >
                <LayoutList size={14} />
                List
              </button>
              <button
                onClick={() => setViewMode('board')}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm transition-colors ${
                  viewMode === 'board'
                    ? 'bg-[#e8002d] text-white'
                    : 'text-[#7d92b0] hover:text-white'
                }`}
              >
                <Columns size={14} />
                Board
              </button>
            </div>

            <button
              onClick={() => {
                qc.invalidateQueries({ queryKey: ['incidents'] })
                qc.invalidateQueries({ queryKey: ['incidents-board'] })
              }}
              className="flex items-center gap-1.5 px-3 py-2 bg-[#0d1220] border border-[#1e2d42] hover:bg-[#1d2f4a] text-[#7d92b0] text-sm rounded-lg transition-colors"
              title="更新"
            >
              <RefreshCw size={14} />
              更新
            </button>

            <button
              onClick={exportCSV}
              disabled={allListIncidents.length === 0}
              className="flex items-center gap-1.5 px-3 py-2 bg-[#0d1220] border border-[#1e2d42] hover:bg-[#1d2f4a] text-[#7d92b0] text-sm rounded-lg transition-colors disabled:opacity-40"
            >
              <Download size={14} />
              CSV
            </button>

            {canWrite && (
              <button
                onClick={() => setShowForm(v => !v)}
                className="flex items-center gap-2 bg-[#e8002d] hover:bg-[#b5001e] px-4 py-2 rounded-lg text-sm font-medium text-white"
              >
                <Plus size={16} />
                新規インシデント
              </button>
            )}
          </div>
        </div>

        {/* 上の見出しは取得に失敗すると (0件) と表示します。
            その 0 が事実かどうかをここで言う。 */}
        <DataUnavailable error={error} what="インシデント" onRetry={refetch} className="mb-6" />

        {/* ------------------------------------------------------------------ */}
        {/* Create Form                                                          */}
        {/* ------------------------------------------------------------------ */}
        {canWrite && showForm && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-red-400">新しいインシデント</h2>
              <button onClick={() => setShowForm(false)} className="text-[#7d92b0] hover:text-white">
                <X size={18} />
              </button>
            </div>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">タイトル *</label>
                <input
                  required
                  value={form.title}
                  onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                  className="w-full bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]"
                  placeholder="例: ランサムウェア感染疑い"
                />
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
                <textarea
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  className="w-full bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm h-20 resize-none text-white focus:outline-hidden focus:border-[#e8002d]"
                  placeholder="インシデントの詳細"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">重大度 (1-10)</label>
                  <input
                    type="number" min={1} max={10}
                    value={form.severity}
                    onChange={e => setForm(f => ({ ...f, severity: parseInt(e.target.value) || 7 }))}
                    className="w-full bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">ステータス</label>
                  <select
                    value={form.status}
                    onChange={e => setForm(f => ({ ...f, status: e.target.value }))}
                    className="w-full bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]"
                  >
                    {STATUS_OPTIONS.slice(1).map(s => (
                      <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                    ))}
                  </select>
                </div>
              </div>
              {createMutation.isError && (
                <p className="text-red-400 text-sm">作成に失敗しました</p>
              )}
              <div className="flex gap-3">
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="bg-[#e8002d] hover:bg-[#b5001e] disabled:opacity-50 px-5 py-2 rounded-lg text-sm font-medium text-white"
                >
                  {createMutation.isPending ? '作成中...' : '作成'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowForm(false)}
                  className="text-[#7d92b0] hover:text-white text-sm px-3"
                >
                  キャンセル
                </button>
              </div>
            </form>
          </div>
        )}

        {/* ------------------------------------------------------------------ */}
        {/* BOARD VIEW                                                           */}
        {/* ------------------------------------------------------------------ */}
        {viewMode === 'board' && (
          <div>
            {/* Board search */}
            <div className="flex items-center gap-3 mb-4 flex-wrap">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="タイトルで検索..."
                  className="pl-8 pr-3 py-1.5 text-sm border border-[#1e2d42] rounded-lg bg-[#0d1220] text-white placeholder-[#5a6a7a] w-52 focus:outline-hidden focus:border-[#e8002d]"
                />
              </div>
              {search && (
                <button
                  onClick={() => setSearch('')}
                  className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white px-2 py-1.5 rounded-lg hover:bg-[#0d1220] transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
              {updateMutation.isPending && (
                <span className="text-xs text-[#7d92b0] animate-pulse">Moving...</span>
              )}
            </div>

            {isLoading && boardIncidents.length === 0 ? (
              <div className="text-center py-16 text-[#7d92b0]">読み込み中...</div>
            ) : (
              <KanbanBoard
                incidents={search
                  ? boardIncidents.filter(i => i.title.toLowerCase().includes(search.toLowerCase()))
                  : boardIncidents}
                swimlanes={swimlanes}
                onMoveIncident={handleMoveIncident}
                onCardClick={(id) => router.push(`/incidents/${id}`)}
              />
            )}

            {/* Board legend */}
            <div className="mt-4 flex items-center gap-4 flex-wrap">
              <span className="text-xs text-[#5a6a7a]">Drag cards between columns to update status.</span>
              <div className="flex items-center gap-3">
                {KANBAN_COLUMNS.map(col => (
                  <div key={col.status} className="flex items-center gap-1">
                    <span className={`w-2 h-2 rounded-full ${col.badgeBg.split(' ')[0]}`} />
                    <span className="text-[10px] text-[#5a6a7a]">{col.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ------------------------------------------------------------------ */}
        {/* LIST VIEW                                                            */}
        {/* ------------------------------------------------------------------ */}
        {viewMode === 'list' && (
          <>
            {/* Search + Filter */}
            <div className="flex items-center gap-3 mb-4 flex-wrap">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="タイトルで検索..."
                  className="pl-8 pr-3 py-1.5 text-sm border border-[#1e2d42] rounded-lg bg-[#0d1220] text-white placeholder-[#5a6a7a] w-52 focus:outline-hidden focus:border-[#e8002d]"
                />
              </div>
              {search && (
                <button
                  onClick={() => setSearch('')}
                  className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white px-2 py-1.5 rounded-lg hover:bg-[#0d1220] transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Status Filter Tabs */}
            <div className="flex gap-2 mb-6 flex-wrap">
              {STATUS_OPTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => { setStatusFilter(s); setPage(1) }}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                    statusFilter === s
                      ? 'bg-[#e8002d] text-white'
                      : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'
                  }`}
                >
                  {STATUS_LABELS[s]}
                </button>
              ))}
            </div>

            {/* Incident List */}
            {isLoading ? (
              <div className="text-center py-12 text-[#7d92b0]">読み込み中...</div>
            ) : allListIncidents.length === 0 ? (
              <div className="text-center py-12 text-[#5a6a7a]">
                <Siren size={48} className="mx-auto mb-3 opacity-30" />
                <p>インシデントがありません</p>
              </div>
            ) : (
              <div className="space-y-3">
                {allListIncidents.map(inc => (
                  <div
                    key={inc.id}
                    onClick={() => router.push(`/incidents/${inc.id}`)}
                    className={`bg-[#0d1220] border rounded-xl p-4 cursor-pointer hover:border-[#2d4060]
                                transition-all flex items-center gap-4 ${severityBg(inc.severity)}`}
                  >
                    {/* Severity Score */}
                    <div className={`text-2xl font-bold w-10 text-center ${severityColor(inc.severity)}`}>
                      {inc.severity}
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-semibold truncate text-white">{inc.title}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full whitespace-nowrap ${STATUS_COLORS[inc.status] ?? 'bg-[#161f33] text-[#7d92b0]'}`}>
                          {STATUS_LABELS[inc.status] ?? inc.status}
                        </span>
                      </div>
                      {inc.description && (
                        <p className="text-xs text-[#7d92b0] truncate">{inc.description}</p>
                      )}
                      <div className="flex gap-4 mt-1 text-xs text-[#5a6a7a]">
                        <span>アラート: {inc.alert_count}件</span>
                        {inc.assigned_to_name && <span>担当: {inc.assigned_to_name}</span>}
                        <span>{new Date(inc.created_at).toLocaleString('ja-JP')}</span>
                      </div>
                    </div>

                    <ChevronRight size={16} className="text-[#5a6a7a] shrink-0" />
                  </div>
                ))}
              </div>
            )}

            {/* Pagination */}
            {(data?.total ?? 0) > 20 && (
              <div className="flex justify-center gap-3 mt-6">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage(p => p - 1)}
                  className="px-4 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-sm disabled:opacity-40 hover:bg-[#1d2f4a] text-white"
                >
                  前へ
                </button>
                <span className="px-4 py-2 text-sm text-[#7d92b0]">
                  {page} / {Math.ceil((data?.total ?? 0) / 20)}
                </span>
                <button
                  disabled={!data?.has_more}
                  onClick={() => setPage(p => p + 1)}
                  className="px-4 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-sm disabled:opacity-40 hover:bg-[#1d2f4a] text-white"
                >
                  次へ
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
