'use client'

import { useState, useCallback, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Clock, Users, UserCircle, Play, StopCircle, Plus, Trash2,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle, Loader2,
  RefreshCw, FileText, Calendar, BarChart2, X
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'
import { usePersist, SaveFailed } from '@/lib/persist'

// ─── Types ────────────────────────────────────────────────────────────────────

type ShiftStatus = 'active' | 'completed' | 'cancelled'
type TaskPriority = 'low' | 'medium' | 'high' | 'critical'

interface TeamMember {
  id: string
  name: string
  role: string
}

interface HandoverTask {
  id: string
  description: string
  assignee_id: string
  assignee_name: string
  priority: TaskPriority
  completed: boolean
}

interface Shift {
  id: string
  name: string
  lead_id: string
  lead_name: string
  team: TeamMember[]
  started_at: string
  ended_at: string | null
  status: ShiftStatus
  handover_notes: string
  tasks: HandoverTask[]
  metrics: {
    open_alerts: number
    open_incidents: number
    tickets_created: number
    alerts_resolved: number
  }
}

interface ShiftStats {
  open_alerts: number
  open_incidents: number
  tickets_created: number
  alerts_resolved: number
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_USERS: TeamMember[] = [
  { id: 'u1', name: '田中 太郎', role: 'Senior Analyst' },
  { id: 'u2', name: '鈴木 花子', role: 'Analyst' },
  { id: 'u3', name: '佐藤 健一', role: 'Analyst' },
  { id: 'u4', name: '山田 美智子', role: 'Junior Analyst' },
  { id: 'u5', name: '伊藤 次郎', role: 'Tier 1 Analyst' },
]

const now = new Date()
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3600_000).toISOString()
const daysAgo = (d: number) => new Date(now.getTime() - d * 86400_000).toISOString()

const MOCK_CURRENT_SHIFT: Shift = {
  id: 's-current',
  name: '夜間シフト 2026-03-18',
  lead_id: 'u1',
  lead_name: '田中 太郎',
  team: [
    { id: 'u2', name: '鈴木 花子', role: 'Analyst' },
    { id: 'u3', name: '佐藤 健一', role: 'Analyst' },
    { id: 'u5', name: '伊藤 次郎', role: 'Tier 1 Analyst' },
  ],
  started_at: hoursAgo(5),
  ended_at: null,
  status: 'active',
  handover_notes: '• ランサムウェア疑いのアラート (ALT-20260318-001) を調査中 — 田中が担当\n• 外部C2接続の疑い (DESKTOP-FIN-04) — 鈴木がフォレンジクス実施中\n• 朝シフトへの引継ぎ: 上記2件は未解決のため継続対応が必要',
  tasks: [
    { id: 'tk1', description: 'ALT-20260318-001 のエスカレーション判断', assignee_id: 'u1', assignee_name: '田中 太郎', priority: 'critical', completed: false },
    { id: 'tk2', description: 'DESKTOP-FIN-04 のメモリダンプ解析', assignee_id: 'u2', assignee_name: '鈴木 花子', priority: 'high', completed: false },
    { id: 'tk3', description: '夜間シフトサマリーレポートの作成', assignee_id: 'u3', assignee_name: '佐藤 健一', priority: 'medium', completed: true },
  ],
  metrics: { open_alerts: 12, open_incidents: 3, tickets_created: 7, alerts_resolved: 24 },
}

const MOCK_HISTORY: Shift[] = [
  {
    id: 's1',
    name: '日勤シフト 2026-03-18',
    lead_id: 'u4', lead_name: '山田 美智子',
    team: [{ id: 'u5', name: '伊藤 次郎', role: 'Tier 1 Analyst' }, { id: 'u3', name: '佐藤 健一', role: 'Analyst' }],
    started_at: hoursAgo(13), ended_at: hoursAgo(5), status: 'completed',
    handover_notes: '特記事項なし。通常業務を引き継ぎ。',
    tasks: [],
    metrics: { open_alerts: 8, open_incidents: 1, tickets_created: 5, alerts_resolved: 31 },
  },
  {
    id: 's2',
    name: '夜間シフト 2026-03-17',
    lead_id: 'u1', lead_name: '田中 太郎',
    team: [{ id: 'u2', name: '鈴木 花子', role: 'Analyst' }],
    started_at: daysAgo(1), ended_at: hoursAgo(13), status: 'completed',
    handover_notes: 'フィッシングキャンペーンの痕跡を検出。メール全件精査を推奨。',
    tasks: [{ id: 'tk-h1', description: 'フィッシングメール調査継続', assignee_id: 'u4', assignee_name: '山田 美智子', priority: 'high', completed: true }],
    metrics: { open_alerts: 19, open_incidents: 2, tickets_created: 9, alerts_resolved: 18 },
  },
  {
    id: 's3',
    name: '日勤シフト 2026-03-17',
    lead_id: 'u3', lead_name: '佐藤 健一',
    team: [{ id: 'u4', name: '山田 美智子', role: 'Junior Analyst' }, { id: 'u5', name: '伊藤 次郎', role: 'Tier 1 Analyst' }],
    started_at: daysAgo(2), ended_at: daysAgo(1), status: 'completed',
    handover_notes: 'VPNアクセス異常 (IP: 198.51.100.42) を検出。IPブロック済み。',
    tasks: [],
    metrics: { open_alerts: 6, open_incidents: 0, tickets_created: 3, alerts_resolved: 42 },
  },
  {
    id: 's4',
    name: '夜間シフト 2026-03-16',
    lead_id: 'u2', lead_name: '鈴木 花子',
    team: [{ id: 'u1', name: '田中 太郎', role: 'Senior Analyst' }],
    started_at: daysAgo(3), ended_at: daysAgo(2), status: 'completed',
    handover_notes: '大きなインシデントなし。軽微なアラート22件をクローズ。',
    tasks: [],
    metrics: { open_alerts: 4, open_incidents: 0, tickets_created: 2, alerts_resolved: 22 },
  },
  {
    id: 's5',
    name: '日勤シフト 2026-03-16',
    lead_id: 'u4', lead_name: '山田 美智子',
    team: [{ id: 'u3', name: '佐藤 健一', role: 'Analyst' }, { id: 'u5', name: '伊藤 次郎', role: 'Tier 1 Analyst' }],
    started_at: daysAgo(4), ended_at: daysAgo(3), status: 'completed',
    handover_notes: 'Splunkインデクサー障害対応。17:00に復旧。ログ欠損なし。',
    tasks: [],
    metrics: { open_alerts: 11, open_incidents: 1, tickets_created: 6, alerts_resolved: 35 },
  },
]

const MOCK_STATS: ShiftStats = {
  open_alerts: 12,
  open_incidents: 3,
  tickets_created: 7,
  alerts_resolved: 24,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatElapsed(startedAt: string): string {
  const ms = Date.now() - new Date(startedAt).getTime()
  const h = Math.floor(ms / 3600_000)
  const m = Math.floor((ms % 3600_000) / 60_000)
  return `${h}時間${m}分`
}

function formatDuration(start: string, end: string | null): string {
  if (!end) return formatElapsed(start)
  const ms = new Date(end).getTime() - new Date(start).getTime()
  const h = Math.floor(ms / 3600_000)
  const m = Math.floor((ms % 3600_000) / 60_000)
  return `${h}時間${m}分`
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function initials(name: string): string {
  return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2)
}

const PRIORITY_STYLES: Record<TaskPriority, string> = {
  critical: 'bg-red-900/40 text-red-400 border border-red-800/40',
  high: 'bg-orange-900/40 text-orange-400 border border-orange-800/40',
  medium: 'bg-yellow-900/40 text-yellow-400 border border-yellow-800/40',
  low: 'bg-blue-900/40 text-blue-400 border border-blue-800/40',
}

const PRIORITY_LABELS: Record<TaskPriority, string> = {
  critical: 'クリティカル', high: '高', medium: '中', low: '低',
}

// ─── Avatar ───────────────────────────────────────────────────────────────────

function Avatar({ name, size = 'sm' }: { name: string; size?: 'sm' | 'md' }) {
  const colors = ['from-blue-600 to-blue-800', 'from-purple-600 to-purple-800', 'from-green-600 to-green-800', 'from-orange-600 to-orange-800', 'from-pink-600 to-pink-800']
  const color = colors[name.charCodeAt(0) % colors.length]
  const sz = size === 'sm' ? 'w-7 h-7 text-[10px]' : 'w-9 h-9 text-xs'
  return (
    <div className={`${sz} rounded-full bg-linear-to-br ${color} flex items-center justify-center font-bold text-white shrink-0`}>
      {initials(name)}
    </div>
  )
}

// ─── Start Shift Modal ────────────────────────────────────────────────────────

function StartShiftModal({ onClose, onStart }: { onClose: () => void; onStart: (data: { name: string; lead_id: string; team_ids: string[] }) => void }) {
  const today = new Date().toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' }).replace(/\//g, '-')
  const [name, setName] = useState(`夜間シフト ${today}`)
  const [leadId, setLeadId] = useState('')
  const [teamIds, setTeamIds] = useState<string[]>([])

  const toggleTeam = (id: string) => {
    setTeamIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id])
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold text-lg flex items-center gap-2">
            <Play className="w-5 h-5 text-green-400" />
            シフト開始
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Shift name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5 font-medium">シフト名</label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#3d5068] focus:ring-1 focus:ring-[#3d5068]"
              placeholder="夜間シフト 2026-03-18"
            />
          </div>

          {/* Lead analyst */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5 font-medium">リードアナリスト</label>
            <select
              value={leadId}
              onChange={e => setLeadId(e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#3d5068]"
            >
              {([] as TeamMember[]).map(u => (
                <option key={u.id} value={u.id}>{u.name} — {u.role}</option>
              ))}
            </select>
          </div>

          {/* Team members */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5 font-medium">チームメンバー（複数選択）</label>
            <div className="space-y-1.5">
              {([] as TeamMember[]).filter(u => u.id !== leadId).map(u => (
                <label key={u.id} className="flex items-center gap-2.5 px-3 py-2 rounded-sm border border-[#1e2d42] hover:border-[#3d5068] cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={teamIds.includes(u.id)}
                    onChange={() => toggleTeam(u.id)}
                    className="accent-[#e8002d]"
                  />
                  <Avatar name={u.name} size="sm" />
                  <div>
                    <p className="text-sm text-white">{u.name}</p>
                    <p className="text-[10px] text-[#7d92b0]">{u.role}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="flex gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="flex-1 px-4 py-2 rounded-sm border border-[#1e2d42] text-sm text-[#7d92b0] hover:text-white hover:border-[#3d5068] transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => onStart({ name, lead_id: leadId, team_ids: teamIds })}
            className="flex-1 px-4 py-2 rounded-sm bg-green-700 hover:bg-green-600 text-white text-sm font-medium transition-colors flex items-center justify-center gap-2"
          >
            <Play className="w-4 h-4" />
            シフト開始
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── End Shift Modal ──────────────────────────────────────────────────────────

function EndShiftModal({ shift, onClose, onEnd }: { shift: Shift; onClose: () => void; onEnd: () => void }) {
  const pendingTasks = shift.tasks.filter(t => !t.completed)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold text-lg flex items-center gap-2">
            <StopCircle className="w-5 h-5 text-[#e8002d]" />
            シフト終了確認
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {pendingTasks.length > 0 && (
            <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-sm p-3">
              <p className="text-yellow-400 text-sm font-medium flex items-center gap-1.5 mb-2">
                <AlertTriangle className="w-4 h-4" />
                未完了タスクがあります ({pendingTasks.length}件)
              </p>
              <ul className="space-y-1">
                {pendingTasks.map(t => (
                  <li key={t.id} className="text-xs text-yellow-300/80 flex items-start gap-1.5">
                    <span className="mt-0.5">•</span>
                    <span>{t.description}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3">
            <p className="text-xs text-[#7d92b0] mb-1 font-medium">引継ぎメモ（プレビュー）</p>
            <p className="text-sm text-white whitespace-pre-line line-clamp-4">
              {shift.handover_notes || '（メモなし）'}
            </p>
          </div>

          <p className="text-sm text-[#7d92b0]">
            シフトを終了してよろしいですか？引継ぎ事項は次のシフトに引き渡されます。
          </p>
        </div>

        <div className="flex gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="flex-1 px-4 py-2 rounded-sm border border-[#1e2d42] text-sm text-[#7d92b0] hover:text-white hover:border-[#3d5068] transition-colors">
            キャンセル
          </button>
          <button
            onClick={onEnd}
            className="flex-1 px-4 py-2 rounded-sm bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors flex items-center justify-center gap-2"
          >
            <StopCircle className="w-4 h-4" />
            シフト終了
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── History Row ──────────────────────────────────────────────────────────────

function HistoryRow({ shift }: { shift: Shift }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <>
      <tr
        className="border-b border-[#1e2d42] hover:bg-[#0d1220] cursor-pointer transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <td className="px-4 py-3 text-sm text-white font-medium">{shift.name}</td>
        <td className="px-4 py-3 text-sm text-[#7d92b0]">{formatDateTime(shift.started_at)}</td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5">
            <Avatar name={shift.lead_name} size="sm" />
            <span className="text-sm text-white">{shift.lead_name}</span>
          </div>
        </td>
        <td className="px-4 py-3 text-sm text-[#7d92b0] text-center">{shift.team.length + 1}</td>
        <td className="px-4 py-3 text-sm text-[#7d92b0]">{formatDuration(shift.started_at, shift.ended_at)}</td>
        <td className="px-4 py-3 text-sm text-[#7d92b0] text-center">{shift.metrics.alerts_resolved}</td>
        <td className="px-4 py-3 text-sm text-[#7d92b0] text-center">{shift.metrics.open_incidents}</td>
        <td className="px-4 py-3 max-w-[180px]">
          <span className="text-xs text-[#7d92b0] line-clamp-2">{shift.handover_notes || '—'}</span>
        </td>
        <td className="px-4 py-3">
          <span className="text-xs px-2 py-0.5 rounded-sm bg-green-900/30 text-green-400 border border-green-800/40">完了</span>
        </td>
        <td className="px-4 py-3 text-[#3d5068]">
          {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-[#1e2d42] bg-[#070d19]/60">
          <td colSpan={10} className="px-6 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-[#7d92b0] font-medium mb-2">引継ぎメモ（全文）</p>
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-sm p-3">
                  <p className="text-sm text-white whitespace-pre-line">{shift.handover_notes || '（メモなし）'}</p>
                </div>
              </div>
              <div>
                <p className="text-xs text-[#7d92b0] font-medium mb-2">引継ぎタスク ({shift.tasks.length}件)</p>
                {shift.tasks.length === 0 ? (
                  <p className="text-sm text-[#3d5068] italic">タスクなし</p>
                ) : (
                  <div className="space-y-1.5">
                    {shift.tasks.map(t => (
                      <div key={t.id} className="flex items-center gap-2 p-2 rounded-sm bg-[#0d1220] border border-[#1e2d42]">
                        <CheckCircle className={`w-4 h-4 shrink-0 ${t.completed ? 'text-green-400' : 'text-[#3d5068]'}`} />
                        <span className="flex-1 text-sm text-white">{t.description}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${PRIORITY_STYLES[t.priority]}`}>{PRIORITY_LABELS[t.priority]}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Shift Calendar ───────────────────────────────────────────────────────────

function ShiftCalendar({ allShifts }: { allShifts: Shift[] }) {
  const today = new Date()
  today.setHours(0, 0, 0, 0)

  const days = Array.from({ length: 7 }, (_, i) => {
    const d = new Date(today)
    d.setDate(d.getDate() - 6 + i)
    return d
  })

  const DAY_LABELS = ['日', '月', '火', '水', '木', '金', '土']
  const isToday = (d: Date) => d.toDateString() === today.toDateString()

  const shiftsForDay = (day: Date): Shift[] => {
    const dayStart = day.getTime()
    const dayEnd   = dayStart + 86_400_000
    return allShifts.filter(s => {
      const start = new Date(s.started_at).getTime()
      const end   = s.ended_at ? new Date(s.ended_at).getTime() : Date.now()
      return start < dayEnd && end > dayStart
    })
  }

  const statusBadge = (s: Shift) => {
    if (s.status === 'active') return 'bg-green-900/40 border-green-700/60 text-green-300'
    return 'bg-[#131d30] border-[#1e2d42] text-[#7d92b0]'
  }

  const summary = {
    totalShifts:    allShifts.length,
    avgResolved:    allShifts.length > 0
      ? Math.round(allShifts.reduce((s, sh) => s + sh.metrics.alerts_resolved, 0) / allShifts.length)
      : 0,
    activeAnalysts: [...new Set(allShifts.flatMap(s => [s.lead_id, ...s.team.map(m => m.id)]))].length,
  }

  return (
    <div className="space-y-6">
      {/* Summary row */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: '過去7日シフト数', value: allShifts.length, color: 'text-blue-400' },
          { label: '平均アラート解決数', value: summary.avgResolved, color: 'text-green-400' },
          { label: '参加アナリスト', value: summary.activeAnalysts, color: 'text-purple-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 text-center">
            <p className={`text-3xl font-bold ${color}`}>{value}</p>
            <p className="text-xs text-[#7d92b0] mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* Weekly grid */}
      <div className="grid grid-cols-7 gap-2">
        {days.map((day, di) => {
          const shifts = shiftsForDay(day)
          const isCurrentDay = isToday(day)
          return (
            <div
              key={di}
              className={`rounded-lg border p-2 min-h-[160px] ${
                isCurrentDay
                  ? 'border-[#e8002d]/50 bg-[#0d1220]'
                  : 'border-[#1e2d42] bg-[#070d19]'
              }`}
            >
              {/* Day header */}
              <div className="mb-2 text-center">
                <p className={`text-[10px] font-medium ${isCurrentDay ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`}>
                  {DAY_LABELS[day.getDay()]}
                </p>
                <p className={`text-lg font-bold leading-none ${isCurrentDay ? 'text-white' : 'text-[#7d92b0]'}`}>
                  {day.getDate()}
                </p>
                {isCurrentDay && (
                  <span className="text-[9px] text-[#e8002d] font-medium">今日</span>
                )}
              </div>

              {/* Shifts */}
              <div className="space-y-1">
                {shifts.length === 0 ? (
                  <p className="text-[9px] text-[#3d5068] text-center pt-4">—</p>
                ) : (
                  shifts.map(shift => (
                    <div
                      key={shift.id}
                      className={`rounded-sm border px-1.5 py-1 ${statusBadge(shift)}`}
                    >
                      <p className="text-[9px] font-semibold truncate">{shift.name.replace(/\s+\d{4}-\d{2}-\d{2}/, '')}</p>
                      <p className="text-[8px] opacity-70 truncate mt-0.5">{shift.lead_name}</p>
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-[8px] opacity-60">
                          {new Date(shift.started_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })}
                        </span>
                        {shift.status === 'active' && (
                          <span className="text-[8px] bg-green-500/20 text-green-400 px-1 rounded-sm">稼働</span>
                        )}
                      </div>
                      <div className="flex items-center gap-0.5 mt-1">
                        <Users className="w-2.5 h-2.5 opacity-50" />
                        <span className="text-[8px] opacity-60">{shift.team.length + 1}名</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-[#7d92b0]">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm border bg-green-900/40 border-green-700/60" />
          <span>稼働中</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm border bg-[#131d30] border-[#1e2d42]" />
          <span>完了</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-sm border border-[#e8002d]/50 bg-[#0d1220]" />
          <span>本日</span>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ShiftsPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'current' | 'history' | 'calendar'>('current')
  const [showStartModal, setShowStartModal] = useState(false)
  const [showEndModal, setShowEndModal] = useState(false)
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const notesRef = useRef<HTMLTextAreaElement>(null)

  // ── API queries ───────────────────────────────────────────────

  const { data: currentShift, isLoading: loadingCurrent } = useQuery<Shift | null>({
    queryKey: ['soc-shift-current'],
    queryFn: () => apiFetch('/api/v1/soc/shifts/current'),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const { data: shiftStats } = useQuery<ShiftStats>({
    queryKey: ['soc-shift-stats', currentShift?.id],
    queryFn: async () => {
      if (!currentShift) return { open_alerts: 0, open_incidents: 0, tickets_created: 0, alerts_resolved: 0 } satisfies ShiftStats
      return await apiFetch(`/api/v1/soc/shifts/${currentShift.id}/stats`)
    },
    enabled: !!currentShift,
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const { data: historyShifts } = useQuery<Shift[]>({
    queryKey: ['soc-shifts-history'],
    queryFn: () => apiFetchList<Shift>('/api/v1/soc/shifts'),
    staleTime: 30_000,
  })

  // Local state derived from currentShift
  const [localShift, setLocalShift] = useState<Shift | null>(null)
  const [notesSaving, setNotesSaving] = useState(false)
  const { persist, saveError } = usePersist()
  const [notesSaved, setNotesSaved] = useState(false)

  // ── Mutations ─────────────────────────────────────────────────

  const startMutation = useMutation({
    mutationFn: (data: { name: string; lead_id: string; team_ids: string[] }) =>
      apiFetch('/api/v1/soc/shifts/start', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: (newShift) => {
      setLocalShift(newShift as Shift)
      setShowStartModal(false)
      qc.invalidateQueries({ queryKey: ['soc-shift-current'] })
    },
  })

  const endMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/soc/shifts/${id}/end`, { method: 'POST' }),
    onSuccess: () => {
      setLocalShift(null)
      setShowEndModal(false)
      qc.invalidateQueries({ queryKey: ['soc-shift-current'] })
      qc.invalidateQueries({ queryKey: ['soc-shifts-history'] })
    },
  })

  const saveNotes = useCallback(async () => {
    if (!localShift) return
    setNotesSaving(true)
    try {
      // 引き継ぎメモです。.catch(() => {}) の直後に「保存しました」の印を
      // 出していたので、保存できていないメモを書いた人は保存できたと思い、
      // 次のシフトの担当者は空のメモを受け取ります。交代時に伝わらなかった
      // ことは、伝わらなかったと分かるまで誰も気づきません。
      if (await persist('引き継ぎメモ', `/api/v1/soc/shifts/${localShift.id}/notes`, {
        method: 'PUT',
        body: JSON.stringify({ notes: localShift.handover_notes }),
      })) {
        setNotesSaved(true)
        setTimeout(() => setNotesSaved(false), 2000)
      }
    } finally {
      setNotesSaving(false)
    }
  }, [localShift])

  const addTask = () => {
    if (!localShift) return
    const newTask: HandoverTask = {
      id: `tk-${Date.now()}`,
      description: '',
      assignee_id: '',
      assignee_name: '',
      priority: 'medium',
      completed: false,
    }
    setLocalShift(s => s ? { ...s, tasks: [...s.tasks, newTask] } : s)
  }

  const updateTask = (id: string, updates: Partial<HandoverTask>) => {
    setLocalShift(s => s ? { ...s, tasks: s.tasks.map(t => t.id === id ? { ...t, ...updates } : t) } : s)
  }

  const removeTask = (id: string) => {
    setLocalShift(s => s ? { ...s, tasks: s.tasks.filter(t => t.id !== id) } : s)
  }

  // Filtered history
  const filteredHistory = (historyShifts ?? []).filter(s => {
    const d = new Date(s.started_at)
    if (dateFrom && d < new Date(dateFrom)) return false
    if (dateTo && d > new Date(dateTo + 'T23:59:59')) return false
    return true
  })

  const activeShift = localShift

  return (
    <div className="flex-1 overflow-auto bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed />
      <SaveFailed error={saveError} />
      {/* ── Modals ─────────────────────────────────────────────── */}
      {showStartModal && (
        <StartShiftModal
          onClose={() => setShowStartModal(false)}
          onStart={(data) => startMutation.mutate(data)}
        />
      )}
      {showEndModal && activeShift && (
        <EndShiftModal
          shift={activeShift}
          onClose={() => setShowEndModal(false)}
          onEnd={() => endMutation.mutate(activeShift.id)}
        />
      )}

      {/* ── Header ─────────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold text-white">シフト引継ぎ</h1>
        <p className="text-sm text-[#7d92b0] mt-1">SOCシフトの開始・終了・引継ぎ事項の管理</p>
      </div>

      {/* ── Active Shift Banner ─────────────────────────────────── */}
      {activeShift ? (
        <div className="bg-green-900/20 border border-green-700/40 rounded-lg p-4 flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2 text-green-400">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="font-semibold text-sm">シフト稼働中</span>
          </div>
          <div className="flex-1 min-w-0">
            <span className="text-white font-medium">{activeShift.name}</span>
            <span className="text-[#7d92b0] text-sm ml-3">リード: {activeShift.lead_name}</span>
            <span className="text-[#7d92b0] text-sm ml-3 shrink-0">
              <Clock className="w-3.5 h-3.5 inline mr-1" />
              {formatElapsed(activeShift.started_at)} 経過
            </span>
          </div>
          <div className="flex items-center gap-2">
            {[activeShift.lead_name, ...activeShift.team.map(m => m.name)].map(name => (
              <Avatar key={name} name={name} size="sm" />
            ))}
            <span className="text-xs text-[#7d92b0] ml-1">({activeShift.team.length + 1}名)</span>
          </div>
          <button
            onClick={() => setShowEndModal(true)}
            className="px-4 py-2 rounded-sm bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors flex items-center gap-2"
          >
            <StopCircle className="w-4 h-4" />
            シフト終了
          </button>
        </div>
      ) : (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-8 text-center">
          <div className="w-16 h-16 rounded-full bg-[#070d19] border border-[#1e2d42] flex items-center justify-center mx-auto mb-4">
            <Play className="w-8 h-8 text-[#3d5068]" />
          </div>
          <p className="text-white font-semibold mb-1">現在アクティブなシフトはありません</p>
          <p className="text-sm text-[#7d92b0] mb-4">新しいシフトを開始してSOC運用を記録してください</p>
          <button
            onClick={() => setShowStartModal(true)}
            className="px-6 py-2.5 rounded-sm bg-green-700 hover:bg-green-600 text-white text-sm font-medium transition-colors flex items-center gap-2 mx-auto"
          >
            <Play className="w-4 h-4" />
            シフト開始
          </button>
        </div>
      )}

      {/* ── Tabs ───────────────────────────────────────────────── */}
      <div className="flex gap-0 border-b border-[#1e2d42]">
        {([
          { key: 'current',  label: '現在のシフト' },
          { key: 'history',  label: 'シフト履歴' },
          { key: 'calendar', label: 'カレンダー' },
        ] as const).map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-5 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === key
                ? 'border-[#e8002d] text-white'
                : 'border-transparent text-[#7d92b0] hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Current Shift Tab ───────────────────────────────────── */}
      {tab === 'current' && (
        <div className="space-y-6">
          {!activeShift ? (
            <div className="text-center py-12">
              <p className="text-[#7d92b0]">アクティブなシフトはありません。「シフト開始」ボタンから新しいシフトを開始してください。</p>
            </div>
          ) : (
            <>
              {/* Shift summary card */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h2 className="text-lg font-semibold text-white">{activeShift.name}</h2>
                    <p className="text-sm text-[#7d92b0] mt-0.5">
                      <Calendar className="w-3.5 h-3.5 inline mr-1" />
                      開始: {formatDateTime(activeShift.started_at)} — 経過: {formatElapsed(activeShift.started_at)}
                    </p>
                  </div>
                  <button
                    onClick={() => setShowStartModal(false)}
                    className="text-xs text-[#7d92b0] flex items-center gap-1 hover:text-white transition-colors"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    リフレッシュ
                  </button>
                </div>

                <div className="flex flex-wrap gap-4">
                  <div>
                    <p className="text-xs text-[#7d92b0] mb-1.5">リードアナリスト</p>
                    <div className="flex items-center gap-2">
                      <Avatar name={activeShift.lead_name} size="md" />
                      <div>
                        <p className="text-sm text-white font-medium">{activeShift.lead_name}</p>
                        <p className="text-xs text-[#7d92b0]">Lead</p>
                      </div>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-[#7d92b0] mb-1.5">チームメンバー</p>
                    <div className="flex items-center gap-2 flex-wrap">
                      {activeShift.team.map(m => (
                        <div key={m.id} className="flex items-center gap-1.5">
                          <Avatar name={m.name} size="sm" />
                          <span className="text-xs text-white">{m.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Live metrics */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium text-white flex items-center gap-2">
                    <BarChart2 className="w-4 h-4 text-[#e8002d]" />
                    ライブメトリクス
                  </h3>
                  <span className="text-xs text-[#3d5068]">60秒ごとに自動更新</span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: 'オープンアラート', value: shiftStats?.open_alerts ?? activeShift.metrics.open_alerts, color: 'text-[#e8002d]' },
                    { label: 'オープンインシデント', value: shiftStats?.open_incidents ?? activeShift.metrics.open_incidents, color: 'text-orange-400' },
                    { label: '今日作成チケット', value: shiftStats?.tickets_created ?? activeShift.metrics.tickets_created, color: 'text-blue-400' },
                    { label: '解決済みアラート', value: shiftStats?.alerts_resolved ?? activeShift.metrics.alerts_resolved, color: 'text-green-400' },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 text-center">
                      <p className={`text-3xl font-bold ${color}`}>{value}</p>
                      <p className="text-xs text-[#7d92b0] mt-1">{label}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Handover notes */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium text-white flex items-center gap-2">
                    <FileText className="w-4 h-4 text-[#e8002d]" />
                    引継ぎメモ
                  </h3>
                  <span className={`text-xs transition-opacity duration-300 ${notesSaved ? 'text-green-400 opacity-100' : 'text-[#3d5068] opacity-60'}`}>
                    {notesSaving ? '保存中...' : notesSaved ? '保存済み' : 'フォーカスを外すと自動保存'}
                  </span>
                </div>
                <textarea
                  ref={notesRef}
                  value={activeShift.handover_notes}
                  onChange={e => setLocalShift(s => s ? { ...s, handover_notes: e.target.value } : s)}
                  onBlur={saveNotes}
                  rows={6}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2.5 text-sm text-white resize-y focus:outline-hidden focus:border-[#3d5068] focus:ring-1 focus:ring-[#3d5068] placeholder-[#3d5068]"
                  placeholder="引継ぎ事項を入力してください..."
                />
              </div>

              {/* Pending tasks */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-medium text-white flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-[#e8002d]" />
                    引継ぎタスク ({activeShift.tasks.length}件)
                  </h3>
                  <button
                    onClick={addTask}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#070d19] border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-white hover:border-[#3d5068] transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    タスク追加
                  </button>
                </div>

                {activeShift.tasks.length === 0 ? (
                  <p className="text-sm text-[#3d5068] italic text-center py-4">タスクはありません</p>
                ) : (
                  <div className="space-y-2">
                    {activeShift.tasks.map(task => (
                      <div key={task.id} className="flex items-center gap-3 p-3 rounded-sm bg-[#070d19] border border-[#1e2d42]">
                        <input
                          type="checkbox"
                          checked={task.completed}
                          onChange={e => updateTask(task.id, { completed: e.target.checked })}
                          className="accent-[#e8002d] w-4 h-4 shrink-0"
                        />
                        <input
                          value={task.description}
                          onChange={e => updateTask(task.id, { description: e.target.value })}
                          className={`flex-1 bg-transparent text-sm focus:outline-hidden ${task.completed ? 'line-through text-[#3d5068]' : 'text-white'}`}
                          placeholder="タスクの説明..."
                        />
                        <select
                          value={task.assignee_id}
                          onChange={e => {
                            const u = ([] as TeamMember[]).find(u => u.id === e.target.value)
                            if (u) updateTask(task.id, { assignee_id: u.id, assignee_name: u.name })
                          }}
                          className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-[#7d92b0] focus:outline-hidden"
                        >
                          {([] as TeamMember[]).map(u => <option key={u.id} value={u.id}>{u.name}</option>)}
                        </select>
                        <select
                          value={task.priority}
                          onChange={e => updateTask(task.id, { priority: e.target.value as TaskPriority })}
                          className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-[#7d92b0] focus:outline-hidden"
                        >
                          <option value="critical">クリティカル</option>
                          <option value="high">高</option>
                          <option value="medium">中</option>
                          <option value="low">低</option>
                        </select>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${PRIORITY_STYLES[task.priority]}`}>
                          {PRIORITY_LABELS[task.priority]}
                        </span>
                        <button
                          onClick={() => removeTask(task.id)}
                          className="text-[#3d5068] hover:text-[#e8002d] transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* End shift button */}
              <div className="flex justify-end">
                <button
                  onClick={() => setShowEndModal(true)}
                  className="px-6 py-2.5 rounded-sm bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium text-sm transition-colors flex items-center gap-2"
                >
                  <StopCircle className="w-4 h-4" />
                  シフト終了
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── History Tab ─────────────────────────────────────────── */}
      {tab === 'history' && (
        <div className="space-y-4">
          {/* Date range filter */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-sm text-[#7d92b0]">期間:</span>
            <input
              type="date"
              value={dateFrom}
              onChange={e => setDateFrom(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#3d5068]"
            />
            <span className="text-[#3d5068]">—</span>
            <input
              type="date"
              value={dateTo}
              onChange={e => setDateTo(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#3d5068]"
            />
            {(dateFrom || dateTo) && (
              <button onClick={() => { setDateFrom(''); setDateTo('') }} className="text-xs text-[#7d92b0] hover:text-white transition-colors">
                クリア
              </button>
            )}
          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                    {['シフト名', '日時', 'リード', 'チーム', '勤務時間', 'アラート解決', 'インシデント', '引継ぎメモ', 'ステータス', ''].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredHistory.length === 0 ? (
                    <tr>
                      <td colSpan={10} className="px-4 py-8 text-center text-[#7d92b0] text-sm">
                        該当するシフトはありません
                      </td>
                    </tr>
                  ) : (
                    filteredHistory.map(shift => <HistoryRow key={shift.id} shift={shift} />)
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Calendar Tab ──────────────────────────────────────── */}
      {tab === 'calendar' && (
        <ShiftCalendar allShifts={[...(activeShift ? [activeShift] : []), ...(historyShifts ?? [])]} />
      )}
    </div>
  )
}
