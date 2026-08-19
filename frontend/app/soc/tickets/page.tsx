'use client'

import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  Ticket, Plus, X, ChevronRight, Clock, User, AlertTriangle,
  CheckCircle, Circle, Loader2, RefreshCw, Filter, MessageSquare,
  ExternalLink, GripVertical, Tag, Calendar, Send
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type TicketStatus = 'open' | 'in_progress' | 'pending' | 'resolved'
type TicketPriority = 'critical' | 'high' | 'medium' | 'low'

interface SocTicket {
  id: string
  ticket_number: string
  title: string
  description: string
  status: TicketStatus
  priority: TicketPriority
  assignee_id: string | null
  assignee_name: string | null
  alert_id: string | null
  tags: string[]
  sla_due_at: string | null
  created_at: string
  updated_at: string
  comment_count: number
}

interface TicketComment {
  id: string
  ticket_id: string
  author_name: string
  body: string
  created_at: string
}

interface TicketStats {
  open: number
  in_progress: number
  sla_breach: number
  resolved_today: number
}

interface UserOption {
  id: string
  full_name: string
  email: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_USERS: UserOption[] = [
  { id: 'u1', full_name: '田中 太郎', email: 'tanaka@example.com' },
  { id: 'u2', full_name: '鈴木 花子', email: 'suzuki@example.com' },
  { id: 'u3', full_name: '佐藤 健一', email: 'sato@example.com' },
  { id: 'u4', full_name: '山田 美智子', email: 'yamada@example.com' },
]

const now = new Date()
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3600000).toISOString()
const hoursFromNow = (h: number) => new Date(now.getTime() + h * 3600000).toISOString()

const MOCK_TICKETS: SocTicket[] = [
  {
    id: 't1', ticket_number: 'TKT-0001',
    title: 'ランサムウェア疑いのプロセス検出 - DESKTOP-PROD01',
    description: '複数のエンドポイントでランサムウェアに関連するプロセスが検出されました。即時調査が必要です。',
    status: 'open', priority: 'critical',
    assignee_id: 'u1', assignee_name: '田中 太郎',
    alert_id: 'ALT-20260318-001', tags: ['ransomware', 'critical'],
    sla_due_at: hoursFromNow(2), created_at: hoursAgo(3), updated_at: hoursAgo(1), comment_count: 4,
  },
  {
    id: 't2', ticket_number: 'TKT-0002',
    title: '不審な外部接続の調査 - 複数エンドポイント',
    description: '内部ネットワークから不明な外部IPへの大量のデータ送信が確認されました。',
    status: 'in_progress', priority: 'high',
    assignee_id: 'u2', assignee_name: '鈴木 花子',
    alert_id: 'ALT-20260318-002', tags: ['exfiltration', 'network'],
    sla_due_at: hoursFromNow(6), created_at: hoursAgo(8), updated_at: hoursAgo(2), comment_count: 7,
  },
  {
    id: 't3', ticket_number: 'TKT-0003',
    title: 'PowerShell スクリプト悪用の調査',
    description: 'エンコードされたPowerShellコマンドが実行されています。マルウェアのダウンロードが疑われます。',
    status: 'in_progress', priority: 'high',
    assignee_id: 'u3', assignee_name: '佐藤 健一',
    alert_id: 'ALT-20260317-015', tags: ['powershell', 'living-off-land'],
    sla_due_at: hoursFromNow(12), created_at: hoursAgo(24), updated_at: hoursAgo(5), comment_count: 3,
  },
  {
    id: 't4', ticket_number: 'TKT-0004',
    title: '管理者アカウントへの不正アクセス試行',
    description: 'ブルートフォース攻撃によってドメイン管理者アカウントへのログイン試行が多数検出されました。',
    status: 'open', priority: 'critical',
    assignee_id: null, assignee_name: null,
    alert_id: 'ALT-20260318-003', tags: ['brute-force', 'identity'],
    sla_due_at: hoursFromNow(-1), created_at: hoursAgo(5), updated_at: hoursAgo(5), comment_count: 0,
  },
  {
    id: 't5', ticket_number: 'TKT-0005',
    title: 'フィッシングメール対応 - 財務部門',
    description: '財務部門の複数ユーザーがフィッシングメールを開封した可能性があります。',
    status: 'pending', priority: 'medium',
    assignee_id: 'u4', assignee_name: '山田 美智子',
    alert_id: null, tags: ['phishing', 'email'],
    sla_due_at: hoursFromNow(24), created_at: hoursAgo(12), updated_at: hoursAgo(6), comment_count: 2,
  },
  {
    id: 't6', ticket_number: 'TKT-0006',
    title: 'USB デバイス不正利用の調査',
    description: '許可されていないUSBデバイスがHR部門のエンドポイントに接続されました。',
    status: 'pending', priority: 'medium',
    assignee_id: 'u1', assignee_name: '田中 太郎',
    alert_id: null, tags: ['usb', 'device'],
    sla_due_at: hoursFromNow(48), created_at: hoursAgo(16), updated_at: hoursAgo(10), comment_count: 1,
  },
  {
    id: 't7', ticket_number: 'TKT-0007',
    title: '脆弱性スキャン結果の対応 - CVE-2026-1234',
    description: '先月実施した脆弱性スキャンで発見された重大な脆弱性の対応状況を確認します。',
    status: 'resolved', priority: 'low',
    assignee_id: 'u2', assignee_name: '鈴木 花子',
    alert_id: null, tags: ['vulnerability', 'patching'],
    sla_due_at: null, created_at: hoursAgo(48), updated_at: hoursAgo(2), comment_count: 9,
  },
  {
    id: 't8', ticket_number: 'TKT-0008',
    title: '定期セキュリティ監査レポートの作成',
    description: '四半期ごとの定期セキュリティ監査レポートを作成します。コンプライアンス要件に従って記録します。',
    status: 'resolved', priority: 'low',
    assignee_id: 'u3', assignee_name: '佐藤 健一',
    alert_id: null, tags: ['audit', 'compliance'],
    sla_due_at: null, created_at: hoursAgo(72), updated_at: hoursAgo(4), comment_count: 5,
  },
]

const MOCK_COMMENTS: TicketComment[] = [
  { id: 'c1', ticket_id: 't1', author_name: '田中 太郎', body: '初期調査を開始しました。対象プロセスを隔離中です。', created_at: hoursAgo(2) },
  { id: 'c2', ticket_id: 't1', author_name: '鈴木 花子', body: '同様のパターンがSIEMでも検出されています。TKT-0002と関連している可能性があります。', created_at: hoursAgo(1) },
  { id: 'c3', ticket_id: 't2', author_name: '鈴木 花子', body: '外部IPのWhois調査を実施しました。Torエグジットノードと一致しています。', created_at: hoursAgo(3) },
]

const MOCK_STATS: TicketStats = {
  open: 2, in_progress: 2, sla_breach: 1, resolved_today: 2,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function priorityBadge(p: TicketPriority) {
  const map = {
    critical: 'bg-red-900/60 text-red-300 border border-red-700/50',
    high: 'bg-orange-900/60 text-orange-300 border border-orange-700/50',
    medium: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50',
    low: 'bg-green-900/60 text-green-300 border border-green-700/50',
  }
  const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }
  return <span className={`text-[11px] px-2 py-0.5 rounded-sm font-medium ${map[p]}`}>{labels[p]}</span>
}

function statusBadge(s: TicketStatus) {
  const map = {
    open: 'bg-blue-900/60 text-blue-300 border border-blue-700/50',
    in_progress: 'bg-purple-900/60 text-purple-300 border border-purple-700/50',
    pending: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50',
    resolved: 'bg-green-900/60 text-green-300 border border-green-700/50',
  }
  const labels = { open: 'Open', in_progress: 'In Progress', pending: 'Pending', resolved: 'Resolved' }
  return <span className={`text-[11px] px-2 py-0.5 rounded-sm font-medium ${map[s]}`}>{labels[s]}</span>
}

function slaIndicator(sla: string | null) {
  if (!sla) return <span className="text-[#7d92b0] text-xs">-</span>
  const due = new Date(sla)
  const diff = due.getTime() - Date.now()
  const hours = diff / 3600000
  if (diff < 0) return <span className="text-red-400 text-xs font-medium flex items-center gap-1"><AlertTriangle className="w-3 h-3" />超過</span>
  if (hours < 4) return <span className="text-yellow-400 text-xs font-medium">{Math.round(hours)}h</span>
  return <span className="text-green-400 text-xs">{Math.round(hours)}h</span>
}

function priorityBarColor(p: TicketPriority) {
  return { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500' }[p]
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function assigneeInitial(name: string | null) {
  if (!name) return '?'
  return name.trim().split(' ').map(p => p[0]).join('').slice(0, 2).toUpperCase()
}

// ─── Components ───────────────────────────────────────────────────────────────

function StatCard({ label, value, color = 'text-white' }: { label: string; value: number; color?: string }) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3">
      <p className="text-[#7d92b0] text-xs mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )
}

// ─── Create Ticket Modal ───────────────────────────────────────────────────────

interface CreateModalProps {
  users: UserOption[]
  onClose: () => void
  onCreate: (data: Partial<SocTicket>) => void
  loading: boolean
}

function CreateTicketModal({ users, onClose, onCreate, loading }: CreateModalProps) {
  const [form, setForm] = useState({
    title: '', description: '', priority: 'medium' as TicketPriority,
    assignee_id: '', tags: '', link_alert_id: '',
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onCreate({
      title: form.title,
      description: form.description,
      priority: form.priority,
      assignee_id: form.assignee_id || null,
      tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
      alert_id: form.link_alert_id || null,
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-[540px] max-h-[90vh] overflow-y-auto shadow-xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold flex items-center gap-2">
            <Ticket className="w-4 h-4 text-[#e8002d]" />
            チケット作成
          </h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">タイトル *</label>
            <input
              required value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
              placeholder="チケットのタイトルを入力"
            />
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">説明</label>
            <textarea
              rows={3} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50 resize-none"
              placeholder="詳細な説明を入力"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">優先度</label>
              <select
                value={form.priority} onChange={e => setForm(f => ({ ...f, priority: e.target.value as TicketPriority }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">担当者</label>
              <select
                value={form.assignee_id} onChange={e => setForm(f => ({ ...f, assignee_id: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden"
              >
                <option value="">未割り当て</option>
                {users.map(u => <option key={u.id} value={u.id}>{u.full_name}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">タグ（カンマ区切り）</label>
            <input
              value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
              placeholder="ransomware, network, identity"
            />
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">アラートID（任意）</label>
            <input
              value={form.link_alert_id} onChange={e => setForm(f => ({ ...f, link_alert_id: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
              placeholder="ALT-20260318-001"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 rounded-sm text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/40 transition-colors">
              キャンセル
            </button>
            <button type="submit" disabled={loading} className="px-4 py-2 rounded-sm text-sm bg-[#e8002d] hover:bg-[#c0001f] text-white font-medium transition-colors disabled:opacity-50 flex items-center gap-2">
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              作成
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Side Panel ───────────────────────────────────────────────────────────────

function TicketSidePanel({ ticket, comments, onClose, onAddComment, addingComment, canWrite = true }: {
  ticket: SocTicket
  comments: TicketComment[]
  onClose: () => void
  onAddComment: (body: string) => void
  addingComment: boolean
  canWrite?: boolean
}) {
  const [comment, setComment] = useState('')

  function handleSend() {
    if (!comment.trim()) return
    onAddComment(comment)
    setComment('')
  }

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-[480px] bg-[#0d1220] border-l border-[#1e2d42] shadow-2xl flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
        <div>
          <span className="font-mono text-[#e8002d] text-sm">{ticket.ticket_number}</span>
          <h3 className="text-white font-semibold text-sm mt-0.5">{ticket.title}</h3>
        </div>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
      </div>
      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
        <div className="flex flex-wrap gap-2">
          {priorityBadge(ticket.priority)}
          {statusBadge(ticket.status)}
          {ticket.tags.map(t => (
            <span key={t} className="text-[11px] px-2 py-0.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] flex items-center gap-1">
              <Tag className="w-2.5 h-2.5" />{t}
            </span>
          ))}
        </div>
        <div className="bg-[#070d19] rounded-lg p-4 text-sm text-[#7d92b0] leading-relaxed">
          {ticket.description}
        </div>
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="bg-[#070d19] rounded-sm p-3">
            <p className="text-[#7d92b0] mb-1">担当者</p>
            <p className="text-white font-medium">{ticket.assignee_name || '未割り当て'}</p>
          </div>
          <div className="bg-[#070d19] rounded-sm p-3">
            <p className="text-[#7d92b0] mb-1">SLA期限</p>
            <div className="font-medium">{slaIndicator(ticket.sla_due_at)}</div>
          </div>
          <div className="bg-[#070d19] rounded-sm p-3">
            <p className="text-[#7d92b0] mb-1">作成日時</p>
            <p className="text-white">{fmtDate(ticket.created_at)}</p>
          </div>
          {ticket.alert_id && (
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] mb-1">アラート</p>
              <a href={`/alerts?id=${ticket.alert_id}`} className="text-[#1a6bff] hover:underline flex items-center gap-1">
                {ticket.alert_id}<ExternalLink className="w-3 h-3" />
              </a>
            </div>
          )}
        </div>

        <div>
          <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-3 flex items-center gap-2">
            <MessageSquare className="w-3.5 h-3.5" />コメント ({comments.length})
          </h4>
          <div className="space-y-3">
            {comments.map(c => (
              <div key={c.id} className="bg-[#070d19] rounded-lg p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-white text-xs font-medium">{c.author_name}</span>
                  <span className="text-[#7d92b0] text-[11px]">{fmtDate(c.created_at)}</span>
                </div>
                <p className="text-[#7d92b0] text-xs leading-relaxed">{c.body}</p>
              </div>
            ))}
            {comments.length === 0 && <p className="text-[#7d92b0] text-xs text-center py-4">コメントなし</p>}
          </div>
        </div>
      </div>

      {canWrite && (
        <div className="border-t border-[#1e2d42] px-6 py-4">
          <div className="flex gap-2">
            <input
              value={comment} onChange={e => setComment(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && (e.preventDefault(), handleSend())}
              className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
              placeholder="コメントを追加..."
            />
            <button
              onClick={handleSend} disabled={addingComment || !comment.trim()}
              className="px-3 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-sm transition-colors disabled:opacity-50 flex items-center"
            >
              {addingComment ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Kanban Card ──────────────────────────────────────────────────────────────

function KanbanCard({ ticket, onClick }: { ticket: SocTicket; onClick: () => void }) {
  const sla = ticket.sla_due_at ? new Date(ticket.sla_due_at) : null
  const slaHours = sla ? (sla.getTime() - Date.now()) / 3600000 : null
  const slaSoon = slaHours !== null && slaHours < 8 && slaHours > 0
  const slaBreached = slaHours !== null && slaHours <= 0

  return (
    <div
      onClick={onClick}
      className="bg-[#070d19] border border-[#1e2d42] rounded-lg overflow-hidden cursor-pointer hover:border-[#7d92b0]/40 transition-all group"
    >
      <div className={`h-1 ${priorityBarColor(ticket.priority)}`} />
      <div className="p-3">
        <div className="flex items-start justify-between gap-2 mb-2">
          <span className="font-mono text-[10px] text-[#7d92b0]">{ticket.ticket_number}</span>
          {ticket.assignee_name && (
            <div className="w-5 h-5 rounded-full bg-[#1a6bff]/20 flex items-center justify-center shrink-0">
              <span className="text-[8px] text-[#1a6bff] font-bold">{assigneeInitial(ticket.assignee_name)}</span>
            </div>
          )}
        </div>
        <p className="text-white text-xs font-medium leading-snug line-clamp-2 mb-2">{ticket.title}</p>
        <div className="flex items-center justify-between">
          {priorityBadge(ticket.priority)}
          {(slaSoon || slaBreached) && (
            <span className={`text-[10px] flex items-center gap-0.5 font-medium ${slaBreached ? 'text-red-400' : 'text-yellow-400'}`}>
              <Clock className="w-2.5 h-2.5" />
              {slaBreached ? '超過' : `${Math.round(slaHours!)}h`}
            </span>
          )}
        </div>
        {ticket.comment_count > 0 && (
          <div className="mt-2 flex items-center gap-1 text-[#7d92b0] text-[10px]">
            <MessageSquare className="w-2.5 h-2.5" />{ticket.comment_count}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SocTicketsPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()
  const [view, setView] = useState<'list' | 'kanban'>('list')
  const [showCreate, setShowCreate] = useState(false)
  const [selectedTicket, setSelectedTicket] = useState<SocTicket | null>(null)
  const [filterStatus, setFilterStatus] = useState('')
  const [filterPriority, setFilterPriority] = useState('')
  const [filterAssignee, setFilterAssignee] = useState('')
  const [dragOverCol, setDragOverCol] = useState<TicketStatus | null>(null)
  const dragRef = useRef<string | null>(null)

  const { data: stats } = useQuery<TicketStats | null>({
    queryKey: ['soc-ticket-stats'],
    queryFn: () => apiFetch<TicketStats>('/api/v1/soc/tickets/stats'),
    staleTime: 30000,
    retry: false,
  })

  const { data: tickets = [], isLoading } = useQuery<SocTicket[]>({
    queryKey: ['soc-tickets'],
    queryFn: () => apiFetchList<SocTicket>('/api/v1/soc/tickets'),
    staleTime: 30000,
    retry: false,
  })

  const { data: users = [] } = useQuery<UserOption[]>({
    queryKey: ['soc-users'],
    queryFn: () => apiFetchList<UserOption>('/api/v1/users'),
    staleTime: 60000,
    retry: false,
  })

  const { data: comments = [] } = useQuery<TicketComment[]>({
    queryKey: ['ticket-comments', selectedTicket?.id],
    queryFn: () => apiFetchList<TicketComment>(`/api/v1/soc/tickets/${selectedTicket?.id}/comments`),
    enabled: !!selectedTicket,
    staleTime: 10000,
    retry: false,
    initialData: [],
  })

  const createMutation = useMutation({
    mutationFn: (data: Partial<SocTicket>) => apiFetch('/api/v1/soc/tickets', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['soc-tickets'] }); setShowCreate(false) },
    onError: () => setShowCreate(false),
  })

  const closeMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/soc/tickets/${id}/close`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soc-tickets'] }),
    onError: () => {},
  })

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: TicketStatus }) =>
      apiFetch(`/api/v1/soc/tickets/${id}`, { method: 'PUT', body: JSON.stringify({ status }) }),
    onMutate: async ({ id, status }) => {
      await qc.cancelQueries({ queryKey: ['soc-tickets'] })
      const prev = qc.getQueryData<SocTicket[]>(['soc-tickets'])
      qc.setQueryData<SocTicket[]>(['soc-tickets'], old => old?.map(t => t.id === id ? { ...t, status } : t))
      return { prev }
    },
    onError: (_e, _v, ctx) => { if (ctx?.prev) qc.setQueryData(['soc-tickets'], ctx.prev) },
    onSettled: () => qc.invalidateQueries({ queryKey: ['soc-tickets'] }),
  })

  const commentMutation = useMutation({
    mutationFn: ({ ticketId, body }: { ticketId: string; body: string }) =>
      apiFetch(`/api/v1/soc/tickets/${ticketId}/comments`, { method: 'POST', body: JSON.stringify({ body }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ticket-comments', selectedTicket?.id] }),
    onError: () => {},
  })

  const displayTickets: SocTicket[] = tickets ?? []
  const displayStats: TicketStats = stats ?? { open: 0, in_progress: 0, sla_breach: 0, resolved_today: 0 }
  const displayUsers: UserOption[] = users ?? []

  const filtered = displayTickets.filter(t => {
    if (filterStatus && t.status !== filterStatus) return false
    if (filterPriority && t.priority !== filterPriority) return false
    if (filterAssignee && t.assignee_id !== filterAssignee) return false
    return true
  })

  const kanbanCols: { key: TicketStatus; label: string }[] = [
    { key: 'open', label: 'Open' },
    { key: 'in_progress', label: 'In Progress' },
    { key: 'pending', label: 'Pending' },
    { key: 'resolved', label: 'Resolved' },
  ]

  function handleDrop(status: TicketStatus) {
    if (dragRef.current) {
      statusMutation.mutate({ id: dragRef.current, status })
      dragRef.current = null
    }
    setDragOverCol(null)
  }

  const ticketComments = (comments ?? [])

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-white text-2xl font-bold flex items-center gap-2">
            <Ticket className="w-6 h-6 text-[#e8002d]" />
            SOCチケット
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">セキュリティインシデントとアラートのチケット管理</p>
        </div>
        {canWrite && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            チケット作成
          </button>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Open" value={displayStats.open} color="text-blue-400" />
        <StatCard label="In Progress" value={displayStats.in_progress} color="text-purple-400" />
        <StatCard label="SLA超過" value={displayStats.sla_breach} color="text-red-400" />
        <StatCard label="本日解決" value={displayStats.resolved_today} color="text-green-400" />
      </div>

      {/* View toggle */}
      <div className="flex items-center gap-2 mb-4">
        <div className="flex bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 gap-1">
          <button
            onClick={() => setView('list')}
            className={`px-4 py-1.5 rounded-sm text-sm font-medium transition-colors ${view === 'list' ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
          >
            リスト
          </button>
          <button
            onClick={() => setView('kanban')}
            className={`px-4 py-1.5 rounded-sm text-sm font-medium transition-colors ${view === 'kanban' ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
          >
            カンバン
          </button>
        </div>
      </div>

      {/* List View */}
      {view === 'list' && (
        <div>
          {/* Filter bar */}
          <div className="flex items-center gap-3 mb-4">
            <Filter className="w-4 h-4 text-[#7d92b0]" />
            <select
              value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-[#7d92b0] focus:outline-hidden"
            >
              <option value="">全ステータス</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="pending">Pending</option>
              <option value="resolved">Resolved</option>
            </select>
            <select
              value={filterPriority} onChange={e => setFilterPriority(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-[#7d92b0] focus:outline-hidden"
            >
              <option value="">全優先度</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select
              value={filterAssignee} onChange={e => setFilterAssignee(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-[#7d92b0] focus:outline-hidden"
            >
              <option value="">全担当者</option>
              {displayUsers.map(u => <option key={u.id} value={u.id}>{u.full_name}</option>)}
            </select>
            {(filterStatus || filterPriority || filterAssignee) && (
              <button
                onClick={() => { setFilterStatus(''); setFilterPriority(''); setFilterAssignee('') }}
                className="text-[#7d92b0] hover:text-white text-sm flex items-center gap-1"
              >
                <X className="w-3.5 h-3.5" />クリア
              </button>
            )}
          </div>

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['チケット#', 'タイトル', 'アラート', '優先度', 'ステータス', '担当者', 'SLA', '作成日時', '操作'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {filtered.map(ticket => (
                  <tr
                    key={ticket.id}
                    onClick={() => setSelectedTicket(ticket)}
                    className="hover:bg-[#19253d]/50 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3">
                      <span className="font-mono text-[#e8002d] text-xs">{ticket.ticket_number}</span>
                    </td>
                    <td className="px-4 py-3 max-w-[220px]">
                      <span className="text-white text-xs font-medium truncate block">{ticket.title}</span>
                    </td>
                    <td className="px-4 py-3">
                      {ticket.alert_id ? (
                        <a
                          href={`/alerts?id=${ticket.alert_id}`}
                          onClick={e => e.stopPropagation()}
                          className="text-[#1a6bff] hover:underline text-xs flex items-center gap-1"
                        >
                          {ticket.alert_id}<ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      ) : <span className="text-[#7d92b0] text-xs">-</span>}
                    </td>
                    <td className="px-4 py-3">{priorityBadge(ticket.priority)}</td>
                    <td className="px-4 py-3">{statusBadge(ticket.status)}</td>
                    <td className="px-4 py-3">
                      {ticket.assignee_name ? (
                        <div className="flex items-center gap-2">
                          <div className="w-6 h-6 rounded-full bg-[#1a6bff]/20 flex items-center justify-center">
                            <span className="text-[9px] text-[#1a6bff] font-bold">{assigneeInitial(ticket.assignee_name)}</span>
                          </div>
                          <span className="text-white text-xs">{ticket.assignee_name}</span>
                        </div>
                      ) : <span className="text-[#7d92b0] text-xs">未割り当て</span>}
                    </td>
                    <td className="px-4 py-3">{slaIndicator(ticket.sla_due_at)}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-xs">{fmtDate(ticket.created_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => setSelectedTicket(ticket)}
                          className="text-[#7d92b0] hover:text-white text-xs px-2 py-1 rounded-sm border border-[#1e2d42] hover:border-[#7d92b0]/40 transition-colors"
                        >
                          表示
                        </button>
                        {canWrite && ticket.status !== 'resolved' && (
                          <button
                            onClick={() => closeMutation.mutate(ticket.id)}
                            className="text-[#7d92b0] hover:text-green-400 text-xs px-2 py-1 rounded-sm border border-[#1e2d42] hover:border-green-700/50 transition-colors"
                          >
                            クローズ
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-4 py-12 text-center text-[#7d92b0] text-sm">チケットが見つかりません</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Kanban View */}
      {view === 'kanban' && (
        <div className="grid grid-cols-4 gap-4">
          {kanbanCols.map(col => {
            const colTickets = displayTickets.filter(t => t.status === col.key)
            const isOver = dragOverCol === col.key
            return (
              <div
                key={col.key}
                onDragOver={e => { e.preventDefault(); setDragOverCol(col.key) }}
                onDragLeave={() => setDragOverCol(null)}
                onDrop={() => handleDrop(col.key)}
                className={`min-h-[200px] rounded-xl border transition-colors ${isOver ? 'border-[#e8002d]/50 bg-[#e8002d]/5' : 'border-[#1e2d42] bg-[#0d1220]'}`}
              >
                <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
                  <span className="text-white text-sm font-medium">{col.label}</span>
                  <span className="text-[10px] text-[#7d92b0] bg-[#1e2d42] rounded-full px-2 py-0.5">{colTickets.length}</span>
                </div>
                <div className="p-3 space-y-2">
                  {colTickets.map(t => (
                    <div
                      key={t.id}
                      draggable
                      onDragStart={() => { dragRef.current = t.id }}
                    >
                      <KanbanCard ticket={t} onClick={() => setSelectedTicket(t)} />
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Side Panel */}
      {selectedTicket && (
        <>
          <div className="fixed inset-0 z-30 bg-black/20" onClick={() => setSelectedTicket(null)} />
          <TicketSidePanel
            ticket={selectedTicket}
            comments={ticketComments}
            onClose={() => setSelectedTicket(null)}
            onAddComment={(body) => commentMutation.mutate({ ticketId: selectedTicket.id, body })}
            addingComment={commentMutation.isPending}
            canWrite={canWrite}
          />
        </>
      )}

      {/* Create Modal */}
      {showCreate && (
        <CreateTicketModal
          users={displayUsers}
          onClose={() => setShowCreate(false)}
          onCreate={(data) => createMutation.mutate(data)}
          loading={createMutation.isPending}
        />
      )}
    </div>
  )
}
