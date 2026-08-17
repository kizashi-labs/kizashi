'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  TicketIcon, MessageSquare, ChevronDown, ChevronUp,
  Clock, CheckCircle, AlertTriangle, XCircle, Loader2,
  Users, TrendingUp, Activity,
} from 'lucide-react'

// ─── 型定義 ─────────────────────────────────────────────────────────────────

interface Ticket {
  id: string
  tenant_id: string | null
  created_by: string | null
  created_by_name: string
  assigned_to: string | null
  assigned_to_name: string
  title: string
  description: string
  category: string
  priority: string
  status: string
  comment_count: number
  resolved_at: string | null
  closed_at: string | null
  created_at: string
  updated_at: string
}

interface Comment {
  id: string
  ticket_id: string
  author_name: string
  body: string
  is_internal: boolean
  created_at: string
}

interface Stats {
  open: number
  in_progress: number
  resolved: number
  closed: number
  critical: number
  high: number
  avg_resolve_hours: number
}

// ─── ヘルパー ────────────────────────────────────────────────────────────────

const statusIcon: Record<string, React.ReactNode> = {
  open:             <Clock className="w-3.5 h-3.5 text-[#3b82f6]" />,
  in_progress:      <Loader2 className="w-3.5 h-3.5 text-[#f59e0b] animate-spin" />,
  waiting_customer: <AlertTriangle className="w-3.5 h-3.5 text-[#f97316]" />,
  resolved:         <CheckCircle className="w-3.5 h-3.5 text-[#22c55e]" />,
  closed:           <XCircle className="w-3.5 h-3.5 text-[#5a6a7a]" />,
}

const statusLabel: Record<string, string> = {
  open:             'オープン',
  in_progress:      '対応中',
  waiting_customer: '顧客回答待ち',
  resolved:         '解決済み',
  closed:           'クローズ',
}

const priorityBadge: Record<string, string> = {
  critical: 'bg-falcon-red/20 text-falcon-red',
  high:     'bg-[#f97316]/20 text-[#f97316]',
  medium:   'bg-[#f59e0b]/20 text-[#f59e0b]',
  low:      'bg-[#5a6a7a]/20 text-[#8899aa]',
}

const priorityLabel: Record<string, string> = {
  critical: '緊急',
  high:     '高',
  medium:   '中',
  low:      '低',
}

const categoryLabel: Record<string, string> = {
  billing:         '課金',
  technical:       'テクニカル',
  feature_request: '機能要望',
  bug_report:      'バグ報告',
  installation:    'インストール',
  configuration:   '設定',
  security:        'セキュリティ',
  other:           'その他',
}

function fmtDate(s: string) {
  return new Date(s).toLocaleString('ja-JP', { dateStyle: 'short', timeStyle: 'short' })
}

// ─── 統計カード ──────────────────────────────────────────────────────────

function StatCard({ icon, label, value, sub }: {
  icon: React.ReactNode
  label: string
  value: string | number
  sub?: string
}) {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
      <div className="flex items-center gap-2 mb-2 text-[#5a6a7a]">
        {icon}
        <span className="text-xs">{label}</span>
      </div>
      <p className="text-2xl font-bold text-falcon-text">{value}</p>
      {sub && <p className="text-xs text-[#5a6a7a] mt-0.5">{sub}</p>}
    </div>
  )
}

// ─── 管理者コメント欄 ─────────────────────────────────────────────────────

function AdminComments({ ticketId }: { ticketId: string }) {
  const [body, setBody] = useState('')
  const [isInternal, setIsInternal] = useState(false)
  const qc = useQueryClient()

  const { data: comments = [] } = useQuery<Comment[]>({
    queryKey: ['admin-ticket-comments', ticketId],
    queryFn: () => apiFetch(`/api/v1/support/tickets/${ticketId}/comments`),
  })

  const addMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/support/tickets/${ticketId}/comments`, {
        method: 'POST',
        body: JSON.stringify({ body, is_internal: isInternal }),
      }),
    onSuccess: () => {
      setBody('')
      qc.invalidateQueries({ queryKey: ['admin-ticket-comments', ticketId] })
      qc.invalidateQueries({ queryKey: ['admin-support-tickets'] })
    },
  })

  return (
    <div className="mt-4 pt-4 border-t border-falcon-border">
      <p className="text-xs font-medium text-[#5a6a7a] mb-3">コメント ({comments.length})</p>
      <div className="space-y-2 mb-3 max-h-48 overflow-y-auto">
        {comments.map(cm => (
          <div key={cm.id} className={`flex gap-2 ${cm.is_internal ? 'opacity-70' : ''}`}>
            <div className="w-6 h-6 rounded-full bg-falcon-border flex items-center justify-center shrink-0 text-xs text-[#5a6a7a] mt-0.5">
              {cm.author_name.charAt(0).toUpperCase()}
            </div>
            <div className={`flex-1 rounded-sm p-2 border ${cm.is_internal ? 'bg-[#1a1000] border-[#f59e0b]/20' : 'bg-falcon-bg border-falcon-border'}`}>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-medium text-falcon-text">{cm.author_name}</span>
                {cm.is_internal && (
                  <span className="px-1 py-0.5 rounded-sm text-[9px] bg-[#f59e0b]/20 text-[#f59e0b]">内部メモ</span>
                )}
                <span className="text-xs text-[#5a6a7a]">{fmtDate(cm.created_at)}</span>
              </div>
              <p className="text-xs text-[#8899aa] whitespace-pre-wrap">{cm.body}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="space-y-2">
        <textarea
          value={body}
          onChange={e => setBody(e.target.value)}
          rows={2}
          placeholder="返信を入力..."
          className="w-full bg-falcon-bg border border-falcon-border rounded-sm px-3 py-2 text-xs text-falcon-text placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#2a3f5a] resize-none"
        />
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-2 text-xs text-[#5a6a7a] cursor-pointer">
            <input
              type="checkbox"
              checked={isInternal}
              onChange={e => setIsInternal(e.target.checked)}
              className="rounded-sm"
            />
            内部メモ（顧客非表示）
          </label>
          <button
            onClick={() => addMutation.mutate()}
            disabled={!body || addMutation.isPending}
            className="px-3 py-1.5 bg-falcon-border hover:bg-[#2a3f5a] disabled:opacity-50 text-falcon-text text-xs rounded-sm transition-colors"
          >
            送信
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── チケット行 (管理者用) ────────────────────────────────────────────────

function AdminTicketRow({ ticket }: { ticket: Ticket }) {
  const [expanded, setExpanded] = useState(false)
  const qc = useQueryClient()

  const updateMutation = useMutation({
    mutationFn: (payload: { status?: string; priority?: string }) =>
      apiFetch(`/api/v1/support/tickets/${ticket.id}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-support-tickets'] })
      qc.invalidateQueries({ queryKey: ['admin-support-stats'] })
    },
  })

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-falcon-card transition-colors"
      >
        {/* ステータス */}
        <div className="flex items-center gap-1 w-28 shrink-0">
          {statusIcon[ticket.status]}
          <span className="text-xs text-[#8899aa]">{statusLabel[ticket.status] ?? ticket.status}</span>
        </div>
        {/* タイトル */}
        <div className="flex-1 min-w-0">
          <p className="text-sm text-falcon-text truncate">{ticket.title}</p>
          <p className="text-xs text-[#5a6a7a]">
            {ticket.created_by_name} · {categoryLabel[ticket.category] ?? ticket.category} · {fmtDate(ticket.updated_at)}
          </p>
        </div>
        {/* 優先度バッジ */}
        <span className={`px-1.5 py-0.5 rounded-sm text-[10px] font-medium shrink-0 ${priorityBadge[ticket.priority] ?? 'bg-falcon-border text-[#8899aa]'}`}>
          {priorityLabel[ticket.priority] ?? ticket.priority}
        </span>
        {/* コメント数 */}
        <span className="flex items-center gap-1 text-xs text-[#5a6a7a] shrink-0">
          <MessageSquare className="w-3 h-3" />
          {ticket.comment_count}
        </span>
        {expanded ? <ChevronUp className="w-4 h-4 text-[#5a6a7a]" /> : <ChevronDown className="w-4 h-4 text-[#5a6a7a]" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-falcon-border">
          <p className="text-xs text-[#8899aa] mt-3 whitespace-pre-wrap mb-4">{ticket.description}</p>

          {/* アクション */}
          <div className="flex flex-wrap gap-2 mb-2">
            <div>
              <label className="block text-[10px] text-[#5a6a7a] mb-1">ステータス変更</label>
              <select
                defaultValue={ticket.status}
                onChange={e => updateMutation.mutate({ status: e.target.value })}
                className="bg-falcon-bg border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-falcon-text focus:outline-hidden"
              >
                <option value="open">オープン</option>
                <option value="in_progress">対応中</option>
                <option value="waiting_customer">顧客回答待ち</option>
                <option value="resolved">解決済み</option>
                <option value="closed">クローズ</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] text-[#5a6a7a] mb-1">優先度変更</label>
              <select
                defaultValue={ticket.priority}
                onChange={e => updateMutation.mutate({ priority: e.target.value })}
                className="bg-falcon-bg border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-falcon-text focus:outline-hidden"
              >
                <option value="low">低</option>
                <option value="medium">中</option>
                <option value="high">高</option>
                <option value="critical">緊急</option>
              </select>
            </div>
          </div>

          <AdminComments ticketId={ticket.id} />
        </div>
      )}
    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────

export default function AdminSupportPage() {
  const [statusFilter, setStatusFilter] = useState('')
  const [priorityFilter, setPriorityFilter] = useState('')

  const { data: stats } = useQuery<Stats>({
    queryKey: ['admin-support-stats'],
    queryFn: () => apiFetch('/api/v1/admin/support/stats'),
    refetchInterval: 30_000,
  })

  const { data: tickets = [], isLoading } = useQuery<Ticket[]>({
    queryKey: ['admin-support-tickets', statusFilter, priorityFilter],
    queryFn: () => {
      const p = new URLSearchParams()
      if (statusFilter)   p.set('status', statusFilter)
      if (priorityFilter) p.set('priority', priorityFilter)
      const qs = p.toString()
      return apiFetch(`/api/v1/support/tickets${qs ? `?${qs}` : ''}`)
    },
  })

  const statusTabs = [
    { value: '',             label: 'すべて' },
    { value: 'open',         label: `オープン (${stats?.open ?? 0})` },
    { value: 'in_progress',  label: `対応中 (${stats?.in_progress ?? 0})` },
    { value: 'waiting_customer', label: '回答待ち' },
    { value: 'resolved',     label: `解決済み (${stats?.resolved ?? 0})` },
    { value: 'closed',       label: 'クローズ' },
  ]

  return (
    <div className="p-6">
      <div className="flex items-center gap-3 mb-6">
        <TicketIcon className="w-5 h-5 text-falcon-red" />
        <div>
          <h1 className="text-lg font-semibold text-falcon-text">サポート管理</h1>
          <p className="text-xs text-[#5a6a7a]">全テナントのサポートチケットを管理</p>
        </div>
      </div>

      {/* 統計カード */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatCard
            icon={<Activity className="w-4 h-4" />}
            label="オープン + 対応中"
            value={stats.open + stats.in_progress}
          />
          <StatCard
            icon={<AlertTriangle className="w-4 h-4 text-falcon-red" />}
            label="緊急・高優先度"
            value={stats.critical + stats.high}
            sub={`緊急: ${stats.critical} / 高: ${stats.high}`}
          />
          <StatCard
            icon={<CheckCircle className="w-4 h-4 text-[#22c55e]" />}
            label="解決済み"
            value={stats.resolved}
          />
          <StatCard
            icon={<TrendingUp className="w-4 h-4 text-[#3b82f6]" />}
            label="平均解決時間"
            value={`${stats.avg_resolve_hours.toFixed(1)}h`}
          />
        </div>
      )}

      {/* フィルター */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="flex gap-0 border-b border-falcon-border">
          {statusTabs.map(tab => (
            <button
              key={tab.value}
              onClick={() => setStatusFilter(tab.value)}
              className={`px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px ${
                statusFilter === tab.value
                  ? 'border-falcon-red text-falcon-text'
                  : 'border-transparent text-[#5a6a7a] hover:text-[#8899aa]'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <select
          value={priorityFilter}
          onChange={e => setPriorityFilter(e.target.value)}
          className="ml-auto bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-falcon-text focus:outline-hidden"
        >
          <option value="">優先度: すべて</option>
          <option value="critical">緊急</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>
      </div>

      {/* チケット一覧 */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16 text-[#5a6a7a] text-sm">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />
          読み込み中...
        </div>
      ) : tickets.length === 0 ? (
        <div className="text-center py-16 text-[#5a6a7a] text-sm">
          <TicketIcon className="w-8 h-8 mx-auto mb-3 opacity-30" />
          <p>チケットはありません</p>
        </div>
      ) : (
        <div className="space-y-2">
          {tickets.map(tk => (
            <AdminTicketRow key={tk.id} ticket={tk} />
          ))}
        </div>
      )}
    </div>
  )
}
