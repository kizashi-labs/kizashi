'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  TicketIcon, PlusCircle, MessageSquare, ChevronDown, ChevronUp,
  Clock, CheckCircle, AlertTriangle, XCircle, Loader2,
} from 'lucide-react'

// ─── 型定義 ─────────────────────────────────────────────────────────────────

interface Ticket {
  id: string
  title: string
  description: string
  category: string
  priority: string
  status: string
  comment_count: number
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
  waiting_customer: '回答待ち',
  resolved:         '解決済み',
  closed:           'クローズ',
}

const priorityBadge: Record<string, string> = {
  critical: 'bg-[#e8002d]/20 text-[#e8002d]',
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

// ─── 新規チケット作成フォーム ─────────────────────────────────────────────

function NewTicketForm({ onCreated }: { onCreated: () => void }) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [category, setCategory] = useState('technical')
  const [priority, setPriority] = useState('medium')
  const [open, setOpen] = useState(false)

  const mutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/support/tickets', {
        method: 'POST',
        body: JSON.stringify({ title, description, category, priority }),
      }),
    onSuccess: () => {
      setTitle('')
      setDescription('')
      setOpen(false)
      onCreated()
    },
  })

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded transition-colors"
      >
        <PlusCircle className="w-4 h-4" />
        新しいチケットを作成
      </button>
    )
  }

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5 mb-6">
      <h2 className="text-sm font-semibold text-[#e2e8f4] mb-4">新しいサポートチケット</h2>
      <div className="space-y-3">
        <div>
          <label className="block text-xs text-[#5a6a7a] mb-1">件名 *</label>
          <input
            value={title}
            onChange={e => setTitle(e.target.value)}
            placeholder="問題を簡潔に説明してください"
            className="w-full bg-[#080c14] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-none focus:border-[#2a3f5a]"
          />
        </div>
        <div>
          <label className="block text-xs text-[#5a6a7a] mb-1">詳細 *</label>
          <textarea
            value={description}
            onChange={e => setDescription(e.target.value)}
            rows={4}
            placeholder="問題の詳細、再現手順、エラーメッセージなどを記入してください"
            className="w-full bg-[#080c14] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-none focus:border-[#2a3f5a] resize-none"
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-[#5a6a7a] mb-1">カテゴリ</label>
            <select
              value={category}
              onChange={e => setCategory(e.target.value)}
              className="w-full bg-[#080c14] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#2a3f5a]"
            >
              {Object.entries(categoryLabel).map(([v, l]) => (
                <option key={v} value={v}>{l}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-[#5a6a7a] mb-1">優先度</label>
            <select
              value={priority}
              onChange={e => setPriority(e.target.value)}
              className="w-full bg-[#080c14] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#2a3f5a]"
            >
              <option value="low">低</option>
              <option value="medium">中</option>
              <option value="high">高</option>
              <option value="critical">緊急</option>
            </select>
          </div>
        </div>
        {mutation.isError && (
          <p className="text-xs text-[#e8002d]">送信に失敗しました。もう一度お試しください。</p>
        )}
        <div className="flex gap-2 pt-1">
          <button
            onClick={() => mutation.mutate()}
            disabled={!title || !description || mutation.isPending}
            className="px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 text-white text-sm rounded transition-colors"
          >
            {mutation.isPending ? '送信中...' : '送信'}
          </button>
          <button
            onClick={() => setOpen(false)}
            className="px-4 py-2 bg-[#1e2d42] hover:bg-[#2a3f5a] text-[#8899aa] text-sm rounded transition-colors"
          >
            キャンセル
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── コメント欄 ───────────────────────────────────────────────────────────

function CommentsPanel({ ticketId }: { ticketId: string }) {
  const [body, setBody] = useState('')
  const qc = useQueryClient()

  const { data: comments = [] } = useQuery<Comment[]>({
    queryKey: ['ticket-comments', ticketId],
    queryFn: () => apiFetch(`/api/v1/support/tickets/${ticketId}/comments`),
  })

  const addMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/support/tickets/${ticketId}/comments`, {
        method: 'POST',
        body: JSON.stringify({ body }),
      }),
    onSuccess: () => {
      setBody('')
      qc.invalidateQueries({ queryKey: ['ticket-comments', ticketId] })
    },
  })

  return (
    <div className="mt-4 pt-4 border-t border-[#1e2d42]">
      <p className="text-xs font-medium text-[#5a6a7a] mb-3">
        コメント ({comments.length})
      </p>
      <div className="space-y-2 mb-3">
        {comments.map(cm => (
          <div key={cm.id} className="flex gap-2">
            <div className="w-6 h-6 rounded-full bg-[#1e2d42] flex items-center justify-center flex-shrink-0 text-xs text-[#5a6a7a] mt-0.5">
              {cm.author_name.charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 bg-[#080c14] border border-[#1e2d42] rounded p-2">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-medium text-[#e2e8f4]">{cm.author_name}</span>
                <span className="text-xs text-[#5a6a7a]">{fmtDate(cm.created_at)}</span>
              </div>
              <p className="text-xs text-[#8899aa] whitespace-pre-wrap">{cm.body}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          value={body}
          onChange={e => setBody(e.target.value)}
          placeholder="返信を入力..."
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey && body) { e.preventDefault(); addMutation.mutate() } }}
          className="flex-1 bg-[#080c14] border border-[#1e2d42] rounded px-3 py-2 text-xs text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-none focus:border-[#2a3f5a]"
        />
        <button
          onClick={() => addMutation.mutate()}
          disabled={!body || addMutation.isPending}
          className="px-3 py-2 bg-[#1e2d42] hover:bg-[#2a3f5a] disabled:opacity-50 text-[#e2e8f4] text-xs rounded transition-colors"
        >
          送信
        </button>
      </div>
    </div>
  )
}

// ─── チケット行 ──────────────────────────────────────────────────────────

function TicketRow({ ticket }: { ticket: Ticket }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-[#111827] transition-colors"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-medium text-[#e2e8f4] truncate">{ticket.title}</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${priorityBadge[ticket.priority] ?? 'bg-[#1e2d42] text-[#8899aa]'}`}>
              {priorityLabel[ticket.priority] ?? ticket.priority}
            </span>
          </div>
          <div className="flex items-center gap-3 text-xs text-[#5a6a7a]">
            <span className="flex items-center gap-1">
              {statusIcon[ticket.status]}
              {statusLabel[ticket.status] ?? ticket.status}
            </span>
            <span>{categoryLabel[ticket.category] ?? ticket.category}</span>
            <span className="flex items-center gap-1">
              <MessageSquare className="w-3 h-3" />
              {ticket.comment_count}
            </span>
            <span>{fmtDate(ticket.updated_at)}</span>
          </div>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-[#5a6a7a] flex-shrink-0" /> : <ChevronDown className="w-4 h-4 text-[#5a6a7a] flex-shrink-0" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-[#1e2d42]">
          <p className="text-xs text-[#8899aa] mt-3 whitespace-pre-wrap">{ticket.description}</p>
          <CommentsPanel ticketId={ticket.id} />
        </div>
      )}
    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────

export default function SupportPage() {
  const [statusFilter, setStatusFilter] = useState('')
  const qc = useQueryClient()

  const { data: tickets = [], isLoading } = useQuery<Ticket[]>({
    queryKey: ['support-tickets', statusFilter],
    queryFn: () =>
      apiFetch(`/api/v1/support/tickets${statusFilter ? `?status=${statusFilter}` : ''}`),
  })

  const statusTabs = [
    { value: '',             label: 'すべて' },
    { value: 'open',         label: 'オープン' },
    { value: 'in_progress',  label: '対応中' },
    { value: 'resolved',     label: '解決済み' },
    { value: 'closed',       label: 'クローズ' },
  ]

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <TicketIcon className="w-5 h-5 text-[#e8002d]" />
          <div>
            <h1 className="text-lg font-semibold text-[#e2e8f4]">サポートチケット</h1>
            <p className="text-xs text-[#5a6a7a]">技術的な問題や質問はチケットでお問い合わせください</p>
          </div>
        </div>
        <NewTicketForm onCreated={() => qc.invalidateQueries({ queryKey: ['support-tickets'] })} />
      </div>

      {/* ステータスフィルター */}
      <div className="flex gap-1 mb-4 border-b border-[#1e2d42] pb-0">
        {statusTabs.map(tab => (
          <button
            key={tab.value}
            onClick={() => setStatusFilter(tab.value)}
            className={`px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px ${
              statusFilter === tab.value
                ? 'border-[#e8002d] text-[#e2e8f4]'
                : 'border-transparent text-[#5a6a7a] hover:text-[#8899aa]'
            }`}
          >
            {tab.label}
          </button>
        ))}
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
          {statusFilter === '' && (
            <p className="text-xs mt-1">「新しいチケットを作成」からお問い合わせください</p>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {tickets.map(tk => (
            <TicketRow key={tk.id} ticket={tk} />
          ))}
        </div>
      )}
    </div>
  )
}
