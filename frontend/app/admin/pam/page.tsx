'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Key, Clock, Users, CheckCircle, XCircle, Shield,
  Plus, RefreshCw, X, AlertTriangle, ChevronRight,
  Terminal, Eye, Download, Filter, Calendar,
  Lock, Unlock, Monitor, Database, Globe, Cloud,
  Timer
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type AccessLevel = 'read' | 'write' | 'admin'
type ResourceType = 'server' | 'database' | 'network' | 'cloud'
type RequestStatus = 'pending' | 'approved' | 'denied' | 'expired'

interface PAMRequest {
  id: string
  short_id: string
  requester_name: string
  requester_email: string
  target_resource: string
  resource_type: ResourceType
  access_level: AccessLevel
  duration_minutes: number
  justification: string
  status: RequestStatus
  requested_at: string
  approved_at?: string
  approved_by?: string
  denied_reason?: string
  session_id?: string
}

interface PAMSession {
  id: string
  short_id: string
  request_id: string
  requester_name: string
  target_resource: string
  resource_type: ResourceType
  access_level: AccessLevel
  started_at: string
  expires_at: string
  commands_count: number
}

interface PAMStats {
  pending_requests: number
  approved_today: number
  active_sessions: number
  avg_approval_minutes: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDuration(minutes: number): string {
  if (minutes < 60) return `${minutes}分`
  const h = Math.floor(minutes / 60)
  const m = minutes % 60
  return m > 0 ? `${h}時間${m}分` : `${h}時間`
}

function timeAgo(dateStr: string): { text: string; minutes: number } {
  const diff = Date.now() - new Date(dateStr).getTime()
  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(minutes / 60)
  if (hours > 0) return { text: `${hours}時間前`, minutes }
  return { text: `${minutes}分前`, minutes }
}

function countdown(dateStr: string): string {
  const diff = new Date(dateStr).getTime() - Date.now()
  if (diff <= 0) return '期限切れ'
  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(minutes / 60)
  const m = minutes % 60
  if (hours > 0) return `${hours}h ${m}m`
  return `${m}分`
}

function elapsed(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(minutes / 60)
  const m = minutes % 60
  if (hours > 0) return `${hours}h ${m}m`
  return `${m}分`
}

const ACCESS_LEVEL_COLORS: Record<AccessLevel, string> = {
  read: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  write: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  admin: 'bg-red-500/20 text-red-400 border-red-500/30',
}

const STATUS_COLORS: Record<RequestStatus, string> = {
  pending: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  approved: 'bg-green-500/20 text-green-400 border-green-500/30',
  denied: 'bg-red-500/20 text-red-400 border-red-500/30',
  expired: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
}

const STATUS_LABELS: Record<RequestStatus, string> = {
  pending: '審査中',
  approved: '承認済',
  denied: '却下',
  expired: '期限切れ',
}

const RESOURCE_ICONS: Record<ResourceType, React.ComponentType<{ className?: string }>> = {
  server: Monitor,
  database: Database,
  network: Globe,
  cloud: Cloud,
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: {
  label: string; value: string | number; sub?: string; color?: string
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
      <p className="text-[#7d92b0] text-xs mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color ?? 'text-white'}`}>{value}</p>
      {sub && <p className="text-[#7d92b0] text-xs mt-1">{sub}</p>}
    </div>
  )
}

function AccessLevelBadge({ level }: { level: AccessLevel }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${ACCESS_LEVEL_COLORS[level]}`}>
      {level === 'read' ? '読取' : level === 'write' ? '書込' : '管理者'}
    </span>
  )
}

function StatusBadge({ status }: { status: RequestStatus }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${STATUS_COLORS[status]}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}

function AvatarInitial({ name }: { name: string }) {
  const initial = name[0]
  return (
    <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center flex-shrink-0">
      <span className="text-[10px] font-bold text-white">{initial}</span>
    </div>
  )
}

// ─── Deny Modal ───────────────────────────────────────────────────────────────

function DenyModal({ requestId, onClose, onConfirm }: {
  requestId: string
  onClose: () => void
  onConfirm: (reason: string) => void
}) {
  const [reason, setReason] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md mx-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-400" />
            申請を却下
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <p className="text-[#7d92b0] text-sm mb-4">却下理由を入力してください（申請者に通知されます）</p>
        <textarea
          className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm resize-none focus:outline-none focus:border-[#e8002d] h-28"
          placeholder="却下理由を入力..."
          value={reason}
          onChange={e => setReason(e.target.value)}
        />
        <div className="flex gap-3 mt-4 justify-end">
          <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0] transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => reason.trim() && onConfirm(reason)}
            disabled={!reason.trim()}
            className="px-4 py-2 text-sm rounded-lg bg-red-600 text-white hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            却下する
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── New Request Modal ────────────────────────────────────────────────────────

function NewRequestModal({ onClose, onSubmit }: {
  onClose: () => void
  onSubmit: (data: Partial<PAMRequest>) => void
}) {
  const [form, setForm] = useState({
    target_resource: '',
    resource_type: 'server' as ResourceType,
    access_level: 'read' as AccessLevel,
    duration_minutes: 60,
    justification: '',
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <Plus className="w-5 h-5 text-[#e8002d]" />
            新規アクセス申請
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">対象リソース *</label>
            <input
              type="text"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
              placeholder="例: prod-db-01.internal"
              value={form.target_resource}
              onChange={e => setForm(f => ({ ...f, target_resource: e.target.value }))}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">リソース種別</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                value={form.resource_type}
                onChange={e => setForm(f => ({ ...f, resource_type: e.target.value as ResourceType }))}
              >
                <option value="server">サーバー</option>
                <option value="database">データベース</option>
                <option value="network">ネットワーク</option>
                <option value="cloud">クラウド</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">アクセスレベル</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                value={form.access_level}
                onChange={e => setForm(f => ({ ...f, access_level: e.target.value as AccessLevel }))}
              >
                <option value="read">読取 (read)</option>
                <option value="write">書込 (write)</option>
                <option value="admin">管理者 (admin)</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">アクセス期間</label>
            <select
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
              value={form.duration_minutes}
              onChange={e => setForm(f => ({ ...f, duration_minutes: Number(e.target.value) }))}
            >
              <option value={30}>30分</option>
              <option value={60}>60分</option>
              <option value={120}>120分 (2時間)</option>
              <option value={240}>240分 (4時間)</option>
              <option value={480}>480分 (8時間)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">申請理由 *</label>
            <textarea
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm resize-none focus:outline-none focus:border-[#e8002d] h-24"
              placeholder="アクセスが必要な理由を詳しく記入してください..."
              value={form.justification}
              onChange={e => setForm(f => ({ ...f, justification: e.target.value }))}
            />
          </div>
        </div>
        <div className="flex gap-3 mt-5 justify-end">
          <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0] transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => form.target_resource && form.justification && onSubmit(form)}
            disabled={!form.target_resource || !form.justification}
            className="px-4 py-2 text-sm rounded-lg bg-[#e8002d] text-white hover:bg-[#c0001f] disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            申請する
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────

function RequestsTab({
  requests,
  onApprove,
  onDeny,
  onNewRequest,
}: {
  requests: PAMRequest[]
  onApprove: (id: string) => void
  onDeny: (id: string, reason: string) => void
  onNewRequest: () => void
}) {
  const [denyTarget, setDenyTarget] = useState<string | null>(null)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-white font-semibold">申請一覧</h2>
        <button
          onClick={onNewRequest}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors"
        >
          <Plus className="w-4 h-4" />
          新規申請
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['申請ID', '申請者', '対象リソース', 'レベル', '期間', 'ステータス', '申請日時', 'SLA', '操作'].map(h => (
                <th key={h} className="text-left text-[#7d92b0] text-xs font-medium px-3 py-2 whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1e2d42]/50">
            {requests.map(req => {
              const { text: ago, minutes } = timeAgo(req.requested_at)
              const slaOver = req.status === 'pending' && minutes > 30
              const ResourceIcon = RESOURCE_ICONS[req.resource_type]
              return (
                <tr key={req.id} className="hover:bg-[#0d1220]/60 transition-colors">
                  <td className="px-3 py-2.5 font-mono text-xs text-[#7d92b0]">{req.short_id}</td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <AvatarInitial name={req.requester_name} />
                      <span className="text-white text-xs whitespace-nowrap">{req.requester_name}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <ResourceIcon className="w-3.5 h-3.5 text-[#7d92b0]" />
                      <span className="text-white text-xs">{req.target_resource}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5"><AccessLevelBadge level={req.access_level} /></td>
                  <td className="px-3 py-2.5 text-[#7d92b0] whitespace-nowrap">{formatDuration(req.duration_minutes)}</td>
                  <td className="px-3 py-2.5"><StatusBadge status={req.status} /></td>
                  <td className="px-3 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">
                    {new Date(req.requested_at).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="px-3 py-2.5">
                    {req.status === 'pending' ? (
                      <span className={`text-xs font-medium ${slaOver ? 'text-red-400' : 'text-[#7d92b0]'}`}>
                        {slaOver ? '⚠ ' : ''}{ago}
                      </span>
                    ) : (
                      <span className="text-xs text-[#7d92b0]">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-1.5">
                      {req.status === 'pending' && (
                        <>
                          <button
                            onClick={() => {
                              if (confirm(`「${req.target_resource}」へのアクセスを承認しますか？`)) onApprove(req.id)
                            }}
                            className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-green-600/20 text-green-400 border border-green-600/30 hover:bg-green-600/30 transition-colors"
                          >
                            <CheckCircle className="w-3 h-3" />承認
                          </button>
                          <button
                            onClick={() => setDenyTarget(req.id)}
                            className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30 transition-colors"
                          >
                            <XCircle className="w-3 h-3" />却下
                          </button>
                        </>
                      )}
                      {req.status === 'approved' && req.session_id && (
                        <button className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-blue-600/20 text-blue-400 border border-blue-600/30 hover:bg-blue-600/30 transition-colors">
                          <Eye className="w-3 h-3" />セッション詳細
                        </button>
                      )}
                      {req.status === 'denied' && (
                        <span className="text-xs text-red-400 max-w-[120px] truncate" title={req.denied_reason}>
                          {req.denied_reason}
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {denyTarget && (
        <DenyModal
          requestId={denyTarget}
          onClose={() => setDenyTarget(null)}
          onConfirm={reason => { onDeny(denyTarget, reason); setDenyTarget(null) }}
        />
      )}
    </div>
  )
}

function SessionsTab({
  sessions,
  onEndSession,
  lastRefresh,
  onRefresh,
}: {
  sessions: PAMSession[]
  onEndSession: (id: string) => void
  lastRefresh: Date
  onRefresh: () => void
}) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const iv = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(iv)
  }, [])

  const ResourceIcon = (type: ResourceType) => {
    const IC = RESOURCE_ICONS[type]
    return <IC className="w-3.5 h-3.5 text-[#7d92b0]" />
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-white font-semibold">アクティブセッション ({sessions.length})</h2>
        <div className="flex items-center gap-3">
          <span className="text-xs text-[#7d92b0]">最終更新: {lastRefresh.toLocaleTimeString('ja-JP')}</span>
          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white hover:border-[#7d92b0] transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />更新
          </button>
        </div>
      </div>

      {sessions.length === 0 ? (
        <div className="text-center py-16 text-[#7d92b0]">
          <Shield className="w-10 h-10 mx-auto mb-3 opacity-40" />
          <p>アクティブなセッションはありません</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['セッションID', '申請者', 'リソース', 'レベル', '開始時刻', '経過時間', 'コマンド数', '有効期限', '操作'].map(h => (
                  <th key={h} className="text-left text-[#7d92b0] text-xs font-medium px-3 py-2 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]/50">
              {sessions.map(sess => {
                const expiring = new Date(sess.expires_at).getTime() - Date.now() < 15 * 60 * 1000
                return (
                  <tr key={sess.id} className="hover:bg-[#0d1220]/60 transition-colors">
                    <td className="px-3 py-2.5 font-mono text-xs text-[#7d92b0]">{sess.short_id}</td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <AvatarInitial name={sess.requester_name} />
                        <span className="text-white text-xs whitespace-nowrap">{sess.requester_name}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1.5">
                        {ResourceIcon(sess.resource_type)}
                        <span className="text-white text-xs">{sess.target_resource}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2.5"><AccessLevelBadge level={sess.access_level} /></td>
                    <td className="px-3 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">
                      {new Date(sess.started_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-3 py-2.5 text-white text-xs font-mono">{elapsed(sess.started_at)}</td>
                    <td className="px-3 py-2.5">
                      <span className="text-white font-medium">{sess.commands_count}</span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`text-xs font-mono font-medium ${expiring ? 'text-red-400' : 'text-green-400'}`}>
                        {countdown(sess.expires_at)}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <button
                        onClick={() => {
                          if (confirm(`セッション ${sess.short_id} を強制終了しますか？`)) onEndSession(sess.id)
                        }}
                        className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30 transition-colors"
                      >
                        <Lock className="w-3 h-3" />終了
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function AuditTab({ requests }: { requests: PAMRequest[] }) {
  const [statusFilter, setStatusFilter] = useState<RequestStatus | 'all'>('all')
  const [requesterFilter, setRequesterFilter] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  const auditRequests = requests.filter(r => r.status !== 'pending')

  const filtered = auditRequests.filter(r => {
    if (statusFilter !== 'all' && r.status !== statusFilter) return false
    if (requesterFilter && !r.requester_name.includes(requesterFilter) && !r.target_resource.includes(requesterFilter)) return false
    if (dateFrom && new Date(r.requested_at) < new Date(dateFrom)) return false
    if (dateTo && new Date(r.requested_at) > new Date(dateTo + 'T23:59:59')) return false
    return true
  })

  const exportCSV = () => {
    const headers = ['申請ID', '申請者', '対象リソース', 'アクセスレベル', '期間(分)', 'ステータス', '申請日時', '承認日時', '却下理由']
    const rows = filtered.map(r => [
      r.short_id, r.requester_name, r.target_resource,
      r.access_level, r.duration_minutes, r.status,
      r.requested_at, r.approved_at ?? '', r.denied_reason ?? '',
    ])
    const csv = [headers, ...rows].map(row => row.join(',')).join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'pam_audit.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-white font-semibold mr-auto">監査ログ</h2>
        <button onClick={exportCSV} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white hover:border-[#7d92b0] transition-colors">
          <Download className="w-3.5 h-3.5" />CSV出力
        </button>
      </div>

      <div className="flex flex-wrap gap-3 p-3 bg-[#0d1220] border border-[#1e2d42] rounded-lg">
        <select
          className="bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-white text-xs focus:outline-none focus:border-[#e8002d]"
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value as RequestStatus | 'all')}
        >
          <option value="all">全ステータス</option>
          <option value="approved">承認済</option>
          <option value="denied">却下</option>
          <option value="expired">期限切れ</option>
        </select>
        <input
          type="text"
          className="bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-white text-xs focus:outline-none focus:border-[#e8002d] w-40"
          placeholder="申請者/リソース検索..."
          value={requesterFilter}
          onChange={e => setRequesterFilter(e.target.value)}
        />
        <input
          type="date"
          className="bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-white text-xs focus:outline-none focus:border-[#e8002d]"
          value={dateFrom}
          onChange={e => setDateFrom(e.target.value)}
        />
        <span className="text-[#7d92b0] text-xs self-center">〜</span>
        <input
          type="date"
          className="bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-white text-xs focus:outline-none focus:border-[#e8002d]"
          value={dateTo}
          onChange={e => setDateTo(e.target.value)}
        />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['申請ID', '申請者', '対象リソース', 'レベル', '期間', 'ステータス', '申請日時', '処理日時', '詳細'].map(h => (
                <th key={h} className="text-left text-[#7d92b0] text-xs font-medium px-3 py-2 whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1e2d42]/50">
            {filtered.map(req => {
              const ResourceIcon = RESOURCE_ICONS[req.resource_type]
              return (
                <tr key={req.id} className="hover:bg-[#0d1220]/60 transition-colors">
                  <td className="px-3 py-2.5 font-mono text-xs text-[#7d92b0]">{req.short_id}</td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <AvatarInitial name={req.requester_name} />
                      <span className="text-white text-xs">{req.requester_name}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <ResourceIcon className="w-3.5 h-3.5 text-[#7d92b0]" />
                      <span className="text-white text-xs">{req.target_resource}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5"><AccessLevelBadge level={req.access_level} /></td>
                  <td className="px-3 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">{formatDuration(req.duration_minutes)}</td>
                  <td className="px-3 py-2.5"><StatusBadge status={req.status} /></td>
                  <td className="px-3 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">
                    {new Date(req.requested_at).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="px-3 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">
                    {(req.approved_at || req.denied_reason)
                      ? req.approved_at
                        ? new Date(req.approved_at).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
                        : '—'
                      : '—'}
                  </td>
                  <td className="px-3 py-2.5">
                    {req.denied_reason && (
                      <span className="text-xs text-red-400 max-w-[150px] block truncate" title={req.denied_reason}>
                        {req.denied_reason}
                      </span>
                    )}
                    {req.approved_by && (
                      <span className="text-xs text-green-400">承認: {req.approved_by}</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="text-center py-10 text-[#7d92b0] text-sm">該当するログがありません</div>
        )}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PAMPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'requests' | 'sessions' | 'audit'>('requests')
  const [showNewRequest, setShowNewRequest] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(new Date())

  const EMPTY_STATS: PAMStats = { pending_requests: 0, approved_today: 0, active_sessions: 0, avg_approval_minutes: 0 }

  const { data: statsData } = useQuery<PAMStats>({
    queryKey: ['pam-stats'],
    queryFn: async () => {
      try { return await apiFetch('/api/v1/pam/stats') } catch { return EMPTY_STATS }
    },
    staleTime: 30_000,
    retry: false,
  })
  const stats = (statsData && typeof statsData === 'object' && 'active_sessions' in statsData)
    ? statsData as PAMStats
    : EMPTY_STATS

  const { data: requestsData, refetch: refetchRequests } = useQuery<PAMRequest[]>({
    queryKey: ['pam-requests'],
    queryFn: () => apiFetchList<PAMRequest>('/api/v1/pam/requests').catch(() => []),
    staleTime: 30_000,
    retry: false,
  })
  const [localRequests, setLocalRequests] = useState<PAMRequest[]>([])
  const requests: PAMRequest[] = Array.isArray(requestsData) ? requestsData : localRequests

  const { data: sessionsData, refetch: refetchSessions } = useQuery<PAMSession[]>({
    queryKey: ['pam-sessions'],
    queryFn: () => apiFetchList<PAMSession>('/api/v1/pam/sessions').catch(() => []),
    staleTime: 30_000,
    retry: false,
    refetchInterval: 30_000,
  })
  const [localSessions, setLocalSessions] = useState<PAMSession[]>([])
  const sessions: PAMSession[] = Array.isArray(sessionsData) ? sessionsData : localSessions

  const approveMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/pam/requests/${id}/approve`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pam-requests'] }),
    onError: (_, id) => {
      setLocalRequests(prev => prev.map(r => r.id === id ? { ...r, status: 'approved', approved_at: new Date().toISOString(), approved_by: '管理者' } : r))
    },
  })

  const denyMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiFetch(`/api/v1/pam/requests/${id}/deny`, { method: 'POST', body: JSON.stringify({ reason }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pam-requests'] }),
    onError: (_, { id, reason }) => {
      setLocalRequests(prev => prev.map(r => r.id === id ? { ...r, status: 'denied', denied_reason: reason } : r))
    },
  })

  const endSessionMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/pam/sessions/${id}/end`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['pam-sessions'] }),
    onError: (_, id) => {
      setLocalSessions(prev => prev.filter(s => s.id !== id))
    },
  })

  const createRequestMutation = useMutation({
    mutationFn: (data: Partial<PAMRequest>) => apiFetch('/api/v1/pam/requests', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['pam-requests'] }); setShowNewRequest(false) },
    onError: (_, data) => {
      const newReq: PAMRequest = {
        id: `req-${Date.now()}`,
        short_id: `PAM-${String(localRequests.length + 1).padStart(3, '0')}`,
        requester_name: '現在のユーザー',
        requester_email: 'current@example.com',
        target_resource: data.target_resource ?? '',
        resource_type: data.resource_type ?? 'server',
        access_level: data.access_level ?? 'read',
        duration_minutes: data.duration_minutes ?? 60,
        justification: data.justification ?? '',
        status: 'pending',
        requested_at: new Date().toISOString(),
      }
      setLocalRequests(prev => [newReq, ...prev])
      setShowNewRequest(false)
    },
  })

  const handleRefresh = () => {
    refetchRequests()
    refetchSessions()
    setLastRefresh(new Date())
  }

  const TABS = [
    { id: 'requests', label: 'アクセス申請' },
    { id: 'sessions', label: 'アクティブセッション' },
    { id: 'audit', label: '監査ログ' },
  ] as const

  const pendingCount = requests.filter(r => r.status === 'pending').length

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Key className="w-7 h-7 text-[#e8002d]" />
            特権アクセス管理 (PAM)
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">特権アクセス申請・承認・セッション記録の管理</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="審査中の申請"
          value={stats.pending_requests}
          sub="要対応"
          color={stats.pending_requests > 0 ? 'text-yellow-400' : 'text-white'}
        />
        <StatCard label="本日承認数" value={stats.approved_today} sub="件" color="text-green-400" />
        <StatCard label="アクティブセッション" value={stats.active_sessions} sub="現在稼働中" color="text-blue-400" />
        <StatCard
          label="平均承認時間"
          value={stats.avg_approval_minutes != null ? `${stats.avg_approval_minutes}分` : '—'}
          sub="目標: 30分以内"
          color={(stats.avg_approval_minutes ?? 0) > 30 ? 'text-red-400' : 'text-white'}
        />
      </div>

      {/* Card */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        {/* Tabs */}
        <div className="flex border-b border-[#1e2d42]">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-5 py-3 text-sm font-medium transition-colors relative flex items-center gap-2 ${
                tab === t.id
                  ? 'text-white border-b-2 border-[#e8002d]'
                  : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {t.label}
              {t.id === 'requests' && pendingCount > 0 && (
                <span className="bg-yellow-500 text-black text-[10px] font-bold px-1.5 py-0.5 rounded-full">
                  {pendingCount}
                </span>
              )}
              {t.id === 'sessions' && sessions.length > 0 && (
                <span className="bg-blue-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">
                  {sessions.length}
                </span>
              )}
            </button>
          ))}
        </div>

        <div className="p-5">
          {tab === 'requests' && (
            <RequestsTab
              requests={requests}
              onApprove={id => approveMutation.mutate(id)}
              onDeny={(id, reason) => denyMutation.mutate({ id, reason })}
              onNewRequest={() => setShowNewRequest(true)}
            />
          )}
          {tab === 'sessions' && (
            <SessionsTab
              sessions={sessions}
              onEndSession={id => endSessionMutation.mutate(id)}
              lastRefresh={lastRefresh}
              onRefresh={handleRefresh}
            />
          )}
          {tab === 'audit' && <AuditTab requests={requests} />}
        </div>
      </div>

      {showNewRequest && (
        <NewRequestModal
          onClose={() => setShowNewRequest(false)}
          onSubmit={data => createRequestMutation.mutate(data)}
        />
      )}
    </div>
  )
}
