'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  MonitorSmartphone, RefreshCw, Shield, XCircle, CheckCircle,
  Clock, Users, Globe, AlertTriangle, Trash2, X,
  Search, Filter, ChevronDown, ToggleLeft, ToggleRight,
  Activity
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ──────────────────────────────────────────────────────────────────────

interface Session {
  id: string
  user_id: string
  user_email: string
  user_name?: string
  ip_address: string
  user_agent: string
  created_at: string
  last_active_at: string
  expires_at: string
  revoked: boolean
}

interface SessionsResponse {
  sessions: Session[]
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function parseBrowser(ua: string): string {
  if (!ua) return 'Unknown'
  if (ua.includes('Firefox')) return 'Firefox'
  if (ua.includes('Chrome')) return 'Chrome'
  if (ua.includes('Safari')) return 'Safari'
  return 'Unknown'
}

function parseOS(ua: string): string {
  if (!ua) return 'Unknown'
  if (ua.includes('Windows')) return 'Windows'
  if (ua.includes('Mac OS')) return 'macOS'
  if (ua.includes('Linux')) return 'Linux'
  if (ua.includes('Android')) return 'Android'
  if (ua.includes('iPhone') || ua.includes('iPad')) return 'iOS'
  return 'Unknown'
}

function getSessionStatus(session: Session): 'active' | 'expired' | 'revoked' {
  if (session.revoked) return 'revoked'
  if (new Date(session.expires_at) < new Date()) return 'expired'
  return 'active'
}

function fmtDate(iso: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    })
  } catch {
    return '—'
  }
}

function timeAgo(iso: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'たった今'
  if (mins < 60) return `${mins}分前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}時間前`
  const days = Math.floor(hours / 24)
  return `${days}日前`
}

// ── Status Badge ───────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: 'active' | 'expired' | 'revoked' }) {
  const styles = {
    active:  'bg-green-900/40 text-green-300 border border-green-700/50',
    expired: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',
    revoked: 'bg-red-900/40 text-red-300 border border-red-700/50',
  }
  const labels = {
    active:  'アクティブ',
    expired: '期限切れ',
    revoked: '無効化',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${styles[status]}`}>
      {labels[status]}
    </span>
  )
}

// ── Confirm Modal ──────────────────────────────────────────────────────────────

interface ConfirmModalProps {
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
  isPending: boolean
  danger?: boolean
}

function ConfirmModal({ title, message, onConfirm, onCancel, isPending, danger = true }: ConfirmModalProps) {
  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-[#0d1220] rounded-2xl p-6 w-full max-w-md border border-[#1e2d42] shadow-2xl">
        <div className="flex items-start gap-3 mb-4">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${
            danger ? 'bg-red-900/40' : 'bg-blue-900/40'
          }`}>
            <AlertTriangle className={`w-5 h-5 ${danger ? 'text-red-400' : 'text-blue-400'}`} />
          </div>
          <div>
            <h3 className="text-white font-semibold text-lg">{title}</h3>
            <p className="text-[#7d92b0] text-sm mt-1">{message}</p>
          </div>
        </div>
        <div className="flex gap-3 justify-end mt-6">
          <button
            onClick={onCancel}
            disabled={isPending}
            className="px-4 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] hover:text-white transition-colors text-sm disabled:opacity-50"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className={`px-4 py-2 rounded-lg text-white text-sm transition-colors
                        disabled:opacity-50 flex items-center gap-2
                        ${danger ? 'bg-[#e8002d] hover:bg-[#c0001f]' : 'bg-blue-600 hover:bg-blue-700'}`}
          >
            {isPending && (
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            )}
            確認
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function AdminSessionsPage() {
  const qc = useQueryClient()

  // Filter state
  const [searchUser, setSearchUser]   = useState('')
  const [searchIP, setSearchIP]       = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'expired' | 'revoked'>('all')

  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(false)

  // Confirm modal state
  const [confirmRevokeId, setConfirmRevokeId]           = useState<string | null>(null)
  const [confirmRevokeUserId, setConfirmRevokeUserId]   = useState<string | null>(null)
  const [confirmRevokeUserEmail, setConfirmRevokeUserEmail] = useState<string>('')
  const [confirmCleanup, setConfirmCleanup]             = useState(false)

  // ── Query ────────────────────────────────────────────────────────────────────

  const { data, isLoading, isFetching, refetch } = useQuery<SessionsResponse>({
    queryKey: ['admin-sessions'],
    queryFn: () => apiFetch('/api/v1/admin/sessions'),
    refetchInterval: autoRefresh ? 30_000 : false,
    staleTime: 15_000,
  })

  // Re-enable interval when autoRefresh changes
  useEffect(() => {
    if (autoRefresh) {
      refetch()
    }
  }, [autoRefresh, refetch])

  const sessions = data?.sessions ?? []

  // ── Stats ─────────────────────────────────────────────────────────────────────

  const activeSessions    = sessions.filter(s => getSessionStatus(s) === 'active')
  const uniqueUsers       = new Set(sessions.map(s => s.user_id)).size
  const today             = new Date(); today.setHours(0, 0, 0, 0)
  const createdToday      = sessions.filter(s => new Date(s.created_at) >= today).length
  const revokedToday      = sessions.filter(s => s.revoked && new Date(s.last_active_at) >= today).length
  const expiredCount      = sessions.filter(s => getSessionStatus(s) === 'expired').length

  // ── Mutations ─────────────────────────────────────────────────────────────────

  const revokeSessionMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/sessions/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-sessions'] })
      setConfirmRevokeId(null)
    },
  })

  const revokeUserSessionsMutation = useMutation({
    mutationFn: (userId: string) =>
      apiFetch(`/api/v1/admin/users/${userId}/sessions`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-sessions'] })
      setConfirmRevokeUserId(null)
      setConfirmRevokeUserEmail('')
    },
  })

  const cleanupExpiredMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/sessions/cleanup', { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-sessions'] })
      setConfirmCleanup(false)
    },
  })

  // ── Filtering & Sorting ───────────────────────────────────────────────────────

  const filtered = sessions
    .filter(s => {
      const status = getSessionStatus(s)
      if (statusFilter !== 'all' && status !== statusFilter) return false
      if (searchUser) {
        const q = searchUser.toLowerCase()
        if (!s.user_email?.toLowerCase().includes(q) && !s.user_name?.toLowerCase().includes(q)) return false
      }
      if (searchIP && !s.ip_address?.includes(searchIP)) return false
      return true
    })
    .sort((a, b) => new Date(b.last_active_at).getTime() - new Date(a.last_active_at).getTime())

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <MonitorSmartphone className="w-6 h-6 text-[#e8002d]" />
            セッション管理
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">
            アクティブなユーザーセッションの監視・管理
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors ${
              autoRefresh
                ? 'bg-green-900/30 text-green-300 border-green-700/40'
                : 'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42] hover:text-white'
            }`}
          >
            {autoRefresh
              ? <ToggleRight className="w-4 h-4" />
              : <ToggleLeft  className="w-4 h-4" />
            }
            自動更新 (30s)
          </button>

          {/* Revoke All Expired */}
          <button
            onClick={() => setConfirmCleanup(true)}
            disabled={expiredCount === 0}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm border bg-yellow-900/20 text-yellow-300 border-yellow-700/40 hover:bg-yellow-900/40 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Trash2 className="w-4 h-4" />
            期限切れを削除 ({expiredCount})
          </button>

          {/* Refresh */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 text-[#7d92b0] hover:text-white transition-colors disabled:opacity-50"
            title="更新"
          >
            <RefreshCw className={`w-5 h-5 ${isFetching ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ── Stats Row ───────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-4">
        {[
          {
            label: 'アクティブセッション',
            value: activeSessions.length,
            icon: Activity,
            color: 'text-green-400',
            iconBg: 'bg-green-900/30',
          },
          {
            label: 'ユニークユーザー',
            value: uniqueUsers,
            icon: Users,
            color: 'text-blue-400',
            iconBg: 'bg-blue-900/30',
          },
          {
            label: '本日作成',
            value: createdToday,
            icon: Clock,
            color: 'text-purple-400',
            iconBg: 'bg-purple-900/30',
          },
          {
            label: '本日無効化',
            value: revokedToday,
            icon: XCircle,
            color: 'text-[#e8002d]',
            iconBg: 'bg-red-900/30',
          },
        ].map(({ label, value, icon: Icon, color, iconBg }) => (
          <div key={label} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg ${iconBg} flex items-center justify-center shrink-0`}>
              <Icon className={`w-5 h-5 ${color}`} />
            </div>
            <div>
              <p className="text-[#7d92b0] text-xs">{label}</p>
              <p className={`text-2xl font-bold mt-0.5 ${color}`}>{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* ── Filters ─────────────────────────────────────────────────────────── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center gap-3 flex-wrap">
          <Filter className="w-4 h-4 text-[#7d92b0] shrink-0" />

          {/* Filter by user (dropdown) */}
          <div className="relative">
            <select
              value={searchUser}
              onChange={e => setSearchUser(e.target.value)}
              className="appearance-none bg-[#070d19] text-white px-3 py-2 pr-8 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] cursor-pointer min-w-[180px]"
            >
              <option value="">すべてのユーザー</option>
              {Array.from(new Map(sessions.map(s => [s.user_id, s.user_email])).entries()).map(([uid, email]) => (
                <option key={uid} value={email}>{email}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0] pointer-events-none" />
          </div>

          {/* Search by IP */}
          <div className="relative flex-1 min-w-[160px]">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0]" />
            <input
              type="text"
              value={searchIP}
              onChange={e => setSearchIP(e.target.value)}
              placeholder="IPアドレスで検索..."
              className="w-full bg-[#070d19] text-white pl-9 pr-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] placeholder-[#7d92b0] font-mono"
            />
          </div>

          {/* Status filter */}
          <div className="relative">
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value as typeof statusFilter)}
              className="appearance-none bg-[#070d19] text-white px-3 py-2 pr-8 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] cursor-pointer"
            >
              <option value="all">すべてのステータス</option>
              <option value="active">アクティブ</option>
              <option value="expired">期限切れ</option>
              <option value="revoked">無効化済み</option>
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0] pointer-events-none" />
          </div>

          {/* Clear filters */}
          {(searchUser || searchIP || statusFilter !== 'all') && (
            <button
              onClick={() => { setSearchUser(''); setSearchIP(''); setStatusFilter('all') }}
              className="flex items-center gap-1.5 text-xs text-[#7d92b0] hover:text-white px-2 py-1.5 rounded-sm border border-[#1e2d42] hover:border-[#7d92b0] transition-colors"
            >
              <X className="w-3 h-3" />
              クリア
            </button>
          )}

          <span className="text-[#7d92b0] text-xs ml-auto">
            {filtered.length} / {sessions.length} 件
          </span>
        </div>
      </div>

      {/* ── Sessions Table ───────────────────────────────────────────────────── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">

        {/* Table header */}
        <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <MonitorSmartphone className="w-4 h-4 text-[#7d92b0]" />
            セッション一覧
            <span className="text-xs text-[#7d92b0] font-normal">
              最終アクティブ降順
            </span>
          </h2>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="w-8 h-8 border-2 border-[#e8002d] border-t-transparent rounded-full animate-spin" />
          </div>
        ) : filtered.length === 0 ? (
          /* ── Empty state ── */
          <div className="flex flex-col items-center justify-center h-48 text-[#7d92b0]">
            <MonitorSmartphone className="w-12 h-12 mb-3 opacity-20" />
            <p className="text-sm font-medium">
              {sessions.length === 0 ? 'セッションがありません' : 'フィルター条件に一致するセッションがありません'}
            </p>
            {sessions.length > 0 && (
              <button
                onClick={() => { setSearchUser(''); setSearchIP(''); setStatusFilter('all') }}
                className="mt-2 text-xs text-[#1a6bff] hover:underline"
              >
                フィルターをクリア
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ユーザー</th>
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">IPアドレス</th>
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ブラウザ / OS</th>
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">作成日時</th>
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">最終アクティブ</th>
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">有効期限</th>
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ステータス</th>
                  <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">操作</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(session => {
                  const status  = getSessionStatus(session)
                  const browser = parseBrowser(session.user_agent)
                  const os      = parseOS(session.user_agent)
                  const isActive = status === 'active'

                  return (
                    <tr
                      key={session.id}
                      className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#131c2e] transition-colors"
                    >
                      {/* User */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-7 h-7 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0">
                            <span className="text-[9px] font-bold text-white uppercase">
                              {(session.user_name || session.user_email || '?')[0]?.toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <p className="text-white text-xs font-medium">
                              {session.user_name || '—'}
                            </p>
                            <p className="text-[#7d92b0] text-xs font-mono">{session.user_email}</p>
                          </div>
                        </div>
                      </td>

                      {/* IP */}
                      <td className="px-4 py-3">
                        <span className="text-[#7d92b0] text-xs font-mono">{session.ip_address || '—'}</span>
                      </td>

                      {/* Browser / OS */}
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-white text-xs">{browser}</span>
                          <span className="text-[#7d92b0] text-xs">{os}</span>
                        </div>
                      </td>

                      {/* Created at */}
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                        {fmtDate(session.created_at)}
                      </td>

                      {/* Last active */}
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-0.5">
                          <span className={`text-xs font-medium ${isActive ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                            {timeAgo(session.last_active_at)}
                          </span>
                          <span className="text-[#7d92b0] text-xs">{fmtDate(session.last_active_at)}</span>
                        </div>
                      </td>

                      {/* Expires at */}
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                        {fmtDate(session.expires_at)}
                      </td>

                      {/* Status */}
                      <td className="px-4 py-3">
                        <StatusBadge status={status} />
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {/* Revoke individual session */}
                          {!session.revoked && (
                            <button
                              onClick={() => setConfirmRevokeId(session.id)}
                              className="flex items-center gap-1 text-xs px-2 py-1 rounded-sm bg-red-900/20 text-red-400 border border-red-700/30 hover:bg-red-900/40 transition-colors"
                              title="このセッションを無効化"
                            >
                              <XCircle className="w-3 h-3" />
                              無効化
                            </button>
                          )}

                          {/* Revoke all user sessions */}
                          <button
                            onClick={() => {
                              setConfirmRevokeUserId(session.user_id)
                              setConfirmRevokeUserEmail(session.user_email)
                            }}
                            className="flex items-center gap-1 text-xs px-2 py-1 rounded-sm bg-[#0d1220] text-[#7d92b0] border border-[#1e2d42] hover:bg-[#161f33] hover:text-white transition-colors"
                            title="このユーザーの全セッションを無効化"
                          >
                            <Shield className="w-3 h-3" />
                            全無効化
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

      {/* ── Confirm: Revoke single session ──────────────────────────────────── */}
      {confirmRevokeId && (
        <ConfirmModal
          title="セッションを無効化"
          message="このセッションを無効化します。ユーザーは再ログインが必要になります。"
          onConfirm={() => revokeSessionMutation.mutate(confirmRevokeId)}
          onCancel={() => setConfirmRevokeId(null)}
          isPending={revokeSessionMutation.isPending}
        />
      )}

      {/* ── Confirm: Revoke user's all sessions ─────────────────────────────── */}
      {confirmRevokeUserId && (
        <ConfirmModal
          title="ユーザーの全セッションを無効化"
          message={`${confirmRevokeUserEmail} のすべてのアクティブセッションを無効化します。\nユーザーは全デバイスで再ログインが必要になります。`}
          onConfirm={() => revokeUserSessionsMutation.mutate(confirmRevokeUserId)}
          onCancel={() => { setConfirmRevokeUserId(null); setConfirmRevokeUserEmail('') }}
          isPending={revokeUserSessionsMutation.isPending}
        />
      )}

      {/* ── Confirm: Cleanup expired sessions ───────────────────────────────── */}
      {confirmCleanup && (
        <ConfirmModal
          title="期限切れセッションを削除"
          message={`${expiredCount}件の期限切れセッションを一括削除します。この操作は元に戻せません。`}
          onConfirm={() => cleanupExpiredMutation.mutate()}
          onCancel={() => setConfirmCleanup(false)}
          isPending={cleanupExpiredMutation.isPending}
          danger={false}
        />
      )}
    </div>
  )
}
