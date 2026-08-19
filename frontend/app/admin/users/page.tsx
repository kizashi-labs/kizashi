'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Users, UserPlus, Trash2, Shield, Eye, EyeOff,
  CheckCircle, XCircle, RefreshCw, UserCheck, ChevronDown,
  Mail, Send, Clock, X, Lock, Unlock, KeyRound,
  AlertTriangle, ChevronRight, Activity, MonitorSmartphone,
  ShieldCheck, Search, SlidersHorizontal
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ──────────────────────────────────────────────────────────────────────

interface UserRow {
  id: string
  email: string
  full_name: string
  role: string
  is_active: boolean
  is_locked?: boolean
  mfa_enabled: boolean
  created_at: string
  last_login?: string
}

interface UserDetail {
  sessions_count?: number
  last_login?: string
  mfa_enabled?: boolean
  api_keys_count?: number
  recent_actions?: { action: string; at: string }[]
}

interface Invitation {
  id: string
  email: string
  role: string
  tenant_id?: string
  created_at: string
  expires_at: string
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const ROLE_STYLES: Record<string, string> = {
  admin:   'bg-red-900/40 text-red-300 border border-red-700/50',
  analyst: 'bg-blue-900/40 text-blue-300 border border-blue-700/50',
  viewer:  'bg-[#161f33] text-[#8899aa] border border-[#1e2d42]',
}

const ROLE_LABELS: Record<string, string> = {
  admin:   '管理者',
  analyst: 'アナリスト',
  viewer:  '閲覧者',
}

function fmtDate(iso?: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleDateString('ja-JP')
  } catch { return '—' }
}

function fmtDateTime(iso?: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    })
  } catch { return '—' }
}

function getInitials(name?: string, email?: string): string {
  const src = name || email || '?'
  return src[0]?.toUpperCase() ?? '?'
}

// ── User Detail Side Panel ─────────────────────────────────────────────────────

interface UserDetailPanelProps {
  user: UserRow
  onClose: () => void
}

function UserDetailPanel({ user, onClose }: UserDetailPanelProps) {
  const { data: detail, isLoading } = useQuery<UserDetail>({
    queryKey: ['admin-user-detail', user.id],
    queryFn: () => apiFetch(`/api/v1/admin/users/${user.id}/detail`),
    staleTime: 30_000,
  })

  return (
    <div className="fixed inset-0 z-40 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      {/* Panel */}
      <div className="w-96 bg-[#0d1220] border-l border-[#1e2d42] flex flex-col overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">ユーザー詳細</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Avatar + name */}
        <div className="px-5 py-5 border-b border-[#1e2d42] flex items-center gap-4">
          <div className="w-14 h-14 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0 text-xl font-bold text-white">
            {getInitials(user.full_name, user.email)}
          </div>
          <div className="min-w-0">
            <p className="text-white font-semibold truncate">{user.full_name || '—'}</p>
            <p className="text-[#7d92b0] text-sm font-mono truncate">{user.email}</p>
            <div className="flex items-center gap-2 mt-1.5">
              <span className={`text-xs px-2 py-0.5 rounded-full ${ROLE_STYLES[user.role] ?? ROLE_STYLES.viewer}`}>
                {ROLE_LABELS[user.role] ?? user.role}
              </span>
              {user.is_locked && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-orange-900/40 text-orange-300 border border-orange-700/50">
                  ロック中
                </span>
              )}
              {!user.is_active && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-red-900/40 text-red-300 border border-red-700/50">
                  無効
                </span>
              )}
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-6 h-6 border-2 border-[#e8002d] border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          <div className="px-5 py-4 space-y-4">
            {/* Stats grid */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'セッション数',   value: detail?.sessions_count ?? 0,  icon: MonitorSmartphone, color: 'text-blue-400' },
                { label: 'APIキー',        value: detail?.api_keys_count  ?? 0,  icon: KeyRound,          color: 'text-purple-400' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
                  <div className="flex items-center gap-2 mb-1">
                    <Icon className={`w-3.5 h-3.5 ${color}`} />
                    <span className="text-[#7d92b0] text-xs">{label}</span>
                  </div>
                  <p className={`text-xl font-bold ${color}`}>{value}</p>
                </div>
              ))}
            </div>

            {/* Info rows */}
            <div className="space-y-2">
              {[
                { label: '最終ログイン',   value: fmtDateTime(detail?.last_login ?? user.last_login) },
                { label: 'アカウント作成', value: fmtDateTime(user.created_at) },
                { label: 'MFA',           value: (detail?.mfa_enabled ?? user.mfa_enabled) ? '有効' : '無効' },
              ].map(({ label, value }) => (
                <div key={label} className="flex items-center justify-between py-2 border-b border-[#1e2d42]/50 last:border-0">
                  <span className="text-[#7d92b0] text-xs">{label}</span>
                  <span className="text-white text-xs font-medium">{value}</span>
                </div>
              ))}
            </div>

            {/* Recent actions */}
            {detail?.recent_actions && detail.recent_actions.length > 0 && (
              <div>
                <p className="text-[#7d92b0] text-xs font-medium mb-2 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  最近の操作
                </p>
                <div className="space-y-1.5">
                  {detail.recent_actions.slice(0, 5).map((a, i) => (
                    <div key={i} className="flex items-start gap-2 bg-[#070d19] rounded-sm px-2.5 py-1.5">
                      <span className="text-white text-xs flex-1">{a.action}</span>
                      <span className="text-[#7d92b0] text-xs whitespace-nowrap">{fmtDateTime(a.at)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function AdminUsersPage() {
  const qc = useQueryClient()

  // Modal/panel visibility
  const [showCreate, setShowCreate]       = useState(false)
  const [showInvite, setShowInvite]       = useState(false)
  const [showInvitations, setShowInvitations] = useState(false)
  const [detailUser, setDetailUser]       = useState<UserRow | null>(null)

  // Form state
  const [form, setForm]             = useState({ email: '', password: '', full_name: '', role: 'analyst' })
  const [inviteForm, setInviteForm] = useState({ email: '', role: 'analyst', tenant_id: '' })
  const [inviteSent, setInviteSent] = useState<string | null>(null)
  const [showPw, setShowPw]         = useState(false)

  // Row-level UI state
  const [confirmDeactivate, setConfirmDeactivate] = useState<string | null>(null)
  const [editingRoleId, setEditingRoleId]         = useState<string | null>(null)
  const [confirmForceReset, setConfirmForceReset] = useState<string | null>(null)

  // Bulk selection
  const [selectedIds, setSelectedIds]   = useState<Set<string>>(new Set())
  const [bulkRole, setBulkRole]         = useState('analyst')
  const [confirmBulkRole, setConfirmBulkRole] = useState(false)

  // Search/filter
  const [searchQ, setSearchQ]           = useState('')
  const [roleFilter, setRoleFilter]     = useState('all')

  // ── Queries ───────────────────────────────────────────────────────────────────

  const { data, isLoading, refetch, isFetching } = useQuery<{ data: UserRow[]; total: number }>({
    queryKey: ['admin-users'],
    queryFn: () => apiFetch('/api/v1/users'),
  })

  const { data: invitationsData, refetch: refetchInvitations } = useQuery<{ data: Invitation[]; total: number }>({
    queryKey: ['admin-invitations'],
    queryFn: () => apiFetch('/api/v1/admin/invitations'),
    enabled: showInvitations,
  })

  const allUsers = data?.data ?? []
  const invitations = invitationsData?.data ?? []

  // Filtered list
  const users = useMemo(() => {
    return allUsers.filter(u => {
      if (roleFilter !== 'all' && u.role !== roleFilter) return false
      if (searchQ) {
        const q = searchQ.toLowerCase()
        if (!u.email.toLowerCase().includes(q) && !u.full_name?.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [allUsers, searchQ, roleFilter])

  // ── Mutations ─────────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (payload: typeof form) =>
      apiFetch('/api/v1/users', { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-users'] })
      setShowCreate(false)
      setForm({ email: '', password: '', full_name: '', role: 'analyst' })
    },
  })

  const inviteMutation = useMutation({
    mutationFn: (payload: typeof inviteForm) =>
      apiFetch<{ invite_url?: string; email?: string }>('/api/v1/admin/invitations', { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: (res: { invite_url?: string; email?: string }) => {
      qc.invalidateQueries({ queryKey: ['admin-invitations'] })
      setInviteSent(res.invite_url ?? null)
    },
  })

  const revokeInviteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/invitations/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-invitations'] }),
  })

  const deactivateMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/users/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-users'] })
      setConfirmDeactivate(null)
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      apiFetch(`/api/v1/users/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-users'] })
      setEditingRoleId(null)
    },
  })

  // Lock / Unlock account
  const lockMutation = useMutation({
    mutationFn: ({ id, lock }: { id: string; lock: boolean }) =>
      apiFetch(`/api/v1/admin/users/${id}/lock`, { method: 'PUT', body: JSON.stringify({ locked: lock }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-users'] }),
  })

  // Force password reset
  const forceResetMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/users/${id}/force-reset`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-users'] })
      setConfirmForceReset(null)
    },
  })

  // Bulk role change
  const bulkRoleMutation = useMutation({
    mutationFn: ({ ids, role }: { ids: string[]; role: string }) =>
      Promise.all(
        ids.map(id => apiFetch(`/api/v1/users/${id}`, { method: 'PUT', body: JSON.stringify({ role }) }))
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-users'] })
      setSelectedIds(new Set())
      setConfirmBulkRole(false)
    },
  })

  // ── Selection helpers ─────────────────────────────────────────────────────────

  const allSelected = users.length > 0 && users.every(u => selectedIds.has(u.id))
  const someSelected = selectedIds.size > 0

  function toggleSelect(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(users.map(u => u.id)))
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Users className="w-6 h-6 text-blue-400" />
            ユーザー管理
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">
            アカウントの作成・管理（管理者専用）
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => { setShowInvitations(v => !v); refetchInvitations() }}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors text-sm border
              ${showInvitations
                ? 'bg-purple-900/40 text-purple-300 border-purple-700/50'
                : 'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42] hover:text-white'}`}
          >
            <Clock className="w-4 h-4" />
            招待一覧
          </button>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 text-[#7d92b0] hover:text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-5 h-5 ${isFetching ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => { setShowInvite(true); setInviteSent(null) }}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm"
          >
            <Mail className="w-4 h-4" />
            ユーザーを招待
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors text-sm"
          >
            <UserPlus className="w-4 h-4" />
            ユーザー追加
          </button>
        </div>
      </div>

      {/* ── Stats ───────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: '総ユーザー数',       value: allUsers.length,                                    color: 'text-white' },
          { label: 'アクティブ',         value: allUsers.filter(u => u.is_active).length,           color: 'text-green-400' },
          { label: 'MFA有効',            value: allUsers.filter(u => u.mfa_enabled).length,         color: 'text-blue-400' },
          { label: 'ロック中',           value: allUsers.filter(u => u.is_locked).length,           color: 'text-orange-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
            <p className="text-[#7d92b0] text-xs">{label}</p>
            <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* ── Filters & Bulk Actions bar ──────────────────────────────────────── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0]" />
            <input
              type="text"
              value={searchQ}
              onChange={e => setSearchQ(e.target.value)}
              placeholder="名前またはメールで検索..."
              className="w-full bg-[#070d19] text-white pl-9 pr-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] placeholder-[#7d92b0]"
            />
          </div>

          {/* Role filter */}
          <div className="relative">
            <select
              value={roleFilter}
              onChange={e => setRoleFilter(e.target.value)}
              className="appearance-none bg-[#070d19] text-white px-3 py-2 pr-8 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] cursor-pointer"
            >
              <option value="all">すべてのロール</option>
              <option value="admin">管理者</option>
              <option value="analyst">アナリスト</option>
              <option value="viewer">閲覧者</option>
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0] pointer-events-none" />
          </div>

          {/* Bulk role change */}
          {someSelected && (
            <div className="flex items-center gap-2 ml-auto">
              <span className="text-[#7d92b0] text-xs">{selectedIds.size}件選択中</span>
              <div className="relative">
                <select
                  value={bulkRole}
                  onChange={e => setBulkRole(e.target.value)}
                  className="appearance-none bg-[#070d19] text-white px-3 py-2 pr-8 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
                >
                  <option value="viewer">閲覧者</option>
                  <option value="analyst">アナリスト</option>
                  <option value="admin">管理者</option>
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0] pointer-events-none" />
              </div>
              <button
                onClick={() => setConfirmBulkRole(true)}
                className="flex items-center gap-1.5 px-3 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors text-sm"
              >
                <SlidersHorizontal className="w-3.5 h-3.5" />
                一括ロール変更
              </button>
              <button
                onClick={() => setSelectedIds(new Set())}
                className="text-[#7d92b0] hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {!someSelected && (
            <span className="text-[#7d92b0] text-xs ml-auto">{users.length} 件</span>
          )}
        </div>
      </div>

      {/* ── Pending Invitations Panel ────────────────────────────────────────── */}
      {showInvitations && (
        <div className="bg-[#0d1220] rounded-xl border border-purple-700/30 overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-purple-400" />
              保留中の招待
            </h2>
            <span className="text-xs text-[#7d92b0]">{invitations.length}件</span>
          </div>
          {invitations.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-20 text-[#7d92b0]">
              <p className="text-sm">保留中の招待はありません</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] bg-[#070d19]/30">
                  <th className="text-left px-4 py-2 text-[#7d92b0] text-xs font-medium">メールアドレス</th>
                  <th className="text-left px-4 py-2 text-[#7d92b0] text-xs font-medium">ロール</th>
                  <th className="text-left px-4 py-2 text-[#7d92b0] text-xs font-medium">送信日時</th>
                  <th className="text-left px-4 py-2 text-[#7d92b0] text-xs font-medium">有効期限</th>
                  <th className="text-left px-4 py-2 text-[#7d92b0] text-xs font-medium">操作</th>
                </tr>
              </thead>
              <tbody>
                {invitations.map(inv => (
                  <tr key={inv.id} className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#131c2e] transition-colors">
                    <td className="px-4 py-2 text-white text-sm font-mono">{inv.email}</td>
                    <td className="px-4 py-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${ROLE_STYLES[inv.role] ?? ROLE_STYLES.viewer}`}>
                        {ROLE_LABELS[inv.role] ?? inv.role}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-[#7d92b0] text-xs">{fmtDate(inv.created_at)}</td>
                    <td className="px-4 py-2 text-[#7d92b0] text-xs">{fmtDate(inv.expires_at)}</td>
                    <td className="px-4 py-2">
                      <button
                        onClick={() => revokeInviteMutation.mutate(inv.id)}
                        disabled={revokeInviteMutation.isPending}
                        className="text-[#7d92b0] hover:text-[#e8002d] transition-colors disabled:opacity-50"
                        title="招待を取り消す"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── User Table ───────────────────────────────────────────────────────── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : users.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-[#7d92b0]">
            <Users className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">
              {allUsers.length === 0 ? 'ユーザーがいません' : 'フィルター条件に一致するユーザーがいません'}
            </p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/30">
                {/* Checkbox */}
                <th className="px-4 py-3 w-10">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleSelectAll}
                    className="w-3.5 h-3.5 accent-[#1a6bff] cursor-pointer"
                  />
                </th>
                <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ユーザー</th>
                <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ロール</th>
                <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ステータス</th>
                <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">MFA</th>
                <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">最終ログイン</th>
                <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">作成日</th>
                <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              {users.map(user => (
                <tr
                  key={user.id}
                  className={`border-b border-[#1e2d42]/50 last:border-0 transition-colors cursor-pointer
                    ${selectedIds.has(user.id) ? 'bg-[#0d1f35]' : 'hover:bg-[#131c2e]'}`}
                  onClick={() => setDetailUser(user)}
                >
                  {/* Checkbox */}
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(user.id)}
                      onChange={() => toggleSelect(user.id)}
                      className="w-3.5 h-3.5 accent-[#1a6bff] cursor-pointer"
                    />
                  </td>

                  {/* User name + email + avatar */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0 text-xs font-bold text-white">
                        {getInitials(user.full_name, user.email)}
                      </div>
                      <div>
                        <p className="text-white font-medium text-sm">{user.full_name || '—'}</p>
                        <p className="text-[#7d92b0] text-xs font-mono">{user.email}</p>
                      </div>
                    </div>
                  </td>

                  {/* Role */}
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    {editingRoleId === user.id ? (
                      <select
                        defaultValue={user.role}
                        autoFocus
                        onChange={e => updateMutation.mutate({ id: user.id, payload: { role: e.target.value } })}
                        onBlur={() => setEditingRoleId(null)}
                        className="text-xs bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-0.5 text-[#7d92b0] focus:outline-hidden focus:border-[#1a6bff]"
                      >
                        <option value="viewer">閲覧者</option>
                        <option value="analyst">アナリスト</option>
                        <option value="admin">管理者</option>
                      </select>
                    ) : (
                      <button
                        onClick={() => setEditingRoleId(user.id)}
                        className={`text-xs px-2 py-0.5 rounded-full flex items-center gap-1 ${ROLE_STYLES[user.role] ?? ROLE_STYLES.viewer}`}
                        title="クリックしてロールを変更"
                      >
                        {ROLE_LABELS[user.role] ?? user.role}
                        <ChevronDown className="w-2.5 h-2.5 opacity-60" />
                      </button>
                    )}
                  </td>

                  {/* Status */}
                  <td className="px-4 py-3">
                    <div className="flex flex-col gap-0.5">
                      <div className="flex items-center gap-1.5">
                        {user.is_active
                          ? <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                          : <XCircle    className="w-3.5 h-3.5 text-[#e8002d]" />
                        }
                        <span className={`text-xs ${user.is_active ? 'text-green-400' : 'text-[#e8002d]'}`}>
                          {user.is_active ? 'アクティブ' : '無効'}
                        </span>
                      </div>
                      {user.is_locked && (
                        <div className="flex items-center gap-1.5">
                          <Lock className="w-3 h-3 text-orange-400" />
                          <span className="text-xs text-orange-400">ロック中</span>
                        </div>
                      )}
                    </div>
                  </td>

                  {/* MFA */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <ShieldCheck className={`w-3.5 h-3.5 ${user.mfa_enabled ? 'text-green-400' : 'text-[#3d5068]'}`} />
                      <span className={`text-xs ${user.mfa_enabled ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                        {user.mfa_enabled ? '有効' : '無効'}
                      </span>
                    </div>
                  </td>

                  {/* Last login */}
                  <td className="px-4 py-3 text-[#7d92b0] text-xs">
                    {fmtDate(user.last_login)}
                  </td>

                  {/* Created at */}
                  <td className="px-4 py-3 text-[#7d92b0] text-xs">
                    {fmtDate(user.created_at)}
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1.5 flex-wrap">

                      {/* Lock / Unlock */}
                      {user.role !== 'admin' && (
                        <button
                          onClick={() => lockMutation.mutate({ id: user.id, lock: !user.is_locked })}
                          disabled={lockMutation.isPending}
                          className={`flex items-center gap-1 text-xs px-2 py-1 rounded-sm border transition-colors disabled:opacity-50
                            ${user.is_locked
                              ? 'bg-orange-900/20 text-orange-300 border-orange-700/40 hover:bg-orange-900/40'
                              : 'bg-[#0d1220] text-[#7d92b0] border-[#1e2d42] hover:text-orange-300 hover:border-orange-700/40'
                            }`}
                          title={user.is_locked ? 'ロック解除' : 'アカウントをロック'}
                        >
                          {user.is_locked
                            ? <Unlock className="w-3 h-3" />
                            : <Lock   className="w-3 h-3" />
                          }
                          {user.is_locked ? '解除' : 'ロック'}
                        </button>
                      )}

                      {/* Force password reset */}
                      <button
                        onClick={() => setConfirmForceReset(user.id)}
                        className="flex items-center gap-1 text-xs px-2 py-1 rounded-sm border bg-[#0d1220] text-[#7d92b0] border-[#1e2d42] hover:text-yellow-300 hover:border-yellow-700/40 transition-colors"
                        title="パスワードリセットを強制"
                      >
                        <KeyRound className="w-3 h-3" />
                        PW強制
                      </button>

                      {/* Detail arrow */}
                      <button
                        onClick={() => setDetailUser(user)}
                        className="p-1 text-[#7d92b0] hover:text-white transition-colors"
                        title="詳細を表示"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>

                      {/* Activate / Deactivate */}
                      {user.is_active ? (
                        user.role !== 'admin' && (
                          confirmDeactivate === user.id ? (
                            <div className="flex items-center gap-1.5">
                              <button
                                onClick={() => deactivateMutation.mutate(user.id)}
                                disabled={deactivateMutation.isPending}
                                className="text-xs text-red-300 bg-red-900/40 px-2 py-1 rounded-sm hover:bg-red-900/60 transition-colors disabled:opacity-50"
                              >
                                確認
                              </button>
                              <button
                                onClick={() => setConfirmDeactivate(null)}
                                className="text-xs text-[#7d92b0] hover:text-white transition-colors"
                              >
                                <X className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          ) : (
                            <button
                              onClick={() => setConfirmDeactivate(user.id)}
                              className="text-[#7d92b0] hover:text-[#e8002d] transition-colors"
                              title="無効化"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )
                        )
                      ) : (
                        <button
                          onClick={() => updateMutation.mutate({ id: user.id, payload: { is_active: true } })}
                          disabled={updateMutation.isPending}
                          className="flex items-center gap-1 text-xs text-green-300 bg-green-900/30 px-2 py-1 rounded-sm hover:bg-green-900/50 transition-colors disabled:opacity-50"
                          title="アカウントを再有効化"
                        >
                          <UserCheck className="w-3 h-3" />
                          有効化
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Confirm: Force Password Reset ───────────────────────────────────── */}
      {confirmForceReset && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#0d1220] rounded-2xl p-6 w-full max-w-md border border-[#1e2d42] shadow-2xl">
            <div className="flex items-start gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-yellow-900/40 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-5 h-5 text-yellow-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold text-lg">パスワードリセットを強制</h3>
                <p className="text-[#7d92b0] text-sm mt-1">
                  このユーザーは次回ログイン時にパスワードの変更が必須になります。
                </p>
              </div>
            </div>
            <div className="flex gap-3 justify-end mt-6">
              <button
                onClick={() => setConfirmForceReset(null)}
                className="px-4 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] transition-colors text-sm"
              >
                キャンセル
              </button>
              <button
                onClick={() => forceResetMutation.mutate(confirmForceReset)}
                disabled={forceResetMutation.isPending}
                className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700 transition-colors text-sm disabled:opacity-50 flex items-center gap-2"
              >
                {forceResetMutation.isPending && (
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                )}
                強制リセット
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Confirm: Bulk Role Change ────────────────────────────────────────── */}
      {confirmBulkRole && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#0d1220] rounded-2xl p-6 w-full max-w-md border border-[#1e2d42] shadow-2xl">
            <div className="flex items-start gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-blue-900/40 flex items-center justify-center shrink-0">
                <SlidersHorizontal className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold text-lg">一括ロール変更</h3>
                <p className="text-[#7d92b0] text-sm mt-1">
                  {selectedIds.size}件のユーザーのロールを
                  <span className="text-white font-medium mx-1">{ROLE_LABELS[bulkRole] ?? bulkRole}</span>
                  に変更します。
                </p>
              </div>
            </div>
            <div className="flex gap-3 justify-end mt-6">
              <button
                onClick={() => setConfirmBulkRole(false)}
                className="px-4 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] transition-colors text-sm"
              >
                キャンセル
              </button>
              <button
                onClick={() => bulkRoleMutation.mutate({ ids: Array.from(selectedIds), role: bulkRole })}
                disabled={bulkRoleMutation.isPending}
                className="px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors text-sm disabled:opacity-50 flex items-center gap-2"
              >
                {bulkRoleMutation.isPending && (
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                )}
                変更を適用
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Invite User Modal ────────────────────────────────────────────────── */}
      {showInvite && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#0d1220] rounded-2xl p-6 w-full max-w-md border border-[#1e2d42]">
            <h2 className="text-xl font-bold text-white mb-5 flex items-center gap-2">
              <Mail className="w-5 h-5 text-purple-400" />
              ユーザーを招待
            </h2>

            {inviteSent ? (
              <div className="space-y-4">
                <div className="bg-green-900/20 border border-green-700/30 rounded-xl p-4">
                  <p className="text-green-400 text-sm font-medium mb-2 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    招待を送信しました
                  </p>
                  <p className="text-[#7d92b0] text-xs mb-2">
                    SMTPが未設定の場合、以下のURLを共有してください:
                  </p>
                  <input
                    readOnly
                    value={inviteSent}
                    onClick={e => (e.target as HTMLInputElement).select()}
                    className="w-full bg-[#070d19] text-[#7d92b0] px-3 py-2 rounded-lg border border-[#1e2d42] text-xs font-mono focus:outline-hidden cursor-pointer"
                  />
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => { setInviteSent(null); setInviteForm({ email: '', role: 'analyst', tenant_id: '' }) }}
                    className="flex-1 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm"
                  >
                    別のユーザーを招待
                  </button>
                  <button
                    onClick={() => { setShowInvite(false); setInviteSent(null) }}
                    className="px-4 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] transition-colors text-sm"
                  >
                    閉じる
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="text-[#7d92b0] text-sm block mb-1">
                    メールアドレス <span className="text-[#e8002d]">*</span>
                  </label>
                  <input
                    type="email"
                    value={inviteForm.email}
                    onChange={e => setInviteForm(f => ({ ...f, email: e.target.value }))}
                    placeholder="user@example.com"
                    className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
                  />
                </div>
                <div>
                  <label className="text-[#7d92b0] text-sm block mb-1">ロール</label>
                  <select
                    value={inviteForm.role}
                    onChange={e => setInviteForm(f => ({ ...f, role: e.target.value }))}
                    className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
                  >
                    <option value="viewer">閲覧者 (viewer)</option>
                    <option value="analyst">アナリスト (analyst)</option>
                    <option value="admin">管理者 (admin)</option>
                  </select>
                </div>
                <div>
                  <label className="text-[#7d92b0] text-sm block mb-1">テナントID（任意）</label>
                  <input
                    value={inviteForm.tenant_id}
                    onChange={e => setInviteForm(f => ({ ...f, tenant_id: e.target.value }))}
                    placeholder="UUID（省略可）"
                    className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff] font-mono"
                  />
                </div>
                {inviteMutation.isError && (
                  <p className="text-[#e8002d] text-sm">
                    {(inviteMutation.error as Error)?.message ?? '招待の送信に失敗しました'}
                  </p>
                )}
                <div className="flex gap-3 pt-1">
                  <button
                    onClick={() => inviteMutation.mutate(inviteForm)}
                    disabled={inviteMutation.isPending || !inviteForm.email}
                    className="flex-1 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 text-sm"
                  >
                    {inviteMutation.isPending
                      ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      : <Send className="w-4 h-4" />
                    }
                    招待を送信
                  </button>
                  <button
                    onClick={() => setShowInvite(false)}
                    className="px-4 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] transition-colors text-sm"
                  >
                    キャンセル
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Create User Modal ────────────────────────────────────────────────── */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#0d1220] rounded-2xl p-6 w-full max-w-md border border-[#1e2d42]">
            <h2 className="text-xl font-bold text-white mb-5 flex items-center gap-2">
              <UserPlus className="w-5 h-5 text-blue-400" />
              ユーザー追加
            </h2>
            <div className="space-y-4">
              <div>
                <label className="text-[#7d92b0] text-sm block mb-1">氏名</label>
                <input
                  value={form.full_name}
                  onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))}
                  placeholder="田中 太郎"
                  className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
                />
              </div>
              <div>
                <label className="text-[#7d92b0] text-sm block mb-1">
                  メールアドレス <span className="text-[#e8002d]">*</span>
                </label>
                <input
                  type="email"
                  value={form.email}
                  onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                  placeholder="user@example.com"
                  className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
                />
              </div>
              <div>
                <label className="text-[#7d92b0] text-sm block mb-1">
                  パスワード <span className="text-[#e8002d]">*</span>
                </label>
                <div className="relative">
                  <input
                    type={showPw ? 'text' : 'password'}
                    value={form.password}
                    onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                    placeholder="8文字以上"
                    className="w-full bg-[#070d19] text-white px-3 py-2 pr-10 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[#7d92b0] hover:text-white"
                  >
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="text-[#7d92b0] text-sm block mb-1">ロール</label>
                <select
                  value={form.role}
                  onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                  className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
                >
                  <option value="viewer">閲覧者 (viewer)</option>
                  <option value="analyst">アナリスト (analyst)</option>
                  <option value="admin">管理者 (admin)</option>
                </select>
              </div>
              {createMutation.isError && (
                <p className="text-[#e8002d] text-sm">
                  {(createMutation.error as Error)?.message ?? '作成に失敗しました'}
                </p>
              )}
              <div className="flex gap-3 pt-1">
                <button
                  onClick={() => createMutation.mutate(form)}
                  disabled={createMutation.isPending || !form.email || !form.password}
                  className="flex-1 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors disabled:opacity-50 flex items-center justify-center gap-2 text-sm"
                >
                  {createMutation.isPending
                    ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    : <Shield className="w-4 h-4" />
                  }
                  作成
                </button>
                <button
                  onClick={() => setShowCreate(false)}
                  className="px-4 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] transition-colors text-sm"
                >
                  キャンセル
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── User Detail Side Panel ───────────────────────────────────────────── */}
      {detailUser && (
        <UserDetailPanel
          user={detailUser}
          onClose={() => setDetailUser(null)}
        />
      )}
    </div>
  )
}
