'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ShieldCheck, Users, ShieldOff, Clock, Search, Filter,
  RefreshCw, RotateCcw, ShieldAlert, X, CheckSquare, Square,
  AlertTriangle, Mail, Save, ChevronDown,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ──────────────────────────────────────────────────────────────────────

interface MfaUser {
  id: string
  username: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  mfa_status: 'enabled' | 'disabled' | 'pending'
  mfa_method: 'TOTP' | 'SMS' | 'Email' | 'none'
  last_mfa_used?: string
}

interface MfaSettings {
  mfa_required: boolean
  required_roles: string[]
  grace_period_days: number
  allowed_methods: string[]
  backup_codes_enabled: boolean
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const ROLE_STYLES: Record<string, string> = {
  admin:   'bg-red-900/40 text-red-300 border border-red-700/50',
  analyst: 'bg-blue-900/40 text-blue-300 border border-blue-700/50',
  viewer:  'bg-[#161f33] text-[#8899aa] border border-[#1e2d42]',
}
const ROLE_LABELS: Record<string, string> = {
  admin: '管理者', analyst: 'アナリスト', viewer: '閲覧者',
}

const MFA_STATUS_STYLES: Record<string, string> = {
  enabled:  'bg-green-900/40 text-green-300 border border-green-700/50',
  disabled: 'bg-red-900/40 text-red-300 border border-red-700/50',
  pending:  'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',
}
const MFA_STATUS_LABELS: Record<string, string> = {
  enabled: '有効', disabled: '無効', pending: '保留中',
}

function fmtDateTime(iso?: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return '—' }
}

// ── Pie Chart (SVG) ────────────────────────────────────────────────────────────

function MfaMethodPieChart({ users }: { users: MfaUser[] }) {
  const totp  = users.filter(u => u.mfa_method === 'TOTP').length
  const email = users.filter(u => u.mfa_method === 'Email').length
  const none  = users.filter(u => u.mfa_method === 'none').length
  const total = users.length || 1

  const segments = [
    { label: 'TOTP', value: totp, color: '#3b82f6' },
    { label: 'Email', value: email, color: '#8b5cf6' },
    { label: 'なし', value: none, color: '#e8002d' },
  ]

  const cx = 80, cy = 80, r = 60
  let startAngle = -Math.PI / 2
  const paths: { d: string; color: string; label: string; value: number }[] = []

  for (const seg of segments) {
    if (seg.value === 0) continue
    const angle = (seg.value / total) * 2 * Math.PI
    const endAngle = startAngle + angle
    const x1 = cx + r * Math.cos(startAngle)
    const y1 = cy + r * Math.sin(startAngle)
    const x2 = cx + r * Math.cos(endAngle)
    const y2 = cy + r * Math.sin(endAngle)
    const largeArc = angle > Math.PI ? 1 : 0
    paths.push({
      d: `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2} Z`,
      color: seg.color,
      label: seg.label,
      value: seg.value,
    })
    startAngle = endAngle
  }

  return (
    <div className="flex items-center gap-6">
      <svg width="160" height="160" viewBox="0 0 160 160">
        {paths.map((p, i) => (
          <path key={i} d={p.d} fill={p.color} opacity="0.85" />
        ))}
        <circle cx={cx} cy={cy} r="30" fill="#0d1220" />
        <text x={cx} y={cy + 4} textAnchor="middle" fontSize="12" fill="#e2e8f4" fontWeight="600">
          {total}
        </text>
        <text x={cx} y={cy + 16} textAnchor="middle" fontSize="8" fill="#7d92b0">
          ユーザー
        </text>
      </svg>
      <div className="space-y-2">
        {segments.map(s => (
          <div key={s.label} className="flex items-center gap-2 text-sm">
            <span className="w-3 h-3 rounded-xs shrink-0" style={{ background: s.color }} />
            <span className="text-[#7d92b0]">{s.label}</span>
            <span className="text-[#e2e8f4] font-semibold ml-1">{s.value}</span>
            <span className="text-[#3d5068] text-xs">({Math.round(s.value / total * 100)}%)</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Confirmation Modal ─────────────────────────────────────────────────────────

function ConfirmModal({
  title, message, onConfirm, onCancel, requireReason,
}: {
  title: string
  message: string
  onConfirm: (reason?: string) => void
  onCancel: () => void
  requireReason?: boolean
}) {
  const [reason, setReason] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 w-[420px] shadow-2xl">
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-[#e2e8f4] font-semibold">{title}</h3>
            <p className="text-[#7d92b0] text-sm mt-1">{message}</p>
          </div>
        </div>
        {requireReason && (
          <div className="mb-4">
            <label className="block text-xs text-[#7d92b0] mb-1">理由 (任意)</label>
            <textarea
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] resize-none focus:outline-hidden focus:border-[#1a6bff]"
              rows={2}
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="無効化の理由を入力..."
            />
          </div>
        )}
        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-sm text-sm text-[#7d92b0] border border-[#1e2d42] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onConfirm(reason || undefined)}
            className="px-4 py-2 rounded-sm text-sm bg-[#e8002d] text-white hover:bg-[#c8001d] transition-colors font-medium"
          >
            確認
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function MfaManagementPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'users' | 'settings'>('users')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [confirmAction, setConfirmAction] = useState<{
    type: 'reset' | 'force' | 'disable'
    userId: string
    username: string
  } | null>(null)
  const [bulkConfirm, setBulkConfirm] = useState(false)
  const [settingsSaved, setSettingsSaved] = useState(false)

  // MFA settings state
  const [mfaRequired, setMfaRequired] = useState(false)
  const [requiredRoles, setRequiredRoles] = useState<string[]>([])
  const [gracePeriod, setGracePeriod] = useState(0)
  const [allowedMethods, setAllowedMethods] = useState<string[]>([])
  const [backupCodes, setBackupCodes] = useState(false)

  // Fetch users
  const { data: usersData, isLoading } = useQuery<MfaUser[]>({
    queryKey: ['mfa-users'],
    queryFn: async () => {
      try {
        const res = await apiFetch<{ data?: any[]; users?: any[] } | any[]>('/api/v1/users')
        const raw: any[] = Array.isArray(res) ? res : ((res as any).data ?? (res as any).users ?? [])
        return raw.map((u: any): MfaUser => ({
          id: u.id,
          username: u.full_name || u.username || u.email,
          email: u.email,
          role: u.role ?? 'viewer',
          mfa_status: u.mfa_enabled ? 'enabled' : 'disabled',
          mfa_method: u.mfa_enabled ? 'TOTP' : 'none',
          last_mfa_used: u.mfa_enabled ? (u.last_mfa_used ?? u.last_login ?? undefined) : undefined,
        }))
      } catch { return [] }
    },
  })
  const users = usersData ?? []

  // Mutations
  const resetMutation = useMutation({
    mutationFn: (userId: string) =>
      apiFetch(`/api/v1/users/${userId}/mfa/reset`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mfa-users'] }),
  })
  const disableMutation = useMutation({
    mutationFn: ({ userId, reason }: { userId: string; reason?: string }) =>
      apiFetch(`/api/v1/users/${userId}/mfa/disable`, {
        method: 'POST',
        body: JSON.stringify({ reason }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['mfa-users'] }),
  })
  const settingsMutation = useMutation({
    mutationFn: (settings: MfaSettings) =>
      apiFetch('/api/v1/admin/mfa-settings', {
        method: 'PUT',
        body: JSON.stringify(settings),
      }),
    onSuccess: () => { setSettingsSaved(true); setTimeout(() => setSettingsSaved(false), 2000) },
  })

  // Stats
  const stats = useMemo(() => {
    const total    = users.length
    const enabled  = users.filter(u => u.mfa_status === 'enabled').length
    const disabled = users.filter(u => u.mfa_status === 'disabled').length
    const pending  = users.filter(u => u.mfa_status === 'pending').length
    return { total, enabled, disabled, pending }
  }, [users])

  // Filtered users
  const filtered = useMemo(() => {
    return users.filter(u => {
      if (statusFilter !== 'all' && u.mfa_status !== statusFilter) return false
      if (roleFilter !== 'all' && u.role !== roleFilter) return false
      if (search) {
        const q = search.toLowerCase()
        if (!u.username.toLowerCase().includes(q) && !u.email.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [users, statusFilter, roleFilter, search])

  const allSelected = filtered.length > 0 && filtered.every(u => selected.has(u.id))

  function toggleSelect(id: string) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }
  function toggleAll() {
    if (allSelected) setSelected(new Set())
    else setSelected(new Set(filtered.map(u => u.id)))
  }

  function handleConfirm(reason?: string) {
    if (!confirmAction) return
    if (confirmAction.type === 'reset') {
      resetMutation.mutate(confirmAction.userId)
    } else if (confirmAction.type === 'disable') {
      disableMutation.mutate({ userId: confirmAction.userId, reason })
    } else {
      // force enable → mock: mark pending, send email
    }
    setConfirmAction(null)
  }

  function handleBulkForce() {
    // Mock bulk force enrollment
    setBulkConfirm(false)
    setSelected(new Set())
  }

  function handleSaveSettings() {
    settingsMutation.mutate({
      mfa_required: mfaRequired,
      required_roles: requiredRoles,
      grace_period_days: gracePeriod,
      allowed_methods: allowedMethods,
      backup_codes_enabled: backupCodes,
    })
  }

  function toggleRole(role: string) {
    setRequiredRoles(prev => prev.includes(role) ? prev.filter(r => r !== role) : [...prev, role])
  }
  function toggleMethod(method: string) {
    setAllowedMethods(prev => prev.includes(method) ? prev.filter(m => m !== method) : [...prev, method])
  }

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed />
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e2e8f4]">MFA登録管理</h1>
        <p className="text-[#7d92b0] text-sm mt-1">ユーザーの多要素認証登録状況の管理・強制設定</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Users className="w-4 h-4 text-[#7d92b0]" />
            <span className="text-xs text-[#7d92b0] uppercase tracking-wide">総ユーザー数</span>
          </div>
          <p className="text-3xl font-bold text-[#e2e8f4]">{stats.total}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <ShieldCheck className="w-4 h-4 text-green-400" />
            <span className="text-xs text-[#7d92b0] uppercase tracking-wide">MFA有効</span>
          </div>
          <p className="text-3xl font-bold text-green-400">{stats.enabled}</p>
          <p className="text-xs text-[#7d92b0] mt-1">
            {stats.total ? Math.round(stats.enabled / stats.total * 100) : 0}%
          </p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <ShieldOff className="w-4 h-4 text-red-400" />
            <span className="text-xs text-[#7d92b0] uppercase tracking-wide">MFA無効</span>
          </div>
          <p className="text-3xl font-bold text-red-400">{stats.disabled}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Clock className="w-4 h-4 text-yellow-400" />
            <span className="text-xs text-[#7d92b0] uppercase tracking-wide">保留中</span>
          </div>
          <p className="text-3xl font-bold text-yellow-400">{stats.pending}</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#1e2d42]">
        {([['users', 'ユーザー一覧'], ['settings', 'MFA設定']] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === key
                ? 'border-[#e8002d] text-[#e2e8f4]'
                : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Users Tab ── */}
      {tab === 'users' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
              <input
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 pl-9 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff]"
                placeholder="ユーザー名・メールで検索..."
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <select
              className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
            >
              <option value="all">全ステータス</option>
              <option value="enabled">有効</option>
              <option value="disabled">無効</option>
              <option value="pending">保留中</option>
            </select>
            <select
              className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
              value={roleFilter}
              onChange={e => setRoleFilter(e.target.value)}
            >
              <option value="all">全ロール</option>
              <option value="admin">管理者</option>
              <option value="analyst">アナリスト</option>
              <option value="viewer">閲覧者</option>
            </select>

            {/* Bulk action */}
            {selected.size > 0 && (
              <button
                onClick={() => setBulkConfirm(true)}
                className="flex items-center gap-2 px-3 py-2 rounded-sm text-sm bg-blue-600 text-white hover:bg-blue-700 transition-colors"
              >
                <Mail className="w-4 h-4" />
                一括強制有効化 ({selected.size})
              </button>
            )}
          </div>

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center h-32 text-[#7d92b0]">
                <RefreshCw className="w-5 h-5 animate-spin mr-2" />読み込み中...
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                    <th className="w-10 px-4 py-3">
                      <button onClick={toggleAll}>
                        {allSelected
                          ? <CheckSquare className="w-4 h-4 text-[#1a6bff]" />
                          : <Square className="w-4 h-4 text-[#3d5068]" />}
                      </button>
                    </th>
                    <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">ユーザー</th>
                    <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">ロール</th>
                    <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">MFAステータス</th>
                    <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">MFA方式</th>
                    <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">最終MFA使用</th>
                    <th className="px-4 py-3 text-left text-xs text-[#7d92b0] uppercase tracking-wide font-medium">アクション</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filtered.map(user => (
                    <tr key={user.id} className="hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3">
                        <button onClick={() => toggleSelect(user.id)}>
                          {selected.has(user.id)
                            ? <CheckSquare className="w-4 h-4 text-[#1a6bff]" />
                            : <Square className="w-4 h-4 text-[#3d5068]" />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0">
                            <span className="text-[11px] font-bold text-white uppercase">
                              {user.username[0]}
                            </span>
                          </div>
                          <div>
                            <p className="text-[#e2e8f4] font-medium">{user.username}</p>
                            <p className="text-[#7d92b0] text-xs">{user.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${ROLE_STYLES[user.role]}`}>
                          {ROLE_LABELS[user.role]}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${MFA_STATUS_STYLES[user.mfa_status]}`}>
                          {MFA_STATUS_LABELS[user.mfa_status]}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[#7d92b0] text-sm">{user.mfa_method}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[#7d92b0] text-xs">{fmtDateTime(user.last_mfa_used)}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setConfirmAction({ type: 'reset', userId: user.id, username: user.username })}
                            className="px-2 py-1 rounded-sm text-xs bg-[#161f33] text-[#7d92b0] border border-[#1e2d42] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 transition-colors flex items-center gap-1"
                          >
                            <RotateCcw className="w-3 h-3" />
                            リセット
                          </button>
                          {user.mfa_status !== 'pending' && (
                            <button
                              onClick={() => setConfirmAction({ type: 'force', userId: user.id, username: user.username })}
                              className="px-2 py-1 rounded-sm text-xs bg-blue-900/30 text-blue-300 border border-blue-700/50 hover:bg-blue-900/50 transition-colors flex items-center gap-1"
                            >
                              <ShieldAlert className="w-3 h-3" />
                              強制有効化
                            </button>
                          )}
                          {user.mfa_status === 'enabled' && (
                            <button
                              onClick={() => setConfirmAction({ type: 'disable', userId: user.id, username: user.username })}
                              className="px-2 py-1 rounded-sm text-xs bg-red-900/30 text-red-300 border border-red-700/50 hover:bg-red-900/50 transition-colors flex items-center gap-1"
                            >
                              <X className="w-3 h-3" />
                              無効化
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-[#7d92b0]">
                        該当するユーザーが見つかりません
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Settings Tab ── */}
      {tab === 'settings' && (
        <div className="grid grid-cols-2 gap-6">
          {/* Settings form */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6 space-y-6">
            <h2 className="text-[#e2e8f4] font-semibold">グローバルMFA設定</h2>

            {/* MFA Required Toggle */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[#e2e8f4] text-sm font-medium">MFAを必須にする</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">全ユーザーにMFAを義務付けます</p>
              </div>
              <button
                onClick={() => setMfaRequired(v => !v)}
                className={`relative w-11 h-6 rounded-full transition-colors ${
                  mfaRequired ? 'bg-green-600' : 'bg-[#1e2d42]'
                }`}
              >
                <span className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] transition-all ${
                  mfaRequired ? 'left-6' : 'left-1'
                }`} />
              </button>
            </div>

            {/* Required Roles */}
            <div>
              <p className="text-[#e2e8f4] text-sm font-medium mb-2">MFA必須の対象ロール</p>
              <div className="space-y-2">
                {[['admin', '管理者'], ['analyst', 'アナリスト'], ['viewer', '閲覧者']].map(([role, label]) => (
                  <label key={role} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={requiredRoles.includes(role)}
                      onChange={() => toggleRole(role)}
                      className="w-4 h-4 rounded-sm border-[#1e2d42] bg-[#070d19] accent-[#e8002d]"
                    />
                    <span className="text-sm text-[#7d92b0]">{label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Grace Period */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#e2e8f4] text-sm font-medium">猶予期間</p>
                <span className="text-[#e8002d] text-sm font-bold">{gracePeriod}日</span>
              </div>
              <input
                type="range"
                min="0"
                max="30"
                value={gracePeriod}
                onChange={e => setGracePeriod(Number(e.target.value))}
                className="w-full accent-[#e8002d]"
              />
              <div className="flex justify-between text-xs text-[#3d5068] mt-1">
                <span>0日 (即時)</span>
                <span>30日</span>
              </div>
            </div>

            {/* Allowed Methods */}
            <div>
              <p className="text-[#e2e8f4] text-sm font-medium mb-2">許可するMFA方式</p>
              <div className="space-y-2">
                {[['TOTP', 'TOTP (認証アプリ)'], ['Email', 'メール OTP']].map(([method, label]) => (
                  <label key={method} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={allowedMethods.includes(method)}
                      onChange={() => toggleMethod(method)}
                      className="w-4 h-4 rounded-sm border-[#1e2d42] bg-[#070d19] accent-[#e8002d]"
                    />
                    <span className="text-sm text-[#7d92b0]">{label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Backup Codes */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[#e2e8f4] text-sm font-medium">バックアップコード</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">リカバリーコードの使用を許可します</p>
              </div>
              <button
                onClick={() => setBackupCodes(v => !v)}
                className={`relative w-11 h-6 rounded-full transition-colors ${
                  backupCodes ? 'bg-green-600' : 'bg-[#1e2d42]'
                }`}
              >
                <span className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] transition-all ${
                  backupCodes ? 'left-6' : 'left-1'
                }`} />
              </button>
            </div>

            {/* Save Button */}
            <button
              onClick={handleSaveSettings}
              disabled={settingsMutation.isPending}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-sm bg-[#e8002d] text-white text-sm font-medium hover:bg-[#c8001d] disabled:opacity-60 transition-colors"
            >
              {settingsMutation.isPending
                ? <RefreshCw className="w-4 h-4 animate-spin" />
                : <Save className="w-4 h-4" />}
              {settingsSaved ? '保存しました！' : '設定を保存'}
            </button>
          </div>

          {/* Pie Chart */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6">
            <h2 className="text-[#e2e8f4] font-semibold mb-6">登録統計</h2>
            <MfaMethodPieChart users={users} />

            <div className="mt-6 space-y-3">
              <h3 className="text-[#7d92b0] text-xs uppercase tracking-wide font-medium">ステータス内訳</h3>
              {[
                { label: 'MFA有効', count: stats.enabled, color: 'bg-green-500' },
                { label: 'MFA無効', count: stats.disabled, color: 'bg-red-500' },
                { label: '保留中', count: stats.pending, color: 'bg-yellow-500' },
              ].map(s => (
                <div key={s.label} className="flex items-center gap-3">
                  <span className={`w-2 h-2 rounded-full ${s.color}`} />
                  <span className="text-[#7d92b0] text-sm flex-1">{s.label}</span>
                  <span className="text-[#e2e8f4] text-sm font-medium">{s.count}</span>
                  <div className="w-24 bg-[#161f33] rounded-full h-1.5 overflow-hidden">
                    <div
                      className={`h-full ${s.color} rounded-full`}
                      style={{ width: `${stats.total ? s.count / stats.total * 100 : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Confirm Modal */}
      {confirmAction && (
        <ConfirmModal
          title={
            confirmAction.type === 'reset' ? 'MFAリセットの確認' :
            confirmAction.type === 'force' ? '強制有効化の確認' :
            'MFA無効化の確認'
          }
          message={
            confirmAction.type === 'reset'
              ? `${confirmAction.username} のMFAをリセットし、再登録が必要になります。`
              : confirmAction.type === 'force'
              ? `${confirmAction.username} に登録メールを送信し、MFA登録を求めます。`
              : `${confirmAction.username} のMFAを無効化します。`
          }
          onConfirm={handleConfirm}
          onCancel={() => setConfirmAction(null)}
          requireReason={confirmAction.type === 'disable'}
        />
      )}

      {/* Bulk Confirm Modal */}
      {bulkConfirm && (
        <ConfirmModal
          title="一括強制有効化の確認"
          message={`選択した ${selected.size} 名のユーザーにMFA登録メールを送信します。`}
          onConfirm={handleBulkForce}
          onCancel={() => setBulkConfirm(false)}
        />
      )}
    </div>
  )
}
