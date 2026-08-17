'use client'


import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Plus, Trash2, Edit2, Save, Users,
  Check, X, ChevronDown, AlertCircle
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface Role {
  name: string
  description: string
  member_count: number
  color?: string
  is_system?: boolean
}

interface PermissionMatrix {
  [role: string]: string[]
}

interface User {
  id: string
  email: string
  full_name: string
  role: string
}

// ── Permission Definitions ─────────────────────────────────────────────────

const PERMISSION_CATEGORIES: { category: string; label: string; permissions: { id: string; label: string }[] }[] = [
  {
    category: 'alerts',
    label: 'アラート',
    permissions: [
      { id: 'view_alerts',   label: 'アラート閲覧' },
      { id: 'manage_alerts', label: 'アラート管理' },
      { id: 'close_alerts',  label: 'アラートクローズ' },
      { id: 'assign_alerts', label: 'アラート割り当て' },
      { id: 'export_alerts', label: 'アラートエクスポート' },
    ],
  },
  {
    category: 'agents',
    label: 'エージェント',
    permissions: [
      { id: 'view_agents',    label: 'エージェント閲覧' },
      { id: 'manage_agents',  label: 'エージェント管理' },
      { id: 'deploy_agents',  label: 'エージェント配備' },
      { id: 'run_commands',   label: 'コマンド実行' },
    ],
  },
  {
    category: 'incidents',
    label: 'インシデント',
    permissions: [
      { id: 'view_incidents',   label: 'インシデント閲覧' },
      { id: 'manage_incidents', label: 'インシデント管理' },
      { id: 'close_incidents',  label: 'インシデントクローズ' },
    ],
  },
  {
    category: 'rules',
    label: '検知ルール',
    permissions: [
      { id: 'view_rules',   label: 'ルール閲覧' },
      { id: 'manage_rules', label: 'ルール管理' },
      { id: 'import_rules', label: 'ルールインポート' },
    ],
  },
  {
    category: 'reports',
    label: 'レポート',
    permissions: [
      { id: 'view_reports',      label: 'レポート閲覧' },
      { id: 'generate_reports',  label: 'レポート生成' },
      { id: 'schedule_reports',  label: 'レポートスケジュール' },
    ],
  },
  {
    category: 'admin',
    label: '管理',
    permissions: [
      { id: 'manage_users',    label: 'ユーザー管理' },
      { id: 'manage_roles',    label: 'ロール管理' },
      { id: 'view_audit',      label: '監査ログ閲覧' },
      { id: 'manage_settings', label: '設定管理' },
    ],
  },
  {
    category: 'intel',
    label: 'インテリジェンス',
    permissions: [
      { id: 'view_intel',   label: 'インテル閲覧' },
      { id: 'manage_intel', label: 'インテル管理' },
      { id: 'manage_feeds', label: 'フィード管理' },
    ],
  },
]

const ROLE_COLORS: string[] = [
  '#e8002d', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6',
  '#ec4899', '#14b8a6', '#f97316', '#06b6d4', '#84cc16',
]

// ── Helper Components ──────────────────────────────────────────────────────

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
        active
          ? 'border-falcon-red text-white'
          : 'border-transparent text-falcon-muted hover:text-falcon-text hover:border-falcon-border'
      }`}
    >
      {children}
    </button>
  )
}

function Badge({ color, children }: { color?: string; children: React.ReactNode }) {
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium"
      style={{ backgroundColor: color ? color + '22' : '#1e2d4290', color: color ?? '#7d92b0', border: `1px solid ${color ?? '#1e2d42'}55` }}
    >
      {children}
    </span>
  )
}

// ── Tab 1: Permission Matrix ───────────────────────────────────────────────

function PermissionMatrixTab() {
  const queryClient = useQueryClient()

  const { data: rolesData } = useQuery<{ roles: Role[] }>({
    queryKey: ['admin-roles'],
    queryFn: () => apiFetch<{ roles: Role[] }>('/api/v1/admin/roles').catch(() => ({ roles: [] })),
  })

  const { data: matrixData } = useQuery<{ matrix: PermissionMatrix }>({
    queryKey: ['admin-permissions'],
    queryFn: () => apiFetch<{ matrix: PermissionMatrix }>('/api/v1/admin/permissions').catch(() => ({ matrix: {} as PermissionMatrix })),
  })

  const [localMatrix, setLocalMatrix] = useState<PermissionMatrix | null>(null)
  const [saveSuccess, setSaveSuccess] = useState(false)

  const matrix = localMatrix ?? (matrixData?.matrix ?? {} as PermissionMatrix)
  const roles = rolesData?.roles ?? []

  const saveMutation = useMutation({
    mutationFn: (data: PermissionMatrix) =>
      apiFetch('/api/v1/admin/permissions', { method: 'PUT', body: JSON.stringify(data) }).catch(() => ({ ok: true })),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-permissions'] })
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 3000)
    },
  })

  function togglePermission(role: string, permission: string) {
    const current = matrix[role] ?? []
    const updated = current.includes(permission)
      ? current.filter(p => p !== permission)
      : [...current, permission]
    setLocalMatrix({ ...matrix, [role]: updated })
  }

  function hasPermission(role: string, permission: string): boolean {
    return (matrix[role] ?? []).includes(permission)
  }

  function toggleCategoryForRole(role: string, categoryPermissions: string[], allOn: boolean) {
    const current = matrix[role] ?? []
    let updated: string[]
    if (allOn) {
      updated = current.filter(p => !categoryPermissions.includes(p))
    } else {
      updated = Array.from(new Set([...current, ...categoryPermissions]))
    }
    setLocalMatrix({ ...matrix, [role]: updated })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-white font-semibold text-lg">パーミッションマトリクス</h2>
          <p className="text-falcon-muted text-sm mt-0.5">ロールごとの権限を管理します。チェックボックスをクリックして変更してください。</p>
        </div>
        <button
          onClick={() => saveMutation.mutate(matrix)}
          disabled={saveMutation.isPending || localMatrix === null}
          className={`flex items-center gap-2 px-4 py-2 rounded text-sm font-medium transition-colors ${
            saveSuccess
              ? 'bg-green-600/20 text-green-400 border border-green-600/30'
              : localMatrix !== null
              ? 'bg-falcon-red hover:bg-[#c0001f] text-white'
              : 'bg-falcon-border text-falcon-muted cursor-not-allowed'
          }`}
        >
          {saveSuccess ? (
            <><Check className="w-4 h-4" /> 保存済み</>
          ) : (
            <><Save className="w-4 h-4" /> マトリクスを保存</>
          )}
        </button>
      </div>

      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border">
                <th className="text-left px-4 py-3 text-falcon-muted font-medium w-48 sticky left-0 bg-falcon-surface z-10">
                  権限
                </th>
                {roles.map(role => (
                  <th key={role.name} className="px-4 py-3 text-center min-w-[110px]">
                    <div className="flex flex-col items-center gap-1">
                      <span
                        className="font-semibold text-xs px-2 py-0.5 rounded-sm"
                        style={{ backgroundColor: (role.color ?? '#3b82f6') + '22', color: role.color ?? '#3b82f6' }}
                      >
                        {role.name}
                      </span>
                      <span className="text-falcon-subtle text-[10px]">{role.member_count}人</span>
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {PERMISSION_CATEGORIES.map((cat, catIdx) => (
                <>
                  {/* Category header row */}
                  <tr key={`cat-${cat.category}`} className="bg-[#070d19]/50 border-t border-falcon-border">
                    <td className="px-4 py-2 sticky left-0 bg-[#070d19]/80 z-10">
                      <span className="text-falcon-muted text-xs font-semibold uppercase tracking-wider">
                        {cat.label}
                      </span>
                    </td>
                    {roles.map(role => {
                      const catPerms = cat.permissions.map(p => p.id)
                      const allOn = catPerms.every(p => hasPermission(role.name, p))
                      const someOn = catPerms.some(p => hasPermission(role.name, p))
                      return (
                        <td key={role.name} className="px-4 py-2 text-center">
                          <button
                            onClick={() => toggleCategoryForRole(role.name, catPerms, allOn)}
                            className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
                              allOn
                                ? 'bg-falcon-red/20 text-falcon-red hover:bg-falcon-red/30'
                                : someOn
                                ? 'bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20'
                                : 'bg-falcon-border text-falcon-muted hover:bg-falcon-border/80'
                            }`}
                          >
                            {allOn ? '全解除' : someOn ? '一部' : '全付与'}
                          </button>
                        </td>
                      )
                    })}
                  </tr>
                  {/* Permission rows */}
                  {cat.permissions.map((perm, permIdx) => (
                    <tr
                      key={perm.id}
                      className={`border-t border-falcon-border/50 hover:bg-falcon-surface/80 transition-colors ${
                        permIdx % 2 === 0 ? '' : 'bg-[#070d19]/20'
                      }`}
                    >
                      <td className="px-4 py-2.5 sticky left-0 bg-inherit z-10">
                        <span className="text-falcon-text text-xs">{perm.label}</span>
                        <span className="ml-2 text-falcon-subtle text-[10px] font-mono">{perm.id}</span>
                      </td>
                      {roles.map(role => {
                        const checked = hasPermission(role.name, perm.id)
                        return (
                          <td key={role.name} className="px-4 py-2.5 text-center">
                            <button
                              onClick={() => togglePermission(role.name, perm.id)}
                              className={`w-5 h-5 rounded border transition-all flex items-center justify-center mx-auto ${
                                checked
                                  ? 'bg-falcon-red border-falcon-red'
                                  : 'bg-transparent border-falcon-border hover:border-falcon-muted'
                              }`}
                              title={checked ? '権限を削除' : '権限を付与'}
                            >
                              {checked && <Check className="w-3 h-3 text-white" strokeWidth={3} />}
                            </button>
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {localMatrix !== null && (
        <div className="flex items-center gap-2 text-sm text-yellow-400 bg-yellow-400/10 border border-yellow-400/20 rounded-lg px-4 py-2.5">
          <AlertCircle className="w-4 h-4 shrink-0" />
          未保存の変更があります。「マトリクスを保存」ボタンをクリックして変更を反映してください。
        </div>
      )}
    </div>
  )
}

// ── Tab 2: Roles Management ────────────────────────────────────────────────

function RolesTab() {
  const queryClient = useQueryClient()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingRole, setEditingRole] = useState<Role | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  const { data: rolesData } = useQuery<{ roles: Role[] }>({
    queryKey: ['admin-roles'],
    queryFn: () => apiFetch<{ roles: Role[] }>('/api/v1/admin/roles').catch(() => ({ roles: [] })),
  })

  const roles = rolesData?.roles ?? []

  const deleteMutation = useMutation({
    mutationFn: (name: string) =>
      apiFetch(`/api/v1/admin/roles/${name}`, { method: 'DELETE' }).catch(() => ({ ok: true })),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-roles'] })
      setDeleteConfirm(null)
    },
  })

  const SYSTEM_ROLES = ['admin', 'analyst', 'viewer']

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-white font-semibold text-lg">ロール管理</h2>
          <p className="text-falcon-muted text-sm mt-0.5">ロールの作成・編集・削除を行います。システムロールは削除できません。</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white rounded-sm text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          ロール作成
        </button>
      </div>

      <div className="grid gap-3">
        {roles.map(role => (
          <div
            key={role.name}
            className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-4 hover:border-falcon-border/80 transition-colors"
          >
            {/* Color dot */}
            <div
              className="w-3 h-3 rounded-full shrink-0"
              style={{ backgroundColor: role.color ?? '#6b7280' }}
            />

            {/* Role info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-white font-medium">{role.name}</span>
                {role.is_system && (
                  <Badge color="#3b82f6">システム</Badge>
                )}
              </div>
              <p className="text-falcon-muted text-sm mt-0.5 truncate">{role.description}</p>
            </div>

            {/* Member count */}
            <div className="flex items-center gap-1.5 text-falcon-muted text-sm shrink-0">
              <Users className="w-4 h-4" />
              <span>{role.member_count}人</span>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => setEditingRole(role)}
                className="p-1.5 rounded-sm text-falcon-muted hover:text-falcon-text hover:bg-falcon-border transition-colors"
                title="編集"
              >
                <Edit2 className="w-4 h-4" />
              </button>
              {!SYSTEM_ROLES.includes(role.name) && (
                <button
                  onClick={() => setDeleteConfirm(role.name)}
                  className="p-1.5 rounded-sm text-falcon-muted hover:text-red-400 hover:bg-red-900/20 transition-colors"
                  title="削除"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Delete confirmation */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-falcon-surface border border-falcon-border rounded-lg p-6 max-w-sm w-full mx-4 shadow-xl">
            <h3 className="text-white font-semibold mb-2">ロールを削除しますか？</h3>
            <p className="text-falcon-muted text-sm mb-4">
              ロール <span className="text-white font-medium">「{deleteConfirm}」</span> を削除します。
              このロールが割り当てられているユーザーは viewer に変更されます。
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-falcon-muted hover:text-white border border-falcon-border hover:border-falcon-muted rounded-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-red-700 hover:bg-red-600 text-white rounded-sm transition-colors"
              >
                削除する
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create / Edit Modal */}
      {(showCreateModal || editingRole) && (
        <RoleModal
          role={editingRole}
          existingRoles={roles}
          onClose={() => { setShowCreateModal(false); setEditingRole(null) }}
          onSaved={() => {
            queryClient.invalidateQueries({ queryKey: ['admin-roles'] })
            setShowCreateModal(false)
            setEditingRole(null)
          }}
        />
      )}
    </div>
  )
}

// ── Role Create/Edit Modal ─────────────────────────────────────────────────

function RoleModal({
  role,
  existingRoles,
  onClose,
  onSaved,
}: {
  role: Role | null
  existingRoles: Role[]
  onClose: () => void
  onSaved: () => void
}) {
  const [name, setName] = useState(role?.name ?? '')
  const [description, setDescription] = useState(role?.description ?? '')
  const [color, setColor] = useState(role?.color ?? ROLE_COLORS[0])
  const [basedOnRole, setBasedOnRole] = useState('')
  const [useBaseRole, setUseBaseRole] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleSave() {
    if (!name.trim()) { setError('ロール名を入力してください'); return }
    setSaving(true)
    try {
      const endpoint = role
        ? `/api/v1/admin/roles/${role.name}`
        : '/api/v1/admin/roles'
      const method = role ? 'PUT' : 'POST'
      await apiFetch(endpoint, {
        method,
        body: JSON.stringify({ name: name.trim(), description, color, based_on: useBaseRole ? basedOnRole : undefined }),
      }).catch(() => null)
      onSaved()
    } catch (e) {
      setError('保存に失敗しました')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-white font-semibold text-lg">
            {role ? 'ロールを編集' : '新規ロール作成'}
          </h3>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className="block text-sm text-falcon-muted mb-1.5">ロール名 <span className="text-falcon-red">*</span></label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              disabled={!!role}
              placeholder="例: security_ops"
              className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                         focus:outline-hidden focus:border-falcon-red/50 placeholder:text-falcon-subtle
                         disabled:opacity-50 disabled:cursor-not-allowed"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm text-falcon-muted mb-1.5">説明</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={2}
              placeholder="このロールの用途を記述してください"
              className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                         focus:outline-hidden focus:border-falcon-red/50 placeholder:text-falcon-subtle resize-none"
            />
          </div>

          {/* Color picker */}
          <div>
            <label className="block text-sm text-falcon-muted mb-1.5">カラー</label>
            <div className="flex gap-2 flex-wrap">
              {ROLE_COLORS.map(c => (
                <button
                  key={c}
                  onClick={() => setColor(c)}
                  className={`w-7 h-7 rounded-full border-2 transition-all ${
                    color === c ? 'border-white scale-110' : 'border-transparent hover:scale-105'
                  }`}
                  style={{ backgroundColor: c }}
                />
              ))}
            </div>
          </div>

          {/* Base on existing role (only for create) */}
          {!role && (
            <div>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useBaseRole}
                  onChange={e => setUseBaseRole(e.target.checked)}
                  className="accent-falcon-red"
                />
                <span className="text-sm text-falcon-muted">既存ロールをベースにする</span>
              </label>
              {useBaseRole && (
                <div className="mt-2 relative">
                  <select
                    value={basedOnRole}
                    onChange={e => setBasedOnRole(e.target.value)}
                    className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-white text-sm
                               focus:outline-hidden focus:border-falcon-red/50 appearance-none pr-8"
                  >
                    <option value="">ベースロールを選択</option>
                    {existingRoles.map(r => (
                      <option key={r.name} value={r.name}>{r.name}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-2 top-2.5 w-4 h-4 text-falcon-muted pointer-events-none" />
                </div>
              )}
            </div>
          )}

          {error && (
            <p className="text-red-400 text-sm flex items-center gap-1">
              <AlertCircle className="w-4 h-4" /> {error}
            </p>
          )}
        </div>

        <div className="flex gap-3 justify-end mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-falcon-muted hover:text-white border border-falcon-border hover:border-falcon-muted rounded-sm transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c0001f] text-white rounded-sm transition-colors disabled:opacity-50"
          >
            {saving ? '保存中...' : role ? '変更を保存' : 'ロールを作成'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Tab 3: User Role Assignment ────────────────────────────────────────────

function UserRoleAssignmentTab() {
  const queryClient = useQueryClient()
  const [localRoles, setLocalRoles] = useState<Record<string, string>>({})
  const [savingUser, setSavingUser] = useState<string | null>(null)
  const [savedUsers, setSavedUsers] = useState<Set<string>>(new Set())

  const { data: usersData } = useQuery<{ users: User[] }>({
    queryKey: ['admin-users-list'],
    queryFn: () => apiFetch<{ users: User[] }>('/api/v1/admin/users').catch(() => ({ users: [] })),
  })

  const { data: rolesData } = useQuery<{ roles: Role[] }>({
    queryKey: ['admin-roles'],
    queryFn: () => apiFetch<{ roles: Role[] }>('/api/v1/admin/roles').catch(() => ({ roles: [] })),
  })

  const users = usersData?.users ?? []
  const roles = rolesData?.roles ?? []

  async function saveUserRole(userId: string, newRole: string) {
    setSavingUser(userId)
    try {
      await apiFetch(`/api/v1/admin/users/${userId}/role`, {
        method: 'PUT',
        body: JSON.stringify({ role: newRole }),
      }).catch(() => null)
      setSavedUsers(prev => new Set([...prev, userId]))
      setTimeout(() => setSavedUsers(prev => { const n = new Set(prev); n.delete(userId); return n }), 2500)
      queryClient.invalidateQueries({ queryKey: ['admin-users-list'] })
    } finally {
      setSavingUser(null)
    }
  }

  function getUserRole(user: User): string {
    return localRoles[user.id] ?? user.role
  }

  function handleRoleChange(userId: string, newRole: string) {
    setLocalRoles(prev => ({ ...prev, [userId]: newRole }))
  }

  function getRoleColor(roleName: string): string {
    return roles.find(r => r.name === roleName)?.color ?? '#6b7280'
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-white font-semibold text-lg">ユーザーロール割り当て</h2>
        <p className="text-falcon-muted text-sm mt-0.5">ユーザーごとのロールを変更できます。変更後に「保存」をクリックしてください。</p>
      </div>

      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-falcon-border bg-[#070d19]/50">
              <th className="text-left px-4 py-3 text-falcon-muted font-medium">ユーザー</th>
              <th className="text-left px-4 py-3 text-falcon-muted font-medium">メールアドレス</th>
              <th className="text-left px-4 py-3 text-falcon-muted font-medium">現在のロール</th>
              <th className="text-left px-4 py-3 text-falcon-muted font-medium">変更後のロール</th>
              <th className="px-4 py-3 text-falcon-muted font-medium text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user, idx) => {
              const currentRole = getUserRole(user)
              const hasChange = localRoles[user.id] !== undefined && localRoles[user.id] !== user.role
              const isSaving = savingUser === user.id
              const wasSaved = savedUsers.has(user.id)
              return (
                <tr
                  key={user.id}
                  className={`border-t border-falcon-border/50 hover:bg-[#070d19]/30 transition-colors ${
                    idx % 2 === 0 ? '' : 'bg-[#070d19]/10'
                  }`}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-full bg-linear-to-br from-falcon-blue to-[#0044cc] flex items-center justify-center shrink-0">
                        <span className="text-[10px] font-bold text-white">
                          {(user.full_name || user.email)?.[0]?.toUpperCase() ?? 'U'}
                        </span>
                      </div>
                      <span className="text-falcon-text">{user.full_name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-falcon-muted">{user.email}</td>
                  <td className="px-4 py-3">
                    <Badge color={getRoleColor(user.role)}>{user.role}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="relative w-40">
                      <select
                        value={currentRole}
                        onChange={e => handleRoleChange(user.id, e.target.value)}
                        className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-1.5 text-white text-xs
                                   focus:outline-hidden focus:border-falcon-red/50 appearance-none pr-7"
                      >
                        {roles.map(r => (
                          <option key={r.name} value={r.name}>{r.name}</option>
                        ))}
                      </select>
                      <ChevronDown className="absolute right-2 top-2 w-3.5 h-3.5 text-falcon-muted pointer-events-none" />
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => saveUserRole(user.id, currentRole)}
                      disabled={(!hasChange && !wasSaved) || isSaving}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ml-auto ${
                        wasSaved
                          ? 'bg-green-600/20 text-green-400 border border-green-600/30'
                          : hasChange
                          ? 'bg-falcon-red hover:bg-[#c0001f] text-white'
                          : 'bg-falcon-border text-falcon-muted cursor-not-allowed opacity-50'
                      }`}
                    >
                      {isSaving ? (
                        <span className="w-3 h-3 border border-white/30 border-t-white rounded-full animate-spin" />
                      ) : wasSaved ? (
                        <Check className="w-3 h-3" />
                      ) : (
                        <Save className="w-3 h-3" />
                      )}
                      {wasSaved ? '保存済み' : isSaving ? '保存中' : '保存'}
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

const TABS = [
  { id: 'matrix',     label: 'パーミッションマトリクス' },
  { id: 'roles',      label: 'ロール管理' },
  { id: 'assignment', label: 'ユーザーロール割り当て' },
] as const

type TabId = typeof TABS[number]['id']

export default function RBACPage() {
  const [activeTab, setActiveTab] = useState<TabId>('matrix')

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Page Header */}
      <div className="flex items-start gap-4 mb-6">
        <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center shadow-lg shrink-0">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">RBAC 権限管理</h1>
          <p className="text-falcon-muted text-sm mt-0.5">
            ロールベースのアクセス制御 — ロールと権限のマトリクスを管理します
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        {/* Tab bar */}
        <div className="flex border-b border-falcon-border overflow-x-auto">
          {TABS.map(tab => (
            <TabButton
              key={tab.id}
              active={activeTab === tab.id}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </TabButton>
          ))}
        </div>

        {/* Tab content */}
        <div className="p-6">
          {activeTab === 'matrix'     && <PermissionMatrixTab />}
          {activeTab === 'roles'      && <RolesTab />}
          {activeTab === 'assignment' && <UserRoleAssignmentTab />}
        </div>
      </div>
    </div>
  )
}
