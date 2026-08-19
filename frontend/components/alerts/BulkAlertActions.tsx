'use client'

import { useState, useEffect, useRef } from 'react'
import {
  CheckSquare, Square, Loader2, CheckCircle2, AlertTriangle,
  XCircle, ChevronDown, Tag, UserCheck, Trash2, X,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ── Types ──────────────────────────────────────────────────────

export interface Alert {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'resolved' | 'suppressed'
  source: string
  created_at: string
}

export interface BulkAlertActionsProps {
  alerts: Alert[]
  selectedIds: Set<string>
  onSelectionChange: (ids: Set<string>) => void
  onBulkAction: (action: string, ids: string[], value?: string) => Promise<void>
}

interface UserItem {
  id: string
  email: string
  full_name: string
  role: string
}

// ── Predefined tag options ────────────────────────────────────

const TAG_OPTIONS = [
  { value: 'critical',       label: 'クリティカル',     color: 'text-red-400' },
  { value: 'false-positive', label: '誤検知',           color: 'text-gray-400' },
  { value: 'reviewed',       label: 'レビュー済み',     color: 'text-green-400' },
  { value: 'escalated',      label: 'エスカレート済み', color: 'text-orange-400' },
]

// ── Notification sub-component ────────────────────────────────

type NotifType = 'success' | 'error'

interface Notification {
  type: NotifType
  message: string
}

function InlineNotification({ notif, onDismiss }: { notif: Notification; onDismiss: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 4000)
    return () => clearTimeout(t)
  }, [notif, onDismiss])

  const isSuccess = notif.type === 'success'
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium
                     transition-all animate-in fade-in slide-in-from-bottom-2 duration-200
                     ${isSuccess
                       ? 'bg-green-900/40 border border-green-700/50 text-green-300'
                       : 'bg-red-900/40 border border-red-700/50 text-red-300'}`}
    >
      {isSuccess
        ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
        : <AlertTriangle className="w-3.5 h-3.5 shrink-0" />}
      <span>{notif.message}</span>
      <button
        onClick={onDismiss}
        className="ml-1 opacity-60 hover:opacity-100 transition-opacity"
        aria-label="通知を閉じる"
      >
        <X className="w-3 h-3" />
      </button>
    </div>
  )
}

// ── Dropdown sub-component ────────────────────────────────────

interface DropdownProps {
  trigger: React.ReactNode
  children: React.ReactNode
  align?: 'left' | 'right'
}

function Dropdown({ trigger, children, align = 'left' }: DropdownProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  return (
    <div ref={ref} className="relative">
      <div onClick={() => setOpen(v => !v)} className="cursor-pointer">
        {trigger}
      </div>
      {open && (
        <div
          className={`absolute bottom-full mb-2 z-50 min-w-[160px] bg-[#1a2540] border border-[#2a3a5c]
                      rounded-lg shadow-xl overflow-hidden
                      ${align === 'right' ? 'right-0' : 'left-0'}`}
        >
          <div onClick={() => setOpen(false)}>
            {children}
          </div>
        </div>
      )}
    </div>
  )
}

// ── useAlertSelection hook ────────────────────────────────────

export function useAlertSelection() {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const toggleId = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const toggleAll = (ids: string[]) => {
    setSelectedIds(prev => {
      const allSelected = ids.every(id => prev.has(id))
      if (allSelected) {
        // deselect all provided ids
        const next = new Set(prev)
        ids.forEach(id => next.delete(id))
        return next
      } else {
        // select all provided ids
        const next = new Set(prev)
        ids.forEach(id => next.add(id))
        return next
      }
    })
  }

  const clear = () => setSelectedIds(new Set())

  return { selectedIds, toggleId, toggleAll, clear }
}

// ── Row checkbox (exported for use in alert list rows) ────────

export function AlertRowCheckbox({
  alertId,
  selectedIds,
  onSelectionChange,
}: {
  alertId: string
  selectedIds: Set<string>
  onSelectionChange: (ids: Set<string>) => void
}) {
  const checked = selectedIds.has(alertId)

  function handleToggle(e: React.MouseEvent) {
    e.preventDefault()
    e.stopPropagation()
    const next = new Set(selectedIds)
    if (checked) {
      next.delete(alertId)
    } else {
      next.add(alertId)
    }
    onSelectionChange(next)
  }

  return (
    <button
      onClick={handleToggle}
      aria-label={checked ? '選択解除' : '選択'}
      className={`shrink-0 w-4 h-4 transition-colors
                  ${checked ? 'text-[#1a6bff]' : 'text-[#3d5068] hover:text-[#5a7aaa]'}`}
    >
      {checked ? <CheckSquare className="w-4 h-4" /> : <Square className="w-4 h-4" />}
    </button>
  )
}

// ── Main BulkAlertActions component ──────────────────────────

export default function BulkAlertActions({
  alerts,
  selectedIds,
  onSelectionChange,
  onBulkAction,
}: BulkAlertActionsProps) {
  const [loading, setLoading] = useState(false)
  const [notification, setNotification] = useState<Notification | null>(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [users, setUsers] = useState<UserItem[]>([])
  const [usersLoading, setUsersLoading] = useState(false)

  const count = selectedIds.size
  const allIds = alerts.map(a => a.id)
  const allSelected = allIds.length > 0 && allIds.every(id => selectedIds.has(id))

  // Fetch users when assign dropdown is about to be used
  async function fetchUsers() {
    if (users.length > 0) return
    setUsersLoading(true)
    try {
      const res = await apiFetch<{ data: UserItem[] }>('/api/v1/users')
      setUsers(res.data ?? [])
    } catch {
      // Users endpoint may not exist; fail gracefully
      setUsers([])
    } finally {
      setUsersLoading(false)
    }
  }

  function handleSelectAll() {
    if (allSelected) {
      onSelectionChange(new Set())
    } else {
      onSelectionChange(new Set(allIds))
    }
  }

  function notify(type: NotifType, message: string) {
    setNotification({ type, message })
  }

  async function runAction(action: string, value?: string) {
    const ids = Array.from(selectedIds)
    setLoading(true)
    setNotification(null)
    try {
      await onBulkAction(action, ids, value)
      notify('success', `${ids.length}件の操作が完了しました`)
      // Clear selection after successful bulk action
      onSelectionChange(new Set())
    } catch (err) {
      notify('error', (err as Error).message ?? '操作に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  async function handleBulkStatus(status: string) {
    const ids = Array.from(selectedIds)
    setLoading(true)
    setNotification(null)
    try {
      await apiFetch('/api/v1/alerts/bulk-status', {
        method: 'POST',
        body: JSON.stringify({ ids, status }),
      })
      await onBulkAction('status', ids, status)
      notify('success', `${ids.length}件のステータスを更新しました`)
      onSelectionChange(new Set())
    } catch (err) {
      notify('error', (err as Error).message ?? 'ステータス更新に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  async function handleBulkDelete() {
    const ids = Array.from(selectedIds)
    setLoading(true)
    setNotification(null)
    setShowDeleteConfirm(false)
    try {
      await apiFetch('/api/v1/alerts/bulk-delete', {
        method: 'POST',
        body: JSON.stringify({ ids }),
      })
      await onBulkAction('delete', ids)
      notify('success', `${ids.length}件を削除しました`)
      onSelectionChange(new Set())
    } catch (err) {
      notify('error', (err as Error).message ?? '削除に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  async function handleBulkTag(tag: string) {
    const ids = Array.from(selectedIds)
    setLoading(true)
    setNotification(null)
    try {
      await apiFetch('/api/v1/alerts/bulk-tag', {
        method: 'POST',
        body: JSON.stringify({ ids, tag }),
      })
      await onBulkAction('tag', ids, tag)
      notify('success', `${ids.length}件にタグを追加しました`)
      onSelectionChange(new Set())
    } catch (err) {
      notify('error', (err as Error).message ?? 'タグ追加に失敗しました')
    } finally {
      setLoading(false)
    }
  }

  async function handleBulkAssign(userId: string) {
    const ids = Array.from(selectedIds)
    setLoading(true)
    setNotification(null)
    try {
      await apiFetch('/api/v1/alerts/bulk-assign', {
        method: 'POST',
        body: JSON.stringify({ ids, user_id: userId }),
      })
      await onBulkAction('assign', ids, userId)
      notify('success', `${ids.length}件をアサインしました`)
      onSelectionChange(new Set())
    } catch (err) {
      notify('error', (err as Error).message ?? 'アサインに失敗しました')
    } finally {
      setLoading(false)
    }
  }

  if (count === 0) return null

  return (
    <>
      {/* Floating action bar — sticky at viewport bottom */}
      <div
        className="fixed bottom-0 inset-x-0 z-50 flex items-center justify-center pb-4 pointer-events-none"
        role="toolbar"
        aria-label="一括操作バー"
      >
        <div
          className={`pointer-events-auto flex items-center gap-2 flex-wrap
                      bg-[#111c2e] border border-[#2a3a5c] rounded-xl shadow-2xl
                      px-4 py-3 max-w-4xl w-full mx-4
                      ${loading ? 'opacity-80' : ''}`}
        >
          {/* Selection count badge */}
          <span className="flex items-center gap-1.5 text-xs font-bold text-[#1a6bff] bg-[#1a6bff]/10 border border-[#1a6bff]/30 rounded-full px-3 py-1 shrink-0">
            <CheckSquare className="w-3.5 h-3.5" />
            {count}件選択中
          </span>

          {/* Divider */}
          <div className="h-5 w-px bg-[#2a3a5c] shrink-0" />

          {/* Select all / deselect */}
          <button
            onClick={handleSelectAll}
            disabled={loading}
            className="text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors px-2 py-1 rounded-sm hover:bg-[#1a2540] disabled:opacity-50"
          >
            {allSelected ? '選択解除' : '全選択'}
          </button>

          {/* Divider */}
          <div className="h-5 w-px bg-[#2a3a5c] shrink-0" />

          {/* Status actions */}
          <button
            onClick={() => handleBulkStatus('resolved')}
            disabled={loading}
            title="クローズ（解決済みに変更）"
            className="flex items-center gap-1.5 text-xs text-[#00e676] bg-[#00c853]/10 border border-[#00c853]/25 hover:bg-[#00c853]/20 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            クローズ
          </button>

          <button
            onClick={() => handleBulkStatus('investigating')}
            disabled={loading}
            title="調査中に変更"
            className="flex items-center gap-1.5 text-xs text-[#ffb74d] bg-[#ff9800]/10 border border-[#ff9800]/25 hover:bg-[#ff9800]/20 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            <Loader2 className="w-3.5 h-3.5" />
            調査中
          </button>

          <button
            onClick={() => handleBulkStatus('suppressed')}
            disabled={loading}
            title="抑制（suppressed）に変更"
            className="flex items-center gap-1.5 text-xs text-[#7d92b0] bg-[#3d5068]/20 border border-[#3d5068]/40 hover:bg-[#3d5068]/30 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            <XCircle className="w-3.5 h-3.5" />
            抑制
          </button>

          {/* Divider */}
          <div className="h-5 w-px bg-[#2a3a5c] shrink-0" />

          {/* Tag dropdown */}
          <Dropdown
            align="left"
            trigger={
              <button
                disabled={loading}
                className="flex items-center gap-1.5 text-xs text-[#a78bfa] bg-[#7c3aed]/10 border border-[#7c3aed]/25 hover:bg-[#7c3aed]/20 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
              >
                <Tag className="w-3.5 h-3.5" />
                タグ追加
                <ChevronDown className="w-3 h-3 opacity-70" />
              </button>
            }
          >
            <div className="py-1">
              {TAG_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => handleBulkTag(opt.value)}
                  className={`w-full text-left px-4 py-2 text-xs hover:bg-[#253050] transition-colors ${opt.color}`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </Dropdown>

          {/* Assign dropdown */}
          <Dropdown
            align="left"
            trigger={
              <button
                disabled={loading}
                onMouseEnter={fetchUsers}
                className="flex items-center gap-1.5 text-xs text-[#5a99ff] bg-[#1a6bff]/10 border border-[#1a6bff]/25 hover:bg-[#1a6bff]/20 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
              >
                <UserCheck className="w-3.5 h-3.5" />
                アサイン
                <ChevronDown className="w-3 h-3 opacity-70" />
              </button>
            }
          >
            <div className="py-1 min-w-[200px]">
              {usersLoading ? (
                <div className="flex items-center gap-2 px-4 py-3 text-xs text-[#7d92b0]">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  読み込み中...
                </div>
              ) : users.length === 0 ? (
                <p className="px-4 py-3 text-xs text-[#5a6a7a]">アナリストが見つかりません</p>
              ) : (
                users.map(user => (
                  <button
                    key={user.id}
                    onClick={() => handleBulkAssign(user.id)}
                    className="w-full text-left px-4 py-2 text-xs text-[#e2e8f4] hover:bg-[#253050] transition-colors"
                  >
                    <span className="block font-medium">{user.full_name}</span>
                    <span className="text-[#5a6a7a]">{user.email}</span>
                  </button>
                ))
              )}
            </div>
          </Dropdown>

          {/* Delete */}
          {showDeleteConfirm ? (
            <div className="flex items-center gap-1.5 ml-auto">
              <span className="text-xs text-red-300">{count}件を削除しますか？</span>
              <button
                onClick={handleBulkDelete}
                disabled={loading}
                className="text-xs text-red-400 hover:text-red-300 font-semibold px-2 py-1 rounded-sm hover:bg-red-900/20 transition-colors disabled:opacity-50"
              >
                削除
              </button>
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="text-xs text-[#5a6a7a] hover:text-[#8899aa] px-2 py-1 transition-colors"
              >
                取消
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowDeleteConfirm(true)}
              disabled={loading}
              title="選択したアラートを削除"
              className="flex items-center gap-1.5 text-xs text-red-400 bg-red-900/10 border border-red-700/25 hover:bg-red-900/20 px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50 ml-auto"
            >
              <Trash2 className="w-3.5 h-3.5" />
              削除
            </button>
          )}

          {/* Loading spinner overlay */}
          {loading && (
            <div className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-[#1a6bff]" />
              処理中...
            </div>
          )}

          {/* Inline notification */}
          {notification && (
            <InlineNotification
              notif={notification}
              onDismiss={() => setNotification(null)}
            />
          )}
        </div>
      </div>

      {/* Spacer so page content isn't hidden behind the bar */}
      <div className="h-20" aria-hidden="true" />
    </>
  )
}
