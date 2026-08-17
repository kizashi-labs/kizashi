'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Bell, X, Check, AlertCircle, Info, ShieldAlert } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'

// ── Types ──────────────────────────────────────────────────────
export type NotificationType = 'alert' | 'system' | 'agent' | 'alert_critical' | 'agent_offline' | 'incident_created' | 'rule_matched' | 'system_warning'
export type FilterTab = 'all' | 'alert' | 'system' | 'agent'

export interface Notification {
  id: string
  type: NotificationType
  title: string
  message: string
  read: boolean
  created_at: string
  timestamp?: string
  link: string
}

// ── Mock Data ──────────────────────────────────────────────────
const MOCK_STORAGE_KEY = 'edr_notifications_mock'

const BASE_MOCK: Notification[] = [
  {
    id: '1',
    type: 'alert_critical',
    title: 'Critical: Mimikatz Detected',
    message: 'Mimikatz detected on WORKSTATION-04 — credential dumping attempt blocked',
    read: false,
    created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    link: '/alerts',
  },
  {
    id: '2',
    type: 'agent_offline',
    title: 'Agent Offline',
    message: 'Agent agent-linux-02 went offline — last seen 12 minutes ago',
    read: false,
    created_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    link: '/endpoints',
  },
  {
    id: '3',
    type: 'incident_created',
    title: 'New Incident Created',
    message: 'New incident: Lateral Movement Campaign — severity HIGH, 3 endpoints affected',
    read: false,
    created_at: new Date(Date.now() - 28 * 60 * 1000).toISOString(),
    link: '/incidents',
  },
  {
    id: '4',
    type: 'rule_matched',
    title: 'YARA Rule Matched',
    message: "YARA rule 'Cobalt Strike' matched on SERVER-01 — file: svchost_fake.exe",
    read: false,
    created_at: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    link: '/admin/yara-rules',
  },
  {
    id: '5',
    type: 'system_warning',
    title: 'System Warning',
    message: 'Database connection pool at 85% capacity — consider scaling resources',
    read: true,
    created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    link: '/admin/system-status',
  },
]

function getMockNotifications(): Notification[] {
  if (typeof window === 'undefined') return BASE_MOCK
  try {
    const stored = localStorage.getItem(MOCK_STORAGE_KEY)
    if (stored) return JSON.parse(stored) as Notification[]
  } catch {
    // ignore
  }
  return BASE_MOCK
}

function saveMockNotifications(notifications: Notification[]) {
  if (typeof window === 'undefined') return
  try {
    localStorage.setItem(MOCK_STORAGE_KEY, JSON.stringify(notifications))
  } catch {
    // ignore
  }
}

// ── Relative Time ──────────────────────────────────────────────
function relativeTime(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime()
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return `${seconds}秒前`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}分前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}時間前`
  const days = Math.floor(hours / 24)
  return `${days}日前`
}

// ── Notification Icon ──────────────────────────────────────────
function NotificationIcon({ type }: { type: NotificationType }) {
  if (type === 'alert' || type === 'alert_critical') {
    return (
      <div className="shrink-0 w-8 h-8 rounded-full bg-red-500/10 flex items-center justify-center">
        <ShieldAlert className="w-4 h-4 text-red-400" />
      </div>
    )
  }
  if (type === 'agent' || type === 'agent_offline') {
    return (
      <div className="shrink-0 w-8 h-8 rounded-full bg-orange-500/10 flex items-center justify-center">
        <AlertCircle className="w-4 h-4 text-orange-400" />
      </div>
    )
  }
  if (type === 'incident_created') {
    return (
      <div className="shrink-0 w-8 h-8 rounded-full bg-yellow-500/10 flex items-center justify-center">
        <AlertCircle className="w-4 h-4 text-yellow-400" />
      </div>
    )
  }
  if (type === 'rule_matched') {
    return (
      <div className="shrink-0 w-8 h-8 rounded-full bg-purple-500/10 flex items-center justify-center">
        <ShieldAlert className="w-4 h-4 text-purple-400" />
      </div>
    )
  }
  if (type === 'system_warning') {
    return (
      <div className="shrink-0 w-8 h-8 rounded-full bg-yellow-500/10 flex items-center justify-center">
        <Info className="w-4 h-4 text-yellow-400" />
      </div>
    )
  }
  return (
    <div className="shrink-0 w-8 h-8 rounded-full bg-blue-500/10 flex items-center justify-center">
      <Info className="w-4 h-4 text-blue-400" />
    </div>
  )
}

// ── Notification Item ──────────────────────────────────────────
interface NotificationItemProps {
  notification: Notification
  onRead: (id: string) => void
  onClick: (notification: Notification) => void
}

function NotificationItem({ notification, onRead, onClick }: NotificationItemProps) {
  const borderColor =
    notification.type === 'alert'
      ? 'border-l-red-500/60'
      : notification.type === 'agent'
      ? 'border-l-orange-500/60'
      : 'border-l-blue-500/60'

  return (
    <div
      className={`
        relative flex items-start gap-3 px-4 py-3 cursor-pointer
        border-l-2 ${borderColor}
        ${notification.read ? 'opacity-60' : 'bg-[#0f1929]/40'}
        hover:bg-falcon-hover/60 transition-colors group
      `}
      onClick={() => onClick(notification)}
    >
      {/* Unread dot */}
      {!notification.read && (
        <span className="absolute top-3.5 right-4 w-2 h-2 rounded-full bg-falcon-red shrink-0" />
      )}

      <NotificationIcon type={notification.type} />

      <div className="flex-1 min-w-0 pr-4">
        <p className={`text-sm font-medium truncate ${notification.read ? 'text-falcon-muted' : 'text-falcon-text'}`}>
          {notification.title}
        </p>
        <p className="text-xs text-[#4d6480] mt-0.5 line-clamp-2">
          {notification.message}
        </p>
        <p className="text-[10px] text-falcon-subtle mt-1">
          {relativeTime(notification.created_at)}
        </p>
      </div>

      {/* Mark as read button (shows on hover) */}
      {!notification.read && (
        <button
          className="absolute right-7 top-3 opacity-0 group-hover:opacity-100 transition-opacity
                     p-0.5 rounded hover:bg-falcon-hover text-falcon-subtle hover:text-falcon-muted"
          title="既読にする"
          onClick={(e) => {
            e.stopPropagation()
            onRead(notification.id)
          }}
        >
          <Check className="w-3 h-3" />
        </button>
      )}
    </div>
  )
}

// ── Filter Tabs ────────────────────────────────────────────────
const TABS: { value: FilterTab; label: string }[] = [
  { value: 'all', label: 'すべて' },
  { value: 'alert', label: 'アラート' },
  { value: 'system', label: 'システム' },
  { value: 'agent', label: 'エージェント' },
]

// ── Main Component ─────────────────────────────────────────────
export function NotificationCenter() {
  const router = useRouter()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [activeTab, setActiveTab] = useState<FilterTab>('all')
  const [useMock, setUseMock] = useState(false)
  const [mockNotifications, setMockNotifications] = useState<Notification[]>([])
  const dropdownRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)

  // ── Fetch notifications from API ─────────────────────────────
  const { data: apiNotifications, error: fetchError, isSuccess } = useQuery<Notification[]>({
    queryKey: ['notifications-unread'],
    queryFn: () => apiFetchList<Notification>('/api/v1/notifications/unread'),
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: 1,
  })

  // Use mock when API errors OR returns empty array (demo environment)
  useEffect(() => {
    if (fetchError || (isSuccess && Array.isArray(apiNotifications) && apiNotifications.length === 0)) {
      setUseMock(true)
      setMockNotifications(getMockNotifications())
    }
  }, [fetchError, isSuccess, apiNotifications])

  const notifications: Notification[] = useMock ? mockNotifications : (apiNotifications ?? [])

  // ── Mark single as read ──────────────────────────────────────
  const markReadMutation = useMutation({
    mutationFn: (id: string) => {
      if (useMock) {
        const updated = mockNotifications.map(n => n.id === id ? { ...n, read: true } : n)
        saveMockNotifications(updated)
        setMockNotifications(updated)
        return Promise.resolve()
      }
      return apiFetch(`/api/v1/notifications/${id}/read`, { method: 'POST' })
    },
    onSuccess: () => {
      if (!useMock) {
        queryClient.invalidateQueries({ queryKey: ['notifications-unread'] })
      }
    },
  })

  // ── Mark all as read ─────────────────────────────────────────
  const markAllReadMutation = useMutation({
    mutationFn: () => {
      if (useMock) {
        const updated = mockNotifications.map(n => ({ ...n, read: true }))
        saveMockNotifications(updated)
        setMockNotifications(updated)
        return Promise.resolve()
      }
      return apiFetch('/api/v1/notifications/read-all', { method: 'POST' })
    },
    onSuccess: () => {
      if (!useMock) {
        queryClient.invalidateQueries({ queryKey: ['notifications-unread'] })
      }
    },
  })

  // ── Clear all ────────────────────────────────────────────────
  const clearAll = useCallback(() => {
    if (useMock) {
      saveMockNotifications([])
      setMockNotifications([])
    } else {
      queryClient.setQueryData(['notifications-unread'], [])
    }
  }, [useMock, queryClient])

  // ── Outside click handler ─────────────────────────────────────
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(e.target as Node)
      ) {
        setOpen(false)
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside)
    }
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [open])

  // ── Navigate on click ─────────────────────────────────────────
  const handleNotificationClick = useCallback((notification: Notification) => {
    markReadMutation.mutate(notification.id)
    setOpen(false)
    router.push(notification.link)
  }, [markReadMutation, router])

  // ── Filtered list ─────────────────────────────────────────────
  // Map extended types to base filter categories
  const typeToTab = (t: NotificationType): FilterTab => {
    if (t === 'alert' || t === 'alert_critical' || t === 'rule_matched') return 'alert'
    if (t === 'agent' || t === 'agent_offline') return 'agent'
    if (t === 'system' || t === 'system_warning' || t === 'incident_created') return 'system'
    return 'system'
  }

  const filteredNotifications = activeTab === 'all'
    ? notifications
    : notifications.filter(n => typeToTab(n.type) === activeTab)

  const unreadCount = notifications.filter(n => !n.read).length

  return (
    <div className="relative">
      {/* Bell Button */}
      <button
        ref={buttonRef}
        onClick={() => setOpen(prev => !prev)}
        className={`relative p-1.5 rounded transition-colors ${
          unreadCount > 0
            ? 'text-falcon-red hover:bg-falcon-red/10'
            : 'text-falcon-subtle hover:bg-falcon-hover hover:text-falcon-muted'
        }`}
        aria-label="通知センター"
        aria-expanded={open}
      >
        <Bell className="w-4 h-4" />
        {unreadCount > 0 && (
          <span
            className="absolute -top-0.5 -right-0.5 w-4 h-4 text-[9px] font-bold
                       bg-falcon-red text-white rounded-full flex items-center justify-center
                       critical-pulse"
          >
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Panel */}
      {open && (
        <div
          ref={dropdownRef}
          className="fixed z-50 mt-2 bg-falcon-surface border border-falcon-border rounded-lg shadow-xl w-96
                     flex flex-col max-h-[calc(100vh-80px)]"
          style={{
            top: buttonRef.current
              ? buttonRef.current.getBoundingClientRect().bottom + 8
              : 48,
            right: buttonRef.current
              ? window.innerWidth - buttonRef.current.getBoundingClientRect().right
              : 16,
          }}
        >
          {/* Panel Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-falcon-border">
            <div className="flex items-center gap-2">
              <Bell className="w-4 h-4 text-falcon-muted" />
              <h2 className="text-sm font-semibold text-falcon-text">通知</h2>
              {unreadCount > 0 && (
                <span className="text-[10px] bg-falcon-red/20 text-falcon-red border border-falcon-red/30
                                 px-1.5 py-0.5 rounded-full font-medium">
                  {unreadCount} 件未読
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <button
                  onClick={() => markAllReadMutation.mutate()}
                  disabled={markAllReadMutation.isPending}
                  className="text-[10px] text-[#4d8fff] hover:text-[#7daaff] transition-colors
                             disabled:opacity-50 px-2 py-0.5 rounded hover:bg-[#4d8fff]/10"
                >
                  すべて既読
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                className="p-1 rounded-sm text-falcon-subtle hover:text-falcon-muted hover:bg-falcon-hover transition-colors"
                aria-label="閉じる"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Filter Tabs */}
          <div className="flex border-b border-falcon-border">
            {TABS.map(tab => (
              <button
                key={tab.value}
                onClick={() => setActiveTab(tab.value)}
                className={`flex-1 text-[11px] py-2 font-medium transition-colors ${
                  activeTab === tab.value
                    ? 'text-[#4d8fff] border-b-2 border-[#4d8fff] bg-[#4d8fff]/5'
                    : 'text-[#4d6480] hover:text-falcon-muted hover:bg-falcon-hover/40'
                }`}
              >
                {tab.label}
                {tab.value !== 'all' && (
                  <span className="ml-1 text-[9px] text-falcon-subtle">
                    ({notifications.filter(n => typeToTab(n.type) === tab.value).length})
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Notification List */}
          <div className="flex-1 overflow-y-auto divide-y divide-falcon-border/50">
            {filteredNotifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
                <Bell className="w-8 h-8 text-falcon-border mb-3" />
                <p className="text-sm text-[#4d6480]">通知はありません</p>
                <p className="text-[11px] text-falcon-subtle mt-1">
                  {activeTab !== 'all' ? 'このカテゴリに通知はありません' : '現在、新しい通知はありません'}
                </p>
              </div>
            ) : (
              filteredNotifications.map(notification => (
                <NotificationItem
                  key={notification.id}
                  notification={notification}
                  onRead={(id) => markReadMutation.mutate(id)}
                  onClick={handleNotificationClick}
                />
              ))
            )}
          </div>

          {/* Panel Footer */}
          {filteredNotifications.length > 0 && (
            <div className="border-t border-falcon-border px-4 py-2.5 flex items-center justify-between">
              <button
                onClick={clearAll}
                className="text-[11px] text-[#4d6480] hover:text-falcon-red transition-colors
                           px-2 py-1 rounded hover:bg-falcon-red/10"
              >
                すべてクリア
              </button>
              <button
                onClick={() => {
                  setOpen(false)
                  router.push('/admin/audit-logs')
                }}
                className="text-[11px] text-[#4d8fff] hover:text-[#7daaff] transition-colors
                           px-2 py-1 rounded hover:bg-[#4d8fff]/10"
              >
                View all →
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
