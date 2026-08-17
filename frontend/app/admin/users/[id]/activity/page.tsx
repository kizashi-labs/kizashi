'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams, useRouter } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  ArrowLeft,
  LogIn,
  ShieldAlert,
  Siren,
  BookOpen,
  Settings,
  User,
  Activity,
  Clock,
  Globe,
  ChevronDown,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface UserDetail {
  id: string
  email: string
  full_name: string
  role: string
  is_active: boolean
  created_at: string
  last_login?: string
}

interface AuditLog {
  id: string
  user_id: string
  action_type: string
  action: string
  resource_type?: string
  resource_id?: string
  ip_address?: string
  user_agent?: string
  created_at: string
  status?: string
}

interface AuditLogsResponse {
  data: AuditLog[]
  total: number
}

type DateRange = '7days' | '30days' | 'all'
type ActionFilter = 'all' | 'login' | 'alert' | 'incident' | 'rule' | 'settings'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function timeAgo(dateStr: string): string {
  const now = Date.now()
  const then = new Date(dateStr).getTime()
  const diff = Math.floor((now - then) / 1000)
  if (diff < 60)    return `${diff}秒前`
  if (diff < 3600)  return `${Math.floor(diff / 60)}分前`
  if (diff < 86400) return `${Math.floor(diff / 3600)}時間前`
  return `${Math.floor(diff / 86400)}日前`
}

function getDateRangeStart(range: DateRange): Date | null {
  if (range === 'all') return null
  const d = new Date()
  if (range === '7days')  d.setDate(d.getDate() - 7)
  if (range === '30days') d.setDate(d.getDate() - 30)
  return d
}

function matchesActionFilter(log: AuditLog, filter: ActionFilter): boolean {
  if (filter === 'all') return true
  const t = log.action_type?.toLowerCase() ?? ''
  const a = log.action?.toLowerCase() ?? ''
  if (filter === 'login')    return t === 'login' || a.includes('login') || a.includes('auth')
  if (filter === 'alert')    return t === 'alert' || a.includes('alert')
  if (filter === 'incident') return t === 'incident' || a.includes('incident')
  if (filter === 'rule')     return t === 'rule' || a.includes('rule')
  if (filter === 'settings') return t === 'settings' || t === 'config' || a.includes('setting') || a.includes('config')
  return false
}

// ─── Action icon + color ──────────────────────────────────────────────────────

interface ActionStyle {
  icon: React.ReactNode
  dotColor: string
  label: string
}

function getActionStyle(log: AuditLog): ActionStyle {
  const t = log.action_type?.toLowerCase() ?? ''
  const a = log.action?.toLowerCase() ?? ''

  if (t === 'login' || a.includes('login') || a.includes('auth')) {
    return {
      icon: <LogIn className="w-4 h-4 text-green-400" />,
      dotColor: 'bg-green-500',
      label: 'ログイン',
    }
  }
  if (t === 'alert' || a.includes('alert')) {
    return {
      icon: <ShieldAlert className="w-4 h-4 text-orange-400" />,
      dotColor: 'bg-orange-500',
      label: 'アラート操作',
    }
  }
  if (t === 'incident' || a.includes('incident')) {
    return {
      icon: <Siren className="w-4 h-4 text-red-400" />,
      dotColor: 'bg-red-500',
      label: 'インシデント操作',
    }
  }
  if (t === 'rule' || a.includes('rule')) {
    return {
      icon: <BookOpen className="w-4 h-4 text-purple-400" />,
      dotColor: 'bg-purple-500',
      label: 'ルール操作',
    }
  }
  if (t === 'settings' || t === 'config' || a.includes('setting')) {
    return {
      icon: <Settings className="w-4 h-4 text-blue-400" />,
      dotColor: 'bg-blue-500',
      label: '設定変更',
    }
  }
  return {
    icon: <Activity className="w-4 h-4 text-gray-400" />,
    dotColor: 'bg-gray-500',
    label: 'アクション',
  }
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon,
  color = 'text-white',
}: {
  label: string
  value: string | number
  icon: React.ReactNode
  color?: string
}) {
  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-3">
      <div className="flex items-center gap-2">
        <div className="text-gray-400">{icon}</div>
        <p className="text-xs text-gray-400 uppercase tracking-wide">{label}</p>
      </div>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )
}

// ─── Filter button ────────────────────────────────────────────────────────────

function FilterButton<T extends string>({
  value,
  current,
  onClick,
  children,
}: {
  value: T
  current: T
  onClick: (v: T) => void
  children: React.ReactNode
}) {
  const active = value === current
  return (
    <button
      onClick={() => onClick(value)}
      className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
        active
          ? 'bg-blue-600 text-white border-blue-600'
          : 'bg-gray-800 text-gray-400 border-gray-700 hover:text-gray-200 hover:border-gray-600'
      }`}
    >
      {children}
    </button>
  )
}

// ─── Timeline entry ───────────────────────────────────────────────────────────

function TimelineEntry({ log, isLast }: { log: AuditLog; isLast: boolean }) {
  const style = getActionStyle(log)
  return (
    <div className="relative flex items-start gap-4 pb-6">
      {/* Vertical line */}
      {!isLast && (
        <div className="absolute left-[15px] top-8 bottom-0 w-px bg-gray-700" />
      )}

      {/* Icon dot */}
      <div
        className={`relative z-10 w-8 h-8 rounded-full border-2 border-gray-900 ${style.dotColor}
                    flex items-center justify-center shrink-0`}
      >
        {style.icon}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0 bg-gray-800 rounded-xl border border-gray-700 p-4">
        <div className="flex items-start justify-between gap-2 flex-wrap">
          <div className="min-w-0">
            <p className="text-sm font-medium text-white truncate">
              {log.action}
            </p>
            <p className="text-xs text-gray-500 mt-0.5">{style.label}</p>
          </div>
          <div className="text-right shrink-0">
            <p className="text-xs text-gray-400 whitespace-nowrap">
              {new Date(log.created_at).toLocaleString('ja-JP')}
            </p>
            <p className="text-xs text-gray-600">{timeAgo(log.created_at)}</p>
          </div>
        </div>

        {log.ip_address && (
          <div className="flex items-center gap-1.5 mt-2 pt-2 border-t border-gray-700">
            <Globe className="w-3 h-3 text-gray-500 shrink-0" />
            <span className="text-xs text-gray-500 font-mono">{log.ip_address}</span>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function PageSkeleton() {
  return (
    <div className="min-h-screen bg-gray-900 p-6 space-y-6 animate-pulse">
      <div className="flex items-center gap-3">
        <div className="w-28 h-9 bg-gray-800 rounded-lg" />
        <div className="h-8 bg-gray-800 rounded-sm w-64" />
      </div>
      <div className="grid grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => <div key={i} className="h-28 bg-gray-800 rounded-xl" />)}
      </div>
      <div className="h-64 bg-gray-800 rounded-xl" />
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function UserActivityPage() {
  const params = useParams()
  const router = useRouter()
  const userId = params.id as string

  const [dateRange, setDateRange] = useState<DateRange>('30days')
  const [actionFilter, setActionFilter] = useState<ActionFilter>('all')
  const [visibleCount, setVisibleCount] = useState(20)

  // Fetch user
  const { data: user, isLoading: userLoading } = useQuery<UserDetail>({
    queryKey: ['user', userId],
    queryFn: () => apiFetch<UserDetail>(`/api/v1/users/${userId}`),
    enabled: !!userId,
  })

  // Fetch audit logs
  const { data: logsData, isLoading: logsLoading } = useQuery<AuditLogsResponse>({
    queryKey: ['audit-logs-user', userId],
    queryFn: () =>
      apiFetch<AuditLogsResponse>(`/api/v1/audit-logs?user_id=${userId}&limit=100`),
    enabled: !!userId,
  })

  const allLogs = logsData?.data ?? []

  // Filter logs
  const filteredLogs = useMemo(() => {
    const rangeStart = getDateRangeStart(dateRange)
    return allLogs.filter(log => {
      if (rangeStart && new Date(log.created_at) < rangeStart) return false
      return matchesActionFilter(log, actionFilter)
    })
  }, [allLogs, dateRange, actionFilter])

  // Stats (computed from full log list, not filtered)
  const totalActions = allLogs.length
  const loginCount = allLogs.filter(
    l => l.action_type === 'login' || l.action?.toLowerCase().includes('login'),
  ).length
  const alertOps = allLogs.filter(
    l => l.action_type === 'alert' || l.action?.toLowerCase().includes('alert'),
  ).length
  const lastActivity = allLogs[0]?.created_at ?? user?.last_login ?? null

  // Login history table rows
  const loginLogs = allLogs.filter(
    l => l.action_type === 'login' || l.action?.toLowerCase().includes('login'),
  )

  const visibleLogs = filteredLogs.slice(0, visibleCount)
  const hasMore = filteredLogs.length > visibleCount

  if (userLoading) return <PageSkeleton />

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="max-w-(--breakpoint-xl) mx-auto p-6 space-y-6">

        {/* ── Header ─────────────────────────────────────────────── */}
        <div className="flex items-center gap-3 flex-wrap">
          <button
            onClick={() => router.push('/admin/users')}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-gray-400 bg-gray-800
                       border border-gray-700 rounded-lg hover:bg-gray-700 hover:text-gray-200
                       transition-colors shrink-0"
          >
            <ArrowLeft className="w-4 h-4" />
            ユーザー管理
          </button>

          <div className="flex items-center gap-3 min-w-0">
            <div className="w-9 h-9 rounded-full bg-blue-900/40 border border-blue-700/50
                            flex items-center justify-center shrink-0">
              <User className="w-5 h-5 text-blue-400" />
            </div>
            <div className="min-w-0">
              <h1 className="text-xl font-bold text-white truncate">
                ユーザーアクティビティ
              </h1>
              {user && (
                <p className="text-sm text-gray-400 truncate">
                  {user.full_name || user.email}
                </p>
              )}
            </div>
          </div>
        </div>

        {/* ── Stats row ──────────────────────────────────────────── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            label="総アクション数"
            value={logsLoading ? '…' : totalActions}
            icon={<Activity className="w-4 h-4" />}
            color="text-white"
          />
          <StatCard
            label="ログイン回数"
            value={logsLoading ? '…' : loginCount}
            icon={<LogIn className="w-4 h-4" />}
            color="text-green-400"
          />
          <StatCard
            label="アラート操作"
            value={logsLoading ? '…' : alertOps}
            icon={<ShieldAlert className="w-4 h-4" />}
            color="text-orange-400"
          />
          <StatCard
            label="最終アクティビティ"
            value={logsLoading ? '…' : lastActivity ? timeAgo(lastActivity) : '—'}
            icon={<Clock className="w-4 h-4" />}
            color="text-blue-400"
          />
        </div>

        {/* ── Filters ────────────────────────────────────────────── */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-4">
          <div className="flex flex-wrap items-center gap-4">
            {/* Date range */}
            <div className="space-y-1">
              <p className="text-xs text-gray-500 uppercase tracking-wide">期間</p>
              <div className="flex items-center gap-2">
                <FilterButton value="7days"  current={dateRange} onClick={setDateRange}>過去7日</FilterButton>
                <FilterButton value="30days" current={dateRange} onClick={setDateRange}>過去30日</FilterButton>
                <FilterButton value="all"    current={dateRange} onClick={setDateRange}>全期間</FilterButton>
              </div>
            </div>

            <div className="w-px h-8 bg-gray-700 hidden sm:block" />

            {/* Action type */}
            <div className="space-y-1">
              <p className="text-xs text-gray-500 uppercase tracking-wide">アクション種別</p>
              <div className="flex items-center gap-2 flex-wrap">
                <FilterButton value="all"      current={actionFilter} onClick={setActionFilter}>すべて</FilterButton>
                <FilterButton value="login"    current={actionFilter} onClick={setActionFilter}>ログイン</FilterButton>
                <FilterButton value="alert"    current={actionFilter} onClick={setActionFilter}>アラート</FilterButton>
                <FilterButton value="incident" current={actionFilter} onClick={setActionFilter}>インシデント</FilterButton>
                <FilterButton value="rule"     current={actionFilter} onClick={setActionFilter}>ルール</FilterButton>
                <FilterButton value="settings" current={actionFilter} onClick={setActionFilter}>設定</FilterButton>
              </div>
            </div>
          </div>
        </div>

        {/* ── Timeline ───────────────────────────────────────────── */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
          <h2 className="text-base font-semibold text-white mb-6 flex items-center gap-2">
            <Activity className="w-4 h-4 text-gray-400" />
            アクティビティタイムライン
            <span className="text-xs text-gray-500 font-normal ml-1">
              ({filteredLogs.length}件)
            </span>
          </h2>

          {logsLoading ? (
            <div className="space-y-4 animate-pulse">
              {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-gray-700 shrink-0" />
                  <div className="flex-1 h-20 bg-gray-700 rounded-xl" />
                </div>
              ))}
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 gap-2">
              <Activity className="w-8 h-8 text-gray-600" />
              <p className="text-gray-500 text-sm">アクティビティが見つかりません</p>
            </div>
          ) : (
            <>
              <div className="pl-2">
                {visibleLogs.map((log, idx) => (
                  <TimelineEntry
                    key={log.id}
                    log={log}
                    isLast={idx === visibleLogs.length - 1 && !hasMore}
                  />
                ))}
              </div>

              {/* Load more */}
              {hasMore && (
                <div className="flex justify-center pt-2">
                  <button
                    onClick={() => setVisibleCount(c => c + 20)}
                    className="flex items-center gap-2 px-5 py-2 text-sm text-gray-400
                               bg-gray-700 hover:bg-gray-600 border border-gray-600
                               rounded-lg transition-colors hover:text-gray-200"
                  >
                    <ChevronDown className="w-4 h-4" />
                    もっと見る ({filteredLogs.length - visibleCount}件)
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        {/* ── Login history table ─────────────────────────────────── */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <LogIn className="w-4 h-4 text-green-400" />
              ログイン履歴
              <span className="text-xs text-gray-500 font-normal ml-1">
                ({loginLogs.length}件)
              </span>
            </h2>
          </div>

          {logsLoading ? (
            <div className="flex items-center justify-center h-24">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : loginLogs.length === 0 ? (
            <div className="flex items-center justify-center h-20">
              <p className="text-gray-500 text-sm">ログイン履歴がありません</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 bg-gray-900/30">
                    <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                      日時
                    </th>
                    <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                      IPアドレス
                    </th>
                    <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                      ユーザーエージェント
                    </th>
                    <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                      ステータス
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {loginLogs.map(log => (
                    <tr key={log.id} className="hover:bg-gray-700/30 transition-colors">
                      <td className="px-6 py-3 text-gray-300 text-xs whitespace-nowrap">
                        {new Date(log.created_at).toLocaleString('ja-JP')}
                      </td>
                      <td className="px-6 py-3">
                        <span className="text-gray-300 text-xs font-mono">
                          {log.ip_address ?? '—'}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        <span
                          className="text-gray-500 text-xs max-w-xs truncate block"
                          title={log.user_agent ?? ''}
                        >
                          {log.user_agent ?? '—'}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        {log.status === 'failed' ? (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-red-900/40 text-red-300 border border-red-700/40">
                            失敗
                          </span>
                        ) : (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-green-900/40 text-green-300 border border-green-700/40">
                            成功
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
