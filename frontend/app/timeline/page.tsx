'use client'

import { useState, useEffect, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  Activity, ShieldAlert, ClipboardList, FolderOpen,
  Monitor, Search, ChevronRight, Calendar, AlertTriangle,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────

type EventType = 'alert' | 'audit' | 'fim' | 'agent'

interface TimelineEvent {
  id: string
  type: EventType
  title: string
  detail: string
  severity: number
  agent_id: string
  timestamp: string
  link: string
}

interface TimelineResponse {
  events: TimelineEvent[]
  total: number
}

type FilterType = 'all' | EventType

// ── Constants ──────────────────────────────────────────────────

const FILTER_PILLS: { value: FilterType; label: string }[] = [
  { value: 'all', label: 'すべて' },
  { value: 'alert', label: 'アラート' },
  { value: 'audit', label: '監査' },
  { value: 'fim', label: 'FIM' },
  { value: 'agent', label: 'エージェント' },
]

const TYPE_ICONS: Record<EventType, React.ComponentType<{ className?: string }>> = {
  alert: ShieldAlert,
  audit: ClipboardList,
  fim: FolderOpen,
  agent: Monitor,
}

const TYPE_LABELS: Record<EventType, string> = {
  alert: 'アラート',
  audit: '監査ログ',
  fim: 'ファイル変更',
  agent: 'エージェント',
}

const TYPE_BORDER: Record<EventType, string> = {
  alert: 'border-l-falcon-red',
  audit: 'border-l-blue-500',
  fim: 'border-l-yellow-500',
  agent: 'border-l-green-500',
}

const TYPE_ICON_COLOR: Record<EventType, string> = {
  alert: 'text-falcon-red bg-falcon-red/10',
  audit: 'text-blue-400 bg-blue-500/10',
  fim: 'text-yellow-400 bg-yellow-500/10',
  agent: 'text-green-400 bg-green-500/10',
}

function getSeverityColor(severity: number) {
  if (severity >= 9) return 'text-falcon-red bg-falcon-red/10'
  if (severity >= 7) return 'text-orange-400 bg-orange-500/10'
  if (severity >= 4) return 'text-yellow-400 bg-yellow-500/10'
  return 'text-green-400 bg-green-500/10'
}

function getSeverityLabel(severity: number) {
  if (severity >= 9) return 'Critical'
  if (severity >= 7) return 'High'
  if (severity >= 4) return 'Medium'
  return 'Low'
}

// ── Date grouping helpers ──────────────────────────────────────

function formatTimestamp(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString('ja-JP', {
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  } catch {
    return iso
  }
}

function getDateGroupKey(iso: string): string {
  try {
    return new Date(iso).toISOString().slice(0, 10)
  } catch {
    return iso
  }
}

function formatDateGroupLabel(dateKey: string): string {
  try {
    const date = new Date(dateKey)
    const today = new Date()
    const yesterday = new Date(today)
    yesterday.setDate(today.getDate() - 1)
    const weekAgo = new Date(today)
    weekAgo.setDate(today.getDate() - 7)

    const dk = dateKey
    const todayKey = today.toISOString().slice(0, 10)
    const yestKey = yesterday.toISOString().slice(0, 10)

    if (dk === todayKey) return '今日'
    if (dk === yestKey) return '昨日'
    if (date >= weekAgo) return '今週'
    return `${date.getMonth() + 1}月${date.getDate()}日`
  } catch {
    return dateKey
  }
}

// ── Skeleton ───────────────────────────────────────────────────

function SkeletonCard() {
  return (
    <div className="flex gap-4 p-4 bg-falcon-surface border border-falcon-border border-l-4 border-l-falcon-border rounded-lg animate-pulse">
      <div className="w-8 h-8 rounded-lg bg-falcon-border shrink-0" />
      <div className="flex-1 space-y-2">
        <div className="h-4 bg-falcon-border rounded-sm w-3/4" />
        <div className="h-3 bg-falcon-border rounded-sm w-full" />
        <div className="h-3 bg-falcon-border rounded-sm w-1/3" />
      </div>
    </div>
  )
}

// ── Event Card ─────────────────────────────────────────────────

function EventCard({ event }: { event: TimelineEvent }) {
  const Icon = TYPE_ICONS[event.type]
  const iconColor = TYPE_ICON_COLOR[event.type]
  const borderColor = TYPE_BORDER[event.type]

  return (
    <Link
      href={event.link}
      className={`flex gap-3 p-4 bg-falcon-surface border border-falcon-border border-l-4 ${borderColor}
                  rounded-lg hover:bg-[#0a1628] transition-colors group`}
    >
      {/* Icon */}
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${iconColor}`}>
        <Icon className="w-4 h-4" />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-start justify-between gap-2 mb-1">
          <p className="text-sm font-medium text-falcon-text group-hover:text-white transition-colors truncate">
            {event.title}
          </p>
          <div className="flex items-center gap-1.5 shrink-0">
            {event.type === 'alert' && event.severity > 0 && (
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-sm ${getSeverityColor(event.severity)}`}>
                {getSeverityLabel(event.severity)}
              </span>
            )}
            <ChevronRight className="w-3.5 h-3.5 text-falcon-subtle group-hover:text-falcon-muted transition-colors" />
          </div>
        </div>

        <p className="text-xs text-falcon-muted mb-2 line-clamp-2">{event.detail}</p>

        <div className="flex items-center gap-3">
          {/* Type badge */}
          <span className={`text-[10px] font-medium px-2 py-0.5 rounded-sm ${iconColor}`}>
            {TYPE_LABELS[event.type]}
          </span>

          {/* Agent badge */}
          {event.agent_id && (
            <span className="text-[10px] px-2 py-0.5 rounded-sm bg-falcon-border text-falcon-muted font-mono truncate max-w-[120px]">
              {event.agent_id.slice(0, 8)}…
            </span>
          )}

          {/* Timestamp */}
          <span className="text-[10px] text-falcon-subtle ml-auto shrink-0">
            {formatTimestamp(event.timestamp)}
          </span>
        </div>
      </div>
    </Link>
  )
}

// ── Date Group Header ──────────────────────────────────────────

function DateGroupHeader({ label, count }: { label: string; count: number }) {
  return (
    <div className="flex items-center gap-3 my-4">
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 rounded-sm bg-falcon-border flex items-center justify-center shrink-0">
          <Calendar className="w-3 h-3 text-falcon-muted" />
        </div>
        <span className="text-sm font-semibold text-falcon-text">{label}</span>
        <span className="text-xs text-falcon-subtle">({count}件)</span>
      </div>
      <div className="flex-1 h-px bg-falcon-border" />
    </div>
  )
}

// ── Page ───────────────────────────────────────────────────────

export default function TimelinePage() {
  const [activeFilter, setActiveFilter] = useState<FilterType>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [fromDate, setFromDate] = useState('')
  const [toDate, setToDate] = useState('')
  const [offset, setOffset] = useState(0)
  const [allEvents, setAllEvents] = useState<TimelineEvent[]>([])

  const buildUrl = (currentOffset: number) => {
    const params = new URLSearchParams({
      limit: '50',
      offset: String(currentOffset),
    })
    if (fromDate) params.set('from', fromDate)
    if (toDate) params.set('to', toDate)
    return `/api/v1/timeline?${params.toString()}`
  }

  const { data, isLoading, isFetching } = useQuery<TimelineResponse>({
    queryKey: ['timeline', offset, fromDate, toDate],
    queryFn: () => apiFetch(buildUrl(offset)),
  })

  // Accumulate events on new data
  useEffect(() => {
    if (data?.events) {
      if (offset === 0) {
        setAllEvents(data.events)
      } else {
        setAllEvents(prev => [...prev, ...data.events])
      }
    }
  }, [data, offset])

  // Reset when filters change
  useEffect(() => {
    setOffset(0)
    setAllEvents([])
  }, [fromDate, toDate])

  const total = data?.total ?? 0

  // Client-side filtering by type and search
  const filteredEvents = useMemo(() => {
    return allEvents.filter(ev => {
      const typeMatch = activeFilter === 'all' || ev.type === activeFilter
      const searchMatch = !searchQuery.trim() ||
        ev.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        ev.detail.toLowerCase().includes(searchQuery.toLowerCase())
      return typeMatch && searchMatch
    })
  }, [allEvents, activeFilter, searchQuery])

  // Group by date
  const groupedByDate = useMemo(() => {
    const groups: Record<string, TimelineEvent[]> = {}
    for (const ev of filteredEvents) {
      const key = getDateGroupKey(ev.timestamp)
      if (!groups[key]) groups[key] = []
      groups[key].push(ev)
    }
    return groups
  }, [filteredEvents])

  const sortedDateKeys = Object.keys(groupedByDate).sort((a, b) => b.localeCompare(a))

  const handleLoadMore = () => {
    setOffset(prev => prev + 50)
  }

  const hasMore = allEvents.length < total

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <div className="max-w-4xl mx-auto">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
              <Activity className="w-4 h-4 text-falcon-red" />
            </div>
            <h1 className="text-xl font-bold text-white">セキュリティタイムライン</h1>
          </div>
          <p className="text-falcon-muted text-sm ml-11">
            アラート・監査・FIM・エージェントイベントの時系列ビュー
          </p>
        </div>

        {/* Filter Bar */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4 mb-6 space-y-3">
          {/* Type pills */}
          <div className="flex gap-2 flex-wrap">
            {FILTER_PILLS.map(pill => (
              <button
                key={pill.value}
                onClick={() => setActiveFilter(pill.value)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-all ${
                  activeFilter === pill.value
                    ? 'bg-falcon-red/15 border-falcon-red/40 text-falcon-red'
                    : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40 hover:text-falcon-text'
                }`}
              >
                {pill.label}
              </button>
            ))}
          </div>

          {/* Search and date range */}
          <div className="flex gap-3 flex-wrap">
            {/* Search input */}
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="タイトル・詳細を検索..."
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg
                           pl-9 pr-3 py-2 text-sm text-falcon-text placeholder-falcon-subtle
                           focus:outline-hidden focus:border-falcon-red/50 transition-all"
              />
            </div>

            {/* Date from */}
            <div className="relative">
              <input
                type="date"
                value={fromDate}
                onChange={e => setFromDate(e.target.value)}
                className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2
                           text-sm text-falcon-text focus:outline-hidden focus:border-falcon-red/50
                           transition-all scheme-dark"
              />
            </div>

            <span className="self-center text-falcon-subtle text-sm">〜</span>

            {/* Date to */}
            <div className="relative">
              <input
                type="date"
                value={toDate}
                onChange={e => setToDate(e.target.value)}
                className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2
                           text-sm text-falcon-text focus:outline-hidden focus:border-falcon-red/50
                           transition-all scheme-dark"
              />
            </div>

            {/* Clear dates */}
            {(fromDate || toDate) && (
              <button
                onClick={() => { setFromDate(''); setToDate('') }}
                className="px-3 py-2 rounded-lg text-xs text-falcon-muted hover:text-white
                           bg-falcon-border hover:bg-falcon-border/80 transition-colors"
              >
                クリア
              </button>
            )}
          </div>
        </div>

        {/* Results meta */}
        {!isLoading && (
          <div className="flex items-center justify-between mb-3">
            <p className="text-xs text-falcon-muted">
              <span className="text-white font-medium">{filteredEvents.length}</span> 件表示
              {total > filteredEvents.length && (
                <span className="text-falcon-subtle"> / 全{total}件</span>
              )}
            </p>
            {(activeFilter !== 'all' || searchQuery) && (
              <button
                onClick={() => { setActiveFilter('all'); setSearchQuery('') }}
                className="text-xs text-falcon-subtle hover:text-falcon-muted transition-colors"
              >
                フィルターをクリア
              </button>
            )}
          </div>
        )}

        {/* Timeline content */}
        {isLoading && offset === 0 ? (
          <div className="space-y-3">
            {[1, 2, 3, 4, 5].map(i => <SkeletonCard key={i} />)}
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-12 text-center">
            <AlertTriangle className="w-10 h-10 text-falcon-border mx-auto mb-3" />
            <p className="text-sm font-medium text-falcon-muted mb-1">イベントが見つかりません</p>
            <p className="text-xs text-falcon-subtle">フィルターや日付範囲を変更してください</p>
          </div>
        ) : (
          <div>
            {sortedDateKeys.map(dateKey => {
              const events = groupedByDate[dateKey]
              const label = formatDateGroupLabel(dateKey)
              return (
                <div key={dateKey}>
                  <DateGroupHeader label={label} count={events.length} />
                  <div className="space-y-2">
                    {events.map(event => (
                      <EventCard key={event.id} event={event} />
                    ))}
                  </div>
                </div>
              )
            })}

            {/* Load More */}
            {hasMore && (
              <div className="mt-6 text-center">
                <button
                  onClick={handleLoadMore}
                  disabled={isFetching}
                  className="px-6 py-2.5 rounded-lg bg-falcon-surface border border-falcon-border
                             text-sm text-falcon-muted hover:text-white hover:border-falcon-muted/40
                             transition-all disabled:opacity-50 disabled:cursor-not-allowed
                             flex items-center gap-2 mx-auto"
                >
                  {isFetching ? (
                    <>
                      <Activity className="w-4 h-4 animate-spin" />
                      読み込み中...
                    </>
                  ) : (
                    <>
                      さらに読み込む
                      <span className="text-xs text-falcon-subtle">({total - allEvents.length}件残り)</span>
                    </>
                  )}
                </button>
              </div>
            )}

            {/* Skeleton for load more */}
            {isFetching && offset > 0 && (
              <div className="mt-3 space-y-3">
                {[1, 2, 3].map(i => <SkeletonCard key={i} />)}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
