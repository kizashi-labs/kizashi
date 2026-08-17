'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Activity, Clock, RefreshCw, Filter, Cpu, Network,
  FileText, Globe, KeyRound, ChevronRight
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

type EventType = 'process' | 'network' | 'file' | 'dns' | 'auth'
type TimeRange = '1h' | '24h' | '7d'

interface SecurityEvent {
  id: string
  timestamp: string
  event_type: EventType
  severity: number   // 0=info, 1=low, 2=medium, 3=high, 4=critical
  agent_hostname: string
  description: string
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtTime(iso: string): string {
  try { return new Date(iso).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) }
  catch { return '—' }
}

function fmtGroupLabel(iso: string): string {
  try {
    const d = new Date(iso)
    const now = new Date()
    const diffMs = now.getTime() - d.getTime()
    const diffH = diffMs / 3600000

    if (diffH < 1) return 'Last Hour'
    if (diffH < 2) return '1–2 Hours Ago'
    if (diffH < 6) return '2–6 Hours Ago'
    if (diffH < 24) return `${Math.floor(diffH)} Hours Ago`
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  } catch { return '—' }
}

const SEVERITY_COLORS: Record<number, string> = {
  0: '#3b82f6',  // info - blue
  1: '#22c55e',  // low - green
  2: '#eab308',  // medium - yellow
  3: '#f97316',  // high - orange
  4: '#e8002d',  // critical - red
}

const SEVERITY_LABELS: Record<number, string> = {
  0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical',
}

const EVENT_TYPE_STYLES: Record<EventType, string> = {
  process: 'bg-purple-900/40 text-purple-300 border border-purple-700/40',
  network: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  file:    'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  dns:     'bg-teal-900/40 text-teal-300 border border-teal-700/40',
  auth:    'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
}

const EVENT_TYPE_ICONS: Record<EventType, React.ElementType> = {
  process: Cpu,
  network: Network,
  file:    FileText,
  dns:     Globe,
  auth:    KeyRound,
}

function getTimeRangeMs(range: TimeRange): number {
  return range === '1h' ? 3600000 : range === '24h' ? 86400000 : 604800000
}

// ── Filter Chip ───────────────────────────────────────────────────────────────

function FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
        active
          ? 'bg-falcon-red/20 text-falcon-red border-falcon-red/50'
          : 'bg-falcon-surface text-falcon-muted border-falcon-border hover:text-white hover:border-[#2a3f5c]'
      }`}
    >
      {label}
    </button>
  )
}

// ── Event Bubble ──────────────────────────────────────────────────────────────

function EventBubble({ event }: { event: SecurityEvent }) {
  const [expanded, setExpanded] = useState(false)
  const color = SEVERITY_COLORS[event.severity]
  const Icon = EVENT_TYPE_ICONS[event.event_type]

  return (
    <div className="flex gap-4 relative group">
      {/* Timeline dot */}
      <div className="flex flex-col items-center shrink-0 w-8">
        <div
          className="w-3 h-3 rounded-full border-2 border-[#070d19] z-10 mt-1"
          style={{ backgroundColor: color }}
        />
      </div>

      {/* Event card */}
      <div
        className="flex-1 bg-falcon-surface border border-falcon-border rounded-lg p-3 mb-3 cursor-pointer
                   hover:border-[#2a3f5c] transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs px-1.5 py-0.5 rounded-sm flex items-center gap-1 ${EVENT_TYPE_STYLES[event.event_type]}`}>
              <Icon className="w-3 h-3" />
              {event.event_type}
            </span>
            <span className="text-xs px-1.5 py-0.5 rounded-sm"
              style={{ backgroundColor: `${color}20`, color, border: `1px solid ${color}40` }}>
              {SEVERITY_LABELS[event.severity]}
            </span>
            <span className="text-falcon-muted text-xs font-mono">{event.agent_hostname}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-falcon-muted text-xs">{fmtTime(event.timestamp)}</span>
            <ChevronRight className={`w-3.5 h-3.5 text-falcon-subtle transition-transform ${expanded ? 'rotate-90' : ''}`} />
          </div>
        </div>

        <p className="text-white text-sm mt-2 font-mono text-xs break-all">{event.description}</p>

        {expanded && (
          <div className="mt-3 pt-3 border-t border-falcon-border grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="text-falcon-muted">Event ID: </span>
              <span className="text-white font-mono">{event.id}</span>
            </div>
            <div>
              <span className="text-falcon-muted">Timestamp: </span>
              <span className="text-white">{new Date(event.timestamp).toISOString()}</span>
            </div>
            <div>
              <span className="text-falcon-muted">Agent: </span>
              <span className="text-white">{event.agent_hostname}</span>
            </div>
            <div>
              <span className="text-falcon-muted">Severity: </span>
              <span style={{ color }}>{SEVERITY_LABELS[event.severity]} ({event.severity})</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function EventTimelinePage() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h')
  const [typeFilter, setTypeFilter] = useState<EventType | 'all'>('all')

  const { data: events = [], isLoading, refetch, isFetching } = useQuery<SecurityEvent[]>({
    queryKey: ['events-timeline', typeFilter, timeRange],
    queryFn: () => {
      const params = new URLSearchParams({ limit: '100' })
      if (typeFilter !== 'all') params.set('event_type', typeFilter)
      return apiFetch<{ events: SecurityEvent[] }>(`/api/v1/events?${params}`)
        .then(r => r.events)
        .catch(() => [])
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  })

  const filteredEvents = useMemo(() => {
    const cutoff = Date.now() - getTimeRangeMs(timeRange)
    return events.filter(e => {
      const ts = new Date(e.timestamp).getTime()
      if (ts < cutoff) return false
      if (typeFilter !== 'all' && e.event_type !== typeFilter) return false
      return true
    }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  }, [events, timeRange, typeFilter])

  // Group by approximate time bucket
  const grouped = useMemo(() => {
    const buckets: Map<string, SecurityEvent[]> = new Map()
    for (const ev of filteredEvents) {
      const label = fmtGroupLabel(ev.timestamp)
      if (!buckets.has(label)) buckets.set(label, [])
      buckets.get(label)!.push(ev)
    }
    return Array.from(buckets.entries())
  }, [filteredEvents])

  const criticalCount = filteredEvents.filter(e => e.severity === 4).length
  const highCount     = filteredEvents.filter(e => e.severity === 3).length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Activity className="w-7 h-7 text-falcon-red" />
            Security Event Timeline
          </h1>
          <p className="text-falcon-muted text-sm mt-1">
            Interactive timeline of endpoint security events
            {criticalCount > 0 && (
              <span className="ml-2 text-falcon-red font-medium">{criticalCount} critical</span>
            )}
            {highCount > 0 && (
              <span className="ml-2 text-orange-400 font-medium">{highCount} high</span>
            )}
          </p>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-2 px-3 py-2 bg-falcon-surface border border-falcon-border hover:bg-falcon-hover
                     text-falcon-muted hover:text-white rounded-lg text-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Time range + type filter bar */}
      <div className="flex items-center gap-4 mb-6 flex-wrap">
        {/* Time range */}
        <div className="flex items-center gap-1 bg-falcon-surface border border-falcon-border rounded-lg p-1">
          {([['1h', 'Last Hour'], ['24h', 'Last 24h'], ['7d', 'Last 7 days']] as [TimeRange, string][]).map(([v, l]) => (
            <button
              key={v}
              onClick={() => setTimeRange(v)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                timeRange === v ? 'bg-falcon-active text-white' : 'text-falcon-muted hover:text-white'
              }`}
            >
              {l}
            </button>
          ))}
        </div>

        {/* Type filter */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <Filter className="w-4 h-4 text-falcon-muted" />
          {(['all', 'process', 'network', 'file', 'dns', 'auth'] as const).map(t => (
            <FilterChip
              key={t}
              label={t === 'all' ? 'All Events' : t}
              active={typeFilter === t}
              onClick={() => setTypeFilter(t)}
            />
          ))}
        </div>

        {/* Event count */}
        <span className="text-falcon-muted text-xs ml-auto">
          {filteredEvents.length} event{filteredEvents.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Timeline */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <RefreshCw className="w-6 h-6 text-falcon-muted animate-spin" />
        </div>
      ) : filteredEvents.length === 0 ? (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl py-16 text-center">
          <Activity className="w-10 h-10 text-falcon-subtle mx-auto mb-3" />
          <p className="text-falcon-muted text-sm">No events found for the selected filters</p>
        </div>
      ) : (
        <div className="relative">
          {/* Vertical timeline line */}
          <div className="absolute left-[30px] top-0 bottom-0 w-px bg-falcon-border" />

          {grouped.map(([groupLabel, groupEvents]) => (
            <div key={groupLabel} className="mb-6">
              {/* Group label */}
              <div className="flex items-center gap-3 mb-4 relative z-10">
                <div className="w-8 shrink-0 flex justify-center">
                  <div className="w-2 h-2 rounded-full bg-falcon-border" />
                </div>
                <div className="flex items-center gap-2 px-3 py-1 bg-falcon-surface border border-falcon-border rounded-lg">
                  <Clock className="w-3.5 h-3.5 text-falcon-muted" />
                  <span className="text-falcon-muted text-xs font-medium">{groupLabel}</span>
                  <span className="text-falcon-subtle text-xs">({groupEvents.length})</span>
                </div>
              </div>

              {/* Events in group */}
              <div className="pl-0">
                {groupEvents.map(ev => (
                  <EventBubble key={ev.id} event={ev} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Severity legend */}
      <div className="mt-8 bg-falcon-surface border border-falcon-border rounded-lg p-4">
        <p className="text-falcon-muted text-xs mb-3 font-medium">Severity Legend</p>
        <div className="flex items-center gap-6 flex-wrap">
          {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
            <div key={sev} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-falcon-muted text-xs capitalize">{SEVERITY_LABELS[Number(sev)]}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
