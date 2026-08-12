'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Clock, AlertTriangle, Shield, Filter, Search,
  ChevronDown, ChevronRight, RefreshCw, Network,
  FileText, Terminal, Lock, Zap, Globe, Eye,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface TimelineEvent {
  id: string
  timestamp: string
  event_type: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  hostname: string
  agent_id: string
  mitre_technique?: string
  mitre_phase?: string
  raw_data?: Record<string, unknown>
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<string, { dot: string; bg: string; text: string; border: string; icon: React.ElementType }> = {
  Execution:       { dot: 'bg-purple-500', bg: 'bg-purple-900/20', text: 'text-purple-300', border: 'border-purple-700/50', icon: Terminal },
  Persistence:     { dot: 'bg-red-500',    bg: 'bg-red-900/20',    text: 'text-red-300',    border: 'border-red-700/50',    icon: Lock },
  Discovery:       { dot: 'bg-blue-500',   bg: 'bg-blue-900/20',   text: 'text-blue-300',   border: 'border-blue-700/50',   icon: Search },
  'Lateral Movement': { dot: 'bg-orange-500', bg: 'bg-orange-900/20', text: 'text-orange-300', border: 'border-orange-700/50', icon: Network },
  Exfiltration:    { dot: 'bg-yellow-500', bg: 'bg-yellow-900/20', text: 'text-yellow-300', border: 'border-yellow-700/50', icon: Globe },
  C2:              { dot: 'bg-red-600 animate-pulse', bg: 'bg-red-900/30', text: 'text-red-300', border: 'border-red-600/60', icon: Globe },
  'Defense Evasion': { dot: 'bg-zinc-500', bg: 'bg-zinc-800/60', text: 'text-zinc-300', border: 'border-zinc-600/50', icon: Eye },
}

const DEFAULT_CFG = { dot: 'bg-zinc-500', bg: 'bg-zinc-800/40', text: 'text-zinc-300', border: 'border-zinc-700/50', icon: Shield }

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-300 border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border-blue-700',
  info:     'bg-zinc-800 text-zinc-400 border-zinc-700',
}

function formatTime(ts: string): { time: string; date: string } {
  const d = new Date(ts)
  const now = new Date()
  const sameDay = d.toDateString() === now.toDateString()
  return {
    time: d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }),
    date: sameDay ? '' : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
  }
}

type Mode = 'agent' | 'incident' | 'alert'

// ─── Event Card ────────────────────────────────────────────────────────────────

function EventCard({ event }: { event: TimelineEvent }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = CATEGORY_CONFIG[event.category] ?? DEFAULT_CFG
  const Icon = cfg.icon
  const { time, date } = formatTime(event.timestamp)

  return (
    <div className="flex gap-4 group">
      {/* Timestamp */}
      <div className="w-24 shrink-0 text-right pt-3">
        <div className="text-sm font-mono text-zinc-300">{time}</div>
        {date && <div className="text-xs text-zinc-500">{date}</div>}
      </div>

      {/* Timeline dot + line */}
      <div className="flex flex-col items-center">
        <div className={`w-3 h-3 rounded-full mt-3.5 shrink-0 ring-2 ring-zinc-950 ${cfg.dot}`} />
        <div className="flex-1 w-px bg-zinc-800 mt-1" />
      </div>

      {/* Event card */}
      <div className={`flex-1 mb-3 border rounded-xl p-3 ${cfg.bg} ${cfg.border} transition-all`}>
        <div className="flex items-start justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <Icon className={`w-4 h-4 shrink-0 ${cfg.text}`} />
            <span className={`text-xs font-medium px-2 py-0.5 rounded border ${cfg.bg} ${cfg.text} ${cfg.border}`}>
              {event.category}
            </span>
            <span className={`text-xs font-medium px-2 py-0.5 rounded border ${SEVERITY_COLORS[event.severity]}`}>
              {event.severity.toUpperCase()}
            </span>
            {event.mitre_technique && (
              <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700 font-mono">
                {event.mitre_technique}
              </span>
            )}
          </div>
        </div>

        <div className="mt-2">
          <div className="font-semibold text-sm text-zinc-100">{event.title}</div>
          <div className="text-xs text-zinc-400 mt-0.5">{event.description}</div>
        </div>

        <div className="mt-2 flex items-center gap-3 flex-wrap">
          <span className="text-xs text-zinc-500">{event.hostname}</span>
          <span className="text-xs text-zinc-600 font-mono">{event.agent_id}</span>
          {event.event_type && (
            <span className="text-xs text-zinc-600">#{event.event_type}</span>
          )}
        </div>

        {/* Raw data toggle */}
        {event.raw_data && (
          <button
            onClick={() => setExpanded(v => !v)}
            className="mt-2 flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
            Details
          </button>
        )}

        {expanded && event.raw_data && (
          <div className="mt-2 bg-zinc-950 border border-zinc-800 rounded-lg p-3">
            <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap overflow-x-auto">
              {JSON.stringify(event.raw_data, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function AttackTimelinePage() {
  const [mode, setMode] = useState<Mode>('agent')
  const [agentId, setAgentId] = useState('a001')
  const [incidentId, setIncidentId] = useState('')
  const [alertId, setAlertId] = useState('')
  const [hours, setHours] = useState(24)
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [isLoaded, setIsLoaded] = useState(true)
  const [loading, setLoading] = useState(false)
  const [filterCategory, setFilterCategory] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [searchText, setSearchText] = useState('')

  const handleLoad = async () => {
    setLoading(true)
    try {
      let url = ''
      if (mode === 'agent') url = `/api/v1/agents/${agentId}/timeline?hours=${hours}`
      else if (mode === 'incident') url = `/api/v1/admin/incidents/${incidentId}/timeline`
      else url = `/api/v1/alerts/${alertId}/timeline`
      const data = await apiFetchList<TimelineEvent>(url)
      setEvents(data)
    } catch {
      setEvents([])
    } finally {
      setLoading(false)
      setIsLoaded(true)
    }
  }

  const filteredEvents = events.filter(e => {
    if (filterCategory && e.category !== filterCategory) return false
    if (filterSeverity && e.severity !== filterSeverity) return false
    if (searchText && !e.title.toLowerCase().includes(searchText.toLowerCase()) &&
        !e.description.toLowerCase().includes(searchText.toLowerCase())) return false
    return true
  })

  const categories = [...new Set(events.map(e => e.category))]
  const mitrePhases = [...new Set(events.filter(e => e.mitre_phase).map(e => e.mitre_phase!))]
  const alertCount = events.filter(e => e.severity === 'critical' || e.severity === 'high').length

  const firstTs = events.length ? new Date(events[0].timestamp) : null
  const lastTs = events.length ? new Date(events[events.length - 1].timestamp) : null
  const spanMinutes = firstTs && lastTs ? Math.round((lastTs.getTime() - firstTs.getTime()) / 60000) : 0

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="p-2 bg-blue-900/40 rounded-lg border border-blue-700/50">
          <Clock className="w-6 h-6 text-blue-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Attack Timeline</h1>
          <p className="text-sm text-zinc-400">Chronological event visualization for incident investigation</p>
        </div>
      </div>

      {/* Mode Tabs */}
      <div className="flex gap-1 mb-4 bg-zinc-900 border border-zinc-800 rounded-xl p-1 w-fit">
        {(['agent', 'incident', 'alert'] as Mode[]).map(m => (
          <button
            key={m}
            onClick={() => setMode(m)}
            className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${
              mode === m
                ? 'bg-blue-900/50 text-blue-200 border border-blue-700/60'
                : 'text-zinc-400 hover:text-zinc-300'
            }`}
          >
            {m === 'agent' ? 'Agent Timeline' : m === 'incident' ? 'Incident Timeline' : 'Alert Timeline'}
          </button>
        ))}
      </div>

      {/* Input Controls */}
      <div className="flex items-end gap-3 mb-6">
        {mode === 'agent' && (
          <>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Agent ID</label>
              <input
                type="text"
                value={agentId}
                onChange={e => setAgentId(e.target.value)}
                placeholder="e.g. a001"
                className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-blue-500 w-40"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Hours</label>
              <select
                value={hours}
                onChange={e => setHours(Number(e.target.value))}
                className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 focus:outline-none focus:border-blue-500"
              >
                {[1, 6, 24, 72].map(h => <option key={h} value={h}>{h}h</option>)}
              </select>
            </div>
          </>
        )}
        {mode === 'incident' && (
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Incident ID</label>
            <input
              type="text"
              value={incidentId}
              onChange={e => setIncidentId(e.target.value)}
              placeholder="e.g. INC-001"
              className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-blue-500 w-40"
            />
          </div>
        )}
        {mode === 'alert' && (
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Alert ID</label>
            <input
              type="text"
              value={alertId}
              onChange={e => setAlertId(e.target.value)}
              placeholder="e.g. alert-001"
              className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-blue-500 w-40"
            />
          </div>
        )}
        <button
          onClick={handleLoad}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-blue-700 hover:bg-blue-600 disabled:bg-zinc-700 disabled:text-zinc-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Clock className="w-4 h-4" />}
          {loading ? '読み込み中...' : 'タイムラインを読み込む'}
        </button>
      </div>

      {isLoaded && (
        <>
          {/* MITRE Phases */}
          {mitrePhases.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-4">
              <span className="text-xs text-zinc-500 self-center">MITRE Phases:</span>
              {mitrePhases.map(phase => (
                <span key={phase} className="text-xs px-2.5 py-1 bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-full">
                  {phase}
                </span>
              ))}
            </div>
          )}

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            {[
              { label: 'Total Events', value: events.length, color: 'text-zinc-100' },
              { label: 'Alerts', value: alertCount, color: 'text-red-400' },
              { label: 'Time Span', value: `${spanMinutes}m`, color: 'text-blue-400' },
              { label: 'Phases Detected', value: mitrePhases.length, color: 'text-purple-400' },
            ].map(s => (
              <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-xl p-3 text-center">
                <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-zinc-500 mt-0.5">{s.label}</div>
              </div>
            ))}
          </div>

          {/* Filters */}
          <div className="flex flex-wrap gap-3 mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
              <input
                type="text"
                placeholder="Search events..."
                value={searchText}
                onChange={e => setSearchText(e.target.value)}
                className="pl-9 pr-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <select
              value={filterCategory}
              onChange={e => setFilterCategory(e.target.value)}
              className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 focus:outline-none focus:border-blue-500"
            >
              <option value="">All Categories</option>
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <select
              value={filterSeverity}
              onChange={e => setFilterSeverity(e.target.value)}
              className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 focus:outline-none focus:border-blue-500"
            >
              <option value="">All Severities</option>
              {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            {(filterCategory || filterSeverity || searchText) && (
              <button
                onClick={() => { setFilterCategory(''); setFilterSeverity(''); setSearchText('') }}
                className="px-3 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 rounded-lg text-sm border border-zinc-700 transition-colors"
              >
                Clear
              </button>
            )}
          </div>

          {/* Timeline */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <div className="relative">
              {filteredEvents.map(event => (
                <EventCard key={event.id} event={event} />
              ))}
              {filteredEvents.length === 0 && (
                <div className="text-center py-10 text-zinc-500">No events match current filters</div>
              )}
            </div>
          </div>
        </>
      )}

      {!isLoaded && !loading && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
          <Clock className="w-12 h-12 mb-3 opacity-30" />
          <p className="text-lg">Load a timeline to begin investigation</p>
        </div>
      )}
    </div>
  )
}
