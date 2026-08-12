'use client'

import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Search, Play, Plus, X, Download,
  AlertTriangle, Loader2, ChevronDown, ChevronRight,
  Shield, Crosshair, FileSearch, BookOpen,
} from 'lucide-react'


// ── Types ────────────────────────────────────────────────────────────────────

interface QueryFilter {
  id: string
  field: string
  operator: string
  value: string
}

interface TimeRange {
  last?: string
  start?: string
  end?: string
}

interface HuntingQuery {
  event_types: string[]
  filters: Omit<QueryFilter, 'id'>[]
  time_range: TimeRange
  limit: number
  order_by: string
  agent_ids?: string[]
}

interface HuntingResult {
  event_id: string
  agent_id: string
  hostname: string
  event_type: string
  timestamp: string
  severity: number
  data: Record<string, unknown>
}

interface QueryResult {
  total: number
  returned: number
  time_taken: string
  results: HuntingResult[]
}

interface SavedQueryDef {
  id: string
  name: string
  description: string
  query: HuntingQuery
}

interface SavedQueriesResponse {
  queries: SavedQueryDef[]
}

// ── Constants ────────────────────────────────────────────────────────────────

const EVENT_TYPES = ['process', 'network', 'file', 'dns', 'registry', 'auth'] as const

const EVENT_TYPE_COLORS: Record<string, string> = {
  process:  'bg-blue-900/60 text-blue-300 border-blue-700',
  network:  'bg-purple-900/60 text-purple-300 border-purple-700',
  file:     'bg-amber-900/60 text-amber-300 border-amber-700',
  dns:      'bg-cyan-900/60 text-cyan-300 border-cyan-700',
  registry: 'bg-green-900/60 text-green-300 border-green-700',
  auth:     'bg-red-900/60 text-red-300 border-red-700',
}

const TIME_RANGES = ['15m', '1h', '6h', '24h', '7d', '30d'] as const

const FILTER_FIELDS = [
  { value: 'process_name', label: 'Process Name' },
  { value: 'cmdline',      label: 'Command Line' },
  { value: 'file_path',    label: 'File Path' },
  { value: 'src_ip',       label: 'Source IP' },
  { value: 'dst_ip',       label: 'Dest IP' },
  { value: 'domain',       label: 'Domain' },
  { value: 'hostname',     label: 'Hostname' },
  { value: 'username',     label: 'Username' },
  { value: 'hash',         label: 'File Hash' },
]

const OPERATORS = [
  { value: 'contains', label: 'Contains' },
  { value: 'eq',       label: 'Equals' },
  { value: 'neq',      label: 'Not Equals' },
  { value: 'gt',       label: 'Greater Than' },
  { value: 'lt',       label: 'Less Than' },
]

const LIMIT_OPTIONS = [50, 100, 500]

const SEVERITY_LABELS: Record<number, { label: string; cls: string }> = {
  0: { label: 'Info',     cls: 'bg-zinc-700 text-zinc-300' },
  1: { label: 'Low',      cls: 'bg-blue-900/60 text-blue-300' },
  2: { label: 'Medium',   cls: 'bg-amber-900/60 text-amber-300' },
  3: { label: 'High',     cls: 'bg-orange-900/60 text-orange-300' },
  4: { label: 'Critical', cls: 'bg-red-900/60 text-red-300' },
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTs(ts: string) {
  try { return new Date(ts).toLocaleString() } catch { return ts }
}

function keyData(data: Record<string, unknown>): string {
  const keys = ['process_name', 'cmdline', 'file_path', 'src_ip', 'dst_ip', 'domain', 'username']
  for (const k of keys) {
    if (data[k]) return `${k}: ${String(data[k])}`
  }
  return Object.entries(data).slice(0, 2).map(([k, v]) => `${k}: ${String(v)}`).join(' | ')
}

function uid() { return Math.random().toString(36).slice(2, 9) }

// ── Component ────────────────────────────────────────────────────────────────

export default function ThreatHuntingQueryBuilder() {
  // Quick search state
  const [quickTerm, setQuickTerm] = useState('')
  const [quickType, setQuickType] = useState('')
  const [quickLast, setQuickLast] = useState('24h')

  // Query builder state
  const [selectedTypes, setSelectedTypes] = useState<string[]>([])
  const [timeRange, setTimeRange]         = useState<string>('24h')
  const [filters, setFilters]             = useState<QueryFilter[]>([])
  const [agentFilter, setAgentFilter]     = useState('')
  const [limit, setLimit]                 = useState(100)

  // Results state
  const [results, setResults]   = useState<QueryResult | null>(null)
  const [running, setRunning]   = useState(false)
  const [runError, setRunError] = useState('')

  // Expanded rows
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const { data: agentsData } = useQuery<{ data: { id: string; hostname: string }[] }>({
    queryKey: ['agents-for-hunting'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=500'),
    staleTime: 60_000,
  })
  const agentsList = agentsData?.data ?? []

  // Saved queries
  const { data: savedData } = useQuery<SavedQueriesResponse>({
    queryKey: ['hunting-saved-queries'],
    queryFn:  () => apiFetch('/api/v1/admin/hunting/saved-queries'),
  })

  const toggleType = useCallback((t: string) => {
    setSelectedTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])
  }, [])

  const addFilter = useCallback(() => {
    setFilters(prev => [...prev, { id: uid(), field: 'process_name', operator: 'contains', value: '' }])
  }, [])

  const removeFilter = useCallback((id: string) => {
    setFilters(prev => prev.filter(f => f.id !== id))
  }, [])

  const updateFilter = useCallback((id: string, key: keyof QueryFilter, val: string) => {
    setFilters(prev => prev.map(f => f.id === id ? { ...f, [key]: val } : f))
  }, [])

  const clearAll = useCallback(() => {
    setSelectedTypes([]); setTimeRange('24h'); setFilters([])
    setAgentFilter(''); setLimit(100); setResults(null); setRunError('')
  }, [])

  const loadSaved = useCallback((q: HuntingQuery) => {
    setSelectedTypes(q.event_types ?? [])
    setTimeRange(q.time_range?.last ?? '24h')
    setLimit(q.limit ?? 100)
    setFilters((q.filters ?? []).map(f => ({ id: uid(), field: f.field, operator: f.operator, value: f.value })))
  }, [])

  const runQuery = useCallback(async () => {
    setRunning(true); setRunError('')
    try {
      const body: HuntingQuery = {
        event_types: selectedTypes,
        filters:     filters.map(({ id: _id, ...rest }) => rest),
        time_range:  { last: timeRange },
        limit,
        order_by: 'desc',
      }
      if (agentFilter.trim()) {
        body.agent_ids = agentFilter.split(',').map(s => s.trim()).filter(Boolean)
      }
      const data = await apiFetch('/api/v1/admin/hunting/query', {
        method: 'POST',
        body: JSON.stringify(body),
      }) as QueryResult
      setResults(data)
    } catch {
      setResults(null)
    } finally {
      setRunning(false)
    }
  }, [selectedTypes, filters, timeRange, limit, agentFilter])

  const runQuickSearch = useCallback(async () => {
    setRunning(true); setRunError('')
    try {
      const params = new URLSearchParams({ last: quickLast })
      if (quickTerm) params.set('q', quickTerm)
      if (quickType) params.set('type', quickType)
      const data = await apiFetch(`/api/v1/admin/hunting/search?${params}`) as QueryResult
      setResults(data)
    } catch {
      setResults(null)
    } finally {
      setRunning(false)
    }
  }, [quickTerm, quickType, quickLast])

  const toggleExpand = useCallback((id: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }, [])

  const exportResults = useCallback(() => {
    if (!results) return
    const blob = new Blob([JSON.stringify(results.results, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = `hunt-results-${Date.now()}.json`; a.click()
    URL.revokeObjectURL(url)
  }, [results])

  const severityInfo = (s: number) => SEVERITY_LABELS[Math.min(s, 4)] ?? SEVERITY_LABELS[0]

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <Crosshair className="w-6 h-6 text-red-400" />
          <h1 className="text-2xl font-bold text-zinc-100">Threat Hunting</h1>
        </div>
        <p className="text-zinc-400 text-sm">Ad-hoc event investigation across all endpoint telemetry</p>
      </div>

      {/* Quick Search */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 mb-6">
        <div className="flex items-center gap-2 mb-3">
          <Search className="w-4 h-4 text-zinc-400" />
          <span className="text-sm font-medium text-zinc-300">Quick Search</span>
        </div>
        <div className="flex gap-2 flex-wrap">
          <input
            type="text"
            placeholder="Search term (process name, IP, domain...)"
            value={quickTerm}
            onChange={e => setQuickTerm(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runQuickSearch()}
            className="flex-1 min-w-48 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-red-500"
          />
          <select
            value={quickType}
            onChange={e => setQuickType(e.target.value)}
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-red-500"
          >
            <option value="">All Types</option>
            {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select
            value={quickLast}
            onChange={e => setQuickLast(e.target.value)}
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-red-500"
          >
            {TIME_RANGES.map(r => <option key={r} value={r}>Last {r}</option>)}
          </select>
          <button
            onClick={runQuickSearch}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
          >
            {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Search
          </button>
        </div>
      </div>

      {/* Two-panel layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Left: Query Builder */}
        <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-5 space-y-5">
          <div className="flex items-center gap-2">
            <FileSearch className="w-4 h-4 text-red-400" />
            <h2 className="font-semibold text-zinc-200">Query Builder</h2>
          </div>

          {/* Event Types */}
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-2 uppercase tracking-wider">Event Types</label>
            <div className="flex flex-wrap gap-2">
              {EVENT_TYPES.map(t => (
                <button
                  key={t}
                  onClick={() => toggleType(t)}
                  className={`px-3 py-1 rounded-full text-xs font-medium border transition-all ${
                    selectedTypes.includes(t)
                      ? EVENT_TYPE_COLORS[t]
                      : 'bg-zinc-800 text-zinc-400 border-zinc-700 hover:border-zinc-500'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
            {selectedTypes.length === 0 && (
              <p className="text-xs text-zinc-500 mt-1">No types selected = all types</p>
            )}
          </div>

          {/* Time Range */}
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-2 uppercase tracking-wider">Time Range</label>
            <div className="flex gap-2 flex-wrap">
              {TIME_RANGES.map(r => (
                <button
                  key={r}
                  onClick={() => setTimeRange(r)}
                  className={`px-3 py-1 rounded-lg text-xs font-medium border transition-colors ${
                    timeRange === r
                      ? 'bg-red-600 border-red-500 text-white'
                      : 'bg-zinc-800 border-zinc-700 text-zinc-300 hover:border-zinc-500'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

          {/* Filters */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Filters</label>
              <button
                onClick={addFilter}
                className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300 transition-colors"
              >
                <Plus className="w-3 h-3" /> Add Filter
              </button>
            </div>
            {filters.length === 0 && (
              <p className="text-xs text-zinc-500">No filters — returns all events in time range</p>
            )}
            <div className="space-y-2">
              {filters.map(f => (
                <div key={f.id} className="flex gap-2 items-center">
                  <select
                    value={f.field}
                    onChange={e => updateFilter(f.id, 'field', e.target.value)}
                    className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-red-500"
                  >
                    {FILTER_FIELDS.map(ff => <option key={ff.value} value={ff.value}>{ff.label}</option>)}
                  </select>
                  <select
                    value={f.operator}
                    onChange={e => updateFilter(f.id, 'operator', e.target.value)}
                    className="w-32 bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-1.5 text-xs text-zinc-100 focus:outline-none focus:border-red-500"
                  >
                    {OPERATORS.map(op => <option key={op.value} value={op.value}>{op.label}</option>)}
                  </select>
                  <input
                    type="text"
                    placeholder="Value"
                    value={f.value}
                    onChange={e => updateFilter(f.id, 'value', e.target.value)}
                    className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-1.5 text-xs text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-red-500"
                  />
                  <button onClick={() => removeFilter(f.id)} className="text-zinc-500 hover:text-red-400 transition-colors">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Agent Filter + Limit */}
          <div className="flex gap-4 flex-wrap">
            <div className="flex-1 min-w-48">
              <label className="block text-xs font-medium text-zinc-400 mb-1 uppercase tracking-wider">
                エージェントフィルター <span className="normal-case text-zinc-600">(省略可)</span>
              </label>
              <div className="border border-zinc-700 rounded-lg p-2 max-h-32 overflow-y-auto bg-zinc-800 space-y-1">
                {agentsList.length === 0 ? (
                  <p className="text-xs text-zinc-500 px-1">エージェントなし</p>
                ) : agentsList.map(a => {
                  const selected = agentFilter.split(',').map(s => s.trim()).includes(a.id)
                  return (
                    <label key={a.id} className="flex items-center gap-2 px-1 py-0.5 rounded hover:bg-zinc-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selected}
                        onChange={e => {
                          const current = agentFilter.split(',').map(s => s.trim()).filter(Boolean)
                          const next = e.target.checked ? [...current, a.id] : current.filter(id => id !== a.id)
                          setAgentFilter(next.join(', '))
                        }}
                        className="accent-red-500"
                      />
                      <span className="text-xs text-zinc-200">{a.hostname}</span>
                    </label>
                  )
                })}
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-1 uppercase tracking-wider">Result Limit</label>
              <select
                value={limit}
                onChange={e => setLimit(Number(e.target.value))}
                className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-red-500"
              >
                {LIMIT_OPTIONS.map(l => <option key={l} value={l}>{l}</option>)}
              </select>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 pt-1">
            <button
              onClick={runQuery}
              disabled={running}
              className="flex items-center gap-2 px-6 py-2.5 bg-red-600 hover:bg-red-500 disabled:opacity-50 rounded-lg font-medium transition-colors"
            >
              {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Run Hunt
            </button>
            <button
              onClick={clearAll}
              className="flex items-center gap-2 px-4 py-2.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-sm text-zinc-300 transition-colors"
            >
              <X className="w-4 h-4" /> Clear
            </button>
          </div>

          {runError && (
            <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-800 rounded-lg px-3 py-2">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {runError}
            </div>
          )}
        </div>

        {/* Right: Saved Queries */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <BookOpen className="w-4 h-4 text-zinc-400" />
            <h2 className="font-semibold text-zinc-200">Saved Queries</h2>
          </div>
          <div className="space-y-3 overflow-y-auto max-h-[520px] pr-1">
            {(savedData?.queries ?? []).map(sq => (
              <div key={sq.id} className="bg-zinc-800/60 border border-zinc-700 rounded-lg p-3">
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="text-sm font-medium text-zinc-200 leading-tight">{sq.name}</span>
                  <button
                    onClick={() => loadSaved(sq.query)}
                    className="flex-shrink-0 text-xs px-2 py-0.5 bg-red-900/40 hover:bg-red-800/60 border border-red-700 text-red-300 rounded transition-colors"
                  >
                    Load
                  </button>
                </div>
                <p className="text-xs text-zinc-500 mb-2">{sq.description}</p>
                <div className="flex flex-wrap gap-1">
                  {(sq.query.event_types ?? []).map(t => (
                    <span
                      key={t}
                      className={`px-1.5 py-0.5 rounded text-xs border ${EVENT_TYPE_COLORS[t] ?? 'bg-zinc-700 text-zinc-300 border-zinc-600'}`}
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
            {!savedData && (
              <div className="text-center py-6 text-zinc-500 text-sm">
                <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
                読み込み中...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Loading skeleton */}
      {running && !results && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-8 text-center">
          <Loader2 className="w-8 h-8 animate-spin text-red-400 mx-auto mb-3" />
          <p className="text-zinc-400">Running hunt query...</p>
          <div className="mt-4 space-y-2 max-w-xl mx-auto">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-10 bg-zinc-800 rounded-lg animate-pulse" />
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Shield className="w-4 h-4 text-red-400" />
              <span className="font-semibold text-zinc-200">
                {(results.total ?? 0).toLocaleString()} results
                {results.time_taken && (
                  <span className="text-zinc-500 font-normal ml-2 text-sm">in {results.time_taken}</span>
                )}
              </span>
              {results.returned < results.total && (
                <span className="text-xs text-amber-400 bg-amber-900/30 border border-amber-800 px-2 py-0.5 rounded">
                  Showing {results.returned}
                </span>
              )}
            </div>
            <button
              onClick={exportResults}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-sm text-zinc-300 transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> Export JSON
            </button>
          </div>

          {results.results.length === 0 ? (
            <div className="text-center py-12 text-zinc-500">
              <Search className="w-8 h-8 mx-auto mb-3 opacity-40" />
              <p>クエリに一致するイベントがありません</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800">
                    <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400 uppercase tracking-wider w-4" />
                    <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">Timestamp</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">Agent / Host</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">Event Type</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">Key Data</th>
                    <th className="text-left py-2 px-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {results.results.map(r => {
                    const isOpen = expanded.has(r.event_id)
                    const sev    = severityInfo(r.severity)
                    return (
                      <>
                        <tr
                          key={r.event_id}
                          onClick={() => toggleExpand(r.event_id)}
                          className="border-b border-zinc-800/50 hover:bg-zinc-800/40 cursor-pointer transition-colors"
                        >
                          <td className="py-2.5 px-3 text-zinc-500">
                            {isOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          </td>
                          <td className="py-2.5 px-3 text-zinc-300 whitespace-nowrap font-mono text-xs">
                            {formatTs(r.timestamp)}
                          </td>
                          <td className="py-2.5 px-3">
                            <div className="text-zinc-200 font-medium">{r.hostname}</div>
                            <div className="text-zinc-500 text-xs font-mono">{r.agent_id}</div>
                          </td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-xs border ${EVENT_TYPE_COLORS[r.event_type] ?? 'bg-zinc-700 text-zinc-300 border-zinc-600'}`}>
                              {r.event_type}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-zinc-300 font-mono text-xs max-w-xs truncate">
                            {keyData(r.data)}
                          </td>
                          <td className="py-2.5 px-3">
                            <span className={`px-2 py-0.5 rounded text-xs ${sev.cls}`}>{sev.label}</span>
                          </td>
                        </tr>
                        {isOpen && (
                          <tr key={`${r.event_id}-exp`} className="bg-zinc-800/30 border-b border-zinc-800/50">
                            <td colSpan={6} className="px-4 py-3">
                              <pre className="text-xs text-zinc-300 font-mono whitespace-pre-wrap break-all bg-zinc-900 rounded-lg p-3 border border-zinc-700 overflow-x-auto max-h-64">
                                {JSON.stringify(r.data, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        )}
                      </>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
