'use client'

import React, { useState, Suspense, useMemo, useEffect, useRef, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  Search, Activity, RefreshCw, ChevronDown, ChevronRight, Filter, X, Download,
  Radio, Wifi, WifiOff, Plus, Code2, Sliders, ChevronUp,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

interface EventRow {
  id: string
  agent_id: string
  event_type: string
  raw_data: Record<string, unknown>
  timestamp: string
}

interface EventsResponse {
  data: EventRow[]
  total: number
  page: number
  per_page: number
  has_more: boolean
}

interface TimelineBucket {
  bucket: string
  count: number
  event_type: string
}

interface TimelineResponse {
  data: TimelineBucket[]
  interval: string
}

// --- Types / colours ---

const EVENT_TYPES = ['', 'process', 'network', 'file', 'dns', 'registry', 'auth']

const HEATMAP_TYPES = [
  'Process Events',
  'Network Connections',
  'File Events',
  'DNS Queries',
  'Auth Events',
  'System Events',
]

const HEATMAP_TYPE_KEYS = ['process', 'network', 'file', 'dns', 'auth', 'registry']

const TYPE_COLORS: Record<string, string> = {
  process:  'bg-blue-900/40 text-blue-300',
  network:  'bg-purple-900/40 text-purple-300',
  file:     'bg-yellow-900/40 text-yellow-300',
  dns:      'bg-green-900/40 text-green-300',
  registry: 'bg-orange-900/40 text-orange-300',
  auth:     'bg-red-900/40 text-red-300',
}

const CHART_COLORS: Record<string, string> = {
  process:  '#3b82f6',
  network:  '#a855f7',
  file:     '#eab308',
  dns:      '#22c55e',
  registry: '#f97316',
  auth:     '#ef4444',
}

const INTERVALS = ['5m', '15m', '1h', '6h', '1d'] as const
type Interval = typeof INTERVALS[number]

type LiveStatus = 'idle' | 'connected' | 'reconnecting'

// ── Query Builder ────────────────────────────────────────────────────────────

const QB_FIELDS = [
  { value: 'event_type',   label: 'Event Type' },
  { value: 'hostname',     label: 'Hostname' },
  { value: 'process_name', label: 'Process Name' },
  { value: 'file_path',    label: 'File Path' },
  { value: 'cmd_line',     label: 'Command Line' },
  { value: 'ip_address',   label: 'IP Address' },
  { value: 'status',       label: 'Status' },
] as const

const QB_OPERATORS = [
  { value: 'eq',         label: 'equals' },
  { value: 'contains',   label: 'contains' },
  { value: 'starts',     label: 'starts with' },
  { value: 'ends',       label: 'ends with' },
  { value: 'regex',      label: 'matches regex' },
  { value: 'neq',        label: 'not equals' },
] as const

interface QBCondition {
  id: string
  field: string
  op: string
  value: string
}

function buildKQL(conds: QBCondition[], logic: 'AND' | 'OR'): string {
  const parts = conds
    .filter(c => c.value.trim())
    .map(c => {
      const v = c.value.trim()
      switch (c.op) {
        case 'eq':       return `${c.field}:"${v}"`
        case 'neq':      return `NOT ${c.field}:"${v}"`
        case 'contains': return `${c.field}:*${v}*`
        case 'starts':   return `${c.field}:${v}*`
        case 'ends':     return `${c.field}:*${v}`
        case 'regex':    return `${c.field}:/${v}/`
        default:         return `${c.field}:"${v}"`
      }
    })
  return parts.join(` ${logic} `)
}

function QueryBuilder({ onApply }: { onApply: (kql: string) => void }) {
  const [open, setOpen] = useState(false)
  const [logic, setLogic] = useState<'AND' | 'OR'>('AND')
  const [conditions, setConditions] = useState<QBCondition[]>([
    { id: '1', field: 'event_type', op: 'eq', value: '' },
  ])

  const addCond = () => {
    if (conditions.length >= 5) return
    setConditions(prev => [...prev, { id: Date.now().toString(), field: 'process_name', op: 'contains', value: '' }])
  }

  const removeCond = (id: string) =>
    setConditions(prev => prev.length > 1 ? prev.filter(c => c.id !== id) : prev)

  const updateCond = (id: string, patch: Partial<QBCondition>) =>
    setConditions(prev => prev.map(c => c.id === id ? { ...c, ...patch } : c))

  const kql = buildKQL(conditions, logic)

  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 hover:bg-[#19253d]/40 transition-colors"
      >
        <Sliders className="w-4 h-4 text-[#1a6bff]" />
        <span className="text-sm font-medium text-[#8899aa]">クエリビルダー</span>
        <span className="text-xs text-[#3d5068] ml-1">（高度なフィルター）</span>
        {kql && (
          <span className="ml-2 text-[10px] bg-[#1a6bff]/15 text-[#1a6bff] border border-[#1a6bff]/30 px-2 py-0.5 rounded-sm font-mono truncate max-w-xs">
            {kql}
          </span>
        )}
        <div className="ml-auto">
          {open
            ? <ChevronUp className="w-4 h-4 text-[#3d5068]" />
            : <ChevronDown className="w-4 h-4 text-[#3d5068]" />}
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-[#1e2d42] pt-3 space-y-3">
          {/* Logic toggle */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#7d92b0]">条件の結合:</span>
            {(['AND', 'OR'] as const).map(l => (
              <button
                key={l}
                onClick={() => setLogic(l)}
                className={`px-3 py-1 rounded-sm text-xs font-mono font-bold transition-colors ${
                  logic === l
                    ? 'bg-[#1a6bff] text-white'
                    : 'bg-[#161f33] text-[#7d92b0] hover:bg-[#1d2f4a]'
                }`}
              >
                {l}
              </button>
            ))}
          </div>

          {/* Conditions */}
          <div className="space-y-2">
            {conditions.map((cond, idx) => (
              <div key={cond.id} className="flex items-center gap-2 flex-wrap">
                {idx > 0 && (
                  <span className="text-[10px] text-[#3d5068] font-mono font-bold w-8 text-center">
                    {logic}
                  </span>
                )}
                {idx === 0 && <span className="w-8" />}
                <select
                  value={cond.field}
                  onChange={e => updateCond(cond.id, { field: e.target.value })}
                  className="bg-[#080c14] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#1a6bff] min-w-0"
                >
                  {QB_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                </select>
                <select
                  value={cond.op}
                  onChange={e => updateCond(cond.id, { op: e.target.value })}
                  className="bg-[#080c14] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#1a6bff] min-w-0"
                >
                  {QB_OPERATORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <input
                  type="text"
                  value={cond.value}
                  onChange={e => updateCond(cond.id, { value: e.target.value })}
                  placeholder="値を入力..."
                  className="flex-1 min-w-32 bg-[#080c14] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs placeholder:text-[#3d5068] focus:outline-hidden focus:border-[#1a6bff] font-mono"
                />
                <button
                  onClick={() => removeCond(cond.id)}
                  disabled={conditions.length === 1}
                  className="text-[#3d5068] hover:text-[#e8002d] transition-colors disabled:opacity-30"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>

          {/* Add condition */}
          {conditions.length < 5 && (
            <button
              onClick={addCond}
              className="flex items-center gap-1.5 text-xs text-[#3d5068] hover:text-[#7d92b0] transition-colors"
            >
              <Plus className="w-3 h-3" />
              条件を追加
            </button>
          )}

          {/* KQL preview + Apply */}
          <div className="flex items-center gap-3 pt-2 border-t border-[#1e2d42]">
            <div className="flex-1 flex items-center gap-2 bg-[#080c14] border border-[#1e2d42] rounded-sm px-2 py-1.5 min-w-0">
              <Code2 className="w-3 h-3 text-[#3d5068] shrink-0" />
              <span className="text-[10px] font-mono text-[#3d5068] truncate">
                {kql || '(条件を入力してください)'}
              </span>
            </div>
            <button
              onClick={() => { onApply(kql); setOpen(false) }}
              disabled={!kql}
              className="flex items-center gap-1.5 px-4 py-1.5 bg-[#1a6bff] hover:bg-[#1557d4] disabled:opacity-40 text-white text-xs font-medium rounded-sm transition-colors"
            >
              <Search className="w-3 h-3" />
              適用
            </button>
            <button
              onClick={() => { onApply(''); setConditions([{ id: '1', field: 'event_type', op: 'eq', value: '' }]) }}
              className="text-xs text-[#3d5068] hover:text-[#7d92b0] transition-colors"
            >
              リセット
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Event Rate Graph (SVG line chart, events/min for last 60 min) ───────────

interface RatePoint { minute: number; count: number }

function EventRateGraph({ rateData }: { rateData: RatePoint[] }) {
  const width = 600
  const height = 80
  const padLeft = 32
  const padRight = 8
  const padTop = 8
  const padBottom = 20

  const maxCount = Math.max(1, ...rateData.map(p => p.count))

  const xs = (minute: number) =>
    padLeft + ((59 - minute) / 59) * (width - padLeft - padRight)
  const ys = (count: number) =>
    padTop + (1 - count / maxCount) * (height - padTop - padBottom)

  const points = rateData
    .map(p => `${xs(p.minute).toFixed(1)},${ys(p.count).toFixed(1)}`)
    .join(' ')

  const areaPoints = rateData.length
    ? `${xs(rateData[0].minute).toFixed(1)},${(height - padBottom).toFixed(1)} ` +
      points +
      ` ${xs(rateData[rateData.length - 1].minute).toFixed(1)},${(height - padBottom).toFixed(1)}`
    : ''

  const yTicks = [0, Math.round(maxCount / 2), maxCount]

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ height: 80 }}>
      {/* y-axis ticks */}
      {yTicks.map(t => (
        <g key={t}>
          <line
            x1={padLeft} x2={width - padRight}
            y1={ys(t)} y2={ys(t)}
            stroke="#1e2d42" strokeWidth={1}
          />
          <text x={padLeft - 4} y={ys(t) + 4} textAnchor="end" fill="#5a6a7a" fontSize={9}>
            {t}
          </text>
        </g>
      ))}
      {/* area fill */}
      {areaPoints && (
        <polygon points={areaPoints} fill="#1a6bff" fillOpacity={0.12} />
      )}
      {/* line */}
      {rateData.length > 1 && (
        <polyline points={points} fill="none" stroke="#1a6bff" strokeWidth={1.5} />
      )}
      {/* x-axis labels */}
      {[0, 15, 30, 45, 59].map(m => (
        <text key={m} x={xs(m)} y={height - 4} textAnchor="middle" fill="#5a6a7a" fontSize={9}>
          -{m}m
        </text>
      ))}
    </svg>
  )
}

// ── Event Type Heatmap (6 rows × 24 cols) ───────────────────────────────────

interface HeatmapCell { type: string; hour: number; count: number }

function EventHeatmap({ cells }: { cells: HeatmapCell[] }) {
  const maxCount = Math.max(1, ...cells.map(c => c.count))

  const cellColor = (count: number) => {
    if (count === 0) return 'bg-[#0d1526]'
    const intensity = count / maxCount
    if (intensity < 0.2)  return 'bg-blue-900/30'
    if (intensity < 0.4)  return 'bg-blue-800/50'
    if (intensity < 0.6)  return 'bg-blue-700/60'
    if (intensity < 0.8)  return 'bg-blue-600/70'
    return 'bg-blue-500/90'
  }

  return (
    <div className="overflow-x-auto">
      <div className="min-w-[640px]">
        {/* Hour labels */}
        <div className="flex ml-[120px] mb-1">
          {Array.from({ length: 24 }, (_, h) => (
            <div key={h} className="flex-1 text-center text-[9px] text-[#5a6a7a]">
              {h % 6 === 0 ? `${h}h` : ''}
            </div>
          ))}
        </div>
        {HEATMAP_TYPES.map((label, ri) => {
          const typeKey = HEATMAP_TYPE_KEYS[ri]
          return (
            <div key={label} className="flex items-center mb-0.5">
              <div className="w-[120px] text-[10px] text-[#8899aa] truncate pr-2 text-right">
                {label}
              </div>
              {Array.from({ length: 24 }, (_, h) => {
                const cell = cells.find(c => c.type === typeKey && c.hour === h)
                const count = cell?.count ?? 0
                return (
                  <div
                    key={h}
                    title={`${label} ${h}:00 — ${count} events`}
                    className={`flex-1 h-5 mx-px rounded-xs ${cellColor(count)}`}
                  />
                )
              })}
            </div>
          )
        })}
        {/* Legend */}
        <div className="flex items-center gap-2 mt-2 ml-[120px]">
          <span className="text-[9px] text-[#5a6a7a]">少</span>
          {['bg-[#0d1526]', 'bg-blue-900/30', 'bg-blue-800/50', 'bg-blue-700/60', 'bg-blue-600/70', 'bg-blue-500/90'].map((cls, i) => (
            <div key={i} className={`w-4 h-3 rounded-xs ${cls}`} />
          ))}
          <span className="text-[9px] text-[#5a6a7a]">多</span>
        </div>
      </div>
    </div>
  )
}

// ── Main component ───────────────────────────────────────────────────────────

function EventsContent() {
  const searchParams = useSearchParams()
  const initialAgentId = searchParams.get('agent_id') ?? ''

  const [agentId, setAgentId]               = useState(initialAgentId)
  const [eventType, setEventType]           = useState('')
  const [search, setSearch]                 = useState('')
  const [qbSearch, setQbSearch]             = useState('')
  const [fromDate, setFromDate]             = useState('')
  const [toDate, setToDate]                 = useState('')
  const [page, setPage]                     = useState(1)
  const [expandedId, setExpandedId]         = useState<string | null>(null)
  const [chartInterval, setChartInterval]   = useState<Interval>('1h')
  const perPage = 50

  // SSE state
  const [liveEnabled, setLiveEnabled]       = useState(false)
  const [liveStatus, setLiveStatus]         = useState<LiveStatus>('idle')
  const [liveEvents, setLiveEvents]         = useState<EventRow[]>([])

  // Event rate data: rateData[i].minute = minutes ago (0 = current), count = events in that minute
  const [rateData, setRateData]             = useState<RatePoint[]>(() =>
    Array.from({ length: 60 }, (_, i) => ({ minute: i, count: 0 }))
  )
  const rateRef = useRef<RatePoint[]>(Array.from({ length: 60 }, (_, i) => ({ minute: i, count: 0 })))
  const minuteCounterRef = useRef(0)

  // Heatmap cells derived from liveEvents + static data
  const heatmapCells = useMemo<HeatmapCell[]>(() => {
    const map = new Map<string, number>()
    // Seed from live events
    for (const ev of liveEvents) {
      const hour = new Date(ev.timestamp).getHours()
      const key = `${ev.event_type}|${hour}`
      map.set(key, (map.get(key) ?? 0) + 1)
    }
    const result: HeatmapCell[] = []
    for (const type of HEATMAP_TYPE_KEYS) {
      for (let h = 0; h < 24; h++) {
        result.push({ type, hour: h, count: map.get(`${type}|${h}`) ?? 0 })
      }
    }
    return result
  }, [liveEvents])

  // SSE connection
  useEffect(() => {
    if (!liveEnabled) {
      setLiveStatus('idle')
      return
    }
    const es = new EventSource('/api/v1/stream?types=alerts,agents')
    es.onopen = () => setLiveStatus('connected')
    es.onerror = () => setLiveStatus('reconnecting')
    es.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data) as EventRow
        setLiveEvents(prev => [event, ...prev].slice(0, 500))
        // Update rate counter
        minuteCounterRef.current += 1
      } catch {
        // ignore parse errors
      }
    }
    return () => {
      es.close()
      setLiveStatus('idle')
    }
  }, [liveEnabled])

  // Advance rate graph every minute
  useEffect(() => {
    if (!liveEnabled) return
    const interval = setInterval(() => {
      const newPoint: RatePoint = { minute: 0, count: minuteCounterRef.current }
      minuteCounterRef.current = 0
      const shifted = [newPoint, ...rateRef.current.slice(0, 59).map((p, i) => ({ ...p, minute: i + 1 }))]
      rateRef.current = shifted
      setRateData([...shifted])
    }, 60_000)
    return () => clearInterval(interval)
  }, [liveEnabled])

  const { data, isLoading, refetch, isFetching } = useQuery<EventsResponse>({
    queryKey: ['events', agentId, eventType, search, qbSearch, fromDate, toDate, page],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
      if (agentId) params.set('agent_id', agentId)
      if (eventType) params.set('type', eventType)
      const effectiveSearch = qbSearch || search
      if (effectiveSearch) params.set('search', effectiveSearch)
      if (fromDate) params.set('from', new Date(fromDate).toISOString())
      if (toDate) params.set('to', new Date(toDate + 'T23:59:59').toISOString())
      return apiFetch<EventsResponse>(`/api/v1/events?${params}`)
    },
  })

  const { data: timeline } = useQuery<TimelineResponse>({
    queryKey: ['events-timeline', agentId, chartInterval],
    queryFn: () => {
      const params = new URLSearchParams({ interval: chartInterval })
      if (agentId) params.set('agent_id', agentId)
      return apiFetch<TimelineResponse>(`/api/v1/events/timeline?${params}`)
    },
    staleTime: 60_000,
  })

  // Pivot {bucket, count, event_type}[] → [{bucket, process:N, network:M, ...}]
  const chartData = useMemo(() => {
    if (!timeline?.data?.length) return []
    const bucketMap = new Map<string, Record<string, number>>()
    for (const row of timeline.data) {
      if (!bucketMap.has(row.bucket)) bucketMap.set(row.bucket, {})
      const b = bucketMap.get(row.bucket)!
      b[row.event_type] = (b[row.event_type] ?? 0) + row.count
    }
    return Array.from(bucketMap.entries())
      .map(([bucket, counts]) => ({ bucket, ...counts }))
      .sort((a, b) => a.bucket.localeCompare(b.bucket))
  }, [timeline])

  // Merge live events on top of fetched events
  const fetchedEvents = data?.data ?? []
  const events = liveEnabled && liveEvents.length > 0
    ? [...liveEvents, ...fetchedEvents].slice(0, perPage * 2)
    : fetchedEvents
  const total  = data?.total ?? 0

  function handleSearch() {
    setPage(1)
    refetch()
  }

  const exportCSV = useCallback(() => {
    if (events.length === 0) return
    const headers = ['timestamp', 'agent_id', 'event_type', 'summary']
    const rows = events.map(e => [
      e.timestamp,
      e.agent_id,
      e.event_type,
      getSummary(e.event_type, e.raw_data ?? {}),
    ])
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `events-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [events])

  function clearFilters() {
    setAgentId('')
    setEventType('')
    setSearch('')
    setQbSearch('')
    setFromDate('')
    setToDate('')
    setPage(1)
  }

  const hasFilters = !!(agentId || eventType || search || qbSearch || fromDate || toDate)

  const liveStatusLabel: Record<LiveStatus, string> = {
    idle: '',
    connected: 'connected',
    reconnecting: 'reconnecting',
  }

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-2xl font-bold text-white">イベント検索</h1>
          <p className="text-[#8899aa] text-sm mt-1">エンドポイントから収集した生イベントを検索・閲覧します</p>
        </div>
        <div className="flex items-center gap-2">
          {/* SSE Live Toggle */}
          <button
            onClick={() => {
              if (liveEnabled) {
                setLiveEnabled(false)
                setLiveEvents([])
              } else {
                setLiveEnabled(true)
              }
            }}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors border ${
              liveEnabled
                ? 'bg-green-900/30 border-green-700/50 text-green-300 hover:bg-green-900/50'
                : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:bg-[#1d2f4a]'
            }`}
          >
            {liveEnabled ? (
              <>
                <Radio className="w-4 h-4 animate-pulse" />
                <span className="flex items-center gap-1.5">
                  LIVE
                  {liveStatus !== 'idle' && (
                    <span className={`text-xs font-normal ${liveStatus === 'connected' ? 'text-green-400' : 'text-yellow-400'}`}>
                      {liveStatus === 'connected'
                        ? <Wifi className="w-3 h-3 inline" />
                        : <WifiOff className="w-3 h-3 inline" />}
                      {' '}{liveStatusLabel[liveStatus]}
                    </span>
                  )}
                </span>
              </>
            ) : (
              <>
                <Radio className="w-4 h-4" />
                ライブ開始
              </>
            )}
          </button>

          <button
            onClick={exportCSV}
            disabled={events.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#161f33] hover:bg-[#1d2f4a] text-[#8899aa] text-sm rounded-lg transition-colors disabled:opacity-40"
          >
            <Download className="w-4 h-4" />CSV
          </button>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 px-4 py-2 bg-[#161f33] hover:bg-[#1d2f4a] text-white text-sm rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* Live Event Count Banner */}
      {liveEnabled && liveEvents.length > 0 && (
        <div className="flex items-center gap-3 bg-green-900/20 border border-green-800/40 rounded-lg px-4 py-2.5">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-green-300 text-sm font-medium">
            {liveEvents.length} 件の新しいイベントを受信しました
          </span>
          <button
            onClick={() => setLiveEvents([])}
            className="ml-auto text-xs text-green-500 hover:text-green-300 transition-colors"
          >
            クリア
          </button>
        </div>
      )}

      {/* Query Builder */}
      <QueryBuilder onApply={kql => { setQbSearch(kql); setPage(1) }} />

      {/* Event Rate Graph (shown when live is active) */}
      {liveEnabled && (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-medium text-[#8899aa] flex items-center gap-2">
              <Activity className="w-4 h-4 text-green-400" />
              イベントレート（直近60分、/分）
            </h2>
            <span className="text-xs text-[#5a6a7a]">リアルタイム更新</span>
          </div>
          <EventRateGraph rateData={rateData} />
        </div>
      )}

      {/* Event Type Heatmap (always shown) */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center gap-2 mb-3">
          <h2 className="text-sm font-medium text-[#8899aa]">
            イベントタイプ別ヒートマップ（時間帯別）
          </h2>
          {liveEnabled && (
            <span className="text-xs text-green-400 bg-green-900/20 px-2 py-0.5 rounded-sm font-mono">
              ライブ更新中
            </span>
          )}
        </div>
        <EventHeatmap cells={heatmapCells} />
        {!liveEnabled && liveEvents.length === 0 && (
          <p className="text-xs text-[#5a6a7a] mt-2">
            ライブモードを開始するとイベントデータがヒートマップに反映されます
          </p>
        )}
      </div>

      {/* Timeline chart */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-medium text-[#8899aa] flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-400" />
            イベントタイムライン
          </h2>
          <div className="flex gap-1">
            {INTERVALS.map(iv => (
              <button
                key={iv}
                onClick={() => setChartInterval(iv)}
                className={`px-2 py-1 text-xs rounded-sm transition-colors ${
                  chartInterval === iv
                    ? 'bg-[#1a6bff] text-white'
                    : 'bg-[#161f33] text-[#8899aa] hover:bg-[#1d2f4a]'
                }`}
              >
                {iv}
              </button>
            ))}
          </div>
        </div>

        {chartData.length === 0 ? (
          <div className="h-32 flex items-center justify-center text-[#5a6a7a] text-sm">
            データなし
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={chartData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" vertical={false} />
              <XAxis
                dataKey="bucket"
                tickFormatter={v => {
                  const d = new Date(v)
                  return chartInterval === '1d'
                    ? d.toLocaleDateString('ja-JP', { month: '2-digit', day: '2-digit' })
                    : d.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })
                }}
                tick={{ fill: '#8899aa', fontSize: 10 }}
                stroke="#1e2d42"
              />
              <YAxis tick={{ fill: '#8899aa', fontSize: 10 }} stroke="#1e2d42" width={30} />
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #1e2d42', borderRadius: '8px', fontSize: '12px' }}
                labelStyle={{ color: '#e5e7eb' }}
                labelFormatter={v => new Date(v as string).toLocaleString('ja-JP')}
              />
              {EVENT_TYPES.filter(Boolean).map(type => (
                <Bar key={type} dataKey={type} stackId="a"
                     fill={CHART_COLORS[type] ?? '#6b7280'} name={type} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}

        {/* Legend */}
        <div className="flex flex-wrap gap-3 mt-2">
          {EVENT_TYPES.filter(Boolean).map(type => (
            <span key={type} className="flex items-center gap-1 text-xs text-[#8899aa]">
              <span className="w-2.5 h-2.5 rounded-xs inline-block" style={{ backgroundColor: CHART_COLORS[type] }} />
              {type}
            </span>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-[#8899aa]" />
            <span className="text-[#8899aa] text-sm font-medium">フィルター</span>
            {qbSearch && (
              <span className="text-[10px] bg-[#1a6bff]/15 text-[#1a6bff] border border-[#1a6bff]/30 px-2 py-0.5 rounded-sm font-mono flex items-center gap-1">
                <Code2 className="w-3 h-3" />
                クエリビルダー適用中
              </span>
            )}
          </div>
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-[#e2e8f4] transition-colors"
            >
              <X className="w-3 h-3" />
              クリア
            </button>
          )}
        </div>
        <div className="flex flex-wrap gap-3">
          <div className="flex-1 min-w-48">
            <label className="text-[#8899aa] text-xs block mb-1">エージェントID</label>
            <input
              type="text"
              value={agentId}
              onChange={e => setAgentId(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch()}
              placeholder="UUID または空欄（すべて）"
              className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#1a6bff] font-mono"
            />
          </div>
          <div>
            <label className="text-[#8899aa] text-xs block mb-1">イベントタイプ</label>
            <select
              value={eventType}
              onChange={e => { setEventType(e.target.value); setPage(1) }}
              className="bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
            >
              <option value="">すべてのタイプ</option>
              {EVENT_TYPES.filter(Boolean).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="flex-1 min-w-44">
            <label className="text-[#8899aa] text-xs block mb-1">キーワード検索</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
                placeholder="IPアドレス、ファイル名、コマンド..."
                className="w-full pl-8 pr-3 bg-[#080c14] text-white py-2 rounded-lg border border-[#1e2d42] text-sm placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#1a6bff]"
              />
            </div>
          </div>
          <div>
            <label className="text-[#8899aa] text-xs block mb-1">開始日時</label>
            <input
              type="date"
              value={fromDate}
              onChange={e => { setFromDate(e.target.value); setPage(1) }}
              className="bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
            />
          </div>
          <div>
            <label className="text-[#8899aa] text-xs block mb-1">終了日時</label>
            <input
              type="date"
              value={toDate}
              onChange={e => { setToDate(e.target.value); setPage(1) }}
              className="bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-[#1a6bff]"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={handleSearch}
              className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] text-white rounded-lg hover:bg-[#1557d4] transition-colors text-sm"
            >
              <Search className="w-4 h-4" />
              検索
            </button>
          </div>
        </div>
      </div>

      {/* Results summary */}
      {!isLoading && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-[#8899aa]">{total.toLocaleString()} 件のイベント</span>
          {total > perPage && (
            <span className="text-[#5a6a7a]">
              {((page - 1) * perPage + 1).toLocaleString()}–{Math.min(page * perPage, total).toLocaleString()} 件を表示
            </span>
          )}
        </div>
      )}

      {/* Events table */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-16">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-[#1a6bff]" />
          </div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-[#5a6a7a]">
            <Activity className="w-12 h-12 mb-3 opacity-30" />
            <p>イベントが見つかりません</p>
            <p className="text-xs mt-1">フィルターを変更してみてください</p>
          </div>
        ) : (
          <div>
            <div className="grid grid-cols-[1fr_auto_auto_auto] gap-0 border-b border-[#1e2d42] px-4 py-3 text-xs font-medium text-[#8899aa]">
              <span>タイムスタンプ / エージェント</span>
              <span className="px-4">タイプ</span>
              <span className="px-4">概要</span>
              <span className="w-6" />
            </div>
            <div className="divide-y divide-[#1e2d42]">
              {events.map((event, idx) => {
                const isNew = liveEnabled && idx < liveEvents.length
                return (
                  <EventRowItem
                    key={event.id ?? `live-${idx}`}
                    event={event}
                    expanded={expandedId === (event.id ?? `live-${idx}`)}
                    onToggle={() => setExpandedId(expandedId === (event.id ?? `live-${idx}`) ? null : (event.id ?? `live-${idx}`))}
                    isLive={isNew}
                  />
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Pagination */}
      {total > perPage && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 bg-[#161f33] text-[#8899aa] rounded-lg text-sm disabled:opacity-40 hover:bg-[#1d2f4a] transition-colors"
          >
            前へ
          </button>
          <span className="text-[#8899aa] text-sm px-2">
            {page} / {Math.ceil(total / perPage)}
          </span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={!data?.has_more}
            className="px-4 py-2 bg-[#161f33] text-[#8899aa] rounded-lg text-sm disabled:opacity-40 hover:bg-[#1d2f4a] transition-colors"
          >
            次へ
          </button>
        </div>
      )}
    </div>
  )
}

function EventRowItem({ event, expanded, onToggle, isLive }: {
  event: EventRow
  expanded: boolean
  onToggle: () => void
  isLive?: boolean
}) {
  const raw = event.raw_data ?? {}
  const summary = getSummary(event.event_type, raw)
  const typeColor = TYPE_COLORS[event.event_type] ?? 'bg-[#161f33] text-[#8899aa]'

  return (
    <div className={isLive ? 'border-l-2 border-green-600/60' : ''}>
      <button
        onClick={onToggle}
        className="w-full grid grid-cols-[1fr_auto_auto_auto] gap-0 px-4 py-3 hover:bg-[#161f33] transition-colors text-left"
      >
        <div className="flex items-center gap-2">
          {isLive && (
            <span className="text-[10px] bg-green-900/40 text-green-400 border border-green-700/40 px-1.5 py-0.5 rounded-sm font-mono font-bold shrink-0">
              LIVE
            </span>
          )}
          <span className="text-[#8899aa] text-xs font-mono">
            {new Date(event.timestamp).toLocaleString('ja-JP')}
          </span>
          <span className="text-[#5a6a7a] text-xs font-mono">
            {event.agent_id?.slice(0, 8)}…
          </span>
        </div>
        <div className="px-4 flex items-center">
          <span className={`text-xs px-2 py-0.5 rounded-sm font-mono ${typeColor}`}>
            {event.event_type}
          </span>
        </div>
        <div className="px-4 flex items-center">
          <span className="text-[#8899aa] text-xs truncate max-w-xs">{summary}</span>
        </div>
        <div className="w-6 flex items-center justify-center">
          {expanded
            ? <ChevronDown className="w-3.5 h-3.5 text-[#8899aa]" />
            : <ChevronRight className="w-3.5 h-3.5 text-[#5a6a7a]" />}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 bg-[#080c14]/50">
          <EventDetail eventType={event.event_type} raw={raw} />
        </div>
      )}
    </div>
  )
}

// ── Field helpers ────────────────────────────────────────────────────────────

function Field({ label, value, mono }: { label: string; value?: unknown; mono?: boolean }) {
  if (value === undefined || value === null || value === '') return null
  const text = typeof value === 'object' ? JSON.stringify(value) : String(value)
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] text-[#5a6a7a] uppercase tracking-wider">{label}</span>
      <span className={`text-xs text-[#e2e8f4] break-all ${mono ? 'font-mono' : ''}`}>{text}</span>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <p className="text-[10px] font-semibold text-[#5a6a7a] uppercase tracking-widest">{title}</p>
      <div className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3 lg:grid-cols-4">
        {children}
      </div>
    </div>
  )
}

function RawJson({ raw }: { raw: Record<string, unknown> }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="mt-3 border-t border-[#1e2d42]/60 pt-3">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1 text-[10px] text-[#5a6a7a] hover:text-[#8899aa] transition-colors"
      >
        {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        生データ (JSON)
      </button>
      {open && (
        <pre className="mt-2 text-xs text-[#8899aa] bg-[#080c14] rounded-lg p-4 overflow-auto font-mono leading-relaxed max-h-56">
          {JSON.stringify(raw, null, 2)}
        </pre>
      )}
    </div>
  )
}

// ── Per-type detail panels ────────────────────────────────────────────────────

function ProcessDetail({ raw }: { raw: Record<string, unknown> }) {
  return (
    <div className="space-y-3">
      <Section title="プロセス情報">
        <Field label="イメージ"   value={raw.image ?? raw.process_name} mono />
        <Field label="PID"        value={raw.pid} mono />
        <Field label="PPID"       value={raw.ppid} mono />
        <Field label="ユーザー"   value={raw.user ?? raw.username} />
        <Field label="アクション" value={raw.action ?? raw.event_action} />
        <Field label="整合性"     value={raw.integrity_level} />
      </Section>
      {!!(raw.cmdline || raw.command_line) && (
        <div className="space-y-0.5">
          <span className="text-[10px] text-[#5a6a7a] uppercase tracking-wider">コマンドライン</span>
          <p className="text-xs text-[#e2e8f4] font-mono break-all bg-[#080c14] rounded-sm px-2 py-1">
            {String(raw.cmdline ?? raw.command_line)}
          </p>
        </div>
      )}
      {!!(raw.md5 || raw.sha256 || raw.sha1) && (
        <Section title="ハッシュ">
          <Field label="MD5"    value={raw.md5}    mono />
          <Field label="SHA1"   value={raw.sha1}   mono />
          <Field label="SHA256" value={raw.sha256} mono />
        </Section>
      )}
    </div>
  )
}

function NetworkDetail({ raw }: { raw: Record<string, unknown> }) {
  const src = `${raw.src_ip ?? raw.local_ip ?? ''}:${raw.src_port ?? raw.local_port ?? ''}`.replace(/^:/, '')
  const dst = `${raw.dst_ip ?? raw.remote_ip ?? ''}:${raw.dst_port ?? raw.remote_port ?? ''}`.replace(/^:/, '')
  return (
    <Section title="ネットワーク接続">
      <Field label="送信元"        value={src || undefined} mono />
      <Field label="宛先"          value={dst || undefined} mono />
      <Field label="プロトコル"    value={raw.protocol} mono />
      <Field label="方向"          value={raw.direction} />
      <Field label="送信バイト"    value={raw.bytes_sent ?? raw.tx_bytes} />
      <Field label="受信バイト"    value={raw.bytes_recv ?? raw.rx_bytes} />
      <Field label="プロセス"      value={raw.image ?? raw.process_name} mono />
      <Field label="PID"           value={raw.pid} mono />
    </Section>
  )
}

function FileDetail({ raw }: { raw: Record<string, unknown> }) {
  return (
    <div className="space-y-3">
      <Section title="ファイル操作">
        <Field label="アクション"   value={raw.action ?? raw.event_action} />
        <Field label="プロセス"     value={raw.image ?? raw.process_name} mono />
        <Field label="PID"          value={raw.pid} mono />
        <Field label="ユーザー"     value={raw.user ?? raw.username} />
      </Section>
      {!!(raw.path || raw.file_path) && (
        <div className="space-y-0.5">
          <span className="text-[10px] text-[#5a6a7a] uppercase tracking-wider">パス</span>
          <p className="text-xs text-[#e2e8f4] font-mono break-all bg-[#080c14] rounded-sm px-2 py-1">
            {String(raw.path ?? raw.file_path)}
          </p>
        </div>
      )}
      {!!(raw.target_path || raw.new_path) && (
        <div className="space-y-0.5">
          <span className="text-[10px] text-[#5a6a7a] uppercase tracking-wider">移動先パス</span>
          <p className="text-xs text-[#e2e8f4] font-mono break-all bg-[#080c14] rounded-sm px-2 py-1">
            {String(raw.target_path ?? raw.new_path)}
          </p>
        </div>
      )}
    </div>
  )
}

function DnsDetail({ raw }: { raw: Record<string, unknown> }) {
  const answers = Array.isArray(raw.answers) ? raw.answers : []
  return (
    <div className="space-y-3">
      <Section title="DNS クエリ">
        <Field label="クエリ"      value={raw.query ?? raw.domain} mono />
        <Field label="タイプ"      value={raw.query_type ?? raw.type} mono />
        <Field label="レスポンス"  value={raw.rcode ?? raw.status} />
        <Field label="プロセス"    value={raw.image ?? raw.process_name} mono />
        <Field label="PID"         value={raw.pid} mono />
      </Section>
      {answers.length > 0 && (
        <div className="space-y-0.5">
          <span className="text-[10px] text-[#5a6a7a] uppercase tracking-wider">応答</span>
          <p className="text-xs text-[#e2e8f4] font-mono bg-[#080c14] rounded-sm px-2 py-1">
            {answers.map(a => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(', ')}
          </p>
        </div>
      )}
    </div>
  )
}

function RegistryDetail({ raw }: { raw: Record<string, unknown> }) {
  return (
    <div className="space-y-3">
      <Section title="レジストリ操作">
        <Field label="アクション"  value={raw.action ?? raw.event_action} />
        <Field label="プロセス"    value={raw.image ?? raw.process_name} mono />
        <Field label="PID"         value={raw.pid} mono />
        <Field label="値の型"      value={raw.value_type} mono />
      </Section>
      {!!(raw.key_path || raw.registry_key) && (
        <div className="space-y-0.5">
          <span className="text-[10px] text-[#5a6a7a] uppercase tracking-wider">キーパス</span>
          <p className="text-xs text-[#e2e8f4] font-mono break-all bg-[#080c14] rounded-sm px-2 py-1">
            {String(raw.key_path ?? raw.registry_key)}
          </p>
        </div>
      )}
      {raw.value_name !== undefined && (
        <Section title="値">
          <Field label="名前" value={raw.value_name} mono />
          <Field label="データ" value={raw.value_data} mono />
        </Section>
      )}
    </div>
  )
}

function AuthDetail({ raw }: { raw: Record<string, unknown> }) {
  return (
    <Section title="認証イベント">
      <Field label="ユーザー"    value={raw.user ?? raw.username} />
      <Field label="ドメイン"    value={raw.domain} mono />
      <Field label="ワークステーション" value={raw.workstation ?? raw.host} mono />
      <Field label="ログオンタイプ" value={raw.logon_type} />
      <Field label="認証パッケージ" value={raw.auth_package} mono />
      <Field label="結果"        value={raw.result ?? raw.status} />
      <Field label="IPアドレス"  value={raw.src_ip ?? raw.ip_address} mono />
      <Field label="プロセス"    value={raw.image ?? raw.process_name} mono />
    </Section>
  )
}

function GenericDetail({ raw }: { raw: Record<string, unknown> }) {
  const entries = Object.entries(raw).filter(([, v]) => v !== null && v !== undefined)
  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
      {entries.map(([k, v]) => (
        <Field key={k} label={k} value={v} mono />
      ))}
    </div>
  )
}

function EventDetail({ eventType, raw }: { eventType: string; raw: Record<string, unknown> }) {
  let body: React.ReactNode
  switch (eventType) {
    case 'process':  body = <ProcessDetail  raw={raw} />; break
    case 'network':  body = <NetworkDetail  raw={raw} />; break
    case 'file':     body = <FileDetail     raw={raw} />; break
    case 'dns':      body = <DnsDetail      raw={raw} />; break
    case 'registry': body = <RegistryDetail raw={raw} />; break
    case 'auth':     body = <AuthDetail     raw={raw} />; break
    default:         body = <GenericDetail  raw={raw} />
  }
  return (
    <div className="mt-1 rounded-lg border border-[#1e2d42] bg-[#080c14]/70 p-4">
      {body}
      <RawJson raw={raw} />
    </div>
  )
}

// ── getSummary ────────────────────────────────────────────────────────────────

function getSummary(eventType: string, raw: Record<string, unknown>): string {
  switch (eventType) {
    case 'process':
      return String(raw.image ?? raw.process_name ?? raw.cmdline ?? '').slice(0, 80) || '—'
    case 'network':
      return `${raw.dst_ip ?? raw.remote_ip ?? ''}:${raw.dst_port ?? raw.remote_port ?? ''}`
        .replace(/^:/, '').slice(0, 80) || '—'
    case 'file':
      return String(raw.path ?? raw.file_path ?? '').slice(0, 80) || '—'
    case 'dns':
      return String(raw.query ?? raw.domain ?? '').slice(0, 80) || '—'
    case 'registry':
      return String(raw.key_path ?? raw.registry_key ?? '').slice(0, 80) || '—'
    case 'auth':
      return `${raw.user ?? ''} @ ${raw.workstation ?? raw.host ?? ''}`.replace(/^ @ $/, '—')
    default:
      return JSON.stringify(raw).slice(0, 80)
  }
}

export default function EventsPage() {
  return (
    <Suspense fallback={
      <div className="p-6 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-[#1a6bff]" />
      </div>
    }>
      <EventsContent />
    </Suspense>
  )
}
