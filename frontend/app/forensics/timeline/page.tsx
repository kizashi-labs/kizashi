'use client'

import { useState, useMemo, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Clock,
  Download,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  Activity,
  Wifi,
  Folder,
  Globe,
  MonitorDot,
  Loader2,
  AlertCircle,
  PlayCircle,
  Server,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os?: string
  status?: string
}

interface AgentsResponse {
  agents?: Agent[]
  data?: Agent[]
}

export type EventType = 'process' | 'file' | 'network' | 'dns'

export interface ProcessEvent {
  id: string
  type: 'process'
  timestamp: string
  process_name: string
  pid: number
  ppid?: number
  cmdline?: string
  action?: 'create' | 'terminate'
  user?: string
  parent_name?: string
  children?: ProcessEvent[]
}

export interface FileEvent {
  id: string
  type: 'file'
  timestamp: string
  path: string
  action: 'create' | 'modify' | 'delete' | 'rename'
  new_path?: string
  size?: number
  process_name?: string
}

export interface NetworkEvent {
  id: string
  type: 'network'
  timestamp: string
  src_ip: string
  dst_ip: string
  dst_port: number
  protocol: string
  bytes_sent?: number
  bytes_recv?: number
  process_name?: string
}

export interface DnsEvent {
  id: string
  type: 'dns'
  timestamp: string
  domain: string
  query_type: string
  response?: string
  response_code?: string
  process_name?: string
}

export type TimelineEvent = ProcessEvent | FileEvent | NetworkEvent | DnsEvent

interface EventsResponse {
  events: TimelineEvent[]
}

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_AGENTS: Agent[] = [
  { id: 'ag-001', hostname: 'endpoint-01', os: 'Windows 11', status: 'online' },
  { id: 'ag-002', hostname: 'endpoint-42', os: 'Windows 10', status: 'offline' },
  { id: 'ag-003', hostname: 'server-dc01', os: 'Windows Server 2022', status: 'online' },
]

function generateMockEvents(agentId: string, from: Date, to: Date): TimelineEvent[] {
  const baseTime = from.getTime()
  const range = to.getTime() - baseTime

  const events: TimelineEvent[] = [
    {
      id: 'ev-001',
      type: 'process',
      timestamp: new Date(baseTime + range * 0.1).toISOString(),
      process_name: 'powershell.exe',
      pid: 4824,
      ppid: 1032,
      cmdline: '-ExecutionPolicy Bypass -EncodedCommand JABjA...',
      action: 'create',
      user: 'SYSTEM',
      parent_name: 'cmd.exe',
    },
    {
      id: 'ev-002',
      type: 'process',
      timestamp: new Date(baseTime + range * 0.12).toISOString(),
      process_name: 'net.exe',
      pid: 5120,
      ppid: 4824,
      cmdline: 'net user administrator /active:yes',
      action: 'create',
      user: 'SYSTEM',
      parent_name: 'powershell.exe',
    },
    {
      id: 'ev-003',
      type: 'file',
      timestamp: new Date(baseTime + range * 0.2).toISOString(),
      path: 'C:\\Windows\\Temp\\payload.exe',
      action: 'create',
      size: 524288,
      process_name: 'powershell.exe',
    },
    {
      id: 'ev-004',
      type: 'network',
      timestamp: new Date(baseTime + range * 0.3).toISOString(),
      src_ip: '192.168.1.100',
      dst_ip: '185.220.101.5',
      dst_port: 443,
      protocol: 'TCP',
      bytes_sent: 1024,
      bytes_recv: 8192,
      process_name: 'powershell.exe',
    },
    {
      id: 'ev-005',
      type: 'dns',
      timestamp: new Date(baseTime + range * 0.35).toISOString(),
      domain: 'malicious-c2-server.example.com',
      query_type: 'A',
      response: '185.220.101.5',
      response_code: 'NOERROR',
      process_name: 'powershell.exe',
    },
    {
      id: 'ev-006',
      type: 'file',
      timestamp: new Date(baseTime + range * 0.4).toISOString(),
      path: 'C:\\Users\\Administrator\\Documents\\sensitive_data.xlsx',
      action: 'modify',
      size: 2097152,
      process_name: 'payload.exe',
    },
    {
      id: 'ev-007',
      type: 'network',
      timestamp: new Date(baseTime + range * 0.5).toISOString(),
      src_ip: '192.168.1.100',
      dst_ip: '10.0.0.1',
      dst_port: 445,
      protocol: 'TCP',
      bytes_sent: 4096,
      bytes_recv: 1024,
      process_name: 'payload.exe',
    },
    {
      id: 'ev-008',
      type: 'process',
      timestamp: new Date(baseTime + range * 0.6).toISOString(),
      process_name: 'vssadmin.exe',
      pid: 6240,
      ppid: 4824,
      cmdline: 'vssadmin delete shadows /all /quiet',
      action: 'create',
      user: 'SYSTEM',
      parent_name: 'powershell.exe',
    },
    {
      id: 'ev-009',
      type: 'file',
      timestamp: new Date(baseTime + range * 0.65).toISOString(),
      path: 'C:\\Windows\\Temp\\README.RANSOMWARE.txt',
      action: 'create',
      size: 2048,
      process_name: 'payload.exe',
    },
    {
      id: 'ev-010',
      type: 'dns',
      timestamp: new Date(baseTime + range * 0.7).toISOString(),
      domain: 'update.microsoft.com',
      query_type: 'A',
      response: '23.218.130.119',
      response_code: 'NOERROR',
      process_name: 'svchost.exe',
    },
    {
      id: 'ev-011',
      type: 'network',
      timestamp: new Date(baseTime + range * 0.8).toISOString(),
      src_ip: '192.168.1.100',
      dst_ip: '185.220.101.5',
      dst_port: 8443,
      protocol: 'TCP',
      bytes_sent: 1048576,
      bytes_recv: 512,
      process_name: 'payload.exe',
    },
    {
      id: 'ev-012',
      type: 'file',
      timestamp: new Date(baseTime + range * 0.9).toISOString(),
      path: 'C:\\Windows\\System32\\config\\SAM',
      action: 'modify',
      process_name: 'payload.exe',
    },
  ]

  return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
}

// ── Helpers ────────────────────────────────────────────────────

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString('ja-JP', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatBytes(bytes?: number): string {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

const EVENT_TYPE_LABELS: Record<EventType, string> = {
  process: 'プロセス',
  file: 'ファイル',
  network: 'ネットワーク',
  dns: 'DNS',
}

// ── Process Node Component ─────────────────────────────────────

function ProcessNode({ proc, depth = 0 }: { proc: ProcessEvent; depth: number }) {
  return (
    <div style={{ paddingLeft: depth * 16 }}>
      <div className="flex items-center gap-2 text-sm">
        <span className="text-green-400">▶</span>
        <span className="text-white font-mono">{proc.process_name}</span>
        <span className="text-falcon-muted">({proc.pid})</span>
        {proc.cmdline && (
          <span className="text-falcon-muted text-xs truncate max-w-xs">{proc.cmdline}</span>
        )}
      </div>
      {proc.children?.map(child => (
        <ProcessNode key={child.id} proc={child} depth={depth + 1} />
      ))}
    </div>
  )
}

// ── Event Card Components ──────────────────────────────────────

function ProcessCard({ event }: { event: ProcessEvent }) {
  return (
    <div className="space-y-1.5">
      <ProcessNode proc={event} depth={0} />
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-[#4d6480] mt-1">
        {event.parent_name && (
          <span>親プロセス: <span className="text-falcon-muted font-mono">{event.parent_name}</span></span>
        )}
        {event.user && (
          <span>ユーザー: <span className="text-falcon-muted">{event.user}</span></span>
        )}
        {event.action && (
          <span>アクション: <span className={event.action === 'create' ? 'text-green-400' : 'text-red-400'}>{event.action}</span></span>
        )}
      </div>
    </div>
  )
}

function FileCard({ event }: { event: FileEvent }) {
  const actionColor = {
    create: 'text-green-400',
    modify: 'text-yellow-400',
    delete: 'text-red-400',
    rename: 'text-blue-400',
  }[event.action]

  const actionLabel = {
    create: '作成',
    modify: '変更',
    delete: '削除',
    rename: 'リネーム',
  }[event.action]

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <span className={`text-xs font-bold uppercase px-1.5 py-0.5 rounded-sm ${actionColor} bg-current/10`} style={{ backgroundColor: 'rgba(0,0,0,0.2)' }}>
          <span className={actionColor}>{actionLabel}</span>
        </span>
        <span className="text-sm font-mono text-falcon-text break-all">{event.path}</span>
      </div>
      {event.new_path && (
        <div className="text-xs text-[#4d6480]">
          → <span className="font-mono text-falcon-muted">{event.new_path}</span>
        </div>
      )}
      <div className="flex gap-4 text-xs text-[#4d6480]">
        {event.size !== undefined && (
          <span>サイズ: <span className="text-falcon-muted">{formatBytes(event.size)}</span></span>
        )}
        {event.process_name && (
          <span>プロセス: <span className="text-falcon-muted font-mono">{event.process_name}</span></span>
        )}
      </div>
    </div>
  )
}

function NetworkCard({ event }: { event: NetworkEvent }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 text-sm flex-wrap">
        <span className="font-mono text-falcon-text">{event.src_ip}</span>
        <span className="text-[#4d6480]">→</span>
        <span className="font-mono text-falcon-text">{event.dst_ip}</span>
        <span className="text-blue-400 font-mono">:{event.dst_port}</span>
        <span className="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded-sm">
          {event.protocol}
        </span>
      </div>
      <div className="flex gap-4 text-xs text-[#4d6480]">
        {event.bytes_sent !== undefined && (
          <span>送信: <span className="text-falcon-muted">{formatBytes(event.bytes_sent)}</span></span>
        )}
        {event.bytes_recv !== undefined && (
          <span>受信: <span className="text-falcon-muted">{formatBytes(event.bytes_recv)}</span></span>
        )}
        {event.process_name && (
          <span>プロセス: <span className="text-falcon-muted font-mono">{event.process_name}</span></span>
        )}
      </div>
    </div>
  )
}

function DnsCard({ event }: { event: DnsEvent }) {
  const rcodeColor = event.response_code === 'NOERROR' ? 'text-green-400' : 'text-red-400'
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 text-sm flex-wrap">
        <span className="font-mono text-falcon-text">{event.domain}</span>
        <span className="text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20 px-1.5 py-0.5 rounded-sm">
          {event.query_type}
        </span>
        {event.response_code && (
          <span className={`text-xs ${rcodeColor}`}>{event.response_code}</span>
        )}
      </div>
      <div className="flex gap-4 text-xs text-[#4d6480]">
        {event.response && (
          <span>レスポンス: <span className="text-falcon-muted font-mono">{event.response}</span></span>
        )}
        {event.process_name && (
          <span>プロセス: <span className="text-falcon-muted font-mono">{event.process_name}</span></span>
        )}
      </div>
    </div>
  )
}

// ── Event Config ───────────────────────────────────────────────

const EVENT_CONFIG = {
  process: {
    icon: PlayCircle,
    color: 'text-green-400',
    dotColor: 'bg-green-400',
    borderColor: 'border-l-green-500/60',
    bgColor: 'bg-green-500/5',
    label: 'プロセス',
  },
  file: {
    icon: Folder,
    color: 'text-yellow-400',
    dotColor: 'bg-yellow-400',
    borderColor: 'border-l-yellow-500/60',
    bgColor: 'bg-yellow-500/5',
    label: 'ファイル',
  },
  network: {
    icon: Wifi,
    color: 'text-blue-400',
    dotColor: 'bg-blue-400',
    borderColor: 'border-l-blue-500/60',
    bgColor: 'bg-blue-500/5',
    label: 'ネットワーク',
  },
  dns: {
    icon: Globe,
    color: 'text-purple-400',
    dotColor: 'bg-purple-400',
    borderColor: 'border-l-purple-500/60',
    bgColor: 'bg-purple-500/5',
    label: 'DNS',
  },
}

// ── Event Density Ruler ────────────────────────────────────────

function EventDensityRuler({
  events,
  from,
  to,
}: {
  events: TimelineEvent[]
  from: string
  to: string
}) {
  const BUCKETS = 30
  const fromMs = new Date(from).getTime()
  const toMs   = new Date(to).getTime()
  const range  = toMs - fromMs
  if (range <= 0 || events.length === 0) return null

  const bucketSize = range / BUCKETS
  const counts = Array.from({ length: BUCKETS }, (_, i) => {
    const lo = fromMs + i * bucketSize
    const hi = lo + bucketSize
    return events.filter(e => {
      const ts = new Date(e.timestamp).getTime()
      return ts >= lo && ts < hi
    }).length
  })
  const maxCount = Math.max(1, ...counts)

  const colorMap: Record<EventType, string> = {
    process: '#22c55e',
    file: '#eab308',
    network: '#3b82f6',
    dns: '#a855f7',
  }

  const getDominantColor = (i: number): string => {
    const lo = fromMs + i * bucketSize
    const hi = lo + bucketSize
    const inBucket = events.filter(e => {
      const ts = new Date(e.timestamp).getTime()
      return ts >= lo && ts < hi
    })
    if (inBucket.length === 0) return '#1e2d42'
    const typeCounts: Record<string, number> = {}
    inBucket.forEach(e => { typeCounts[e.type] = (typeCounts[e.type] || 0) + 1 })
    const dominant = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0][0] as EventType
    return colorMap[dominant]
  }

  const fmt = (ms: number) => new Date(ms).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg px-4 pt-3 pb-2 mb-4">
      <div className="flex items-center justify-between mb-2">
        <p className="text-[10px] font-semibold text-[#4d6480] uppercase tracking-wider">
          イベント密度 — {events.length} 件
        </p>
        <div className="flex items-center gap-3">
          {(Object.keys(colorMap) as EventType[]).map(type => (
            <div key={type} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: colorMap[type] }} />
              <span className="text-[9px] text-[#4d6480]">{EVENT_CONFIG[type].label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="flex items-end gap-px h-10">
        {counts.map((count, i) => (
          <div
            key={i}
            className="flex-1 rounded-t transition-opacity hover:opacity-70"
            style={{
              height: count > 0 ? `${Math.max(3, (count / maxCount) * 36)}px` : '2px',
              backgroundColor: getDominantColor(i),
              opacity: count > 0 ? 0.85 : 0.3,
            }}
            title={`${fmt(fromMs + i * bucketSize)} — ${count}件`}
          />
        ))}
      </div>
      <div className="flex justify-between mt-1">
        <span className="text-[9px] text-falcon-subtle font-mono">{fmt(fromMs)}</span>
        <span className="text-[9px] text-falcon-subtle font-mono">{fmt(toMs)}</span>
      </div>
    </div>
  )
}

// ── Timeline Event Card ────────────────────────────────────────

function TimelineEventCard({ event }: { event: TimelineEvent }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = EVENT_CONFIG[event.type]
  const Icon = cfg.icon

  return (
    <div className="flex gap-4 group">
      {/* Left timeline dot */}
      <div className="flex flex-col items-center shrink-0" style={{ width: 24 }}>
        <div className={`w-3 h-3 rounded-full ${cfg.dotColor} border-2 border-falcon-surface z-10 shrink-0 mt-4`} />
        <div className="w-px flex-1 bg-falcon-border mt-1" />
      </div>

      {/* Event card */}
      <div className={`
        flex-1 mb-3 rounded-lg border border-falcon-border border-l-2 ${cfg.borderColor}
        ${cfg.bgColor} overflow-hidden
      `}>
        {/* Card header */}
        <div
          className="flex items-start gap-3 px-4 py-3 cursor-pointer hover:bg-white/2 transition-colors"
          onClick={() => setExpanded(prev => !prev)}
        >
          <div className={`shrink-0 mt-0.5 ${cfg.color}`}>
            <Icon className="w-4 h-4" />
          </div>
          <div className="flex-1 min-w-0">
            {event.type === 'process' && <ProcessCard event={event as ProcessEvent} />}
            {event.type === 'file' && <FileCard event={event as FileEvent} />}
            {event.type === 'network' && <NetworkCard event={event as NetworkEvent} />}
            {event.type === 'dns' && <DnsCard event={event as DnsEvent} />}
          </div>
          <div className="flex items-center gap-2 shrink-0 text-right">
            <span className="text-[10px] text-falcon-subtle font-mono">
              {formatTimestamp(event.timestamp)}
            </span>
            {expanded
              ? <ChevronDown className="w-3.5 h-3.5 text-[#4d6480]" />
              : <ChevronRight className="w-3.5 h-3.5 text-[#4d6480]" />
            }
          </div>
        </div>

        {/* Expanded raw JSON */}
        {expanded && (
          <div className="border-t border-falcon-border px-4 py-3">
            <p className="text-[10px] text-[#4d6480] uppercase tracking-wider mb-2 font-medium">
              Raw Event Data
            </p>
            <pre className="text-xs text-falcon-muted font-mono bg-falcon-bg rounded-sm p-3 overflow-x-auto">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Time Preset Helper ─────────────────────────────────────────

function getPresetRange(preset: '1h' | '6h' | '24h' | '7d'): { from: string; to: string } {
  const now = new Date()
  const to = now.toISOString().slice(0, 16)
  const offsets: Record<string, number> = {
    '1h': 60,
    '6h': 360,
    '24h': 1440,
    '7d': 10080,
  }
  const from = new Date(now.getTime() - offsets[preset] * 60 * 1000).toISOString().slice(0, 16)
  return { from, to }
}

// ── Main Page ──────────────────────────────────────────────────

export default function ForensicsTimelinePage() {
  // Agent selection
  const [selectedAgentId, setSelectedAgentId] = useState<string>('')
  const [useMockAgents, setUseMockAgents] = useState(false)

  // Time range
  const now = new Date()
  const [timeFrom, setTimeFrom] = useState(
    new Date(now.getTime() - 60 * 60 * 1000).toISOString().slice(0, 16)
  )
  const [timeTo, setTimeTo] = useState(now.toISOString().slice(0, 16))

  // Query trigger
  const [queryParams, setQueryParams] = useState<{
    agentId: string; from: string; to: string
  } | null>(null)

  // Filters
  const [enabledTypes, setEnabledTypes] = useState<Set<EventType>>(
    new Set(['process', 'file', 'network', 'dns'])
  )
  const [searchQuery, setSearchQuery] = useState('')
  const [useMockEvents, setUseMockEvents] = useState(false)
  const [mockEvents, setMockEvents] = useState<TimelineEvent[]>([])

  // ── Fetch agents ─────────────────────────────────────────────
  const { data: agentsData, error: agentsError } = useQuery<AgentsResponse>({
    queryKey: ['agents-list'],
    queryFn: () => apiFetch<AgentsResponse>('/api/v1/agents'),
    staleTime: 60_000,
    retry: 1,
  })

  // Fallback to mock agents
  const agents: Agent[] = useMockAgents
    ? m(MOCK_AGENTS)
    : (agentsData?.data ?? agentsData?.agents ?? [])

  // When agents API fails, switch to mock
  if (USE_MOCK && agentsError && !useMockAgents) {
    setUseMockAgents(true)
  }

  // ── Fetch events ──────────────────────────────────────────────
  const { data: eventsData, error: eventsError, isFetching } = useQuery<EventsResponse>({
    queryKey: ['forensics-events', queryParams],
    queryFn: async () => {
      if (!queryParams) return { events: [] }
      const params = new URLSearchParams({
        from: new Date(queryParams.from).toISOString(),
        to: new Date(queryParams.to).toISOString(),
        types: 'process,file,network,dns',
      })
      return apiFetch<EventsResponse>(
        `/api/v1/agents/${queryParams.agentId}/events?${params.toString()}`
      )
    },
    enabled: !!queryParams,
    staleTime: 30_000,
    retry: 1,
  })

  // Fallback to mock events
  if (USE_MOCK && eventsError && !useMockEvents && queryParams) {
    const mocks = generateMockEvents(
      queryParams.agentId,
      new Date(queryParams.from),
      new Date(queryParams.to)
    )
    setMockEvents(mocks)
    setUseMockEvents(true)
  }

  const rawEvents: TimelineEvent[] = useMockEvents
    ? mockEvents
    : (eventsData?.events ?? [])

  // ── Filter & search ───────────────────────────────────────────
  const filteredEvents = useMemo(() => {
    let events = rawEvents.filter(e => enabledTypes.has(e.type))

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      events = events.filter(e => JSON.stringify(e).toLowerCase().includes(q))
    }

    return events.sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    )
  }, [rawEvents, enabledTypes, searchQuery])

  // ── Event type toggle ─────────────────────────────────────────
  const toggleType = useCallback((type: EventType) => {
    setEnabledTypes(prev => {
      const next = new Set(prev)
      if (next.has(type)) {
        next.delete(type)
      } else {
        next.add(type)
      }
      return next
    })
  }, [])

  // ── Load timeline ─────────────────────────────────────────────
  const handleLoadTimeline = useCallback(() => {
    if (!selectedAgentId) return
    setUseMockEvents(false)
    setMockEvents([])
    setQueryParams({ agentId: selectedAgentId, from: timeFrom, to: timeTo })
  }, [selectedAgentId, timeFrom, timeTo])

  // ── Time preset ───────────────────────────────────────────────
  const applyPreset = useCallback((preset: '1h' | '6h' | '24h' | '7d') => {
    const { from, to } = getPresetRange(preset)
    setTimeFrom(from)
    setTimeTo(to)
  }, [])

  // ── Export ────────────────────────────────────────────────────
  const handleExport = useCallback(() => {
    const blob = new Blob([JSON.stringify(filteredEvents, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const agentName = agents.find(a => a.id === selectedAgentId)?.hostname ?? selectedAgentId
    a.download = `forensics-timeline-${agentName}-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [filteredEvents, agents, selectedAgentId])

  // ── Event counts ──────────────────────────────────────────────
  const typeCounts = useMemo(() => {
    const counts: Record<EventType, number> = { process: 0, file: 0, network: 0, dns: 0 }
    rawEvents.forEach(e => counts[e.type]++)
    return counts
  }, [rawEvents])

  const selectedAgent = agents.find(a => a.id === selectedAgentId)

  return (
    <div className="min-h-full bg-falcon-bg p-6">
      {/* Page Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-linear-to-br from-[#4d8fff]/20 to-[#7b61ff]/20
                          border border-[#4d8fff]/20 flex items-center justify-center">
            <Activity className="w-5 h-5 text-[#4d8fff]" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-falcon-text">フォレンジックタイムライン</h1>
            <p className="text-xs text-[#4d6480]">エンドポイントイベントの時系列分析</p>
          </div>
        </div>

        {filteredEvents.length > 0 && (
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-falcon-hover border border-falcon-border
                       text-sm text-falcon-muted hover:text-falcon-text hover:border-[#2a3d5a] transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>エクスポート</span>
          </button>
        )}
      </div>

      {/* Control Panel */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4 mb-4">
        <div className="flex flex-wrap gap-4 items-end">
          {/* Agent Selector */}
          <div className="flex flex-col gap-1.5 min-w-[200px]">
            <label className="text-xs font-medium text-[#4d6480] uppercase tracking-wider">
              対象エージェント
            </label>
            <div className="relative">
              <select
                value={selectedAgentId}
                onChange={e => setSelectedAgentId(e.target.value)}
                className="w-full bg-falcon-bg border border-falcon-border rounded-lg px-3 py-2 text-sm
                           text-falcon-text appearance-none cursor-pointer
                           focus:outline-hidden focus:border-[#4d8fff]/50 transition-colors pr-8"
              >
                <option value="">エージェントを選択...</option>
                {agents.map(agent => (
                  <option key={agent.id} value={agent.id}>
                    {agent.hostname}
                    {agent.os ? ` (${agent.os})` : ''}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-2.5 top-2.5 w-4 h-4 text-[#4d6480] pointer-events-none" />
            </div>
            {useMockAgents && (
              <span className="text-[10px] text-yellow-500/70">モックデータ使用中</span>
            )}
          </div>

          {/* Time From */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-[#4d6480] uppercase tracking-wider">
              開始日時
            </label>
            <input
              type="datetime-local"
              value={timeFrom}
              onChange={e => setTimeFrom(e.target.value)}
              className="bg-falcon-bg border border-falcon-border rounded-lg px-3 py-2 text-sm
                         text-falcon-text focus:outline-hidden focus:border-[#4d8fff]/50 transition-colors"
            />
          </div>

          {/* Time To */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-[#4d6480] uppercase tracking-wider">
              終了日時
            </label>
            <input
              type="datetime-local"
              value={timeTo}
              onChange={e => setTimeTo(e.target.value)}
              className="bg-falcon-bg border border-falcon-border rounded-lg px-3 py-2 text-sm
                         text-falcon-text focus:outline-hidden focus:border-[#4d8fff]/50 transition-colors"
            />
          </div>

          {/* Preset Buttons */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-[#4d6480] uppercase tracking-wider">
              プリセット
            </label>
            <div className="flex gap-1.5">
              {(['1h', '6h', '24h', '7d'] as const).map(p => (
                <button
                  key={p}
                  onClick={() => applyPreset(p)}
                  className="px-2.5 py-2 text-xs rounded-lg bg-falcon-bg border border-falcon-border
                             text-falcon-muted hover:text-falcon-text hover:border-[#2a3d5a] transition-colors"
                >
                  {p === '7d' ? '直近7日' : p === '24h' ? '直近24h' : p === '6h' ? '直近6h' : '直近1h'}
                </button>
              ))}
            </div>
          </div>

          {/* Load Button */}
          <button
            onClick={handleLoadTimeline}
            disabled={!selectedAgentId || isFetching}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#4d8fff] text-white text-sm font-medium
                       hover:bg-[#3d7fff] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isFetching
              ? <><Loader2 className="w-4 h-4 animate-spin" /> 読み込み中...</>
              : <><Activity className="w-4 h-4" /> タイムライン読み込み</>
            }
          </button>
        </div>
      </div>

      {/* Filter + Search Bar */}
      {(rawEvents.length > 0 || queryParams) && (
        <div className="bg-falcon-surface border border-falcon-border rounded-lg px-4 py-3 mb-4">
          <div className="flex flex-wrap items-center gap-4">
            {/* Type Toggles */}
            <div className="flex items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-[#4d6480]" />
              <span className="text-xs text-[#4d6480] mr-1">フィルター:</span>
              {(Object.keys(EVENT_CONFIG) as EventType[]).map(type => {
                const cfg = EVENT_CONFIG[type]
                const Icon = cfg.icon
                const enabled = enabledTypes.has(type)
                return (
                  <button
                    key={type}
                    onClick={() => toggleType(type)}
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border transition-colors ${
                      enabled
                        ? `${cfg.color} border-current/30 bg-current/5`
                        : 'text-falcon-subtle border-falcon-border hover:border-[#2a3d5a]'
                    }`}
                  >
                    <Icon className="w-3 h-3" />
                    <span>{cfg.label}</span>
                    <span className="text-[10px] opacity-60">({typeCounts[type]})</span>
                  </button>
                )
              })}
            </div>

            {/* Search */}
            <div className="flex-1 min-w-[200px] relative">
              <Search className="absolute left-3 top-2 w-3.5 h-3.5 text-[#4d6480]" />
              <input
                type="text"
                placeholder="イベントを検索..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-falcon-bg border border-falcon-border rounded-lg pl-8 pr-3 py-1.5 text-sm
                           text-falcon-text placeholder-falcon-subtle
                           focus:outline-hidden focus:border-[#4d8fff]/50 transition-colors"
              />
            </div>

            {/* Stats */}
            {filteredEvents.length > 0 && (
              <span className="text-xs text-[#4d6480]">
                {filteredEvents.length} 件のイベント
                {searchQuery && ` (検索: "${searchQuery}")`}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Main Content */}
      {!queryParams ? (
        // Empty state — no query yet
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <div className="w-16 h-16 rounded-2xl bg-falcon-surface border border-falcon-border flex items-center justify-center mb-4">
            <Activity className="w-8 h-8 text-falcon-border" />
          </div>
          <h3 className="text-base font-medium text-[#4d6480] mb-1">タイムラインを読み込む</h3>
          <p className="text-sm text-falcon-subtle max-w-sm">
            エージェントと時間範囲を選択して「タイムライン読み込み」をクリックしてください
          </p>
        </div>
      ) : isFetching ? (
        // Loading
        <div className="flex flex-col items-center justify-center py-24">
          <Loader2 className="w-8 h-8 text-[#4d8fff] animate-spin mb-3" />
          <p className="text-sm text-[#4d6480]">イベントを取得中...</p>
        </div>
      ) : filteredEvents.length === 0 ? (
        // No events
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <div className="w-16 h-16 rounded-2xl bg-falcon-surface border border-falcon-border flex items-center justify-center mb-4">
            <Clock className="w-8 h-8 text-falcon-border" />
          </div>
          <h3 className="text-base font-medium text-[#4d6480] mb-1">イベントが見つかりません</h3>
          <p className="text-sm text-falcon-subtle">
            {searchQuery
              ? `"${searchQuery}" に一致するイベントはありません`
              : '選択した時間範囲にイベントはありません'}
          </p>
        </div>
      ) : (
        // Timeline
        <div>
          {queryParams && (
            <EventDensityRuler
              events={filteredEvents}
              from={queryParams.from}
              to={queryParams.to}
            />
          )}
          <div className="flex gap-6">
          {/* Timeline main */}
          <div className="flex-1 min-w-0">
            {/* Agent Info Banner */}
            {selectedAgent && (
              <div className="flex items-center gap-3 px-4 py-2.5 mb-4 rounded-lg
                              bg-falcon-surface border border-falcon-border">
                <Server className="w-4 h-4 text-[#4d8fff]" />
                <span className="text-sm font-medium text-falcon-text">{selectedAgent.hostname}</span>
                {selectedAgent.os && (
                  <span className="text-xs text-[#4d6480]">{selectedAgent.os}</span>
                )}
                {selectedAgent.status && (
                  <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                    selectedAgent.status === 'online'
                      ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                      : 'bg-red-500/10 text-red-400 border border-red-500/20'
                  }`}>
                    {selectedAgent.status === 'online' ? 'オンライン' : 'オフライン'}
                  </span>
                )}
                <span className="ml-auto text-xs text-falcon-subtle font-mono">
                  {new Date(timeFrom).toLocaleString('ja-JP')}
                  {' → '}
                  {new Date(timeTo).toLocaleString('ja-JP')}
                </span>
                {useMockEvents && (
                  <span className="text-[10px] bg-yellow-500/10 text-yellow-500 border border-yellow-500/20
                                   px-1.5 py-0.5 rounded">モックデータ</span>
                )}
              </div>
            )}

            {/* Timeline Items */}
            <div className="relative">
              {filteredEvents.map((event, index) => (
                <TimelineEventCard key={event.id ?? index} event={event} />
              ))}
            </div>
          </div>

          {/* Sidebar Summary */}
          <div className="w-52 shrink-0 hidden xl:block">
            <div className="sticky top-20 space-y-3">
              <div className="bg-falcon-surface border border-falcon-border rounded-lg p-3">
                <h3 className="text-xs font-semibold text-[#4d6480] uppercase tracking-wider mb-3">
                  イベント集計
                </h3>
                {(Object.keys(EVENT_CONFIG) as EventType[]).map(type => {
                  const cfg = EVENT_CONFIG[type]
                  const count = typeCounts[type]
                  const total = rawEvents.length
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0
                  return (
                    <div key={type} className="mb-2.5">
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-xs ${cfg.color}`}>{cfg.label}</span>
                        <span className="text-xs text-[#4d6480]">{count}</span>
                      </div>
                      <div className="h-1.5 bg-falcon-border rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${cfg.dotColor}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>

              <div className="bg-falcon-surface border border-falcon-border rounded-lg p-3">
                <h3 className="text-xs font-semibold text-[#4d6480] uppercase tracking-wider mb-2">
                  合計
                </h3>
                <p className="text-2xl font-bold text-falcon-text">{filteredEvents.length}</p>
                <p className="text-[11px] text-[#4d6480] mt-0.5">件のイベント</p>
              </div>
            </div>
          </div>
          </div>
        </div>
      )}
    </div>
  )
}
