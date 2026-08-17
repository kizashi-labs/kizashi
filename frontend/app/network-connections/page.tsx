'use client'

import React, { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Network, Globe, ArrowUpRight, ArrowDownLeft, RefreshCw,
  Search, Filter, Wifi,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface RawEvent {
  id: string
  agent_id: string
  event_type: string
  raw_data: string | Record<string, unknown>
  timestamp: string
  // legacy aliases kept for compat
  type?: string
  raw_event?: string
  created_at?: string
}

interface NetworkConnection {
  src_ip?: string
  src_port?: number
  dst_ip?: string
  dst_port?: number
  protocol?: string
  direction?: string
  state?: string
  process_name?: string
  pid?: number
  bytes_sent?: number
  bytes_recv?: number
}

interface EventsResponse {
  events?: RawEvent[]
  data?: RawEvent[]
}

interface AgentsResponse {
  agents?: { id: string; hostname: string }[]
  data?: { id: string; hostname: string }[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RFC1918 = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^::1$/,
  /^fc|^fd/,
]

function isPrivateIP(ip?: string): boolean {
  if (!ip) return true
  return RFC1918.some(re => re.test(ip))
}

const COMMON_PORTS = new Set([
  80, 443, 8080, 8443, 53, 22, 25, 587, 465, 21, 20, 3306, 5432,
  1433, 27017, 6379, 5672, 9200, 9300,
])

function isSuspicious(conn: NetworkConnection): boolean {
  if (isPrivateIP(conn.dst_ip)) return false
  if (conn.dst_port && !COMMON_PORTS.has(conn.dst_port)) return true
  return false
}

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function parseConn(raw: string | Record<string, unknown> | undefined): NetworkConnection {
  if (!raw) return {}
  if (typeof raw === 'object') return raw as NetworkConnection
  try {
    return JSON.parse(raw)
  } catch {
    return {}
  }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string
  value: string | number
  icon: React.ElementType
  color: 'blue' | 'green' | 'yellow' | 'orange' | 'purple'
}) {
  const colorMap: Record<string, string> = {
    blue:   'text-blue-400   bg-blue-900/30',
    green:  'text-green-400  bg-green-900/30',
    yellow: 'text-yellow-400 bg-yellow-900/30',
    orange: 'text-orange-400 bg-orange-900/30',
    purple: 'text-purple-400 bg-purple-900/30',
  }
  const cls = colorMap[color]
  return (
    <div className="bg-falcon-card rounded-xl border border-falcon-border p-4">
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-lg ${cls}`}>
          <Icon className={`w-5 h-5 ${cls.split(' ')[0]}`} />
        </div>
        <div>
          <p className="text-2xl font-bold text-white">{typeof value === 'number' ? value.toLocaleString() : value}</p>
          <p className="text-[#8899aa] text-xs mt-0.5">{label}</p>
        </div>
      </div>
    </div>
  )
}

function ProtocolBadge({ proto }: { proto?: string }) {
  if (!proto) return <span className="text-[#5a6a7a] text-xs">—</span>
  const upper = proto.toUpperCase()
  const cls = upper === 'TCP'
    ? 'bg-blue-900/40 text-blue-300'
    : upper === 'UDP'
    ? 'bg-purple-900/40 text-purple-300'
    : 'bg-gray-700 text-gray-300'
  return (
    <span className={`px-2 py-0.5 rounded-sm text-xs font-mono font-semibold ${cls}`}>
      {upper}
    </span>
  )
}

function DirectionBadge({ direction }: { direction?: string }) {
  if (!direction) return <span className="text-[#5a6a7a] text-xs">—</span>
  const isIn = direction.toLowerCase() === 'inbound'
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium
      ${isIn ? 'bg-blue-900/40 text-blue-300' : 'bg-orange-900/40 text-orange-300'}`}>
      {isIn ? <ArrowDownLeft className="w-3 h-3" /> : <ArrowUpRight className="w-3 h-3" />}
      {isIn ? 'inbound' : 'outbound'}
    </span>
  )
}

function StateBadge({ state }: { state?: string }) {
  if (!state) return <span className="text-[#5a6a7a] text-xs">—</span>
  const upper = state.toUpperCase()
  let cls = 'bg-gray-700/60 text-gray-300'
  if (upper === 'ESTABLISHED') cls = 'bg-green-900/40 text-green-300'
  else if (upper === 'LISTEN')  cls = 'bg-yellow-900/40 text-yellow-300'
  else if (upper === 'TIME_WAIT' || upper === 'CLOSE_WAIT') cls = 'bg-red-900/30 text-red-300'
  else if (upper === 'SYN_SENT' || upper === 'SYN_RECV')   cls = 'bg-indigo-900/40 text-indigo-300'
  return (
    <span className={`px-2 py-0.5 rounded-sm text-xs font-mono ${cls}`}>
      {upper}
    </span>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

const PAGE_SIZE = 50

export default function NetworkConnectionsPage() {
  const [agentFilter, setAgentFilter]       = useState<string>('all')
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL')
  const [directionFilter, setDirectionFilter] = useState<string>('ALL')
  const [stateFilter, setStateFilter]       = useState<string>('ALL')
  const [search, setSearch]                 = useState('')
  const [page, setPage]                     = useState(1)
  const [autoRefresh, setAutoRefresh]       = useState(true)

  // Agents query
  const { data: agentsData } = useQuery<AgentsResponse>({
    queryKey: ['agents-list-netconn'],
    queryFn: () => apiFetch<AgentsResponse>('/api/v1/agents?limit=200'),
    staleTime: 60_000,
  })
  const agents = agentsData?.agents ?? agentsData?.data ?? []
  const hostnameMap = useMemo(() => {
    const m: Record<string, string> = {}
    agents.forEach(a => { m[a.id] = a.hostname })
    return m
  }, [agents])

  // Events query
  const eventsUrl = agentFilter === 'all'
    ? '/api/v1/events?type=network&per_page=100'
    : `/api/v1/events?type=network&per_page=100&agent_id=${agentFilter}`

  const { data: eventsData, isLoading, isFetching, refetch } = useQuery<EventsResponse>({
    queryKey: ['network-connections', agentFilter],
    queryFn: () => apiFetch<EventsResponse>(eventsUrl),
    refetchInterval: autoRefresh ? 15_000 : false,
  })

  const allEvents: RawEvent[] = eventsData?.events ?? eventsData?.data ?? []

  // Parse + filter
  const filtered = useMemo(() => {
    return allEvents.filter(ev => {
      const conn = parseConn(ev.raw_data ?? ev.raw_event)

      if (protocolFilter !== 'ALL' && (conn.protocol ?? '').toUpperCase() !== protocolFilter) return false
      if (directionFilter !== 'ALL' && (conn.direction ?? '').toLowerCase() !== directionFilter.toLowerCase()) return false
      if (stateFilter !== 'ALL' && (conn.state ?? '').toUpperCase() !== stateFilter.toUpperCase()) return false

      if (search) {
        const q = search.toLowerCase()
        const hostname = hostnameMap[ev.agent_id] ?? ev.agent_id
        const srcIp = conn.src_ip ?? ''
        const dstIp = conn.dst_ip ?? ''
        const proc  = conn.process_name ?? ''
        if (
          !hostname.toLowerCase().includes(q) &&
          !srcIp.includes(q) &&
          !dstIp.includes(q) &&
          !proc.toLowerCase().includes(q)
        ) return false
      }

      return true
    })
  }, [allEvents, protocolFilter, directionFilter, stateFilter, search, hostnameMap])

  // Stats
  const stats = useMemo(() => {
    const established = allEvents.filter(ev => {
      const c = parseConn(ev.raw_data ?? ev.raw_event)
      return (c.state ?? '').toUpperCase() === 'ESTABLISHED'
    }).length
    const listening = allEvents.filter(ev => {
      const c = parseConn(ev.raw_data ?? ev.raw_event)
      return (c.state ?? '').toUpperCase() === 'LISTEN'
    }).length
    const inbound = allEvents.filter(ev => {
      const c = parseConn(ev.raw_data ?? ev.raw_event)
      return (c.direction ?? '').toLowerCase() === 'inbound'
    }).length
    const outbound = allEvents.filter(ev => {
      const c = parseConn(ev.raw_data ?? ev.raw_event)
      return (c.direction ?? '').toLowerCase() === 'outbound'
    }).length
    return { total: allEvents.length, established, listening, inbound, outbound }
  }, [allEvents])

  // Unique states for dropdown
  const uniqueStates = useMemo(() => {
    const s = new Set<string>()
    allEvents.forEach(ev => {
      const st = parseConn(ev.raw_data ?? ev.raw_event).state
      if (st) s.add(st.toUpperCase())
    })
    return Array.from(s).sort()
  }, [allEvents])

  // Pagination
  const totalFiltered = filtered.length
  const totalPages    = Math.max(1, Math.ceil(totalFiltered / PAGE_SIZE))
  const paginated     = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  function handleSearchChange(v: string) {
    setSearch(v)
    setPage(1)
  }
  function handleFilterChange<T>(setter: (v: T) => void, v: T) {
    setter(v)
    setPage(1)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-blue-700 rounded-lg flex items-center justify-center">
            <Network className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">ネットワーク接続</h1>
            <p className="text-sm text-[#8899aa]">エンドポイントのネットワーク接続をリアルタイムで監視します</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors border ${
              autoRefresh
                ? 'border-blue-600 bg-blue-900/30 text-blue-300'
                : 'border-falcon-border bg-falcon-card text-[#8899aa] hover:bg-falcon-hover'
            }`}
          >
            <Wifi className="w-4 h-4" />
            {autoRefresh ? '自動更新: ON' : '自動更新: OFF'}
          </button>

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-card border border-falcon-border
                       hover:bg-falcon-hover text-white text-sm rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="総接続数"       value={stats.total}       icon={Network}       color="blue"   />
        <StatCard label="ESTABLISHED"   value={stats.established}  icon={Globe}         color="green"  />
        <StatCard label="LISTEN"        value={stats.listening}    icon={Filter}        color="yellow" />
        <StatCard label="インバウンド"    value={stats.inbound}      icon={ArrowDownLeft} color="blue"   />
        <StatCard label="アウトバウンド"  value={stats.outbound}     icon={ArrowUpRight}  color="orange" />
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap gap-3 items-center">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#8899aa]" />
          <input
            type="text"
            placeholder="IP・ホスト名・プロセス検索..."
            value={search}
            onChange={e => handleSearchChange(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-falcon-card border border-falcon-border rounded-lg
                       text-white text-sm placeholder-[#5a6a7a] focus:outline-hidden focus:border-falcon-blue"
          />
        </div>

        {/* Agent dropdown */}
        <select
          value={agentFilter}
          onChange={e => { setAgentFilter(e.target.value); setPage(1) }}
          className="px-3 py-2 bg-falcon-card border border-falcon-border rounded-lg text-sm text-white
                     focus:outline-hidden focus:border-falcon-blue min-w-[160px]"
        >
          <option value="all">すべてのエージェント</option>
          {agents.map(a => (
            <option key={a.id} value={a.id}>{a.hostname || a.id}</option>
          ))}
        </select>

        {/* Protocol */}
        <div className="flex rounded-lg overflow-hidden border border-falcon-border">
          {(['ALL', 'TCP', 'UDP'] as const).map(p => (
            <button
              key={p}
              onClick={() => handleFilterChange(setProtocolFilter, p)}
              className={`px-3 py-2 text-sm transition-colors ${
                protocolFilter === p
                  ? 'bg-blue-700 text-white'
                  : 'bg-falcon-card text-[#8899aa] hover:bg-falcon-hover hover:text-white'
              }`}
            >
              {p}
            </button>
          ))}
        </div>

        {/* Direction */}
        <div className="flex rounded-lg overflow-hidden border border-falcon-border">
          {([
            { val: 'ALL',      label: '方向: ALL' },
            { val: 'inbound',  label: 'inbound'  },
            { val: 'outbound', label: 'outbound' },
          ] as const).map(d => (
            <button
              key={d.val}
              onClick={() => handleFilterChange(setDirectionFilter, d.val)}
              className={`px-3 py-2 text-sm transition-colors ${
                directionFilter === d.val
                  ? 'bg-blue-700 text-white'
                  : 'bg-falcon-card text-[#8899aa] hover:bg-falcon-hover hover:text-white'
              }`}
            >
              {d.label}
            </button>
          ))}
        </div>

        {/* State dropdown */}
        <select
          value={stateFilter}
          onChange={e => handleFilterChange(setStateFilter, e.target.value)}
          className="px-3 py-2 bg-falcon-card border border-falcon-border rounded-lg text-sm text-white
                     focus:outline-hidden focus:border-falcon-blue min-w-[150px]"
        >
          <option value="ALL">状態: ALL</option>
          {uniqueStates.map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="bg-falcon-card rounded-xl border border-falcon-border overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-blue-500" />
          </div>
        ) : paginated.length === 0 ? (
          <div className="text-center py-20 text-[#5a6a7a]">
            <Network className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>ネットワーク接続が見つかりません</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[#8899aa] border-b border-falcon-border bg-[#0d1526]">
                  <th className="px-4 py-3 font-medium whitespace-nowrap">日時</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">エージェント</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">送信元 IP:ポート</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">宛先 IP:ポート</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">プロトコル</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">方向</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">状態</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">プロセス</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">送信</th>
                  <th className="px-4 py-3 font-medium whitespace-nowrap">受信</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {paginated.map(ev => {
                  const conn     = parseConn(ev.raw_data ?? ev.raw_event)
                  const hostname = hostnameMap[ev.agent_id] ?? ev.agent_id.slice(0, 12)
                  const suspicious = isSuspicious(conn)
                  return (
                    <tr
                      key={ev.id}
                      className={`transition-colors hover:bg-falcon-raised ${
                        suspicious ? 'bg-yellow-900/10 hover:bg-yellow-900/20' : ''
                      }`}
                    >
                      {/* Timestamp */}
                      <td className="px-4 py-2.5 text-[#8899aa] font-mono text-xs whitespace-nowrap">
                        {new Date(ev.timestamp ?? ev.created_at ?? '').toLocaleString('ja-JP')}
                      </td>

                      {/* Agent */}
                      <td className="px-4 py-2.5 text-[#c9d6e8] text-xs whitespace-nowrap">
                        {hostname}
                      </td>

                      {/* Src IP:port */}
                      <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap">
                        {conn.src_ip ? (
                          <span className="text-[#c9d6e8]">
                            {conn.src_ip}
                            {conn.src_port !== undefined && (
                              <span className="text-[#5a6a7a]">:{conn.src_port}</span>
                            )}
                          </span>
                        ) : (
                          <span className="text-[#5a6a7a]">—</span>
                        )}
                      </td>

                      {/* Dst IP:port */}
                      <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap">
                        {conn.dst_ip ? (
                          <span className={suspicious ? 'text-yellow-300' : 'text-[#c9d6e8]'}>
                            {conn.dst_ip}
                            {conn.dst_port !== undefined && (
                              <span className="text-[#5a6a7a]">:{conn.dst_port}</span>
                            )}
                          </span>
                        ) : (
                          <span className="text-[#5a6a7a]">—</span>
                        )}
                      </td>

                      {/* Protocol */}
                      <td className="px-4 py-2.5">
                        <ProtocolBadge proto={conn.protocol} />
                      </td>

                      {/* Direction */}
                      <td className="px-4 py-2.5">
                        <DirectionBadge direction={conn.direction} />
                      </td>

                      {/* State */}
                      <td className="px-4 py-2.5">
                        <StateBadge state={conn.state} />
                      </td>

                      {/* Process */}
                      <td className="px-4 py-2.5 text-xs max-w-[180px]">
                        {conn.process_name ? (
                          <div
                            className="text-[#c9d6e8] truncate"
                            title={conn.pid ? `${conn.process_name} (PID: ${conn.pid})` : conn.process_name}
                          >
                            {conn.process_name}
                            {conn.pid && (
                              <span className="ml-1 text-[#5a6a7a] text-[10px]">({conn.pid})</span>
                            )}
                          </div>
                        ) : conn.pid ? (
                          <span className="text-[#5a6a7a]">PID:{conn.pid}</span>
                        ) : (
                          <span className="text-[#5a6a7a]">—</span>
                        )}
                      </td>

                      {/* Bytes sent */}
                      <td className="px-4 py-2.5 text-[#8899aa] text-xs whitespace-nowrap text-right">
                        {formatBytes(conn.bytes_sent)}
                      </td>

                      {/* Bytes recv */}
                      <td className="px-4 py-2.5 text-[#8899aa] text-xs whitespace-nowrap text-right">
                        {formatBytes(conn.bytes_recv)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalFiltered > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-[#8899aa]">
          <span>
            {totalFiltered.toLocaleString()} 件中{' '}
            {((page - 1) * PAGE_SIZE + 1).toLocaleString()}–
            {Math.min(page * PAGE_SIZE, totalFiltered).toLocaleString()} 件
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1.5 bg-falcon-card border border-falcon-border rounded-lg
                         hover:bg-falcon-hover disabled:opacity-40 transition-colors"
            >
              前へ
            </button>
            <span className="text-xs">
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1.5 bg-falcon-card border border-falcon-border rounded-lg
                         hover:bg-falcon-hover disabled:opacity-40 transition-colors"
            >
              次へ
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
