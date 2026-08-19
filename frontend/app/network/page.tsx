'use client'

import { useState, useCallback, useRef, useEffect, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { m } from '@/lib/mock'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts'
import {
  Network, Globe, Server, Wifi, Activity, Clock, Search,
  Download, RefreshCw, AlertTriangle, X, ChevronRight,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import type { Agent, NetworkEventData } from '@/types/api'

// ─── Local types ─────────────────────────────────────────────────────────────

interface NetworkStats {
  total: number
  top_destinations: { ip: string; count: number }[]
  top_ports: { port: string; protocol: string; count: number }[]
  top_agents: { agent_id: string; hostname: string; count: number }[]
}

interface NetworkEvent {
  id: string
  agent_id: string
  event_type: string
  raw_data: NetworkEventData
  timestamp: string
  time?: string
}

interface AgentsResponse {
  data: Agent[]
  total: number
}

// ─── Graph types ──────────────────────────────────────────────────────────────

interface GraphNode {
  id: string           // agent id or external IP
  label: string        // hostname or IP
  type: 'agent' | 'external'
  status?: Agent['status']
  x: number
  y: number
}

interface GraphEdge {
  source: string       // node id
  target: string       // node id
  count: number
  suspicious: boolean
  ports: string[]
}

// ─── Constants ────────────────────────────────────────────────────────────────

const HOURS_OPTIONS = [
  { value: 1,   label: '1時間' },
  { value: 6,   label: '6時間' },
  { value: 24,  label: '24時間' },
]

const SUSPICIOUS_PORTS = new Set(['4444', '1337', '31337', '6667', '23', '135', '445'])

const NOTABLE_PORTS: Record<string, { label: string; risk: 'critical' | 'warn' | 'info' }> = {
  '4444':  { label: 'Metasploit default', risk: 'critical' },
  '1337':  { label: 'Leet/hacker port',   risk: 'critical' },
  '31337': { label: 'Backdoor',           risk: 'critical' },
  '6667':  { label: 'IRC C2',             risk: 'critical' },
  '3389':  { label: 'RDP',               risk: 'warn' },
  '22':    { label: 'SSH',               risk: 'info' },
  '445':   { label: 'SMB',               risk: 'warn' },
  '23':    { label: 'Telnet',            risk: 'warn' },
  '135':   { label: 'RPC',              risk: 'warn' },
  '80':    { label: 'HTTP',             risk: 'info' },
  '443':   { label: 'HTTPS',            risk: 'info' },
  '53':    { label: 'DNS',              risk: 'info' },
}

const STATUS_COLOR: Record<string, string> = {
  online:   '#22c55e',
  isolated: '#ef4444',
  offline:  '#6b7280',
  error:    '#f59e0b',
  inactive: '#3f4652',
}

// 凡例のラベル。以前は三項演算子の連鎖で、末尾が「エラー」へ落ちる作りだった
// ため、STATUS_COLOR にキーを足すたびに未対応の状態が「エラー」と誤表示された。
const STATUS_LABEL: Record<string, string> = {
  online:   'オンライン',
  isolated: '隔離中',
  offline:  'オフライン',
  error:    'エラー',
  inactive: '非アクティブ',
}

// ─── Mock fallback data ───────────────────────────────────────────────────────

const _mockNow = Date.now()
const MOCK_AGENTS_RESPONSE: AgentsResponse = {
  data: [
    { id: 'ag-001', hostname: 'WIN-SRV-001', status: 'online' } as Agent,
    { id: 'ag-002', hostname: 'DEV-LNX-01',  status: 'online' } as Agent,
    { id: 'ag-003', hostname: 'FINANCE-PC',  status: 'online' } as Agent,
    { id: 'ag-004', hostname: 'HR-LAPTOP',   status: 'offline' } as Agent,
    { id: 'ag-005', hostname: 'DMZ-WEB-01',  status: 'isolated' } as Agent,
  ],
  total: 5,
}

const MOCK_GRAPH_EVENTS_DATA: NetworkEvent[] = [
  { id: 'mg-01', agent_id: 'ag-001', event_type: 'network', timestamp: new Date(_mockNow - 1_000).toISOString(),  raw_data: { dst_ip: '8.8.8.8',        dst_port: 53,    protocol: 'UDP', process_name: 'svchost.exe'       } as unknown as NetworkEventData },
  { id: 'mg-02', agent_id: 'ag-001', event_type: 'network', timestamp: new Date(_mockNow - 2_000).toISOString(),  raw_data: { dst_ip: '185.220.101.5',  dst_port: 4444,  protocol: 'TCP', process_name: 'powershell.exe'    } as unknown as NetworkEventData },
  { id: 'mg-03', agent_id: 'ag-001', event_type: 'network', timestamp: new Date(_mockNow - 3_000).toISOString(),  raw_data: { dst_ip: '185.220.101.5',  dst_port: 443,   protocol: 'TCP', process_name: 'chrome.exe'         } as unknown as NetworkEventData },
  { id: 'mg-04', agent_id: 'ag-001', event_type: 'network', timestamp: new Date(_mockNow - 4_000).toISOString(),  raw_data: { dst_ip: '1.1.1.1',        dst_port: 443,   protocol: 'TCP', process_name: 'chrome.exe'         } as unknown as NetworkEventData },
  { id: 'mg-05', agent_id: 'ag-002', event_type: 'network', timestamp: new Date(_mockNow - 5_000).toISOString(),  raw_data: { dst_ip: '8.8.8.8',        dst_port: 53,    protocol: 'UDP', process_name: 'systemd-resolve'    } as unknown as NetworkEventData },
  { id: 'mg-06', agent_id: 'ag-002', event_type: 'network', timestamp: new Date(_mockNow - 6_000).toISOString(),  raw_data: { dst_ip: '91.108.4.236',   dst_port: 1337,  protocol: 'TCP', process_name: 'python3'            } as unknown as NetworkEventData },
  { id: 'mg-07', agent_id: 'ag-002', event_type: 'network', timestamp: new Date(_mockNow - 7_000).toISOString(),  raw_data: { dst_ip: '104.21.33.196',  dst_port: 80,    protocol: 'TCP', process_name: 'curl'               } as unknown as NetworkEventData },
  { id: 'mg-08', agent_id: 'ag-003', event_type: 'network', timestamp: new Date(_mockNow - 8_000).toISOString(),  raw_data: { dst_ip: '52.15.246.12',   dst_port: 443,   protocol: 'TCP', process_name: 'outlook.exe'        } as unknown as NetworkEventData },
  { id: 'mg-09', agent_id: 'ag-003', event_type: 'network', timestamp: new Date(_mockNow - 9_000).toISOString(),  raw_data: { dst_ip: '8.8.8.8',        dst_port: 53,    protocol: 'UDP', process_name: 'svchost.exe'       } as unknown as NetworkEventData },
  { id: 'mg-10', agent_id: 'ag-003', event_type: 'network', timestamp: new Date(_mockNow - 10_000).toISOString(), raw_data: { dst_ip: '185.220.101.5',  dst_port: 445,   protocol: 'TCP', process_name: 'payload.exe'        } as unknown as NetworkEventData },
  { id: 'mg-11', agent_id: 'ag-004', event_type: 'network', timestamp: new Date(_mockNow - 11_000).toISOString(), raw_data: { dst_ip: '1.1.1.1',        dst_port: 53,    protocol: 'UDP', process_name: 'svchost.exe'       } as unknown as NetworkEventData },
  { id: 'mg-12', agent_id: 'ag-004', event_type: 'network', timestamp: new Date(_mockNow - 12_000).toISOString(), raw_data: { dst_ip: '104.21.33.196',  dst_port: 443,   protocol: 'TCP', process_name: 'firefox.exe'        } as unknown as NetworkEventData },
  { id: 'mg-13', agent_id: 'ag-005', event_type: 'network', timestamp: new Date(_mockNow - 13_000).toISOString(), raw_data: { dst_ip: '91.108.4.236',   dst_port: 6667,  protocol: 'TCP', process_name: 'unknown'            } as unknown as NetworkEventData },
  { id: 'mg-14', agent_id: 'ag-005', event_type: 'network', timestamp: new Date(_mockNow - 14_000).toISOString(), raw_data: { dst_ip: '185.220.101.5',  dst_port: 31337, protocol: 'TCP', process_name: 'cmd.exe'            } as unknown as NetworkEventData },
  { id: 'mg-15', agent_id: 'ag-005', event_type: 'network', timestamp: new Date(_mockNow - 15_000).toISOString(), raw_data: { dst_ip: '52.15.246.12',   dst_port: 443,   protocol: 'TCP', process_name: 'nginx'              } as unknown as NetworkEventData },
]

const GRAPH_W = 780
const GRAPH_H = 440
const NODE_R  = 20
const EXT_R   = 12

// ─── Helpers ──────────────────────────────────────────────────────────────────

function portRiskColor(port: string): string {
  const p = NOTABLE_PORTS[port]
  if (!p) return ''
  if (p.risk === 'critical') return 'text-red-400'
  if (p.risk === 'warn') return 'text-yellow-400'
  return 'text-blue-400'
}

function barColor(idx: number): string {
  const colors = ['#3b82f6', '#6366f1', '#8b5cf6', '#a78bfa', '#c4b5fd']
  return colors[idx % colors.length]
}

function formatTime(s: string): string {
  return new Date(s).toLocaleString('ja-JP', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function circleLayout(count: number, cx: number, cy: number, r: number): { x: number; y: number }[] {
  if (count === 0) return []
  if (count === 1) return [{ x: cx, y: cy }]
  return Array.from({ length: count }, (_, i) => {
    const angle = (2 * Math.PI * i) / count - Math.PI / 2
    return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) }
  })
}

// Clamp node positions so they stay within the SVG viewport
function clamp(val: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, val))
}

// ─── NetworkGraph component ───────────────────────────────────────────────────

interface NetworkGraphProps {
  nodes: GraphNode[]
  edges: GraphEdge[]
  selectedId: string | null
  onSelect: (id: string | null) => void
  onNodeMove: (id: string, x: number, y: number) => void
}

function NetworkGraph({ nodes, edges, selectedId, onSelect, onNodeMove }: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const dragging = useRef<{ id: string; ox: number; oy: number; nx: number; ny: number } | null>(null)

  const handleMouseDown = useCallback(
    (e: React.MouseEvent<SVGGElement>, id: string) => {
      e.preventDefault()
      e.stopPropagation()
      const svg = svgRef.current
      if (!svg) return
      const rect = svg.getBoundingClientRect()
      const scaleX = GRAPH_W / rect.width
      const scaleY = GRAPH_H / rect.height
      const node = nodes.find(n => n.id === id)
      if (!node) return
      dragging.current = {
        id,
        ox: (e.clientX - rect.left) * scaleX - node.x,
        oy: (e.clientY - rect.top)  * scaleY - node.y,
        nx: node.x,
        ny: node.y,
      }
    },
    [nodes],
  )

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!dragging.current) return
    const svg = svgRef.current
    if (!svg) return
    const rect = svg.getBoundingClientRect()
    const scaleX = GRAPH_W / rect.width
    const scaleY = GRAPH_H / rect.height
    const nx = clamp((e.clientX - rect.left) * scaleX - dragging.current.ox, NODE_R + 4, GRAPH_W - NODE_R - 4)
    const ny = clamp((e.clientY - rect.top)  * scaleY - dragging.current.oy, NODE_R + 4, GRAPH_H - NODE_R - 4)
    dragging.current.nx = nx
    dragging.current.ny = ny
    onNodeMove(dragging.current.id, nx, ny)
  }, [onNodeMove])

  const handleMouseUp = useCallback(() => {
    dragging.current = null
  }, [])

  useEffect(() => {
    window.addEventListener('mousemove', handleMouseMove)
    window.addEventListener('mouseup', handleMouseUp)
    return () => {
      window.removeEventListener('mousemove', handleMouseMove)
      window.removeEventListener('mouseup', handleMouseUp)
    }
  }, [handleMouseMove, handleMouseUp])

  const nodeMap = useMemo(() => {
    const m: Record<string, GraphNode> = {}
    for (const n of nodes) m[n.id] = n
    return m
  }, [nodes])

  if (nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-[#5a6a7a] gap-3">
        <Network className="w-12 h-12 opacity-40" />
        <p className="text-sm">ネットワーク接続データがありません</p>
        <p className="text-xs opacity-60">時間範囲を変更するか、エージェントがオンラインか確認してください</p>
      </div>
    )
  }

  // Max edge count for stroke-width scaling
  const maxEdgeCount = Math.max(1, ...edges.map(e => e.count))

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${GRAPH_W} ${GRAPH_H}`}
      className="w-full h-full select-none"
      onClick={() => onSelect(null)}
    >
      <defs>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 Z" fill="#334155" />
        </marker>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      {/* Edges */}
      {edges.map((edge, i) => {
        const src = nodeMap[edge.source]
        const tgt = nodeMap[edge.target]
        if (!src || !tgt) return null
        const strokeW = 0.8 + (edge.count / maxEdgeCount) * 3.2
        const stroke  = edge.suspicious ? 'rgba(239,68,68,0.65)' : 'rgba(99,102,241,0.35)'
        const isActive = selectedId === edge.source || selectedId === edge.target
        return (
          <line
            key={i}
            x1={src.x} y1={src.y}
            x2={tgt.x} y2={tgt.y}
            stroke={isActive ? (edge.suspicious ? '#ef4444' : '#818cf8') : stroke}
            strokeWidth={isActive ? strokeW + 1 : strokeW}
            strokeOpacity={isActive ? 1 : 0.6}
            strokeLinecap="round"
          />
        )
      })}

      {/* Nodes */}
      {nodes.map(node => {
        const r         = node.type === 'agent' ? NODE_R : EXT_R
        const fill      = node.type === 'agent' ? (STATUS_COLOR[node.status ?? 'offline'] ?? '#6b7280') : '#334155'
        const isSelected = selectedId === node.id
        return (
          <g
            key={node.id}
            transform={`translate(${node.x},${node.y})`}
            style={{ cursor: 'grab' }}
            onClick={e => { e.stopPropagation(); onSelect(isSelected ? null : node.id) }}
            onMouseDown={e => handleMouseDown(e, node.id)}
          >
            {/* Outer ring when selected */}
            {isSelected && (
              <circle r={r + 6} fill="none" stroke={fill} strokeWidth={1.5} strokeOpacity={0.5} />
            )}
            {/* Shadow ring */}
            <circle r={r + 2} fill={fill} fillOpacity={0.15} />
            {/* Main node circle */}
            <circle
              r={r}
              fill={fill}
              fillOpacity={0.9}
              stroke={isSelected ? fill : '#1e293b'}
              strokeWidth={isSelected ? 2 : 1}
              filter={isSelected ? 'url(#glow)' : undefined}
            />
            {/* Agent status icon: dot for type indicator */}
            {node.type === 'external' && (
              <text textAnchor="middle" dominantBaseline="central" fontSize={10} fill="#94a3b8">IP</text>
            )}
            {/* Label below node */}
            <text
              y={r + 13}
              textAnchor="middle"
              fontSize={node.type === 'agent' ? 10 : 8}
              fill={isSelected ? '#f1f5f9' : '#94a3b8'}
              fontWeight={isSelected ? 600 : 400}
            >
              {node.label.length > 14 ? node.label.slice(0, 13) + '…' : node.label}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

// ─── NodeDetailPanel ──────────────────────────────────────────────────────────

interface NodeDetailPanelProps {
  node: GraphNode
  edges: GraphEdge[]
  nodes: GraphNode[]
  onClose: () => void
}

function NodeDetailPanel({ node, edges, nodes, onClose }: NodeDetailPanelProps) {
  const nodeMap = useMemo(() => {
    const m: Record<string, GraphNode> = {}
    for (const n of nodes) m[n.id] = n
    return m
  }, [nodes])

  const related = edges
    .filter(e => e.source === node.id || e.target === node.id)
    .map(e => {
      const otherId = e.source === node.id ? e.target : e.source
      return { node: nodeMap[otherId], edge: e }
    })
    .filter(r => r.node !== undefined)
    .sort((a, b) => b.edge.count - a.edge.count)
    .slice(0, 8)

  return (
    <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-4 h-full overflow-y-auto">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div
            className="w-3 h-3 rounded-full shrink-0"
            style={{ backgroundColor: node.type === 'agent' ? (STATUS_COLOR[node.status ?? 'offline'] ?? '#6b7280') : '#334155' }}
          />
          <span className="text-sm font-semibold text-white truncate">{node.label}</span>
        </div>
        <button onClick={onClose} className="text-[#5a6a7a] hover:text-white transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="space-y-2 mb-4 text-xs">
        <div className="flex justify-between">
          <span className="text-[#5a6a7a]">タイプ</span>
          <span className="text-[#c5d0e0]">{node.type === 'agent' ? 'エンドポイント' : '外部IP'}</span>
        </div>
        {node.type === 'agent' && (
          <div className="flex justify-between">
            <span className="text-[#5a6a7a]">ステータス</span>
            <span style={{ color: STATUS_COLOR[node.status ?? 'offline'] }}>
              {node.status ?? '不明'}
            </span>
          </div>
        )}
        <div className="flex justify-between">
          <span className="text-[#5a6a7a]">接続数</span>
          <span className="text-[#c5d0e0]">{related.length} ノード</span>
        </div>
      </div>

      <h4 className="text-xs font-semibold text-[#5a6a7a] mb-2 uppercase tracking-wide">通信先</h4>
      <div className="space-y-1.5">
        {related.length === 0 ? (
          <p className="text-xs text-[#5a6a7a]">接続なし</p>
        ) : (
          related.map(({ node: other, edge }, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <ChevronRight className="w-3 h-3 text-[#5a6a7a] shrink-0" />
              <span className="flex-1 text-[#8899aa] truncate">{other.label}</span>
              <div className="flex items-center gap-1 shrink-0">
                {edge.suspicious && <AlertTriangle className="w-3 h-3 text-red-400" />}
                <span className={edge.suspicious ? 'text-red-400' : 'text-[#5a6a7a]'}>{edge.count}</span>
              </div>
            </div>
          ))
        )}
      </div>

      {related.some(r => r.edge.suspicious) && (
        <div className="mt-4 p-2 bg-red-900/20 border border-red-700/40 rounded-lg">
          <p className="text-xs text-red-400 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> 不審なポートへの通信を検知
          </p>
        </div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function NetworkPage() {
  const [hours, setHours]               = useState(24)
  const [agentFilter, setAgentFilter]   = useState('')
  const [search, setSearch]             = useState('')
  const [page, setPage]                 = useState(1)
  const [suspiciousOnly, setSuspicious] = useState(false)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [nodePositions, setNodePositions]   = useState<Record<string, { x: number; y: number }>>({})
  const [tab, setTab]                   = useState<'graph' | 'table'>('graph')

  // ── API queries ──────────────────────────────────────────────────────────

  const { data: statsData, isLoading: statsLoading, refetch: refetchStats } = useQuery<NetworkStats>({
    queryKey: ['network-stats', hours, agentFilter],
    queryFn: () => {
      const p = new URLSearchParams({ hours: String(hours) })
      if (agentFilter) p.set('agent_id', agentFilter)
      return apiFetch(`/api/v1/events/network-stats?${p}`)
    },
    refetchInterval: 30_000,
  })

  const { data: agentsData } = useQuery<AgentsResponse>({
    queryKey: ['agents-list'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=200'),
    staleTime: 60_000,
  })

  const { data: graphEventsData, isLoading: graphLoading, refetch: refetchGraph } = useQuery<{ data: NetworkEvent[] }>({
    queryKey: ['network-graph-events', hours, agentFilter],
    queryFn: () => {
      const p = new URLSearchParams({ type: 'network', limit: '500' })
      if (agentFilter) p.set('agent_id', agentFilter)
      // hours → approximate since param = limit 500 most recent
      return apiFetch(`/api/v1/events?${p}`)
    },
    refetchInterval: 30_000,
  })

  const eventsParams = new URLSearchParams({
    type: 'network',
    ...(agentFilter && { agent_id: agentFilter }),
    ...(search      && { search }),
    page: String(page),
    per_page: '30',
  })

  const { data: eventsData, isLoading: eventsLoading, refetch: refetchEvents } = useQuery<{ data: NetworkEvent[]; total: number }>({
    queryKey: ['network-events', agentFilter, search, page, suspiciousOnly],
    queryFn: () => apiFetch(`/api/v1/events?${eventsParams}`),
    refetchInterval: 15_000,
  })

  // ── Build graph ──────────────────────────────────────────────────────────

  const { nodes, edges } = useMemo<{ nodes: GraphNode[]; edges: GraphEdge[] }>(() => {
    // Fall back to mock only while API hasn't responded; empty array once it has
    const rawEvents = graphEventsData !== undefined ? (graphEventsData?.data ?? []) : m(MOCK_GRAPH_EVENTS_DATA)
    const agentList  = agentsData?.data?.length ? agentsData.data : (agentsData?.data ? [] : m(MOCK_AGENTS_RESPONSE.data))
    const agentById: Record<string, Agent> = {}
    for (const a of agentList) agentById[a.id] = a

    // Build edge map: key = `agentId::dstIp`
    const edgeMap: Record<string, { count: number; suspicious: boolean; ports: Set<string> }> = {}

    for (const ev of rawEvents) {
      const nd = ev.raw_data
      if (!nd?.dst_ip) continue
      const srcId  = ev.agent_id
      const dstId  = nd.dst_ip
      const port   = String(nd.dst_port ?? '')
      const key    = `${srcId}::${dstId}`
      if (!edgeMap[key]) edgeMap[key] = { count: 0, suspicious: false, ports: new Set() }
      edgeMap[key].count++
      if (port) edgeMap[key].ports.add(port)
      if (SUSPICIOUS_PORTS.has(port)) edgeMap[key].suspicious = true
    }

    // Collect unique node IDs
    const agentIds   = new Set<string>()
    const externalIds = new Set<string>()

    for (const key of Object.keys(edgeMap)) {
      const [src, dst] = key.split('::')
      agentIds.add(src)
      // dst is always external IP in this model
      externalIds.add(dst)
    }

    // Ensure every agent from /agents appears as a node (even without events)
    for (const a of agentList) {
      agentIds.add(a.id)
    }

    const agentArr   = [...agentIds]
    const externalArr = [...externalIds]

    // Layout: agents in a circle, external IPs in outer ring
    const aPositions = circleLayout(agentArr.length, GRAPH_W / 2, GRAPH_H / 2, Math.min(GRAPH_H, GRAPH_W) * 0.25)
    const ePositions = circleLayout(externalArr.length, GRAPH_W / 2, GRAPH_H / 2, Math.min(GRAPH_H, GRAPH_W) * 0.43)

    const nodes: GraphNode[] = [
      ...agentArr.map((id, i) => {
        const agent  = agentById[id]
        const cached = nodePositions[id]
        return {
          id,
          label:  agent?.hostname ?? id.slice(0, 12),
          type:   'agent' as const,
          status: agent?.status,
          x:      cached?.x ?? aPositions[i]?.x ?? GRAPH_W / 2,
          y:      cached?.y ?? aPositions[i]?.y ?? GRAPH_H / 2,
        }
      }),
      ...externalArr.map((ip, i) => {
        const cached = nodePositions[ip]
        return {
          id:    ip,
          label: ip,
          type:  'external' as const,
          x:     cached?.x ?? ePositions[i]?.x ?? GRAPH_W / 2,
          y:     cached?.y ?? ePositions[i]?.y ?? GRAPH_H / 2,
        }
      }),
    ]

    const edges: GraphEdge[] = Object.entries(edgeMap).map(([key, val]) => {
      const [src, dst] = key.split('::')
      return {
        source:     src,
        target:     dst,
        count:      val.count,
        suspicious: val.suspicious,
        ports:      [...val.ports],
      }
    })

    return { nodes, edges }
    // nodePositions deliberately not in deps — positions are separate state
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphEventsData, agentsData])

  const handleNodeMove = useCallback((id: string, x: number, y: number) => {
    setNodePositions(prev => ({ ...prev, [id]: { x, y } }))
  }, [])

  // Merge stored positions into computed nodes
  const displayNodes = useMemo<GraphNode[]>(
    () => nodes.map(n => nodePositions[n.id] ? { ...n, ...nodePositions[n.id] } : n),
    [nodes, nodePositions],
  )

  const selectedNode  = displayNodes.find(n => n.id === selectedNodeId) ?? null
  const stats         = statsData
  const events        = eventsData?.data ?? []
  const totalEvents   = eventsData?.total ?? 0
  const totalPages    = Math.ceil(totalEvents / 30)

  const suspiciousCount   = edges.filter(e => e.suspicious).length
  const agentNodeCount    = nodes.filter(n => n.type === 'agent').length
  const totalConnections  = stats?.total ?? edges.reduce((s, e) => s + e.count, 0)

  function handleRefresh() {
    void refetchStats()
    void refetchGraph()
    void refetchEvents()
  }

  function exportCSV() {
    if (events.length === 0) return
    const headers = ['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'process', 'direction']
    const rows = events.map(ev => {
      const d = ev.raw_data
      return [
        ev.timestamp ?? ev.time ?? '',
        d.src_ip  ?? '',
        d.dst_ip  ?? '',
        String(d.dst_port ?? ''),
        d.protocol ?? '',
        d.process_name ?? '',
        d.direction ?? '',
      ]
    })
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `network-flow-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  // ── Filtered events for table ────────────────────────────────────────────

  const tableEvents = useMemo(() => {
    let evs = events
    if (suspiciousOnly) {
      evs = evs.filter(ev => {
        const port = String(ev.raw_data?.dst_port ?? '')
        return SUSPICIOUS_PORTS.has(port)
      })
    }
    return evs
  }, [events, suspiciousOnly])

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="bg-[#080c14] text-white min-h-screen">
      <PageDataUnavailable />
      <div className="max-w-7xl mx-auto px-6 py-8">

        {/* ── Header ── */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Network className="w-6 h-6 text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">ネットワークフロー</h1>
              <p className="text-[#8899aa] text-sm mt-0.5">エンドポイント間の通信グラフを可視化</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Time range */}
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-[#5a6a7a]" />
              <div className="flex border border-[#1e2d42] rounded-lg overflow-hidden text-sm">
                {HOURS_OPTIONS.map(h => (
                  <button
                    key={h.value}
                    onClick={() => { setHours(h.value); setPage(1) }}
                    className={`px-3 py-1.5 transition-colors ${hours === h.value ? 'bg-[#1a6bff] text-white' : 'text-[#8899aa] hover:bg-[#111827]'}`}
                  >
                    {h.label}
                  </button>
                ))}
              </div>
            </div>
            {/* Refresh */}
            <button
              onClick={handleRefresh}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111827] border border-[#1e2d42] text-[#8899aa] hover:text-white text-sm rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              更新
            </button>
          </div>
        </div>

        {/* ── Stats bar ── */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          {[
            { label: '総接続数',           value: totalConnections.toLocaleString(),                   icon: Activity,       color: 'text-blue-400' },
            { label: 'ユニーク接続先',     value: stats?.top_destinations?.length ?? nodes.filter(n => n.type === 'external').length, icon: Globe, color: 'text-purple-400' },
            { label: '不審な接続',         value: suspiciousCount,                                    icon: AlertTriangle,  color: 'text-red-400' },
            { label: '登録エンドポイント', value: agentNodeCount,                                     icon: Wifi,           color: 'text-green-400' },
          ].map(s => (
            <div key={s.label} className="bg-[#111827] border border-[#1e2d42] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-[#8899aa]">{s.label}</span>
              </div>
              <p className={`text-2xl font-bold ${s.color}`}>{statsLoading ? '…' : s.value}</p>
            </div>
          ))}
        </div>

        {/* ── Tab selector ── */}
        <div className="flex gap-1 mb-6 bg-[#111827] border border-[#1e2d42] rounded-xl p-1 w-fit">
          {(['graph', 'table'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${tab === t ? 'bg-[#1a6bff] text-white' : 'text-[#8899aa] hover:text-white'}`}
            >
              {t === 'graph' ? '通信グラフ' : '接続テーブル'}
            </button>
          ))}
        </div>

        {/* ── Graph tab ── */}
        {tab === 'graph' && (
          <div className="mb-8">
            {/* Legend */}
            <div className="flex items-center gap-5 mb-3 text-xs text-[#5a6a7a]">
              {Object.entries(STATUS_COLOR).map(([status, color]) => (
                <div key={status} className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
                  <span>{STATUS_LABEL[status] ?? status}</span>
                </div>
              ))}
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-[#334155]" />
                <span>外部IP</span>
              </div>
              <div className="flex items-center gap-1.5 ml-4">
                <div className="h-0.5 w-6 bg-indigo-500/60" />
                <span>通常接続</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="h-0.5 w-6 bg-red-500/60" />
                <span>不審な接続</span>
              </div>
              <span className="ml-auto opacity-60">ノードはドラッグして移動できます</span>
            </div>

            <div className="flex gap-4 items-start">
              {/* SVG graph */}
              <div
                className="flex-1 bg-[#0d1526] border border-[#1e2d42] rounded-xl overflow-hidden"
                style={{ height: '460px' }}
              >
                {graphLoading ? (
                  <div className="flex items-center justify-center h-full text-[#5a6a7a] text-sm">
                    読み込み中...
                  </div>
                ) : (
                  <NetworkGraph
                    nodes={displayNodes}
                    edges={edges}
                    selectedId={selectedNodeId}
                    onSelect={setSelectedNodeId}
                    onNodeMove={handleNodeMove}
                  />
                )}
              </div>

              {/* Detail panel */}
              {selectedNode && (
                <div className="w-64 shrink-0" style={{ height: '460px' }}>
                  <NodeDetailPanel
                    node={selectedNode}
                    edges={edges}
                    nodes={displayNodes}
                    onClose={() => setSelectedNodeId(null)}
                  />
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Analytics row (always shown) ── */}
        <div className="grid grid-cols-2 gap-6 mb-8">
          {/* Top destinations */}
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[#8899aa] mb-4 flex items-center gap-2">
              <Globe className="w-4 h-4 text-purple-400" /> 接続先IPアドレス TOP 10
            </h2>
            {statsLoading || !stats?.top_destinations?.length ? (
              <div className="flex items-center justify-center h-40 text-[#5a6a7a] text-sm">データなし</div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={stats.top_destinations.slice(0, 10)} layout="vertical" margin={{ left: 80 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#8899aa' }} />
                  <YAxis type="category" dataKey="ip" tick={{ fontSize: 10, fill: '#8899aa' }} width={80} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #1e2d42', borderRadius: '8px', fontSize: '12px' }}
                    labelStyle={{ color: '#f3f4f6' }}
                  />
                  <Bar dataKey="count" name="接続数" radius={[0, 3, 3, 0]}>
                    {stats.top_destinations.slice(0, 10).map((_, i) => (
                      <Cell key={i} fill={barColor(i)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Top ports */}
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5">
            <h2 className="text-sm font-semibold text-[#8899aa] mb-4 flex items-center gap-2">
              <Server className="w-4 h-4 text-yellow-400" /> 宛先ポート TOP 15
            </h2>
            {statsLoading || !stats?.top_ports?.length ? (
              <div className="flex items-center justify-center h-40 text-[#5a6a7a] text-sm">データなし</div>
            ) : (
              <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                {stats.top_ports.map((p, i) => {
                  const notable = NOTABLE_PORTS[p.port]
                  const max     = stats.top_ports[0].count
                  const pct     = Math.round((p.count / max) * 100)
                  const bgColor = notable
                    ? notable.risk === 'critical' ? '#dc2626' : notable.risk === 'warn' ? '#ca8a04' : '#2563eb'
                    : '#4b5563'
                  return (
                    <div key={i} className="flex items-center gap-3">
                      <div className={`text-xs font-mono w-14 text-right shrink-0 ${portRiskColor(p.port) || 'text-[#8899aa]'}`}>
                        :{p.port}
                      </div>
                      <div className="flex-1 bg-[#0d1526] rounded-full h-4 relative overflow-hidden">
                        <div className="h-4 rounded-full" style={{ width: `${pct}%`, backgroundColor: bgColor }} />
                        <span className="absolute inset-0 flex items-center px-2 text-[10px] text-[#8899aa]">
                          {notable ? notable.label : p.protocol} · {p.count}
                        </span>
                      </div>
                      <span className="text-xs text-[#5a6a7a] w-10 text-right shrink-0">{p.count}</span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* Critical port warnings */}
        {stats?.top_ports?.some(p => NOTABLE_PORTS[p.port]?.risk === 'critical') && (
          <div className="bg-red-900/20 border border-red-700/50 rounded-xl p-4 mb-6">
            <h3 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" /> 危険なポートへの通信を検知
            </h3>
            <div className="flex flex-wrap gap-2">
              {stats.top_ports
                .filter(p => NOTABLE_PORTS[p.port]?.risk === 'critical')
                .map(p => (
                  <span key={p.port} className="text-xs bg-red-900/40 border border-red-700 text-red-300 px-2 py-1 rounded-sm font-mono">
                    :{p.port} ({NOTABLE_PORTS[p.port].label}) — {p.count}件
                  </span>
                ))}
            </div>
          </div>
        )}

        {/* ── Connection table tab ── */}
        {tab === 'table' && (
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl overflow-hidden mb-8">
            {/* Table toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-sm font-semibold text-[#8899aa]">
                接続テーブル ({totalEvents.toLocaleString()}件)
              </h2>
              <div className="flex flex-wrap items-center gap-2">
                {/* CSV export */}
                <button
                  onClick={exportCSV}
                  disabled={events.length === 0}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#161f33] hover:bg-[#1d2f4a] text-[#8899aa] text-xs rounded-lg transition-colors disabled:opacity-40"
                >
                  <Download className="w-3.5 h-3.5" /> CSV
                </button>
                {/* Suspicious-only toggle */}
                <button
                  onClick={() => { setSuspicious(p => !p); setPage(1) }}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                    suspiciousOnly
                      ? 'bg-red-900/40 border-red-700 text-red-300'
                      : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:bg-[#1d2f4a]'
                  }`}
                >
                  <AlertTriangle className="w-3.5 h-3.5" /> 不審のみ
                </button>
                {/* Agent filter */}
                <select
                  value={agentFilter}
                  onChange={e => { setAgentFilter(e.target.value); setPage(1) }}
                  className="bg-[#111827] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-xs text-white"
                >
                  <option value="">すべてのエンドポイント</option>
                  {(agentsData?.data ?? []).map(a => (
                    <option key={a.id} value={a.id}>{a.hostname}</option>
                  ))}
                </select>
                {/* Search */}
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
                  <input
                    className="bg-[#111827] border border-[#1e2d42] rounded-sm pl-7 pr-3 py-1.5 text-xs text-white w-44"
                    placeholder="IP・ポート・プロセスで検索"
                    value={search}
                    onChange={e => { setSearch(e.target.value); setPage(1) }}
                  />
                </div>
              </div>
            </div>

            {eventsLoading ? (
              <div className="text-center py-10 text-[#5a6a7a] text-sm">読み込み中...</div>
            ) : tableEvents.length === 0 ? (
              <div className="text-center py-12 text-[#5a6a7a] text-sm flex flex-col items-center gap-3">
                <Network className="w-10 h-10 opacity-30" />
                <p>ネットワーク接続データがありません</p>
                {suspiciousOnly && (
                  <button
                    onClick={() => setSuspicious(false)}
                    className="text-xs text-blue-400 underline mt-1"
                  >
                    フィルターを解除する
                  </button>
                )}
              </div>
            ) : (
              <>
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#1e2d42] text-[#8899aa]">
                      <th className="text-left px-4 py-2.5">送信元エージェント</th>
                      <th className="text-left px-4 py-2.5">宛先IP</th>
                      <th className="text-left px-4 py-2.5">ポート</th>
                      <th className="text-left px-4 py-2.5">プロトコル</th>
                      <th className="text-left px-4 py-2.5">プロセス</th>
                      <th className="text-left px-4 py-2.5">方向</th>
                      <th className="text-left px-4 py-2.5">最終検知</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tableEvents.map(ev => {
                      const d         = ev.raw_data
                      const port      = String(d.dst_port ?? '')
                      const portNote  = port ? NOTABLE_PORTS[port] : undefined
                      const isSuspect = SUSPICIOUS_PORTS.has(port)
                      const agent     = agentsData?.data?.find(a => a.id === ev.agent_id)
                      const ts        = ev.timestamp ?? ev.time ?? ''
                      return (
                        <tr
                          key={ev.id}
                          className={`border-b border-[#1e2d42]/60 hover:bg-[#0d1526]/60 transition-colors ${isSuspect ? 'bg-red-900/10' : ''}`}
                        >
                          <td className="px-4 py-2 text-[#c5d0e0] font-medium">
                            {agent?.hostname ?? ev.agent_id.slice(0, 12)}
                          </td>
                          <td className="px-4 py-2 font-mono text-[#e2e8f4]">{d.dst_ip ?? '—'}</td>
                          <td className={`px-4 py-2 font-mono font-semibold ${portRiskColor(port) || 'text-[#8899aa]'}`}>
                            {port || '—'}
                            {portNote && (
                              <span className="ml-1 font-normal text-[10px] opacity-70">({portNote.label})</span>
                            )}
                          </td>
                          <td className="px-4 py-2 text-[#8899aa] uppercase">{d.protocol ?? '—'}</td>
                          <td className="px-4 py-2 text-[#8899aa] font-mono truncate max-w-[140px]">
                            {d.process_name ?? '—'}
                          </td>
                          <td className="px-4 py-2">
                            {d.direction && (
                              <span className={`px-1.5 py-0.5 rounded-sm text-[10px] border ${
                                d.direction === 'outbound'
                                  ? 'text-orange-400 bg-orange-900/30 border-orange-700'
                                  : 'text-blue-400 bg-blue-900/30 border-blue-700'
                              }`}>
                                {d.direction === 'outbound' ? '→ 送信' : '← 受信'}
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2 text-[#5a6a7a] whitespace-nowrap">
                            {ts ? formatTime(ts) : '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div className="flex justify-center items-center gap-2 px-4 py-3 border-t border-[#1e2d42]">
                    <button
                      disabled={page === 1}
                      onClick={() => setPage(p => p - 1)}
                      className="px-3 py-1 text-xs rounded-sm bg-[#111827] text-[#8899aa] disabled:opacity-40 hover:bg-[#19253d]"
                    >前へ</button>
                    <span className="text-xs text-[#5a6a7a]">{page} / {totalPages}</span>
                    <button
                      disabled={page === totalPages}
                      onClick={() => setPage(p => p + 1)}
                      className="px-3 py-1 text-xs rounded-sm bg-[#111827] text-[#8899aa] disabled:opacity-40 hover:bg-[#19253d]"
                    >次へ</button>
                  </div>
                )}
              </>
            )}
          </div>
        )}

      </div>
    </div>
  )
}
