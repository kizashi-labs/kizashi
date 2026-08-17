'use client'

import React, { useState, useMemo, useCallback, useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Network, RefreshCw, Globe, Wifi, AlertTriangle, Server,
  Monitor, ExternalLink, Activity, Shield, Filter, X,
  ChevronDown, ChevronUp, Layers, ZoomIn, ZoomOut,
} from 'lucide-react'
import Link from 'next/link'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  ip_address?: string
  os?: string
  status: 'online' | 'offline' | 'warning'
  lateral_movement?: boolean
}

interface TopologyNode {
  id: string
  hostname: string
  ip_address?: string
  os?: string
  status: 'online' | 'offline' | 'warning'
  lateral_movement?: boolean
  subnet?: string
}

interface TopologyEdge {
  source: string
  target: string
  connection_count?: number
  lateral_movement?: boolean
}

interface SubnetGroup {
  subnet: string
  node_ids: string[]
}

interface TopologyResponse {
  nodes?: TopologyNode[]
  edges?: TopologyEdge[]
  subnet_groups?: SubnetGroup[]
}

interface AgentsResponse {
  agents?: Agent[]
  data?: Agent[]
}

interface NetConn {
  id?: string
  agent_id?: string
  local_address: string
  remote_address: string
  protocol: string
  state: string
}

interface NetConnResponse {
  connections?: NetConn[]
  data?: NetConn[]
}

interface LayoutNode extends TopologyNode {
  x: number
  y: number
}

interface FilterState {
  os: string
  status: string
  subnet: string
  lateralMovementOnly: boolean
}

interface ContextMenu {
  x: number
  y: number
  nodeId: string
  hostname: string
}


// ─── Layout helpers ───────────────────────────────────────────────────────────

function hashStr(s: string): number {
  let h = 0
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0
  }
  return Math.abs(h)
}

const SVG_W = 900
const SVG_H = 600
const CENTER_X = SVG_W / 2
const CENTER_Y = SVG_H / 2
const RADIUS = 220

function getSubnet(ip?: string): string | null {
  if (!ip) return null
  const parts = ip.split('.')
  if (parts.length < 3) return null
  return parts.slice(0, 3).join('.')
}

function layoutNodes(nodes: TopologyNode[], groupBySubnet: boolean): LayoutNode[] {
  if (!groupBySubnet) {
    const count = nodes.length
    return nodes.map((node, i) => {
      const angle = (2 * Math.PI * i) / count - Math.PI / 2
      const jitter = (hashStr(node.id) % 30) - 15
      const r = RADIUS + jitter
      return {
        ...node,
        x: CENTER_X + r * Math.cos(angle),
        y: CENTER_Y + r * Math.sin(angle),
      }
    })
  }

  // Group by subnet layout
  const subnetMap: Record<string, TopologyNode[]> = {}
  for (const node of nodes) {
    const subnet = node.subnet ?? getSubnet(node.ip_address) ?? 'unknown'
    if (!subnetMap[subnet]) subnetMap[subnet] = []
    subnetMap[subnet].push(node)
  }

  const subnets = Object.keys(subnetMap)
  const result: LayoutNode[] = []
  const subnetCount = subnets.length

  subnets.forEach((subnet, si) => {
    const subAngle = (2 * Math.PI * si) / subnetCount - Math.PI / 2
    const subCx = CENTER_X + (RADIUS * 0.65) * Math.cos(subAngle)
    const subCy = CENTER_Y + (RADIUS * 0.65) * Math.sin(subAngle)
    const subNodes = subnetMap[subnet]
    const subR = 55 + subNodes.length * 8

    subNodes.forEach((node, ni) => {
      const nodeAngle = (2 * Math.PI * ni) / subNodes.length - Math.PI / 2
      result.push({
        ...node,
        x: subCx + subR * Math.cos(nodeAngle),
        y: subCy + subR * Math.sin(nodeAngle),
      })
    })
  })

  return result
}

// ─── OS color helpers ─────────────────────────────────────────────────────────

function osColor(node: TopologyNode): string {
  const os = (node.os ?? '').toLowerCase()
  if (node.lateral_movement) return '#ef4444'
  if (os.includes('linux')) return '#3b82f6'
  if (os.includes('windows')) return '#f97316'
  if (os.includes('mac')) return '#a855f7'
  // Fall back to status color
  if (node.status === 'online') return '#3b82f6'
  if (node.status === 'warning') return '#ef4444'
  return '#6b7280'
}

function osGlow(node: TopologyNode): string {
  const c = osColor(node)
  return c + '55'
}

function edgeColor(edge: TopologyEdge): string {
  if (edge.lateral_movement) return '#f97316'
  return '#1e3a5f'
}

function edgeWidth(edge: TopologyEdge): number {
  const cnt = edge.connection_count ?? 1
  return Math.min(1 + cnt / 8, 5)
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string
  value: number | string
  icon: React.ElementType
  color: 'blue' | 'green' | 'yellow' | 'red' | 'orange'
}) {
  const map: Record<string, string> = {
    blue:   'text-blue-400 bg-blue-900/30',
    green:  'text-green-400 bg-green-900/30',
    yellow: 'text-yellow-400 bg-yellow-900/30',
    red:    'text-red-400 bg-red-900/30',
    orange: 'text-orange-400 bg-orange-900/30',
  }
  const cls = map[color]
  return (
    <div className="bg-falcon-surface rounded-xl border border-falcon-border p-4">
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-lg ${cls}`}>
          <Icon className={`w-5 h-5 ${cls.split(' ')[0]}`} />
        </div>
        <div>
          <p className="text-2xl font-bold text-white">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
          <p className="text-falcon-muted text-xs mt-0.5">{label}</p>
        </div>
      </div>
    </div>
  )
}

// ─── SVG Subnet Containers ────────────────────────────────────────────────────

function SubnetContainers({
  nodes,
  groupBySubnet,
}: {
  nodes: LayoutNode[]
  groupBySubnet: boolean
}) {
  if (!groupBySubnet) return null

  const subnetMap: Record<string, LayoutNode[]> = {}
  for (const node of nodes) {
    const subnet = node.subnet ?? getSubnet(node.ip_address) ?? 'unknown'
    if (!subnetMap[subnet]) subnetMap[subnet] = []
    subnetMap[subnet].push(node)
  }

  return (
    <>
      {Object.entries(subnetMap).map(([subnet, snNodes]) => {
        if (snNodes.length === 0) return null
        const xs = snNodes.map(n => n.x)
        const ys = snNodes.map(n => n.y)
        const minX = Math.min(...xs) - 30
        const minY = Math.min(...ys) - 30
        const maxX = Math.max(...xs) + 30
        const maxY = Math.max(...ys) + 30
        const w = maxX - minX
        const h = maxY - minY
        return (
          <g key={subnet}>
            <rect
              x={minX} y={minY} width={w} height={h} rx={12}
              fill="#0d1a2e"
              fillOpacity="0.6"
              stroke="#1e3a5f"
              strokeWidth="1.5"
              strokeDasharray="4 3"
            />
            <text
              x={minX + 8}
              y={minY + 14}
              fontSize="9"
              fill="#3b82f6"
              fontWeight="600"
              style={{ userSelect: 'none', pointerEvents: 'none' }}
            >
              {subnet}.0/24
            </text>
          </g>
        )
      })}
    </>
  )
}

// ─── Context Menu ─────────────────────────────────────────────────────────────

function ContextMenuPopup({
  menu,
  onClose,
  onViewAgent,
  onShowConnections,
  onIsolateNode,
}: {
  menu: ContextMenu
  onClose: () => void
  onViewAgent: (id: string) => void
  onShowConnections: (id: string) => void
  onIsolateNode: (id: string) => void
}) {
  return (
    <>
      {/* Click-away overlay */}
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div
        className="fixed z-50 bg-falcon-surface border border-falcon-border rounded-xl shadow-xl overflow-hidden min-w-[180px]"
        style={{ left: menu.x, top: menu.y }}
      >
        <div className="px-3 py-2 border-b border-falcon-border">
          <p className="text-xs font-semibold text-falcon-muted">{menu.hostname}</p>
        </div>
        <button
          onClick={() => { onViewAgent(menu.nodeId); onClose() }}
          className="w-full flex items-center gap-2 px-3 py-2.5 text-sm text-[#c9d6e8] hover:bg-[#1a2744] transition-colors"
        >
          <ExternalLink className="w-3.5 h-3.5 text-blue-400" />
          エージェント詳細
        </button>
        <button
          onClick={() => { onShowConnections(menu.nodeId); onClose() }}
          className="w-full flex items-center gap-2 px-3 py-2.5 text-sm text-[#c9d6e8] hover:bg-[#1a2744] transition-colors"
        >
          <Activity className="w-3.5 h-3.5 text-green-400" />
          接続を表示
        </button>
        <button
          onClick={() => { onIsolateNode(menu.nodeId); onClose() }}
          className="w-full flex items-center gap-2 px-3 py-2.5 text-sm text-[#c9d6e8] hover:bg-[#1a2744] transition-colors"
        >
          <Layers className="w-3.5 h-3.5 text-orange-400" />
          ノードを分離
        </button>
      </div>
    </>
  )
}

// ─── SVG Graph ────────────────────────────────────────────────────────────────

interface GraphProps {
  layouted: LayoutNode[]
  edges: TopologyEdge[]
  hoveredId: string | null
  selectedId: string | null
  isolatedId: string | null
  groupBySubnet: boolean
  onHover: (id: string | null) => void
  onSelect: (id: string | null) => void
  onContextMenu: (e: React.MouseEvent, node: LayoutNode) => void
}

function NetworkGraph({
  layouted, edges, hoveredId, selectedId, isolatedId, groupBySubnet,
  onHover, onSelect, onContextMenu,
}: GraphProps) {
  const nodeMap = useMemo(() => {
    const m: Record<string, LayoutNode> = {}
    layouted.forEach(n => { m[n.id] = n })
    return m
  }, [layouted])

  const activeId = hoveredId ?? selectedId

  const isEdgeHighlighted = useCallback(
    (src: string, tgt: string) => {
      if (!activeId) return false
      return src === activeId || tgt === activeId
    },
    [activeId],
  )

  const isNodeFaded = useCallback(
    (id: string) => {
      if (isolatedId) {
        if (id === isolatedId) return false
        return !edges.some(e => (e.source === isolatedId && e.target === id) || (e.target === isolatedId && e.source === id))
      }
      if (!activeId) return false
      if (id === activeId) return false
      return !edges.some(e => (e.source === activeId && e.target === id) || (e.target === activeId && e.source === id))
    },
    [activeId, isolatedId, edges],
  )

  return (
    <svg
      viewBox={`0 0 ${SVG_W} ${SVG_H}`}
      className="w-full h-full"
      style={{ background: 'transparent' }}
    >
      <defs>
        <filter id="glow-node" x="-80%" y="-80%" width="260%" height="260%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="glow-lm" x="-80%" y="-80%" width="260%" height="260%">
          <feGaussianBlur stdDeviation="6" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <radialGradient id="gw-grad" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#1e3a5f" />
          <stop offset="100%" stopColor="#0f172a" />
        </radialGradient>
      </defs>

      {/* Concentric guide circles */}
      {!groupBySubnet && (
        <>
          <circle cx={CENTER_X} cy={CENTER_Y} r={RADIUS + 40} fill="none" stroke="#1e2d42" strokeWidth="1" strokeDasharray="4 6" opacity="0.4" />
          <circle cx={CENTER_X} cy={CENTER_Y} r={RADIUS - 40} fill="none" stroke="#1e2d42" strokeWidth="1" strokeDasharray="2 8" opacity="0.25" />
        </>
      )}

      {/* Subnet containers */}
      <SubnetContainers nodes={layouted} groupBySubnet={groupBySubnet} />

      {/* Edges */}
      {edges.map((e, i) => {
        const na = nodeMap[e.source]
        const nb = nodeMap[e.target]
        if (!na || !nb) return null
        const highlighted = isEdgeHighlighted(e.source, e.target)
        const isLM = !!e.lateral_movement
        const w = edgeWidth(e)
        const color = highlighted ? '#60a5fa' : isLM ? '#f97316' : '#1e3a5f'
        const opacity = highlighted ? 0.95 : isLM ? 0.7 : 0.45
        return (
          <line
            key={`edge-${i}`}
            x1={na.x} y1={na.y} x2={nb.x} y2={nb.y}
            stroke={color}
            strokeWidth={highlighted ? w + 1 : w}
            opacity={opacity}
            strokeDasharray={isLM && !highlighted ? '5 3' : undefined}
            style={{ transition: 'stroke 0.15s, opacity 0.15s' }}
          />
        )
      })}

      {/* Gateway spokes (non-grouped only) */}
      {!groupBySubnet && layouted.map(node => {
        const isActive = activeId === node.id
        return (
          <line
            key={`spoke-${node.id}`}
            x1={CENTER_X} y1={CENTER_Y}
            x2={node.x} y2={node.y}
            stroke={isActive ? '#3b82f6' : '#1e2d42'}
            strokeWidth={isActive ? 1.5 : 0.7}
            opacity={isActive ? 0.75 : 0.3}
            style={{ transition: 'stroke 0.15s, opacity 0.15s' }}
          />
        )
      })}

      {/* Agent nodes */}
      {layouted.map(node => {
        const color = osColor(node)
        const glow = osGlow(node)
        const faded = isNodeFaded(node.id)
        const isSelected = selectedId === node.id
        const isHovered = hoveredId === node.id
        const active = isSelected || isHovered
        const r = active ? 14 : 11
        const isLM = !!node.lateral_movement

        return (
          <g
            key={node.id}
            style={{ cursor: 'pointer', opacity: faded ? 0.2 : 1, transition: 'opacity 0.15s' }}
            onMouseEnter={() => onHover(node.id)}
            onMouseLeave={() => onHover(null)}
            onClick={() => onSelect(selectedId === node.id ? null : node.id)}
            onContextMenu={(e) => { e.preventDefault(); onContextMenu(e, node) }}
          >
            {/* LM pulse ring */}
            {isLM && (
              <circle cx={node.x} cy={node.y} r={r + 10} fill="none" stroke="#ef4444" strokeWidth="1.5" opacity="0.4" strokeDasharray="3 4" />
            )}
            {/* Glow ring */}
            {active && (
              <circle cx={node.x} cy={node.y} r={r + 6} fill={glow} />
            )}
            {/* Selection ring */}
            {isSelected && (
              <circle cx={node.x} cy={node.y} r={r + 9} fill="none" stroke={color} strokeWidth="1.5" strokeDasharray="3 3" opacity="0.7" />
            )}
            {/* Main circle */}
            <circle
              cx={node.x} cy={node.y} r={r}
              fill={color}
              filter={active ? (isLM ? 'url(#glow-lm)' : 'url(#glow-node)') : undefined}
              style={{ transition: 'r 0.1s' }}
            />
            {/* Inner highlight */}
            <circle cx={node.x - r * 0.3} cy={node.y - r * 0.3} r={r * 0.25} fill="white" opacity="0.15" />

            {/* Label */}
            <text
              x={node.x}
              y={node.y + r + 14}
              textAnchor="middle"
              fontSize="10"
              fill={active ? '#e2e8f0' : '#94a3b8'}
              style={{ pointerEvents: 'none', userSelect: 'none', transition: 'fill 0.15s' }}
            >
              {node.hostname.length > 14 ? node.hostname.slice(0, 13) + '…' : node.hostname}
            </text>
            {node.ip_address && (
              <text
                x={node.x}
                y={node.y + r + 25}
                textAnchor="middle"
                fontSize="8"
                fill="#475569"
                style={{ pointerEvents: 'none', userSelect: 'none' }}
              >
                {node.ip_address}
              </text>
            )}
          </g>
        )
      })}

      {/* Gateway node (non-grouped only) */}
      {!groupBySubnet && (
        <g style={{ cursor: 'pointer' }} onClick={() => onSelect(null)}>
          <circle cx={CENTER_X} cy={CENTER_Y} r={34} fill="url(#gw-grad)" stroke="#1e3a5f" strokeWidth="2" />
          <circle cx={CENTER_X} cy={CENTER_Y} r={28} fill="#0f172a" stroke="#1d4ed8" strokeWidth="1.5" />
          <text x={CENTER_X} y={CENTER_Y + 1} textAnchor="middle" dominantBaseline="middle" fontSize="16" fill="#60a5fa" style={{ userSelect: 'none', pointerEvents: 'none' }}>
            ⬡
          </text>
          <text x={CENTER_X} y={CENTER_Y + 40} textAnchor="middle" fontSize="11" fontWeight="600" fill="#93c5fd" style={{ pointerEvents: 'none', userSelect: 'none' }}>
            ゲートウェイ
          </text>
        </g>
      )}

      {/* Legend */}
      <g transform={`translate(16, ${SVG_H - 72})`}>
        <rect x={0} y={0} width={290} height={60} rx={6} fill="#070d19" fillOpacity="0.92" stroke="#1e2d42" strokeWidth="1" />
        <circle cx={14} cy={12} r={5} fill="#3b82f6" /><text x={23} y={16} fontSize="9" fill="#7d92b0">Linux</text>
        <circle cx={70} cy={12} r={5} fill="#f97316" /><text x={79} y={16} fontSize="9" fill="#7d92b0">Windows</text>
        <circle cx={148} cy={12} r={5} fill="#a855f7" /><text x={157} y={16} fontSize="9" fill="#7d92b0">macOS</text>
        <circle cx={210} cy={12} r={5} fill="#ef4444" /><text x={219} y={16} fontSize="9" fill="#7d92b0">横展開</text>
        <line x1={8} y1={33} x2={20} y2={33} stroke="#f97316" strokeWidth="2.5" strokeDasharray="4 2" />
        <text x={25} y={37} fontSize="9" fill="#7d92b0">横展開エッジ</text>
        <line x1={100} y1={33} x2={112} y2={33} stroke="#1e3a5f" strokeWidth="3" />
        <text x={117} y={37} fontSize="9" fill="#7d92b0">通常エッジ (太さ=接続数)</text>
        <circle cx={14} cy={50} r={4} fill="#6b7280" /><text x={23} y={54} fontSize="9" fill="#7d92b0">オフライン</text>
      </g>
    </svg>
  )
}

// ─── Node Details Panel ───────────────────────────────────────────────────────

function NodeDetailPanel({
  node,
  connections,
}: {
  node: LayoutNode | null
  connections: TopologyEdge[]
}) {
  if (!node) {
    return (
      <div className="bg-falcon-surface rounded-xl border border-falcon-border p-6 flex flex-col items-center justify-center text-center gap-3 min-h-[200px]">
        <div className="w-12 h-12 rounded-full bg-falcon-border flex items-center justify-center">
          <Monitor className="w-6 h-6 text-[#475569]" />
        </div>
        <p className="text-[#475569] text-sm">ノードをクリックして詳細を表示</p>
        <p className="text-[#2d3f55] text-xs">右クリックでその他のオプション</p>
      </div>
    )
  }

  const nodeEdges = connections.filter(e => e.source === node.id || e.target === node.id)
  const totalConns = nodeEdges.reduce((sum, e) => sum + (e.connection_count ?? 0), 0)
  const hasLM = !!node.lateral_movement

  const statusColor =
    node.status === 'online'
      ? 'text-green-400 bg-green-900/30'
      : node.status === 'warning'
      ? 'text-yellow-400 bg-yellow-900/30'
      : 'text-gray-400 bg-gray-700/40'

  const statusLabel =
    node.status === 'online' ? 'オンライン' : node.status === 'warning' ? '警告' : 'オフライン'

  return (
    <div className="bg-falcon-surface rounded-xl border border-falcon-border p-5 flex flex-col gap-4">
      {/* Title bar */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center"
            style={{ background: osColor(node) + '22' }}
          >
            <Server className="w-5 h-5" style={{ color: osColor(node) }} />
          </div>
          <div>
            <p className="text-white font-semibold text-sm leading-tight">{node.hostname}</p>
            <span className={`mt-0.5 inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium ${statusColor}`}>
              {statusLabel}
            </span>
          </div>
        </div>
        {hasLM && (
          <span className="flex items-center gap-1 px-2 py-1 rounded-md bg-red-900/30 border border-red-700/50 text-red-300 text-[10px] font-semibold">
            <AlertTriangle className="w-3 h-3" />
            横展開検知
          </span>
        )}
      </div>

      {/* Details grid */}
      <div className="space-y-2.5 text-sm">
        <Row label="エージェントID" value={node.id.slice(0, 20) + (node.id.length > 20 ? '…' : '')} mono />
        {node.ip_address && <Row label="IPアドレス" value={node.ip_address} mono />}
        {node.ip_address && <Row label="サブネット" value={(getSubnet(node.ip_address) ?? '?') + '.0/24'} mono />}
        {node.os && <Row label="OS" value={node.os} />}
        <Row label="エッジ接続数" value={String(nodeEdges.length)} />
        <Row label="総トラフィック" value={String(totalConns)} />
      </div>

      {/* Divider */}
      <div className="border-t border-falcon-border" />

      {/* Actions */}
      <div className="flex flex-col gap-2">
        <Link
          href={`/agents/${node.id}`}
          className="flex items-center justify-between px-3 py-2 bg-[#1a2744] hover:bg-[#1e3060] border border-[#1e3a60] rounded-lg text-blue-300 text-sm transition-colors"
        >
          <span>エージェント詳細</span>
          <ExternalLink className="w-3.5 h-3.5" />
        </Link>
        <Link
          href={`/alerts?agent_id=${node.id}`}
          className="flex items-center justify-between px-3 py-2 bg-[#1a1a2a] hover:bg-[#22223a] border border-[#2a2050] rounded-lg text-purple-300 text-sm transition-colors"
        >
          <span>アラート一覧</span>
          <AlertTriangle className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-falcon-muted shrink-0">{label}</span>
      <span className={`text-[#c9d6e8] text-right truncate ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
    </div>
  )
}

// ─── Filter Panel ─────────────────────────────────────────────────────────────

function FilterPanel({
  filters,
  onChange,
  allOS,
  allSubnets,
  lateralMovementCount,
}: {
  filters: FilterState
  onChange: (f: FilterState) => void
  allOS: string[]
  allSubnets: string[]
  lateralMovementCount: number
}) {
  const [open, setOpen] = useState(true)

  return (
    <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-falcon-border hover:bg-falcon-card transition-colors"
      >
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-blue-400" />
          <span className="text-white font-medium text-sm">フィルター</span>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-falcon-muted" /> : <ChevronDown className="w-4 h-4 text-falcon-muted" />}
      </button>

      {open && (
        <div className="p-4 space-y-4">
          {/* OS */}
          <div>
            <label className="text-xs text-falcon-muted uppercase tracking-wide mb-1.5 block">OS</label>
            <select
              value={filters.os}
              onChange={e => onChange({ ...filters, os: e.target.value })}
              className="w-full text-sm bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2
                         text-[#c9d6e8] focus:outline-hidden focus:border-blue-500"
            >
              <option value="">すべてのOS</option>
              {allOS.map(os => <option key={os} value={os}>{os}</option>)}
            </select>
          </div>

          {/* Status */}
          <div>
            <label className="text-xs text-falcon-muted uppercase tracking-wide mb-1.5 block">ステータス</label>
            <select
              value={filters.status}
              onChange={e => onChange({ ...filters, status: e.target.value })}
              className="w-full text-sm bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2
                         text-[#c9d6e8] focus:outline-hidden focus:border-blue-500"
            >
              <option value="">すべてのステータス</option>
              <option value="online">オンライン</option>
              <option value="offline">オフライン</option>
              <option value="warning">警告</option>
            </select>
          </div>

          {/* Subnet */}
          <div>
            <label className="text-xs text-falcon-muted uppercase tracking-wide mb-1.5 block">サブネット</label>
            <select
              value={filters.subnet}
              onChange={e => onChange({ ...filters, subnet: e.target.value })}
              className="w-full text-sm bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2
                         text-[#c9d6e8] focus:outline-hidden focus:border-blue-500"
            >
              <option value="">すべてのサブネット</option>
              {allSubnets.map(s => <option key={s} value={s}>{s}.0/24</option>)}
            </select>
          </div>

          {/* Lateral movement only */}
          <label className="flex items-center gap-3 cursor-pointer group">
            <div
              onClick={() => onChange({ ...filters, lateralMovementOnly: !filters.lateralMovementOnly })}
              className={`w-10 h-5 rounded-full transition-colors relative ${
                filters.lateralMovementOnly ? 'bg-red-600' : 'bg-falcon-border'
              }`}
            >
              <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text transition-transform ${
                filters.lateralMovementOnly ? 'translate-x-5' : 'translate-x-0.5'
              }`} />
            </div>
            <span className="text-sm text-[#c9d6e8] group-hover:text-white transition-colors">
              横展開のみ表示
            </span>
            {lateralMovementCount > 0 && (
              <span className="ml-auto px-1.5 py-0.5 rounded-sm bg-red-900/40 text-red-300 text-[10px] font-semibold border border-red-700/50">
                {lateralMovementCount}
              </span>
            )}
          </label>

          {/* Reset */}
          <button
            onClick={() => onChange({ os: '', status: '', subnet: '', lateralMovementOnly: false })}
            className="w-full text-xs text-falcon-muted hover:text-white border border-falcon-border rounded-lg py-1.5 transition-colors hover:bg-falcon-border"
          >
            フィルターをリセット
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Top Talkers Panel ────────────────────────────────────────────────────────

function TopTalkersPanel({
  nodes,
  edges,
  onSelect,
}: {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
  onSelect: (id: string) => void
}) {
  const talkers = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const edge of edges) {
      counts[edge.source] = (counts[edge.source] ?? 0) + (edge.connection_count ?? 1)
      counts[edge.target] = (counts[edge.target] ?? 0) + (edge.connection_count ?? 1)
    }
    return Object.entries(counts)
      .map(([id, count]) => ({ id, count, node: nodes.find(n => n.id === id) }))
      .filter(t => t.node)
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
  }, [nodes, edges])

  return (
    <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
      <div className="px-4 py-3 border-b border-falcon-border flex items-center gap-2">
        <Activity className="w-4 h-4 text-blue-400" />
        <span className="text-white font-medium text-sm">通信量上位</span>
      </div>
      <div className="divide-y divide-falcon-border">
        {talkers.length === 0 ? (
          <p className="text-center text-[#475569] text-sm py-6">データなし</p>
        ) : (
          talkers.map(({ id, count, node }) => {
            const color = node ? osColor(node as TopologyNode) : '#6b7280'
            return (
              <button
                key={id}
                onClick={() => onSelect(id)}
                className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-falcon-card transition-colors text-left"
              >
                <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: color }} />
                <span className="text-sm text-[#c9d6e8] truncate flex-1">{node?.hostname ?? id}</span>
                <span className="text-xs font-mono text-falcon-muted shrink-0">{count} 接続</span>
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function NetworkTopologyPage() {
  const [hoveredId, setHoveredId] = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [isolatedId, setIsolatedId] = useState<string | null>(null)
  const [groupBySubnet, setGroupBySubnet] = useState(false)
  const [contextMenu, setContextMenu] = useState<ContextMenu | null>(null)
  const [filters, setFilters] = useState<FilterState>({
    os: '', status: '', subnet: '', lateralMovementOnly: false,
  })

  // Fetch topology from dedicated endpoint, fall back to agents+connections
  const {
    data: topoData,
    isLoading: topoLoading,
    isFetching: topoFetching,
    refetch: refetchTopo,
  } = useQuery<TopologyResponse>({
    queryKey: ['network-topology'],
    queryFn: async () => {
      try {
        return await apiFetch<TopologyResponse>('/api/v1/network/topology')
      } catch {
        return { nodes: [], edges: [], subnet_groups: [] }
      }
    },
    staleTime: 30_000,
  })

  const {
    data: agentsData,
    isLoading: agentsLoading,
    isFetching: agentsFetching,
    refetch: refetchAgents,
  } = useQuery<AgentsResponse>({
    queryKey: ['network-topology-agents'],
    queryFn: () => apiFetch<AgentsResponse>('/api/v1/agents?limit=200').catch(() => ({ agents: [] })),
    staleTime: 30_000,
  })

  const {
    data: connData,
    isLoading: connLoading,
    isFetching: connFetching,
    refetch: refetchConn,
  } = useQuery<NetConnResponse>({
    queryKey: ['network-topology-connections'],
    queryFn: () => apiFetch<NetConnResponse>('/api/v1/network-connections?limit=50').catch(() => ({ connections: [] })),
    staleTime: 30_000,
  })

  // Prefer topology API, fall back to building from agents
  const rawNodes: TopologyNode[] = useMemo(() => {
    if (topoData?.nodes && topoData.nodes.length > 0) return topoData.nodes
    const agents = agentsData?.agents ?? agentsData?.data ?? []
    return agents.map(a => ({
      id: a.id,
      hostname: a.hostname,
      ip_address: a.ip_address,
      os: a.os,
      status: a.status,
      lateral_movement: a.lateral_movement,
    }))
  }, [topoData, agentsData])

  const rawEdges: TopologyEdge[] = useMemo(() => {
    if (topoData?.edges && topoData.edges.length > 0) return topoData.edges
    // Build edges from subnet co-membership
    const built: TopologyEdge[] = []
    const seen = new Set<string>()
    for (let i = 0; i < rawNodes.length; i++) {
      const subA = getSubnet(rawNodes[i].ip_address)
      for (let j = i + 1; j < rawNodes.length; j++) {
        const subB = getSubnet(rawNodes[j].ip_address)
        if (subA && subB && subA === subB) {
          const key = [rawNodes[i].id, rawNodes[j].id].sort().join('|')
          if (!seen.has(key)) {
            seen.add(key)
            built.push({ source: rawNodes[i].id, target: rawNodes[j].id, connection_count: 1 })
          }
        }
      }
    }
    return built
  }, [topoData, rawNodes])

  // Apply filters
  const filteredNodes = useMemo(() => {
    return rawNodes.filter(node => {
      if (filters.os && (node.os ?? '').toLowerCase() !== filters.os.toLowerCase()) return false
      if (filters.status && node.status !== filters.status) return false
      if (filters.subnet && getSubnet(node.ip_address) !== filters.subnet) return false
      if (filters.lateralMovementOnly && !node.lateral_movement) return false
      return true
    })
  }, [rawNodes, filters])

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes])
  const filteredEdges = useMemo(() => rawEdges.filter(e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)), [rawEdges, filteredNodeIds])

  const layouted = useMemo(() => layoutNodes(filteredNodes, groupBySubnet), [filteredNodes, groupBySubnet])

  // Metadata
  const allOS = useMemo(() => [...new Set(rawNodes.map(n => n.os).filter(Boolean))] as string[], [rawNodes])
  const allSubnets = useMemo(() => [...new Set(rawNodes.map(n => getSubnet(n.ip_address)).filter(Boolean))] as string[], [rawNodes])
  const lateralMovementCount = useMemo(() => rawNodes.filter(n => n.lateral_movement).length, [rawNodes])

  const stats = useMemo(() => {
    const online = rawNodes.filter(a => a.status === 'online').length
    const subnets = allSubnets.length
    const lmEdges = rawEdges.filter(e => e.lateral_movement).length
    return { online, subnets, lateral: lateralMovementCount, lmEdges }
  }, [rawNodes, allSubnets, lateralMovementCount, rawEdges])

  const selectedNode = useMemo(() => layouted.find(n => n.id === selectedId) ?? null, [layouted, selectedId])

  function handleRefresh() {
    refetchTopo()
    refetchAgents()
    refetchConn()
  }

  const isFetching = topoFetching || agentsFetching || connFetching
  const isLoading = topoLoading && rawNodes.length === 0

  function handleContextMenu(e: React.MouseEvent, node: LayoutNode) {
    setContextMenu({ x: e.clientX, y: e.clientY, nodeId: node.id, hostname: node.hostname })
  }

  function handleIsolate(id: string) {
    setIsolatedId(prev => prev === id ? null : id)
    setSelectedId(id)
  }

  return (
    <div className="p-6 space-y-6 min-h-screen bg-[#070d19]">
      {/* Context menu */}
      {contextMenu && (
        <ContextMenuPopup
          menu={contextMenu}
          onClose={() => setContextMenu(null)}
          onViewAgent={(id) => window.open(`/agents/${id}`, '_blank')}
          onShowConnections={(id) => setSelectedId(id)}
          onIsolateNode={handleIsolate}
        />
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-falcon-red rounded-lg flex items-center justify-center shrink-0">
            <Network className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">ネットワークトポロジー</h1>
            <p className="text-sm text-falcon-muted">エンドポイント接続、サブネット、横展開の可視化</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Group by subnet toggle */}
          <button
            onClick={() => setGroupBySubnet(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-lg text-sm transition-colors ${
              groupBySubnet
                ? 'bg-blue-700 border-blue-600 text-white'
                : 'bg-falcon-surface border-falcon-border text-falcon-muted hover:text-white hover:bg-falcon-card'
            }`}
          >
            <Layers className="w-4 h-4" />
            サブネット別
          </button>
          {isolatedId && (
            <button
              onClick={() => setIsolatedId(null)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-900/30 border border-orange-700/50 rounded-lg text-orange-300 text-sm hover:bg-orange-900/50 transition-colors"
            >
              <X className="w-4 h-4" />
              分離を解除
            </button>
          )}
          <button
            onClick={handleRefresh}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-surface border border-falcon-border
                       hover:bg-falcon-card text-white text-sm rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* ── Stats row ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="総ノード数"           value={rawNodes.length}   icon={Server}   color="blue"   />
        <StatCard label="総エッジ数"           value={rawEdges.length}   icon={Globe}    color="blue"   />
        <StatCard label="横展開検知"           value={stats.lateral}     icon={AlertTriangle} color="red" />
        <StatCard label="アクティブノード"     value={stats.online}      icon={Wifi}     color="green"  />
      </div>

      {/* ── Main area ── */}
      {isLoading ? (
        <div className="flex items-center justify-center py-32">
          <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-falcon-red" />
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
          {/* SVG graph — 3/4 width */}
          <div className="xl:col-span-3 bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3 border-b border-falcon-border">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-blue-400" />
                <span className="text-white font-medium text-sm">ネットワークグラフ</span>
                <span className="text-[#475569] text-xs">
                  {filteredNodes.length} nodes · {filteredEdges.length} edges
                  {stats.lateral > 0 && (
                    <span className="ml-2 text-orange-400">· {stats.lateral} 横展開</span>
                  )}
                </span>
              </div>
              {(selectedId || isolatedId) && (
                <button
                  onClick={() => { setSelectedId(null); setIsolatedId(null) }}
                  className="text-xs text-falcon-muted hover:text-white transition-colors flex items-center gap-1"
                >
                  <X className="w-3 h-3" />
                  選択を解除
                </button>
              )}
            </div>
            <div className="p-2" style={{ aspectRatio: `${SVG_W}/${SVG_H}`, minHeight: 360 }}>
              {filteredNodes.length === 0 ? (
                <div className="flex items-center justify-center h-full text-[#475569] text-sm py-24">
                  現在のフィルターに一致するノードがありません
                </div>
              ) : (
                <NetworkGraph
                  layouted={layouted}
                  edges={filteredEdges}
                  hoveredId={hoveredId}
                  selectedId={selectedId}
                  isolatedId={isolatedId}
                  groupBySubnet={groupBySubnet}
                  onHover={setHoveredId}
                  onSelect={setSelectedId}
                  onContextMenu={handleContextMenu}
                />
              )}
            </div>
          </div>

          {/* Right panel — 1/4 width */}
          <div className="xl:col-span-1 space-y-4">
            {/* Node detail */}
            <NodeDetailPanel node={selectedNode} connections={filteredEdges} />

            {/* Filter panel */}
            <FilterPanel
              filters={filters}
              onChange={setFilters}
              allOS={allOS}
              allSubnets={allSubnets}
              lateralMovementCount={lateralMovementCount}
            />

            {/* Top talkers */}
            <TopTalkersPanel nodes={filteredNodes} edges={filteredEdges} onSelect={setSelectedId} />
          </div>
        </div>
      )}
    </div>
  )
}
