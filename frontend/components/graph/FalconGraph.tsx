'use client'

import React, { useRef, useState, useCallback, useEffect, useMemo } from 'react'
import {
  Shield, Cpu, Globe, FileText, Search as DnsIcon,
  AlertTriangle, ZoomIn, ZoomOut, RotateCcw, Maximize2,
  Filter, ChevronRight, Copy, ExternalLink
} from 'lucide-react'
import { format, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'

// ── Types ──────────────────────────────────────────────────────

export interface GraphNode {
  id: string
  type: 'alert' | 'process' | 'network' | 'file' | 'registry' | 'dns'
  label: string
  detail: Record<string, string>
  suspicious: boolean
  timestamp: string
  severity?: number
}

export interface GraphEdge {
  source: string
  target: string
  type: 'spawned' | 'connected' | 'wrote' | 'read' | 'queried'
  label: string
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  alert_id: string
}

// ── Design tokens ──────────────────────────────────────────────

const NODE_STYLES: Record<string, {
  bg: string; border: string; icon: string; text: string
  iconColor: string; glow: string; Icon: React.ElementType
}> = {
  alert:    { bg: '#1a0a0d', border: '#e8002d', icon: '#e8002d', text: '#ff6b7a',  iconColor: '#e8002d', glow: 'rgba(232,0,45,0.25)',    Icon: Shield },
  process:  { bg: '#080f1a', border: '#1a6bff', icon: '#1a6bff', text: '#5a99ff',  iconColor: '#1a6bff', glow: 'rgba(26,107,255,0.2)',   Icon: Cpu },
  network:  { bg: '#041418', border: '#00b8d4', icon: '#00b8d4', text: '#00e5ff',  iconColor: '#00b8d4', glow: 'rgba(0,184,212,0.2)',    Icon: Globe },
  file:     { bg: '#141008', border: '#ff9800', icon: '#ff9800', text: '#ffb74d',  iconColor: '#ff9800', glow: 'rgba(255,152,0,0.2)',    Icon: FileText },
  registry: { bg: '#100814', border: '#7c3aed', icon: '#7c3aed', text: '#a78bfa',  iconColor: '#7c3aed', glow: 'rgba(124,58,237,0.2)',   Icon: AlertTriangle },
  dns:      { bg: '#041408', border: '#00c853', icon: '#00c853', text: '#00e676',  iconColor: '#00c853', glow: 'rgba(0,200,83,0.2)',     Icon: DnsIcon },
}

const EDGE_COLORS: Record<string, string> = {
  spawned:   '#1a6bff',
  connected: '#00b8d4',
  wrote:     '#ff9800',
  read:      '#ff9800',
  queried:   '#00c853',
}

const TYPE_LABELS: Record<string, string> = {
  alert: 'ALERT', process: 'PROCESS', network: 'NETWORK',
  file: 'FILE', registry: 'REGISTRY', dns: 'DNS',
}

// ── Layout engine ──────────────────────────────────────────────
// Hierarchical left-to-right layout

const NODE_W = 200
const NODE_H = 56
const COL_GAP = 140
const ROW_GAP = 22

interface LayoutNode extends GraphNode {
  x: number
  y: number
  col: number
  row: number
}

function computeLayout(nodes: GraphNode[], edges: GraphEdge[]): LayoutNode[] {
  if (nodes.length === 0) return []

  // Build adjacency list (children)
  const children = new Map<string, string[]>()
  const parents  = new Map<string, string[]>()
  for (const n of nodes) { children.set(n.id, []); parents.set(n.id, []) }
  for (const e of edges) {
    children.get(e.source)?.push(e.target)
    parents.get(e.target)?.push(e.source)
  }

  // BFS column assignment from roots (nodes with no parents / or type=alert)
  const col = new Map<string, number>()
  const queue: string[] = []

  // Roots = nodes with no incoming edges
  for (const n of nodes) {
    if ((parents.get(n.id)?.length ?? 0) === 0) {
      col.set(n.id, 0)
      queue.push(n.id)
    }
  }
  if (queue.length === 0) { col.set(nodes[0].id, 0); queue.push(nodes[0].id) }

  const visited = new Set<string>()
  while (queue.length > 0) {
    const cur = queue.shift()!
    if (visited.has(cur)) continue
    visited.add(cur)
    const curCol = col.get(cur) ?? 0
    for (const child of (children.get(cur) ?? [])) {
      const existing = col.get(child) ?? 0
      col.set(child, Math.max(existing, curCol + 1))
      queue.push(child)
    }
  }

  // Group by column
  const byCol = new Map<number, string[]>()
  for (const n of nodes) {
    const c = col.get(n.id) ?? 0
    if (!byCol.has(c)) byCol.set(c, [])
    byCol.get(c)!.push(n.id)
  }

  // Sort by type within column (alert first, then process, then network/file/dns)
  const TYPE_ORDER: Record<string, number> = {
    alert: 0, process: 1, network: 2, dns: 2, file: 3, registry: 4
  }
  for (const arr of byCol.values()) {
    arr.sort((a, b) => {
      const na = nodes.find(n => n.id === a)
      const nb = nodes.find(n => n.id === b)
      return (TYPE_ORDER[na?.type ?? ''] ?? 9) - (TYPE_ORDER[nb?.type ?? ''] ?? 9)
    })
  }

  // Assign x, y positions
  const result: LayoutNode[] = []
  const idMap = new Map(nodes.map(n => [n.id, n]))

  const maxCol = Math.max(...Array.from(col.values()))
  for (let c = 0; c <= maxCol; c++) {
    const colNodes = byCol.get(c) ?? []
    const totalH = colNodes.length * (NODE_H + ROW_GAP) - ROW_GAP
    const startY = -totalH / 2
    colNodes.forEach((nid, i) => {
      const node = idMap.get(nid)!
      result.push({
        ...node,
        col: c,
        row: i,
        x: c * (NODE_W + COL_GAP),
        y: startY + i * (NODE_H + ROW_GAP),
      })
    })
  }

  return result
}

// ── Edge path (cubic bezier) ───────────────────────────────────

function edgePath(sx: number, sy: number, tx: number, ty: number): string {
  const mx = (sx + tx) / 2
  return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ty}, ${tx} ${ty}`
}

// ── Main component ─────────────────────────────────────────────

interface FalconGraphProps {
  data: GraphData
  isLoading?: boolean
}

export function FalconGraph({ data, isLoading }: FalconGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [transform, setTransform] = useState({ x: 60, y: 300, scale: 1 })
  const [dragging, setDragging] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  const [selected, setSelected] = useState<LayoutNode | null>(null)
  const [filter, setFilter] = useState<string[]>([]) // empty = show all
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null)
  const [tooltipCopied, setTooltipCopied] = useState(false)

  // Filter nodes/edges
  const filteredNodes = useMemo(() =>
    filter.length === 0 ? data.nodes : data.nodes.filter(n => filter.includes(n.type)),
    [data.nodes, filter]
  )
  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes])
  const filteredEdges = useMemo(() =>
    data.edges.filter(e => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)),
    [data.edges, filteredNodeIds]
  )

  const layout = useMemo(() => computeLayout(filteredNodes, filteredEdges), [filteredNodes, filteredEdges])
  const layoutMap = useMemo(() => new Map(layout.map(n => [n.id, n])), [layout])

  // Bounds for auto-fit
  const bounds = useMemo(() => {
    if (layout.length === 0) return { minX: 0, minY: 0, maxX: 800, maxY: 400 }
    return {
      minX: Math.min(...layout.map(n => n.x)),
      minY: Math.min(...layout.map(n => n.y)),
      maxX: Math.max(...layout.map(n => n.x + NODE_W)),
      maxY: Math.max(...layout.map(n => n.y + NODE_H)),
    }
  }, [layout])

  // Auto-fit on data change
  useEffect(() => {
    if (!svgRef.current || layout.length === 0) return
    const svgRect = svgRef.current.getBoundingClientRect()
    const graphW = bounds.maxX - bounds.minX + NODE_W
    const graphH = bounds.maxY - bounds.minY + NODE_H
    const scaleX = (svgRect.width  - 120) / graphW
    const scaleY = (svgRect.height - 120) / graphH
    const scale  = Math.min(scaleX, scaleY, 1.2)
    setTransform({
      scale,
      x: 60 - bounds.minX * scale,
      y: svgRect.height / 2 - (bounds.minY + graphH / 2) * scale,
    })
  }, [layout.length, bounds])

  // Pan
  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return
    setDragging(true)
    setDragStart({ x: e.clientX - transform.x, y: e.clientY - transform.y })
  }, [transform])
  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging) return
    setTransform(t => ({ ...t, x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }))
  }, [dragging, dragStart])
  const onMouseUp = useCallback(() => setDragging(false), [])

  // Zoom
  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const delta = e.deltaY > 0 ? 0.9 : 1.1
    setTransform(t => ({
      ...t,
      scale: Math.max(0.2, Math.min(3, t.scale * delta)),
    }))
  }, [])

  const zoom = (delta: number) =>
    setTransform(t => ({ ...t, scale: Math.max(0.2, Math.min(3, t.scale * delta)) }))

  // Type filter toggle
  const toggleFilter = (type: string) => {
    setFilter(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }

  const allTypes = useMemo(() =>
    Array.from(new Set(data.nodes.map(n => n.type))),
    [data.nodes]
  )

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full bg-[#080c14]">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-[#e8002d]/30 border-t-[#e8002d] rounded-full animate-spin" />
          <p className="text-[#3d5068] text-xs uppercase tracking-widest">グラフ構築中...</p>
        </div>
      </div>
    )
  }

  if (data.nodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full bg-[#080c14]">
        <div className="text-center">
          <Shield className="w-12 h-12 text-[#1e2d42] mx-auto mb-3" />
          <p className="text-[#3d5068] text-sm">このアラートに関連するイベントデータがありません</p>
          <p className="text-[#1e2d42] text-xs mt-1">エージェントからのイベントが蓄積されると表示されます</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full bg-[#080c14] rounded-md overflow-hidden border border-[#1e2d42]">

      {/* ── Main SVG canvas ─────────────────────────────── */}
      <div className="flex-1 relative overflow-hidden">

        {/* Toolbar */}
        <div className="absolute top-3 left-3 z-10 flex items-center gap-1.5">
          {/* Zoom controls */}
          <div className="flex items-center bg-[#111827] border border-[#1e2d42] rounded overflow-hidden">
            <button onClick={() => zoom(1.2)}
                    className="px-2.5 py-1.5 text-[#7d92b0] hover:bg-[#19253d] hover:text-white transition-colors">
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <span className="px-2 text-[10px] text-[#3d5068] font-mono border-x border-[#1e2d42]">
              {Math.round(transform.scale * 100)}%
            </span>
            <button onClick={() => zoom(0.83)}
                    className="px-2.5 py-1.5 text-[#7d92b0] hover:bg-[#19253d] hover:text-white transition-colors">
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
          </div>
          <button
            onClick={() => {
              if (!svgRef.current || layout.length === 0) return
              const svgRect = svgRef.current.getBoundingClientRect()
              const graphW = bounds.maxX - bounds.minX + NODE_W
              const graphH = bounds.maxY - bounds.minY + NODE_H
              const scaleX = (svgRect.width  - 120) / graphW
              const scaleY = (svgRect.height - 120) / graphH
              const scale  = Math.min(scaleX, scaleY, 1.2)
              setTransform({
                scale, x: 60 - bounds.minX * scale,
                y: svgRect.height / 2 - (bounds.minY + graphH / 2) * scale,
              })
            }}
            className="px-2.5 py-1.5 bg-[#111827] border border-[#1e2d42] rounded
                       text-[#7d92b0] hover:bg-[#19253d] hover:text-white transition-colors">
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          {/* Type filter */}
          <div className="flex items-center gap-1 ml-1">
            {allTypes.map(type => {
              const s = NODE_STYLES[type]
              const active = filter.length === 0 || filter.includes(type)
              return (
                <button
                  key={type}
                  onClick={() => toggleFilter(type)}
                  className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-bold
                              tracking-wider uppercase border transition-all ${
                    active
                      ? 'opacity-100'
                      : 'opacity-30 grayscale'
                  }`}
                  style={{
                    background: active ? s.bg : '#111827',
                    borderColor: active ? s.border : '#1e2d42',
                    color: s.text,
                  }}
                >
                  <s.Icon className="w-2.5 h-2.5" />
                  {TYPE_LABELS[type]}
                </button>
              )
            })}
          </div>
        </div>

        {/* Stats */}
        <div className="absolute top-3 right-3 z-10 flex items-center gap-3
                        bg-[#111827] border border-[#1e2d42] rounded px-3 py-1.5">
          <span className="text-[10px] text-[#3d5068] font-mono">
            {layout.length} nodes · {filteredEdges.length} edges
          </span>
          {data.nodes.some(n => n.suspicious) && (
            <span className="flex items-center gap-1 text-[10px] text-[#e8002d] font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-[#e8002d] critical-pulse" />
              SUSPICIOUS
            </span>
          )}
        </div>

        {/* SVG */}
        <svg
          ref={svgRef}
          className="w-full h-full"
          style={{ cursor: dragging ? 'grabbing' : 'grab', background: 'transparent' }}
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseUp}
          onWheel={onWheel}
        >
          <defs>
            {/* Grid pattern */}
            <pattern id="fg-grid" width="32" height="32" patternUnits="userSpaceOnUse">
              <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#1e2d42" strokeWidth="0.5" opacity="0.4" />
            </pattern>
            {/* Arrowhead markers */}
            {Object.entries(EDGE_COLORS).map(([type, color]) => (
              <marker key={type} id={`arrow-${type}`} markerWidth="8" markerHeight="8"
                      refX="7" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill={color} opacity="0.8" />
              </marker>
            ))}
            {/* Glow filters */}
            {Object.entries(NODE_STYLES).map(([type, s]) => (
              <filter key={type} id={`glow-${type}`}>
                <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
                <feFlood floodColor={s.glow} floodOpacity="1" result="color" />
                <feComposite in="color" in2="blur" operator="in" result="shadow" />
                <feMerge><feMergeNode in="shadow" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            ))}
          </defs>

          {/* Background grid */}
          <rect width="100%" height="100%" fill="url(#fg-grid)" />

          {/* Graph content (transformed) */}
          <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>

            {/* ── Edges ──────────────────────────────── */}
            {filteredEdges.map((edge, i) => {
              const src = layoutMap.get(edge.source)
              const tgt = layoutMap.get(edge.target)
              if (!src || !tgt) return null
              const color = EDGE_COLORS[edge.type] ?? '#1e2d42'
              const edgeKey = `${edge.source}-${edge.target}-${i}`
              const isHovered = hoveredEdge === edgeKey
              const sx = src.x + NODE_W
              const sy = src.y + NODE_H / 2
              const tx = tgt.x
              const ty = tgt.y + NODE_H / 2
              const path = edgePath(sx, sy, tx, ty)
              const midX = (sx + tx) / 2
              const midY = (sy + ty) / 2

              return (
                <g key={edgeKey}>
                  {/* Hit area (wider, invisible) */}
                  <path
                    d={path} fill="none" stroke="transparent" strokeWidth="12"
                    style={{ cursor: 'pointer' }}
                    onMouseEnter={() => setHoveredEdge(edgeKey)}
                    onMouseLeave={() => setHoveredEdge(null)}
                  />
                  {/* Visible edge */}
                  <path
                    d={path} fill="none"
                    stroke={color} strokeWidth={isHovered ? 1.5 : 1}
                    strokeDasharray={edge.type === 'connected' ? '6 3' : undefined}
                    opacity={isHovered ? 0.9 : 0.45}
                    markerEnd={`url(#arrow-${edge.type})`}
                  />
                  {/* Edge label on hover */}
                  {isHovered && (
                    <g>
                      <rect x={midX - 24} y={midY - 10} width={48} height={16}
                            rx={3} fill="#111827" stroke={color} strokeWidth="0.5" />
                      <text x={midX} y={midY + 2} textAnchor="middle"
                            fontSize={9} fill={color} fontFamily="monospace">
                        {edge.label || edge.type}
                      </text>
                    </g>
                  )}
                </g>
              )
            })}

            {/* ── Nodes ──────────────────────────────── */}
            {layout.map(node => {
              const s = NODE_STYLES[node.type] ?? NODE_STYLES.process
              const isSelected = selected?.id === node.id
              const NodeIcon = s.Icon

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x},${node.y})`}
                  style={{ cursor: 'pointer' }}
                  onClick={e => { e.stopPropagation(); setSelected(isSelected ? null : node) }}
                >
                  {/* Glow on suspicious or selected */}
                  {(node.suspicious || isSelected) && (
                    <rect x={-4} y={-4} width={NODE_W + 8} height={NODE_H + 8}
                          rx={8} fill={s.glow}
                          filter={`url(#glow-${node.type})`} />
                  )}

                  {/* Card bg */}
                  <rect width={NODE_W} height={NODE_H} rx={5}
                        fill={s.bg}
                        stroke={isSelected ? s.border : (node.suspicious ? s.border : '#1e2d42')}
                        strokeWidth={isSelected ? 1.5 : (node.suspicious ? 1 : 0.5)}
                        opacity="0.97" />

                  {/* Left accent bar */}
                  <rect width={3} height={NODE_H} rx={1.5} fill={s.border} opacity="0.9" />

                  {/* Icon */}
                  <g transform={`translate(10, ${NODE_H / 2 - 7})`}>
                    <NodeIcon width={14} height={14} color={s.iconColor} strokeWidth={1.5} />
                  </g>

                  {/* Type label */}
                  <text x={30} y={18} fontSize={8} fill={s.text}
                        fontFamily="monospace" letterSpacing="1" opacity="0.7">
                    {TYPE_LABELS[node.type]}
                  </text>

                  {/* Main label (truncated) */}
                  <text x={30} y={34} fontSize={11} fill="#e2e8f4" fontFamily="monospace"
                        fontWeight="500">
                    <title>{node.label}</title>
                    {node.label.length > 18 ? node.label.slice(0, 18) + '…' : node.label}
                  </text>

                  {/* Suspicious badge */}
                  {node.suspicious && (
                    <g transform={`translate(${NODE_W - 18}, 6)`}>
                      <circle r={5} fill="#e8002d" opacity="0.9" />
                      <text x={0} y={3.5} textAnchor="middle" fontSize={7}
                            fill="white" fontWeight="bold">!</text>
                    </g>
                  )}

                  {/* Timestamp (small) */}
                  {node.timestamp && (
                    <text x={30} y={48} fontSize={8} fill={s.text}
                          fontFamily="monospace" opacity="0.4">
                      {(() => {
                        try { return format(parseISO(node.timestamp), 'HH:mm:ss') }
                        catch { return '' }
                      })()}
                    </text>
                  )}

                  {/* Output port dot */}
                  <circle cx={NODE_W} cy={NODE_H / 2} r={3} fill={s.border} opacity="0.6" />
                  {/* Input port dot */}
                  <circle cx={0} cy={NODE_H / 2} r={3} fill={s.border} opacity="0.6" />
                </g>
              )
            })}
          </g>
        </svg>

        {/* Click backdrop to deselect */}
        {selected && (
          <div className="absolute inset-0 z-0" onClick={() => setSelected(null)} />
        )}
      </div>

      {/* ── Detail panel ────────────────────────────────────── */}
      <div className={`flex-shrink-0 flex flex-col bg-[#0d1220] border-l border-[#1e2d42]
                       transition-all duration-200 overflow-hidden ${
                         selected ? 'w-72' : 'w-0'
                       }`}>
        {selected && (() => {
          const s = NODE_STYLES[selected.type] ?? NODE_STYLES.process
          const NodeIcon = s.Icon
          return (
            <div className="p-4 flex flex-col h-full overflow-y-auto">
              {/* Header */}
              <div className="flex items-start gap-3 mb-4">
                <div className="w-8 h-8 rounded flex-shrink-0 flex items-center justify-center"
                     style={{ background: s.bg, border: `1px solid ${s.border}` }}>
                  <NodeIcon className="w-4 h-4" style={{ color: s.iconColor }} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] font-bold tracking-widest uppercase"
                          style={{ color: s.text }}>
                      {TYPE_LABELS[selected.type]}
                    </span>
                    {selected.suspicious && (
                      <span className="text-[9px] font-bold text-[#e8002d] bg-[#e8002d]/10
                                       px-1.5 py-0.5 rounded border border-[#e8002d]/30">
                        SUSPICIOUS
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-mono text-[#e2e8f4] font-semibold mt-0.5 break-all leading-tight">
                    {selected.label}
                  </p>
                </div>
                <button onClick={() => setSelected(null)}
                        className="text-[#3d5068] hover:text-[#7d92b0] flex-shrink-0 ml-1">
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>

              {/* Timestamp */}
              {selected.timestamp && (
                <div className="mb-3 px-3 py-2 rounded bg-[#161f33] border border-[#1e2d42]">
                  <p className="text-[9px] text-[#3d5068] uppercase tracking-wider mb-0.5">Timestamp</p>
                  <p className="text-[11px] text-[#7d92b0] font-mono">
                    {(() => {
                      try { return format(parseISO(selected.timestamp), 'yyyy-MM-dd HH:mm:ss', { locale: ja }) }
                      catch { return selected.timestamp }
                    })()}
                  </p>
                </div>
              )}

              {/* Details */}
              <div className="space-y-2">
                {Object.entries(selected.detail).filter(([, v]) => v).map(([key, value]) => (
                  <div key={key} className="px-3 py-2 rounded bg-[#111827] border border-[#1e2d42]">
                    <p className="text-[9px] text-[#3d5068] uppercase tracking-wider mb-0.5">{key}</p>
                    <div className="flex items-start gap-1.5">
                      <p className="text-[11px] text-[#e2e8f4] font-mono break-all flex-1 leading-relaxed">
                        {value}
                      </p>
                      <button
                        onClick={() => { navigator.clipboard.writeText(value); setTooltipCopied(true); setTimeout(() => setTooltipCopied(false), 1500) }}
                        className="text-[#3d5068] hover:text-[#7d92b0] transition-colors flex-shrink-0 mt-0.5"
                        title="コピー"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Connected edges */}
              <div className="mt-4">
                <p className="text-[9px] text-[#3d5068] uppercase tracking-wider mb-2">接続関係</p>
                <div className="space-y-1">
                  {data.edges
                    .filter(e => e.source === selected.id || e.target === selected.id)
                    .map((e, i) => {
                      const isOut = e.source === selected.id
                      const otherId = isOut ? e.target : e.source
                      const other = data.nodes.find(n => n.id === otherId)
                      const eColor = EDGE_COLORS[e.type] ?? '#3d5068'
                      return (
                        <div key={i}
                             className="flex items-center gap-2 px-2 py-1.5 rounded bg-[#111827]
                                        border border-[#1e2d42] cursor-pointer hover:bg-[#19253d]"
                             onClick={() => {
                               const node = layout.find(n => n.id === otherId)
                               if (node) setSelected(node)
                             }}>
                          <span className="text-[9px] font-mono" style={{ color: eColor }}>
                            {isOut ? '→' : '←'}
                          </span>
                          <span className="text-[9px] font-mono text-[#3d5068] uppercase">{e.type}</span>
                          <span className="text-[10px] text-[#7d92b0] font-mono truncate flex-1">
                            {other?.label ?? otherId.slice(0, 12)}
                          </span>
                        </div>
                      )
                    })}
                </div>
              </div>

              {/* Copy feedback */}
              {tooltipCopied && (
                <div className="mt-3 px-3 py-1.5 rounded bg-[#00c853]/10 border border-[#00c853]/30
                                text-[#00e676] text-[10px] text-center font-medium">
                  コピーしました
                </div>
              )}
            </div>
          )
        })()}
      </div>
    </div>
  )
}

// ── Legend ─────────────────────────────────────────────────────

export function FalconGraphLegend() {
  return (
    <div className="flex items-center gap-3 flex-wrap">
      {Object.entries(NODE_STYLES).map(([type, s]) => (
        <div key={type} className="flex items-center gap-1.5">
          <s.Icon className="w-3 h-3" style={{ color: s.iconColor }} />
          <span className="text-[10px] uppercase tracking-wider font-bold"
                style={{ color: s.text }}>
            {TYPE_LABELS[type]}
          </span>
        </div>
      ))}
      <div className="w-px h-4 bg-[#1e2d42]" />
      {Object.entries(EDGE_COLORS).map(([type, color]) => (
        <div key={type} className="flex items-center gap-1">
          <div className="w-6 h-px" style={{ background: color }} />
          <span className="text-[9px] text-[#3d5068] uppercase tracking-wide">{type}</span>
        </div>
      ))}
    </div>
  )
}
