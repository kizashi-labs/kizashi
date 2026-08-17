'use client'

import { useState, useRef, useCallback, useMemo, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  ArrowLeft, RefreshCw, GitBranch, Search, Download,
  Calendar, ZoomIn, ZoomOut, Maximize2, Filter
} from 'lucide-react'
import type { Alert, PaginatedResponse } from '@/types/api'

// ── Types ──────────────────────────────────────────────────────────────────

interface NodePos {
  x: number
  y: number
  vx: number
  vy: number
}

interface GraphNode {
  alert: Alert
  pos: NodePos
}

interface GraphEdge {
  source: string
  target: string
}

type TimeRange = '1h' | '6h' | '24h' | '7d' | 'custom'

// ── Constants ──────────────────────────────────────────────────────────────

const SVG_W = 900
const SVG_H = 560

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#e8002d',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#3b82f6',
}

const SEVERITY_RADIUS: Record<string, number> = {
  critical: 22,
  high:     17,
  medium:   13,
  low:      9,
}

const SEVERITY_LABEL_JP: Record<string, string> = {
  critical: 'クリティカル',
  high:     '高',
  medium:   '中',
  low:      '低',
}

// MITRE tactic to abbreviated label
const TACTIC_ABBREV: Record<string, string> = {
  'initial-access':        'IA',
  'execution':             'EX',
  'persistence':           'PE',
  'privilege-escalation':  'PE',
  'defense-evasion':       'DE',
  'credential-access':     'CA',
  'discovery':             'DI',
  'lateral-movement':      'LM',
  'collection':            'CO',
  'command-and-control':   'C2',
  'exfiltration':          'EF',
  'impact':                'IM',
}

const TACTIC_COLORS: Record<string, string> = {
  'initial-access':        '#8b5cf6',
  'execution':             '#6366f1',
  'persistence':           '#ec4899',
  'privilege-escalation':  '#f43f5e',
  'defense-evasion':       '#14b8a6',
  'credential-access':     '#f97316',
  'discovery':             '#84cc16',
  'lateral-movement':      '#22d3ee',
  'collection':            '#a78bfa',
  'command-and-control':   '#fb923c',
  'exfiltration':          '#e879f9',
  'impact':                '#ef4444',
}

function getTacticFromTechnique(technique?: string): string | null {
  if (!technique) return null
  const t = technique.toLowerCase()
  for (const tactic of Object.keys(TACTIC_ABBREV)) {
    if (t.includes(tactic.replace('-', ''))) return tactic
  }
  // Try numeric prefixes like T1059 (execution), T1055 (privilege-escalation) etc.
  return null
}

function severityLabel(s: number): 'critical' | 'high' | 'medium' | 'low' {
  if (s >= 9) return 'critical'
  if (s >= 7) return 'high'
  if (s >= 5) return 'medium'
  return 'low'
}

// ── Simple seeded random for deterministic jitter ─────────────────────────

function seededRandom(seed: number) {
  let s = seed
  return () => {
    s = (s * 1664525 + 1013904223) & 0xffffffff
    return (s >>> 0) / 0xffffffff
  }
}

// ── Build graph data ───────────────────────────────────────────────────────

function buildGraph(alerts: Alert[], severityFilter: string, agentFilter: string) {
  let filtered = alerts
  if (severityFilter) {
    filtered = filtered.filter(a => severityLabel(a.severity) === severityFilter)
  }
  if (agentFilter) {
    filtered = filtered.filter(a =>
      a.agent_hostname.toLowerCase().includes(agentFilter.toLowerCase()) ||
      a.agent_id.toLowerCase().includes(agentFilter.toLowerCase())
    )
  }

  const rng = seededRandom(42)
  const cols = Math.ceil(Math.sqrt(filtered.length))
  const cellW = (SVG_W - 100) / Math.max(cols, 1)
  const cellH = (SVG_H - 100) / Math.max(Math.ceil(filtered.length / Math.max(cols, 1)), 1)

  const nodes: GraphNode[] = filtered.map((alert, i) => {
    const col = i % cols
    const row = Math.floor(i / cols)
    const jitterX = (rng() - 0.5) * cellW * 0.6
    const jitterY = (rng() - 0.5) * cellH * 0.6
    return {
      alert,
      pos: {
        x: 50 + col * cellW + cellW / 2 + jitterX,
        y: 50 + row * cellH + cellH / 2 + jitterY,
        vx: 0,
        vy: 0,
      },
    }
  })

  // Edges: connect alerts sharing the same agent_id
  const edges: GraphEdge[] = []
  const nodeMap = new Map(nodes.map(n => [n.alert.id, n]))
  const agentGroups = new Map<string, string[]>()

  for (const n of nodes) {
    if (!n.alert.agent_id) continue
    const grp = agentGroups.get(n.alert.agent_id) ?? []
    grp.push(n.alert.id)
    agentGroups.set(n.alert.agent_id, grp)
  }

  for (const [, ids] of agentGroups) {
    for (let i = 0; i < ids.length - 1; i++) {
      edges.push({ source: ids[i], target: ids[i + 1] })
    }
  }

  // Clusters: connected components
  const parent = new Map<string, string>()
  const find = (x: string): string => {
    if (!parent.has(x)) parent.set(x, x)
    if (parent.get(x) !== x) parent.set(x, find(parent.get(x)!))
    return parent.get(x)!
  }
  const union = (a: string, b: string) => {
    const pa = find(a), pb = find(b)
    if (pa !== pb) parent.set(pa, pb)
  }
  for (const e of edges) { union(e.source, e.target) }
  for (const n of nodes) { find(n.alert.id) }

  const clusterMap = new Map<string, Alert[]>()
  for (const n of nodes) {
    const root = find(n.alert.id)
    const cl = clusterMap.get(root) ?? []
    cl.push(n.alert)
    clusterMap.set(root, cl)
  }
  const clusters = Array.from(clusterMap.values()).filter(c => c.length > 0)

  return { nodes, edges, nodeMap, clusters }
}

// ── Tooltip ────────────────────────────────────────────────────────────────

interface TooltipState {
  visible: boolean
  x: number
  y: number
  text: string
}

// ── Main component ─────────────────────────────────────────────────────────

export default function AlertGraphPage() {
  const [timeRange, setTimeRange]       = useState<TimeRange>('24h')
  const [customFrom, setCustomFrom]     = useState('')
  const [customTo, setCustomTo]         = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [agentFilter, setAgentFilter]   = useState('')
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [tooltip, setTooltip]           = useState<TooltipState>({ visible: false, x: 0, y: 0, text: '' })
  const [expandedClusters, setExpandedClusters] = useState<Set<number>>(new Set())
  const [showLegend, setShowLegend]     = useState(true)
  const [zoom, setZoom]                 = useState(1)
  const [pan, setPan]                   = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning]       = useState(false)
  const [panStart, setPanStart]         = useState({ x: 0, y: 0 })
  const [draggingNode, setDraggingNode] = useState<string | null>(null)
  const [nodePositions, setNodePositions] = useState<Map<string, { x: number; y: number }>>(new Map())
  const svgRef = useRef<SVGSVGElement>(null)

  const fromDate = useMemo(() => {
    if (timeRange === 'custom' && customFrom) return new Date(customFrom).toISOString()
    const d = new Date()
    if (timeRange === '1h')  d.setHours(d.getHours() - 1)
    else if (timeRange === '6h')  d.setHours(d.getHours() - 6)
    else if (timeRange === '24h') d.setHours(d.getHours() - 24)
    else if (timeRange === '7d')  d.setDate(d.getDate() - 7)
    return d.toISOString()
  }, [timeRange, customFrom])

  const toDate = useMemo(() => {
    if (timeRange === 'custom' && customTo) return new Date(customTo).toISOString()
    return new Date().toISOString()
  }, [timeRange, customTo])

  const { data, isLoading, refetch } = useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts-graph', timeRange, customFrom, customTo],
    queryFn: () => apiFetch<PaginatedResponse<Alert>>(
      `/api/v1/alerts?limit=80&from=${fromDate}&to=${toDate}`
    ),
  })

  const alerts = data?.data ?? []

  const { nodes: rawNodes, edges, nodeMap: rawNodeMap, clusters } = useMemo(
    () => buildGraph(alerts, severityFilter, agentFilter),
    [alerts, severityFilter, agentFilter]
  )

  // Merge overridden positions into nodes
  const nodes = useMemo(() => rawNodes.map(n => {
    const override = nodePositions.get(n.alert.id)
    if (override) return { ...n, pos: { ...n.pos, ...override } }
    return n
  }), [rawNodes, nodePositions])

  const nodeMap = useMemo(() => new Map(nodes.map(n => [n.alert.id, n])), [nodes])

  // ── SVG Export ─────────────────────────────────────────────────────────
  const handleExportSVG = useCallback(() => {
    const svgEl = svgRef.current
    if (!svgEl) return
    const serializer = new XMLSerializer()
    const svgString = serializer.serializeToString(svgEl)
    const blob = new Blob([svgString], { type: 'image/svg+xml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `alert-graph-${timeRange}-${new Date().toISOString().slice(0,10)}.svg`
    a.click()
    URL.revokeObjectURL(url)
  }, [timeRange])

  // ── Draggable nodes ─────────────────────────────────────────────────────
  const handleNodeMouseDown = useCallback((e: React.MouseEvent, alertId: string) => {
    e.stopPropagation()
    setDraggingNode(alertId)
  }, [])

  const handleSVGMouseMove = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    // Update tooltip
    if (tooltip.visible && !draggingNode) {
      const rect = svgRef.current?.getBoundingClientRect()
      if (rect) {
        setTooltip(prev => ({ ...prev, x: e.clientX - rect.left + 12, y: e.clientY - rect.top - 8 }))
      }
    }

    // Drag node
    if (draggingNode) {
      const rect = svgRef.current?.getBoundingClientRect()
      if (!rect) return
      const svgX = (e.clientX - rect.left - pan.x) / zoom
      const svgY = (e.clientY - rect.top - pan.y) / zoom
      setNodePositions(prev => {
        const next = new Map(prev)
        next.set(draggingNode, { x: svgX, y: svgY })
        return next
      })
    }

    // Pan
    if (isPanning) {
      const dx = e.clientX - panStart.x
      const dy = e.clientY - panStart.y
      setPan({ x: dx, y: dy })
    }
  }, [tooltip.visible, draggingNode, isPanning, panStart, pan, zoom])

  const handleSVGMouseUp = useCallback(() => {
    setDraggingNode(null)
    setIsPanning(false)
  }, [])

  const handleSVGMouseDown = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if (e.target === svgRef.current || (e.target as SVGElement).tagName === 'rect') {
      setIsPanning(true)
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y })
    }
  }, [pan])

  const handleMouseEnter = useCallback((e: React.MouseEvent, alert: Alert) => {
    if (draggingNode) return
    const rect = svgRef.current?.getBoundingClientRect()
    if (!rect) return
    setTooltip({
      visible: true,
      x: e.clientX - rect.left + 12,
      y: e.clientY - rect.top - 8,
      text: `${alert.title} · ${alert.agent_hostname}`,
    })
  }, [draggingNode])

  const handleMouseLeave = useCallback(() => {
    setTooltip(prev => ({ ...prev, visible: false }))
  }, [])

  const toggleCluster = useCallback((idx: number) => {
    setExpandedClusters(prev => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }, [])

  const resetView = useCallback(() => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
    setNodePositions(new Map())
  }, [])

  // ── Time range bar ──────────────────────────────────────────────────────
  const TIME_RANGES: { label: string; value: TimeRange }[] = [
    { label: '1h',  value: '1h' },
    { label: '6h',  value: '6h' },
    { label: '24h', value: '24h' },
    { label: '7d',  value: '7d' },
    { label: 'カスタム', value: 'custom' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <GitBranch className="w-6 h-6 text-falcon-red" />
          <div>
            <h1 className="text-2xl font-bold text-white">アラート相関グラフ</h1>
            <p className="text-sm text-falcon-muted">同一エンドポイント上のアラートをグラフで可視化</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportSVG}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-falcon-muted
                       bg-falcon-surface border border-falcon-border rounded-lg hover:bg-falcon-border transition-colors"
          >
            <Download className="w-4 h-4" />
            SVG エクスポート
          </button>
          <Link
            href="/alerts"
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-falcon-muted
                       bg-falcon-surface border border-falcon-border rounded-lg hover:bg-falcon-border transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            アラートへ戻る
          </Link>
        </div>
      </div>

      {/* ── Time Range Filter Bar ───────────────────────────────────── */}
      <div className="flex items-center gap-3 mb-4 p-3 bg-falcon-surface border border-falcon-border rounded-xl flex-wrap">
        <Calendar className="w-4 h-4 text-falcon-muted shrink-0" />
        <div className="flex rounded-lg border border-falcon-border overflow-hidden">
          {TIME_RANGES.map(r => (
            <button
              key={r.value}
              onClick={() => setTimeRange(r.value)}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                timeRange === r.value
                  ? 'bg-falcon-red text-white'
                  : 'bg-[#0a111e] text-falcon-muted hover:text-white hover:bg-falcon-border'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
        {timeRange === 'custom' && (
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-falcon-muted">From</span>
              <input
                type="datetime-local"
                value={customFrom}
                onChange={e => setCustomFrom(e.target.value)}
                className="text-xs border border-falcon-border rounded-lg px-2 py-1.5
                           bg-[#0a111e] text-falcon-text focus:outline-hidden focus:border-falcon-red"
              />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-falcon-muted">To</span>
              <input
                type="datetime-local"
                value={customTo}
                onChange={e => setCustomTo(e.target.value)}
                className="text-xs border border-falcon-border rounded-lg px-2 py-1.5
                           bg-[#0a111e] text-falcon-text focus:outline-hidden focus:border-falcon-red"
              />
            </div>
          </div>
        )}
        <div className="text-xs text-falcon-subtle ml-auto">
          {isLoading ? '読み込み中...' : `${alerts.length} アラート取得`}
        </div>
      </div>

      {/* ── Controls ───────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <Filter className="w-4 h-4 text-falcon-muted shrink-0" />
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          className="text-sm border border-falcon-border rounded-lg px-3 py-2
                     bg-falcon-surface text-falcon-muted focus:outline-hidden focus:border-falcon-red"
        >
          <option value="">重大度: すべて</option>
          <option value="critical">クリティカル</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>

        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
          <input
            value={agentFilter}
            onChange={e => setAgentFilter(e.target.value)}
            placeholder="エージェント名でフィルター..."
            className="pl-9 pr-4 py-2 text-sm border border-falcon-border rounded-lg
                       bg-falcon-surface text-white placeholder-falcon-subtle w-56
                       focus:outline-hidden focus:border-falcon-red"
          />
        </div>

        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-2 text-sm text-falcon-muted
                     bg-falcon-surface border border-falcon-border rounded-lg hover:bg-falcon-border transition-colors
                     disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          更新
        </button>

        {/* Zoom controls */}
        <div className="flex items-center gap-1 ml-auto">
          <button
            onClick={() => setZoom(z => Math.min(z + 0.2, 3))}
            className="p-1.5 text-falcon-muted bg-falcon-surface border border-falcon-border rounded-sm hover:bg-falcon-border transition-colors"
            title="ズームイン"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <span className="text-xs text-falcon-muted w-10 text-center">{Math.round(zoom * 100)}%</span>
          <button
            onClick={() => setZoom(z => Math.max(z - 0.2, 0.3))}
            className="p-1.5 text-falcon-muted bg-falcon-surface border border-falcon-border rounded-sm hover:bg-falcon-border transition-colors"
            title="ズームアウト"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={resetView}
            className="p-1.5 text-falcon-muted bg-falcon-surface border border-falcon-border rounded-sm hover:bg-falcon-border transition-colors"
            title="ビューをリセット"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowLegend(l => !l)}
            className={`px-2 py-1.5 text-xs border rounded transition-colors ${
              showLegend
                ? 'bg-falcon-border text-white border-falcon-subtle'
                : 'bg-falcon-surface text-falcon-muted border-falcon-border hover:bg-falcon-border'
            }`}
          >
            凡例
          </button>
        </div>
      </div>

      {/* ── Main layout ────────────────────────────────────────────── */}
      <div className="flex gap-4">

        {/* Graph area */}
        <div className="flex-1 min-w-0">

          {/* Stats bar */}
          <div className="flex items-center gap-6 px-4 py-2 mb-3 bg-falcon-surface border border-falcon-border rounded-lg">
            <div className="flex items-center gap-2">
              <span className="text-xs text-falcon-muted">ノード数</span>
              <span className="text-sm font-bold text-white">{nodes.length}</span>
            </div>
            <div className="w-px h-4 bg-falcon-border" />
            <div className="flex items-center gap-2">
              <span className="text-xs text-falcon-muted">エッジ数</span>
              <span className="text-sm font-bold text-white">{edges.length}</span>
            </div>
            <div className="w-px h-4 bg-falcon-border" />
            <div className="flex items-center gap-2">
              <span className="text-xs text-falcon-muted">クラスター数</span>
              <span className="text-sm font-bold text-white">{clusters.length}</span>
            </div>
            <div className="w-px h-4 bg-falcon-border" />
            <div className="flex items-center gap-2">
              <span className="text-xs text-falcon-muted">クリティカル</span>
              <span className="text-sm font-bold text-falcon-red">
                {nodes.filter(n => severityLabel(n.alert.severity) === 'critical').length}
              </span>
            </div>
            <div className="text-xs text-falcon-subtle ml-auto">ノードをドラッグして移動 · 背景をドラッグしてパン</div>
          </div>

          {/* SVG Graph */}
          <div className="relative bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden"
               style={{ height: 580 }}>
            {isLoading ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <RefreshCw className="w-8 h-8 text-falcon-subtle animate-spin mx-auto mb-2" />
                  <p className="text-sm text-falcon-muted">グラフを読み込み中...</p>
                </div>
              </div>
            ) : nodes.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <GitBranch className="w-10 h-10 text-falcon-subtle mx-auto mb-2" />
                  <p className="text-sm text-falcon-muted">表示するアラートがありません</p>
                  <p className="text-xs text-falcon-subtle mt-1">時間範囲やフィルターを変更してください</p>
                </div>
              </div>
            ) : (
              <svg
                ref={svgRef}
                width="100%"
                height="100%"
                viewBox={`0 0 ${SVG_W} ${SVG_H}`}
                onMouseMove={handleSVGMouseMove}
                onMouseDown={handleSVGMouseDown}
                onMouseUp={handleSVGMouseUp}
                onMouseLeave={handleSVGMouseUp}
                className={`block ${isPanning ? 'cursor-grabbing' : draggingNode ? 'cursor-move' : 'cursor-default'}`}
              >
                <defs>
                  <pattern id="smallGrid" width="20" height="20" patternUnits="userSpaceOnUse">
                    <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1e2d42" strokeWidth="0.5" opacity="0.4" />
                  </pattern>
                  {/* Arrow marker */}
                  <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L6,3 z" fill="#1e2d42" opacity="0.6" />
                  </marker>
                </defs>

                {/* Background grid */}
                <rect width={SVG_W} height={SVG_H} fill="url(#smallGrid)" />

                {/* Pan/zoom group */}
                <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>

                  {/* Edges */}
                  {edges.map((edge, i) => {
                    const src = nodeMap.get(edge.source)
                    const tgt = nodeMap.get(edge.target)
                    if (!src || !tgt) return null
                    return (
                      <line
                        key={i}
                        x1={src.pos.x}
                        y1={src.pos.y}
                        x2={tgt.pos.x}
                        y2={tgt.pos.y}
                        stroke="#2a3f5e"
                        strokeWidth="1.5"
                        strokeDasharray="5 4"
                        opacity="0.6"
                        markerEnd="url(#arrow)"
                      />
                    )
                  })}

                  {/* Nodes */}
                  {nodes.map(node => {
                    const sev = severityLabel(node.alert.severity)
                    const color = SEVERITY_COLOR[sev]
                    const r = SEVERITY_RADIUS[sev]
                    const isSelected = selectedAlert?.id === node.alert.id
                    const tactic = getTacticFromTechnique(node.alert.mitre_technique)
                    const tacticAbbr = tactic ? TACTIC_ABBREV[tactic] : null
                    const tacticColor = tactic ? TACTIC_COLORS[tactic] : null

                    return (
                      <g
                        key={node.alert.id}
                        onClick={() => !draggingNode && setSelectedAlert(node.alert)}
                        onMouseEnter={e => handleMouseEnter(e, node.alert)}
                        onMouseLeave={handleMouseLeave}
                        onMouseDown={e => handleNodeMouseDown(e, node.alert.id)}
                        className="cursor-pointer"
                      >
                        {/* Cluster glow ring */}
                        {isSelected && (
                          <circle
                            cx={node.pos.x}
                            cy={node.pos.y}
                            r={r + 8}
                            fill="none"
                            stroke={color}
                            strokeWidth="2"
                            opacity="0.35"
                          />
                        )}

                        {/* Pulse ring for critical */}
                        {sev === 'critical' && !isSelected && (
                          <circle
                            cx={node.pos.x}
                            cy={node.pos.y}
                            r={r + 5}
                            fill="none"
                            stroke={color}
                            strokeWidth="1"
                            opacity="0.25"
                          />
                        )}

                        {/* Main circle */}
                        <circle
                          cx={node.pos.x}
                          cy={node.pos.y}
                          r={r}
                          fill={color}
                          fillOpacity={isSelected ? 1 : 0.78}
                          stroke={isSelected ? 'white' : color}
                          strokeWidth={isSelected ? 2.5 : 1}
                        />

                        {/* Severity letter inside */}
                        {r >= 13 && (
                          <text
                            x={node.pos.x}
                            y={node.pos.y}
                            textAnchor="middle"
                            dominantBaseline="central"
                            fontSize={r * 0.65}
                            fill="white"
                            fontWeight="bold"
                            pointerEvents="none"
                          >
                            {sev[0].toUpperCase()}
                          </text>
                        )}

                        {/* MITRE tactic badge */}
                        {tacticAbbr && tacticColor && (
                          <g pointerEvents="none">
                            <rect
                              x={node.pos.x + r * 0.55}
                              y={node.pos.y - r - 9}
                              width={18}
                              height={11}
                              rx={3}
                              fill={tacticColor}
                              opacity={0.9}
                            />
                            <text
                              x={node.pos.x + r * 0.55 + 9}
                              y={node.pos.y - r - 3}
                              textAnchor="middle"
                              dominantBaseline="central"
                              fontSize={7}
                              fill="white"
                              fontWeight="bold"
                            >
                              {tacticAbbr}
                            </text>
                          </g>
                        )}
                      </g>
                    )
                  })}
                </g>
              </svg>
            )}

            {/* Tooltip */}
            {tooltip.visible && (
              <div
                className="absolute z-20 pointer-events-none px-2.5 py-1.5 text-xs text-white
                           bg-falcon-raised border border-falcon-border rounded-lg shadow-xl max-w-[300px]"
                style={{ left: tooltip.x, top: tooltip.y }}
              >
                {tooltip.text}
              </div>
            )}

            {/* Legend Panel */}
            {showLegend && (
              <div className="absolute bottom-3 left-3 bg-falcon-surface/90 border border-falcon-border rounded-xl p-3 backdrop-blur-xs">
                <p className="text-[10px] font-bold text-falcon-muted uppercase tracking-wider mb-2">凡例</p>

                {/* Severity */}
                <p className="text-[9px] text-falcon-subtle mb-1.5 uppercase">重大度 (サイズ)</p>
                <div className="space-y-1 mb-3">
                  {Object.entries(SEVERITY_COLOR).map(([sev, color]) => (
                    <div key={sev} className="flex items-center gap-2">
                      <div
                        className="rounded-full shrink-0"
                        style={{
                          width:  SEVERITY_RADIUS[sev] * 1.2,
                          height: SEVERITY_RADIUS[sev] * 1.2,
                          background: color,
                          opacity: 0.85,
                        }}
                      />
                      <span className="text-[10px] text-falcon-muted">{SEVERITY_LABEL_JP[sev]}</span>
                    </div>
                  ))}
                </div>

                {/* MITRE tactic samples */}
                <p className="text-[9px] text-falcon-subtle mb-1.5 uppercase">MITRE タクティク (バッジ)</p>
                <div className="space-y-1">
                  {[
                    ['IA', 'initial-access', 'Initial Access'],
                    ['EX', 'execution', 'Execution'],
                    ['C2', 'command-and-control', 'C2'],
                    ['LM', 'lateral-movement', 'Lateral Move'],
                  ].map(([abbr, tactic, label]) => (
                    <div key={tactic} className="flex items-center gap-2">
                      <span
                        className="text-[8px] font-bold px-1 py-0.5 rounded-sm shrink-0"
                        style={{ background: TACTIC_COLORS[tactic], color: 'white', minWidth: 18, textAlign: 'center' }}
                      >
                        {abbr}
                      </span>
                      <span className="text-[10px] text-falcon-muted">{label}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Cluster list (expandable) */}
          {clusters.length > 0 && (
            <div className="mt-4">
              <h2 className="text-sm font-semibold text-falcon-muted mb-2 uppercase tracking-wide flex items-center gap-2">
                クラスター一覧
                <span className="text-xs bg-falcon-border text-falcon-muted px-1.5 py-0.5 rounded-sm">{clusters.length}</span>
                <span className="text-xs text-falcon-subtle font-normal normal-case">クリックして展開</span>
              </h2>
              <div className="grid grid-cols-2 gap-2">
                {clusters.map((clusterAlerts, ci) => {
                  const agentId   = clusterAlerts[0]?.agent_id
                  const hostname  = clusterAlerts[0]?.agent_hostname
                  const maxSev    = clusterAlerts.reduce((m, a) => Math.max(m, a.severity), 0)
                  const sevKey    = severityLabel(maxSev)
                  const isExpanded = expandedClusters.has(ci)
                  return (
                    <div
                      key={ci}
                      className="bg-falcon-surface border border-falcon-border rounded-lg hover:border-falcon-muted/40 transition-colors"
                    >
                      {/* Cluster header */}
                      <button
                        className="w-full flex items-center justify-between p-3 text-left"
                        onClick={() => toggleCluster(ci)}
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs font-medium text-white truncate">{hostname || agentId || '不明'}</span>
                          <span
                            className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm shrink-0"
                            style={{
                              background: SEVERITY_COLOR[sevKey] + '30',
                              color: SEVERITY_COLOR[sevKey],
                            }}
                          >
                            {sevKey}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span className="text-xs text-falcon-muted">{clusterAlerts.length}</span>
                          <span className="text-xs text-falcon-subtle">{isExpanded ? '▲' : '▼'}</span>
                        </div>
                      </button>

                      {/* Expanded: individual alerts */}
                      {isExpanded && (
                        <div className="border-t border-falcon-border px-3 pb-3 space-y-1.5">
                          {clusterAlerts.map(alert => {
                            const sev = severityLabel(alert.severity)
                            return (
                              <button
                                key={alert.id}
                                onClick={() => setSelectedAlert(alert)}
                                className="w-full flex items-center gap-2 py-1.5 px-2 rounded
                                           hover:bg-falcon-border transition-colors text-left group"
                              >
                                <div
                                  className="w-2 h-2 rounded-full shrink-0"
                                  style={{ background: SEVERITY_COLOR[sev] }}
                                />
                                <span className="text-xs text-falcon-muted group-hover:text-white truncate transition-colors">
                                  {alert.title}
                                </span>
                              </button>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>

        {/* ── Alert detail panel ─────────────────────────────────── */}
        <div className="w-72 shrink-0">
          {selectedAlert ? (
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4 space-y-4 sticky top-4">
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-sm font-semibold text-white leading-snug">{selectedAlert.title}</h3>
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="text-falcon-muted hover:text-white transition-colors shrink-0 text-lg leading-none"
                >
                  ×
                </button>
              </div>

              {/* Severity badge */}
              <div className="flex items-center gap-2 flex-wrap">
                {(() => {
                  const sev = severityLabel(selectedAlert.severity)
                  return (
                    <span
                      className="text-xs font-bold px-2 py-0.5 rounded-sm"
                      style={{
                        background: SEVERITY_COLOR[sev] + '30',
                        color: SEVERITY_COLOR[sev],
                      }}
                    >
                      {SEVERITY_LABEL_JP[sev]} ({selectedAlert.severity})
                    </span>
                  )
                })()}
                <span className={`text-xs px-2 py-0.5 rounded border ${
                  selectedAlert.status === 'open'
                    ? 'bg-red-900/30 text-red-300 border-red-700/50'
                    : selectedAlert.status === 'investigating'
                    ? 'bg-yellow-900/30 text-yellow-300 border-yellow-700/50'
                    : 'bg-green-900/30 text-green-300 border-green-700/50'
                }`}>
                  {selectedAlert.status === 'open' ? '未対応'
                    : selectedAlert.status === 'investigating' ? '調査中'
                    : selectedAlert.status === 'resolved' ? '解決済み'
                    : selectedAlert.status}
                </span>
              </div>

              {/* MITRE tactic badge */}
              {selectedAlert.mitre_technique && (
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs text-falcon-muted">MITRE:</span>
                  <span className="text-xs font-mono bg-purple-900/30 text-purple-300 border border-purple-700/30 px-2 py-0.5 rounded-sm">
                    {selectedAlert.mitre_technique}
                  </span>
                </div>
              )}
              {selectedAlert.ai_mitre_tags && selectedAlert.ai_mitre_tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {selectedAlert.ai_mitre_tags.slice(0, 4).map(tag => (
                    <span key={tag} className="text-[10px] bg-falcon-raised border border-falcon-border text-falcon-muted px-1.5 py-0.5 rounded-sm">
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              {/* Details */}
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-falcon-muted">エンドポイント</span>
                  <span className="text-white font-medium">{selectedAlert.agent_hostname}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-falcon-muted">OS</span>
                  <span className="text-white">{selectedAlert.agent_os}</span>
                </div>
                {selectedAlert.rule_name && (
                  <div className="flex justify-between text-xs">
                    <span className="text-falcon-muted">ルール</span>
                    <span className="text-white truncate max-w-[140px]">{selectedAlert.rule_name}</span>
                  </div>
                )}
                {selectedAlert.assigned_to_name && (
                  <div className="flex justify-between text-xs">
                    <span className="text-falcon-muted">担当者</span>
                    <span className="text-white">{selectedAlert.assigned_to_name}</span>
                  </div>
                )}
                <div className="flex justify-between text-xs">
                  <span className="text-falcon-muted">作成日時</span>
                  <span className="text-white">
                    {new Date(selectedAlert.created_at).toLocaleString('ja-JP', {
                      month: '2-digit', day: '2-digit',
                      hour: '2-digit', minute: '2-digit',
                    })}
                  </span>
                </div>
              </div>

              {selectedAlert.description && (
                <p className="text-xs text-falcon-muted leading-relaxed border-t border-falcon-border pt-3">
                  {selectedAlert.description.slice(0, 200)}
                  {selectedAlert.description.length > 200 ? '...' : ''}
                </p>
              )}

              <Link
                href={`/alerts/${selectedAlert.id}`}
                className="block w-full text-center py-2 text-xs font-medium text-white
                           bg-falcon-red rounded-lg hover:bg-[#c8001e] transition-colors"
              >
                アラート詳細を見る →
              </Link>
            </div>
          ) : (
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6 text-center">
              <GitBranch className="w-8 h-8 text-falcon-subtle mx-auto mb-2" />
              <p className="text-sm text-falcon-muted">ノードをクリックして</p>
              <p className="text-sm text-falcon-muted">詳細を表示</p>
              <div className="mt-4 text-left space-y-2 border-t border-falcon-border pt-4">
                <p className="text-xs text-falcon-subtle font-semibold uppercase tracking-wide">操作方法</p>
                <p className="text-xs text-falcon-subtle">• ノードをクリック → 詳細表示</p>
                <p className="text-xs text-falcon-subtle">• ノードをドラッグ → 移動</p>
                <p className="text-xs text-falcon-subtle">• 背景をドラッグ → パン</p>
                <p className="text-xs text-falcon-subtle">• ±ボタン → ズーム</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
