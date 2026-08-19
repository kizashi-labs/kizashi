'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GitBranch, Search, RefreshCw, Activity, Monitor,
  FileText, Network, User, AlertTriangle, Server, Zap
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

const NODE_COLORS: Record<string, string> = {
  process: 'bg-blue-500 border-blue-400',
  file: 'bg-green-500 border-green-400',
  network: 'bg-purple-500 border-purple-400',
  user: 'bg-yellow-500 border-yellow-400',
  alert: 'bg-red-500 border-red-400',
  agent: 'bg-cyan-500 border-cyan-400',
}

const NODE_LABELS: Record<string, string> = {
  process: 'プロセス',
  file: 'ファイル',
  network: 'ネットワーク',
  user: 'ユーザー',
  alert: 'アラート',
  agent: 'エージェント',
}

const NODE_ICONS: Record<string, React.ReactNode> = {
  process: <Activity className="w-3 h-3" />,
  file: <FileText className="w-3 h-3" />,
  network: <Network className="w-3 h-3" />,
  user: <User className="w-3 h-3" />,
  alert: <AlertTriangle className="w-3 h-3" />,
  agent: <Server className="w-3 h-3" />,
}

// Compute a simple force-directed-like layout for nodes (static, CSS-based)
function computeLayout(nodes: any[], edges: any[]) {
  const positions: Record<string, { x: number; y: number }> = {}
  const centerX = 400
  const centerY = 300
  const radius = 200

  nodes.forEach((node, i) => {
    const angle = (i / nodes.length) * 2 * Math.PI
    positions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    }
  })

  // Put root/agent at center
  const rootNode = nodes.find(n => n.type === 'agent' || n.id.includes('pid:1234'))
  if (rootNode) {
    positions[rootNode.id] = { x: centerX, y: centerY }
    const others = nodes.filter(n => n.id !== rootNode.id)
    others.forEach((node, i) => {
      const angle = (i / others.length) * 2 * Math.PI
      positions[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      }
    })
  }

  return positions
}

function GraphVisualization({ graph }: { graph: { root_id: string; max_depth: number; nodes: any[]; edges: any[] } }) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  const positions = computeLayout(graph.nodes, graph.edges)
  const svgWidth = 800
  const svgHeight = 600

  const EDGE_COLORS: Record<string, string> = {
    spawned: '#60a5fa',
    accessed: '#34d399',
    connected: '#a78bfa',
    modified: '#fb923c',
    dns_resolved: '#f472b6',
    triggered: '#f87171',
    loaded: '#facc15',
  }

  return (
    <div className="relative bg-gray-900 rounded-xl overflow-hidden border border-gray-700" style={{ height: 600 }}>
      <svg width="100%" height="100%" viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="absolute inset-0">
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#4b5563" />
          </marker>
        </defs>

        {/* Edges */}
        {graph.edges.map(edge => {
          const sp = positions[edge.source]
          const tp = positions[edge.target]
          if (!sp || !tp) return null
          const color = EDGE_COLORS[edge.type] || '#4b5563'
          return (
            <g key={edge.id}>
              <line
                x1={sp.x} y1={sp.y} x2={tp.x} y2={tp.y}
                stroke={color}
                strokeWidth={1.5}
                strokeOpacity={0.5}
                markerEnd="url(#arrowhead)"
              />
              <text
                x={(sp.x + tp.x) / 2}
                y={(sp.y + tp.y) / 2 - 4}
                fill={color}
                fontSize={9}
                textAnchor="middle"
                opacity={0.7}
              >
                {edge.type}
              </text>
            </g>
          )
        })}

        {/* Nodes */}
        {graph.nodes.map(node => {
          const pos = positions[node.id]
          if (!pos) return null
          const isSelected = selectedNode === node.id
          const colors: Record<string, string> = {
            process: '#3b82f6',
            file: '#22c55e',
            network: '#a855f7',
            user: '#eab308',
            alert: '#ef4444',
            agent: '#06b6d4',
          }
          const fillColor = colors[node.type] || '#6b7280'
          return (
            <g
              key={node.id}
              transform={`translate(${pos.x}, ${pos.y})`}
              className="cursor-pointer"
              onClick={() => setSelectedNode(isSelected ? null : node.id)}
            >
              <circle
                r={isSelected ? 22 : 18}
                fill={fillColor}
                fillOpacity={0.2}
                stroke={fillColor}
                strokeWidth={isSelected ? 2.5 : 1.5}
              />
              {node.risk_score >= 70 && (
                <circle r={22} fill="none" stroke="#ef4444" strokeWidth={1} strokeDasharray="3 2" opacity={0.6} />
              )}
              <text textAnchor="middle" y={4} fontSize={9} fill="white" fontWeight="bold">
                {node.label.length > 14 ? node.label.slice(0, 14) + '…' : node.label}
              </text>
              <text textAnchor="middle" y={30} fontSize={8} fill="#9ca3af">
                {node.type}
              </text>
            </g>
          )
        })}
      </svg>

      {/* Node detail panel */}
      {selectedNode && (() => {
        const node = graph.nodes.find(n => n.id === selectedNode)
        if (!node) return null
        return (
          <div className="absolute top-4 right-4 bg-gray-800 rounded-lg p-4 border border-gray-600 w-64 shadow-xl">
            <div className="flex items-center gap-2 mb-3">
              <div className={`p-1.5 rounded-lg ${NODE_COLORS[node.type] || 'bg-gray-600'}`}>
                {NODE_ICONS[node.type]}
              </div>
              <div>
                <div className="text-sm font-semibold text-white truncate">{node.label}</div>
                <div className="text-xs text-gray-400">{node.type}</div>
              </div>
            </div>
            {node.risk_score > 0 && (
              <div className="mb-2">
                <span className="text-xs text-gray-400">リスクスコア: </span>
                <span className={`text-xs font-bold ${node.risk_score >= 70 ? 'text-red-400' : 'text-yellow-400'}`}>
                  {node.risk_score}
                </span>
              </div>
            )}
            <div className="space-y-1">
              {Object.entries(node.properties || {}).map(([k, v]) => (
                <div key={k} className="flex gap-1 text-xs">
                  <span className="text-gray-500 shrink-0">{k}:</span>
                  <span className="text-gray-300 truncate">{String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )
      })()}

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-gray-800/90 rounded-lg p-3 border border-gray-700">
        <div className="text-xs text-gray-400 mb-2 font-medium">ノードタイプ</div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-1.5">
              <div className={`w-2.5 h-2.5 rounded-full ${color.split(' ')[0]}`} />
              <span className="text-xs text-gray-400">{NODE_LABELS[type] ?? type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function ThreatGraphPage() {
  const queryClient = useQueryClient()
  const [searchQuery, setSearchQuery] = useState('')
  const [rootNodeId, setRootNodeId] = useState('')
  const [depth, setDepth] = useState(3)

  const EMPTY_STATS = { process: 0, file: 0, network: 0, agent: 0, alert: 0, total_nodes: 0, total_edges: 0 }
  const EMPTY_SUBGRAPH = { root_id: '', max_depth: 0, nodes: [], edges: [] }

  const { data: stats = EMPTY_STATS } = useQuery({
    queryKey: ['threat-graph-stats'],
    queryFn: () => apiFetch('/api/v1/admin/threat-graph/stats'),
    refetchInterval: 60000,
  })

  const { data: graphData = EMPTY_SUBGRAPH, isLoading } = useQuery({
    queryKey: ['threat-graph-subgraph', rootNodeId, depth],
    queryFn: () =>
      rootNodeId
        ? apiFetch(`/api/v1/admin/threat-graph/subgraph?root_id=${encodeURIComponent(rootNodeId)}&depth=${depth}`)
        : Promise.resolve(EMPTY_SUBGRAPH),
  })

  const buildMutation = useMutation({
    mutationFn: () => apiFetch('/api/v1/admin/threat-graph/build', { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['threat-graph-stats'] }),
  })

  const s = (stats || EMPTY_STATS) as typeof EMPTY_STATS
  const graph = (graphData || EMPTY_SUBGRAPH) as typeof EMPTY_SUBGRAPH

  const statCards = [
    { label: 'プロセスノード', value: s.process || 0, color: 'text-blue-400' },
    { label: 'ファイルノード', value: s.file || 0, color: 'text-green-400' },
    { label: 'ネットワークノード', value: s.network || 0, color: 'text-purple-400' },
    { label: '総ノード数', value: s.total_nodes || 0, color: 'text-white' },
    { label: '総エッジ数', value: s.total_edges || 0, color: 'text-cyan-400' },
  ]

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <GitBranch className="w-7 h-7 text-cyan-400" />
            脅威グラフ
          </h1>
          <p className="text-gray-400 text-sm mt-1">プロセス・ファイル・ネットワーク接続の関係グラフ可視化</p>
        </div>
        <button
          onClick={() => buildMutation.mutate()}
          disabled={buildMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${buildMutation.isPending ? 'animate-spin' : ''}`} />
          グラフ再構築
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {statCards.map((card) => (
          <div key={card.label} className="bg-gray-800 rounded-xl p-3 border border-gray-700 text-center">
            <div className={`text-xl font-bold ${card.color}`}>{(card.value ?? 0).toLocaleString()}</div>
            <div className="text-xs text-gray-400 mt-0.5">{card.label}</div>
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="bg-gray-800 rounded-xl p-4 border border-gray-700 flex flex-wrap gap-3 items-end">
        <div className="flex-1 min-w-48">
          <label className="text-xs text-gray-400 mb-1 block">ルートノードID</label>
          <input
            value={rootNodeId}
            onChange={(e) => setRootNodeId(e.target.value)}
            className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-cyan-500"
            placeholder="process:agent-id:pid:1234"
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">深度</label>
          <select
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
            className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-cyan-500"
          >
            {[1, 2, 3, 4, 5, 6].map(d => <option key={d} value={d}>{d}</option>)}
          </select>
        </div>
        <button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['threat-graph-subgraph'] })}
          className="flex items-center gap-1.5 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors"
        >
          <Search className="w-4 h-4" />
          検索
        </button>
      </div>

      {/* Graph */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-300">
            {graph.nodes.length} ノード / {graph.edges.length} エッジ (深度 {graph.max_depth})
          </h2>
          <div className="flex items-center gap-1.5 text-xs text-gray-500">
            <Zap className="w-3.5 h-3.5" />
            ノードをクリックして詳細を表示
          </div>
        </div>
        {isLoading ? (
          <div className="bg-gray-800 rounded-xl border border-gray-700 flex items-center justify-center h-96">
            <RefreshCw className="w-8 h-8 text-gray-500 animate-spin" />
          </div>
        ) : (
          <GraphVisualization graph={graph} />
        )}
      </div>
    </div>
  )
}
