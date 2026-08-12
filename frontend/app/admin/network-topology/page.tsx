'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Plus, X, Network, Activity, ChevronRight } from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

type NodeType = 'endpoint' | 'server' | 'router' | 'firewall' | 'cloud' | 'switch'
type Criticality = 'critical' | 'high' | 'medium' | 'low'

interface TopologyNode {
  id: string
  name: string
  type: NodeType
  ip_addresses: string[]
  criticality: Criticality
  os: string
  department: string
  connection_count: number
}

interface TopologyEdge {
  id: string
  source_id: string
  source_name: string
  target_id: string
  target_name: string
  protocol: string
  port: number
  bytes_transferred: number
}

interface TopologyStats {
  total_nodes: number
  endpoints: number
  servers: number
  critical_nodes: number
  total_edges: number
}

interface TopologyData {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

interface AddNodeForm {
  name: string
  type: NodeType
  ip_address: string
  os: string
  department: string
  criticality: Criticality
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const NODE_ICONS: Record<NodeType, string> = {
  endpoint: '💻',
  server: '🖥️',
  router: '🔀',
  firewall: '🛡️',
  cloud: '☁️',
  switch: '🔌',
}

const CRITICALITY_BORDER: Record<Criticality, string> = {
  critical: 'border-red-500',
  high: 'border-orange-500',
  medium: 'border-yellow-500',
  low: 'border-blue-500',
}

const CRITICALITY_BADGE: Record<Criticality, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} B`
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function NetworkTopologyPage() {
  const queryClient = useQueryClient()
  const [selectedNodeType, setSelectedNodeType] = useState<NodeType | 'all'>('all')
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [addForm, setAddForm] = useState<AddNodeForm>({
    name: '', type: 'endpoint', ip_address: '', os: '', department: '', criticality: 'low',
  })

  // ── Queries ──────────────────────────────────────────────────────────────────

  const { data: stats, isLoading: statsLoading } = useQuery<TopologyStats>({
    queryKey: ['network-topology-stats'],
    queryFn: () => apiFetch<TopologyStats>('/api/v1/admin/network-topology/stats').catch(() => ({ total_nodes: 0, endpoints: 0, servers: 0, critical_nodes: 0, total_edges: 0 })),
  })

  const { data: topology, isLoading: topoLoading } = useQuery<TopologyData>({
    queryKey: ['network-topology'],
    queryFn: () => apiFetch<TopologyData>('/api/v1/admin/network-topology').catch(() => ({ nodes: [], edges: [] })),
  })

  const addNodeMutation = useMutation({
    mutationFn: (data: AddNodeForm) =>
      apiFetch('/api/v1/admin/network-topology/nodes', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['network-topology'] })
      queryClient.invalidateQueries({ queryKey: ['network-topology-stats'] })
      setShowAddModal(false)
      setAddForm({ name: '', type: 'endpoint', ip_address: '', os: '', department: '', criticality: 'low' })
    },
  })

  // ── Derived Data ─────────────────────────────────────────────────────────────

  const filteredNodes = (topology?.nodes ?? []).filter(
    (n) => selectedNodeType === 'all' || n.type === selectedNodeType,
  )

  const selectedNodeEdges = selectedNode
    ? (topology?.edges ?? []).filter(
        (e) => e.source_id === selectedNode.id || e.target_id === selectedNode.id,
      )
    : []

  const nodeTypeFilters: Array<NodeType | 'all'> = ['all', 'endpoint', 'server', 'router', 'firewall', 'cloud']

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Network className="w-7 h-7 text-[#e8002d]" />
              Network Topology
            </h1>
            <p className="text-[#7d92b0] text-sm mt-0.5">Visual map of your network infrastructure</p>
          </div>
          <div className="flex gap-2 ml-2">
            <span className="px-3 py-1 rounded-full bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-sm">
              {statsLoading ? '…' : stats?.total_nodes} nodes
            </span>
            <span className="px-3 py-1 rounded-full bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-sm">
              {statsLoading ? '…' : stats?.total_edges} edges
            </span>
          </div>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> Add Node
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {[
          { label: 'Total Nodes', value: stats?.total_nodes ?? 0, color: 'text-white' },
          { label: 'Endpoints', value: stats?.endpoints ?? 0, color: 'text-blue-400' },
          { label: 'Servers', value: stats?.servers ?? 0, color: 'text-purple-400' },
          { label: 'Critical Nodes', value: stats?.critical_nodes ?? 0, color: 'text-red-400' },
          { label: 'Total Connections', value: stats?.total_edges ?? 0, color: 'text-green-400' },
        ].map((s) => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <p className="text-[#7d92b0] text-xs mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{statsLoading ? '…' : s.value}</p>
          </div>
        ))}
      </div>

      {/* Main Content */}
      <div className="flex gap-6">
        {/* Left: Node Grid */}
        <div className="flex-1 min-w-0">
          {/* Filter Bar */}
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-[#7d92b0]" />
            <span className="text-[#7d92b0] text-sm">Filter:</span>
            {nodeTypeFilters.map((type) => (
              <button
                key={type}
                onClick={() => setSelectedNodeType(type)}
                className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors border ${
                  selectedNodeType === type
                    ? 'bg-[#e8002d] border-[#e8002d] text-white'
                    : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0] hover:border-[#e8002d] hover:text-white'
                }`}
              >
                {type !== 'all' && <span className="mr-1">{NODE_ICONS[type as NodeType]}</span>}
                {type}
              </button>
            ))}
          </div>

          {/* Node Cards Grid */}
          {topoLoading ? (
            <div className="grid grid-cols-4 gap-3">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 animate-pulse h-40" />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-4 gap-3">
              {filteredNodes.map((node) => (
                <button
                  key={node.id}
                  onClick={() => setSelectedNode(selectedNode?.id === node.id ? null : node)}
                  className={`bg-[#0d1220] border-2 ${CRITICALITY_BORDER[node.criticality]} rounded-xl p-4 text-left hover:bg-[#111827] transition-all ${
                    selectedNode?.id === node.id ? 'ring-2 ring-[#e8002d]' : ''
                  }`}
                >
                  <div className="text-2xl mb-2">{NODE_ICONS[node.type]}</div>
                  <p className="text-white text-sm font-semibold truncate mb-1">{node.name}</p>
                  <div className="space-y-0.5 mb-2">
                    {node.ip_addresses.map((ip) => (
                      <p key={ip} className="text-[#7d92b0] text-xs font-mono">{ip}</p>
                    ))}
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={`px-1.5 py-0.5 rounded text-xs font-medium capitalize ${CRITICALITY_BADGE[node.criticality]}`}>
                      {node.criticality}
                    </span>
                  </div>
                  <p className="text-[#7d92b0] text-xs mt-1 truncate">{node.os}</p>
                  <p className="text-[#7d92b0] text-xs truncate">{node.department}</p>
                </button>
              ))}
            </div>
          )}

          {/* Connections Table */}
          <div className="mt-6 bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-[#1e2d42]">
              <h2 className="text-white font-semibold text-sm">All Connections</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['Source', '', 'Target', 'Protocol', 'Port', 'Bytes Transferred'].map((h) => (
                      <th key={h} className="text-left text-[#7d92b0] font-medium px-4 py-2 text-xs">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(topology?.edges ?? []).map((edge) => (
                    <tr key={edge.id} className="border-b border-[#1e2d42] last:border-0 hover:bg-[#111827]">
                      <td className="px-4 py-2.5 text-white font-mono text-xs">{edge.source_name}</td>
                      <td className="px-2 py-2.5 text-[#7d92b0]"><ChevronRight className="w-4 h-4" /></td>
                      <td className="px-4 py-2.5 text-white font-mono text-xs">{edge.target_name}</td>
                      <td className="px-4 py-2.5">
                        <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 text-xs">{edge.protocol}</span>
                      </td>
                      <td className="px-4 py-2.5 text-[#7d92b0] text-xs">{edge.port}</td>
                      <td className="px-4 py-2.5 text-[#7d92b0] text-xs">{formatBytes(edge.bytes_transferred)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right: Node Detail Panel */}
        {selectedNode && (
          <div className="w-72 shrink-0">
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 sticky top-6">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-white font-semibold text-sm">Node Details</h2>
                <button onClick={() => setSelectedNode(null)} className="text-[#7d92b0] hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="text-3xl mb-2">{NODE_ICONS[selectedNode.type]}</div>
              <p className="text-white font-bold mb-1">{selectedNode.name}</p>
              <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium capitalize mb-3 ${CRITICALITY_BADGE[selectedNode.criticality]}`}>
                {selectedNode.criticality}
              </span>

              <div className="space-y-2 mb-4">
                <div>
                  <p className="text-[#7d92b0] text-xs">Type</p>
                  <p className="text-white text-sm capitalize">{selectedNode.type}</p>
                </div>
                <div>
                  <p className="text-[#7d92b0] text-xs">IP Addresses</p>
                  {selectedNode.ip_addresses.map((ip) => (
                    <p key={ip} className="text-white text-sm font-mono">{ip}</p>
                  ))}
                </div>
                <div>
                  <p className="text-[#7d92b0] text-xs">OS</p>
                  <p className="text-white text-sm">{selectedNode.os}</p>
                </div>
                <div>
                  <p className="text-[#7d92b0] text-xs">Department</p>
                  <p className="text-white text-sm">{selectedNode.department}</p>
                </div>
              </div>

              <div className="border-t border-[#1e2d42] pt-3">
                <p className="text-[#7d92b0] text-xs font-medium mb-2">Connected via</p>
                {selectedNodeEdges.length === 0 ? (
                  <p className="text-[#7d92b0] text-xs">No connections</p>
                ) : (
                  <div className="space-y-2">
                    {selectedNodeEdges.map((edge) => {
                      const peer = edge.source_id === selectedNode.id ? edge.target_name : edge.source_name
                      const direction = edge.source_id === selectedNode.id ? 'OUT →' : '← IN'
                      return (
                        <div key={edge.id} className="bg-[#0a1020] rounded-lg p-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[#7d92b0] text-xs">{direction}</span>
                            <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 text-xs">{edge.protocol}</span>
                          </div>
                          <p className="text-white text-xs font-mono truncate">{peer}</p>
                          <p className="text-[#7d92b0] text-xs">:{edge.port} · {formatBytes(edge.bytes_transferred)}</p>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Add Node Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-2xl w-full max-w-md">
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
              <h2 className="text-white font-semibold">Add Network Node</h2>
              <button onClick={() => setShowAddModal(false)} className="text-[#7d92b0] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="px-6 py-4 space-y-4">
              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">Name</label>
                <input
                  value={addForm.name}
                  onChange={(e) => setAddForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. SRV-APP-01"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[#7d92b0] text-xs mb-1">Type</label>
                  <select
                    value={addForm.type}
                    onChange={(e) => setAddForm((f) => ({ ...f, type: e.target.value as NodeType }))}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                  >
                    {(['endpoint', 'server', 'router', 'firewall', 'cloud', 'switch'] as NodeType[]).map((t) => (
                      <option key={t} value={t}>{NODE_ICONS[t]} {t}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-[#7d92b0] text-xs mb-1">Criticality</label>
                  <select
                    value={addForm.criticality}
                    onChange={(e) => setAddForm((f) => ({ ...f, criticality: e.target.value as Criticality }))}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                  >
                    {(['critical', 'high', 'medium', 'low'] as Criticality[]).map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">IP Address</label>
                <input
                  value={addForm.ip_address}
                  onChange={(e) => setAddForm((f) => ({ ...f, ip_address: e.target.value }))}
                  placeholder="e.g. 10.0.1.50"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm font-mono focus:outline-none focus:border-[#e8002d]"
                />
              </div>
              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">OS</label>
                <input
                  value={addForm.os}
                  onChange={(e) => setAddForm((f) => ({ ...f, os: e.target.value }))}
                  placeholder="e.g. Windows 11"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                />
              </div>
              <div>
                <label className="block text-[#7d92b0] text-xs mb-1">Department</label>
                <input
                  value={addForm.department}
                  onChange={(e) => setAddForm((f) => ({ ...f, department: e.target.value }))}
                  placeholder="e.g. Engineering"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                />
              </div>
            </div>
            <div className="px-6 py-4 border-t border-[#1e2d42] flex gap-3 justify-end">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => addNodeMutation.mutate(addForm)}
                disabled={!addForm.name || !addForm.ip_address || addNodeMutation.isPending}
                className="px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
              >
                {addNodeMutation.isPending ? 'Adding…' : 'Add Node'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
