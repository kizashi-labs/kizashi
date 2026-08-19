'use client'

import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  GitBranch, AlertTriangle, CheckCircle, Search, Download,
  ChevronRight, ChevronDown, RefreshCw, Filter, Monitor,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os: string
  status: string
}

interface ProcessNode {
  pid: number
  ppid: number
  name: string
  cmdline: string
  suspicious: boolean
  children?: ProcessNode[]
}

function countNodes(nodes: ProcessNode[]): number {
  let count = 0
  for (const n of nodes) {
    count += 1 + countNodes(n.children ?? [])
  }
  return count
}

function countSuspicious(nodes: ProcessNode[]): number {
  let count = 0
  for (const n of nodes) {
    if (n.suspicious) count++
    count += countSuspicious(n.children ?? [])
  }
  return count
}

function maxDepth(nodes: ProcessNode[], depth = 0): number {
  if (nodes.length === 0) return depth
  return Math.max(...nodes.map(n => maxDepth(n.children ?? [], depth + 1)))
}

function flattenTree(nodes: ProcessNode[], result: ProcessNode[] = []): ProcessNode[] {
  for (const n of nodes) {
    result.push(n)
    flattenTree(n.children ?? [], result)
  }
  return result
}

// ─── Tree Node Component ───────────────────────────────────────────────────────

interface TreeNodeProps {
  node: ProcessNode
  depth: number
  isLast: boolean
  collapsed: Set<number>
  onToggle: (pid: number) => void
  search: string
  suspiciousOnly: boolean
  parentLines: boolean[]
}

function TreeNodeRow({
  node, depth, isLast, collapsed, onToggle, search, suspiciousOnly, parentLines,
}: TreeNodeProps) {
  const hasChildren = (node.children ?? []).length > 0
  const isCollapsed = collapsed.has(node.pid)
  const isRoot = depth === 0
  const isRootProcess = node.pid === 4 || node.name === 'explorer.exe' || node.name === 'System'
  const matchesSearch = search ? node.name.toLowerCase().includes(search.toLowerCase()) : false

  // Filter: if suspiciousOnly, only show node if it or a descendant is suspicious
  function hasSuspiciousDescendant(n: ProcessNode): boolean {
    if (n.suspicious) return true
    return (n.children ?? []).some(hasSuspiciousDescendant)
  }

  if (suspiciousOnly && !hasSuspiciousDescendant(node)) return null

  const children = (node.children ?? []).filter(c =>
    suspiciousOnly ? hasSuspiciousDescendant(c) : true
  )

  let borderColor = 'border-zinc-700'
  let bgColor = 'bg-zinc-900'
  if (node.suspicious) { borderColor = 'border-red-500'; bgColor = 'bg-red-950/30' }
  else if (isRootProcess) { borderColor = 'border-blue-500'; bgColor = 'bg-blue-950/30' }

  const highlightClass = matchesSearch ? 'ring-2 ring-yellow-400' : ''

  return (
    <div>
      <div className="flex items-start" style={{ paddingLeft: `${depth * 24}px` }}>
        {/* Connector lines */}
        <div className="flex items-center shrink-0" style={{ width: 24 }}>
          {depth > 0 && (
            <div className="flex flex-col items-center" style={{ width: 24 }}>
              <div className={`w-px bg-zinc-600 ${isLast ? 'h-4' : 'h-full'}`} style={{ minHeight: 16 }} />
              <div className="w-3 h-px bg-zinc-600" />
            </div>
          )}
        </div>

        {/* Node card */}
        <div
          className={`flex-1 mb-1 border rounded-lg px-3 py-2 cursor-pointer transition-all ${borderColor} ${bgColor} ${highlightClass} hover:brightness-125 group relative`}
          onClick={() => hasChildren && onToggle(node.pid)}
        >
          <div className="flex items-center gap-2">
            {/* Expand/collapse */}
            {hasChildren ? (
              isCollapsed
                ? <ChevronRight className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                : <ChevronDown className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
            ) : (
              <span className="w-3.5 h-3.5 shrink-0" />
            )}

            {/* Status icon */}
            {node.suspicious
              ? <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
              : isRootProcess
                ? <Monitor className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                : <CheckCircle className="w-3.5 h-3.5 text-green-500 shrink-0" />
            }

            {/* Process name */}
            <span className={`font-bold text-sm ${node.suspicious ? 'text-red-300' : isRootProcess ? 'text-blue-300' : 'text-zinc-100'}`}>
              {node.name}
            </span>
            <span className="text-xs text-zinc-500">(PID: {node.pid})</span>
            {node.ppid > 0 && <span className="text-xs text-zinc-600">← {node.ppid}</span>}

            {/* Badges */}
            {node.suspicious && (
              <span className="ml-auto text-xs bg-red-900/60 text-red-300 border border-red-700 px-1.5 py-0.5 rounded-sm">
                SUSPICIOUS
              </span>
            )}
            {isRootProcess && !node.suspicious && (
              <span className="ml-auto text-xs bg-blue-900/60 text-blue-300 border border-blue-700 px-1.5 py-0.5 rounded-sm">
                ROOT
              </span>
            )}
          </div>

          {/* Cmdline */}
          {node.cmdline && (
            <div className="mt-1 ml-6">
              <code className="text-xs text-zinc-500 font-mono truncate block max-w-xl" title={node.cmdline}>
                {node.cmdline.length > 80 ? node.cmdline.slice(0, 80) + '…' : node.cmdline}
              </code>
            </div>
          )}

          {/* Full cmdline tooltip */}
          {node.cmdline && (
            <div className="absolute left-0 top-full mt-1 z-50 bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 max-w-lg break-all opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity shadow-xl">
              {node.cmdline}
            </div>
          )}
        </div>
      </div>

      {/* Children */}
      {!isCollapsed && children.length > 0 && (
        <div className="relative">
          {/* Vertical line for children */}
          <div
            className="absolute bg-zinc-700"
            style={{
              left: `${depth * 24 + 24 + 11}px`,
              top: 0,
              bottom: 4,
              width: 1,
            }}
          />
          {children.map((child, idx) => (
            <TreeNodeRow
              key={child.pid}
              node={child}
              depth={depth + 1}
              isLast={idx === children.length - 1}
              collapsed={collapsed}
              onToggle={onToggle}
              search={search}
              suspiciousOnly={suspiciousOnly}
              parentLines={[...parentLines, !isLast]}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function ProcessTreePage() {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null)
  const [agentSearch, setAgentSearch] = useState('')
  const [timeRange, setTimeRange] = useState<1 | 6 | 24>(1)
  const [treeData, setTreeData] = useState<ProcessNode[]>([])
  const [isLoaded, setIsLoaded] = useState(true)
  const [loading, setLoading] = useState(false)
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set())
  const [suspiciousOnly, setSuspiciousOnly] = useState(false)
  const [search, setSearch] = useState('')

  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents'],
    queryFn: () => apiFetch('/api/v1/agents'),
  })

  const filteredAgents = agents.filter(a =>
    a.hostname.toLowerCase().includes(agentSearch.toLowerCase())
  )

  const handleLoadTree = async () => {
    if (!selectedAgent) return
    setLoading(true)
    try {
      const data = await apiFetchList<ProcessNode>(
        `/api/v1/agents/${selectedAgent.id}/process-tree?hours=${timeRange}`
      )
      setTreeData(data)
    } catch {
      setTreeData([])
    } finally {
      setLoading(false)
      setIsLoaded(true)
    }
  }

  const toggleNode = useCallback((pid: number) => {
    setCollapsed(prev => {
      const next = new Set(prev)
      if (next.has(pid)) next.delete(pid)
      else next.add(pid)
      return next
    })
  }, [])

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(treeData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `process-tree-${selectedAgent?.hostname ?? 'unknown'}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const totalNodes = countNodes(treeData)
  const suspiciousCount = countSuspicious(treeData)
  const depth = maxDepth(treeData)

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-900/40 rounded-lg border border-purple-700/50">
            <GitBranch className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Process Tree</h1>
            <p className="text-sm text-zinc-400">Visual process hierarchy and attack chain analysis</p>
          </div>
        </div>
        {isLoaded && (
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg border border-zinc-700 text-sm transition-colors"
          >
            <Download className="w-4 h-4" />
            Export JSON
          </button>
        )}
      </div>

      {/* Controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {/* Agent Selector */}
        <div className="md:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-4">
          <label className="block text-xs text-zinc-400 mb-2 font-medium uppercase tracking-wider">Select Agent</label>
          <div className="relative mb-2">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              type="text"
              placeholder="Search agents..."
              value={agentSearch}
              onChange={e => setAgentSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-hidden focus:border-purple-500"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-32 overflow-y-auto">
            {filteredAgents.map(agent => (
              <button
                key={agent.id}
                onClick={() => setSelectedAgent(agent)}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm text-left transition-colors ${
                  selectedAgent?.id === agent.id
                    ? 'bg-purple-900/40 border-purple-600 text-purple-200'
                    : 'bg-zinc-800 border-zinc-700 text-zinc-300 hover:border-zinc-600'
                }`}
              >
                <div className={`w-2 h-2 rounded-full ${agent.status === 'online' ? 'bg-green-400' : 'bg-zinc-500'}`} />
                <div>
                  <div className="font-medium">{agent.hostname}</div>
                  <div className="text-xs text-zinc-500">{agent.os}</div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Time Range + Load */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 flex flex-col gap-3">
          <div>
            <label className="block text-xs text-zinc-400 mb-2 font-medium uppercase tracking-wider">Time Range</label>
            <div className="flex gap-2">
              {([1, 6, 24] as const).map(h => (
                <button
                  key={h}
                  onClick={() => setTimeRange(h)}
                  className={`flex-1 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
                    timeRange === h
                      ? 'bg-purple-900/40 border-purple-600 text-purple-200'
                      : 'bg-zinc-800 border-zinc-700 text-zinc-400 hover:border-zinc-600'
                  }`}
                >
                  {h}h
                </button>
              ))}
            </div>
          </div>
          <button
            onClick={handleLoadTree}
            disabled={!selectedAgent || loading}
            className="w-full py-2 bg-purple-700 hover:bg-purple-600 disabled:bg-zinc-700 disabled:text-zinc-500 text-white rounded-lg font-medium text-sm flex items-center justify-center gap-2 transition-colors"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <GitBranch className="w-4 h-4" />}
            {loading ? '読み込み中...' : 'ツリーを読み込む'}
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      {isLoaded && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          {[
            { label: 'Total Nodes', value: totalNodes, color: 'text-zinc-100' },
            { label: 'Suspicious Nodes', value: suspiciousCount, color: suspiciousCount > 0 ? 'text-red-400' : 'text-green-400' },
            { label: 'Max Depth', value: depth, color: 'text-blue-400' },
            { label: 'Time Range', value: `${timeRange}h`, color: 'text-purple-400' },
          ].map(stat => (
            <div key={stat.label} className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 text-center">
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-zinc-500 mt-1">{stat.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      {isLoaded && (
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              type="text"
              placeholder="Highlight process name..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-zinc-900 border border-zinc-800 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-hidden focus:border-purple-500"
            />
          </div>
          <button
            onClick={() => setSuspiciousOnly(v => !v)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${
              suspiciousOnly
                ? 'bg-red-900/40 border-red-600 text-red-300'
                : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-600'
            }`}
          >
            <Filter className="w-4 h-4" />
            Suspicious Only
          </button>
          <button
            onClick={() => setCollapsed(new Set())}
            className="flex items-center gap-2 px-3 py-2 bg-zinc-900 border border-zinc-700 rounded-lg text-sm text-zinc-400 hover:border-zinc-600 transition-colors"
          >
            <ChevronDown className="w-4 h-4" />
            Expand All
          </button>
        </div>
      )}

      {/* Tree Visualization */}
      {isLoaded && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 overflow-x-auto">
          <div className="min-w-[600px]">
            {treeData.map((node, idx) => (
              <TreeNodeRow
                key={node.pid}
                node={node}
                depth={0}
                isLast={idx === treeData.length - 1}
                collapsed={collapsed}
                onToggle={toggleNode}
                search={search}
                suspiciousOnly={suspiciousOnly}
                parentLines={[]}
              />
            ))}
          </div>
        </div>
      )}

      {!isLoaded && !loading && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
          <GitBranch className="w-12 h-12 mb-3 opacity-30" />
          <p className="text-lg">Select an agent and load the process tree</p>
        </div>
      )}
    </div>
  )
}
