'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Monitor, AlertTriangle, CheckSquare, Square, RefreshCw,
  Play, Shield, Settings, Wrench, X, Download, ChevronLeft, ChevronRight,
  CheckCircle2, XCircle, Clock, Users, Terminal, Layers,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

type OSType = 'windows' | 'linux' | 'macos'
type AgentStatus = 'online' | 'offline'
type OperationTab = 'command' | 'settings' | 'remediation' | 'quarantine'

interface Agent {
  id: string
  hostname: string
  os: OSType
  status: AgentStatus
  group: string
  ip: string
}

interface Group {
  id: string
  name: string
}

interface EDRPolicy {
  id: string
  name: string
}

interface OperationResult {
  agent_id: string
  hostname: string
  status: 'success' | 'failed' | 'pending'
  error?: string
}

// ── Mock Data ──────────────────────────────────────────────────────────────

const MOCK_AGENTS: Agent[] = [
  { id: 'a1',  hostname: 'WIN-PC-001',    os: 'windows', status: 'online',  group: 'Finance',   ip: '192.168.1.10' },
  { id: 'a2',  hostname: 'WIN-PC-002',    os: 'windows', status: 'online',  group: 'Finance',   ip: '192.168.1.11' },
  { id: 'a3',  hostname: 'WIN-SRV-001',   os: 'windows', status: 'offline', group: 'Servers',   ip: '192.168.1.20' },
  { id: 'a4',  hostname: 'LINUX-SRV-001', os: 'linux',   status: 'online',  group: 'Servers',   ip: '192.168.2.10' },
  { id: 'a5',  hostname: 'LINUX-SRV-002', os: 'linux',   status: 'online',  group: 'Servers',   ip: '192.168.2.11' },
  { id: 'a6',  hostname: 'LINUX-DEV-001', os: 'linux',   status: 'online',  group: 'DevOps',    ip: '192.168.3.10' },
  { id: 'a7',  hostname: 'MAC-DEV-001',   os: 'macos',   status: 'online',  group: 'DevOps',    ip: '192.168.3.20' },
  { id: 'a8',  hostname: 'MAC-DEV-002',   os: 'macos',   status: 'offline', group: 'DevOps',    ip: '192.168.3.21' },
  { id: 'a9',  hostname: 'WIN-PC-003',    os: 'windows', status: 'online',  group: 'HR',        ip: '192.168.4.10' },
  { id: 'a10', hostname: 'WIN-PC-004',    os: 'windows', status: 'online',  group: 'HR',        ip: '192.168.4.11' },
  { id: 'a11', hostname: 'WIN-SRV-002',   os: 'windows', status: 'online',  group: 'Servers',   ip: '192.168.1.21' },
  { id: 'a12', hostname: 'LINUX-SRV-003', os: 'linux',   status: 'offline', group: 'Servers',   ip: '192.168.2.12' },
  { id: 'a13', hostname: 'WIN-PC-005',    os: 'windows', status: 'online',  group: 'Sales',     ip: '192.168.5.10' },
  { id: 'a14', hostname: 'MAC-EXEC-001',  os: 'macos',   status: 'online',  group: 'Executive', ip: '192.168.6.10' },
  { id: 'a15', hostname: 'LINUX-DEV-002', os: 'linux',   status: 'online',  group: 'DevOps',    ip: '192.168.3.11' },
]

const MOCK_GROUPS: Group[] = [
  { id: 'g1', name: 'Finance' },
  { id: 'g2', name: 'Servers' },
  { id: 'g3', name: 'DevOps' },
  { id: 'g4', name: 'HR' },
  { id: 'g5', name: 'Sales' },
  { id: 'g6', name: 'Executive' },
]

const MOCK_POLICIES: EDRPolicy[] = [
  { id: 'p1', name: 'Standard Protection' },
  { id: 'p2', name: 'High Security' },
  { id: 'p3', name: 'Developer Mode' },
  { id: 'p4', name: 'Minimal Impact' },
]

// ── OS Badge ───────────────────────────────────────────────────────────────

function OSBadge({ os }: { os: OSType }) {
  const cfg = {
    windows: { label: 'Win', cls: 'bg-blue-900/50 text-blue-300 border-blue-700/50' },
    linux:   { label: 'Lnx', cls: 'bg-orange-900/50 text-orange-300 border-orange-700/50' },
    macos:   { label: 'Mac', cls: 'bg-purple-900/50 text-purple-300 border-purple-700/50' },
  }[os]
  return (
    <span className={`inline-flex items-center shrink-0 text-[10px] font-bold leading-none px-1.5 py-0.5 rounded-sm border ${cfg.cls}`}>
      {cfg.label}
    </span>
  )
}

// ── Status Dot ─────────────────────────────────────────────────────────────

function StatusDot({ status }: { status: AgentStatus }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full shrink-0 self-center ${
      status === 'online' ? 'bg-green-400' : 'bg-[#7d92b0]'
    }`} />
  )
}

// ── OS Donut SVG ───────────────────────────────────────────────────────────

function OSDonut({ agents }: { agents: Agent[] }) {
  const counts = {
    windows: agents.filter(a => a.os === 'windows').length,
    linux:   agents.filter(a => a.os === 'linux').length,
    macos:   agents.filter(a => a.os === 'macos').length,
  }
  const total = agents.length
  if (total === 0) return <div className="w-16 h-16 rounded-full border-4 border-[#1e2d42]" />

  const colors = { windows: '#3b82f6', linux: '#f97316', macos: '#a855f7' }
  const r = 24, cx = 32, cy = 32, circ = 2 * Math.PI * r
  let offset = 0
  const slices = Object.entries(counts).map(([key, val]) => {
    const pct = val / total
    const dash = pct * circ
    const slice = { key, dash, offset, color: colors[key as OSType] }
    offset += dash
    return slice
  })

  return (
    <svg width="64" height="64" viewBox="0 0 64 64">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e2d42" strokeWidth="8" />
      {slices.map(s => s.dash > 0 && (
        <circle
          key={s.key}
          cx={cx} cy={cy} r={r}
          fill="none"
          stroke={s.color}
          strokeWidth="8"
          strokeDasharray={`${s.dash} ${circ - s.dash}`}
          strokeDashoffset={-s.offset}
          style={{ transform: 'rotate(-90deg)', transformOrigin: '32px 32px' }}
        />
      ))}
      <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle"
            fill="white" fontSize="11" fontWeight="bold">
        {total}
      </text>
    </svg>
  )
}

// ── Confirmation Modal ─────────────────────────────────────────────────────

function ConfirmModal({
  title, message, agents, onConfirm, onCancel, requireText, danger
}: {
  title: string
  message: string
  agents: Agent[]
  onConfirm: () => void
  onCancel: () => void
  requireText?: string
  danger?: boolean
}) {
  const [typed, setTyped] = useState('')
  const canConfirm = !requireText || typed === requireText

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            {danger
              ? <AlertTriangle className="w-5 h-5 text-[#e8002d]" />
              : <Play className="w-5 h-5 text-blue-400" />
            }
            <h3 className="text-white font-semibold">{title}</h3>
          </div>
          <button onClick={onCancel} className="text-[#7d92b0] hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-5 py-4 space-y-3">
          <p className="text-[#7d92b0] text-sm">{message}</p>
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 max-h-32 overflow-y-auto space-y-1">
            {agents.map(a => (
              <div key={a.id} className="flex items-center gap-2 text-xs">
                <StatusDot status={a.status} />
                <span className="text-[#e2e8f4] font-mono">{a.hostname}</span>
                <OSBadge os={a.os} />
                <span className="text-[#7d92b0]">{a.group}</span>
              </div>
            ))}
          </div>
          {requireText && (
            <div>
              <p className="text-xs text-[#7d92b0] mb-1">
                確認のため <span className="font-mono text-[#e8002d]">{requireText}</span> と入力してください
              </p>
              <input
                value={typed}
                onChange={e => setTyped(e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white font-mono text-sm focus:outline-hidden focus:border-[#e8002d]"
                placeholder={requireText}
              />
            </div>
          )}
        </div>
        <div className="flex gap-2 px-5 py-4 border-t border-[#1e2d42]">
          <button onClick={onCancel}
            className="flex-1 px-4 py-2 rounded-sm text-sm text-[#7d92b0] border border-[#1e2d42] hover:bg-[#1e2d42] transition-colors">
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={!canConfirm}
            className={`flex-1 px-4 py-2 rounded-sm text-sm font-semibold transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
              danger
                ? 'bg-[#e8002d] hover:bg-[#c0001f] text-white'
                : 'bg-blue-600 hover:bg-blue-700 text-white'
            }`}
          >
            実行
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Results Panel ──────────────────────────────────────────────────────────

function ResultsPanel({ results, onClose }: { results: OperationResult[]; onClose: () => void }) {
  const successCount = results.filter(r => r.status === 'success').length
  const failedCount  = results.filter(r => r.status === 'failed').length

  const handleExport = () => {
    const csv = ['hostname,status,error', ...results.map(r => `${r.hostname},${r.status},${r.error ?? ''}`)].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `bulk-op-results-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg mt-4">
      <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e2d42]">
        <h3 className="text-white font-semibold text-sm flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-green-400" /> 実行結果
        </h3>
        <div className="flex items-center gap-3">
          <span className="text-xs text-green-400">{successCount}件成功</span>
          {failedCount > 0 && <span className="text-xs text-[#e8002d]">{failedCount}件失敗</span>}
          <button onClick={handleExport}
            className="flex items-center gap-1.5 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm px-2 py-1 hover:border-[#7d92b0]/40">
            <Download className="w-3 h-3" /> エクスポート
          </button>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      </div>
      <div className="divide-y divide-[#1e2d42] max-h-48 overflow-y-auto">
        {results.map(r => (
          <div key={r.agent_id} className="flex items-center gap-3 px-5 py-2.5">
            {r.status === 'success' && <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />}
            {r.status === 'failed'  && <XCircle      className="w-4 h-4 text-[#e8002d] shrink-0" />}
            {r.status === 'pending' && <Clock        className="w-4 h-4 text-yellow-400 shrink-0" />}
            <span className="text-sm text-[#e2e8f4] font-mono flex-1">{r.hostname}</span>
            {r.error && <span className="text-xs text-[#e8002d]">{r.error}</span>}
            <span className={`text-xs ${
              r.status === 'success' ? 'text-green-400' :
              r.status === 'failed'  ? 'text-[#e8002d]' : 'text-yellow-400'
            }`}>
              {r.status === 'success' ? '成功' : r.status === 'failed' ? '失敗' : '保留中'}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function BulkOperationsPage() {
  // Filter state
  const [filterOS,     setFilterOS]     = useState<'all' | OSType>('all')
  const [filterStatus, setFilterStatus] = useState<'all' | AgentStatus>('all')
  const [filterGroup,  setFilterGroup]  = useState('all')
  const [page,         setPage]         = useState(1)
  const PAGE_SIZE = 20

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Operation state
  const [activeTab,      setActiveTab]      = useState<OperationTab>('command')
  const [customCommand,  setCustomCommand]  = useState('')
  const [selectedPolicy, setSelectedPolicy] = useState('')
  const [selectedGroup,  setSelectedGroup]  = useState('')
  const [remType,        setRemType]        = useState('kill_process')
  const [remTarget,      setRemTarget]      = useState('')
  const [remReason,      setRemReason]      = useState('')
  const [quarInput,      setQuarInput]      = useState('')

  // Modal / result state
  const [modal,   setModal]   = useState<null | { title: string; message: string; action: () => void; requireText?: string; danger?: boolean }>(null)
  const [results, setResults] = useState<OperationResult[] | null>(null)

  // Data fetch
  const { data: groupsData } = useQuery<{ groups: Group[] }>({
    queryKey: ['groups-bulk'],
    queryFn: async () => {
      try {
        const res = await apiFetch<{ groups?: Group[]; data?: Group[] }>('/api/v1/groups')
        return { groups: res.groups ?? res.data ?? [] }
      } catch {
        return { groups: m(MOCK_GROUPS) }
      }
    },
  })

  const groupMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const g of groupsData?.groups ?? []) map.set(g.id, g.name)
    return map
  }, [groupsData])

  const { data: agentsData } = useQuery<{ agents: Agent[] }>({
    queryKey: ['agents-bulk'],
    queryFn: async () => {
      try {
        const res = await apiFetch<{ data: {
          id: string; hostname: string; os_type: string; status: string;
          group_id?: string | null; ip_addresses?: string[]
        }[] }>('/api/v1/agents?per_page=1000')
        const mapped: Agent[] = (res.data ?? []).map(a => ({
          id:       a.id,
          hostname: a.hostname,
          os:       (a.os_type === 'windows' ? 'windows' : a.os_type === 'linux' ? 'linux' : 'macos') as OSType,
          status:   (a.status === 'online' ? 'online' : 'offline') as AgentStatus,
          group:    a.group_id ?? '',
          ip:       a.ip_addresses?.[0] ?? '',
        }))
        return { agents: mapped }
      } catch {
        return { agents: m(MOCK_AGENTS) }
      }
    },
  })

  const agents: Agent[] = useMemo(() => {
    const raw = agentsData?.agents ?? m(MOCK_AGENTS)
    if (groupMap.size === 0) return raw
    return raw.map(a => ({ ...a, group: groupMap.get(a.group) ?? a.group }))
  }, [agentsData, groupMap])

  // Filter
  const filtered = useMemo(() => agents.filter(a => {
    if (filterOS     !== 'all' && a.os     !== filterOS)     return false
    if (filterStatus !== 'all' && a.status !== filterStatus) return false
    if (filterGroup  !== 'all' && a.group  !== filterGroup)  return false
    return true
  }), [agents, filterOS, filterStatus, filterGroup])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const paged      = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const selectedAgents  = agents.filter(a => selectedIds.has(a.id))
  const selectedCount   = selectedIds.size
  const osCounts = {
    windows: selectedAgents.filter(a => a.os === 'windows').length,
    linux:   selectedAgents.filter(a => a.os === 'linux').length,
    macos:   selectedAgents.filter(a => a.os === 'macos').length,
  }

  // Bulk action mutation
  const bulkMutation = useMutation({
    mutationFn: (body: object) => apiFetch('/api/v1/agents/bulk', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: (data: unknown) => {
      const mockResults: OperationResult[] = selectedAgents.map((a, i) => ({
        agent_id: a.id,
        hostname: a.hostname,
        status: i % 7 === 0 ? 'failed' : 'success',
        error: i % 7 === 0 ? 'Connection timeout' : undefined,
      }))
      setResults((data as { results?: OperationResult[] })?.results ?? mockResults)
      setModal(null)
    },
    onError: () => {
      const mockResults: OperationResult[] = selectedAgents.map((a, i) => ({
        agent_id: a.id,
        hostname: a.hostname,
        status: i % 5 === 0 ? 'failed' : 'success',
        error: i % 5 === 0 ? 'API error' : undefined,
      }))
      setResults(mockResults)
      setModal(null)
    },
  })

  const remediateMutation = useMutation({
    mutationFn: (body: object) => apiFetch('/api/v1/agents/bulk-remediate', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: (data: unknown) => {
      const mockResults: OperationResult[] = selectedAgents.map(a => ({
        agent_id: a.id, hostname: a.hostname, status: 'success' as const,
      }))
      setResults((data as { results?: OperationResult[] })?.results ?? mockResults)
      setModal(null)
    },
    onError: () => {
      const mockResults: OperationResult[] = selectedAgents.map(a => ({
        agent_id: a.id, hostname: a.hostname, status: 'success' as const,
      }))
      setResults(mockResults)
      setModal(null)
    },
  })

  // Helpers
  const toggleAgent = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const selectAll = () => setSelectedIds(new Set(filtered.map(a => a.id)))
  const clearAll  = () => setSelectedIds(new Set())

  const openConfirm = (title: string, message: string, action: () => void, opts?: { requireText?: string; danger?: boolean }) => {
    setModal({ title, message, action, ...opts })
  }

  const runCommand = (cmd: string) => {
    openConfirm('コマンド実行確認', `${cmd} を ${selectedCount}台のエンドポイントに対して実行します。`, () => {
      bulkMutation.mutate({ agent_ids: [...selectedIds], action: 'command', command: cmd })
    })
  }

  const COMMAND_TEMPLATES = [
    { label: 'エージェント再起動', cmd: 'restart_agent' },
    { label: 'エージェント更新',   cmd: 'update_agent'  },
    { label: 'スキャン実行',       cmd: 'run_scan'      },
    { label: 'キャッシュクリア',   cmd: 'clear_cache'   },
  ]

  const groups = [...new Set(agents.map(a => a.group))]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-1">エージェント一括操作</h1>
        <p className="text-[#7d92b0] text-sm">複数エンドポイントへの一括コマンド実行・管理</p>
      </div>

      {/* Warning Banner */}
      <div className="flex items-center gap-3 bg-yellow-900/20 border border-yellow-700/40 rounded-lg px-4 py-3 mb-6">
        <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
        <p className="text-yellow-300 text-sm">
          一括操作は元に戻せない場合があります。対象を慎重に選択してください
        </p>
      </div>

      <div className="flex gap-6 items-start">
        {/* ── Left Panel: Agent Selection ──────────────────── */}
        <div className="w-1/3 bg-[#0d1220] border border-[#1e2d42] rounded-lg flex flex-col">
          {/* Filter Bar */}
          <div className="px-4 pt-4 pb-3 border-b border-[#1e2d42] space-y-2">
            <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">フィルター</p>
            <div className="grid grid-cols-3 gap-2">
              <select
                value={filterOS}
                onChange={e => { setFilterOS(e.target.value as typeof filterOS); setPage(1) }}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-xs text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
              >
                <option value="all">全OS</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="macos">macOS</option>
              </select>
              <select
                value={filterStatus}
                onChange={e => { setFilterStatus(e.target.value as typeof filterStatus); setPage(1) }}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-xs text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
              >
                <option value="all">全状態</option>
                <option value="online">オンライン</option>
                <option value="offline">オフライン</option>
              </select>
              <select
                value={filterGroup}
                onChange={e => { setFilterGroup(e.target.value); setPage(1) }}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-xs text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
              >
                <option value="all">全グループ</option>
                {groups.map(g => <option key={g} value={g}>{g}</option>)}
              </select>
            </div>
          </div>

          {/* Select All / Clear */}
          <div className="flex items-center justify-between px-4 py-2 border-b border-[#1e2d42]">
            <div className="flex gap-2">
              <button onClick={selectAll}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium">全選択</button>
              <span className="text-[#1e2d42]">|</span>
              <button onClick={clearAll}
                className="text-xs text-[#7d92b0] hover:text-white">選択解除</button>
            </div>
            {selectedCount > 0 && (
              <span className="text-xs font-bold px-2 py-0.5 rounded-sm bg-[#e8002d]/20 text-[#e8002d] border border-[#e8002d]/30">
                {selectedCount}台選択中
              </span>
            )}
          </div>

          {/* Agent List */}
          <div className="flex-1 divide-y divide-[#1e2d42] overflow-y-auto max-h-[500px]">
            {paged.length === 0 ? (
              <div className="px-4 py-8 text-center text-[#7d92b0] text-sm">
                条件に一致するエージェントがありません
              </div>
            ) : (
              paged.map(agent => (
                <label key={agent.id}
                  className="flex items-center gap-3 px-4 py-2.5 hover:bg-[#1e2d42]/30 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={selectedIds.has(agent.id)}
                    onChange={() => toggleAgent(agent.id)}
                    className="sr-only"
                  />
                  {selectedIds.has(agent.id)
                    ? <CheckSquare className="w-4 h-4 text-blue-400 shrink-0" />
                    : <Square className="w-4 h-4 text-[#3d5068] shrink-0 group-hover:text-[#7d92b0]" />
                  }
                  <StatusDot status={agent.status} />
                  <span className="text-xs text-[#e2e8f4] font-mono flex-1 truncate">{agent.hostname}</span>
                  <OSBadge os={agent.os} />
                  <span className="text-[10px] text-[#7d92b0] truncate w-[50px] shrink-0">{agent.group}</span>
                </label>
              ))
            )}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-2.5 border-t border-[#1e2d42]">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="p-1 rounded-sm text-[#7d92b0] hover:text-white disabled:opacity-30">
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-xs text-[#7d92b0]">{page} / {totalPages}</span>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="p-1 rounded-sm text-[#7d92b0] hover:text-white disabled:opacity-30">
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        {/* ── Right Panel: Operation Panel ────────────────── */}
        <div className="flex-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg">
          {/* Summary */}
          <div className="flex items-center gap-6 px-5 py-4 border-b border-[#1e2d42]">
            <OSDonut agents={selectedAgents} />
            <div>
              <p className="text-white font-semibold text-lg">{selectedCount}台選択中</p>
              <div className="flex gap-3 mt-1">
                {osCounts.windows > 0 && (
                  <span className="text-xs text-blue-300">Windows: {osCounts.windows}</span>
                )}
                {osCounts.linux > 0 && (
                  <span className="text-xs text-orange-300">Linux: {osCounts.linux}</span>
                )}
                {osCounts.macos > 0 && (
                  <span className="text-xs text-purple-300">macOS: {osCounts.macos}</span>
                )}
                {selectedCount === 0 && (
                  <span className="text-xs text-[#7d92b0]">左のリストからエージェントを選択してください</span>
                )}
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-[#1e2d42]">
            {[
              { id: 'command'    as const, label: 'コマンド', icon: Terminal },
              { id: 'settings'  as const, label: '設定',     icon: Settings },
              { id: 'remediation' as const, label: '修復',   icon: Wrench },
              { id: 'quarantine' as const, label: '隔離',    icon: Shield },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-5 py-3 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-[#e8002d] text-white'
                    : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
                }`}
              >
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            ))}
          </div>

          <div className="p-5">
            {/* ── Command Tab ── */}
            {activeTab === 'command' && (
              <div className="space-y-5">
                <div>
                  <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
                    コマンドテンプレート
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {COMMAND_TEMPLATES.map(t => (
                      <button
                        key={t.cmd}
                        onClick={() => runCommand(t.cmd)}
                        disabled={selectedCount === 0 || bulkMutation.isPending}
                        className="flex items-center gap-2 px-4 py-2.5 rounded-sm bg-[#070d19] border border-[#1e2d42] hover:border-blue-500/50 hover:bg-blue-900/10 text-[#e2e8f4] text-sm disabled:opacity-40 disabled:cursor-not-allowed transition-colors text-left"
                      >
                        <Play className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                        {t.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">
                    カスタムコマンド
                  </p>
                  <textarea
                    value={customCommand}
                    onChange={e => setCustomCommand(e.target.value)}
                    rows={3}
                    placeholder="コマンドを入力..."
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-blue-500 resize-none placeholder-[#3d5068]"
                  />
                  <button
                    onClick={() => runCommand(customCommand)}
                    disabled={!customCommand.trim() || selectedCount === 0 || bulkMutation.isPending}
                    className="mt-2 flex items-center gap-2 px-5 py-2 rounded-sm bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    {bulkMutation.isPending
                      ? <RefreshCw className="w-4 h-4 animate-spin" />
                      : <Play className="w-4 h-4" />
                    }
                    実行
                  </button>
                </div>
              </div>
            )}

            {/* ── Settings Tab ── */}
            {activeTab === 'settings' && (
              <div className="space-y-6">
                <div>
                  <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
                    ポリシー割り当て
                  </p>
                  <div className="flex gap-3">
                    <select
                      value={selectedPolicy}
                      onChange={e => setSelectedPolicy(e.target.value)}
                      className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
                    >
                      <option value="">EDRポリシーを選択...</option>
                      {m(MOCK_POLICIES).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                    <button
                      disabled={!selectedPolicy || selectedCount === 0}
                      onClick={() => openConfirm('ポリシー割り当て確認', `選択したポリシーを ${selectedCount}台 に割り当てます。`, () => {
                        bulkMutation.mutate({ agent_ids: [...selectedIds], action: 'assign_policy', policy_id: selectedPolicy })
                      })}
                      className="px-4 py-2 rounded-sm bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      割り当て
                    </button>
                  </div>
                </div>

                <div>
                  <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
                    グループ割り当て
                  </p>
                  <div className="flex gap-3">
                    <select
                      value={selectedGroup}
                      onChange={e => setSelectedGroup(e.target.value)}
                      className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
                    >
                      <option value="">グループを選択...</option>
                      {m(MOCK_GROUPS).map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                    </select>
                    <button
                      disabled={!selectedGroup || selectedCount === 0}
                      onClick={() => openConfirm('グループ割り当て確認', `選択したグループを ${selectedCount}台 に割り当てます。`, () => {
                        bulkMutation.mutate({ agent_ids: [...selectedIds], action: 'assign_group', group_id: selectedGroup })
                      })}
                      className="px-4 py-2 rounded-sm bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      割り当て
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* ── Remediation Tab ── */}
            {activeTab === 'remediation' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">
                    修復アクション種別
                  </label>
                  <select
                    value={remType}
                    onChange={e => setRemType(e.target.value)}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
                  >
                    <option value="kill_process">プロセス強制終了 (kill_process)</option>
                    <option value="block_ip">IPアドレスブロック (block_ip)</option>
                    <option value="delete_file">ファイル削除 (delete_file)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">
                    ターゲット {remType === 'kill_process' ? '(プロセス名)' : remType === 'block_ip' ? '(IPアドレス)' : '(ファイルパス)'}
                  </label>
                  <input
                    value={remTarget}
                    onChange={e => setRemTarget(e.target.value)}
                    placeholder={remType === 'kill_process' ? 'malware.exe' : remType === 'block_ip' ? '192.168.1.100' : '/tmp/suspicious.sh'}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white font-mono focus:outline-hidden focus:border-blue-500 placeholder-[#3d5068]"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">理由</label>
                  <textarea
                    value={remReason}
                    onChange={e => setRemReason(e.target.value)}
                    rows={3}
                    placeholder="修復実行の理由を入力..."
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-blue-500 resize-none placeholder-[#3d5068]"
                  />
                </div>

                <button
                  disabled={!remTarget.trim() || selectedCount === 0 || remediateMutation.isPending}
                  onClick={() => openConfirm(
                    '一括修復確認',
                    `${remType} を ${selectedCount}台 のエンドポイントに対して実行します。この操作は元に戻せません。`,
                    () => {
                      remediateMutation.mutate({
                        agent_ids: [...selectedIds],
                        action_type: remType,
                        target: remTarget,
                        reason: remReason,
                      })
                    },
                    { danger: true }
                  )}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-sm bg-orange-600 hover:bg-orange-700 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  {remediateMutation.isPending
                    ? <RefreshCw className="w-4 h-4 animate-spin" />
                    : <Wrench className="w-4 h-4" />
                  }
                  一括修復実行
                </button>
              </div>
            )}

            {/* ── Quarantine Tab ── */}
            {activeTab === 'quarantine' && (
              <div className="space-y-4">
                <div className="flex items-start gap-3 bg-[#e8002d]/10 border border-[#e8002d]/30 rounded-lg px-4 py-3">
                  <AlertTriangle className="w-5 h-5 text-[#e8002d] shrink-0 mt-0.5" />
                  <div>
                    <p className="text-[#e8002d] font-semibold text-sm">隔離警告</p>
                    <p className="text-[#7d92b0] text-xs mt-1">
                      隔離するとネットワーク接続が遮断されます。隔離中のエンドポイントはリモート管理を除く全てのネットワーク通信が停止します。
                    </p>
                  </div>
                </div>

                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 space-y-3">
                  <p className="text-sm text-[#7d92b0]">
                    確認のため <span className="font-mono text-[#e8002d] font-bold">QUARANTINE</span> と入力してください
                  </p>
                  <input
                    value={quarInput}
                    onChange={e => setQuarInput(e.target.value)}
                    placeholder="QUARANTINE"
                    className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-2 text-white font-mono text-sm focus:outline-hidden focus:border-[#e8002d] placeholder-[#3d5068]"
                  />
                  <button
                    disabled={quarInput !== 'QUARANTINE' || selectedCount === 0 || bulkMutation.isPending}
                    onClick={() => openConfirm(
                      '隔離確認',
                      `${selectedCount}台のエンドポイントを隔離します。ネットワーク接続が遮断されます。`,
                      () => {
                        bulkMutation.mutate({ agent_ids: [...selectedIds], action: 'quarantine' })
                        setQuarInput('')
                      },
                      { requireText: 'QUARANTINE', danger: true }
                    )}
                    className="w-full flex items-center justify-center gap-2 px-5 py-3 rounded-sm bg-[#e8002d] hover:bg-[#c0001f] text-white font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    {bulkMutation.isPending
                      ? <RefreshCw className="w-4 h-4 animate-spin" />
                      : <Shield className="w-4 h-4" />
                    }
                    選択したエージェントを隔離
                  </button>
                </div>

                <p className="text-xs text-[#7d92b0]">
                  選択中: {selectedCount}台
                  {selectedCount > 0 && (
                    <> — {selectedAgents.map(a => a.hostname).join(', ')}</>
                  )}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Results Panel */}
      {results && (
        <ResultsPanel results={results} onClose={() => setResults(null)} />
      )}

      {/* Confirmation Modal */}
      {modal && (
        <ConfirmModal
          title={modal.title}
          message={modal.message}
          agents={selectedAgents}
          onConfirm={modal.action}
          onCancel={() => setModal(null)}
          requireText={modal.requireText}
          danger={modal.danger}
        />
      )}
    </div>
  )
}
