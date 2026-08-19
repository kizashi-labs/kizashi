'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Activity, RefreshCw, AlertTriangle, ChevronUp, ChevronDown,
  ChevronsUpDown, Clock, Cpu, MemoryStick, Zap, CheckCircle,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ───────────────────────────────────────────────────────────────────

interface CpuHistory {
  values: number[] // 10 data points
}

interface ExpensiveOp {
  name: string
  avg_ms: number
}

interface AgentPerf {
  id: string
  hostname: string
  os: 'Windows' | 'Linux' | 'macOS'
  version: string
  cpu_pct: number
  memory_mb: number
  events_per_sec: number
  latency_ms: number
  status: 'online' | 'degraded' | 'offline'
  last_seen: string
  cpu_history: CpuHistory
  top_ops: ExpensiveOp[]
}

interface Operation {
  name: string
  avg_duration_ms: number
  call_count: number
  p99_ms: number
}

interface PerformanceData {
  agents: AgentPerf[]
  avg_cpu: number
  avg_memory_mb: number
  avg_events_per_sec: number
  slow_agents_count: number
  operations: Operation[]
}

// ── Mock Data ────────────────────────────────────────────────────────────────


// ── Helper components ────────────────────────────────────────────────────────

type SortKey = keyof Pick<AgentPerf, 'hostname' | 'cpu_pct' | 'memory_mb' | 'events_per_sec' | 'latency_ms'>
type SortDir = 'asc' | 'desc'

function CpuBar({ pct }: { pct: number }) {
  const color =
    pct > 50 ? 'bg-[#e8002d]' : pct > 20 ? 'bg-yellow-400' : 'bg-[#00c853]'
  const textColor =
    pct > 50 ? 'text-[#e8002d]' : pct > 20 ? 'text-yellow-400' : 'text-[#00c853]'
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      <span className={`text-xs font-mono w-10 text-right ${textColor}`}>{pct.toFixed(1)}%</span>
    </div>
  )
}

function MemBar({ mb }: { mb: number }) {
  const pct = Math.min((mb / 1024) * 100, 100)
  const color = mb > 500 ? 'bg-[#e8002d]' : mb > 300 ? 'bg-yellow-400' : 'bg-[#4a90e2]'
  return (
    <div className="flex items-center gap-2 min-w-[110px]">
      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-[#7d92b0] w-14 text-right">{mb} MB</span>
    </div>
  )
}

function OsBadge({ os }: { os: AgentPerf['os'] }) {
  const map = {
    Windows: 'bg-[#0078d4]/20 text-[#4fc3f7] border-[#0078d4]/40',
    Linux:   'bg-[#e8002d]/10 text-[#ef9a9a] border-[#e8002d]/30',
    macOS:   'bg-gray-500/10 text-gray-300 border-gray-500/30',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] font-semibold border ${map[os]}`}>
      {os}
    </span>
  )
}

function StatusBadge({ status }: { status: AgentPerf['status'] }) {
  const map = {
    online:   'bg-[#00c853]/10 text-[#00c853] border-[#00c853]/30',
    degraded: 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30',
    offline:  'bg-[#e8002d]/10 text-[#e8002d] border-[#e8002d]/30',
  }
  const labels = { online: 'オンライン', degraded: '低下', offline: 'オフライン' }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] font-semibold border ${map[status]}`}>
      {labels[status]}
    </span>
  )
}

function Sparkline({ values }: { values: number[] }) {
  const max = Math.max(...values, 1)
  const h = 32
  const w = 120
  const step = w / (values.length - 1)
  const pts = values.map((v, i) => `${i * step},${h - (v / max) * h}`).join(' ')
  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline
        points={pts}
        fill="none"
        stroke="#e8002d"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      {values.map((v, i) => (
        <circle key={i} cx={i * step} cy={h - (v / max) * h} r={2} fill="#e8002d" opacity={0.6} />
      ))}
    </svg>
  )
}

function SortIcon({ col, sortKey, sortDir }: { col: SortKey; sortKey: SortKey; sortDir: SortDir }) {
  if (col !== sortKey) return <ChevronsUpDown className="w-3 h-3 text-[#3d5068]" />
  return sortDir === 'asc'
    ? <ChevronUp className="w-3 h-3 text-[#e8002d]" />
    : <ChevronDown className="w-3 h-3 text-[#e8002d]" />
}

function formatLastSeen(iso: string) {
  const d = new Date(iso)
  const now = new Date('2026-03-18T10:01:00Z')
  const diff = Math.floor((now.getTime() - d.getTime()) / 1000)
  if (diff < 60) return `${diff}秒前`
  if (diff < 3600) return `${Math.floor(diff / 60)}分前`
  return `${Math.floor(diff / 3600)}時間前`
}

// ── Main Page ────────────────────────────────────────────────────────────────

const EMPTY_DATA: PerformanceData = {
  agents: [],
  avg_cpu: 0,
  avg_memory_mb: 0,
  avg_events_per_sec: 0,
  slow_agents_count: 0,
  operations: [],
}

const TIME_RANGES = ['1h', '6h', '24h', '7d'] as const
type TimeRange = (typeof TIME_RANGES)[number]

export default function AgentPerformancePage() {
  const [range, setRange] = useState<TimeRange>('1h')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [sortKey, setSortKey] = useState<SortKey>('cpu_pct')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(new Date())

  const { data: perf = EMPTY_DATA, isLoading, refetch } = useQuery<PerformanceData>({
    queryKey: ['agent-performance', range],
    queryFn: async () => {
      const res = await apiFetchList<AgentPerf>(`/api/v1/admin/agent-performance?range=${range}`)
      if (Array.isArray(res)) return { ...EMPTY_DATA, agents: res }
      const d = res as any
      return (d && 'agents' in d) ? d as PerformanceData : EMPTY_DATA
    },
    staleTime: 25_000,
  })

  // Auto-refresh every 30s
  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(() => {
      refetch()
      setLastRefresh(new Date())
    }, 30_000)
    return () => clearInterval(id)
  }, [autoRefresh, refetch])

  const handleSort = useCallback((key: SortKey) => {
    if (key === sortKey) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }, [sortKey])

  const sortedAgents = [...perf.agents].sort((a, b) => {
    const av = a[sortKey] as number | string
    const bv = b[sortKey] as number | string
    const cmp = typeof av === 'string' ? (av as string).localeCompare(bv as string) : (av as number) - (bv as number)
    return sortDir === 'asc' ? cmp : -cmp
  })

  const slowAgents = perf.agents.filter(a => a.cpu_pct > 80 || a.memory_mb > 500)

  const inputCls = 'w-full px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-[#e2e8f4] text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#3d6baa] transition-colors'

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
            <Activity className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">エージェントパフォーマンス</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">エージェントのCPU・メモリ・イベント処理プロファイリング</p>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {/* Time range selector */}
          <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1">
            {TIME_RANGES.map(r => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`px-3 py-1.5 rounded-sm text-sm font-medium transition-colors ${
                  range === r
                    ? 'bg-[#e8002d] text-white'
                    : 'text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#1e2d42]'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${
              autoRefresh
                ? 'bg-[#e8002d]/10 border-[#e8002d]/40 text-[#e8002d]'
                : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4]'
            }`}
          >
            <RefreshCw className={`w-4 h-4 ${autoRefresh ? 'animate-spin' : ''}`} style={autoRefresh ? { animationDuration: '3s' } : {}} />
            自動更新 {autoRefresh ? 'ON' : 'OFF'}
          </button>
          <button
            onClick={() => { refetch(); setLastRefresh(new Date()) }}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 text-sm transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
        </div>
      </div>

      {/* Last refresh */}
      <p className="text-xs text-[#3d5068] flex items-center gap-1.5">
        <Clock className="w-3 h-3" />
        最終更新: {lastRefresh.toLocaleTimeString('ja-JP')}
      </p>

      {/* Top Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: '平均CPU使用率', value: `${perf.avg_cpu.toFixed(1)}%`, icon: Cpu, color: 'text-[#4a90e2]', bg: 'bg-[#4a90e2]/10' },
          { label: '平均メモリ', value: `${perf.avg_memory_mb} MB`, icon: MemoryStick, color: 'text-[#00c853]', bg: 'bg-[#00c853]/10' },
          { label: '平均イベント/秒', value: (perf.avg_events_per_sec ?? 0).toLocaleString(), icon: Zap, color: 'text-yellow-400', bg: 'bg-yellow-400/10' },
          { label: '低速エージェント', value: perf.slow_agents_count, icon: AlertTriangle, color: 'text-[#e8002d]', bg: 'bg-[#e8002d]/10' },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-4">
            <div className={`w-10 h-10 rounded-lg ${bg} flex items-center justify-center shrink-0`}>
              <Icon className={`w-5 h-5 ${color}`} />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{value}</p>
              <p className="text-xs text-[#7d92b0] mt-0.5">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Slow Agents Alert */}
      {slowAgents.length > 0 && (
        <div className="bg-[#e8002d]/5 border border-[#e8002d]/30 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-[#e8002d]" />
            <h3 className="text-sm font-semibold text-[#e8002d]">パフォーマンス警告 — {slowAgents.length}件のエージェントで問題が検出されました</h3>
          </div>
          <div className="flex flex-wrap gap-3">
            {slowAgents.map(a => (
              <div key={a.id} className="flex items-center gap-2 px-3 py-2 bg-[#0d1220] border border-[#e8002d]/20 rounded-lg">
                <OsBadge os={a.os} />
                <span className="text-sm font-medium text-white">{a.hostname}</span>
                {a.cpu_pct > 80 && <span className="text-xs text-[#e8002d] font-mono">CPU {a.cpu_pct.toFixed(0)}%</span>}
                {a.memory_mb > 500 && <span className="text-xs text-orange-400 font-mono">MEM {a.memory_mb}MB</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Agents Performance Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
          <Activity className="w-5 h-5 text-[#e8002d]" />
          <h2 className="text-white font-semibold">エージェント パフォーマンス一覧</h2>
          <span className="ml-auto text-xs text-[#7d92b0] bg-[#1e2d42] px-2 py-0.5 rounded-sm">{perf.agents.length} エージェント</span>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center h-32 text-[#7d92b0]">
            <RefreshCw className="w-5 h-5 animate-spin mr-2" /> 読み込み中...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {([
                    { key: 'hostname' as SortKey, label: 'ホスト名', w: '' },
                    { key: null,                  label: 'OS',       w: 'w-20' },
                    { key: null,                  label: 'バージョン', w: 'w-20' },
                    { key: 'cpu_pct' as SortKey,   label: 'CPU %',    w: 'w-36' },
                    { key: 'memory_mb' as SortKey, label: 'メモリ',   w: 'w-36' },
                    { key: 'events_per_sec' as SortKey, label: 'EPS', w: 'w-20' },
                    { key: 'latency_ms' as SortKey, label: 'レイテンシ', w: 'w-24' },
                    { key: null,                  label: 'ステータス', w: 'w-24' },
                    { key: null,                  label: '最終確認', w: 'w-24' },
                  ]).map(({ key, label, w }) => (
                    <th
                      key={label}
                      className={`px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider ${w} ${key ? 'cursor-pointer hover:text-[#e2e8f4] select-none' : ''}`}
                      onClick={() => key && handleSort(key)}
                    >
                      <div className="flex items-center gap-1">
                        {label}
                        {key && <SortIcon col={key} sortKey={sortKey} sortDir={sortDir} />}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {sortedAgents.map(agent => (
                  <>
                    <tr
                      key={agent.id}
                      className={`transition-colors cursor-pointer ${
                        expandedId === agent.id
                          ? 'bg-[#19253d]'
                          : 'hover:bg-[#111827]'
                      }`}
                      onClick={() => setExpandedId(expandedId === agent.id ? null : agent.id)}
                    >
                      <td className="px-4 py-3 font-mono text-sm text-[#e2e8f4]">{agent.hostname}</td>
                      <td className="px-4 py-3"><OsBadge os={agent.os} /></td>
                      <td className="px-4 py-3 font-mono text-xs text-[#7d92b0]">{agent.version}</td>
                      <td className="px-4 py-3"><CpuBar pct={agent.cpu_pct} /></td>
                      <td className="px-4 py-3"><MemBar mb={agent.memory_mb} /></td>
                      <td className="px-4 py-3 font-mono text-sm text-[#e2e8f4]">{(agent.events_per_sec ?? 0).toLocaleString()}</td>
                      <td className="px-4 py-3 font-mono text-sm text-[#7d92b0]">{agent.latency_ms}ms</td>
                      <td className="px-4 py-3"><StatusBadge status={agent.status} /></td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">{formatLastSeen(agent.last_seen)}</td>
                    </tr>
                    {expandedId === agent.id && (
                      <tr key={`${agent.id}-detail`} className="bg-[#0a1128]">
                        <td colSpan={9} className="px-6 py-4">
                          <div className="grid grid-cols-2 gap-6">
                            {/* CPU History Sparkline */}
                            <div>
                              <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">CPU 使用率履歴 (直近10サンプル)</p>
                              <div className="p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg">
                                <Sparkline values={agent.cpu_history.values} />
                                <div className="flex justify-between mt-1">
                                  <span className="text-[10px] text-[#3d5068]">最古</span>
                                  <span className="text-[10px] text-[#3d5068]">最新</span>
                                </div>
                              </div>
                            </div>
                            {/* Top Expensive Operations */}
                            <div>
                              <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">高コスト操作 Top 5</p>
                              <div className="space-y-1.5">
                                {agent.top_ops.map((op, i) => (
                                  <div key={op.name} className="flex items-center gap-3 px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-sm">
                                    <span className="text-xs font-bold text-[#3d5068] w-4">{i + 1}</span>
                                    <span className="flex-1 text-xs font-mono text-[#e2e8f4]">{op.name}</span>
                                    <span className="text-xs font-mono text-yellow-400">{op.avg_ms}ms</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Operations Breakdown */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
          <Zap className="w-5 h-5 text-[#e8002d]" />
          <h2 className="text-white font-semibold">オペレーション ブレークダウン</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['オペレーション名', '平均時間 (ms)', '呼び出し回数', 'P99 (ms)'].map(h => (
                  <th key={h} className="px-5 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {perf.operations.map(op => {
                const pct = Math.min((op.avg_duration_ms / 120) * 100, 100)
                const barColor = op.avg_duration_ms > 50 ? 'bg-[#e8002d]' : op.avg_duration_ms > 20 ? 'bg-yellow-400' : 'bg-[#00c853]'
                return (
                  <tr key={op.name} className="hover:bg-[#111827] transition-colors">
                    <td className="px-5 py-3 font-mono text-sm text-[#e2e8f4]">{op.name}</td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-3">
                        <div className="w-24 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${barColor}`} style={{ width: `${pct}%` }} />
                        </div>
                        <span className="font-mono text-sm text-[#e2e8f4]">{op.avg_duration_ms}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3 font-mono text-sm text-[#7d92b0]">{(op.call_count ?? 0).toLocaleString()}</td>
                    <td className="px-5 py-3 font-mono text-sm text-[#7d92b0]">{op.p99_ms}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  )
}
