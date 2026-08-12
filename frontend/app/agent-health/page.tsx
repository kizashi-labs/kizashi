'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { apiFetch } from '@/lib/api'
import {
  Activity, Server, WifiOff, AlertTriangle, Cpu, MemoryStick,
  RefreshCw, ExternalLink, RotateCcw, LayoutGrid, List, HardDrive,
  ChevronDown,
} from 'lucide-react'
import Link from 'next/link'

// ── Types ─────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  ip_address?: string
  os?: string
  status: 'online' | 'offline' | 'warning'
  last_seen?: string
  version?: string
  cpu_usage?: number
  memory_usage?: number
  disk_usage?: number
}

interface AgentResource {
  cpu_usage?: number
  memory_usage?: number
  disk_usage?: number
}

interface AlertItem {
  id: string
  agent_id?: string
  created_at: string
}

interface AgentWithScore extends Agent {
  healthScore: number
  cpu: number
  mem: number
  disk: number
}

type ViewMode = 'list' | 'grid'
type HealthFilter = 'all' | 'healthy' | 'warning' | 'critical'
type SortField = 'health_score' | 'hostname' | 'last_seen' | 'cpu'

// ── Helpers ───────────────────────────────────────────────────────

function formatTs(iso?: string): string {
  if (!iso) return '不明'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

function minutesSince(iso?: string): number {
  if (!iso) return Infinity
  try {
    return (Date.now() - new Date(iso).getTime()) / 60_000
  } catch {
    return Infinity
  }
}

function timeAgo(iso?: string): string {
  if (!iso) return '不明'
  const mins = minutesSince(iso)
  if (!isFinite(mins)) return '不明'
  if (mins < 1) return 'たった今'
  if (mins < 60) return `${Math.floor(mins)}分前`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}時間前`
  return `${Math.floor(hrs / 24)}日前`
}

function calcHealthScore(agent: Agent): number {
  const cpu = agent.cpu_usage ?? 0
  const mem = agent.memory_usage ?? 0
  const late = minutesSince(agent.last_seen) > 5 ? 50 : 0
  return Math.max(0, Math.round(100 - cpu / 2 - mem / 3 - late))
}

function healthColor(score: number): string {
  if (score >= 80) return '#00e676'
  if (score >= 60) return '#ff9800'
  return '#e8002d'
}

function healthBg(score: number): string {
  if (score >= 80) return 'bg-green-900/30 text-green-400'
  if (score >= 60) return 'bg-yellow-900/30 text-yellow-400'
  return 'bg-red-900/30 text-red-400'
}

function healthLabel(score: number): HealthFilter {
  if (score >= 80) return 'healthy'
  if (score >= 60) return 'warning'
  return 'critical'
}

function statusBadge(status: string) {
  if (status === 'online')  return 'bg-green-900/40 text-green-400 border border-green-700/50'
  if (status === 'offline') return 'bg-red-900/40 text-red-400 border border-red-700/50'
  return 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/50'
}

function statusLabel(status: string) {
  if (status === 'online')  return 'オンライン'
  if (status === 'offline') return 'オフライン'
  return '警告'
}

// Mock historical data: generate 12 time points relative to current counts
function buildHistoricalData(onlineCount: number, offlineCount: number, warningCount: number) {
  const now = Date.now()
  return Array.from({ length: 12 }, (_, i) => {
    const t = new Date(now - (11 - i) * 5 * 60_000)
    return {
      time: t.toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }),
      online: onlineCount,
      offline: offlineCount,
      warning: warningCount,
    }
  })
}

// CPU/Memory histogram buckets
function buildHistogram(agents: Agent[], field: 'cpu_usage' | 'memory_usage') {
  const buckets = [
    { label: '0-25%', count: 0 },
    { label: '25-50%', count: 0 },
    { label: '50-75%', count: 0 },
    { label: '75-100%', count: 0 },
  ]
  for (const a of agents) {
    const v = a[field] ?? 0
    if (v < 25) buckets[0].count++
    else if (v < 50) buckets[1].count++
    else if (v < 75) buckets[2].count++
    else buckets[3].count++
  }
  return buckets
}

// ── Mini Arc Gauge ─────────────────────────────────────────────────

function MiniGauge({ value, label, size = 56 }: { value: number; label: string; size?: number }) {
  const r = size * 0.38
  const cx = size / 2
  const cy = size / 2
  const circumference = Math.PI * r // half circle
  const used = (value / 100) * circumference
  const color = value > 90 ? '#e8002d' : value > 70 ? '#f59e0b' : '#22c55e'
  return (
    <div className="flex flex-col items-center gap-0.5">
      <svg width={size} height={size * 0.6} viewBox={`0 0 ${size} ${size * 0.6}`}>
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="#1e2d42"
          strokeWidth="4"
        />
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeDasharray={`${used} ${circumference}`}
        />
        <text
          x={cx}
          y={cy - 2}
          textAnchor="middle"
          fill="white"
          fontSize={size * 0.22}
          fontWeight="bold"
        >
          {value}%
        </text>
      </svg>
      <span className="text-[#7d92b0] text-xs">{label}</span>
    </div>
  )
}

// ── Agent Card (Grid View) ─────────────────────────────────────────

function AgentCard({ agent }: { agent: AgentWithScore }) {
  const score = agent.healthScore
  const scoreColor = healthColor(score)
  return (
    <Link
      href={`/endpoints/${agent.id}`}
      className="block bg-[#0d1b2e] border border-[#1e3050] rounded-xl p-4 hover:border-blue-600/50 hover:bg-[#0f2040] transition-all group"
    >
      {/* Header row */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0">
          <p className="font-bold text-sm text-white truncate group-hover:text-blue-300 transition-colors">
            {agent.hostname || '—'}
          </p>
          {agent.os && (
            <span className="inline-block mt-1 px-1.5 py-0.5 text-[10px] bg-[#1e2d42] text-[#7d92b0] rounded font-mono">
              {agent.os}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5 ml-2 flex-shrink-0">
          <span
            className={`w-2 h-2 rounded-full flex-shrink-0 ${
              agent.status === 'online' ? 'bg-green-400' :
              agent.status === 'offline' ? 'bg-red-400' : 'bg-yellow-400'
            }`}
          />
          <span
            className="text-[10px] font-bold px-1.5 py-0.5 rounded"
            style={{ color: scoreColor, background: `${scoreColor}22` }}
          >
            {score}
          </span>
        </div>
      </div>

      {/* Gauges row */}
      <div className="flex items-end justify-around py-2">
        <MiniGauge value={agent.cpu} label="CPU" size={52} />
        <MiniGauge value={agent.mem} label="MEM" size={52} />
        <MiniGauge value={agent.disk} label="DISK" size={52} />
      </div>

      {/* Footer */}
      <div className="mt-2 pt-2 border-t border-[#1e3050]">
        <p className="text-[10px] text-[#7d92b0] truncate">
          最終確認: {timeAgo(agent.last_seen)}
        </p>
      </div>
    </Link>
  )
}

// ── Toast ─────────────────────────────────────────────────────────

interface ToastMsg { id: number; text: string; type: 'success' | 'info' | 'error' }

function Toast({ toasts, onDismiss }: { toasts: ToastMsg[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`flex items-center gap-3 px-4 py-3 rounded-lg shadow-xl text-sm font-medium border ${
            t.type === 'success' ? 'bg-green-900/80 text-green-300 border-green-700' :
            t.type === 'error'   ? 'bg-red-900/80 text-red-300 border-red-700' :
                                   'bg-blue-900/80 text-blue-300 border-blue-700'
          }`}
        >
          <span>{t.text}</span>
          <button onClick={() => onDismiss(t.id)} className="opacity-60 hover:opacity-100 transition-opacity">✕</button>
        </div>
      ))}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────

export default function AgentHealthPage() {
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date())
  const [toasts, setToasts] = useState<ToastMsg[]>([])
  const [toastCounter, setToastCounter] = useState(0)
  const [viewMode, setViewMode] = useState<ViewMode>('list')
  const [healthFilter, setHealthFilter] = useState<HealthFilter>('all')
  const [sortField, setSortField] = useState<SortField>('health_score')

  const addToast = useCallback((text: string, type: ToastMsg['type'] = 'info') => {
    const id = toastCounter + 1
    setToastCounter(id)
    setToasts(prev => [...prev, { id, text, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }, [toastCounter])

  const dismissToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  // ── Agents query ─────────────────────────────────────────────
  const { data: agentsData, isLoading: agentsLoading, dataUpdatedAt, refetch: refetchAgents } =
    useQuery<{ agents?: Agent[]; data?: Agent[]; items?: Agent[] }>({
      queryKey: ['agent-health-agents'],
      queryFn: () => apiFetch('/api/v1/agents?limit=500'),
      refetchInterval: 30_000,
    })

  useEffect(() => {
    if (dataUpdatedAt) setLastUpdated(new Date(dataUpdatedAt))
  }, [dataUpdatedAt])

  const agents: Agent[] = agentsData?.agents ?? agentsData?.data ?? agentsData?.items ?? []

  // ── Alerts query (for alerts-by-agent chart) ──────────────────
  const { data: alertsData } = useQuery<{ data?: AlertItem[]; items?: AlertItem[] }>({
    queryKey: ['agent-health-alerts'],
    queryFn: () => apiFetch('/api/v1/alerts?limit=1000'),
    refetchInterval: 30_000,
  })
  const alerts: AlertItem[] = alertsData?.data ?? alertsData?.items ?? []

  // ── Per-agent resources (first 10 in parallel) ─────────────────
  const first10 = agents.slice(0, 10)
  const { data: resourcesMap } = useQuery<Record<string, AgentResource>>({
    queryKey: ['agent-health-resources', first10.map(a => a.id).join(',')],
    queryFn: async () => {
      const results = await Promise.allSettled(
        first10.map(a => apiFetch<AgentResource>(`/api/v1/agents/${a.id}/resources`))
      )
      const map: Record<string, AgentResource> = {}
      results.forEach((r, i) => {
        if (r.status === 'fulfilled') map[first10[i].id] = r.value
      })
      return map
    },
    enabled: first10.length > 0,
    refetchInterval: 30_000,
    retry: false,
  })

  // Merge resource data into agents
  const enrichedAgents: Agent[] = agents.map(a => {
    const res = resourcesMap?.[a.id]
    if (!res) return a
    return {
      ...a,
      cpu_usage: res.cpu_usage ?? a.cpu_usage,
      memory_usage: res.memory_usage ?? a.memory_usage,
      disk_usage: res.disk_usage ?? a.disk_usage,
    }
  })

  // ── Derived counts ────────────────────────────────────────────
  const onlineAgents  = enrichedAgents.filter(a => a.status === 'online')
  const offlineAgents = enrichedAgents.filter(a => a.status === 'offline')
  const warningAgents = enrichedAgents.filter(a => a.status === 'warning')

  const avgCpu = onlineAgents.length > 0
    ? Math.round(onlineAgents.reduce((s, a) => s + (a.cpu_usage ?? 0), 0) / onlineAgents.length)
    : 0
  const avgMem = onlineAgents.length > 0
    ? Math.round(onlineAgents.reduce((s, a) => s + (a.memory_usage ?? 0), 0) / onlineAgents.length)
    : 0

  // ── Health-scored agents ──────────────────────────────────────
  const scoredAgents: AgentWithScore[] = enrichedAgents.map(a => ({
    ...a,
    healthScore: calcHealthScore(a),
    cpu: a.cpu_usage ?? 0,
    mem: a.memory_usage ?? 0,
    disk: a.disk_usage ?? 0,
  }))

  // ── Health stat counts ────────────────────────────────────────
  const healthyCnt  = scoredAgents.filter(a => healthLabel(a.healthScore) === 'healthy').length
  const warningCnt  = scoredAgents.filter(a => healthLabel(a.healthScore) === 'warning').length
  const criticalCnt = scoredAgents.filter(a => healthLabel(a.healthScore) === 'critical').length
  const offlineCnt  = offlineAgents.length

  // ── Filter ────────────────────────────────────────────────────
  const filteredAgents: AgentWithScore[] = scoredAgents.filter(a => {
    if (healthFilter === 'all') return true
    return healthLabel(a.healthScore) === healthFilter
  })

  // ── Sort ──────────────────────────────────────────────────────
  const sortedAgents: AgentWithScore[] = [...filteredAgents].sort((a, b) => {
    switch (sortField) {
      case 'health_score': return a.healthScore - b.healthScore
      case 'hostname':     return (a.hostname ?? '').localeCompare(b.hostname ?? '')
      case 'last_seen':    return minutesSince(a.last_seen) - minutesSince(b.last_seen)
      case 'cpu':          return b.cpu - a.cpu
      default:             return 0
    }
  })

  // ── Chart data ────────────────────────────────────────────────
  const histData = buildHistoricalData(onlineAgents.length, offlineAgents.length, warningAgents.length)
  const cpuHistogram = buildHistogram(onlineAgents, 'cpu_usage')
  const memHistogram = buildHistogram(onlineAgents, 'memory_usage')

  const distData = cpuHistogram.map((b, i) => ({
    label: b.label,
    cpu: b.count,
    mem: memHistogram[i].count,
  }))

  // Alerts by agent (last 24h, top 10)
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000
  const agentAlertCount: Record<string, number> = {}
  for (const al of alerts) {
    const ago = al.agent_id && new Date(al.created_at).getTime() > oneDayAgo
    if (ago && al.agent_id) {
      agentAlertCount[al.agent_id] = (agentAlertCount[al.agent_id] ?? 0) + 1
    }
  }
  const alertsByAgent = Object.entries(agentAlertCount)
    .map(([agentId, count]) => {
      const agent = enrichedAgents.find(a => a.id === agentId)
      return { name: agent?.hostname ?? agentId.slice(0, 8), count }
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  const summaryCards = [
    {
      label: 'オンライン',
      value: onlineAgents.length,
      icon: Server,
      color: 'text-green-400',
      badge: 'bg-green-900/40 text-green-400 border border-green-700/50',
    },
    {
      label: 'オフライン',
      value: offlineAgents.length,
      icon: WifiOff,
      color: 'text-red-400',
      badge: 'bg-red-900/40 text-red-400 border border-red-700/50',
    },
    {
      label: '警告',
      value: warningAgents.length,
      icon: AlertTriangle,
      color: 'text-yellow-400',
      badge: 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/50',
    },
    {
      label: '平均CPU使用率',
      value: `${avgCpu}%`,
      icon: Cpu,
      color: 'text-blue-400',
      badge: 'bg-blue-900/40 text-blue-400 border border-blue-700/50',
    },
    {
      label: '平均メモリ使用率',
      value: `${avgMem}%`,
      icon: MemoryStick,
      color: 'text-purple-400',
      badge: 'bg-purple-900/40 text-purple-400 border border-purple-700/50',
    },
  ]

  const tooltipStyle = {
    contentStyle: { backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px', fontSize: '11px' },
    labelStyle: { color: '#e5e7eb' },
  }

  const healthFilterChips: { key: HealthFilter; label: string; count: number; color: string }[] = [
    { key: 'all',      label: 'すべて',    count: scoredAgents.length, color: 'text-gray-300 bg-gray-700/60 border-gray-600' },
    { key: 'healthy',  label: '正常',      count: healthyCnt,          color: 'text-green-400 bg-green-900/30 border-green-700/50' },
    { key: 'warning',  label: '警告',      count: warningCnt,          color: 'text-yellow-400 bg-yellow-900/30 border-yellow-700/50' },
    { key: 'critical', label: 'クリティカル', count: criticalCnt,       color: 'text-red-400 bg-red-900/30 border-red-700/50' },
  ]

  const sortOptions: { value: SortField; label: string }[] = [
    { value: 'health_score', label: '健全性スコア（昇順）' },
    { value: 'hostname',     label: 'ホスト名（A-Z）' },
    { value: 'last_seen',    label: '最終確認（新しい順）' },
    { value: 'cpu',          label: 'CPU使用率（高い順）' },
  ]

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <Toast toasts={toasts} onDismiss={dismissToast} />

      {/* ── Header ──────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-3">
          <Activity className="w-6 h-6 text-blue-400 flex-shrink-0" />
          <div>
            <h1 className="text-xl font-bold text-white">エージェント健全性ダッシュボード</h1>
            <p className="text-xs text-gray-500 mt-0.5">
              最終更新: {lastUpdated.toLocaleTimeString('ja-JP')}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-blue-900/40 text-blue-300 border border-blue-700/50">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
            30秒ごとに自動更新
          </span>
          <button
            onClick={() => refetchAgents()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700 hover:text-white transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
        </div>
      </div>

      {/* ── Loading skeleton ─────────────────────────────────────── */}
      {agentsLoading && (
        <div className="space-y-4 animate-pulse">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="h-24 bg-gray-800 rounded-xl border border-gray-700" />
            ))}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="h-64 bg-gray-800 rounded-xl border border-gray-700" />
            <div className="h-64 bg-gray-800 rounded-xl border border-gray-700" />
          </div>
          <div className="h-96 bg-gray-800 rounded-xl border border-gray-700" />
        </div>
      )}

      {!agentsLoading && (
        <>
          {/* ── Health stat chips row ────────────────────────────── */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            <div className="bg-gray-800 rounded-xl border border-green-800/40 p-3 flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-green-400 flex-shrink-0" />
              <div>
                <p className="text-xs text-gray-400">正常</p>
                <p className="text-xl font-bold text-green-400">{healthyCnt}</p>
              </div>
            </div>
            <div className="bg-gray-800 rounded-xl border border-yellow-800/40 p-3 flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-yellow-400 flex-shrink-0" />
              <div>
                <p className="text-xs text-gray-400">警告</p>
                <p className="text-xl font-bold text-yellow-400">{warningCnt}</p>
              </div>
            </div>
            <div className="bg-gray-800 rounded-xl border border-red-800/40 p-3 flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-red-400 flex-shrink-0" />
              <div>
                <p className="text-xs text-gray-400">クリティカル</p>
                <p className="text-xl font-bold text-red-400">{criticalCnt}</p>
              </div>
            </div>
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-3 flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-gray-500 flex-shrink-0" />
              <div>
                <p className="text-xs text-gray-400">オフライン</p>
                <p className="text-xl font-bold text-gray-400">{offlineCnt}</p>
              </div>
            </div>
          </div>

          {/* ── Summary cards ───────────────────────────────────── */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
            {summaryCards.map(card => {
              const Icon = card.icon
              return (
                <div key={card.label} className="bg-gray-800 rounded-xl border border-gray-700 p-4 flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <Icon className={`w-5 h-5 ${card.color}`} />
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${card.badge}`}>
                      {card.value}
                    </span>
                  </div>
                  <span className="text-xs text-gray-400 mt-1">{card.label}</span>
                  <span className={`text-2xl font-bold ${card.color}`}>{card.value}</span>
                </div>
              )
            })}
          </div>

          {/* ── Charts row ──────────────────────────────────────── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
            {/* Line chart: agent count over time */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-4">
              <h2 className="text-sm font-semibold text-gray-200 mb-4">エージェント数の推移（直近1時間）</h2>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={histData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                  <Tooltip {...tooltipStyle} cursor={{ stroke: '#4b5563' }} />
                  <Line type="monotone" dataKey="online"  name="オンライン"  stroke="#00e676" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="offline" name="オフライン" stroke="#e8002d" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="warning" name="警告"       stroke="#ff9800" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Bar chart: CPU/Memory distribution */}
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-4">
              <h2 className="text-sm font-semibold text-gray-200 mb-4">CPU・メモリ使用率分布（オンラインエージェント）</h2>
              {Object.keys(resourcesMap ?? {}).length === 0 && first10.length > 0 ? (
                <div className="flex flex-col items-center justify-center h-[200px] text-gray-500">
                  <Cpu className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-sm">リソースデータは利用できません</p>
                  <p className="text-xs mt-1 opacity-70">/api/v1/agents/&#123;id&#125;/resources が未実装です</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={distData} barCategoryGap="25%">
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                    <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                    <Tooltip {...tooltipStyle} cursor={{ fill: '#374151' }} />
                    <Bar dataKey="cpu" name="CPU" fill="#1a6bff" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="mem" name="メモリ" fill="#a855f7" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* ── View controls: filter chips + sort + view toggle ── */}
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            {/* Health filter chips */}
            <div className="flex flex-wrap items-center gap-2">
              {healthFilterChips.map(chip => (
                <button
                  key={chip.key}
                  onClick={() => setHealthFilter(chip.key)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all ${
                    healthFilter === chip.key
                      ? chip.color + ' ring-1 ring-current'
                      : 'text-gray-400 bg-gray-800 border-gray-700 hover:border-gray-500'
                  }`}
                >
                  {chip.label}
                  <span className={`ml-1 px-1.5 py-0.5 rounded-full text-[10px] font-bold ${
                    healthFilter === chip.key ? 'bg-white/20' : 'bg-gray-700'
                  }`}>
                    {chip.count}
                  </span>
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              {/* Sort dropdown */}
              <div className="relative">
                <select
                  value={sortField}
                  onChange={e => setSortField(e.target.value as SortField)}
                  className="appearance-none pl-3 pr-8 py-1.5 text-xs text-gray-300 bg-gray-800 border border-gray-700 rounded-lg hover:border-gray-500 focus:outline-none focus:border-blue-500 cursor-pointer"
                >
                  {sortOptions.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500 pointer-events-none" />
              </div>

              {/* View toggle */}
              <div className="flex items-center bg-gray-800 border border-gray-700 rounded-lg p-0.5">
                <button
                  onClick={() => setViewMode('list')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all ${
                    viewMode === 'list'
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  <List className="w-3.5 h-3.5" />
                  リスト
                </button>
                <button
                  onClick={() => setViewMode('grid')}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all ${
                    viewMode === 'grid'
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  <LayoutGrid className="w-3.5 h-3.5" />
                  グリッド
                </button>
              </div>
            </div>
          </div>

          {/* ── Grid View ────────────────────────────────────────── */}
          {viewMode === 'grid' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mb-6">
              {sortedAgents.length === 0 && (
                <div className="col-span-full py-16 text-center text-gray-500 text-sm bg-gray-800 rounded-xl border border-gray-700">
                  エージェントが見つかりません
                </div>
              )}
              {sortedAgents.map(agent => (
                <AgentCard key={agent.id} agent={agent} />
              ))}
            </div>
          )}

          {/* ── List View / Health score table ───────────────────── */}
          {viewMode === 'list' && (
            <div className="bg-gray-800 rounded-xl border border-gray-700 mb-6 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-200">
                  健全性スコア一覧
                </h2>
                <span className="text-xs text-gray-500">{sortedAgents.length} エージェント</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700 text-xs text-gray-400 text-left">
                      <th className="px-4 py-3 font-medium">ホスト名</th>
                      <th className="px-4 py-3 font-medium">IPアドレス</th>
                      <th className="px-4 py-3 font-medium">最終確認</th>
                      <th className="px-4 py-3 font-medium text-right">
                        <span className="inline-flex items-center gap-1"><Cpu className="w-3 h-3" />CPU%</span>
                      </th>
                      <th className="px-4 py-3 font-medium text-right">
                        <span className="inline-flex items-center gap-1"><MemoryStick className="w-3 h-3" />メモリ%</span>
                      </th>
                      <th className="px-4 py-3 font-medium text-right">
                        <span className="inline-flex items-center gap-1"><HardDrive className="w-3 h-3" />ディスク%</span>
                      </th>
                      <th className="px-4 py-3 font-medium text-right">健全性スコア</th>
                      <th className="px-4 py-3 font-medium">ステータス</th>
                      <th className="px-4 py-3 font-medium" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700/50">
                    {sortedAgents.length === 0 && (
                      <tr>
                        <td colSpan={9} className="px-4 py-10 text-center text-gray-500 text-sm">
                          エージェントが見つかりません
                        </td>
                      </tr>
                    )}
                    {sortedAgents.map(agent => (
                      <tr key={agent.id} className="hover:bg-gray-700/30 transition-colors">
                        <td className="px-4 py-3 font-mono text-xs text-gray-200 whitespace-nowrap">
                          {agent.hostname || '—'}
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-400 whitespace-nowrap">
                          {agent.ip_address || '—'}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">
                          {formatTs(agent.last_seen)}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <span className={`text-xs ${agent.cpu > 90 ? 'text-red-400' : agent.cpu > 70 ? 'text-yellow-400' : 'text-gray-300'}`}>
                            {agent.cpu.toFixed(1)}%
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <span className={`text-xs ${agent.mem > 90 ? 'text-red-400' : agent.mem > 70 ? 'text-yellow-400' : 'text-gray-300'}`}>
                            {agent.mem.toFixed(1)}%
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <span className={`text-xs ${agent.disk > 90 ? 'text-red-400' : agent.disk > 70 ? 'text-yellow-400' : 'text-gray-300'}`}>
                            {agent.disk.toFixed(1)}%
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <span
                            className={`inline-block px-2 py-0.5 rounded text-xs font-bold tabular-nums ${healthBg(agent.healthScore)}`}
                          >
                            {agent.healthScore}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${statusBadge(agent.status)}`}>
                            {statusLabel(agent.status)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <Link
                            href={`/endpoints/${agent.id}`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs text-blue-400 bg-blue-900/30 border border-blue-700/50 rounded hover:bg-blue-900/50 transition-colors whitespace-nowrap"
                          >
                            <ExternalLink className="w-3 h-3" />
                            詳細
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Offline agents card ──────────────────────────────── */}
          {offlineAgents.length > 0 && (
            <div className="bg-gray-800 rounded-xl border border-red-800/50 mb-6 overflow-hidden">
              <div className="px-4 py-3 border-b border-gray-700 flex items-center gap-2 bg-red-900/20">
                <WifiOff className="w-4 h-4 text-red-400" />
                <h2 className="text-sm font-semibold text-red-300">
                  オフラインエージェント ({offlineAgents.length})
                </h2>
              </div>
              <div className="divide-y divide-gray-700/50">
                {offlineAgents.map(agent => (
                  <div key={agent.id} className="flex items-center gap-4 px-4 py-3">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-200 truncate">
                        {agent.hostname || agent.id}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        最終確認: {formatTs(agent.last_seen)}
                        {agent.ip_address && ` · ${agent.ip_address}`}
                      </p>
                    </div>
                    <button
                      onClick={() => addToast(`再起動指示を送信しました: ${agent.hostname || agent.id}`, 'info')}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-orange-400 bg-orange-900/30 border border-orange-700/50 rounded-lg hover:bg-orange-900/50 transition-colors whitespace-nowrap"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      再起動指示
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── Alerts by agent chart ────────────────────────────── */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-4">
            <h2 className="text-sm font-semibold text-gray-200 mb-4">
              エージェント別アラート数（過去24時間 · 上位10件）
            </h2>
            {alertsByAgent.length === 0 ? (
              <div className="flex items-center justify-center h-40 text-gray-500 text-sm">
                過去24時間のアラートデータがありません
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={alertsByAgent} layout="vertical" margin={{ left: 20, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fontSize: 10, fill: '#9ca3af' }}
                    axisLine={false}
                    tickLine={false}
                    width={80}
                  />
                  <Tooltip {...tooltipStyle} cursor={{ fill: '#374151' }} />
                  <Bar dataKey="count" name="アラート数" radius={[0, 3, 3, 0]}>
                    {alertsByAgent.map((_, i) => (
                      <Cell key={i} fill={i < 3 ? '#e8002d' : i < 6 ? '#ff9800' : '#1a6bff'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </>
      )}
    </div>
  )
}
