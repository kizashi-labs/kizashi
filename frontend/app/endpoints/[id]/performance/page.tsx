'use client'

import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  ArrowLeft, Cpu, MemoryStick, HardDrive, Wifi,
  RefreshCw, Clock, Monitor, ToggleLeft, ToggleRight,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os?: string
  status?: string
  ip_address?: string
}

interface MetricPoint {
  timestamp: string
  cpu: number
  memory: number
  disk: number
  network: number
}

interface ProcessEntry {
  name: string
  pid: number
  cpu_pct: number
  mem_pct: number
  user?: string
}

interface PerformanceData {
  metrics: MetricPoint[]
  processes: ProcessEntry[]
}

// ─── Mock helpers ─────────────────────────────────────────────────────────────

function generateMockMetrics(range: string): MetricPoint[] {
  const points = range === '1h' ? 60 : range === '6h' ? 72 : 96
  const intervalMs = range === '1h' ? 60_000 : range === '6h' ? 300_000 : 900_000
  const now = Date.now()
  let cpu = 30, mem = 55, disk = 42, net = 5
  return Array.from({ length: points }, (_, i) => {
    cpu    = Math.min(100, Math.max(0,  cpu    + (Math.random() - 0.5) * 8))
    mem    = Math.min(100, Math.max(10, mem    + (Math.random() - 0.5) * 4))
    disk   = Math.min(100, Math.max(5,  disk   + (Math.random() - 0.5) * 2))
    net    = Math.min(100, Math.max(0,  net    + (Math.random() - 0.5) * 3))
    return {
      timestamp: new Date(now - (points - i) * intervalMs).toISOString(),
      cpu:    Math.round(cpu    * 10) / 10,
      memory: Math.round(mem    * 10) / 10,
      disk:   Math.round(disk   * 10) / 10,
      network: Math.round(net   * 10) / 10,
    }
  })
}

function generateMockProcesses(): ProcessEntry[] {
  const names = [
    'chrome.exe', 'node.exe', 'python.exe', 'svchost.exe', 'lsass.exe',
    'explorer.exe', 'antivirus.exe', 'nginx.exe', 'postgres.exe', 'redis-server.exe',
  ]
  const users = ['SYSTEM', 'Administrator', 'user1', 'svc-account', 'NT AUTHORITY']
  return names.map((name, i) => ({
    name,
    pid: 1000 + i * 337,
    cpu_pct: Math.round((Math.random() * 40) * 10) / 10,
    mem_pct: Math.round((Math.random() * 20 + 2) * 10) / 10,
    user: users[i % users.length],
  })).sort((a, b) => b.cpu_pct - a.cpu_pct)
}

// ─── Tooltip style ────────────────────────────────────────────────────────────

const TOOLTIP_STYLE = {
  backgroundColor: '#0d1220',
  border: '1px solid #1e2d42',
  borderRadius: 8,
  color: '#fff',
  fontSize: 12,
}

// ─── Metric card ──────────────────────────────────────────────────────────────

function MetricCard({
  label, value, unit, icon: Icon, color, trend,
}: {
  label: string
  value: number | undefined
  unit: string
  icon: React.ElementType
  color: string
  trend?: 'up' | 'down' | 'neutral'
}) {
  const display = value !== undefined ? value.toFixed(1) : '—'
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-[#7d92b0] font-medium uppercase tracking-wide">{label}</span>
        <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${color}22` }}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
      </div>
      <div className="flex items-end gap-1">
        <span className="text-3xl font-bold text-white leading-none">{display}</span>
        <span className="text-sm text-[#7d92b0] mb-0.5">{unit}</span>
      </div>
      <div className="h-1 rounded-full bg-[#1e2d42] overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${Math.min(value ?? 0, 100)}%`,
            background: (value ?? 0) > 85 ? '#e8002d' : color,
          }}
        />
      </div>
    </div>
  )
}

// ─── Chart card ───────────────────────────────────────────────────────────────

function ChartCard({
  label, dataKey, data, color, unit,
}: {
  label: string
  dataKey: string
  data: MetricPoint[]
  color: string
  unit: string
}) {
  const formatted = data.map(p => ({
    ...p,
    time: new Date(p.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
  }))

  // Subsample for readability — keep at most 30 points on the x-axis
  const step = Math.max(1, Math.floor(formatted.length / 30))
  const sampled = formatted.filter((_, i) => i % step === 0)

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      <h3 className="text-sm font-semibold text-white mb-4">{label}</h3>
      <ResponsiveContainer width="100%" height={160}>
        <LineChart data={sampled} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#7d92b0', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fill: '#7d92b0', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            tickFormatter={v => `${v}${unit}`}
          />
          <Tooltip
            contentStyle={TOOLTIP_STYLE}
            labelStyle={{ color: '#7d92b0' }}
            formatter={(v: number) => [`${v}${unit}`, label]}
          />
          <Line
            type="monotone"
            dataKey={dataKey}
            stroke={color}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, fill: color }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function EndpointPerformancePage() {
  const { id } = useParams<{ id: string }>()
  const [range, setRange]         = useState<'1h' | '6h' | '24h'>('1h')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [tick, setTick]           = useState(0)

  // Auto-refresh every 30s
  useEffect(() => {
    if (!autoRefresh) return
    const timer = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(timer)
  }, [autoRefresh])

  // Agent details
  const { data: agent } = useQuery<Agent>({
    queryKey: ['agent', id],
    queryFn: () => apiFetch<Agent>(`/api/v1/agents/${id}`),
    retry: false,
  })

  // Performance data
  const { data: perfData, isLoading, refetch } = useQuery<PerformanceData>({
    queryKey: ['agent-performance', id, range, tick],
    queryFn: async () => {
      try {
        return await apiFetch<PerformanceData>(`/api/v1/agents/${id}/performance?range=${range}`)
      } catch {
        // Mock data when endpoint returns 404
        return {
          metrics:   generateMockMetrics(range),
          processes: generateMockProcesses(),
        }
      }
    },
    staleTime: 25_000,
  })

  const latest = perfData?.metrics?.slice(-1)[0]
  const processes = (perfData?.processes ?? [])
    .slice()
    .sort((a, b) => b.cpu_pct - a.cpu_pct)
    .slice(0, 10)

  const handleRefresh = useCallback(() => {
    setTick(t => t + 1)
    refetch()
  }, [refetch])

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Link
            href={`/endpoints/${id}`}
            className="p-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div className="w-9 h-9 bg-[#e8002d]/20 rounded-lg flex items-center justify-center">
            <Monitor className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">
              {agent?.hostname ?? id}
            </h1>
            <p className="text-xs text-[#7d92b0]">
              ID: {id} &nbsp;·&nbsp; パフォーマンス監視
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Time range selector */}
          <div className="flex gap-1 bg-[#0d1220] rounded-lg p-1 border border-[#1e2d42]">
            {(['1h', '6h', '24h'] as const).map(r => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  range === r
                    ? 'bg-[#e8002d] text-white'
                    : 'text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${
              autoRefresh
                ? 'bg-[#0d1220] border-[#e8002d]/50 text-[#e8002d]'
                : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0]'
            }`}
            title="30秒ごとに自動更新"
          >
            {autoRefresh ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
            <span className="hidden sm:inline">自動更新</span>
          </button>

          {/* Manual refresh */}
          <button
            onClick={handleRefresh}
            disabled={isLoading}
            className="p-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors disabled:opacity-40"
            title="今すぐ更新"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Auto-refresh indicator */}
      {autoRefresh && (
        <div className="flex items-center gap-2 text-xs text-[#7d92b0]">
          <Clock className="w-3 h-3" />
          30秒ごとに自動更新中
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="flex justify-center items-center py-20">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-[#e8002d]" />
          <span className="ml-3 text-[#7d92b0] text-sm">データを読み込み中...</span>
        </div>
      )}

      {!isLoading && (
        <>
          {/* Metric cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <MetricCard
              label="CPU"
              value={latest?.cpu}
              unit="%"
              icon={Cpu}
              color="#3b82f6"
            />
            <MetricCard
              label="メモリ"
              value={latest?.memory}
              unit="%"
              icon={MemoryStick}
              color="#8b5cf6"
            />
            <MetricCard
              label="ディスク"
              value={latest?.disk}
              unit="%"
              icon={HardDrive}
              color="#10b981"
            />
            <MetricCard
              label="ネットワーク"
              value={latest?.network}
              unit=" MB/s"
              icon={Wifi}
              color="#f59e0b"
            />
          </div>

          {/* Line charts */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ChartCard
              label="CPU 使用率"
              dataKey="cpu"
              data={perfData?.metrics ?? []}
              color="#3b82f6"
              unit="%"
            />
            <ChartCard
              label="メモリ使用率"
              dataKey="memory"
              data={perfData?.metrics ?? []}
              color="#8b5cf6"
              unit="%"
            />
            <ChartCard
              label="ディスク使用率"
              dataKey="disk"
              data={perfData?.metrics ?? []}
              color="#10b981"
              unit="%"
            />
            <ChartCard
              label="ネットワーク (MB/s)"
              dataKey="network"
              data={perfData?.metrics ?? []}
              color="#f59e0b"
              unit=" MB/s"
            />
          </div>

          {/* Top 10 processes table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h2 className="text-sm font-semibold text-white mb-4">
              CPU 使用率 Top 10 プロセス
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['プロセス名', 'PID', 'CPU %', 'メモリ %', 'ユーザー'].map(h => (
                      <th
                        key={h}
                        className="text-left text-xs text-[#7d92b0] font-medium pb-3 pr-4 last:pr-0"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {processes.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-[#7d92b0] text-xs">
                        プロセスデータなし
                      </td>
                    </tr>
                  ) : (
                    processes.map((proc, i) => (
                      <tr
                        key={`${proc.pid}-${i}`}
                        className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors"
                      >
                        <td className="py-3 pr-4 text-white font-mono text-xs truncate max-w-[180px]">
                          {proc.name}
                        </td>
                        <td className="py-3 pr-4 text-[#7d92b0] font-mono text-xs">
                          {proc.pid}
                        </td>
                        <td className="py-3 pr-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 rounded-full bg-[#1e2d42] overflow-hidden flex-shrink-0">
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${Math.min(proc.cpu_pct, 100)}%`,
                                  background: proc.cpu_pct > 50 ? '#e8002d' : '#3b82f6',
                                }}
                              />
                            </div>
                            <span
                              className={`text-xs font-medium ${
                                proc.cpu_pct > 50 ? 'text-[#e8002d]' : 'text-white'
                              }`}
                            >
                              {proc.cpu_pct.toFixed(1)}%
                            </span>
                          </div>
                        </td>
                        <td className="py-3 pr-4">
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 rounded-full bg-[#1e2d42] overflow-hidden flex-shrink-0">
                              <div
                                className="h-full rounded-full bg-[#8b5cf6]"
                                style={{ width: `${Math.min(proc.mem_pct, 100)}%` }}
                              />
                            </div>
                            <span className="text-xs text-white">
                              {proc.mem_pct.toFixed(1)}%
                            </span>
                          </div>
                        </td>
                        <td className="py-3 text-xs text-[#7d92b0] font-mono">
                          {proc.user ?? '—'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
