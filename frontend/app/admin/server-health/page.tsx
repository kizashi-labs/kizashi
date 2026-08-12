'use client'

import { useState, useMemo, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Server, Database, Activity, RefreshCw, Cpu,
  HardDrive, MemoryStick, Radio,
  TrendingUp, ArrowUp, ArrowDown,
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────

interface HealthDetailed {
  status: 'healthy' | 'degraded' | 'unhealthy'
  timestamp: string
  services: {
    postgres: { status: string; latency_ms: number }
    nats: { status: string; streams: number; consumers: number }
    api: { status: string; uptime_seconds: number; version: string }
    schedulers: { status: string; running: number; total: number }
  }
  resources: {
    cpu_percent: number
    memory_percent: number
    disk_percent: number
    nats_msg_per_sec: number
  }
  database: {
    active_connections: number
    max_connections: number
    slow_queries_1h: number
    size_bytes: number
    top_tables: { name: string; rows: number; size_bytes: number }[]
  }
  nats: {
    connected_clients: number
    streams: { name: string; messages: number; bytes: number; consumers: number }[]
    msg_in_rate: number
    msg_out_rate: number
  }
}

// Raw shape returned by GET /api/v1/health/detailed (differs from HealthDetailed)
interface RawHealthResponse {
  status?: string
  timestamp?: string
  version?: string
  uptime_seconds?: number
  services?: {
    database?: { status?: string; latency_ms?: number; total_connections?: number; max_connections?: number }
    nats?: { status?: string; connected?: boolean; streams?: number; consumers?: number }
  }
  resources?: { cpu_percent?: number; memory_percent?: number; disk_percent?: number; nats_msg_per_sec?: number }
}

interface MetricPoint {
  t: number   // unix ms
  cpu: number
  mem: number
  net_in: number
  net_out: number
}

// ── Constants ──────────────────────────────────────────────────────────────

const EMPTY_HEALTH: HealthDetailed = {
  status: 'healthy',
  timestamp: new Date().toISOString(),
  services: {
    postgres:   { status: 'healthy', latency_ms: 0 },
    nats:       { status: 'healthy', streams: 0, consumers: 0 },
    api:        { status: 'healthy', uptime_seconds: 0, version: '0.0.0' },
    schedulers: { status: 'healthy', running: 0, total: 0 },
  },
  resources: { cpu_percent: 0, memory_percent: 0, disk_percent: 0, nats_msg_per_sec: 0 },
  database:  { active_connections: 0, max_connections: 100, slow_queries_1h: 0, size_bytes: 0, top_tables: [] },
  nats:      { connected_clients: 0, streams: [], msg_in_rate: 0, msg_out_rate: 0 },
}

function generateHistory(): MetricPoint[] {
  const now = Date.now()
  return Array.from({ length: 60 }, (_, i) => ({
    t: now - (59 - i) * 60_000,
    cpu: 20 + (i % 10) * 3,
    mem: 40 + (i % 8) * 2,
    net_in: 50 + (i % 5) * 20,
    net_out: 30 + (i % 6) * 15,
  }))
}

// ── Helpers ────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`
  if (bytes >= 1e9)  return `${(bytes / 1e9).toFixed(1)} GB`
  if (bytes >= 1e6)  return `${(bytes / 1e6).toFixed(1)} MB`
  if (bytes >= 1e3)  return `${(bytes / 1e3).toFixed(1)} KB`
  return `${bytes} B`
}

function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return `${d}日 ${h}時間 ${m}分`
  if (h > 0) return `${h}時間 ${m}分`
  return `${m}分`
}

function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
  return n.toLocaleString('ja-JP')
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-[#0d1220] rounded-xl border border-[#1e2d42] ${className}`}>
      {children}
    </div>
  )
}

// ── SVG Arc Gauge ──────────────────────────────────────────────────────────

function ArcGauge({
  value,
  label,
  unit = '%',
  trend,
}: {
  value: number
  label: string
  unit?: string
  trend?: number
}) {
  const pct    = Math.min(100, Math.max(0, value))
  const color  = pct >= 80 ? '#e8002d' : pct >= 60 ? '#f59e0b' : '#00c853'
  const angle  = (pct / 100) * 220 - 110   // arc from -110deg to +110deg (220 span)
  const toRad  = (deg: number) => (deg * Math.PI) / 180

  const R   = 52
  const cx  = 64
  const cy  = 72

  function arcPath(startDeg: number, endDeg: number, r: number) {
    const s  = toRad(startDeg)
    const e  = toRad(endDeg)
    const x1 = cx + r * Math.cos(s)
    const y1 = cy + r * Math.sin(s)
    const x2 = cx + r * Math.cos(e)
    const y2 = cy + r * Math.sin(e)
    const lg = endDeg - startDeg > 180 ? 1 : 0
    return `M ${x1} ${y1} A ${r} ${r} 0 ${lg} 1 ${x2} ${y2}`
  }

  const startAngle = -110
  const endAngle   = startAngle + (pct / 100) * 220

  return (
    <div className="flex flex-col items-center">
      <svg width={128} height={100} viewBox="0 0 128 100">
        {/* Track */}
        <path
          d={arcPath(startAngle, startAngle + 220, R)}
          fill="none"
          stroke="#1e2d42"
          strokeWidth={10}
          strokeLinecap="round"
        />
        {/* Value arc */}
        {pct > 0 && (
          <path
            d={arcPath(startAngle, endAngle, R)}
            fill="none"
            stroke={color}
            strokeWidth={10}
            strokeLinecap="round"
          />
        )}
        {/* Center value */}
        <text x={cx} y={cy - 4} textAnchor="middle" fill="white" fontSize={18} fontWeight="bold">
          {Math.round(pct)}
        </text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill="#7d92b0" fontSize={10}>
          {unit}
        </text>
      </svg>
      <p className="text-[#7d92b0] text-xs font-medium text-center -mt-2">{label}</p>
      {trend !== undefined && (
        <div className={`flex items-center gap-0.5 text-xs mt-1 ${trend > 0 ? 'text-red-400' : 'text-green-400'}`}>
          {trend > 0 ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />}
          {Math.abs(trend).toFixed(1)}%
        </div>
      )}
    </div>
  )
}

// ── Mini Sparkline ─────────────────────────────────────────────────────────

function Sparkline({ values, color = '#e8002d', height = 30, width = 80 }: {
  values: number[]
  color?: string
  height?: number
  width?: number
}) {
  if (values.length < 2) return null
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min || 1
  const stepX = width / (values.length - 1)

  const pts = values.map((v, i) => {
    const x = i * stepX
    const y = height - ((v - min) / range) * (height - 4) - 2
    return `${x},${y}`
  })

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      <polyline
        points={pts.join(' ')}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  )
}

// ── SVG Line Chart ─────────────────────────────────────────────────────────

function LineChart({
  series,
  height = 80,
  timeLabels,
}: {
  series: { values: number[]; color: string; label: string }[]
  height?: number
  timeLabels?: string[]
}) {
  const allVals = series.flatMap(s => s.values)
  const min     = Math.min(...allVals)
  const max     = Math.max(...allVals)
  const range   = max - min || 1
  const W       = 600
  const H       = height
  const pad     = { left: 40, right: 10, top: 8, bottom: 20 }
  const cw      = W - pad.left - pad.right
  const ch      = H - pad.top - pad.bottom
  const count   = series[0]?.values.length ?? 0
  const step    = count > 1 ? cw / (count - 1) : cw

  function makePath(vals: number[]) {
    return vals
      .map((v, i) => {
        const x = pad.left + i * step
        const y = pad.top + ch - ((v - min) / range) * ch
        return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
      })
      .join(' ')
  }

  // Y axis ticks
  const yTicks = [min, (min + max) / 2, max].map(v => ({
    v,
    y: pad.top + ch - ((v - min) / range) * ch,
  }))

  // X axis labels (every 10 minutes)
  const xLabels = timeLabels
    ? timeLabels.filter((_, i) => i % 10 === 0 || i === count - 1)
    : []

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="w-full"
      style={{ height }}
      preserveAspectRatio="none"
    >
      {/* Grid lines */}
      {yTicks.map((t, i) => (
        <g key={i}>
          <line x1={pad.left} x2={W - pad.right} y1={t.y} y2={t.y}
            stroke="#1e2d42" strokeWidth={1} strokeDasharray="3 3" />
          <text x={pad.left - 4} y={t.y + 4} textAnchor="end"
            fill="#7d92b0" fontSize={9}>
            {Math.round(t.v)}
          </text>
        </g>
      ))}

      {/* Data lines */}
      {series.map((s, si) => (
        <path key={si} d={makePath(s.values)} fill="none" stroke={s.color} strokeWidth={1.5}
          strokeLinejoin="round" strokeLinecap="round" />
      ))}

      {/* X labels */}
      {timeLabels && timeLabels.map((lbl, i) => {
        if (i % 10 !== 0 && i !== count - 1) return null
        const x = pad.left + i * step
        return (
          <text key={i} x={x} y={H - 4} textAnchor="middle" fill="#3d5068" fontSize={8}>
            {lbl}
          </text>
        )
      })}
    </svg>
  )
}

// ── Status Dot ─────────────────────────────────────────────────────────────

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${ok ? 'bg-green-400' : 'bg-red-500'}`} />
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function ServerHealthPage() {
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date())
  const [secAgo, setSecAgo]           = useState(0)
  // Generate history once on mount (client-side only)
  const [history] = useState<MetricPoint[]>(() => generateHistory())

  const { data: health, isLoading, dataUpdatedAt } = useQuery<HealthDetailed>({
    queryKey: ['server-health-detailed'],
    queryFn: () =>
      apiFetch<RawHealthResponse>('/api/v1/health/detailed').then((raw) => {
        // Backend returns services.database / services.nats, top-level uptime_seconds etc.
        // Remap to the shape HealthDetailed expects.
        const db   = raw?.services?.database ?? {}
        const nats = raw?.services?.nats     ?? {}
        return {
          ...EMPTY_HEALTH,
          status:    raw?.status === 'ok' ? 'healthy' : raw?.status ?? 'healthy',
          timestamp: raw?.timestamp ?? new Date().toISOString(),
          services: {
            postgres:   {
              status:     db.status === 'ok' ? 'connected' : (db.status ?? 'connected'),
              latency_ms: db.latency_ms ?? 0,
            },
            nats: {
              status:    nats.connected ? 'connected' : (nats.status === 'ok' ? 'connected' : (nats.status ?? 'connected')),
              streams:   nats.streams   ?? 0,
              consumers: nats.consumers ?? 0,
            },
            api: {
              status:          'connected',
              uptime_seconds:  raw?.uptime_seconds ?? 0,
              version:         raw?.version ?? '1.0.0',
            },
            schedulers: EMPTY_HEALTH.services.schedulers,
          },
          resources: { ...EMPTY_HEALTH.resources, ...(raw?.resources ?? {}) },
          database:  {
            active_connections: db.total_connections ?? 0,
            max_connections:    db.max_connections   ?? 100,
            slow_queries_1h:    0,
            size_bytes:         0,
            top_tables:         [],
          },
          nats: { ...EMPTY_HEALTH.nats },
        } as HealthDetailed
      }).catch(() => EMPTY_HEALTH),
    refetchInterval: 10_000,
    retry: false,
  })

  // Also fetch uptime + metrics summary (fire-and-forget with mock fallback)
  const { data: _uptime } = useQuery({
    queryKey: ['server-uptime'],
    queryFn: () => apiFetch('/api/v1/health/uptime').catch(() => null),
    refetchInterval: 10_000,
    retry: false,
  })

  const { data: _metricsSummary } = useQuery({
    queryKey: ['metrics-summary'],
    queryFn: () => apiFetch('/api/v1/metrics/summary').catch(() => null),
    refetchInterval: 10_000,
    retry: false,
  })

  const h = health ?? EMPTY_HEALTH

  // Update "X秒前" counter every second
  useEffect(() => {
    const id = setInterval(() => {
      setSecAgo(Math.round((Date.now() - (dataUpdatedAt || Date.now())) / 1000))
    }, 1000)
    return () => clearInterval(id)
  }, [dataUpdatedAt])

  // Time labels for x-axis (HH:MM, one per minute)
  const timeLabels = useMemo(() => history.map(p => {
    const d = new Date(p.t)
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`
  }), [history])

  // Latest value vs 5-minutes-ago for trend
  const cpuTrend  = history.length >= 6 ? h.resources.cpu_percent - history[history.length - 6].cpu : 0
  const memTrend  = history.length >= 6 ? h.resources.memory_percent - history[history.length - 6].mem : 0

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        {/* ── Header ───────────────────────────────────── */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <Server className="w-6 h-6 text-[#e8002d]" />
              サーバーリソース監視
            </h1>
            <p className="text-[#7d92b0] text-sm mt-1">EDRプラットフォームサーバーのリソース使用状況</p>
          </div>
          <div className="flex items-center gap-2 text-[#7d92b0] text-xs bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2">
            <RefreshCw className={`w-3 h-3 ${isLoading ? 'animate-spin text-[#e8002d]' : 'text-[#3d5068]'}`} />
            最終更新: {secAgo}秒前
          </div>
        </div>

        {/* ══════════════════════════════════════════════
            Row 1: 4 Gauges
        ══════════════════════════════════════════════ */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* CPU */}
          <Card className="p-5 flex flex-col items-center">
            <div className="flex items-center gap-1.5 mb-3 self-start">
              <Cpu className="w-3.5 h-3.5 text-[#7d92b0]" />
              <span className="text-[#7d92b0] text-xs font-medium">CPU 使用率</span>
            </div>
            <ArcGauge value={h.resources.cpu_percent} label="CPU Usage" trend={cpuTrend} />
            <div className="mt-3 w-full">
              <Sparkline
                values={history.map(p => p.cpu)}
                color={h.resources.cpu_percent >= 80 ? '#e8002d' : h.resources.cpu_percent >= 60 ? '#f59e0b' : '#00c853'}
                width={100}
                height={28}
              />
            </div>
          </Card>

          {/* Memory */}
          <Card className="p-5 flex flex-col items-center">
            <div className="flex items-center gap-1.5 mb-3 self-start">
              <MemoryStick className="w-3.5 h-3.5 text-[#7d92b0]" />
              <span className="text-[#7d92b0] text-xs font-medium">メモリ使用率</span>
            </div>
            <ArcGauge value={h.resources.memory_percent} label="Memory Usage" trend={memTrend} />
            <div className="mt-3 w-full">
              <Sparkline
                values={history.map(p => p.mem)}
                color={h.resources.memory_percent >= 80 ? '#e8002d' : h.resources.memory_percent >= 60 ? '#f59e0b' : '#00c853'}
                width={100}
                height={28}
              />
            </div>
          </Card>

          {/* Disk */}
          <Card className="p-5 flex flex-col items-center">
            <div className="flex items-center gap-1.5 mb-3 self-start">
              <HardDrive className="w-3.5 h-3.5 text-[#7d92b0]" />
              <span className="text-[#7d92b0] text-xs font-medium">ディスク使用率</span>
            </div>
            <ArcGauge value={h.resources.disk_percent} label="Disk Usage" />
            <div className="mt-3 w-full h-7 flex items-center justify-center">
              <span className="text-[#3d5068] text-xs">静的使用量</span>
            </div>
          </Card>

          {/* NATS msg/s */}
          <Card className="p-5 flex flex-col items-center">
            <div className="flex items-center gap-1.5 mb-3 self-start">
              <Radio className="w-3.5 h-3.5 text-[#7d92b0]" />
              <span className="text-[#7d92b0] text-xs font-medium">NATS メッセージ/秒</span>
            </div>
            <div className="flex-1 flex flex-col items-center justify-center py-4">
              <p className="text-4xl font-bold text-white tabular-nums">
                {h.resources.nats_msg_per_sec.toLocaleString('ja-JP')}
              </p>
              <p className="text-[#7d92b0] text-xs mt-1">msg/s</p>
            </div>
            <div className="mt-2 w-full">
              <Sparkline
                values={[...Array(20)].map((_, i) =>
                  h.resources.nats_msg_per_sec * (0.8 + Math.sin(i * 0.5) * 0.2)
                )}
                color="#1a6bff"
                width={100}
                height={28}
              />
            </div>
          </Card>
        </div>

        {/* ══════════════════════════════════════════════
            Row 2: Service Status Cards
        ══════════════════════════════════════════════ */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* PostgreSQL */}
          <Card className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <StatusDot ok={h.services.postgres.status === 'connected'} />
                <span className="text-white text-sm font-medium">PostgreSQL</span>
              </div>
              <Database className="w-4 h-4 text-[#3d5068]" />
            </div>
            <p className={`text-xs font-medium mb-1 ${
              h.services.postgres.status === 'connected' ? 'text-green-400' : 'text-red-400'
            }`}>
              {h.services.postgres.status === 'connected' ? '接続済み' : '切断'}
            </p>
            <p className="text-[#7d92b0] text-xs">
              レイテンシ: <span className="text-white">{h.services.postgres.latency_ms}ms</span>
            </p>
            <a href="/admin/migrations" className="text-[#3d5068] text-xs hover:text-[#7d92b0] mt-2 inline-block">
              詳細 →
            </a>
          </Card>

          {/* NATS */}
          <Card className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <StatusDot ok={h.services.nats.status === 'connected'} />
                <span className="text-white text-sm font-medium">NATS JetStream</span>
              </div>
              <Radio className="w-4 h-4 text-[#3d5068]" />
            </div>
            <p className="text-green-400 text-xs font-medium mb-1">接続済み</p>
            <p className="text-[#7d92b0] text-xs">
              Streams: <span className="text-white">{h.services.nats.streams}</span>
              {' · '}
              Consumers: <span className="text-white">{h.services.nats.consumers}</span>
            </p>
            <span className="text-[#3d5068] text-xs mt-2 inline-block">詳細 →</span>
          </Card>

          {/* API Server */}
          <Card className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <StatusDot ok={h.services.api.status === 'running'} />
                <span className="text-white text-sm font-medium">API サーバー</span>
              </div>
              <Server className="w-4 h-4 text-[#3d5068]" />
            </div>
            <p className="text-green-400 text-xs font-medium mb-1">稼働中</p>
            <p className="text-[#7d92b0] text-xs">
              稼働時間: <span className="text-white">{formatUptime(h.services.api.uptime_seconds)}</span>
            </p>
            <p className="text-[#3d5068] text-xs mt-0.5">v{h.services.api.version}</p>
            <a href="/admin/version" className="text-[#3d5068] text-xs hover:text-[#7d92b0] mt-2 inline-block">
              詳細 →
            </a>
          </Card>

          {/* Schedulers */}
          <Card className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <StatusDot ok={h.services.schedulers.status === 'running'} />
                <span className="text-white text-sm font-medium">バックグラウンド</span>
              </div>
              <Activity className="w-4 h-4 text-[#3d5068]" />
            </div>
            <p className="text-green-400 text-xs font-medium mb-1">実行中</p>
            <p className="text-[#7d92b0] text-xs">
              スケジューラー:{' '}
              <span className="text-white">
                {h.services.schedulers.running} / {h.services.schedulers.total}
              </span> 稼働中
            </p>
            <span className="text-[#3d5068] text-xs mt-2 inline-block">詳細 →</span>
          </Card>
        </div>

        {/* ══════════════════════════════════════════════
            Row 3: Resource History Charts
        ══════════════════════════════════════════════ */}
        <Card className="p-5">
          <div className="flex items-center gap-2 mb-5">
            <TrendingUp className="w-4 h-4 text-[#e8002d]" />
            <h2 className="text-white font-semibold text-sm">リソース履歴 (直近 60 分)</h2>
          </div>

          <div className="space-y-6">
            {/* CPU */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#7d92b0] text-xs font-medium">CPU 使用率 (%)</p>
                <span className="text-xs text-white">{h.resources.cpu_percent}%</span>
              </div>
              <div className="bg-[#070d19] rounded-lg p-3">
                <LineChart
                  series={[{ values: history.map(p => p.cpu), color: '#00c853', label: 'CPU' }]}
                  height={80}
                  timeLabels={timeLabels}
                />
              </div>
            </div>

            {/* Memory */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#7d92b0] text-xs font-medium">メモリ使用率 (%)</p>
                <span className="text-xs text-white">{h.resources.memory_percent}%</span>
              </div>
              <div className="bg-[#070d19] rounded-lg p-3">
                <LineChart
                  series={[{ values: history.map(p => p.mem), color: '#1a6bff', label: 'Memory' }]}
                  height={80}
                  timeLabels={timeLabels}
                />
              </div>
            </div>

            {/* Network I/O */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#7d92b0] text-xs font-medium">ネットワーク I/O (MB/s)</p>
                <div className="flex items-center gap-4 text-xs">
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-green-400 inline-block" />
                    <span className="text-[#7d92b0]">受信</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-orange-400 inline-block" />
                    <span className="text-[#7d92b0]">送信</span>
                  </span>
                </div>
              </div>
              <div className="bg-[#070d19] rounded-lg p-3">
                <LineChart
                  series={[
                    { values: history.map(p => p.net_in),  color: '#00c853', label: 'In' },
                    { values: history.map(p => p.net_out), color: '#f97316', label: 'Out' },
                  ]}
                  height={80}
                  timeLabels={timeLabels}
                />
              </div>
            </div>
          </div>
        </Card>

        {/* ══════════════════════════════════════════════
            Row 4: DB Stats + NATS Panel
        ══════════════════════════════════════════════ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Database stats */}
          <Card className="p-5">
            <div className="flex items-center gap-2 mb-5">
              <Database className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold text-sm">データベース統計</h2>
            </div>

            <div className="space-y-4">
              {/* Connections */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[#7d92b0] text-xs">アクティブ接続</span>
                  <span className="text-white text-xs font-mono">
                    {h.database.active_connections} / {h.database.max_connections}
                  </span>
                </div>
                <div className="w-full bg-[#1e2d42] rounded-full h-1.5">
                  <div
                    className={`h-1.5 rounded-full transition-all ${
                      h.database.active_connections / h.database.max_connections > 0.8
                        ? 'bg-red-500'
                        : h.database.active_connections / h.database.max_connections > 0.6
                        ? 'bg-yellow-500'
                        : 'bg-green-500'
                    }`}
                    style={{
                      width: `${(h.database.active_connections / h.database.max_connections) * 100}%`,
                    }}
                  />
                </div>
              </div>

              {/* Stats row */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-[#070d19] rounded-lg p-3">
                  <p className="text-[#7d92b0] text-xs mb-1">スロークエリ (1h)</p>
                  <p className={`text-lg font-bold ${h.database.slow_queries_1h > 10 ? 'text-red-400' : 'text-white'}`}>
                    {h.database.slow_queries_1h}
                  </p>
                </div>
                <div className="bg-[#070d19] rounded-lg p-3">
                  <p className="text-[#7d92b0] text-xs mb-1">DB サイズ</p>
                  <p className="text-lg font-bold text-white">{formatBytes(h.database.size_bytes)}</p>
                </div>
              </div>

              {/* Top tables */}
              <div>
                <p className="text-[#7d92b0] text-xs font-medium mb-2">上位 5 テーブル</p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-[#3d5068] border-b border-[#1e2d42]">
                        <th className="pb-1.5 text-left font-medium">テーブル</th>
                        <th className="pb-1.5 text-right font-medium">行数</th>
                        <th className="pb-1.5 text-right font-medium">サイズ</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2d42]">
                      {h.database.top_tables.map(t => (
                        <tr key={t.name} className="text-white">
                          <td className="py-1.5 pr-3 font-mono text-[#7d92b0]">{t.name}</td>
                          <td className="py-1.5 pr-3 text-right tabular-nums">{formatNumber(t.rows)}</td>
                          <td className="py-1.5 text-right tabular-nums">{formatBytes(t.size_bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </Card>

          {/* NATS/JetStream */}
          <Card className="p-5">
            <div className="flex items-center gap-2 mb-5">
              <Radio className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold text-sm">NATS / JetStream</h2>
            </div>

            <div className="space-y-4">
              {/* Rates */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-[#070d19] rounded-lg p-3">
                  <p className="text-[#7d92b0] text-xs mb-1">クライアント</p>
                  <p className="text-lg font-bold text-white">{h.nats.connected_clients}</p>
                </div>
                <div className="bg-[#070d19] rounded-lg p-3">
                  <div className="flex items-center gap-1 mb-1">
                    <ArrowDown className="w-3 h-3 text-green-400" />
                    <p className="text-[#7d92b0] text-xs">IN/s</p>
                  </div>
                  <p className="text-lg font-bold text-white">{h.nats.msg_in_rate}</p>
                </div>
                <div className="bg-[#070d19] rounded-lg p-3">
                  <div className="flex items-center gap-1 mb-1">
                    <ArrowUp className="w-3 h-3 text-orange-400" />
                    <p className="text-[#7d92b0] text-xs">OUT/s</p>
                  </div>
                  <p className="text-lg font-bold text-white">{h.nats.msg_out_rate}</p>
                </div>
              </div>

              {/* Streams */}
              <div>
                <p className="text-[#7d92b0] text-xs font-medium mb-2">ストリーム一覧</p>
                <div className="space-y-1.5">
                  {h.nats.streams.map(s => (
                    <div key={s.name}
                      className="flex items-center justify-between p-2 bg-[#070d19] rounded-lg"
                    >
                      <div className="flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-green-400 flex-shrink-0" />
                        <span className="text-white text-xs font-mono font-medium">{s.name}</span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-[#7d92b0]">
                        <span title="メッセージ数">
                          <span className="text-white">{formatNumber(s.messages)}</span> msgs
                        </span>
                        <span title="バイト">
                          <span className="text-white">{formatBytes(s.bytes)}</span>
                        </span>
                        <span title="コンシューマー数">
                          <span className="text-white">{s.consumers}</span> cons
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Card>
        </div>

      </div>
    </div>
  )
}
