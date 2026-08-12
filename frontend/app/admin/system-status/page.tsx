'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Server, RefreshCw, CheckCircle, XCircle, AlertTriangle,
  Database, Activity, Zap, HardDrive, Cpu, MemoryStick,
  Clock, TrendingUp, Trash2, Radio, ToggleLeft, ToggleRight
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

interface ServiceHealth {
  name: string
  status: 'healthy' | 'degraded' | 'down'
  uptime_seconds: number
  latency_ms: number
  version?: string
  last_check: string
}

interface SystemMetrics {
  goroutines: number
  memory_mb: number
  cache_hit_rate: number
  db_pool_used: number
  db_pool_total: number
  cpu_percent: number
  uptime_seconds: number
}

interface TableStat {
  table_name: string
  row_count: number
  total_size: string
  index_size: string
  seq_scans: number
  idx_scans: number
}

interface SystemStatus {
  services: ServiceHealth[]
  metrics: SystemMetrics
  tables: TableStat[]
}

const EMPTY_STATUS: SystemStatus = { services: [], metrics: { goroutines: 0, memory_mb: 0, cache_hit_rate: 0, db_pool_used: 0, db_pool_total: 0, cpu_percent: 0, uptime_seconds: 0 }, tables: [] }

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

const SERVICE_ICONS: Record<string, React.ElementType> = {
  'API Server': Server,
  'Database':   Database,
  'NATS':       Radio,
  'Frontend':   Activity,
}

const STATUS_CONFIG: Record<string, { badge: string; dot: string; icon: React.ElementType; label: string }> = {
  healthy:  { badge: 'bg-green-900/30 text-green-400 border border-green-700/30', dot: 'bg-green-400', icon: CheckCircle, label: '正常' },
  degraded: { badge: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/30', dot: 'bg-yellow-400', icon: AlertTriangle, label: '低下' },
  down:     { badge: 'bg-red-900/30 text-red-400 border border-red-700/30', dot: 'bg-red-500', icon: XCircle, label: '停止' },
}

// ── Service Card ───────────────────────────────────────────────────────────────

function ServiceCard({ svc }: { svc: ServiceHealth }) {
  const cfg = STATUS_CONFIG[svc.status]
  const Icon = SERVICE_ICONS[svc.name] ?? Server

  return (
    <div className={`bg-zinc-900 border rounded-xl p-5 ${svc.status === 'down' ? 'border-red-700/40' : svc.status === 'degraded' ? 'border-yellow-700/40' : 'border-zinc-700'}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center">
            <Icon className="h-5 w-5 text-zinc-400" />
          </div>
          <div>
            <div className="font-medium text-zinc-200">{svc.name}</div>
            {svc.version && <div className="text-xs text-zinc-600">{svc.version}</div>}
          </div>
        </div>
        <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg font-medium ${cfg.badge}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot} ${svc.status === 'healthy' ? 'animate-pulse' : ''}`} />
          {cfg.label}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center gap-1.5 text-zinc-500">
          <Clock className="h-3 w-3" />
          <span>稼働時間: <span className="text-zinc-300">{fmtUptime(svc.uptime_seconds)}</span></span>
        </div>
        <div className="flex items-center gap-1.5 text-zinc-500">
          <Zap className="h-3 w-3" />
          <span>レイテンシ: <span className={`font-medium ${svc.latency_ms > 100 ? 'text-yellow-400' : svc.latency_ms > 300 ? 'text-red-400' : 'text-green-400'}`}>{svc.latency_ms}ms</span></span>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function SystemStatusPage() {
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [flushResult, setFlushResult] = useState<{ success: boolean; message: string } | null>(null)

  const { data: status = EMPTY_STATUS, refetch, isFetching } = useQuery<SystemStatus>({
    queryKey: ['admin-system-status'],
    queryFn: async () => {
      try {
        const [rawData, dbRaw] = await Promise.all([
          apiFetch<Record<string, unknown>>('/api/v1/admin/system/status').catch(() => ({} as Record<string, unknown>)),
          apiFetch<{ table_sizes?: { table_name: string; row_count: number; total_bytes: number; index_bytes: number; seq_scans: number; idx_scans: number }[] }>('/api/v1/admin/system/db-stats').catch(() => ({ table_sizes: [] })),
        ])
        const raw = rawData as Record<string, unknown>
        const pool = (raw.db_pool_stats as Record<string, number> | undefined) ?? {}
        const cacheStats = (raw.cache_stats as Record<string, number> | undefined) ?? {}
        const rawServices = (raw.services as ServiceHealth[] | undefined) ?? []
        return {
          services: rawServices,
          metrics: {
            goroutines: (raw.goroutines as number) ?? 0,
            memory_mb: Math.round((raw.memory_mb as number) ?? 0),
            cache_hit_rate: Math.round((cacheStats.hit_rate as number) ?? 0),
            db_pool_used: pool.acquired_conns ?? 0,
            db_pool_total: pool.max_conns ?? 0,
            cpu_percent: Math.round((raw.cpu_percent as number) ?? 0),
            uptime_seconds: (raw.uptime_seconds as number) ?? 0,
          },
          tables: (dbRaw.table_sizes ?? []).map(t => ({
            table_name: t.table_name,
            row_count: t.row_count,
            total_size: `${Math.round(t.total_bytes / 1024 / 1024)} MB`,
            index_size: `${Math.round((t.index_bytes ?? 0) / 1024 / 1024)} MB`,
            seq_scans: t.seq_scans ?? 0,
            idx_scans: t.idx_scans ?? 0,
          })),
        }
      } catch { return EMPTY_STATUS }
    },
    refetchInterval: autoRefresh ? 30000 : false,
  })

  const flushMut = useMutation({
    mutationFn: () => apiFetch('/api/v1/admin/system/cache/flush', { method: 'POST' }),
    onSuccess: () => setFlushResult({ success: true, message: 'キャッシュをフラッシュしました。' }),
    onError: () => setFlushResult({ success: false, message: 'キャッシュのフラッシュに失敗しました。' }),
  })

  const { metrics, tables } = status

  const METRICS_CARDS = [
    { label: 'Goroutines', value: metrics.goroutines, icon: Cpu, color: 'text-blue-400', unit: '' },
    { label: 'メモリ使用量', value: metrics.memory_mb, icon: MemoryStick, color: 'text-purple-400', unit: ' MB' },
    { label: 'キャッシュヒット率', value: `${metrics.cache_hit_rate}%`, icon: TrendingUp, color: 'text-green-400', unit: '' },
    { label: 'DBプール', value: `${metrics.db_pool_used}/${metrics.db_pool_total}`, icon: Database, color: 'text-orange-400', unit: '' },
  ]

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-green-900/40 border border-green-700/40 flex items-center justify-center">
            <Server className="h-5 w-5 text-green-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">システムステータス</h1>
            <p className="text-sm text-zinc-400">サービスの健全性・パフォーマンス・データベース統計の監視</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Auto-refresh toggle */}
          <button onClick={() => setAutoRefresh(v => !v)}
            className="flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors">
            {autoRefresh ? <ToggleRight className="h-5 w-5 text-green-400" /> : <ToggleLeft className="h-5 w-5" />}
            自動更新 (30秒)
          </button>
          <button onClick={() => refetch()} disabled={isFetching}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg hover:bg-zinc-700 transition-colors text-zinc-300 disabled:opacity-50">
            <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* Service Health Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {status.services.map(svc => (
          <ServiceCard key={svc.name} svc={svc} />
        ))}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {METRICS_CARDS.map(m => (
          <div key={m.label} className="bg-zinc-900 border border-zinc-700 rounded-xl p-4 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-zinc-800 flex items-center justify-center">
              <m.icon className={`h-5 w-5 ${m.color}`} />
            </div>
            <div>
              <div className="text-xl font-bold text-zinc-100">{m.value}{m.unit}</div>
              <div className="text-xs text-zinc-500">{m.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Additional metrics */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-4">
          <div className="text-xs text-zinc-500 font-medium mb-2 uppercase tracking-wide">CPU使用率</div>
          <div className="flex items-center gap-3">
            <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
              <div className={`h-full rounded-full ${metrics.cpu_percent > 80 ? 'bg-red-500' : metrics.cpu_percent > 60 ? 'bg-yellow-500' : 'bg-blue-500'}`}
                style={{ width: `${metrics.cpu_percent}%` }} />
            </div>
            <span className="text-sm font-bold text-zinc-300 w-12 text-right">{metrics.cpu_percent}%</span>
          </div>
        </div>
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-4">
          <div className="text-xs text-zinc-500 font-medium mb-2 uppercase tracking-wide">システム稼働時間</div>
          <div className="text-xl font-bold text-zinc-100">{fmtUptime(metrics.uptime_seconds)}</div>
        </div>
      </div>

      {/* DB Stats + Cache Control */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* DB Table Stats */}
        <div className="lg:col-span-2 bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-zinc-700 bg-zinc-800/30">
            <h2 className="text-sm font-medium text-zinc-300 flex items-center gap-2">
              <Database className="h-4 w-4 text-zinc-500" />
              サイズ別上位テーブル
            </h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-700/50 bg-zinc-800/10">
                <th className="text-left px-5 py-2.5 text-xs text-zinc-500 font-medium">テーブル</th>
                <th className="text-right px-5 py-2.5 text-xs text-zinc-500 font-medium">行数</th>
                <th className="text-right px-5 py-2.5 text-xs text-zinc-500 font-medium">サイズ</th>
                <th className="text-right px-5 py-2.5 text-xs text-zinc-500 font-medium">インデックス</th>
                <th className="text-right px-5 py-2.5 text-xs text-zinc-500 font-medium">シーケンシャルスキャン</th>
                <th className="text-right px-5 py-2.5 text-xs text-zinc-500 font-medium">インデックススキャン</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/50">
              {tables.map(t => (
                <tr key={t.table_name} className="hover:bg-zinc-800/20 transition-colors">
                  <td className="px-5 py-2.5 font-mono text-xs text-zinc-300">{t.table_name}</td>
                  <td className="px-5 py-2.5 text-xs text-zinc-400 text-right">{(t.row_count ?? 0).toLocaleString()}</td>
                  <td className="px-5 py-2.5 text-xs text-zinc-400 text-right">{t.total_size}</td>
                  <td className="px-5 py-2.5 text-xs text-zinc-500 text-right">{t.index_size}</td>
                  <td className="px-5 py-2.5 text-xs text-right">
                    <span className={t.seq_scans > 500 ? 'text-yellow-400' : 'text-zinc-500'}>{(t.seq_scans ?? 0).toLocaleString()}</span>
                  </td>
                  <td className="px-5 py-2.5 text-xs text-zinc-400 text-right">{(t.idx_scans ?? 0).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Cache Control */}
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5">
          <h2 className="text-sm font-medium text-zinc-300 flex items-center gap-2 mb-4">
            <HardDrive className="h-4 w-4 text-zinc-500" />
            キャッシュ制御
          </h2>

          <div className="space-y-3 mb-5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-500">ヒット率</span>
              <span className="font-medium text-green-400">{metrics.cache_hit_rate}%</span>
            </div>
            <div className="w-full h-2 bg-zinc-800 rounded-full overflow-hidden">
              <div className="h-full rounded-full bg-green-500" style={{ width: `${metrics.cache_hit_rate}%` }} />
            </div>
          </div>

          {flushResult && (
            <div className={`flex items-center gap-2 text-xs p-2.5 rounded-lg mb-3 ${flushResult.success ? 'bg-green-900/20 border border-green-700/30 text-green-400' : 'bg-red-900/20 border border-red-700/30 text-red-400'}`}>
              {flushResult.success ? <CheckCircle className="h-3.5 w-3.5 shrink-0" /> : <XCircle className="h-3.5 w-3.5 shrink-0" />}
              {flushResult.message}
            </div>
          )}

          <button onClick={() => { setFlushResult(null); flushMut.mutate() }} disabled={flushMut.isPending}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm bg-red-900/20 border border-red-700/40 text-red-400 hover:bg-red-900/30 rounded-lg transition-colors disabled:opacity-50 font-medium">
            {flushMut.isPending ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            キャッシュをフラッシュ
          </button>

          <p className="text-xs text-zinc-600 mt-2 text-center">
            インメモリキャッシュを全消去します。一時的な遅延が発生する場合があります。
          </p>
        </div>
      </div>
    </div>
  )
}
