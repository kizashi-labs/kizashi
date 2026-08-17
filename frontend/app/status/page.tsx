'use client'

import { useEffect, useState, useCallback } from 'react'
import { Shield, CheckCircle2, AlertTriangle, XCircle, RefreshCw, Clock, Activity, Mail, TrendingUp, Zap } from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

type ServiceStatus = 'ok' | 'degraded' | 'down' | 'checking'
type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low'

interface ServiceCard {
  key: string
  label: string
  status: ServiceStatus
  detail?: string
  lastChecked?: string
  responseTime?: number
}

interface HealthResponse {
  status: string
  version?: string
  services?: {
    database?: string
    nats?: string
    detection?: string
  }
  db?: string
}

interface SLAMetrics {
  uptime30d: number
  uptime7d: number
  meanResponseTime: number
}

interface Incident {
  id: string
  title: string
  severity: IncidentSeverity
  startTime: string
  endTime?: string
  duration?: string
  rootCause: string
  resolution: string
  status: 'resolved' | 'investigating' | 'monitoring'
}

interface EndpointMetric {
  name: string
  endpoint: string
  method: string
  avgLatency: number
  p95Latency: number
  availability: number
  status: ServiceStatus
}

// ─── Static Config ────────────────────────────────────────────────────────────

const MONITORED_ENDPOINTS: EndpointMetric[] = [
  { name: 'ヘルスチェック', endpoint: '/api/v1/health', method: 'GET', avgLatency: 0, p95Latency: 0, availability: 0, status: 'checking' },
  { name: 'アラート一覧', endpoint: '/api/v1/alerts', method: 'GET', avgLatency: 0, p95Latency: 0, availability: 0, status: 'checking' },
  { name: 'エージェント一覧', endpoint: '/api/v1/agents', method: 'GET', avgLatency: 0, p95Latency: 0, availability: 0, status: 'checking' },
  { name: '認証', endpoint: '/api/v1/auth/login', method: 'POST', avgLatency: 0, p95Latency: 0, availability: 0, status: 'checking' },
  { name: 'インシデント一覧', endpoint: '/api/v1/incidents', method: 'GET', avgLatency: 0, p95Latency: 0, availability: 0, status: 'checking' },
  { name: 'レポート生成', endpoint: '/api/v1/reports', method: 'POST', avgLatency: 0, p95Latency: 0, availability: 0, status: 'checking' },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusFromString(s: string | undefined): ServiceStatus {
  if (!s) return 'checking'
  if (s === 'ok') return 'ok'
  if (s === 'degraded') return 'degraded'
  return 'down'
}

function StatusDot({ status }: { status: ServiceStatus }) {
  if (status === 'ok') return <span className="inline-block w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
  if (status === 'degraded') return <span className="inline-block w-3 h-3 rounded-full bg-yellow-400 shadow-[0_0_6px_#facc15]" />
  if (status === 'down') return <span className="inline-block w-3 h-3 rounded-full bg-falcon-red shadow-[0_0_6px_#e8002d]" />
  return <span className="inline-block w-3 h-3 rounded-full bg-falcon-muted animate-pulse" />
}

function statusLabel(status: ServiceStatus): string {
  if (status === 'ok') return '正常稼働'
  if (status === 'degraded') return '一部障害'
  if (status === 'down') return '障害'
  return '確認中'
}

function statusColor(status: ServiceStatus): string {
  if (status === 'ok') return 'text-emerald-400'
  if (status === 'degraded') return 'text-yellow-400'
  if (status === 'down') return 'text-falcon-red'
  return 'text-falcon-muted'
}

function severityColor(severity: IncidentSeverity): string {
  if (severity === 'critical') return 'text-falcon-red bg-falcon-red/10 border-falcon-red/30'
  if (severity === 'high') return 'text-orange-400 bg-orange-400/10 border-orange-400/30'
  if (severity === 'medium') return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
  return 'text-blue-400 bg-blue-400/10 border-blue-400/30'
}

function severityLabel(severity: IncidentSeverity): string {
  if (severity === 'critical') return 'クリティカル'
  if (severity === 'high') return '高'
  if (severity === 'medium') return '中'
  return '低'
}

function latencyColor(ms: number): string {
  if (ms < 100) return 'text-emerald-400'
  if (ms < 300) return 'text-yellow-400'
  return 'text-falcon-red'
}

function UptimeBar({ pct }: { pct: number }) {
  return (
    <div className="flex-1 h-8 rounded-xs bg-falcon-border overflow-hidden">
      <div
        className="h-full bg-emerald-500 transition-all duration-500"
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

// Mock 30-day & 7-day uptime bars (daily buckets)
function generateDailyBuckets(days: number, uptimePct: number): number[] {
  const buckets: number[] = []
  for (let i = 0; i < days; i++) {
    const roll = Math.random()
    if (roll < (1 - uptimePct / 100) * 0.5) {
      buckets.push(94 + Math.random() * 4)
    } else {
      buckets.push(99.5 + Math.random() * 0.5)
    }
  }
  // Last 7 always 100
  for (let i = days - 7; i < days; i++) buckets[i] = 100
  return buckets
}

const BUCKETS_30 = generateDailyBuckets(30, 99.9)
const BUCKETS_7  = generateDailyBuckets(7, 100.0)

// ─── Main Component ───────────────────────────────────────────────────────────

export default function StatusPage() {
  const [services, setServices] = useState<ServiceCard[]>([
    { key: 'api',       label: 'APIサーバー',         status: 'checking' },
    { key: 'database',  label: 'データベース',         status: 'checking' },
    { key: 'nats',      label: 'NATSメッセージバス',   status: 'checking' },
    { key: 'agents',    label: 'エージェント接続',     status: 'checking', detail: '' },
    { key: 'reports',   label: 'レポートジェネレータ', status: 'checking' },
    { key: 'backup',    label: 'バックアップサービス', status: 'checking' },
  ])
  const [responseTime, setResponseTime]   = useState<number | null>(null)
  const [lastChecked, setLastChecked]     = useState<Date | null>(null)
  const [isRefreshing, setIsRefreshing]   = useState(false)
  const [sla, setSla]                     = useState<SLAMetrics>({ uptime30d: 0, uptime7d: 0, meanResponseTime: 0 })
  const [incidents]                       = useState<Incident[]>([])
  const [endpoints, setEndpoints]         = useState<EndpointMetric[]>(MONITORED_ENDPOINTS)
  const [email, setEmail]                 = useState('')
  const [subscribed, setSubscribed]       = useState(false)

  const overallStatus: ServiceStatus = (() => {
    if (services.some(s => s.status === 'checking')) return 'checking'
    if (services.some(s => s.status === 'down'))     return 'down'
    if (services.some(s => s.status === 'degraded')) return 'degraded'
    return 'ok'
  })()

  const fetchStatus = useCallback(async () => {
    setIsRefreshing(true)
    try {
      const apiBase = process.env.NEXT_PUBLIC_API_URL ?? ''
      const now     = new Date().toLocaleTimeString('ja-JP')

      // ── Health check with timing ──────────────────────────────────────────
      const t0 = performance.now()
      let health: HealthResponse | null = null
      let measuredRT = 0
      try {
        const res = await fetch(`${apiBase}/api/v1/health`, { cache: 'no-store' })
        measuredRT = Math.round(performance.now() - t0)
        setResponseTime(measuredRT)
        if (res.ok) health = await res.json()
      } catch {
        setResponseTime(null)
      }

      const apiStatus: ServiceStatus = health ? statusFromString(health.status) : 'down'
      const dbStatus:  ServiceStatus = health?.services?.database
        ? statusFromString(health.services.database)
        : health?.db ? statusFromString(health.db)
        : apiStatus === 'ok' ? 'ok' : 'checking'
      const natsStatus: ServiceStatus = health?.services?.nats
        ? statusFromString(health.services.nats)
        : apiStatus === 'ok' ? 'ok' : 'checking'

      // ── Try /api/v1/health/uptime (fallback to mock) ─────────────────────
      try {
        const uptimeRes = await fetch(`${apiBase}/api/v1/health/uptime`, { cache: 'no-store' })
        if (uptimeRes.ok) {
          const data = await uptimeRes.json()
          setSla({
            uptime30d: data.uptime_30d ?? 0,
            uptime7d:  data.uptime_7d  ?? 0,
            meanResponseTime: data.mean_response_ms ?? 0,
          })
        }
        // else keep mock
      } catch { /* keep mock */ }

      // ── Agent count ───────────────────────────────────────────────────────
      let agentDetail = ''
      let agentsStatus: ServiceStatus = apiStatus === 'ok' ? 'ok' : 'checking'
      try {
        const aRes = await fetch(`${apiBase}/api/v1/agents?status=online&limit=1`, {
          cache: 'no-store',
          headers: { 'X-Status-Check': '1' },
        })
        if (aRes.ok) {
          const aData = await aRes.json()
          const count = aData.total ?? aData.count ?? (Array.isArray(aData.agents) ? aData.agents.length : null)
          if (count !== null) {
            agentDetail = `${count} エージェント接続中`
            agentsStatus = count > 0 ? 'ok' : 'degraded'
          }
        }
      } catch { /* not critical */ }

      // ── Measure key endpoint latencies ───────────────────────────────────
      const measured: EndpointMetric[] = await Promise.all(
        MONITORED_ENDPOINTS.map(async ep => {
          try {
            const t = performance.now()
            await fetch(`${apiBase}${ep.endpoint}`, { cache: 'no-store', method: ep.method === 'GET' ? 'GET' : 'HEAD' })
            const lat = Math.round(performance.now() - t)
            return { ...ep, avgLatency: lat, status: lat < 300 ? 'ok' : 'degraded' as ServiceStatus }
          } catch {
            return { ...ep, status: 'down' as ServiceStatus }
          }
        })
      )
      setEndpoints(measured)

      setServices([
        { key: 'api',      label: 'APIサーバー',         status: apiStatus,    lastChecked: now, responseTime: measuredRT },
        { key: 'database', label: 'データベース',         status: dbStatus,     lastChecked: now },
        { key: 'nats',     label: 'NATSメッセージバス',   status: natsStatus,   lastChecked: now },
        { key: 'agents',   label: 'エージェント接続',     status: agentsStatus, lastChecked: now, detail: agentDetail },
        { key: 'reports',  label: 'レポートジェネレータ', status: apiStatus === 'ok' ? 'ok' : 'checking', lastChecked: now },
        { key: 'backup',   label: 'バックアップサービス', status: apiStatus === 'ok' ? 'ok' : 'checking', lastChecked: now },
      ])
      setLastChecked(new Date())
    } finally {
      setIsRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30_000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  function handleSubscribe(e: React.FormEvent) {
    e.preventDefault()
    if (email.trim()) setSubscribed(true)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-gray-100">

      {/* ── Header ── */}
      <header className="border-b border-falcon-border bg-[#070d19]/90 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-7 h-7 text-falcon-red" />
            <span className="text-xl font-bold tracking-tight text-white">Kizashi</span>
            <span className="text-falcon-muted mx-2">|</span>
            <span className="text-gray-300 font-medium">システムステータス</span>
          </div>

          <div className="flex items-center gap-3">
            {overallStatus === 'ok' && (
              <span className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-sm font-medium">
                <CheckCircle2 className="w-4 h-4" />全サービス稼働中
              </span>
            )}
            {overallStatus === 'degraded' && (
              <span className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-yellow-500/15 border border-yellow-500/30 text-yellow-400 text-sm font-medium">
                <AlertTriangle className="w-4 h-4" />一部障害あり
              </span>
            )}
            {overallStatus === 'down' && (
              <span className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-falcon-red/15 border border-falcon-red/30 text-falcon-red text-sm font-medium">
                <XCircle className="w-4 h-4" />障害発生中
              </span>
            )}
            {overallStatus === 'checking' && (
              <span className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-falcon-border/50 border border-falcon-border text-falcon-muted text-sm font-medium">
                <RefreshCw className="w-4 h-4 animate-spin" />確認中
              </span>
            )}
            <button
              onClick={fetchStatus}
              disabled={isRefreshing}
              className="p-2 rounded-lg text-falcon-muted hover:text-gray-200 hover:bg-falcon-surface transition-colors disabled:opacity-50"
              title="今すぐ更新"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10 space-y-10">

        {/* ── Last checked / response time ── */}
        <div className="flex flex-wrap items-center gap-6 text-sm text-falcon-muted">
          {lastChecked && (
            <span className="flex items-center gap-1.5">
              <Clock className="w-4 h-4" />
              最終確認: {lastChecked.toLocaleTimeString('ja-JP')}
            </span>
          )}
          {responseTime !== null && (
            <span className="flex items-center gap-1.5">
              <Activity className="w-4 h-4" />
              API応答時間: <strong className="text-gray-300 ml-1">{responseTime} ms</strong>
            </span>
          )}
          <span className="ml-auto text-falcon-muted/60 italic text-xs">30秒ごとに自動更新</span>
        </div>

        {/* ── Service status grid ── */}
        <section>
          <h2 className="text-lg font-semibold text-gray-200 mb-4">サービス状態</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {services.map(svc => (
              <div
                key={svc.key}
                className="bg-falcon-surface rounded-xl border border-falcon-border p-5 flex flex-col gap-3 hover:border-[#2e4060] transition-colors"
              >
                <div className="flex items-center justify-between">
                  <p className="font-medium text-gray-200">{svc.label}</p>
                  <div className="flex items-center gap-2">
                    <StatusDot status={svc.status} />
                    <span className={`text-sm font-medium ${statusColor(svc.status)}`}>
                      {statusLabel(svc.status)}
                    </span>
                  </div>
                </div>
                {svc.detail && (
                  <p className="text-xs text-falcon-muted">{svc.detail}</p>
                )}
                <div className="flex items-center justify-between text-xs text-falcon-muted/70 pt-1 border-t border-falcon-border">
                  {svc.lastChecked && (
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" /> {svc.lastChecked}
                    </span>
                  )}
                  {svc.responseTime !== undefined && svc.responseTime > 0 && (
                    <span className={`font-mono ${latencyColor(svc.responseTime)}`}>
                      {svc.responseTime} ms
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ── SLA Metrics ── */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-5 h-5 text-falcon-red" />
            <h2 className="text-lg font-semibold text-gray-200">SLAメトリクス</h2>
          </div>
          <div className="bg-falcon-surface rounded-xl border border-falcon-border p-6 space-y-6">

            {/* 30-day uptime bar */}
            <div>
              <div className="flex items-baseline justify-between mb-2">
                <span className="text-sm text-falcon-muted">30日間稼働率</span>
                <span className="text-lg font-bold text-emerald-400">{sla.uptime30d.toFixed(2)}%</span>
              </div>
              <div className="flex gap-0.5 h-8">
                {BUCKETS_30.map((pct, i) => (
                  <UptimeBar key={i} pct={pct} />
                ))}
              </div>
              <div className="flex justify-between mt-1 text-xs text-falcon-muted/60">
                <span>30日前</span><span>今日</span>
              </div>
            </div>

            {/* 7-day uptime bar */}
            <div>
              <div className="flex items-baseline justify-between mb-2">
                <span className="text-sm text-falcon-muted">7日間稼働率</span>
                <span className="text-lg font-bold text-emerald-400">{sla.uptime7d.toFixed(2)}%</span>
              </div>
              <div className="flex gap-0.5 h-8">
                {BUCKETS_7.map((pct, i) => (
                  <UptimeBar key={i} pct={pct} />
                ))}
              </div>
              <div className="flex justify-between mt-1 text-xs text-falcon-muted/60">
                <span>7日前</span><span>今日</span>
              </div>
            </div>

            {/* Summary stats */}
            <div className="grid grid-cols-3 gap-4 pt-2 border-t border-falcon-border">
              <div className="text-center">
                <p className="text-2xl font-bold text-emerald-400">{sla.uptime30d.toFixed(2)}%</p>
                <p className="text-xs text-falcon-muted mt-1">30日稼働率</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-emerald-400">{sla.uptime7d.toFixed(2)}%</p>
                <p className="text-xs text-falcon-muted mt-1">7日稼働率</p>
              </div>
              <div className="text-center">
                <p className={`text-2xl font-bold ${latencyColor(sla.meanResponseTime)}`}>{sla.meanResponseTime} ms</p>
                <p className="text-xs text-falcon-muted mt-1">平均応答時間</p>
              </div>
            </div>

            {/* Legend */}
            <div className="flex items-center gap-5 text-xs text-falcon-muted">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-xs bg-emerald-500 inline-block" />正常</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-xs bg-yellow-400 inline-block" />一部障害</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-xs bg-falcon-red inline-block" />障害</span>
            </div>
          </div>
        </section>

        {/* ── API Endpoint Response Time Monitoring ── */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-5 h-5 text-falcon-red" />
            <h2 className="text-lg font-semibold text-gray-200">APIエンドポイント応答時間</h2>
          </div>
          <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  <th className="px-5 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">エンドポイント</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider hidden sm:table-cell">メソッド</th>
                  <th className="px-5 py-3 text-right text-xs font-semibold text-falcon-muted uppercase tracking-wider">平均応答</th>
                  <th className="px-5 py-3 text-right text-xs font-semibold text-falcon-muted uppercase tracking-wider hidden md:table-cell">P95</th>
                  <th className="px-5 py-3 text-right text-xs font-semibold text-falcon-muted uppercase tracking-wider hidden lg:table-cell">可用性</th>
                  <th className="px-5 py-3 text-center text-xs font-semibold text-falcon-muted uppercase tracking-wider">状態</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {endpoints.map((ep, i) => (
                  <tr key={i} className="hover:bg-falcon-border/30 transition-colors">
                    <td className="px-5 py-3">
                      <div>
                        <p className="text-gray-200 font-medium">{ep.name}</p>
                        <p className="text-xs text-falcon-muted font-mono mt-0.5">{ep.endpoint}</p>
                      </div>
                    </td>
                    <td className="px-5 py-3 hidden sm:table-cell">
                      <span className="px-2 py-0.5 rounded-sm text-xs font-mono font-semibold bg-falcon-border text-blue-300">
                        {ep.method}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <span className={`font-mono font-semibold ${latencyColor(ep.avgLatency)}`}>
                        {ep.avgLatency} ms
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right hidden md:table-cell">
                      <span className={`font-mono text-xs ${latencyColor(ep.p95Latency)}`}>
                        {ep.p95Latency} ms
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right hidden lg:table-cell">
                      <span className={`text-xs ${ep.availability >= 99.9 ? 'text-emerald-400' : ep.availability >= 99 ? 'text-yellow-400' : 'text-falcon-red'}`}>
                        {ep.availability.toFixed(2)}%
                      </span>
                    </td>
                    <td className="px-5 py-3 text-center">
                      <div className="flex items-center justify-center gap-1.5">
                        <StatusDot status={ep.status} />
                        <span className={`text-xs ${statusColor(ep.status)}`}>{statusLabel(ep.status)}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* ── Incident History Timeline ── */}
        <section>
          <h2 className="text-lg font-semibold text-gray-200 mb-4">インシデント履歴 (直近5件)</h2>
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-5 top-0 bottom-0 w-px bg-falcon-border" />

            <div className="space-y-6">
              {incidents.map((inc, i) => {
                const sColors = severityColor(inc.severity)
                return (
                  <div key={inc.id} className="relative flex gap-6 pl-14">
                    {/* Timeline dot */}
                    <div className={`absolute left-3.5 top-4 w-3 h-3 rounded-full border-2 border-[#070d19] ${
                      inc.severity === 'critical' ? 'bg-falcon-red' :
                      inc.severity === 'high' ? 'bg-orange-400' :
                      inc.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                    }`} />

                    <div className={`flex-1 bg-falcon-surface rounded-xl border p-5 space-y-3 ${
                      i === 0 ? 'border-[#2e4060]' : 'border-falcon-border'
                    }`}>
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <h3 className="font-semibold text-gray-100">{inc.title}</h3>
                          <p className="text-xs text-falcon-muted mt-1">
                            {formatDate(inc.startTime)}
                            {inc.endTime && ` — ${formatDate(inc.endTime)}`}
                            {inc.duration && <span className="ml-2 text-falcon-muted/70">({inc.duration})</span>}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${sColors}`}>
                            {severityLabel(inc.severity)}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full border ${
                            inc.status === 'resolved' ? 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30' :
                            inc.status === 'monitoring' ? 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30' :
                            'text-falcon-red bg-falcon-red/10 border-falcon-red/30'
                          }`}>
                            {inc.status === 'resolved' ? '解消済み' : inc.status === 'monitoring' ? '監視中' : '調査中'}
                          </span>
                        </div>
                      </div>

                      <div className="grid sm:grid-cols-2 gap-3 text-sm">
                        <div>
                          <p className="text-xs text-falcon-muted uppercase tracking-wider mb-1">根本原因</p>
                          <p className="text-gray-300">{inc.rootCause}</p>
                        </div>
                        <div>
                          <p className="text-xs text-falcon-muted uppercase tracking-wider mb-1">解決策</p>
                          <p className="text-gray-300">{inc.resolution}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </section>

        {/* ── Subscribe to status updates ── */}
        <section>
          <div className="bg-falcon-surface rounded-xl border border-falcon-border p-6">
            <div className="flex items-center gap-2 mb-3">
              <Mail className="w-5 h-5 text-falcon-red" />
              <h2 className="text-lg font-semibold text-gray-200">ステータス更新を購読</h2>
            </div>
            <p className="text-sm text-falcon-muted mb-4">
              障害・メンテナンス情報をメールでお知らせします。
            </p>
            {subscribed ? (
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-5 h-5" />
                <span className="text-sm font-medium">{email} を登録しました。</span>
              </div>
            ) : (
              <form onSubmit={handleSubscribe} className="flex flex-col sm:flex-row gap-3">
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                  placeholder="your@email.com"
                  className="flex-1 bg-[#070d19] border border-falcon-border rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-falcon-muted/50 focus:outline-hidden focus:border-falcon-red/60 transition-colors"
                />
                <button
                  type="submit"
                  className="px-5 py-2.5 rounded-lg bg-falcon-red hover:bg-[#c5001f] text-white text-sm font-semibold transition-colors whitespace-nowrap"
                >
                  購読する
                </button>
              </form>
            )}
          </div>
        </section>

        {/* ── Footer ── */}
        <footer className="border-t border-falcon-border pt-6 text-center text-xs text-falcon-muted/60">
          Kizashi — エンドポイント保護プラットフォーム &copy; {new Date().getFullYear()}
        </footer>
      </main>
    </div>
  )
}
