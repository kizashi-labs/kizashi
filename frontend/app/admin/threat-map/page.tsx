'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Globe2, Shield, Activity, AlertTriangle } from 'lucide-react'
import { WorldMap, latLonToPercent } from '@/components/WorldMap'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatOrigin {
  id: string
  country: string
  country_code: string
  flag: string
  connections: number
  threats: number
  severity: 'low' | 'medium' | 'high' | 'critical'
  lat: number
  lon: number
}

interface TopThreat {
  ip: string
  country: string
  flag: string
  connection_count: number
  first_seen: string
  last_seen: string
  blocked: boolean
}

interface ThreatMapStats {
  active_connections: number
  countries: number
  threats_blocked: number
  top_source: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_LABEL: Record<ThreatOrigin['severity'], string> = {
  critical: '重大',
  high: '高',
  medium: '中',
  low: '低',
}

function severityDotColor(sev: ThreatOrigin['severity']): string {
  const map: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
  }
  return map[sev] || '#6b7280'
}

function severityGlow(sev: ThreatOrigin['severity']): string {
  const map: Record<string, string> = {
    critical: 'rgba(239,68,68,0.5)',
    high: 'rgba(249,115,22,0.4)',
    medium: 'rgba(234,179,8,0.3)',
    low: 'rgba(34,197,94,0.2)',
  }
  return map[sev] || 'transparent'
}

function dotSize(connections: number): number {
  if (connections > 300) return 20
  if (connections > 150) return 15
  if (connections > 80) return 11
  return 8
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ThreatMapPage() {
  const [timeRange, setTimeRange] = useState<'1h' | '6h' | '24h' | '7d'>('24h')
  const [hoveredOrigin, setHoveredOrigin] = useState<ThreatOrigin | null>(null)
  const [tooltip, setTooltip] = useState<{ x: number; y: number } | null>(null)
  const [error, setError] = useState<string | null>(null)

  const { data: mapData } = useQuery<{ origins: ThreatOrigin[]; top_threats: TopThreat[] }>({
    queryKey: ['threat-map', timeRange],
    queryFn: async () => {
      try {
        const [data, threats] = await Promise.all([
          apiFetch<{ origins: ThreatOrigin[] }>(`/api/v1/threat-map/data?hours=${timeRange === '1h' ? 1 : timeRange === '6h' ? 6 : timeRange === '24h' ? 24 : 168}`),
          apiFetch<{ threats: TopThreat[] }>('/api/v1/threat-map/top-threats'),
        ])
        return { origins: data.origins, top_threats: threats.threats }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'データの取得に失敗しました')
        return { origins: [], top_threats: [] }
      }
    },
    refetchInterval: 30000,
  })

  const origins = mapData?.origins ?? []
  const topThreats = mapData?.top_threats ?? []

  function handleDotMouseEnter(origin: ThreatOrigin, e: React.MouseEvent<HTMLDivElement>) {
    setHoveredOrigin(origin)
    const rect = (e.currentTarget.closest('.map-container') as HTMLElement)?.getBoundingClientRect()
    if (rect) {
      setTooltip({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      })
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-700 rounded-lg">
            <Globe2 className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">脅威マップ</h1>
            <p className="text-sm text-zinc-400">グローバル脅威発生源の可視化</p>
          </div>
        </div>
        <div className="flex gap-1 bg-zinc-900 rounded-xl p-1 border border-zinc-800">
          {(['1h', '6h', '24h', '7d'] as const).map(r => (
            <button
              key={r}
              onClick={() => setTimeRange(r)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium ${
                timeRange === r ? 'bg-cyan-700 text-white' : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-950 border border-red-800 rounded-xl p-4 text-red-300 mb-6">
          <AlertTriangle className="w-5 h-5 inline mr-2" />{error}
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'アクティブ接続', value: origins.reduce((s, o) => s + o.connections, 0).toLocaleString(), color: 'text-cyan-400', icon: Activity },
          { label: '国数', value: origins.length, color: 'text-zinc-100', icon: Globe2 },
          { label: 'ブロック済み脅威', value: origins.reduce((s, o) => s + o.threats, 0).toLocaleString(), color: 'text-green-400', icon: Shield },
          { label: '最多発生源', value: [...origins].sort((a, b) => b.connections - a.connections)[0]?.country ?? '—', color: 'text-red-400', icon: AlertTriangle },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 rounded-xl p-4 border border-zinc-800 flex items-center gap-3">
            <div className="p-2 bg-zinc-800 rounded-lg">
              <s.icon className="w-4 h-4 text-zinc-400" />
            </div>
            <div>
              <p className="text-xs text-zinc-500">{s.label}</p>
              <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Map */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl mb-6 overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-zinc-300">リアルタイム脅威発生源</h3>
          <div className="flex items-center gap-4 text-xs text-zinc-500">
            {(['critical', 'high', 'medium', 'low'] as const).map(s => (
              <div key={s} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: severityDotColor(s) }} />
                <span>{SEVERITY_LABEL[s]}</span>
              </div>
            ))}
          </div>
        </div>
        <div
          className="relative map-container overflow-hidden"
          style={{ height: '400px', background: 'linear-gradient(180deg, #0a0f1a 0%, #0d1520 50%, #0a1018 100%)' }}
          onMouseLeave={() => { setHoveredOrigin(null); setTooltip(null) }}
        >
          {/* Accurate world map background */}
          <div className="absolute inset-0">
            <WorldMap landFill="#0d1e30" borderStroke="#1e3a5f" borderWidth={0.4} />
          </div>

          {/* Threat dots */}
          {origins.map(origin => {
            const size = dotSize(origin.connections)
            const color = severityDotColor(origin.severity)
            const glow = severityGlow(origin.severity)
            const isPulsing = origin.severity === 'critical' || origin.severity === 'high'
            const { x, y } = latLonToPercent(origin.lat, origin.lon)
            return (
              <div
                key={origin.id}
                className="absolute cursor-pointer"
                style={{
                  left: `${x}%`,
                  top: `${y}%`,
                  transform: 'translate(-50%, -50%)',
                }}
                onMouseEnter={e => handleDotMouseEnter(origin, e)}
              >
                {/* Pulse ring for high severity */}
                {isPulsing && (
                  <div
                    className="absolute rounded-full animate-ping"
                    style={{
                      width: size * 2.5,
                      height: size * 2.5,
                      backgroundColor: glow,
                      top: '50%',
                      left: '50%',
                      transform: 'translate(-50%, -50%)',
                    }}
                  />
                )}
                {/* Main dot */}
                <div
                  className="rounded-full border-2 relative z-10"
                  style={{
                    width: size,
                    height: size,
                    backgroundColor: color,
                    borderColor: color,
                    boxShadow: `0 0 ${size}px ${glow}`,
                  }}
                />
              </div>
            )
          })}

          {/* Tooltip */}
          {hoveredOrigin && tooltip && (
            <div
              className="absolute z-20 bg-zinc-900 border border-zinc-600 rounded-xl p-3 text-xs shadow-2xl pointer-events-none"
              style={{
                left: tooltip.x + 12,
                top: tooltip.y - 10,
                minWidth: '160px',
              }}
            >
              <div className="flex items-center gap-1.5 mb-1.5">
                <span className="text-base">{hoveredOrigin.flag}</span>
                <span className="font-semibold text-zinc-100">{hoveredOrigin.country}</span>
              </div>
              <div className="space-y-1 text-zinc-400">
                <div className="flex justify-between gap-3">
                  <span>接続数:</span>
                  <span className="text-cyan-300 font-semibold">{(hoveredOrigin.connections ?? 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span>脅威数:</span>
                  <span className="text-red-300 font-semibold">{(hoveredOrigin.threats ?? 0).toLocaleString()}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span>深刻度:</span>
                  <span style={{ color: severityDotColor(hoveredOrigin.severity) }} className="font-semibold">
                    {SEVERITY_LABEL[hoveredOrigin.severity]}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Top Threats Table */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
        <div className="px-5 py-3 border-b border-zinc-800">
          <h3 className="text-sm font-semibold text-zinc-300">トップ脅威IP</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-zinc-800">
              {['IPアドレス', '国', '接続数', '初回検出', '最終検出', 'ステータス'].map(h => (
                <th key={h} className="text-left text-xs text-zinc-500 font-medium px-4 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {topThreats.map((threat, i) => (
              <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                <td className="px-4 py-3 font-mono text-sm text-cyan-300">{threat.ip}</td>
                <td className="px-4 py-3 text-sm">
                  <span className="flex items-center gap-1.5">
                    <span>{threat.flag}</span>
                    <span className="text-zinc-300">{threat.country}</span>
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-zinc-200 font-semibold">{(threat.connection_count ?? 0).toLocaleString()}</td>
                <td className="px-4 py-3 text-sm text-zinc-400">{fmtDate(threat.first_seen)}</td>
                <td className="px-4 py-3 text-sm text-zinc-400">{fmtDate(threat.last_seen)}</td>
                <td className="px-4 py-3">
                  {threat.blocked ? (
                    <span className="flex items-center gap-1 px-2 py-0.5 bg-red-900 text-red-300 rounded-sm text-xs">
                      <Shield className="w-3 h-3" /> ブロック済み
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 bg-zinc-700 text-zinc-400 rounded-sm text-xs">
                      アクティブ
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
