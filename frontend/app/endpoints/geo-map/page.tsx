'use client'

import { useState, useMemo } from 'react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Map as MapIcon, Globe, RefreshCw, ChevronRight, X, Info } from 'lucide-react'
import { latLonToPercent } from '@/components/WorldMap'

// Load WorldMap only on the client to avoid SSR issues with react-simple-maps / d3
const WorldMap = dynamic(() => import('@/components/WorldMap').then(m => m.WorldMap), { ssr: false })

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  status?: string
  last_seen?: string
  ip_addresses?: string[]
  ip_address?: string
  os_type?: string
  os?: string
}

interface AgentsResponse {
  data?: Agent[]
  items?: Agent[]
  agents?: Agent[]
}

// ─── IP → Region mapping ──────────────────────────────────────────────────────

interface RegionInfo {
  region: string
  continent: string
  country: string
  countryCode: string
  lat: number
  lon: number
}

// Simplified IP-to-region mapping based on first-octet ranges (rough approximation)
// Extended with second-octet ranges for better coverage
function ipToRegion(ip: string): RegionInfo {
  const parts = ip.split('.')
  const first = parseInt(parts[0] ?? '0', 10)
  const second = parseInt(parts[1] ?? '0', 10)

  // Private ranges → local / unknown
  if (first === 10 || first === 172 && second >= 16 && second <= 31 || first === 192 && second === 168) {
    return { region: 'ローカル', continent: 'Others', country: 'Private Network', countryCode: 'XX', lat: 0, lon: 0 }
  }
  if (first === 127) return { region: 'ローカルホスト', continent: 'Others', country: 'Localhost', countryCode: 'LH', lat: 0, lon: 0 }

  // AWS ap-northeast-1 (Tokyo) specific ranges — must check before generic ARIN/APNIC blocks
  // 13.112-115.x.x, 52.68-69.x.x, 52.192-199.x.x, 54.64-95.x.x, 54.168-169.x.x, 54.238-239.x.x
  if (first === 13) return { region: 'Japan', continent: 'Asia-Pacific', country: '日本', countryCode: 'JP', lat: 35.7, lon: 139.7 }
  if (first === 52 && ((second >= 68 && second <= 69) || (second >= 192 && second <= 199) || second === 246 || second === 247)) return { region: 'Japan', continent: 'Asia-Pacific', country: '日本', countryCode: 'JP', lat: 35.7, lon: 139.7 }
  if (first === 54 && ((second >= 64 && second <= 95) || second === 168 || second === 169 || second === 238 || second === 239)) return { region: 'Japan', continent: 'Asia-Pacific', country: '日本', countryCode: 'JP', lat: 35.7, lon: 139.7 }

  // APNIC blocks → Asia-Pacific
  if ((first >= 1 && first <= 14) || (first >= 43 && first <= 49) || (first >= 58 && first <= 61) || (first >= 101 && first <= 126) || (first >= 150 && first <= 153) || (first >= 163 && first <= 165) || (first >= 175 && first <= 180) || (first >= 182 && first <= 183) || (first >= 202 && first <= 223)) {
    if (first >= 210 && first <= 211) return { region: 'Japan', continent: 'Asia-Pacific', country: '日本', countryCode: 'JP', lat: 35.7, lon: 139.7 }
    if (first >= 113 && first <= 125) return { region: 'China', continent: 'Asia-Pacific', country: '中国', countryCode: 'CN', lat: 39.9, lon: 116.4 }
    if (first >= 59 && first <= 61) return { region: 'Korea/Japan', continent: 'Asia-Pacific', country: '韓国', countryCode: 'KR', lat: 37.6, lon: 127.0 }
    if (first >= 103 && first <= 107) return { region: 'Southeast Asia', continent: 'Asia-Pacific', country: 'シンガポール', countryCode: 'SG', lat: 1.35, lon: 103.8 }
    if (first >= 150 && first <= 153) return { region: 'Australia', continent: 'Asia-Pacific', country: 'オーストラリア', countryCode: 'AU', lat: -33.9, lon: 151.2 }
    // Unknown APNIC: don't pin to a specific country
    return { region: 'Asia-Pacific', continent: 'Asia-Pacific', country: 'アジア太平洋', countryCode: 'AP', lat: 0, lon: 0 }
  }

  // RIPE NCC blocks → Europe / Middle East
  if ((first >= 2 && first <= 5) || (first >= 62 && first <= 95) || (first >= 176 && first <= 178) || (first >= 185 && first <= 195)) {
    if (first >= 77 && first <= 95) return { region: 'Western Europe', continent: 'Europe', country: 'ドイツ', countryCode: 'DE', lat: 52.5, lon: 13.4 }
    if (first >= 178 && first <= 179) return { region: 'Eastern Europe', continent: 'Europe', country: 'ロシア', countryCode: 'RU', lat: 55.8, lon: 37.6 }
    if (first >= 185 && first <= 188) return { region: 'UK/France', continent: 'Europe', country: 'イギリス', countryCode: 'GB', lat: 51.5, lon: -0.1 }
    return { region: 'Europe', continent: 'Europe', country: 'ヨーロッパ', countryCode: 'EU', lat: 48.9, lon: 2.3 }
  }

  // ARIN blocks → Americas
  if ((first >= 3 && first <= 4) || (first >= 6 && first <= 9) || (first >= 15 && first <= 42) || (first >= 50 && first <= 57) || (first >= 63 && first <= 76) || (first >= 96 && first <= 100) || (first >= 128 && first <= 149) || (first >= 154 && first <= 162) || (first >= 166 && first <= 174) || (first >= 199 && first <= 201)) {
    if (first >= 3 && first <= 35) return { region: 'US East', continent: 'Americas', country: 'アメリカ合衆国', countryCode: 'US', lat: 40.7, lon: -74.0 }
    if (first >= 36 && first <= 57) return { region: 'US West', continent: 'Americas', country: 'アメリカ合衆国', countryCode: 'US', lat: 37.8, lon: -122.4 }
    if (first >= 189 && first <= 201) return { region: 'Latin America', continent: 'Americas', country: 'ブラジル', countryCode: 'BR', lat: -23.5, lon: -46.6 }
    return { region: 'Americas', continent: 'Americas', country: 'アメリカ', countryCode: 'AM', lat: 38.9, lon: -77.0 }
  }

  // AFRINIC blocks → Africa
  if ((first >= 41 && first <= 42) || (first >= 196 && first <= 197)) {
    return { region: 'Africa', continent: 'Others', country: 'アフリカ', countryCode: 'AF', lat: -1.3, lon: 36.8 }
  }

  // LACNIC blocks → Latin America
  if (first >= 177 && first <= 181 || first >= 186 && first <= 191) {
    return { region: 'Latin America', continent: 'Americas', country: 'ラテンアメリカ', countryCode: 'LA', lat: -15.8, lon: -47.9 }
  }

  return { region: 'Unknown', continent: 'Others', country: '不明', countryCode: '??', lat: 0, lon: 20 }
}

function getAgentIp(agent: Agent): string {
  if (agent.ip_addresses && agent.ip_addresses.length > 0) {
    const privateRanges = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
    const publicIp = agent.ip_addresses.find(ip => !privateRanges.test(ip))
    if (publicIp) return publicIp
    return agent.ip_addresses[0]
  }
  if (agent.ip_address) return agent.ip_address
  return ''
}

function formatLastSeen(s?: string): string {
  if (!s) return '—'
  try {
    return new Date(s).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
  } catch { return s }
}

// ─── Simplified SVG World Map paths (approximate continent outlines) ───────────

// Each continent is a simplified polygon (lat/lon → SVG coordinates)
// SVG viewport: 800 x 400
// Projection: simple equirectangular (lon: -180..180 → 0..800, lat: 90..-90 → 0..400)
function project(lon: number, lat: number): [number, number] {
  const x = ((lon + 180) / 360) * 800
  const y = ((90 - lat) / 180) * 400
  return [x, y]
}

function latLonPath(coords: [number, number][]): string {
  return coords.map((c, i) => {
    const [x, y] = project(c[0], c[1])
    return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ') + ' Z'
}

const CONTINENTS_SVG = [
  {
    name: 'North America',
    path: latLonPath([
      [-168, 72], [-140, 72], [-100, 72], [-80, 72], [-60, 47], [-56, 47],
      [-60, 24], [-84, 10], [-92, 16], [-117, 32], [-125, 42], [-140, 58],
      [-168, 62],
    ]),
  },
  {
    name: 'South America',
    path: latLonPath([
      [-80, 12], [-60, 12], [-36, -4], [-34, -10], [-38, -56], [-58, -56],
      [-76, -52], [-82, -8], [-80, 12],
    ]),
  },
  {
    name: 'Europe',
    path: latLonPath([
      [-10, 72], [32, 72], [40, 62], [38, 48], [28, 38], [12, 36],
      [-6, 36], [-10, 44], [-10, 72],
    ]),
  },
  {
    name: 'Africa',
    path: latLonPath([
      [-18, 38], [52, 38], [52, 12], [44, -12], [36, -36], [18, -36],
      [12, -36], [-18, 14], [-18, 38],
    ]),
  },
  {
    name: 'Asia',
    path: latLonPath([
      [26, 72], [180, 72], [180, 62], [142, 46], [138, 36], [126, 20],
      [100, 2], [80, 8], [60, 22], [38, 16], [38, 38], [36, 48],
      [26, 48], [26, 72],
    ]),
  },
  {
    name: 'Australia',
    path: latLonPath([
      [114, -22], [122, -18], [136, -12], [148, -20], [154, -28],
      [150, -40], [136, -38], [116, -36], [114, -22],
    ]),
  },
  {
    name: 'New Zealand',
    path: latLonPath([
      [166, -44], [168, -46], [174, -40], [174, -36], [172, -36], [166, -44],
    ]),
  },
]

// ─── Dot position for agents on the map ───────────────────────────────────────

function agentDotColor(status?: string): string {
  if (status === 'online') return '#00c853'
  if (status === 'offline') return '#7d92b0'
  if (status === 'isolated') return '#f59e0b'
  if (status === 'inactive') return '#5c6f8a'
  return '#7d92b0'
}

// ラベルは表引きにする。以前は三項演算子の連鎖で、該当しない状態がすべて
// 「オフライン」に落ちていた（error / inactive が誤ラベルになる）。
const AGENT_STATUS_LABEL: Record<string, string> = {
  online:   'オンライン',
  offline:  'オフライン',
  isolated: '隔離中',
  error:    'エラー',
  inactive: '非アクティブ',
}

function agentStatusLabel(status?: string): string {
  return AGENT_STATUS_LABEL[status ?? ''] ?? (status || 'オフライン')
}

// Small jitter so dots don't pile up exactly on each other
function jitter(seed: string, range: number): number {
  let h = 0
  for (let i = 0; i < seed.length; i++) h = (Math.imul(31, h) + seed.charCodeAt(i)) | 0
  return ((h % 1000) / 1000 - 0.5) * range
}

// ─── Region Summary Table ─────────────────────────────────────────────────────

const CONTINENT_ORDER = ['Asia-Pacific', 'Americas', 'Europe', 'Others']
const CONTINENT_LABELS: Record<string, string> = {
  'Asia-Pacific': 'アジア太平洋',
  'Americas': 'アメリカ大陸',
  'Europe': 'ヨーロッパ',
  'Others': 'その他',
}

// ─── Geo helpers ──────────────────────────────────────────────────────────────

const UNKNOWN_GEO: RegionInfo = { region: 'Unknown', continent: 'Others', country: '不明', countryCode: '??', lat: 0, lon: 20 }

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function GeoMapPage() {
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null)
  const [activeContinent, setActiveContinent] = useState<string | null>(null)
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null)
  const [selectedPin, setSelectedPin] = useState<string | null>(null)

  const { data: rawAgents, isLoading, refetch } = useQuery<AgentsResponse | Agent[]>({
    queryKey: ['geo-map-agents'],
    queryFn: () => apiFetch('/api/v1/agents?limit=500'),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  // Normalize agents array
  const agents: Agent[] = useMemo(() => {
    if (!rawAgents) return []
    if (Array.isArray(rawAgents)) return rawAgents
    return (rawAgents as AgentsResponse).data
      ?? (rawAgents as AgentsResponse).items
      ?? (rawAgents as AgentsResponse).agents
      ?? []
  }, [rawAgents])

  // Map each agent to geo info
  const agentGeo = useMemo(() => {
    const list = Array.isArray(agents) ? agents : []
    return list
      .filter((a): a is Agent => !!a && typeof a === 'object')
      .map((agent, idx) => {
        const ip = getAgentIp(agent)
        let geo: RegionInfo = UNKNOWN_GEO
        try {
          const resolved = ip ? ipToRegion(ip) : UNKNOWN_GEO
          if (resolved && typeof resolved === 'object' && resolved.countryCode) geo = resolved
        } catch { /* use UNKNOWN_GEO */ }
        return { agent, geo }
      })
  }, [agents])

  // Use mock data if no real agents
  const effectiveGeo = useMemo(() => agentGeo, [agentGeo])

  // Stats
  const totalAgents = effectiveGeo.length
  const onlineCount = effectiveGeo.filter(e => e.agent?.status === 'online').length
  const offlineCount = effectiveGeo.filter(e => e.agent?.status !== 'online').length
  // Agents that cannot be geolocated (private IP → lat=0, lon=0)
  const privateNetAgents = effectiveGeo.filter(e => e.geo.lat === 0 && e.geo.lon === 0).map(e => e.agent)

  // Group by country
  // Cast to nullable types so TypeScript CANNOT optimize away the null checks in the
  // compiled/minified output. Without this cast, TS knows geo:RegionInfo is non-null
  // and compiles `geo?.countryCode` → `geo.countryCode`, crashing when runtime data
  // is unexpectedly undefined.
  const countryMap = useMemo(() => {
    const map = new Map<string, { geo: RegionInfo; agents: Agent[] }>()
    const items = effectiveGeo as Array<{ agent: Agent | undefined; geo: RegionInfo | undefined }>
    for (const item of items) {
      const geo = item.geo
      const agent = item.agent
      if (!geo || !agent) continue
      const key = geo.countryCode
      if (!key) continue
      if (!map.has(key)) map.set(key, { geo, agents: [] })
      map.get(key)!.agents.push(agent)
    }
    return map
  }, [effectiveGeo])

  const countryCount = countryMap.size

  // Group by continent
  const continentGroups = useMemo(() => {
    const grouped: Record<string, Map<string, { geo: RegionInfo; agents: Agent[] }>> = {}
    for (const [code, info] of countryMap) {
      const cont = info?.geo?.continent ?? 'Others'
      if (!grouped[cont]) grouped[cont] = new Map()
      grouped[cont].set(code, info)
    }
    return grouped
  }, [countryMap])

  // Visible countries by active continent filter
  const visibleCountries = useMemo(() => {
    const result: { code: string; geo: RegionInfo; agents: Agent[] }[] = []
    for (const [code, info] of countryMap) {
      if (!activeContinent || info?.geo?.continent === activeContinent) {
        result.push({ code, ...info })
      }
    }
    return result.sort((a, b) => b.agents.length - a.agents.length)
  }, [countryMap, activeContinent])

  const selectedCountryData = selectedCountry ? countryMap.get(selectedCountry) : null

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />

      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-linear-to-br from-[#e8002d] to-[#a80020] shrink-0">
            <MapIcon className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">エージェント地理分布</h1>
            <p className="text-xs text-[#7d92b0]">エージェントの地理的分布を地域別に可視化します</p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 text-sm transition-colors disabled:opacity-40"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          更新
        </button>
      </div>

      {/* ── Stats Bar ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: '総エージェント', value: totalAgents, color: 'text-white' },
          { label: 'オンライン', value: onlineCount, color: 'text-[#00c853]' },
          { label: 'オフライン', value: offlineCount, color: 'text-[#e8002d]' },
          { label: '国数', value: countryCount, color: 'text-[#1a6bff]' },
        ].map(card => (
          <div key={card.label} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
            <Globe className="w-4 h-4 text-[#3d5068] mb-2" />
            <p className={`text-2xl font-bold tabular-nums ${card.color}`}>{card.value}</p>
            <p className="text-xs text-[#7d92b0] mt-0.5">{card.label}</p>
          </div>
        ))}
      </div>

      {/* ── SVG World Map ── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#e8002d]" />
            ワールドマップ
          </h2>
          <span className="flex items-center gap-1 text-[10px] text-[#7d92b0]">
            <Info className="w-3 h-3" />
            位置情報はIPアドレスから推定されます
          </span>
        </div>
        <div className="relative rounded-lg overflow-hidden" style={{ height: 420, background: '#071020' }}>
          <WorldMap landFill="#1a2540" borderStroke="#2a3d5a" borderWidth={0.5} />

          {/* Agent dots — grouped by country */}
          {Array.from(countryMap.entries()).map(([code, { geo, agents: groupAgents }]) => {
            if (!geo || (geo.lat === 0 && geo.lon === 0)) return null
            const { x, y } = latLonToPercent(geo.lat, geo.lon)
            const onlineCount = groupAgents.filter(a => a.status === 'online').length
            const color = onlineCount > 0 ? '#00c853' : '#7d92b0'
            const count = groupAgents.length
            return (
              <div
                key={code}
                className="absolute cursor-pointer"
                style={{ left: `${x}%`, top: `${y}%`, transform: 'translate(-50%, -50%)', zIndex: 10 }}
                onClick={() => setSelectedPin(selectedPin === code ? null : code)}
              >
                <div className="absolute rounded-full" style={{ width: 20, height: 20, backgroundColor: color, opacity: 0.15, top: '50%', left: '50%', transform: 'translate(-50%,-50%)' }} />
                <div className="rounded-full flex items-center justify-center" style={{ width: count > 1 ? 16 : 10, height: count > 1 ? 16 : 10, backgroundColor: color, opacity: 0.9, boxShadow: `0 0 6px ${color}80`, fontSize: 9, color: '#000', fontWeight: 700 }}>
                  {count > 1 ? count : ''}
                </div>
              </div>
            )
          })}

          {/* Region labels */}
          {[
            { label: 'N. America', lat: 45, lon: -100 },
            { label: 'S. America', lat: -15, lon: -55 },
            { label: 'Europe',     lat: 54,  lon: 15  },
            { label: 'Africa',     lat: 2,   lon: 20  },
            { label: 'Asia',       lat: 40,  lon: 90  },
            { label: 'Australia',  lat: -28, lon: 135 },
          ].map(r => {
            const { x, y } = latLonToPercent(r.lat, r.lon)
            return (
              <div
                key={r.label}
                className="absolute text-[9px] text-[#3d5068] pointer-events-none select-none"
                style={{ left: `${x}%`, top: `${y}%`, transform: 'translate(-50%,-50%)' }}
              >
                {r.label}
              </div>
            )
          })}
        </div>

        {/* Pin popup — rendered outside overflow-hidden */}
        {selectedPin && countryMap.has(selectedPin) && (() => {
          const { geo, agents: groupAgents } = countryMap.get(selectedPin)!
          return (
            <div className="mt-3 bg-[#071828] border border-[#1e2d42] rounded-lg p-4 text-xs">
              <div className="flex items-center justify-between mb-3">
                <p className="font-semibold text-white text-sm">{geo.country}（{groupAgents.length}台）</p>
                <button onClick={() => setSelectedPin(null)} className="text-[#7d92b0] hover:text-white text-lg leading-none">×</button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {groupAgents.map(a => (
                  <div key={a.id} className="bg-[#0d1220] rounded-lg p-3 border border-[#1e2d42]">
                    <p className="text-white font-medium mb-1">{a.hostname}</p>
                    {(a.ip_addresses && a.ip_addresses.length > 0 ? a.ip_addresses : [getAgentIp(a)]).filter(Boolean).map(ip => (
                      <p key={ip} className="text-[#7d92b0]">IP: {ip}</p>
                    ))}
                    <p className="text-[#7d92b0]">OS: {a.os_type ?? a.os ?? '—'}</p>
                    <p className="mt-1" style={{ color: agentDotColor(a.status) }}>{agentStatusLabel(a.status)}</p>
                  </div>
                ))}
              </div>
            </div>
          )
        })()}

        {/* Legend */}
        <div className="flex items-center gap-5 mt-3 text-xs text-[#7d92b0]">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#00c853]" />
            オンライン
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#7d92b0]" />
            オフライン
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#f59e0b]" />
            隔離中
          </span>
        </div>

        {/* Private-IP agents that cannot be plotted on the map */}
        {privateNetAgents.length > 0 && (
          <div className="mt-3 bg-[#071828] border border-[#1e2d42] rounded-lg p-3 text-xs">
            <p className="text-[#7d92b0] mb-2 flex items-center gap-1">
              <Info className="w-3 h-3 shrink-0" />
              <span>以下 {privateNetAgents.length} 台のエージェントはプライベートIPアドレスのため地図上に表示されていません</span>
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {privateNetAgents.filter((a): a is Agent => !!a).map(a => (
                <div key={a.id} className="bg-[#0d1220] rounded-lg p-2 border border-[#1e2d42] flex items-center justify-between">
                  <div>
                    <p className="text-white font-medium">{a.hostname}</p>
                    <p className="text-[#7d92b0]">{(a.ip_addresses && a.ip_addresses.length > 0 ? a.ip_addresses[0] : a.ip_address) ?? '—'}</p>
                  </div>
                  <span style={{ color: agentDotColor(a.status) }} className="text-xs font-medium">
                    {agentStatusLabel(a.status)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Continent filter tabs ── */}
      <div className="flex flex-wrap gap-2">
        {['all', ...CONTINENT_ORDER].map(cont => {
          const label = cont === 'all' ? '全地域' : CONTINENT_LABELS[cont] ?? cont
          const count = cont === 'all' ? totalAgents : (continentGroups[cont] ? Array.from(continentGroups[cont].values()).reduce((s, v) => s + v.agents.length, 0) : 0)
          const active = (cont === 'all' && !activeContinent) || activeContinent === cont
          return (
            <button
              key={cont}
              onClick={() => setActiveContinent(cont === 'all' ? null : cont)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all
                ${active
                  ? 'bg-[#e8002d]/20 border border-[#e8002d]/40 text-[#e8002d]'
                  : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40 hover:text-white'
                }`}
            >
              {label}
              <span className={`px-1.5 py-0.5 rounded-sm text-[10px] font-bold ${active ? 'bg-[#e8002d]/30 text-[#e8002d]' : 'bg-[#1e2d42] text-[#7d92b0]'}`}>
                {count}
              </span>
            </button>
          )
        })}
      </div>

      {/* ── Main content: Region summary table + Country detail panel ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* Region Summary Table */}
        <div className="xl:col-span-2 bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <MapIcon className="w-4 h-4 text-[#e8002d]" />
              地域別サマリー
            </h2>
            <span className="text-xs text-[#7d92b0]">{visibleCountries.length} 国</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] text-[10px] text-[#7d92b0] uppercase tracking-wide">
                  <th className="px-4 py-3 text-left font-medium">地域</th>
                  <th className="px-4 py-3 text-left font-medium">国</th>
                  <th className="px-4 py-3 text-right font-medium">エージェント数</th>
                  <th className="px-4 py-3 text-right font-medium">オンライン</th>
                  <th className="px-4 py-3 text-right font-medium">オフライン</th>
                  <th className="px-4 py-3 text-left font-medium">最終アクティブ</th>
                  <th className="px-4 py-3 text-left font-medium" />
                </tr>
              </thead>
              <tbody>
                {CONTINENT_ORDER.map(continent => {
                  const group = continentGroups[continent]
                  if (!group) return null
                  if (activeContinent && activeContinent !== continent) return null
                  const rows = Array.from(group.entries()).sort((a, b) => b[1].agents.length - a[1].agents.length)
                  return (
                    <>
                      {/* Continent header row */}
                      <tr key={`cont-${continent}`} className="bg-[#0a1525]">
                        <td colSpan={7} className="px-4 py-2">
                          <span className="text-[10px] font-bold text-[#7d92b0] uppercase tracking-wider">
                            {CONTINENT_LABELS[continent] ?? continent}
                          </span>
                        </td>
                      </tr>
                      {rows.map(([code, info]) => {
                        const online = info.agents.filter(a => a.status === 'online').length
                        const offline = info.agents.length - online
                        const latestAgent = info.agents.reduce<Agent | null>((best, a) => {
                          if (!best || (a.last_seen && (!best.last_seen || a.last_seen > best.last_seen))) return a
                          return best
                        }, null)
                        const isSelected = selectedCountry === code
                        return (
                          <tr
                            key={code}
                            onClick={() => setSelectedCountry(isSelected ? null : code)}
                            className={`border-b border-[#1e2d42]/50 cursor-pointer transition-colors
                              ${isSelected ? 'bg-[#1a2540]' : 'hover:bg-[#111928]'}`}
                          >
                            <td className="px-4 py-3 text-xs text-[#7d92b0]">
                              {info?.geo?.region}
                            </td>
                            <td className="px-4 py-3">
                              <span className="text-xs font-medium text-white">{info?.geo?.country}</span>
                              <span className="ml-1.5 text-[10px] text-[#3d5068]">{code}</span>
                            </td>
                            <td className="px-4 py-3 text-right">
                              <span className="text-sm font-bold text-white tabular-nums">{info.agents.length}</span>
                            </td>
                            <td className="px-4 py-3 text-right">
                              <span className="text-xs font-medium text-[#00c853] tabular-nums">{online}</span>
                            </td>
                            <td className="px-4 py-3 text-right">
                              <span className={`text-xs font-medium tabular-nums ${offline > 0 ? 'text-[#e8002d]' : 'text-[#3d5068]'}`}>{offline}</span>
                            </td>
                            <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                              {formatLastSeen(latestAgent?.last_seen)}
                            </td>
                            <td className="px-4 py-3">
                              <ChevronRight className={`w-3.5 h-3.5 transition-transform ${isSelected ? 'rotate-90 text-[#e8002d]' : 'text-[#3d5068]'}`} />
                            </td>
                          </tr>
                        )
                      })}
                    </>
                  )
                })}
                {visibleCountries.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-[#7d92b0] text-sm">
                      データがありません
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Country Detail Panel */}
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          {selectedCountryData ? (
            <>
              <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-white">{selectedCountryData?.geo?.country}</h2>
                  <p className="text-[10px] text-[#7d92b0] mt-0.5">{selectedCountryData?.geo?.region}</p>
                </div>
                <button
                  onClick={() => setSelectedCountry(null)}
                  className="p-1 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Country stats */}
              <div className="grid grid-cols-3 divide-x divide-[#1e2d42] border-b border-[#1e2d42]">
                {[
                  { label: '合計', value: selectedCountryData.agents.length, color: 'text-white' },
                  { label: 'オンライン', value: selectedCountryData.agents.filter(a => a.status === 'online').length, color: 'text-[#00c853]' },
                  { label: 'オフライン', value: selectedCountryData.agents.filter(a => a.status !== 'online').length, color: 'text-[#e8002d]' },
                ].map(s => (
                  <div key={s.label} className="px-3 py-3 text-center">
                    <p className={`text-lg font-bold tabular-nums ${s.color}`}>{s.value}</p>
                    <p className="text-[10px] text-[#7d92b0]">{s.label}</p>
                  </div>
                ))}
              </div>

              {/* Agents list */}
              <div className="overflow-y-auto max-h-[480px]">
                {selectedCountryData.agents.map(agent => (
                  <div key={agent.id} className="flex items-center gap-3 px-4 py-3 border-b border-[#1e2d42]/50 hover:bg-[#111928] transition-colors">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${agent.status === 'online' ? 'bg-[#00c853]' : 'bg-[#7d92b0]'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-white truncate">{agent.hostname}</p>
                      <p className="text-[10px] text-[#7d92b0] mt-0.5">
                        {getAgentIp(agent) || '—'} · {formatLastSeen(agent.last_seen)}
                      </p>
                    </div>
                    <Link
                      href={`/endpoints/${agent.id}`}
                      className="shrink-0 flex items-center gap-1 text-[10px] text-[#1a6bff] hover:text-blue-300 transition-colors"
                    >
                      詳細
                      <ChevronRight className="w-3 h-3" />
                    </Link>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full min-h-[300px] text-center px-6">
              <MapIcon className="w-10 h-10 text-[#1e2d42] mb-3" />
              <p className="text-sm font-medium text-[#7d92b0]">国を選択してください</p>
              <p className="text-xs text-[#3d5068] mt-1">左のテーブルの行をクリックすると<br />その国のエージェント一覧が表示されます</p>
            </div>
          )}
        </div>
      </div>

      {/* ── Continent Distribution Bars ── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
        <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Globe className="w-4 h-4 text-[#e8002d]" />
          大陸別エージェント分布
        </h2>
        <div className="space-y-4">
          {CONTINENT_ORDER.map(cont => {
            const group = continentGroups[cont]
            if (!group) return null
            const count = Array.from(group.values()).reduce((s, v) => s + v.agents.length, 0)
            const online = Array.from(group.values()).reduce((s, v) => s + v.agents.filter(a => a.status === 'online').length, 0)
            const pct = totalAgents > 0 ? Math.round((count / totalAgents) * 100) : 0
            return (
              <div key={cont} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-white font-medium">{CONTINENT_LABELS[cont] ?? cont}</span>
                    <span className="text-[#7d92b0]">{count} エージェント</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[#00c853]">{online} オンライン</span>
                    <span className="text-[#7d92b0] tabular-nums w-10 text-right">{pct}%</span>
                  </div>
                </div>
                <div className="h-2.5 bg-[#0a1525] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${pct}%`,
                      background: 'linear-gradient(90deg, #e8002d, #1a6bff)',
                    }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      </div>

    </div>
  )
}
