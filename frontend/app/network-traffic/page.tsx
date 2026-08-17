'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Network, Activity, Globe, Shield, AlertTriangle,
  Filter, X, Download, Search, Server, Clock,
  ChevronRight, Loader2, Eye, ArrowRight,
} from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

interface TrafficStats {
  total_flows: number
  bandwidth_gb: number
  top_protocol: string
  suspicious_flows: number
}

interface BandwidthPoint {
  time: string
  inbound_gb: number
  outbound_gb: number
}

interface CommPair {
  id: string
  src_ip: string
  dst_ip: string
  protocol: string
  bytes: number
  packets: number
  duration_s: number
  threat_score: number
}

interface GeoEntry {
  country: string
  flag: string
  bytes_gb: number
  pct: number
}

interface ProtoDist {
  name: string
  pct: number
  color: string
}

interface Flow {
  id: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: string
  state: string
  bytes_in: number
  bytes_out: number
  duration_s: number
  process: string
  pid: number
  risk: number
}

interface HttpEntry {
  method: string
  url: string
  status: number
  count: number
}

interface UserAgent {
  ua: string
  count: number
  suspicious: boolean
}

interface DnsEntry {
  domain: string
  count: number
  nx: boolean
  tunnel: boolean
}

interface SmbEntry {
  share: string
  accesses: number
  auth_failures: number
  lateral: boolean
}

interface RdpEntry {
  src_ip: string
  attempts: number
  success: number
  failed: number
}

interface SshEntry {
  src_ip: string
  dst_ip: string
  key_auth: number
  pass_auth: number
  total: number
}

const PROTOS = ['TCP', 'UDP', 'ICMP', 'DNS', 'TLS', 'HTTP', 'HTTPS']
const STATES = ['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT', 'SYN_RECV']
const EMPTY_TRAFFIC_STATS: TrafficStats = { total_flows: 0, bandwidth_gb: 0, top_protocol: 'TCP', suspicious_flows: 0 }

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtBytes(b: number) {
  if (b < 1024) return `${b}B`
  if (b < 1_048_576) return `${(b / 1024).toFixed(1)}KB`
  if (b < 1_073_741_824) return `${(b / 1_048_576).toFixed(1)}MB`
  return `${(b / 1_073_741_824).toFixed(2)}GB`
}

function fmtDuration(s: number) {
  if (s < 60) return `${s}秒`
  if (s < 3600) return `${Math.floor(s / 60)}分`
  return `${(s / 3600).toFixed(1)}時間`
}

function riskColor(r: number) {
  if (r >= 75) return 'text-falcon-red bg-falcon-red/15 border-falcon-red/30'
  if (r >= 40) return 'text-[#ffd740] bg-[#ffd740]/15 border-[#ffd740]/30'
  return 'text-falcon-green bg-falcon-green/15 border-falcon-green/30'
}

function stateBadge(state: string) {
  const m: Record<string, string> = {
    ESTABLISHED: 'bg-falcon-green/15 text-falcon-green border-falcon-green/30',
    CLOSE_WAIT:  'bg-[#ffd740]/15 text-[#ffd740] border-[#ffd740]/30',
    TIME_WAIT:   'bg-falcon-muted/15 text-falcon-muted border-falcon-muted/30',
    SYN_SENT:    'bg-falcon-blue/15 text-falcon-blue border-falcon-blue/30',
    LISTEN:      'bg-[#a855f7]/15 text-[#a855f7] border-[#a855f7]/30',
    FIN_WAIT:    'bg-[#f59e0b]/15 text-[#f59e0b] border-[#f59e0b]/30',
  }
  return m[state] ?? 'bg-falcon-border text-falcon-muted border-falcon-border'
}

function methodBadge(m: string) {
  const c: Record<string, string> = {
    GET:    'bg-falcon-blue/15 text-falcon-blue border-falcon-blue/30',
    POST:   'bg-falcon-green/15 text-falcon-green border-falcon-green/30',
    PUT:    'bg-[#ffd740]/15 text-[#ffd740] border-[#ffd740]/30',
    DELETE: 'bg-falcon-red/15 text-falcon-red border-falcon-red/30',
    PATCH:  'bg-[#a855f7]/15 text-[#a855f7] border-[#a855f7]/30',
  }
  return c[m] ?? 'bg-falcon-border text-falcon-muted border-falcon-border'
}

function statusBadge(s: number) {
  if (s < 300) return 'bg-falcon-green/15 text-falcon-green border-falcon-green/30'
  if (s < 400) return 'bg-falcon-blue/15 text-falcon-blue border-falcon-blue/30'
  if (s < 500) return 'bg-[#ffd740]/15 text-[#ffd740] border-[#ffd740]/30'
  return 'bg-falcon-red/15 text-falcon-red border-falcon-red/30'
}

// ─── Bandwidth Area Chart SVG ─────────────────────────────────────────────────

function BandwidthChart({ data }: { data: BandwidthPoint[] }) {
  const W = 700, H = 180, PL = 44, PR = 16, PT = 16, PB = 32
  const n = data.length
  if (!n) return null

  const allVals = data.flatMap(d => [d.inbound_gb, d.outbound_gb])
  const maxV = Math.max(...allVals, 0.1) * 1.2

  const toX = (i: number) => PL + (i / (n - 1)) * (W - PL - PR)
  const toY = (v: number) => PT + (1 - v / maxV) * (H - PT - PB)

  const inPath  = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toY(d.inbound_gb)}`).join(' ')
  const outPath = data.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toY(d.outbound_gb)}`).join(' ')

  const ticks = n <= 12 ? data.map((_, i) => i) : [0, Math.floor(n * 0.25), Math.floor(n * 0.5), Math.floor(n * 0.75), n - 1]

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 180 }}>
        <defs>
          <linearGradient id="bwIn" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#1a6bff" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#1a6bff" stopOpacity="0.02" />
          </linearGradient>
          <linearGradient id="bwOut" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#22c55e" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#22c55e" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {[0, 0.25, 0.5, 0.75, 1].map(f => {
          const y = PT + (1 - f) * (H - PT - PB)
          return (
            <g key={f}>
              <line x1={PL} y1={y} x2={W - PR} y2={y} stroke="#1e2d42" strokeWidth="1" strokeDasharray="3,4" />
              <text x={PL - 4} y={y + 3} textAnchor="end" fill="#3d5068" fontSize="8">{(maxV * f).toFixed(1)}</text>
            </g>
          )
        })}
        <path d={`${inPath} L ${toX(n - 1)} ${H - PB} L ${toX(0)} ${H - PB} Z`} fill="url(#bwIn)" />
        <path d={`${outPath} L ${toX(n - 1)} ${H - PB} L ${toX(0)} ${H - PB} Z`} fill="url(#bwOut)" />
        <path d={inPath} fill="none" stroke="#1a6bff" strokeWidth="2" strokeLinejoin="round" />
        <path d={outPath} fill="none" stroke="#22c55e" strokeWidth="2" strokeLinejoin="round" />
        {ticks.map(i => (
          <text key={i} x={toX(i)} y={H - PB + 14} textAnchor="middle" fill="#3d5068" fontSize="8">{data[i].time}</text>
        ))}
        <text x={PL - 4} y={PT - 4} textAnchor="end" fill="#7d92b0" fontSize="7">GB</text>
      </svg>
      <div className="flex items-center gap-6 mt-1 text-xs text-falcon-muted">
        <span className="flex items-center gap-1.5"><span className="w-4 h-0.5 bg-blue-500 inline-block rounded-sm" />受信 (インバウンド)</span>
        <span className="flex items-center gap-1.5"><span className="w-4 h-0.5 bg-green-500 inline-block rounded-sm" />送信 (アウトバウンド)</span>
      </div>
    </div>
  )
}

// ─── Protocol Pie SVG ─────────────────────────────────────────────────────────

function ProtoPie({ protos }: { protos: ProtoDist[] }) {
  const size = 160, cx = size / 2, cy = size / 2, r = size * 0.38, sw = size * 0.15
  let cumulAngle = -90

  return (
    <div className="flex items-center gap-6">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {protos.map((p, i) => {
          const angle = (p.pct / 100) * 360
          const startA = cumulAngle
          cumulAngle += angle
          const endA = cumulAngle
          const toRad = (d: number) => (d * Math.PI) / 180
          const px1 = cx + r * Math.cos(toRad(startA))
          const py1 = cy + r * Math.sin(toRad(startA))
          const px2 = cx + r * Math.cos(toRad(endA))
          const py2 = cy + r * Math.sin(toRad(endA))
          const large = angle > 180 ? 1 : 0
          const circ = 2 * Math.PI * r
          const arcLen = (angle / 360) * circ
          const gapAngle = 2
          const gapOffset = gapAngle / 360 * circ
          return (
            <circle
              key={p.name}
              cx={cx} cy={cy} r={r}
              fill="none"
              stroke={p.color}
              strokeWidth={sw}
              strokeDasharray={`${arcLen - gapOffset} ${circ - arcLen + gapOffset}`}
              strokeDashoffset={-((startA + 90) / 360 * circ)}
              transform={`rotate(0 ${cx} ${cy})`}
              style={{ filter: `drop-shadow(0 0 4px ${p.color}50)` }}
            />
          )
        })}
        <text x={cx} y={cy + 3} textAnchor="middle" dominantBaseline="middle" fill="white" fontSize="10" fontWeight="bold">プロトコル</text>
      </svg>
      <div className="space-y-1.5 flex-1">
        {protos.map(p => (
          <div key={p.name} className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-xs shrink-0" style={{ background: p.color }} />
            <span className="text-xs text-falcon-text w-16">{p.name}</span>
            <div className="flex-1 h-1.5 bg-falcon-border rounded-full overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${p.pct}%`, background: p.color }} />
            </div>
            <span className="text-xs font-semibold text-falcon-muted w-8 text-right">{p.pct}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Flow Detail Modal ────────────────────────────────────────────────────────

function FlowDetailModal({ flow, onClose }: { flow: Flow; onClose: () => void }) {
  const geoMap: Record<string, { country: string; city: string }> = {
    '142.250.80.46': { country: 'アメリカ合衆国', city: 'マウンテンビュー' },
    '185.220.101.45': { country: 'ロシア', city: 'モスクワ' },
    '8.8.8.8': { country: 'アメリカ合衆国', city: 'マウンテンビュー (Google DNS)' },
    '203.0.113.50': { country: '中国', city: 'Beijing' },
    '52.84.12.10': { country: 'アメリカ合衆国', city: 'Ashburn' },
  }
  const geo = geoMap[flow.dst_ip] ?? { country: '不明', city: '不明' }
  const rdns: Record<string, string> = {
    '142.250.80.46': 'lga34s10-in-f14.1e100.net',
    '185.220.101.45': '185.220.101.45.in-addr.arpa (PTRなし)',
    '8.8.8.8': 'dns.google',
    '203.0.113.50': '203.0.113.50.in-addr.arpa (PTRなし)',
  }

  const similarFlows = ([] as Flow[]).filter(f => f.id !== flow.id && (f.dst_ip === flow.dst_ip || f.process === flow.process)).slice(0, 3)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-3">
            <Network className="w-5 h-5 text-falcon-red" />
            <div>
              <h2 className="text-falcon-text font-semibold text-sm">フロー詳細調査</h2>
              <p className="text-falcon-muted text-xs">{flow.id}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5 space-y-5">

          {/* Basic info */}
          <div className="grid grid-cols-2 gap-4">
            <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border space-y-2">
              <p className="text-[10px] text-falcon-muted uppercase tracking-wider font-medium">接続情報</p>
              <div className="flex items-center gap-2 text-xs">
                <span className="font-mono text-falcon-text">{flow.src_ip}:{flow.src_port}</span>
                <ArrowRight className="w-3 h-3 text-falcon-muted" />
                <span className="font-mono text-falcon-text">{flow.dst_ip}:{flow.dst_port}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div><p className="text-falcon-muted">プロトコル</p><p className="text-falcon-text font-medium">{flow.protocol}</p></div>
                <div><p className="text-falcon-muted">状態</p><p className="text-falcon-text font-medium">{flow.state}</p></div>
                <div><p className="text-falcon-muted">受信量</p><p className="text-falcon-text">{fmtBytes(flow.bytes_in)}</p></div>
                <div><p className="text-falcon-muted">送信量</p><p className="text-falcon-text">{fmtBytes(flow.bytes_out)}</p></div>
                <div><p className="text-falcon-muted">継続時間</p><p className="text-falcon-text">{fmtDuration(flow.duration_s)}</p></div>
                <div><p className="text-falcon-muted">リスクスコア</p>
                  <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] font-bold ${riskColor(flow.risk)}`}>{flow.risk}</span>
                </div>
              </div>
            </div>
            <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border space-y-2">
              <p className="text-[10px] text-falcon-muted uppercase tracking-wider font-medium">プロセス情報</p>
              <div className="text-xs space-y-1.5">
                <div><p className="text-falcon-muted">プロセス名</p><p className="text-falcon-text font-mono">{flow.process}</p></div>
                <div><p className="text-falcon-muted">PID</p><p className="text-falcon-text font-mono">{flow.pid}</p></div>
              </div>
              <p className="text-[10px] text-falcon-muted uppercase tracking-wider font-medium mt-3">逆引きDNS</p>
              <p className="text-xs font-mono text-falcon-text">{rdns[flow.dst_ip] ?? `${flow.dst_ip}.in-addr.arpa (不明)`}</p>
            </div>
          </div>

          {/* Geolocation */}
          <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
            <p className="text-[10px] text-falcon-muted uppercase tracking-wider font-medium mb-2">ジオロケーション (宛先)</p>
            <div className="flex items-center gap-4 text-xs">
              <Globe className="w-4 h-4 text-falcon-muted" />
              <div><p className="text-falcon-muted">国</p><p className="text-falcon-text font-medium">{geo.country}</p></div>
              <div><p className="text-falcon-muted">都市</p><p className="text-falcon-text">{geo.city}</p></div>
            </div>
          </div>

          {/* Similar flows */}
          {similarFlows.length > 0 && (
            <div>
              <p className="text-xs text-falcon-muted font-medium mb-2">類似フロー</p>
              <div className="space-y-1.5">
                {similarFlows.map(f => (
                  <div key={f.id} className="flex items-center gap-3 p-2 bg-[#070d19] rounded-sm border border-falcon-border text-xs">
                    <span className="font-mono text-falcon-muted">{f.id}</span>
                    <span className="font-mono text-falcon-text">{f.src_ip}:{f.src_port}</span>
                    <ArrowRight className="w-3 h-3 text-falcon-subtle" />
                    <span className="font-mono text-falcon-text">{f.dst_ip}:{f.dst_port}</span>
                    <span className={`ml-auto px-1.5 py-0.5 rounded-sm border text-[10px] font-bold ${riskColor(f.risk)}`}>{f.risk}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Tab: トラフィック概要 ─────────────────────────────────────────────────────

function OverviewTab() {
  const [range, setRange] = useState<'1h' | '6h' | '24h' | '7d'>('24h')

  const bwData: BandwidthPoint[] = []
  const pairMax = 1

  return (
    <div className="space-y-5">
      {/* Time range + chart */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-falcon-text flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-400" />帯域幅推移
          </h3>
          <div className="flex gap-1">
            {(['1h', '6h', '24h', '7d'] as const).map(r => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`px-3 py-1 text-xs rounded font-medium transition-colors
                  ${range === r ? 'bg-falcon-red text-white' : 'bg-falcon-border text-falcon-muted hover:text-falcon-text'}`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
        <BandwidthChart data={bwData} />
      </div>

      {/* Comm pairs table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <h3 className="text-sm font-semibold text-falcon-text mb-4 flex items-center gap-2">
          <ArrowRight className="w-4 h-4 text-falcon-muted" />上位通信ペア (Top 10)
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-falcon-border bg-[#070d19]/40">
                {['送信元', '宛先', 'プロトコル', 'データ量', 'パケット数', '継続時間', 'リスク'].map(h => (
                  <th key={h} className="text-left py-2 px-3 text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {([] as CommPair[]).map(p => (
                <tr key={p.id} className="border-b border-falcon-border/40 hover:bg-falcon-border/20">
                  <td className="py-2.5 px-3 font-mono text-falcon-text">{p.src_ip}</td>
                  <td className="py-2.5 px-3 font-mono text-falcon-text">{p.dst_ip}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 bg-falcon-border text-falcon-muted border border-[#2d3f58] rounded-sm text-[10px] font-medium">{p.protocol}</span>
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1 bg-falcon-border rounded-full overflow-hidden">
                        <div className="h-full bg-blue-500 rounded-full" style={{ width: `${(p.bytes / pairMax) * 100}%` }} />
                      </div>
                      <span className="text-falcon-muted">{fmtBytes(p.bytes)}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-falcon-muted">{(p.packets ?? 0).toLocaleString()}</td>
                  <td className="py-2.5 px-3 text-falcon-muted">{fmtDuration(p.duration_s)}</td>
                  <td className="py-2.5 px-3">
                    <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] font-bold ${riskColor(p.threat_score)}`}>{p.threat_score}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Geo + Protocol side by side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-falcon-text mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-falcon-muted" />地域分布 (宛先国・Top 5)
          </h3>
          <div className="space-y-3">
            {([] as GeoEntry[]).map(g => (
              <div key={g.country}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm flex items-center gap-2">
                    <span>{g.flag}</span>
                    <span className="text-falcon-text text-xs">{g.country}</span>
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-falcon-muted">{g.bytes_gb}GB</span>
                    <span className="text-xs font-bold text-falcon-text">{g.pct}%</span>
                  </div>
                </div>
                <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${g.pct}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-falcon-text mb-4 flex items-center gap-2">
            <Network className="w-4 h-4 text-falcon-muted" />プロトコル分布
          </h3>
          <ProtoPie protos={[]} />
        </div>
      </div>
    </div>
  )
}

// ─── Tab: フロー分析 ──────────────────────────────────────────────────────────

function FlowAnalysisTab() {
  const [protoFilter, setProtoFilter] = useState('all')
  const [stateFilter, setStateFilter] = useState('all')
  const [riskFilter,  setRiskFilter]  = useState('all')
  const [portRange,   setPortRange]   = useState('')
  const [agent,       setAgent]       = useState('all')
  const [selectedFlow, setSelectedFlow] = useState<Flow | null>(null)

  const filtered = useMemo(() => ([] as Flow[]).filter(f => {
    if (protoFilter !== 'all' && f.protocol !== protoFilter) return false
    if (stateFilter !== 'all' && f.state !== stateFilter) return false
    if (riskFilter === 'high'   && f.risk < 75) return false
    if (riskFilter === 'medium' && (f.risk < 40 || f.risk >= 75)) return false
    if (riskFilter === 'low'    && f.risk >= 40) return false
    if (portRange) {
      const [lo, hi] = portRange.split('-').map(Number)
      const p = f.dst_port
      if (hi ? (p < lo || p > hi) : p !== lo) return false
    }
    return true
  }), [protoFilter, stateFilter, riskFilter, portRange])

  function exportCSV() {
    const header = 'ID,送信元IP,送信元Port,宛先IP,宛先Port,プロトコル,状態,受信量,送信量,継続時間,プロセス,PID,リスク'
    const rows = filtered.map(f =>
      [f.id, f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.protocol, f.state,
       fmtBytes(f.bytes_in), fmtBytes(f.bytes_out), fmtDuration(f.duration_s), f.process, f.pid, f.risk].join(',')
    )
    const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'flows.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      {selectedFlow && <FlowDetailModal flow={selectedFlow} onClose={() => setSelectedFlow(null)} />}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Filter className="w-4 h-4 text-falcon-muted" />
        <select value={agent} onChange={e => setAgent(e.target.value)}
          className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-falcon-text focus:outline-hidden focus:border-falcon-red/60">
          <option value="all">全エージェント</option>
          <option value="WIN-ENDPOINT-01">WIN-ENDPOINT-01</option>
          <option value="WIN-SERVER-02">WIN-SERVER-02</option>
          <option value="MAC-DEV-01">MAC-DEV-01</option>
        </select>
        <select value={protoFilter} onChange={e => setProtoFilter(e.target.value)}
          className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-falcon-text focus:outline-hidden focus:border-falcon-red/60">
          <option value="all">全プロトコル</option>
          {PROTOS.map(p => <option key={p}>{p}</option>)}
        </select>
        <select value={stateFilter} onChange={e => setStateFilter(e.target.value)}
          className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-falcon-text focus:outline-hidden focus:border-falcon-red/60">
          <option value="all">全状態</option>
          {STATES.map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
          className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-falcon-text focus:outline-hidden focus:border-falcon-red/60">
          <option value="all">全リスク</option>
          <option value="high">高 (75+)</option>
          <option value="medium">中 (40-74)</option>
          <option value="low">低 (&lt;40)</option>
        </select>
        <input
          value={portRange}
          onChange={e => setPortRange(e.target.value)}
          placeholder="ポート例: 443 または 1024-65535"
          className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-falcon-text focus:outline-hidden focus:border-falcon-red/60 w-52"
        />
        <span className="text-xs text-falcon-muted">{filtered.length}件</span>
        <button
          onClick={exportCSV}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 bg-falcon-border hover:bg-[#2a3f5f] text-falcon-text text-xs rounded-lg border border-[#2d3f58] transition-colors"
        >
          <Download className="w-3.5 h-3.5" />CSV出力
        </button>
      </div>

      {/* Flow table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-falcon-border bg-[#070d19]/40">
                {['送信元 IP:Port', '宛先 IP:Port', 'プロトコル', '状態', '受信量', '送信量', '継続時間', 'プロセス', 'PID', 'リスク', ''].map(h => (
                  <th key={h} className="text-left py-2 px-3 text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr key={f.id} className={`border-b border-falcon-border/40 hover:bg-falcon-border/20 ${f.risk >= 75 ? 'bg-red-500/5' : ''}`}>
                  <td className="py-2 px-3 font-mono text-falcon-text">{f.src_ip}:{f.src_port}</td>
                  <td className="py-2 px-3 font-mono text-falcon-text">{f.dst_ip}:{f.dst_port}</td>
                  <td className="py-2 px-3">
                    <span className="px-1.5 py-0.5 bg-falcon-border text-falcon-muted border border-[#2d3f58] rounded-sm text-[10px] font-medium">{f.protocol}</span>
                  </td>
                  <td className="py-2 px-3">
                    <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] font-medium ${stateBadge(f.state)}`}>{f.state}</span>
                  </td>
                  <td className="py-2 px-3 text-falcon-muted">{fmtBytes(f.bytes_in)}</td>
                  <td className="py-2 px-3 text-falcon-muted">{fmtBytes(f.bytes_out)}</td>
                  <td className="py-2 px-3 text-falcon-muted whitespace-nowrap">{fmtDuration(f.duration_s)}</td>
                  <td className="py-2 px-3 font-mono text-falcon-muted">{f.process}</td>
                  <td className="py-2 px-3 font-mono text-falcon-muted">{f.pid}</td>
                  <td className="py-2 px-3">
                    <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] font-bold ${riskColor(f.risk)}`}>{f.risk}</span>
                  </td>
                  <td className="py-2 px-3">
                    <button
                      onClick={() => setSelectedFlow(f)}
                      className="flex items-center gap-1 px-2 py-1 text-xs bg-falcon-border hover:bg-[#2a3f5f] text-falcon-text rounded-sm border border-[#2d3f58] transition-colors whitespace-nowrap"
                    >
                      <Eye className="w-3 h-3" />調査
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ─── Tab: プロトコル詳細 ──────────────────────────────────────────────────────

function ProtocolDetailTab() {
  const [proto, setProto] = useState<'HTTP' | 'DNS' | 'SMB' | 'RDP' | 'SSH'>('HTTP')

  const protoTabs = ['HTTP', 'DNS', 'SMB', 'RDP', 'SSH'] as const

  return (
    <div className="space-y-4">
      {/* Protocol sub-tabs */}
      <div className="flex gap-1 flex-wrap">
        {protoTabs.map(p => (
          <button
            key={p}
            onClick={() => setProto(p)}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors
              ${proto === p ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-falcon-text'}`}
          >
            {p}
          </button>
        ))}
      </div>

      {/* HTTP */}
      {proto === 'HTTP' && (
        <div className="space-y-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-sm font-semibold text-falcon-text mb-4">上位URLアクセス</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['メソッド', 'URL', 'ステータス', 'リクエスト数'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {([] as HttpEntry[]).map((h, i) => (
                    <tr key={i} className="border-b border-falcon-border/40 hover:bg-falcon-border/20">
                      <td className="py-2 px-3"><span className={`px-1.5 py-0.5 rounded-sm border text-[10px] font-bold ${methodBadge(h.method)}`}>{h.method}</span></td>
                      <td className="py-2 px-3 font-mono text-falcon-muted max-w-[280px]"><span className="truncate block">{h.url}</span></td>
                      <td className="py-2 px-3"><span className={`px-1.5 py-0.5 rounded-sm border text-[10px] font-bold ${statusBadge(h.status)}`}>{h.status}</span></td>
                      <td className="py-2 px-3 text-falcon-text font-semibold">{(h.count ?? 0).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-sm font-semibold text-falcon-text mb-4">User-Agent 一覧</h3>
            <div className="space-y-2">
              {([] as UserAgent[]).map((ua, i) => (
                <div key={i} className={`flex items-center gap-3 p-3 rounded-lg border text-xs ${ua.suspicious ? 'border-red-500/20 bg-red-500/5' : 'border-falcon-border bg-[#070d19]'}`}>
                  <span className="font-mono text-falcon-muted flex-1 truncate">{ua.ua}</span>
                  <span className="text-falcon-text font-semibold whitespace-nowrap">{(ua.count ?? 0).toLocaleString()}件</span>
                  {ua.suspicious && <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-sm text-[9px] font-medium whitespace-nowrap">不審</span>}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* DNS */}
      {proto === 'DNS' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-falcon-text mb-4">DNSクエリ分析</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ドメイン', 'クエリ数', 'NX失敗', 'トンネル疑い'].map(h => (
                    <th key={h} className="text-left py-2 px-3 text-falcon-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {([] as DnsEntry[]).map((d, i) => (
                  <tr key={i} className={`border-b border-falcon-border/40 hover:bg-falcon-border/20 ${(d.nx || d.tunnel) ? 'bg-red-500/5' : ''}`}>
                    <td className="py-2 px-3 font-mono text-falcon-text">{d.domain}</td>
                    <td className="py-2 px-3 text-falcon-muted">{(d.count ?? 0).toLocaleString()}</td>
                    <td className="py-2 px-3">
                      {d.nx ? <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-sm text-[10px] font-medium">NXDOMAIN</span>
                             : <span className="text-falcon-subtle">—</span>}
                    </td>
                    <td className="py-2 px-3">
                      {d.tunnel ? <span className="px-1.5 py-0.5 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded-sm text-[10px] font-medium">検出</span>
                                : <span className="text-falcon-subtle">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SMB */}
      {proto === 'SMB' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-falcon-text mb-4">SMB共有アクセス状況</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['共有パス', 'アクセス数', '認証失敗', '横断移動の疑い'].map(h => (
                    <th key={h} className="text-left py-2 px-3 text-falcon-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {([] as SmbEntry[]).map((s, i) => (
                  <tr key={i} className={`border-b border-falcon-border/40 hover:bg-falcon-border/20 ${s.lateral ? 'bg-red-500/5' : ''}`}>
                    <td className="py-2 px-3 font-mono text-falcon-text">{s.share}</td>
                    <td className="py-2 px-3 text-falcon-muted">{(s.accesses ?? 0).toLocaleString()}</td>
                    <td className="py-2 px-3">
                      {s.auth_failures > 0
                        ? <span className="text-falcon-red font-semibold">{s.auth_failures}回</span>
                        : <span className="text-falcon-green">0回</span>}
                    </td>
                    <td className="py-2 px-3">
                      {s.lateral ? <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-sm text-[10px] font-medium">横断移動検出</span>
                                 : <span className="text-falcon-subtle">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* RDP */}
      {proto === 'RDP' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-falcon-text mb-4">RDP接続試行</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['送信元IP', '接続試行', '成功', '失敗'].map(h => (
                    <th key={h} className="text-left py-2 px-3 text-falcon-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {([] as RdpEntry[]).map((r, i) => (
                  <tr key={i} className={`border-b border-falcon-border/40 hover:bg-falcon-border/20 ${r.failed > 100 ? 'bg-red-500/5' : ''}`}>
                    <td className="py-2 px-3 font-mono text-falcon-text">{r.src_ip}</td>
                    <td className="py-2 px-3 text-falcon-muted font-semibold">{(r.attempts ?? 0).toLocaleString()}</td>
                    <td className="py-2 px-3 text-falcon-green font-semibold">{r.success}</td>
                    <td className="py-2 px-3">
                      <span className={r.failed > 100 ? 'text-falcon-red font-semibold' : 'text-falcon-muted'}>{(r.failed ?? 0).toLocaleString()}</span>
                      {r.failed > 100 && <span className="ml-2 px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-sm text-[9px] font-medium">ブルートフォース疑い</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SSH */}
      {proto === 'SSH' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-semibold text-falcon-text mb-4">SSH接続分析</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['送信元IP', '宛先IP', '鍵認証', 'パスワード認証', '合計'].map(h => (
                    <th key={h} className="text-left py-2 px-3 text-falcon-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {([] as SshEntry[]).map((s, i) => (
                  <tr key={i} className={`border-b border-falcon-border/40 hover:bg-falcon-border/20 ${s.pass_auth > 100 ? 'bg-orange-500/5' : ''}`}>
                    <td className="py-2 px-3 font-mono text-falcon-text">{s.src_ip}</td>
                    <td className="py-2 px-3 font-mono text-falcon-text">{s.dst_ip}</td>
                    <td className="py-2 px-3 text-falcon-green font-semibold">{s.key_auth}</td>
                    <td className="py-2 px-3">
                      <span className={s.pass_auth > 100 ? 'text-[#ffd740] font-semibold' : 'text-falcon-muted'}>{s.pass_auth}</span>
                      {s.pass_auth > 100 && <span className="ml-2 px-1.5 py-0.5 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded-sm text-[9px] font-medium">要監視</span>}
                    </td>
                    <td className="py-2 px-3 text-falcon-text font-semibold">{s.total}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 p-3 bg-[#070d19] rounded-lg border border-yellow-500/20">
            <p className="text-xs text-[#ffd740] font-medium flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              パスワード認証の多用は推奨されません。鍵認証への移行を検討してください。
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function NetworkTrafficPage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'flows' | 'protocols'>('overview')

  const { data: stats } = useQuery<TrafficStats>({
    queryKey: ['network-traffic-stats'],
    queryFn: () => apiFetch<TrafficStats>('/api/v1/network-traffic/stats').catch(() => EMPTY_TRAFFIC_STATS),
    staleTime: 60_000,
    refetchInterval: 60_000,
  })

  const s: TrafficStats = stats ?? EMPTY_TRAFFIC_STATS

  const statCards = [
    { label: '本日の総フロー数', value: (s.total_flows ?? 0).toLocaleString(), icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
    { label: '帯域幅使用量', value: `${s.bandwidth_gb ?? 0} GB`, icon: Network, color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20' },
    { label: '最多プロトコル', value: s.top_protocol ?? '—', icon: Server, color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20' },
    { label: '不審フロー', value: String(s.suspicious_flows ?? 0), icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
  ]

  const tabs = [
    { key: 'overview',   label: 'トラフィック概要' },
    { key: 'flows',      label: 'フロー分析' },
    { key: 'protocols',  label: 'プロトコル詳細' },
  ] as const

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-falcon-text flex items-center gap-3">
            <Network className="w-6 h-6 text-falcon-red" />
            ネットワークトラフィック分析
          </h1>
          <p className="text-falcon-muted text-sm mt-1">プロトコル別統計・フロー分析・異常検知</p>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statCards.map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className={`bg-falcon-surface border rounded-xl p-4 ${c.bg}`}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#070d19]/60">
                  <Icon className={`w-5 h-5 ${c.color}`} />
                </div>
                <div>
                  <p className={`text-xl font-bold ${c.color}`}>{c.value}</p>
                  <p className="text-falcon-muted text-xs">{c.label}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-falcon-border">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px
              ${activeTab === t.key
                ? 'border-falcon-red text-falcon-text'
                : 'border-transparent text-falcon-muted hover:text-falcon-text'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'overview'   && <OverviewTab />}
      {activeTab === 'flows'      && <FlowAnalysisTab />}
      {activeTab === 'protocols'  && <ProtocolDetailTab />}
    </div>
  )
}
