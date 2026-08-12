'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Network, Activity, AlertTriangle, Shield, Globe, Zap,
  Filter, X, ChevronRight, Eye, BellOff, Loader2,
  TrendingUp, TrendingDown, Radio, Server, RefreshCw,
  Clock, AlertCircle, CheckCircle, Search
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os: string
  status: string
}

interface AnomalyStats {
  anomalies_today: number
  traffic_spikes: number
  suspicious_ports: number
  c2_beaconing_alerts: number
}

type AnomalyType = 'traffic_spike' | 'new_port' | 'beaconing' | 'lateral_movement' | 'dns_tunnel'
type Severity = 'low' | 'medium' | 'high' | 'critical'

interface NetworkAnomaly {
  id: string
  type: AnomalyType
  agent_id: string
  agent_hostname: string
  description: string
  severity: Severity
  source_ip: string
  source_port: number | null
  dest_ip: string | null
  dest_port: number | null
  detected_at: string
  related_alert_id: string | null
  suppressed: boolean
  bytes_transferred: number | null
}

interface TrafficDataPoint {
  hour: number
  inbound_bytes: number
  outbound_bytes: number
  anomaly: boolean
}

interface TopIP {
  ip: string
  bytes_in: number
  bytes_out: number
  connections: number
  country: string
  threat_match: boolean
}

interface ProtocolDist {
  protocol: string
  bytes: number
  percentage: number
}

interface PortScanData {
  agent_id: string
  agent_hostname: string
  range_0_1023: number
  range_1024_4999: number
  range_5000_9999: number
  range_10000_plus: number
}

interface SuspiciousPort {
  port: number
  protocol: string
  description: string
  threat: string
  count: number
}

// ── Mock Data ─────────────────────────────────────────────────────────────────

const MOCK_STATS: AnomalyStats = {
  anomalies_today: 31,
  traffic_spikes: 8,
  suspicious_ports: 12,
  c2_beaconing_alerts: 5,
}

const MOCK_ANOMALIES: NetworkAnomaly[] = [
  {
    id: 'an-001', type: 'beaconing', agent_id: 'agent-001', agent_hostname: 'WIN-ENDPOINT-01',
    description: '定期的なC2通信を検出: 185.220.101.45:443 へ30秒間隔でビーコン送信',
    severity: 'critical', source_ip: '192.168.1.101', source_port: 49234,
    dest_ip: '185.220.101.45', dest_port: 443, detected_at: '2026-03-18T08:22:00Z',
    related_alert_id: 'ALT-2026-0312', suppressed: false, bytes_transferred: 48200,
  },
  {
    id: 'an-002', type: 'traffic_spike', agent_id: 'agent-002', agent_hostname: 'WIN-SERVER-02',
    description: 'アウトバウンドトラフィックが通常の850%増加 (ベースライン: 2.3MB/h → 実測: 19.5MB/h)',
    severity: 'high', source_ip: '192.168.1.102', source_port: null,
    dest_ip: null, dest_port: null, detected_at: '2026-03-18T09:45:00Z',
    related_alert_id: null, suppressed: false, bytes_transferred: 20390000,
  },
  {
    id: 'an-003', type: 'new_port', agent_id: 'agent-003', agent_hostname: 'MAC-DEV-01',
    description: '未知のポートでのリスニング検出: TCP/4444 (Metasploit デフォルトポート)',
    severity: 'high', source_ip: '192.168.1.103', source_port: 4444,
    dest_ip: null, dest_port: null, detected_at: '2026-03-18T10:12:00Z',
    related_alert_id: 'ALT-2026-0315', suppressed: false, bytes_transferred: null,
  },
  {
    id: 'an-004', type: 'lateral_movement', agent_id: 'agent-004', agent_hostname: 'WIN-WORKSTATION-04',
    description: '内部ネットワーク横断移動の疑い: 複数の内部ホストへSMB (445) スキャン',
    severity: 'critical', source_ip: '192.168.1.104', source_port: null,
    dest_ip: '192.168.1.0/24', dest_port: 445, detected_at: '2026-03-18T11:30:00Z',
    related_alert_id: 'ALT-2026-0318', suppressed: false, bytes_transferred: 8900,
  },
  {
    id: 'an-005', type: 'dns_tunnel', agent_id: 'agent-001', agent_hostname: 'WIN-ENDPOINT-01',
    description: 'DNSトンネリングの可能性: 通常の20倍のDNSクエリ数、長いサブドメイン名を検出',
    severity: 'high', source_ip: '192.168.1.101', source_port: 53,
    dest_ip: '8.8.8.8', dest_port: 53, detected_at: '2026-03-18T12:05:00Z',
    related_alert_id: null, suppressed: false, bytes_transferred: 124000,
  },
  {
    id: 'an-006', type: 'traffic_spike', agent_id: 'agent-005', agent_hostname: 'LINUX-SERVER-01',
    description: 'インバウンドスパイク検出: 外部IP 203.0.113.50 から大量接続試行 (DDoS疑い)',
    severity: 'medium', source_ip: '203.0.113.50', source_port: null,
    dest_ip: '192.168.1.105', dest_port: 80, detected_at: '2026-03-18T13:20:00Z',
    related_alert_id: null, suppressed: false, bytes_transferred: 5600000,
  },
  {
    id: 'an-007', type: 'new_port', agent_id: 'agent-002', agent_hostname: 'WIN-SERVER-02',
    description: 'RAT通信に使われる既知のポート検出: TCP/1080 (SOCKS プロキシ)',
    severity: 'medium', source_ip: '192.168.1.102', source_port: 1080,
    dest_ip: null, dest_port: null, detected_at: '2026-03-18T14:00:00Z',
    related_alert_id: null, suppressed: false, bytes_transferred: null,
  },
  {
    id: 'an-008', type: 'beaconing', agent_id: 'agent-003', agent_hostname: 'MAC-DEV-01',
    description: '規則的な外部通信: update-cdn.suspicious.net へ5分間隔アクセス',
    severity: 'medium', source_ip: '192.168.1.103', source_port: 49812,
    dest_ip: null, dest_port: 443, detected_at: '2026-03-18T14:45:00Z',
    related_alert_id: null, suppressed: true, bytes_transferred: 3200,
  },
]

function generateTraffic(agentId: string): TrafficDataPoint[] {
  const base = agentId === 'agent-001' ? 3_000_000 : agentId === 'agent-002' ? 8_000_000 : 1_500_000
  return Array.from({ length: 24 }, (_, i) => {
    const isSpike = (agentId === 'agent-002' && i === 9) || (agentId === 'agent-001' && i === 8)
    const jitter = 0.5 + Math.random()
    return {
      hour: i,
      inbound_bytes: Math.floor(base * jitter * (isSpike ? 8.5 : 1)),
      outbound_bytes: Math.floor(base * 0.6 * jitter * (isSpike ? 3 : 1)),
      anomaly: isSpike,
    }
  })
}

const MOCK_TOP_IPS: TopIP[] = [
  { ip: '185.220.101.45', bytes_in: 2400000, bytes_out: 48200, connections: 287, country: 'RU', threat_match: true },
  { ip: '203.0.113.50',   bytes_in: 5600000, bytes_out: 12000, connections: 1240, country: 'CN', threat_match: true },
  { ip: '8.8.8.8',        bytes_in: 890000,  bytes_out: 124000, connections: 4500, country: 'US', threat_match: false },
  { ip: '142.250.80.46',  bytes_in: 3200000, bytes_out: 980000, connections: 820, country: 'US', threat_match: false },
  { ip: '91.108.4.100',   bytes_in: 420000,  bytes_out: 230000, connections: 156, country: 'NL', threat_match: true },
]

const MOCK_PROTOCOLS: ProtocolDist[] = [
  { protocol: 'HTTPS', bytes: 45_000_000, percentage: 52 },
  { protocol: 'HTTP',  bytes: 15_000_000, percentage: 17 },
  { protocol: 'DNS',   bytes: 12_000_000, percentage: 14 },
  { protocol: 'SMB',   bytes:  8_000_000, percentage: 9 },
  { protocol: 'RDP',   bytes:  5_000_000, percentage: 6 },
  { protocol: 'Other', bytes:  2_000_000, percentage: 2 },
]

const MOCK_PORT_SCAN: PortScanData[] = [
  { agent_id: 'agent-001', agent_hostname: 'WIN-ENDPOINT-01', range_0_1023: 8,  range_1024_4999: 120, range_5000_9999: 45,  range_10000_plus: 12 },
  { agent_id: 'agent-002', agent_hostname: 'WIN-SERVER-02',   range_0_1023: 25, range_1024_4999: 280, range_5000_9999: 90,  range_10000_plus: 35 },
  { agent_id: 'agent-003', agent_hostname: 'MAC-DEV-01',      range_0_1023: 5,  range_1024_4999: 45,  range_5000_9999: 180, range_10000_plus: 8  },
  { agent_id: 'agent-004', agent_hostname: 'WIN-WORKSTATION-04', range_0_1023: 450, range_1024_4999: 680, range_5000_9999: 120, range_10000_plus: 20 },
  { agent_id: 'agent-005', agent_hostname: 'LINUX-SERVER-01', range_0_1023: 15, range_1024_4999: 95,  range_5000_9999: 30,  range_10000_plus: 5  },
]

const MOCK_SUSPICIOUS_PORTS: SuspiciousPort[] = [
  { port: 4444, protocol: 'TCP', description: 'Metasploit デフォルトリバースシェル', threat: 'RAT/C2', count: 3 },
  { port: 1080, protocol: 'TCP', description: 'SOCKS プロキシ (悪用多数)', threat: 'プロキシ/トンネル', count: 2 },
  { port: 6667, protocol: 'TCP', description: 'IRC (ボットネット C2)', threat: 'ボットネット', count: 1 },
  { port: 31337, protocol: 'TCP', description: 'Back Orifice / Elite RAT', threat: 'RAT', count: 1 },
  { port: 9001,  protocol: 'TCP', description: 'Tor ORPort', threat: 'プロキシ/匿名化', count: 4 },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(b: number) {
  if (b === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(b) / Math.log(k))
  return `${parseFloat((b / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function formatDate(d: string) {
  return new Date(d).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Badges ────────────────────────────────────────────────────────────────────

function AnomalyTypeBadge({ type }: { type: AnomalyType }) {
  const cfg: Record<AnomalyType, { cls: string; label: string }> = {
    traffic_spike:     { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30',   label: 'トラフィックスパイク' },
    new_port:          { cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30',   label: '新規ポート' },
    beaconing:         { cls: 'bg-red-500/20 text-red-400 border-red-500/30',            label: 'ビーコニング' },
    lateral_movement:  { cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',  label: '横断移動' },
    dns_tunnel:        { cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30',         label: 'DNSトンネル' },
  }
  const { cls, label } = cfg[type]
  return <span className={`inline-flex px-2 py-0.5 rounded border text-[11px] font-medium ${cls}`}>{label}</span>
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg: Record<Severity, string> = {
    low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
    medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  }
  const labels: Record<Severity, string> = { low: '低', medium: '中', high: '高', critical: '重大' }
  return <span className={`inline-flex px-1.5 py-0.5 rounded border text-[10px] font-medium ${cfg[severity]}`}>{labels[severity]}</span>
}

// ── Anomaly Detail Modal ──────────────────────────────────────────────────────

function AnomalyDetailModal({ anomaly, onClose }: { anomaly: NetworkAnomaly; onClose: () => void }) {
  const traffic = useMemo(() => generateTraffic(anomaly.agent_id), [anomaly.agent_id])
  const maxBytes = Math.max(...traffic.map(d => Math.max(d.inbound_bytes, d.outbound_bytes)))
  const W = 520, H = 140, PAD = 30

  function toX(h: number) { return PAD + (h / 23) * (W - PAD * 2) }
  function toY(v: number) { return H - PAD - (v / maxBytes) * (H - PAD * 2) }

  const inPath = traffic.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(d.hour)} ${toY(d.inbound_bytes)}`).join(' ')
  const outPath = traffic.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(d.hour)} ${toY(d.outbound_bytes)}`).join(' ')

  const suggestedActions = [
    { done: false, label: 'エンドポイントをネットワーク分離する' },
    { done: false, label: '関連プロセスを特定・終了する' },
    { done: false, label: 'メモリダンプを取得する' },
    { done: false, label: 'フォレンジック調査を開始する' },
    { done: false, label: '侵害状況をインシデントとして記録する' },
  ]
  const [actions, setActions] = useState(suggestedActions)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-[#e8002d]" />
            <div>
              <h2 className="text-[#e2e8f4] font-semibold">異常詳細調査</h2>
              <p className="text-[#7d92b0] text-xs">{anomaly.agent_hostname} — {formatDate(anomaly.detected_at)}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Anomaly info */}
          <div className="p-4 bg-[#070d19] rounded-lg border border-[#1e2d42] space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <AnomalyTypeBadge type={anomaly.type} />
              <SeverityBadge severity={anomaly.severity} />
            </div>
            <p className="text-[#e2e8f4] text-sm">{anomaly.description}</p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div><p className="text-[#7d92b0]">送信元IP</p><p className="text-[#e2e8f4] font-mono">{anomaly.source_ip}</p></div>
              <div><p className="text-[#7d92b0]">送信元ポート</p><p className="text-[#e2e8f4] font-mono">{anomaly.source_port ?? '—'}</p></div>
              <div><p className="text-[#7d92b0]">宛先IP</p><p className="text-[#e2e8f4] font-mono">{anomaly.dest_ip ?? '—'}</p></div>
              <div><p className="text-[#7d92b0]">宛先ポート</p><p className="text-[#e2e8f4] font-mono">{anomaly.dest_port ?? '—'}</p></div>
            </div>
            {anomaly.bytes_transferred && (
              <p className="text-xs text-[#7d92b0]">転送量: <span className="text-[#e2e8f4]">{formatBytes(anomaly.bytes_transferred)}</span></p>
            )}
          </div>

          {/* Traffic graph */}
          <div>
            <h3 className="text-[#e2e8f4] font-semibold mb-3 text-sm">トラフィックグラフ (過去24時間)</h3>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3 overflow-x-auto">
              <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="min-w-[400px]">
                {/* Grid */}
                {[0, 25, 50, 75, 100].map(pct => {
                  const y = PAD + (1 - pct / 100) * (H - PAD * 2)
                  return (
                    <g key={pct}>
                      <line x1={PAD} x2={W - PAD} y1={y} y2={y} stroke="#1e2d42" strokeWidth="1" />
                      <text x={PAD - 4} y={y + 3} fill="#3d5068" fontSize="7" textAnchor="end">{formatBytes(maxBytes * pct / 100)}</text>
                    </g>
                  )
                })}
                {/* Anomaly markers */}
                {traffic.filter(d => d.anomaly).map(d => (
                  <line key={d.hour} x1={toX(d.hour)} x2={toX(d.hour)} y1={PAD} y2={H - PAD}
                    stroke="#e8002d" strokeWidth="1.5" strokeDasharray="3,2" opacity="0.7" />
                ))}
                {/* Lines */}
                <path d={inPath} fill="none" stroke="#1a6bff" strokeWidth="1.5" />
                <path d={outPath} fill="none" stroke="#22c55e" strokeWidth="1.5" />
                {/* Hour labels */}
                {[0, 4, 8, 12, 16, 20, 23].map(h => (
                  <text key={h} x={toX(h)} y={H - PAD + 12} fill="#3d5068" fontSize="7" textAnchor="middle">{h}:00</text>
                ))}
              </svg>
              <div className="flex items-center gap-4 mt-2 text-xs text-[#7d92b0]">
                <span className="flex items-center gap-1"><span className="w-4 h-0.5 bg-blue-500 inline-block" /> インバウンド</span>
                <span className="flex items-center gap-1"><span className="w-4 h-0.5 bg-green-500 inline-block" /> アウトバウンド</span>
                <span className="flex items-center gap-1"><span className="w-4 h-0.5 bg-red-500 inline-block" /> 異常検出</span>
              </div>
            </div>
          </div>

          {/* Related connections */}
          <div>
            <h3 className="text-[#e2e8f4] font-semibold mb-3 text-sm">関連接続</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['送信元', 'ポート', '宛先', 'ポート', 'プロトコル', '転送量'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    [anomaly.source_ip, anomaly.source_port ?? 49234, anomaly.dest_ip ?? '185.220.101.45', anomaly.dest_port ?? 443, 'TCP', formatBytes(anomaly.bytes_transferred ?? 48200)],
                    ['192.168.1.1', 53, '8.8.8.8', 53, 'UDP', '2.1 KB'],
                    [anomaly.source_ip, 49892, '142.250.80.46', 443, 'TCP', '890 KB'],
                  ].map((row, i) => (
                    <tr key={i} className="border-b border-[#1e2d42]/40 hover:bg-[#1e2d42]/20">
                      {row.map((cell, j) => (
                        <td key={j} className="py-2 px-3 font-mono text-[#e2e8f4]">{cell}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Suggested actions */}
          <div>
            <h3 className="text-[#e2e8f4] font-semibold mb-3 text-sm">推奨アクション</h3>
            <div className="space-y-2">
              {actions.map((a, i) => (
                <label key={i} className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-[#1e2d42]/30 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={a.done}
                    onChange={() => setActions(prev => prev.map((x, j) => j === i ? { ...x, done: !x.done } : x))}
                    className="w-4 h-4 rounded accent-[#e8002d]"
                  />
                  <span className={`text-sm ${a.done ? 'line-through text-[#3d5068]' : 'text-[#e2e8f4]'}`}>{a.label}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Anomaly List Tab ──────────────────────────────────────────────────────────

function AnomalyListTab({ agents }: { agents: Agent[] }) {
  const [typeFilter, setTypeFilter] = useState<AnomalyType | 'all'>('all')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [agentFilter, setAgentFilter] = useState('all')
  const [selectedAnomaly, setSelectedAnomaly] = useState<NetworkAnomaly | null>(null)
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery<{ anomalies: NetworkAnomaly[] }>({
    queryKey: ['network-anomalies'],
    queryFn: async () => {
      try { return await apiFetch<{ anomalies: NetworkAnomaly[] }>('/api/v1/network-anomalies') }
      catch { return { anomalies: [] } }
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  })

  const suppressMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/network-anomalies/${id}/suppress`, { method: 'POST' }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['network-anomalies'] }),
  })

  const anomalies = data?.anomalies ?? []
  const filtered = anomalies.filter(a => {
    if (typeFilter !== 'all' && a.type !== typeFilter) return false
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false
    if (agentFilter !== 'all' && a.agent_hostname !== agentFilter) return false
    return true
  })

  return (
    <div className="space-y-4">
      {selectedAnomaly && <AnomalyDetailModal anomaly={selectedAnomaly} onClose={() => setSelectedAnomaly(null)} />}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-[#7d92b0]" />
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value as AnomalyType | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]/60"
        >
          <option value="all">全タイプ</option>
          <option value="traffic_spike">トラフィックスパイク</option>
          <option value="new_port">新規ポート</option>
          <option value="beaconing">ビーコニング</option>
          <option value="lateral_movement">横断移動</option>
          <option value="dns_tunnel">DNSトンネル</option>
        </select>
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value as Severity | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]/60"
        >
          <option value="all">全深刻度</option>
          <option value="critical">重大</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>
        <select
          value={agentFilter}
          onChange={e => setAgentFilter(e.target.value)}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]/60"
        >
          <option value="all">全エージェント</option>
          {[...new Set(anomalies.map(a => a.agent_hostname))].map(h => (
            <option key={h} value={h}>{h}</option>
          ))}
        </select>
        <span className="text-xs text-[#7d92b0] ml-auto">{filtered.length} 件</span>
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                <th className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">タイプ</th>
                <th className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">エージェント</th>
                <th className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">説明</th>
                <th className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">深刻度</th>
                <th className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">送信元 IP:Port</th>
                <th className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">検出日時</th>
                <th className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">関連アラート</th>
                <th className="py-3 px-4" />
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={8} className="py-10 text-center text-[#7d92b0]"><Loader2 className="w-6 h-6 animate-spin inline" /></td></tr>
              ) : filtered.map(a => (
                <tr key={a.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors ${a.suppressed ? 'opacity-50' : ''}`}>
                  <td className="py-3 px-4"><AnomalyTypeBadge type={a.type} /></td>
                  <td className="py-3 px-4 text-[#e2e8f4] text-xs font-medium">{a.agent_hostname}</td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs max-w-[260px]">
                    <span className="line-clamp-2">{a.description}</span>
                  </td>
                  <td className="py-3 px-4"><SeverityBadge severity={a.severity} /></td>
                  <td className="py-3 px-4 font-mono text-xs text-[#7d92b0]">
                    {a.source_ip}{a.source_port ? `:${a.source_port}` : ''}
                  </td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs whitespace-nowrap">{formatDate(a.detected_at)}</td>
                  <td className="py-3 px-4">
                    {a.related_alert_id ? (
                      <a href={`/alerts?id=${a.related_alert_id}`} className="text-xs text-blue-400 hover:text-blue-300 font-mono">
                        {a.related_alert_id}
                      </a>
                    ) : <span className="text-[#3d5068] text-xs">—</span>}
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setSelectedAnomaly(a)}
                        className="flex items-center gap-1 px-2 py-1 text-xs bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded transition-colors border border-[#2a3f5f]"
                      >
                        <Search className="w-3 h-3" />
                        調査
                      </button>
                      {!a.suppressed && (
                        <button
                          onClick={() => suppressMutation.mutate(a.id)}
                          className="flex items-center gap-1 px-2 py-1 text-xs bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#7d92b0] rounded transition-colors border border-[#2a3f5f]"
                          title="抑制"
                        >
                          <BellOff className="w-3 h-3" />
                        </button>
                      )}
                    </div>
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

// ── Traffic Analysis Tab ──────────────────────────────────────────────────────

function TrafficAnalysisTab({ agents }: { agents: Agent[] }) {
  const [selectedAgent, setSelectedAgent] = useState(agents[0]?.id ?? 'agent-002')
  const traffic = useMemo(() => generateTraffic(selectedAgent), [selectedAgent])
  const maxBytes = Math.max(...traffic.map(d => Math.max(d.inbound_bytes, d.outbound_bytes)))
  const W = 600, H = 180, PAD = 40

  function toX(h: number) { return PAD + (h / 23) * (W - PAD * 2) }
  function toY(v: number) { return H - PAD - (v / maxBytes) * (H - PAD * 2) }

  const inPath = traffic.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(d.hour)} ${toY(d.inbound_bytes)}`).join(' ')
  const outPath = traffic.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(d.hour)} ${toY(d.outbound_bytes)}`).join(' ')

  const protocols: ProtocolDist[] = []
  const protocolMax = protocols.length ? Math.max(...protocols.map(p => p.bytes)) : 1
  const protocolColors = ['#1a6bff', '#22c55e', '#f59e0b', '#a855f7', '#e8002d', '#7d92b0']

  return (
    <div className="space-y-6">
      {/* Agent selector */}
      <div className="flex items-center gap-3">
        <Server className="w-4 h-4 text-[#7d92b0]" />
        <select
          value={selectedAgent}
          onChange={e => setSelectedAgent(e.target.value)}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]/60"
        >
          {(agents.length > 0 ? agents : [
            { id: 'agent-001', hostname: 'WIN-ENDPOINT-01' },
            { id: 'agent-002', hostname: 'WIN-SERVER-02' },
            { id: 'agent-003', hostname: 'MAC-DEV-01' },
          ]).map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
        </select>
      </div>

      {/* Traffic chart */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-[#e2e8f4] font-semibold mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-blue-400" />
          トラフィックボリューム (過去24時間)
        </h3>
        <div className="overflow-x-auto">
          <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="min-w-[480px]">
            {[0, 25, 50, 75, 100].map(pct => {
              const y = PAD + (1 - pct / 100) * (H - PAD * 2)
              return (
                <g key={pct}>
                  <line x1={PAD} x2={W - PAD} y1={y} y2={y} stroke="#1e2d42" strokeWidth="1" />
                  <text x={PAD - 6} y={y + 3} fill="#3d5068" fontSize="8" textAnchor="end">{formatBytes(maxBytes * pct / 100)}</text>
                </g>
              )
            })}
            {/* Fill areas */}
            <defs>
              <linearGradient id="inGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#1a6bff" stopOpacity="0.15" />
                <stop offset="100%" stopColor="#1a6bff" stopOpacity="0" />
              </linearGradient>
              <linearGradient id="outGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22c55e" stopOpacity="0.15" />
                <stop offset="100%" stopColor="#22c55e" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path
              d={`${inPath} L ${toX(23)} ${H - PAD} L ${toX(0)} ${H - PAD} Z`}
              fill="url(#inGrad)"
            />
            <path
              d={`${outPath} L ${toX(23)} ${H - PAD} L ${toX(0)} ${H - PAD} Z`}
              fill="url(#outGrad)"
            />
            {/* Anomaly markers */}
            {traffic.filter(d => d.anomaly).map(d => (
              <g key={d.hour}>
                <line x1={toX(d.hour)} x2={toX(d.hour)} y1={PAD} y2={H - PAD}
                  stroke="#e8002d" strokeWidth="1.5" strokeDasharray="4,3" opacity="0.8" />
                <text x={toX(d.hour)} y={PAD - 4} fill="#e8002d" fontSize="8" textAnchor="middle">異常</text>
              </g>
            ))}
            {/* Lines */}
            <path d={inPath} fill="none" stroke="#1a6bff" strokeWidth="2" />
            <path d={outPath} fill="none" stroke="#22c55e" strokeWidth="2" />
            {/* Dots at anomalies */}
            {traffic.filter(d => d.anomaly).map(d => (
              <g key={`dot-${d.hour}`}>
                <circle cx={toX(d.hour)} cy={toY(d.inbound_bytes)} r="4" fill="#e8002d" />
                <circle cx={toX(d.hour)} cy={toY(d.outbound_bytes)} r="4" fill="#e8002d" />
              </g>
            ))}
            {/* Hour labels */}
            {[0, 3, 6, 9, 12, 15, 18, 21, 23].map(h => (
              <text key={h} x={toX(h)} y={H - PAD + 14} fill="#3d5068" fontSize="8" textAnchor="middle">{h}:00</text>
            ))}
          </svg>
        </div>
        <div className="flex items-center gap-6 mt-3 text-xs text-[#7d92b0]">
          <span className="flex items-center gap-1.5"><span className="w-5 h-0.5 bg-blue-500 inline-block rounded" /> インバウンド</span>
          <span className="flex items-center gap-1.5"><span className="w-5 h-0.5 bg-green-500 inline-block rounded" /> アウトバウンド</span>
          <span className="flex items-center gap-1.5"><span className="w-5 h-0.5 bg-red-500 inline-block rounded" style={{ borderStyle: 'dashed' }} /> 異常検出ポイント</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Top IPs */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <h3 className="text-[#e2e8f4] font-semibold mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#7d92b0]" />
            上位通信IP
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="text-left py-2 px-2 text-[#7d92b0] font-medium">IP</th>
                  <th className="text-left py-2 px-2 text-[#7d92b0] font-medium">受信</th>
                  <th className="text-left py-2 px-2 text-[#7d92b0] font-medium">送信</th>
                  <th className="text-left py-2 px-2 text-[#7d92b0] font-medium">接続数</th>
                  <th className="text-left py-2 px-2 text-[#7d92b0] font-medium">国</th>
                  <th className="py-2 px-2" />
                </tr>
              </thead>
              <tbody>
                {([] as TopIP[]).map((ip, i) => (
                  <tr key={i} className="border-b border-[#1e2d42]/40 hover:bg-[#1e2d42]/20">
                    <td className="py-2 px-2 font-mono text-[#e2e8f4]">{ip.ip}</td>
                    <td className="py-2 px-2 text-[#7d92b0]">{formatBytes(ip.bytes_in)}</td>
                    <td className="py-2 px-2 text-[#7d92b0]">{formatBytes(ip.bytes_out)}</td>
                    <td className="py-2 px-2 text-[#e2e8f4]">{(ip.connections ?? 0).toLocaleString()}</td>
                    <td className="py-2 px-2 text-[#7d92b0]">{ip.country}</td>
                    <td className="py-2 px-2">
                      {ip.threat_match && (
                        <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[9px] font-medium">TI</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Protocol distribution */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <h3 className="text-[#e2e8f4] font-semibold mb-4 flex items-center gap-2">
            <Network className="w-4 h-4 text-[#7d92b0]" />
            プロトコル分布
          </h3>
          <div className="space-y-3">
            {protocols.map((p, i) => (
              <div key={p.protocol}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-[#e2e8f4] font-medium">{p.protocol}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[#7d92b0]">{formatBytes(p.bytes)}</span>
                    <span className="text-xs font-bold" style={{ color: protocolColors[i] }}>{p.percentage}%</span>
                  </div>
                </div>
                <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${(p.bytes / protocolMax) * 100}%`, backgroundColor: protocolColors[i] }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Port Scan Tab ─────────────────────────────────────────────────────────────

function PortScanTab({ agents }: { agents: Agent[] }) {
  const [agentFilter, setAgentFilter] = useState('all')
  const portRanges = ['0-1023', '1024-4999', '5000-9999', '10000+']
  const rangeKeys: (keyof PortScanData)[] = ['range_0_1023', 'range_1024_4999', 'range_5000_9999', 'range_10000_plus']

  const portScanData: PortScanData[] = []
  const filtered = portScanData.filter(d => agentFilter === 'all' || d.agent_id === agentFilter)
  const allValues = filtered.flatMap(d => rangeKeys.map(k => d[k] as number))
  const maxVal = Math.max(...allValues, 1)

  function heatColor(v: number) {
    const pct = v / maxVal
    if (pct > 0.7) return 'bg-red-500/80'
    if (pct > 0.4) return 'bg-orange-500/60'
    if (pct > 0.2) return 'bg-yellow-500/40'
    if (pct > 0.05) return 'bg-blue-500/30'
    return 'bg-[#1e2d42]/40'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Filter className="w-4 h-4 text-[#7d92b0]" />
        <select
          value={agentFilter}
          onChange={e => setAgentFilter(e.target.value)}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]/60"
        >
          <option value="all">全エージェント</option>
          {portScanData.map(d => <option key={d.agent_id} value={d.agent_id}>{d.agent_hostname}</option>)}
        </select>
      </div>

      {/* Heatmap */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-[#e2e8f4] font-semibold mb-4 flex items-center gap-2">
          <Activity className="w-4 h-4 text-orange-400" />
          ポートレンジヒートマップ
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr>
                <th className="text-left py-2 pr-4 text-[#7d92b0] text-xs font-medium w-44">エージェント</th>
                {portRanges.map(r => (
                  <th key={r} className="py-2 px-3 text-[#7d92b0] text-xs font-medium text-center">{r}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(row => (
                <tr key={row.agent_id} className="border-t border-[#1e2d42]/40">
                  <td className="py-2 pr-4 text-[#e2e8f4] text-xs font-medium">{row.agent_hostname}</td>
                  {rangeKeys.map((k, i) => {
                    const v = row[k] as number
                    return (
                      <td key={i} className="py-2 px-3 text-center">
                        <div className={`inline-flex items-center justify-center w-20 h-9 rounded ${heatColor(v)} transition-all`}>
                          <span className="text-xs font-bold text-white">{v}</span>
                        </div>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {/* Legend */}
        <div className="flex items-center gap-3 mt-4 text-xs text-[#7d92b0]">
          <span>低</span>
          {['bg-[#1e2d42]/40', 'bg-blue-500/30', 'bg-yellow-500/40', 'bg-orange-500/60', 'bg-red-500/80'].map((c, i) => (
            <div key={i} className={`w-6 h-3 rounded ${c}`} />
          ))}
          <span>高</span>
        </div>
      </div>

      {/* Suspicious ports */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-[#e2e8f4] font-semibold mb-4 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400" />
          不審ポート検出 (既知のC2/RATポート)
        </h3>
        <div className="space-y-2">
          {([] as SuspiciousPort[]).map(p => (
            <div key={p.port} className="flex items-center gap-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
              <span className="font-mono text-lg font-bold text-red-400 w-12 text-right">{p.port}</span>
              <span className="text-xs text-[#7d92b0] w-8">{p.protocol}</span>
              <div className="flex-1">
                <p className="text-[#e2e8f4] text-sm">{p.description}</p>
                <p className="text-red-400/70 text-xs">{p.threat}</p>
              </div>
              <span className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-bold">
                {p.count}件
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function NetworkAnomaliesPage() {
  const [activeTab, setActiveTab] = useState<'anomalies' | 'traffic' | 'ports'>('anomalies')

  const { data: stats } = useQuery<AnomalyStats>({
    queryKey: ['network-anomaly-stats'],
    queryFn: async () => {
      try { return await apiFetch<AnomalyStats>('/api/v1/network-anomalies/stats') }
      catch { return null as any }
    },
    staleTime: 60_000,
    refetchInterval: 60_000,
  })

  const { data: agentsData } = useQuery<{ agents?: Agent[]; data?: Agent[] }>({
    queryKey: ['agents-list-network'],
    queryFn: async () => {
      try { return await apiFetch<{ agents: Agent[] }>('/api/v1/agents') }
      catch { return { agents: [] } }
    },
    staleTime: 120_000,
  })

  const s = stats ?? { anomalies_today: 0, traffic_spikes: 0, suspicious_ports: 0, c2_beaconing_alerts: 0 } as AnomalyStats
  const agents = agentsData?.data ?? agentsData?.agents ?? []

  const statCards = [
    { label: '本日の異常検出', value: s.anomalies_today, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
    { label: 'トラフィックスパイク', value: s.traffic_spikes, icon: TrendingUp, color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
    { label: '不審ポート', value: s.suspicious_ports, icon: Radio, color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20' },
    { label: 'C2ビーコニング', value: s.c2_beaconing_alerts, icon: Zap, color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  ]

  const tabs = [
    { key: 'anomalies', label: '異常一覧' },
    { key: 'traffic',   label: 'トラフィック分析' },
    { key: 'ports',     label: 'ポートスキャン' },
  ] as const

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[#e2e8f4] flex items-center gap-3">
            <Network className="w-6 h-6 text-[#e8002d]" />
            ネットワーク異常検知
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">AIベースのトラフィック異常・ビーコニング・不審ポート検出</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statCards.map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className={`bg-[#0d1220] border rounded-xl p-4 ${c.bg}`}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#070d19]/60">
                  <Icon className={`w-5 h-5 ${c.color}`} />
                </div>
                <div>
                  <p className={`text-xl font-bold ${c.color}`}>{c.value}</p>
                  <p className="text-[#7d92b0] text-xs">{c.label}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#1e2d42]">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px
              ${activeTab === tab.key
                ? 'border-[#e8002d] text-[#e2e8f4]'
                : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'}`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'anomalies' && <AnomalyListTab agents={agents} />}
      {activeTab === 'traffic'   && <TrafficAnalysisTab agents={agents} />}
      {activeTab === 'ports'     && <PortScanTab agents={agents} />}
    </div>
  )
}
