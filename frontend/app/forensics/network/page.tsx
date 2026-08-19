'use client'

import { useState, useRef } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Wifi, Clock, Filter, X, Upload, Download, ArrowRight,
  ArrowLeft, AlertTriangle, CheckCircle2, Globe, MapPin,
  ChevronDown, Eye, Plus, RefreshCw, Activity, Loader2,
  FileDown, Shield,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m } from '@/lib/mock'

// ── Types ─────────────────────────────────────────────────────────────────────

type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'HTTPS'

interface NetworkFlow {
  id: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: Protocol
  bytes_sent: number
  bytes_recv: number
  duration_ms: number
  flow_flags: string[]
  risk_score: number
  start_time: string
  src_country?: string
  src_city?: string
  dst_country?: string
  dst_city?: string
  payload_preview?: string
}

interface ReconstructedSession {
  session_id: string
  protocol: 'HTTP' | 'SMTP' | 'FTP' | 'DNS'
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  object_count: number
  interesting_findings: number
  start_time: string
}

interface PacketEntry {
  seq: number
  direction: 'sent' | 'recv'
  size_bytes: number
  timestamp: string
  flags: string[]
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS']
const FLAGS = ['SYN', 'FIN', 'RST', 'ACK', 'PSH']

function randIp() {
  return `${10 + Math.floor(Math.random() * 245)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
}

const GEO = [
  { country: 'Japan', city: 'Tokyo' },
  { country: 'USA', city: 'New York' },
  { country: 'China', city: 'Beijing' },
  { country: 'Russia', city: 'Moscow' },
  { country: 'Germany', city: 'Frankfurt' },
  { country: 'Netherlands', city: 'Amsterdam' },
]

const MOCK_FLOWS: NetworkFlow[] = Array.from({ length: 20 }, (_, i) => {
  const proto = PROTOCOLS[i % PROTOCOLS.length]
  const risk = [2, 8, 35, 65, 88, 95, 12, 44, 71, 90, 5, 55, 80, 30, 17, 63, 77, 9, 48, 99][i]
  const srcGeo = GEO[i % GEO.length]
  const dstGeo = GEO[(i + 2) % GEO.length]
  const flags: string[] = []
  if (proto === 'TCP') {
    if (i % 3 === 0) flags.push('SYN')
    if (i % 5 === 0) flags.push('FIN')
    if (i % 7 === 0) flags.push('RST')
    flags.push('ACK')
  }
  return {
    id: `flow-${String(i + 1).padStart(3, '0')}`,
    src_ip: `192.168.${Math.floor(i / 5)}.${10 + i}`,
    src_port: 49152 + i * 37,
    dst_ip: randIp(),
    dst_port: [80, 443, 53, 25, 21, 8080, 3389, 22, 3306, 5432][i % 10],
    protocol: proto,
    bytes_sent: Math.floor(Math.random() * 500000) + 1000,
    bytes_recv: Math.floor(Math.random() * 2000000) + 500,
    duration_ms: Math.floor(Math.random() * 30000) + 100,
    flow_flags: flags,
    risk_score: risk,
    start_time: new Date(Date.now() - i * 3600000).toISOString(),
    src_country: srcGeo.country,
    src_city: srcGeo.city,
    dst_country: dstGeo.country,
    dst_city: dstGeo.city,
    payload_preview: proto === 'HTTP' ? `GET /api/data HTTP/1.1\r\nHost: target-server-${i}.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n` : undefined,
  }
})

const MOCK_SESSIONS: ReconstructedSession[] = [
  { session_id: 'sess-001', protocol: 'HTTP', src_ip: '192.168.1.15', dst_ip: '45.33.101.22', src_port: 50231, dst_port: 80, object_count: 12, interesting_findings: 3, start_time: new Date(Date.now() - 7200000).toISOString() },
  { session_id: 'sess-002', protocol: 'FTP', src_ip: '192.168.0.45', dst_ip: '198.51.100.77', src_port: 50888, dst_port: 21, object_count: 5, interesting_findings: 2, start_time: new Date(Date.now() - 14400000).toISOString() },
  { session_id: 'sess-003', protocol: 'SMTP', src_ip: '192.168.2.10', dst_ip: '203.0.113.55', src_port: 51200, dst_port: 25, object_count: 3, interesting_findings: 0, start_time: new Date(Date.now() - 21600000).toISOString() },
  { session_id: 'sess-004', protocol: 'DNS', src_ip: '192.168.1.100', dst_ip: '8.8.8.8', src_port: 52000, dst_port: 53, object_count: 45, interesting_findings: 1, start_time: new Date(Date.now() - 3600000).toISOString() },
  { session_id: 'sess-005', protocol: 'HTTP', src_ip: '192.168.3.77', dst_ip: '104.21.45.88', src_port: 53100, dst_port: 8080, object_count: 8, interesting_findings: 0, start_time: new Date(Date.now() - 28800000).toISOString() },
]

const MOCK_PACKETS: PacketEntry[] = Array.from({ length: 10 }, (_, i) => ({
  seq: i + 1,
  direction: i % 2 === 0 ? 'sent' : 'recv',
  size_bytes: 64 + Math.floor(Math.random() * 1400),
  timestamp: new Date(Date.now() - (10 - i) * 450).toISOString(),
  flags: i === 0 ? ['SYN'] : i === 9 ? ['FIN', 'ACK'] : ['ACK'],
}))

const MOCK_DNS_QUERIES = [
  { query: 'malware-c2.evil.example.com', type: 'A', response: 'NXDOMAIN', ttl: 0 },
  { query: 'update.windows.com', type: 'A', response: '40.119.212.108', ttl: 300 },
  { query: '_dmarc.company.jp', type: 'TXT', response: 'v=DMARC1; p=reject', ttl: 3600 },
  { query: 'smtp.gmail.com', type: 'MX', response: 'alt1.gmail-smtp-in.l.google.com', ttl: 3600 },
]

const MOCK_CREDS = [
  { protocol: 'FTP', username: 'admin', server: '198.51.100.77', password: '****' },
  { protocol: 'HTTP', username: 'user@corp.jp', server: '45.33.101.22', password: '****' },
  { protocol: 'SMTP', username: 'noreply@company.jp', server: '203.0.113.55', password: '****' },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(b: number) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`
  if (b >= 1_000) return `${(b / 1_000).toFixed(1)} KB`
  return `${b} B`
}

function formatDuration(ms: number) {
  if (ms >= 60000) return `${(ms / 60000).toFixed(1)}m`
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`
  return `${ms}ms`
}

function fmtTime(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function riskColor(score: number) {
  if (score >= 80) return 'text-red-400 bg-red-400/10 border-red-400/30'
  if (score >= 50) return 'text-orange-400 bg-orange-400/10 border-orange-400/30'
  if (score >= 20) return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
  return 'text-green-400 bg-green-400/10 border-green-400/30'
}

function protocolColor(p: Protocol) {
  const map: Record<Protocol, string> = {
    TCP: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    UDP: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
    ICMP: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
    DNS: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
    HTTP: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    HTTPS: 'bg-green-500/20 text-green-300 border-green-500/30',
  }
  return map[p]
}

function flagColor(f: string) {
  if (f === 'SYN') return 'bg-blue-500/20 text-blue-300'
  if (f === 'RST') return 'bg-red-500/20 text-red-300'
  if (f === 'FIN') return 'bg-yellow-500/20 text-yellow-300'
  return 'bg-[#1e2d42] text-[#7d92b0]'
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function FlowDetailModal({ flow, onClose }: { flow: NetworkFlow; onClose: () => void }) {
  const relatedFlows = m(MOCK_FLOWS).filter(f => f.src_ip === flow.src_ip && f.id !== flow.id).slice(0, 3)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-[#e8002d]" />
            <h3 className="text-white font-semibold">フロー詳細 — {flow.id}</h3>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Geo-IP */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42]">
              <div className="flex items-center gap-2 mb-2">
                <MapPin className="w-4 h-4 text-[#e8002d]" />
                <span className="text-xs text-[#7d92b0] uppercase tracking-wider">送信元</span>
              </div>
              <p className="text-white font-mono text-sm">{flow.src_ip}:{flow.src_port}</p>
              <p className="text-[#7d92b0] text-xs mt-1">{flow.src_city}, {flow.src_country}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42]">
              <div className="flex items-center gap-2 mb-2">
                <Globe className="w-4 h-4 text-blue-400" />
                <span className="text-xs text-[#7d92b0] uppercase tracking-wider">送信先</span>
              </div>
              <p className="text-white font-mono text-sm">{flow.dst_ip}:{flow.dst_port}</p>
              <p className="text-[#7d92b0] text-xs mt-1">{flow.dst_city}, {flow.dst_country}</p>
            </div>
          </div>

          {/* Packet Timeline */}
          <div>
            <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-3">パケットタイムライン</h4>
            <div className="space-y-1.5 max-h-52 overflow-y-auto">
              {m(MOCK_PACKETS).map(pkt => (
                <div key={pkt.seq} className="flex items-center gap-3 px-3 py-2 rounded-sm bg-[#070d19] border border-[#1e2d42]">
                  <span className="text-[#3d5068] text-xs w-6">{pkt.seq}</span>
                  {pkt.direction === 'sent'
                    ? <ArrowRight className="w-3.5 h-3.5 text-[#e8002d] shrink-0" />
                    : <ArrowLeft className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                  }
                  <span className="text-[#7d92b0] text-xs w-16">{formatBytes(pkt.size_bytes)}</span>
                  <div className="flex gap-1">
                    {pkt.flags.map(f => (
                      <span key={f} className={`text-[10px] px-1.5 py-0.5 rounded-sm font-mono ${flagColor(f)}`}>{f}</span>
                    ))}
                  </div>
                  <span className="ml-auto text-[#3d5068] text-[11px] font-mono">{new Date(pkt.timestamp).toLocaleTimeString('ja-JP')}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Payload Preview */}
          {flow.payload_preview && (
            <div>
              <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-3">ペイロードプレビュー (HTTP)</h4>
              <pre className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 text-[11px] text-green-300 font-mono overflow-x-auto whitespace-pre-wrap break-all">
                {flow.payload_preview}
              </pre>
            </div>
          )}

          {/* Related Flows */}
          {relatedFlows.length > 0 && (
            <div>
              <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-3">同一送信元の関連フロー</h4>
              <div className="space-y-1.5">
                {relatedFlows.map(f => (
                  <div key={f.id} className="flex items-center gap-3 px-3 py-2 rounded-sm bg-[#070d19] border border-[#1e2d42]">
                    <span className="text-[#7d92b0] font-mono text-xs">{f.id}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border font-mono ${protocolColor(f.protocol)}`}>{f.protocol}</span>
                    <span className="text-[#7d92b0] text-xs">{f.dst_ip}:{f.dst_port}</span>
                    <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded-sm border ${riskColor(f.risk_score)}`}>{f.risk_score}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 pt-2 border-t border-[#1e2d42]">
            <button className="flex items-center gap-2 px-4 py-2 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d] text-sm hover:bg-[#e8002d]/20 transition-colors">
              <Plus className="w-4 h-4" />
              IOCに追加
            </button>
            <button onClick={onClose} className="flex items-center gap-2 px-4 py-2 rounded-sm bg-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
              閉じる
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function HttpSessionViewer({ session }: { session: ReconstructedSession }) {
  const request = `GET /api/v1/users HTTP/1.1\r\nHost: ${session.dst_ip}\r\nAuthorization: Basic dXNlcjpwYXNz\r\nAccept: application/json\r\nUser-Agent: curl/7.68.0\r\nConnection: keep-alive`
  const response = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 384\r\nServer: nginx/1.18.0\r\nX-Powered-By: Express\r\n\r\n{"users":[{"id":1,"name":"admin","email":"admin@corp.jp","role":"administrator"}]}`

  return (
    <div className="grid grid-cols-2 gap-4 mt-4">
      <div>
        <p className="text-xs text-[#7d92b0] uppercase tracking-wider mb-2">HTTPリクエスト</p>
        <pre className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 text-[11px] text-blue-300 font-mono overflow-x-auto whitespace-pre-wrap break-all h-48">{request}</pre>
      </div>
      <div>
        <p className="text-xs text-[#7d92b0] uppercase tracking-wider mb-2">HTTPレスポンス</p>
        <pre className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 text-[11px] text-green-300 font-mono overflow-x-auto whitespace-pre-wrap break-all h-48">{response}</pre>
      </div>
    </div>
  )
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function NetworkForensicsPage() {
  const [activeTab, setActiveTab] = useState<'flows' | 'packets'>('flows')
  const [timeRange, setTimeRange] = useState('24h')
  const [ipFilter, setIpFilter] = useState('')
  const [protocolFilter, setProtocolFilter] = useState<Protocol | ''>('')
  const [riskFilter, setRiskFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all')
  const [selectedFlow, setSelectedFlow] = useState<NetworkFlow | null>(null)
  const [selectedSession, setSelectedSession] = useState<ReconstructedSession | null>(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisComplete, setAnalysisComplete] = useState(false)
  const [topSortBy, setTopSortBy] = useState<'bytes' | 'count'>('bytes')
  const fileInputRef = useRef<HTMLInputElement>(null)

  // API calls
  const { data: flowsData } = useQuery({
    queryKey: ['network-flows', timeRange, ipFilter],
    queryFn: () => apiFetch(`/api/v1/forensics/network/flows?range=${timeRange}&ip=${ipFilter}`),
    retry: false,
  })

  const { data: sessionsData } = useQuery({
    queryKey: ['network-sessions'],
    queryFn: () => apiFetch('/api/v1/forensics/network/sessions'),
    retry: false,
  })

  const flows: NetworkFlow[] = (flowsData as { flows?: NetworkFlow[] } | null)?.flows ?? m(MOCK_FLOWS)
  const sessions: ReconstructedSession[] = (sessionsData as { sessions?: ReconstructedSession[] } | null)?.sessions ?? m(MOCK_SESSIONS)

  // Filtering
  const filteredFlows = flows.filter(f => {
    if (protocolFilter && f.protocol !== protocolFilter) return false
    if (ipFilter && !f.src_ip.includes(ipFilter) && !f.dst_ip.includes(ipFilter)) return false
    if (riskFilter === 'high' && f.risk_score < 70) return false
    if (riskFilter === 'medium' && (f.risk_score < 30 || f.risk_score >= 70)) return false
    if (riskFilter === 'low' && f.risk_score >= 30) return false
    return true
  })

  // Summary stats
  const totalFlows = filteredFlows.length
  const suspiciousFlows = filteredFlows.filter(f => f.risk_score >= 70).length
  const exfilAlerts = filteredFlows.filter(f => f.bytes_sent > 200000 && f.risk_score >= 50).length
  const topTalker = filteredFlows.reduce((acc, f) => {
    acc[f.src_ip] = (acc[f.src_ip] ?? 0) + f.bytes_sent
    return acc
  }, {} as Record<string, number>)
  const topTalkerIp = Object.entries(topTalker).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '—'

  // Top connections
  const connMap: Record<string, { bytes: number; count: number }> = {}
  filteredFlows.forEach(f => {
    const key = `${f.src_ip}→${f.dst_ip}`
    if (!connMap[key]) connMap[key] = { bytes: 0, count: 0 }
    connMap[key].bytes += f.bytes_sent + f.bytes_recv
    connMap[key].count += 1
  })
  const topConnections = Object.entries(connMap)
    .sort((a, b) => topSortBy === 'bytes' ? b[1].bytes - a[1].bytes : b[1].count - a[1].count)
    .slice(0, 10)

  // Mock PCAP upload
  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setIsAnalyzing(true)
    setAnalysisComplete(false)
    let prog = 0
    const interval = setInterval(() => {
      prog += 10
      setUploadProgress(prog)
      if (prog >= 100) {
        clearInterval(interval)
        setIsAnalyzing(false)
        setAnalysisComplete(true)
      }
    }, 200)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      <PageDataUnavailable />
      {/* ── Header ─────────────────────────────────────────── */}
      <div className="border-b border-[#1e2d42] px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <Wifi className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-white text-xl font-bold tracking-tight">ネットワークフォレンジクス</h1>
              <p className="text-xs text-[#7d92b0] mt-0.5">パケット再構成 & フロー分析</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Time range */}
            <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1">
              {(['1h', '6h', '24h', '7d'] as const).map(r => (
                <button
                  key={r}
                  onClick={() => setTimeRange(r)}
                  className={`px-3 py-1.5 rounded-sm text-xs font-medium transition-colors ${timeRange === r ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
                >
                  {r}
                </button>
              ))}
            </div>
            {/* IP filter */}
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
              <input
                type="text"
                placeholder="IPフィルター..."
                value={ipFilter}
                onChange={e => setIpFilter(e.target.value)}
                className="pl-8 pr-3 py-2 text-sm bg-[#0d1220] border border-[#1e2d42] rounded-lg text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#7d92b0] w-44"
              />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mt-4">
          {(['flows', 'packets'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2 rounded-t-lg text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab
                  ? 'border-[#e8002d] text-white bg-[#0d1220]'
                  : 'border-transparent text-[#7d92b0] hover:text-white'
              }`}
            >
              {tab === 'flows' ? 'フロー分析' : 'パケット再構成'}
            </button>
          ))}
        </div>
      </div>

      <div className="p-6">
        {/* ── フロー分析 tab ───────────────────────────────── */}
        {activeTab === 'flows' && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-4 gap-4">
              {[
                { label: '総フロー数', value: totalFlows, icon: Activity, color: 'text-blue-400' },
                { label: '不審フロー', value: suspiciousFlows, icon: AlertTriangle, color: 'text-orange-400' },
                { label: 'データ持ち出しアラート', value: exfilAlerts, icon: Shield, color: 'text-[#e8002d]' },
                { label: 'トップトーカー', value: topTalkerIp, icon: Globe, color: 'text-cyan-400' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className={`w-4 h-4 ${color}`} />
                    <span className="text-xs text-[#7d92b0]">{label}</span>
                  </div>
                  <p className={`text-xl font-bold ${color} font-mono`}>{value}</p>
                </div>
              ))}
            </div>

            {/* Filters */}
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-xs text-[#7d92b0]">フィルター:</span>
              {/* Protocol filter */}
              <div className="relative">
                <select
                  value={protocolFilter}
                  onChange={e => setProtocolFilter(e.target.value as Protocol | '')}
                  className="pl-3 pr-8 py-1.5 text-xs bg-[#0d1220] border border-[#1e2d42] rounded-sm text-[#7d92b0] focus:outline-hidden appearance-none cursor-pointer"
                >
                  <option value="">全プロトコル</option>
                  {PROTOCOLS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[#3d5068] pointer-events-none" />
              </div>
              {/* Risk filter */}
              <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-sm p-0.5">
                {(['all', 'high', 'medium', 'low'] as const).map(r => (
                  <button
                    key={r}
                    onClick={() => setRiskFilter(r)}
                    className={`px-2.5 py-1 rounded-sm text-xs transition-colors ${riskFilter === r ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
                  >
                    {r === 'all' ? '全て' : r === 'high' ? '高リスク' : r === 'medium' ? '中リスク' : '低リスク'}
                  </button>
                ))}
              </div>
              {(protocolFilter || ipFilter || riskFilter !== 'all') && (
                <button
                  onClick={() => { setProtocolFilter(''); setIpFilter(''); setRiskFilter('all') }}
                  className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white"
                >
                  <X className="w-3 h-3" /> クリア
                </button>
              )}
            </div>

            {/* Flow Table */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
                <h2 className="text-white font-semibold text-sm">ネットワークフロー ({filteredFlows.length}件)</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['送信元 IP:Port', '送信先 IP:Port', 'プロトコル', '送信', '受信', '時間', 'フラグ', 'リスク', '開始時刻', '操作'].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left text-[#3d5068] font-medium whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {filteredFlows.map(flow => (
                      <tr key={flow.id} className="hover:bg-[#0a1628] transition-colors">
                        <td className="px-3 py-2.5 font-mono text-white whitespace-nowrap">{flow.src_ip}<span className="text-[#3d5068]">:{flow.src_port}</span></td>
                        <td className="px-3 py-2.5 font-mono text-white whitespace-nowrap">{flow.dst_ip}<span className="text-[#3d5068]">:{flow.dst_port}</span></td>
                        <td className="px-3 py-2.5">
                          <span className={`px-2 py-0.5 rounded-sm border text-[10px] font-mono font-bold ${protocolColor(flow.protocol)}`}>{flow.protocol}</span>
                        </td>
                        <td className="px-3 py-2.5 text-[#7d92b0] whitespace-nowrap">{formatBytes(flow.bytes_sent)}</td>
                        <td className="px-3 py-2.5 text-[#7d92b0] whitespace-nowrap">{formatBytes(flow.bytes_recv)}</td>
                        <td className="px-3 py-2.5 text-[#7d92b0] whitespace-nowrap">{formatDuration(flow.duration_ms)}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex gap-1 flex-wrap">
                            {flow.flow_flags.slice(0, 3).map(f => (
                              <span key={f} className={`text-[9px] px-1 py-0.5 rounded-sm font-mono ${flagColor(f)}`}>{f}</span>
                            ))}
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <span className={`px-2 py-0.5 rounded-sm border text-[10px] font-mono font-bold ${riskColor(flow.risk_score)}`}>{flow.risk_score}</span>
                        </td>
                        <td className="px-3 py-2.5 text-[#3d5068] whitespace-nowrap font-mono">{fmtTime(flow.start_time)}</td>
                        <td className="px-3 py-2.5">
                          <button
                            onClick={() => setSelectedFlow(flow)}
                            className="flex items-center gap-1 text-[#7d92b0] hover:text-white transition-colors"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Top Connections */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
                <h2 className="text-white font-semibold text-sm">トップ接続 (Top 10)</h2>
                <div className="flex items-center gap-1 bg-[#070d19] border border-[#1e2d42] rounded-sm p-0.5">
                  {(['bytes', 'count'] as const).map(s => (
                    <button
                      key={s}
                      onClick={() => setTopSortBy(s)}
                      className={`px-2.5 py-1 rounded-sm text-xs transition-colors ${topSortBy === s ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0]'}`}
                    >
                      {s === 'bytes' ? 'バイト数' : '接続数'}
                    </button>
                  ))}
                </div>
              </div>
              <div className="p-4 space-y-2">
                {topConnections.map(([pair, stats], idx) => {
                  const maxBytes = topConnections[0]?.[1].bytes ?? 1
                  const pct = Math.round((stats.bytes / maxBytes) * 100)
                  return (
                    <div key={pair} className="flex items-center gap-3">
                      <span className="text-[#3d5068] text-xs w-4">{idx + 1}</span>
                      <span className="font-mono text-xs text-white w-44 truncate">{pair}</span>
                      <div className="flex-1 h-2 bg-[#070d19] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-linear-to-r from-[#1a6bff] to-[#0044cc] rounded-full transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-[#7d92b0] text-xs w-20 text-right font-mono">{formatBytes(stats.bytes)}</span>
                      <span className="text-[#3d5068] text-xs w-10 text-right">{stats.count}回</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}

        {/* ── パケット再構成 tab ───────────────────────────── */}
        {activeTab === 'packets' && (
          <div className="space-y-6">
            {/* PCAP Upload */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
              <h2 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
                <Upload className="w-4 h-4 text-[#e8002d]" />
                PCAPファイルインポート
              </h2>
              <div
                className="border-2 border-dashed border-[#1e2d42] rounded-xl p-8 text-center cursor-pointer hover:border-[#7d92b0]/40 transition-colors"
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".pcap,.pcapng"
                  className="hidden"
                  onChange={handleFileChange}
                />
                <Upload className="w-8 h-8 text-[#3d5068] mx-auto mb-3" />
                <p className="text-[#7d92b0] text-sm">PCAPまたはPCAPNGファイルをクリックしてアップロード</p>
                <p className="text-[#3d5068] text-xs mt-1">.pcap, .pcapng ファイル対応</p>
              </div>
              {isAnalyzing && (
                <div className="mt-4">
                  <div className="flex items-center gap-3 mb-2">
                    <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
                    <span className="text-sm text-[#7d92b0]">解析中... {uploadProgress}%</span>
                  </div>
                  <div className="h-2 bg-[#070d19] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-linear-to-r from-blue-600 to-blue-400 rounded-full transition-all duration-200"
                      style={{ width: `${uploadProgress}%` }}
                    />
                  </div>
                </div>
              )}
              {analysisComplete && (
                <div className="mt-4 flex items-center gap-2 text-green-400 text-sm">
                  <CheckCircle2 className="w-4 h-4" />
                  解析完了 — 5件のセッションが検出されました
                </div>
              )}
            </div>

            {/* Credential Alert */}
            <div className="bg-[#e8002d]/5 border border-[#e8002d]/30 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-[#e8002d]" />
                <span className="text-[#e8002d] font-semibold text-sm">3件の平文認証情報が検出されました</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#e8002d]/20">
                      {['プロトコル', 'ユーザー名', 'サーバー', 'パスワード'].map(h => (
                        <th key={h} className="px-3 py-2 text-left text-[#e8002d]/70 font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {m(MOCK_CREDS).map((c, i) => (
                      <tr key={i} className="border-b border-[#e8002d]/10">
                        <td className="px-3 py-2 font-mono text-orange-400">{c.protocol}</td>
                        <td className="px-3 py-2 font-mono text-white">{c.username}</td>
                        <td className="px-3 py-2 font-mono text-[#7d92b0]">{c.server}</td>
                        <td className="px-3 py-2 font-mono text-[#3d5068]">{c.password}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Reconstructed Sessions */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
                <h2 className="text-white font-semibold text-sm">再構成セッション ({sessions.length}件)</h2>
                <button className="flex items-center gap-2 text-xs text-[#7d92b0] hover:text-white px-3 py-1.5 rounded-sm border border-[#1e2d42] transition-colors">
                  <FileDown className="w-3.5 h-3.5" />
                  PCAPダウンロード
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['セッションID', 'プロトコル', '送信元→送信先', 'オブジェクト数', '検出事項', '開始時刻', '操作'].map(h => (
                        <th key={h} className="px-3 py-2.5 text-left text-[#3d5068] font-medium whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {sessions.map(sess => (
                      <tr key={sess.session_id} className="hover:bg-[#0a1628] transition-colors">
                        <td className="px-3 py-2.5 font-mono text-white">{sess.session_id}</td>
                        <td className="px-3 py-2.5">
                          <span className={`px-2 py-0.5 rounded-sm border text-[10px] font-mono font-bold ${protocolColor(sess.protocol as Protocol)}`}>{sess.protocol}</span>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[#7d92b0] whitespace-nowrap">
                          {sess.src_ip}:{sess.src_port} → {sess.dst_ip}:{sess.dst_port}
                        </td>
                        <td className="px-3 py-2.5 text-center text-[#7d92b0]">{sess.object_count}</td>
                        <td className="px-3 py-2.5 text-center">
                          <span className={sess.interesting_findings > 0 ? 'text-[#e8002d] font-bold' : 'text-[#3d5068]'}>
                            {sess.interesting_findings}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-[#3d5068] font-mono whitespace-nowrap">{fmtTime(sess.start_time)}</td>
                        <td className="px-3 py-2.5">
                          <button
                            onClick={() => setSelectedSession(selectedSession?.session_id === sess.session_id ? null : sess)}
                            className="flex items-center gap-1.5 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/40 px-2.5 py-1 rounded-sm transition-colors"
                          >
                            <RefreshCw className="w-3 h-3" />
                            再構成
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Session Viewer */}
              {selectedSession && (
                <div className="border-t border-[#1e2d42] p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-white font-medium text-sm">
                      {selectedSession.session_id} — {selectedSession.protocol} セッション詳細
                    </h3>
                    <button onClick={() => setSelectedSession(null)} className="text-[#7d92b0] hover:text-white">
                      <X className="w-4 h-4" />
                    </button>
                  </div>

                  {selectedSession.protocol === 'HTTP' && <HttpSessionViewer session={selectedSession} />}

                  {selectedSession.protocol === 'DNS' && (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="border-b border-[#1e2d42]">
                            {['クエリ', 'タイプ', 'レスポンス', 'TTL'].map(h => (
                              <th key={h} className="px-3 py-2 text-left text-[#3d5068] font-medium">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#1e2d42]/50">
                          {m(MOCK_DNS_QUERIES).map((q, i) => (
                            <tr key={i} className="hover:bg-[#0a1628]">
                              <td className="px-3 py-2 font-mono text-white">{q.query}</td>
                              <td className="px-3 py-2"><span className="px-1.5 py-0.5 rounded-sm bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-[10px] font-mono">{q.type}</span></td>
                              <td className="px-3 py-2 font-mono text-[#7d92b0]">{q.response}</td>
                              <td className="px-3 py-2 text-[#3d5068]">{q.ttl}s</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {(selectedSession.protocol === 'FTP' || selectedSession.protocol === 'SMTP') && (
                    <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42]">
                      <pre className="text-[11px] text-green-300 font-mono whitespace-pre-wrap">
                        {selectedSession.protocol === 'FTP'
                          ? `220 FTP Server ready\r\nUSER admin\r\n331 Password required\r\nPASS ****\r\n230 User logged in\r\nPWD\r\n257 "/var/ftp/uploads"\r\nRETR sensitive_data.csv\r\n150 Opening BINARY mode data connection\r\n226 Transfer complete`
                          : `220 smtp.example.com ESMTP\r\nEHLO corp.jp\r\n250-smtp.example.com\r\nAUTH LOGIN\r\n334 VXNlcm5hbWU6\r\nAGVtYWlsQGNvcnAuanA=\r\n334 UGFzc3dvcmQ6\r\n****\r\n235 Authentication successful\r\nMAIL FROM:<noreply@company.jp>`
                        }
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Flow Detail Modal */}
      {selectedFlow && <FlowDetailModal flow={selectedFlow} onClose={() => setSelectedFlow(null)} />}
    </div>
  )
}
