'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import React from 'react'
import {
  Network, RefreshCw, AlertTriangle, Shield, Activity,
  Globe, ChevronDown, ChevronRight,
  Zap, Radio
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

interface TopConnection {
  id: string
  src_ip: string
  dst_ip: string
  port: number
  protocol: string
  packet_count: number
  first_seen: string
  last_seen: string
  threat_score: number  // 0–100
  flags: string[]
}

interface PortStat {
  port: number
  protocol: string
  connection_count: number
  unique_hosts: number
  risk_level: 'low' | 'medium' | 'high' | 'critical'
  is_common: boolean
}

interface BeaconingEntry {
  dst_ip: string
  agent_id: string
  hostname?: string
  interval_seconds: number
  connection_count: number
  confidence: number  // 0–100
  first_seen: string
  last_seen: string
}

interface NetworkStats {
  total_connections: number
  unique_external_ips: number
  threats_detected: number
  beaconing_suspects: number
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const FLAG_STYLES: Record<string, string> = {
  tor_exit:     'bg-red-900/40 text-red-300 border border-red-700/40',
  known_c2:     'bg-red-900/50 text-red-200 border border-red-600/50',
  unusual_port: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  high_frequency: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
}

const RISK_STYLES: Record<string, string> = {
  low:      'bg-green-900/30 text-green-400 border border-green-700/30',
  medium:   'bg-yellow-900/30 text-yellow-400 border border-yellow-700/30',
  high:     'bg-orange-900/30 text-orange-400 border border-orange-700/30',
  critical: 'bg-red-900/40 text-red-300 border border-red-700/40',
}

function ThreatBar({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-red-500' : score >= 60 ? 'bg-orange-500' : score >= 30 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-mono ${score >= 80 ? 'text-red-400' : score >= 60 ? 'text-orange-400' : score >= 30 ? 'text-yellow-400' : 'text-green-400'}`}>{score}</span>
    </div>
  )
}

function fmtRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'たった今'
  if (mins < 60) return `${mins}分前`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}時間前`
  return `${Math.floor(hrs / 24)}日前`
}

function fmtNum(n: number | undefined | null): string {
  const v = n ?? 0
  if (v >= 1000000) return (v / 1000000).toFixed(1) + 'M'
  if (v >= 1000) return (v / 1000).toFixed(1) + 'K'
  return String(v)
}

// ── Tab Components ─────────────────────────────────────────────────────────────

function TopConnectionsTab({ connections }: { connections: TopConnection[] }) {
  const [expanded, setExpanded] = useState<string | null>(null)

  return (
    <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-700 bg-zinc-800/50">
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">送信元IP</th>
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">宛先IP</th>
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">ポート</th>
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">プロトコル</th>
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">パケット数</th>
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">最終検出</th>
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">脅威スコア</th>
            <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">フラグ</th>
            <th className="px-4 py-3" />
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {connections.map(c => (
            <React.Fragment key={c.id}>
              <tr
                className={`hover:bg-zinc-800/30 transition-colors cursor-pointer ${expanded === c.id ? 'bg-zinc-800/20' : ''}`}
                onClick={() => setExpanded(expanded === c.id ? null : c.id)}>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">{c.src_ip}</td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">{c.dst_ip}</td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-400">{c.port}</td>
                <td className="px-4 py-3 text-xs text-zinc-400">{c.protocol}</td>
                <td className="px-4 py-3 text-xs text-zinc-300 font-medium">{fmtNum(c.packet_count)}</td>
                <td className="px-4 py-3 text-xs text-zinc-500">{fmtRelative(c.last_seen)}</td>
                <td className="px-4 py-3"><ThreatBar score={c.threat_score} /></td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {c.flags.map(f => (
                      <span key={f} className={`text-xs px-1.5 py-0.5 rounded-sm font-medium ${FLAG_STYLES[f] ?? 'bg-zinc-700 text-zinc-400'}`}>{f.replace('_', ' ')}</span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3 text-zinc-500">
                  {expanded === c.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                </td>
              </tr>
              {expanded === c.id && (
                <tr className="bg-zinc-800/20">
                  <td colSpan={9} className="px-6 py-4">
                    <div className="grid grid-cols-4 gap-4 text-xs">
                      <div><span className="text-zinc-500">送信元IP</span><div className="font-mono text-zinc-300 mt-0.5">{c.src_ip}</div></div>
                      <div><span className="text-zinc-500">宛先IP</span><div className="font-mono text-zinc-300 mt-0.5">{c.dst_ip}</div></div>
                      <div><span className="text-zinc-500">ポート / プロトコル</span><div className="font-mono text-zinc-300 mt-0.5">{c.port}/{c.protocol}</div></div>
                      <div><span className="text-zinc-500">パケット数</span><div className="font-mono text-zinc-300 mt-0.5">{(c.packet_count ?? 0).toLocaleString()}</div></div>
                      <div><span className="text-zinc-500">初回検出</span><div className="text-zinc-300 mt-0.5">{fmtRelative(c.first_seen)}</div></div>
                      <div><span className="text-zinc-500">最終検出</span><div className="text-zinc-300 mt-0.5">{fmtRelative(c.last_seen)}</div></div>
                      <div><span className="text-zinc-500">脅威スコア</span><div className="mt-1"><ThreatBar score={c.threat_score} /></div></div>
                      <div><span className="text-zinc-500">フラグ</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {c.flags.length > 0 ? c.flags.map(f => (
                            <span key={f} className={`text-xs px-1.5 py-0.5 rounded-sm ${FLAG_STYLES[f] ?? 'bg-zinc-700 text-zinc-400'}`}>{f.replace('_', ' ')}</span>
                          )) : <span className="text-zinc-600">なし</span>}
                        </div>
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function PortAnalysisTab({ ports }: { ports: PortStat[] }) {
  const maxCount = ports.length > 0 ? Math.max(...ports.map(p => p.connection_count)) : 1

  return (
    <div className="space-y-4">
      {/* Bar Chart */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5">
        <h3 className="text-sm font-medium text-zinc-300 mb-4">接続数上位ポート</h3>
        <div className="space-y-2">
          {ports.slice(0, 10).map(p => {
            const pct = (p.connection_count / maxCount) * 100
            const barColor = p.risk_level === 'critical' ? 'bg-red-500' : p.risk_level === 'high' ? 'bg-orange-500' : p.risk_level === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
            return (
              <div key={p.port} className="flex items-center gap-3">
                <div className="w-12 text-right text-xs font-mono text-zinc-400 shrink-0">{p.port}</div>
                <div className="flex-1 h-5 bg-zinc-800 rounded-sm overflow-hidden">
                  <div className={`h-full rounded-sm ${barColor} transition-all`} style={{ width: `${pct}%` }} />
                </div>
                <div className="w-16 text-right text-xs font-mono text-zinc-400 shrink-0">{fmtNum(p.connection_count)}</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Table */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700 bg-zinc-800/50">
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">ポート</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">プロトコル</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">接続数</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">ユニークホスト</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">リスクレベル</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">一般ポート</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {ports.map(p => (
              <tr key={p.port} className={`hover:bg-zinc-800/30 transition-colors ${!p.is_common ? 'bg-orange-900/5' : ''}`}>
                <td className="px-4 py-3">
                  <span className={`font-mono text-sm font-bold ${!p.is_common ? 'text-orange-300' : 'text-zinc-200'}`}>{p.port}</span>
                </td>
                <td className="px-4 py-3 text-xs text-zinc-400">{p.protocol}</td>
                <td className="px-4 py-3 text-xs text-zinc-300 font-medium">{(p.connection_count ?? 0).toLocaleString()}</td>
                <td className="px-4 py-3 text-xs text-zinc-400">{p.unique_hosts}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${RISK_STYLES[p.risk_level]}`}>{p.risk_level}</span>
                </td>
                <td className="px-4 py-3">
                  {p.is_common
                    ? <span className="text-xs text-green-400">はい</span>
                    : <span className="text-xs text-orange-400 font-medium">いいえ — 異常</span>
                  }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function BeaconingTab({ entries }: { entries: BeaconingEntry[] }) {
  const highConfidence = entries.filter(e => e.confidence >= 80)

  return (
    <div className="space-y-4">
      {highConfidence.length > 0 && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-xl p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-red-300 text-sm">C2通信の可能性を検出</div>
            <div className="text-xs text-red-400 mt-1">
              {highConfidence.length}件のエンドポイントで高信頼度のビーコニング挙動を検出（信頼度80%以上）。即座の調査を推奨します。
            </div>
          </div>
        </div>
      )}

      <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700 bg-zinc-800/50">
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">宛先IP</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">エージェント / ホスト</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">間隔</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">接続数</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">信頼度</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">最終検出</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {entries.map((e, i) => (
              <tr key={i} className={`hover:bg-zinc-800/30 transition-colors ${e.confidence >= 80 ? 'bg-red-900/5' : ''}`}>
                <td className="px-4 py-3 font-mono text-xs text-zinc-300">{e.dst_ip}</td>
                <td className="px-4 py-3">
                  <div className="text-xs text-zinc-300">{e.hostname || e.agent_id}</div>
                  <div className="text-xs text-zinc-600 font-mono">{e.agent_id}</div>
                </td>
                <td className="px-4 py-3 text-xs">
                  <span className="font-mono text-zinc-300">{e.interval_seconds}s</span>
                  <span className="text-zinc-600 ml-1">({Math.floor(e.interval_seconds / 60)}m)</span>
                </td>
                <td className="px-4 py-3 text-xs text-zinc-300 font-medium">{e.connection_count}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${e.confidence >= 80 ? 'bg-red-500' : e.confidence >= 60 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                        style={{ width: `${e.confidence}%` }} />
                    </div>
                    <span className={`text-xs font-bold ${e.confidence >= 80 ? 'text-red-400' : e.confidence >= 60 ? 'text-orange-400' : 'text-yellow-400'}`}>
                      {e.confidence}%
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3 text-xs text-zinc-500">{fmtRelative(e.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

const TIME_RANGES = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
]

const TABS = ['主要接続', 'ポート分析', 'ビーコニング検出']

export default function NetworkAnalysisPage() {
  const [timeRange, setTimeRange] = useState(24)
  const [activeTab, setActiveTab] = useState(0)

  const EMPTY_NETWORK_STATS: NetworkStats = { total_connections: 0, unique_external_ips: 0, threats_detected: 0, beaconing_suspects: 0 }
  const { data: stats = EMPTY_NETWORK_STATS } = useQuery<NetworkStats>({
    queryKey: ['network-stats', timeRange],
    queryFn: async () => {
      try { return await apiFetch(`/api/v1/admin/network/stats?hours=${timeRange}`) } catch { return EMPTY_NETWORK_STATS }
    },
  })

  const { data: connections = [] } = useQuery<TopConnection[]>({
    queryKey: ['network-connections', timeRange],
    queryFn: () => apiFetchList<TopConnection>(`/api/v1/admin/network/top-connections?hours=${timeRange}`).catch(() => []),
  })

  const { data: ports = [] } = useQuery<PortStat[]>({
    queryKey: ['network-ports', timeRange],
    queryFn: () => apiFetchList<PortStat>(`/api/v1/admin/network/ports?hours=${timeRange}`).catch(() => []),
  })

  const { data: beaconing = [] } = useQuery<BeaconingEntry[]>({
    queryKey: ['network-beaconing', timeRange],
    queryFn: () => apiFetchList<BeaconingEntry>(`/api/v1/admin/network/beaconing?hours=${timeRange}`).catch(() => []),
  })

  const STATS_CARDS = [
    { label: '総接続数', value: fmtNum(stats.total_connections), icon: Activity, color: 'text-blue-400' },
    { label: 'ユニーク外部IP', value: fmtNum(stats.unique_external_ips), icon: Globe, color: 'text-cyan-400' },
    { label: '検出された脅威', value: fmtNum(stats.threats_detected), icon: Shield, color: 'text-red-400' },
    { label: 'ビーコニング疑い', value: fmtNum(stats.beaconing_suspects), icon: Radio, color: 'text-orange-400' },
  ]

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-cyan-900/40 border border-cyan-700/40 flex items-center justify-center">
            <Network className="h-5 w-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">ネットワークトラフィック分析</h1>
            <p className="text-sm text-zinc-400">接続、ポート使用状況、ビーコニング活動を監視</p>
          </div>
        </div>
        {/* Time range */}
        <div className="flex gap-1 bg-zinc-900 border border-zinc-700 rounded-lg p-1">
          {TIME_RANGES.map(t => (
            <button key={t.hours} onClick={() => setTimeRange(t.hours)}
              className={`px-3 py-1.5 text-xs rounded-md transition-colors ${timeRange === t.hours ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'}`}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {STATS_CARDS.map(s => (
          <div key={s.label} className="bg-zinc-900 border border-zinc-700 rounded-xl p-4 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-zinc-800 flex items-center justify-center">
              <s.icon className={`h-5 w-5 ${s.color}`} />
            </div>
            <div>
              <div className="text-2xl font-bold text-zinc-100">{s.value}</div>
              <div className="text-xs text-zinc-500">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-zinc-900 border border-zinc-700 rounded-lg p-1 w-fit mb-6">
        {TABS.map((tab, i) => (
          <button key={i} onClick={() => setActiveTab(i)}
            className={`px-4 py-2 text-sm rounded-md transition-colors ${activeTab === i ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'}`}>
            {tab}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 0 && <TopConnectionsTab connections={connections} />}
      {activeTab === 1 && <PortAnalysisTab ports={ports} />}
      {activeTab === 2 && <BeaconingTab entries={beaconing} />}
    </div>
  )
}
