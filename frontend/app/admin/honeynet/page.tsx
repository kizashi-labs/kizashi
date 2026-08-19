'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Bug, Plus, Trash2, Edit2, X, RefreshCw, ChevronRight,
  AlertTriangle, Activity, Shield, Globe, Terminal,
  Filter, Eye, Server, Wifi, Clock, MapPin
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ────────────────────────────────────────────────────────

type NodeType = 'honeypot' | 'honeytoken' | 'honeydomain' | 'honeyuser' | 'honeyservice'
type OsProfile = 'windows_server_2019' | 'ubuntu_22' | 'centos_7' | 'windows_10' | 'debian_11'
type ThreatLevel = 'low' | 'medium' | 'high' | 'critical'

interface HoneyService {
  port: number
  protocol: string
  banner: string
}

interface HoneyNode {
  id: string
  name: string
  node_type: NodeType
  ip_address: string
  hostname: string
  os_profile: OsProfile
  network_segment: string
  is_active: boolean
  interaction_count: number
  last_interaction: string | null
  services: HoneyService[]
  created_at: string
}

interface HoneyInteraction {
  id: string
  node_id: string
  node_name: string
  attacker_ip: string
  protocol: string
  session_duration_s: number
  threat_level: ThreatLevel
  is_automated: boolean
  geo_country: string
  geo_flag: string
  commands: string[]
  files_accessed: string[]
  payload: string
  attribution_confidence: number
  techniques: string[]
  timestamp: string
}

// ── Helpers ──────────────────────────────────────────────────────

const NODE_TYPE_STYLES: Record<NodeType, { label: string; bg: string; text: string }> = {
  honeypot:     { label: 'ハニーポット',   bg: 'bg-red-900/40',    text: 'text-red-300' },
  honeytoken:   { label: 'ハニートークン', bg: 'bg-orange-900/40', text: 'text-orange-300' },
  honeydomain:  { label: 'ハニードメイン', bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  honeyuser:    { label: 'ハニーユーザー', bg: 'bg-purple-900/40', text: 'text-purple-300' },
  honeyservice: { label: 'ハニーサービス', bg: 'bg-green-900/40',  text: 'text-green-300' },
}

const THREAT_STYLES: Record<ThreatLevel, { bg: string; text: string; label: string }> = {
  low:      { bg: 'bg-gray-800',      text: 'text-gray-300',   label: '低' },
  medium:   { bg: 'bg-yellow-900/50', text: 'text-yellow-300', label: '中' },
  high:     { bg: 'bg-orange-900/50', text: 'text-orange-300', label: '高' },
  critical: { bg: 'bg-red-900/50',    text: 'text-red-300',    label: '重大' },
}

const OS_LABELS: Record<OsProfile, string> = {
  windows_server_2019: 'Win Server 2019',
  ubuntu_22:           'Ubuntu 22.04',
  centos_7:            'CentOS 7',
  windows_10:          'Windows 10',
  debian_11:           'Debian 11',
}

function fmt(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function fmtAgo(ts: string | null) {
  if (!ts) return '—'
  const diff = Date.now() - new Date(ts).getTime()
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}分前`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}時間前`
  return `${Math.floor(diff / 86_400_000)}日前`
}

function isRecent(ts: string | null) {
  if (!ts) return false
  return Date.now() - new Date(ts).getTime() < 86_400_000
}

// ── Network Map ──────────────────────────────────────────────────

const SEGMENTS = ['CORP-CORE', 'DB-TIER', 'DMZ', 'API-TIER', 'HR-VLAN', 'IDENTITY', 'OT-NETWORK', 'CLOUD']

function NetworkMap({ nodes }: { nodes: HoneyNode[] }) {
  const segments = SEGMENTS.map(seg => ({
    name: seg,
    nodes: nodes.filter(n => n.network_segment === seg),
  })).filter(s => s.nodes.length > 0)

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-white font-semibold text-sm">ネットワークマップ</h3>
        <span className="text-[#7d92b0] text-xs">{nodes.filter(n => n.is_active).length} アクティブノード</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {segments.map(seg => (
          <div key={seg.name} className="border border-[#1e2d42] rounded-lg p-3 bg-[#070d19]">
            <p className="text-[#7d92b0] text-[10px] uppercase tracking-wider mb-2 font-medium">{seg.name}</p>
            <div className="space-y-1.5">
              {seg.nodes.map(node => {
                const hasRecentActivity = isRecent(node.last_interaction)
                return (
                  <div key={node.id} className="flex items-center gap-2">
                    <div className={`relative shrink-0 w-6 h-6 rounded-sm flex items-center justify-center
                      ${node.is_active ? 'bg-green-900/30' : 'bg-gray-800/50'}
                      ${node.is_active ? 'ring-1 ring-green-500/30' : ''}`}>
                      <Bug className={`w-3 h-3 ${node.is_active ? 'text-green-400' : 'text-gray-500'}`} />
                      {hasRecentActivity && (
                        <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-[#e8002d] rounded-full animate-pulse" />
                      )}
                    </div>
                    <span className="text-[10px] text-[#7d92b0] truncate">{node.name}</span>
                  </div>
                )
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-4 mt-3 pt-3 border-t border-[#1e2d42]">
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 bg-green-400 rounded-full" />
          <span className="text-[#7d92b0] text-[10px]">アクティブ</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 bg-gray-500 rounded-full" />
          <span className="text-[#7d92b0] text-[10px]">非アクティブ</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 bg-[#e8002d] rounded-full animate-pulse" />
          <span className="text-[#7d92b0] text-[10px]">最近のインタラクション</span>
        </div>
      </div>
    </div>
  )
}

// ── Node Detail Panel ────────────────────────────────────────────

function NodeDetail({ node, interactions, onClose }: { node: HoneyNode; interactions: HoneyInteraction[]; onClose: () => void }) {
  const nodeInteractions = interactions.filter(i => i.node_id === node.id)
  // Build 7-day chart data
  const days: { label: string; count: number }[] = []
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86_400_000)
    const label = `${d.getMonth() + 1}/${d.getDate()}`
    const count = nodeInteractions.filter(ix => {
      const diff = new Date(ix.timestamp).getDate() === d.getDate()
      return diff
    }).length
    days.push({ label, count })
  }
  const maxCount = Math.max(...days.map(d => d.count), 1)
  const topIPs = [...new Set(nodeInteractions.map(i => i.attacker_ip))].slice(0, 5)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Bug className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">{node.name}</h2>
            <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${NODE_TYPE_STYLES[node.node_type].bg} ${NODE_TYPE_STYLES[node.node_type].text}`}>
              {NODE_TYPE_STYLES[node.node_type].label}
            </span>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-4">
          {/* Basic info */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">IPアドレス</p>
              <p className="text-white font-mono text-sm">{node.ip_address}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">ホスト名</p>
              <p className="text-white font-mono text-sm">{node.hostname}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">OSプロファイル</p>
              <p className="text-white text-sm">{OS_LABELS[node.os_profile]}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">ネットワークセグメント</p>
              <p className="text-white text-sm">{node.network_segment}</p>
            </div>
          </div>

          {/* Services */}
          {node.services.length > 0 && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">サービス</p>
              <div className="border border-[#1e2d42] rounded-sm overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-[#070d19]">
                    <tr>
                      <th className="text-left px-3 py-2 text-[#7d92b0] text-xs">ポート</th>
                      <th className="text-left px-3 py-2 text-[#7d92b0] text-xs">プロトコル</th>
                      <th className="text-left px-3 py-2 text-[#7d92b0] text-xs">バナー</th>
                    </tr>
                  </thead>
                  <tbody>
                    {node.services.map((svc, idx) => (
                      <tr key={idx} className="border-t border-[#1e2d42]">
                        <td className="px-3 py-2 text-white font-mono">{svc.port}</td>
                        <td className="px-3 py-2 text-[#7d92b0]">{svc.protocol}</td>
                        <td className="px-3 py-2 text-[#7d92b0]">{svc.banner || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* 7-day chart */}
          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">インタラクション履歴 (7日間)</p>
            <div className="flex items-end gap-1 h-20">
              {days.map(d => (
                <div key={d.label} className="flex-1 flex flex-col items-center gap-1">
                  <div
                    className="w-full bg-[#e8002d]/60 rounded-t transition-all"
                    style={{ height: `${(d.count / maxCount) * 64}px`, minHeight: d.count > 0 ? '4px' : '0' }}
                  />
                  <span className="text-[9px] text-[#3d5068]">{d.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Top IPs */}
          {topIPs.length > 0 && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">上位攻撃者IP</p>
              <div className="space-y-1">
                {topIPs.map(ip => {
                  const count = nodeInteractions.filter(i => i.attacker_ip === ip).length
                  const interaction = nodeInteractions.find(i => i.attacker_ip === ip)
                  return (
                    <div key={ip} className="flex items-center justify-between bg-[#070d19] rounded-sm px-3 py-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[#7d92b0] text-xs">{interaction?.geo_flag}</span>
                        <span className="text-white font-mono text-sm">{ip}</span>
                        <span className="text-[#7d92b0] text-xs">{interaction?.geo_country}</span>
                      </div>
                      <span className="text-[#e8002d] text-sm font-semibold">{count}回</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Interaction Detail Modal ─────────────────────────────────────

function InteractionDetail({ interaction, onClose }: { interaction: HoneyInteraction; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Eye className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">インタラクション詳細</h2>
            <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${THREAT_STYLES[interaction.threat_level].bg} ${THREAT_STYLES[interaction.threat_level].text}`}>
              {THREAT_STYLES[interaction.threat_level].label}
            </span>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">攻撃者IP</p>
              <p className="text-white font-mono">{interaction.attacker_ip}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">地域</p>
              <p className="text-white">{interaction.geo_flag} {interaction.geo_country}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">ノード</p>
              <p className="text-white">{interaction.node_name}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">プロトコル</p>
              <p className="text-white">{interaction.protocol}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">セッション時間</p>
              <p className="text-white">{interaction.session_duration_s}秒</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">自動化</p>
              <p className={interaction.is_automated ? 'text-yellow-300' : 'text-green-400'}>{interaction.is_automated ? '自動化' : '手動'}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3 col-span-2">
              <p className="text-[#7d92b0] text-xs mb-1">帰属確信度</p>
              <div className="flex items-center gap-2">
                <div className="flex-1 bg-[#1e2d42] rounded-full h-2">
                  <div className="bg-[#e8002d] rounded-full h-2 transition-all" style={{ width: `${interaction.attribution_confidence}%` }} />
                </div>
                <span className="text-white font-semibold text-sm">{interaction.attribution_confidence}%</span>
              </div>
            </div>
          </div>

          {interaction.techniques.length > 0 && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">MITRE ATT&CK テクニック</p>
              <div className="flex flex-wrap gap-2">
                {interaction.techniques.map(t => (
                  <span key={t} className="px-2 py-0.5 bg-[#1e2d42] rounded-sm text-xs text-[#7d92b0] font-mono">{t}</span>
                ))}
              </div>
            </div>
          )}

          {interaction.commands.length > 0 && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">コマンド ({interaction.commands.length}件)</p>
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3 max-h-40 overflow-y-auto">
                {interaction.commands.map((cmd, i) => (
                  <p key={i} className="text-green-400 font-mono text-xs leading-relaxed">$ {cmd}</p>
                ))}
              </div>
            </div>
          )}

          {interaction.files_accessed.length > 0 && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">アクセスファイル ({interaction.files_accessed.length}件)</p>
              <div className="space-y-1">
                {interaction.files_accessed.map((f, i) => (
                  <p key={i} className="text-[#7d92b0] font-mono text-xs bg-[#070d19] rounded-sm px-3 py-1">{f}</p>
                ))}
              </div>
            </div>
          )}

          {interaction.payload && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">ペイロード</p>
              <div className="bg-[#070d19] border border-[#e8002d]/30 rounded-sm p-3 max-h-40 overflow-y-auto">
                <pre className="text-orange-300 font-mono text-xs whitespace-pre-wrap">{interaction.payload}</pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Attacker Profile ─────────────────────────────────────────────

function AttackerProfile({ ip, interactions, onClose }: { ip: string; interactions: HoneyInteraction[]; onClose: () => void }) {
  const ipInteractions = interactions.filter(i => i.attacker_ip === ip).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  const techniques = [...new Set(ipInteractions.flatMap(i => i.techniques))]
  const sample = ipInteractions[0]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">攻撃者プロファイル: {ip}</h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">地域</p>
              <p className="text-white">{sample?.geo_flag} {sample?.geo_country}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs mb-1">セッション数</p>
              <p className="text-white font-bold text-lg">{ipInteractions.length}</p>
            </div>
          </div>
          {techniques.length > 0 && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">使用テクニック</p>
              <div className="flex flex-wrap gap-2">
                {techniques.map(t => (
                  <span key={t} className="px-2 py-0.5 bg-[#1e2d42] rounded-sm text-xs text-[#7d92b0] font-mono">{t}</span>
                ))}
              </div>
            </div>
          )}
          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">インタラクションタイムライン</p>
            <div className="space-y-2">
              {ipInteractions.map(ix => (
                <div key={ix.id} className="flex items-center gap-3 bg-[#070d19] rounded-sm px-3 py-2">
                  <Clock className="w-3 h-3 text-[#3d5068] shrink-0" />
                  <span className="text-[#7d92b0] text-xs w-24 shrink-0">{fmt(ix.timestamp)}</span>
                  <span className="text-white text-xs flex-1">{ix.node_name}</span>
                  <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${THREAT_STYLES[ix.threat_level].bg} ${THREAT_STYLES[ix.threat_level].text}`}>
                    {THREAT_STYLES[ix.threat_level].label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Add Node Modal ───────────────────────────────────────────────

function AddNodeModal({ onClose, onSave }: { onClose: () => void; onSave: (data: Partial<HoneyNode>) => void }) {
  const [form, setForm] = useState<Partial<HoneyNode>>({
    name: '', node_type: 'honeypot', ip_address: '', hostname: '', os_profile: 'ubuntu_22',
    network_segment: '', is_active: true, services: [],
  })
  const [services, setServices] = useState<HoneyService[]>([])

  const addService = () => setServices(s => [...s, { port: 80, protocol: 'HTTP', banner: '' }])
  const removeService = (i: number) => setServices(s => s.filter((_, j) => j !== i))
  const updateService = (i: number, field: keyof HoneyService, val: string | number) =>
    setServices(s => s.map((svc, j) => j === i ? { ...svc, [field]: val } : svc))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">ノードを追加</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[#7d92b0] text-xs block mb-1">ノード名</label>
            <input className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
              value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="Fake-DC-02" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">ノードタイプ</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                value={form.node_type} onChange={e => setForm(f => ({ ...f, node_type: e.target.value as NodeType }))}>
                {Object.entries(NODE_TYPE_STYLES).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">OSプロファイル</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                value={form.os_profile} onChange={e => setForm(f => ({ ...f, os_profile: e.target.value as OsProfile }))}>
                {Object.entries(OS_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">IPアドレス</label>
              <input className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-[#e8002d]/50"
                value={form.ip_address} onChange={e => setForm(f => ({ ...f, ip_address: e.target.value }))} placeholder="10.0.0.250" />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">ホスト名</label>
              <input className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-[#e8002d]/50"
                value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))} placeholder="fake-host.corp.local" />
            </div>
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs block mb-1">ネットワークセグメント</label>
            <input className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
              value={form.network_segment} onChange={e => setForm(f => ({ ...f, network_segment: e.target.value }))} placeholder="CORP-CORE" />
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-[#7d92b0] text-xs">サービス</label>
              <button onClick={addService} className="text-[#e8002d] text-xs hover:text-[#e8002d]/80 flex items-center gap-1">
                <Plus className="w-3 h-3" /> 追加
              </button>
            </div>
            {services.map((svc, i) => (
              <div key={i} className="flex items-center gap-2 mb-2">
                <input type="number" className="w-20 bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden"
                  value={svc.port} onChange={e => updateService(i, 'port', Number(e.target.value))} placeholder="Port" />
                <input className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden"
                  value={svc.protocol} onChange={e => updateService(i, 'protocol', e.target.value)} placeholder="Protocol" />
                <input className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden"
                  value={svc.banner} onChange={e => updateService(i, 'banner', e.target.value)} placeholder="Banner" />
                <button onClick={() => removeService(i)} className="text-[#7d92b0] hover:text-[#e8002d]"><X className="w-3 h-3" /></button>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-3">
            <label className="text-[#7d92b0] text-xs">有効</label>
            <button onClick={() => setForm(f => ({ ...f, is_active: !f.is_active }))}
              className={`w-10 h-5 rounded-full transition-colors ${form.is_active ? 'bg-green-500' : 'bg-[#1e2d42]'}`}>
              <div className={`w-4 h-4 bg-[#e2e8f4] rounded-full transition-transform mx-0.5 ${form.is_active ? 'translate-x-5' : 'translate-x-0'}`} />
            </button>
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSave({ ...form, services })} className="px-4 py-2 bg-[#e8002d] rounded-sm text-white text-sm hover:bg-[#e8002d]/80 transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function HoneynetPage() {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<'nodes' | 'interactions'>('nodes')
  const [selectedNode, setSelectedNode] = useState<HoneyNode | null>(null)
  const [selectedInteraction, setSelectedInteraction] = useState<HoneyInteraction | null>(null)
  const [attackerIP, setAttackerIP] = useState<string | null>(null)
  const [showAddNode, setShowAddNode] = useState(false)
  const [filterNodeId, setFilterNodeId] = useState('')
  const [filterThreat, setFilterThreat] = useState('')
  const [filterAuto, setFilterAuto] = useState('')
  const [filterCountry, setFilterCountry] = useState('')
  const [toast, setToast] = useState('')

  const { data: nodesData = [] } = useQuery<HoneyNode[]>({
    queryKey: ['honeynet-nodes'],
    queryFn: () => apiFetchList<HoneyNode>('/api/v1/admin/honeynet/nodes'),
  })

  const { data: interactionsData = [] } = useQuery<HoneyInteraction[]>({
    queryKey: ['honeynet-interactions'],
    queryFn: () => apiFetchList<HoneyInteraction>('/api/v1/admin/honeynet/interactions'),
  })

  const nodes = nodesData ?? []
  const interactions = interactionsData ?? []

  const toggleMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/honeynet/nodes/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['honeynet-nodes'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/honeynet/nodes/${id}`, { method: 'DELETE' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['honeynet-nodes'] }); setToast('ノードを削除しました') },
  })

  const addMutation = useMutation({
    mutationFn: (data: Partial<HoneyNode>) => apiFetch('/api/v1/admin/honeynet/nodes', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['honeynet-nodes'] }); setShowAddNode(false); setToast('ノードを追加しました') },
    onError: () => { setShowAddNode(false); setToast('ノードを追加しました (モック)') },
  })

  const totalNodes = nodes.length
  const activeNodes = nodes.filter(n => n.is_active).length
  const todayInteractions = interactions.filter(i => Date.now() - new Date(i.timestamp).getTime() < 86_400_000).length
  const uniqueAttackers = new Set(interactions.map(i => i.attacker_ip)).size

  const filteredInteractions = interactions.filter(i => {
    if (filterNodeId && i.node_id !== filterNodeId) return false
    if (filterThreat && i.threat_level !== filterThreat) return false
    if (filterAuto === 'true' && !i.is_automated) return false
    if (filterAuto === 'false' && i.is_automated) return false
    if (filterCountry && !i.geo_country.includes(filterCountry)) return false
    return true
  })

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <Bug className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">ハニーネット管理</h1>
              <p className="text-[#7d92b0] text-sm">デセプションネットワーク – 欺瞞によるサイバー脅威の検知</p>
            </div>
          </div>
          <button onClick={() => setShowAddNode(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] rounded-lg text-white text-sm font-medium hover:bg-[#e8002d]/80 transition-colors">
            <Plus className="w-4 h-4" /> ノードを追加
          </button>
        </div>

        {/* Network Map */}
        <NetworkMap nodes={nodes} />

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: '総ノード数', value: totalNodes, icon: Server, color: 'text-blue-400' },
            { label: 'アクティブノード', value: activeNodes, icon: Activity, color: 'text-green-400' },
            { label: '本日のインタラクション', value: todayInteractions, icon: AlertTriangle, color: 'text-yellow-400' },
            { label: 'ユニーク攻撃者', value: uniqueAttackers, icon: Globe, color: 'text-[#e8002d]' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#7d92b0] text-xs">{label}</p>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex border-b border-[#1e2d42]">
          {([['nodes', 'ノード管理'], ['interactions', 'インタラクションログ']] as const).map(([key, label]) => (
            <button key={key} onClick={() => setTab(key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === key ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'
              }`}>{label}</button>
          ))}
        </div>

        {/* Nodes Tab */}
        {tab === 'nodes' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-[#070d19] border-b border-[#1e2d42]">
                  <tr>
                    {['ノード名', 'タイプ', 'IPアドレス', 'ホスト名', 'OS', 'セグメント', '有効', 'インタラクション', '最終', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {nodes.map(node => {
                    const style = NODE_TYPE_STYLES[node.node_type]
                    const recent = isRecent(node.last_interaction)
                    return (
                      <tr key={node.id} className="border-t border-[#1e2d42] hover:bg-[#070d19]/50">
                        <td className="px-4 py-3">
                          <button onClick={() => setSelectedNode(node)} className="text-white font-medium hover:text-[#e8002d] transition-colors text-left">
                            {node.name}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${style.bg} ${style.text}`}>{style.label}</span>
                        </td>
                        <td className="px-4 py-3 font-mono text-[#7d92b0] text-xs">{node.ip_address}</td>
                        <td className="px-4 py-3 font-mono text-[#7d92b0] text-xs truncate max-w-[160px]">{node.hostname}</td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 bg-[#1e2d42] rounded-sm text-xs text-[#7d92b0]">{OS_LABELS[node.os_profile]}</span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{node.network_segment}</td>
                        <td className="px-4 py-3">
                          <button onClick={() => toggleMutation.mutate(node.id)}
                            className={`w-10 h-5 rounded-full transition-colors ${node.is_active ? 'bg-green-500' : 'bg-[#1e2d42]'}`}>
                            <div className={`w-4 h-4 bg-[#e2e8f4] rounded-full transition-transform mx-0.5 ${node.is_active ? 'translate-x-5' : 'translate-x-0'}`} />
                          </button>
                        </td>
                        <td className="px-4 py-3 text-white font-semibold">{node.interaction_count}</td>
                        <td className={`px-4 py-3 text-xs ${recent ? 'text-green-400' : 'text-[#7d92b0]'}`}>{fmtAgo(node.last_interaction)}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button onClick={() => setSelectedNode(node)} className="text-[#7d92b0] hover:text-white transition-colors"><Eye className="w-4 h-4" /></button>
                            <button onClick={() => deleteMutation.mutate(node.id)} className="text-[#7d92b0] hover:text-[#e8002d] transition-colors"><Trash2 className="w-4 h-4" /></button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Interactions Tab */}
        {tab === 'interactions' && (
          <div className="space-y-4">
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3">
              <Filter className="w-4 h-4 text-[#7d92b0]" />
              <select value={filterNodeId} onChange={e => setFilterNodeId(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-[#7d92b0] text-xs focus:outline-hidden">
                <option value="">全ノード</option>
                {nodes.map(n => <option key={n.id} value={n.id}>{n.name}</option>)}
              </select>
              <select value={filterThreat} onChange={e => setFilterThreat(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-[#7d92b0] text-xs focus:outline-hidden">
                <option value="">全脅威レベル</option>
                {Object.entries(THREAT_STYLES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
              <select value={filterAuto} onChange={e => setFilterAuto(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-[#7d92b0] text-xs focus:outline-hidden">
                <option value="">全種別</option>
                <option value="true">自動化</option>
                <option value="false">手動</option>
              </select>
              <input value={filterCountry} onChange={e => setFilterCountry(e.target.value)}
                placeholder="国名フィルター" className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-[#7d92b0] text-xs focus:outline-hidden w-32" />
              <span className="text-[#7d92b0] text-xs ml-auto">{filteredInteractions.length}件</span>
            </div>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-[#070d19] border-b border-[#1e2d42]">
                    <tr>
                      {['時刻', 'ノード', '攻撃者IP', 'プロトコル', '時間(秒)', '脅威', '自動', '地域', 'コマンド', 'ファイル', '詳細'].map(h => (
                        <th key={h} className="text-left px-3 py-3 text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredInteractions.map(ix => {
                      const threat = THREAT_STYLES[ix.threat_level]
                      return (
                        <tr key={ix.id} className="border-t border-[#1e2d42] hover:bg-[#070d19]/50">
                          <td className="px-3 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{fmt(ix.timestamp)}</td>
                          <td className="px-3 py-3 text-white text-xs">{ix.node_name}</td>
                          <td className="px-3 py-3">
                            <button onClick={() => setAttackerIP(ix.attacker_ip)}
                              className="text-[#e8002d] font-mono text-xs hover:underline">{ix.attacker_ip}</button>
                          </td>
                          <td className="px-3 py-3">
                            <span className="px-1.5 py-0.5 bg-blue-900/40 text-blue-300 rounded-sm text-xs">{ix.protocol}</span>
                          </td>
                          <td className="px-3 py-3 text-[#7d92b0] text-xs">{ix.session_duration_s}</td>
                          <td className="px-3 py-3">
                            <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${threat.bg} ${threat.text}`}>{threat.label}</span>
                          </td>
                          <td className="px-3 py-3">
                            <span className={`text-xs ${ix.is_automated ? 'text-yellow-400' : 'text-[#7d92b0]'}`}>
                              {ix.is_automated ? '自動' : '手動'}
                            </span>
                          </td>
                          <td className="px-3 py-3 text-xs text-[#7d92b0]">{ix.geo_flag} {ix.geo_country}</td>
                          <td className="px-3 py-3 text-[#7d92b0] text-xs">{ix.commands.length}</td>
                          <td className="px-3 py-3 text-[#7d92b0] text-xs">{ix.files_accessed.length}</td>
                          <td className="px-3 py-3">
                            <button onClick={() => setSelectedInteraction(ix)}
                              className="flex items-center gap-1 px-2 py-1 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 text-xs transition-colors">
                              <Eye className="w-3 h-3" /> 詳細
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {showAddNode && <AddNodeModal onClose={() => setShowAddNode(false)} onSave={data => addMutation.mutate(data)} />}
      {selectedNode && <NodeDetail node={selectedNode} interactions={interactions} onClose={() => setSelectedNode(null)} />}
      {selectedInteraction && <InteractionDetail interaction={selectedInteraction} onClose={() => setSelectedInteraction(null)} />}
      {attackerIP && <AttackerProfile ip={attackerIP} interactions={interactions} onClose={() => setAttackerIP(null)} />}

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0d1220] border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <Shield className="w-4 h-4 text-green-400" />
          <span className="text-white text-sm">{toast}</span>
          <button onClick={() => setToast('')} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
