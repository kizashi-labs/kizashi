'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ShieldCheck, Plus, Pencil, ToggleLeft, ToggleRight,
  RefreshCw, AlertTriangle, CheckCircle, Clock,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type PolicyType = 'access' | 'network' | 'device' | 'user'
type EnforceMode = 'enforce' | 'monitor'
type Decision = 'allow' | 'deny' | 'challenge'
type PostureStatus = 'compliant' | 'non-compliant' | 'unknown' | 'pending'

interface ZTNAPolicy {
  id: string; name: string; type: PolicyType; mode: EnforceMode
  priority: number; hits: number; last_triggered: string; enabled: boolean
}
interface AccessLog {
  id: string; time: string; user: string; device: string; source_ip: string
  resource: string; decision: Decision; risk_score: number
}
interface DevicePosture {
  id: string; hostname: string; os: string; version: string
  compliance_score: number; status: PostureStatus; last_checked: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const policyTypeCls: Record<PolicyType, string> = {
  access:  'bg-blue-900/40 text-blue-300 border-blue-700/50',
  network: 'bg-green-900/40 text-green-300 border-green-700/50',
  device:  'bg-orange-900/40 text-orange-300 border-orange-700/50',
  user:    'bg-purple-900/40 text-purple-300 border-purple-700/50',
}
const enforceCls: Record<EnforceMode, string> = {
  enforce: 'bg-red-900/40 text-red-300 border-red-700/50',
  monitor: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
}
const decisionCls: Record<Decision, string> = {
  allow:     'bg-green-900/40 text-green-300 border-green-700/50',
  deny:      'bg-red-900/40 text-red-300 border-red-700/50',
  challenge: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
}
const postureCls: Record<PostureStatus, string> = {
  compliant:     'bg-green-900/40 text-green-300 border-green-700/50',
  'non-compliant': 'bg-red-900/40 text-red-300 border-red-700/50',
  unknown:       'bg-gray-700/40 text-gray-400 border-gray-600/50',
  pending:       'bg-blue-900/40 text-blue-300 border-blue-700/50',
}
const riskDot = (s: number) =>
  s < 3 ? 'bg-green-400' : s < 6 ? 'bg-yellow-400' : 'bg-red-400'

const fmtTime = (iso: string) =>
  new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ZTNAPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'policies' | 'logs' | 'posture'>('policies')
  const [typeFilter, setTypeFilter] = useState<string>('全て')
  const [modeFilter, setModeFilter] = useState<string>('全て')
  const [statusFilter, setStatusFilter] = useState<PostureStatus | '全て'>('全て')
  const [refreshKey, setRefreshKey] = useState(0)

  const { data: policies = [] } = useQuery<ZTNAPolicy[]>({
    queryKey: ['ztna-policies'],
    queryFn: () => apiFetchList<ZTNAPolicy>('/api/v1/admin/ztna/policies').catch(() => []),
    staleTime: 30_000,
  })

  const { data: logs = [] } = useQuery<AccessLog[]>({
    queryKey: ['ztna-logs', refreshKey],
    queryFn: () => apiFetchList<AccessLog>('/api/v1/admin/ztna/logs').catch(() => []),
    staleTime: 15_000,
  })

  const { data: devices = [] } = useQuery<DevicePosture[]>({
    queryKey: ['ztna-devices'],
    queryFn: () => apiFetchList<DevicePosture>('/api/v1/admin/ztna/devices').catch(() => []),
    staleTime: 30_000,
  })

  const togglePolicy = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/ztna/policies/${id}/toggle`, { method: 'POST' }).catch(() => null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ztna-policies'] }),
  })

  const filteredPolicies = policies.filter(p => {
    if (typeFilter !== '全て' && p.type !== typeFilter) return false
    if (modeFilter !== '全て' && p.mode !== modeFilter) return false
    return true
  })

  const filteredDevices = devices.filter(d =>
    statusFilter === '全て' ? true : d.status === statusFilter
  )

  const compliantCount = devices.filter(d => d.status === 'compliant').length
  const nonCompliantCount = devices.filter(d => d.status === 'non-compliant').length

  const STATS = [
    { label: 'アクティブポリシー', value: '12', color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30' },
    { label: '本日アクセス', value: '14,823', color: 'text-white', bg: 'bg-falcon-surface border-falcon-border' },
    { label: '許可', value: '14,201', color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30' },
    { label: '拒否', value: '512', color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
    { label: 'チャレンジ', value: '110', color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700/30' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-white" />
            </div>
            <h1 className="text-2xl font-bold">ゼロトラストネットワークアクセス</h1>
          </div>
          <p className="text-falcon-muted text-sm ml-11">ZTNAポリシー・アクセスログ・デバイスポスチャを管理します</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-4 mb-6">
          {STATS.map(s => (
            <div key={s.label} className={`rounded-xl p-4 border ${s.bg}`}>
              <p className="text-xs text-falcon-muted mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-5 border-b border-falcon-border">
          {([['policies', 'ポリシー'], ['logs', 'アクセスログ'], ['posture', 'デバイスポスチャ']] as const).map(([k, label]) => (
            <button key={k} onClick={() => setTab(k)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${tab === k ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'}`}>
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab: Policies ── */}
        {tab === 'policies' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex gap-2">
                {['全て', 'access', 'network', 'device', 'user'].map(f => (
                  <button key={f} onClick={() => setTypeFilter(f)}
                    className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${typeFilter === f ? 'bg-falcon-red border-falcon-red text-white' : 'bg-falcon-surface border-falcon-border text-falcon-muted hover:text-white'}`}>
                    {f}
                  </button>
                ))}
                <span className="text-falcon-subtle mx-1">|</span>
                {['全て', 'enforce', 'monitor'].map(f => (
                  <button key={f} onClick={() => setModeFilter(f)}
                    className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${modeFilter === f ? 'bg-falcon-blue border-falcon-blue text-white' : 'bg-falcon-surface border-falcon-border text-falcon-muted hover:text-white'}`}>
                    {f}
                  </button>
                ))}
              </div>
              <button className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors">
                <Plus className="w-4 h-4" /> 新規ポリシー
              </button>
            </div>

            <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['ポリシー名', 'タイプ', '強制モード', '優先度', 'ヒット数', '最終トリガー', '有効', '編集'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredPolicies.map(p => (
                    <tr key={p.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                      <td className="px-4 py-3 text-white font-medium">{p.name}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${policyTypeCls[p.type]}`}>{p.type}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${enforceCls[p.mode]}`}>{p.mode}</span>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted">{p.priority}</td>
                      <td className="px-4 py-3 text-white font-mono">{(p.hits ?? 0).toLocaleString()}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{fmtTime(p.last_triggered)}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => togglePolicy.mutate(p.id)}>
                          {p.enabled
                            ? <ToggleRight className="w-6 h-6 text-green-400 hover:text-green-300 transition-colors" />
                            : <ToggleLeft className="w-6 h-6 text-falcon-subtle hover:text-falcon-muted transition-colors" />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button className="text-falcon-muted hover:text-falcon-blue transition-colors">
                          <Pencil className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Tab: Access Logs ── */}
        {tab === 'logs' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2 text-xs text-falcon-muted">
                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse inline-block" />
                直近20件 — 自動更新中
              </div>
              <button onClick={() => setRefreshKey(k => k + 1)}
                className="flex items-center gap-2 px-3 py-1.5 text-xs bg-falcon-surface border border-falcon-border hover:border-falcon-muted/40 text-falcon-muted hover:text-white rounded-lg transition-colors">
                <RefreshCw className="w-3.5 h-3.5" /> 更新
              </button>
            </div>

            <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['時刻', 'ユーザー', 'デバイス', 'ソースIP', 'リソース', '決定', 'リスクスコア'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {logs.map((l, i) => (
                    <tr key={l.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                      <td className="px-4 py-2.5 text-falcon-muted text-xs whitespace-nowrap">{fmtTime(l.time)}</td>
                      <td className="px-4 py-2.5 text-white text-xs">{l.user}</td>
                      <td className="px-4 py-2.5 text-falcon-muted text-xs font-mono">{l.device}</td>
                      <td className="px-4 py-2.5 text-falcon-muted text-xs font-mono">{l.source_ip}</td>
                      <td className="px-4 py-2.5 text-falcon-muted text-xs font-mono">{l.resource}</td>
                      <td className="px-4 py-2.5">
                        <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-sm border capitalize ${decisionCls[l.decision]} ${l.decision === 'deny' && i < 3 ? 'animate-pulse' : ''}`}>
                          {l.decision}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          <span className={`w-2 h-2 rounded-full ${riskDot(l.risk_score)}`} />
                          <span className={`text-xs font-mono ${l.risk_score >= 6 ? 'text-red-400' : l.risk_score >= 3 ? 'text-yellow-400' : 'text-green-400'}`}>
                            {l.risk_score.toFixed(1)}
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Tab: Device Posture ── */}
        {tab === 'posture' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex gap-3">
                <div className="flex items-center gap-2 bg-green-900/20 border border-green-700/30 rounded-lg px-3 py-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-green-300 font-medium">準拠: {compliantCount}</span>
                </div>
                <div className="flex items-center gap-2 bg-red-900/20 border border-red-700/30 rounded-lg px-3 py-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  <span className="text-sm text-red-300 font-medium">非準拠: {nonCompliantCount}</span>
                </div>
              </div>
              <div className="flex gap-2">
                {(['全て', 'compliant', 'non-compliant', 'unknown', 'pending'] as const).map(s => (
                  <button key={s} onClick={() => setStatusFilter(s)}
                    className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${statusFilter === s ? 'bg-falcon-red border-falcon-red text-white' : 'bg-falcon-surface border-falcon-border text-falcon-muted hover:text-white'}`}>
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredDevices.map(d => (
                <div key={d.id} className="bg-falcon-surface rounded-xl border border-falcon-border p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <p className="text-white font-medium">{d.hostname}</p>
                      <p className="text-xs text-falcon-muted mt-0.5">{d.id}</p>
                    </div>
                    <span className={`text-xs px-2 py-0.5 rounded-sm border ${postureCls[d.status]}`}>{d.status}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 mb-3 text-xs">
                    <div><span className="text-falcon-muted">OS: </span><span className="text-white">{d.os}</span></div>
                    <div><span className="text-falcon-muted">バージョン: </span><span className="text-white">{d.version}</span></div>
                  </div>
                  <div className="mb-2">
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-falcon-muted">コンプライアンススコア</span>
                      <span className={`font-medium ${d.compliance_score >= 80 ? 'text-green-400' : d.compliance_score >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>
                        {d.compliance_score}%
                      </span>
                    </div>
                    <div className="w-full bg-falcon-border rounded-full h-1.5">
                      <div className={`h-1.5 rounded-full transition-all ${d.compliance_score >= 80 ? 'bg-green-400' : d.compliance_score >= 50 ? 'bg-yellow-400' : 'bg-red-400'}`}
                        style={{ width: `${d.compliance_score}%` }} />
                    </div>
                  </div>
                  <div className="flex items-center gap-1 text-xs text-falcon-muted">
                    <Clock className="w-3 h-3" />
                    <span>最終確認: {fmtTime(d.last_checked)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── ZTNA Architecture Diagram ── */}
        <div className="mt-8 bg-falcon-surface rounded-xl border border-falcon-border p-6">
          <p className="text-xs text-falcon-muted uppercase tracking-widest mb-5">ZTNAアーキテクチャ</p>
          <div className="flex items-center justify-center gap-0">
            {[
              { label: 'Client', sub: 'エンドポイント', color: 'border-blue-500/50 text-blue-300' },
              { label: 'Trust Broker', sub: 'トラストブローカー', color: 'border-yellow-500/50 text-yellow-300' },
              { label: 'Policy Engine', sub: 'ポリシーエンジン', color: 'border-falcon-red/50 text-red-300' },
              { label: 'Resource', sub: 'リソース', color: 'border-green-500/50 text-green-300' },
            ].map((node, i, arr) => (
              <div key={node.label} className="flex items-center">
                <div className={`flex flex-col items-center justify-center w-32 h-20 rounded-xl border-2 bg-[#070d19] ${node.color}`}>
                  <p className="text-sm font-semibold">{node.label}</p>
                  <p className="text-xs text-falcon-muted mt-0.5">{node.sub}</p>
                </div>
                {i < arr.length - 1 && (
                  <div className="flex items-center w-12">
                    <div className="h-0.5 flex-1 bg-linear-to-r from-falcon-border to-falcon-red/40" />
                    <div className="w-0 h-0 border-t-[5px] border-t-transparent border-b-[5px] border-b-transparent border-l-8 border-l-falcon-red/60" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  )
}
