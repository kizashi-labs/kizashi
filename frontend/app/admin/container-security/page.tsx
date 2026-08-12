'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { Box, ScanLine, AlertTriangle, Loader2, RefreshCw, Shield, Plus, X, ToggleLeft, ToggleRight } from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

type ScanStatus = 'pending' | 'scanning' | 'scanned' | 'failed'
type Severity = 'low' | 'medium' | 'high' | 'critical'
type RuntimeEventType = 'privilege_escalation' | 'crypto_mining' | 'policy_violation' | 'network_anomaly' | 'file_tampering'
type PolicyType = 'image_allowlist' | 'runtime_behavior' | 'network_policy' | 'resource_limit'

interface ContainerPolicy {
  id: string
  name: string
  policy_type: PolicyType
  description: string
  is_enabled: boolean
  action: 'alert' | 'block' | 'log'
  conditions: Record<string, unknown>
  created_at: string
}

interface ContainerSecurityStats {
  total_images: number
  critical_vulnerabilities: number
  scanned: number
  runtime_events_24h: number
  critical_events: number
}

interface ContainerImage {
  id: string
  registry: string
  repo: string
  tag: string
  critical_vulns: number
  high_vulns: number
  medium_vulns: number
  scan_status: ScanStatus
  last_scanned: string | null
  size_mb: number
}

interface RuntimeEvent {
  id: string
  container: string
  pod: string
  image: string
  namespace: string
  event_type: RuntimeEventType
  severity: Severity
  description: string
  timestamp: string
}

const EMPTY_STATS: ContainerSecurityStats = {
  total_images: 0,
  critical_vulnerabilities: 0,
  scanned: 0,
  runtime_events_24h: 0,
  critical_events: 0,
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const SCAN_STATUS_CONFIG: Record<ScanStatus, { label: string; cls: string; animated?: boolean }> = {
  pending:  { label: '保留中',    cls: 'bg-gray-500/15 text-gray-400 border-gray-500/30'         },
  scanning: { label: 'スキャン中', cls: 'bg-blue-500/15 text-blue-300 border-blue-500/30', animated: true },
  scanned:  { label: '完了',      cls: 'bg-green-500/15 text-green-300 border-green-500/30'       },
  failed:   { label: '失敗',      cls: 'bg-red-500/15 text-red-300 border-red-500/30'              },
}

const SEVERITY_CONFIG: Record<Severity, { label: string; cls: string }> = {
  low:      { label: '低',  cls: 'bg-green-500/15 text-green-300 border-green-500/30'    },
  medium:   { label: '中',  cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  high:     { label: '高',  cls: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  critical: { label: '重大', cls: 'bg-red-500/15 text-red-300 border-red-500/30'          },
}

const EVENT_TYPE_CONFIG: Record<RuntimeEventType, { label: string; cls: string }> = {
  privilege_escalation: { label: '権限昇格',           cls: 'bg-red-500/15 text-red-300 border-red-500/30'          },
  crypto_mining:        { label: 'クリプトマイニング',  cls: 'bg-red-600/15 text-red-400 border-red-600/30'           },
  policy_violation:     { label: 'ポリシー違反',        cls: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  network_anomaly:      { label: 'ネットワーク異常',    cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  file_tampering:       { label: 'ファイル改ざん',      cls: 'bg-orange-600/15 text-orange-400 border-orange-600/30' },
}

function fmtDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function fmtSize(mb: number) {
  return mb >= 1000 ? `${(mb / 1000).toFixed(1)} GB` : `${mb} MB`
}

// ── Page ──────────────────────────────────────────────────────────────────────

const POLICY_TYPE_META: Record<PolicyType, { label: string; color: string }> = {
  image_allowlist:  { label: 'イメージ許可リスト', color: '#1a6bff' },
  runtime_behavior: { label: 'ランタイム動作',     color: '#e8002d' },
  network_policy:   { label: 'ネットワークポリシー', color: '#7c3aed' },
  resource_limit:   { label: 'リソース制限',       color: '#f59e0b' },
}

export default function ContainerSecurityPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'images' | 'events' | 'policies'>('images')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [scanningIds, setScanningIds] = useState<Set<string>>(new Set())

  const { data: stats, isLoading: statsLoading } = useQuery<ContainerSecurityStats>({
    queryKey: ['container-sec-stats'],
    queryFn: async () => {
      try {
        const res = await apiFetch('/api/v1/admin/container-security/stats')
        return (res && typeof res === 'object' && 'total_images' in (res as object)) ? res as ContainerSecurityStats : EMPTY_STATS
      } catch { return EMPTY_STATS }
    },
  })

  const { data: images = [], isLoading: imagesLoading } = useQuery<ContainerImage[]>({
    queryKey: ['container-sec-images'],
    queryFn: async () => {
      try { return await apiFetchList<ContainerImage>('/api/v1/admin/container-security/images') } catch { return [] }
    },
  })

  const { data: events = [], isLoading: eventsLoading } = useQuery<RuntimeEvent[]>({
    queryKey: ['container-sec-events', severityFilter],
    queryFn: async () => {
      try {
        const params = severityFilter !== 'all' ? `?severity=${severityFilter}` : ''
        return await apiFetchList<RuntimeEvent>(`/api/v1/admin/container-security/events${params}`)
      } catch { return [] }
    },
  })

  const scanMutation = useMutation({
    mutationFn: async (id: string) => {
      setScanningIds(prev => new Set(prev).add(id))
      try { return await apiFetch(`/api/v1/admin/container-security/images/${id}/scan`, { method: 'POST' }) }
      catch { return null }
    },
    onSettled: (_data, _err, id) => {
      setScanningIds(prev => { const s = new Set(prev); s.delete(id); return s })
      qc.invalidateQueries({ queryKey: ['container-sec-images'] })
    },
  })

  const { data: policies = [], isLoading: policiesLoading } = useQuery<ContainerPolicy[]>({
    queryKey: ['container-sec-policies'],
    queryFn: async () => {
      try { return await apiFetchList<ContainerPolicy>('/api/v1/admin/container-security/policies') } catch { return [] }
    },
  })

  const togglePolicyMutation = useMutation({
    mutationFn: async (id: string) => {
      try { return await apiFetch(`/api/v1/admin/container-security/policies/${id}/toggle`, { method: 'POST' }) }
      catch { return null }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['container-sec-policies'] }),
  })

  const scanAllMutation = useMutation({
    mutationFn: async () => {
      const ids = images.map(i => i.id)
      setScanningIds(new Set(ids))
      try {
        await Promise.all(ids.map(id =>
          apiFetch(`/api/v1/admin/container-security/images/${id}/scan`, { method: 'POST' }).catch(() => null)
        ))
      } finally {
        setScanningIds(new Set())
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['container-sec-images'] }),
  })

  const displayStats = stats ?? EMPTY_STATS

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 flex items-center justify-center">
            <Box className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">コンテナセキュリティ</h1>
            <p className="text-sm text-[#7d92b0]">イメージスキャン &amp; ランタイム保護</p>
          </div>
        </div>
        <button
          onClick={() => scanAllMutation.mutate()}
          disabled={scanAllMutation.isPending || imagesLoading}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50"
        >
          {scanAllMutation.isPending
            ? <Loader2 className="w-4 h-4 animate-spin" />
            : <ScanLine className="w-4 h-4" />}
          全スキャン
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {statsLoading
          ? Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 animate-pulse">
                <div className="h-3 w-24 bg-[#1e2d42] rounded mb-3" />
                <div className="h-7 w-10 bg-[#1e2d42] rounded" />
              </div>
            ))
          : [
              { label: '総イメージ数',             value: displayStats.total_images,             color: 'text-[#7d92b0]'  },
              { label: '重大脆弱性',              value: displayStats.critical_vulnerabilities, color: 'text-red-400'    },
              { label: 'スキャン済み',            value: displayStats.scanned,                  color: 'text-green-400'  },
              { label: 'ランタイムイベント(24h)', value: displayStats.runtime_events_24h,        color: 'text-orange-400' },
              { label: '重大イベント',            value: displayStats.critical_events,           color: 'text-red-400'    },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
                <p className="text-xs text-[#7d92b0] mb-2">{label}</p>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
              </div>
            ))
        }
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {([
          ['images',   'コンテナイメージ'],
          ['events',   'ランタイムイベント'],
          ['policies', 'セキュリティポリシー'],
        ] as const).map(([tab, label]) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === tab ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Images Tab */}
      {activeTab === 'images' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          {imagesLoading ? (
            <div className="flex items-center justify-center py-16 gap-2">
              <Loader2 className="w-5 h-5 text-[#e8002d] animate-spin" />
              <span className="text-sm text-[#7d92b0]">イメージ読込中...</span>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['レジストリ / リポジトリ:タグ', '脆弱性', 'スキャン状態', '最終スキャン', 'サイズ', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {images.map(img => {
                  const sc = SCAN_STATUS_CONFIG[img.scan_status]
                  const hasCritical = img.critical_vulns > 0
                  return (
                    <tr
                      key={img.id}
                      className={`border-b border-[#1e2d42]/60 last:border-0 transition-colors hover:bg-[#070d19]/50 ${hasCritical ? 'border-l-2 border-l-red-500' : ''}`}
                    >
                      <td className="px-4 py-3">
                        <p className="text-xs text-[#7d92b0]">{img.registry}</p>
                        <p className="text-sm text-white font-mono">{img.repo}:{img.tag}</p>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {img.critical_vulns > 0 && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-semibold bg-red-500/15 text-red-300 border-red-500/30">
                              {img.critical_vulns} 重大
                            </span>
                          )}
                          {img.high_vulns > 0 && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-semibold bg-orange-500/15 text-orange-300 border-orange-500/30">
                              {img.high_vulns} 高
                            </span>
                          )}
                          {img.critical_vulns === 0 && img.high_vulns === 0 && (
                            <span className="text-xs text-green-400">{img.medium_vulns} 中</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs border font-medium ${sc.cls}`}>
                          {sc.animated && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />}
                          {sc.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">{fmtDate(img.last_scanned)}</td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">{fmtSize(img.size_mb)}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => scanMutation.mutate(img.id)}
                          disabled={scanningIds.has(img.id) || scanAllMutation.isPending}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1e2d42] hover:bg-[#2a3a52] text-[#7d92b0] hover:text-white text-xs font-medium transition-colors disabled:opacity-50"
                        >
                          {scanningIds.has(img.id)
                            ? <Loader2 className="w-3 h-3 animate-spin" />
                            : <ScanLine className="w-3 h-3" />}
                          スキャン
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Policies Tab */}
      {activeTab === 'policies' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-[#7d92b0]">
              コンテナのセキュリティポリシーを管理します。ポリシーはイメージのプル・コンテナ起動時に評価されます。
            </p>
          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            {policiesLoading ? (
              <div className="flex items-center justify-center py-16 gap-2">
                <Loader2 className="w-5 h-5 text-[#e8002d] animate-spin" />
                <span className="text-sm text-[#7d92b0]">ポリシー読込中...</span>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ポリシー名', 'タイプ', '説明', 'アクション', '有効'].map(h => (
                      <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {policies.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-12 text-center text-sm text-[#7d92b0]">
                        ポリシーが設定されていません。
                      </td>
                    </tr>
                  ) : policies.map(pol => {
                    const typeMeta = POLICY_TYPE_META[pol.policy_type] ?? { label: pol.policy_type, color: '#7d92b0' }
                    return (
                      <tr key={pol.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 flex-shrink-0" style={{ color: typeMeta.color }} />
                            <span className="text-sm text-white font-medium">{pol.name}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs border font-mono"
                                style={{ color: typeMeta.color, backgroundColor: `${typeMeta.color}15`, borderColor: `${typeMeta.color}40` }}>
                            {typeMeta.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-[#7d92b0] max-w-xs">
                          <span className="line-clamp-2">{pol.description}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${
                            pol.action === 'block' ? 'bg-red-500/15 text-red-300 border-red-500/30' :
                            pol.action === 'alert' ? 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' :
                            'bg-blue-500/15 text-blue-300 border-blue-500/30'
                          }`}>
                            {pol.action === 'block' ? 'ブロック' : pol.action === 'alert' ? 'アラート' : 'ログ'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => togglePolicyMutation.mutate(pol.id)}
                            disabled={togglePolicyMutation.isPending}
                            className="transition-colors"
                            title={pol.is_enabled ? '無効化' : '有効化'}
                          >
                            {pol.is_enabled
                              ? <ToggleRight className="w-6 h-6 text-green-400" />
                              : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />}
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Runtime Events Tab */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value as Severity | 'all')}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#7d92b0] focus:outline-none focus:border-[#e8002d]/50"
            >
              <option value="all">全重要度</option>
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => (
                <option key={s} value={s}>{SEVERITY_CONFIG[s].label}</option>
              ))}
            </select>
            <span className="text-xs text-[#7d92b0] ml-auto">{events.length} 件</span>
          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            {eventsLoading ? (
              <div className="flex items-center justify-center py-16 gap-2">
                <Loader2 className="w-5 h-5 text-[#e8002d] animate-spin" />
                <span className="text-sm text-[#7d92b0]">イベント読込中...</span>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['コンテナ / Pod', 'イメージ', '名前空間', 'イベントタイプ', '重要度', '説明', 'タイムスタンプ'].map(h => (
                      <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-4 py-10 text-center text-sm text-[#7d92b0]">ランタイムイベントがありません。</td>
                    </tr>
                  ) : events.map(ev => (
                    <tr key={ev.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3">
                        <p className="text-xs text-[#7d92b0]">{ev.pod}</p>
                        <p className="text-sm text-white font-mono">{ev.container}</p>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono max-w-[180px] truncate" title={ev.image}>
                        {ev.image}
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs border font-mono bg-[#070d19] border-[#1e2d42] text-[#7d92b0]">
                          {ev.namespace}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium whitespace-nowrap ${EVENT_TYPE_CONFIG[ev.event_type].cls}`}>
                          {EVENT_TYPE_CONFIG[ev.event_type].label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${SEVERITY_CONFIG[ev.severity].cls}`}>
                          {SEVERITY_CONFIG[ev.severity].label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] max-w-[260px]">
                        <span title={ev.description} className="line-clamp-2">{ev.description}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{fmtDate(ev.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
