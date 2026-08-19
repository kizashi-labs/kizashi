'use client'

import { useState, useEffect, useRef, Suspense } from 'react'
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { formatDistanceToNow, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import type { Agent, PaginatedResponse } from '@/types/api'
import { apiFetch } from '@/lib/api'
import { DataUnavailable } from '@/components/DataUnavailable'
import { AgentStatusBadge, OSIcon } from '@/components/ui/badges'
import { usePlan } from '@/lib/usePlan'
import { useCanWrite } from '@/lib/auth'
import { Monitor, ShieldAlert, ShieldCheck, Search, RefreshCw, Wifi, WifiOff, PowerOff, Layers, X, TrendingUp, Download, Terminal, BarChart2, Trash2 } from 'lucide-react'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface AgentGroup {
  id: string
  name: string
}

interface AgentRisk {
  id: string
  score: number
  level: string
}

// ── Kernel-protection fleet readiness (OS-agnostic) ───────────────
// Visualizes the protection_mode reported by agents via heartbeat:
// enforce = in-kernel prevention/tamper active, observe = detection only,
// poll = fallback, 未申告 = older agents / not yet reported. The tier is the
// same across platforms — Linux reports it from eBPF LSM (KRSI) readiness,
// Windows from the KizashiPrevention driver state — so this aggregate spans
// the whole fleet regardless of OS.
function PreventionReadinessCard() {
  const { data } = useQuery({
    queryKey: ['protection-summary'],
    queryFn: () =>
      apiFetch<{
        by_mode: Record<string, number>
        by_os?: Record<string, Record<string, number>>
        total: number
        enforce_ready_pct: number
        // Effective collection mechanism, distinct from the capability tiers above.
        telemetry_by_mode?: Record<string, number>
        ebpf_effective_pct?: number
      }>('/api/v1/agents-protection-summary'),
    staleTime: 60_000,
  })
  if (!data || data.total === 0) return null
  const m = data.by_mode || {}
  const tiers = [
    { key: 'enforce', label: 'enforce（実行前防御）', color: 'text-green-400', bar: '#22c55e' },
    { key: 'observe', label: 'observe（検知のみ）', color: 'text-blue-400', bar: '#3b82f6' },
    { key: 'poll', label: 'poll（ポーリング）', color: 'text-[#8899aa]', bar: '#64748b' },
    { key: 'unreported', label: '未申告', color: 'text-[#5a6a7a]', bar: '#374151' },
  ]
  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 mb-6">
      <div className="flex items-center gap-2 mb-3">
        <ShieldCheck className="w-4 h-4 text-green-400" />
        <h2 className="text-sm font-semibold text-[#8899aa]">カーネル能動防御レディネス（Linux eBPF LSM / Windows ドライバ）</h2>
        <span className="ml-auto text-xs text-[#5a6a7a]">
          enforce 率 <span className="text-white font-bold">{data.enforce_ready_pct}%</span>
        </span>
      </div>
      <div className="flex h-2.5 rounded-full overflow-hidden mb-3 bg-[#0b1220]">
        {tiers.map(t => {
          const v = m[t.key] || 0
          const w = data.total > 0 ? (v / data.total) * 100 : 0
          return w > 0 ? (
            <div key={t.key} style={{ width: `${w}%`, background: t.bar }} title={`${t.label}: ${v}`} />
          ) : null
        })}
      </div>
      <div className="grid grid-cols-4 gap-3">
        {tiers.map(t => (
          <div key={t.key}>
            <p className="text-xs text-[#5a6a7a]">{t.label}</p>
            <p className={`text-lg font-bold ${t.color}`}>{m[t.key] || 0}</p>
          </div>
        ))}
      </div>
      {data.by_os && Object.keys(data.by_os).length > 0 && (
        <div className="mt-3 pt-3 border-t border-[#1e2d42] space-y-1.5">
          <p className="text-[10px] uppercase tracking-wide text-[#5a6a7a] mb-1">OS 別内訳</p>
          {Object.entries(data.by_os)
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([os, modes]) => {
              const osTotal = Object.values(modes).reduce((a, b) => a + b, 0)
              return (
                <div key={os} className="flex items-center gap-2 text-xs">
                  <span className="w-16 text-[#8899aa] capitalize shrink-0">{os}</span>
                  <div className="flex h-1.5 flex-1 rounded-full overflow-hidden bg-[#0b1220]">
                    {tiers.map(t => {
                      const v = modes[t.key] || 0
                      const w = osTotal > 0 ? (v / osTotal) * 100 : 0
                      return w > 0 ? (
                        <div
                          key={t.key}
                          style={{ width: `${w}%`, background: t.bar }}
                          title={`${os} ${t.label}: ${v}`}
                        />
                      ) : null
                    })}
                  </div>
                  <span className="text-[#5a6a7a] tabular-nums shrink-0">
                    {modes.enforce || 0}/{osTotal}
                  </span>
                </div>
              )
            })}
        </div>
      )}
      <TelemetryModeRow byMode={data.telemetry_by_mode} pct={data.ebpf_effective_pct} />
    </div>
  )
}

// ── Effective collection mechanism ────────────────────────────────
// protection_mode above is host CAPABILITY; this is what the collectors ACTUALLY
// ended up running on. The two diverge exactly where it hurts: an eBPF-capable host
// whose sensors fell back to userspace polling reports enforce-ready while it is
// collecting blind — port scans of closed ports (T1046) become structurally
// invisible and file events lose process attribution, so ransomware detection can no
// longer name the process. That state ran unnoticed for days (2026-08-03) because
// the number existed and nothing displayed it.
//
// `poll` is therefore rendered as a warning rather than a neutral tier, and the row
// is hidden entirely when no agent reports a mode — Windows/macOS agents do not, and
// a permanent "0 / unknown" row would just be noise.
function TelemetryModeRow({ byMode, pct }: { byMode?: Record<string, number>; pct?: number }) {
  if (!byMode) return null
  const reporting = (byMode.ebpf || 0) + (byMode.poll || 0) + (byMode.off || 0)
  if (reporting === 0) return null
  const degraded = byMode.poll || 0
  return (
    <div className="mt-3 pt-3 border-t border-[#1e2d42]">
      <div className="flex items-center gap-2">
        <p className="text-[10px] uppercase tracking-wide text-[#5a6a7a]">実効テレメトリ（実際の収集方式）</p>
        <span className="ml-auto text-xs text-[#5a6a7a]">
          eBPF 実効率 <span className="text-white font-bold">{pct ?? 0}%</span>
        </span>
      </div>
      <div className="flex items-center gap-4 mt-2 text-xs">
        <span className="text-[#8899aa]">
          eBPF <span className="text-green-400 font-bold tabular-nums">{byMode.ebpf || 0}</span>
        </span>
        <span className="text-[#8899aa]">
          ポーリング{' '}
          <span className={`font-bold tabular-nums ${degraded > 0 ? 'text-amber-400' : 'text-[#5a6a7a]'}`}>
            {degraded}
          </span>
        </span>
        <span className="text-[#8899aa]">
          無効 <span className="text-[#5a6a7a] font-bold tabular-nums">{byMode.off || 0}</span>
        </span>
      </div>
      {degraded > 0 && (
        <p className="mt-2 text-[11px] text-amber-400/90 leading-relaxed">
          {degraded} 台のセンサーが eBPF からポーリングに降格しています。閉じたポートへの接続（ポートスキャン
          T1046）が観測できず、ファイルイベントにプロセス帰属が付きません。該当エージェントには
          「センサー降格」アラートが上がっています。
        </p>
      )}
    </div>
  )
}

// ── UEBA behavioral-anomaly risk board ────────────────────────────
// Top agents by anomaly_score (UEBA + Isolation Forest) stamped onto recent
// alerts by the detection engine — surfaces the live ML behavioral scoring.
function AnomalyBoardCard() {
  const { data } = useQuery({
    queryKey: ['anomaly-board'],
    queryFn: () =>
      apiFetch<{
        agents: Array<{
          agent_id: string
          hostname: string
          os_type: string
          max_anomaly: number
          avg_anomaly: number
          alert_count: number
        }>
        total: number
      }>('/api/v1/agents-anomaly-board'),
    staleTime: 60_000,
  })
  if (!data || data.total === 0) return null
  // anomaly_score は 0–1 の契約だが、範囲外の値が入っても 60786% のような
  // 描画にならないよう clamp する（実際に生の z スコアが混入していた）。
  const clamp01 = (v: number) => (Number.isFinite(v) ? Math.min(Math.max(v, 0), 1) : 0)
  const riskColor = (v: number) => (v >= 0.7 ? '#ef4444' : v >= 0.4 ? '#f59e0b' : '#3b82f6')
  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 mb-6">
      <div className="flex items-center gap-2 mb-3">
        <TrendingUp className="w-4 h-4 text-amber-400" />
        <h2 className="text-sm font-semibold text-[#8899aa]">UEBA 振る舞い異常スコア（直近7日）</h2>
        <span className="ml-auto text-xs text-[#5a6a7a]">上位 {data.agents.length} 台</span>
      </div>
      <div className="space-y-1.5">
        {data.agents.map(a => {
          const score = clamp01(a.max_anomaly)
          const pct = Math.round(score * 100)
          return (
            <div key={a.agent_id} className="flex items-center gap-3 text-xs">
              <span className="w-40 truncate text-white" title={a.hostname || a.agent_id}>
                {a.hostname || a.agent_id.slice(0, 8)}
              </span>
              <span className="w-12 text-[#5a6a7a] capitalize shrink-0">{a.os_type}</span>
              <div className="flex-1 h-2 rounded-full overflow-hidden bg-[#0b1220]">
                <div className="h-full" style={{ width: `${pct}%`, background: riskColor(score) }} />
              </div>
              <span className="w-10 text-right tabular-nums shrink-0" style={{ color: riskColor(score) }}>
                {pct}%
              </span>
              <span className="w-14 text-right text-[#5a6a7a] tabular-nums shrink-0">{a.alert_count} 件</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Risk Ranking view ─────────────────────────────────────────────

function RiskRankingView({
  agents,
  riskMap,
}: {
  agents: Agent[]
  riskMap: Map<string, AgentRisk>
}) {
  const ranked = [...agents]
    .map(a => ({ ...a, risk: riskMap.get(a.id) }))
    .filter(a => a.risk)
    .sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0))
    .slice(0, 20)

  if (ranked.length === 0) {
    return (
      <div className="text-center py-16 bg-[#111827] rounded-xl border border-[#1e2d42]">
        <TrendingUp className="w-10 h-10 text-[#5a6a7a] mx-auto mb-2" />
        <p className="text-[#5a6a7a] text-sm">リスクスコアデータがありません</p>
      </div>
    )
  }

  const maxScore = ranked[0]?.risk?.score ?? 100

  function riskStyle(level?: string) {
    if (level === 'critical') return { bar: '#ef4444', badge: 'bg-red-900/40 text-red-300 border-red-700/50' }
    if (level === 'high')     return { bar: '#f97316', badge: 'bg-orange-900/40 text-orange-300 border-orange-700/50' }
    if (level === 'medium')   return { bar: '#eab308', badge: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50' }
    return { bar: '#3b82f6', badge: 'bg-blue-900/40 text-blue-300 border-blue-700/50' }
  }

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-3">
        {(['critical', 'high', 'medium', 'low'] as const).map(level => {
          const cnt = ranked.filter(a => a.risk?.level === level).length
          const style = riskStyle(level)
          const label = level === 'critical' ? 'クリティカル' : level === 'high' ? '高' : level === 'medium' ? '中' : '低'
          return (
            <div key={level} className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-3">
              <div className="w-3 h-8 rounded-full shrink-0" style={{ background: style.bar }} />
              <div>
                <p className="text-xs text-[#5a6a7a]">{label}</p>
                <p className="text-xl font-bold text-white">{cnt}</p>
              </div>
            </div>
          )
        })}
      </div>

      {/* Risk bar chart */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5">
        <div className="flex items-center gap-2 mb-4">
          <BarChart2 className="w-4 h-4 text-[#5a6a7a]" />
          <h2 className="text-sm font-semibold text-[#8899aa]">Top 20 高リスクエンドポイント</h2>
        </div>
        <div className="space-y-2">
          {ranked.map((a, idx) => {
            const style = riskStyle(a.risk?.level)
            const pct   = maxScore > 0 ? ((a.risk?.score ?? 0) / maxScore) * 100 : 0
            return (
              <div key={a.id} className="flex items-center gap-3">
                <span className="text-xs text-[#5a6a7a] w-5 text-right shrink-0">{idx + 1}</span>
                <Link href={`/endpoints/${a.id}`}
                  className="text-sm text-[#c9d6e8] hover:text-white transition-colors w-40 truncate shrink-0">
                  {a.hostname}
                </Link>
                <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all"
                    style={{ width: `${pct}%`, background: style.bar }} />
                </div>
                <span className="text-xs font-bold w-8 text-right shrink-0" style={{ color: style.bar }}>
                  {a.risk?.score}
                </span>
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-sm border shrink-0 ${style.badge}`}>
                  {a.risk?.level?.toUpperCase()}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── Virtual agent table (used when agents.length > 100) ───────────────────────
const VIRTUAL_ROW_H = 56 // px

function VirtualAgentTable({
  agents,
  riskMap,
  groupsData,
  isolate,
  unisolate,
  deleteAgent,
  setGroupFilter,
  canWrite,
}: {
  agents: Agent[]
  riskMap: Map<string, AgentRisk>
  groupsData: { data: AgentGroup[] } | undefined
  isolate: { mutate: (id: string) => void; isPending: boolean }
  unisolate: { mutate: (id: string) => void; isPending: boolean }
  deleteAgent: { mutate: (id: string) => void; isPending: boolean }
  setGroupFilter: (gid: string) => void
  canWrite: boolean
}) {
  const parentRef = useRef<HTMLDivElement>(null)
  const rowVirtualizer = useVirtualizer({
    count: agents.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => VIRTUAL_ROW_H,
    overscan: 10,
  })
  const totalHeight = rowVirtualizer.getTotalSize()

  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
      {/* Sticky header */}
      <table className="w-full text-sm table-fixed">
        <thead>
          <tr className="border-b border-[#1e2d42] bg-[#080c14]/40">
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[22%]">ホスト名</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[14%]">OS</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[11%]">ステータス</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[13%]">グループ</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[14%]">IPアドレス</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[10%]">最終確認</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[7%]">リスク</th>
            <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] w-[9%]">操作</th>
          </tr>
        </thead>
      </table>
      {/* Scrollable virtual body */}
      <div ref={parentRef} className="overflow-y-auto" style={{ maxHeight: 520 }}>
        <div style={{ height: totalHeight, position: 'relative' }}>
          {rowVirtualizer.getVirtualItems().map(vRow => {
            const agent = agents[vRow.index]
            const r = riskMap.get(agent.id)
            const riskCls = r
              ? r.level === 'critical' ? 'text-red-400 bg-red-900/30 border-red-700'
              : r.level === 'high'     ? 'text-orange-400 bg-orange-900/30 border-orange-700'
              : r.level === 'medium'   ? 'text-yellow-400 bg-yellow-900/30 border-yellow-700'
              :                          'text-blue-400 bg-blue-900/30 border-blue-700'
              : ''
            return (
              <div
                key={agent.id}
                style={{
                  position: 'absolute',
                  top: vRow.start,
                  left: 0,
                  right: 0,
                  height: VIRTUAL_ROW_H,
                }}
                className="flex items-center border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30 transition-colors text-sm px-4 gap-4"
              >
                <div className="w-[22%] min-w-0">
                  <Link href={`/endpoints/${agent.id}`}
                    className="font-medium text-[#e2e8f4] hover:text-blue-400 transition-colors truncate block">
                    {agent.hostname}
                  </Link>
                  {agent.status === 'isolated' && (
                    <span className="text-xs bg-red-900/40 text-red-300 border border-red-700/50 px-1.5 py-0.5 rounded-sm">隔離中</span>
                  )}
                </div>
                <div className="w-[14%] flex items-center gap-1.5">
                  <OSIcon os={agent.os_type} />
                  <span className="text-xs text-[#5a6a7a] truncate">{agent.os_version}</span>
                </div>
                <div className="w-[11%]"><AgentStatusBadge status={agent.status} /></div>
                <div className="w-[13%]">
                  {agent.group_id ? (
                    <button onClick={() => setGroupFilter(agent.group_id!)}
                      className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300">
                      <Layers className="w-3 h-3 shrink-0" />
                      <span className="truncate">{groupsData?.data?.find(g => g.id === agent.group_id)?.name ?? '—'}</span>
                    </button>
                  ) : <span className="text-xs text-[#5a6a7a]">—</span>}
                </div>
                <div className="w-[14%]">
                  <span className="text-xs text-[#8899aa] font-mono">{agent.ip_addresses?.[0] ?? '—'}</span>
                </div>
                <div className="w-[10%] text-xs text-[#5a6a7a]">
                  {agent.last_seen
                    ? formatDistanceToNow(parseISO(agent.last_seen), { addSuffix: true, locale: ja })
                    : '—'}
                </div>
                <div className="w-[7%]">
                  {r ? (
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-bold ${riskCls}`}>{r.score}</span>
                  ) : <span className="text-xs text-[#5a6a7a]">—</span>}
                </div>
                <div className="w-[9%] flex items-center gap-1.5">
                  {canWrite && (agent.status === 'isolated' ? (
                    <button onClick={() => unisolate.mutate(agent.id)} disabled={unisolate.isPending}
                      className="text-xs text-green-300 bg-green-900/30 border border-green-700/50 rounded-lg px-2 py-1 hover:bg-green-900/50 transition-colors disabled:opacity-50">
                      解除
                    </button>
                  ) : (
                    <button onClick={() => { if (confirm(`${agent.hostname} を隔離しますか？`)) isolate.mutate(agent.id) }}
                      disabled={isolate.isPending || agent.status === 'offline'}
                      className="text-xs text-red-300 bg-red-900/30 border border-red-700/50 rounded-lg px-2 py-1 hover:bg-red-900/50 transition-colors disabled:opacity-50">
                      隔離
                    </button>
                  ))}
                  <Link href={`/endpoints/${agent.id}`} className="text-xs text-blue-400 hover:text-blue-300">→</Link>
                  {canWrite && (
                  <button
                    onClick={() => {
                      if (confirm(`「${agent.hostname}」を削除しますか？この操作は取り消せません。`)) {
                        deleteAgent.mutate(agent.id)
                      }
                    }}
                    disabled={deleteAgent.isPending}
                    title="エージェントを削除"
                    className="flex items-center justify-center text-xs text-gray-400 hover:text-red-400 bg-transparent hover:bg-red-900/20 border border-transparent hover:border-red-700/50 rounded-lg p-1.5 transition-colors disabled:opacity-50"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function EndpointsInner() {
  const canWrite = useCanWrite()
  const qc = useQueryClient()
  const searchParams = useSearchParams()
  const searchInputRef = useRef<HTMLInputElement>(null)
  const [search, setSearch]         = useState('')
  const [osFilter, setOS]           = useState('')
  const [statusFilter, setStatus]   = useState('')
  const [groupFilter, setGroupFilter] = useState(searchParams.get('group_id') ?? '')
  const [activeView, setActiveView] = useState<'list' | 'risk'>('list')

  // Sync group_id from URL on mount
  useEffect(() => {
    const gid = searchParams.get('group_id')
    if (gid) setGroupFilter(gid)
  }, [searchParams])

  const { data: riskData } = useQuery<{ data: AgentRisk[] }>({
    queryKey: ['agents-risk-scores'],
    queryFn: () => apiFetch('/api/v1/agents-risk-scores'),
    staleTime: 60_000,
  })
  const riskMap = new Map((riskData?.data ?? []).map(r => [r.id, r]))

  const { data: groupsData } = useQuery<{ data: AgentGroup[] }>({
    queryKey: ['groups'],
    queryFn: () => apiFetch('/api/v1/groups'),
  })

  const apiParams = new URLSearchParams({
    ...(osFilter     && { os: osFilter }),
    ...(statusFilter && { status: statusFilter }),
    ...(groupFilter  && { group_id: groupFilter }),
    per_page: '200',
  })

  const { data, isLoading, isError, error, refetch } = useQuery<PaginatedResponse<Agent>>({
    queryKey: ['agents', osFilter, statusFilter, groupFilter],
    queryFn: () => apiFetch<PaginatedResponse<Agent>>(`/api/v1/agents?${apiParams}`),
    refetchInterval: 15_000,
    placeholderData: keepPreviousData,
  })

  const isolate = useMutation({
    mutationFn: (agentID: string) =>
      apiFetch(`/api/v1/agents/${agentID}/isolate`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const unisolate = useMutation({
    mutationFn: (agentID: string) =>
      apiFetch(`/api/v1/agents/${agentID}/unisolate`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const deleteAgent = useMutation({
    mutationFn: (agentID: string) =>
      apiFetch(`/api/v1/agents/${agentID}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const agentsRaw = data?.data ?? []
  const agents = search
    ? agentsRaw.filter(a =>
        a.hostname?.toLowerCase().includes(search.toLowerCase()) ||
        (a.ip_addresses ?? []).some(ip => ip.includes(search))
      )
    : agentsRaw

  function exportCSV() {
    if (agents.length === 0) return
    const groupMap = Object.fromEntries((groupsData?.data ?? []).map(g => [g.id, g.name]))
    const headers = ['hostname', 'status', 'os_type', 'os_version', 'ip_address', 'group', 'last_seen', 'agent_version']
    const rows = agents.map(a => [
      a.hostname, a.status, a.os_type ?? '', a.os_version ?? '',
      (a.ip_addresses ?? []).join('; '),
      (a.group_id ? (groupMap[a.group_id] ?? a.group_id) : ''),
      a.last_seen ?? '', a.agent_version ?? '',
    ])
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `endpoints-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  // inactive（30日以上未確認）を独立して数える。省くと total だけが増えて
  // online+offline+isolated と一致せず、退役済みホストがどの内訳にも現れない。
  const counts = {
    total:    data?.total ?? 0,
    online:   agents.filter(a => a.status === 'online').length,
    offline:  agents.filter(a => a.status === 'offline').length,
    isolated: agents.filter(a => a.status === 'isolated').length,
    inactive: agents.filter(a => a.status === 'inactive').length,
  }

  const { plan, agentUsed, agentLimit, isNearFreeLimit, isAtFreeLimit } = usePlan()

  return (
    <div className="p-6">
      <PageSaveFailed className="mb-4" />
      {/* 下の集計は取得に失敗すると 0台 を表示します。
          その 0 が事実かどうかをここで言う。 */}
      <DataUnavailable error={error} what="エンドポイント" onRetry={refetch} className="mb-4" />

      {/* Freeプラン エージェント上限インライン警告 */}
      {isAtFreeLimit && (
        <div className="mb-4 flex items-center gap-3 px-4 py-3 bg-red-950/40 border border-red-600/40 rounded-xl">
          <span className="text-red-400 text-sm font-medium">
            ⚠ Freeプランの上限（{agentLimit}台）に達しました。
            新しいエンドポイントを追加するには
          </span>
          <a href="/admin/license" className="text-red-300 underline text-sm font-bold hover:text-red-200">
            Liteプランへアップグレード
          </a>
          <span className="text-[#3d5068] text-xs ml-auto">¥500/台/月〜 · 最小5台</span>
        </div>
      )}
      {isNearFreeLimit && !isAtFreeLimit && (
        <div className="mb-4 flex items-center gap-3 px-4 py-3 bg-orange-950/30 border border-orange-600/30 rounded-xl">
          <span className="text-orange-300 text-sm">
            エージェント数が上限に近づいています（{agentUsed}/{agentLimit}台）。
            あと{agentLimit - agentUsed}台追加できます。
          </span>
          <a href="/admin/license" className="ml-auto text-orange-300 underline text-sm font-bold hover:text-orange-200">
            Liteプランで45台まで拡張 →
          </a>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">エンドポイント</h1>
          <p className="text-sm text-[#8899aa]">
            {counts.total}台 · オンライン {counts.online}台 · 隔離中 {counts.isolated}台
            {plan === 'free' && (
              <span className="ml-2 text-[#3d5068]">
                · Freeプラン {agentUsed}/{agentLimit}台
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={exportCSV}
            disabled={agents.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#8899aa] bg-[#161f33] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            CSV出力
          </button>
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ['agents'] })}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#8899aa] bg-[#161f33] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
        </div>
      </div>

      {/* View tabs */}
      <div className="flex items-center gap-1 mb-6 border-b border-[#1e2d42]">
        <button
          onClick={() => setActiveView('list')}
          className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            activeView === 'list'
              ? 'border-[#1a6bff] text-white'
              : 'border-transparent text-[#5a6a7a] hover:text-[#c9d6e8]'
          }`}
        >
          <Monitor className="w-4 h-4" />
          エンドポイント一覧
        </button>
        <button
          onClick={() => setActiveView('risk')}
          className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            activeView === 'risk'
              ? 'border-[#1a6bff] text-white'
              : 'border-transparent text-[#5a6a7a] hover:text-[#c9d6e8]'
          }`}
        >
          <TrendingUp className="w-4 h-4" />
          リスクランキング
          {riskMap.size > 0 && (
            <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-red-900/40 text-red-300 border border-red-700/50">
              {[...riskMap.values()].filter(r => r.level === 'critical' || r.level === 'high').length}
            </span>
          )}
        </button>
      </div>

      {/* Risk ranking view */}
      {activeView === 'risk' && (
        <RiskRankingView agents={agents} riskMap={riskMap} />
      )}

      {/* List view */}
      {activeView === 'list' && (<>

      {/* Summary cards */}
      <div className="grid grid-cols-5 gap-3 mb-6">
        {[
          { label: '総数',         value: counts.total,    icon: Monitor,     color: 'text-[#8899aa]' },
          { label: 'オンライン',   value: counts.online,   icon: Wifi,        color: 'text-green-400' },
          { label: 'オフライン',   value: counts.offline,  icon: WifiOff,     color: 'text-[#5a6a7a]' },
          { label: '隔離中',       value: counts.isolated, icon: ShieldAlert, color: 'text-red-400' },
          { label: '非アクティブ', value: counts.inactive, icon: PowerOff,    color: 'text-[#5c6f8a]' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#111827] rounded-xl border border-[#1e2d42] p-3 flex items-center gap-3">
            <Icon className={`w-5 h-5 ${color}`} />
            <div>
              <p className="text-xs text-[#5a6a7a]">{label}</p>
              <p className="text-lg font-bold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Kernel-protection fleet readiness */}
      <PreventionReadinessCard />

      {/* UEBA behavioral-anomaly risk board */}
      <AnomalyBoardCard />

      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
          <input
            ref={searchInputRef}
            type="text"
            defaultValue=""
            placeholder="ホスト名・IPアドレスで検索..."
            onInput={e => setSearch((e.target as HTMLInputElement).value)}
            className="w-full pl-9 pr-4 py-2 text-sm border border-[#1e2d42] rounded-xl bg-[#111827] text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#1a6bff]"
          />
        </div>

        <select
          value={groupFilter}
          onChange={e => setGroupFilter(e.target.value)}
          className="text-sm border border-[#1e2d42] rounded-xl px-3 py-2 bg-[#111827] text-[#8899aa] focus:outline-hidden focus:border-[#1a6bff]"
        >
          <option value="">グループ: すべて</option>
          {(groupsData?.data ?? []).map(g => (
            <option key={g.id} value={g.id}>{g.name}</option>
          ))}
        </select>

        <select
          value={osFilter}
          onChange={e => setOS(e.target.value)}
          className="text-sm border border-[#1e2d42] rounded-xl px-3 py-2 bg-[#111827] text-[#8899aa] focus:outline-hidden focus:border-[#1a6bff]"
        >
          <option value="">OS: すべて</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="darwin">macOS</option>
        </select>

        <select
          value={statusFilter}
          onChange={e => setStatus(e.target.value)}
          className="text-sm border border-[#1e2d42] rounded-xl px-3 py-2 bg-[#111827] text-[#8899aa] focus:outline-hidden focus:border-[#1a6bff]"
        >
          <option value="">ステータス: すべて</option>
          <option value="online">オンライン</option>
          <option value="offline">オフライン</option>
          <option value="isolated">隔離中</option>
          <option value="error">エラー</option>
          <option value="inactive">非アクティブ</option>
        </select>

        {(search || osFilter || statusFilter || groupFilter) && (
          <button
            onClick={() => { setSearch(''); setOS(''); setStatus(''); setGroupFilter(''); if (searchInputRef.current) searchInputRef.current.value = '' }}
            className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-white px-2 py-1 rounded-lg hover:bg-[#19253d] transition-colors"
            title="フィルターをすべてクリア"
          >
            <X className="w-3.5 h-3.5" />
            クリア
          </button>
        )}
      </div>

      {/* Agent table */}
      {isLoading ? (
        <div className="space-y-2">
          {[...Array(10)].map((_, i) => (
            <div key={i} className="h-14 bg-[#111827] rounded-xl border border-[#1e2d42] animate-pulse" />
          ))}
        </div>
      ) : isError ? (
        <div className="text-center py-16 bg-[#111827] rounded-xl border border-[#e8002d]/30">
          <p className="text-[#e8002d] text-sm font-medium">エンドポイントデータの取得に失敗しました</p>
          <p className="text-[#5a6a7a] text-xs mt-1">ネットワーク接続またはサーバーの状態を確認してください</p>
        </div>
      ) : agents.length === 0 ? (
        <div className="text-center py-16 bg-[#111827] rounded-xl border border-[#1e2d42]">
          <Monitor className="w-10 h-10 text-[#5a6a7a] mx-auto mb-2" />
          <p className="text-[#5a6a7a] text-sm">エンドポイントが見つかりません</p>
        </div>
      ) : agents.length > 100 ? (
        <VirtualAgentTable
          agents={agents}
          riskMap={riskMap}
          groupsData={groupsData}
          isolate={isolate}
          unisolate={unisolate}
          deleteAgent={deleteAgent}
          setGroupFilter={setGroupFilter}
          canWrite={canWrite}
        />
      ) : (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#080c14]/40">
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap">ホスト名</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap">OS</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap">ステータス</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap">グループ</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap">IPアドレス</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap">最終確認</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap flex items-center gap-1">
                  <TrendingUp className="w-3 h-3" />リスク
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-[#8899aa] whitespace-nowrap">操作</th>
              </tr>
            </thead>
            <tbody>
              {agents.map(agent => {
                const isOffline = agent.status === 'offline'
                return (
                <tr key={agent.id}
                  className={`border-b border-[#1e2d42]/50 last:border-0 transition-colors ${
                    isOffline
                      ? 'bg-red-950/20 hover:bg-red-950/30 border-l-2 border-l-red-600/50'
                      : 'hover:bg-[#19253d]/30'
                  }`}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {isOffline && (
                        <span className="shrink-0 w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" title="オフライン" />
                      )}
                      <Link href={`/endpoints/${agent.id}`}
                        className={`font-medium transition-colors ${isOffline ? 'text-[#9aacbe] hover:text-red-400' : 'text-[#e2e8f4] hover:text-blue-400'}`}>
                        {agent.hostname}
                      </Link>
                    </div>
                    {agent.status === 'isolated' && (
                      <span className="ml-2 text-xs bg-red-900/40 text-red-300 border border-red-700/50 px-1.5 py-0.5 rounded-sm">
                        隔離中
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <OSIcon os={agent.os_type} />
                      <span className="text-xs text-[#5a6a7a]">{agent.os_version}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <AgentStatusBadge status={agent.status} />
                  </td>
                  <td className="px-4 py-3">
                    {agent.group_id ? (
                      <button
                        onClick={() => setGroupFilter(agent.group_id!)}
                        className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                      >
                        <Layers className="w-3 h-3" />
                        {groupsData?.data?.find(g => g.id === agent.group_id)?.name ?? '—'}
                      </button>
                    ) : (
                      <span className="text-xs text-[#5a6a7a]">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-[#8899aa] font-mono">
                      {agent.ip_addresses?.[0] ?? '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#5a6a7a]">
                    {agent.last_seen
                      ? formatDistanceToNow(parseISO(agent.last_seen), { addSuffix: true, locale: ja })
                      : '—'}
                  </td>
                  <td className="px-4 py-3">
                    {(() => {
                      const r = riskMap.get(agent.id)
                      if (!r) return <span className="text-xs text-[#5a6a7a]">—</span>
                      const cls = r.level === 'critical' ? 'text-red-400 bg-red-900/30 border-red-700' :
                                  r.level === 'high'     ? 'text-orange-400 bg-orange-900/30 border-orange-700' :
                                  r.level === 'medium'   ? 'text-yellow-400 bg-yellow-900/30 border-yellow-700' :
                                                           'text-blue-400 bg-blue-900/30 border-blue-700'
                      return (
                        <span className={`text-xs px-2 py-0.5 rounded-full border font-bold ${cls}`}>
                          {r.score}
                        </span>
                      )
                    })()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {canWrite && (agent.status === 'isolated' ? (
                        <button
                          onClick={() => unisolate.mutate(agent.id)}
                          disabled={unisolate.isPending}
                          className="flex items-center gap-1 text-xs text-green-300 bg-green-900/30 border border-green-700/50 rounded-lg px-2 py-1 whitespace-nowrap hover:bg-green-900/50 transition-colors disabled:opacity-50"
                        >
                          <ShieldCheck className="w-3 h-3" />
                          隔離解除
                        </button>
                      ) : (
                        <button
                          onClick={() => {
                            if (confirm(`${agent.hostname} を隔離しますか？`)) {
                              isolate.mutate(agent.id)
                            }
                          }}
                          disabled={isolate.isPending || agent.status === 'offline'}
                          className="flex items-center gap-1 text-xs text-red-300 bg-red-900/30 border border-red-700/50 rounded-lg px-2 py-1 whitespace-nowrap hover:bg-red-900/50 transition-colors disabled:opacity-50"
                        >
                          <ShieldAlert className="w-3 h-3" />
                          隔離
                        </button>
                      ))}
                      {agent.status === 'online' && (
                        <Link
                          href={`/live-response/${agent.id}`}
                          title="ライブレスポンス"
                          className="flex items-center gap-1 text-xs text-green-400 hover:text-green-300 bg-green-900/20 border border-green-800/50 rounded-lg px-2 py-1 hover:bg-green-900/40 transition-colors"
                        >
                          <Terminal className="w-3 h-3" />
                          LR
                        </Link>
                      )}
                      <Link
                        href={`/endpoints/${agent.id}`}
                        className="text-xs text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                      >
                        詳細 →
                      </Link>
                      {canWrite && (
                      <button
                        onClick={() => {
                          if (confirm(`「${agent.hostname}」を削除しますか？この操作は取り消せません。`)) {
                            deleteAgent.mutate(agent.id)
                          }
                        }}
                        disabled={deleteAgent.isPending}
                        title="エージェントを削除"
                        className="flex items-center justify-center text-xs text-gray-400 hover:text-red-400 bg-transparent hover:bg-red-900/20 border border-transparent hover:border-red-700/50 rounded-lg p-1.5 transition-colors disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                      )}
                    </div>
                  </td>
                </tr>
              )
              })}
            </tbody>
          </table>
        </div>
      )}
      </>)}
    </div>
  )
}

export default function EndpointsPage() {
  return (
    <Suspense fallback={
      <div className="p-6 space-y-2">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="h-14 bg-[#111827] rounded-xl border border-[#1e2d42] animate-pulse" />
        ))}
      </div>
    }>
      <EndpointsInner />
    </Suspense>
  )
}
