'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { format, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import {
  Users, Monitor, ShieldAlert,
  UserX, Server, Cpu, Globe, Clock, Activity,
  ChevronDown, ChevronRight, Zap, Search,
  TrendingUp, TrendingDown, Minus, BarChart2
} from 'lucide-react'
import Link from 'next/link'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { apiFetch } from '@/lib/api'
import { USE_MOCK } from '@/lib/mock'

const TIME_RANGES = [
  { label: '24時間', hours: 24 },
  { label: '7日間',  hours: 168 },
  { label: '30日間', hours: 720 },
]

interface UserAnomaly {
  username: string
  total_logins: number
  failed_logins: number
  fail_rate: number
  unique_hosts: number
  risk_score: number
  signals: string[]
  risk_trend?: 'up' | 'down' | 'stable'
  risk_history?: number[]
}

interface EntityAnomaly {
  agent_id: string
  hostname: string
  alert_count: number
  auth_fails: number
  new_procs: number
  net_conns: number
  risk_score: number
  signals: string[]
}

interface RareProcess {
  image: string
  count: number
  agent_id: string
  hostname: string
  first_seen: string
}

interface NewHost {
  agent_id: string
  hostname: string
  os: string
  first_seen: string
}

interface UEBASummary {
  user_anomalies: UserAnomaly[]
  entity_anomalies: EntityAnomaly[]
  rare_processes: RareProcess[]
  new_hosts: NewHost[]
  summary: {
    high_risk_users: number
    high_risk_entities: number
    rare_process_count: number
    new_host_count: number
  }
}

interface HeatmapData {
  data: number[][]  // [day][hour]
}

interface BaselinePoint {
  day: string
  actual: number
  baseline: number
}

interface AnomalyTypeCount {
  type: string
  count: number
}

// ─── Mock data generators ──────────────────────────────────────────────────

function generateMockHeatmap(): number[][] {
  return Array.from({ length: 7 }, () =>
    Array.from({ length: 24 }, () => Math.random() < 0.3 ? Math.floor(Math.random() * 12) : 0)
  )
}

function generateMockBaseline(): BaselinePoint[] {
  const days = ['月', '火', '水', '木', '金', '土', '日']
  return days.map((day, i) => ({
    day,
    actual:   30 + Math.floor(Math.random() * 40) + (i === 3 ? 60 : 0),
    baseline: 35 + Math.floor(Math.random() * 10),
  }))
}

function generateMockAnomalyTypes(): AnomalyTypeCount[] {
  return [
    { type: '多数のログイン失敗',     count: 42 },
    { type: '異常なログイン時間帯',   count: 31 },
    { type: '多数のホストアクセス',   count: 27 },
    { type: '高失敗率',               count: 19 },
    { type: '多数のアラート発生',     count: 15 },
    { type: '多数のネットワーク接続', count: 11 },
    { type: '多数の新規プロセス',     count: 8 },
  ]
}

// ─── Anomaly Heatmap ───────────────────────────────────────────────────────

function AnomalyHeatmap({ data }: { data: number[][] }) {
  const maxVal = Math.max(...data.flat(), 1)
  const days = ['月', '火', '水', '木', '金', '土', '日']
  const getColor = (v: number) => {
    if (v === 0) return '#0d1220'
    const intensity = v / maxVal
    if (intensity < 0.3) return '#1e3a5f'
    if (intensity < 0.7) return '#1e6b9f'
    return '#e8002d'
  }
  return (
    <div className="overflow-x-auto">
      {/* Day headers */}
      <div className="grid gap-0.5 mb-1" style={{ gridTemplateColumns: 'auto repeat(7, 1fr)' }}>
        <span className="w-10" />
        {days.map((d, i) => (
          <span key={i} className="text-[#7d92b0] text-xs text-center font-medium">{d}</span>
        ))}
      </div>
      <div className="grid gap-0.5" style={{ gridTemplateColumns: 'auto repeat(7, 1fr)' }}>
        {Array.from({ length: 24 }, (_, h) => (
          <>
            <span key={`h${h}`} className="text-[#7d92b0] text-xs text-right pr-1 leading-3 w-10">{h}:00</span>
            {days.map((d, di) => (
              <div
                key={`${h}-${di}`}
                title={`${d} ${h}:00 - ${data[di]?.[h] || 0}件`}
                className="h-3 rounded-xs cursor-pointer hover:opacity-80 transition-opacity"
                style={{ backgroundColor: getColor(data[di]?.[h] || 0) }}
              />
            ))}
          </>
        ))}
      </div>
      {/* Legend */}
      <div className="flex items-center gap-3 mt-3 pt-2 border-t border-[#1e2d42]">
        <span className="text-[10px] text-[#5a6a7a]">密度:</span>
        {[
          { color: '#0d1220', label: '0' },
          { color: '#1e3a5f', label: '低' },
          { color: '#1e6b9f', label: '中' },
          { color: '#e8002d', label: '高' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-xs border border-[#1e2d42]/50" style={{ backgroundColor: color }} />
            <span className="text-[10px] text-[#7d92b0]">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Baseline Deviation Chart ─────────────────────────────────────────────

function BaselineDeviationChart({ points }: { points: BaselinePoint[] }) {
  const W = 520
  const H = 140
  const PAD = { top: 12, right: 16, bottom: 24, left: 36 }
  const innerW = W - PAD.left - PAD.right
  const innerH = H - PAD.top - PAD.bottom

  const allVals = points.flatMap(p => [p.actual, p.baseline])
  const minV = Math.max(0, Math.min(...allVals) - 10)
  const maxV = Math.max(...allVals) + 10

  const xScale = (i: number) => PAD.left + (i / (points.length - 1)) * innerW
  const yScale = (v: number) => PAD.top + innerH - ((v - minV) / (maxV - minV)) * innerH

  const toPath = (vals: number[]) =>
    vals.map((v, i) => `${i === 0 ? 'M' : 'L'} ${xScale(i).toFixed(1)} ${yScale(v).toFixed(1)}`).join(' ')

  const actualPath   = toPath(points.map(p => p.actual))
  const baselinePath = toPath(points.map(p => p.baseline))

  // Fill area between actual and baseline
  const fillPath = [
    ...points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${xScale(i).toFixed(1)} ${yScale(p.actual).toFixed(1)}`),
    ...points.map((p, i) => `L ${xScale(points.length - 1 - i).toFixed(1)} ${yScale(points[points.length - 1 - i].baseline).toFixed(1)}`),
    'Z',
  ].join(' ')

  return (
    <div className="w-full overflow-x-auto">
      <svg width={W} height={H} className="overflow-visible" style={{ maxWidth: '100%' }}>
        {/* Grid lines */}
        {[0.25, 0.5, 0.75, 1].map(f => {
          const y = PAD.top + innerH * (1 - f)
          const v = Math.round(minV + (maxV - minV) * f)
          return (
            <g key={f}>
              <line x1={PAD.left} y1={y} x2={PAD.left + innerW} y2={y} stroke="#1e2d42" strokeDasharray="3,3" />
              <text x={PAD.left - 4} y={y + 4} textAnchor="end" fontSize={9} fill="#5a6a7a">{v}</text>
            </g>
          )
        })}

        {/* Fill area */}
        <path d={fillPath} fill="rgba(232,0,45,0.08)" />

        {/* Baseline line (blue dashed) */}
        <path d={baselinePath} fill="none" stroke="#1a6bff" strokeWidth={1.5} strokeDasharray="5,3" opacity={0.7} />

        {/* Actual line (red solid) */}
        <path d={actualPath} fill="none" stroke="#e8002d" strokeWidth={2} />

        {/* Data points */}
        {points.map((p, i) => (
          <g key={i}>
            <circle cx={xScale(i)} cy={yScale(p.actual)} r={3} fill="#e8002d" />
            <circle cx={xScale(i)} cy={yScale(p.baseline)} r={2.5} fill="#1a6bff" opacity={0.7} />
          </g>
        ))}

        {/* X-axis labels */}
        {points.map((p, i) => (
          <text key={i} x={xScale(i)} y={H - 4} textAnchor="middle" fontSize={10} fill="#7d92b0">
            {p.day}
          </text>
        ))}
      </svg>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-1">
        <div className="flex items-center gap-1.5">
          <svg width={20} height={10}><line x1={0} y1={5} x2={20} y2={5} stroke="#e8002d" strokeWidth={2} /></svg>
          <span className="text-[10px] text-[#7d92b0]">実際の活動</span>
        </div>
        <div className="flex items-center gap-1.5">
          <svg width={20} height={10}><line x1={0} y1={5} x2={20} y2={5} stroke="#1a6bff" strokeWidth={1.5} strokeDasharray="5,3" /></svg>
          <span className="text-[10px] text-[#7d92b0]">ベースライン</span>
        </div>
      </div>
    </div>
  )
}

// ─── Anomaly Type Distribution ────────────────────────────────────────────

function AnomalyTypeBar({ items }: { items: AnomalyTypeCount[] }) {
  const maxCount = Math.max(...items.map(i => i.count), 1)
  return (
    <div className="space-y-2">
      {items.map((item, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="text-xs text-[#8899aa] w-40 truncate shrink-0">{item.type}</span>
          <div className="flex-1 h-4 bg-[#0d1220] rounded-sm overflow-hidden">
            <div
              className="h-full rounded-sm transition-all"
              style={{
                width: `${(item.count / maxCount) * 100}%`,
                background: `linear-gradient(90deg, #1a6bff, #7c3aed)`,
              }}
            />
          </div>
          <span className="text-xs text-white font-mono w-8 text-right shrink-0">{item.count}</span>
        </div>
      ))}
    </div>
  )
}

// ─── Trend Arrow ──────────────────────────────────────────────────────────

function TrendArrow({ trend }: { trend?: 'up' | 'down' | 'stable' }) {
  if (trend === 'up') return <span title="リスク増加中"><TrendingUp className="w-3.5 h-3.5 text-red-400 shrink-0" /></span>
  if (trend === 'down') return <span title="リスク低下中"><TrendingDown className="w-3.5 h-3.5 text-green-400 shrink-0" /></span>
  return <span title="安定"><Minus className="w-3.5 h-3.5 text-[#5a6a7a] shrink-0" /></span>
}

// ─── Existing helpers (unchanged) ─────────────────────────────────────────

function RiskBadge({ score }: { score: number }) {
  const cfg = score >= 70
    ? { cls: 'bg-red-900/50 text-red-300 border-red-700', label: '高リスク' }
    : score >= 40
    ? { cls: 'bg-yellow-900/50 text-yellow-300 border-yellow-700', label: '中リスク' }
    : { cls: 'bg-[#161f33] text-[#8899aa] border-[#1e2d42]', label: '低リスク' }
  return (
    <span className={`px-2 py-0.5 rounded-sm border text-xs font-semibold ${cfg.cls}`}>
      {cfg.label} {score}
    </span>
  )
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="w-24 h-1.5 bg-[#161f33] rounded-full overflow-hidden">
      <div className={`h-full ${color} transition-all`} style={{ width: `${score}%` }} />
    </div>
  )
}

const SIGNAL_WEIGHTS: Record<string, number> = {
  '多数のログイン失敗': 35,
  '異常なログイン時間帯': 20,
  '多数のホストへのアクセス': 25,
  '高失敗率': 30,
  '多数のアラート発生': 40,
  '多数の認証失敗': 35,
  '多数のネットワーク接続': 20,
  '多数の新規プロセス': 25,
}

function ScoreBreakdown({ signals, score }: { signals: string[]; score: number }) {
  if (signals.length === 0) return null
  const weighted = signals.map(sig => ({
    label: sig,
    weight: SIGNAL_WEIGHTS[sig] ?? 15,
  }))
  const total = weighted.reduce((s, w) => s + w.weight, 0)
  return (
    <div className="mt-2 space-y-1.5 bg-[#080c14]/40 rounded-lg p-3 border border-[#1e2d42]/50">
      <p className="text-[10px] text-[#5a6a7a] font-semibold uppercase tracking-wider mb-2">スコア内訳 (推定)</p>
      {weighted.map((w, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="text-xs text-orange-300 flex-1 truncate">{w.label}</span>
          <div className="w-20 h-1.5 bg-[#161f33] rounded-full overflow-hidden shrink-0">
            <div
              className="h-full bg-orange-500/70 rounded-full"
              style={{ width: `${(w.weight / total) * 100}%` }}
            />
          </div>
          <span className="text-[10px] text-[#5a6a7a] w-8 text-right">{Math.round((w.weight / total) * score)}</span>
        </div>
      ))}
      <div className="flex justify-between text-[10px] text-[#5a6a7a] pt-1 border-t border-[#1e2d42]/50 mt-1">
        <span>合計リスクスコア</span>
        <span className={`font-bold ${score >= 70 ? 'text-red-400' : score >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>{score}</span>
      </div>
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color, warn }: {
  label: string; value: number; icon: React.ElementType; color: string; warn?: boolean
}) {
  return (
    <div className={`bg-[#111827] rounded-xl border p-4 flex items-center gap-3 ${warn && value > 0 ? 'border-red-700' : 'border-[#1e2d42]'}`}>
      <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
        <Icon className="w-4.5 h-4.5 text-white" />
      </div>
      <div>
        <p className="text-xs text-[#8899aa]">{label}</p>
        <p className={`text-2xl font-bold ${warn && value > 0 ? 'text-red-400' : 'text-white'}`}>{value}</p>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────

export default function UEBAPage() {
  const [hours, setHours] = useState(168)
  const [expandedUser, setExpandedUser] = useState<string | null>(null)
  const [expandedEntity, setExpandedEntity] = useState<string | null>(null)
  const [userSearch, setUserSearch] = useState('')
  const [entitySearch, setEntitySearch] = useState('')

  const { data, isLoading } = useQuery<UEBASummary | null>({
    queryKey: ['ueba-summary', hours],
    queryFn: () => apiFetch<UEBASummary>(`/api/v1/ueba/summary?hours=${hours}`),
    refetchInterval: 120_000,
  })

  const { data: heatmapData } = useQuery<HeatmapData>({
    queryKey: ['ueba-heatmap', hours],
    queryFn: () =>
      apiFetch<HeatmapData>(`/api/v1/ueba/heatmap?hours=${hours}`),
    refetchInterval: 120_000,
  })

  const { data: usersData } = useQuery<{ users: UserAnomaly[] }>({
    queryKey: ['ueba-users', hours],
    queryFn: () =>
      // risk_trend を ['up','down','stable'] から無作為に選んでいました。
      // 利用者ごとのリスクが上がっているか下がっているかは、この画面で
      // 誰を先に見るかを決める値です。取れなかったときは取れなかったと
      // 扱い、傾向は付けません。
      apiFetch<{ users: UserAnomaly[] }>(`/api/v1/ueba/users?hours=${hours}`),
    refetchInterval: 120_000,
  })

  const s = data?.summary
  const filteredUsers = (data?.user_anomalies ?? []).filter(u =>
    !userSearch || u.username.toLowerCase().includes(userSearch.toLowerCase())
  )
  const filteredEntities = (data?.entity_anomalies ?? []).filter(e =>
    !entitySearch || e.hostname.toLowerCase().includes(entitySearch.toLowerCase())
  )

  // Merge risk trend from /ueba/users into user_anomalies
  const userTrendMap = new Map(
    (usersData?.users ?? []).map(u => [u.username, u.risk_trend])
  )

  const heatmap = heatmapData?.data ?? (USE_MOCK ? generateMockHeatmap() : [])
  const baselinePoints = USE_MOCK ? generateMockBaseline() : []
  const anomalyTypes = USE_MOCK ? generateMockAnomalyTypes() : []

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-violet-600 rounded-lg flex items-center justify-center">
            <Activity className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">UEBA — 行動分析</h1>
            <p className="text-sm text-[#8899aa]">User & Entity Behavior Analytics — 異常行動検知</p>
          </div>
        </div>
        <div className="flex gap-2">
          {TIME_RANGES.map(r => (
            <button
              key={r.hours}
              onClick={() => setHours(r.hours)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                hours === r.hours ? 'bg-violet-600 text-white' : 'bg-[#111827] text-[#8899aa] hover:bg-[#19253d]'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-20">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-violet-500" />
        </div>
      ) : (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="高リスクユーザー"     value={s?.high_risk_users ?? 0}    icon={UserX}     color="bg-[#e8002d]"    warn />
            <StatCard label="高リスクエンドポイント" value={s?.high_risk_entities ?? 0} icon={Server}    color="bg-orange-600" warn />
            <StatCard label="希少プロセス"          value={s?.rare_process_count ?? 0} icon={Cpu}       color="bg-yellow-600" />
            <StatCard label="新規ホスト"            value={s?.new_host_count ?? 0}     icon={Globe}     color="bg-[#1a6bff]" />
          </div>

          {/* ── NEW: Anomaly Heatmap + Anomaly Type Distribution ── */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* Anomaly Heatmap */}
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-[#1e2d42]">
                <Activity className="w-4 h-4 text-violet-400" />
                <h2 className="text-sm font-semibold text-white">異常ヒートマップ</h2>
                <span className="ml-auto text-xs text-[#5a6a7a]">曜日 × 時間帯</span>
              </div>
              <div className="p-5">
                <AnomalyHeatmap data={heatmap} />
              </div>
            </div>

            {/* Anomaly Type Distribution */}
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-[#1e2d42]">
                <BarChart2 className="w-4 h-4 text-blue-400" />
                <h2 className="text-sm font-semibold text-white">異常タイプ分布</h2>
                <span className="ml-auto text-xs text-[#5a6a7a]">件数</span>
              </div>
              <div className="p-5">
                <AnomalyTypeBar items={anomalyTypes} />
              </div>
            </div>
          </div>

          {/* ── NEW: Baseline Deviation Chart ── */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            <div className="flex items-center gap-2 px-5 py-4 border-b border-[#1e2d42]">
              <TrendingUp className="w-4 h-4 text-orange-400" />
              <h2 className="text-sm font-semibold text-white">ベースライン乖離チャート</h2>
              <span className="ml-auto text-xs text-[#5a6a7a]">過去7日間の実際の活動 vs ベースライン</span>
            </div>
            <div className="p-5">
              <BaselineDeviationChart points={baselinePoints} />
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* User anomalies — enhanced with trend arrow */}
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-[#1e2d42]">
                <Users className="w-4 h-4 text-violet-400" />
                <h2 className="text-sm font-semibold text-white">ユーザー異常行動</h2>
                <div className="ml-auto flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[#5a6a7a]" />
                    <input
                      type="text"
                      placeholder="ユーザー名..."
                      value={userSearch}
                      onChange={e => setUserSearch(e.target.value)}
                      className="pl-6 pr-2 py-1 bg-[#111827] border border-[#1e2d42] rounded-sm text-xs text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-violet-500 w-32"
                    />
                  </div>
                  <span className="text-xs text-[#5a6a7a]">{filteredUsers.length}件</span>
                </div>
              </div>
              {filteredUsers.length === 0 ? (
                <div className="py-10 text-center text-[#5a6a7a] text-sm">異常なユーザー行動は検出されていません</div>
              ) : (
                <div className="divide-y divide-[#1e2d42]/50">
                  {filteredUsers.map(u => (
                    <div key={u.username}>
                      <button
                        onClick={() => setExpandedUser(expandedUser === u.username ? null : u.username)}
                        className="w-full flex items-center gap-3 px-5 py-3 hover:bg-[#161f33]/30 text-left transition-colors"
                      >
                        <div className="w-7 h-7 bg-[#161f33] rounded-full flex items-center justify-center shrink-0">
                          <Users className="w-3.5 h-3.5 text-[#8899aa]" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <p className="text-sm text-white font-mono truncate">{u.username}</p>
                            {/* Trend arrow — from /ueba/users endpoint or mock */}
                            <TrendArrow trend={userTrendMap.get(u.username) ?? u.risk_trend} />
                          </div>
                          <p className="text-xs text-[#8899aa]">
                            {u.total_logins}回ログイン · 失敗{u.failed_logins}回 ({u.fail_rate.toFixed(0)}%) · {u.unique_hosts}台
                          </p>
                        </div>
                        <RiskBar score={u.risk_score} />
                        <RiskBadge score={u.risk_score} />
                        {expandedUser === u.username
                          ? <ChevronDown className="w-4 h-4 text-[#5a6a7a] shrink-0" />
                          : <ChevronRight className="w-4 h-4 text-[#5a6a7a] shrink-0" />}
                      </button>
                      {expandedUser === u.username && u.signals.length > 0 && (
                        <div className="px-5 pb-4">
                          <ScoreBreakdown signals={u.signals} score={u.risk_score} />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Entity anomalies */}
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-[#1e2d42]">
                <Monitor className="w-4 h-4 text-orange-400" />
                <h2 className="text-sm font-semibold text-white">エンドポイント異常行動</h2>
                <div className="ml-auto flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[#5a6a7a]" />
                    <input
                      type="text"
                      placeholder="ホスト名..."
                      value={entitySearch}
                      onChange={e => setEntitySearch(e.target.value)}
                      className="pl-6 pr-2 py-1 bg-[#111827] border border-[#1e2d42] rounded-sm text-xs text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-orange-500 w-32"
                    />
                  </div>
                  <span className="text-xs text-[#5a6a7a]">{filteredEntities.length}件</span>
                </div>
              </div>
              {filteredEntities.length === 0 ? (
                <div className="py-10 text-center text-[#5a6a7a] text-sm">異常なエンドポイント行動は検出されていません</div>
              ) : (
                <div className="divide-y divide-[#1e2d42]/50">
                  {filteredEntities.map(e => (
                    <div key={e.agent_id}>
                      <button
                        onClick={() => setExpandedEntity(expandedEntity === e.agent_id ? null : e.agent_id)}
                        className="w-full flex items-center gap-3 px-5 py-3 hover:bg-[#161f33]/30 text-left transition-colors"
                      >
                        <div className="w-7 h-7 bg-[#161f33] rounded-full flex items-center justify-center shrink-0">
                          <Monitor className="w-3.5 h-3.5 text-[#8899aa]" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-white truncate">{e.hostname}</p>
                          <p className="text-xs text-[#8899aa]">
                            アラート{e.alert_count} · 認証失敗{e.auth_fails} · 接続{e.net_conns}
                          </p>
                        </div>
                        <RiskBar score={e.risk_score} />
                        <RiskBadge score={e.risk_score} />
                        {expandedEntity === e.agent_id
                          ? <ChevronDown className="w-4 h-4 text-[#5a6a7a] shrink-0" />
                          : <ChevronRight className="w-4 h-4 text-[#5a6a7a] shrink-0" />}
                      </button>
                      {expandedEntity === e.agent_id && (
                        <div className="px-5 pb-4">
                          <ScoreBreakdown signals={e.signals} score={e.risk_score} />
                          <Link
                            href={`/endpoints/${e.agent_id}`}
                            className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 mt-2"
                          >
                            <ShieldAlert className="w-3 h-3" />
                            エンドポイント詳細を確認
                          </Link>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Rare processes */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            <div className="flex items-center gap-2 px-5 py-4 border-b border-[#1e2d42]">
              <Zap className="w-4 h-4 text-yellow-400" />
              <h2 className="text-sm font-semibold text-white">希少プロセス（1台のみで実行）</h2>
              <span className="ml-auto text-xs text-[#5a6a7a]">ベースライン外の実行ファイル</span>
            </div>
            {(data?.rare_processes ?? []).length === 0 ? (
              <div className="py-8 text-center text-[#5a6a7a] text-sm">希少プロセスは検出されていません</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa]">
                      <th className="px-4 py-3 text-left">実行ファイル</th>
                      <th className="px-4 py-3 text-left">ホスト</th>
                      <th className="px-4 py-3 text-left">初回検知</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data?.rare_processes ?? []).map((p, i) => (
                      <tr key={i} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/30">
                        <td className="px-4 py-2.5 font-mono text-xs text-yellow-300 max-w-xs truncate">
                          {p.image}
                        </td>
                        <td className="px-4 py-2.5">
                          <Link href={`/endpoints/${p.agent_id}`} className="text-blue-400 hover:text-blue-300 text-xs">
                            {p.hostname}
                          </Link>
                        </td>
                        <td className="px-4 py-2.5 text-[#8899aa] text-xs whitespace-nowrap">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {p.first_seen ? p.first_seen.slice(0, 19).replace('T', ' ') : '-'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* New hosts */}
          {(data?.new_hosts ?? []).length > 0 && (
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-[#1e2d42]">
                <Globe className="w-4 h-4 text-blue-400" />
                <h2 className="text-sm font-semibold text-white">新規エンドポイント</h2>
                <span className="ml-auto text-xs text-[#5a6a7a]">期間内に初めて登録されたホスト</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 p-4">
                {(data?.new_hosts ?? []).map(h => (
                  <Link
                    key={h.agent_id}
                    href={`/endpoints/${h.agent_id}`}
                    className="flex items-center gap-3 p-3 bg-[#161f33]/50 rounded-lg hover:bg-[#161f33] transition-colors"
                  >
                    <Monitor className="w-4 h-4 text-blue-400 shrink-0" />
                    <div className="min-w-0">
                      <p className="text-sm text-white truncate">{h.hostname}</p>
                      <p className="text-xs text-[#8899aa]">{h.os}</p>
                      <p className="text-xs text-[#5a6a7a] font-mono">
                        {h.first_seen ? h.first_seen.slice(0,10) : ''}
                      </p>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
