'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Clock, AlertTriangle, CheckCircle, XCircle,
  TrendingUp, Users, Filter, ChevronDown,
  Save, Settings,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface SLAStats {
  achievement_rate: number
  breached_today: number
  at_risk: number
  avg_response_time: string
}

interface PriorityRow {
  priority: 'critical' | 'high' | 'medium' | 'low'
  sla_hours: number
  tickets_week: number
  met: number
  breached: number
  achievement_pct: number
  avg_actual: string
}

interface DayBar {
  date: string
  met: number
  breached: number
}

interface BreachReason {
  reason: string
  count: number
  pct: number
  color: string
}

interface SLATicket {
  id: string
  title: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  created_at: string
  sla_due: string
  time_remaining_min: number
  status: string
  assignee: string
}

interface SLAConfig {
  critical_hours: number
  high_hours: number
  medium_hours: number
  low_hours: number
  business_hours_only: boolean
  escalate_75: boolean
  escalate_90: boolean
  escalate_breach: boolean
}

interface SLAData {
  stats: SLAStats
  priority_breakdown: PriorityRow[]
  daily_bars: DayBar[]
  breach_reasons: BreachReason[]
  tickets: SLATicket[]
  config: SLAConfig
}

// ─── Mock Data ─────────────────────────────────────────────────────────────

const now = Date.now()
const mkDue = (minutesFromNow: number) =>
  new Date(now + minutesFromNow * 60 * 1000).toISOString()

const MOCK_DATA: SLAData = {
  stats: {
    achievement_rate: 91.4,
    breached_today: 3,
    at_risk: 5,
    avg_response_time: '3時間28分',
  },
  priority_breakdown: [
    { priority: 'critical', sla_hours: 4,  tickets_week: 8,  met: 7,  breached: 1, achievement_pct: 87.5, avg_actual: '3.2時間' },
    { priority: 'high',     sla_hours: 8,  tickets_week: 22, met: 21, breached: 1, achievement_pct: 95.5, avg_actual: '6.1時間' },
    { priority: 'medium',   sla_hours: 24, tickets_week: 45, met: 41, breached: 4, achievement_pct: 91.1, avg_actual: '18.4時間' },
    { priority: 'low',      sla_hours: 72, tickets_week: 31, met: 29, breached: 2, achievement_pct: 93.5, avg_actual: '52.0時間' },
  ],
  daily_bars: Array.from({ length: 30 }, (_, i) => {
    const d = new Date()
    d.setDate(d.getDate() - (29 - i))
    const met = Math.floor(Math.random() * 10) + 5
    const breached = Math.random() < 0.3 ? Math.floor(Math.random() * 3) + 1 : 0
    return {
      date: d.toLocaleDateString('ja-JP', { month: 'numeric', day: 'numeric' }),
      met,
      breached,
    }
  }),
  breach_reasons: [
    { reason: 'スタッフ不足', count: 4, pct: 36, color: '#e8002d' },
    { reason: '複雑な調査', count: 3, pct: 27, color: '#ff9100' },
    { reason: '情報待ち', count: 3, pct: 27, color: '#ffd740' },
    { reason: 'その他', count: 1, pct: 10, color: '#7d92b0' },
  ],
  tickets: [
    { id: 'TK-1042', title: 'ランサムウェア感染疑い', priority: 'critical', created_at: new Date(now - 3*3600000).toISOString(), sla_due: mkDue(55), time_remaining_min: 55, status: 'in_progress', assignee: '田中 太郎' },
    { id: 'TK-1041', title: 'RDPブルートフォース攻撃', priority: 'critical', created_at: new Date(now - 2*3600000).toISOString(), sla_due: mkDue(110), time_remaining_min: 110, status: 'open', assignee: '未割り当て' },
    { id: 'TK-1040', title: '不審なPowerShell実行', priority: 'high', created_at: new Date(now - 5*3600000).toISOString(), sla_due: mkDue(-30), time_remaining_min: -30, status: 'open', assignee: '鈴木 花子' },
    { id: 'TK-1039', title: 'フィッシングメール大量受信', priority: 'high', created_at: new Date(now - 4*3600000).toISOString(), sla_due: mkDue(220), time_remaining_min: 220, status: 'in_progress', assignee: '山田 一郎' },
    { id: 'TK-1038', title: 'エンドポイントの異常通信', priority: 'medium', created_at: new Date(now - 20*3600000).toISOString(), sla_due: mkDue(240), time_remaining_min: 240, status: 'open', assignee: '佐藤 美咲' },
    { id: 'TK-1037', title: 'CVE-2024-1234 対応', priority: 'medium', created_at: new Date(now - 18*3600000).toISOString(), sla_due: mkDue(-120), time_remaining_min: -120, status: 'open', assignee: '田中 太郎' },
    { id: 'TK-1036', title: 'ゼロデイ脆弱性調査', priority: 'high', created_at: new Date(now - 6*3600000).toISOString(), sla_due: mkDue(80), time_remaining_min: 80, status: 'in_progress', assignee: '山田 一郎' },
    { id: 'TK-1035', title: 'IOCブロックリスト更新', priority: 'low', created_at: new Date(now - 48*3600000).toISOString(), sla_due: mkDue(1440), time_remaining_min: 1440, status: 'open', assignee: '鈴木 花子' },
    { id: 'TK-1034', title: 'コンプライアンス違反調査', priority: 'medium', created_at: new Date(now - 10*3600000).toISOString(), sla_due: mkDue(840), time_remaining_min: 840, status: 'open', assignee: '佐藤 美咲' },
    { id: 'TK-1033', title: 'アクセス権限レビュー', priority: 'low', created_at: new Date(now - 60*3600000).toISOString(), sla_due: mkDue(-300), time_remaining_min: -300, status: 'open', assignee: '未割り当て' },
    { id: 'TK-1032', title: 'ログ収集エラー対応', priority: 'medium', created_at: new Date(now - 8*3600000).toISOString(), sla_due: mkDue(960), time_remaining_min: 960, status: 'in_progress', assignee: '田中 太郎' },
    { id: 'TK-1031', title: 'エージェント更新計画', priority: 'low', created_at: new Date(now - 36*3600000).toISOString(), sla_due: mkDue(2880), time_remaining_min: 2880, status: 'open', assignee: '山田 一郎' },
  ],
  config: {
    critical_hours: 4,
    high_hours: 8,
    medium_hours: 24,
    low_hours: 72,
    business_hours_only: true,
    escalate_75: true,
    escalate_90: true,
    escalate_breach: true,
  },
}

const EMPTY_SLA_DATA: SLAData = {
  stats: { achievement_rate: 0, breached_today: 0, at_risk: 0, avg_response_time: '-' },
  priority_breakdown: [],
  daily_bars: [],
  breach_reasons: [],
  tickets: [],
  config: { critical_hours: 4, high_hours: 8, medium_hours: 24, low_hours: 72, business_hours_only: true, escalate_75: true, escalate_90: true, escalate_breach: true },
}

// ─── Helpers ─────────────────────────────────────────────────────────────

const PRIORITY_LABELS: Record<string, string> = {
  critical: 'クリティカル',
  high: '高',
  medium: '中',
  low: '低',
}
const PRIORITY_COLORS: Record<string, string> = {
  critical: '#e8002d',
  high: '#ff9100',
  medium: '#ffd740',
  low: '#69f0ae',
}

function timeRemainingColor(min: number, slaTotalMin: number) {
  if (min < 0) return 'text-[#7d92b0]'
  const pct = min / slaTotalMin
  if (pct > 0.5) return 'text-[#00c853]'
  if (pct > 0.2) return 'text-[#ffd740]'
  return 'text-[#e8002d]'
}

function formatRemaining(min: number): string {
  if (min < 0) return `超過 ${Math.abs(Math.floor(min / 60))}時間${Math.abs(min) % 60}分`
  const h = Math.floor(min / 60)
  const m = min % 60
  return h > 0 ? `${h}時間${m}分` : `${m}分`
}

function SemiCircleGauge({ pct, color, label }: { pct: number; color: string; label: string }) {
  const r = 50
  const cx = 65
  const cy = 65
  const startAngle = 180
  const endAngle = 0
  // Semi-circle: from left to right (180 -> 360 ie 0)
  const toRad = (d: number) => (d * Math.PI) / 180
  const bgStart = { x: cx + r * Math.cos(toRad(180)), y: cy + r * Math.sin(toRad(180)) }
  const bgEnd   = { x: cx + r * Math.cos(toRad(0)),   y: cy + r * Math.sin(toRad(0)) }
  const filledAngle = 180 - pct / 100 * 180
  const fillEnd = { x: cx + r * Math.cos(toRad(filledAngle)), y: cy + r * Math.sin(toRad(filledAngle)) }

  return (
    <svg viewBox="0 0 130 80" className="w-full" style={{ maxWidth: 130 }}>
      <path
        d={`M ${bgStart.x} ${bgStart.y} A ${r} ${r} 0 0 1 ${bgEnd.x} ${bgEnd.y}`}
        fill="none" stroke="#1e2d42" strokeWidth="10" strokeLinecap="round"
      />
      <path
        d={`M ${bgStart.x} ${bgStart.y} A ${r} ${r} 0 ${pct > 50 ? 1 : 0} 1 ${fillEnd.x} ${fillEnd.y}`}
        fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
        style={{ filter: `drop-shadow(0 0 4px ${color}80)` }}
      />
      <text x={cx} y={cy - 4} textAnchor="middle" fill="white" fontSize="16" fontWeight="bold">{pct}%</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="#7d92b0" fontSize="9">{label}</text>
    </svg>
  )
}

function BreachPieChart({ reasons }: { reasons: BreachReason[] }) {
  const total = reasons.reduce((s, r) => s + r.count, 0)
  const cx = 70
  const cy = 70
  const r = 50

  let angle = -90
  const slices = reasons.map(reason => {
    const sweep = (reason.count / total) * 360
    const start = angle
    angle += sweep
    return { ...reason, startAngle: start, sweep }
  })

  const toRad = (d: number) => (d * Math.PI) / 180
  const arc = (startDeg: number, sweep: number) => {
    const x1 = cx + r * Math.cos(toRad(startDeg))
    const y1 = cy + r * Math.sin(toRad(startDeg))
    const endDeg = startDeg + sweep
    const x2 = cx + r * Math.cos(toRad(endDeg))
    const y2 = cy + r * Math.sin(toRad(endDeg))
    const large = sweep > 180 ? 1 : 0
    return `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`
  }

  return (
    <div className="flex items-center gap-6">
      <svg viewBox="0 0 140 140" style={{ width: 120, height: 120, flexShrink: 0 }}>
        {slices.map(s => (
          <path key={s.reason} d={arc(s.startAngle, s.sweep)} fill={s.color} opacity="0.85" />
        ))}
        <circle cx={cx} cy={cy} r={28} fill="#0d1220" />
      </svg>
      <div className="space-y-1.5">
        {reasons.map(r => (
          <div key={r.reason} className="flex items-center gap-2 text-xs">
            <span className="w-2.5 h-2.5 rounded-xs shrink-0" style={{ background: r.color }} />
            <span className="text-[#7d92b0]">{r.reason}</span>
            <span className="text-white font-medium ml-auto pl-3">{r.pct}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function DailyBarChart({ bars }: { bars: DayBar[] }) {
  const maxVal = Math.max(...bars.map(b => b.met + b.breached), 1)
  const width = 700
  const height = 80
  const padL = 8
  const padR = 8
  const padT = 8
  const padB = 20
  if (bars.length === 0) return <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ height: 80 }} />
  const barW = (width - padL - padR) / bars.length - 1
  const toH = (v: number) => ((v / maxVal) * (height - padT - padB))
  const toX = (i: number) => padL + i * ((width - padL - padR) / bars.length)
  const tickIdx = [0, 6, 13, 20, 29]

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ height: 80 }}>
      {bars.map((b, i) => {
        const barH = toH(b.met + b.breached)
        const bH = toH(b.breached)
        const x = toX(i)
        const y = height - padB
        return (
          <g key={i}>
            <rect x={x} y={y - barH} width={barW} height={Math.max(barH - bH, 0)} fill="#00c853" opacity="0.7" rx="1" />
            {bH > 0 && (
              <rect x={x} y={y - bH} width={barW} height={bH} fill="#e8002d" opacity="0.8" rx="1" />
            )}
          </g>
        )
      })}
      {tickIdx.filter(i => i < bars.length).map(i => (
        <text key={i} x={toX(i) + barW / 2} y={height - 4} textAnchor="middle" fill="#7d92b0" fontSize="9">
          {bars[i].date}
        </text>
      ))}
    </svg>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────

export default function SLAPage() {
  const [tab, setTab] = useState<'overview' | 'tickets' | 'settings'>('overview')
  const [ticketFilter, setTicketFilter] = useState<'all' | 'breached' | 'at_risk' | 'on_track'>('all')
  const [priorityFilter, setPriorityFilter] = useState<string>('all')
  const [assigneeFilter, setAssigneeFilter] = useState<string>('all')
  const [config, setConfig] = useState<SLAConfig>(EMPTY_SLA_DATA.config)
  const [saveMsg, setSaveMsg] = useState('')

  const { data = EMPTY_SLA_DATA } = useQuery<SLAData>({
    queryKey: ['sla-data'],
    queryFn: () => apiFetch<SLAData>('/api/v1/soc/sla'),
    staleTime: 60_000,
  })

  const sla: SLAData = data ?? EMPTY_SLA_DATA

  // Filter tickets
  const filteredTickets = sla.tickets
    .filter(t => {
      if (ticketFilter === 'breached' && t.time_remaining_min >= 0) return false
      const slaTotalMin = sla.config[`${t.priority}_hours` as keyof SLAConfig] as number * 60
      if (ticketFilter === 'at_risk' && (t.time_remaining_min < 0 || t.time_remaining_min / slaTotalMin > 0.2)) return false
      if (ticketFilter === 'on_track' && (t.time_remaining_min < 0 || t.time_remaining_min / (slaTotalMin || 1) <= 0.2)) return false
      if (priorityFilter !== 'all' && t.priority !== priorityFilter) return false
      if (assigneeFilter !== 'all' && t.assignee !== assigneeFilter) return false
      return true
    })
    .sort((a, b) => a.time_remaining_min - b.time_remaining_min)

  const assignees = Array.from(new Set(sla.tickets.map(t => t.assignee)))

  const achieveColor = sla.stats.achievement_rate >= 90 ? 'text-[#00c853]' : 'text-[#ffd740]'

  function handleSave() {
    setSaveMsg('保存しました')
    setTimeout(() => setSaveMsg(''), 2500)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">SLA管理</h1>
        <p className="text-[#7d92b0] text-sm mt-1">インシデント・チケット対応のSLA達成状況</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 text-center">
          <div className={`text-4xl font-black ${achieveColor}`}>{sla.stats.achievement_rate}%</div>
          <div className="text-xs text-[#7d92b0] mt-1">SLA達成率</div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 text-center">
          <div className="text-4xl font-black text-[#e8002d]">{sla.stats.breached_today}</div>
          <div className="text-xs text-[#7d92b0] mt-1">本日の違反</div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 text-center">
          <div className="text-4xl font-black text-[#ffd740]">{sla.stats.at_risk}</div>
          <div className="text-xs text-[#7d92b0] mt-1">リスク件数 (&lt;1h)</div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 text-center">
          <div className="text-2xl font-black text-white">{sla.stats.avg_response_time}</div>
          <div className="text-xs text-[#7d92b0] mt-1">平均対応時間</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['overview', 'tickets', 'settings'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${
              tab === t
                ? 'bg-[#1e2d42] text-white'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {t === 'overview' ? 'SLA概要' : t === 'tickets' ? 'チケット別' : '設定'}
          </button>
        ))}
      </div>

      {/* ── Overview Tab ──────────────────────────────────────── */}
      {tab === 'overview' && (
        <div className="space-y-6">
          {/* Gauges per priority */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <h2 className="text-base font-semibold text-white mb-5">優先度別 SLA達成率</h2>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-6">
              {sla.priority_breakdown.map(row => (
                <div key={row.priority} className="flex flex-col items-center gap-1">
                  <SemiCircleGauge
                    pct={Math.round(row.achievement_pct)}
                    color={PRIORITY_COLORS[row.priority]}
                    label={PRIORITY_LABELS[row.priority]}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Priority breakdown table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <h2 className="text-base font-semibold text-white mb-4">優先度別内訳</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42]">
                    <th className="pb-2 text-left">優先度</th>
                    <th className="pb-2 text-center">SLA目標</th>
                    <th className="pb-2 text-center">今週チケット</th>
                    <th className="pb-2 text-center">達成</th>
                    <th className="pb-2 text-center">違反</th>
                    <th className="pb-2 text-center">達成率</th>
                    <th className="pb-2 text-center">平均実績</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {sla.priority_breakdown.map(row => (
                    <tr key={row.priority} className="hover:bg-[#0a1020]">
                      <td className="py-3">
                        <span
                          className="px-2 py-0.5 rounded-sm text-xs font-medium"
                          style={{ background: `${PRIORITY_COLORS[row.priority]}20`, color: PRIORITY_COLORS[row.priority] }}
                        >
                          {PRIORITY_LABELS[row.priority]}
                        </span>
                      </td>
                      <td className="py-3 text-center text-[#c8d6ea]">{row.sla_hours}時間</td>
                      <td className="py-3 text-center text-white">{row.tickets_week}</td>
                      <td className="py-3 text-center text-[#00c853]">{row.met}</td>
                      <td className="py-3 text-center text-[#e8002d]">{row.breached}</td>
                      <td className="py-3 text-center">
                        <span className={row.achievement_pct >= 90 ? 'text-[#00c853]' : 'text-[#ffd740]'}>
                          {row.achievement_pct.toFixed(1)}%
                        </span>
                      </td>
                      <td className="py-3 text-center text-[#c8d6ea]">{row.avg_actual}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Monthly trend */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white">過去30日 日別トレンド</h2>
              <div className="flex items-center gap-4 text-xs text-[#7d92b0]">
                <div className="flex items-center gap-1"><span className="w-3 h-2 rounded-sm bg-[#00c853] inline-block opacity-70" /> 達成</div>
                <div className="flex items-center gap-1"><span className="w-3 h-2 rounded-sm bg-[#e8002d] inline-block opacity-80" /> 違反</div>
              </div>
            </div>
            <DailyBarChart bars={sla.daily_bars} />
          </div>

          {/* Breach reasons */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <h2 className="text-base font-semibold text-white mb-4">違反理由内訳</h2>
            <BreachPieChart reasons={sla.breach_reasons} />
          </div>
        </div>
      )}

      {/* ── Tickets Tab ──────────────────────────────────────── */}
      {tab === 'tickets' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            {/* Status filter */}
            <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-sm p-1">
              {([['all', '全て'], ['breached', '違反'], ['at_risk', 'リスク'], ['on_track', '正常']] as const).map(([v, l]) => (
                <button
                  key={v}
                  onClick={() => setTicketFilter(v)}
                  className={`px-3 py-1 rounded-sm text-xs font-medium transition-colors ${ticketFilter === v ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
                >
                  {l}
                </button>
              ))}
            </div>

            {/* Priority filter */}
            <div className="relative">
              <select
                value={priorityFilter}
                onChange={e => setPriorityFilter(e.target.value)}
                className="appearance-none bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-xs text-[#c8d6ea] pr-7 cursor-pointer"
              >
                <option value="all">全優先度</option>
                {Object.entries(PRIORITY_LABELS).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
              <ChevronDown className="w-3 h-3 text-[#7d92b0] absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>

            {/* Assignee filter */}
            <div className="relative">
              <select
                value={assigneeFilter}
                onChange={e => setAssigneeFilter(e.target.value)}
                className="appearance-none bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-xs text-[#c8d6ea] pr-7 cursor-pointer"
              >
                <option value="all">全担当者</option>
                {assignees.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
              <ChevronDown className="w-3 h-3 text-[#7d92b0] absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>

            <span className="text-xs text-[#7d92b0] ml-auto">{filteredTickets.length}件</span>
          </div>

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0a1020]">
                    <th className="px-4 py-3 text-left">チケット#</th>
                    <th className="px-4 py-3 text-left">タイトル</th>
                    <th className="px-4 py-3 text-center">優先度</th>
                    <th className="px-4 py-3 text-center">作成日時</th>
                    <th className="px-4 py-3 text-center">SLA期限</th>
                    <th className="px-4 py-3 text-center">残り時間</th>
                    <th className="px-4 py-3 text-center">ステータス</th>
                    <th className="px-4 py-3 text-left">担当者</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filteredTickets.map(t => {
                    const slaTotalMin = (sla.config[`${t.priority}_hours` as keyof SLAConfig] as number) * 60
                    const remColor = timeRemainingColor(t.time_remaining_min, slaTotalMin)
                    return (
                      <tr key={t.id} className="hover:bg-[#0a1020] transition-colors">
                        <td className="px-4 py-3 text-[#e8002d] font-mono text-xs">{t.id}</td>
                        <td className="px-4 py-3 text-white max-w-[200px] truncate">{t.title}</td>
                        <td className="px-4 py-3 text-center">
                          <span
                            className="px-2 py-0.5 rounded-sm text-xs font-medium"
                            style={{ background: `${PRIORITY_COLORS[t.priority]}20`, color: PRIORITY_COLORS[t.priority] }}
                          >
                            {PRIORITY_LABELS[t.priority]}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center text-[#7d92b0] text-xs whitespace-nowrap">
                          {new Date(t.created_at).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                        </td>
                        <td className="px-4 py-3 text-center text-[#7d92b0] text-xs whitespace-nowrap">
                          {new Date(t.sla_due).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                        </td>
                        <td className={`px-4 py-3 text-center text-xs font-medium whitespace-nowrap ${remColor}`}>
                          {formatRemaining(t.time_remaining_min)}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className={`px-2 py-0.5 rounded-sm text-xs ${t.status === 'in_progress' ? 'bg-[#1e6ef440] text-[#60a5fa]' : 'bg-[#1e2d42] text-[#7d92b0]'}`}>
                            {t.status === 'in_progress' ? '対応中' : 'オープン'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[#c8d6ea] text-xs">{t.assignee}</td>
                      </tr>
                    )
                  })}
                  {filteredTickets.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-[#7d92b0] text-sm">
                        該当チケットはありません
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Settings Tab ──────────────────────────────────────── */}
      {tab === 'settings' && (
        <div className="space-y-6 max-w-2xl">
          {/* SLA Targets */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <h2 className="text-base font-semibold text-white mb-4">SLA目標時間設定</h2>
            <div className="space-y-4">
              {([ ['critical', 'クリティカル'], ['high', '高'], ['medium', '中'], ['low', '低'] ] as const).map(([key, label]) => (
                <div key={key} className="flex items-center gap-4">
                  <span
                    className="w-24 px-2 py-0.5 rounded-sm text-xs font-medium text-center shrink-0"
                    style={{ background: `${PRIORITY_COLORS[key]}20`, color: PRIORITY_COLORS[key] }}
                  >
                    {label}
                  </span>
                  <div className="flex items-center gap-2 flex-1">
                    <input
                      type="number"
                      value={config[`${key}_hours` as keyof SLAConfig] as number}
                      onChange={e => setConfig(prev => ({ ...prev, [`${key}_hours`]: Number(e.target.value) }))}
                      className="w-20 bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#e8002d]"
                      min={1}
                    />
                    <span className="text-[#7d92b0] text-sm">時間</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Business Hours */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <h2 className="text-base font-semibold text-white mb-4">ビジネス時間設定</h2>
            <label className="flex items-center gap-3 cursor-pointer">
              <div
                className={`w-10 h-5 rounded-full transition-colors relative ${config.business_hours_only ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
                onClick={() => setConfig(p => ({ ...p, business_hours_only: !p.business_hours_only }))}
              >
                <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-transform ${config.business_hours_only ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </div>
              <div>
                <div className="text-sm text-white">ビジネス時間のみでSLAをカウント</div>
                <div className="text-xs text-[#7d92b0]">月〜金 9:00〜18:00 (JST)</div>
              </div>
            </label>
          </div>

          {/* Escalation Rules */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <h2 className="text-base font-semibold text-white mb-4">エスカレーションルール</h2>
            <div className="space-y-3">
              {[
                { key: 'escalate_75', label: 'SLA 75% 消費時に自動エスカレーション' },
                { key: 'escalate_90', label: 'SLA 90% 消費時に自動エスカレーション' },
                { key: 'escalate_breach', label: 'SLA 違反時に自動エスカレーション' },
              ].map(({ key, label }) => (
                <label key={key} className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config[key as keyof SLAConfig] as boolean}
                    onChange={e => setConfig(p => ({ ...p, [key]: e.target.checked }))}
                    className="w-4 h-4 rounded-sm border-[#1e2d42] bg-[#070d19] accent-[#e8002d]"
                  />
                  <span className="text-sm text-[#c8d6ea]">{label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Save */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleSave}
              className="flex items-center gap-2 px-6 py-2.5 bg-[#e8002d] hover:bg-[#c0001e] rounded-lg text-white text-sm font-medium transition-colors"
            >
              <Save className="w-4 h-4" />
              保存する
            </button>
            {saveMsg && <span className="text-[#00c853] text-sm">{saveMsg}</span>}
          </div>
        </div>
      )}
    </div>
  )
}
