'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  BarChart3, Users, Clock, TrendingUp, TrendingDown,
  AlertTriangle, CheckCircle2, Target, ArrowUp, ArrowDown,
  Calendar, ChevronDown, Award, Shield, Activity,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

type Period = 'today' | 'week' | 'month' | 'custom'
type Tier = 'L1' | 'L2' | 'L3'
type Severity = 'critical' | 'high' | 'medium' | 'low'

interface Analyst {
  id: string
  name: string
  initials: string
  tier: Tier
  alerts_handled: number
  avg_triage_min: number
  escalation_rate: number
  fp_rate: number
  satisfaction: number
  current_workload: number
  color: string
}

interface ShiftUtilization {
  shift: string
  mon: number; tue: number; wed: number; thu: number; fri: number; sat: number; sun: number
}

interface AlertFunnel {
  total: number
  triaged: number
  escalated: number
  incidents: number
  resolved: number
}

interface AlertAgeBucket {
  label: string
  count: number
}

interface AlertCategory {
  name: string
  avg_triage_min: number
  volume: number
  escalation_rate: number
}

interface MttrEntry {
  severity: Severity
  current_min: number
  target_min: number
  last_month_min: number
}

interface OpenIncident {
  id: string
  title: string
  severity: Severity
  age_hours: number
  assigned_to: string
}

interface ResolutionMethod {
  label: string
  value: number
  color: string
}

interface SocMetricsData {
  analysts: Analyst[]
  funnel: AlertFunnel
  age_buckets: AlertAgeBucket[]
  sla_compliance: number
  categories: AlertCategory[]
  mttr: MttrEntry[]
  open_incidents: OpenIncident[]
  resolution_methods: ResolutionMethod[]
}

// ── Mock Data ──────────────────────────────────────────────────────────────

const MOCK_ANALYSTS: Analyst[] = [
  { id: 'a1', name: '田中 健一', initials: 'TK', tier: 'L3', alerts_handled: 342, avg_triage_min: 4.2, escalation_rate: 8.3, fp_rate: 2.1, satisfaction: 4.8, current_workload: 7, color: '#e8002d' },
  { id: 'a2', name: '鈴木 美咲', initials: 'SM', tier: 'L2', alerts_handled: 287, avg_triage_min: 6.8, escalation_rate: 14.2, fp_rate: 5.4, satisfaction: 4.6, current_workload: 12, color: '#3b82f6' },
  { id: 'a3', name: '佐藤 隆', initials: 'SR', tier: 'L3', alerts_handled: 265, avg_triage_min: 5.1, escalation_rate: 9.7, fp_rate: 3.2, satisfaction: 4.7, current_workload: 5, color: '#10b981' },
  { id: 'a4', name: '山本 恵子', initials: 'YK', tier: 'L2', alerts_handled: 231, avg_triage_min: 8.3, escalation_rate: 18.5, fp_rate: 7.1, satisfaction: 4.2, current_workload: 18, color: '#f59e0b' },
  { id: 'a5', name: '伊藤 大介', initials: 'ID', tier: 'L1', alerts_handled: 198, avg_triage_min: 12.1, escalation_rate: 28.4, fp_rate: 11.3, satisfaction: 3.9, current_workload: 22, color: '#8b5cf6' },
  { id: 'a6', name: '中村 さや', initials: 'NS', tier: 'L1', alerts_handled: 175, avg_triage_min: 14.7, escalation_rate: 32.1, fp_rate: 14.2, satisfaction: 3.7, current_workload: 25, color: '#06b6d4' },
  { id: 'a7', name: '小林 直人', initials: 'KN', tier: 'L2', alerts_handled: 156, avg_triage_min: 9.2, escalation_rate: 21.3, fp_rate: 8.6, satisfaction: 4.1, current_workload: 15, color: '#f97316' },
  { id: 'a8', name: '加藤 雅子', initials: 'KM', tier: 'L1', alerts_handled: 134, avg_triage_min: 16.5, escalation_rate: 35.7, fp_rate: 16.8, satisfaction: 3.5, current_workload: 28, color: '#ec4899' },
]

const MOCK_SHIFT_UTIL: ShiftUtilization[] = [
  { shift: '朝番 (06-14)', mon: 87, tue: 91, wed: 85, thu: 89, fri: 92, sat: 65, sun: 58 },
  { shift: '昼番 (14-22)', mon: 94, tue: 96, wed: 98, thu: 95, fri: 91, sat: 72, sun: 63 },
  { shift: '夜番 (22-06)', mon: 71, tue: 68, wed: 75, thu: 73, fri: 70, sat: 55, sun: 48 },
]

const MOCK_FUNNEL: AlertFunnel = {
  total: 18_742, triaged: 14_893, escalated: 2_134, incidents: 876, resolved: 831,
}

const MOCK_AGE_BUCKETS: AlertAgeBucket[] = [
  { label: '0-1時間', count: 1243 },
  { label: '1-4時間', count: 876 },
  { label: '4-8時間', count: 432 },
  { label: '8-24時間', count: 287 },
  { label: '24時間以上', count: 143 },
]

const MOCK_CATEGORIES: AlertCategory[] = [
  { name: 'マルウェア検知', avg_triage_min: 5.2, volume: 4231, escalation_rate: 12.3 },
  { name: 'フィッシング', avg_triage_min: 3.8, volume: 3876, escalation_rate: 8.7 },
  { name: '不審なプロセス', avg_triage_min: 7.4, volume: 2943, escalation_rate: 21.4 },
  { name: 'ネットワーク異常', avg_triage_min: 9.1, volume: 2187, escalation_rate: 15.6 },
  { name: '認証失敗', avg_triage_min: 2.9, volume: 1954, escalation_rate: 5.2 },
  { name: 'データ漏洩', avg_triage_min: 11.3, volume: 876, escalation_rate: 34.7 },
  { name: '特権昇格', avg_triage_min: 8.7, volume: 654, escalation_rate: 28.9 },
  { name: 'ランサムウェア', avg_triage_min: 2.1, volume: 89, escalation_rate: 91.0 },
]

const MOCK_MTTR: MttrEntry[] = [
  { severity: 'critical', current_min: 47, target_min: 60, last_month_min: 52 },
  { severity: 'high', current_min: 183, target_min: 240, last_month_min: 198 },
  { severity: 'medium', current_min: 612, target_min: 480, last_month_min: 574 },
  { severity: 'low', current_min: 2340, target_min: 2880, last_month_min: 2567 },
]

const MOCK_OPEN_INCIDENTS: OpenIncident[] = [
  { id: 'INC-1042', title: 'APT攻撃 — 製造部門のサーバー侵害の疑い', severity: 'critical', age_hours: 72, assigned_to: '田中 健一' },
  { id: 'INC-1039', title: 'ランサムウェア感染 — 経理部門ファイルサーバー', severity: 'critical', age_hours: 96, assigned_to: '佐藤 隆' },
  { id: 'INC-1035', title: '内部からの大量データ転送', severity: 'high', age_hours: 128, assigned_to: '鈴木 美咲' },
  { id: 'INC-1031', title: 'VPN異常アクセス — 海外IPからの不審ログイン', severity: 'high', age_hours: 145, assigned_to: '山本 恵子' },
  { id: 'INC-1028', title: 'Active Directory特権昇格の疑い', severity: 'high', age_hours: 167, assigned_to: '小林 直人' },
]

const RESOLUTION_METHODS = [
  { label: '自動解決', value: 42, color: '#10b981' },
  { label: 'アナリスト対応', value: 31, color: '#3b82f6' },
  { label: 'エスカレーション', value: 15, color: '#f59e0b' },
  { label: '誤検知', value: 12, color: '#6b7280' },
]

// ── Helpers ────────────────────────────────────────────────────────────────

function severityColor(s: Severity): string {
  switch (s) {
    case 'critical': return '#e8002d'
    case 'high': return '#f97316'
    case 'medium': return '#eab308'
    case 'low': return '#22c55e'
  }
}

function severityLabel(s: Severity): string {
  return { critical: 'クリティカル', high: '高', medium: '中', low: '低' }[s]
}

function tierBadge(t: Tier): string {
  return { L1: 'bg-blue-900/30 text-blue-300', L2: 'bg-purple-900/30 text-purple-300', L3: 'bg-orange-900/30 text-orange-300' }[t]
}

function utilizationColor(v: number): string {
  if (v >= 90) return '#e8002d'
  if (v >= 75) return '#f97316'
  if (v >= 50) return '#10b981'
  return '#7d92b0'
}

function formatMinutes(min: number): string {
  if (min < 60) return `${min}分`
  const h = Math.floor(min / 60)
  const m = min % 60
  return m > 0 ? `${h}時間${m}分` : `${h}時間`
}

function ageColor(hours: number): string {
  if (hours > 120) return 'text-red-400'
  if (hours > 72) return 'text-orange-400'
  if (hours > 24) return 'text-yellow-400'
  return 'text-green-400'
}

// ── Sub-components ─────────────────────────────────────────────────────────

function SectionHeader({ title, icon: Icon, children }: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children?: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2">
        <Icon className="w-4 h-4 text-[#e8002d]" />
        <h2 className="text-white font-semibold text-base">{title}</h2>
      </div>
      {children}
    </div>
  )
}

function AlertFunnelViz({ funnel }: { funnel: AlertFunnel }) {
  const steps = [
    { label: '総アラート', value: funnel.total, color: '#3b82f6', pct: 100 },
    { label: 'トリアージ済み', value: funnel.triaged, color: '#8b5cf6', pct: Math.round((funnel.triaged / funnel.total) * 100) },
    { label: 'エスカレーション', value: funnel.escalated, color: '#f59e0b', pct: Math.round((funnel.escalated / funnel.total) * 100) },
    { label: 'インシデント化', value: funnel.incidents, color: '#f97316', pct: Math.round((funnel.incidents / funnel.total) * 100) },
    { label: '解決済み', value: funnel.resolved, color: '#10b981', pct: Math.round((funnel.resolved / funnel.total) * 100) },
  ]
  return (
    <div className="space-y-1.5">
      {steps.map((step, i) => (
        <div key={step.label} className="flex items-center gap-3">
          <div className="w-28 text-right text-xs text-[#7d92b0] shrink-0">{step.label}</div>
          <div
            className="h-8 rounded-sm flex items-center px-3 transition-all"
            style={{ width: `${Math.max(step.pct, 5)}%`, backgroundColor: step.color + '33', borderLeft: `3px solid ${step.color}` }}
          >
            <span className="text-white text-sm font-bold">{(step.value ?? 0).toLocaleString()}</span>
          </div>
          <span className="text-[#7d92b0] text-xs shrink-0">{step.pct}%</span>
          {i > 0 && (
            <span className="text-[#7d92b0] text-xs">
              (前段比 {Math.round((step.value / steps[i-1].value) * 100)}%)
            </span>
          )}
        </div>
      ))}
    </div>
  )
}

function SlaGauge({ value }: { value: number }) {
  const isGood = value >= 90
  const isMed = value >= 70
  const color = isGood ? '#10b981' : isMed ? '#f59e0b' : '#e8002d'
  const circumference = 2 * Math.PI * 40
  const dashOffset = circumference * (1 - value / 100)
  return (
    <div className="flex flex-col items-center justify-center py-4">
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#1e2d42" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="40" fill="none"
            stroke={color} strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-white font-bold text-2xl">{value}%</span>
        </div>
      </div>
      <p className="text-white font-medium mt-2">1時間以内対応率</p>
      <p className="text-xs mt-1" style={{ color }}>
        {isGood ? '目標達成 ✓' : isMed ? '要改善' : '目標未達成'}
      </p>
      <p className="text-[#7d92b0] text-xs mt-0.5">目標: 90%</p>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function SocMetricsPage() {
  const [period, setPeriod] = useState<Period>('month')
  const [activeTab, setActiveTab] = useState<0 | 1 | 2>(0)

  const { data } = useQuery<SocMetricsData>({
    queryKey: ['soc-metrics', period],
    queryFn: () => apiFetch(`/api/v1/soc/metrics?period=${period}`),
    retry: 0,
  })

  const analysts = data?.analysts ?? []
  const funnel = data?.funnel ?? { total: 0, triaged: 0, escalated: 0, incidents: 0, resolved: 0 }
  const ageBuckets = data?.age_buckets ?? []
  const slaCompliance = data?.sla_compliance ?? 0
  const categories = data?.categories ?? []
  const mttr = data?.mttr ?? []
  const openIncidents = data?.open_incidents ?? []
  const resolutionMethods = data?.resolution_methods ?? []

  const maxWorkload = analysts.length > 0 ? Math.max(...analysts.map(a => a.current_workload)) : 1
  const maxAgeBucket = ageBuckets.length > 0 ? Math.max(...ageBuckets.map(b => b.count)) : 1

  const tabs = ['アナリスト効率', 'アラート処理', 'インシデント対応']

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center">
            <BarChart3 className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">SOC効率指標</h1>
            <p className="text-[#7d92b0] text-sm">アナリスト・アラート・インシデントのパフォーマンス分析</p>
          </div>
        </div>

        {/* Period Selector */}
        <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1">
          {([
            { value: 'today', label: '本日' },
            { value: 'week', label: '今週' },
            { value: 'month', label: '今月' },
            { value: 'custom', label: 'カスタム' },
          ] as { value: Period; label: string }[]).map(p => (
            <button
              key={p.value}
              onClick={() => setPeriod(p.value)}
              className={`px-4 py-1.5 rounded-sm text-sm font-medium transition-colors ${
                period === p.value
                  ? 'bg-[#e8002d] text-white'
                  : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Summary KPI Cards ── */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-sm mb-1">総アラート処理数</p>
          <p className="text-white font-bold text-2xl">{analysts.reduce((s, a) => s + a.alerts_handled, 0).toLocaleString()}</p>
          <p className="text-green-400 text-xs mt-1 flex items-center gap-1"><ArrowUp className="w-3 h-3" />先月比 +8.2%</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-sm mb-1">平均トリアージ時間</p>
          <p className="text-white font-bold text-2xl">8.5分</p>
          <p className="text-green-400 text-xs mt-1 flex items-center gap-1"><ArrowDown className="w-3 h-3" />先月比 -1.2分</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-sm mb-1">SLA達成率</p>
          <p className="text-white font-bold text-2xl">87.3%</p>
          <p className="text-orange-400 text-xs mt-1">目標: 90%</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-sm mb-1">誤検知率</p>
          <p className="text-white font-bold text-2xl">7.8%</p>
          <p className="text-green-400 text-xs mt-1 flex items-center gap-1"><ArrowDown className="w-3 h-3" />先月比 -1.1pt</p>
        </div>
      </div>

      {/* ── Tabs ── */}
      <div className="flex gap-0 border-b border-[#1e2d42]">
        {tabs.map((tab, i) => (
          <button
            key={tab}
            onClick={() => setActiveTab(i as 0 | 1 | 2)}
            className={`px-6 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === i
                ? 'border-[#e8002d] text-white'
                : 'border-transparent text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* ── Tab 0: アナリスト効率 ── */}
      {activeTab === 0 && (
        <div className="space-y-6">

          {/* Leaderboard */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg">
            <div className="px-4 py-3 border-b border-[#1e2d42]">
              <SectionHeader title="アナリストリーダーボード" icon={Award} />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">順位</th>
                    <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">アナリスト</th>
                    <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">Tier</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">処理件数</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">平均時間</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">EscRate</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">FP率</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">CSAT</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">現在</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {analysts.map((analyst, idx) => (
                    <tr key={analyst.id} className="hover:bg-[#1e2d42]/30 transition-colors">
                      <td className="px-4 py-2.5">
                        <span className={`font-bold text-sm ${idx === 0 ? 'text-yellow-400' : idx === 1 ? 'text-[#94a3b8]' : idx === 2 ? 'text-orange-400' : 'text-[#7d92b0]'}`}>
                          #{idx + 1}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <div
                            className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white shrink-0"
                            style={{ backgroundColor: analyst.color }}
                          >
                            {analyst.initials}
                          </div>
                          <span className="text-white font-medium">{analyst.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`px-2 py-0.5 rounded-sm text-xs font-bold ${tierBadge(analyst.tier)}`}>
                          {analyst.tier}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right text-white font-mono">{analyst.alerts_handled}</td>
                      <td className="px-4 py-2.5 text-right">
                        <span className={`font-mono ${analyst.avg_triage_min <= 6 ? 'text-green-400' : analyst.avg_triage_min <= 10 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {analyst.avg_triage_min}分
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <span className={`font-mono ${analyst.escalation_rate <= 15 ? 'text-green-400' : analyst.escalation_rate <= 25 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {analyst.escalation_rate}%
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <span className={`font-mono ${analyst.fp_rate <= 5 ? 'text-green-400' : analyst.fp_rate <= 10 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {analyst.fp_rate}%
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <span className="text-yellow-400">★</span>
                          <span className="text-white font-medium">{analyst.satisfaction}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <span className={`font-mono font-bold ${analyst.current_workload >= 20 ? 'text-red-400' : analyst.current_workload >= 12 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {analyst.current_workload}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Workload Distribution */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <SectionHeader title="現在のワークロード分布" icon={Activity} />
            <div className="space-y-3">
              {analysts.map(analyst => (
                <div key={analyst.id} className="flex items-center gap-3">
                  <div className="w-24 text-sm text-[#7d92b0] truncate shrink-0">{analyst.name.split(' ')[0]}</div>
                  <div className="flex-1 h-5 bg-[#1e2d42] rounded-sm overflow-hidden">
                    <div
                      className="h-full rounded-sm transition-all duration-500 flex items-center px-2"
                      style={{
                        width: `${(analyst.current_workload / maxWorkload) * 100}%`,
                        backgroundColor: analyst.current_workload >= 20 ? '#e8002d33' : analyst.current_workload >= 12 ? '#f59e0b33' : '#10b98133',
                        borderLeft: `3px solid ${analyst.current_workload >= 20 ? '#e8002d' : analyst.current_workload >= 12 ? '#f59e0b' : '#10b981'}`,
                      }}
                    >
                      <span className="text-white text-xs font-bold">{analyst.current_workload}</span>
                    </div>
                  </div>
                  <span className={`text-xs font-medium w-14 text-right shrink-0 ${analyst.current_workload >= 20 ? 'text-red-400' : analyst.current_workload >= 12 ? 'text-yellow-400' : 'text-green-400'}`}>
                    {analyst.current_workload >= 20 ? '過負荷' : analyst.current_workload >= 12 ? '高負荷' : '正常'}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Shift Utilization */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <SectionHeader title="シフト稼働率" icon={Calendar} />
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left text-[#7d92b0] font-medium px-3 py-2">シフト</th>
                    {['月', '火', '水', '木', '金', '土', '日'].map(d => (
                      <th key={d} className="text-center text-[#7d92b0] font-medium px-3 py-2">{d}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  <tr>
                    <td colSpan={8} className="px-4 py-6 text-center text-[#7d92b0] text-sm">
                      シフトデータがありません
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab 1: アラート処理 ── */}
      {activeTab === 1 && (
        <div className="space-y-6">
          {/* Funnel + SLA */}
          <div className="grid grid-cols-3 gap-4">
            <div className="col-span-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <SectionHeader title="アラート処理ファネル" icon={TrendingDown} />
              <AlertFunnelViz funnel={funnel} />
            </div>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <SlaGauge value={slaCompliance} />
            </div>
          </div>

          {/* Alert Age Distribution */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <SectionHeader title="アラート経過時間分布" icon={Clock} />
            <div className="space-y-3">
              {ageBuckets.map(bucket => (
                <div key={bucket.label} className="flex items-center gap-3">
                  <div className="w-24 text-sm text-[#7d92b0] shrink-0">{bucket.label}</div>
                  <div className="flex-1 h-7 bg-[#1e2d42] rounded-sm overflow-hidden">
                    <div
                      className="h-full rounded-sm flex items-center px-3 transition-all duration-500"
                      style={{
                        width: `${(bucket.count / maxAgeBucket) * 100}%`,
                        backgroundColor: bucket.label.includes('24時間') ? '#e8002d33' : '#3b82f633',
                        borderLeft: `3px solid ${bucket.label.includes('24時間') ? '#e8002d' : '#3b82f6'}`,
                      }}
                    >
                      <span className="text-white text-sm font-medium">{(bucket.count ?? 0).toLocaleString()}</span>
                    </div>
                  </div>
                  <span className="text-[#7d92b0] text-xs w-16 text-right shrink-0">
                    {Math.round((bucket.count / ageBuckets.reduce((s, b) => s + b.count, 0)) * 100)}%
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Category Breakdown */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg">
            <div className="px-4 py-3 border-b border-[#1e2d42]">
              <SectionHeader title="カテゴリ別分析" icon={BarChart3} />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">カテゴリ</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">件数</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">平均時間</th>
                    <th className="text-right text-[#7d92b0] font-medium px-4 py-2.5">Esc率</th>
                    <th className="text-left text-[#7d92b0] font-medium px-4 py-2.5">件数分布</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {categories.map(cat => {
                    const maxVol = Math.max(...categories.map(c => c.volume))
                    return (
                      <tr key={cat.name} className="hover:bg-[#1e2d42]/30 transition-colors">
                        <td className="px-4 py-2.5 text-white font-medium">{cat.name}</td>
                        <td className="px-4 py-2.5 text-right text-white font-mono">{(cat.volume ?? 0).toLocaleString()}</td>
                        <td className="px-4 py-2.5 text-right">
                          <span className={cat.avg_triage_min <= 5 ? 'text-green-400' : cat.avg_triage_min <= 10 ? 'text-yellow-400' : 'text-red-400'}>
                            {cat.avg_triage_min}分
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-right">
                          <span className={cat.escalation_rate <= 15 ? 'text-green-400' : cat.escalation_rate <= 30 ? 'text-yellow-400' : 'text-red-400'}>
                            {cat.escalation_rate}%
                          </span>
                        </td>
                        <td className="px-4 py-2.5">
                          <div className="w-32 h-3 bg-[#1e2d42] rounded-sm overflow-hidden">
                            <div
                              className="h-full rounded-sm bg-[#3b82f6]/60"
                              style={{ width: `${(cat.volume / maxVol) * 100}%` }}
                            />
                          </div>
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

      {/* ── Tab 2: インシデント対応 ── */}
      {activeTab === 2 && (
        <div className="space-y-6">

          {/* MTTR Cards */}
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Clock className="w-4 h-4 text-[#e8002d]" />
              <h2 className="text-white font-semibold">深刻度別 MTTR (平均解決時間)</h2>
            </div>
            <div className="grid grid-cols-4 gap-4">
              {mttr.map(entry => {
                const isGood = entry.current_min <= entry.target_min
                const improved = entry.current_min < entry.last_month_min
                return (
                  <div key={entry.severity} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span
                        className="px-2 py-0.5 rounded-sm text-xs font-bold"
                        style={{ backgroundColor: severityColor(entry.severity) + '22', color: severityColor(entry.severity) }}
                      >
                        {severityLabel(entry.severity)}
                      </span>
                      {improved
                        ? <ArrowDown className="w-3.5 h-3.5 text-green-400" />
                        : <ArrowUp className="w-3.5 h-3.5 text-red-400" />
                      }
                    </div>
                    <p className={`text-2xl font-bold ${isGood ? 'text-green-400' : 'text-orange-400'}`}>
                      {formatMinutes(entry.current_min)}
                    </p>
                    <div className="mt-2 space-y-0.5 text-xs">
                      <div className="flex justify-between">
                        <span className="text-[#7d92b0]">目標</span>
                        <span className="text-[#7d92b0]">{formatMinutes(entry.target_min)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[#7d92b0]">先月</span>
                        <span className="text-[#7d92b0]">{formatMinutes(entry.last_month_min)}</span>
                      </div>
                    </div>
                    {/* Progress bar vs target */}
                    <div className="mt-2 h-1.5 bg-[#1e2d42] rounded-sm overflow-hidden">
                      <div
                        className="h-full rounded-sm transition-all"
                        style={{
                          width: `${Math.min(100, (entry.target_min / entry.current_min) * 100)}%`,
                          backgroundColor: isGood ? '#10b981' : '#f97316',
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Resolution Methods + Open Incidents */}
          <div className="grid grid-cols-2 gap-4">

            {/* Resolution Methods */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <SectionHeader title="解決方法の内訳" icon={CheckCircle2} />
              {resolutionMethods.length === 0 ? (
                <p className="text-[#7d92b0] text-sm py-4 text-center">データがありません</p>
              ) : (
              <div className="space-y-3">
                {resolutionMethods.map(method => (
                  <div key={method.label}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-[#7d92b0]">{method.label}</span>
                      <span className="text-white font-medium">{method.value}%</span>
                    </div>
                    <div className="h-4 bg-[#1e2d42] rounded-sm overflow-hidden">
                      <div
                        className="h-full rounded-sm transition-all duration-700"
                        style={{ width: `${method.value}%`, backgroundColor: method.color + '88', borderRight: `2px solid ${method.color}` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
              )}
              <div className="mt-4 grid grid-cols-2 gap-2">
                {resolutionMethods.map(m => (
                  <div key={m.label} className="flex items-center gap-2 text-xs">
                    <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: m.color }} />
                    <span className="text-[#7d92b0]">{m.label}</span>
                    <span className="text-white font-bold ml-auto">{m.value}%</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Open Incident Aging */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <SectionHeader title="オープンインシデント (経過時間)" icon={AlertTriangle} />
              <div className="space-y-2">
                {openIncidents.map(inc => (
                  <div
                    key={inc.id}
                    className="flex items-start gap-3 p-2.5 rounded-lg bg-[#070d19] border border-[#1e2d42] hover:border-[#7d92b0]/30 transition-colors"
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[#7d92b0] text-xs font-mono">{inc.id}</span>
                        <span
                          className="px-1.5 py-0.5 rounded-sm text-[10px] font-bold"
                          style={{ backgroundColor: severityColor(inc.severity) + '22', color: severityColor(inc.severity) }}
                        >
                          {severityLabel(inc.severity)}
                        </span>
                      </div>
                      <p className="text-white text-sm font-medium leading-snug">{inc.title}</p>
                      <p className="text-[#7d92b0] text-xs mt-1">{displayUser(inc.assigned_to)}</p>
                    </div>
                    <div className="ml-auto shrink-0 text-right">
                      <span className={`text-sm font-bold ${ageColor(inc.age_hours)}`}>
                        {inc.age_hours >= 24 ? `${Math.floor(inc.age_hours / 24)}日` : `${inc.age_hours}時間`}
                      </span>
                      <p className="text-[#7d92b0] text-[10px]">経過</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Trend sparklines summary */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <SectionHeader title="インシデント対応トレンド (過去30日)" icon={TrendingUp} />
            <div className="grid grid-cols-3 gap-6">
              {[
                { label: 'MTTR改善率', value: '-12.3%', positive: true, desc: '全深刻度平均' },
                { label: 'SLA達成率', value: '87.3%', positive: false, desc: '目標: 90%' },
                { label: 'エスカレーション率', value: '11.4%', positive: true, desc: '先月比 -2.1pt' },
              ].map(stat => (
                <div key={stat.label} className="text-center py-4 border border-[#1e2d42] rounded-lg">
                  <p className="text-[#7d92b0] text-sm mb-2">{stat.label}</p>
                  <p className={`text-2xl font-bold ${stat.positive ? 'text-green-400' : 'text-orange-400'}`}>{stat.value}</p>
                  <p className="text-[#7d92b0] text-xs mt-1">{stat.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
