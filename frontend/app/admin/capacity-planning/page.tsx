'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  TrendingUp, Users, DollarSign, HardDrive, Server,
  AlertTriangle, CheckCircle, BarChart3, Calendar,
  Plus, Download, RefreshCw, Cpu, Wifi, Package, Settings,
} from 'lucide-react'
import AdminDrawer from './AdminDrawer'

// ── Types ──────────────────────────────────────────────────────────────────────

type AnalystRole = 'L1 Analyst' | 'L2 Analyst' | 'L3 Analyst' | 'Threat Hunter' | 'Incident Responder' | 'Engineer' | 'Manager' | 'Cloud Analyst'
type SkillName = 'DFIR' | 'Malware' | 'Network' | 'Cloud' | 'Compliance'
type SkillLevel = 'full' | 'partial' | 'none'

interface Analyst {
  id: string
  name: string
  role: AnalystRole
  skills: Record<SkillName, SkillLevel>
  alerts_handled_per_day: number
  hire_date: string
}

interface ToolLicense {
  id: string
  tool_name: string
  category: string
  purchased: number
  used: number
  price_per_unit: number
  renewal_date: string
}

interface StorageMetric {
  used_tb: number
  total_tb: number
  projected_6m_tb: number
  projected_12m_tb: number
}

interface BudgetCategory {
  label: string
  current_year: number
  next_year: number
  year3: number
}

interface PlannedHire {
  role: AnalystRole
  planned_quarter: string
  estimated_annual_cost: number
  priority: 'high' | 'medium' | 'low'
}

interface TechDebtItem {
  id: string
  title: string
  impact: string
  severity: 'high' | 'medium' | 'low'
}

const SKILLS: SkillName[] = ['DFIR', 'Malware', 'Network', 'Cloud', 'Compliance']

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtJPY(n: number): string {
  if (n >= 1_000_000_000) return `¥${(n / 1_000_000_000).toFixed(1)}B`
  if (n >= 1_000_000) return `¥${(n / 1_000_000).toFixed(0)}M`
  return `¥${n.toLocaleString()}`
}

function ScoreBar({ value, max = 100, color }: { value: number; max?: number; color?: string }) {
  const pct = Math.min((value / max) * 100, 100)
  const c = color ?? (pct >= 70 ? '#00c853' : pct >= 50 ? '#ffc107' : '#e8002d')
  return (
    <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: c }} />
    </div>
  )
}

function StatCard({ label, value, sub, icon: Icon, accent }: { label: string; value: string | number; sub?: string; icon: React.ElementType; accent?: string }) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-5 py-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[#7d92b0] text-xs">{label}</p>
          <p className={`text-2xl font-bold mt-1 ${accent ?? 'text-white'}`}>{value}</p>
          {sub && <p className="text-[#7d92b0] text-xs mt-0.5">{sub}</p>}
        </div>
        <div className="p-2 bg-[#e8002d]/10 border border-[#e8002d]/20 rounded-lg">
          <Icon className="w-4 h-4 text-[#e8002d]" />
        </div>
      </div>
    </div>
  )
}

const SKILL_COLORS: Record<SkillLevel, string> = {
  full: 'bg-green-500/30 text-green-300 border-green-500/30',
  partial: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/20',
  none: 'bg-[#1e2d42] text-[#3d5068] border-[#1e2d42]',
}
const SKILL_LABELS: Record<SkillLevel, string> = { full: '◎', partial: '△', none: '—' }

const PRIORITY_COLORS = { high: 'text-red-400', medium: 'text-yellow-400', low: 'text-green-400' }
const SEVERITY_COLORS = { high: 'bg-red-500/20 text-red-300 border-red-500/30', medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30', low: 'bg-green-500/20 text-green-300 border-green-500/30' }

const ROLE_COLORS: Record<AnalystRole, string> = {
  'L1 Analyst': 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  'L2 Analyst': 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  'L3 Analyst': 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  'Threat Hunter': 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  'Incident Responder': 'bg-red-500/20 text-red-300 border-red-500/30',
  'Engineer': 'bg-green-500/20 text-green-300 border-green-500/30',
  'Manager': 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  'Cloud Analyst': 'bg-sky-500/20 text-sky-300 border-sky-500/30',
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function CapacityPlanningPage() {
  const [tab, setTab] = useState<'workforce' | 'tech' | 'budget'>('workforce')
  const [alertGrowthPct, setAlertGrowthPct] = useState(20)
  const [showBudgetModal, setShowBudgetModal] = useState(false)
  const [showAdminDrawer, setShowAdminDrawer] = useState(false)

  const { data: overviewData } = useQuery({
    queryKey: ['capacity-planning-overview'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/overview'),
    retry: false,
    staleTime: 60_000,
  })

  const { data: workforceData } = useQuery({
    queryKey: ['capacity-planning-workforce'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/workforce'),
    retry: false,
    staleTime: 60_000,
  })

  const { data: resourcesData } = useQuery({
    queryKey: ['capacity-planning-resources'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/resources'),
    retry: false,
    staleTime: 60_000,
  })

  const { data: storageData } = useQuery({
    queryKey: ['capacity-planning-storage'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/storage').catch(() => null),
    retry: false, staleTime: 60_000,
  })
  const { data: budgetData } = useQuery({
    queryKey: ['capacity-planning-budget'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/budget').catch(() => null),
    retry: false, staleTime: 60_000,
  })
  const { data: plannedHiresData } = useQuery({
    queryKey: ['capacity-planning-planned-hires'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/planned-hires').catch(() => null),
    retry: false, staleTime: 60_000,
  })
  const { data: techDebtData } = useQuery({
    queryKey: ['capacity-planning-tech-debt'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/tech-debt').catch(() => null),
    retry: false, staleTime: 60_000,
  })
  const { data: oncallData } = useQuery({
    queryKey: ['capacity-planning-oncall'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/oncall-shifts').catch(() => null),
    retry: false, staleTime: 60_000,
  })
  const { data: roiData } = useQuery({
    queryKey: ['capacity-planning-roi'],
    queryFn: () => apiFetch('/api/v1/admin/capacity-planning/roi').catch(() => null),
    retry: false, staleTime: 60_000,
  })

  const analysts = ((workforceData as Analyst[]) ?? [])
  const licenses = ((resourcesData as ToolLicense[]) ?? [])
  const storage = (storageData as StorageMetric | null) ?? { used_tb: 0, total_tb: 1, projected_6m_tb: 0, projected_12m_tb: 0 }
  const budget = ((budgetData as BudgetCategory[]) ?? [])
  const plannedHires = ((plannedHiresData as PlannedHire[]) ?? [])
  const techDebt = ((techDebtData as TechDebtItem[]) ?? [])
  const oncallShifts = ((oncallData as { id: string; analyst: string; shift: string; start: string; end: string; mon: string; tue: string; wed: string; thu: string; fri: string; sat: string; sun: string }[]) ?? [])
  const alertsPerDay = ((overviewData as any)?.alerts_per_day ?? 0) as number
  const costPerEndpointTarget = ((overviewData as any)?.cost_per_endpoint_target ?? 500000) as number
  const analystHeadroom = ((overviewData as any)?.analyst_headroom ?? 2) as number
  type ROIItem = { category: string; label: string; sub_label: string; roi_pct: number; color: 'green' | 'yellow' | 'red' }
  const roiItems = ((roiData as ROIItem[]) ?? [])
  const analystCapacity = analysts.reduce((s, a) => s + a.alerts_handled_per_day, 0)
  const totalBudget = budget.reduce((s, b) => s + b.current_year, 0)
  const agentCount = licenses.find(l => l.category === 'EDR')?.used ?? 0
  const costPerEndpoint = agentCount > 0 ? Math.round(totalBudget / agentCount) : 0

  const workloadRatio = analystCapacity > 0 ? alertsPerDay / analystCapacity : 0
  const workloadColor = workloadRatio < 0.7 ? 'text-green-400' : workloadRatio < 1.0 ? 'text-yellow-400' : 'text-red-400'
  const surplus = analystCapacity - alertsPerDay

  // Growth projections
  const projections = useMemo(() => {
    const months = [6, 12, 24]
    const dailyAlertsCurrent = alertsPerDay
    return months.map(m => {
      const growth = Math.pow(1 + alertGrowthPct / 100, m / 12)
      const projAlerts = Math.round(dailyAlertsCurrent * growth)
      const requiredAnalysts = analysts.length > 0 && analystCapacity > 0 ? Math.ceil(projAlerts / (analystCapacity / analysts.length)) : 0
      return { months: m, projected_alerts: projAlerts, required_analysts: requiredAnalysts, gap: requiredAnalysts - analysts.length }
    })
  }, [alertGrowthPct, analysts.length])

  // Roles composition
  const roleCounts = useMemo(() => {
    const counts: Partial<Record<AnalystRole, number>> = {}
    for (const a of analysts) counts[a.role] = (counts[a.role] ?? 0) + 1
    return Object.entries(counts) as [AnalystRole, number][]
  }, [analysts])

  // Scaling scenarios
  const scalingScenarios = [
    { label: 'エージェント×1.5', agents: Math.round(agentCount * 1.5), storage: `${(storage.used_tb * 1.5).toFixed(1)} TB`, compute: '要増設', bandwidth: '+50%' },
    { label: 'エージェント×2', agents: agentCount * 2, storage: `${(storage.used_tb * 2).toFixed(1)} TB`, compute: '要大幅増設', bandwidth: '+100%' },
    { label: 'エージェント×3', agents: agentCount * 3, storage: `${(storage.used_tb * 3).toFixed(1)} TB`, compute: '新規クラスタ必要', bandwidth: '+200%' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      {/* Header */}
      <div className="border-b border-[#1e2d42] bg-[#0d1220] px-6 py-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#e8002d]/10 border border-[#e8002d]/20 rounded-lg">
              <TrendingUp className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-white font-semibold text-xl">セキュリティリソース計画</h1>
              <p className="text-[#7d92b0] text-sm">人員・技術・予算の容量計画と最適化</p>
            </div>
          </div>
          <button
            onClick={() => setShowAdminDrawer(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#2a3a52] text-white text-sm rounded-lg transition-colors"
          >
            <Settings className="w-4 h-4" />
            データ管理
          </button>
        </div>
        {/* Overview cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="アナリスト" value={analysts.length} sub={`必要数: ${analysts.length + analystHeadroom}`} icon={Users} />
          <StatCard label="ツール予算 (年)" value={fmtJPY(budget.find(b => b.label === 'ツール・ライセンス')?.current_year ?? 0)} icon={DollarSign} />
          <StatCard label="ストレージ使用量" value={`${storage.used_tb} TB`} sub={`上限: ${storage.total_tb} TB`} icon={HardDrive} accent={storage.used_tb / storage.total_tb > 0.8 ? 'text-red-400' : 'text-white'} />
          <StatCard label="エージェントライセンス" value={agentCount} sub={`購入数: ${licenses.find(l => l.category === 'EDR')?.purchased ?? 500}`} icon={Server} />
        </div>
      </div>

      {/* Tabs */}
      <div className="px-6 pt-4 border-b border-[#1e2d42]">
        <div className="flex gap-1">
          {([['workforce', '人員計画'], ['tech', '技術リソース'], ['budget', '予算計画']] as const).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors ${tab === id ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'}`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* ── 人員計画 ── */}
        {tab === 'workforce' && (
          <>
            {/* Team composition */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><Users className="w-4 h-4 text-[#e8002d]" />チーム構成</h2>
              <div className="flex flex-wrap gap-3">
                {roleCounts.map(([role, count]) => (
                  <div key={role} className="flex items-center gap-2 bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-3 min-w-[160px]">
                    <div className="flex flex-col gap-1">
                      <span className={`text-xs px-2 py-0.5 rounded border ${ROLE_COLORS[role]}`}>{role}</span>
                      <span className="text-2xl font-bold text-white">{count}</span>
                      <span className="text-[#3d5068] text-xs">名</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Workload analysis */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><BarChart3 className="w-4 h-4 text-[#e8002d]" />ワークロード分析</h2>
              <div className="grid grid-cols-3 gap-6">
                <div className="text-center">
                  <p className="text-[#7d92b0] text-xs mb-1">日次アラート量</p>
                  <p className="text-3xl font-bold text-white">{alertsPerDay}</p>
                  <p className="text-[#3d5068] text-xs">アラート/日</p>
                </div>
                <div className="text-center">
                  <p className="text-[#7d92b0] text-xs mb-1">アナリスト処理能力</p>
                  <p className="text-3xl font-bold text-green-400">{analystCapacity}</p>
                  <p className="text-[#3d5068] text-xs">アラート/日</p>
                </div>
                <div className="text-center">
                  <p className="text-[#7d92b0] text-xs mb-1">ワークロード比率</p>
                  <p className={`text-3xl font-bold ${workloadColor}`}>{(workloadRatio * 100).toFixed(0)}%</p>
                  <p className={`text-xs mt-1 ${surplus >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                    {surplus >= 0 ? `余裕: +${surplus}` : `不足: ${surplus}`} アラート/日
                  </p>
                </div>
              </div>
              <div className="mt-4">
                <div className="flex justify-between text-xs text-[#7d92b0] mb-1">
                  <span>処理能力使用率</span>
                  <span className={workloadColor}>{(workloadRatio * 100).toFixed(0)}%</span>
                </div>
                <div className="h-3 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{ width: `${Math.min(workloadRatio * 100, 100)}%`, backgroundColor: workloadRatio < 0.7 ? '#00c853' : workloadRatio < 1.0 ? '#ffc107' : '#e8002d' }}
                  />
                </div>
              </div>
            </div>

            {/* Growth planning */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><TrendingUp className="w-4 h-4 text-[#e8002d]" />成長計画</h2>
              <div className="flex items-center gap-4 mb-5">
                <label className="text-sm text-[#7d92b0]">アラート年間成長率</label>
                <input
                  type="range" min={0} max={100} step={5}
                  value={alertGrowthPct}
                  onChange={e => setAlertGrowthPct(Number(e.target.value))}
                  className="flex-1 accent-[#e8002d]"
                />
                <span className="text-white font-bold w-12 text-right">{alertGrowthPct}%</span>
              </div>
              <div className="grid grid-cols-3 gap-4">
                {projections.map(p => (
                  <div key={p.months} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                    <p className="text-[#7d92b0] text-xs mb-2">{p.months}ヶ月後</p>
                    <p className="text-white text-lg font-bold">{(p.projected_alerts ?? 0).toLocaleString()}</p>
                    <p className="text-[#3d5068] text-xs mb-3">アラート/日</p>
                    <div className="border-t border-[#1e2d42] pt-2">
                      <p className="text-[#7d92b0] text-xs">必要アナリスト数</p>
                      <p className="text-white font-bold text-xl">{p.required_analysts} 名</p>
                      <p className={`text-xs font-medium ${p.gap > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {p.gap > 0 ? `+${p.gap}名 不足` : `${Math.abs(p.gap)}名 余裕`}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Skills matrix */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><CheckCircle className="w-4 h-4 text-[#e8002d]" />スキルマトリクス</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      <th className="py-2 pr-4 text-left text-xs text-[#7d92b0]">アナリスト</th>
                      <th className="py-2 pr-4 text-left text-xs text-[#7d92b0]">役割</th>
                      {SKILLS.map(s => <th key={s} className="py-2 px-3 text-center text-xs text-[#7d92b0]">{s}</th>)}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {analysts.map(a => (
                      <tr key={a.id} className="hover:bg-[#070d19]/50">
                        <td className="py-2.5 pr-4 text-white text-sm font-medium">{a.name}</td>
                        <td className="py-2.5 pr-4">
                          <span className={`text-xs px-2 py-0.5 rounded border ${ROLE_COLORS[a.role]}`}>{a.role}</span>
                        </td>
                        {SKILLS.map(s => (
                          <td key={s} className="py-2.5 px-3 text-center">
                            <span className={`text-xs px-2 py-0.5 rounded border ${SKILL_COLORS[a.skills[s]]}`}>
                              {SKILL_LABELS[a.skills[s]]}
                            </span>
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="text-[#3d5068] text-xs mt-2">◎ = 熟練 &nbsp; △ = 習得中 &nbsp; — = 未習得</p>
              </div>
            </div>

            {/* Hiring roadmap */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><Calendar className="w-4 h-4 text-[#e8002d]" />採用ロードマップ</h2>
              <div className="space-y-3">
                {plannedHires.map((h, i) => (
                  <div key={i} className="flex items-center justify-between bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className={`w-2 h-2 rounded-full ${PRIORITY_COLORS[h.priority].replace('text-', 'bg-')}`} />
                      <span className={`text-xs px-2 py-0.5 rounded border ${ROLE_COLORS[h.role as AnalystRole] ?? 'bg-gray-500/20 text-gray-300 border-gray-500/30'}`}>{h.role}</span>
                      <span className="text-[#7d92b0] text-sm">{h.planned_quarter}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-white text-sm font-medium">{fmtJPY(h.estimated_annual_cost)}/年</span>
                      <span className={`text-xs font-medium ${PRIORITY_COLORS[h.priority]}`}>{h.priority === 'high' ? '優先高' : h.priority === 'medium' ? '優先中' : '優先低'}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* On-call coverage */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><RefreshCw className="w-4 h-4 text-[#e8002d]" />24/7 オンコールカバレッジ</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      <th className="py-2 pr-4 text-left text-xs text-[#7d92b0]">シフト</th>
                      {['月', '火', '水', '木', '金', '土', '日'].map(d => (
                        <th key={d} className="py-2 px-3 text-center text-xs text-[#7d92b0]">{d}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {oncallShifts.map(s => (
                      <tr key={s.shift} className="hover:bg-[#070d19]/50">
                        <td className="py-2.5 pr-4 text-[#7d92b0] text-xs whitespace-nowrap">{s.shift}</td>
                        {[s.mon, s.tue, s.wed, s.thu, s.fri, s.sat, s.sun].map((p, i) => (
                          <td key={i} className={`py-2.5 px-3 text-center text-xs font-medium ${p === '—' ? 'text-red-400' : 'text-white'}`}>
                            {p === '—' ? <span className="px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 rounded text-red-400">空白</span> : p}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {/* ── 技術リソース ── */}
        {tab === 'tech' && (
          <>
            {/* Storage */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><HardDrive className="w-4 h-4 text-[#e8002d]" />ストレージ容量</h2>
              <div className="grid grid-cols-4 gap-4 mb-5">
                {[
                  { label: '使用中', value: `${storage.used_tb} TB`, color: 'text-white' },
                  { label: '上限', value: `${storage.total_tb} TB`, color: 'text-[#7d92b0]' },
                  { label: '6ヶ月後予測', value: `${storage.projected_6m_tb} TB`, color: storage.projected_6m_tb > storage.total_tb ? 'text-red-400' : 'text-yellow-400' },
                  { label: '12ヶ月後予測', value: `${storage.projected_12m_tb} TB`, color: storage.projected_12m_tb > storage.total_tb ? 'text-red-400' : 'text-orange-400' },
                ].map(c => (
                  <div key={c.label} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-center">
                    <p className="text-[#7d92b0] text-xs">{c.label}</p>
                    <p className={`text-xl font-bold mt-1 ${c.color}`}>{c.value}</p>
                  </div>
                ))}
              </div>
              <div>
                <div className="flex justify-between text-xs text-[#7d92b0] mb-1">
                  <span>現在の使用率</span>
                  <span className={storage.used_tb / storage.total_tb > 0.8 ? 'text-red-400' : 'text-white'}>
                    {((storage.used_tb / storage.total_tb) * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="h-3 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${(storage.used_tb / storage.total_tb) * 100}%`,
                      backgroundColor: storage.used_tb / storage.total_tb > 0.8 ? '#e8002d' : '#ffc107',
                    }}
                  />
                </div>
              </div>
            </div>

            {/* License utilization */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><Package className="w-4 h-4 text-[#e8002d]" />ライセンス使用状況</h2>
              <div className="space-y-3">
                {licenses.map(l => {
                  const pct = (l.used / l.purchased) * 100
                  const exhaustDate = pct >= 100 ? '満杯' : pct >= 90 ? '3ヶ月以内' : '余裕あり'
                  const exhaustColor = pct >= 100 ? 'text-red-400' : pct >= 90 ? 'text-yellow-400' : 'text-green-400'
                  return (
                    <div key={l.id} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-3">
                      <div className="flex items-center justify-between mb-2">
                        <div>
                          <span className="text-white text-sm font-medium">{l.tool_name}</span>
                          <span className="ml-2 text-xs px-1.5 py-0.5 bg-[#1e2d42] text-[#7d92b0] rounded">{l.category}</span>
                        </div>
                        <div className="flex items-center gap-4 text-xs">
                          <span className="text-[#7d92b0]">{l.used}/{l.purchased}</span>
                          <span className={`font-medium ${exhaustColor}`}>{exhaustDate}</span>
                          <span className="text-[#3d5068]">更新: {l.renewal_date}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <ScoreBar value={pct} max={100} color={pct >= 100 ? '#e8002d' : pct >= 90 ? '#ffc107' : '#00c853'} />
                        <span className={`text-xs font-medium w-10 text-right ${pct >= 100 ? 'text-red-400' : pct >= 90 ? 'text-yellow-400' : 'text-green-400'}`}>{pct.toFixed(0)}%</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Technical debt */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-400" />技術的負債</h2>
              <div className="space-y-3">
                {techDebt.map(td => (
                  <div key={td.id} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <p className="text-white text-sm font-medium">{td.title}</p>
                        <p className="text-[#7d92b0] text-xs mt-1">{td.impact}</p>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded border flex-shrink-0 ${SEVERITY_COLORS[td.severity]}`}>
                        {td.severity === 'high' ? '高' : td.severity === 'medium' ? '中' : '低'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Scaling scenarios */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><Cpu className="w-4 h-4 text-[#e8002d]" />スケーリングシナリオ</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['シナリオ', 'エージェント数', 'ストレージ影響', 'コンピュート', '帯域幅'].map(h => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0]">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {scalingScenarios.map((s, i) => (
                      <tr key={i} className="hover:bg-[#070d19]/50">
                        <td className="px-4 py-3 text-white font-medium">{s.label}</td>
                        <td className="px-4 py-3 text-[#7d92b0]">{(s.agents ?? 0).toLocaleString()}</td>
                        <td className="px-4 py-3 text-yellow-300">{s.storage}</td>
                        <td className="px-4 py-3 text-orange-300">{s.compute}</td>
                        <td className="px-4 py-3 text-red-300">{s.bandwidth}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {/* ── 予算計画 ── */}
        {tab === 'budget' && (
          <>
            {/* Summary */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <p className="text-[#7d92b0] text-xs mb-1">総予算 (当年度)</p>
                <p className="text-3xl font-bold text-white">{fmtJPY(totalBudget)}</p>
              </div>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <p className="text-[#7d92b0] text-xs mb-1">エンドポイント単価</p>
                <p className="text-3xl font-bold text-white">{fmtJPY(costPerEndpoint)}</p>
                <p className="text-[#3d5068] text-xs mt-0.5">目標: {fmtJPY(costPerEndpointTarget)}/台</p>
              </div>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <p className="text-[#7d92b0] text-xs mb-1">3年予測総額</p>
                <p className="text-3xl font-bold text-white">
                  {fmtJPY(budget.reduce((s, b) => s + b.next_year + b.year3, 0) + totalBudget)}
                </p>
              </div>
            </div>

            {/* Budget allocation table */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><DollarSign className="w-4 h-4 text-[#e8002d]" />3年間予算予測</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      <th className="px-4 py-3 text-left text-xs text-[#7d92b0]">カテゴリ</th>
                      <th className="px-4 py-3 text-right text-xs text-[#7d92b0]">当年度</th>
                      <th className="px-4 py-3 text-right text-xs text-[#7d92b0]">来年度</th>
                      <th className="px-4 py-3 text-right text-xs text-[#7d92b0]">3年目</th>
                      <th className="px-4 py-3 text-right text-xs text-[#7d92b0]">3年合計</th>
                      <th className="px-4 py-3 text-left text-xs text-[#7d92b0]">割合</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {budget.map(b => {
                      const pct = (b.current_year / totalBudget) * 100
                      const total3 = b.current_year + b.next_year + b.year3
                      return (
                        <tr key={b.label} className="hover:bg-[#070d19]/50">
                          <td className="px-4 py-3 text-white font-medium">{b.label}</td>
                          <td className="px-4 py-3 text-right text-white">{fmtJPY(b.current_year)}</td>
                          <td className="px-4 py-3 text-right text-[#7d92b0]">{fmtJPY(b.next_year)}</td>
                          <td className="px-4 py-3 text-right text-[#7d92b0]">{fmtJPY(b.year3)}</td>
                          <td className="px-4 py-3 text-right text-[#7d92b0]">{fmtJPY(total3)}</td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <div className="w-20 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                                <div className="h-full bg-[#e8002d] rounded-full" style={{ width: `${pct}%` }} />
                              </div>
                              <span className="text-xs text-[#7d92b0]">{pct.toFixed(0)}%</span>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                    <tr className="border-t border-[#1e2d42] bg-[#070d19]/30">
                      <td className="px-4 py-3 text-white font-bold">合計</td>
                      <td className="px-4 py-3 text-right text-white font-bold">{fmtJPY(totalBudget)}</td>
                      <td className="px-4 py-3 text-right text-white font-bold">{fmtJPY(budget.reduce((s, b) => s + b.next_year, 0))}</td>
                      <td className="px-4 py-3 text-right text-white font-bold">{fmtJPY(budget.reduce((s, b) => s + b.year3, 0))}</td>
                      <td className="px-4 py-3 text-right text-white font-bold">{fmtJPY(budget.reduce((s, b) => s + b.current_year + b.next_year + b.year3, 0))}</td>
                      <td />
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* ROI metrics — values computed server-side from investment vs benefit inputs (cp_roi_inputs) */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-medium mb-4 flex items-center gap-2"><TrendingUp className="w-4 h-4 text-[#e8002d]" />ROI指標</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {roiItems.map(r => {
                  const colorCls = r.color === 'green' ? 'text-green-400' : r.color === 'yellow' ? 'text-yellow-400' : 'text-red-400'
                  return (
                    <div key={r.category} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 text-center">
                      <p className="text-[#7d92b0] text-xs mb-1">{r.label}</p>
                      <p className={`text-3xl font-bold ${colorCls}`}>{r.roi_pct}%</p>
                      <p className="text-[#3d5068] text-xs mt-1">{r.sub_label}</p>
                    </div>
                  )
                })}
                {roiItems.length === 0 && (
                  <p className="col-span-4 text-[#7d92b0] text-sm text-center py-4">ROIデータを読み込み中...</p>
                )}
              </div>
            </div>

            {/* Budget request builder */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-white font-medium">予算申請書</h2>
                  <p className="text-[#7d92b0] text-sm mt-0.5">現在のデータに基づいた予算申請書を生成します</p>
                </div>
                <button
                  onClick={() => setShowBudgetModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors"
                >
                  <Download className="w-4 h-4" />
                  予算申請書を作成
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Admin data editor drawer */}
      <AdminDrawer open={showAdminDrawer} onClose={() => setShowAdminDrawer(false)} />

      {/* Budget proposal modal */}
      {showBudgetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setShowBudgetModal(false)}>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl p-6 shadow-xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-white font-semibold text-lg">予算申請書 (テンプレート)</h2>
              <button onClick={() => setShowBudgetModal(false)} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0]">
                <span className="text-lg">×</span>
              </button>
            </div>
            <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-5 space-y-4 text-sm">
              <div>
                <p className="text-[#e8002d] font-bold text-base mb-1">セキュリティ予算申請書 FY2027</p>
                <p className="text-[#7d92b0]">作成日: {new Date().toISOString().slice(0, 10)} | 作成者: セキュリティ部門</p>
              </div>
              <div>
                <p className="text-white font-medium mb-2">1. 申請概要</p>
                <p className="text-[#7d92b0]">現在のセキュリティ態勢強化および増大する脅威への対応力向上を目的として、FY2027予算 {fmtJPY(budget.reduce((s, b) => s + b.next_year, 0))} を申請します。</p>
              </div>
              <div>
                <p className="text-white font-medium mb-2">2. 予算内訳</p>
                {budget.map(b => (
                  <div key={b.label} className="flex justify-between border-b border-[#1e2d42]/50 py-1">
                    <span className="text-[#7d92b0]">{b.label}</span>
                    <span className="text-white">{fmtJPY(b.next_year)}</span>
                  </div>
                ))}
                <div className="flex justify-between pt-2 font-bold">
                  <span className="text-white">合計</span>
                  <span className="text-[#e8002d]">{fmtJPY(budget.reduce((s, b) => s + b.next_year, 0))}</span>
                </div>
              </div>
              <div>
                <p className="text-white font-medium mb-2">3. 根拠・ROI</p>
                <p className="text-[#7d92b0]">現在のアラート増加率 ({alertGrowthPct}%/年) に対応するため、{projections[1].gap > 0 ? `アナリスト${projections[1].gap}名の採用` : '現行人員維持'} および技術強化が必要です。推定投資対効果は {roiItems.find(r => r.category === 'overall')?.roi_pct ?? 0}% です。</p>
              </div>
            </div>
            <div className="flex justify-end mt-4">
              <button
                onClick={() => setShowBudgetModal(false)}
                className="px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded-lg transition-colors"
              >
                閉じる
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
