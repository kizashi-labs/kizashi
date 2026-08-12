'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  TrendingUp, X, Calculator, RefreshCw, ChevronRight,
  AlertTriangle, DollarSign, Clock, ShieldOff,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type TabKey = 'incident' | 'category' | 'monthly'

interface Incident {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  date: string
  status: 'open' | 'investigating' | 'resolved' | 'closed'
  direct_cost: number
  indirect_cost: number
  total_cost: number
  hours_spent: number
  personnel_cost: number
  tool_cost: number
  recovery_cost: number
  regulatory_fine: number
  reputation_cost: number
}

interface CategoryCost {
  category: string
  incident_count: number
  total_cost: number
  avg_cost: number
  max_cost: number
}

interface MonthlyCost {
  month: string
  incident_count: number
  total_cost: number
  prev_change_pct: number | null
}

interface CostData {
  year: number
  annual_total: number
  max_incident_cost: number
  avg_resolution_cost: number
  avoided_cost: number
  incidents: Incident[]
  categories: CategoryCost[]
  monthly: MonthlyCost[]
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_INCIDENTS: Incident[] = [
  { id: 'INC-001', title: 'ランサムウェア感染 - 財務部門サーバー', severity: 'critical', date: '2026-01-05', status: 'resolved', direct_cost: 2500000, indirect_cost: 1800000, total_cost: 4300000, hours_spent: 168, personnel_cost: 840000, tool_cost: 350000, recovery_cost: 1310000, regulatory_fine: 0, reputation_cost: 1800000 },
  { id: 'INC-002', title: 'フィッシング攻撃による認証情報漏洩', severity: 'high', date: '2026-01-12', status: 'closed', direct_cost: 450000, indirect_cost: 320000, total_cost: 770000, hours_spent: 40, personnel_cost: 200000, tool_cost: 80000, recovery_cost: 170000, regulatory_fine: 0, reputation_cost: 320000 },
  { id: 'INC-003', title: '内部不正によるデータ持ち出し', severity: 'critical', date: '2026-01-18', status: 'investigating', direct_cost: 1200000, indirect_cost: 900000, total_cost: 2100000, hours_spent: 96, personnel_cost: 480000, tool_cost: 120000, recovery_cost: 600000, regulatory_fine: 500000, reputation_cost: 400000 },
  { id: 'INC-004', title: 'DDoS攻撃によるサービス停止', severity: 'high', date: '2026-02-03', status: 'resolved', direct_cost: 680000, indirect_cost: 420000, total_cost: 1100000, hours_spent: 24, personnel_cost: 120000, tool_cost: 60000, recovery_cost: 500000, regulatory_fine: 0, reputation_cost: 420000 },
  { id: 'INC-005', title: 'SQLインジェクションによるDBアクセス', severity: 'high', date: '2026-02-14', status: 'closed', direct_cost: 320000, indirect_cost: 180000, total_cost: 500000, hours_spent: 32, personnel_cost: 160000, tool_cost: 40000, recovery_cost: 120000, regulatory_fine: 0, reputation_cost: 180000 },
  { id: 'INC-006', title: '顧客データ漏洩 (個人情報3000件)', severity: 'critical', date: '2026-02-22', status: 'closed', direct_cost: 3200000, indirect_cost: 2400000, total_cost: 5600000, hours_spent: 240, personnel_cost: 1200000, tool_cost: 200000, recovery_cost: 1800000, regulatory_fine: 1200000, reputation_cost: 1200000 },
  { id: 'INC-007', title: 'マルウェア感染 - 開発サーバー', severity: 'medium', date: '2026-03-01', status: 'resolved', direct_cost: 180000, indirect_cost: 90000, total_cost: 270000, hours_spent: 16, personnel_cost: 80000, tool_cost: 30000, recovery_cost: 70000, regulatory_fine: 0, reputation_cost: 90000 },
  { id: 'INC-008', title: '不正アクセス - VPN経由', severity: 'high', date: '2026-03-08', status: 'open', direct_cost: 560000, indirect_cost: 280000, total_cost: 840000, hours_spent: 48, personnel_cost: 240000, tool_cost: 80000, recovery_cost: 240000, regulatory_fine: 0, reputation_cost: 280000 },
  { id: 'INC-009', title: 'サプライチェーン攻撃の疑い', severity: 'critical', date: '2026-03-10', status: 'investigating', direct_cost: 890000, indirect_cost: 560000, total_cost: 1450000, hours_spent: 72, personnel_cost: 360000, tool_cost: 180000, recovery_cost: 350000, regulatory_fine: 0, reputation_cost: 560000 },
  { id: 'INC-010', title: 'フィッシング - HR部門', severity: 'medium', date: '2026-03-14', status: 'resolved', direct_cost: 95000, indirect_cost: 45000, total_cost: 140000, hours_spent: 8, personnel_cost: 40000, tool_cost: 15000, recovery_cost: 40000, regulatory_fine: 0, reputation_cost: 45000 },
  { id: 'INC-011', title: 'ブルートフォース攻撃 - 管理コンソール', severity: 'medium', date: '2026-03-15', status: 'closed', direct_cost: 65000, indirect_cost: 30000, total_cost: 95000, hours_spent: 6, personnel_cost: 30000, tool_cost: 10000, recovery_cost: 25000, regulatory_fine: 0, reputation_cost: 30000 },
  { id: 'INC-012', title: 'ゼロデイ脆弱性悪用の試み', severity: 'high', date: '2026-03-16', status: 'open', direct_cost: 420000, indirect_cost: 210000, total_cost: 630000, hours_spent: 36, personnel_cost: 180000, tool_cost: 60000, recovery_cost: 180000, regulatory_fine: 0, reputation_cost: 210000 },
  { id: 'INC-013', title: 'ラテラルムーブメント検出', severity: 'high', date: '2026-03-17', status: 'investigating', direct_cost: 310000, indirect_cost: 150000, total_cost: 460000, hours_spent: 28, personnel_cost: 140000, tool_cost: 50000, recovery_cost: 120000, regulatory_fine: 0, reputation_cost: 150000 },
  { id: 'INC-014', title: '設定ミスによるクラウドデータ露出', severity: 'medium', date: '2026-03-17', status: 'resolved', direct_cost: 75000, indirect_cost: 40000, total_cost: 115000, hours_spent: 10, personnel_cost: 50000, tool_cost: 10000, recovery_cost: 15000, regulatory_fine: 0, reputation_cost: 40000 },
  { id: 'INC-015', title: '外部スキャン・偵察活動', severity: 'low', date: '2026-03-18', status: 'closed', direct_cost: 20000, indirect_cost: 8000, total_cost: 28000, hours_spent: 2, personnel_cost: 10000, tool_cost: 5000, recovery_cost: 5000, regulatory_fine: 0, reputation_cost: 8000 },
]

const MOCK_CATEGORIES: CategoryCost[] = [
  { category: 'マルウェア',   incident_count: 3, total_cost: 4670000, avg_cost: 1556667, max_cost: 4300000 },
  { category: 'フィッシング', incident_count: 3, total_cost: 910000,  avg_cost: 303333,  max_cost: 770000  },
  { category: '内部不正',     incident_count: 1, total_cost: 2100000, avg_cost: 2100000, max_cost: 2100000 },
  { category: 'データ漏洩',   incident_count: 2, total_cost: 5715000, avg_cost: 2857500, max_cost: 5600000 },
  { category: 'DDoS',         incident_count: 1, total_cost: 1100000, avg_cost: 1100000, max_cost: 1100000 },
  { category: '不正アクセス', incident_count: 5, total_cost: 2455000, avg_cost: 491000,  max_cost: 1450000 },
]

const MOCK_MONTHLY: MonthlyCost[] = [
  { month: '2025-04', incident_count: 2, total_cost: 580000,   prev_change_pct: null  },
  { month: '2025-05', incident_count: 1, total_cost: 270000,   prev_change_pct: -53.4 },
  { month: '2025-06', incident_count: 3, total_cost: 1240000,  prev_change_pct: 359.3 },
  { month: '2025-07', incident_count: 2, total_cost: 860000,   prev_change_pct: -30.6 },
  { month: '2025-08', incident_count: 4, total_cost: 2100000,  prev_change_pct: 144.2 },
  { month: '2025-09', incident_count: 2, total_cost: 670000,   prev_change_pct: -68.1 },
  { month: '2025-10', incident_count: 3, total_cost: 1450000,  prev_change_pct: 116.4 },
  { month: '2025-11', incident_count: 2, total_cost: 720000,   prev_change_pct: -50.3 },
  { month: '2025-12', incident_count: 5, total_cost: 3800000,  prev_change_pct: 427.8 },
  { month: '2026-01', incident_count: 3, total_cost: 7170000,  prev_change_pct: 88.7  },
  { month: '2026-02', incident_count: 3, total_cost: 6200000,  prev_change_pct: -13.5 },
  { month: '2026-03', incident_count: 7, total_cost: 2818000,  prev_change_pct: -54.5 },
]

const MOCK_DATA: CostData = {
  year: 2026,
  annual_total:        27878000,
  max_incident_cost:    5600000,
  avg_resolution_cost:  1858533,
  avoided_cost:        12400000,
  incidents:   MOCK_INCIDENTS,
  categories:  MOCK_CATEGORIES,
  monthly:     MOCK_MONTHLY,
}

const EMPTY_COST_DATA: CostData = {
  year: new Date().getFullYear(),
  annual_total: 0,
  max_incident_cost: 0,
  avg_resolution_cost: 0,
  avoided_cost: 0,
  incidents: [],
  categories: [],
  monthly: [],
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const fmt = (n: number) => `¥${n.toLocaleString('ja-JP')}`

function SeverityBadge({ severity }: { severity: Incident['severity'] }) {
  const map = {
    critical: { label: 'クリティカル', bg: 'bg-red-500/20',    text: 'text-red-400'    },
    high:     { label: '高',           bg: 'bg-orange-500/20', text: 'text-orange-400' },
    medium:   { label: '中',           bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    low:      { label: '低',           bg: 'bg-blue-500/20',   text: 'text-blue-400'   },
  }
  const s = map[severity]
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${s.bg} ${s.text}`}>{s.label}</span>
}

function StatusBadge({ status }: { status: Incident['status'] }) {
  const map = {
    open:          { label: 'オープン',     bg: 'bg-red-500/20',    text: 'text-red-400'    },
    investigating: { label: '調査中',       bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    resolved:      { label: '解決済み',     bg: 'bg-green-500/20',  text: 'text-green-400'  },
    closed:        { label: 'クローズ',     bg: 'bg-gray-500/20',   text: 'text-gray-400'   },
  }
  const s = map[status]
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${s.bg} ${s.text}`}>{s.label}</span>
}

// ─── Cost Detail Modal ────────────────────────────────────────────────────────

function CostDetailModal({ incident, onClose }: { incident: Incident; onClose: () => void }) {
  const breakdownItems = [
    { label: '人員対応コスト',   value: incident.personnel_cost,   pct: (incident.personnel_cost / incident.total_cost) * 100 },
    { label: 'ツール・外部費用', value: incident.tool_cost,        pct: (incident.tool_cost / incident.total_cost) * 100 },
    { label: '復旧・修復コスト', value: incident.recovery_cost,    pct: (incident.recovery_cost / incident.total_cost) * 100 },
    { label: '規制罰金',         value: incident.regulatory_fine,  pct: (incident.regulatory_fine / incident.total_cost) * 100 },
    { label: '風評リスク推定',   value: incident.reputation_cost,  pct: (incident.reputation_cost / incident.total_cost) * 100 },
  ]

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[85vh] overflow-y-auto">
        <div className="sticky top-0 bg-[#0d1220] border-b border-[#1e2d42] p-4 flex items-center justify-between">
          <h3 className="text-white font-semibold">コスト詳細: {incident.id}</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          {/* Incident info */}
          <div className="bg-[#070d19] rounded-lg p-4 space-y-2">
            <p className="text-white font-medium">{incident.title}</p>
            <div className="flex items-center gap-3 flex-wrap">
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
              <span className="text-[#7d92b0] text-sm">{incident.date}</span>
              <span className="text-[#7d92b0] text-sm flex items-center gap-1">
                <Clock className="w-3 h-3" />{incident.hours_spent}時間
              </span>
            </div>
          </div>

          {/* Cost summary */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-[#070d19] rounded-lg p-3 text-center">
              <p className="text-[#7d92b0] text-xs mb-1">直接コスト</p>
              <p className="text-white font-bold text-sm">{fmt(incident.direct_cost)}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 text-center">
              <p className="text-[#7d92b0] text-xs mb-1">間接コスト</p>
              <p className="text-white font-bold text-sm">{fmt(incident.indirect_cost)}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 text-center border border-[#e8002d]/30">
              <p className="text-[#7d92b0] text-xs mb-1">合計コスト</p>
              <p className="text-[#e8002d] font-bold text-sm">{fmt(incident.total_cost)}</p>
            </div>
          </div>

          {/* Breakdown */}
          <div>
            <p className="text-[#7d92b0] text-sm font-medium mb-3">コスト内訳</p>
            <div className="space-y-2.5">
              {breakdownItems.map(item => (
                <div key={item.label}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-[#7d92b0]">{item.label}</span>
                    <span className="text-sm text-white font-medium">{fmt(item.value)}</span>
                  </div>
                  <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[#e8002d] rounded-full"
                      style={{ width: `${item.pct.toFixed(1)}%` }}
                    />
                  </div>
                  <p className="text-xs text-[#7d92b0] mt-0.5 text-right">{item.pct.toFixed(1)}%</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function IncidentCostPage() {
  const [activeTab, setActiveTab] = useState<TabKey>('incident')
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [investmentInput, setInvestmentInput] = useState('10000000')

  const { data, isLoading, refetch } = useQuery<CostData>({
    queryKey: ['incident-costs'],
    queryFn: () =>
      apiFetch<CostData>('/api/v1/reports/incident-costs?year=2026').catch(() => USE_MOCK ? MOCK_DATA : EMPTY_COST_DATA),
    ...(USE_MOCK ? { initialData: MOCK_DATA } : {}),
  })

  const d: CostData = data ?? EMPTY_COST_DATA

  const investment = parseInt(investmentInput.replace(/[^0-9]/g, '')) || 0
  const roiRatio = investment > 0 ? (d.avoided_cost / investment).toFixed(2) : '—'
  const roiPct = investment > 0 ? (((d.avoided_cost - investment) / investment) * 100).toFixed(1) : '—'

  const maxCategoryCost = Math.max(...d.categories.map(c => c.total_cost))
  const maxMonthlyCost  = Math.max(...d.monthly.map(m => m.total_cost))

  const tabs: { key: TabKey; label: string }[] = [
    { key: 'incident', label: 'インシデント別' },
    { key: 'category', label: 'カテゴリ別' },
    { key: 'monthly',  label: '月次推移' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
            <TrendingUp className="w-6 h-6 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">インシデントコスト追跡</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">セキュリティインシデントの財務的影響分析</p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#e8002d] transition-colors text-sm"
        >
          <RefreshCw className="w-4 h-4" />
          更新
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          { label: '年間累計コスト',      value: fmt(d.annual_total),        icon: DollarSign,   color: '#e8002d', sub: `${d.incidents.length}件のインシデント` },
          { label: '最高コストインシデント', value: fmt(d.max_incident_cost), icon: AlertTriangle, color: '#f97316', sub: '単一インシデント最大' },
          { label: '平均解決コスト',       value: fmt(d.avg_resolution_cost), icon: TrendingUp,   color: '#3b82f6', sub: 'インシデントあたり' },
          { label: '回避できたコスト',     value: fmt(d.avoided_cost),        icon: ShieldOff,    color: '#22c55e', sub: 'セキュリティ対策による回避額' },
        ].map(card => (
          <div key={card.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[#7d92b0] text-sm">{card.label}</span>
              <card.icon className="w-5 h-5" style={{ color: card.color }} />
            </div>
            <p className="text-xl font-bold text-white">{card.value}</p>
            <p className="text-xs text-[#7d92b0] mt-1">{card.sub}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="flex border-b border-[#1e2d42]">
          {tabs.map(t => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`px-6 py-3 text-sm font-medium transition-colors ${
                activeTab === t.key
                  ? 'text-white border-b-2 border-[#e8002d]'
                  : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* ── インシデント別 ── */}
        {activeTab === 'incident' && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['インシデント', '重大度', '日付', 'ステータス', '直接コスト', '間接コスト', '合計コスト', '時間', ''].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {d.incidents.map(inc => (
                  <tr key={inc.id} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-white text-sm font-medium max-w-xs truncate">{inc.title}</p>
                      <p className="text-[#7d92b0] text-xs">{inc.id}</p>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap"><SeverityBadge severity={inc.severity} /></td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{inc.date}</td>
                    <td className="px-4 py-3 whitespace-nowrap"><StatusBadge status={inc.status} /></td>
                    <td className="px-4 py-3 text-white text-sm whitespace-nowrap">{fmt(inc.direct_cost)}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{fmt(inc.indirect_cost)}</td>
                    <td className="px-4 py-3 text-[#e8002d] font-semibold text-sm whitespace-nowrap">{fmt(inc.total_cost)}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{inc.hours_spent}h</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#e8002d] px-2 py-1 rounded transition-colors"
                      >
                        詳細<ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── カテゴリ別 ── */}
        {activeTab === 'category' && (
          <div className="p-6 space-y-6">
            {/* Horizontal Bar Chart */}
            <div className="space-y-3">
              <p className="text-[#7d92b0] text-sm font-medium">カテゴリ別総コスト</p>
              {d.categories
                .sort((a, b) => b.total_cost - a.total_cost)
                .map(cat => (
                  <div key={cat.category} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-white font-medium w-28 shrink-0">{cat.category}</span>
                      <span className="text-[#7d92b0]">{fmt(cat.total_cost)}</span>
                    </div>
                    <div className="h-6 bg-[#070d19] rounded overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-[#e8002d] to-[#f97316] rounded transition-all duration-500 flex items-center justify-end pr-2"
                        style={{ width: `${(cat.total_cost / maxCategoryCost) * 100}%` }}
                      >
                        <span className="text-white text-xs font-semibold">{cat.incident_count}件</span>
                      </div>
                    </div>
                  </div>
                ))}
            </div>

            {/* Category Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['カテゴリ', 'インシデント数', '総コスト', '平均コスト', '最高コスト'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {d.categories.map(cat => (
                    <tr key={cat.category} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                      <td className="px-4 py-3 text-white text-sm font-medium">{cat.category}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-sm">{cat.incident_count}件</td>
                      <td className="px-4 py-3 text-[#e8002d] font-semibold text-sm">{fmt(cat.total_cost)}</td>
                      <td className="px-4 py-3 text-white text-sm">{fmt(cat.avg_cost)}</td>
                      <td className="px-4 py-3 text-white text-sm">{fmt(cat.max_cost)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── 月次推移 ── */}
        {activeTab === 'monthly' && (
          <div className="p-6 space-y-6">
            {/* Bar Chart */}
            <div className="space-y-1">
              <p className="text-[#7d92b0] text-sm font-medium mb-3">月次インシデントコスト推移</p>
              <div className="flex items-end gap-2 h-48">
                {d.monthly.map(m => (
                  <div key={m.month} className="flex-1 flex flex-col items-center gap-1 group">
                    <div className="relative w-full flex flex-col justify-end" style={{ height: '168px' }}>
                      <div
                        className="w-full bg-gradient-to-t from-[#e8002d] to-[#f97316] rounded-t transition-all duration-500"
                        style={{ height: `${(m.total_cost / maxMonthlyCost) * 100}%` }}
                      />
                      <div className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity bg-[#0d1220] border border-[#1e2d42] rounded px-2 py-1 text-xs text-white whitespace-nowrap z-10">
                        {fmt(m.total_cost)}
                      </div>
                    </div>
                    <span className="text-[#7d92b0] text-xs">{m.month.slice(5)}月</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Monthly Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['月', 'インシデント数', '総コスト', '前月比'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {d.monthly.map(m => (
                    <tr key={m.month} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                      <td className="px-4 py-3 text-white text-sm">{m.month}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-sm">{m.incident_count}件</td>
                      <td className="px-4 py-3 text-white font-medium text-sm">{fmt(m.total_cost)}</td>
                      <td className="px-4 py-3">
                        {m.prev_change_pct === null ? (
                          <span className="text-[#7d92b0] text-sm">—</span>
                        ) : (
                          <span className={`text-sm font-medium ${m.prev_change_pct > 0 ? 'text-red-400' : 'text-green-400'}`}>
                            {m.prev_change_pct > 0 ? '▲' : '▼'}{Math.abs(m.prev_change_pct)}%
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ROI Calculator */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <Calculator className="w-5 h-5 text-[#e8002d]" />
          <h2 className="text-lg font-semibold text-white">ROI計算機</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
          <div>
            <label className="block text-[#7d92b0] text-sm mb-2">セキュリティ投資額 (¥)</label>
            <input
              type="text"
              value={parseInt(investmentInput || '0').toLocaleString('ja-JP')}
              onChange={e => setInvestmentInput(e.target.value.replace(/[^0-9]/g, ''))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white focus:outline-none focus:border-[#e8002d] text-sm"
              placeholder="例: 10,000,000"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] rounded-lg p-3 text-center">
              <p className="text-[#7d92b0] text-xs mb-1">投資対回避コスト比率</p>
              <p className="text-xl font-bold text-green-400">{roiRatio}x</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 text-center">
              <p className="text-[#7d92b0] text-xs mb-1">ROI</p>
              <p className={`text-xl font-bold ${typeof roiPct === 'string' && roiPct !== '—' && parseFloat(roiPct) > 0 ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                {roiPct !== '—' ? `${parseFloat(roiPct) > 0 ? '+' : ''}${roiPct}%` : '—'}
              </p>
            </div>
          </div>
          <div className="bg-[#070d19] rounded-lg p-3">
            <p className="text-[#7d92b0] text-xs mb-1">回避できたコスト総額</p>
            <p className="text-lg font-bold text-green-400">{fmt(d.avoided_cost)}</p>
            <p className="text-xs text-[#7d92b0] mt-1">セキュリティ対策実施による推定回避額</p>
          </div>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedIncident && (
        <CostDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
        />
      )}

      {isLoading && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 flex items-center gap-3">
            <RefreshCw className="w-5 h-5 text-[#e8002d] animate-spin" />
            <span className="text-white">データを読み込み中...</span>
          </div>
        </div>
      )}
    </div>
  )
}
