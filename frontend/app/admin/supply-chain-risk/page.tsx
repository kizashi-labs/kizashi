'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Building2, AlertTriangle, ClipboardList, BarChart3,
  RefreshCw, Shield,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
type VendorType = 'クラウド' | 'ソフトウェア' | 'ハードウェア' | 'サービス' | 'OSS'
type Criticality = 'critical' | 'important' | 'standard'
type AssessmentStatus = '完了' | '実施中' | '待機中' | '未実施'
type IncidentStatus = 'open' | 'investigating' | 'resolved'
type TabId = 'vendors' | 'incidents' | 'riskmap'

interface Vendor {
  id: string
  name: string
  type: VendorType
  risk_score: number
  risk_level: RiskLevel
  criticality: Criticality
  assessment_status: AssessmentStatus
  last_assessed: string
}

interface SCIncident {
  id: string
  title: string
  severity: RiskLevel
  status: IncidentStatus
  vendor_name: string
  reported_at: string
  description: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const riskColor: Record<RiskLevel, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

const riskBadge: Record<RiskLevel, string> = {
  critical: 'bg-red-900 text-red-300',
  high: 'bg-orange-900 text-orange-300',
  medium: 'bg-yellow-900 text-yellow-300',
  low: 'bg-green-900 text-green-300',
}

const riskLabel: Record<RiskLevel, string> = {
  critical: '重大',
  high: '高',
  medium: '中',
  low: '低',
}

const incidentStatusConfig: Record<IncidentStatus, { label: string; cls: string }> = {
  open: { label: 'オープン', cls: 'bg-red-900 text-red-300' },
  investigating: { label: '調査中', cls: 'bg-blue-900 text-blue-300' },
  resolved: { label: '解決済', cls: 'bg-green-900 text-green-300' },
}

function RiskBar({ score }: { score: number }) {
  const pct = (score / 10) * 100
  const color = score < 3 ? 'bg-green-500' : score < 5 ? 'bg-yellow-500' : score < 7 ? 'bg-orange-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-[#070d19] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-xs font-medium ${score < 3 ? 'text-green-400' : score < 5 ? 'text-yellow-400' : score < 7 ? 'text-orange-400' : 'text-red-400'}`}>
        {score.toFixed(1)}
      </span>
    </div>
  )
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────

function VendorsTab({ vendors }: { vendors: Vendor[] }) {
  const [filter, setFilter] = useState<'all' | RiskLevel>('all')
  const filters: { key: 'all' | RiskLevel; label: string }[] = [
    { key: 'all', label: '全て' },
    { key: 'critical', label: '重大' },
    { key: 'high', label: '高' },
    { key: 'medium', label: '中' },
    { key: 'low', label: '低' },
  ]
  const filtered = filter === 'all' ? vendors : vendors.filter(v => v.risk_level === filter)

  return (
    <div>
      <div className="flex gap-2 mb-4">
        {filters.map(f => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${filter === f.key ? 'bg-[#e8002d] text-white' : 'bg-[#070d19] text-[#7d92b0] border border-[#1e2d42] hover:text-white'}`}
          >
            {f.label}
          </button>
        ))}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['ベンダー名', '種別', 'リスクスコア', 'リスクレベル', '重要度', '評価状況', '最終評価日', 'アクション'].map(h => (
                <th key={h} className="text-left px-4 py-2.5 text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(v => (
              <tr key={v.id} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                <td className="px-4 py-3 text-white font-medium">{v.name}</td>
                <td className="px-4 py-3 text-[#7d92b0]">{v.type}</td>
                <td className="px-4 py-3"><RiskBar score={v.risk_score} /></td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${riskBadge[v.risk_level]}`}>{riskLabel[v.risk_level]}</span>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs ${v.criticality === 'critical' ? 'text-red-400' : v.criticality === 'important' ? 'text-orange-400' : 'text-[#7d92b0]'}`}>
                    {v.criticality === 'critical' ? '重要' : v.criticality === 'important' ? '重要度高' : '標準'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs ${v.assessment_status === '完了' ? 'text-green-400' : v.assessment_status === '実施中' ? 'text-blue-400' : 'text-[#7d92b0]'}`}>
                    {v.assessment_status}
                  </span>
                </td>
                <td className="px-4 py-3 text-[#7d92b0] text-xs">{v.last_assessed}</td>
                <td className="px-4 py-3">
                  <button className="flex items-center gap-1 px-2.5 py-1 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] rounded text-xs hover:text-white hover:border-[#e8002d] transition-colors">
                    <RefreshCw size={10} />
                    評価実行
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function IncidentsTab({ incidents }: { incidents: SCIncident[] }) {
  return (
    <div className="space-y-3">
      {incidents.map(inc => {
        const st = incidentStatusConfig[inc.status]
        return (
          <div key={inc.id} className="p-4 bg-[#070d19] border border-[#1e2d42] rounded-lg">
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="font-medium text-white">{inc.title}</div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${riskBadge[inc.severity]}`}>{riskLabel[inc.severity]}</span>
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${st.cls}`}>{st.label}</span>
              </div>
            </div>
            <div className="flex items-center gap-4 text-xs text-[#7d92b0] mb-2">
              <span className="flex items-center gap-1"><Building2 size={11} />{inc.vendor_name}</span>
              <span>{inc.reported_at}</span>
            </div>
            <p className="text-sm text-[#7d92b0]">{inc.description}</p>
          </div>
        )
      })}
    </div>
  )
}

function RiskMapTab({ vendors }: { vendors: Vendor[] }) {
  // 4x4 grid: X = Likelihood (1-4), Y = Impact (1-4, top=high)
  const grid: (Vendor[])[][] = Array.from({ length: 4 }, () => Array.from({ length: 4 }, () => []))

  const vendorPos: Record<string, { x: number; y: number }> = {
    'v1': { x: 0, y: 0 },
    'v2': { x: 2, y: 2 },
    'v3': { x: 1, y: 2 },
    'v4': { x: 3, y: 3 },
    'v5': { x: 1, y: 1 },
    'v6': { x: 0, y: 1 },
  }

  vendors.forEach(v => {
    const pos = vendorPos[v.id]
    if (pos) grid[3 - pos.y][pos.x].push(v)
  })

  const xLabels = ['低', '中低', '中高', '高']
  const yLabels = ['高', '中高', '中低', '低']
  const cellColor = (row: number, col: number) => {
    const risk = row + col
    if (risk <= 1) return 'bg-green-900/20'
    if (risk <= 3) return 'bg-yellow-900/20'
    if (risk <= 5) return 'bg-orange-900/20'
    return 'bg-red-900/20'
  }

  return (
    <div>
      <div className="flex gap-6">
        <div className="flex-1">
          <div className="text-center text-[#7d92b0] text-xs mb-2">発生可能性 →</div>
          <div className="flex items-start gap-1">
            <div className="flex flex-col justify-around h-[224px] mr-1">
              {yLabels.map(l => <span key={l} className="text-[#7d92b0] text-xs">{l}</span>)}
            </div>
            <div className="flex-1">
              <div className="grid grid-cols-4 gap-1">
                {grid.map((row, ri) =>
                  row.map((cell, ci) => (
                    <div key={`${ri}-${ci}`} className={`${cellColor(ri, ci)} border border-[#1e2d42] rounded h-14 p-1 flex flex-wrap gap-1 items-start content-start`}>
                      {cell.map(v => (
                        <div
                          key={v.id}
                          title={v.name}
                          className={`w-3 h-3 rounded-full flex-shrink-0 ${riskBadge[v.risk_level].split(' ')[0]}`}
                        />
                      ))}
                    </div>
                  ))
                )}
              </div>
              <div className="grid grid-cols-4 gap-1 mt-1">
                {xLabels.map(l => <div key={l} className="text-center text-[#7d92b0] text-xs">{l}</div>)}
              </div>
            </div>
          </div>
          <div className="text-center text-[#7d92b0] text-xs mt-1">← 影響度</div>
        </div>

        <div className="w-48">
          <div className="text-[#7d92b0] text-xs font-medium uppercase tracking-wider mb-2">凡例</div>
          <div className="space-y-2">
            {vendors.map(v => (
              <div key={v.id} className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full flex-shrink-0 ${riskBadge[v.risk_level].split(' ')[0]}`} />
                <span className="text-sm text-[#7d92b0] truncate">{v.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3 mt-6 pt-4 border-t border-[#1e2d42]">
        {(['critical', 'high', 'medium', 'low'] as RiskLevel[]).map(level => {
          const count = vendors.filter(v => v.risk_level === level).length
          return (
            <div key={level} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-center">
              <div className={`text-xl font-bold ${riskColor[level]}`}>{count}</div>
              <div className="text-[#7d92b0] text-xs mt-1">{riskLabel[level]}リスク</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SupplyChainRiskPage() {
  const [activeTab, setActiveTab] = useState<TabId>('vendors')

  const { data: vendors = [] } = useQuery<Vendor[]>({
    queryKey: ['supply-chain-vendors'],
    queryFn: () =>
      apiFetchList<Vendor>('/api/v1/admin/supply-chain-risk/vendors').catch(() => []),
  })

  const { data: incidents = [] } = useQuery<SCIncident[]>({
    queryKey: ['supply-chain-incidents'],
    queryFn: () =>
      apiFetchList<SCIncident>('/api/v1/admin/supply-chain-risk/incidents').catch(() => []),
  })

  const stats = [
    { label: '総ベンダー数', value: 47, icon: <Building2 size={16} className="text-blue-400" /> },
    { label: '重大リスク', value: 3, icon: <AlertTriangle size={16} className="text-red-400" /> },
    { label: '高リスク', value: 8, icon: <Shield size={16} className="text-orange-400" /> },
    { label: '評価待ち', value: 7, icon: <ClipboardList size={16} className="text-yellow-400" /> },
  ]

  const tabs: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: 'vendors', label: 'ベンダー一覧', icon: <Building2 size={14} /> },
    { id: 'incidents', label: 'インシデント', icon: <AlertTriangle size={14} /> },
    { id: 'riskmap', label: 'リスクマップ', icon: <BarChart3 size={14} /> },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">サプライチェーンリスク管理</h1>
        <p className="text-[#7d92b0] text-sm mt-1">Supply Chain Risk Management</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {stats.map(s => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-3">
            <div className="p-2 bg-[#070d19] rounded-lg">{s.icon}</div>
            <div>
              <div className="text-2xl font-bold text-white">{s.value}</div>
              <div className="text-[#7d92b0] text-xs">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="flex border-b border-[#1e2d42]">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-white'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>
        <div className="p-4">
          {activeTab === 'vendors' && <VendorsTab vendors={vendors} />}
          {activeTab === 'incidents' && <IncidentsTab incidents={incidents} />}
          {activeTab === 'riskmap' && <RiskMapTab vendors={vendors} />}
        </div>
      </div>
    </div>
  )
}
