'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Building2, AlertTriangle, Shield, Calendar,
  Filter, X, Plus, ExternalLink, ChevronRight,
  ClipboardList, TrendingUp, TrendingDown, Minus,
  CheckCircle, XCircle, Clock, Edit, Trash2,
} from 'lucide-react'
// ── Types ─────────────────────────────────────────────────────────────────────

type RiskTier = 'critical' | 'high' | 'medium' | 'low'
type VendorCategory = 'software' | 'hardware' | 'cloud' | 'service' | 'contractor'
type VendorStatus = 'active' | 'inactive' | 'under_review' | 'suspended'

interface Vendor {
  id: string
  name: string
  category: VendorCategory
  website: string
  contact_email: string
  risk_score: number
  risk_tier: RiskTier
  last_assessment_date: string | null
  next_assessment_due: string | null
  status: VendorStatus
  notes: string
  likelihood: number
  impact: number
}

interface Assessment {
  id: string
  vendor_id: string
  vendor_name: string
  assessor: string
  security_posture: number
  compliance: number
  availability: number
  data_protection: number
  incident_response: number
  overall_score: number
  previous_tier: RiskTier | null
  new_tier: RiskTier
  findings: string
  assessed_at: string
}

interface VendorStats {
  total: number
  critical_count: number
  high_count: number
  assessment_due_this_month: number
}

const today = new Date()

// ── Helpers ───────────────────────────────────────────────────────────────────

function calcRiskTier(score: number): RiskTier {
  if (score >= 81) return 'critical'
  if (score >= 61) return 'high'
  if (score >= 31) return 'medium'
  return 'low'
}

function calcOverall(scores: { security_posture: number; compliance: number; availability: number; data_protection: number; incident_response: number }): number {
  // Weights: security 30%, compliance 25%, data protection 25%, incident response 10%, availability 10%
  return Math.round(
    scores.security_posture * 0.30 +
    scores.compliance * 0.25 +
    scores.data_protection * 0.25 +
    scores.incident_response * 0.10 +
    scores.availability * 0.10
  )
}

const TIER_CONFIG: Record<RiskTier, { label: string; color: string; bg: string; dot: string }> = {
  critical: { label: 'クリティカル', color: 'text-red-300', bg: 'bg-red-500/20 border border-red-500/30', dot: 'bg-red-400' },
  high:     { label: '高',           color: 'text-orange-300', bg: 'bg-orange-500/20 border border-orange-500/30', dot: 'bg-orange-400' },
  medium:   { label: '中',           color: 'text-yellow-300', bg: 'bg-yellow-500/20 border border-yellow-500/30', dot: 'bg-yellow-400' },
  low:      { label: '低',           color: 'text-green-300', bg: 'bg-green-500/20 border border-green-500/30', dot: 'bg-green-400' },
}

const CATEGORY_CONFIG: Record<VendorCategory, { label: string; color: string }> = {
  software:   { label: 'ソフトウェア', color: 'bg-blue-500/20 text-blue-300 border border-blue-500/30' },
  hardware:   { label: 'ハードウェア', color: 'bg-purple-500/20 text-purple-300 border border-purple-500/30' },
  cloud:      { label: 'クラウド',     color: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' },
  service:    { label: 'サービス',     color: 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30' },
  contractor: { label: 'コントラクター', color: 'bg-pink-500/20 text-pink-300 border border-pink-500/30' },
}

const STATUS_CONFIG: Record<VendorStatus, { label: string; color: string }> = {
  active:       { label: 'アクティブ', color: 'bg-green-500/20 text-green-300 border border-green-500/30' },
  inactive:     { label: '非アクティブ', color: 'bg-[#1e2d42] text-[#7d92b0] border border-[#1e2d42]' },
  under_review: { label: 'レビュー中', color: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30' },
  suspended:    { label: '停止中', color: 'bg-red-500/20 text-red-300 border border-red-500/30' },
}

function formatDate(d: string | null): string {
  if (!d) return '—'
  try { return new Date(d).toLocaleDateString('ja-JP') } catch { return d }
}

function isOverdue(d: string | null): boolean {
  if (!d) return false
  return new Date(d) < today
}

function getRiskScoreColor(score: number): string {
  if (score >= 81) return 'bg-red-500'
  if (score >= 61) return 'bg-orange-500'
  if (score >= 31) return 'bg-yellow-500'
  return 'bg-green-500'
}

function getRiskScoreTextColor(score: number): string {
  if (score >= 81) return 'text-red-400'
  if (score >= 61) return 'text-orange-400'
  if (score >= 31) return 'text-yellow-400'
  return 'text-green-400'
}

// ── Risk Matrix Component ─────────────────────────────────────────────────────

function RiskMatrix({ vendors }: { vendors: Vendor[] }) {
  const labels = ['非常に低', '低', '中', '高', '非常に高']
  const cellSize = 80
  const padding = 48
  const svgW = padding + 5 * cellSize + 4
  const svgH = padding + 5 * cellSize + 4

  const tierColor: Record<RiskTier, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
  }

  // Map vendor likelihood/impact (1-5) to grid cell (0-4)
  const cellBackground = (col: number, row: number): string => {
    const risk = (col + 1) * (5 - row)
    if (risk >= 16) return '#ef4444'
    if (risk >= 10) return '#f97316'
    if (risk >= 6) return '#eab308'
    return '#22c55e'
  }

  return (
    <div className="overflow-x-auto">
      <div className="mb-2 text-xs text-[#7d92b0]">発生可能性 → （X軸）　　影響度 ↑ （Y軸）</div>
      <svg width={svgW} height={svgH} className="block">
        {/* Grid cells */}
        {Array.from({ length: 5 }, (_, row) =>
          Array.from({ length: 5 }, (_, col) => (
            <rect
              key={`${row}-${col}`}
              x={padding + col * cellSize + 1}
              y={padding + row * cellSize + 1}
              width={cellSize - 2}
              height={cellSize - 2}
              fill={cellBackground(col, row)}
              opacity={0.15}
              rx={2}
            />
          ))
        )}

        {/* Column labels (Likelihood) */}
        {labels.map((l, i) => (
          <text
            key={`col-${i}`}
            x={padding + i * cellSize + cellSize / 2}
            y={padding - 8}
            textAnchor="middle"
            fill="#7d92b0"
            fontSize={9}
          >{l}</text>
        ))}

        {/* Row labels (Impact) */}
        {labels.map((l, i) => (
          <text
            key={`row-${i}`}
            x={padding - 6}
            y={padding + (4 - i) * cellSize + cellSize / 2 + 4}
            textAnchor="end"
            fill="#7d92b0"
            fontSize={9}
          >{l}</text>
        ))}

        {/* Vendor dots */}
        {vendors.map(v => {
          const cx = padding + (v.likelihood - 1) * cellSize + cellSize / 2
          const cy = padding + (5 - v.impact) * cellSize + cellSize / 2
          const color = tierColor[v.risk_tier]
          return (
            <g key={v.id}>
              <circle cx={cx} cy={cy} r={10} fill={color} opacity={0.3} />
              <circle cx={cx} cy={cy} r={5} fill={color} />
              <title>{v.name} (スコア: {v.risk_score})</title>
            </g>
          )
        })}
      </svg>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-3 text-xs text-[#7d92b0]">
        {Object.entries(tierColor).map(([tier, color]) => (
          <span key={tier} className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full inline-block" style={{ background: color }} />
            {TIER_CONFIG[tier as RiskTier].label}
          </span>
        ))}
      </div>
    </div>
  )
}

// ── Slider Input ──────────────────────────────────────────────────────────────

function ScoreSlider({ label, value, onChange }: { label: string; value: number; onChange: (v: number) => void }) {
  const color = value >= 81 ? 'text-red-400' : value >= 61 ? 'text-orange-400' : value >= 31 ? 'text-yellow-400' : 'text-green-400'
  return (
    <div>
      <div className="flex justify-between items-center mb-1">
        <span className="text-sm text-[#7d92b0]">{label}</span>
        <span className={`text-sm font-bold tabular-nums ${color}`}>{value}</span>
      </div>
      <input
        type="range" min={0} max={100} value={value}
        onChange={e => onChange(Number(e.target.value))}
        className="w-full h-1.5 rounded-full appearance-none bg-[#1e2d42] accent-[#e8002d] cursor-pointer"
      />
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function VendorRiskPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'vendors' | 'assessments'>('vendors')
  const [tierFilter, setTierFilter] = useState<string>('all')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  // Add vendor modal
  const [showAddModal, setShowAddModal] = useState(false)
  const [newVendor, setNewVendor] = useState({ name: '', category: 'software' as VendorCategory, website: '', contact_email: '', notes: '' })

  // Assessment modal
  const [assessingVendor, setAssessingVendor] = useState<Vendor | null>(null)
  const [assessmentScores, setAssessmentScores] = useState({
    security_posture: 50, compliance: 50, availability: 50, data_protection: 50, incident_response: 50,
  })
  const [assessmentFindings, setAssessmentFindings] = useState('')

  const overallScore = calcOverall(assessmentScores)
  const computedTier = calcRiskTier(overallScore)

  // Queries
  const { data: statsData } = useQuery<VendorStats>({
    queryKey: ['vendor-risk-stats'],
    queryFn: () => apiFetch('/api/v1/vendor-risk/stats'),
    retry: false, staleTime: 30_000,
  })
  const EMPTY_STATS: VendorStats = { total: 0, critical_count: 0, high_count: 0, assessment_due_this_month: 0 }
  const stats = statsData ?? EMPTY_STATS

  const { data: vendorsData } = useQuery<{ items: Vendor[] }>({
    queryKey: ['vendor-risk-vendors'],
    queryFn: () => apiFetch('/api/v1/vendor-risk/vendors'),
    retry: false, staleTime: 30_000,
  })
  const vendors = vendorsData?.items ?? []

  const { data: assessmentsData } = useQuery<{ items: Assessment[] }>({
    queryKey: ['vendor-risk-assessments'],
    queryFn: () => apiFetch('/api/v1/vendor-risk/assessments'),
    retry: false, staleTime: 30_000,
  })
  const assessments = assessmentsData?.items ?? []

  // Mutations
  const addVendorMutation = useMutation({
    mutationFn: (data: typeof newVendor) => apiFetch('/api/v1/vendor-risk/vendors', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['vendor-risk-vendors'] }); setShowAddModal(false) },
    onError: () => setShowAddModal(false),
  })

  const submitAssessmentMutation = useMutation({
    mutationFn: ({ vendorId, payload }: { vendorId: string; payload: object }) =>
      apiFetch(`/api/v1/vendor-risk/vendors/${vendorId}/assessments`, { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-risk-vendors'] })
      queryClient.invalidateQueries({ queryKey: ['vendor-risk-assessments'] })
      setAssessingVendor(null)
    },
    onError: () => setAssessingVendor(null),
  })

  const filteredVendors = useMemo(() => vendors.filter(v => {
    if (tierFilter !== 'all' && v.risk_tier !== tierFilter) return false
    if (categoryFilter !== 'all' && v.category !== categoryFilter) return false
    if (statusFilter !== 'all' && v.status !== statusFilter) return false
    return true
  }), [vendors, tierFilter, categoryFilter, statusFilter])

  const upcomingAssessments = useMemo(() => {
    const cutoff = new Date(today); cutoff.setDate(cutoff.getDate() + 30)
    return vendors.filter(v => v.next_assessment_due && new Date(v.next_assessment_due) <= cutoff)
      .sort((a, b) => (a.next_assessment_due ?? '').localeCompare(b.next_assessment_due ?? ''))
  }, [vendors])

  function openAssessment(vendor: Vendor) {
    setAssessingVendor(vendor)
    setAssessmentScores({ security_posture: 50, compliance: 50, availability: 50, data_protection: 50, incident_response: 50 })
    setAssessmentFindings('')
  }

  function submitAssessment() {
    if (!assessingVendor) return
    const payload = { ...assessmentScores, overall_score: overallScore, findings: assessmentFindings }
    submitAssessmentMutation.mutate({ vendorId: assessingVendor.id, payload })
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">サードパーティリスク管理</h1>
        <p className="text-[#7d92b0] mt-1 text-sm">サプライチェーン・外部ベンダーのセキュリティリスク管理</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総ベンダー数', value: stats.total, icon: <Building2 className="w-5 h-5" />, color: 'text-blue-400', bg: 'bg-blue-500/10' },
          { label: 'クリティカル', value: stats.critical_count, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-400', bg: 'bg-red-500/10' },
          { label: '高リスク', value: stats.high_count, icon: <TrendingUp className="w-5 h-5" />, color: 'text-orange-400', bg: 'bg-orange-500/10' },
          { label: '今月評価期限', value: stats.assessment_due_this_month, icon: <Calendar className="w-5 h-5" />, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
        ].map(({ label, value, icon, color, bg }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${bg} ${color}`}>{icon}</div>
              <div>
                <p className="text-[#7d92b0] text-xs">{label}</p>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {[
          { id: 'vendors', label: 'ベンダー一覧' },
          { id: 'assessments', label: 'リスク評価' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as typeof activeTab)}
            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
              activeTab === tab.id ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Vendors Tab ── */}
      {activeTab === 'vendors' && (
        <div className="space-y-4">
          {/* Filters + Add button */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2 text-[#7d92b0] text-sm">
              <Filter className="w-4 h-4" />
              <span>フィルター:</span>
            </div>
            <select value={tierFilter} onChange={e => setTierFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">リスク階層: すべて</option>
              <option value="critical">クリティカル</option>
              <option value="high">高</option>
              <option value="medium">中</option>
              <option value="low">低</option>
            </select>
            <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">カテゴリー: すべて</option>
              <option value="software">ソフトウェア</option>
              <option value="hardware">ハードウェア</option>
              <option value="cloud">クラウド</option>
              <option value="service">サービス</option>
              <option value="contractor">コントラクター</option>
            </select>
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
              <option value="all">ステータス: すべて</option>
              <option value="active">アクティブ</option>
              <option value="inactive">非アクティブ</option>
              <option value="under_review">レビュー中</option>
              <option value="suspended">停止中</option>
            </select>
            {(tierFilter !== 'all' || categoryFilter !== 'all' || statusFilter !== 'all') && (
              <button onClick={() => { setTierFilter('all'); setCategoryFilter('all'); setStatusFilter('all') }}
                className="flex items-center gap-1 px-2 py-1.5 text-xs text-[#7d92b0] hover:text-white">
                <X className="w-3.5 h-3.5" /> クリア
              </button>
            )}
            <span className="text-[#7d92b0] text-sm">{filteredVendors.length} 件</span>
            <button
              onClick={() => setShowAddModal(true)}
              className="ml-auto flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded transition-colors"
            >
              <Plus className="w-4 h-4" />
              ベンダー追加
            </button>
          </div>

          {/* Vendors Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0a101d]">
                    <th className="text-left px-4 py-3">ベンダー名</th>
                    <th className="text-left px-4 py-3">カテゴリー</th>
                    <th className="text-left px-4 py-3">WEB</th>
                    <th className="text-left px-4 py-3 w-40">リスクスコア</th>
                    <th className="text-left px-4 py-3">リスク階層</th>
                    <th className="text-left px-4 py-3">前回評価日</th>
                    <th className="text-left px-4 py-3">次回評価期限</th>
                    <th className="text-left px-4 py-3">ステータス</th>
                    <th className="text-left px-4 py-3">アクション</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filteredVendors.map(vendor => {
                    const tier = TIER_CONFIG[vendor.risk_tier]
                    const cat = CATEGORY_CONFIG[vendor.category]
                    const st = STATUS_CONFIG[vendor.status]
                    const overdue = isOverdue(vendor.next_assessment_due)
                    return (
                      <tr key={vendor.id} className={`hover:bg-[#0d1830]/40 transition-colors ${vendor.risk_tier === 'critical' ? 'bg-red-500/3' : ''}`}>
                        <td className="px-4 py-3">
                          <span className="text-white font-medium">{vendor.name}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${cat.color}`}>{cat.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          {vendor.website ? (
                            <a href={vendor.website} target="_blank" rel="noopener noreferrer"
                              className="text-[#7d92b0] hover:text-blue-400 transition-colors">
                              <ExternalLink className="w-4 h-4" />
                            </a>
                          ) : <span className="text-[#3d5068]">—</span>}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div className={`h-full rounded-full ${getRiskScoreColor(vendor.risk_score)}`}
                                style={{ width: `${vendor.risk_score}%` }} />
                            </div>
                            <span className={`text-xs font-bold tabular-nums w-8 text-right ${getRiskScoreTextColor(vendor.risk_score)}`}>
                              {vendor.risk_score}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium flex items-center gap-1 w-fit ${tier.bg} ${tier.color}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${tier.dot}`} />
                            {tier.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">
                          {vendor.last_assessment_date ? formatDate(vendor.last_assessment_date) : (
                            <span className="text-red-400">未評価</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {vendor.next_assessment_due ? (
                            <span className={overdue ? 'text-red-400 font-medium' : 'text-[#7d92b0]'}>
                              {overdue && '⚠ '}{formatDate(vendor.next_assessment_due)}
                            </span>
                          ) : <span className="text-[#3d5068]">—</span>}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${st.color}`}>{st.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => openAssessment(vendor)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1d2f4a] hover:bg-[#243a5e] text-white text-xs rounded transition-colors"
                          >
                            <ClipboardList className="w-3.5 h-3.5" />
                            評価実施
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

      {/* ── Risk Assessment Tab ── */}
      {activeTab === 'assessments' && (
        <div className="space-y-6">
          {/* Risk Matrix */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#e8002d]" />
              リスクマトリクス
            </h3>
            <RiskMatrix vendors={vendors} />
          </div>

          {/* Upcoming Assessments */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
              <Calendar className="w-4 h-4 text-yellow-400" />
              今後30日以内の評価予定
            </h3>
            {upcomingAssessments.length === 0 ? (
              <p className="text-[#7d92b0] text-sm">今後30日以内の評価予定はありません</p>
            ) : (
              <div className="space-y-2">
                {upcomingAssessments.map(v => {
                  const overdue = isOverdue(v.next_assessment_due)
                  const tier = TIER_CONFIG[v.risk_tier]
                  return (
                    <div key={v.id} className={`flex items-center gap-4 px-4 py-3 rounded-lg border ${overdue ? 'border-red-500/30 bg-red-500/5' : 'border-[#1e2d42] bg-[#070d19]'}`}>
                      <span className={`text-xs font-medium ${overdue ? 'text-red-400' : 'text-[#7d92b0]'}`}>
                        {overdue ? '期限超過' : formatDate(v.next_assessment_due)}
                      </span>
                      <span className="text-white font-medium flex-1">{v.name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${tier.bg} ${tier.color}`}>{tier.label}</span>
                      <button onClick={() => { openAssessment(v); }}
                        className="flex items-center gap-1 px-3 py-1.5 bg-[#1d2f4a] hover:bg-[#243a5e] text-white text-xs rounded transition-colors">
                        <ClipboardList className="w-3.5 h-3.5" />
                        評価実施
                      </button>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Assessment History */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2d42]">
              <h3 className="text-white font-semibold">評価履歴</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0a101d]">
                    <th className="text-left px-4 py-3">ベンダー</th>
                    <th className="text-left px-4 py-3">評価者</th>
                    <th className="text-left px-4 py-3">総合スコア</th>
                    <th className="text-left px-4 py-3">階層変化</th>
                    <th className="text-left px-4 py-3">所見（抜粋）</th>
                    <th className="text-left px-4 py-3">評価日</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {assessments.map(a => {
                    const tierChanged = a.previous_tier && a.previous_tier !== a.new_tier
                    const improved = a.previous_tier && tierChanged &&
                      (['critical', 'high', 'medium', 'low'].indexOf(a.new_tier) > ['critical', 'high', 'medium', 'low'].indexOf(a.previous_tier))
                    return (
                      <tr key={a.id} className="hover:bg-[#0d1830]/40 transition-colors">
                        <td className="px-4 py-3 text-white font-medium">{a.vendor_name}</td>
                        <td className="px-4 py-3 text-[#7d92b0]">{a.assessor}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className={`text-sm font-bold ${getRiskScoreTextColor(100 - a.overall_score)}`}>{a.overall_score}</span>
                            <div className="w-16 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div className="h-full bg-blue-500 rounded-full" style={{ width: `${a.overall_score}%` }} />
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {!a.previous_tier ? (
                            <span className="text-[#7d92b0] text-xs">初回</span>
                          ) : !tierChanged ? (
                            <span className="flex items-center gap-1 text-[#7d92b0] text-xs"><Minus className="w-3.5 h-3.5" /> 変化なし</span>
                          ) : improved ? (
                            <span className="flex items-center gap-1 text-green-400 text-xs"><TrendingDown className="w-3.5 h-3.5" /> 改善</span>
                          ) : (
                            <span className="flex items-center gap-1 text-red-400 text-xs"><TrendingUp className="w-3.5 h-3.5" /> 悪化</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[240px]">
                          <span className="line-clamp-1">{a.findings}</span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                          {formatDate(a.assessed_at)}
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

      {/* ── Add Vendor Modal ── */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowAddModal(false)}>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-white font-semibold text-lg">ベンダー追加</h2>
              <button onClick={() => setShowAddModal(false)} className="text-[#7d92b0] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="text-[#7d92b0] text-xs mb-1 block">ベンダー名 *</label>
                <input type="text" value={newVendor.name} onChange={e => setNewVendor(p => ({ ...p, name: e.target.value }))}
                  placeholder="例: Acme Corporation"
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]/50" />
              </div>
              <div>
                <label className="text-[#7d92b0] text-xs mb-1 block">カテゴリー</label>
                <select value={newVendor.category} onChange={e => setNewVendor(p => ({ ...p, category: e.target.value as VendorCategory }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded text-sm text-white focus:outline-none focus:border-[#7d92b0]/50">
                  <option value="software">ソフトウェア</option>
                  <option value="hardware">ハードウェア</option>
                  <option value="cloud">クラウド</option>
                  <option value="service">サービス</option>
                  <option value="contractor">コントラクター</option>
                </select>
              </div>
              <div>
                <label className="text-[#7d92b0] text-xs mb-1 block">ウェブサイト</label>
                <input type="url" value={newVendor.website} onChange={e => setNewVendor(p => ({ ...p, website: e.target.value }))}
                  placeholder="https://example.com"
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]/50" />
              </div>
              <div>
                <label className="text-[#7d92b0] text-xs mb-1 block">連絡先メール</label>
                <input type="email" value={newVendor.contact_email} onChange={e => setNewVendor(p => ({ ...p, contact_email: e.target.value }))}
                  placeholder="security@vendor.com"
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]/50" />
              </div>
              <div>
                <label className="text-[#7d92b0] text-xs mb-1 block">備考</label>
                <textarea value={newVendor.notes} onChange={e => setNewVendor(p => ({ ...p, notes: e.target.value }))}
                  rows={3} placeholder="特記事項など..."
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]/50 resize-none" />
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button onClick={() => setShowAddModal(false)}
                className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded text-sm transition-colors">
                キャンセル
              </button>
              <button
                onClick={() => addVendorMutation.mutate(newVendor)}
                disabled={!newVendor.name}
                className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed text-white rounded text-sm font-medium transition-colors"
              >
                追加
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Assessment Modal ── */}
      {assessingVendor && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setAssessingVendor(null)}>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <div>
                <h2 className="text-white font-semibold text-lg">リスク評価: {assessingVendor.name}</h2>
                <p className="text-[#7d92b0] text-xs mt-0.5">{CATEGORY_CONFIG[assessingVendor.category].label}</p>
              </div>
              <button onClick={() => setAssessingVendor(null)} className="text-[#7d92b0] hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-5">
              <ScoreSlider label="セキュリティ体制" value={assessmentScores.security_posture}
                onChange={v => setAssessmentScores(p => ({ ...p, security_posture: v }))} />
              <ScoreSlider label="コンプライアンス遵守" value={assessmentScores.compliance}
                onChange={v => setAssessmentScores(p => ({ ...p, compliance: v }))} />
              <ScoreSlider label="可用性・信頼性" value={assessmentScores.availability}
                onChange={v => setAssessmentScores(p => ({ ...p, availability: v }))} />
              <ScoreSlider label="データ保護" value={assessmentScores.data_protection}
                onChange={v => setAssessmentScores(p => ({ ...p, data_protection: v }))} />
              <ScoreSlider label="インシデント対応能力" value={assessmentScores.incident_response}
                onChange={v => setAssessmentScores(p => ({ ...p, incident_response: v }))} />

              {/* Overall computed */}
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[#7d92b0] text-sm font-medium">総合スコア（自動計算）</span>
                  <span className={`text-2xl font-bold tabular-nums ${getRiskScoreTextColor(overallScore)}`}>{overallScore}</span>
                </div>
                <div className="w-full h-2 bg-[#1e2d42] rounded-full overflow-hidden mb-2">
                  <div className={`h-full rounded-full transition-all ${getRiskScoreColor(overallScore)}`}
                    style={{ width: `${overallScore}%` }} />
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[#7d92b0] text-xs">判定リスク階層:</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${TIER_CONFIG[computedTier].bg} ${TIER_CONFIG[computedTier].color}`}>
                    {TIER_CONFIG[computedTier].label}
                  </span>
                </div>
              </div>

              <div>
                <label className="text-[#7d92b0] text-xs mb-1 block">評価所見・推奨事項</label>
                <textarea value={assessmentFindings} onChange={e => setAssessmentFindings(e.target.value)}
                  rows={4} placeholder="発見された問題点、推奨改善事項などを記載..."
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#7d92b0]/50 resize-none" />
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button onClick={() => setAssessingVendor(null)}
                className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded text-sm transition-colors">
                キャンセル
              </button>
              <button onClick={submitAssessment}
                className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded text-sm font-medium transition-colors">
                評価を保存
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
