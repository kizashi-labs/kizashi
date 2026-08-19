'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BookMarked, Plus, X, ChevronDown, ChevronRight, Edit2,
  Filter, Download, AlertTriangle, TrendingUp, TrendingDown,
  Shield, Clock, User, BarChart2, ArrowUpDown, Search,
  CheckCircle, XCircle, MinusCircle, Target, Building2,
  Layers, AlertOctagon, Package, Save
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────────────────────

type RiskCategory = 'Strategic' | 'Operational' | 'Compliance' | 'Technical' | 'Third-party'
type RiskStatus = 'active' | 'mitigated' | 'transferred' | 'accepted' | 'closed'
type RiskAppetite = 'within' | 'exceeds' | 'at_limit'

interface RiskControl {
  id: string
  name: string
  effectiveness: number
}

interface TreatmentAction {
  id: string
  action: string
  owner: string
  due_date: string
  progress: number
}

interface RiskHistoryEntry {
  date: string
  score: number
  note: string
}

interface Risk {
  id: string
  risk_id: string
  title: string
  description: string
  category: RiskCategory
  threat_source: string
  vulnerability: string
  likelihood: number
  impact: number
  inherent_risk_score: number
  controls: RiskControl[]
  control_effectiveness: number
  residual_risk_score: number
  risk_appetite: RiskAppetite
  owner: string
  last_review_date: string
  status: RiskStatus
  treatment_plan: TreatmentAction[]
  risk_history: RiskHistoryEntry[]
  related_risk_ids?: string[]
}

interface AppetiteConfig {
  Strategic: number
  Operational: number
  Compliance: number
  Technical: number
  'Third-party': number
}

const DEFAULT_APPETITE: AppetiteConfig = { Strategic: 12, Operational: 8, Compliance: 4, Technical: 10, 'Third-party': 9 }

// ── Helpers ────────────────────────────────────────────────────────────────────

function residualColor(score: number) {
  if (score > 15) return 'text-red-400'
  if (score > 7) return 'text-orange-400'
  if (score > 3) return 'text-yellow-400'
  return 'text-green-400'
}

function residualBg(score: number) {
  if (score > 15) return 'bg-red-900/30 border-red-800/50'
  if (score > 7) return 'bg-orange-900/30 border-orange-800/50'
  if (score > 3) return 'bg-yellow-900/30 border-yellow-800/50'
  return 'bg-green-900/30 border-green-800/50'
}

const STATUS_STYLES: Record<RiskStatus, string> = {
  active: 'bg-blue-900/40 text-blue-400 border-blue-800/50',
  mitigated: 'bg-green-900/40 text-green-400 border-green-800/50',
  transferred: 'bg-purple-900/40 text-purple-400 border-purple-800/50',
  accepted: 'bg-yellow-900/40 text-yellow-400 border-yellow-800/50',
  closed: 'bg-[#1e2d42] text-[#7d92b0] border-[#2e4060]',
}

const STATUS_LABELS: Record<RiskStatus, string> = {
  active: 'アクティブ',
  mitigated: '低減済み',
  transferred: '移転',
  accepted: '受容',
  closed: 'クローズ',
}

const APPETITE_STYLES: Record<RiskAppetite, string> = {
  within: 'bg-green-900/40 text-green-400 border-green-800/50',
  at_limit: 'bg-yellow-900/40 text-yellow-400 border-yellow-800/50',
  exceeds: 'bg-red-900/40 text-red-400 border-red-800/50',
}

const APPETITE_LABELS: Record<RiskAppetite, string> = {
  within: '許容範囲内',
  at_limit: '上限値',
  exceeds: '超過',
}

const CATEGORY_ICONS: Record<RiskCategory, any> = {
  Strategic: Target,
  Operational: Layers,
  Compliance: Shield,
  Technical: AlertOctagon,
  'Third-party': Building2,
}

// ── Heat Map ───────────────────────────────────────────────────────────────────

function HeatMap({ risks }: { risks: Risk[] }) {
  const matrix: number[][] = Array.from({ length: 5 }, () => Array(5).fill(0))
  risks.forEach(r => {
    const l = Math.min(r.likelihood - 1, 4)
    const i = Math.min(r.impact - 1, 4)
    matrix[l][i]++
  })
  const cellColor = (count: number, row: number, col: number) => {
    const score = (row + 1) * (col + 1)
    if (count === 0) return 'bg-[#0d1220]'
    if (score > 15) return 'bg-red-900/80'
    if (score > 7) return 'bg-orange-900/80'
    if (score > 3) return 'bg-yellow-900/80'
    return 'bg-green-900/80'
  }
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1">
        <div className="w-6" />
        {['1', '2', '3', '4', '5'].map(i => (
          <div key={i} className="w-8 text-center text-[9px] text-[#3d5068]">{i}</div>
        ))}
        <div className="text-[9px] text-[#3d5068] ml-1">影響</div>
      </div>
      {[4, 3, 2, 1, 0].map(row => (
        <div key={row} className="flex items-center gap-1">
          <div className="w-6 text-[9px] text-[#3d5068] text-right">{row + 1}</div>
          {[0, 1, 2, 3, 4].map(col => (
            <div
              key={col}
              className={`w-8 h-8 rounded-sm border border-[#1e2d42] flex items-center justify-center text-[10px] font-bold text-white transition-colors
                ${cellColor(matrix[row][col], row, col)}`}
            >
              {matrix[row][col] > 0 ? matrix[row][col] : ''}
            </div>
          ))}
        </div>
      ))}
      <div className="text-[9px] text-[#3d5068] text-center ml-6">← 発生可能性</div>
    </div>
  )
}

// ── Risk Detail Modal ──────────────────────────────────────────────────────────

function RiskDetailModal({ risk, allRisks, onClose, onEdit }: {
  risk: Risk
  allRisks: Risk[]
  onClose: () => void
  onEdit: () => void
}) {
  const related = allRisks.filter(r => risk.related_risk_ids?.includes(r.id))
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="sticky top-0 bg-[#0d1220] border-b border-[#1e2d42] px-6 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            <span className="text-sm font-mono font-bold text-[#e8002d]">{risk.risk_id}</span>
            <h2 className="text-base font-bold text-white">{risk.title}</h2>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onEdit}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#e8002d]/10 text-[#e8002d] hover:bg-[#e8002d]/20 text-xs transition-colors"
            >
              <Edit2 className="w-3.5 h-3.5" /> 編集
            </button>
            <button onClick={onClose} className="p-1.5 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]"><X className="w-4 h-4" /></button>
          </div>
        </div>
        <div className="p-6 space-y-6">
          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-xs text-[#7d92b0] mb-1">カテゴリ</p>
              <p className="text-sm font-medium text-white">{risk.category}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-xs text-[#7d92b0] mb-1">オーナー</p>
              <p className="text-sm font-medium text-white">{risk.owner}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-xs text-[#7d92b0] mb-1">脅威源</p>
              <p className="text-sm text-[#c8d6e8]">{risk.threat_source}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-xs text-[#7d92b0] mb-1">脆弱性</p>
              <p className="text-sm text-[#c8d6e8]">{risk.vulnerability}</p>
            </div>
          </div>

          {/* Description */}
          <div>
            <p className="text-xs font-semibold text-[#7d92b0] mb-2">リスク説明</p>
            <p className="text-sm text-[#c8d6e8]">{risk.description}</p>
          </div>

          {/* Risk factors */}
          <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42]">
            <p className="text-xs font-semibold text-[#7d92b0] mb-3">リスク係数</p>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-xs text-[#7d92b0] mb-1">発生可能性</p>
                <p className="text-2xl font-bold text-orange-400">{risk.likelihood}</p>
                <p className="text-[10px] text-[#3d5068]">/ 5</p>
              </div>
              <div className="flex items-center justify-center text-[#3d5068] text-xl">×</div>
              <div>
                <p className="text-xs text-[#7d92b0] mb-1">影響度</p>
                <p className="text-2xl font-bold text-orange-400">{risk.impact}</p>
                <p className="text-[10px] text-[#3d5068]">/ 5</p>
              </div>
            </div>
            <div className="mt-3 pt-3 border-t border-[#1e2d42] flex items-center justify-between">
              <span className="text-xs text-[#7d92b0]">固有リスクスコア</span>
              <span className={`text-lg font-bold ${residualColor(risk.inherent_risk_score)}`}>{risk.inherent_risk_score}</span>
            </div>
          </div>

          {/* Controls */}
          <div>
            <p className="text-xs font-semibold text-[#7d92b0] mb-2">現在のコントロール</p>
            <div className="space-y-2">
              {risk.controls.map(c => (
                <div key={c.id} className="flex items-center gap-3 p-2 bg-[#070d19] rounded-sm border border-[#1e2d42]">
                  <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                  <span className="flex-1 text-sm text-[#c8d6e8]">{c.name}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-1.5 bg-[#1e2d42] rounded-full">
                      <div className="h-full bg-green-500 rounded-full" style={{ width: `${c.effectiveness}%` }} />
                    </div>
                    <span className="text-xs text-green-400 w-8 text-right">{c.effectiveness}%</span>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-3 flex items-center justify-between p-3 bg-[#070d19] rounded-sm border border-[#1e2d42]">
              <span className="text-sm text-[#7d92b0]">コントロール有効性（平均）</span>
              <span className="text-sm font-bold text-green-400">{risk.control_effectiveness}%</span>
            </div>
            <div className="mt-2 flex items-center justify-between p-3 bg-[#070d19] rounded-sm border border-[#1e2d42]">
              <span className="text-sm text-[#7d92b0]">残存リスクスコア</span>
              <span className={`text-lg font-bold ${residualColor(risk.residual_risk_score)}`}>{risk.residual_risk_score}</span>
            </div>
          </div>

          {/* Treatment plan */}
          {risk.treatment_plan.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-[#7d92b0] mb-2">対応計画</p>
              <div className="space-y-2">
                {risk.treatment_plan.map(t => (
                  <div key={t.id} className="p-3 bg-[#070d19] rounded-sm border border-[#1e2d42]">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-white">{t.action}</span>
                      <span className="text-xs text-[#3d5068]">{t.due_date}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-[#7d92b0]">{t.owner}</span>
                      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full">
                        <div className="h-full bg-[#e8002d] rounded-full transition-all" style={{ width: `${t.progress}%` }} />
                      </div>
                      <span className="text-xs text-[#e8002d]">{t.progress}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Risk history */}
          <div>
            <p className="text-xs font-semibold text-[#7d92b0] mb-2">リスクスコア履歴</p>
            <div className="space-y-1">
              {risk.risk_history.map((h, i) => (
                <div key={i} className="flex items-center gap-3 py-1.5 border-b border-[#1e2d42]">
                  <span className="text-xs text-[#3d5068] w-20">{h.date}</span>
                  <span className={`text-sm font-bold w-6 ${residualColor(h.score)}`}>{h.score}</span>
                  <span className="text-xs text-[#7d92b0]">{h.note}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Related risks */}
          {related.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-[#7d92b0] mb-2">関連リスク</p>
              <div className="space-y-1">
                {related.map(r => (
                  <div key={r.id} className="flex items-center gap-2 p-2 bg-[#070d19] rounded-sm border border-[#1e2d42]">
                    <span className="text-xs font-mono text-[#e8002d]">{r.risk_id}</span>
                    <span className="text-sm text-[#c8d6e8]">{r.title}</span>
                    <span className={`ml-auto text-xs font-bold ${residualColor(r.residual_risk_score)}`}>{r.residual_risk_score}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Add/Edit Risk Modal ────────────────────────────────────────────────────────

function RiskEditModal({ risk, onClose, onSave }: {
  risk: Risk | null
  onClose: () => void
  onSave: (data: Partial<Risk>) => void
}) {
  const [form, setForm] = useState<Partial<Risk>>(risk ?? {
    risk_id: '',
    title: '',
    category: 'Technical',
    description: '',
    threat_source: '',
    vulnerability: '',
    likelihood: 3,
    impact: 3,
    owner: '',
    status: 'active',
    controls: [],
    treatment_plan: [],
    risk_history: [],
  })

  const inherent = (form.likelihood ?? 1) * (form.impact ?? 1)

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-xl max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="sticky top-0 bg-[#0d1220] border-b border-[#1e2d42] px-6 py-4 flex items-center justify-between z-10">
          <h2 className="text-base font-bold text-white">{risk ? 'リスク編集' : '新規リスク登録'}</h2>
          <button onClick={onClose} className="p-1.5 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]"><X className="w-4 h-4" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">リスクID</label>
              <input value={form.risk_id ?? ''} readOnly className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-[#7d92b0] text-sm" />
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">カテゴリ *</label>
              <select value={form.category ?? 'Technical'} onChange={e => setForm(f => ({ ...f, category: e.target.value as RiskCategory }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden">
                {(['Strategic', 'Operational', 'Compliance', 'Technical', 'Third-party'] as RiskCategory[]).map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">タイトル *</label>
            <input value={form.title ?? ''} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">説明</label>
            <textarea value={form.description ?? ''} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={2} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">脅威源</label>
              <input value={form.threat_source ?? ''} onChange={e => setForm(f => ({ ...f, threat_source: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">オーナー</label>
              <input value={form.owner ?? ''} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">発生可能性 (1-5)</label>
              <input type="number" min={1} max={5} value={form.likelihood ?? 3} onChange={e => setForm(f => ({ ...f, likelihood: +e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden" />
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">影響度 (1-5)</label>
              <input type="number" min={1} max={5} value={form.impact ?? 3} onChange={e => setForm(f => ({ ...f, impact: +e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden" />
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">固有スコア</label>
              <div className={`px-3 py-2 rounded-sm border border-[#1e2d42] text-sm font-bold ${residualColor(inherent)}`}>{inherent}</div>
            </div>
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">ステータス</label>
            <select value={form.status ?? 'active'} onChange={e => setForm(f => ({ ...f, status: e.target.value as RiskStatus }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden">
              {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </div>
          <div className="flex gap-3 pt-2">
            <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
            <button
              onClick={() => onSave({ ...form, inherent_risk_score: inherent })}
              className="flex-1 py-2 rounded-sm bg-[#e8002d] text-white text-sm font-medium hover:bg-[#c00025] transition-colors"
            >
              {risk ? '更新' : '登録'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function RiskRegisterPage() {
  const queryClient = useQueryClient()
  const [filterCategory, setFilterCategory] = useState<string>('all')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [filterAppetite, setFilterAppetite] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [sortField, setSortField] = useState<'residual_risk_score' | 'inherent_risk_score' | 'last_review_date'>('residual_risk_score')
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc')
  const [selectedRisk, setSelectedRisk] = useState<Risk | null>(null)
  const [editRisk, setEditRisk] = useState<Risk | 'new' | null>(null)
  const [appetite, setAppetite] = useState<AppetiteConfig>(DEFAULT_APPETITE)
  const [appetiteStatement, setAppetiteStatement] = useState(
    '当社はセキュリティリスクに対して保守的な姿勢を取り、残存リスクスコアが各カテゴリの許容閾値を超えるリスクについては積極的に低減策を講じる。'
  )
  const [showBoardSection, setShowBoardSection] = useState(false)

  const { data: riskData = [] } = useQuery<Risk[]>({
    queryKey: ['risk-register'],
    queryFn: () => apiFetch<Risk[]>('/api/v1/admin/risk-register'),
    staleTime: 30_000,
    select: d => d ?? [],
  })

  const [localRisks, setLocalRisks] = useState<Risk[]>([])
  const risks = (riskData && riskData.length > 0 ? riskData : localRisks)

  const filtered = useMemo(() => {
    return risks
      .filter(r => {
        const catOk = filterCategory === 'all' || r.category === filterCategory
        const statusOk = filterStatus === 'all' || r.status === filterStatus
        const appetiteOk = filterAppetite === 'all' || r.risk_appetite === filterAppetite
        const q = searchQuery.toLowerCase()
        const textOk = !q || r.title.toLowerCase().includes(q) || r.risk_id.toLowerCase().includes(q) || r.owner.toLowerCase().includes(q)
        return catOk && statusOk && appetiteOk && textOk
      })
      .sort((a, b) => {
        const va = (a as any)[sortField]
        const vb = (b as any)[sortField]
        if (sortDir === 'desc') return vb > va ? 1 : -1
        return va > vb ? 1 : -1
      })
  }, [risks, filterCategory, filterStatus, filterAppetite, searchQuery, sortField, sortDir])

  const summary = useMemo(() => {
    const total = risks.length
    const critical = risks.filter(r => r.residual_risk_score > 15).length
    const high = risks.filter(r => r.residual_risk_score > 7 && r.residual_risk_score <= 15).length
    const medium = risks.filter(r => r.residual_risk_score > 3 && r.residual_risk_score <= 7).length
    const low = risks.filter(r => r.residual_risk_score <= 3).length
    const avg = +(risks.reduce((s, r) => s + r.residual_risk_score, 0) / Math.max(total, 1)).toFixed(1)
    const exceeds = risks.filter(r => r.risk_appetite === 'exceeds').length
    return { total, critical, high, medium, low, avg, exceeds }
  }, [risks])

  const top5 = useMemo(() => [...risks].sort((a, b) => b.residual_risk_score - a.residual_risk_score).slice(0, 5), [risks])

  const handleSaveRisk = (data: Partial<Risk>) => {
    if (editRisk === 'new') {
      const nr: Risk = {
        ...(data as Risk),
        id: String(Date.now()),
        risk_id: data.risk_id ?? `R-${String(localRisks.length + 1).padStart(3, '0')}`,
        controls: [],
        control_effectiveness: 0,
        residual_risk_score: data.inherent_risk_score ?? 0,
        risk_appetite: 'within',
        last_review_date: new Date().toISOString().slice(0, 10),
        treatment_plan: [],
        risk_history: [{ date: new Date().toISOString().slice(0, 10), score: data.inherent_risk_score ?? 0, note: '初期登録' }],
      }
      setLocalRisks(prev => [nr, ...prev])
    } else if (editRisk) {
      setLocalRisks(prev => prev.map(r => r.id === editRisk.id ? { ...r, ...data } : r))
    }
    setEditRisk(null)
  }

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) setSortDir(d => d === 'desc' ? 'asc' : 'desc')
    else { setSortField(field); setSortDir('desc') }
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-white flex flex-col">
      <PageDataUnavailable />
      {/* Header */}
      <div className="border-b border-[#1e2d42] px-6 py-4 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <BookMarked className="w-4 h-4 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">セキュリティリスク台帳</h1>
            <p className="text-xs text-[#7d92b0]">Security Risk Register — 企業リスク管理</p>
          </div>
        </div>
        <button
          onClick={() => setEditRisk('new')}
          className="flex items-center gap-2 px-4 py-2 rounded-sm bg-[#e8002d] text-white hover:bg-[#c00025] text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> リスク登録
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="p-6 space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: '総リスク数', value: summary.total, color: 'text-white', icon: BookMarked },
              { label: '重大（Critical）', value: summary.critical, color: 'text-red-400', icon: AlertOctagon },
              { label: '高（High）', value: summary.high, color: 'text-orange-400', icon: AlertTriangle },
              { label: '中（Medium）', value: summary.medium, color: 'text-yellow-400', icon: MinusCircle },
            ].map(({ label, value, color, icon: Icon }) => (
              <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs text-[#7d92b0]">{label}</p>
                  <Icon className={`w-4 h-4 ${color}`} />
                </div>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Additional stats */}
            <div className="lg:col-span-2 grid grid-cols-3 gap-4">
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <p className="text-xs text-[#7d92b0] mb-2">低（Low）</p>
                <p className="text-2xl font-bold text-green-400">{summary.low}</p>
              </div>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <p className="text-xs text-[#7d92b0] mb-2">平均残存スコア</p>
                <p className={`text-2xl font-bold ${residualColor(summary.avg)}`}>{summary.avg}</p>
              </div>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                <p className="text-xs text-[#7d92b0] mb-2">リスク許容超過</p>
                <p className="text-2xl font-bold text-red-400">{summary.exceeds}</p>
              </div>
            </div>

            {/* Heatmap */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <p className="text-xs font-semibold text-[#7d92b0] mb-3">リスクマトリクス（プレビュー）</p>
              <HeatMap risks={risks} />
            </div>
          </div>

          {/* Filters */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex flex-wrap gap-3 items-center">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
                <input
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="リスクを検索..."
                  className="bg-[#070d19] border border-[#1e2d42] rounded-sm pl-8 pr-3 py-1.5 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 w-48"
                />
              </div>
              <select value={filterCategory} onChange={e => setFilterCategory(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden">
                <option value="all">全カテゴリ</option>
                {(['Strategic', 'Operational', 'Compliance', 'Technical', 'Third-party'] as RiskCategory[]).map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden">
                <option value="all">全ステータス</option>
                {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <select value={filterAppetite} onChange={e => setFilterAppetite(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden">
                <option value="all">全リスク許容度</option>
                {Object.entries(APPETITE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <span className="text-xs text-[#3d5068] ml-auto">{filtered.length} 件</span>
            </div>
          </div>

          {/* Risk Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-[#1e2d42]">
                  <tr className="text-xs text-[#7d92b0]">
                    <th className="px-4 py-3 text-left font-semibold">ID</th>
                    <th className="px-4 py-3 text-left font-semibold">リスクタイトル</th>
                    <th className="px-4 py-3 text-left font-semibold">カテゴリ</th>
                    <th className="px-4 py-3 text-center font-semibold cursor-pointer hover:text-white" onClick={() => toggleSort('inherent_risk_score')}>
                      <span className="flex items-center gap-1 justify-center">固有スコア <ArrowUpDown className="w-3 h-3" /></span>
                    </th>
                    <th className="px-4 py-3 text-center font-semibold">有効性</th>
                    <th className="px-4 py-3 text-center font-semibold cursor-pointer hover:text-white" onClick={() => toggleSort('residual_risk_score')}>
                      <span className="flex items-center gap-1 justify-center">残存スコア <ArrowUpDown className="w-3 h-3" /></span>
                    </th>
                    <th className="px-4 py-3 text-center font-semibold">許容度</th>
                    <th className="px-4 py-3 text-left font-semibold">オーナー</th>
                    <th className="px-4 py-3 text-left font-semibold">ステータス</th>
                    <th className="px-4 py-3 text-center font-semibold">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(risk => {
                    const CatIcon = CATEGORY_ICONS[risk.category]
                    return (
                      <tr
                        key={risk.id}
                        className="border-b border-[#1e2d42] hover:bg-[#0a1018] cursor-pointer transition-colors"
                        onClick={() => setSelectedRisk(risk)}
                      >
                        <td className="px-4 py-3 font-mono text-xs text-[#e8002d] font-bold">{risk.risk_id}</td>
                        <td className="px-4 py-3 max-w-xs">
                          <p className="text-white font-medium truncate">{risk.title}</p>
                        </td>
                        <td className="px-4 py-3">
                          <span className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
                            <CatIcon className="w-3.5 h-3.5 text-[#3d5068]" />
                            {risk.category}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className={`text-sm font-bold ${residualColor(risk.inherent_risk_score)}`}>{risk.inherent_risk_score}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2 justify-center">
                            <div className="w-16 h-1.5 bg-[#1e2d42] rounded-full">
                              <div className="h-full bg-green-500 rounded-full" style={{ width: `${risk.control_effectiveness}%` }} />
                            </div>
                            <span className="text-xs text-green-400">{risk.control_effectiveness}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className={`inline-block px-2 py-0.5 rounded-sm border text-xs font-bold ${residualBg(risk.residual_risk_score)} ${residualColor(risk.residual_risk_score)}`}>
                            {risk.residual_risk_score}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className={`px-2 py-0.5 rounded-sm border text-xs ${APPETITE_STYLES[risk.risk_appetite]}`}>
                            {APPETITE_LABELS[risk.risk_appetite]}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-[#7d92b0]">{risk.owner}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm border text-xs ${STATUS_STYLES[risk.status]}`}>
                            {STATUS_LABELS[risk.status]}
                          </span>
                        </td>
                        <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                          <div className="flex items-center gap-1 justify-center">
                            <button
                              onClick={() => setSelectedRisk(risk)}
                              className="p-1.5 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
                            >
                              <ChevronRight className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => setEditRisk(risk)}
                              className="p-1.5 rounded-sm text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                            >
                              <Edit2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={10} className="px-4 py-12 text-center text-[#3d5068]">
                        <BookMarked className="w-8 h-8 mx-auto mb-2 opacity-40" />
                        リスクが見つかりません
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Risk Appetite Configuration */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Target className="w-4 h-4 text-[#e8002d]" /> リスク許容度設定
            </h3>
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-4">
              {(Object.keys(appetite) as (keyof AppetiteConfig)[]).map(cat => (
                <div key={cat} className="bg-[#070d19] rounded-sm border border-[#1e2d42] p-3">
                  <label className="text-xs text-[#7d92b0] mb-1 block">{cat}</label>
                  <input
                    type="number"
                    min={1}
                    max={25}
                    value={appetite[cat]}
                    onChange={e => setAppetite(prev => ({ ...prev, [cat]: +e.target.value }))}
                    className="w-full bg-transparent text-white text-lg font-bold focus:outline-hidden"
                  />
                  <p className="text-[10px] text-[#3d5068]">/ 25</p>
                </div>
              ))}
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">リスク許容度方針</label>
              <textarea
                value={appetiteStatement}
                onChange={e => setAppetiteStatement(e.target.value)}
                rows={2}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#c8d6e8] focus:outline-hidden focus:border-[#e8002d]/50 resize-none"
              />
            </div>
          </div>

          {/* Board Reporting */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-[#e8002d]" /> 取締役会報告
              </h3>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowBoardSection(!showBoardSection)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] hover:bg-[#2e3d52] hover:text-white text-xs transition-colors"
                >
                  {showBoardSection ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                  詳細
                </button>
                <button
                  onClick={() => alert('取締役会報告PDFを生成中... (モック)')}
                  className="flex items-center gap-2 px-4 py-1.5 rounded-sm bg-[#e8002d] text-white hover:bg-[#c00025] text-xs font-medium transition-colors"
                >
                  <Download className="w-3.5 h-3.5" /> 取締役会報告用エクスポート
                </button>
              </div>
            </div>
            {showBoardSection && (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-[#070d19] rounded-sm border border-[#1e2d42] p-3">
                    <p className="text-xs text-[#7d92b0] mb-1">リスク許容超過数</p>
                    <p className="text-2xl font-bold text-red-400">{summary.exceeds}</p>
                    <p className="text-[10px] text-[#3d5068]">前四半期比 +1</p>
                  </div>
                  <div className="bg-[#070d19] rounded-sm border border-[#1e2d42] p-3">
                    <p className="text-xs text-[#7d92b0] mb-1">平均残存リスク</p>
                    <p className={`text-2xl font-bold ${residualColor(summary.avg)}`}>{summary.avg}</p>
                    <p className="text-[10px] text-[#3d5068]">前四半期比 -0.8</p>
                  </div>
                  <div className="bg-[#070d19] rounded-sm border border-[#1e2d42] p-3">
                    <p className="text-xs text-[#7d92b0] mb-1">低減済みリスク</p>
                    <p className="text-2xl font-bold text-green-400">{risks.filter(r => r.status === 'mitigated').length}</p>
                    <p className="text-[10px] text-[#3d5068]">当四半期</p>
                  </div>
                </div>
                <div>
                  <p className="text-xs font-semibold text-[#7d92b0] mb-2">上位5リスク（残存スコア順）</p>
                  <div className="space-y-1.5">
                    {top5.map((r, i) => (
                      <div key={r.id} className="flex items-center gap-3 p-2 bg-[#070d19] rounded-sm border border-[#1e2d42]">
                        <span className="text-xs text-[#3d5068] w-4">{i + 1}</span>
                        <span className="text-xs font-mono text-[#e8002d]">{r.risk_id}</span>
                        <span className="flex-1 text-xs text-[#c8d6e8] truncate">{r.title}</span>
                        <span className={`text-xs font-bold ${residualColor(r.residual_risk_score)}`}>{r.residual_risk_score}</span>
                        <span className={`px-1.5 py-0.5 rounded-sm border text-[10px] ${APPETITE_STYLES[r.risk_appetite]}`}>{APPETITE_LABELS[r.risk_appetite]}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Modals */}
      {selectedRisk && (
        <RiskDetailModal
          risk={selectedRisk}
          allRisks={risks}
          onClose={() => setSelectedRisk(null)}
          onEdit={() => { setEditRisk(selectedRisk); setSelectedRisk(null) }}
        />
      )}
      {editRisk !== null && (
        <RiskEditModal
          risk={editRisk === 'new' ? null : editRisk}
          onClose={() => setEditRisk(null)}
          onSave={handleSaveRisk}
        />
      )}
    </div>
  )
}
