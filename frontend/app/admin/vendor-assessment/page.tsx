'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ClipboardList, Star, Plus, X, ChevronDown, ChevronUp,
  CheckCircle, XCircle, AlertTriangle, Clock, Edit,
  ExternalLink, Building2, Shield, BarChart3, GitCompare,
  FileText, Filter, Search, Minus,
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

type AssessmentCategory = 'EDR' | 'SIEM' | 'SOAR' | 'IAM' | 'Network' | 'Cloud' | 'GRC' | 'Other'
type AssessmentStatus = 'draft' | 'in_progress' | 'completed' | 'rejected' | 'approved'
type RiskRating = 'low' | 'medium' | 'high' | 'critical'
type Recommendation = 'approved' | 'conditional' | 'rejected'

interface ScoringCriterion {
  id: string
  label: string
  score: number // 1-5
  notes: string
}

interface ScoringSection {
  id: string
  label: string
  weight: number
  criteria: ScoringCriterion[]
}

interface VendorAssessment {
  id: string
  vendor_name: string
  product_name: string
  category: AssessmentCategory
  version: string
  use_case: string
  status: AssessmentStatus
  assessor: string
  submitted_date: string | null
  overall_score: number
  risk_rating: RiskRating
  recommendation: Recommendation | null
  conditions: string
  final_approver: string
  approval_date: string | null
  certifications: string[]
  website: string
  founding_year: number
  headquarters: string
  annual_revenue_estimate: string
  public_company: boolean
  identified_risks: string[]
  scoring_sections: ScoringSection[]
  template_id: string | null
}

interface AssessmentTemplate {
  id: string
  template_name: string
  category: AssessmentCategory
  question_count: number
  last_updated: string
  built_in: boolean
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const CATEGORY_COLORS: Record<AssessmentCategory, string> = {
  EDR: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  SIEM: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  SOAR: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  IAM: 'bg-green-500/20 text-green-300 border-green-500/30',
  Network: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  Cloud: 'bg-sky-500/20 text-sky-300 border-sky-500/30',
  GRC: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  Other: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
}

function calcOverallScore(sections: ScoringSection[]): number {
  if (!sections.length) return 0
  const totalWeight = sections.reduce((s, sec) => s + sec.weight, 0)
  if (!totalWeight) return 0
  return sections.reduce((s, sec) => {
    const avg = sec.criteria.length ? sec.criteria.reduce((a, c) => a + c.score, 0) / sec.criteria.length : 0
    return s + (avg / 5) * 100 * (sec.weight / totalWeight)
  }, 0)
}

function makeSections(category: string): ScoringSection[] {
  return [
    { id: 'sec-1', label: '技術的評価', weight: 0.4, criteria: [{ id: 'c1', label: '機能性', score: 3, notes: '' }, { id: 'c2', label: 'パフォーマンス', score: 3, notes: '' }] },
    { id: 'sec-2', label: 'セキュリティ', weight: 0.3, criteria: [{ id: 'c3', label: '認証・認可', score: 3, notes: '' }] },
    { id: 'sec-3', label: 'サポート・SLA', weight: 0.3, criteria: [{ id: 'c4', label: 'サポート品質', score: 3, notes: '' }] },
  ]
}

const STATUS_CONFIG: Record<AssessmentStatus, { label: string; color: string; icon: React.ReactNode }> = {
  draft: { label: '下書き', color: 'bg-gray-500/20 text-gray-300 border-gray-500/30', icon: <FileText className="w-3 h-3" /> },
  in_progress: { label: '評価中', color: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30', icon: <Clock className="w-3 h-3" /> },
  completed: { label: '完了', color: 'bg-blue-500/20 text-blue-300 border-blue-500/30', icon: <CheckCircle className="w-3 h-3" /> },
  rejected: { label: '却下', color: 'bg-red-500/20 text-red-300 border-red-500/30', icon: <XCircle className="w-3 h-3" /> },
  approved: { label: '承認済', color: 'bg-green-500/20 text-green-300 border-green-500/30', icon: <CheckCircle className="w-3 h-3" /> },
}

const RISK_COLORS: Record<RiskRating, string> = {
  low: 'bg-green-500/20 text-green-300 border-green-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
}

const RECOM_COLORS: Record<Recommendation, string> = {
  approved: 'bg-green-500/20 text-green-300 border-green-500/30',
  conditional: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  rejected: 'bg-red-500/20 text-red-300 border-red-500/30',
}
const RECOM_LABELS: Record<Recommendation, string> = {
  approved: '承認推奨', conditional: '条件付き承認', rejected: '採用不可',
}

function ScoreDot({ score }: { score: number }) {
  const color = score >= 4 ? 'bg-green-400' : score === 3 ? 'bg-yellow-400' : 'bg-red-400'
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${color}`} />
}

function ScoreBar({ value, max = 100 }: { value: number; max?: number }) {
  const pct = (value / max) * 100
  const color = pct >= 70 ? '#00c853' : pct >= 50 ? '#ffc107' : '#e8002d'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-falcon-border rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs text-white font-medium w-8 text-right">{value}</span>
    </div>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function CollapsibleSection({ section }: { section: ScoringSection }) {
  const [open, setOpen] = useState(false)
  const avg = section.criteria.reduce((s, c) => s + c.score, 0) / section.criteria.length
  const pct = Math.round((avg / 5) * 100)

  return (
    <div className="border border-falcon-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-[#0d1a2d] transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span className="text-white font-medium text-sm">{section.label}</span>
          <span className="text-xs text-falcon-muted">({section.criteria.length}項目)</span>
          <span className="text-xs text-falcon-muted">重み: {(section.weight * 100).toFixed(0)}%</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-24">
            <ScoreBar value={pct} />
          </div>
          {open ? <ChevronUp className="w-4 h-4 text-falcon-muted" /> : <ChevronDown className="w-4 h-4 text-falcon-muted" />}
        </div>
      </button>
      {open && (
        <div className="border-t border-falcon-border divide-y divide-falcon-border/50">
          {section.criteria.map(c => (
            <div key={c.id} className="flex items-center justify-between px-4 py-2.5 bg-[#070d19]/50">
              <span className="text-sm text-falcon-muted">{c.label}</span>
              <div className="flex items-center gap-2">
                {[1, 2, 3, 4, 5].map(n => (
                  <span key={n} className={`w-5 h-5 rounded-sm text-[10px] font-bold flex items-center justify-center border ${n <= c.score ? 'bg-falcon-red border-falcon-red text-white' : 'border-falcon-border text-falcon-subtle'}`}>{n}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function AssessmentDetailPanel({ a, onClose, allAssessments }: { a: VendorAssessment; onClose: () => void; allAssessments: VendorAssessment[] }) {
  const [compareMode, setCompareMode] = useState(false)
  const score = a.scoring_sections.length > 0 ? calcOverallScore(a.scoring_sections) : a.overall_score
  const comparable = allAssessments.filter(x => x.id !== a.id && x.category === a.category && x.scoring_sections.length > 0)

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end bg-black/60 backdrop-blur-xs" onClick={onClose}>
      <div
        className="w-full max-w-2xl h-full bg-falcon-surface border-l border-falcon-border overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 z-10 bg-falcon-surface border-b border-falcon-border px-6 py-4 flex items-center justify-between">
          <div>
            <h2 className="text-white font-semibold text-lg">{a.vendor_name}</h2>
            <p className="text-falcon-muted text-sm">{a.product_name} v{a.version}</p>
          </div>
          <div className="flex items-center gap-2">
            {comparable.length > 0 && (
              <button
                onClick={() => setCompareMode(v => !v)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-sm border transition-colors ${compareMode ? 'bg-falcon-red/20 border-falcon-red/50 text-falcon-red' : 'border-falcon-border text-falcon-muted hover:border-falcon-muted/40'}`}
              >
                <GitCompare className="w-3.5 h-3.5" />
                他のベンダーと比較
              </button>
            )}
            <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Score hero */}
          <div className="grid grid-cols-3 gap-4">
            <div className="col-span-1 bg-[#070d19] border border-falcon-border rounded-lg p-4 text-center">
              <p className="text-falcon-muted text-xs mb-1">総合スコア</p>
              <p className={`text-4xl font-black ${score >= 70 ? 'text-green-400' : score >= 50 ? 'text-yellow-400' : 'text-red-400'}`}>{score}</p>
              <p className="text-falcon-muted text-[10px] mt-1">/ 100</p>
            </div>
            <div className="col-span-2 bg-[#070d19] border border-falcon-border rounded-lg p-4 space-y-2">
              {a.scoring_sections.slice(0, 3).map(sec => (
                <div key={sec.id}>
                  <div className="flex justify-between text-xs mb-0.5">
                    <span className="text-falcon-muted">{sec.label}</span>
                    <span className="text-white">{Math.round(sec.criteria.reduce((s, c) => s + c.score, 0) / sec.criteria.length * 20)}点</span>
                  </div>
                  <ScoreBar value={Math.round(sec.criteria.reduce((s, c) => s + c.score, 0) / sec.criteria.length * 20)} />
                </div>
              ))}
            </div>
          </div>

          {/* Compare mode */}
          {compareMode && comparable.length > 0 && (
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
              <h3 className="text-white font-medium text-sm mb-3">スコア比較 ({a.category})</h3>
              <div className="space-y-2">
                {[a, ...comparable].map(v => {
                  const sc = v.scoring_sections.length > 0 ? calcOverallScore(v.scoring_sections) : v.overall_score
                  return (
                    <div key={v.id} className="flex items-center gap-3">
                      <span className={`text-sm w-36 truncate ${v.id === a.id ? 'text-white font-medium' : 'text-falcon-muted'}`}>{v.vendor_name}</span>
                      <div className="flex-1">
                        <ScoreBar value={sc} />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Vendor info */}
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
            <h3 className="text-white font-medium text-sm mb-3 flex items-center gap-2"><Building2 className="w-4 h-4 text-falcon-red" />ベンダー情報</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div><span className="text-falcon-muted">設立:</span> <span className="text-white ml-2">{a.founding_year}年</span></div>
              <div><span className="text-falcon-muted">本社:</span> <span className="text-white ml-2">{a.headquarters}</span></div>
              <div><span className="text-falcon-muted">売上推定:</span> <span className="text-white ml-2">{a.annual_revenue_estimate}</span></div>
              <div><span className="text-falcon-muted">上場:</span> <span className={`ml-2 font-medium ${a.public_company ? 'text-green-400' : 'text-falcon-muted'}`}>{a.public_company ? '上場企業' : '非上場'}</span></div>
              <div className="col-span-2 flex items-center gap-2">
                <span className="text-falcon-muted">Webサイト:</span>
                <a href={a.website} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 flex items-center gap-1 ml-2 text-xs">
                  {a.website} <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
            {a.certifications.length > 0 && (
              <div className="mt-3">
                <span className="text-falcon-muted text-xs">認証・認定:</span>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {a.certifications.map(c => (
                    <span key={c} className="px-2 py-0.5 bg-green-500/10 border border-green-500/20 text-green-300 text-xs rounded-full flex items-center gap-1">
                      <Shield className="w-2.5 h-2.5" />{c}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Scoring sections */}
          <div>
            <h3 className="text-white font-medium text-sm mb-3">スコアリング詳細</h3>
            <div className="space-y-2">
              {a.scoring_sections.map(sec => <CollapsibleSection key={sec.id} section={sec} />)}
            </div>
          </div>

          {/* Risks */}
          {a.identified_risks.length > 0 && (
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
              <h3 className="text-white font-medium text-sm mb-3 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-400" />特定リスク</h3>
              <div className="flex flex-wrap gap-2">
                {a.identified_risks.map(r => (
                  <span key={r} className="px-2.5 py-1 bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 text-xs rounded-full">{r}</span>
                ))}
              </div>
            </div>
          )}

          {/* Decision */}
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
            <h3 className="text-white font-medium text-sm mb-3">評価決定</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-falcon-muted">推奨事項:</span>
                {a.recommendation ? (
                  <span className={`ml-2 px-2 py-0.5 rounded-sm text-xs border ${RECOM_COLORS[a.recommendation]}`}>{RECOM_LABELS[a.recommendation]}</span>
                ) : <span className="text-falcon-muted ml-2">未決定</span>}
              </div>
              <div><span className="text-falcon-muted">最終承認者:</span> <span className="text-white ml-2">{a.final_approver || '—'}</span></div>
              {a.conditions && (
                <div className="col-span-2">
                  <span className="text-falcon-muted">条件:</span>
                  <p className="text-white text-xs mt-1 bg-yellow-500/5 border border-yellow-500/20 rounded-sm p-2">{a.conditions}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function CreateAssessmentModal({ templates, onClose, onCreated }: { templates: AssessmentTemplate[]; onClose: () => void; onCreated: (a: Partial<VendorAssessment>) => void }) {
  const [form, setForm] = useState({
    vendor_name: '', product_name: '', category: 'EDR' as AssessmentCategory,
    version: '', use_case: '', template_id: '', assessor: '',
  })
  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs" onClick={onClose}>
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg p-6 shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-lg">新規評価案件を作成</h2>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-falcon-muted mb-1.5 block">ベンダー名 *</label>
              <input value={form.vendor_name} onChange={e => set('vendor_name', e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" placeholder="例: CrowdStrike" />
            </div>
            <div>
              <label className="text-xs text-falcon-muted mb-1.5 block">製品名 *</label>
              <input value={form.product_name} onChange={e => set('product_name', e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" placeholder="例: Falcon Insight XDR" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-falcon-muted mb-1.5 block">カテゴリ</label>
              <select value={form.category} onChange={e => set('category', e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50">
                {(['EDR', 'SIEM', 'SOAR', 'IAM', 'Network', 'Cloud', 'GRC', 'Other'] as AssessmentCategory[]).map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-falcon-muted mb-1.5 block">バージョン</label>
              <input value={form.version} onChange={e => set('version', e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" placeholder="例: 7.2" />
            </div>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1.5 block">導入目的</label>
            <input value={form.use_case} onChange={e => set('use_case', e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" placeholder="例: 次世代EDR/XDR導入" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-falcon-muted mb-1.5 block">テンプレート</label>
              <select value={form.template_id} onChange={e => set('template_id', e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50">
                <option value="">テンプレートなし</option>
                {templates.map(t => <option key={t.id} value={t.id}>{t.template_name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-falcon-muted mb-1.5 block">評価担当者</label>
              <input value={form.assessor} onChange={e => set('assessor', e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" placeholder="担当者名" />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/40 text-sm transition-colors">キャンセル</button>
          <button
            onClick={() => { if (form.vendor_name && form.product_name) { onCreated(form); onClose() } }}
            className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
          >
            評価案件を作成
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function VendorAssessmentPage() {
  const [tab, setTab] = useState<'cases' | 'templates'>('cases')
  const [selectedAssessment, setSelectedAssessment] = useState<VendorAssessment | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [filterCategory, setFilterCategory] = useState<AssessmentCategory | 'all'>('all')
  const [filterStatus, setFilterStatus] = useState<AssessmentStatus | 'all'>('all')
  const [searchQ, setSearchQ] = useState('')
  const [localAssessments, setLocalAssessments] = useState<VendorAssessment[]>([])

  const { data: remoteAssessments } = useQuery<VendorAssessment[]>({
    queryKey: ['vendor-assessments'],
    queryFn: () => apiFetch('/api/v1/admin/vendor-assessments'),
    staleTime: 60_000,
    retry: false,
  })

  const { data: remoteTemplates } = useQuery<AssessmentTemplate[]>({
    queryKey: ['vendor-assessment-templates'],
    queryFn: () => apiFetch('/api/v1/admin/vendor-assessments/templates'),
    staleTime: 60_000,
    retry: false,
  })

  const assessments = remoteAssessments ?? localAssessments
  const templates = remoteTemplates ?? []

  const filtered = useMemo(() => assessments.filter(a => {
    if (filterCategory !== 'all' && a.category !== filterCategory) return false
    if (filterStatus !== 'all' && a.status !== filterStatus) return false
    if (searchQ && !a.vendor_name.toLowerCase().includes(searchQ.toLowerCase()) && !a.product_name.toLowerCase().includes(searchQ.toLowerCase())) return false
    return true
  }), [assessments, filterCategory, filterStatus, searchQ])

  const stats = useMemo(() => ({
    total: assessments.length,
    in_progress: assessments.filter(a => a.status === 'in_progress').length,
    approved: assessments.filter(a => a.status === 'approved').length,
    high_risk: assessments.filter(a => a.risk_rating === 'high' || a.risk_rating === 'critical').length,
  }), [assessments])

  const handleCreated = (partial: Partial<VendorAssessment>) => {
    const newA: VendorAssessment = {
      id: `va-${Date.now()}`,
      vendor_name: partial.vendor_name ?? '',
      product_name: partial.product_name ?? '',
      category: partial.category ?? 'Other',
      version: partial.version ?? '',
      use_case: partial.use_case ?? '',
      status: 'draft',
      assessor: partial.assessor ?? '',
      submitted_date: null,
      overall_score: 0,
      risk_rating: 'low',
      recommendation: null,
      conditions: '',
      final_approver: '',
      approval_date: null,
      certifications: [],
      website: '',
      founding_year: 0,
      headquarters: '',
      annual_revenue_estimate: '',
      public_company: false,
      identified_risks: [],
      scoring_sections: makeSections('C'),
      template_id: partial.template_id ?? null,
    }
    setLocalAssessments(prev => [newA, ...prev])
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-muted">
      {/* Header */}
      <div className="border-b border-falcon-border bg-falcon-surface px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-falcon-red/10 border border-falcon-red/20 rounded-lg">
              <ClipboardList className="w-5 h-5 text-falcon-red" />
            </div>
            <div>
              <h1 className="text-white font-semibold text-xl">セキュリティベンダー評価</h1>
              <p className="text-falcon-muted text-sm">調達前・更新時のセキュリティ能力評価</p>
            </div>
          </div>
          {tab === 'cases' && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              新規評価案件
            </button>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mt-4">
          {[
            { label: '総評価案件', value: stats.total, color: 'text-white' },
            { label: '評価中', value: stats.in_progress, color: 'text-yellow-400' },
            { label: '承認済み', value: stats.approved, color: 'text-green-400' },
            { label: '高リスク', value: stats.high_risk, color: 'text-falcon-red' },
          ].map(s => (
            <div key={s.label} className="bg-[#070d19] border border-falcon-border rounded-lg px-4 py-3">
              <p className="text-falcon-muted text-xs">{s.label}</p>
              <p className={`text-2xl font-bold ${s.color} mt-0.5`}>{s.value}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="px-6 pt-4 border-b border-falcon-border">
        <div className="flex gap-1">
          {([['cases', '評価案件'], ['templates', '評価テンプレート']] as const).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors ${tab === id ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'}`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="p-6">
        {tab === 'cases' && (
          <div className="space-y-4">
            {/* Filters */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
                <input
                  value={searchQ} onChange={e => setSearchQ(e.target.value)}
                  placeholder="ベンダー名・製品名で検索..."
                  className="w-full pl-9 pr-4 py-2 bg-falcon-surface border border-falcon-border rounded-lg text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                />
              </div>
              <select value={filterCategory} onChange={e => setFilterCategory(e.target.value as AssessmentCategory | 'all')} className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm text-falcon-muted focus:outline-hidden">
                <option value="all">全カテゴリ</option>
                {(['EDR', 'SIEM', 'SOAR', 'IAM', 'Network', 'Cloud', 'GRC', 'Other'] as AssessmentCategory[]).map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value as AssessmentStatus | 'all')} className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm text-falcon-muted focus:outline-hidden">
                <option value="all">全ステータス</option>
                <option value="draft">下書き</option>
                <option value="in_progress">評価中</option>
                <option value="completed">完了</option>
                <option value="approved">承認済</option>
                <option value="rejected">却下</option>
              </select>
            </div>

            {/* Table */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['ベンダー名', 'カテゴリ', 'ステータス', '評価者', '提出日', 'スコア', 'リスク', '推奨', '操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border/50">
                  {filtered.map(a => {
                    const sc = a.scoring_sections.length > 0 ? calcOverallScore(a.scoring_sections) : a.overall_score
                    const status = STATUS_CONFIG[a.status]
                    return (
                      <tr key={a.id} className="hover:bg-[#070d19]/50 transition-colors">
                        <td className="px-4 py-3">
                          <p className="text-white font-medium">{a.vendor_name}</p>
                          <p className="text-falcon-muted text-xs">{a.product_name}</p>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs font-medium border ${CATEGORY_COLORS[a.category]}`}>{a.category}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs border flex items-center gap-1 w-fit ${status.color}`}>{status.icon}{status.label}</span>
                        </td>
                        <td className="px-4 py-3 text-falcon-muted text-xs">{a.assessor || '—'}</td>
                        <td className="px-4 py-3 text-falcon-muted text-xs">{a.submitted_date ?? '—'}</td>
                        <td className="px-4 py-3">
                          {sc > 0 ? (
                            <div className="w-20">
                              <ScoreBar value={sc} />
                            </div>
                          ) : <span className="text-falcon-subtle">—</span>}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs border ${RISK_COLORS[a.risk_rating]}`}>{a.risk_rating}</span>
                        </td>
                        <td className="px-4 py-3">
                          {a.recommendation ? (
                            <span className={`px-2 py-0.5 rounded-sm text-xs border ${RECOM_COLORS[a.recommendation]}`}>{RECOM_LABELS[a.recommendation]}</span>
                          ) : <span className="text-falcon-subtle">—</span>}
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => setSelectedAssessment(a)}
                            className="px-2.5 py-1 bg-falcon-border hover:bg-[#253a56] text-falcon-muted hover:text-white text-xs rounded-sm transition-colors"
                          >
                            詳細
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                  {filtered.length === 0 && (
                    <tr><td colSpan={9} className="px-4 py-12 text-center text-falcon-subtle">条件に一致する評価案件が見つかりません</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === 'templates' && (
          <div className="space-y-4">
            <div className="flex justify-end">
              <button className="flex items-center gap-2 px-4 py-2 border border-falcon-border hover:border-falcon-muted/40 text-falcon-muted hover:text-white text-sm rounded-lg transition-colors">
                <Plus className="w-4 h-4" />
                テンプレートを作成
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {templates.map(t => (
                <div key={t.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-5 hover:border-falcon-red/30 transition-colors">
                  <div className="flex items-start justify-between mb-3">
                    <div className="p-2 bg-falcon-red/10 border border-falcon-red/20 rounded-lg">
                      <FileText className="w-4 h-4 text-falcon-red" />
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded-sm text-xs border ${CATEGORY_COLORS[t.category]}`}>{t.category}</span>
                      {t.built_in && <span className="px-2 py-0.5 bg-blue-500/10 border border-blue-500/20 text-blue-300 text-xs rounded-sm">組み込み</span>}
                    </div>
                  </div>
                  <h3 className="text-white font-medium mb-1">{t.template_name}</h3>
                  <p className="text-falcon-muted text-sm">{t.question_count} 質問項目</p>
                  <p className="text-falcon-subtle text-xs mt-1">最終更新: {t.last_updated}</p>
                  <button className="mt-4 w-full py-2 bg-falcon-red/10 hover:bg-falcon-red/20 border border-falcon-red/30 text-falcon-red text-sm rounded-lg transition-colors">
                    このテンプレートを使用
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {selectedAssessment && (
        <AssessmentDetailPanel
          a={selectedAssessment}
          onClose={() => setSelectedAssessment(null)}
          allAssessments={assessments}
        />
      )}
      {showCreateModal && (
        <CreateAssessmentModal
          templates={templates}
          onClose={() => setShowCreateModal(false)}
          onCreated={handleCreated}
        />
      )}
    </div>
  )
}
