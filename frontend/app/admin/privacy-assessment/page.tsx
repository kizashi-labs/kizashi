'use client'

import { useState, useMemo } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Plus, X, ChevronRight, CheckCircle, Clock,
  AlertTriangle, Search, RefreshCw, User, Calendar,
  Info, FileText, Download, Check, ChevronDown,
  AlertCircle, Eye,
} from 'lucide-react'


// ── Types ────────────────────────────────────────────────────────────────────

type AssessmentType = 'PIA' | 'DPIA'
type PIAStatus = 'draft' | 'in_progress' | 'dpo_review' | 'approved' | 'overdue'
type RiskLevel = 'low' | 'medium' | 'high' | 'very_high'
type LegalBasis = 'consent' | 'contract' | 'legal_obligation' | 'vital_interests' | 'public_task' | 'legitimate_interests'
type DataCategory = 'personal' | 'sensitive' | 'financial' | 'health' | 'biometric' | 'location' | 'children'

interface PrivacyRisk {
  id: string
  name: string
  likelihood: number   // 1-5
  impact: number       // 1-5
  score: number        // likelihood × impact
  mitigation: string
  residual_risk: 'low' | 'medium' | 'high'
}

interface DataNecessity {
  category: DataCategory
  is_necessary: boolean | null
  justification: string
}

interface PIA {
  id: string
  title: string
  system_name: string
  assessment_type: AssessmentType
  status: PIAStatus
  risk_level: RiskLevel
  data_controller: string
  dpo_consulted: boolean
  dpo_consultation_date?: string
  dpo_notes?: string
  started_date: string
  completed_date?: string
  next_review_date?: string
  description: string
  processing_purpose: string
  legal_basis?: LegalBasis
  data_categories: DataCategory[]
  data_subjects: string
  data_recipients: string
  retention_period: string
  international_transfers: boolean
  minimization_measures: string
  necessities: DataNecessity[]
  risks: PrivacyRisk[]
  current_step: number  // 1-5
  approval_comment?: string
  approved_by?: string
  supervisory_authority_required: boolean
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<PIAStatus, { label: string; cls: string }> = {
  draft: { label: 'ドラフト', cls: 'bg-gray-900/40 border-gray-700 text-gray-300' },
  in_progress: { label: '進行中', cls: 'bg-blue-900/40 border-blue-700 text-blue-300' },
  dpo_review: { label: 'DPO審査中', cls: 'bg-yellow-900/40 border-yellow-700 text-yellow-300' },
  approved: { label: '承認済み', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  overdue: { label: '期限超過', cls: 'bg-red-900/60 border-red-700 text-red-300' },
}

const RISK_LEVEL_CONFIG: Record<RiskLevel, { label: string; cls: string }> = {
  low: { label: '低リスク', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  medium: { label: '中リスク', cls: 'bg-yellow-900/40 border-yellow-700 text-yellow-300' },
  high: { label: '高リスク', cls: 'bg-orange-900/40 border-orange-700 text-orange-300' },
  very_high: { label: '最高リスク', cls: 'bg-red-900/60 border-red-700 text-red-300' },
}

const DATA_CAT_CONFIG: Record<DataCategory, { label: string; cls: string }> = {
  personal: { label: '個人情報', cls: 'bg-blue-900/40 border-blue-700 text-blue-300' },
  sensitive: { label: '要配慮個人情報', cls: 'bg-purple-900/40 border-purple-700 text-purple-300' },
  financial: { label: '金融情報', cls: 'bg-yellow-900/40 border-yellow-700 text-yellow-300' },
  health: { label: '健康情報', cls: 'bg-red-900/40 border-red-700 text-red-300' },
  biometric: { label: '生体情報', cls: 'bg-orange-900/40 border-orange-700 text-orange-300' },
  location: { label: '位置情報', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  children: { label: '子供のデータ', cls: 'bg-pink-900/40 border-pink-700 text-pink-300' },
}

const LEGAL_BASIS_LABELS: Record<LegalBasis, string> = {
  consent: '同意',
  contract: '契約の履行',
  legal_obligation: '法的義務',
  vital_interests: '生命に関わる利益',
  public_task: '公的任務',
  legitimate_interests: '正当な利益',
}

const RESIDUAL_RISK_CONFIG = {
  low: 'bg-green-900/40 border-green-700 text-green-300',
  medium: 'bg-yellow-900/40 border-yellow-700 text-yellow-300',
  high: 'bg-red-900/60 border-red-700 text-red-300',
}

function riskScoreColor(score: number) {
  if (score >= 15) return 'text-red-400'
  if (score >= 8) return 'text-orange-400'
  if (score >= 4) return 'text-yellow-400'
  return 'text-green-400'
}

function riskCellColor(val: number) {
  if (val >= 4) return 'bg-red-900/60'
  if (val >= 3) return 'bg-orange-900/40'
  if (val >= 2) return 'bg-yellow-900/40'
  return 'bg-green-900/20'
}

function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium ${cls}`}>{children}</span>
}

const STEPS = [
  { num: 1, label: '処理活動の説明' },
  { num: 2, label: '必要性・比例性評価' },
  { num: 3, label: 'リスク評価' },
  { num: 4, label: 'リスク軽減措置' },
  { num: 5, label: 'DPO協議・承認' },
]

// ── Create PIA Modal ─────────────────────────────────────────────────────────

function CreatePIAModal({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({
    title: '',
    system_name: '',
    assessment_type: 'PIA' as AssessmentType,
    description: '',
    data_controller: '',
    processing_purpose: '',
    data_categories: [] as DataCategory[],
  })
  const qc = useQueryClient()

  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))
  const toggleCat = (cat: DataCategory) => {
    setForm(f => ({
      ...f,
      data_categories: f.data_categories.includes(cat)
        ? f.data_categories.filter(c => c !== cat)
        : [...f.data_categories, cat],
    }))
  }

  const handleSubmit = async () => {
    try {
      await apiFetch('/api/v1/admin/pia', { method: 'POST', body: JSON.stringify(form) })
    } catch { /* mock */ }
    qc.invalidateQueries({ queryKey: ['pia-list'] })
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-6 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-lg">新規 PIA/DPIA 作成</h2>
          <button onClick={onClose} className="p-2 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">タイトル *</label>
              <input value={form.title} onChange={e => set('title', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" placeholder="例: 顧客分析システム DPIA" />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">システム/プロセス名</label>
              <input value={form.system_name} onChange={e => set('system_name', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">評価種別</label>
              <select value={form.assessment_type} onChange={e => set('assessment_type', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#7d92b0] text-sm focus:outline-none focus:border-[#e8002d]/50">
                <option value="PIA">PIA（プライバシー影響評価）</option>
                <option value="DPIA">DPIA（データ保護影響評価）</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">データ管理者</label>
              <input value={form.data_controller} onChange={e => set('data_controller', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" />
            </div>
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">処理目的</label>
              <input value={form.processing_purpose} onChange={e => set('processing_purpose', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" />
            </div>
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-2">データカテゴリ（複数選択可）</label>
              <div className="flex flex-wrap gap-2">
                {(Object.keys(DATA_CAT_CONFIG) as DataCategory[]).map(cat => {
                  const selected = form.data_categories.includes(cat)
                  return (
                    <button
                      key={cat}
                      onClick={() => toggleCat(cat)}
                      className={`px-3 py-1.5 rounded border text-xs font-medium transition-colors ${selected ? DATA_CAT_CONFIG[cat].cls : 'bg-[#070d19] border-[#1e2d42] text-[#3d5068] hover:text-[#7d92b0]'}`}
                    >
                      {DATA_CAT_CONFIG[cat].label}
                    </button>
                  )
                })}
              </div>
            </div>
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">説明</label>
              <textarea value={form.description} onChange={e => set('description', e.target.value)} rows={3} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors resize-none" />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 p-6 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:text-white transition-colors">キャンセル</button>
          <button onClick={handleSubmit} className="px-4 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-semibold hover:bg-[#c0001f] transition-colors">作成</button>
        </div>
      </div>
    </div>
  )
}

// ── PIA Wizard ────────────────────────────────────────────────────────────────

function PIAWizard({ pia, onClose }: { pia: PIA; onClose: () => void }) {
  const [step, setStep] = useState(pia.current_step)
  const [form, setForm] = useState({
    processing_purpose: pia.processing_purpose,
    legal_basis: pia.legal_basis ?? 'consent' as LegalBasis,
    data_subjects: pia.data_subjects,
    data_recipients: pia.data_recipients,
    retention_period: pia.retention_period,
    international_transfers: pia.international_transfers,
    minimization_measures: pia.minimization_measures,
    necessities: pia.necessities.map(n => ({ ...n })),
    risks: pia.risks.map(r => ({ ...r })),
    dpo_consulted: pia.dpo_consulted,
    dpo_consultation_date: pia.dpo_consultation_date ?? '',
    dpo_notes: pia.dpo_notes ?? '',
    approval_comment: pia.approval_comment ?? '',
    custom_risk_name: '',
  })

  const setF = (k: string, v: string | boolean) => setForm(f => ({ ...f, [k]: v }))

  const updateNecessity = (idx: number, k: string, v: string | boolean | null) => {
    setForm(f => {
      const n = [...f.necessities]
      n[idx] = { ...n[idx], [k]: v }
      return { ...f, necessities: n }
    })
  }

  const updateRisk = (id: string, k: string, v: string | number) => {
    setForm(f => ({
      ...f,
      risks: f.risks.map(r => {
        if (r.id !== id) return r
        const updated = { ...r, [k]: v }
        if (k === 'likelihood' || k === 'impact') {
          updated.score = Number(updated.likelihood) * Number(updated.impact)
        }
        return updated
      }),
    }))
  }

  const addCustomRisk = () => {
    if (!form.custom_risk_name.trim()) return
    const newRisk: PrivacyRisk = {
      id: `custom_${Date.now()}`,
      name: form.custom_risk_name,
      likelihood: 1,
      impact: 1,
      score: 1,
      mitigation: '',
      residual_risk: 'low',
    }
    setForm(f => ({ ...f, risks: [...f.risks, newRisk], custom_risk_name: '' }))
  }

  const handleSave = async () => {
    try {
      await apiFetch(`/api/v1/admin/pia/${pia.id}`, { method: 'PUT', body: JSON.stringify({ ...form, current_step: step }) })
    } catch { /* mock */ }
    onClose()
  }

  const highResidualRisks = form.risks.filter(r => r.residual_risk === 'high')

  return (
    <div className="fixed inset-0 z-40 bg-black/80 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-4xl max-h-[92vh] flex flex-col" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start gap-4 p-6 border-b border-[#1e2d42]">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <Badge cls={pia.assessment_type === 'DPIA' ? 'bg-orange-900/40 border-orange-700 text-orange-300' : 'bg-blue-900/40 border-blue-700 text-blue-300'}>{pia.assessment_type}</Badge>
              <Badge cls={RISK_LEVEL_CONFIG[pia.risk_level].cls}>{RISK_LEVEL_CONFIG[pia.risk_level].label}</Badge>
            </div>
            <h2 className="text-white font-bold text-lg">{pia.title}</h2>
            <p className="text-[#7d92b0] text-sm">{pia.system_name}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => alert('PDFエクスポートは実装予定です')}
              className="flex items-center gap-1.5 px-3 py-2 bg-[#0a1628] border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg text-sm transition-colors"
            >
              <Download className="w-4 h-4" /> PIAレポート出力
            </button>
            <button onClick={onClose} className="p-2 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
          </div>
        </div>

        {/* Step indicators */}
        <div className="px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center">
            {STEPS.map((s, i) => (
              <div key={s.num} className="flex items-center flex-1 last:flex-none">
                <button
                  onClick={() => setStep(s.num)}
                  className="flex flex-col items-center group"
                >
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold transition-colors ${
                    step === s.num ? 'bg-[#e8002d] text-white' :
                    s.num < step ? 'bg-green-900/50 border border-green-700 text-green-300' :
                    'bg-[#0a1628] border border-[#1e2d42] text-[#3d5068]'
                  }`}>
                    {s.num < step ? <Check className="w-4 h-4" /> : s.num}
                  </div>
                  <span className={`text-xs mt-1 text-center max-w-[80px] leading-tight transition-colors ${step === s.num ? 'text-white' : 'text-[#3d5068]'}`}>{s.label}</span>
                </button>
                {i < STEPS.length - 1 && (
                  <div className={`flex-1 h-px mx-2 mb-4 ${s.num < step ? 'bg-green-700' : 'bg-[#1e2d42]'}`} />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Step Content */}
        <div className="flex-1 overflow-y-auto p-6">

          {/* Step 1: Processing Activities */}
          {step === 1 && (
            <div className="space-y-4">
              <h3 className="text-white font-semibold text-lg">処理活動の説明</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">処理目的</label>
                  <textarea value={form.processing_purpose} onChange={e => setF('processing_purpose', e.target.value)} rows={2} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors resize-none" />
                </div>
                <div>
                  <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">法的根拠</label>
                  <select value={form.legal_basis} onChange={e => setF('legal_basis', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#7d92b0] text-sm focus:outline-none focus:border-[#e8002d]/50">
                    {(Object.keys(LEGAL_BASIS_LABELS) as LegalBasis[]).map(lb => (
                      <option key={lb} value={lb}>{LEGAL_BASIS_LABELS[lb]}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">保存期間</label>
                  <input value={form.retention_period} onChange={e => setF('retention_period', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" />
                </div>
                <div className="col-span-2">
                  <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">データ主体</label>
                  <input value={form.data_subjects} onChange={e => setF('data_subjects', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" />
                </div>
                <div className="col-span-2">
                  <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">データ受領者</label>
                  <input value={form.data_recipients} onChange={e => setF('data_recipients', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" />
                </div>
                <div className="col-span-2">
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setF('international_transfers', !form.international_transfers)}
                      className={`w-12 h-6 rounded-full relative transition-colors ${form.international_transfers ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
                    >
                      <span className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] transition-transform ${form.international_transfers ? 'translate-x-7' : 'translate-x-1'}`} />
                    </button>
                    <span className="text-white text-sm">国際データ移転あり</span>
                    {form.international_transfers && (
                      <Badge cls="bg-orange-900/40 border-orange-700 text-orange-300">SCCまたは十分性認定が必要</Badge>
                    )}
                  </div>
                </div>
                <div className="col-span-2">
                  <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">処理するデータカテゴリ</p>
                  <div className="flex flex-wrap gap-2">
                    {pia.data_categories.map(cat => (
                      <Badge key={cat} cls={DATA_CAT_CONFIG[cat].cls}>{DATA_CAT_CONFIG[cat].label}</Badge>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 2: Necessity & Proportionality */}
          {step === 2 && (
            <div className="space-y-4">
              <h3 className="text-white font-semibold text-lg">必要性・比例性評価</h3>
              <p className="text-[#7d92b0] text-sm">各データカテゴリが処理目的に対して必要かどうかを評価してください。</p>
              <div className="space-y-3">
                {form.necessities.map((n, idx) => (
                  <div key={idx} className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                    <div className="flex items-center gap-3 mb-3">
                      <Badge cls={DATA_CAT_CONFIG[n.category].cls}>{DATA_CAT_CONFIG[n.category].label}</Badge>
                      <span className="text-white font-medium text-sm">このデータカテゴリは処理目的に必要ですか？</span>
                    </div>
                    <div className="flex gap-3 mb-3">
                      {[true, false].map(val => (
                        <button
                          key={String(val)}
                          onClick={() => updateNecessity(idx, 'is_necessary', val)}
                          className={`px-4 py-2 rounded border text-sm font-medium transition-colors ${
                            n.is_necessary === val
                              ? val ? 'bg-green-900/40 border-green-700 text-green-300' : 'bg-red-900/60 border-red-700 text-red-300'
                              : 'bg-[#0d1220] border-[#1e2d42] text-[#3d5068] hover:text-[#7d92b0]'
                          }`}
                        >
                          {val ? '✓ はい、必要です' : '✗ いいえ、不要です'}
                        </button>
                      ))}
                    </div>
                    <textarea
                      value={n.justification}
                      onChange={e => updateNecessity(idx, 'justification', e.target.value)}
                      placeholder="根拠・理由を入力..."
                      rows={2}
                      className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors resize-none"
                    />
                  </div>
                ))}
              </div>
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-2">データ最小化措置</label>
                <textarea
                  value={form.minimization_measures}
                  onChange={e => setF('minimization_measures', e.target.value)}
                  placeholder="収集・利用するデータを最小限にするための措置を記述してください..."
                  rows={3}
                  className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors resize-none"
                />
              </div>
            </div>
          )}

          {/* Step 3: Risk Assessment */}
          {step === 3 && (
            <div className="space-y-4">
              <h3 className="text-white font-semibold text-lg">リスク評価</h3>
              <p className="text-[#7d92b0] text-sm">各プライバシーリスクの可能性（1-5）と影響度（1-5）を評価してください。</p>

              {/* Risk Matrix Legend */}
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                <p className="text-[#7d92b0] text-xs mb-3">リスクスコア = 可能性 × 影響度</p>
                <div className="flex gap-3 flex-wrap">
                  {[['1-3', '低', 'text-green-400'], ['4-8', '中', 'text-yellow-400'], ['9-15', '高', 'text-orange-400'], ['16-25', '最高', 'text-red-400']].map(([range, label, cls]) => (
                    <div key={range} className="flex items-center gap-1.5">
                      <span className={`font-bold text-sm ${cls}`}>{range}</span>
                      <span className="text-[#7d92b0] text-xs">= {label}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                {form.risks.map(risk => (
                  <div key={risk.id} className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-white font-medium text-sm">{risk.name}</span>
                      <span className={`text-2xl font-black ${riskScoreColor(risk.score)}`}>{risk.score}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-[#7d92b0] text-xs block mb-2">可能性 ({risk.likelihood}/5)</label>
                        <div className="flex gap-1">
                          {[1, 2, 3, 4, 5].map(v => (
                            <button
                              key={v}
                              onClick={() => updateRisk(risk.id, 'likelihood', v)}
                              className={`w-8 h-8 rounded text-xs font-bold transition-colors ${risk.likelihood >= v ? riskCellColor(v) + ' text-white' : 'bg-[#0d1220] text-[#3d5068]'}`}
                            >
                              {v}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div>
                        <label className="text-[#7d92b0] text-xs block mb-2">影響度 ({risk.impact}/5)</label>
                        <div className="flex gap-1">
                          {[1, 2, 3, 4, 5].map(v => (
                            <button
                              key={v}
                              onClick={() => updateRisk(risk.id, 'impact', v)}
                              className={`w-8 h-8 rounded text-xs font-bold transition-colors ${risk.impact >= v ? riskCellColor(v) + ' text-white' : 'bg-[#0d1220] text-[#3d5068]'}`}
                            >
                              {v}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Add Custom Risk */}
              <div className="flex gap-2">
                <input
                  value={form.custom_risk_name}
                  onChange={e => setF('custom_risk_name', e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addCustomRisk()}
                  placeholder="カスタムリスクを追加..."
                  className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors"
                />
                <button onClick={addCustomRisk} className="px-4 py-2 bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d] rounded-lg text-sm font-medium hover:bg-[#e8002d]/20 transition-colors">
                  <Plus className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Step 4: Risk Mitigation */}
          {step === 4 && (
            <div className="space-y-4">
              <h3 className="text-white font-semibold text-lg">リスク軽減措置</h3>
              <p className="text-[#7d92b0] text-sm">各リスクに対する軽減措置と残余リスクを設定してください。</p>
              <div className="space-y-4">
                {form.risks.map(risk => (
                  <div key={risk.id} className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                    <div className="flex items-center gap-3 mb-3">
                      <span className="text-white font-medium text-sm">{risk.name}</span>
                      <span className={`text-sm font-bold ${riskScoreColor(risk.score)}`}>スコア: {risk.score}</span>
                    </div>
                    <div className="mb-3">
                      <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">軽減措置</label>
                      <textarea
                        value={risk.mitigation}
                        onChange={e => updateRisk(risk.id, 'mitigation', e.target.value)}
                        placeholder="このリスクを軽減するための措置を記述してください..."
                        rows={2}
                        className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors resize-none"
                      />
                    </div>
                    <div>
                      <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-2">措置後の残余リスク</label>
                      <div className="flex gap-2">
                        {(['low', 'medium', 'high'] as const).map(level => (
                          <button
                            key={level}
                            onClick={() => updateRisk(risk.id, 'residual_risk', level)}
                            className={`px-3 py-1.5 rounded border text-xs font-medium transition-colors ${risk.residual_risk === level ? RESIDUAL_RISK_CONFIG[level] : 'bg-[#0d1220] border-[#1e2d42] text-[#3d5068] hover:text-[#7d92b0]'}`}
                          >
                            {level === 'low' ? '低' : level === 'medium' ? '中' : '高'}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Step 5: DPO Consultation & Approval */}
          {step === 5 && (
            <div className="space-y-4">
              <h3 className="text-white font-semibold text-lg">DPO協議・承認</h3>

              {/* DPO Consultation */}
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                <h4 className="text-white font-medium mb-4">DPO（個人情報保護責任者）協議</h4>
                <div className="flex items-center gap-3 mb-4">
                  <button
                    onClick={() => setF('dpo_consulted', !form.dpo_consulted)}
                    className={`w-12 h-6 rounded-full relative transition-colors ${form.dpo_consulted ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
                  >
                    <span className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] transition-transform ${form.dpo_consulted ? 'translate-x-7' : 'translate-x-1'}`} />
                  </button>
                  <span className="text-white text-sm">DPOに協議済み</span>
                </div>
                {form.dpo_consulted && (
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">協議日</label>
                      <input type="date" value={form.dpo_consultation_date} onChange={e => setF('dpo_consultation_date', e.target.value)} className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors" />
                    </div>
                    <div className="col-span-2">
                      <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">DPOコメント</label>
                      <textarea value={form.dpo_notes} onChange={e => setF('dpo_notes', e.target.value)} rows={3} className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors resize-none" />
                    </div>
                  </div>
                )}
              </div>

              {/* Supervisory Authority */}
              {highResidualRisks.length > 0 && (
                <div className="bg-red-900/20 border border-red-800/40 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                    <span className="text-red-300 font-semibold">監督機関への事前協議が必要な可能性があります</span>
                  </div>
                  <p className="text-red-200 text-sm">
                    {highResidualRisks.length}件の高リスク項目の残余リスクが「高」のままです。
                    GDPR第35条・36条に基づき、監督機関への事前協議が必要な場合があります。
                  </p>
                  <div className="mt-2 space-y-1">
                    {highResidualRisks.map(r => (
                      <p key={r.id} className="text-red-300 text-xs">• {r.name}</p>
                    ))}
                  </div>
                </div>
              )}

              {/* Final Approval */}
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                <h4 className="text-white font-medium mb-3">最終承認</h4>
                <textarea
                  value={form.approval_comment}
                  onChange={e => setF('approval_comment', e.target.value)}
                  placeholder="承認コメントを入力..."
                  rows={3}
                  className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors resize-none mb-3"
                />
                <div className="flex gap-2">
                  <button className="flex items-center gap-1.5 px-4 py-2 bg-green-900/30 border border-green-700 text-green-300 rounded-lg text-sm font-medium hover:bg-green-900/50 transition-colors">
                    <Check className="w-4 h-4" /> 承認
                  </button>
                  <button className="flex items-center gap-1.5 px-4 py-2 bg-red-900/30 border border-red-700 text-red-300 rounded-lg text-sm font-medium hover:bg-red-900/50 transition-colors">
                    <X className="w-4 h-4" /> 否認
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between p-6 border-t border-[#1e2d42]">
          <button
            onClick={() => setStep(s => Math.max(1, s - 1))}
            disabled={step === 1}
            className="flex items-center gap-1.5 px-4 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm font-medium hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← 前へ
          </button>
          <div className="flex items-center gap-2">
            <button onClick={handleSave} className="px-4 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:text-white transition-colors">
              保存
            </button>
            {step < 5 && (
              <button
                onClick={() => setStep(s => Math.min(5, s + 1))}
                className="flex items-center gap-1.5 px-4 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-semibold hover:bg-[#c0001f] transition-colors"
              >
                次へ →
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function PrivacyAssessmentPage() {
  const [selectedPIA, setSelectedPIA] = useState<PIA | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [search, setSearch] = useState('')

  const { data: piaData } = useQuery<PIA[]>({
    queryKey: ['pia-list'],
    queryFn: () => apiFetch('/api/v1/admin/pia'),
    retry: false,
  })

  const pias = useMemo(() => piaData ?? [], [piaData])

  const filtered = useMemo(() => {
    if (!search.trim()) return pias
    const q = search.toLowerCase()
    return pias.filter(p => p.title.toLowerCase().includes(q) || p.system_name.toLowerCase().includes(q) || p.data_controller.toLowerCase().includes(q))
  }, [pias, search])

  const stats = useMemo(() => ({
    total: pias.length,
    dpiaRequired: pias.filter(p => p.assessment_type === 'DPIA').length,
    completed: pias.filter(p => p.status === 'approved').length,
    overdue: pias.filter(p => p.status === 'overdue').length,
  }), [pias])

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-purple-900/30 border border-purple-800/40 flex items-center justify-center">
            <Shield className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h1 className="text-white text-xl font-bold">プライバシー影響評価 (PIA/DPIA)</h1>
            <p className="text-[#7d92b0] text-sm">Privacy Impact Assessment / Data Protection Impact Assessment</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-2 px-4 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-[#7d92b0] hover:text-white text-sm transition-colors">
            <RefreshCw className="w-4 h-4" /> 更新
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-semibold hover:bg-[#c0001f] transition-colors"
          >
            <Plus className="w-4 h-4" /> 新規 PIA/DPIA
          </button>
        </div>
      </div>

      {/* GDPR Article 35 Banner */}
      <div className="bg-blue-900/20 border border-blue-700/40 rounded-xl p-4 mb-6 flex items-start gap-3">
        <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-blue-300 font-semibold text-sm">GDPR 第35条 – データ保護影響評価</p>
          <p className="text-blue-200/80 text-sm mt-1">
            GDPRの高リスク処理にはDPIAが必要です。大規模な特別カテゴリデータの処理、公開場所の大規模監視、プロファイリング等が該当します。
            高リスクが残存する場合は監督機関への事前協議が必要です（GDPR第36条）。
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: '総評価数', value: stats.total, icon: FileText, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-800/40' },
          { label: 'DPIA必要件数', value: stats.dpiaRequired, icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-800/40' },
          { label: '完了件数', value: stats.completed, icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-900/20 border-green-800/40' },
          { label: '期限超過', value: stats.overdue, icon: Clock, color: 'text-red-400', bg: 'bg-red-900/20 border-red-800/40' },
        ].map(s => {
          const Icon = s.icon
          return (
            <div key={s.label} className={`bg-[#0d1220] border rounded-xl p-4 ${s.bg}`}>
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-[#7d92b0] text-xs">{s.label}</span>
              </div>
              <p className={`text-3xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          )
        })}
      </div>

      {/* Search */}
      <div className="mb-4 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="タイトル・システム名・管理者で検索..."
          className="w-full max-w-md bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 text-sm transition-colors"
        />
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['タイトル / システム名', '種別', 'ステータス', 'リスクレベル', 'データ管理者', 'DPO協議', '開始日', '完了日', '次回レビュー', '操作'].map(h => (
                  <th key={h} className="text-left text-[#7d92b0] text-xs font-medium uppercase tracking-wider px-4 py-3 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {filtered.map(pia => {
                const st = STATUS_CONFIG[pia.status]
                const rl = RISK_LEVEL_CONFIG[pia.risk_level]
                return (
                  <tr key={pia.id} className="hover:bg-[#0a1628] transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-white text-sm font-medium max-w-xs truncate">{pia.title}</p>
                      <p className="text-[#3d5068] text-xs">{pia.system_name}</p>
                    </td>
                    <td className="px-4 py-3">
                      <Badge cls={pia.assessment_type === 'DPIA' ? 'bg-orange-900/40 border-orange-700 text-orange-300' : 'bg-blue-900/40 border-blue-700 text-blue-300'}>
                        {pia.assessment_type}
                      </Badge>
                    </td>
                    <td className="px-4 py-3"><Badge cls={st.cls}>{st.label}</Badge></td>
                    <td className="px-4 py-3"><Badge cls={rl.cls}>{rl.label}</Badge></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3 h-3 text-[#3d5068]" />
                        <span className="text-[#7d92b0] text-sm max-w-[140px] truncate">{pia.data_controller}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {pia.dpo_consulted
                        ? <CheckCircle className="w-4 h-4 text-green-400" />
                        : <AlertCircle className="w-4 h-4 text-[#3d5068]" />
                      }
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{pia.started_date}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{pia.completed_date ?? '—'}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{pia.next_review_date ?? '—'}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedPIA(pia)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0a1628] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/30 rounded text-xs transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" /> 開く
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {selectedPIA && <PIAWizard pia={selectedPIA} onClose={() => setSelectedPIA(null)} />}
      {showCreate && <CreatePIAModal onClose={() => setShowCreate(false)} />}
    </div>
  )
}
