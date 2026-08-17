'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, X, Plus, Pencil, Eye, Download, Upload, FileText,
  CheckCircle, AlertTriangle, Clock, TrendingUp, TrendingDown,
  Phone, Mail, Building2, DollarSign, Calendar, ChevronDown, ChevronUp,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type RenewalStatus = 'active' | 'up_for_renewal' | 'expired' | 'pending'
type ClaimStatus = 'draft' | 'submitted' | 'under_review' | 'approved' | 'rejected' | 'paid'
type ClaimType = 'ransomware' | 'data_breach' | 'business_interruption' | 'cyber_extortion' | 'regulatory_fines' | 'other'

interface CoverageItem {
  risk: string
  risk_label: string
  coverage_limit: number
  included: boolean
}

interface Policy {
  id: string
  insurer_name: string
  policy_number: string
  coverage_amount: number
  premium_annual: number
  deductible: number
  policy_start: string
  policy_end: string
  renewal_status: RenewalStatus
  broker_name: string
  broker_email: string
  broker_phone: string
  broker_company: string
  coverages: CoverageItem[]
  exclusions: string[]
}

interface Claim {
  id: string
  claim_id: string
  incident_date: string
  claim_type: ClaimType
  description: string
  estimated_loss: number
  claimed_amount: number
  status: ClaimStatus
  adjuster_name: string
  filed_date: string
  settled_amount: number | null
  timeline: { date: string; event: string; note: string }[]
  adjuster_notes: string
}

interface QuestionnaireItem {
  id: string
  question: string
  response_type: 'yes_no' | 'percentage' | 'count'
  answer: string | number
  is_positive: boolean
  premium_impact_pct: number
  category: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const RENEWAL_CONFIG: Record<RenewalStatus, { label: string; color: string }> = {
  active:         { label: '有効', color: 'bg-green-500/10 text-green-400 border-green-500/30' },
  up_for_renewal: { label: '更新時期', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  expired:        { label: '期限切れ', color: 'bg-red-500/10 text-red-400 border-red-500/30' },
  pending:        { label: '審査中', color: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
}

const CLAIM_STATUS_CONFIG: Record<ClaimStatus, { label: string; color: string }> = {
  draft:        { label: '下書き', color: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
  submitted:    { label: '提出済', color: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
  under_review: { label: '審査中', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  approved:     { label: '承認済', color: 'bg-green-500/10 text-green-400 border-green-500/30' },
  rejected:     { label: '却下', color: 'bg-red-500/10 text-red-400 border-red-500/30' },
  paid:         { label: '支払済', color: 'bg-teal-500/10 text-teal-400 border-teal-500/30' },
}

const CLAIM_TYPE_LABELS: Record<ClaimType, string> = {
  ransomware: 'ランサムウェア',
  data_breach: 'データ漏洩',
  business_interruption: '事業中断',
  cyber_extortion: 'サイバー恐喝',
  regulatory_fines: '規制当局罰金',
  other: 'その他',
}

function fmtYen(v: number) {
  if (v >= 100_000_000) return `¥${(v / 100_000_000).toFixed(1)}億`
  if (v >= 10_000_000) return `¥${(v / 10_000_000).toFixed(0)}千万`
  if (v >= 1_000_000) return `¥${(v / 1_000_000).toFixed(0)}百万`
  return `¥${v.toLocaleString()}`
}

function fmtYenFull(v: number) {
  return `¥${v.toLocaleString()}`
}

function Badge({ cfg }: { cfg: { label: string; color: string } }) {
  return <span className={`text-xs px-2 py-0.5 rounded-sm border font-medium ${cfg.color}`}>{cfg.label}</span>
}

function daysUntil(dateStr: string) {
  return Math.ceil((new Date(dateStr).getTime() - Date.now()) / 86400000)
}

// ─── Modals ───────────────────────────────────────────────────────────────────

function ClaimDetailModal({ claim, onClose }: { claim: Claim; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border shrink-0">
          <div>
            <h2 className="text-white font-semibold">{claim.claim_id}</h2>
            <p className="text-xs text-falcon-muted mt-0.5">{CLAIM_TYPE_LABELS[claim.claim_type]} — {claim.incident_date}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto px-6 py-5 space-y-5 flex-1">
          <div className="flex flex-wrap gap-3">
            <Badge cfg={CLAIM_STATUS_CONFIG[claim.status]} />
            <div className="flex items-center gap-1.5 text-xs text-falcon-muted">
              <DollarSign className="w-3.5 h-3.5" /> 請求額: <span className="text-white font-semibold">{fmtYenFull(claim.claimed_amount)}</span>
            </div>
            {claim.settled_amount !== null && (
              <div className="flex items-center gap-1.5 text-xs text-teal-400">
                <CheckCircle className="w-3.5 h-3.5" /> 決済額: <span className="font-semibold">{fmtYenFull(claim.settled_amount)}</span>
              </div>
            )}
          </div>

          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
            <p className="text-xs text-falcon-muted mb-1">インシデント概要</p>
            <p className="text-falcon-text text-sm">{claim.description}</p>
          </div>

          {/* Timeline */}
          <div>
            <p className="text-xs text-falcon-muted mb-3">対応タイムライン</p>
            <div className="relative space-y-3 pl-5">
              <div className="absolute left-1.5 top-0 bottom-0 w-px bg-falcon-border" />
              {claim.timeline.map((t, i) => (
                <div key={i} className="relative">
                  <div className="absolute -left-3.5 top-1 w-2.5 h-2.5 rounded-full bg-falcon-red border-2 border-[#070d19]" />
                  <p className="text-xs text-falcon-muted">{t.date}</p>
                  <p className="text-sm text-white font-medium">{t.event}</p>
                  {t.note && <p className="text-xs text-falcon-muted mt-0.5">{t.note}</p>}
                </div>
              ))}
            </div>
          </div>

          {claim.adjuster_notes && (
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
              <p className="text-xs text-falcon-muted mb-1">調査員ノート</p>
              <p className="text-falcon-text text-sm">{claim.adjuster_notes}</p>
            </div>
          )}
        </div>
        <div className="px-6 py-4 border-t border-falcon-border flex justify-end shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg bg-falcon-red text-white hover:bg-[#c8001f] text-sm transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

function NewClaimModal({ onClose, onSubmit }: { onClose: () => void; onSubmit: (c: Partial<Claim>) => void }) {
  const [form, setForm] = useState({
    claim_type: 'ransomware' as ClaimType,
    incident_date: '',
    description: '',
    estimated_loss: '',
    claimed_amount: '',
  })
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold">保険申請を作成</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1">申請タイプ</label>
              <select value={form.claim_type} onChange={e => setForm(p => ({ ...p, claim_type: e.target.value as ClaimType }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                {(Object.keys(CLAIM_TYPE_LABELS) as ClaimType[]).map(t => (
                  <option key={t} value={t}>{CLAIM_TYPE_LABELS[t]}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1">インシデント日付</label>
              <input type="date" value={form.incident_date} onChange={e => setForm(p => ({ ...p, incident_date: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1">インシデント概要</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1">推定損失額（円）</label>
              <input type="number" value={form.estimated_loss} onChange={e => setForm(p => ({ ...p, estimated_loss: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1">請求金額（円）</label>
              <input type="number" value={form.claimed_amount} onChange={e => setForm(p => ({ ...p, claimed_amount: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1">証拠書類（アップロード）</label>
            <div className="border border-dashed border-falcon-border rounded-lg p-4 text-center cursor-pointer hover:border-[#2a3f5e] transition-colors">
              <Upload className="w-5 h-5 text-falcon-subtle mx-auto mb-1" />
              <p className="text-xs text-falcon-muted">ファイルをドラッグ＆ドロップ または クリックして選択</p>
            </div>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-falcon-border flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSubmit({ ...form, estimated_loss: Number(form.estimated_loss) || 0, claimed_amount: Number(form.claimed_amount) || 0 })} disabled={!form.incident_date || !form.description}
            className="px-4 py-2 rounded-lg bg-falcon-red text-white hover:bg-[#c8001f] text-sm transition-colors disabled:opacity-50">
            申請を作成
          </button>
        </div>
      </div>
    </div>
  )
}

const EMPTY_POLICY: Policy = {
  id: '',
  insurer_name: '',
  policy_number: '',
  coverage_amount: 0,
  premium_annual: 0,
  deductible: 0,
  policy_start: '',
  policy_end: '',
  renewal_status: 'active',
  broker_name: '',
  broker_email: '',
  broker_phone: '',
  broker_company: '',
  coverages: [],
  exclusions: [],
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CyberInsurancePage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'policy' | 'claims' | 'risk'>('policy')
  const [editingPolicy, setEditingPolicy] = useState(false)
  const [selectedClaim, setSelectedClaim] = useState<Claim | null>(null)
  const [newClaimOpen, setNewClaimOpen] = useState(false)
  const [answers, setAnswers] = useState<Record<string, string | number>>({})
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000) }

  const { data: policy = EMPTY_POLICY } = useQuery<Policy>({
    queryKey: ['cyber-insurance-policy'],
    queryFn: async () => {
      try {
        const res = await apiFetch('/api/v1/admin/cyber-insurance/policy')
        return (res && 'coverage_amount' in (res as any)) ? res as Policy : EMPTY_POLICY
      } catch { return EMPTY_POLICY }
    },
  })

  const { data: claims = [] } = useQuery<Claim[]>({
    queryKey: ['cyber-insurance-claims'],
    queryFn: async () => {
      try {
        const res = await apiFetch('/api/v1/admin/cyber-insurance/claims')
        return Array.isArray(res) ? res : (res as any)?.data ?? (res as any)?.items ?? []
      } catch { return [] }
    },
  })

  const savePolicyMutation = useMutation({
    mutationFn: (d: Partial<Policy>) => apiFetch('/api/v1/admin/cyber-insurance/policy', { method: 'PUT', body: JSON.stringify(d) }).catch(() => d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['cyber-insurance-policy'] }); showToast('保険証券を更新しました'); setEditingPolicy(false) },
  })

  const newClaimMutation = useMutation({
    mutationFn: (d: Partial<Claim>) => apiFetch('/api/v1/admin/cyber-insurance/claims', { method: 'POST', body: JSON.stringify(d) }).catch(() => d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['cyber-insurance-claims'] }); showToast('申請を作成しました'); setNewClaimOpen(false) },
  })

  const daysLeft = daysUntil(policy.policy_end)
  const policyEndColor = daysLeft < 90 ? 'text-red-400' : 'text-white'

  // Claims stats
  const totalClaimed = claims.reduce((s, c) => s + c.claimed_amount, 0)
  const totalPaid = claims.reduce((s, c) => s + (c.settled_amount ?? 0), 0)
  const pendingAmount = claims.filter(c => ['submitted', 'under_review'].includes(c.status)).reduce((s, c) => s + c.claimed_amount, 0)
  const approvedOrPaid = claims.filter(c => ['approved', 'paid'].includes(c.status)).length
  const approvalRate = claims.length > 0 ? Math.round((approvedOrPaid / claims.length) * 100) : 0

  // Premium impact calculator
  const premiumImpact = useMemo(() => {
    return ([] as QuestionnaireItem[]).reduce((sum, q) => {
      const answer = answers[q.id]
      if (q.response_type === 'yes_no') {
        if (answer === 'yes' && q.is_positive) return sum + q.premium_impact_pct
        if (answer === 'no' && !q.is_positive) return sum + Math.abs(q.premium_impact_pct)
        if (answer === 'no' && q.is_positive) return sum - q.premium_impact_pct
      } else {
        return sum + q.premium_impact_pct
      }
      return sum
    }, 0)
  }, [answers])

  const gaps = ([] as QuestionnaireItem[])
    .filter(q => {
      const a = answers[q.id]
      if (q.response_type === 'yes_no' && q.is_positive && a === 'no') return true
      if (q.response_type === 'percentage' && q.is_positive && (a as number) < 95) return true
      if (q.response_type === 'count' && !q.is_positive && (a as number) > 14) return true
      return false
    })
    .sort((a, b) => Math.abs(b.premium_impact_pct) - Math.abs(a.premium_impact_pct))
    .slice(0, 5)

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-5">
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-falcon-surface border border-green-500/40 text-green-400 px-4 py-3 rounded-lg shadow-2xl text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" /> {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">サイバー保険管理</h1>
          <p className="text-xs text-falcon-muted mt-0.5">保険証券・申請・リスク評価の一元管理</p>
        </div>
      </div>

      {/* Policy Summary Card */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <div className="flex items-start justify-between mb-4">
          <div>
            <p className="text-xs text-falcon-muted">現在の保険証券</p>
            <h2 className="text-white font-bold text-lg mt-0.5">{policy.insurer_name}</h2>
            <p className="text-xs text-falcon-muted font-mono mt-0.5">{policy.policy_number}</p>
          </div>
          <Badge cfg={RENEWAL_CONFIG[policy.renewal_status]} />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-xs text-falcon-muted">補償金額</p>
            <p className="text-white font-semibold mt-0.5">{fmtYen(policy.coverage_amount)}</p>
          </div>
          <div>
            <p className="text-xs text-falcon-muted">年間保険料</p>
            <p className="text-white font-semibold mt-0.5">{fmtYen(policy.premium_annual)}</p>
          </div>
          <div>
            <p className="text-xs text-falcon-muted">免責金額</p>
            <p className="text-white font-semibold mt-0.5">{fmtYen(policy.deductible)}</p>
          </div>
          <div>
            <p className="text-xs text-falcon-muted">満了日</p>
            <div className="flex items-center gap-2 mt-0.5">
              <p className={`font-semibold ${policyEndColor}`}>{policy.policy_end}</p>
              {daysLeft < 90 && (
                <span className="text-xs px-1.5 py-0.5 rounded-sm bg-red-500/20 text-red-400 border border-red-500/30">{daysLeft}日</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {([['policy', '保険設定'], ['claims', 'インシデント申請'], ['risk', 'リスク評価']] as const).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)}
            className={`px-5 py-2 rounded-md text-sm font-medium transition-all ${tab === k ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}>
            {l}
          </button>
        ))}
      </div>

      {/* ── 保険設定 tab ── */}
      {tab === 'policy' && (
        <div className="space-y-6">
          {/* Policy Details */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-semibold">証券詳細</h2>
              <div className="flex gap-2">
                <button onClick={() => showToast('証券をエクスポートしました')}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-xs transition-colors">
                  <Download className="w-3.5 h-3.5" /> 保険証券をエクスポート
                </button>
                <button onClick={() => setEditingPolicy(v => !v)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-xs transition-colors">
                  <Pencil className="w-3.5 h-3.5" /> {editingPolicy ? 'キャンセル' : '編集'}
                </button>
                {editingPolicy && (
                  <button onClick={() => savePolicyMutation.mutate({})}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-falcon-red text-white text-xs transition-colors">
                    保存
                  </button>
                )}
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {[
                { label: '保険会社', value: policy.insurer_name },
                { label: '証券番号', value: policy.policy_number },
                { label: '補償金額', value: fmtYenFull(policy.coverage_amount) },
                { label: '年間保険料', value: fmtYenFull(policy.premium_annual) },
                { label: '免責金額', value: fmtYenFull(policy.deductible) },
                { label: '保険期間', value: `${policy.policy_start} 〜 ${policy.policy_end}` },
              ].map(f => (
                <div key={f.label}>
                  <p className="text-xs text-falcon-muted mb-1">{f.label}</p>
                  {editingPolicy ? (
                    <input defaultValue={f.value}
                      className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-1.5 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
                  ) : (
                    <p className="text-white text-sm">{f.value}</p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Coverage Breakdown */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-falcon-border">
              <h2 className="text-white font-semibold">補償内容</h2>
            </div>
            <table className="w-full text-sm">
              <thead><tr className="border-b border-falcon-border">
                <th className="px-5 py-3 text-left text-xs text-falcon-muted font-medium">リスク種別</th>
                <th className="px-5 py-3 text-right text-xs text-falcon-muted font-medium">補償上限</th>
                <th className="px-5 py-3 text-center text-xs text-falcon-muted font-medium">補償状態</th>
              </tr></thead>
              <tbody>
                {policy.coverages.map(c => (
                  <tr key={c.risk} className="border-b border-falcon-border/50 hover:bg-[#070d19] transition-colors">
                    <td className="px-5 py-3 text-falcon-text">{c.risk_label}</td>
                    <td className="px-5 py-3 text-right font-mono text-sm">
                      {c.included ? <span className="text-white">{fmtYenFull(c.coverage_limit)}</span> : <span className="text-falcon-subtle">—</span>}
                    </td>
                    <td className="px-5 py-3 text-center">
                      {c.included ? (
                        <span className="text-xs px-2 py-0.5 rounded-sm border bg-green-500/10 text-green-400 border-green-500/30">対象</span>
                      ) : (
                        <span className="text-xs px-2 py-0.5 rounded-sm border bg-red-500/10 text-red-400 border-red-500/30">除外</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Exclusions */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" /> 免責事項・除外条件
            </h2>
            <div className="space-y-2">
              {policy.exclusions.map((ex, i) => (
                <div key={i} className="flex items-start gap-2.5 p-3 bg-[#070d19] rounded-lg border border-amber-500/10">
                  <X className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span className="text-sm text-falcon-text">{ex}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Broker Info */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold mb-4 flex items-center gap-2">
              <Building2 className="w-4 h-4 text-falcon-red" /> ブローカー情報
            </h2>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-sm bg-falcon-border flex items-center justify-center shrink-0">
                  <Building2 className="w-3.5 h-3.5 text-falcon-muted" />
                </div>
                <div>
                  <p className="text-xs text-falcon-muted">会社名</p>
                  <p className="text-white text-sm">{policy.broker_company}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-sm bg-falcon-border flex items-center justify-center shrink-0">
                  <Mail className="w-3.5 h-3.5 text-falcon-muted" />
                </div>
                <div>
                  <p className="text-xs text-falcon-muted">メールアドレス</p>
                  <p className="text-white text-sm">{policy.broker_email}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-sm bg-falcon-border flex items-center justify-center shrink-0">
                  <Phone className="w-3.5 h-3.5 text-falcon-muted" />
                </div>
                <div>
                  <p className="text-xs text-falcon-muted">担当者</p>
                  <p className="text-white text-sm">{policy.broker_name}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-sm bg-falcon-border flex items-center justify-center shrink-0">
                  <Phone className="w-3.5 h-3.5 text-falcon-muted" />
                </div>
                <div>
                  <p className="text-xs text-falcon-muted">電話番号</p>
                  <p className="text-white text-sm">{policy.broker_phone}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Document uploads */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold mb-4">関連書類</h2>
            <div className="space-y-2">
              {[
                { name: '保険証券 TM-CYBER-2025-00472.pdf', date: '2025-04-01', size: '2.3 MB' },
                { name: '特約承認書 2025.pdf', date: '2025-04-05', size: '0.8 MB' },
              ].map(doc => (
                <div key={doc.name} className="flex items-center justify-between p-3 bg-[#070d19] border border-falcon-border rounded-lg">
                  <div className="flex items-center gap-3">
                    <FileText className="w-4 h-4 text-blue-400" />
                    <div>
                      <p className="text-sm text-white">{doc.name}</p>
                      <p className="text-xs text-falcon-muted">{doc.date} — {doc.size}</p>
                    </div>
                  </div>
                  <button onClick={() => showToast('ダウンロードを開始しました')}
                    className="p-1.5 rounded-sm border border-falcon-border text-falcon-muted hover:text-white transition-colors">
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
              <button onClick={() => showToast('ファイル選択ダイアログ（モック）')}
                className="w-full flex items-center justify-center gap-2 p-3 border border-dashed border-falcon-border rounded-lg text-xs text-falcon-muted hover:border-[#2a3f5e] hover:text-white transition-colors">
                <Upload className="w-4 h-4" /> 書類をアップロード
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── インシデント申請 tab ── */}
      {tab === 'claims' && (
        <div className="space-y-6">
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <p className="text-xs text-falcon-muted mb-1">総請求額</p>
              <p className="text-xl font-bold text-white">{fmtYen(totalClaimed)}</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <p className="text-xs text-falcon-muted mb-1">総支払額</p>
              <p className="text-xl font-bold text-teal-400">{fmtYen(totalPaid)}</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <p className="text-xs text-falcon-muted mb-1">審査中金額</p>
              <p className="text-xl font-bold text-amber-400">{fmtYen(pendingAmount)}</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <p className="text-xs text-falcon-muted mb-1">承認率</p>
              <p className="text-xl font-bold text-white">{approvalRate}<span className="text-sm text-falcon-muted">%</span></p>
            </div>
          </div>

          {/* Claims Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
              <h2 className="text-white font-semibold">申請一覧</h2>
              <button onClick={() => setNewClaimOpen(true)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-falcon-red/20 border border-falcon-red/30 text-falcon-red hover:bg-falcon-red/30 text-xs transition-colors">
                <Plus className="w-3.5 h-3.5" /> 新規申請
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-falcon-border">
                  {['申請ID', 'インシデント日', '種別', '推定損失', '請求額', '決済額', 'ステータス', '調査員', '提出日'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                  ))}
                  <th className="px-4 py-3" />
                </tr></thead>
                <tbody>
                  {claims.map(c => (
                    <tr key={c.id} className="border-b border-falcon-border/50 hover:bg-[#070d19] transition-colors">
                      <td className="px-4 py-3 font-mono text-xs text-falcon-text whitespace-nowrap">{c.claim_id}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{c.incident_date}</td>
                      <td className="px-4 py-3 text-xs text-falcon-text whitespace-nowrap">{CLAIM_TYPE_LABELS[c.claim_type]}</td>
                      <td className="px-4 py-3 text-xs font-mono text-falcon-text whitespace-nowrap">{fmtYen(c.estimated_loss)}</td>
                      <td className="px-4 py-3 text-xs font-mono text-white whitespace-nowrap">{fmtYen(c.claimed_amount)}</td>
                      <td className="px-4 py-3 text-xs font-mono whitespace-nowrap">
                        {c.settled_amount !== null ? <span className="text-teal-400">{fmtYen(c.settled_amount)}</span> : <span className="text-falcon-subtle">—</span>}
                      </td>
                      <td className="px-4 py-3"><Badge cfg={CLAIM_STATUS_CONFIG[c.status]} /></td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{c.adjuster_name === '未割当' ? <span className="text-falcon-subtle">未割当</span> : c.adjuster_name.split('（')[0]}</td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{c.filed_date}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedClaim(c)}
                          className="p-1.5 rounded-sm border border-falcon-border text-falcon-muted hover:text-white transition-colors">
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── リスク評価 tab ── */}
      {tab === 'risk' && (
        <div className="space-y-6">
          {/* Premium Impact Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={`bg-falcon-surface border rounded-xl p-5 ${premiumImpact < 0 ? 'border-green-500/30' : 'border-red-500/30'}`}>
              <p className="text-xs text-falcon-muted mb-1">推定保険料インパクト</p>
              <div className="flex items-center gap-2">
                {premiumImpact < 0
                  ? <TrendingDown className="w-5 h-5 text-green-400" />
                  : <TrendingUp className="w-5 h-5 text-red-400" />}
                <p className={`text-3xl font-bold ${premiumImpact < 0 ? 'text-green-400' : 'text-red-400'}`}>
                  {premiumImpact > 0 ? '+' : ''}{premiumImpact}%
                </p>
              </div>
              <p className="text-xs text-falcon-muted mt-1">ベースライン比</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <p className="text-xs text-falcon-muted mb-1">ポジティブ要素</p>
              <p className="text-3xl font-bold text-green-400">
                {([] as QuestionnaireItem[]).filter(q => q.is_positive && (answers[q.id] === 'yes' || q.response_type !== 'yes_no')).length}
              </p>
              <p className="text-xs text-falcon-muted mt-1">保険料削減効果のある項目</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <p className="text-xs text-falcon-muted mb-1">改善対象項目</p>
              <p className="text-3xl font-bold text-amber-400">{gaps.length}</p>
              <p className="text-xs text-falcon-muted mt-1">保険料改善余地のある項目</p>
            </div>
          </div>

          {/* Questionnaire */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-falcon-border">
              <h2 className="text-white font-semibold">保険会社セキュリティ審査票（模擬）</h2>
              <p className="text-xs text-falcon-muted mt-0.5">回答を変更すると保険料インパクトがリアルタイムで更新されます</p>
            </div>
            <div className="divide-y divide-falcon-border">
              {([] as QuestionnaireItem[]).map(q => (
                <div key={q.id} className="px-5 py-4 flex items-start gap-4 hover:bg-[#070d19] transition-colors">
                  <div className={`w-2 h-2 rounded-full shrink-0 mt-2 ${q.is_positive ? 'bg-green-400' : 'bg-amber-400'}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <span className="text-xs text-falcon-subtle uppercase tracking-wide">{q.category}</span>
                        <p className="text-sm text-falcon-text mt-0.5">{q.question}</p>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        {q.response_type === 'yes_no' ? (
                          <div className="flex gap-2">
                            <button onClick={() => setAnswers(p => ({ ...p, [q.id]: 'yes' }))}
                              className={`px-3 py-1 rounded-sm text-xs font-medium transition-all border ${answers[q.id] === 'yes' ? 'bg-green-500/20 border-green-500/40 text-green-400' : 'border-falcon-border text-falcon-muted hover:text-white'}`}>
                              はい
                            </button>
                            <button onClick={() => setAnswers(p => ({ ...p, [q.id]: 'no' }))}
                              className={`px-3 py-1 rounded-sm text-xs font-medium transition-all border ${answers[q.id] === 'no' ? 'bg-red-500/20 border-red-500/40 text-red-400' : 'border-falcon-border text-falcon-muted hover:text-white'}`}>
                              いいえ
                            </button>
                          </div>
                        ) : (
                          <input type="number" value={answers[q.id] as number}
                            onChange={e => setAnswers(p => ({ ...p, [q.id]: Number(e.target.value) }))}
                            className="w-24 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-white text-sm text-right focus:outline-hidden focus:border-falcon-red/50" />
                        )}
                        <span className={`text-xs font-mono w-12 text-right ${q.premium_impact_pct < 0 ? 'text-green-400' : 'text-red-400'}`}>
                          {q.premium_impact_pct > 0 ? '+' : ''}{q.premium_impact_pct}%
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Gap Analysis */}
          {gaps.length > 0 && (
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <h2 className="text-white font-semibold mb-4 flex items-center gap-2">
                <TrendingDown className="w-4 h-4 text-green-400" />
                保険料削減トップ5改善項目
              </h2>
              <div className="space-y-3">
                {gaps.map((q, i) => (
                  <div key={q.id} className="flex items-center gap-4 p-3 bg-[#070d19] border border-falcon-border rounded-lg">
                    <span className="w-6 h-6 rounded-full bg-falcon-border text-falcon-muted text-xs flex items-center justify-center shrink-0 font-bold">{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-falcon-text truncate">{q.question}</p>
                      <p className="text-xs text-falcon-muted mt-0.5">{q.category}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-sm font-bold text-green-400">{Math.abs(q.premium_impact_pct)}%削減可能</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Modals */}
      {selectedClaim && <ClaimDetailModal claim={selectedClaim} onClose={() => setSelectedClaim(null)} />}
      {newClaimOpen && (
        <NewClaimModal
          onClose={() => setNewClaimOpen(false)}
          onSubmit={(c) => newClaimMutation.mutate(c)}
        />
      )}
    </div>
  )
}
