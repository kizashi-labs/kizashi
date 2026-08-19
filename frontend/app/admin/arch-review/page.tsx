'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Building2, Plus, X, ChevronDown, ChevronRight, CheckCircle,
  Clock, AlertTriangle, Shield, Search, RefreshCw,
  User, Calendar, FileText, ChevronUp, Check, Minus,
  AlertCircle, Eye, Edit3, Activity,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { usePersist, SaveFailed } from '@/lib/persist'

// ── Types ────────────────────────────────────────────────────────────────────

type ReviewType = 'new_system' | 'change_request' | 'annual' | 'merger_acquisition'
type ReviewStatus = 'draft' | 'submitted' | 'in_review' | 'approved' | 'rejected' | 'changes_requested'
type RiskRating = 'low' | 'medium' | 'high' | 'critical'
type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'
type FindingStatus = 'open' | 'accepted' | 'resolved' | 'in_progress'
type ChecklistAnswer = 'yes' | 'no' | 'partial' | 'na'

interface Finding {
  id: string
  title: string
  severity: FindingSeverity
  description: string
  recommendation: string
  assignee: string
  status: FindingStatus
  created_at: string
}

interface ChecklistItem {
  id: string
  question: string
  answer: ChecklistAnswer | null
  notes: string
}

interface ChecklistSection {
  id: string
  title: string
  items: ChecklistItem[]
}

interface ArchReview {
  id: string
  name: string
  review_type: ReviewType
  status: ReviewStatus
  requested_by: string
  assigned_reviewer: string
  submission_date: string
  target_completion: string
  risk_rating: RiskRating
  description: string
  system_name: string
  data_classification: 'public' | 'internal' | 'confidential' | 'restricted'
  network_exposure: 'internet' | 'dmz' | 'internal' | 'air_gapped'
  auth_type: 'password' | 'mfa' | 'sso' | 'certificate'
  design_doc_url?: string
  findings: Finding[]
  checklist: ChecklistSection[]
  timeline: Array<{ date: string; action: string; actor: string; comment?: string }>
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const REVIEW_TYPE_CONFIG: Record<ReviewType, { label: string; cls: string }> = {
  new_system: { label: '新規システム', cls: 'bg-blue-900/40 border-blue-700 text-blue-300' },
  change_request: { label: '変更申請', cls: 'bg-purple-900/40 border-purple-700 text-purple-300' },
  annual: { label: '年次レビュー', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  merger_acquisition: { label: 'M&A', cls: 'bg-orange-900/40 border-orange-700 text-orange-300' },
}

const STATUS_CONFIG: Record<ReviewStatus, { label: string; cls: string; icon: React.ElementType }> = {
  draft: { label: 'ドラフト', cls: 'bg-gray-900/40 border-gray-700 text-gray-300', icon: Edit3 },
  submitted: { label: '提出済み', cls: 'bg-blue-900/40 border-blue-700 text-blue-300', icon: FileText },
  in_review: { label: 'レビュー中', cls: 'bg-yellow-900/40 border-yellow-700 text-yellow-300', icon: Eye },
  approved: { label: '承認', cls: 'bg-green-900/40 border-green-700 text-green-300', icon: CheckCircle },
  rejected: { label: '否認', cls: 'bg-red-900/60 border-red-700 text-red-300', icon: X },
  changes_requested: { label: '修正依頼', cls: 'bg-orange-900/40 border-orange-700 text-orange-300', icon: AlertCircle },
}

const RISK_CONFIG: Record<RiskRating, { label: string; cls: string }> = {
  low: { label: '低リスク', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  medium: { label: '中リスク', cls: 'bg-yellow-900/40 border-yellow-700 text-yellow-300' },
  high: { label: '高リスク', cls: 'bg-orange-900/40 border-orange-700 text-orange-300' },
  critical: { label: '最高リスク', cls: 'bg-red-900/60 border-red-700 text-red-300' },
}

const FINDING_SEV_CONFIG: Record<FindingSeverity, { label: string; cls: string }> = {
  info: { label: 'Info', cls: 'bg-blue-900/40 border-blue-700 text-blue-300' },
  low: { label: 'Low', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  medium: { label: 'Medium', cls: 'bg-yellow-900/40 border-yellow-700 text-yellow-300' },
  high: { label: 'High', cls: 'bg-orange-900/40 border-orange-700 text-orange-300' },
  critical: { label: 'Critical', cls: 'bg-red-900/60 border-red-700 text-red-300' },
}

const ANSWER_CONFIG: Record<ChecklistAnswer, { label: string; cls: string }> = {
  yes: { label: '✓ はい', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  no: { label: '✗ いいえ', cls: 'bg-red-900/60 border-red-700 text-red-300' },
  partial: { label: '△ 一部', cls: 'bg-yellow-900/40 border-yellow-700 text-yellow-300' },
  na: { label: '— N/A', cls: 'bg-gray-900/40 border-gray-700 text-gray-300' },
}

function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-xs font-medium ${cls}`}>{children}</span>
}

function calcAutoRisk(findings: Finding[]): RiskRating {
  if (findings.some(f => f.severity === 'critical' && f.status !== 'resolved')) return 'critical'
  if (findings.filter(f => f.severity === 'high' && f.status !== 'resolved').length >= 2) return 'high'
  if (findings.some(f => f.severity === 'high' && f.status !== 'resolved')) return 'medium'
  return 'low'
}

// ── Create Review Modal ───────────────────────────────────────────────────────

function CreateReviewModal({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({
    name: '', review_type: 'new_system' as ReviewType, description: '', system_name: '',
    submitted_by: '', data_classification: 'internal', network_exposure: 'internal',
    auth_type: 'password', design_doc_url: '',
  })
  const qc = useQueryClient()
  const { persist, saveError } = usePersist()

  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async () => {
    if (!(await persist('アーキテクチャレビュー', '/api/v1/admin/arch-reviews', {
      method: 'POST', body: JSON.stringify(form),
    }))) return
    qc.invalidateQueries({ queryKey: ['arch-reviews'] })
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="px-6 pt-4"><SaveFailed error={saveError} /></div>
        <div className="flex items-center justify-between p-6 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-lg">新規アーキテクチャレビュー作成</h2>
          <button onClick={onClose} className="p-2 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">レビュー名 *</label>
              <input value={form.name} onChange={e => set('name', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors" placeholder="例: 新規ECシステム アーキテクチャレビュー" />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">レビュー種別</label>
              <select value={form.review_type} onChange={e => set('review_type', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#7d92b0] text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="new_system">新規システム</option>
                <option value="change_request">変更申請</option>
                <option value="annual">年次レビュー</option>
                <option value="merger_acquisition">M&A</option>
              </select>
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">システム名</label>
              <input value={form.system_name} onChange={e => set('system_name', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors" />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">申請者</label>
              <input value={form.submitted_by} onChange={e => set('submitted_by', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors" />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">データ分類</label>
              <select value={form.data_classification} onChange={e => set('data_classification', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#7d92b0] text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="public">公開</option>
                <option value="internal">社内</option>
                <option value="confidential">機密</option>
                <option value="restricted">制限</option>
              </select>
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">ネットワーク露出</label>
              <select value={form.network_exposure} onChange={e => set('network_exposure', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#7d92b0] text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="internet">インターネット公開</option>
                <option value="dmz">DMZ</option>
                <option value="internal">内部ネットワーク</option>
                <option value="air_gapped">エアギャップ</option>
              </select>
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">認証方式</label>
              <select value={form.auth_type} onChange={e => set('auth_type', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#7d92b0] text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="password">パスワード</option>
                <option value="mfa">MFA</option>
                <option value="sso">SSO</option>
                <option value="certificate">証明書認証</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">設計書URL（参照用）</label>
              <input value={form.design_doc_url} onChange={e => set('design_doc_url', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors font-mono" placeholder="https://confluence.example.com/..." />
            </div>
            <div className="col-span-2">
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">説明</label>
              <textarea value={form.description} onChange={e => set('description', e.target.value)} rows={3} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors resize-none" />
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

// ── Add Finding Modal ─────────────────────────────────────────────────────────

function AddFindingModal({ reviewId, onClose }: { reviewId: string; onClose: () => void }) {
  const [form, setForm] = useState({ title: '', severity: 'medium' as FindingSeverity, description: '', recommendation: '', assignee: '' })
  const { persist, saveError } = usePersist()
  const set = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }))

  const handleSubmit = async () => {
    if (await persist('指摘事項', `/api/v1/admin/arch-reviews/${reviewId}/findings`, {
      method: 'POST', body: JSON.stringify(form),
    })) {
      onClose()
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-xl" onClick={e => e.stopPropagation()}>
        <div className="px-6 pt-4"><SaveFailed error={saveError} /></div>
        <div className="flex items-center justify-between p-6 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">指摘事項の追加</h2>
          <button onClick={onClose} className="p-2 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-4 h-4" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">タイトル</label>
            <input value={form.title} onChange={e => set('title', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">重要度</label>
              <select value={form.severity} onChange={e => set('severity', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#7d92b0] text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="info">Info</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">担当者</label>
              <input value={form.assignee} onChange={e => set('assignee', e.target.value)} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors" />
            </div>
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">説明</label>
            <textarea value={form.description} onChange={e => set('description', e.target.value)} rows={3} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors resize-none" />
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs uppercase tracking-wider block mb-1.5">推奨対応</label>
            <textarea value={form.recommendation} onChange={e => set('recommendation', e.target.value)} rows={2} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors resize-none" />
          </div>
        </div>
        <div className="flex justify-end gap-3 p-6 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:text-white transition-colors">キャンセル</button>
          <button onClick={handleSubmit} className="px-4 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-semibold hover:bg-[#c0001f] transition-colors">追加</button>
        </div>
      </div>
    </div>
  )
}

// ── Review Detail Panel ───────────────────────────────────────────────────────

function ReviewDetailPanel({ review, onClose }: { review: ArchReview; onClose: () => void }) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['auth']))
  const [checklist, setChecklist] = useState<ChecklistSection[]>(review.checklist)
  const [showAddFinding, setShowAddFinding] = useState(false)
  const [approvalComment, setApprovalComment] = useState('')
  const autoRisk = calcAutoRisk(review.findings)

  const toggleSection = (id: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const setAnswer = (sectionId: string, itemId: string, answer: ChecklistAnswer) => {
    setChecklist(prev => prev.map(s =>
      s.id === sectionId ? { ...s, items: s.items.map(i => i.id === itemId ? { ...i, answer } : i) } : s
    ))
  }

  const setNote = (sectionId: string, itemId: string, notes: string) => {
    setChecklist(prev => prev.map(s =>
      s.id === sectionId ? { ...s, items: s.items.map(i => i.id === itemId ? { ...i, notes } : i) } : s
    ))
  }

  const dataClassLabels: Record<string, string> = {
    public: '公開', internal: '社内', confidential: '機密', restricted: '制限',
  }
  const networkLabels: Record<string, string> = {
    internet: 'インターネット公開', dmz: 'DMZ', internal: '内部NW', air_gapped: 'エアギャップ',
  }
  const authLabels: Record<string, string> = {
    password: 'パスワード', mfa: 'MFA', sso: 'SSO', certificate: '証明書',
  }

  const totalItems = checklist.reduce((s, sec) => s + sec.items.length, 0)
  const answeredItems = checklist.reduce((s, sec) => s + sec.items.filter(i => i.answer !== null).length, 0)

  return (
    <div className="fixed inset-0 z-40 bg-black/70 flex" onClick={onClose}>
      <div className="ml-auto bg-[#0d1220] border-l border-[#1e2d42] w-full max-w-3xl flex flex-col h-full overflow-hidden" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start gap-3 p-6 border-b border-[#1e2d42]">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <Badge cls={REVIEW_TYPE_CONFIG[review.review_type].cls}>{REVIEW_TYPE_CONFIG[review.review_type].label}</Badge>
              <Badge cls={STATUS_CONFIG[review.status].cls}>{STATUS_CONFIG[review.status].label}</Badge>
              <Badge cls={RISK_CONFIG[review.risk_rating].cls}>{RISK_CONFIG[review.risk_rating].label}</Badge>
            </div>
            <h2 className="text-white font-bold text-lg leading-tight">{review.name}</h2>
            <p className="text-[#7d92b0] text-sm mt-0.5">{review.system_name}</p>
          </div>
          <button onClick={onClose} className="p-2 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors shrink-0"><X className="w-5 h-5" /></button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* System Info */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
            <h3 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-3">システム情報</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-[#7d92b0]">申請者: </span>
                <span className="text-white">{review.requested_by}</span>
              </div>
              <div>
                <span className="text-[#7d92b0]">レビュアー: </span>
                <span className="text-white">{review.assigned_reviewer}</span>
              </div>
              <div>
                <span className="text-[#7d92b0]">提出日: </span>
                <span className="text-white">{review.submission_date}</span>
              </div>
              <div>
                <span className="text-[#7d92b0]">完了目標: </span>
                <span className="text-white">{review.target_completion}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#7d92b0]">データ分類: </span>
                <Badge cls="bg-purple-900/40 border-purple-700 text-purple-300">{dataClassLabels[review.data_classification]}</Badge>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#7d92b0]">ネットワーク: </span>
                <span className="text-white">{networkLabels[review.network_exposure]}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[#7d92b0]">認証方式: </span>
                <span className="text-white">{authLabels[review.auth_type]}</span>
              </div>
              {review.design_doc_url && (
                <div className="col-span-2">
                  <span className="text-[#7d92b0]">設計書: </span>
                  <span className="text-[#7d92b0] font-mono text-xs ml-1">{review.design_doc_url}</span>
                </div>
              )}
            </div>
            {review.description && (
              <p className="text-[#7d92b0] text-sm mt-3 pt-3 border-t border-[#1e2d42]">{review.description}</p>
            )}
          </div>

          {/* Checklist */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-white font-semibold">レビューチェックリスト</h3>
              <span className="text-[#7d92b0] text-xs">{answeredItems}/{totalItems} 完了</span>
            </div>
            <div className="h-1 bg-[#1e2d42] rounded-full mb-4 overflow-hidden">
              <div className="h-full bg-[#e8002d] rounded-full transition-all" style={{ width: `${(answeredItems / totalItems) * 100}%` }} />
            </div>
            <div className="space-y-2">
              {checklist.map(section => {
                const isOpen = expandedSections.has(section.id)
                const yesCount = section.items.filter(i => i.answer === 'yes').length
                const noCount = section.items.filter(i => i.answer === 'no').length
                return (
                  <div key={section.id} className="bg-[#070d19] border border-[#1e2d42] rounded-xl overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-4 hover:bg-[#0a1628] transition-colors"
                      onClick={() => toggleSection(section.id)}
                    >
                      <div className="flex items-center gap-3">
                        {isOpen ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />}
                        <span className="text-white font-medium">{section.title}</span>
                        <span className="text-[#3d5068] text-xs">({section.items.length}項目)</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {yesCount > 0 && <span className="text-green-400 text-xs font-medium">{yesCount}✓</span>}
                        {noCount > 0 && <span className="text-red-400 text-xs font-medium">{noCount}✗</span>}
                      </div>
                    </button>
                    {isOpen && (
                      <div className="border-t border-[#1e2d42] divide-y divide-[#1e2d42]">
                        {section.items.map(item => (
                          <div key={item.id} className="p-4">
                            <p className="text-white text-sm mb-3">{item.question}</p>
                            <div className="flex gap-2 mb-2 flex-wrap">
                              {(['yes', 'no', 'partial', 'na'] as ChecklistAnswer[]).map(ans => (
                                <button
                                  key={ans}
                                  onClick={() => setAnswer(section.id, item.id, ans)}
                                  className={`px-3 py-1 rounded-sm border text-xs font-medium transition-colors ${item.answer === ans ? ANSWER_CONFIG[ans].cls : 'bg-[#0d1220] border-[#1e2d42] text-[#3d5068] hover:text-[#7d92b0]'}`}
                                >
                                  {ANSWER_CONFIG[ans].label}
                                </button>
                              ))}
                            </div>
                            {(item.answer === 'no' || item.answer === 'partial') && (
                              <input
                                value={item.notes}
                                onChange={e => setNote(section.id, item.id, e.target.value)}
                                placeholder="メモ・補足..."
                                className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#e8002d]/50 transition-colors"
                              />
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* Findings */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-white font-semibold flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#e8002d]" /> 指摘事項 ({review.findings.length}件)
              </h3>
              <button
                onClick={() => setShowAddFinding(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d] rounded-lg text-xs font-medium hover:bg-[#e8002d]/20 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" /> 追加
              </button>
            </div>
            <div className="space-y-3">
              {review.findings.length === 0 && (
                <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-6 text-center">
                  <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                  <p className="text-[#7d92b0] text-sm">指摘事項なし</p>
                </div>
              )}
              {review.findings.map(f => (
                <div key={f.id} className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge cls={FINDING_SEV_CONFIG[f.severity].cls}>{FINDING_SEV_CONFIG[f.severity].label}</Badge>
                    <span className="text-white font-medium text-sm">{f.title}</span>
                    <Badge cls={f.status === 'resolved' ? 'bg-green-900/40 border-green-700 text-green-300' : f.status === 'in_progress' ? 'bg-blue-900/40 border-blue-700 text-blue-300' : 'bg-gray-900/40 border-gray-700 text-gray-300'}>
                      {f.status === 'resolved' ? '解決済み' : f.status === 'in_progress' ? '対応中' : f.status === 'accepted' ? '承認済み' : 'オープン'}
                    </Badge>
                  </div>
                  <p className="text-[#7d92b0] text-sm mb-2">{f.description}</p>
                  <p className="text-green-300 text-xs bg-green-900/10 border border-green-900/20 rounded-sm p-2">{f.recommendation}</p>
                  <div className="flex items-center gap-3 mt-2 text-xs text-[#3d5068]">
                    <span>担当: <span className="text-[#7d92b0]">{f.assignee}</span></span>
                    <span>{f.created_at}</span>
                  </div>
                </div>
              ))}
            </div>
            {/* Auto Risk Rating */}
            <div className="mt-4 bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
              <div className="flex items-center justify-between">
                <span className="text-[#7d92b0] text-sm">自動計算リスク評価</span>
                <Badge cls={RISK_CONFIG[autoRisk].cls}>{RISK_CONFIG[autoRisk].label}</Badge>
              </div>
              <p className="text-[#3d5068] text-xs mt-1">指摘事項の重要度から自動計算</p>
            </div>
          </div>

          {/* Approval Section */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
            <h3 className="text-white font-semibold mb-3">承認・判定</h3>
            <textarea
              value={approvalComment}
              onChange={e => setApprovalComment(e.target.value)}
              placeholder="コメントを入力..."
              rows={3}
              className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 transition-colors resize-none mb-3"
            />
            <div className="flex gap-2">
              <button className="flex items-center gap-1.5 px-4 py-2 bg-green-900/30 border border-green-700 text-green-300 rounded-lg text-sm font-medium hover:bg-green-900/50 transition-colors">
                <Check className="w-4 h-4" /> 承認
              </button>
              <button className="flex items-center gap-1.5 px-4 py-2 bg-orange-900/30 border border-orange-700 text-orange-300 rounded-lg text-sm font-medium hover:bg-orange-900/50 transition-colors">
                <AlertCircle className="w-4 h-4" /> 修正依頼
              </button>
              <button className="flex items-center gap-1.5 px-4 py-2 bg-red-900/30 border border-red-700 text-red-300 rounded-lg text-sm font-medium hover:bg-red-900/50 transition-colors">
                <X className="w-4 h-4" /> 否認
              </button>
            </div>
          </div>

          {/* Timeline */}
          <div>
            <h3 className="text-white font-semibold mb-3 flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#e8002d]" /> レビュー履歴
            </h3>
            <div className="relative pl-6">
              <div className="absolute left-2 top-0 bottom-0 w-px bg-[#1e2d42]" />
              {review.timeline.map((ev, i) => (
                <div key={i} className="relative mb-4 last:mb-0">
                  <div className="absolute -left-4 w-4 h-4 rounded-full bg-[#1e2d42] border-2 border-[#e8002d] -translate-x-1/2" />
                  <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 ml-2">
                    <div className="flex items-center justify-between">
                      <span className="text-white text-sm font-medium">{ev.action}</span>
                      <span className="text-[#3d5068] text-xs">{ev.date}</span>
                    </div>
                    <span className="text-[#7d92b0] text-xs">{ev.actor}</span>
                    {ev.comment && <p className="text-[#7d92b0] text-xs mt-1 italic">"{ev.comment}"</p>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {showAddFinding && <AddFindingModal reviewId={review.id} onClose={() => setShowAddFinding(false)} />}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function ArchReviewPage() {
  const [selectedReview, setSelectedReview] = useState<ArchReview | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [search, setSearch] = useState('')

  const { data: reviewData, isLoading } = useQuery<ArchReview[]>({
    queryKey: ['arch-reviews'],
    queryFn: () => apiFetch('/api/v1/admin/arch-reviews'),
    retry: false,
  })

  const reviews = useMemo(() => reviewData ?? [], [reviewData])

  const filtered = useMemo(() => {
    if (!search.trim()) return reviews
    const q = search.toLowerCase()
    return reviews.filter(r => r.name.toLowerCase().includes(q) || r.system_name.toLowerCase().includes(q) || r.requested_by.toLowerCase().includes(q))
  }, [reviews, search])

  const stats = useMemo(() => ({
    total: reviews.length,
    inProgress: reviews.filter(r => r.status === 'in_review').length,
    totalFindings: reviews.reduce((sum, r) => sum + r.findings.length, 0),
    highFindings: reviews.reduce((sum, r) => sum + r.findings.filter(f => (f.severity === 'high' || f.severity === 'critical') && f.status !== 'resolved').length, 0),
  }), [reviews])

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-900/30 border border-blue-800/40 flex items-center justify-center">
            <Building2 className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-white text-xl font-bold">セキュリティアーキテクチャレビュー</h1>
            <p className="text-[#7d92b0] text-sm">システム設計のセキュリティ審査・指摘事項管理</p>
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
            <Plus className="w-4 h-4" /> 新規レビュー
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: '総レビュー数', value: stats.total, icon: FileText, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-800/40' },
          { label: 'レビュー中', value: stats.inProgress, icon: Clock, color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-800/40' },
          { label: '総指摘件数', value: stats.totalFindings, icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-800/40' },
          { label: 'High+指摘 (未解決)', value: stats.highFindings, icon: Shield, color: 'text-red-400', bg: 'bg-red-900/20 border-red-800/40' },
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
          placeholder="レビュー名・システム名・申請者で検索..."
          className="w-full max-w-md bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-10 pr-4 py-2.5 text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 text-sm transition-colors"
        />
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['レビュー名', '種別', 'ステータス', '申請者', 'レビュアー', '提出日', '完了目標', 'リスク', '操作'].map(h => (
                  <th key={h} className="text-left text-[#7d92b0] text-xs font-medium uppercase tracking-wider px-4 py-3 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {filtered.map(r => {
                const rt = REVIEW_TYPE_CONFIG[r.review_type]
                const st = STATUS_CONFIG[r.status]
                const rk = RISK_CONFIG[r.risk_rating]
                const StatusIcon = st.icon
                return (
                  <tr key={r.id} className="hover:bg-[#0a1628] transition-colors">
                    <td className="px-4 py-3">
                      <div>
                        <p className="text-white text-sm font-medium max-w-xs truncate">{r.name}</p>
                        <p className="text-[#3d5068] text-xs">{r.system_name}</p>
                      </div>
                    </td>
                    <td className="px-4 py-3"><Badge cls={rt.cls}>{rt.label}</Badge></td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border text-xs font-medium ${st.cls}`}>
                        <StatusIcon className="w-3 h-3" />{st.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3 h-3 text-[#3d5068]" />
                        <span className="text-[#7d92b0] text-sm">{r.requested_by}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{r.assigned_reviewer}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{r.submission_date}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap">{r.target_completion}</td>
                    <td className="px-4 py-3"><Badge cls={rk.cls}>{rk.label}</Badge></td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedReview(r)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0a1628] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/30 rounded-sm text-xs transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" /> 詳細
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {selectedReview && <ReviewDetailPanel review={selectedReview} onClose={() => setSelectedReview(null)} />}
      {showCreate && <CreateReviewModal onClose={() => setShowCreate(false)} />}
    </div>
  )
}
