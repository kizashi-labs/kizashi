'use client'



import { useState } from 'react'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'

import {

  Shield, Users, FileText, AlertTriangle, CheckCircle, XCircle,

  Plus, Clock, RefreshCw, X, ChevronRight, Database, ArrowRight,

  Info, Flag, Eye, Trash2, Check,

} from 'lucide-react'




// ─── Types ────────────────────────────────────────────────────────────────────



type SubjectType = 'employee' | 'customer' | 'contractor'

type DataCategory = 'PII' | 'financial' | 'health' | 'behavioral' | 'location'

type DSARType = 'access' | 'rectification' | 'erasure' | 'portability' | 'objection'

type DSARStatus = 'pending' | 'in_progress' | 'completed' | 'overdue'

type IncidentType = 'breach' | 'unauthorized_access' | 'data_loss' | 'accidental_disclosure'

type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical'

type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'reported'



interface DataSubject {

  id: string

  email: string

  name: string

  subject_type: SubjectType

  data_categories: DataCategory[]

  consent_given: boolean

  retention_period_days: number

  deletion_requested: boolean

  created_at: string

}



interface DSARRequest {

  id: string

  subject_email: string

  subject_name: string

  request_type: DSARType

  status: DSARStatus

  due_date: string

  completed_at?: string

  notes?: string

  response_notes?: string

  created_at: string

}



interface PrivacyIncident {

  id: string

  incident_type: IncidentType

  description: string

  affected_subjects_count: number

  data_categories: DataCategory[]

  severity: IncidentSeverity

  reported_to_authority: boolean

  status: IncidentStatus

  remediation_steps?: string

  created_at: string

}



interface PrivacyStats {

  total_subjects: number

  active_dsars: number

  overdue_dsars: number

  open_incidents: number

}



interface RoPAEntry {

  id: string

  activity: string

  purpose: string

  legal_basis: string

  data_categories: string[]

  retention: string

  third_parties: string[]

}



// ─── Helpers ─────────────────────────────────────────────────────────────────



function maskEmail(email: string): string {

  const [local, domain] = email.split('@')

  if (!domain || local.length < 2) return email

  return `${local.slice(0, 2)}***@${domain}`

}



function daysUntil(dateStr: string): number {

  const diff = new Date(dateStr).getTime() - Date.now()

  return Math.ceil(diff / (1000 * 60 * 60 * 24))

}



function formatDate(dateStr: string): string {

  return new Date(dateStr).toLocaleDateString('ja-JP', {

    year: 'numeric', month: '2-digit', day: '2-digit',

  })

}



function subjectTypeBadge(type: SubjectType): string {

  switch (type) {

    case 'employee': return 'bg-blue-900/40 text-blue-300 border-blue-700/40'

    case 'customer': return 'bg-purple-900/40 text-purple-300 border-purple-700/40'

    case 'contractor': return 'bg-yellow-900/40 text-yellow-300 border-yellow-700/40'

  }

}



function subjectTypeLabel(type: SubjectType): string {

  switch (type) {

    case 'employee': return '従業員'

    case 'customer': return '顧客'

    case 'contractor': return '委託先'

  }

}



function dsarTypeBadge(type: DSARType): string {

  switch (type) {

    case 'access': return 'bg-blue-900/40 text-blue-300 border-blue-700/40'

    case 'rectification': return 'bg-yellow-900/40 text-yellow-300 border-yellow-700/40'

    case 'erasure': return 'bg-red-900/40 text-red-300 border-red-700/40'

    case 'portability': return 'bg-teal-900/40 text-teal-300 border-teal-700/40'

    case 'objection': return 'bg-orange-900/40 text-orange-300 border-orange-700/40'

  }

}



function dsarTypeLabel(type: DSARType): string {

  switch (type) {

    case 'access': return 'アクセス (Art.15)'

    case 'rectification': return '訂正 (Art.16)'

    case 'erasure': return '消去 (Art.17)'

    case 'portability': return '移転 (Art.20)'

    case 'objection': return '異議 (Art.21)'

  }

}



function dsarStatusBadge(status: DSARStatus): string {

  switch (status) {

    case 'pending': return 'bg-yellow-900/40 text-yellow-300 border-yellow-700/40'

    case 'in_progress': return 'bg-blue-900/40 text-blue-300 border-blue-700/40'

    case 'completed': return 'bg-green-900/40 text-green-300 border-green-700/40'

    case 'overdue': return 'bg-red-900/40 text-red-300 border-red-700/40'

  }

}



function dsarStatusLabel(status: DSARStatus): string {

  switch (status) {

    case 'pending': return '未着手'

    case 'in_progress': return '対応中'

    case 'completed': return '完了'

    case 'overdue': return '期限超過'

  }

}



function incidentTypeBadge(type: IncidentType): string {

  switch (type) {

    case 'breach': return 'bg-red-900/40 text-red-300 border-red-700/40'

    case 'unauthorized_access': return 'bg-orange-900/40 text-orange-300 border-orange-700/40'

    case 'data_loss': return 'bg-purple-900/40 text-purple-300 border-purple-700/40'

    case 'accidental_disclosure': return 'bg-yellow-900/40 text-yellow-300 border-yellow-700/40'

  }

}



function incidentTypeLabel(type: IncidentType): string {

  switch (type) {

    case 'breach': return 'データ漏洩'

    case 'unauthorized_access': return '不正アクセス'

    case 'data_loss': return 'データ損失'

    case 'accidental_disclosure': return '誤開示'

  }

}



function severityBadge(severity: IncidentSeverity): string {

  switch (severity) {

    case 'low': return 'bg-green-900/40 text-green-300 border-green-700/40'

    case 'medium': return 'bg-yellow-900/40 text-yellow-300 border-yellow-700/40'

    case 'high': return 'bg-orange-900/40 text-orange-300 border-orange-700/40'

    case 'critical': return 'bg-red-900/40 text-red-300 border-red-700/40'

  }

}



function severityLabel(severity: IncidentSeverity): string {

  switch (severity) {

    case 'low': return '低'

    case 'medium': return '中'

    case 'high': return '高'

    case 'critical': return '重大'

  }

}



function incidentStatusLabel(status: IncidentStatus): string {

  switch (status) {

    case 'open': return '未対応'

    case 'investigating': return '調査中'

    case 'resolved': return '解決済み'

    case 'reported': return '当局報告済み'

  }

}



const DATA_CATEGORIES: DataCategory[] = ['PII', 'financial', 'health', 'behavioral', 'location']

const DATA_CATEGORY_LABELS: Record<DataCategory, string> = {

  PII: '個人識別情報',

  financial: '金融情報',

  health: '健康情報',

  behavioral: '行動データ',

  location: '位置情報',

}



// ─── Sub-components ───────────────────────────────────────────────────────────



function StatCard({

  icon: Icon, label, value, accent,

}: { icon: React.ElementType; label: string; value: number; accent?: boolean }) {

  return (

    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-4">

      <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${

        accent ? 'bg-red-900/30' : 'bg-[#161f33]'

      }`}>

        <Icon className={`w-5 h-5 ${accent ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`} />

      </div>

      <div>

        <p className="text-[#7d92b0] text-xs">{label}</p>

        <p className={`text-2xl font-bold ${accent ? 'text-[#e8002d]' : 'text-[#e2e8f4]'}`}>{value}</p>

      </div>

    </div>

  )

}



function Badge({ className, children }: { className: string; children: React.ReactNode }) {

  return (

    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${className}`}>

      {children}

    </span>

  )

}



function CategoryTag({ category }: { category: DataCategory }) {

  return (

    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-[#161f33] border border-[#1e2d42] text-[#7d92b0]">

      {category}

    </span>

  )

}



// ─── Add Subject Modal ────────────────────────────────────────────────────────



function AddSubjectModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {

  const [form, setForm] = useState({

    subject_type: 'customer' as SubjectType,

    email: '',

    name: '',

    data_categories: [] as DataCategory[],

    consent_given: false,

    retention_period_days: 365,

  })



  const mutation = useMutation({

    mutationFn: (data: typeof form) => apiFetch('/api/v1/privacy/subjects', { method: 'POST', body: JSON.stringify(data) }),

    onSuccess: () => { onSuccess(); onClose() },

    onError: () => { onSuccess(); onClose() },

  })



  const toggleCategory = (cat: DataCategory) => {

    setForm(f => ({

      ...f,

      data_categories: f.data_categories.includes(cat)

        ? f.data_categories.filter(c => c !== cat)

        : [...f.data_categories, cat],

    }))

  }



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6 shadow-2xl">

        <div className="flex items-center justify-between mb-6">

          <h3 className="text-white font-semibold text-lg">データ主体追加</h3>

          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>

        </div>

        <div className="space-y-4">

          <div className="grid grid-cols-2 gap-4">

            <div>

              <label className="text-[#7d92b0] text-xs block mb-1">種別</label>

              <select

                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

                value={form.subject_type}

                onChange={e => setForm(f => ({ ...f, subject_type: e.target.value as SubjectType }))}

              >

                <option value="employee">従業員</option>

                <option value="customer">顧客</option>

                <option value="contractor">委託先</option>

              </select>

            </div>

            <div>

              <label className="text-[#7d92b0] text-xs block mb-1">保持期間 (日)</label>

              <input

                type="number"

                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

                value={form.retention_period_days}

                onChange={e => setForm(f => ({ ...f, retention_period_days: parseInt(e.target.value) }))}

              />

            </div>

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-1">メールアドレス</label>

            <input

              type="email"

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

              placeholder="user@example.com"

              value={form.email}

              onChange={e => setForm(f => ({ ...f, email: e.target.value }))}

            />

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-1">氏名</label>

            <input

              type="text"

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

              placeholder="山田 太郎"

              value={form.name}

              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}

            />

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-2">データカテゴリ</label>

            <div className="grid grid-cols-2 gap-2">

              {DATA_CATEGORIES.map(cat => (

                <label key={cat} className="flex items-center gap-2 cursor-pointer">

                  <input

                    type="checkbox"

                    className="accent-[#e8002d]"

                    checked={form.data_categories.includes(cat)}

                    onChange={() => toggleCategory(cat)}

                  />

                  <span className="text-[#e2e8f4] text-sm">{DATA_CATEGORY_LABELS[cat]}</span>

                </label>

              ))}

            </div>

          </div>

          <div className="flex items-center gap-3">

            <label className="text-[#7d92b0] text-sm">同意取得済み</label>

            <button

              onClick={() => setForm(f => ({ ...f, consent_given: !f.consent_given }))}

              className={`relative w-10 h-5 rounded-full transition-colors ${form.consent_given ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}

            >

              <span className={`absolute top-0.5 w-4 h-4 bg-[#e2e8f4] rounded-full transition-transform shadow ${form.consent_given ? 'translate-x-5' : 'translate-x-0.5'}`} />

            </button>

          </div>

        </div>

        <div className="flex gap-3 mt-6">

          <button onClick={onClose} className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>

          <button

            onClick={() => mutation.mutate(form)}

            disabled={mutation.isPending || !form.email || !form.name}

            className="flex-1 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c00025] disabled:opacity-50 text-white text-sm font-medium transition-colors"

          >

            {mutation.isPending ? '登録中...' : '追加'}

          </button>

        </div>

      </div>

    </div>

  )

}



// ─── DSAR Modal ───────────────────────────────────────────────────────────────



const DSAR_TYPE_DESCRIPTIONS: Record<DSARType, string> = {

  access: 'GDPR Art.15: 保有データへのアクセス要求',

  rectification: 'GDPR Art.16: 不正確なデータの訂正要求',

  erasure: 'GDPR Art.17: 「忘れられる権利」によるデータ削除',

  portability: 'GDPR Art.20: データの機械可読形式での提供',

  objection: 'GDPR Art.21: データ処理への異議申し立て',

}



function AddDSARModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {

  const [form, setForm] = useState({

    request_type: 'access' as DSARType,

    subject_email: '',

    subject_name: '',

    notes: '',

  })



  const mutation = useMutation({

    mutationFn: (data: typeof form) => apiFetch('/api/v1/privacy/dsar', { method: 'POST', body: JSON.stringify(data) }),

    onSuccess: () => { onSuccess(); onClose() },

    onError: () => { onSuccess(); onClose() },

  })



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6 shadow-2xl">

        <div className="flex items-center justify-between mb-6">

          <h3 className="text-white font-semibold text-lg">DSAR新規登録</h3>

          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>

        </div>

        <div className="space-y-4">

          <div>

            <label className="text-[#7d92b0] text-xs block mb-1">リクエスト種別</label>

            <select

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

              value={form.request_type}

              onChange={e => setForm(f => ({ ...f, request_type: e.target.value as DSARType }))}

            >

              {(Object.keys(DSAR_TYPE_DESCRIPTIONS) as DSARType[]).map(t => (

                <option key={t} value={t}>{dsarTypeLabel(t)}</option>

              ))}

            </select>

            <p className="text-[#7d92b0] text-xs mt-1">{DSAR_TYPE_DESCRIPTIONS[form.request_type]}</p>

          </div>

          <div className="grid grid-cols-2 gap-4">

            <div>

              <label className="text-[#7d92b0] text-xs block mb-1">メールアドレス</label>

              <input

                type="email"

                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

                value={form.subject_email}

                onChange={e => setForm(f => ({ ...f, subject_email: e.target.value }))}

              />

            </div>

            <div>

              <label className="text-[#7d92b0] text-xs block mb-1">氏名</label>

              <input

                type="text"

                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

                value={form.subject_name}

                onChange={e => setForm(f => ({ ...f, subject_name: e.target.value }))}

              />

            </div>

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-1">備考</label>

            <textarea

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa] resize-none"

              rows={3}

              value={form.notes}

              onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}

            />

          </div>

          <div className="bg-blue-900/20 border border-blue-700/40 rounded-lg p-3 flex gap-2">

            <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />

            <p className="text-blue-300 text-xs">DSARは受付から30日以内に対応する義務があります (GDPR Art.12(3))。期限を超えた場合は自動的に「期限超過」となります。</p>

          </div>

        </div>

        <div className="flex gap-3 mt-6">

          <button onClick={onClose} className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>

          <button

            onClick={() => mutation.mutate(form)}

            disabled={mutation.isPending || !form.subject_email}

            className="flex-1 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c00025] disabled:opacity-50 text-white text-sm font-medium transition-colors"

          >

            {mutation.isPending ? '登録中...' : '登録'}

          </button>

        </div>

      </div>

    </div>

  )

}



// ─── Complete DSAR Modal ──────────────────────────────────────────────────────



function CompleteDSARModal({ dsar, onClose, onSuccess }: { dsar: DSARRequest; onClose: () => void; onSuccess: () => void }) {

  const [responseNotes, setResponseNotes] = useState('')



  const mutation = useMutation({

    mutationFn: () => apiFetch(`/api/v1/privacy/dsar/${dsar.id}/complete`, {

      method: 'POST',

      body: JSON.stringify({ response_notes: responseNotes }),

    }),

    onSuccess: () => { onSuccess(); onClose() },

    onError: () => { onSuccess(); onClose() },

  })



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6 shadow-2xl">

        <div className="flex items-center justify-between mb-4">

          <h3 className="text-white font-semibold text-lg">DSAR完了処理</h3>

          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>

        </div>

        <div className="bg-[#161f33] rounded-lg p-3 mb-4 space-y-1">

          <p className="text-[#7d92b0] text-xs">リクエストID: <span className="text-[#e2e8f4] font-mono">{dsar.id}</span></p>

          <p className="text-[#7d92b0] text-xs">種別: <span className="text-[#e2e8f4]">{dsarTypeLabel(dsar.request_type)}</span></p>

          <p className="text-[#7d92b0] text-xs">申請者: <span className="text-[#e2e8f4]">{dsar.subject_name}</span></p>

        </div>

        <div>

          <label className="text-[#7d92b0] text-xs block mb-1">対応内容・回答メモ</label>

          <textarea

            className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa] resize-none"

            rows={4}

            placeholder="データ主体への回答内容・実施した処置を記録してください"

            value={responseNotes}

            onChange={e => setResponseNotes(e.target.value)}

          />

        </div>

        <div className="flex gap-3 mt-5">

          <button onClick={onClose} className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>

          <button

            onClick={() => mutation.mutate()}

            disabled={mutation.isPending}

            className="flex-1 px-4 py-2 rounded bg-green-700 hover:bg-green-600 disabled:opacity-50 text-white text-sm font-medium transition-colors flex items-center justify-center gap-2"

          >

            <Check className="w-4 h-4" />

            {mutation.isPending ? '処理中...' : '完了にする'}

          </button>

        </div>

      </div>

    </div>

  )

}



// ─── Add Incident Modal ───────────────────────────────────────────────────────



function AddIncidentModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {

  const [form, setForm] = useState({

    incident_type: 'breach' as IncidentType,

    description: '',

    affected_subjects_count: 0,

    data_categories: [] as DataCategory[],

    severity: 'medium' as IncidentSeverity,

    remediation_steps: '',

  })



  const mutation = useMutation({

    mutationFn: (data: typeof form) => apiFetch('/api/v1/privacy/incidents', { method: 'POST', body: JSON.stringify(data) }),

    onSuccess: () => { onSuccess(); onClose() },

    onError: () => { onSuccess(); onClose() },

  })



  const toggleCategory = (cat: DataCategory) => {

    setForm(f => ({

      ...f,

      data_categories: f.data_categories.includes(cat)

        ? f.data_categories.filter(c => c !== cat)

        : [...f.data_categories, cat],

    }))

  }



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6 shadow-2xl max-h-[90vh] overflow-y-auto">

        <div className="flex items-center justify-between mb-6">

          <h3 className="text-white font-semibold text-lg">インシデント登録</h3>

          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>

        </div>

        <div className="space-y-4">

          <div className="grid grid-cols-2 gap-4">

            <div>

              <label className="text-[#7d92b0] text-xs block mb-1">インシデント種別</label>

              <select

                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

                value={form.incident_type}

                onChange={e => setForm(f => ({ ...f, incident_type: e.target.value as IncidentType }))}

              >

                <option value="breach">データ漏洩</option>

                <option value="unauthorized_access">不正アクセス</option>

                <option value="data_loss">データ損失</option>

                <option value="accidental_disclosure">誤開示</option>

              </select>

            </div>

            <div>

              <label className="text-[#7d92b0] text-xs block mb-1">深刻度</label>

              <select

                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

                value={form.severity}

                onChange={e => setForm(f => ({ ...f, severity: e.target.value as IncidentSeverity }))}

              >

                <option value="low">低</option>

                <option value="medium">中</option>

                <option value="high">高</option>

                <option value="critical">重大</option>

              </select>

            </div>

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-1">説明</label>

            <textarea

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa] resize-none"

              rows={3}

              value={form.description}

              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}

            />

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-1">影響を受けるデータ主体数</label>

            <input

              type="number"

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa]"

              value={form.affected_subjects_count}

              onChange={e => setForm(f => ({ ...f, affected_subjects_count: parseInt(e.target.value) }))}

            />

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-2">関連データカテゴリ</label>

            <div className="grid grid-cols-2 gap-2">

              {DATA_CATEGORIES.map(cat => (

                <label key={cat} className="flex items-center gap-2 cursor-pointer">

                  <input

                    type="checkbox"

                    className="accent-[#e8002d]"

                    checked={form.data_categories.includes(cat)}

                    onChange={() => toggleCategory(cat)}

                  />

                  <span className="text-[#e2e8f4] text-sm">{DATA_CATEGORY_LABELS[cat]}</span>

                </label>

              ))}

            </div>

          </div>

          <div>

            <label className="text-[#7d92b0] text-xs block mb-1">是正措置</label>

            <textarea

              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] focus:outline-none focus:border-[#3d6baa] resize-none"

              rows={2}

              value={form.remediation_steps}

              onChange={e => setForm(f => ({ ...f, remediation_steps: e.target.value }))}

            />

          </div>

          <div className="bg-orange-900/20 border border-orange-700/40 rounded-lg p-3 flex gap-2">

            <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />

            <p className="text-orange-300 text-xs">GDPR Art.33: 個人データ侵害を認知してから72時間以内に監督機関へ報告する義務があります。</p>

          </div>

        </div>

        <div className="flex gap-3 mt-6">

          <button onClick={onClose} className="flex-1 px-4 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>

          <button

            onClick={() => mutation.mutate(form)}

            disabled={mutation.isPending || !form.description}

            className="flex-1 px-4 py-2 rounded bg-[#e8002d] hover:bg-[#c00025] disabled:opacity-50 text-white text-sm font-medium transition-colors"

          >

            {mutation.isPending ? '登録中...' : '登録'}

          </button>

        </div>

      </div>

    </div>

  )

}



// ─── Data Mapping Tab ─────────────────────────────────────────────────────────



function DataMappingTab() {

  const dataSources = [

    { id: 'hr', label: 'HR System', x: 40, y: 60, categories: ['PII', '雇用情報', '給与'] },

    { id: 'crm', label: 'CRM', x: 40, y: 180, categories: ['PII', '連絡先', '購買履歴'] },

    { id: 'security', label: 'Security Tools', x: 40, y: 300, categories: ['ログ', 'イベント', 'アラート'] },

    { id: 'edr', label: 'EDR Agents', x: 40, y: 420, categories: ['行動データ', 'プロセス', 'ネットワーク'] },

  ]



  const storageNodes = [

    { id: 'db', label: 'Central DB', x: 280, y: 60, color: '#1a6bff' },

    { id: 'log', label: 'Log Storage', x: 280, y: 200, color: '#7c3aed' },

    { id: 'archive', label: 'Archive', x: 280, y: 340, color: '#059669' },

  ]



  const processingNodes = [

    { id: 'siem', label: 'SIEM Engine', x: 500, y: 120, color: '#d97706' },

    { id: 'ml', label: 'ML / UEBA', x: 500, y: 280, color: '#e8002d' },

    { id: 'report', label: 'Reporting', x: 500, y: 400, color: '#0891b2' },

  ]



  const flows = [

    { from: { x: 160, y: 75 }, to: { x: 280, y: 75 } },

    { from: { x: 160, y: 195 }, to: { x: 280, y: 75 } },

    { from: { x: 160, y: 315 }, to: { x: 280, y: 215 } },

    { from: { x: 160, y: 435 }, to: { x: 280, y: 215 } },

    { from: { x: 160, y: 435 }, to: { x: 280, y: 355 } },

    { from: { x: 400, y: 75 }, to: { x: 500, y: 135 } },

    { from: { x: 400, y: 215 }, to: { x: 500, y: 135 } },

    { from: { x: 400, y: 215 }, to: { x: 500, y: 295 } },

    { from: { x: 400, y: 355 }, to: { x: 500, y: 415 } },

  ]



  return (

    <div className="space-y-6">

      {/* Data Flow Diagram */}

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6">

        <h3 className="text-white font-semibold mb-2">データフロー図</h3>

        <p className="text-[#7d92b0] text-xs mb-4">Kizashi プラットフォームが収集・処理するデータの流れ</p>

        <div className="overflow-x-auto">

          <svg width="680" height="500" className="min-w-[680px]">

            {/* Section labels */}

            <text x="75" y="22" fill="#7d92b0" fontSize="11" textAnchor="middle" fontWeight="500">データソース</text>

            <text x="340" y="22" fill="#7d92b0" fontSize="11" textAnchor="middle" fontWeight="500">ストレージ</text>

            <text x="560" y="22" fill="#7d92b0" fontSize="11" textAnchor="middle" fontWeight="500">処理エンジン</text>



            {/* Section backgrounds */}

            <rect x="10" y="30" width="150" height="460" rx="8" fill="#0a1323" stroke="#1e2d42" strokeWidth="1" />

            <rect x="250" y="30" width="150" height="360" rx="8" fill="#0a1323" stroke="#1e2d42" strokeWidth="1" />

            <rect x="470" y="30" width="150" height="420" rx="8" fill="#0a1323" stroke="#1e2d42" strokeWidth="1" />



            {/* Flow arrows */}

            {flows.map((f, i) => (

              <g key={i}>

                <line

                  x1={f.from.x} y1={f.from.y}

                  x2={f.to.x} y2={f.to.y}

                  stroke="#1e2d42" strokeWidth="1.5"

                  markerEnd="url(#arrowhead)"

                />

              </g>

            ))}



            {/* Arrowhead marker */}

            <defs>

              <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">

                <polygon points="0 0, 8 3, 0 6" fill="#1e2d42" />

              </marker>

            </defs>



            {/* Data source nodes */}

            {dataSources.map(node => (

              <g key={node.id}>

                <rect x={node.x} y={node.y - 15} width="120" height="60" rx="6" fill="#161f33" stroke="#1e2d42" strokeWidth="1" />

                <text x={node.x + 60} y={node.y + 4} fill="#e2e8f4" fontSize="11" textAnchor="middle" fontWeight="600">{node.label}</text>

                <text x={node.x + 60} y={node.y + 18} fill="#7d92b0" fontSize="9" textAnchor="middle">{node.categories.join(' · ')}</text>

                <circle cx={node.x + 120} cy={node.y + 15} r="4" fill="#1e2d42" />

              </g>

            ))}



            {/* Storage nodes */}

            {storageNodes.map(node => (

              <g key={node.id}>

                <rect x={node.x} y={node.y - 20} width="120" height="50" rx="6" fill="#161f33" stroke={node.color} strokeWidth="1" opacity="0.8" />

                <text x={node.x + 60} y={node.y + 7} fill="#e2e8f4" fontSize="11" textAnchor="middle" fontWeight="600">{node.label}</text>

                <circle cx={node.x} cy={node.y + 5} r="4" fill={node.color} opacity="0.6" />

                <circle cx={node.x + 120} cy={node.y + 5} r="4" fill={node.color} opacity="0.6" />

              </g>

            ))}



            {/* Processing nodes */}

            {processingNodes.map(node => (

              <g key={node.id}>

                <rect x={node.x} y={node.y - 20} width="120" height="50" rx="6" fill="#161f33" stroke={node.color} strokeWidth="1.5" opacity="0.9" />

                <text x={node.x + 60} y={node.y + 7} fill="#e2e8f4" fontSize="11" textAnchor="middle" fontWeight="600">{node.label}</text>

                <circle cx={node.x} cy={node.y + 5} r="4" fill={node.color} opacity="0.8" />

              </g>

            ))}

          </svg>

        </div>



        {/* Retention legend */}

        <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-3">

          {[

            { label: 'PII / 個人情報', retention: '730日', color: '#1a6bff' },

            { label: '行動・ログデータ', retention: '365日', color: '#7c3aed' },

            { label: 'フォレンジクス', retention: '1095日', color: '#e8002d' },

            { label: 'アーカイブ', retention: '2190日', color: '#059669' },

          ].map(item => (

            <div key={item.label} className="bg-[#161f33] rounded-lg p-3 border border-[#1e2d42]">

              <div className="flex items-center gap-2 mb-1">

                <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />

                <span className="text-[#e2e8f4] text-xs font-medium">{item.label}</span>

              </div>

              <p className="text-[#7d92b0] text-xs">保持期間: {item.retention}</p>

            </div>

          ))}

        </div>

      </div>



      {/* RoPA Table */}

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg">

        <div className="p-4 border-b border-[#1e2d42]">

          <h3 className="text-white font-semibold">データ処理活動記録 (RoPA)</h3>

          <p className="text-[#7d92b0] text-xs mt-1">GDPR Art.30 — Records of Processing Activities</p>

        </div>

        <div className="overflow-x-auto">

          <table className="w-full text-sm">

            <thead>

              <tr className="border-b border-[#1e2d42]">

                {['処理活動', '目的', '法的根拠', 'データカテゴリ', '保持期間', '第三者提供先'].map(h => (

                  <th key={h} className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs whitespace-nowrap">{h}</th>

                ))}

              </tr>

            </thead>

            <tbody>

              {([] as RoPAEntry[]).map((entry, idx) => (

                <tr key={entry.id} className={`border-b border-[#1e2d42]/50 ${idx % 2 === 0 ? '' : 'bg-[#070d19]/30'}`}>

                  <td className="px-4 py-3 text-[#e2e8f4] font-medium whitespace-nowrap">{entry.activity}</td>

                  <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[140px]">{entry.purpose}</td>

                  <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{entry.legal_basis}</td>

                  <td className="px-4 py-3">

                    <div className="flex flex-wrap gap-1">

                      {entry.data_categories.map(c => (

                        <span key={c} className="inline-flex px-1.5 py-0.5 rounded text-[10px] bg-[#161f33] border border-[#1e2d42] text-[#7d92b0]">{c}</span>

                      ))}

                    </div>

                  </td>

                  <td className="px-4 py-3 text-[#e2e8f4] text-xs font-mono whitespace-nowrap">{entry.retention}</td>

                  <td className="px-4 py-3 text-xs">

                    {entry.third_parties.length === 0

                      ? <span className="text-green-400">なし</span>

                      : entry.third_parties.map(tp => (

                          <span key={tp} className="block text-[#7d92b0]">{tp}</span>

                        ))

                    }

                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>

      </div>

    </div>

  )

}



// ─── Main Page ────────────────────────────────────────────────────────────────



type Tab = 'subjects' | 'dsar' | 'incidents' | 'mapping'



export default function PrivacyPage() {

  const queryClient = useQueryClient()

  const [activeTab, setActiveTab] = useState<Tab>('subjects')

  const [showAddSubject, setShowAddSubject] = useState(false)

  const [showAddDSAR, setShowAddDSAR] = useState(false)

  const [showAddIncident, setShowAddIncident] = useState(false)

  const [completingDSAR, setCompletingDSAR] = useState<DSARRequest | null>(null)

  const [deletingSubjectId, setDeletingSubjectId] = useState<string | null>(null)

  const [reportingIncidentId, setReportingIncidentId] = useState<string | null>(null)



  // ── API Queries ──────────────────────────────────────────────

  const { data: stats } = useQuery<PrivacyStats>({

    queryKey: ['privacy-stats'],

    queryFn: () => apiFetch<PrivacyStats>('/api/v1/privacy/stats').catch(() => EMPTY_STATS),

    staleTime: 60_000,

    retry: false,


  })



  const { data: subjectsData, refetch: refetchSubjects } = useQuery<{ subjects: DataSubject[] }>({

    queryKey: ['privacy-subjects'],

    queryFn: () => apiFetch<{ subjects: DataSubject[] }>('/api/v1/privacy/subjects').catch(() => ({ subjects: [] })),

    staleTime: 60_000,

    retry: false,


  })



  const { data: dsarData, refetch: refetchDSAR } = useQuery<{ requests: DSARRequest[] }>({

    queryKey: ['privacy-dsar'],

    queryFn: () => apiFetch<{ requests: DSARRequest[] }>('/api/v1/privacy/dsar').catch(() => ({ requests: [] })),

    staleTime: 60_000,

    retry: false,


  })



  const { data: incidentsData, refetch: refetchIncidents } = useQuery<{ incidents: PrivacyIncident[] }>({

    queryKey: ['privacy-incidents'],

    queryFn: () => apiFetch<{ incidents: PrivacyIncident[] }>('/api/v1/privacy/incidents').catch(() => ({ incidents: [] })),

    staleTime: 60_000,

    retry: false,


  })



  // ── Mutations ────────────────────────────────────────────────

  const deleteSubjectMutation = useMutation({

    mutationFn: (id: string) => apiFetch(`/api/v1/privacy/subjects/${id}`, { method: 'DELETE' }),

    onSuccess: () => { setDeletingSubjectId(null); refetchSubjects() },

    onError: () => { setDeletingSubjectId(null); refetchSubjects() },

  })



  const reportIncidentMutation = useMutation({

    mutationFn: (id: string) => apiFetch(`/api/v1/privacy/incidents/${id}`, {

      method: 'PATCH',

      body: JSON.stringify({ reported_to_authority: true }),

    }),

    onSuccess: () => { setReportingIncidentId(null); refetchIncidents() },

    onError: () => { setReportingIncidentId(null); refetchIncidents() },

  })



  const EMPTY_STATS: PrivacyStats = { total_subjects: 0, active_dsars: 0, overdue_dsars: 0, open_incidents: 0 }
  const displayStats = stats ?? EMPTY_STATS

  const subjects = subjectsData?.subjects ?? []

  const dsarRequests = dsarData?.requests ?? []

  const incidents = incidentsData?.incidents ?? []



  // Sort DSAR — overdue first

  const sortedDSAR = [...dsarRequests].sort((a, b) => {

    if (a.status === 'overdue' && b.status !== 'overdue') return -1

    if (b.status === 'overdue' && a.status !== 'overdue') return 1

    return 0

  })



  const tabs: { id: Tab; label: string }[] = [

    { id: 'subjects', label: 'データ主体' },

    { id: 'dsar', label: 'DSAR' },

    { id: 'incidents', label: 'プライバシーインシデント' },

    { id: 'mapping', label: 'データマッピング' },

  ]



  return (

    <div className="min-h-screen bg-[#070d19] p-6">

      {/* ── Header ── */}

      <div className="mb-6">

        <div className="flex items-center gap-2 text-[#7d92b0] text-xs mb-3">

          <span>管理</span>

          <ChevronRight className="w-3 h-3" />

          <span className="text-[#e2e8f4]">プライバシー/GDPR管理</span>

        </div>

        <div className="flex items-start justify-between">

          <div>

            <h1 className="text-2xl font-bold text-white flex items-center gap-3">

              <div className="w-8 h-8 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">

                <Shield className="w-4 h-4 text-[#e8002d]" />

              </div>

              プライバシー/GDPR管理

            </h1>

            <p className="text-[#7d92b0] text-sm mt-1">データ主体の権利管理・プライバシーインシデント・DSAR対応</p>

          </div>

          <button

            onClick={() => {

              queryClient.invalidateQueries({ queryKey: ['privacy-stats'] })

              queryClient.invalidateQueries({ queryKey: ['privacy-subjects'] })

              queryClient.invalidateQueries({ queryKey: ['privacy-dsar'] })

              queryClient.invalidateQueries({ queryKey: ['privacy-incidents'] })

            }}

            className="p-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#3d5068] transition-colors"

          >

            <RefreshCw className="w-4 h-4" />

          </button>

        </div>

      </div>



      {/* ── Stats ── */}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">

        <StatCard icon={Users} label="総データ主体数" value={displayStats.total_subjects} />

        <StatCard icon={FileText} label="進行中DSAR" value={displayStats.active_dsars} />

        <StatCard icon={Clock} label="期限超過DSAR" value={displayStats.overdue_dsars} accent />

        <StatCard icon={AlertTriangle} label="未解決インシデント" value={displayStats.open_incidents} accent={displayStats.open_incidents > 0} />

      </div>



      {/* ── Tabs ── */}

      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">

        {tabs.map(tab => (

          <button

            key={tab.id}

            onClick={() => setActiveTab(tab.id)}

            className={`px-4 py-2 rounded text-sm font-medium transition-all ${

              activeTab === tab.id

                ? 'bg-[#1d2f4a] text-white'

                : 'text-[#7d92b0] hover:text-[#e2e8f4]'

            }`}

          >

            {tab.label}

          </button>

        ))}

      </div>



      {/* ── Tab Content ── */}



      {/* データ主体 Tab */}

      {activeTab === 'subjects' && (

        <div className="space-y-4">

          <div className="flex justify-end">

            <button

              onClick={() => setShowAddSubject(true)}

              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c00025] text-white text-sm font-medium transition-colors"

            >

              <Plus className="w-4 h-4" />

              データ主体追加

            </button>

          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">

            <div className="overflow-x-auto">

              <table className="w-full text-sm">

                <thead>

                  <tr className="border-b border-[#1e2d42]">

                    {['メールアドレス', '氏名', '種別', 'データカテゴリ', '同意', '保持期間', '削除要求', '操作'].map(h => (

                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs whitespace-nowrap">{h}</th>

                    ))}

                  </tr>

                </thead>

                <tbody>

                  {subjects.map(subject => (

                    <tr key={subject.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33]/30 transition-colors ${subject.deletion_requested ? 'bg-red-900/5' : ''}`}>

                      <td className="px-4 py-3 font-mono text-[#e2e8f4] text-xs">{maskEmail(subject.email)}</td>

                      <td className="px-4 py-3 text-[#e2e8f4]">{subject.name}</td>

                      <td className="px-4 py-3">

                        <Badge className={subjectTypeBadge(subject.subject_type)}>

                          {subjectTypeLabel(subject.subject_type)}

                        </Badge>

                      </td>

                      <td className="px-4 py-3">

                        <div className="flex flex-wrap gap-1">

                          {subject.data_categories.map(c => <CategoryTag key={c} category={c} />)}

                        </div>

                      </td>

                      <td className="px-4 py-3">

                        {subject.consent_given

                          ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" />取得済み</span>

                          : <span className="flex items-center gap-1 text-[#7d92b0] text-xs"><XCircle className="w-3.5 h-3.5" />未取得</span>

                        }

                      </td>

                      <td className="px-4 py-3 text-[#7d92b0] text-xs font-mono">{subject.retention_period_days}日</td>

                      <td className="px-4 py-3">

                        {subject.deletion_requested

                          ? <span className="flex items-center gap-1 text-[#e8002d] text-xs font-medium"><AlertTriangle className="w-3.5 h-3.5" />保留中</span>

                          : <span className="text-[#7d92b0] text-xs">なし</span>

                        }

                      </td>

                      <td className="px-4 py-3">

                        <button

                          onClick={() => {

                            if (confirm(`"${subject.name}" の削除要求を処理しますか？`)) {

                              setDeletingSubjectId(subject.id)

                              deleteSubjectMutation.mutate(subject.id)

                            }

                          }}

                          disabled={deletingSubjectId === subject.id}

                          className="flex items-center gap-1 px-2.5 py-1.5 rounded text-xs bg-red-900/20 border border-red-700/40 text-red-400 hover:bg-red-900/40 disabled:opacity-50 transition-colors"

                        >

                          <Trash2 className="w-3 h-3" />

                          削除要求処理

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



      {/* DSAR Tab */}

      {activeTab === 'dsar' && (

        <div className="space-y-4">

          <div className="flex items-center justify-between">

            <div className="bg-blue-900/20 border border-blue-700/40 rounded-lg px-4 py-2.5 flex items-center gap-2">

              <Info className="w-4 h-4 text-blue-400 flex-shrink-0" />

              <p className="text-blue-300 text-xs">GDPR Art.12(3): DSARは受付から<strong>30日</strong>以内に対応が必要です。</p>

            </div>

            <button

              onClick={() => setShowAddDSAR(true)}

              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c00025] text-white text-sm font-medium transition-colors"

            >

              <Plus className="w-4 h-4" />

              DSAR新規登録

            </button>

          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">

            <div className="overflow-x-auto">

              <table className="w-full text-sm">

                <thead>

                  <tr className="border-b border-[#1e2d42]">

                    {['リクエストID', '申請者', '種別', 'ステータス', '期限', '完了日時', '操作'].map(h => (

                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs whitespace-nowrap">{h}</th>

                    ))}

                  </tr>

                </thead>

                <tbody>

                  {sortedDSAR.map(req => {

                    const daysLeft = daysUntil(req.due_date)

                    const isOverdue = req.status === 'overdue' || daysLeft < 0

                    const slaPercent = Math.max(0, Math.min(100, ((30 - Math.max(0, daysLeft)) / 30) * 100))



                    return (

                      <tr

                        key={req.id}

                        className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33]/30 transition-colors ${isOverdue ? 'bg-red-900/10' : ''}`}

                      >

                        <td className="px-4 py-3 font-mono text-[#7d92b0] text-xs">{req.id.slice(-8)}</td>

                        <td className="px-4 py-3">

                          <p className="text-[#e2e8f4] text-xs">{req.subject_name}</p>

                          <p className="text-[#7d92b0] text-[10px] font-mono">{maskEmail(req.subject_email)}</p>

                        </td>

                        <td className="px-4 py-3">

                          <Badge className={dsarTypeBadge(req.request_type)}>

                            {dsarTypeLabel(req.request_type)}

                          </Badge>

                        </td>

                        <td className="px-4 py-3">

                          <Badge className={`${dsarStatusBadge(req.status)} ${req.status === 'overdue' ? 'animate-pulse' : ''}`}>

                            {dsarStatusLabel(req.status)}

                          </Badge>

                        </td>

                        <td className="px-4 py-3">

                          <div>

                            <p className={`text-xs font-medium ${isOverdue ? 'text-[#e8002d]' : daysLeft <= 7 ? 'text-orange-400' : 'text-[#e2e8f4]'}`}>

                              {isOverdue ? `${Math.abs(daysLeft)}日超過` : `残${daysLeft}日`}

                            </p>

                            <p className="text-[#7d92b0] text-[10px]">{formatDate(req.due_date)}</p>

                            {/* SLA bar */}

                            <div className="mt-1 w-20 h-1 bg-[#1e2d42] rounded-full overflow-hidden">

                              <div

                                className={`h-full rounded-full transition-all ${slaPercent > 80 ? 'bg-[#e8002d]' : slaPercent > 60 ? 'bg-orange-500' : 'bg-green-500'}`}

                                style={{ width: `${slaPercent}%` }}

                              />

                            </div>

                          </div>

                        </td>

                        <td className="px-4 py-3 text-[#7d92b0] text-xs">

                          {req.completed_at ? formatDate(req.completed_at) : '—'}

                        </td>

                        <td className="px-4 py-3">

                          {req.status !== 'completed' && (

                            <button

                              onClick={() => setCompletingDSAR(req)}

                              className="flex items-center gap-1 px-2.5 py-1.5 rounded text-xs bg-green-900/20 border border-green-700/40 text-green-400 hover:bg-green-900/40 transition-colors"

                            >

                              <Check className="w-3 h-3" />

                              完了

                            </button>

                          )}

                          {req.status === 'completed' && (

                            <span className="flex items-center gap-1 text-green-400 text-xs">

                              <CheckCircle className="w-3.5 h-3.5" />完了済み

                            </span>

                          )}

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



      {/* プライバシーインシデント Tab */}

      {activeTab === 'incidents' && (

        <div className="space-y-4">

          <div className="flex items-center justify-between">

            <div className="bg-orange-900/20 border border-orange-700/40 rounded-lg px-4 py-2.5 flex items-center gap-2">

              <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0" />

              <p className="text-orange-300 text-xs">GDPR Art.33: 個人データ侵害は認知から<strong>72時間以内</strong>に監督機関へ報告が必要です。</p>

            </div>

            <button

              onClick={() => setShowAddIncident(true)}

              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c00025] text-white text-sm font-medium transition-colors"

            >

              <Plus className="w-4 h-4" />

              インシデント登録

            </button>

          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">

            <div className="overflow-x-auto">

              <table className="w-full text-sm">

                <thead>

                  <tr className="border-b border-[#1e2d42]">

                    {['種別', '説明', '影響者数', 'データカテゴリ', '深刻度', '当局報告', 'ステータス', '発生日', '操作'].map(h => (

                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] font-medium text-xs whitespace-nowrap">{h}</th>

                    ))}

                  </tr>

                </thead>

                <tbody>

                  {incidents.map(incident => (

                    <tr key={incident.id} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/30 transition-colors">

                      <td className="px-4 py-3">

                        <Badge className={incidentTypeBadge(incident.incident_type)}>

                          {incidentTypeLabel(incident.incident_type)}

                        </Badge>

                      </td>

                      <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[200px]">

                        <span title={incident.description}>

                          {incident.description.length > 60 ? `${incident.description.slice(0, 60)}…` : incident.description}

                        </span>

                      </td>

                      <td className="px-4 py-3">

                        <span className={`font-bold text-sm ${incident.affected_subjects_count > 100 ? 'text-[#e8002d]' : 'text-[#e2e8f4]'}`}>

                          {(incident.affected_subjects_count ?? 0).toLocaleString()}

                        </span>

                      </td>

                      <td className="px-4 py-3">

                        <div className="flex flex-wrap gap-1">

                          {incident.data_categories.map(c => <CategoryTag key={c} category={c} />)}

                        </div>

                      </td>

                      <td className="px-4 py-3">

                        <Badge className={severityBadge(incident.severity)}>

                          {severityLabel(incident.severity)}

                        </Badge>

                      </td>

                      <td className="px-4 py-3">

                        {incident.reported_to_authority

                          ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" />報告済</span>

                          : <span className="flex items-center gap-1 text-[#7d92b0] text-xs"><XCircle className="w-3.5 h-3.5" />未報告</span>

                        }

                      </td>

                      <td className="px-4 py-3">

                        <Badge className={

                          incident.status === 'resolved' || incident.status === 'reported'

                            ? 'bg-green-900/40 text-green-300 border-green-700/40'

                            : incident.status === 'investigating'

                              ? 'bg-blue-900/40 text-blue-300 border-blue-700/40'

                              : 'bg-orange-900/40 text-orange-300 border-orange-700/40'

                        }>

                          {incidentStatusLabel(incident.status)}

                        </Badge>

                      </td>

                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{formatDate(incident.created_at)}</td>

                      <td className="px-4 py-3">

                        {!incident.reported_to_authority && (

                          <button

                            onClick={() => {

                              setReportingIncidentId(incident.id)

                              reportIncidentMutation.mutate(incident.id)

                            }}

                            disabled={reportingIncidentId === incident.id}

                            className="flex items-center gap-1 px-2.5 py-1.5 rounded text-xs bg-blue-900/20 border border-blue-700/40 text-blue-400 hover:bg-blue-900/40 disabled:opacity-50 transition-colors whitespace-nowrap"

                          >

                            <Flag className="w-3 h-3" />

                            当局報告済み

                          </button>

                        )}

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          </div>

        </div>

      )}



      {/* データマッピング Tab */}

      {activeTab === 'mapping' && <DataMappingTab />}



      {/* ── Modals ── */}

      {showAddSubject && (

        <AddSubjectModal

          onClose={() => setShowAddSubject(false)}

          onSuccess={() => refetchSubjects()}

        />

      )}

      {showAddDSAR && (

        <AddDSARModal

          onClose={() => setShowAddDSAR(false)}

          onSuccess={() => refetchDSAR()}

        />

      )}

      {showAddIncident && (

        <AddIncidentModal

          onClose={() => setShowAddIncident(false)}

          onSuccess={() => refetchIncidents()}

        />

      )}

      {completingDSAR && (

        <CompleteDSARModal

          dsar={completingDSAR}

          onClose={() => setCompletingDSAR(null)}

          onSuccess={() => refetchDSAR()}

        />

      )}

    </div>

  )

}

