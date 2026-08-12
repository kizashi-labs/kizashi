'use client'



import { useState } from 'react'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'

import {

  BookOpen, Play, Plus, Trash2, Edit2, ToggleLeft, ToggleRight,

  ChevronDown, X, GripVertical, CheckCircle, Clock, XCircle,

  AlertTriangle, Shield, Zap, RefreshCw, Search, Filter,

  ArrowRight, CheckSquare, Square, Activity, Users, TrendingUp

} from 'lucide-react'




// ── Types ──────────────────────────────────────────────────────────────────────



interface PlaybookStep {

  id: string

  order: number

  title: string

  description: string

  type: 'investigation' | 'containment' | 'eradication' | 'recovery' | 'communication'

  required: boolean

}



interface Playbook {

  id: string

  name: string

  description: string

  incident_type: 'ransomware' | 'phishing' | 'intrusion' | 'ddos' | 'general'

  severity_threshold: number

  auto_assign: boolean

  enabled: boolean

  steps: PlaybookStep[]

  created_at: string

  updated_at: string

}



interface ExecutionRecord {

  id: string

  playbook_id: string

  playbook_name: string

  incident_id: string

  status: 'in_progress' | 'completed' | 'cancelled'

  steps_done: number

  total_steps: number

  started_by: string

  started_at: string

  ended_at?: string

}



// ── Helpers ────────────────────────────────────────────────────────────────────



function fmtDateTime(iso?: string): string {

  if (!iso) return '—'

  try {

    return new Date(iso).toLocaleString('ja-JP', {

      year: 'numeric', month: '2-digit', day: '2-digit',

      hour: '2-digit', minute: '2-digit'

    })

  } catch { return '—' }

}



function calcDuration(start: string, end?: string): string {

  if (!end) return '進行中'

  const ms = new Date(end).getTime() - new Date(start).getTime()

  const h = Math.floor(ms / 3600000)

  const m = Math.floor((ms % 3600000) / 60000)

  return h > 0 ? `${h}時間${m}分` : `${m}分`

}



function calcCompletionRate(executions: ExecutionRecord[], playbookId: string): number {

  const completed = executions.filter(e => e.playbook_id === playbookId && e.status === 'completed')

  if (completed.length === 0) return 0

  const rates = completed.map(e => Math.round((e.steps_done / e.total_steps) * 100))

  return Math.round(rates.reduce((a, b) => a + b, 0) / rates.length)

}



const INCIDENT_TYPE_STYLES: Record<string, string> = {

  ransomware:  'bg-red-900/40 text-red-300 border border-red-700/50',

  phishing:    'bg-orange-900/40 text-orange-300 border border-orange-700/50',

  intrusion:   'bg-purple-900/40 text-purple-300 border border-purple-700/50',

  ddos:        'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',

  general:     'bg-[#161f33] text-[#8899aa] border border-[#1e2d42]',

}



const INCIDENT_TYPE_LABELS: Record<string, string> = {

  ransomware:  'ランサムウェア',

  phishing:    'フィッシング',

  intrusion:   '不正侵入',

  ddos:        'DDoS',

  general:     '一般',

}



const STEP_TYPE_STYLES: Record<string, string> = {

  investigation:  'bg-blue-900/40 text-blue-300',

  containment:    'bg-red-900/40 text-red-300',

  eradication:    'bg-orange-900/40 text-orange-300',

  recovery:       'bg-green-900/40 text-green-300',

  communication:  'bg-purple-900/40 text-purple-300',

}



const STEP_TYPE_LABELS: Record<string, string> = {

  investigation:  '調査',

  containment:    '封じ込め',

  eradication:    '除去',

  recovery:       '復旧',

  communication:  'コミュニケーション',

}



const STATUS_STYLES: Record<string, string> = {

  in_progress: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',

  completed:   'bg-green-900/40 text-green-300 border border-green-700/50',

  cancelled:   'bg-[#161f33] text-[#8899aa] border border-[#1e2d42]',

}



const STATUS_LABELS: Record<string, string> = {

  in_progress: '実行中',

  completed:   '完了',

  cancelled:   'キャンセル',

}



const EMPTY_STEP: Omit<PlaybookStep, 'id' | 'order'> = {

  title: '',

  description: '',

  type: 'investigation',

  required: false,

}



const EMPTY_FORM = {

  name: '',

  description: '',

  incident_type: 'general' as Playbook['incident_type'],

  severity_threshold: 5,

  auto_assign: false,

  enabled: true,

  steps: [] as PlaybookStep[],

}



// ── Stat Card ─────────────────────────────────────────────────────────────────



function StatCard({ label, value, icon: Icon, color = '#7d92b0' }: {

  label: string; value: string | number; icon: React.ElementType; color?: string

}) {

  return (

    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-4">

      <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"

           style={{ backgroundColor: `${color}20` }}>

        <Icon className="w-5 h-5" style={{ color }} />

      </div>

      <div>

        <p className="text-[#7d92b0] text-xs">{label}</p>

        <p className="text-white text-xl font-bold">{value}</p>

      </div>

    </div>

  )

}



// ── Execute Modal ─────────────────────────────────────────────────────────────



function ExecuteModal({ playbook, onClose }: { playbook: Playbook; onClose: () => void }) {

  const [incidentId, setIncidentId] = useState('')

  const [success, setSuccess] = useState(false)



  const mutation = useMutation({

    mutationFn: (data: { incident_id: string }) =>

      apiFetch(`/api/v1/playbooks/${playbook.id}/execute`, {

        method: 'POST', body: JSON.stringify(data),

      }).catch(() => ({ ok: true })),

    onSuccess: () => setSuccess(true),

  })



  if (success) {

    return (

      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">

        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-8 w-full max-w-md text-center">

          <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-4" />

          <h3 className="text-white font-bold text-lg mb-2">実行開始</h3>

          <p className="text-[#7d92b0] text-sm mb-6">

            プレイブック「{playbook.name}」をインシデント {incidentId} で実行開始しました。

          </p>

          <button onClick={onClose}

            className="px-6 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors">

            閉じる

          </button>

        </div>

      </div>

    )

  }



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md">

        <div className="flex items-center justify-between mb-6">

          <h3 className="text-white font-bold text-lg flex items-center gap-2">

            <Play className="w-5 h-5 text-green-400" />

            プレイブック実行

          </h3>

          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">

            <X className="w-5 h-5" />

          </button>

        </div>

        <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 mb-4">

          <p className="text-[#7d92b0] text-xs mb-1">プレイブック</p>

          <p className="text-white font-medium text-sm">{playbook.name}</p>

          <p className="text-[#7d92b0] text-xs mt-1">{playbook.steps.length} ステップ</p>

        </div>

        <div className="mb-6">

          <label className="block text-[#7d92b0] text-xs mb-1.5">

            インシデント ID <span className="text-[#e8002d]">*</span>

          </label>

          <input

            type="text"

            value={incidentId}

            onChange={e => setIncidentId(e.target.value)}

            placeholder="例: INC-2026-0318"

            className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm

                       placeholder:text-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"

          />

        </div>

        <div className="flex gap-3">

          <button onClick={onClose}

            className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:bg-[#19253d] transition-colors">

            キャンセル

          </button>

          <button

            onClick={() => mutation.mutate({ incident_id: incidentId })}

            disabled={!incidentId.trim() || mutation.isPending}

            className="flex-1 px-4 py-2 bg-green-700 hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed

                       text-white rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2">

            {mutation.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}

            実行開始

          </button>

        </div>

      </div>

    </div>

  )

}



// ── Playbook Form Modal ────────────────────────────────────────────────────────



function PlaybookFormModal({ initial, onClose, onSave }: {

  initial?: Playbook

  onClose: () => void

  onSave: (data: typeof EMPTY_FORM) => void

}) {

  const [section, setSection] = useState<'basic' | 'steps'>('basic')

  const [form, setForm] = useState<typeof EMPTY_FORM>(

    initial

      ? { ...initial }

      : { ...EMPTY_FORM, steps: [] }

  )



  const addStep = () => {

    setForm(f => ({

      ...f,

      steps: [...f.steps, {

        id: `new-${Date.now()}`,

        order: f.steps.length + 1,

        ...EMPTY_STEP,

      }],

    }))

  }



  const removeStep = (idx: number) => {

    setForm(f => ({

      ...f,

      steps: f.steps.filter((_, i) => i !== idx).map((s, i) => ({ ...s, order: i + 1 })),

    }))

  }



  const updateStep = (idx: number, field: string, value: unknown) => {

    setForm(f => ({

      ...f,

      steps: f.steps.map((s, i) => i === idx ? { ...s, [field]: value } : s),

    }))

  }



  return (

    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">

      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col">

        {/* Header */}

        <div className="flex items-center justify-between p-6 border-b border-[#1e2d42] flex-shrink-0">

          <h3 className="text-white font-bold text-lg">

            {initial ? 'プレイブック編集' : 'プレイブック作成'}

          </h3>

          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">

            <X className="w-5 h-5" />

          </button>

        </div>



        {/* Tab selector */}

        <div className="flex border-b border-[#1e2d42] flex-shrink-0 px-6">

          {(['basic', 'steps'] as const).map(s => (

            <button key={s}

              onClick={() => setSection(s)}

              className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${

                section === s

                  ? 'border-[#e8002d] text-white'

                  : 'border-transparent text-[#7d92b0] hover:text-white'

              }`}>

              {s === 'basic' ? '基本設定' : `ステップ (${form.steps.length})`}

            </button>

          ))}

        </div>



        {/* Body */}

        <div className="flex-1 overflow-y-auto p-6">

          {section === 'basic' ? (

            <div className="space-y-4">

              <div>

                <label className="block text-[#7d92b0] text-xs mb-1.5">名前 <span className="text-[#e8002d]">*</span></label>

                <input type="text" value={form.name}

                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}

                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm

                             focus:outline-none focus:border-[#e8002d]/50 placeholder:text-[#3d5068]"

                  placeholder="プレイブック名" />

              </div>

              <div>

                <label className="block text-[#7d92b0] text-xs mb-1.5">説明</label>

                <textarea value={form.description}

                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}

                  rows={3}

                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm

                             focus:outline-none focus:border-[#e8002d]/50 placeholder:text-[#3d5068] resize-none"

                  placeholder="プレイブックの説明" />

              </div>

              <div className="grid grid-cols-2 gap-4">

                <div>

                  <label className="block text-[#7d92b0] text-xs mb-1.5">インシデントタイプ</label>

                  <select value={form.incident_type}

                    onChange={e => setForm(f => ({ ...f, incident_type: e.target.value as Playbook['incident_type'] }))}

                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm

                               focus:outline-none focus:border-[#e8002d]/50">

                    {Object.entries(INCIDENT_TYPE_LABELS).map(([v, l]) => (

                      <option key={v} value={v}>{l}</option>

                    ))}

                  </select>

                </div>

                <div>

                  <label className="block text-[#7d92b0] text-xs mb-1.5">

                    重大度しきい値: <span className="text-white font-bold">{form.severity_threshold}</span>

                  </label>

                  <input type="range" min={1} max={10} value={form.severity_threshold}

                    onChange={e => setForm(f => ({ ...f, severity_threshold: Number(e.target.value) }))}

                    className="w-full accent-[#e8002d]" />

                  <div className="flex justify-between text-[#3d5068] text-xs mt-1">

                    <span>1</span><span>10</span>

                  </div>

                </div>

              </div>

              <div className="flex gap-6">

                <label className="flex items-center gap-3 cursor-pointer">

                  <span className="text-[#7d92b0] text-sm">自動割り当て</span>

                  <button onClick={() => setForm(f => ({ ...f, auto_assign: !f.auto_assign }))}

                    className={`w-10 h-5 rounded-full transition-colors relative ${form.auto_assign ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}>

                    <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-all ${form.auto_assign ? 'left-5' : 'left-0.5'}`} />

                  </button>

                </label>

                <label className="flex items-center gap-3 cursor-pointer">

                  <span className="text-[#7d92b0] text-sm">有効</span>

                  <button onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}

                    className={`w-10 h-5 rounded-full transition-colors relative ${form.enabled ? 'bg-green-600' : 'bg-[#1e2d42]'}`}>

                    <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-all ${form.enabled ? 'left-5' : 'left-0.5'}`} />

                  </button>

                </label>

              </div>

            </div>

          ) : (

            <div className="space-y-3">

              {form.steps.length === 0 && (

                <div className="text-center py-8 text-[#7d92b0]">

                  <BookOpen className="w-8 h-8 mx-auto mb-2 opacity-40" />

                  <p className="text-sm">ステップがありません。追加してください。</p>

                </div>

              )}

              {form.steps.map((step, idx) => (

                <div key={step.id} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">

                  <div className="flex items-center gap-3 mb-3">

                    <GripVertical className="w-4 h-4 text-[#3d5068] cursor-grab flex-shrink-0" />

                    <span className="w-6 h-6 rounded-full bg-[#1e2d42] text-[#7d92b0] text-xs flex items-center justify-center font-bold flex-shrink-0">

                      {idx + 1}

                    </span>

                    <input type="text" value={step.title}

                      onChange={e => updateStep(idx, 'title', e.target.value)}

                      placeholder="ステップタイトル"

                      className="flex-1 bg-[#0d1220] border border-[#1e2d42] rounded px-2 py-1.5 text-white text-sm

                                 focus:outline-none focus:border-[#e8002d]/50 placeholder:text-[#3d5068]" />

                    <button onClick={() => removeStep(idx)}

                      className="text-[#7d92b0] hover:text-red-400 transition-colors flex-shrink-0">

                      <X className="w-4 h-4" />

                    </button>

                  </div>

                  <textarea value={step.description}

                    onChange={e => updateStep(idx, 'description', e.target.value)}

                    placeholder="ステップの説明"

                    rows={2}

                    className="w-full bg-[#0d1220] border border-[#1e2d42] rounded px-2 py-1.5 text-white text-sm

                               focus:outline-none focus:border-[#e8002d]/50 placeholder:text-[#3d5068] resize-none mb-3" />

                  <div className="flex items-center gap-4">

                    <select value={step.type}

                      onChange={e => updateStep(idx, 'type', e.target.value)}

                      className="bg-[#0d1220] border border-[#1e2d42] rounded px-2 py-1.5 text-white text-xs

                                 focus:outline-none focus:border-[#e8002d]/50">

                      {Object.entries(STEP_TYPE_LABELS).map(([v, l]) => (

                        <option key={v} value={v}>{l}</option>

                      ))}

                    </select>

                    <label className="flex items-center gap-2 cursor-pointer text-xs text-[#7d92b0]">

                      <button onClick={() => updateStep(idx, 'required', !step.required)}

                        className="flex-shrink-0">

                        {step.required

                          ? <CheckSquare className="w-4 h-4 text-[#e8002d]" />

                          : <Square className="w-4 h-4 text-[#3d5068]" />}

                      </button>

                      必須

                    </label>

                  </div>

                </div>

              ))}

              <button onClick={addStep}

                className="w-full py-3 border border-dashed border-[#1e2d42] rounded-lg text-[#7d92b0]

                           hover:border-[#e8002d]/50 hover:text-white transition-colors flex items-center justify-center gap-2 text-sm">

                <Plus className="w-4 h-4" />

                ステップを追加

              </button>

            </div>

          )}

        </div>



        {/* Footer */}

        <div className="flex gap-3 p-6 border-t border-[#1e2d42] flex-shrink-0">

          <button onClick={onClose}

            className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:bg-[#19253d] transition-colors">

            キャンセル

          </button>

          <button onClick={() => onSave(form)}

            disabled={!form.name.trim()}

            className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed

                       text-white rounded-lg text-sm font-medium transition-colors">

            {initial ? '更新' : '作成'}

          </button>

        </div>

      </div>

    </div>

  )

}



// ── Main Page ─────────────────────────────────────────────────────────────────



export default function PlaybooksPage() {

  const qc = useQueryClient()

  const [activeTab, setActiveTab] = useState<'list' | 'history'>('list')

  const [showCreate, setShowCreate] = useState(false)

  const [editTarget, setEditTarget] = useState<Playbook | null>(null)

  const [executeTarget, setExecuteTarget] = useState<Playbook | null>(null)

  const [statusFilter, setStatusFilter] = useState<string>('all')

  const [playbookFilter, setPlaybookFilter] = useState<string>('all')



  const { data: playbooks = [] } = useQuery<Playbook[], Error, Playbook[]>({

    queryKey: ['playbooks'],

    queryFn: (): Promise<Playbook[]> => apiFetch('/api/v1/playbooks').catch(() => []) as Promise<Playbook[]>,

    staleTime: 30_000,

  })



  const { data: executions = [] } = useQuery<ExecutionRecord[], Error, ExecutionRecord[]>({

    queryKey: ['playbook-executions'],

    queryFn: (): Promise<ExecutionRecord[]> => apiFetch('/api/v1/playbooks/executions').catch(() => []) as Promise<ExecutionRecord[]>,

    staleTime: 30_000,

  })



  const createMutation = useMutation({

    mutationFn: (data: typeof EMPTY_FORM) =>

      apiFetch('/api/v1/playbooks', { method: 'POST', body: JSON.stringify(data) })

        .catch(() => ({ id: `pb-new-${Date.now()}`, ...data })),

    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); setShowCreate(false) },

  })



  const updateMutation = useMutation({

    mutationFn: ({ id, data }: { id: string; data: typeof EMPTY_FORM }) =>

      apiFetch(`/api/v1/playbooks/${id}`, { method: 'PUT', body: JSON.stringify(data) })

        .catch(() => data),

    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); setEditTarget(null) },

  })



  const deleteMutation = useMutation({

    mutationFn: (id: string) =>

      apiFetch(`/api/v1/playbooks/${id}`, { method: 'DELETE' }).catch(() => ({})),

    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),

  })



  const filteredExecutions = executions.filter(e => {

    if (statusFilter !== 'all' && e.status !== statusFilter) return false

    if (playbookFilter !== 'all' && e.playbook_id !== playbookFilter) return false

    return true

  })



  const totalEnabled = playbooks.filter(p => p.enabled).length

  const totalExecutions = executions.length

  const avgCompletion = executions.length > 0

    ? Math.round(executions.filter(e => e.status === 'completed')

        .reduce((sum, e) => sum + Math.round((e.steps_done / e.total_steps) * 100), 0)

        / Math.max(1, executions.filter(e => e.status === 'completed').length))

    : 0



  return (

    <div className="min-h-screen bg-[#070d19] p-6">

      {/* Header */}

      <div className="flex items-center justify-between mb-6">

        <div>

          <h1 className="text-2xl font-bold text-white flex items-center gap-3">

            <BookOpen className="w-7 h-7 text-[#e8002d]" />

            インシデントプレイブック

          </h1>

          <p className="text-[#7d92b0] text-sm mt-1">インシデント対応手順書の管理・実行</p>

        </div>

        <button onClick={() => setShowCreate(true)}

          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors">

          <Plus className="w-4 h-4" />

          プレイブック作成

        </button>

      </div>



      {/* Stats */}

      <div className="grid grid-cols-4 gap-4 mb-6">

        <StatCard label="総プレイブック" value={playbooks.length} icon={BookOpen} color="#7d92b0" />

        <StatCard label="有効" value={totalEnabled} icon={CheckCircle} color="#00c853" />

        <StatCard label="今月の実行数" icon={Activity} value={totalExecutions} color="#1a6bff" />

        <StatCard label="平均完了率" value={`${avgCompletion}%`} icon={TrendingUp} color="#e8002d" />

      </div>



      {/* Tabs */}

      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit mb-6">

        {([['list', 'プレイブック一覧'], ['history', '実行履歴']] as const).map(([key, label]) => (

          <button key={key}

            onClick={() => setActiveTab(key)}

            className={`px-4 py-2 rounded text-sm font-medium transition-colors ${

              activeTab === key

                ? 'bg-[#1d2f4a] text-white'

                : 'text-[#7d92b0] hover:text-white'

            }`}>

            {label}

          </button>

        ))}

      </div>



      {/* Playbook List Tab */}

      {activeTab === 'list' && (

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">

          {playbooks.map(pb => {

            const rate = calcCompletionRate(executions, pb.id)

            return (

              <div key={pb.id}

                className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 hover:border-[#2a3f5c] transition-colors">

                {/* Card header */}

                <div className="flex items-start justify-between mb-3">

                  <div className="flex-1 min-w-0">

                    <div className="flex items-center gap-2 mb-1 flex-wrap">

                      <h3 className="text-white font-semibold text-sm">{pb.name}</h3>

                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${INCIDENT_TYPE_STYLES[pb.incident_type]}`}>

                        {INCIDENT_TYPE_LABELS[pb.incident_type]}

                      </span>

                    </div>

                    <p className="text-[#7d92b0] text-xs line-clamp-2">{pb.description}</p>

                  </div>

                </div>



                {/* Meta */}

                <div className="flex items-center gap-4 mb-4 flex-wrap">

                  <div className="flex items-center gap-1.5">

                    <AlertTriangle className="w-3.5 h-3.5 text-[#7d92b0]" />

                    <span className="text-[#7d92b0] text-xs">重大度しきい値:</span>

                    <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${

                      pb.severity_threshold >= 8 ? 'bg-red-900/40 text-red-300'

                      : pb.severity_threshold >= 5 ? 'bg-orange-900/40 text-orange-300'

                      : 'bg-yellow-900/40 text-yellow-300'

                    }`}>{pb.severity_threshold}</span>

                  </div>

                  <div className="flex items-center gap-1.5">

                    <BookOpen className="w-3.5 h-3.5 text-[#7d92b0]" />

                    <span className="text-[#7d92b0] text-xs">{pb.steps.length} ステップ</span>

                  </div>

                  {rate > 0 && (

                    <div className="flex items-center gap-1.5">

                      <TrendingUp className="w-3.5 h-3.5 text-green-400" />

                      <span className="text-xs text-green-400">{rate}% 完了率</span>

                    </div>

                  )}

                </div>



                {/* Toggles */}

                <div className="flex items-center gap-4 mb-4">

                  <label className="flex items-center gap-2 cursor-pointer">

                    <span className="text-[#7d92b0] text-xs">自動割り当て</span>

                    <div className={`w-8 h-4 rounded-full relative transition-colors ${pb.auto_assign ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}>

                      <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-[#e2e8f4] transition-all ${pb.auto_assign ? 'left-4' : 'left-0.5'}`} />

                    </div>

                  </label>

                  <label className="flex items-center gap-2 cursor-pointer">

                    <span className="text-[#7d92b0] text-xs">有効</span>

                    <div className={`w-8 h-4 rounded-full relative transition-colors ${pb.enabled ? 'bg-green-600' : 'bg-[#1e2d42]'}`}>

                      <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-[#e2e8f4] transition-all ${pb.enabled ? 'left-4' : 'left-0.5'}`} />

                    </div>

                  </label>

                </div>



                {/* Actions */}

                <div className="flex gap-2">

                  <button onClick={() => setExecuteTarget(pb)}

                    className="flex items-center gap-1.5 px-3 py-1.5 bg-green-700/20 hover:bg-green-700/40 border border-green-700/50

                               text-green-300 rounded-lg text-xs font-medium transition-colors">

                    <Play className="w-3.5 h-3.5" />

                    実行

                  </button>

                  <button onClick={() => setEditTarget(pb)}

                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#161f33] hover:bg-[#19253d] border border-[#1e2d42]

                               text-[#7d92b0] hover:text-white rounded-lg text-xs font-medium transition-colors">

                    <Edit2 className="w-3.5 h-3.5" />

                    編集

                  </button>

                  <button onClick={() => deleteMutation.mutate(pb.id)}

                    className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/20 hover:bg-red-900/40 border border-red-700/50

                               text-red-400 rounded-lg text-xs font-medium transition-colors">

                    <Trash2 className="w-3.5 h-3.5" />

                    削除

                  </button>

                </div>

              </div>

            )

          })}

        </div>

      )}



      {/* History Tab */}

      {activeTab === 'history' && (

        <div>

          {/* Filters */}

          <div className="flex items-center gap-3 mb-4 flex-wrap">

            <div className="flex items-center gap-2">

              <Filter className="w-4 h-4 text-[#7d92b0]" />

              <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}

                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-white text-sm

                           focus:outline-none focus:border-[#e8002d]/50">

                <option value="all">全ステータス</option>

                <option value="in_progress">実行中</option>

                <option value="completed">完了</option>

                <option value="cancelled">キャンセル</option>

              </select>

            </div>

            <select value={playbookFilter} onChange={e => setPlaybookFilter(e.target.value)}

              className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-white text-sm

                         focus:outline-none focus:border-[#e8002d]/50">

              <option value="all">全プレイブック</option>

              {playbooks.map(pb => (

                <option key={pb.id} value={pb.id}>{pb.name}</option>

              ))}

            </select>

          </div>



          {/* Table */}

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">

            <table className="w-full">

              <thead>

                <tr className="border-b border-[#1e2d42]">

                  {['プレイブック名', 'インシデントID', 'ステータス', '進捗', '実行者', '開始日時', '所要時間'].map(h => (

                    <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium">{h}</th>

                  ))}

                </tr>

              </thead>

              <tbody>

                {filteredExecutions.length === 0 ? (

                  <tr>

                    <td colSpan={7} className="px-4 py-8 text-center text-[#7d92b0] text-sm">

                      実行履歴がありません

                    </td>

                  </tr>

                ) : filteredExecutions.map(ex => (

                  <tr key={ex.id} className="border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30 transition-colors">

                    <td className="px-4 py-3 text-white text-sm font-medium">{ex.playbook_name}</td>

                    <td className="px-4 py-3">

                      <a href={`/incidents/${ex.incident_id}`}

                        className="text-[#1a6bff] hover:text-[#4488ff] text-sm transition-colors font-mono">

                        {ex.incident_id}

                      </a>

                    </td>

                    <td className="px-4 py-3">

                      <span className={`text-xs px-2 py-0.5 rounded-full ${STATUS_STYLES[ex.status]}`}>

                        {STATUS_LABELS[ex.status]}

                      </span>

                    </td>

                    <td className="px-4 py-3">

                      <div className="flex items-center gap-2">

                        <div className="w-20 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">

                          <div className="h-full bg-[#e8002d] rounded-full transition-all"

                            style={{ width: `${Math.round((ex.steps_done / ex.total_steps) * 100)}%` }} />

                        </div>

                        <span className="text-[#7d92b0] text-xs">{ex.steps_done}/{ex.total_steps}</span>

                      </div>

                    </td>

                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{ex.started_by}</td>

                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{fmtDateTime(ex.started_at)}</td>

                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{calcDuration(ex.started_at, ex.ended_at)}</td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        </div>

      )}



      {/* Modals */}

      {showCreate && (

        <PlaybookFormModal

          onClose={() => setShowCreate(false)}

          onSave={data => createMutation.mutate(data)}

        />

      )}

      {editTarget && (

        <PlaybookFormModal

          initial={editTarget}

          onClose={() => setEditTarget(null)}

          onSave={data => updateMutation.mutate({ id: editTarget.id, data })}

        />

      )}

      {executeTarget && (

        <ExecuteModal playbook={executeTarget} onClose={() => setExecuteTarget(null)} />

      )}

    </div>

  )

}

