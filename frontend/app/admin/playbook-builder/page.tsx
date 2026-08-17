'use client'

import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GitBranch, Plus, Pencil, Trash2, X, Play, Save,
  CheckCircle, ChevronDown, ChevronRight, GripVertical,
  Zap, Clock, Bell, GitMerge, Terminal, AlertTriangle,
  ToggleRight, ToggleLeft, RefreshCw, Copy,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type StepType = 'action' | 'condition' | 'notification' | 'wait' | 'parallel'
type ActionType = 'isolate_host' | 'block_ip' | 'send_notification' | 'create_ticket' | 'run_script' | 'wait' | 'query'
type TriggerType = 'alert' | 'manual' | 'scheduled' | 'webhook'
type OnFailure = 'continue' | 'stop' | 'alert'

interface StepParam { key: string; value: string }

interface PlaybookStep {
  id: string
  step_number: number
  title: string
  type: StepType
  description: string
  action_type: ActionType
  parameters: StepParam[]
  timeout_minutes: number
  on_failure: OnFailure
  yes_branch?: string
  no_branch?: string
}

interface PlaybookTrigger {
  trigger_type: TriggerType
  alert_severity?: string
  alert_category?: string
}

interface Playbook {
  id: string
  name: string
  description: string
  trigger: PlaybookTrigger
  steps: PlaybookStep[]
  is_active: boolean
  last_updated: string
}

// ─── Constants ───────────────────────────────────────────────────────────────

const STEP_TYPE_CONFIG: Record<StepType, { color: string; bg: string; border: string; icon: React.ElementType }> = {
  action:       { color: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/30',   icon: Zap },
  condition:    { color: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/30',  icon: GitMerge },
  notification: { color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30',  icon: Bell },
  wait:         { color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/30', icon: Clock },
  parallel:     { color: 'text-cyan-400',   bg: 'bg-cyan-500/10',   border: 'border-cyan-500/30',   icon: GitBranch },
}

const ACTION_TYPE_LABELS: Record<ActionType, string> = {
  isolate_host: 'ホスト隔離', block_ip: 'IPブロック', send_notification: '通知送信',
  create_ticket: 'チケット作成', run_script: 'スクリプト実行', wait: '待機', query: 'クエリ実行',
}

const TRIGGER_TYPE_LABELS: Record<TriggerType, string> = {
  alert: 'アラート', manual: '手動', scheduled: 'スケジュール', webhook: 'Webhook',
}

// ─── Step Card ────────────────────────────────────────────────────────────────

function StepCard({ step, index, total, onEdit, onDelete, onInsertAfter }: {
  step: PlaybookStep; index: number; total: number
  onEdit: () => void; onDelete: () => void; onInsertAfter: () => void
}) {
  const cfg = STEP_TYPE_CONFIG[step.type]
  const Icon = cfg.icon
  const isCondition = step.type === 'condition'

  return (
    <div className="flex flex-col items-center">
      <div className={`w-full max-w-lg bg-falcon-surface border rounded-xl p-4 group hover:border-falcon-muted/30 transition-colors ${cfg.border}`}>
        <div className="flex items-start gap-3">
          {/* Drag handle */}
          <div className="shrink-0 mt-1 text-falcon-subtle group-hover:text-falcon-muted transition-colors cursor-grab">
            <GripVertical className="w-4 h-4" />
          </div>
          {/* Step number */}
          <div className={`shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border ${cfg.bg} ${cfg.border} ${cfg.color}`}>
            {step.step_number}
          </div>
          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[10px] font-semibold border ${cfg.bg} ${cfg.border} ${cfg.color}`}>
                <Icon className="w-2.5 h-2.5" />
                {step.type === 'action' ? 'アクション' : step.type === 'condition' ? '条件' : step.type === 'notification' ? '通知' : step.type === 'wait' ? '待機' : '並列'}
              </span>
              <span className="text-[10px] text-falcon-muted bg-falcon-border px-1.5 py-0.5 rounded-sm">{ACTION_TYPE_LABELS[step.action_type]}</span>
            </div>
            <p className="text-sm font-semibold text-white">{step.title}</p>
            <p className="text-xs text-falcon-muted mt-0.5">{step.description}</p>
            {step.parameters.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {step.parameters.map((p, pi) => (
                  <span key={pi} className="text-[10px] font-mono bg-[#070d19] border border-falcon-border px-1.5 py-0.5 rounded-sm text-falcon-muted">
                    {p.key}: {p.value}
                  </span>
                ))}
              </div>
            )}
            <div className="flex items-center gap-3 mt-2 text-[10px] text-falcon-subtle">
              <span>タイムアウト: {step.timeout_minutes}分</span>
              <span>失敗時: {step.on_failure === 'continue' ? '継続' : step.on_failure === 'stop' ? '停止' : 'アラート'}</span>
            </div>
          </div>
          {/* Actions */}
          <div className="shrink-0 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button onClick={onEdit} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors">
              <Pencil className="w-3.5 h-3.5" />
            </button>
            <button onClick={onDelete} className="p-1.5 rounded-sm hover:bg-red-900/20 text-falcon-muted hover:text-red-400 transition-colors">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
        {/* Condition branches */}
        {isCondition && (
          <div className="mt-3 flex gap-4 ml-10">
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-green-500/5 border border-green-500/20 text-xs text-green-400">
              <CheckCircle className="w-3 h-3" /> Yes → 次のステップへ
            </div>
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-red-500/5 border border-red-500/20 text-xs text-red-400">
              <X className="w-3 h-3" /> No → スキップ/終了
            </div>
          </div>
        )}
      </div>
      {/* Arrow + Insert button */}
      {index < total - 1 && (
        <div className="flex flex-col items-center my-1 group/insert">
          <div className="w-px h-4 bg-falcon-border" />
          <button onClick={onInsertAfter}
            className="w-6 h-6 rounded-full bg-[#070d19] border border-falcon-border hover:border-falcon-red/50 hover:bg-falcon-red/10 flex items-center justify-center text-falcon-subtle hover:text-falcon-red transition-all opacity-0 group-hover/insert:opacity-100">
            <Plus className="w-3 h-3" />
          </button>
          <div className="w-px h-4 bg-falcon-border" />
        </div>
      )}
    </div>
  )
}

// ─── Step Edit Modal ─────────────────────────────────────────────────────────

function StepModal({ step, onClose, onSave }: { step?: PlaybookStep; onClose: () => void; onSave: (d: Partial<PlaybookStep>) => void }) {
  const [form, setForm] = useState({
    title: step?.title ?? '',
    type: (step?.type ?? 'action') as StepType,
    description: step?.description ?? '',
    action_type: (step?.action_type ?? 'run_script') as ActionType,
    parameters: step?.parameters ?? [] as StepParam[],
    timeout_minutes: step?.timeout_minutes ?? 10,
    on_failure: (step?.on_failure ?? 'continue') as OnFailure,
  })
  const [newParamKey, setNewParamKey] = useState('')
  const [newParamVal, setNewParamVal] = useState('')

  function addParam() {
    if (!newParamKey) return
    setForm(p => ({ ...p, parameters: [...p.parameters, { key: newParamKey, value: newParamVal }] }))
    setNewParamKey(''); setNewParamVal('')
  }
  function removeParam(i: number) { setForm(p => ({ ...p, parameters: p.parameters.filter((_, pi) => pi !== i) })) }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg mx-4 shadow-2xl max-h-[85vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border shrink-0">
          <h2 className="text-white font-semibold">{step ? 'ステップを編集' : '新規ステップ追加'}</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-falcon-muted mb-1">ステップタイトル</label>
            <input value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1">タイプ</label>
              <select value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value as StepType }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                {(['action','condition','notification','wait','parallel'] as StepType[]).map(t => (
                  <option key={t} value={t}>{t === 'action' ? 'アクション' : t === 'condition' ? '条件' : t === 'notification' ? '通知' : t === 'wait' ? '待機' : '並列'}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1">アクションタイプ</label>
              <select value={form.action_type} onChange={e => setForm(p => ({ ...p, action_type: e.target.value as ActionType }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                {(Object.keys(ACTION_TYPE_LABELS) as ActionType[]).map(a => <option key={a} value={a}>{ACTION_TYPE_LABELS[a]}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1">説明</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none" />
          </div>
          {/* Parameters */}
          <div>
            <label className="block text-xs text-falcon-muted mb-2">パラメータ</label>
            <div className="space-y-2">
              {form.parameters.map((p, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="font-mono text-xs bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-falcon-muted flex-1">{p.key}</span>
                  <span className="text-falcon-subtle">:</span>
                  <span className="font-mono text-xs bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-white flex-1">{p.value}</span>
                  <button onClick={() => removeParam(i)} className="p-1 rounded-sm hover:bg-red-900/20 text-falcon-muted hover:text-red-400 transition-colors"><X className="w-3 h-3" /></button>
                </div>
              ))}
              <div className="flex items-center gap-2">
                <input value={newParamKey} onChange={e => setNewParamKey(e.target.value)} placeholder="キー"
                  className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-white text-xs font-mono focus:outline-hidden focus:border-falcon-red/50" />
                <span className="text-falcon-subtle">:</span>
                <input value={newParamVal} onChange={e => setNewParamVal(e.target.value)} placeholder="値"
                  className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1 text-white text-xs font-mono focus:outline-hidden focus:border-falcon-red/50" />
                <button onClick={addParam} className="p-1.5 rounded-sm bg-falcon-border hover:bg-falcon-red/20 text-falcon-muted hover:text-falcon-red transition-colors"><Plus className="w-3 h-3" /></button>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1">タイムアウト (分)</label>
              <input type="number" value={form.timeout_minutes} onChange={e => setForm(p => ({ ...p, timeout_minutes: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1">失敗時の動作</label>
              <select value={form.on_failure} onChange={e => setForm(p => ({ ...p, on_failure: e.target.value as OnFailure }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                <option value="continue">継続</option>
                <option value="stop">停止</option>
                <option value="alert">アラート送信</option>
              </select>
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-falcon-muted hover:text-white border border-falcon-border transition-colors">キャンセル</button>
          <button onClick={() => { onSave(form); onClose() }}
            className="px-4 py-2 rounded-lg text-sm bg-falcon-red hover:bg-[#c0001f] text-white font-medium transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ─── Trigger Modal ───────────────────────────────────────────────────────────

function TriggerModal({ trigger, onClose, onSave }: { trigger: PlaybookTrigger; onClose: () => void; onSave: (t: PlaybookTrigger) => void }) {
  const [form, setForm] = useState({ ...trigger })
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold">トリガー設定</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-falcon-muted mb-1">トリガータイプ</label>
            <select value={form.trigger_type} onChange={e => setForm(p => ({ ...p, trigger_type: e.target.value as TriggerType }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              {(['alert','manual','scheduled','webhook'] as TriggerType[]).map(t => <option key={t} value={t}>{TRIGGER_TYPE_LABELS[t]}</option>)}
            </select>
          </div>
          {form.trigger_type === 'alert' && (
            <>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">アラート深刻度 ({'>'}=)</label>
                <select value={form.alert_severity ?? ''} onChange={e => setForm(p => ({ ...p, alert_severity: e.target.value }))}
                  className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
                  {['', 'low', 'medium', 'high', 'critical'].map(s => <option key={s} value={s}>{s || '条件なし'}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">アラートカテゴリ</label>
                <input value={form.alert_category ?? ''} onChange={e => setForm(p => ({ ...p, alert_category: e.target.value }))} placeholder="例: ransomware, phishing"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" />
              </div>
            </>
          )}
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-falcon-muted hover:text-white border border-falcon-border transition-colors">キャンセル</button>
          <button onClick={() => { onSave(form); onClose() }}
            className="px-4 py-2 rounded-lg text-sm bg-falcon-red hover:bg-[#c0001f] text-white font-medium transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ─── Test Execution Panel ─────────────────────────────────────────────────────

function TestPanel({ steps, onClose }: { steps: PlaybookStep[]; onClose: () => void }) {
  const [currentStep, setCurrentStep] = useState(-1)
  const [done, setDone] = useState(false)

  async function runTest() {
    setCurrentStep(0)
    setDone(false)
    for (let i = 0; i < steps.length; i++) {
      setCurrentStep(i)
      await new Promise(r => setTimeout(r, 800 + Math.random() * 400))
    }
    setDone(true)
    setCurrentStep(-1)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold">テスト実行</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-3 max-h-[50vh] overflow-y-auto">
          {steps.map((s, i) => {
            const state = done ? 'done' : currentStep === i ? 'running' : currentStep > i ? 'done' : 'pending'
            return (
              <div key={s.id} className={`flex items-center gap-3 p-3 rounded-lg border transition-all ${
                state === 'done' ? 'bg-green-500/5 border-green-500/20' :
                state === 'running' ? 'bg-falcon-red/5 border-falcon-red/20 animate-pulse' :
                'bg-[#070d19] border-falcon-border'}`}>
                <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 text-xs font-bold transition-colors ${
                  state === 'done' ? 'bg-green-500 text-white' :
                  state === 'running' ? 'bg-falcon-red text-white' :
                  'bg-falcon-border text-falcon-subtle'}`}>
                  {state === 'done' ? '✓' : s.step_number}
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium ${state === 'done' ? 'text-green-300' : state === 'running' ? 'text-white' : 'text-falcon-muted'}`}>{s.title}</p>
                  <p className="text-xs text-falcon-subtle truncate">{s.description}</p>
                </div>
                {state === 'running' && <RefreshCw className="w-3.5 h-3.5 text-falcon-red animate-spin shrink-0" />}
                {state === 'done' && !done && <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />}
              </div>
            )
          })}
          {done && (
            <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/30 text-center">
              <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
              <p className="text-green-300 font-semibold">テスト完了</p>
              <p className="text-xs text-green-400/70 mt-1">全{steps.length}ステップが正常に実行されました</p>
            </div>
          )}
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 rounded-lg text-sm text-falcon-muted hover:text-white border border-falcon-border transition-colors">閉じる</button>
          <button onClick={runTest} disabled={currentStep >= 0 && !done}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white font-medium transition-colors">
            <Play className="w-3.5 h-3.5" /> 実行
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function PlaybookBuilderPage() {
  const qc = useQueryClient()
  const [selectedPB, setSelectedPB] = useState<Playbook | null>(null)
  const [editingStep, setEditingStep] = useState<PlaybookStep | undefined>()
  const [showStepModal, setShowStepModal] = useState(false)
  const [insertAfterIndex, setInsertAfterIndex] = useState<number | null>(null)
  const [showTriggerModal, setShowTriggerModal] = useState(false)
  const [showTestPanel, setShowTestPanel] = useState(false)
  const [editingName, setEditingName] = useState(false)
  const [savedToast, setSavedToast] = useState(false)

  const { data: pbData } = useQuery<Playbook[]>({
    queryKey: ['playbooks-builder'],
    queryFn: () => apiFetch('/api/v1/admin/playbooks'),
  })
  const playbooks = pbData ?? []

  const savePlaybook = useMutation({
    mutationFn: (p: Playbook) =>
      p.id ? apiFetch(`/api/v1/admin/playbooks/${p.id}`, { method: 'PUT', body: JSON.stringify(p) })
           : apiFetch('/api/v1/admin/playbooks', { method: 'POST', body: JSON.stringify(p) }),
    onSettled: () => qc.invalidateQueries({ queryKey: ['playbooks-builder'] }),
  })

  function handleSave() {
    if (!selectedPB) return
    savePlaybook.mutate(selectedPB)
    setSavedToast(true)
    setTimeout(() => setSavedToast(false), 2500)
  }

  function updateStep(updated: Partial<PlaybookStep>) {
    if (!selectedPB) return
    if (editingStep) {
      // Edit existing
      setSelectedPB(p => p ? ({
        ...p,
        steps: p.steps.map(s => s.id === editingStep.id ? { ...s, ...updated } : s),
      }) : p)
    } else {
      // Add new
      const stepNumber = insertAfterIndex !== null ? insertAfterIndex + 2 : selectedPB.steps.length + 1
      const newStep: PlaybookStep = {
        id: Math.random().toString(36).slice(2),
        step_number: stepNumber,
        title: updated.title ?? '新規ステップ',
        type: updated.type ?? 'action',
        description: updated.description ?? '',
        action_type: updated.action_type ?? 'run_script',
        parameters: updated.parameters ?? [],
        timeout_minutes: updated.timeout_minutes ?? 10,
        on_failure: updated.on_failure ?? 'continue',
      }
      setSelectedPB(p => {
        if (!p) return p
        const steps = [...p.steps]
        const insertAt = insertAfterIndex !== null ? insertAfterIndex + 1 : steps.length
        steps.splice(insertAt, 0, newStep)
        return { ...p, steps: steps.map((s, i) => ({ ...s, step_number: i + 1 })) }
      })
    }
    setEditingStep(undefined)
    setInsertAfterIndex(null)
  }

  function deleteStep(id: string) {
    setSelectedPB(p => p ? ({
      ...p,
      steps: p.steps.filter(s => s.id !== id).map((s, i) => ({ ...s, step_number: i + 1 })),
    }) : p)
  }

  function createNew() {
    const nb: Playbook = {
      id: '', name: '新規プレイブック', description: '',
      trigger: { trigger_type: 'manual' }, steps: [], is_active: false,
      last_updated: new Date().toISOString(),
    }
    setSelectedPB(nb)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-muted flex flex-col">
      {/* Toast */}
      {savedToast && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg border bg-green-900/80 border-green-500/50 text-green-300 text-sm font-medium">
          <CheckCircle className="w-4 h-4" /> 保存されました
        </div>
      )}

      {/* Header */}
      <div className="border-b border-falcon-border px-8 py-6 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-falcon-red/10 border border-falcon-red/20 flex items-center justify-center">
            <GitBranch className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">プレイブックビルダー</h1>
            <p className="text-xs text-falcon-muted mt-0.5">インシデント対応プレイブックの作成・編集</p>
          </div>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left Panel: Playbook List */}
        <div className="w-72 shrink-0 border-r border-falcon-border flex flex-col bg-falcon-surface">
          <div className="flex items-center justify-between px-4 py-3 border-b border-falcon-border">
            <span className="text-xs font-semibold text-falcon-muted uppercase tracking-wider">プレイブック</span>
            <button onClick={createNew}
              className="flex items-center gap-1 px-2 py-1 rounded-sm text-xs bg-falcon-red hover:bg-[#c0001f] text-white font-medium transition-colors">
              <Plus className="w-3 h-3" /> 新規作成
            </button>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            {playbooks.map(pb => (
              <button key={pb.id} onClick={() => setSelectedPB({ ...pb })}
                className={`w-full text-left p-3 rounded-lg border transition-all ${selectedPB?.id === pb.id ? 'bg-falcon-active border-falcon-red/30 text-white' : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/30 hover:text-white'}`}>
                <div className="flex items-start justify-between gap-2">
                  <span className="text-sm font-medium truncate">{pb.name}</span>
                  <span className={`shrink-0 px-1.5 py-0.5 rounded-sm text-[9px] font-bold border ${pb.is_active ? 'bg-green-500/10 text-green-400 border-green-500/30' : 'bg-falcon-border text-falcon-subtle border-falcon-border'}`}>
                    {pb.is_active ? '有効' : '無効'}
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-1.5">
                  <span className="text-[10px] text-falcon-subtle">{pb.steps.length}ステップ</span>
                  <span className="text-[10px] bg-falcon-border text-falcon-muted px-1.5 py-0.5 rounded-sm">{TRIGGER_TYPE_LABELS[pb.trigger.trigger_type]}</span>
                </div>
                <p className="text-[10px] text-falcon-subtle mt-1">{new Date(pb.last_updated).toLocaleDateString('ja-JP')}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Main Editor */}
        {selectedPB ? (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Toolbar */}
            <div className="flex items-center gap-3 px-6 py-3 border-b border-falcon-border bg-[#070d19] shrink-0">
              <div className="flex-1 flex items-center gap-2">
                {editingName ? (
                  <input value={selectedPB.name}
                    onChange={e => setSelectedPB(p => p ? { ...p, name: e.target.value } : p)}
                    onBlur={() => setEditingName(false)} autoFocus
                    className="text-white font-semibold bg-transparent border-b border-falcon-red/50 focus:outline-hidden text-sm" />
                ) : (
                  <button onClick={() => setEditingName(true)} className="text-white font-semibold hover:text-falcon-red transition-colors text-sm flex items-center gap-1">
                    {selectedPB.name} <Pencil className="w-3 h-3 opacity-60" />
                  </button>
                )}
                <button onClick={() => setShowTriggerModal(true)}
                  className="flex items-center gap-1 px-2 py-1 rounded-sm text-[10px] bg-falcon-border text-falcon-muted hover:text-white border border-falcon-border transition-colors">
                  トリガー: {TRIGGER_TYPE_LABELS[selectedPB.trigger.trigger_type]}
                  {selectedPB.trigger.alert_severity && <span className="text-falcon-red"> {selectedPB.trigger.alert_severity}</span>}
                </button>
              </div>
              <button onClick={() => setSelectedPB(p => p ? { ...p, is_active: !p.is_active } : p)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-colors ${selectedPB.is_active ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-falcon-border border-falcon-border text-falcon-muted'}`}>
                {selectedPB.is_active ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
                {selectedPB.is_active ? '有効' : '無効'}
              </button>
              <button onClick={() => setShowTestPanel(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-green-600 hover:bg-green-500 text-white transition-colors">
                <Play className="w-3.5 h-3.5" /> テスト実行
              </button>
              <button onClick={handleSave}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-falcon-red hover:bg-[#c0001f] text-white transition-colors">
                <Save className="w-3.5 h-3.5" /> 保存
              </button>
            </div>

            {/* Canvas */}
            <div className="flex-1 overflow-y-auto px-8 py-6">
              {/* Description */}
              <div className="max-w-lg mx-auto mb-6">
                <textarea value={selectedPB.description}
                  onChange={e => setSelectedPB(p => p ? { ...p, description: e.target.value } : p)}
                  placeholder="プレイブックの説明を入力..."
                  rows={2}
                  className="w-full bg-transparent border-b border-falcon-border focus:border-falcon-muted/50 text-falcon-muted text-sm focus:outline-hidden resize-none placeholder-falcon-subtle" />
              </div>

              {/* Steps */}
              <div className="max-w-lg mx-auto">
                {/* Add first step button */}
                {selectedPB.steps.length === 0 && (
                  <div className="text-center py-12">
                    <GitBranch className="w-10 h-10 mx-auto mb-3 text-falcon-border" />
                    <p className="text-falcon-subtle mb-4">ステップがありません</p>
                    <button onClick={() => { setEditingStep(undefined); setInsertAfterIndex(null); setShowStepModal(true) }}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-falcon-red hover:bg-[#c0001f] text-white mx-auto transition-colors">
                      <Plus className="w-4 h-4" /> 最初のステップを追加
                    </button>
                  </div>
                )}
                {selectedPB.steps.map((step, i) => (
                  <StepCard key={step.id} step={step} index={i} total={selectedPB.steps.length}
                    onEdit={() => { setEditingStep(step); setShowStepModal(true) }}
                    onDelete={() => deleteStep(step.id)}
                    onInsertAfter={() => { setEditingStep(undefined); setInsertAfterIndex(i); setShowStepModal(true) }} />
                ))}
                {/* Add step at end */}
                {selectedPB.steps.length > 0 && (
                  <div className="flex flex-col items-center mt-1">
                    <div className="w-px h-4 bg-falcon-border" />
                    <button onClick={() => { setEditingStep(undefined); setInsertAfterIndex(null); setShowStepModal(true) }}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-falcon-surface hover:bg-falcon-border text-falcon-muted hover:text-white border border-dashed border-falcon-border hover:border-falcon-muted/50 transition-colors mt-1">
                      <Plus className="w-4 h-4" /> ステップを追加
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <GitBranch className="w-12 h-12 mx-auto mb-4 text-falcon-border" />
              <p className="text-falcon-muted mb-2">プレイブックを選択するか新規作成してください</p>
              <button onClick={createNew}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-falcon-red hover:bg-[#c0001f] text-white mx-auto transition-colors">
                <Plus className="w-4 h-4" /> 新規作成
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {showStepModal && (
        <StepModal step={editingStep} onClose={() => { setShowStepModal(false); setEditingStep(undefined) }}
          onSave={updateStep} />
      )}
      {showTriggerModal && selectedPB && (
        <TriggerModal trigger={selectedPB.trigger} onClose={() => setShowTriggerModal(false)}
          onSave={t => setSelectedPB(p => p ? { ...p, trigger: t } : p)} />
      )}
      {showTestPanel && selectedPB && (
        <TestPanel steps={selectedPB.steps} onClose={() => setShowTestPanel(false)} />
      )}
    </div>
  )
}
