'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Workflow, Play, Plus, Trash2, Edit2, X, CheckCircle, XCircle,
  Clock, AlertTriangle, ToggleLeft, ToggleRight, RefreshCw,
  Loader2, ChevronDown, Filter, Calendar, Zap, Bell,
  Shield, Ticket, Activity, AlertCircle, CheckSquare
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

type TriggerType = 'alert' | 'schedule' | 'manual' | 'webhook'
type ActionType = 'create_ticket' | 'send_notification' | 'quarantine_agent' | 'create_incident' | 'run_playbook'
type ExecStatus = 'running' | 'completed' | 'failed'

interface WorkflowAction {
  id: string
  type: ActionType
  params: Record<string, string>
}

interface SoarWorkflow {
  id: string
  name: string
  description: string
  trigger_type: TriggerType
  enabled: boolean
  execution_count: number
  last_executed?: string
  conditions: Record<string, string>
  actions: WorkflowAction[]
  created_at: string
}

interface ExecutionStep {
  action_id: string
  action_type: ActionType
  status: 'success' | 'failed' | 'skipped'
  error?: string
  duration_ms: number
}

interface WorkflowExecution {
  id: string
  workflow_id: string
  workflow_name: string
  trigger: string
  status: ExecStatus
  actions_completed: number
  actions_total: number
  duration_ms: number
  started_at: string
  steps: ExecutionStep[]
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const TRIGGER_LABELS: Record<TriggerType, string> = {
  alert: 'アラート', schedule: 'スケジュール', manual: '手動', webhook: 'Webhook',
}
const TRIGGER_COLORS: Record<TriggerType, string> = {
  alert: 'bg-falcon-red/20 text-falcon-red',
  schedule: 'bg-blue-500/20 text-blue-400',
  manual: 'bg-purple-500/20 text-purple-400',
  webhook: 'bg-orange-500/20 text-orange-400',
}
const ACTION_LABELS: Record<ActionType, string> = {
  create_ticket: 'チケット作成',
  send_notification: '通知送信',
  quarantine_agent: 'エージェント隔離',
  create_incident: 'インシデント作成',
  run_playbook: 'プレイブック実行',
}
const ACTION_ICONS: Record<ActionType, React.ElementType> = {
  create_ticket: Ticket,
  send_notification: Bell,
  quarantine_agent: Shield,
  create_incident: AlertTriangle,
  run_playbook: Play,
}

function formatDuration(ms: number) {
  if (ms === 0) return '-'
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function formatDate(iso: string) {
  const d = new Date(iso)
  return d.toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// ── Create/Edit Modal ──────────────────────────────────────────────────────────

const EMPTY_WORKFLOW = {
  name: '',
  description: '',
  trigger_type: 'alert' as TriggerType,
  conditions: {} as Record<string, string>,
  actions: [] as WorkflowAction[],
}

function WorkflowModal({
  onClose, onSave, initial
}: {
  onClose: () => void
  onSave: (data: typeof EMPTY_WORKFLOW) => void
  initial?: typeof EMPTY_WORKFLOW
}) {
  const [form, setForm] = useState(initial ?? EMPTY_WORKFLOW)

  const addAction = () => setForm(f => ({
    ...f,
    actions: [...f.actions, { id: `a${Date.now()}`, type: 'create_ticket', params: { priority: 'medium' } }],
  }))

  const removeAction = (idx: number) => setForm(f => ({
    ...f, actions: f.actions.filter((_, i) => i !== idx),
  }))

  const updateAction = (idx: number, patch: Partial<WorkflowAction>) => setForm(f => ({
    ...f,
    actions: f.actions.map((a, i) => i === idx ? { ...a, ...patch } : a),
  }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-lg">ワークフロー作成</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-4 space-y-6">
          {/* Section 1: Basic */}
          <div>
            <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-3">基本設定</h3>
            <div className="space-y-3">
              <div>
                <label className="text-falcon-muted text-xs mb-1 block">ワークフロー名</label>
                <input
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                  placeholder="ワークフロー名を入力"
                />
              </div>
              <div>
                <label className="text-falcon-muted text-xs mb-1 block">説明</label>
                <textarea
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  rows={2}
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5] resize-none"
                  placeholder="ワークフローの説明"
                />
              </div>
              <div>
                <label className="text-falcon-muted text-xs mb-1 block">トリガータイプ</label>
                <select
                  value={form.trigger_type}
                  onChange={e => setForm(f => ({ ...f, trigger_type: e.target.value as TriggerType, conditions: {} }))}
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                >
                  <option value="alert">アラート</option>
                  <option value="schedule">スケジュール</option>
                  <option value="manual">手動</option>
                  <option value="webhook">Webhook</option>
                </select>
              </div>
            </div>
          </div>

          {/* Section 2: Trigger conditions */}
          <div>
            <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-3">トリガー条件</h3>
            {form.trigger_type === 'alert' && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-falcon-muted text-xs mb-1 block">重要度</label>
                  <select
                    value={form.conditions.severity ?? ''}
                    onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, severity: e.target.value } }))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                  >
                    <option value="">すべて</option>
                    <option value="critical">クリティカル</option>
                    <option value="high">高</option>
                    <option value="medium">中</option>
                    <option value="low">低</option>
                  </select>
                </div>
                <div>
                  <label className="text-falcon-muted text-xs mb-1 block">アラートタイプ</label>
                  <select
                    value={form.conditions.alert_type ?? ''}
                    onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, alert_type: e.target.value } }))}
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                  >
                    <option value="">すべて</option>
                    <option value="malware">マルウェア</option>
                    <option value="ransomware">ランサムウェア</option>
                    <option value="lateral_movement">横断的移動</option>
                    <option value="privilege_escalation">権限昇格</option>
                    <option value="data_exfiltration">データ窃取</option>
                  </select>
                </div>
              </div>
            )}
            {form.trigger_type === 'schedule' && (
              <div>
                <label className="text-falcon-muted text-xs mb-1 block">Cron式</label>
                <input
                  value={form.conditions.cron ?? ''}
                  onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, cron: e.target.value } }))}
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono focus:outline-hidden focus:border-[#4a6fa5]"
                  placeholder="0 8 * * * (毎日8時)"
                />
                <p className="text-falcon-subtle text-xs mt-1">例: 0 8 * * * = 毎日8時, 0 */6 * * * = 6時間ごと</p>
              </div>
            )}
            {form.trigger_type === 'manual' && (
              <p className="text-falcon-muted text-sm">手動トリガーには条件は不要です。</p>
            )}
            {form.trigger_type === 'webhook' && (
              <div>
                <label className="text-falcon-muted text-xs mb-1 block">Webhookエンドポイント（自動生成）</label>
                <div className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-muted font-mono">
                  /api/v1/soar/webhook/&lt;generated-id&gt;
                </div>
              </div>
            )}
          </div>

          {/* Section 3: Actions */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider">アクション設定</h3>
              <button
                onClick={addAction}
                className="flex items-center gap-1.5 text-xs text-[#4a6fa5] hover:text-blue-300 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                アクション追加
              </button>
            </div>
            {form.actions.length === 0 && (
              <div className="text-center py-6 border border-dashed border-falcon-border rounded-sm text-falcon-subtle text-sm">
                アクションを追加してください
              </div>
            )}
            <div className="space-y-3">
              {form.actions.map((action, idx) => {
                const Icon = ACTION_ICONS[action.type]
                return (
                  <div key={action.id} className="border border-falcon-border rounded-sm p-3 bg-[#070d19]">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-falcon-muted text-xs font-medium">アクション {idx + 1}</span>
                      <button onClick={() => removeAction(idx)} className="text-falcon-subtle hover:text-falcon-red transition-colors">
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className="w-4 h-4 text-[#4a6fa5]" />
                      <select
                        value={action.type}
                        onChange={e => updateAction(idx, { type: e.target.value as ActionType, params: {} })}
                        className="flex-1 bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                      >
                        {(Object.entries(ACTION_LABELS) as [ActionType, string][]).map(([k, v]) => (
                          <option key={k} value={k}>{v}</option>
                        ))}
                      </select>
                    </div>
                    {/* Dynamic params */}
                    {action.type === 'create_ticket' && (
                      <div>
                        <label className="text-falcon-muted text-xs mb-1 block">優先度</label>
                        <select
                          value={action.params.priority ?? 'medium'}
                          onChange={e => updateAction(idx, { params: { ...action.params, priority: e.target.value } })}
                          className="w-full bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                        >
                          <option value="critical">クリティカル</option>
                          <option value="high">高</option>
                          <option value="medium">中</option>
                          <option value="low">低</option>
                        </select>
                      </div>
                    )}
                    {action.type === 'send_notification' && (
                      <div>
                        <label className="text-falcon-muted text-xs mb-1 block">メッセージ</label>
                        <textarea
                          value={action.params.message ?? ''}
                          onChange={e => updateAction(idx, { params: { ...action.params, message: e.target.value } })}
                          rows={2}
                          className="w-full bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5] resize-none"
                          placeholder="通知メッセージ"
                        />
                      </div>
                    )}
                    {action.type === 'quarantine_agent' && (
                      <div>
                        <label className="text-falcon-muted text-xs mb-1 block">エージェント</label>
                        <select
                          value={action.params.agent_id ?? 'auto'}
                          onChange={e => updateAction(idx, { params: { ...action.params, agent_id: e.target.value } })}
                          className="w-full bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                        >
                          <option value="auto">トリガーエージェント（自動）</option>
                          <option value="all">すべてのエージェント</option>
                        </select>
                      </div>
                    )}
                    {action.type === 'create_incident' && (
                      <div>
                        <label className="text-falcon-muted text-xs mb-1 block">重要度</label>
                        <select
                          value={action.params.severity ?? 'medium'}
                          onChange={e => updateAction(idx, { params: { ...action.params, severity: e.target.value } })}
                          className="w-full bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                        >
                          <option value="critical">クリティカル</option>
                          <option value="high">高</option>
                          <option value="medium">中</option>
                          <option value="low">低</option>
                        </select>
                      </div>
                    )}
                    {action.type === 'run_playbook' && (
                      <div>
                        <label className="text-falcon-muted text-xs mb-1 block">プレイブックID</label>
                        <input
                          value={action.params.playbook_id ?? ''}
                          onChange={e => updateAction(idx, { params: { ...action.params, playbook_id: e.target.value } })}
                          className="w-full bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#4a6fa5]"
                          placeholder="pb-001"
                        />
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-falcon-border flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => { onSave(form); onClose() }}
            disabled={!form.name}
            className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c0001f] text-white rounded-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Trigger Confirm Modal ──────────────────────────────────────────────────────

function TriggerModal({ workflow, onClose, onConfirm }: {
  workflow: SoarWorkflow
  onClose: () => void
  onConfirm: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-falcon-red/20 flex items-center justify-center">
            <Play className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h2 className="text-white font-semibold">ワークフロー実行確認</h2>
            <p className="text-falcon-muted text-xs">{workflow.name}</p>
          </div>
        </div>
        <p className="text-falcon-muted text-sm mb-6">
          このワークフローを手動でトリガーします。実行後、設定されたアクションが順次実行されます。
        </p>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => { onConfirm(); onClose() }}
            className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c0001f] text-white rounded-sm flex items-center gap-2 transition-colors"
          >
            <Play className="w-4 h-4" />
            実行
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Execution Detail Modal ─────────────────────────────────────────────────────

function ExecDetailModal({ exec, onClose }: { exec: WorkflowExecution; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-lg" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold">実行詳細</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-4">
          <p className="text-falcon-muted text-xs mb-1">ワークフロー</p>
          <p className="text-white font-medium mb-3">{exec.workflow_name}</p>
          <div className="grid grid-cols-3 gap-3 mb-4 text-xs">
            <div className="bg-[#070d19] rounded-sm p-2 text-center">
              <p className="text-falcon-subtle">トリガー</p>
              <p className="text-falcon-muted mt-1 truncate">{exec.trigger}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-2 text-center">
              <p className="text-falcon-subtle">所要時間</p>
              <p className="text-falcon-muted mt-1">{formatDuration(exec.duration_ms)}</p>
            </div>
            <div className="bg-[#070d19] rounded-sm p-2 text-center">
              <p className="text-falcon-subtle">開始日時</p>
              <p className="text-falcon-muted mt-1">{formatDate(exec.started_at)}</p>
            </div>
          </div>
          <h3 className="text-falcon-muted text-xs font-semibold uppercase tracking-wider mb-2">実行ステップ</h3>
          <div className="space-y-2">
            {exec.steps.map((step, i) => (
              <div key={i} className="flex items-start gap-3 p-3 bg-[#070d19] rounded-sm border border-falcon-border">
                <div className="shrink-0 mt-0.5">
                  {step.status === 'success' && <CheckCircle className="w-4 h-4 text-green-400" />}
                  {step.status === 'failed' && <XCircle className="w-4 h-4 text-falcon-red" />}
                  {step.status === 'skipped' && <Clock className="w-4 h-4 text-falcon-subtle" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-white">{ACTION_LABELS[step.action_type]}</span>
                    <span className="text-xs text-falcon-subtle">{formatDuration(step.duration_ms)}</span>
                  </div>
                  {step.error && <p className="text-xs text-falcon-red mt-1">{step.error}</p>}
                  {step.status === 'skipped' && <p className="text-xs text-falcon-subtle mt-1">前のステップの失敗によりスキップ</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function SoarPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'workflows' | 'history'>('workflows')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [triggerWorkflow, setTriggerWorkflow] = useState<SoarWorkflow | null>(null)
  const [detailExec, setDetailExec] = useState<WorkflowExecution | null>(null)
  const [filterStatus, setFilterStatus] = useState('')
  const [filterWorkflow, setFilterWorkflow] = useState('')

  // Fetch workflows
  const { data: workflowsData, isError: wfError } = useQuery<SoarWorkflow[]>({
    queryKey: ['soar-workflows'],
    queryFn: () => apiFetchList<SoarWorkflow>('/api/v1/soar/workflows'),
    retry: 1,
  })
  const workflows = workflowsData ?? []

  // Fetch executions
  const { data: execData, isError: execError } = useQuery<WorkflowExecution[]>({
    queryKey: ['soar-executions'],
    queryFn: () => apiFetchList<WorkflowExecution>('/api/v1/soar/executions'),
    retry: 1,
    refetchInterval: 10_000,
  })
  const executions = execData ?? []

  // Toggle mutation
  const toggleMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/soar/workflows/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-workflows'] }),
  })

  // Trigger mutation
  const triggerMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/soar/workflows/${id}/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_id: null, context: {} }),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-executions'] }),
  })

  // Delete mutation
  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/soar/workflows/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-workflows'] }),
  })

  // Create mutation
  const createMut = useMutation({
    mutationFn: (data: typeof EMPTY_WORKFLOW) => apiFetch('/api/v1/soar/workflows', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-workflows'] }),
  })

  // Stats
  const totalWorkflows = workflows.length
  const enabledCount = workflows.filter(w => w.enabled).length
  const todayExecs = executions.filter(e => new Date(e.started_at).toDateString() === new Date().toDateString()).length
  const completedExecs = executions.filter(e => e.status === 'completed').length
  const successRate = executions.length > 0 ? Math.round((completedExecs / executions.length) * 100) : 0

  // Filtered executions
  const filteredExecs = executions.filter(e => {
    if (filterStatus && e.status !== filterStatus) return false
    if (filterWorkflow && e.workflow_id !== filterWorkflow) return false
    return true
  })

  const statusBadge = (status: ExecStatus) => {
    if (status === 'running') return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-xs bg-blue-500/20 text-blue-400">
        <Loader2 className="w-3 h-3 animate-spin" />実行中
      </span>
    )
    if (status === 'completed') return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-xs bg-green-500/20 text-green-400">
        <CheckCircle className="w-3 h-3" />完了
      </span>
    )
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-xs bg-falcon-red/20 text-falcon-red">
        <XCircle className="w-3 h-3" />失敗
      </span>
    )
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Modals */}
      {showCreateModal && (
        <WorkflowModal
          onClose={() => setShowCreateModal(false)}
          onSave={data => createMut.mutate(data)}
        />
      )}
      {triggerWorkflow && (
        <TriggerModal
          workflow={triggerWorkflow}
          onClose={() => setTriggerWorkflow(null)}
          onConfirm={() => triggerMut.mutate(triggerWorkflow.id)}
        />
      )}
      {detailExec && (
        <ExecDetailModal exec={detailExec} onClose={() => setDetailExec(null)} />
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Workflow className="w-6 h-6 text-falcon-red" />
            SOARワークフロー
          </h1>
          <p className="text-falcon-muted text-sm mt-1">セキュリティオーケストレーション・自動対応ワークフローの管理</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white rounded-sm text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          ワークフロー作成
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総ワークフロー', value: totalWorkflows, icon: Workflow, color: 'text-blue-400' },
          { label: '有効', value: enabledCount, icon: CheckCircle, color: 'text-green-400' },
          { label: '今日の実行', value: todayExecs, icon: Activity, color: 'text-purple-400' },
          { label: '成功率', value: `${successRate}%`, icon: Zap, color: 'text-falcon-red' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-falcon-muted text-xs">{label}</span>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-falcon-border">
        {([['workflows', 'ワークフロー'], ['history', '実行履歴']] as const).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === id
                ? 'text-white border-falcon-red'
                : 'text-falcon-muted border-transparent hover:text-white'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Workflows Tab */}
      {activeTab === 'workflows' && (
        <div className="grid grid-cols-1 gap-4">
          {workflows.map(wf => (
            <div key={wf.id} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-1">
                    <h3 className="text-white font-semibold">{wf.name}</h3>
                    <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${TRIGGER_COLORS[wf.trigger_type]}`}>
                      {TRIGGER_LABELS[wf.trigger_type]}
                    </span>
                  </div>
                  <p className="text-falcon-muted text-sm mb-3">{wf.description}</p>
                  <div className="flex items-center gap-4 text-xs text-falcon-subtle">
                    <span className="flex items-center gap-1">
                      <Activity className="w-3 h-3" />
                      実行回数: {wf.execution_count}
                    </span>
                    {wf.last_executed && (
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        最終実行: {formatDate(wf.last_executed)}
                      </span>
                    )}
                    <span>{wf.actions.length} アクション</span>
                  </div>
                </div>
                <div className="flex items-center gap-2 ml-4 shrink-0">
                  <button
                    onClick={() => setTriggerWorkflow(wf)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-sm transition-colors"
                  >
                    <Play className="w-3.5 h-3.5" />
                    実行
                  </button>
                  <button
                    onClick={() => toggleMut.mutate(wf.id)}
                    className={`p-1.5 rounded-sm transition-colors ${wf.enabled ? 'text-green-400 hover:bg-green-400/10' : 'text-falcon-subtle hover:bg-falcon-border'}`}
                    title={wf.enabled ? '無効化' : '有効化'}
                  >
                    {wf.enabled
                      ? <ToggleRight className="w-5 h-5" />
                      : <ToggleLeft className="w-5 h-5" />
                    }
                  </button>
                  <button className="p-1.5 text-falcon-muted hover:text-white hover:bg-falcon-border rounded-sm transition-colors">
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => deleteMut.mutate(wf.id)}
                    className="p-1.5 text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10 rounded-sm transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
              {/* Action list */}
              <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-falcon-border">
                {wf.actions.map((action, i) => {
                  const Icon = ACTION_ICONS[action.type]
                  return (
                    <span key={i} className="inline-flex items-center gap-1 px-2 py-1 bg-[#070d19] rounded-sm text-xs text-falcon-muted">
                      <Icon className="w-3 h-3" />
                      {ACTION_LABELS[action.type]}
                    </span>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div>
          {/* Filters */}
          <div className="flex items-center gap-3 mb-4">
            <Filter className="w-4 h-4 text-falcon-muted" />
            <select
              value={filterWorkflow}
              onChange={e => setFilterWorkflow(e.target.value)}
              className="bg-falcon-surface border border-falcon-border rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden"
            >
              <option value="">すべてのワークフロー</option>
              {workflows.map(w => (
                <option key={w.id} value={w.id}>{w.name}</option>
              ))}
            </select>
            <select
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value)}
              className="bg-falcon-surface border border-falcon-border rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden"
            >
              <option value="">すべてのステータス</option>
              <option value="running">実行中</option>
              <option value="completed">完了</option>
              <option value="failed">失敗</option>
            </select>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ワークフロー名', 'トリガー', 'ステータス', 'アクション', '所要時間', '開始日時', ''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-falcon-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredExecs.map(exec => (
                  <tr key={exec.id} className="border-b border-falcon-border hover:bg-[#070d19] transition-colors">
                    <td className="px-4 py-3 text-white font-medium">{exec.workflow_name}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs text-falcon-muted font-mono bg-[#070d19] px-2 py-0.5 rounded-sm">
                        {exec.trigger}
                      </span>
                    </td>
                    <td className="px-4 py-3">{statusBadge(exec.status)}</td>
                    <td className="px-4 py-3 text-falcon-muted">
                      {exec.actions_completed}/{exec.actions_total}
                    </td>
                    <td className="px-4 py-3 text-falcon-muted">{formatDuration(exec.duration_ms)}</td>
                    <td className="px-4 py-3 text-falcon-muted text-xs">{formatDate(exec.started_at)}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setDetailExec(exec)}
                        className="text-xs text-[#4a6fa5] hover:text-blue-300 transition-colors"
                      >
                        詳細
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredExecs.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-falcon-subtle text-sm">
                      実行履歴がありません
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
