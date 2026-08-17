'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Zap, Plus, Play, Pause, Trash2, Copy, Edit3, X, ChevronDown, ChevronUp,
  Clock, Webhook, Calendar, MousePointer, Bell, Monitor, Globe, Ticket,
  Search, AlertTriangle, CheckCircle, XCircle, Loader2, ChevronRight,
  ArrowUp, ArrowDown, Settings, BarChart2, History, BookOpen, Send,
  RefreshCw, Shield,
} from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

type TriggerType = 'alert' | 'schedule' | 'webhook' | 'manual'
type WorkflowStatus = 'active' | 'paused' | 'draft'
type StepStatus = 'pending' | 'running' | 'success' | 'failure' | 'skipped'
type ActionCategory = 'Notification' | 'Endpoint' | 'ThreatIntel' | 'Ticketing' | 'Enrichment' | 'Custom'

interface ActionConfig {
  [key: string]: string | number | boolean | string[]
}

interface WorkflowAction {
  id: string
  type: string
  category: ActionCategory
  label: string
  icon: string
  config: ActionConfig
}

interface WorkflowTrigger {
  type: TriggerType
  conditions?: { field: string; operator: string; value: string }[]
  cron?: string
  webhook_path?: string
}

interface Workflow {
  id: string
  name: string
  description: string
  trigger: WorkflowTrigger
  actions: WorkflowAction[]
  status: WorkflowStatus
  run_count: number
  success_rate: number
  last_run?: string
  created_at: string
}

interface RunHistory {
  id: string
  workflow_id: string
  trigger_info: string
  started_at: string
  duration_ms: number
  status: 'success' | 'failure' | 'running'
  steps: { step: string; status: StepStatus; duration_ms: number; output?: string }[]
}

interface Template {
  id: string
  name: string
  description: string
  trigger_type: TriggerType
  action_count: number
  tags: string[]
}

const ACTION_LIBRARY: { category: ActionCategory; actions: { type: string; label: string; defaultConfig: ActionConfig }[] }[] = [
  { category: 'Notification', actions: [
    { type: 'send_slack', label: 'Slack通知', defaultConfig: { webhook_url: '', channel: '#alerts', message_template: '' } },
    { type: 'send_email', label: 'メール送信', defaultConfig: { to: '', subject: '', template: '' } },
    { type: 'send_pagerduty', label: 'PagerDuty', defaultConfig: { urgency: 'high', service_id: '' } },
  ]},
  { category: 'Endpoint', actions: [
    { type: 'isolate_host', label: 'ホスト隔離', defaultConfig: { confirm: true, timeout: 300 } },
    { type: 'kill_process', label: 'プロセス終了', defaultConfig: { process_name: '' } },
    { type: 'run_vuln_scan', label: '脆弱性スキャン', defaultConfig: { scope: 'all', severity_threshold: 'medium' } },
    { type: 'block_sender', label: 'IP/ドメインブロック', defaultConfig: { duration_hours: 24 } },
  ]},
  { category: 'ThreatIntel', actions: [
    { type: 'enrich_ioc', label: 'IOCエンリッチ', defaultConfig: { vt: true, otx: false, misp: false } },
    { type: 'query_ti', label: 'TIクエリ', defaultConfig: { source: 'all' } },
  ]},
  { category: 'Ticketing', actions: [
    { type: 'create_ticket', label: 'チケット作成', defaultConfig: { priority: 'medium', assignee: '' } },
    { type: 'update_ticket', label: 'チケット更新', defaultConfig: { status: 'in_progress' } },
    { type: 'create_war_room', label: '作戦室開設', defaultConfig: { invite_roles: [] } },
  ]},
  { category: 'Enrichment', actions: [
    { type: 'generate_report', label: 'レポート生成', defaultConfig: { period: '24h', format: 'html' } },
    { type: 'create_alert', label: 'アラート作成', defaultConfig: { auto_triage: true } },
  ]},
  { category: 'Custom', actions: [
    { type: 'custom_script', label: 'カスタムスクリプト', defaultConfig: { script: '', timeout: 60 } },
    { type: 'http_request', label: 'HTTPリクエスト', defaultConfig: { url: '', method: 'POST', headers: '' } },
  ]},
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function formatDuration(ms: number) {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function TriggerBadge({ type }: { type: TriggerType }) {
  const map: Record<TriggerType, { label: string; color: string }> = {
    alert: { label: 'アラート', color: 'bg-red-900/30 text-red-400 border-red-700/30' },
    schedule: { label: 'スケジュール', color: 'bg-blue-900/30 text-blue-400 border-blue-700/30' },
    webhook: { label: 'Webhook', color: 'bg-purple-900/30 text-purple-400 border-purple-700/30' },
    manual: { label: '手動', color: 'bg-orange-900/30 text-orange-400 border-orange-700/30' },
  }
  const { label, color } = map[type]
  return <span className={`px-2 py-0.5 rounded-sm text-xs border ${color}`}>{label}</span>
}

function StatusBadge({ status }: { status: WorkflowStatus }) {
  if (status === 'active') return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-emerald-900/30 text-emerald-400 border border-emerald-700/30"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />有効</span>
  if (status === 'paused') return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-amber-900/30 text-amber-400 border border-amber-700/30"><span className="w-1.5 h-1.5 rounded-full bg-amber-400" />一時停止</span>
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-falcon-border text-falcon-muted border border-falcon-border"><span className="w-1.5 h-1.5 rounded-full bg-falcon-subtle" />下書き</span>
}

function TriggerIcon({ type }: { type: TriggerType }) {
  const map: Record<TriggerType, React.ComponentType<{ className?: string }>> = {
    alert: Bell, schedule: Calendar, webhook: Webhook, manual: MousePointer
  }
  const Icon = map[type]
  return <Icon className="w-4 h-4" />
}

function CategoryColor(cat: ActionCategory): string {
  const map: Record<ActionCategory, string> = {
    Notification: 'bg-blue-900/30 text-blue-400',
    Endpoint: 'bg-red-900/30 text-red-400',
    ThreatIntel: 'bg-purple-900/30 text-purple-400',
    Ticketing: 'bg-orange-900/30 text-orange-400',
    Enrichment: 'bg-teal-900/30 text-teal-400',
    Custom: 'bg-falcon-border text-falcon-muted',
  }
  return map[cat]
}

// ─── Workflow Editor ──────────────────────────────────────────────────────────

interface WorkflowEditorProps {
  workflow?: Partial<Workflow>
  onClose: () => void
  onSave: (workflow: Partial<Workflow>) => void
}

function WorkflowEditor({ workflow, onClose, onSave }: WorkflowEditorProps) {
  const [name, setName] = useState(workflow?.name ?? '')
  const [description, setDescription] = useState(workflow?.description ?? '')
  const [trigger, setTrigger] = useState<WorkflowTrigger>(workflow?.trigger ?? { type: 'alert' })
  const [actions, setActions] = useState<WorkflowAction[]>(workflow?.actions ?? [])
  const [testRunning, setTestRunning] = useState(false)
  const [testResults, setTestResults] = useState<{ step: string; status: StepStatus; output: string }[] | null>(null)
  const [showActionLibrary, setShowActionLibrary] = useState(false)
  const [configTarget, setConfigTarget] = useState<string | null>(null)

  const addAction = (type: string, category: ActionCategory, label: string, defaultConfig: ActionConfig) => {
    const newAction: WorkflowAction = {
      id: `action-${Date.now()}`,
      type, category, label, icon: 'zap', config: { ...defaultConfig }
    }
    setActions(prev => [...prev, newAction])
    setShowActionLibrary(false)
  }

  const removeAction = (id: string) => setActions(prev => prev.filter(a => a.id !== id))
  const moveAction = (id: string, dir: 'up' | 'down') => {
    setActions(prev => {
      const idx = prev.findIndex(a => a.id === id)
      if ((dir === 'up' && idx === 0) || (dir === 'down' && idx === prev.length - 1)) return prev
      const next = [...prev]
      const swap = dir === 'up' ? idx - 1 : idx + 1
      ;[next[idx], next[swap]] = [next[swap], next[idx]]
      return next
    })
  }

  const runTest = () => {
    setTestRunning(true)
    setTestResults(null)
    const steps = actions.map(a => ({ step: a.label, status: 'pending' as StepStatus, output: '' }))
    setTestResults(steps)
    steps.forEach((_, i) => {
      setTimeout(() => {
        setTestResults(prev => prev ? prev.map((s, j) => j === i ? { ...s, status: 'success', output: 'テスト実行成功 (モック)' } : s) : null)
        if (i === steps.length - 1) setTestRunning(false)
      }, (i + 1) * 800)
    })
  }

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-xs flex items-start justify-end z-50">
      <div className="w-full max-w-2xl h-screen bg-falcon-surface border-l border-falcon-border flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-6 py-5 border-b border-falcon-border shrink-0">
          <h3 className="text-white font-semibold text-lg">{workflow?.id ? 'ワークフロー編集' : '新規ワークフロー'}</h3>
          <div className="flex items-center gap-2">
            <button
              onClick={runTest}
              disabled={testRunning || actions.length === 0}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-900/30 hover:bg-blue-900/50 text-blue-400 text-sm border border-blue-700/30 transition-colors disabled:opacity-40"
            >
              {testRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              テスト実行
            </button>
            <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors"><X className="w-5 h-5" /></button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {/* Basic Info */}
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">ワークフロー名</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="ワークフロー名を入力" className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-muted/50" />
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">説明</label>
              <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2} placeholder="ワークフローの説明" className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-falcon-border text-white text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-muted/50 resize-none" />
            </div>
          </div>

          {/* Trigger */}
          <div>
            <h4 className="text-white font-medium mb-3 flex items-center gap-2">
              <div className="w-5 h-5 rounded-sm bg-falcon-red/20 flex items-center justify-center text-falcon-red"><Zap className="w-3 h-3" /></div>
              トリガー設定
            </h4>
            <div className="bg-[#070d19] border border-falcon-border rounded-xl p-4 space-y-3">
              <div className="grid grid-cols-2 gap-2">
                {(['alert', 'schedule', 'webhook', 'manual'] as TriggerType[]).map(t => (
                  <button
                    key={t}
                    onClick={() => setTrigger({ type: t })}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors ${
                      trigger.type === t ? 'bg-falcon-red/20 border-falcon-red/50 text-white' : 'border-falcon-border text-falcon-muted hover:border-falcon-muted/40'
                    }`}
                  >
                    <TriggerIcon type={t} />
                    {t === 'alert' ? 'アラート' : t === 'schedule' ? 'スケジュール' : t === 'webhook' ? 'Webhook' : '手動'}
                  </button>
                ))}
              </div>
              {trigger.type === 'alert' && (
                <div className="space-y-2">
                  <p className="text-xs text-falcon-muted">条件設定:</p>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <select className="px-2 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted focus:outline-hidden">
                      <option>severity</option><option>category</option><option>confidence</option>
                    </select>
                    <select className="px-2 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted focus:outline-hidden">
                      <option>{'>'}{`=`}</option><option>{'='}</option><option>{'!='}</option>
                    </select>
                    <input placeholder="値" className="px-2 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-white placeholder-falcon-subtle focus:outline-hidden" />
                  </div>
                </div>
              )}
              {trigger.type === 'schedule' && (
                <div>
                  <p className="text-xs text-falcon-muted mb-2">Cronスケジュール:</p>
                  <div className="grid grid-cols-2 gap-2 text-xs mb-2">
                    {['毎時', '毎日8:00', '毎週月曜', '毎月1日'].map(p => (
                      <button key={p} className="px-2 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/40 transition-colors text-left">{p}</button>
                    ))}
                  </div>
                  <input value={trigger.cron ?? ''} onChange={e => setTrigger(prev => ({ ...prev, cron: e.target.value }))} placeholder="カスタムCRON (例: 0 8 * * *)" className="w-full px-3 py-1.5 rounded-sm bg-falcon-surface border border-falcon-border text-white text-xs placeholder-falcon-subtle font-mono focus:outline-hidden" />
                </div>
              )}
              {trigger.type === 'webhook' && (
                <div className="p-3 rounded-lg bg-blue-900/20 border border-blue-700/30 text-xs">
                  <p className="text-falcon-muted">Webhookエンドポイント:</p>
                  <p className="text-blue-400 font-mono mt-1">/api/v1/webhooks/custom-{`{workflow-id}`}</p>
                </div>
              )}
            </div>
          </div>

          {/* Actions */}
          <div>
            <h4 className="text-white font-medium mb-3 flex items-center gap-2">
              <div className="w-5 h-5 rounded-sm bg-blue-900/30 flex items-center justify-center text-blue-400"><Settings className="w-3 h-3" /></div>
              アクション ({actions.length})
            </h4>
            <div className="space-y-2">
              {actions.map((action, idx) => (
                <div key={action.id} className="bg-[#070d19] border border-falcon-border rounded-xl p-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-falcon-border flex items-center justify-center text-xs text-falcon-muted shrink-0">{idx + 1}</span>
                      <span className={`px-2 py-0.5 rounded-sm text-xs ${CategoryColor(action.category)}`}>{action.category}</span>
                      <span className="text-white text-sm">{action.label}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <button onClick={() => moveAction(action.id, 'up')} disabled={idx === 0} className="p-1 rounded-sm hover:bg-falcon-border text-falcon-muted disabled:opacity-30 transition-colors"><ArrowUp className="w-3.5 h-3.5" /></button>
                      <button onClick={() => moveAction(action.id, 'down')} disabled={idx === actions.length - 1} className="p-1 rounded-sm hover:bg-falcon-border text-falcon-muted disabled:opacity-30 transition-colors"><ArrowDown className="w-3.5 h-3.5" /></button>
                      <button onClick={() => setConfigTarget(configTarget === action.id ? null : action.id)} className="p-1 rounded-sm hover:bg-falcon-border text-falcon-muted transition-colors"><Settings className="w-3.5 h-3.5" /></button>
                      <button onClick={() => removeAction(action.id)} className="p-1 rounded-sm hover:bg-red-900/30 text-falcon-muted hover:text-red-400 transition-colors"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </div>
                  {configTarget === action.id && (
                    <div className="mt-3 pt-3 border-t border-falcon-border space-y-2">
                      {Object.entries(action.config).map(([key, val]) => (
                        <div key={key} className="flex items-center gap-2">
                          <span className="text-xs text-falcon-muted w-24 shrink-0 font-mono">{key}</span>
                          <input
                            value={String(val)}
                            onChange={e => setActions(prev => prev.map(a => a.id === action.id ? { ...a, config: { ...a.config, [key]: e.target.value } } : a))}
                            className="flex-1 px-2 py-1 rounded-sm bg-falcon-surface border border-falcon-border text-white text-xs font-mono focus:outline-hidden focus:border-falcon-muted/50"
                          />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              <button
                onClick={() => setShowActionLibrary(true)}
                className="w-full py-3 rounded-xl border border-dashed border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/50 text-sm transition-colors flex items-center justify-center gap-2"
              >
                <Plus className="w-4 h-4" />
                + アクション追加
              </button>
            </div>
          </div>

          {/* Test Results */}
          {testResults && (
            <div className="bg-[#070d19] border border-falcon-border rounded-xl p-4">
              <h4 className="text-white font-medium mb-3 flex items-center gap-2"><Play className="w-4 h-4 text-blue-400" />テスト実行結果</h4>
              <div className="space-y-2">
                {testResults.map((step, i) => (
                  <div key={i} className="flex items-center gap-3 text-sm">
                    {step.status === 'success' ? <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                      : step.status === 'failure' ? <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                      : step.status === 'running' ? <Loader2 className="w-4 h-4 text-blue-400 animate-spin shrink-0" />
                      : <div className="w-4 h-4 rounded-full border border-falcon-subtle shrink-0" />}
                    <span className="text-white">{step.step}</span>
                    {step.output && <span className="text-falcon-muted text-xs truncate">{step.output}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="px-6 py-4 border-t border-falcon-border flex justify-end gap-3 shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button
            onClick={() => onSave({ name, description, trigger, actions })}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c8001d] text-white text-sm font-medium transition-colors"
          >
            <CheckCircle className="w-4 h-4" />
            保存
          </button>
        </div>
      </div>

      {/* Action Library Modal */}
      {showActionLibrary && (
        <div className="absolute inset-0 bg-black/50 flex items-center justify-center p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-lg max-h-[80vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
              <h4 className="text-white font-semibold">アクションを選択</h4>
              <button onClick={() => setShowActionLibrary(false)} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {ACTION_LIBRARY.map(cat => (
                <div key={cat.category}>
                  <p className="text-xs text-falcon-muted font-medium mb-2 uppercase tracking-wider">{cat.category}</p>
                  <div className="space-y-1.5">
                    {cat.actions.map(action => (
                      <button
                        key={action.type}
                        onClick={() => addAction(action.type, cat.category, action.label, action.defaultConfig)}
                        className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#070d19] border border-falcon-border hover:border-falcon-muted/40 hover:text-white text-falcon-muted text-sm transition-colors text-left"
                      >
                        <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${CategoryColor(cat.category)}`}>{cat.category}</span>
                        {action.label}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AutomationPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'library' | 'history' | 'templates'>('library')
  const [editingWorkflow, setEditingWorkflow] = useState<Partial<Workflow> | null>(null)
  const [creatingNew, setCreatingNew] = useState(false)
  const [expandedHistory, setExpandedHistory] = useState<string | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  const { data: workflows, refetch } = useQuery<Workflow[]>({
    queryKey: ['automation-workflows'],
    queryFn: () => apiFetch('/api/v1/admin/automation/workflows'),
  })

  const { data: runHistory } = useQuery<RunHistory[]>({
    queryKey: ['automation-history'],
    queryFn: () => apiFetch('/api/v1/admin/automation/workflows/history'),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: WorkflowStatus }) =>
      apiFetch(`/api/v1/admin/automation/workflows/${id}`, { method: 'PUT', body: JSON.stringify({ status }) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['automation-workflows'] }); refetch() },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/automation/workflows/${id}`, { method: 'DELETE' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['automation-workflows'] }); refetch(); setDeleteConfirm(null) },
  })

  const saveMutation = useMutation({
    mutationFn: (data: Partial<Workflow>) =>
      data.id
        ? apiFetch(`/api/v1/admin/automation/workflows/${data.id}`, { method: 'PUT', body: JSON.stringify(data) })
        : apiFetch('/api/v1/admin/automation/workflows', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { refetch(); setEditingWorkflow(null); setCreatingNew(false) },
  })

  const runMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/automation/workflows/${id}/run`, { method: 'POST' }),
  })

  const activeWorkflows = (workflows ?? [])

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-muted">
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center shadow-lg">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">セキュリティ自動化</h1>
              <p className="text-sm text-falcon-muted">ノーコードワークフロービルダーでセキュリティ対応を自動化</p>
            </div>
          </div>
          <button
            onClick={() => setCreatingNew(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c8001d] text-white text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            新規ワークフロー
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: '有効ワークフロー', value: activeWorkflows.filter(w => w.status === 'active').length, icon: CheckCircle, color: 'text-emerald-400' },
            { label: '総実行回数', value: activeWorkflows.reduce((s, w) => s + w.run_count, 0).toLocaleString(), icon: Play, color: 'text-blue-400' },
            { label: '平均成功率', value: `${(activeWorkflows.reduce((s, w) => s + w.success_rate, 0) / activeWorkflows.length).toFixed(1)}%`, icon: BarChart2, color: 'text-emerald-400' },
            { label: '一時停止中', value: activeWorkflows.filter(w => w.status === 'paused').length, icon: Pause, color: 'text-amber-400' },
          ].map(stat => (
            <div key={stat.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <stat.icon className={`w-4 h-4 ${stat.color}`} />
                <span className="text-xs text-falcon-muted">{stat.label}</span>
              </div>
              <p className="text-2xl font-bold text-white">{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-1 border-b border-falcon-border">
          {[
            { key: 'library', label: 'ワークフロー一覧', icon: Zap },
            { key: 'history', label: '実行履歴', icon: History },
            { key: 'templates', label: 'テンプレート', icon: BookOpen },
          ].map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === tab.key ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Workflow Library */}
        {activeTab === 'library' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {activeWorkflows.map(wf => (
              <div key={wf.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-5 hover:border-[#2a3d5a] transition-colors">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <TriggerBadge type={wf.trigger.type} />
                      <StatusBadge status={wf.status} />
                    </div>
                    <h3 className="text-white font-semibold text-sm mt-1">{wf.name}</h3>
                    <p className="text-falcon-muted text-xs mt-0.5 line-clamp-2">{wf.description}</p>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-3 mb-3 text-xs">
                  <div className="text-center p-2 rounded-sm bg-falcon-border/40">
                    <p className="text-white font-bold">{wf.actions.length}</p>
                    <p className="text-falcon-muted">アクション数</p>
                  </div>
                  <div className="text-center p-2 rounded-sm bg-falcon-border/40">
                    <p className="text-white font-bold">{(wf.run_count ?? 0).toLocaleString()}</p>
                    <p className="text-falcon-muted">実行回数</p>
                  </div>
                  <div className="text-center p-2 rounded-sm bg-falcon-border/40">
                    <p className={`font-bold ${wf.success_rate >= 95 ? 'text-emerald-400' : wf.success_rate >= 80 ? 'text-amber-400' : 'text-red-400'}`}>
                      {wf.success_rate}%
                    </p>
                    <p className="text-falcon-muted">成功率</p>
                  </div>
                </div>
                {wf.last_run && (
                  <p className="text-xs text-falcon-subtle flex items-center gap-1 mb-3">
                    <Clock className="w-3 h-3" />
                    最終実行: {formatDate(wf.last_run)}
                  </p>
                )}
                <div className="flex items-center gap-2 pt-2 border-t border-falcon-border">
                  <button onClick={() => setEditingWorkflow(wf)} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs bg-falcon-border hover:bg-[#2a3d5a] text-white transition-colors"><Edit3 className="w-3 h-3" />編集</button>
                  <button className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs bg-falcon-border hover:bg-[#2a3d5a] text-white transition-colors"><Copy className="w-3 h-3" />複製</button>
                  {wf.trigger.type === 'manual' && (
                    <button
                      onClick={() => runMutation.mutate(wf.id)}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs bg-blue-900/30 hover:bg-blue-900/50 text-blue-400 border border-blue-700/30 transition-colors"
                    >
                      <Play className="w-3 h-3" />実行
                    </button>
                  )}
                  <button
                    onClick={() => toggleMutation.mutate({ id: wf.id, status: wf.status === 'active' ? 'paused' : 'active' })}
                    className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs transition-colors border ${
                      wf.status === 'active'
                        ? 'bg-amber-900/20 hover:bg-amber-900/40 text-amber-400 border-amber-700/30'
                        : 'bg-emerald-900/20 hover:bg-emerald-900/40 text-emerald-400 border-emerald-700/30'
                    }`}
                  >
                    {wf.status === 'active' ? <><Pause className="w-3 h-3" />一時停止</> : <><Play className="w-3 h-3" />有効化</>}
                  </button>
                  <button
                    onClick={() => setDeleteConfirm(wf.id)}
                    className="ml-auto flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs bg-red-900/20 hover:bg-red-900/40 text-red-400 border border-red-700/30 transition-colors"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Run History */}
        {activeTab === 'history' && (
          <div className="bg-falcon-surface border border-falcon-border rounded-xl divide-y divide-falcon-border">
            {(runHistory ?? []).map(run => {
              const wf = activeWorkflows.find(w => w.id === run.workflow_id)
              return (
                <div key={run.id}>
                  <button
                    className="w-full px-5 py-4 flex items-center justify-between hover:bg-falcon-border/20 transition-colors text-left"
                    onClick={() => setExpandedHistory(expandedHistory === run.id ? null : run.id)}
                  >
                    <div className="flex items-center gap-3">
                      {run.status === 'success' ? <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                        : run.status === 'failure' ? <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                        : <Loader2 className="w-4 h-4 text-blue-400 animate-spin shrink-0" />}
                      <div>
                        <p className="text-white text-sm font-medium">{wf?.name ?? run.workflow_id}</p>
                        <p className="text-falcon-muted text-xs">{run.trigger_info}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-falcon-muted">
                      <span>{formatDuration(run.duration_ms)}</span>
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{formatDate(run.started_at)}</span>
                      {expandedHistory === run.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </div>
                  </button>
                  {expandedHistory === run.id && (
                    <div className="px-5 pb-4 space-y-2">
                      {run.steps.map((step, i) => (
                        <div key={i} className="flex items-center gap-3 text-sm ml-7">
                          {step.status === 'success' ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            : step.status === 'failure' ? <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                            : step.status === 'skipped' ? <div className="w-3.5 h-3.5 rounded-full border border-falcon-subtle shrink-0" />
                            : <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin shrink-0" />}
                          <span className="text-white">{step.step}</span>
                          <span className="text-falcon-subtle text-xs">{formatDuration(step.duration_ms)}</span>
                          {step.output && <span className="text-falcon-muted text-xs truncate">{step.output}</span>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}

        {/* Templates */}
        {activeTab === 'templates' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {([] as Template[]).map(tmpl => (
              <div key={tmpl.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-5 flex flex-col">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="mb-2"><TriggerBadge type={tmpl.trigger_type} /></div>
                    <h3 className="text-white font-semibold text-sm">{tmpl.name}</h3>
                  </div>
                  <span className="text-xs text-falcon-muted bg-falcon-border px-2 py-0.5 rounded-sm shrink-0 ml-2">{tmpl.action_count} アクション</span>
                </div>
                <p className="text-falcon-muted text-xs flex-1 mb-4">{tmpl.description}</p>
                <div className="flex flex-wrap gap-1 mb-4">
                  {tmpl.tags.map(tag => (
                    <span key={tag} className="px-2 py-0.5 rounded-sm text-[10px] bg-falcon-border text-falcon-muted">{tag}</span>
                  ))}
                </div>
                <button
                  onClick={() => setCreatingNew(true)}
                  className="w-full py-2 rounded-lg bg-falcon-red/20 hover:bg-falcon-red/40 text-falcon-red text-sm font-medium transition-colors border border-falcon-red/30"
                >
                  このテンプレートを使用
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Workflow Editor Slide-over */}
      {(editingWorkflow || creatingNew) && (
        <WorkflowEditor
          workflow={editingWorkflow ?? {}}
          onClose={() => { setEditingWorkflow(null); setCreatingNew(false) }}
          onSave={data => saveMutation.mutate(data)}
        />
      )}

      {/* Delete Confirm */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-sm shadow-2xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-red-900/30 flex items-center justify-center"><Trash2 className="w-5 h-5 text-red-400" /></div>
              <div>
                <h3 className="text-white font-semibold">ワークフローを削除</h3>
                <p className="text-falcon-muted text-sm">この操作は取り消せません。</p>
              </div>
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setDeleteConfirm(null)} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white text-sm font-medium transition-colors"
              >
                {deleteMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                削除
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
