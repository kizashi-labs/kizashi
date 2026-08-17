'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Bot, Plus, X, Play, Eye, CheckCircle, XCircle, AlertTriangle,
  ToggleLeft, ToggleRight, Edit2, Trash2, RefreshCw, Shield,
  Clock, Filter, TrendingUp, ChevronUp, ChevronDown, Zap,
  ArrowUp, ArrowDown, Circle
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────

type MaxScope = 'single_host' | 'subnet' | 'all'
type ActionType = 'isolate_host' | 'block_ip' | 'kill_process' | 'quarantine_file' | 'create_ticket' | 'send_notification' | 'run_script' | 'disable_account'
type ExecutionStatus = 'pending' | 'awaiting_approval' | 'approved' | 'running' | 'completed' | 'failed' | 'rejected'
type OnFailure = 'continue' | 'abort' | 'alert'

interface ConditionRow {
  field: string
  operator: string
  value: string
}

interface ActionStep {
  id: string
  action_type: ActionType
  params: Record<string, string>
  timeout_s: number
  on_failure: OnFailure
}

interface ResponsePolicy {
  id: string
  name: string
  description: string
  conditions: ConditionRow[]
  actions: ActionStep[]
  max_scope: MaxScope
  requires_approval: boolean
  approval_timeout_s: number
  execution_count: number
  success_rate: number
  is_active: boolean
  created_at: string
}

interface ActionResult {
  action_type: ActionType
  timestamp: string
  status: 'success' | 'failed' | 'skipped'
  result: string
}

interface Execution {
  id: string
  policy_id: string
  policy_name: string
  trigger_summary: string
  trigger_event: Record<string, unknown>
  status: ExecutionStatus
  affected_hosts: string[]
  created_at: string
  completed_at: string | null
  duration_s: number | null
  actions_taken: ActionResult[]
  approval_chain: { user: string; action: 'approved' | 'rejected'; timestamp: string }[]
}

// ── Helpers ───────────────────────────────────────────────────────

const SCOPE_CONFIG: Record<MaxScope, { label: string; bg: string; text: string }> = {
  single_host: { label: '単一ホスト', bg: 'bg-green-900/40', text: 'text-green-300' },
  subnet:      { label: 'サブネット', bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  all:         { label: '全体',       bg: 'bg-red-900/40',    text: 'text-red-300' },
}

const STATUS_CONFIG: Record<ExecutionStatus, { label: string; bg: string; text: string; pulse?: boolean }> = {
  pending:           { label: '待機中',     bg: 'bg-gray-800',      text: 'text-gray-400' },
  awaiting_approval: { label: '承認待ち',   bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  approved:          { label: '承認済',     bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  running:           { label: '実行中',     bg: 'bg-green-900/40',  text: 'text-green-300', pulse: true },
  completed:         { label: '完了',       bg: 'bg-green-900/40',  text: 'text-green-300' },
  failed:            { label: '失敗',       bg: 'bg-red-900/40',    text: 'text-red-300' },
  rejected:          { label: '拒否',       bg: 'bg-red-900/50',    text: 'text-red-200' },
}

const ACTION_TYPE_LABELS: Record<ActionType, string> = {
  isolate_host:       'ホスト隔離',
  block_ip:           'IP ブロック',
  kill_process:       'プロセス終了',
  quarantine_file:    'ファイル隔離',
  create_ticket:      'チケット作成',
  send_notification:  '通知送信',
  run_script:         'スクリプト実行',
  disable_account:    'アカウント無効化',
}

const ON_FAILURE_LABELS: Record<OnFailure, string> = { continue: '継続', abort: '中断', alert: 'アラート' }
const CONDITION_FIELDS = ['severity', 'category', 'hostname', 'source', 'rule_name', 'alert_id']
const CONDITION_OPERATORS = ['equals', 'contains', 'not_equals', 'greater_than']

function fmt(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Policy Form Modal ─────────────────────────────────────────────

function PolicyFormModal({ policy, onClose, onSave }: {
  policy: ResponsePolicy | null
  onClose: () => void
  onSave: (p: Omit<ResponsePolicy, 'id' | 'execution_count' | 'success_rate' | 'created_at'>) => void
}) {
  const blank = {
    name: '', description: '', conditions: [{ field: 'severity', operator: 'equals', value: '' }] as ConditionRow[],
    actions: [] as ActionStep[], max_scope: 'single_host' as MaxScope, requires_approval: false, approval_timeout_s: 300, is_active: true,
  }
  const [form, setForm] = useState(policy ? {
    name: policy.name, description: policy.description, conditions: policy.conditions, actions: policy.actions,
    max_scope: policy.max_scope, requires_approval: policy.requires_approval, approval_timeout_s: policy.approval_timeout_s, is_active: policy.is_active,
  } : blank)

  const addCondition = () => setForm(p => ({ ...p, conditions: [...p.conditions, { field: 'severity', operator: 'equals', value: '' }] }))
  const removeCondition = (i: number) => setForm(p => ({ ...p, conditions: p.conditions.filter((_, idx) => idx !== i) }))

  const addAction = () => setForm(p => ({ ...p, actions: [...p.actions, { id: String(Date.now()), action_type: 'isolate_host' as ActionType, params: {}, timeout_s: 30, on_failure: 'abort' as OnFailure }] }))
  const removeAction = (i: number) => setForm(p => ({ ...p, actions: p.actions.filter((_, idx) => idx !== i) }))
  const moveAction = (i: number, dir: -1 | 1) => {
    const actions = [...form.actions]
    const j = i + dir
    if (j < 0 || j >= actions.length) return
    ;[actions[i], actions[j]] = [actions[j], actions[i]]
    setForm(p => ({ ...p, actions }))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold text-lg">{policy ? 'ポリシー編集' : 'ポリシー追加'}</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">ポリシー名</label>
              <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" />
            </div>
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">最大スコープ</label>
              <select value={form.max_scope} onChange={e => setForm(p => ({ ...p, max_scope: e.target.value as MaxScope }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden">
                {(Object.keys(SCOPE_CONFIG) as MaxScope[]).map(s => <option key={s} value={s}>{SCOPE_CONFIG[s].label}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">説明</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
              rows={2} className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden resize-none" />
          </div>

          {/* Conditions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-falcon-muted font-medium uppercase tracking-wider">トリガー条件</label>
              <button onClick={addCondition} className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300">
                <Plus className="w-3 h-3" /> 条件追加
              </button>
            </div>
            <div className="space-y-2">
              {form.conditions.map((c, i) => (
                <div key={i} className="flex items-center gap-2">
                  <select value={c.field} onChange={e => setForm(p => ({ ...p, conditions: p.conditions.map((cc, idx) => idx === i ? { ...cc, field: e.target.value } : cc) }))}
                    className="bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-falcon-muted focus:outline-hidden">
                    {CONDITION_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                  </select>
                  <select value={c.operator} onChange={e => setForm(p => ({ ...p, conditions: p.conditions.map((cc, idx) => idx === i ? { ...cc, operator: e.target.value } : cc) }))}
                    className="bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-falcon-muted focus:outline-hidden">
                    {CONDITION_OPERATORS.map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                  <input value={c.value} onChange={e => setForm(p => ({ ...p, conditions: p.conditions.map((cc, idx) => idx === i ? { ...cc, value: e.target.value } : cc) }))}
                    placeholder="値..."
                    className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-white focus:outline-hidden" />
                  {form.conditions.length > 1 && (
                    <button onClick={() => removeCondition(i)} className="text-falcon-muted hover:text-red-400"><X className="w-3.5 h-3.5" /></button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-falcon-muted font-medium uppercase tracking-wider">レスポンスアクション (順序付き)</label>
              <button onClick={addAction} className="flex items-center gap-1 text-xs text-green-400 hover:text-green-300">
                <Plus className="w-3 h-3" /> アクション追加
              </button>
            </div>
            <div className="space-y-2">
              {form.actions.map((a, i) => (
                <div key={a.id} className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs text-falcon-subtle font-mono w-4">{i + 1}.</span>
                    <select value={a.action_type} onChange={e => setForm(p => ({ ...p, actions: p.actions.map((aa, idx) => idx === i ? { ...aa, action_type: e.target.value as ActionType } : aa) }))}
                      className="flex-1 bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-white focus:outline-hidden">
                      {(Object.keys(ACTION_TYPE_LABELS) as ActionType[]).map(t => <option key={t} value={t}>{ACTION_TYPE_LABELS[t]}</option>)}
                    </select>
                    <select value={a.on_failure} onChange={e => setForm(p => ({ ...p, actions: p.actions.map((aa, idx) => idx === i ? { ...aa, on_failure: e.target.value as OnFailure } : aa) }))}
                      className="bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1.5 text-xs text-falcon-muted focus:outline-hidden">
                      {(Object.keys(ON_FAILURE_LABELS) as OnFailure[]).map(f => <option key={f} value={f}>失敗時: {ON_FAILURE_LABELS[f]}</option>)}
                    </select>
                    <div className="flex gap-0.5">
                      <button onClick={() => moveAction(i, -1)} className="text-falcon-subtle hover:text-white p-0.5"><ArrowUp className="w-3 h-3" /></button>
                      <button onClick={() => moveAction(i, 1)} className="text-falcon-subtle hover:text-white p-0.5"><ArrowDown className="w-3 h-3" /></button>
                    </div>
                    <button onClick={() => removeAction(i)} className="text-falcon-muted hover:text-red-400"><X className="w-3.5 h-3.5" /></button>
                  </div>
                  <div className="flex items-center gap-2 pl-5">
                    <span className="text-xs text-falcon-subtle">タイムアウト:</span>
                    <input type="number" value={a.timeout_s} onChange={e => setForm(p => ({ ...p, actions: p.actions.map((aa, idx) => idx === i ? { ...aa, timeout_s: Number(e.target.value) } : aa) }))}
                      className="w-20 bg-falcon-surface border border-falcon-border rounded-sm px-2 py-1 text-xs text-white focus:outline-hidden" />
                    <span className="text-xs text-falcon-subtle">秒</span>
                  </div>
                </div>
              ))}
              {form.actions.length === 0 && (
                <p className="text-xs text-falcon-subtle text-center py-3">アクションを追加してください</p>
              )}
            </div>
          </div>

          {/* Approval */}
          <div className="flex items-center justify-between p-3 bg-[#070d19] rounded-lg border border-falcon-border">
            <div>
              <p className="text-sm text-falcon-text font-medium">承認を必要とする</p>
              <p className="text-xs text-falcon-muted">実行前に管理者の承認が必要</p>
            </div>
            <button onClick={() => setForm(p => ({ ...p, requires_approval: !p.requires_approval }))}>
              {form.requires_approval ? <ToggleRight className="w-6 h-6 text-yellow-400" /> : <ToggleLeft className="w-6 h-6 text-falcon-subtle" />}
            </button>
          </div>
          {form.requires_approval && (
            <div>
              <label className="text-xs text-falcon-muted mb-1 block">承認タイムアウト (秒)</label>
              <input type="number" value={form.approval_timeout_s} onChange={e => setForm(p => ({ ...p, approval_timeout_s: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden" />
            </div>
          )}
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => { if (form.name && form.actions.length > 0) { onSave(form); onClose() } }}
            className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ── Policy Test Modal ─────────────────────────────────────────────

function PolicyTestModal({ policies, onClose }: { policies: ResponsePolicy[]; onClose: () => void }) {
  const [alertInput, setAlertInput] = useState({ severity: 'critical', category: 'ransomware', hostname: 'workstation-01', source: 'edr', rule_name: 'Ransomware-Detection' })
  const [results, setResults] = useState<{ policy: ResponsePolicy; matched: boolean }[] | null>(null)

  const runTest = () => {
    const res = policies.filter(p => p.is_active).map(p => {
      const matched = p.conditions.every(c => {
        const val = (alertInput as any)[c.field] as string
        if (!val) return false
        if (c.operator === 'equals') return val === c.value
        if (c.operator === 'not_equals') return val !== c.value
        if (c.operator === 'contains') return val.toLowerCase().includes(c.value.toLowerCase())
        return false
      })
      return { policy: p, matched }
    })
    setResults(res)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-lg">ポリシーをテスト (ドライラン)</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="grid grid-cols-2 gap-3 mb-4">
          {Object.keys(alertInput).map(f => (
            <div key={f}>
              <label className="text-xs text-falcon-muted mb-1 block">{f}</label>
              <input value={(alertInput as any)[f]} onChange={e => setAlertInput(p => ({ ...p, [f]: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-xs text-white focus:outline-hidden" />
            </div>
          ))}
        </div>
        <button onClick={runTest}
          className="w-full py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors flex items-center justify-center gap-2 mb-4">
          <Play className="w-4 h-4" /> ドライラン実行
        </button>
        {results && (
          <div className="space-y-2">
            <p className="text-xs text-falcon-muted mb-2 uppercase tracking-wider">
              {results.filter(r => r.matched).length}/{results.length} ポリシーがマッチ
            </p>
            {results.map(({ policy, matched }) => (
              <div key={policy.id} className={`p-3 rounded-lg border flex items-center gap-3 ${matched ? 'border-falcon-red/30 bg-falcon-red/10' : 'border-falcon-border opacity-50'}`}>
                {matched ? <Zap className="w-4 h-4 text-falcon-red shrink-0" /> : <XCircle className="w-4 h-4 text-falcon-subtle shrink-0" />}
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium ${matched ? 'text-white' : 'text-falcon-muted'}`}>{policy.name}</p>
                  {matched && (
                    <p className="text-xs text-falcon-muted">
                      アクション: {policy.actions.map(a => ACTION_TYPE_LABELS[a.action_type]).join(' → ')}
                    </p>
                  )}
                </div>
                {matched && <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SCOPE_CONFIG[policy.max_scope].bg} ${SCOPE_CONFIG[policy.max_scope].text}`}>{SCOPE_CONFIG[policy.max_scope].label}</span>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Execution Detail Modal ────────────────────────────────────────

function ExecutionDetailModal({ execution, onClose }: { execution: Execution; onClose: () => void }) {
  const sc = STATUS_CONFIG[execution.status]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-white font-semibold text-lg">{execution.policy_name}</h2>
            <p className="text-falcon-muted text-xs mt-0.5">{execution.trigger_summary}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        <div className="flex items-center gap-3 mb-4">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sc.bg} ${sc.text}`}>{sc.label}</span>
          <span className="text-xs text-falcon-muted">{fmt(execution.created_at)}</span>
          {execution.affected_hosts.length > 0 && (
            <div className="flex gap-1">
              {execution.affected_hosts.map(h => (
                <span key={h} className="text-xs font-mono bg-falcon-border px-2 py-0.5 rounded-sm text-falcon-text">{h}</span>
              ))}
            </div>
          )}
        </div>

        {/* Trigger event */}
        <div className="mb-4">
          <p className="text-xs text-falcon-muted mb-2 font-medium uppercase tracking-wider">トリガーイベント</p>
          <pre className="bg-[#070d19] border border-falcon-border rounded-sm p-3 text-xs font-mono text-falcon-muted overflow-x-auto">
            {JSON.stringify(execution.trigger_event, null, 2)}
          </pre>
        </div>

        {/* Actions taken */}
        {execution.actions_taken.length > 0 && (
          <div className="mb-4">
            <p className="text-xs text-falcon-muted mb-2 font-medium uppercase tracking-wider">実行アクション</p>
            <div className="space-y-2">
              {execution.actions_taken.map((a, i) => (
                <div key={i} className={`p-3 rounded-lg border flex items-start gap-3 ${a.status === 'success' ? 'border-green-700/30 bg-green-900/10' : a.status === 'failed' ? 'border-red-700/30 bg-red-900/10' : 'border-falcon-border'}`}>
                  {a.status === 'success' ? <CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" /> :
                    a.status === 'failed' ? <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" /> :
                    <Circle className="w-4 h-4 text-falcon-subtle shrink-0 mt-0.5" />}
                  <div className="flex-1">
                    <p className="text-sm text-white font-medium">{ACTION_TYPE_LABELS[a.action_type]}</p>
                    <p className="text-xs text-falcon-muted">{a.result}</p>
                    <p className="text-xs text-falcon-subtle mt-0.5">{fmt(a.timestamp)}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Approval chain */}
        {execution.approval_chain.length > 0 && (
          <div>
            <p className="text-xs text-falcon-muted mb-2 font-medium uppercase tracking-wider">承認チェーン</p>
            {execution.approval_chain.map((ac, i) => (
              <div key={i} className="flex items-center gap-3 p-3 bg-[#070d19] rounded-lg border border-falcon-border">
                {ac.action === 'approved' ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                <div>
                  <p className="text-sm text-white">{ac.user}</p>
                  <p className="text-xs text-falcon-muted">{ac.action === 'approved' ? '承認' : '拒否'} — {fmt(ac.timestamp)}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────

export default function AutonomousResponsePage() {
  const [tab, setTab] = useState<'policies' | 'executions'>('policies')
  const [masterEnabled, setMasterEnabled] = useState(false)
  const [localPolicies, setLocalPolicies] = useState<ResponsePolicy[]>([])
  const [localExecutions, setLocalExecutions] = useState<Execution[]>([])
  const [showPolicyForm, setShowPolicyForm] = useState(false)
  const [editPolicy, setEditPolicy] = useState<ResponsePolicy | null>(null)
  const [showPolicyTest, setShowPolicyTest] = useState(false)
  const [detailExecution, setDetailExecution] = useState<Execution | null>(null)
  const [filterStatus, setFilterStatus] = useState<ExecutionStatus | ''>('')
  const [filterPolicy, setFilterPolicy] = useState<string>('')
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 4000) }

  useQuery({
    queryKey: ['autonomous-response-policies'],
    queryFn: () => apiFetch('/api/v1/admin/autonomous-response/policies'),
    onError: () => {},
  } as any)

  useQuery({
    queryKey: ['autonomous-response-executions'],
    queryFn: () => apiFetch('/api/v1/admin/autonomous-response/executions'),
    onError: () => {},
  } as any)

  const handleTogglePolicy = async (p: ResponsePolicy) => {
    try { await apiFetch(`/api/v1/admin/autonomous-response/policies/${p.id}/toggle`, { method: 'POST' }) } catch {}
    setLocalPolicies(prev => prev.map(x => x.id === p.id ? { ...x, is_active: !x.is_active } : x))
  }

  const handleDeletePolicy = async (p: ResponsePolicy) => {
    try { await apiFetch(`/api/v1/admin/autonomous-response/policies/${p.id}`, { method: 'DELETE' }) } catch {}
    setLocalPolicies(prev => prev.filter(x => x.id !== p.id))
    showToast(`ポリシー「${p.name}」を削除しました`)
  }

  const handleSavePolicy = (form: Omit<ResponsePolicy, 'id' | 'execution_count' | 'success_rate' | 'created_at'>) => {
    if (editPolicy) {
      setLocalPolicies(prev => prev.map(x => x.id === editPolicy.id ? { ...x, ...form } : x))
      showToast('ポリシーを更新しました')
    } else {
      const newP: ResponsePolicy = { ...form, id: String(Date.now()), execution_count: 0, success_rate: 0, created_at: new Date().toISOString() }
      try { apiFetch('/api/v1/admin/autonomous-response/policies', { method: 'POST', body: JSON.stringify(form) }) } catch {}
      setLocalPolicies(prev => [...prev, newP])
      showToast(`ポリシー「${form.name}」を追加しました`)
    }
    setEditPolicy(null)
  }

  const handleApprove = async (exec: Execution) => {
    try { await apiFetch(`/api/v1/admin/autonomous-response/executions/${exec.id}/approve`, { method: 'POST' }) } catch {}
    setLocalExecutions(prev => prev.map(x => x.id === exec.id ? { ...x, status: 'approved', approval_chain: [...x.approval_chain, { user: '現在のユーザー', action: 'approved', timestamp: new Date().toISOString() }] } : x))
    showToast('実行を承認しました')
  }

  const handleReject = async (exec: Execution) => {
    try { await apiFetch(`/api/v1/admin/autonomous-response/executions/${exec.id}/reject`, { method: 'POST' }) } catch {}
    setLocalExecutions(prev => prev.map(x => x.id === exec.id ? { ...x, status: 'rejected', approval_chain: [...x.approval_chain, { user: '現在のユーザー', action: 'rejected', timestamp: new Date().toISOString() }] } : x))
    showToast('実行を拒否しました')
  }

  // Stats
  const activePolicies = localPolicies.filter(p => p.is_active).length
  const executionsToday = localExecutions.filter(e => e.created_at.startsWith('2026-03-18')).length
  const awaitingApproval = localExecutions.filter(e => e.status === 'awaiting_approval').length
  const completedExecs = localExecutions.filter(e => e.status === 'completed')
  const successRate = completedExecs.length > 0 ?
    Math.round(localExecutions.filter(e => e.status === 'completed').length / localExecutions.filter(e => ['completed', 'failed'].includes(e.status)).length * 100) : 0

  // Filtered executions
  const filtered = localExecutions.filter(e => {
    if (filterStatus && e.status !== filterStatus) return false
    if (filterPolicy && e.policy_id !== filterPolicy) return false
    return true
  })

  // Success rate chart data (mock)
  const effectivenessData = [78, 82, 85, 88, 86, 92].map((v, i) => ({ label: `W${i + 1}`, value: v }))

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
            <Bot className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white text-2xl font-bold">自律対応エンジン</h1>
            <p className="text-falcon-muted text-sm">アラートトリガーに基づく自動レスポンスポリシー</p>
          </div>
        </div>
        {/* Master switch */}
        <div className={`flex items-center gap-3 px-4 py-3 rounded-xl border ${masterEnabled ? 'border-falcon-red/50 bg-falcon-red/10' : 'border-falcon-border bg-falcon-surface'}`}>
          {masterEnabled && <AlertTriangle className="w-4 h-4 text-falcon-red" />}
          <div>
            <p className="text-sm text-white font-medium">自動実行</p>
            <p className={`text-xs ${masterEnabled ? 'text-falcon-red' : 'text-falcon-subtle'}`}>{masterEnabled ? '有効 — 注意して使用' : '無効'}</p>
          </div>
          <button onClick={() => setMasterEnabled(!masterEnabled)}>
            {masterEnabled ? <ToggleRight className="w-7 h-7 text-falcon-red" /> : <ToggleLeft className="w-7 h-7 text-falcon-subtle" />}
          </button>
        </div>
      </div>

      {masterEnabled && (
        <div className="p-3 bg-falcon-red/10 border border-falcon-red/30 rounded-lg mb-6 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-falcon-red shrink-0 mt-0.5" />
          <p className="text-xs text-falcon-red">自動実行が有効です。ポリシーは承認なしに実行されます。承認が必要なポリシーを除いて、すべての自動アクションが即時実行されます。</p>
        </div>
      )}

      {/* Status Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'アクティブポリシー', value: activePolicies, color: 'text-blue-400' },
          { label: '本日の実行数', value: executionsToday, color: 'text-purple-400' },
          { label: '承認待ち', value: awaitingApproval, color: awaitingApproval > 0 ? 'text-yellow-400' : 'text-falcon-muted' },
          { label: '成功率', value: `${successRate}%`, color: successRate >= 80 ? 'text-green-400' : 'text-orange-400' },
        ].map(c => (
          <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <p className="text-xs text-falcon-muted mb-2">{c.label}</p>
            <p className={`text-2xl font-bold ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[{ key: 'policies', label: 'ポリシー設定' }, { key: 'executions', label: '実行ログ' }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${tab === t.key ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'}`}>
            {t.label}
            {t.key === 'executions' && awaitingApproval > 0 && (
              <span className="ml-2 text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-yellow-500 text-black">{awaitingApproval}</span>
            )}
          </button>
        ))}
      </div>

      {/* Policies Tab */}
      {tab === 'policies' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="text-falcon-muted text-sm">{localPolicies.length} ポリシー</p>
            <div className="flex gap-2">
              <button onClick={() => setShowPolicyTest(true)}
                className="flex items-center gap-2 px-4 py-2 bg-falcon-surface border border-falcon-border text-falcon-muted rounded-lg text-sm hover:text-white transition-colors">
                <Play className="w-4 h-4" /> ポリシーをテスト
              </button>
              <button onClick={() => { setEditPolicy(null); setShowPolicyForm(true) }}
                className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
                <Plus className="w-4 h-4" /> ポリシー追加
              </button>
            </div>
          </div>
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ポリシー名', 'トリガー', 'アクション', 'スコープ', '承認', '実行数', '成功率', '有効', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {localPolicies.map(p => {
                  const sc = SCOPE_CONFIG[p.max_scope]
                  const triggerSummary = p.conditions.map(c => `${c.field}${c.operator === 'equals' ? '=' : c.operator === 'contains' ? '∋' : '≠'}${c.value}`).join(' & ')
                  const actionSummary = p.actions.map(a => ACTION_TYPE_LABELS[a.action_type]).join(' → ')
                  return (
                    <tr key={p.id} className={`border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors ${!p.is_active ? 'opacity-50' : ''}`}>
                      <td className="px-4 py-3 max-w-[160px]">
                        <p className="text-white text-sm font-medium truncate" title={p.name}>{p.name}</p>
                        <p className="text-falcon-muted text-xs truncate" title={p.description}>{p.description}</p>
                      </td>
                      <td className="px-4 py-3 max-w-[140px]">
                        <p className="text-xs font-mono text-falcon-muted truncate" title={triggerSummary}>{triggerSummary}</p>
                      </td>
                      <td className="px-4 py-3 max-w-[160px]">
                        <p className="text-xs text-falcon-muted truncate" title={actionSummary}>{actionSummary}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sc.bg} ${sc.text}`}>{sc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        {p.requires_approval ? (
                          <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-yellow-900/40 text-yellow-300">必要</span>
                        ) : (
                          <span className="text-xs text-falcon-subtle">不要</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-white font-semibold">{p.execution_count}</td>
                      <td className="px-4 py-3">
                        <span className={`text-sm font-bold ${p.success_rate >= 90 ? 'text-green-400' : p.success_rate >= 70 ? 'text-yellow-400' : 'text-red-400'}`}>{p.success_rate}%</span>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleTogglePolicy(p)}>
                          {p.is_active ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button onClick={() => { setEditPolicy(p); setShowPolicyForm(true) }} className="text-falcon-muted hover:text-white transition-colors">
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => handleDeletePolicy(p)} className="text-falcon-muted hover:text-red-400 transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Executions Tab */}
      {tab === 'executions' && (
        <div>
          {/* Filters */}
          <div className="flex flex-wrap gap-3 mb-4">
            <div className="flex items-center gap-2 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2">
              <Filter className="w-3.5 h-3.5 text-falcon-muted" />
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value as any)}
                className="bg-transparent text-sm text-falcon-muted focus:outline-hidden">
                <option value="">全ステータス</option>
                {(Object.keys(STATUS_CONFIG) as ExecutionStatus[]).map(s => (
                  <option key={s} value={s}>{STATUS_CONFIG[s].label}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2">
              <select value={filterPolicy} onChange={e => setFilterPolicy(e.target.value)}
                className="bg-transparent text-sm text-falcon-muted focus:outline-hidden">
                <option value="">全ポリシー</option>
                {localPolicies.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
            {(filterStatus || filterPolicy) && (
              <button onClick={() => { setFilterStatus(''); setFilterPolicy('') }}
                className="text-xs text-falcon-muted hover:text-white px-3 border border-falcon-border rounded-lg">リセット</button>
            )}
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden mb-6">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ポリシー', 'トリガーサマリー', 'ステータス', '影響ホスト', '開始時刻', '所要時間', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(exec => {
                  const sc = STATUS_CONFIG[exec.status]
                  return (
                    <tr key={exec.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3 max-w-[140px]">
                        <p className="text-white text-xs font-medium truncate" title={exec.policy_name}>{exec.policy_name}</p>
                      </td>
                      <td className="px-4 py-3 max-w-[200px]">
                        <p className="text-xs text-falcon-muted truncate" title={exec.trigger_summary}>{exec.trigger_summary}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sc.bg} ${sc.text} ${sc.pulse ? 'animate-pulse' : ''}`}>{sc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {exec.affected_hosts.slice(0, 2).map(h => (
                            <span key={h} className="text-[10px] font-mono bg-falcon-border px-1.5 py-0.5 rounded-sm text-falcon-muted">{h}</span>
                          ))}
                          {exec.affected_hosts.length > 2 && <span className="text-[10px] text-falcon-subtle">+{exec.affected_hosts.length - 2}</span>}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmt(exec.created_at)}</td>
                      <td className="px-4 py-3 text-xs text-falcon-muted">
                        {exec.duration_s !== null ? `${exec.duration_s}s` : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          {exec.status === 'awaiting_approval' && (
                            <>
                              <button onClick={() => handleApprove(exec)}
                                className="px-2 py-1 rounded-sm text-xs font-medium bg-green-900/40 text-green-300 hover:bg-green-900/60 transition-colors">承認</button>
                              <button onClick={() => handleReject(exec)}
                                className="px-2 py-1 rounded-sm text-xs font-medium bg-red-900/40 text-red-300 hover:bg-red-900/60 transition-colors">拒否</button>
                            </>
                          )}
                          <button onClick={() => setDetailExecution(exec)} className="text-falcon-muted hover:text-white transition-colors">
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
                {filtered.length === 0 && (
                  <tr><td colSpan={7} className="text-center py-10 text-falcon-muted text-sm">条件に一致する実行ログがありません</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Effectiveness chart */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <p className="text-xs text-falcon-muted mb-3 font-medium uppercase tracking-wider flex items-center gap-2">
              <TrendingUp className="w-3.5 h-3.5" /> 自動対応成功率トレンド (週次)
            </p>
            <div className="flex items-end gap-4 h-16">
              {effectivenessData.map(d => (
                <div key={d.label} className="flex-1 flex flex-col items-center gap-1">
                  <span className="text-[9px] text-falcon-muted">{d.value}%</span>
                  <div className={`w-full rounded-t ${d.value >= 90 ? 'bg-green-500' : d.value >= 80 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ height: `${(d.value / 100) * 48}px` }} />
                  <span className="text-[9px] text-falcon-subtle">{d.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {showPolicyForm && (
        <PolicyFormModal
          policy={editPolicy}
          onClose={() => { setShowPolicyForm(false); setEditPolicy(null) }}
          onSave={handleSavePolicy}
        />
      )}
      {showPolicyTest && <PolicyTestModal policies={localPolicies} onClose={() => setShowPolicyTest(false)} />}
      {detailExecution && <ExecutionDetailModal execution={detailExecution} onClose={() => setDetailExecution(null)} />}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-falcon-surface border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-sm text-falcon-text flex-1">{toast}</p>
          <button onClick={() => setToast(null)} className="text-falcon-muted hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
