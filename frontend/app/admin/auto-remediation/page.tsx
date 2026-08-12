'use client'

import { Fragment, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Zap, Plus, ToggleLeft, ToggleRight,
  Shield, Lock, Unlock, Trash2, AlertTriangle, CheckCircle, XCircle,
  Clock, Activity, X, ShieldOff, Webhook, RotateCcw, CheckSquare, Bell, Settings,
} from 'lucide-react'

// ─── Types (server wire format) ───────────────────────────────────────────────
// Shapes below mirror server/internal/remediation/engine.go — do not "simplify"
// them without checking the Go structs; the two drifted apart once already.

type LogStatus = 'success' | 'partial' | 'failed'

interface RuleTrigger {
  event_type?: string
  min_severity?: number
  tags?: string[] | null
  conditions?: Record<string, string> | null
}

interface RuleAction {
  type: string
  params?: Record<string, string> | null
}

interface RemediationRule {
  id: string
  name: string
  enabled: boolean
  trigger?: RuleTrigger | null
  actions?: RuleAction[] | null
  /** Go duration string, e.g. "15m0s" */
  cooldown?: string
  rollback_timeout?: string
  created_at?: string
}

interface ActionResult {
  action_type: string
  success: boolean
  message: string
  duration_ms?: number
}

interface ExecutionLog {
  id: string
  rule_id: string
  rule_name: string
  trigger_id: string
  agent_id: string
  status: LogStatus | string
  /** null when logs come from the DB — that query does not select action rows. */
  actions?: ActionResult[] | null
  executed_at: string
}

interface RemediationExclusion {
  id: string
  hostname_pattern: string
  reason: string
  created_by: string
  created_at: string
}

interface PendingRollback {
  execution_id: string
  agent_id: string
  scheduled_at: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

interface ActionConfig { label: string; icon: React.ReactNode; color: string }

// Keys must match the action types the engine actually dispatches on
// (engine.go executeAction switch). Unknown types fall back to UNKNOWN_ACTION
// rather than crashing the page.
const ACTION_CONFIG: Record<string, ActionConfig> = {
  isolate_network: { label: 'Isolate', icon: <Lock className="w-3.5 h-3.5" />, color: 'text-red-400' },
  un_isolate_network: { label: 'Un-isolate', icon: <Unlock className="w-3.5 h-3.5" />, color: 'text-green-400' },
  kill_process: { label: 'Kill Process', icon: <XCircle className="w-3.5 h-3.5" />, color: 'text-orange-400' },
  quarantine_file: { label: 'Quarantine', icon: <Shield className="w-3.5 h-3.5" />, color: 'text-yellow-400' },
  create_alert: { label: 'Create Alert', icon: <AlertTriangle className="w-3.5 h-3.5" />, color: 'text-amber-400' },
  notify: { label: 'Notify', icon: <Bell className="w-3.5 h-3.5" />, color: 'text-blue-400' },
  webhook: { label: 'Webhook', icon: <Webhook className="w-3.5 h-3.5" />, color: 'text-purple-400' },
}

const UNKNOWN_ACTION: ActionConfig = {
  label: 'Unknown', icon: <Settings className="w-3.5 h-3.5" />, color: 'text-zinc-400',
}

const actionConfig = (type: string): ActionConfig =>
  ACTION_CONFIG[type] ?? { ...UNKNOWN_ACTION, label: type || 'Unknown' }

interface StatusConfig { label: string; className: string; icon: React.ReactNode }

const LOG_STATUS_CONFIG: Record<string, StatusConfig> = {
  success: { label: 'Success', className: 'bg-green-500/15 text-green-400 border-green-500/30', icon: <CheckCircle className="w-3.5 h-3.5" /> },
  partial: { label: 'Partial', className: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30', icon: <AlertTriangle className="w-3.5 h-3.5" /> },
  failed: { label: 'Failed', className: 'bg-red-500/15 text-red-400 border-red-500/30', icon: <XCircle className="w-3.5 h-3.5" /> },
}

const logStatusConfig = (status: string): StatusConfig =>
  LOG_STATUS_CONFIG[status] ?? {
    label: status || 'Unknown',
    className: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
    icon: <Activity className="w-3.5 h-3.5" />,
  }

const SEV_COLOR = (s: number) => {
  if (s >= 9) return 'border-l-red-500 bg-red-500/5'
  if (s >= 7) return 'border-l-orange-500 bg-orange-500/5'
  if (s >= 5) return 'border-l-yellow-500 bg-yellow-500/5'
  return 'border-l-blue-500 bg-blue-500/5'
}

const SEV_TEXT = (s: number) => {
  if (s >= 9) return 'text-red-400'
  if (s >= 7) return 'text-orange-400'
  if (s >= 5) return 'text-yellow-400'
  return 'text-blue-400'
}

// The engine always evaluates triggers with eventType "alert"
// (engine.go TriggerOnAlert), so anything else here would produce a rule that
// can never fire. An empty value means "match any event type".
const EVENT_TYPES: { value: string; label: string }[] = [
  { value: 'alert', label: 'alert' },
  { value: '', label: '(any)' },
]

const LOG_LIMIT = 200

const isToday = (iso: string) => {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return false
  const now = new Date()
  return d.getFullYear() === now.getFullYear()
    && d.getMonth() === now.getMonth()
    && d.getDate() === now.getDate()
}

const fmtDate = (iso?: string) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AutoRemediationPage() {
  const qc = useQueryClient()
  const [expandedLog, setExpandedLog] = useState<string | null>(null)
  const [showCreateRule, setShowCreateRule] = useState(false)
  const [ruleEnabled, setRuleEnabled] = useState<Record<string, boolean>>({})
  const [ruleError, setRuleError] = useState('')
  const [newRule, setNewRule] = useState({
    name: '',
    min_severity: 7,
    event_type: 'alert',
    action_type: 'isolate_network',
    tags: '',
    cooldown_seconds: 300,
    rollback_timeout_seconds: 0,
  })

  // Exclusion list state
  const [showAddExclusion, setShowAddExclusion] = useState(false)
  const [newExclusion, setNewExclusion] = useState({ hostname_pattern: '', reason: '' })
  const [exclusionError, setExclusionError] = useState('')

  const { data: rulesData, refetch: refetchRules } = useQuery<RemediationRule[]>({
    queryKey: ['remediation-rules'],
    queryFn: () => apiFetch<{ rules: RemediationRule[] }>('/api/v1/admin/remediation/rules')
      .then(r => r.rules ?? []).catch(() => []),
    staleTime: 30_000,
    retry: false,
  })

  const { data: logsData } = useQuery<ExecutionLog[]>({
    queryKey: ['remediation-logs'],
    queryFn: () => apiFetch<{ logs: ExecutionLog[] }>(`/api/v1/admin/remediation/logs?limit=${LOG_LIMIT}`)
      .then(r => r.logs ?? []).catch(() => []),
    staleTime: 30_000,
    retry: false,
  })

  const { data: exclusionsData, refetch: refetchExclusions } = useQuery<RemediationExclusion[]>({
    queryKey: ['remediation-exclusions'],
    queryFn: () => apiFetch<{ exclusions: RemediationExclusion[] }>('/api/v1/admin/remediation/exclusions')
      .then(r => r.exclusions ?? []).catch(() => []),
    staleTime: 30_000,
    retry: false,
  })

  const { data: pendingData, refetch: refetchPending } = useQuery<PendingRollback[]>({
    queryKey: ['remediation-pending-rollbacks'],
    queryFn: () => apiFetch<{ pending_rollbacks: PendingRollback[] }>('/api/v1/admin/remediation/pending-rollbacks')
      .then(r => r.pending_rollbacks ?? []).catch(() => []),
    refetchInterval: 15_000,
    retry: false,
  })

  const approveMutation = useMutation({
    mutationFn: (executionId: string) =>
      apiFetch(`/api/v1/admin/remediation/executions/${executionId}/approve`, { method: 'POST' }),
    onSuccess: () => {
      refetchPending()
      qc.invalidateQueries({ queryKey: ['remediation-logs'] })
    },
  })

  const deleteExclusionMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/remediation/exclusions/${id}`, { method: 'DELETE' }),
    onSuccess: () => refetchExclusions(),
  })

  const rules = rulesData ?? []
  const logs = logsData ?? []
  const exclusions = exclusionsData ?? []
  const pendingRollbacks = pendingData ?? []

  // The API has no executions_today field; derive it from the most recent
  // LOG_LIMIT execution logs. Saturated counts are marked with "+".
  const logsTruncated = logs.length >= LOG_LIMIT
  const todayLogs = logs.filter(l => isToday(l.executed_at))
  const execCountByRule = todayLogs.reduce<Record<string, number>>((acc, l) => {
    acc[l.rule_id] = (acc[l.rule_id] ?? 0) + 1
    return acc
  }, {})

  const displayedRules = rules.map(r => ({
    ...r,
    enabled: ruleEnabled[r.id] !== undefined ? ruleEnabled[r.id] : r.enabled,
    minSeverity: r.trigger?.min_severity ?? 0,
    eventType: r.trigger?.event_type || 'any',
    triggerTags: r.trigger?.tags ?? [],
    actionList: r.actions ?? [],
    executionsToday: execCountByRule[r.id] ?? 0,
  }))

  const stats = {
    active: displayedRules.filter(r => r.enabled).length,
    executionsToday: `${todayLogs.length}${logsTruncated ? '+' : ''}`,
    successRate: Math.round(logs.filter(l => l.status === 'success').length / Math.max(logs.length, 1) * 100),
    pendingRollbacks: pendingRollbacks.length,
  }

  const handleToggle = async (ruleId: string, current: boolean) => {
    const next = !current
    setRuleEnabled(prev => ({ ...prev, [ruleId]: next }))
    try {
      await apiFetch(`/api/v1/admin/remediation/rules/${ruleId}/enable`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: next }),
      })
    } catch {
      // Roll the optimistic update back — the server rejected the change.
      setRuleEnabled(prev => ({ ...prev, [ruleId]: current }))
    }
  }

  const handleCreateRule = async () => {
    setRuleError('')
    const tags = newRule.tags.split(',').map(t => t.trim()).filter(Boolean)
    try {
      await apiFetch('/api/v1/admin/remediation/rules', {
        method: 'POST',
        body: JSON.stringify({
          name: newRule.name,
          enabled: true,
          trigger: {
            event_type: newRule.event_type,
            min_severity: newRule.min_severity,
            tags,
          },
          actions: [{ type: newRule.action_type, params: {} }],
          cooldown_seconds: newRule.cooldown_seconds,
          rollback_timeout_seconds: newRule.rollback_timeout_seconds,
        }),
      })
    } catch (e: unknown) {
      setRuleError(e instanceof Error ? e.message : 'ルールの作成に失敗しました')
      return
    }
    setShowCreateRule(false)
    setNewRule({
      name: '', min_severity: 7, event_type: 'alert', action_type: 'isolate_network',
      tags: '', cooldown_seconds: 300, rollback_timeout_seconds: 0,
    })
    refetchRules()
  }

  const handleAddExclusion = async () => {
    setExclusionError('')
    if (!newExclusion.hostname_pattern.trim()) {
      setExclusionError('Hostname pattern is required')
      return
    }
    try {
      await apiFetch('/api/v1/admin/remediation/exclusions', {
        method: 'POST',
        body: JSON.stringify(newExclusion),
      })
      setShowAddExclusion(false)
      setNewExclusion({ hostname_pattern: '', reason: '' })
      refetchExclusions()
    } catch (e: unknown) {
      setExclusionError(e instanceof Error ? e.message : 'Failed to add exclusion')
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Zap className="w-7 h-7 text-yellow-400" />
            Auto-Remediation
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            Automated response rules and execution history
          </p>
        </div>
        <button
          onClick={() => { setShowCreateRule(v => !v); setRuleError('') }}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 hover:bg-yellow-500/20 text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          Create Rule
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Active Rules', value: stats.active, color: 'text-yellow-400' },
          { label: 'Executions Today', value: stats.executionsToday, color: 'text-blue-400' },
          { label: 'Success Rate', value: `${stats.successRate}%`, color: 'text-green-400' },
          {
            label: 'Pending Rollbacks',
            value: stats.pendingRollbacks,
            color: stats.pendingRollbacks > 0 ? 'text-orange-400' : 'text-zinc-500',
          },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-zinc-500 text-xs mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Create Rule Form */}
      {showCreateRule && (
        <div className="bg-zinc-900 border border-yellow-500/20 rounded-lg p-5 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-zinc-100 font-semibold flex items-center gap-2">
              <Plus className="w-4 h-4 text-yellow-400" />
              New Remediation Rule
            </h2>
            <button onClick={() => setShowCreateRule(false)} className="text-zinc-500 hover:text-zinc-300">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">Rule Name</label>
              <input
                value={newRule.name}
                onChange={e => setNewRule(f => ({ ...f, name: e.target.value }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-yellow-500/50"
                placeholder="My Remediation Rule"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">Event Type</label>
              <select
                value={newRule.event_type}
                onChange={e => setNewRule(f => ({ ...f, event_type: e.target.value }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-yellow-500/50"
              >
                {EVENT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">
                Tags <span className="text-zinc-600">(comma separated — matches if ANY tag matches; empty = all alerts)</span>
              </label>
              <input
                value={newRule.tags}
                onChange={e => setNewRule(f => ({ ...f, tags: e.target.value }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-yellow-500/50 font-mono"
                placeholder="ransomware, file_encryption"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">
                Auto-Rollback (seconds) <span className="text-zinc-600">(0 = off; isolation only)</span>
              </label>
              <input
                type="number"
                value={newRule.rollback_timeout_seconds}
                onChange={e => setNewRule(f => ({ ...f, rollback_timeout_seconds: Number(e.target.value) }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-yellow-500/50"
                min={0}
              />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">
                Min Severity: <span className={`font-bold ${SEV_TEXT(newRule.min_severity)}`}>{newRule.min_severity}</span>
              </label>
              <input
                type="range"
                min={1}
                max={10}
                value={newRule.min_severity}
                onChange={e => setNewRule(f => ({ ...f, min_severity: Number(e.target.value) }))}
                className="w-full accent-yellow-400"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">Primary Action</label>
              <select
                value={newRule.action_type}
                onChange={e => setNewRule(f => ({ ...f, action_type: e.target.value }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-yellow-500/50"
              >
                {Object.entries(ACTION_CONFIG).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">Cooldown (seconds)</label>
              <input
                type="number"
                value={newRule.cooldown_seconds}
                onChange={e => setNewRule(f => ({ ...f, cooldown_seconds: Number(e.target.value) }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-yellow-500/50"
                min={60}
              />
            </div>
          </div>
          {ruleError && <p className="text-xs text-red-400 mb-3">{ruleError}</p>}
          <button
            onClick={handleCreateRule}
            disabled={!newRule.name}
            className="px-5 py-2 rounded bg-yellow-500 text-zinc-900 font-medium text-sm hover:bg-yellow-400 disabled:opacity-50 transition-colors"
          >
            Create Rule
          </button>
        </div>
      )}

      {/* Pending Rollbacks */}
      {pendingRollbacks.length > 0 && (
        <div className="mb-6">
          <h2 className="text-zinc-300 font-semibold mb-3 flex items-center gap-2">
            <RotateCcw className="w-4 h-4 text-orange-400" />
            Pending Auto-Rollbacks
            <span className="ml-1 px-1.5 py-0.5 rounded-full bg-orange-500/15 text-orange-400 text-[11px] font-semibold border border-orange-500/30">
              {pendingRollbacks.length}
            </span>
          </h2>
          <div className="space-y-2">
            {pendingRollbacks.map(rb => (
              <div
                key={rb.execution_id}
                className="flex items-center justify-between bg-zinc-900 border border-orange-500/20 rounded-lg px-4 py-3"
              >
                <div className="flex items-center gap-4">
                  <div className="w-2 h-2 rounded-full bg-orange-400 animate-pulse" />
                  <div>
                    <p className="text-sm text-zinc-200">
                      Agent <span className="font-mono text-zinc-400">{rb.agent_id}</span> is isolated
                    </p>
                    <p className="text-xs text-zinc-500 mt-0.5">
                      Scheduled rollback at {fmtDate(rb.scheduled_at)}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-zinc-500 font-mono">{rb.execution_id.slice(0, 8)}…</span>
                  <button
                    onClick={() => approveMutation.mutate(rb.execution_id)}
                    disabled={approveMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 text-xs font-medium transition-colors disabled:opacity-50"
                  >
                    <CheckSquare className="w-3.5 h-3.5" />
                    Approve (Keep Isolated)
                  </button>
                </div>
              </div>
            ))}
          </div>
          <p className="text-xs text-zinc-600 mt-2">
            Click &quot;Approve&quot; to keep the agent isolated. If no action is taken, the agent will be automatically un-isolated at the scheduled time.
          </p>
        </div>
      )}

      {/* Rules List */}
      <h2 className="text-zinc-300 font-semibold mb-3 flex items-center gap-2">
        <Zap className="w-4 h-4 text-yellow-400" />
        Remediation Rules
      </h2>
      <div className="grid grid-cols-2 gap-4 mb-6">
        {displayedRules.map(rule => (
          <div
            key={rule.id}
            className={`bg-zinc-900 border-l-4 rounded-lg p-4 ${SEV_COLOR(rule.minSeverity)} ${!rule.enabled ? 'opacity-60' : ''}`}
          >
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-zinc-100 font-semibold text-sm">{rule.name}</span>
                  {!rule.enabled && (
                    <span className="px-1.5 py-0.5 rounded bg-zinc-700 text-zinc-500 text-[10px]">Disabled</span>
                  )}
                  {rule.rollback_timeout && (
                    <span className="px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 text-[10px] border border-orange-500/30 flex items-center gap-0.5">
                      <RotateCcw className="w-2.5 h-2.5" />
                      Auto-rollback {rule.rollback_timeout}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs text-zinc-500">
                  <span>Trigger: <span className="text-zinc-400">{rule.eventType}</span></span>
                  <span className={`font-semibold ${SEV_TEXT(rule.minSeverity)}`}>Sev ≥ {rule.minSeverity}</span>
                </div>
                {rule.triggerTags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {rule.triggerTags.map(t => (
                      <span key={t} className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px] font-mono">
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <button
                onClick={() => handleToggle(rule.id, rule.enabled)}
                className={`flex-shrink-0 ml-2 transition-colors ${rule.enabled ? 'text-yellow-400' : 'text-zinc-600'}`}
              >
                {rule.enabled ? <ToggleRight className="w-6 h-6" /> : <ToggleLeft className="w-6 h-6" />}
              </button>
            </div>

            <div className="flex flex-wrap gap-1.5 mb-3">
              {rule.actionList.map((action, i) => {
                const cfg = actionConfig(action.type)
                return (
                  <span key={i} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-800 text-xs ${cfg.color}`}>
                    {cfg.icon}
                    {cfg.label}
                  </span>
                )
              })}
            </div>

            <div className="flex items-center justify-between text-xs text-zinc-600">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                Cooldown: {rule.cooldown || '—'}
              </span>
              <span className="flex items-center gap-1">
                <Activity className="w-3 h-3" />
                {rule.executionsToday} runs today
              </span>
            </div>
          </div>
        ))}
        {displayedRules.length === 0 && (
          <div className="col-span-2 text-center py-10 text-zinc-600 text-sm bg-zinc-900 border border-zinc-800 rounded-lg">
            No remediation rules configured
          </div>
        )}
      </div>

      {/* Exclusion List */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-zinc-300 font-semibold flex items-center gap-2">
            <ShieldOff className="w-4 h-4 text-zinc-500" />
            Exclusion List
            <span className="text-zinc-600 text-sm font-normal">— hosts exempt from auto-remediation</span>
          </h2>
          <button
            onClick={() => { setShowAddExclusion(v => !v); setExclusionError('') }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 text-xs font-medium transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Exclusion
          </button>
        </div>

        {/* Add Exclusion Form */}
        {showAddExclusion && (
          <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-4 mb-3">
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div>
                <label className="block text-xs text-zinc-500 mb-1.5">
                  Hostname Pattern <span className="text-zinc-600">(glob, e.g. dc-*, prod-db-*)</span>
                </label>
                <input
                  value={newExclusion.hostname_pattern}
                  onChange={e => setNewExclusion(f => ({ ...f, hostname_pattern: e.target.value }))}
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-zinc-500 font-mono"
                  placeholder="dc-* or prod-db-01"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1.5">Reason</label>
                <input
                  value={newExclusion.reason}
                  onChange={e => setNewExclusion(f => ({ ...f, reason: e.target.value }))}
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-zinc-500"
                  placeholder="Domain controller — manual response only"
                />
              </div>
            </div>
            {exclusionError && (
              <p className="text-xs text-red-400 mb-2">{exclusionError}</p>
            )}
            <div className="flex items-center gap-2">
              <button
                onClick={handleAddExclusion}
                disabled={!newExclusion.hostname_pattern.trim()}
                className="px-4 py-1.5 rounded bg-zinc-700 text-zinc-200 text-xs font-medium hover:bg-zinc-600 disabled:opacity-50 transition-colors"
              >
                Add
              </button>
              <button
                onClick={() => { setShowAddExclusion(false); setExclusionError('') }}
                className="px-4 py-1.5 rounded text-zinc-500 text-xs hover:text-zinc-300 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
          {exclusions.length === 0 ? (
            <div className="text-center py-8 text-zinc-600 text-sm">
              No exclusions configured — all hosts are subject to auto-remediation
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  {['Pattern', 'Reason', 'Added By', 'Added At', ''].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {exclusions.map(ex => (
                  <tr key={ex.id} className="border-b border-zinc-800/50 hover:bg-zinc-800/20 transition-colors">
                    <td className="px-4 py-3 font-mono text-zinc-200 text-sm">{ex.hostname_pattern}</td>
                    <td className="px-4 py-3 text-zinc-400 text-sm">{ex.reason || '—'}</td>
                    <td className="px-4 py-3 text-zinc-500 text-xs">{ex.created_by || 'system'}</td>
                    <td className="px-4 py-3 text-zinc-500 text-xs whitespace-nowrap">
                      {fmtDate(ex.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => deleteExclusionMutation.mutate(ex.id)}
                        disabled={deleteExclusionMutation.isPending}
                        className="text-zinc-600 hover:text-red-400 transition-colors disabled:opacity-50"
                        title="Remove exclusion"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Execution Logs */}
      <h2 className="text-zinc-300 font-semibold mb-3 flex items-center gap-2">
        <Activity className="w-4 h-4 text-zinc-500" />
        Execution Logs
      </h2>
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800">
                {['Rule Name', 'Trigger ID', 'Agent', 'Status', 'Actions', 'Time'].map(h => (
                  <th key={h} className="text-left px-5 py-3 text-xs font-semibold text-zinc-500 uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-zinc-600 text-sm">
                    No execution logs
                  </td>
                </tr>
              )}
              {logs.map((log, i) => {
                const isExpanded = expandedLog === log.id
                const cfg = logStatusConfig(log.status)
                const results = log.actions ?? []
                return (
                  <Fragment key={log.id}>
                    <tr
                      onClick={() => setExpandedLog(isExpanded ? null : log.id)}
                      className={`border-b border-zinc-800/50 hover:bg-zinc-800/30 cursor-pointer transition-colors ${i % 2 === 0 ? '' : 'bg-zinc-950/20'}`}
                    >
                      <td className="px-5 py-3 text-zinc-300 font-medium text-sm">{log.rule_name}</td>
                      <td className="px-5 py-3 font-mono text-zinc-500 text-xs">{log.trigger_id}</td>
                      <td className="px-5 py-3 text-zinc-400 text-sm">{log.agent_id || '—'}</td>
                      <td className="px-5 py-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium border ${cfg.className}`}>
                          {cfg.icon}
                          {cfg.label}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-zinc-400 text-sm">{results.length}</td>
                      <td className="px-5 py-3 text-zinc-500 text-xs whitespace-nowrap">
                        {fmtDate(log.executed_at)}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="border-b border-zinc-800/50 bg-zinc-950/50">
                        <td colSpan={6} className="px-5 py-4">
                          {results.length === 0 ? (
                            <p className="text-zinc-600 text-xs">
                              このログには個別アクションの記録がありません（DB 保存時はアクション明細を保持しません）。
                            </p>
                          ) : (
                            <div className="grid grid-cols-2 gap-3">
                              {results.map((ar, j) => {
                                const acfg = actionConfig(ar.action_type)
                                const scfg = logStatusConfig(ar.success ? 'success' : 'failed')
                                return (
                                  <div key={j} className={`flex items-start gap-3 p-3 rounded-lg border ${scfg.className} bg-zinc-900`}>
                                    <span className={acfg.color}>{acfg.icon}</span>
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center gap-2 mb-0.5">
                                        <span className={`text-xs font-semibold ${acfg.color}`}>{acfg.label}</span>
                                        <span className={`text-[10px] ${scfg.className.split(' ')[1]}`}>{scfg.label}</span>
                                      </div>
                                      <p className="text-zinc-400 text-xs">{ar.message}</p>
                                    </div>
                                  </div>
                                )
                              })}
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
