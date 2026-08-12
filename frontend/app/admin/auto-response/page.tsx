'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Zap, Plus, Pencil, Trash2, X, ToggleLeft, ToggleRight,
  ChevronRight, Clock, PlayCircle, History, AlertCircle, CheckCircle2,
  XCircle, FlaskConical,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────

type ActionType = 'isolate_host' | 'kill_process' | 'block_ip' | 'create_ticket' | 'notify_channel'

interface AutoResponseRule {
  id: string
  name: string
  description?: string
  trigger_severity_min: number
  trigger_title_pattern?: string
  action_type: ActionType
  action_params: Record<string, string>
  cooldown_seconds: number
  execution_count: number
  enabled: boolean
  created_at: string
  updated_at: string
}

interface RulesResponse {
  rules: AutoResponseRule[]
}

interface Execution {
  id: string
  rule_id: string
  triggered_at: string
  status: 'success' | 'failure' | 'dry_run'
  result?: string
  alert_id?: string
}

interface ExecutionsResponse {
  executions: Execution[]
}

interface TestResult {
  dry_run: boolean
  would_trigger: boolean
  message: string
}

// ── Constants ────────────────────────────────────────────────────────────────

const ACTION_TYPE_OPTIONS: { value: ActionType; label: string }[] = [
  { value: 'isolate_host',   label: 'ホスト隔離 (Isolate Host)' },
  { value: 'kill_process',   label: 'プロセス終了 (Kill Process)' },
  { value: 'block_ip',       label: 'IPブロック (Block IP)' },
  { value: 'create_ticket',  label: 'チケット作成 (Create Ticket)' },
  { value: 'notify_channel', label: 'チャンネル通知 (Notify Channel)' },
]

const ACTION_BADGE: Record<ActionType, { bg: string; text: string; label: string }> = {
  isolate_host:   { bg: 'bg-red-500/20',    text: 'text-red-400',    label: 'Isolate Host' },
  kill_process:   { bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'Kill Process' },
  block_ip:       { bg: 'bg-yellow-500/20', text: 'text-yellow-400', label: 'Block IP' },
  create_ticket:  { bg: 'bg-blue-500/20',   text: 'text-blue-400',   label: 'Create Ticket' },
  notify_channel: { bg: 'bg-green-500/20',  text: 'text-green-400',  label: 'Notify Channel' },
}

const emptyForm = {
  name: '',
  description: '',
  trigger_severity_min: 5,
  trigger_title_pattern: '',
  action_type: 'isolate_host' as ActionType,
  action_params: {} as Record<string, string>,
  cooldown_seconds: 3600,
  enabled: true,
}

type FormState = typeof emptyForm

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityLabel(n: number) {
  if (n >= 9) return { label: 'Critical', color: 'text-red-400' }
  if (n >= 7) return { label: 'High',     color: 'text-orange-400' }
  if (n >= 5) return { label: 'Medium',   color: 'text-yellow-400' }
  if (n >= 3) return { label: 'Low',      color: 'text-blue-400' }
  return { label: 'Info', color: 'text-[#7d92b0]' }
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { dateStyle: 'short', timeStyle: 'short' })
}

function fmtCooldown(secs: number) {
  if (secs >= 3600) return `${secs / 3600}h`
  if (secs >= 60)   return `${secs / 60}m`
  return `${secs}s`
}

// ── Action Params Sub-form ────────────────────────────────────────────────────

function ActionParamsFields({
  actionType,
  params,
  onChange,
}: {
  actionType: ActionType
  params: Record<string, string>
  onChange: (params: Record<string, string>) => void
}) {
  const set = (key: string, value: string) => onChange({ ...params, [key]: value })

  switch (actionType) {
    case 'isolate_host':
      return (
        <p className="text-xs text-[#7d92b0] italic px-3 py-2 bg-[#070d19] rounded border border-[#1e2d42]">
          追加パラメーターは不要です。アラートのホストを自動的に隔離します。
        </p>
      )
    case 'kill_process':
      return (
        <div>
          <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
            プロセス名 <span className="text-[#e8002d]">*</span>
          </label>
          <input
            type="text"
            value={params.process_name ?? ''}
            onChange={e => set('process_name', e.target.value)}
            placeholder="malware.exe"
            className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
          />
        </div>
      )
    case 'block_ip':
      return (
        <div>
          <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
            IPアドレス <span className="text-[#e8002d]">*</span>
          </label>
          <input
            type="text"
            value={params.ip_address ?? ''}
            onChange={e => set('ip_address', e.target.value)}
            placeholder="192.168.1.100"
            className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
          />
        </div>
      )
    case 'create_ticket':
      return (
        <div>
          <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
            キュー / プロジェクト <span className="text-[#e8002d]">*</span>
          </label>
          <input
            type="text"
            value={params.queue ?? ''}
            onChange={e => set('queue', e.target.value)}
            placeholder="SOC-QUEUE"
            className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
          />
        </div>
      )
    case 'notify_channel':
      return (
        <div>
          <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
            チャンネルID <span className="text-[#e8002d]">*</span>
          </label>
          <input
            type="text"
            value={params.channel_id ?? ''}
            onChange={e => set('channel_id', e.target.value)}
            placeholder="#soc-alerts"
            className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
          />
        </div>
      )
  }
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AutoResponsePage() {
  const queryClient = useQueryClient()

  const [modalOpen,      setModalOpen]      = useState(false)
  const [editingRule,    setEditingRule]     = useState<AutoResponseRule | null>(null)
  const [form,           setForm]            = useState<FormState>(emptyForm)
  const [formError,      setFormError]       = useState('')
  const [deleteConfirm,  setDeleteConfirm]   = useState<string | null>(null)
  const [historyRuleId,  setHistoryRuleId]   = useState<string | null>(null)
  const [testResult,     setTestResult]      = useState<TestResult | null>(null)
  const [testLoading,    setTestLoading]     = useState(false)

  // ── Queries ───────────────────────────────────────────────────────────────

  const { data, isLoading } = useQuery<RulesResponse>({
    queryKey: ['auto-response-rules'],
    queryFn: () => apiFetch('/api/v1/admin/auto-response'),
  })

  const { data: execData, isLoading: execLoading } = useQuery<ExecutionsResponse>({
    queryKey: ['auto-response-executions', historyRuleId],
    queryFn: () => apiFetch(`/api/v1/admin/auto-response/${historyRuleId}/executions`),
    enabled: !!historyRuleId,
  })

  const rules      = data?.rules ?? []
  const executions = execData?.executions ?? []
  const historyRule = rules.find(r => r.id === historyRuleId)

  // ── Mutations ─────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/admin/auto-response', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auto-response-rules'] })
      setModalOpen(false)
    },
    onError: () => setFormError('作成に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/admin/auto-response/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auto-response-rules'] })
      setModalOpen(false)
    },
    onError: () => setFormError('更新に失敗しました'),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/auto-response/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['auto-response-rules'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/auto-response/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auto-response-rules'] })
      setDeleteConfirm(null)
      if (historyRuleId === deleteConfirm) setHistoryRuleId(null)
    },
  })

  // ── Handlers ──────────────────────────────────────────────────────────────

  const openCreate = () => {
    setEditingRule(null)
    setForm(emptyForm)
    setFormError('')
    setTestResult(null)
    setModalOpen(true)
  }

  const openEdit = (rule: AutoResponseRule) => {
    setEditingRule(rule)
    setForm({
      name:                    rule.name,
      description:             rule.description ?? '',
      trigger_severity_min:    rule.trigger_severity_min,
      trigger_title_pattern:   rule.trigger_title_pattern ?? '',
      action_type:             rule.action_type,
      action_params:           { ...rule.action_params },
      cooldown_seconds:        rule.cooldown_seconds,
      enabled:                 rule.enabled,
    })
    setFormError('')
    setTestResult(null)
    setModalOpen(true)
  }

  const handleSubmit = () => {
    if (!form.name.trim()) {
      setFormError('ルール名は必須です')
      return
    }
    const body = {
      name:                  form.name.trim(),
      description:           form.description.trim() || undefined,
      trigger_severity_min:  form.trigger_severity_min,
      trigger_title_pattern: form.trigger_title_pattern.trim() || undefined,
      action_type:           form.action_type,
      action_params:         form.action_params,
      cooldown_seconds:      form.cooldown_seconds,
      enabled:               form.enabled,
    }
    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const handleTestRule = async () => {
    if (!editingRule) return
    setTestLoading(true)
    setTestResult(null)
    try {
      const result = await apiFetch<TestResult>(
        `/api/v1/admin/auto-response/${editingRule.id}/test`,
        { method: 'POST' }
      )
      setTestResult(result)
    } catch {
      setTestResult({ dry_run: true, would_trigger: false, message: 'テスト実行に失敗しました' })
    } finally {
      setTestLoading(false)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] p-6 flex gap-4">

      {/* ── Main Column ──────────────────────────────────────────────────── */}
      <div className={`flex-1 min-w-0 flex flex-col gap-4 ${historyRuleId ? 'max-w-[calc(100%-340px)]' : ''}`}>

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-8 h-8 rounded bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
                <Zap className="w-4 h-4 text-[#e8002d]" />
              </div>
              <h1 className="text-xl font-bold text-white">自動レスポンスルール</h1>
            </div>
            <p className="text-[#7d92b0] text-sm ml-11">
              アラートトリガーに基づく自動対応アクションを設定します
            </p>
          </div>
          <button
            onClick={openCreate}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded transition-colors"
          >
            <Plus className="w-4 h-4" />
            ルールを追加
          </button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: '合計ルール',     value: rules.length,                         color: 'text-white' },
            { label: '有効',           value: rules.filter(r => r.enabled).length,  color: 'text-green-400' },
            { label: '無効',           value: rules.filter(r => !r.enabled).length, color: 'text-[#7d92b0]' },
            { label: '総実行回数',     value: rules.reduce((s, r) => s + r.execution_count, 0), color: 'text-blue-400' },
          ].map(stat => (
            <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3">
              <p className="text-xs text-[#7d92b0] mb-1">{stat.label}</p>
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Table */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden flex-1">
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">ルール一覧</h2>
            <span className="text-xs text-[#7d92b0]">{rules.length} 件</span>
          </div>

          {isLoading ? (
            <div className="p-8 text-center text-[#7d92b0] text-sm">読み込み中...</div>
          ) : rules.length === 0 ? (
            <div className="p-8 text-center">
              <Zap className="w-8 h-8 text-[#1e2d42] mx-auto mb-3" />
              <p className="text-[#7d92b0] text-sm">ルールが登録されていません</p>
              <p className="text-[#3d5068] text-xs mt-1">「ルールを追加」ボタンから作成できます</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ルール名', 'トリガー条件', 'アクション', 'クールダウン', '実行回数', '有効', '操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {rules.map(rule => {
                    const sev    = severityLabel(rule.trigger_severity_min)
                    const badge  = ACTION_BADGE[rule.action_type]
                    const isOpen = historyRuleId === rule.id
                    return (
                      <tr
                        key={rule.id}
                        className={`transition-colors ${isOpen ? 'bg-[#0a1628]' : 'hover:bg-[#0a1628]'}`}
                      >
                        <td className="px-4 py-3">
                          <p className="text-sm font-medium text-white">{rule.name}</p>
                          {rule.description && (
                            <p className="text-xs text-[#7d92b0] mt-0.5 truncate max-w-[180px]">{rule.description}</p>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-1">
                            <span className={`text-xs font-medium ${sev.color}`}>
                              重大度 ≥ {rule.trigger_severity_min} ({sev.label})
                            </span>
                            {rule.trigger_title_pattern && (
                              <span className="text-xs text-[#7d92b0] font-mono truncate max-w-[140px]">
                                /{rule.trigger_title_pattern}/
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${badge.bg} ${badge.text}`}>
                            {badge.label}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="flex items-center gap-1 text-xs text-[#7d92b0]">
                            <Clock className="w-3 h-3" />
                            {fmtCooldown(rule.cooldown_seconds)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="flex items-center gap-1 text-xs text-[#7d92b0]">
                            <PlayCircle className="w-3 h-3" />
                            {(rule.execution_count ?? 0).toLocaleString()}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => toggleMutation.mutate(rule.id)}
                            disabled={toggleMutation.isPending}
                            title={rule.enabled ? '無効にする' : '有効にする'}
                          >
                            {rule.enabled ? (
                              <span className="flex items-center gap-1 text-xs text-green-400 hover:text-green-300">
                                <ToggleRight className="w-4 h-4" /> 有効
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white">
                                <ToggleLeft className="w-4 h-4" /> 無効
                              </span>
                            )}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => setHistoryRuleId(isOpen ? null : rule.id)}
                              className={`p-1.5 rounded transition-colors ${isOpen ? 'text-blue-400 bg-blue-500/10' : 'text-[#7d92b0] hover:text-blue-400 hover:bg-[#1e2d42]'}`}
                              title="実行履歴"
                            >
                              <History className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => openEdit(rule)}
                              className="p-1.5 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
                              title="編集"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => setDeleteConfirm(rule.id)}
                              className="p-1.5 rounded text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                              title="削除"
                            >
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
          )}
        </div>
      </div>

      {/* ── Execution History Side Panel ──────────────────────────────────── */}
      {historyRuleId && (
        <div className="w-[320px] flex-shrink-0 bg-[#0d1220] border border-[#1e2d42] rounded-lg flex flex-col">
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <div className="min-w-0">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <History className="w-4 h-4 text-blue-400 flex-shrink-0" />
                実行履歴
              </h3>
              {historyRule && (
                <p className="text-xs text-[#7d92b0] mt-0.5 truncate">{historyRule.name}</p>
              )}
            </div>
            <button
              onClick={() => setHistoryRuleId(null)}
              className="p-1 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors flex-shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {execLoading ? (
              <p className="text-xs text-[#7d92b0] text-center py-6">読み込み中...</p>
            ) : executions.length === 0 ? (
              <div className="text-center py-8">
                <History className="w-6 h-6 text-[#1e2d42] mx-auto mb-2" />
                <p className="text-xs text-[#7d92b0]">実行履歴がありません</p>
              </div>
            ) : (
              executions.slice(0, 20).map(exec => (
                <div key={exec.id} className="bg-[#070d19] border border-[#1e2d42] rounded p-3">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    {exec.status === 'success' ? (
                      <span className="flex items-center gap-1 text-xs text-green-400">
                        <CheckCircle2 className="w-3 h-3" /> 成功
                      </span>
                    ) : exec.status === 'dry_run' ? (
                      <span className="flex items-center gap-1 text-xs text-blue-400">
                        <FlaskConical className="w-3 h-3" /> ドライラン
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs text-red-400">
                        <XCircle className="w-3 h-3" /> 失敗
                      </span>
                    )}
                    <span className="text-[10px] text-[#3d5068]">{fmtDate(exec.triggered_at)}</span>
                  </div>
                  {exec.result && (
                    <p className="text-xs text-[#7d92b0] mt-1 break-words">{exec.result}</p>
                  )}
                  {exec.alert_id && (
                    <p className="text-[10px] text-[#3d5068] mt-1 font-mono">Alert: {exec.alert_id}</p>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ── Create / Edit Modal ───────────────────────────────────────────── */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42] flex-shrink-0">
              <h2 className="text-base font-semibold text-white">
                {editingRule ? 'ルールを編集' : '新規ルール作成'}
              </h2>
              <button
                onClick={() => setModalOpen(false)}
                className="p-1 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="px-5 py-4 space-y-4 overflow-y-auto flex-1">
              {/* Name */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  ルール名 <span className="text-[#e8002d]">*</span>
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="例: Critical Alert Auto-Isolate"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">説明（任意）</label>
                <textarea
                  rows={2}
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="ルールの目的や動作を記述..."
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 resize-none"
                />
              </div>

              {/* Trigger Section */}
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 space-y-3">
                <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider">トリガー条件</p>

                {/* Severity Slider */}
                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-2">
                    最小重大度:{' '}
                    <span className={`font-bold ${severityLabel(form.trigger_severity_min).color}`}>
                      {form.trigger_severity_min} ({severityLabel(form.trigger_severity_min).label})
                    </span>
                  </label>
                  <input
                    type="range"
                    min={1}
                    max={10}
                    value={form.trigger_severity_min}
                    onChange={e => setForm(f => ({ ...f, trigger_severity_min: Number(e.target.value) }))}
                    className="w-full accent-[#e8002d]"
                  />
                  <div className="flex justify-between text-[10px] text-[#3d5068] mt-1">
                    <span>1 (Info)</span>
                    <span>5 (Medium)</span>
                    <span>10 (Critical)</span>
                  </div>
                </div>

                {/* Title Pattern */}
                <div>
                  <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                    タイトルパターン（正規表現、任意）
                  </label>
                  <input
                    type="text"
                    value={form.trigger_title_pattern}
                    onChange={e => setForm(f => ({ ...f, trigger_title_pattern: e.target.value }))}
                    placeholder="例: ransomware|crypto|lateral"
                    className="w-full bg-[#0d1220] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50 font-mono"
                  />
                </div>
              </div>

              {/* Action Type */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  アクションタイプ <span className="text-[#e8002d]">*</span>
                </label>
                <select
                  value={form.action_type}
                  onChange={e => setForm(f => ({ ...f, action_type: e.target.value as ActionType, action_params: {} }))}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50"
                >
                  {ACTION_TYPE_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>

              {/* Action Params */}
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">アクションパラメーター</p>
                <ActionParamsFields
                  actionType={form.action_type}
                  params={form.action_params}
                  onChange={params => setForm(f => ({ ...f, action_params: params }))}
                />
              </div>

              {/* Cooldown */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  クールダウン（秒）
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min={60}
                    step={60}
                    value={form.cooldown_seconds}
                    onChange={e => setForm(f => ({ ...f, cooldown_seconds: Number(e.target.value) }))}
                    className="w-32 bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50"
                  />
                  <span className="text-xs text-[#7d92b0]">
                    = {fmtCooldown(form.cooldown_seconds)}
                  </span>
                </div>
              </div>

              {/* Enabled */}
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-[#7d92b0]">有効</label>
                <button
                  type="button"
                  onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    form.enabled ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
                  }`}
                >
                  <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-[#e2e8f4] transition-transform ${
                    form.enabled ? 'translate-x-4' : 'translate-x-1'
                  }`} />
                </button>
              </div>

              {/* Test Result */}
              {testResult && (
                <div className={`rounded-lg p-3 border text-sm ${
                  testResult.would_trigger
                    ? 'bg-green-500/10 border-green-500/30 text-green-400'
                    : 'bg-[#1e2d42]/50 border-[#1e2d42] text-[#7d92b0]'
                }`}>
                  <div className="flex items-center gap-2 font-medium mb-1">
                    {testResult.would_trigger
                      ? <CheckCircle2 className="w-4 h-4" />
                      : <AlertCircle className="w-4 h-4" />}
                    ドライラン結果
                  </div>
                  <p className="text-xs">{testResult.message}</p>
                </div>
              )}

              {formError && (
                <p className="text-xs text-[#e8002d]">{formError}</p>
              )}
            </div>

            <div className="px-5 py-4 border-t border-[#1e2d42] flex items-center justify-between flex-shrink-0">
              <div>
                {editingRule && (
                  <button
                    onClick={handleTestRule}
                    disabled={testLoading}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-blue-400 border border-blue-500/30 rounded hover:bg-blue-500/10 transition-colors disabled:opacity-50"
                  >
                    <FlaskConical className="w-3.5 h-3.5" />
                    {testLoading ? 'テスト中...' : 'テスト実行'}
                  </button>
                )}
              </div>
              <div className="flex gap-3">
                <button
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded border border-[#1e2d42] hover:border-[#7d92b0]/40 transition-colors"
                >
                  キャンセル
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={isPending}
                  className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded font-medium transition-colors disabled:opacity-50"
                >
                  {isPending ? '保存中...' : editingRule ? '更新' : '作成'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete Confirm Modal ──────────────────────────────────────────── */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-8 h-8 rounded-full bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center flex-shrink-0">
                <AlertCircle className="w-4 h-4 text-[#e8002d]" />
              </div>
              <h2 className="text-base font-semibold text-white">ルールを削除しますか？</h2>
            </div>
            <p className="text-sm text-[#7d92b0] mb-5">
              このルールと関連する実行履歴を削除します。この操作は取り消せません。
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded font-medium transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending ? '削除中...' : '削除'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
