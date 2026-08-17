'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Bell, Plus, Pencil, Trash2, X, ToggleLeft, ToggleRight,
  ChevronDown, Minus, AlertTriangle,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────

type EventType = 'process_event' | 'network_connection' | 'file_event' | 'dns_query'
type Operator = 'equals' | 'not_equals' | 'contains' | 'starts_with' | 'ends_with' | 'regex' | 'greater_than' | 'less_than'

interface Condition {
  field: string
  operator: Operator
  value: string
}

interface CustomAlertRule {
  id: string
  name: string
  event_type: EventType
  conditions: Condition[]
  threshold: number
  time_window: number
  severity: number
  alert_title_template: string
  mitre_tags: string[]
  enabled: boolean
  created_at: string
  updated_at: string
}

interface ListResponse {
  rules: CustomAlertRule[]
  total: number
}

interface RuleFormState {
  name: string
  event_type: EventType
  conditions: Condition[]
  threshold: number
  time_window: number
  severity: number
  alert_title_template: string
  mitre_tags: string
}

// ── Constants ──────────────────────────────────────────────────

const EVENT_TYPE_FIELDS: Record<EventType, string[]> = {
  process_event: ['process_name', 'cmdline', 'user', 'parent_process', 'hash'],
  network_connection: ['dst_ip', 'dst_port', 'protocol', 'bytes_sent'],
  file_event: ['path', 'action', 'hash', 'size_bytes'],
  dns_query: ['domain', 'query_type', 'response_code'],
}

const OPERATORS: { value: Operator; label: string }[] = [
  { value: 'equals', label: '等しい' },
  { value: 'not_equals', label: '等しくない' },
  { value: 'contains', label: '含む' },
  { value: 'starts_with', label: '始まる' },
  { value: 'ends_with', label: '終わる' },
  { value: 'regex', label: '正規表現' },
  { value: 'greater_than', label: '大きい' },
  { value: 'less_than', label: '小さい' },
]

const EVENT_TYPE_LABELS: Record<EventType, string> = {
  process_event: 'プロセス',
  network_connection: 'ネットワーク',
  file_event: 'ファイル',
  dns_query: 'DNS',
}

const EVENT_TYPE_COLORS: Record<EventType, string> = {
  process_event: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  network_connection: 'bg-green-500/10 text-green-400 border-green-500/20',
  file_event: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  dns_query: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
}

const SEVERITY_LEVELS = [
  { min: 1, max: 3, label: 'Low', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20' },
  { min: 4, max: 6, label: 'Medium', color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  { min: 7, max: 8, label: 'High', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
  { min: 9, max: 10, label: 'Critical', color: 'text-falcon-red', bg: 'bg-falcon-red/10 border-falcon-red/20' },
]

function getSeverityLevel(severity: number) {
  return SEVERITY_LEVELS.find(l => severity >= l.min && severity <= l.max) ?? SEVERITY_LEVELS[0]
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

const defaultForm = (): RuleFormState => ({
  name: '',
  event_type: 'process_event',
  conditions: [{ field: 'process_name', operator: 'equals', value: '' }],
  threshold: 1,
  time_window: 60,
  severity: 5,
  alert_title_template: '',
  mitre_tags: '',
})

// ── Condition Row ──────────────────────────────────────────────

function ConditionRow({
  condition,
  index,
  fields,
  onChange,
  onRemove,
  canRemove,
}: {
  condition: Condition
  index: number
  fields: string[]
  onChange: (idx: number, c: Condition) => void
  onRemove: (idx: number) => void
  canRemove: boolean
}) {
  return (
    <div className="flex items-center gap-2 p-2 bg-[#070d19] rounded-sm border border-falcon-border">
      <span className="text-xs text-falcon-subtle w-4 text-center shrink-0">{index + 1}</span>

      {/* Field */}
      <div className="relative flex-1 min-w-0">
        <select
          value={condition.field}
          onChange={e => onChange(index, { ...condition, field: e.target.value })}
          className="w-full bg-falcon-surface border border-falcon-border rounded px-2 py-1.5
                     text-xs text-falcon-text appearance-none pr-6
                     focus:outline-hidden focus:border-falcon-red/50"
        >
          {fields.map(f => (
            <option key={f} value={f}>{f}</option>
          ))}
        </select>
        <ChevronDown className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 text-falcon-subtle pointer-events-none" />
      </div>

      {/* Operator */}
      <div className="relative w-28 shrink-0">
        <select
          value={condition.operator}
          onChange={e => onChange(index, { ...condition, operator: e.target.value as Operator })}
          className="w-full bg-falcon-surface border border-falcon-border rounded px-2 py-1.5
                     text-xs text-falcon-text appearance-none pr-6
                     focus:outline-hidden focus:border-falcon-red/50"
        >
          {OPERATORS.map(op => (
            <option key={op.value} value={op.value}>{op.label}</option>
          ))}
        </select>
        <ChevronDown className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 text-falcon-subtle pointer-events-none" />
      </div>

      {/* Value */}
      <input
        type="text"
        value={condition.value}
        onChange={e => onChange(index, { ...condition, value: e.target.value })}
        placeholder="値を入力..."
        className="flex-1 min-w-0 bg-falcon-surface border border-falcon-border rounded px-2 py-1.5
                   text-xs text-falcon-text placeholder-falcon-subtle
                   focus:outline-hidden focus:border-falcon-red/50"
      />

      {/* Remove */}
      <button
        onClick={() => onRemove(index)}
        disabled={!canRemove}
        className="p-1 rounded text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10
                   disabled:opacity-30 disabled:cursor-not-allowed transition-colors shrink-0"
        title="条件を削除"
      >
        <Minus className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

// ── Modal ──────────────────────────────────────────────────────

function RuleModal({
  initial,
  onClose,
  onSave,
  isSaving,
}: {
  initial: RuleFormState
  onClose: () => void
  onSave: (form: RuleFormState) => void
  isSaving: boolean
}) {
  const [form, setForm] = useState<RuleFormState>(initial)
  const sevLevel = getSeverityLevel(form.severity)

  const fields = EVENT_TYPE_FIELDS[form.event_type]

  const handleEventTypeChange = (et: EventType) => {
    const newFields = EVENT_TYPE_FIELDS[et]
    setForm(f => ({
      ...f,
      event_type: et,
      conditions: f.conditions.map(c => ({
        ...c,
        field: newFields.includes(c.field) ? c.field : newFields[0],
      })),
    }))
  }

  const handleConditionChange = useCallback((idx: number, c: Condition) => {
    setForm(f => {
      const conditions = [...f.conditions]
      conditions[idx] = c
      return { ...f, conditions }
    })
  }, [])

  const handleConditionRemove = useCallback((idx: number) => {
    setForm(f => ({ ...f, conditions: f.conditions.filter((_, i) => i !== idx) }))
  }, [])

  const handleAddCondition = () => {
    setForm(f => ({
      ...f,
      conditions: [...f.conditions, { field: fields[0], operator: 'equals', value: '' }],
    }))
  }

  const valid = form.name.trim() !== '' && form.alert_title_template.trim() !== '' &&
    form.conditions.every(c => c.value.trim() !== '')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]">
        {/* Modal header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border shrink-0">
          <div className="flex items-center gap-2">
            <Bell className="w-4 h-4 text-falcon-red" />
            <h2 className="text-base font-semibold text-white">
              {initial.name ? 'ルールを編集' : '新規カスタムアラートルール'}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal body */}
        <div className="overflow-y-auto flex-1 px-5 py-4 space-y-5">

          {/* Rule Name */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted uppercase tracking-wider mb-1.5">
              ルール名 <span className="text-falcon-red">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: Suspicious PowerShell Execution"
              className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2
                         text-sm text-falcon-text placeholder-falcon-subtle
                         focus:outline-hidden focus:border-falcon-red/50"
            />
          </div>

          {/* Event Type */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted uppercase tracking-wider mb-1.5">
              イベントタイプ
            </label>
            <div className="grid grid-cols-4 gap-2">
              {(Object.entries(EVENT_TYPE_LABELS) as [EventType, string][]).map(([et, label]) => (
                <button
                  key={et}
                  onClick={() => handleEventTypeChange(et)}
                  className={`px-3 py-2 rounded text-xs font-medium border transition-all ${
                    form.event_type === et
                      ? 'bg-falcon-red/15 border-falcon-red/40 text-falcon-red'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/30 hover:text-falcon-text'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Conditions */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-falcon-muted uppercase tracking-wider">
                条件 ({form.conditions.length})
              </label>
              <button
                onClick={handleAddCondition}
                className="flex items-center gap-1 px-2 py-1 rounded text-xs
                           bg-falcon-border hover:bg-falcon-red/10 text-falcon-muted hover:text-falcon-red
                           border border-falcon-border hover:border-falcon-red/30 transition-all"
              >
                <Plus className="w-3 h-3" />
                条件を追加
              </button>
            </div>
            <div className="space-y-2">
              {form.conditions.map((c, i) => (
                <ConditionRow
                  key={i}
                  condition={c}
                  index={i}
                  fields={fields}
                  onChange={handleConditionChange}
                  onRemove={handleConditionRemove}
                  canRemove={form.conditions.length > 1}
                />
              ))}
            </div>
            <p className="text-xs text-falcon-subtle mt-1.5">
              全条件が AND で評価されます
            </p>
          </div>

          {/* Threshold + Time Window */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-falcon-muted uppercase tracking-wider mb-1.5">
                しきい値 (件数)
              </label>
              <input
                type="number"
                min={1}
                value={form.threshold}
                onChange={e => setForm(f => ({ ...f, threshold: Math.max(1, Number(e.target.value)) }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2
                           text-sm text-falcon-text
                           focus:outline-hidden focus:border-falcon-red/50"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-falcon-muted uppercase tracking-wider mb-1.5">
                タイムウィンドウ (秒)
              </label>
              <input
                type="number"
                min={1}
                value={form.time_window}
                onChange={e => setForm(f => ({ ...f, time_window: Math.max(1, Number(e.target.value)) }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2
                           text-sm text-falcon-text
                           focus:outline-hidden focus:border-falcon-red/50"
              />
              <p className="text-xs text-falcon-subtle mt-1">
                {form.time_window >= 3600
                  ? `${(form.time_window / 3600).toFixed(1)}時間`
                  : form.time_window >= 60
                  ? `${(form.time_window / 60).toFixed(1)}分`
                  : `${form.time_window}秒`}
              </p>
            </div>
          </div>

          {/* Severity Slider */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-medium text-falcon-muted uppercase tracking-wider">
                重大度
              </label>
              <span className={`text-xs font-bold px-2 py-0.5 rounded-sm border ${sevLevel.bg} ${sevLevel.color}`}>
                {form.severity} — {sevLevel.label}
              </span>
            </div>
            <input
              type="range"
              min={1}
              max={10}
              step={1}
              value={form.severity}
              onChange={e => setForm(f => ({ ...f, severity: Number(e.target.value) }))}
              className="w-full h-2 rounded-lg appearance-none cursor-pointer
                         bg-linear-to-r from-green-500 via-yellow-500 via-orange-500 to-falcon-red"
            />
            <div className="flex justify-between text-[10px] text-falcon-subtle mt-1">
              <span>1 Low</span>
              <span>4 Medium</span>
              <span>7 High</span>
              <span>9 Critical</span>
            </div>
          </div>

          {/* Alert Title Template */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted uppercase tracking-wider mb-1.5">
              アラートタイトルテンプレート <span className="text-falcon-red">*</span>
            </label>
            <input
              type="text"
              value={form.alert_title_template}
              onChange={e => setForm(f => ({ ...f, alert_title_template: e.target.value }))}
              placeholder="例: Suspicious PowerShell on {{agent_hostname}}"
              className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2
                         text-sm text-falcon-text placeholder-falcon-subtle font-mono
                         focus:outline-hidden focus:border-falcon-red/50"
            />
            <p className="text-xs text-falcon-subtle mt-1">
              {'{{agent_hostname}}, {{process_name}} などの変数が使用できます'}
            </p>
          </div>

          {/* MITRE Tags */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted uppercase tracking-wider mb-1.5">
              MITREタグ (カンマ区切り)
            </label>
            <input
              type="text"
              value={form.mitre_tags}
              onChange={e => setForm(f => ({ ...f, mitre_tags: e.target.value }))}
              placeholder="例: T1059.001, T1569.002"
              className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2
                         text-sm text-falcon-text placeholder-falcon-subtle font-mono
                         focus:outline-hidden focus:border-falcon-red/50"
            />
          </div>
        </div>

        {/* Modal footer */}
        <div className="flex items-center justify-end gap-3 px-5 py-4 border-t border-falcon-border shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-falcon-muted hover:text-white rounded
                       border border-falcon-border hover:border-falcon-muted/40 transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={!valid || isSaving}
            className="px-5 py-2 text-sm bg-falcon-red hover:bg-[#c8001f] text-white rounded
                       font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSaving ? '保存中...' : '保存'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Page ───────────────────────────────────────────────────────

export default function CustomAlertRulesPage() {
  const queryClient = useQueryClient()
  const [modalMode, setModalMode] = useState<null | 'create' | 'edit'>(null)
  const [editTarget, setEditTarget] = useState<CustomAlertRule | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<CustomAlertRule | null>(null)

  const { data, isLoading, isError } = useQuery<ListResponse>({
    queryKey: ['custom-alert-rules'],
    queryFn: () => apiFetch('/api/v1/admin/custom-alert-rules'),
  })

  const rules = data?.rules ?? []
  const total = data?.total ?? 0

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/admin/custom-alert-rules', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-alert-rules'] })
      setModalMode(null)
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/admin/custom-alert-rules/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-alert-rules'] })
      setModalMode(null)
      setEditTarget(null)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/custom-alert-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-alert-rules'] })
      setDeleteConfirm(null)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/custom-alert-rules/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-alert-rules'] })
    },
  })

  const handleSave = (form: RuleFormState) => {
    const body = {
      name: form.name,
      event_type: form.event_type,
      conditions: form.conditions,
      threshold: form.threshold,
      time_window: form.time_window,
      severity: form.severity,
      alert_title_template: form.alert_title_template,
      mitre_tags: form.mitre_tags
        .split(',')
        .map(t => t.trim())
        .filter(Boolean),
    }
    if (modalMode === 'create') {
      createMutation.mutate(body)
    } else if (editTarget) {
      updateMutation.mutate({ id: editTarget.id, body })
    }
  }

  const openEdit = (rule: CustomAlertRule) => {
    setEditTarget(rule)
    setModalMode('edit')
  }

  const initialForm = (): RuleFormState => {
    if (modalMode === 'edit' && editTarget) {
      return {
        name: editTarget.name,
        event_type: editTarget.event_type,
        conditions: editTarget.conditions,
        threshold: editTarget.threshold,
        time_window: editTarget.time_window,
        severity: editTarget.severity,
        alert_title_template: editTarget.alert_title_template,
        mitre_tags: editTarget.mitre_tags.join(', '),
      }
    }
    return defaultForm()
  }

  const isSaving = createMutation.isPending || updateMutation.isPending

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
              <Bell className="w-4 h-4 text-falcon-red" />
            </div>
            <h1 className="text-xl font-bold text-white">カスタムアラートルール</h1>
          </div>
          <p className="text-falcon-muted text-sm ml-11">
            イベントパターンに基づいたカスタムアラートルールの管理
          </p>
        </div>
        <button
          onClick={() => { setEditTarget(null); setModalMode('create') }}
          className="flex items-center gap-2 px-4 py-2 rounded bg-falcon-red hover:bg-[#c8001f]
                     text-white text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          新規ルール作成
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <p className="text-falcon-muted text-xs mb-1">総ルール数</p>
          <p className="text-2xl font-bold text-white">{total}</p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <p className="text-falcon-muted text-xs mb-1">有効</p>
          <p className="text-2xl font-bold text-green-400">
            {rules.filter(r => r.enabled).length}
          </p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <p className="text-falcon-muted text-xs mb-1">Critical</p>
          <p className="text-2xl font-bold text-falcon-red">
            {rules.filter(r => r.severity >= 9).length}
          </p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <p className="text-falcon-muted text-xs mb-1">無効</p>
          <p className="text-2xl font-bold text-falcon-muted">
            {rules.filter(r => !r.enabled).length}
          </p>
        </div>
      </div>

      {/* Table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-falcon-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">ルール一覧</h2>
          <span className="text-xs text-falcon-muted">{total} 件</span>
        </div>

        {isLoading ? (
          <div className="p-8 text-center">
            <div className="space-y-3 max-w-full">
              {[1, 2, 3, 4].map(i => (
                <div key={i} className="h-12 bg-[#0a1628] rounded-sm animate-pulse" />
              ))}
            </div>
          </div>
        ) : isError ? (
          <div className="p-8 text-center">
            <AlertTriangle className="w-8 h-8 text-falcon-red mx-auto mb-2" />
            <p className="text-sm text-falcon-muted">データの読み込みに失敗しました</p>
          </div>
        ) : rules.length === 0 ? (
          <div className="p-12 text-center">
            <Bell className="w-10 h-10 text-falcon-border mx-auto mb-3" />
            <p className="text-sm font-medium text-falcon-muted mb-1">ルールがありません</p>
            <p className="text-xs text-falcon-subtle">「新規ルール作成」ボタンからルールを追加してください</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ルール名', 'イベントタイプ', '条件数', 'しきい値', 'タイムウィンドウ', '重大度', '状態', '更新日時', '操作'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {rules.map(rule => {
                  const sevLevel = getSeverityLevel(rule.severity)
                  return (
                    <tr key={rule.id} className="hover:bg-[#0a1628] transition-colors">
                      {/* Name */}
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-sm font-medium text-falcon-text">{rule.name}</span>
                          {rule.mitre_tags.length > 0 && (
                            <div className="flex gap-1 flex-wrap">
                              {rule.mitre_tags.slice(0, 3).map(tag => (
                                <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded-sm bg-purple-500/10 text-purple-400 border border-purple-500/20 font-mono">
                                  {tag}
                                </span>
                              ))}
                              {rule.mitre_tags.length > 3 && (
                                <span className="text-[10px] text-falcon-subtle">+{rule.mitre_tags.length - 3}</span>
                              )}
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Event Type */}
                      <td className="px-4 py-3">
                        <span className={`inline-block px-2 py-0.5 rounded-sm text-xs font-medium border ${EVENT_TYPE_COLORS[rule.event_type]}`}>
                          {EVENT_TYPE_LABELS[rule.event_type]}
                        </span>
                      </td>

                      {/* Conditions Count */}
                      <td className="px-4 py-3">
                        <span className="text-sm font-bold text-white">{rule.conditions.length}</span>
                      </td>

                      {/* Threshold */}
                      <td className="px-4 py-3">
                        <span className="text-sm text-falcon-text font-mono">{rule.threshold}件</span>
                      </td>

                      {/* Time Window */}
                      <td className="px-4 py-3">
                        <span className="text-sm text-falcon-muted font-mono">
                          {rule.time_window >= 3600
                            ? `${(rule.time_window / 3600).toFixed(0)}h`
                            : rule.time_window >= 60
                            ? `${(rule.time_window / 60).toFixed(0)}m`
                            : `${rule.time_window}s`}
                        </span>
                      </td>

                      {/* Severity */}
                      <td className="px-4 py-3">
                        <span className={`inline-block px-2 py-0.5 rounded-sm text-xs font-bold border ${sevLevel.bg} ${sevLevel.color}`}>
                          {rule.severity} {sevLevel.label}
                        </span>
                      </td>

                      {/* Enabled Toggle */}
                      <td className="px-4 py-3">
                        <button
                          onClick={() => toggleMutation.mutate(rule.id)}
                          disabled={toggleMutation.isPending}
                          className="flex items-center gap-1.5 text-xs transition-colors disabled:opacity-50"
                          title={rule.enabled ? '無効にする' : '有効にする'}
                        >
                          {rule.enabled ? (
                            <>
                              <ToggleRight className="w-5 h-5 text-green-400" />
                              <span className="text-green-400 font-medium">有効</span>
                            </>
                          ) : (
                            <>
                              <ToggleLeft className="w-5 h-5 text-falcon-subtle" />
                              <span className="text-falcon-subtle">無効</span>
                            </>
                          )}
                        </button>
                      </td>

                      {/* Updated At */}
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">
                        {formatDate(rule.updated_at)}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => openEdit(rule)}
                            className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
                            title="編集"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setDeleteConfirm(rule)}
                            className="p-1.5 rounded-sm text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10 transition-colors"
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

      {/* Create / Edit Modal */}
      {modalMode && (
        <RuleModal
          initial={initialForm()}
          onClose={() => { setModalMode(null); setEditTarget(null) }}
          onSave={handleSave}
          isSaving={isSaving}
        />
      )}

      {/* Delete Confirm Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-falcon-red" />
              <h2 className="text-base font-semibold text-white">ルールを削除しますか？</h2>
            </div>
            <p className="text-sm text-falcon-muted mb-1">
              <span className="font-medium text-falcon-text">"{deleteConfirm.name}"</span> を削除します。
            </p>
            <p className="text-xs text-falcon-subtle mb-5">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-falcon-muted hover:text-white rounded
                           border border-falcon-border transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm.id)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c8001f] text-white rounded
                           font-medium transition-colors disabled:opacity-50"
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
