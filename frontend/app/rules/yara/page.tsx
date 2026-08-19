'use client'

// NOTE: Full YARA scanning requires cgo + the YARA C library (go-yara).
// The server provides pure-Go rule management only. Actual matching is
// deferred to a future agent build that links against libyara.

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield, Plus, Search, Filter,
  ToggleLeft, ToggleRight,
  Edit3, Trash2, X, AlertTriangle, CheckCircle
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

import { apiFetch } from '@/lib/api'

interface YARARule {
  id: string
  name: string
  description: string
  content: string
  tags: string[]
  enabled: boolean
  severity: 'low' | 'medium' | 'high' | 'critical'
  last_match_count: number
  last_matched_at?: string
  created_by?: string
  created_at: string
  updated_at: string
}

interface ListResponse {
  data: YARARule[]
  total: number
  limit: number
  offset: number
  has_more: boolean
}

const SEVERITY_COLORS: Record<string, string> = {
  low:      'text-green-400 bg-green-900/30',
  medium:   'text-yellow-400 bg-yellow-900/30',
  high:     'text-orange-400 bg-orange-900/30',
  critical: 'text-red-400 bg-red-900/30',
}

const SEVERITY_LABELS: Record<string, string> = {
  low:      '低',
  medium:   '中',
  high:     '高',
  critical: '緊急',
}

function fetchYARARules(params: { search?: string; severity?: string; enabled?: boolean }) {
  const q = new URLSearchParams()
  if (params.search)   q.set('search', params.search)
  if (params.severity) q.set('severity', params.severity)
  if (params.enabled !== undefined) q.set('enabled', String(params.enabled))
  q.set('limit', '100')
  return apiFetch<ListResponse>(`/api/v1/yara-rules?${q}`)
}

function createYARARule(body: Partial<YARARule>) {
  return apiFetch<YARARule>('/api/v1/yara-rules', {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

function updateYARARule(id: string, body: Partial<YARARule>) {
  return apiFetch<YARARule>(`/api/v1/yara-rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  })
}

function deleteYARARule(id: string) {
  return apiFetch(`/api/v1/yara-rules/${id}`, { method: 'DELETE' })
}

function toggleYARARule(id: string) {
  return apiFetch<YARARule>(`/api/v1/yara-rules/${id}/toggle`, { method: 'PATCH' })
}

const BLANK_FORM: Partial<YARARule> = {
  name: '',
  description: '',
  content: 'rule ExampleRule {\n  meta:\n    description = "Describe what this rule detects"\n  strings:\n    $a = "suspicious_string" nocase\n  condition:\n    $a\n}',
  tags: [],
  enabled: true,
  severity: 'medium',
}

export default function YARARulesPage() {
  const qc = useQueryClient()

  // Filters
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [enabledFilter, setEnabledFilter] = useState<boolean | undefined>(undefined)

  // Modal state
  const [showModal, setShowModal] = useState(false)
  const [editingRule, setEditingRule] = useState<YARARule | null>(null)
  const [form, setForm] = useState<Partial<YARARule>>(BLANK_FORM)
  const [tagsInput, setTagsInput] = useState('')
  const [contentWarning, setContentWarning] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['yara-rules', search, severityFilter, enabledFilter],
    queryFn: () => fetchYARARules({
      search: search || undefined,
      severity: severityFilter || undefined,
      enabled: enabledFilter,
    }),
    refetchInterval: 30000,
  })

  const createMutation = useMutation({
    mutationFn: (body: Partial<YARARule>) => createYARARule(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['yara-rules'] })
      closeModal()
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<YARARule> }) => updateYARARule(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['yara-rules'] })
      closeModal()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteYARARule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) => toggleYARARule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })

  const rules = data?.data || []
  const total = data?.total || 0
  const enabledCount = rules.filter(r => r.enabled).length

  function openCreate() {
    setEditingRule(null)
    setForm(BLANK_FORM)
    setTagsInput('')
    setContentWarning('')
    setShowModal(true)
  }

  function openEdit(rule: YARARule) {
    setEditingRule(rule)
    setForm({
      name:        rule.name,
      description: rule.description,
      content:     rule.content,
      tags:        rule.tags,
      enabled:     rule.enabled,
      severity:    rule.severity,
    })
    setTagsInput(rule.tags.join(', '))
    setContentWarning('')
    setShowModal(true)
  }

  function closeModal() {
    setShowModal(false)
    setEditingRule(null)
    setForm(BLANK_FORM)
    setTagsInput('')
    setContentWarning('')
  }

  function handleContentChange(val: string) {
    setForm(f => ({ ...f, content: val }))
    // Client-side syntax hint: warn if the content doesn't start with the `rule ` keyword
    const trimmed = val.trim()
    if (trimmed && !trimmed.startsWith('rule ')) {
      setContentWarning('YARA ルールは "rule <名前> { ... }" の形式で記述してください')
    } else {
      setContentWarning('')
    }
  }

  function handleSubmit() {
    const tags = tagsInput
      .split(',')
      .map(t => t.trim())
      .filter(Boolean)

    const payload: Partial<YARARule> = { ...form, tags }

    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, body: payload })
    } else {
      createMutation.mutate(payload)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending
  const mutationError = createMutation.error || updateMutation.error

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-purple-400" />
            YARA ルール
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            {total} 件のルール（有効: {enabledCount} 件）
          </p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors text-sm"
        >
          <Plus className="w-4 h-4" />
          新規ルール
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {((['low', 'medium', 'high', 'critical'] as const)).map(sev => (
          <div key={sev} className="bg-[#111827] rounded-xl p-4">
            <div className={`text-2xl font-bold ${SEVERITY_COLORS[sev].split(' ')[0]}`}>
              {rules.filter(r => r.severity === sev).length}
            </div>
            <div className="text-[#8899aa] text-sm mt-1">{SEVERITY_LABELS[sev]}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#8899aa]" />
          <input
            type="text"
            placeholder="ルール名・説明を検索..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-[#111827] text-white pl-9 pr-4 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-purple-500 text-sm"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[#8899aa]" />
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-[#111827] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-purple-500"
          >
            <option value="">全深刻度</option>
            <option value="low">低</option>
            <option value="medium">中</option>
            <option value="high">高</option>
            <option value="critical">緊急</option>
          </select>
          <select
            value={enabledFilter === undefined ? '' : String(enabledFilter)}
            onChange={e => setEnabledFilter(e.target.value === '' ? undefined : e.target.value === 'true')}
            className="bg-[#111827] text-white px-3 py-2 rounded-lg border border-[#1e2d42] text-sm focus:outline-hidden focus:border-purple-500"
          >
            <option value="">全状態</option>
            <option value="true">有効</option>
            <option value="false">無効</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#111827] rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">ルール名</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">深刻度</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">タグ</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">マッチ数</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">最終マッチ</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">有効</th>
              <th className="text-left px-4 py-3 text-[#8899aa] text-sm font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              [...Array(5)].map((_, i) => (
                <tr key={i} className="border-b border-[#1e2d42]/50">
                  {[...Array(7)].map((_, j) => (
                    <td key={j} className="px-4 py-3">
                      <div className="h-4 bg-[#161f33] rounded-sm animate-pulse" />
                    </td>
                  ))}
                </tr>
              ))
            ) : rules.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-[#5a6a7a]">
                  YARAルールが見つかりません
                </td>
              </tr>
            ) : (
              rules.map(rule => (
                <tr key={rule.id} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors">
                  <td className="px-4 py-3">
                    <div className="text-white font-medium text-sm">{rule.name}</div>
                    {rule.description && (
                      <div className="text-[#5a6a7a] text-xs mt-0.5 truncate max-w-xs">{rule.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-bold px-2 py-1 rounded-sm ${SEVERITY_COLORS[rule.severity]}`}>
                      {SEVERITY_LABELS[rule.severity]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[160px]">
                      {rule.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="text-xs bg-[#161f33] text-[#8899aa] px-1.5 py-0.5 rounded-sm font-mono">
                          {tag}
                        </span>
                      ))}
                      {rule.tags.length > 3 && (
                        <span className="text-xs text-[#5a6a7a]">+{rule.tags.length - 3}</span>
                      )}
                      {rule.tags.length === 0 && (
                        <span className="text-xs text-[#5a6a7a]">—</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-[#8899aa] text-sm">
                    {rule.last_match_count > 0
                      ? <span className="text-purple-400 font-medium">{rule.last_match_count}</span>
                      : <span className="text-[#5a6a7a]">0</span>
                    }
                  </td>
                  <td className="px-4 py-3 text-[#5a6a7a] text-xs">
                    {rule.last_matched_at
                      ? new Date(rule.last_matched_at).toLocaleString('ja-JP')
                      : '—'
                    }
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleMutation.mutate(rule.id)}
                      disabled={toggleMutation.isPending}
                      className="text-[#8899aa] hover:text-white transition-colors disabled:opacity-50"
                    >
                      {rule.enabled
                        ? <ToggleRight className="w-6 h-6 text-green-400" />
                        : <ToggleLeft className="w-6 h-6 text-[#5a6a7a]" />
                      }
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => openEdit(rule)}
                        className="text-[#8899aa] hover:text-purple-400 transition-colors"
                        title="編集"
                      >
                        <Edit3 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => {
                          if (confirm(`ルール「${rule.name}」を削除しますか？`)) {
                            deleteMutation.mutate(rule.id)
                          }
                        }}
                        className="text-[#8899aa] hover:text-red-400 transition-colors"
                        title="削除"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Create / Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#111827] rounded-2xl w-full max-w-2xl border border-[#1e2d42] flex flex-col max-h-[90vh]">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-[#1e2d42] shrink-0">
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-purple-400" />
                {editingRule ? 'YARAルールを編集' : '新規YARAルール'}
              </h2>
              <button
                onClick={closeModal}
                className="text-[#8899aa] hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="overflow-y-auto p-6 space-y-4 flex-1">
              {/* Name */}
              <div>
                <label className="text-[#8899aa] text-sm block mb-1">
                  ルール名 <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={form.name || ''}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="例: DetectMimikatz"
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-purple-500 text-sm"
                />
              </div>

              {/* Description */}
              <div>
                <label className="text-[#8899aa] text-sm block mb-1">説明</label>
                <input
                  type="text"
                  value={form.description || ''}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="このルールが検知する内容..."
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-purple-500 text-sm"
                />
              </div>

              {/* Severity + Enabled row */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[#8899aa] text-sm block mb-1">深刻度</label>
                  <select
                    value={form.severity || 'medium'}
                    onChange={e => setForm(f => ({ ...f, severity: e.target.value as YARARule['severity'] }))}
                    className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-purple-500 text-sm"
                  >
                    <option value="low">低 (Low)</option>
                    <option value="medium">中 (Medium)</option>
                    <option value="high">高 (High)</option>
                    <option value="critical">緊急 (Critical)</option>
                  </select>
                </div>
                <div className="flex items-end pb-1">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={form.enabled ?? true}
                      onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))}
                      className="w-4 h-4 rounded-sm border-[#1e2d42] bg-[#161f33] accent-purple-500"
                    />
                    <span className="text-[#8899aa] text-sm">有効にする</span>
                  </label>
                </div>
              </div>

              {/* Tags */}
              <div>
                <label className="text-[#8899aa] text-sm block mb-1">
                  タグ <span className="text-[#5a6a7a] text-xs">（カンマ区切り）</span>
                </label>
                <input
                  type="text"
                  value={tagsInput}
                  onChange={e => setTagsInput(e.target.value)}
                  placeholder="例: malware, ransomware, apt"
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-purple-500 text-sm"
                />
              </div>

              {/* YARA Content */}
              <div>
                <label className="text-[#8899aa] text-sm block mb-1">
                  YARAルール内容 <span className="text-red-400">*</span>
                </label>
                <textarea
                  value={form.content || ''}
                  onChange={e => handleContentChange(e.target.value)}
                  rows={12}
                  spellCheck={false}
                  className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42] focus:outline-hidden focus:border-purple-500 text-sm font-mono resize-y"
                  placeholder="rule RuleName {&#10;  meta:&#10;    description = &quot;&quot;&#10;  strings:&#10;    $a = &quot;string&quot;&#10;  condition:&#10;    $a&#10;}"
                />
                {contentWarning && (
                  <div className="flex items-start gap-2 mt-2 text-yellow-400 text-xs">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    <span>{contentWarning}</span>
                  </div>
                )}
                <p className="text-[#5a6a7a] text-xs mt-1">
                  注意: 実際のYARAスキャンにはエージェント側でlibyaraが必要です（現在はスタブ実装）。
                </p>
              </div>

              {/* Error */}
              {mutationError && (
                <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 px-3 py-2 rounded-lg">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>保存に失敗しました。再度お試しください。</span>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="flex gap-3 p-6 border-t border-[#1e2d42] shrink-0">
              <button
                onClick={handleSubmit}
                disabled={isPending || !form.name || !form.content}
                className="flex-1 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isPending ? (
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                ) : (
                  <CheckCircle className="w-4 h-4" />
                )}
                {editingRule ? '更新する' : '作成する'}
              </button>
              <button
                onClick={closeModal}
                className="px-4 py-2 bg-[#161f33] text-[#8899aa] rounded-lg hover:bg-[#1d2f4a] transition-colors"
              >
                キャンセル
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
