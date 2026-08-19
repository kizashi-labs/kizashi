'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { GitMerge, Plus, Pencil, Trash2, Info, X, ToggleLeft, ToggleRight } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface AssignRule {
  id: string
  name: string
  priority: number
  conditions: { severity_match?: string[]; rule_id_match?: string[] }
  assignee_id: string
  enabled: boolean
  created_at: string
}

interface RulesResponse {
  rules: AssignRule[]
}

const SEVERITIES = ['critical', 'high', 'medium', 'low']

const emptyForm = {
  name: '',
  priority: 0,
  conditions: { severity_match: [] as string[], rule_id_match: '' },
  assignee_id: '',
  enabled: true,
}

type FormState = typeof emptyForm

export default function AssignRulesPage() {
  const queryClient = useQueryClient()
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<AssignRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [formError, setFormError] = useState('')

  const { data, isLoading } = useQuery<RulesResponse>({
    queryKey: ['assign-rules'],
    queryFn: () => apiFetch('/api/v1/alert-assign-rules'),
  })

  const rules = data?.rules ?? []

  const openCreate = () => {
    setEditingRule(null)
    setForm(emptyForm)
    setFormError('')
    setModalOpen(true)
  }

  const openEdit = (rule: AssignRule) => {
    setEditingRule(rule)
    setForm({
      name: rule.name,
      priority: rule.priority,
      conditions: {
        severity_match: rule.conditions.severity_match ?? [],
        rule_id_match: (rule.conditions.rule_id_match ?? []).join(', '),
      },
      assignee_id: rule.assignee_id,
      enabled: rule.enabled,
    })
    setFormError('')
    setModalOpen(true)
  }

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/alert-assign-rules', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assign-rules'] })
      setModalOpen(false)
    },
    onError: () => setFormError('作成に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/alert-assign-rules/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assign-rules'] })
      setModalOpen(false)
    },
    onError: () => setFormError('更新に失敗しました'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/alert-assign-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assign-rules'] })
      setDeleteConfirm(null)
    },
  })

  const handleSubmit = () => {
    if (!form.name.trim()) {
      setFormError('ルール名は必須です')
      return
    }
    const body = {
      name: form.name.trim(),
      priority: form.priority,
      conditions: {
        ...(form.conditions.severity_match.length > 0
          ? { severity_match: form.conditions.severity_match }
          : {}),
        ...(form.conditions.rule_id_match.trim()
          ? { rule_id_match: form.conditions.rule_id_match.split(',').map(s => s.trim()).filter(Boolean) }
          : {}),
      },
      assignee_id: form.assignee_id.trim(),
      enabled: form.enabled,
    }
    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const toggleSeverity = (sev: string) => {
    const current = form.conditions.severity_match
    setForm(f => ({
      ...f,
      conditions: {
        ...f.conditions,
        severity_match: current.includes(sev)
          ? current.filter(s => s !== sev)
          : [...current, sev],
      },
    }))
  }

  const severityColor: Record<string, string> = {
    critical: 'text-red-400 border-red-400/30 bg-red-400/10',
    high: 'text-orange-400 border-orange-400/30 bg-orange-400/10',
    medium: 'text-yellow-400 border-yellow-400/30 bg-yellow-400/10',
    low: 'text-blue-400 border-blue-400/30 bg-blue-400/10',
  }

  const isPending = createMutation.isPending || updateMutation.isPending

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
              <GitMerge className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h1 className="text-xl font-bold text-white">アラート自動割り当てルール</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">アラートの自動アサインルールを管理します</p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors"
        >
          <Plus className="w-4 h-4" />
          ルールを追加
        </button>
      </div>

      {/* Info card */}
      <div className="flex items-start gap-2 bg-blue-500/5 border border-blue-500/20 rounded-lg px-4 py-3 mb-6">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <p className="text-xs text-blue-300">条件が空の場合は全アラートに適用されます。優先度は数値が小さいほど高優先です（0が最高）。</p>
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">ルール一覧</h2>
          <span className="text-xs text-[#7d92b0]">{rules.length} 件</span>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-[#7d92b0] text-sm">読み込み中...</div>
        ) : rules.length === 0 ? (
          <div className="p-8 text-center text-[#7d92b0] text-sm">ルールが登録されていません</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">優先度</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">ルール名</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">条件</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">割り当て先</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">有効</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {[...rules].sort((a, b) => a.priority - b.priority).map(rule => (
                  <tr key={rule.id} className="hover:bg-[#0a1628] transition-colors">
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-[#1e2d42] text-xs font-bold text-white">
                        {rule.priority}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-medium text-white">{rule.name}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(rule.conditions.severity_match ?? []).map(sev => (
                          <span
                            key={sev}
                            className={`px-1.5 py-0.5 rounded-sm text-[10px] font-medium border ${severityColor[sev] ?? 'text-[#7d92b0] border-[#1e2d42] bg-[#1e2d42]'}`}
                          >
                            {sev}
                          </span>
                        ))}
                        {(rule.conditions.rule_id_match ?? []).map(rid => (
                          <span key={rid} className="px-1.5 py-0.5 rounded-sm text-[10px] font-medium border border-[#1e2d42] bg-[#1e2d42] text-[#7d92b0]">
                            {rid}
                          </span>
                        ))}
                        {!(rule.conditions.severity_match?.length) && !(rule.conditions.rule_id_match?.length) && (
                          <span className="text-xs text-[#7d92b0]">全アラート</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-[#7d92b0] max-w-[140px] truncate">
                      {rule.assignee_id || '—'}
                    </td>
                    <td className="px-4 py-3">
                      {rule.enabled ? (
                        <span className="flex items-center gap-1 text-xs text-green-400">
                          <ToggleRight className="w-4 h-4" /> 有効
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-xs text-[#7d92b0]">
                          <ToggleLeft className="w-4 h-4" /> 無効
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openEdit(rule)}
                          className="p-1.5 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
                          title="編集"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(rule.id)}
                          className="p-1.5 rounded-sm text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                          title="削除"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create/Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-base font-semibold text-white">
                {editingRule ? 'ルールを編集' : '新規ルール作成'}
              </h2>
              <button
                onClick={() => setModalOpen(false)}
                className="p-1 rounded-sm text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="px-5 py-4 space-y-4">
              {/* Name */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  ルール名 <span className="text-[#e8002d]">*</span>
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="例: Critical alerts to admin"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>

              {/* Priority */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  優先度（0が最高）
                </label>
                <input
                  type="number"
                  min={0}
                  value={form.priority}
                  onChange={e => setForm(f => ({ ...f, priority: Number(e.target.value) }))}
                  className="w-28 bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>

              {/* Severity match */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-2">
                  重大度フィルタ（複数選択可）
                </label>
                <div className="flex flex-wrap gap-2">
                  {SEVERITIES.map(sev => {
                    const selected = form.conditions.severity_match.includes(sev)
                    return (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => toggleSeverity(sev)}
                        className={`px-3 py-1.5 rounded-sm text-xs font-medium border transition-all ${
                          selected
                            ? `${severityColor[sev]} border-current`
                            : 'text-[#7d92b0] border-[#1e2d42] hover:border-[#7d92b0]/40'
                        }`}
                      >
                        {sev}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Rule ID match */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  ルールIDフィルタ（カンマ区切り）
                </label>
                <input
                  type="text"
                  value={form.conditions.rule_id_match}
                  onChange={e =>
                    setForm(f => ({
                      ...f,
                      conditions: { ...f.conditions, rule_id_match: e.target.value },
                    }))
                  }
                  placeholder="rule-001, rule-002"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>

              {/* Assignee */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  割り当て先ユーザーID (UUID)
                </label>
                <input
                  type="text"
                  value={form.assignee_id}
                  onChange={e => setForm(f => ({ ...f, assignee_id: e.target.value }))}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50 font-mono"
                />
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
                  <span
                    className={`inline-block h-3.5 w-3.5 transform rounded-full bg-[#e2e8f4] transition-transform ${
                      form.enabled ? 'translate-x-4' : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>

              {formError && (
                <p className="text-xs text-[#e8002d]">{formError}</p>
              )}
            </div>
            <div className="px-5 py-4 border-t border-[#1e2d42] flex justify-end gap-3">
              <button
                onClick={() => setModalOpen(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] hover:border-[#7d92b0]/40 transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleSubmit}
                disabled={isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {isPending ? '保存中...' : editingRule ? '更新' : '作成'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <h2 className="text-base font-semibold text-white mb-2">ルールを削除しますか？</h2>
            <p className="text-sm text-[#7d92b0] mb-5">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded-sm border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
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
