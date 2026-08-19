'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { TrendingUp, Plus, Pencil, Trash2, X, ToggleLeft, ToggleRight } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface EscalationRule {
  id: string
  name: string
  severity_min: number
  unresolved_mins: number
  escalate_to: string
  notify_channel?: string
  enabled: boolean
  created_at: string
}

interface RulesResponse {
  data: EscalationRule[]
  total: number
}

const emptyForm = {
  name: '',
  severity_min: 5,
  unresolved_mins: 60,
  escalate_to: '',
  notify_channel: '',
  enabled: true,
}

type FormState = typeof emptyForm

export default function EscalationRulesPage() {
  const queryClient = useQueryClient()
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<EscalationRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [formError, setFormError] = useState('')

  const { data, isLoading } = useQuery<RulesResponse>({
    queryKey: ['escalation-rules'],
    queryFn: () => apiFetch('/api/v1/escalation-rules'),
  })

  const rules = data?.data ?? []

  const openCreate = () => {
    setEditingRule(null)
    setForm(emptyForm)
    setFormError('')
    setModalOpen(true)
  }

  const openEdit = (rule: EscalationRule) => {
    setEditingRule(rule)
    setForm({
      name: rule.name,
      severity_min: rule.severity_min,
      unresolved_mins: rule.unresolved_mins,
      escalate_to: rule.escalate_to,
      notify_channel: rule.notify_channel ?? '',
      enabled: rule.enabled,
    })
    setFormError('')
    setModalOpen(true)
  }

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/escalation-rules', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['escalation-rules'] })
      setModalOpen(false)
    },
    onError: () => setFormError('作成に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/escalation-rules/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['escalation-rules'] })
      setModalOpen(false)
    },
    onError: () => setFormError('更新に失敗しました'),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      // 有効/無効の切り替えは PATCH /escalation-rules/:id/toggle です。
      // /toggle が抜けており、PATCH /escalation-rules/:id はルートが
      // 無いので、このトグルは一度も効いていませんでした。
      apiFetch(`/api/v1/escalation-rules/${id}/toggle`, { method: 'PATCH' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['escalation-rules'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/escalation-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['escalation-rules'] })
      setDeleteConfirm(null)
    },
  })

  const handleSubmit = () => {
    if (!form.name.trim()) {
      setFormError('ルール名は必須です')
      return
    }
    if (!form.escalate_to.trim()) {
      setFormError('エスカレーション先メールは必須です')
      return
    }
    const body = {
      name: form.name.trim(),
      severity_min: form.severity_min,
      unresolved_mins: form.unresolved_mins,
      escalate_to: form.escalate_to.trim(),
      notify_channel: form.notify_channel.trim() || undefined,
      enabled: form.enabled,
    }
    if (editingRule) {
      updateMutation.mutate({ id: editingRule.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending

  const severityLabel = (n: number) => {
    if (n >= 9) return { label: 'Critical', color: 'text-red-400' }
    if (n >= 7) return { label: 'High', color: 'text-orange-400' }
    if (n >= 5) return { label: 'Medium', color: 'text-yellow-400' }
    if (n >= 3) return { label: 'Low', color: 'text-blue-400' }
    return { label: 'Info', color: 'text-[#7d92b0]' }
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
              <TrendingUp className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h1 className="text-xl font-bold text-white">エスカレーションルール</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">未解決アラートの自動エスカレーションを設定します</p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors"
        >
          <Plus className="w-4 h-4" />
          ルールを追加
        </button>
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
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">ルール名</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">最小重大度</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">未解決時間(分)</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">エスカレーション先</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">通知Ch</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">有効</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {rules.map(rule => {
                  const sev = severityLabel(rule.severity_min)
                  return (
                    <tr key={rule.id} className="hover:bg-[#0a1628] transition-colors">
                      <td className="px-4 py-3 text-sm font-medium text-white">{rule.name}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-medium ${sev.color}`}>
                          {rule.severity_min} / {sev.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-[#7d92b0]">{rule.unresolved_mins} 分</td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono truncate max-w-[160px]">
                        {rule.escalate_to}
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">
                        {rule.notify_channel || '—'}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => toggleMutation.mutate(rule.id)}
                          disabled={toggleMutation.isPending}
                          className="flex items-center gap-1 text-xs transition-colors"
                          title={rule.enabled ? '無効にする' : '有効にする'}
                        >
                          {rule.enabled ? (
                            <span className="flex items-center gap-1 text-green-400 hover:text-green-300">
                              <ToggleRight className="w-4 h-4" /> 有効
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-[#7d92b0] hover:text-white">
                              <ToggleLeft className="w-4 h-4" /> 無効
                            </span>
                          )}
                        </button>
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
                  )
                })}
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
                  placeholder="例: Critical unresolved 1h"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>

              {/* Severity min */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-2">
                  最小重大度: <span className={`font-bold ${severityLabel(form.severity_min).color}`}>
                    {form.severity_min} ({severityLabel(form.severity_min).label})
                  </span>
                </label>
                <input
                  type="range"
                  min={1}
                  max={10}
                  value={form.severity_min}
                  onChange={e => setForm(f => ({ ...f, severity_min: Number(e.target.value) }))}
                  className="w-full accent-[#e8002d]"
                />
                <div className="flex justify-between text-[10px] text-[#3d5068] mt-1">
                  <span>1 (Info)</span>
                  <span>5 (Medium)</span>
                  <span>10 (Critical)</span>
                </div>
              </div>

              {/* Unresolved mins */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  未解決時間（分）
                </label>
                <input
                  type="number"
                  min={1}
                  value={form.unresolved_mins}
                  onChange={e => setForm(f => ({ ...f, unresolved_mins: Number(e.target.value) }))}
                  className="w-32 bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>

              {/* Escalate to */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  エスカレーション先（メール） <span className="text-[#e8002d]">*</span>
                </label>
                <input
                  type="email"
                  value={form.escalate_to}
                  onChange={e => setForm(f => ({ ...f, escalate_to: e.target.value }))}
                  placeholder="soc@example.com"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                />
              </div>

              {/* Notify channel */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
                  通知チャンネル（任意）
                </label>
                <input
                  type="text"
                  value={form.notify_channel}
                  onChange={e => setForm(f => ({ ...f, notify_channel: e.target.value }))}
                  placeholder="#soc-alerts"
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
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
