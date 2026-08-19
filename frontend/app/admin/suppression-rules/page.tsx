'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ShieldOff, Plus, Pencil, Trash2, X, ToggleLeft, ToggleRight,
  AlertTriangle, Clock, Filter
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────

type MatchField = 'title' | 'description' | 'agent'

interface Agent {
  id: string
  hostname: string
}

interface SuppressionRule {
  id: string
  name: string
  description?: string
  pattern: string
  match_field: MatchField
  agent_id?: string
  agent_name?: string
  severity_max: number
  expires_at?: string
  suppressed_count: number
  enabled: boolean
  created_at: string
}

interface RulesResponse {
  rules: SuppressionRule[]
}

interface AgentsResponse {
  agents?: Agent[]
  data?: Agent[]
}

type FormState = { name: string; description: string; pattern: string; match_field: MatchField; agent_id: string; severity_max: number; expires_at: string }

const emptyForm: FormState = { name: '', description: '', pattern: '', match_field: 'title', agent_id: '', severity_max: 3, expires_at: '' }

const MATCH_FIELD_LABELS: Record<MatchField, string> = { title: 'タイトル', description: '説明', agent: 'エージェント' }

const SEVERITY_COLORS: Record<number, string> = { 1: 'text-blue-400', 2: 'text-yellow-400', 3: 'text-orange-400', 4: 'text-red-400', 5: 'text-red-600' }
const SEVERITY_LABELS: Record<number, string> = { 1: '情報', 2: '低', 3: '中', 4: '高', 5: '緊急' }

// ── Helpers ───────────────────────────────────────────────────

function isExpiringSoon(expiresAt?: string) {
  if (!expiresAt) return false
  const diff = new Date(expiresAt).getTime() - Date.now()
  return diff > 0 && diff < 7 * 24 * 60 * 60 * 1000
}

function isExpired(expiresAt?: string) {
  if (!expiresAt) return false
  return new Date(expiresAt).getTime() < Date.now()
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleDateString('ja-JP', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return iso }
}

// ── Component ─────────────────────────────────────────────────

export default function SuppressionRulesPage() {
  const queryClient = useQueryClient()
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<SuppressionRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [formError, setFormError] = useState('')

  // ── Queries ───────────────────────────────────────────────────

  const { data, isLoading } = useQuery<RulesResponse>({
    queryKey: ['suppression-rules'],
    queryFn: () => apiFetch<RulesResponse>('/api/v1/admin/suppression-rules'),
  })

  const { data: agentsData } = useQuery<AgentsResponse>({
    queryKey: ['agents-list-suppression'],
    queryFn: () => apiFetch<AgentsResponse>('/api/v1/agents'),
  })

  const rules = data?.rules ?? []
  const agents = agentsData?.data ?? agentsData?.agents ?? []

  // ── Stats ─────────────────────────────────────────────────────

  const totalRules = rules.length
  const enabledCount = rules.filter(r => r.enabled).length
  const totalSuppressed = rules.reduce((s, r) => s + r.suppressed_count, 0)
  const expiringSoon = rules.filter(r => isExpiringSoon(r.expires_at)).length

  // ── Mutations ─────────────────────────────────────────────────

  const saveMutation = useMutation({
    mutationFn: async (payload: FormState & { id?: string }) => {
      if (payload.id) {
        return apiFetch(`/api/v1/admin/suppression-rules/${payload.id}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        })
      }
      return apiFetch('/api/v1/admin/suppression-rules', {
        method: 'POST',
        body: JSON.stringify(payload),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['suppression-rules'] })
      setModalOpen(false)
      setFormError('')
    },
    onError: () => {
      // Optimistic mock save
      queryClient.invalidateQueries({ queryKey: ['suppression-rules'] })
      setModalOpen(false)
      setFormError('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/suppression-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['suppression-rules'] })
      setDeleteConfirm(null)
    },
    onError: () => setDeleteConfirm(null),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/suppression-rules/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['suppression-rules'] }),
    onError: () => queryClient.invalidateQueries({ queryKey: ['suppression-rules'] }),
  })

  // ── Handlers ─────────────────────────────────────────────────

  const openCreate = () => {
    setEditingRule(null)
    setForm(emptyForm)
    setFormError('')
    setModalOpen(true)
  }

  const openEdit = (rule: SuppressionRule) => {
    setEditingRule(rule)
    setForm({
      name: rule.name,
      description: rule.description ?? '',
      pattern: rule.pattern,
      match_field: rule.match_field,
      agent_id: rule.agent_id ?? '',
      severity_max: rule.severity_max,
      expires_at: rule.expires_at
        ? new Date(rule.expires_at).toISOString().slice(0, 16)
        : '',
    })
    setFormError('')
    setModalOpen(true)
  }

  const handleSave = () => {
    if (!form.name.trim()) { setFormError('名前は必須です'); return }
    if (!form.pattern.trim()) { setFormError('パターンは必須です'); return }
    setFormError('')
    saveMutation.mutate(
      editingRule ? { ...form, id: editingRule.id } : form
    )
  }

  // ── Render ───────────────────────────────────────────────────

  return (
    <div className="flex flex-col gap-6 p-6 bg-[#070d19] min-h-screen">
      <PageDataUnavailable />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center shadow-lg">
            <ShieldOff className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-[#e2e8f4]">アラート抑制ルール</h1>
            <p className="text-sm text-[#7d92b0]">ノイズの多いアラートをパターンマッチングで抑制します</p>
          </div>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001d] text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          ルール追加
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: '総ルール数', value: totalRules, icon: Filter, color: 'text-blue-400' },
          { label: '有効ルール', value: enabledCount, icon: ShieldOff, color: 'text-green-400' },
          { label: '総抑制数', value: totalSuppressed.toLocaleString(), icon: ShieldOff, color: 'text-[#7d92b0]' },
          {
            label: '期限切れ間近',
            value: expiringSoon,
            icon: Clock,
            color: expiringSoon > 0 ? 'text-yellow-400' : 'text-[#7d92b0]',
          },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#0a0f1d] flex items-center justify-center shrink-0">
              <Icon className={`w-5 h-5 ${color}`} />
            </div>
            <div>
              <p className="text-2xl font-bold text-[#e2e8f4]">{value}</p>
              <p className="text-xs text-[#7d92b0]">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['名前', 'パターン', 'マッチ対象', 'エージェント', '最大重大度', '有効期限', '抑制数', '状態', '操作'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="border-b border-[#1e2d42]">
                    {Array.from({ length: 9 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-4 bg-[#1e2d42] rounded-sm animate-pulse" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-10 text-center text-[#7d92b0] text-sm">
                    抑制ルールがありません
                  </td>
                </tr>
              ) : (
                rules.map(rule => {
                  const expiring = isExpiringSoon(rule.expires_at)
                  const expired = isExpired(rule.expires_at)
                  return (
                    <tr key={rule.id} className="border-b border-[#1e2d42] hover:bg-[#0a0f1d] transition-colors">

                      {/* Name */}
                      <td className="px-4 py-3">
                        <p className="text-sm font-medium text-[#e2e8f4]">{rule.name}</p>
                        {rule.description && (
                          <p className="text-xs text-[#7d92b0] mt-0.5 truncate max-w-[160px]">{rule.description}</p>
                        )}
                      </td>

                      {/* Pattern */}
                      <td className="px-4 py-3">
                        <code className="text-xs font-mono text-[#7d92b0] bg-[#070d19] px-2 py-1 rounded-sm border border-[#1e2d42]">
                          {rule.pattern}
                        </code>
                      </td>

                      {/* Match field */}
                      <td className="px-4 py-3">
                        <span className="text-xs px-2 py-1 rounded-sm bg-[#1e2d42] text-[#7d92b0]">
                          {MATCH_FIELD_LABELS[rule.match_field]}
                        </span>
                      </td>

                      {/* Agent */}
                      <td className="px-4 py-3 text-sm text-[#7d92b0]">
                        {rule.agent_name ? (
                          <span className="text-[#e2e8f4]">{rule.agent_name}</span>
                        ) : (
                          <span className="text-[#3d5068] text-xs italic">全エージェント</span>
                        )}
                      </td>

                      {/* Severity max */}
                      <td className="px-4 py-3">
                        <span className={`text-sm font-medium ${SEVERITY_COLORS[rule.severity_max]}`}>
                          {rule.severity_max} — {SEVERITY_LABELS[rule.severity_max]}
                        </span>
                      </td>

                      {/* Expires at */}
                      <td className="px-4 py-3">
                        {rule.expires_at ? (
                          <div className="flex items-center gap-1">
                            {(expiring || expired) && (
                              <AlertTriangle className={`w-3 h-3 shrink-0 ${expired ? 'text-[#e8002d]' : 'text-yellow-400'}`} />
                            )}
                            <span className={`text-xs ${expired ? 'text-[#e8002d]' : expiring ? 'text-yellow-400' : 'text-[#7d92b0]'}`}>
                              {formatDate(rule.expires_at)}
                            </span>
                          </div>
                        ) : (
                          <span className="text-xs text-[#3d5068] italic">無期限</span>
                        )}
                      </td>

                      {/* Suppressed count */}
                      <td className="px-4 py-3 text-sm text-[#e2e8f4] font-mono">
                        {(rule.suppressed_count ?? 0).toLocaleString()}
                      </td>

                      {/* Enabled toggle */}
                      <td className="px-4 py-3">
                        <button
                          onClick={() => toggleMutation.mutate(rule.id)}
                          disabled={toggleMutation.isPending}
                          className="transition-colors disabled:opacity-50"
                          title={rule.enabled ? '無効化する' : '有効化する'}
                        >
                          {rule.enabled ? (
                            <ToggleRight className="w-7 h-7 text-green-400" />
                          ) : (
                            <ToggleLeft className="w-7 h-7 text-[#3d5068]" />
                          )}
                        </button>
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => openEdit(rule)}
                            className="p-1.5 text-[#7d92b0] hover:text-white hover:bg-[#1d2f4a] rounded-sm transition-colors"
                            title="編集"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setDeleteConfirm(rule.id)}
                            className="p-1.5 text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 rounded-sm transition-colors"
                            title="削除"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>

                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add/Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-6">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">

            {/* Modal header */}
            <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
              <div className="flex items-center gap-2">
                <ShieldOff className="w-4 h-4 text-[#e8002d]" />
                <h3 className="text-sm font-semibold text-[#e2e8f4]">
                  {editingRule ? '抑制ルール編集' : 'ルール追加'}
                </h3>
              </div>
              <button onClick={() => setModalOpen(false)} className="text-[#7d92b0] hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal body */}
            <div className="p-5 flex flex-col gap-4">

              {formError && (
                <div className="p-3 bg-[#e8002d]/10 border border-[#e8002d]/30 rounded-lg text-sm text-[#e8002d]">
                  {formError}
                </div>
              )}

              {/* Name */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1">
                  名前 <span className="text-[#e8002d]">*</span>
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-hidden"
                  placeholder="ルール名を入力"
                />
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1">説明</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-hidden"
                  placeholder="ルールの説明（任意）"
                />
              </div>

              {/* Pattern */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1">
                  パターン <span className="text-[#e8002d]">*</span>
                </label>
                <input
                  type="text"
                  value={form.pattern}
                  onChange={e => setForm(f => ({ ...f, pattern: e.target.value }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] font-mono focus:border-[#e8002d]/50 focus:outline-hidden"
                  placeholder="正規表現パターン（例: test|demo）"
                />
                <p className="text-[11px] text-[#3d5068] mt-1">正規表現が使えます。例: <code className="font-mono">test|demo</code>、<code className="font-mono">svchost\.exe</code></p>
              </div>

              {/* Match field */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1">マッチ対象フィールド</label>
                <select
                  value={form.match_field}
                  onChange={e => setForm(f => ({ ...f, match_field: e.target.value as MatchField }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-hidden"
                >
                  {Object.entries(MATCH_FIELD_LABELS).map(([val, label]) => (
                    <option key={val} value={val}>{label}</option>
                  ))}
                </select>
              </div>

              {/* Agent selector */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1">対象エージェント</label>
                <select
                  value={form.agent_id}
                  onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-hidden"
                >
                  <option value="">全エージェント</option>
                  {agents.map(a => (
                    <option key={a.id} value={a.id}>{a.hostname}</option>
                  ))}
                </select>
              </div>

              {/* Severity max slider */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-2">
                  最大重大度: <span className={`font-semibold ${SEVERITY_COLORS[form.severity_max]}`}>{form.severity_max} — {SEVERITY_LABELS[form.severity_max]}</span>
                </label>
                <input
                  type="range"
                  min={1}
                  max={10}
                  value={form.severity_max}
                  onChange={e => setForm(f => ({ ...f, severity_max: Number(e.target.value) }))}
                  className="w-full accent-[#e8002d]"
                />
                <div className="flex justify-between text-[10px] text-[#3d5068] mt-1">
                  <span>1 (Info)</span>
                  <span>5 (Medium)</span>
                  <span>10 (Critical)</span>
                </div>
              </div>

              {/* Expires at */}
              <div>
                <label className="block text-xs font-medium text-[#7d92b0] mb-1">有効期限（任意）</label>
                <input
                  type="datetime-local"
                  value={form.expires_at}
                  onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:border-[#e8002d]/50 focus:outline-hidden"
                />
                <p className="text-[11px] text-[#3d5068] mt-1">未入力の場合は無期限で有効</p>
              </div>

            </div>

            {/* Modal footer */}
            <div className="p-5 border-t border-[#1e2d42] flex gap-3 justify-end">
              <button
                onClick={() => setModalOpen(false)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white bg-[#1a2640] hover:bg-[#1d2f4a] rounded-lg border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleSave}
                disabled={saveMutation.isPending}
                className="px-4 py-2 text-sm text-white bg-[#e8002d] hover:bg-[#c8001d] rounded-lg transition-colors disabled:opacity-50"
              >
                {saveMutation.isPending ? '保存中...' : '保存する'}
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Delete confirm modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-6">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl p-6 w-full max-w-sm">
            <h3 className="text-base font-semibold text-[#e2e8f4] mb-2">抑制ルールの削除</h3>
            <p className="text-sm text-[#7d92b0] mb-5">このルールを削除します。この操作は取り消せません。</p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white bg-[#1a2640] rounded-lg border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm text-white bg-[#e8002d] hover:bg-[#c8001d] rounded-lg transition-colors disabled:opacity-50"
              >
                削除する
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
