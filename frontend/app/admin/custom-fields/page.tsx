'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Layers, Plus, Pencil, Trash2, X,
  ChevronUp, ChevronDown, ToggleLeft, ToggleRight,
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

interface CustomField {
  id: string
  field_name: string
  display_name: string
  field_type: 'text' | 'number' | 'boolean' | 'select' | 'date'
  entity_type: 'alert' | 'endpoint'
  required: boolean
  default_value?: string
  options?: string[]
  enabled: boolean
  display_order: number
  created_at: string
}

interface FieldsResponse {
  fields: CustomField[]
}

// ─── Constants ────────────────────────────────────────────────────────────────

const FIELD_TYPE_LABELS: Record<CustomField['field_type'], string> = {
  text: 'テキスト',
  number: '数値',
  boolean: '真偽値',
  select: '選択肢',
  date: '日付',
}

const emptyForm = {
  field_name: '',
  display_name: '',
  field_type: 'text' as CustomField['field_type'],
  required: false,
  default_value: '',
  options_text: '',
  enabled: true,
}

type FormState = typeof emptyForm

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function CustomFieldsPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'alert' | 'endpoint'>('alert')
  const [modalOpen, setModalOpen] = useState(false)
  const [editingField, setEditingField] = useState<CustomField | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [formError, setFormError] = useState('')

  // ── Queries ──────────────────────────────────────────────────────────────

  const { data: alertData, isLoading: alertLoading } = useQuery<FieldsResponse>({
    queryKey: ['custom-fields', 'alert'],
    queryFn: () => apiFetch('/api/v1/custom-fields?entity_type=alert'),
  })

  const { data: endpointData, isLoading: endpointLoading } = useQuery<FieldsResponse>({
    queryKey: ['custom-fields', 'endpoint'],
    queryFn: () => apiFetch('/api/v1/custom-fields?entity_type=endpoint'),
  })

  const alertFields = alertData?.fields ?? []
  const endpointFields = endpointData?.fields ?? []
  const currentFields = activeTab === 'alert' ? alertFields : endpointFields
  const isLoading = activeTab === 'alert' ? alertLoading : endpointLoading

  // ── Mutations ────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/custom-fields', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-fields'] })
      setModalOpen(false)
    },
    onError: () => setFormError('作成に失敗しました'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/custom-fields/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-fields'] })
      setModalOpen(false)
    },
    onError: () => setFormError('更新に失敗しました'),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/custom-fields/${id}/toggle`, { method: 'PUT' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['custom-fields'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/custom-fields/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-fields'] })
      setDeleteConfirm(null)
    },
  })

  const reorderMutation = useMutation({
    mutationFn: ({ id, direction }: { id: string; direction: 'up' | 'down' }) => {
      const fields = [...currentFields].sort((a, b) => a.display_order - b.display_order)
      const idx = fields.findIndex(f => f.id === id)
      if (idx < 0) return Promise.resolve()
      const targetIdx = direction === 'up' ? idx - 1 : idx + 1
      if (targetIdx < 0 || targetIdx >= fields.length) return Promise.resolve()
      const current = fields[idx]
      const target = fields[targetIdx]
      return Promise.all([
        apiFetch(`/api/v1/custom-fields/${current.id}`, {
          method: 'PUT',
          body: JSON.stringify({ display_order: target.display_order }),
        }).catch(() => null),
        apiFetch(`/api/v1/custom-fields/${target.id}`, {
          method: 'PUT',
          body: JSON.stringify({ display_order: current.display_order }),
        }).catch(() => null),
      ]).then(() => {})
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['custom-fields'] }),
  })

  // ── Handlers ─────────────────────────────────────────────────────────────

  const openCreate = () => {
    setEditingField(null)
    setForm(emptyForm)
    setFormError('')
    setModalOpen(true)
  }

  const openEdit = (field: CustomField) => {
    setEditingField(field)
    setForm({
      field_name: field.field_name,
      display_name: field.display_name,
      field_type: field.field_type,
      required: field.required,
      default_value: field.default_value ?? '',
      options_text: (field.options ?? []).join('\n'),
      enabled: field.enabled,
    })
    setFormError('')
    setModalOpen(true)
  }

  const handleSubmit = () => {
    if (!form.field_name.trim()) { setFormError('フィールド名は必須です'); return }
    if (!form.display_name.trim()) { setFormError('表示名は必須です'); return }
    if (!/^[a-z_][a-z0-9_]*$/.test(form.field_name.trim())) {
      setFormError('フィールド名は snake_case (英小文字・数字・アンダースコア) で入力してください')
      return
    }

    const body = {
      field_name: form.field_name.trim(),
      display_name: form.display_name.trim(),
      field_type: form.field_type,
      entity_type: activeTab,
      required: form.required,
      default_value: form.default_value.trim() || undefined,
      options: form.field_type === 'select'
        ? form.options_text.split('\n').map(s => s.trim()).filter(Boolean)
        : undefined,
      enabled: form.enabled,
    }

    if (editingField) {
      updateMutation.mutate({ id: editingField.id, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending
  const sortedFields = [...currentFields].sort((a, b) => a.display_order - b.display_order)

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] p-6">

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
              <Layers className="w-4 h-4 text-falcon-red" />
            </div>
            <h1 className="text-xl font-bold text-white">カスタムフィールド管理</h1>
          </div>
          <p className="text-falcon-muted text-sm ml-11">アラートおよびエンドポイントに付加するカスタムメタデータフィールドを管理します</p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors"
        >
          <Plus className="w-4 h-4" />
          フィールドを追加
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-5 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {(['alert', 'endpoint'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-5 py-2 text-sm font-medium rounded transition-colors ${
              activeTab === tab
                ? 'bg-falcon-red text-white'
                : 'text-falcon-muted hover:text-white hover:bg-falcon-border'
            }`}
          >
            {tab === 'alert' ? 'アラートフィールド' : 'エンドポイントフィールド'}
            <span className={`ml-2 text-xs px-1.5 py-0.5 rounded-full ${
              activeTab === tab ? 'bg-white/20 text-white' : 'bg-falcon-border text-falcon-muted'
            }`}>
              {tab === 'alert' ? alertFields.length : endpointFields.length}
            </span>
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-falcon-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            {activeTab === 'alert' ? 'アラートフィールド' : 'エンドポイントフィールド'}
          </h2>
          <span className="text-xs text-falcon-muted">{sortedFields.length} 件</span>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-falcon-muted text-sm">読み込み中...</div>
        ) : sortedFields.length === 0 ? (
          <div className="p-12 text-center">
            <Layers className="w-10 h-10 text-falcon-border mx-auto mb-3" />
            <p className="text-falcon-muted text-sm">フィールドが登録されていません</p>
            <button
              onClick={openCreate}
              className="mt-3 text-xs text-falcon-red hover:text-[#ff2040] transition-colors"
            >
              最初のフィールドを追加する
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider w-8">#</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">フィールド名</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">表示名</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">タイプ</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">必須</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">デフォルト値</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">有効</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {sortedFields.map((field, idx) => (
                  <tr key={field.id} className="hover:bg-[#0a1628] transition-colors">
                    {/* Order */}
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        <button
                          onClick={() => reorderMutation.mutate({ id: field.id, direction: 'up' })}
                          disabled={idx === 0 || reorderMutation.isPending}
                          className="p-0.5 text-falcon-subtle hover:text-falcon-muted disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
                          title="上へ"
                        >
                          <ChevronUp className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => reorderMutation.mutate({ id: field.id, direction: 'down' })}
                          disabled={idx === sortedFields.length - 1 || reorderMutation.isPending}
                          className="p-0.5 text-falcon-subtle hover:text-falcon-muted disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
                          title="下へ"
                        >
                          <ChevronDown className="w-3 h-3" />
                        </button>
                      </div>
                    </td>

                    {/* field_name */}
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono text-falcon-text bg-[#070d19] px-2 py-0.5 rounded-sm border border-falcon-border">
                        {field.field_name}
                      </span>
                    </td>

                    {/* display_name */}
                    <td className="px-4 py-3 text-sm text-white font-medium">{field.display_name}</td>

                    {/* field_type */}
                    <td className="px-4 py-3">
                      <span className="text-xs px-2 py-0.5 rounded-sm border bg-[#070d19] border-falcon-border text-falcon-muted">
                        {FIELD_TYPE_LABELS[field.field_type]}
                        {field.field_type === 'select' && field.options && field.options.length > 0 && (
                          <span className="ml-1 text-falcon-subtle">({field.options.length})</span>
                        )}
                      </span>
                    </td>

                    {/* required */}
                    <td className="px-4 py-3">
                      {field.required ? (
                        <span className="text-xs px-2 py-0.5 rounded-sm bg-falcon-red/10 text-falcon-red border border-falcon-red/20">必須</span>
                      ) : (
                        <span className="text-xs text-falcon-subtle">任意</span>
                      )}
                    </td>

                    {/* default_value */}
                    <td className="px-4 py-3 text-xs text-falcon-muted font-mono max-w-[140px] truncate">
                      {field.default_value || <span className="text-falcon-subtle">—</span>}
                    </td>

                    {/* enabled */}
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleMutation.mutate(field.id)}
                        disabled={toggleMutation.isPending}
                        className="flex items-center gap-1 text-xs transition-colors"
                        title={field.enabled ? '無効にする' : '有効にする'}
                      >
                        {field.enabled ? (
                          <span className="flex items-center gap-1 text-green-400 hover:text-green-300">
                            <ToggleRight className="w-4 h-4" /> 有効
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-falcon-muted hover:text-white">
                            <ToggleLeft className="w-4 h-4" /> 無効
                          </span>
                        )}
                      </button>
                    </td>

                    {/* actions */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openEdit(field)}
                          className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
                          title="編集"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setDeleteConfirm(field.id)}
                          className="p-1.5 rounded-sm text-falcon-muted hover:text-falcon-red hover:bg-falcon-red/10 transition-colors"
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

      {/* Create / Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg shadow-2xl flex flex-col max-h-[90vh]">

            {/* Modal header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border shrink-0">
              <h2 className="text-base font-semibold text-white">
                {editingField ? 'フィールドを編集' : 'フィールドを追加'}
              </h2>
              <button
                onClick={() => setModalOpen(false)}
                className="p-1 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal body */}
            <div className="px-5 py-4 space-y-4 overflow-y-auto">

              {/* entity_type hint */}
              <div className="flex items-center gap-2 px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-xs text-falcon-muted">
                <Layers className="w-3.5 h-3.5 text-falcon-red" />
                対象: <span className="text-white font-medium ml-1">
                  {activeTab === 'alert' ? 'アラート' : 'エンドポイント'}
                </span>
              </div>

              {/* field_name */}
              <div>
                <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                  フィールド名 <span className="text-falcon-red">*</span>
                  <span className="ml-2 text-falcon-subtle font-normal">(snake_case)</span>
                </label>
                <input
                  type="text"
                  value={form.field_name}
                  onChange={e => setForm(f => ({ ...f, field_name: e.target.value }))}
                  placeholder="例: ticket_id"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                />
              </div>

              {/* display_name */}
              <div>
                <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                  表示名 <span className="text-falcon-red">*</span>
                </label>
                <input
                  type="text"
                  value={form.display_name}
                  onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))}
                  placeholder="例: チケットID"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                />
              </div>

              {/* field_type */}
              <div>
                <label className="block text-xs font-medium text-falcon-muted mb-1.5">タイプ</label>
                <div className="flex flex-wrap gap-2">
                  {(Object.keys(FIELD_TYPE_LABELS) as CustomField['field_type'][]).map(t => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setForm(f => ({ ...f, field_type: t }))}
                      className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                        form.field_type === t
                          ? 'bg-falcon-red border-falcon-red text-white'
                          : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40 hover:text-white'
                      }`}
                    >
                      {FIELD_TYPE_LABELS[t]}
                    </button>
                  ))}
                </div>
              </div>

              {/* default_value */}
              {form.field_type !== 'boolean' && (
                <div>
                  <label className="block text-xs font-medium text-falcon-muted mb-1.5">デフォルト値</label>
                  <input
                    type="text"
                    value={form.default_value}
                    onChange={e => setForm(f => ({ ...f, default_value: e.target.value }))}
                    placeholder="省略可"
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                  />
                </div>
              )}

              {/* options (select type only) */}
              {form.field_type === 'select' && (
                <div>
                  <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                    選択肢
                    <span className="ml-2 text-falcon-subtle font-normal">(1行1オプション)</span>
                  </label>
                  <textarea
                    value={form.options_text}
                    onChange={e => setForm(f => ({ ...f, options_text: e.target.value }))}
                    rows={4}
                    placeholder={"low\nmedium\nhigh\ncritical"}
                    className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 resize-none"
                  />
                </div>
              )}

              {/* required toggle */}
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-falcon-muted">必須フィールド</label>
                <button
                  type="button"
                  onClick={() => setForm(f => ({ ...f, required: !f.required }))}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    form.required ? 'bg-falcon-red' : 'bg-falcon-border'
                  }`}
                >
                  <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-falcon-text transition-transform ${
                    form.required ? 'translate-x-4' : 'translate-x-1'
                  }`} />
                </button>
              </div>

              {/* enabled toggle */}
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-falcon-muted">有効</label>
                <button
                  type="button"
                  onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    form.enabled ? 'bg-falcon-red' : 'bg-falcon-border'
                  }`}
                >
                  <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-falcon-text transition-transform ${
                    form.enabled ? 'translate-x-4' : 'translate-x-1'
                  }`} />
                </button>
              </div>

              {formError && (
                <p className="text-xs text-falcon-red">{formError}</p>
              )}
            </div>

            {/* Modal footer */}
            <div className="px-5 py-4 border-t border-falcon-border flex justify-end gap-3 shrink-0">
              <button
                onClick={() => setModalOpen(false)}
                className="px-4 py-2 text-sm text-falcon-muted hover:text-white rounded-sm border border-falcon-border hover:border-falcon-muted/40 transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleSubmit}
                disabled={isPending}
                className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
              >
                {isPending ? '保存中...' : editingField ? '更新' : '追加'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirm modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <h2 className="text-base font-semibold text-white mb-2">フィールドを削除しますか？</h2>
            <p className="text-sm text-falcon-muted mb-5">
              このフィールドに記録されたデータもすべて削除されます。この操作は取り消せません。
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-falcon-muted hover:text-white rounded-sm border border-falcon-border transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c8001f] text-white rounded-sm font-medium transition-colors disabled:opacity-50"
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
