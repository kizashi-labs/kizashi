'use client'

import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  Workflow, Plus, Trash2, ToggleLeft, ToggleRight,
  ChevronDown, ChevronUp, X, Play, Clock, CheckCircle2, XCircle, Pencil, Search
} from 'lucide-react'

interface PlaybookConditions {
  min_severity?: number
  max_severity?: number
  rule_name?: string
  hostname?: string
  mitre_technique?: string
  status?: string
}

interface PlaybookAction {
  type: 'isolate_endpoint' | 'create_incident' | 'notify' | 'assign_alert'
  title?: string
  severity?: number
  message?: string
  user_id?: string
}

interface Playbook {
  id: string
  name: string
  description: string
  conditions: PlaybookConditions
  actions: PlaybookAction[]
  is_active: boolean
  run_count: number
  last_run_at?: string
  created_by_name: string
  created_at: string
}

interface PlaybookRun {
  id: string
  alert_id: string
  actions_run: PlaybookAction[]
  success: boolean
  error_msg: string
  ran_at: string
}

const ACTION_TYPES = [
  { value: 'isolate_endpoint', label: 'エンドポイントを隔離' },
  { value: 'create_incident',  label: 'インシデントを作成' },
  { value: 'notify',           label: '通知を送信' },
  { value: 'assign_alert',     label: 'アラートを割り当て' },
]

const emptyConditions: PlaybookConditions = {
  min_severity: 0, max_severity: 0,
  rule_name: '', hostname: '', mitre_technique: '', status: '',
}

const emptyAction: PlaybookAction = { type: 'isolate_endpoint' }

function actionLabel(a: PlaybookAction): string {
  switch (a.type) {
    case 'isolate_endpoint': return 'エンドポイントを隔離'
    case 'create_incident':  return `インシデント作成: "${a.title || '(タイトル未設定)'}"`
    case 'notify':           return `通知: "${a.message || '(メッセージ未設定)'}"`
    case 'assign_alert':     return `アラートを割り当て`
    default: return a.type
  }
}

function condSummary(c: PlaybookConditions): string {
  const parts: string[] = []
  if (c.min_severity) parts.push(`重大度 ≥ ${c.min_severity}`)
  if (c.max_severity) parts.push(`重大度 ≤ ${c.max_severity}`)
  if (c.rule_name) parts.push(`ルール: ${c.rule_name}`)
  if (c.hostname) parts.push(`ホスト: ${c.hostname}`)
  if (c.mitre_technique) parts.push(`MITRE: ${c.mitre_technique}`)
  if (c.status) parts.push(`ステータス: ${c.status}`)
  return parts.length ? parts.join(' | ') : 'すべてのアラートにマッチ'
}

export default function PlaybooksPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()
  const [activeOnly, setActiveOnly] = useState(false)
  const [search, setSearch] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [runsId, setRunsId] = useState<string | null>(null)

  const [form, setForm] = useState({
    name: '', description: '',
    conditions: { ...emptyConditions },
    actions: [{ ...emptyAction }] as PlaybookAction[],
    is_active: true,
  })

  const { data } = useQuery<{ data: Playbook[]; total: number }>({
    queryKey: ['playbooks', activeOnly],
    queryFn: () => apiFetch(`/api/v1/playbooks${activeOnly ? '?active=true' : ''}`),
    refetchInterval: 30000,
  })
  const allPlaybooks = data?.data ?? []
  const playbooks = search
    ? allPlaybooks.filter(p =>
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.description?.toLowerCase().includes(search.toLowerCase())
      )
    : allPlaybooks

  const { data: runsData } = useQuery<{ data: PlaybookRun[] }>({
    queryKey: ['playbook-runs', runsId],
    queryFn: () => apiFetch(`/api/v1/playbooks/${runsId}/runs`),
    enabled: !!runsId,
  })
  const runs = runsData?.data ?? []

  const createMutation = useMutation({
    mutationFn: (body: object) => apiFetch('/api/v1/playbooks', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); resetForm() },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/playbooks/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbooks'] }); resetForm() },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/playbooks/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      apiFetch(`/api/v1/playbooks/${id}/toggle`, { method: 'PUT', body: JSON.stringify({ is_active }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['playbooks'] }),
  })

  const resetForm = () => {
    setShowForm(false)
    setEditId(null)
    setForm({ name: '', description: '', conditions: { ...emptyConditions }, actions: [{ ...emptyAction }], is_active: true })
  }

  const startEdit = (pb: Playbook) => {
    setForm({
      name: pb.name,
      description: pb.description,
      conditions: { ...emptyConditions, ...pb.conditions },
      actions: pb.actions.length ? pb.actions : [{ ...emptyAction }],
      is_active: pb.is_active,
    })
    setEditId(pb.id)
    setShowForm(true)
    setExpandedId(null)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const body = {
      name: form.name,
      description: form.description,
      is_active: form.is_active,
      actions: form.actions.filter(a => a.type),
      conditions: Object.fromEntries(
        Object.entries(form.conditions).filter(([, v]) => v !== '' && v !== 0)
      ),
    }
    if (editId) {
      updateMutation.mutate({ id: editId, body })
    } else {
      createMutation.mutate(body)
    }
  }

  const updateAction = (i: number, partial: Partial<PlaybookAction>) => {
    setForm(f => {
      const actions = [...f.actions]
      actions[i] = { ...actions[i], ...partial }
      return { ...f, actions }
    })
  }

  const addAction = () => setForm(f => ({ ...f, actions: [...f.actions, { ...emptyAction }] }))
  const removeAction = (i: number) => setForm(f => ({ ...f, actions: f.actions.filter((_, idx) => idx !== i) }))

  const isPending = createMutation.isPending || updateMutation.isPending

  return (
    <div className="p-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Workflow className="text-purple-400" size={24} />
            <h1 className="text-2xl font-bold">レスポンス・プレイブック</h1>
            <span className="text-sm text-[#8899aa]">({data?.total ?? 0}件)</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="名前・説明で検索..."
                className="pl-8 pr-3 py-1.5 text-sm border border-[#1e2d42] rounded-lg
                           bg-[#111827] text-white placeholder-[#5a6a7a] w-44
                           focus:outline-none focus:border-purple-500"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-[#8899aa] cursor-pointer">
              <input type="checkbox" checked={activeOnly} onChange={e => setActiveOnly(e.target.checked)} className="rounded" />
              有効のみ
            </label>
            {canWrite && (
              <button
                onClick={() => { resetForm(); setShowForm(true) }}
                className="flex items-center gap-2 bg-purple-700 hover:bg-purple-600 px-4 py-2 rounded-lg text-sm font-medium"
              >
                <Plus size={16} />
                新規プレイブック
              </button>
            )}
          </div>
        </div>

        {/* Description */}
        <div className="bg-purple-900/20 border border-purple-800/40 rounded-xl p-4 mb-6 text-sm text-purple-200">
          プレイブックはアラートが条件を満たしたとき自動的にアクション（隔離・インシデント作成・通知・割り当て）を実行します。
          現在、新規アラート受信時に検知エンジンから自動トリガーされます。
        </div>

        {/* Form */}
        {showForm && (
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-purple-400">{editId ? 'プレイブックを編集' : '新しいプレイブック'}</h2>
              <button onClick={resetForm} className="text-[#8899aa] hover:text-white"><X size={18} /></button>
            </div>
            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[#8899aa] mb-1">プレイブック名 *</label>
                  <input
                    required
                    value={form.name}
                    onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-2 text-sm"
                    placeholder="例: 高重大度アラート自動対応"
                  />
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 text-sm text-[#8899aa] cursor-pointer">
                    <input
                      type="checkbox"
                      checked={form.is_active}
                      onChange={e => setForm(f => ({ ...f, is_active: e.target.checked }))}
                      className="rounded"
                    />
                    作成時から有効
                  </label>
                </div>
              </div>
              <div>
                <label className="block text-xs text-[#8899aa] mb-1">説明</label>
                <input
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-2 text-sm"
                  placeholder="このプレイブックの目的"
                />
              </div>

              {/* Conditions */}
              <div className="border border-[#1e2d42] rounded-lg p-4">
                <p className="text-xs font-medium text-[#8899aa] mb-3">トリガー条件 (空白=ワイルドカード)</p>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-[#5a6a7a] mb-1">最小重大度</label>
                    <input
                      type="number" min={0} max={10}
                      value={form.conditions.min_severity || ''}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, min_severity: parseInt(e.target.value) || 0 } }))}
                      className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-1.5 text-sm"
                      placeholder="例: 8"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#5a6a7a] mb-1">最大重大度</label>
                    <input
                      type="number" min={0} max={10}
                      value={form.conditions.max_severity || ''}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, max_severity: parseInt(e.target.value) || 0 } }))}
                      className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-1.5 text-sm"
                      placeholder="例: 10"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#5a6a7a] mb-1">ルール名 (部分一致)</label>
                    <input
                      value={form.conditions.rule_name}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, rule_name: e.target.value } }))}
                      className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-1.5 text-sm"
                      placeholder="例: mimikatz"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#5a6a7a] mb-1">ホスト名 (部分一致)</label>
                    <input
                      value={form.conditions.hostname}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, hostname: e.target.value } }))}
                      className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-1.5 text-sm"
                      placeholder="例: SERVER-"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#5a6a7a] mb-1">MITRE手法ID</label>
                    <input
                      value={form.conditions.mitre_technique}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, mitre_technique: e.target.value } }))}
                      className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-1.5 text-sm"
                      placeholder="例: T1003"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#5a6a7a] mb-1">アラートステータス</label>
                    <select
                      value={form.conditions.status}
                      onChange={e => setForm(f => ({ ...f, conditions: { ...f.conditions, status: e.target.value } }))}
                      className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-3 py-1.5 text-sm"
                    >
                      <option value="">すべて</option>
                      <option value="open">未対応 (open)</option>
                      <option value="investigating">調査中</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="border border-[#1e2d42] rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <p className="text-xs font-medium text-[#8899aa]">実行アクション (順番に実行)</p>
                  <button
                    type="button"
                    onClick={addAction}
                    className="flex items-center gap-1 text-xs text-purple-400 hover:text-purple-300"
                  >
                    <Plus size={12} /> アクションを追加
                  </button>
                </div>
                <div className="space-y-3">
                  {form.actions.map((action, i) => (
                    <div key={i} className="bg-[#161f33]/50 rounded-lg p-3 space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-[#5a6a7a] w-5">{i + 1}.</span>
                        <select
                          value={action.type}
                          onChange={e => updateAction(i, { type: e.target.value as PlaybookAction['type'] })}
                          className="flex-1 bg-[#161f33] border border-[#1e2d42] rounded px-2 py-1.5 text-sm"
                        >
                          {ACTION_TYPES.map(t => (
                            <option key={t.value} value={t.value}>{t.label}</option>
                          ))}
                        </select>
                        {form.actions.length > 1 && (
                          <button type="button" onClick={() => removeAction(i)} className="text-[#5a6a7a] hover:text-red-400">
                            <X size={14} />
                          </button>
                        )}
                      </div>
                      {action.type === 'create_incident' && (
                        <div className="grid grid-cols-2 gap-2 pl-5">
                          <input
                            value={action.title || ''}
                            onChange={e => updateAction(i, { title: e.target.value })}
                            className="bg-[#161f33] border border-[#1e2d42] rounded px-2 py-1.5 text-xs"
                            placeholder="インシデントタイトル"
                          />
                          <input
                            type="number" min={1} max={10}
                            value={action.severity || ''}
                            onChange={e => updateAction(i, { severity: parseInt(e.target.value) || undefined })}
                            className="bg-[#161f33] border border-[#1e2d42] rounded px-2 py-1.5 text-xs"
                            placeholder="重大度 (1-10)"
                          />
                        </div>
                      )}
                      {action.type === 'notify' && (
                        <div className="pl-5">
                          <input
                            value={action.message || ''}
                            onChange={e => updateAction(i, { message: e.target.value })}
                            className="w-full bg-[#161f33] border border-[#1e2d42] rounded px-2 py-1.5 text-xs"
                            placeholder="通知メッセージ"
                          />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {(createMutation.isError || updateMutation.isError) && (
                <p className="text-red-400 text-sm">{editId ? '更新' : '作成'}に失敗しました</p>
              )}
              <div className="flex gap-3">
                <button
                  type="submit"
                  disabled={isPending}
                  className="bg-purple-700 hover:bg-purple-600 disabled:opacity-50 px-5 py-2 rounded-lg text-sm font-medium"
                >
                  {isPending ? '保存中...' : editId ? '更新' : '作成'}
                </button>
                <button type="button" onClick={resetForm} className="text-[#8899aa] hover:text-white text-sm px-3">
                  キャンセル
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Run History Modal */}
        {runsId && (
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5 mb-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Clock size={16} className="text-[#8899aa]" />
                <h2 className="font-semibold">実行履歴</h2>
              </div>
              <button onClick={() => setRunsId(null)} className="text-[#8899aa] hover:text-white"><X size={16} /></button>
            </div>
            {runs.length === 0 ? (
              <p className="text-[#5a6a7a] text-sm text-center py-4">実行履歴がありません</p>
            ) : (
              <div className="space-y-2">
                {runs.map(r => (
                  <div key={r.id} className="flex items-center gap-3 text-sm bg-[#080c14]/40 rounded-lg px-3 py-2">
                    {r.success
                      ? <CheckCircle2 size={14} className="text-green-400 flex-shrink-0" />
                      : <XCircle size={14} className="text-red-400 flex-shrink-0" />
                    }
                    <span className="font-mono text-xs text-[#8899aa] w-64 truncate">{r.alert_id}</span>
                    <span className="text-xs text-[#5a6a7a]">{r.actions_run.length}アクション実行</span>
                    {r.error_msg && <span className="text-xs text-red-400 truncate">{r.error_msg}</span>}
                    <span className="ml-auto text-xs text-[#5a6a7a] whitespace-nowrap">
                      {new Date(r.ran_at).toLocaleString('ja-JP')}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Playbook List */}
        {playbooks.length === 0 ? (
          <div className="text-center py-12 text-[#5a6a7a]">
            <Workflow size={48} className="mx-auto mb-3 opacity-30" />
            <p>プレイブックがありません</p>
          </div>
        ) : (
          <div className="space-y-3">
            {playbooks.map(pb => (
              <div
                key={pb.id}
                className={`bg-[#111827] border rounded-xl overflow-hidden ${pb.is_active ? 'border-[#1e2d42]' : 'border-[#1e2d42] opacity-60'}`}
              >
                <div className="flex items-center gap-4 p-4">
                  {/* Toggle */}
                  {canWrite ? (
                    <button
                      onClick={() => toggleMutation.mutate({ id: pb.id, is_active: !pb.is_active })}
                      className={pb.is_active ? 'text-purple-400' : 'text-[#5a6a7a]'}
                    >
                      {pb.is_active ? <ToggleRight size={28} /> : <ToggleLeft size={28} />}
                    </button>
                  ) : (
                    <span className={pb.is_active ? 'text-purple-400' : 'text-[#5a6a7a]'}>
                      {pb.is_active ? <ToggleRight size={28} /> : <ToggleLeft size={28} />}
                    </span>
                  )}

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold truncate">{pb.name}</span>
                      {pb.is_active && (
                        <span className="text-xs bg-purple-900/50 text-purple-300 px-2 py-0.5 rounded-full">有効</span>
                      )}
                      <span className="text-xs bg-[#161f33] text-[#8899aa] px-2 py-0.5 rounded-full">
                        {pb.actions.length}アクション
                      </span>
                    </div>
                    <p className="text-xs text-[#8899aa] mt-0.5">{condSummary(pb.conditions)}</p>
                  </div>

                  {/* Stats */}
                  <div className="text-right text-xs text-[#5a6a7a] whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      <Play size={10} />
                      {pb.run_count}回実行
                    </div>
                    {pb.last_run_at && (
                      <div>最終: {new Date(pb.last_run_at).toLocaleDateString('ja-JP')}</div>
                    )}
                  </div>

                  {/* Actions */}
                  <button
                    onClick={() => setRunsId(runsId === pb.id ? null : pb.id)}
                    title="実行履歴"
                    className="text-[#8899aa] hover:text-white"
                  >
                    <Clock size={15} />
                  </button>
                  <button
                    onClick={() => setExpandedId(expandedId === pb.id ? null : pb.id)}
                    className="text-[#8899aa] hover:text-white"
                  >
                    {expandedId === pb.id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </button>
                  {canWrite && (
                    <button onClick={() => startEdit(pb)} className="text-blue-400 hover:text-blue-300">
                      <Pencil size={14} />
                    </button>
                  )}
                  {canWrite && (
                    <button
                      onClick={() => { if (confirm(`"${pb.name}" を削除しますか？`)) deleteMutation.mutate(pb.id) }}
                      className="text-red-400 hover:text-red-300"
                    >
                      <Trash2 size={15} />
                    </button>
                  )}
                </div>

                {/* Expanded Detail */}
                {expandedId === pb.id && (
                  <div className="border-t border-[#1e2d42] px-4 py-3 bg-[#080c14]/40 text-sm space-y-3">
                    {pb.description && <p className="text-[#8899aa]">{pb.description}</p>}

                    <div>
                      <p className="text-xs text-[#5a6a7a] mb-2 font-medium">実行アクション:</p>
                      <ol className="space-y-1">
                        {pb.actions.map((a, i) => (
                          <li key={i} className="flex items-start gap-2 text-xs">
                            <span className="text-[#5a6a7a] w-4 flex-shrink-0">{i + 1}.</span>
                            <span className="text-[#8899aa]">{actionLabel(a)}</span>
                          </li>
                        ))}
                      </ol>
                    </div>

                    <div className="text-xs text-[#5a6a7a]">
                      作成者: {pb.created_by_name || '—'} ·
                      作成: {new Date(pb.created_at).toLocaleString('ja-JP')}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
