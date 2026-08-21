'use client'

import React, { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  ShieldOff, Plus, Edit2, Trash2, CheckCircle, XCircle, Clock,
  Filter, AlertTriangle, Search, X,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ────────────────────────────────────────────────────────────────────
//
// この画面は長らく実在しない契約 (field / match_type / pattern / notes /
// enabled) で書かれていた。サーバが返すのは conditions / description /
// is_active なので、一覧では条件が空欄のまま並び、作成は名前だけが保存されて
// **条件ゼロのルール**になる。条件ゼロは検知側 (ClassifySuppression) が
// catch-all として適用を拒むので、**画面から作った抑制は一件も効かない。**
// 編集に至っては PUT のルート自体が無く 404 だった。
//
// 以下の型は server/internal/store/suppressions.go と
// server/internal/detection/suppression_matcher.go に合わせてある。

interface SuppressionConditions {
  rule_name?: string
  hostname?: string
  agent_id?: string
  mitre_technique?: string
  severity_max?: number
  command_line_contains?: string
  parent_process?: string
}

interface SuppressionRule {
  id: string
  name: string
  description?: string
  conditions: SuppressionConditions
  duration_h: number
  is_active: boolean
  hit_count: number
  created_by_name?: string
  expires_at?: string
  created_at: string
  updated_at: string
}

interface SuppressionResponse {
  data: SuppressionRule[]
}

type FilterStatus = 'all' | 'enabled' | 'disabled'

// 条件ごとに一致の仕方が違う (SuppressionMatcher.matches)。ここの説明は
// その実装そのままで、「部分一致のつもりが後方一致だった」で外すのを防ぐ。
const CONDITION_FIELDS = [
  {
    key: 'rule_name' as const,
    label: '検知ルール名',
    hint: '部分一致・大文字小文字を区別しない',
    placeholder: '例: Data Exfiltration',
  },
  {
    key: 'hostname' as const,
    label: 'ホスト名',
    hint: '部分一致・大文字小文字を区別しない',
    placeholder: '例: ci-runner-',
  },
  {
    key: 'agent_id' as const,
    label: 'エージェントID',
    hint: '完全一致',
    placeholder: '例: 3f2a9c1e-…',
  },
  {
    key: 'mitre_technique' as const,
    label: 'MITRE 技法',
    hint: '前方一致。T1059 はサブ技法 T1059.001 にも当たる',
    placeholder: '例: T1059',
  },
  {
    key: 'command_line_contains' as const,
    label: 'コマンドライン',
    hint: '部分一致。8文字未満の断片は絞り込みとみなされない',
    placeholder: '例: /opt/backup/nightly.sh',
  },
  {
    key: 'parent_process' as const,
    label: '親プロセス',
    hint: '後方一致。パスを知らなくても実行ファイル名だけで書ける',
    placeholder: '例: cron',
  },
]

const EMPTY_FORM = {
  name: '',
  description: '',
  rule_name: '',
  hostname: '',
  agent_id: '',
  mitre_technique: '',
  command_line_contains: '',
  parent_process: '',
  severity_max: '',
  expires_at: '',
  is_active: true,
}

type FormState = typeof EMPTY_FORM

// ── Helpers ───────────────────────────────────────────────────────────────────

function isExpired(expiresAt?: string): boolean {
  if (!expiresAt) return false
  return new Date(expiresAt).getTime() < Date.now()
}

function formatExpiry(expiresAt?: string): string {
  if (!expiresAt) return '無期限'
  const d = new Date(expiresAt)
  if (d.getTime() < Date.now()) return '期限切れ'
  return d.toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

// 検知側 (ClassifySuppression) は条件がひとつも無いルールを catch-all として
// **適用しない**。保存自体は通るので、画面で言わないと「保存したのに効かない」
// が黙って起きる。
function conditionCount(c: SuppressionConditions): number {
  let n = 0
  for (const f of CONDITION_FIELDS) {
    if ((c[f.key] ?? '').toString().trim() !== '') n++
  }
  if ((c.severity_max ?? 0) > 0) n++
  return n
}

function formToConditions(form: FormState): SuppressionConditions {
  const c: SuppressionConditions = {}
  for (const f of CONDITION_FIELDS) {
    const v = form[f.key].trim()
    if (v) c[f.key] = v
  }
  const sev = parseInt(form.severity_max, 10)
  if (!Number.isNaN(sev) && sev > 0) c.severity_max = sev
  return c
}

function ruleToForm(rule: SuppressionRule): FormState {
  const c = rule.conditions ?? {}
  return {
    name: rule.name,
    description: rule.description ?? '',
    rule_name: c.rule_name ?? '',
    hostname: c.hostname ?? '',
    agent_id: c.agent_id ?? '',
    mitre_technique: c.mitre_technique ?? '',
    command_line_contains: c.command_line_contains ?? '',
    parent_process: c.parent_process ?? '',
    severity_max: c.severity_max ? String(c.severity_max) : '',
    expires_at: rule.expires_at
      ? new Date(rule.expires_at).toISOString().slice(0, 16)
      : '',
    is_active: rule.is_active,
  }
}

// ── Condition badges ──────────────────────────────────────────────────────────

function ConditionBadges({ conditions }: { conditions: SuppressionConditions }) {
  const c = conditions ?? {}
  const items: { label: string; value: string }[] = []
  for (const f of CONDITION_FIELDS) {
    const v = (c[f.key] ?? '').toString()
    if (v) items.push({ label: f.label, value: v })
  }
  if ((c.severity_max ?? 0) > 0) {
    items.push({ label: '重大度', value: `${c.severity_max} 以下` })
  }

  if (items.length === 0) {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-red-400">
        <AlertTriangle size={11} />
        条件なし（適用されません）
      </span>
    )
  }

  return (
    <div className="flex flex-wrap gap-1">
      {items.map(it => (
        <span
          key={it.label}
          className="text-xs px-2 py-0.5 rounded-sm border bg-gray-700/50 text-gray-300 border-gray-600/40"
          title={`${it.label}: ${it.value}`}
        >
          <span className="text-gray-500">{it.label}</span>{' '}
          <span className="font-mono">{it.value}</span>
        </span>
      ))}
    </div>
  )
}

// ── Rule Form ─────────────────────────────────────────────────────────────────

interface RuleFormProps {
  initial?: FormState
  onSubmit: (data: FormState) => void
  onCancel: () => void
  isPending: boolean
  isError: boolean
  editMode?: boolean
}

function RuleForm({ initial, onSubmit, onCancel, isPending, isError, editMode }: RuleFormProps) {
  const [form, setForm] = useState<FormState>(initial ?? EMPTY_FORM)

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  const filledConditions = useMemo(
    () => conditionCount(formToConditions(form)),
    [form],
  )

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(form)
  }

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-semibold text-yellow-400 flex items-center gap-2">
          <ShieldOff size={16} />
          {editMode ? 'ルールを編集' : '新しいルール'}
        </h2>
        <button onClick={onCancel} className="text-gray-400 hover:text-white">
          <X size={18} />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Row 1: name */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">ルール名 *</label>
          <input
            required
            value={form.name}
            onChange={e => set('name', e.target.value)}
            placeholder="例: 定期バックアップの誤検知を抑制"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:border-yellow-500 text-white placeholder-gray-600"
          />
        </div>

        {/* Conditions */}
        <div>
          <div className="flex items-baseline justify-between mb-2">
            <label className="block text-xs text-gray-400">抑制条件</label>
            <span className="text-xs text-gray-500">
              書いた条件すべてに一致したアラートを抑制します（AND）
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {CONDITION_FIELDS.map(f => (
              <div key={f.key}>
                <label className="block text-xs text-gray-400 mb-1">{f.label}</label>
                <input
                  value={form[f.key]}
                  onChange={e => set(f.key, e.target.value)}
                  placeholder={f.placeholder}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-hidden focus:border-yellow-500 text-white placeholder-gray-600"
                />
                <p className="text-xs text-gray-600 mt-1">{f.hint}</p>
              </div>
            ))}
            <div>
              <label className="block text-xs text-gray-400 mb-1">重大度の上限</label>
              <input
                type="number"
                min={1}
                max={10}
                value={form.severity_max}
                onChange={e => set('severity_max', e.target.value)}
                placeholder="例: 3"
                className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-hidden focus:border-yellow-500 text-white placeholder-gray-600"
              />
              <p className="text-xs text-gray-600 mt-1">
                この値以下の重大度だけを抑制。10 は上限そのものなので何も絞れません
              </p>
            </div>
          </div>
        </div>

        {/* 条件ゼロの警告 */}
        {filledConditions === 0 && (
          <div className="flex items-start gap-2 text-sm px-3 py-2 rounded-lg bg-red-900/20 border border-red-800/50 text-red-300">
            <AlertTriangle size={14} className="text-red-400 shrink-0 mt-0.5" />
            <span>
              条件がひとつも書かれていません。このルールは保存できますが、
              全アラートを消してしまうため検知エンジンは<strong>適用しません</strong>。
            </span>
          </div>
        )}

        {/* Row 3: expires_at + is_active */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">有効期限 (省略で無期限)</label>
            <input
              type="datetime-local"
              value={form.expires_at}
              onChange={e => set('expires_at', e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:border-yellow-500 text-white"
            />
          </div>
          <div className="flex items-end gap-3 pb-1">
            <label className="flex items-center gap-2 cursor-pointer select-none text-sm text-gray-300">
              <div
                role="switch"
                aria-checked={form.is_active}
                onClick={() => set('is_active', !form.is_active)}
                className={`w-10 h-5 rounded-full transition-colors cursor-pointer ${
                  form.is_active ? 'bg-yellow-500' : 'bg-gray-600'
                }`}
              >
                <div className={`w-4 h-4 rounded-full bg-[#e2e8f4] mt-0.5 transition-transform shadow-sm ${
                  form.is_active ? 'translate-x-5.5' : 'translate-x-0.5'
                }`} />
              </div>
              {form.is_active ? 'ルール有効' : 'ルール無効'}
            </label>
          </div>
        </div>

        {/* description */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">メモ (省略可)</label>
          <textarea
            rows={2}
            value={form.description}
            onChange={e => set('description', e.target.value)}
            placeholder="このルールの目的や背景を記入..."
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:border-yellow-500 text-white placeholder-gray-600 resize-none"
          />
        </div>

        {isError && (
          <p className="text-red-400 text-sm">{editMode ? '更新' : '作成'}に失敗しました。もう一度お試しください。</p>
        )}

        <div className="flex gap-3">
          <button
            type="submit"
            disabled={isPending}
            className="bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 px-5 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            {isPending ? (editMode ? '更新中...' : '作成中...') : (editMode ? 'ルールを更新' : 'ルールを作成')}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="text-gray-400 hover:text-white text-sm px-3 transition-colors"
          >
            キャンセル
          </button>
        </div>
      </form>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function SuppressionsPage() {
  const canWrite = useCanWrite()
  const qc = useQueryClient()

  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all')
  const [search, setSearch] = useState('')
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [editingRule, setEditingRule] = useState<SuppressionRule | null>(null)

  // ── Queries ────────────────────────────────────────────────────

  const { data, isLoading } = useQuery<SuppressionResponse>({
    queryKey: ['suppressions'],
    queryFn: () => apiFetch('/api/v1/suppressions'),
    refetchInterval: 30_000,
  })

  const allRules: SuppressionRule[] = data?.data ?? []

  // ── Mutations ──────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/suppressions', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['suppressions'] })
      setShowCreateForm(false)
    },
  })

  // conditions は丸ごと置き換わる (PUT)。編集後の条件をすべて送ること。
  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/suppressions/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['suppressions'] })
      setEditingRule(null)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/suppressions/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['suppressions'] }),
  })

  // 有効/無効は PUT /suppressions/:id/toggle。サーバが読むキーは is_active で、
  // enabled を送っても bool のゼロ値 false になり、**どちらに倒しても無効化**
  // される。
  const toggleMutation = useMutation({
    mutationFn: ({ id, isActive }: { id: string; isActive: boolean }) =>
      apiFetch(`/api/v1/suppressions/${id}/toggle`, {
        method: 'PUT',
        body: JSON.stringify({ is_active: isActive }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['suppressions'] }),
  })

  // ── Stats ──────────────────────────────────────────────────────

  const totalRules = allRules.length
  const enabledCount = allRules.filter(r => r.is_active).length
  const totalSuppressed = allRules.reduce((acc, r) => acc + (r.hit_count ?? 0), 0)

  // ── Filtered view ──────────────────────────────────────────────

  const visibleRules = useMemo(() => {
    return allRules.filter(r => {
      if (filterStatus === 'enabled' && !r.is_active) return false
      if (filterStatus === 'disabled' && r.is_active) return false
      if (search) {
        const q = search.toLowerCase()
        const haystack = [
          r.name,
          r.description ?? '',
          ...Object.values(r.conditions ?? {}).map(v => String(v)),
        ].join(' ').toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }, [allRules, filterStatus, search])

  // ── Handlers ───────────────────────────────────────────────────

  const buildBody = (form: FormState): Record<string, unknown> => {
    const body: Record<string, unknown> = {
      name: form.name,
      description: form.description,
      conditions: formToConditions(form),
      is_active: form.is_active,
    }
    if (form.expires_at) body.expires_at = new Date(form.expires_at).toISOString()
    return body
  }

  const handleCreate = (form: FormState) => createMutation.mutate(buildBody(form))

  const handleUpdate = (form: FormState) => {
    if (!editingRule) return
    updateMutation.mutate({ id: editingRule.id, body: buildBody(form) })
  }

  const handleEditOpen = (rule: SuppressionRule) => {
    setShowCreateForm(false)
    setEditingRule(rule)
  }

  const handleEditClose = () => setEditingRule(null)

  // ── Render ─────────────────────────────────────────────────────

  return (
    <div className="p-6 min-h-screen bg-gray-900 text-white">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-6xl mx-auto">

        {/* ── Header ───────────────────────────────────────────── */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <ShieldOff className="text-yellow-400" size={26} />
              <h1 className="text-2xl font-bold">アラート抑制ルール</h1>
            </div>
            <p className="text-sm text-gray-400 ml-11">
              条件に一致するアラートを検知エンジンの手前で抑制します
            </p>
          </div>
          {canWrite && (
            <button
              onClick={() => { setShowCreateForm(v => !v); setEditingRule(null) }}
              className="flex items-center gap-2 bg-yellow-600 hover:bg-yellow-700 px-4 py-2 rounded-lg text-sm font-medium transition-colors shrink-0 mt-1"
            >
              <Plus size={16} />
              新しいルール
            </button>
          )}
        </div>

        {/* ── Stats bar ────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { label: '合計ルール数', value: totalRules, icon: <ShieldOff size={18} className="text-gray-400" /> },
            { label: '有効ルール', value: enabledCount, icon: <CheckCircle size={18} className="text-green-400" /> },
            {
              label: '累計抑制件数',
              value: totalSuppressed.toLocaleString(),
              icon: <XCircle size={18} className="text-yellow-400" />,
            },
          ].map(stat => (
            <div key={stat.label} className="bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 flex items-center gap-3">
              {stat.icon}
              <div>
                <p className="text-2xl font-bold leading-none">{stat.value}</p>
                <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* ── Filters ──────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3 mb-5">
          {/* Status filter pills */}
          <div className="flex items-center gap-1.5 bg-gray-800 border border-gray-700 rounded-lg p-1">
            <Filter size={13} className="text-gray-500 ml-1" />
            {(['all', 'enabled', 'disabled'] as FilterStatus[]).map(s => (
              <button
                key={s}
                onClick={() => setFilterStatus(s)}
                className={`px-3 py-1 rounded-sm text-xs font-medium transition-colors ${
                  filterStatus === s
                    ? 'bg-yellow-600 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                {s === 'all' ? 'すべて' : s === 'enabled' ? '有効' : '無効'}
              </button>
            ))}
          </div>

          {/* Search */}
          <div className="relative flex-1 min-w-48 max-w-72">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="名前・条件で検索..."
              className="w-full pl-8 pr-8 py-1.5 text-sm border border-gray-700 rounded-lg bg-gray-800 text-white placeholder-gray-600 focus:outline-hidden focus:border-yellow-500"
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white"
              >
                <X size={13} />
              </button>
            )}
          </div>

          <span className="text-xs text-gray-500 ml-auto">
            {visibleRules.length} / {totalRules} 件表示
          </span>
        </div>

        {/* ── Create Form ───────────────────────────────────────── */}
        {showCreateForm && (
          <RuleForm
            onSubmit={handleCreate}
            onCancel={() => setShowCreateForm(false)}
            isPending={createMutation.isPending}
            isError={createMutation.isError}
          />
        )}

        {/* ── Edit Form ─────────────────────────────────────────── */}
        {editingRule && (
          <RuleForm
            key={editingRule.id}
            editMode
            initial={ruleToForm(editingRule)}
            onSubmit={handleUpdate}
            onCancel={handleEditClose}
            isPending={updateMutation.isPending}
            isError={updateMutation.isError}
          />
        )}

        {/* ── Rules Table ───────────────────────────────────────── */}
        {isLoading ? (
          <div className="text-center py-16 text-gray-500">読み込み中...</div>
        ) : visibleRules.length === 0 ? (
          <div className="text-center py-16 text-gray-600">
            <ShieldOff size={52} className="mx-auto mb-4 opacity-25" />
            <p className="text-sm">
              {search || filterStatus !== 'all'
                ? '条件に一致するルールが見つかりません'
                : '抑制ルールがまだありません'}
            </p>
          </div>
        ) : (
          <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-xs text-gray-400 uppercase tracking-wide">
                  <th className="text-left px-4 py-3 font-medium">名前</th>
                  <th className="text-left px-4 py-3 font-medium">条件</th>
                  <th className="text-left px-4 py-3 font-medium">有効期限</th>
                  <th className="text-right px-4 py-3 font-medium">抑制数</th>
                  <th className="text-center px-4 py-3 font-medium">状態</th>
                  <th className="text-center px-4 py-3 font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/60">
                {visibleRules.map(rule => {
                  const expired = isExpired(rule.expires_at)
                  const rowClass = expired
                    ? 'opacity-50'
                    : !rule.is_active
                    ? 'opacity-60'
                    : ''

                  return (
                    <tr
                      key={rule.id}
                      className={`group hover:bg-gray-700/30 transition-colors ${rowClass}`}
                    >
                      {/* Name */}
                      <td className="px-4 py-3 align-top">
                        <div className="flex flex-col gap-0.5">
                          <span className={`font-medium ${expired ? 'line-through text-gray-500' : 'text-white'}`}>
                            {rule.name}
                          </span>
                          {expired && (
                            <span className="flex items-center gap-1 text-xs text-red-400">
                              <Clock size={10} />
                              期限切れ
                            </span>
                          )}
                          {rule.description && !expired && (
                            <span className="text-xs text-gray-500 truncate max-w-48">{rule.description}</span>
                          )}
                        </div>
                      </td>

                      {/* Conditions */}
                      <td className="px-4 py-3 align-top max-w-96">
                        <ConditionBadges conditions={rule.conditions} />
                      </td>

                      {/* Expiry */}
                      <td className="px-4 py-3 align-top whitespace-nowrap">
                        {rule.expires_at ? (
                          <span className={`flex items-center gap-1 text-xs ${expired ? 'text-red-400' : 'text-gray-400'}`}>
                            <Clock size={11} />
                            {formatExpiry(rule.expires_at)}
                          </span>
                        ) : (
                          <span className="text-xs text-gray-600">無期限</span>
                        )}
                      </td>

                      {/* Hit count */}
                      <td className="px-4 py-3 align-top text-right">
                        <span className="text-sm font-mono text-gray-300">
                          {(rule.hit_count ?? 0).toLocaleString()}
                        </span>
                      </td>

                      {/* Active toggle */}
                      <td className="px-4 py-3 align-top text-center">
                        {canWrite ? (
                          <button
                            onClick={() => toggleMutation.mutate({ id: rule.id, isActive: !rule.is_active })}
                            disabled={toggleMutation.isPending}
                            title={rule.is_active ? '無効にする' : '有効にする'}
                            className="inline-flex items-center gap-1 transition-colors disabled:opacity-40"
                          >
                            {rule.is_active ? (
                              <CheckCircle size={18} className="text-green-400 hover:text-green-300" />
                            ) : (
                              <XCircle size={18} className="text-gray-600 hover:text-gray-400" />
                            )}
                          </button>
                        ) : (
                          rule.is_active ? (
                            <CheckCircle size={18} className="text-green-400" />
                          ) : (
                            <XCircle size={18} className="text-gray-600" />
                          )
                        )}
                      </td>

                      {/* Edit / Delete */}
                      <td className="px-4 py-3 align-top text-center">
                        {canWrite && (
                          <div className="flex items-center justify-center gap-3 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button
                              onClick={() => handleEditOpen(rule)}
                              title="編集"
                              className="text-gray-400 hover:text-white transition-colors"
                            >
                              <Edit2 size={15} />
                            </button>
                            <button
                              onClick={() => {
                                if (confirm(`"${rule.name}" を削除しますか？\nこの操作は元に戻せません。`)) {
                                  deleteMutation.mutate(rule.id)
                                }
                              }}
                              title="削除"
                              className="text-red-500 hover:text-red-400 transition-colors"
                            >
                              <Trash2 size={15} />
                            </button>
                          </div>
                        )}
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
  )
}
