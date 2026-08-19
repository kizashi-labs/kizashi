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

interface SuppressionRule {
  id: string
  name: string
  pattern?: string
  field?: string
  match_type?: string
  enabled: boolean
  expires_at?: string
  hit_count?: number
  created_at: string
  notes?: string
}

interface SuppressionResponse {
  data: SuppressionRule[]
}

type FilterStatus = 'all' | 'enabled' | 'disabled'

const FIELD_OPTIONS = [
  { value: 'title',     label: 'タイトル' },
  { value: 'agent_id',  label: 'エージェントID' },
  { value: 'rule_name', label: 'ルール名' },
  { value: 'severity',  label: '重大度' },
] as const

const MATCH_TYPE_OPTIONS = [
  { value: 'exact',    label: '完全一致' },
  { value: 'contains', label: '部分一致' },
  { value: 'regex',    label: '正規表現' },
  { value: 'wildcard', label: 'ワイルドカード' },
] as const

const EMPTY_FORM = {
  name: '',
  field: 'title' as string,
  match_type: 'contains' as string,
  pattern: '',
  expires_at: '',
  notes: '',
  enabled: true,
}

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

function fieldLabel(field?: string): string {
  return FIELD_OPTIONS.find(f => f.value === field)?.label ?? field ?? '—'
}

function matchTypeLabel(mt?: string): string {
  return MATCH_TYPE_OPTIONS.find(m => m.value === mt)?.label ?? mt ?? '—'
}

// Client-side pattern preview — estimates how many rules could match a pattern
// by checking if pattern is non-empty (actual match count requires server data)
function previewMatchCount(
  pattern: string,
  matchType: string,
  allRules: SuppressionRule[],
): number {
  if (!pattern) return 0
  // Count existing rules whose own pattern would overlap (simple heuristic)
  return allRules.filter(r => {
    if (!r.pattern) return false
    try {
      if (matchType === 'exact') return r.pattern === pattern
      if (matchType === 'contains') return r.pattern.toLowerCase().includes(pattern.toLowerCase())
      if (matchType === 'regex') return new RegExp(pattern, 'i').test(r.pattern)
      if (matchType === 'wildcard') {
        const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i')
        return re.test(r.pattern)
      }
    } catch { /* invalid regex */ }
    return false
  }).length
}

// ── Field Badge ───────────────────────────────────────────────────────────────

function FieldBadge({ field }: { field?: string }) {
  const colours: Record<string, string> = {
    title:     'bg-blue-900/50 text-blue-300 border-blue-700/40',
    agent_id:  'bg-purple-900/50 text-purple-300 border-purple-700/40',
    rule_name: 'bg-teal-900/50 text-teal-300 border-teal-700/40',
    severity:  'bg-orange-900/50 text-orange-300 border-orange-700/40',
  }
  const cls = colours[field ?? ''] ?? 'bg-gray-700/50 text-gray-300 border-gray-600/40'
  return (
    <span className={`text-xs px-2 py-0.5 rounded-sm border ${cls}`}>
      {fieldLabel(field)}
    </span>
  )
}

// ── Match Type Badge ──────────────────────────────────────────────────────────

function MatchTypeBadge({ matchType }: { matchType?: string }) {
  const colours: Record<string, string> = {
    exact:    'bg-gray-700/60 text-gray-300',
    contains: 'bg-gray-700/60 text-gray-300',
    regex:    'bg-yellow-900/40 text-yellow-300',
    wildcard: 'bg-gray-700/60 text-gray-300',
  }
  const cls = colours[matchType ?? ''] ?? 'bg-gray-700/60 text-gray-300'
  return (
    <span className={`text-xs px-2 py-0.5 rounded-sm font-mono ${cls}`}>
      {matchTypeLabel(matchType)}
    </span>
  )
}

// ── Rule Form ─────────────────────────────────────────────────────────────────

interface RuleFormProps {
  initial?: typeof EMPTY_FORM & { id?: string }
  allRules: SuppressionRule[]
  onSubmit: (data: typeof EMPTY_FORM) => void
  onCancel: () => void
  isPending: boolean
  isError: boolean
  editMode?: boolean
}

function RuleForm({ initial, allRules, onSubmit, onCancel, isPending, isError, editMode }: RuleFormProps) {
  const [form, setForm] = useState<typeof EMPTY_FORM>(initial ?? EMPTY_FORM)

  const set = <K extends keyof typeof EMPTY_FORM>(k: K, v: (typeof EMPTY_FORM)[K]) =>
    setForm(f => ({ ...f, [k]: v }))

  const previewCount = useMemo(
    () => previewMatchCount(form.pattern, form.match_type, allRules),
    [form.pattern, form.match_type, allRules],
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
            placeholder="例: 定期スキャン除外"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:border-yellow-500 text-white placeholder-gray-600"
          />
        </div>

        {/* Row 2: field + match_type + pattern */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">対象フィールド</label>
            <select
              value={form.field}
              onChange={e => set('field', e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:border-yellow-500 text-white"
            >
              {FIELD_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">マッチタイプ</label>
            <select
              value={form.match_type}
              onChange={e => set('match_type', e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:border-yellow-500 text-white"
            >
              {MATCH_TYPE_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">パターン *</label>
            <input
              required
              value={form.pattern}
              onChange={e => set('pattern', e.target.value)}
              placeholder={
                form.match_type === 'regex' ? '例: ^mimikatz.*'
                : form.match_type === 'wildcard' ? '例: *scan*'
                : '例: mimikatz'
              }
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-hidden focus:border-yellow-500 text-white placeholder-gray-600"
            />
          </div>
        </div>

        {/* Preview */}
        {form.pattern && (
          <div className="flex items-center gap-2 text-sm px-3 py-2 rounded-lg bg-gray-900/60 border border-gray-700 text-gray-300">
            <AlertTriangle size={14} className="text-yellow-400 shrink-0" />
            このルールは既存の
            <span className="font-bold text-yellow-300">{previewCount}</span>
            件のルールパターンに一致します
          </div>
        )}

        {/* Row 3: expires_at + enabled */}
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
                aria-checked={form.enabled}
                onClick={() => set('enabled', !form.enabled)}
                className={`w-10 h-5 rounded-full transition-colors cursor-pointer ${
                  form.enabled ? 'bg-yellow-500' : 'bg-gray-600'
                }`}
              >
                <div className={`w-4 h-4 rounded-full bg-[#e2e8f4] mt-0.5 transition-transform shadow-sm ${
                  form.enabled ? 'translate-x-5.5' : 'translate-x-0.5'
                }`} />
              </div>
              {form.enabled ? 'ルール有効' : 'ルール無効'}
            </label>
          </div>
        </div>

        {/* notes */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">メモ (省略可)</label>
          <textarea
            rows={2}
            value={form.notes}
            onChange={e => set('notes', e.target.value)}
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

  // 有効/無効は PUT /suppressions/:id/toggle です。/toggle の無い
  // PUT /suppressions/:id はルートが無く、切り替えは効いていませんでした。
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/v1/suppressions/${id}/toggle`, { method: 'PUT', body: JSON.stringify({ enabled }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['suppressions'] }),
  })

  // ── Stats ──────────────────────────────────────────────────────

  const totalRules = allRules.length
  const enabledCount = allRules.filter(r => r.enabled).length
  const totalSuppressed = allRules.reduce((acc, r) => acc + (r.hit_count ?? 0), 0)

  // ── Filtered view ──────────────────────────────────────────────

  const visibleRules = useMemo(() => {
    return allRules.filter(r => {
      if (filterStatus === 'enabled' && !r.enabled) return false
      if (filterStatus === 'disabled' && r.enabled) return false
      if (search) {
        const q = search.toLowerCase()
        const nameMatch = r.name.toLowerCase().includes(q)
        const patternMatch = r.pattern?.toLowerCase().includes(q) ?? false
        if (!nameMatch && !patternMatch) return false
      }
      return true
    })
  }, [allRules, filterStatus, search])

  // ── Handlers ───────────────────────────────────────────────────

  const handleCreate = (form: typeof EMPTY_FORM) => {
    const body: Record<string, unknown> = {
      name: form.name,
      field: form.field,
      match_type: form.match_type,
      pattern: form.pattern,
      enabled: form.enabled,
    }
    if (form.expires_at) body.expires_at = new Date(form.expires_at).toISOString()
    if (form.notes) body.notes = form.notes
    createMutation.mutate(body)
  }

  const handleUpdate = (form: typeof EMPTY_FORM) => {
    if (!editingRule) return
    const body: Record<string, unknown> = {
      name: form.name,
      field: form.field,
      match_type: form.match_type,
      pattern: form.pattern,
      enabled: form.enabled,
    }
    if (form.expires_at) body.expires_at = new Date(form.expires_at).toISOString()
    if (form.notes) body.notes = form.notes
    updateMutation.mutate({ id: editingRule.id, body })
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
              特定のパターンに一致するアラートを自動的に抑制します
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
              placeholder="名前・パターンで検索..."
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
            allRules={allRules}
            onSubmit={handleCreate}
            onCancel={() => setShowCreateForm(false)}
            isPending={createMutation.isPending}
            isError={createMutation.isError}
          />
        )}

        {/* ── Edit Form ─────────────────────────────────────────── */}
        {editingRule && (
          <RuleForm
            editMode
            initial={{
              name: editingRule.name,
              field: editingRule.field ?? 'title',
              match_type: editingRule.match_type ?? 'contains',
              pattern: editingRule.pattern ?? '',
              expires_at: editingRule.expires_at
                ? new Date(editingRule.expires_at).toISOString().slice(0, 16)
                : '',
              notes: editingRule.notes ?? '',
              enabled: editingRule.enabled,
            }}
            allRules={allRules.filter(r => r.id !== editingRule.id)}
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
          <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-xs text-gray-400 uppercase tracking-wide">
                  <th className="text-left px-4 py-3 font-medium">名前</th>
                  <th className="text-left px-4 py-3 font-medium">フィールド</th>
                  <th className="text-left px-4 py-3 font-medium">タイプ</th>
                  <th className="text-left px-4 py-3 font-medium">パターン</th>
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
                    : !rule.enabled
                    ? 'opacity-60'
                    : ''

                  return (
                    <tr
                      key={rule.id}
                      className={`group hover:bg-gray-700/30 transition-colors ${rowClass}`}
                    >
                      {/* Name */}
                      <td className="px-4 py-3">
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
                          {rule.notes && !expired && (
                            <span className="text-xs text-gray-500 truncate max-w-48">{rule.notes}</span>
                          )}
                        </div>
                      </td>

                      {/* Field badge */}
                      <td className="px-4 py-3">
                        <FieldBadge field={rule.field} />
                      </td>

                      {/* Match type badge */}
                      <td className="px-4 py-3">
                        <MatchTypeBadge matchType={rule.match_type} />
                      </td>

                      {/* Pattern */}
                      <td className="px-4 py-3 max-w-56">
                        <code className="text-xs font-mono text-gray-300 bg-gray-900/60 px-2 py-0.5 rounded-sm truncate block max-w-full">
                          {rule.pattern ?? '—'}
                        </code>
                      </td>

                      {/* Expiry */}
                      <td className="px-4 py-3 whitespace-nowrap">
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
                      <td className="px-4 py-3 text-right">
                        <span className="text-sm font-mono text-gray-300">
                          {(rule.hit_count ?? 0).toLocaleString()}
                        </span>
                      </td>

                      {/* Enabled toggle */}
                      <td className="px-4 py-3 text-center">
                        {canWrite ? (
                          <button
                            onClick={() => toggleMutation.mutate({ id: rule.id, enabled: !rule.enabled })}
                            disabled={toggleMutation.isPending}
                            title={rule.enabled ? '無効にする' : '有効にする'}
                            className="inline-flex items-center gap-1 transition-colors disabled:opacity-40"
                          >
                            {rule.enabled ? (
                              <CheckCircle size={18} className="text-green-400 hover:text-green-300" />
                            ) : (
                              <XCircle size={18} className="text-gray-600 hover:text-gray-400" />
                            )}
                          </button>
                        ) : (
                          rule.enabled ? (
                            <CheckCircle size={18} className="text-green-400" />
                          ) : (
                            <XCircle size={18} className="text-gray-600" />
                          )
                        )}
                      </td>

                      {/* Edit / Delete */}
                      <td className="px-4 py-3 text-center">
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
