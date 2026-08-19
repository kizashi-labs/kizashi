'use client'

import React, { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Search, Plus, Edit2, Trash2, Play, X, RefreshCw,
  BookMarked, Tag, User, Clock, Hash, Share2, ChevronDown,
  AlertCircle, Zap, Monitor, Network, Filter, CheckCircle,
  SlidersHorizontal,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'
import { VerdictUnavailable } from '@/components/VerdictUnavailable'
import { SaveFailed, saveErrorOf } from '@/lib/persist'

// ── Types ──────────────────────────────────────────────────────────────────────

type Category = 'alerts' | 'events' | 'endpoints' | 'network'

interface SavedSearch {
  id: string
  name: string
  query: string
  category: Category
  description?: string
  created_by: string
  created_at: string
  last_run?: string
  run_count: number
  shared: boolean
}

interface SavedSearchPayload {
  name: string
  query: string
  category: Category
  description: string
  shared: boolean
}

interface RunResult {
  search_id: string
  result_count: number
  elapsed_ms: number
  executed_at: string
}

const CATEGORY_OPTIONS: { value: string; label: string }[] = [
  { value: 'all', label: 'すべて' },
  { value: 'threat_hunting', label: '脅威ハンティング' },
  { value: 'incident_response', label: 'インシデント対応' },
  { value: 'compliance', label: 'コンプライアンス' },
  { value: 'forensics', label: 'フォレンジクス' },
  { value: 'performance', label: 'パフォーマンス' },
]

const CATEGORY_ICONS: Record<Category, React.ElementType> = {
  alerts: AlertCircle,
  events: Zap,
  endpoints: Monitor,
  network: Network,
}
const CATEGORY_STYLES: Record<Category, string> = {
  alerts: 'bg-red-500/20 text-red-400',
  events: 'bg-blue-500/20 text-blue-400',
  endpoints: 'bg-green-500/20 text-green-400',
  network: 'bg-cyan-500/20 text-cyan-400',
}
const CATEGORY_LABELS: Record<Category, string> = {
  alerts: 'アラート',
  events: 'イベント',
  endpoints: 'エンドポイント',
  network: 'ネットワーク',
}
const DEFAULT_PAYLOAD: SavedSearchPayload = { name: '', query: '', category: 'alerts', description: '', shared: false }

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDateTime(iso?: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return '—' }
}

function fmtDate(iso?: string): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString('ja-JP') } catch { return '—' }
}

// ── Category Badge ─────────────────────────────────────────────────────────────

function CategoryBadge({ category }: { category: Category }) {
  const Icon = CATEGORY_ICONS[category]
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full ${CATEGORY_STYLES[category]}`}>
      <Icon className="w-3 h-3" />
      {CATEGORY_LABELS[category]}
    </span>
  )
}

// ── Run Results Slide-over ─────────────────────────────────────────────────────

interface RunResultPanelProps {
  search: SavedSearch
  result: RunResult | null
  error: string | null
  loading: boolean
  onClose: () => void
}

function RunResultPanel({ search, result, error, loading, onClose }: RunResultPanelProps) {
  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="w-[480px] bg-[#0d1220] border-l border-[#1e2d42] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#e8002d]/15 flex items-center justify-center">
              <Play className="w-4 h-4 text-[#e8002d]" />
            </div>
            <div>
              <h3 className="text-white font-semibold text-sm">検索実行結果</h3>
              <p className="text-[#7d92b0] text-xs mt-0.5 truncate max-w-[280px]">{search.name}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors p-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 p-6 space-y-5 overflow-y-auto">
          {loading ? (
            <div className="flex flex-col items-center justify-center gap-3 py-16">
              <div className="w-10 h-10 border-2 border-[#e8002d] border-t-transparent rounded-full animate-spin" />
              <p className="text-[#7d92b0] text-sm">検索を実行中...</p>
            </div>
          ) : error ? (
            <VerdictUnavailable what="保存済み検索の実行" detail={error} />
          ) : result ? (
            <>
              {/* Result count */}
              <div className="bg-[#070d19] rounded-xl border border-[#1e2d42] p-5 text-center">
                <p className="text-[#7d92b0] text-xs mb-2">マッチした件数</p>
                <p className="text-5xl font-bold text-white">{(result.result_count ?? 0).toLocaleString()}</p>
                <p className="text-[#7d92b0] text-xs mt-2">件のレコード</p>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
                  <p className="text-[#7d92b0] text-xs mb-1">実行時間</p>
                  <p className="text-white font-semibold">{result.elapsed_ms} ms</p>
                </div>
                <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
                  <p className="text-[#7d92b0] text-xs mb-1">実行日時</p>
                  <p className="text-white font-semibold text-xs">{fmtDateTime(result.executed_at)}</p>
                </div>
              </div>

              {/* Query */}
              <div>
                <p className="text-[#7d92b0] text-xs font-medium mb-2 flex items-center gap-1.5">
                  <Hash className="w-3.5 h-3.5" />
                  実行クエリ
                </p>
                <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
                  <code className="text-green-400 text-xs font-mono break-all">{search.query}</code>
                </div>
              </div>

              <div className="bg-blue-900/20 border border-blue-700/30 rounded-lg p-3 flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                <p className="text-blue-300 text-xs">
                  検索が正常に完了しました。詳細な結果は「検索」ページで確認できます。
                </p>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  )
}

// ── Save/Edit Modal ────────────────────────────────────────────────────────────

interface SearchModalProps {
  mode: 'create' | 'edit'
  initial: SavedSearchPayload
  onSubmit: (payload: SavedSearchPayload) => void
  onClose: () => void
  loading: boolean
}

function SearchModal({ mode, initial, onSubmit, onClose, loading }: SearchModalProps) {
  const [form, setForm] = useState<SavedSearchPayload>(initial)

  const set = <K extends keyof SavedSearchPayload>(k: K, v: SavedSearchPayload[K]) =>
    setForm(p => ({ ...p, [k]: v }))

  const valid = form.name.trim().length > 0 && form.query.trim().length > 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#1a6bff]/15 flex items-center justify-center">
              <BookMarked className="w-4 h-4 text-[#1a6bff]" />
            </div>
            <h3 className="text-white font-semibold">
              {mode === 'create' ? '保存済み検索を作成' : '保存済み検索を編集'}
            </h3>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <div className="px-6 py-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-[#7d92b0] text-xs font-medium mb-1.5">
              検索名 <span className="text-[#e8002d]">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="例: クリティカルアラート - 過去24時間"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder-[#3d5275] focus:outline-hidden focus:border-[#1a6bff] transition-colors"
            />
          </div>

          {/* Query */}
          <div>
            <label className="block text-[#7d92b0] text-xs font-medium mb-1.5">
              クエリ <span className="text-[#e8002d]">*</span>
            </label>
            <textarea
              rows={4}
              value={form.query}
              onChange={e => set('query', e.target.value)}
              placeholder="severity:critical AND timestamp:>now-24h"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder-[#3d5275] font-mono focus:outline-hidden focus:border-[#1a6bff] transition-colors resize-none"
            />
          </div>

          {/* Category */}
          <div>
            <label className="block text-[#7d92b0] text-xs font-medium mb-1.5">カテゴリ</label>
            <div className="relative">
              <select
                value={form.category}
                onChange={e => set('category', e.target.value as Category)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm appearance-none focus:outline-hidden focus:border-[#1a6bff] transition-colors pr-8"
              >
                <option value="alerts">アラート</option>
                <option value="events">イベント</option>
                <option value="endpoints">エンドポイント</option>
                <option value="network">ネットワーク</option>
              </select>
              <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0] pointer-events-none" />
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-[#7d92b0] text-xs font-medium mb-1.5">説明</label>
            <input
              type="text"
              value={form.description}
              onChange={e => set('description', e.target.value)}
              placeholder="この検索の目的や使用方法を説明..."
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm placeholder-[#3d5275] focus:outline-hidden focus:border-[#1a6bff] transition-colors"
            />
          </div>

          {/* Shared toggle */}
          <div className="flex items-center justify-between py-2">
            <div className="flex items-center gap-2">
              <Share2 className="w-4 h-4 text-[#7d92b0]" />
              <div>
                <p className="text-white text-sm">チームで共有</p>
                <p className="text-[#7d92b0] text-xs">有効にするとすべてのユーザーが使用できます</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => set('shared', !form.shared)}
              className={`w-10 h-5 rounded-full transition-colors relative ${form.shared ? 'bg-[#1a6bff]' : 'bg-[#1e2d42]'}`}
            >
              <span className={`absolute top-0.5 w-4 h-4 bg-[#e2e8f4] rounded-full shadow-sm transition-transform
                               ${form.shared ? 'translate-x-5' : 'translate-x-0.5'}`} />
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#2d4060] rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSubmit(form)}
            disabled={!valid || loading}
            className="px-4 py-2 text-sm text-white bg-[#1a6bff] hover:bg-[#1558e0] rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {loading && <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />}
            {mode === 'create' ? '作成' : '保存'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Delete Confirm Modal ───────────────────────────────────────────────────────

function DeleteModal({ search, onConfirm, onClose, loading }: {
  search: SavedSearch
  onConfirm: () => void
  onClose: () => void
  loading: boolean
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-sm bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-[#e8002d]/15 flex items-center justify-center shrink-0">
            <Trash2 className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h3 className="text-white font-semibold">削除の確認</h3>
            <p className="text-[#7d92b0] text-xs mt-0.5">この操作は元に戻せません</p>
          </div>
        </div>
        <p className="text-[#7d92b0] text-sm mb-5">
          「<span className="text-white font-medium">{search.name}</span>」を削除します。よろしいですか？
        </p>
        <div className="flex items-center justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#2d4060] rounded-lg transition-colors">
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={loading}
            className="px-4 py-2 text-sm text-white bg-[#e8002d] hover:bg-[#c20026] rounded-lg transition-colors disabled:opacity-40 flex items-center gap-2"
          >
            {loading && <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />}
            削除する
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function SavedSearchesPage() {
  const qc = useQueryClient()

  // Filters
  const [nameFilter, setNameFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<Category | ''>('')

  // Modal state
  const [showCreate, setShowCreate] = useState(false)
  const [editTarget, setEditTarget] = useState<SavedSearch | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SavedSearch | null>(null)

  // Run panel state
  const [runTarget, setRunTarget]   = useState<SavedSearch | null>(null)
  const [runResult, setRunResult]   = useState<RunResult | null>(null)
  const [runError, setRunError]     = useState<string | null>(null)
  const [runLoading, setRunLoading] = useState(false)

  // ── API Queries ──────────────────────────────────────────────────────────────

  const { data: searches = [], isLoading, refetch } = useQuery<SavedSearch[]>({
    queryKey: ['admin-saved-searches'],
    queryFn: () => apiFetchList<SavedSearch>('/api/v1/admin/saved-searches'),
    staleTime: 30_000,
  })

  const createMutation = useMutation({
    mutationFn: (payload: SavedSearchPayload) =>
      apiFetch<SavedSearch>('/api/v1/admin/saved-searches', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin-saved-searches'] }); setShowCreate(false) },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: SavedSearchPayload }) =>
      apiFetch<SavedSearch>(`/api/v1/admin/saved-searches/${id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin-saved-searches'] }); setEditTarget(null) },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      // .catch(() => null) で失敗が成功になり、削除できていないのに
      // 一覧から消えたように見えていました。
      apiFetch(`/api/v1/admin/saved-searches/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin-saved-searches'] }); setDeleteTarget(null) },
  })

  // ── Run Search ───────────────────────────────────────────────────────────────

  async function handleRun(search: SavedSearch) {
    setRunTarget(search)
    setRunResult(null)
    setRunError(null)
    setRunLoading(true)
    try {
      const result = await apiFetch<RunResult>(`/api/v1/admin/saved-searches/${search.id}/run`, { method: 'POST' })
      setRunResult(result)
    } catch (e) {
      // ここは result_count: Math.floor(Math.random() * 5000) + 50 でした。
      // 検索が実行できなかったときに「3,412件マッチ・210ms」のような
      // 具体的な結果を大きな数字で表示していました。ハンティングの
      // クエリを評価している人が、その件数を根拠に次を決めます。
      setRunError(e instanceof Error ? e.message : '不明なエラー')
    } finally {
      setRunLoading(false)
    }
  }

  // ── Filtered list ────────────────────────────────────────────────────────────

  const filtered = useMemo(() => {
    let list = searches
    if (categoryFilter) list = list.filter(s => s.category === categoryFilter)
    if (nameFilter.trim()) {
      const q = nameFilter.toLowerCase()
      list = list.filter(s => s.name.toLowerCase().includes(q) || s.query.toLowerCase().includes(q))
    }
    return list
  }, [searches, categoryFilter, nameFilter])

  // ── Stats ────────────────────────────────────────────────────────────────────

  const stats = useMemo(() => ({
    total: searches.length,
    shared: searches.filter(s => s.shared).length,
    byCategory: Object.fromEntries(
      (['alerts', 'events', 'endpoints', 'network'] as Category[]).map(c => [c, searches.filter(s => s.category === c).length])
    ) as Record<Category, number>,
  }), [searches])

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <PageDataUnavailable />
      <PageSaveFailed />
      <SaveFailed error={saveErrorOf('保存済み検索', deleteMutation)} />
      {/* Modals */}
      {showCreate && (
        <SearchModal
          mode="create"
          initial={DEFAULT_PAYLOAD}
          onSubmit={p => createMutation.mutate(p)}
          onClose={() => setShowCreate(false)}
          loading={createMutation.isPending}
        />
      )}
      {editTarget && (
        <SearchModal
          mode="edit"
          initial={{ name: editTarget.name, query: editTarget.query, category: editTarget.category, description: editTarget.description ?? '', shared: editTarget.shared }}
          onSubmit={p => updateMutation.mutate({ id: editTarget.id, payload: p })}
          onClose={() => setEditTarget(null)}
          loading={updateMutation.isPending}
        />
      )}
      {deleteTarget && (
        <DeleteModal
          search={deleteTarget}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onClose={() => setDeleteTarget(null)}
          loading={deleteMutation.isPending}
        />
      )}
      {runTarget && (
        <RunResultPanel
          search={runTarget}
          result={runResult}
          error={runError}
          loading={runLoading}
          onClose={() => { setRunTarget(null); setRunResult(null); setRunError(null) }}
        />
      )}

      <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
        {/* Page Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-[#1a6bff]/15 border border-[#1a6bff]/30 flex items-center justify-center">
              <BookMarked className="w-5 h-5 text-[#1a6bff]" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">保存済み検索</h1>
              <p className="text-[#7d92b0] text-sm mt-0.5">
                よく使う検索クエリを保存・管理します
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              className="p-2 text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#2d4060] rounded-lg transition-colors"
              title="更新"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] hover:bg-[#1558e0] text-white text-sm font-medium rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              新規作成
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {/* Total */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 col-span-1">
            <p className="text-[#7d92b0] text-xs mb-1">合計</p>
            <p className="text-2xl font-bold text-white">{stats.total}</p>
          </div>
          {/* Shared */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 col-span-1">
            <p className="text-[#7d92b0] text-xs mb-1">共有中</p>
            <p className="text-2xl font-bold text-white">{stats.shared}</p>
          </div>
          {/* Category counts */}
          {(['alerts', 'events', 'endpoints', 'network'] as Category[]).map(cat => {
            const Icon = CATEGORY_ICONS[cat]
            return (
              <div key={cat} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
                <div className="flex items-center gap-1.5 mb-1">
                  <Icon className="w-3.5 h-3.5 text-[#7d92b0]" />
                  <p className="text-[#7d92b0] text-xs">{CATEGORY_LABELS[cat]}</p>
                </div>
                <p className="text-2xl font-bold text-white">{stats.byCategory[cat]}</p>
              </div>
            )
          })}
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
            <input
              type="text"
              value={nameFilter}
              onChange={e => setNameFilter(e.target.value)}
              placeholder="名前またはクエリで検索..."
              className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2 text-white text-sm placeholder-[#3d5275] focus:outline-hidden focus:border-[#1a6bff] transition-colors"
            />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
            <select
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value as Category | '')}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-9 pr-8 py-2 text-white text-sm appearance-none focus:outline-hidden focus:border-[#1a6bff] transition-colors"
            >
              {CATEGORY_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0] pointer-events-none" />
          </div>
          {(nameFilter || categoryFilter) && (
            <button
              onClick={() => { setNameFilter(''); setCategoryFilter('') }}
              className="flex items-center gap-1.5 px-3 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#2d4060] rounded-lg transition-colors"
            >
              <X className="w-3.5 h-3.5" />
              クリア
            </button>
          )}
          <p className="flex items-center text-[#7d92b0] text-sm ml-auto">
            <SlidersHorizontal className="w-3.5 h-3.5 mr-1.5" />
            {filtered.length} / {searches.length} 件
          </p>
        </div>

        {/* Table */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-48">
              <div className="w-7 h-7 border-2 border-[#e8002d] border-t-transparent rounded-full animate-spin" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 h-48">
              <BookMarked className="w-10 h-10 text-[#3d5275]" />
              <p className="text-[#7d92b0]">保存済み検索が見つかりません</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['名前 / クエリ', 'カテゴリ', '作成者', '最終実行', '実行数', '共有', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((s, i) => (
                    <tr
                      key={s.id}
                      className={`border-b border-[#1e2d42]/50 hover:bg-[#111827]/60 transition-colors
                                  ${i === filtered.length - 1 ? 'border-0' : ''}`}
                    >
                      {/* Name / Query */}
                      <td className="px-4 py-3 max-w-[280px]">
                        <p className="text-white text-sm font-medium truncate">{s.name}</p>
                        <p className="text-[#7d92b0] text-xs font-mono truncate mt-0.5">{s.query}</p>
                        {s.description && (
                          <p className="text-[#4d6480] text-xs truncate mt-0.5">{s.description}</p>
                        )}
                      </td>

                      {/* Category */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <CategoryBadge category={s.category} />
                      </td>

                      {/* Created by */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-[#7d92b0] shrink-0" />
                          <span className="text-[#7d92b0] text-xs truncate max-w-[120px]">{s.created_by}</span>
                        </div>
                        <p className="text-[#4d6480] text-xs mt-0.5">{fmtDate(s.created_at)}</p>
                      </td>

                      {/* Last run */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-[#7d92b0]" />
                          <span className="text-[#7d92b0] text-xs">{fmtDateTime(s.last_run)}</span>
                        </div>
                      </td>

                      {/* Run count */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Hash className="w-3.5 h-3.5 text-[#7d92b0]" />
                          <span className="text-white text-sm font-medium">{s.run_count}</span>
                        </div>
                      </td>

                      {/* Shared */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        {s.shared ? (
                          <span className="inline-flex items-center gap-1 text-xs text-green-400">
                            <Share2 className="w-3.5 h-3.5" />
                            共有
                          </span>
                        ) : (
                          <span className="text-[#3d5275] text-xs">非公開</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleRun(s)}
                            title="実行"
                            className="p-1.5 text-[#7d92b0] hover:text-green-400 hover:bg-green-900/20 rounded-lg transition-colors"
                          >
                            <Play className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => setEditTarget(s)}
                            title="編集"
                            className="p-1.5 text-[#7d92b0] hover:text-[#1a6bff] hover:bg-[#1a6bff]/10 rounded-lg transition-colors"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => setDeleteTarget(s)}
                            title="削除"
                            className="p-1.5 text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 rounded-lg transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
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
      </div>
    </div>
  )
}
