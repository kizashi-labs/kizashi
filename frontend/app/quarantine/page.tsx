'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import { formatDistanceToNow, parseISO, format } from 'date-fns'
import { ja } from 'date-fns/locale'
import {
  Archive, RotateCcw, Trash2, RefreshCw, Search, ShieldCheck, X,
  Clock, History, CheckSquare, Square, AlertTriangle, FileText,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────

interface QuarantinedFile {
  id: string
  agent_id: string
  agent_hostname?: string
  alert_id?: string
  original_path: string
  file_size?: number
  hash_md5?: string
  hash_sha256?: string
  quarantine_reason?: string
  quarantine_notes?: string
  quarantined_by?: string
  quarantined_at: string
  restored_at?: string
  restored_by?: string
}

interface QuarantineResponse {
  data: QuarantinedFile[]
  total: number
  page: number
  per_page: number
  has_more: boolean
}

interface QuarantineHistoryEvent {
  id: string
  file_id: string
  agent_id: string
  original_path: string
  event_type: 'quarantined' | 'restored' | 'deleted'
  performed_by?: string
  reason?: string
  notes?: string
  occurred_at: string
}

// ─── Helpers ──────────────────────────────────────────────────

function formatBytes(bytes?: number): string {
  if (bytes == null) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatDuration(quarantinedAt: string): string {
  try {
    return formatDistanceToNow(parseISO(quarantinedAt), { addSuffix: false, locale: ja })
  } catch {
    return '—'
  }
}

const STATUS_OPTIONS = ['', 'quarantined', 'restored'] as const
const STATUS_LABELS: Record<string, string> = { '': 'すべて', quarantined: '検疫中', restored: '復元済み' }

// ─── Quarantine Reason Modal ──────────────────────────────────

function QuarantineModal({
  fileId,
  filePath,
  agentId,
  onClose,
  onSuccess,
}: {
  fileId: string
  filePath: string
  agentId: string
  onClose: () => void
  onSuccess: () => void
}) {
  const [reason, setReason] = useState('')
  const [notes, setNotes] = useState('')

  const restore = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/quarantine/${fileId}/restore`, {
        method: 'POST',
        body: JSON.stringify({ agent_id: agentId, reason, notes }),
      }),
    onSuccess: () => {
      onSuccess()
      onClose()
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl shadow-2xl w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-white font-semibold text-lg flex items-center gap-2">
            <RotateCcw className="w-5 h-5 text-green-400" />
            ファイルを復元
          </h3>
          <button onClick={onClose} className="text-[#8899aa] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <p className="text-[#8899aa] text-sm font-mono break-all">{filePath}</p>
        <div>
          <label className="block text-xs text-[#8899aa] mb-1.5">復元理由</label>
          <input
            type="text"
            placeholder="例: 誤検知、調査完了..."
            value={reason}
            onChange={e => setReason(e.target.value)}
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-white text-sm placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#1a6bff]"
          />
        </div>
        <div>
          <label className="block text-xs text-[#8899aa] mb-1.5">備考</label>
          <textarea
            rows={3}
            placeholder="追加のメモや備考..."
            value={notes}
            onChange={e => setNotes(e.target.value)}
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-white text-sm placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#1a6bff] resize-none"
          />
        </div>
        <div className="flex gap-3 pt-2">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#161f33] hover:bg-[#1d2f4a] text-white text-sm rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => restore.mutate()}
            disabled={restore.isPending}
            className="flex-1 px-4 py-2 bg-green-700 hover:bg-green-600 text-white text-sm rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {restore.isPending ? (
              <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-white" />
            ) : (
              <RotateCcw className="w-4 h-4" />
            )}
            復元する
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── History Tab ──────────────────────────────────────────────

function HistoryTab() {
  const { data, isLoading } = useQuery<QuarantineResponse, Error, { data: QuarantineHistoryEvent[]; total: number }>({
    queryKey: ['quarantine-history'],
    queryFn: () => apiFetch<QuarantineResponse>('/api/v1/quarantine?status=&page=1&per_page=100'),
    select: (raw) => ({
      total: raw.total,
      data: raw.data.map(f => ({
        id: f.id,
        file_id: f.id,
        agent_id: f.agent_id,
        original_path: f.original_path,
        event_type: (f.restored_at ? 'restored' : 'quarantined') as QuarantineHistoryEvent['event_type'],
        performed_by: f.restored_at ? f.restored_by : f.quarantined_by,
        reason: f.quarantine_reason,
        notes: f.quarantine_notes,
        occurred_at: f.restored_at ?? f.quarantined_at,
      })),
    }),
  })

  const events = data?.data ?? []

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-yellow-500" />
      </div>
    )
  }

  if (events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-[#5a6a7a]">
        <History className="w-12 h-12 mb-3 opacity-30" />
        <p className="text-sm">履歴はありません</p>
      </div>
    )
  }

  return (
    <div className="relative pl-6">
      {/* Timeline line */}
      <div className="absolute left-2.5 top-0 bottom-0 w-px bg-[#1e2d42]" />

      <div className="space-y-4">
        {events.map(ev => (
          <div key={ev.id} className="relative">
            {/* Dot */}
            <div
              className={`absolute -left-4 top-1.5 w-3 h-3 rounded-full border-2 border-[#111827] ${
                ev.event_type === 'quarantined'
                  ? 'bg-yellow-500'
                  : ev.event_type === 'restored'
                  ? 'bg-green-500'
                  : 'bg-red-500'
              }`}
            />

            <div className="bg-[#111827] border border-[#1e2d42] rounded-lg p-4 space-y-1.5">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <span
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium mb-1 ${
                      ev.event_type === 'quarantined'
                        ? 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50'
                        : ev.event_type === 'restored'
                        ? 'bg-green-900/40 text-green-300 border border-green-700/50'
                        : 'bg-red-900/40 text-red-300 border border-red-700/50'
                    }`}
                  >
                    {ev.event_type === 'quarantined' ? (
                      <Archive className="w-3 h-3" />
                    ) : ev.event_type === 'restored' ? (
                      <ShieldCheck className="w-3 h-3" />
                    ) : (
                      <Trash2 className="w-3 h-3" />
                    )}
                    {ev.event_type === 'quarantined'
                      ? '検疫'
                      : ev.event_type === 'restored'
                      ? '復元'
                      : '削除'}
                  </span>
                  <p className="text-white text-sm font-mono truncate" title={ev.original_path}>
                    {ev.original_path}
                  </p>
                </div>
                <time className="text-[#5a6a7a] text-xs whitespace-nowrap shrink-0">
                  {format(parseISO(ev.occurred_at), 'yyyy/MM/dd HH:mm', { locale: ja })}
                </time>
              </div>
              <div className="flex items-center gap-4 text-xs text-[#8899aa]">
                {ev.performed_by && (
                  <span>実行者: {ev.performed_by}</span>
                )}
                {ev.reason && (
                  <span className="flex items-center gap-1">
                    <FileText className="w-3 h-3" />
                    {ev.reason}
                  </span>
                )}
              </div>
              {ev.notes && (
                <p className="text-xs text-[#5a6a7a] italic">{ev.notes}</p>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────

export default function QuarantinePage() {
  const canWrite = useCanWrite()
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'active' | 'history'>('active')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('quarantined')
  const [page, setPage] = useState(1)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [restoreModal, setRestoreModal] = useState<{
    id: string; path: string; agentId: string
  } | null>(null)
  const perPage = 20

  const { data, isLoading, isFetching } = useQuery<QuarantineResponse>({
    queryKey: ['quarantine', search, statusFilter, page],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
      if (search) params.set('search', search)
      if (statusFilter) params.set('status', statusFilter)
      return apiFetch(`/api/v1/quarantine?${params}`)
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/quarantine/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['quarantine'] }),
  })

  const bulkRelease = useMutation({
    mutationFn: async (ids: string[]) => {
      await Promise.all(
        ids.map(id =>
          apiFetch(`/api/v1/quarantine/${id}/release`, { method: 'POST' })
        )
      )
    },
    onSuccess: () => {
      setSelectedIds(new Set())
      qc.invalidateQueries({ queryKey: ['quarantine'] })
    },
  })

  const files = data?.data ?? []

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedIds.size === files.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(files.map(f => f.id)))
    }
  }

  const canBulkRelease = selectedIds.size > 0 && [...selectedIds].every(id => {
    const f = files.find(x => x.id === id)
    return f && !f.restored_at
  })

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Archive className="w-6 h-6 text-yellow-400" />
            検疫管理
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            エンドポイントで検疫されたファイルの管理と履歴
          </p>
        </div>
        <div className="flex items-center gap-3">
          {canWrite && selectedIds.size > 0 && (
            <button
              onClick={() => {
                if (confirm(`選択した ${selectedIds.size} 件を一括リリースしますか？`)) {
                  bulkRelease.mutate([...selectedIds])
                }
              }}
              disabled={!canBulkRelease || bulkRelease.isPending}
              className="flex items-center gap-1.5 px-3 py-2 bg-green-800 hover:bg-green-700 text-white text-sm rounded-lg transition-colors disabled:opacity-50"
            >
              <ShieldCheck className="w-4 h-4" />
              一括リリース ({selectedIds.size})
            </button>
          )}
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ['quarantine'] })}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#161f33] hover:bg-[#1d2f4a] text-white text-sm rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#080c14]/60 border border-[#1e2d42] rounded-xl p-1 w-fit">
        {([['active', Archive, 'アクティブ検疫'], ['history', History, '履歴']] as const).map(
          ([tab, Icon, label]) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab
                  ? 'bg-yellow-600 text-white shadow-lg'
                  : 'text-[#8899aa] hover:text-white hover:bg-[#161f33]'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          )
        )}
      </div>

      {activeTab === 'active' ? (
        <>
          {/* Filter */}
          <div className="space-y-3">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#8899aa]" />
                <input
                  type="text"
                  placeholder="ファイルパス・ハッシュで検索..."
                  value={search}
                  onChange={e => { setSearch(e.target.value); setPage(1) }}
                  className="pl-9 pr-4 py-2 bg-[#111827] border border-[#1e2d42] rounded-lg text-white text-sm placeholder-[#5a6a7a] focus:outline-hidden focus:border-[#1a6bff] w-64"
                />
              </div>
              {search && (
                <button
                  onClick={() => { setSearch(''); setPage(1) }}
                  className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-white px-2 py-2 rounded-lg hover:bg-[#161f33] transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
              {data && (
                <span className="text-[#8899aa] text-sm ml-auto">{data.total}件</span>
              )}
            </div>
            <div className="flex gap-2">
              {STATUS_OPTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => { setStatusFilter(s); setPage(1) }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    statusFilter === s
                      ? 'bg-yellow-600 text-white'
                      : 'bg-[#111827] border border-[#1e2d42] text-[#8899aa] hover:text-white'
                  }`}
                >
                  {STATUS_LABELS[s]}
                </button>
              ))}
            </div>
          </div>

          {/* Bulk action bar */}
          {files.length > 0 && (
            <div className="flex items-center gap-3 px-4 py-2 bg-[#080c14]/60 border border-[#1e2d42] rounded-lg text-sm">
              <button
                onClick={toggleSelectAll}
                className="flex items-center gap-2 text-[#8899aa] hover:text-white transition-colors"
              >
                {selectedIds.size === files.length && files.length > 0 ? (
                  <CheckSquare className="w-4 h-4 text-yellow-400" />
                ) : (
                  <Square className="w-4 h-4" />
                )}
                <span>
                  {selectedIds.size > 0
                    ? `${selectedIds.size}件選択中`
                    : 'すべて選択'}
                </span>
              </button>
              {selectedIds.size > 0 && (
                <button
                  onClick={() => setSelectedIds(new Set())}
                  className="text-[#5a6a7a] hover:text-white transition-colors flex items-center gap-1"
                >
                  <X className="w-3.5 h-3.5" />
                  選択解除
                </button>
              )}
            </div>
          )}

          {/* Table */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center py-16">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-yellow-500" />
              </div>
            ) : files.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-[#5a6a7a]">
                <Archive className="w-12 h-12 mb-3 opacity-30" />
                <p className="text-sm">検疫ファイルはありません</p>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[#8899aa] text-xs border-b border-[#1e2d42] bg-[#080c14]/30">
                    <th className="px-4 py-3 w-8" />
                    <th className="px-4 py-3">ファイルパス</th>
                    <th className="px-4 py-3">端末名</th>
                    <th className="px-4 py-3">サイズ</th>
                    <th className="px-4 py-3">SHA256</th>
                    <th className="px-4 py-3">検疫理由</th>
                    <th className="px-4 py-3">検疫者</th>
                    <th className="px-4 py-3">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" />
                        検疫期間
                      </span>
                    </th>
                    <th className="px-4 py-3">状態</th>
                    <th className="px-4 py-3 text-right">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {files.map(f => (
                    <tr
                      key={f.id}
                      className={`hover:bg-[#161f33] transition-colors ${f.restored_at ? 'opacity-50' : ''} ${
                        selectedIds.has(f.id) ? 'bg-yellow-900/10' : ''
                      }`}
                    >
                      <td className="px-4 py-3">
                        <button
                          onClick={() => toggleSelect(f.id)}
                          className="text-[#8899aa] hover:text-yellow-400 transition-colors"
                        >
                          {selectedIds.has(f.id) ? (
                            <CheckSquare className="w-4 h-4 text-yellow-400" />
                          ) : (
                            <Square className="w-4 h-4" />
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-white" title={f.original_path}>
                          {f.original_path.length > 45
                            ? '...' + f.original_path.slice(-42)
                            : f.original_path}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#8899aa]" title={f.agent_id}>
                        {f.agent_hostname ?? f.agent_id.slice(0, 8) + '...'}
                      </td>
                      <td className="px-4 py-3 text-[#8899aa] text-xs">{formatBytes(f.file_size)}</td>
                      <td className="px-4 py-3 font-mono text-xs text-[#5a6a7a]" title={f.hash_sha256}>
                        {f.hash_sha256 ? f.hash_sha256.slice(0, 12) + '...' : '—'}
                      </td>
                      <td className="px-4 py-3 text-xs text-[#8899aa]">
                        {f.quarantine_reason ? (
                          <span
                            className="flex items-center gap-1"
                            title={f.quarantine_notes ?? undefined}
                          >
                            <AlertTriangle className="w-3 h-3 text-yellow-500 shrink-0" />
                            {f.quarantine_reason}
                          </span>
                        ) : '—'}
                      </td>
                      <td className="px-4 py-3 text-xs text-[#8899aa]">
                        {f.quarantined_by ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-xs text-[#8899aa]">
                        {f.restored_at ? (
                          <span className="text-green-400">復元済み</span>
                        ) : (
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3 text-yellow-500" />
                            {formatDuration(f.quarantined_at)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {f.restored_at ? (
                          <span className="flex items-center gap-1 text-green-400 text-xs">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            復元済み
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 bg-yellow-900/40 text-yellow-300 text-xs rounded-full border border-yellow-700/50">
                            検疫中
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-2">
                          {canWrite && !f.restored_at && (
                            <button
                              onClick={() =>
                                setRestoreModal({ id: f.id, path: f.original_path, agentId: f.agent_id })
                              }
                              title="復元"
                              className="p-1.5 text-[#8899aa] hover:text-green-400 hover:bg-green-900/20 rounded-sm transition-colors"
                            >
                              <RotateCcw className="w-4 h-4" />
                            </button>
                          )}
                          {canWrite && (
                            <button
                              onClick={() => {
                                if (confirm('この検疫レコードを削除しますか？ファイルはエンドポイントから完全に削除されます。')) {
                                  remove.mutate(f.id)
                                }
                              }}
                              disabled={remove.isPending}
                              title="削除"
                              className="p-1.5 text-[#8899aa] hover:text-red-400 hover:bg-red-900/20 rounded-sm transition-colors disabled:opacity-50"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination */}
          {data && data.total > perPage && (
            <div className="flex items-center justify-between">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-4 py-2 bg-[#111827] border border-[#1e2d42] text-white text-sm rounded-lg disabled:opacity-40 hover:bg-[#19253d] transition-colors"
              >
                前へ
              </button>
              <span className="text-[#8899aa] text-sm">
                {(page - 1) * perPage + 1}–{Math.min(page * perPage, data.total)} / {data.total}件
              </span>
              <button
                onClick={() => setPage(p => p + 1)}
                disabled={!data.has_more}
                className="px-4 py-2 bg-[#111827] border border-[#1e2d42] text-white text-sm rounded-lg disabled:opacity-40 hover:bg-[#19253d] transition-colors"
              >
                次へ
              </button>
            </div>
          )}
        </>
      ) : (
        <HistoryTab />
      )}

      {/* Restore Modal */}
      {restoreModal && (
        <QuarantineModal
          fileId={restoreModal.id}
          filePath={restoreModal.path}
          agentId={restoreModal.agentId}
          onClose={() => setRestoreModal(null)}
          onSuccess={() => qc.invalidateQueries({ queryKey: ['quarantine'] })}
        />
      )}
    </div>
  )
}
