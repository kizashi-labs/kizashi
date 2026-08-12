'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GitBranch, Info, Trash2, X, ToggleLeft, ToggleRight,
  ChevronRight, ExternalLink,
} from 'lucide-react'

interface CorrelationGroup {
  id: string
  agent_id: string
  mitre_technique: string
  first_seen_at: string
  last_seen_at: string
  alert_count: number
  incident_id?: string
  created_at: string
}

interface CorrelationResponse {
  data: CorrelationGroup[]
  total: number
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

export default function CorrelationRulesPage() {
  const queryClient = useQueryClient()
  const [selectedGroup, setSelectedGroup] = useState<CorrelationGroup | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  const { data, isLoading } = useQuery<CorrelationResponse>({
    queryKey: ['correlation-rules'],
    queryFn: () => apiFetch('/api/v1/correlation-rules'),
  })

  const groups = data?.data ?? []
  const total = data?.total ?? 0

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/correlation-rules/${id}/toggle`, { method: 'PUT' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/correlation-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['correlation-rules'] })
      setDeleteConfirm(null)
      if (selectedGroup?.id === deleteConfirm) setSelectedGroup(null)
    },
  })

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <GitBranch className="w-4 h-4 text-[#e8002d]" />
          </div>
          <h1 className="text-xl font-bold text-white">コリレーションルール管理</h1>
        </div>
        <p className="text-[#7d92b0] text-sm ml-11">検知エンジンが自動生成したコリレーショングループ</p>
      </div>

      {/* Info banner */}
      <div className="flex items-start gap-2 bg-blue-500/5 border border-blue-500/20 rounded-lg px-4 py-3 mb-6">
        <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-blue-300">
          コリレーショングループは検知エンジンが自動生成します。手動での作成は行えません。
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 mb-6 max-w-sm">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-xs mb-1">総グループ数</p>
          <p className="text-2xl font-bold text-white">{total}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-xs mb-1">インシデント関連</p>
          <p className="text-2xl font-bold text-white">
            {groups.filter(g => g.incident_id).length}
          </p>
        </div>
      </div>

      <div className="flex gap-4">
        {/* Table */}
        <div className={`bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden flex-1 min-w-0 transition-all ${selectedGroup ? 'max-w-[calc(100%-320px)]' : ''}`}>
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">グループ一覧</h2>
            <span className="text-xs text-[#7d92b0]">{total} 件</span>
          </div>

          {isLoading ? (
            <div className="p-8 text-center text-[#7d92b0] text-sm">読み込み中...</div>
          ) : groups.length === 0 ? (
            <div className="p-8 text-center text-[#7d92b0] text-sm">コリレーショングループが存在しません</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">ID</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">エージェント</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">MITRE技術</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">アラート数</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">最初検知</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">最終検知</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">インシデント</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {groups.map(group => (
                    <tr
                      key={group.id}
                      className={`hover:bg-[#0a1628] transition-colors cursor-pointer ${
                        selectedGroup?.id === group.id ? 'bg-[#0a1628]' : ''
                      }`}
                      onClick={() => setSelectedGroup(selectedGroup?.id === group.id ? null : group)}
                    >
                      <td className="px-4 py-3 text-xs font-mono text-[#7d92b0] max-w-[80px] truncate">
                        {group.id.slice(0, 8)}…
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-[#e2e8f4] max-w-[100px] truncate">
                        {group.agent_id.slice(0, 8)}…
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-block px-2 py-0.5 rounded text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
                          {group.mitre_technique}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm font-bold ${group.alert_count > 10 ? 'text-[#e8002d]' : group.alert_count > 5 ? 'text-orange-400' : 'text-white'}`}>
                          {group.alert_count}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                        {formatDate(group.first_seen_at)}
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                        {formatDate(group.last_seen_at)}
                      </td>
                      <td className="px-4 py-3">
                        {group.incident_id ? (
                          <a
                            href={`/incidents/${group.incident_id}`}
                            onClick={e => e.stopPropagation()}
                            className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-[#e8002d] transition-colors font-mono"
                          >
                            <ExternalLink className="w-3 h-3" />
                            {group.incident_id.slice(0, 8)}…
                          </a>
                        ) : (
                          <span className="text-xs text-[#3d5068]">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => toggleMutation.mutate(group.id)}
                            disabled={toggleMutation.isPending}
                            className="p-1.5 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
                            title="有効/無効切り替え"
                          >
                            <ToggleRight className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => setDeleteConfirm(group.id)}
                            className="p-1.5 rounded text-[#7d92b0] hover:text-[#e8002d] hover:bg-[#e8002d]/10 transition-colors"
                            title="削除"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                          <ChevronRight className={`w-3.5 h-3.5 text-[#3d5068] transition-transform ${selectedGroup?.id === group.id ? 'rotate-90' : ''}`} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Detail slide-out panel */}
        {selectedGroup && (
          <div className="w-72 flex-shrink-0 bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden self-start">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
              <h3 className="text-sm font-semibold text-white">グループ詳細</h3>
              <button
                onClick={() => setSelectedGroup(null)}
                className="p-1 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="px-4 py-4 space-y-4">
              {[
                { label: 'ID', value: selectedGroup.id, mono: true },
                { label: 'エージェントID', value: selectedGroup.agent_id, mono: true },
                { label: 'MITRE技術', value: selectedGroup.mitre_technique },
                { label: 'アラート数', value: String(selectedGroup.alert_count) },
                { label: '最初検知', value: formatDate(selectedGroup.first_seen_at) },
                { label: '最終検知', value: formatDate(selectedGroup.last_seen_at) },
                { label: '作成日時', value: formatDate(selectedGroup.created_at) },
                { label: 'インシデントID', value: selectedGroup.incident_id ?? '—', mono: !!selectedGroup.incident_id },
              ].map(({ label, value, mono }) => (
                <div key={label}>
                  <p className="text-[10px] font-medium text-[#7d92b0] uppercase tracking-wider mb-1">{label}</p>
                  <p className={`text-xs text-[#e2e8f4] break-all ${mono ? 'font-mono' : ''}`}>{value}</p>
                </div>
              ))}

              {selectedGroup.incident_id && (
                <a
                  href={`/incidents/${selectedGroup.incident_id}`}
                  className="flex items-center gap-2 w-full px-3 py-2 rounded bg-[#1e2d42] hover:bg-[#e8002d]/10 hover:border-[#e8002d]/30 border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-[#e8002d] transition-all mt-2"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  インシデントを開く
                </a>
              )}

              <div className="pt-2 border-t border-[#1e2d42] flex flex-col gap-2">
                <button
                  onClick={() => toggleMutation.mutate(selectedGroup.id)}
                  disabled={toggleMutation.isPending}
                  className="flex items-center gap-2 w-full px-3 py-2 rounded bg-[#1e2d42] hover:bg-[#1e2d42]/80 text-xs text-[#7d92b0] hover:text-white transition-colors border border-[#1e2d42]"
                >
                  {toggleMutation.isPending ? (
                    <ToggleLeft className="w-3.5 h-3.5" />
                  ) : (
                    <ToggleRight className="w-3.5 h-3.5" />
                  )}
                  有効/無効切り替え
                </button>
                <button
                  onClick={() => setDeleteConfirm(selectedGroup.id)}
                  className="flex items-center gap-2 w-full px-3 py-2 rounded bg-[#e8002d]/5 hover:bg-[#e8002d]/15 text-xs text-[#e8002d] transition-colors border border-[#e8002d]/20"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  削除
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Delete Confirm Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5">
            <h2 className="text-base font-semibold text-white mb-2">グループを削除しますか？</h2>
            <p className="text-sm text-[#7d92b0] mb-5">この操作は取り消せません。</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white rounded border border-[#1e2d42] transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded font-medium transition-colors disabled:opacity-50"
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
