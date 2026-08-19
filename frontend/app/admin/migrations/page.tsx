'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { RefreshCw, Database, CheckCircle, Clock, XCircle } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

interface Migration {
  id: string
  name: string
  applied_at: string | null
  status: 'applied' | 'pending' | 'failed'
}

interface MigrationsResponse {
  migrations: Migration[]
}

function StatusBadge({ status }: { status: Migration['status'] }) {
  if (status === 'applied') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-900/50 text-green-400 border border-green-800">
        <CheckCircle className="w-3 h-3" />
        適用済み
      </span>
    )
  }
  if (status === 'pending') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-900/50 text-yellow-400 border border-yellow-800">
        <Clock className="w-3 h-3" />
        未適用
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-900/50 text-red-400 border border-red-800">
      <XCircle className="w-3 h-3" />
      失敗
    </span>
  )
}

export default function MigrationsPage() {
  const { data = { migrations: [] }, isLoading, refetch, isFetching } = useQuery<MigrationsResponse>({
    queryKey: ['admin', 'migrations'],
    queryFn: () => apiFetch<MigrationsResponse>('/api/v1/admin/migrations'),
    retry: false,
  })

  const migrations: Migration[] = data?.migrations ?? []

  const total = migrations.length
  const applied = migrations.filter(m => m.status === 'applied').length
  const pending = migrations.filter(m => m.status === 'pending').length

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Database className="w-6 h-6 text-blue-400" />
          <h1 className="text-2xl font-bold text-white">データベースマイグレーション管理</h1>
        </div>
        <p className="text-gray-400 text-sm">
          データベーススキーマのマイグレーション状態を確認できます。
        </p>
      </div>

      {/* Info Banner */}
      <div className="mb-6 flex items-start gap-3 bg-blue-900/30 border border-blue-800 rounded-lg px-4 py-3">
        <div className="mt-0.5 text-blue-400 shrink-0">
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
        </div>
        <p className="text-blue-300 text-sm">
          マイグレーションは自動的に適用されます。手動操作は通常不要です。
        </p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-xs mb-1">総マイグレーション数</p>
          <p className="text-2xl font-bold text-white">{total}</p>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-xs mb-1">適用済み</p>
          <p className="text-2xl font-bold text-green-400">{applied}</p>
        </div>
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-xs mb-1">未適用</p>
          <p className="text-2xl font-bold text-yellow-400">{pending}</p>
        </div>
      </div>

      {/* Migration List Card */}
      <div className="bg-gray-800 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <h2 className="text-sm font-semibold text-white">マイグレーション一覧</h2>
          <div className="flex items-center gap-3">
            {false && (
              <span className="text-xs text-yellow-400 bg-yellow-900/30 border border-yellow-800 px-2 py-0.5 rounded-sm">
                モックデータ表示中
              </span>
            )}
            <button
              onClick={() => refetch()}
              disabled={isLoading || isFetching}
              className="flex items-center gap-2 px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-sm border border-gray-600 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
              マイグレーション状態を更新
            </button>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-16 text-gray-400">
            <RefreshCw className="w-5 h-5 animate-spin mr-2" />
            読み込み中...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">バージョン</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider">名前</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-32">ステータス</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-48">適用日時</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {migrations.map((m) => (
                  <tr key={m.id} className="hover:bg-gray-700/30 transition-colors">
                    <td className="px-4 py-3 text-gray-300 font-mono text-xs">{m.id}</td>
                    <td className="px-4 py-3 text-gray-200 font-mono text-xs">{m.name}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={m.status} />
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      {m.applied_at
                        ? new Date(m.applied_at).toLocaleString('ja-JP', {
                            year: 'numeric', month: '2-digit', day: '2-digit',
                            hour: '2-digit', minute: '2-digit',
                          })
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
