'use client'

import React, { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ClipboardList, Search, Download, ChevronDown, ChevronRight,
  CheckCircle, XCircle, Filter,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type Action = 'create' | 'update' | 'delete' | 'login' | 'logout' | 'export' | 'view' | 'execute'

interface AuditEvent {
  id: string
  timestamp: string
  username: string
  user_id: string
  action: Action
  resource: string
  resource_id: string
  ip_address: string
  risk_score: number
  success: boolean
  details: Record<string, unknown>
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const ACTION_COLORS: Record<Action, string> = {
  create: 'bg-green-900 text-green-300',
  update: 'bg-blue-900 text-blue-300',
  delete: 'bg-red-900 text-red-300',
  login: 'bg-purple-900 text-purple-300',
  logout: 'bg-zinc-700 text-zinc-300',
  export: 'bg-yellow-900 text-yellow-300',
  view: 'bg-zinc-800 text-zinc-400',
  execute: 'bg-orange-900 text-orange-300',
}


function riskColor(score: number): string {
  if (score > 60) return 'bg-red-500'
  if (score > 30) return 'bg-yellow-500'
  return 'bg-green-500'
}

function riskTextColor(score: number): string {
  if (score > 60) return 'text-red-400'
  if (score > 30) return 'text-yellow-400'
  return 'text-green-400'
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AuditLogsPage() {
  const [exportError, setExportError] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [filterUser, setFilterUser] = useState('')
  const [filterAction, setFilterAction] = useState('all')
  const [filterResource, setFilterResource] = useState('all')
  const [filterStart, setFilterStart] = useState('')
  const [filterEnd, setFilterEnd] = useState('')

  const { data: apiEvents = [] } = useQuery<AuditEvent[]>({
    queryKey: ['audit-events'],
    queryFn: () => apiFetchList<AuditEvent>('/api/v1/admin/audit/events'),
    staleTime: 30_000,
    retry: 0,
  })

  const { data: apiStats } = useQuery<{ events_today: number; suspicious_events: number; top_users: { user_id: string; username: string; count: number }[] }>({
    queryKey: ['audit-stats'],
    queryFn: () => apiFetch<{ events_today: number; suspicious_events: number; top_users: { user_id: string; username: string; count: number }[] }>('/api/v1/admin/audit/stats').catch(() => ({ events_today: 0, suspicious_events: 0, top_users: [] })),
    staleTime: 60_000,
    retry: 0,
  })

  const events = apiEvents ?? []
  const allResources = Array.from(new Set(events.map(e => e.resource))).sort()
  const [filtered, setFiltered] = useState<AuditEvent[]>([])

  // Re-apply filter whenever source data changes
  useEffect(() => {
    setFiltered(events)
  }, [events])

  function applyFilter() {
    let result = events
    if (filterUser) result = result.filter(e => e.username.toLowerCase().includes(filterUser.toLowerCase()) || e.user_id.toLowerCase().includes(filterUser.toLowerCase()))
    if (filterAction !== 'all') result = result.filter(e => e.action === filterAction)
    if (filterResource !== 'all') result = result.filter(e => e.resource === filterResource)
    if (filterStart) result = result.filter(e => new Date(e.timestamp) >= new Date(filterStart))
    if (filterEnd) result = result.filter(e => new Date(e.timestamp) <= new Date(filterEnd + 'T23:59:59'))
    setFiltered(result)
  }

  function handleReset() {
    setFilterUser(''); setFilterAction('all'); setFilterResource('all')
    setFilterStart(''); setFilterEnd('')
    setFiltered(events)
  }

  async function handleExport() {
    const params = new URLSearchParams()
    if (filterUser) params.set('user_id', filterUser)
    if (filterAction !== 'all') params.set('action', filterAction)
    if (filterResource !== 'all') params.set('resource', filterResource)
    if (filterStart) params.set('start', filterStart)
    if (filterEnd) params.set('end', filterEnd)
    // fetch は 4xx/5xx で reject しません。res.ok を見ないと、サーバが
    // 返したエラー本文がそのまま audit-export.csv になります。
    //
    // 失敗時に画面上の filtered から CSV を組み立てて同じ名前で保存して
    // いました。監査に出すファイルが、いま絞り込んで見えている行に
    // すり替わります。件数も並びも「それらしい」ので、受け取った側に
    // 見分ける手がかりはありません。
    try {
      const res = await fetch(`/api/v1/admin/audit/export?${params}`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('edr_token') || ''}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = 'audit-export.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setExportError(
        `監査ログを書き出せませんでした（${e instanceof Error ? e.message : String(e)}）。` +
        'ファイルは作成していません'
      )
    }
  }

  const activeUsers = apiStats?.top_users.length ?? 0
  const exportCount = events.filter(e => e.action === 'export').length
  const todayCount = apiStats?.events_today ?? events.length
  const highRiskEvents = apiStats?.suspicious_events ?? filtered.filter(e => e.risk_score > 60).length

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <PageDataUnavailable />
      {exportError && (
        <div className="mb-4 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {exportError}
        </div>
      )}
      {/* ヘッダー */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-teal-700 rounded-lg">
            <ClipboardList className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">監査ログ</h1>
            <p className="text-sm text-zinc-400">完全なユーザーアクティビティ履歴</p>
          </div>
        </div>
        <button
          onClick={handleExport}
          className="flex items-center gap-2 px-4 py-2 bg-teal-700 hover:bg-teal-600 rounded-lg text-sm"
        >
          <Download className="w-4 h-4" />
          CSVエクスポート
        </button>
      </div>

      {/* 統計 */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '本日のイベント', value: todayCount.toLocaleString(), color: 'text-teal-400' },
          { label: '高リスクイベント', value: highRiskEvents, color: 'text-red-400' },
          { label: 'アクティブユーザー', value: activeUsers, color: 'text-zinc-100' },
          { label: 'エクスポート件数', value: exportCount, color: 'text-yellow-400' },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* フィルターバー */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 mb-4">
        <div className="flex flex-wrap gap-3 items-end">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">ユーザー / ID</label>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-400" />
              <input
                value={filterUser}
                onChange={e => setFilterUser(e.target.value)}
                placeholder="ユーザー名またはID"
                className="bg-zinc-800 border border-zinc-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-zinc-100 focus:outline-hidden focus:border-teal-500 w-44"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">アクション</label>
            <select value={filterAction} onChange={e => setFilterAction(e.target.value)}
              className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-100 focus:outline-hidden">
              <option value="all">すべてのアクション</option>
              {(['create', 'update', 'delete', 'login', 'logout', 'export', 'view', 'execute'] as Action[]).map(a => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">リソース</label>
            <select value={filterResource} onChange={e => setFilterResource(e.target.value)}
              className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-100 focus:outline-hidden">
              <option value="all">すべてのリソース</option>
              {allResources.map(r => <option key={r} value={r}>{r.replace(/_/g, ' ')}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">開始日</label>
            <input type="date" value={filterStart} onChange={e => setFilterStart(e.target.value)}
              className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-100 focus:outline-hidden" />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">終了日</label>
            <input type="date" value={filterEnd} onChange={e => setFilterEnd(e.target.value)}
              className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-100 focus:outline-hidden" />
          </div>
          <div className="flex gap-2">
            <button onClick={applyFilter}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-700 hover:bg-teal-600 rounded-lg text-sm">
              <Filter className="w-3.5 h-3.5" /> フィルター
            </button>
            <button onClick={handleReset}
              className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-sm text-zinc-400">
              リセット
            </button>
          </div>
        </div>
      </div>

      {/* イベントテーブル */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3 w-4"></th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">タイムスタンプ</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">ユーザー</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">アクション</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">リソース</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">リソースID</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">IP</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">リスク</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-3 py-3">ステータス</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(evt => (
              <React.Fragment key={evt.id}>
                <tr
                  className="border-b border-zinc-800/60 hover:bg-zinc-800/30 cursor-pointer"
                  onClick={() => setExpandedId(expandedId === evt.id ? null : evt.id)}
                >
                  <td className="px-3 py-3">
                    {expandedId === evt.id
                      ? <ChevronDown className="w-3.5 h-3.5 text-zinc-400" />
                      : <ChevronRight className="w-3.5 h-3.5 text-zinc-400" />}
                  </td>
                  <td className="px-3 py-3 text-xs text-zinc-400 whitespace-nowrap">{fmtDate(evt.timestamp)}</td>
                  <td className="px-3 py-3">
                    <p className="text-sm text-zinc-200 truncate max-w-[140px]">{evt.username || evt.user_id || '—'}</p>
                  </td>
                  <td className="px-3 py-3">
                    <span className={`px-2 py-0.5 rounded-sm text-xs font-semibold capitalize ${ACTION_COLORS[evt.action]}`}>
                      {evt.action}
                    </span>
                  </td>
                  <td className="px-3 py-3 text-sm text-zinc-300 capitalize">{evt.resource.replace(/_/g, ' ')}</td>
                  <td className="px-3 py-3 text-xs font-mono text-zinc-500 truncate max-w-[100px]">{evt.resource_id}</td>
                  <td className="px-3 py-3 text-xs font-mono text-zinc-400">{evt.ip_address}</td>
                  <td className="px-3 py-3" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${riskColor(evt.risk_score)}`}
                          style={{ width: `${evt.risk_score}%` }}
                        />
                      </div>
                      <span className={`text-xs font-semibold ${riskTextColor(evt.risk_score)}`}>{evt.risk_score}</span>
                    </div>
                  </td>
                  <td className="px-3 py-3">
                    {evt.success
                      ? <CheckCircle className="w-4 h-4 text-green-500" />
                      : <XCircle className="w-4 h-4 text-red-500" />}
                  </td>
                </tr>
                {expandedId === evt.id && (
                  <tr key={`${evt.id}-details`} className="bg-zinc-950 border-b border-zinc-800">
                    <td colSpan={9} className="px-8 py-4">
                      <p className="text-xs text-zinc-500 mb-2 font-medium uppercase tracking-wide">イベント詳細</p>
                      <pre className="bg-zinc-900 border border-zinc-700 rounded-lg p-3 text-xs font-mono text-green-300 overflow-x-auto">
                        {JSON.stringify(evt.details, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="text-center py-12 text-zinc-500">
            <ClipboardList className="w-10 h-10 mx-auto mb-2 opacity-30" />
            <p>現在のフィルター条件に一致するイベントはありません。</p>
          </div>
        )}
        <div className="px-4 py-3 border-t border-zinc-800 text-xs text-zinc-600">
          {events.length} 件中 {filtered.length} 件を表示
        </div>
      </div>
    </div>
  )
}
