'use client'

import { useState, use } from 'react'
import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Activity,
  Shield,
  Terminal,
  RefreshCw,
  Search,
  AlertTriangle,
  ChevronLeft,
  Cpu,
} from 'lucide-react'

// ─── 型定義 ───────────────────────────────────────────────────────────────────

interface AgentDetail {
  id: string
  hostname: string
  status: string
}

interface ProcessEvent {
  id: string
  agent_id: string
  type: string
  severity?: number
  message?: string
  raw_event?: string
  created_at: string
}

interface ParsedProcess {
  pid?: number
  name?: string
  process_name?: string
  command_line?: string
  parent_pid?: number
  parent_name?: string
  user?: string
  action?: string
}

interface ProcessRule {
  process_name: string
  action: string
  severity: string
  enabled: boolean
}

interface ProcessRulesResponse {
  rules: ProcessRule[]
}

// ─── ユーティリティ ───────────────────────────────────────────────────────────

function formatTime(s: string) {
  if (!s) return '—'
  return new Date(s).toLocaleString('ja-JP', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function truncate(s: string | undefined | null, n: number): string {
  if (!s) return '—'
  return s.length <= n ? s : s.slice(0, n) + '…'
}

function parseProc(raw?: string): ParsedProcess {
  try {
    return JSON.parse(raw || '{}')
  } catch {
    return {}
  }
}

function getProcessName(proc: ParsedProcess): string {
  return proc.name || proc.process_name || '—'
}

// ─── アクションバッジ ─────────────────────────────────────────────────────────

function ActionBadge({ action }: { action?: string }) {
  const a = action?.toLowerCase()
  if (a === 'blocked') {
    return (
      <span className="px-2 py-0.5 rounded-sm text-xs font-medium bg-red-900/50 text-red-300 border border-red-700/40">
        BLOCKED
      </span>
    )
  }
  if (a === 'alert') {
    return (
      <span className="px-2 py-0.5 rounded-sm text-xs font-medium bg-orange-900/50 text-orange-300 border border-orange-700/40">
        ALERT
      </span>
    )
  }
  return (
    <span className="px-2 py-0.5 rounded-sm text-xs font-medium bg-green-900/40 text-green-300 border border-green-700/40">
      ALLOWED
    </span>
  )
}

// ─── ルール重要度バッジ ────────────────────────────────────────────────────────

function RuleSeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase()
  const style =
    s === 'critical'
      ? 'bg-red-900/40 text-red-300'
      : s === 'high'
      ? 'bg-orange-900/40 text-orange-300'
      : s === 'medium'
      ? 'bg-yellow-900/40 text-yellow-300'
      : s === 'low'
      ? 'bg-green-900/40 text-green-300'
      : 'bg-gray-800 text-gray-400'
  return (
    <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${style}`}>
      {severity?.toUpperCase() || '—'}
    </span>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────────

// Next.js 15 以降、動的セグメントの params は Promise で渡る。
// クライアントコンポーネントでは React の use() で解決する。
export default function ProcessesPage({ params }: { params: Promise<{ id: string }> }) {
  const agentId = use(params).id
  const [search, setSearch] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)

  // エージェント情報
  const { data: agent } = useQuery<AgentDetail>({
    queryKey: ['agent-detail', agentId],
    queryFn: () => apiFetch<AgentDetail>(`/api/v1/agents/${agentId}`),
    refetchInterval: 30_000,
  })

  // プロセスイベント
  const {
    data: eventsData,
    isLoading: eventsLoading,
    isError: eventsError,
    refetch: refetchEvents,
    isFetching,
  } = useQuery<{ data: ProcessEvent[] }>({
    queryKey: ['agent-process-events', agentId],
    queryFn: () =>
      apiFetch<{ data: ProcessEvent[] }>(
        `/api/v1/events?agent_id=${agentId}&type=process_create&limit=100&sort=desc`
      ),
    refetchInterval: autoRefresh ? 10_000 : false,
  })

  // ブロックルール
  const { data: rulesData, isLoading: rulesLoading } = useQuery<ProcessRulesResponse>({
    queryKey: ['agent-process-rules', agentId],
    queryFn: () =>
      apiFetch<ProcessRulesResponse>(`/api/v1/process-rules/agent/${agentId}`),
    refetchInterval: autoRefresh ? 10_000 : false,
  })

  const events = eventsData?.data ?? []
  const rules = rulesData?.rules ?? []

  // 統計
  const blockedCount = events.filter((ev) => {
    const proc = parseProc(ev.raw_event)
    return proc.action?.toLowerCase() === 'blocked'
  }).length

  const alertCount = events.filter((ev) => {
    const proc = parseProc(ev.raw_event)
    return proc.action?.toLowerCase() === 'alert'
  }).length

  // 検索フィルタ
  const filteredEvents = events.filter((ev) => {
    if (!search.trim()) return true
    const proc = parseProc(ev.raw_event)
    const name = getProcessName(proc).toLowerCase()
    const cmd = (proc.command_line ?? '').toLowerCase()
    const q = search.toLowerCase()
    return name.includes(q) || cmd.includes(q)
  })

  const hostname = agent?.hostname ?? agentId

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="max-w-7xl mx-auto p-6 space-y-6">

        {/* ── 戻るリンク ── */}
        <Link
          href={`/agents/${agentId}`}
          className="inline-flex items-center gap-1.5 text-gray-400 hover:text-white text-sm transition-colors"
        >
          <ChevronLeft className="w-4 h-4" />
          {hostname}
        </Link>

        {/* ── ヘッダー ── */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-purple-900/40 flex items-center justify-center shrink-0">
                <Cpu className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">ライブプロセス監視</h1>
                <p className="text-gray-400 text-sm mt-0.5">{hostname}</p>
              </div>
            </div>

            {/* 自動更新トグル */}
            <button
              onClick={() => setAutoRefresh((v) => !v)}
              className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
                autoRefresh
                  ? 'bg-blue-900/40 border-blue-700/50 text-blue-300 hover:bg-blue-900/60'
                  : 'bg-gray-700 border-gray-600 text-gray-400 hover:bg-gray-600'
              }`}
            >
              <RefreshCw
                className={`w-4 h-4 ${isFetching && autoRefresh ? 'animate-spin' : ''}`}
              />
              {autoRefresh ? '自動更新 ON' : '自動更新 OFF'}
            </button>
          </div>
        </div>

        {/* ── 統計バー ── */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* 合計 */}
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-900/40 flex items-center justify-center shrink-0">
              <Activity className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <p className="text-gray-400 text-xs">合計プロセス</p>
              <p className="text-white text-xl font-bold">{events.length}</p>
            </div>
          </div>

          {/* ブロック */}
          <div className="bg-gray-800 rounded-lg border border-red-900/30 p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-red-900/40 flex items-center justify-center shrink-0">
              <Shield className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="text-gray-400 text-xs">ブロック</p>
              <p className="text-red-400 text-xl font-bold">{blockedCount}</p>
            </div>
          </div>

          {/* アラート */}
          <div className="bg-gray-800 rounded-lg border border-orange-900/30 p-4 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-orange-900/40 flex items-center justify-center shrink-0">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
            </div>
            <div>
              <p className="text-gray-400 text-xs">アラート</p>
              <p className="text-orange-400 text-xl font-bold">{alertCount}</p>
            </div>
          </div>
        </div>

        {/* ── プロセステーブル ── */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          {/* テーブルヘッダー + 検索バー */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-gray-700">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-gray-400" />
              <span className="text-white text-sm font-semibold">プロセスイベント</span>
            </div>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="プロセス名またはコマンドラインで検索…"
                className="pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-600 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-hidden focus:border-blue-500 w-72"
              />
            </div>
          </div>

          {/* テーブル本体 */}
          {eventsLoading ? (
            <div className="flex items-center justify-center py-12">
              <RefreshCw className="animate-spin w-6 h-6 text-blue-400" />
            </div>
          ) : eventsError ? (
            <div className="py-8 text-center text-red-400 text-sm">
              プロセスイベントの取得に失敗しました
            </div>
          ) : filteredEvents.length === 0 ? (
            <div className="py-8 text-center text-gray-500 text-sm">
              {search ? '検索結果なし' : 'プロセスイベントなし'}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-gray-500 text-xs">
                    <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">タイムスタンプ</th>
                    <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">PID</th>
                    <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">プロセス名</th>
                    <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">コマンドライン</th>
                    <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">親プロセス</th>
                    <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">ユーザー</th>
                    <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">アクション</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((ev) => {
                    const proc = parseProc(ev.raw_event)
                    const isBlocked = proc.action?.toLowerCase() === 'blocked'
                    const procName = getProcessName(proc)
                    const parentLabel =
                      proc.parent_name && proc.parent_pid
                        ? `${proc.parent_name} (${proc.parent_pid})`
                        : proc.parent_name ?? (proc.parent_pid ? String(proc.parent_pid) : '—')

                    return (
                      <tr
                        key={ev.id}
                        className={`border-b border-gray-700 last:border-0 transition-colors ${
                          isBlocked
                            ? 'bg-red-950/30 hover:bg-red-950/50'
                            : 'bg-gray-900 hover:bg-gray-800/70'
                        }`}
                      >
                        <td className="px-4 py-2.5 text-gray-400 whitespace-nowrap text-xs">
                          {formatTime(ev.created_at)}
                        </td>
                        <td className="px-4 py-2.5 text-gray-300 font-mono text-xs whitespace-nowrap">
                          {proc.pid ?? '—'}
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          <span className="font-mono text-white text-xs">{procName}</span>
                        </td>
                        <td className="px-4 py-2.5 text-gray-400 font-mono text-xs max-w-xs">
                          <span title={proc.command_line ?? ''}>
                            {truncate(proc.command_line, 50)}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-gray-400 text-xs whitespace-nowrap">
                          {parentLabel}
                        </td>
                        <td className="px-4 py-2.5 text-gray-300 text-xs whitespace-nowrap">
                          {proc.user ?? '—'}
                        </td>
                        <td className="px-4 py-2.5">
                          <ActionBadge action={proc.action} />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── ブロックルール ── */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-gray-700">
            <Shield className="w-4 h-4 text-red-400" />
            <span className="text-white text-sm font-semibold">ブロックルール</span>
          </div>

          {rulesLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="animate-spin w-5 h-5 text-blue-400" />
            </div>
          ) : rules.length === 0 ? (
            <div className="py-8 text-center text-gray-500 text-sm">
              ブロックルールなし
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-gray-500 text-xs">
                    <th className="px-4 py-2.5 text-left font-medium">プロセス名</th>
                    <th className="px-4 py-2.5 text-left font-medium">アクション</th>
                    <th className="px-4 py-2.5 text-left font-medium">重要度</th>
                    <th className="px-4 py-2.5 text-left font-medium">有効</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule, i) => (
                    <tr
                      key={i}
                      className={`border-b border-gray-700 last:border-0 ${
                        rule.enabled ? 'bg-gray-900' : 'bg-gray-900/50 opacity-60'
                      }`}
                    >
                      <td className="px-4 py-2.5 font-mono text-white text-xs">
                        {rule.process_name || '—'}
                      </td>
                      <td className="px-4 py-2.5">
                        <ActionBadge action={rule.action} />
                      </td>
                      <td className="px-4 py-2.5">
                        <RuleSeverityBadge severity={rule.severity} />
                      </td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium ${
                            rule.enabled
                              ? 'bg-green-900/40 text-green-300'
                              : 'bg-gray-700 text-gray-500'
                          }`}
                        >
                          {rule.enabled ? '有効' : '無効'}
                        </span>
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
