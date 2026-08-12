'use client'

import { useState, useCallback, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ClipboardList, RefreshCw, Search, X, Filter,
  XCircle, Download, ShieldCheck, User, TrendingUp, AlertOctagon,
} from 'lucide-react'

// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface AuditLog {
  id: string
  user_id: string
  user_email?: string
  action: string       // e.g. "POST /api/v1/agents/:id/isolate"
  resource_id: string
  ip_address: string
  status_code: number
  created_at: string
}

interface AuditResponse {
  logs: AuditLog[]
  total: number
  page: number
  per_page: number
}

type SiemFormat = 'cef' | 'leef' | 'json'

// ─── 定数 ────────────────────────────────────────────────────────────────────

const PER_PAGE = 50

const METHODS = ['', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const
type Method = (typeof METHODS)[number]

// ─── ユーティリティ ──────────────────────────────────────────────────────────

function extractMethod(action: string): string {
  const m = action.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/)
  return m ? m[1] : 'GET'
}

function methodBadgeStyle(method: string): string {
  switch (method) {
    case 'POST':   return 'bg-green-900/40 text-green-300'
    case 'PUT':    return 'bg-yellow-900/40 text-yellow-300'
    case 'PATCH':  return 'bg-orange-900/40 text-orange-300'
    case 'DELETE': return 'bg-red-900/40 text-red-300'
    default:       return 'bg-[#161f33] text-[#8899aa]'
  }
}

function statusStyle(code: number): string {
  if (code >= 500) return 'text-red-400'
  if (code >= 400) return 'text-red-400'
  if (code >= 300) return 'text-yellow-400'
  return 'text-green-400'
}

function statusDotStyle(code: number): string {
  if (code >= 500) return 'bg-red-400'
  if (code >= 400) return 'bg-red-400'
  if (code >= 300) return 'bg-yellow-400'
  return 'bg-green-400'
}

// ─── CSVエクスポート ──────────────────────────────────────────────────────────

function exportCsv(logs: AuditLog[]): void {
  const header = ['ID', 'タイムスタンプ', 'ユーザー', 'アクション', 'リソースID', 'IPアドレス', 'ステータスコード']
  const rows = logs.map(log => [
    log.id,
    new Date(log.created_at).toLocaleString('ja-JP'),
    log.user_email ?? log.user_id,
    log.action,
    log.resource_id,
    log.ip_address,
    String(log.status_code),
  ])

  const escape = (v: string) => `"${v.replace(/"/g, '""')}"`
  const csv = [header, ...rows].map(r => r.map(escape).join(',')).join('\r\n')
  const bom = '\uFEFF' // UTF-8 BOM for Excel
  const blob = new Blob([bom + csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `audit-log-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// ─── デフォルト日付範囲ヘルパー ───────────────────────────────────────────────

function defaultSince(): string {
  const d = new Date()
  d.setDate(d.getDate() - 30)
  // datetime-local input expects "YYYY-MM-DDTHH:mm"
  return d.toISOString().slice(0, 16)
}

function defaultUntil(): string {
  return new Date().toISOString().slice(0, 16)
}

// ─── リスクスコア ────────────────────────────────────────────────────────────

function computeRiskScore(log: AuditLog): number {
  let score = 0
  const method = extractMethod(log.action)
  const path = log.action.replace(/^\S+\s+/, '').toLowerCase()
  if (method === 'DELETE') score += 40
  else if (method === 'POST' || method === 'PUT') score += 20
  if (path.includes('isolat') || path.includes('quarant') || path.includes('kill')) score += 30
  if (path.includes('admin') || path.includes('user') || path.includes('password')) score += 20
  if (log.status_code >= 500) score += 20
  else if (log.status_code >= 400) score += 10
  return Math.min(100, score)
}

function riskBarColor(score: number): string {
  if (score >= 70) return 'bg-red-500'
  if (score >= 40) return 'bg-yellow-500'
  return 'bg-green-500'
}

function riskLabel(score: number): string {
  if (score >= 70) return '高'
  if (score >= 40) return '中'
  return '低'
}

function riskLabelColor(score: number): string {
  if (score >= 70) return 'text-red-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

// ─── ユーザーサマリーカード ─────────────────────────────────────────────────

interface UserStat {
  email: string
  count: number
  deleteCount: number
  errorCount: number
}

function UserSummarySection({ logs }: { logs: AuditLog[] }) {
  const stats = useMemo(() => {
    const map = new Map<string, UserStat>()
    for (const log of logs) {
      const key = log.user_email ?? log.user_id ?? 'unknown'
      const existing = map.get(key) ?? { email: key, count: 0, deleteCount: 0, errorCount: 0 }
      existing.count++
      if (extractMethod(log.action) === 'DELETE') existing.deleteCount++
      if (log.status_code >= 400) existing.errorCount++
      map.set(key, existing)
    }
    return Array.from(map.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 4)
  }, [logs])

  if (stats.length === 0) return null

  const maxCount = stats[0]?.count ?? 1

  return (
    <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2">
        <TrendingUp className="w-5 h-5 text-purple-400 shrink-0" />
        <h2 className="text-base font-semibold text-white">アクティブユーザー Top 4</h2>
        <span className="text-xs text-[#5a6a7a] ml-auto">現在フィルター範囲内</span>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map(u => (
          <div
            key={u.email}
            className="bg-[#080c14] border border-[#1e2d42] rounded-lg p-4 space-y-3"
          >
            {/* アバター + メール */}
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-8 h-8 rounded-full bg-purple-900/60 border border-purple-700/50
                              flex items-center justify-center shrink-0">
                <User className="w-4 h-4 text-purple-300" />
              </div>
              <span className="text-xs font-mono text-[#c8d8e8] truncate" title={u.email}>
                {u.email}
              </span>
            </div>

            {/* アクション件数バー */}
            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-[#5a6a7a]">総アクション</span>
                <span className="text-xs font-bold text-white">{u.count}</span>
              </div>
              <div className="w-full h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                <div
                  className="h-full bg-purple-500 rounded-full"
                  style={{ width: `${(u.count / maxCount) * 100}%` }}
                />
              </div>
            </div>

            {/* 削除 / エラー */}
            <div className="flex gap-3">
              <div className="flex items-center gap-1">
                <AlertOctagon className="w-3 h-3 text-red-400 shrink-0" />
                <span className="text-[10px] text-red-400 font-medium">{u.deleteCount} 削除</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shrink-0" />
                <span className="text-[10px] text-yellow-400 font-medium">{u.errorCount} エラー</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── SIEMエクスポートパネル ───────────────────────────────────────────────────

const SIEM_FORMATS: { value: SiemFormat; label: string; description: string }[] = [
  { value: 'cef',  label: 'CEF',  description: 'Splunk / ArcSight 対応 (CEF 0.1)' },
  { value: 'leef', label: 'LEEF', description: 'IBM QRadar 対応 (LEEF 2.0)' },
  { value: 'json', label: 'JSON', description: '汎用 JSON 形式' },
]

const LIMIT_OPTIONS: { value: string; label: string }[] = [
  { value: '1000',  label: '1,000 件' },
  { value: '5000',  label: '5,000 件' },
  { value: '10000', label: '10,000 件' },
  { value: '10000', label: '最大' },
]

// Deduplicate by value so the select has unique option keys
const UNIQUE_LIMIT_OPTIONS = [
  { value: '1000',  label: '1,000 件' },
  { value: '5000',  label: '5,000 件' },
  { value: '10000', label: '10,000 件 (最大)' },
]

function SiemExportPanel() {
  const [format, setFormat] = useState<SiemFormat>('cef')
  const [since,  setSince]  = useState<string>(defaultSince)
  const [until,  setUntil]  = useState<string>(defaultUntil)
  const [limit,  setLimit]  = useState<string>('10000')

  const handleExport = useCallback(() => {
    // Convert datetime-local ("YYYY-MM-DDTHH:mm") to RFC 3339
    const sinceRfc = since ? new Date(since).toISOString() : ''
    const untilRfc = until ? new Date(until).toISOString() : ''

    const params = new URLSearchParams({ format, limit })
    if (sinceRfc) params.set('since', sinceRfc)
    if (untilRfc) params.set('until', untilRfc)

    const url = `/api/v1/audit-logs/export?${params.toString()}`
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-logs-${format}-${Date.now()}.${format === 'json' ? 'json' : 'txt'}`
    a.click()
  }, [format, since, until, limit])

  const activeFormat = SIEM_FORMATS.find(f => f.value === format)!

  return (
    <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5 space-y-5">

      {/* セクションヘッダー */}
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0" />
        <h2 className="text-base font-semibold text-white">SIEM エクスポート</h2>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">

        {/* フォーマット選択 */}
        <div className="space-y-2 lg:col-span-1">
          <label className="block text-xs font-medium text-[#8899aa] uppercase tracking-wide">
            フォーマット
          </label>
          <div className="flex gap-1">
            {SIEM_FORMATS.map(f => (
              <button
                key={f.value}
                onClick={() => setFormat(f.value)}
                className={`flex-1 py-1.5 text-xs font-semibold rounded-lg border transition-colors ${
                  format === f.value
                    ? 'bg-cyan-700 border-cyan-500 text-white'
                    : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-white hover:border-[#2a3d5a]'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <p className="text-[10px] text-[#5a6a7a] leading-relaxed min-h-[2.5em]">
            {activeFormat.description}
          </p>
        </div>

        {/* 開始日時 */}
        <div className="space-y-2">
          <label className="block text-xs font-medium text-[#8899aa] uppercase tracking-wide">
            開始日時 (From)
          </label>
          <input
            type="datetime-local"
            value={since}
            onChange={e => setSince(e.target.value)}
            className="w-full px-3 py-1.5 text-xs border border-[#1e2d42] rounded-lg
                       bg-[#080c14] text-white
                       focus:outline-none focus:border-cyan-500 transition-colors
                       [color-scheme:dark]"
          />
        </div>

        {/* 終了日時 */}
        <div className="space-y-2">
          <label className="block text-xs font-medium text-[#8899aa] uppercase tracking-wide">
            終了日時 (To)
          </label>
          <input
            type="datetime-local"
            value={until}
            onChange={e => setUntil(e.target.value)}
            className="w-full px-3 py-1.5 text-xs border border-[#1e2d42] rounded-lg
                       bg-[#080c14] text-white
                       focus:outline-none focus:border-cyan-500 transition-colors
                       [color-scheme:dark]"
          />
        </div>

        {/* レコード上限 */}
        <div className="space-y-2">
          <label className="block text-xs font-medium text-[#8899aa] uppercase tracking-wide">
            レコード上限
          </label>
          <select
            value={limit}
            onChange={e => setLimit(e.target.value)}
            className="w-full px-3 py-1.5 text-xs border border-[#1e2d42] rounded-lg
                       bg-[#080c14] text-white
                       focus:outline-none focus:border-cyan-500 transition-colors
                       [color-scheme:dark]"
          >
            {UNIQUE_LIMIT_OPTIONS.map(opt => (
              <option key={opt.value + opt.label} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

      </div>

      {/* エクスポートボタン */}
      <div className="flex justify-end pt-1">
        <button
          onClick={handleExport}
          className="flex items-center gap-2 px-5 py-2 bg-cyan-700 hover:bg-cyan-600
                     border border-cyan-500 text-white text-sm font-medium rounded-lg
                     transition-colors"
        >
          <Download className="w-4 h-4" />
          エクスポート
        </button>
      </div>

    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────────

export default function AdminAuditPage() {
  const [page, setPage]               = useState(1)
  const [userFilter, setUserFilter]   = useState('')
  const [methodFilter, setMethodFilter] = useState<Method>('')
  const [errorsOnly, setErrorsOnly]   = useState(false)

  const params = new URLSearchParams({
    page:     String(page),
    per_page: String(PER_PAGE),
    ...(userFilter    && { user: userFilter }),
    ...(methodFilter  && { method: methodFilter }),
    ...(errorsOnly    && { errors: '1' }),
  })

  const { data, isLoading, refetch, isFetching } = useQuery<AuditResponse>({
    queryKey: ['admin-audit', page, userFilter, methodFilter, errorsOnly],
    queryFn: () => apiFetch(`/api/v1/audit?${params}`),
    refetchInterval: 30_000,
  })

  const logs      = data?.logs ?? []
  const totalPages = data ? Math.ceil(data.total / PER_PAGE) : 1
  const hasFilters = !!(userFilter || methodFilter || errorsOnly)

  const clearFilters = useCallback(() => {
    setUserFilter('')
    setMethodFilter('')
    setErrorsOnly(false)
    setPage(1)
  }, [])

  return (
    <div className="p-6 space-y-6">

      {/* ─── ヘッダー ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ClipboardList className="w-6 h-6 text-purple-400" />
            監査ログ
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            全操作履歴の記録と検索（管理者専用）
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* CSVエクスポート */}
          <button
            onClick={() => exportCsv(logs)}
            disabled={logs.length === 0}
            className="flex items-center gap-2 px-4 py-2 bg-[#161f33] border border-[#1e2d42]
                       text-[#8899aa] hover:text-white hover:bg-[#1d2f4a] text-sm rounded-lg
                       transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            CSVエクスポート
          </button>

          {/* 更新 */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 px-4 py-2 bg-[#161f33] border border-[#1e2d42]
                       text-[#8899aa] hover:text-white hover:bg-[#1d2f4a] text-sm rounded-lg
                       transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* ─── フィルターバー ──────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-3 bg-[#111827] border border-[#1e2d42]
                      rounded-xl px-4 py-3">
        <Filter className="w-4 h-4 text-[#5a6a7a] flex-shrink-0" />

        {/* メールアドレス検索 */}
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
          <input
            value={userFilter}
            onChange={e => { setUserFilter(e.target.value); setPage(1) }}
            placeholder="メールで検索..."
            className="pl-8 pr-3 py-1.5 text-xs border border-[#1e2d42] rounded-lg
                       bg-[#080c14] text-white placeholder-[#5a6a7a] w-52
                       focus:outline-none focus:border-purple-500 transition-colors"
          />
        </div>

        {/* メソッドセレクター */}
        <div className="flex gap-1 flex-wrap">
          {METHODS.map(m => (
            <button
              key={m === '' ? '__all__' : m}
              onClick={() => { setMethodFilter(m); setPage(1) }}
              className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${
                methodFilter === m
                  ? 'bg-purple-700 border-purple-600 text-white'
                  : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-[#e2e8f4] hover:border-[#2a3d5a]'
              }`}
            >
              {m === '' ? 'ALL' : m}
            </button>
          ))}
        </div>

        {/* エラーのみトグル */}
        <button
          onClick={() => { setErrorsOnly(v => !v); setPage(1) }}
          className={`flex items-center gap-1.5 px-3 py-1 text-xs rounded-full border transition-colors ${
            errorsOnly
              ? 'bg-red-800 text-red-200 border-red-600'
              : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-[#e2e8f4] hover:border-[#2a3d5a]'
          }`}
        >
          <XCircle className="w-3 h-3" />
          エラーのみ
        </button>

        {/* フィルタークリア */}
        {hasFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-white
                       px-2 py-1 rounded-lg hover:bg-[#161f33] transition-colors ml-auto"
          >
            <X className="w-3.5 h-3.5" />
            クリア
          </button>
        )}
      </div>

      {/* ─── 件数表示 ────────────────────────────────────────────────── */}
      {!isLoading && data && (
        <p className="text-[#8899aa] text-sm">
          全 <span className="text-white font-medium">{(data.total ?? 0).toLocaleString()}</span> 件
          {data.total > PER_PAGE && (
            <span className="ml-1">
              （{((page - 1) * PER_PAGE + 1).toLocaleString()}–
              {Math.min(page * PER_PAGE, data.total).toLocaleString()} 件を表示）
            </span>
          )}
        </p>
      )}

      {/* ─── ユーザーサマリー ─────────────────────────────────────────── */}
      {logs.length > 0 && <UserSummarySection logs={logs} />}

      {/* ─── ログテーブル ────────────────────────────────────────────── */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : logs.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-[#5a6a7a]">
            <ClipboardList className="w-10 h-10 mb-3 opacity-20" />
            <p className="text-sm">監査ログがありません</p>
            {hasFilters && (
              <button
                onClick={clearFilters}
                className="mt-2 text-xs text-purple-400 hover:text-purple-300 transition-colors underline"
              >
                フィルターをクリア
              </button>
            )}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#080c14]/30">
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  日時
                </th>
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  ユーザー
                </th>
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  アクション
                </th>
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  リソースID
                </th>
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  IPアドレス
                </th>
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  ステータス
                </th>
                <th className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  リスク
                </th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => {
                const method  = extractMethod(log.action)
                const path    = log.action.replace(/^\S+\s+/, '')
                const sStyle  = statusStyle(log.status_code)
                const dotStyle = statusDotStyle(log.status_code)

                const riskScore = computeRiskScore(log)

                return (
                  <tr
                    key={log.id}
                    className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#161f33] transition-colors"
                  >
                    {/* 日時 */}
                    <td className="px-4 py-3 text-[#8899aa] text-xs font-mono whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString('ja-JP')}
                    </td>

                    {/* ユーザー */}
                    <td className="px-4 py-3">
                      <span className="text-[#c8d8e8] text-xs font-mono">
                        {log.user_email ?? log.user_id ?? '—'}
                      </span>
                    </td>

                    {/* アクション */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`shrink-0 text-xs px-1.5 py-0.5 rounded font-mono ${methodBadgeStyle(method)}`}>
                          {method}
                        </span>
                        <span className="text-[#e2e8f4] text-xs font-mono truncate max-w-[260px]" title={path}>
                          {path}
                        </span>
                      </div>
                    </td>

                    {/* リソースID */}
                    <td className="px-4 py-3">
                      {log.resource_id ? (
                        <span
                          className="text-[#5a6a7a] text-xs font-mono"
                          title={log.resource_id}
                        >
                          {log.resource_id.length > 12
                            ? log.resource_id.slice(0, 8) + '…'
                            : log.resource_id}
                        </span>
                      ) : (
                        <span className="text-[#3a4a5a] text-xs">—</span>
                      )}
                    </td>

                    {/* IPアドレス */}
                    <td className="px-4 py-3">
                      <span className="text-[#5a6a7a] text-xs font-mono whitespace-nowrap">
                        {log.ip_address || '—'}
                      </span>
                    </td>

                    {/* ステータスコード */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${dotStyle}`} />
                        <span className={`text-xs font-mono font-semibold ${sStyle}`}>
                          {log.status_code}
                        </span>
                      </div>
                    </td>

                    {/* リスクスコア */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 min-w-[80px]">
                        <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${riskBarColor(riskScore)}`}
                            style={{ width: `${riskScore}%` }}
                          />
                        </div>
                        <span className={`text-[10px] font-semibold w-4 shrink-0 ${riskLabelColor(riskScore)}`}>
                          {riskLabel(riskScore)}
                        </span>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* ─── ページネーション ─────────────────────────────────────────── */}
      {data && data.total > PER_PAGE && (
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 bg-[#161f33] border border-[#1e2d42] text-[#8899aa] text-sm
                       rounded-lg disabled:opacity-40 hover:bg-[#1d2f4a] transition-colors"
          >
            前へ
          </button>
          <span className="text-[#8899aa] text-sm">
            {page} / {totalPages} ページ
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="px-4 py-2 bg-[#161f33] border border-[#1e2d42] text-[#8899aa] text-sm
                       rounded-lg disabled:opacity-40 hover:bg-[#1d2f4a] transition-colors"
          >
            次へ
          </button>
        </div>
      )}

      {/* ─── SIEMエクスポート ─────────────────────────────────────────── */}
      <SiemExportPanel />

    </div>
  )
}
