'use client'

import { useState, Suspense, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import type { Alert, AlertStatus, PaginatedResponse } from '@/types/api'
import { apiFetch } from '@/lib/api'
import { AlertCard } from '@/components/alerts/AlertCard'
import { DataUnavailable } from '@/components/DataUnavailable'
import { useRealtimeAlerts } from '@/lib/websocket'
import { Filter, RefreshCw, CheckSquare, UserCheck, Search, X, Download, Clock, AlertTriangle, ChevronDown, Layers, List } from 'lucide-react'
import { useCanWrite } from '@/lib/auth'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface UserItem {
  id: string
  email: string
  full_name: string
  role: string
}

// ── Severity color helpers ────────────────────────────────────────────────────
const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-700/40',
  high:     'text-orange-400 bg-orange-900/30 border-orange-700/40',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-700/40',
  low:      'text-blue-400 bg-blue-900/30 border-blue-700/40',
}

const SEV_LABEL: Record<string, string> = {
  critical: 'クリティカル',
  high:     '高',
  medium:   '中',
  low:      '低',
}

// ── Alert Group View ──────────────────────────────────────────────────────────
function AlertGroupView({ alerts }: { alerts: Alert[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  // Group by rule_name (fallback to 'Unknown Rule')
  const groups = alerts.reduce<Record<string, Alert[]>>((acc, a) => {
    const key = a.rule_name ?? 'Unknown Rule'
    ;(acc[key] ??= []).push(a)
    return acc
  }, {})

  const sortedGroups = Object.entries(groups).sort((a, b) => b[1].length - a[1].length)

  const toggle = (key: string) => setExpanded(prev => {
    const next = new Set(prev)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    return next
  })

  const topSeverity = (list: Alert[]) => {
    const max = Math.max(...list.map(a => a.severity as number))
    if (max >= 8) return 'critical'
    if (max >= 6) return 'high'
    if (max >= 4) return 'medium'
    return 'low'
  }

  return (
    <div className="space-y-2">
      <p className="text-xs text-[#5a6a7a] mb-3">
        {sortedGroups.length}グループ（ルール名でグループ化）
      </p>
      {sortedGroups.map(([ruleName, group]) => {
        const sev = topSeverity(group)
        const isOpen = expanded.has(ruleName)
        const hostnames = [...new Set(group.map(a => a.agent_hostname))].slice(0, 5)
        return (
          <div key={ruleName} className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            <button
              onClick={() => toggle(ruleName)}
              className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[#19253d]/30 transition-colors text-left"
            >
              <ChevronDown className={`w-4 h-4 text-[#5a6a7a] shrink-0 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
              <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold ${SEV_COLOR[sev] ?? SEV_COLOR.low}`}>
                {SEV_LABEL[sev] ?? sev}
              </span>
              <span className="font-medium text-[#e2e8f4] text-sm flex-1 truncate">{ruleName}</span>
              <span className="text-xs text-[#5a6a7a] shrink-0 ml-2">
                {group.length}件 · {hostnames.join(', ')}{hostnames.length < [...new Set(group.map(a => a.agent_hostname))].length ? '…' : ''}
              </span>
            </button>
            {isOpen && (
              <div className="border-t border-[#1e2d42] space-y-0">
                {group.map(alert => (
                  <div key={alert.id} className="border-b border-[#1e2d42]/50 last:border-0 px-4 py-1">
                    <AlertCard alert={alert} />
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

const STATUSES: { value: AlertStatus | ''; label: string }[] = [
  { value: '',               label: 'すべて' },
  { value: 'open',           label: '未対応' },
  { value: 'investigating',  label: '調査中' },
  { value: 'resolved',       label: '解決済み' },
  { value: 'false_positive', label: '誤検知' },
]

function AlertsInner() {
  const qc = useQueryClient()
  const searchParams = useSearchParams()
  const [exportError, setExportError] = useState('')
  const [status, setStatus]         = useState<string>(searchParams.get('status') ?? '')
  const [severity, setSeverity]     = useState<string>(searchParams.get('severity') ?? '')
  const [search, setSearch]         = useState(searchParams.get('q') ?? '')
  const [mitreTech, setMitreTech]   = useState(searchParams.get('mitre_technique') ?? '')
  const [fromDate, setFromDate]     = useState('')
  const [toDate, setToDate]         = useState('')
  const [selected, setSelected]     = useState<Set<string>>(new Set())
  const [page, setPage]             = useState(1)
  const [showBulkAssign, setShowBulkAssign] = useState(false)
  const [assignTarget, setAssignTarget] = useState<string | null>(null)  // alert id for per-alert assign
  const [viewMode, setViewMode] = useState<'list' | 'group'>('list')
  const assignRef = useRef<HTMLDivElement>(null)

  const canWrite = useCanWrite()
  const [severityMin, severityMax] = severity ? severity.split(':') : ['', '']
  const params = new URLSearchParams({
    ...(status      && { status }),
    ...(severityMin && { severity: severityMin }),
    ...(severityMax && { severity_max: severityMax }),
    ...(search      && { search }),
    ...(mitreTech   && { mitre_technique: mitreTech }),
    ...(fromDate    && { from: new Date(fromDate).toISOString() }),
    ...(toDate      && { to: new Date(toDate + 'T23:59:59').toISOString() }),
    page: String(page),
    per_page: '20',
  })

  const { data, isLoading, isError, error, refetch } = useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts', status, severity, search, mitreTech, fromDate, toDate, page],
    queryFn: () => apiFetch<PaginatedResponse<Alert>>(`/api/v1/alerts?${params}`),
    refetchInterval: 30_000,
  })

  const { latestAlerts } = useRealtimeAlerts()

  const { data: usersData } = useQuery<{ data: UserItem[] }>({
    queryKey: ['users'],
    queryFn: () => apiFetch('/api/v1/users'),
    enabled: showBulkAssign || !!assignTarget,
    staleTime: 60_000,
  })

  // SLA thresholds (hours) per severity bucket
  const SLA_HOURS: Record<string, number> = { critical: 4, high: 24, medium: 72, low: 168 }
  function slaHours(sev: number): number {
    if (sev >= 9) return SLA_HOURS.critical
    if (sev >= 7) return SLA_HOURS.high
    if (sev >= 5) return SLA_HOURS.medium
    return SLA_HOURS.low
  }

  // Close per-alert assign popup on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (assignRef.current && !assignRef.current.contains(e.target as Node)) {
        setAssignTarget(null)
      }
    }
    if (assignTarget) document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [assignTarget])

  const singleAssign = useMutation({
    mutationFn: ({ alertId, userId }: { alertId: string; userId: string }) =>
      apiFetch('/api/v1/alerts/bulk-update', {
        method: 'POST',
        body: JSON.stringify({ ids: [alertId], assigned_to: userId }),
      }),
    onSuccess: () => {
      setAssignTarget(null)
      qc.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const bulkUpdate = useMutation({
    mutationFn: (payload: { status?: string; assigned_to?: string }) =>
      apiFetch('/api/v1/alerts/bulk-update', {
        method: 'POST',
        body: JSON.stringify({ ids: Array.from(selected), ...payload }),
      }),
    onSuccess: () => {
      setSelected(new Set())
      setShowBulkAssign(false)
      qc.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const alerts = data?.data ?? []
  const total  = data?.total ?? 0

  const newAlerts = latestAlerts.filter(a =>
    !!a.id &&
    !alerts.find(existing => existing.id === a.id) &&
    (!status || a.status === status)
  )
  const displayAlerts = [...newAlerts, ...alerts]

  const slaStats = (() => {
    let breached = 0, atRisk = 0, ok = 0
    for (const a of displayAlerts) {
      if (a.status === 'resolved' || a.status === 'false_positive') continue
      const ageH = (Date.now() - new Date(a.created_at).getTime()) / 3600000
      const limit = slaHours(a.severity)
      if (ageH > limit) breached++
      else if (ageH > limit * 0.75) atRisk++
      else ok++
    }
    return { breached, atRisk, ok }
  })()

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selected.size === alerts.length) setSelected(new Set())
    else setSelected(new Set(alerts.map(a => a.id)))
  }

  function downloadCSV() {
    const token = localStorage.getItem('edr_token')
    const p = new URLSearchParams({
      ...(status    && { status }),
      ...(severity  && { severity }),
      ...(search    && { search }),
      ...(mitreTech && { mitre_technique: mitreTech }),
      ...(fromDate  && { from: new Date(fromDate).toISOString() }),
      ...(toDate    && { to: new Date(toDate + 'T23:59:59').toISOString() }),
    })
    const url = `/api/v1/alerts/export?${p}`
    const a = document.createElement('a')
    a.href = url
    a.download = ''
    // attach auth header via fetch then blob
    //
    // fetch は 4xx/5xx で reject しません。r.ok を見ないと、サーバが
    // 返したエラー本文がそのまま alerts_YYYY-MM-DD.csv として保存され、
    // 開くまで気づきません。
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.blob()
      })
      .then(blob => {
        a.href = URL.createObjectURL(blob)
        a.download = `alerts_${new Date().toISOString().slice(0, 10)}.csv`
        a.click()
        URL.revokeObjectURL(a.href)
      })
      .catch(e => setExportError(
        `アラートを書き出せませんでした（${e instanceof Error ? e.message : String(e)}）。` +
        'ファイルは作成していません'
      ))
  }

  return (
    <div className="p-6">
      <PageSaveFailed className="mb-4" />
      {exportError && (
        <div className="mb-4 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {exportError}
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">アラート</h1>
          <p className="text-sm text-[#8899aa]">{total.toLocaleString()}件</p>
        </div>
        <div className="flex items-center gap-2">
          {/* View mode toggle */}
          <div className="flex items-center bg-[#161f33] border border-[#1e2d42] rounded-lg overflow-hidden">
            <button
              onClick={() => setViewMode('list')}
              title="リスト表示"
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm transition-colors
                ${viewMode === 'list' ? 'bg-[#1d2f4a] text-[#e2e8f4]' : 'text-[#5a6a7a] hover:text-[#8899aa]'}`}
            >
              <List className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewMode('group')}
              title="グループ表示"
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm transition-colors
                ${viewMode === 'group' ? 'bg-[#1d2f4a] text-[#e2e8f4]' : 'text-[#5a6a7a] hover:text-[#8899aa]'}`}
            >
              <Layers className="w-4 h-4" />
            </button>
          </div>
          <button
            onClick={downloadCSV}
            title="現在のフィルターでCSVダウンロード"
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#8899aa] bg-[#161f33] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ['alerts'] })}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#8899aa] bg-[#161f33] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
        </div>
      </div>

      {/* SLA Summary */}
      {displayAlerts.length > 0 && (
        <div className="flex items-center gap-3 mb-5 flex-wrap">
          <span className="text-xs text-[#5a6a7a] flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5" /> SLA状況:
          </span>
          {slaStats.breached > 0 && (
            <span className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-full bg-[#e8002d]/15 text-[#ff4d6d] border border-[#e8002d]/30 font-medium">
              <AlertTriangle className="w-3 h-3" />
              期限超過 {slaStats.breached}件
            </span>
          )}
          {slaStats.atRisk > 0 && (
            <span className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-full bg-[#ff9800]/10 text-[#ffb74d] border border-[#ff9800]/30 font-medium">
              <Clock className="w-3 h-3" />
              期限間近 {slaStats.atRisk}件
            </span>
          )}
          <span className="text-xs px-2.5 py-1 rounded-full bg-[#00c853]/10 text-[#69f0ae] border border-[#00c853]/30 font-medium">
            正常 {slaStats.ok}件
          </span>
        </div>
      )}

      {/* 取得に失敗しているとき、上のヘッダーは 0件 と表示します。
          その 0 が事実なのかどうかをここで言う。 */}
      <DataUnavailable error={error} what="アラート" onRetry={refetch} className="mb-4" />

      {/* Filters */}
      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#5a6a7a]" />
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            placeholder="タイトル・ホスト名で検索..."
            className="pl-9 pr-4 py-1.5 text-sm border border-[#1e2d42] rounded-lg bg-[#111827] text-white placeholder-[#5a6a7a] w-56 focus:outline-hidden focus:border-[#1a6bff]"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="w-4 h-4 text-[#5a6a7a]" />
          <span className="text-sm text-[#5a6a7a]">フィルター:</span>
        </div>

        <div className="flex gap-1">
          {STATUSES.map(({ value, label }) => (
            <button
              key={value}
              onClick={() => { setStatus(value); setPage(1) }}
              className={`px-3 py-1 text-xs rounded-full transition-colors ${
                status === value
                  ? 'bg-[#1a6bff] text-white'
                  : 'bg-[#161f33] border border-[#1e2d42] text-[#8899aa] hover:border-[#1e2d42] hover:text-[#e2e8f4]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <select
          value={severity}
          onChange={e => { setSeverity(e.target.value); setPage(1) }}
          className="text-xs border border-[#1e2d42] rounded-lg px-2 py-1 bg-[#161f33] text-[#8899aa] focus:outline-hidden focus:border-[#1a6bff]"
        >
          <option value="">重大度: すべて</option>
          <option value="9:10">クリティカル (9-10)</option>
          <option value="7:8">高 (7-8)</option>
          <option value="5:6">中 (5-6)</option>
          <option value="1:4">低 (1-4)</option>
        </select>

        <div className="flex items-center gap-1.5">
          <input
            type="date"
            value={fromDate}
            onChange={e => { setFromDate(e.target.value); setPage(1) }}
            title="開始日"
            className="text-xs border border-[#1e2d42] rounded-lg px-2 py-1 bg-[#161f33] text-[#8899aa] focus:outline-hidden focus:border-[#1a6bff]"
          />
          <span className="text-[#5a6a7a] text-xs">〜</span>
          <input
            type="date"
            value={toDate}
            onChange={e => { setToDate(e.target.value); setPage(1) }}
            title="終了日"
            className="text-xs border border-[#1e2d42] rounded-lg px-2 py-1 bg-[#161f33] text-[#8899aa] focus:outline-hidden focus:border-[#1a6bff]"
          />
        </div>

        {mitreTech && (
          <button
            onClick={() => { setMitreTech(''); setPage(1) }}
            className="flex items-center gap-1 text-xs text-blue-300 bg-blue-900/30 border border-blue-700 px-2 py-1 rounded-lg hover:bg-blue-900/50 transition-colors"
            title="MITREフィルターを解除"
          >
            MITRE: {mitreTech} ×
          </button>
        )}

        {(search || status || severity || fromDate || toDate || mitreTech) && (
          <button
            onClick={() => {
              setSearch(''); setStatus(''); setSeverity(''); setFromDate(''); setToDate(''); setMitreTech(''); setPage(1)
            }}
            className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-white px-2 py-1 rounded-lg hover:bg-[#19253d] transition-colors"
            title="フィルターをすべてクリア"
          >
            <X className="w-3.5 h-3.5" />
            クリア
          </button>
        )}
      </div>

      {/* Bulk actions (admin/analyst only) */}
      {canWrite && selected.size > 0 && (
        <div className="mb-4 p-3 bg-blue-900/30 rounded-xl border border-blue-700/50 space-y-2">
          <div className="flex items-center gap-2">
            <CheckSquare className="w-4 h-4 text-blue-400" />
            <span className="text-sm text-blue-300">{selected.size}件を選択中</span>
            <div className="flex gap-2 ml-auto flex-wrap">
              <button
                onClick={() => bulkUpdate.mutate({ status: 'open' })}
                disabled={bulkUpdate.isPending}
                className="text-xs px-3 py-1 bg-red-900/40 text-red-300 border border-red-700/50 rounded-lg hover:bg-red-900/60 transition-colors disabled:opacity-50"
              >
                未対応に戻す
              </button>
              <button
                onClick={() => bulkUpdate.mutate({ status: 'investigating' })}
                disabled={bulkUpdate.isPending}
                className="text-xs px-3 py-1 bg-yellow-900/40 text-yellow-300 border border-yellow-700/50 rounded-lg hover:bg-yellow-900/60 transition-colors disabled:opacity-50"
              >
                調査中にする
              </button>
              <button
                onClick={() => bulkUpdate.mutate({ status: 'resolved' })}
                disabled={bulkUpdate.isPending}
                className="text-xs px-3 py-1 bg-green-900/40 text-green-300 border border-green-700/50 rounded-lg hover:bg-green-900/60 transition-colors disabled:opacity-50"
              >
                解決済みにする
              </button>
              <button
                onClick={() => bulkUpdate.mutate({ status: 'false_positive' })}
                disabled={bulkUpdate.isPending}
                className="text-xs px-3 py-1 bg-[#161f33] text-[#8899aa] border border-[#1e2d42] rounded-lg hover:bg-[#1d2f4a] transition-colors disabled:opacity-50"
              >
                誤検知にする
              </button>
              <button
                onClick={() => setShowBulkAssign(v => !v)}
                className={`text-xs px-3 py-1 border rounded-lg transition-colors flex items-center gap-1 ${
                  showBulkAssign
                    ? 'bg-blue-700 text-white border-blue-600'
                    : 'bg-[#161f33] text-[#8899aa] border-[#1e2d42] hover:bg-[#1d2f4a]'
                }`}
              >
                <UserCheck className="w-3 h-3" />
                担当者を割り当て
              </button>
              <button
                onClick={() => { setSelected(new Set()); setShowBulkAssign(false) }}
                className="text-xs text-[#5a6a7a] hover:text-[#8899aa] transition-colors"
              >
                選択解除
              </button>
            </div>
          </div>

          {/* Bulk assign panel */}
          {showBulkAssign && (
            <div className="flex items-center gap-2 pt-1 border-t border-blue-700/30">
              <UserCheck className="w-3.5 h-3.5 text-blue-400 shrink-0" />
              <select
                className="flex-1 text-xs bg-[#111827] border border-[#1e2d42] rounded-lg px-2 py-1.5 text-[#8899aa] focus:outline-hidden focus:border-[#1a6bff]"
                defaultValue=""
                onChange={e => {
                  bulkUpdate.mutate({ assigned_to: e.target.value })
                }}
              >
                <option value="">担当者を選択...</option>
                <option value="">未割り当て</option>
                {(usersData?.data ?? []).map(u => (
                  <option key={u.id} value={u.id}>
                    {u.full_name || u.email}
                  </option>
                ))}
              </select>
              <span className="text-xs text-[#5a6a7a]">に選択中の{selected.size}件を割り当て</span>
            </div>
          )}
        </div>
      )}

      {/* Alert list / grouped view */}
      {isLoading ? (
        <AlertListSkeleton />
      ) : isError ? (
        <div className="text-center py-16 bg-[#111827] rounded-xl border border-[#e8002d]/30">
          <p className="text-[#e8002d] text-sm font-medium">アラートデータの取得に失敗しました</p>
          <p className="text-[#5a6a7a] text-xs mt-1">ネットワーク接続またはサーバーの状態を確認してください</p>
        </div>
      ) : displayAlerts.length === 0 ? (
        <div className="text-center py-16 bg-[#111827] rounded-xl border border-[#1e2d42]">
          <p className="text-[#5a6a7a] text-sm">アラートがありません</p>
        </div>
      ) : viewMode === 'group' ? (
        <AlertGroupView alerts={displayAlerts} />
      ) : (
        <div className="space-y-2">
          {canWrite && (
            <div className="flex items-center gap-3 px-1 pb-1">
              <input
                type="checkbox"
                checked={selected.size === alerts.length && alerts.length > 0}
                onChange={toggleSelectAll}
                className="rounded-sm border-[#1e2d42] bg-[#161f33] text-blue-600"
              />
              <span className="text-xs text-[#5a6a7a]">すべて選択</span>
            </div>
          )}

          {displayAlerts.map(alert => (
            <div key={alert.id} className="flex items-start gap-3 group/row">
              {canWrite && (
                <input
                  type="checkbox"
                  checked={selected.has(alert.id)}
                  onChange={() => toggleSelect(alert.id)}
                  className="mt-3 rounded-sm border-[#1e2d42] bg-[#161f33] text-blue-600"
                />
              )}
              <div className="flex-1">
                <AlertCard alert={alert} />
              </div>
              {/* Per-alert quick assign (admin/analyst only) */}
              {canWrite && <div className="mt-2 shrink-0 relative" ref={assignTarget === alert.id ? assignRef : null}>
                <button
                  onClick={e => { e.stopPropagation(); setAssignTarget(assignTarget === alert.id ? null : alert.id) }}
                  title="担当者を割り当て"
                  className={`opacity-0 group-hover/row:opacity-100 flex items-center gap-1 px-2 py-1.5 rounded-lg text-xs border transition-all
                    ${alert.assigned_to_name
                      ? 'bg-blue-900/30 text-blue-400 border-blue-700/50 opacity-100'
                      : 'bg-[#161f33] text-[#5a6a7a] border-[#1e2d42] hover:text-[#8899aa]'
                    }`}
                >
                  <UserCheck className="w-3.5 h-3.5" />
                  <ChevronDown className="w-3 h-3" />
                </button>
                {assignTarget === alert.id && (
                  <div className="absolute right-0 top-8 z-30 w-48 bg-[#111827] border border-[#1e2d42] rounded-xl shadow-2xl overflow-hidden">
                    <p className="text-[10px] text-[#3d5068] uppercase tracking-wider px-3 pt-2.5 pb-1">担当者を選択</p>
                    <button
                      onClick={() => singleAssign.mutate({ alertId: alert.id, userId: '' })}
                      disabled={singleAssign.isPending}
                      className="w-full text-left px-3 py-2 text-xs text-[#5a6a7a] hover:bg-[#1e2d42] hover:text-white transition-colors border-b border-[#1e2d42]"
                    >
                      未割り当て
                    </button>
                    {(usersData?.data ?? []).map(u => (
                      <button
                        key={u.id}
                        onClick={() => singleAssign.mutate({ alertId: alert.id, userId: u.id })}
                        disabled={singleAssign.isPending}
                        className="w-full text-left px-3 py-2 text-xs text-[#8899aa] hover:bg-[#1e2d42] hover:text-white transition-colors"
                      >
                        {u.full_name || u.email}
                      </button>
                    ))}
                    {(usersData?.data ?? []).length === 0 && (
                      <p className="px-3 py-2 text-xs text-[#3d5068]">ユーザーを読み込み中...</p>
                    )}
                  </div>
                )}
              </div>}
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {(data?.has_more || page > 1) && (
        <div className="flex justify-center gap-2 mt-6">
          <button
            disabled={page === 1}
            onClick={() => setPage(p => p - 1)}
            className="px-4 py-2 text-sm bg-[#161f33] border border-[#1e2d42] text-[#8899aa] rounded-lg disabled:opacity-50 hover:bg-[#1d2f4a] transition-colors"
          >
            前へ
          </button>
          <span className="px-4 py-2 text-sm text-[#8899aa]">{page}ページ</span>
          <button
            disabled={!data?.has_more}
            onClick={() => setPage(p => p + 1)}
            className="px-4 py-2 text-sm bg-[#161f33] border border-[#1e2d42] text-[#8899aa] rounded-lg disabled:opacity-50 hover:bg-[#1d2f4a] transition-colors"
          >
            次へ
          </button>
        </div>
      )}
    </div>
  )
}

export default function AlertsPage() {
  return (
    <Suspense fallback={<AlertListSkeleton />}>
      <AlertsInner />
    </Suspense>
  )
}

function AlertListSkeleton() {
  return (
    <div className="space-y-2">
      {[...Array(8)].map((_, i) => (
        <div key={i} className="h-24 bg-[#111827] rounded-xl border border-[#1e2d42] animate-pulse" />
      ))}
    </div>
  )
}
