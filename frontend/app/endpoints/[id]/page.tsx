'use client'

import React, { useMemo, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { formatDistanceToNow, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import {
  ArrowLeft, Monitor, ShieldAlert, ShieldCheck, Cpu, Activity,
  RefreshCw, Scan, Clock, AlertTriangle, Globe, FileText,
  History, CheckCircle, XCircle, Pencil, X, Check, Tag, Trash2
} from 'lucide-react'
import Link from 'next/link'
import { AgentStatusBadge, OSIcon } from '@/components/ui/badges'
import { useCanWrite } from '@/lib/auth'
import type { Agent } from '@/types/api'

interface ProcessInfo {
  id: string
  timestamp: string
  pid: string
  image: string
  cmdline: string
  parent_image: string
  user: string
  hashes: string
}

interface ProcessStatEntry {
  pid: number
  name: string
  cpu_pct: number
  mem_mb: number
}

interface AlertSummary {
  id: string
  title: string
  severity: number
  status: string
  created_at: string
}

interface AgentEvent {
  id: string
  agent_id: string
  event_type: string
  raw_data: Record<string, unknown>
  timestamp: string
}

interface ResponseAction {
  id: string
  action_type: string
  status: string
  triggered_by: string
  triggered_by_name?: string
  triggered_at: string
  completed_at?: string
  error?: string
  details?: Record<string, unknown>
}

// 対応履歴の「実行者」表示: ユーザー名(解決済) → なければ agent/system を日本語化 → 生値。
function actorLabel(name?: string, raw?: string): string {
  if (name && name.trim()) return name
  if (raw === 'agent') return 'エージェント (自動)'
  if (raw === 'system') return 'システム'
  return raw || '—'
}

export default function EndpointDetailPage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()
  const canWrite = useCanWrite()
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'overview' | 'processes' | 'alerts' | 'events' | 'software' | 'vulnerabilities' | 'process-tree' | 'timeline' | 'response-history' | 'live-response'>('overview')
  const [swSearch, setSwSearch]       = useState('')
  const [treeHours, setTreeHours]     = useState(4)
  const [timelineHours, setTimelineHours] = useState(24)
  const [timelineTypes, setTimelineTypes] = useState<string[]>([])
  const [treeExpanded, setTreeExpanded] = useState<Set<string>>(new Set())
  const [treeSearch, setTreeSearch]     = useState('')
  const [editingMeta, setEditingMeta]   = useState(false)
  const [tagInput, setTagInput]         = useState('')
  const [groupInput, setGroupInput]     = useState('')
  const [scanRowExpanded, setScanRowExpanded] = useState<Set<string>>(new Set())

  const { data: agent, isLoading } = useQuery<Agent>({
    queryKey: ['agent', id],
    queryFn: () => apiFetch<Agent>(`/api/v1/agents/${id}`),
    refetchInterval: 15_000,
  })

  const { data: processes } = useQuery<{ data: ProcessInfo[] }>({
    queryKey: ['agent-processes', id],
    queryFn: () => apiFetch(`/api/v1/agents/${id}/processes`),
    enabled: activeTab === 'processes',
  })

  const { data: processStats } = useQuery<{ data: ProcessStatEntry[]; updated_at: string | null }>({
    queryKey: ['agent-process-stats', id],
    queryFn: () => apiFetch(`/api/v1/agents/${id}/process-stats`),
    enabled: activeTab === 'processes',
    refetchInterval: 30_000,
  })
  // Build a lookup map: pid (as string) → stats
  const statsMap = Object.fromEntries(
    (processStats?.data ?? []).map(s => [String(s.pid), s])
  )

  const { data: alerts } = useQuery<{ data: AlertSummary[] }>({
    queryKey: ['agent-alerts', id],
    queryFn: () => apiFetch(`/api/v1/alerts?agent_id=${id}&per_page=20`),
    enabled: activeTab === 'alerts',
  })

  const { data: recentEvents, isFetching: eventsFetching } = useQuery<{ data: AgentEvent[]; total: number }>({
    queryKey: ['agent-events', id],
    queryFn: () => apiFetch(`/api/v1/agents/${id}/events?per_page=20`),
    enabled: activeTab === 'events',
  })

  const { data: groupsData } = useQuery<{ data: Array<{ id: string; name: string }> }>({
    queryKey: ['agent-groups'],
    queryFn: () => apiFetch('/api/v1/groups'),
    enabled: editingMeta,
  })

  interface ProcessNode { id: string; pid: string; ppid: string; image: string; cmdline: string; username: string; parent_image: string; timestamp: string }
  const { data: processTreeData } = useQuery<{ processes: ProcessNode[]; total: number }>({
    queryKey: ['agent-process-tree', id, treeHours],
    queryFn: () => apiFetch(`/api/v1/agents/${id}/process-tree?hours=${treeHours}`),
    enabled: activeTab === 'process-tree',
  })

  const { data: softwareData } = useQuery<{ data: Array<{ id: string; name: string; version: string; vendor: string; install_date: string }>; total: number }>({
    queryKey: ['agent-software', id],
    queryFn: () => apiFetch(`/api/v1/agents/${id}/software`),
    enabled: activeTab === 'software',
  })

  interface VulnRow {
    id: string; cve_id: string; title: string; severity: string
    cvss_score?: number; affected_package?: string; fixed_version?: string
    status: string; detected_at: string
  }
  const { data: vulnData } = useQuery<{ data: VulnRow[]; total: number }>({
    queryKey: ['agent-vulns', id],
    queryFn: () => apiFetch(`/api/v1/vulnerabilities?agent_id=${id}&per_page=100`),
    enabled: activeTab === 'vulnerabilities',
  })

  const { data: responseHistory } = useQuery<{ data: ResponseAction[]; total: number }>({
    queryKey: ['agent-response-history', id],
    queryFn: () => apiFetch(`/api/v1/agents/${id}/response-history`),
    enabled: activeTab === 'response-history',
  })

  // Pair `scan` (issued) and `scan_result` (reported) records into a single
  // logical row so the history table reads as one scan = one entry instead of
  // alternating issue/result lines. Pairing is heuristic (closest scan_result
  // within 10 minutes after a scan), which is sufficient because scans never
  // run in parallel for a given agent.
  type ScanRow = {
    type: 'scan'
    key: string
    triggeredAt: string
    triggeredBy?: string
    triggeredByName?: string
    completedAt?: string
    status: 'pending' | 'success' | 'warning' | 'failed' | 'cancelled' | 'timeout'
    scanType?: string
    target?: string
    scanned?: number
    matched?: number
    matches?: { file: string; rule: string; sha256?: string; size?: number }[]
  }
  type OtherRow = { type: 'other'; key: string; action: ResponseAction }
  type DisplayRow = ScanRow | OtherRow

  const displayRows: DisplayRow[] = useMemo(() => {
    const all: ResponseAction[] = responseHistory?.data ?? []
    const scans = all.filter(a => a.action_type === 'scan')
      .sort((a, b) => +new Date(a.triggered_at) - +new Date(b.triggered_at))
    const results = all.filter(a => a.action_type === 'scan_result')
      .sort((a, b) => +new Date(a.triggered_at) - +new Date(b.triggered_at))
    const others = all.filter(a => a.action_type !== 'scan' && a.action_type !== 'scan_result')

    const usedResults = new Set<string>()
    const rows: DisplayRow[] = []
    const PAIR_WINDOW_MS = 10 * 60 * 1000

    for (const scan of scans) {
      const scanTime = +new Date(scan.triggered_at)
      let pair: ResponseAction | undefined
      for (const r of results) {
        if (usedResults.has(r.id)) continue
        const rTime = +new Date(r.triggered_at)
        if (rTime < scanTime) continue
        if (rTime - scanTime > PAIR_WINDOW_MS) continue
        pair = r
        break
      }
      if (pair) usedResults.add(pair.id)

      const sd = (scan.details ?? {}) as { scan_type?: string }
      const rd = (pair?.details ?? {}) as {
        target?: string; scanned?: number; matched?: number
        matches?: { file: string; rule: string; sha256?: string; size?: number }[]
      }
      rows.push({
        type: 'scan',
        key: scan.id,
        triggeredAt: scan.triggered_at,
        triggeredBy: scan.triggered_by,
        triggeredByName: scan.triggered_by_name,
        completedAt: pair?.triggered_at,
        // No result paired: a scan still shows "実行中" only while a result could
        // realistically still arrive (within the pairing window). Past that the
        // agent restarted / the result was lost, so mark it timed-out rather than
        // leaving it spinning forever.
        status: pair
          ? (pair.status as ScanRow['status'])
          : (Date.now() - scanTime > PAIR_WINDOW_MS ? 'timeout' : 'pending'),
        scanType: sd.scan_type,
        target: rd.target,
        scanned: rd.scanned,
        matched: rd.matched,
        matches: rd.matches,
      })
    }

    // Orphan scan_results (no matching scan within window — typically older records)
    for (const r of results) {
      if (usedResults.has(r.id)) continue
      const rd = (r.details ?? {}) as {
        target?: string; scanned?: number; matched?: number
        matches?: { file: string; rule: string; sha256?: string; size?: number }[]
      }
      rows.push({
        type: 'scan',
        key: r.id,
        triggeredAt: r.triggered_at,
        triggeredBy: r.triggered_by,
        triggeredByName: r.triggered_by_name,
        completedAt: r.triggered_at,
        status: r.status as ScanRow['status'],
        target: rd.target,
        scanned: rd.scanned,
        matched: rd.matched,
        matches: rd.matches,
      })
    }

    for (const o of others) {
      rows.push({ type: 'other', key: o.id, action: o })
    }

    rows.sort((a, b) => {
      const at = a.type === 'scan' ? (a.completedAt || a.triggeredAt) : a.action.triggered_at
      const bt = b.type === 'scan' ? (b.completedAt || b.triggeredAt) : b.action.triggered_at
      return +new Date(bt) - +new Date(at)
    })
    return rows
  }, [responseHistory])

  interface TimelineItem {
    id: string; timestamp: string; category: string
    title: string; detail?: string; severity?: number; status?: string
  }
  const { data: timelineData, isFetching: timelineFetching } = useQuery<{ items: TimelineItem[]; total: number }>({
    queryKey: ['agent-timeline', id, timelineHours, timelineTypes.join(',')],
    queryFn: () => {
      const typesQ = timelineTypes.length > 0 ? `&types=${timelineTypes.join(',')}` : ''
      return apiFetch(`/api/v1/agents/${id}/timeline?hours=${timelineHours}${typesQ}`)
    },
    enabled: activeTab === 'timeline',
  })

  const isolate = useMutation({
    mutationFn: () => apiFetch(`/api/v1/agents/${id}/isolate`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent', id] }),
  })

  const unisolate = useMutation({
    mutationFn: () => apiFetch(`/api/v1/agents/${id}/unisolate`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent', id] }),
  })

  const scan = useMutation({
    mutationFn: () => apiFetch(`/api/v1/agents/${id}/scan`, { method: 'POST' }),
    onSuccess: () => {
      setActiveTab('live-response')
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] スキャンコマンドを送信しました`, ...prev])
      qc.invalidateQueries({ queryKey: ['agent-response-history', id] })
    },
    onError: (e: Error) => {
      setActiveTab('live-response')
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] エラー: ${e.message}`, ...prev])
    },
  })

  const scanCancel = useMutation({
    mutationFn: () => apiFetch(`/api/v1/agents/${id}/scan/cancel`, { method: 'POST' }),
    onSuccess: () => {
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] スキャン停止コマンドを送信しました`, ...prev])
      qc.invalidateQueries({ queryKey: ['agent-response-history', id] })
    },
    onError: (e: Error) => {
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] エラー: ${e.message}`, ...prev])
    },
  })

  const deleteAgent = useMutation({
    mutationFn: () => apiFetch(`/api/v1/agents/${id}`, { method: 'DELETE' }),
    onSuccess: () => router.push('/endpoints'),
  })

  const killProcess = useMutation({
    mutationFn: (pid: number) =>
      apiFetch(`/api/v1/agents/${id}/kill-process`, {
        method: 'POST',
        body: JSON.stringify({ pid }),
      }),
    onSuccess: (_: unknown, pid: number) => {
      setKillConfirmPid(null)
      qc.invalidateQueries({ queryKey: ['agent-processes', id] })
      setActiveTab('live-response')
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] PID ${pid} の終了コマンドを送信しました`, ...prev])
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      alert(`プロセス終了エラー: ${msg}`)
    },
  })
  const [killConfirmPid, setKillConfirmPid] = useState<number | null>(null)
  const [processSearch, setProcessSearch] = useState('')

  // Quarantine a single file matched by a YARA scan. Triggered from the
  // detection cards inside an expanded scan row on the response-history tab.
  const quarantineFile = useMutation({
    mutationFn: (path: string) =>
      apiFetch(`/api/v1/agents/${id}/quarantine-file`, {
        method: 'POST',
        body: JSON.stringify({ path, reason: 'manual: scan_result quarantine' }),
      }),
    onSuccess: (_: unknown, path: string) => {
      qc.invalidateQueries({ queryKey: ['agent-response-history', id] })
      setActiveTab('response-history')
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] ${path} の隔離コマンドを送信しました`, ...prev])
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      alert(`ファイル隔離エラー: ${msg}`)
    },
  })

  const updateMeta = useMutation({
    mutationFn: (payload: { tags: string[]; group_id: string | null }) =>
      apiFetch(`/api/v1/agents/${id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent', id] })
      setEditingMeta(false)
    },
  })

  const [lrOutput, setLrOutput]  = useState<string[]>([])
  const [lrCommand, setLrCommand] = useState('')

  // executeScan was a duplicate of `scan` above — both POST the same
  // /scan endpoint, but with separate isPending state, so the header
  // "スキャン" button and the live-response "フルスキャン" button could
  // each fire independently and result in two POSTs (the agent then
  // ran the scan twice, producing duplicate detection log entries).
  // Both buttons now share the single `scan` mutation defined above.

  const executeKillPidDirect = useMutation({
    mutationFn: (pid: number) =>
      apiFetch(`/api/v1/agents/${id}/kill-process`, { method: 'POST', body: JSON.stringify({ pid }) }),
    onSuccess: (_: unknown, pid: number) => {
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] PID ${pid} 終了コマンドを送信しました`, ...prev])
    },
    onError: (e: Error) => setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] エラー: ${e.message}`, ...prev]),
  })

  const executeQuarantine = useMutation({
    mutationFn: (path: string) =>
      apiFetch(`/api/v1/agents/${id}/quarantine-file`, { method: 'POST', body: JSON.stringify({ path }) }),
    onSuccess: (_: unknown, path: string) => {
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] ファイル隔離コマンドを送信しました: ${path}`, ...prev])
      qc.invalidateQueries({ queryKey: ['agent-response-history', id] })
    },
    onError: (e: Error) => setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] エラー: ${e.message}`, ...prev]),
  })

  const executeRestore = useMutation({
    mutationFn: ({ quarantineId, restorePath }: { quarantineId: string; restorePath: string }) =>
      apiFetch(`/api/v1/agents/${id}/restore-file`, { method: 'POST', body: JSON.stringify({ quarantine_id: quarantineId, restore_path: restorePath }) }),
    onSuccess: (_: unknown, vars: { quarantineId: string; restorePath: string }) => {
      setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] ファイル復元コマンドを送信しました: ${vars.quarantineId}`, ...prev])
      qc.invalidateQueries({ queryKey: ['agent-response-history', id] })
    },
    onError: (e: Error) => setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] エラー: ${e.message}`, ...prev]),
  })

  function openEditMeta() {
    setTagInput(agent?.tags?.join(', ') ?? '')
    setGroupInput(agent?.group_id ?? '')
    setEditingMeta(true)
  }

  function saveEditMeta() {
    const tags = tagInput.split(',').map(t => t.trim()).filter(Boolean)
    const group_id = groupInput.trim() || null
    updateMeta.mutate({ tags, group_id })
  }

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-blue-500" />
      </div>
    )
  }

  if (!agent) {
    return (
      <div className="p-6 text-center text-[#8899aa]">
        <Monitor className="w-12 h-12 mx-auto mb-3 opacity-30" />
        <p>エンドポイントが見つかりません</p>
        <button onClick={() => router.back()} className="mt-4 text-blue-400 hover:underline text-sm">
          ← 戻る
        </button>
      </div>
    )
  }

  function handleLrCommand() {
    const cmd = lrCommand.trim()
    if (!cmd) return
    setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] > ${cmd}`, ...prev])
    setLrCommand('')
    // Parse common commands
    const killMatch = cmd.match(/^kill(?:-process)?\s+(\d+)$/i)
    if (killMatch) {
      executeKillPidDirect.mutate(Number(killMatch[1]))
      return
    }
    if (cmd.toLowerCase() === 'scan') {
      scan.mutate()
      return
    }
    const quarantineMatch = cmd.match(/^quarantine\s+(.+)$/i)
    if (quarantineMatch) {
      executeQuarantine.mutate(quarantineMatch[1].trim())
      return
    }
    const restoreMatch = cmd.match(/^restore\s+(\S+)(?:\s+(.+))?$/i)
    if (restoreMatch) {
      executeRestore.mutate({ quarantineId: restoreMatch[1].trim(), restorePath: restoreMatch[2]?.trim() ?? '' })
      return
    }
    setLrOutput(prev => [`[${new Date().toLocaleTimeString()}] 不明なコマンド: ${cmd}`, ...prev])
  }

  const tabs = [
    { id: 'overview',       label: '概要' },
    { id: 'processes',      label: 'プロセス' },
    { id: 'process-tree',   label: 'プロセスツリー' },
    { id: 'timeline',       label: 'タイムライン' },
    { id: 'alerts',         label: 'アラート' },
    { id: 'events',         label: 'イベント' },
    { id: 'software',        label: 'ソフトウェア' },
    { id: 'vulnerabilities', label: '脆弱性' },
    { id: 'response-history', label: '対応履歴' },
    { id: 'live-response',  label: 'ライブレスポンス' },
  ] as const

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <button onClick={() => router.back()} className="text-[#8899aa] hover:text-white transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-2.5">
              <OSIcon os={agent.os_type} />
              <h1 className="text-2xl font-bold text-white">{agent.hostname}</h1>
              <AgentStatusBadge status={agent.status} />
            </div>
            <p className="text-[#8899aa] text-sm mt-0.5">
              {agent.os_type} {agent.os_version} · エージェント v{agent.agent_version}
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          {canWrite && (
          <button
            type="button"
            onClick={() => scan.mutate()}
            disabled={scan.isPending}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#161f33] hover:bg-[#1d2f4a]
                       text-white text-sm rounded-lg transition-colors disabled:opacity-50"
          >
            <Scan className="w-4 h-4" />
            {scan.isPending ? 'スキャン送信中...' : 'スキャン'}
          </button>
          )}

          {canWrite && (
          <button
            onClick={() => { if (confirm(`「${agent.hostname}」を削除しますか？この操作は取り消せません。`)) deleteAgent.mutate() }}
            disabled={deleteAgent.isPending}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#161f33] hover:bg-red-900/40
                       text-[#8899aa] hover:text-red-400 text-sm rounded-lg transition-colors disabled:opacity-50"
          >
            <Trash2 className="w-4 h-4" />
            削除
          </button>
          )}

          {canWrite && (agent.status === 'isolated' ? (
            <button
              onClick={() => { if (confirm('隔離を解除しますか？')) unisolate.mutate() }}
              disabled={unisolate.isPending}
              className="flex items-center gap-1.5 px-3 py-2 bg-green-600 hover:bg-green-500
                         text-white text-sm rounded-lg transition-colors disabled:opacity-50"
            >
              <ShieldCheck className="w-4 h-4" />
              隔離解除
            </button>
          ) : (
            <button
              onClick={() => { if (confirm(`${agent.hostname} を隔離しますか？`)) isolate.mutate() }}
              disabled={isolate.isPending || agent.status === 'offline'}
              className="flex items-center gap-1.5 px-3 py-2 bg-[#e8002d] hover:bg-[#b5001e]
                         text-white text-sm rounded-lg transition-colors disabled:opacity-50"
            >
              <ShieldAlert className="w-4 h-4" />
              隔離
            </button>
          ))}
        </div>
      </div>

      {/* Info cards */}
      <div className="grid grid-cols-4 gap-4">
        <InfoCard
          icon={Globe}
          label="IPアドレス"
          value={agent.ip_addresses?.[0] ?? '不明'}
        />
        <InfoCard
          icon={Clock}
          label="最終接続時刻"
          value={agent.last_seen
            ? `${formatDistanceToNow(parseISO(agent.last_seen), { addSuffix: true, locale: ja })} (${new Date(agent.last_seen).toLocaleString('ja-JP')})`
            : '不明'}
        />
        <InfoCard
          icon={Activity}
          label="登録日時"
          value={agent.enrolled_at
            ? formatDistanceToNow(parseISO(agent.enrolled_at), { addSuffix: true, locale: ja })
            : '不明'}
        />
        <InfoCard
          icon={Cpu}
          label="グループ"
          value={agent.group_id ?? '未割り当て'}
        />
      </div>

      {/* Tabs */}
      <div className="border-b border-[#1e2d42]">
        <div className="flex gap-0">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm transition-colors border-b-2 -mb-px ${
                activeTab === tab.id
                  ? 'border-blue-500 text-white'
                  : 'border-transparent text-[#8899aa] hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5 space-y-4">
            <h2 className="text-white font-semibold">システム情報</h2>
            <dl className="grid grid-cols-2 gap-x-8 gap-y-3 text-sm">
              {[
                ['ホスト名',       agent.hostname],
                ['OS',             `${agent.os_type} ${agent.os_version ?? ''}`],
                ['エージェントID', agent.id],
                ['バージョン',     agent.agent_version ?? '不明'],
                ['ステータス',     agent.status],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between border-b border-[#1e2d42] pb-2">
                  <dt className="text-[#8899aa]">{label}</dt>
                  <dd className="text-white font-mono text-xs">{value}</dd>
                </div>
              ))}
            </dl>

            {agent.status === 'isolated' && agent.isolated_at && (
              <div className="p-3 bg-red-900/30 border border-red-700 rounded-lg text-sm">
                <div className="flex items-center gap-2 text-red-400 font-medium mb-1">
                  <ShieldAlert className="w-4 h-4" />
                  隔離中
                </div>
                <p className="text-[#8899aa] text-xs">
                  理由: {agent.isolated_reason ?? '—'} | 実行: {agent.isolated_by ?? '—'}
                </p>
              </div>
            )}
          </div>

          {/* Tags & Group editing */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-white font-semibold flex items-center gap-2">
                <Tag className="w-4 h-4 text-[#8899aa]" />
                タグ / グループ
              </h2>
              {canWrite && (!editingMeta ? (
                <button
                  onClick={openEditMeta}
                  className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-white
                             px-2 py-1 rounded bg-[#161f33] hover:bg-[#1d2f4a] transition-colors"
                >
                  <Pencil className="w-3 h-3" />
                  編集
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <button
                    onClick={saveEditMeta}
                    disabled={updateMeta.isPending}
                    className="flex items-center gap-1 text-xs text-green-300 bg-green-900/40
                               px-2 py-1 rounded hover:bg-green-900/60 transition-colors disabled:opacity-50"
                  >
                    <Check className="w-3 h-3" />
                    保存
                  </button>
                  <button
                    onClick={() => setEditingMeta(false)}
                    className="flex items-center gap-1 text-xs text-[#8899aa] bg-[#161f33]
                               px-2 py-1 rounded hover:bg-[#1d2f4a] transition-colors"
                  >
                    <X className="w-3 h-3" />
                    キャンセル
                  </button>
                </div>
              ))}
            </div>

            {editingMeta ? (
              <div className="space-y-3">
                <div>
                  <label className="text-[#8899aa] text-xs block mb-1">タグ（カンマ区切り）</label>
                  <input
                    value={tagInput}
                    onChange={e => setTagInput(e.target.value)}
                    placeholder="例: critical, windows, production"
                    className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42]
                               text-sm focus:outline-none focus:border-[#1a6bff] font-mono"
                  />
                </div>
                <div>
                  <label className="text-[#8899aa] text-xs block mb-1">グループ</label>
                  <select
                    value={groupInput}
                    onChange={e => setGroupInput(e.target.value)}
                    className="w-full bg-[#080c14] text-white px-3 py-2 rounded-lg border border-[#1e2d42]
                               text-sm focus:outline-none focus:border-[#1a6bff]"
                  >
                    <option value="">— 未割り当て</option>
                    {(groupsData?.data ?? []).map(g => (
                      <option key={g.id} value={g.id}>{g.name}</option>
                    ))}
                  </select>
                </div>
                {updateMeta.isError && (
                  <p className="text-red-400 text-xs">更新に失敗しました</p>
                )}
              </div>
            ) : (
              <div className="space-y-2 text-sm">
                <div className="flex items-start gap-3">
                  <span className="text-[#8899aa] w-20 text-xs mt-0.5">タグ</span>
                  <div className="flex flex-wrap gap-1.5">
                    {(agent.tags ?? []).length > 0
                      ? agent.tags.map(tag => (
                          <span key={tag}
                            className="flex items-center gap-1 px-2 py-0.5 bg-blue-900/40 text-blue-300 text-xs rounded-full border border-blue-700/50">
                            {tag}
                            {canWrite && (
                            <button
                              onClick={() => {
                                const newTags = agent.tags.filter(t => t !== tag)
                                updateMeta.mutate({ tags: newTags, group_id: agent.group_id ?? null })
                              }}
                              className="text-blue-400 hover:text-red-400 transition-colors ml-0.5"
                            >×</button>
                            )}
                          </span>
                        ))
                      : <span className="text-[#5a6a7a] text-xs">なし</span>
                    }
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-[#8899aa] w-20 text-xs">グループ</span>
                  <span className="text-white text-xs font-mono">
                    {agent.group_id
                      ? (groupsData?.data?.find(g => g.id === agent.group_id)?.name ?? agent.group_id)
                      : '未割り当て'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'processes' && (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
            <div>
              <h2 className="text-white font-semibold text-sm">実行中のプロセス</h2>
              {processStats?.updated_at && (
                <p className="text-[10px] text-[#5a6a7a] mt-0.5">
                  CPU/メモリ更新: {new Date(processStats.updated_at).toLocaleTimeString('ja-JP')}
                </p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <input
                value={processSearch}
                onChange={e => setProcessSearch(e.target.value)}
                placeholder="プロセスを検索..."
                className="text-xs bg-[#080c14] border border-[#1e2d42] rounded px-2 py-1 text-white placeholder-[#5a6a7a] w-48 focus:outline-none focus:border-[#2e4d7a]"
              />
              <button
                onClick={() => qc.invalidateQueries({ queryKey: ['agent-processes', id] })}
                className="text-[#8899aa] hover:text-white"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>
          </div>
          {(processes?.data ?? []).length === 0 ? (
            <div className="text-center py-12 text-[#5a6a7a] text-sm">プロセス情報がありません</div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[#8899aa] border-b border-[#1e2d42] bg-[#080c14]/30">
                  <th className="px-4 py-2">タイムスタンプ</th>
                  <th className="px-4 py-2">イメージ</th>
                  <th className="px-4 py-2">PID</th>
                  <th className="px-4 py-2 text-right">CPU%</th>
                  <th className="px-4 py-2 text-right">メモリ(MB)</th>
                  <th className="px-4 py-2">ユーザー</th>
                  <th className="px-4 py-2">コマンドライン</th>
                  <th className="px-4 py-2">親プロセス</th>
                  <th className="px-4 py-2">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {(processes?.data ?? []).filter(p =>
                  !processSearch ||
                  p.image.toLowerCase().includes(processSearch.toLowerCase()) ||
                  String(p.pid ?? '').includes(processSearch) ||
                  (p.user ?? '').toLowerCase().includes(processSearch.toLowerCase()) ||
                  (p.cmdline ?? '').toLowerCase().includes(processSearch.toLowerCase())
                ).map(p => {
                  const imgBasename = p.image.split(/[/\\]/).pop() ?? p.image
                  const parentBasename = p.parent_image.split(/[/\\]/).pop() ?? p.parent_image
                  return (
                    <tr key={p.id} className="hover:bg-[#19253d]/30 transition-colors group">
                      <td className="px-4 py-2 font-mono text-[#5a6a7a] whitespace-nowrap">
                        {new Date(p.timestamp).toLocaleTimeString('ja-JP')}
                      </td>
                      <td className="px-4 py-2 text-white font-mono" title={p.image}>{imgBasename}</td>
                      <td className="px-4 py-2 font-mono text-[#8899aa]">{p.pid || '—'}</td>
                      {(() => {
                        const st = statsMap[String(p.pid)]
                        const cpu = st?.cpu_pct ?? null
                        const mem = st?.mem_mb ?? null
                        const cpuColor = cpu === null ? 'text-[#3d5068]' : cpu >= 50 ? 'text-red-400' : cpu >= 20 ? 'text-yellow-400' : 'text-[#8899aa]'
                        return (
                          <>
                            <td className={`px-4 py-2 font-mono text-right ${cpuColor}`}>
                              {cpu !== null ? `${cpu.toFixed(1)}%` : '—'}
                            </td>
                            <td className="px-4 py-2 font-mono text-right text-[#8899aa]">
                              {mem !== null ? mem.toFixed(1) : '—'}
                            </td>
                          </>
                        )
                      })()}
                      <td className="px-4 py-2 text-[#8899aa]">{p.user || '—'}</td>
                      <td className="px-4 py-2 text-[#5a6a7a] truncate max-w-[200px] font-mono" title={p.cmdline}>
                        {p.cmdline || '—'}
                      </td>
                      <td className="px-4 py-2 text-[#5a6a7a] font-mono" title={p.parent_image}>
                        {parentBasename || '—'}
                      </td>
                      <td className="px-4 py-2">
                        {canWrite && (killConfirmPid === Number(p.pid) ? (
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => killProcess.mutate(Number(p.pid))}
                              disabled={killProcess.isPending}
                              className="text-xs px-2 py-0.5 bg-[#e8002d] hover:bg-[#b5001e]
                                         text-white rounded transition-colors disabled:opacity-50"
                            >
                              {killProcess.isPending ? '...' : '確認'}
                            </button>
                            <button
                              onClick={() => setKillConfirmPid(null)}
                              className="text-xs text-[#5a6a7a] hover:text-[#8899aa]"
                            >
                              取消
                            </button>
                          </div>
                        ) : (
                          p.pid && agent?.status !== 'isolated' ? (
                            <button
                              onClick={() => setKillConfirmPid(Number(p.pid))}
                              className="text-xs text-red-400 hover:text-red-300 opacity-0
                                         group-hover:opacity-100 transition-opacity"
                              title="プロセスを終了"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                            </button>
                          ) : null
                        ))}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'alerts' && (
        <div className="space-y-2">
          {(alerts?.data ?? []).length === 0 ? (
            <div className="text-center py-12 text-[#5a6a7a] bg-[#111827] rounded-xl border border-[#1e2d42] text-sm">
              アラートはありません
            </div>
          ) : (
            (alerts?.data ?? []).map(alert => (
              <Link key={alert.id} href={`/alerts/${alert.id}`}
                className="flex items-center justify-between p-4 bg-[#111827] rounded-xl
                           border border-[#1e2d42] hover:border-[#1e2d42] transition-colors"
              >
                <div className="flex items-center gap-3">
                  <AlertTriangle className={`w-4 h-4 ${
                    alert.severity >= 8 ? 'text-red-400' :
                    alert.severity >= 5 ? 'text-yellow-400' : 'text-blue-400'
                  }`} />
                  <span className="text-white text-sm">{alert.title}</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-[#8899aa]">
                  <span className={`px-2 py-0.5 rounded-full ${
                    alert.status === 'open' ? 'bg-red-900/40 text-red-400' :
                    alert.status === 'resolved' ? 'bg-green-900/40 text-green-400' :
                    'bg-[#161f33] text-[#8899aa]'
                  }`}>{alert.status}</span>
                  <span>{formatDistanceToNow(parseISO(alert.created_at), { addSuffix: true, locale: ja })}</span>
                </div>
              </Link>
            ))
          )}
        </div>
      )}

      {activeTab === 'events' && (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#8899aa]" />
              <h2 className="text-white font-semibold text-sm">最近のイベント</h2>
              {recentEvents && (
                <span className="text-xs text-[#5a6a7a]">（直近20件）</span>
              )}
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => qc.invalidateQueries({ queryKey: ['agent-events', id] })}
                className="text-[#8899aa] hover:text-white"
              >
                <RefreshCw className={`w-4 h-4 ${eventsFetching ? 'animate-spin' : ''}`} />
              </button>
              <Link
                href={`/events?agent_id=${id}`}
                className="text-blue-400 hover:text-blue-300 text-xs transition-colors"
              >
                すべて検索 →
              </Link>
            </div>
          </div>

          {(recentEvents?.data ?? []).length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-[#5a6a7a]">
              <FileText className="w-10 h-10 mb-3 opacity-30" />
              <p className="text-sm">イベントはありません</p>
            </div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[#8899aa] border-b border-[#1e2d42] bg-[#080c14]/30">
                  <th className="px-4 py-2">タイムスタンプ</th>
                  <th className="px-4 py-2">種別</th>
                  <th className="px-4 py-2">概要</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {(recentEvents?.data ?? []).map(ev => (
                  <tr key={ev.id} className="hover:bg-[#161f33] transition-colors">
                    <td className="px-4 py-2 font-mono text-[#5a6a7a] whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleString('ja-JP')}
                    </td>
                    <td className="px-4 py-2">
                      <EventTypeBadge type={ev.event_type} />
                    </td>
                    <td className="px-4 py-2 text-[#8899aa] truncate max-w-[400px] font-mono">
                      {summarizeEvent(ev.event_type, ev.raw_data)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'process-tree' && (() => {
        const procs = processTreeData?.processes ?? []
        const suspPattern = /powershell|cmd|wscript|cscript|mshta|rundll|regsvr|certutil|bitsadmin|msiexec|svchost|lsass|csrss/i

        // Build tree
        const pidMap = new Map<string, ProcessNode[]>()
        const rootProcs: ProcessNode[] = []
        procs.forEach(p => { if (!pidMap.has(p.pid)) pidMap.set(p.pid, []) })
        procs.forEach(p => {
          const parentChildren = pidMap.get(p.ppid)
          if (parentChildren !== undefined && p.ppid !== p.pid && p.ppid !== '0') {
            parentChildren.push(p)
          } else {
            rootProcs.push(p)
          }
        })

        // Stats
        const suspCount = procs.filter(p => suspPattern.test(p.image.split(/[/\\]/).pop() ?? p.image)).length
        const uniqueExe = new Set(procs.map(p => (p.image.split(/[/\\]/).pop() ?? p.image).toLowerCase())).size

        // Search filter: collect matching node IDs + all ancestors
        const searchLower = treeSearch.toLowerCase().trim()
        const matchedIds = new Set<string>()
        if (searchLower) {
          const parentOf = new Map<string, string>() // nodeId → parentId
          procs.forEach(p => { if (p.ppid !== '0' && p.ppid !== p.pid) parentOf.set(p.id, p.ppid) })
          procs.forEach(p => {
            const imgName = (p.image.split(/[/\\]/).pop() ?? p.image).toLowerCase()
            if (imgName.includes(searchLower) || p.cmdline.toLowerCase().includes(searchLower) || p.pid.includes(searchLower)) {
              matchedIds.add(p.id)
              // Walk up ancestors
              let cur = p.ppid
              while (cur && cur !== '0') {
                const parent = procs.find(x => x.pid === cur)
                if (!parent) break
                matchedIds.add(parent.id)
                cur = parent.ppid
              }
            }
          })
        }

        // Expand all / collapse all helpers
        const expandAll = () => setTreeExpanded(new Set(procs.map(p => p.id)))
        const collapseAll = () => setTreeExpanded(new Set())

        function renderNode(node: ProcessNode, depth: number, isLast: boolean, prefixSegments: boolean[]): JSX.Element | null {
          if (searchLower && !matchedIds.has(node.id)) return null
          const children = (pidMap.get(node.pid) ?? []).filter(c => !searchLower || matchedIds.has(c.id))
          const isExp = searchLower ? true : treeExpanded.has(node.id)
          const imgName = node.image.split(/[/\\]/).pop() ?? node.image
          const isSusp = suspPattern.test(imgName)

          // Build connector prefix
          const connectors = prefixSegments.map((hasMore, i) => (
            <span key={i} className="select-none" style={{ display: 'inline-block', width: 16, textAlign: 'center', color: '#1e2d42' }}>
              {hasMore ? '│' : ' '}
            </span>
          ))
          const branch = depth > 0 ? (
            <span className="select-none" style={{ display: 'inline-block', width: 16, color: '#1e2d42' }}>
              {isLast ? '└' : '├'}
            </span>
          ) : null
          const dash = depth > 0 ? (
            <span className="select-none" style={{ color: '#1e2d42' }}>─ </span>
          ) : null

          return (
            <div key={node.id}>
              <div
                title={`${node.image}\nPID: ${node.pid}  PPID: ${node.ppid}\n${node.timestamp ? new Date(node.timestamp).toLocaleString('ja-JP') : ''}`}
                className={`flex items-center gap-0 py-0.5 px-1 rounded hover:bg-[#19253d]/50 cursor-pointer group ${isSusp ? 'bg-red-950/20' : ''}`}
                onClick={() => !searchLower && setTreeExpanded(prev => { const n = new Set(prev); n.has(node.id) ? n.delete(node.id) : n.add(node.id); return n })}
              >
                {/* Tree connectors */}
                <span className="font-mono text-xs flex-shrink-0 select-none">
                  {connectors}{branch}{dash}
                </span>

                {/* Expand toggle */}
                {!searchLower && (
                  <span className="text-[#5a6a7a] text-[10px] w-3 flex-shrink-0 select-none">
                    {children.length > 0 ? (isExp ? '▾' : '▸') : ''}
                  </span>
                )}

                {/* Process icon */}
                <span className="mr-1.5 text-[11px] flex-shrink-0">
                  {isSusp ? '⚠' : '⬡'}
                </span>

                {/* Process name */}
                <span className={`text-xs font-semibold flex-shrink-0 ${isSusp ? 'text-red-300' : 'text-[#e2e8f4]'}`}>
                  {imgName}
                </span>

                {/* Metadata badges */}
                <span className="text-[10px] text-[#5a6a7a] font-mono ml-2 flex-shrink-0">:{node.pid}</span>
                {node.username && (
                  <span className="text-[10px] text-[#5a6a7a] ml-2 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">{node.username}</span>
                )}
                {children.length > 0 && !isExp && (
                  <span className="text-[10px] text-blue-500/60 ml-2 flex-shrink-0">[+{children.length}]</span>
                )}
                {isSusp && (
                  <span className="text-[9px] text-red-400 bg-red-900/40 px-1 rounded ml-2 flex-shrink-0">suspicious</span>
                )}

                {/* Cmdline */}
                {node.cmdline && (
                  <span className="text-[10px] text-[#5a6a7a] font-mono ml-3 truncate flex-1 min-w-0">{node.cmdline}</span>
                )}
              </div>
              {isExp && children.map((c, i) =>
                renderNode(c, depth + 1, i === children.length - 1, [...prefixSegments, !isLast && depth > 0 || depth === 0 ? false : true])
              )}
            </div>
          )
        }

        return (
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42]">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42] gap-3 flex-wrap">
              <span className="text-sm font-medium text-[#8899aa]">プロセスツリー</span>
              <div className="flex items-center gap-2 flex-1 max-w-xs">
                <input
                  type="text"
                  placeholder="検索 (プロセス名/PID/コマンド)..."
                  value={treeSearch}
                  onChange={e => setTreeSearch(e.target.value)}
                  className="flex-1 bg-[#080c14] border border-[#1e2d42] rounded px-2 py-1 text-xs text-[#8899aa] placeholder-[#5a6a7a] focus:outline-none focus:border-[#1a6bff]"
                />
                {treeSearch && (
                  <button onClick={() => setTreeSearch('')} className="text-[#5a6a7a] hover:text-[#8899aa] text-xs">✕</button>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button onClick={expandAll} className="text-[10px] text-[#5a6a7a] hover:text-[#8899aa] px-2 py-1 border border-[#1e2d42] rounded transition-colors">すべて展開</button>
                <button onClick={collapseAll} className="text-[10px] text-[#5a6a7a] hover:text-[#8899aa] px-2 py-1 border border-[#1e2d42] rounded transition-colors">すべて折りたたむ</button>
                <div className="flex border border-[#1e2d42] rounded-lg overflow-hidden text-xs">
                  {[1, 4, 12, 24].map(h => (
                    <button key={h} onClick={() => setTreeHours(h)}
                      className={`px-2.5 py-1.5 transition-colors ${treeHours === h ? 'bg-[#1a6bff] text-white' : 'text-[#8899aa] hover:bg-[#19253d]'}`}>
                      {h}h
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Stats bar */}
            {procs.length > 0 && (
              <div className="flex items-center gap-6 px-4 py-2 bg-[#080c14]/40 border-b border-[#1e2d42]/50 text-[10px]">
                <span className="text-[#5a6a7a]">合計: <span className="text-[#8899aa] font-semibold">{procs.length}</span> プロセス</span>
                <span className="text-[#5a6a7a]">ユニーク実行ファイル: <span className="text-[#8899aa] font-semibold">{uniqueExe}</span></span>
                <span className="text-[#5a6a7a]">疑わしい: <span className={`font-semibold ${suspCount > 0 ? 'text-red-400' : 'text-green-400'}`}>{suspCount}</span></span>
                {searchLower && <span className="text-blue-400">検索結果: {matchedIds.size} 件</span>}
              </div>
            )}

            {procs.length === 0 ? (
              <p className="text-center text-[#5a6a7a] py-10 text-sm">プロセスイベントデータがありません</p>
            ) : (
              <div className="p-3 font-mono text-xs max-h-[600px] overflow-y-auto overflow-x-auto">
                {rootProcs
                  .filter(r => !searchLower || matchedIds.has(r.id))
                  .map((r, i, arr) => renderNode(r, 0, i === arr.length - 1, []))}
              </div>
            )}
          </div>
        )
      })()}

      {activeTab === 'software' && (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
            <span className="text-sm font-medium text-[#8899aa]">インストール済みソフトウェア ({softwareData?.total ?? 0}件)</span>
            <div className="flex items-center gap-2">
              <input
                className="bg-[#161f33] border border-[#1e2d42] rounded px-3 py-1.5 text-xs text-white w-44"
                placeholder="名前で絞り込み..."
                value={swSearch}
                onChange={e => setSwSearch(e.target.value)}
              />
              {swSearch && (
                <Link
                  href={`/software?q=${encodeURIComponent(swSearch)}`}
                  className="text-xs text-teal-400 hover:text-teal-300 whitespace-nowrap"
                >
                  全体を検索 →
                </Link>
              )}
              <Link
                href="/software"
                className="text-xs text-[#5a6a7a] hover:text-[#8899aa]"
              >
                管理
              </Link>
            </div>
          </div>
          {!softwareData?.data?.length ? (
            <p className="text-center text-[#5a6a7a] py-10 text-sm">ソフトウェアデータがありません</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42] text-[#8899aa]">
                  <th className="text-left px-4 py-2">名前</th>
                  <th className="text-left px-4 py-2">バージョン</th>
                  <th className="text-left px-4 py-2">ベンダー</th>
                  <th className="text-left px-4 py-2">インストール日</th>
                </tr>
              </thead>
              <tbody>
                {softwareData.data
                  .filter(sw => !swSearch || sw.name.toLowerCase().includes(swSearch.toLowerCase()))
                  .map(sw => (
                    <tr key={sw.id} className="border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30">
                      <td className="px-4 py-2 text-[#e2e8f4] font-medium">{sw.name}</td>
                      <td className="px-4 py-2 text-[#8899aa] font-mono">{sw.version || '—'}</td>
                      <td className="px-4 py-2 text-[#8899aa]">{sw.vendor || '—'}</td>
                      <td className="px-4 py-2 text-[#5a6a7a]">{sw.install_date || '—'}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'vulnerabilities' && (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-[#8899aa]">脆弱性 ({vulnData?.total ?? 0}件)</span>
            </div>
            <a href="/vulnerabilities" className="text-xs text-[#5a6a7a] hover:text-[#8899aa]">管理 →</a>
          </div>
          {!vulnData?.data?.length ? (
            <p className="text-center text-[#5a6a7a] py-10 text-sm">脆弱性データがありません</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42] text-[#8899aa]">
                  <th className="text-left px-4 py-2">CVE ID</th>
                  <th className="text-left px-4 py-2">タイトル</th>
                  <th className="text-left px-4 py-2">重大度</th>
                  <th className="text-left px-4 py-2">CVSS</th>
                  <th className="text-left px-4 py-2">パッケージ</th>
                  <th className="text-left px-4 py-2">ステータス</th>
                </tr>
              </thead>
              <tbody>
                {(vulnData?.data ?? []).map(v => {
                  const sevColor = v.severity === 'critical' ? 'text-red-400 bg-red-900/30 border-red-700' :
                    v.severity === 'high' ? 'text-orange-400 bg-orange-900/30 border-orange-700' :
                    v.severity === 'medium' ? 'text-yellow-400 bg-yellow-900/30 border-yellow-700' :
                    'text-blue-400 bg-blue-900/30 border-blue-700'
                  const statusColor = v.status === 'open' ? 'text-red-400' :
                    v.status === 'patched' ? 'text-green-400' :
                    v.status === 'mitigated' ? 'text-yellow-400' : 'text-[#8899aa]'
                  return (
                    <tr key={v.id} className="border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30">
                      <td className="px-4 py-2 font-mono text-[#1a6bff]">{v.cve_id}</td>
                      <td className="px-4 py-2 text-[#e2e8f4] max-w-xs truncate">{v.title}</td>
                      <td className="px-4 py-2">
                        <span className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold ${sevColor}`}>
                          {v.severity}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-[#8899aa] font-mono">{v.cvss_score ?? '—'}</td>
                      <td className="px-4 py-2 text-[#8899aa]">{v.affected_package || '—'}</td>
                      <td className={`px-4 py-2 font-medium ${statusColor}`}>
                        {v.status === 'open' ? '未対応' : v.status === 'patched' ? 'パッチ済' :
                         v.status === 'mitigated' ? '緩和済み' : v.status}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'response-history' && (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1e2d42]">
            <History className="w-4 h-4 text-[#8899aa]" />
            <h2 className="text-white font-semibold text-sm">対応アクション履歴</h2>
            {displayRows.length > 0 && (
              <span className="ml-auto text-xs text-[#5a6a7a]">{displayRows.length}件</span>
            )}
          </div>
          {displayRows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-[#5a6a7a]">
              <History className="w-10 h-10 mb-3 opacity-30" />
              <p className="text-sm">対応アクションの記録はありません</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[#8899aa] text-xs border-b border-[#1e2d42]">
                  <th className="px-4 py-3 w-8"></th>
                  <th className="px-4 py-3">アクション</th>
                  <th className="px-4 py-3">結果</th>
                  <th className="px-4 py-3">実行者</th>
                  <th className="px-4 py-3">開始</th>
                  <th className="px-4 py-3">完了</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {displayRows.map(row => {
                  if (row.type === 'other') {
                    const action = row.action
                    const det = (action.details ?? {}) as { path?: string; restore_path?: string; pid?: number; reason?: string; alert_id?: string }
                    const actionLabel =
                      action.action_type === 'isolate'         ? 'ネットワーク隔離' :
                      action.action_type === 'unisolate'       ? '隔離解除' :
                      action.action_type === 'kill_process'    ? 'プロセス終了' :
                      action.action_type === 'quarantine_file' ? 'ファイル隔離' :
                      action.action_type === 'restore_file'    ? 'ファイル復元' :
                      action.action_type
                    // Per-action subject line: surface "what" the action targeted
                    // (path/PID/reason) so the row is self-explanatory.
                    const subject =
                      (action.action_type === 'quarantine_file' && det.path) ? det.path :
                      (action.action_type === 'restore_file' && (det.restore_path || det.path)) ? (det.restore_path || det.path) :
                      (action.action_type === 'kill_process' && det.pid != null) ? `PID ${det.pid}` :
                      (action.action_type === 'isolate' && det.reason) ? det.reason :
                      ''
                    return (
                      <tr key={row.key} className="hover:bg-[#161f33] transition-colors">
                        <td className="px-4 py-3"></td>
                        <td className="px-4 py-3">
                          <div className="flex flex-col gap-1">
                            <span className={`text-xs px-2 py-1 rounded font-mono w-fit ${
                              action.action_type === 'isolate'        ? 'bg-red-900/40 text-red-300' :
                              action.action_type === 'unisolate'      ? 'bg-green-900/40 text-green-300' :
                              action.action_type === 'kill_process'   ? 'bg-orange-900/40 text-orange-300' :
                              action.action_type === 'quarantine_file'? 'bg-yellow-900/40 text-yellow-300' :
                              action.action_type === 'restore_file'   ? 'bg-blue-900/40 text-blue-300' :
                              'bg-[#161f33] text-[#8899aa]'
                            }`}>
                              {actionLabel}
                            </span>
                            {subject && (
                              <span className="text-[11px] text-[#aab4be] font-mono truncate max-w-[320px]" title={subject}>
                                {subject}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            {action.status === 'success'
                              ? <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                              : action.status === 'failed'
                              ? <XCircle className="w-3.5 h-3.5 text-red-400" />
                              : <RefreshCw className="w-3.5 h-3.5 text-blue-400 animate-spin" />}
                            <span className={`text-xs ${
                              action.status === 'success' ? 'text-green-400' :
                              action.status === 'failed'  ? 'text-red-400'   : 'text-blue-400'
                            }`}>
                              {action.status === 'failed' ? '失敗' :
                               action.status === 'success' ? '完了' : '実行中'}
                            </span>
                          </div>
                          {action.error && (
                            <p className="text-red-400 text-xs mt-0.5 truncate max-w-[260px]">{action.error}</p>
                          )}
                        </td>
                        <td className="px-4 py-3 text-[#8899aa] text-xs truncate max-w-[180px]" title={action.triggered_by}>{actorLabel(action.triggered_by_name, action.triggered_by)}</td>
                        <td className="px-4 py-3 text-[#8899aa] text-xs">{new Date(action.triggered_at).toLocaleString('ja-JP')}</td>
                        <td className="px-4 py-3 text-[#8899aa] text-xs">
                          {action.completed_at ? new Date(action.completed_at).toLocaleString('ja-JP') : '—'}
                        </td>
                      </tr>
                    )
                  }

                  const expanded = scanRowExpanded.has(row.key)
                  const detected = (row.matched ?? 0) > 0
                  const toggle = () => {
                    setScanRowExpanded(prev => {
                      const next = new Set(prev)
                      if (next.has(row.key)) next.delete(row.key); else next.add(row.key)
                      return next
                    })
                  }

                  return (
                    <React.Fragment key={row.key}>
                      <tr
                        onClick={toggle}
                        className={`cursor-pointer transition-colors ${
                          detected
                            ? 'bg-red-900/15 hover:bg-red-900/25 border-l-4 border-red-500'
                            : 'hover:bg-[#161f33]'
                        }`}
                      >
                        <td className="px-4 py-3 text-[#5a6a7a]">
                          <span className={`inline-block transition-transform ${expanded ? 'rotate-90' : ''}`}>▶</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="text-xs px-2 py-1 rounded font-mono bg-blue-900/40 text-blue-300">
                              フルスキャン
                            </span>
                            {row.scanType && row.scanType !== 'full' && (
                              <span className="text-[10px] text-[#7d92b0]">({row.scanType})</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {row.status === 'pending' ? (
                            <div className="flex items-center gap-2">
                              <div className="flex items-center gap-1.5">
                                <RefreshCw className="w-3.5 h-3.5 text-blue-400 animate-spin" />
                                <span className="text-xs text-blue-400">実行中</span>
                              </div>
                              {canWrite && (
                                <button
                                  onClick={() => scanCancel.mutate()}
                                  disabled={scanCancel.isPending}
                                  title="このスキャンを停止します"
                                  className="flex items-center gap-1 px-1.5 py-0.5 text-[11px] text-amber-300
                                             bg-amber-900/30 border border-amber-700/50 rounded hover:bg-amber-900/50
                                             disabled:opacity-50 transition-colors"
                                >
                                  <XCircle className="w-3 h-3" />
                                  停止
                                </button>
                              )}
                            </div>
                          ) : row.status === 'cancelled' ? (
                            <div className="flex items-center gap-1.5">
                              <XCircle className="w-3.5 h-3.5 text-amber-400" />
                              <span className="text-xs text-amber-400">停止済み ({row.scanned ?? 0}件走査)</span>
                            </div>
                          ) : row.status === 'timeout' ? (
                            <div className="flex items-center gap-1.5">
                              <Clock className="w-3.5 h-3.5 text-[#7d92b0]" />
                              <span className="text-xs text-[#7d92b0]">タイムアウト</span>
                            </div>
                          ) : detected ? (
                            <div className="flex items-center gap-2">
                              <span className="px-2 py-1 rounded bg-red-900/50 border border-red-500/50 text-red-200 text-xs font-bold">
                                ⚠ 検知 {row.matched}件
                              </span>
                              <span className="text-[11px] text-[#7d92b0]">{row.scanned ?? 0}件中</span>
                            </div>
                          ) : row.status === 'failed' ? (
                            <div className="flex items-center gap-1.5">
                              <XCircle className="w-3.5 h-3.5 text-red-400" />
                              <span className="text-xs text-red-400">失敗</span>
                            </div>
                          ) : (
                            <div className="flex items-center gap-1.5">
                              <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                              <span className="text-xs text-green-400">クリーン ({row.scanned ?? 0}件)</span>
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3 text-[#8899aa] text-xs truncate max-w-[180px]" title={row.triggeredBy}>{actorLabel(row.triggeredByName, row.triggeredBy)}</td>
                        <td className="px-4 py-3 text-[#8899aa] text-xs">{new Date(row.triggeredAt).toLocaleString('ja-JP')}</td>
                        <td className="px-4 py-3 text-[#8899aa] text-xs">
                          {row.completedAt ? new Date(row.completedAt).toLocaleString('ja-JP') : '—'}
                        </td>
                      </tr>
                      {expanded && (
                        <tr className={detected ? 'bg-red-950/30' : 'bg-[#0d1520]'}>
                          <td colSpan={6} className="px-6 py-4">
                            <div className="grid grid-cols-3 gap-4 text-xs mb-3">
                              <div>
                                <div className="text-[#5a6a7a] mb-1">スキャン対象</div>
                                <div className="text-[#aab4be] font-mono">{row.target ?? '—'}</div>
                              </div>
                              <div>
                                <div className="text-[#5a6a7a] mb-1">スキャン件数</div>
                                <div className="text-[#aab4be]">{row.scanned ?? 0} ファイル</div>
                              </div>
                              <div>
                                <div className="text-[#5a6a7a] mb-1">YARA一致</div>
                                <div className={detected ? 'text-red-300 font-bold' : 'text-[#aab4be]'}>
                                  {row.matched ?? 0} 件
                                </div>
                              </div>
                            </div>
                            {(row.matches ?? []).length > 0 ? (
                              <div className="space-y-1.5">
                                <div className="text-[11px] text-[#5a6a7a] uppercase tracking-wider">検知ファイル</div>
                                {(row.matches ?? []).map((m, i) => (
                                  <div key={i} className="flex items-center gap-3 px-3 py-2 bg-red-900/20 border border-red-700/30 rounded">
                                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                                    <div className="flex-1 min-w-0">
                                      <div className="text-[#e2e8f4] font-mono text-xs truncate" title={m.file}>{m.file}</div>
                                      <div className="text-[10px] text-purple-300 mt-0.5">YARAルール: {m.rule}</div>
                                      {m.sha256 && (
                                        <div className="text-[10px] text-[#5a6a7a] mt-0.5 font-mono" title={`SHA256: ${m.sha256}${m.size ? ` (${m.size.toLocaleString()} bytes)` : ''}`}>
                                          SHA256: {m.sha256.slice(0, 16)}…{m.size ? ` · ${m.size.toLocaleString()} B` : ''}
                                        </div>
                                      )}
                                    </div>
                                    {canWrite && (
                                      <button
                                        onClick={(e) => {
                                          e.stopPropagation()
                                          if (confirm(`このファイルを隔離しますか？\n\n${m.file}\n\n隔離後、ファイルは agent の quarantine ディレクトリに移動され、元のパスから削除されます。`)) {
                                            quarantineFile.mutate(m.file)
                                          }
                                        }}
                                        disabled={quarantineFile.isPending}
                                        className="flex items-center gap-1 px-2.5 py-1 text-xs bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded shrink-0 transition-colors"
                                        title="このファイルを隔離"
                                      >
                                        <ShieldAlert className="w-3 h-3" />
                                        隔離
                                      </button>
                                    )}
                                  </div>
                                ))}
                                <div className="text-[10px] text-[#5a6a7a] mt-2">
                                  ※ 検知ファイルは <Link href="/alerts" className="text-blue-400 hover:underline">アラート画面</Link> にも記録されています。
                                </div>
                              </div>
                            ) : row.status === 'pending' ? (
                              <div className="text-xs text-blue-400 flex items-center gap-2">
                                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                エージェントからの結果報告を待っています…
                              </div>
                            ) : (
                              <div className="text-xs text-green-400">マルウェアの兆候は検出されませんでした。</div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'live-response' && (
        <div className="space-y-4">
          {/* Full terminal session link */}
          <div className="bg-[#111827] rounded-xl border border-green-500/30 p-4 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-[#e2e8f4] mb-0.5">インタラクティブターミナル</h3>
              <p className="text-xs text-[#7d92b0]">リアルタイムシェルセッションを開きます</p>
            </div>
            <Link
              href={`/live-response/${id}`}
              className="flex items-center gap-1.5 px-4 py-2 text-sm bg-green-700 text-white rounded-lg hover:bg-green-600 transition-colors font-medium"
            >
              ターミナルを開く →
            </Link>
          </div>

          {/* Quick actions */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
            <h3 className="text-sm font-semibold text-[#8899aa] mb-3">クイックアクション</h3>
            <div className="flex flex-wrap gap-2">
              {canWrite && (
              <button
                onClick={() => scan.mutate()}
                disabled={scan.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-blue-300 bg-blue-900/30
                           border border-blue-700/50 rounded-lg hover:bg-blue-900/50 disabled:opacity-50 transition-colors"
              >
                <Scan className="w-4 h-4" />
                {scan.isPending ? 'スキャン送信中...' : 'フルスキャン'}
              </button>
              )}
              {canWrite && (
              <button
                onClick={() => scanCancel.mutate()}
                disabled={scanCancel.isPending}
                title="実行中のフルスキャンを停止します"
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-amber-300 bg-amber-900/30
                           border border-amber-700/50 rounded-lg hover:bg-amber-900/50 disabled:opacity-50 transition-colors"
              >
                <XCircle className="w-4 h-4" />
                {scanCancel.isPending ? '停止中...' : 'スキャン停止'}
              </button>
              )}
              {canWrite && (
              <button
                onClick={() => {
                  if (confirm(`${agent.hostname} を隔離しますか？`)) isolate.mutate()
                }}
                disabled={isolate.isPending || agent.status === 'isolated'}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-red-300 bg-red-900/30
                           border border-red-700/50 rounded-lg hover:bg-red-900/50 disabled:opacity-50 transition-colors"
              >
                <ShieldAlert className="w-4 h-4" />
                ネットワーク隔離
              </button>
              )}
              {canWrite && (
              <button
                onClick={() => {
                  const path = prompt('隔離するファイルのパスを入力してください:')
                  if (path?.trim()) executeQuarantine.mutate(path.trim())
                }}
                disabled={executeQuarantine.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-yellow-300 bg-yellow-900/30
                           border border-yellow-700/50 rounded-lg hover:bg-yellow-900/50 disabled:opacity-50 transition-colors"
              >
                ファイル隔離
              </button>
              )}
              {canWrite && agent.status === 'isolated' && (
                <button
                  onClick={() => unisolate.mutate()}
                  disabled={unisolate.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-green-300 bg-green-900/30
                             border border-green-700/50 rounded-lg hover:bg-green-900/50 disabled:opacity-50 transition-colors"
                >
                  <ShieldCheck className="w-4 h-4" />
                  隔離解除
                </button>
              )}
            </div>
          </div>

          {/* Command input */}
          {canWrite && (
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
            <h3 className="text-sm font-semibold text-[#8899aa] mb-2">コマンド実行</h3>
            <p className="text-xs text-[#5a6a7a] mb-3">
              利用可能コマンド: <code className="text-blue-300">scan</code>、
              <code className="text-blue-300">kill &lt;PID&gt;</code>、
              <code className="text-blue-300">quarantine &lt;ファイルパス&gt;</code>、
              <code className="text-blue-300">restore &lt;quarantine_id&gt; [復元先パス]</code>
            </p>
            <div className="flex gap-2">
              <span className="text-green-400 font-mono text-sm flex items-center">$</span>
              <input
                value={lrCommand}
                onChange={e => setLrCommand(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') handleLrCommand() }}
                placeholder="コマンドを入力..."
                className="flex-1 text-sm font-mono bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2
                           text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-none focus:border-green-500"
              />
              <button
                onClick={handleLrCommand}
                disabled={!lrCommand.trim()}
                className="px-3 py-2 text-sm bg-green-700 text-white rounded-lg
                           hover:bg-green-600 disabled:opacity-50 transition-colors"
              >
                実行
              </button>
            </div>

            {/* Output console */}
            <div className="mt-3 bg-[#080c14] rounded-lg border border-[#1e2d42] p-3 font-mono text-xs min-h-[120px] max-h-60 overflow-y-auto">
              {lrOutput.length === 0 ? (
                <span className="text-[#5a6a7a]">コマンドの実行ログがここに表示されます</span>
              ) : (
                lrOutput.map((line, i) => (
                  <div key={i} className={`${
                    line.includes('エラー') ? 'text-red-400' :
                    line.includes('送信') ? 'text-green-400' :
                    line.startsWith('[') && line.includes('>') ? 'text-yellow-300' :
                    'text-[#8899aa]'
                  }`}>
                    {line}
                  </div>
                ))
              )}
            </div>
          </div>
          )}
        </div>
      )}

      {/* Timeline tab */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          {/* Controls */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex gap-1">
              {[1, 4, 12, 24, 72].map(h => (
                <button
                  key={h}
                  onClick={() => setTimelineHours(h)}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                    timelineHours === h ? 'bg-[#1a6bff] text-white' : 'bg-[#161f33] text-[#8899aa] hover:bg-[#1d2f4a]'
                  }`}
                >
                  {h < 24 ? `${h}h` : `${h/24}d`}
                </button>
              ))}
            </div>
            <div className="flex gap-1 flex-wrap">
              {['alert','process','network','file','auth','dns'].map(t => {
                const active = timelineTypes.length === 0 || timelineTypes.includes(t)
                const COLORS: Record<string,string> = {
                  alert:'bg-red-900/50 text-red-300 border-red-700',
                  process:'bg-blue-900/50 text-blue-300 border-blue-700',
                  network:'bg-green-900/50 text-green-300 border-green-700',
                  file:'bg-yellow-900/50 text-yellow-300 border-yellow-700',
                  auth:'bg-indigo-900/50 text-indigo-300 border-indigo-700',
                  dns:'bg-purple-900/50 text-purple-300 border-purple-700',
                }
                return (
                  <button
                    key={t}
                    onClick={() => setTimelineTypes(prev =>
                      prev.length === 0
                        ? ['alert','process','network','file','auth','dns'].filter(x => x !== t)
                        : prev.includes(t) ? (prev.length === 1 ? [] : prev.filter(x => x !== t)) : [...prev, t]
                    )}
                    className={`px-2 py-0.5 rounded border text-xs transition-all ${
                      active ? (COLORS[t] ?? 'bg-[#161f33] text-[#8899aa] border-[#1e2d42]') : 'bg-[#111827] text-[#5a6a7a] border-[#1e2d42] opacity-50'
                    }`}
                  >
                    {t}
                  </button>
                )
              })}
            </div>
            {timelineFetching && <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500 ml-auto" />}
            <span className="text-xs text-[#5a6a7a] ml-auto">
              {timelineData?.total ?? 0}件のイベント
            </span>
          </div>

          {/* Timeline list */}
          <div className="relative">
            {/* Vertical line */}
            <div className="absolute left-[22px] top-0 bottom-0 w-px bg-[#1e2d42]" />

            <div className="space-y-1">
              {(timelineData?.items ?? []).length === 0 && !timelineFetching && (
                <div className="py-12 text-center text-[#5a6a7a] text-sm">
                  この期間のイベントはありません
                </div>
              )}
              {(timelineData?.items ?? []).map(item => {
                const CAT_STYLES: Record<string, { dot: string; badge: string; label: string }> = {
                  alert:   { dot: 'bg-red-500',    badge: 'bg-red-900/40 text-red-300 border-red-700/50',     label: 'ALERT' },
                  process: { dot: 'bg-blue-500',   badge: 'bg-blue-900/40 text-blue-300 border-blue-700/50',  label: 'PROC' },
                  network: { dot: 'bg-green-500',  badge: 'bg-green-900/40 text-green-300 border-green-700/50', label: 'NET' },
                  file:    { dot: 'bg-yellow-500', badge: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50', label: 'FILE' },
                  auth:    { dot: 'bg-indigo-500', badge: 'bg-indigo-900/40 text-indigo-300 border-indigo-700/50', label: 'AUTH' },
                  dns:     { dot: 'bg-purple-500', badge: 'bg-purple-900/40 text-purple-300 border-purple-700/50', label: 'DNS' },
                }
                const s = CAT_STYLES[item.category] ?? { dot: 'bg-[#5a6a7a]', badge: 'bg-[#161f33] text-[#8899aa] border-[#1e2d42]', label: item.category.toUpperCase() }
                const SEV_COLOR: Record<number,string> = { 4:'text-red-400', 3:'text-orange-400', 2:'text-yellow-400', 1:'text-blue-400' }
                return (
                  <div key={item.id} className="flex gap-3 pl-1 py-1.5 group hover:bg-[#111827]/40 rounded-lg pr-2">
                    {/* Dot */}
                    <div className="flex-shrink-0 mt-1.5">
                      <div className={`w-3.5 h-3.5 rounded-full ring-2 ring-[#080c14] ${s.dot}`} />
                    </div>
                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-mono font-semibold ${s.badge}`}>
                          {s.label}
                        </span>
                        <span className="text-sm text-[#e2e8f4] truncate flex-1">{item.title}</span>
                        {item.severity != null && item.severity > 0 && (
                          <span className={`text-xs font-mono ${SEV_COLOR[item.severity] ?? 'text-[#8899aa]'}`}>
                            Sev{item.severity}
                          </span>
                        )}
                        {item.status && (
                          <span className="text-xs text-[#5a6a7a]">{item.status}</span>
                        )}
                      </div>
                      {item.detail && (
                        <p className="text-xs text-[#5a6a7a] mt-0.5 truncate font-mono">{item.detail}</p>
                      )}
                    </div>
                    {/* Timestamp */}
                    <span className="text-xs text-[#5a6a7a] flex-shrink-0 mt-1 font-mono whitespace-nowrap">
                      {item.timestamp ? item.timestamp.slice(5, 19).replace('T', ' ') : ''}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

const EVENT_TYPE_STYLES: Record<string, string> = {
  process: 'bg-blue-900/40 text-blue-300 border-blue-700/50',
  file:    'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  network: 'bg-green-900/40 text-green-300 border-green-700/50',
  dns:     'bg-purple-900/40 text-purple-300 border-purple-700/50',
  registry:'bg-orange-900/40 text-orange-300 border-orange-700/50',
}

function EventTypeBadge({ type }: { type: string }) {
  const cls = EVENT_TYPE_STYLES[type] ?? 'bg-[#161f33] text-[#8899aa] border-[#1e2d42]'
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs border font-mono ${cls}`}>
      {type}
    </span>
  )
}

function summarizeEvent(type: string, raw: Record<string, unknown>): string {
  if (!raw) return '—'
  switch (type) {
    case 'process':
      return [raw.image, raw.cmdline].filter(Boolean).join(' ').slice(0, 120) || '—'
    case 'file':
      return [raw.operation, raw.path].filter(Boolean).join(' ') as string || '—'
    case 'network':
      return [raw.dst_ip, raw.dst_port ? `:${raw.dst_port}` : '', raw.protocol ? `(${raw.protocol})` : '']
        .filter(Boolean).join('') || '—'
    case 'dns':
      return (raw.query as string) || '—'
    case 'registry':
      return [raw.operation, raw.key].filter(Boolean).join(' ') as string || '—'
    default:
      return Object.entries(raw).slice(0, 2).map(([k, v]) => `${k}=${v}`).join(' ') || '—'
  }
}

function InfoCard({ icon: Icon, label, value }: {
  icon: React.ElementType
  label: string
  value: string
}) {
  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4 text-[#8899aa]" />
        <span className="text-[#8899aa] text-xs">{label}</span>
      </div>
      <p className="text-white text-sm font-medium truncate">{value}</p>
    </div>
  )
}
