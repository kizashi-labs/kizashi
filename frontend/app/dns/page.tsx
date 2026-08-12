'use client'

import React, { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Search, Globe, AlertTriangle, RefreshCw, Download,
  ScanSearch, ChevronDown, ChevronUp, ChevronRight,
  Shield, Activity, X, ExternalLink, Plus, Radio,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface DNSRecord {
  id: string
  timestamp: string
  query: string
  query_type: string
  answers: string[]
  pid: number
  process_name: string
  agent_id: string
  hostname: string
  is_suspicious: boolean
}

interface DNSResponse {
  records: DNSRecord[]
  total: number
}

type QueryTypeFilter = 'ALL' | 'A' | 'AAAA' | 'MX' | 'TXT' | 'CNAME' | 'NS'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function queryTypeBadgeColor(type: string) {
  const map: Record<string, string> = {
    A:     'bg-blue-900/40 text-blue-300 border-blue-700/50',
    AAAA:  'bg-violet-900/40 text-violet-300 border-violet-700/50',
    MX:    'bg-orange-900/40 text-orange-300 border-orange-700/50',
    TXT:   'bg-teal-900/40 text-teal-300 border-teal-700/50',
    CNAME: 'bg-cyan-900/40 text-cyan-300 border-cyan-700/50',
    NS:    'bg-pink-900/40 text-pink-300 border-pink-700/50',
  }
  return map[type] ?? 'bg-[#1e2d42] text-[#7d92b0] border-[#2a3f5a]'
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({
  label, value, icon: Icon, colorClass, subtext,
}: {
  label: string
  value: string
  icon: React.ElementType
  colorClass: string
  subtext?: string
}) {
  return (
    <div className="bg-[#0d1220] rounded-xl p-4 border border-[#1e2d42] flex items-center gap-4">
      <div className={`p-2.5 rounded-lg shrink-0 ${colorClass}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div className="min-w-0">
        <p className="text-2xl font-bold text-white leading-none">{value}</p>
        <p className="text-[#7d92b0] text-xs mt-1">{label}</p>
        {subtext && <p className="text-[#5a6a7a] text-xs mt-0.5">{subtext}</p>}
      </div>
    </div>
  )
}

// ─── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({
  record,
  onClose,
}: {
  record: DNSRecord
  onClose: () => void
}) {
  const queryClient = useQueryClient()

  const addIOC = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/ioc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'domain',
          value: record.query,
          source: 'dns-monitor',
          description: `DNS監視から検出: ${record.query_type} クエリ`,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ioc'] })
    },
  })

  const vtUrl = `https://www.virustotal.com/gui/domain/${encodeURIComponent(record.query)}`
  const whoisUrl = `https://www.whois.com/whois/${encodeURIComponent(record.query)}`

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
      {/* Panel header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-[#1e2d42] bg-[#0a0f1c]">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-[#7d92b0]" />
          <span className="text-white text-sm font-medium font-mono">{record.query}</span>
          {record.is_suspicious && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-900/40 border border-amber-700/50 text-amber-400 text-xs">
              <AlertTriangle className="w-3 h-3" />
              不審
            </span>
          )}
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded text-[#5a6a7a] hover:text-white hover:bg-[#1e2d42] transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-5 grid grid-cols-2 gap-6">
        {/* Left: query details */}
        <div className="space-y-4">
          <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-widest">
            クエリ詳細
          </h3>
          <dl className="space-y-2 text-sm">
            {[
              ['タイムスタンプ', fmtTime(record.timestamp)],
              ['ドメイン', record.query],
              ['クエリタイプ', record.query_type],
              ['プロセス', record.process_name || (record.pid ? `PID: ${record.pid}` : '—')],
              ['PID', record.pid ? String(record.pid) : '—'],
              ['エージェントID', record.agent_id],
              ['ホスト名', record.hostname || '—'],
            ].map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <dt className="w-32 shrink-0 text-[#7d92b0]">{k}</dt>
                <dd className="text-white font-mono break-all">{v}</dd>
              </div>
            ))}
          </dl>
        </div>

        {/* Right: DNS answers */}
        <div className="space-y-4">
          <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-widest">
            DNSアンサー ({record.answers?.length ?? 0})
          </h3>
          {record.answers && record.answers.length > 0 ? (
            <ul className="space-y-1">
              {record.answers.map((ans, i) => (
                <li
                  key={i}
                  className="px-3 py-1.5 bg-[#0a0f1c] border border-[#1e2d42] rounded text-xs font-mono text-[#7d92b0]"
                >
                  {ans}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[#5a6a7a] text-sm">応答なし</p>
          )}
        </div>
      </div>

      {/* Actions footer */}
      <div className="flex items-center gap-3 px-5 py-3 border-t border-[#1e2d42] bg-[#0a0f1c]">
        <a
          href={vtUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1e2d42] hover:bg-[#263a56]
                     text-[#7d92b0] hover:text-white text-xs transition-colors"
        >
          <ScanSearch className="w-3.5 h-3.5" />
          VirusTotal
          <ExternalLink className="w-3 h-3 opacity-60" />
        </a>
        <a
          href={whoisUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1e2d42] hover:bg-[#263a56]
                     text-[#7d92b0] hover:text-white text-xs transition-colors"
        >
          <Globe className="w-3.5 h-3.5" />
          WHOIS
          <ExternalLink className="w-3 h-3 opacity-60" />
        </a>
        <div className="flex-1" />
        <button
          onClick={() => addIOC.mutate()}
          disabled={addIOC.isPending || addIOC.isSuccess}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs transition-colors
                     disabled:opacity-50 bg-[#e8002d]/20 hover:bg-[#e8002d]/30 text-[#e8002d]
                     border border-[#e8002d]/30 hover:border-[#e8002d]/60"
        >
          <Plus className="w-3.5 h-3.5" />
          {addIOC.isSuccess ? 'IOCに追加済み' : addIOC.isPending ? '追加中…' : 'IOCに追加'}
        </button>
      </div>
    </div>
  )
}

// ─── Tunneling Detection Panel ────────────────────────────────────────────────

interface TunnelingAgent {
  agentId: string
  hostname: string
  queryCount: number
  uniqueDomains: number
}

function TunnelingPanel({ records }: { records: DNSRecord[] }) {
  const [open, setOpen] = useState(false)

  const suspects: TunnelingAgent[] = useMemo(() => {
    const byAgent = new Map<string, { hostname: string; queries: string[] }>()
    for (const r of records) {
      if (!byAgent.has(r.agent_id)) {
        byAgent.set(r.agent_id, { hostname: r.hostname || r.agent_id.slice(0, 8), queries: [] })
      }
      byAgent.get(r.agent_id)!.queries.push(r.query)
    }
    const results: TunnelingAgent[] = []
    byAgent.forEach(({ hostname, queries }, agentId) => {
      const uniqueDomains = new Set(queries).size
      // Flag agents with >= 20 queries or unusually high unique TXT/long-subdomain domains
      if (queries.length >= 20 || uniqueDomains >= 15) {
        results.push({ agentId, hostname, queryCount: queries.length, uniqueDomains })
      }
    })
    return results.sort((a, b) => b.queryCount - a.queryCount)
  }, [records])

  return (
    <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-[#0a0f1c] transition-colors"
      >
        <div className="flex items-center gap-3">
          <Radio className="w-4 h-4 text-[#7d92b0]" />
          <span className="text-sm font-medium text-white">DNSトンネリング検出</span>
          {suspects.length > 0 && (
            <span className="px-2 py-0.5 rounded-full bg-[#e8002d]/20 border border-[#e8002d]/40 text-[#e8002d] text-xs font-bold">
              {suspects.length} 件の警告
            </span>
          )}
          {suspects.length === 0 && (
            <span className="px-2 py-0.5 rounded-full bg-green-900/30 border border-green-700/40 text-green-400 text-xs">
              異常なし
            </span>
          )}
        </div>
        {open ? (
          <ChevronUp className="w-4 h-4 text-[#7d92b0]" />
        ) : (
          <ChevronDown className="w-4 h-4 text-[#7d92b0]" />
        )}
      </button>

      {open && (
        <div className="border-t border-[#1e2d42] px-5 py-4">
          {suspects.length === 0 ? (
            <p className="text-[#5a6a7a] text-sm text-center py-4">
              現在の表示範囲でDNSトンネリングの疑いがあるエージェントはありません
            </p>
          ) : (
            <div className="space-y-2">
              <p className="text-[#7d92b0] text-xs mb-3">
                以下のエージェントは異常に高いDNSクエリレートを示しています
              </p>
              <div className="grid grid-cols-4 gap-2 text-xs text-[#5a6a7a] px-3 pb-1">
                <span>ホスト名</span>
                <span>エージェントID</span>
                <span className="text-right">クエリ数</span>
                <span className="text-right">ユニークドメイン</span>
              </div>
              {suspects.map(s => (
                <div
                  key={s.agentId}
                  className="grid grid-cols-4 gap-2 items-center px-3 py-2.5 rounded-lg
                             bg-[#e8002d]/5 border border-[#e8002d]/20 text-sm"
                >
                  <span className="text-white font-medium">{s.hostname}</span>
                  <span className="text-[#7d92b0] font-mono text-xs">{s.agentId.slice(0, 12)}…</span>
                  <span className="text-right text-[#e8002d] font-bold">{s.queryCount}</span>
                  <span className="text-right text-amber-400">{s.uniqueDomains}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DNSMonitoringPage() {
  const [search, setSearch] = useState('')
  const [queryTypeFilter, setQueryTypeFilter] = useState<QueryTypeFilter>('ALL')
  const [suspiciousOnly, setSuspiciousOnly] = useState(false)
  const [agentFilter, setAgentFilter] = useState('')
  const [page, setPage] = useState(1)
  const [selectedRecord, setSelectedRecord] = useState<DNSRecord | null>(null)
  const pageSize = 50

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['dns', search, suspiciousOnly, queryTypeFilter, agentFilter, page],
    queryFn: () => {
      const params = new URLSearchParams({
        limit: String(pageSize),
        offset: String((page - 1) * pageSize),
      })
      if (search) params.set('q', search)
      if (suspiciousOnly) params.set('suspicious', 'true')
      if (queryTypeFilter !== 'ALL') params.set('query_type', queryTypeFilter)
      if (agentFilter) params.set('agent_id', agentFilter)
      return apiFetch<DNSResponse>(`/api/v1/events/dns?${params}`)
    },
    refetchInterval: 10000,
  })

  const records = data?.records ?? []
  const total = data?.total ?? 0

  // Derived stats from current page data
  const suspiciousCount = records.filter(r => r.is_suspicious).length
  const uniqueDomains = new Set(records.map(r => r.query)).size
  const blockedCount = records.filter(r =>
    r.is_suspicious && (!r.answers || r.answers.length === 0)
  ).length

  // Unique agents list for filter dropdown
  const agentOptions = useMemo(() => {
    const seen = new Map<string, string>()
    records.forEach(r => {
      if (!seen.has(r.agent_id)) seen.set(r.agent_id, r.hostname || r.agent_id.slice(0, 8))
    })
    return Array.from(seen.entries())
  }, [records])

  // Server-side CSV export
  function exportCSV() {
    const params = new URLSearchParams({ format: 'csv' })
    if (search) params.set('q', search)
    if (suspiciousOnly) params.set('suspicious', 'true')
    if (queryTypeFilter !== 'ALL') params.set('query_type', queryTypeFilter)
    if (agentFilter) params.set('agent_id', agentFilter)
    window.open(`/api/v1/events/dns?${params}`, '_blank')
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-5">

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">DNS モニタリング</h1>
          <p className="text-[#7d92b0] text-sm mt-1">
            エンドポイントのDNSクエリをリアルタイムで監視します
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#0d1220] hover:bg-[#1e2d42]
                       border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm
                       rounded-lg transition-colors"
          >
            <Download className="w-4 h-4" />
            CSVエクスポート
          </button>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 px-4 py-2 bg-[#0d1220] hover:bg-[#1e2d42]
                       border border-[#1e2d42] text-white text-sm rounded-lg
                       transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* ── Stats bar ── */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="総クエリ数"
          value={total.toLocaleString()}
          icon={Globe}
          colorClass="bg-blue-900/30 text-blue-400"
          subtext="全期間"
        />
        <StatCard
          label="不審なクエリ"
          value={suspiciousCount.toLocaleString()}
          icon={AlertTriangle}
          colorClass="bg-amber-900/30 text-amber-400"
          subtext={total > 0 ? `${((suspiciousCount / records.length) * 100).toFixed(1)}%` : undefined}
        />
        <StatCard
          label="ユニークドメイン"
          value={uniqueDomains.toLocaleString()}
          icon={Activity}
          colorClass="bg-emerald-900/30 text-emerald-400"
          subtext="現在のページ"
        />
        <StatCard
          label="ブロック済み"
          value={blockedCount.toLocaleString()}
          icon={Shield}
          colorClass="bg-[#e8002d]/20 text-[#e8002d]"
          subtext="応答なし"
        />
      </div>

      {/* ── Filter bar ── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 flex flex-wrap gap-3 items-center">
        {/* Search */}
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
          <input
            type="text"
            placeholder="ドメイン名で検索…"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            className="w-full pl-9 pr-4 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg
                       text-white text-sm placeholder-[#5a6a7a] focus:outline-none
                       focus:border-[#e8002d]/60 transition-colors"
          />
        </div>

        {/* Query type filter */}
        <div className="flex rounded-lg overflow-hidden border border-[#1e2d42]">
          {(['ALL', 'A', 'AAAA', 'MX', 'TXT'] as QueryTypeFilter[]).map(t => (
            <button
              key={t}
              onClick={() => { setQueryTypeFilter(t); setPage(1) }}
              className={`px-3 py-2 text-xs font-mono transition-colors ${
                queryTypeFilter === t
                  ? 'bg-[#e8002d] text-white'
                  : 'bg-[#070d19] text-[#7d92b0] hover:bg-[#1e2d42] hover:text-white'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Suspicious toggle */}
        <button
          onClick={() => { setSuspiciousOnly(v => !v); setPage(1) }}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm border transition-colors ${
            suspiciousOnly
              ? 'bg-amber-900/30 border-amber-700/60 text-amber-400'
              : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-amber-700/40 hover:text-amber-400'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          不審のみ
        </button>

        {/* Agent filter */}
        {agentOptions.length > 0 && (
          <select
            value={agentFilter}
            onChange={e => { setAgentFilter(e.target.value); setPage(1) }}
            className="px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg
                       text-sm text-[#7d92b0] focus:outline-none focus:border-[#e8002d]/60
                       transition-colors"
          >
            <option value="">すべてのエージェント</option>
            {agentOptions.map(([id, name]) => (
              <option key={id} value={id}>{name}</option>
            ))}
          </select>
        )}

        {/* Active filter count badge */}
        {(search || suspiciousOnly || queryTypeFilter !== 'ALL' || agentFilter) && (
          <button
            onClick={() => {
              setSearch(''); setSuspiciousOnly(false)
              setQueryTypeFilter('ALL'); setAgentFilter(''); setPage(1)
            }}
            className="flex items-center gap-1 px-2 py-1.5 rounded text-xs text-[#e8002d]
                       hover:bg-[#e8002d]/10 border border-[#e8002d]/30 transition-colors"
          >
            <X className="w-3 h-3" />
            フィルターをクリア
          </button>
        )}
      </div>

      {/* ── Detail panel (selected row) ── */}
      {selectedRecord && (
        <DetailPanel record={selectedRecord} onClose={() => setSelectedRecord(null)} />
      )}

      {/* ── Table ── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-[#e8002d]" />
            <p className="text-[#7d92b0] text-sm">読み込み中…</p>
          </div>
        ) : records.length === 0 ? (
          <div className="text-center py-20 text-[#5a6a7a]">
            <Globe className="w-12 h-12 mx-auto mb-3 opacity-20" />
            <p className="text-base">DNSクエリが見つかりません</p>
            <p className="text-xs mt-1 text-[#3a4a5a]">フィルター条件を変更してください</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[#7d92b0] border-b border-[#1e2d42] bg-[#0a0f1c]">
                <th className="px-4 py-3 font-medium">タイムスタンプ</th>
                <th className="px-4 py-3 font-medium">ドメイン</th>
                <th className="px-4 py-3 font-medium">クエリタイプ</th>
                <th className="px-4 py-3 font-medium">応答</th>
                <th className="px-4 py-3 font-medium">プロセス</th>
                <th className="px-4 py-3 font-medium">エージェント</th>
                <th className="px-4 py-3 font-medium">不審フラグ</th>
                <th className="px-4 py-3 font-medium w-8" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {records.map(record => {
                const isSelected = selectedRecord?.id === record.id
                return (
                  <tr
                    key={record.id}
                    onClick={() => setSelectedRecord(isSelected ? null : record)}
                    className={`
                      transition-colors cursor-pointer group
                      ${record.is_suspicious
                        ? 'border-l-2 border-l-amber-500/70 hover:bg-amber-900/10 bg-amber-900/5'
                        : 'border-l-2 border-l-transparent hover:bg-[#1a2640]'
                      }
                      ${isSelected ? 'bg-[#1a2640] ring-1 ring-inset ring-[#e8002d]/30' : ''}
                    `}
                  >
                    {/* Timestamp */}
                    <td className="px-4 py-3 text-[#7d92b0] whitespace-nowrap font-mono text-xs">
                      {fmtTime(record.timestamp)}
                    </td>

                    {/* Domain */}
                    <td className="px-4 py-3 max-w-xs">
                      <span className="text-white font-mono text-xs truncate block" title={record.query}>
                        {record.query}
                      </span>
                    </td>

                    {/* Query type */}
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded border text-xs font-mono font-medium ${queryTypeBadgeColor(record.query_type)}`}>
                        {record.query_type}
                      </span>
                    </td>

                    {/* Answers */}
                    <td className="px-4 py-3 max-w-[180px]">
                      {record.answers && record.answers.length > 0 ? (
                        <span className="text-[#7d92b0] font-mono text-xs truncate block" title={record.answers.join(', ')}>
                          {record.answers[0]}
                          {record.answers.length > 1 && (
                            <span className="text-[#5a6a7a]"> +{record.answers.length - 1}</span>
                          )}
                        </span>
                      ) : (
                        <span className="text-[#3a4a5a] text-xs">—</span>
                      )}
                    </td>

                    {/* Process */}
                    <td className="px-4 py-3 text-[#7d92b0] text-xs">
                      {record.process_name || (record.pid ? `PID:${record.pid}` : '—')}
                    </td>

                    {/* Agent */}
                    <td className="px-4 py-3">
                      <div>
                        <p className="text-white text-xs">{record.hostname || '—'}</p>
                        <p className="text-[#5a6a7a] font-mono text-xs">{record.agent_id.slice(0, 8)}</p>
                      </div>
                    </td>

                    {/* Suspicious flag */}
                    <td className="px-4 py-3">
                      {record.is_suspicious ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full
                                         bg-amber-900/40 border border-amber-700/50 text-amber-400 text-xs">
                          <AlertTriangle className="w-3 h-3" />
                          不審
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full
                                         bg-emerald-900/30 border border-emerald-700/40 text-emerald-400 text-xs">
                          <Shield className="w-3 h-3" />
                          正常
                        </span>
                      )}
                    </td>

                    {/* Expand indicator */}
                    <td className="px-3 py-3 text-[#5a6a7a] group-hover:text-[#7d92b0] transition-colors">
                      <ChevronRight className={`w-4 h-4 transition-transform ${isSelected ? 'rotate-90 text-[#e8002d]' : ''}`} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Pagination ── */}
      {total > pageSize && (
        <div className="flex items-center justify-between text-sm text-[#7d92b0]">
          <span>
            全 {total.toLocaleString()} 件中{' '}
            {((page - 1) * pageSize + 1).toLocaleString()}–
            {Math.min(page * pageSize, total).toLocaleString()} 件を表示
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(1)}
              disabled={page === 1}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-lg
                         disabled:opacity-30 hover:bg-[#1e2d42] transition-colors text-xs"
            >
              最初
            </button>
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-lg
                         disabled:opacity-30 hover:bg-[#1e2d42] transition-colors"
            >
              前へ
            </button>
            <span className="px-3 py-1.5 text-white text-xs">
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={page >= totalPages}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-lg
                         disabled:opacity-30 hover:bg-[#1e2d42] transition-colors"
            >
              次へ
            </button>
            <button
              onClick={() => setPage(totalPages)}
              disabled={page >= totalPages}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-lg
                         disabled:opacity-30 hover:bg-[#1e2d42] transition-colors text-xs"
            >
              最後
            </button>
          </div>
        </div>
      )}

      {/* ── DNS Tunneling detection ── */}
      <TunnelingPanel records={records} />

    </div>
  )
}
