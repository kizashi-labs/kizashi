'use client'

import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import { formatDistanceToNow, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import {
  ArrowLeft, Search, ArrowLeftRight, Copy, Check,
  Monitor, ShieldAlert, Activity, Package, Settings
} from 'lucide-react'
import type { Agent, PaginatedResponse, Alert } from '@/types/api'

// ── Types ──────────────────────────────────────────────────────────────────

interface AgentDetail extends Agent {
  alert_count?: number
  open_alert_count?: number
  risk_score?: number
  last_alert_at?: string
  installed_software_count?: number
  outdated_packages?: number
  policy_name?: string
  collection_interval?: number
  monitoring_flags?: string[]
}

// ── Helpers ────────────────────────────────────────────────────────────────

function relativeTime(iso: string | undefined) {
  if (!iso) return '—'
  try {
    return formatDistanceToNow(parseISO(iso), { addSuffix: true, locale: ja })
  } catch {
    return iso
  }
}

// ── Agent Search Input ─────────────────────────────────────────────────────

function AgentSearchInput({
  label,
  selected,
  onSelect,
}: {
  label: string
  selected: AgentDetail | null
  onSelect: (agent: AgentDetail) => void
}) {
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  const { data } = useQuery<PaginatedResponse<Agent>>({
    queryKey: ['agents-search', q],
    queryFn: () => apiFetch<PaginatedResponse<Agent>>(`/api/v1/agents?search=${encodeURIComponent(q)}&per_page=10`),
    enabled: q.length >= 1,
  })

  const results = data?.data ?? []

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  return (
    <div ref={ref} className="relative">
      <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">{label}</label>
      {selected ? (
        <div className="flex items-center gap-2 px-3 py-2 bg-[#0d1220] border border-[#e8002d]/50 rounded-lg">
          <Monitor className="w-4 h-4 text-[#e8002d] flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-white truncate">{selected.hostname}</p>
            <p className="text-xs text-[#7d92b0]">{selected.os_type} · {(selected.ip_addresses ?? [])[0] ?? '—'}</p>
          </div>
          <button
            onClick={() => { setQ(''); setOpen(false); onSelect(null as unknown as AgentDetail) }}
            className="text-[#7d92b0] hover:text-white transition-colors text-lg leading-none"
          >
            ×
          </button>
        </div>
      ) : (
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
          <input
            value={q}
            onChange={e => { setQ(e.target.value); setOpen(true) }}
            onFocus={() => setOpen(true)}
            placeholder="ホスト名で検索..."
            className="w-full pl-9 pr-4 py-2 text-sm border border-[#1e2d42] rounded-lg
                       bg-[#0d1220] text-white placeholder-[#3d5068]
                       focus:outline-none focus:border-[#e8002d]"
          />
          {open && results.length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-1 z-20 bg-[#0d1220] border border-[#1e2d42]
                            rounded-lg shadow-xl overflow-hidden max-h-48 overflow-y-auto">
              {results.map(agent => (
                <button
                  key={agent.id}
                  onClick={() => { onSelect(agent as AgentDetail); setQ(''); setOpen(false) }}
                  className="w-full flex items-center gap-2.5 px-3 py-2.5 hover:bg-[#1e2d42] transition-colors text-left"
                >
                  <Monitor className="w-4 h-4 text-[#3d5068] flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-sm text-white truncate">{agent.hostname}</p>
                    <p className="text-xs text-[#7d92b0]">{agent.os_type} · {agent.status}</p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Comparison Cell ────────────────────────────────────────────────────────

function CompareCell({
  value,
  otherValue,
  render,
}: {
  value: unknown
  otherValue: unknown
  render?: (v: unknown) => React.ReactNode
}) {
  const differs = value !== otherValue && value !== undefined && otherValue !== undefined
  return (
    <td
      className={`px-4 py-3 text-sm ${
        differs ? 'bg-amber-900/20 text-amber-200' : 'text-white'
      }`}
    >
      {render ? render(value) : (value !== undefined && value !== null && String(value) !== '' ? String(value) : '—')}
    </td>
  )
}

// ── Alert row ─────────────────────────────────────────────────────────────

function AlertRow({ alert }: { alert: Alert }) {
  const sevColor =
    alert.severity >= 9 ? 'text-red-400' :
    alert.severity >= 7 ? 'text-orange-400' :
    alert.severity >= 5 ? 'text-amber-400' :
    'text-blue-400'

  return (
    <Link
      href={`/alerts/${alert.id}`}
      className="flex items-center gap-2 py-1.5 px-2 hover:bg-[#1e2d42]/50 rounded transition-colors"
    >
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
        alert.severity >= 9 ? 'bg-red-400' : alert.severity >= 7 ? 'bg-orange-400' : alert.severity >= 5 ? 'bg-amber-400' : 'bg-blue-400'
      }`} />
      <span className="text-xs text-[#7d92b0] flex-1 truncate">{alert.title}</span>
      <span className={`text-xs font-bold ${sevColor}`}>{alert.severity}</span>
    </Link>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function EndpointComparePage() {
  const [agentA, setAgentA] = useState<AgentDetail | null>(null)
  const [agentB, setAgentB] = useState<AgentDetail | null>(null)
  const [copied, setCopied] = useState(false)

  // Fetch full detail for A
  const { data: detailA } = useQuery<AgentDetail>({
    queryKey: ['agent-detail', agentA?.id],
    queryFn: () => apiFetch<AgentDetail>(`/api/v1/agents/${agentA!.id}`),
    enabled: !!agentA?.id,
  })

  // Fetch full detail for B
  const { data: detailB } = useQuery<AgentDetail>({
    queryKey: ['agent-detail', agentB?.id],
    queryFn: () => apiFetch<AgentDetail>(`/api/v1/agents/${agentB!.id}`),
    enabled: !!agentB?.id,
  })

  // Alerts for A
  const { data: alertsA } = useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts-compare', agentA?.id],
    queryFn: () => apiFetch<PaginatedResponse<Alert>>(`/api/v1/alerts?agent_id=${agentA!.id}&limit=5`),
    enabled: !!agentA?.id,
  })

  // Alerts for B
  const { data: alertsB } = useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts-compare', agentB?.id],
    queryFn: () => apiFetch<PaginatedResponse<Alert>>(`/api/v1/alerts?agent_id=${agentB!.id}&limit=5`),
    enabled: !!agentB?.id,
  })

  const effA = detailA ?? agentA
  const effB = detailB ?? agentB

  function swapAgents() {
    setAgentA(agentB)
    setAgentB(agentA)
  }

  function copyComparison() {
    if (!effA || !effB) return
    const lines = [
      `エンドポイント比較 — ${new Date().toLocaleString('ja-JP')}`,
      '',
      `項目 | ${effA.hostname} | ${effB.hostname}`,
      `---`,
      `OS | ${effA.os_type} ${effA.os_version} | ${effB.os_type} ${effB.os_version}`,
      `ステータス | ${effA.status} | ${effB.status}`,
      `IP | ${(effA.ip_addresses ?? [])[0] ?? '—'} | ${(effB.ip_addresses ?? [])[0] ?? '—'}`,
      `エージェントバージョン | ${effA.agent_version} | ${effB.agent_version}`,
      `最終確認 | ${effA.last_seen ?? '—'} | ${effB.last_seen ?? '—'}`,
    ]
    navigator.clipboard.writeText(lines.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const rows: {
    section: string
    icon: React.ReactNode
    fields: { label: string; keyA: keyof AgentDetail; keyB?: keyof AgentDetail; render?: (v: unknown) => React.ReactNode }[]
  }[] = [
    {
      section: '基本情報',
      icon: <Monitor className="w-4 h-4 text-[#e8002d]" />,
      fields: [
        { label: 'ホスト名', keyA: 'hostname' },
        { label: 'OS種別', keyA: 'os_type' },
        { label: 'OSバージョン', keyA: 'os_version' },
        { label: 'エージェントバージョン', keyA: 'agent_version' },
        {
          label: 'IPアドレス',
          keyA: 'ip_addresses',
          render: (v: unknown) => Array.isArray(v) ? (v[0] as string) ?? '—' : '—',
        },
        {
          label: 'ステータス',
          keyA: 'status',
          render: (v: unknown) => {
            const s = String(v)
            const cls =
              s === 'online' ? 'text-green-400' :
              s === 'offline' ? 'text-[#7d92b0]' :
              s === 'isolated' ? 'text-red-400' : 'text-orange-400'
            return <span className={`font-medium ${cls}`}>{s}</span>
          },
        },
        {
          label: '最終確認',
          keyA: 'last_seen',
          render: (v: unknown) => typeof v === 'string' ? relativeTime(v) : '—',
        },
      ],
    },
    {
      section: 'セキュリティ状態',
      icon: <ShieldAlert className="w-4 h-4 text-[#e8002d]" />,
      fields: [
        { label: 'アラート総数', keyA: 'alert_count' },
        { label: '未対応アラート', keyA: 'open_alert_count' },
        { label: 'リスクスコア', keyA: 'risk_score' },
        {
          label: '最終アラート',
          keyA: 'last_alert_at',
          render: (v: unknown) => typeof v === 'string' ? relativeTime(v) : '—',
        },
      ],
    },
    {
      section: 'ソフトウェア',
      icon: <Package className="w-4 h-4 text-[#e8002d]" />,
      fields: [
        { label: 'インストール済みソフトウェア', keyA: 'installed_software_count' },
        { label: '期限切れパッケージ', keyA: 'outdated_packages' },
      ],
    },
    {
      section: 'エージェント設定',
      icon: <Settings className="w-4 h-4 text-[#e8002d]" />,
      fields: [
        { label: 'ポリシー名', keyA: 'policy_id' },
        { label: 'グループ', keyA: 'group_id' },
        {
          label: 'CPU',
          keyA: 'cpu_model',
        },
        {
          label: 'メモリ (MB)',
          keyA: 'total_memory_mb',
        },
        {
          label: '登録日時',
          keyA: 'enrolled_at',
          render: (v: unknown) => typeof v === 'string' ? new Date(v).toLocaleDateString('ja-JP') : '—',
        },
      ],
    },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <ArrowLeftRight className="w-6 h-6 text-[#e8002d]" />
          <div>
            <h1 className="text-2xl font-bold text-white">エンドポイント比較</h1>
            <p className="text-sm text-[#7d92b0]">2つのエンドポイントを並べて比較</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {effA && effB && (
            <button
              onClick={copyComparison}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#7d92b0]
                         bg-[#0d1220] border border-[#1e2d42] rounded-lg hover:bg-[#1e2d42] transition-colors"
            >
              {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
              {copied ? 'コピー済み' : 'テキストでコピー'}
            </button>
          )}
          <Link
            href="/endpoints"
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#7d92b0]
                       bg-[#0d1220] border border-[#1e2d42] rounded-lg hover:bg-[#1e2d42] transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            エンドポイントへ戻る
          </Link>
        </div>
      </div>

      {/* Endpoint selectors */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 mb-6">
        <div className="grid grid-cols-[1fr_auto_1fr] gap-4 items-end">
          <AgentSearchInput label="エンドポイント A" selected={agentA} onSelect={setAgentA} />
          <button
            onClick={swapAgents}
            disabled={!agentA && !agentB}
            title="A と B を入れ替え"
            className="flex items-center justify-center w-10 h-10 rounded-lg border border-[#1e2d42]
                       bg-[#070d19] text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]
                       transition-colors disabled:opacity-40 disabled:cursor-not-allowed mb-0.5"
          >
            <ArrowLeftRight className="w-4 h-4" />
          </button>
          <AgentSearchInput label="エンドポイント B" selected={agentB} onSelect={setAgentB} />
        </div>
      </div>

      {/* Comparison grid */}
      {(!effA || !effB) ? (
        <div className="text-center py-20 bg-[#0d1220] border border-[#1e2d42] rounded-xl">
          <ArrowLeftRight className="w-10 h-10 text-[#3d5068] mx-auto mb-3" />
          <p className="text-[#7d92b0]">比較するエンドポイントを2つ選択してください</p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Amber diff legend */}
          <div className="flex items-center gap-2 text-xs text-amber-300">
            <div className="w-3 h-3 rounded bg-amber-900/40 border border-amber-700/50" />
            差分ハイライト — 値が異なる行を強調表示
          </div>

          {rows.map(section => (
            <div key={section.section} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              {/* Section header */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1e2d42] bg-[#070d19]/60">
                {section.icon}
                <span className="text-sm font-semibold text-white">{section.section}</span>
              </div>

              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]/60">
                    <th className="text-left px-4 py-2.5 text-xs text-[#7d92b0] font-medium w-1/3">項目</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-white">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-[#e8002d]" />
                        {effA.hostname}
                      </div>
                    </th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-white">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-blue-500" />
                        {effB.hostname}
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {section.fields.map(field => {
                    const valA = effA[field.keyA]
                    const valB = effB[field.keyA]
                    // Normalize for diff comparison
                    const normA = Array.isArray(valA) ? (valA as unknown[])[0] : valA
                    const normB = Array.isArray(valB) ? (valB as unknown[])[0] : valB
                    return (
                      <tr key={field.label} className="border-b border-[#1e2d42]/40 last:border-0">
                        <td className="px-4 py-3 text-xs text-[#7d92b0]">{field.label}</td>
                        <CompareCell value={valA} otherValue={valB} render={field.render} />
                        <CompareCell value={valB} otherValue={valA} render={field.render} />
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ))}

          {/* Recent alerts section */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-[#1e2d42] bg-[#070d19]/60">
              <Activity className="w-4 h-4 text-[#e8002d]" />
              <span className="text-sm font-semibold text-white">最近のアラート (直近5件)</span>
            </div>
            <div className="grid grid-cols-2 divide-x divide-[#1e2d42]">
              {/* A alerts */}
              <div className="p-3">
                <p className="text-xs text-[#7d92b0] font-medium mb-2 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#e8002d]" />
                  {effA.hostname}
                </p>
                {(alertsA?.data ?? []).length === 0 ? (
                  <p className="text-xs text-[#3d5068] px-2 py-1">アラートなし</p>
                ) : (
                  (alertsA?.data ?? []).map(a => <AlertRow key={a.id} alert={a} />)
                )}
              </div>
              {/* B alerts */}
              <div className="p-3">
                <p className="text-xs text-[#7d92b0] font-medium mb-2 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-blue-500" />
                  {effB.hostname}
                </p>
                {(alertsB?.data ?? []).length === 0 ? (
                  <p className="text-xs text-[#3d5068] px-2 py-1">アラートなし</p>
                ) : (
                  (alertsB?.data ?? []).map(a => <AlertRow key={a.id} alert={a} />)
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
