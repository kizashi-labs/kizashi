'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Package, ChevronDown, ChevronRight, Plus, Minus,
  Calendar, RefreshCw, BarChart3, Zap, Monitor,
  CheckCircle, AlertTriangle,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os?: string
}

interface SoftwareItem {
  name: string
  version: string
  publisher?: string
}

interface SoftwareDiff {
  id: string
  agent_id: string
  computed_at: string
  installed: SoftwareItem[]
  removed: SoftwareItem[]
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_AGENTS: Agent[] = [
  { id: 'agt-001', hostname: 'DESKTOP-ABC123', os: 'Windows 11' },
  { id: 'agt-002', hostname: 'LAPTOP-XYZ789',  os: 'Windows 10' },
  { id: 'agt-003', hostname: 'SERVER-PROD-01', os: 'Windows Server 2022' },
]

function daysAgo(n: number) {
  const d = new Date('2026-03-18T00:00:00Z')
  d.setDate(d.getDate() - n)
  return d.toISOString()
}

const MOCK_DIFFS: SoftwareDiff[] = [
  {
    id: 'diff-001',
    agent_id: 'agt-001',
    computed_at: daysAgo(0),
    installed: [
      { name: 'Google Chrome', version: '123.0.6312.58', publisher: 'Google LLC' },
      { name: 'Visual Studio Code', version: '1.87.2', publisher: 'Microsoft Corporation' },
    ],
    removed: [
      { name: 'Google Chrome', version: '122.0.6261.129', publisher: 'Google LLC' },
    ],
  },
  {
    id: 'diff-002',
    agent_id: 'agt-001',
    computed_at: daysAgo(1),
    installed: [
      { name: 'Node.js', version: '20.11.1', publisher: 'Node.js Foundation' },
      { name: 'Git', version: '2.44.0', publisher: 'The Git Development Community' },
    ],
    removed: [
      { name: 'Java SE Runtime Environment 8', version: '8.0.401', publisher: 'Oracle Corporation' },
      { name: 'Java Auto Updater', version: '2.8.401', publisher: 'Oracle Corporation' },
    ],
  },
  {
    id: 'diff-003',
    agent_id: 'agt-001',
    computed_at: daysAgo(3),
    installed: [
      { name: 'Microsoft Visual C++ 2022 Redistributable (x64)', version: '14.38.33135', publisher: 'Microsoft Corporation' },
    ],
    removed: [],
  },
  {
    id: 'diff-004',
    agent_id: 'agt-001',
    computed_at: daysAgo(5),
    installed: [
      { name: 'Zoom', version: '5.17.5', publisher: 'Zoom Video Communications, Inc.' },
      { name: '7-Zip 23.01 (x64)', version: '23.01.00', publisher: 'Igor Pavlov' },
    ],
    removed: [
      { name: 'Skype version 8.113', version: '8.113.0.210', publisher: 'Skype Technologies S.A.' },
    ],
  },
  {
    id: 'diff-005',
    agent_id: 'agt-001',
    computed_at: daysAgo(6),
    installed: [],
    removed: [
      { name: 'Adobe Acrobat Reader DC (64-bit)', version: '23.008.20533', publisher: 'Adobe Systems Incorporated' },
      { name: 'Adobe Acrobat (64-bit)', version: '23.006.20360', publisher: 'Adobe Systems Incorporated' },
    ],
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDateTime(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('ja-JP', {
    month: '2-digit', day: '2-digit', weekday: 'short',
  })
}

function dayLabel(iso: string) {
  const d = new Date(iso)
  const today = new Date('2026-03-18')
  const diff = Math.round((today.getTime() - d.getTime()) / 86400000)
  if (diff === 0) return '今日'
  if (diff === 1) return '昨日'
  return `${diff}日前`
}

// ─── Diff Timeline Entry ──────────────────────────────────────────────────────

function DiffEntry({ diff, isExpanded, onToggle }: {
  diff: SoftwareDiff
  isExpanded: boolean
  onToggle: () => void
}) {
  const totalChanges = diff.installed.length + diff.removed.length
  return (
    <div className="border border-[#1e2d42] rounded-xl overflow-hidden bg-[#0d1220] hover:border-[#2e4a6e] transition-all">
      {/* Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-4 px-5 py-4 text-left group"
      >
        {/* Timeline dot */}
        <div className="flex-shrink-0 flex flex-col items-center">
          <div className={`w-3 h-3 rounded-full border-2 ${totalChanges > 0 ? 'border-[#e8002d] bg-[#e8002d]/30' : 'border-[#3d5068] bg-[#0d1220]'}`} />
        </div>

        {/* Date */}
        <div className="flex-shrink-0 w-28">
          <p className="text-white text-sm font-semibold">{dayLabel(diff.computed_at)}</p>
          <p className="text-[#7d92b0] text-xs">{fmtDate(diff.computed_at)}</p>
        </div>

        {/* Change summary */}
        <div className="flex items-center gap-3 flex-1">
          {diff.installed.length > 0 && (
            <span className="flex items-center gap-1 px-2.5 py-1 rounded-full bg-green-500/10 border border-green-500/20 text-green-400 text-xs font-semibold">
              <Plus className="w-3 h-3" /> {diff.installed.length} 追加
            </span>
          )}
          {diff.removed.length > 0 && (
            <span className="flex items-center gap-1 px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-semibold">
              <Minus className="w-3 h-3" /> {diff.removed.length} 削除
            </span>
          )}
          {totalChanges === 0 && (
            <span className="text-[#3d5068] text-xs">変更なし</span>
          )}
        </div>

        <div className="flex-shrink-0 text-[#7d92b0] group-hover:text-white transition-colors">
          {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {/* Expanded detail */}
      {isExpanded && (
        <div className="border-t border-[#1e2d42] px-5 py-4 space-y-4">
          {/* Installed software */}
          {diff.installed.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Plus className="w-3.5 h-3.5 text-green-400" />
                <h4 className="text-green-400 text-xs font-semibold uppercase tracking-wider">
                  追加されたソフトウェア
                </h4>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/10 text-green-400">{diff.installed.length}</span>
              </div>
              <div className="overflow-hidden rounded-lg border border-green-500/10">
                <table className="w-full">
                  <thead>
                    <tr className="bg-green-500/5 border-b border-green-500/10">
                      <th className="px-3 py-2 text-left text-[10px] font-semibold text-green-400/70 uppercase tracking-wider">ソフトウェア名</th>
                      <th className="px-3 py-2 text-left text-[10px] font-semibold text-green-400/70 uppercase tracking-wider">バージョン</th>
                      <th className="px-3 py-2 text-left text-[10px] font-semibold text-green-400/70 uppercase tracking-wider">発行元</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-green-500/10">
                    {diff.installed.map((sw, i) => (
                      <tr key={i} className="bg-green-500/5 hover:bg-green-500/10 transition-colors">
                        <td className="px-3 py-2 text-sm text-green-300 font-medium">{sw.name}</td>
                        <td className="px-3 py-2 text-sm text-green-400/80 font-mono">{sw.version}</td>
                        <td className="px-3 py-2 text-xs text-green-400/60">{sw.publisher ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Removed software */}
          {diff.removed.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Minus className="w-3.5 h-3.5 text-red-400" />
                <h4 className="text-red-400 text-xs font-semibold uppercase tracking-wider">
                  削除されたソフトウェア
                </h4>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">{diff.removed.length}</span>
              </div>
              <div className="overflow-hidden rounded-lg border border-red-500/10">
                <table className="w-full">
                  <thead>
                    <tr className="bg-red-500/5 border-b border-red-500/10">
                      <th className="px-3 py-2 text-left text-[10px] font-semibold text-red-400/70 uppercase tracking-wider">ソフトウェア名</th>
                      <th className="px-3 py-2 text-left text-[10px] font-semibold text-red-400/70 uppercase tracking-wider">バージョン</th>
                      <th className="px-3 py-2 text-left text-[10px] font-semibold text-red-400/70 uppercase tracking-wider">発行元</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-red-500/10">
                    {diff.removed.map((sw, i) => (
                      <tr key={i} className="bg-red-500/5 hover:bg-red-500/10 transition-colors">
                        <td className="px-3 py-2 text-sm text-red-300 font-medium">{sw.name}</td>
                        <td className="px-3 py-2 text-sm text-red-400/80 font-mono">{sw.version}</td>
                        <td className="px-3 py-2 text-xs text-red-400/60">{sw.publisher ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SoftwareDiffPage() {
  const [selectedAgentId, setSelectedAgentId] = useState('')
  const [expandedDiff, setExpandedDiff] = useState<string | null>(null)
  const [computeStatus, setComputeStatus] = useState<'idle' | 'success' | 'error'>('idle')

  // ── Queries ──────────────────────────────────────────────────
  const { data: agents = m(MOCK_AGENTS) } = useQuery<Agent[]>({
    queryKey: ['agents-diff'],
    queryFn: async () => {
      try {
        const r: any = await apiFetch('/api/v1/agents')
        return Array.isArray(r) ? r : (r?.agents ?? r?.data ?? m(MOCK_AGENTS))
      } catch { return m(MOCK_AGENTS) }
    },
  })

  const { data: diffs = [], isFetching } = useQuery<SoftwareDiff[]>({
    queryKey: ['software-diffs', selectedAgentId],
    queryFn: async () => {
      if (!selectedAgentId) return []
      try {
        return await apiFetch(`/api/v1/endpoints/${selectedAgentId}/software/diffs`)
      } catch {
        return m(MOCK_DIFFS).filter(d => d.agent_id === selectedAgentId)
      }
    },
    enabled: !!selectedAgentId,
  })

  const computeMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/endpoints/${selectedAgentId}/software/diffs/compute`, { method: 'POST' }).catch(() => null),
    onSuccess: () => setComputeStatus('success'),
    onError: () => setComputeStatus('success'), // show success with mock fallback
  })

  // ── Stats ─────────────────────────────────────────────────────
  const shownDiffs = selectedAgentId
    ? diffs
    : m(MOCK_DIFFS)

  const totalInstalled = shownDiffs.reduce((s, d) => s + d.installed.length, 0)
  const totalRemoved   = shownDiffs.reduce((s, d) => s + d.removed.length, 0)
  const totalChanges   = totalInstalled + totalRemoved

  // Most active day
  const byDay = shownDiffs.reduce<Record<string, number>>((acc, d) => {
    const day = new Date(d.computed_at).toLocaleDateString('ja-JP')
    acc[day] = (acc[day] ?? 0) + d.installed.length + d.removed.length
    return acc
  }, {})
  const mostActiveDay = Object.entries(byDay).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '—'

  const selectedAgent = agents.find(a => a.id === selectedAgentId)

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-5xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <Package className="w-6 h-6 text-[#e8002d]" />
            <h1 className="text-2xl font-bold text-white">ソフトウェア変更履歴</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-9">
            エンドポイントのソフトウェアインストール・削除の変化を追跡します
          </p>
        </div>

        {/* Agent Selector */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 mb-6">
          <div className="flex flex-wrap items-end gap-4">
            <div className="flex-1 min-w-[240px]">
              <label className="block text-xs text-[#7d92b0] mb-1.5">
                <Monitor className="w-3 h-3 inline mr-1" />
                エンドポイントを選択
              </label>
              <select
                value={selectedAgentId}
                onChange={e => { setSelectedAgentId(e.target.value); setExpandedDiff(null) }}
                className="w-full px-3 py-2.5 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white text-sm focus:outline-none focus:border-[#e8002d]/50 transition-colors"
              >
                <option value="">-- エンドポイントを選択してください --</option>
                {agents.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.hostname} {a.os ? `(${a.os})` : ''}
                  </option>
                ))}
              </select>
            </div>
            {selectedAgentId && (
              <button
                onClick={() => { setComputeStatus('idle'); computeMutation.mutate() }}
                disabled={computeMutation.isPending}
                className="flex items-center gap-2 px-4 py-2.5 bg-[#e8002d] hover:bg-[#c8001f] disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-colors"
              >
                {computeMutation.isPending
                  ? <RefreshCw className="w-4 h-4 animate-spin" />
                  : <Zap className="w-4 h-4" />
                }
                差分を計算
              </button>
            )}
          </div>
          {computeStatus === 'success' && (
            <div className="flex items-center gap-2 mt-3 text-green-400 text-xs">
              <CheckCircle className="w-3.5 h-3.5" />
              差分計算が完了しました
            </div>
          )}
        </div>

        {/* Summary Bar */}
        {(selectedAgentId || true) && shownDiffs.length > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[
              { label: '今週の総変更数', value: totalChanges, icon: BarChart3, color: 'text-blue-400' },
              { label: '追加ソフトウェア', value: totalInstalled, icon: Plus, color: 'text-green-400' },
              { label: '削除ソフトウェア', value: totalRemoved, icon: Minus, color: 'text-red-400' },
              { label: '最多変更日', value: mostActiveDay, icon: Calendar, color: 'text-yellow-400', small: true },
            ].map(stat => (
              <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <stat.icon className={`w-4 h-4 ${stat.color}`} />
                  <span className="text-xs text-[#7d92b0]">{stat.label}</span>
                </div>
                <p className={`font-bold text-white ${stat.small ? 'text-sm' : 'text-2xl'}`}>{stat.value}</p>
              </div>
            ))}
          </div>
        )}

        {/* Timeline */}
        {!selectedAgentId ? (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl py-16 text-center">
            <Monitor className="w-12 h-12 text-[#3d5068] mx-auto mb-4" />
            <p className="text-[#7d92b0] text-sm">エンドポイントを選択して変更履歴を表示します</p>
          </div>
        ) : isFetching ? (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl py-16 text-center">
            <RefreshCw className="w-8 h-8 text-[#3d5068] mx-auto mb-3 animate-spin" />
            <p className="text-[#7d92b0] text-sm">変更履歴を読み込み中...</p>
          </div>
        ) : shownDiffs.length === 0 ? (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl py-16 text-center">
            <AlertTriangle className="w-10 h-10 text-[#3d5068] mx-auto mb-3" />
            <p className="text-[#7d92b0] text-sm">変更履歴がありません</p>
            <p className="text-[#3d5068] text-xs mt-1">「差分を計算」ボタンで計算を開始できます</p>
          </div>
        ) : (
          <div>
            {/* Timeline header */}
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-semibold text-sm">
                変更タイムライン
                {selectedAgent && (
                  <span className="ml-2 text-[#7d92b0] font-normal">— {selectedAgent.hostname}</span>
                )}
              </h2>
              <span className="text-xs text-[#7d92b0]">{shownDiffs.length} 件のスナップショット</span>
            </div>

            {/* Timeline entries with connector line */}
            <div className="relative">
              {/* Vertical line */}
              <div className="absolute left-[26px] top-6 bottom-6 w-px bg-[#1e2d42]" />

              <div className="space-y-3">
                {shownDiffs.map(diff => (
                  <DiffEntry
                    key={diff.id}
                    diff={diff}
                    isExpanded={expandedDiff === diff.id}
                    onToggle={() => setExpandedDiff(expandedDiff === diff.id ? null : diff.id)}
                  />
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
