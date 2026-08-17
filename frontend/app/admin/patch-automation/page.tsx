'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Wrench, Plus, ToggleLeft, ToggleRight, CheckCircle,
  AlertTriangle, Clock, Play, RefreshCw, ChevronDown, ChevronUp,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low'
type JobStatus = 'pending' | 'approved' | 'running' | 'completed' | 'failed'

interface PatchPolicy {
  id: string; name: string; severities: Severity[]
  auto_approve: boolean; window: string; enabled: boolean
}
interface PatchJob {
  id: string; name: string; status: JobStatus
  total_endpoints: number; patched_count: number; failed_count: number
  pending_reboot: number; started_at: string
}
interface MissingPatch {
  id: string; cve: string; severity: Severity; title: string
  affected_endpoints: number; release_date: string; days_missing: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const severityCls: Record<Severity, string> = {
  critical: 'bg-red-900/40 text-red-300 border-red-700/50',
  high:     'bg-orange-900/40 text-orange-300 border-orange-700/50',
  medium:   'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  low:      'bg-green-900/40 text-green-300 border-green-700/50',
}
const jobStatusCls: Record<JobStatus, string> = {
  pending:   'bg-blue-900/40 text-blue-300 border-blue-700/50',
  approved:  'bg-purple-900/40 text-purple-300 border-purple-700/50',
  running:   'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  completed: 'bg-green-900/40 text-green-300 border-green-700/50',
  failed:    'bg-red-900/40 text-red-300 border-red-700/50',
}
const daysMissingColor = (d: number) =>
  d > 30 ? 'text-red-400' : d > 15 ? 'text-orange-400' : 'text-green-400'

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PatchAutomationPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'policies' | 'jobs' | 'missing'>('policies')
  const [jobFilter, setJobFilter] = useState<JobStatus | '全て'>('全て')
  const [missingSort, setMissingSort] = useState<'severity' | 'days' | 'endpoints'>('severity')
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null)
  const [showNewJobForm, setShowNewJobForm] = useState(false)

  const { data: policies = [] } = useQuery<PatchPolicy[]>({
    queryKey: ['patch-policies'],
    queryFn: () => apiFetchList<PatchPolicy>('/api/v1/admin/patch-automation/policies').catch(() => []),
    staleTime: 30_000,
  })

  const { data: jobs = [] } = useQuery<PatchJob[]>({
    queryKey: ['patch-jobs'],
    queryFn: () => apiFetchList<PatchJob>('/api/v1/admin/patch-automation/jobs').catch(() => []),
    staleTime: 15_000,
  })

  const { data: missing = [] } = useQuery<MissingPatch[]>({
    queryKey: ['missing-patches'],
    queryFn: () => apiFetchList<MissingPatch>('/api/v1/admin/patch-automation/missing-patches').catch(() => []),
    staleTime: 60_000,
  })

  const togglePolicy = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/patch-automation/policies/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['patch-policies'] }),
  })

  const approveJob = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/patch-automation/jobs/${id}/approve`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['patch-jobs'] }),
  })

  const filteredJobs = jobs.filter(j => jobFilter === '全て' ? true : j.status === jobFilter)

  const sortedMissing = [...missing].sort((a, b) => {
    if (missingSort === 'days') return b.days_missing - a.days_missing
    if (missingSort === 'endpoints') return b.affected_endpoints - a.affected_endpoints
    const order: Severity[] = ['critical', 'high', 'medium', 'low']
    return order.indexOf(a.severity) - order.indexOf(b.severity)
  })

  const criticalMissing = missing.filter(p => p.severity === 'critical').length

  const STATS = [
    { label: 'コンプライアンス率', value: '87.3%', color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30' },
    { label: 'クリティカル未適用', value: criticalMissing.toString(), color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
    { label: '高リスク未適用', value: '8', color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/30' },
    { label: '今月ジョブ', value: '8', color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30' },
    { label: '成功率', value: '97.5%', color: 'text-purple-400', bg: 'bg-purple-900/20 border-purple-700/30' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
              <Wrench className="w-4 h-4 text-white" />
            </div>
            <h1 className="text-2xl font-bold">パッチ管理自動化</h1>
          </div>
          <p className="text-falcon-muted text-sm ml-11">エンドポイントのパッチポリシー・適用ジョブ・未適用パッチを管理します</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-4 mb-6">
          {STATS.map(s => (
            <div key={s.label} className={`rounded-xl p-4 border ${s.bg}`}>
              <p className="text-xs text-falcon-muted mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-5 border-b border-falcon-border">
          {([['policies', 'パッチポリシー'], ['jobs', 'パッチジョブ'], ['missing', '未適用パッチ']] as const).map(([k, label]) => (
            <button key={k} onClick={() => setTab(k)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${tab === k ? 'border-falcon-red text-white' : 'border-transparent text-falcon-muted hover:text-white'}`}>
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab: Patch Policies ── */}
        {tab === 'policies' && (
          <div>
            <div className="flex justify-end mb-4">
              <button className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors">
                <Plus className="w-4 h-4" /> 新規ポリシー
              </button>
            </div>
            <div className="space-y-3">
              {policies.map(p => (
                <div key={p.id} className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
                  <div className="flex items-center justify-between px-5 py-4">
                    <div className="flex items-center gap-4">
                      <div>
                        <p className="text-white font-medium">{p.name}</p>
                        <p className="text-xs text-falcon-muted mt-0.5">{p.window}</p>
                      </div>
                      <div className="flex gap-1.5">
                        {p.severities.map(s => (
                          <span key={s} className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${severityCls[s]}`}>{s}</span>
                        ))}
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded-sm border ${p.auto_approve ? 'bg-green-900/30 text-green-300 border-green-700/40' : 'bg-gray-700/30 text-gray-400 border-gray-600/40'}`}>
                        {p.auto_approve ? '自動承認' : '手動承認'}
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      <button onClick={() => togglePolicy.mutate(p.id)}>
                        {p.enabled
                          ? <ToggleRight className="w-6 h-6 text-green-400 hover:text-green-300 transition-colors" />
                          : <ToggleLeft className="w-6 h-6 text-falcon-subtle hover:text-falcon-muted transition-colors" />}
                      </button>
                      <button onClick={() => setExpandedPolicy(expandedPolicy === p.id ? null : p.id)}
                        className="text-falcon-muted hover:text-white transition-colors">
                        {expandedPolicy === p.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                  {expandedPolicy === p.id && (
                    <div className="border-t border-falcon-border px-5 py-4 bg-[#070d19]/50">
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div><p className="text-xs text-falcon-muted mb-1">ポリシーID</p><p className="text-white font-mono">{p.id}</p></div>
                        <div><p className="text-xs text-falcon-muted mb-1">メンテナンスウィンドウ</p><p className="text-white">{p.window}</p></div>
                        <div><p className="text-xs text-falcon-muted mb-1">自動承認</p><p className="text-white">{p.auto_approve ? 'はい' : 'いいえ'}</p></div>
                        <div><p className="text-xs text-falcon-muted mb-1">対象深刻度</p>
                          <div className="flex gap-1 mt-1">{p.severities.map(s => <span key={s} className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${severityCls[s]}`}>{s}</span>)}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tab: Patch Jobs ── */}
        {tab === 'jobs' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex gap-2">
                {(['全て', 'pending', 'approved', 'running', 'completed', 'failed'] as const).map(f => (
                  <button key={f} onClick={() => setJobFilter(f)}
                    className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${jobFilter === f ? 'bg-falcon-red border-falcon-red text-white' : 'bg-falcon-surface border-falcon-border text-falcon-muted hover:text-white'}`}>
                    {f}
                  </button>
                ))}
              </div>
              <button onClick={() => setShowNewJobForm(v => !v)}
                className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors">
                <Plus className="w-4 h-4" /> 新規ジョブ作成
              </button>
            </div>

            {showNewJobForm && (
              <div className="bg-falcon-surface rounded-xl border border-falcon-border p-5 mb-4">
                <p className="text-white font-medium mb-4">新規パッチジョブ作成</p>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-falcon-muted mb-1.5">ジョブ名</label>
                    <input className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-blue/60" placeholder="例: 緊急パッチ適用" />
                  </div>
                  <div>
                    <label className="block text-xs text-falcon-muted mb-1.5">ポリシー選択</label>
                    <select className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-blue/60">
                      {policies.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                    </select>
                  </div>
                </div>
                <div className="flex justify-end gap-3 mt-4">
                  <button onClick={() => setShowNewJobForm(false)} className="px-4 py-2 text-sm text-falcon-muted hover:text-white border border-falcon-border rounded-lg transition-colors">キャンセル</button>
                  <button className="px-4 py-2 text-sm bg-falcon-red hover:bg-[#c0001f] text-white rounded-lg transition-colors">作成</button>
                </div>
              </div>
            )}

            <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['ジョブ名', 'ステータス', '対象', '適用済み', '失敗', '再起動待ち', '進捗', '開始時刻', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredJobs.map(j => {
                    const pct = j.total_endpoints > 0 ? Math.round((j.patched_count / j.total_endpoints) * 100) : 0
                    return (
                      <tr key={j.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                        <td className="px-4 py-3 text-white font-medium">{j.name}</td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-sm border capitalize ${jobStatusCls[j.status]} ${j.status === 'running' ? 'animate-pulse' : ''}`}>
                            {j.status === 'running' && <RefreshCw className="w-3 h-3 animate-spin" />}
                            {j.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-falcon-muted">{j.total_endpoints}</td>
                        <td className="px-4 py-3 text-green-400">{j.patched_count}</td>
                        <td className="px-4 py-3 text-red-400">{j.failed_count}</td>
                        <td className="px-4 py-3 text-yellow-400">{j.pending_reboot}</td>
                        <td className="px-4 py-3 min-w-[120px]">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 bg-falcon-border rounded-full h-1.5">
                              <div className={`h-1.5 rounded-full ${pct === 100 ? 'bg-green-400' : 'bg-blue-400'}`} style={{ width: `${pct}%` }} />
                            </div>
                            <span className="text-xs text-falcon-muted w-8 text-right">{pct}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{fmtDate(j.started_at)}</td>
                        <td className="px-4 py-3">
                          {j.status === 'pending' && (
                            <button onClick={() => approveJob.mutate(j.id)}
                              className="flex items-center gap-1 px-3 py-1 text-xs bg-green-900/40 hover:bg-green-800/60 text-green-300 border border-green-700/50 rounded-lg transition-colors">
                              <CheckCircle className="w-3.5 h-3.5" /> 承認
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Tab: Missing Patches ── */}
        {tab === 'missing' && (
          <div>
            {/* Risk summary card */}
            <div className="bg-red-900/10 border border-red-700/30 rounded-xl p-4 mb-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <div>
                  <p className="text-white font-medium">未適用パッチ リスクサマリー</p>
                  <p className="text-xs text-falcon-muted mt-0.5">クリティカル {criticalMissing} 件 — 即時対応が必要です</p>
                </div>
              </div>
              <button className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors">
                <Play className="w-4 h-4" /> 一括適用 (Critical)
              </button>
            </div>

            <div className="flex items-center justify-between mb-4">
              <p className="text-sm text-falcon-muted">並び替え:</p>
              <div className="flex gap-2">
                {[['severity', '深刻度'], ['days', '未適用日数'], ['endpoints', '影響エンドポイント数']] as const as [string, string][]}
                {(['severity', 'days', 'endpoints'] as const).map((s, i) => (
                  <button key={s} onClick={() => setMissingSort(s)}
                    className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${missingSort === s ? 'bg-falcon-red border-falcon-red text-white' : 'bg-falcon-surface border-falcon-border text-falcon-muted hover:text-white'}`}>
                    {['深刻度', '未適用日数', '影響エンドポイント数'][i]}
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['パッチID', 'CVE', '深刻度', 'タイトル', '影響EP', 'リリース日', '未適用日数', '対応'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sortedMissing.map(p => (
                    <tr key={p.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                      <td className="px-4 py-3 text-white font-mono text-xs">{p.id}</td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono text-falcon-muted bg-[#070d19] px-2 py-0.5 rounded-sm">{p.cve}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${severityCls[p.severity]}`}>{p.severity}</span>
                      </td>
                      <td className="px-4 py-3 text-white text-xs max-w-[200px] truncate">{p.title}</td>
                      <td className="px-4 py-3 text-white font-medium">{p.affected_endpoints}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{p.release_date}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-falcon-subtle" />
                          <span className={`text-xs font-medium ${daysMissingColor(p.days_missing)}`}>{p.days_missing}日</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <button className="flex items-center gap-1 px-3 py-1 text-xs bg-falcon-blue/20 hover:bg-falcon-blue/40 text-blue-300 border border-blue-700/50 rounded-lg transition-colors">
                          <Play className="w-3 h-3" /> 適用
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
