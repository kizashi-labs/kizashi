'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  HardDrive, CheckCircle, XCircle, Shield, RefreshCw,
  ToggleLeft, ToggleRight, Server, Layers,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type OSType = 'Windows' | 'Linux' | 'macOS' | 'RHEL'
type Framework = 'CIS' | 'STIG' | 'NIST'
type AssessmentStatus = 'compliant' | 'non_compliant' | 'partial'

interface Assessment {
  id: string
  hostname: string
  baseline: string
  passed: number
  failed: number
  score: number
  status: AssessmentStatus
  last_assessed: string
}

interface Baseline {
  id: string
  name: string
  os_type: OSType
  framework: Framework
  version: string
  enabled: boolean
}

interface HardeningStats {
  total_assessments: number
  compliant_count: number
  average_score: number
  active_baselines: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const scoreColor = (score: number) => {
  if (score >= 80) return 'text-green-400'
  if (score >= 60) return 'text-yellow-400'
  return 'text-red-400'
}

const scoreBarColor = (score: number) => {
  if (score >= 80) return 'bg-green-500'
  if (score >= 60) return 'bg-yellow-500'
  return 'bg-red-500'
}

const statusBadge = (s: AssessmentStatus) => {
  const map: Record<AssessmentStatus, string> = {
    compliant:     'bg-green-900/40 text-green-300 border-green-700/50',
    partial:       'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    non_compliant: 'bg-red-900/40 text-red-300 border-red-700/50',
  }
  return map[s]
}

const statusLabel = (s: AssessmentStatus) => {
  const map: Record<AssessmentStatus, string> = {
    compliant:     '準拠',
    partial:       '一部準拠',
    non_compliant: '非準拠',
  }
  return map[s]
}

const osBadge = (os: OSType) => {
  const map: Record<OSType, string> = {
    Windows: 'bg-blue-900/40 text-blue-300 border-blue-700/50',
    Linux:   'bg-orange-900/40 text-orange-300 border-orange-700/50',
    macOS:   'bg-purple-900/40 text-purple-300 border-purple-700/50',
    RHEL:    'bg-red-900/40 text-red-300 border-red-700/50',
  }
  return map[os]
}

const frameworkBadge = (f: Framework) => {
  const map: Record<Framework, string> = {
    CIS:  'bg-cyan-900/40 text-cyan-300 border-cyan-700/50',
    STIG: 'bg-indigo-900/40 text-indigo-300 border-indigo-700/50',
    NIST: 'bg-green-900/40 text-green-300 border-green-700/50',
  }
  return map[f]
}

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EndpointHardeningPage() {
  const [activeTab, setActiveTab] = useState<'assessments' | 'baselines'>('assessments')

  const { data: stats, isLoading: statsLoading, refetch } = useQuery<HardeningStats>({
    queryKey: ['endpoint-hardening-stats'],
    queryFn: () => apiFetch('/api/v1/admin/endpoint-hardening/stats'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: assessmentsData } = useQuery<{ assessments: Assessment[] }>({
    queryKey: ['endpoint-hardening-assessments'],
    queryFn: () => apiFetch('/api/v1/admin/endpoint-hardening/assessments'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: baselinesData } = useQuery<{ baselines: Baseline[] }>({
    queryKey: ['endpoint-hardening-baselines'],
    queryFn: () => apiFetch('/api/v1/admin/endpoint-hardening/baselines'),
    staleTime: 60_000,
    retry: false,
  })

  const EMPTY_HARDENING_STATS: HardeningStats = { total_assessments: 0, compliant_count: 0, average_score: 0, active_baselines: 0 }
  const rawStats = stats as any
  const normalizedStats: HardeningStats = stats ? {
    total_assessments: rawStats.total_assessments ?? rawStats.total ?? 0,
    compliant_count:   rawStats.compliant_count ?? rawStats.compliant ?? 0,
    average_score:     rawStats.average_score ?? rawStats.avg_score ?? 0,
    active_baselines:  rawStats.active_baselines ?? rawStats.baselines ?? 0,
  } : EMPTY_HARDENING_STATS
  const displayStats = normalizedStats
  const displayAssessments = assessmentsData?.assessments ?? []
  const displayBaselines = baselinesData?.baselines ?? []

  const avgScore = displayStats.average_score
  const gaugeColor = avgScore >= 80 ? '#22c55e' : avgScore >= 60 ? '#eab308' : '#ef4444'

  // Gauge: we approximate a ring via a conic-gradient approach using inline style
  const gaugeDeg = Math.round((avgScore / 100) * 360)

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center shadow-lg">
                <HardDrive className="w-4 h-4 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">エンドポイント堅牢化</h1>
                <p className="text-falcon-muted text-sm">CIS/STIGコンプライアンス評価</p>
              </div>
            </div>
            <button
              onClick={() => refetch()}
              className="flex items-center gap-2 px-3 py-2 text-sm text-falcon-muted hover:text-white border border-falcon-border hover:border-falcon-muted/40 rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              更新
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: '総評価数', value: displayStats.total_assessments, icon: Server, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30' },
            { label: '準拠済み (≥80%)', value: displayStats.compliant_count, icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30' },
            { label: '平均スコア', value: `${displayStats.average_score}%`, icon: Shield, color: avgScore >= 80 ? 'text-green-400' : avgScore >= 60 ? 'text-yellow-400' : 'text-red-400', bg: avgScore >= 80 ? 'bg-green-900/20 border-green-700/30' : avgScore >= 60 ? 'bg-yellow-900/20 border-yellow-700/30' : 'bg-red-900/20 border-red-700/30' },
            { label: '有効ベースライン', value: displayStats.active_baselines, icon: Layers, color: 'text-purple-400', bg: 'bg-purple-900/20 border-purple-700/30' },
          ].map(s => (
            <div key={s.label} className={`rounded-xl p-4 border ${s.bg} bg-falcon-surface`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-falcon-muted">{s.label}</span>
                <s.icon className={`w-4 h-4 ${s.color}`} />
              </div>
              <p className={`text-3xl font-bold ${s.color}`}>
                {statsLoading ? '—' : s.value}
              </p>
            </div>
          ))}
        </div>

        {/* Overall Score Gauge */}
        <div className="bg-falcon-surface rounded-xl border border-falcon-border p-6 mb-6 flex items-center gap-8">
          {/* Gauge display */}
          <div className="shrink-0 flex flex-col items-center">
            <div
              className="relative w-32 h-32 rounded-full flex items-center justify-center"
              style={{
                background: `conic-gradient(${gaugeColor} ${gaugeDeg}deg, #1e2d42 ${gaugeDeg}deg)`,
              }}
            >
              <div className="absolute inset-3 rounded-full bg-falcon-surface flex flex-col items-center justify-center">
                <span className={`text-3xl font-bold`} style={{ color: gaugeColor }}>
                  {avgScore}
                </span>
                <span className="text-falcon-muted text-xs">/ 100</span>
              </div>
            </div>
            <p className="text-falcon-muted text-xs mt-2">総合スコア</p>
          </div>

          {/* Breakdown */}
          <div className="flex-1 grid grid-cols-3 gap-4">
            <div className="text-center">
              <p className="text-green-400 text-2xl font-bold">{displayStats.compliant_count}</p>
              <p className="text-falcon-muted text-xs mt-1">準拠ホスト</p>
            </div>
            <div className="text-center">
              <p className="text-yellow-400 text-2xl font-bold">
                {displayAssessments.filter(a => a.status === 'partial').length}
              </p>
              <p className="text-falcon-muted text-xs mt-1">一部準拠</p>
            </div>
            <div className="text-center">
              <p className="text-red-400 text-2xl font-bold">
                {displayAssessments.filter(a => a.status === 'non_compliant').length}
              </p>
              <p className="text-falcon-muted text-xs mt-1">非準拠</p>
            </div>
          </div>

          <div className="flex-1">
            <p className="text-xs text-falcon-muted mb-2">スコア分布</p>
            <div className="space-y-2">
              {[
                { label: '高 (≥80%)', count: displayAssessments.filter(a => a.score >= 80).length, color: 'bg-green-500' },
                { label: '中 (60–79%)', count: displayAssessments.filter(a => a.score >= 60 && a.score < 80).length, color: 'bg-yellow-500' },
                { label: '低 (<60%)', count: displayAssessments.filter(a => a.score < 60).length, color: 'bg-red-500' },
              ].map(b => (
                <div key={b.label} className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${b.color}`} />
                  <span className="text-xs text-falcon-muted flex-1">{b.label}</span>
                  <span className="text-xs text-white font-bold">{b.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-5 border-b border-falcon-border">
          {(['assessments', 'baselines'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px
                ${activeTab === tab
                  ? 'border-falcon-red text-white'
                  : 'border-transparent text-falcon-muted hover:text-white'
                }`}
            >
              {tab === 'assessments' ? '評価一覧' : 'ベースライン'}
            </button>
          ))}
        </div>

        {/* Assessments Tab */}
        {activeTab === 'assessments' && (
          <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ホスト名', 'ベースライン', '合格', '不合格', 'スコア', 'ステータス', '最終評価日時'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayAssessments.map(a => (
                  <tr key={a.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Server className="w-3.5 h-3.5 text-falcon-muted" />
                        <span className="text-white font-mono text-xs">{a.hostname}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-xs">{a.baseline}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                        <span className="text-green-400 text-xs font-bold">{a.passed}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <XCircle className="w-3.5 h-3.5 text-red-400" />
                        <span className="text-red-400 text-xs font-bold">{a.failed}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <div className="w-20 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${scoreBarColor(a.score)}`}
                              style={{ width: `${a.score}%` }}
                            />
                          </div>
                          <span className={`text-xs font-bold ${scoreColor(a.score)}`}>{a.score}%</span>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-sm border ${statusBadge(a.status)}`}>
                        {statusLabel(a.status)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-xs whitespace-nowrap">{fmtDate(a.last_assessed)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Baselines Tab */}
        {activeTab === 'baselines' && (
          <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['名前', 'OSタイプ', 'フレームワーク', 'バージョン', '有効'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayBaselines.map(bl => (
                  <tr key={bl.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                    <td className="px-4 py-3">
                      <span className="text-white font-medium">{bl.name}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-sm border ${osBadge(bl.os_type)}`}>
                        {bl.os_type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-sm border ${frameworkBadge(bl.framework)}`}>
                        {bl.framework}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted font-mono text-xs">{bl.version}</span>
                    </td>
                    <td className="px-4 py-3">
                      {bl.enabled
                        ? <ToggleRight className="w-6 h-6 text-green-400" />
                        : <ToggleLeft className="w-6 h-6 text-falcon-subtle" />
                      }
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
