'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Flame, X, CheckSquare, Square, Clock, Shield, AlertTriangle,
  ExternalLink, ChevronDown, ChevronUp, Eye, Zap, Lock,
  RefreshCw, Activity, CheckCircle, Circle,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ──────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low'
type ResponseStatus = 'monitoring' | 'mitigating' | 'patched' | 'accepted_risk'

interface Advisory {
  id: string
  cve_id: string
  title: string
  product_affected: string
  severity: Severity
  discovery_date: string
  public_exploit: boolean
  patch_available: boolean
  affected_assets: number
  response_status: ResponseStatus
  description: string
  affected_versions: string[]
  exploitation_techniques: { technique_id: string; name: string }[]
  temporary_mitigations: string[]
  vendor_advisory_url: string
  workarounds: string[]
  cvss_score: number
}

interface ResponseTask {
  id: string
  phase: string
  task: string
  completed: boolean
}

interface TimelineEntry {
  id: string
  timestamp: string
  actor: string
  action: string
}

interface AffectedEndpoint {
  id: string
  hostname: string
  ip: string
  os: string
  vulnerable_version: string
  patched: boolean
}

interface IntelItem {
  id: string
  cve_id: string
  product: string
  severity: Severity
  source: string
  summary: string
  timestamp: string
}

// ── Helpers ────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40',
  high: 'bg-orange-900/30 text-orange-400 border border-orange-700/40',
  medium: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/40',
  low: 'bg-blue-900/30 text-blue-400 border border-blue-700/40',
}

const STATUS_STYLES: Record<ResponseStatus, string> = {
  monitoring: 'bg-blue-900/30 text-blue-400 border border-blue-700/40',
  mitigating: 'bg-orange-900/30 text-orange-400 border border-orange-700/40',
  patched: 'bg-green-900/30 text-green-400 border border-green-700/40',
  accepted_risk: 'bg-purple-900/30 text-purple-400 border border-purple-700/40',
}

const STATUS_LABELS: Record<ResponseStatus, string> = {
  monitoring: 'モニタリング中',
  mitigating: '対応中',
  patched: 'パッチ適用済',
  accepted_risk: 'リスク承認',
}

const PHASES = ['Detection', 'Assessment', 'Containment', 'Remediation', 'Monitoring']

function fmt(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Advisory Card ──────────────────────────────────────────────────────────

function AdvisoryCard({
  advisory,
  selected,
  onSelect,
  onStartResponse,
}: {
  advisory: Advisory
  selected: boolean
  onSelect: () => void
  onStartResponse: () => void
}) {
  const [showDetail, setShowDetail] = useState(false)

  return (
    <div className={`bg-[#0d1220] border rounded-lg transition-all ${selected ? 'border-[#e8002d]/60' : 'border-[#1e2d42] hover:border-[#2a3f5c]'}`}>
      <div className="p-4">
        <div className="flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-bold text-[#e8002d]">{advisory.cve_id}</span>
              <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${SEVERITY_STYLES[advisory.severity]} ${advisory.severity === 'critical' ? 'critical-pulse' : ''}`}>
                {advisory.severity.toUpperCase()} {advisory.severity === 'critical' ? '(0-day)' : ''}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${STATUS_STYLES[advisory.response_status]}`}>
                {STATUS_LABELS[advisory.response_status]}
              </span>
            </div>
            <p className="text-white font-semibold mt-1 text-sm">{advisory.title}</p>
            <p className="text-[#7d92b0] text-xs mt-0.5">{advisory.product_affected}</p>
          </div>
          <div className="flex flex-col items-end gap-1 shrink-0">
            <span className="text-[#7d92b0] text-xs">{advisory.discovery_date}</span>
            <div className="flex items-center gap-2 mt-1">
              <span className={`text-xs px-2 py-0.5 rounded-sm ${advisory.public_exploit ? 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40' : 'bg-[#1e2d42] text-[#7d92b0]'}`}>
                {advisory.public_exploit ? '公開エクスプロイト' : 'エクスプロイトなし'}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded-sm ${advisory.patch_available ? 'bg-green-900/30 text-green-400 border border-green-700/40' : 'bg-orange-900/30 text-orange-400 border border-orange-700/40'}`}>
                {advisory.patch_available ? 'パッチあり' : 'パッチなし'}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4 mt-3">
          <div className="flex items-center gap-1 text-xs text-[#7d92b0]">
            <Shield className="w-3.5 h-3.5" />
            <span>影響資産: <span className="text-white font-medium">{advisory.affected_assets}</span> 台</span>
          </div>
          <div className="flex items-center gap-1 text-xs text-[#7d92b0]">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>CVSS: <span className={`font-bold ${advisory.cvss_score >= 9 ? 'text-[#ff4d6d]' : advisory.cvss_score >= 7 ? 'text-orange-400' : 'text-yellow-400'}`}>{advisory.cvss_score.toFixed(1)}</span></span>
          </div>
        </div>

        <div className="flex items-center gap-2 mt-3">
          <button
            onClick={() => setShowDetail(v => !v)}
            className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white transition-colors"
          >
            {showDetail ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            {showDetail ? '詳細を閉じる' : '詳細を表示'}
          </button>
          <button
            onClick={onSelect}
            className="flex items-center gap-1.5 px-3 py-1 text-xs rounded-sm bg-[#1e2d42] text-[#7d92b0] hover:bg-[#243650] hover:text-white transition-colors"
          >
            <Eye className="w-3.5 h-3.5" />
            対応ワークフロー
          </button>
          {advisory.response_status === 'monitoring' && (
            <button
              onClick={onStartResponse}
              className="flex items-center gap-1.5 px-3 py-1 text-xs rounded-sm bg-[#e8002d] text-white hover:bg-[#c4001f] transition-colors"
            >
              <Flame className="w-3.5 h-3.5" />
              対応開始
            </button>
          )}
        </div>
      </div>

      {showDetail && (
        <div className="border-t border-[#1e2d42] p-4 space-y-4">
          <div>
            <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-2">説明</h4>
            <p className="text-[#7d92b0] text-sm leading-relaxed">{advisory.description}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-2">影響バージョン</h4>
              <div className="flex flex-wrap gap-1">
                {advisory.affected_versions.map(v => (
                  <span key={v} className="font-mono text-xs bg-[#161f33] border border-[#1e2d42] px-2 py-0.5 rounded-sm text-[#7d92b0]">{v}</span>
                ))}
              </div>
            </div>

            <div>
              <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-2">MITRE ATT&CK テクニック</h4>
              <div className="space-y-1">
                {advisory.exploitation_techniques.map(t => (
                  <div key={t.technique_id} className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-[#e8002d] bg-[#e8002d]/10 px-1.5 py-0.5 rounded-sm">{t.technique_id}</span>
                    <span className="text-[#7d92b0]">{t.name}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div>
            <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-2">暫定緩和策</h4>
            <ul className="space-y-1">
              {advisory.temporary_mitigations.map((m, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-[#7d92b0]">
                  <CheckCircle className="w-3.5 h-3.5 text-green-500 shrink-0 mt-0.5" />
                  {m}
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-2">ワークアラウンド</h4>
            <ul className="space-y-1">
              {advisory.workarounds.map((w, i) => (
                <li key={i} className="font-mono text-xs text-[#7d92b0] bg-[#161f33] border border-[#1e2d42] px-3 py-2 rounded-sm">{w}</li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-1">ベンダーアドバイザリ</h4>
            <p className="font-mono text-xs text-[#7d92b0] bg-[#161f33] border border-[#1e2d42] px-3 py-2 rounded-sm break-all">{advisory.vendor_advisory_url}</p>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Response Workflow ──────────────────────────────────────────────────────

function ResponseWorkflow({ advisory }: { advisory: Advisory }) {
  const [tasks, setTasks] = useState<ResponseTask[]>([])
  const [activePhase, setActivePhase] = useState('Detection')
  const [mitigationMsg, setMitigationMsg] = useState<string | null>(null)

  const toggleTask = (id: string) => {
    setTasks(prev => prev.map(t => t.id === id ? { ...t, completed: !t.completed } : t))
  }

  const phaseProgress = (phase: string) => {
    const phaseTasks = tasks.filter(t => t.phase === phase)
    if (phaseTasks.length === 0) return 0
    return Math.round((phaseTasks.filter(t => t.completed).length / phaseTasks.length) * 100)
  }

  const handleMitigation = (action: string) => {
    setMitigationMsg(`${action} を実行しました (モック)`)
    setTimeout(() => setMitigationMsg(null), 3000)
  }

  const timeline: TimelineEntry[] = []
  const endpoints: AffectedEndpoint[] = []

  return (
    <div className="space-y-4">
      {/* Phase Progress */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
        <h3 className="text-white font-semibold mb-4 text-sm">対応フェーズ</h3>
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          {PHASES.map((phase, idx) => {
            const prog = phaseProgress(phase)
            const isActive = phase === activePhase
            const isComplete = prog === 100
            return (
              <div key={phase} className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => setActivePhase(phase)}
                  className={`flex flex-col items-center gap-1 px-3 py-2 rounded-lg transition-all ${isActive ? 'bg-[#1d2f4a] border border-[#e8002d]/40' : 'border border-[#1e2d42] hover:border-[#2a3f5c]'}`}
                >
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${isComplete ? 'bg-green-900/50 text-green-400 border border-green-700/50' : isActive ? 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40' : 'bg-[#161f33] text-[#7d92b0] border border-[#1e2d42]'}`}>
                    {isComplete ? <CheckCircle className="w-4 h-4" /> : idx + 1}
                  </div>
                  <span className={`text-xs font-medium ${isActive ? 'text-white' : 'text-[#7d92b0]'}`}>{phase}</span>
                  <div className="w-full h-1 bg-[#161f33] rounded-full mt-1" style={{ minWidth: '60px' }}>
                    <div className="h-1 rounded-full bg-[#e8002d] transition-all" style={{ width: `${prog}%` }} />
                  </div>
                  <span className="text-[10px] text-[#7d92b0]">{prog}%</span>
                </button>
                {idx < PHASES.length - 1 && <div className="w-6 h-0.5 bg-[#1e2d42] shrink-0" />}
              </div>
            )
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Checklist */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <h3 className="text-white font-semibold mb-3 text-sm">{activePhase} チェックリスト</h3>
          <div className="space-y-2">
            {tasks.filter(t => t.phase === activePhase).map(task => (
              <label key={task.id} className="flex items-start gap-2 cursor-pointer group">
                <button onClick={() => toggleTask(task.id)} className="mt-0.5 shrink-0">
                  {task.completed
                    ? <CheckSquare className="w-4 h-4 text-green-400" />
                    : <Square className="w-4 h-4 text-[#3d5068] group-hover:text-[#7d92b0]" />
                  }
                </button>
                <span className={`text-sm ${task.completed ? 'line-through text-[#3d5068]' : 'text-[#7d92b0] group-hover:text-white'} transition-colors`}>
                  {task.task}
                </span>
              </label>
            ))}
            {tasks.filter(t => t.phase === activePhase).length === 0 && (
              <p className="text-[#3d5068] text-sm">このフェーズのタスクはありません</p>
            )}
          </div>
        </div>

        {/* Timeline Log */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <h3 className="text-white font-semibold mb-3 text-sm">対応タイムライン</h3>
          <div className="space-y-3">
            {timeline.map(entry => (
              <div key={entry.id} className="flex gap-3">
                <div className="flex flex-col items-center">
                  <div className="w-2 h-2 rounded-full bg-[#e8002d] shrink-0 mt-1.5" />
                  <div className="w-0.5 flex-1 bg-[#1e2d42] mt-1" />
                </div>
                <div className="pb-3 min-w-0">
                  <p className="text-white text-xs font-medium">{entry.action}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[#3d5068] text-[10px] font-mono">{fmt(entry.timestamp)}</span>
                    <span className="text-[#7d92b0] text-[10px]">{entry.actor}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Affected Endpoints */}
      {endpoints.length > 0 && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <h3 className="text-white font-semibold mb-3 text-sm">影響エンドポイント ({endpoints.length} 台)</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['ホスト名', 'IPアドレス', 'OS', '脆弱バージョン', 'パッチ状態'].map(h => (
                    <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {endpoints.map(ep => (
                  <tr key={ep.id} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors">
                    <td className="py-2 px-3 font-mono text-white">{ep.hostname}</td>
                    <td className="py-2 px-3 font-mono text-[#7d92b0]">{ep.ip}</td>
                    <td className="py-2 px-3 text-[#7d92b0]">{ep.os}</td>
                    <td className="py-2 px-3 font-mono text-orange-400">{ep.vulnerable_version}</td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded-sm text-xs ${ep.patched ? 'bg-green-900/30 text-green-400 border border-green-700/40' : 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40'}`}>
                        {ep.patched ? 'パッチ済' : '未パッチ'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Mitigation Actions */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
        <h3 className="text-white font-semibold mb-3 text-sm">緩和アクション</h3>
        {mitigationMsg && (
          <div className="mb-3 px-3 py-2 bg-green-900/30 border border-green-700/40 rounded-sm text-green-400 text-xs">
            {mitigationMsg}
          </div>
        )}
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => handleMitigation('仮想パッチ適用')}
            className="flex items-center gap-1.5 px-4 py-2 bg-orange-900/30 border border-orange-700/40 text-orange-400 text-xs rounded-sm hover:bg-orange-900/50 transition-colors"
          >
            <Shield className="w-3.5 h-3.5" />
            仮想パッチ適用
          </button>
          <button
            onClick={() => handleMitigation('ネットワーク隔離')}
            className="flex items-center gap-1.5 px-4 py-2 bg-[#e8002d]/20 border border-[#e8002d]/40 text-[#ff4d6d] text-xs rounded-sm hover:bg-[#e8002d]/30 transition-colors"
          >
            <Lock className="w-3.5 h-3.5" />
            ネットワーク隔離
          </button>
          <button
            onClick={() => handleMitigation('IOCブロック')}
            className="flex items-center gap-1.5 px-4 py-2 bg-purple-900/30 border border-purple-700/40 text-purple-400 text-xs rounded-sm hover:bg-purple-900/50 transition-colors"
          >
            <Zap className="w-3.5 h-3.5" />
            IOCブロック
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function ZeroDayPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery<Advisory[]>({
    queryKey: ['zero-day-advisories'],
    queryFn: () => apiFetch('/api/v1/admin/zero-day/advisories'),
    staleTime: 60_000,
    retry: false,
    throwOnError: false,
  })

  const advisories: Advisory[] = data ?? []
  const activeCount = advisories.filter(a => a.response_status !== 'patched').length

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: ResponseStatus }) =>
      apiFetch(`/api/v1/admin/zero-day/advisories/${id}/status`, { method: 'PUT', body: JSON.stringify({ status }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['zero-day-advisories'] }),
  })

  const selectedAdvisory = advisories.find(a => a.id === selectedId)

  // Statistics
  const totalOpen = advisories.filter(a => a.response_status !== 'patched').length
  const totalAssets = advisories.reduce((s, a) => s + a.affected_assets, 0)
  const patchedCount = advisories.filter(a => a.response_status === 'patched').length
  const patchedPct = advisories.length > 0 ? Math.round((patchedCount / advisories.length) * 100) : 0

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/40 flex items-center justify-center">
            <Flame className="w-5 h-5 text-[#ff4d6d]" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-white text-xl font-bold">ゼロデイ対応センター</h1>
              {activeCount > 0 && (
                <span className="px-2 py-0.5 text-xs font-bold rounded-sm bg-[#e8002d] text-white critical-pulse">
                  CRITICAL
                </span>
              )}
            </div>
            <p className="text-[#7d92b0] text-sm mt-0.5">Zero-Day Response Center — アクティブな脆弱性の追跡と対応</p>
          </div>
        </div>
        <button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['zero-day-advisories'] })}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-xs rounded-sm hover:border-[#2a3f5c] hover:text-white transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          更新
        </button>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'オープン ゼロデイ', value: totalOpen, sub: '件', color: 'text-[#ff4d6d]' },
          { label: '影響アセット合計', value: totalAssets, sub: '台', color: 'text-orange-400' },
          { label: 'パッチ適用済 (最新)', value: `${patchedPct}%`, sub: 'of fleet', color: 'text-green-400' },
          { label: '平均対応時間', value: '18h', sub: 'MTTM', color: 'text-blue-400' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <p className="text-[#7d92b0] text-xs">{stat.label}</p>
            <div className="flex items-baseline gap-1 mt-1">
              <span className={`text-2xl font-bold ${stat.color}`}>{stat.value}</span>
              <span className="text-[#7d92b0] text-xs">{stat.sub}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 space-y-4">
          {/* Active Advisories */}
          <div>
            <h2 className="text-white font-semibold mb-3 flex items-center gap-2">
              <Flame className="w-4 h-4 text-[#e8002d]" />
              アクティブ アドバイザリ ({advisories.length})
            </h2>

            {isLoading ? (
              <div className="space-y-4">
                {[1, 2].map(i => (
                  <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 animate-pulse">
                    <div className="h-4 bg-[#1e2d42] rounded-sm w-1/3 mb-2" />
                    <div className="h-3 bg-[#1e2d42] rounded-sm w-2/3" />
                  </div>
                ))}
              </div>
            ) : advisories.length === 0 ? (
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-8 text-center">
                <CheckCircle className="w-10 h-10 text-green-400 mx-auto mb-3" />
                <p className="text-white font-medium">アクティブなゼロデイアドバイザリはありません</p>
                <p className="text-[#7d92b0] text-sm mt-1">フリートは現在保護されています</p>
              </div>
            ) : (
              <div className="space-y-3">
                {advisories.map(adv => (
                  <AdvisoryCard
                    key={adv.id}
                    advisory={adv}
                    selected={selectedId === adv.id}
                    onSelect={() => setSelectedId(selectedId === adv.id ? null : adv.id)}
                    onStartResponse={() => {
                      setSelectedId(adv.id)
                      updateStatus.mutate({ id: adv.id, status: 'mitigating' })
                    }}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Response Workflow */}
          {selectedAdvisory && (
            <div>
              <h2 className="text-white font-semibold mb-3 flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#e8002d]" />
                対応ワークフロー: <span className="font-mono text-[#e8002d]">{selectedAdvisory.cve_id}</span>
              </h2>
              <ResponseWorkflow advisory={selectedAdvisory} />
            </div>
          )}
        </div>

        {/* Intel Feed */}
        <div className="space-y-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <h2 className="text-white font-semibold mb-3 flex items-center gap-2 text-sm">
              <Rss className="w-4 h-4 text-[#e8002d]" />
              インテリジェンスフィード
            </h2>
            <div className="space-y-3">
              {([] as IntelItem[]).map(item => (
                <div key={item.id} className="border border-[#1e2d42] rounded-lg p-3 hover:border-[#2a3f5c] transition-colors">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-[#e8002d] font-bold">{item.cve_id}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${SEVERITY_STYLES[item.severity]}`}>
                      {item.severity.toUpperCase()}
                    </span>
                    <span className="text-[10px] text-[#3d5068] ml-auto">{item.source}</span>
                  </div>
                  <p className="text-[#7d92b0] text-xs mt-1">{item.product}</p>
                  <p className="text-[#7d92b0] text-xs mt-1 leading-relaxed">{item.summary}</p>
                  <p className="text-[#3d5068] text-[10px] mt-1.5 font-mono">{fmt(item.timestamp)}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// needed for intel feed icon
function Rss(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg {...props} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 11a9 9 0 0 1 9 9" /><path d="M4 4a16 16 0 0 1 16 16" /><circle cx="5" cy="19" r="1" />
    </svg>
  )
}
