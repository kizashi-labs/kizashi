'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ShieldCheck, RefreshCw, ChevronDown, ChevronRight,
  CheckCircle, XCircle, HelpCircle, Play, AlertTriangle,
  ClipboardList,
} from 'lucide-react'
// ─── Types ────────────────────────────────────────────────────────────────────

type Framework = 'cis' | 'nist' | 'soc2'

interface ControlDetail {
  control_id: string
  title: string
  status: 'pass' | 'fail' | 'unknown'
  evidence: string
  remediation: string
}

interface AgentReport {
  agent_id: string
  framework: Framework
  score: number
  passed: number
  failed: number
  unknown: number
  details: ControlDetail[]
  evaluated_at: string
}

interface FrameworkSummary {
  framework: string
  avg_score: number
  total_agents: number
  evaluated_at: string
}

interface AgentRow {
  id: string
  hostname: string
  os: string
  report?: AgentReport
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const FRAMEWORK_LABELS: Record<Framework, string> = {
  cis:  'CIS Benchmark',
  nist: 'NIST CSF',
  soc2: 'SOC2',
}

const scoreColor  = (s: number) => s >= 80 ? 'text-green-400' : s >= 60 ? 'text-yellow-400' : 'text-red-400'
const scoreRingColor = (s: number) => s >= 80 ? '#4ade80' : s >= 60 ? '#facc15' : '#f87171'

function ScoreRing({ score, size = 100 }: { score: number; size?: number }) {
  const r = size * 0.4
  const circumference = 2 * Math.PI * r
  const dashoffset = circumference * (1 - score / 100)
  const center = size / 2
  const strokeWidth = size * 0.09

  return (
    <svg width={size} height={size} className="-rotate-90" viewBox={`0 0 ${size} ${size}`}>
      <circle cx={center} cy={center} r={r} fill="none" stroke="#1e293b" strokeWidth={strokeWidth} />
      <circle
        cx={center} cy={center} r={r}
        fill="none"
        stroke={scoreRingColor(score)}
        strokeWidth={strokeWidth}
        strokeDasharray={circumference}
        strokeDashoffset={dashoffset}
        strokeLinecap="round"
        style={{ transition: 'stroke-dashoffset 0.8s ease' }}
      />
    </svg>
  )
}

const STATUS_CONFIG = {
  pass:    { label: '合格', className: 'bg-green-500/15 text-green-400 border-green-500/30', icon: <CheckCircle className="w-3 h-3" /> },
  fail:    { label: '不合格', className: 'bg-red-500/15 text-red-400 border-red-500/30',     icon: <XCircle className="w-3 h-3" /> },
  unknown: { label: '不明', className: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',    icon: <HelpCircle className="w-3 h-3" /> },
}

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  } catch {
    return iso
  }
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ComplianceAutoPage() {
  const qc = useQueryClient()
  const [framework, setFramework] = useState<Framework>('cis')
  const [expandedAgentId, setExpandedAgentId] = useState<string | null>(null)
  const [evaluatingAgentId, setEvaluatingAgentId] = useState<string | null>(null)
  const [confirmAll, setConfirmAll] = useState(false)

  // ── Queries ─────────────────────────────────────────────────────────────────

  const summaryQuery = useQuery<FrameworkSummary[]>({
    queryKey: ['compliance-auto-summary'],
    queryFn: () => apiFetchList<FrameworkSummary>('/api/v1/compliance/auto/summary').catch(() => []),
    staleTime: 60_000,
    retry: false,
  })

  const agentsQuery = useQuery<AgentRow[]>({
    queryKey: ['compliance-auto-agents', framework],
    queryFn: () => apiFetchList<AgentRow>(`/api/v1/compliance/auto/agents?framework=${framework}`).catch(() => []),
    staleTime: 60_000,
    retry: false,
  })

  // ── Mutations ────────────────────────────────────────────────────────────────

  const evaluateAgent = useMutation({
    mutationFn: ({ agentId }: { agentId: string }) =>
      apiFetch(`/api/v1/compliance/auto/agents/${agentId}/evaluate?framework=${framework}`, { method: 'POST' }),
    onSuccess: (_data, { agentId }) => {
      setEvaluatingAgentId(null)
      qc.invalidateQueries({ queryKey: ['compliance-auto-agents', framework] })
      qc.invalidateQueries({ queryKey: ['compliance-auto-summary'] })
      console.log(`Agent ${agentId} evaluation triggered`)
    },
    onError: () => setEvaluatingAgentId(null),
  })

  const evaluateAll = useMutation({
    mutationFn: () =>
      Promise.all(
        (agentsQuery.data ?? []).map(a =>
          apiFetch(`/api/v1/compliance/auto/agents/${a.id}/evaluate?framework=${framework}`, { method: 'POST' })
        )
      ),
    onSuccess: () => {
      setConfirmAll(false)
      qc.invalidateQueries({ queryKey: ['compliance-auto-agents', framework] })
      qc.invalidateQueries({ queryKey: ['compliance-auto-summary'] })
    },
  })

  // ── Data helpers ─────────────────────────────────────────────────────────────

  const summary = summaryQuery.data ?? []
  const agents  = agentsQuery.data ?? []

  const getSummary = (fw: Framework) =>
    summary.find(s => s.framework === fw) ?? { framework: fw, avg_score: 0, total_agents: 0, evaluated_at: '' }

  // ─── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#0d1117] p-6">

      {/* ── Header ─────────────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div>
          <h1 className="text-2xl font-bold text-[#e6edf3] flex items-center gap-2.5">
            <ShieldCheck className="w-7 h-7 text-blue-400" />
            コンプライアンス自動評価
          </h1>
          <p className="text-[#7d8590] text-sm mt-1">
            CIS Benchmark / NIST CSF / SOC2 フレームワークに基づくエージェントの自動コンプライアンス評価
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {confirmAll ? (
            <div className="flex items-center gap-2">
              <span className="text-[#f0883e] text-sm">全エージェントを評価しますか？</span>
              <button
                onClick={() => evaluateAll.mutate()}
                disabled={evaluateAll.isPending}
                className="px-3 py-1.5 bg-falcon-red text-white text-sm rounded-sm hover:bg-[#c80026] disabled:opacity-50 transition-colors"
              >
                {evaluateAll.isPending ? '実行中...' : '確認'}
              </button>
              <button
                onClick={() => setConfirmAll(false)}
                className="px-3 py-1.5 bg-[#21262d] text-[#e6edf3] text-sm rounded-sm hover:bg-[#30363d] transition-colors"
              >
                キャンセル
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmAll(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#1f6feb] text-white text-sm rounded-md hover:bg-[#388bfd] transition-colors font-medium"
            >
              <Play className="w-4 h-4" />
              全エージェントを評価
            </button>
          )}
        </div>
      </div>

      {/* ── Framework Cards ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {(['cis', 'nist', 'soc2'] as Framework[]).map(fw => {
          const s = getSummary(fw)
          const isSelected = framework === fw
          return (
            <button
              key={fw}
              onClick={() => { setFramework(fw); setExpandedAgentId(null) }}
              className={`bg-[#161b22] border rounded-lg p-5 text-left transition-all cursor-pointer hover:border-[#388bfd]/50 ${
                isSelected ? 'border-[#1f6feb] ring-1 ring-[#1f6feb]/30' : 'border-[#30363d] hover:bg-[#1c2128]'
              }`}
            >
              <div className="flex items-center justify-between mb-4">
                <div>
                  <p className="text-[#7d8590] text-xs font-medium uppercase tracking-wider mb-1">
                    {FRAMEWORK_LABELS[fw]}
                  </p>
                  <p className={`text-4xl font-bold ${scoreColor(s.avg_score)}`}>
                    {s.avg_score}
                    <span className="text-base font-normal text-[#7d8590] ml-1">/ 100</span>
                  </p>
                </div>
                <div className="relative shrink-0">
                  <ScoreRing score={s.avg_score} size={72} />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className={`text-sm font-bold ${scoreColor(s.avg_score)}`}>{s.avg_score}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between text-xs text-[#7d8590]">
                <span>{s.total_agents} エージェント評価済み</span>
                {s.evaluated_at && (
                  <span>{fmtDate(s.evaluated_at)}</span>
                )}
              </div>
              {isSelected && (
                <div className="mt-3 pt-3 border-t border-[#30363d]">
                  <span className="text-xs text-[#1f6feb] font-medium">選択中のフレームワーク</span>
                </div>
              )}
            </button>
          )
        })}
      </div>

      {/* ── Framework Tabs (secondary) ──────────────────────────────────────────── */}
      <div className="flex items-center gap-1 mb-4 bg-[#161b22] border border-[#30363d] rounded-lg p-1 w-fit">
        {(['cis', 'nist', 'soc2'] as Framework[]).map(fw => (
          <button
            key={fw}
            onClick={() => { setFramework(fw); setExpandedAgentId(null) }}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              framework === fw
                ? 'bg-[#1f6feb] text-white'
                : 'text-[#7d8590] hover:text-[#e6edf3]'
            }`}
          >
            {FRAMEWORK_LABELS[fw]}
          </button>
        ))}
      </div>

      {/* ── Agent Table ─────────────────────────────────────────────────────────── */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#30363d]">
          <div className="flex items-center gap-2">
            <ClipboardList className="w-4 h-4 text-[#7d8590]" />
            <h2 className="text-[#e6edf3] font-semibold text-sm">
              エージェント評価結果 — {FRAMEWORK_LABELS[framework]}
            </h2>
            <span className="px-2 py-0.5 bg-[#21262d] text-[#7d8590] text-xs rounded-sm">
              {agents.length} 件
            </span>
          </div>
          {agentsQuery.isFetching && (
            <RefreshCw className="w-4 h-4 text-[#7d8590] animate-spin" />
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#30363d]">
                {['ホスト名', 'OS', 'スコア', '合格', '不合格', '不明', '評価日時', '操作'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-[#7d8590] uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {agents.map(agent => {
                const r = agent.report
                const isExpanded = expandedAgentId === agent.id
                const isEvaluating = evaluatingAgentId === agent.id && evaluateAgent.isPending

                return (
                  <>
                    <tr
                      key={agent.id}
                      onClick={() => setExpandedAgentId(isExpanded ? null : agent.id)}
                      className="border-b border-[#21262d] hover:bg-[#1c2128] cursor-pointer transition-colors"
                    >
                      {/* Hostname */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {isExpanded
                            ? <ChevronDown className="w-4 h-4 text-[#7d8590] shrink-0" />
                            : <ChevronRight className="w-4 h-4 text-[#7d8590] shrink-0" />
                          }
                          <span className="text-[#e6edf3] font-medium font-mono text-xs">{agent.hostname}</span>
                        </div>
                      </td>
                      {/* OS */}
                      <td className="px-4 py-3 text-[#7d8590] text-xs whitespace-nowrap">{agent.os}</td>
                      {/* Score */}
                      <td className="px-4 py-3">
                        {r ? (
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full transition-all ${
                                  r.score >= 80 ? 'bg-green-400' : r.score >= 60 ? 'bg-yellow-400' : 'bg-red-400'
                                }`}
                                style={{ width: `${r.score}%` }}
                              />
                            </div>
                            <span className={`text-sm font-bold ${scoreColor(r.score)}`}>{r.score}</span>
                          </div>
                        ) : (
                          <span className="text-[#484f58] text-xs">未評価</span>
                        )}
                      </td>
                      {/* Passed */}
                      <td className="px-4 py-3">
                        {r ? <span className="text-green-400 font-medium text-sm">{r.passed}</span> : <span className="text-[#484f58]">—</span>}
                      </td>
                      {/* Failed */}
                      <td className="px-4 py-3">
                        {r ? <span className="text-red-400 font-medium text-sm">{r.failed}</span> : <span className="text-[#484f58]">—</span>}
                      </td>
                      {/* Unknown */}
                      <td className="px-4 py-3">
                        {r ? <span className="text-[#7d8590] font-medium text-sm">{r.unknown}</span> : <span className="text-[#484f58]">—</span>}
                      </td>
                      {/* Evaluated At */}
                      <td className="px-4 py-3 text-[#7d8590] text-xs whitespace-nowrap">
                        {r ? fmtDate(r.evaluated_at) : '—'}
                      </td>
                      {/* Action */}
                      <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => {
                            setEvaluatingAgentId(agent.id)
                            evaluateAgent.mutate({ agentId: agent.id })
                          }}
                          disabled={isEvaluating}
                          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#21262d] border border-[#30363d] text-[#e6edf3] text-xs rounded-sm hover:bg-[#30363d] disabled:opacity-50 transition-colors whitespace-nowrap"
                        >
                          {isEvaluating
                            ? <RefreshCw className="w-3 h-3 animate-spin" />
                            : <Play className="w-3 h-3 text-[#1f6feb]" />
                          }
                          評価実行
                        </button>
                      </td>
                    </tr>

                    {/* ── Expanded Detail Row ─────────────────────────────────── */}
                    {isExpanded && r && (
                      <tr key={`${agent.id}-detail`} className="border-b border-[#21262d]">
                        <td colSpan={8} className="px-0 py-0">
                          <div className="bg-[#0d1117] border-t border-[#30363d] px-6 py-4">
                            <div className="flex items-center gap-2 mb-3">
                              <AlertTriangle className="w-4 h-4 text-[#f0883e]" />
                              <h3 className="text-[#e6edf3] font-semibold text-sm">
                                コントロール詳細 — {agent.hostname}
                              </h3>
                              <span className="ml-auto flex items-center gap-3 text-xs">
                                <span className="flex items-center gap-1 text-green-400">
                                  <CheckCircle className="w-3 h-3" /> {r.passed} 合格
                                </span>
                                <span className="flex items-center gap-1 text-red-400">
                                  <XCircle className="w-3 h-3" /> {r.failed} 不合格
                                </span>
                                <span className="flex items-center gap-1 text-[#7d8590]">
                                  <HelpCircle className="w-3 h-3" /> {r.unknown} 不明
                                </span>
                              </span>
                            </div>
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="border-b border-[#21262d]">
                                  {['コントロールID', 'タイトル', 'ステータス', '証拠', '是正措置'].map(h => (
                                    <th key={h} className="text-left py-2 px-3 text-[#7d8590] font-medium uppercase tracking-wider">
                                      {h}
                                    </th>
                                  ))}
                                </tr>
                              </thead>
                              <tbody>
                                {r.details.map(ctrl => (
                                  <tr key={ctrl.control_id} className="border-b border-[#21262d]/50 hover:bg-[#161b22] transition-colors">
                                    <td className="py-2.5 px-3 font-mono text-[#7d8590] whitespace-nowrap">
                                      {ctrl.control_id}
                                    </td>
                                    <td className="py-2.5 px-3 text-[#e6edf3] max-w-[200px]">
                                      {ctrl.title}
                                    </td>
                                    <td className="py-2.5 px-3">
                                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm border text-[11px] font-medium ${STATUS_CONFIG[ctrl.status].className}`}>
                                        {STATUS_CONFIG[ctrl.status].icon}
                                        {STATUS_CONFIG[ctrl.status].label}
                                      </span>
                                    </td>
                                    <td className="py-2.5 px-3 text-[#7d8590] max-w-[260px]">
                                      <span className="line-clamp-2">{ctrl.evidence || '—'}</span>
                                    </td>
                                    <td className="py-2.5 px-3 text-[#f0883e] max-w-[260px]">
                                      {ctrl.remediation
                                        ? <span className="line-clamp-2">{ctrl.remediation}</span>
                                        : <span className="text-[#484f58]">—</span>
                                      }
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}

              {agents.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[#484f58]">
                    エージェントが見つかりません
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
