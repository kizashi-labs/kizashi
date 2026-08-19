'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Eye, AlertTriangle, Shield, TrendingUp, FileText, CheckCircle, ArrowUpCircle } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────────────────────

type ThreatCategory = 'data_exfil' | 'privilege_abuse' | 'unusual_hours' | 'mass_download' | 'lateral_movement' | 'policy_violation'
type InvestigationStatus = 'active' | 'monitoring' | 'cleared'
type Severity = 'low' | 'medium' | 'high' | 'critical'

interface Investigation {
  id: string
  subject: string
  category: ThreatCategory
  risk_score: number
  evidence_count: number
  status: InvestigationStatus
  assigned_to: string
  started: string
}

interface BehaviorIndicator {
  id: string
  user: string
  type: ThreatCategory
  description: string
  severity: Severity
  timestamp: string
}

const RISK_TIMELINE: { day: string; score: number }[] = [
  { day: 'Mar 06', score: 42 }, { day: 'Mar 07', score: 38 }, { day: 'Mar 08', score: 55 },
  { day: 'Mar 09', score: 61 }, { day: 'Mar 10', score: 48 }, { day: 'Mar 11', score: 72 },
  { day: 'Mar 12', score: 67 }, { day: 'Mar 13', score: 58 }, { day: 'Mar 14', score: 83 },
  { day: 'Mar 15', score: 76 }, { day: 'Mar 16', score: 69 }, { day: 'Mar 17', score: 91 },
  { day: 'Mar 18', score: 85 }, { day: 'Mar 19', score: 78 },
]

// ── Helpers ────────────────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<ThreatCategory, { label: string; icon: string; cls: string }> = {
  data_exfil:       { label: 'データ持ち出し',       icon: '📤', cls: 'bg-red-500/15 text-red-300 border-red-500/30'          },
  privilege_abuse:  { label: '権限乱用',             icon: '🔑', cls: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  unusual_hours:    { label: '異常な時間帯',         icon: '🌙', cls: 'bg-blue-500/15 text-blue-300 border-blue-500/30'       },
  mass_download:    { label: '大量ダウンロード',     icon: '📥', cls: 'bg-red-600/15 text-red-400 border-red-600/30'          },
  lateral_movement: { label: 'ラテラルムーブメント', icon: '🔄', cls: 'bg-purple-500/15 text-purple-300 border-purple-500/30' },
  policy_violation: { label: 'ポリシー違反',         icon: '⚠️', cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
}

const STATUS_CONFIG: Record<InvestigationStatus, { label: string; cls: string }> = {
  active:     { label: 'アクティブ', cls: 'bg-red-500/15 text-red-300 border-red-500/30'          },
  monitoring: { label: '監視中',     cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  cleared:    { label: '解除',       cls: 'bg-green-500/15 text-green-300 border-green-500/30'    },
}

const SEVERITY_CONFIG: Record<Severity, { cls: string }> = {
  low:      { cls: 'bg-green-500/15 text-green-300 border-green-500/30'    },
  medium:   { cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  high:     { cls: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  critical: { cls: 'bg-red-500/15 text-red-300 border-red-500/30'           },
}

function riskScoreColor(score: number) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

function timelineBarColor(score: number) {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#eab308'
  return '#22c55e'
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function InsiderThreatPage() {
  const qc = useQueryClient()
  const [localInvestigations, setLocalInvestigations] = useState<Investigation[]>([])

  const { data: indicatorsData } = useQuery<BehaviorIndicator[]>({
    queryKey: ['insider-threat-indicators'],
    queryFn: () => apiFetch<BehaviorIndicator[]>('/api/v1/insider-threat/indicators'),
    staleTime: 60_000,
  })
  const indicators: BehaviorIndicator[] = indicatorsData ?? []
  // Threat indicator dashboard counts
  const dataExfilCount     = indicators.filter(i => i.type === 'data_exfil').length
  const privilegeAbuseCount = indicators.filter(i => i.type === 'privilege_abuse').length
  const unusualAccessCount = indicators.filter(i => i.type === 'unusual_hours' || i.type === 'lateral_movement').length
  const policyViolCount    = indicators.filter(i => i.type === 'policy_violation').length

  const handleCaseAction = (id: string, action: 'escalate' | 'open' | 'clear') => {
    setLocalInvestigations(prev =>
      prev.map(inv => {
        if (inv.id !== id) return inv
        if (action === 'clear') return { ...inv, status: 'cleared' as InvestigationStatus }
        if (action === 'escalate') return { ...inv, status: 'active' as InvestigationStatus }
        return inv
      })
    )
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 flex items-center justify-center">
            <Eye className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">内部脅威検出</h1>
            <p className="text-sm text-[#7d92b0]">行動インテリジェンスとケース管理</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-orange-500/10 border border-orange-500/30">
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          <span className="text-xs text-[#7d92b0]">現在の脅威レベル:</span>
          <span className="text-sm font-bold text-orange-400">上昇中</span>
        </div>
      </div>

      {/* Threat Indicator Cards */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        {[
          { label: 'データ持ち出し試行',     value: dataExfilCount,      icon: '📤', color: 'text-red-400',    border: 'border-red-500/20'    },
          { label: '権限乱用',               value: privilegeAbuseCount, icon: '🔑', color: 'text-orange-400', border: 'border-orange-500/20' },
          { label: '不審アクセスパターン',   value: unusualAccessCount,  icon: '🔄', color: 'text-yellow-400', border: 'border-yellow-500/20' },
          { label: 'ポリシー違反',           value: policyViolCount,     icon: '⚠️', color: 'text-blue-400',   border: 'border-blue-500/20'   },
        ].map(({ label, value, icon, color, border }) => (
          <div key={label} className={`bg-[#0d1220] border ${border} rounded-xl p-4`}>
            <div className="flex items-center gap-2 mb-3">
              <span className="text-lg">{icon}</span>
              <p className="text-xs text-[#7d92b0] leading-tight">{label}</p>
            </div>
            <p className={`text-3xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Active Investigations */}
      <div className="mb-8">
        <h2 className="text-white font-semibold text-lg mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-[#e8002d]" />
          アクティブな調査
        </h2>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['対象者', '脅威カテゴリ', 'リスクスコア', '証拠', 'ステータス', '担当者', '開始日', '操作'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {localInvestigations.map(inv => {
                const cat = CATEGORY_CONFIG[inv.category]
                const st  = STATUS_CONFIG[inv.status]
                return (
                  <tr key={inv.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                    <td className="px-4 py-3">
                      <span className="text-sm text-white font-mono">{inv.subject}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs border font-medium ${cat.cls}`}>
                        <span>{cat.icon}</span>
                        {cat.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-lg font-bold ${riskScoreColor(inv.risk_score)}`}>{inv.risk_score}</span>
                    </td>
                    <td className="px-4 py-3 text-sm text-[#7d92b0]">{inv.evidence_count} 件</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${st.cls}`}>
                        {st.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-[#7d92b0]">{inv.assigned_to}</td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">{inv.started}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleCaseAction(inv.id, 'open')}
                          className="px-2 py-1 rounded-sm text-xs bg-blue-900/30 hover:bg-blue-900/50 text-blue-300 border border-blue-500/20 transition-colors whitespace-nowrap"
                        >
                          開く
                        </button>
                        <button
                          onClick={() => handleCaseAction(inv.id, 'escalate')}
                          className="px-2 py-1 rounded-sm text-xs bg-orange-900/30 hover:bg-orange-900/50 text-orange-300 border border-orange-500/20 transition-colors"
                        >
                          エスカレート
                        </button>
                        <button
                          onClick={() => handleCaseAction(inv.id, 'clear')}
                          className="px-2 py-1 rounded-sm text-xs bg-green-900/30 hover:bg-green-900/50 text-green-300 border border-green-500/20 transition-colors"
                        >
                          解除
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Behavioral Indicators + Risk Timeline — side by side */}
      <div className="grid grid-cols-5 gap-6 mb-8">
        {/* Behavioral Indicators */}
        <div className="col-span-3">
          <h2 className="text-white font-semibold text-lg mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-[#e8002d]" />
            行動指標
          </h2>
          <div className="space-y-3">
            {indicators.map(indicator => {
              const cat = CATEGORY_CONFIG[indicator.type]
              const sev = SEVERITY_CONFIG[indicator.severity]
              return (
                <div
                  key={indicator.id}
                  className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 hover:border-[#2a3a52] transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <span className="text-xl shrink-0 mt-0.5">{cat.icon}</span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="text-sm font-semibold text-white font-mono">{indicator.user}</span>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${cat.cls}`}>
                            {cat.label}
                          </span>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium capitalize ${sev.cls}`}>
                            {indicator.severity}
                          </span>
                        </div>
                        <p className="text-sm text-[#7d92b0]">{indicator.description}</p>
                      </div>
                    </div>
                    <span className="text-xs text-[#7d92b0] whitespace-nowrap shrink-0">{fmtDate(indicator.timestamp)}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Risk Timeline */}
        <div className="col-span-2">
          <h2 className="text-white font-semibold text-lg mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-[#e8002d]" />
            7日間リスクタイムライン
          </h2>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-end gap-2 h-40 mb-3">
              {RISK_TIMELINE.map(({ day, score }) => {
                const heightPct = (score / 100) * 100
                const barColor = timelineBarColor(score)
                return (
                  <div key={day} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs font-mono font-semibold" style={{ color: barColor }}>{score}</span>
                    <div className="w-full flex items-end" style={{ height: '120px' }}>
                      <div
                        className="w-full rounded-t transition-all"
                        style={{
                          height: `${heightPct}%`,
                          backgroundColor: barColor,
                          opacity: 0.85,
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
            <div className="flex items-center gap-2 border-t border-[#1e2d42] pt-3">
              {RISK_TIMELINE.map(({ day }) => (
                <div key={day} className="flex-1 text-center">
                  <span className="text-[10px] text-[#7d92b0]">{day.replace('Mar ', '')}</span>
                </div>
              ))}
            </div>
            <p className="text-xs text-[#7d92b0] mt-3 text-center">内部脅威スコアの総合値（0〜100）</p>

            {/* Score legend */}
            <div className="flex items-center justify-center gap-4 mt-3">
              {[
                { color: '#22c55e', label: '低' },
                { color: '#eab308', label: '中' },
                { color: '#f97316', label: '高' },
                { color: '#ef4444', label: 'クリティカル' },
              ].map(({ color, label }) => (
                <div key={label} className="flex items-center gap-1">
                  <div className="w-2.5 h-2.5 rounded-xs" style={{ backgroundColor: color }} />
                  <span className="text-xs text-[#7d92b0]">{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
