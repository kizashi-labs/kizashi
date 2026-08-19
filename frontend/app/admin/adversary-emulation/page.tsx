'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  Target, Plus, X, ChevronDown, ChevronRight, Download,
  Play, Eye, Shield, AlertTriangle, CheckCircle, XCircle,
  Clock, User, Calendar, BarChart3, FileText, Info,
  TrendingUp, Minus, RefreshCw
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ────────────────────────────────────────────────────────

type PlanStatus = 'draft' | 'approved' | 'in_progress' | 'completed' | 'archived'

interface Technique {
  id: string
  mitre_id: string
  name: string
  description: string
  detection_opportunity: string
  procedure_steps: string[]
}

interface EmulationPhase {
  id: string
  name: string
  order: number
  description: string
  techniques: Technique[]
}

interface ActorProfile {
  name: string
  motivation: string
  sophistication: 'nation_state' | 'organized_crime' | 'hacktivist' | 'insider'
  origin: string
  known_campaigns: string[]
}

interface EmulationPlan {
  id: string
  plan_name: string
  threat_actor_based_on: string
  actor_profile: ActorProfile
  scope: string
  status: PlanStatus
  created_by: string
  last_executed: string | null
  technique_count: number
  phases: EmulationPhase[]
  target_systems: string[]
  excluded_systems: string[]
  time_window: string
  rules_of_engagement: string
  preconditions: { label: string; checked: boolean }[]
  created_at: string
}

type TechniqueResult = 'detected' | 'missed' | 'blocked'

interface TechniqueExecResult {
  mitre_id: string
  technique_name: string
  result: TechniqueResult
  notes: string
}

interface PhaseExecResult {
  phase_name: string
  techniques: TechniqueExecResult[]
}

interface ExecutionResult {
  id: string
  plan_id: string
  plan_name: string
  executed_at: string
  executed_by: string
  duration_minutes: number
  phases_completed: number
  phases_total: number
  detections_count: number
  missed_detections_count: number
  detection_rate: number
  phase_results: PhaseExecResult[]
  gap_analysis: { mitre_id: string; technique_name: string; recommendation: string }[]
  notes: string
}

// ── Helpers ──────────────────────────────────────────────────────

const PLAN_STATUS_STYLES: Record<PlanStatus, { bg: string; text: string; label: string }> = {
  draft:       { bg: 'bg-gray-800',      text: 'text-gray-400',   label: 'ドラフト' },
  approved:    { bg: 'bg-blue-900/40',   text: 'text-blue-300',   label: '承認済み' },
  in_progress: { bg: 'bg-yellow-900/40', text: 'text-yellow-300', label: '実行中' },
  completed:   { bg: 'bg-green-900/40',  text: 'text-green-300',  label: '完了' },
  archived:    { bg: 'bg-gray-800',      text: 'text-gray-500',   label: 'アーカイブ' },
}

const SOPHISTICATION_LABELS: Record<string, string> = {
  nation_state:     '国家アクター',
  organized_crime:  '組織犯罪',
  hacktivist:       'ハクティビスト',
  insider:          '内部脅威',
}

const RESULT_CONFIG: Record<TechniqueResult, { icon: React.ComponentType<{ className?: string }>; color: string; label: string; bg: string }> = {
  detected: { icon: CheckCircle, color: 'text-green-400',  label: '検知',   bg: 'bg-green-900/30' },
  missed:   { icon: XCircle,    color: 'text-red-400',    label: '見逃し', bg: 'bg-red-900/30' },
  blocked:  { icon: Shield,     color: 'text-blue-400',   label: 'ブロック', bg: 'bg-blue-900/30' },
}

function fmt(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Plan Detail Panel ────────────────────────────────────────────

function PlanDetail({ plan, onClose }: { plan: EmulationPlan; onClose: () => void }) {
  const [expandedPhase, setExpandedPhase] = useState<string | null>(null)
  const statusStyle = PLAN_STATUS_STYLES[plan.status]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-3xl max-h-[92vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Target className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">{plan.plan_name}</h2>
            <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${statusStyle.bg} ${statusStyle.text}`}>{statusStyle.label}</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => {}} className="flex items-center gap-1 px-3 py-1.5 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white text-xs transition-colors">
              <Download className="w-3.5 h-3.5" /> 計画をエクスポート
            </button>
            <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
          </div>
        </div>
        <div className="p-4 space-y-4">
          {/* Actor Profile */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-3">脅威アクタープロファイル: {plan.threat_actor_based_on}</p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-[#3d5068] text-xs mb-0.5">動機</p>
                <p className="text-white text-sm">{plan.actor_profile.motivation}</p>
              </div>
              <div>
                <p className="text-[#3d5068] text-xs mb-0.5">洗練度</p>
                <p className="text-white text-sm">{SOPHISTICATION_LABELS[plan.actor_profile.sophistication]}</p>
              </div>
              <div>
                <p className="text-[#3d5068] text-xs mb-0.5">帰属</p>
                <p className="text-white text-sm">{plan.actor_profile.origin}</p>
              </div>
              <div>
                <p className="text-[#3d5068] text-xs mb-0.5">既知キャンペーン</p>
                <div className="flex flex-wrap gap-1">
                  {plan.actor_profile.known_campaigns.map(c => (
                    <span key={c} className="px-1.5 py-0.5 bg-[#1e2d42] rounded-sm text-[10px] text-[#7d92b0]">{c}</span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Scope & ROE */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">スコープ</p>
              <p className="text-white text-sm mb-2">{plan.scope}</p>
              <p className="text-[#3d5068] text-xs mb-1">対象システム:</p>
              {plan.target_systems.map(s => <p key={s} className="text-[#7d92b0] text-xs font-mono">{s}</p>)}
              <p className="text-[#3d5068] text-xs mt-2 mb-1">除外システム:</p>
              {plan.excluded_systems.map(s => <p key={s} className="text-[#7d92b0] text-xs font-mono">{s}</p>)}
            </div>
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">実施規則 (ROE)</p>
              <p className="text-[#7d92b0] text-xs leading-relaxed">{plan.rules_of_engagement}</p>
              <p className="text-[#3d5068] text-xs mt-2 mb-1">時間帯:</p>
              <p className="text-white text-xs">{plan.time_window}</p>
            </div>
          </div>

          {/* Preconditions */}
          <div className="bg-[#070d19] rounded-sm p-3">
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">実施前提条件チェックリスト</p>
            <div className="space-y-2">
              {plan.preconditions.map((pre, i) => (
                <div key={i} className="flex items-center gap-2">
                  {pre.checked
                    ? <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                    : <div className="w-4 h-4 rounded-full border border-[#1e2d42] shrink-0" />
                  }
                  <span className={`text-sm ${pre.checked ? 'text-[#7d92b0]' : 'text-white'}`}>{pre.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Emulation Phases */}
          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">エミュレーションフェーズ ({plan.phases.length}フェーズ / {plan.technique_count}テクニック)</p>
            <div className="space-y-2">
              {plan.phases.map(phase => (
                <div key={phase.id} className="border border-[#1e2d42] rounded-lg overflow-hidden">
                  <button onClick={() => setExpandedPhase(expandedPhase === phase.id ? null : phase.id)}
                    className="w-full flex items-center justify-between px-4 py-3 bg-[#070d19] hover:bg-[#070d19]/50 transition-colors">
                    <div className="flex items-center gap-2">
                      {expandedPhase === phase.id ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />}
                      <span className="text-white font-medium">Phase {phase.order}: {phase.name}</span>
                    </div>
                    <span className="text-[#7d92b0] text-xs">{phase.techniques.length} テクニック</span>
                  </button>
                  {expandedPhase === phase.id && (
                    <div className="px-4 py-3 space-y-3">
                      <p className="text-[#7d92b0] text-sm">{phase.description}</p>
                      {phase.techniques.map(tech => (
                        <div key={tech.id} className="bg-[#070d19] border border-[#1e2d42] rounded-sm p-3">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="px-1.5 py-0.5 bg-[#e8002d]/10 border border-[#e8002d]/20 rounded-sm text-xs text-[#e8002d] font-mono">{tech.mitre_id}</span>
                            <span className="text-white font-medium text-sm">{tech.name}</span>
                          </div>
                          <p className="text-[#7d92b0] text-xs mb-2">{tech.description}</p>
                          <div className="mb-2">
                            <span className="text-[#3d5068] text-xs">検知機会: </span>
                            <span className="text-green-400 text-xs">{tech.detection_opportunity}</span>
                          </div>
                          <div>
                            <p className="text-[#3d5068] text-xs mb-1">手順 (シミュレーションのみ):</p>
                            {tech.procedure_steps.map((step, si) => (
                              <p key={si} className="text-[#7d92b0] font-mono text-xs leading-relaxed ml-2">{si + 1}. {step}</p>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Execution Result Detail ──────────────────────────────────────

function ExecutionDetail({ result, onClose }: { result: ExecutionResult; onClose: () => void }) {
  const allTechniques = result.phase_results.flatMap(p => p.techniques)
  const tactics = ['初期侵害', '足場確立', '権限昇格', '内部偵察', '横移動', '収集・持ち出し']

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-3xl max-h-[92vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">実行結果詳細</h2>
            <span className="text-[#7d92b0] text-sm">{result.plan_name}</span>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-4">
          {/* Summary */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: '検知率', value: `${result.detection_rate.toFixed(1)}%`, color: result.detection_rate >= 80 ? 'text-green-400' : result.detection_rate >= 60 ? 'text-yellow-400' : 'text-red-400' },
              { label: '検知数', value: result.detections_count, color: 'text-green-400' },
              { label: '見逃し', value: result.missed_detections_count, color: 'text-red-400' },
              { label: '所要時間', value: `${result.duration_minutes}分`, color: 'text-[#7d92b0]' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-[#070d19] rounded-sm p-3 text-center">
                <p className="text-[#7d92b0] text-xs mb-1">{label}</p>
                <p className={`text-xl font-bold ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Detection heatmap-style: tactic columns */}
          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">検知カバレッジ (MITRE ATT&CK タクティクス × 検知状況)</p>
            <div className="overflow-x-auto">
              <div className="flex gap-2 min-w-max">
                {result.phase_results.map(phase => (
                  <div key={phase.phase_name} className="min-w-[120px]">
                    <p className="text-[#7d92b0] text-[10px] text-center mb-1 truncate">{phase.phase_name}</p>
                    <div className="space-y-1">
                      {phase.techniques.map(tech => {
                        const rc = RESULT_CONFIG[tech.result]
                        const RIcon = rc.icon
                        return (
                          <div key={tech.mitre_id} className={`${rc.bg} rounded-sm p-1.5 flex items-center gap-1`}>
                            <RIcon className={`w-3 h-3 shrink-0 ${rc.color}`} />
                            <span className="text-[10px] text-white font-mono truncate">{tech.mitre_id}</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="flex items-center gap-4 mt-2">
              {Object.entries(RESULT_CONFIG).map(([key, val]) => {
                const VIcon = val.icon
                return (
                  <div key={key} className="flex items-center gap-1">
                    <VIcon className={`w-3 h-3 ${val.color}`} />
                    <span className="text-[#7d92b0] text-xs">{val.label}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Phase-by-phase results */}
          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">フェーズ別結果</p>
            <div className="space-y-3">
              {result.phase_results.map(phase => (
                <div key={phase.phase_name} className="bg-[#070d19] rounded-lg p-3">
                  <p className="text-white font-medium text-sm mb-2">{phase.phase_name}</p>
                  {phase.techniques.map(tech => {
                    const rc = RESULT_CONFIG[tech.result]
                    const TIcon = rc.icon
                    return (
                      <div key={tech.mitre_id} className="flex items-start gap-3 mb-2 last:mb-0">
                        <div className={`flex items-center gap-1.5 shrink-0 px-2 py-1 rounded-sm ${rc.bg}`}>
                          <TIcon className={`w-3.5 h-3.5 ${rc.color}`} />
                          <span className={`text-xs font-medium ${rc.color}`}>{rc.label}</span>
                        </div>
                        <div>
                          <p className="text-white text-xs font-mono">{tech.mitre_id} — {tech.technique_name}</p>
                          <p className="text-[#7d92b0] text-xs">{tech.notes}</p>
                        </div>
                      </div>
                    )
                  })}
                </div>
              ))}
            </div>
          </div>

          {/* Gap Analysis */}
          {result.gap_analysis.length > 0 && (
            <div>
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">ギャップ分析と推奨事項</p>
              <div className="space-y-3">
                {result.gap_analysis.map((gap, i) => (
                  <div key={i} className="bg-red-900/10 border border-red-500/20 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <XCircle className="w-4 h-4 text-red-400" />
                      <span className="text-white font-medium text-sm">{gap.technique_name}</span>
                      <span className="text-[#7d92b0] font-mono text-xs">{gap.mitre_id}</span>
                    </div>
                    <p className="text-[#7d92b0] text-sm">{gap.recommendation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Notes */}
          {result.notes && (
            <div className="bg-[#070d19] rounded-sm p-3">
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-1">総括</p>
              <p className="text-[#7d92b0] text-sm">{result.notes}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── New Execution Log Modal ──────────────────────────────────────

function NewExecutionModal({ plans, onClose, onSave }: { plans: EmulationPlan[]; onClose: () => void; onSave: (data: Partial<ExecutionResult>) => void }) {
  const [planId, setPlanId] = useState(plans[0]?.id ?? '')
  const [notes, setNotes] = useState('')
  const [duration, setDuration] = useState(240)
  const [detected, setDetected] = useState(0)
  const [missed, setMissed] = useState(0)

  const total = detected + missed
  const rate = total > 0 ? Math.round((detected / total) * 100 * 10) / 10 : 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">新規実行結果を記録</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[#7d92b0] text-xs block mb-1">計画</label>
            <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden"
              value={planId} onChange={e => setPlanId(e.target.value)}>
              {plans.map(p => <option key={p.id} value={p.id}>{p.plan_name}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">所要時間 (分)</label>
              <input type="number" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden"
                value={duration} onChange={e => setDuration(Number(e.target.value))} />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">検知率: {rate}%</label>
              <div className="w-full bg-[#1e2d42] rounded-full h-2 mt-3">
                <div className={`h-2 rounded-full ${rate >= 80 ? 'bg-green-500' : rate >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${rate}%` }} />
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">検知数</label>
              <input type="number" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden"
                value={detected} onChange={e => setDetected(Number(e.target.value))} />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">見逃し数</label>
              <input type="number" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden"
                value={missed} onChange={e => setMissed(Number(e.target.value))} />
            </div>
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs block mb-1">メモ</label>
            <textarea rows={3} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden resize-none"
              value={notes} onChange={e => setNotes(e.target.value)} placeholder="実行結果の概要を入力..." />
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
          <button onClick={() => onSave({ plan_id: planId, duration_minutes: duration, detections_count: detected, missed_detections_count: missed, detection_rate: rate, notes, phases_completed: 0, phases_total: 0, phase_results: [], gap_analysis: [] })}
            className="px-4 py-2 bg-[#e8002d] rounded-sm text-white text-sm hover:bg-[#e8002d]/80">記録する</button>
        </div>
      </div>
    </div>
  )
}

function NewPlanModal({ onClose, onSave, saving }: { onClose: () => void; onSave: (data: Partial<EmulationPlan>) => void; saving: boolean }) {
  const [planName, setPlanName] = useState('')
  const [basedOn, setBasedOn] = useState('')
  const [actorName, setActorName] = useState('')
  const [sophistication, setSophistication] = useState<ActorProfile['sophistication']>('nation_state')
  const [motivation, setMotivation] = useState('')
  const [origin, setOrigin] = useState('')
  const [scope, setScope] = useState('')
  const [status, setStatus] = useState<PlanStatus>('draft')
  const [timeWindow, setTimeWindow] = useState('')
  const [roe, setRoe] = useState('')
  const [targets, setTargets] = useState('')
  const [excluded, setExcluded] = useState('')

  const csv = (s: string) => s.split(',').map(x => x.trim()).filter(Boolean)
  const canSave = planName.trim().length > 0 && !saving
  const inputCls = 'w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none'
  const labelCls = 'text-[#7d92b0] text-xs block mb-1'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-lg max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">計画を作成</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3 overflow-y-auto">
          <div>
            <label className={labelCls}>計画名 <span className="text-[#e8002d]">*</span></label>
            <input className={inputCls} value={planName} onChange={e => setPlanName(e.target.value)} placeholder="例: APT29 エミュレーション Q3" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>基にする脅威アクター</label>
              <input className={inputCls} value={basedOn} onChange={e => setBasedOn(e.target.value)} placeholder="例: APT29 (Cozy Bear)" />
            </div>
            <div>
              <label className={labelCls}>ステータス</label>
              <select className={inputCls} value={status} onChange={e => setStatus(e.target.value as PlanStatus)}>
                <option value="draft">ドラフト</option>
                <option value="approved">承認済み</option>
                <option value="in_progress">実行中</option>
                <option value="completed">完了</option>
                <option value="archived">アーカイブ</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>アクター名</label>
              <input className={inputCls} value={actorName} onChange={e => setActorName(e.target.value)} placeholder="例: Cozy Bear" />
            </div>
            <div>
              <label className={labelCls}>高度さ</label>
              <select className={inputCls} value={sophistication} onChange={e => setSophistication(e.target.value as ActorProfile['sophistication'])}>
                <option value="nation_state">国家アクター</option>
                <option value="organized_crime">組織犯罪</option>
                <option value="hacktivist">ハクティビスト</option>
                <option value="insider">内部脅威</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>動機</label>
              <input className={inputCls} value={motivation} onChange={e => setMotivation(e.target.value)} placeholder="例: 諜報活動" />
            </div>
            <div>
              <label className={labelCls}>起源</label>
              <input className={inputCls} value={origin} onChange={e => setOrigin(e.target.value)} placeholder="例: ロシア" />
            </div>
          </div>
          <div>
            <label className={labelCls}>スコープ</label>
            <textarea rows={2} className={`${inputCls} resize-none`} value={scope} onChange={e => setScope(e.target.value)} placeholder="評価対象範囲の概要..." />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>対象システム (カンマ区切り)</label>
              <input className={inputCls} value={targets} onChange={e => setTargets(e.target.value)} placeholder="web-01, db-01" />
            </div>
            <div>
              <label className={labelCls}>除外システム (カンマ区切り)</label>
              <input className={inputCls} value={excluded} onChange={e => setExcluded(e.target.value)} placeholder="prod-payment" />
            </div>
          </div>
          <div>
            <label className={labelCls}>実施時間帯</label>
            <input className={inputCls} value={timeWindow} onChange={e => setTimeWindow(e.target.value)} placeholder="例: 平日 22:00-02:00" />
          </div>
          <div>
            <label className={labelCls}>交戦規則 (ROE)</label>
            <textarea rows={2} className={`${inputCls} resize-none`} value={roe} onChange={e => setRoe(e.target.value)} placeholder="実施上の制約・禁止事項..." />
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
          <button disabled={!canSave}
            onClick={() => onSave({
              plan_name: planName.trim(),
              threat_actor_based_on: basedOn,
              actor_profile: { name: actorName, motivation, sophistication, origin, known_campaigns: [] },
              scope,
              status,
              time_window: timeWindow,
              rules_of_engagement: roe,
              target_systems: csv(targets),
              excluded_systems: csv(excluded),
              phases: [],
              preconditions: [],
            })}
            className={`px-4 py-2 rounded-sm text-white text-sm ${canSave ? 'bg-[#e8002d] hover:bg-[#e8002d]/80' : 'bg-[#e8002d]/40 cursor-not-allowed'}`}>
            {saving ? '作成中...' : '作成する'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function AdversaryEmulationPage() {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<'plans' | 'results'>('plans')
  const [selectedPlan, setSelectedPlan] = useState<EmulationPlan | null>(null)
  const [selectedResult, setSelectedResult] = useState<ExecutionResult | null>(null)
  const [showNewExec, setShowNewExec] = useState(false)
  const [showNewPlan, setShowNewPlan] = useState(false)
  const [toast, setToast] = useState('')

  const { data: plansData } = useQuery<EmulationPlan[]>({
    queryKey: ['adversary-emulation-plans'],
    queryFn: () => apiFetch('/api/v1/admin/adversary-emulation'),
  })

  const { data: resultsData } = useQuery<ExecutionResult[]>({
    queryKey: ['adversary-emulation-results'],
    queryFn: () => apiFetch('/api/v1/admin/adversary-emulation/executions'),
  })

  const plans = plansData ?? []
  const results = resultsData ?? []

  const createPlan = useMutation({
    mutationFn: (data: Partial<EmulationPlan>) =>
      apiFetch('/api/v1/admin/adversary-emulation', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['adversary-emulation-plans'] })
      setShowNewPlan(false)
      setToast('計画を作成しました')
    },
    onError: () => setToast('計画の作成に失敗しました'),
  })

  const createExec = useMutation({
    mutationFn: (data: Partial<ExecutionResult>) =>
      apiFetch('/api/v1/admin/adversary-emulation/executions', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['adversary-emulation-results'] })
      setShowNewExec(false)
      setToast('実行結果を記録しました')
    },
    onError: () => setToast('実行結果の記録に失敗しました'),
  })

  const handleNewExec = (data: Partial<ExecutionResult>) => createExec.mutate(data)
  const handleNewPlan = (data: Partial<EmulationPlan>) => createPlan.mutate(data)

  const avgDetectionRate = results.length > 0
    ? (results.reduce((s, r) => s + r.detection_rate, 0) / results.length).toFixed(1)
    : '0'

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <PageDataUnavailable />
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <Target className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">敵対的エミュレーション計画</h1>
              <p className="text-[#7d92b0] text-sm">Adversary Emulation – MITRE ATT&CK ベースの検知能力評価</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {tab === 'results' && (
              <button onClick={() => setShowNewExec(true)}
                className="flex items-center gap-2 px-4 py-2 border border-[#1e2d42] rounded-lg text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 text-sm transition-colors">
                <Play className="w-4 h-4" /> 新規実行記録
              </button>
            )}
            {tab === 'plans' && (
              <button onClick={() => setShowNewPlan(true)}
                className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] rounded-lg text-white text-sm font-medium hover:bg-[#e8002d]/80 transition-colors">
                <Plus className="w-4 h-4" /> 計画を作成
              </button>
            )}
          </div>
        </div>

        {/* Info Card */}
        <div className="bg-blue-900/10 border border-blue-500/20 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-white font-medium text-sm">敵対的エミュレーションとは</p>
              <p className="text-[#7d92b0] text-sm mt-1">
                敵対的エミュレーションは、実際の脅威アクター (APT) の戦術・技術・手順 (TTPs) を安全に再現し、
                組織の検知・対応能力を評価するプロセスです。
                MITRE ATT&CK フレームワークに基づいてシミュレーションを構造化し、
                セキュリティコントロールのギャップを特定します。
                すべての手順は事前承認済みシステム上でシミュレーションとして実施されます。
              </p>
              <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-blue-400 text-xs mt-1 hover:underline">
                MITRE ATT&CK 参照 <ChevronRight className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: '計画数', value: plans.length, icon: FileText, color: 'text-blue-400' },
            { label: '実行済み', value: results.length, icon: Play, color: 'text-green-400' },
            { label: '平均検知率', value: `${avgDetectionRate}%`, icon: BarChart3, color: Number(avgDetectionRate) >= 75 ? 'text-green-400' : 'text-yellow-400' },
            { label: '総テクニック数', value: plans.reduce((s, p) => s + p.technique_count, 0), icon: Target, color: 'text-[#e8002d]' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#7d92b0] text-xs">{label}</p>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex border-b border-[#1e2d42]">
          {([['plans', 'エミュレーション計画'], ['results', '実行結果']] as const).map(([key, label]) => (
            <button key={key} onClick={() => setTab(key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === key ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'
              }`}>{label}</button>
          ))}
        </div>

        {/* Plans Tab */}
        {tab === 'plans' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-[#070d19] border-b border-[#1e2d42]">
                  <tr>
                    {['計画名', 'ベース脅威アクター', 'スコープ', 'ステータス', '作成者', '最終実行', 'テクニック数', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {plans.map(plan => {
                    const statusStyle = PLAN_STATUS_STYLES[plan.status]
                    return (
                      <tr key={plan.id} className="border-t border-[#1e2d42] hover:bg-[#070d19]/50">
                        <td className="px-4 py-3">
                          <button onClick={() => setSelectedPlan(plan)} className="text-white font-medium hover:text-[#e8002d] transition-colors text-left">
                            {plan.plan_name}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 bg-[#e8002d]/10 border border-[#e8002d]/20 rounded-sm text-xs text-[#e8002d] font-bold">{plan.threat_actor_based_on}</span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[160px] truncate">{plan.scope}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${statusStyle.bg} ${statusStyle.text}`}>{statusStyle.label}</span>
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{displayUser(plan.created_by)}</td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{fmt(plan.last_executed)}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            <Target className="w-3.5 h-3.5 text-[#e8002d]" />
                            <span className="text-white font-semibold">{plan.technique_count}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <button onClick={() => setSelectedPlan(plan)}
                            className="flex items-center gap-1 px-2 py-1 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 text-xs transition-colors">
                            <Eye className="w-3 h-3" /> 詳細
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Results Tab */}
        {tab === 'results' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-[#070d19] border-b border-[#1e2d42]">
                  <tr>
                    {['計画名', '実行日時', '実行者', '所要時間', 'フェーズ', '検知', '見逃し', '検知率', '詳細'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {results.map(result => (
                    <tr key={result.id} className="border-t border-[#1e2d42] hover:bg-[#070d19]/50">
                      <td className="px-4 py-3 text-white font-medium">{result.plan_name}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{fmt(result.executed_at)}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{result.executed_by?.split('@')[0]}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{result.duration_minutes}分</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{result.phases_completed}/{result.phases_total}</td>
                      <td className="px-4 py-3 text-green-400 font-semibold">{result.detections_count}</td>
                      <td className="px-4 py-3 text-red-400 font-semibold">{result.missed_detections_count}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-[#1e2d42] rounded-full h-2">
                            <div className={`h-2 rounded-full ${result.detection_rate >= 80 ? 'bg-green-500' : result.detection_rate >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
                              style={{ width: `${result.detection_rate}%` }} />
                          </div>
                          <span className={`text-xs font-bold ${result.detection_rate >= 80 ? 'text-green-400' : result.detection_rate >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>
                            {result.detection_rate.toFixed(1)}%
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedResult(result)}
                          className="flex items-center gap-1 px-2 py-1 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 text-xs transition-colors">
                          <Eye className="w-3 h-3" /> 詳細
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

      {/* Modals */}
      {selectedPlan && <PlanDetail plan={selectedPlan} onClose={() => setSelectedPlan(null)} />}
      {selectedResult && <ExecutionDetail result={selectedResult} onClose={() => setSelectedResult(null)} />}
      {showNewExec && <NewExecutionModal plans={plans} onClose={() => setShowNewExec(false)} onSave={handleNewExec} />}
      {showNewPlan && <NewPlanModal onClose={() => setShowNewPlan(false)} onSave={handleNewPlan} saving={createPlan.isPending} />}

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0d1220] border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400" />
          <span className="text-white text-sm">{toast}</span>
          <button onClick={() => setToast('')} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
