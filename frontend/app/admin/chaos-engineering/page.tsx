'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Zap, X, ChevronDown, ChevronUp, Play, Calendar, Info,
  AlertTriangle, CheckCircle, Clock, Shield, User, RotateCcw,
  ClipboardList, Filter, Eye, ThumbsUp, ThumbsDown,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type ExperimentCategory = 'network' | 'endpoint' | 'auth' | 'data' | 'detection'
type SeverityImpact = 'low' | 'medium' | 'high' | 'critical'
type TargetType = 'agent' | 'network' | 'auth_service' | 'logging'
type SafetyLevel = 'safe' | 'moderate_risk' | 'high_risk'
type RunResult = 'hypothesis_confirmed' | 'hypothesis_rejected' | 'inconclusive' | 'aborted'
type ApprovalStatus = 'pending' | 'approved' | 'rejected'

interface Experiment {
  id: string
  name: string
  category: ExperimentCategory
  description: string
  severity_impact: SeverityImpact
  target_type: TargetType
  estimated_duration_min: number
  is_safe: SafetyLevel
  hypothesis: string
  blast_radius: string
  rollback_procedure: string[]
  steady_state_metrics: string[]
  execution_steps: string[]
}

interface ExperimentRun {
  id: string
  experiment_id: string
  experiment_name: string
  executed_by: string
  started_at: string
  duration_min: number
  scope: string
  result: RunResult
  findings_summary: string
  hypothesis_actual: string
  metrics_before: Record<string, number>
  metrics_after: Record<string, number>
  rollback_taken: boolean
  lessons_learned: string
}

interface ApprovalRequest {
  id: string
  experiment_id: string
  experiment_name: string
  requested_by: string
  justification: string
  approvers: string[]
  status: ApprovalStatus
  requested_at: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<ExperimentCategory, { label: string; color: string }> = {
  network:   { label: 'ネットワーク', color: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
  endpoint:  { label: 'エンドポイント', color: 'bg-purple-500/10 text-purple-400 border-purple-500/30' },
  auth:      { label: '認証', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  data:      { label: 'データ', color: 'bg-green-500/10 text-green-400 border-green-500/30' },
  detection: { label: '検知', color: 'bg-red-500/10 text-red-400 border-red-500/30' },
}

const SEVERITY_CONFIG: Record<SeverityImpact, { label: string; color: string }> = {
  low:      { label: '低', color: 'bg-green-500/10 text-green-400 border-green-500/30' },
  medium:   { label: '中', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  high:     { label: '高', color: 'bg-orange-500/10 text-orange-400 border-orange-500/30' },
  critical: { label: '重大', color: 'bg-red-500/10 text-red-400 border-red-500/30' },
}

const SAFETY_CONFIG: Record<SafetyLevel, { label: string; color: string }> = {
  safe:          { label: '安全', color: 'bg-green-500/10 text-green-400 border-green-500/30' },
  moderate_risk: { label: '中程度リスク', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  high_risk:     { label: '高リスク', color: 'bg-red-500/10 text-red-400 border-red-500/30' },
}

const RESULT_CONFIG: Record<RunResult, { label: string; color: string }> = {
  hypothesis_confirmed: { label: '仮説確認', color: 'bg-green-500/10 text-green-400 border-green-500/30' },
  hypothesis_rejected:  { label: '仮説否定', color: 'bg-red-500/10 text-red-400 border-red-500/30' },
  inconclusive:         { label: '不確定', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
  aborted:              { label: '中断', color: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
}

function fmtDate(s: string) {
  return new Date(s).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function Badge({ cfg }: { cfg: { label: string; color: string } }) {
  return <span className={`text-xs px-2 py-0.5 rounded-sm border font-medium ${cfg.color}`}>{cfg.label}</span>
}

const SAFETY_RULES: { id: string; rule: string; active: boolean }[] = [
  { id: 'sr-1', rule: '本番データベースへの直接書き込みを禁止', active: true },
  { id: 'sr-2', rule: '実験中のCPU使用率が80%を超えた場合は自動停止', active: true },
  { id: 'sr-3', rule: 'エージェント台数が10%未満になった場合は中断', active: true },
  { id: 'sr-4', rule: '顧客データへのアクセスを含む実験は事前承認必須', active: true },
  { id: 'sr-5', rule: 'ネットワーク分離実験は業務時間外のみ許可', active: false },
]

// ─── Modals ───────────────────────────────────────────────────────────────────

function ExperimentDetailModal({ exp, onClose, onRunRequest, onApprovalRequest }: {
  exp: Experiment
  onClose: () => void
  onRunRequest: () => void
  onApprovalRequest: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42] shrink-0">
          <div className="flex items-center gap-3">
            <Zap className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">{exp.name}</h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto px-6 py-5 space-y-5 flex-1">
          <div className="flex flex-wrap gap-2">
            <Badge cfg={CATEGORY_CONFIG[exp.category]} />
            <Badge cfg={SEVERITY_CONFIG[exp.severity_impact]} />
            <Badge cfg={SAFETY_CONFIG[exp.is_safe]} />
            <span className="text-xs px-2 py-0.5 rounded-sm border border-[#1e2d42] text-[#7d92b0]">目安 {exp.estimated_duration_min}分</span>
          </div>

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
            <p className="text-xs text-[#7d92b0] mb-1">仮説</p>
            <p className="text-white text-sm">{exp.hypothesis}</p>
          </div>

          <div className="bg-[#070d19] border border-amber-500/20 rounded-lg p-4">
            <p className="text-xs text-amber-400 mb-1">ブラスト半径（影響範囲）</p>
            <p className="text-[#e2e8f4] text-sm">{exp.blast_radius}</p>
          </div>

          <div>
            <p className="text-xs text-[#7d92b0] mb-2">ステディステートメトリクス</p>
            <ul className="space-y-1">
              {exp.steady_state_metrics.map((m, i) => (
                <li key={i} className="flex items-center gap-2 text-sm text-[#e2e8f4]">
                  <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                  {m}
                </li>
              ))}
            </ul>
          </div>

          <div>
            <p className="text-xs text-[#7d92b0] mb-2">実行ステップ</p>
            <ol className="space-y-1.5">
              {exp.execution_steps.map((s, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-[#e2e8f4]">
                  <span className="w-5 h-5 rounded-full bg-[#1e2d42] text-[#7d92b0] text-xs flex items-center justify-center shrink-0 mt-0.5">{i + 1}</span>
                  {s}
                </li>
              ))}
            </ol>
          </div>

          <div>
            <p className="text-xs text-[#7d92b0] mb-2">ロールバック手順</p>
            <ol className="space-y-1.5">
              {exp.rollback_procedure.map((s, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-[#e2e8f4]">
                  <RotateCcw className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                  {s}
                </li>
              ))}
            </ol>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42] flex items-center justify-end gap-3 shrink-0">
          <button onClick={onApprovalRequest}
            className="px-4 py-2 rounded-lg border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 text-sm transition-colors">
            承認を申請
          </button>
          <button onClick={onRunRequest}
            className="px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors flex items-center gap-2">
            <Play className="w-4 h-4" /> 実行
          </button>
        </div>
      </div>
    </div>
  )
}

function ApprovalRequestModal({ exp, onClose, onSubmit }: {
  exp: Experiment
  onClose: () => void
  onSubmit: (justification: string, approvers: string[]) => void
}) {
  const [justification, setJustification] = useState('')
  const [approvers, setApprovers] = useState<string[]>(['tanaka@example.com'])
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">承認申請: {exp.name}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">実施理由・正当化</label>
            <textarea value={justification} onChange={e => setJustification(e.target.value)} rows={4}
              placeholder="この実験を実施する理由と期待される成果を記述してください..."
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 resize-none" />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">承認者</label>
            <select multiple value={approvers} onChange={e => setApprovers(Array.from(e.target.selectedOptions, o => o.value))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 h-28">
              <option value="tanaka@example.com">田中 (Security Lead)</option>
              <option value="manager@example.com">山田 (Manager)</option>
              <option value="sato@example.com">佐藤 (SOC Lead)</option>
              <option value="ciso@example.com">CISO</option>
            </select>
            <p className="text-xs text-[#3d5068] mt-1">Ctrl+クリックで複数選択</p>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42] flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSubmit(justification, approvers)} disabled={!justification.trim() || approvers.length === 0}
            className="px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors disabled:opacity-50">
            申請を送信
          </button>
        </div>
      </div>
    </div>
  )
}

function RunModal({ exp, onClose, onRun }: {
  exp: Experiment
  onClose: () => void
  onRun: (scope: string, now: boolean) => void
}) {
  const [scope, setScope] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [runNow, setRunNow] = useState(true)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">実験実行: {exp.name}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div className="flex items-start gap-3 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-amber-300">この実験は本番環境に影響を与える可能性があります。実行前に影響範囲を確認してください。</p>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">ターゲットスコープ</label>
            <input value={scope} onChange={e => setScope(e.target.value)}
              placeholder="例: セグメントA (192.168.1.0/24) または エンドポイントID"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
          </div>
          <div className="flex gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="radio" checked={runNow} onChange={() => setRunNow(true)} className="accent-[#e8002d]" />
              <span className="text-sm text-[#e2e8f4]">今すぐ実行</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="radio" checked={!runNow} onChange={() => setRunNow(false)} className="accent-[#e8002d]" />
              <span className="text-sm text-[#e2e8f4]">スケジュール実行</span>
            </label>
          </div>
          <label className="flex items-start gap-3 cursor-pointer">
            <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} className="mt-0.5 accent-[#e8002d]" />
            <span className="text-sm text-[#e2e8f4]">本番環境への影響を理解しています。ロールバック手順を確認済みです。</span>
          </label>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42] flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onRun(scope, runNow)} disabled={!scope.trim() || !confirmed}
            className="px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors disabled:opacity-50 flex items-center gap-2">
            <Play className="w-4 h-4" /> {runNow ? '今すぐ実行' : 'スケジュール'}
          </button>
        </div>
      </div>
    </div>
  )
}

function RunDetailModal({ run, onClose }: { run: ExperimentRun; onClose: () => void }) {
  const [lessons, setLessons] = useState(run.lessons_learned)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42] shrink-0">
          <div>
            <h2 className="text-white font-semibold">{run.experiment_name}</h2>
            <p className="text-xs text-[#7d92b0] mt-0.5">{fmtDate(run.started_at)} — {run.executed_by}</p>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto px-6 py-5 space-y-5 flex-1">
          <div className="flex items-center gap-3">
            <Badge cfg={RESULT_CONFIG[run.result]} />
            {run.rollback_taken && <span className="text-xs px-2 py-0.5 rounded-sm border border-blue-500/30 bg-blue-500/10 text-blue-400">ロールバック実施</span>}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
              <p className="text-xs text-[#7d92b0] mb-2">メトリクス（実験前）</p>
              {Object.entries(run.metrics_before).map(([k, v]) => (
                <div key={k} className="flex justify-between text-sm py-0.5">
                  <span className="text-[#7d92b0] text-xs">{k}</span>
                  <span className="text-white font-mono">{v}</span>
                </div>
              ))}
            </div>
            <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
              <p className="text-xs text-[#7d92b0] mb-2">メトリクス（実験後）</p>
              {Object.entries(run.metrics_after).map(([k, v]) => (
                <div key={k} className="flex justify-between text-sm py-0.5">
                  <span className="text-[#7d92b0] text-xs">{k}</span>
                  <span className="text-white font-mono">{v}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
            <p className="text-xs text-[#7d92b0] mb-1">実際の結果</p>
            <p className="text-[#e2e8f4] text-sm">{run.hypothesis_actual}</p>
          </div>

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
            <p className="text-xs text-[#7d92b0] mb-1">主な発見</p>
            <p className="text-[#e2e8f4] text-sm">{run.findings_summary}</p>
          </div>

          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">教訓・改善点</label>
            <textarea value={lessons} onChange={e => setLessons(e.target.value)} rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 resize-none" />
          </div>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42] flex justify-end shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ChaosEngineeringPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'experiments' | 'history'>('experiments')
  const [selectedExp, setSelectedExp] = useState<Experiment | null>(null)
  const [runExp, setRunExp] = useState<Experiment | null>(null)
  const [approvalExp, setApprovalExp] = useState<Experiment | null>(null)
  const [selectedRun, setSelectedRun] = useState<ExperimentRun | null>(null)
  const [safetyOpen, setSafetyOpen] = useState(false)
  const [filterCategory, setFilterCategory] = useState<string>('all')
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  const { data: experiments = [] } = useQuery<Experiment[]>({
    queryKey: ['chaos-experiments'],
    queryFn: () => apiFetch('/api/v1/admin/chaos/experiments'),
  })

  const { data: runs = [] } = useQuery<ExperimentRun[]>({
    queryKey: ['chaos-runs'],
    queryFn: () => apiFetch('/api/v1/admin/chaos/runs'),
  })

  const { data: approvals = [] } = useQuery<ApprovalRequest[]>({
    queryKey: ['chaos-approvals'],
    queryFn: () => apiFetch('/api/v1/admin/chaos/approvals'),
  })

  const runMutation = useMutation({
    mutationFn: (d: { experiment_id: string; scope: string; run_now: boolean }) =>
      apiFetch('/api/v1/admin/chaos/runs', { method: 'POST', body: JSON.stringify(d) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['chaos-runs'] }); showToast('実験を開始しました') },
    onError: () => showToast('実験の開始に失敗しました'),
  })

  const approvalMutation = useMutation({
    mutationFn: (d: { experiment_id: string; justification: string; approvers: string[] }) =>
      apiFetch('/api/v1/admin/chaos/approvals', { method: 'POST', body: JSON.stringify(d) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['chaos-approvals'] }); showToast('承認申請を送信しました') },
    onError: () => showToast('承認申請の送信に失敗しました'),
  })

  const approveRejectMutation = useMutation({
    mutationFn: (d: { id: string; action: 'approve' | 'reject' }) =>
      apiFetch(`/api/v1/admin/chaos/approvals/${d.id}`, { method: 'PUT', body: JSON.stringify({ status: d.action === 'approve' ? 'approved' : 'rejected' }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['chaos-approvals'] }); showToast('承認状態を更新しました') },
    onError: () => showToast('承認状態の更新に失敗しました'),
  })

  const filteredExps = filterCategory === 'all' ? experiments : experiments.filter(e => e.category === filterCategory)

  // Stats for history tab
  const confirmedCount = runs.filter(r => r.result === 'hypothesis_confirmed').length
  const successRate = runs.length > 0 ? Math.round((confirmedCount / runs.length) * 100) : 0
  const avgVulnFound = 1.8 // mock average

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-5">
      <PageDataUnavailable />
      {/* Toast */}
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-[#0d1220] border border-green-500/40 text-green-400 px-4 py-3 rounded-lg shadow-2xl text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" />
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
            <Zap className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">セキュリティカオスエンジニアリング</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">実験設計・実行・知見管理プラットフォーム</p>
          </div>
        </div>
      </div>

      {/* Warning Banner */}
      <div className="flex items-start gap-3 p-4 rounded-lg bg-amber-500/5 border border-amber-500/30">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <p className="text-sm text-amber-300">
          カオスエンジニアリング実験は本番環境に影響を与える可能性があります。必ず承認を取得してください。
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {([['experiments', '実験管理'], ['history', '実行履歴']] as const).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)}
            className={`px-5 py-2 rounded-md text-sm font-medium transition-all ${tab === k ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {l}
          </button>
        ))}
      </div>

      {/* ── 実験管理 tab ── */}
      {tab === 'experiments' && (
        <div className="space-y-6">
          {/* Filter */}
          <div className="flex items-center gap-3">
            <Filter className="w-4 h-4 text-[#7d92b0]" />
            <div className="flex gap-2">
              {(['all', 'network', 'endpoint', 'auth', 'data', 'detection'] as const).map(c => (
                <button key={c} onClick={() => setFilterCategory(c)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-all border ${filterCategory === c ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-[#e8002d]' : 'border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {c === 'all' ? '全て' : CATEGORY_CONFIG[c].label}
                </button>
              ))}
            </div>
          </div>

          {/* Experiment Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {filteredExps.map(exp => (
              <div key={exp.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 hover:border-[#2a3f5e] transition-colors">
                <div className="flex items-start justify-between mb-3">
                  <h3 className="text-white font-semibold text-sm leading-snug flex-1 pr-2">{exp.name}</h3>
                  <Badge cfg={SAFETY_CONFIG[exp.is_safe]} />
                </div>
                <p className="text-xs text-[#7d92b0] mb-4 line-clamp-2">{exp.description}</p>
                <div className="flex flex-wrap gap-1.5 mb-4">
                  <Badge cfg={CATEGORY_CONFIG[exp.category]} />
                  <Badge cfg={SEVERITY_CONFIG[exp.severity_impact]} />
                  <span className="text-xs px-2 py-0.5 rounded-sm border border-[#1e2d42] text-[#7d92b0]">{exp.target_type}</span>
                  <span className="text-xs px-2 py-0.5 rounded-sm border border-[#1e2d42] text-[#7d92b0] flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {exp.estimated_duration_min}分
                  </span>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => setRunExp(exp)}
                    className="flex-1 py-1.5 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 text-[#e8002d] hover:bg-[#e8002d]/30 text-xs font-medium transition-colors flex items-center justify-center gap-1.5">
                    <Play className="w-3.5 h-3.5" /> 実行
                  </button>
                  <button onClick={() => setApprovalExp(exp)}
                    className="flex-1 py-1.5 rounded-lg border border-amber-500/30 text-amber-400 hover:bg-amber-500/10 text-xs font-medium transition-colors flex items-center justify-center gap-1.5">
                    <Calendar className="w-3.5 h-3.5" /> スケジュール
                  </button>
                  <button onClick={() => setSelectedExp(exp)}
                    className="py-1.5 px-3 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#2a3f5e] text-xs transition-colors">
                    <Info className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Approval Queue */}
          {approvals.length > 0 && (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-white font-semibold mb-4 flex items-center gap-2">
                <ClipboardList className="w-4 h-4 text-[#e8002d]" />
                承認待ちキュー
                <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">{approvals.filter(a => a.status === 'pending').length}</span>
              </h2>
              <div className="space-y-3">
                {approvals.filter(a => a.status === 'pending').map(apr => (
                  <div key={apr.id} className="flex items-start justify-between p-4 bg-[#070d19] border border-[#1e2d42] rounded-lg">
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-medium text-sm">{apr.experiment_name}</p>
                      <p className="text-xs text-[#7d92b0] mt-1 flex items-center gap-1.5">
                        <User className="w-3 h-3" /> {apr.requested_by} — {fmtDate(apr.requested_at)}
                      </p>
                      <p className="text-xs text-[#e2e8f4] mt-2 line-clamp-2">{apr.justification}</p>
                    </div>
                    <div className="flex gap-2 ml-4 shrink-0">
                      <button onClick={() => approveRejectMutation.mutate({ id: apr.id, action: 'approve' })}
                        className="p-2 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-colors">
                        <ThumbsUp className="w-4 h-4" />
                      </button>
                      <button onClick={() => approveRejectMutation.mutate({ id: apr.id, action: 'reject' })}
                        className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 transition-colors">
                        <ThumbsDown className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Safety Rules */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <button onClick={() => setSafetyOpen(v => !v)}
              className="w-full flex items-center justify-between text-white font-semibold">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-green-400" />
                自動安全チェックルール ({SAFETY_RULES.filter(r => r.active).length}/{SAFETY_RULES.length} 有効)
              </div>
              {safetyOpen ? <ChevronUp className="w-4 h-4 text-[#7d92b0]" /> : <ChevronDown className="w-4 h-4 text-[#7d92b0]" />}
            </button>
            {safetyOpen && (
              <div className="mt-4 space-y-2">
                {SAFETY_RULES.map(rule => (
                  <div key={rule.id} className="flex items-center gap-3 p-3 bg-[#070d19] rounded-lg border border-[#1e2d42]">
                    <div className={`w-2 h-2 rounded-full shrink-0 ${rule.active ? 'bg-green-400' : 'bg-[#3d5068]'}`} />
                    <span className={`text-sm flex-1 ${rule.active ? 'text-[#e2e8f4]' : 'text-[#3d5068] line-through'}`}>{rule.rule}</span>
                    <span className={`text-xs ${rule.active ? 'text-green-400' : 'text-[#3d5068]'}`}>{rule.active ? '有効' : '無効'}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── 実行履歴 tab ── */}
      {tab === 'history' && (
        <div className="space-y-6">
          {/* Metrics Dashboard */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <p className="text-xs text-[#7d92b0] mb-1">仮説確認率</p>
              <p className="text-3xl font-bold text-white">{successRate}<span className="text-lg text-[#7d92b0]">%</span></p>
              <p className="text-xs text-[#7d92b0] mt-1">全{runs.length}回の実験</p>
            </div>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <p className="text-xs text-[#7d92b0] mb-1">平均発見数/実験</p>
              <p className="text-3xl font-bold text-amber-400">{avgVulnFound}</p>
              <p className="text-xs text-[#7d92b0] mt-1">新規脆弱性・改善点</p>
            </div>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <p className="text-xs text-[#7d92b0] mb-1">ロールバック率</p>
              <p className="text-3xl font-bold text-blue-400">
                {Math.round((runs.filter(r => r.rollback_taken).length / runs.length) * 100)}
                <span className="text-lg text-[#7d92b0]">%</span>
              </p>
              <p className="text-xs text-[#7d92b0] mt-1">{runs.filter(r => r.rollback_taken).length}回のロールバック実施</p>
            </div>
          </div>

          {/* Execution Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-white font-semibold">実行履歴</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['実験名', '実行者', '実施日時', '所要時間', 'スコープ', '結果', '主な発見'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                    ))}
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody>
                  {runs.map(run => (
                    <tr key={run.id} className="border-b border-[#1e2d42]/50 hover:bg-[#070d19] transition-colors">
                      <td className="px-4 py-3 text-white font-medium text-xs whitespace-nowrap">{run.experiment_name}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{run.executed_by.split('@')[0]}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{fmtDate(run.started_at)}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{run.duration_min}分</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[120px] truncate">{run.scope}</td>
                      <td className="px-4 py-3"><Badge cfg={RESULT_CONFIG[run.result]} /></td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[200px] truncate">{run.findings_summary}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedRun(run)}
                          className="p-1.5 rounded-sm border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {selectedExp && (
        <ExperimentDetailModal
          exp={selectedExp}
          onClose={() => setSelectedExp(null)}
          onRunRequest={() => { setSelectedExp(null); setRunExp(selectedExp) }}
          onApprovalRequest={() => { setSelectedExp(null); setApprovalExp(selectedExp) }}
        />
      )}
      {runExp && (
        <RunModal
          exp={runExp}
          onClose={() => setRunExp(null)}
          onRun={(scope, now) => {
            runMutation.mutate({ experiment_id: runExp.id, scope, run_now: now })
            setRunExp(null)
          }}
        />
      )}
      {approvalExp && (
        <ApprovalRequestModal
          exp={approvalExp}
          onClose={() => setApprovalExp(null)}
          onSubmit={(justification, approvers) => {
            approvalMutation.mutate({ experiment_id: approvalExp.id, justification, approvers })
            setApprovalExp(null)
          }}
        />
      )}
      {selectedRun && <RunDetailModal run={selectedRun} onClose={() => setSelectedRun(null)} />}
    </div>
  )
}
