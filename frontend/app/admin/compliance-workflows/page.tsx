'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  GitBranch, Plus, Play, ChevronRight, X, Check, AlertTriangle,
  Clock, RefreshCw, ChevronUp, ChevronDown, Trash2, GripVertical,
  CheckCircle, XCircle, Loader2, RotateCcw, Eye
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

type Framework = 'ISO27001' | 'SOC2' | 'PCI-DSS' | 'HIPAA' | 'NIST' | 'GDPR'
type WorkflowType = 'audit' | 'incident_response' | 'change_management' | 'access_review' | 'risk_assessment'
type TriggerType = 'manual' | 'scheduled' | 'event_driven' | 'threshold'
type RunStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled'
type StageType = 'review' | 'approval' | 'evidence_collection' | 'notification' | 'remediation'

interface Stage {
  id: string
  name: string
  type: StageType
  assignee: string
  due_days: number
}

interface Workflow {
  id: string
  name: string
  framework: Framework
  workflow_type: WorkflowType
  trigger_type: TriggerType
  run_count: number
  active: boolean
  stages: Stage[]
  created_at: string
}

interface WorkflowRun {
  id: string
  workflow_id: string
  workflow_name: string
  framework: Framework
  status: RunStatus
  current_stage: number
  total_stages: number
  due_date: string
  started_at: string
  stage_results: StageResult[]
}

interface StageResult {
  stage_name: string
  status: 'pending' | 'completed' | 'failed' | 'skipped'
  completed_at?: string
  notes?: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const fwColors: Record<Framework, string> = {
  'ISO27001': 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  'SOC2': 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  'PCI-DSS': 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  'HIPAA': 'bg-green-500/20 text-green-300 border-green-500/30',
  'NIST': 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  'GDPR': 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
}

const runStatusColors: Record<RunStatus, string> = {
  pending: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  in_progress: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  completed: 'bg-green-500/20 text-green-300 border-green-500/30',
  failed: 'bg-red-500/20 text-red-300 border-red-500/30',
  cancelled: 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]',
}

const runStatusLabel: Record<RunStatus, string> = {
  pending: '待機中', in_progress: '進行中', completed: '完了', failed: '失敗', cancelled: 'キャンセル',
}

const stageStatusIcon = (s: StageResult['status']) => {
  if (s === 'completed') return <CheckCircle className="w-4 h-4 text-green-400" />
  if (s === 'failed') return <XCircle className="w-4 h-4 text-red-400" />
  if (s === 'skipped') return <RotateCcw className="w-4 h-4 text-[#7d92b0]" />
  return <Clock className="w-4 h-4 text-yellow-400" />
}

function Badge({ text, cls }: { text: string; cls: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[11px] font-medium border ${cls}`}>
      {text}
    </span>
  )
}

// ─── Stage Builder Row ────────────────────────────────────────────────────────

function StageRow({
  stage, idx, total,
  onChange, onRemove, onMoveUp, onMoveDown,
}: {
  stage: Stage; idx: number; total: number
  onChange: (s: Stage) => void
  onRemove: () => void
  onMoveUp: () => void
  onMoveDown: () => void
}) {
  return (
    <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-sm p-2">
      <GripVertical className="w-4 h-4 text-[#3d5068] shrink-0" />
      <span className="text-[#7d92b0] text-xs w-5">{idx + 1}.</span>
      <input
        className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-white focus:outline-hidden focus:border-[#e8002d]/50"
        placeholder="ステージ名"
        value={stage.name}
        onChange={e => onChange({ ...stage, name: e.target.value })}
      />
      <select
        className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-white focus:outline-hidden"
        value={stage.type}
        onChange={e => onChange({ ...stage, type: e.target.value as StageType })}
      >
        <option value="review">レビュー</option>
        <option value="approval">承認</option>
        <option value="evidence_collection">証拠収集</option>
        <option value="notification">通知</option>
        <option value="remediation">改善</option>
      </select>
      <input
        className="w-32 bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-white focus:outline-hidden"
        placeholder="担当者メール"
        value={stage.assignee}
        onChange={e => onChange({ ...stage, assignee: e.target.value })}
      />
      <input
        type="number" min={1}
        className="w-16 bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-white focus:outline-hidden"
        placeholder="日数"
        value={stage.due_days}
        onChange={e => onChange({ ...stage, due_days: parseInt(e.target.value) || 1 })}
      />
      <div className="flex gap-1">
        <button onClick={onMoveUp} disabled={idx === 0} className="text-[#7d92b0] hover:text-white disabled:opacity-30">
          <ChevronUp className="w-3.5 h-3.5" />
        </button>
        <button onClick={onMoveDown} disabled={idx === total - 1} className="text-[#7d92b0] hover:text-white disabled:opacity-30">
          <ChevronDown className="w-3.5 h-3.5" />
        </button>
        <button onClick={onRemove} className="text-[#7d92b0] hover:text-[#e8002d]">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

// ─── Modal ────────────────────────────────────────────────────────────────────

function WorkflowModal({ initial, onClose, onSave }: {
  initial?: Workflow | null
  onClose: () => void
  onSave: (w: Partial<Workflow>) => void
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [framework, setFramework] = useState<Framework>(initial?.framework ?? 'ISO27001')
  const [type, setType] = useState<WorkflowType>(initial?.workflow_type ?? 'audit')
  const [trigger, setTrigger] = useState<TriggerType>(initial?.trigger_type ?? 'manual')
  const [stages, setStages] = useState<Stage[]>(initial?.stages ?? [])

  const addStage = () => setStages(prev => [
    ...prev,
    { id: `s-${Date.now()}`, name: '', type: 'review', assignee: '', due_days: 7 },
  ])

  const updateStage = (i: number, s: Stage) => setStages(prev => prev.map((x, idx) => idx === i ? s : x))
  const removeStage = (i: number) => setStages(prev => prev.filter((_, idx) => idx !== i))
  const moveUp = (i: number) => {
    if (i === 0) return
    setStages(prev => { const a = [...prev]; [a[i - 1], a[i]] = [a[i], a[i - 1]]; return a })
  }
  const moveDown = (i: number) => {
    setStages(prev => {
      if (i === prev.length - 1) return prev
      const a = [...prev]; [a[i], a[i + 1]] = [a[i + 1], a[i]]; return a
    })
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">
            {initial ? 'ワークフローを編集' : '新規ワークフロー作成'}
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">ワークフロー名</label>
              <input
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
                value={name} onChange={e => setName(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">フレームワーク</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden"
                value={framework} onChange={e => setFramework(e.target.value as Framework)}
              >
                {(['ISO27001','SOC2','PCI-DSS','HIPAA','NIST','GDPR'] as Framework[]).map(f => (
                  <option key={f} value={f}>{f}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">ワークフロータイプ</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden"
                value={type} onChange={e => setType(e.target.value as WorkflowType)}
              >
                <option value="audit">監査</option>
                <option value="incident_response">インシデント対応</option>
                <option value="change_management">変更管理</option>
                <option value="access_review">アクセスレビュー</option>
                <option value="risk_assessment">リスクアセスメント</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">トリガータイプ</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden"
                value={trigger} onChange={e => setTrigger(e.target.value as TriggerType)}
              >
                <option value="manual">手動</option>
                <option value="scheduled">スケジュール</option>
                <option value="event_driven">イベント駆動</option>
                <option value="threshold">閾値</option>
              </select>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-[#7d92b0]">ステージ ({stages.length})</label>
              <button
                onClick={addStage}
                className="flex items-center gap-1 text-xs text-[#e8002d] hover:text-white transition-colors"
              >
                <Plus className="w-3.5 h-3.5" /> ステージ追加
              </button>
            </div>
            <div className="space-y-2">
              {stages.map((s, i) => (
                <StageRow
                  key={s.id} stage={s} idx={i} total={stages.length}
                  onChange={ns => updateStage(i, ns)}
                  onRemove={() => removeStage(i)}
                  onMoveUp={() => moveUp(i)}
                  onMoveDown={() => moveDown(i)}
                />
              ))}
              {stages.length === 0 && (
                <p className="text-center text-[#7d92b0] text-xs py-4">ステージを追加してください</p>
              )}
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
          <button
            onClick={() => onSave({ name, framework, workflow_type: type, trigger_type: trigger, stages })}
            className="px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded-lg transition-colors"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Run Detail Modal ─────────────────────────────────────────────────────────

function RunDetailModal({ run, onClose }: { run: WorkflowRun; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div>
            <h3 className="text-white font-semibold">{run.workflow_name}</h3>
            <p className="text-xs text-[#7d92b0]">実行ID: {run.id}</p>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          {/* Stepper */}
          <div className="space-y-3">
            {run.stage_results.map((sr, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className="flex flex-col items-center">
                  <div className="mt-0.5">{stageStatusIcon(sr.status)}</div>
                  {i < run.stage_results.length - 1 && (
                    <div className="w-px h-6 bg-[#1e2d42] mt-1" />
                  )}
                </div>
                <div className="flex-1 pb-2">
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-white font-medium">{sr.stage_name}</p>
                    {sr.completed_at && (
                      <span className="text-xs text-[#7d92b0]">
                        {new Date(sr.completed_at).toLocaleDateString('ja-JP')}
                      </span>
                    )}
                  </div>
                  {sr.notes && (
                    <p className="text-xs text-[#7d92b0] mt-0.5">{sr.notes}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ComplianceWorkflowsPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'workflows' | 'runs'>('workflows')
  const [showModal, setShowModal] = useState(false)
  const [editWf, setEditWf] = useState<Workflow | null>(null)
  const [detailRun, setDetailRun] = useState<WorkflowRun | null>(null)

  const { data: workflows = [] } = useQuery<Workflow[]>({
    queryKey: ['compliance-workflows'],
    queryFn: () => apiFetchList<Workflow>('/api/v1/admin/compliance-workflows'),
  })

  const { data: runs = [] } = useQuery<WorkflowRun[]>({
    queryKey: ['compliance-runs'],
    queryFn: () => apiFetchList<WorkflowRun>('/api/v1/admin/compliance-workflows/runs'),
  })

  const runMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/compliance-workflows/${id}/run`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-runs'] }),
  })

  const advanceMutation = useMutation({
    mutationFn: (runId: string) => apiFetch(`/api/v1/admin/compliance-workflows/runs/${runId}/advance`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-runs'] }),
  })

  const saveMutation = useMutation({
    mutationFn: (data: Partial<Workflow>) => apiFetch('/api/v1/admin/compliance-workflows', {
      method: editWf ? 'PUT' : 'POST',
      body: JSON.stringify(editWf ? { ...data, id: editWf.id } : data),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['compliance-workflows'] }); setShowModal(false); setEditWf(null) },
  })

  const typeLabel: Record<WorkflowType, string> = {
    audit: '監査', incident_response: 'インシデント', change_management: '変更管理',
    access_review: 'アクセスレビュー', risk_assessment: 'リスクアセスメント',
  }
  const triggerLabel: Record<TriggerType, string> = {
    manual: '手動', scheduled: 'スケジュール', event_driven: 'イベント', threshold: '閾値',
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <GitBranch className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">コンプライアンスワークフロー</h1>
            <p className="text-xs text-[#7d92b0]">コンプライアンスプロセスを自動化・追跡</p>
          </div>
        </div>
        <button
          onClick={() => { setEditWf(null); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" /> 新規ワークフロー
        </button>
      </div>

      {/* Stats row */}
      {(() => {
        const active = workflows.filter(w => w.active).length
        const inProgress = runs.filter(r => r.status === 'in_progress').length
        const completed = runs.filter(r => r.status === 'completed').length
        const failed = runs.filter(r => r.status === 'failed').length
        const stats = [
          { label: 'アクティブワークフロー', value: active, color: 'text-green-400' },
          { label: '実行中', value: inProgress, color: 'text-blue-400' },
          { label: '完了 (今月)', value: completed, color: 'text-[#7d92b0]' },
          { label: '失敗', value: failed, color: 'text-red-400' },
        ]
        return (
          <div className="grid grid-cols-4 gap-4">
            {stats.map(s => (
              <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
                <p className="text-xs text-[#7d92b0] mb-1">{s.label}</p>
                <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
              </div>
            ))}
          </div>
        )
      })()}

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['workflows', 'runs'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-sm text-sm font-medium transition-colors ${
              tab === t ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {t === 'workflows' ? 'ワークフロー' : '実行履歴'}
          </button>
        ))}
      </div>

      {/* Workflows Table */}
      {tab === 'workflows' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['名前', 'フレームワーク', 'タイプ', 'トリガー', '実行回数', '状態', '操作'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {workflows.map(wf => (
                <tr key={wf.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="px-4 py-3 text-white font-medium">{wf.name}</td>
                  <td className="px-4 py-3">
                    <Badge text={wf.framework} cls={fwColors[wf.framework]} />
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0]">{typeLabel[wf.workflow_type]}</td>
                  <td className="px-4 py-3 text-[#7d92b0]">{triggerLabel[wf.trigger_type]}</td>
                  <td className="px-4 py-3 text-[#7d92b0]">{wf.run_count}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 text-xs ${wf.active ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${wf.active ? 'bg-green-400' : 'bg-[#3d5068]'}`} />
                      {wf.active ? '有効' : '無効'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => { setEditWf(wf); setShowModal(true) }}
                        className="text-xs text-[#7d92b0] hover:text-white px-2 py-1 border border-[#1e2d42] rounded-sm transition-colors"
                      >
                        編集
                      </button>
                      <button
                        onClick={() => runMutation.mutate(wf.id)}
                        disabled={!wf.active || runMutation.isPending}
                        className="flex items-center gap-1 text-xs text-white px-2 py-1 bg-[#e8002d] hover:bg-[#c0001f] rounded-sm transition-colors disabled:opacity-40"
                      >
                        <Play className="w-3 h-3" /> 実行
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Runs Table */}
      {tab === 'runs' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['ワークフロー', 'フレームワーク', 'ステータス', 'ステージ進捗', '期限', '操作'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {runs.map(run => (
                <tr key={run.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="px-4 py-3 text-white font-medium">{run.workflow_name}</td>
                  <td className="px-4 py-3">
                    <Badge text={run.framework} cls={fwColors[run.framework]} />
                  </td>
                  <td className="px-4 py-3">
                    <Badge text={runStatusLabel[run.status]} cls={runStatusColors[run.status]} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-[#e8002d] rounded-full transition-all"
                          style={{ width: `${run.total_stages > 0 ? (run.current_stage / run.total_stages) * 100 : 0}%` }}
                        />
                      </div>
                      <span className="text-xs text-[#7d92b0]">{run.current_stage}/{run.total_stages}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs">
                    {new Date(run.due_date).toLocaleDateString('ja-JP')}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setDetailRun(run)}
                        className="text-xs text-[#7d92b0] hover:text-white px-2 py-1 border border-[#1e2d42] rounded-sm transition-colors flex items-center gap-1"
                      >
                        <Eye className="w-3 h-3" /> 詳細
                      </button>
                      {run.status === 'in_progress' && (
                        <button
                          onClick={() => advanceMutation.mutate(run.id)}
                          disabled={advanceMutation.isPending}
                          className="flex items-center gap-1 text-xs text-white px-2 py-1 bg-blue-600 hover:bg-blue-700 rounded-sm transition-colors disabled:opacity-40"
                        >
                          {advanceMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <ChevronRight className="w-3 h-3" />}
                          次のステージへ
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modals */}
      {showModal && (
        <WorkflowModal
          initial={editWf}
          onClose={() => { setShowModal(false); setEditWf(null) }}
          onSave={data => saveMutation.mutate(data)}
        />
      )}
      {detailRun && (
        <RunDetailModal run={detailRun} onClose={() => setDetailRun(null)} />
      )}
    </div>
  )
}
