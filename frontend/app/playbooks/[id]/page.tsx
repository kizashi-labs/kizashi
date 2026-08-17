'use client'

import { useState } from 'react'
import { useParams } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  ArrowLeft,
  Workflow,
  Play,
  Pencil,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  ChevronRight,
  X,
  Zap,
  ListOrdered,
  History,
  Tag,
  Calendar,
  RefreshCw,
  Terminal,
  Bell,
  Shield,
  Skull,
  Code2,
  Globe,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { USE_MOCK } from '@/lib/mock'

// ─── Types ─────────────────────────────────────────────────────────────────────

interface Playbook {
  id: string
  name: string
  description: string
  trigger_type: string
  trigger_config: Record<string, unknown>
  steps: PlaybookStep[]
  enabled: boolean
  run_count: number
  last_run?: string
  created_at: string
  updated_at: string
  tags?: string[]
}

interface PlaybookStep {
  order: number
  action: string
  name: string
  params: Record<string, unknown>
  on_success?: string
  on_failure?: string
}

interface PlaybookRun {
  id: string
  playbook_id: string
  trigger: string
  status: 'running' | 'completed' | 'failed'
  started_at: string
  finished_at?: string
  steps_log: Array<{ step: number; status: string; output: string }>
}

// ─── Mock execution history data ───────────────────────────────────────────────

function makeMockRuns(playbookId: string): PlaybookRun[] {
  const now = new Date()
  return [
    {
      id: 'run-001',
      playbook_id: playbookId,
      trigger: '手動実行',
      status: 'completed',
      started_at: new Date(now.getTime() - 1000 * 60 * 15).toISOString(),
      finished_at: new Date(now.getTime() - 1000 * 60 * 14).toISOString(),
      steps_log: [
        { step: 1, status: 'success', output: 'エージェント DESKTOP-ABC123 の隔離に成功しました。' },
        { step: 2, status: 'success', output: 'インシデント INC-9021 を作成しました。' },
        { step: 3, status: 'success', output: 'Slack チャンネル #soc-alerts に通知を送信しました。' },
      ],
    },
    {
      id: 'run-002',
      playbook_id: playbookId,
      trigger: 'アラート: T1059 検知',
      status: 'failed',
      started_at: new Date(now.getTime() - 1000 * 60 * 60 * 2).toISOString(),
      finished_at: new Date(now.getTime() - 1000 * 60 * 60 * 2 + 1000 * 8).toISOString(),
      steps_log: [
        { step: 1, status: 'success', output: 'エージェント SERVER-DC01 の隔離に成功しました。' },
        { step: 2, status: 'failed', output: 'エラー: インシデント作成に失敗しました。API タイムアウト (30s)' },
      ],
    },
    {
      id: 'run-003',
      playbook_id: playbookId,
      trigger: 'アラート: Mimikatz 検知',
      status: 'completed',
      started_at: new Date(now.getTime() - 1000 * 60 * 60 * 5).toISOString(),
      finished_at: new Date(now.getTime() - 1000 * 60 * 60 * 5 + 1000 * 22).toISOString(),
      steps_log: [
        { step: 1, status: 'success', output: 'IP 192.168.1.45 をブロックリストに追加しました。' },
        { step: 2, status: 'success', output: 'プロセス lsass_dumper.exe (PID 4821) を強制終了しました。' },
        { step: 3, status: 'success', output: 'スクリプト collect_forensics.ps1 を実行しました。終了コード: 0' },
      ],
    },
    {
      id: 'run-004',
      playbook_id: playbookId,
      trigger: 'スケジュール実行',
      status: 'completed',
      started_at: new Date(now.getTime() - 1000 * 60 * 60 * 24).toISOString(),
      finished_at: new Date(now.getTime() - 1000 * 60 * 60 * 24 + 1000 * 5).toISOString(),
      steps_log: [
        { step: 1, status: 'success', output: 'スクリプトが正常に完了しました。出力: 42 件のログを収集。' },
      ],
    },
    {
      id: 'run-005',
      playbook_id: playbookId,
      trigger: '手動実行',
      status: 'running',
      started_at: new Date(now.getTime() - 1000 * 30).toISOString(),
      steps_log: [
        { step: 1, status: 'running', output: 'エージェントへの接続中...' },
      ],
    },
  ]
}

// ─── Action type display helpers ──────────────────────────────────────────────

const ACTION_META: Record<string, { label: string; icon: React.ReactNode; color: string; bg: string }> = {
  isolate_agent: {
    label: 'エージェント隔離',
    icon: <Shield size={14} />,
    color: 'text-red-400',
    bg: 'bg-red-900/20 border-red-800/40',
  },
  create_alert: {
    label: 'アラート作成',
    icon: <AlertTriangle size={14} />,
    color: 'text-orange-400',
    bg: 'bg-orange-900/20 border-orange-800/40',
  },
  notify_slack: {
    label: 'Slack 通知',
    icon: <Bell size={14} />,
    color: 'text-blue-400',
    bg: 'bg-blue-900/20 border-blue-800/40',
  },
  block_ip: {
    label: 'IP ブロック',
    icon: <Globe size={14} />,
    color: 'text-yellow-400',
    bg: 'bg-yellow-900/20 border-yellow-800/40',
  },
  kill_process: {
    label: 'プロセス強制終了',
    icon: <Skull size={14} />,
    color: 'text-pink-400',
    bg: 'bg-pink-900/20 border-pink-800/40',
  },
  run_script: {
    label: 'スクリプト実行',
    icon: <Code2 size={14} />,
    color: 'text-purple-400',
    bg: 'bg-purple-900/20 border-purple-800/40',
  },
}

function getActionMeta(action: string) {
  return ACTION_META[action] ?? {
    label: action,
    icon: <Terminal size={14} />,
    color: 'text-falcon-muted',
    bg: 'bg-falcon-surface border-falcon-border',
  }
}

// ─── Status badge helpers ──────────────────────────────────────────────────────

function RunStatusBadge({ status }: { status: PlaybookRun['status'] }) {
  if (status === 'completed') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-900/40 text-green-300 border border-green-700/50">
        <CheckCircle2 size={10} />
        完了
      </span>
    )
  }
  if (status === 'failed') {
    return (
      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-red-900/40 text-red-300 border border-red-700/50">
        <XCircle size={10} />
        失敗
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-blue-900/40 text-blue-300 border border-blue-700/50">
      <Loader2 size={10} className="animate-spin" />
      実行中
    </span>
  )
}

function StepStatusIcon({ status }: { status: string }) {
  if (status === 'success') return <CheckCircle2 size={16} className="text-green-400 shrink-0" />
  if (status === 'failed') return <XCircle size={16} className="text-red-400 shrink-0" />
  return <Loader2 size={16} className="text-blue-400 shrink-0 animate-spin" />
}

function durationString(started: string, finished?: string): string {
  if (!finished) return '—'
  const ms = new Date(finished).getTime() - new Date(started).getTime()
  if (ms < 1000) return `${ms}ms`
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

// ─── Tab definitions ──────────────────────────────────────────────────────────

const TABS = [
  { id: 'overview', label: '概要', icon: <Workflow size={14} /> },
  { id: 'steps', label: 'ステップ', icon: <ListOrdered size={14} /> },
  { id: 'history', label: '実行履歴', icon: <History size={14} /> },
] as const

type TabId = typeof TABS[number]['id']

// ─── Run Modal ────────────────────────────────────────────────────────────────

interface RunModalProps {
  playbookId: string
  playbookName: string
  onClose: () => void
}

function RunModal({ playbookId, playbookName, onClose }: RunModalProps) {
  const qc = useQueryClient()
  const [target, setTarget] = useState('')

  const { data: agentsData } = useQuery<{ data: { id: string; hostname: string; os_type: string }[] }>({
    queryKey: ['agents-for-playbook'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=500'),
    staleTime: 60_000,
  })
  const agentsList = agentsData?.data ?? []

  const executeMutation = useMutation({
    mutationFn: () =>
      apiFetch(`/api/v1/playbooks/${playbookId}/execute`, {
        method: 'POST',
        body: JSON.stringify({ target_agent: target || undefined }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['playbook-runs', playbookId] })
      qc.invalidateQueries({ queryKey: ['playbook', playbookId] })
      onClose()
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-xs" onClick={onClose} />

      {/* Modal */}
      <div className="relative bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-md mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-2">
            <Play size={16} className="text-falcon-red" />
            <h2 className="font-semibold text-white">手動実行</h2>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-4">
          <p className="text-sm text-falcon-muted">
            プレイブック <span className="text-white font-medium">"{playbookName}"</span> を手動で実行します。
          </p>

          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">
              ターゲットエージェント <span className="text-[#5a6a7a]">(省略可)</span>
            </label>
            <div className="relative">
              <select
                value={target}
                onChange={e => setTarget(e.target.value)}
                className="w-full appearance-none bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/60 transition-colors pr-8"
              >
                <option value="">すべて（指定なし）</option>
                {agentsList.map(a => (
                  <option key={a.id} value={a.id}>{a.hostname} ({a.os_type})</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle pointer-events-none" />
            </div>
          </div>

          <div className="bg-yellow-900/20 border border-yellow-800/40 rounded-lg px-4 py-3 flex items-start gap-2">
            <AlertTriangle size={14} className="text-yellow-400 shrink-0 mt-0.5" />
            <p className="text-xs text-yellow-300">
              プレイブックのアクション（隔離・プロセス停止など）は実際のシステムに影響します。実行前に対象を確認してください。
            </p>
          </div>

          {executeMutation.isError && (
            <p className="text-red-400 text-sm">実行に失敗しました。もう一度お試しください。</p>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button
            onClick={onClose}
            className="text-sm text-falcon-muted hover:text-white px-4 py-2 transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => executeMutation.mutate()}
            disabled={executeMutation.isPending}
            className="flex items-center gap-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50
                       text-white text-sm font-medium px-5 py-2 rounded-lg transition-colors"
          >
            {executeMutation.isPending ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Play size={14} />
            )}
            実行する
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Execution detail slide-out panel ─────────────────────────────────────────

interface ExecutionPanelProps {
  run: PlaybookRun
  onClose: () => void
}

function ExecutionPanel({ run, onClose }: ExecutionPanelProps) {
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />

      {/* Panel */}
      <div className="relative bg-falcon-surface border-l border-falcon-border w-full max-w-lg h-full flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border shrink-0">
          <div className="flex items-center gap-3">
            <History size={16} className="text-falcon-muted" />
            <div>
              <h3 className="font-semibold text-white text-sm">実行詳細</h3>
              <p className="text-xs text-falcon-muted font-mono">{run.id}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Meta info */}
        <div className="px-5 py-3 border-b border-falcon-border shrink-0 space-y-1.5">
          <div className="flex items-center justify-between text-sm">
            <span className="text-falcon-muted">ステータス</span>
            <RunStatusBadge status={run.status} />
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-falcon-muted">トリガー</span>
            <span className="text-white">{run.trigger}</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-falcon-muted">開始時刻</span>
            <span className="text-falcon-muted font-mono text-xs">
              {new Date(run.started_at).toLocaleString('ja-JP')}
            </span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-falcon-muted">所要時間</span>
            <span className="text-falcon-muted font-mono text-xs">
              {durationString(run.started_at, run.finished_at)}
            </span>
          </div>
        </div>

        {/* Step logs */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-3">
          <p className="text-xs text-falcon-muted font-medium uppercase tracking-wider mb-3">ステップログ</p>
          {run.steps_log.length === 0 ? (
            <p className="text-[#3a4a5a] text-sm text-center py-8">ログがありません</p>
          ) : (
            run.steps_log.map((log, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 bg-[#070d19] border border-falcon-border rounded-lg px-4 py-3"
              >
                <StepStatusIcon status={log.status} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-mono text-falcon-muted">Step {log.step}</span>
                    <span
                      className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                        log.status === 'success'
                          ? 'bg-green-900/30 text-green-400'
                          : log.status === 'failed'
                          ? 'bg-red-900/30 text-red-400'
                          : 'bg-blue-900/30 text-blue-400'
                      }`}
                    >
                      {log.status === 'success' ? '成功' : log.status === 'failed' ? '失敗' : '実行中'}
                    </span>
                  </div>
                  <p className="text-sm text-white leading-relaxed">{log.output}</p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────

function OverviewTab({ playbook }: { playbook: Playbook }) {
  return (
    <div className="space-y-5">
      {/* Description */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <h3 className="text-sm font-medium text-falcon-muted mb-2">説明</h3>
        <p className="text-white text-sm leading-relaxed">
          {playbook.description || <span className="text-[#3a4a5a] italic">説明が設定されていません</span>}
        </p>
      </div>

      {/* Trigger conditions */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Zap size={14} className="text-yellow-400" />
          <h3 className="text-sm font-medium text-falcon-muted">トリガー設定</h3>
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-falcon-muted">トリガータイプ</span>
            <span className="text-xs bg-falcon-raised text-white px-2.5 py-1 rounded-lg font-mono">
              {playbook.trigger_type || '—'}
            </span>
          </div>
          {Object.keys(playbook.trigger_config ?? {}).length > 0 && (
            <div className="mt-3 space-y-1.5">
              {Object.entries(playbook.trigger_config).map(([k, v]) => (
                <div key={k} className="flex items-start justify-between gap-4">
                  <span className="text-xs text-falcon-muted font-mono">{k}</span>
                  <span className="text-xs text-white font-mono text-right max-w-xs truncate">
                    {String(v)}
                  </span>
                </div>
              ))}
            </div>
          )}
          {Object.keys(playbook.trigger_config ?? {}).length === 0 && (
            <p className="text-xs text-[#3a4a5a] italic mt-1">トリガー設定なし (すべてのイベントにマッチ)</p>
          )}
        </div>
      </div>

      {/* Tags */}
      {playbook.tags && playbook.tags.length > 0 && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Tag size={14} className="text-falcon-muted" />
            <h3 className="text-sm font-medium text-falcon-muted">タグ</h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {playbook.tags.map(tag => (
              <span
                key={tag}
                className="text-xs bg-falcon-raised text-falcon-muted border border-falcon-border px-2.5 py-1 rounded-lg"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Timestamps */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Calendar size={14} className="text-falcon-muted" />
          <h3 className="text-sm font-medium text-falcon-muted">タイムスタンプ</h3>
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-falcon-muted">作成日時</span>
            <span className="text-xs text-white font-mono">
              {playbook.created_at ? new Date(playbook.created_at).toLocaleString('ja-JP') : '—'}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs text-falcon-muted">最終更新</span>
            <span className="text-xs text-white font-mono">
              {playbook.updated_at ? new Date(playbook.updated_at).toLocaleString('ja-JP') : '—'}
            </span>
          </div>
          {playbook.last_run && (
            <div className="flex items-center justify-between">
              <span className="text-xs text-falcon-muted">最終実行</span>
              <span className="text-xs text-white font-mono">
                {new Date(playbook.last_run).toLocaleString('ja-JP')}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Steps Tab ────────────────────────────────────────────────────────────────

function StepsTab({ steps }: { steps: PlaybookStep[] }) {
  const [expandedStep, setExpandedStep] = useState<number | null>(null)

  if (steps.length === 0) {
    return (
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-10 text-center">
        <ListOrdered size={40} className="mx-auto mb-3 text-[#3a4a5a]" />
        <p className="text-falcon-muted text-sm">ステップが設定されていません</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {steps
        .slice()
        .sort((a, b) => a.order - b.order)
        .map((step, idx) => {
          const meta = getActionMeta(step.action)
          const isExpanded = expandedStep === step.order
          const paramEntries = Object.entries(step.params ?? {})

          return (
            <div
              key={step.order}
              className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden"
            >
              {/* Step header */}
              <div
                className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-falcon-card/50 transition-colors"
                onClick={() => setExpandedStep(isExpanded ? null : step.order)}
              >
                {/* Step number circle */}
                <div className="w-8 h-8 rounded-full bg-falcon-raised border border-falcon-border flex items-center
                                justify-center text-sm font-bold text-falcon-muted shrink-0">
                  {idx + 1}
                </div>

                {/* Action type badge */}
                <div className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border ${meta.bg} ${meta.color} shrink-0`}>
                  {meta.icon}
                  {meta.label}
                </div>

                {/* Step name */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">{step.name || step.action}</p>
                  {paramEntries.length > 0 && (
                    <p className="text-xs text-falcon-muted mt-0.5 truncate">
                      {paramEntries.slice(0, 2).map(([k, v]) => `${k}: ${String(v)}`).join(' · ')}
                      {paramEntries.length > 2 && ` · +${paramEntries.length - 2}個`}
                    </p>
                  )}
                </div>

                {/* Expand toggle */}
                <div className="text-falcon-muted shrink-0">
                  {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </div>
              </div>

              {/* Expanded detail */}
              {isExpanded && (
                <div className="border-t border-falcon-border px-5 py-4 bg-[#070d19]/60 space-y-4">
                  {/* Parameters */}
                  {paramEntries.length > 0 && (
                    <div>
                      <p className="text-xs text-falcon-muted font-medium mb-2 uppercase tracking-wider">パラメータ</p>
                      <div className="space-y-1.5">
                        {paramEntries.map(([k, v]) => (
                          <div key={k} className="flex items-start justify-between gap-4">
                            <span className="text-xs text-falcon-muted font-mono shrink-0">{k}</span>
                            <span className="text-xs text-white font-mono text-right break-all">{String(v)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Success/failure conditions */}
                  {(step.on_success || step.on_failure) && (
                    <div className="grid grid-cols-2 gap-3">
                      {step.on_success && (
                        <div className="bg-green-900/10 border border-green-800/30 rounded-lg px-3 py-2">
                          <p className="text-xs text-green-400 font-medium mb-0.5">成功時</p>
                          <p className="text-xs text-green-300">{step.on_success}</p>
                        </div>
                      )}
                      {step.on_failure && (
                        <div className="bg-red-900/10 border border-red-800/30 rounded-lg px-3 py-2">
                          <p className="text-xs text-red-400 font-medium mb-0.5">失敗時</p>
                          <p className="text-xs text-red-300">{step.on_failure}</p>
                        </div>
                      )}
                    </div>
                  )}

                  {paramEntries.length === 0 && !step.on_success && !step.on_failure && (
                    <p className="text-xs text-[#3a4a5a] italic">追加設定なし</p>
                  )}
                </div>
              )}
            </div>
          )
        })}
    </div>
  )
}

// ─── History Tab ──────────────────────────────────────────────────────────────

function HistoryTab({
  runs,
  onSelectRun,
}: {
  runs: PlaybookRun[]
  onSelectRun: (run: PlaybookRun) => void
}) {
  if (runs.length === 0) {
    return (
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-10 text-center">
        <History size={40} className="mx-auto mb-3 text-[#3a4a5a]" />
        <p className="text-falcon-muted text-sm">実行履歴がありません</p>
      </div>
    )
  }

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-falcon-border">
            <th className="text-left text-xs text-falcon-muted px-5 py-3 font-medium">実行ID</th>
            <th className="text-left text-xs text-falcon-muted px-5 py-3 font-medium">トリガー</th>
            <th className="text-left text-xs text-falcon-muted px-5 py-3 font-medium">ステータス</th>
            <th className="text-left text-xs text-falcon-muted px-5 py-3 font-medium">開始時刻</th>
            <th className="text-left text-xs text-falcon-muted px-5 py-3 font-medium">所要時間</th>
            <th className="text-right text-xs text-falcon-muted px-5 py-3 font-medium">操作</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run, idx) => (
            <tr
              key={run.id}
              className={`border-b border-falcon-border/50 hover:bg-falcon-card/40 transition-colors ${
                idx === runs.length - 1 ? 'border-b-0' : ''
              }`}
            >
              <td className="px-5 py-3">
                <span className="font-mono text-xs text-falcon-muted">{run.id}</span>
              </td>
              <td className="px-5 py-3">
                <span className="text-white text-xs">{run.trigger}</span>
              </td>
              <td className="px-5 py-3">
                <RunStatusBadge status={run.status} />
              </td>
              <td className="px-5 py-3">
                <span className="text-xs text-falcon-muted font-mono whitespace-nowrap">
                  {new Date(run.started_at).toLocaleString('ja-JP')}
                </span>
              </td>
              <td className="px-5 py-3">
                <span className="text-xs text-falcon-muted font-mono">
                  {durationString(run.started_at, run.finished_at)}
                </span>
              </td>
              <td className="px-5 py-3 text-right">
                <button
                  onClick={() => onSelectRun(run)}
                  className="inline-flex items-center gap-1 text-xs text-falcon-muted hover:text-white
                             transition-colors px-2.5 py-1 rounded-lg hover:bg-falcon-raised border border-transparent
                             hover:border-falcon-border"
                >
                  詳細
                  <ChevronRight size={12} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Info cards row ───────────────────────────────────────────────────────────

function InfoCards({ playbook }: { playbook: Playbook }) {
  const cards = [
    {
      label: 'トリガータイプ',
      value: playbook.trigger_type || '—',
      icon: <Zap size={16} className="text-yellow-400" />,
      mono: true,
    },
    {
      label: 'ステップ数',
      value: String(playbook.steps?.length ?? 0),
      icon: <ListOrdered size={16} className="text-blue-400" />,
      mono: false,
    },
    {
      label: '実行回数',
      value: String(playbook.run_count ?? 0),
      icon: <RefreshCw size={16} className="text-purple-400" />,
      mono: false,
    },
    {
      label: '最終実行',
      value: playbook.last_run
        ? new Date(playbook.last_run).toLocaleDateString('ja-JP')
        : '未実行',
      icon: <Clock size={16} className="text-falcon-muted" />,
      mono: false,
    },
  ]

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {cards.map(card => (
        <div
          key={card.label}
          className="bg-falcon-surface border border-falcon-border rounded-xl px-4 py-4 flex items-center gap-3"
        >
          <div className="shrink-0">{card.icon}</div>
          <div className="min-w-0">
            <p className="text-xs text-falcon-muted">{card.label}</p>
            <p className={`text-sm font-semibold text-white truncate mt-0.5 ${card.mono ? 'font-mono' : ''}`}>
              {card.value}
            </p>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function PlaybookDetailPage() {
  const params = useParams()
  const id = params.id as string

  const [activeTab, setActiveTab] = useState<TabId>('overview')
  const [showRunModal, setShowRunModal] = useState(false)
  const [selectedRun, setSelectedRun] = useState<PlaybookRun | null>(null)

  // Fetch playbook detail
  const { data: playbook, isLoading, isError } = useQuery<Playbook>({
    queryKey: ['playbook', id],
    queryFn: () => apiFetch<Playbook>(`/api/v1/playbooks/${id}`),
    enabled: !!id,
  })

  // Mock execution history (replace with real endpoint when available)
  const mockRuns = USE_MOCK && id ? makeMockRuns(id) : []

  // ── Loading state ──────────────────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="p-6 space-y-4 min-h-screen bg-[#070d19]">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-8 h-8 bg-falcon-surface rounded-lg animate-pulse" />
          <div className="h-7 w-64 bg-falcon-surface rounded-lg animate-pulse" />
        </div>
        <div className="grid grid-cols-4 gap-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-20 bg-falcon-surface rounded-xl animate-pulse" />
          ))}
        </div>
        <div className="h-96 bg-falcon-surface rounded-xl animate-pulse" />
      </div>
    )
  }

  // ── Error state ────────────────────────────────────────────────────────────
  if (isError || !playbook) {
    return (
      <div className="p-6 min-h-screen bg-[#070d19]">
        <div className="flex items-center gap-4 mb-6">
          <Link href="/playbooks" className="text-falcon-muted hover:text-white transition-colors">
            <ArrowLeft size={20} />
          </Link>
        </div>
        <div className="bg-falcon-surface border border-red-800/40 rounded-xl p-10 text-center">
          <XCircle size={48} className="mx-auto mb-3 text-red-500 opacity-60" />
          <p className="text-white font-medium">プレイブックが見つかりません</p>
          <p className="text-falcon-muted text-sm mt-1">ID: {id}</p>
          <Link
            href="/playbooks"
            className="inline-flex items-center gap-2 mt-5 text-sm text-falcon-muted hover:text-white transition-colors"
          >
            <ArrowLeft size={14} />
            プレイブック一覧に戻る
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#070d19]">
      <div className="p-6 max-w-6xl mx-auto space-y-5">

        {/* ── Header ─────────────────────────────────────────────────────────── */}
        <div className="flex items-start gap-4">
          {/* Back link */}
          <Link
            href="/playbooks"
            className="text-falcon-muted hover:text-white transition-colors mt-1 shrink-0"
            title="プレイブック一覧に戻る"
          >
            <ArrowLeft size={20} />
          </Link>

          {/* Title area */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <Workflow size={20} className="text-purple-400 shrink-0" />
              <h1 className="text-2xl font-bold text-white truncate">{playbook.name}</h1>

              {/* Status badge */}
              {playbook.enabled ? (
                <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full
                                 bg-green-900/40 text-green-300 border border-green-700/50 shrink-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
                  有効
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full
                                 bg-falcon-raised text-falcon-muted border border-falcon-border shrink-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-falcon-muted inline-block" />
                  無効
                </span>
              )}
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 shrink-0">
            <Link
              href={`/playbooks/${id}/edit`}
              className="flex items-center gap-1.5 text-sm text-falcon-muted hover:text-white border
                         border-falcon-border hover:border-[#2e3d52] bg-falcon-surface px-3.5 py-2 rounded-lg transition-colors"
            >
              <Pencil size={14} />
              編集
            </Link>
            <button
              onClick={() => setShowRunModal(true)}
              className="flex items-center gap-1.5 text-sm font-medium text-white bg-falcon-red
                         hover:bg-[#c0001f] px-4 py-2 rounded-lg transition-colors"
            >
              <Play size={14} />
              実行
            </button>
          </div>
        </div>

        {/* ── Info cards ─────────────────────────────────────────────────────── */}
        <InfoCards playbook={playbook} />

        {/* ── Tab bar ────────────────────────────────────────────────────────── */}
        <div className="border-b border-falcon-border">
          <div className="flex gap-1">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
                  activeTab === tab.id
                    ? 'border-falcon-red text-white'
                    : 'border-transparent text-falcon-muted hover:text-white hover:border-falcon-border'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Tab content ────────────────────────────────────────────────────── */}
        <div>
          {activeTab === 'overview' && <OverviewTab playbook={playbook} />}
          {activeTab === 'steps' && <StepsTab steps={playbook.steps ?? []} />}
          {activeTab === 'history' && (
            <HistoryTab runs={mockRuns} onSelectRun={setSelectedRun} />
          )}
        </div>
      </div>

      {/* ── Run modal ──────────────────────────────────────────────────────────── */}
      {showRunModal && (
        <RunModal
          playbookId={id}
          playbookName={playbook.name}
          onClose={() => setShowRunModal(false)}
        />
      )}

      {/* ── Execution detail panel ─────────────────────────────────────────────── */}
      {selectedRun && (
        <ExecutionPanel run={selectedRun} onClose={() => setSelectedRun(null)} />
      )}
    </div>
  )
}
