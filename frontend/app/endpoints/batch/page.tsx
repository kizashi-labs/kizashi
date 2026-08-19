'use client'

import { useState, Suspense } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useSearchParams } from 'next/navigation'
import {
  Terminal, AlertTriangle, Search, CheckSquare, Square, ChevronRight,
  Play, Clock, Monitor, Loader2, CheckCircle2, XCircle, SkipForward
} from 'lucide-react'
import type { Agent, PaginatedResponse } from '@/types/api'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────────────────

type CommandType = 'isolate' | 'unisolate' | 'scan' | 'kill_process' | 'run_script' | 'update_policy'
type ScheduleType = 'now' | 'scheduled'

interface BatchCommandPayload {
  agent_ids: string[]
  command: CommandType
  params?: Record<string, unknown>
  scheduled_at?: string
}

interface AgentGroup {
  id: string
  name: string
}

interface PerAgentResult {
  agent_id: string
  hostname: string
  status: 'pending' | 'running' | 'success' | 'failed' | 'skipped'
  error?: string
}

// ── Step indicator ─────────────────────────────────────────────────────────

function StepIndicator({ current }: { current: 1 | 2 | 3 }) {
  const steps = [
    { n: 1 as const, label: 'エンドポイント選択' },
    { n: 2 as const, label: 'コマンド設定' },
    { n: 3 as const, label: '確認と実行' },
  ]
  return (
    <div className="flex items-center gap-0">
      {steps.map((step, i) => (
        <div key={step.n} className="flex items-center">
          <div className="flex items-center gap-2">
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold shrink-0 ${
              step.n < current
                ? 'bg-green-700 text-white'
                : step.n === current
                ? 'bg-[#e8002d] text-white'
                : 'bg-[#1e2d42] text-[#7d92b0]'
            }`}>
              {step.n < current ? '✓' : step.n}
            </div>
            <span className={`text-sm ${step.n === current ? 'text-white font-medium' : 'text-[#7d92b0]'}`}>
              {step.label}
            </span>
          </div>
          {i < steps.length - 1 && (
            <ChevronRight className="w-4 h-4 text-[#3d5068] mx-3" />
          )}
        </div>
      ))}
    </div>
  )
}

// ── Command type button ────────────────────────────────────────────────────

function CommandButton({
  cmd, label, description, selected, onClick
}: {
  cmd: CommandType
  label: string
  description: string
  selected: boolean
  onClick: () => void
}) {
  const colorMap: Record<CommandType, string> = {
    isolate: 'border-red-700/50 hover:border-red-500 data-[selected=true]:border-red-500 data-[selected=true]:bg-red-900/20',
    unisolate: 'border-green-700/50 hover:border-green-500 data-[selected=true]:border-green-500 data-[selected=true]:bg-green-900/20',
    scan: 'border-blue-700/50 hover:border-blue-500 data-[selected=true]:border-blue-500 data-[selected=true]:bg-blue-900/20',
    kill_process: 'border-orange-700/50 hover:border-orange-500 data-[selected=true]:border-orange-500 data-[selected=true]:bg-orange-900/20',
    run_script: 'border-purple-700/50 hover:border-purple-500 data-[selected=true]:border-purple-500 data-[selected=true]:bg-purple-900/20',
    update_policy: 'border-[#7d92b0]/30 hover:border-[#7d92b0] data-[selected=true]:border-[#7d92b0] data-[selected=true]:bg-[#1e2d42]/60',
  }
  return (
    <button
      data-selected={selected}
      onClick={onClick}
      className={`text-left p-3 rounded-lg border transition-all ${colorMap[cmd]} ${
        selected ? '' : 'border-[#1e2d42] bg-[#0d1220]'
      }`}
    >
      <p className="text-sm font-medium text-white mb-0.5">{label}</p>
      <p className="text-xs text-[#7d92b0]">{description}</p>
    </button>
  )
}

// ── Agent status label ─────────────────────────────────────────────────────
// 表引きにする。以前は三項演算子の連鎖で、該当しない状態（error / inactive）が
// 生の英語値のまま表示されていた。
const AGENT_STATUS_LABEL: Record<string, string> = {
  online:   'オンライン',
  offline:  'オフライン',
  isolated: '隔離中',
  error:    'エラー',
  inactive: '非アクティブ',
}

// ── Result status icon ─────────────────────────────────────────────────────

function ResultIcon({ status }: { status: PerAgentResult['status'] }) {
  if (status === 'pending') return <span className="w-4 h-4 rounded-full border border-[#3d5068]" />
  if (status === 'running') return <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
  if (status === 'success') return <CheckCircle2 className="w-4 h-4 text-green-400" />
  if (status === 'failed') return <XCircle className="w-4 h-4 text-red-400" />
  return <SkipForward className="w-4 h-4 text-[#7d92b0]" />
}

// ── Main page ──────────────────────────────────────────────────────────────

function BatchCommandInner() {
  useSearchParams() // required for Suspense boundary

  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [search, setSearch] = useState('')
  const [groupFilter, setGroupFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [osFilter, setOsFilter] = useState('')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const [command, setCommand] = useState<CommandType>('scan')
  const [processName, setProcessName] = useState('')
  const [scriptContent, setScriptContent] = useState('')
  const [scriptTimeout, setScriptTimeout] = useState('60')
  const [policyId, setPolicyId] = useState('')
  const [schedule, setSchedule] = useState<ScheduleType>('now')
  const [scheduledAt, setScheduledAt] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [results, setResults] = useState<PerAgentResult[]>([])

  const { data: groupsData } = useQuery<{ data: AgentGroup[] }>({
    queryKey: ['groups'],
    queryFn: () => apiFetch('/api/v1/groups'),
  })

  const params = new URLSearchParams({
    ...(search && { search }),
    ...(groupFilter && { group_id: groupFilter }),
    ...(statusFilter && { status: statusFilter }),
    ...(osFilter && { os: osFilter }),
    per_page: '100',
  })

  const { data, isLoading } = useQuery<PaginatedResponse<Agent>>({
    queryKey: ['agents-batch', search, groupFilter, statusFilter, osFilter],
    queryFn: () => apiFetch<PaginatedResponse<Agent>>(`/api/v1/agents?${params}`),
  })

  const agents = data?.data ?? []

  const batchMutation = useMutation({
    mutationFn: (payload: BatchCommandPayload) =>
      apiFetch('/api/v1/agents/batch-command', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: (res: unknown) => {
      // Simulate per-agent results from response
      const resp = res as { results?: { agent_id: string; status: string; error?: string }[] }
      const agentIdToHostname = new Map(agents.map(a => [a.id, a.hostname]))
      if (resp?.results) {
        setResults(resp.results.map(r => ({
          agent_id: r.agent_id,
          hostname: agentIdToHostname.get(r.agent_id) ?? r.agent_id,
          status: (r.status as PerAgentResult['status']) ?? 'success',
          error: r.error,
        })))
      } else {
        // Fallback: mark all as success
        setResults(Array.from(selectedIds).map(id => ({
          agent_id: id,
          hostname: agentIdToHostname.get(id) ?? id,
          status: 'success',
        })))
      }
    },
    onError: () => {
      // Mark all as failed
      const agentIdToHostname = new Map(agents.map(a => [a.id, a.hostname]))
      setResults(Array.from(selectedIds).map(id => ({
        agent_id: id,
        hostname: agentIdToHostname.get(id) ?? id,
        status: 'failed',
        error: '実行エラー',
      })))
    },
  })

  const selectedAgents = agents.filter(a => selectedIds.has(a.id))

  function toggleAgent(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function selectAll() {
    setSelectedIds(new Set(agents.map(a => a.id)))
  }

  function deselectAll() {
    setSelectedIds(new Set())
  }

  function handleExecute() {
    if (!confirmed) return
    const params: Record<string, unknown> = {}
    if (command === 'kill_process') params.process_name = processName
    if (command === 'run_script') { params.script = scriptContent; params.timeout = Number(scriptTimeout) }
    if (command === 'update_policy') params.policy_id = policyId

    const payload: BatchCommandPayload = {
      agent_ids: Array.from(selectedIds),
      command,
      params: Object.keys(params).length > 0 ? params : undefined,
      scheduled_at: schedule === 'scheduled' ? scheduledAt : undefined,
    }

    // Set results to pending/running
    const agentIdToHostname = new Map(agents.map(a => [a.id, a.hostname]))
    setResults(Array.from(selectedIds).map(id => ({
      agent_id: id,
      hostname: agentIdToHostname.get(id) ?? id,
      status: 'running',
    })))

    batchMutation.mutate(payload)
  }

  const commandLabels: Record<CommandType, string> = {
    isolate: 'ネットワーク隔離',
    unisolate: '隔離解除',
    scan: 'セキュリティスキャン',
    kill_process: 'プロセス終了',
    run_script: 'スクリプト実行',
    update_policy: 'ポリシー更新',
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <Terminal className="w-6 h-6 text-[#e8002d]" />
        <div>
          <h1 className="text-2xl font-bold text-white">バッチコマンド実行</h1>
          <p className="text-sm text-[#7d92b0]">複数エンドポイントに一括でコマンドを実行</p>
        </div>
      </div>

      {/* Warning banner */}
      <div className="flex items-center gap-3 px-4 py-3 mb-6 bg-amber-900/20 border border-amber-700/50 rounded-xl">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
        <p className="text-sm text-amber-300 font-medium">管理者権限が必要です — この操作は取り消せない場合があります。実行前に影響範囲を必ず確認してください。</p>
      </div>

      {/* Step indicator */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-5 py-4 mb-6">
        <StepIndicator current={step} />
      </div>

      {/* ── Step 1: Endpoint selection ────────────────────────────── */}
      {step === 1 && (
        <div className="space-y-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-semibold text-white">Step 1 — エンドポイント選択</h2>
              <div className="flex items-center gap-2">
                <button
                  onClick={selectAll}
                  className="text-xs px-2.5 py-1 bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] rounded-lg hover:bg-[#1e2d42] transition-colors"
                >
                  全選択
                </button>
                <button
                  onClick={deselectAll}
                  className="text-xs px-2.5 py-1 bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] rounded-lg hover:bg-[#1e2d42] transition-colors"
                >
                  全解除
                </button>
                {selectedIds.size > 0 && (
                  <span className="text-xs px-2.5 py-1 bg-[#e8002d] text-white rounded-lg font-bold">
                    {selectedIds.size} 件選択中
                  </span>
                )}
              </div>
            </div>

            {/* Filters */}
            <div className="flex gap-2 flex-wrap mb-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="ホスト名で検索..."
                  className="pl-9 pr-3 py-1.5 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-white placeholder-[#3d5068] w-44 focus:outline-hidden focus:border-[#e8002d]"
                />
              </div>
              <select
                value={groupFilter}
                onChange={e => setGroupFilter(e.target.value)}
                className="text-sm border border-[#1e2d42] rounded-lg px-2 py-1.5 bg-[#070d19] text-[#7d92b0] focus:outline-hidden focus:border-[#e8002d]"
              >
                <option value="">グループ: すべて</option>
                {(groupsData?.data ?? []).map(g => (
                  <option key={g.id} value={g.id}>{g.name}</option>
                ))}
              </select>
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="text-sm border border-[#1e2d42] rounded-lg px-2 py-1.5 bg-[#070d19] text-[#7d92b0] focus:outline-hidden focus:border-[#e8002d]"
              >
                <option value="">ステータス: すべて</option>
                <option value="online">オンライン</option>
                <option value="offline">オフライン</option>
                <option value="isolated">隔離中</option>
                <option value="inactive">非アクティブ</option>
              </select>
              <select
                value={osFilter}
                onChange={e => setOsFilter(e.target.value)}
                className="text-sm border border-[#1e2d42] rounded-lg px-2 py-1.5 bg-[#070d19] text-[#7d92b0] focus:outline-hidden focus:border-[#e8002d]"
              >
                <option value="">OS: すべて</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="darwin">macOS</option>
              </select>
            </div>

            {/* Agent table */}
            {isLoading ? (
              <div className="space-y-1.5">
                {[...Array(8)].map((_, i) => (
                  <div key={i} className="h-10 bg-[#070d19] rounded-lg animate-pulse" />
                ))}
              </div>
            ) : agents.length === 0 ? (
              <div className="text-center py-10">
                <Monitor className="w-8 h-8 text-[#3d5068] mx-auto mb-2" />
                <p className="text-sm text-[#7d92b0]">エンドポイントが見つかりません</p>
              </div>
            ) : (
              <div className="border border-[#1e2d42] rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42] bg-[#070d19]/80">
                      <th className="px-3 py-2 w-10">
                        <input
                          type="checkbox"
                          checked={selectedIds.size === agents.length && agents.length > 0}
                          onChange={e => e.target.checked ? selectAll() : deselectAll()}
                          className="rounded-sm border-[#1e2d42] bg-[#0d1220] text-[#e8002d]"
                        />
                      </th>
                      <th className="text-left px-3 py-2 text-xs font-medium text-[#7d92b0]">ホスト名</th>
                      <th className="text-left px-3 py-2 text-xs font-medium text-[#7d92b0]">OS</th>
                      <th className="text-left px-3 py-2 text-xs font-medium text-[#7d92b0]">ステータス</th>
                      <th className="text-left px-3 py-2 text-xs font-medium text-[#7d92b0]">グループ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {agents.map(agent => {
                      const isSelected = selectedIds.has(agent.id)
                      return (
                        <tr
                          key={agent.id}
                          onClick={() => toggleAgent(agent.id)}
                          className={`border-b border-[#1e2d42]/40 last:border-0 cursor-pointer transition-colors ${
                            isSelected ? 'bg-[#e8002d]/5 hover:bg-[#e8002d]/10' : 'hover:bg-[#1e2d42]/30'
                          }`}
                        >
                          <td className="px-3 py-2.5">
                            {isSelected
                              ? <CheckSquare className="w-4 h-4 text-[#e8002d]" />
                              : <Square className="w-4 h-4 text-[#3d5068]" />
                            }
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="font-medium text-white">{agent.hostname}</span>
                          </td>
                          <td className="px-3 py-2.5 text-xs text-[#7d92b0]">
                            {agent.os_type} {agent.os_version}
                          </td>
                          <td className="px-3 py-2.5">
                            <span className={`text-xs font-medium ${
                              agent.status === 'online' ? 'text-green-400' :
                              agent.status === 'isolated' ? 'text-red-400' :
                              'text-[#7d92b0]'
                            }`}>
                              {AGENT_STATUS_LABEL[agent.status] ?? agent.status}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-xs text-[#7d92b0]">
                            {(groupsData?.data ?? []).find(g => g.id === agent.group_id)?.name ?? '—'}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="flex justify-end">
            <button
              onClick={() => setStep(2)}
              disabled={selectedIds.size === 0}
              className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium bg-[#e8002d] text-white rounded-lg hover:bg-[#c8001e] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              次へ: コマンド設定
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── Step 2: Command configuration ─────────────────────────── */}
      {step === 2 && (
        <div className="space-y-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <h2 className="text-base font-semibold text-white mb-4">Step 2 — コマンド設定</h2>

            {/* Command type grid */}
            <div className="grid grid-cols-3 gap-2 mb-6">
              <CommandButton cmd="scan" label="セキュリティスキャン" description="完全スキャンを実行" selected={command === 'scan'} onClick={() => setCommand('scan')} />
              <CommandButton cmd="isolate" label="ネットワーク隔離" description="エンドポイントを隔離" selected={command === 'isolate'} onClick={() => setCommand('isolate')} />
              <CommandButton cmd="unisolate" label="隔離解除" description="ネットワークへ復帰" selected={command === 'unisolate'} onClick={() => setCommand('unisolate')} />
              <CommandButton cmd="kill_process" label="プロセス終了" description="指定プロセスを強制終了" selected={command === 'kill_process'} onClick={() => setCommand('kill_process')} />
              <CommandButton cmd="run_script" label="スクリプト実行" description="任意スクリプトを実行" selected={command === 'run_script'} onClick={() => setCommand('run_script')} />
              <CommandButton cmd="update_policy" label="ポリシー更新" description="エージェントポリシーを変更" selected={command === 'update_policy'} onClick={() => setCommand('update_policy')} />
            </div>

            {/* Dynamic params */}
            {command === 'kill_process' && (
              <div className="space-y-2">
                <label className="block text-sm font-medium text-[#7d92b0]">終了するプロセス名</label>
                <input
                  value={processName}
                  onChange={e => setProcessName(e.target.value)}
                  placeholder="例: malware.exe"
                  className="w-full px-3 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]"
                />
              </div>
            )}

            {command === 'run_script' && (
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium text-[#7d92b0] mb-1">スクリプト内容</label>
                  <textarea
                    value={scriptContent}
                    onChange={e => setScriptContent(e.target.value)}
                    rows={6}
                    placeholder="#!/bin/bash&#10;echo 'Hello World'"
                    className="w-full px-3 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-white placeholder-[#3d5068] font-mono focus:outline-hidden focus:border-[#e8002d] resize-y"
                  />
                </div>
                <div className="flex items-center gap-3">
                  <label className="text-sm font-medium text-[#7d92b0]">タイムアウト (秒)</label>
                  <input
                    type="number"
                    value={scriptTimeout}
                    onChange={e => setScriptTimeout(e.target.value)}
                    min="1"
                    max="3600"
                    className="w-24 px-3 py-1.5 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-white focus:outline-hidden focus:border-[#e8002d]"
                  />
                </div>
              </div>
            )}

            {command === 'update_policy' && (
              <div className="space-y-2">
                <label className="block text-sm font-medium text-[#7d92b0]">ポリシーID</label>
                <input
                  value={policyId}
                  onChange={e => setPolicyId(e.target.value)}
                  placeholder="ポリシーIDを入力..."
                  className="w-full px-3 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#070d19] text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]"
                />
              </div>
            )}

            {/* Schedule option */}
            <div className="mt-6 pt-4 border-t border-[#1e2d42]">
              <p className="text-sm font-medium text-[#7d92b0] mb-3">実行タイミング</p>
              <div className="flex gap-3">
                <button
                  onClick={() => setSchedule('now')}
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm transition-colors ${
                    schedule === 'now'
                      ? 'border-[#e8002d] bg-[#e8002d]/10 text-white'
                      : 'border-[#1e2d42] bg-[#070d19] text-[#7d92b0] hover:border-[#7d92b0]/50'
                  }`}
                >
                  <Play className="w-4 h-4" />
                  今すぐ実行
                </button>
                <button
                  onClick={() => setSchedule('scheduled')}
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm transition-colors ${
                    schedule === 'scheduled'
                      ? 'border-[#e8002d] bg-[#e8002d]/10 text-white'
                      : 'border-[#1e2d42] bg-[#070d19] text-[#7d92b0] hover:border-[#7d92b0]/50'
                  }`}
                >
                  <Clock className="w-4 h-4" />
                  スケジュール実行
                </button>
              </div>
              {schedule === 'scheduled' && (
                <div className="mt-3">
                  <input
                    type="datetime-local"
                    value={scheduledAt}
                    onChange={e => setScheduledAt(e.target.value)}
                    className="text-sm border border-[#1e2d42] rounded-lg px-3 py-2 bg-[#070d19] text-white focus:outline-hidden focus:border-[#e8002d]"
                  />
                </div>
              )}
            </div>
          </div>

          <div className="flex justify-between">
            <button
              onClick={() => setStep(1)}
              className="px-4 py-2 text-sm text-[#7d92b0] bg-[#0d1220] border border-[#1e2d42] rounded-lg hover:bg-[#1e2d42] transition-colors"
            >
              ← 戻る
            </button>
            <button
              onClick={() => setStep(3)}
              disabled={
                (command === 'kill_process' && !processName.trim()) ||
                (command === 'run_script' && !scriptContent.trim()) ||
                (command === 'update_policy' && !policyId.trim()) ||
                (schedule === 'scheduled' && !scheduledAt)
              }
              className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium bg-[#e8002d] text-white rounded-lg hover:bg-[#c8001e] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              次へ: 確認
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* ── Step 3: Confirm & Execute ──────────────────────────────── */}
      {step === 3 && (
        <div className="space-y-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <h2 className="text-base font-semibold text-white mb-4">Step 3 — 確認と実行</h2>

            {/* Summary card */}
            <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 mb-4 space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
                  <Terminal className="w-5 h-5 text-[#e8002d]" />
                </div>
                <div>
                  <p className="text-base font-bold text-white">{commandLabels[command]}</p>
                  <p className="text-sm text-[#7d92b0]">
                    {selectedIds.size} エンドポイントに実行 ·{' '}
                    {schedule === 'now' ? '今すぐ実行' : `スケジュール: ${scheduledAt}`}
                  </p>
                </div>
              </div>

              {command === 'kill_process' && processName && (
                <div className="text-xs text-[#7d92b0]">
                  プロセス名: <span className="text-white font-mono">{processName}</span>
                </div>
              )}

              {command === 'run_script' && (
                <div className="text-xs text-[#7d92b0]">
                  タイムアウト: <span className="text-white">{scriptTimeout}秒</span>
                </div>
              )}

              {command === 'update_policy' && policyId && (
                <div className="text-xs text-[#7d92b0]">
                  ポリシーID: <span className="text-white font-mono">{policyId}</span>
                </div>
              )}

              {/* Selected endpoints list */}
              <div className="border-t border-[#1e2d42] pt-3">
                <p className="text-xs text-[#7d92b0] mb-2">対象エンドポイント ({selectedAgents.length})</p>
                <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                  {selectedAgents.map(a => (
                    <span key={a.id} className="text-xs px-2 py-0.5 bg-[#1e2d42] text-[#7d92b0] rounded-sm font-mono">
                      {a.hostname}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* Warning confirmation checkbox */}
            <div className="flex items-start gap-3 p-3 bg-amber-900/10 border border-amber-700/30 rounded-lg mb-4">
              <input
                id="confirm-check"
                type="checkbox"
                checked={confirmed}
                onChange={e => setConfirmed(e.target.checked)}
                className="mt-0.5 rounded-sm border-amber-700 bg-[#070d19] text-amber-500"
              />
              <label htmlFor="confirm-check" className="text-sm text-amber-200 cursor-pointer leading-snug">
                この操作の影響を理解しています。
                <span className="text-amber-400"> {selectedIds.size} 台のエンドポイントに「{commandLabels[command]}」を実行します。</span>
                この操作は取り消せない場合があります。
              </label>
            </div>

            <div className="flex justify-between items-center">
              <button
                onClick={() => { setStep(2); setConfirmed(false) }}
                className="px-4 py-2 text-sm text-[#7d92b0] bg-[#0d1220] border border-[#1e2d42] rounded-lg hover:bg-[#1e2d42] transition-colors"
              >
                ← 戻る
              </button>
              <button
                onClick={handleExecute}
                disabled={!confirmed || batchMutation.isPending}
                className="flex items-center gap-2 px-6 py-2.5 text-sm font-bold bg-[#e8002d] text-white rounded-lg hover:bg-[#c8001e] transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {batchMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                実行
              </button>
            </div>
          </div>

          {/* Results table */}
          {results.length > 0 && (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <div className="px-4 py-3 border-b border-[#1e2d42] bg-[#070d19]/60">
                <h3 className="text-sm font-semibold text-white">実行結果</h3>
                <div className="flex items-center gap-4 mt-1">
                  <span className="text-xs text-green-400">
                    成功: {results.filter(r => r.status === 'success').length}
                  </span>
                  <span className="text-xs text-red-400">
                    失敗: {results.filter(r => r.status === 'failed').length}
                  </span>
                  <span className="text-xs text-blue-400">
                    実行中: {results.filter(r => r.status === 'running').length}
                  </span>
                </div>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]/60">
                    <th className="text-left px-4 py-2.5 text-xs text-[#7d92b0] font-medium">エンドポイント</th>
                    <th className="text-left px-4 py-2.5 text-xs text-[#7d92b0] font-medium">ステータス</th>
                    <th className="text-left px-4 py-2.5 text-xs text-[#7d92b0] font-medium">詳細</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(r => (
                    <tr key={r.agent_id} className="border-b border-[#1e2d42]/40 last:border-0">
                      <td className="px-4 py-3 font-medium text-white font-mono text-sm">{r.hostname}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <ResultIcon status={r.status} />
                          <span className={`text-xs ${
                            r.status === 'success' ? 'text-green-400' :
                            r.status === 'failed' ? 'text-red-400' :
                            r.status === 'running' ? 'text-blue-400' :
                            'text-[#7d92b0]'
                          }`}>
                            {r.status === 'success' ? '成功' :
                             r.status === 'failed' ? '失敗' :
                             r.status === 'running' ? '実行中' :
                             r.status === 'pending' ? '待機中' : 'スキップ'}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0]">
                        {r.error ?? (r.status === 'success' ? 'コマンドが正常に完了しました' : '—')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function BatchCommandPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-[#070d19] p-6">
        <div className="space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-[#0d1220] rounded-xl border border-[#1e2d42] animate-pulse" />
          ))}
        </div>
      </div>
    }>
      <BatchCommandInner />
    </Suspense>
  )
}
