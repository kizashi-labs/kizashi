'use client'

import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useParams } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  ArrowLeft,
  Terminal,
  Monitor,
  Play,
  X,
  Copy,
  Download,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
  FileDown,
  FileUp,
  Cpu,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os?: string
  status?: string
  ip_address?: string
  platform?: string
  version?: string
  last_seen?: string
}

interface QueuedCommand {
  id: string
  agent_id: string
  session_id?: string
  command_type: string
  command: string
  args?: Record<string, unknown>
  status: string
  output?: string
  exit_code?: number
  created_by?: string
  created_at: string
  started_at?: string
  completed_at?: string
  timeout_at: string
}

interface CommandsResponse {
  commands: QueuedCommand[]
}

type CommandTab = 'shell' | 'file' | 'process'
type TimeoutOption = 10 | 30 | 60 | 120

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; cls: string; icon: React.ReactNode }> = {
    pending: {
      label: 'Pending',
      cls: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
      icon: <Loader2 className="w-3 h-3 animate-spin" />,
    },
    running: {
      label: 'Running',
      cls: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
      icon: <Loader2 className="w-3 h-3 animate-spin" />,
    },
    completed: {
      label: 'Completed',
      cls: 'bg-green-500/10 text-green-400 border border-green-500/30',
      icon: <CheckCircle className="w-3 h-3" />,
    },
    failed: {
      label: 'Failed',
      cls: 'bg-red-500/10 text-red-400 border border-red-500/30',
      icon: <XCircle className="w-3 h-3" />,
    },
    cancelled: {
      label: 'Cancelled',
      cls: 'bg-[#7d92b0]/10 text-[#7d92b0] border border-[#7d92b0]/30',
      icon: <X className="w-3 h-3" />,
    },
    timeout: {
      label: 'Timeout',
      cls: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
      icon: <AlertCircle className="w-3 h-3" />,
    },
  }

  const c = config[status] ?? {
    label: status,
    cls: 'bg-[#7d92b0]/10 text-[#7d92b0] border border-[#7d92b0]/30',
    icon: null,
  }

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${c.cls}`}>
      {c.icon}
      {c.label}
    </span>
  )
}

// ─── Duration helper ──────────────────────────────────────────────────────────

function calcDuration(cmd: QueuedCommand): string {
  if (!cmd.completed_at && !cmd.started_at) return '—'
  const start = cmd.started_at ? new Date(cmd.started_at) : new Date(cmd.created_at)
  const end = cmd.completed_at ? new Date(cmd.completed_at) : new Date()
  const ms = end.getTime() - start.getTime()
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return iso
  }
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AgentCommandsPage() {
  const { id: agentId } = useParams<{ id: string }>()
  const queryClient = useQueryClient()

  // UI state
  const [activeTab, setActiveTab] = useState<CommandTab>('shell')
  const [shellCmd, setShellCmd] = useState('')
  const [timeoutSec, setTimeoutSec] = useState<TimeoutOption>(30)
  const [fileAction, setFileAction] = useState<'download' | 'upload'>('download')
  const [filePath, setFilePath] = useState('')
  const [uploadPath, setUploadPath] = useState('')
  const [processAction, setProcessAction] = useState<'kill_pid' | 'kill_name'>('kill_pid')
  const [processTarget, setProcessTarget] = useState('')
  const [selectedCmdId, setSelectedCmdId] = useState<string | null>(null)
  const [expandedCmds, setExpandedCmds] = useState<Set<string>>(new Set())
  const [copyFeedback, setCopyFeedback] = useState(false)
  const terminalRef = useRef<HTMLPreElement>(null)

  // Fetch agent info
  const { data: agent } = useQuery<Agent>({
    queryKey: ['agent', agentId],
    queryFn: () => apiFetch<Agent>(`/api/v1/agents/${agentId}`),
    staleTime: 30_000,
  })

  // Fetch commands
  const {
    data: commandsData,
    isLoading: cmdsLoading,
    refetch: refetchCmds,
  } = useQuery<CommandsResponse>({
    queryKey: ['agent-commands', agentId],
    queryFn: () => apiFetch<CommandsResponse>(`/api/v1/agents/${agentId}/commands?limit=50`),
    refetchInterval: (query) => {
      const cmds = query.state.data?.commands ?? []
      const hasActive = cmds.some((c) => c.status === 'pending' || c.status === 'running')
      return hasActive ? 3000 : false
    },
  })

  const commands = commandsData?.commands ?? []
  const selectedCmd = commands.find((c) => c.id === selectedCmdId) ?? null

  // Auto-select first command
  useEffect(() => {
    if (!selectedCmdId && commands.length > 0) {
      setSelectedCmdId(commands[0].id)
    }
  }, [commands, selectedCmdId])

  // Execute mutation
  const executeMutation = useMutation({
    mutationFn: async (payload: { command_type: string; command: string; args?: Record<string, unknown> }) => {
      return apiFetch<QueuedCommand>(`/api/v1/agents/${agentId}/commands`, {
        method: 'POST',
        body: JSON.stringify(payload),
      })
    },
    onSuccess: (newCmd) => {
      queryClient.invalidateQueries({ queryKey: ['agent-commands', agentId] })
      setSelectedCmdId(newCmd.id)
      // Reset inputs
      setShellCmd('')
      setFilePath('')
      setUploadPath('')
      setProcessTarget('')
    },
  })

  // Cancel mutation
  const cancelMutation = useMutation({
    mutationFn: (cmdId: string) =>
      apiFetch<{ message: string }>(`/api/v1/agents/${agentId}/commands/${cmdId}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agent-commands', agentId] })
    },
  })

  // Build execute payload
  const handleExecute = useCallback(() => {
    if (activeTab === 'shell') {
      if (!shellCmd.trim()) return
      executeMutation.mutate({
        command_type: 'shell',
        command: shellCmd.trim(),
        args: { timeout_seconds: timeoutSec },
      })
    } else if (activeTab === 'file') {
      if (!filePath.trim()) return
      if (fileAction === 'download') {
        executeMutation.mutate({
          command_type: 'file_get',
          command: filePath.trim(),
        })
      } else {
        executeMutation.mutate({
          command_type: 'file_put',
          command: uploadPath.trim(),
          args: { destination: filePath.trim() },
        })
      }
    } else if (activeTab === 'process') {
      if (!processTarget.trim()) return
      executeMutation.mutate({
        command_type: processAction === 'kill_pid' ? 'process_kill' : 'process_kill',
        command: processTarget.trim(),
        args: { method: processAction },
      })
    }
  }, [activeTab, shellCmd, timeoutSec, fileAction, filePath, uploadPath, processAction, processTarget, executeMutation])

  // Copy output
  const handleCopyOutput = useCallback(() => {
    if (!selectedCmd?.output) return
    navigator.clipboard.writeText(selectedCmd.output).then(() => {
      setCopyFeedback(true)
      setTimeout(() => setCopyFeedback(false), 2000)
    })
  }, [selectedCmd])

  // Download output as .txt
  const handleDownloadOutput = useCallback(() => {
    if (!selectedCmd?.output) return
    const blob = new Blob([selectedCmd.output], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `command-output-${selectedCmd.id.slice(0, 8)}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }, [selectedCmd])

  // Toggle command expansion in history
  const toggleExpand = useCallback((id: string) => {
    setExpandedCmds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  // Keyboard shortcut: Ctrl+Enter to execute
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault()
        handleExecute()
      }
    },
    [handleExecute]
  )

  // OS badge
  const osBadge = agent?.os ?? agent?.platform ?? 'Unknown OS'

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      {/* ─── Header ──────────────────────────────────────────── */}
      <div className="border-b border-[#1e2d42] bg-[#0d1220]">
        <div className="max-w-screen-2xl mx-auto px-6 py-4">
          <div className="flex items-center gap-3 mb-4">
            <Link
              href={`/endpoints/${agentId}`}
              className="text-[#7d92b0] hover:text-white transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </Link>
            <Terminal className="w-5 h-5 text-[#e8002d]" />
            <h1 className="text-lg font-semibold">Agent Commands</h1>
          </div>

          {/* Agent info bar */}
          <div className="flex items-center gap-6 flex-wrap">
            <div className="flex items-center gap-2">
              <Monitor className="w-4 h-4 text-[#7d92b0]" />
              <span className="font-mono text-sm text-white">
                {agent?.hostname ?? agentId}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#7d92b0]">OS:</span>
              <span className="text-xs text-white">{osBadge}</span>
            </div>
            {agent?.ip_address && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[#7d92b0]">IP:</span>
                <span className="text-xs font-mono text-white">{agent.ip_address}</span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#7d92b0]">Status:</span>
              <span
                className={`text-xs font-medium ${
                  agent?.status === 'online'
                    ? 'text-green-400'
                    : agent?.status === 'offline'
                    ? 'text-red-400'
                    : 'text-[#7d92b0]'
                }`}
              >
                {agent?.status ?? 'unknown'}
              </span>
            </div>
            {agent?.version && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[#7d92b0]">Agent v{agent.version}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ─── Main Layout ─────────────────────────────────────── */}
      <div className="max-w-screen-2xl mx-auto px-6 py-6 grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* ── Left column: input + history ── */}
        <div className="xl:col-span-1 flex flex-col gap-6">
          {/* Command Input Panel */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#e8002d]" />
              <span className="text-sm font-semibold text-white">Command Input</span>
            </div>

            {/* Tab selector */}
            <div className="flex border-b border-[#1e2d42]">
              {(['shell', 'file', 'process'] as CommandTab[]).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`flex-1 py-2 text-xs font-medium capitalize transition-colors ${
                    activeTab === tab
                      ? 'text-white border-b-2 border-[#e8002d] bg-[#e8002d]/5'
                      : 'text-[#7d92b0] hover:text-white'
                  }`}
                >
                  {tab === 'shell' ? 'Shell' : tab === 'file' ? 'File' : 'Process'}
                </button>
              ))}
            </div>

            <div className="p-4 space-y-4">
              {/* Shell tab */}
              {activeTab === 'shell' && (
                <>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">
                      Command <span className="text-[#7d92b0]/60">(Ctrl+Enter to execute)</span>
                    </label>
                    <textarea
                      value={shellCmd}
                      onChange={(e) => setShellCmd(e.target.value)}
                      onKeyDown={handleKeyDown}
                      placeholder="ps aux"
                      rows={4}
                      className="w-full bg-black border border-[#1e2d42] rounded-lg px-3 py-2 font-mono text-sm text-[#22c55e] placeholder-[#7d92b0]/40 focus:outline-none focus:border-[#e8002d]/50 resize-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-2">Timeout</label>
                    <div className="grid grid-cols-4 gap-2">
                      {([10, 30, 60, 120] as TimeoutOption[]).map((t) => (
                        <button
                          key={t}
                          onClick={() => setTimeoutSec(t)}
                          className={`py-1.5 text-xs rounded-lg border transition-colors ${
                            timeoutSec === t
                              ? 'bg-[#e8002d]/10 border-[#e8002d]/50 text-[#e8002d]'
                              : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/50 hover:text-white'
                          }`}
                        >
                          {t}s
                        </button>
                      ))}
                    </div>
                  </div>
                </>
              )}

              {/* File tab */}
              {activeTab === 'file' && (
                <>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() => setFileAction('download')}
                      className={`flex items-center justify-center gap-2 py-2 text-xs rounded-lg border transition-colors ${
                        fileAction === 'download'
                          ? 'bg-[#e8002d]/10 border-[#e8002d]/50 text-[#e8002d]'
                          : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/50 hover:text-white'
                      }`}
                    >
                      <FileDown className="w-3.5 h-3.5" />
                      Download
                    </button>
                    <button
                      onClick={() => setFileAction('upload')}
                      className={`flex items-center justify-center gap-2 py-2 text-xs rounded-lg border transition-colors ${
                        fileAction === 'upload'
                          ? 'bg-[#e8002d]/10 border-[#e8002d]/50 text-[#e8002d]'
                          : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/50 hover:text-white'
                      }`}
                    >
                      <FileUp className="w-3.5 h-3.5" />
                      Upload
                    </button>
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">
                      {fileAction === 'download' ? 'Remote File Path' : 'Local File Path'}
                    </label>
                    <input
                      type="text"
                      value={filePath}
                      onChange={(e) => setFilePath(e.target.value)}
                      placeholder={fileAction === 'download' ? '/etc/passwd' : '/local/file.txt'}
                      className="w-full bg-black border border-[#1e2d42] rounded-lg px-3 py-2 font-mono text-sm text-[#22c55e] placeholder-[#7d92b0]/40 focus:outline-none focus:border-[#e8002d]/50"
                    />
                  </div>
                  {fileAction === 'upload' && (
                    <div>
                      <label className="block text-xs text-[#7d92b0] mb-1">Destination Path (on agent)</label>
                      <input
                        type="text"
                        value={uploadPath}
                        onChange={(e) => setUploadPath(e.target.value)}
                        placeholder="/tmp/uploaded.txt"
                        className="w-full bg-black border border-[#1e2d42] rounded-lg px-3 py-2 font-mono text-sm text-[#22c55e] placeholder-[#7d92b0]/40 focus:outline-none focus:border-[#e8002d]/50"
                      />
                    </div>
                  )}
                </>
              )}

              {/* Process tab */}
              {activeTab === 'process' && (
                <>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() => setProcessAction('kill_pid')}
                      className={`flex items-center justify-center gap-2 py-2 text-xs rounded-lg border transition-colors ${
                        processAction === 'kill_pid'
                          ? 'bg-[#e8002d]/10 border-[#e8002d]/50 text-[#e8002d]'
                          : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/50 hover:text-white'
                      }`}
                    >
                      <Cpu className="w-3.5 h-3.5" />
                      Kill by PID
                    </button>
                    <button
                      onClick={() => setProcessAction('kill_name')}
                      className={`flex items-center justify-center gap-2 py-2 text-xs rounded-lg border transition-colors ${
                        processAction === 'kill_name'
                          ? 'bg-[#e8002d]/10 border-[#e8002d]/50 text-[#e8002d]'
                          : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/50 hover:text-white'
                      }`}
                    >
                      <Cpu className="w-3.5 h-3.5" />
                      Kill by Name
                    </button>
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">
                      {processAction === 'kill_pid' ? 'PID' : 'Process Name'}
                    </label>
                    <input
                      type="text"
                      value={processTarget}
                      onChange={(e) => setProcessTarget(e.target.value)}
                      placeholder={processAction === 'kill_pid' ? '1234' : 'malware.exe'}
                      className="w-full bg-black border border-[#1e2d42] rounded-lg px-3 py-2 font-mono text-sm text-[#22c55e] placeholder-[#7d92b0]/40 focus:outline-none focus:border-[#e8002d]/50"
                    />
                  </div>
                </>
              )}

              {/* Execute button */}
              <button
                onClick={handleExecute}
                disabled={executeMutation.isPending}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-[#e8002d] hover:bg-[#e8002d]/90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold transition-colors"
              >
                {executeMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                {executeMutation.isPending ? 'Sending...' : 'Execute'}
              </button>

              {executeMutation.isError && (
                <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                  {(executeMutation.error as Error)?.message ?? 'Failed to execute command'}
                </p>
              )}
            </div>
          </div>

          {/* Command History Panel */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden flex flex-col">
            <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#7d92b0]" />
                <span className="text-sm font-semibold text-white">Command History</span>
                {commands.length > 0 && (
                  <span className="text-xs bg-[#1e2d42] text-[#7d92b0] px-1.5 py-0.5 rounded-full">
                    {commands.length}
                  </span>
                )}
              </div>
              <button
                onClick={() => refetchCmds()}
                className="text-[#7d92b0] hover:text-white transition-colors"
                title="Refresh"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="overflow-y-auto max-h-[480px]">
              {cmdsLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-5 h-5 animate-spin text-[#7d92b0]" />
                </div>
              ) : commands.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-[#7d92b0]">
                  <Terminal className="w-8 h-8 mb-2 opacity-40" />
                  <p className="text-sm">No commands yet</p>
                </div>
              ) : (
                <ul className="divide-y divide-[#1e2d42]">
                  {commands.map((cmd) => {
                    const isExpanded = expandedCmds.has(cmd.id)
                    const isSelected = selectedCmdId === cmd.id

                    return (
                      <li key={cmd.id}>
                        <div
                          className={`px-4 py-3 cursor-pointer transition-colors ${
                            isSelected
                              ? 'bg-[#e8002d]/5 border-l-2 border-[#e8002d]'
                              : 'hover:bg-[#1e2d42]/30 border-l-2 border-transparent'
                          }`}
                          onClick={() => {
                            setSelectedCmdId(cmd.id)
                          }}
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex items-start gap-2 min-w-0 flex-1">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  toggleExpand(cmd.id)
                                }}
                                className="mt-0.5 text-[#7d92b0] hover:text-white flex-shrink-0"
                              >
                                {isExpanded ? (
                                  <ChevronDown className="w-3.5 h-3.5" />
                                ) : (
                                  <ChevronRight className="w-3.5 h-3.5" />
                                )}
                              </button>
                              <div className="min-w-0">
                                <p className="font-mono text-xs text-white truncate">
                                  {cmd.command.length > 50
                                    ? cmd.command.slice(0, 50) + '…'
                                    : cmd.command}
                                </p>
                                <div className="flex items-center gap-2 mt-1">
                                  <span className="text-xs text-[#7d92b0]">
                                    {fmtTime(cmd.created_at)}
                                  </span>
                                  <span className="text-xs text-[#7d92b0]">
                                    {calcDuration(cmd)}
                                  </span>
                                  <span className="text-xs text-[#7d92b0] capitalize">
                                    {cmd.command_type}
                                  </span>
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              <StatusBadge status={cmd.status} />
                              {cmd.status === 'pending' && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    cancelMutation.mutate(cmd.id)
                                  }}
                                  disabled={cancelMutation.isPending}
                                  className="text-[#7d92b0] hover:text-red-400 transition-colors"
                                  title="キャンセル"
                                >
                                  <X className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          </div>

                          {/* Expanded output inline */}
                          {isExpanded && cmd.output && (
                            <div
                              className="mt-2 ml-5"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <pre className="bg-black border border-[#1e2d42] rounded-lg p-2 font-mono text-[#22c55e] text-xs overflow-x-auto whitespace-pre-wrap max-h-32 overflow-y-auto">
                                {cmd.output}
                              </pre>
                            </div>
                          )}
                          {isExpanded && !cmd.output && cmd.status === 'completed' && (
                            <p className="mt-2 ml-5 text-xs text-[#7d92b0] italic">
                              No output
                            </p>
                          )}
                        </div>
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* ── Right column: output panel ── */}
        <div className="xl:col-span-2 flex flex-col gap-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden flex flex-col h-full min-h-[600px]">
            <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <Terminal className="w-4 h-4 text-[#22c55e] flex-shrink-0" />
                {selectedCmd ? (
                  <>
                    <span className="font-mono text-sm text-white truncate">
                      {selectedCmd.command.length > 80
                        ? selectedCmd.command.slice(0, 80) + '…'
                        : selectedCmd.command}
                    </span>
                    <StatusBadge status={selectedCmd.status} />
                  </>
                ) : (
                  <span className="text-sm text-[#7d92b0]">Select a command to view output</span>
                )}
              </div>

              {selectedCmd?.output && (
                <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                  <button
                    onClick={handleCopyOutput}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/50 rounded-lg transition-colors"
                  >
                    <Copy className="w-3 h-3" />
                    {copyFeedback ? 'Copied!' : 'Copy'}
                  </button>
                  <button
                    onClick={handleDownloadOutput}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#7d92b0]/50 rounded-lg transition-colors"
                  >
                    <Download className="w-3 h-3" />
                    Download
                  </button>
                </div>
              )}
            </div>

            {/* Command metadata strip */}
            {selectedCmd && (
              <div className="px-4 py-2 border-b border-[#1e2d42] bg-[#070d19]/50 flex items-center gap-4 flex-wrap text-xs text-[#7d92b0]">
                <span>
                  ID: <span className="font-mono text-white/70">{selectedCmd.id.slice(0, 8)}…</span>
                </span>
                <span>
                  Type: <span className="text-white/70 capitalize">{selectedCmd.command_type}</span>
                </span>
                <span>
                  Created: <span className="text-white/70">{fmtTime(selectedCmd.created_at)}</span>
                </span>
                {selectedCmd.started_at && (
                  <span>
                    Started: <span className="text-white/70">{fmtTime(selectedCmd.started_at)}</span>
                  </span>
                )}
                {selectedCmd.completed_at && (
                  <span>
                    Completed:{' '}
                    <span className="text-white/70">{fmtTime(selectedCmd.completed_at)}</span>
                  </span>
                )}
                <span>
                  Duration: <span className="text-white/70">{calcDuration(selectedCmd)}</span>
                </span>
                {selectedCmd.exit_code !== undefined && selectedCmd.exit_code !== null && (
                  <span>
                    Exit:{' '}
                    <span
                      className={selectedCmd.exit_code === 0 ? 'text-green-400' : 'text-red-400'}
                    >
                      {selectedCmd.exit_code}
                    </span>
                  </span>
                )}
                {selectedCmd.created_by && (
                  <span>
                    By: <span className="text-white/70">{selectedCmd.created_by}</span>
                  </span>
                )}
              </div>
            )}

            {/* Terminal output */}
            <div className="flex-1 overflow-hidden relative">
              {!selectedCmd ? (
                <div className="flex flex-col items-center justify-center h-full text-[#7d92b0]">
                  <Terminal className="w-12 h-12 mb-3 opacity-20" />
                  <p className="text-sm">No command selected</p>
                  <p className="text-xs mt-1 opacity-60">
                    Execute a command or select one from history
                  </p>
                </div>
              ) : selectedCmd.status === 'pending' || selectedCmd.status === 'running' ? (
                <div className="flex flex-col items-center justify-center h-full text-[#7d92b0]">
                  <Loader2 className="w-8 h-8 mb-3 animate-spin text-[#22c55e]" />
                  <p className="text-sm">
                    {selectedCmd.status === 'pending'
                      ? 'Waiting for agent…'
                      : 'Command running on agent…'}
                  </p>
                  <p className="text-xs mt-1 opacity-60">Auto-refreshing every 3s</p>
                </div>
              ) : !selectedCmd.output ? (
                <div className="flex flex-col items-center justify-center h-full text-[#7d92b0]">
                  <Terminal className="w-8 h-8 mb-3 opacity-20" />
                  <p className="text-sm">
                    {selectedCmd.status === 'failed'
                      ? 'Command failed — no output'
                      : selectedCmd.status === 'cancelled'
                      ? 'Command was cancelled'
                      : selectedCmd.status === 'timeout'
                      ? 'Command timed out'
                      : 'No output returned'}
                  </p>
                </div>
              ) : (
                <pre
                  ref={terminalRef}
                  className="h-full bg-black font-mono text-[#22c55e] text-sm overflow-auto p-4 leading-relaxed"
                >
                  {/* Output with timestamp prefix on first line */}
                  <span className="text-[#7d92b0] select-none">
                    [{fmtTime(selectedCmd.completed_at ?? selectedCmd.created_at)}]{' '}
                  </span>
                  {selectedCmd.output}
                </pre>
              )}
            </div>

            {/* Bottom status bar */}
            <div className="px-4 py-2 border-t border-[#1e2d42] bg-[#070d19]/50 flex items-center justify-between text-xs text-[#7d92b0]">
              <div className="flex items-center gap-2">
                {selectedCmd?.output && (
                  <span>{selectedCmd.output.split('\n').length} lines</span>
                )}
                {selectedCmd?.output && (
                  <span>{(new TextEncoder().encode(selectedCmd.output).length / 1024).toFixed(1)} KB</span>
                )}
              </div>
              <div className="flex items-center gap-1">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#22c55e]" />
                <span>
                  {commands.some((c) => c.status === 'pending' || c.status === 'running')
                    ? 'Auto-refreshing'
                    : 'Ready'}
                </span>
              </div>
            </div>
          </div>

          {/* Quick stats row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              {
                label: 'Total',
                value: commands.length,
                cls: 'text-white',
              },
              {
                label: 'Pending',
                value: commands.filter((c) => c.status === 'pending').length,
                cls: 'text-yellow-400',
              },
              {
                label: 'Completed',
                value: commands.filter((c) => c.status === 'completed').length,
                cls: 'text-green-400',
              },
              {
                label: 'Failed',
                value: commands.filter(
                  (c) => c.status === 'failed' || c.status === 'timeout'
                ).length,
                cls: 'text-red-400',
              },
            ].map(({ label, value, cls }) => (
              <div
                key={label}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-4 py-3"
              >
                <p className="text-xs text-[#7d92b0] mb-1">{label}</p>
                <p className={`text-2xl font-bold tabular-nums ${cls}`}>{value}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
