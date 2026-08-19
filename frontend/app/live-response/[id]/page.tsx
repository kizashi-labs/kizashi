'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { apiFetch } from '@/lib/api'

const getToken = (): string =>
  typeof window !== 'undefined' ? (localStorage.getItem('edr_token') ?? '') : ''

interface CommandEntry {
  id: string
  input: string
  output: string
  exit_code: number | null
  status: 'pending' | 'running' | 'completed' | 'error' | 'timeout'
  timestamp: string
}

interface Session {
  id: string
  agent_id: string
  token: string
  status: string
  started_by: string
  created_at: string
}

export default function LiveResponsePage() {
  const params = useParams()
  const router = useRouter()
  const agentID = params.id as string

  const [session, setSession] = useState<Session | null>(null)
  const [commands, setCommands] = useState<CommandEntry[]>([])
  const [input, setInput] = useState('')
  const [cmdHistory, setCmdHistory] = useState<string[]>([])
  const [historyIdx, setHistoryIdx] = useState(-1)
  const [isConnected, setIsConnected] = useState(false)
  const [isCreating, setIsCreating] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pendingCmdIds, setPendingCmdIds] = useState<Set<string>>(new Set())

  const terminalRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const sessionRef = useRef<Session | null>(null)

  // Keep sessionRef in sync
  useEffect(() => {
    sessionRef.current = session
  }, [session])

  // Auto-scroll terminal to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [commands])

  // Create session on mount
  useEffect(() => {
    let cancelled = false

    async function createSession() {
      try {
        const data = await apiFetch<Session>(`/api/v1/agents/${agentID}/live-response/sessions`, {
          method: 'POST',
        })
        if (!cancelled) {
          setSession(data)
          setIsCreating(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'セッションの作成に失敗しました')
          setIsCreating(false)
        }
      }
    }

    createSession()
    return () => { cancelled = true }
  }, [agentID])

  // Poll for command output every 2 seconds once session is created
  useEffect(() => {
    if (!session) return

    setIsConnected(true)
    const sessionId = session.id

    async function poll() {
      try {
        const res = await apiFetch<{ data: Array<{
          id: string; input: string; output: string;
          exit_code: number | null; status: string; submitted_at: string;
        }> }>(`/api/v1/agents/${agentID}/live-response/sessions/${sessionId}/commands`)
        const cmds = res.data ?? []
        setCommands(cmds.map((c) => ({
          id: c.id,
          input: c.input,
          output: c.output ?? '',
          exit_code: c.exit_code ?? null,
          status: (c.status as CommandEntry['status']) ?? 'pending',
          timestamp: c.submitted_at,
        })))
        setPendingCmdIds((prev) => {
          const next = new Set(prev)
          cmds.forEach((c) => { if (c.status !== 'pending' && c.status !== 'running') next.delete(c.id) })
          return next
        })
      } catch {
        // keep polling even on error
      }
    }

    poll()
    const timer = setInterval(poll, 2000)
    return () => {
      clearInterval(timer)
      setIsConnected(false)
    }
  }, [session, agentID])

  // Focus input when terminal is clicked
  const handleTerminalClick = useCallback(() => {
    inputRef.current?.focus()
  }, [])

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      const trimmed = input.trim()
      if (!trimmed || !sessionRef.current) return

      setInput('')
      setHistoryIdx(-1)
      setCmdHistory(prev => [trimmed, ...prev].slice(0, 100))

      try {
        const cmd = await apiFetch<{ id: string; submitted_at?: string }>(
          `/api/v1/agents/${agentID}/live-response/sessions/${sessionRef.current.id}/exec`,
          {
            method: 'POST',
            body: JSON.stringify({ command: trimmed }),
          }
        )
        // Add optimistic pending entry
        setCommands((prev) => [
          ...prev,
          {
            id: cmd.id,
            input: trimmed,
            output: '',
            exit_code: null,
            status: 'pending',
            timestamp: cmd.submitted_at ?? new Date().toISOString(),
          },
        ])
        setPendingCmdIds((prev) => new Set(prev).add(cmd.id))
      } catch (err: unknown) {
        setCommands((prev) => [
          ...prev,
          {
            id: `local-err-${Date.now()}`,
            input: trimmed,
            output: err instanceof Error ? err.message : 'エラーが発生しました',
            exit_code: 1,
            status: 'error',
            timestamp: new Date().toISOString(),
          },
        ])
      }
    },
    [input, agentID]
  )

  const handleClose = useCallback(async () => {
    if (!sessionRef.current) {
      router.back()
      return
    }
    try {
      await apiFetch(
        `/api/v1/agents/${agentID}/live-response/sessions/${sessionRef.current.id}`,
        { method: 'DELETE' }
      )
    } catch {
      // best effort
    }
    router.back()
  }, [agentID, router])

  const statusColor = (status: CommandEntry['status']) => {
    switch (status) {
      case 'completed': return 'text-green-400'
      case 'error':
      case 'timeout': return 'text-red-400'
      case 'pending':
      case 'running': return 'text-yellow-400'
      default: return 'text-gray-400'
    }
  }

  const exitBadge = (cmd: CommandEntry) => {
    if (cmd.status === 'pending' || cmd.status === 'running') return null
    if (cmd.exit_code === null) return null
    const color = cmd.exit_code === 0 ? 'text-green-500' : 'text-red-500'
    return (
      <span className={`text-xs font-mono ml-2 ${color}`}>
        [exit {cmd.exit_code}]
      </span>
    )
  }

  // ── Loading state ──────────────────────────────────────────────────────────
  if (isCreating) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center">
        <div className="text-green-400 font-mono text-sm animate-pulse">
          セッションを初期化中...
        </div>
      </div>
    )
  }

  // ── Error state ────────────────────────────────────────────────────────────
  if (error) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-400 font-mono text-sm mb-4">{error}</p>
          <button
            onClick={() => router.back()}
            className="text-xs font-mono text-gray-500 hover:text-gray-300 border border-gray-700 px-4 py-2 rounded-sm"
          >
            戻る
          </button>
        </div>
      </div>
    )
  }

  // ── Terminal UI ────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#080c14] flex flex-col text-green-400 font-mono text-sm">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-[#1a2234] bg-[#0a0f1e]">
        <div className="flex items-center gap-3">
          {/* Traffic light dots */}
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/80" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <span className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <span className="text-gray-400 text-xs">
            live-response — agent:{agentID.slice(0, 8)}
          </span>
          {session && (
            <span className="text-gray-600 text-xs">
              session:{session.id.slice(0, 8)}
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          {/* Connection status */}
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-green-400 animate-pulse' : 'bg-gray-600'
              }`}
            />
            <span className="text-xs text-gray-500">
              {isConnected ? '接続中' : '未接続'}
            </span>
          </div>

          {/* Session status badge */}
          {session && (
            <span
              className={`text-xs px-2 py-0.5 rounded-sm border ${
                session.status === 'active'
                  ? 'border-green-800 text-green-400 bg-green-900/20'
                  : 'border-gray-700 text-gray-500 bg-gray-900/20'
              }`}
            >
              {session.status}
            </span>
          )}

          <button
            onClick={handleClose}
            className="text-xs text-red-400 hover:text-red-300 border border-red-900/50 hover:border-red-700 px-3 py-1 rounded-sm transition-colors"
          >
            セッション終了
          </button>
        </div>
      </div>

      {/* Terminal body */}
      <div
        ref={terminalRef}
        className="flex-1 overflow-y-auto p-4 cursor-text select-text"
        style={{ minHeight: 0 }}
        onClick={handleTerminalClick}
      >
        {/* Welcome banner */}
        <div className="text-green-600 text-xs mb-4 border-b border-green-900/30 pb-3">
          <div>FalconEDR Live Response Terminal</div>
          <div className="text-gray-600 mt-1">
            Agent: {agentID} | Session: {session?.id}
          </div>
          <div className="text-gray-600">
            接続先のエージェントがコマンドをポーリングします。応答に最大1秒かかります。
          </div>
        </div>

        {/* Command history */}
        {commands.length === 0 && (
          <div className="text-gray-600 text-xs mb-4">
            コマンドを入力してください...
          </div>
        )}

        {commands.map((cmd) => (
          <div key={cmd.id} className="mb-4">
            {/* Prompt line */}
            <div className="flex items-baseline gap-2">
              <span className="text-green-500 select-none">$</span>
              <span className="text-green-300">{cmd.input}</span>
              {exitBadge(cmd)}
            </div>

            {/* Output or spinner */}
            {(cmd.status === 'pending' || cmd.status === 'running') && (
              <div className="flex items-center gap-2 mt-1 ml-4 text-yellow-500 text-xs">
                <span className="animate-spin inline-block w-3 h-3 border border-yellow-500 border-t-transparent rounded-full" />
                <span>実行中...</span>
              </div>
            )}

            {cmd.output && (
              <pre
                className={`mt-1 ml-0 whitespace-pre-wrap break-words leading-relaxed text-xs ${
                  cmd.status === 'error' || cmd.status === 'timeout'
                    ? 'text-red-400'
                    : 'text-gray-300'
                }`}
              >
                {cmd.output}
              </pre>
            )}

            {!cmd.output &&
              cmd.status !== 'pending' &&
              cmd.status !== 'running' && (
                <div className={`mt-1 text-xs ${statusColor(cmd.status)}`}>
                  (出力なし)
                </div>
              )}
          </div>
        ))}

        {/* Pending command indicator */}
        {pendingCmdIds.size > 0 && (
          <div className="flex items-center gap-2 text-yellow-600 text-xs mb-2">
            <span className="animate-spin inline-block w-3 h-3 border border-yellow-600 border-t-transparent rounded-full" />
            <span>エージェントの応答を待っています...</span>
          </div>
        )}
      </div>

      {/* Input area */}
      <div className="border-t border-[#1a2234] bg-[#0a0f1e] px-4 py-3">
        <form onSubmit={handleSubmit} className="flex items-center gap-2">
          <span className="text-green-500 select-none shrink-0">$</span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => { setInput(e.target.value); setHistoryIdx(-1) }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowUp') {
                e.preventDefault()
                const next = Math.min(historyIdx + 1, cmdHistory.length - 1)
                setHistoryIdx(next)
                if (cmdHistory[next] !== undefined) setInput(cmdHistory[next])
              } else if (e.key === 'ArrowDown') {
                e.preventDefault()
                const next = Math.max(historyIdx - 1, -1)
                setHistoryIdx(next)
                setInput(next === -1 ? '' : (cmdHistory[next] ?? ''))
              }
            }}
            placeholder="コマンドを入力..."
            autoFocus
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            className={`flex-1 bg-transparent text-green-300 outline-hidden placeholder-gray-700 caret-green-400 text-sm font-mono ${
              !session ? 'opacity-50 cursor-not-allowed' : ''
            }`}
            disabled={!session}
          />
          <button
            type="submit"
            disabled={!input.trim() || !session}
            className="text-xs text-gray-600 hover:text-green-400 disabled:opacity-30 transition-colors px-2 py-1"
          >
            実行
          </button>
        </form>
      </div>
    </div>
  )
}
