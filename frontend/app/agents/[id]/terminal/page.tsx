'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { apiFetch, apiFetchList } from '@/lib/api'
import { Agent } from '@/types/api'
import {
  Terminal, Play, Square, ChevronLeft, Send, Trash2,
  Clock, CheckCircle, XCircle, Loader2, ChevronDown, ChevronUp,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────

interface LiveResponseSession {
  id: string
  agent_id: string
  token: string
  status: string
  started_by: string
  started_at: string
}

interface LiveResponseCommand {
  id: string
  command: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'timeout' | 'error'
  output?: string
  error?: string
  started_at: string
  completed_at?: string
}

type SessionState = 'idle' | 'connecting' | 'active' | 'disconnected'

interface TerminalEntry {
  id: string
  command: string
  output?: string
  error?: string
  pending?: boolean
}

// ─── Quick commands ───────────────────────────────────────────

const QUICK_COMMANDS = [
  { label: 'ls', cmd: 'ls -la' },
  { label: 'ps', cmd: 'ps aux' },
  { label: 'netstat', cmd: 'netstat -tulnp' },
  { label: 'whoami', cmd: 'whoami' },
  { label: 'pwd', cmd: 'pwd' },
  { label: 'df -h', cmd: 'df -h' },
  { label: 'uname -a', cmd: 'uname -a' },
]

// ─── Helpers ──────────────────────────────────────────────────

function statusBadge(status: Agent['status']) {
  switch (status) {
    case 'online':
      return (
        <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-green-900/40 border border-green-700/50 text-green-300">
          <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
          オンライン
        </span>
      )
    case 'isolated':
      return (
        <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-yellow-900/40 border border-yellow-700/50 text-yellow-300">
          <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
          隔離中
        </span>
      )
    case 'offline':
      return (
        <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-[#1e2d42] border border-[#2d4060] text-[#8899aa]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#3d5068]" />
          オフライン
        </span>
      )
    default:
      return (
        <span className="flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full bg-red-900/40 border border-red-700/50 text-red-300">
          <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
          エラー
        </span>
      )
  }
}

function sessionStateBadge(state: SessionState) {
  switch (state) {
    case 'idle':
      return <span className="text-xs text-[#5a6a7a]">セッション未開始</span>
    case 'connecting':
      return (
        <span className="flex items-center gap-1.5 text-xs text-yellow-400">
          <Loader2 className="w-3 h-3 animate-spin" />
          接続中...
        </span>
      )
    case 'active':
      return (
        <span className="flex items-center gap-1.5 text-xs text-green-400">
          <CheckCircle className="w-3 h-3" />
          接続済み
        </span>
      )
    case 'disconnected':
      return (
        <span className="flex items-center gap-1.5 text-xs text-[#5a6a7a]">
          <XCircle className="w-3 h-3" />
          切断済み
        </span>
      )
  }
}

// ─── Main component ───────────────────────────────────────────

export default function TerminalPage({ params }: { params: { id: string } }) {
  const router = useRouter()
  const agentId = params.id

  // Agent & session state
  const [agent, setAgent] = useState<Agent | null>(null)
  const [agentLoading, setAgentLoading] = useState(true)
  const [session, setSession] = useState<LiveResponseSession | null>(null)
  const [sessionState, setSessionState] = useState<SessionState>('idle')
  // セッションが生きているかを確認できていないこと。閉じられたかどうかは不明です。
  const [pollError, setPollError] = useState('')

  // Terminal state
  const [entries, setEntries] = useState<TerminalEntry[]>([])
  const [inputValue, setInputValue] = useState('')
  const [isExecuting, setIsExecuting] = useState(false)
  const [cmdHistory, setCmdHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [quickOpen, setQuickOpen] = useState(false)

  // Refs
  const terminalEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const sessionPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // ── Load agent info ──
  useEffect(() => {
    apiFetch<Agent>(`/api/v1/agents/${agentId}`)
      .then(setAgent)
      .catch(console.error)
      .finally(() => setAgentLoading(false))
  }, [agentId])

  // ── Auto-scroll ──
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [entries])

  // ── Session status polling ──
  const pollSessionStatus = useCallback(async () => {
    if (!session) return
    try {
      const sessions = await apiFetchList<LiveResponseSession>(
        `/api/v1/agents/${agentId}/live-response/sessions`
      )
      const current = sessions.find(s => s.id === session.id)
      if (current && current.status === 'closed') {
        setSessionState('disconnected')
        clearInterval(sessionPollRef.current ?? undefined)
      }
      setPollError('')
    } catch (e) {
      // 以前はここで黙って諦めていました。セッションが閉じられていても
      // 画面は「接続中」のまま、解析者は届かないコマンドを打ち続けます。
      setPollError(e instanceof Error ? e.message : String(e))
    }
  }, [agentId, session])

  useEffect(() => {
    if (sessionState === 'active' && session) {
      sessionPollRef.current = setInterval(pollSessionStatus, 5000)
    } else {
      if (sessionPollRef.current) clearInterval(sessionPollRef.current)
    }
    return () => {
      if (sessionPollRef.current) clearInterval(sessionPollRef.current)
    }
  }, [sessionState, session, pollSessionStatus])

  // ── Start session ──
  async function startSession() {
    setSessionState('connecting')
    try {
      const sess = await apiFetch<LiveResponseSession>(
        `/api/v1/agents/${agentId}/live-response/sessions`,
        { method: 'POST' }
      )
      setSession(sess)
      setSessionState('active')
      setEntries([
        {
          id: '__init__',
          command: '',
          output: `セッション開始 — agent: ${agentId}  session: ${sess.id}\nReady.`,
        },
      ])
      inputRef.current?.focus()
    } catch (err) {
      setSessionState('idle')
      console.error('セッション開始失敗:', err)
    }
  }

  // ── End session ──
  async function endSession() {
    if (!session) return
    // 終了はローカルでは必ず行います。サーバ側に伝わらなかった場合は
    // セッションが残るので、それは端末の出力に書きます。切断できない
    // ままここで止めると、利用者は画面から出られません。
    try {
      await apiFetch(
        `/api/v1/agents/${agentId}/live-response/sessions/${session.id}`,
        { method: 'DELETE' }
      )
    } catch (e) {
      setEntries(prev => [...prev, {
        id: `end-error-${prev.length}`,
        command: '',
        error: `セッションの終了をサーバに伝えられませんでした: ${e instanceof Error ? e.message : '不明なエラー'}。サーバ側にセッションが残っている可能性があります`,
      }])
    } finally {
      setSessionState('disconnected')
      setSession(null)
    }
  }

  // ── Send command ──
  async function sendCommand(cmd: string) {
    const trimmed = cmd.trim()
    if (!trimmed || !session || sessionState !== 'active' || isExecuting) return

    const entryId = `cmd-${Date.now()}`
    setEntries(prev => [...prev, { id: entryId, command: trimmed, pending: true }])
    setCmdHistory(prev => [trimmed, ...prev.slice(0, 99)])
    setHistoryIndex(-1)
    setInputValue('')
    setIsExecuting(true)

    try {
      // POST command (queue endpoint is .../exec; .../commands is GET-only)
      const posted = await apiFetch<LiveResponseCommand>(
        `/api/v1/agents/${agentId}/live-response/sessions/${session.id}/exec`,
        { method: 'POST', body: JSON.stringify({ command: trimmed }) }
      )

      // Poll for completion
      const deadline = Date.now() + 30_000
      let result: LiveResponseCommand = posted

      while (
        (result.status === 'pending' || result.status === 'running') &&
        Date.now() < deadline
      ) {
        await new Promise(r => setTimeout(r, 2000))
        try {
          const history = await apiFetchList<LiveResponseCommand>(
            `/api/v1/agents/${agentId}/live-response/sessions/${session.id}/commands`
          )
          const latest = history.find(c => c.id === posted.id)
          if (latest) result = latest
        } catch {
          break
        }
      }

      // Update entry with result
      setEntries(prev =>
        prev.map(e =>
          e.id === entryId
            ? {
                ...e,
                pending: false,
                output: result.output,
                error:
                  result.status === 'failed' || result.status === 'timeout' || result.status === 'error'
                    ? result.output || result.error || 'コマンドが失敗しました'
                    : result.status === 'pending' || result.status === 'running'
                    ? 'タイムアウト: コマンドの応答がありませんでした'
                    : undefined,
              }
            : e
        )
      )
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'コマンドの送信に失敗しました'
      setEntries(prev =>
        prev.map(e =>
          e.id === entryId ? { ...e, pending: false, error: message } : e
        )
      )
    } finally {
      setIsExecuting(false)
      inputRef.current?.focus()
    }
  }

  // ── Key handling ──
  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault()
      sendCommand(inputValue)
      return
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      const next = Math.min(historyIndex + 1, cmdHistory.length - 1)
      setHistoryIndex(next)
      setInputValue(cmdHistory[next] ?? '')
      return
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      const next = Math.max(historyIndex - 1, -1)
      setHistoryIndex(next)
      setInputValue(next === -1 ? '' : cmdHistory[next] ?? '')
    }
  }

  // ── Clear history ──
  function clearHistory() {
    setEntries(prev => prev.filter(e => e.id === '__init__'))
  }

  const hostname = agent?.hostname ?? agentId

  // ─────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full p-6 space-y-4 min-h-0">

      {/* ── Back link ── */}
      <div>
        <button
          onClick={() => router.push('/live-response')}
          className="flex items-center gap-1.5 text-sm text-[#8899aa] hover:text-white transition-colors"
        >
          <ChevronLeft className="w-4 h-4" />
          ライブレスポンス
        </button>
      </div>

      {/* ── Agent header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3 bg-[#111827] border border-[#1e2d42] rounded-xl px-5 py-3">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-green-400 shrink-0" />
          <div>
            {agentLoading ? (
              <div className="w-32 h-4 bg-[#1e2d42] rounded-sm animate-pulse" />
            ) : (
              <span className="font-semibold text-white text-base">{hostname}</span>
            )}
            <div className="flex items-center gap-2 mt-0.5">
              {agent && statusBadge(agent.status)}
              {sessionStateBadge(sessionState)}
              {pollError && (
                <span
                  role="alert"
                  title={pollError}
                  className="px-2 py-0.5 rounded-sm text-[11px] border border-amber-500/40 bg-amber-950/30 text-amber-300"
                >
                  接続状態を確認できていません
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Session controls */}
        <div className="flex items-center gap-2">
          {sessionState === 'idle' || sessionState === 'disconnected' ? (
            <button
              onClick={startSession}
              disabled={agentLoading || agent?.status !== 'online'}
              className="flex items-center gap-1.5 px-4 py-2 bg-green-900/40 hover:bg-green-900/70 border border-green-700/50 text-green-300 text-sm rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Play className="w-4 h-4" />
              セッションを開始
            </button>
          ) : sessionState === 'connecting' ? (
            <button disabled
              className="flex items-center gap-1.5 px-4 py-2 bg-yellow-900/20 border border-yellow-700/40 text-yellow-400 text-sm rounded-lg opacity-60 cursor-not-allowed">
              <Loader2 className="w-4 h-4 animate-spin" />
              接続中...
            </button>
          ) : (
            <button
              onClick={endSession}
              className="flex items-center gap-1.5 px-4 py-2 bg-red-900/30 hover:bg-red-900/50 border border-red-700/50 text-red-300 text-sm rounded-lg transition-colors"
            >
              <Square className="w-4 h-4" />
              セッションを終了
            </button>
          )}

          {entries.length > 1 && (
            <button
              onClick={clearHistory}
              title="コマンド履歴をクリア"
              className="flex items-center gap-1.5 px-3 py-2 bg-[#1e2d42] hover:bg-[#253647] border border-[#2d4060] text-[#8899aa] hover:text-white text-sm rounded-lg transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              コマンド履歴をクリア
            </button>
          )}
        </div>
      </div>

      {/* ── Quick commands (collapsible) ── */}
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl overflow-hidden">
        <button
          onClick={() => setQuickOpen(v => !v)}
          className="w-full flex items-center justify-between px-4 py-2.5 text-sm text-[#8899aa] hover:text-white transition-colors"
        >
          <span className="flex items-center gap-2">
            <Clock className="w-4 h-4" />
            クイックコマンド
          </span>
          {quickOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {quickOpen && (
          <div className="px-4 pb-3 flex flex-wrap gap-2 border-t border-[#1e2d42] pt-3">
            {QUICK_COMMANDS.map(({ label, cmd }) => (
              <button
                key={cmd}
                onClick={() => sendCommand(cmd)}
                disabled={sessionState !== 'active' || isExecuting}
                className="px-3 py-1 bg-[#0d1626] hover:bg-[#1a2840] border border-[#2d4060] text-green-400 hover:text-green-300 text-xs font-mono rounded-lg transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* ── Terminal window ── */}
      <div className="flex-1 flex flex-col bg-[#0a0f1a] border border-[#1a2535] rounded-xl overflow-hidden min-h-0" style={{ minHeight: '420px' }}>

        {/* Terminal title bar */}
        <div className="flex items-center gap-2 px-4 py-2.5 bg-[#0d1626] border-b border-[#1a2535] shrink-0">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/70" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/70" />
            <span className="w-3 h-3 rounded-full bg-green-500/70" />
          </div>
          <span className="text-xs text-[#5a6a7a] font-mono ml-2">
            terminal — {hostname}
          </span>
        </div>

        {/* Output area */}
        <div className="flex-1 overflow-y-auto px-5 py-4 font-mono text-sm space-y-3 min-h-0">

          {sessionState === 'idle' && (
            <p className="text-[#3d5068] text-sm">
              「セッションを開始」ボタンを押してリモートターミナルに接続してください。
            </p>
          )}

          {entries.map(entry => (
            <div key={entry.id} className="space-y-0.5">
              {/* Command line */}
              {entry.command && (
                <div className="flex items-start gap-2">
                  <span className="text-[#5a8a6a] select-none shrink-0">
                    [{hostname}]$
                  </span>
                  <span className="text-yellow-300 break-all">{entry.command}</span>
                </div>
              )}

              {/* Pending spinner */}
              {entry.pending && (
                <div className="flex items-center gap-2 text-[#5a6a7a] pl-0">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-green-600" />
                  <span className="text-xs">実行中...</span>
                </div>
              )}

              {/* Output */}
              {!entry.pending && entry.output && (
                <pre className="text-green-400 whitespace-pre-wrap break-all leading-relaxed pl-2 border-l-2 border-[#1a3028]">
                  {entry.output}
                </pre>
              )}

              {/* Error */}
              {!entry.pending && entry.error && (
                <pre className="text-red-400 whitespace-pre-wrap break-all leading-relaxed pl-2 border-l-2 border-[#3a1a1a]">
                  {entry.error}
                </pre>
              )}
            </div>
          ))}

          <div ref={terminalEndRef} />
        </div>

        {/* Input line */}
        <div className="shrink-0 border-t border-[#1a2535] bg-[#0a0f1a] px-4 py-3">
          {sessionState === 'active' ? (
            <div className="flex items-center gap-2">
              <span className="text-[#5a8a6a] font-mono text-sm select-none shrink-0">
                [{hostname}]$
              </span>
              <input
                ref={inputRef}
                type="text"
                value={inputValue}
                onChange={e => { setInputValue(e.target.value); setHistoryIndex(-1) }}
                onKeyDown={handleKeyDown}
                disabled={isExecuting}
                placeholder={isExecuting ? '実行中...' : 'コマンドを入力（↑↓ で履歴）'}
                className="flex-1 bg-transparent outline-hidden text-white font-mono text-sm placeholder-[#2d4060] caret-green-400 disabled:opacity-40"
                autoComplete="off"
                spellCheck={false}
              />
              <button
                onClick={() => sendCommand(inputValue)}
                disabled={isExecuting || !inputValue.trim()}
                className="p-1.5 text-[#5a6a7a] hover:text-green-400 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                title="送信 (Enter)"
              >
                {isExecuting
                  ? <Loader2 className="w-4 h-4 animate-spin" />
                  : <Send className="w-4 h-4" />
                }
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-[#3d5068] font-mono text-sm">
              <span className="select-none">[{hostname}]$</span>
              <span className="text-xs italic">
                {sessionState === 'connecting'
                  ? '接続中...'
                  : sessionState === 'disconnected'
                  ? 'セッションが切断されました'
                  : 'セッションを開始してください'}
              </span>
            </div>
          )}
        </div>
      </div>

    </div>
  )
}
