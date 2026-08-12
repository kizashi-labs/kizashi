'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useRouter } from 'next/navigation'
import { apiFetch, apiFetchList } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import { Agent } from '@/types/api'
import {
  Terminal, Monitor, Search, Wifi, WifiOff,
  ChevronRight, Clock, Shield, Play, Square,
  Copy, Trash2, List, LayoutTemplate, RefreshCw,
  CheckCircle2, XCircle, ChevronUp, ChevronDown,
  ArrowRight, Activity, User, Hash, History, ChevronLeft,
} from 'lucide-react'
import { formatDistanceToNow, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'

// ── Types ──────────────────────────────────────────────────────

interface AgentListResponse {
  data: Agent[]
  total: number
}

interface TerminalLine {
  id: string
  type: 'input' | 'output' | 'error' | 'system'
  content: string
  timestamp: Date
}

interface CommandHistoryEntry {
  id: string
  command: string
  hostname: string
  agentId: string
  timestamp: Date
  output: string
  isError: boolean
}

interface LiveSession {
  id: string
  agentId: string
  agentHostname: string
  agentOs: string
  startedAt: Date
  commandCount: number
  lastCommand?: string
  status: 'active' | 'idle' | 'closed'
}

// ── Constants ──────────────────────────────────────────────────

const TAB_COMPLETION_COMMANDS = [
  'ps aux', 'ps -ef', 'ps -axo pid,ppid,user,command',
  'ls', 'ls -la', 'ls /tmp', 'ls /var/log', 'ls /etc',
  'netstat -an', 'netstat -tulpn', 'netstat -rn',
  'whoami', 'id', 'hostname', 'uname -a', 'uname -r',
  'cat /etc/passwd', 'cat /etc/hosts', 'cat /etc/resolv.conf',
  'find / -name "*.sh" -perm +111', 'find /tmp -type f',
  'curl', 'wget', 'ping',
  'systemctl status', 'systemctl list-units',
  'journalctl -n 50', 'tail -f /var/log/syslog',
  'df -h', 'free -m', 'top -bn1', 'uptime',
  'last', 'lastlog', 'w',
  'iptables -L', 'ss -tulpn',
  'crontab -l', 'cat /etc/crontab',
  'lsof -i', 'lsof -p',
  'env', 'printenv',
]

const COMMAND_TEMPLATES = [
  { category: 'プロセス', commands: [
    { label: 'プロセス一覧', cmd: 'ps aux' },
    { label: '詳細プロセス', cmd: 'ps -axo pid,ppid,user,command' },
    { label: 'トップ (1回)', cmd: 'top -bn1 | head -30' },
  ]},
  { category: 'ネットワーク', commands: [
    { label: 'ネット接続', cmd: 'netstat -tulpn' },
    { label: 'ソケット', cmd: 'ss -tulpn' },
    { label: 'ルーティング', cmd: 'netstat -rn' },
    { label: 'ファイアウォール', cmd: 'iptables -L -n' },
  ]},
  { category: 'ファイル', commands: [
    { label: '/tmp 一覧', cmd: 'ls -la /tmp' },
    { label: 'ログ', cmd: 'ls -la /var/log' },
    { label: '隠しファイル', cmd: 'find /home -name ".*" -type f' },
    { label: 'SUID', cmd: 'find / -perm -4000 -type f 2>/dev/null' },
  ]},
  { category: 'システム', commands: [
    { label: 'ユーザー情報', cmd: 'id && whoami' },
    { label: 'システム情報', cmd: 'uname -a' },
    { label: 'ディスク使用', cmd: 'df -h' },
    { label: 'メモリ', cmd: 'free -m' },
    { label: 'ログイン履歴', cmd: 'last -n 20' },
    { label: 'Cron', cmd: 'crontab -l' },
  ]},
  { category: '永続性', commands: [
    { label: 'スタートアップ', cmd: 'systemctl list-units --type=service --state=running' },
    { label: 'Crontab', cmd: 'cat /etc/crontab' },
    { label: '環境変数', cmd: 'env' },
  ]},
]

// ── Helpers ─────────────────────────────────────────────────────

function statusDot(status: Agent['status']) {
  switch (status) {
    case 'online':   return 'bg-green-400'
    case 'isolated': return 'bg-yellow-400'
    case 'offline':  return 'bg-[#3d5068]'
    default:         return 'bg-red-400'
  }
}

function statusLabel(status: Agent['status']) {
  switch (status) {
    case 'online':   return 'オンライン'
    case 'isolated': return '隔離中'
    case 'offline':  return 'オフライン'
    default:         return 'エラー'
  }
}

function osBadge(os: string) {
  if (os === 'windows') return 'bg-blue-900/40 text-blue-300 border-blue-700/50'
  if (os === 'linux')   return 'bg-orange-900/40 text-orange-300 border-orange-700/50'
  return 'bg-purple-900/40 text-purple-300 border-purple-700/50'
}

function generateId() {
  return Math.random().toString(36).slice(2, 9)
}

// ── Terminal Component ─────────────────────────────────────────

function TerminalPanel({
  hostname,
  agentId,
  onClose,
  onCommandRun,
  canWrite = true,
}: {
  hostname: string
  agentId: string
  onClose: () => void
  onCommandRun?: (entry: Omit<CommandHistoryEntry, 'id'>) => void
  canWrite?: boolean
}) {
  const [lines, setLines] = useState<TerminalLine[]>([
    {
      id: generateId(),
      type: 'system',
      content: `セッションを開始しています… (${hostname})`,
      timestamp: new Date(),
    },
    {
      id: generateId(),
      type: 'system',
      content: 'Kizashi Live Response — すべての操作は監査ログに記録されます',
      timestamp: new Date(),
    },
  ])
  const [input, setInput] = useState('')
  const [history, setHistory] = useState<string[]>([])
  const [historyIdx, setHistoryIdx] = useState(-1)
  const [completionHints, setCompletionHints] = useState<string[]>([])
  const [isRunning, setIsRunning] = useState(false)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [lines])

  // Establish a real live-response session against the agent. Commands are run
  // through this session (the agent polls and executes them) — not the legacy
  // stub /live-response/:id/execute endpoint which never actually ran anything.
  useEffect(() => {
    let cancelled = false
    let createdSessionId: string | null = null
    ;(async () => {
      try {
        const sess = await apiFetch<{ id: string }>(
          `/api/v1/agents/${agentId}/live-response/sessions`,
          { method: 'POST' },
        )
        if (cancelled) return
        createdSessionId = sess.id
        setSessionId(sess.id)
        setLines(l => [...l, { id: generateId(), type: 'system', content: `セッション確立: ${sess.id}`, timestamp: new Date() }])
      } catch {
        if (cancelled) return
        setLines(l => [...l, { id: generateId(), type: 'error', content: 'セッションの確立に失敗しました。エージェントがオンラインか確認してください。', timestamp: new Date() }])
      }
    })()
    return () => {
      cancelled = true
      if (createdSessionId) {
        apiFetch(`/api/v1/agents/${agentId}/live-response/sessions/${createdSessionId}`, { method: 'DELETE' }).catch(() => {})
      }
    }
  }, [agentId])

  function getCompletions(value: string) {
    if (!value.trim()) return []
    return TAB_COMPLETION_COMMANDS.filter(c => c.startsWith(value)).slice(0, 5)
  }

  function handleInputChange(val: string) {
    setInput(val)
    setCompletionHints(getCompletions(val))
    setHistoryIdx(-1)
  }

  async function runCommand(cmd: string) {
    if (!cmd.trim() || isRunning) return
    if (!sessionId) {
      setLines(l => [...l, { id: generateId(), type: 'error', content: 'セッションが確立していません。', timestamp: new Date() }])
      return
    }
    const trimmed = cmd.trim()
    setHistory(h => [trimmed, ...h.slice(0, 49)])
    setHistoryIdx(-1)
    setInput('')
    setCompletionHints([])
    setIsRunning(true)

    // Add input line
    setLines(l => [...l, {
      id: generateId(),
      type: 'input',
      content: trimmed,
      timestamp: new Date(),
    }])

    try {
      // Queue the command on the session (POST .../exec); the agent polls,
      // executes and posts the result back. Poll the command list (GET
      // .../commands) until it completes (max 30s).
      type LRCommand = { id: string; status: string; output?: string }
      const posted = await apiFetch<LRCommand>(
        `/api/v1/agents/${agentId}/live-response/sessions/${sessionId}/exec`,
        { method: 'POST', body: JSON.stringify({ command: trimmed }) },
      )
      let result = posted
      const deadline = Date.now() + 30_000
      while ((result.status === 'pending' || result.status === 'running') && Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 2000))
        try {
          const cmds = await apiFetchList<LRCommand>(
            `/api/v1/agents/${agentId}/live-response/sessions/${sessionId}/commands`,
          )
          const latest = cmds.find(c => c.id === posted.id)
          if (latest) result = latest
        } catch {
          break
        }
      }

      const done = result.status === 'completed'
      const stillPending = result.status === 'pending' || result.status === 'running'
      const outputText = stillPending
        ? 'タイムアウト: コマンドの応答がありませんでした'
        : (result.output && result.output.length > 0
            ? result.output
            : done ? '(出力なし)' : 'コマンドが失敗しました')
      setLines(l => [...l, {
        id: generateId(),
        type: done ? 'output' : 'error',
        content: outputText,
        timestamp: new Date(),
      }])
      onCommandRun?.({ command: trimmed, hostname, agentId, timestamp: new Date(), output: outputText, isError: !done })
    } catch {
      setLines(l => [...l, { id: generateId(), type: 'error', content: 'コマンドの送信に失敗しました。エージェントとの接続を確認してください。', timestamp: new Date() }])
    } finally {
      setIsRunning(false)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      runCommand(input)
      return
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      const nextIdx = Math.min(historyIdx + 1, history.length - 1)
      setHistoryIdx(nextIdx)
      setInput(history[nextIdx] ?? '')
      setCompletionHints([])
      return
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      const nextIdx = Math.max(historyIdx - 1, -1)
      setHistoryIdx(nextIdx)
      setInput(nextIdx === -1 ? '' : history[nextIdx] ?? '')
      setCompletionHints([])
      return
    }
    if (e.key === 'Tab') {
      e.preventDefault()
      const hints = getCompletions(input)
      if (hints.length === 1) {
        setInput(hints[0])
        setCompletionHints([])
      } else {
        setCompletionHints(hints)
      }
      return
    }
    if (e.key === 'c' && e.ctrlKey) {
      if (isRunning) setIsRunning(false)
      setLines(l => [...l, { id: generateId(), type: 'system', content: '^C', timestamp: new Date() }])
      setInput('')
      setCompletionHints([])
      return
    }
    if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault()
      setLines([])
      return
    }
  }

  function clearTerminal() {
    setLines([])
  }

  function copyOutput() {
    const text = lines.map(l => {
      if (l.type === 'input') return `$ ${l.content}`
      return l.content
    }).join('\n')
    navigator.clipboard.writeText(text)
  }

  const lineColor = {
    input:  'text-[#22c55e]',
    output: 'text-[#e2e8f4]',
    error:  'text-red-400',
    system: 'text-[#7d92b0]',
  }

  return (
    <div className="flex flex-col h-full bg-black border border-[#1e2d42] rounded-xl overflow-hidden font-mono">
      {/* Terminal Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#0d1220] border-b border-[#1e2d42]">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <span className="text-xs text-[#7d92b0]">
            live-response@{hostname}
          </span>
          {isRunning && (
            <span className="flex items-center gap-1 text-xs text-yellow-400">
              <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
              実行中...
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button onClick={copyOutput} className="p-1 text-[#3d5068] hover:text-[#7d92b0] transition-colors" title="出力をコピー">
            <Copy className="w-3.5 h-3.5" />
          </button>
          <button onClick={clearTerminal} className="p-1 text-[#3d5068] hover:text-[#7d92b0] transition-colors" title="クリア">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          <button onClick={onClose} className="p-1 text-[#3d5068] hover:text-red-400 transition-colors ml-1" title="セッション終了">
            <Square className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Output area */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-4 py-3 space-y-0.5 min-h-[300px] max-h-[400px] text-xs"
        onClick={() => inputRef.current?.focus()}
      >
        {lines.map(line => (
          <div key={line.id} className="leading-relaxed">
            {line.type === 'input' ? (
              <div className="flex items-start gap-2">
                <span className="text-[#22c55e] flex-shrink-0">[{hostname}]$</span>
                <span className="text-[#22c55e] whitespace-pre-wrap break-all">{line.content}</span>
              </div>
            ) : (
              <pre className={`whitespace-pre-wrap break-all ${lineColor[line.type]}`}>{line.content}</pre>
            )}
          </div>
        ))}
        {isRunning && (
          <div className="flex items-center gap-2 text-yellow-400 text-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
            コマンド実行中...
          </div>
        )}
      </div>

      {/* Tab completion hints */}
      {completionHints.length > 0 && (
        <div className="px-4 py-1 bg-[#0d1220] border-t border-[#1e2d42] flex flex-wrap gap-2">
          {completionHints.map(hint => (
            <button
              key={hint}
              onClick={() => { setInput(hint); setCompletionHints([]); inputRef.current?.focus() }}
              className="text-xs text-[#7d92b0] hover:text-white px-2 py-0.5 rounded bg-[#1e2d42] hover:bg-[#2d3d52] transition-colors"
            >
              {hint}
            </button>
          ))}
        </div>
      )}

      {/* Input row */}
      <div className="flex items-center gap-2 px-4 py-2 border-t border-[#1e2d42] bg-black">
        <span className="text-[#22c55e] text-xs flex-shrink-0">[{hostname}]$</span>
        <input
          ref={inputRef}
          value={input}
          onChange={e => handleInputChange(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isRunning || !canWrite}
          className="flex-1 bg-transparent text-[#22c55e] text-xs outline-none caret-[#22c55e] placeholder-[#3d5068]"
          placeholder={canWrite ? "コマンドを入力 (Tab: 補完, ↑↓: 履歴)" : "コマンド実行には書き込み権限が必要です"}
          autoFocus
          spellCheck={false}
          autoComplete="off"
        />
      </div>
    </div>
  )
}

// ── Session Card ────────────────────────────────────────────────

function SessionCard({ session, onResume, onClose }: { session: LiveSession; onResume: () => void; onClose: () => void }) {
  const duration = formatDistanceToNow(session.startedAt, { locale: ja })
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 hover:border-green-700/40 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-white text-sm font-semibold">{session.agentHostname}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className={`text-xs px-1.5 py-0.5 rounded border ${osBadge(session.agentOs)}`}>{session.agentOs}</span>
            <span className={`flex items-center gap-1 text-xs ${
              session.status === 'active' ? 'text-green-400' : session.status === 'idle' ? 'text-yellow-400' : 'text-[#3d5068]'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                session.status === 'active' ? 'bg-green-400 animate-pulse' : session.status === 'idle' ? 'bg-yellow-400' : 'bg-[#3d5068]'
              }`} />
              {session.status === 'active' ? 'アクティブ' : session.status === 'idle' ? 'アイドル' : 'クローズ'}
            </span>
          </div>
        </div>
        <button onClick={onClose} className="text-[#3d5068] hover:text-red-400 transition-colors p-1">
          <XCircle className="w-4 h-4" />
        </button>
      </div>
      <div className="grid grid-cols-2 gap-2 mb-3">
        <div className="bg-[#070d19] rounded-lg p-2">
          <p className="text-[10px] text-[#3d5068] mb-0.5">継続時間</p>
          <p className="text-xs text-[#7d92b0] flex items-center gap-1"><Clock className="w-3 h-3" />{duration}</p>
        </div>
        <div className="bg-[#070d19] rounded-lg p-2">
          <p className="text-[10px] text-[#3d5068] mb-0.5">コマンド数</p>
          <p className="text-xs text-[#7d92b0] flex items-center gap-1"><Hash className="w-3 h-3" />{session.commandCount}</p>
        </div>
      </div>
      {session.lastCommand && (
        <div className="bg-[#070d19] rounded-lg p-2 mb-3">
          <p className="text-[10px] text-[#3d5068] mb-0.5">最後のコマンド</p>
          <code className="text-xs text-[#22c55e]">{session.lastCommand}</code>
        </div>
      )}
      <button
        onClick={onResume}
        className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-green-900/30 border border-green-700/40 text-green-300 text-xs rounded-lg hover:bg-green-900/50 transition-colors"
      >
        <Terminal className="w-3.5 h-3.5" />
        セッションを再開
      </button>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────

export default function LiveResponsePage() {
  const router = useRouter()
  const canWrite = useCanWrite()
  const [activeTab, setActiveTab] = useState<'agents' | 'sessions' | 'templates' | 'history'>('agents')
  const [commandHistory, setCommandHistory] = useState<CommandHistoryEntry[]>([])
  const [search, setSearch] = useState('')
  const [onlineOnly, setOnlineOnly] = useState(true)
  const [activeAgentId, setActiveAgentId] = useState<string | null>(null)
  const [activeHostname, setActiveHostname] = useState<string>('')
  // Sessions opened in this page (no fabricated initial data).
  const [sessions, setSessions] = useState<LiveSession[]>([])

  const { data, isLoading } = useQuery<AgentListResponse>({
    queryKey: ['agents-lr', onlineOnly],
    queryFn: () => {
      const params = new URLSearchParams({ per_page: '200' })
      if (onlineOnly) params.set('status', 'online')
      return apiFetch(`/api/v1/agents?${params}`)
    },
    refetchInterval: 15000,
  })

  const agents = (data?.data ?? []).filter(a =>
    !search || a.hostname.toLowerCase().includes(search.toLowerCase()) ||
    (a.ip_addresses ?? []).some(ip => ip.includes(search))
  )

  function startSession(agent: Agent) {
    const existing = sessions.find(s => s.agentId === agent.id && s.status !== 'closed')
    if (existing) {
      setActiveAgentId(agent.id)
      setActiveHostname(agent.hostname)
      return
    }
    const newSession: LiveSession = {
      id: `sess-${generateId()}`,
      agentId: agent.id,
      agentHostname: agent.hostname,
      agentOs: agent.os_type,
      startedAt: new Date(),
      commandCount: 0,
      lastCommand: undefined,
      status: 'active',
    }
    setSessions(s => [newSession, ...s])
    setActiveAgentId(agent.id)
    setActiveHostname(agent.hostname)
  }

  function closeSession(sessionId: string) {
    setSessions(s => s.map(sess => sess.id === sessionId ? { ...sess, status: 'closed' as const } : sess))
    if (sessions.find(s => s.id === sessionId)?.agentId === activeAgentId) {
      setActiveAgentId(null)
    }
  }

  function resumeSession(session: LiveSession) {
    setActiveAgentId(session.agentId)
    setActiveHostname(session.agentHostname)
    setSessions(s => s.map(sess => sess.id === session.id ? { ...sess, status: 'active' as const } : sess))
  }

  const activeSessions = sessions.filter(s => s.status !== 'closed')
  const tabs = [
    { id: 'agents' as const,    label: 'エージェント', icon: Monitor,        count: agents.length },
    { id: 'sessions' as const,  label: 'セッション',   icon: Activity,       count: activeSessions.length },
    { id: 'templates' as const, label: 'テンプレート', icon: LayoutTemplate,  count: COMMAND_TEMPLATES.length },
    { id: 'history' as const,   label: '履歴',         icon: History,         count: commandHistory.length },
  ]

  return (
    <div className="p-6 space-y-6 min-h-screen bg-[#070d19]">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Terminal className="w-6 h-6 text-green-400" />
            ライブレスポンス
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            エンドポイントへのリモートターミナルセッション
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-[#5a6a7a]">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            {data?.total ?? 0} エンドポイント
          </div>
        </div>
      </div>

      {/* Info banner */}
      <div className="flex items-start gap-3 bg-green-900/10 border border-green-800/30 rounded-xl px-4 py-3">
        <Terminal className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-green-300/80 leading-relaxed">
          ライブレスポンスはエンドポイントへの直接ターミナルアクセスを提供します。
          エージェントはコマンドをポーリングして実行します（最大1秒の遅延）。
          すべての操作は監査ログに記録されます。Tab補完・コマンド履歴 (↑↓) をご利用ください。
        </p>
      </div>

      {/* Main layout: left panel + terminal */}
      <div className="flex gap-4">
        {/* Left Panel */}
        <div className="flex-shrink-0 space-y-3" style={{ width: 280 }}>
          {/* Tabs */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, background: '#0d1220', border: '1px solid #1e2d42', borderRadius: 12, padding: 4 }}>
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 12px', borderRadius: 8, fontSize: 12, fontWeight: 500,
                  cursor: 'pointer', width: '100%', textAlign: 'left',
                  background: activeTab === tab.id ? 'rgba(20,83,45,0.5)' : 'transparent',
                  color: activeTab === tab.id ? '#86efac' : '#7d92b0',
                  border: activeTab === tab.id ? '1px solid rgba(21,128,61,0.5)' : '1px solid transparent',
                  transition: 'all 0.15s',
                }}
              >
                <tab.icon style={{ width: 14, height: 14, flexShrink: 0 }} />
                <span style={{ whiteSpace: 'nowrap', flex: 1 }}>{tab.label}</span>
                <span style={{
                  fontSize: 10, padding: '2px 6px', borderRadius: 999,
                  background: activeTab === tab.id ? 'rgba(21,128,61,0.4)' : '#1e2d42',
                  color: activeTab === tab.id ? '#bbf7d0' : '#7d92b0',
                }}>{tab.count}</span>
              </button>
            ))}
          </div>

          {/* Tab: Agents */}
          {activeTab === 'agents' && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
                  <input
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    placeholder="ホスト名・IPで検索..."
                    className="w-full pl-8 pr-3 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-white text-xs placeholder-[#5a6a7a] focus:outline-none focus:border-green-500/50"
                  />
                </div>
                <button
                  onClick={() => setOnlineOnly(v => !v)}
                  className={`p-2 rounded-lg border text-xs transition-colors ${
                    onlineOnly
                      ? 'bg-green-900/40 border-green-700/50 text-green-300'
                      : 'bg-[#0d1220] border-[#1e2d42] text-[#8899aa] hover:text-white'
                  }`}
                >
                  {onlineOnly ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
                </button>
              </div>

              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="w-6 h-6 border-2 border-green-500 border-t-transparent rounded-full animate-spin" />
                </div>
              ) : agents.length === 0 ? (
                <div className="flex flex-col items-center py-8 text-[#5a6a7a]">
                  <Monitor className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-xs">{onlineOnly ? 'オンラインのエンドポイントなし' : 'エンドポイントなし'}</p>
                </div>
              ) : (
                <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
                  {agents.map(agent => {
                    const canConnect = agent.status === 'online'
                    const isSelected = activeAgentId === agent.id
                    return (
                      <div
                        key={agent.id}
                        className={`bg-[#0d1220] border rounded-xl px-3 py-2.5 flex items-center gap-3 transition-all cursor-pointer ${
                          isSelected
                            ? 'border-green-500/60 bg-green-900/10'
                            : canConnect
                            ? 'border-[#1e2d42] hover:border-green-700/40 hover:bg-[#0f1c2e]'
                            : 'border-[#1e2d42] opacity-50 cursor-not-allowed'
                        }`}
                        onClick={() => canConnect && startSession(agent)}
                      >
                        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${statusDot(agent.status)} ${agent.status === 'online' ? 'animate-pulse' : ''}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-white text-xs font-semibold truncate">{agent.hostname}</p>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <span className={`text-[10px] px-1 py-0.5 rounded border ${osBadge(agent.os_type)}`}>{agent.os_type}</span>
                            <span className="text-[10px] text-[#5a6a7a] truncate">
                              {(() => {
                                const ips = agent.ip_addresses ?? []
                                const privateRanges = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
                                return ips.find(ip => !privateRanges.test(ip)) ?? ips[0] ?? '—'
                              })()}
                            </span>
                          </div>
                        </div>
                        {canConnect && (
                          <Terminal className={`w-3.5 h-3.5 flex-shrink-0 ${isSelected ? 'text-green-400' : 'text-[#3d5068]'}`} />
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {/* Tab: Sessions */}
          {activeTab === 'sessions' && (
            <div className="space-y-2">
              {activeSessions.length === 0 ? (
                <div className="flex flex-col items-center py-8 text-[#5a6a7a]">
                  <Activity className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-xs">アクティブなセッションなし</p>
                </div>
              ) : (
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {activeSessions.map(session => (
                    <SessionCard
                      key={session.id}
                      session={session}
                      onResume={() => resumeSession(session)}
                      onClose={() => closeSession(session.id)}
                    />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab: History */}
          {activeTab === 'history' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#5a6a7a]">{commandHistory.length} 件のコマンド</span>
                {commandHistory.length > 0 && (
                  <button
                    onClick={() => setCommandHistory([])}
                    className="text-xs text-red-400 hover:text-red-300 transition-colors flex items-center gap-1"
                  >
                    <Trash2 className="w-3 h-3" />
                    クリア
                  </button>
                )}
              </div>
              {commandHistory.length === 0 ? (
                <div className="flex flex-col items-center py-8 text-[#5a6a7a]">
                  <History className="w-8 h-8 mb-2 opacity-30" />
                  <p className="text-xs">コマンド履歴がありません</p>
                </div>
              ) : (
                <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
                  {commandHistory.slice().reverse().map(entry => (
                    <div
                      key={entry.id}
                      className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3 space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <code className={`text-xs font-mono flex-1 truncate ${entry.isError ? 'text-red-400' : 'text-[#22c55e]'}`}>
                          $ {entry.command}
                        </code>
                        <button
                          onClick={() => navigator.clipboard.writeText(entry.command)}
                          className="text-[#3d5068] hover:text-[#7d92b0] transition-colors flex-shrink-0"
                          title="コマンドをコピー"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-[#3d5068]">
                        <span className="font-mono">{entry.hostname}</span>
                        <span>·</span>
                        <span>{entry.timestamp.toLocaleTimeString('ja-JP')}</span>
                      </div>
                      {entry.output && (
                        <pre className="text-[10px] text-[#5a6a7a] font-mono bg-black/40 rounded px-2 py-1 truncate max-h-12 overflow-hidden">
                          {entry.output.slice(0, 120)}{entry.output.length > 120 ? '…' : ''}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab: Templates */}
          {activeTab === 'templates' && (
            <div className="space-y-3 max-h-[500px] overflow-y-auto">
              {COMMAND_TEMPLATES.map(group => (
                <div key={group.category} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-3">
                  <p className="text-xs text-[#7d92b0] font-medium mb-2 flex items-center gap-1.5">
                    <LayoutTemplate className="w-3 h-3" />
                    {group.category}
                  </p>
                  <div className="space-y-1">
                    {group.commands.map(({ label, cmd }) => (
                      <button
                        key={cmd}
                        disabled={!activeAgentId}
                        onClick={() => {
                          // This would send to terminal - in real impl use a callback
                          if (!activeAgentId) return
                        }}
                        title={cmd}
                        className="w-full text-left flex items-center justify-between gap-2 px-2 py-1.5 rounded-lg bg-[#070d19] border border-[#1e2d42]/60 hover:border-green-700/40 hover:bg-green-900/10 transition-colors group disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        <span className="text-xs text-[#7d92b0] group-hover:text-green-300 truncate">{label}</span>
                        <code className="text-[10px] text-[#3d5068] group-hover:text-[#7d92b0] truncate max-w-[120px]">{cmd}</code>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Terminal Panel */}
        <div className="flex-1 min-w-0">
          {activeAgentId ? (
            <TerminalPanel
              hostname={activeHostname}
              agentId={activeAgentId}
              canWrite={canWrite}
              onCommandRun={entry => setCommandHistory(h => [...h, { ...entry, id: generateId() }])}
              onClose={() => {
                setSessions(s => s.map(sess =>
                  sess.agentId === activeAgentId ? { ...sess, status: 'idle' as const } : sess
                ))
                setActiveAgentId(null)
              }}
            />
          ) : (
            <div className="h-full min-h-[400px] bg-black border border-[#1e2d42] rounded-xl flex flex-col items-center justify-center text-center p-8">
              <div className="w-16 h-16 rounded-full bg-green-900/20 border border-green-700/30 flex items-center justify-center mb-4">
                <Terminal className="w-8 h-8 text-green-400/60" />
              </div>
              <p className="text-white font-semibold mb-2">ターミナル待機中</p>
              <p className="text-[#5a6a7a] text-sm max-w-xs">
                左のパネルからオンラインのエンドポイントを選択してセッションを開始してください
              </p>
              <div className="mt-6 grid grid-cols-2 gap-2 text-xs text-[#3d5068] font-mono">
                {['Tab: 補完', '↑↓: 履歴', 'Ctrl+C: 中断', 'Ctrl+L: クリア'].map(hint => (
                  <span key={hint} className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded">{hint}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
