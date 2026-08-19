'use client'

import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Video, Play, Flag, Download, X, Filter, AlertTriangle,
  Terminal, Monitor, Database, Globe, ChevronRight,
  Clock, User, Shield, RefreshCw, Wifi, Activity,
  Square, Eye, Search, Calendar,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type SessionType = 'ssh' | 'rdp' | 'database' | 'web_console'
type SessionStatus = 'active' | 'ended' | 'flagged'

interface SessionActivity {
  timestamp: string
  type: 'command' | 'action' | 'connection' | 'file_access'
  content: string
  suspicious?: boolean
}

interface PrivilegedSession {
  id: string
  session_id: string
  user: string
  user_account: string
  target_system: string
  session_type: SessionType
  start_time: string
  end_time?: string
  duration_seconds: number
  status: SessionStatus
  recording_size_mb: number
  risk_score: number
  bytes_transferred: number
  activity: SessionActivity[]
  flagged_reason?: string
}

interface SessionStats {
  active_sessions: number
  recorded_today: number
  flagged_sessions: number
  total_recording_gb: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (h > 0) return `${h}h ${m}m`
  return `${m}分`
}

function fmtSize(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`
  return `${mb.toFixed(1)} MB`
}

function fmtBytes(bytes: number): string {
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  return `${(bytes / 1_000).toFixed(0)} KB`
}

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

const SUSPICIOUS_PATTERNS = ['rm -rf', 'curl.*|.*bash', 'wget.*|.*sh', 'sudo su', 'passwd', 'nc -e', '/etc/shadow', 'chmod 777']

function isSuspicious(cmd: string): boolean {
  return SUSPICIOUS_PATTERNS.some(p => new RegExp(p, 'i').test(cmd))
}

const SESSION_TYPE_LABELS: Record<SessionType, string> = {
  ssh: 'SSH', rdp: 'RDP', database: 'DB', web_console: 'WebConsole',
}
const SESSION_TYPE_COLORS: Record<SessionType, string> = {
  ssh: 'bg-green-500/20 text-green-400 border-green-500/30',
  rdp: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  database: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  web_console: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
}
const SESSION_TYPE_ICONS: Record<SessionType, React.ComponentType<{ className?: string }>> = {
  ssh: Terminal, rdp: Monitor, database: Database, web_console: Globe,
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
      <p className="text-[#7d92b0] text-xs mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color ?? 'text-white'}`}>{value}</p>
      {sub && <p className="text-[#7d92b0] text-xs mt-1">{sub}</p>}
    </div>
  )
}

function SessionTypeBadge({ type }: { type: SessionType }) {
  const Icon = SESSION_TYPE_ICONS[type]
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium border ${SESSION_TYPE_COLORS[type]}`}>
      <Icon className="w-3 h-3" />
      {SESSION_TYPE_LABELS[type]}
    </span>
  )
}

function StatusBadge({ status }: { status: SessionStatus }) {
  if (status === 'active') return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/30">
      <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
      アクティブ
    </span>
  )
  if (status === 'flagged') return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/30">
      <Flag className="w-3 h-3" />
      フラグ
    </span>
  )
  return <span className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium bg-gray-500/20 text-gray-400 border border-gray-500/30">終了</span>
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden w-16">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-mono font-medium ${score >= 70 ? 'text-red-400' : score >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>
        {score}
      </span>
    </div>
  )
}

// ─── Playback Modal ───────────────────────────────────────────────────────────

function PlaybackModal({ session, onClose }: { session: PrivilegedSession; onClose: () => void }) {
  const [playing, setPlaying] = useState(false)
  const [playIdx, setPlayIdx] = useState(0)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const termRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (playing) {
      intervalRef.current = setInterval(() => {
        setPlayIdx(i => {
          if (i >= session.activity.length - 1) { setPlaying(false); return i }
          return i + 1
        })
      }, 600)
    } else if (intervalRef.current) {
      clearInterval(intervalRef.current)
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [playing, session.activity.length])

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [playIdx])

  const visibleActivity = session.activity.slice(0, playIdx + 1)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Play className="w-5 h-5 text-[#e8002d]" />
            <div>
              <h3 className="text-white font-semibold">セッション再生</h3>
              <p className="text-[#7d92b0] text-xs">{session.session_id} — {session.user}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-5 flex-1 overflow-hidden flex flex-col gap-4">
          {session.session_type === 'rdp' ? (
            <div className="flex-1 bg-[#1a2235] border border-[#1e2d42] rounded-lg flex items-center justify-center min-h-48">
              <div className="text-center text-[#7d92b0]">
                <Monitor className="w-12 h-12 mx-auto mb-3 opacity-40" />
                <p className="text-sm">RDPセッション録画</p>
                <p className="text-xs mt-1 opacity-60">映像再生: プレースホルダー</p>
                <p className="text-xs mt-1 opacity-40">実際のビデオファイルは storage から取得されます</p>
              </div>
            </div>
          ) : (
            <div
              ref={termRef}
              className="flex-1 bg-[#020609] border border-[#1e2d42] rounded-lg p-4 font-mono text-xs overflow-y-auto min-h-48 max-h-80 space-y-1"
            >
              <p className="text-green-400 mb-2">── セッション開始: {fmtTime(session.start_time)} ──</p>
              {visibleActivity.map((act, i) => (
                <div key={i} className={`flex gap-2 ${act.suspicious ? 'text-red-400' : 'text-green-300'}`}>
                  <span className="text-[#3d5068] shrink-0">{new Date(act.timestamp).toLocaleTimeString('ja-JP')}</span>
                  {act.suspicious && <span className="text-red-500 shrink-0">[!]</span>}
                  <span className="break-all">{act.type === 'command' ? `$ ${act.content}` : `> ${act.content}`}</span>
                </div>
              ))}
              {playing && <span className="inline-block w-2 h-3 bg-green-400 animate-pulse" />}
            </div>
          )}

          <div className="flex items-center gap-3">
            <button
              onClick={() => { setPlayIdx(0); setPlaying(true) }}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors"
            >
              <Play className="w-4 h-4" />最初から再生
            </button>
            {playing ? (
              <button onClick={() => setPlaying(false)} className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
                <Square className="w-4 h-4" />停止
              </button>
            ) : (
              <button onClick={() => setPlaying(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">
                <Play className="w-4 h-4" />再開
              </button>
            )}
            <span className="text-[#7d92b0] text-xs ml-auto">
              {playIdx + 1} / {session.activity.length} イベント
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Session Detail Panel ─────────────────────────────────────────────────────

function SessionDetailPanel({ session, onClose, onFlag }: {
  session: PrivilegedSession
  onClose: () => void
  onFlag: (id: string) => void
}) {
  const [showPlayback, setShowPlayback] = useState(false)

  const suspiciousCount = session.activity.filter(a => a.suspicious).length

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/40" onClick={onClose} />
      <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-xl bg-[#0d1220] border-l border-[#1e2d42] flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Video className="w-5 h-5 text-[#e8002d]" />
            <div>
              <h3 className="text-white font-semibold">{session.session_id}</h3>
              <p className="text-[#7d92b0] text-xs">{session.user}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Metadata */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 grid grid-cols-2 gap-3">
            {[
              ['ユーザー', session.user],
              ['アカウント', session.user_account],
              ['対象システム', session.target_system],
              ['セッション種別', SESSION_TYPE_LABELS[session.session_type]],
              ['開始時刻', fmtTime(session.start_time)],
              ['継続時間', fmtDuration(session.duration_seconds)],
              ['データ転送量', fmtBytes(session.bytes_transferred)],
              ['録画サイズ', fmtSize(session.recording_size_mb)],
            ].map(([k, v]) => (
              <div key={k}>
                <p className="text-[#7d92b0] text-xs">{k}</p>
                <p className="text-white text-sm font-medium mt-0.5">{v}</p>
              </div>
            ))}
          </div>

          {/* Risk */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-white text-sm font-semibold">リスク指標</h4>
              <div className="flex items-center gap-2">
                <RiskBar score={session.risk_score} />
              </div>
            </div>
            {suspiciousCount > 0 && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-red-400 text-sm font-medium">{suspiciousCount} 件の不審なアクティビティ検出</p>
                  {session.flagged_reason && <p className="text-red-300/80 text-xs mt-1">{session.flagged_reason}</p>}
                </div>
              </div>
            )}
          </div>

          {/* Activity Timeline */}
          <div>
            <h4 className="text-white text-sm font-semibold mb-3">アクティビティタイムライン</h4>
            <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
              {session.activity.map((act, i) => (
                <div key={i} className={`flex gap-3 p-2.5 rounded-lg text-xs ${act.suspicious ? 'bg-red-500/10 border border-red-500/20' : 'bg-[#070d19] border border-[#1e2d42]'}`}>
                  <span className="text-[#3d5068] shrink-0 font-mono mt-0.5">
                    {new Date(act.timestamp).toLocaleTimeString('ja-JP')}
                  </span>
                  {act.suspicious && <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />}
                  <span className={`font-mono break-all leading-relaxed ${act.suspicious ? 'text-red-300' : 'text-[#a8c0d8]'}`}>
                    {act.type === 'command' ? `$ ${act.content}` : `> ${act.content}`}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="border-t border-[#1e2d42] px-5 py-4 flex items-center gap-3 flex-wrap">
          <button
            onClick={() => setShowPlayback(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors"
          >
            <Play className="w-4 h-4" />再生
          </button>
          {session.status !== 'flagged' && (
            <button
              onClick={() => onFlag(session.id)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-yellow-500/30 text-yellow-400 text-sm hover:bg-yellow-500/10 transition-colors"
            >
              <Flag className="w-4 h-4" />フラグ
            </button>
          )}
          <button className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors ml-auto">
            <Download className="w-4 h-4" />ログ出力
          </button>
        </div>
      </div>

      {showPlayback && <PlaybackModal session={session} onClose={() => setShowPlayback(false)} />}
    </>
  )
}

// ─── Typewriter Live Feed ─────────────────────────────────────────────────────

const LIVE_COMMANDS = [
  'ls -la /var/log/', 'ps aux | grep nginx', 'netstat -tulpn', 'df -h',
  'cat /etc/passwd', 'tail -f /var/log/auth.log', 'who', 'last -10',
  'find /tmp -newer /etc/passwd', 'curl -s http://169.254.169.254/latest/meta-data/',
  'id', 'uname -a', 'env | grep -i pass', 'history',
]

function LiveFeed({ session }: { session: PrivilegedSession }) {
  const [lines, setLines] = useState<string[]>([])
  const [current, setCurrent] = useState('')
  const [charIdx, setCharIdx] = useState(0)
  const [lineIdx, setLineIdx] = useState(0)
  const feedRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const cmd = LIVE_COMMANDS[lineIdx % LIVE_COMMANDS.length]
    if (charIdx < cmd.length) {
      const t = setTimeout(() => {
        setCurrent(cmd.slice(0, charIdx + 1))
        setCharIdx(c => c + 1)
      }, 50)
      return () => clearTimeout(t)
    } else {
      const t = setTimeout(() => {
        setLines(prev => [`$ ${cmd}`, ...prev.slice(0, 19)])
        setCurrent('')
        setCharIdx(0)
        setLineIdx(l => l + 1)
      }, 800)
      return () => clearTimeout(t)
    }
  }, [charIdx, lineIdx])

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = 0
  }, [lines])

  return (
    <div className="mt-3 bg-[#020609] border border-[#1e2d42] rounded-lg p-3 font-mono text-xs max-h-40 overflow-y-auto" ref={feedRef}>
      <p className="text-[#3d5068] mb-1">── ライブフィード: {session.user} @ {session.target_system} ──</p>
      <div className="text-green-400">
        $ {current}<span className="inline-block w-1.5 h-3 bg-green-400 animate-pulse ml-0.5" />
      </div>
      {lines.map((l, i) => (
        <div key={i} className={`mt-0.5 ${l.includes('passwd') || l.includes('meta-data') || l.includes('pass') ? 'text-red-400' : 'text-green-300/60'}`}>{l}</div>
      ))}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PrivilegedSessionsPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'list' | 'active'>('list')
  const [selectedSession, setSelectedSession] = useState<PrivilegedSession | null>(null)
  const [liveMonitor, setLiveMonitor] = useState(false)
  const [localSessions, setLocalSessions] = useState<PrivilegedSession[]>([])

  // Filters
  const [filterUser, setFilterUser] = useState('')
  const [filterTarget, setFilterTarget] = useState('')
  const [filterType, setFilterType] = useState<SessionType | 'all'>('all')
  const [filterDateFrom, setFilterDateFrom] = useState('')
  const [filterFlagged, setFilterFlagged] = useState(false)

  const { data: statsData } = useQuery<SessionStats>({
    queryKey: ['privileged-sessions-stats'],
    queryFn: () => apiFetch('/api/v1/admin/privileged-sessions/stats'),
    retry: false,
    staleTime: 30_000,
  })
  const EMPTY_SESSION_STATS: SessionStats = { active_sessions: 0, recorded_today: 0, flagged_sessions: 0, total_recording_gb: 0 }
  const stats = statsData ?? EMPTY_SESSION_STATS

  const { data: sessionsData } = useQuery<PrivilegedSession[]>({
    queryKey: ['privileged-sessions'],
    queryFn: () => apiFetch('/api/v1/admin/privileged-sessions'),
    retry: false,
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
  const sessions = sessionsData ?? localSessions

  const flagMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/privileged-sessions/${id}/flag`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['privileged-sessions'] }),
    onError: (_, id) => {
      setLocalSessions(prev => prev.map(s => s.id === id ? { ...s, status: 'flagged' as SessionStatus, flagged_reason: '手動フラグ設定' } : s))
      if (selectedSession?.id === id) setSelectedSession(prev => prev ? { ...prev, status: 'flagged', flagged_reason: '手動フラグ設定' } : null)
    },
  })

  const terminateMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/privileged-sessions/${id}/terminate`, { method: 'POST' }),
    onError: (_, id) => {
      setLocalSessions(prev => prev.map(s => s.id === id ? { ...s, status: 'ended' as SessionStatus } : s))
    },
  })

  const activeSessions = sessions.filter(s => s.status === 'active')
  const longRunningSessions = activeSessions.filter(s => s.duration_seconds > 4 * 3600)

  const filteredSessions = sessions.filter(s => {
    if (filterUser && !s.user.includes(filterUser) && !s.user_account.includes(filterUser)) return false
    if (filterTarget && !s.target_system.includes(filterTarget)) return false
    if (filterType !== 'all' && s.session_type !== filterType) return false
    if (filterFlagged && s.status !== 'flagged') return false
    if (filterDateFrom && new Date(s.start_time) < new Date(filterDateFrom)) return false
    return true
  })

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Video className="w-7 h-7 text-[#e8002d]" />
            特権セッション録画
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">特権アカウントセッションの録画・再生・監査</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="アクティブセッション" value={stats.active_sessions} sub="現在進行中" color="text-green-400" />
        <StatCard label="本日録画数" value={stats.recorded_today} sub="件" color="text-blue-400" />
        <StatCard label="フラグ済み" value={stats.flagged_sessions} sub="要確認" color={stats.flagged_sessions > 0 ? 'text-red-400' : 'text-white'} />
        <StatCard label="総録画サイズ" value={`${stats.total_recording_gb} GB`} sub="累計" color="text-white" />
      </div>

      {/* Long-running warning */}
      {longRunningSessions.length > 0 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-yellow-400 font-medium text-sm">長時間セッション検出</p>
            <p className="text-yellow-300/80 text-xs mt-1">
              {longRunningSessions.map(s => `${s.user} (${s.target_system})`).join('、')} — 4時間以上経過
            </p>
          </div>
        </div>
      )}

      {/* Main card */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        {/* Tabs */}
        <div className="flex border-b border-[#1e2d42]">
          {[
            { id: 'list', label: 'セッション一覧', count: sessions.length },
            { id: 'active', label: 'アクティブセッション', count: activeSessions.length },
          ].map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id as 'list' | 'active')}
              className={`px-5 py-3 text-sm font-medium transition-colors relative flex items-center gap-2 ${
                tab === t.id ? 'text-white border-b-2 border-[#e8002d]' : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {t.label}
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full ${
                t.id === 'active' ? 'bg-green-500 text-white' : 'bg-[#1e2d42] text-[#7d92b0]'
              }`}>{t.count}</span>
            </button>
          ))}
        </div>

        <div className="p-5">
          {/* ── Session List Tab ────────────────────────────────── */}
          {tab === 'list' && (
            <div className="space-y-4">
              {/* Filters */}
              <div className="flex flex-wrap gap-3 p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg">
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-[#7d92b0]" />
                  <span className="text-[#7d92b0] text-xs">フィルター:</span>
                </div>
                <input
                  type="text"
                  placeholder="ユーザー検索..."
                  value={filterUser}
                  onChange={e => setFilterUser(e.target.value)}
                  className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#e8002d] w-36"
                />
                <input
                  type="text"
                  placeholder="対象システム..."
                  value={filterTarget}
                  onChange={e => setFilterTarget(e.target.value)}
                  className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#e8002d] w-36"
                />
                <select
                  value={filterType}
                  onChange={e => setFilterType(e.target.value as SessionType | 'all')}
                  className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#e8002d]"
                >
                  <option value="all">全種別</option>
                  <option value="ssh">SSH</option>
                  <option value="rdp">RDP</option>
                  <option value="database">Database</option>
                  <option value="web_console">Web Console</option>
                </select>
                <input
                  type="date"
                  value={filterDateFrom}
                  onChange={e => setFilterDateFrom(e.target.value)}
                  className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#e8002d]"
                />
                <label className="flex items-center gap-2 text-[#7d92b0] text-xs cursor-pointer hover:text-white">
                  <input
                    type="checkbox"
                    checked={filterFlagged}
                    onChange={e => setFilterFlagged(e.target.checked)}
                    className="accent-[#e8002d]"
                  />
                  フラグのみ
                </label>
                {(filterUser || filterTarget || filterType !== 'all' || filterFlagged || filterDateFrom) && (
                  <button
                    onClick={() => { setFilterUser(''); setFilterTarget(''); setFilterType('all'); setFilterFlagged(false); setFilterDateFrom('') }}
                    className="text-xs text-[#e8002d] hover:underline ml-auto"
                  >
                    クリア
                  </button>
                )}
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['セッションID', 'ユーザー', '対象システム', '種別', '開始時刻', '継続時間', 'ステータス', '録画サイズ', 'リスクスコア', ''].map(h => (
                        <th key={h} className="text-left text-[#7d92b0] text-xs font-medium px-3 py-2 whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {filteredSessions.map(s => (
                      <tr
                        key={s.id}
                        className="hover:bg-[#0a1428]/60 transition-colors cursor-pointer"
                        onClick={() => setSelectedSession(s)}
                      >
                        <td className="px-3 py-2.5 font-mono text-xs text-[#7d92b0]">{s.session_id}</td>
                        <td className="px-3 py-2.5">
                          <div>
                            <p className="text-white text-xs font-medium">{s.user}</p>
                            <p className="text-[#7d92b0] text-[10px] font-mono">{s.user_account}</p>
                          </div>
                        </td>
                        <td className="px-3 py-2.5 text-[#a8c0d8] text-xs">{s.target_system}</td>
                        <td className="px-3 py-2.5"><SessionTypeBadge type={s.session_type} /></td>
                        <td className="px-3 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">{fmtTime(s.start_time)}</td>
                        <td className="px-3 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">{fmtDuration(s.duration_seconds)}</td>
                        <td className="px-3 py-2.5"><StatusBadge status={s.status} /></td>
                        <td className="px-3 py-2.5 text-[#7d92b0] text-xs">{fmtSize(s.recording_size_mb)}</td>
                        <td className="px-3 py-2.5 min-w-[100px]"><RiskBar score={s.risk_score} /></td>
                        <td className="px-3 py-2.5">
                          <button
                            onClick={e => { e.stopPropagation(); setSelectedSession(s) }}
                            className="flex items-center gap-1 px-2 py-1 rounded-sm text-xs bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"
                          >
                            <Eye className="w-3 h-3" />詳細
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {filteredSessions.length === 0 && (
                  <div className="text-center py-12 text-[#7d92b0]">
                    <Search className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">該当するセッションがありません</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Active Sessions Tab ──────────────────────────────── */}
          {tab === 'active' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-3">
                <div className="flex items-center gap-3">
                  <Activity className="w-4 h-4 text-green-400" />
                  <span className="text-white font-medium text-sm">{activeSessions.length} セッション稼働中</span>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <div
                    onClick={() => setLiveMonitor(v => !v)}
                    className={`w-10 h-5 rounded-full transition-colors relative ${liveMonitor ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
                  >
                    <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-all ${liveMonitor ? 'left-5' : 'left-0.5'}`} />
                  </div>
                  <span className="text-[#7d92b0] text-sm">ライブモニタリング</span>
                </label>
              </div>

              {activeSessions.length === 0 ? (
                <div className="text-center py-16 text-[#7d92b0]">
                  <Shield className="w-10 h-10 mx-auto mb-3 opacity-40" />
                  <p>アクティブなセッションはありません</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {activeSessions.map(s => {
                    const overFourHours = s.duration_seconds > 4 * 3600
                    return (
                      <div key={s.id} className={`border rounded-lg p-4 ${overFourHours ? 'border-yellow-500/40 bg-yellow-500/5' : 'border-[#1e2d42] bg-[#070d19]'}`}>
                        <div className="flex items-start justify-between gap-4 flex-wrap">
                          <div className="flex items-start gap-3">
                            <div className="w-9 h-9 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0">
                              <span className="text-xs font-bold text-white">{s.user[0]}</span>
                            </div>
                            <div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <p className="text-white font-medium text-sm">{s.user}</p>
                                <SessionTypeBadge type={s.session_type} />
                                <StatusBadge status={s.status} />
                                {overFourHours && (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                                    <AlertTriangle className="w-3 h-3" />4時間超過
                                  </span>
                                )}
                              </div>
                              <p className="text-[#7d92b0] text-xs mt-0.5 font-mono">{s.user_account}</p>
                              <div className="flex items-center gap-3 mt-1 text-xs text-[#7d92b0]">
                                <span>{s.target_system}</span>
                                <span>•</span>
                                <span className="font-mono">{fmtDuration(s.duration_seconds)}</span>
                                <span>•</span>
                                <span>{fmtBytes(s.bytes_transferred)} 転送</span>
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <RiskBar score={s.risk_score} />
                            <button
                              onClick={() => setSelectedSession(s)}
                              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"
                            >
                              <Eye className="w-3.5 h-3.5" />詳細
                            </button>
                            <button
                              onClick={() => { if (confirm(`${s.user} のセッションを終了しますか？`)) terminateMutation.mutate(s.id) }}
                              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors"
                            >
                              <Square className="w-3.5 h-3.5" />終了
                            </button>
                          </div>
                        </div>
                        {liveMonitor && <LiveFeed session={s} />}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Session detail panel */}
      {selectedSession && (
        <SessionDetailPanel
          session={selectedSession}
          onClose={() => setSelectedSession(null)}
          onFlag={id => flagMutation.mutate(id)}
        />
      )}
    </div>
  )
}
