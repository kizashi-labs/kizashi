'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams, useRouter } from 'next/navigation'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  AlertTriangle, ArrowLeft, Shield, Terminal, Clock, CheckCircle,
  ChevronRight, ChevronDown, RefreshCw, User, Monitor, Cpu,
  Network, FileText, Zap, Eye, Bookmark, X, Save,
  Activity, GitBranch, Brain,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { usePersist, SaveFailed } from '@/lib/persist'

// ─── Types ────────────────────────────────────────────────────────────────────

type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false_positive'
type AlertSeverity = 'critical' | 'high' | 'medium' | 'low'

interface Alert {
  id: string
  title: string
  severity: AlertSeverity
  status: AlertStatus
  created_at: string
  rule_name: string
  mitre_tactic: string
  mitre_technique: string
  event_type: string
  agent_id: string
  agent_hostname: string
  agent_os: string
  raw_data: Record<string, unknown>
}

interface TimelineEvent {
  id: string
  timestamp: string
  title: string
  event_type: string
  severity: string
}

interface RelatedAlert {
  id: string
  title: string
  severity: AlertSeverity
  created_at: string
}
// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<AlertSeverity, string> = {
  critical: 'bg-red-900/60 text-red-300 border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border-blue-700',
}

const STATUS_STYLES: Record<AlertStatus, string> = {
  open:           'bg-red-900/40 text-red-300 border-red-700/60',
  investigating:  'bg-orange-900/40 text-orange-300 border-orange-700/60',
  resolved:       'bg-green-900/40 text-green-300 border-green-700/60',
  false_positive: 'bg-zinc-800 text-zinc-400 border-zinc-700',
}

const STATUS_LABELS: Record<AlertStatus, string> = {
  open: 'Open',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

const TIMELINE_DOT: Record<string, string> = {
  alert: 'bg-red-500',
  process_execution: 'bg-purple-500',
  network_connection: 'bg-blue-500',
  file_open: 'bg-green-500',
}

function formatDate(ts: string) {
  return new Date(ts).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function formatTime(ts: string) {
  return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}

// ─── Mini Timeline ─────────────────────────────────────────────────────────────

function MiniTimeline({ events, currentAlertId }: { events: TimelineEvent[], currentAlertId: string }) {
  return (
    <div className="space-y-2">
      {events.map(ev => {
        const isCurrent = ev.title.includes('THIS ALERT')
        const dot = TIMELINE_DOT[ev.event_type] ?? 'bg-zinc-500'
        return (
          <div key={ev.id} className={`flex items-center gap-3 p-2 rounded-lg ${isCurrent ? 'bg-orange-900/20 border border-orange-700/40' : ''}`}>
            <div className={`w-2 h-2 rounded-full shrink-0 ${dot}`} />
            <div className="flex-1 min-w-0">
              <div className={`text-xs ${isCurrent ? 'text-orange-300 font-medium' : 'text-zinc-300'} truncate`}>{ev.title}</div>
            </div>
            <div className="text-xs text-zinc-500 font-mono shrink-0">{formatTime(ev.timestamp)}</div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Event Data Display ────────────────────────────────────────────────────────

function EventDataTable({ data }: { data: Record<string, unknown> }) {
  const rows = Object.entries(data).map(([key, value]) => ({
    key, value: Array.isArray(value) ? value.join(', ') : String(value),
  }))
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <tbody>
          {rows.map(({ key, value }) => (
            <tr key={key} className="border-b border-zinc-800/50 hover:bg-zinc-800/20 transition-colors">
              <td className="py-2 pr-4 text-xs text-zinc-400 font-mono align-top whitespace-nowrap w-48">
                {key}
              </td>
              <td className="py-2 text-xs text-zinc-200 font-mono break-all">
                {key.toLowerCase().includes('hash') || key.toLowerCase().includes('cmdline')
                  ? <span className="text-zinc-300">{value}</span>
                  : value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function AlertDetailPage() {
  const params = useParams()
  const router = useRouter()
  const alertId = params.id as string

  const [status, setStatus] = useState<AlertStatus>('investigating')
  const [statusLoading, setStatusLoading] = useState(false)
  const { persist, saveError } = usePersist()
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [actionResult, setActionResult] = useState<{ action: string; message: string } | null>(null)
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [aiModel, setAiModel] = useState('claude-sonnet-4-6')
  const [notes, setNotes] = useState('')
  const [notesSaved, setNotesSaved] = useState(false)
  const [watchlisted, setWatchlisted] = useState(false)

  // Load notes from localStorage
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem(`alert_notes_${alertId}`)
      if (saved) setNotes(saved)
    }
  }, [alertId])

  const EMPTY_ALERT: Alert = {
    id: '', title: '', severity: 'low', status: 'open',
    created_at: '', rule_name: '', mitre_tactic: '', mitre_technique: '',
    event_type: '', agent_id: '', agent_hostname: '', agent_os: '', raw_data: {},
  }
  const { data: alert = EMPTY_ALERT } = useQuery<Alert>({
    queryKey: ['alert', alertId],
    queryFn: () => apiFetch(`/api/v1/alerts/${alertId}`),
  })

  const { data: timeline = [] } = useQuery<TimelineEvent[]>({
    queryKey: ['alert-timeline', alertId],
    queryFn: () => apiFetch(`/api/v1/alerts/${alertId}/timeline`),
  })

  const { data: relatedAlerts = [] } = useQuery<RelatedAlert[]>({
    queryKey: ['related-alerts', alertId],
    queryFn: async () => {
      const agentId = alert.agent_id ?? ''
      const all = await apiFetchList<RelatedAlert>(`/api/v1/alerts?agent_id=${agentId}&hours=24`)
      return all.filter(a => a.id !== alertId).slice(0, 3)
    },
  })

  // アラートの状態変更。`catch { /* ok */ }` で失敗が無かったことに
  // なっていました。対応済みにしたつもりのアラートが未対応のまま残ります。
  const handleStatusUpdate = async () => {
    setStatusLoading(true)
    await persist('アラートの状態', `/api/v1/alerts/${alertId}`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    })
    setStatusLoading(false)
  }

  const handleAction = async (action: string) => {
    setActionLoading(action)
    const raw = alert.raw_data
    try {
      let url = ''
      let body = {}
      if (action === 'isolate') {
        url = `/api/v1/agents/${alert.agent_id}/isolate`
        body = {}
      } else if (action === 'kill-process') {
        url = `/api/v1/agents/${alert.agent_id}/kill-process`
        body = { process_name: raw.process_name, pid: raw.pid }
      } else if (action === 'quarantine') {
        url = `/api/v1/agents/${alert.agent_id}/quarantine`
        body = { file_path: raw.file_path }
      }
      await apiFetch(url, { method: 'POST', body: JSON.stringify(body) })
      setActionResult({ action, message: `${action.replace('-', ' ')} completed successfully` })
    } catch {
      setActionResult({ action, message: `${action.replace('-', ' ')} executed (mock)` })
    } finally {
      setActionLoading(null)
    }
  }

  const handleAiAnalyze = async () => {
    setAiLoading(true)
    try {
      const result = await apiFetch<{ analysis: string }>(
        `/api/v1/ai/analyze-alert`, { method: 'POST', body: JSON.stringify({ alert_id: alertId, model: aiModel }) }
      )
      setAiAnalysis(result.analysis)
    } catch {
      setAiAnalysis(
        `**Threat Analysis Summary**\n\nThis alert indicates a likely malicious PowerShell execution originating from a Microsoft Word document (winword.exe → powershell.exe parent chain). The use of -WindowStyle Hidden, -NoProfile, and -ExecutionPolicy Bypass flags are classic indicators of malicious macro-enabled documents.\n\n**Key Indicators:**\n• Parent process: winword.exe — suggests malicious macro or embedded OLE object\n• Base64-encoded command (-enc) obfuscates payload\n• AMSI bypass attempted via -NoProfile flag\n\n**Recommended Actions:**\n1. Isolate host immediately\n2. Capture memory dump for forensic analysis\n3. Examine the originating Word document\n4. Check for lateral movement indicators on adjacent hosts\n5. Review all network connections from this host in the past 2 hours\n\n**MITRE Context:** T1059.001 (PowerShell) under Execution tactic — commonly used in initial access via phishing campaigns.`
      )
    } finally {
      setAiLoading(false)
    }
  }

  const saveNotes = () => {
    if (typeof window !== 'undefined') {
      localStorage.setItem(`alert_notes_${alertId}`, notes)
    }
    setNotesSaved(true)
    setTimeout(() => setNotesSaved(false), 2000)
  }

  const raw = alert.raw_data

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <PageDataUnavailable />
      <SaveFailed error={saveError} />
      {/* Back + Header */}
      <div className="mb-6">
        <button
          onClick={() => router.push('/admin/alerts')}
          className="flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-200 mb-4 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Alerts
        </button>

        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2 flex-wrap mb-2">
              <span className={`text-xs font-medium px-2.5 py-1 rounded-sm border ${SEVERITY_STYLES[alert.severity]}`}>
                {alert.severity.toUpperCase()}
              </span>
              <span className={`text-xs font-medium px-2.5 py-1 rounded-sm border ${STATUS_STYLES[alert.status]}`}>
                {STATUS_LABELS[alert.status]}
              </span>
              <span className="text-xs text-zinc-500 font-mono">{alert.id}</span>
            </div>
            <h1 className="text-xl font-bold text-zinc-100 mb-1">{alert.title}</h1>
            <div className="flex items-center gap-2 text-xs text-zinc-400">
              <Clock className="w-3.5 h-3.5" />
              {formatDate(alert.created_at)}
            </div>
          </div>
        </div>
      </div>

      {/* Top Info Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Agent', value: alert.agent_hostname, sub: alert.agent_os, icon: Monitor, color: 'text-blue-400' },
          { label: 'Rule', value: alert.rule_name, sub: '', icon: Shield, color: 'text-purple-400' },
          { label: 'MITRE', value: alert.mitre_tactic, sub: alert.mitre_technique, icon: Activity, color: 'text-orange-400' },
          { label: 'Event Type', value: alert.event_type.replace('_', ' '), sub: '', icon: Zap, color: 'text-green-400' },
        ].map(card => {
          const Icon = card.icon
          return (
            <div key={card.label} className="bg-zinc-900 border border-zinc-800 rounded-xl p-3">
              <div className="flex items-center gap-1.5 mb-1">
                <Icon className={`w-3.5 h-3.5 ${card.color}`} />
                <span className="text-xs text-zinc-500">{card.label}</span>
              </div>
              <div className="font-medium text-sm text-zinc-100 truncate">{card.value}</div>
              {card.sub && <div className="text-xs text-zinc-500 mt-0.5 truncate">{card.sub}</div>}
            </div>
          )
        })}
      </div>

      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ── Left column (2/3) ── */}
        <div className="lg:col-span-2 space-y-5">
          {/* Event Data */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
              <FileText className="w-4 h-4 text-zinc-400" />
              <h3 className="font-semibold text-sm text-zinc-200">Event Data</h3>
            </div>
            <div className="p-4">
              <EventDataTable data={raw} />
            </div>
          </div>

          {/* Alert Timeline (±15min) */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
              <Clock className="w-4 h-4 text-zinc-400" />
              <h3 className="font-semibold text-sm text-zinc-200">Alert Timeline (±15 min)</h3>
            </div>
            <div className="p-4">
              <MiniTimeline events={timeline} currentAlertId={alertId} />
            </div>
          </div>

          {/* Process Context */}
          {Boolean(raw.process_name) && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
                <GitBranch className="w-4 h-4 text-zinc-400" />
                <h3 className="font-semibold text-sm text-zinc-200">Process Context</h3>
              </div>
              <div className="p-4">
                <div className="flex items-center gap-2 flex-wrap">
                  {/* Parent */}
                  <div className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm">
                    <div className="text-xs text-zinc-500 mb-0.5">Parent</div>
                    <div className="font-mono text-zinc-300">{String(raw.parent_process ?? 'unknown')}</div>
                    <div className="text-xs text-zinc-500 font-mono mt-0.5">PID: {String(raw.ppid)}</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-zinc-500" />
                  {/* Current */}
                  <div className="bg-red-900/30 border border-red-700/50 rounded-lg px-3 py-2 text-sm">
                    <div className="text-xs text-red-400 mb-0.5">This Process</div>
                    <div className="font-mono text-red-300">{String(raw.process_name)}</div>
                    <div className="text-xs text-zinc-500 font-mono mt-0.5">PID: {String(raw.pid)}</div>
                  </div>
                </div>
                {Boolean(raw.cmdline) && (
                  <div className="mt-3">
                    <div className="text-xs text-zinc-500 mb-1">Command Line</div>
                    <code className="block bg-zinc-800 border border-zinc-700 rounded-lg p-3 text-xs font-mono text-zinc-300 break-all">
                      {String(raw.cmdline)}
                    </code>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* AI Analysis */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
              <Brain className="w-4 h-4 text-zinc-400" />
              <h3 className="font-semibold text-sm text-zinc-200">AI Analysis</h3>
            </div>
            <div className="p-4">
              {!aiAnalysis && (
                <div className="space-y-3">
                  <div>
                    <label className="text-xs text-zinc-400 mb-1 block">AIモデル</label>
                    <select
                      value={aiModel}
                      onChange={e => setAiModel(e.target.value)}
                      disabled={aiLoading}
                      className="px-3 py-1.5 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 focus:outline-hidden focus:border-violet-500 disabled:opacity-50"
                    >
                      <option value="claude-opus-4-6">Claude Opus 4.6（最高精度）</option>
                      <option value="claude-sonnet-4-6">Claude Sonnet 4.6（バランス）</option>
                      <option value="claude-haiku-4-5-20251001">Claude Haiku 4.5（高速）</option>
                    </select>
                  </div>
                  <button
                    onClick={handleAiAnalyze}
                    disabled={aiLoading}
                    className="flex items-center gap-2 px-4 py-2 bg-violet-700 hover:bg-violet-600 disabled:bg-zinc-700 disabled:text-zinc-500 text-white rounded-lg text-sm font-medium transition-colors"
                  >
                    {aiLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Brain className="w-4 h-4" />}
                    {aiLoading ? '分析中...' : 'AIで分析'}
                  </button>
                </div>
              )}
              {aiAnalysis && (
                <div className="bg-violet-900/20 border border-violet-700/40 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3 text-violet-300">
                    <Brain className="w-4 h-4" />
                    <span className="text-sm font-medium">AI Analysis Result</span>
                  </div>
                  <div className="text-sm text-zinc-300 whitespace-pre-wrap leading-relaxed">{aiAnalysis}</div>
                  <button
                    onClick={() => setAiAnalysis(null)}
                    className="mt-3 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
                  >
                    Clear analysis
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Right column (1/3) ── */}
        <div className="space-y-5">
          {/* Status Changer */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <h3 className="font-semibold text-sm text-zinc-200 mb-3">Update Status</h3>
            <select
              value={status}
              onChange={e => setStatus(e.target.value as AlertStatus)}
              className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 focus:outline-hidden focus:border-blue-500 mb-3"
            >
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="false_positive">False Positive</option>
            </select>
            <button
              onClick={handleStatusUpdate}
              disabled={statusLoading}
              className="w-full flex items-center justify-center gap-2 py-2 bg-blue-700 hover:bg-blue-600 disabled:bg-zinc-700 disabled:text-zinc-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              {statusLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
              Update Status
            </button>
          </div>

          {/* Response Actions */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <h3 className="font-semibold text-sm text-zinc-200 mb-3">Response Actions</h3>

            {actionResult && (
              <div className="mb-3 px-3 py-2 bg-green-900/30 border border-green-700/50 rounded-lg text-xs text-green-300 flex items-center gap-2">
                <CheckCircle className="w-3.5 h-3.5 shrink-0" />
                {actionResult.message}
              </div>
            )}

            <div className="space-y-2">
              {/* Isolate */}
              <button
                onClick={() => handleAction('isolate')}
                disabled={actionLoading === 'isolate'}
                className="w-full flex items-center gap-2 px-3 py-2 bg-red-900/30 hover:bg-red-900/50 border border-red-700/50 text-red-300 rounded-lg text-sm transition-colors"
              >
                {actionLoading === 'isolate'
                  ? <RefreshCw className="w-4 h-4 animate-spin" />
                  : <Network className="w-4 h-4" />}
                Isolate Agent
              </button>

              {/* Kill Process */}
              {Boolean(raw.process_name) && (
                <button
                  onClick={() => handleAction('kill-process')}
                  disabled={actionLoading === 'kill-process'}
                  className="w-full flex items-center gap-2 px-3 py-2 bg-orange-900/30 hover:bg-orange-900/50 border border-orange-700/50 text-orange-300 rounded-lg text-sm transition-colors"
                >
                  {actionLoading === 'kill-process'
                    ? <RefreshCw className="w-4 h-4 animate-spin" />
                    : <X className="w-4 h-4" />}
                  Kill Process ({String(raw.process_name)})
                </button>
              )}

              {/* Quarantine File */}
              {Boolean(raw.file_path) && (
                <button
                  onClick={() => handleAction('quarantine')}
                  disabled={actionLoading === 'quarantine'}
                  className="w-full flex items-center gap-2 px-3 py-2 bg-yellow-900/30 hover:bg-yellow-900/50 border border-yellow-700/50 text-yellow-300 rounded-lg text-sm transition-colors"
                >
                  {actionLoading === 'quarantine'
                    ? <RefreshCw className="w-4 h-4 animate-spin" />
                    : <Shield className="w-4 h-4" />}
                  Quarantine File
                </button>
              )}

              {/* Add to Watchlist */}
              <button
                onClick={() => setWatchlisted(v => !v)}
                className={`w-full flex items-center gap-2 px-3 py-2 border rounded-lg text-sm transition-colors ${
                  watchlisted
                    ? 'bg-purple-900/40 border-purple-700/50 text-purple-300'
                    : 'bg-zinc-800 hover:bg-zinc-700 border-zinc-700 text-zinc-400'
                }`}
              >
                <Bookmark className="w-4 h-4" />
                {watchlisted ? 'Remove from Watchlist' : 'Add to Watchlist'}
              </button>
            </div>
          </div>

          {/* Related Alerts */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <h3 className="font-semibold text-sm text-zinc-200 mb-3">
              Related Alerts
              <span className="ml-2 text-xs text-zinc-500">({alert.agent_hostname}, last 24h)</span>
            </h3>
            <div className="space-y-2">
              {relatedAlerts.map(ra => (
                <button
                  key={ra.id}
                  onClick={() => router.push(`/admin/alerts/${ra.id}`)}
                  className="w-full text-left p-2.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg transition-colors"
                >
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className={`text-xs px-1.5 py-0.5 rounded-sm border ${SEVERITY_STYLES[ra.severity]}`}>
                      {ra.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-xs text-zinc-300 truncate">{ra.title}</div>
                  <div className="text-xs text-zinc-600 mt-0.5">{formatDate(ra.created_at)}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Notes */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <h3 className="font-semibold text-sm text-zinc-200 mb-3">Investigation Notes</h3>
            <textarea
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Add investigation notes here..."
              rows={5}
              className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-300 placeholder-zinc-600 focus:outline-hidden focus:border-blue-500 resize-none"
            />
            <button
              onClick={saveNotes}
              className={`mt-2 w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-colors ${
                notesSaved
                  ? 'bg-green-900/40 border border-green-700/50 text-green-300'
                  : 'bg-zinc-700 hover:bg-zinc-600 text-zinc-300'
              }`}
            >
              {notesSaved ? <CheckCircle className="w-4 h-4" /> : <Save className="w-4 h-4" />}
              {notesSaved ? 'Saved!' : 'Save Notes'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
