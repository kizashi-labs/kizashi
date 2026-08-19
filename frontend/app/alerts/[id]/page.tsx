'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  AlertTriangle,
  ArrowLeft,
  Shield,
  Terminal,
  Clock,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Fingerprint,
  Activity,
  Tag,
  Copy,
  MessageSquare,
  Send,
  FolderOpen,
  X,
  GitCommitHorizontal,
  UserCircle,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

interface AlertDetail {
  id: string
  title: string
  description: string
  severity: number       // 1-10
  status: 'open' | 'investigating' | 'resolved' | 'false_positive'
  hostname?: string
  agent_hostname?: string
  rule_name?: string
  rule_type?: string
  mitre_tactics?: string[]
  mitre_techniques?: string[]
  mitre_technique?: string
  assigned_to?: string
  assigned_to_name?: string
  created_at: string
  updated_at: string
  ioc_matches?: { type: string; value: string; threat_level: string }[]
  related_alert_ids?: string[]
  raw_event?: Record<string, unknown>
  // 生イベントを出せなかったときに、サーバが理由を入れてきます。
  // raw_event が空であることと、出せなかったことは別です。
  raw_event_unavailable?: string
}

interface AlertComment {
  id: string
  content: string
  user_name?: string
  created_at: string
}

interface StatusHistoryEntry {
  id: string
  from_status: string | null
  to_status: string
  changed_by: string
  changed_at: string
}

type ActivityItem =
  | { kind: 'status'; ts: string; entry: StatusHistoryEntry }
  | { kind: 'comment'; ts: string; comment: AlertComment }

interface TimelineEvent {
  hour: number        // 0-23 UTC
  alertCount: number  // alerts fired in this hour (primary)
  eventCount: number  // raw telemetry events (activity background, scaled)
}

// ─── Mock data ────────────────────────────────────────────────────────────────


const MOCK_ALERT: AlertDetail = {
  id: 'mock-001',
  title: 'Suspicious PowerShell Execution Detected',
  description:
    'A PowerShell process was launched with encoded command arguments commonly used in malicious payloads. The process attempted to download and execute a remote script.',
  severity: 8,
  status: 'investigating',
  hostname: 'DESKTOP-XYZ123',
  rule_name: 'PS_Encoded_Command_Exec',
  rule_type: 'sigma',
  mitre_tactics: ['Execution', 'Defense Evasion'],
  mitre_techniques: ['T1059.001', 'T1027'],
  created_at: new Date(Date.now() - 3600000).toISOString(),
  updated_at: new Date(Date.now() - 1800000).toISOString(),
  ioc_matches: [
    { type: 'domain', value: 'evil-c2.example.com', threat_level: 'high' },
    { type: 'hash', value: 'a1b2c3d4e5f6...', threat_level: 'critical' },
    { type: 'ip', value: '192.0.2.55', threat_level: 'medium' },
  ],
  related_alert_ids: ['alert-002', 'alert-003', 'alert-007', 'alert-014', 'alert-019'],
}

// ─── Severity helpers ─────────────────────────────────────────────────────────

function getSeverityColor(severity: number): { bar: string; badge: string; text: string } {
  if (severity >= 9) return { bar: 'bg-red-500', badge: 'bg-red-900/50 border-red-600/60 text-red-300', text: 'クリティカル' }
  if (severity >= 7) return { bar: 'bg-orange-500', badge: 'bg-orange-900/50 border-orange-600/60 text-orange-300', text: '高' }
  if (severity >= 5) return { bar: 'bg-yellow-500', badge: 'bg-yellow-900/50 border-yellow-600/60 text-yellow-300', text: '中' }
  if (severity >= 3) return { bar: 'bg-blue-500', badge: 'bg-blue-900/50 border-blue-600/60 text-blue-300', text: '低' }
  return { bar: 'bg-gray-500', badge: 'bg-gray-700/50 border-gray-600/60 text-gray-300', text: '情報' }
}

function getThreatLevelColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'critical': return 'bg-red-900/40 text-red-300 border border-red-700/60'
    case 'high':     return 'bg-orange-900/40 text-orange-300 border border-orange-700/60'
    case 'medium':   return 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/60'
    case 'low':      return 'bg-blue-900/40 text-blue-300 border border-blue-700/60'
    default:         return 'bg-gray-700/40 text-gray-300 border border-gray-600/60'
  }
}

// ─── Status selector ──────────────────────────────────────────────────────────

const STATUS_LABEL: Record<string, string> = {
  open: '未対応',
  investigating: '調査中',
  resolved: '解決済み',
  false_positive: '誤検知',
}

const STATUS_OPTIONS: { value: AlertDetail['status']; label: string; cls: string }[] = [
  { value: 'open',           label: '未対応',   cls: 'text-red-300 bg-red-900/40 border-red-700/60' },
  { value: 'investigating',  label: '調査中',   cls: 'text-yellow-300 bg-yellow-900/40 border-yellow-700/60' },
  { value: 'resolved',       label: '解決済み', cls: 'text-green-300 bg-green-900/40 border-green-700/60' },
  { value: 'false_positive', label: '誤検知',   cls: 'text-gray-300 bg-gray-700/40 border-gray-600/60' },
]

// ─── 24-Hour CSS-only bar chart ───────────────────────────────────────────────

function TimelineBarChart({
  events,
  severity,
}: {
  events: TimelineEvent[]
  severity: number
}) {
  const { bar } = getSeverityColor(severity)
  // Scale: alerts shown actual height; events shown scaled (÷50, capped) as background
  const maxAlert = Math.max(...events.map(e => e.alertCount), 1)
  const maxActivity = Math.max(...events.map(e => Math.min(e.eventCount / 50, maxAlert)), 1)
  const chartMax = Math.max(maxAlert, maxActivity, 1)

  return (
    <div className="space-y-2">
      {/* Legend */}
      <div className="flex items-center gap-4 text-[10px] text-[#4a6080]">
        <span className="flex items-center gap-1">
          <span className="inline-block w-2 h-2 rounded-xs bg-[#2a3a52]" />
          テレメトリ活動量（÷50）
        </span>
        <span className="flex items-center gap-1">
          <span className={`inline-block w-2 h-2 rounded-xs ${bar}`} />
          アラート数
        </span>
      </div>

      <div className="flex items-end gap-[3px] h-20">
        {events.map(e => {
          const activityH = Math.max((Math.min(e.eventCount / 50, maxAlert) / chartMax) * 100, e.eventCount > 0 ? 4 : 0)
          const alertH    = Math.max((e.alertCount / chartMax) * 100, e.alertCount > 0 ? 8 : 0)
          const tooltip   = `${String(e.hour).padStart(2,'0')}:00 JST — アラート ${e.alertCount}件 / テレメトリ ${e.eventCount.toLocaleString()}件`
          return (
            <div
              key={e.hour}
              className="relative flex-1 group cursor-default"
              style={{ height: '100%' }}
              title={tooltip}
            >
              {/* Activity background bar */}
              {activityH > 0 && (
                <div
                  className="absolute bottom-0 left-0 right-0 bg-[#1e2d42] rounded-t-sm"
                  style={{ height: `${activityH}%` }}
                />
              )}
              {/* Alert foreground bar */}
              {alertH > 0 && (
                <div
                  className={`absolute bottom-0 left-0 right-0 ${bar} opacity-80 group-hover:opacity-100 rounded-t-sm transition-opacity`}
                  style={{ height: `${alertH}%` }}
                />
              )}
            </div>
          )
        })}
      </div>

      {/* Hour labels (UTC) — every 6 hours */}
      <div className="flex items-center" style={{ gap: '3px' }}>
        {events.map(e => (
          <div key={e.hour} className="flex-1 text-center">
            {e.hour % 6 === 0 ? (
              <span className="text-[9px] text-[#4a6080]">{String(e.hour).padStart(2, '0')}</span>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Loading skeleton ─────────────────────────────────────────────────────────

function PageSkeleton() {
  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6 animate-pulse">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 bg-[#1e2d42] rounded-lg" />
        <div className="h-4 w-40 bg-[#1e2d42] rounded-sm" />
        <div className="h-4 w-2 bg-[#1e2d42] rounded-sm" />
        <div className="h-4 w-48 bg-[#1e2d42] rounded-sm" />
      </div>
      <div className="h-32 bg-[#0d1220] rounded-xl border border-[#1e2d42]" />
      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 space-y-4">
          <div className="h-40 bg-[#0d1220] rounded-xl border border-[#1e2d42]" />
          <div className="h-36 bg-[#0d1220] rounded-xl border border-[#1e2d42]" />
        </div>
        <div className="space-y-4">
          <div className="h-44 bg-[#0d1220] rounded-xl border border-[#1e2d42]" />
          <div className="h-28 bg-[#0d1220] rounded-xl border border-[#1e2d42]" />
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AlertDetailPage() {
  const params = useParams()
  const router = useRouter()
  const qc = useQueryClient()
  const id = params.id as string

  const canWrite = useCanWrite()
  const [rawExpanded, setRawExpanded] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [commentText, setCommentText] = useState('')
  const [showIncidentModal, setShowIncidentModal] = useState(false)
  const [incidentTitle, setIncidentTitle] = useState('')
  const [incidentDesc, setIncidentDesc] = useState('')
  const [showAssignSelect, setShowAssignSelect] = useState(false)

  // ── Alert detail query ──
  const {
    data: alert,
    isLoading: alertLoading,
    isError: alertError,
  } = useQuery<AlertDetail>({
    queryKey: ['alert-detail', id],
    queryFn: async () => {
      try {
        const raw = await apiFetch<AlertDetail & { mitre_technique?: string; ai_mitre_tags?: string[] }>(`/api/v1/alerts/${id}`)
        // Build mitre_techniques from singular mitre_technique + ai_mitre_tags
        const techSet = new Set<string>()
        if (raw.mitre_technique) techSet.add(raw.mitre_technique)
        if (Array.isArray(raw.ai_mitre_tags)) raw.ai_mitre_tags.forEach(t => techSet.add(t))
        if (Array.isArray(raw.mitre_techniques)) raw.mitre_techniques.forEach(t => techSet.add(t))
        return {
          ...raw,
          mitre_tactics:     Array.isArray(raw.mitre_tactics)    ? raw.mitre_tactics    : [],
          mitre_techniques:  Array.from(techSet),
          ioc_matches:       Array.isArray(raw.ioc_matches)      ? raw.ioc_matches      : [],
          related_alert_ids: Array.isArray(raw.related_alert_ids) ? raw.related_alert_ids : [],
        }
      } catch (err) {
        throw err
      }
    },
    enabled: !!id,
  })

  // ── Timeline query ──
  const { data: timelineData } = useQuery<TimelineEvent[]>({
    queryKey: ['alert-timeline', id],
    queryFn: async () => {
      const empty = Array.from({ length: 24 }, (_, h) => ({ hour: h, alertCount: 0, eventCount: 0 }))
      try {
        const raw = await apiFetch<{
          hourly_alerts?: number[]
          hourly_events?: number[]
        }>(`/api/v1/alerts/${id}/timeline`)

        if (Array.isArray(raw?.hourly_alerts) && raw.hourly_alerts.length === 24) {
          // Convert UTC hour buckets to local time (JST = UTC+9)
          const offsetHours = -new Date().getTimezoneOffset() / 60
          return Array.from({ length: 24 }, (_, localHour) => {
            const utcHour = ((localHour - offsetHours) % 24 + 24) % 24
            return {
              hour: localHour,
              alertCount: raw.hourly_alerts![Math.floor(utcHour)] ?? 0,
              eventCount:  raw.hourly_events?.[Math.floor(utcHour)] ?? 0,
            }
          })
        }
        return empty
      } catch {
        return empty
      }
    },
    enabled: !!id,
  })

  // ── Comments query ──
  const { data: comments = [] } = useQuery<AlertComment[]>({
    queryKey: ['alert-comments', id],
    queryFn: () => apiFetchList<AlertComment>(`/api/v1/alerts/${id}/comments`),
    enabled: !!id,
  })

  // ── Status history query ──
  const { data: statusHistory = [] } = useQuery<StatusHistoryEntry[]>({
    queryKey: ['alert-history', id],
    queryFn: async () => {
      try {
        const res = await apiFetch<{ data: StatusHistoryEntry[] }>(`/api/v1/alerts/${id}/history`)
        return res.data ?? []
      } catch {
        return []
      }
    },
    enabled: !!id,
  })

  // ── Users list (for assign dropdown) ──
  const { data: userList = [] } = useQuery<{ id: string; full_name: string; email: string }[]>({
    queryKey: ['users-list'],
    queryFn: () => apiFetchList('/api/v1/users'),
    staleTime: 60_000,
  })

  // ── Assign mutation ──
  const assignMutation = useMutation({
    mutationFn: (userId: string | null) =>
      apiFetch(`/api/v1/alerts/${id}/assign`, {
        method: 'PUT',
        body: JSON.stringify({ assigned_to: userId }),
      }),
    onSuccess: () => {
      setShowAssignSelect(false)
      qc.invalidateQueries({ queryKey: ['alert-detail', id] })
    },
  })

  // ── Add comment mutation ──
  const addCommentMutation = useMutation({
    mutationFn: (content: string) =>
      apiFetch(`/api/v1/alerts/${id}/comments`, {
        method: 'POST',
        body: JSON.stringify({ content }),
      }),
    onSuccess: () => {
      setCommentText('')
      qc.invalidateQueries({ queryKey: ['alert-comments', id] })
    },
  })

  // ── Status update mutation ──
  const statusMutation = useMutation({
    mutationFn: (status: AlertDetail['status']) =>
      apiFetch(`/api/v1/alerts/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ status }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert-detail', id] })
    },
  })

  // ── Incident creation mutation ──
  const createIncidentMutation = useMutation({
    mutationFn: async () => {
      const inc = await apiFetch<{ id: string }>('/api/v1/incidents', {
        method: 'POST',
        body: JSON.stringify({
          title: incidentTitle,
          description: incidentDesc,
          severity: alert?.severity ?? 5,
          status: 'open',
        }),
      })
      await apiFetch(`/api/v1/incidents/${inc.id}/alerts`, {
        method: 'POST',
        body: JSON.stringify({ alert_id: id }),
      })
      return inc.id
    },
    onSuccess: (incidentId: string) => {
      setShowIncidentModal(false)
      router.push(`/incidents/${incidentId}`)
    },
  })

  // ── Copy helper ──
  function copyToClipboard(text: string, key: string) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        setCopiedId(key)
        setTimeout(() => setCopiedId(null), 1500)
      }).catch(() => fallbackCopy(text, key))
    } else {
      fallbackCopy(text, key)
    }
  }

  function fallbackCopy(text: string, key: string) {
    const el = document.createElement('textarea')
    el.value = text
    el.style.position = 'fixed'
    el.style.opacity = '0'
    document.body.appendChild(el)
    el.focus()
    el.select()
    try {
      document.execCommand('copy')
      setCopiedId(key)
      setTimeout(() => setCopiedId(null), 1500)
    } finally {
      document.body.removeChild(el)
    }
  }

  if (alertLoading) return <PageSkeleton />

  if (alertError || !alert) {
    return (
      <div className="min-h-screen bg-[#070d19] flex items-center justify-center">
        <div className="text-center space-y-3">
          <AlertTriangle className="w-12 h-12 text-red-400 mx-auto" />
          <p className="text-white font-medium">アラートの読み込みに失敗しました</p>
          <button
            onClick={() => router.push('/alerts')}
            className="px-4 py-2 text-sm bg-[#0d1220] border border-[#1e2d42] text-[#c9d6e8] rounded-lg hover:bg-[#111827] transition-colors"
          >
            アラート一覧に戻る
          </button>
        </div>
      </div>
    )
  }

  const timeline = Array.isArray(timelineData) ? timelineData : Array.from({ length: 24 }, (_, h) => ({ hour: h, alertCount: 0, eventCount: 0 }))
  const timelineTotalAlerts = timeline.reduce((s, e) => s + e.alertCount, 0)
  const timelinePeakHour = timelineTotalAlerts > 0
    ? timeline.reduce((m, e) => e.alertCount > m.alertCount ? e : m, timeline[0]).hour
    : null
  const mitreTactics    = Array.isArray(alert.mitre_tactics)    ? alert.mitre_tactics    : []
  const mitreTechniques = Array.isArray(alert.mitre_techniques) ? alert.mitre_techniques : []
  const iocMatches      = Array.isArray(alert.ioc_matches)      ? alert.ioc_matches      : []
  const relatedIds      = Array.isArray(alert.related_alert_ids) ? alert.related_alert_ids : []
  const severityColors = getSeverityColor(alert.severity)
  const currentStatus = STATUS_OPTIONS.find(s => s.value === alert.status) ?? STATUS_OPTIONS[0]
  const displayHostname: string = (alert.agent_hostname || alert.hostname || '—') as string
  const displayRuleName: string = (alert.rule_name || '—') as string

  const rawEventData = alert.raw_event ?? {
    id: alert.id,
    hostname: displayHostname,
    rule: { name: displayRuleName },
    severity: alert.severity,
    status: alert.status,
    created_at: alert.created_at,
    updated_at: alert.updated_at,
  }

  return (
    <div className="min-h-screen bg-[#070d19]">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-screen-xl mx-auto p-6 space-y-6">

        {/* Breadcrumb + back button */}
        <div className="flex items-center gap-3 flex-wrap">
          <button
            onClick={() => router.push('/alerts')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-[#7d92b0] bg-[#0d1220] border border-[#1e2d42] rounded-lg hover:bg-[#111827] hover:text-[#c9d6e8] transition-colors shrink-0"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            戻る
          </button>
          <nav className="flex items-center gap-2 text-sm text-[#4a6080]">
            <button
              onClick={() => router.push('/alerts')}
              className="hover:text-cyan-400 transition-colors"
            >
              アラート一覧
            </button>
            <span>/</span>
            <span className="text-[#c9d6e8] truncate max-w-xs">{alert.title}</span>
          </nav>
        </div>

        {/* Header card */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 space-y-4">
          {/* Title row */}
          <div className="flex items-start gap-3 flex-wrap">
            <span
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border shrink-0 ${severityColors.badge}`}
            >
              <AlertTriangle className="w-3 h-3" />
              {severityColors.text} {alert.severity}/10
            </span>
            <h1 className="flex-1 text-xl font-bold text-white leading-snug">{alert.title}</h1>
          </div>

          {alert.description && (
            <p className="text-sm text-[#7d92b0] leading-relaxed">{alert.description}</p>
          )}

          {/* Meta badges row */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Hostname */}
            {displayHostname !== '—' && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs bg-[#070d19] border border-[#1e2d42] text-[#c9d6e8]">
                <Activity className="w-3 h-3 text-cyan-400" />
                {displayHostname}
              </span>
            )}

            {/* Process from raw_event */}
            {!!alert.raw_event?.image_path && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs bg-[#070d19] border border-[#1e2d42] text-[#c9d6e8] font-mono">
                <Terminal className="w-3 h-3 text-green-400" />
                {String(alert.raw_event.image_path).split('\\').pop()}
                {alert.raw_event.pid ? ` (PID: ${alert.raw_event.pid})` : ''}
              </span>
            )}

            {/* Rule */}
            {displayRuleName !== '—' && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs bg-[#070d19] border border-[#1e2d42] text-[#c9d6e8]">
                <Shield className="w-3 h-3 text-purple-400" />
                {displayRuleName}
              </span>
            )}

            {/* Rule type */}
            {alert.rule_type && (
              <span className="inline-flex items-center gap-1 px-2 py-1 rounded-sm text-[10px] font-bold uppercase tracking-wide bg-purple-900/30 text-purple-300 border border-purple-700/50">
                <Tag className="w-2.5 h-2.5" />
                {alert.rule_type}
              </span>
            )}

            {/* Timestamps */}
            <span className="inline-flex items-center gap-1.5 text-xs text-[#4a6080] ml-auto">
              <Clock className="w-3 h-3" />
              {new Date(alert.created_at).toLocaleString('ja-JP', {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit',
              })}
            </span>
          </div>

          {/* Status selector */}
          <div className="flex items-center gap-3 pt-1 border-t border-[#1e2d42]">
            <span className="text-xs text-[#4a6080]">ステータス:</span>
            <div className="flex gap-2 flex-wrap">
              {STATUS_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => statusMutation.mutate(opt.value)}
                  disabled={!canWrite || statusMutation.isPending || alert.status === opt.value}
                  className={`px-3 py-1 text-xs font-medium rounded-full border transition-all
                    ${alert.status === opt.value
                      ? `${opt.cls} ring-1 ring-white/20`
                      : 'bg-transparent border-[#1e2d42] text-[#7d92b0] hover:border-[#2d4060] hover:text-[#c9d6e8]'
                    } disabled:cursor-not-allowed`}
                >
                  {opt.label}
                  {alert.status === opt.value && ' ✓'}
                </button>
              ))}
            </div>
            {statusMutation.isError && (
              <span className="text-xs text-red-400 ml-2">
                {(statusMutation.error as Error)?.message}
              </span>
            )}
            {canWrite && (
              <button
                onClick={() => {
                  setIncidentTitle(`[${alert.title}] インシデント`)
                  setIncidentDesc(`アラート「${alert.title}」から作成されたインシデントです。`)
                  setShowIncidentModal(true)
                }}
                className="ml-auto flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-orange-900/30 border border-orange-700/50 text-orange-300 hover:bg-orange-800/40 transition-colors"
              >
                <FolderOpen className="w-3.5 h-3.5" />
                インシデント作成
              </button>
            )}
          </div>
        </div>

        {/* Incident creation modal */}
        {showIncidentModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-semibold text-white flex items-center gap-2">
                  <FolderOpen className="w-4 h-4 text-orange-400" />
                  インシデント作成
                </h3>
                <button onClick={() => setShowIncidentModal(false)} className="text-[#4a6080] hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-[#7d92b0] mb-1 block">タイトル</label>
                  <input
                    type="text"
                    value={incidentTitle}
                    onChange={e => setIncidentTitle(e.target.value)}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-[#c9d6e8] focus:outline-hidden focus:border-cyan-700/60"
                  />
                </div>
                <div>
                  <label className="text-xs text-[#7d92b0] mb-1 block">説明</label>
                  <textarea
                    value={incidentDesc}
                    onChange={e => setIncidentDesc(e.target.value)}
                    rows={3}
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-[#c9d6e8] focus:outline-hidden focus:border-cyan-700/60 resize-none"
                  />
                </div>
                {createIncidentMutation.isError && (
                  <p className="text-xs text-red-400">インシデントの作成に失敗しました</p>
                )}
                <div className="flex gap-2 pt-1">
                  <button
                    onClick={() => setShowIncidentModal(false)}
                    className="flex-1 px-3 py-2 text-sm border border-[#1e2d42] text-[#7d92b0] rounded-lg hover:bg-[#111827] transition-colors"
                  >
                    キャンセル
                  </button>
                  <button
                    onClick={() => createIncidentMutation.mutate()}
                    disabled={!incidentTitle.trim() || createIncidentMutation.isPending}
                    className="flex-1 px-3 py-2 text-sm bg-orange-900/40 border border-orange-700/60 text-orange-300 rounded-lg hover:bg-orange-800/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  >
                    {createIncidentMutation.isPending ? '作成中...' : '作成'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 2-column main grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* ── LEFT column (wider: 2/3) ── */}
          <div className="lg:col-span-2 space-y-6">

            {/* 24h Event Timeline */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-sm font-semibold text-cyan-400 mb-4 flex items-center gap-2">
                <Activity className="w-4 h-4" />
                24時間イベントタイムライン
              </h2>
              <TimelineBarChart events={timeline} severity={alert.severity} />
              <div className="flex items-center justify-between mt-3 text-xs text-[#4a6080]">
                <span>時刻は日本時間 (JST) · アラート発生時刻 ±6時間</span>
                <span>
                  アラート合計: {timelineTotalAlerts}件
                  {timelinePeakHour !== null && <> · ピーク: {String(timelinePeakHour).padStart(2, '0')}:00 JST</>}
                </span>
              </div>
            </div>

            {/* MITRE ATT&CK */}
            {(mitreTactics.length > 0 || mitreTechniques.length > 0) && (
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h2 className="text-sm font-semibold text-cyan-400 mb-4 flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  MITRE ATT&CK
                </h2>

                {mitreTactics.length > 0 && (
                  <div className="mb-4">
                    <p className="text-[10px] text-[#4a6080] uppercase tracking-widest mb-2">Tactics</p>
                    <div className="flex flex-wrap gap-2">
                      {mitreTactics.map(tactic => (
                        <a
                          key={tactic}
                          href={`https://attack.mitre.org/tactics/${tactic.toLowerCase().replace(/\s+/g, '-')}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-purple-900/30 text-purple-300 border border-purple-700/50 hover:bg-purple-900/50 transition-colors"
                        >
                          {tactic}
                          <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {mitreTechniques.length > 0 && (
                  <div>
                    <p className="text-[10px] text-[#4a6080] uppercase tracking-widest mb-2">Techniques</p>
                    <div className="flex flex-wrap gap-2">
                      {mitreTechniques.map(tech => {
                        const techId = tech.match(/T\d+(\.\d+)?/)?.[0] ?? ''
                        return (
                          <a
                            key={tech}
                            href={
                              techId
                                ? `https://attack.mitre.org/techniques/${techId.replace('.', '/')}`
                                : '#'
                            }
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-mono bg-indigo-900/30 text-indigo-300 border border-indigo-700/50 hover:bg-indigo-900/50 transition-colors"
                          >
                            {tech}
                            <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                          </a>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

          </div>

          {/* ── RIGHT column (1/3) ── */}
          <div className="space-y-6">

            {/* Assignee */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-sm font-semibold text-cyan-400 mb-3 flex items-center gap-2">
                <Fingerprint className="w-4 h-4" />
                担当者
              </h2>
              <div className="flex items-center gap-2">
                <span className="flex-1 text-sm text-[#c9d6e8]">
                  {alert.assigned_to_name ?? '未割り当て'}
                </span>
                {canWrite && <button
                  onClick={() => setShowAssignSelect(v => !v)}
                  className="px-2.5 py-1 text-xs rounded-lg bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-cyan-300 hover:border-cyan-700/60 transition-colors"
                >
                  {alert.assigned_to ? '変更' : '割り当て'}
                </button>}
              </div>
              {showAssignSelect && (
                <div className="mt-3 space-y-1">
                  <select
                    className="w-full px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-[#c9d6e8] focus:outline-hidden focus:border-cyan-700/60"
                    defaultValue={alert.assigned_to ?? ''}
                    onChange={e => assignMutation.mutate(e.target.value || null)}
                    disabled={assignMutation.isPending}
                  >
                    <option value="">未割り当て</option>
                    {userList.map(u => (
                      <option key={u.id} value={u.id}>{u.full_name || u.email}</option>
                    ))}
                  </select>
                  <button
                    onClick={() => setShowAssignSelect(false)}
                    className="text-xs text-[#4a6080] hover:text-[#7d92b0]"
                  >キャンセル</button>
                </div>
              )}
            </div>

            {/* IOC Matches */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b border-[#1e2d42] flex items-center gap-2">
                <Fingerprint className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold text-cyan-400">IOC マッチ</h2>
                {iocMatches.length > 0 && (
                  <span className="ml-auto px-2 py-0.5 rounded-full bg-red-900/30 text-red-300 text-[10px] font-bold border border-red-700/50">
                    {iocMatches.length}
                  </span>
                )}
              </div>

              {iocMatches.length === 0 ? (
                <div className="px-5 py-6 text-center text-xs text-[#4a6080]">
                  IOCマッチなし
                </div>
              ) : (
                <div className="divide-y divide-[#1e2d42]">
                  {iocMatches.map((ioc, i) => (
                    <div key={i} className="px-4 py-3 flex items-start gap-3 group hover:bg-[#111827] transition-colors">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] font-bold uppercase tracking-wide text-[#7d92b0]">
                            {ioc.type}
                          </span>
                          <span className={`px-1.5 py-0.5 rounded-sm text-[9px] font-bold uppercase ${getThreatLevelColor(ioc.threat_level)}`}>
                            {ioc.threat_level}
                          </span>
                        </div>
                        <p className="text-xs text-[#c9d6e8] font-mono truncate">{ioc.value}</p>
                      </div>
                      <button
                        onClick={() => copyToClipboard(ioc.value, `ioc-${i}`)}
                        className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded-sm hover:bg-[#1e2d42]"
                        title="コピー"
                      >
                        <Copy className={`w-3.5 h-3.5 ${copiedId === `ioc-${i}` ? 'text-green-400' : 'text-[#7d92b0]'}`} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Related Alerts */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h2 className="text-sm font-semibold text-cyan-400 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                関連アラート
              </h2>

              {relatedIds.length === 0 ? (
                <p className="text-xs text-[#4a6080]">関連アラートなし</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {relatedIds.slice(0, 5).map(relId => (
                    <a
                      key={relId}
                      href={`/alerts/${relId}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-full bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] hover:border-cyan-700/60 hover:text-cyan-300 transition-colors font-mono"
                    >
                      {relId}
                      <ExternalLink className="w-2.5 h-2.5 opacity-50" />
                    </a>
                  ))}
                </div>
              )}
            </div>

            {/* Activity Timeline (status changes + comments) */}
            {(() => {
              const activityItems: ActivityItem[] = [
                ...statusHistory.map(e => ({ kind: 'status' as const, ts: e.changed_at, entry: e })),
                ...comments.map(c => ({ kind: 'comment' as const, ts: c.created_at, comment: c })),
              ].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime())

              return (
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 space-y-4">
                  <h2 className="text-sm font-semibold text-[#c9d6e8] flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    アクティビティログ
                    <span className="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-[#1e2d42] text-[#7d92b0]">
                      {activityItems.length}
                    </span>
                  </h2>

                  {activityItems.length === 0 ? (
                    <p className="text-xs text-[#4a6080]">アクティビティなし</p>
                  ) : (
                    <div className="relative">
                      {/* Vertical line */}
                      <div className="absolute left-3 top-2 bottom-2 w-px bg-[#1e2d42]" />
                      <div className="space-y-4 pl-8">
                        {activityItems.map((item, idx) => {
                          if (item.kind === 'status') {
                            const e = item.entry
                            const isFirst = e.from_status === null
                            return (
                              <div key={`s-${e.id}`} className="relative">
                                <div className="absolute -left-5 top-1 w-2.5 h-2.5 rounded-full bg-[#1a6bff] border-2 border-[#0d1220] z-10" />
                                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2">
                                  <div className="flex items-center justify-between gap-2 flex-wrap">
                                    <div className="flex items-center gap-1.5 text-xs">
                                      <GitCommitHorizontal className="w-3.5 h-3.5 text-[#1a6bff]" />
                                      {isFirst ? (
                                        <span className="text-[#7d92b0]">
                                          アラート作成 — ステータス:
                                          <span className="ml-1 font-medium text-[#c9d6e8]">
                                            {STATUS_LABEL[e.to_status] ?? e.to_status}
                                          </span>
                                        </span>
                                      ) : (
                                        <span className="text-[#7d92b0]">
                                          ステータス変更:
                                          <span className="mx-1 font-medium text-[#c9d6e8]">
                                            {STATUS_LABEL[e.from_status!] ?? e.from_status}
                                          </span>
                                          →
                                          <span className="ml-1 font-medium text-cyan-300">
                                            {STATUS_LABEL[e.to_status] ?? e.to_status}
                                          </span>
                                        </span>
                                      )}
                                    </div>
                                    <span className="text-[10px] text-[#4a6080]">
                                      {new Date(e.changed_at).toLocaleString('ja-JP')}
                                    </span>
                                  </div>
                                  {e.changed_by && e.changed_by !== 'system' && (
                                    <p className="text-[10px] text-[#4a6080] mt-0.5 flex items-center gap-1">
                                      <UserCircle className="w-3 h-3" />
                                      {e.changed_by}
                                    </p>
                                  )}
                                </div>
                              </div>
                            )
                          } else {
                            const c = item.comment
                            return (
                              <div key={`c-${c.id}`} className="relative">
                                <div className="absolute -left-5 top-1 w-2.5 h-2.5 rounded-full bg-[#2d4a6e] border-2 border-[#0d1220] z-10" />
                                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2">
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
                                      <MessageSquare className="w-3.5 h-3.5 text-[#4a8fc0]" />
                                      {c.user_name || 'ユーザー'}
                                    </span>
                                    <span className="text-[10px] text-[#4a6080]">
                                      {new Date(c.created_at).toLocaleString('ja-JP')}
                                    </span>
                                  </div>
                                  <p className="text-sm text-[#c9d6e8] whitespace-pre-wrap">{c.content}</p>
                                </div>
                              </div>
                            )
                          }
                        })}
                      </div>
                    </div>
                  )}

                  {/* Comment input (admin/analyst only) */}
                  {canWrite && (
                    <div className="flex gap-2 pt-2 border-t border-[#1e2d42]">
                      <input
                        type="text"
                        value={commentText}
                        onChange={e => setCommentText(e.target.value)}
                        onKeyDown={e => {
                          if (e.key === 'Enter' && !e.shiftKey && commentText.trim()) {
                            e.preventDefault()
                            addCommentMutation.mutate(commentText.trim())
                          }
                        }}
                        placeholder="コメントを入力… (Enterで送信)"
                        className="flex-1 px-3 py-2 text-sm bg-[#070d19] border border-[#1e2d42] rounded-lg text-[#c9d6e8] placeholder-[#4a6080] focus:outline-hidden focus:border-cyan-700/60"
                      />
                      <button
                        onClick={() => commentText.trim() && addCommentMutation.mutate(commentText.trim())}
                        disabled={!commentText.trim() || addCommentMutation.isPending}
                        className="px-3 py-2 rounded-lg bg-cyan-900/40 border border-cyan-700/60 text-cyan-300 hover:bg-cyan-800/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                      >
                        <Send className="w-4 h-4" />
                      </button>
                    </div>
                  )}
                </div>
              )
            })()}

            {/* プロセスツリー (raw_event にプロセス情報がある場合のみ表示) */}
            {!!(alert.raw_event && (alert.raw_event.image_path || alert.raw_event.process_name)) && (
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-sm font-semibold text-[#c9d6e8] flex items-center gap-2 mb-4">
                  <Terminal className="w-4 h-4 text-green-400" />
                  プロセスツリー
                </h3>
                <div className="font-mono text-xs space-y-1">
                  {/* 祖先プロセス */}
                  {!!(alert.raw_event!.grandparent_image || alert.raw_event!.grandparent_pid) && (
                    <div className="flex items-center gap-2 text-[#4a6080]">
                      <span className="w-4" />
                      <span className="text-[#4a6080]">◆</span>
                      <span className="truncate max-w-xs">
                        {String(alert.raw_event!.grandparent_image ?? '').split('\\').pop() || '—'}
                      </span>
                      {!!alert.raw_event!.grandparent_pid && (
                        <span className="text-[#2d4060]">PID:{String(alert.raw_event!.grandparent_pid)}</span>
                      )}
                    </div>
                  )}
                  {/* 親プロセス */}
                  {!!(alert.raw_event!.parent_image || alert.raw_event!.parent_pid) && (
                    <div className="flex items-center gap-2 text-[#7d92b0]">
                      <span className="w-4 text-[#2d4060]">└─</span>
                      <span className="text-[#7d92b0]">◆</span>
                      <span className="truncate max-w-xs">
                        {String(alert.raw_event!.parent_image ?? '').split('\\').pop() || '—'}
                      </span>
                      {!!alert.raw_event!.parent_pid && (
                        <span className="text-[#2d4060]">PID:{String(alert.raw_event!.parent_pid)}</span>
                      )}
                    </div>
                  )}
                  {/* 対象プロセス（強調） */}
                  <div className={`flex items-start gap-2 px-2 py-1.5 rounded-lg ${
                    !!(alert.raw_event!.parent_image || alert.raw_event!.parent_pid) ? 'ml-8' : ''
                  } bg-red-950/30 border border-red-800/40`}>
                    <span className="text-red-400 mt-0.5">▶</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-red-300 font-bold">
                          {String(alert.raw_event!.image_path ?? alert.raw_event!.process_name ?? '').split('\\').pop()}
                        </span>
                        {!!alert.raw_event!.pid && (
                          <span className="text-[#4a6080]">PID:{String(alert.raw_event!.pid)}</span>
                        )}
                        {!!alert.raw_event!.user && (
                          <span className="text-yellow-600">@{String(alert.raw_event!.user)}</span>
                        )}
                      </div>
                      {!!(alert.raw_event!.command_line || alert.raw_event!.cmd_line) && (
                        <p className="text-[#7d92b0] mt-1 break-all text-[10px] leading-relaxed">
                          {String(alert.raw_event!.command_line ?? alert.raw_event!.cmd_line)}
                        </p>
                      )}
                    </div>
                  </div>
                  {/* 子プロセス */}
                  {!!alert.raw_event!.child_image && (
                    <div className="flex items-center gap-2 text-[#7d92b0] ml-8">
                      <span className="text-[#2d4060]">└─</span>
                      <span>◆</span>
                      <span className="truncate max-w-xs">
                        {String(alert.raw_event!.child_image).split('\\').pop()}
                      </span>
                      {!!alert.raw_event!.child_pid && (
                        <span className="text-[#2d4060]">PID:{String(alert.raw_event!.child_pid)}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Raw Event JSON (collapsible) */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <button
                onClick={() => setRawExpanded(v => !v)}
                className="w-full px-5 py-3 flex items-center gap-2 text-sm font-semibold text-cyan-400 hover:bg-[#111827] transition-colors"
              >
                <Terminal className="w-4 h-4" />
                Raw Event JSON
                <span className="ml-auto">
                  {rawExpanded
                    ? <ChevronUp className="w-4 h-4" />
                    : <ChevronDown className="w-4 h-4" />
                  }
                </span>
              </button>

              {rawExpanded && (
                <div className="border-t border-[#1e2d42] relative">
                  {/* サーバが生イベントを出せなかったとき、その理由をここに出します。
                      黙って落とすと「もともと生イベントの無い検知」と区別がつかず、
                      鍵の設定ミスに何週間も気づきません。 */}
                  {!!alert.raw_event_unavailable && (
                    <div className="m-3 px-3 py-2 rounded-sm border border-amber-500/40 bg-amber-500/10 text-[12px] text-amber-300 flex items-start gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                      <span>
                        {alert.raw_event_unavailable}
                        <span className="block text-amber-400/70 mt-0.5">
                          下に出ているのはアラートの要約です。生イベントそのものではありません。
                        </span>
                      </span>
                    </div>
                  )}
                  <button
                    onClick={() => copyToClipboard(JSON.stringify(rawEventData, null, 2), 'raw')}
                    className="absolute top-2 right-2 p-1.5 rounded-sm bg-[#1e2d42] hover:bg-[#2d3f55] transition-colors z-10"
                    title="JSONをコピー"
                  >
                    <Copy className={`w-3.5 h-3.5 ${copiedId === 'raw' ? 'text-green-400' : 'text-[#7d92b0]'}`} />
                  </button>
                  <pre className="p-4 text-[11px] text-green-300 font-mono overflow-auto max-h-64 whitespace-pre leading-relaxed">
                    {JSON.stringify(rawEventData, null, 2)}
                  </pre>
                </div>
              )}
            </div>

          </div>
        </div>

      </div>
    </div>
  )
}
