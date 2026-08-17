'use client'

import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  AlertOctagon, RefreshCw, ChevronDown, ChevronUp,
  Clock, User, Hash, Activity, List, Server,
} from 'lucide-react'

// ─── Types (server wire format) ───────────────────────────────────────────────
// Mirrors server/internal/store.Incident, served by IncidentHandler.List at
// GET /api/v1/admin/incidents as {data: [...], total, page, per_page}.
// NOTE: there is no alert_ids / agent_ids / mitre_tactic on this model — the
// correlation.Incident type that has those fields is served by a handler that
// is never registered in the router. Do not reintroduce those fields here.

interface Incident {
  id: string
  title: string
  description?: string
  severity: number
  status: string
  assigned_to?: string
  assigned_to_name?: string
  created_by?: string
  created_by_name?: string
  alert_count: number
  created_at: string
  updated_at: string
  resolved_at?: string
}

/** Alert linked to an incident — store.IncidentAlert, from GET /api/v1/incidents/:id */
interface IncidentAlert {
  alert_id: string
  title: string
  severity: number
  status: string
  hostname: string
  mitre_technique: string
  created_at: string
  linked_at: string
}

/** correlationEngineRule, from GET /api/v1/correlation-engine */
interface CorrelationRule {
  id: string
  name: string
  description: string
  enabled: boolean
  trigger_event_type: string
  follow_event_type: string
  time_window_seconds: number
  alert_severity: number
  match_count: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_COLOR = (s: number) => {
  if (s >= 9) return { bg: 'bg-red-500/15 border-red-500/30', text: 'text-red-400' }
  if (s >= 7) return { bg: 'bg-orange-500/15 border-orange-500/30', text: 'text-orange-400' }
  if (s >= 5) return { bg: 'bg-yellow-500/15 border-yellow-500/30', text: 'text-yellow-400' }
  return { bg: 'bg-blue-500/15 border-blue-500/30', text: 'text-blue-400' }
}

// Must cover every value in the server's validIncidentStatuses map
// (incidents_handler.go). Unknown values fall back rather than crashing.
const STATUS_CONFIG: Record<string, { label: string; className: string }> = {
  open: { label: 'Open', className: 'bg-red-500/15 text-red-400 border-red-500/30' },
  investigating: { label: 'Investigating', className: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
  contained: { label: 'Contained', className: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
  resolved: { label: 'Resolved', className: 'bg-green-500/15 text-green-400 border-green-500/30' },
  closed: { label: 'Closed', className: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30' },
}

const statusConfig = (s: string) =>
  STATUS_CONFIG[s] ?? { label: s || 'Unknown', className: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30' }

const STATUS_FLOW = ['open', 'investigating', 'contained', 'resolved', 'closed'] as const

const PER_PAGE = 200

// GET /api/v1/incidents/:id returns every linked alert with no server-side
// LIMIT (store.IncidentStore.ListAlerts), and live data has incidents with
// 85k+ linked alerts. Only expand inline below this threshold; above it, send
// the user to the dedicated detail page instead of pulling the whole set.
const MAX_INLINE_ALERTS = 200

const fmtDate = (iso?: string) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

const fmtWindow = (sec: number) => {
  if (!sec) return '—'
  if (sec % 3600 === 0) return `${sec / 3600}h`
  if (sec % 60 === 0) return `${sec / 60}m`
  return `${sec}s`
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function IncidentsPage() {
  const qc = useQueryClient()
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [showCorrelation, setShowCorrelation] = useState(false)
  const [statusError, setStatusError] = useState<Record<string, string>>({})

  const { data: incidentsData, isLoading: incLoading, refetch: refetchInc } = useQuery<Incident[]>({
    queryKey: ['admin-incidents'],
    queryFn: () => apiFetchList<Incident>(`/api/v1/admin/incidents?per_page=${PER_PAGE}`).catch(() => []),
    staleTime: 30_000,
    retry: 0,
  })

  const { data: correlationRulesData } = useQuery<CorrelationRule[]>({
    queryKey: ['correlation-engine-rules'],
    queryFn: () => apiFetchList<CorrelationRule>('/api/v1/correlation-engine?limit=200').catch(() => []),
    staleTime: 60_000,
    retry: 0,
  })

  const incidents = incidentsData ?? []
  const correlationRules = correlationRulesData ?? []

  const expandedIncident = incidents.find(i => i.id === expandedId)
  const inlineAlertsOk = !!expandedIncident
    && expandedIncident.alert_count > 0
    && expandedIncident.alert_count <= MAX_INLINE_ALERTS

  // Linked alerts are not part of the list payload — fetch them per incident
  // only while its row is expanded, and only when the set is small enough to
  // render inline (see MAX_INLINE_ALERTS).
  const { data: detail, isLoading: detailLoading } = useQuery<{ alerts: IncidentAlert[] }>({
    queryKey: ['admin-incident-detail', expandedId],
    queryFn: () => apiFetch<{ alerts: IncidentAlert[] }>(`/api/v1/incidents/${expandedId}`)
      .then(r => ({ alerts: r.alerts ?? [] })).catch(() => ({ alerts: [] })),
    enabled: !!expandedId && inlineAlertsOk,
    staleTime: 30_000,
    retry: 0,
  })

  const filtered = statusFilter === 'all'
    ? incidents
    : incidents.filter(i => i.status === statusFilter)

  const countBy = (s: string) => incidents.filter(i => i.status === s).length

  const stats = {
    open: countBy('open'),
    investigating: countBy('investigating'),
    resolved: countBy('resolved') + countBy('closed'),
    alertsCorrelated: incidents.reduce((sum, i) => sum + (i.alert_count ?? 0), 0),
  }

  const handleStatusChange = async (incId: string, newStatus: string) => {
    setStatusError(prev => ({ ...prev, [incId]: '' }))
    try {
      await apiFetch(`/api/v1/incidents/${incId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: newStatus }),
      })
      await qc.invalidateQueries({ queryKey: ['admin-incidents'] })
    } catch (e: unknown) {
      setStatusError(prev => ({
        ...prev,
        [incId]: e instanceof Error ? e.message : 'ステータスの更新に失敗しました',
      }))
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <AlertOctagon className="w-7 h-7 text-red-400" />
            Incident Management
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            Correlated security incidents and response tracking
          </p>
        </div>
        <button
          onClick={() => refetchInc()}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200 text-sm transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Open Incidents', value: stats.open, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
          { label: 'Investigating', value: stats.investigating, color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
          { label: 'Resolved / Closed', value: stats.resolved, color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20' },
          { label: 'Alerts Correlated', value: stats.alertsCorrelated.toLocaleString(), color: 'text-blue-400', bg: 'bg-zinc-900 border-zinc-800' },
        ].map(s => (
          <div key={s.label} className={`${s.bg} border rounded-lg p-4`}>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            <p className="text-zinc-500 text-xs mt-1">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Status Filter */}
      <div className="flex gap-1 mb-5 border-b border-zinc-800 flex-wrap">
        {(['all', ...STATUS_FLOW] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setStatusFilter(tab)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              statusFilter === tab
                ? 'border-red-400 text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {tab === 'all' ? 'All' : statusConfig(tab).label}
            <span className="ml-1.5 text-xs opacity-70">
              ({tab === 'all' ? incidents.length : countBy(tab)})
            </span>
          </button>
        ))}
      </div>

      {/* Incidents List */}
      {incLoading && (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-6 h-6 text-zinc-500 animate-spin" />
        </div>
      )}

      <div className="space-y-2 mb-6">
        {filtered.length === 0 && !incLoading && (
          <div className="text-center py-12 text-zinc-600">
            <AlertOctagon className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p>フィルターに一致するインシデントがありません</p>
          </div>
        )}

        {filtered.map(inc => {
          const sev = SEVERITY_COLOR(inc.severity)
          const st = statusConfig(inc.status)
          const isExpanded = expandedId === inc.id

          return (
            <div key={inc.id} className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
              {/* Row */}
              <div
                onClick={() => setExpandedId(isExpanded ? null : inc.id)}
                className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-zinc-800/40 transition-colors"
              >
                {/* Severity Badge */}
                <span className={`inline-flex items-center justify-center w-8 h-8 rounded-lg text-sm font-bold border shrink-0 ${sev.bg} ${sev.text}`}>
                  {inc.severity}
                </span>

                {/* Title */}
                <div className="flex-1 min-w-0">
                  <span className="text-zinc-100 font-semibold text-sm">{inc.title}</span>
                  {inc.description && (
                    <p className="text-zinc-500 text-xs mt-0.5 truncate">{inc.description}</p>
                  )}
                </div>

                {/* Status */}
                <span className={`inline-flex items-center px-2.5 py-1 rounded-sm text-xs font-medium border shrink-0 ${st.className}`}>
                  {st.label}
                </span>

                {/* Counts */}
                <div className="flex items-center gap-3 text-xs text-zinc-500 shrink-0">
                  <span className="flex items-center gap-1">
                    <Activity className="w-3.5 h-3.5" />
                    {inc.alert_count} alerts
                  </span>
                  <span className="flex items-center gap-1">
                    <User className="w-3.5 h-3.5" />
                    {inc.assigned_to_name || '未割当'}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3.5 h-3.5" />
                    {new Date(inc.created_at).toLocaleDateString()}
                  </span>
                </div>

                {isExpanded ? <ChevronUp className="w-4 h-4 text-zinc-500 shrink-0" /> : <ChevronDown className="w-4 h-4 text-zinc-500 shrink-0" />}
              </div>

              {/* Expanded Detail */}
              {isExpanded && (
                <div className="border-t border-zinc-800 px-5 py-4 bg-zinc-950/40">
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <h4 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Description</h4>
                      <p className="text-zinc-300 text-sm leading-relaxed">{inc.description || '—'}</p>

                      <div className="mt-4">
                        <h4 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Details</h4>
                        <dl className="space-y-1 text-sm">
                          {[
                            ['Assigned To', inc.assigned_to_name || '未割当'],
                            ['Created By', inc.created_by_name || 'system'],
                            ['Created', fmtDate(inc.created_at)],
                            ['Updated', fmtDate(inc.updated_at)],
                            ['Resolved', fmtDate(inc.resolved_at)],
                          ].map(([k, v]) => (
                            <div key={k} className="flex items-center gap-2">
                              <dt className="text-zinc-500 w-24 shrink-0">{k}:</dt>
                              <dd className="text-zinc-300">{v}</dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    </div>

                    <div>
                      <div className="mb-4">
                        <h4 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2 flex items-center gap-1">
                          <Activity className="w-3.5 h-3.5" /> Linked Alerts ({inc.alert_count})
                        </h4>
                        {inc.alert_count > MAX_INLINE_ALERTS ? (
                          <p className="text-zinc-500 text-xs">
                            アラートが {inc.alert_count.toLocaleString()} 件と多いため、ここには表示しません。
                            {' '}
                            <a
                              href={`/incidents/${inc.id}`}
                              onClick={e => e.stopPropagation()}
                              className="text-blue-400 hover:underline"
                            >
                              インシデント詳細ページ
                            </a>
                            {' '}で確認してください。
                          </p>
                        ) : detailLoading ? (
                          <p className="text-zinc-600 text-xs">読み込み中...</p>
                        ) : (detail?.alerts.length ?? 0) === 0 ? (
                          <p className="text-zinc-600 text-xs">紐づくアラートはありません</p>
                        ) : (
                          <div className="space-y-1.5 max-h-64 overflow-y-auto">
                            {detail!.alerts.map(a => {
                              const asev = SEVERITY_COLOR(a.severity)
                              return (
                                <div key={a.alert_id} className="flex items-start gap-2 p-2 rounded-sm bg-zinc-900 border border-zinc-800">
                                  <span className={`inline-flex items-center justify-center w-6 h-6 rounded-sm text-[11px] font-bold border shrink-0 ${asev.bg} ${asev.text}`}>
                                    {a.severity}
                                  </span>
                                  <div className="min-w-0">
                                    <p className="text-zinc-200 text-xs truncate">{a.title}</p>
                                    <div className="flex items-center gap-2 text-[11px] text-zinc-500 mt-0.5">
                                      {a.hostname && (
                                        <span className="flex items-center gap-0.5">
                                          <Server className="w-3 h-3" />{a.hostname}
                                        </span>
                                      )}
                                      {a.mitre_technique && (
                                        <span className="text-purple-400">{a.mitre_technique}</span>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              )
                            })}
                          </div>
                        )}
                      </div>

                      <div>
                        <h4 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2">Change Status</h4>
                        <div className="flex gap-2 flex-wrap">
                          {STATUS_FLOW.map(s => (
                            <button
                              key={s}
                              onClick={e => { e.stopPropagation(); handleStatusChange(inc.id, s) }}
                              className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
                                inc.status === s
                                  ? statusConfig(s).className
                                  : 'border-zinc-700 text-zinc-500 hover:text-zinc-300 hover:border-zinc-600'
                              }`}
                            >
                              {statusConfig(s).label}
                            </button>
                          ))}
                        </div>
                        {statusError[inc.id] && (
                          <p className="text-xs text-red-400 mt-2">{statusError[inc.id]}</p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Correlation Rules Panel */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg">
        <button
          onClick={() => setShowCorrelation(v => !v)}
          className="w-full flex items-center justify-between px-5 py-4 hover:bg-zinc-800/30 transition-colors"
        >
          <div className="flex items-center gap-2">
            <List className="w-5 h-5 text-zinc-500" />
            <span className="text-zinc-100 font-semibold">Correlation Rules</span>
            <span className="text-xs text-zinc-500 ml-1">({correlationRules.length} rules)</span>
          </div>
          {showCorrelation ? <ChevronUp className="w-4 h-4 text-zinc-500" /> : <ChevronDown className="w-4 h-4 text-zinc-500" />}
        </button>

        {showCorrelation && (
          <div className="border-t border-zinc-800">
            {correlationRules.length === 0 ? (
              <div className="text-center py-8 text-zinc-600 text-sm">
                相関ルールが登録されていません
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-zinc-800">
                      {['Rule Name', 'Trigger → Follow', 'Time Window', 'Severity', 'Matches', 'Status'].map(h => (
                        <th key={h} className="text-left px-5 py-3 text-xs font-semibold text-zinc-500 uppercase tracking-wider whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {correlationRules.map((rule, i) => (
                      <tr key={rule.id} className={`border-b border-zinc-800/50 ${i % 2 === 0 ? '' : 'bg-zinc-950/20'}`}>
                        <td className="px-5 py-3 text-zinc-200 font-medium text-sm">
                          {rule.name}
                          {rule.description && (
                            <p className="text-zinc-500 text-xs font-normal mt-0.5 max-w-md">{rule.description}</p>
                          )}
                        </td>
                        <td className="px-5 py-3 text-zinc-400 text-xs font-mono whitespace-nowrap">
                          {rule.trigger_event_type} → {rule.follow_event_type}
                        </td>
                        <td className="px-5 py-3 text-zinc-400 text-sm">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3.5 h-3.5" />
                            {fmtWindow(rule.time_window_seconds)}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-sm">
                          <span className={SEVERITY_COLOR(rule.alert_severity).text}>{rule.alert_severity}</span>
                        </td>
                        <td className="px-5 py-3 text-zinc-400 text-sm">
                          <span className="flex items-center gap-1">
                            <Hash className="w-3.5 h-3.5" />
                            {rule.match_count}
                          </span>
                        </td>
                        <td className="px-5 py-3">
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[11px] font-medium border ${rule.enabled ? 'bg-green-500/15 text-green-400 border-green-500/30' : 'bg-zinc-500/15 text-zinc-500 border-zinc-500/30'}`}>
                            {rule.enabled ? 'Enabled' : 'Disabled'}
                          </span>
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
    </div>
  )
}
