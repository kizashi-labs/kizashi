'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Mail, Shield, AlertTriangle, Ban, FileText,
  RefreshCw, Filter, ChevronDown,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type EventType = 'phishing' | 'malware' | 'spam' | 'bec' | 'data_leak' | 'suspicious' | 'clean'
type ActionTaken = 'blocked' | 'quarantined' | 'tagged' | 'allowed'
type PolicyType = 'inbound' | 'outbound' | 'internal'

interface EmailEvent {
  id: string
  sender: string
  recipient: string
  subject: string
  event_type: EventType
  threat_score: number
  action_taken: ActionTaken
  source_ip: string
  timestamp: string
}

interface EmailPolicy {
  id: string
  name: string
  type: PolicyType
  action: string
  priority: number
  enabled: boolean
}

interface EmailStats {
  events_24h: number
  phishing_detected: number
  malware_detected: number
  blocked: number
  active_policies: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const eventTypeBadge = (t: EventType) => {
  const map: Record<EventType, string> = {
    phishing:  'bg-red-900/40 text-red-300 border-red-700/50',
    malware:   'bg-red-900/40 text-red-300 border-red-700/50',
    bec:       'bg-orange-900/40 text-orange-300 border-orange-700/50',
    spam:      'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    data_leak: 'bg-orange-900/40 text-orange-300 border-orange-700/50',
    suspicious:'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    clean:     'bg-green-900/40 text-green-300 border-green-700/50',
  }
  return map[t]
}

const actionBadge = (a: ActionTaken) => {
  const map: Record<ActionTaken, string> = {
    blocked:     'bg-red-900/40 text-red-300 border-red-700/50',
    quarantined: 'bg-orange-900/40 text-orange-300 border-orange-700/50',
    tagged:      'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    allowed:     'bg-green-900/40 text-green-300 border-green-700/50',
  }
  return map[a]
}

const policyTypeBadge = (t: PolicyType) => {
  const map: Record<PolicyType, string> = {
    inbound:  'bg-blue-900/40 text-blue-300 border-blue-700/50',
    outbound: 'bg-purple-900/40 text-purple-300 border-purple-700/50',
    internal: 'bg-cyan-900/40 text-cyan-300 border-cyan-700/50',
  }
  return map[t]
}

const threatScoreColor = (score: number) => {
  if (score >= 80) return 'bg-red-500'
  if (score >= 60) return 'bg-orange-500'
  if (score >= 40) return 'bg-yellow-500'
  return 'bg-green-500'
}

const threatScoreTextColor = (score: number) => {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString('en-US', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EmailSecurityPage() {
  const [activeTab, setActiveTab] = useState<'events' | 'policies'>('events')
  const [eventTypeFilter, setEventTypeFilter] = useState('all')

  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery<EmailStats>({
    queryKey: ['email-security-stats'],
    queryFn: () => apiFetch('/api/v1/admin/email-security/stats'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: eventsData } = useQuery<{ events: EmailEvent[] }>({
    queryKey: ['email-security-events', eventTypeFilter],
    queryFn: () => apiFetch(`/api/v1/admin/email-security/events?event_type=${eventTypeFilter}`),
    staleTime: 30_000,
    retry: false,
  })

  const { data: policiesData } = useQuery<{ policies: EmailPolicy[] }>({
    queryKey: ['email-security-policies'],
    queryFn: () => apiFetch('/api/v1/admin/email-security/policies'),
    staleTime: 60_000,
    retry: false,
  })

  const EMPTY_EMAIL_STATS: EmailStats = { events_24h: 0, phishing_detected: 0, malware_detected: 0, blocked: 0, active_policies: 0 }
  const displayStats = stats ?? EMPTY_EMAIL_STATS
  const rawEvents = eventsData?.events ?? []
  const displayEvents = eventTypeFilter === 'all'
    ? rawEvents
    : rawEvents.filter(e => e.event_type === eventTypeFilter)
  const displayPolicies = policiesData?.policies ?? []

  const statCards = [
    { label: 'Events (24h)', value: (displayStats.events_24h ?? 0).toLocaleString(), icon: Mail, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30' },
    { label: 'Phishing Detected', value: displayStats.phishing_detected, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
    { label: 'Malware Detected', value: displayStats.malware_detected, icon: Shield, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-700/30' },
    { label: 'Blocked', value: displayStats.blocked, icon: Ban, color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
    { label: 'Active Policies', value: displayStats.active_policies, icon: FileText, color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center shadow-lg">
                <Mail className="w-4 h-4 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">Email Security</h1>
                <p className="text-falcon-muted text-sm">Phishing, malware &amp; BEC protection</p>
              </div>
            </div>
            <button
              onClick={() => refetchStats()}
              className="flex items-center gap-2 px-3 py-2 text-sm text-falcon-muted hover:text-white border border-falcon-border hover:border-falcon-muted/40 rounded-lg transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
          </div>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-5 gap-4 mb-6">
          {statCards.map(s => (
            <div key={s.label} className={`rounded-xl p-4 border ${s.bg} bg-falcon-surface`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-falcon-muted">{s.label}</span>
                <s.icon className={`w-4 h-4 ${s.color}`} />
              </div>
              <p className={`text-3xl font-bold ${s.color}`}>
                {statsLoading ? '—' : s.value}
              </p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-5 border-b border-falcon-border">
          {(['events', 'policies'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px capitalize
                ${activeTab === tab
                  ? 'border-falcon-red text-white'
                  : 'border-transparent text-falcon-muted hover:text-white'
                }`}
            >
              {tab === 'events' ? 'Email Events' : 'Policies'}
            </button>
          ))}
        </div>

        {/* Events Tab */}
        {activeTab === 'events' && (
          <div>
            {/* Filter bar */}
            <div className="flex items-center gap-3 mb-4">
              <div className="flex items-center gap-2 text-falcon-muted">
                <Filter className="w-4 h-4" />
                <span className="text-sm">Event Type:</span>
              </div>
              <div className="relative">
                <select
                  value={eventTypeFilter}
                  onChange={e => setEventTypeFilter(e.target.value)}
                  className="bg-falcon-surface border border-falcon-border rounded-lg pl-3 pr-8 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/60 appearance-none cursor-pointer"
                >
                  <option value="all">All Types</option>
                  <option value="phishing">Phishing</option>
                  <option value="malware">Malware</option>
                  <option value="spam">Spam</option>
                  <option value="bec">BEC</option>
                  <option value="data_leak">Data Leak</option>
                  <option value="suspicious">Suspicious</option>
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-muted pointer-events-none" />
              </div>
              <span className="text-xs text-falcon-muted ml-auto">{displayEvents.length} events</span>
            </div>

            <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['Sender', 'Recipient', 'Subject', 'Event Type', 'Threat Score', 'Action Taken', 'Source IP', 'Timestamp'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {displayEvents.map(evt => (
                    <tr
                      key={evt.id}
                      className={`border-b border-falcon-border/50 transition-colors
                        ${evt.threat_score >= 70
                          ? 'bg-red-950/20 hover:bg-red-950/30'
                          : 'hover:bg-[#131d31]/50'
                        }`}
                    >
                      <td className="px-4 py-3">
                        <span className="text-white text-xs font-mono">{evt.sender}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-falcon-muted text-xs font-mono">{evt.recipient}</span>
                      </td>
                      <td className="px-4 py-3 max-w-[180px]">
                        <span className="text-white text-xs block truncate" title={evt.subject}>
                          {evt.subject}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${eventTypeBadge(evt.event_type)}`}>
                          {evt.event_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${threatScoreColor(evt.threat_score)}`}
                              style={{ width: `${evt.threat_score}%` }}
                            />
                          </div>
                          <span className={`text-xs font-bold ${threatScoreTextColor(evt.threat_score)}`}>
                            {evt.threat_score}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${actionBadge(evt.action_taken)}`}>
                          {evt.action_taken}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-falcon-muted text-xs font-mono">{evt.source_ip}</span>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className="text-falcon-muted text-xs">{fmtDate(evt.timestamp)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Policies Tab */}
        {activeTab === 'policies' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm text-falcon-muted">{displayPolicies.length} policies configured</p>
            </div>
            <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['Name', 'Type', 'Action', 'Priority', 'Enabled'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-falcon-muted font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {displayPolicies.map(pol => (
                    <tr key={pol.id} className="border-b border-falcon-border/50 hover:bg-[#131d31]/50 transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-white font-medium">{pol.name}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${policyTypeBadge(pol.type)}`}>
                          {pol.type}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-falcon-muted text-sm">{pol.action}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-white font-mono text-sm">P{pol.priority}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-medium
                          ${pol.enabled
                            ? 'bg-green-900/30 text-green-400 border border-green-700/40'
                            : 'bg-falcon-border/60 text-falcon-muted border border-falcon-border'
                          }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${pol.enabled ? 'bg-green-400' : 'bg-falcon-muted'}`} />
                          {pol.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
