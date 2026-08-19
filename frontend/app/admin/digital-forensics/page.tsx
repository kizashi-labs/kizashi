'use client'

import { useState } from 'react'
import {
  Search, HardDrive, FileText, Network, Database,
  Clock, CheckCircle, Archive, AlertTriangle,
  ChevronRight, Loader2, Play,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type CaseStatus = 'active' | 'evidence_collection' | 'analysis' | 'closed'
type CasePriority = 'critical' | 'high' | 'medium' | 'low'
type EvidenceType = 'memory' | 'disk' | 'logs' | 'network_capture'
type EvidenceStatus = 'collected' | 'verified' | 'submitted' | 'archived'
type TimelineType = 'alert' | 'malware' | 'network' | 'file' | 'response' | 'forensics'

interface ForensicCase {
  id: string
  name: string
  status: CaseStatus
  priority: CasePriority
  investigator: string
  evidence_count: number
  created: string
}

interface Evidence {
  id: string
  type: EvidenceType
  host: string
  collected_by: string
  hash: string
  status: EvidenceStatus
  timestamp: string
}

interface TimelineEvent {
  time: string
  event: string
  type: TimelineType
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const caseStatusBadge = (s: CaseStatus) => {
  const map: Record<CaseStatus, string> = {
    active:             'bg-green-900/40 text-green-300 border-green-700/50',
    evidence_collection:'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    analysis:           'bg-blue-900/40 text-blue-300 border-blue-700/50',
    closed:             'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]',
  }
  return map[s]
}

const caseStatusLabel = (s: CaseStatus) => {
  const map: Record<CaseStatus, string> = {
    active:             'Active',
    evidence_collection:'Evidence Collection',
    analysis:           'Analysis',
    closed:             'Closed',
  }
  return map[s]
}

const priorityBadge = (p: CasePriority) => {
  const map: Record<CasePriority, string> = {
    critical: 'bg-red-900/40 text-red-300 border-red-700/50',
    high:     'bg-orange-900/40 text-orange-300 border-orange-700/50',
    medium:   'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    low:      'bg-blue-900/40 text-blue-300 border-blue-700/50',
  }
  return map[p]
}

const evidenceTypeIcon = (t: EvidenceType) => {
  const map: Record<EvidenceType, React.ElementType> = {
    memory:          Database,
    disk:            HardDrive,
    logs:            FileText,
    network_capture: Network,
  }
  return map[t]
}

const evidenceTypeBadge = (t: EvidenceType) => {
  const map: Record<EvidenceType, string> = {
    memory:          'bg-purple-900/40 text-purple-300 border-purple-700/50',
    disk:            'bg-blue-900/40 text-blue-300 border-blue-700/50',
    logs:            'bg-cyan-900/40 text-cyan-300 border-cyan-700/50',
    network_capture: 'bg-orange-900/40 text-orange-300 border-orange-700/50',
  }
  return map[t]
}

const evidenceStatusBadge = (s: EvidenceStatus) => {
  const map: Record<EvidenceStatus, string> = {
    collected: 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
    verified:  'bg-green-900/40 text-green-300 border-green-700/50',
    submitted: 'bg-blue-900/40 text-blue-300 border-blue-700/50',
    archived:  'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]',
  }
  return map[s]
}

const evidenceStatusIcon = (s: EvidenceStatus) => {
  const map: Record<EvidenceStatus, React.ElementType> = {
    collected: Clock,
    verified:  CheckCircle,
    submitted: ChevronRight,
    archived:  Archive,
  }
  return map[s]
}

const timelineColor = (t: TimelineType) => {
  const map: Record<TimelineType, string> = {
    alert:     'bg-red-500 border-red-400',
    malware:   'bg-red-700 border-red-600',
    network:   'bg-orange-500 border-orange-400',
    file:      'bg-yellow-500 border-yellow-400',
    response:  'bg-blue-500 border-blue-400',
    forensics: 'bg-purple-500 border-purple-400',
  }
  return map[t]
}

const timelineTextColor = (t: TimelineType) => {
  const map: Record<TimelineType, string> = {
    alert:     'text-red-400',
    malware:   'text-red-400',
    network:   'text-orange-400',
    file:      'text-yellow-400',
    response:  'text-blue-400',
    forensics: 'text-purple-400',
  }
  return map[t]
}

const timelineTypeLabel = (t: TimelineType) =>
  t.charAt(0).toUpperCase() + t.slice(1)

const fmtDateTime = (iso: string) =>
  new Date(iso).toLocaleString('en-US', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })

const fmtDate = (d: string) => new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DigitalForensicsPage() {
  // Evidence collection local state
  const [memAcquiring, setMemAcquiring] = useState<Record<string, 'idle' | 'loading' | 'done'>>({})
  const [diskPath, setDiskPath] = useState('')
  const [diskAgent, setDiskAgent] = useState<string | null>(null)
  const [diskState, setDiskState] = useState<'idle' | 'loading' | 'done'>('idle')
  const [logsFrom, setLogsFrom] = useState('')
  const [logsTo, setLogsTo] = useState('')
  const [logsAgent, setLogsAgent] = useState<string | null>(null)
  const [logsState, setLogsState] = useState<'idle' | 'loading' | 'done'>('idle')

  const acquireMemory = (host: string) => {
    setMemAcquiring(prev => ({ ...prev, [host]: 'loading' }))
    setTimeout(() => setMemAcquiring(prev => ({ ...prev, [host]: 'done' })), 1800)
  }

  const createDiskImage = () => {
    setDiskState('loading')
    setTimeout(() => setDiskState('done'), 2000)
  }

  const collectLogs = () => {
    setLogsState('loading')
    setTimeout(() => setLogsState('done'), 1600)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center shadow-lg">
              <Search className="w-4 h-4 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Digital Forensics</h1>
              <p className="text-[#7d92b0] text-sm">Evidence collection &amp; chain of custody</p>
            </div>
          </div>
        </div>

        {/* Active Cases */}
        <section className="mb-8">
          <h2 className="text-white font-semibold text-lg mb-4">Active Cases</h2>
          <div className="grid grid-cols-3 gap-4">
            {([] as ForensicCase[]).map(c => (
              <div
                key={c.id}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 hover:border-[#2a3d58] transition-colors"
              >
                <div className="flex items-start justify-between mb-3">
                  <span className="text-[#7d92b0] text-xs font-mono">{c.id}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${priorityBadge(c.priority)}`}>
                    {c.priority}
                  </span>
                </div>
                <h3 className="text-white font-semibold text-sm mb-3 leading-snug">{c.name}</h3>
                <div className="space-y-2 mb-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[#7d92b0]">Status</span>
                    <span className={`text-xs px-2 py-0.5 rounded-sm border ${caseStatusBadge(c.status)}`}>
                      {caseStatusLabel(c.status)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[#7d92b0]">Investigator</span>
                    <span className="text-xs text-white">{c.investigator}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[#7d92b0]">Evidence Items</span>
                    <span className="text-xs text-white font-bold">{c.evidence_count}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[#7d92b0]">Created</span>
                    <span className="text-xs text-[#7d92b0]">{fmtDate(c.created)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Evidence Collection Panel */}
        <section className="mb-8">
          <h2 className="text-white font-semibold text-lg mb-4">Evidence Collection</h2>
          <div className="grid grid-cols-3 gap-4">

            {/* Memory Acquisition */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <Database className="w-4 h-4 text-purple-400" />
                <h3 className="text-white font-medium text-sm">Memory Acquisition</h3>
              </div>
              <div className="space-y-2">
                {([] as string[]).slice(0, 4).map(agent => {
                  const state = memAcquiring[agent] ?? 'idle'
                  return (
                    <div key={agent} className="flex items-center justify-between py-1.5 px-2 rounded-lg bg-[#070d19] border border-[#1e2d42]/60">
                      <span className="text-xs text-[#7d92b0] font-mono truncate flex-1 mr-2">{agent}</span>
                      {state === 'idle' && (
                        <button
                          onClick={() => acquireMemory(agent)}
                          className="flex items-center gap-1 px-2 py-1 text-xs bg-purple-900/40 hover:bg-purple-900/60 text-purple-300 border border-purple-700/50 rounded-sm transition-colors whitespace-nowrap"
                        >
                          <Play className="w-3 h-3" />
                          Acquire
                        </button>
                      )}
                      {state === 'loading' && (
                        <span className="flex items-center gap-1 text-xs text-yellow-400">
                          <Loader2 className="w-3 h-3 animate-spin" />
                          Running...
                        </span>
                      )}
                      {state === 'done' && (
                        <span className="flex items-center gap-1 text-xs text-green-400">
                          <CheckCircle className="w-3 h-3" />
                          Scheduled
                        </span>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Disk Imaging */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <HardDrive className="w-4 h-4 text-blue-400" />
                <h3 className="text-white font-medium text-sm">Disk Imaging</h3>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">File Path / Drive</label>
                  <input
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/60"
                    placeholder="/dev/sda or C:\\"
                    value={diskPath}
                    onChange={e => setDiskPath(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">Target Agent</label>
                  <select
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/60"
                    value={diskAgent ?? ''}
                    onChange={e => setDiskAgent(e.target.value)}
                  >
                    {([] as string[]).map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
                <button
                  onClick={createDiskImage}
                  disabled={diskState === 'loading' || !diskPath}
                  className={`w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-colors
                    ${diskState === 'done'
                      ? 'bg-green-900/40 text-green-300 border border-green-700/50 cursor-default'
                      : 'bg-[#e8002d] hover:bg-[#c0001f] text-white disabled:opacity-50 disabled:cursor-not-allowed'
                    }`}
                >
                  {diskState === 'loading' && <Loader2 className="w-4 h-4 animate-spin" />}
                  {diskState === 'done' && <CheckCircle className="w-4 h-4" />}
                  {diskState === 'idle' && 'Create Image'}
                  {diskState === 'loading' && 'Creating...'}
                  {diskState === 'done' && 'Scheduled'}
                </button>
              </div>
            </div>

            {/* Log Collection */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-white font-medium text-sm">Log Collection</h3>
              </div>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1.5">From</label>
                    <input
                      type="date"
                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-2 py-2 text-xs text-white focus:outline-hidden focus:border-[#e8002d]/60"
                      value={logsFrom}
                      onChange={e => setLogsFrom(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1.5">To</label>
                    <input
                      type="date"
                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-2 py-2 text-xs text-white focus:outline-hidden focus:border-[#e8002d]/60"
                      value={logsTo}
                      onChange={e => setLogsTo(e.target.value)}
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1.5">Target Agent</label>
                  <select
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/60"
                    value={logsAgent ?? ''}
                    onChange={e => setLogsAgent(e.target.value)}
                  >
                    {([] as string[]).map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
                <button
                  onClick={collectLogs}
                  disabled={logsState === 'loading' || !logsFrom || !logsTo}
                  className={`w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-colors
                    ${logsState === 'done'
                      ? 'bg-green-900/40 text-green-300 border border-green-700/50 cursor-default'
                      : 'bg-[#e8002d] hover:bg-[#c0001f] text-white disabled:opacity-50 disabled:cursor-not-allowed'
                    }`}
                >
                  {logsState === 'loading' && <Loader2 className="w-4 h-4 animate-spin" />}
                  {logsState === 'done' && <CheckCircle className="w-4 h-4" />}
                  {logsState === 'idle' && 'Collect Logs'}
                  {logsState === 'loading' && 'Collecting...'}
                  {logsState === 'done' && 'Scheduled'}
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* Chain of Custody */}
        <section className="mb-8">
          <h2 className="text-white font-semibold text-lg mb-4">Chain of Custody</h2>
          <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['Evidence ID', 'Type', 'Agent / Host', 'Collected By', 'SHA256 Hash', 'Status', 'Timestamp'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {([] as Evidence[]).map(evd => {
                  const TypeIcon = evidenceTypeIcon(evd.type)
                  const StatusIcon = evidenceStatusIcon(evd.status)
                  return (
                    <tr key={evd.id} className="border-b border-[#1e2d42]/50 hover:bg-[#131d31]/50 transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-white font-mono text-xs font-bold">{evd.id}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-sm border ${evidenceTypeBadge(evd.type)}`}>
                          <TypeIcon className="w-3 h-3" />
                          {evd.type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[#7d92b0] text-xs font-mono">{evd.host}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-white text-xs">{evd.collected_by}</span>
                      </td>
                      <td className="px-4 py-3">
                        <code className="text-[#7d92b0] text-xs font-mono bg-[#070d19] px-2 py-0.5 rounded-sm">
                          {evd.hash}
                        </code>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-sm border capitalize ${evidenceStatusBadge(evd.status)}`}>
                          <StatusIcon className="w-3 h-3" />
                          {evd.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[#7d92b0] text-xs whitespace-nowrap">{fmtDateTime(evd.timestamp)}</span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* Timeline Reconstruction */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold text-lg">Timeline Reconstruction</h2>
            <span className="text-[#7d92b0] text-sm">— FOR-2026-001: Ransomware Incident</span>
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <div className="relative">
              {/* Vertical line */}
              <div className="absolute left-[11px] top-2 bottom-2 w-px bg-[#1e2d42]" />
              <div className="space-y-6">
                {([] as TimelineEvent[]).map((evt, idx) => (
                  <div key={idx} className="flex gap-4 relative">
                    {/* Dot */}
                    <div className={`w-6 h-6 rounded-full border-2 shrink-0 flex items-center justify-center z-10 ${timelineColor(evt.type)}`}>
                      <div className="w-2 h-2 rounded-full bg-[#e2e8f4]/80" />
                    </div>
                    {/* Content */}
                    <div className="flex-1 pb-1">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-white text-sm">{evt.event}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={`text-xs font-medium ${timelineTextColor(evt.type)}`}>
                              {timelineTypeLabel(evt.type)}
                            </span>
                            <span className="text-[#3d5068] text-xs">•</span>
                            <span className="text-[#7d92b0] text-xs font-mono">
                              {new Date(evt.time).toLocaleString('en-US', {
                                month: '2-digit', day: '2-digit',
                                hour: '2-digit', minute: '2-digit',
                                second: '2-digit', hour12: false,
                              })}
                            </span>
                          </div>
                        </div>
                        {evt.type === 'alert' && (
                          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                        )}
                        {evt.type === 'response' && (
                          <CheckCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

      </div>
    </div>
  )
}
