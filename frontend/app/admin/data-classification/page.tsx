'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  FolderLock, ShieldAlert, AlertTriangle, FileSearch,
  Plus, Loader2, X, Filter,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface DLPStats {
  total_findings: number
  restricted_top_secret: number
  confidential: number
  open: number
}

interface ClassificationPolicy {
  id: string
  name: string
  description: string
  level: 'top_secret' | 'restricted' | 'confidential' | 'internal' | 'public'
  file_extensions: string[]
  enabled: boolean
  match_count: number
}

interface DataFinding {
  id: string
  file_path: string
  level: 'top_secret' | 'restricted' | 'confidential' | 'internal' | 'public'
  agent_hostname: string
  match_count: number
  status: 'open' | 'reviewed' | 'dismissed'
  found_at: string
}

interface CreatePolicyPayload {
  name: string
  description: string
  level: ClassificationPolicy['level']
  file_extensions: string[]
}

// ─── Badge Helpers ────────────────────────────────────────────────────────────

type ClassLevel = ClassificationPolicy['level']

const LEVEL_STYLES: Record<ClassLevel, string> = {
  top_secret: 'bg-red-900/50 text-red-300 border border-red-700/50',
  restricted: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  confidential: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  internal: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  public: 'bg-green-900/40 text-green-300 border border-green-700/40',
}

const LEVEL_LABELS: Record<ClassLevel, string> = {
  top_secret: 'Top Secret',
  restricted: 'Restricted',
  confidential: 'Confidential',
  internal: 'Internal',
  public: 'Public',
}

function LevelBadge({ level }: { level: ClassLevel }) {
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[11px] font-semibold ${LEVEL_STYLES[level]}`}>
      {LEVEL_LABELS[level]}
    </span>
  )
}

function FindingStatusBadge({ status }: { status: DataFinding['status'] }) {
  const map = {
    open: 'bg-red-900/30 text-red-300 border border-red-700/30',
    reviewed: 'bg-blue-900/30 text-blue-300 border border-blue-700/30',
    dismissed: 'bg-falcon-border text-falcon-muted border border-[#2a3f5c]',
  }
  const labels = { open: 'Open', reviewed: 'Reviewed', dismissed: 'Dismissed' }
  return <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium ${map[status]}`}>{labels[status]}</span>
}

function EnabledToggle({ enabled }: { enabled: boolean }) {
  return (
    <div className={`relative w-9 h-5 rounded-full ${enabled ? 'bg-falcon-blue' : 'bg-falcon-border'}`}>
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text shadow-sm transition-transform ${enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </div>
  )
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

function formatMatchCount(n: number) {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`
  return String(n)
}

// ─── Add Policy Modal ─────────────────────────────────────────────────────────

function AddPolicyModal({
  onClose,
  onSubmit,
  loading,
}: {
  onClose: () => void
  onSubmit: (data: CreatePolicyPayload) => void
  loading: boolean
}) {
  const [form, setForm] = useState({
    name: '',
    description: '',
    level: 'confidential' as ClassLevel,
    file_extensions: '',
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md shadow-2xl mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-base">Add Classification Policy</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <form
          onSubmit={e => {
            e.preventDefault()
            onSubmit({
              ...form,
              file_extensions: form.file_extensions
                .split(',')
                .map(s => s.trim())
                .filter(Boolean),
            })
          }}
          className="p-6 space-y-4"
        >
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">Policy Name *</label>
            <input
              required
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-blue transition-colors"
              placeholder="e.g. Restricted PII"
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">Description</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-blue transition-colors resize-none"
              placeholder="Describe what this policy detects..."
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">Classification Level</label>
            <select
              value={form.level}
              onChange={e => setForm(f => ({ ...f, level: e.target.value as ClassLevel }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-blue transition-colors"
            >
              <option value="top_secret">Top Secret</option>
              <option value="restricted">Restricted</option>
              <option value="confidential">Confidential</option>
              <option value="internal">Internal</option>
              <option value="public">Public</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">File Extensions (comma-separated)</label>
            <input
              value={form.file_extensions}
              onChange={e => setForm(f => ({ ...f, file_extensions: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-blue transition-colors font-mono"
              placeholder=".pdf, .docx, .csv"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2 bg-falcon-red hover:bg-[#c00025] text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              Add Policy
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DataClassificationPage() {
  const qc = useQueryClient()
  const [showAddPolicy, setShowAddPolicy] = useState(false)
  const [levelFilter, setLevelFilter] = useState('all')

  // Stats
  const { data: statsData } = useQuery<DLPStats>({
    queryKey: ['dlp-stats'],
    queryFn: () => apiFetch('/api/v1/admin/data-classification/stats'),
    retry: false,
  })
  const EMPTY_DLP_STATS: DLPStats = { total_findings: 0, restricted_top_secret: 0, confidential: 0, open: 0 }
  const stats = statsData ?? EMPTY_DLP_STATS

  // Policies
  const { data: policiesData, isLoading: loadingPolicies } = useQuery<{ policies: ClassificationPolicy[] }>({
    queryKey: ['dlp-policies'],
    queryFn: () => apiFetch('/api/v1/admin/data-classification/policies'),
    retry: false,
  })
  const policies: ClassificationPolicy[] = policiesData?.policies ?? []

  // Findings
  const { data: findingsData, isLoading: loadingFindings } = useQuery<{ findings: DataFinding[] }>({
    queryKey: ['dlp-findings', levelFilter],
    queryFn: () => {
      const params = new URLSearchParams()
      if (levelFilter !== 'all') params.set('level', levelFilter)
      return apiFetch(`/api/v1/admin/data-classification/findings?${params.toString()}`)
    },
    retry: false,
  })
  const findings: DataFinding[] = findingsData?.findings ?? []

  // Create policy mutation
  const createPolicy = useMutation({
    mutationFn: (data: CreatePolicyPayload) =>
      apiFetch('/api/v1/admin/data-classification/policies', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp-policies'] })
      setShowAddPolicy(false)
    },
    onError: () => setShowAddPolicy(false),
  })

  const filteredFindings = findings.filter(f =>
    levelFilter === 'all' || f.level === levelFilter,
  )

  const STAT_CARDS = [
    { label: 'Total Findings', value: stats.total_findings, icon: FileSearch, color: 'text-falcon-muted', bg: 'border-falcon-border' },
    { label: 'Restricted / Top Secret', value: stats.restricted_top_secret, icon: ShieldAlert, color: 'text-red-400', bg: 'border-red-700/30 bg-red-900/10' },
    { label: 'Confidential', value: stats.confidential, icon: FolderLock, color: 'text-yellow-400', bg: 'border-yellow-700/30 bg-yellow-900/10' },
    { label: 'Open', value: stats.open, icon: AlertTriangle, color: 'text-orange-400', bg: 'border-orange-700/30 bg-orange-900/10' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <FolderLock className="w-6 h-6 text-falcon-red" />
            Data Loss Prevention &amp; Classification
          </h1>
          <p className="text-falcon-muted text-sm mt-1">
            Define classification policies and monitor sensitive data exposure across endpoints
          </p>
        </div>
        <button
          onClick={() => setShowAddPolicy(true)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c00025] text-white text-sm font-medium rounded-lg transition-colors shadow-lg shadow-red-900/20"
        >
          <Plus className="w-4 h-4" />
          Add Policy
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {STAT_CARDS.map(card => (
          <div key={card.label} className={`bg-falcon-surface border rounded-xl p-4 flex items-center gap-3 ${card.bg}`}>
            <card.icon className={`w-8 h-8 shrink-0 ${card.color}`} />
            <div>
              <p className="text-2xl font-bold text-white">{card.value}</p>
              <p className="text-xs text-falcon-muted">{card.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Classification Policies */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-falcon-border flex items-center justify-between">
          <div>
            <h2 className="text-white font-semibold text-sm">Classification Policies</h2>
            <p className="text-falcon-muted text-xs mt-0.5">{policies.length} policies configured</p>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border">
                {['Name', 'Level', 'File Extensions', 'Matches', 'Enabled'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {loadingPolicies ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i} className="animate-pulse border-b border-falcon-border">
                    {[160, 90, 200, 60, 50].map((w, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-3 bg-falcon-border rounded-sm" style={{ width: w }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : policies.map(policy => (
                <tr key={policy.id} className="hover:bg-[#0a1428] transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-white font-medium">{policy.name}</p>
                    {policy.description && (
                      <p className="text-falcon-muted text-xs mt-0.5 max-w-[200px] truncate">{policy.description}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <LevelBadge level={policy.level} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[260px]">
                      {policy.file_extensions.map(ext => (
                        <span key={ext} className="px-1.5 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-[10px] font-mono">
                          {ext}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-white font-semibold text-center">
                    {formatMatchCount(policy.match_count)}
                  </td>
                  <td className="px-4 py-3">
                    <EnabledToggle enabled={policy.enabled} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Data Findings */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-falcon-border flex items-center justify-between gap-4">
          <div>
            <h2 className="text-white font-semibold text-sm">Data Findings</h2>
            <p className="text-falcon-muted text-xs mt-0.5">{filteredFindings.length} findings</p>
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-falcon-muted" />
            <select
              value={levelFilter}
              onChange={e => setLevelFilter(e.target.value)}
              className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-1.5 text-xs text-white focus:outline-hidden focus:border-falcon-blue transition-colors"
            >
              <option value="all">All Levels</option>
              <option value="top_secret">Top Secret</option>
              <option value="restricted">Restricted</option>
              <option value="confidential">Confidential</option>
              <option value="internal">Internal</option>
              <option value="public">Public</option>
            </select>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border">
                {['File Path', 'Level', 'Agent / Hostname', 'Match Count', 'Status', 'Found At'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {loadingFindings ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="animate-pulse border-b border-falcon-border">
                    {[240, 90, 110, 60, 80, 100].map((w, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-3 bg-falcon-border rounded-sm" style={{ width: w }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-falcon-muted text-sm">
                    No findings match the selected level
                  </td>
                </tr>
              ) : filteredFindings.map(finding => (
                <tr key={finding.id} className="hover:bg-[#0a1428] transition-colors">
                  <td className="px-4 py-3 max-w-[280px]">
                    <span
                      className="block truncate font-mono text-xs text-falcon-muted hover:text-white transition-colors"
                      title={finding.file_path}
                    >
                      {finding.file_path}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <LevelBadge level={finding.level} />
                  </td>
                  <td className="px-4 py-3 text-white text-xs font-medium whitespace-nowrap">
                    {finding.agent_hostname}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-semibold text-sm ${finding.match_count > 1000 ? 'text-red-400' : finding.match_count > 100 ? 'text-orange-400' : 'text-white'}`}>
                      {formatMatchCount(finding.match_count)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <FindingStatusBadge status={finding.status} />
                  </td>
                  <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">
                    {formatDate(finding.found_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Policy Modal */}
      {showAddPolicy && (
        <AddPolicyModal
          onClose={() => setShowAddPolicy(false)}
          onSubmit={data => createPolicy.mutate(data)}
          loading={createPolicy.isPending}
        />
      )}
    </div>
  )
}
