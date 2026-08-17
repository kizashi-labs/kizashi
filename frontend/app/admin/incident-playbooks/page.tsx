'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BookOpen, Play, Plus, Loader2, X, CheckCircle,
  XCircle, Clock, RefreshCw, Zap, ListChecks,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Playbook {
  id: string
  name: string
  description: string
  category: string
  trigger_type: 'manual' | 'alert' | 'scheduled'
  enabled: boolean
  run_count: number
  last_run?: string
  steps_count: number
}

interface PlaybookExecution {
  id: string
  playbook_id: string
  playbook_name: string
  status: 'running' | 'completed' | 'failed'
  current_step: string
  started_at: string
  duration_seconds?: number
}

interface CreatePlaybookPayload {
  name: string
  description: string
  trigger_type: Playbook['trigger_type']
  category: string
}

// ─── Badge Helpers ────────────────────────────────────────────────────────────

function CategoryBadge({ category }: { category: string }) {
  const map: Record<string, string> = {
    Malware: 'bg-red-900/40 text-red-300 border border-red-700/40',
    Phishing: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
    Identity: 'bg-purple-900/40 text-purple-300 border border-purple-700/40',
    Network: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
    Compliance: 'bg-green-900/40 text-green-300 border border-green-700/40',
  }
  const cls = map[category] ?? 'bg-falcon-border text-falcon-muted border border-[#2a3f5c]'
  return <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium ${cls}`}>{category}</span>
}

function TriggerBadge({ type }: { type: Playbook['trigger_type'] }) {
  const map = {
    manual: 'bg-falcon-border text-falcon-muted border border-[#2a3f5c]',
    alert: 'bg-yellow-900/30 text-yellow-300 border border-yellow-700/30',
    scheduled: 'bg-blue-900/30 text-blue-300 border border-blue-700/30',
  }
  const labels = { manual: 'Manual', alert: 'Alert', scheduled: 'Scheduled' }
  return <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium ${map[type]}`}>{labels[type]}</span>
}

function ExecStatusBadge({ status }: { status: PlaybookExecution['status'] }) {
  const map = {
    running: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
    completed: 'bg-green-900/40 text-green-300 border border-green-700/40',
    failed: 'bg-red-900/40 text-red-300 border border-red-700/40',
  }
  const icons = {
    running: <Loader2 className="w-3 h-3 animate-spin" />,
    completed: <CheckCircle className="w-3 h-3" />,
    failed: <XCircle className="w-3 h-3" />,
  }
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium flex items-center gap-1 w-fit ${map[status]}`}>
      {icons[status]}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  )
}

function Toggle({ enabled, onChange }: { enabled: boolean; onChange: () => void }) {
  return (
    <button
      onClick={onChange}
      className={`relative w-9 h-5 rounded-full transition-colors shrink-0 ${enabled ? 'bg-falcon-blue' : 'bg-falcon-border'}`}
    >
      <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text shadow-sm transition-transform ${enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </button>
  )
}

function formatDuration(seconds?: number) {
  if (seconds === undefined) return '—'
  if (seconds < 60) return `${seconds}s`
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
}

function formatDate(iso?: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

// ─── New Playbook Modal ───────────────────────────────────────────────────────

function NewPlaybookModal({
  onClose,
  onSubmit,
  loading,
}: {
  onClose: () => void
  onSubmit: (data: CreatePlaybookPayload) => void
  loading: boolean
}) {
  const [form, setForm] = useState<CreatePlaybookPayload>({
    name: '',
    description: '',
    trigger_type: 'manual',
    category: '',
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md shadow-2xl mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-base">New Playbook</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <form
          onSubmit={e => { e.preventDefault(); onSubmit(form) }}
          className="p-6 space-y-4"
        >
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">Name *</label>
            <input
              required
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-blue transition-colors"
              placeholder="e.g. Ransomware Response"
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">Description</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-blue transition-colors resize-none"
              placeholder="Describe what this playbook does..."
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">Trigger Type</label>
              <select
                value={form.trigger_type}
                onChange={e => setForm(f => ({ ...f, trigger_type: e.target.value as Playbook['trigger_type'] }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-blue transition-colors"
              >
                <option value="manual">Manual</option>
                <option value="alert">Alert</option>
                <option value="scheduled">Scheduled</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">Category</label>
              <input
                value={form.category}
                onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-blue transition-colors"
                placeholder="e.g. Malware"
              />
            </div>
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
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function IncidentPlaybooksPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'playbooks' | 'executions'>('playbooks')
  const [showCreate, setShowCreate] = useState(false)
  const [runningId, setRunningId] = useState<string | null>(null)

  // Playbooks query
  const { data: pbData, isLoading: loadingPB } = useQuery<{ playbooks: Playbook[] }>({
    queryKey: ['incident-playbooks'],
    queryFn: () => apiFetch('/api/v1/admin/incident-playbooks'),
    retry: false,
  })
  const playbooks: Playbook[] = pbData?.playbooks ?? []

  // Executions query
  const { data: execData, isLoading: loadingExec } = useQuery<{ executions: PlaybookExecution[] }>({
    queryKey: ['playbook-executions'],
    queryFn: () => apiFetch('/api/v1/admin/incident-playbooks/executions'),
    retry: false,
  })
  const executions: PlaybookExecution[] = execData?.executions ?? []

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: CreatePlaybookPayload) =>
      apiFetch('/api/v1/admin/incident-playbooks', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incident-playbooks'] })
      setShowCreate(false)
    },
    onError: () => setShowCreate(false),
  })

  // Execute mutation
  const executeMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/incident-playbooks/${id}/execute`, { method: 'POST' }),
    onMutate: (id) => setRunningId(id),
    onSettled: () => {
      setRunningId(null)
      qc.invalidateQueries({ queryKey: ['playbook-executions'] })
      qc.invalidateQueries({ queryKey: ['incident-playbooks'] })
    },
  })

  const totalExecutions = executions.length
  const enabledCount = playbooks.filter(p => p.enabled).length

  const STAT_CARDS = [
    { label: 'Total Playbooks', value: playbooks.length, icon: BookOpen, color: 'text-falcon-muted' },
    { label: 'Enabled', value: enabledCount, icon: CheckCircle, color: 'text-green-400' },
    { label: 'Total Executions', value: totalExecutions, icon: Zap, color: 'text-blue-400' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <ListChecks className="w-6 h-6 text-falcon-red" />
            Incident Response Playbooks
          </h1>
          <p className="text-falcon-muted text-sm mt-1">
            Automate and orchestrate incident response workflows
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c00025] text-white text-sm font-medium rounded-lg transition-colors shadow-lg shadow-red-900/20"
        >
          <Plus className="w-4 h-4" />
          New Playbook
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-4">
        {STAT_CARDS.map(card => (
          <div key={card.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4 flex items-center gap-3">
            <card.icon className={`w-8 h-8 shrink-0 ${card.color}`} />
            <div>
              <p className="text-2xl font-bold text-white">{card.value}</p>
              <p className="text-xs text-falcon-muted">{card.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {[
          { key: 'playbooks', label: 'Playbooks' },
          { key: 'executions', label: 'Executions' },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as 'playbooks' | 'executions')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === tab.key ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Playbooks Tab */}
      {activeTab === 'playbooks' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['Name', 'Category', 'Trigger', 'Enabled', 'Run Count', 'Last Run', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {loadingPB ? (
                  Array.from({ length: 3 }).map((_, i) => (
                    <tr key={i} className="animate-pulse border-b border-falcon-border">
                      {[180, 80, 70, 50, 50, 100, 80].map((w, j) => (
                        <td key={j} className="px-4 py-3">
                          <div className="h-3 bg-falcon-border rounded-sm" style={{ width: w }} />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : playbooks.map(pb => (
                  <tr key={pb.id} className="hover:bg-[#0a1428] transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-white font-medium">{pb.name}</p>
                      {pb.description && (
                        <p className="text-falcon-muted text-xs mt-0.5 max-w-[220px] truncate">{pb.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <CategoryBadge category={pb.category} />
                    </td>
                    <td className="px-4 py-3">
                      <TriggerBadge type={pb.trigger_type} />
                    </td>
                    <td className="px-4 py-3">
                      <Toggle enabled={pb.enabled} onChange={() => {}} />
                    </td>
                    <td className="px-4 py-3 text-white font-semibold text-center">{pb.run_count}</td>
                    <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{formatDate(pb.last_run)}</td>
                    <td className="px-4 py-3">
                      <button
                        disabled={runningId === pb.id}
                        onClick={() => executeMutation.mutate(pb.id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-red/20 hover:bg-falcon-red/30 text-falcon-red text-xs font-medium rounded-lg transition-colors border border-falcon-red/30 disabled:opacity-50"
                      >
                        {runningId === pb.id
                          ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          : <Play className="w-3.5 h-3.5" />
                        }
                        Run
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Executions Tab */}
      {activeTab === 'executions' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['Playbook Name', 'Status', 'Current Step', 'Started At', 'Duration'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {loadingExec ? (
                  Array.from({ length: 4 }).map((_, i) => (
                    <tr key={i} className="animate-pulse border-b border-falcon-border">
                      {[160, 90, 180, 110, 70].map((w, j) => (
                        <td key={j} className="px-4 py-3">
                          <div className="h-3 bg-falcon-border rounded-sm" style={{ width: w }} />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : executions.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-10 text-center text-falcon-muted text-sm">
                      No executions recorded yet
                    </td>
                  </tr>
                ) : executions.map(exec => (
                  <tr key={exec.id} className="hover:bg-[#0a1428] transition-colors">
                    <td className="px-4 py-3 text-white font-medium">{exec.playbook_name}</td>
                    <td className="px-4 py-3">
                      <ExecStatusBadge status={exec.status} />
                    </td>
                    <td className="px-4 py-3 text-falcon-muted text-xs">{exec.current_step}</td>
                    <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">{formatDate(exec.started_at)}</td>
                    <td className="px-4 py-3 text-falcon-muted text-xs whitespace-nowrap">
                      {exec.status === 'running' ? (
                        <span className="flex items-center gap-1 text-blue-400">
                          <Loader2 className="w-3 h-3 animate-spin" /> Running...
                        </span>
                      ) : (
                        formatDuration(exec.duration_seconds)
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* New Playbook Modal */}
      {showCreate && (
        <NewPlaybookModal
          onClose={() => setShowCreate(false)}
          onSubmit={data => createMutation.mutate(data)}
          loading={createMutation.isPending}
        />
      )}
    </div>
  )
}
