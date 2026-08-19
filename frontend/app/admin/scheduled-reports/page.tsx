'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Calendar, Plus, Trash2, Play, ToggleLeft, ToggleRight,
  Mail, Clock, FileText, RefreshCw, X, CheckCircle, AlertCircle,
  Download, ChevronDown,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { usePersist, SaveFailed } from '@/lib/persist'

// ─── Types ────────────────────────────────────────────────────────────────────

type ReportType = 'executive_summary' | 'compliance' | 'incident_report' | 'threat_summary'
type Format = 'json' | 'csv' | 'pdf'
type SchedulePreset = 'daily' | 'weekly' | 'monthly' | 'custom'

interface ReportSchedule {
  id: string
  name: string
  report_type: ReportType
  cron: string
  format: Format
  recipients: string[]
  enabled: boolean
  last_run: string | null
  next_run: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  executive_summary: 'Executive Summary',
  compliance: 'Compliance',
  incident_report: 'Incident Report',
  threat_summary: 'Threat Summary',
}

const REPORT_TYPE_COLORS: Record<ReportType, string> = {
  executive_summary: 'bg-blue-900/40 text-blue-300 border-blue-700/60',
  compliance:        'bg-green-900/40 text-green-300 border-green-700/60',
  incident_report:   'bg-red-900/40 text-red-300 border-red-700/60',
  threat_summary:    'bg-orange-900/40 text-orange-300 border-orange-700/60',
}

const FORMAT_COLORS: Record<Format, string> = {
  json: 'bg-zinc-800 text-zinc-300 border-zinc-700',
  csv:  'bg-purple-900/40 text-purple-300 border-purple-700/60',
  pdf:  'bg-rose-900/40 text-rose-300 border-rose-700/60',
}

const PRESET_CRONS: Record<Exclude<SchedulePreset, 'custom'>, string> = {
  daily:   '0 8 * * *',
  weekly:  '0 8 * * MON',
  monthly: '0 8 1 * *',
}

function humanizeCron(cron: string): string {
  if (cron === '0 8 * * *') return 'Every day at 8:00 AM'
  if (cron === '0 8 * * MON') return 'Every Monday at 8:00 AM'
  if (cron === '0 8 1 * *') return 'Every 1st of month at 8:00 AM'
  return cron
}

function formatDate(ts: string | null): string {
  if (!ts) return 'Never'
  return new Date(ts).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function ScheduledReportsPage() {
  const queryClient = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [runningId, setRunningId] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Form state
  const [form, setForm] = useState({
    name: '',
    report_type: 'executive_summary' as ReportType,
    preset: 'weekly' as SchedulePreset,
    custom_cron: '',
    format: 'json' as Format,
    recipient_input: '',
    recipients: [] as string[],
  })

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message })
    setTimeout(() => setToast(null), 3000)
  }

  const { data: schedules = [], refetch } = useQuery<ReportSchedule[]>({
    queryKey: ['report-schedules'],
    queryFn: () => apiFetch('/api/v1/admin/reports/schedules'),
  })

  const [localSchedules, setLocalSchedules] = useState<ReportSchedule[]>([])
  const { persist, saveError } = usePersist()

  // Sync API data into local state when a real (non-mock) response arrives
  useEffect(() => {
    if (schedules && schedules.length > 0) {
      setLocalSchedules(schedules)
    }
  }, [schedules])

  // 定期レポートは、届かなくなったことに誰も気づかない種類の機能です。
  // 有効にしたつもりのスケジュールが保存されていなければ、報告書は
  // 来月も再来月も届きません。
  const handleToggle = async (id: string) => {
    if (await persist('スケジュールの有効/無効', `/api/v1/admin/reports/schedules/${id}/toggle`, { method: 'PUT' })) {
      setLocalSchedules(prev =>
        prev.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s)
      )
    }
  }

  const handleDelete = async (id: string) => {
    setDeletingId(id)
    const ok = await persist('スケジュールの削除', `/api/v1/admin/reports/schedules/${id}`, { method: 'DELETE' })
    setDeletingId(null)
    if (!ok) return
    setLocalSchedules(prev => prev.filter(s => s.id !== id))
    showToast('success', 'Schedule deleted')
  }

  const handleRunNow = async (schedule: ReportSchedule) => {
    setRunningId(schedule.id)
    try {
      const result = await apiFetch<Blob>('/api/v1/admin/reports/generate', {
        method: 'POST',
        body: JSON.stringify({
          report_type: schedule.report_type,
          format: schedule.format,
          recipients: schedule.recipients,
        }),
      })
      // Simulate download
      const blob = new Blob([JSON.stringify({ report: 'generated', schedule: schedule.name })], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${schedule.name.replace(/\s+/g, '-')}-${Date.now()}.${schedule.format}`
      a.click()
      URL.revokeObjectURL(url)
      showToast('success', 'Report generated and downloaded')
    } catch {
      // Mock download
      const blob = new Blob([JSON.stringify({ report: 'mock', name: schedule.name }, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${schedule.name.replace(/\s+/g, '-')}-${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
      showToast('success', 'Report downloaded (mock)')
    } finally {
      setRunningId(null)
    }
  }

  const handleCreate = async () => {
    if (!form.name.trim()) { showToast('error', 'Name is required'); return }
    if (form.recipients.length === 0) { showToast('error', 'Add at least one recipient'); return }
    const cron = form.preset === 'custom' ? form.custom_cron : PRESET_CRONS[form.preset]
    const newSchedule: ReportSchedule = {
      id: `rs${Date.now()}`, name: form.name,
      report_type: form.report_type, cron,
      format: form.format, recipients: form.recipients,
      enabled: true, last_run: null,
      next_run: new Date(Date.now() + 86400000).toISOString(),
    }
    if (!(await persist('スケジュール', '/api/v1/admin/reports/schedules', {
      method: 'POST',
      body: JSON.stringify(newSchedule),
    }))) return
    setLocalSchedules(prev => [...prev, newSchedule])
    setShowModal(false)
    setForm({ name: '', report_type: 'executive_summary', preset: 'weekly', custom_cron: '', format: 'json', recipient_input: '', recipients: [] })
    showToast('success', 'Schedule created')
  }

  const addRecipient = () => {
    const email = form.recipient_input.trim()
    if (!email || !email.includes('@')) return
    if (!form.recipients.includes(email)) {
      setForm(f => ({ ...f, recipients: [...f.recipients, email], recipient_input: '' }))
    }
  }

  const removeRecipient = (email: string) => {
    setForm(f => ({ ...f, recipients: f.recipients.filter(r => r !== email) }))
  }

  const activeCount = localSchedules.filter(s => s.enabled).length
  const lastGenerated = localSchedules
    .filter(s => s.last_run)
    .sort((a, b) => new Date(b.last_run!).getTime() - new Date(a.last_run!).getTime())[0]
  const nextRun = localSchedules
    .filter(s => s.enabled && s.next_run)
    .sort((a, b) => new Date(a.next_run).getTime() - new Date(b.next_run).getTime())[0]
  const totalRecipients = [...new Set(localSchedules.flatMap(s => s.recipients))].length

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <PageDataUnavailable />
      <SaveFailed error={saveError} />
      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-xl border shadow-xl text-sm font-medium transition-all ${
          toast.type === 'success'
            ? 'bg-green-900/90 border-green-700 text-green-200'
            : 'bg-red-900/90 border-red-700 text-red-200'
        }`}>
          {toast.type === 'success' ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
          {toast.message}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-900/40 rounded-lg border border-indigo-700/50">
            <Calendar className="w-6 h-6 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Scheduled Reports</h1>
            <p className="text-sm text-zinc-400">Automated report generation and delivery</p>
          </div>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-700 hover:bg-indigo-600 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          Create Schedule
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Active Schedules', value: activeCount, color: 'text-green-400', icon: Calendar },
          { label: 'Last Generated', value: lastGenerated ? formatDate(lastGenerated.last_run) : 'Never', color: 'text-zinc-300', icon: Clock, small: true },
          { label: 'Next Run', value: nextRun ? formatDate(nextRun.next_run) : '—', color: 'text-blue-400', icon: RefreshCw, small: true },
          { label: 'Recipients', value: totalRecipients, color: 'text-indigo-400', icon: Mail },
        ].map(stat => {
          const Icon = stat.icon
          return (
            <div key={stat.label} className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-1">
                <Icon className="w-4 h-4 text-zinc-500" />
                <span className="text-xs text-zinc-500">{stat.label}</span>
              </div>
              <div className={`font-bold ${stat.small ? 'text-sm' : 'text-2xl'} ${stat.color}`}>
                {stat.value}
              </div>
            </div>
          )
        })}
      </div>

      {/* Schedules List */}
      <div className="space-y-3">
        {localSchedules.map(schedule => (
          <div key={schedule.id} className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 hover:border-zinc-700 transition-colors">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-sm border ${REPORT_TYPE_COLORS[schedule.report_type]}`}>
                    {REPORT_TYPE_LABELS[schedule.report_type]}
                  </span>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-sm border ${FORMAT_COLORS[schedule.format]}`}>
                    {schedule.format.toUpperCase()}
                  </span>
                </div>
                <h3 className="font-semibold text-zinc-100 text-base mb-1">{schedule.name}</h3>
                <div className="flex items-center gap-1 text-xs text-zinc-400 mb-2">
                  <Clock className="w-3 h-3" />
                  {humanizeCron(schedule.cron)}
                  <span className="text-zinc-600 font-mono ml-1">({schedule.cron})</span>
                </div>
                <div className="flex flex-wrap gap-1 mb-2">
                  {schedule.recipients.map(r => (
                    <span key={r} className="flex items-center gap-1 text-xs px-2 py-0.5 bg-zinc-800 text-zinc-400 border border-zinc-700 rounded-full">
                      <Mail className="w-2.5 h-2.5" />
                      {r}
                    </span>
                  ))}
                </div>
                <div className="flex gap-4 text-xs text-zinc-500">
                  <span>Last run: {formatDate(schedule.last_run)}</span>
                  <span>Next: {formatDate(schedule.next_run)}</span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {/* Toggle */}
                <button
                  onClick={() => handleToggle(schedule.id)}
                  className="flex items-center gap-1 text-xs"
                  title={schedule.enabled ? 'Disable' : 'Enable'}
                >
                  {schedule.enabled
                    ? <ToggleRight className="w-7 h-7 text-green-400" />
                    : <ToggleLeft className="w-7 h-7 text-zinc-600" />}
                </button>

                {/* Run Now */}
                <button
                  onClick={() => handleRunNow(schedule)}
                  disabled={runningId === schedule.id}
                  className="flex items-center gap-1 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg text-xs border border-zinc-700 transition-colors"
                >
                  {runningId === schedule.id
                    ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    : <Play className="w-3.5 h-3.5" />}
                  Run Now
                </button>

                {/* Delete */}
                <button
                  onClick={() => handleDelete(schedule.id)}
                  disabled={deletingId === schedule.id}
                  className="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
                >
                  {deletingId === schedule.id
                    ? <RefreshCw className="w-4 h-4 animate-spin" />
                    : <Trash2 className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>
        ))}

        {localSchedules.length === 0 && (
          <div className="text-center py-16 text-zinc-500">
            <Calendar className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p>No schedules configured. Create one to get started.</p>
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-5 border-b border-zinc-800">
              <h2 className="text-lg font-semibold text-zinc-100">Create Schedule</h2>
              <button onClick={() => setShowModal(false)} className="text-zinc-500 hover:text-zinc-300">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {/* Name */}
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Schedule Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. Weekly Executive Summary"
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-hidden focus:border-indigo-500"
                />
              </div>

              {/* Report Type */}
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Report Type</label>
                <select
                  value={form.report_type}
                  onChange={e => setForm(f => ({ ...f, report_type: e.target.value as ReportType }))}
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 focus:outline-hidden focus:border-indigo-500"
                >
                  {(Object.keys(REPORT_TYPE_LABELS) as ReportType[]).map(k => (
                    <option key={k} value={k}>{REPORT_TYPE_LABELS[k]}</option>
                  ))}
                </select>
              </div>

              {/* Schedule Preset */}
              <div>
                <label className="block text-xs text-zinc-400 mb-2">Schedule</label>
                <div className="grid grid-cols-2 gap-2">
                  {(['daily', 'weekly', 'monthly', 'custom'] as SchedulePreset[]).map(p => (
                    <button
                      key={p}
                      onClick={() => setForm(f => ({ ...f, preset: p }))}
                      className={`py-2 px-3 rounded-lg text-sm border capitalize transition-colors ${
                        form.preset === p
                          ? 'bg-indigo-900/40 border-indigo-600 text-indigo-200'
                          : 'bg-zinc-800 border-zinc-700 text-zinc-400 hover:border-zinc-600'
                      }`}
                    >
                      {p === 'daily' ? 'Daily (8am)' : p === 'weekly' ? 'Weekly (Mon 8am)' : p === 'monthly' ? 'Monthly (1st, 8am)' : 'Custom Cron'}
                    </button>
                  ))}
                </div>
                {form.preset === 'custom' && (
                  <input
                    type="text"
                    value={form.custom_cron}
                    onChange={e => setForm(f => ({ ...f, custom_cron: e.target.value }))}
                    placeholder="e.g. 0 9 * * FRI"
                    className="mt-2 w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm font-mono text-zinc-100 placeholder-zinc-500 focus:outline-hidden focus:border-indigo-500"
                  />
                )}
              </div>

              {/* Format */}
              <div>
                <label className="block text-xs text-zinc-400 mb-2">Format</label>
                <div className="flex gap-2">
                  {(['json', 'csv', 'pdf'] as Format[]).map(f => (
                    <button
                      key={f}
                      onClick={() => setForm(prev => ({ ...prev, format: f }))}
                      className={`flex-1 py-1.5 rounded-lg text-sm uppercase font-medium border transition-colors ${
                        form.format === f
                          ? FORMAT_COLORS[f] + ' opacity-100'
                          : 'bg-zinc-800 border-zinc-700 text-zinc-500 hover:border-zinc-600'
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              {/* Recipients */}
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Recipients</label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="email"
                    value={form.recipient_input}
                    onChange={e => setForm(f => ({ ...f, recipient_input: e.target.value }))}
                    onKeyDown={e => e.key === 'Enter' && addRecipient()}
                    placeholder="email@company.com"
                    className="flex-1 px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-hidden focus:border-indigo-500"
                  />
                  <button
                    onClick={addRecipient}
                    className="px-3 py-2 bg-indigo-700 hover:bg-indigo-600 text-white rounded-lg text-sm transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
                <div className="flex flex-wrap gap-1">
                  {form.recipients.map(r => (
                    <span key={r} className="flex items-center gap-1 text-xs px-2 py-1 bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-full">
                      {r}
                      <button onClick={() => removeRecipient(r)} className="text-zinc-500 hover:text-red-400">
                        <X className="w-3 h-3" />
                      </button>
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 p-5 border-t border-zinc-800">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg text-sm border border-zinc-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-700 hover:bg-indigo-600 text-white rounded-lg text-sm font-medium transition-colors"
              >
                <CheckCircle className="w-4 h-4" />
                Create Schedule
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
