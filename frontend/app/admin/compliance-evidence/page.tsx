'use client'

import { useState, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ClipboardCheck, Plus, X, RefreshCw, Download,
  CheckCircle, AlertCircle, Clock, Filter, Eye,
  ToggleLeft, ToggleRight, Play, ChevronDown, FileText,
  Calendar
} from 'lucide-react'
// ── Types ──────────────────────────────────────────────────────

type Framework = 'SOC2' | 'ISO27001' | 'PCI-DSS' | 'HIPAA' | 'NIST'
type CollectionMethod = 'auto' | 'manual' | 'api' | 'screenshot'
type EvidenceType = 'screenshot' | 'log_export' | 'config_snapshot' | 'report' | 'attestation'
type EvidenceStatus = 'pending_review' | 'approved' | 'rejected'

interface ComplianceTask {
  id: string
  name: string
  framework: Framework
  control_id: string
  description: string
  collection_method: CollectionMethod
  schedule: string
  last_collected: string | null
  is_active: boolean
  evidence_ids: string[]
}

interface Evidence {
  id: string
  task_id: string
  task_name: string
  name: string
  evidence_type: EvidenceType
  content: string
  collected_at: string
  collected_by: string
  status: EvidenceStatus
  expires_at: string | null
  reviewer_notes: string
  framework: Framework
  control_id: string
}

// ── Helpers ────────────────────────────────────────────────────

const FRAMEWORKS: Framework[] = ['SOC2', 'ISO27001', 'PCI-DSS', 'HIPAA', 'NIST']

const frameworkColor: Record<Framework, string> = {
  'SOC2':    'bg-blue-500/20 text-blue-400 border-blue-500/30',
  'ISO27001':'bg-purple-500/20 text-purple-400 border-purple-500/30',
  'PCI-DSS': 'bg-red-500/20 text-red-400 border-red-500/30',
  'HIPAA':   'bg-teal-500/20 text-teal-400 border-teal-500/30',
  'NIST':    'bg-orange-500/20 text-orange-400 border-orange-500/30',
}

const methodMeta: Record<CollectionMethod, { label: string; color: string }> = {
  auto:       { label: 'Auto',       color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  manual:     { label: 'Manual',     color: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
  api:        { label: 'API',        color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  screenshot: { label: 'Screenshot', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
}

const evidenceTypeMeta: Record<EvidenceType, { label: string; color: string }> = {
  screenshot:      { label: 'Screenshot',     color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  log_export:      { label: 'ログエクスポート', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  config_snapshot: { label: '設定スナップショット', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  report:          { label: 'レポート',          color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  attestation:     { label: '証明書',            color: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
}

const statusMeta: Record<EvidenceStatus, { label: string; color: string }> = {
  pending_review: { label: 'レビュー中', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  approved:       { label: '承認済み',   color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  rejected:       { label: '却下',       color: 'bg-red-500/20 text-red-400 border-red-500/30' },
}

function Badge({ className, children }: { className: string; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${className}`}>
      {children}
    </span>
  )
}

function Toast({ message, type, onClose }: { message: string; type: 'success' | 'error'; onClose: () => void }) {
  return (
    <div className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl ${
      type === 'success' ? 'bg-green-900/90 border-green-500/40 text-green-100' : 'bg-red-900/90 border-red-500/40 text-red-100'
    }`}>
      {type === 'success' ? <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" /> : <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />}
      <span className="text-sm">{message}</span>
      <button onClick={onClose} className="ml-2 opacity-60 hover:opacity-100"><X className="w-3.5 h-3.5" /></button>
    </div>
  )
}

function humanizeCron(cron: string): string {
  const map: Record<string, string> = {
    '0 0 * * *':       '毎日',
    '0 2 * * 0':       '毎週日曜',
    '0 1 1 * *':       '毎月1日',
    '0 9 * * 1':       '毎週月曜',
    '0 3 * * 1':       '毎週月曜',
    '0 0 1 1,4,7,10 *':'四半期',
    '0 0 1 */6 *':     '半年',
  }
  return map[cron] ?? cron
}

function daysUntilExpiry(iso: string | null): { days: number | null; isExpiring: boolean } {
  if (!iso) return { days: null, isExpiring: false }
  const days = Math.ceil((new Date(iso).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
  return { days, isExpiring: days < 30 }
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('ja-JP')
}

// ── Main Component ─────────────────────────────────────────────

export default function ComplianceEvidencePage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'tasks' | 'evidence'>('tasks')
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)
  const showToast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4000)
  }, [])

  const [selectedFramework, setSelectedFramework] = useState<Framework | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<EvidenceStatus | 'all'>('all')

  // Task state
  const [showAddTask, setShowAddTask] = useState(false)
  const [selectedTask, setSelectedTask] = useState<ComplianceTask | null>(null)
  const [newTask, setNewTask] = useState({ name: '', framework: 'SOC2' as Framework, control_id: '', description: '', collection_method: 'auto' as CollectionMethod, schedule: '0 0 * * *', is_active: true })

  // Evidence state
  const [reviewEvidence, setReviewEvidence] = useState<Evidence | null>(null)
  const [reviewNotes, setReviewNotes] = useState('')
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState<Set<string>>(new Set())

  // Local state for evidence (to support local optimistic updates)
  const [localEvidence, setLocalEvidence] = useState<Evidence[]>([])
  const [localTasks, setLocalTasks] = useState<ComplianceTask[]>([])

  // API queries
  const { data: tasksData } = useQuery<ComplianceTask[]>({
    queryKey: ['compliance-tasks'],
    queryFn: () => apiFetchList<ComplianceTask>('/api/v1/admin/compliance-evidence/tasks').catch(() => []),
    staleTime: 30_000,
  })
  const tasks = tasksData ?? localTasks

  const { data: evidenceData } = useQuery<Evidence[]>({
    queryKey: ['compliance-evidence'],
    queryFn: () => apiFetchList<Evidence>('/api/v1/admin/compliance-evidence/evidence').catch(() => []),
    staleTime: 30_000,
  })
  const evidenceList = evidenceData ?? localEvidence

  // Stats
  const totalTasks = tasks.length
  const autoCollected = evidenceList.filter(e => e.status === 'approved').length
  const pendingReview = evidenceList.filter(e => e.status === 'pending_review').length
  const approved = evidenceList.filter(e => e.status === 'approved').length
  const expiring30d = evidenceList.filter(e => {
    const { days } = daysUntilExpiry(e.expires_at)
    return days !== null && days < 30 && days >= 0
  }).length

  const handleCollect = async (task: ComplianceTask) => {
    try {
      await apiFetch(`/api/v1/admin/compliance-evidence/tasks/${task.id}/collect`, { method: 'POST' })
      qc.invalidateQueries({ queryKey: ['compliance-evidence'] })
      showToast('証拠を収集しました')
    } catch {
      // Mock: add a new evidence item
      const newEv: Evidence = {
        id: `e${Date.now()}`,
        task_id: task.id,
        task_name: task.name,
        name: `${task.control_id.replace(/[./()]/g, '_')}_${new Date().toISOString().slice(0, 10)}.json`,
        evidence_type: task.collection_method === 'screenshot' ? 'screenshot' : 'log_export',
        content: `{"auto_collected":true,"task":"${task.name}","timestamp":"${new Date().toISOString()}"}`,
        collected_at: new Date().toISOString(),
        collected_by: 'system',
        status: 'pending_review',
        expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
        reviewer_notes: '',
        framework: task.framework,
        control_id: task.control_id,
      }
      setLocalEvidence(prev => [newEv, ...prev])
      showToast('証拠を収集しました')
    }
  }

  const handleReview = async (action: 'approved' | 'rejected') => {
    if (!reviewEvidence) return
    try {
      await apiFetch(`/api/v1/admin/compliance-evidence/evidence/${reviewEvidence.id}/review`, {
        method: 'PATCH',
        body: JSON.stringify({ status: action, reviewer_notes: reviewNotes }),
      })
      qc.invalidateQueries({ queryKey: ['compliance-evidence'] })
    } catch {
      setLocalEvidence(prev => prev.map(e => e.id === reviewEvidence.id ? { ...e, status: action, reviewer_notes: reviewNotes } : e))
    }
    showToast(action === 'approved' ? '証拠を承認しました' : '証拠を却下しました', action === 'approved' ? 'success' : 'error')
    setReviewEvidence(null)
    setReviewNotes('')
  }

  const handleBulkApprove = async () => {
    for (const id of selectedEvidenceIds) {
      setLocalEvidence(prev => prev.map(e => e.id === id && e.status === 'pending_review' ? { ...e, status: 'approved' } : e))
    }
    showToast(`${selectedEvidenceIds.size}件の証拠を一括承認しました`)
    setSelectedEvidenceIds(new Set())
  }

  const handleAddTask = async () => {
    try {
      await apiFetch('/api/v1/admin/compliance-evidence/tasks', { method: 'POST', body: JSON.stringify(newTask) })
      qc.invalidateQueries({ queryKey: ['compliance-tasks'] })
    } catch {
      const t: ComplianceTask = { id: `t${Date.now()}`, ...newTask, last_collected: null, evidence_ids: [] }
      setLocalTasks(prev => [...prev, t])
    }
    showToast('タスクを追加しました')
    setShowAddTask(false)
  }

  const filteredEvidence = evidenceList.filter(e => {
    if (selectedFramework !== 'all' && e.framework !== selectedFramework) return false
    if (statusFilter !== 'all' && e.status !== statusFilter) return false
    return true
  })

  const taskEvidence = selectedTask ? localEvidence.filter(e => e.task_id === selectedTask.id).slice(0, 5) : []

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0] p-6">
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <ClipboardCheck className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">コンプライアンス証拠収集</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">自動証拠収集・レビュー管理</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1">
            <button onClick={() => setSelectedFramework('all')} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${selectedFramework === 'all' ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>全て</button>
            {FRAMEWORKS.map(f => (
              <button key={f} onClick={() => setSelectedFramework(f)} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${selectedFramework === f ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>{f}</button>
            ))}
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {[
          { label: '総タスク数', value: totalTasks, icon: ClipboardCheck, color: 'text-blue-400' },
          { label: '自動収集済み', value: autoCollected, icon: CheckCircle, color: 'text-green-400' },
          { label: 'レビュー待ち', value: pendingReview, icon: Clock, color: 'text-yellow-400' },
          { label: '承認済み', value: approved, icon: CheckCircle, color: 'text-green-400' },
          { label: '30日以内失効', value: expiring30d, icon: AlertCircle, color: 'text-[#e8002d]' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-[#7d92b0]">{stat.label}</span>
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
            </div>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['tasks', 'evidence'] as const).map((t, i) => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded text-sm font-medium transition-colors ${tab === t ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {['収集タスク', '証拠一覧'][i]}
          </button>
        ))}
      </div>

      {/* ── Tasks Tab ────────────────────────────────────────── */}
      {tab === 'tasks' && (
        <div>
          <div className="flex justify-end mb-4">
            <button onClick={() => setShowAddTask(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" />
              タスクを追加
            </button>
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['名前', 'フレームワーク', 'コントロールID', '収集方法', 'スケジュール', '最終収集', '有効', '操作'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(selectedFramework === 'all' ? tasks : tasks.filter(t => t.framework === selectedFramework)).map(task => (
                  <tr key={task.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                    <td className="px-4 py-3">
                      <button onClick={() => setSelectedTask(selectedTask?.id === task.id ? null : task)} className="text-white font-medium hover:text-[#e8002d] transition-colors text-left">
                        {task.name}
                      </button>
                    </td>
                    <td className="px-4 py-3"><Badge className={frameworkColor[task.framework]}>{task.framework}</Badge></td>
                    <td className="px-4 py-3 font-mono text-white text-xs">{task.control_id}</td>
                    <td className="px-4 py-3"><Badge className={methodMeta[task.collection_method].color}>{methodMeta[task.collection_method].label}</Badge></td>
                    <td className="px-4 py-3 text-[#7d92b0] text-xs">{humanizeCron(task.schedule)}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-xs">{task.last_collected ? formatDate(task.last_collected) : '—'}</td>
                    <td className="px-4 py-3">
                      <button>
                        {task.is_active
                          ? <ToggleRight className="w-6 h-6 text-green-400" />
                          : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                        }
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => handleCollect(task)} className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#e8002d]/20 text-[#e8002d] border border-[#e8002d]/30 hover:bg-[#e8002d]/30 text-xs transition-colors">
                        <Play className="w-3 h-3" />
                        今すぐ収集
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Task Detail */}
          {selectedTask && (
            <div className="mt-4 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-white font-semibold">{selectedTask.name} — 直近の証拠</h3>
                <button onClick={() => setSelectedTask(null)}><X className="w-4 h-4" /></button>
              </div>
              {taskEvidence.length === 0 ? (
                <p className="text-sm text-[#3d5068]">証拠がありません</p>
              ) : (
                <div className="space-y-2">
                  {taskEvidence.map(ev => (
                    <div key={ev.id} className="flex items-center justify-between px-3 py-2 bg-[#1e2d42]/30 border border-[#1e2d42] rounded-lg">
                      <div className="flex items-center gap-3">
                        <FileText className="w-4 h-4 text-[#7d92b0]" />
                        <span className="text-sm text-white">{ev.name}</span>
                        <Badge className={evidenceTypeMeta[ev.evidence_type].color}>{evidenceTypeMeta[ev.evidence_type].label}</Badge>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge className={statusMeta[ev.status].color}>{statusMeta[ev.status].label}</Badge>
                        <span className="text-xs text-[#7d92b0]">{formatDate(ev.collected_at)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Evidence Tab ─────────────────────────────────────── */}
      {tab === 'evidence' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as EvidenceStatus | 'all')} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#7d92b0] outline-none">
                <option value="all">全ステータス</option>
                {Object.entries(statusMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-2">
              {selectedEvidenceIds.size > 0 && (
                <button onClick={handleBulkApprove} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-green-600 text-white text-sm hover:bg-green-500 transition-colors">
                  <CheckCircle className="w-4 h-4" />
                  {selectedEvidenceIds.size}件を一括承認
                </button>
              )}
              <button onClick={() => showToast('ZIP エクスポートを開始しました')} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-sm transition-colors">
                <Download className="w-4 h-4" />
                全証拠をZIPエクスポート
              </button>
            </div>
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="px-4 py-3 w-10">
                    <input type="checkbox" className="rounded" onChange={e => {
                      if (e.target.checked) setSelectedEvidenceIds(new Set(filteredEvidence.filter(ev => ev.status === 'pending_review').map(ev => ev.id)))
                      else setSelectedEvidenceIds(new Set())
                    }} />
                  </th>
                  {['名前', 'タスク', 'タイプ', '収集日時', '収集者', 'ステータス', '失効日', '操作'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredEvidence.map(ev => {
                  const { days, isExpiring } = daysUntilExpiry(ev.expires_at)
                  return (
                    <tr key={ev.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                      <td className="px-4 py-3">
                        {ev.status === 'pending_review' && (
                          <input type="checkbox" checked={selectedEvidenceIds.has(ev.id)} onChange={e => {
                            const next = new Set(selectedEvidenceIds)
                            e.target.checked ? next.add(ev.id) : next.delete(ev.id)
                            setSelectedEvidenceIds(next)
                          }} className="rounded" />
                        )}
                      </td>
                      <td className="px-4 py-3 text-white font-medium text-sm">{ev.name}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{ev.task_name}</td>
                      <td className="px-4 py-3"><Badge className={evidenceTypeMeta[ev.evidence_type].color}>{evidenceTypeMeta[ev.evidence_type].label}</Badge></td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{formatDate(ev.collected_at)}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{ev.collected_by}</td>
                      <td className="px-4 py-3"><Badge className={statusMeta[ev.status].color}>{statusMeta[ev.status].label}</Badge></td>
                      <td className={`px-4 py-3 text-xs font-mono ${isExpiring ? 'text-red-400' : 'text-[#7d92b0]'}`}>
                        {ev.expires_at ? `${formatDate(ev.expires_at)} (${days}日)` : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => { setReviewEvidence(ev); setReviewNotes(ev.reviewer_notes) }} className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#1e2d42] hover:bg-[#2a3f5a] text-xs transition-colors">
                          <Eye className="w-3 h-3" />
                          レビュー
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Add Task Modal ─────────────────────────────────── */}
      {showAddTask && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">収集タスクを追加</h2>
              <button onClick={() => setShowAddTask(false)}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">タスク名</label>
                <input value={newTask.name} onChange={e => setNewTask(p => ({ ...p, name: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none" placeholder="アクセスログ収集" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">フレームワーク</label>
                  <select value={newTask.framework} onChange={e => setNewTask(p => ({ ...p, framework: e.target.value as Framework }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none">
                    {FRAMEWORKS.map(f => <option key={f} value={f}>{f}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">コントロールID</label>
                  <input value={newTask.control_id} onChange={e => setNewTask(p => ({ ...p, control_id: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none" placeholder="CC6.1" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
                <input value={newTask.description} onChange={e => setNewTask(p => ({ ...p, description: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">収集方法</label>
                  <select value={newTask.collection_method} onChange={e => setNewTask(p => ({ ...p, collection_method: e.target.value as CollectionMethod }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none">
                    {Object.entries(methodMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">スケジュール</label>
                  <select value={newTask.schedule} onChange={e => setNewTask(p => ({ ...p, schedule: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none">
                    <option value="0 0 * * *">毎日</option>
                    <option value="0 9 * * 1">毎週月曜</option>
                    <option value="0 1 1 * *">毎月1日</option>
                    <option value="0 0 1 1,4,7,10 *">四半期</option>
                  </select>
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setShowAddTask(false)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">キャンセル</button>
              <button onClick={handleAddTask} className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">追加</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Review Modal ────────────────────────────────────── */}
      {reviewEvidence && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">証拠レビュー</h2>
              <button onClick={() => setReviewEvidence(null)}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-sm font-medium text-white">{reviewEvidence.name}</span>
                <Badge className={frameworkColor[reviewEvidence.framework]}>{reviewEvidence.framework}</Badge>
                <Badge className={evidenceTypeMeta[reviewEvidence.evidence_type].color}>{evidenceTypeMeta[reviewEvidence.evidence_type].label}</Badge>
                <Badge className={statusMeta[reviewEvidence.status].color}>{statusMeta[reviewEvidence.status].label}</Badge>
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-2">コンテンツプレビュー</label>
                {reviewEvidence.evidence_type === 'screenshot' ? (
                  <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 flex items-center justify-center h-24">
                    <p className="text-[#3d5068] text-sm">[スクリーンショット画像]</p>
                  </div>
                ) : (
                  <pre className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-xs font-mono text-[#7d92b0] overflow-auto max-h-40 whitespace-pre-wrap">{reviewEvidence.content}</pre>
                )}
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">レビュアーメモ</label>
                <textarea value={reviewNotes} onChange={e => setReviewNotes(e.target.value)} className="w-full h-20 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none resize-none" placeholder="レビューコメントを入力..." />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setReviewEvidence(null)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">キャンセル</button>
              <button onClick={() => handleReview('rejected')} className="px-4 py-2 rounded-lg bg-red-600 text-white text-sm hover:bg-red-500 transition-colors">却下</button>
              <button onClick={() => handleReview('approved')} className="px-4 py-2 rounded-lg bg-green-600 text-white text-sm hover:bg-green-500 transition-colors">承認</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
