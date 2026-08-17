'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Search, Database, Clock, FileSearch, User, ChevronRight,
  Plus, X, CheckSquare, Square, AlertTriangle, Shield,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type JobStatus = 'pending' | 'running' | 'completed' | 'failed'
type JobPriority = 'critical' | 'high' | 'medium' | 'low'
type EvidenceModule = 'memory_dump' | 'disk_image' | 'registry' | 'event_logs' | 'network_pcap' | 'prefetch' | 'shellbag'
type FindingSeverity = 'critical' | 'high' | 'medium' | 'low'

interface CustodyEvent {
  time: string
  actor: string
  action: string
}

interface Finding {
  id: string
  description: string
  severity: FindingSeverity
}

interface ForensicsJob {
  id: string
  name: string
  trigger: string
  priority: JobPriority
  status: JobStatus
  evidence_count: number
  assignee: string
  started_at: string
  custody_chain: CustodyEvent[]
  evidence_modules: EvidenceModule[]
  collected_modules: EvidenceModule[]
  findings: Finding[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const statusConfig: Record<JobStatus, { label: string; cls: string }> = {
  pending: { label: '待機中', cls: 'bg-gray-700 text-gray-300' },
  running: { label: '実行中', cls: 'bg-blue-900 text-blue-300 animate-pulse' },
  completed: { label: '完了', cls: 'bg-green-900 text-green-300' },
  failed: { label: '失敗', cls: 'bg-red-900 text-red-300' },
}

const priorityConfig: Record<JobPriority, { label: string; cls: string }> = {
  critical: { label: '重大', cls: 'bg-red-900 text-red-300' },
  high: { label: '高', cls: 'bg-orange-900 text-orange-300' },
  medium: { label: '中', cls: 'bg-yellow-900 text-yellow-300' },
  low: { label: '低', cls: 'bg-gray-700 text-gray-300' },
}

const severityConfig: Record<FindingSeverity, { label: string; cls: string }> = {
  critical: { label: '重大', cls: 'text-red-400' },
  high: { label: '高', cls: 'text-orange-400' },
  medium: { label: '中', cls: 'text-yellow-400' },
  low: { label: '低', cls: 'text-gray-400' },
}

const MODULE_LABELS: Record<EvidenceModule, string> = {
  memory_dump: 'メモリダンプ',
  disk_image: 'ディスクイメージ',
  registry: 'レジストリ',
  event_logs: 'イベントログ',
  network_pcap: 'ネットワークPCAP',
  prefetch: 'プリフェッチ',
  shellbag: 'シェルバッグ',
}

// ─── New Job Form ─────────────────────────────────────────────────────────────

function NewJobForm({ onClose }: { onClose: () => void }) {
  return (
    <div className="mt-4 p-4 bg-falcon-surface border border-falcon-border rounded-lg">
      <div className="flex items-center justify-between mb-3">
        <span className="text-white font-medium text-sm">新規フォレンジックジョブ</span>
        <button onClick={onClose}><X size={14} className="text-falcon-muted" /></button>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-falcon-muted text-xs mb-1">ジョブ名</label>
          <input className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-white text-sm focus:outline-hidden focus:border-falcon-red" placeholder="調査名を入力" />
        </div>
        <div>
          <label className="block text-falcon-muted text-xs mb-1">優先度</label>
          <select className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-white text-sm focus:outline-hidden">
            <option value="critical">重大</option>
            <option value="high">高</option>
            <option value="medium">中</option>
            <option value="low">低</option>
          </select>
        </div>
        <div>
          <label className="block text-falcon-muted text-xs mb-1">担当者</label>
          <input className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-white text-sm focus:outline-hidden focus:border-falcon-red" placeholder="担当者名" />
        </div>
        <div>
          <label className="block text-falcon-muted text-xs mb-1">トリガー</label>
          <select className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-white text-sm focus:outline-hidden">
            <option>手動実行</option>
            <option>アラート自動</option>
            <option>スケジュール</option>
          </select>
        </div>
      </div>
      <div className="flex justify-end gap-2 mt-3">
        <button onClick={onClose} className="px-3 py-1.5 border border-falcon-border text-falcon-muted rounded-sm text-sm hover:text-white">キャンセル</button>
        <button className="px-3 py-1.5 bg-falcon-red text-white rounded-sm text-sm hover:bg-red-600">作成</button>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ForensicsAutomationPage() {
  const [selectedJob, setSelectedJob] = useState<ForensicsJob | null>(null)
  const [showNewForm, setShowNewForm] = useState(false)

  const { data: jobs = [] } = useQuery<ForensicsJob[]>({
    queryKey: ['forensics-jobs'],
    queryFn: () =>
      apiFetchList<ForensicsJob>('/api/v1/admin/forensics-automation/jobs').catch(() => []),
  })

  const stats = [
    { label: '総ジョブ数', value: 142, icon: <Database size={16} className="text-falcon-red" /> },
    { label: '実行中', value: 3, icon: <Clock size={16} className="text-blue-400" /> },
    { label: '本日完了', value: 8, icon: <FileSearch size={16} className="text-green-400" /> },
    { label: '証拠アイテム', value: 1847, icon: <Shield size={16} className="text-yellow-400" /> },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">フォレンジック自動化</h1>
          <p className="text-falcon-muted text-sm mt-1">Forensics Automation Dashboard</p>
        </div>
        <button
          onClick={() => setShowNewForm(v => !v)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm hover:bg-red-600 transition-colors"
        >
          <Plus size={14} />
          新規ジョブ
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {stats.map(s => (
          <div key={s.label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-3">
            <div className="p-2 bg-[#070d19] rounded-lg">{s.icon}</div>
            <div>
              <div className="text-2xl font-bold text-white">{(s.value ?? 0).toLocaleString()}</div>
              <div className="text-falcon-muted text-xs">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {showNewForm && <NewJobForm onClose={() => setShowNewForm(false)} />}

      {/* Two-panel layout */}
      <div className="flex gap-4 mt-4">
        {/* Left Panel — Job List */}
        <div className="w-[60%] bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
          <div className="p-4 border-b border-falcon-border">
            <span className="text-white font-medium">ジョブ一覧</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ジョブ名', 'トリガー', '優先度', 'ステータス', '証拠数', '担当者', '開始時刻'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {jobs.map(job => {
                  const st = statusConfig[job.status]
                  const pr = priorityConfig[job.priority]
                  const isSelected = selectedJob?.id === job.id
                  return (
                    <tr
                      key={job.id}
                      onClick={() => setSelectedJob(job)}
                      className={`border-b border-falcon-border cursor-pointer hover:bg-[#070d19] transition-colors ${isSelected ? 'bg-[#0a1628]' : ''}`}
                    >
                      <td className="px-4 py-3 text-white font-medium flex items-center gap-1">
                        {isSelected && <ChevronRight size={12} className="text-falcon-red" />}
                        <span className="truncate max-w-[140px]">{job.name}</span>
                      </td>
                      <td className="px-4 py-3 text-falcon-muted">{job.trigger}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${pr.cls}`}>{pr.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${st.cls}`}>{st.label}</span>
                      </td>
                      <td className="px-4 py-3 text-white">{job.evidence_count}</td>
                      <td className="px-4 py-3 text-falcon-muted">{job.assignee}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">{job.started_at === '—' ? '—' : new Date(job.started_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Panel — Job Detail */}
        <div className="w-[40%] bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
          {selectedJob ? (
            <>
              <div className="p-4 border-b border-falcon-border">
                <div className="text-white font-medium truncate">{selectedJob.name}</div>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${statusConfig[selectedJob.status].cls}`}>
                    {statusConfig[selectedJob.status].label}
                  </span>
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${priorityConfig[selectedJob.priority].cls}`}>
                    {priorityConfig[selectedJob.priority].label}
                  </span>
                </div>
              </div>

              <div className="p-4 space-y-5 overflow-y-auto max-h-[calc(100vh-320px)]">
                {/* Chain of Custody */}
                <div>
                  <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider mb-3">証拠保全チェーン</div>
                  <div className="relative pl-4">
                    <div className="absolute left-[7px] top-2 bottom-2 w-px bg-falcon-border" />
                    {selectedJob.custody_chain.map((ev, i) => (
                      <div key={i} className="relative flex items-start gap-3 mb-3">
                        <div className="absolute -left-4 top-1.5 w-2 h-2 rounded-full bg-falcon-red border border-[#070d19]" />
                        <div className="ml-2">
                          <div className="text-xs text-falcon-muted">{ev.time} — <span className="text-white">{ev.actor}</span></div>
                          <div className="text-sm text-falcon-muted mt-0.5">{ev.action}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Evidence Modules */}
                <div>
                  <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider mb-3">証拠モジュール</div>
                  <div className="space-y-2">
                    {selectedJob.evidence_modules.map(mod => {
                      const collected = selectedJob.collected_modules.includes(mod)
                      return (
                        <div key={mod} className="flex items-center gap-2">
                          {collected
                            ? <CheckSquare size={14} className="text-green-400 shrink-0" />
                            : <Square size={14} className="text-falcon-muted shrink-0" />}
                          <span className={`text-sm ${collected ? 'text-white' : 'text-falcon-muted'}`}>
                            {MODULE_LABELS[mod]}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Findings */}
                {selectedJob.findings.length > 0 && (
                  <div>
                    <div className="text-falcon-muted text-xs font-medium uppercase tracking-wider mb-3">検出結果</div>
                    <div className="space-y-2">
                      {selectedJob.findings.map(f => {
                        const sv = severityConfig[f.severity]
                        return (
                          <div key={f.id} className="flex items-start gap-2 p-2 bg-[#070d19] rounded-lg border border-falcon-border">
                            <AlertTriangle size={13} className={`${sv.cls} mt-0.5 shrink-0`} />
                            <div>
                              <span className={`text-xs font-medium ${sv.cls}`}>[{sv.label}]</span>
                              <span className="text-sm text-falcon-muted ml-1">{f.description}</span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-40 text-falcon-muted">ジョブを選択してください</div>
          )}
        </div>
      </div>
    </div>
  )
}
