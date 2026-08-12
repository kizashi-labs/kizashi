'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Printer, Plus, Pencil, Trash2, X, Play, ToggleLeft, ToggleRight,
  ChevronDown, Download, Filter, Calendar, RefreshCw, CheckCircle,
  AlertCircle, Clock, FileText, BarChart2,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type ReportType = 'executive' | 'operational' | 'compliance' | 'threat_intel' | 'custom'
type OutputFormat = 'PDF' | 'HTML' | 'JSON' | 'CSV'
type ReportStatus = 'pending' | 'generating' | 'completed' | 'failed'

interface Schedule {
  id: string
  name: string
  report_type: ReportType
  description: string
  schedule: string
  schedule_label: string
  recipients: string[]
  output_format: OutputFormat
  next_run: string
  is_active: boolean
  parameters: Record<string, string>
}

interface GeneratedReport {
  id: string
  name: string
  report_type: ReportType
  period_start: string
  period_end: string
  status: ReportStatus
  output_format: OutputFormat
  file_size_kb: number
  generated_at: string
  schedule_id?: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TYPE_BADGE: Record<ReportType, string> = {
  executive: 'bg-purple-500/10 text-purple-400 border border-purple-500/30',
  operational: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  compliance: 'bg-green-500/10 text-green-400 border border-green-500/30',
  threat_intel: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  custom: 'bg-gray-500/10 text-gray-400 border border-gray-500/30',
}
const TYPE_LABEL: Record<ReportType, string> = {
  executive: 'エグゼクティブ', operational: 'オペレーション', compliance: 'コンプライアンス', threat_intel: '脅威インテリジェンス', custom: 'カスタム',
}
const FORMAT_BADGE: Record<OutputFormat, string> = {
  PDF: 'bg-red-500/10 text-red-400 border border-red-500/30',
  HTML: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  JSON: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
  CSV: 'bg-teal-500/10 text-teal-400 border border-teal-500/30',
}
const STATUS_BADGE: Record<ReportStatus, string> = {
  pending: 'bg-gray-500/10 text-gray-400 border border-gray-500/30',
  generating: 'bg-blue-500/10 text-blue-400 border border-blue-500/30 animate-pulse',
  completed: 'bg-green-500/10 text-green-400 border border-green-500/30',
  failed: 'bg-red-500/10 text-red-400 border border-red-500/30',
}
const STATUS_LABEL: Record<ReportStatus, string> = {
  pending: '待機中', generating: '生成中', completed: '完了', failed: '失敗',
}

function formatBytes(kb: number): string {
  if (kb === 0) return '—'
  if (kb < 1024) return `${kb} KB`
  return `${(kb / 1024).toFixed(1)} MB`
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ─── Schedule Modal ───────────────────────────────────────────────────────────

interface ScheduleModalProps {
  schedule?: Schedule
  onClose: () => void
  onSave: (data: Partial<Schedule>) => void
}

function ScheduleModal({ schedule, onClose, onSave }: ScheduleModalProps) {
  const [form, setForm] = useState({
    name: schedule?.name ?? '',
    report_type: schedule?.report_type ?? 'executive' as ReportType,
    description: schedule?.description ?? '',
    schedule_preset: 'daily',
    schedule_time: '09:00',
    custom_cron: schedule?.schedule ?? '',
    use_custom: false,
    recipients_input: '',
    recipients: schedule?.recipients ?? [] as string[],
    output_format: schedule?.output_format ?? 'PDF' as OutputFormat,
    is_active: schedule?.is_active ?? true,
    param_key: '',
    param_value: '',
    parameters: schedule?.parameters ?? {} as Record<string, string>,
  })

  const addRecipient = () => {
    if (form.recipients_input && !form.recipients.includes(form.recipients_input)) {
      setForm(f => ({ ...f, recipients: [...f.recipients, f.recipients_input], recipients_input: '' }))
    }
  }
  const removeRecipient = (email: string) => setForm(f => ({ ...f, recipients: f.recipients.filter(r => r !== email) }))
  const addParam = () => {
    if (form.param_key) {
      setForm(f => ({ ...f, parameters: { ...f.parameters, [f.param_key]: f.param_value }, param_key: '', param_value: '' }))
    }
  }
  const removeParam = (key: string) => setForm(f => { const p = { ...f.parameters }; delete p[key]; return { ...f, parameters: p } })

  const scheduleValue = form.use_custom ? form.custom_cron :
    form.schedule_preset === 'daily' ? `0 ${form.schedule_time.split(':')[1]} ${form.schedule_time.split(':')[0]} * * *` :
    form.schedule_preset === 'weekly' ? `0 ${form.schedule_time.split(':')[1]} ${form.schedule_time.split(':')[0]} * * 1` :
    `0 ${form.schedule_time.split(':')[1]} ${form.schedule_time.split(':')[0]} 1 * *`

  const scheduleLabel = form.use_custom ? form.custom_cron :
    form.schedule_preset === 'daily' ? `毎日 ${form.schedule_time}` :
    form.schedule_preset === 'weekly' ? `毎週月曜 ${form.schedule_time}` :
    `毎月1日 ${form.schedule_time}`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-lg">{schedule ? 'スケジュール編集' : '新規スケジュール作成'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1 rounded hover:bg-[#1e2d42] transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">レポート名 *</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" placeholder="レポート名を入力..." />
          </div>
          {/* Type & Format */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">レポートタイプ</label>
              <select value={form.report_type} onChange={e => setForm(f => ({ ...f, report_type: e.target.value as ReportType }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(Object.keys(TYPE_LABEL) as ReportType[]).map(t => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">出力形式</label>
              <select value={form.output_format} onChange={e => setForm(f => ({ ...f, output_format: e.target.value as OutputFormat }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(['PDF', 'HTML', 'JSON', 'CSV'] as OutputFormat[]).map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
          </div>
          {/* Description */}
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">説明</label>
            <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={2} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 resize-none" />
          </div>
          {/* Schedule */}
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">スケジュール</label>
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-sm text-[#7d92b0] cursor-pointer">
                  <input type="radio" checked={!form.use_custom} onChange={() => setForm(f => ({ ...f, use_custom: false }))} className="accent-[#e8002d]" />
                  プリセット
                </label>
                <label className="flex items-center gap-2 text-sm text-[#7d92b0] cursor-pointer">
                  <input type="radio" checked={form.use_custom} onChange={() => setForm(f => ({ ...f, use_custom: true }))} className="accent-[#e8002d]" />
                  カスタムCron
                </label>
              </div>
              {!form.use_custom ? (
                <div className="flex gap-3">
                  <select value={form.schedule_preset} onChange={e => setForm(f => ({ ...f, schedule_preset: e.target.value }))} className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                    <option value="daily">毎日</option>
                    <option value="weekly">毎週</option>
                    <option value="monthly">毎月</option>
                  </select>
                  <input type="time" value={form.schedule_time} onChange={e => setForm(f => ({ ...f, schedule_time: e.target.value }))} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
                </div>
              ) : (
                <input value={form.custom_cron} onChange={e => setForm(f => ({ ...f, custom_cron: e.target.value }))} placeholder="0 9 * * 1" className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 font-mono" />
              )}
              <p className="text-xs text-[#7d92b0]">スケジュール: <span className="text-white">{scheduleLabel}</span></p>
            </div>
          </div>
          {/* Recipients */}
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">送信先</label>
            <div className="flex gap-2 mb-2">
              <input value={form.recipients_input} onChange={e => setForm(f => ({ ...f, recipients_input: e.target.value }))} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addRecipient() } }} placeholder="email@example.com" className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
              <button onClick={addRecipient} className="px-3 py-2 bg-[#1e2d42] text-white rounded-lg text-sm hover:bg-[#243347] transition-colors">追加</button>
            </div>
            <div className="flex flex-wrap gap-2">
              {form.recipients.map(r => (
                <span key={r} className="flex items-center gap-1 px-2 py-1 bg-[#1e2d42] rounded text-xs text-white">
                  {r}
                  <button onClick={() => removeRecipient(r)} className="text-[#7d92b0] hover:text-[#e8002d] ml-1"><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          </div>
          {/* Parameters */}
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">パラメータ</label>
            <div className="flex gap-2 mb-2">
              <input value={form.param_key} onChange={e => setForm(f => ({ ...f, param_key: e.target.value }))} placeholder="キー" className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
              <input value={form.param_value} onChange={e => setForm(f => ({ ...f, param_value: e.target.value }))} placeholder="値" className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
              <button onClick={addParam} className="px-3 py-2 bg-[#1e2d42] text-white rounded-lg text-sm hover:bg-[#243347] transition-colors">追加</button>
            </div>
            {Object.entries(form.parameters).length > 0 && (
              <div className="space-y-1">
                {Object.entries(form.parameters).map(([k, v]) => (
                  <div key={k} className="flex items-center gap-2 px-2 py-1 bg-[#070d19] border border-[#1e2d42] rounded text-xs">
                    <span className="text-[#7d92b0] font-mono">{k}</span>
                    <span className="text-[#3d5068]">=</span>
                    <span className="text-white font-mono flex-1">{v}</span>
                    <button onClick={() => removeParam(k)} className="text-[#7d92b0] hover:text-[#e8002d]"><X className="w-3 h-3" /></button>
                  </div>
                ))}
              </div>
            )}
          </div>
          {/* Active */}
          <div className="flex items-center gap-3">
            <label className="text-[#7d92b0] text-sm">有効</label>
            <button onClick={() => setForm(f => ({ ...f, is_active: !f.is_active }))} className={`text-2xl transition-colors ${form.is_active ? 'text-green-400' : 'text-[#3d5068]'}`}>
              {form.is_active ? <ToggleRight className="w-8 h-5" /> : <ToggleLeft className="w-8 h-5" />}
            </button>
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-[#7d92b0] text-sm hover:text-white rounded-lg hover:bg-[#1e2d42] transition-colors">キャンセル</button>
          <button onClick={() => onSave({ ...form, schedule: scheduleValue, schedule_label: scheduleLabel })} className="px-4 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ─── Generate Modal ───────────────────────────────────────────────────────────

interface GenerateModalProps {
  onClose: () => void
  onGenerate: (data: { name: string; report_type: ReportType; period_start: string; period_end: string; output_format: OutputFormat }) => void
}

function GenerateModal({ onClose, onGenerate }: GenerateModalProps) {
  const [form, setForm] = useState({
    name: '', report_type: 'executive' as ReportType,
    period_start: '2026-03-01', period_end: '2026-03-18', output_format: 'PDF' as OutputFormat,
  })
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-lg">新規レポート生成</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1 rounded hover:bg-[#1e2d42] transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">レポート名</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" placeholder="レポート名を入力..." />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">レポートタイプ</label>
              <select value={form.report_type} onChange={e => setForm(f => ({ ...f, report_type: e.target.value as ReportType }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(Object.keys(TYPE_LABEL) as ReportType[]).map(t => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">出力形式</label>
              <select value={form.output_format} onChange={e => setForm(f => ({ ...f, output_format: e.target.value as OutputFormat }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(['PDF', 'HTML', 'JSON', 'CSV'] as OutputFormat[]).map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">開始日</label>
              <input type="date" value={form.period_start} onChange={e => setForm(f => ({ ...f, period_start: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
            </div>
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1.5">終了日</label>
              <input type="date" value={form.period_end} onChange={e => setForm(f => ({ ...f, period_end: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-[#7d92b0] text-sm hover:text-white rounded-lg hover:bg-[#1e2d42] transition-colors">キャンセル</button>
          <button onClick={() => onGenerate(form)} className="px-4 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors flex items-center gap-2"><Play className="w-4 h-4" />生成開始</button>
        </div>
      </div>
    </div>
  )
}

// ─── Statistics Bar Chart ─────────────────────────────────────────────────────

function StatsChart({ reports }: { reports: GeneratedReport[] }) {
  const types: ReportType[] = ['executive', 'operational', 'compliance', 'threat_intel', 'custom']
  const counts = types.map(t => reports.filter(r => r.report_type === t).length)
  const max = Math.max(...counts, 1)
  const colors: Record<ReportType, string> = {
    executive: 'bg-purple-500', operational: 'bg-blue-500', compliance: 'bg-green-500', threat_intel: 'bg-orange-500', custom: 'bg-gray-500',
  }
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      <h3 className="text-white font-semibold text-sm mb-4">タイプ別生成統計</h3>
      <div className="space-y-3">
        {types.map((t, i) => (
          <div key={t} className="flex items-center gap-3">
            <span className="text-[#7d92b0] text-xs w-28 flex-shrink-0">{TYPE_LABEL[t]}</span>
            <div className="flex-1 bg-[#070d19] rounded-full h-2">
              <div className={`${colors[t]} h-2 rounded-full transition-all duration-500`} style={{ width: `${(counts[i] / max) * 100}%` }} />
            </div>
            <span className="text-white text-xs w-6 text-right">{counts[i]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ReportsEnginePage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'schedules' | 'reports'>('schedules')
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [showGenerateModal, setShowGenerateModal] = useState(false)
  const [editingSchedule, setEditingSchedule] = useState<Schedule | undefined>()
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)
  const [filterType, setFilterType] = useState<ReportType | 'all'>('all')
  const [filterStatus, setFilterStatus] = useState<ReportStatus | 'all'>('all')
  const [filterFrom, setFilterFrom] = useState('')
  const [filterTo, setFilterTo] = useState('')

  const showToast = (message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3500)
  }

  const { data: schedulesData } = useQuery<{ schedules: Schedule[] }>({
    queryKey: ['report-schedules'],
    queryFn: () => apiFetch('/api/v1/admin/metrics-reports/schedules'),
  })
  const schedules = schedulesData?.schedules ?? []

  const { data: reportsData, refetch: refetchReports } = useQuery<{ reports: GeneratedReport[] }>({
    queryKey: ['generated-reports'],
    queryFn: () => apiFetch('/api/v1/admin/metrics-reports/reports'),
  })
  const reports = reportsData?.reports ?? []

  const [localSchedules, setLocalSchedules] = useState<Schedule[]>([])
  const [localReports, setLocalReports] = useState<GeneratedReport[]>([])

  const displaySchedules = schedulesData?.schedules ?? localSchedules
  const displayReports = reportsData?.reports ?? localReports

  const filteredReports = displayReports.filter(r => {
    if (filterType !== 'all' && r.report_type !== filterType) return false
    if (filterStatus !== 'all' && r.status !== filterStatus) return false
    if (filterFrom && r.generated_at < filterFrom) return false
    if (filterTo && r.generated_at > filterTo + 'T23:59:59Z') return false
    return true
  })

  const handleSaveSchedule = (data: Partial<Schedule>) => {
    if (editingSchedule) {
      setLocalSchedules(s => s.map(x => x.id === editingSchedule.id ? { ...x, ...data } : x))
      showToast('スケジュールを更新しました')
    } else {
      const newSched: Schedule = { id: `s${Date.now()}`, name: data.name ?? '', report_type: data.report_type ?? 'custom', description: data.description ?? '', schedule: data.schedule ?? '', schedule_label: data.schedule_label ?? '', recipients: data.recipients ?? [], output_format: data.output_format ?? 'PDF', next_run: new Date(Date.now() + 86400000).toISOString(), is_active: data.is_active ?? true, parameters: data.parameters ?? {} }
      setLocalSchedules(s => [...s, newSched])
      showToast('スケジュールを作成しました')
    }
    setShowScheduleModal(false)
    setEditingSchedule(undefined)
  }

  const handleDeleteSchedule = (id: string) => {
    setLocalSchedules(s => s.filter(x => x.id !== id))
    showToast('スケジュールを削除しました')
  }

  const handleToggleSchedule = (id: string) => {
    setLocalSchedules(s => s.map(x => x.id === id ? { ...x, is_active: !x.is_active } : x))
  }

  const handleRunNow = (s: Schedule) => {
    showToast(`「${s.name}」を生成しました`)
    const newReport: GeneratedReport = {
      id: `r${Date.now()}`, name: `${s.name} ${new Date().toLocaleDateString('ja-JP')}`, report_type: s.report_type,
      period_start: new Date(Date.now() - 86400000).toISOString().split('T')[0], period_end: new Date().toISOString().split('T')[0],
      status: 'completed', output_format: s.output_format, file_size_kb: Math.floor(Math.random() * 3000 + 500), generated_at: new Date().toISOString(),
    }
    setLocalReports(r => [newReport, ...r])
    setActiveTab('reports')
  }

  const handleGenerate = (data: { name: string; report_type: ReportType; period_start: string; period_end: string; output_format: OutputFormat }) => {
    setShowGenerateModal(false)
    showToast(`レポートの生成を開始しました`)
    const newReport: GeneratedReport = {
      id: `r${Date.now()}`, name: data.name || `${TYPE_LABEL[data.report_type]} レポート`, report_type: data.report_type,
      period_start: data.period_start, period_end: data.period_end, status: 'generating', output_format: data.output_format, file_size_kb: 0, generated_at: new Date().toISOString(),
    }
    setLocalReports(r => [newReport, ...r])
    setTimeout(() => {
      setLocalReports(r => r.map(x => x.id === newReport.id ? { ...x, status: 'completed', file_size_kb: Math.floor(Math.random() * 3000 + 500) } : x))
      showToast('レポートを生成しました')
    }, 3000)
  }

  const handleDeleteReport = (id: string) => {
    setLocalReports(r => r.filter(x => x.id !== id))
    showToast('レポートを削除しました')
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Toast */}
      {toast && (
        <div className={`fixed top-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-xl border text-sm font-medium transition-all ${toast.type === 'success' ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
          {toast.type === 'success' ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
          {toast.message}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center">
            <Printer className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">レポーティングエンジン</h1>
            <p className="text-[#7d92b0] text-sm">セキュリティメトリクスレポートの自動生成・管理</p>
          </div>
        </div>
        <button onClick={activeTab === 'schedules' ? () => { setEditingSchedule(undefined); setShowScheduleModal(true) } : () => setShowGenerateModal(true)} className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors">
          <Plus className="w-4 h-4" />
          {activeTab === 'schedules' ? '新規スケジュール' : '新規レポート生成'}
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['schedules', 'reports'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === tab ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {tab === 'schedules' ? 'スケジュール' : '生成済みレポート'}
          </button>
        ))}
      </div>

      {/* Schedules Tab */}
      {activeTab === 'schedules' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['レポート名', 'タイプ', 'スケジュール', '送信先', '形式', '次回実行', '状態', 'アクション'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {displaySchedules.map(s => (
                <tr key={s.id} className="hover:bg-[#0d1826] transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-white text-sm font-medium">{s.name}</p>
                    {s.description && <p className="text-[#7d92b0] text-xs mt-0.5">{s.description}</p>}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${TYPE_BADGE[s.report_type]}`}>{TYPE_LABEL[s.report_type]}</span>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{s.schedule_label}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{s.recipients.length}人</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${FORMAT_BADGE[s.output_format]}`}>{s.output_format}</span>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm">{formatDate(s.next_run)}</td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleToggleSchedule(s.id)} className={`text-2xl transition-colors ${s.is_active ? 'text-green-400' : 'text-[#3d5068]'}`}>
                      {s.is_active ? <ToggleRight className="w-8 h-5" /> : <ToggleLeft className="w-8 h-5" />}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button onClick={() => handleRunNow(s)} title="今すぐ生成" className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-green-400 transition-colors"><Play className="w-3.5 h-3.5" /></button>
                      <button onClick={() => { setEditingSchedule(s); setShowScheduleModal(true) }} title="編集" className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><Pencil className="w-3.5 h-3.5" /></button>
                      <button onClick={() => handleDeleteSchedule(s.id)} title="削除" className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] transition-colors"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 text-[#7d92b0]"><Filter className="w-4 h-4" /></div>
            <select value={filterType} onChange={e => setFilterType(e.target.value as ReportType | 'all')} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
              <option value="all">全タイプ</option>
              {(Object.keys(TYPE_LABEL) as ReportType[]).map(t => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
            </select>
            <select value={filterStatus} onChange={e => setFilterStatus(e.target.value as ReportStatus | 'all')} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
              <option value="all">全ステータス</option>
              {(Object.keys(STATUS_LABEL) as ReportStatus[]).map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
            </select>
            <input type="date" value={filterFrom} onChange={e => setFilterFrom(e.target.value)} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
            <span className="text-[#7d92b0] text-sm">〜</span>
            <input type="date" value={filterTo} onChange={e => setFilterTo(e.target.value)} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
            {(filterType !== 'all' || filterStatus !== 'all' || filterFrom || filterTo) && (
              <button onClick={() => { setFilterType('all'); setFilterStatus('all'); setFilterFrom(''); setFilterTo('') }} className="flex items-center gap-1 px-2 py-1 text-xs text-[#7d92b0] hover:text-white rounded hover:bg-[#1e2d42] transition-colors"><X className="w-3 h-3" />クリア</button>
            )}
          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['レポート名', 'タイプ', '期間', 'ステータス', '形式', 'サイズ', '生成日時', 'アクション'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {filteredReports.map(r => (
                  <tr key={r.id} className="hover:bg-[#0d1826] transition-colors">
                    <td className="px-4 py-3 text-white text-sm font-medium">{r.name}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${TYPE_BADGE[r.report_type]}`}>{TYPE_LABEL[r.report_type]}</span>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-xs">{r.period_start} 〜 {r.period_end}</td>
                    <td className="px-4 py-3">
                      <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium w-fit ${STATUS_BADGE[r.status]}`}>
                        {r.status === 'generating' && <RefreshCw className="w-3 h-3 animate-spin" />}
                        {STATUS_LABEL[r.status]}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${FORMAT_BADGE[r.output_format]}`}>{r.output_format}</span>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{formatBytes(r.file_size_kb)}</td>
                    <td className="px-4 py-3 text-[#7d92b0] text-sm">{formatDate(r.generated_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        {r.status === 'completed' && (
                          <button title="ダウンロード" onClick={() => showToast('ダウンロードを開始しました')} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-blue-400 transition-colors"><Download className="w-3.5 h-3.5" /></button>
                        )}
                        <button onClick={() => handleDeleteReport(r.id)} title="削除" className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] transition-colors"><Trash2 className="w-3.5 h-3.5" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
                {filteredReports.length === 0 && (
                  <tr><td colSpan={8} className="px-4 py-12 text-center text-[#7d92b0] text-sm">条件に一致するレポートがありません</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Statistics */}
          <div className="grid grid-cols-2 gap-4 mt-4">
            <StatsChart reports={displayReports} />
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h3 className="text-white font-semibold text-sm mb-4">ステータス内訳</h3>
              <div className="space-y-3">
                {(Object.keys(STATUS_LABEL) as ReportStatus[]).map(s => {
                  const count = displayReports.filter(r => r.status === s).length
                  const pct = Math.round((count / Math.max(displayReports.length, 1)) * 100)
                  return (
                    <div key={s} className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium w-20 text-center ${STATUS_BADGE[s]}`}>{STATUS_LABEL[s]}</span>
                      <div className="flex-1 bg-[#070d19] rounded-full h-2">
                        <div className="bg-[#e8002d] h-2 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-white text-xs w-6 text-right">{count}</span>
                    </div>
                  )
                })}
              </div>
              <div className="mt-4 pt-4 border-t border-[#1e2d42] flex items-center justify-between">
                <span className="text-[#7d92b0] text-sm">合計レポート数</span>
                <span className="text-white font-bold text-lg">{displayReports.length}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {showScheduleModal && (
        <ScheduleModal schedule={editingSchedule} onClose={() => { setShowScheduleModal(false); setEditingSchedule(undefined) }} onSave={handleSaveSchedule} />
      )}
      {showGenerateModal && (
        <GenerateModal onClose={() => setShowGenerateModal(false)} onGenerate={handleGenerate} />
      )}
    </div>
  )
}
