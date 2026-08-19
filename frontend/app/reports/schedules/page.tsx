'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Calendar, Plus, Trash2, Edit2, X, Check,
  Clock, Mail, ToggleLeft, ToggleRight, ChevronDown, ChevronUp
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface ReportSchedule {
  id: string
  name: string
  report_type: string
  frequency: 'daily' | 'weekly' | 'monthly'
  day_of_week?: number
  day_of_month?: number
  hour: number
  recipients: string[]
  is_active: boolean
  last_run_at?: string
  next_run_at: string
  created_by_name: string
  created_at: string
  updated_at: string
}

const REPORT_TYPES = [
  { value: 'daily_summary',    label: 'デイリーサマリー' },
  { value: 'alert_summary',    label: 'アラートサマリー' },
  { value: 'agent_status',     label: 'エージェント状態' },
  { value: 'incident_report',  label: 'インシデントレポート' },
  { value: 'threat_summary',   label: '脅威サマリー' },
  { value: 'compliance',       label: 'コンプライアンス' },
]

const DAYS_OF_WEEK = ['日', '月', '火', '水', '木', '金', '土']

const FREQUENCY_LABEL: Record<string, string> = {
  daily: '毎日',
  weekly: '毎週',
  monthly: '毎月',
}

function formatDateTime(s?: string) {
  if (!s) return '—'
  return new Date(s).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function frequencyDetail(sc: ReportSchedule) {
  const hour = `${sc.hour}:00`
  if (sc.frequency === 'daily') return `毎日 ${hour}`
  if (sc.frequency === 'weekly') {
    const dow = sc.day_of_week !== undefined ? DAYS_OF_WEEK[sc.day_of_week] : '日'
    return `毎週${dow}曜日 ${hour}`
  }
  if (sc.frequency === 'monthly') {
    const dom = sc.day_of_month ?? 1
    return `毎月${dom}日 ${hour}`
  }
  return hour
}

const emptyForm = {
  name: '',
  report_type: 'daily_summary',
  frequency: 'daily' as 'daily' | 'weekly' | 'monthly',
  day_of_week: 1,
  day_of_month: 1,
  hour: 8,
  recipients: '',
  is_active: true,
}

export default function ReportSchedulesPage() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [form, setForm] = useState({ ...emptyForm })
  const [editForm, setEditForm] = useState({ ...emptyForm })
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const { data, isLoading } = useQuery<{ data: ReportSchedule[]; total: number }>({
    queryKey: ['report-schedules'],
    queryFn: () => apiFetch('/api/v1/reports/schedules'),
  })
  const schedules = data?.data ?? []

  const createMut = useMutation({
    mutationFn: (body: object) => apiFetch('/api/v1/reports/schedules', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['report-schedules'] }); setShowCreate(false); setForm({ ...emptyForm }) },
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) =>
      apiFetch(`/api/v1/reports/schedules/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['report-schedules'] }); setEditId(null) },
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/reports/schedules/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['report-schedules'] }),
  })

  const toggleMut = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      apiFetch(`/api/v1/reports/schedules/${id}/toggle`, { method: 'PUT', body: JSON.stringify({ is_active }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['report-schedules'] }),
  })

  function buildPayload(f: typeof emptyForm) {
    return {
      name: f.name,
      report_type: f.report_type,
      frequency: f.frequency,
      day_of_week: f.frequency === 'weekly' ? f.day_of_week : undefined,
      day_of_month: f.frequency === 'monthly' ? f.day_of_month : undefined,
      hour: f.hour,
      recipients: f.recipients.split(',').map(s => s.trim()).filter(Boolean),
      is_active: f.is_active,
    }
  }

  function startEdit(sc: ReportSchedule) {
    setEditId(sc.id)
    setEditForm({
      name: sc.name,
      report_type: sc.report_type,
      frequency: sc.frequency,
      day_of_week: sc.day_of_week ?? 1,
      day_of_month: sc.day_of_month ?? 1,
      hour: sc.hour,
      recipients: sc.recipients.join(', '),
      is_active: sc.is_active,
    })
  }

  const FrequencyExtra = ({ f, setF }: { f: typeof emptyForm; setF: (v: typeof emptyForm) => void }) => (
    <>
      {f.frequency === 'weekly' && (
        <div className="flex flex-col gap-1">
          <label className="text-xs text-[#8899aa]">曜日</label>
          <select
            className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white"
            value={f.day_of_week}
            onChange={e => setF({ ...f, day_of_week: Number(e.target.value) })}
          >
            {DAYS_OF_WEEK.map((d, i) => <option key={i} value={i}>{d}曜日</option>)}
          </select>
        </div>
      )}
      {f.frequency === 'monthly' && (
        <div className="flex flex-col gap-1">
          <label className="text-xs text-[#8899aa]">日付</label>
          <input
            type="number" min={1} max={28}
            className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white w-20"
            value={f.day_of_month}
            onChange={e => setF({ ...f, day_of_month: Number(e.target.value) })}
          />
        </div>
      )}
    </>
  )

  return (
    <div className="bg-[#080c14] text-white">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-5xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Calendar className="w-6 h-6 text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">スケジュールレポート</h1>
              <p className="text-[#8899aa] text-sm mt-0.5">定期的なレポートの自動生成を管理します</p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            新規スケジュール
          </button>
        </div>

        {/* Create Form */}
        {showCreate && (
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-6 mb-6">
            <h2 className="text-lg font-semibold mb-4 text-white">新規スケジュール作成</h2>
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2 flex flex-col gap-1">
                <label className="text-xs text-[#8899aa]">スケジュール名 <span className="text-red-400">*</span></label>
                <input
                  className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white"
                  placeholder="例: 週次セキュリティレポート"
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#8899aa]">レポート種別 <span className="text-red-400">*</span></label>
                <select
                  className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white"
                  value={form.report_type}
                  onChange={e => setForm({ ...form, report_type: e.target.value })}
                >
                  {REPORT_TYPES.map(rt => <option key={rt.value} value={rt.value}>{rt.label}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#8899aa]">頻度 <span className="text-red-400">*</span></label>
                <select
                  className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white"
                  value={form.frequency}
                  onChange={e => setForm({ ...form, frequency: e.target.value as 'daily' | 'weekly' | 'monthly' })}
                >
                  <option value="daily">毎日</option>
                  <option value="weekly">毎週</option>
                  <option value="monthly">毎月</option>
                </select>
              </div>
              <FrequencyExtra f={form} setF={setForm} />
              <div className="flex flex-col gap-1">
                <label className="text-xs text-[#8899aa]">実行時刻 (時)</label>
                <input
                  type="number" min={0} max={23}
                  className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white w-24"
                  value={form.hour}
                  onChange={e => setForm({ ...form, hour: Number(e.target.value) })}
                />
              </div>
              <div className="col-span-2 flex flex-col gap-1">
                <label className="text-xs text-[#8899aa] flex items-center gap-1">
                  <Mail className="w-3 h-3" /> 送信先メールアドレス (カンマ区切り)
                </label>
                <input
                  className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white"
                  placeholder="admin@example.com, soc@example.com"
                  value={form.recipients}
                  onChange={e => setForm({ ...form, recipients: e.target.value })}
                />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-5">
              <button
                onClick={() => { setShowCreate(false); setForm({ ...emptyForm }) }}
                className="px-4 py-2 text-sm text-[#8899aa] hover:text-white transition-colors"
              >キャンセル</button>
              <button
                onClick={() => createMut.mutate(buildPayload(form))}
                disabled={!form.name || createMut.isPending}
                className="flex items-center gap-2 bg-[#1a6bff] hover:bg-[#1557d4] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              >
                <Check className="w-4 h-4" />
                作成
              </button>
            </div>
          </div>
        )}

        {/* Schedules List */}
        {isLoading ? (
          <div className="text-center py-16 text-[#5a6a7a]">読み込み中...</div>
        ) : schedules.length === 0 ? (
          <div className="text-center py-16">
            <Calendar className="w-12 h-12 text-[#1e2d42] mx-auto mb-3" />
            <p className="text-[#5a6a7a]">スケジュールが登録されていません</p>
          </div>
        ) : (
          <div className="space-y-3">
            {schedules.map(sc => (
              <div key={sc.id} className={`bg-[#111827] border rounded-xl transition-all ${sc.is_active ? 'border-[#1e2d42]' : 'border-[#1e2d42] opacity-60'}`}>
                {/* Main Row */}
                <div className="flex items-center gap-4 px-5 py-4">
                  {/* Toggle */}
                  <button
                    onClick={() => toggleMut.mutate({ id: sc.id, is_active: !sc.is_active })}
                    className="shrink-0"
                    title={sc.is_active ? '無効化' : '有効化'}
                  >
                    {sc.is_active
                      ? <ToggleRight className="w-6 h-6 text-blue-400" />
                      : <ToggleLeft className="w-6 h-6 text-[#5a6a7a]" />
                    }
                  </button>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    {editId === sc.id ? (
                      /* Inline Edit */
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                          <div className="col-span-2 flex flex-col gap-1">
                            <label className="text-xs text-[#8899aa]">名前</label>
                            <input
                              className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white"
                              value={editForm.name}
                              onChange={e => setEditForm({ ...editForm, name: e.target.value })}
                            />
                          </div>
                          <div className="flex flex-col gap-1">
                            <label className="text-xs text-[#8899aa]">レポート種別</label>
                            <select
                              className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white"
                              value={editForm.report_type}
                              onChange={e => setEditForm({ ...editForm, report_type: e.target.value })}
                            >
                              {REPORT_TYPES.map(rt => <option key={rt.value} value={rt.value}>{rt.label}</option>)}
                            </select>
                          </div>
                          <div className="flex flex-col gap-1">
                            <label className="text-xs text-[#8899aa]">頻度</label>
                            <select
                              className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white"
                              value={editForm.frequency}
                              onChange={e => setEditForm({ ...editForm, frequency: e.target.value as 'daily' | 'weekly' | 'monthly' })}
                            >
                              <option value="daily">毎日</option>
                              <option value="weekly">毎週</option>
                              <option value="monthly">毎月</option>
                            </select>
                          </div>
                          <FrequencyExtra f={editForm} setF={setEditForm} />
                          <div className="flex flex-col gap-1">
                            <label className="text-xs text-[#8899aa]">実行時刻 (時)</label>
                            <input
                              type="number" min={0} max={23}
                              className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white w-20"
                              value={editForm.hour}
                              onChange={e => setEditForm({ ...editForm, hour: Number(e.target.value) })}
                            />
                          </div>
                          <div className="col-span-2 flex flex-col gap-1">
                            <label className="text-xs text-[#8899aa]">送信先</label>
                            <input
                              className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-sm text-white"
                              value={editForm.recipients}
                              onChange={e => setEditForm({ ...editForm, recipients: e.target.value })}
                            />
                          </div>
                          <div className="col-span-2 flex items-center gap-2">
                            <input
                              type="checkbox"
                              id={`active-${sc.id}`}
                              checked={editForm.is_active}
                              onChange={e => setEditForm({ ...editForm, is_active: e.target.checked })}
                              className="rounded-sm"
                            />
                            <label htmlFor={`active-${sc.id}`} className="text-sm text-[#8899aa]">有効</label>
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => updateMut.mutate({ id: sc.id, body: buildPayload(editForm) })}
                            disabled={updateMut.isPending}
                            className="flex items-center gap-1 bg-[#1a6bff] hover:bg-[#1557d4] text-white px-3 py-1.5 rounded-sm text-xs"
                          >
                            <Check className="w-3 h-3" /> 保存
                          </button>
                          <button
                            onClick={() => setEditId(null)}
                            className="flex items-center gap-1 text-[#8899aa] hover:text-white px-3 py-1.5 rounded-sm text-xs"
                          >
                            <X className="w-3 h-3" /> キャンセル
                          </button>
                        </div>
                      </div>
                    ) : (
                      /* Display */
                      <>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-semibold text-white text-sm">{sc.name}</span>
                          <span className="text-xs bg-[#161f33] text-[#8899aa] px-2 py-0.5 rounded-full">
                            {REPORT_TYPES.find(r => r.value === sc.report_type)?.label ?? sc.report_type}
                          </span>
                          <span className="text-xs bg-blue-900/40 text-blue-300 border border-blue-700/40 px-2 py-0.5 rounded-full">
                            {FREQUENCY_LABEL[sc.frequency]}
                          </span>
                          {!sc.is_active && (
                            <span className="text-xs bg-[#111827] text-[#5a6a7a] px-2 py-0.5 rounded-full">無効</span>
                          )}
                        </div>
                        <div className="flex items-center gap-4 text-xs text-[#8899aa]">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" /> {frequencyDetail(sc)}
                          </span>
                          {sc.recipients.length > 0 && (
                            <span className="flex items-center gap-1">
                              <Mail className="w-3 h-3" /> {sc.recipients.length}件の送信先
                            </span>
                          )}
                        </div>
                      </>
                    )}
                  </div>

                  {/* Actions */}
                  {editId !== sc.id && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => setExpandedId(expandedId === sc.id ? null : sc.id)}
                        className="p-1.5 text-[#5a6a7a] hover:text-white transition-colors"
                        title="詳細"
                      >
                        {expandedId === sc.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                      <button
                        onClick={() => startEdit(sc)}
                        className="p-1.5 text-[#5a6a7a] hover:text-blue-400 transition-colors"
                        title="編集"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => { if (confirm('このスケジュールを削除しますか？')) deleteMut.mutate(sc.id) }}
                        className="p-1.5 text-[#5a6a7a] hover:text-red-400 transition-colors"
                        title="削除"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  )}
                </div>

                {/* Expanded Detail */}
                {expandedId === sc.id && editId !== sc.id && (
                  <div className="px-5 pb-4 border-t border-[#1e2d42] pt-4 grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <p className="text-xs text-[#5a6a7a] mb-1">次回実行</p>
                      <p className="text-[#8899aa]">{formatDateTime(sc.next_run_at)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-[#5a6a7a] mb-1">最終実行</p>
                      <p className="text-[#8899aa]">{formatDateTime(sc.last_run_at)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-[#5a6a7a] mb-1">作成者</p>
                      <p className="text-[#8899aa]">{sc.created_by_name || '—'}</p>
                    </div>
                    {sc.recipients.length > 0 && (
                      <div className="col-span-3">
                        <p className="text-xs text-[#5a6a7a] mb-1">送信先</p>
                        <div className="flex flex-wrap gap-1.5">
                          {sc.recipients.map(r => (
                            <span key={r} className="text-xs bg-[#111827] text-[#8899aa] px-2 py-0.5 rounded-sm flex items-center gap-1">
                              <Mail className="w-3 h-3" /> {r}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="col-span-3 text-xs text-[#5a6a7a]">
                      作成日: {formatDateTime(sc.created_at)} / 更新日: {formatDateTime(sc.updated_at)}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
