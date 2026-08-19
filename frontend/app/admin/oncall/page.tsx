'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Plus, Trash2, Edit2, AlertTriangle, X, Loader2,
  Bell, Activity, Clock, AlertCircle, CheckCircle2,
  RefreshCw, Send, Filter, ChevronDown, ToggleLeft, ToggleRight,
  Zap,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ────────────────────────────────────────────────────────────────────

type Provider = 'pagerduty' | 'opsgenie' | 'victorops'
type EventType = 'trigger' | 'resolve' | 'acknowledge'
type EventStatus = 'sent' | 'failed'

interface OnCallIntegration {
  id: string
  provider: Provider
  name: string
  integration_key: string
  severity_threshold: number
  enabled: boolean
  events_sent: number
  last_event: string | null
  created_at: string
}

interface OnCallEvent {
  id: string
  integration_id: string
  integration_name: string
  alert_id: string
  event_type: EventType
  summary: string
  severity: number
  status: EventStatus
  response_code: number | null
  sent_at: string
}

interface CreateIntegrationPayload {
  provider: Provider
  name: string
  integration_key: string
  severity_threshold: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const PROVIDER_META: Record<Provider, { label: string; color: string; bg: string; border: string; help: string }> = {
  pagerduty: {
    label: 'PagerDuty',
    color: 'text-[#00c853]',
    bg: 'bg-[#00c853]/10',
    border: 'border-[#00c853]/30',
    help: 'PagerDutyのサービス統合キーを入力してください。サービス → 統合 → Events API v2 で取得できます。',
  },
  opsgenie: {
    label: 'OpsGenie',
    color: 'text-[#1a6bff]',
    bg: 'bg-[#1a6bff]/10',
    border: 'border-[#1a6bff]/30',
    help: 'OpsGenieのAPIキーを入力してください。設定 → API key management で作成できます。',
  },
  victorops: {
    label: 'VictorOps',
    color: 'text-[#e8002d]',
    bg: 'bg-[#e8002d]/10',
    border: 'border-[#e8002d]/30',
    help: 'VictorOps (Splunk On-Call) のルーティングキーを入力してください。Integrations → REST Endpoint で確認できます。',
  },
}

function maskKey(key: string): string {
  if (key.length <= 4) return '****'
  return '****' + key.slice(-4)
}

function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const min = Math.floor(diff / 60000)
  if (min < 60) return `${min}分前`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}時間前`
  return `${Math.floor(hr / 24)}日前`
}

function Badge({ children, color }: { children: React.ReactNode; color: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[11px] font-medium border ${color}`}>
      {children}
    </span>
  )
}

function Toast({ message, onClose }: { message: string; onClose: () => void }) {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-lg bg-[#0d1220] border border-[#00c853]/40 shadow-xl text-sm text-[#e2e8f4]">
      <CheckCircle2 className="w-4 h-4 text-[#00c853] shrink-0" />
      <span>{message}</span>
      <button onClick={onClose} className="p-0.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] transition-colors">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}

// ── Integration Form Modal ────────────────────────────────────────────────────

interface IntegrationForm {
  provider: Provider
  name: string
  integration_key: string
  severity_threshold: number
}

const defaultForm = (): IntegrationForm => ({
  provider: 'pagerduty',
  name: '',
  integration_key: '',
  severity_threshold: 7,
})

function IntegrationModal({
  title,
  initial,
  onSave,
  onClose,
  saving,
}: {
  title: string
  initial?: IntegrationForm
  onSave: (form: IntegrationForm) => void
  onClose: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<IntegrationForm>(initial ?? defaultForm())
  const [showKey, setShowKey] = useState(false)
  const meta = PROVIDER_META[form.provider]
  const valid = form.name.trim().length > 0 && form.integration_key.trim().length > 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm overflow-y-auto py-8">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
          <div className="w-8 h-8 rounded-lg bg-[#1a6bff]/10 flex items-center justify-center">
            <Bell className="w-4 h-4 text-[#1a6bff]" />
          </div>
          <h3 className="text-sm font-semibold text-[#e2e8f4] flex-1">{title}</h3>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Provider Select */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">プロバイダー <span className="text-[#e8002d]">*</span></label>
            <div className="grid grid-cols-3 gap-2">
              {(Object.keys(PROVIDER_META) as Provider[]).map(p => {
                const m = PROVIDER_META[p]
                return (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setForm(f => ({ ...f, provider: p }))}
                    className={`flex flex-col items-center gap-1.5 px-3 py-3 rounded-lg border text-center transition-colors ${
                      form.provider === p
                        ? `${m.bg} ${m.border} ${m.color}`
                        : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#253750]'
                    }`}
                  >
                    <Zap className="w-4 h-4" />
                    <span className="text-xs font-semibold">{m.label}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Name */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">名前 <span className="text-[#e8002d]">*</span></label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder={`${meta.label} Production`}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff]/60 transition-colors"
            />
          </div>

          {/* Integration Key */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">統合キー <span className="text-[#e8002d]">*</span></label>
            <div className="relative">
              <input
                type={showKey ? 'text' : 'password'}
                value={form.integration_key}
                onChange={e => setForm(f => ({ ...f, integration_key: e.target.value }))}
                placeholder="統合キーを入力..."
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 pr-10 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#1a6bff]/60 transition-colors font-mono"
              />
              <button
                type="button"
                onClick={() => setShowKey(s => !s)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
              >
                {showKey
                  ? <X className="w-4 h-4" />
                  : <Activity className="w-4 h-4" />
                }
              </button>
            </div>
            <p className="text-xs text-[#7d92b0] mt-0.5">{meta.help}</p>
          </div>

          {/* Severity Threshold Slider */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">重大度しきい値</label>
              <span className={`text-sm font-bold px-2 py-0.5 rounded-sm ${
                form.severity_threshold >= 8 ? 'text-[#e8002d] bg-[#e8002d]/10' :
                form.severity_threshold >= 6 ? 'text-[#f59e0b] bg-[#f59e0b]/10' :
                'text-[#00c853] bg-[#00c853]/10'
              }`}>
                {form.severity_threshold}
              </span>
            </div>
            <input
              type="range"
              min={1}
              max={10}
              value={form.severity_threshold}
              onChange={e => setForm(f => ({ ...f, severity_threshold: Number(e.target.value) }))}
              className="w-full accent-[#e8002d]"
            />
            <div className="flex justify-between text-[10px] text-[#3d5068]">
              <span>1 (低)</span>
              <span>重大度 ≥ {form.severity_threshold} で通知</span>
              <span>10 (高)</span>
            </div>
          </div>
        </div>

        <div className="px-5 py-4 border-t border-[#1e2d42] flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] text-sm font-medium transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => valid && onSave(form)}
            disabled={!valid || saving}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-[#1a6bff] hover:bg-[#1558d6] text-white text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Confirm Modal ─────────────────────────────────────────────────────────────

function ConfirmModal({ message, onConfirm, onClose }: { message: string; onConfirm: () => void; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#e8002d]/10 flex items-center justify-center">
            <AlertTriangle className="w-4 h-4 text-[#e8002d]" />
          </div>
          <p className="text-sm text-[#e2e8f4] flex-1">{message}</p>
        </div>
        <div className="flex gap-3">
          <button onClick={onClose} className="flex-1 py-2.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] text-sm font-medium transition-colors">
            キャンセル
          </button>
          <button onClick={onConfirm} className="flex-1 py-2.5 rounded-lg bg-[#e8002d] hover:bg-[#c8001d] text-white text-sm font-semibold transition-colors">
            削除
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function OnCallPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'settings' | 'history'>('settings')
  const [showCreate, setShowCreate] = useState(false)
  const [editTarget, setEditTarget] = useState<OnCallIntegration | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<OnCallIntegration | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [filterIntegration, setFilterIntegration] = useState<string>('all')
  const [filterEventType, setFilterEventType] = useState<string>('all')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [testingId, setTestingId] = useState<string | null>(null)

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(null), 4000)
  }

  // ── Queries ──
  const { data: displayIntegrations = [], isLoading: loadingInt } = useQuery<OnCallIntegration[]>({
    queryKey: ['oncall-integrations'],
    queryFn: () => apiFetchList<OnCallIntegration>('/api/v1/admin/oncall'),
    staleTime: 60_000,
  })

  const { data: displayEvents = [], isLoading: loadingEv } = useQuery<OnCallEvent[]>({
    queryKey: ['oncall-events'],
    queryFn: () => apiFetchList<OnCallEvent>('/api/v1/admin/oncall/events'),
    staleTime: 30_000,
    enabled: activeTab === 'history',
  })

  // ── Mutations ──
  const createMutation = useMutation({
    mutationFn: (payload: CreateIntegrationPayload) =>
      apiFetch('/api/v1/admin/oncall', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oncall-integrations'] })
      setShowCreate(false)
      showToast('統合を追加しました')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Partial<CreateIntegrationPayload> }) =>
      apiFetch(`/api/v1/admin/oncall/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oncall-integrations'] })
      setEditTarget(null)
      showToast('統合を更新しました')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/oncall/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oncall-integrations'] })
      setDeleteTarget(null)
      showToast('統合を削除しました')
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/v1/admin/oncall/${id}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['oncall-integrations'] }),
  })

  const testMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/oncall/${id}/test`, { method: 'POST' }),
    onSuccess: (data: any, id) => {
      setTestingId(null)
      showToast(`テストイベントを送信しました (${data?.status ?? 202})`)
    },
    onError: (_, id) => {
      setTestingId(null)
      showToast('テスト送信に失敗しました')
    },
  })

  const resendMutation = useMutation({
    mutationFn: (eventId: string) =>
      apiFetch(`/api/v1/admin/oncall/events/${eventId}/resend`, { method: 'POST' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oncall-events'] })
      showToast('再送信しました')
    },
  })

  // ── Stats ──
  const activeCount = displayIntegrations.filter(i => i.enabled).length
  const eventsSentToday = displayEvents.filter(e => {
    const sentAt = new Date(e.sent_at)
    const now = new Date()
    return sentAt.toDateString() === now.toDateString()
  }).length
  const failedCount = displayEvents.filter(e => e.status === 'failed').length
  const lastEvent = displayEvents.length > 0
    ? displayEvents.reduce((a, b) => a.sent_at > b.sent_at ? a : b).sent_at
    : null

  // ── Filtered Events ──
  const filteredEvents = displayEvents.filter(e => {
    if (filterIntegration !== 'all' && e.integration_id !== filterIntegration) return false
    if (filterEventType !== 'all' && e.event_type !== filterEventType) return false
    if (filterStatus !== 'all' && e.status !== filterStatus) return false
    return true
  })

  return (
    <div className="min-h-screen bg-[#070d19] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed />
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">

        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-[#e2e8f4] tracking-tight">オンコール統合</h1>
            <p className="text-sm text-[#7d92b0] mt-1">PagerDuty・OpsGenieへの重大アラート自動通知</p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#e8002d] hover:bg-[#c8001d] text-white text-sm font-semibold transition-colors shadow-lg"
          >
            <Plus className="w-4 h-4" />
            統合追加
          </button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'アクティブ統合', value: String(activeCount), icon: Activity, color: 'text-[#00c853]' },
            { label: '今日のイベント送信', value: String(eventsSentToday), icon: Send, color: 'text-[#1a6bff]' },
            {
              label: '最終イベント時刻',
              value: lastEvent ? formatRelative(lastEvent) : 'なし',
              icon: Clock,
              color: 'text-[#7d92b0]',
            },
            {
              label: '失敗イベント',
              value: String(failedCount),
              icon: AlertCircle,
              color: failedCount > 0 ? 'text-[#e8002d]' : 'text-[#7d92b0]',
            },
          ].map(stat => (
            <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-[#7d92b0]">{stat.label}</p>
                <stat.icon className={`w-4 h-4 ${stat.color}`} />
              </div>
              <p className={`text-xl font-bold ${stat.label === '失敗イベント' && failedCount > 0 ? 'text-[#e8002d]' : 'text-[#e2e8f4]'}`}>
                {stat.value}
              </p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 p-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg w-fit">
          {([['settings', '統合設定'], ['history', 'イベント履歴']] as const).map(([tab, label]) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${
                activeTab === tab
                  ? 'bg-[#1e2d42] text-[#e2e8f4]'
                  : 'text-[#7d92b0] hover:text-[#e2e8f4]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ── 統合設定 Tab ── */}
        {activeTab === 'settings' && (
          <div className="grid grid-cols-1 gap-4">
            {loadingInt
              ? Array.from({ length: 2 }).map((_, i) => (
                  <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 animate-pulse">
                    <div className="h-5 bg-[#1e2d42] rounded-sm w-48 mb-3" />
                    <div className="h-4 bg-[#1e2d42] rounded-sm w-32" />
                  </div>
                ))
              : displayIntegrations.map(intg => {
                  const meta = PROVIDER_META[intg.provider]
                  const isTesting = testingId === intg.id
                  return (
                    <div key={intg.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex items-start gap-4 flex-1 min-w-0">
                          {/* Provider Badge */}
                          <div className={`shrink-0 px-3 py-2 rounded-lg border ${meta.bg} ${meta.border}`}>
                            <span className={`text-xs font-bold ${meta.color}`}>{meta.label}</span>
                          </div>

                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <h3 className="text-sm font-semibold text-[#e2e8f4]">{intg.name}</h3>
                              {/* Severity Badge */}
                              <Badge color={
                                intg.severity_threshold >= 8
                                  ? 'border-[#e8002d]/40 text-[#e8002d] bg-[#e8002d]/5'
                                  : intg.severity_threshold >= 6
                                  ? 'border-[#f59e0b]/40 text-[#f59e0b] bg-[#f59e0b]/5'
                                  : 'border-[#00c853]/40 text-[#00c853] bg-[#00c853]/5'
                              }>
                                重大度 ≥ {intg.severity_threshold}
                              </Badge>
                            </div>
                            {/* Masked Key */}
                            <p className="text-xs font-mono text-[#7d92b0] mt-1">
                              鍵: {maskKey(intg.integration_key)}
                            </p>
                            <div className="flex items-center gap-4 mt-2 text-xs text-[#7d92b0]">
                              <span>送信: <span className="text-[#e2e8f4] font-medium">{intg.events_sent}</span></span>
                              {intg.last_event && (
                                <span>最終: <span className="text-[#e2e8f4]">{formatRelative(intg.last_event)}</span></span>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center gap-2 shrink-0">
                          {/* Enabled Toggle */}
                          <div
                            onClick={() => toggleMutation.mutate({ id: intg.id, enabled: !intg.enabled })}
                            className="cursor-pointer"
                          >
                            {intg.enabled
                              ? <ToggleRight className="w-8 h-8 text-[#00c853]" />
                              : <ToggleLeft className="w-8 h-8 text-[#3d5068]" />
                            }
                          </div>

                          {/* Test Button */}
                          <button
                            onClick={() => {
                              setTestingId(intg.id)
                              testMutation.mutate(intg.id)
                            }}
                            disabled={isTesting}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#253750] disabled:opacity-50 transition-colors"
                          >
                            {isTesting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                            テスト送信
                          </button>

                          {/* Edit */}
                          <button
                            onClick={() => setEditTarget(intg)}
                            className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>

                          {/* Delete */}
                          <button
                            onClick={() => setDeleteTarget(intg)}
                            className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  )
                })
            }

            {!loadingInt && displayIntegrations.length === 0 && (
              <div className="bg-[#0d1220] border border-dashed border-[#1e2d42] rounded-xl p-10 text-center">
                <Bell className="w-8 h-8 text-[#3d5068] mx-auto mb-3" />
                <p className="text-sm text-[#7d92b0]">統合がまだ設定されていません</p>
                <button
                  onClick={() => setShowCreate(true)}
                  className="mt-3 text-sm text-[#1a6bff] hover:text-[#4d8bff] transition-colors flex items-center gap-1.5 mx-auto"
                >
                  <Plus className="w-4 h-4" />
                  最初の統合を追加
                </button>
              </div>
            )}
          </div>
        )}

        {/* ── イベント履歴 Tab ── */}
        {activeTab === 'history' && (
          <div className="space-y-4">
            {/* Filters */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
                <Filter className="w-3.5 h-3.5" />
                フィルター:
              </div>

              <select
                value={filterIntegration}
                onChange={e => setFilterIntegration(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-xs text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]/60 transition-colors"
              >
                <option value="all">すべての統合</option>
                {displayIntegrations.map(i => (
                  <option key={i.id} value={i.id}>{i.name}</option>
                ))}
              </select>

              <select
                value={filterEventType}
                onChange={e => setFilterEventType(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-xs text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]/60 transition-colors"
              >
                <option value="all">すべてのタイプ</option>
                <option value="trigger">trigger</option>
                <option value="resolve">resolve</option>
                <option value="acknowledge">acknowledge</option>
              </select>

              <select
                value={filterStatus}
                onChange={e => setFilterStatus(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-xs text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]/60 transition-colors"
              >
                <option value="all">すべてのステータス</option>
                <option value="sent">送信済み</option>
                <option value="failed">失敗</option>
              </select>

              <span className="text-xs text-[#3d5068]">{filteredEvents.length} 件</span>
            </div>

            {/* Table */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['統合名', 'アラートID', 'タイプ', 'サマリー', '重大度', 'ステータス', 'レスポンス', '送信時刻', ''].map(h => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wide whitespace-nowrap">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {loadingEv
                      ? Array.from({ length: 5 }).map((_, i) => (
                          <tr key={i} className="animate-pulse">
                            {Array.from({ length: 9 }).map((_, j) => (
                              <td key={j} className="px-4 py-3">
                                <div className="h-3.5 bg-[#1e2d42] rounded-sm" />
                              </td>
                            ))}
                          </tr>
                        ))
                      : filteredEvents.map(ev => (
                          <tr key={ev.id} className="hover:bg-[#0a1120] transition-colors">
                            <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                              {ev.integration_name}
                            </td>
                            <td className="px-4 py-3">
                              <a href={`/alerts?id=${ev.alert_id}`} className="text-xs font-mono text-[#1a6bff] hover:text-[#4d8bff] transition-colors">
                                {ev.alert_id}
                              </a>
                            </td>
                            <td className="px-4 py-3">
                              <Badge color={
                                ev.event_type === 'trigger'
                                  ? 'border-[#e8002d]/40 text-[#e8002d] bg-[#e8002d]/5'
                                  : ev.event_type === 'resolve'
                                  ? 'border-[#00c853]/40 text-[#00c853] bg-[#00c853]/5'
                                  : 'border-[#f59e0b]/40 text-[#f59e0b] bg-[#f59e0b]/5'
                              }>
                                {ev.event_type}
                              </Badge>
                            </td>
                            <td className="px-4 py-3 max-w-[220px]">
                              <p className="text-xs text-[#7d92b0] truncate" title={ev.summary}>{ev.summary}</p>
                            </td>
                            <td className="px-4 py-3 text-center">
                              <span className={`text-xs font-bold ${
                                ev.severity >= 8 ? 'text-[#e8002d]' : ev.severity >= 6 ? 'text-[#f59e0b]' : 'text-[#7d92b0]'
                              }`}>
                                {ev.severity}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <Badge color={
                                ev.status === 'sent'
                                  ? 'border-[#00c853]/40 text-[#00c853] bg-[#00c853]/5'
                                  : 'border-[#e8002d]/40 text-[#e8002d] bg-[#e8002d]/5'
                              }>
                                {ev.status === 'sent' ? '送信済み' : '失敗'}
                              </Badge>
                            </td>
                            <td className="px-4 py-3 text-xs font-mono text-[#7d92b0]">
                              {ev.response_code ?? '—'}
                            </td>
                            <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                              {formatRelative(ev.sent_at)}
                            </td>
                            <td className="px-4 py-3">
                              {ev.status === 'failed' && (
                                <button
                                  onClick={() => resendMutation.mutate(ev.id)}
                                  className="flex items-center gap-1 px-2.5 py-1 rounded-sm border border-[#1e2d42] text-xs text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#253750] transition-colors"
                                >
                                  <RefreshCw className="w-3 h-3" />
                                  再送信
                                </button>
                              )}
                            </td>
                          </tr>
                        ))
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Modals ── */}
      {showCreate && (
        <IntegrationModal
          title="統合追加"
          onSave={form => createMutation.mutate(form)}
          onClose={() => setShowCreate(false)}
          saving={createMutation.isPending}
        />
      )}

      {editTarget && (
        <IntegrationModal
          title="統合編集"
          initial={{
            provider: editTarget.provider,
            name: editTarget.name,
            integration_key: editTarget.integration_key,
            severity_threshold: editTarget.severity_threshold,
          }}
          onSave={form => updateMutation.mutate({ id: editTarget.id, payload: form })}
          onClose={() => setEditTarget(null)}
          saving={updateMutation.isPending}
        />
      )}

      {deleteTarget && (
        <ConfirmModal
          message={`「${deleteTarget.name}」を削除します。この操作は元に戻せません。`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onClose={() => setDeleteTarget(null)}
        />
      )}

      {toast && <Toast message={toast} onClose={() => setToast(null)} />}
    </div>
  )
}
