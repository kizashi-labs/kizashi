'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Bell, Plus, Trash2, RefreshCw, CheckCircle, XCircle,
  ChevronDown, ChevronRight, ToggleLeft, ToggleRight,
  Globe, Zap, AlertTriangle, Send, X, Copy, Check,
  Activity, Clock, TrendingUp, TrendingDown
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { usePersist, SaveFailed, saveErrorOf } from '@/lib/persist'

// ── Types ──────────────────────────────────────────────────────────────────────

interface WebhookDelivery {
  id: string
  status: 'success' | 'failed'
  status_code: number
  delivered_at: string
  event_type: string
  duration_ms?: number
}

interface Webhook {
  id: string
  name: string
  platform: 'slack' | 'teams' | 'pagerduty' | 'generic'
  url: string
  secret?: string
  events: string[]
  enabled: boolean
  retry_count: number
  delivery_count: number
  failure_count: number
  last_delivery_at?: string
  last_delivery_status?: 'success' | 'failed'
  created_at: string
  recent_deliveries?: WebhookDelivery[]
}

interface WebhookStats {
  active: number
  deliveries_24h: number
  success_rate: number
  failed_24h: number
}

const ALL_EVENTS = [
  'alert.created', 'alert.resolved', 'alert.escalated',
  'incident.created', 'incident.updated', 'incident.closed',
  'agent.connected', 'agent.disconnected', 'agent.updated',
  'rule.triggered', 'rule.created', 'rule.updated',
  'user.login', 'user.created', 'user.deleted',
  'scan.completed', 'scan.failed',
  'compliance.violation', 'backup.completed',
]

const PLATFORM_STYLES: Record<string, { label: string; icon: string; bg: string; color: string }> = {
  slack:     { label: 'Slack',            icon: '💬', bg: 'bg-purple-500/20 border-purple-500/30', color: 'text-purple-400' },
  teams:     { label: 'Microsoft Teams',  icon: '🟦', bg: 'bg-blue-500/20 border-blue-500/30',    color: 'text-blue-400'   },
  pagerduty: { label: 'PagerDuty',        icon: '🔔', bg: 'bg-green-500/20 border-green-500/30',  color: 'text-green-400'  },
  generic:   { label: 'Generic Webhook',  icon: '🔗', bg: 'bg-gray-500/20 border-gray-500/30',    color: 'text-gray-400'   },
}

const EXAMPLE_PAYLOAD = JSON.stringify({
  event: 'alert.created',
  timestamp: new Date().toISOString(),
  alert: { id: 'a-001', title: 'Suspicious process execution', severity: 'high', agent_id: 'ag-001' }
}, null, 2)

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtRelative(iso?: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'たった今'
  if (mins < 60) return `${mins}分前`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}時間前`
  return `${Math.floor(hrs / 24)}日前`
}

function truncateUrl(url: string, max = 50): string {
  return url.length > max ? url.slice(0, max) + '...' : url
}

// ── Add Webhook Modal ──────────────────────────────────────────────────────────

interface AddWebhookModalProps {
  onClose: () => void
  onSuccess: () => void
}

function AddWebhookModal({ onClose, onSuccess }: AddWebhookModalProps) {
  const [form, setForm] = useState({
    name: '',
    platform: 'generic' as Webhook['platform'],
    url: '',
    secret: '',
    retry_count: 3,
    events: [] as string[],
  })
  const [saving, setSaving] = useState(false)
  const { persist, saveError } = usePersist()
  const [error, setError] = useState('')

  function toggleEvent(ev: string) {
    setForm(f => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter(e => e !== ev) : [...f.events, ev],
    }))
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!form.name || !form.url || form.events.length === 0) {
      setError('名前、URL、イベントを1つ以上選択してください')
      return
    }
    setSaving(true)
    setError('')
    const ok = await persist('Webhook', '/api/v1/admin/webhooks', { method: 'POST', body: JSON.stringify(form) })
    setSaving(false)
    if (ok) onSuccess()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-lg mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-700">
          <h2 className="text-lg font-semibold text-zinc-100">Webhook追加</h2>
          <button onClick={onClose} className="text-zinc-400 hover:text-zinc-200 transition-colors"><X className="h-5 w-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && <div className="text-red-400 text-sm bg-red-900/20 border border-red-700/40 rounded-sm px-3 py-2">{error}</div>}
          <SaveFailed error={saveError} />

          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs text-zinc-400 mb-1">名前</label>
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500" placeholder="マイWebhook" />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">プラットフォーム</label>
              <select value={form.platform} onChange={e => setForm(f => ({ ...f, platform: e.target.value as Webhook['platform'] }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500">
                <option value="slack">Slack</option>
                <option value="teams">MS Teams</option>
                <option value="pagerduty">PagerDuty</option>
                <option value="generic">Generic</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">リトライ回数</label>
              <select value={form.retry_count} onChange={e => setForm(f => ({ ...f, retry_count: Number(e.target.value) }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500">
                {[1,2,3,4,5].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div className="col-span-2">
              <label className="block text-xs text-zinc-400 mb-1">URL</label>
              <input value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500 font-mono" placeholder="https://hooks.example.com/..." />
            </div>
            <div className="col-span-2">
              <label className="block text-xs text-zinc-400 mb-1">シークレット（任意）</label>
              <input value={form.secret} onChange={e => setForm(f => ({ ...f, secret: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500" placeholder="HMAC署名シークレット" />
            </div>
          </div>

          <div>
            <label className="block text-xs text-zinc-400 mb-2">イベント</label>
            <div className="grid grid-cols-2 gap-2">
              {ALL_EVENTS.map(ev => (
                <label key={ev} className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={form.events.includes(ev)} onChange={() => toggleEvent(ev)}
                    className="accent-blue-500" />
                  <span className="text-xs text-zinc-300 font-mono">{ev}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors">キャンセル</button>
            <button type="submit" disabled={saving}
              className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center gap-2">
              {saving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              {saving ? '追加中...' : 'Webhook追加'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Webhook Card ───────────────────────────────────────────────────────────────

interface WebhookCardProps {
  webhook: Webhook
  onToggle: (id: string, enabled: boolean) => void
  onTest: (id: string) => void
  onDelete: (id: string) => void
  testing: boolean
}

function WebhookCard({ webhook, onToggle, onTest, onDelete, testing }: WebhookCardProps) {
  const [expanded, setExpanded] = useState(false)
  const plat = PLATFORM_STYLES[webhook.platform] ?? PLATFORM_STYLES.generic
  const successRate = webhook.delivery_count > 0
    ? (((webhook.delivery_count - webhook.failure_count) / webhook.delivery_count) * 100).toFixed(1)
    : '0.0'

  return (
    <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
      <div className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium shrink-0 ${plat.color}`}>{plat.label}</span>
            <div className="min-w-0">
              <div className="font-medium text-zinc-100">{webhook.name}</div>
              <div className="text-xs text-zinc-500 font-mono truncate mt-0.5">{truncateUrl(webhook.url)}</div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {/* Status dot */}
            {webhook.last_delivery_status === 'success'
              ? <span className="h-2 w-2 rounded-full bg-green-500" title="Last delivery succeeded" />
              : webhook.last_delivery_status === 'failed'
              ? <span className="h-2 w-2 rounded-full bg-red-500" title="Last delivery failed" />
              : <span className="h-2 w-2 rounded-full bg-zinc-600" title="No deliveries yet" />
            }
            <button onClick={() => onToggle(webhook.id, !webhook.enabled)}
              className="text-zinc-400 hover:text-zinc-200 transition-colors" title={webhook.enabled ? 'Disable' : 'Enable'}>
              {webhook.enabled ? <ToggleRight className="h-6 w-6 text-green-400" /> : <ToggleLeft className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Events */}
        <div className="flex flex-wrap gap-1.5 mt-3">
          {webhook.events.map(ev => (
            <span key={ev} className="text-xs font-mono px-2 py-0.5 rounded-sm bg-zinc-800 text-zinc-400 border border-zinc-700">{ev}</span>
          ))}
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-6 mt-3 text-xs text-zinc-500">
          <span className="flex items-center gap-1"><Activity className="h-3 w-3" />{webhook.delivery_count} 配信</span>
          <span className="flex items-center gap-1">
            {parseFloat(successRate) >= 95
              ? <TrendingUp className="h-3 w-3 text-green-400" />
              : <TrendingDown className="h-3 w-3 text-red-400" />
            }
            {successRate}% 成功率
          </span>
          {webhook.failure_count > 0 && <span className="text-red-400 flex items-center gap-1"><XCircle className="h-3 w-3" />{webhook.failure_count} 失敗</span>}
          <span className="flex items-center gap-1"><Clock className="h-3 w-3" />最終: {fmtRelative(webhook.last_delivery_at)}</span>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 mt-4 pt-4 border-t border-zinc-800">
          <button onClick={() => onTest(webhook.id)} disabled={testing || !webhook.enabled}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-blue-600/20 text-blue-300 border border-blue-700/40 rounded-lg hover:bg-blue-600/30 disabled:opacity-40 transition-colors">
            {testing ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Send className="h-3 w-3" />}
            テスト
          </button>
          <button onClick={() => setExpanded(v => !v)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-zinc-800 text-zinc-300 border border-zinc-700 rounded-lg hover:bg-zinc-700 transition-colors">
            {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            配信履歴
          </button>
          <div className="flex-1" />
          <button onClick={() => onDelete(webhook.id)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-400 border border-red-700/40 rounded-lg hover:bg-red-900/20 transition-colors">
            <Trash2 className="h-3 w-3" />削除
          </button>
        </div>
      </div>

      {/* Deliveries panel */}
      {expanded && (
        <div className="border-t border-zinc-800 bg-zinc-950/50">
          <div className="px-5 py-3">
            <div className="text-xs text-zinc-500 font-medium mb-2">最近の配信</div>
            {(!webhook.recent_deliveries || webhook.recent_deliveries.length === 0) ? (
              <div className="text-xs text-zinc-600 italic">配信記録なし</div>
            ) : (
              <div className="space-y-1.5">
                {webhook.recent_deliveries.map(d => (
                  <div key={d.id} className="flex items-center gap-3 text-xs">
                    {d.status === 'success'
                      ? <CheckCircle className="h-3.5 w-3.5 text-green-400 shrink-0" />
                      : <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                    }
                    <span className="font-mono text-zinc-400 w-16 text-right shrink-0">{d.status_code}</span>
                    <span className="font-mono text-zinc-500 shrink-0">{d.event_type}</span>
                    {d.duration_ms && <span className="text-zinc-600">{d.duration_ms}ms</span>}
                    <span className="text-zinc-600 ml-auto">{fmtRelative(d.delivered_at)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function WebhooksPage() {
  const qc = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [showPayload, setShowPayload] = useState(false)
  const [copied, setCopied] = useState(false)

  const { data: webhooks = [] } = useQuery<Webhook[]>({
    queryKey: ['admin-webhooks'],
    queryFn: () => apiFetchList<Webhook>('/api/v1/admin/webhooks'),
  })

  const EMPTY_STATS: WebhookStats = { active: 0, deliveries_24h: 0, success_rate: 0, failed_24h: 0 }
  const { data: stats = EMPTY_STATS } = useQuery<WebhookStats>({
    queryKey: ['admin-webhooks-stats'],
    queryFn: () => apiFetch('/api/v1/admin/webhooks/stats'),
  })

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      // .catch(() => {}) が失敗を成功に変えていました。Webhook は外部への
      // 通知経路なので、止めたつもりが止まっていない／動かしたつもりが
      // 動いていない、どちらも気づく手がかりがありません。
      apiFetch(`/api/v1/admin/webhooks/${id}`, { method: 'PUT', body: JSON.stringify({ enabled }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-webhooks'] }),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/webhooks/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-webhooks'] }),
  })

  const testMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/webhooks/${id}/test`, { method: 'POST' }),
  })

  async function handleTest(id: string) {
    setTestingId(id)
    try { await testMut.mutateAsync(id) } catch { /* testMut.error に出ます */ }
    setTestingId(null)
  }

  function handleCopyPayload() {
    navigator.clipboard.writeText(EXAMPLE_PAYLOAD).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const STATS_CARDS = [
    { label: 'アクティブ Webhook', value: stats.active, icon: Bell, color: 'text-blue-400' },
    { label: '配信数（24時間）', value: stats.deliveries_24h, icon: Activity, color: 'text-green-400' },
    { label: '成功率', value: `${stats.success_rate}%`, icon: TrendingUp, color: 'text-emerald-400' },
    { label: '失敗数（24時間）', value: stats.failed_24h, icon: AlertTriangle, color: 'text-red-400' },
  ]

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <PageDataUnavailable />
      <SaveFailed error={saveErrorOf('Webhook', toggleMut, deleteMut, testMut)} />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-blue-900/40 border border-blue-700/40 flex items-center justify-center">
            <Bell className="h-5 w-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Webhook通知</h1>
            <p className="text-sm text-zinc-400">セキュリティイベントをリアルタイムで外部プラットフォームに通知します</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowPayload(v => !v)}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg hover:bg-zinc-700 transition-colors text-zinc-300">
            <Globe className="h-4 w-4" />
            ペイロード{showPayload ? '非表示' : '表示'}
          </button>
          <button onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors font-medium">
            <Plus className="h-4 w-4" />
            Webhook追加
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {STATS_CARDS.map(s => (
          <div key={s.label} className="bg-zinc-900 border border-zinc-700 rounded-xl p-4 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-zinc-800 flex items-center justify-center">
              <s.icon className={`h-5 w-5 ${s.color}`} />
            </div>
            <div>
              <div className="text-2xl font-bold text-zinc-100">{s.value}</div>
              <div className="text-xs text-zinc-500">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="flex gap-6">
        {/* Webhook Cards */}
        <div className="flex-1 space-y-4">
          {webhooks.length === 0 ? (
            <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-12 text-center">
              <Bell className="h-12 w-12 text-zinc-700 mx-auto mb-3" />
              <p className="text-zinc-500">Webhookが設定されていません。</p>
              <button onClick={() => setShowAdd(true)}
                className="mt-4 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors">
                最初のWebhookを追加
              </button>
            </div>
          ) : (
            webhooks.map(wh => (
              <WebhookCard
                key={wh.id}
                webhook={wh}
                onToggle={(id, enabled) => toggleMut.mutate({ id, enabled })}
                onTest={handleTest}
                onDelete={id => { if (confirm('このWebhookを削除しますか？')) deleteMut.mutate(id) }}
                testing={testingId === wh.id}
              />
            ))
          )}
        </div>

        {/* Event Format Preview Panel */}
        {showPayload && (
          <div className="w-80 shrink-0">
            <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden sticky top-6">
              <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-700">
                <span className="text-sm font-medium text-zinc-200 flex items-center gap-2">
                  <Zap className="h-4 w-4 text-yellow-400" />
                  ペイロード例
                </span>
                <button onClick={handleCopyPayload}
                  className="text-xs text-zinc-400 hover:text-zinc-200 flex items-center gap-1 transition-colors">
                  {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                  {copied ? 'コピーしました' : 'コピー'}
                </button>
              </div>
              <pre className="p-4 text-xs font-mono text-zinc-400 overflow-x-auto leading-relaxed">
                {EXAMPLE_PAYLOAD}
              </pre>
            </div>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAdd && (
        <AddWebhookModal
          onClose={() => setShowAdd(false)}
          onSuccess={() => { setShowAdd(false); qc.invalidateQueries({ queryKey: ['admin-webhooks'] }) }}
        />
      )}
    </div>
  )
}
