'use client'

import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { format, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import { Bell, Plus, Trash2, TestTube, Mail, MessageSquare, Webhook, Users, Pencil, X, ToggleLeft, ToggleRight, History, CheckCircle2, XCircle, BarChart3, RefreshCw } from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface NotifChannel {
  id: string
  name: string
  type: 'email' | 'slack' | 'webhook' | 'teams'
  config: Record<string, string>
  enabled: boolean
  min_severity: number
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  email:   Mail,
  slack:   MessageSquare,
  webhook: Webhook,
  teams:   Users,
}

const TYPE_LABELS: Record<string, string> = {
  email:   'メール',
  slack:   'Slack',
  webhook: 'Webhook',
  teams:   'Microsoft Teams',
}

const CONFIG_FIELDS: Record<string, Array<{ key: string; label: string; placeholder: string; type?: string }>> = {
  email: [
    { key: 'smtp_host',      label: 'SMTPサーバー', placeholder: 'smtp.example.com' },
    { key: 'smtp_port',      label: 'SMTPポート',   placeholder: '587' },
    { key: 'username',       label: 'ユーザー名',   placeholder: 'user@example.com' },
    { key: 'password',       label: 'パスワード',   placeholder: '••••••••', type: 'password' },
    { key: 'from',           label: '送信元アドレス', placeholder: 'edr@example.com' },
    { key: 'recipients',     label: '送信先アドレス（カンマ区切り）', placeholder: 'soc@example.com,team@example.com' },
    { key: 'sender_name',    label: '送信者名',     placeholder: 'EDR Platform' },
    { key: 'subject_prefix', label: '件名プレフィックス', placeholder: '例: [KizashiEDR] / [自社名 Security]' },
    { key: 'test_subject',   label: 'テスト通知の件名（任意）', placeholder: '未入力の場合: プレフィックス + テスト通知' },
    { key: 'test_body',      label: 'テスト通知の本文（任意・HTML可）', placeholder: '例:\nセキュリティ監視システムからのテスト通知です。\n\n対応手順は <a href="https://example.com/runbook">運用マニュアル</a> を参照してください。\nお問い合わせ: <a href="mailto:soc@example.com">SOCチーム</a>', type: 'textarea' },
  ],
  slack: [
    { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/...' },
    { key: 'channel',     label: 'チャンネル',  placeholder: '#security-alerts' },
  ],
  webhook: [
    { key: 'url',     label: 'エンドポイントURL', placeholder: 'https://your-siem.example.com/webhook' },
    { key: 'secret',  label: 'シークレット',       placeholder: 'HMACシークレット（任意）' },
    { key: 'method',  label: 'HTTPメソッド',        placeholder: 'POST' },
  ],
  teams: [
    { key: 'webhook_url', label: 'Incoming Webhook URL', placeholder: 'https://outlook.office.com/webhook/...' },
  ],
}

interface NotifHistoryEntry {
  id: string
  channel_name: string
  channel_type: string
  subject: string
  status: string
  error?: string
  sent_at: string
}

interface NotifStats {
  sent: number
  failed: number
  by_channel: { name: string; count: number }[]
}

type EmailTemplate = 'alert' | 'digest' | 'onboarding'

const EMAIL_TEMPLATES: { value: EmailTemplate; label: string; description: string }[] = [
  { value: 'alert',      label: 'アラート通知',    description: 'セキュリティアラートのHTML通知メール' },
  { value: 'digest',     label: 'ウィークリーサマリー', description: '週次セキュリティダイジェストメール' },
  { value: 'onboarding', label: 'ウェルカムメール', description: '新規ユーザー向けオンボーディングメール' },
]

function TestEmailModal({ onClose }: { onClose: () => void }) {
  const [to, setTo] = useState('')
  const [template, setTemplate] = useState<EmailTemplate>('alert')
  const [status, setStatus] = useState<'idle' | 'sending' | 'success' | 'error'>('idle')
  const [errorMsg, setErrorMsg] = useState('')

  const send = useMutation<{ ok: boolean; error?: string }, Error, void>({
    mutationFn: () => apiFetch('/api/v1/admin/notifications/test-email', {
      method: 'POST',
      body: JSON.stringify({ to, template }),
    }) as Promise<{ ok: boolean; error?: string }>,
    onMutate: () => { setStatus('sending'); setErrorMsg('') },
    onSuccess: (res: { ok: boolean; error?: string }) => {
      if (res.ok) {
        setStatus('success')
      } else {
        setStatus('error')
        setErrorMsg(res.error ?? '送信失敗')
      }
    },
    onError: (e: Error) => { setStatus('error'); setErrorMsg(e.message) },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1e2d42] rounded-2xl p-6 w-full max-w-md shadow-2xl space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Mail className="w-5 h-5 text-blue-400" />
            <h2 className="text-white font-semibold">テストメール送信</h2>
          </div>
          <button onClick={onClose} className="text-[#5a6a7a] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Recipient */}
        <div className="space-y-1.5">
          <label className="text-xs text-[#8899aa]">送信先メールアドレス</label>
          <input
            type="email"
            value={to}
            onChange={e => setTo(e.target.value)}
            placeholder="recipient@example.com"
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-white text-sm focus:outline-hidden focus:border-blue-500 transition-colors"
          />
        </div>

        {/* Template selector */}
        <div className="space-y-2">
          <label className="text-xs text-[#8899aa]">テンプレート</label>
          <div className="space-y-2">
            {EMAIL_TEMPLATES.map(t => (
              <label
                key={t.value}
                className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                  template === t.value
                    ? 'border-blue-500/60 bg-blue-900/10'
                    : 'border-[#1e2d42] hover:border-[#2a3d5a]'
                }`}
              >
                <input
                  type="radio"
                  name="template"
                  value={t.value}
                  checked={template === t.value}
                  onChange={() => setTemplate(t.value)}
                  className="mt-0.5 accent-blue-500"
                />
                <div>
                  <p className="text-sm text-white font-medium">{t.label}</p>
                  <p className="text-xs text-[#5a6a7a] mt-0.5">{t.description}</p>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Status */}
        {status === 'success' && (
          <div className="flex items-center gap-2 px-3 py-2 bg-green-900/20 border border-green-700/40 rounded-lg">
            <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
            <span className="text-sm text-green-300">テストメールを送信しました</span>
          </div>
        )}
        {status === 'error' && (
          <div className="flex items-center gap-2 px-3 py-2 bg-red-900/20 border border-red-700/40 rounded-lg">
            <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span className="text-sm text-red-300">{errorMsg || '送信に失敗しました'}</span>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-2 pt-1">
          <button
            onClick={() => send.mutate()}
            disabled={!to || status === 'sending'}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-blue-700 hover:bg-blue-600 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-xl transition-colors"
          >
            {status === 'sending' ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                送信中...
              </>
            ) : (
              <>
                <TestTube className="w-4 h-4" />
                送信する
              </>
            )}
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2.5 bg-[#161f33] hover:bg-[#1d2f4a] border border-[#1e2d42] text-[#8899aa] text-sm rounded-xl transition-colors"
          >
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

export default function NotificationsPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()
  const [activeTab, setActiveTab] = useState<'channels' | 'history'>('channels')
  const [showForm, setShowForm] = useState(false)
  const [showTestEmailModal, setShowTestEmailModal] = useState(false)
  const [testResult, setTestResult] = useState<Record<string, string>>({})
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editForm, setEditForm] = useState<NotifChannel | null>(null)

  const [form, setForm] = useState<Omit<NotifChannel, 'id'>>({
    name: '',
    type: 'slack',
    config: {},
    enabled: true,
    min_severity: 7,
  })

  const { data, isLoading } = useQuery<{ data: NotifChannel[] }>({
    queryKey: ['notif-channels'],
    queryFn: () => apiFetch('/api/v1/notifications/channels'),
  })

  const create = useMutation({
    mutationFn: (payload: Omit<NotifChannel, 'id'>) =>
      apiFetch('/api/v1/notifications/channels', { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['notif-channels'] })
      setShowForm(false)
      setForm({ name: '', type: 'slack', config: {}, enabled: true, min_severity: 7 })
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/notifications/channels/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['notif-channels'] }),
  })

  const update = useMutation({
    mutationFn: (ch: NotifChannel) =>
      apiFetch(`/api/v1/notifications/channels/${ch.id}`, {
        method: 'PUT',
        body: JSON.stringify(ch),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['notif-channels'] })
      setEditingId(null)
      setEditForm(null)
    },
  })

  const test = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/notifications/channels/${id}/test`, { method: 'POST' }),
    onSuccess: (_, id) => setTestResult(prev => ({ ...prev, [id]: 'success' })),
    onError: (_, id) => setTestResult(prev => ({ ...prev, [id]: 'error' })),
  })

  const { data: historyData } = useQuery<{ data: NotifHistoryEntry[]; total: number }>({
    queryKey: ['notif-history'],
    queryFn: () => apiFetch('/api/v1/notification-history?per_page=100'),
    enabled: activeTab === 'history',
    refetchInterval: 30_000,
  })

  const { data: statsData } = useQuery<NotifStats>({
    queryKey: ['notif-history-stats'],
    queryFn: () => apiFetch('/api/v1/notification-history/stats?days=7'),
    enabled: activeTab === 'history',
  })

  const channels = data?.data ?? []

  const setConfig = (key: string, value: string) =>
    setForm(prev => ({ ...prev, config: { ...prev.config, [key]: value } }))

  const setEditConfig = (key: string, value: string) =>
    setEditForm(prev => prev ? ({ ...prev, config: { ...prev.config, [key]: value } }) : prev)

  const startEdit = (channel: NotifChannel) => {
    setEditingId(channel.id)
    setEditForm({ ...channel, config: { ...channel.config } })
    setShowForm(false)
  }

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {showTestEmailModal && <TestEmailModal onClose={() => setShowTestEmailModal(false)} />}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">通知設定</h1>
          <p className="text-[#8899aa] text-sm mt-1">アラート通知チャンネルの管理</p>
        </div>
        <div className="flex items-center gap-2">
          {canWrite && (
            <button
              onClick={() => setShowTestEmailModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#161f33] hover:bg-[#1d2f4a] border border-[#1e2d42] text-[#8899aa] hover:text-white text-sm rounded-lg transition-colors"
            >
              <TestTube className="w-4 h-4" />
              テストメール
            </button>
          )}
          {canWrite && activeTab === 'channels' && (
            <button
              onClick={() => setShowForm(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              チャンネルを追加
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#1e2d42] flex gap-0">
        {([['channels','チャンネル設定',Bell], ['history','送信履歴',History]] as const).map(([id, label, Icon]) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm border-b-2 -mb-px transition-colors ${
              activeTab === id ? 'border-blue-500 text-white' : 'border-transparent text-[#8899aa] hover:text-white'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* History tab */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          {/* Stats */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-3">
              <div className="w-9 h-9 bg-[#1a6bff] rounded-lg flex items-center justify-center">
                <BarChart3 className="w-5 h-5 text-white" />
              </div>
              <div>
                <p className="text-xs text-[#8899aa]">7日間 送信数</p>
                <p className="text-2xl font-bold text-white">{(statsData?.sent ?? 0) + (statsData?.failed ?? 0)}</p>
              </div>
            </div>
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-3">
              <div className="w-9 h-9 bg-green-600 rounded-lg flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5 text-white" />
              </div>
              <div>
                <p className="text-xs text-[#8899aa]">送信成功</p>
                <p className="text-2xl font-bold text-white">{statsData?.sent ?? 0}</p>
              </div>
            </div>
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-3">
              <div className="w-9 h-9 bg-[#e8002d] rounded-lg flex items-center justify-center">
                <XCircle className="w-5 h-5 text-white" />
              </div>
              <div>
                <p className="text-xs text-[#8899aa]">送信失敗</p>
                <p className="text-2xl font-bold text-white">{statsData?.failed ?? 0}</p>
              </div>
            </div>
          </div>

          {/* History table */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            <div className="px-5 py-3 border-b border-[#1e2d42] text-xs text-[#8899aa] font-semibold">
              送信履歴（直近100件）
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa]">
                    <th className="px-4 py-3 text-left">日時</th>
                    <th className="px-4 py-3 text-left">チャンネル</th>
                    <th className="px-4 py-3 text-left">件名</th>
                    <th className="px-4 py-3 text-left">結果</th>
                  </tr>
                </thead>
                <tbody>
                  {(historyData?.data ?? []).length === 0 ? (
                    <tr><td colSpan={4} className="px-4 py-10 text-center text-[#5a6a7a]">送信履歴はありません</td></tr>
                  ) : (historyData?.data ?? []).map(e => (
                    <tr key={e.id} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/30">
                      <td className="px-4 py-2.5 text-[#8899aa] font-mono text-xs whitespace-nowrap">
                        {e.sent_at ? format(parseISO(e.sent_at), 'MM/dd HH:mm:ss', { locale: ja }) : '-'}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="text-[#8899aa] text-xs">{e.channel_name}</span>
                        <span className="ml-2 text-xs text-[#5a6a7a] bg-[#161f33] px-1.5 py-0.5 rounded-sm">{e.channel_type}</span>
                      </td>
                      <td className="px-4 py-2.5 text-[#e2e8f4] text-xs max-w-xs truncate">{e.subject || '-'}</td>
                      <td className="px-4 py-2.5">
                        {e.status === 'sent' ? (
                          <span className="flex items-center gap-1 text-green-400 text-xs">
                            <CheckCircle2 className="w-3.5 h-3.5" />成功
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-red-400 text-xs" title={e.error}>
                            <XCircle className="w-3.5 h-3.5" />失敗
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Channels list */}
      {activeTab === 'channels' && isLoading ? (
        <div className="flex items-center justify-center py-16">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-blue-500" />
        </div>
      ) : channels.length === 0 && !showForm ? (
        <div className="text-center py-16 bg-[#111827] rounded-xl border border-[#1e2d42]">
          <Bell className="w-12 h-12 mx-auto mb-3 text-[#5a6a7a]" />
          <p className="text-[#8899aa]">通知チャンネルが設定されていません</p>
          {canWrite && (
            <button
              onClick={() => setShowForm(true)}
              className="mt-4 text-blue-400 hover:underline text-sm"
            >
              最初のチャンネルを追加
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {channels.map(channel => {
            const Icon = TYPE_ICONS[channel.type] ?? Bell
            const result = testResult[channel.id]
            const isEditing = editingId === channel.id && editForm

            if (isEditing && editForm) {
              return (
                <div key={channel.id} className="bg-[#111827] rounded-xl border border-blue-700 p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-white font-semibold text-sm">チャンネルを編集</h3>
                    <button onClick={() => { setEditingId(null); setEditForm(null) }}
                      className="text-[#8899aa] hover:text-[#e2e8f4]"><X className="w-4 h-4" /></button>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[#8899aa] text-xs mb-1.5">チャンネル名</label>
                      <input
                        value={editForm.name}
                        onChange={e => setEditForm(p => p ? { ...p, name: e.target.value } : p)}
                        className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-[#8899aa] text-xs mb-1.5">最低重大度</label>
                      <input
                        type="number" min={1} max={10}
                        value={editForm.min_severity}
                        onChange={e => setEditForm(p => p ? { ...p, min_severity: parseInt(e.target.value) } : p)}
                        className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    {(CONFIG_FIELDS[editForm.type] ?? []).map(field => (
                      <div key={field.key} className={field.type === 'textarea' ? 'col-span-2' : ''}>
                        <label className="block text-[#8899aa] text-xs mb-1.5">{field.label}</label>
                        {field.type === 'textarea' ? (
                          <textarea
                            placeholder={field.placeholder}
                            value={editForm.config[field.key] ?? ''}
                            onChange={e => setEditConfig(field.key, e.target.value)}
                            rows={4}
                            className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm resize-y"
                          />
                        ) : (
                          <input
                            type={field.type ?? 'text'}
                            placeholder={field.placeholder}
                            value={editForm.config[field.key] ?? ''}
                            onChange={e => setEditConfig(field.key, e.target.value)}
                            className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm"
                          />
                        )}
                      </div>
                    ))}
                  </div>

                  <div className="flex items-center gap-3">
                    <label className="flex items-center gap-2 cursor-pointer select-none">
                      <button
                        onClick={() => setEditForm(p => p ? { ...p, enabled: !p.enabled } : p)}
                        className={editForm.enabled ? 'text-blue-400' : 'text-[#5a6a7a]'}
                      >
                        {editForm.enabled
                          ? <ToggleRight className="w-6 h-6" />
                          : <ToggleLeft  className="w-6 h-6" />}
                      </button>
                      <span className="text-sm text-[#8899aa]">
                        {editForm.enabled ? '有効' : '無効'}
                      </span>
                    </label>
                    <div className="flex gap-2 ml-auto">
                      <button
                        onClick={() => update.mutate(editForm)}
                        disabled={update.isPending || !editForm.name}
                        className="px-4 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm rounded-lg disabled:opacity-50"
                      >
                        {update.isPending ? '保存中...' : '保存'}
                      </button>
                      <button
                        onClick={() => { setEditingId(null); setEditForm(null) }}
                        className="px-4 py-2 bg-[#161f33] hover:bg-[#1d2f4a] text-white text-sm rounded-lg"
                      >
                        キャンセル
                      </button>
                    </div>
                  </div>
                </div>
              )
            }

            return (
              <div key={channel.id}
                className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 flex items-center justify-between"
              >
                <div className="flex items-center gap-4">
                  <div className={`p-2 rounded-lg ${channel.enabled ? 'bg-blue-900/30' : 'bg-[#161f33]'}`}>
                    <Icon className={`w-5 h-5 ${channel.enabled ? 'text-blue-400' : 'text-[#5a6a7a]'}`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-white font-medium text-sm">{channel.name}</p>
                      <span className="text-xs px-2 py-0.5 bg-[#161f33] text-[#8899aa] rounded-sm">
                        {TYPE_LABELS[channel.type]}
                      </span>
                      {!channel.enabled && (
                        <span className="text-xs px-2 py-0.5 bg-[#161f33] text-[#5a6a7a] rounded-sm">無効</span>
                      )}
                    </div>
                    <p className="text-[#8899aa] text-xs mt-0.5">
                      重大度 {channel.min_severity} 以上のアラートで通知
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {result && (
                    <span className={`text-xs px-2 py-1 rounded-sm ${
                      result === 'success' ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
                    }`}>
                      {result === 'success' ? '送信成功' : '送信失敗'}
                    </span>
                  )}
                  <button
                    onClick={() => test.mutate(channel.id)}
                    disabled={test.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[#161f33] hover:bg-[#1d2f4a] text-[#8899aa] text-xs rounded-lg transition-colors"
                  >
                    <TestTube className="w-3.5 h-3.5" />
                    テスト
                  </button>
                  {canWrite && (
                    <button
                      onClick={() => startEdit(channel)}
                      className="p-1.5 text-[#5a6a7a] hover:text-blue-400 transition-colors"
                      title="編集"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                  )}
                  {canWrite && (
                    <button
                      onClick={() => { if (confirm('このチャンネルを削除しますか？')) remove.mutate(channel.id) }}
                      className="p-1.5 text-[#5a6a7a] hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Create form */}
      {showForm && (
        <div className="bg-[#111827] rounded-xl border border-blue-700 p-5 space-y-4">
          <h2 className="text-white font-semibold text-sm">新しい通知チャンネル</h2>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#8899aa] text-xs mb-1.5">チャンネル名</label>
              <input
                value={form.name}
                onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                placeholder="例: SOCチーム Slack"
                className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-[#8899aa] text-xs mb-1.5">種類</label>
              <select
                value={form.type}
                onChange={e => setForm(p => ({ ...p, type: e.target.value as NotifChannel['type'], config: {} }))}
                className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm"
              >
                {Object.entries(TYPE_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[#8899aa] text-xs mb-1.5">最低重大度（1-10）</label>
            <input
              type="number"
              min={1}
              max={10}
              value={form.min_severity}
              onChange={e => setForm(p => ({ ...p, min_severity: parseInt(e.target.value) }))}
              className="w-24 px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm"
            />
          </div>

          {/* Type-specific config fields */}
          <div className="grid grid-cols-2 gap-3">
            {(CONFIG_FIELDS[form.type] ?? []).map(field => (
              <div key={field.key} className={field.type === 'textarea' ? 'col-span-2' : ''}>
                <label className="block text-[#8899aa] text-xs mb-1.5">{field.label}</label>
                {field.type === 'textarea' ? (
                  <textarea
                    placeholder={field.placeholder}
                    value={form.config[field.key] ?? ''}
                    onChange={e => setConfig(field.key, e.target.value)}
                    rows={4}
                    className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm resize-y"
                  />
                ) : (
                  <input
                    type={field.type ?? 'text'}
                    placeholder={field.placeholder}
                    value={form.config[field.key] ?? ''}
                    onChange={e => setConfig(field.key, e.target.value)}
                    className="w-full px-3 py-2 bg-[#161f33] border border-[#1e2d42] rounded-lg text-white text-sm"
                  />
                )}
              </div>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => create.mutate(form)}
              disabled={create.isPending || !form.name}
              className="px-4 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm rounded-lg disabled:opacity-50"
            >
              作成
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="px-4 py-2 bg-[#161f33] hover:bg-[#1d2f4a] text-white text-sm rounded-lg"
            >
              キャンセル
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
