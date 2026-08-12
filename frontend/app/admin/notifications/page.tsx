'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Bell,
  MessageSquare,
  Users,
  Globe,
  Mail,
  Plus,
  Pencil,
  Trash2,
  Send,
  X,
  CheckCircle,
  AlertCircle,
} from 'lucide-react'

// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface NotifChannel {
  id: string
  name: string
  type: 'webhook_slack' | 'webhook_teams' | 'webhook_generic' | 'email' | 'webhook_pagerduty'
  config: Record<string, string>
  enabled: boolean
  created_at: string
  updated_at: string
}

interface ChannelListResponse {
  channels: NotifChannel[]
}

type ChannelType = NotifChannel['type']

interface FormState {
  name: string
  type: ChannelType
  enabled: boolean
  // webhook fields
  webhook_url: string
  auth_header: string
  // pagerduty fields
  integration_key: string
  // email fields
  smtp_host: string
  smtp_port: string
  smtp_username: string
  smtp_password: string
  from_address: string
  to_address: string
}

interface TestResult {
  channelId: string
  success: boolean
  message: string
}

// ─── 定数 ────────────────────────────────────────────────────────────────────

const CHANNEL_TYPES: { value: ChannelType; label: string }[] = [
  { value: 'webhook_slack',      label: 'Slack Webhook' },
  { value: 'webhook_teams',      label: 'Microsoft Teams' },
  { value: 'webhook_pagerduty',  label: 'PagerDuty' },
  { value: 'webhook_generic',    label: 'Generic Webhook' },
  { value: 'email',              label: 'メール (SMTP)' },
]

const DEFAULT_FORM: FormState = {
  name: '',
  type: 'webhook_slack',
  enabled: true,
  webhook_url: '',
  auth_header: '',
  integration_key: '',
  smtp_host: '',
  smtp_port: '587',
  smtp_username: '',
  smtp_password: '',
  from_address: '',
  to_address: '',
}

// ─── ユーティリティ ──────────────────────────────────────────────────────────

function typeIcon(type: ChannelType, className: string) {
  switch (type) {
    case 'webhook_slack':      return <MessageSquare className={className} />
    case 'webhook_teams':      return <Users className={className} />
    case 'webhook_pagerduty':  return <Bell className={className} />
    case 'webhook_generic':    return <Globe className={className} />
    case 'email':              return <Mail className={className} />
  }
}

function typeIconColor(type: ChannelType): string {
  switch (type) {
    case 'webhook_slack':      return 'text-orange-400'
    case 'webhook_teams':      return 'text-purple-400'
    case 'webhook_pagerduty':  return 'text-green-400'
    case 'webhook_generic':    return 'text-blue-400'
    case 'email':              return 'text-emerald-400'
  }
}

function typeBadgeStyle(type: ChannelType): string {
  switch (type) {
    case 'webhook_slack':      return 'bg-orange-900/40 text-orange-300 border-orange-800/50'
    case 'webhook_teams':      return 'bg-purple-900/40 text-purple-300 border-purple-800/50'
    case 'webhook_pagerduty':  return 'bg-green-900/40 text-green-300 border-green-800/50'
    case 'webhook_generic':    return 'bg-blue-900/40 text-blue-300 border-blue-800/50'
    case 'email':              return 'bg-emerald-900/40 text-emerald-300 border-emerald-800/50'
  }
}

function typeLabel(type: ChannelType): string {
  return CHANNEL_TYPES.find(t => t.value === type)?.label ?? type
}

function configPreview(channel: NotifChannel): string {
  if (channel.type === 'email') {
    return channel.config.to_address ? `宛先: ${channel.config.to_address}` : '—'
  }
  if (channel.type === 'webhook_pagerduty') {
    const key = channel.config.integration_key ?? ''
    return key ? `Key: ${key.slice(0, 8)}••••` : '—'
  }
  const url = channel.config.webhook_url ?? ''
  if (!url) return '—'
  if (url.length <= 48) return url
  return url.slice(0, 24) + '…' + url.slice(-16)
}

function buildConfig(form: FormState): Record<string, string> {
  if (form.type === 'email') {
    const cfg: Record<string, string> = {
      smtp_host:    form.smtp_host,
      smtp_port:    form.smtp_port,
      smtp_username: form.smtp_username,
      from_address: form.from_address,
      to_address:   form.to_address,
    }
    if (form.smtp_password) cfg.smtp_password = form.smtp_password
    return cfg
  }
  if (form.type === 'webhook_pagerduty') {
    return { integration_key: form.integration_key }
  }
  const cfg: Record<string, string> = { webhook_url: form.webhook_url }
  if (form.type === 'webhook_generic' && form.auth_header) {
    cfg.auth_header = form.auth_header
  }
  return cfg
}

function formFromChannel(ch: NotifChannel): FormState {
  const c = ch.config
  return {
    name: ch.name,
    type: ch.type,
    enabled: ch.enabled,
    webhook_url:     c.webhook_url     ?? '',
    auth_header:     c.auth_header     ?? '',
    integration_key: c.integration_key ?? '',
    smtp_host:       c.smtp_host       ?? '',
    smtp_port:       c.smtp_port       ?? '587',
    smtp_username:   c.smtp_username   ?? '',
    smtp_password:   '',  // never pre-fill password
    from_address:    c.from_address    ?? '',
    to_address:      c.to_address      ?? '',
  }
}

// ─── トグルスイッチ ───────────────────────────────────────────────────────────

function ToggleSwitch({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent
                  transition-colors duration-200 focus:outline-none
                  disabled:opacity-40 disabled:cursor-not-allowed
                  ${checked ? 'bg-blue-600' : 'bg-gray-600'}`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-[#e2e8f4] shadow
                    transform transition-transform duration-200
                    ${checked ? 'translate-x-4' : 'translate-x-0'}`}
      />
    </button>
  )
}

// ─── フォーム入力コンポーネント ───────────────────────────────────────────────

function Field({
  label,
  required,
  children,
}: {
  label: string
  required?: boolean
  children: React.ReactNode
}) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-gray-400 uppercase tracking-wide">
        {label}
        {required && <span className="text-red-400 ml-0.5">*</span>}
      </label>
      {children}
    </div>
  )
}

const inputClass =
  'w-full px-3 py-2 text-sm border border-gray-700 rounded-lg ' +
  'bg-gray-900 text-white placeholder-gray-600 ' +
  'focus:outline-none focus:border-blue-500 transition-colors'

// ─── 設定フォーム(タイプ別) ───────────────────────────────────────────────────

function WebhookFields({
  form,
  setForm,
  showAuth,
}: {
  form: FormState
  setForm: React.Dispatch<React.SetStateAction<FormState>>
  showAuth: boolean
}) {
  return (
    <>
      <Field label="Webhook URL" required>
        <input
          type="url"
          value={form.webhook_url}
          onChange={e => setForm(f => ({ ...f, webhook_url: e.target.value }))}
          placeholder="https://hooks.example.com/..."
          className={inputClass}
          required
        />
      </Field>
      {showAuth && (
        <Field label="Authorization Header（任意）">
          <input
            type="text"
            value={form.auth_header}
            onChange={e => setForm(f => ({ ...f, auth_header: e.target.value }))}
            placeholder="Bearer xxxxxxxx"
            className={inputClass}
          />
        </Field>
      )}
    </>
  )
}

function PagerDutyFields({
  form,
  setForm,
}: {
  form: FormState
  setForm: React.Dispatch<React.SetStateAction<FormState>>
}) {
  return (
    <Field label="Integration Key (Events API v2)" required>
      <input
        type="text"
        value={form.integration_key}
        onChange={e => setForm(f => ({ ...f, integration_key: e.target.value }))}
        placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        className={inputClass}
        required
      />
      <p className="mt-1 text-xs text-gray-500">
        PagerDuty サービスの Integrations タブから Events API v2 の Integration Key を取得してください。
      </p>
    </Field>
  )
}

const SMTP_PRESETS: { label: string; host: string; port: string; note: string }[] = [
  { label: '手動設定',          host: '',                          port: '587', note: '' },
  { label: 'Amazon SES',       host: 'email-smtp.ap-northeast-1.amazonaws.com', port: '587', note: 'IAMでSMTP認証情報を作成してください' },
  { label: 'Gmail',            host: 'smtp.gmail.com',            port: '587', note: 'Googleアカウントのアプリパスワードが必要です' },
  { label: 'SendGrid',         host: 'smtp.sendgrid.net',         port: '587', note: 'ユーザー名は "apikey"、パスワードにAPIキーを入力' },
  { label: 'Microsoft 365',    host: 'smtp.office365.com',        port: '587', note: '' },
]

function EmailFields({
  form,
  setForm,
  isEdit,
}: {
  form: FormState
  setForm: React.Dispatch<React.SetStateAction<FormState>>
  isEdit: boolean
}) {
  const applyPreset = (idx: number) => {
    const p = SMTP_PRESETS[idx]
    if (p.host) {
      setForm(f => ({ ...f, smtp_host: p.host, smtp_port: p.port }))
    }
  }

  const activePreset = SMTP_PRESETS.find(p => p.host && p.host === form.smtp_host)

  return (
    <>
      <Field label="SMTPプリセット">
        <div className="flex flex-wrap gap-2">
          {SMTP_PRESETS.map((p, i) => (
            <button
              key={i}
              type="button"
              onClick={() => applyPreset(i)}
              className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                (p.host && p.host === form.smtp_host)
                  ? 'bg-blue-600/30 border-blue-500 text-blue-300'
                  : 'bg-[#070d19] border-[#1e2d42] text-[#8899aa] hover:border-[#4a6fa5]'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>
        {activePreset?.note && (
          <p className="text-xs text-yellow-400/70 mt-2">{activePreset.note}</p>
        )}
      </Field>
      <div className="grid grid-cols-2 gap-4">
        <Field label="SMTP ホスト" required>
          <input
            type="text"
            value={form.smtp_host}
            onChange={e => setForm(f => ({ ...f, smtp_host: e.target.value }))}
            placeholder="smtp.example.com"
            className={inputClass}
            required
          />
        </Field>
        <Field label="ポート" required>
          <input
            type="number"
            value={form.smtp_port}
            onChange={e => setForm(f => ({ ...f, smtp_port: e.target.value }))}
            placeholder="587"
            className={inputClass}
            required
          />
        </Field>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <Field label="ユーザー名">
          <input
            type="text"
            value={form.smtp_username}
            onChange={e => setForm(f => ({ ...f, smtp_username: e.target.value }))}
            placeholder="user@example.com"
            className={inputClass}
          />
        </Field>
        <Field label={isEdit ? 'パスワード（変更する場合のみ）' : 'パスワード'}>
          <input
            type="password"
            value={form.smtp_password}
            onChange={e => setForm(f => ({ ...f, smtp_password: e.target.value }))}
            placeholder={isEdit ? '変更しない場合は空白' : ''}
            className={inputClass}
          />
        </Field>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <Field label="送信元アドレス" required>
          <input
            type="email"
            value={form.from_address}
            onChange={e => setForm(f => ({ ...f, from_address: e.target.value }))}
            placeholder="noreply@example.com"
            className={inputClass}
            required
          />
        </Field>
        <Field label="送信先アドレス" required>
          <input
            type="email"
            value={form.to_address}
            onChange={e => setForm(f => ({ ...f, to_address: e.target.value }))}
            placeholder="admin@example.com"
            className={inputClass}
            required
          />
        </Field>
      </div>
    </>
  )
}

// ─── モーダル ─────────────────────────────────────────────────────────────────

function ChannelModal({
  editTarget,
  onClose,
}: {
  editTarget: NotifChannel | null
  onClose: () => void
}) {
  const isEdit = editTarget !== null
  const queryClient = useQueryClient()

  const [form, setForm] = useState<FormState>(
    isEdit ? formFromChannel(editTarget) : { ...DEFAULT_FORM }
  )
  const [error, setError] = useState<string | null>(null)

  const saveMutation = useMutation<NotifChannel, Error, void>({
    mutationFn: () => {
      const body = {
        name: form.name.trim(),
        type: form.type,
        config: buildConfig(form),
        enabled: form.enabled,
      }
      if (isEdit) {
        return apiFetch<NotifChannel>(`/api/v1/admin/notifications/${editTarget.id}`, {
          method: 'PUT',
          body: JSON.stringify(body),
        })
      }
      return apiFetch<NotifChannel>('/api/v1/admin/notifications', {
        method: 'POST',
        body: JSON.stringify(body),
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-notifications'] })
      onClose()
    },
    onError: (err) => setError(err.message),
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    saveMutation.mutate()
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(0,0,0,0.7)' }}
    >
      <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-lg shadow-2xl">

        {/* ヘッダー */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
          <h2 className="text-base font-semibold text-white">
            {isEdit ? 'チャンネルを編集' : 'チャンネルを追加'}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* フォーム */}
        <form onSubmit={handleSubmit}>
          <div className="px-6 py-5 space-y-5 max-h-[70vh] overflow-y-auto">

            {/* 名前 */}
            <Field label="チャンネル名" required>
              <input
                type="text"
                value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="例: Slackアラート通知"
                className={inputClass}
                required
                autoFocus
              />
            </Field>

            {/* タイプ選択 */}
            <Field label="タイプ" required>
              <select
                value={form.type}
                onChange={e =>
                  setForm(f => ({ ...f, type: e.target.value as ChannelType }))
                }
                className={inputClass}
              >
                {CHANNEL_TYPES.map(t => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </Field>

            {/* タイプ別フィールド */}
            {form.type === 'webhook_slack' && (
              <WebhookFields form={form} setForm={setForm} showAuth={false} />
            )}
            {form.type === 'webhook_teams' && (
              <WebhookFields form={form} setForm={setForm} showAuth={false} />
            )}
            {form.type === 'webhook_generic' && (
              <WebhookFields form={form} setForm={setForm} showAuth={true} />
            )}
            {form.type === 'webhook_pagerduty' && (
              <PagerDutyFields form={form} setForm={setForm} />
            )}
            {form.type === 'email' && (
              <EmailFields form={form} setForm={setForm} isEdit={isEdit} />
            )}

            {/* 有効/無効 */}
            <div className="flex items-center gap-3">
              <ToggleSwitch
                checked={form.enabled}
                onChange={v => setForm(f => ({ ...f, enabled: v }))}
              />
              <span className="text-sm text-gray-300">
                {form.enabled ? '有効' : '無効'}
              </span>
            </div>

            {/* エラー表示 */}
            {error && (
              <div className="flex items-center gap-2 px-3 py-2 bg-red-900/40 border border-red-700/50 rounded-lg">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                <p className="text-xs text-red-300">{error}</p>
              </div>
            )}
          </div>

          {/* フッター */}
          <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-700">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-gray-400 hover:text-white
                         bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={saveMutation.isPending}
              className="px-5 py-2 text-sm font-medium text-white
                         bg-blue-600 hover:bg-blue-500 disabled:opacity-50
                         rounded-lg transition-colors"
            >
              {saveMutation.isPending ? '保存中…' : '保存'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── チャンネルカード ─────────────────────────────────────────────────────────

function ChannelCard({
  channel,
  onEdit,
  onDelete,
  onTest,
  testResult,
  testLoading,
}: {
  channel: NotifChannel
  onEdit: (ch: NotifChannel) => void
  onDelete: (ch: NotifChannel) => void
  onTest: (ch: NotifChannel) => void
  testResult: TestResult | null
  testLoading: boolean
}) {
  const iconColor = typeIconColor(channel.type)
  const badgeStyle = typeBadgeStyle(channel.type)
  const preview = configPreview(channel)
  const isThisTestResult = testResult?.channelId === channel.id

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 flex flex-col gap-4
                    hover:border-gray-600 transition-colors">

      {/* 上部: アイコン + 名前 + バッジ + トグル */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="mt-0.5 shrink-0">
            {typeIcon(channel.type, `w-5 h-5 ${iconColor}`)}
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-white truncate">{channel.name}</p>
            <span className={`inline-block mt-1 text-xs px-2 py-0.5 rounded-full border font-medium ${badgeStyle}`}>
              {typeLabel(channel.type)}
            </span>
          </div>
        </div>
        <ToggleSwitch
          checked={channel.enabled}
          onChange={() => {
            /* toggle via edit mutation — handled by parent */
          }}
          disabled
        />
      </div>

      {/* 設定プレビュー */}
      <p
        className="text-xs text-gray-500 font-mono truncate"
        title={
          channel.type === 'email'
            ? channel.config.to_address
            : channel.config.webhook_url
        }
      >
        {preview}
      </p>

      {/* テスト結果 */}
      {isThisTestResult && testResult && (
        <div
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs
                      ${testResult.success
                        ? 'bg-green-900/40 border border-green-700/50 text-green-300'
                        : 'bg-red-900/40 border border-red-700/50 text-red-300'}`}
        >
          {testResult.success
            ? <CheckCircle className="w-3.5 h-3.5 shrink-0" />
            : <AlertCircle className="w-3.5 h-3.5 shrink-0" />}
          <span>{testResult.message}</span>
        </div>
      )}

      {/* アクションボタン */}
      <div className="flex items-center gap-2 pt-1">
        <button
          onClick={() => onEdit(channel)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400
                     hover:text-white bg-gray-700 hover:bg-gray-600
                     rounded-lg transition-colors"
        >
          <Pencil className="w-3.5 h-3.5" />
          編集
        </button>
        <button
          onClick={() => onTest(channel)}
          disabled={testLoading && isThisTestResult}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-blue-400
                     hover:text-white bg-blue-900/30 hover:bg-blue-800/50
                     border border-blue-800/50 rounded-lg transition-colors
                     disabled:opacity-50"
        >
          <Send className="w-3.5 h-3.5" />
          {testLoading && isThisTestResult ? '送信中…' : 'テスト送信'}
        </button>
        <button
          onClick={() => onDelete(channel)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-400
                     hover:text-white bg-red-900/20 hover:bg-red-900/40
                     border border-red-800/40 rounded-lg transition-colors ml-auto"
        >
          <Trash2 className="w-3.5 h-3.5" />
          削除
        </button>
      </div>
    </div>
  )
}

// ─── 削除確認ダイアログ ───────────────────────────────────────────────────────

function DeleteConfirmDialog({
  channel,
  onCancel,
  onConfirm,
  isPending,
}: {
  channel: NotifChannel
  onCancel: () => void
  onConfirm: () => void
  isPending: boolean
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(0,0,0,0.7)' }}
    >
      <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-sm shadow-2xl p-6 space-y-5">
        <div className="flex items-center gap-3">
          <Trash2 className="w-5 h-5 text-red-400 shrink-0" />
          <h2 className="text-base font-semibold text-white">チャンネルを削除</h2>
        </div>
        <p className="text-sm text-gray-400">
          <span className="text-white font-medium">{channel.name}</span> を削除します。
          この操作は取り消せません。
        </p>
        <div className="flex items-center justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-gray-400 hover:text-white
                       bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className="px-4 py-2 text-sm font-medium text-white
                       bg-red-700 hover:bg-red-600 disabled:opacity-50
                       rounded-lg transition-colors"
          >
            {isPending ? '削除中…' : '削除する'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────────

export default function AdminNotificationsPage() {
  const queryClient = useQueryClient()

  const [modalOpen, setModalOpen]       = useState(false)
  const [editTarget, setEditTarget]     = useState<NotifChannel | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<NotifChannel | null>(null)
  const [testResult, setTestResult]     = useState<TestResult | null>(null)
  const [testingId, setTestingId]       = useState<string | null>(null)

  // ─ データ取得 ───────────────────────────────────────────────────────────────

  const { data, isLoading, isError, error } = useQuery<ChannelListResponse>({
    queryKey: ['admin-notifications'],
    queryFn: async () => {
      try {
        const res = await apiFetch<ChannelListResponse>('/api/v1/admin/notifications')
        if (res && typeof res === 'object' && 'channels' in res) return res
        return { channels: [] }
      } catch { return { channels: [] } }
    },
  })

  const channels = data?.channels ?? []

  // ─ 削除 ─────────────────────────────────────────────────────────────────────

  const deleteMutation = useMutation<void, Error, string>({
    mutationFn: (id) =>
      apiFetch<void>(`/api/v1/admin/notifications/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-notifications'] })
      setDeleteTarget(null)
    },
  })

  // ─ テスト送信 ────────────────────────────────────────────────────────────────

  const testMutation = useMutation<{ success: boolean; message?: string }, Error, string>({
    mutationFn: (id) =>
      apiFetch(`/api/v1/admin/notifications/${id}/test`, { method: 'POST' }),
    onSuccess: (res, id) => {
      setTestResult({
        channelId: id,
        success: res.success,
        message: res.message ?? (res.success ? 'テスト送信に成功しました' : 'テスト送信に失敗しました'),
      })
      setTestingId(null)
    },
    onError: (err, id) => {
      setTestResult({
        channelId: id,
        success: false,
        message: err.message,
      })
      setTestingId(null)
    },
  })

  // ─ ハンドラー ────────────────────────────────────────────────────────────────

  function openAdd() {
    setEditTarget(null)
    setModalOpen(true)
  }

  function openEdit(ch: NotifChannel) {
    setEditTarget(ch)
    setModalOpen(true)
  }

  function closeModal() {
    setModalOpen(false)
    setEditTarget(null)
  }

  function handleTest(ch: NotifChannel) {
    setTestingId(ch.id)
    setTestResult(null)
    testMutation.mutate(ch.id)
  }

  return (
    <div className="p-6 space-y-6">

      {/* ─── ヘッダー ──────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bell className="w-6 h-6 text-blue-400" />
            通知チャンネル管理
          </h1>
          <p className="text-gray-500 text-sm mt-1">
            アラート発生時の通知先を設定します
          </p>
        </div>
        <button
          onClick={openAdd}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500
                     text-white text-sm font-medium rounded-lg transition-colors shrink-0"
        >
          <Plus className="w-4 h-4" />
          チャンネルを追加
        </button>
      </div>

      {/* ─── ローディング ──────────────────────────────────────────────── */}
      {isLoading && (
        <div className="flex items-center justify-center h-48">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {/* ─── エラー ────────────────────────────────────────────────────── */}
      {isError && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-900/40 border border-red-700/50 rounded-xl">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
          <p className="text-sm text-red-300">
            {(error as Error).message ?? 'データの取得に失敗しました'}
          </p>
        </div>
      )}

      {/* ─── 空状態 ────────────────────────────────────────────────────── */}
      {!isLoading && !isError && channels.length === 0 && (
        <div className="flex flex-col items-center justify-center h-56
                        bg-gray-800 border border-gray-700 rounded-xl text-gray-500">
          <Bell className="w-12 h-12 mb-3 opacity-20" />
          <p className="text-sm">通知チャンネルがまだ登録されていません</p>
          <button
            onClick={openAdd}
            className="mt-4 flex items-center gap-1.5 text-sm text-blue-400
                       hover:text-blue-300 transition-colors"
          >
            <Plus className="w-4 h-4" />
            最初のチャンネルを追加する
          </button>
        </div>
      )}

      {/* ─── チャンネルグリッド ─────────────────────────────────────────── */}
      {!isLoading && channels.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {channels.map(ch => (
            <ChannelCard
              key={ch.id}
              channel={ch}
              onEdit={openEdit}
              onDelete={setDeleteTarget}
              onTest={handleTest}
              testResult={testResult}
              testLoading={testingId === ch.id}
            />
          ))}
        </div>
      )}

      {/* ─── 追加/編集モーダル ─────────────────────────────────────────── */}
      {modalOpen && (
        <ChannelModal editTarget={editTarget} onClose={closeModal} />
      )}

      {/* ─── 削除確認ダイアログ ────────────────────────────────────────── */}
      {deleteTarget && (
        <DeleteConfirmDialog
          channel={deleteTarget}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          isPending={deleteMutation.isPending}
        />
      )}

    </div>
  )
}
