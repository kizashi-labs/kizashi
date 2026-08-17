'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  User, Lock, ShieldCheck, ShieldOff, Eye, EyeOff,
  CheckCircle, AlertCircle, KeyRound, Pencil, X, Check,
  Smartphone, Mail, Plus, Copy, Trash2, Clock, Globe,
  Bell, BellOff, Activity, Settings, RefreshCw
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface UserProfile {
  id: string
  email: string
  full_name?: string
  role: string
  mfa_enabled: boolean
  totp_enabled?: boolean
  email_mfa_enabled?: boolean
  created_at?: string
  last_login?: string
  timezone?: string
  language?: string
}

interface APIKey {
  id: string
  name: string
  key_prefix: string
  created_at: string
  last_used_at?: string
  expires_at?: string
}

interface LoginEvent {
  id: string
  ip_address: string
  user_agent: string
  created_at: string
  success: boolean
  location?: string
}

interface APICallEvent {
  id: string
  method: string
  path: string
  status: number
  created_at: string
}

interface NotificationPref {
  event_type: string
  label: string
  email: boolean
  in_app: boolean
}

const TABS = [
  { id: 'profile',       label: 'プロフィール',  icon: User },
  { id: 'security',      label: 'セキュリティ',  icon: Lock },
  { id: 'mfa',           label: 'MFA',           icon: ShieldCheck },
  { id: 'api-keys',      label: 'API キー',      icon: KeyRound },
  { id: 'activity',      label: 'アクティビティ', icon: Activity },
  { id: 'notifications', label: '通知設定',       icon: Bell },
] as const
type TabID = typeof TABS[number]['id']

// ── Helpers ────────────────────────────────────────────────────────────────

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-falcon-surface rounded-xl border border-falcon-border p-5 ${className}`}>
      {children}
    </div>
  )
}

function Badge({ role }: { role: string }) {
  const map: Record<string, string> = {
    admin:   'bg-red-900/40 text-red-300',
    analyst: 'bg-blue-900/40 text-blue-300',
    viewer:  'bg-falcon-raised text-falcon-muted',
  }
  const labels: Record<string, string> = { admin: '管理者', analyst: 'アナリスト', viewer: 'ビューアー' }
  return (
    <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${map[role] ?? map.viewer}`}>
      {labels[role] ?? role}
    </span>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function ProfilePage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<TabID>('profile')

  const { data: profile, isLoading } = useQuery<UserProfile>({
    queryKey: ['me'],
    queryFn: () => apiFetch<UserProfile>('/api/v1/users/me'),
  })

  if (isLoading || !profile) {
    return (
      <div className="min-h-screen bg-[#070d19] flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-falcon-red" />
      </div>
    )
  }

  const initials = (profile.full_name || profile.email || 'U')
    .split(' ')
    .map(s => s[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <div className="max-w-4xl mx-auto space-y-6">

        {/* ── Header card ──────────────────────────────────── */}
        <Card className="flex flex-col sm:flex-row items-start sm:items-center gap-5">
          <div className="w-16 h-16 rounded-full bg-linear-to-br from-falcon-blue to-[#0044cc]
                          flex items-center justify-center shrink-0 text-xl font-bold text-white">
            {initials}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-xl font-bold text-white">{profile.full_name || profile.email}</h1>
              <Badge role={profile.role} />
            </div>
            <p className="text-falcon-muted text-sm mt-0.5">{profile.email}</p>
            {profile.last_login && (
              <p className="text-falcon-muted text-xs mt-1 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                最終ログイン: {new Date(profile.last_login).toLocaleString('ja-JP')}
              </p>
            )}
          </div>
        </Card>

        {/* ── Tabs ─────────────────────────────────────────── */}
        <div className="flex gap-1 overflow-x-auto pb-1 scrollbar-thin">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-all
                ${tab === id
                  ? 'bg-falcon-active text-white border border-[#2d4a6e]'
                  : 'text-falcon-muted hover:bg-falcon-surface hover:text-falcon-text'
                }`}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab content ──────────────────────────────────── */}
        {tab === 'profile'       && <ProfileTab profile={profile} qc={qc} />}
        {tab === 'security'      && <SecurityTab profile={profile} />}
        {tab === 'mfa'           && <MFATab profile={profile} qc={qc} />}
        {tab === 'api-keys'      && <APIKeysTab />}
        {tab === 'activity'      && <ActivityTab />}
        {tab === 'notifications' && <NotificationsTab />}
      </div>
    </div>
  )
}

// ── Tab: Profile Info ──────────────────────────────────────────────────────

function ProfileTab({ profile, qc }: { profile: UserProfile; qc: ReturnType<typeof useQueryClient> }) {
  const [editingName, setEditingName] = useState(false)
  const [nameInput, setNameInput]   = useState('')
  const [nameSaved, setNameSaved]   = useState(false)
  const [timezone, setTimezone]     = useState(profile.timezone ?? 'Asia/Tokyo')
  const [language, setLanguage]     = useState(profile.language ?? 'ja')
  const [prefSaved, setPrefSaved]   = useState(false)

  const updateName = useMutation({
    mutationFn: (fullName: string) =>
      apiFetch('/api/v1/users/me', { method: 'PATCH', body: JSON.stringify({ full_name: fullName }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setEditingName(false)
      setNameSaved(true)
      setTimeout(() => setNameSaved(false), 3000)
    },
  })

  const updatePrefs = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/users/me', { method: 'PATCH', body: JSON.stringify({ timezone, language }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setPrefSaved(true)
      setTimeout(() => setPrefSaved(false), 3000)
    },
  })

  return (
    <Card>
      <div className="flex items-center gap-2 mb-5">
        <Settings className="w-4 h-4 text-falcon-muted" />
        <h2 className="text-white font-medium">プロフィール情報</h2>
      </div>

      <div className="space-y-4">
        {/* Name */}
        <div>
          <label className="text-falcon-muted text-sm block mb-1">表示名</label>
          {editingName ? (
            <div className="flex items-center gap-2">
              <input
                autoFocus
                value={nameInput}
                onChange={e => setNameInput(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && nameInput.trim()) updateName.mutate(nameInput.trim())
                  if (e.key === 'Escape') setEditingName(false)
                }}
                placeholder="表示名"
                className="flex-1 bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                           text-sm focus:outline-hidden focus:border-falcon-red"
              />
              <button
                onClick={() => nameInput.trim() && updateName.mutate(nameInput.trim())}
                disabled={!nameInput.trim() || updateName.isPending}
                className="p-1.5 text-green-400 hover:text-green-300 disabled:opacity-40"
              >
                <Check className="w-4 h-4" />
              </button>
              <button onClick={() => setEditingName(false)} className="p-1.5 text-falcon-muted hover:text-falcon-text">
                <X className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 group">
              <p className="text-white text-sm bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 flex-1">
                {profile.full_name || <span className="text-falcon-muted">未設定</span>}
                {nameSaved && <span className="ml-2 text-green-400 text-xs">✓ 保存しました</span>}
              </p>
              <button
                onClick={() => { setNameInput(profile.full_name || ''); setEditingName(true) }}
                className="p-1.5 text-falcon-muted hover:text-falcon-text"
              >
                <Pencil className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        {/* Email (read-only) */}
        <div>
          <label className="text-falcon-muted text-sm block mb-1">メールアドレス</label>
          <p className="text-white text-sm bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2">
            {profile.email}
          </p>
        </div>

        {/* Timezone */}
        <div>
          <label className="text-falcon-muted text-sm block mb-1">タイムゾーン</label>
          <select
            value={timezone}
            onChange={e => setTimezone(e.target.value)}
            className="w-full bg-[#070d19] text-white text-sm border border-falcon-border rounded-lg px-3 py-2
                       focus:outline-hidden focus:border-falcon-red"
          >
            <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
            <option value="UTC">UTC</option>
            <option value="America/New_York">America/New_York (EST)</option>
            <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
            <option value="Europe/London">Europe/London (GMT)</option>
            <option value="Europe/Paris">Europe/Paris (CET)</option>
          </select>
        </div>

        {/* Language */}
        <div>
          <label className="text-falcon-muted text-sm block mb-1">言語</label>
          <select
            value={language}
            onChange={e => setLanguage(e.target.value)}
            className="w-full bg-[#070d19] text-white text-sm border border-falcon-border rounded-lg px-3 py-2
                       focus:outline-hidden focus:border-falcon-red"
          >
            <option value="ja">日本語</option>
            <option value="en">English</option>
          </select>
        </div>

        <div className="pt-2">
          <button
            onClick={() => updatePrefs.mutate()}
            disabled={updatePrefs.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg
                       hover:bg-[#c40026] transition-colors disabled:opacity-50 text-sm"
          >
            {updatePrefs.isPending
              ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <Check className="w-4 h-4" />
            }
            設定を保存
          </button>
          {prefSaved && <span className="ml-3 text-green-400 text-sm">✓ 保存しました</span>}
        </div>
      </div>
    </Card>
  )
}

// ── Tab: Security ──────────────────────────────────────────────────────────

function SecurityTab({ profile }: { profile: UserProfile }) {
  const [form, setForm] = useState({ current: '', next: '', confirm: '' })
  const [show, setShow] = useState(false)
  const [success, setSuccess] = useState(false)

  const mutation = useMutation({
    mutationFn: () => {
      if (!form.current) throw new Error('現在のパスワードを入力してください')
      if (form.next !== form.confirm) throw new Error('新しいパスワードが一致しません')
      if (form.next.length < 8) throw new Error('パスワードは8文字以上にしてください')
      return apiFetch(`/api/v1/users/${profile.id}/password`, {
        method: 'PUT',
        body: JSON.stringify({ current_password: form.current, password: form.next }),
      })
    },
    onSuccess: () => {
      setSuccess(true)
      setForm({ current: '', next: '', confirm: '' })
      setTimeout(() => setSuccess(false), 4000)
    },
  })

  const errMsg = mutation.error instanceof Error ? mutation.error.message : null

  return (
    <Card>
      <div className="flex items-center gap-2 mb-5">
        <Lock className="w-4 h-4 text-falcon-muted" />
        <h2 className="text-white font-medium">パスワード変更</h2>
      </div>

      {success && (
        <div className="flex items-center gap-2 text-green-400 text-sm bg-green-900/20 border border-green-700/50
                        rounded-lg px-3 py-2 mb-4">
          <CheckCircle className="w-4 h-4 shrink-0" />
          パスワードを更新しました
        </div>
      )}
      {errMsg && (
        <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/50
                        rounded-lg px-3 py-2 mb-4">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {errMsg}
        </div>
      )}

      <div className="space-y-3">
        {(['current', 'next', 'confirm'] as const).map(field => (
          <div key={field}>
            <label className="text-falcon-muted text-sm block mb-1">
              {field === 'current' ? '現在のパスワード' : field === 'next' ? '新しいパスワード' : '新しいパスワード（確認）'}
            </label>
            <div className="relative">
              <input
                type={show ? 'text' : 'password'}
                value={form[field]}
                onChange={e => setForm(f => ({ ...f, [field]: e.target.value }))}
                placeholder={field === 'next' ? '8文字以上' : ''}
                className="w-full bg-[#070d19] text-white px-3 py-2 pr-9 rounded-lg border border-falcon-border
                           text-sm focus:outline-hidden focus:border-falcon-red placeholder-falcon-subtle"
              />
              {field === 'current' && (
                <button
                  type="button"
                  onClick={() => setShow(s => !s)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-falcon-muted hover:text-falcon-text"
                >
                  {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              )}
            </div>
          </div>
        ))}
        <div className="pt-1">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || !form.current || !form.next || !form.confirm}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg
                       hover:bg-[#c40026] transition-colors disabled:opacity-50 text-sm"
          >
            {mutation.isPending
              ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <KeyRound className="w-4 h-4" />
            }
            パスワードを更新
          </button>
        </div>
      </div>
    </Card>
  )
}

// ── Tab: MFA ───────────────────────────────────────────────────────────────

function MFATab({ profile, qc }: { profile: UserProfile; qc: ReturnType<typeof useQueryClient> }) {
  const [emailMsg, setEmailMsg] = useState<string | null>(null)

  // TOTP の有効化は QR スキャン + コード確認、無効化はパスワード再確認が必要な
  // ため、専用フローのある /profile/security に誘導する（ここでの単純トグルは
  // バックエンドに存在しない /auth/mfa/totp を呼んでいて機能していなかった）。

  const toggleEmailMFA = useMutation({
    mutationFn: (enable: boolean) =>
      apiFetch(`/api/v1/auth/mfa/email/${enable ? 'enable' : 'disable'}`, { method: 'POST' }),
    onSuccess: (_, enable) => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setEmailMsg(enable ? 'メール MFA を有効にしました' : 'メール MFA を無効にしました')
      setTimeout(() => setEmailMsg(null), 4000)
    },
    onError: () => {
      setEmailMsg('メール MFA の更新に失敗しました')
      setTimeout(() => setEmailMsg(null), 4000)
    },
  })

  const totpEnabled  = profile.totp_enabled  ?? profile.mfa_enabled
  const emailEnabled = profile.email_mfa_enabled ?? false

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${totpEnabled ? 'bg-green-900/30' : 'bg-falcon-border/50'}`}>
              <Smartphone className={`w-5 h-5 ${totpEnabled ? 'text-green-400' : 'text-falcon-muted'}`} />
            </div>
            <div>
              <h3 className="text-white font-medium">TOTP 認証アプリ</h3>
              <p className="text-falcon-muted text-xs mt-0.5">Google Authenticator などのアプリを使用します</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${
              totpEnabled ? 'bg-green-900/40 text-green-300' : 'bg-falcon-border text-falcon-muted'
            }`}>
              {totpEnabled ? '有効' : '無効'}
            </span>
            <a
              href="/profile/security"
              className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors bg-falcon-border text-white hover:bg-[#2a3d58]"
            >
              {totpEnabled ? '設定を管理' : 'セットアップ'}
            </a>
          </div>
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${emailEnabled ? 'bg-green-900/30' : 'bg-falcon-border/50'}`}>
              <Mail className={`w-5 h-5 ${emailEnabled ? 'text-green-400' : 'text-falcon-muted'}`} />
            </div>
            <div>
              <h3 className="text-white font-medium">メール MFA</h3>
              <p className="text-falcon-muted text-xs mt-0.5">ログイン時にメールで確認コードを送信します</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${
              emailEnabled ? 'bg-green-900/40 text-green-300' : 'bg-falcon-border text-falcon-muted'
            }`}>
              {emailEnabled ? '有効' : '無効'}
            </span>
            <button
              onClick={() => toggleEmailMFA.mutate(!emailEnabled)}
              disabled={toggleEmailMFA.isPending}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors disabled:opacity-50
                ${emailEnabled
                  ? 'bg-red-900/40 text-red-300 hover:bg-red-900/60'
                  : 'bg-falcon-red text-white hover:bg-[#c40026]'
                }`}
            >
              {emailEnabled ? '無効にする' : '有効にする'}
            </button>
          </div>
        </div>
        {emailMsg && <p className="text-green-400 text-sm mt-2">{emailMsg}</p>}
      </Card>
    </div>
  )
}

// ── Tab: API Keys ──────────────────────────────────────────────────────────

function APIKeysTab() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: keys = [], isLoading } = useQuery<APIKey[]>({
    queryKey: ['my-api-keys'],
    queryFn: () => apiFetchList<APIKey>('/api/v1/api-keys'),
  })

  const createKey = useMutation({
    mutationFn: () =>
      apiFetch<{ key: string }>('/api/v1/api-keys', {
        method: 'POST',
        body: JSON.stringify({ name: newKeyName }),
      }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['my-api-keys'] })
      setNewKeyValue(data.key)
      setNewKeyName('')
    },
  })

  const revokeKey = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/api-keys/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['my-api-keys'] }),
  })

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <Card>
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-falcon-muted" />
          <h2 className="text-white font-medium">API キー</h2>
        </div>
        <button
          onClick={() => { setShowCreate(true); setNewKeyValue(null) }}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-red text-white text-sm rounded-lg
                     hover:bg-[#c40026] transition-colors"
        >
          <Plus className="w-4 h-4" />
          新規作成
        </button>
      </div>

      {/* Create modal */}
      {showCreate && !newKeyValue && (
        <div className="mb-5 p-4 bg-[#070d19] rounded-lg border border-falcon-border">
          <h3 className="text-white text-sm font-medium mb-3">新しい API キーを作成</h3>
          <input
            autoFocus
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && newKeyName.trim()) createKey.mutate()
            }}
            placeholder="キー名 (例: CI/CD Pipeline)"
            className="w-full bg-falcon-surface text-white px-3 py-2 rounded-lg border border-falcon-border
                       text-sm focus:outline-hidden focus:border-falcon-red mb-3 placeholder-falcon-subtle"
          />
          <div className="flex items-center gap-2">
            <button
              onClick={() => createKey.mutate()}
              disabled={!newKeyName.trim() || createKey.isPending}
              className="px-3 py-1.5 bg-falcon-red text-white text-sm rounded-lg hover:bg-[#c40026]
                         disabled:opacity-50 transition-colors"
            >
              作成
            </button>
            <button
              onClick={() => setShowCreate(false)}
              className="px-3 py-1.5 text-falcon-muted text-sm hover:text-falcon-text"
            >
              キャンセル
            </button>
          </div>
        </div>
      )}

      {/* Show new key */}
      {newKeyValue && (
        <div className="mb-5 p-4 bg-green-900/20 border border-green-700/50 rounded-lg">
          <p className="text-green-400 text-sm font-medium mb-2">
            <CheckCircle className="w-4 h-4 inline mr-1" />
            API キーを作成しました。このキーは一度しか表示されません。
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-[#070d19] text-green-300 text-xs px-3 py-2 rounded-lg border border-green-700/30 font-mono break-all">
              {newKeyValue}
            </code>
            <button
              onClick={() => handleCopy(newKeyValue)}
              className="p-2 text-green-400 hover:text-green-300"
              title="コピー"
            >
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <button
            onClick={() => { setNewKeyValue(null); setShowCreate(false) }}
            className="mt-2 text-falcon-muted text-xs hover:text-falcon-text"
          >
            閉じる
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="flex justify-center py-8">
          <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-falcon-red" />
        </div>
      ) : keys.length === 0 ? (
        <p className="text-falcon-muted text-sm text-center py-8">API キーがありません</p>
      ) : (
        <div className="space-y-3">
          {keys.map(k => (
            <div key={k.id}
              className="flex items-center justify-between p-3 bg-[#070d19] rounded-lg border border-falcon-border"
            >
              <div>
                <p className="text-white text-sm font-medium">{k.name}</p>
                <p className="text-falcon-muted text-xs font-mono mt-0.5">
                  {k.key_prefix}••••••••••••
                </p>
                <p className="text-falcon-subtle text-xs mt-0.5">
                  作成: {new Date(k.created_at).toLocaleDateString('ja-JP')}
                  {k.last_used_at && (
                    <> &nbsp;·&nbsp; 最終使用: {new Date(k.last_used_at).toLocaleDateString('ja-JP')}</>
                  )}
                </p>
              </div>
              <button
                onClick={() => revokeKey.mutate(k.id)}
                disabled={revokeKey.isPending}
                className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-900/20 rounded-lg
                           transition-colors disabled:opacity-50"
                title="失効"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

// ── Tab: Activity ──────────────────────────────────────────────────────────

function ActivityTab() {
  const { data: loginHistory = [], isLoading: loadingLogin } = useQuery<LoginEvent[]>({
    queryKey: ['login-history'],
    queryFn: () => apiFetchList<LoginEvent>('/api/v1/users/me/login-history?limit=20'),
  })

  const { data: apiCalls = [], isLoading: loadingApi } = useQuery<APICallEvent[]>({
    queryKey: ['api-activity'],
    queryFn: () => apiFetchList<APICallEvent>('/api/v1/users/me/api-activity?limit=20'),
  })

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center gap-2 mb-5">
          <Globe className="w-4 h-4 text-falcon-muted" />
          <h2 className="text-white font-medium">ログイン履歴</h2>
          <span className="text-falcon-muted text-xs ml-1">(直近 20 件)</span>
        </div>
        {loadingLogin ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-falcon-red" />
          </div>
        ) : loginHistory.length === 0 ? (
          <p className="text-falcon-muted text-sm text-center py-8">ログイン履歴がありません</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-falcon-muted text-xs border-b border-falcon-border">
                  <th className="pb-2 pr-4">日時</th>
                  <th className="pb-2 pr-4">IP アドレス</th>
                  <th className="pb-2 pr-4">ブラウザ / エージェント</th>
                  <th className="pb-2">結果</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {loginHistory.map(ev => (
                  <tr key={ev.id} className="text-falcon-text">
                    <td className="py-2 pr-4 text-xs text-falcon-muted whitespace-nowrap">
                      {new Date(ev.created_at).toLocaleString('ja-JP')}
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs">{ev.ip_address}</td>
                    <td className="py-2 pr-4 text-xs text-falcon-muted max-w-xs truncate">
                      {ev.user_agent}
                    </td>
                    <td className="py-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${
                        ev.success ? 'bg-green-900/40 text-green-300' : 'bg-red-900/40 text-red-300'
                      }`}>
                        {ev.success ? '成功' : '失敗'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card>
        <div className="flex items-center gap-2 mb-5">
          <Activity className="w-4 h-4 text-falcon-muted" />
          <h2 className="text-white font-medium">最近の API 呼び出し</h2>
          <span className="text-falcon-muted text-xs ml-1">(直近 20 件)</span>
        </div>
        {loadingApi ? (
          <div className="flex justify-center py-8">
            <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-falcon-red" />
          </div>
        ) : apiCalls.length === 0 ? (
          <p className="text-falcon-muted text-sm text-center py-8">API 呼び出し履歴がありません</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-falcon-muted text-xs border-b border-falcon-border">
                  <th className="pb-2 pr-4">日時</th>
                  <th className="pb-2 pr-4">メソッド</th>
                  <th className="pb-2 pr-4">パス</th>
                  <th className="pb-2">ステータス</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {apiCalls.map(ev => (
                  <tr key={ev.id} className="text-falcon-text">
                    <td className="py-2 pr-4 text-xs text-falcon-muted whitespace-nowrap">
                      {new Date(ev.created_at).toLocaleString('ja-JP')}
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${
                        ev.method === 'GET'    ? 'bg-blue-900/40 text-blue-300'   :
                        ev.method === 'POST'   ? 'bg-green-900/40 text-green-300' :
                        ev.method === 'DELETE' ? 'bg-red-900/40 text-red-300'     :
                                                 'bg-falcon-border text-falcon-muted'
                      }`}>
                        {ev.method}
                      </span>
                    </td>
                    <td className="py-2 pr-4 font-mono text-xs text-falcon-muted max-w-xs truncate">
                      {ev.path}
                    </td>
                    <td className="py-2">
                      <span className={`text-xs font-mono ${
                        ev.status < 300 ? 'text-green-400' :
                        ev.status < 500 ? 'text-yellow-400' : 'text-red-400'
                      }`}>
                        {ev.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

// ── Tab: Notifications ─────────────────────────────────────────────────────

const DEFAULT_PREFS: NotificationPref[] = [
  { event_type: 'alert_critical',    label: 'クリティカルアラート',      email: true,  in_app: true  },
  { event_type: 'alert_high',        label: '高リスクアラート',          email: true,  in_app: true  },
  { event_type: 'alert_medium',      label: '中リスクアラート',          email: false, in_app: true  },
  { event_type: 'alert_low',         label: '低リスクアラート',          email: false, in_app: false },
  { event_type: 'incident_created',  label: 'インシデント作成',          email: true,  in_app: true  },
  { event_type: 'incident_updated',  label: 'インシデント更新',          email: false, in_app: true  },
  { event_type: 'agent_offline',     label: 'エージェントオフライン',    email: true,  in_app: true  },
  { event_type: 'agent_online',      label: 'エージェントオンライン',    email: false, in_app: false },
  { event_type: 'rule_triggered',    label: '検知ルールトリガー',        email: false, in_app: true  },
  { event_type: 'backup_failed',     label: 'バックアップ失敗',          email: true,  in_app: true  },
  { event_type: 'login_failed',      label: 'ログイン失敗',              email: true,  in_app: true  },
  { event_type: 'report_ready',      label: 'レポート生成完了',          email: true,  in_app: false },
]

function NotificationsTab() {
  const qc = useQueryClient()
  const [prefs, setPrefs] = useState<NotificationPref[]>(DEFAULT_PREFS)
  const [saved, setSaved] = useState(false)

  const { data: serverPrefs } = useQuery<NotificationPref[]>({
    queryKey: ['notif-prefs-me'],
    queryFn: () => apiFetchList<NotificationPref>('/api/v1/users/me/notification-prefs'),
    onSuccess: (data: NotificationPref[]) => { if (data && data.length) setPrefs(data) },
  } as any)

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/users/me/notification-prefs', {
        method: 'PUT',
        body: JSON.stringify({ prefs }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['notif-prefs-me'] })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    },
  })

  const toggle = (idx: number, field: 'email' | 'in_app') => {
    setPrefs(p => p.map((item, i) => i === idx ? { ...item, [field]: !item[field] } : item))
  }

  return (
    <Card>
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-falcon-muted" />
          <h2 className="text-white font-medium">通知設定</h2>
        </div>
        <button
          onClick={() => saveMutation.mutate()}
          disabled={saveMutation.isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-red text-white text-sm rounded-lg
                     hover:bg-[#c40026] transition-colors disabled:opacity-50"
        >
          {saveMutation.isPending
            ? <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            : <Check className="w-3.5 h-3.5" />
          }
          保存
        </button>
      </div>

      {saved && (
        <div className="mb-4 flex items-center gap-2 text-green-400 text-sm bg-green-900/20 border border-green-700/50 rounded-lg px-3 py-2">
          <CheckCircle className="w-4 h-4" /> 設定を保存しました
        </div>
      )}

      {/* Table header */}
      <div className="grid grid-cols-[1fr_auto_auto] gap-4 text-xs text-falcon-muted pb-2 border-b border-falcon-border mb-2">
        <span>イベント</span>
        <span className="text-center w-16">メール</span>
        <span className="text-center w-16">アプリ内</span>
      </div>

      <div className="space-y-1">
        {prefs.map((pref, idx) => (
          <div
            key={pref.event_type}
            className="grid grid-cols-[1fr_auto_auto] gap-4 items-center py-2 px-1
                       hover:bg-[#070d19] rounded-lg transition-colors"
          >
            <span className="text-white text-sm">{pref.label}</span>
            <div className="flex justify-center w-16">
              <button
                onClick={() => toggle(idx, 'email')}
                className={`w-8 h-5 rounded-full transition-colors relative ${
                  pref.email ? 'bg-falcon-red' : 'bg-falcon-border'
                }`}
              >
                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text shadow transition-transform ${
                  pref.email ? 'left-3.5' : 'left-0.5'
                }`} />
              </button>
            </div>
            <div className="flex justify-center w-16">
              <button
                onClick={() => toggle(idx, 'in_app')}
                className={`w-8 h-5 rounded-full transition-colors relative ${
                  pref.in_app ? 'bg-falcon-red' : 'bg-falcon-border'
                }`}
              >
                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text shadow transition-transform ${
                  pref.in_app ? 'left-3.5' : 'left-0.5'
                }`} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}
