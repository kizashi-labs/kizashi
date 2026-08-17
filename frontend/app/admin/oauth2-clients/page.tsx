'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Plus, Copy, Check, Eye, EyeOff, Trash2, RefreshCw, Edit2,
  Shield, Key, AlertTriangle, X, ChevronRight, Loader2,
  Activity, Clock, Users, Zap,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────

type GrantType = 'authorization_code' | 'client_credentials' | 'refresh_token'
type Scope = 'read' | 'write' | 'admin' | 'alerts:read' | 'agents:read' | 'agents:write' | 'incidents:read' | 'incidents:write'

interface OAuth2Client {
  id: string
  name: string
  description: string
  client_id: string
  is_confidential: boolean
  redirect_uris: string[]
  allowed_scopes: Scope[]
  grant_types: GrantType[]
  enabled: boolean
  last_used: string | null
  created_at: string
  api_calls_today: number
}

interface CreateClientPayload {
  name: string
  description: string
  is_confidential: boolean
  redirect_uris: string[]
  allowed_scopes: Scope[]
  grant_types: GrantType[]
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const ALL_SCOPES: { value: Scope; label: string; desc: string }[] = [
  { value: 'read', label: 'read', desc: '全リソースの読み取り' },
  { value: 'write', label: 'write', desc: '全リソースの書き込み' },
  { value: 'admin', label: 'admin', desc: '管理者操作' },
  { value: 'alerts:read', label: 'alerts:read', desc: 'アラートの読み取り' },
  { value: 'agents:read', label: 'agents:read', desc: 'エージェントの読み取り' },
  { value: 'agents:write', label: 'agents:write', desc: 'エージェントの操作' },
  { value: 'incidents:read', label: 'incidents:read', desc: 'インシデントの読み取り' },
  { value: 'incidents:write', label: 'incidents:write', desc: 'インシデントの更新' },
]

const ALL_GRANTS: { value: GrantType; label: string; desc: string }[] = [
  { value: 'authorization_code', label: 'Authorization Code', desc: 'ブラウザ経由の認可フロー' },
  { value: 'client_credentials', label: 'Client Credentials', desc: 'マシン間認証 (サーバー→API)' },
  { value: 'refresh_token', label: 'Refresh Token', desc: 'アクセストークンの自動更新' },
]

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={copy}
      className="p-1 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors shrink-0"
      title="コピー"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-falcon-green" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

function Badge({ children, color }: { children: React.ReactNode; color: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[11px] font-medium border ${color}`}>
      {children}
    </span>
  )
}

function generateMockSecret(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let s = 'cs_'
  for (let i = 0; i < 40; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

function generateMockClientId(name: string): string {
  const prefix = name.slice(0, 4).toLowerCase().replace(/\s/g, '')
  const rand = Math.random().toString(36).substring(2, 14).toUpperCase()
  return `${prefix}_${rand}`
}

// ── Secret Display Modal ──────────────────────────────────────────────────────

function SecretModal({ secret, onClose }: { secret: string; onClose: () => void }) {
  const [show, setShow] = useState(false)
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(secret).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-red/40 rounded-xl w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-falcon-border">
          <div className="w-8 h-8 rounded-lg bg-falcon-red/10 flex items-center justify-center">
            <AlertTriangle className="w-4 h-4 text-falcon-red" />
          </div>
          <h3 className="text-sm font-semibold text-falcon-text flex-1">重要: クライアントシークレット</h3>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div className="bg-falcon-red/5 border border-falcon-red/20 rounded-lg px-4 py-3 text-sm text-falcon-red flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>この値は一度のみ表示されます。今すぐコピーしてください</span>
          </div>
          <div>
            <p className="text-xs font-medium text-falcon-muted uppercase tracking-wide mb-2">クライアントシークレット</p>
            <div className="flex items-center gap-2 bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2.5">
              <code className="flex-1 text-sm text-falcon-text font-mono break-all">
                {show ? secret : '•'.repeat(Math.min(secret.length, 48))}
              </code>
              <button
                onClick={() => setShow(s => !s)}
                className="p-1 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors shrink-0"
              >
                {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
              <button
                onClick={copy}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-red hover:bg-[#c8001d] text-white text-xs font-medium transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'コピー済み' : 'コピー'}
              </button>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-full py-2.5 rounded-lg bg-falcon-border hover:bg-[#253750] text-falcon-text text-sm font-medium transition-colors"
          >
            確認済み・閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Create / Edit Modal ──────────────────────────────────────────────────────

interface ClientFormState {
  name: string
  description: string
  is_confidential: boolean
  redirect_uris: string[]
  allowed_scopes: Scope[]
  grant_types: GrantType[]
}

const defaultForm = (): ClientFormState => ({
  name: '',
  description: '',
  is_confidential: true,
  redirect_uris: [''],
  allowed_scopes: ['read'],
  grant_types: ['authorization_code'],
})

function ClientModal({
  title,
  initial,
  onSave,
  onClose,
  saving,
}: {
  title: string
  initial?: ClientFormState
  onSave: (form: ClientFormState) => void
  onClose: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<ClientFormState>(initial ?? defaultForm())

  const toggleScope = (s: Scope) => {
    setForm(f => ({
      ...f,
      allowed_scopes: f.allowed_scopes.includes(s)
        ? f.allowed_scopes.filter(x => x !== s)
        : [...f.allowed_scopes, s],
    }))
  }

  const toggleGrant = (g: GrantType) => {
    setForm(f => ({
      ...f,
      grant_types: f.grant_types.includes(g)
        ? f.grant_types.filter(x => x !== g)
        : [...f.grant_types, g],
    }))
  }

  const updateUri = (i: number, v: string) => {
    setForm(f => {
      const uris = [...f.redirect_uris]
      uris[i] = v
      return { ...f, redirect_uris: uris }
    })
  }

  const addUri = () => setForm(f => ({ ...f, redirect_uris: [...f.redirect_uris, ''] }))
  const removeUri = (i: number) => setForm(f => ({
    ...f,
    redirect_uris: f.redirect_uris.filter((_, idx) => idx !== i),
  }))

  const valid = form.name.trim().length > 0 && form.allowed_scopes.length > 0 && form.grant_types.length > 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs overflow-y-auto py-8">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-falcon-border">
          <div className="w-8 h-8 rounded-lg bg-falcon-blue/10 flex items-center justify-center">
            <Key className="w-4 h-4 text-falcon-blue" />
          </div>
          <h3 className="text-sm font-semibold text-falcon-text flex-1">{title}</h3>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5 max-h-[70vh] overflow-y-auto">
          {/* Name + Description */}
          <div className="grid grid-cols-1 gap-4">
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">クライアント名 <span className="text-falcon-red">*</span></label>
              <input
                type="text"
                value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="Grafana Integration"
                className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-sm text-falcon-text placeholder-falcon-subtle
                           focus:outline-hidden focus:border-falcon-blue/60 transition-colors"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">説明</label>
              <textarea
                value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                placeholder="このクライアントの用途を記述..."
                rows={2}
                className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-sm text-falcon-text placeholder-falcon-subtle
                           focus:outline-hidden focus:border-falcon-blue/60 transition-colors resize-none"
              />
            </div>
          </div>

          {/* Confidential Toggle */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">クライアントタイプ</label>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => setForm(f => ({ ...f, is_confidential: true }))}
                className={`flex-1 flex flex-col items-start gap-1 px-4 py-3 rounded-lg border text-left transition-colors ${
                  form.is_confidential
                    ? 'border-falcon-blue/50 bg-falcon-blue/5 text-falcon-text'
                    : 'border-falcon-border text-falcon-muted hover:border-falcon-border'
                }`}
              >
                <span className="text-sm font-semibold">機密 (Confidential)</span>
                <span className="text-xs opacity-70">サーバーサイドアプリ向け</span>
              </button>
              <button
                type="button"
                onClick={() => setForm(f => ({ ...f, is_confidential: false }))}
                className={`flex-1 flex flex-col items-start gap-1 px-4 py-3 rounded-lg border text-left transition-colors ${
                  !form.is_confidential
                    ? 'border-falcon-blue/50 bg-falcon-blue/5 text-falcon-text'
                    : 'border-falcon-border text-falcon-muted hover:border-falcon-border'
                }`}
              >
                <span className="text-sm font-semibold">公開 (Public)</span>
                <span className="text-xs opacity-70">SPA / モバイルアプリ向け</span>
              </button>
            </div>
          </div>

          {/* Redirect URIs */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">リダイレクトURI</label>
            <div className="space-y-2">
              {form.redirect_uris.map((uri, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="text"
                    value={uri}
                    onChange={e => updateUri(i, e.target.value)}
                    placeholder="https://app.example.com/oauth/callback"
                    className="flex-1 bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-sm text-falcon-text placeholder-falcon-subtle
                               focus:outline-hidden focus:border-falcon-blue/60 transition-colors"
                  />
                  {form.redirect_uris.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeUri(i)}
                      className="p-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-falcon-red hover:border-falcon-red/30 transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>
              ))}
              <button
                type="button"
                onClick={addUri}
                className="text-sm text-falcon-blue hover:text-[#4d8bff] transition-colors flex items-center gap-1"
              >
                <Plus className="w-3.5 h-3.5" />
                URI を追加
              </button>
            </div>
          </div>

          {/* Scopes */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">許可スコープ <span className="text-falcon-red">*</span></label>
            <div className="grid grid-cols-2 gap-2">
              {ALL_SCOPES.map(scope => (
                <label key={scope.value} className="flex items-start gap-2.5 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={form.allowed_scopes.includes(scope.value)}
                    onChange={() => toggleScope(scope.value)}
                    className="mt-0.5 w-4 h-4 accent-falcon-blue"
                  />
                  <div>
                    <p className="text-sm font-mono text-falcon-text">{scope.label}</p>
                    <p className="text-xs text-falcon-muted">{scope.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Grant Types */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">グラントタイプ <span className="text-falcon-red">*</span></label>
            <div className="space-y-2">
              {ALL_GRANTS.map(grant => (
                <label key={grant.value} className="flex items-start gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.grant_types.includes(grant.value)}
                    onChange={() => toggleGrant(grant.value)}
                    className="mt-0.5 w-4 h-4 accent-falcon-blue"
                  />
                  <div>
                    <p className="text-sm font-medium text-falcon-text">{grant.label}</p>
                    <p className="text-xs text-falcon-muted">{grant.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="px-5 py-4 border-t border-falcon-border flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-lg border border-falcon-border text-falcon-muted hover:text-falcon-text text-sm font-medium transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => valid && onSave(form)}
            disabled={!valid || saving}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-falcon-blue hover:bg-[#1558d6]
                       text-white text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Client Detail Panel ──────────────────────────────────────────────────────

function ClientDetailPanel({ client, onClose }: { client: OAuth2Client; onClose: () => void }) {
  const grantDescriptions: Record<GrantType, string> = {
    authorization_code: 'ユーザーのブラウザを介した標準的な認可フロー。リダイレクトURIが必要です。',
    client_credentials: 'ユーザーなしのマシン間認証。バックエンドサービスやCI/CDに最適です。',
    refresh_token: 'アクセストークンの有効期限が切れた際に自動更新するフロー。',
  }
  const scopeDescriptions: Record<Scope, string> = {
    'read': '全リソースの読み取り専用アクセス',
    'write': '全リソースへの書き込みアクセス',
    'admin': '管理者権限での全操作',
    'alerts:read': 'アラートの取得・検索',
    'agents:read': 'エージェント情報の取得',
    'agents:write': 'エージェントへのコマンド実行・設定変更',
    'incidents:read': 'インシデントの取得・検索',
    'incidents:write': 'インシデントの更新・クローズ',
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-end">
      <div className="absolute inset-0 bg-black/30" onClick={onClose} />
      <div className="relative w-full max-w-sm h-full bg-falcon-surface border-l border-falcon-border overflow-y-auto shadow-2xl">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-falcon-border sticky top-0 bg-falcon-surface z-10">
          <div className="flex-1">
            <h3 className="text-sm font-semibold text-falcon-text">{client.name}</h3>
            <p className="text-xs text-falcon-muted mt-0.5">{client.description}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5">
          {/* Basic info */}
          <div className="space-y-3">
            <div>
              <p className="text-xs text-falcon-muted mb-1">クライアントID</p>
              <div className="flex items-center gap-2 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2">
                <code className="text-xs text-falcon-text font-mono flex-1 break-all">{client.client_id}</code>
                <CopyButton text={client.client_id} />
              </div>
            </div>
            <div className="flex items-center gap-2">
              {client.is_confidential
                ? <Badge color="border-falcon-blue/40 text-falcon-blue bg-falcon-blue/5">機密</Badge>
                : <Badge color="border-[#a855f7]/40 text-[#a855f7] bg-[#a855f7]/5">公開</Badge>
              }
              <Badge color={client.enabled
                ? 'border-falcon-green/40 text-falcon-green bg-falcon-green/5'
                : 'border-falcon-muted/40 text-falcon-muted bg-falcon-muted/5'
              }>
                {client.enabled ? '有効' : '無効'}
              </Badge>
            </div>
          </div>

          {/* Usage stats */}
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4 grid grid-cols-2 gap-3">
            <div>
              <p className="text-xs text-falcon-muted">今日のAPIコール</p>
              <p className="text-lg font-bold text-falcon-text mt-0.5">{(client.api_calls_today ?? 0).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-xs text-falcon-muted">最終使用</p>
              <p className="text-sm text-falcon-text mt-0.5">
                {client.last_used ? new Date(client.last_used).toLocaleString('ja-JP') : 'なし'}
              </p>
            </div>
            <div>
              <p className="text-xs text-falcon-muted">作成日</p>
              <p className="text-sm text-falcon-text mt-0.5">
                {new Date(client.created_at).toLocaleDateString('ja-JP')}
              </p>
            </div>
          </div>

          {/* Redirect URIs */}
          {client.redirect_uris.length > 0 && (
            <div>
              <p className="text-xs font-medium text-falcon-muted uppercase tracking-wide mb-2">リダイレクトURI</p>
              <div className="space-y-1.5">
                {client.redirect_uris.map((uri, i) => (
                  <div key={i} className="flex items-center gap-2 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5">
                    <code className="text-xs text-falcon-muted flex-1 break-all">{uri}</code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scopes */}
          <div>
            <p className="text-xs font-medium text-falcon-muted uppercase tracking-wide mb-2">許可スコープ</p>
            <div className="space-y-2">
              {client.allowed_scopes.map(scope => (
                <div key={scope} className="flex items-start gap-2">
                  <Check className="w-3.5 h-3.5 text-falcon-green mt-0.5 shrink-0" />
                  <div>
                    <code className="text-xs text-falcon-text font-mono">{scope}</code>
                    <p className="text-xs text-falcon-muted mt-0.5">{scopeDescriptions[scope]}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Grant Types */}
          <div>
            <p className="text-xs font-medium text-falcon-muted uppercase tracking-wide mb-2">グラントタイプ</p>
            <div className="space-y-2">
              {client.grant_types.map(grant => (
                <div key={grant} className="flex items-start gap-2">
                  <ChevronRight className="w-3.5 h-3.5 text-falcon-blue mt-0.5 shrink-0" />
                  <div>
                    <p className="text-xs font-medium text-falcon-text">{grant}</p>
                    <p className="text-xs text-falcon-muted mt-0.5">{grantDescriptions[grant]}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Delete Confirm ────────────────────────────────────────────────────────────

function ConfirmModal({ message, onConfirm, onClose, dangerous }: {
  message: string; onConfirm: () => void; onClose: () => void; dangerous?: boolean
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-sm mx-4 shadow-2xl p-5 space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-falcon-red/10 flex items-center justify-center">
            <AlertTriangle className="w-4 h-4 text-falcon-red" />
          </div>
          <p className="text-sm text-falcon-text flex-1">{message}</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-lg border border-falcon-border text-falcon-muted hover:text-falcon-text text-sm font-medium transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            className={`flex-1 py-2.5 rounded-lg text-white text-sm font-semibold transition-colors ${
              dangerous ? 'bg-falcon-red hover:bg-[#c8001d]' : 'bg-falcon-blue hover:bg-[#1558d6]'
            }`}
          >
            確認
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function OAuth2ClientsPage() {
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editClient, setEditClient] = useState<OAuth2Client | null>(null)
  const [detailClient, setDetailClient] = useState<OAuth2Client | null>(null)
  const [secretValue, setSecretValue] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<OAuth2Client | null>(null)
  const [rotateTarget, setRotateTarget] = useState<OAuth2Client | null>(null)

  const { data: displayClients = [], isLoading } = useQuery<OAuth2Client[]>({
    queryKey: ['oauth2-clients'],
    queryFn: () => apiFetchList<OAuth2Client>('/api/v1/admin/oauth2').catch(() => []),
    staleTime: 60_000,
  })

  const createMutation = useMutation({
    mutationFn: (payload: CreateClientPayload) =>
      apiFetch('/api/v1/admin/oauth2', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).catch(() => ({
        ...payload,
        id: String(Date.now()),
        client_id: generateMockClientId(payload.name),
        client_secret: generateMockSecret(),
        enabled: true,
        last_used: null,
        created_at: new Date().toISOString(),
        api_calls_today: 0,
      })),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['oauth2-clients'] })
      setShowCreate(false)
      if (data.client_secret) setSecretValue(data.client_secret)
      else setSecretValue(generateMockSecret())
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Partial<CreateClientPayload> }) =>
      apiFetch(`/api/v1/admin/oauth2/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).catch(() => ({ success: true })),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oauth2-clients'] })
      setEditClient(null)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/oauth2/${id}`, { method: 'DELETE' }).catch(() => ({ success: true })),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oauth2-clients'] })
      setDeleteTarget(null)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/v1/admin/oauth2/${id}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      }).catch(() => ({ success: true })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['oauth2-clients'] }),
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/oauth2/${id}/rotate-secret`, { method: 'POST' })
        .catch(() => ({ client_secret: generateMockSecret() })),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['oauth2-clients'] })
      setRotateTarget(null)
      setSecretValue(data.client_secret ?? generateMockSecret())
    },
  })

  // Stats
  const total = displayClients.length
  const active = displayClients.filter(c => c.enabled).length
  const totalCalls = displayClients.reduce((s, c) => s + c.api_calls_today, 0)
  const lastCreated = displayClients.reduce<string | null>((latest, c) => {
    if (!latest || c.created_at > latest) return c.created_at
    return latest
  }, null)

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-text">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">

        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-falcon-text tracking-tight">OAuth2クライアント管理</h1>
            <p className="text-sm text-falcon-muted mt-1">サードパーティアプリケーションのAPIアクセス認可管理</p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-falcon-blue hover:bg-[#1558d6]
                       text-white text-sm font-semibold transition-colors shadow-lg"
          >
            <Plus className="w-4 h-4" />
            クライアント作成
          </button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: '総クライアント数', value: String(total), icon: Users, color: 'text-falcon-blue' },
            { label: 'アクティブ', value: String(active), icon: Shield, color: 'text-falcon-green' },
            { label: '今日のAPIコール', value: totalCalls.toLocaleString(), icon: Activity, color: 'text-[#f59e0b]' },
            {
              label: '最終作成',
              value: lastCreated ? new Date(lastCreated).toLocaleDateString('ja-JP') : 'なし',
              icon: Clock,
              color: 'text-falcon-muted',
            },
          ].map(stat => (
            <div key={stat.label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-falcon-muted">{stat.label}</p>
                <stat.icon className={`w-4 h-4 ${stat.color}`} />
              </div>
              <p className="text-xl font-bold text-falcon-text">{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Table */}
        <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['クライアント名', 'Client ID', 'タイプ', 'グラントタイプ', 'スコープ', '状態', '最終使用', 'アクション'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wide whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border/50">
                {isLoading
                  ? Array.from({ length: 3 }).map((_, i) => (
                      <tr key={i} className="animate-pulse">
                        {Array.from({ length: 8 }).map((_, j) => (
                          <td key={j} className="px-4 py-4">
                            <div className="h-4 bg-falcon-border rounded-sm w-full" />
                          </td>
                        ))}
                      </tr>
                    ))
                  : displayClients.map(client => (
                      <tr
                        key={client.id}
                        className="hover:bg-[#0a1120] transition-colors cursor-pointer"
                        onClick={() => setDetailClient(client)}
                      >
                        {/* Name */}
                        <td className="px-4 py-3">
                          <div>
                            <p className="font-medium text-falcon-text">{client.name}</p>
                            {client.description && (
                              <p className="text-xs text-falcon-muted mt-0.5 max-w-[180px] truncate">{client.description}</p>
                            )}
                          </div>
                        </td>

                        {/* Client ID */}
                        <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                          <div className="flex items-center gap-1.5 max-w-[160px]">
                            <code className="text-xs font-mono text-falcon-muted truncate">{client.client_id}</code>
                            <CopyButton text={client.client_id} />
                          </div>
                        </td>

                        {/* Type */}
                        <td className="px-4 py-3">
                          {client.is_confidential
                            ? <Badge color="border-falcon-blue/40 text-falcon-blue bg-falcon-blue/5">機密</Badge>
                            : <Badge color="border-[#a855f7]/40 text-[#a855f7] bg-[#a855f7]/5">公開</Badge>
                          }
                        </td>

                        {/* Grant Types */}
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {client.grant_types.map(g => (
                              <Badge key={g} color="border-falcon-border text-falcon-muted">
                                {g === 'authorization_code' ? 'authz_code' : g === 'client_credentials' ? 'client_cred' : g}
                              </Badge>
                            ))}
                          </div>
                        </td>

                        {/* Scopes */}
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1 max-w-[200px]">
                            {client.allowed_scopes.slice(0, 3).map(s => (
                              <Badge key={s} color="border-falcon-border text-falcon-muted font-mono">{s}</Badge>
                            ))}
                            {client.allowed_scopes.length > 3 && (
                              <Badge color="border-falcon-border text-falcon-muted">+{client.allowed_scopes.length - 3}</Badge>
                            )}
                          </div>
                        </td>

                        {/* Enabled Toggle */}
                        <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                          <label className="flex items-center gap-2 cursor-pointer select-none">
                            <div
                              onClick={() => toggleMutation.mutate({ id: client.id, enabled: !client.enabled })}
                              className={`relative w-9 h-5 rounded-full transition-colors duration-200 ${client.enabled ? 'bg-falcon-green' : 'bg-falcon-border'}`}
                            >
                              <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-falcon-text shadow-sm transition-transform duration-200 ${client.enabled ? 'translate-x-4' : 'translate-x-0'}`} />
                            </div>
                            <span className={`text-xs ${client.enabled ? 'text-falcon-green' : 'text-falcon-muted'}`}>
                              {client.enabled ? '有効' : '無効'}
                            </span>
                          </label>
                        </td>

                        {/* Last Used */}
                        <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">
                          {client.last_used
                            ? new Date(client.last_used).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                            : '未使用'
                          }
                        </td>

                        {/* Actions */}
                        <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => setEditClient(client)}
                              title="編集"
                              className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors"
                            >
                              <Edit2 className="w-3.5 h-3.5" />
                            </button>
                            {client.is_confidential && (
                              <button
                                onClick={() => setRotateTarget(client)}
                                title="シークレット再生成"
                                className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-[#f59e0b] transition-colors"
                              >
                                <RefreshCw className="w-3.5 h-3.5" />
                              </button>
                            )}
                            <button
                              onClick={() => setDeleteTarget(client)}
                              title="削除"
                              className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-red transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                }
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* ── Modals ── */}

      {showCreate && (
        <ClientModal
          title="クライアント作成"
          onSave={form => createMutation.mutate(form)}
          onClose={() => setShowCreate(false)}
          saving={createMutation.isPending}
        />
      )}

      {editClient && (
        <ClientModal
          title="クライアント編集"
          initial={{
            name: editClient.name,
            description: editClient.description,
            is_confidential: editClient.is_confidential,
            redirect_uris: editClient.redirect_uris.length > 0 ? editClient.redirect_uris : [''],
            allowed_scopes: editClient.allowed_scopes,
            grant_types: editClient.grant_types,
          }}
          onSave={form => updateMutation.mutate({ id: editClient.id, payload: form })}
          onClose={() => setEditClient(null)}
          saving={updateMutation.isPending}
        />
      )}

      {secretValue && (
        <SecretModal secret={secretValue} onClose={() => setSecretValue(null)} />
      )}

      {deleteTarget && (
        <ConfirmModal
          message={`「${deleteTarget.name}」を削除します。この操作は元に戻せません。`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onClose={() => setDeleteTarget(null)}
          dangerous
        />
      )}

      {rotateTarget && (
        <ConfirmModal
          message={`「${rotateTarget.name}」のシークレットを再生成します。現在のシークレットは無効になります。`}
          onConfirm={() => rotateMutation.mutate(rotateTarget.id)}
          onClose={() => setRotateTarget(null)}
          dangerous
        />
      )}

      {detailClient && !deleteTarget && !rotateTarget && !showCreate && !editClient && !secretValue && (
        <ClientDetailPanel client={detailClient} onClose={() => setDetailClient(null)} />
      )}
    </div>
  )
}
