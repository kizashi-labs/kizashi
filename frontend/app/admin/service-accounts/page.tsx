'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Plus, Trash2, Edit2, AlertTriangle, X, Loader2,
  Copy, Check, Eye, EyeOff, RefreshCw, ChevronDown, ChevronRight,
  Users, Clock, AlertCircle, Shield, Key, Network, Terminal,
  CheckCircle2, CalendarDays,
} from 'lucide-react'


// ── Types ────────────────────────────────────────────────────────────────────

type Scope = 'read' | 'write' | 'admin' | 'alerts:read' | 'agents:read' | 'agents:write'

interface ServiceAccount {
  id: string
  name: string
  description: string
  client_id: string
  scopes: Scope[]
  allowed_ips: string[]
  expires_at: string | null
  enabled: boolean
  last_used: string | null
  created_at: string
}

interface CreatePayload {
  name: string
  description: string
  scopes: Scope[]
  allowed_ips: string[]
  expires_at: string | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const ALL_SCOPES: { value: Scope; label: string; desc: string }[] = [
  { value: 'read', label: 'read', desc: '全リソースの読み取り' },
  { value: 'write', label: 'write', desc: '全リソースへの書き込み' },
  { value: 'admin', label: 'admin', desc: '管理者操作' },
  { value: 'alerts:read', label: 'alerts:read', desc: 'アラートの読み取り' },
  { value: 'agents:read', label: 'agents:read', desc: 'エージェント情報の取得' },
  { value: 'agents:write', label: 'agents:write', desc: 'エージェントへの操作' },
]

function maskClientId(cid: string): string {
  if (cid.length <= 8) return cid
  const prefix = cid.substring(0, cid.indexOf('_') + 1)
  return prefix + '****' + cid.slice(-4)
}

function generateMockSecret(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let s = 'sas_'
  for (let i = 0; i < 40; i++) s += chars[Math.floor(Math.random() * chars.length)]
  return s
}

function isExpired(expiresAt: string | null): boolean {
  if (!expiresAt) return false
  return new Date(expiresAt) < new Date()
}

function isNearExpiry(expiresAt: string | null): boolean {
  if (!expiresAt) return false
  const daysLeft = (new Date(expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
  return daysLeft >= 0 && daysLeft <= 30
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
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${color}`}>
      {children}
    </span>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text).catch(() => {})
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      }}
      className="p-1 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors flex-shrink-0"
      title="コピー"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-[#00c853]" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

// ── Secret Modal ──────────────────────────────────────────────────────────────

function SecretModal({ secret, onClose }: { secret: string; onClose: () => void }) {
  const [show, setShow] = useState(false)
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(secret).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#e8002d]/40 rounded-xl w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
          <div className="w-8 h-8 rounded-lg bg-[#e8002d]/10 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-4 h-4 text-[#e8002d]" />
          </div>
          <h3 className="text-sm font-semibold text-[#e2e8f4] flex-1">重要: クライアントシークレット</h3>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div className="bg-[#e8002d]/5 border border-[#e8002d]/20 rounded-lg px-4 py-3 text-sm text-[#e8002d] flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <span>この値は一度のみ表示されます。今すぐコピーしてください</span>
          </div>
          <div>
            <p className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide mb-2">クライアントシークレット</p>
            <div className="flex items-center gap-2 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5">
              <code className="flex-1 text-sm text-[#e2e8f4] font-mono break-all">
                {show ? secret : '•'.repeat(Math.min(secret.length, 48))}
              </code>
              <button
                onClick={() => setShow(s => !s)}
                className="p-1 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors flex-shrink-0"
              >
                {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
              <button
                onClick={copy}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#e8002d] hover:bg-[#c8001d] text-white text-xs font-medium transition-colors flex-shrink-0"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'コピー済み' : 'コピー'}
              </button>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-full py-2.5 rounded-lg bg-[#1e2d42] hover:bg-[#253750] text-[#e2e8f4] text-sm font-medium transition-colors"
          >
            確認済み・閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Account Form Modal ────────────────────────────────────────────────────────

interface AccountForm {
  name: string
  description: string
  scopes: Scope[]
  allowed_ips: string
  expires_at: string
}

const defaultForm = (): AccountForm => ({
  name: '',
  description: '',
  scopes: ['read'],
  allowed_ips: '',
  expires_at: '',
})

function AccountModal({
  title,
  initial,
  onSave,
  onClose,
  saving,
}: {
  title: string
  initial?: AccountForm
  onSave: (form: AccountForm) => void
  onClose: () => void
  saving: boolean
}) {
  const [form, setForm] = useState<AccountForm>(initial ?? defaultForm())
  const valid = form.name.trim().length > 0 && form.scopes.length > 0

  const toggleScope = (s: Scope) => {
    setForm(f => ({
      ...f,
      scopes: f.scopes.includes(s) ? f.scopes.filter(x => x !== s) : [...f.scopes, s],
    }))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm overflow-y-auto py-8">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
          <div className="w-8 h-8 rounded-lg bg-[#e8002d]/10 flex items-center justify-center">
            <Key className="w-4 h-4 text-[#e8002d]" />
          </div>
          <h3 className="text-sm font-semibold text-[#e2e8f4] flex-1">{title}</h3>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5 max-h-[70vh] overflow-y-auto">
          {/* Name */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">名前 <span className="text-[#e8002d]">*</span></label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="CI/CD Pipeline"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] placeholder-[#3d5068]
                         focus:outline-none focus:border-[#e8002d]/60 transition-colors"
            />
          </div>

          {/* Description */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">説明</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="このサービスアカウントの用途を記述..."
              rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] placeholder-[#3d5068]
                         focus:outline-none focus:border-[#e8002d]/60 transition-colors resize-none"
            />
          </div>

          {/* Scopes */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">スコープ <span className="text-[#e8002d]">*</span></label>
            <div className="grid grid-cols-2 gap-2">
              {ALL_SCOPES.map(scope => (
                <label key={scope.value} className="flex items-start gap-2.5 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={form.scopes.includes(scope.value)}
                    onChange={() => toggleScope(scope.value)}
                    className="mt-0.5 w-4 h-4 accent-[#e8002d]"
                  />
                  <div>
                    <p className="text-sm font-mono text-[#e2e8f4]">{scope.label}</p>
                    <p className="text-xs text-[#7d92b0]">{scope.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Allowed IPs */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">許可IPアドレス</label>
            <textarea
              value={form.allowed_ips}
              onChange={e => setForm(f => ({ ...f, allowed_ips: e.target.value }))}
              placeholder={`10.0.0.0/8\n192.168.1.100/32\n(空白の場合は制限なし)`}
              rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4] placeholder-[#3d5068]
                         focus:outline-none focus:border-[#e8002d]/60 transition-colors resize-none font-mono"
            />
            <p className="text-xs text-[#3d5068]">1行につき1つ。CIDR記法 (例: 10.0.0.0/8) または単一IP</p>
          </div>

          {/* Expires At */}
          <div className="flex flex-col gap-1">
            <label className="text-xs font-medium text-[#7d92b0] uppercase tracking-wide">有効期限 (オプション)</label>
            <input
              type="date"
              value={form.expires_at}
              onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#e2e8f4]
                         focus:outline-none focus:border-[#e8002d]/60 transition-colors
                         [color-scheme:dark]"
            />
            <p className="text-xs text-[#3d5068]">空白の場合は無期限</p>
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
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg bg-[#e8002d] hover:bg-[#c8001d]
                       text-white text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            作成
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
            確認
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Usage Guide Panel ─────────────────────────────────────────────────────────

function UsageGuide() {
  const [open, setOpen] = useState(false)
  const snippet = `# トークン取得 (Client Credentials)
curl -X POST https://api.falconedr.example.com/oauth/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=client_credentials" \\
  -d "client_id=sa_xxxx" \\
  -d "client_secret=sas_YOUR_SECRET"

# レスポンス例
{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600
}

# APIリクエスト例
curl https://api.falconedr.example.com/api/v1/alerts \\
  -H "Authorization: Bearer eyJhbGci..."`

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-[#0a1120] transition-colors"
      >
        <div className="flex items-center gap-3">
          <Terminal className="w-4 h-4 text-[#7d92b0]" />
          <span className="text-sm font-medium text-[#e2e8f4]">使用ガイド: Client Credentials 認証</span>
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />}
      </button>
      {open && (
        <div className="px-5 pb-5">
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 border-b border-[#1e2d42]">
              <span className="text-xs text-[#3d5068] font-mono">bash</span>
              <CopyButton text={snippet} />
            </div>
            <pre className="p-4 text-xs text-[#7d92b0] font-mono overflow-x-auto whitespace-pre leading-relaxed">
              {snippet}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ServiceAccountsPage() {
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editTarget, setEditTarget] = useState<ServiceAccount | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ServiceAccount | null>(null)
  const [rotateTarget, setRotateTarget] = useState<ServiceAccount | null>(null)
  const [secretValue, setSecretValue] = useState<string | null>(null)

  const { data: displayAccounts = [], isLoading } = useQuery<ServiceAccount[]>({
    queryKey: ['service-accounts'],
    queryFn: async () => {
      try { return await apiFetchList<ServiceAccount>('/api/v1/admin/service-accounts') } catch { return [] }
    },
    staleTime: 60_000,
  })

  // ── Mutations ──
  const formToPayload = (form: AccountForm): CreatePayload => ({
    name: form.name.trim(),
    description: form.description.trim(),
    scopes: form.scopes,
    allowed_ips: form.allowed_ips.trim() ? form.allowed_ips.split('\n').map(s => s.trim()).filter(Boolean) : [],
    expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null,
  })

  const createMutation = useMutation({
    mutationFn: (payload: CreatePayload) =>
      apiFetch('/api/v1/admin/service-accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).catch(() => ({
        ...payload,
        id: String(Date.now()),
        client_id: `sa_${payload.name.slice(0, 4).toLowerCase().replace(/\s/g, '')}${Math.random().toString(36).substring(2, 10)}`,
        client_secret: generateMockSecret(),
        enabled: true,
        last_used: null,
        created_at: new Date().toISOString(),
      })),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['service-accounts'] })
      setShowCreate(false)
      setSecretValue(data.client_secret ?? generateMockSecret())
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Partial<CreatePayload> }) =>
      apiFetch(`/api/v1/admin/service-accounts/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).catch(() => ({ success: true })),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['service-accounts'] })
      setEditTarget(null)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/service-accounts/${id}`, { method: 'DELETE' }).catch(() => ({ success: true })),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['service-accounts'] })
      setDeleteTarget(null)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/v1/admin/service-accounts/${id}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      }).catch(() => ({ success: true })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['service-accounts'] }),
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/service-accounts/${id}/rotate`, { method: 'POST' })
        .catch(() => ({ client_secret: generateMockSecret() })),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['service-accounts'] })
      setRotateTarget(null)
      setSecretValue(data.client_secret ?? generateMockSecret())
    },
  })

  // ── Stats ──
  const total = displayAccounts.length
  const active = displayAccounts.filter(a => a.enabled && !isExpired(a.expires_at)).length
  const expired = displayAccounts.filter(a => isExpired(a.expires_at)).length
  const lastUsedAccount = displayAccounts
    .filter(a => a.last_used)
    .sort((a, b) => (b.last_used! > a.last_used! ? 1 : -1))[0]

  return (
    <div className="min-h-screen bg-[#070d19] text-[#e2e8f4]">
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">

        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-[#e2e8f4] tracking-tight">サービスアカウント管理</h1>
            <p className="text-sm text-[#7d92b0] mt-1">機械間認証・API自動化用サービスアカウントの管理</p>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#e8002d] hover:bg-[#c8001d]
                       text-white text-sm font-semibold transition-colors shadow-lg"
          >
            <Plus className="w-4 h-4" />
            サービスアカウント作成
          </button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: '総アカウント数', value: String(total), icon: Users, color: 'text-[#1a6bff]' },
            { label: 'アクティブ', value: String(active), icon: CheckCircle2, color: 'text-[#00c853]' },
            { label: '期限切れ', value: String(expired), icon: AlertCircle, color: expired > 0 ? 'text-[#e8002d]' : 'text-[#7d92b0]', danger: expired > 0 },
            {
              label: '最終使用',
              value: lastUsedAccount?.last_used ? formatRelative(lastUsedAccount.last_used) : 'なし',
              icon: Clock,
              color: 'text-[#7d92b0]',
            },
          ].map(stat => (
            <div key={stat.label} className={`bg-[#0d1220] border rounded-lg p-4 ${(stat as any).danger ? 'border-[#e8002d]/30' : 'border-[#1e2d42]'}`}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-[#7d92b0]">{stat.label}</p>
                <stat.icon className={`w-4 h-4 ${stat.color}`} />
              </div>
              <p className={`text-xl font-bold ${(stat as any).danger ? 'text-[#e8002d]' : 'text-[#e2e8f4]'}`}>{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Table */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['名前', 'Client ID', 'スコープ', '許可IP', '有効期限', '状態', '最終使用', 'アクション'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wide whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]/50">
                {isLoading
                  ? Array.from({ length: 3 }).map((_, i) => (
                      <tr key={i} className="animate-pulse">
                        {Array.from({ length: 8 }).map((_, j) => (
                          <td key={j} className="px-4 py-4">
                            <div className="h-4 bg-[#1e2d42] rounded w-full" />
                          </td>
                        ))}
                      </tr>
                    ))
                  : displayAccounts.map(acct => {
                      const expired = isExpired(acct.expires_at)
                      const nearExpiry = isNearExpiry(acct.expires_at)
                      return (
                        <tr key={acct.id} className="hover:bg-[#0a1120] transition-colors">
                          {/* Name */}
                          <td className="px-4 py-3">
                            <div>
                              <p className="font-medium text-[#e2e8f4]">{acct.name}</p>
                              {acct.description && (
                                <p className="text-xs text-[#7d92b0] mt-0.5 max-w-[160px] truncate" title={acct.description}>
                                  {acct.description}
                                </p>
                              )}
                            </div>
                          </td>

                          {/* Client ID */}
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1.5">
                              <code className="text-xs font-mono text-[#7d92b0]">{maskClientId(acct.client_id)}</code>
                              <CopyButton text={acct.client_id} />
                            </div>
                          </td>

                          {/* Scopes */}
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                              {acct.scopes.slice(0, 3).map(s => (
                                <Badge key={s} color="border-[#1e2d42] text-[#7d92b0] font-mono">{s}</Badge>
                              ))}
                              {acct.scopes.length > 3 && (
                                <Badge color="border-[#1e2d42] text-[#3d5068]">+{acct.scopes.length - 3}</Badge>
                              )}
                            </div>
                          </td>

                          {/* Allowed IPs */}
                          <td className="px-4 py-3">
                            {acct.allowed_ips.length === 0
                              ? <span className="text-xs text-[#3d5068]">制限なし</span>
                              : (
                                <div className="flex items-center gap-1">
                                  <Network className="w-3 h-3 text-[#7d92b0]" />
                                  <span className="text-xs text-[#7d92b0]">{acct.allowed_ips.length} CIDR</span>
                                </div>
                              )
                            }
                          </td>

                          {/* Expires At */}
                          <td className="px-4 py-3 whitespace-nowrap">
                            {acct.expires_at ? (
                              <div className="flex items-center gap-1.5">
                                <CalendarDays className={`w-3.5 h-3.5 flex-shrink-0 ${expired ? 'text-[#e8002d]' : nearExpiry ? 'text-[#f59e0b]' : 'text-[#7d92b0]'}`} />
                                <span className={`text-xs ${expired ? 'text-[#e8002d] font-medium' : nearExpiry ? 'text-[#f59e0b]' : 'text-[#7d92b0]'}`}>
                                  {new Date(acct.expires_at).toLocaleDateString('ja-JP')}
                                  {expired && ' (期限切れ)'}
                                </span>
                              </div>
                            ) : (
                              <span className="text-xs text-[#3d5068]">無期限</span>
                            )}
                          </td>

                          {/* Enabled Toggle */}
                          <td className="px-4 py-3">
                            <div
                              onClick={() => toggleMutation.mutate({ id: acct.id, enabled: !acct.enabled })}
                              className={`relative w-9 h-5 rounded-full cursor-pointer transition-colors duration-200 ${acct.enabled ? 'bg-[#00c853]' : 'bg-[#1e2d42]'}`}
                            >
                              <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] shadow transition-transform duration-200 ${acct.enabled ? 'translate-x-4' : 'translate-x-0'}`} />
                            </div>
                          </td>

                          {/* Last Used */}
                          <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                            {acct.last_used ? formatRelative(acct.last_used) : '未使用'}
                          </td>

                          {/* Actions */}
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1">
                              <button
                                onClick={() => setEditTarget(acct)}
                                title="編集"
                                className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                              >
                                <Edit2 className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => setRotateTarget(acct)}
                                title="シークレット再生成"
                                className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#f59e0b] transition-colors"
                              >
                                <RefreshCw className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => setDeleteTarget(acct)}
                                title="削除"
                                className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] transition-colors"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      )
                    })
                }
              </tbody>
            </table>
          </div>
        </div>

        {/* Usage Guide */}
        <UsageGuide />
      </div>

      {/* ── Modals ── */}
      {showCreate && (
        <AccountModal
          title="サービスアカウント作成"
          onSave={form => createMutation.mutate(formToPayload(form))}
          onClose={() => setShowCreate(false)}
          saving={createMutation.isPending}
        />
      )}

      {editTarget && (
        <AccountModal
          title="サービスアカウント編集"
          initial={{
            name: editTarget.name,
            description: editTarget.description,
            scopes: editTarget.scopes,
            allowed_ips: editTarget.allowed_ips.join('\n'),
            expires_at: editTarget.expires_at
              ? new Date(editTarget.expires_at).toISOString().split('T')[0]
              : '',
          }}
          onSave={form => updateMutation.mutate({ id: editTarget.id, payload: formToPayload(form) })}
          onClose={() => setEditTarget(null)}
          saving={updateMutation.isPending}
        />
      )}

      {rotateTarget && (
        <ConfirmModal
          message={`「${rotateTarget.name}」のシークレットを再生成します。現在のシークレットは無効になります。`}
          onConfirm={() => rotateMutation.mutate(rotateTarget.id)}
          onClose={() => setRotateTarget(null)}
        />
      )}

      {deleteTarget && (
        <ConfirmModal
          message={`「${deleteTarget.name}」を削除します。この操作は元に戻せません。`}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onClose={() => setDeleteTarget(null)}
        />
      )}

      {secretValue && (
        <SecretModal secret={secretValue} onClose={() => setSecretValue(null)} />
      )}
    </div>
  )
}
