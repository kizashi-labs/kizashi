'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  KeyRound,
  Plus,
  Copy,
  Check,
  Trash2,
  AlertTriangle,
  Shield,
  ShieldOff,
  Loader2,
  X,
  Eye,
  EyeOff,
  Clock,
  Calendar,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface APIKey {
  id: string
  name: string
  prefix: string
  scopes: string[]
  last_used?: string
  expires_at?: string
  revoked: boolean
  created_at: string
}

interface ListResponse {
  keys: APIKey[]
}

interface CreateResponse {
  key: APIKey
  raw_key: string
}

// ─── Constants ────────────────────────────────────────────────────────────────

const EXPIRY_OPTIONS = [
  { label: '30日', value: 30 },
  { label: '90日', value: 90 },
  { label: '1年', value: 365 },
  { label: '無期限', value: null },
] as const

type ExpiryValue = 30 | 90 | 365 | null

interface ScopeDef {
  value: string
  label: string
  description: string
  badgeClass: string
}

const SCOPE_DEFS: ScopeDef[] = [
  {
    value: 'read:alerts',
    label: 'read:alerts',
    description: 'アラートの読み取り',
    badgeClass: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  },
  {
    value: 'write:alerts',
    label: 'write:alerts',
    description: 'アラートの作成・更新',
    badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  },
  {
    value: 'read:agents',
    label: 'read:agents',
    description: 'エージェント情報の読み取り',
    badgeClass: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
  },
  {
    value: 'manage:rules',
    label: 'manage:rules',
    description: '検知ルールの管理',
    badgeClass: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  },
  {
    value: 'admin',
    label: 'admin',
    description: '全機能への管理者アクセス',
    badgeClass: 'bg-red-500/15 text-red-300 border-red-500/30',
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function isExpired(key: APIKey): boolean {
  if (!key.expires_at) return false
  return new Date(key.expires_at) < new Date()
}

function ScopeBadge({ scope }: { scope: string }) {
  const def = SCOPE_DEFS.find((d) => d.value === scope)
  const cls = def?.badgeClass ?? 'bg-falcon-border text-falcon-muted border-[#2a3d58]'
  return (
    <span className={`text-[11px] px-2 py-0.5 rounded-full border font-medium ${cls}`}>
      {scope}
    </span>
  )
}

// ─── Copy Button ──────────────────────────────────────────────────────────────

function CopyButton({ text, label = 'コピー' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2500)
  }

  return (
    <button
      onClick={handleCopy}
      title="クリップボードにコピー"
      className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-border hover:bg-[#253550] text-falcon-text
                 text-xs rounded-lg transition-colors shrink-0 border border-[#2a3d58]"
    >
      {copied ? (
        <>
          <Check className="w-3.5 h-3.5 text-green-400" />
          <span className="text-green-400">コピー済み</span>
        </>
      ) : (
        <>
          <Copy className="w-3.5 h-3.5" />
          {label}
        </>
      )}
    </button>
  )
}

// ─── New Key Revealed Box ─────────────────────────────────────────────────────

function NewKeyRevealBox({
  rawKey,
  keyName,
  onDismiss,
}: {
  rawKey: string
  keyName: string
  onDismiss: () => void
}) {
  const [visible, setVisible] = useState(false)

  const masked = rawKey.slice(0, 10) + '•'.repeat(Math.max(0, rawKey.length - 10))

  return (
    <div className="mb-6 rounded-xl border border-amber-500/40 bg-amber-500/8 p-5">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 p-1.5 rounded-lg bg-amber-500/15 border border-amber-500/30 shrink-0">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div>
            <p className="text-sm font-semibold text-amber-300">
              APIキー「{keyName}」が作成されました
            </p>
            <p className="text-xs text-amber-400/80 mt-1 leading-relaxed">
              <span className="font-bold text-amber-300">この値は二度と表示されません。</span>
              今すぐ安全な場所（パスワードマネージャー等）にコピーして保管してください。
            </p>
          </div>
        </div>
        <button
          onClick={onDismiss}
          className="text-amber-400/50 hover:text-amber-300 transition-colors shrink-0 mt-0.5"
          title="閉じる"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Key display */}
      <div className="flex items-center gap-3 bg-[#060b12] border border-amber-500/25 rounded-lg px-4 py-3">
        <code className="flex-1 text-sm font-mono text-amber-200 break-all select-all leading-relaxed">
          {visible ? rawKey : masked}
        </code>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setVisible((v) => !v)}
            title={visible ? 'キーを隠す' : 'キーを表示'}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-border hover:bg-[#253550]
                       text-falcon-muted hover:text-falcon-text text-xs rounded-lg transition-colors
                       border border-[#2a3d58]"
          >
            {visible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            {visible ? '隠す' : '表示'}
          </button>
          <CopyButton text={rawKey} label="コピー" />
        </div>
      </div>

      {/* Checklist */}
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-amber-500/70">
        <span>✓ パスワードマネージャーに保存した</span>
        <span>✓ 環境変数として設定する</span>
        <span>✓ ソースコードには書かない</span>
      </div>
    </div>
  )
}

// ─── Warning Banner ───────────────────────────────────────────────────────────

function WarningBanner() {
  return (
    <div className="flex items-start gap-3 px-4 py-3 bg-[#1a1200] border border-yellow-700/40 rounded-xl mb-6">
      <Shield className="w-4 h-4 text-yellow-500 shrink-0 mt-0.5" />
      <p className="text-xs text-yellow-400/90 leading-relaxed">
        <span className="font-semibold text-yellow-300">セキュリティの注意: </span>
        APIキーはパスワードと同様に扱ってください。作成時のみ全文が表示されます。
        漏洩した場合は直ちに失効させ、新しいキーを発行してください。
      </p>
    </div>
  )
}

// ─── Create Modal ─────────────────────────────────────────────────────────────

function CreateModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (rawKey: string, keyName: string) => void
}) {
  const [name, setName] = useState('')
  const [expiryDays, setExpiryDays] = useState<ExpiryValue>(90)
  const [scopes, setScopes] = useState<string[]>(['read:alerts'])
  const [error, setError] = useState('')

  const mutation = useMutation({
    mutationFn: (body: { name: string; expires_in_days: number | null; scopes: string[] }) =>
      apiFetch<CreateResponse>('/api/v1/api-keys', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: (data) => {
      onCreated(data.raw_key, data.key.name)
    },
    onError: (e: unknown) => {
      setError(e instanceof Error ? e.message : 'APIキーの作成に失敗しました')
    },
  })

  const toggleScope = (scope: string) => {
    setScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    )
  }

  const handleSubmit = () => {
    if (!name.trim()) {
      setError('名前を入力してください')
      return
    }
    if (scopes.length === 0) {
      setError('スコープを1つ以上選択してください')
      return
    }
    setError('')
    mutation.mutate({
      name: name.trim(),
      expires_in_days: expiryDays,
      scopes,
    })
  }

  const hasAdmin = scopes.includes('admin')

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 backdrop-blur-xs"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="bg-falcon-surface border border-falcon-border rounded-2xl w-full max-w-md mx-4 shadow-2xl">

        {/* Modal header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-3">
            <div className="p-1.5 bg-falcon-red/10 rounded-lg border border-falcon-red/20">
              <KeyRound className="w-4 h-4 text-falcon-red" />
            </div>
            <h2 className="text-sm font-semibold text-white">新しいAPIキーを作成</h2>
          </div>
          <button
            onClick={onClose}
            className="text-falcon-muted hover:text-falcon-text transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal body */}
        <div className="px-6 py-5 space-y-5">

          {/* Name */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-1.5">
              名前 <span className="text-falcon-red">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例: CI/CDパイプライン、監視スクリプト"
              className="w-full px-3 py-2 bg-[#070d19] border border-falcon-border rounded-lg text-sm
                         text-falcon-text placeholder-[#3a4d66] focus:outline-hidden focus:border-falcon-red/50
                         transition-colors"
            />
          </div>

          {/* Expiry */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-2">
              有効期限
            </label>
            <div className="grid grid-cols-4 gap-2">
              {EXPIRY_OPTIONS.map((opt) => (
                <button
                  key={String(opt.value)}
                  onClick={() => setExpiryDays(opt.value as ExpiryValue)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium border transition-colors ${
                    expiryDays === opt.value
                      ? 'bg-falcon-red/15 border-falcon-red/50 text-falcon-red'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-[#2a3d58] hover:text-falcon-text'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Scopes */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-2">
              スコープ <span className="text-falcon-red">*</span>
              <span className="text-[#3a4d66] font-normal ml-1">— 最小権限の原則を推奨します</span>
            </label>
            <div className="space-y-1.5">
              {SCOPE_DEFS.map((def) => {
                const checked = scopes.includes(def.value)
                const isAdminScope = def.value === 'admin'
                return (
                  <label
                    key={def.value}
                    className={`flex items-center gap-3 px-3 py-2.5 rounded-lg border cursor-pointer
                                transition-colors ${
                      checked
                        ? isAdminScope
                          ? 'bg-red-500/8 border-red-500/30'
                          : 'bg-[#0d1829] border-[#1e3558]'
                        : 'bg-[#070d19] border-falcon-border hover:border-[#253550]'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleScope(def.value)}
                      className="w-3.5 h-3.5 accent-falcon-red shrink-0"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <code className={`text-xs font-mono font-medium ${checked ? 'text-falcon-text' : 'text-falcon-muted'}`}>
                          {def.value}
                        </code>
                        {isAdminScope && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-sm bg-red-500/15 text-red-400 border border-red-500/30 font-medium">
                            高権限
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-[#3a4d66] mt-0.5">{def.description}</p>
                    </div>
                    {checked && <Check className="w-3.5 h-3.5 text-green-400 shrink-0" />}
                  </label>
                )
              })}
            </div>

            {/* Admin scope warning */}
            {hasAdmin && (
              <div className="mt-2 flex items-start gap-2 px-3 py-2 bg-red-500/8 border border-red-500/20 rounded-lg">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                <p className="text-xs text-red-400/90">
                  admin スコープは全機能へのフルアクセスを付与します。本当に必要な場合のみ使用してください。
                </p>
              </div>
            )}
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-start gap-2 px-3 py-2.5 bg-red-500/10 border border-red-500/20 rounded-lg">
              <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}
        </div>

        {/* Modal footer */}
        <div className="flex gap-3 px-6 py-4 border-t border-falcon-border">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-falcon-border hover:bg-[#253550] text-falcon-text
                       text-sm rounded-lg transition-colors border border-[#2a3d58]"
          >
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            disabled={mutation.isPending}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2
                       bg-falcon-red hover:bg-[#c5001f] disabled:opacity-50
                       text-white text-sm rounded-lg transition-colors font-medium"
          >
            {mutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <KeyRound className="w-4 h-4" />
            )}
            キーを作成
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Revoke Confirmation Dialog ───────────────────────────────────────────────

function RevokeDialog({
  keyName,
  onConfirm,
  onCancel,
  isPending,
}: {
  keyName: string
  onConfirm: () => void
  onCancel: () => void
  isPending: boolean
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/65 backdrop-blur-xs"
      onClick={(e) => { if (e.target === e.currentTarget) onCancel() }}
    >
      <div className="bg-falcon-surface border border-red-500/40 rounded-2xl w-full max-w-sm mx-4 shadow-2xl">
        <div className="px-6 py-5">
          <div className="flex items-start gap-4 mb-5">
            <div className="p-2 bg-red-500/10 rounded-xl border border-red-500/25 shrink-0">
              <ShieldOff className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">APIキーを失効させますか？</h3>
              <p className="text-xs text-falcon-muted mt-2 leading-relaxed">
                <span className="font-medium text-falcon-text">"{keyName}"</span>{' '}
                を失効させます。この操作は取り消せません。
                このキーを使用しているすべての連携・スクリプトが即座に動作しなくなります。
              </p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={onCancel}
              className="flex-1 px-4 py-2 bg-falcon-border hover:bg-[#253550] text-falcon-text
                         text-sm rounded-lg transition-colors border border-[#2a3d58]"
            >
              キャンセル
            </button>
            <button
              onClick={onConfirm}
              disabled={isPending}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2
                         bg-red-600 hover:bg-red-700 disabled:opacity-50
                         text-white text-sm rounded-lg transition-colors"
            >
              {isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Trash2 className="w-4 h-4" />
              )}
              失効させる
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Key Row ──────────────────────────────────────────────────────────────────

function KeyRow({ apiKey, onRevoke }: { apiKey: APIKey; onRevoke: (k: APIKey) => void }) {
  const revoked = apiKey.revoked
  const expired = isExpired(apiKey)
  const inactive = revoked || expired

  const statusBadge = () => {
    if (revoked) {
      return (
        <span className="text-[11px] px-2 py-0.5 rounded-full border bg-falcon-border text-falcon-muted border-[#2a3d58] font-medium">
          失効済み
        </span>
      )
    }
    if (expired) {
      return (
        <span className="text-[11px] px-2 py-0.5 rounded-full border bg-orange-500/15 text-orange-400 border-orange-500/30 font-medium">
          期限切れ
        </span>
      )
    }
    return (
      <span className="text-[11px] px-2 py-0.5 rounded-full border bg-green-500/15 text-green-400 border-green-500/30 font-medium">
        有効
      </span>
    )
  }

  return (
    <tr className={`border-t border-falcon-border transition-colors hover:bg-[#0a1118] ${inactive ? 'opacity-50' : ''}`}>
      {/* 名前 / プレフィックス */}
      <td className="px-5 py-3.5">
        <p className={`text-sm font-medium ${inactive ? 'text-falcon-muted' : 'text-white'}`}>
          {apiKey.name}
        </p>
        <code className="text-[11px] text-falcon-subtle font-mono mt-0.5 block">
          {apiKey.prefix}...
        </code>
      </td>

      {/* スコープ */}
      <td className="px-5 py-3.5">
        <div className="flex flex-wrap gap-1">
          {apiKey.scopes.map((s) => (
            <ScopeBadge key={s} scope={s} />
          ))}
        </div>
      </td>

      {/* 最終使用 */}
      <td className="px-5 py-3.5">
        <span className="text-xs text-falcon-muted whitespace-nowrap flex items-center gap-1.5">
          <Clock className="w-3 h-3 text-falcon-subtle shrink-0" />
          {apiKey.last_used ? fmt(apiKey.last_used) : '未使用'}
        </span>
      </td>

      {/* 有効期限 */}
      <td className="px-5 py-3.5">
        <span className={`text-xs whitespace-nowrap flex items-center gap-1.5 ${expired ? 'text-orange-400' : 'text-falcon-muted'}`}>
          <Calendar className="w-3 h-3 text-falcon-subtle shrink-0" />
          {apiKey.expires_at ? fmt(apiKey.expires_at) : '無期限'}
        </span>
      </td>

      {/* 作成日 */}
      <td className="px-5 py-3.5">
        <span className="text-xs text-falcon-muted whitespace-nowrap">
          {fmt(apiKey.created_at)}
        </span>
      </td>

      {/* ステータス */}
      <td className="px-5 py-3.5">{statusBadge()}</td>

      {/* 操作 */}
      <td className="px-5 py-3.5">
        {!revoked && (
          <button
            onClick={() => onRevoke(apiKey)}
            title="このキーを失効させる"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-falcon-muted border border-falcon-border
                       hover:text-red-400 hover:border-red-500/40 hover:bg-red-500/8
                       rounded-lg transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            失効
          </button>
        )}
        {revoked && (
          <span className="text-xs text-falcon-subtle">—</span>
        )}
      </td>
    </tr>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function APIKeysPage() {
  const qc = useQueryClient()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newKeyInfo, setNewKeyInfo] = useState<{ rawKey: string; keyName: string } | null>(null)
  const [revokeTarget, setRevokeTarget] = useState<APIKey | null>(null)

  const { data, isLoading, isError } = useQuery<ListResponse>({
    queryKey: ['api-keys'],
    queryFn: () => apiFetch<ListResponse>('/api/v1/api-keys'),
  })

  const keys = data?.keys ?? []
  const activeCount = keys.filter((k) => !k.revoked && !isExpired(k)).length
  const inactiveCount = keys.length - activeCount

  const revokeMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/api-keys/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
      setRevokeTarget(null)
    },
  })

  const handleCreated = (rawKey: string, keyName: string) => {
    setShowCreateModal(false)
    setNewKeyInfo({ rawKey, keyName })
    qc.invalidateQueries({ queryKey: ['api-keys'] })
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-text">
      <div className="max-w-6xl mx-auto px-6 py-8">

        {/* ── Header ──────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4 mb-6">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 p-2 bg-falcon-red/10 rounded-xl border border-falcon-red/20">
              <KeyRound className="w-5 h-5 text-falcon-red" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">APIキー管理</h1>
              <p className="text-sm text-falcon-muted mt-0.5">
                プログラムからEDRプラットフォームにアクセスするためのAPIキーを発行・管理します
              </p>
            </div>
          </div>
          <button
            onClick={() => { setNewKeyInfo(null); setShowCreateModal(true) }}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c5001f]
                       text-white text-sm rounded-lg transition-colors font-medium shrink-0"
          >
            <Plus className="w-4 h-4" />
            新しいAPIキーを作成
          </button>
        </div>

        {/* ── Warning Banner ──────────────────────────────────── */}
        <WarningBanner />

        {/* ── New Key Reveal ──────────────────────────────────── */}
        {newKeyInfo && (
          <NewKeyRevealBox
            rawKey={newKeyInfo.rawKey}
            keyName={newKeyInfo.keyName}
            onDismiss={() => setNewKeyInfo(null)}
          />
        )}

        {/* ── Stats ───────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl px-5 py-4">
            <p className="text-xs text-falcon-muted mb-1">合計キー数</p>
            <p className="text-2xl font-bold text-white">{keys.length}</p>
          </div>
          <div className="bg-falcon-surface border border-falcon-border rounded-xl px-5 py-4">
            <p className="text-xs text-falcon-muted mb-1">有効</p>
            <p className="text-2xl font-bold text-green-400">{activeCount}</p>
          </div>
          <div className="bg-falcon-surface border border-falcon-border rounded-xl px-5 py-4">
            <p className="text-xs text-falcon-muted mb-1">失効・期限切れ</p>
            <p className="text-2xl font-bold text-falcon-muted">{inactiveCount}</p>
          </div>
        </div>

        {/* ── Loading ─────────────────────────────────────────── */}
        {isLoading && (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 animate-spin text-falcon-red" />
          </div>
        )}

        {/* ── Error ───────────────────────────────────────────── */}
        {isError && !isLoading && (
          <div className="bg-falcon-surface border border-red-500/30 rounded-xl px-5 py-10 text-center">
            <AlertTriangle className="w-6 h-6 text-red-400 mx-auto mb-3" />
            <p className="text-sm text-red-400">APIキー一覧の取得に失敗しました</p>
          </div>
        )}

        {/* ── Empty State ─────────────────────────────────────── */}
        {!isLoading && !isError && keys.length === 0 && (
          <div className="bg-falcon-surface border border-falcon-border rounded-xl flex flex-col items-center justify-center py-16 text-center">
            <div className="p-3 bg-falcon-border rounded-full mb-4">
              <KeyRound className="w-6 h-6 text-falcon-muted" />
            </div>
            <p className="text-sm text-white font-medium">APIキーがありません</p>
            <p className="text-xs text-falcon-muted mt-1 max-w-xs">
              「新しいAPIキーを作成」ボタンから最初のAPIキーを発行してください
            </p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="mt-5 flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c5001f]
                         text-white text-sm rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              最初のキーを作成
            </button>
          </div>
        )}

        {/* ── Keys Table ──────────────────────────────────────── */}
        {!isLoading && !isError && keys.length > 0 && (
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-[#070d19] border-b border-falcon-border">
                    {['名前 / プレフィックス', 'スコープ', '最終使用', '有効期限', '作成日', 'ステータス', '操作'].map((h) => (
                      <th
                        key={h}
                        className="px-5 py-3 text-left text-[11px] font-semibold text-falcon-muted uppercase tracking-wider whitespace-nowrap"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => (
                    <KeyRow key={k.id} apiKey={k} onRevoke={setRevokeTarget} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Security Info Cards ─────────────────────────────── */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl px-5 py-4">
            <div className="flex items-start gap-3">
              <Shield className="w-4 h-4 text-falcon-red shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-white mb-2">セキュリティのベストプラクティス</p>
                <ul className="space-y-1.5 text-xs text-falcon-muted list-none">
                  {[
                    '必要最小限のスコープのみ付与する（最小権限の原則）',
                    '有効期限を設定することを強く推奨する',
                    'キーをソースコードやGitにコミットしない',
                    '環境変数またはシークレット管理ツールで管理する',
                    '不要になったキーは直ちに失効させる',
                    '定期的にキーのローテーションを実施する',
                  ].map((tip) => (
                    <li key={tip} className="flex items-start gap-2">
                      <span className="text-falcon-red mt-0.5 shrink-0">·</span>
                      {tip}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl px-5 py-4">
            <div className="flex items-start gap-3">
              <KeyRound className="w-4 h-4 text-falcon-muted shrink-0 mt-0.5" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-white mb-2">APIキーの使い方</p>
                <p className="text-xs text-falcon-muted mb-2">
                  すべてのAPIリクエストのヘッダーに以下を付与してください:
                </p>
                <code className="block text-xs font-mono bg-[#070d19] border border-falcon-border
                                 rounded-lg px-3 py-2.5 text-[#4a9eff] break-all">
                  Authorization: Bearer &lt;your-api-key&gt;
                </code>
                <p className="text-xs text-falcon-muted mt-3 mb-1.5">cURL の例:</p>
                <code className="block text-[11px] font-mono bg-[#070d19] border border-falcon-border
                                 rounded-lg px-3 py-2.5 text-falcon-muted break-all leading-relaxed">
                  {'curl -H "Authorization: Bearer edr_..."'}<br />
                  {'     https://your-instance/api/v1/alerts'}
                </code>
              </div>
            </div>
          </div>
        </div>

      </div>

      {/* ── Modals ────────────────────────────────────────────── */}
      {showCreateModal && (
        <CreateModal
          onClose={() => setShowCreateModal(false)}
          onCreated={handleCreated}
        />
      )}

      {revokeTarget && (
        <RevokeDialog
          keyName={revokeTarget.name}
          onConfirm={() => revokeMutation.mutate(revokeTarget.id)}
          onCancel={() => setRevokeTarget(null)}
          isPending={revokeMutation.isPending}
        />
      )}
    </div>
  )
}
