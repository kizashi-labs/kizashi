'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Key, Plus, Trash2, RefreshCw, X, Copy, Check,
  CheckCircle, XCircle, Clock, Shield, AlertTriangle,
  Eye, EyeOff
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { SaveFailed, saveErrorOf } from '@/lib/persist'

// ── Types ──────────────────────────────────────────────────────────────────────

type KeyStatus = 'active' | 'expired' | 'revoked'
type Expiry = 'never' | '30d' | '90d' | '1y'

interface ApiKey {
  id: string
  prefix: string
  name: string
  scopes: string[]
  created_at: string
  expires_at?: string
  last_used_at?: string
  status: KeyStatus
}

interface NewKeyResponse {
  id: string
  key: string
  prefix: string
  name: string
  scopes: string[]
  created_at: string
  expires_at?: string
}

// Backend shapes (field names differ from frontend)
interface BackendApiKey {
  id: string
  name: string
  key_prefix: string
  user_id: string
  role: string
  scopes: string[]
  expires_at?: string | null
  last_used?: string | null
  enabled: boolean
  created_at: string
}

interface BackendCreateResponse {
  key: string
  api_key: BackendApiKey
}

function mapBackendKey(k: BackendApiKey): ApiKey {
  const expired = k.expires_at ? new Date(k.expires_at).getTime() < Date.now() : false
  const status: KeyStatus = !k.enabled ? 'revoked' : expired ? 'expired' : 'active'
  return {
    id: k.id,
    prefix: k.key_prefix ?? '',
    name: k.name,
    scopes: k.scopes ?? [],
    created_at: k.created_at,
    expires_at: k.expires_at ?? undefined,
    last_used_at: k.last_used ?? undefined,
    status,
  }
}

function mapCreateResponse(r: BackendCreateResponse): NewKeyResponse {
  const ak = r.api_key ?? {} as BackendApiKey
  return {
    id: ak.id ?? '',
    key: r.key,
    prefix: ak.key_prefix ?? '',
    name: ak.name ?? '',
    scopes: ak.scopes ?? [],
    created_at: ak.created_at ?? new Date().toISOString(),
    expires_at: ak.expires_at ?? undefined,
  }
}

// ── Scope definitions ──────────────────────────────────────────────────────────

const SCOPES: { id: string; label: string; description: string; dangerous?: boolean }[] = [
  { id: 'read:alerts', label: 'アラート読み取り', description: 'アラートの一覧・詳細を参照' },
  { id: 'write:alerts', label: 'アラート書き込み', description: 'アラートの作成・更新・解決' },
  { id: 'read:agents', label: 'エンドポイント読み取り', description: 'エンドポイント一覧・状態を参照' },
  { id: 'write:agents', label: 'エンドポイント書き込み', description: 'エンドポイントの管理・隔離・修復' },
  { id: 'read:rules', label: 'ルール読み取り', description: '検知ルール・ポリシーを参照' },
  { id: 'write:rules', label: 'ルール書き込み', description: '検知ルールの作成・変更' },
  { id: 'read:reports', label: 'レポート読み取り', description: 'レポート・エクスポートを参照' },
  { id: 'admin', label: '管理者', description: '全機能への完全なアクセス権', dangerous: true },
]

// ── Helpers ────────────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<KeyStatus, string> = {
  active:  'bg-green-900/30 text-green-400 border border-green-700/30',
  expired: 'bg-red-900/30 text-red-400 border border-red-700/30',
  revoked: 'bg-zinc-700/30 text-zinc-500 border border-zinc-600/30',
}

function fmtDate(iso?: string): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString() } catch { return '—' }
}

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

function daysUntil(iso?: string): number | null {
  if (!iso) return null
  const diff = new Date(iso).getTime() - Date.now()
  return Math.floor(diff / (24 * 3600 * 1000))
}

// ── Generate Key Modal ─────────────────────────────────────────────────────────

interface GenerateModalProps {
  onClose: () => void
  onCreated: (key: NewKeyResponse) => void
}

function GenerateModal({ onClose, onCreated }: GenerateModalProps) {
  const [name, setName] = useState('')
  const [selectedScopes, setSelectedScopes] = useState<string[]>([])
  const [expiry, setExpiry] = useState<Expiry>('never')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function toggleScope(id: string) {
    setSelectedScopes(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name) { setError('キー名を入力してください。'); return }
    if (selectedScopes.length === 0) { setError('スコープを1つ以上選択してください。'); return }
    setSaving(true)
    setError('')
    try {
      const expiresInDays = expiry === 'never' ? undefined
        : expiry === '30d' ? 30
        : expiry === '90d' ? 90
        : 365
      const raw = await apiFetch<BackendCreateResponse>('/api/v1/apikeys', {
        method: 'POST',
        body: JSON.stringify({ name, scopes: selectedScopes, expires_in_days: expiresInDays }),
      })
      onCreated(mapCreateResponse(raw))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'APIキーの作成に失敗しました。')
    }
    setSaving(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-lg mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-700">
          <h2 className="text-lg font-semibold text-zinc-100">新規APIキー発行</h2>
          <button onClick={onClose} className="text-zinc-400 hover:text-zinc-200 transition-colors"><X className="h-5 w-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {error && <div className="text-red-400 text-sm bg-red-900/20 border border-red-700/40 rounded-sm px-3 py-2">{error}</div>}

          <div>
            <label className="block text-xs text-zinc-400 mb-1">キー名</label>
            <input value={name} onChange={e => setName(e.target.value)}
              className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500" placeholder="例: SIEM連携" />
          </div>

          <div>
            <label className="block text-xs text-zinc-400 mb-1">有効期限</label>
            <div className="flex gap-2">
              {(['never', '30d', '90d', '1y'] as Expiry[]).map(e => (
                <button key={e} type="button" onClick={() => setExpiry(e)}
                  className={`flex-1 py-2 text-xs rounded-lg border transition-colors ${expiry === e ? 'bg-blue-600 border-blue-500 text-white' : 'bg-zinc-800 border-zinc-600 text-zinc-400 hover:border-zinc-500'}`}>
                  {e === 'never' ? 'なし' : e === '30d' ? '30日' : e === '90d' ? '90日' : '1年'}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs text-zinc-400 mb-2">スコープ</label>
            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {SCOPES.map(s => (
                <label key={s.id} className="flex items-start gap-3 cursor-pointer group">
                  <input type="checkbox" checked={selectedScopes.includes(s.id)} onChange={() => toggleScope(s.id)}
                    className="mt-0.5 accent-blue-500 shrink-0" />
                  <div>
                    <div className={`text-xs font-medium ${s.dangerous ? 'text-red-400' : 'text-zinc-300'}`}>
                      {s.label}
                      {s.dangerous && <span className="ml-1.5 text-xs bg-red-900/40 text-red-400 px-1.5 py-0.5 rounded-sm border border-red-700/30">危険</span>}
                    </div>
                    <div className="text-xs text-zinc-600">{s.description}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors">キャンセル</button>
            <button type="submit" disabled={saving}
              className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center gap-2">
              {saving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Key className="h-4 w-4" />}
              発行する
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Show New Key Modal ─────────────────────────────────────────────────────────

interface ShowKeyModalProps {
  keyData: NewKeyResponse
  onClose: () => void
}

function ShowKeyModal({ keyData, onClose }: ShowKeyModalProps) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(keyData.key).catch(() => fallbackCopy(keyData.key))
    } else {
      fallbackCopy(keyData.key)
    }
    setCopied(true)
    setTimeout(() => setCopied(false), 3000)
  }

  function fallbackCopy(text: string) {
    const el = document.createElement('textarea')
    el.value = text
    el.style.position = 'fixed'
    el.style.opacity = '0'
    document.body.appendChild(el)
    el.select()
    document.execCommand('copy')
    document.body.removeChild(el)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-lg mx-4">
        <div className="px-6 py-4 border-b border-zinc-700">
          <div className="flex items-center gap-2 text-yellow-400 mb-1">
            <AlertTriangle className="h-5 w-5" />
            <h2 className="text-lg font-semibold text-zinc-100">今すぐキーをコピーしてください</h2>
          </div>
          <p className="text-sm text-zinc-400">このキーは一度しか表示されません。安全な場所に保管してください。</p>
        </div>
        <div className="p-6 space-y-4">
          <div className="bg-zinc-950 border border-yellow-700/40 rounded-lg p-4">
            <div className="text-xs text-zinc-500 mb-2 font-medium">APIキー</div>
            <div className="font-mono text-sm text-yellow-300 break-all leading-relaxed">{keyData.key}</div>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs text-zinc-500">
            <div><span className="text-zinc-600">名前:</span> <span className="text-zinc-300">{keyData.name}</span></div>
            <div><span className="text-zinc-600">有効期限:</span> <span className="text-zinc-300">{keyData.expires_at ? fmtDate(keyData.expires_at) : 'なし'}</span></div>
            <div className="col-span-2">
              <span className="text-zinc-600">スコープ:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {(keyData.scopes ?? []).map(s => (
                  <span key={s} className="px-1.5 py-0.5 bg-zinc-800 text-zinc-400 rounded-sm border border-zinc-700 text-xs font-mono">{s}</span>
                ))}
              </div>
            </div>
          </div>

          <div className="flex justify-end gap-3">
            <button onClick={handleCopy}
              className={`flex items-center gap-2 px-4 py-2 text-sm rounded-lg transition-colors font-medium ${copied ? 'bg-green-600 text-white' : 'bg-yellow-600 hover:bg-yellow-500 text-white'}`}>
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              {copied ? 'コピーしました！' : 'コピー'}
            </button>
            <button onClick={onClose}
              className="px-4 py-2 text-sm bg-zinc-700 hover:bg-zinc-600 text-zinc-100 rounded-lg transition-colors">
              保存しました
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ApiKeysPage() {
  const qc = useQueryClient()
  const [showGenerate, setShowGenerate] = useState(false)
  const [newKey, setNewKey] = useState<NewKeyResponse | null>(null)

  const { data: keys = [] } = useQuery<ApiKey[]>({
    queryKey: ['admin-apikeys'],
    queryFn: async () => {
      try {
        const res = await apiFetch<BackendApiKey[] | { api_keys: BackendApiKey[] }>('/api/v1/apikeys')
        const raw = Array.isArray(res) ? res : (res as { api_keys: BackendApiKey[] }).api_keys ?? []
        return raw.map(mapBackendKey)
      } catch { return [] }
    },
  })

  const revokeMut = useMutation({
    // .catch(() => {}) が失敗を成功に変えていました。APIキーの失効が
    // 効かないまま「失効しました」になるので、生きている鍵を止めたと
    // 思い込みます。
    mutationFn: (id: string) => apiFetch(`/api/v1/apikeys/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-apikeys'] }),
  })

  function handleCreated(key: NewKeyResponse) {
    setShowGenerate(false)
    setNewKey(key)
    qc.invalidateQueries({ queryKey: ['admin-apikeys'] })
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <PageDataUnavailable />
      <SaveFailed error={saveErrorOf('APIキーの失効', revokeMut)} />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-yellow-900/40 border border-yellow-700/40 flex items-center justify-center">
            <Key className="h-5 w-5 text-yellow-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">APIキー管理</h1>
            <p className="text-sm text-zinc-400">外部ツールのプログラムアクセスを管理</p>
          </div>
        </div>
        <button onClick={() => setShowGenerate(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors font-medium">
          <Plus className="h-4 w-4" />
          新規キー発行
        </button>
      </div>

      {/* Explanation Banner */}
      <div className="bg-blue-900/20 border border-blue-700/40 rounded-xl p-4 mb-6 flex items-start gap-3">
        <Shield className="h-5 w-5 text-blue-400 shrink-0 mt-0.5" />
        <div className="text-sm text-blue-300">
          APIキーを使用すると、外部ツール（SIEM、SOAR、スクリプト）からEDRプラットフォームにプログラムでアクセスできます。
          必要最小限のスコープを使用してください。定期的にキーをローテーションし、不要なキーは無効化してください。
        </div>
      </div>

      {/* Keys Table */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden mb-6">
        <div className="px-5 py-3 border-b border-zinc-700 bg-zinc-800/30">
          <h2 className="text-sm font-medium text-zinc-300">APIキー {keys.length}件</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700 bg-zinc-800/20">
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">キー</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">名前</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">スコープ</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">作成日</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">有効期限</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">最終使用</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">状態</th>
              <th className="text-right px-5 py-3 text-xs text-zinc-400 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {keys.map(k => {
              const days = daysUntil(k.expires_at)
              return (
                <tr key={k.id} className={`hover:bg-zinc-800/30 transition-colors ${k.status !== 'active' ? 'opacity-60' : ''}`}>
                  <td className="px-5 py-3">
                    <span className="font-mono text-xs text-zinc-300 bg-zinc-800 px-2 py-1 rounded-sm">{k.prefix}...</span>
                  </td>
                  <td className="px-5 py-3 text-sm text-zinc-200">{k.name}</td>
                  <td className="px-5 py-3">
                    <div className="flex flex-wrap gap-1">
                      {k.scopes.slice(0, 3).map(s => (
                        <span key={s} className="text-xs px-1.5 py-0.5 bg-zinc-800 text-zinc-400 rounded-sm border border-zinc-700 font-mono">{s}</span>
                      ))}
                      {k.scopes.length > 3 && <span className="text-xs text-zinc-600">+{k.scopes.length - 3}</span>}
                    </div>
                  </td>
                  <td className="px-5 py-3 text-xs text-zinc-500">{fmtDate(k.created_at)}</td>
                  <td className="px-5 py-3 text-xs">
                    {k.expires_at ? (
                      <span className={days !== null && days < 30 ? 'text-yellow-400' : days !== null && days < 0 ? 'text-red-400' : 'text-zinc-400'}>
                        {fmtDate(k.expires_at)}
                        {days !== null && days >= 0 && <span className="text-zinc-600 ml-1">({days}d)</span>}
                      </span>
                    ) : (
                      <span className="text-zinc-600">なし</span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-xs text-zinc-500">{fmtRelative(k.last_used_at)}</td>
                  <td className="px-5 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${STATUS_STYLES[k.status]}`}>
                      {k.status === 'active' ? '有効' : k.status === 'expired' ? '期限切れ' : '無効化'}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-right">
                    {k.status === 'active' && (
                      <button onClick={() => { if (confirm(`「${k.name}」を無効化しますか？この操作は元に戻せません。`)) revokeMut.mutate(k.id) }}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-xs text-red-400 border border-red-700/40 rounded-lg hover:bg-red-900/20 transition-colors ml-auto">
                        <Trash2 className="h-3 w-3" />無効化
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Scope Descriptions */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-zinc-700 bg-zinc-800/30">
          <h2 className="text-sm font-medium text-zinc-300">利用可能なスコープ</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700/50 bg-zinc-800/10">
              <th className="text-left px-5 py-2.5 text-xs text-zinc-500 font-medium">スコープ</th>
              <th className="text-left px-5 py-2.5 text-xs text-zinc-500 font-medium">説明</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/50">
            {SCOPES.map(s => (
              <tr key={s.id} className="hover:bg-zinc-800/20">
                <td className="px-5 py-2.5">
                  <span className="font-mono text-xs text-zinc-300">{s.id}</span>
                  {s.dangerous && <span className="ml-2 text-xs bg-red-900/40 text-red-400 px-1.5 py-0.5 rounded-sm border border-red-700/30">管理者</span>}
                </td>
                <td className="px-5 py-2.5 text-xs text-zinc-500">{s.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showGenerate && <GenerateModal onClose={() => setShowGenerate(false)} onCreated={handleCreated} />}
      {newKey && <ShowKeyModal keyData={newKey} onClose={() => setNewKey(null)} />}
    </div>
  )
}
