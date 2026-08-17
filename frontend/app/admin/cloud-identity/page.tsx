'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Users, Plus, Pencil, Trash2, X, RefreshCw, Filter,
  ToggleLeft, ToggleRight, AlertTriangle, CheckCircle,
  Link as LinkIcon, Unlink, Search, ChevronDown, AlertCircle,
  Building2, Cloud, Shield,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type ProviderType = 'azure_ad' | 'aws_iam' | 'google_workspace' | 'okta' | 'ping_identity'
type SyncStatus = 'synced' | 'syncing' | 'error' | 'pending'
type RiskIndicator = 'stale' | 'mfa_exempt' | 'over_privileged' | 'guest'

interface IdentityProvider {
  id: string
  name: string
  provider_type: ProviderType
  tenant_id: string
  sync_status: SyncStatus
  last_sync: string
  user_count: number
  group_count: number
  enabled: boolean
  config: Record<string, string>
  linked_identities: number
}

interface FederatedIdentity {
  id: string
  display_name: string
  email: string
  provider_id: string
  provider_type: ProviderType
  groups: string[]
  roles: string[]
  local_user_id: string | null
  local_user_name?: string
  last_seen: string
  risk_indicators: RiskIndicator[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PROVIDER_BADGE: Record<ProviderType, string> = {
  azure_ad: 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  aws_iam: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  google_workspace: 'bg-green-500/10 text-green-400 border border-green-500/30',
  okta: 'bg-purple-500/10 text-purple-400 border border-purple-500/30',
  ping_identity: 'bg-gray-500/10 text-gray-400 border border-gray-500/30',
}
const PROVIDER_LABEL: Record<ProviderType, string> = {
  azure_ad: 'Azure AD', aws_iam: 'AWS IAM', google_workspace: 'Google Workspace', okta: 'Okta', ping_identity: 'Ping Identity',
}
const SYNC_BADGE: Record<SyncStatus, string> = {
  synced: 'bg-green-500/10 text-green-400 border border-green-500/30',
  syncing: 'bg-blue-500/10 text-blue-400 border border-blue-500/30 animate-pulse',
  error: 'bg-red-500/10 text-red-400 border border-red-500/30',
  pending: 'bg-gray-500/10 text-gray-400 border border-gray-500/30',
}
const SYNC_LABEL: Record<SyncStatus, string> = {
  synced: '同期済み', syncing: '同期中', error: 'エラー', pending: '待機中',
}
const RISK_BADGE: Record<RiskIndicator, string> = {
  stale: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
  mfa_exempt: 'bg-red-500/10 text-red-400 border border-red-500/30',
  over_privileged: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  guest: 'bg-gray-500/10 text-gray-400 border border-gray-500/30',
}
const RISK_LABEL: Record<RiskIndicator, string> = {
  stale: '長期未利用', mfa_exempt: 'MFA無効', over_privileged: '過剰権限', guest: 'ゲスト',
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

const CONFIG_HINTS: Record<ProviderType, { label: string; placeholder: string }[]> = {
  azure_ad: [{ label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' }, { label: 'Client ID', placeholder: 'app-client-id' }, { label: 'Client Secret', placeholder: '***' }],
  aws_iam: [{ label: 'Role ARN', placeholder: 'arn:aws:iam::123456789012:role/EDRSync' }, { label: 'External ID', placeholder: 'ext-secret' }],
  google_workspace: [{ label: 'Domain', placeholder: 'company.com' }, { label: 'Service Account', placeholder: 'sync@project.iam.gserviceaccount.com' }],
  okta: [{ label: 'Domain', placeholder: 'company.okta.com' }, { label: 'API Token', placeholder: '***' }],
  ping_identity: [{ label: 'Environment ID', placeholder: 'env-id' }, { label: 'Client ID', placeholder: 'client-id' }, { label: 'Client Secret', placeholder: '***' }],
}

// ─── Provider Modal ───────────────────────────────────────────────────────────

interface ProviderModalProps {
  provider?: IdentityProvider
  onClose: () => void
  onSave: (data: Partial<IdentityProvider>) => void
}

function ProviderModal({ provider, onClose, onSave }: ProviderModalProps) {
  const [form, setForm] = useState({
    name: provider?.name ?? '',
    provider_type: provider?.provider_type ?? 'azure_ad' as ProviderType,
    tenant_id: provider?.tenant_id ?? '',
    config_json: provider ? JSON.stringify(provider.config, null, 2) : '{\n  \n}',
  })

  const hints = CONFIG_HINTS[form.provider_type]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-lg">{provider ? 'プロバイダー編集' : '新規プロバイダー追加'}</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white p-1 rounded-sm hover:bg-falcon-border transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-falcon-muted text-sm mb-1.5">プロバイダー名 *</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50" placeholder="例: Azure AD - 本社" />
          </div>
          <div>
            <label className="block text-falcon-muted text-sm mb-1.5">プロバイダータイプ</label>
            <select value={form.provider_type} onChange={e => setForm(f => ({ ...f, provider_type: e.target.value as ProviderType }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              {(Object.keys(PROVIDER_LABEL) as ProviderType[]).map(t => <option key={t} value={t}>{PROVIDER_LABEL[t]}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-falcon-muted text-sm mb-1.5">テナントID / ドメイン</label>
            <input value={form.tenant_id} onChange={e => setForm(f => ({ ...f, tenant_id: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-falcon-red/50" />
          </div>
          <div>
            <label className="block text-falcon-muted text-sm mb-1.5">設定 (JSON)</label>
            <div className="mb-2 p-3 bg-[#070d19] border border-falcon-border rounded-lg">
              <p className="text-xs text-falcon-muted mb-1.5 font-medium">{PROVIDER_LABEL[form.provider_type]} 必要フィールド:</p>
              <div className="space-y-1">
                {hints.map(h => (
                  <div key={h.label} className="flex items-center gap-2 text-xs">
                    <span className="text-falcon-red font-mono">{h.label}:</span>
                    <span className="text-falcon-muted">{h.placeholder}</span>
                  </div>
                ))}
              </div>
            </div>
            <textarea value={form.config_json} onChange={e => setForm(f => ({ ...f, config_json: e.target.value }))} rows={6} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-falcon-red/50 resize-none" />
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-falcon-muted text-sm hover:text-white rounded-lg hover:bg-falcon-border transition-colors">キャンセル</button>
          <button onClick={() => {
            let config = {}
            try { config = JSON.parse(form.config_json) } catch {}
            onSave({ name: form.name, provider_type: form.provider_type, tenant_id: form.tenant_id, config })
          }} className="px-4 py-2 bg-falcon-red text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

// ─── Link Identity Modal ──────────────────────────────────────────────────────

interface LinkModalProps {
  identity: FederatedIdentity
  onClose: () => void
  onLink: (identityId: string, localUserId: string) => void
}

function LinkModal({ identity, onClose, onLink }: LinkModalProps) {
  const [localUserId, setLocalUserId] = useState('')
  const LOCAL_USERS = ['admin', 'tanaka', 'suzuki', 'yamada', 'sato', 'ito', 'nakamura', 'user001', 'user002', 'user003']
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-lg">ローカルユーザーと紐付け</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white p-1 rounded-sm hover:bg-falcon-border transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div className="p-3 bg-[#070d19] border border-falcon-border rounded-lg">
            <p className="text-white text-sm font-medium">{identity.display_name}</p>
            <p className="text-falcon-muted text-xs font-mono mt-0.5">{identity.email}</p>
          </div>
          <div>
            <label className="block text-falcon-muted text-sm mb-1.5">ローカルユーザーを選択</label>
            <select value={localUserId} onChange={e => setLocalUserId(e.target.value)} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              <option value="">-- 選択してください --</option>
              {LOCAL_USERS.map(u => <option key={u} value={u}>{u}</option>)}
            </select>
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-falcon-muted text-sm hover:text-white rounded-lg hover:bg-falcon-border transition-colors">キャンセル</button>
          <button onClick={() => localUserId && onLink(identity.id, localUserId)} disabled={!localUserId} className="px-4 py-2 bg-falcon-red text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors disabled:opacity-50 disabled:cursor-not-allowed">紐付け</button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CloudIdentityPage() {
  const [activeTab, setActiveTab] = useState<'providers' | 'identities'>('providers')
  const [showProviderModal, setShowProviderModal] = useState(false)
  const [editingProvider, setEditingProvider] = useState<IdentityProvider | undefined>()
  const [linkingIdentity, setLinkingIdentity] = useState<FederatedIdentity | undefined>()
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)
  const [filterProvider, setFilterProvider] = useState<string>('all')
  const [filterLinked, setFilterLinked] = useState<'all' | 'linked' | 'unlinked'>('all')
  const [filterRisk, setFilterRisk] = useState<RiskIndicator | 'all'>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [syncingIds, setSyncingIds] = useState<Set<string>>(new Set())

  const [localProviders, setLocalProviders] = useState<IdentityProvider[]>([])
  const [localIdentities, setLocalIdentities] = useState<FederatedIdentity[]>([])

  const { data: providersData } = useQuery<{ providers: IdentityProvider[] }>({
    queryKey: ['cloud-identity-providers'],
    queryFn: () => apiFetch('/api/v1/admin/cloud-identity/providers'),
  })
  const { data: identitiesData } = useQuery<{ identities: FederatedIdentity[] }>({
    queryKey: ['cloud-identity-identities'],
    queryFn: () => apiFetch('/api/v1/admin/cloud-identity/identities'),
  })

  const providers = providersData?.providers ?? localProviders
  const identities = identitiesData?.identities ?? localIdentities

  const showToast = (message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3500)
  }

  const handleSync = (id: string) => {
    setSyncingIds(s => new Set([...s, id]))
    setLocalProviders(p => p.map(x => x.id === id ? { ...x, sync_status: 'syncing' } : x))
    setTimeout(() => {
      setSyncingIds(s => { const n = new Set(s); n.delete(id); return n })
      setLocalProviders(p => p.map(x => x.id === id ? { ...x, sync_status: 'synced', last_sync: new Date().toISOString(), user_count: x.user_count + Math.floor(Math.random() * 3) } : x))
      showToast('同期が完了しました')
    }, 2500)
  }

  const handleToggleProvider = (id: string) => setLocalProviders(p => p.map(x => x.id === id ? { ...x, enabled: !x.enabled } : x))

  const handleSaveProvider = (data: Partial<IdentityProvider>) => {
    if (editingProvider) {
      setLocalProviders(p => p.map(x => x.id === editingProvider.id ? { ...x, ...data } : x))
      showToast('プロバイダーを更新しました')
    } else {
      const np: IdentityProvider = { id: `p${Date.now()}`, name: data.name ?? '', provider_type: data.provider_type ?? 'azure_ad', tenant_id: data.tenant_id ?? '', sync_status: 'pending', last_sync: '', user_count: 0, group_count: 0, enabled: true, config: data.config ?? {}, linked_identities: 0 }
      setLocalProviders(p => [...p, np])
      showToast('プロバイダーを追加しました')
    }
    setShowProviderModal(false)
    setEditingProvider(undefined)
  }

  const handleDeleteProvider = (id: string) => {
    setLocalProviders(p => p.filter(x => x.id !== id))
    showToast('プロバイダーを削除しました')
  }

  const handleLinkIdentity = (identityId: string, localUserId: string) => {
    setLocalIdentities(ids => ids.map(x => x.id === identityId ? { ...x, local_user_id: localUserId, local_user_name: localUserId } : x))
    setLinkingIdentity(undefined)
    showToast('ユーザーを紐付けました')
  }

  const filteredIdentities = identities.filter(id => {
    if (filterProvider !== 'all' && id.provider_id !== filterProvider) return false
    if (filterLinked === 'linked' && !id.local_user_id) return false
    if (filterLinked === 'unlinked' && id.local_user_id) return false
    if (filterRisk !== 'all' && !id.risk_indicators.includes(filterRisk)) return false
    if (searchQuery && !id.email.toLowerCase().includes(searchQuery.toLowerCase()) && !id.display_name.toLowerCase().includes(searchQuery.toLowerCase())) return false
    return true
  })

  const totalIdentities = identities.length
  const linkedCount = identities.filter(i => i.local_user_id).length
  const atRiskCount = identities.filter(i => i.risk_indicators.length > 0).length

  const riskGroups: Record<RiskIndicator, FederatedIdentity[]> = {
    stale: identities.filter(i => i.risk_indicators.includes('stale')),
    mfa_exempt: identities.filter(i => i.risk_indicators.includes('mfa_exempt')),
    over_privileged: identities.filter(i => i.risk_indicators.includes('over_privileged')),
    guest: identities.filter(i => i.risk_indicators.includes('guest')),
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Toast */}
      {toast && (
        <div className={`fixed top-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-xl border text-sm font-medium ${toast.type === 'success' ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
          {toast.type === 'success' ? <CheckCircle className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
          {toast.message}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-falcon-surface border border-falcon-border flex items-center justify-center">
            <Users className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">クラウドID統合管理</h1>
            <p className="text-falcon-muted text-sm">マルチクラウドIDフェデレーションの統合管理</p>
          </div>
        </div>
        {activeTab === 'providers' && (
          <button onClick={() => { setEditingProvider(undefined); setShowProviderModal(true) }} className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors">
            <Plus className="w-4 h-4" />プロバイダー追加
          </button>
        )}
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'IDプロバイダー数', value: providers.length, icon: Cloud, color: 'text-blue-400' },
          { label: 'フェデレーションID', value: totalIdentities, icon: Users, color: 'text-purple-400' },
          { label: 'ローカルリンク済み', value: linkedCount, icon: LinkIcon, color: 'text-green-400' },
          { label: 'リスクあり', value: atRiskCount, icon: AlertTriangle, color: 'text-orange-400' },
        ].map(c => (
          <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-lg bg-[#070d19] flex items-center justify-center shrink-0">
              <c.icon className={`w-5 h-5 ${c.color}`} />
            </div>
            <div>
              <p className="text-falcon-muted text-xs">{c.label}</p>
              <p className="text-white font-bold text-2xl">{c.value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {(['providers', 'identities'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === tab ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}>
            {tab === 'providers' ? 'IDプロバイダー' : 'フェデレーションID'}
          </button>
        ))}
      </div>

      {/* Providers Tab */}
      {activeTab === 'providers' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-falcon-border">
                {['プロバイダー名', 'タイプ', 'テナントID', '同期ステータス', '最終同期', 'ユーザー', 'グループ', '有効', 'アクション'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {providers.map(p => (
                <tr key={p.id} className="hover:bg-[#0d1826] transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-white text-sm font-medium">{p.name}</p>
                    <p className="text-falcon-muted text-xs mt-0.5">{p.linked_identities} ID リンク済み</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${PROVIDER_BADGE[p.provider_type]}`}>{PROVIDER_LABEL[p.provider_type]}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-falcon-muted text-xs font-mono">{p.tenant_id.length > 20 ? `${p.tenant_id.slice(0, 20)}…` : p.tenant_id}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium w-fit ${SYNC_BADGE[p.sync_status]}`}>
                      {p.sync_status === 'syncing' && <RefreshCw className="w-3 h-3 animate-spin" />}
                      {SYNC_LABEL[p.sync_status]}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-falcon-muted text-xs">{p.last_sync ? formatDate(p.last_sync) : '—'}</td>
                  <td className="px-4 py-3 text-white text-sm">{(p.user_count ?? 0).toLocaleString()}</td>
                  <td className="px-4 py-3 text-white text-sm">{p.group_count}</td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleToggleProvider(p.id)} className={`text-2xl transition-colors ${p.enabled ? 'text-green-400' : 'text-falcon-subtle'}`}>
                      {p.enabled ? <ToggleRight className="w-8 h-5" /> : <ToggleLeft className="w-8 h-5" />}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button onClick={() => handleSync(p.id)} disabled={syncingIds.has(p.id)} title="同期" className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-blue-400 transition-colors disabled:opacity-50">
                        <RefreshCw className={`w-3.5 h-3.5 ${syncingIds.has(p.id) ? 'animate-spin' : ''}`} />
                      </button>
                      <button onClick={() => { setEditingProvider(p); setShowProviderModal(true) }} title="編集" className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors"><Pencil className="w-3.5 h-3.5" /></button>
                      <button onClick={() => handleDeleteProvider(p.id)} title="削除" className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-red transition-colors"><Trash2 className="w-3.5 h-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Identities Tab */}
      {activeTab === 'identities' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-muted" />
              <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="メール/名前で検索..." className="bg-falcon-surface border border-falcon-border rounded-lg pl-9 pr-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 w-56" />
            </div>
            <select value={filterProvider} onChange={e => setFilterProvider(e.target.value)} className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              <option value="all">全プロバイダー</option>
              {providers.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <select value={filterLinked} onChange={e => setFilterLinked(e.target.value as 'all' | 'linked' | 'unlinked')} className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              <option value="all">リンク状態: 全て</option>
              <option value="linked">リンク済み</option>
              <option value="unlinked">未リンク</option>
            </select>
            <select value={filterRisk} onChange={e => setFilterRisk(e.target.value as RiskIndicator | 'all')} className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50">
              <option value="all">リスク: 全て</option>
              {(Object.keys(RISK_LABEL) as RiskIndicator[]).map(r => <option key={r} value={r}>{RISK_LABEL[r]}</option>)}
            </select>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['表示名', 'メール', 'プロバイダー', 'グループ', 'ロール', 'ローカルユーザー', '最終確認', 'リスク', 'アクション'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {filteredIdentities.slice(0, 20).map(id => (
                  <tr key={id.id} className="hover:bg-[#0d1826] transition-colors">
                    <td className="px-4 py-3 text-white text-sm font-medium">{id.display_name}</td>
                    <td className="px-4 py-3 text-falcon-muted text-xs font-mono">{id.email}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${PROVIDER_BADGE[id.provider_type]}`}>{PROVIDER_LABEL[id.provider_type]}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {id.groups.slice(0, 2).map(g => <span key={g} className="px-1.5 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-xs">{g}</span>)}
                        {id.groups.length > 2 && <span className="px-1.5 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-xs">+{id.groups.length - 2}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {id.roles.slice(0, 2).map(r => <span key={r} className="px-1.5 py-0.5 bg-falcon-border text-falcon-muted rounded-sm text-xs">{r}</span>)}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {id.local_user_id ? (
                        <span className="flex items-center gap-1 text-green-400 text-xs"><LinkIcon className="w-3 h-3" />{id.local_user_name ?? id.local_user_id}</span>
                      ) : (
                        <span className="px-2 py-0.5 bg-yellow-500/10 text-yellow-400 border border-yellow-500/30 rounded-sm text-xs">未リンク</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-falcon-muted text-xs">{formatDate(id.last_seen)}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {id.risk_indicators.map(r => <span key={r} className={`px-1.5 py-0.5 rounded-sm text-xs ${RISK_BADGE[r]}`}>{RISK_LABEL[r]}</span>)}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => setLinkingIdentity(id)} title={id.local_user_id ? 'リンク変更' : 'リンク'} className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-blue-400 transition-colors">
                        <LinkIcon className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredIdentities.length === 0 && (
                  <tr><td colSpan={9} className="px-4 py-12 text-center text-falcon-muted text-sm">条件に一致するIDがありません</td></tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Risk Analysis */}
          <div className="mt-6">
            <h3 className="text-white font-semibold text-sm mb-3">リスク分析</h3>
            <div className="grid grid-cols-4 gap-4">
              {(Object.keys(RISK_LABEL) as RiskIndicator[]).map(r => (
                <div key={r} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${RISK_BADGE[r]}`}>{RISK_LABEL[r]}</span>
                    <span className="text-white font-bold text-xl">{riskGroups[r].length}</span>
                  </div>
                  <div className="space-y-1">
                    {riskGroups[r].slice(0, 3).map(id => (
                      <p key={id.id} className="text-falcon-muted text-xs truncate">{id.email}</p>
                    ))}
                    {riskGroups[r].length > 3 && <p className="text-falcon-subtle text-xs">+{riskGroups[r].length - 3} 件</p>}
                    {riskGroups[r].length === 0 && <p className="text-falcon-subtle text-xs">リスクなし</p>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {showProviderModal && (
        <ProviderModal provider={editingProvider} onClose={() => { setShowProviderModal(false); setEditingProvider(undefined) }} onSave={handleSaveProvider} />
      )}
      {linkingIdentity && (
        <LinkModal identity={linkingIdentity} onClose={() => setLinkingIdentity(undefined)} onLink={handleLinkIdentity} />
      )}
    </div>
  )
}
