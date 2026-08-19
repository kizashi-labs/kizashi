'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Server,
  Eye,
  EyeOff,
  RefreshCw,
  Loader2,
  CheckCircle2,
  XCircle,
  Users,
  Save,
  AlertTriangle,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface LdapConfig {
  host: string
  port: number
  base_dn: string
  bind_dn: string
  bind_password: string
  tls_enabled: boolean
  user_search_filter: string
  group_search_filter: string
  username_attribute: string
  email_attribute: string
  display_name_attribute: string
  sync_enabled: boolean
  sync_interval: '' | 'hourly' | 'daily'
  last_sync?: string
}

interface SyncResult {
  total_synced: number
  created: number
  updated: number
  errors: number
}

type TestStatus = 'idle' | 'testing' | 'success' | 'error'
type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type SyncStatus = 'idle' | 'syncing' | 'done' | 'error'

// ─── Default config ───────────────────────────────────────────────────────────

const DEFAULT_CONFIG: LdapConfig = {
  host:                    '',
  port:                    389,
  base_dn:                 '',
  bind_dn:                 '',
  bind_password:           '',
  tls_enabled:             false,
  user_search_filter:      '(objectClass=person)',
  group_search_filter:     '(objectClass=group)',
  username_attribute:      'sAMAccountName',
  email_attribute:         'mail',
  display_name_attribute:  'displayName',
  sync_enabled:            false,
  sync_interval:           'daily',
}

// ─── Shared sub-components ────────────────────────────────────────────────────

function SectionCard({
  title,
  icon,
  children,
}: {
  title: string
  icon: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-700 flex items-center gap-2">
        <span className="text-gray-400">{icon}</span>
        <h2 className="text-base font-semibold text-white">{title}</h2>
      </div>
      <div className="p-6">{children}</div>
    </div>
  )
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-sm text-gray-400 mb-1.5">{children}</label>
  )
}

function TextInput({
  value,
  onChange,
  placeholder,
  type = 'text',
  hint,
  className = '',
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
  hint?: string
  className?: string
}) {
  return (
    <div>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className={`w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2.5 text-sm
                    text-gray-200 placeholder-gray-500 focus:outline-hidden focus:border-blue-500
                    focus:ring-1 focus:ring-blue-500/30 transition-colors ${className}`}
      />
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}

function ToggleRow({
  label,
  description,
  checked,
  onChange,
}: {
  label: string
  description?: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer group">
      <div className="relative mt-0.5 shrink-0">
        <input
          type="checkbox"
          checked={checked}
          onChange={e => onChange(e.target.checked)}
          className="sr-only"
        />
        <div
          className={`w-10 h-6 rounded-full transition-colors ${
            checked ? 'bg-blue-600' : 'bg-gray-600'
          }`}
        >
          <div
            className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] shadow-sm transition-transform ${
              checked ? 'translate-x-5' : 'translate-x-1'
            }`}
          />
        </div>
      </div>
      <div>
        <p className="text-sm text-gray-200 group-hover:text-white transition-colors">{label}</p>
        {description && <p className="text-xs text-gray-500 mt-0.5">{description}</p>}
      </div>
    </label>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function LdapIntegrationPage() {
  // Remote config (initialised from GET /api/v1/admin/ldap)
  const { data: remoteConfig } = useQuery<LdapConfig>({
    queryKey: ['admin-ldap-config'],
    queryFn: () => apiFetch('/api/v1/admin/ldap'),
    staleTime: 60_000,
  })

  const [config, setConfig] = useState<LdapConfig>(remoteConfig ?? DEFAULT_CONFIG)
  const [showPassword, setShowPassword] = useState(false)

  const [testStatus, setTestStatus]     = useState<TestStatus>('idle')
  const [testError,  setTestError]      = useState<string | null>(null)

  const [saveStatus, setSaveStatus]     = useState<SaveStatus>('idle')
  const [saveError,  setSaveError]      = useState<string | null>(null)

  const [syncStatus, setSyncStatus]     = useState<SyncStatus>('idle')
  const [syncResult, setSyncResult]     = useState<SyncResult | null>(null)
  const [syncError,  setSyncError]      = useState<string | null>(null)

  // Merge remote config into local once loaded
  // (only on first mount — we don't override user edits)
  const [hydrated, setHydrated] = useState(false)
  if (remoteConfig && !hydrated) {
    setConfig(remoteConfig)
    setHydrated(true)
  }

  // ── Field helper ────────────────────────────────────────────────────────

  const set = <K extends keyof LdapConfig>(key: K, value: LdapConfig[K]) => {
    setConfig(prev => ({ ...prev, [key]: value }))
  }

  // ── Handlers ─────────────────────────────────────────────────────────────

  const handleTest = async () => {
    setTestStatus('testing')
    setTestError(null)
    try {
      await apiFetch('/api/v1/admin/ldap/test', {
        method: 'POST',
        body: JSON.stringify(config),
      })
      setTestStatus('success')
    } catch (err: unknown) {
      setTestStatus('error')
      setTestError(err instanceof Error ? err.message : '接続テストに失敗しました')
    }
  }

  const handleSave = async () => {
    setSaveStatus('saving')
    setSaveError(null)
    try {
      await apiFetch('/api/v1/admin/ldap', {
        method: 'PUT',
        body: JSON.stringify(config),
      })
      setSaveStatus('saved')
      setTimeout(() => setSaveStatus('idle'), 3000)
    } catch (err: unknown) {
      setSaveStatus('error')
      setSaveError(err instanceof Error ? err.message : '保存に失敗しました')
    }
  }

  const handleSync = async () => {
    setSyncStatus('syncing')
    setSyncError(null)
    setSyncResult(null)
    try {
      const result = await apiFetch<SyncResult>('/api/v1/admin/ldap/sync', {
        method: 'POST',
      })
      setSyncResult(result)
      setSyncStatus('done')
      set('last_sync', new Date().toISOString())
    } catch (err: unknown) {
      setSyncStatus('error')
      setSyncError(err instanceof Error ? err.message : '同期に失敗しました')
    }
  }

  // ─── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-900">
      <PageDataUnavailable />
      <div className="max-w-screen-lg mx-auto p-6 space-y-6">

        {/* ── Header ──────────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-900/40 border border-blue-700/50 flex items-center justify-center shrink-0">
              <Server className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">LDAP/Active Directory連携</h1>
              <p className="text-sm text-gray-400 mt-0.5">
                LDAP/ADディレクトリサービスからユーザーを同期します
              </p>
            </div>
          </div>

          {/* Save button */}
          <button
            onClick={handleSave}
            disabled={saveStatus === 'saving'}
            className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saveStatus === 'saving' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saveStatus === 'saved' ? '保存しました' : '設定を保存'}
          </button>
        </div>

        {/* ── Save error ───────────────────────────────────────────── */}
        {saveStatus === 'error' && saveError && (
          <div className="flex items-start gap-3 bg-red-900/20 border border-red-700/40 rounded-xl px-5 py-4">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <p className="text-sm text-red-300">{saveError}</p>
          </div>
        )}

        {/* ── 1. Connection settings ───────────────────────────────── */}
        <SectionCard title="接続設定" icon={<Server className="w-4 h-4" />}>
          <div className="space-y-5">

            {/* Host / Port */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="sm:col-span-2">
                <FieldLabel>LDAPホスト</FieldLabel>
                <TextInput
                  value={config.host}
                  onChange={v => set('host', v)}
                  placeholder="ldap.company.com"
                />
              </div>
              <div>
                <FieldLabel>ポート</FieldLabel>
                <input
                  type="number"
                  value={config.port}
                  onChange={e => set('port', Number(e.target.value))}
                  min={1}
                  max={65535}
                  className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:outline-hidden focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors [appearance:textfield]"
                />
              </div>
            </div>

            {/* Base DN */}
            <div>
              <FieldLabel>Base DN</FieldLabel>
              <TextInput
                value={config.base_dn}
                onChange={v => set('base_dn', v)}
                placeholder="dc=company,dc=com"
                hint="例: dc=company,dc=com"
              />
            </div>

            {/* Bind DN */}
            <div>
              <FieldLabel>Bind DN</FieldLabel>
              <TextInput
                value={config.bind_dn}
                onChange={v => set('bind_dn', v)}
                placeholder="cn=admin,dc=company,dc=com"
                hint="例: cn=admin,dc=company,dc=com"
              />
            </div>

            {/* Bind password */}
            <div>
              <FieldLabel>Bindパスワード</FieldLabel>
              <div className="relative">
                <TextInput
                  type={showPassword ? 'text' : 'password'}
                  value={config.bind_password}
                  onChange={v => set('bind_password', v)}
                  placeholder="••••••••"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* TLS toggle */}
            <ToggleRow
              label="TLS を有効化"
              description="LDAPS (636番ポート) またはSTARTTLSを使用します"
              checked={config.tls_enabled}
              onChange={v => set('tls_enabled', v)}
            />

            {/* Test connection row */}
            <div className="flex items-center gap-4 pt-1 border-t border-gray-700">
              <button
                onClick={handleTest}
                disabled={testStatus === 'testing' || !config.host}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-gray-700 hover:bg-gray-600 border border-gray-600 text-gray-200 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {testStatus === 'testing' ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <RefreshCw className="w-4 h-4" />
                )}
                接続テスト
              </button>

              {testStatus === 'testing' && (
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-yellow-400 animate-pulse" />
                  <span className="text-sm text-yellow-400">接続中...</span>
                </div>
              )}
              {testStatus === 'success' && (
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-green-400">接続成功</span>
                </div>
              )}
              {testStatus === 'error' && (
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span className="text-sm text-red-400">{testError ?? '接続失敗'}</span>
                </div>
              )}
            </div>

          </div>
        </SectionCard>

        {/* ── 2. Directory settings ────────────────────────────────── */}
        <SectionCard title="ディレクトリ設定" icon={<Users className="w-4 h-4" />}>
          <div className="space-y-5">

            {/* Search filters */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <FieldLabel>ユーザー検索フィルター</FieldLabel>
                <TextInput
                  value={config.user_search_filter}
                  onChange={v => set('user_search_filter', v)}
                  placeholder="(objectClass=person)"
                  hint="LDAP フィルター構文"
                />
              </div>
              <div>
                <FieldLabel>グループ検索フィルター</FieldLabel>
                <TextInput
                  value={config.group_search_filter}
                  onChange={v => set('group_search_filter', v)}
                  placeholder="(objectClass=group)"
                />
              </div>
            </div>

            {/* Attribute mappings */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <FieldLabel>ユーザー名属性</FieldLabel>
                <TextInput
                  value={config.username_attribute}
                  onChange={v => set('username_attribute', v)}
                  placeholder="sAMAccountName"
                  hint="例: sAMAccountName / uid"
                />
              </div>
              <div>
                <FieldLabel>メール属性</FieldLabel>
                <TextInput
                  value={config.email_attribute}
                  onChange={v => set('email_attribute', v)}
                  placeholder="mail"
                />
              </div>
              <div>
                <FieldLabel>表示名属性</FieldLabel>
                <TextInput
                  value={config.display_name_attribute}
                  onChange={v => set('display_name_attribute', v)}
                  placeholder="displayName"
                />
              </div>
            </div>

          </div>
        </SectionCard>

        {/* ── 3. Sync settings ─────────────────────────────────────── */}
        <SectionCard title="同期設定" icon={<RefreshCw className="w-4 h-4" />}>
          <div className="space-y-6">

            {/* Enable toggle */}
            <ToggleRow
              label="LDAP同期を有効化"
              description="定期的にLDAPからユーザーを同期します"
              checked={config.sync_enabled}
              onChange={v => set('sync_enabled', v)}
            />

            {/* Auto-sync interval */}
            <div>
              <FieldLabel>自動同期間隔</FieldLabel>
              <select
                value={config.sync_interval}
                onChange={e => set('sync_interval', e.target.value as LdapConfig['sync_interval'])}
                disabled={!config.sync_enabled}
                className="w-full max-w-xs bg-gray-900 border border-gray-600 rounded-lg px-3 py-2.5 text-sm text-gray-200 focus:outline-hidden focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors disabled:opacity-40 disabled:cursor-not-allowed [color-scheme:dark]"
              >
                <option value="">無効</option>
                <option value="hourly">1時間ごと</option>
                <option value="daily">毎日</option>
              </select>
            </div>

            <div className="border-t border-gray-700" />

            {/* Manual sync controls */}
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div className="space-y-0.5">
                <p className="text-sm text-gray-300 font-medium">手動同期</p>
                {config.last_sync ? (
                  <p className="text-xs text-gray-500">
                    最終同期:{' '}
                    <span className="text-gray-400">
                      {new Date(config.last_sync).toLocaleString('ja-JP')}
                    </span>
                  </p>
                ) : (
                  <p className="text-xs text-gray-600">まだ同期されていません</p>
                )}
              </div>

              <div className="flex items-center gap-3">
                {syncStatus === 'error' && syncError && (
                  <span className="text-sm text-red-400 flex items-center gap-1.5">
                    <XCircle className="w-4 h-4" />
                    {syncError}
                  </span>
                )}
                <button
                  onClick={handleSync}
                  disabled={syncStatus === 'syncing'}
                  className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {syncStatus === 'syncing' ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <RefreshCw className="w-4 h-4" />
                  )}
                  {syncStatus === 'syncing' ? '同期中...' : '今すぐ同期'}
                </button>
              </div>
            </div>

          </div>
        </SectionCard>

        {/* ── 4. Sync results (shown after sync completes) ──────────── */}
        {syncStatus === 'done' && syncResult && (
          <SectionCard title="同期結果" icon={<CheckCircle2 className="w-4 h-4 text-green-400" />}>
            <div className="overflow-x-auto rounded-xl border border-gray-700">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-900/40 border-b border-gray-700">
                    <th className="text-left px-5 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                      項目
                    </th>
                    <th className="text-right px-5 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                      件数
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  <tr className="hover:bg-gray-700/20 transition-colors">
                    <td className="px-5 py-3 text-gray-300">同期済みユーザー数</td>
                    <td className="px-5 py-3 text-right font-mono text-white">{syncResult.total_synced}</td>
                  </tr>
                  <tr className="hover:bg-gray-700/20 transition-colors">
                    <td className="px-5 py-3 text-gray-300">新規作成</td>
                    <td className="px-5 py-3 text-right font-mono text-green-400">{syncResult.created}</td>
                  </tr>
                  <tr className="hover:bg-gray-700/20 transition-colors">
                    <td className="px-5 py-3 text-gray-300">更新</td>
                    <td className="px-5 py-3 text-right font-mono text-blue-400">{syncResult.updated}</td>
                  </tr>
                  <tr className="hover:bg-gray-700/20 transition-colors">
                    <td className="px-5 py-3 text-gray-300">エラー</td>
                    <td className={`px-5 py-3 text-right font-mono ${
                      syncResult.errors > 0 ? 'text-red-400' : 'text-gray-500'
                    }`}>
                      {syncResult.errors}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </SectionCard>
        )}

      </div>
    </div>
  )
}
