'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ChevronRight,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  Save,
  Plus,
  RotateCcw,
  Info,
  AlertTriangle,
  Activity,
  Zap,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ──────────────────────────────────────────────────────────────────────

type AuthMode = 'api_key' | 'userpass'
type ConnectionStatus = 'idle' | 'testing' | 'success' | 'error'
type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'
type SyncStatus = 'idle' | 'syncing' | 'done' | 'error'

interface ConnectionConfig {
  url: string
  authMode: AuthMode
  apiKey: string
  username: string
  password: string
  indexPattern: string
  tlsVerify: boolean
}

interface SyncConfig {
  enabled: boolean
  interval: number
  minSeverity: number
  syncAlerts: boolean
  syncAgents: boolean
  syncEvents: boolean
}

interface FieldMapping {
  id: string
  edrField: string
  elasticField: string
}

interface SyncStats {
  connected: boolean
  lastSync: string | null
  docsToday: number
  totalDocs: number
  recentErrors: string[]
}

// ─── Default values ─────────────────────────────────────────────────────────────

const DEFAULT_CONNECTION: ConnectionConfig = {
  url: '',
  authMode: 'api_key',
  apiKey: '',
  username: '',
  password: '',
  indexPattern: 'edr-alerts-*',
  tlsVerify: true,
}

const DEFAULT_SYNC: SyncConfig = {
  enabled: false,
  interval: 5,
  minSeverity: 5,
  syncAlerts: true,
  syncAgents: true,
  syncEvents: false,
}

const DEFAULT_MAPPINGS: FieldMapping[] = [
  { id: '1', edrField: 'title',       elasticField: 'message' },
  { id: '2', edrField: 'severity',    elasticField: 'event.severity' },
  { id: '3', edrField: 'agent_id',    elasticField: 'host.id' },
  { id: '4', edrField: 'status',      elasticField: 'event.outcome' },
  { id: '5', edrField: 'created_at',  elasticField: '@timestamp' },
  { id: '6', edrField: 'description', elasticField: 'event.reason' },
]

// ─── Shared UI helpers ──────────────────────────────────────────────────────────

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wide">
      {children}
    </label>
  )
}

function TextInput({
  value,
  onChange,
  placeholder,
  type = 'text',
  className = '',
  disabled = false,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
  className?: string
  disabled?: boolean
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className={`w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm
                  text-[#e2e8f4] placeholder-[#3d5068]
                  focus:outline-hidden focus:border-[#e8002d]/60 focus:ring-1 focus:ring-[#e8002d]/20
                  disabled:opacity-40 disabled:cursor-not-allowed
                  transition-colors ${className}`}
    />
  )
}

function Toggle({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  description?: string
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
          className={`w-10 h-6 rounded-full transition-colors duration-200 ${
            checked ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
          }`}
        >
          <div
            className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] shadow-sm transition-transform duration-200 ${
              checked ? 'translate-x-5' : 'translate-x-1'
            }`}
          />
        </div>
      </div>
      <div>
        <p className="text-sm text-[#e2e8f4] font-medium group-hover:text-white transition-colors">
          {label}
        </p>
        {description && (
          <p className="text-xs text-[#7d92b0] mt-0.5">{description}</p>
        )}
      </div>
    </label>
  )
}

function Card({
  title,
  subtitle,
  children,
}: {
  title: string
  subtitle?: string
  children: React.ReactNode
}) {
  return (
    <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
      <div className="px-6 py-4 border-b border-[#1e2d42]">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        {subtitle && <p className="text-xs text-[#7d92b0] mt-0.5">{subtitle}</p>}
      </div>
      <div className="p-6">{children}</div>
    </div>
  )
}

function Banner({ type, message }: { type: 'success' | 'error'; message: string }) {
  if (type === 'success') {
    return (
      <div className="flex items-center gap-3 bg-emerald-900/20 border border-emerald-700/40 rounded-lg px-4 py-3">
        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
        <p className="text-sm text-emerald-300">{message}</p>
      </div>
    )
  }
  return (
    <div className="flex items-center gap-3 bg-red-900/20 border border-red-700/40 rounded-lg px-4 py-3">
      <XCircle className="w-4 h-4 text-red-400 shrink-0" />
      <p className="text-sm text-red-300">{message}</p>
    </div>
  )
}

// ─── Connection Settings Card ───────────────────────────────────────────────────

function ConnectionSettingsCard() {
  const [config, setConfig] = useState<ConnectionConfig>(DEFAULT_CONNECTION)
  const [testStatus, setTestStatus] = useState<ConnectionStatus>('idle')
  const [testMsg, setTestMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const set = <K extends keyof ConnectionConfig>(key: K, val: ConnectionConfig[K]) =>
    setConfig(prev => ({ ...prev, [key]: val }))

  const handleTest = async () => {
    setTestStatus('testing')
    setTestMsg(null)
    try {
      await apiFetch('/api/v1/admin/integrations/elastic/test', {
        method: 'POST',
        body: JSON.stringify(config),
      })
      setTestStatus('success')
      setTestMsg({ type: 'success', text: 'Elasticsearch への接続に成功しました。クラスター情報を取得できます。' })
    } catch (err: unknown) {
      setTestStatus('error')
      const msg = err instanceof Error ? err.message : 'Unknown error'
      setTestMsg({ type: 'error', text: `接続失敗: ${msg}` })
    }
  }

  return (
    <Card title="接続設定" subtitle="Elasticsearch クラスターへの接続情報を設定します">
      <div className="space-y-5">
        {/* URL */}
        <div>
          <FieldLabel>Elasticsearch URL</FieldLabel>
          <TextInput
            value={config.url}
            onChange={v => set('url', v)}
            placeholder="https://localhost:9200"
          />
        </div>

        {/* Auth mode */}
        <div>
          <FieldLabel>認証方式</FieldLabel>
          <div className="flex gap-4">
            {(['api_key', 'userpass'] as AuthMode[]).map(mode => (
              <label key={mode} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="authMode"
                  value={mode}
                  checked={config.authMode === mode}
                  onChange={() => set('authMode', mode)}
                  className="w-4 h-4 accent-[#e8002d]"
                />
                <span className="text-sm text-[#e2e8f4]">
                  {mode === 'api_key' ? 'API Key' : 'Username / Password'}
                </span>
              </label>
            ))}
          </div>
        </div>

        {/* API Key (conditional) */}
        {config.authMode === 'api_key' && (
          <div>
            <FieldLabel>API Key</FieldLabel>
            <TextInput
              type="password"
              value={config.apiKey}
              onChange={v => set('apiKey', v)}
              placeholder="VXNlcklEOkFQSUtleQ=="
            />
            <p className="text-xs text-[#3d5068] mt-1">
              Elasticsearch Console で生成した Base64 エンコード済み API キー
            </p>
          </div>
        )}

        {/* Username / Password (conditional) */}
        {config.authMode === 'userpass' && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FieldLabel>ユーザー名</FieldLabel>
              <TextInput
                value={config.username}
                onChange={v => set('username', v)}
                placeholder="elastic"
              />
            </div>
            <div>
              <FieldLabel>パスワード</FieldLabel>
              <TextInput
                type="password"
                value={config.password}
                onChange={v => set('password', v)}
                placeholder="••••••••"
              />
            </div>
          </div>
        )}

        {/* Index pattern */}
        <div>
          <FieldLabel>インデックスパターン</FieldLabel>
          <TextInput
            value={config.indexPattern}
            onChange={v => set('indexPattern', v)}
            placeholder="edr-alerts-*"
          />
          <p className="text-xs text-[#3d5068] mt-1">
            EDR データを書き込む Elasticsearch インデックスのパターン
          </p>
        </div>

        {/* TLS verification */}
        <div>
          <Toggle
            checked={config.tlsVerify}
            onChange={v => set('tlsVerify', v)}
            label="TLS 証明書を検証する"
            description="本番環境では有効にすることを推奨します。自己署名証明書の場合はオフにしてください。"
          />
        </div>

        {/* Test banner */}
        {testMsg && <Banner type={testMsg.type} message={testMsg.text} />}

        {/* Test button */}
        <div className="pt-1">
          <button
            onClick={handleTest}
            disabled={testStatus === 'testing' || !config.url}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/50 hover:text-[#e2e8f4] disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {testStatus === 'testing' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : testStatus === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : testStatus === 'error' ? (
              <XCircle className="w-4 h-4 text-red-400" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
            {testStatus === 'testing' ? '接続中...' : '接続テスト'}
          </button>
        </div>
      </div>
    </Card>
  )
}

// ─── Sync Settings Card ─────────────────────────────────────────────────────────

function SyncSettingsCard() {
  const queryClient = useQueryClient()
  const [config, setConfig] = useState<SyncConfig>(DEFAULT_SYNC)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')

  const { data: elasticConfigData } = useQuery({
    queryKey: ['elastic-sync-config'],
    queryFn: () => apiFetch<{ sync?: Partial<SyncConfig> }>('/api/v1/admin/integrations/elastic/config').catch(() => null),
  })
  useEffect(() => {
    if (elasticConfigData?.sync) setConfig(prev => ({ ...prev, ...elasticConfigData.sync }))
  }, [elasticConfigData])

  const saveMutation = useMutation({
    mutationFn: (payload: object) =>
      apiFetch('/api/v1/admin/integrations/elastic/config', {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('saved')
      queryClient.invalidateQueries({ queryKey: ['elastic-sync-config'] })
      setTimeout(() => setSaveStatus('idle'), 2500)
    },
    onError: () => setSaveStatus('error'),
  })

  const set = <K extends keyof SyncConfig>(key: K, val: SyncConfig[K]) =>
    setConfig(prev => ({ ...prev, [key]: val }))

  const INTERVAL_OPTIONS = [
    { value: '1',  label: '1 分' },
    { value: '5',  label: '5 分' },
    { value: '15', label: '15 分' },
    { value: '30', label: '30 分' },
    { value: '60', label: '60 分' },
  ]

  return (
    <Card title="同期設定" subtitle="Elasticsearch へのデータ同期スケジュールとフィルタリングを設定します">
      <div className="space-y-6">
        {/* Enable sync */}
        <Toggle
          checked={config.enabled}
          onChange={v => set('enabled', v)}
          label="自動同期を有効化"
          description="有効にすると、指定の間隔でアラートデータが Elasticsearch に自動送信されます"
        />

        <div className={`space-y-6 transition-opacity ${config.enabled ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
          {/* Sync interval */}
          <div>
            <FieldLabel>同期間隔</FieldLabel>
            <select
              value={String(config.interval)}
              onChange={e => set('interval', Number(e.target.value))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#e8002d]/60 focus:ring-1 focus:ring-[#e8002d]/20 transition-colors appearance-none"
            >
              {INTERVAL_OPTIONS.map(o => (
                <option key={o.value} value={o.value} className="bg-[#0d1220]">
                  {o.label}
                </option>
              ))}
            </select>
          </div>

          {/* Min severity */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <FieldLabel>最小重大度しきい値</FieldLabel>
              <span className="text-sm font-mono font-semibold text-[#e8002d]">
                {config.minSeverity}
              </span>
            </div>
            <input
              type="range"
              min={1}
              max={10}
              value={config.minSeverity}
              onChange={e => set('minSeverity', Number(e.target.value))}
              className="w-full h-2 rounded-full appearance-none cursor-pointer bg-[#1e2d42] accent-[#e8002d]"
            />
            <div className="flex justify-between text-xs text-[#3d5068] mt-1">
              <span>1 (低)</span>
              <span>5 (中)</span>
              <span>10 (クリティカル)</span>
            </div>
          </div>

          {/* Data types */}
          <div>
            <FieldLabel>同期するデータ種別</FieldLabel>
            <div className="space-y-3">
              {(
                [
                  { key: 'syncAlerts',  label: 'アラート',         desc: 'セキュリティアラートとインシデント' },
                  { key: 'syncAgents',  label: 'エージェント',     desc: 'エージェントのステータスと設定情報' },
                  { key: 'syncEvents',  label: 'イベント',         desc: '生のテレメトリイベント (大容量)' },
                ] as { key: keyof Pick<SyncConfig, 'syncAlerts' | 'syncAgents' | 'syncEvents'>; label: string; desc: string }[]
              ).map(({ key, label, desc }) => (
                <label key={key} className="flex items-start gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={config[key]}
                    onChange={e => set(key, e.target.checked)}
                    className="mt-0.5 w-4 h-4 accent-[#e8002d] rounded-sm"
                  />
                  <div>
                    <p className="text-sm text-[#e2e8f4] font-medium group-hover:text-white transition-colors">
                      {label}
                    </p>
                    <p className="text-xs text-[#7d92b0]">{desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        {/* Save */}
        <div className="flex items-center justify-between pt-2 border-t border-[#1e2d42]">
          {saveStatus === 'saved' && (
            <span className="text-sm text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              設定を保存しました
            </span>
          )}
          {saveStatus === 'error' && (
            <span className="text-sm text-red-400 flex items-center gap-1.5">
              <XCircle className="w-4 h-4" />
              保存に失敗しました
            </span>
          )}
          {saveStatus === 'idle' && <span />}
          <button
            onClick={() => saveMutation.mutate({ sync: config })}
            disabled={saveStatus === 'saving'}
            className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {saveStatus === 'saving' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saveStatus === 'saving' ? '保存中...' : '設定を保存'}
          </button>
        </div>
      </div>
    </Card>
  )
}

// ─── Field Mapping Card ─────────────────────────────────────────────────────────

function FieldMappingCard() {
  const [mappings, setMappings] = useState<FieldMapping[]>(DEFAULT_MAPPINGS)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')

  const saveMutation = useMutation({
    mutationFn: (payload: object) =>
      // サーバの保存は POST /admin/integrations/:type/mappings です。
      // PUT はルートが無く、フィールドマッピングは保存されないまま
      // 「保存しました」が出ていました。
      apiFetch('/api/v1/admin/integrations/elastic/mappings', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('saved')
      setTimeout(() => setSaveStatus('idle'), 2500)
    },
    onError: () => setSaveStatus('error'),
  })

  const handleAddRow = () => {
    const newId = String(Date.now())
    setMappings(prev => [...prev, { id: newId, edrField: '', elasticField: '' }])
  }

  const handleRemove = (id: string) => {
    setMappings(prev => prev.filter(m => m.id !== id))
  }

  const handleChange = (id: string, field: 'edrField' | 'elasticField', value: string) => {
    setMappings(prev => prev.map(m => m.id === id ? { ...m, [field]: value } : m))
  }

  const handleReset = () => {
    setMappings(DEFAULT_MAPPINGS)
  }

  return (
    <Card
      title="フィールドマッピング"
      subtitle="EDR フィールドを Elasticsearch フィールド名に対応させます"
    >
      <div className="space-y-4">
        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-[#1e2d42]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/80">
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                  EDR フィールド
                </th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                  Elasticsearch フィールド
                </th>
                <th className="w-12 px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]/50">
              {mappings.map(mapping => (
                <tr key={mapping.id} className="hover:bg-[#070d19]/40 transition-colors group">
                  <td className="px-4 py-2.5">
                    <input
                      type="text"
                      value={mapping.edrField}
                      onChange={e => handleChange(mapping.id, 'edrField', e.target.value)}
                      placeholder="edr_field_name"
                      className="w-full bg-transparent border-0 text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden font-mono"
                    />
                  </td>
                  <td className="px-4 py-2.5">
                    <input
                      type="text"
                      value={mapping.elasticField}
                      onChange={e => handleChange(mapping.id, 'elasticField', e.target.value)}
                      placeholder="elastic.field.name"
                      className="w-full bg-transparent border-0 text-sm text-[#7d92b0] placeholder-[#3d5068] focus:outline-hidden font-mono"
                    />
                  </td>
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => handleRemove(mapping.id)}
                      className="opacity-0 group-hover:opacity-100 text-[#3d5068] hover:text-red-400 transition-all text-lg leading-none"
                      title="削除"
                    >
                      ×
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between">
          <div className="flex gap-2">
            <button
              onClick={handleAddRow}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] hover:border-[#e8002d]/40 hover:text-[#e2e8f4] transition-all"
            >
              <Plus className="w-4 h-4" />
              マッピングを追加
            </button>
            <button
              onClick={handleReset}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40 hover:text-[#e2e8f4] transition-all"
            >
              <RotateCcw className="w-4 h-4" />
              デフォルトに戻す
            </button>
          </div>

          <div className="flex items-center gap-3">
            {saveStatus === 'saved' && (
              <span className="text-sm text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                保存済み
              </span>
            )}
            <button
              onClick={() => saveMutation.mutate({ mappings })}
              disabled={saveStatus === 'saving'}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              {saveStatus === 'saving' ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              保存
            </button>
          </div>
        </div>
      </div>
    </Card>
  )
}

// ─── Sync Status Card ───────────────────────────────────────────────────────────

function SyncStatusCard() {
  const [syncStatus, setSyncStatus] = useState<SyncStatus>('idle')
  const [syncMsg, setSyncMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const { data: stats, isLoading } = useQuery<SyncStats>({
    queryKey: ['elastic-sync-stats'],
    queryFn: () => apiFetch('/api/v1/admin/integrations/elastic/status'),
    refetchInterval: 30_000,
  })

  const EMPTY_SYNC_STATS: SyncStats = { connected: false, lastSync: null, docsToday: 0, totalDocs: 0, recentErrors: [] }
  const data = stats ?? EMPTY_SYNC_STATS

  const handleSyncNow = async () => {
    setSyncStatus('syncing')
    setSyncMsg(null)
    try {
      await apiFetch('/api/v1/admin/integrations/elastic/sync', { method: 'POST' })
      setSyncStatus('done')
      setSyncMsg({ type: 'success', text: '同期が正常に完了しました。' })
      setTimeout(() => { setSyncStatus('idle'); setSyncMsg(null) }, 4000)
    } catch (err: unknown) {
      setSyncStatus('error')
      const msg = err instanceof Error ? err.message : 'Unknown error'
      setSyncMsg({ type: 'error', text: `同期に失敗しました: ${msg}` })
    }
  }

  const fmt = (n: number) => n.toLocaleString('ja-JP')

  return (
    <Card title="同期ステータス" subtitle="Elasticsearch クラスターとのデータ同期状態">
      <div className="space-y-5">
        {isLoading && (
          <div className="flex items-center gap-2 text-sm text-[#7d92b0]">
            <Loader2 className="w-4 h-4 animate-spin" />
            読み込み中...
          </div>
        )}

        {/* Status grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {/* Connection status */}
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-2 uppercase tracking-wide">接続状態</p>
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border
                ${data.connected
                  ? 'bg-emerald-900/30 text-emerald-300 border-emerald-700/40'
                  : 'bg-red-900/30 text-red-400 border-red-700/40'
                }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  data.connected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'
                }`}
              />
              {data.connected ? '接続中' : '切断'}
            </span>
          </div>

          {/* Last sync */}
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-2 uppercase tracking-wide">最終同期</p>
            <p className="text-sm text-[#e2e8f4] font-mono">
              {data.lastSync ?? '—'}
            </p>
          </div>

          {/* Docs today */}
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-2 uppercase tracking-wide">本日のドキュメント</p>
            <p className="text-lg font-bold text-[#e2e8f4]">{fmt(data.docsToday)}</p>
          </div>

          {/* Total docs */}
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-2 uppercase tracking-wide">累計ドキュメント</p>
            <p className="text-lg font-bold text-[#e2e8f4]">{fmt(data.totalDocs)}</p>
          </div>
        </div>

        {/* Recent errors */}
        {data.recentErrors.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              <p className="text-xs text-[#7d92b0] uppercase tracking-wide font-medium">
                直近のエラー
              </p>
            </div>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-4 space-y-1.5">
              {data.recentErrors.map((err, i) => (
                <p
                  key={i}
                  className="text-xs font-mono text-[#7d92b0] leading-relaxed"
                >
                  {err}
                </p>
              ))}
            </div>
          </div>
        )}

        {/* Sync banner */}
        {syncMsg && <Banner type={syncMsg.type} message={syncMsg.text} />}

        {/* Sync Now button */}
        <div className="flex items-center gap-3 pt-1">
          <button
            onClick={handleSyncNow}
            disabled={syncStatus === 'syncing'}
            className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {syncStatus === 'syncing' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Zap className="w-4 h-4" />
            )}
            {syncStatus === 'syncing' ? '同期中...' : '今すぐ同期'}
          </button>

          {syncStatus === 'done' && (
            <span className="text-sm text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              完了
            </span>
          )}
        </div>
      </div>
    </Card>
  )
}

// ─── Main page ───────────────────────────────────────────────────────────────────

export default function ElasticIntegrationPage() {
  return (
    <div className="min-h-screen bg-[#070d19]">
      <PageDataUnavailable />
      <div className="max-w-screen-lg mx-auto p-6 space-y-6">

        {/* ── Breadcrumb ─────────────────────────────────────────── */}
        <nav className="flex items-center gap-1.5 text-xs text-[#3d5068]">
          <a href="/admin" className="hover:text-[#7d92b0] transition-colors">Admin</a>
          <ChevronRight className="w-3 h-3" />
          <a href="/admin/integrations" className="hover:text-[#7d92b0] transition-colors">Integrations</a>
          <ChevronRight className="w-3 h-3" />
          <span className="text-[#7d92b0]">Elastic SIEM</span>
        </nav>

        {/* ── Header ────────────────────────────────────────────── */}
        <div className="flex items-start gap-4">
          {/* Elastic logo placeholder */}
          <div
            className="w-12 h-12 rounded-xl flex items-center justify-center text-white font-bold text-lg shrink-0 shadow-lg"
            style={{ background: 'radial-gradient(circle at 35% 35%, #ff8a00, #e07000)' }}
          >
            E
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Elastic SIEM 連携</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">
              Elasticsearch / Elastic Security へのアラート・エージェントデータ同期設定
            </p>
          </div>
        </div>

        {/* ── Dev notice ────────────────────────────────────────── */}
        <div className="flex items-start gap-3 bg-[#1a6bff]/5 border border-[#1a6bff]/20 rounded-xl px-5 py-4">
          <Info className="w-4 h-4 text-[#1a6bff] shrink-0 mt-0.5" />
          <p className="text-sm text-[#7d92b0] leading-relaxed">
            Elastic SIEM 連携は現在スタブ実装です。接続テスト・保存・同期操作はデモ動作となります。
          </p>
        </div>

        {/* ── Cards ─────────────────────────────────────────────── */}
        <ConnectionSettingsCard />
        <SyncSettingsCard />
        <FieldMappingCard />
        <SyncStatusCard />

      </div>
    </div>
  )
}
