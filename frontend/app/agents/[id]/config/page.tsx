'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  ChevronLeft, Settings, Edit2, Send, CheckCircle,
  AlertTriangle, Loader2, Clock, Plus, Trash2, Terminal,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface AgentConfig {
  collectors?: {
    system?: boolean
    fim?: boolean
    device?: boolean
    network?: boolean
    process?: boolean
  }
  fim?: {
    watched_paths?: string[]
    excluded_paths?: string[]
  }
  process_monitor?: {
    poll_interval_seconds?: number
    max_processes?: number
  }
  resource_limits?: {
    cpu_limit_percent?: number
    memory_limit_mb?: number
  }
  logging?: {
    level?: 'debug' | 'info' | 'warn' | 'error'
    max_log_size_mb?: number
  }
}

interface AgentConfigResponse {
  config?: AgentConfig
  data?: AgentConfig
}

interface CommandRecord {
  id: string
  command_type?: string
  command?: string
  status?: string
  created_at?: string
  args?: Record<string, unknown>
}

interface CommandsResponse {
  data?: CommandRecord[]
  items?: CommandRecord[]
}

interface AgentInfo {
  id: string
  hostname: string
}

type ConfigTab = 'collectors' | 'fim' | 'process' | 'resources' | 'logging'

// ─── Default config ───────────────────────────────────────────────────────────

function defaultConfig(): AgentConfig {
  return {
    collectors: {
      system: true,
      fim: true,
      device: true,
      network: true,
      process: true,
    },
    fim: {
      watched_paths: ['/etc', '/var/log', 'C:\\Windows\\System32'],
      excluded_paths: ['/proc', '/sys'],
    },
    process_monitor: {
      poll_interval_seconds: 30,
      max_processes: 500,
    },
    resource_limits: {
      cpu_limit_percent: 20,
      memory_limit_mb: 256,
    },
    logging: {
      level: 'info',
      max_log_size_mb: 50,
    },
  }
}

function mergeWithDefaults(raw: AgentConfig): AgentConfig {
  const def = defaultConfig()
  return {
    collectors:      { ...def.collectors,      ...raw.collectors },
    fim:             { ...def.fim,             ...raw.fim,
      watched_paths:  raw.fim?.watched_paths  ?? def.fim!.watched_paths,
      excluded_paths: raw.fim?.excluded_paths ?? def.fim!.excluded_paths,
    },
    process_monitor: { ...def.process_monitor, ...raw.process_monitor },
    resource_limits: { ...def.resource_limits, ...raw.resource_limits },
    logging:         { ...def.logging,         ...raw.logging },
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTime(s?: string): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('ja-JP', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function statusStyle(status?: string): string {
  const s = status?.toLowerCase() ?? ''
  if (s === 'completed' || s === 'success') return 'bg-green-900/40 text-green-300'
  if (s === 'pending')                       return 'bg-yellow-900/40 text-yellow-300'
  if (s === 'running')                       return 'bg-blue-900/40 text-blue-300'
  if (s === 'failed' || s === 'error')       return 'bg-red-900/40 text-red-300'
  return 'bg-gray-700 text-gray-400'
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function TabBtn({
  id, active, label, onClick,
}: {
  id: ConfigTab
  active: boolean
  label: string
  onClick: (id: ConfigTab) => void
}) {
  return (
    <button
      onClick={() => onClick(id)}
      className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px whitespace-nowrap transition-colors ${
        active
          ? 'text-white border-blue-500 bg-blue-500/5'
          : 'text-gray-400 border-transparent hover:text-white hover:bg-gray-700/40'
      }`}
    >
      {label}
    </button>
  )
}

function PathListEditor({
  paths, onChange, placeholder,
}: {
  paths: string[]
  onChange: (p: string[]) => void
  placeholder?: string
}) {
  const [input, setInput] = useState('')
  const add = () => {
    const val = input.trim()
    if (val && !paths.includes(val)) onChange([...paths, val])
    setInput('')
  }
  return (
    <div className="space-y-2">
      {paths.map((p, i) => (
        <div key={i} className="flex items-center gap-2">
          <code className="flex-1 bg-gray-900 border border-gray-700 rounded-sm px-2 py-1.5 text-xs text-green-300 font-mono">
            {p}
          </code>
          <button
            onClick={() => onChange(paths.filter((_, j) => j !== i))}
            className="p-1 text-gray-500 hover:text-red-400 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') add() }}
          placeholder={placeholder ?? 'パスを入力...'}
          className="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-white
                     placeholder-gray-600 focus:outline-hidden focus:border-blue-500 transition-colors"
        />
        <button
          onClick={add}
          className="p-1.5 rounded-sm bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
        >
          <Plus className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}

// ─── Config Tabs ──────────────────────────────────────────────────────────────

function CollectorsTab({
  config, onChange,
}: {
  config: AgentConfig
  onChange: (c: AgentConfig) => void
}) {
  const cols = config.collectors ?? {}
  const items: { key: keyof typeof cols; label: string; desc: string }[] = [
    { key: 'system',  label: 'システム情報',   desc: 'CPU・メモリ・ディスク等のシステム指標を収集' },
    { key: 'fim',     label: 'ファイル変更監視', desc: 'ファイルシステムの変更を検知・記録' },
    { key: 'device',  label: 'デバイスイベント', desc: 'USB等の外部デバイス接続を監視' },
    { key: 'network', label: 'ネットワーク',    desc: 'ネットワーク接続・通信を監視' },
    { key: 'process', label: 'プロセス',        desc: '実行中プロセスの状態を監視' },
  ]
  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-500">有効にするコレクターを選択してください</p>
      {items.map(({ key, label, desc }) => (
        <label
          key={key}
          className="flex items-start gap-3 p-3 bg-gray-900 rounded-lg border border-gray-700
                     cursor-pointer hover:border-gray-600 transition-colors"
        >
          <input
            type="checkbox"
            checked={cols[key] ?? false}
            onChange={e => onChange({
              ...config,
              collectors: { ...cols, [key]: e.target.checked },
            })}
            className="mt-0.5 accent-blue-500 w-4 h-4"
          />
          <div>
            <p className="text-sm text-white font-medium">{label}</p>
            <p className="text-xs text-gray-500 mt-0.5">{desc}</p>
          </div>
        </label>
      ))}
    </div>
  )
}

function FimTab({
  config, onChange,
}: {
  config: AgentConfig
  onChange: (c: AgentConfig) => void
}) {
  const fim = config.fim ?? {}
  return (
    <div className="space-y-5">
      <div>
        <p className="text-sm font-medium text-gray-300 mb-2">監視パス</p>
        <PathListEditor
          paths={fim.watched_paths ?? []}
          onChange={paths => onChange({ ...config, fim: { ...fim, watched_paths: paths } })}
          placeholder="/etc または C:\path"
        />
      </div>
      <div>
        <p className="text-sm font-medium text-gray-300 mb-2">除外パス</p>
        <PathListEditor
          paths={fim.excluded_paths ?? []}
          onChange={paths => onChange({ ...config, fim: { ...fim, excluded_paths: paths } })}
          placeholder="/proc または /sys"
        />
      </div>
    </div>
  )
}

function ProcessTab({
  config, onChange,
}: {
  config: AgentConfig
  onChange: (c: AgentConfig) => void
}) {
  const pm = config.process_monitor ?? {}
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">
          ポーリング間隔（秒）
        </label>
        <input
          type="number"
          min={5}
          max={300}
          value={pm.poll_interval_seconds ?? 30}
          onChange={e => onChange({
            ...config,
            process_monitor: { ...pm, poll_interval_seconds: Number(e.target.value) },
          })}
          className="w-40 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white
                     focus:outline-hidden focus:border-blue-500 transition-colors"
        />
        <p className="text-xs text-gray-500 mt-1">推奨: 30〜60秒</p>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">
          最大プロセス数
        </label>
        <input
          type="number"
          min={100}
          max={5000}
          value={pm.max_processes ?? 500}
          onChange={e => onChange({
            ...config,
            process_monitor: { ...pm, max_processes: Number(e.target.value) },
          })}
          className="w-40 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white
                     focus:outline-hidden focus:border-blue-500 transition-colors"
        />
        <p className="text-xs text-gray-500 mt-1">同時に追跡するプロセスの上限</p>
      </div>
    </div>
  )
}

function ResourcesTab({
  config, onChange,
}: {
  config: AgentConfig
  onChange: (c: AgentConfig) => void
}) {
  const rl = config.resource_limits ?? {}
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">
          CPU使用率上限（%）
        </label>
        <div className="flex items-center gap-3">
          <input
            type="range"
            min={5}
            max={80}
            value={rl.cpu_limit_percent ?? 20}
            onChange={e => onChange({
              ...config,
              resource_limits: { ...rl, cpu_limit_percent: Number(e.target.value) },
            })}
            className="w-48 accent-blue-500"
          />
          <span className="text-white text-sm w-10">{rl.cpu_limit_percent ?? 20}%</span>
        </div>
        <p className="text-xs text-gray-500 mt-1">エージェントが使用できるCPU上限</p>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">
          メモリ上限（MB）
        </label>
        <input
          type="number"
          min={64}
          max={2048}
          value={rl.memory_limit_mb ?? 256}
          onChange={e => onChange({
            ...config,
            resource_limits: { ...rl, memory_limit_mb: Number(e.target.value) },
          })}
          className="w-40 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white
                     focus:outline-hidden focus:border-blue-500 transition-colors"
        />
        <p className="text-xs text-gray-500 mt-1">エージェントプロセスの最大メモリ使用量</p>
      </div>
    </div>
  )
}

function LoggingTab({
  config, onChange,
}: {
  config: AgentConfig
  onChange: (c: AgentConfig) => void
}) {
  const lg = config.logging ?? {}
  const levels: { value: 'debug' | 'info' | 'warn' | 'error'; label: string }[] = [
    { value: 'debug', label: 'Debug — 詳細ログ' },
    { value: 'info',  label: 'Info — 標準 (推奨)' },
    { value: 'warn',  label: 'Warn — 警告以上' },
    { value: 'error', label: 'Error — エラーのみ' },
  ]
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">ログレベル</label>
        <select
          value={lg.level ?? 'info'}
          onChange={e => onChange({
            ...config,
            logging: { ...lg, level: e.target.value as 'debug' | 'info' | 'warn' | 'error' },
          })}
          className="w-64 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white
                     focus:outline-hidden focus:border-blue-500 transition-colors"
        >
          {levels.map(l => (
            <option key={l.value} value={l.value}>{l.label}</option>
          ))}
        </select>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1.5">
          最大ログサイズ（MB）
        </label>
        <input
          type="number"
          min={10}
          max={500}
          value={lg.max_log_size_mb ?? 50}
          onChange={e => onChange({
            ...config,
            logging: { ...lg, max_log_size_mb: Number(e.target.value) },
          })}
          className="w-40 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white
                     focus:outline-hidden focus:border-blue-500 transition-colors"
        />
        <p className="text-xs text-gray-500 mt-1">ローテーション前の最大ログファイルサイズ</p>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AgentConfigPage() {
  const params = useParams()
  const agentId = params?.id as string

  const [agentInfo, setAgentInfo]     = useState<AgentInfo | null>(null)
  const [rawConfig, setRawConfig]     = useState<AgentConfig | null>(null)
  const [editConfig, setEditConfig]   = useState<AgentConfig>(defaultConfig())
  const [isEditing, setIsEditing]     = useState(false)
  const [activeTab, setActiveTab]     = useState<ConfigTab>('collectors')
  const [configLoading, setConfigLoading] = useState(true)
  const [configError, setConfigError] = useState<string | null>(null)
  const [commands, setCommands]       = useState<CommandRecord[]>([])
  const [cmdsLoading, setCmdsLoading] = useState(true)
  const [pushing, setPushing]         = useState(false)
  const [pushResult, setPushResult]   = useState<'success' | 'error' | null>(null)
  const [pushError, setPushError]     = useState<string | null>(null)
  const [showConfirm, setShowConfirm] = useState(false)

  // ── Load agent info ──

  useEffect(() => {
    if (!agentId) return
    apiFetch<{ id: string; hostname: string }>(`/api/v1/agents/${agentId}`)
      .then(data => setAgentInfo({ id: data.id, hostname: data.hostname }))
      .catch(() => {})
  }, [agentId])

  // ── Load config ──

  useEffect(() => {
    if (!agentId) return
    setConfigLoading(true)
    setConfigError(null)
    apiFetch<AgentConfigResponse | AgentConfig>(`/api/v1/agents/${agentId}/config`)
      .then(data => {
        const cfg: AgentConfig =
          (data as AgentConfigResponse).config ??
          (data as AgentConfigResponse).data ??
          (data as AgentConfig)
        const merged = mergeWithDefaults(cfg)
        setRawConfig(merged)
        setEditConfig(merged)
      })
      .catch(err => {
        setConfigError(err?.message ?? '設定の取得に失敗しました')
        const def = defaultConfig()
        setRawConfig(def)
        setEditConfig(def)
      })
      .finally(() => setConfigLoading(false))
  }, [agentId])

  // ── Load command history ──

  useEffect(() => {
    if (!agentId) return
    setCmdsLoading(true)
    apiFetch<CommandsResponse | CommandRecord[]>(`/api/v1/agents/${agentId}/commands?limit=20`)
      .then(data => {
        const list: CommandRecord[] = Array.isArray(data)
          ? data
          : (data as CommandsResponse).data ?? (data as CommandsResponse).items ?? []
        // Filter to config-related commands
        const filtered = list.filter(
          c => c.command_type === 'shell' && (c.command ?? '').toLowerCase().includes('config')
        )
        setCommands(filtered)
      })
      .catch(() => setCommands([]))
      .finally(() => setCmdsLoading(false))
  }, [agentId])

  // ── Push handler ──

  async function handlePush() {
    if (!agentId) return
    setPushing(true)
    setPushResult(null)
    setPushError(null)
    setShowConfirm(false)
    try {
      await apiFetch(`/api/v1/agents/${agentId}/commands`, {
        method: 'POST',
        body: JSON.stringify({
          command_type: 'shell',
          command: 'config-push',
          args: editConfig,
        }),
      })
      setPushResult('success')
      setRawConfig(editConfig)
      setIsEditing(false)
      // Refresh command history
      apiFetch<CommandsResponse | CommandRecord[]>(
        `/api/v1/agents/${agentId}/commands?limit=20`
      ).then(data => {
        const list: CommandRecord[] = Array.isArray(data)
          ? data
          : (data as CommandsResponse).data ?? (data as CommandsResponse).items ?? []
        setCommands(
          list.filter(c => c.command_type === 'shell' && (c.command ?? '').includes('config'))
        )
      }).catch(() => {})
    } catch (err: unknown) {
      setPushResult('error')
      setPushError(err instanceof Error ? err.message : 'プッシュに失敗しました')
    } finally {
      setPushing(false)
    }
  }

  // ── Tab config ──

  const tabs: { id: ConfigTab; label: string }[] = [
    { id: 'collectors', label: '収集設定' },
    { id: 'fim',        label: 'FIM設定' },
    { id: 'process',    label: 'プロセス監視' },
    { id: 'resources',  label: 'リソース制限' },
    { id: 'logging',    label: 'ログ設定' },
  ]

  // ─────────────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-900 p-6 space-y-6">

      {/* ── Back link ── */}
      <Link
        href={`/agents/${agentId}`}
        className="inline-flex items-center gap-1.5 text-gray-400 hover:text-white text-sm transition-colors"
      >
        <ChevronLeft className="w-4 h-4" />
        エージェント詳細へ戻る
      </Link>

      {/* ── Header ── */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-blue-700 rounded-lg flex items-center justify-center shrink-0">
            <Settings className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">エージェント設定</h1>
            {agentInfo && (
              <p className="text-xs text-gray-400 mt-0.5">
                ホスト: <span className="text-blue-400 font-medium">{agentInfo.hostname}</span>
              </p>
            )}
          </div>
        </div>
      </div>

      {/* ── Push result banner ── */}
      {pushResult === 'success' && (
        <div className="flex items-center gap-3 p-4 bg-green-900/30 border border-green-700/50 rounded-xl text-green-300 text-sm">
          <CheckCircle className="w-4 h-4 shrink-0" />
          設定をエージェントにプッシュしました。次回ポーリング時に反映されます。
        </div>
      )}
      {pushResult === 'error' && (
        <div className="flex items-center gap-3 p-4 bg-red-900/30 border border-red-700/50 rounded-xl text-red-300 text-sm">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {pushError ?? 'プッシュに失敗しました'}
        </div>
      )}

      {/* ── Current Config Card ── */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-700">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-gray-400" />
            現在の設定
          </h2>
          {!isEditing && !configLoading && (
            <button
              onClick={() => { setIsEditing(true); setPushResult(null) }}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600
                         text-sm text-gray-300 hover:text-white transition-colors"
            >
              <Edit2 className="w-3.5 h-3.5" />
              編集
            </button>
          )}
        </div>

        {configLoading ? (
          <div className="flex items-center justify-center py-10">
            <Loader2 className="animate-spin w-5 h-5 text-blue-400" />
          </div>
        ) : configError && !rawConfig ? (
          <div className="flex items-center gap-2 p-5 text-yellow-300 text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {configError} — デフォルト設定を表示しています
          </div>
        ) : !isEditing ? (
          <pre className="p-5 text-xs text-green-300 font-mono overflow-x-auto bg-gray-900/60 max-h-72">
            {JSON.stringify(rawConfig, null, 2)}
          </pre>
        ) : null}
      </div>

      {/* ── Edit Mode ── */}
      {isEditing && (
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-700">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Edit2 className="w-4 h-4 text-blue-400" />
              設定を編集
            </h2>
            <button
              onClick={() => { setIsEditing(false); setEditConfig(rawConfig ?? defaultConfig()) }}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              キャンセル
            </button>
          </div>

          {/* Tabs */}
          <div className="flex border-b border-gray-700 overflow-x-auto">
            {tabs.map(t => (
              <TabBtn
                key={t.id}
                id={t.id}
                active={activeTab === t.id}
                label={t.label}
                onClick={setActiveTab}
              />
            ))}
          </div>

          {/* Tab content */}
          <div className="p-5">
            {activeTab === 'collectors' && (
              <CollectorsTab config={editConfig} onChange={setEditConfig} />
            )}
            {activeTab === 'fim' && (
              <FimTab config={editConfig} onChange={setEditConfig} />
            )}
            {activeTab === 'process' && (
              <ProcessTab config={editConfig} onChange={setEditConfig} />
            )}
            {activeTab === 'resources' && (
              <ResourcesTab config={editConfig} onChange={setEditConfig} />
            )}
            {activeTab === 'logging' && (
              <LoggingTab config={editConfig} onChange={setEditConfig} />
            )}
          </div>

          {/* Push button */}
          <div className="px-5 pb-5">
            {showConfirm ? (
              <div className="bg-yellow-900/20 border border-yellow-700/50 rounded-lg p-4 space-y-3">
                <p className="text-sm text-yellow-200">
                  設定をエージェントにプッシュします。エージェントは次回のポーリング時に設定を受け取ります。
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={handlePush}
                    disabled={pushing}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500
                               text-white text-sm font-medium transition-colors disabled:opacity-50"
                  >
                    {pushing ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Send className="w-3.5 h-3.5" />
                    )}
                    プッシュを確定
                  </button>
                  <button
                    onClick={() => setShowConfirm(false)}
                    className="px-4 py-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm transition-colors"
                  >
                    キャンセル
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setShowConfirm(true)}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500
                           text-white text-sm font-medium transition-colors"
              >
                <Send className="w-4 h-4" />
                設定をプッシュ
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── Config Push History ── */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-gray-700">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Clock className="w-4 h-4 text-gray-400" />
            設定プッシュ履歴
          </h2>
        </div>

        {cmdsLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="animate-spin w-5 h-5 text-blue-400" />
          </div>
        ) : commands.length === 0 ? (
          <p className="py-8 text-center text-gray-500 text-sm">設定プッシュ履歴なし</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-500 text-xs">
                  <th className="px-5 py-2.5 text-left font-medium">送信日時</th>
                  <th className="px-5 py-2.5 text-left font-medium">ステータス</th>
                  <th className="px-5 py-2.5 text-left font-medium">コマンド</th>
                </tr>
              </thead>
              <tbody>
                {commands.map((cmd, i) => (
                  <tr
                    key={cmd.id}
                    className={`border-b border-gray-700 last:border-0 ${
                      i % 2 === 0 ? 'bg-gray-900/40' : ''
                    }`}
                  >
                    <td className="px-5 py-2.5 text-gray-400 text-xs whitespace-nowrap">
                      {formatTime(cmd.created_at)}
                    </td>
                    <td className="px-5 py-2.5">
                      <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${statusStyle(cmd.status)}`}>
                        {cmd.status ?? '—'}
                      </span>
                    </td>
                    <td className="px-5 py-2.5 text-gray-300 text-xs font-mono">
                      {cmd.command ?? cmd.command_type ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  )
}
