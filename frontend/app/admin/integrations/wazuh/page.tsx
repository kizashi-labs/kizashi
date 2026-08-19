'use client'

import { useState } from 'react'
import {
  Link2,
  CheckCircle2,
  XCircle,
  Eye,
  EyeOff,
  RefreshCw,
  Loader2,
  Info,
  Monitor,
  ChevronRight,
  CheckCheck,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface WazuhConfig {
  apiUrl: string
  username: string
  password: string
}

type ConnectionStatus = 'idle' | 'testing' | 'success' | 'error'
type SyncStatus = 'idle' | 'syncing' | 'done'

interface MockAgent {
  id: string
  name: string
  ip: string
  os: string
  version: string
  status: 'active' | 'disconnected'
  added: boolean
}

// ─── Severity mapping table data ──────────────────────────────────────────────

const SEVERITY_MAP = [
  { range: '15',    edr: 'critical', color: 'text-red-400',    bg: 'bg-red-900/30 border-red-700/40' },
  { range: '12-14', edr: 'high',     color: 'text-orange-400', bg: 'bg-orange-900/30 border-orange-700/40' },
  { range: '7-11',  edr: 'medium',   color: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-700/40' },
  { range: '1-6',   edr: 'low',      color: 'text-blue-400',   bg: 'bg-blue-900/30 border-blue-700/40' },
]

// ─── Mock agent data ───────────────────────────────────────────────────────────

const INITIAL_AGENTS: MockAgent[] = [
  { id: '001', name: 'web-server-01',  ip: '192.168.1.10', os: 'Ubuntu 22.04',     version: 'v4.7.2', status: 'active',       added: false },
  { id: '002', name: 'db-primary',     ip: '192.168.1.20', os: 'CentOS 8',         version: 'v4.7.2', status: 'active',       added: false },
  { id: '003', name: 'workstation-05', ip: '10.0.0.15',    os: 'Windows 11',       version: 'v4.6.1', status: 'active',       added: false },
  { id: '004', name: 'mail-relay',     ip: '192.168.2.5',  os: 'Debian 11',        version: 'v4.5.4', status: 'disconnected', added: false },
  { id: '005', name: 'backup-srv',     ip: '172.16.0.30',  os: 'Ubuntu 20.04 LTS', version: 'v4.7.1', status: 'active',       added: false },
]

// ─── Section card ─────────────────────────────────────────────────────────────

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

// ─── Field label ──────────────────────────────────────────────────────────────

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-sm text-gray-400 mb-1.5">{children}</label>
  )
}

// ─── Text input ───────────────────────────────────────────────────────────────

function TextInput({
  value,
  onChange,
  placeholder,
  type = 'text',
  className = '',
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
  className?: string
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      className={`w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2.5 text-sm
                  text-gray-200 placeholder-gray-500 focus:outline-hidden focus:border-blue-500
                  focus:ring-1 focus:ring-blue-500/30 transition-colors ${className}`}
    />
  )
}

// ─── Toggle checkbox ──────────────────────────────────────────────────────────

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

export default function WazuhIntegrationPage() {
  // Config state
  const [config, setConfig] = useState<WazuhConfig>({
    apiUrl: 'https://wazuh-manager:55000',
    username: 'wazuh-api',
    password: '',
  })
  const [showPassword, setShowPassword] = useState(false)

  // Connection state
  const [connStatus, setConnStatus] = useState<ConnectionStatus>('idle')

  // Sync settings
  const [importAgents, setImportAgents]   = useState(true)
  const [importAlerts, setImportAlerts]   = useState(true)
  const [syncStatus, setSyncStatus]       = useState<SyncStatus>('idle')
  const [syncMessage, setSyncMessage]     = useState<string | null>(null)
  const [lastSync, setLastSync]           = useState<string | null>(null)

  // Agents
  const [agents, setAgents] = useState<MockAgent[]>(INITIAL_AGENTS)

  // ─── Handlers ───────────────────────────────────────────────────────────────

  const handleTestConnection = async () => {
    setConnStatus('testing')
    await new Promise(r => setTimeout(r, 1000))
    setConnStatus('success')
  }

  const handleSync = async () => {
    setSyncStatus('syncing')
    setSyncMessage(null)
    // Simulate progress
    await new Promise(r => setTimeout(r, 2000))
    setSyncStatus('done')
    setSyncMessage('同期完了: エージェント 24件, アラート 156件')
    setLastSync(new Date().toLocaleString('ja-JP'))
  }

  const handleAddAgent = (agentId: string) => {
    setAgents(prev =>
      prev.map(a => (a.id === agentId ? { ...a, added: true } : a)),
    )
  }

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="max-w-screen-lg mx-auto p-6 space-y-6">

        {/* ── Header ──────────────────────────────────────────────── */}
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-orange-900/40 border border-orange-700/50 flex items-center justify-center shrink-0">
              <Link2 className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Wazuh連携</h1>
              <p className="text-sm text-gray-400 mt-0.5">
                Wazuh SIEM/XDR プラットフォームとの統合設定
              </p>
            </div>
          </div>
        </div>

        {/* ── Connection config card ───────────────────────────────── */}
        <SectionCard
          title="接続設定"
          icon={<Link2 className="w-4 h-4" />}
        >
          <div className="space-y-5">
            {/* API URL */}
            <div>
              <FieldLabel>Wazuh API URL</FieldLabel>
              <TextInput
                value={config.apiUrl}
                onChange={v => setConfig(c => ({ ...c, apiUrl: v }))}
                placeholder="https://wazuh-manager:55000"
              />
              <p className="text-xs text-gray-600 mt-1">
                例: https://wazuh-manager:55000
              </p>
            </div>

            {/* Username + Password row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <FieldLabel>ユーザー名</FieldLabel>
                <TextInput
                  value={config.username}
                  onChange={v => setConfig(c => ({ ...c, username: v }))}
                  placeholder="wazuh-api"
                />
              </div>
              <div>
                <FieldLabel>パスワード</FieldLabel>
                <div className="relative">
                  <TextInput
                    type={showPassword ? 'text' : 'password'}
                    value={config.password}
                    onChange={v => setConfig(c => ({ ...c, password: v }))}
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
            </div>

            {/* Connection test row */}
            <div className="flex items-center gap-4 pt-1">
              <button
                onClick={handleTestConnection}
                disabled={connStatus === 'testing' || !config.apiUrl}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-gray-700 hover:bg-gray-600 border border-gray-600 text-gray-200 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {connStatus === 'testing' ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <RefreshCw className="w-4 h-4" />
                )}
                接続テスト
              </button>

              {/* Status indicator */}
              {connStatus !== 'idle' && (
                <div className="flex items-center gap-2">
                  {connStatus === 'testing' && (
                    <>
                      <div className="w-2.5 h-2.5 rounded-full bg-yellow-400 animate-pulse" />
                      <span className="text-sm text-yellow-400">接続中...</span>
                    </>
                  )}
                  {connStatus === 'success' && (
                    <>
                      <div className="w-2.5 h-2.5 rounded-full bg-green-400" />
                      <span className="text-sm text-green-400 flex items-center gap-1">
                        <CheckCircle2 className="w-4 h-4" />
                        接続成功
                      </span>
                    </>
                  )}
                  {connStatus === 'error' && (
                    <>
                      <div className="w-2.5 h-2.5 rounded-full bg-red-400" />
                      <span className="text-sm text-red-400 flex items-center gap-1">
                        <XCircle className="w-4 h-4" />
                        接続失敗
                      </span>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        </SectionCard>

        {/* ── Sync settings card ──────────────────────────────────── */}
        <SectionCard
          title="同期設定"
          icon={<RefreshCw className="w-4 h-4" />}
        >
          <div className="space-y-6">
            {/* Import toggles */}
            <div className="space-y-4">
              <ToggleRow
                label="エージェントをインポート"
                description="Wazuh エージェントを EDR プラットフォームに同期します"
                checked={importAgents}
                onChange={setImportAgents}
              />
              <ToggleRow
                label="アラートをインポート"
                description="Wazuh のアラートを EDR アラートとして取り込みます"
                checked={importAlerts}
                onChange={setImportAlerts}
              />
            </div>

            <div className="border-t border-gray-700" />

            {/* Severity mapping */}
            <div>
              <p className="text-sm font-semibold text-gray-300 mb-3">
                アラート重大度マッピング
              </p>
              <div className="rounded-xl border border-gray-700 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-900/40 border-b border-gray-700">
                      <th className="text-left px-4 py-2.5 text-xs text-gray-400 font-medium uppercase tracking-wide">
                        Wazuh レベル
                      </th>
                      <th className="text-left px-4 py-2.5 text-xs text-gray-400 font-medium uppercase tracking-wide">
                        EDR 重大度
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700/50">
                    {SEVERITY_MAP.map(row => (
                      <tr key={row.range} className="hover:bg-gray-700/20 transition-colors">
                        <td className="px-4 py-3">
                          <span className="text-gray-300 font-mono text-sm">
                            Level {row.range}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs
                                        font-semibold border ${row.bg} ${row.color}`}
                          >
                            {row.edr}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="border-t border-gray-700" />

            {/* Sync controls */}
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div>
                {lastSync && (
                  <p className="text-xs text-gray-500">
                    最終同期: <span className="text-gray-400">{lastSync}</span>
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3">
                {syncStatus === 'done' && syncMessage && (
                  <span className="text-sm text-green-400 flex items-center gap-1.5">
                    <CheckCheck className="w-4 h-4" />
                    {syncMessage}
                  </span>
                )}
                <button
                  onClick={handleSync}
                  disabled={syncStatus === 'syncing'}
                  className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
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

        {/* ── Imported agents preview ──────────────────────────────── */}
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Monitor className="w-4 h-4 text-gray-400" />
              <h2 className="text-base font-semibold text-white">インポート済みエージェント</h2>
              <span className="text-xs text-gray-500 bg-gray-700 px-2 py-0.5 rounded-full">
                {agents.length}件 (プレビュー)
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-900/30 border-b border-gray-700">
                  <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                    エージェント名
                  </th>
                  <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                    IPアドレス
                  </th>
                  <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                    OS
                  </th>
                  <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                    Wazuh バージョン
                  </th>
                  <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                    ステータス
                  </th>
                  <th className="text-left px-6 py-3 text-xs text-gray-400 font-medium uppercase tracking-wide">
                    操作
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/50">
                {agents.map(agent => (
                  <tr key={agent.id} className="hover:bg-gray-700/20 transition-colors">
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <Monitor className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                        <span className="text-gray-200 font-medium">{agent.name}</span>
                        <span className="text-xs text-gray-600 font-mono">#{agent.id}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      <span className="text-gray-400 font-mono text-xs">{agent.ip}</span>
                    </td>
                    <td className="px-6 py-3">
                      <span className="text-gray-300 text-xs">{agent.os}</span>
                    </td>
                    <td className="px-6 py-3">
                      <span className="text-gray-400 font-mono text-xs">{agent.version}</span>
                    </td>
                    <td className="px-6 py-3">
                      {agent.status === 'active' ? (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-900/40 text-green-300 border border-green-700/40">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block" />
                          アクティブ
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-gray-700/40 text-gray-400 border border-gray-600/40">
                          <span className="w-1.5 h-1.5 rounded-full bg-gray-500 inline-block" />
                          切断中
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-3">
                      {agent.added ? (
                        <span className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-full bg-blue-900/30 text-blue-300 border border-blue-700/40">
                          <CheckCircle2 className="w-3 h-3" />
                          追加済み
                        </span>
                      ) : (
                        <button
                          onClick={() => handleAddAgent(agent.id)}
                          className="flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-300 border border-gray-600 transition-colors hover:text-white"
                        >
                          EDRに追加
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  )
}
