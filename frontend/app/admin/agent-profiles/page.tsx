'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Settings, Plus, X, RefreshCw, CheckCircle, Monitor,
  Server, Apple, Layers, ChevronDown, ChevronUp, Upload, Edit3,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type OSType = 'Windows' | 'Linux' | 'macOS' | 'All'

interface ProfileConfig {
  collection_interval: number
  enable_process_monitor: boolean
  enable_network_monitor: boolean
  enable_file_monitor: boolean
  enable_registry_monitor: boolean
  file_monitor_paths: string
  max_events_per_min: number
  log_level: 'debug' | 'info' | 'warn' | 'error'
  heartbeat_interval: number
}

interface AgentProfile {
  id: string
  name: string
  description: string
  os_type: OSType
  is_default: boolean
  config: ProfileConfig
  agent_count: number
  updated_at: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: ProfileConfig = {
  collection_interval: 30,
  enable_process_monitor: true,
  enable_network_monitor: true,
  enable_file_monitor: true,
  enable_registry_monitor: false,
  file_monitor_paths: '/etc\n/usr/bin\n/tmp',
  max_events_per_min: 1000,
  log_level: 'info',
  heartbeat_interval: 60,
}


// ─── Helpers ──────────────────────────────────────────────────────────────────

type OSConfig = { label: string; icon: React.ReactNode; className: string }

const OS_CONFIG: Record<OSType, OSConfig> = {
  Windows: { label: 'Windows', icon: <Monitor className="w-3.5 h-3.5" />, className: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
  Linux:   { label: 'Linux',   icon: <Server  className="w-3.5 h-3.5" />, className: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
  macOS:   { label: 'macOS',   icon: <Apple   className="w-3.5 h-3.5" />, className: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30' },
  All:     { label: '全OS',    icon: <Layers  className="w-3.5 h-3.5" />, className: 'bg-purple-500/15 text-purple-400 border-purple-500/30' },
}

const OS_CONFIG_FALLBACK: OSConfig = {
  label: '不明',
  icon: <Layers className="w-3.5 h-3.5" />,
  className: 'bg-zinc-700/30 text-zinc-400 border-zinc-600/40',
}

const OS_ALIAS: Record<string, OSType> = {
  windows: 'Windows', linux: 'Linux', macos: 'macOS', darwin: 'macOS', all: 'All',
  Windows: 'Windows', Linux: 'Linux', macOS: 'macOS', All: 'All',
}

const osConfigFor = (osType: string | undefined): OSConfig => {
  if (!osType) return OS_CONFIG_FALLBACK
  const canonical = OS_ALIAS[osType] ?? OS_ALIAS[osType.toLowerCase()]
  return (canonical && OS_CONFIG[canonical]) || OS_CONFIG_FALLBACK
}

const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const

const MonitorCheck = ({ enabled, label }: { enabled: boolean; label: string }) => (
  <div className="flex items-center gap-1.5 text-xs">
    <CheckCircle className={`w-3.5 h-3.5 shrink-0 ${enabled ? 'text-green-400' : 'text-zinc-700'}`} />
    <span className={enabled ? 'text-zinc-300' : 'text-zinc-600'}>{label}</span>
  </div>
)

// ─── Main Component ───────────────────────────────────────────────────────────

export default function AgentProfilesPage() {
  const [showNewProfile, setShowNewProfile] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [pushModalId, setPushModalId] = useState<string | null>(null)
  const [pushAgentId, setPushAgentId] = useState('')
  const [pushLoading, setPushLoading] = useState(false)
  const [pushSuccess, setPushSuccess] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const [newProfileForm, setNewProfileForm] = useState({
    name: '',
    description: '',
    os_type: 'Windows' as OSType,
    config: { ...DEFAULT_CONFIG },
  })

  const [editConfig, setEditConfig] = useState<ProfileConfig>({ ...DEFAULT_CONFIG })

  const { data: agentsData } = useQuery<{ data: { id: string; hostname: string; os_type: string }[] }>({
    queryKey: ['agents-for-profiles'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=500'),
    staleTime: 60_000,
  })
  const agentsList = agentsData?.data ?? []

  const { data: profiles = [], refetch } = useQuery<AgentProfile[]>({
    queryKey: ['agent-profiles'],
    queryFn: async () => {
      try { return await apiFetchList<AgentProfile>('/api/v1/admin/agent-profiles') } catch { return [] }
    },
    staleTime: 30_000,
    retry: false,
  })

  const handleCreateProfile = async () => {
    try {
      await apiFetch('/api/v1/admin/agent-profiles', {
        method: 'POST',
        body: JSON.stringify(newProfileForm),
      })
    } catch { /* mock */ }
    setShowNewProfile(false)
    setNewProfileForm({ name: '', description: '', os_type: 'Windows', config: { ...DEFAULT_CONFIG } })
    refetch()
  }

  const handleSaveEdit = async (profileId: string) => {
    try {
      await apiFetch(`/api/v1/admin/agent-profiles/${profileId}`, {
        method: 'PUT',
        body: JSON.stringify({ config: editConfig }),
      })
    } catch { /* mock */ }
    setEditingId(null)
    refetch()
  }

  const handlePush = async (profileId: string) => {
    if (!pushAgentId.trim()) return
    setPushLoading(true)
    try {
      await apiFetch(`/api/v1/admin/agent-profiles/${profileId}/push`, {
        method: 'POST',
        body: JSON.stringify({ agent_id: pushAgentId }),
      })
    } catch { /* mock */ } finally {
      setPushLoading(false)
      setPushSuccess(true)
      setTimeout(() => {
        setPushSuccess(false)
        setPushModalId(null)
        setPushAgentId('')
      }, 2000)
    }
  }

  const openEdit = (profile: AgentProfile) => {
    setEditConfig({ ...profile.config })
    setEditingId(profile.id)
    setExpandedId(profile.id)
  }

  const ConfigEditor = ({ config, setConfig }: { config: ProfileConfig; setConfig: (c: ProfileConfig) => void }) => (
    <div className="space-y-4 mt-3">
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="block text-xs text-zinc-500 mb-1">収集間隔（秒）</label>
          <input
            type="number"
            value={config.collection_interval}
            onChange={e => setConfig({ ...config, collection_interval: Number(e.target.value) })}
            className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-700 rounded-sm text-sm text-zinc-200 focus:outline-hidden focus:border-zinc-500"
            min={5}
          />
        </div>
        <div>
          <label className="block text-xs text-zinc-500 mb-1">最大イベント数/分</label>
          <input
            type="number"
            value={config.max_events_per_min}
            onChange={e => setConfig({ ...config, max_events_per_min: Number(e.target.value) })}
            className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-700 rounded-sm text-sm text-zinc-200 focus:outline-hidden focus:border-zinc-500"
            min={100}
          />
        </div>
        <div>
          <label className="block text-xs text-zinc-500 mb-1">ハートビート間隔（秒）</label>
          <input
            type="number"
            value={config.heartbeat_interval}
            onChange={e => setConfig({ ...config, heartbeat_interval: Number(e.target.value) })}
            className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-700 rounded-sm text-sm text-zinc-200 focus:outline-hidden focus:border-zinc-500"
            min={10}
          />
        </div>
      </div>

      <div>
        <label className="block text-xs text-zinc-500 mb-1.5">ログレベル</label>
        <div className="flex gap-2">
          {LOG_LEVELS.map(l => (
            <button
              key={l}
              onClick={() => setConfig({ ...config, log_level: l })}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                config.log_level === l
                  ? 'bg-zinc-600 text-zinc-100'
                  : 'bg-zinc-800 text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {l}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-xs text-zinc-500 mb-2">モニター</label>
        <div className="grid grid-cols-2 gap-2">
          {[
            { key: 'enable_process_monitor',  label: 'プロセスモニター' },
            { key: 'enable_network_monitor',  label: 'ネットワークモニター' },
            { key: 'enable_file_monitor',     label: 'ファイルモニター' },
            { key: 'enable_registry_monitor', label: 'レジストリモニター' },
          ].map(({ key, label }) => (
            <label key={key} className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={config[key as keyof ProfileConfig] as boolean}
                onChange={e => setConfig({ ...config, [key]: e.target.checked })}
                className="w-3.5 h-3.5 rounded-sm accent-blue-500"
              />
              <span className="text-sm text-zinc-300">{label}</span>
            </label>
          ))}
        </div>
      </div>

      {config.enable_file_monitor && (
        <div>
          <label className="block text-xs text-zinc-500 mb-1">ファイル監視パス（1行に1つ）</label>
          <textarea
            value={config.file_monitor_paths}
            onChange={e => setConfig({ ...config, file_monitor_paths: e.target.value })}
            rows={4}
            className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-700 rounded-sm text-sm text-zinc-200 font-mono focus:outline-hidden focus:border-zinc-500 resize-none"
          />
        </div>
      )}
    </div>
  )

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      {/* Push Modal */}
      {pushModalId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-zinc-900 border border-zinc-700 rounded-xl w-full max-w-sm">
            <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
              <h3 className="text-zinc-100 font-semibold">エージェントにプロファイルを適用</h3>
              <button onClick={() => { setPushModalId(null); setPushAgentId('') }} className="text-zinc-500 hover:text-zinc-300">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5">
              {pushSuccess ? (
                <div className="flex flex-col items-center py-4">
                  <CheckCircle className="w-10 h-10 text-green-400 mb-2" />
                  <p className="text-green-400 font-medium">プロファイルを適用しました</p>
                </div>
              ) : (
                <>
                  <label className="block text-xs text-zinc-500 mb-1.5">エージェント</label>
                  <div className="relative mb-4">
                    <select
                      value={pushAgentId}
                      onChange={e => setPushAgentId(e.target.value)}
                      className="w-full appearance-none px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-sm text-sm text-zinc-200 focus:outline-hidden focus:border-blue-500/50 pr-8"
                    >
                      <option value="">エージェントを選択...</option>
                      {agentsList.map(a => (
                        <option key={a.id} value={a.id}>{a.hostname} ({a.os_type})</option>
                      ))}
                    </select>
                    <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500 pointer-events-none" />
                  </div>
                  <div className="flex gap-3">
                    <button
                      onClick={() => { setPushModalId(null); setPushAgentId('') }}
                      className="flex-1 py-2 rounded-sm border border-zinc-700 text-zinc-400 text-sm hover:text-zinc-200 transition-colors"
                    >
                      キャンセル
                    </button>
                    <button
                      onClick={() => handlePush(pushModalId)}
                      disabled={!pushAgentId.trim() || pushLoading}
                      className="flex-1 py-2 rounded-sm bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
                    >
                      {pushLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                      適用
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Settings className="w-7 h-7 text-zinc-400" />
            エージェント設定プロファイル
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            エンドポイントエージェントに設定プロファイルを管理・展開します
          </p>
        </div>
        <button
          onClick={() => setShowNewProfile(v => !v)}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-zinc-900 border border-zinc-700 text-zinc-300 hover:text-zinc-100 text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          新規プロファイル
        </button>
      </div>

      {/* New Profile Form */}
      {showNewProfile && (
        <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-5 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-zinc-100 font-semibold">新規設定プロファイル</h2>
            <button onClick={() => setShowNewProfile(false)} className="text-zinc-500 hover:text-zinc-300">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">プロファイル名</label>
              <input
                value={newProfileForm.name}
                onChange={e => setNewProfileForm(f => ({ ...f, name: e.target.value }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-sm text-sm text-zinc-200 focus:outline-hidden focus:border-zinc-500"
                placeholder="マイプロファイル"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">OSタイプ</label>
              <select
                value={newProfileForm.os_type}
                onChange={e => setNewProfileForm(f => ({ ...f, os_type: e.target.value as OSType }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-sm text-sm text-zinc-200 focus:outline-hidden focus:border-zinc-500"
              >
                {(['Windows', 'Linux', 'macOS', 'All'] as OSType[]).map(os => (
                  <option key={os} value={os}>{os === 'All' ? '全OS' : os}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-zinc-500 mb-1.5">説明</label>
              <input
                value={newProfileForm.description}
                onChange={e => setNewProfileForm(f => ({ ...f, description: e.target.value }))}
                className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-sm text-sm text-zinc-200 focus:outline-hidden focus:border-zinc-500"
                placeholder="任意の説明"
              />
            </div>
          </div>
          <ConfigEditor
            config={newProfileForm.config}
            setConfig={c => setNewProfileForm(f => ({ ...f, config: c }))}
          />
          <div className="mt-4 flex justify-end">
            <button
              onClick={handleCreateProfile}
              disabled={!newProfileForm.name}
              className="px-5 py-2 rounded-sm bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              プロファイルを作成
            </button>
          </div>
        </div>
      )}

      {/* Profile Cards Grid */}
      <div className="grid grid-cols-1 gap-4">
        {profiles.map(profile => {
          const osCfg = osConfigFor(profile.os_type)
          const isEditing = editingId === profile.id
          const isExpanded = expandedId === profile.id

          return (
            <div key={profile.id} className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
              {/* Card Header */}
              <div className="px-5 py-4 flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[11px] font-medium border ${osCfg.className}`}>
                      {osCfg.icon}
                      {osCfg.label}
                    </span>
                    <span className="text-zinc-100 font-semibold">{profile.name}</span>
                    {profile.is_default && (
                      <span className="px-2 py-0.5 rounded-sm bg-blue-500/15 text-blue-400 border border-blue-500/30 text-[10px] font-medium">
                        デフォルト
                      </span>
                    )}
                  </div>
                  <p className="text-zinc-500 text-xs">{profile.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-zinc-600">
                    <span>{profile.agent_count} エージェントが使用中</span>
                    <span>更新日: {new Date(profile.updated_at).toLocaleDateString('ja-JP')}</span>
                    <span>{profile.config.collection_interval}秒ごとに収集</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => setPushModalId(profile.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-zinc-800 text-zinc-300 hover:text-zinc-100 text-xs transition-colors"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    エージェントに適用
                  </button>
                  <button
                    onClick={() => openEdit(profile)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-zinc-800 text-zinc-300 hover:text-zinc-100 text-xs transition-colors"
                  >
                    <Edit3 className="w-3.5 h-3.5" />
                    編集
                  </button>
                  <button
                    onClick={() => setExpandedId(isExpanded && !isEditing ? null : profile.id)}
                    className="p-1.5 rounded-sm hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 transition-colors"
                  >
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Config Preview / Edit */}
              {isExpanded && (
                <div className="border-t border-zinc-800 px-5 py-4 bg-zinc-950/30">
                  {isEditing ? (
                    <>
                      <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">設定を編集</h4>
                      <ConfigEditor config={editConfig} setConfig={setEditConfig} />
                      <div className="flex justify-end gap-3 mt-4">
                        <button
                          onClick={() => setEditingId(null)}
                          className="px-4 py-2 rounded-sm text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
                        >
                          キャンセル
                        </button>
                        <button
                          onClick={() => handleSaveEdit(profile.id)}
                          className="px-4 py-2 rounded-sm bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 transition-colors"
                        >
                          変更を保存
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <h4 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-3">設定プレビュー</h4>
                      <div className="grid grid-cols-3 gap-4">
                        <div className="space-y-1">
                          <p className="text-xs text-zinc-600 font-medium uppercase tracking-wider mb-2">インターバル</p>
                          <div className="text-xs text-zinc-400">収集間隔: <span className="text-zinc-200">{profile.config.collection_interval}秒</span></div>
                          <div className="text-xs text-zinc-400">ハートビート: <span className="text-zinc-200">{profile.config.heartbeat_interval}秒</span></div>
                          <div className="text-xs text-zinc-400">最大イベント数/分: <span className="text-zinc-200">{(profile.config.max_events_per_min ?? 0).toLocaleString()}</span></div>
                          <div className="text-xs text-zinc-400">ログレベル: <span className="text-zinc-200">{profile.config.log_level}</span></div>
                        </div>
                        <div>
                          <p className="text-xs text-zinc-600 font-medium uppercase tracking-wider mb-2">モニター</p>
                          <div className="space-y-1.5">
                            <MonitorCheck enabled={profile.config.enable_process_monitor} label="プロセス" />
                            <MonitorCheck enabled={profile.config.enable_network_monitor} label="ネットワーク" />
                            <MonitorCheck enabled={profile.config.enable_file_monitor}    label="ファイル" />
                            <MonitorCheck enabled={profile.config.enable_registry_monitor} label="レジストリ" />
                          </div>
                        </div>
                        {profile.config.enable_file_monitor && (
                          <div>
                            <p className="text-xs text-zinc-600 font-medium uppercase tracking-wider mb-2">ファイル監視パス</p>
                            <pre className="text-xs text-zinc-400 font-mono leading-relaxed">
                              {profile.config.file_monitor_paths}
                            </pre>
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
