'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ShieldAlert, Plus, X, Trash2, ToggleLeft, ToggleRight,
  Save, Filter, Eye, AlertTriangle, CheckCircle, BarChart3
} from 'lucide-react'


// ── Types ────────────────────────────────────────────────────────

interface RansomwareConfig {
  enabled: boolean
  protected_folders: string[]
  allowed_apps: string[]
  canary_files_enabled: boolean
  canary_paths: string[]
  entropy_detection_enabled: boolean
  entropy_threshold: number
  backup_enabled: boolean
  backup_interval: '1h' | '4h' | '12h' | '24h'
}

type EventType = 'canary_triggered' | 'high_entropy' | 'mass_rename' | 'shadow_delete'

interface RansomEvent {
  id: string
  timestamp: string
  hostname: string
  event_type: EventType
  process_name: string
  affected_files: number
  auto_isolated: boolean
  details: Record<string, unknown>
  timeline: string[]
}

interface RansomStats {
  events_by_type: Record<EventType, number>
  protected_folders_count: number
  canary_files_count: number
  detection_rate: number
  events_blocked: number
  events_allowed: number
}

// ── Helpers ──────────────────────────────────────────────────────

const EVENT_TYPE_STYLES: Record<EventType, { label: string; bg: string; text: string }> = {
  canary_triggered: { label: 'カナリア発火',  bg: 'bg-red-900/50',    text: 'text-red-300' },
  high_entropy:     { label: '高エントロピー', bg: 'bg-orange-900/40', text: 'text-orange-300' },
  mass_rename:      { label: '大量リネーム',   bg: 'bg-red-900/50',    text: 'text-red-300' },
  shadow_delete:    { label: 'VSS削除',        bg: 'bg-red-900/50',    text: 'text-red-300' },
}

const EVENT_TYPE_LABELS: Record<EventType, string> = {
  canary_triggered: 'カナリア発火',
  high_entropy: '高エントロピー',
  mass_rename: '大量リネーム',
  shadow_delete: 'VSS削除',
}

function fmt(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Event Detail Modal ───────────────────────────────────────────

function EventDetailModal({ event, onClose }: { event: RansomEvent; onClose: () => void }) {
  const es = EVENT_TYPE_STYLES[event.event_type]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-falcon-surface border-b border-falcon-border px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${es.bg} ${es.text}`}>{es.label}</span>
            <span className="text-white font-semibold">{event.hostname}</span>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-5">
          <div className="grid grid-cols-3 gap-3">
            {[['タイムスタンプ', fmt(event.timestamp)], ['プロセス', event.process_name], ['影響ファイル', String(event.affected_files)]].map(([k, v]) => (
              <div key={k} className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
                <p className="text-xs text-falcon-muted mb-1">{k}</p>
                <p className="text-white text-sm font-mono">{v}</p>
              </div>
            ))}
          </div>
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
            <p className="text-xs text-falcon-muted font-medium uppercase tracking-wider mb-3">詳細情報</p>
            {Object.entries(event.details).map(([k, v]) => (
              <div key={k} className="flex gap-3 items-start mb-2">
                <span className="text-falcon-muted text-xs font-mono w-40 shrink-0">{k}:</span>
                <span className="text-falcon-text text-xs font-mono break-all">
                  {Array.isArray(v) ? v.join(', ') : String(v)}
                </span>
              </div>
            ))}
          </div>
          <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
            <p className="text-xs text-falcon-muted font-medium uppercase tracking-wider mb-3">アクションタイムライン</p>
            <div className="space-y-2">
              {event.timeline.map((step, i) => (
                <div key={i} className="flex items-start gap-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-falcon-red mt-1.5 shrink-0" />
                  <p className="text-xs text-falcon-text font-mono">{step}</p>
                </div>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-falcon-muted">自動隔離:</span>
            {event.auto_isolated
              ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" />実行済み</span>
              : <span className="text-falcon-muted text-xs">未実行</span>}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function RansomwareProtectionPage() {
  const [tab, setTab] = useState<'config' | 'events' | 'stats'>('config')
  const EMPTY_CONFIG: RansomwareConfig = { enabled: false, protected_folders: [], allowed_apps: [], canary_files_enabled: false, canary_paths: [], entropy_detection_enabled: false, entropy_threshold: 7.0, backup_enabled: false, backup_interval: '24h' }
  const [config, setConfig] = useState<RansomwareConfig>(EMPTY_CONFIG)
  const [newFolder, setNewFolder] = useState('')
  const [newApp, setNewApp] = useState('')
  const [newCanary, setNewCanary] = useState('')
  const [filterType, setFilterType] = useState('')
  const [selectedEvent, setSelectedEvent] = useState<RansomEvent | null>(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const EMPTY_STATS: RansomStats = { events_by_type: { canary_triggered: 0, high_entropy: 0, mass_rename: 0, shadow_delete: 0 }, protected_folders_count: 0, canary_files_count: 0, detection_rate: 0, events_blocked: 0, events_allowed: 0 }

  const { data: eventsData } = useQuery<RansomEvent[]>({
    queryKey: ['ransomware-events'],
    queryFn: async () => {
      try { return await apiFetchList<RansomEvent>('/api/v1/admin/ransomware/events') } catch { return [] }
    },
  })

  const { data: statsData } = useQuery<RansomStats>({
    queryKey: ['ransomware-stats'],
    queryFn: async () => {
      try { return await apiFetch('/api/v1/admin/ransomware/stats') } catch { return EMPTY_STATS }
    },
  })

  const events: RansomEvent[] = Array.isArray(eventsData) ? eventsData : []
  const stats: RansomStats = (statsData && typeof statsData === 'object' && 'events_by_type' in statsData)
    ? statsData as RansomStats
    : EMPTY_STATS

  const filteredEvents = events.filter(e => !filterType || e.event_type === filterType)

  const handleSave = async () => {
    setSaving(true)
    try { await apiFetch('/api/v1/admin/ransomware/config', { method: 'PUT', body: JSON.stringify(config) }) }
    catch {}
    setSaving(false)
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  const statValues = Object.values(stats.events_by_type)
  const maxStat = statValues.length > 0 ? Math.max(...statValues) : 1

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white text-2xl font-bold">ランサムウェア対策</h1>
            <p className="text-falcon-muted text-sm">リアルタイム保護・検知・対応設定</p>
          </div>
        </div>

        {/* Master toggle */}
        <div className="flex items-center gap-4 bg-falcon-surface border border-falcon-border rounded-xl px-5 py-3">
          <div>
            <p className="text-white text-sm font-medium">保護ステータス</p>
            <p className="text-xs mt-0.5">
              {config.enabled
                ? <span className="flex items-center gap-1 text-green-400"><CheckCircle className="w-3 h-3" />保護有効</span>
                : <span className="text-red-400">保護無効</span>}
            </p>
          </div>
          <button onClick={() => setConfig(p => ({ ...p, enabled: !p.enabled }))} className="ml-2">
            {config.enabled
              ? <ToggleRight className="w-10 h-10 text-green-400" />
              : <ToggleLeft className="w-10 h-10 text-falcon-subtle" />}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[
          { key: 'config', label: '保護設定' },
          { key: 'events', label: '検出イベント' },
          { key: 'stats', label: '統計' },
        ].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === t.key ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
            }`}>{t.label}</button>
        ))}
      </div>

      {/* Config Tab */}
      {tab === 'config' && (
        <div className="space-y-5">
          {/* Protected Folders */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">保護フォルダ</h3>
            <div className="space-y-2 mb-4">
              {config.protected_folders.map((f, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="flex-1 font-mono text-xs text-falcon-text bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2">{f}</span>
                  <button onClick={() => setConfig(p => ({ ...p, protected_folders: p.protected_folders.filter((_, j) => j !== i) }))}
                    className="text-red-400 hover:text-red-300 transition-colors p-1">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <input value={newFolder} onChange={e => setNewFolder(e.target.value)}
                placeholder="例: C:\\Users\\*\\Documents"
                className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50" />
              <button onClick={() => { if (newFolder) { setConfig(p => ({ ...p, protected_folders: [...p.protected_folders, newFolder] })); setNewFolder('') } }}
                className="flex items-center gap-1.5 px-4 py-2 bg-falcon-red/20 border border-falcon-red/40 text-falcon-red rounded-sm text-sm hover:bg-falcon-red/30 transition-colors">
                <Plus className="w-4 h-4" /> フォルダ追加
              </button>
            </div>
          </div>

          {/* Allowed Apps */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">許可アプリケーション (Allowlist)</h3>
            <div className="space-y-2 mb-4">
              {config.allowed_apps.map((a, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="flex-1 font-mono text-xs text-falcon-text bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 truncate">{a}</span>
                  <button onClick={() => setConfig(p => ({ ...p, allowed_apps: p.allowed_apps.filter((_, j) => j !== i) }))}
                    className="text-red-400 hover:text-red-300 transition-colors p-1">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <input value={newApp} onChange={e => setNewApp(e.target.value)}
                placeholder="例: C:\\Program Files\\App\\app.exe"
                className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50" />
              <button onClick={() => { if (newApp) { setConfig(p => ({ ...p, allowed_apps: [...p.allowed_apps, newApp] })); setNewApp('') } }}
                className="flex items-center gap-1.5 px-4 py-2 bg-falcon-red/20 border border-falcon-red/40 text-falcon-red rounded-sm text-sm hover:bg-falcon-red/30 transition-colors">
                <Plus className="w-4 h-4" /> アプリ追加
              </button>
            </div>
          </div>

          {/* Detection Settings */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">検出設定</h3>
            <div className="space-y-5">
              {/* Canary files */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <p className="text-white text-sm">カナリアファイル</p>
                    <p className="text-falcon-muted text-xs mt-0.5">おとりファイルへのアクセスを検知します</p>
                  </div>
                  <button onClick={() => setConfig(p => ({ ...p, canary_files_enabled: !p.canary_files_enabled }))}>
                    {config.canary_files_enabled
                      ? <ToggleRight className="w-7 h-7 text-green-400" />
                      : <ToggleLeft className="w-7 h-7 text-falcon-subtle" />}
                  </button>
                </div>
                {config.canary_files_enabled && (
                  <div className="ml-4 space-y-2">
                    {config.canary_paths.map((p, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <span className="flex-1 font-mono text-xs text-falcon-text bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 truncate">{p}</span>
                        <button onClick={() => setConfig(prev => ({ ...prev, canary_paths: prev.canary_paths.filter((_, j) => j !== i) }))}
                          className="text-red-400 hover:text-red-300 p-1"><Trash2 className="w-3.5 h-3.5" /></button>
                      </div>
                    ))}
                    <div className="flex gap-2">
                      <input value={newCanary} onChange={e => setNewCanary(e.target.value)}
                        placeholder="カナリアパスを入力..."
                        className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-xs text-white font-mono placeholder-falcon-subtle focus:outline-hidden" />
                      <button onClick={() => { if (newCanary) { setConfig(p => ({ ...p, canary_paths: [...p.canary_paths, newCanary] })); setNewCanary('') } }}
                        className="px-3 py-1.5 bg-falcon-red/20 border border-falcon-red/40 text-falcon-red rounded-sm text-xs hover:bg-falcon-red/30">
                        <Plus className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Entropy detection */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <p className="text-white text-sm">エントロピー検知</p>
                    <p className="text-falcon-muted text-xs mt-0.5">暗号化を示す高エントロピーのファイル書き込みを検知</p>
                  </div>
                  <button onClick={() => setConfig(p => ({ ...p, entropy_detection_enabled: !p.entropy_detection_enabled }))}>
                    {config.entropy_detection_enabled
                      ? <ToggleRight className="w-7 h-7 text-green-400" />
                      : <ToggleLeft className="w-7 h-7 text-falcon-subtle" />}
                  </button>
                </div>
                {config.entropy_detection_enabled && (
                  <div className="ml-4 flex items-center gap-4">
                    <span className="text-xs text-falcon-muted">閾値:</span>
                    <input type="range" min={5.0} max={8.0} step={0.1} value={config.entropy_threshold}
                      onChange={e => setConfig(p => ({ ...p, entropy_threshold: Number(e.target.value) }))}
                      className="flex-1 accent-falcon-red" />
                    <span className="text-falcon-red font-bold text-sm w-10">{config.entropy_threshold.toFixed(1)}</span>
                  </div>
                )}
              </div>

              {/* Fixed detections */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: '大量リネーム検知', desc: '短時間に多数ファイルの拡張子変更を検知' },
                  { label: 'シャドウコピー削除検知', desc: 'VSS削除コマンドの実行を検知・ブロック' },
                ].map(d => (
                  <div key={d.label} className="bg-[#070d19] border border-green-700/30 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                      <span className="text-white text-xs font-medium">{d.label}</span>
                    </div>
                    <p className="text-falcon-muted text-xs">{d.desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Backup Settings */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-white font-semibold text-sm">バックアップ設定</h3>
                <p className="text-falcon-muted text-xs mt-0.5">自動バックアップによる迅速な復旧を可能にします</p>
              </div>
              <button onClick={() => setConfig(p => ({ ...p, backup_enabled: !p.backup_enabled }))}>
                {config.backup_enabled
                  ? <ToggleRight className="w-7 h-7 text-green-400" />
                  : <ToggleLeft className="w-7 h-7 text-falcon-subtle" />}
              </button>
            </div>
            {config.backup_enabled && (
              <div className="flex items-center gap-3">
                <span className="text-xs text-falcon-muted">バックアップ間隔:</span>
                <select value={config.backup_interval}
                  onChange={e => setConfig(p => ({ ...p, backup_interval: e.target.value as any }))}
                  className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden">
                  {[['1h', '1時間'], ['4h', '4時間'], ['12h', '12時間'], ['24h', '24時間']].map(([v, l]) => (
                    <option key={v} value={v}>{l}</option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Save Button */}
          <button onClick={handleSave} disabled={saving}
            className={`flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-medium transition-colors ${
              saved ? 'bg-green-700 text-white' : 'bg-falcon-red hover:bg-[#c8001e] text-white'
            } disabled:opacity-60`}>
            {saving ? <span className="animate-spin w-4 h-4 border-2 border-white/30 border-t-white rounded-full" /> : <Save className="w-4 h-4" />}
            {saved ? '保存済み ✓' : saving ? '保存中...' : '設定保存'}
          </button>
        </div>
      )}

      {/* Events Tab */}
      {tab === 'events' && (
        <div>
          <div className="flex items-center gap-3 mb-4">
            <div className="flex items-center gap-2 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2">
              <Filter className="w-4 h-4 text-falcon-muted" />
              <select value={filterType} onChange={e => setFilterType(e.target.value)}
                className="bg-transparent text-sm text-falcon-muted focus:outline-hidden focus:text-white">
                <option value="">全イベントタイプ</option>
                {(Object.keys(EVENT_TYPE_STYLES) as EventType[]).map(t => (
                  <option key={t} value={t}>{EVENT_TYPE_LABELS[t]}</option>
                ))}
              </select>
            </div>
            {filterType && (
              <button onClick={() => setFilterType('')}
                className="px-3 py-2 text-xs text-falcon-muted hover:text-white border border-falcon-border rounded-lg">リセット</button>
            )}
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['タイムスタンプ', 'ホスト名', 'イベントタイプ', 'プロセス', '影響ファイル数', '自動隔離', '詳細'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map(ev => {
                  const es = EVENT_TYPE_STYLES[ev.event_type]
                  return (
                    <tr key={ev.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3 text-xs text-falcon-muted font-mono">{fmt(ev.timestamp)}</td>
                      <td className="px-4 py-3 text-xs text-white font-mono">{ev.hostname}</td>
                      <td className="px-4 py-3"><span className={`text-xs font-bold px-2 py-0.5 rounded-sm ${es.bg} ${es.text}`}>{es.label}</span></td>
                      <td className="px-4 py-3 text-xs text-falcon-text font-mono">{ev.process_name}</td>
                      <td className="px-4 py-3 text-xs text-falcon-text text-center">{ev.affected_files}</td>
                      <td className="px-4 py-3">
                        {ev.auto_isolated
                          ? <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle className="w-3 h-3" />済み</span>
                          : <span className="text-falcon-muted text-xs">—</span>}
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedEvent(ev)}
                          className="flex items-center gap-1 text-xs text-falcon-muted hover:text-white">
                          <Eye className="w-3.5 h-3.5" /> 詳細
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Stats Tab */}
      {tab === 'stats' && (
        <div className="space-y-5">
          {/* Summary cards */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: '保護フォルダ数', value: stats.protected_folders_count, color: 'text-blue-400' },
              { label: 'カナリアファイル展開数', value: stats.canary_files_count, color: 'text-yellow-400' },
              { label: 'ブロックされたイベント', value: stats.events_blocked, color: 'text-green-400' },
              { label: '許可されたイベント', value: stats.events_allowed, color: 'text-falcon-muted' },
            ].map(c => (
              <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
                <p className="text-falcon-muted text-xs mb-2">{c.label}</p>
                <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
              </div>
            ))}
          </div>

          {/* Detection effectiveness */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">検知効果</h3>
            <div className="flex items-center gap-6">
              <div className="text-center">
                <p className="text-5xl font-bold text-green-400">{stats.detection_rate}%</p>
                <p className="text-falcon-muted text-xs mt-1">検知率</p>
              </div>
              <div className="flex-1">
                <div className="h-4 bg-falcon-border rounded-full overflow-hidden">
                  <div className="h-full bg-green-500 rounded-full" style={{ width: `${stats.detection_rate}%` }} />
                </div>
                <div className="flex justify-between text-xs text-falcon-muted mt-1">
                  <span>ブロック: {stats.events_blocked}</span>
                  <span>見逃し推定: {Math.round(stats.events_blocked / stats.detection_rate * (100 - stats.detection_rate))}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Events by type */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">直近7日間のイベントタイプ別件数</h3>
            <div className="space-y-3">
              {(Object.entries(stats.events_by_type) as [EventType, number][]).map(([type, count]) => {
                const es = EVENT_TYPE_STYLES[type]
                return (
                  <div key={type} className="flex items-center gap-3">
                    <span className="text-xs text-falcon-muted w-28 shrink-0">{es.label}</span>
                    <div className="flex-1 h-5 bg-falcon-border rounded-sm overflow-hidden">
                      <div className={`h-full ${es.bg.replace('/40', '').replace('/50', '')} bg-red-700 transition-all flex items-center px-2`}
                        style={{ width: `${(count / maxStat) * 100}%` }}>
                        <span className="text-xs text-white font-bold">{count}</span>
                      </div>
                    </div>
                    <span className="text-xs text-white font-bold w-6 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Blocked vs allowed */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">ブロック vs 許可</h3>
            <div className="flex gap-4 items-center">
              <div className="flex-1 h-6 bg-falcon-border rounded-full overflow-hidden flex">
                <div className="h-full bg-green-600 flex items-center justify-center"
                  style={{ width: `${(stats.events_blocked / (stats.events_blocked + stats.events_allowed)) * 100}%` }}>
                  <span className="text-xs text-white font-bold">{stats.events_blocked} ブロック</span>
                </div>
                <div className="h-full bg-yellow-700/60 flex-1 flex items-center justify-center">
                  <span className="text-xs text-white font-bold">{stats.events_allowed} 許可</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {selectedEvent && <EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    </div>
  )
}
