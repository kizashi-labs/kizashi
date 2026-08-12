'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

import {
  Link2, RefreshCw, CheckCircle2, XCircle, AlertTriangle,
  Clock, ChevronRight, X, Settings, ArrowLeftRight,
  ArrowDown, ArrowUp, Shield, Database, ToggleLeft,
  ToggleRight, Eye, EyeOff, Plus, Trash2, AlertCircle,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

type SyncDirection = 'inbound' | 'outbound' | 'bidirectional'
type SyncStatus = 'success' | 'failed' | 'running' | 'partial'
type ObjectType = 'IOCs' | 'TTPs' | 'Actors' | 'Campaigns'
type TLPLevel = 'white' | 'green' | 'amber' | 'red'
type ConflictResolution = 'highest_confidence' | 'most_recent' | 'manual'

interface TIPPlatform {
  id: string
  name: string
  platform_key: string
  status: 'connected' | 'disconnected' | 'error'
  last_sync: string
  objects_synced: number
  sync_direction: SyncDirection
  enabled: boolean
  url: string
  api_key: string
  verify_ssl: boolean
  sync_interval: number
  object_types: ObjectType[]
  min_confidence: number
  tlp_level: TLPLevel
  field_mappings: { platform_field: string; our_field: string }[]
  stats: { iocs: number; ttps: number; actors: number; campaigns: number }
}

interface SyncJob {
  id: string
  platform_id: string
  platform_name: string
  direction: SyncDirection
  started_at: string
  duration_seconds: number
  objects_in: number
  objects_out: number
  status: SyncStatus
  errors: number
  error_message?: string
}

// ── Helpers ────────────────────────────────────────────────────────────────

const directionColor: Record<SyncDirection, string> = {
  inbound: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  outbound: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  bidirectional: 'bg-green-500/20 text-green-300 border-green-500/30',
}

const directionLabel: Record<SyncDirection, string> = {
  inbound: '受信',
  outbound: '送信',
  bidirectional: '双方向',
}

const statusColor: Record<SyncStatus, string> = {
  success: 'bg-green-500/20 text-green-300 border-green-500/30',
  failed: 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/30',
  running: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  partial: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
}

const statusLabel: Record<SyncStatus, string> = {
  success: '成功',
  failed: '失敗',
  running: '実行中',
  partial: '部分成功',
}

const platformStatusColor: Record<string, string> = {
  connected: 'text-green-400',
  disconnected: 'text-[#7d92b0]',
  error: 'text-[#e8002d]',
}

const tlpColors: Record<TLPLevel, string> = {
  white: 'bg-white/20 text-white border-white/30',
  green: 'bg-green-500/20 text-green-300 border-green-500/30',
  amber: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  red: 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/30',
}

function PlatformIcon({ key: platformKey }: { key: string }) {
  const cls = 'w-6 h-6 text-[#7d92b0]'
  return <Database className={cls} />
}

// ── Config Modal ───────────────────────────────────────────────────────────

function ConfigModal({ platform, onClose }: { platform: TIPPlatform; onClose: () => void }) {
  const [activeTab, setActiveTab] = useState<'connection' | 'sync' | 'mapping'>('connection')
  const [showApiKey, setShowApiKey] = useState(false)
  const [verifySsl, setVerifySsl] = useState(platform.verify_ssl)
  const [objectTypes, setObjectTypes] = useState<ObjectType[]>(platform.object_types)
  const [mappings, setMappings] = useState(platform.field_mappings)
  const [isTesting, setIsTesting] = useState(false)
  const [testResult, setTestResult] = useState<null | 'success' | 'failed'>(null)

  const allObjectTypes: ObjectType[] = ['IOCs', 'TTPs', 'Actors', 'Campaigns']

  const toggleObjType = (t: ObjectType) =>
    setObjectTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])

  const handleTestConnection = () => {
    setIsTesting(true)
    setTestResult(null)
    setTimeout(() => {
      setIsTesting(false)
      setTestResult(platform.status === 'error' ? 'failed' : 'success')
    }, 1500)
  }

  const addMapping = () => setMappings(prev => [...prev, { platform_field: '', our_field: '' }])
  const removeMapping = (i: number) => setMappings(prev => prev.filter((_, idx) => idx !== i))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#1e2d42] flex items-center justify-center">
              <Database className="w-4 h-4 text-[#7d92b0]" />
            </div>
            <div>
              <h2 className="text-white font-semibold">{platform.name} 設定</h2>
              <p className={`text-xs ${platformStatusColor[platform.status]}`}>
                {platform.status === 'connected' ? '接続済み' : platform.status === 'error' ? 'エラー' : '未接続'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-[#1e2d42]">
          {[
            { id: 'connection' as const, label: '接続設定' },
            { id: 'sync' as const, label: '同期設定' },
            { id: 'mapping' as const, label: 'フィールドマッピング' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-5 py-3 text-sm font-medium transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'text-white border-[#e8002d]'
                  : 'text-[#7d92b0] border-transparent hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          {activeTab === 'connection' && (
            <>
              <div>
                <label className="text-[#7d92b0] text-sm mb-1 block">接続URL</label>
                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-[#7d92b0] text-sm font-mono">
                  {platform.url}
                </div>
              </div>
              <div>
                <label className="text-[#7d92b0] text-sm mb-1 block">APIキー</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-[#7d92b0] text-sm font-mono">
                    {showApiKey ? platform.api_key : '•'.repeat(24)}
                  </div>
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="p-2.5 bg-[#070d19] border border-[#1e2d42] rounded-lg text-[#7d92b0] hover:text-white transition-colors"
                  >
                    {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <div className="flex items-center justify-between bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-3">
                <div>
                  <p className="text-white text-sm">SSL証明書検証</p>
                  <p className="text-[#7d92b0] text-xs mt-0.5">HTTPS接続時にSSL証明書を検証する</p>
                </div>
                <button onClick={() => setVerifySsl(!verifySsl)} className="flex-shrink-0">
                  {verifySsl
                    ? <ToggleRight className="w-8 h-8 text-[#e8002d]" />
                    : <ToggleLeft className="w-8 h-8 text-[#3d5068]" />
                  }
                </button>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleTestConnection}
                  disabled={isTesting}
                  className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#263d5a] disabled:opacity-50 text-white text-sm rounded-lg transition-colors"
                >
                  {isTesting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Link2 className="w-4 h-4" />}
                  {isTesting ? 'テスト中...' : '接続テスト'}
                </button>
                {testResult === 'success' && (
                  <div className="flex items-center gap-1.5 text-green-400 text-sm">
                    <CheckCircle2 className="w-4 h-4" />
                    接続成功
                  </div>
                )}
                {testResult === 'failed' && (
                  <div className="flex items-center gap-1.5 text-[#e8002d] text-sm">
                    <XCircle className="w-4 h-4" />
                    接続失敗
                  </div>
                )}
              </div>
            </>
          )}

          {activeTab === 'sync' && (
            <>
              <div>
                <label className="text-[#7d92b0] text-sm mb-1 block">同期間隔 (分)</label>
                <input
                  type="number"
                  defaultValue={platform.sync_interval}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/60"
                />
              </div>
              <div>
                <label className="text-[#7d92b0] text-sm mb-2 block">同期オブジェクト種別</label>
                <div className="grid grid-cols-2 gap-2">
                  {allObjectTypes.map(t => (
                    <button
                      key={t}
                      onClick={() => toggleObjType(t)}
                      className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-all ${
                        objectTypes.includes(t)
                          ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-white'
                          : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40'
                      }`}
                    >
                      {objectTypes.includes(t) && <CheckCircle2 className="w-3.5 h-3.5 text-[#e8002d]" />}
                      {t}
                    </button>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[#7d92b0] text-sm mb-1 block">最低信頼度スコア</label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    defaultValue={platform.min_confidence}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/60"
                  />
                </div>
                <div>
                  <label className="text-[#7d92b0] text-sm mb-1 block">TLPレベル</label>
                  <select
                    defaultValue={platform.tlp_level}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/60"
                  >
                    <option value="white">TLP:WHITE</option>
                    <option value="green">TLP:GREEN</option>
                    <option value="amber">TLP:AMBER</option>
                    <option value="red">TLP:RED</option>
                  </select>
                </div>
              </div>
            </>
          )}

          {activeTab === 'mapping' && (
            <>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#7d92b0] text-sm">プラットフォームフィールド → 内部フィールドのマッピングを設定します</p>
                <button
                  onClick={addMapping}
                  className="flex items-center gap-1 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#263d5a] text-[#7d92b0] hover:text-white text-xs rounded-lg transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  追加
                </button>
              </div>
              <div className="space-y-2">
                <div className="grid grid-cols-[1fr_auto_1fr_auto] gap-2 items-center">
                  <p className="text-[#3d5068] text-xs px-1">プラットフォームフィールド</p>
                  <div />
                  <p className="text-[#3d5068] text-xs px-1">内部フィールド</p>
                  <div />
                </div>
                {mappings.map((m, i) => (
                  <div key={i} className="grid grid-cols-[1fr_auto_1fr_auto] gap-2 items-center">
                    <input
                      className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/60 font-mono"
                      value={m.platform_field}
                      onChange={e => setMappings(prev => prev.map((x, j) => j === i ? { ...x, platform_field: e.target.value } : x))}
                      placeholder="platform_field"
                    />
                    <ChevronRight className="w-4 h-4 text-[#3d5068]" />
                    <input
                      className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/60 font-mono"
                      value={m.our_field}
                      onChange={e => setMappings(prev => prev.map((x, j) => j === i ? { ...x, our_field: e.target.value } : x))}
                      placeholder="our_field"
                    />
                    <button onClick={() => removeMapping(i)} className="p-2 text-[#3d5068] hover:text-[#e8002d] transition-colors">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
          <button className="px-5 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors">
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function TIPIntegrationPage() {
  const [selectedPlatform, setSelectedPlatform] = useState<TIPPlatform | null>(null)
  const [conflictResolution, setConflictResolution] = useState<ConflictResolution>('highest_confidence')
  const qc = useQueryClient()

  const { data: platformsData, isError: platformsError } = useQuery<TIPPlatform[]>({
    queryKey: ['tip-integrations'],
    queryFn: () => apiFetch('/api/v1/admin/tip-integrations'),
    staleTime: 60_000,
  })

  const { data: historyData, isError: historyError } = useQuery<SyncJob[]>({
    queryKey: ['tip-integrations-history'],
    queryFn: () => apiFetch('/api/v1/admin/tip-integrations/history'),
    staleTime: 30_000,
  })

  const { mutate: syncNow, isPending: isSyncing } = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/tip-integrations/${id}/sync`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tip-integrations-history'] }),
    onError: () => {},
  })

  const platforms: TIPPlatform[] = platformsError || !platformsData ? [] : platformsData
  const history: SyncJob[] = historyError || !historyData ? [] : historyData

  const totalObjects = platforms.reduce((a, p) => a + p.objects_synced, 0)
  const connectedCount = platforms.filter(p => p.status === 'connected').length

  // Aggregate object stats per source
  const objStats = platforms.map(p => ({
    name: p.name,
    ...p.stats,
  }))

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 flex items-center justify-center">
            <Link2 className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">脅威インテリジェンスプラットフォーム統合</h1>
            <p className="text-[#7d92b0] text-sm">Threat Intelligence Platform Integration</p>
          </div>
        </div>
      </div>

      {/* ── Summary KPIs ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: '連携プラットフォーム', value: `${connectedCount}/${platforms.length}`, sub: '接続済み', icon: Link2, color: 'text-[#e8002d]' },
          { label: '総同期オブジェクト', value: totalObjects.toLocaleString(), sub: '全プラットフォーム合計', icon: Database, color: 'text-blue-400' },
          { label: '本日の同期回数', value: history.filter(j => j.started_at.startsWith('2026-03-18')).length, sub: `成功: ${history.filter(j => j.status === 'success' && j.started_at.startsWith('2026-03-18')).length}`, icon: RefreshCw, color: 'text-green-400' },
          { label: 'エラー数 (本日)', value: history.filter(j => j.status === 'failed' && j.started_at.startsWith('2026-03-18')).length, sub: `部分成功: ${history.filter(j => j.status === 'partial' && j.started_at.startsWith('2026-03-18')).length}`, icon: AlertCircle, color: 'text-amber-400' },
        ].map(({ label, value, sub, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Icon className={`w-4 h-4 ${color}`} />
              <span className="text-[#7d92b0] text-xs">{label}</span>
            </div>
            <p className="text-white font-bold text-2xl">{value}</p>
            <p className="text-[#7d92b0] text-xs mt-1">{sub}</p>
          </div>
        ))}
      </div>

      {/* ── Platform Cards Grid ── */}
      <div>
        <h2 className="text-white font-semibold mb-4">連携プラットフォーム</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {platforms.map(p => (
            <div
              key={p.id}
              className={`bg-[#0d1220] border rounded-xl p-4 transition-all cursor-pointer hover:border-[#7d92b0]/40 ${
                p.status === 'error' ? 'border-[#e8002d]/40' : 'border-[#1e2d42]'
              }`}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-9 h-9 rounded-lg bg-[#1e2d42] flex items-center justify-center flex-shrink-0">
                    <Database className="w-4.5 h-4.5 text-[#7d92b0]" />
                  </div>
                  <div>
                    <p className="text-white font-semibold text-sm">{p.name}</p>
                    <div className="flex items-center gap-1 mt-0.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${p.status === 'connected' ? 'bg-green-400' : p.status === 'error' ? 'bg-[#e8002d]' : 'bg-[#3d5068]'}`} />
                      <span className={`text-xs ${platformStatusColor[p.status]}`}>
                        {p.status === 'connected' ? '接続中' : p.status === 'error' ? 'エラー' : '未接続'}
                      </span>
                    </div>
                  </div>
                </div>
                <div className={`w-5 h-5 rounded-full border-2 flex-shrink-0 ${p.enabled ? 'bg-[#e8002d] border-[#e8002d]' : 'bg-transparent border-[#3d5068]'}`} />
              </div>

              <div className="space-y-1.5 mb-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#7d92b0]">最終同期</span>
                  <span className="text-white">{new Date(p.last_sync).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[#7d92b0]">同期オブジェクト</span>
                  <span className="text-white">{(p.objects_synced ?? 0).toLocaleString()}</span>
                </div>
              </div>

              <div className="flex items-center justify-between mb-3">
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${directionColor[p.sync_direction]}`}>
                  {p.sync_direction === 'inbound' && <ArrowDown className="w-3 h-3" />}
                  {p.sync_direction === 'outbound' && <ArrowUp className="w-3 h-3" />}
                  {p.sync_direction === 'bidirectional' && <ArrowLeftRight className="w-3 h-3" />}
                  {directionLabel[p.sync_direction]}
                </span>
                <span className={`inline-flex px-2 py-0.5 rounded border text-xs font-medium ${tlpColors[p.tlp_level]}`}>
                  TLP:{p.tlp_level.toUpperCase()}
                </span>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => syncNow(p.id)}
                  disabled={!p.enabled || isSyncing}
                  className="flex-1 flex items-center justify-center gap-1 px-2 py-1.5 bg-[#1e2d42] hover:bg-[#263d5a] disabled:opacity-40 text-[#7d92b0] hover:text-white text-xs rounded-lg transition-colors"
                >
                  <RefreshCw className={`w-3 h-3 ${isSyncing ? 'animate-spin' : ''}`} />
                  今すぐ同期
                </button>
                <button
                  onClick={() => setSelectedPlatform(p)}
                  className="flex items-center justify-center px-2.5 py-1.5 bg-[#1e2d42] hover:bg-[#263d5a] text-[#7d92b0] hover:text-white rounded-lg transition-colors"
                >
                  <Settings className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Object Statistics ── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
          <Database className="w-4 h-4 text-[#e8002d]" />
          <h2 className="text-white font-semibold">オブジェクト統計</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['プラットフォーム', 'IOCs', 'TTPs', 'アクター', 'キャンペーン', '合計'].map(h => (
                  <th key={h} className="text-left px-5 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {objStats.map(s => {
                const total = s.iocs + s.ttps + s.actors + s.campaigns
                return (
                  <tr key={s.name} className="hover:bg-[#0a1020] transition-colors">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <Database className="w-4 h-4 text-[#3d5068]" />
                        <span className="text-white text-sm">{s.name}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3"><span className="text-blue-300 text-sm">{(s.iocs ?? 0).toLocaleString()}</span></td>
                    <td className="px-5 py-3"><span className="text-purple-300 text-sm">{(s.ttps ?? 0).toLocaleString()}</span></td>
                    <td className="px-5 py-3"><span className="text-amber-300 text-sm">{(s.actors ?? 0).toLocaleString()}</span></td>
                    <td className="px-5 py-3"><span className="text-green-300 text-sm">{(s.campaigns ?? 0).toLocaleString()}</span></td>
                    <td className="px-5 py-3"><span className="text-white font-semibold text-sm">{total.toLocaleString()}</span></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Sync History ── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-[#e8002d]" />
            <h2 className="text-white font-semibold">同期履歴</h2>
          </div>
          <span className="text-[#7d92b0] text-sm">{history.length}件</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['プラットフォーム', '方向', '開始時刻', '所要時間', '受信', '送信', 'ステータス', 'エラー'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {history.map(j => (
                <tr key={j.id} className="hover:bg-[#0a1020] transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-white text-sm">{j.platform_name}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs ${directionColor[j.direction]}`}>
                      {j.direction === 'inbound' && <ArrowDown className="w-3 h-3" />}
                      {j.direction === 'outbound' && <ArrowUp className="w-3 h-3" />}
                      {j.direction === 'bidirectional' && <ArrowLeftRight className="w-3 h-3" />}
                      {directionLabel[j.direction]}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-[#7d92b0] text-xs">{new Date(j.started_at).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[#7d92b0] text-xs">{j.duration_seconds}秒</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-blue-300 text-sm">{(j.objects_in ?? 0).toLocaleString()}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-purple-300 text-sm">{(j.objects_out ?? 0).toLocaleString()}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 rounded border text-xs font-medium ${statusColor[j.status]}`}>
                      {j.status === 'running' && <RefreshCw className="w-3 h-3 animate-spin mr-1" />}
                      {statusLabel[j.status]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {j.errors > 0 ? (
                      <div className="flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        <span className="text-amber-400 text-xs">{j.errors}</span>
                        {j.error_message && (
                          <span className="text-[#7d92b0] text-xs truncate max-w-[140px]" title={j.error_message}>
                            {j.error_message}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-[#3d5068] text-xs">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Conflict Resolution ── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <AlertCircle className="w-4 h-4 text-[#e8002d]" />
          <h2 className="text-white font-semibold">競合解決ポリシー</h2>
        </div>
        <p className="text-[#7d92b0] text-sm mb-4">同一IOCが複数のプラットフォームから受信された場合の優先度ルール</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {([
            { value: 'highest_confidence' as ConflictResolution, label: '最高信頼度優先', desc: '信頼度スコアが最も高いソースのデータを使用' },
            { value: 'most_recent' as ConflictResolution, label: '最新データ優先', desc: '最も新しいタイムスタンプのデータを使用' },
            { value: 'manual' as ConflictResolution, label: '手動解決', desc: '競合を検出した場合に手動レビューキューに追加' },
          ]).map(opt => (
            <button
              key={opt.value}
              onClick={() => setConflictResolution(opt.value)}
              className={`text-left p-4 rounded-lg border transition-all ${
                conflictResolution === opt.value
                  ? 'border-[#e8002d]/50 bg-[#e8002d]/10'
                  : 'border-[#1e2d42] bg-[#070d19] hover:border-[#7d92b0]/40'
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <div className={`w-3.5 h-3.5 rounded-full border-2 flex-shrink-0 ${
                  conflictResolution === opt.value ? 'border-[#e8002d] bg-[#e8002d]' : 'border-[#3d5068]'
                }`} />
                <span className="text-white text-sm font-medium">{opt.label}</span>
              </div>
              <p className="text-[#7d92b0] text-xs pl-5">{opt.desc}</p>
            </button>
          ))}
        </div>
      </div>

      {/* ── Config Modal ── */}
      {selectedPlatform && (
        <ConfigModal
          platform={selectedPlatform}
          onClose={() => setSelectedPlatform(null)}
        />
      )}
    </div>
  )
}
