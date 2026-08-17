'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Brain, Monitor, CheckCircle2, Clock, AlertTriangle,
  TrendingUp, TrendingDown, Settings, X, RefreshCw,
  Plus, Trash2, ChevronRight, Activity, Network,
  FolderOpen, Users, Eye, Shield,
  ToggleLeft, ToggleRight,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────

type BaselineStatus = 'established' | 'learning' | 'insufficient_data' | 'anomalous'
type DeviationSensitivity = 'low' | 'medium' | 'high' | 'critical'
type OS = 'Windows' | 'macOS' | 'Linux'

interface BaselineConfig {
  learning_period_days: number
  confidence_threshold: number
  auto_alert_on_deviation: boolean
  deviation_sensitivity: DeviationSensitivity
}

interface ProcessEntry {
  name: string
  frequency: number
  is_rare: boolean
}

interface NetworkDestination {
  host: string
  port: number
  protocol: string
  volume_mb: number
}

interface Deviation {
  id: string
  category: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  detected_at: string
}

interface EndpointBaseline {
  id: string
  hostname: string
  os: OS
  baseline_status: BaselineStatus
  learning_started: string
  data_points_collected: number
  last_updated: string
  anomaly_count: number
  confidence_score: number
  active_hours: number[][]  // 7 days × 24 hours, 0-100
  typical_processes: ProcessEntry[]
  typical_destinations: NetworkDestination[]
  typical_directories: string[]
  recent_deviations: Deviation[]
  exclusion_rules: string[]
}

// ── Mock Data ──────────────────────────────────────────────────────────────

const MOCK_CONFIG: BaselineConfig = {
  learning_period_days: 30,
  confidence_threshold: 0.85,
  auto_alert_on_deviation: true,
  deviation_sensitivity: 'medium',
}

function generateHeatmap(): number[][] {
  return Array.from({ length: 7 }, (_, day) =>
    Array.from({ length: 24 }, (_, hour) => {
      if (hour >= 9 && hour <= 18 && day < 5) return Math.floor(60 + Math.random() * 40)
      if (hour >= 7 && hour <= 20 && day < 5) return Math.floor(20 + Math.random() * 40)
      return Math.floor(Math.random() * 15)
    })
  )
}

const MOCK_ENDPOINTS: EndpointBaseline[] = [
  {
    id: 'e1', hostname: 'WS-TOKYO-001', os: 'Windows', baseline_status: 'established',
    learning_started: '2026-02-01', data_points_collected: 2840120, last_updated: '2026-03-18T09:00:00Z',
    anomaly_count: 2, confidence_score: 94,
    active_hours: generateHeatmap(),
    typical_processes: [
      { name: 'chrome.exe', frequency: 98, is_rare: false },
      { name: 'outlook.exe', frequency: 95, is_rare: false },
      { name: 'teams.exe', frequency: 92, is_rare: false },
      { name: 'powershell.exe', frequency: 45, is_rare: false },
      { name: 'mimikatz.exe', frequency: 1, is_rare: true },
    ],
    typical_destinations: [
      { host: 'office365.com', port: 443, protocol: 'HTTPS', volume_mb: 840 },
      { host: 'teams.microsoft.com', port: 443, protocol: 'HTTPS', volume_mb: 620 },
      { host: '10.0.0.5', port: 445, protocol: 'SMB', volume_mb: 230 },
    ],
    typical_directories: ['C:\\Users\\user01\\Documents', 'C:\\Program Files', 'C:\\Windows\\System32'],
    recent_deviations: [
      { id: 'd1', category: 'Process', description: '未知のプロセス mimikatz.exe が実行された', severity: 'critical', detected_at: '2026-03-17T14:22:00Z' },
      { id: 'd2', category: 'Network', description: '異常な外部IPへの接続 (185.220.x.x:4444)', severity: 'high', detected_at: '2026-03-18T08:11:00Z' },
    ],
    exclusion_rules: ['C:\\Windows\\Temp\\update*.exe', 'svchost.exe'],
  },
  {
    id: 'e2', hostname: 'SRV-DB-001', os: 'Linux', baseline_status: 'established',
    learning_started: '2026-01-15', data_points_collected: 5210340, last_updated: '2026-03-18T10:00:00Z',
    anomaly_count: 0, confidence_score: 97,
    active_hours: generateHeatmap(),
    typical_processes: [
      { name: 'mysqld', frequency: 100, is_rare: false },
      { name: 'nginx', frequency: 100, is_rare: false },
      { name: 'python3', frequency: 80, is_rare: false },
    ],
    typical_destinations: [
      { host: '10.0.1.10', port: 3306, protocol: 'MySQL', volume_mb: 1200 },
    ],
    typical_directories: ['/var/lib/mysql', '/etc/nginx', '/opt/app'],
    recent_deviations: [],
    exclusion_rules: ['/tmp/mysql_upgrade*'],
  },
  {
    id: 'e3', hostname: 'WS-OSAKA-015', os: 'Windows', baseline_status: 'learning',
    learning_started: '2026-03-10', data_points_collected: 412800, last_updated: '2026-03-18T09:30:00Z',
    anomaly_count: 0, confidence_score: 43,
    active_hours: generateHeatmap(),
    typical_processes: [
      { name: 'explorer.exe', frequency: 100, is_rare: false },
      { name: 'chrome.exe', frequency: 75, is_rare: false },
    ],
    typical_destinations: [],
    typical_directories: [],
    recent_deviations: [],
    exclusion_rules: [],
  },
  {
    id: 'e4', hostname: 'MAC-DESIGN-003', os: 'macOS', baseline_status: 'anomalous',
    learning_started: '2026-02-10', data_points_collected: 1840200, last_updated: '2026-03-18T10:15:00Z',
    anomaly_count: 5, confidence_score: 88,
    active_hours: generateHeatmap(),
    typical_processes: [
      { name: 'Figma', frequency: 90, is_rare: false },
      { name: 'Sketch', frequency: 80, is_rare: false },
      { name: 'Terminal', frequency: 60, is_rare: false },
      { name: 'cryptominer_hidden', frequency: 3, is_rare: true },
    ],
    typical_destinations: [
      { host: 'figma.com', port: 443, protocol: 'HTTPS', volume_mb: 2400 },
    ],
    typical_directories: ['/Users/designer/Documents', '/Applications'],
    recent_deviations: [
      { id: 'd3', category: 'Process', description: '疑わしいバックグラウンドプロセスが検出された', severity: 'high', detected_at: '2026-03-18T07:45:00Z' },
      { id: 'd4', category: 'Network', description: '高帯域幅の外部通信 (>5GB/日)', severity: 'high', detected_at: '2026-03-18T09:00:00Z' },
      { id: 'd5', category: 'Schedule', description: '深夜2時台に異常なアクティビティ', severity: 'medium', detected_at: '2026-03-18T02:18:00Z' },
      { id: 'd6', category: 'File', description: '/tmp配下への大量ファイル書き込み', severity: 'medium', detected_at: '2026-03-17T23:10:00Z' },
      { id: 'd7', category: 'User', description: '通常と異なるユーザーアカウントでのログイン', severity: 'critical', detected_at: '2026-03-17T22:55:00Z' },
    ],
    exclusion_rules: [],
  },
  {
    id: 'e5', hostname: 'WS-NAGOYA-007', os: 'Windows', baseline_status: 'insufficient_data',
    learning_started: '2026-03-15', data_points_collected: 48200, last_updated: '2026-03-18T10:00:00Z',
    anomaly_count: 0, confidence_score: 12,
    active_hours: generateHeatmap(),
    typical_processes: [],
    typical_destinations: [],
    typical_directories: [],
    recent_deviations: [],
    exclusion_rules: [],
  },
  ...Array.from({ length: 10 }, (_, i) => ({
    id: `e${i + 6}`,
    hostname: `WS-BRANCH-${String(i + 1).padStart(3, '0')}`,
    os: (['Windows', 'Windows', 'macOS', 'Linux'][i % 4]) as OS,
    baseline_status: (['established', 'learning', 'established', 'established'][i % 4]) as BaselineStatus,
    learning_started: '2026-02-01',
    data_points_collected: Math.floor(500000 + Math.random() * 2000000),
    last_updated: '2026-03-18T10:00:00Z',
    anomaly_count: Math.floor(Math.random() * 3),
    confidence_score: Math.floor(70 + Math.random() * 28),
    active_hours: generateHeatmap(),
    typical_processes: [],
    typical_destinations: [],
    typical_directories: [],
    recent_deviations: [],
    exclusion_rules: [],
  })),
]

// ── Helpers ────────────────────────────────────────────────────────────────

const statusConfig: Record<BaselineStatus, { label: string; color: string; pulse?: boolean }> = {
  established: { label: '確立済み', color: 'bg-green-500/20 text-green-300 border-green-500/30' },
  learning: { label: '学習中', color: 'bg-blue-500/20 text-blue-300 border-blue-500/30', pulse: true },
  insufficient_data: { label: 'データ不足', color: 'bg-falcon-muted/20 text-falcon-muted border-falcon-muted/30' },
  anomalous: { label: '異常検知', color: 'bg-falcon-red/20 text-falcon-red border-falcon-red/30' },
}

const severityColor: Record<string, string> = {
  low: 'text-falcon-muted bg-falcon-muted/20 border-falcon-muted/30',
  medium: 'text-amber-300 bg-amber-500/20 border-amber-500/30',
  high: 'text-orange-300 bg-orange-500/20 border-orange-500/30',
  critical: 'text-falcon-red bg-falcon-red/20 border-falcon-red/30',
}

const DAYS = ['月', '火', '水', '木', '金', '土', '日']

// ── Detail Modal ───────────────────────────────────────────────────────────

function DetailModal({ endpoint, onClose }: { endpoint: EndpointBaseline; onClose: () => void }) {
  const [activeTab, setActiveTab] = useState<'process' | 'network' | 'file' | 'schedule' | 'deviations' | 'exclusions'>('process')
  const [showResetConfirm, setShowResetConfirm] = useState(false)
  const [newExclusion, setNewExclusion] = useState('')
  const [exclusions, setExclusions] = useState(endpoint.exclusion_rules)
  const qc = useQueryClient()

  const { data } = useQuery<EndpointBaseline>({
    queryKey: ['endpoint-baseline', endpoint.id],
    queryFn: () => apiFetch(`/api/v1/endpoints/baselines/${endpoint.id}`),
    placeholderData: endpoint,
  })
  const ep = data ?? endpoint

  const addExclusion = () => {
    if (newExclusion.trim()) {
      setExclusions(prev => [...prev, newExclusion.trim()])
      setNewExclusion('')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-3xl shadow-2xl flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div>
            <div className="flex items-center gap-3">
              <Monitor className="w-5 h-5 text-falcon-red" />
              <h2 className="text-white font-semibold text-lg">{ep.hostname}</h2>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-xs font-medium ${statusConfig[ep.baseline_status].color}`}>
                {statusConfig[ep.baseline_status].pulse && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mr-1 animate-pulse" />}
                {statusConfig[ep.baseline_status].label}
              </span>
            </div>
            <p className="text-falcon-muted text-sm mt-1">
              {ep.os} · データポイント: {(ep.data_points_collected ?? 0).toLocaleString()} · 信頼度: {ep.confidence_score}%
            </p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>

        {/* Tabs */}
        <div className="flex gap-0 border-b border-falcon-border overflow-x-auto">
          {[
            { id: 'process' as const, label: 'プロセス', icon: Activity },
            { id: 'network' as const, label: 'ネットワーク', icon: Network },
            { id: 'file' as const, label: 'ファイル', icon: FolderOpen },
            { id: 'schedule' as const, label: 'スケジュール', icon: Clock },
            { id: 'deviations' as const, label: `逸脱 (${ep.recent_deviations.length})`, icon: AlertTriangle },
            { id: 'exclusions' as const, label: '除外ルール', icon: Shield },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-3 text-xs font-medium whitespace-nowrap transition-colors border-b-2 ${
                activeTab === tab.id ? 'text-white border-falcon-red' : 'text-falcon-muted border-transparent hover:text-white'
              }`}
            >
              <tab.icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-4">
          {activeTab === 'process' && (
            <div className="space-y-2">
              <p className="text-falcon-muted text-xs mb-3">標準プロセスと頻度（過去30日間）</p>
              {ep.typical_processes.length === 0 ? (
                <p className="text-center text-falcon-muted py-8">データ学習中...</p>
              ) : ep.typical_processes.map(p => (
                <div key={p.name} className={`flex items-center gap-3 p-3 rounded-lg border ${p.is_rare ? 'border-falcon-red/40 bg-falcon-red/5' : 'border-falcon-border bg-[#070d19]'}`}>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-sm font-mono ${p.is_rare ? 'text-falcon-red' : 'text-white'}`}>{p.name}</span>
                      {p.is_rare && (
                        <span className="px-1.5 py-0.5 bg-falcon-red/20 text-falcon-red text-xs rounded-sm border border-falcon-red/30">レア</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${p.is_rare ? 'bg-falcon-red' : 'bg-falcon-red/60'}`}
                          style={{ width: `${p.frequency}%` }}
                        />
                      </div>
                      <span className="text-falcon-muted text-xs w-10 text-right">{p.frequency}%</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'network' && (
            <div className="space-y-2">
              <p className="text-falcon-muted text-xs mb-3">標準ネットワーク通信先（過去30日間の月平均）</p>
              {ep.typical_destinations.length === 0 ? (
                <p className="text-center text-falcon-muted py-8">データ学習中...</p>
              ) : ep.typical_destinations.map((d, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-[#070d19] border border-falcon-border rounded-lg">
                  <div className="flex items-center gap-3">
                    <Network className="w-4 h-4 text-falcon-subtle" />
                    <div>
                      <span className="text-white text-sm font-mono">{d.host}</span>
                      <span className="text-falcon-subtle text-sm ml-2">:{d.port}</span>
                      <span className="ml-2 px-1.5 py-0.5 bg-blue-500/20 text-blue-300 text-xs rounded-sm">{d.protocol}</span>
                    </div>
                  </div>
                  <span className="text-falcon-muted text-xs">{(d.volume_mb ?? 0).toLocaleString()} MB/月</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'file' && (
            <div className="space-y-2">
              <p className="text-falcon-muted text-xs mb-3">標準ファイルアクセスパターン</p>
              {ep.typical_directories.length === 0 ? (
                <p className="text-center text-falcon-muted py-8">データ学習中...</p>
              ) : ep.typical_directories.map((dir, i) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-[#070d19] border border-falcon-border rounded-lg">
                  <FolderOpen className="w-4 h-4 text-amber-400 shrink-0" />
                  <span className="text-white text-sm font-mono">{dir}</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'schedule' && (
            <div>
              <p className="text-falcon-muted text-xs mb-3">アクティブ時間ヒートマップ（0=非活性 / 100=高活性）</p>
              <div className="overflow-x-auto">
                <div className="min-w-[640px]">
                  <div className="flex gap-1 mb-1">
                    <div className="w-8" />
                    {Array.from({ length: 24 }, (_, h) => (
                      <div key={h} className="flex-1 text-center text-falcon-subtle text-[9px]">{h}</div>
                    ))}
                  </div>
                  {ep.active_hours.map((dayRow, d) => (
                    <div key={d} className="flex gap-1 mb-1">
                      <div className="w-8 flex items-center text-falcon-muted text-xs">{DAYS[d]}</div>
                      {dayRow.map((val, h) => (
                        <div
                          key={h}
                          className="flex-1 h-6 rounded-xs"
                          style={{
                            backgroundColor: val === 0
                              ? '#1e2d42'
                              : `rgba(232, 0, 45, ${val / 100 * 0.8 + 0.1})`,
                          }}
                          title={`${DAYS[d]} ${h}:00 — ${val}%`}
                        />
                      ))}
                    </div>
                  ))}
                  <div className="flex items-center gap-2 mt-3">
                    <span className="text-falcon-subtle text-xs">低</span>
                    <div className="flex gap-0.5">
                      {[10, 20, 40, 60, 80, 100].map(v => (
                        <div key={v} className="w-5 h-3 rounded-xs" style={{ backgroundColor: `rgba(232, 0, 45, ${v / 100 * 0.8 + 0.1})` }} />
                      ))}
                    </div>
                    <span className="text-falcon-subtle text-xs">高</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'deviations' && (
            <div className="space-y-3">
              {ep.recent_deviations.length === 0 ? (
                <div className="flex flex-col items-center py-12 gap-3">
                  <CheckCircle2 className="w-10 h-10 text-green-400" />
                  <p className="text-green-400 font-medium">逸脱なし</p>
                  <p className="text-falcon-muted text-sm">ベースラインからの逸脱は検出されていません</p>
                </div>
              ) : ep.recent_deviations.map(dev => (
                <div key={dev.id} className={`p-4 rounded-lg border ${dev.severity === 'critical' ? 'border-falcon-red/40 bg-falcon-red/5' : 'border-falcon-border bg-[#070d19]'}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-0.5 rounded-sm border text-xs font-medium ${severityColor[dev.severity]}`}>
                          {dev.severity.toUpperCase()}
                        </span>
                        <span className="text-falcon-muted text-xs bg-falcon-border px-2 py-0.5 rounded-sm">{dev.category}</span>
                      </div>
                      <p className="text-white text-sm">{dev.description}</p>
                    </div>
                    <span className="text-falcon-subtle text-xs whitespace-nowrap">
                      {new Date(dev.detected_at).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'exclusions' && (
            <div className="space-y-3">
              <p className="text-falcon-muted text-sm">ベースライン学習から除外するプロセス/ドメインを設定します</p>
              <div className="flex gap-2">
                <input
                  className="flex-1 bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/60 font-mono"
                  value={newExclusion}
                  onChange={e => setNewExclusion(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addExclusion()}
                  placeholder="例: C:\\Temp\\update*.exe"
                />
                <button
                  onClick={addExclusion}
                  disabled={!newExclusion.trim()}
                  className="flex items-center gap-1.5 px-3 py-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-40 text-white text-sm rounded-lg transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  追加
                </button>
              </div>
              <div className="space-y-2">
                {exclusions.map((rule, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-[#070d19] border border-falcon-border rounded-lg">
                    <span className="text-white text-sm font-mono">{rule}</span>
                    <button
                      onClick={() => setExclusions(prev => prev.filter((_, j) => j !== i))}
                      className="text-falcon-subtle hover:text-falcon-red transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
                {exclusions.length === 0 && (
                  <p className="text-center text-falcon-muted py-6 text-sm">除外ルールなし</p>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center justify-between px-6 py-4 border-t border-falcon-border">
          {showResetConfirm ? (
            <div className="flex items-center gap-3">
              <p className="text-amber-400 text-sm">本当にベースラインをリセットしますか？</p>
              <button
                onClick={() => setShowResetConfirm(false)}
                className="px-3 py-1.5 bg-falcon-red hover:bg-[#c0001f] text-white text-xs rounded-lg transition-colors"
              >
                リセット実行
              </button>
              <button onClick={() => setShowResetConfirm(false)} className="text-falcon-muted hover:text-white text-xs transition-colors">
                キャンセル
              </button>
            </div>
          ) : (
            <button
              onClick={() => setShowResetConfirm(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 text-amber-400 text-xs rounded-lg transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              ベースラインをリセット
            </button>
          )}
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

// ── Config Card ────────────────────────────────────────────────────────────

function ConfigCard({ config, onChange }: { config: BaselineConfig; onChange: (c: BaselineConfig) => void }) {
  const qc = useQueryClient()
  const { mutate, isPending } = useMutation({
    mutationFn: (cfg: BaselineConfig) => apiFetch('/api/v1/endpoints/baselines/config', { method: 'PUT', body: JSON.stringify(cfg) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['baselines'] }),
    onError: () => {},
  })

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Settings className="w-4 h-4 text-falcon-red" />
          <h2 className="text-white font-semibold">ベースライン設定</h2>
        </div>
        <button
          onClick={() => mutate(config)}
          disabled={isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 text-white text-xs rounded-lg transition-colors"
        >
          {isPending ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
          {isPending ? '保存中...' : '設定を保存'}
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-falcon-muted text-sm">学習期間</label>
            <span className="text-white font-medium text-sm">{config.learning_period_days}日</span>
          </div>
          <input
            type="range" min={7} max={90} step={1}
            value={config.learning_period_days}
            onChange={e => onChange({ ...config, learning_period_days: Number(e.target.value) })}
            className="w-full accent-falcon-red"
          />
          <div className="flex justify-between text-falcon-subtle text-xs mt-1">
            <span>7日</span><span>90日</span>
          </div>
        </div>
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-falcon-muted text-sm">信頼度閾値</label>
            <span className="text-white font-medium text-sm">{(config.confidence_threshold * 100).toFixed(0)}%</span>
          </div>
          <input
            type="range" min={50} max={99} step={1}
            value={Math.round(config.confidence_threshold * 100)}
            onChange={e => onChange({ ...config, confidence_threshold: Number(e.target.value) / 100 })}
            className="w-full accent-falcon-red"
          />
          <div className="flex justify-between text-falcon-subtle text-xs mt-1">
            <span>50%</span><span>99%</span>
          </div>
        </div>
        <div className="flex items-center justify-between bg-[#070d19] border border-falcon-border rounded-lg px-4 py-3">
          <div>
            <p className="text-white text-sm">逸脱時自動アラート</p>
            <p className="text-falcon-muted text-xs mt-0.5">ベースライン逸脱を検出したら自動でアラートを発生</p>
          </div>
          <button onClick={() => onChange({ ...config, auto_alert_on_deviation: !config.auto_alert_on_deviation })}>
            {config.auto_alert_on_deviation
              ? <ToggleRight className="w-8 h-8 text-falcon-red" />
              : <ToggleLeft className="w-8 h-8 text-falcon-subtle" />
            }
          </button>
        </div>
        <div>
          <label className="text-falcon-muted text-sm mb-2 block">逸脱感度</label>
          <div className="grid grid-cols-4 gap-1.5">
            {(['low', 'medium', 'high', 'critical'] as DeviationSensitivity[]).map(s => (
              <button
                key={s}
                onClick={() => onChange({ ...config, deviation_sensitivity: s })}
                className={`py-1.5 rounded-lg border text-xs font-medium transition-all ${
                  config.deviation_sensitivity === s
                    ? 'border-falcon-red/50 bg-falcon-red/20 text-white'
                    : 'border-falcon-border bg-[#070d19] text-falcon-muted hover:border-falcon-muted/40'
                }`}
              >
                {s === 'low' ? '低' : s === 'medium' ? '中' : s === 'high' ? '高' : '最高'}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function BehavioralBaselinePage() {
  const DEFAULT_CONFIG: BaselineConfig = { learning_period_days: 30, confidence_threshold: 0.85, auto_alert_on_deviation: true, deviation_sensitivity: 'medium' }
  const [config, setConfig] = useState<BaselineConfig>(DEFAULT_CONFIG)
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointBaseline | null>(null)
  const [filterStatus, setFilterStatus] = useState<BaselineStatus | 'all'>('all')

  const { data: configData } = useQuery<BaselineConfig>({
    queryKey: ['baseline-config'],
    queryFn: () => apiFetch<BaselineConfig>('/api/v1/endpoints/baselines/config').catch(() => DEFAULT_CONFIG),
    staleTime: 60_000,
  })
  useEffect(() => { if (configData) setConfig(configData) }, [configData])

  const { data: baselinesData } = useQuery<EndpointBaseline[] | null>({
    queryKey: ['baselines'],
    queryFn: () => apiFetchList<EndpointBaseline>('/api/v1/endpoints/baselines').catch(() => null),
    staleTime: 60_000,
  })

  const { data: agentsData } = useQuery<{ data?: { id: string; hostname: string; os_type?: string }[]; agents?: { id: string; hostname: string; os_type?: string }[] }>({
    queryKey: ['agents-baseline'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=1000'),
    staleTime: 60_000,
  })

  const agentList = agentsData?.data ?? agentsData?.agents ?? []

  const endpoints: EndpointBaseline[] = (Array.isArray(baselinesData) && baselinesData.length > 0)
    ? baselinesData
    : agentList.length > 0
      ? agentList.map(a => ({
          id: a.id,
          hostname: a.hostname,
          os: (a.os_type === 'linux' ? 'Linux' : a.os_type === 'darwin' ? 'macOS' : 'Windows') as OS,
          baseline_status: 'learning' as BaselineStatus,
          learning_started: new Date().toISOString(),
          data_points_collected: 0,
          last_updated: new Date().toISOString(),
          anomaly_count: 0,
          confidence_score: 0,
          active_hours: Array.from({ length: 7 }, () => Array(24).fill(0)),
          typical_processes: [],
          typical_destinations: [],
          typical_directories: [],
          recent_deviations: [],
          exclusion_rules: [],
        }))
      : m(MOCK_ENDPOINTS)
  const filtered = filterStatus === 'all' ? endpoints : endpoints.filter(e => e.baseline_status === filterStatus)

  const stats = {
    total: endpoints.length,
    established: endpoints.filter(e => e.baseline_status === 'established').length,
    learning: endpoints.filter(e => e.baseline_status === 'learning').length,
    anomalous_today: endpoints.reduce((a, e) => a + e.anomaly_count, 0),
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-falcon-red/20 border border-falcon-red/30 flex items-center justify-center">
          <Brain className="w-5 h-5 text-falcon-red" />
        </div>
        <div>
          <h1 className="text-white font-bold text-xl">エンドポイント行動ベースライン</h1>
          <p className="text-falcon-muted text-sm">Endpoint Behavioral Baseline Learning</p>
        </div>
      </div>

      {/* ── Learning Status Overview ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: '総エンドポイント', value: stats.total, icon: Monitor, color: 'text-falcon-red', sub: '管理対象' },
          { label: 'ベースライン確立', value: stats.established, icon: CheckCircle2, color: 'text-green-400', sub: `${Math.round(stats.established / stats.total * 100)}%` },
          { label: '学習中', value: stats.learning, icon: Brain, color: 'text-blue-400', sub: 'データ収集中' },
          { label: '本日の異常検知', value: stats.anomalous_today, icon: AlertTriangle, color: 'text-falcon-red', sub: '逸脱イベント' },
        ].map(({ label, value, icon: Icon, color, sub }) => (
          <div key={label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Icon className={`w-4 h-4 ${color}`} />
              <span className="text-falcon-muted text-xs">{label}</span>
            </div>
            <p className="text-white font-bold text-2xl">{value}</p>
            <p className={`text-xs mt-1 ${color}`}>{sub}</p>
          </div>
        ))}
      </div>

      {/* ── Baseline Config ── */}
      <ConfigCard config={config} onChange={setConfig} />

      {/* ── Endpoints Table ── */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center justify-between flex-wrap gap-3">
          <h2 className="text-white font-semibold">エンドポイント ベースライン一覧</h2>
          <div className="flex items-center gap-2 flex-wrap">
            {(['all', 'established', 'learning', 'insufficient_data', 'anomalous'] as const).map(s => (
              <button
                key={s}
                onClick={() => setFilterStatus(s)}
                className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-all ${
                  filterStatus === s
                    ? 'border-falcon-red/50 bg-falcon-red/20 text-white'
                    : 'border-falcon-border text-falcon-muted hover:border-falcon-muted/40'
                }`}
              >
                {s === 'all' ? 'すべて' : statusConfig[s].label}
                {s !== 'all' && (
                  <span className="ml-1 text-falcon-subtle">({endpoints.filter(e => e.baseline_status === s).length})</span>
                )}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-falcon-border">
                {['ホスト名', 'OS', 'ステータス', '学習開始', 'データポイント', '最終更新', '異常数', '信頼度', '操作'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-falcon-muted text-xs font-medium uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {filtered.map(ep => {
                const sc = statusConfig[ep.baseline_status]
                return (
                  <tr key={ep.id} className="hover:bg-[#0a1020] transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Monitor className="w-4 h-4 text-falcon-subtle" />
                        <span className="text-white text-sm font-medium">{ep.hostname}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-sm">{ep.os}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-xs font-medium ${sc.color}`}>
                        {sc.pulse && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mr-1 animate-pulse" />}
                        {ep.baseline_status === 'anomalous' && <AlertTriangle className="w-3 h-3 mr-1" />}
                        {sc.label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-xs">{ep.learning_started}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-white text-sm">{(ep.data_points_collected ?? 0).toLocaleString()}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-xs">
                        {new Date(ep.last_updated).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {ep.anomaly_count > 0 ? (
                        <span className="text-falcon-red font-semibold">{ep.anomaly_count}</span>
                      ) : (
                        <span className="text-green-400">0</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${ep.confidence_score}%`,
                              backgroundColor: ep.confidence_score >= 80 ? '#22c55e' : ep.confidence_score >= 50 ? '#f59e0b' : '#e8002d',
                            }}
                          />
                        </div>
                        <span className="text-falcon-muted text-xs">{ep.confidence_score}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedEndpoint(ep)}
                        className="flex items-center gap-1 px-2.5 py-1 bg-falcon-border hover:bg-[#263d5a] text-falcon-muted hover:text-white text-xs rounded-lg transition-colors"
                      >
                        <Eye className="w-3 h-3" />
                        詳細
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Baseline Quality Metrics ── */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-falcon-red" />
          <h2 className="text-white font-semibold">ベースライン品質メトリクス</h2>
        </div>
        <div className="p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {endpoints.filter(e => e.baseline_status === 'established' || e.baseline_status === 'anomalous').slice(0, 6).map(ep => (
            <div key={ep.id} className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-white text-sm font-medium">{ep.hostname}</span>
                <span className={`text-xs font-bold ${ep.confidence_score >= 80 ? 'text-green-400' : ep.confidence_score >= 50 ? 'text-amber-400' : 'text-falcon-red'}`}>
                  {ep.confidence_score}%
                </span>
              </div>
              <div className="space-y-1.5">
                {[
                  { label: 'データ充足度', value: Math.min(100, Math.round(ep.data_points_collected / 50000)) },
                  { label: '信頼度スコア', value: ep.confidence_score },
                  { label: '学習完了度', value: ep.baseline_status === 'established' ? 100 : ep.baseline_status === 'learning' ? Math.round(ep.confidence_score * 0.6) : 15 },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <div className="flex justify-between text-xs mb-0.5">
                      <span className="text-falcon-muted">{label}</span>
                      <span className="text-white">{value}%</span>
                    </div>
                    <div className="h-1 bg-falcon-border rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all"
                        style={{
                          width: `${value}%`,
                          backgroundColor: value >= 80 ? '#22c55e' : value >= 50 ? '#f59e0b' : '#e8002d',
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Detail Modal ── */}
      {selectedEndpoint && (
        <DetailModal
          endpoint={selectedEndpoint}
          onClose={() => setSelectedEndpoint(null)}
        />
      )}
    </div>
  )
}
