'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { USE_MOCK } from '@/lib/mock'
import {
  Activity, X, AlertTriangle, Shield, User, Search,
  CheckCircle, XCircle, ArrowUpCircle, ChevronDown, Filter
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { usePersist, SaveFailed } from '@/lib/persist'

// ── Types ──────────────────────────────────────────────────────────

type AnomalyType =
  | 'unusual_login_time'
  | 'bulk_download'
  | 'lateral_movement'
  | 'privilege_abuse'
  | 'data_staging'
  | 'geo_anomaly'
  | 'after_hours'

type Severity = 'low' | 'medium' | 'high' | 'critical'
type AnomalyStatus = 'open' | 'reviewed' | 'false_positive' | 'confirmed'

interface Anomaly {
  id: string
  timestamp: string
  username: string
  anomaly_type: AnomalyType
  severity: Severity
  score: number
  baseline_value: number
  actual_value: number
  baseline_label: string
  description: string
  related_events: string[]
  ml_features: { name: string; importance: number }[]
  status: AnomalyStatus
}

interface UserBaseline {
  metric_name: string
  baseline_value: number
  std_deviation: number
  unit: string
  last_updated: string
}

interface UserProfile {
  username: string
  department: string
  risk_score: number
  anomaly_count: number
  top_types: AnomalyType[]
  baselines: UserBaseline[]
  activity_heatmap: number[][]  // 7 days x 24 hours
}

// ── Helpers ────────────────────────────────────────────────────────

const ANOMALY_TYPE_CONFIG: Record<AnomalyType, { label: string; bg: string; text: string }> = {
  unusual_login_time: { label: '異常ログイン時刻', bg: 'bg-blue-900/40', text: 'text-blue-300' },
  bulk_download:      { label: '大量ダウンロード',  bg: 'bg-red-900/40',    text: 'text-red-300' },
  lateral_movement:   { label: '横断的移動',        bg: 'bg-purple-900/40', text: 'text-purple-300' },
  privilege_abuse:    { label: '特権乱用',           bg: 'bg-orange-900/40', text: 'text-orange-300' },
  data_staging:       { label: 'データ集約',         bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  geo_anomaly:        { label: '地理的異常',          bg: 'bg-cyan-900/40',   text: 'text-cyan-300' },
  after_hours:        { label: '時間外アクセス',      bg: 'bg-pink-900/40',   text: 'text-pink-300' },
}

const SEVERITY_CONFIG = {
  low:      { label: '低',   bg: 'bg-gray-800',      text: 'text-gray-300' },
  medium:   { label: '中',   bg: 'bg-yellow-900/50', text: 'text-yellow-300' },
  high:     { label: '高',   bg: 'bg-orange-900/50', text: 'text-orange-300' },
  critical: { label: '重大', bg: 'bg-red-900/50',    text: 'text-red-300' },
}

const STATUS_CONFIG: Record<AnomalyStatus, { label: string; bg: string; text: string }> = {
  open:           { label: '未対応',       bg: 'bg-red-900/40',    text: 'text-red-300' },
  reviewed:       { label: 'レビュー済み', bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  false_positive: { label: '誤検知',       bg: 'bg-gray-800',      text: 'text-gray-300' },
  confirmed:      { label: '確認済み',     bg: 'bg-orange-900/40', text: 'text-orange-300' },
}

function scoreColor(score: number) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

function fmt(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Anomaly Detail Modal ───────────────────────────────────────────

function AnomalyDetailModal({ anomaly, onClose, onAction }: {
  anomaly: Anomaly
  onClose: () => void
  onAction: (id: string, status: AnomalyStatus) => void
}) {
  const tc = ANOMALY_TYPE_CONFIG[anomaly.anomaly_type]
  const sc = SEVERITY_CONFIG[anomaly.severity]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <h2 className="text-white font-semibold text-lg">異常詳細</h2>
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${tc.bg} ${tc.text}`}>{tc.label}</span>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        <p className="text-[#e2e8f4] text-sm mb-6 bg-[#070d19] p-3 rounded-lg border border-[#1e2d42]">{anomaly.description}</p>

        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            ['ユーザー', anomaly.username],
            ['タイムスタンプ', fmt(anomaly.timestamp)],
            ['スコア', String(anomaly.score)],
          ].map(([k, v]) => (
            <div key={k} className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-xs text-[#7d92b0] mb-1">{k}</p>
              <p className={`text-sm font-semibold ${k === 'スコア' ? scoreColor(anomaly.score) : 'text-white'}`}>{v}</p>
            </div>
          ))}
        </div>

        {/* Baseline vs Actual Chart */}
        <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42] mb-4">
          <p className="text-xs text-[#7d92b0] mb-3 font-medium uppercase tracking-wider">ベースライン vs 実際の値 ({anomaly.baseline_label})</p>
          <div className="space-y-3">
            {[
              { label: 'ベースライン', value: anomaly.baseline_value, color: 'bg-blue-500' },
              { label: '実際の値', value: anomaly.actual_value, color: 'bg-red-500' },
            ].map(row => {
              const max = Math.max(anomaly.baseline_value, anomaly.actual_value)
              const pct = max > 0 ? (row.value / max) * 100 : 0
              return (
                <div key={row.label} className="flex items-center gap-3">
                  <span className="text-xs text-[#7d92b0] w-28 shrink-0">{row.label}</span>
                  <div className="flex-1 h-3 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${row.color} transition-all`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-xs text-white font-mono w-16 text-right">{row.value}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* ML Feature Importance */}
        <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42] mb-4">
          <p className="text-xs text-[#7d92b0] mb-3 font-medium uppercase tracking-wider">MLモデル — 特徴重要度</p>
          <div className="space-y-2">
            {anomaly.ml_features.map(f => (
              <div key={f.name} className="flex items-center gap-3">
                <span className="text-xs text-[#7d92b0] font-mono w-40 shrink-0">{f.name}</span>
                <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-purple-500" style={{ width: `${f.importance * 100}%` }} />
                </div>
                <span className="text-xs text-purple-300 font-mono w-10 text-right">{(f.importance * 100).toFixed(0)}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Related Events */}
        {anomaly.related_events.length > 0 && (
          <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42] mb-6">
            <p className="text-xs text-[#7d92b0] mb-3 font-medium uppercase tracking-wider">関連イベント</p>
            <div className="flex flex-wrap gap-2">
              {anomaly.related_events.map(e => (
                <span key={e} className="text-xs font-mono bg-[#1e2d42] text-[#7d92b0] px-2 py-1 rounded-sm">{e}</span>
              ))}
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-3">
          <button onClick={() => { onAction(anomaly.id, 'confirmed'); onClose() }}
            className="flex-1 py-2 rounded-sm bg-orange-700 text-white text-sm font-medium hover:bg-orange-600 transition-colors flex items-center justify-center gap-2">
            <CheckCircle className="w-4 h-4" /> 確認済み
          </button>
          <button onClick={() => { onAction(anomaly.id, 'false_positive'); onClose() }}
            className="flex-1 py-2 rounded-sm bg-gray-700 text-white text-sm font-medium hover:bg-gray-600 transition-colors flex items-center justify-center gap-2">
            <XCircle className="w-4 h-4" /> 誤検知
          </button>
          <button onClick={() => { onAction(anomaly.id, 'reviewed'); onClose() }}
            className="flex-1 py-2 rounded-sm bg-[#e8002d] text-white text-sm font-medium hover:bg-[#c8001e] transition-colors flex items-center justify-center gap-2">
            <ArrowUpCircle className="w-4 h-4" /> エスカレート
          </button>
        </div>
      </div>
    </div>
  )
}

// ── User Profile Card ──────────────────────────────────────────────

function UserProfileCard({ username, anomalies }: { username: string; anomalies: Anomaly[] }) {
  const userAnomalies = anomalies.filter(a => a.username === username)
  const riskScore = userAnomalies.length > 0 ? Math.round(userAnomalies.reduce((s, a) => s + a.score, 0) / userAnomalies.length) : 0
  const typeCount: Partial<Record<AnomalyType, number>> = {}
  userAnomalies.forEach(a => { typeCount[a.anomaly_type] = (typeCount[a.anomaly_type] ?? 0) + 1 })
  const topTypes = Object.entries(typeCount).sort(([,a],[,b]) => b - a).slice(0, 3).map(([t]) => t as AnomalyType)

  const departments: Record<string, string> = {
    jsmith: 'IT部門', bwilliams: '財務部門', mlopez: '開発部門',
    rjohnson: '営業部門', schen: '人事部門', hlee: 'マーケティング部門', kpatel: 'セキュリティ部門',
  }

  // 7日×24時間の活動ヒートマップ。
  //
  // 以前は営業時間を濃く、それ以外を薄くした乱数で作っていました。
  // UEBA のヒートマップは「いつもと違う時間帯に動いている」を見る図なので、
  // 作った濃淡は、探しているものそのものを偽装します。
  const heatmap = USE_MOCK
    ? Array.from({ length: 7 }, () =>
        Array.from({ length: 24 }, (_, hr) =>
          Math.min(1, (hr >= 9 && hr <= 18 ? 0.7 : 0.1) + Math.random() * 0.3)
        )
      )
    : []

  const days = ['月', '火', '水', '木', '金', '土', '日']
  const circumference = 2 * Math.PI * 28
  const dashOffset = circumference * (1 - riskScore / 100)

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      {/* Profile header */}
      <div className="flex items-start gap-5 mb-6">
        <div className="shrink-0">
          <div className="relative w-16 h-16">
            <svg className="w-16 h-16 -rotate-90" viewBox="0 0 72 72">
              <circle cx="36" cy="36" r="28" fill="none" stroke="#1e2d42" strokeWidth="6" />
              <circle cx="36" cy="36" r="28" fill="none"
                stroke={riskScore >= 70 ? '#ef4444' : riskScore >= 40 ? '#f59e0b' : '#22c55e'}
                strokeWidth="6" strokeDasharray={circumference} strokeDashoffset={dashOffset}
                strokeLinecap="round" />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-sm font-bold ${riskScore >= 70 ? 'text-red-400' : riskScore >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>{riskScore}</span>
            </div>
          </div>
          <p className="text-xs text-[#7d92b0] text-center mt-1">リスク</p>
        </div>
        <div>
          <h3 className="text-white font-semibold text-lg">{username}</h3>
          <p className="text-[#7d92b0] text-sm">{departments[username] ?? '不明'}</p>
          <p className="text-[#7d92b0] text-sm mt-1">異常検知: <span className="text-white font-semibold">{userAnomalies.length}</span> 件</p>
          <div className="flex flex-wrap gap-1 mt-2">
            {topTypes.map(t => {
              const tc = ANOMALY_TYPE_CONFIG[t]
              return <span key={t} className={`text-xs px-2 py-0.5 rounded-full ${tc.bg} ${tc.text}`}>{tc.label}</span>
            })}
          </div>
        </div>
      </div>

      {/* Baselines */}
      <h4 className="text-white text-sm font-semibold mb-3">行動ベースライン</h4>
      <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] overflow-hidden mb-5">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['メトリクス', 'ベースライン', '標準偏差', '更新日'].map(h => (
                <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-3 py-2">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {([] as UserBaseline[]).map(b => (
              <tr key={b.metric_name} className="border-b border-[#1e2d42]/50">
                <td className="px-3 py-2 text-xs text-[#e2e8f4]">{b.metric_name}</td>
                <td className="px-3 py-2 text-xs text-white font-mono">{b.baseline_value} {b.unit}</td>
                <td className="px-3 py-2 text-xs text-[#7d92b0] font-mono">±{b.std_deviation}</td>
                <td className="px-3 py-2 text-xs text-[#7d92b0]">{new Date(b.last_updated).toLocaleDateString('ja-JP')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Activity Heatmap */}
      <h4 className="text-white text-sm font-semibold mb-3">7日間アクティビティヒートマップ</h4>
      <div className="overflow-x-auto">
        <div className="flex gap-1 min-w-max mb-1">
          <div className="w-6" />
          {Array.from({ length: 24 }, (_, hr) => (
            <div key={hr} className="w-4 text-center">
              {hr % 6 === 0 && <span className="text-[8px] text-[#3d5068]">{hr}</span>}
            </div>
          ))}
        </div>
        {heatmap.map((row, dayIdx) => (
          <div key={dayIdx} className="flex items-center gap-1 mb-0.5">
            <span className="text-[9px] text-[#7d92b0] w-6 text-center">{days[dayIdx]}</span>
            {row.map((intensity, hr) => (
              <div key={hr} className="w-4 h-4 rounded-xs"
                style={{ backgroundColor: `rgba(232, 0, 45, ${intensity * 0.8})`, minWidth: '16px' }}
                title={`${days[dayIdx]} ${hr}:00 — アクティビティ: ${(intensity * 100).toFixed(0)}%`} />
            ))}
          </div>
        ))}
        <div className="flex items-center gap-2 mt-2">
          <span className="text-xs text-[#7d92b0]">低</span>
          <div className="flex gap-0.5">
            {[0.1, 0.3, 0.5, 0.7, 0.9].map(v => (
              <div key={v} className="w-3 h-3 rounded-xs" style={{ backgroundColor: `rgba(232, 0, 45, ${v * 0.8})` }} />
            ))}
          </div>
          <span className="text-xs text-[#7d92b0]">高</span>
        </div>
      </div>

      {/* Recent anomalies */}
      <h4 className="text-white text-sm font-semibold mt-5 mb-3">最近の異常</h4>
      <div className="space-y-2">
        {userAnomalies.slice(0, 5).map(a => {
          const tc = ANOMALY_TYPE_CONFIG[a.anomaly_type]
          const sc = SEVERITY_CONFIG[a.severity]
          return (
            <div key={a.id} className="flex items-center gap-3 py-1.5 border-b border-[#1e2d42]/50 last:border-0">
              <span className="text-xs text-[#7d92b0] w-24 shrink-0">{fmt(a.timestamp)}</span>
              <span className={`text-xs px-1.5 py-0.5 rounded-full ${tc.bg} ${tc.text} shrink-0`}>{tc.label}</span>
              <span className={`text-xs px-1.5 py-0.5 rounded-sm font-bold ${sc.bg} ${sc.text} shrink-0`}>{sc.label}</span>
              <span className={`text-xs font-bold ml-auto ${scoreColor(a.score)}`}>{a.score}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────

export default function UEBAPage() {
  const [tab, setTab] = useState<'anomalies' | 'profiles'>('anomalies')
  const [selectedAnomaly, setSelectedAnomaly] = useState<Anomaly | null>(null)
  const [filterType, setFilterType] = useState<AnomalyType | ''>('')
  const [filterSeverity, setFilterSeverity] = useState<Severity | ''>('')
  const [filterStatus, setFilterStatus] = useState<AnomalyStatus | ''>('')
  const [filterUser, setFilterUser] = useState('')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [localAnomalies, setLocalAnomalies] = useState<Anomaly[]>([])
  const { persist, saveError } = usePersist()
  const [userSearch, setUserSearch] = useState('')
  const [activeUser, setActiveUser] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 4000) }

  const { data: anomaliesData } = useQuery<Anomaly[]>({
    queryKey: ['ueba-anomalies'],
    queryFn: async () => {
      try {
        const res = await apiFetch<{ anomalies: Anomaly[] } | Anomaly[]>('/api/v1/admin/ueba/anomalies')
        return Array.isArray(res) ? res : (res as { anomalies: Anomaly[] }).anomalies ?? []
      } catch { return [] }
    },
  })

  useEffect(() => {
    if (anomaliesData) setLocalAnomalies(anomaliesData)
  }, [anomaliesData])

  const anomalies: Anomaly[] = anomaliesData ?? localAnomalies

  const handleStatusUpdate = async (id: string, status: AnomalyStatus) => {
    if (await persist('異常のステータス', `/api/v1/admin/ueba/anomalies/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) })) {
      setLocalAnomalies(prev => prev.map(a => a.id === id ? { ...a, status } : a))
      showToast('ステータスを更新しました')
    }
  }

  const handleBulkAction = (status: AnomalyStatus) => {
    selectedIds.forEach(id => handleStatusUpdate(id, status))
    setSelectedIds(new Set())
    showToast(`${selectedIds.size}件を${STATUS_CONFIG[status].label}に更新しました`)
  }

  // Filter
  const filteredAnomalies = localAnomalies.filter(a => {
    if (filterType && a.anomaly_type !== filterType) return false
    if (filterSeverity && a.severity !== filterSeverity) return false
    if (filterStatus && a.status !== filterStatus) return false
    if (filterUser && !a.username.toLowerCase().includes(filterUser.toLowerCase())) return false
    return true
  })

  const totalAnomalies = localAnomalies.length
  const criticalAnomalies = localAnomalies.filter(a => a.severity === 'critical').length
  const usersWithAnomalies = new Set(localAnomalies.map(a => a.username)).size
  const avgScore = Math.round(localAnomalies.reduce((s, a) => s + a.score, 0) / totalAnomalies)

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <SaveFailed error={saveError} />
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
          <Activity className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-2xl font-bold">ユーザー行動分析 (UEBA)</h1>
          <p className="text-[#7d92b0] text-sm">機械学習による異常行動検知と内部脅威分析</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総異常検知数', value: totalAnomalies, color: 'text-blue-400' },
          { label: '重大異常', value: criticalAnomalies, color: 'text-red-400' },
          { label: '異常ユーザー数', value: usersWithAnomalies, color: 'text-orange-400' },
          { label: '平均リスクスコア', value: avgScore, color: 'text-yellow-400' },
        ].map(c => (
          <div key={c.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <p className="text-xs text-[#7d92b0] mb-2">{c.label}</p>
            <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[{ key: 'anomalies', label: '異常検知' }, { key: 'profiles', label: 'ユーザープロファイル' }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === t.key ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'
            }`}>{t.label}</button>
        ))}
      </div>

      {/* Anomalies Tab */}
      {tab === 'anomalies' && (
        <div>
          {/* Filters */}
          <div className="flex flex-wrap gap-3 mb-4">
            <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2">
              <Filter className="w-3.5 h-3.5 text-[#7d92b0]" />
              <select value={filterType} onChange={e => setFilterType(e.target.value as any)}
                className="bg-transparent text-sm text-[#7d92b0] focus:outline-hidden focus:text-white">
                <option value="">全タイプ</option>
                {(Object.keys(ANOMALY_TYPE_CONFIG) as AnomalyType[]).map(t => (
                  <option key={t} value={t}>{ANOMALY_TYPE_CONFIG[t].label}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2">
              <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value as any)}
                className="bg-transparent text-sm text-[#7d92b0] focus:outline-hidden focus:text-white">
                <option value="">全重要度</option>
                {(['low','medium','high','critical'] as Severity[]).map(s => (
                  <option key={s} value={s}>{SEVERITY_CONFIG[s].label}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2">
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value as any)}
                className="bg-transparent text-sm text-[#7d92b0] focus:outline-hidden focus:text-white">
                <option value="">全ステータス</option>
                {(['open','reviewed','false_positive','confirmed'] as AnomalyStatus[]).map(s => (
                  <option key={s} value={s}>{STATUS_CONFIG[s].label}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2">
              <User className="w-3.5 h-3.5 text-[#7d92b0]" />
              <input value={filterUser} onChange={e => setFilterUser(e.target.value)}
                placeholder="ユーザー名で検索..."
                className="bg-transparent text-sm text-[#7d92b0] focus:outline-hidden focus:text-white w-36" />
            </div>
            {(filterType || filterSeverity || filterStatus || filterUser) && (
              <button onClick={() => { setFilterType(''); setFilterSeverity(''); setFilterStatus(''); setFilterUser('') }}
                className="text-xs text-[#7d92b0] hover:text-white px-3 border border-[#1e2d42] rounded-lg">リセット</button>
            )}
          </div>

          {/* Bulk Actions */}
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-3 mb-4 p-3 bg-[#0d1220] border border-[#1e2d42] rounded-lg">
              <span className="text-sm text-[#7d92b0]">{selectedIds.size}件を選択</span>
              <button onClick={() => handleBulkAction('reviewed')}
                className="px-3 py-1.5 bg-blue-900/40 text-blue-300 border border-blue-700/30 rounded-sm text-xs hover:bg-blue-900/60 transition-colors">
                レビュー済みにする
              </button>
              <button onClick={() => handleBulkAction('false_positive')}
                className="px-3 py-1.5 bg-gray-800 text-gray-300 border border-gray-700/30 rounded-sm text-xs hover:bg-gray-700 transition-colors">
                誤検知にする
              </button>
            </div>
          )}

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="px-4 py-3">
                    <input type="checkbox"
                      checked={selectedIds.size === filteredAnomalies.length && filteredAnomalies.length > 0}
                      onChange={e => setSelectedIds(e.target.checked ? new Set(filteredAnomalies.map(a => a.id)) : new Set())}
                      className="accent-[#e8002d]" />
                  </th>
                  {['タイムスタンプ', 'ユーザー', 'タイプ', '重要度', 'スコア', 'ベースライン', '実際', 'ステータス', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredAnomalies.map(a => {
                  const tc = ANOMALY_TYPE_CONFIG[a.anomaly_type]
                  const sc = SEVERITY_CONFIG[a.severity]
                  const stc = STATUS_CONFIG[a.status]
                  return (
                    <tr key={a.id} className="border-b border-[#1e2d42]/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3">
                        <input type="checkbox" checked={selectedIds.has(a.id)}
                          onChange={e => {
                            const next = new Set(selectedIds)
                            e.target.checked ? next.add(a.id) : next.delete(a.id)
                            setSelectedIds(next)
                          }}
                          className="accent-[#e8002d]" />
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">{fmt(a.timestamp)}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => { setActiveUser(a.username); setTab('profiles') }}
                          className="text-blue-400 text-xs hover:underline font-mono">{a.username}</button>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${tc.bg} ${tc.text}`}>{tc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm font-bold ${sc.bg} ${sc.text}`}>{sc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm font-bold ${scoreColor(a.score)}`}>{a.score}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono">{a.baseline_value}</td>
                      <td className="px-4 py-3 text-xs text-white font-mono font-semibold">{a.actual_value}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${stc.bg} ${stc.text}`}>{stc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedAnomaly(a)}
                          className="text-xs text-[#7d92b0] hover:text-white transition-colors">詳細</button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {filteredAnomalies.length === 0 && <div className="text-center py-12 text-[#7d92b0] text-sm">条件に一致する異常がありません</div>}
          </div>
        </div>
      )}

      {/* User Profile Tab */}
      {tab === 'profiles' && (
        <div>
          <div className="flex items-center gap-3 mb-6">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
              <input
                value={userSearch}
                onChange={e => setUserSearch(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && userSearch.trim() && setActiveUser(userSearch.trim())}
                placeholder="ユーザー名を入力してEnter..."
                className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/50"
              />
            </div>
            <div className="flex flex-wrap gap-2">
              {Array.from(new Set(anomalies.map(a => a.username))).map(u => (
                <button key={u} onClick={() => { setActiveUser(u); setUserSearch(u) }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                    activeUser === u ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'
                  }`}>{u}</button>
              ))}
            </div>
          </div>

          {activeUser ? (
            <UserProfileCard username={activeUser} anomalies={anomalies} />
          ) : (
            <div className="text-center py-20 text-[#7d92b0]">
              <User className="w-12 h-12 mx-auto mb-3 text-[#3d5068]" />
              <p className="text-sm">ユーザー名を入力するか、上のボタンからユーザーを選択してください</p>
            </div>
          )}
        </div>
      )}

      {/* Modals */}
      {selectedAnomaly && (
        <AnomalyDetailModal
          anomaly={selectedAnomaly}
          onClose={() => setSelectedAnomaly(null)}
          onAction={handleStatusUpdate}
        />
      )}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-[#0d1220] border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-sm text-[#e2e8f4] flex-1">{toast}</p>
          <button onClick={() => setToast(null)} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
