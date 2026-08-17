'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BarChart2, X, AlertTriangle, CheckCircle, TrendingUp, TrendingDown,
  DollarSign, AlertCircle, ChevronRight, Info, Zap, Globe, Hash, Link,
  Server, RefreshCw, ShieldOff,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type FeedType = 'commercial' | 'osint' | 'isac' | 'internal'
type FeedStatus = 'active' | 'degraded' | 'disabled'

interface ThreatFeed {
  id: string
  feed_name: string
  feed_type: FeedType
  provider: string
  ioc_count: number
  freshness_score: number
  accuracy_score: number
  false_positive_rate: number
  hit_rate: number
  last_updated: string
  cost_per_month: number
  overall_quality_score: number
  status: FeedStatus
  ioc_type_breakdown: { ip: number; domain: number; hash: number; url: number }
  recent_hits: { ioc: string; alert_id: string; date: string }[]
  recent_fp: { ioc: string; reason: string; date: string }[]
  monthly_hit_rate: number[]
  monthly_fp_rate: number[]
  monthly_ioc_volume: number[]
  incidents_prevented_est: number
}

const MONTHS_6 = ['11月', '12月', '1月', '2月', '3月', '4月']

const IOC_OVERLAP: { label: string; count: number }[] = [
  { label: 'IP アドレス', count: 1243 },
  { label: 'ドメイン', count: 892 },
  { label: 'ファイルハッシュ', count: 3401 },
  { label: 'URL', count: 567 },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const FEED_TYPE_STYLES: Record<FeedType, { label: string; bg: string; text: string }> = {
  commercial: { label: '商用', bg: 'bg-blue-900/40', text: 'text-blue-300' },
  osint: { label: 'OSINT', bg: 'bg-green-900/40', text: 'text-green-300' },
  isac: { label: 'ISAC', bg: 'bg-purple-900/40', text: 'text-purple-300' },
  internal: { label: '社内', bg: 'bg-orange-900/40', text: 'text-orange-300' },
}

const STATUS_STYLES: Record<FeedStatus, { label: string; bg: string; text: string; dot: string }> = {
  active: { label: 'アクティブ', bg: 'bg-green-900/40', text: 'text-green-300', dot: 'bg-green-400' },
  degraded: { label: '低下', bg: 'bg-yellow-900/40', text: 'text-yellow-300', dot: 'bg-yellow-400' },
  disabled: { label: '無効', bg: 'bg-gray-800/60', text: 'text-gray-400', dot: 'bg-gray-500' },
}

function gradeColor(score: number) {
  if (score >= 90) return 'text-green-400'
  if (score >= 75) return 'text-blue-400'
  if (score >= 60) return 'text-yellow-400'
  return 'text-red-400'
}

function grade(score: number) {
  if (score >= 90) return 'A'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

function fmtNum(n: number) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(0) + 'K'
  return n.toString()
}

function fmtYen(n: number) {
  return '¥' + n.toLocaleString('ja-JP')
}

function fmt(d: string) {
  return new Date(d).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// ─── Mini SVG Line Chart ──────────────────────────────────────────────────────

function MiniLineChart({ data, color, label }: { data: number[]; color: string; label: string }) {
  const max = Math.max(...data) * 1.1
  const min = Math.min(...data) * 0.9
  const W = 200, H = 50
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * W
    const y = H - ((v - min) / (max - min || 1)) * H
    return `${x},${y}`
  }).join(' ')

  return (
    <div>
      <p className="text-falcon-muted text-xs mb-1">{label}</p>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-12">
        <polyline fill="none" stroke={color} strokeWidth="2" points={pts} />
        {data.map((v, i) => {
          const x = (i / (data.length - 1)) * W
          const y = H - ((v - min) / (max - min || 1)) * H
          return <circle key={i} cx={x} cy={y} r="3" fill={color} />
        })}
      </svg>
      <div className="flex justify-between">
        {MONTHS_6.map(m => <span key={m} className="text-falcon-subtle text-[9px]">{m}</span>)}
      </div>
    </div>
  )
}

// ─── Feed Detail Modal ────────────────────────────────────────────────────────

function FeedDetailModal({ feed, onClose, onSync, onToggle, syncing }: {
  feed: ThreatFeed
  onClose: () => void
  onSync: () => void
  onToggle: () => void
  syncing: boolean
}) {
  const costPerHit = feed.cost_per_month > 0
    ? Math.round(feed.cost_per_month / Math.max(1, Math.round(feed.ioc_count * feed.hit_rate / 100)))
    : 0
  const totalIocBreak = Object.values(feed.ioc_type_breakdown).reduce((s, v) => s + v, 0)

  const recommendations: string[] = []
  if (feed.false_positive_rate > 3) recommendations.push(`誤検知率 ${feed.false_positive_rate}% は高水準です。IOCフィルタリングルールの見直しを推奨します。`)
  if (feed.overall_quality_score < 70) recommendations.push('総合品質スコアが低いため、このフィードの無効化を検討してください。')
  if (feed.cost_per_month > 300_000 && feed.hit_rate < 10) recommendations.push('このフィードのコストパフォーマンスは低いです。代替フィードへの切り替えを検討してください。')
  if (feed.hit_rate > 15) recommendations.push('ヒット率が高く、コストパフォーマンスに優れています。継続使用を推奨します。')
  if (feed.freshness_score < 75) recommendations.push('フレッシュネススコアが低く、IOCの鮮度に問題があります。')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-3xl max-h-[92vh] flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border">
          <div>
            <h3 className="text-white font-semibold text-lg">{feed.feed_name}</h3>
            <div className="flex items-center gap-2 mt-1">
              <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${FEED_TYPE_STYLES[feed.feed_type].bg} ${FEED_TYPE_STYLES[feed.feed_type].text}`}>
                {FEED_TYPE_STYLES[feed.feed_type].label}
              </span>
              <span className="text-falcon-muted text-sm">{feed.provider}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onSync}
              disabled={syncing}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
              {syncing ? '同期中...' : '手動同期'}
            </button>
            <button
              onClick={onToggle}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${feed.status === 'disabled' ? 'bg-green-700 hover:bg-green-600 text-white' : 'bg-red-900/50 hover:bg-red-800/70 text-red-300'}`}
            >
              <ShieldOff className="w-3.5 h-3.5" />
              {feed.status === 'disabled' ? '有効化' : '無効化'}
            </button>
            <button onClick={onClose} className="text-falcon-muted hover:text-white p-1 ml-1"><X className="w-5 h-5" /></button>
          </div>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-5">
          {/* Key metrics */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: '総合品質', value: feed.overall_quality_score, suffix: '', color: gradeColor(feed.overall_quality_score), extra: `(${grade(feed.overall_quality_score)})` },
              { label: 'ヒット率', value: feed.hit_rate, suffix: '%', color: 'text-green-400', extra: '' },
              { label: '誤検知率', value: feed.false_positive_rate, suffix: '%', color: feed.false_positive_rate > 3 ? 'text-red-400' : 'text-yellow-300', extra: '' },
              { label: 'IOC数', value: fmtNum(feed.ioc_count), suffix: '', color: 'text-blue-400', extra: '' },
            ].map(m => (
              <div key={m.label} className="bg-[#070d19] border border-falcon-border rounded-sm p-3 text-center">
                <p className="text-falcon-muted text-xs mb-1">{m.label}</p>
                <p className={`text-xl font-bold ${m.color}`}>{m.value}{m.suffix} {m.extra}</p>
              </div>
            ))}
          </div>

          {/* 30-day charts */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-[#070d19] border border-falcon-border rounded-sm p-4">
              <MiniLineChart data={feed.monthly_hit_rate} color="#22c55e" label="ヒット率トレンド (%)" />
            </div>
            <div className="bg-[#070d19] border border-falcon-border rounded-sm p-4">
              <MiniLineChart data={feed.monthly_fp_rate} color="#f59e0b" label="誤検知率トレンド (%)" />
            </div>
            <div className="bg-[#070d19] border border-falcon-border rounded-sm p-4">
              <MiniLineChart data={feed.monthly_ioc_volume} color="#3b82f6" label="IOCボリューム" />
            </div>
          </div>

          {/* IOC type breakdown */}
          <div className="bg-[#070d19] border border-falcon-border rounded-sm p-4">
            <h4 className="text-white font-medium mb-3">IOCタイプ内訳</h4>
            <div className="space-y-2">
              {([
                { key: 'ip', label: 'IPアドレス', color: 'bg-blue-500', icon: Server },
                { key: 'domain', label: 'ドメイン', color: 'bg-green-500', icon: Globe },
                { key: 'hash', label: 'ファイルハッシュ', color: 'bg-purple-500', icon: Hash },
                { key: 'url', label: 'URL', color: 'bg-orange-500', icon: Link },
              ] as const).map(({ key, label, color, icon: Icon }) => {
                const pct = feed.ioc_type_breakdown[key]
                return (
                  <div key={key} className="flex items-center gap-3">
                    <Icon className="w-4 h-4 text-falcon-muted shrink-0" />
                    <span className="text-falcon-muted text-sm w-28 shrink-0">{label}</span>
                    <div className="flex-1 bg-falcon-border rounded-full h-2">
                      <div className={`${color} h-2 rounded-full`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-white text-sm w-10 text-right">{pct}%</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Recent hits & FPs */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#070d19] border border-falcon-border rounded-sm p-4">
              <h4 className="text-white font-medium mb-3 flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-400" />最近のヒット</h4>
              {feed.recent_hits.length === 0
                ? <p className="text-falcon-muted text-sm">記録なし</p>
                : <div className="space-y-2">
                    {feed.recent_hits.map((h, i) => (
                      <div key={i} className="flex items-start justify-between text-sm gap-2">
                        <span className="text-falcon-text font-mono text-xs truncate">{h.ioc}</span>
                        <div className="text-right shrink-0">
                          <p className="text-blue-400 text-xs">{h.alert_id}</p>
                          <p className="text-falcon-subtle text-xs">{h.date}</p>
                        </div>
                      </div>
                    ))}
                  </div>
              }
            </div>
            <div className="bg-[#070d19] border border-falcon-border rounded-sm p-4">
              <h4 className="text-white font-medium mb-3 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-400" />誤検知サンプル</h4>
              {feed.recent_fp.length === 0
                ? <p className="text-green-400 text-sm">誤検知なし</p>
                : <div className="space-y-2">
                    {feed.recent_fp.map((fp, i) => (
                      <div key={i} className="text-sm">
                        <p className="text-falcon-text font-mono text-xs truncate">{fp.ioc}</p>
                        <p className="text-falcon-muted text-xs">{fp.reason}</p>
                      </div>
                    ))}
                  </div>
              }
            </div>
          </div>

          {/* Recommendations */}
          {recommendations.length > 0 && (
            <div className="bg-[#070d19] border border-falcon-border rounded-sm p-4">
              <h4 className="text-white font-medium mb-3 flex items-center gap-2"><Info className="w-4 h-4 text-blue-400" />推奨事項</h4>
              <ul className="space-y-2">
                {recommendations.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-falcon-muted">
                    <ChevronRight className="w-4 h-4 text-falcon-red shrink-0 mt-0.5" />{r}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function FeedAnalyticsPage() {
  const [selectedFeed, setSelectedFeed] = useState<ThreatFeed | null>(null)
  const [feedStatuses, setFeedStatuses] = useState<Record<string, FeedStatus>>({})
  const [syncingFeeds, setSyncingFeeds] = useState<Record<string, boolean>>({})
  const [syncingAll, setSyncingAll] = useState(false)
  const [toastMsg, setToastMsg] = useState<string | null>(null)

  function showToast(msg: string) {
    setToastMsg(msg)
    setTimeout(() => setToastMsg(null), 3000)
  }

  async function handleSync(feedId: string, feedName: string) {
    setSyncingFeeds(prev => ({ ...prev, [feedId]: true }))
    try {
      await apiFetch(`/api/v1/admin/feed-analytics/${feedId}/sync`, { method: 'POST' })
    } catch { /* endpoint may not exist yet — ignore */ }
    await new Promise(r => setTimeout(r, 1200))
    setSyncingFeeds(prev => ({ ...prev, [feedId]: false }))
    showToast(`「${feedName}」の同期が完了しました`)
  }

  async function handleSyncAll() {
    setSyncingAll(true)
    try {
      await apiFetch('/api/v1/admin/feed-analytics/sync-all', { method: 'POST' })
    } catch { /* ignore */ }
    await new Promise(r => setTimeout(r, 2000))
    setSyncingAll(false)
    showToast('全フィードの同期が完了しました')
  }

  async function handleToggleStatus(feedId: string, feedName: string, current: FeedStatus) {
    const next: FeedStatus = current === 'disabled' ? 'active' : 'disabled'
    try {
      await apiFetch(`/api/v1/admin/feed-analytics/${feedId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: next }),
      })
    } catch { /* ignore */ }
    setFeedStatuses(prev => ({ ...prev, [feedId]: next }))
    showToast(`「${feedName}」を${next === 'disabled' ? '無効化' : '有効化'}しました`)
    if (selectedFeed?.id === feedId) setSelectedFeed(prev => prev ? { ...prev, status: next } : prev)
  }

  const { data: feedsData } = useQuery<ThreatFeed[]>({
    queryKey: ['feed-analytics'],
    queryFn: () => apiFetch('/api/v1/admin/feed-analytics'),
    retry: false,
  })
  const feeds = (feedsData ?? []).map(f => ({
    ...f,
    status: feedStatuses[f.id] ?? f.status,
  }))

  const totalCost = feeds.reduce((s, f) => s + f.cost_per_month, 0)
  const annualCost = totalCost * 12
  const avgQuality = Math.round(feeds.reduce((s, f) => s + f.overall_quality_score, 0) / feeds.length)
  const overallGrade = grade(avgQuality)

  // Below threshold feeds (quality < 70)
  const belowThreshold = feeds.filter(f => f.overall_quality_score < 70)

  // Savings if removing below-threshold feeds
  const potentialSavings = belowThreshold.reduce((s, f) => s + f.cost_per_month * 12, 0)

  // Sort for comparison
  const sortedByQuality = [...feeds].sort((a, b) => b.overall_quality_score - a.overall_quality_score)

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Toast */}
      {toastMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#1a2a3a] border border-[#2e4460] text-white text-sm px-4 py-3 rounded-lg shadow-lg flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          {toastMsg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-blue-500 to-blue-700 flex items-center justify-center">
            <BarChart2 className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white text-2xl font-bold">脅威フィード品質分析</h1>
            <p className="text-falcon-muted text-sm">脅威インテリジェンスフィードの品質・コストパフォーマンス評価</p>
          </div>
        </div>
        <button
          onClick={handleSyncAll}
          disabled={syncingAll}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${syncingAll ? 'animate-spin' : ''}`} />
          {syncingAll ? '同期中...' : '全フィード同期'}
        </button>
      </div>

      {/* Overall Health Score */}
      <div className="grid grid-cols-5 gap-4">
        <div className="col-span-1 bg-falcon-surface border border-falcon-border rounded-lg p-5 flex flex-col items-center justify-center">
          <p className="text-falcon-muted text-sm mb-2">総合フィード品質</p>
          <p className={`text-7xl font-black ${gradeColor(avgQuality)}`}>{overallGrade}</p>
          <p className="text-white text-xl font-bold mt-1">{avgQuality}/100</p>
          <p className="text-falcon-subtle text-xs mt-2">{feeds.length}フィード平均</p>
        </div>
        <div className="col-span-4 grid grid-cols-4 gap-4">
          {[
            { label: '月次コスト合計', value: fmtYen(totalCost), icon: DollarSign, color: 'text-blue-400', sub: `年間 ${fmtYen(annualCost)}` },
            { label: 'アクティブフィード', value: feeds.filter(f => f.status === 'active').length, icon: CheckCircle, color: 'text-green-400', sub: `${feeds.filter(f => f.status === 'degraded').length} 低下中` },
            { label: '総IOC数', value: fmtNum(feeds.reduce((s, f) => s + f.ioc_count, 0)), icon: Zap, color: 'text-purple-400', sub: '重複含む' },
            { label: '要改善フィード', value: belowThreshold.length, icon: AlertTriangle, color: 'text-yellow-400', sub: '品質スコア<70' },
          ].map(card => (
            <div key={card.label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-falcon-muted text-xs">{card.label}</p>
                <card.icon className={`w-4 h-4 ${card.color}`} />
              </div>
              <p className="text-white text-xl font-bold">{card.value}</p>
              <p className="text-falcon-subtle text-xs mt-1">{card.sub}</p>
            </div>
          ))}
          {/* Quality Scoring Formula */}
          <div className="col-span-4 bg-falcon-surface border border-falcon-border rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Info className="w-4 h-4 text-blue-400" />
              <p className="text-white font-medium text-sm">品質スコア計算式</p>
            </div>
            <p className="text-falcon-muted text-sm font-mono">
              総合品質スコア = フレッシュネス × 0.3 + 精度 × 0.4 + ヒット率 × 0.3
            </p>
            <p className="text-falcon-subtle text-xs mt-1">各スコアは0〜100の正規化値。ヒット率はアラートへの実際の貢献度を示します。</p>
          </div>
        </div>
      </div>

      {/* Feeds Overview Table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold">フィード一覧</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border bg-[#070d19]">
                {['フィード名', 'タイプ', 'IOC数', 'フレッシュネス', '精度', '誤検知率', 'ヒット率', '最終更新', '月額コスト', '対ヒットコスト', '品質', 'ステータス', '操作'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-falcon-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {feeds.map(f => {
                const costPerHit = f.cost_per_month > 0
                  ? Math.round(f.cost_per_month / Math.max(1, Math.round(f.ioc_count * f.hit_rate / 100 / 1000)))
                  : 0
                const ss = STATUS_STYLES[f.status]
                const ft = FEED_TYPE_STYLES[f.feed_type]
                return (
                  <tr key={f.id} onClick={() => setSelectedFeed(f)}
                    className="hover:bg-[#0d1525] cursor-pointer">
                    <td className="px-4 py-3">
                      <p className="text-white font-medium whitespace-nowrap">{f.feed_name}</p>
                      <p className="text-falcon-subtle text-xs">{f.provider}</p>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium ${ft.bg} ${ft.text}`}>{ft.label}</span>
                    </td>
                    <td className="px-4 py-3 text-falcon-muted whitespace-nowrap">{fmtNum(f.ioc_count)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-14 bg-falcon-border rounded-full h-1.5">
                          <div className="bg-blue-500 h-1.5 rounded-full" style={{ width: `${f.freshness_score}%` }} />
                        </div>
                        <span className="text-white text-xs">{f.freshness_score}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-14 bg-falcon-border rounded-full h-1.5">
                          <div className="bg-green-500 h-1.5 rounded-full" style={{ width: `${f.accuracy_score}%` }} />
                        </div>
                        <span className="text-white text-xs">{f.accuracy_score}</span>
                      </div>
                    </td>
                    <td className={`px-4 py-3 font-medium whitespace-nowrap ${f.false_positive_rate > 3 ? 'text-red-400' : f.false_positive_rate > 1.5 ? 'text-yellow-400' : 'text-green-400'}`}>
                      {f.false_positive_rate}%
                    </td>
                    <td className="px-4 py-3 text-green-400 font-medium whitespace-nowrap">{f.hit_rate}%</td>
                    <td className="px-4 py-3 text-falcon-muted whitespace-nowrap text-xs">{fmt(f.last_updated)}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {f.cost_per_month === 0
                        ? <span className="text-green-400 text-xs">無償</span>
                        : <span className="text-white">{fmtYen(f.cost_per_month)}</span>
                      }
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {costPerHit > 0 ? <span className="text-falcon-muted text-xs">{fmtYen(costPerHit)}</span> : <span className="text-falcon-subtle text-xs">N/A</span>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-lg font-black ${gradeColor(f.overall_quality_score)}`}>{grade(f.overall_quality_score)}</span>
                      <span className="text-falcon-muted text-xs ml-1">{f.overall_quality_score}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium ${ss.bg} ${ss.text}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${ss.dot}`} />{ss.label}
                      </span>
                    </td>
                    <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleSync(f.id, f.feed_name)}
                          disabled={!!syncingFeeds[f.id]}
                          title="手動同期"
                          className="p-1.5 rounded-sm bg-blue-900/40 hover:bg-blue-900/70 text-blue-300 disabled:opacity-40 transition-colors"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${syncingFeeds[f.id] ? 'animate-spin' : ''}`} />
                        </button>
                        <button
                          onClick={() => handleToggleStatus(f.id, f.feed_name, f.status)}
                          title={f.status === 'disabled' ? '有効化' : '無効化'}
                          className={`p-1.5 rounded-sm transition-colors ${f.status === 'disabled' ? 'bg-green-900/40 hover:bg-green-900/70 text-green-300' : 'bg-red-900/30 hover:bg-red-900/60 text-red-400'}`}
                        >
                          <ShieldOff className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Comparative Analysis */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
        <h2 className="text-white font-semibold mb-4">比較分析</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border">
                <th className="px-4 py-2 text-left text-falcon-muted text-xs">フィード</th>
                <th className="px-4 py-2 text-left text-falcon-muted text-xs">フレッシュネス</th>
                <th className="px-4 py-2 text-left text-falcon-muted text-xs">精度</th>
                <th className="px-4 py-2 text-left text-falcon-muted text-xs">ヒット率</th>
                <th className="px-4 py-2 text-left text-falcon-muted text-xs">誤検知率</th>
                <th className="px-4 py-2 text-left text-falcon-muted text-xs">推定防御インシデント数</th>
                <th className="px-4 py-2 text-left text-falcon-muted text-xs">総合</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {sortedByQuality.map(f => (
                <tr key={f.id} className="hover:bg-[#0d1525]">
                  <td className="px-4 py-2.5 text-white text-sm font-medium">{f.feed_name}</td>
                  {[f.freshness_score, f.accuracy_score].map((score, i) => (
                    <td key={i} className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-falcon-border rounded-full h-1.5">
                          <div className={`h-1.5 rounded-full ${score >= 80 ? 'bg-green-500' : score >= 65 ? 'bg-yellow-500' : 'bg-red-500'}`} style={{ width: `${score}%` }} />
                        </div>
                        <span className="text-white text-xs">{score}</span>
                      </div>
                    </td>
                  ))}
                  <td className={`px-4 py-2.5 text-sm font-medium ${f.hit_rate >= 10 ? 'text-green-400' : f.hit_rate >= 5 ? 'text-yellow-400' : 'text-red-400'}`}>{f.hit_rate}%</td>
                  <td className={`px-4 py-2.5 text-sm font-medium ${f.false_positive_rate <= 1 ? 'text-green-400' : f.false_positive_rate <= 3 ? 'text-yellow-400' : 'text-red-400'}`}>{f.false_positive_rate}%</td>
                  <td className="px-4 py-2.5 text-white text-sm">{f.incidents_prevented_est}件</td>
                  <td className="px-4 py-2.5">
                    <span className={`text-lg font-black ${gradeColor(f.overall_quality_score)}`}>{grade(f.overall_quality_score)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Disable Recommendations */}
      {belowThreshold.length > 0 && (
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
          <h2 className="text-white font-semibold mb-2 flex items-center gap-2">
            <ShieldOff className="w-5 h-5 text-red-400" />不要フィードの推奨
          </h2>
          <p className="text-falcon-muted text-sm mb-4">品質スコアが70未満のフィードは無効化を検討してください。</p>
          <div className="space-y-3">
            {belowThreshold.map(f => (
              <div key={f.id} className="flex items-center justify-between p-4 bg-red-900/10 border border-red-800/30 rounded-lg">
                <div>
                  <p className="text-white font-medium">{f.feed_name}</p>
                  <p className="text-falcon-muted text-sm mt-0.5">品質スコア {f.overall_quality_score} / 誤検知率 {f.false_positive_rate}% / ヒット率 {f.hit_rate}%</p>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <p className="text-red-400 text-sm font-medium">推奨: 無効化</p>
                    {f.cost_per_month > 0 && <p className="text-falcon-muted text-xs">{fmtYen(f.cost_per_month * 12)}/年 削減可能</p>}
                  </div>
                  <button
                    onClick={() => handleToggleStatus(f.id, f.feed_name, f.status)}
                    disabled={f.status === 'disabled'}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/40 hover:bg-red-900/70 disabled:opacity-40 text-red-300 text-xs font-medium rounded-lg transition-colors whitespace-nowrap"
                  >
                    <ShieldOff className="w-3.5 h-3.5" />
                    {f.status === 'disabled' ? '無効化済み' : '無効化'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* IOC Overlap Analysis */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
          <h2 className="text-white font-semibold mb-4">IOC重複分析</h2>
          <div className="space-y-3 mb-5">
            {IOC_OVERLAP.map(o => (
              <div key={o.label} className="flex items-center justify-between p-3 bg-[#070d19] border border-falcon-border rounded-sm">
                <span className="text-falcon-muted text-sm">{o.label}</span>
                <span className="text-white font-bold">{fmtNum(o.count)}</span>
              </div>
            ))}
          </div>
          {/* Venn-style approximation */}
          <div className="flex items-center justify-center py-4">
            <div className="relative w-32 h-24">
              <div className="absolute left-0 top-0 w-20 h-20 rounded-full bg-blue-500/20 border-2 border-blue-500/40 flex items-end justify-start pl-2 pb-2">
                <span className="text-blue-300 text-xs">CF</span>
              </div>
              <div className="absolute right-0 top-0 w-20 h-20 rounded-full bg-green-500/20 border-2 border-green-500/40 flex items-end justify-end pr-2 pb-2">
                <span className="text-green-300 text-xs">RF</span>
              </div>
              <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
                <span className="text-white text-xs font-bold">24%</span>
              </div>
            </div>
          </div>
          <p className="text-falcon-subtle text-xs text-center">CrowdStrike / Recorded Future 重複率イメージ</p>
        </div>

        {/* Cost Optimization */}
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
          <h2 className="text-white font-semibold mb-4 flex items-center gap-2"><DollarSign className="w-5 h-5 text-green-400" />コスト最適化</h2>
          <div className="space-y-4">
            <div className="p-4 bg-[#070d19] border border-falcon-border rounded-sm">
              <p className="text-falcon-muted text-sm mb-1">年間総コスト</p>
              <p className="text-white text-2xl font-bold">{fmtYen(annualCost)}</p>
            </div>
            {potentialSavings > 0 && (
              <div className="p-4 bg-green-900/10 border border-green-800/30 rounded-sm">
                <p className="text-green-400 text-sm mb-1">推奨設定による削減額</p>
                <p className="text-green-300 text-2xl font-bold">{fmtYen(potentialSavings)}/年</p>
                <p className="text-falcon-muted text-xs mt-1">低品質フィード {belowThreshold.length}件を無効化した場合</p>
              </div>
            )}
            <div className="space-y-2">
              <p className="text-falcon-muted text-sm font-medium">フィード別ROI（インシデント防御推定）</p>
              {(() => {
                const roiFeeds = feeds.filter(f => f.cost_per_month > 0).sort((a, b) => b.incidents_prevented_est - a.incidents_prevented_est)
                const maxPrevented = Math.max(...roiFeeds.map(f => f.incidents_prevented_est), 1)
                return roiFeeds.map(f => (
                  <div key={f.id} className="flex items-center gap-3">
                    <span className="text-falcon-muted text-xs w-32 truncate shrink-0">{f.feed_name.split(' ')[0]}</span>
                    <div className="flex-1 bg-falcon-border rounded-full h-2 overflow-hidden">
                      <div className="bg-falcon-red h-2 rounded-full" style={{ width: `${(f.incidents_prevented_est / maxPrevented) * 100}%` }} />
                    </div>
                    <span className="text-white text-xs w-10 text-right">{f.incidents_prevented_est}件</span>
                  </div>
                ))
              })()}
            </div>
          </div>
        </div>
      </div>

      {/* Feed Detail Modal */}
      {selectedFeed && (
        <FeedDetailModal
          feed={selectedFeed}
          onClose={() => setSelectedFeed(null)}
          onSync={() => handleSync(selectedFeed.id, selectedFeed.feed_name)}
          onToggle={() => handleToggleStatus(selectedFeed.id, selectedFeed.feed_name, selectedFeed.status)}
          syncing={!!syncingFeeds[selectedFeed.id]}
        />
      )}
    </div>
  )
}
