'use client'

import { useQuery } from '@tanstack/react-query'
import { useRef, useEffect, useState } from 'react'
import { apiFetch } from '@/lib/api'
import { formatDistanceToNow, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import {
  Zap, Clock, CalendarDays, RefreshCw, ShieldAlert,
  Siren, ExternalLink, AlertTriangle, CheckCircle2, Inbox,
  VolumeX, ArrowRight, GitMerge, Target, Bell,
} from 'lucide-react'
import Link from 'next/link'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ────────────────────────────────────────────────────────

interface WorkQueueItem {
  id: string
  type: 'alert' | 'incident'
  title: string
  severity: number
  status: string
  hostname?: string
  priority: 'urgent' | 'today' | 'week'
  link: string
  created_at: string
  age_hours: number
}

interface WorkQueueResponse {
  urgent: WorkQueueItem[]
  today: WorkQueueItem[]
  week: WorkQueueItem[]
  total: number
  generated_at: string
}

// ── Helpers ──────────────────────────────────────────────────────

function severityColor(s: number) {
  if (s >= 9) return '#e8002d'
  if (s >= 7) return '#f97316'
  if (s >= 5) return '#f59e0b'
  return '#3b82f6'
}

function severityLabel(s: number) {
  if (s >= 9) return 'クリティカル'
  if (s >= 7) return '高'
  if (s >= 5) return '中'
  return '低'
}

function ageLabel(h: number) {
  if (h < 1) return '1時間未満'
  if (h < 24) return `${h}時間前`
  return `${Math.floor(h / 24)}日前`
}

// ── Item Card ────────────────────────────────────────────────────

function QueueCard({ item }: { item: WorkQueueItem }) {
  const TypeIcon = item.type === 'alert' ? ShieldAlert : Siren
  const color = severityColor(item.severity)

  return (
    <Link href={item.link} className="block group">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3.5 hover:border-[#2a3f60] hover:bg-[#111827] transition-all">
        <div className="flex items-start gap-2.5">
          <TypeIcon className="w-4 h-4 shrink-0 mt-0.5" style={{ color }} />
          <div className="flex-1 min-w-0">
            <p className="text-sm text-[#e2e8f4] font-medium leading-snug line-clamp-2 group-hover:text-white">
              {item.title}
            </p>
            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
              <span
                className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm"
                style={{ color, backgroundColor: `${color}20` }}
              >
                {severityLabel(item.severity)} Lv{item.severity}
              </span>
              <span className="text-[10px] text-[#3d5068] bg-[#161f33] px-1.5 py-0.5 rounded-sm font-mono">
                {item.status}
              </span>
              {item.hostname && (
                <span className="text-[10px] text-[#7d92b0] font-mono truncate max-w-[120px]">
                  {item.hostname}
                </span>
              )}
              <span className="text-[10px] text-[#3d5068] ml-auto shrink-0">
                {ageLabel(item.age_hours)}
              </span>
            </div>
          </div>
          <ExternalLink className="w-3.5 h-3.5 text-[#3d5068] shrink-0 opacity-0 group-hover:opacity-100 transition-opacity mt-0.5" />
        </div>
      </div>
    </Link>
  )
}

// ── Lane ─────────────────────────────────────────────────────────

function Lane({
  icon: Icon,
  title,
  subtitle,
  items,
  color,
  emptyMsg,
}: {
  icon: React.ElementType
  title: string
  subtitle: string
  items: WorkQueueItem[]
  color: string
  emptyMsg: string
}) {
  return (
    <div className="flex flex-col min-h-0">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-[#1e2d42]">
        <Icon className="w-4 h-4" style={{ color }} />
        <div>
          <p className="text-sm font-bold text-[#e2e8f4]">{title}</p>
          <p className="text-[10px] text-[#3d5068]">{subtitle}</p>
        </div>
        <span
          className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full"
          style={{ color, backgroundColor: `${color}20` }}
        >
          {items.length}
        </span>
      </div>

      {/* Items */}
      <div className="space-y-2 overflow-y-auto flex-1">
        {items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-[#3d5068]">
            <CheckCircle2 className="w-8 h-8 mb-2 opacity-40" />
            <p className="text-xs">{emptyMsg}</p>
          </div>
        ) : (
          items.map(item => <QueueCard key={`${item.type}-${item.id}`} item={item} />)
        )}
      </div>
    </div>
  )
}

interface SuppressCandidate {
  rule_name: string
  hostname: string
  count: number
  first_seen: string
  last_seen: string
}

interface CorrelationGroup {
  id: string
  agent_id: string
  mitre_technique: string
  first_seen_at: string
  last_seen_at: string
  alert_count: number
  incident_id: string | null
}

// ── Main Page ─────────────────────────────────────────────────────

export default function SOCQueuePage() {
  const { data, isLoading, refetch, isFetching } = useQuery<WorkQueueResponse>({
    queryKey: ['soc-work-queue'],
    queryFn: () => apiFetch('/api/v1/soc/work-queue'),
    refetchInterval: 60_000,
  })

  // 前回の緊急件数と比較して増加したら通知バナーを表示
  const prevUrgentRef = useRef<number | null>(null)
  const [newUrgentCount, setNewUrgentCount] = useState(0)
  const [showNewBanner, setShowNewBanner] = useState(false)

  useEffect(() => {
    const currentUrgent = data?.urgent?.length ?? 0
    if (prevUrgentRef.current !== null && currentUrgent > prevUrgentRef.current) {
      const diff = currentUrgent - prevUrgentRef.current
      setNewUrgentCount(diff)
      setShowNewBanner(true)
      // 10秒後に自動で消す
      const t = setTimeout(() => setShowNewBanner(false), 10_000)
      return () => clearTimeout(t)
    }
    prevUrgentRef.current = currentUrgent
  }, [data?.urgent?.length])

  const { data: candidatesData } = useQuery<{ candidates: SuppressCandidate[] }>({
    queryKey: ['suppression-candidates'],
    queryFn: () => apiFetch('/api/v1/suppressions/candidates?days=7&threshold=5'),
    refetchInterval: 300_000,
  })
  const candidates = candidatesData?.candidates ?? []

  const { data: groupsData } = useQuery<{ items: CorrelationGroup[]; total: number }>({
    queryKey: ['correlation-groups'],
    queryFn: () => apiFetch('/api/v1/correlation-rules?limit=20&offset=0'),
    refetchInterval: 120_000,
  })
  const correlationGroups = groupsData?.items ?? []

  const urgent = data?.urgent ?? []
  const today  = data?.today  ?? []
  const week   = data?.week   ?? []
  const total  = data?.total  ?? 0

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Inbox className="w-6 h-6 text-[#e8002d]" />
            SOC ワークキュー
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">
            未対応のアラート・インシデントを優先度別に表示
            {data?.generated_at && (
              <span className="ml-2 text-[#3d5068]">
                （{formatDistanceToNow(parseISO(data.generated_at), { addSuffix: true, locale: ja })} 更新）
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-[#7d92b0]">
            合計 <span className="text-white font-bold">{total}</span> 件
          </span>
          <button
            onClick={() => refetch()}
            className="flex items-center gap-1.5 px-3 py-2 bg-[#161f33] hover:bg-[#1d2f4a] rounded-lg text-sm transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* 新規緊急アラート通知バナー */}
      {showNewBanner && (
        <div className="mb-4 flex items-center gap-3 px-4 py-3 bg-red-950/40 border border-red-600/50 rounded-xl animate-pulse">
          <Bell className="w-4 h-4 text-red-400 shrink-0" />
          <p className="text-red-300 text-sm font-medium">
            ⚠ 新しい緊急対応が {newUrgentCount}件 追加されました
          </p>
          <button
            onClick={() => setShowNewBanner(false)}
            className="ml-auto text-red-400/60 hover:text-red-400 transition-colors text-xs"
          >
            閉じる
          </button>
        </div>
      )}

      {/* Summary badges */}
      <div className="flex gap-3 mb-6">
        {[
          { label: '今すぐ対応', count: urgent.length, color: '#e8002d', Icon: Zap },
          { label: '今日中に対応', count: today.length, color: '#f97316', Icon: Clock },
          { label: '今週中に対応', count: week.length, color: '#3b82f6', Icon: CalendarDays },
        ].map(({ label, count, color, Icon }) => (
          <div
            key={label}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg border"
            style={{ borderColor: `${color}30`, backgroundColor: `${color}10` }}
          >
            <Icon className="w-4 h-4" style={{ color }} />
            <span className="text-xs text-[#7d92b0]">{label}</span>
            <span className="text-lg font-bold" style={{ color }}>{count}</span>
          </div>
        ))}
      </div>

      {/* 3-lane layout */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-[#7d92b0]">
          <RefreshCw className="w-6 h-6 animate-spin mr-2" />
          読み込み中...
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-[#080c14] border border-[#e8002d]/20 rounded-xl p-4">
            <Lane
              icon={Zap}
              title="今すぐ対応"
              subtitle="Critical / High・24時間以内"
              items={urgent}
              color="#e8002d"
              emptyMsg="緊急対応が必要な項目はありません"
            />
          </div>
          <div className="bg-[#080c14] border border-[#f97316]/20 rounded-xl p-4">
            <Lane
              icon={Clock}
              title="今日中に対応"
              subtitle="Medium以上 または High・24h超過"
              items={today}
              color="#f97316"
              emptyMsg="本日中の対応が必要な項目はありません"
            />
          </div>
          <div className="bg-[#080c14] border border-[#3b82f6]/20 rounded-xl p-4">
            <Lane
              icon={CalendarDays}
              title="今週中に対応"
              subtitle="Low重要度 / 調査中・封じ込め済み"
              items={week}
              color="#3b82f6"
              emptyMsg="今週中の対応が必要な項目はありません"
            />
          </div>
        </div>
      )}

      {total === 0 && !isLoading && (
        <div className="flex flex-col items-center justify-center py-12 text-[#3d5068]">
          <CheckCircle2 className="w-12 h-12 mb-3 opacity-40" />
          <p className="text-lg font-medium">未対応のアラート・インシデントはありません</p>
          <p className="text-sm mt-1">すべての項目が対応済みです</p>
        </div>
      )}

      {/* アラートグルーピング（相関検知）セクション */}
      {correlationGroups.length > 0 && (
        <div className="mt-6">
          <div className="flex items-center gap-2 mb-3">
            <GitMerge className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-bold text-[#e2e8f4]">アラートグルーピング（相関検知）</h2>
            <span className="text-xs text-purple-400 bg-purple-400/10 px-2 py-0.5 rounded-full border border-purple-400/20">
              {correlationGroups.length}グループ
            </span>
            <span className="text-xs text-[#3d5068] ml-2">同一エージェント・同一MITREテクニックで相関検知されたアラート群</span>
          </div>
          <div className="bg-[#080c14] border border-purple-400/20 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0d1220]">
                  <th className="px-4 py-2.5 text-left font-medium">MITREテクニック</th>
                  <th className="px-4 py-2.5 text-left font-medium">エージェントID</th>
                  <th className="px-4 py-2.5 text-right font-medium">アラート数</th>
                  <th className="px-4 py-2.5 text-left font-medium hidden md:table-cell">最終検知</th>
                  <th className="px-4 py-2.5 text-right font-medium">インシデント</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {correlationGroups.map((g) => (
                  <tr key={g.id} className="hover:bg-[#111827] transition-colors">
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <Target className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                        <span className="text-xs text-[#e2e8f4] font-mono">{g.mitre_technique || '—'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-[#7d92b0] font-mono truncate max-w-[140px]">
                      {g.agent_id.slice(0, 8)}…
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span className="text-purple-400 font-bold text-sm">{g.alert_count}</span>
                      <span className="text-[#3d5068] text-xs">件</span>
                    </td>
                    <td className="px-4 py-2.5 hidden md:table-cell text-xs text-[#3d5068]">
                      {g.last_seen_at
                        ? formatDistanceToNow(parseISO(g.last_seen_at), { addSuffix: true, locale: ja })
                        : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      {g.incident_id ? (
                        <Link
                          href={`/incidents/${g.incident_id}`}
                          className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          インシデント表示
                          <ArrowRight className="w-3 h-3" />
                        </Link>
                      ) : (
                        <span className="text-xs text-[#3d5068]">未リンク</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-[#3d5068] mt-2 text-right">
            * 相関エンジンが自動検知したグループです。詳細は{' '}
            <Link href="/incidents" className="text-blue-400 hover:underline">インシデント管理</Link>で確認できます。
          </p>
        </div>
      )}

      {/* 抑制候補セクション */}
      {candidates.length > 0 && (
        <div className="mt-6">
          <div className="flex items-center gap-2 mb-3">
            <VolumeX className="w-4 h-4 text-yellow-400" />
            <h2 className="text-sm font-bold text-[#e2e8f4]">抑制候補（ノイズアラート）</h2>
            <span className="text-xs text-[#3d5068] bg-yellow-400/10 px-2 py-0.5 rounded-full border border-yellow-400/20 text-yellow-400">
              {candidates.length}件
            </span>
            <span className="text-xs text-[#3d5068] ml-2">過去7日間に5回以上繰り返し発生したアラート</span>
          </div>
          <div className="bg-[#080c14] border border-yellow-400/20 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#0d1220]">
                  <th className="px-4 py-2.5 text-left font-medium">ルール名</th>
                  <th className="px-4 py-2.5 text-left font-medium">端末</th>
                  <th className="px-4 py-2.5 text-right font-medium">発生回数</th>
                  <th className="px-4 py-2.5 text-left font-medium hidden md:table-cell">最終発生</th>
                  <th className="px-4 py-2.5 text-right font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {candidates.map((c, i) => (
                  <tr key={i} className="hover:bg-[#111827] transition-colors">
                    <td className="px-4 py-2.5 font-mono text-xs text-[#e2e8f4] max-w-[200px] truncate">
                      {c.rule_name || '—'}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-[#7d92b0] font-mono">
                      {c.hostname || '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span className="text-yellow-400 font-bold text-sm">{c.count}</span>
                      <span className="text-[#3d5068] text-xs">件</span>
                    </td>
                    <td className="px-4 py-2.5 hidden md:table-cell text-xs text-[#3d5068]">
                      {c.last_seen ? formatDistanceToNow(parseISO(c.last_seen), { addSuffix: true, locale: ja }) : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <Link
                        href={`/suppressions?rule=${encodeURIComponent(c.rule_name)}&hostname=${encodeURIComponent(c.hostname)}`}
                        className="inline-flex items-center gap-1 text-xs text-yellow-400 hover:text-yellow-300 transition-colors"
                      >
                        抑制ルール作成
                        <ArrowRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
