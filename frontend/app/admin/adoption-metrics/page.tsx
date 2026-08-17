'use client'

import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import {
  Monitor, AlertTriangle, Shield, Globe, TrendingUp,
  CheckCircle2, RefreshCw, Siren,
} from 'lucide-react'

interface AdoptionMetrics {
  agents: { total: number; online: number; offline: number }
  alerts: { total: number; open: number; critical: number; weekly_new: number; weekly_resolved: number }
  incidents: { active: number }
  darkweb: { findings: number }
  rules: { yara_total: number; yara_enabled: number; sigma_total: number; sigma_enabled: number }
  alert_trend: { date: string; count: number }[]
}

function StatCard({
  icon: Icon, label, value, sub, color = '#e8002d', href,
}: {
  icon: React.ElementType; label: string; value: number | string
  sub?: string; color?: string; href?: string
}) {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-4 h-4" style={{ color }} />
        <span className="text-xs text-falcon-subtle">{label}</span>
      </div>
      <p className="text-3xl font-bold text-white tabular-nums" style={{ color }}>{value}</p>
      {sub && <p className="text-xs text-falcon-subtle mt-1">{sub}</p>}
    </div>
  )
}

export default function AdoptionMetricsPage() {
  const { data, isLoading, isError, refetch, isFetching } = useQuery<AdoptionMetrics>({
    queryKey: ['adoption-metrics'],
    queryFn: () => apiFetch('/api/v1/admin/adoption-metrics'),
    refetchInterval: 120_000,
  })

  const onlineRate = data
    ? data.agents.total > 0
      ? Math.round(data.agents.online / data.agents.total * 100)
      : 0
    : 0

  const resolveRate = data
    ? data.alerts.weekly_new > 0
      ? Math.round(data.alerts.weekly_resolved / data.alerts.weekly_new * 100)
      : 0
    : 0

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-falcon-red/10 rounded-lg border border-falcon-red/20">
            <TrendingUp className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">利用状況ダッシュボード</h1>
            <p className="text-xs text-falcon-subtle mt-0.5">プロダクト採用状況・セキュリティ運用メトリクス</p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-falcon-muted
                     bg-falcon-surface border border-falcon-border rounded-lg hover:bg-falcon-active transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />
          更新
        </button>
      </div>

      {isError && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-falcon-red/10 border border-falcon-red/30 text-sm text-falcon-red">
          データの取得に失敗しました
        </div>
      )}

      {/* エンドポイント統計 */}
      <h2 className="text-sm font-semibold text-falcon-muted mb-3 flex items-center gap-2">
        <Monitor className="w-4 h-4" /> エンドポイント
      </h2>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <StatCard icon={Monitor} label="総エンドポイント数" value={data?.agents.total ?? '—'} color="#1a6bff" />
        <StatCard icon={CheckCircle2} label="オンライン" value={data?.agents.online ?? '—'}
          sub={`オンライン率 ${onlineRate}%`} color="#00c853" />
        <StatCard icon={Monitor} label="オフライン" value={data?.agents.offline ?? '—'}
          color={data?.agents.offline ? '#ff9800' : '#3d5068'} />
        <StatCard icon={Shield} label="有効YARAルール"
          value={data ? `${data.rules.yara_enabled} / ${data.rules.yara_total}` : '—'}
          sub={`Sigma: ${data?.rules.sigma_enabled ?? '—'} 有効`} color="#aa55ff" />
      </div>

      {/* アラート統計 */}
      <h2 className="text-sm font-semibold text-falcon-muted mb-3 flex items-center gap-2">
        <AlertTriangle className="w-4 h-4" /> アラート・インシデント
      </h2>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        <StatCard icon={AlertTriangle} label="未対応アラート" value={data?.alerts.open ?? '—'}
          color={data?.alerts.open ? '#e8002d' : '#3d5068'} />
        <StatCard icon={Siren} label="Critical アラート" value={data?.alerts.critical ?? '—'}
          color={data?.alerts.critical ? '#e8002d' : '#3d5068'} />
        <StatCard icon={AlertTriangle} label="今週の新規アラート" value={data?.alerts.weekly_new ?? '—'}
          sub={`解決率 ${resolveRate}%`} color="#ff9800" />
        <StatCard icon={Siren} label="アクティブインシデント" value={data?.incidents.active ?? '—'}
          color={data?.incidents.active ? '#ff9800' : '#3d5068'} />
      </div>

      {/* アラートトレンドグラフ */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 mb-6">
        <h3 className="text-sm font-medium text-falcon-text mb-4">直近7日間のアラート数推移</h3>
        {isLoading ? (
          <div className="h-40 flex items-center justify-center text-falcon-subtle">
            <RefreshCw className="w-5 h-5 animate-spin" />
          </div>
        ) : data?.alert_trend.length === 0 ? (
          <div className="h-40 flex items-center justify-center text-falcon-subtle text-sm">
            データなし（7日以内のアラートがありません）
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={data?.alert_trend ?? []} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" />
              <XAxis dataKey="date" tick={{ fill: '#3d5068', fontSize: 11 }} axisLine={false} />
              <YAxis tick={{ fill: '#3d5068', fontSize: 11 }} axisLine={false} />
              <Tooltip
                contentStyle={{ background: '#0d1220', border: '1px solid #1e2d42', borderRadius: 8 }}
                labelStyle={{ color: '#7d92b0' }}
                itemStyle={{ color: '#e8002d' }}
              />
              <Bar dataKey="count" name="アラート数" fill="#e8002d" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* ダークウェブ & ルール */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-medium text-falcon-muted mb-3 flex items-center gap-2">
            <Globe className="w-4 h-4 text-purple-400" />
            ダークウェブ監視
          </h3>
          <p className="text-3xl font-bold text-purple-400">{data?.darkweb.findings ?? '—'}</p>
          <p className="text-xs text-falcon-subtle mt-1">累計検知件数（被害者リスト掲載確認）</p>
          {data?.darkweb.findings ? (
            <p className="text-xs text-red-400 mt-2">
              ⚠ {data.darkweb.findings}件の検知があります — アラートを確認してください
            </p>
          ) : (
            <p className="text-xs text-green-400 mt-2">✓ 現時点で被害者リストへの掲載なし</p>
          )}
        </div>

        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <h3 className="text-sm font-medium text-falcon-muted mb-3 flex items-center gap-2">
            <Shield className="w-4 h-4 text-falcon-red" />
            検知ルール統計
          </h3>
          <div className="space-y-2">
            {[
              { label: 'YARAルール', total: data?.rules.yara_total ?? 0, enabled: data?.rules.yara_enabled ?? 0, color: '#aa55ff' },
              { label: 'Sigmaルール', total: data?.rules.sigma_total ?? 0, enabled: data?.rules.sigma_enabled ?? 0, color: '#1a6bff' },
            ].map(({ label, total, enabled, color }) => (
              <div key={label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-falcon-muted">{label}</span>
                  <span className="text-xs text-falcon-subtle">{enabled} / {total} 有効</span>
                </div>
                <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${total > 0 ? Math.round(enabled/total*100) : 0}%`, backgroundColor: color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
