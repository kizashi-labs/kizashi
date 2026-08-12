'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { format, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import {
  KeyRound, ShieldCheck, ShieldX, Users, Monitor,
  TrendingUp, AlertTriangle, CheckCircle2, XCircle,
  Clock, Search, Download
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid, Legend
} from 'recharts'
import { apiFetch } from '@/lib/api'

const TIME_RANGES = [
  { label: '1時間',  hours: 1 },
  { label: '6時間',  hours: 6 },
  { label: '24時間', hours: 24 },
  { label: '7日間',  hours: 168 },
  { label: '30日間', hours: 720 },
]

interface AuthStats {
  total: number
  success: number
  failure: number
  top_users: { username: string; count: number; failures: number }[]
  top_agents: { agent_id: string; hostname: string; count: number }[]
  hourly: { hour: string; success: number; failure: number }[]
  recent: {
    id: string
    timestamp: string
    agent_id: string
    hostname: string
    username: string
    outcome: string
    logon_type: string
  }[]
}

function StatCard({ label, value, sub, icon: Icon, color }: {
  label: string; value: number; sub?: string
  icon: React.ElementType; color: string
}) {
  return (
    <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
        <Icon className="w-5 h-5 text-white" />
      </div>
      <div>
        <p className="text-xs text-[#8899aa]">{label}</p>
        <p className="text-2xl font-bold text-white">{value.toLocaleString()}</p>
        {sub && <p className="text-xs text-[#5a6a7a]">{sub}</p>}
      </div>
    </div>
  )
}

export default function AuthEventsPage() {
  const [hours, setHours] = useState(24)
  const [outcomeFilter, setOutcomeFilter] = useState<'all' | 'success' | 'failure'>('all')
  const [userSearch, setUserSearch] = useState('')

  const { data, isLoading } = useQuery<AuthStats>({
    queryKey: ['auth-stats', hours],
    queryFn: () => apiFetch(`/api/v1/events/auth-stats?hours=${hours}`),
    refetchInterval: 60_000,
  })

  const successRate = data && data.total > 0
    ? Math.round((data.success / data.total) * 100)
    : 0

  const recent = (data?.recent ?? []).filter(e =>
    (outcomeFilter === 'all' || e.outcome === outcomeFilter) &&
    (!userSearch || e.username?.toLowerCase().includes(userSearch.toLowerCase()) ||
      (e.hostname ?? '').toLowerCase().includes(userSearch.toLowerCase()))
  )

  function exportCSV() {
    const rows = recent.map(e => [
      e.timestamp, e.hostname || e.agent_id, e.username, e.logon_type || '', e.outcome,
    ])
    const headers = ['timestamp', 'hostname', 'username', 'logon_type', 'outcome']
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `auth-events-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const chartData = (data?.hourly ?? []).map(h => ({
    ...h,
    label: h.hour.length >= 13 ? h.hour.slice(5, 13).replace('T', ' ') : h.hour,
  }))

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-indigo-600 rounded-lg flex items-center justify-center">
            <KeyRound className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">認証イベント分析</h1>
            <p className="text-sm text-[#8899aa]">ログイン試行・成功・失敗の監視</p>
          </div>
        </div>
        <div className="flex gap-2">
          {TIME_RANGES.map(r => (
            <button
              key={r.hours}
              onClick={() => setHours(r.hours)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                hours === r.hours
                  ? 'bg-indigo-600 text-white'
                  : 'bg-[#111827] text-[#8899aa] hover:bg-[#19253d]'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-20">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : (
        <>
          {/* Stat cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="総認証イベント" value={data?.total ?? 0}
              icon={KeyRound} color="bg-indigo-600" />
            <StatCard label="成功" value={data?.success ?? 0}
              sub={`成功率 ${successRate}%`}
              icon={ShieldCheck} color="bg-green-600" />
            <StatCard label="失敗" value={data?.failure ?? 0}
              sub={data && data.total > 0 ? `${Math.round((data.failure / data.total) * 100)}%` : ''}
              icon={ShieldX} color="bg-[#e8002d]" />
            <StatCard label="ユーザー数" value={data?.top_users.length ?? 0}
              icon={Users} color="bg-[#1a6bff]" />
          </div>

          {/* Brute force warning */}
          {data && data.failure > 20 && data.total > 0 && (data.failure / data.total) > 0.3 && (
            <div className="flex items-center gap-3 px-4 py-3 bg-red-900/30 border border-red-700 rounded-xl text-red-300">
              <AlertTriangle className="w-5 h-5 flex-shrink-0" />
              <div>
                <span className="font-semibold">ブルートフォース攻撃の可能性</span>
                <span className="text-sm ml-2">
                  失敗率が {Math.round((data.failure / data.total) * 100)}% と高い水準にあります。
                  アカウントロックポリシーを確認してください。
                </span>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Hourly chart */}
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp className="w-4 h-4 text-indigo-400" />
                <h2 className="text-sm font-semibold text-white">認証イベント推移</h2>
              </div>
              {chartData.length === 0 ? (
                <div className="h-48 flex items-center justify-center text-[#5a6a7a] text-sm">データなし</div>
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" />
                    <XAxis dataKey="label" tick={{ fill: '#8899aa', fontSize: 10 }} />
                    <YAxis tick={{ fill: '#8899aa', fontSize: 10 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#111827', border: '1px solid #1e2d42', borderRadius: 8 }}
                      labelStyle={{ color: '#fff' }}
                    />
                    <Legend />
                    <Line type="monotone" dataKey="success" stroke="#10B981" name="成功" strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="failure" stroke="#EF4444" name="失敗" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Top users */}
            <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5">
              <div className="flex items-center gap-2 mb-4">
                <Users className="w-4 h-4 text-blue-400" />
                <h2 className="text-sm font-semibold text-white">上位ユーザー</h2>
              </div>
              {(data?.top_users ?? []).length === 0 ? (
                <div className="h-48 flex items-center justify-center text-[#5a6a7a] text-sm">データなし</div>
              ) : (
                <div className="space-y-2">
                  {(data?.top_users ?? []).slice(0, 8).map(u => {
                    const failRate = u.count > 0 ? Math.round((u.failures / u.count) * 100) : 0
                    return (
                      <div key={u.username} className="flex items-center gap-3">
                        <span className="text-sm text-[#8899aa] font-mono w-36 truncate">{u.username}</span>
                        <div className="flex-1 bg-[#161f33] rounded-full h-2 overflow-hidden">
                          <div className="h-full flex">
                            <div
                              className="bg-green-500 h-full"
                              style={{ width: `${100 - failRate}%` }}
                            />
                            <div
                              className="bg-red-500 h-full"
                              style={{ width: `${failRate}%` }}
                            />
                          </div>
                        </div>
                        <span className="text-xs text-[#8899aa] w-10 text-right">{u.count}</span>
                        {u.failures > 0 && (
                          <span className="text-xs text-red-400 w-16 text-right">{u.failures}失敗</span>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Top agents */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5">
            <div className="flex items-center gap-2 mb-4">
              <Monitor className="w-4 h-4 text-purple-400" />
              <h2 className="text-sm font-semibold text-white">上位エンドポイント（認証イベント数）</h2>
            </div>
            {(data?.top_agents ?? []).length === 0 ? (
              <div className="py-6 text-center text-[#5a6a7a] text-sm">データなし</div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={(data?.top_agents ?? []).slice(0, 8)} layout="vertical">
                  <XAxis type="number" tick={{ fill: '#8899aa', fontSize: 10 }} />
                  <YAxis type="category" dataKey="hostname" tick={{ fill: '#8899aa', fontSize: 11 }} width={120} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #1e2d42', borderRadius: 8 }}
                    labelStyle={{ color: '#fff' }}
                  />
                  <Bar dataKey="count" fill="#818CF8" name="イベント数" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Recent events table */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#8899aa]" />
                <h2 className="text-sm font-semibold text-white">直近の認証イベント</h2>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
                  <input
                    value={userSearch}
                    onChange={e => setUserSearch(e.target.value)}
                    placeholder="ユーザー・ホスト検索..."
                    className="pl-8 pr-3 py-1 text-xs border border-[#1e2d42] rounded-lg
                               bg-[#161f33] text-white placeholder-[#5a6a7a] w-40
                               focus:outline-none focus:border-indigo-500"
                  />
                </div>
                {(['all', 'success', 'failure'] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setOutcomeFilter(f)}
                    className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors ${
                      outcomeFilter === f
                        ? 'bg-indigo-600 text-white'
                        : 'bg-[#161f33] text-[#8899aa] hover:bg-[#1d2f4a]'
                    }`}
                  >
                    {f === 'all' ? 'すべて' : f === 'success' ? '成功' : '失敗'}
                  </button>
                ))}
                <button
                  onClick={exportCSV}
                  disabled={recent.length === 0}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs border border-[#1e2d42]
                             text-[#8899aa] rounded-lg hover:bg-[#1d2f4a] disabled:opacity-40 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />CSV
                </button>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] text-xs text-[#8899aa]">
                    <th className="px-4 py-3 text-left">日時</th>
                    <th className="px-4 py-3 text-left">エンドポイント</th>
                    <th className="px-4 py-3 text-left">ユーザー</th>
                    <th className="px-4 py-3 text-left">ログオン種別</th>
                    <th className="px-4 py-3 text-left">結果</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-[#5a6a7a]">データなし</td>
                    </tr>
                  ) : recent.slice(0, 50).map(e => (
                    <tr key={e.id} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33]/30">
                      <td className="px-4 py-2.5 text-[#8899aa] font-mono text-xs whitespace-nowrap">
                        {e.timestamp ? format(parseISO(e.timestamp), 'MM/dd HH:mm:ss', { locale: ja }) : '-'}
                      </td>
                      <td className="px-4 py-2.5 text-[#8899aa]">{e.hostname || e.agent_id}</td>
                      <td className="px-4 py-2.5 font-mono text-[#e2e8f4]">{e.username}</td>
                      <td className="px-4 py-2.5 text-[#8899aa]">{e.logon_type || '-'}</td>
                      <td className="px-4 py-2.5">
                        {e.outcome === 'success' ? (
                          <span className="flex items-center gap-1 text-green-400 text-xs">
                            <CheckCircle2 className="w-3.5 h-3.5" />成功
                          </span>
                        ) : e.outcome === 'failure' ? (
                          <span className="flex items-center gap-1 text-red-400 text-xs">
                            <XCircle className="w-3.5 h-3.5" />失敗
                          </span>
                        ) : (
                          <span className="text-[#5a6a7a] text-xs">{e.outcome || '-'}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
