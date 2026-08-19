'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { TrendingUp, TrendingDown, Minus, RefreshCw, Shield } from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

function scoreColor(score: number) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 30) return 'text-yellow-400'
  return 'text-emerald-400'
}

function scoreBg(score: number) {
  if (score >= 80) return 'bg-red-500/20 border-red-500/30'
  if (score >= 60) return 'bg-orange-500/20 border-orange-500/30'
  if (score >= 30) return 'bg-yellow-500/20 border-yellow-500/30'
  return 'bg-emerald-500/20 border-emerald-500/30'
}

function levelBadge(level: string) {
  const styles: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    low: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
  }
  const labels: Record<string, string> = { critical: '重大', high: '高', medium: '中', low: '低' }
  return <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${styles[level] || ''}`}>{labels[level] || level}</span>
}

function TrendIcon({ trend }: { trend: string }) {
  if (trend === 'increasing') return <TrendingUp className="w-4 h-4 text-red-400" />
  if (trend === 'decreasing') return <TrendingDown className="w-4 h-4 text-emerald-400" />
  return <Minus className="w-4 h-4 text-[#7d92b0]" />
}

export default function RiskScoringPage() {
  const [activeTab, setActiveTab] = useState<'scores' | 'models' | 'trends'>('scores')
  const [entityType, setEntityType] = useState<'endpoint' | 'user' | 'network'>('endpoint')
  const [recalculating, setRecalculating] = useState(false)

  const { data: scoresData = { scores: null } } = useQuery({
    queryKey: ['risk-scores', entityType],
    queryFn: () => apiFetch(`/api/v1/admin/risk-scoring/scores?entity_type=${entityType}`),
  })

  const { data: modelsData = { models: [] } } = useQuery({
    queryKey: ['risk-models'],
    queryFn: () => apiFetch('/api/v1/admin/risk-scoring/models'),
  })

  const { data: orgData = { overall_risk_score: 0, risk_level: '', trend: '', by_entity_type: [] } } = useQuery({
    queryKey: ['risk-org'],
    queryFn: () => apiFetch('/api/v1/admin/risk-scoring/organization'),
  })

  const recalcMutation = useMutation({
    mutationFn: () => apiFetch('/api/v1/admin/risk-scoring/recalculate', { method: 'POST' }),
    onMutate: () => setRecalculating(true),
    onSettled: () => setTimeout(() => setRecalculating(false), 3000),
  })

  const scores = (scoresData as any)?.scores ?? []
  const models = (modelsData as any)?.models ?? []
  const org = (orgData as any) ?? { overall_risk_score: 0, risk_level: '', trend: '', by_entity_type: [] }
  const overallScore = org.overall_risk_score ?? 52.3

  const TABS = [
    { id: 'scores', label: 'スコア一覧' },
    { id: 'models', label: 'モデル管理' },
    { id: 'trends', label: 'トレンド分析' },
  ] as const

  const ENTITY_TYPES = [
    { id: 'endpoint', label: 'エンドポイント' },
    { id: 'user', label: 'ユーザー' },
    { id: 'network', label: 'ネットワーク' },
  ] as const

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      <PageDataUnavailable />
      <PageSaveFailed />
      {recalculating && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-8 flex flex-col items-center gap-4">
            <RefreshCw className="w-10 h-10 text-[#e8002d] animate-spin" />
            <p className="text-white text-lg font-medium">リスクスコア再計算中...</p>
            <p className="text-[#7d92b0] text-sm">全エンティティのスコアを更新しています</p>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-7 h-7 text-[#e8002d]" />
          <div>
            <h1 className="text-2xl font-bold">リスクスコアリングエンジン</h1>
            <p className="text-[#7d92b0] text-sm">エンティティ別リスクスコアの算出・管理</p>
          </div>
        </div>
        <button
          onClick={() => recalcMutation.mutate()}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] rounded-lg text-sm font-medium transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          スコア再計算
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: '総合リスクスコア', value: `${overallScore}/100`, sub: 'medium リスク' },
          { label: 'エンドポイント平均', value: '48.2', sub: '210台監視中' },
          { label: 'ユーザー平均', value: '31.7', sub: '150名監視中' },
          { label: 'クリティカルエンティティ', value: '5', sub: '即時対応必要' },
        ].map((s) => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <p className="text-[#7d92b0] text-xs mb-1">{s.label}</p>
            <p className="text-2xl font-bold text-white">{s.value}</p>
            <p className="text-[#7d92b0] text-xs mt-1">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1 w-fit">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeTab === t.id ? 'bg-[#e8002d] text-white' : 'text-[#7d92b0] hover:text-white'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab: Scores */}
      {activeTab === 'scores' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <div className="flex gap-2 mb-4">
            {ENTITY_TYPES.map((e) => (
              <button
                key={e.id}
                onClick={() => setEntityType(e.id)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${entityType === e.id ? 'bg-[#e8002d] text-white' : 'bg-[#070d19] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}
              >
                {e.label}
              </button>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] text-[#7d92b0] text-xs">
                  <th className="text-left py-2 px-3">エンティティ名</th>
                  <th className="text-left py-2 px-3">スコア</th>
                  <th className="text-left py-2 px-3">リスクレベル</th>
                  <th className="text-left py-2 px-3">前回スコア</th>
                  <th className="text-left py-2 px-3">変化</th>
                  <th className="text-left py-2 px-3">トレンド</th>
                  <th className="text-left py-2 px-3">算出日時</th>
                </tr>
              </thead>
              <tbody>
                {scores.sort((a: any, b: any) => b.score - a.score).map((s: any) => {
                  const delta = s.score - s.previous_score
                  return (
                    <tr key={s.entity_id} className="border-b border-[#1e2d42]/50 hover:bg-[#070d19]/50">
                      <td className="py-3 px-3 font-medium">{s.entity_name}</td>
                      <td className="py-3 px-3">
                        <span className={`text-2xl font-bold ${scoreColor(s.score)}`}>{s.score.toFixed(1)}</span>
                      </td>
                      <td className="py-3 px-3">{levelBadge(s.risk_level)}</td>
                      <td className="py-3 px-3 text-[#7d92b0]">{s.previous_score.toFixed(1)}</td>
                      <td className="py-3 px-3">
                        <span className={delta > 0 ? 'text-red-400' : delta < 0 ? 'text-emerald-400' : 'text-[#7d92b0]'}>
                          {delta > 0 ? '+' : ''}{delta.toFixed(1)}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <TrendIcon trend={s.trend} />
                      </td>
                      <td className="py-3 px-3 text-[#7d92b0] text-xs">{new Date(s.calculated_at).toLocaleTimeString('ja-JP')}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab: Models */}
      {activeTab === 'models' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {models.map((m: any) => (
            <div key={m.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex items-start justify-between mb-3">
                <h3 className="font-semibold text-white">{m.name}</h3>
                {m.active && <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-sm text-xs">稼働中</span>}
              </div>
              <div className="flex gap-2 mb-3">
                <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded-sm text-xs">{m.entity_type}</span>
                <span className="px-2 py-0.5 bg-[#070d19] text-[#7d92b0] border border-[#1e2d42] rounded-sm text-xs">v{m.version}</span>
              </div>
              <p className="text-[#7d92b0] text-xs mb-2">考慮要因:</p>
              <div className="flex flex-wrap gap-1">
                {m.factors.map((f: string) => (
                  <span key={f} className="px-2 py-0.5 bg-[#070d19] border border-[#1e2d42] rounded-sm text-xs text-[#7d92b0]">{f}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab: Trends */}
      {activeTab === 'trends' && (
        <div className="space-y-6">
          {/* 30-day chart */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="font-semibold mb-4">30日間 平均リスクスコア推移</h3>
            <div className="flex items-end gap-1 h-32">
              {([] as { avg_score: number; date: string }[]).map((d, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <div
                    className="w-full rounded-t"
                    style={{
                      height: `${(d.avg_score / 80) * 100}%`,
                      backgroundColor: d.avg_score >= 60 ? '#ef4444' : d.avg_score >= 40 ? '#f59e0b' : '#10b981',
                      opacity: 0.8,
                    }}
                  />
                </div>
              ))}
            </div>
            <div className="flex justify-between text-xs text-[#7d92b0] mt-2">
              <span></span>
              <span></span>
              <span></span>
            </div>
          </div>

          {/* Org risk */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h3 className="font-semibold mb-4">組織全体リスク</h3>
              <div className="flex items-center gap-6">
                <div
                  className="w-28 h-28 rounded-full flex items-center justify-center text-2xl font-bold shrink-0"
                  style={{
                    background: `conic-gradient(#f59e0b ${overallScore * 3.6}deg, #1e2d42 0deg)`,
                  }}
                >
                  <div className="w-20 h-20 rounded-full bg-[#0d1220] flex items-center justify-center">
                    <span className="text-yellow-400">{overallScore}</span>
                  </div>
                </div>
                <div className="space-y-2 flex-1">
                  {org.by_entity_type?.map((e: any) => (
                    <div key={e.type} className="flex items-center justify-between text-sm">
                      <span className="text-[#7d92b0]">{e.type}</span>
                      <span className={`font-bold ${scoreColor(e.avg_score)}`}>{e.avg_score.toFixed(1)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h3 className="font-semibold mb-4">トップリスクエンティティ</h3>
              <div className="space-y-3">
                {org.top_risks?.map((r: any, i: number) => (
                  <div key={i} className={`p-3 rounded-lg border ${scoreBg(r.score)}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-sm">{r.entity}</span>
                      <span className={`text-lg font-bold ${scoreColor(r.score)}`}>{r.score}</span>
                    </div>
                    <p className="text-xs text-[#7d92b0]">{r.reason}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
