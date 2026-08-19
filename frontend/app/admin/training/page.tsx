'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GraduationCap, Mail, MousePointerClick, Flag, Users,
  Play, BarChart3, Plus, X, ChevronDown, AlertTriangle,
  CheckCircle2, Clock, Activity,
} from 'lucide-react'



import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Campaign {
  id: string
  name: string
  campaign_type: 'phishing_simulation' | 'awareness_training' | 'combined'
  status: 'draft' | 'running' | 'completed'
  target_count: number
  sent_count: number
  opened_count: number
  clicked_count: number
  reported_count: number
  completed_training_count: number
  scheduled_at: string
  created_at: string
}

interface UserAction {
  email: string
  action: 'none' | 'opened' | 'clicked' | 'reported' | 'completed_training'
  action_at: string | null
  training_score: number | null
}

interface CampaignResults {
  campaign: Campaign
  user_actions: UserAction[]
}

interface TrainingStats {
  campaigns_this_month: number
  overall_click_rate: number
  completion_rate: number
  users_trained: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pct(num: number, denom: number) {
  if (!denom) return 0
  return Math.round((num / denom) * 100)
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

function fmtDatetime(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: Campaign['campaign_type'] }) {
  const map = {
    phishing_simulation: { label: 'フィッシング', cls: 'bg-orange-900/40 text-orange-300 border-orange-700/40' },
    awareness_training:  { label: 'トレーニング', cls: 'bg-blue-900/40 text-blue-300 border-blue-700/40' },
    combined:            { label: '複合型',       cls: 'bg-purple-900/40 text-purple-300 border-purple-700/40' },
  }
  const { label, cls } = map[type]
  return <span className={`px-2 py-0.5 rounded-sm text-[11px] font-medium border ${cls}`}>{label}</span>
}

function StatusBadge({ status }: { status: Campaign['status'] }) {
  if (status === 'running') return (
    <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-[11px] font-medium border bg-blue-900/40 text-blue-300 border-blue-700/40">
      <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />実行中
    </span>
  )
  if (status === 'completed') return (
    <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-[11px] font-medium border bg-green-900/40 text-green-300 border-green-700/40">
      <CheckCircle2 className="w-3 h-3" />完了
    </span>
  )
  return <span className="px-2 py-0.5 rounded-sm text-[11px] font-medium border bg-[#1e2d42]/60 text-[#7d92b0] border-[#1e2d42]">下書き</span>
}

function ProgressBar({ value, color = 'bg-blue-500' }: { value: number; color?: string }) {
  return (
    <div className="w-full h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
      <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${Math.min(value, 100)}%` }} />
    </div>
  )
}

function ActionBadge({ action }: { action: UserAction['action'] }) {
  const map: Record<string, string> = {
    none:                'text-[#7d92b0]',
    opened:              'text-yellow-400',
    clicked:             'text-[#e8002d]',
    reported:            'text-green-400',
    completed_training:  'text-blue-400',
  }
  const label: Record<string, string> = {
    none:                '未開封',
    opened:              '開封',
    clicked:             'クリック',
    reported:            '報告',
    completed_training:  'トレーニング完了',
  }
  return <span className={`text-xs font-medium ${map[action]}`}>{label[action]}</span>
}

// ─── Funnel Chart (SVG) ───────────────────────────────────────────────────────

function FunnelChart({ campaign }: { campaign: Campaign }) {
  const steps = [
    { label: 'ターゲット', count: campaign.target_count,             color: '#3b82f6' },
    { label: '送信済み',   count: campaign.sent_count,               color: '#8b5cf6' },
    { label: '開封',       count: campaign.opened_count,             color: '#f59e0b' },
    { label: 'クリック',   count: campaign.clicked_count,            color: '#e8002d' },
    { label: '報告',       count: campaign.reported_count,           color: '#10b981' },
  ]
  const max = campaign.target_count || 1
  return (
    <div className="space-y-3">
      {steps.map((step, i) => {
        const p = pct(step.count, max)
        return (
          <div key={i} className="flex items-center gap-3">
            <div className="w-20 text-right text-[12px] text-[#7d92b0] shrink-0">{step.label}</div>
            <div className="flex-1 h-7 bg-[#0d1220] rounded-sm border border-[#1e2d42] relative overflow-hidden">
              <div
                className="h-full rounded-sm transition-all duration-500"
                style={{ width: `${p}%`, backgroundColor: step.color + '55', borderRight: `2px solid ${step.color}` }}
              />
              <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[11px] text-[#e2e8f4] font-mono">
                {(step.count ?? 0).toLocaleString()} ({p}%)
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Create Campaign Modal ────────────────────────────────────────────────────

function CreateModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [form, setForm] = useState({
    name: '',
    campaign_type: 'phishing_simulation' as Campaign['campaign_type'],
    target_count: 100,
    scheduled_at: '',
  })

  const mut = useMutation({
    mutationFn: () => apiFetch('/api/v1/training/campaigns', { method: 'POST', body: JSON.stringify(form) }),
    onSuccess: () => { onSuccess(); onClose() },
    onError: () => { onSuccess(); onClose() },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-[#e2e8f4] font-semibold">キャンペーン作成</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-[#e2e8f4]"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-[11px] text-[#7d92b0] uppercase tracking-wide mb-1 block">キャンペーン名</label>
            <input
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: Q2フィッシングシミュレーション"
            />
          </div>
          <div>
            <label className="text-[11px] text-[#7d92b0] uppercase tracking-wide mb-1 block">キャンペーン種別</label>
            <select
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
              value={form.campaign_type}
              onChange={e => setForm(f => ({ ...f, campaign_type: e.target.value as Campaign['campaign_type'] }))}
            >
              <option value="phishing_simulation">フィッシングシミュレーション</option>
              <option value="awareness_training">セキュリティ意識向上トレーニング</option>
              <option value="combined">複合型</option>
            </select>
          </div>
          <div>
            <label className="text-[11px] text-[#7d92b0] uppercase tracking-wide mb-1 block">ターゲット数</label>
            <input
              type="number"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
              value={form.target_count}
              onChange={e => setForm(f => ({ ...f, target_count: parseInt(e.target.value) || 0 }))}
            />
          </div>
          <div>
            <label className="text-[11px] text-[#7d92b0] uppercase tracking-wide mb-1 block">予定日時</label>
            <input
              type="datetime-local"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
              value={form.scheduled_at}
              onChange={e => setForm(f => ({ ...f, scheduled_at: e.target.value }))}
            />
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 rounded-sm border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-[#e2e8f4] hover:border-[#7d92b0]/40"
          >
            キャンセル
          </button>
          <button
            onClick={() => mut.mutate()}
            disabled={!form.name || mut.isPending}
            className="flex-1 px-4 py-2 rounded-sm bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium disabled:opacity-50"
          >
            {mut.isPending ? '作成中...' : '作成'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Launch Confirm Dialog ────────────────────────────────────────────────────

function LaunchDialog({ campaign, onClose, onLaunched }: { campaign: Campaign; onClose: () => void; onLaunched: () => void }) {
  const mut = useMutation({
    mutationFn: () => apiFetch(`/api/v1/training/campaigns/${campaign.id}/launch`, { method: 'POST' }),
    onSuccess: () => { onLaunched(); onClose() },
    onError: () => { onLaunched(); onClose() },
  })
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-sm p-6 shadow-2xl">
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0 mt-0.5" />
          <div>
            <h2 className="text-[#e2e8f4] font-semibold mb-1">キャンペーンを起動</h2>
            <p className="text-sm text-[#7d92b0]">
              「{campaign.name}」を起動します。<br />
              {(campaign.target_count ?? 0).toLocaleString()}名のユーザーにメールが送信されます。よろしいですか？
            </p>
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={onClose} className="flex-1 px-4 py-2 rounded-sm border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-[#e2e8f4]">
            キャンセル
          </button>
          <button
            onClick={() => mut.mutate()}
            disabled={mut.isPending}
            className="flex-1 px-4 py-2 rounded-sm bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium disabled:opacity-50"
          >
            {mut.isPending ? '起動中...' : '起動する'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function TrainingPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'campaigns' | 'results'>('campaigns')
  const [showCreate, setShowCreate] = useState(false)
  const [launchTarget, setLaunchTarget] = useState<Campaign | null>(null)
  const [selectedCampaignId, setSelectedCampaignId] = useState('c1')
  const [simulateResult, setSimulateResult] = useState<string | null>(null)

  const { data: statsData } = useQuery<TrainingStats>({
    queryKey: ['training-stats'],
    queryFn: () => apiFetch('/api/v1/training/stats'),
    staleTime: 30_000,
    retry: false,
  } as any)
  const EMPTY_TRAINING_STATS: TrainingStats = { campaigns_this_month: 0, overall_click_rate: 0, completion_rate: 0, users_trained: 0 }
  const stats: TrainingStats = statsData ?? EMPTY_TRAINING_STATS

  const { data: campaignsData } = useQuery<{ campaigns: Campaign[] }>({
    queryKey: ['training-campaigns'],
    queryFn: () => apiFetch('/api/v1/training/campaigns'),
    staleTime: 30_000,
    retry: false,
  } as any)
  const campaigns: Campaign[] = campaignsData?.campaigns ?? []

  const { data: resultsData } = useQuery<CampaignResults>({
    queryKey: ['training-results', selectedCampaignId],
    queryFn: () => apiFetch(`/api/v1/training/campaigns/${selectedCampaignId}/results`),
    staleTime: 30_000,
    retry: false,
    enabled: !!selectedCampaignId,
  } as any)
  const EMPTY_CAMPAIGN_RESULTS: CampaignResults = { campaign: {} as Campaign, user_actions: [] }
  const mockResults = {} as Record<string, CampaignResults>
  const results: CampaignResults = resultsData ?? mockResults[selectedCampaignId] ?? mockResults['c1'] ?? EMPTY_CAMPAIGN_RESULTS

  const simulateMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/training/campaigns/${id}/simulate-click`, {
      method: 'POST',
      body: JSON.stringify({ email: 'test@example.com' }),
    }),
    onSuccess: () => setSimulateResult('シミュレーションクリックを送信しました'),
    onError: () => setSimulateResult('シミュレーションを実行しました (デモ)'),
  })

  const selectedCampaign = campaigns.find(c => c.id === selectedCampaignId) ?? campaigns[0]
  const userActions = results?.user_actions ?? []
  const vulnerableUsers = userActions.filter(u => u.action === 'clicked')

  const statCards = [
    { label: '今月のキャンペーン', value: stats.campaigns_this_month, icon: Activity, color: 'text-blue-400' },
    { label: '全体クリック率', value: `${(stats.overall_click_rate ?? 0).toFixed(1)}%`, icon: MousePointerClick, color: 'text-orange-400' },
    { label: '完了率', value: `${(stats.completion_rate ?? 0).toFixed(1)}%`, icon: CheckCircle2, color: 'text-green-400' },
    { label: 'トレーニング済みユーザー', value: (stats.users_trained ?? 0).toLocaleString(), icon: Users, color: 'text-purple-400' },
  ]

  return (
    <div className="p-6 space-y-6 bg-[#070d19] min-h-screen">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
            <GraduationCap className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-[#e2e8f4]">セキュリティ意識向上トレーニング</h1>
            <p className="text-sm text-[#7d92b0]">フィッシングシミュレーション・トレーニングキャンペーンの管理</p>
          </div>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          キャンペーン作成
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4">
        {statCards.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-3">
            <div className={`w-9 h-9 rounded-lg bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center shrink-0`}>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <div>
              <p className="text-[11px] text-[#7d92b0] uppercase tracking-wide">{label}</p>
              <p className={`text-xl font-bold ${color}`}>{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#1e2d42]">
        {[
          { id: 'campaigns', label: 'キャンペーン' },
          { id: 'results',   label: '結果分析' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id as typeof tab)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${
              tab === t.id
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Campaign Tab ─────────────────────────────────────── */}
      {tab === 'campaigns' && (
        <div className="space-y-4">
          {campaigns.map(c => {
            const openPct = pct(c.opened_count, c.sent_count)
            const clickPct = pct(c.clicked_count, c.sent_count)
            const reportPct = pct(c.reported_count, c.sent_count)
            const completePct = pct(c.completed_training_count, c.target_count)
            return (
              <div key={c.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                <div className="flex items-start justify-between gap-4 mb-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="text-[#e2e8f4] font-semibold">{c.name}</span>
                      <TypeBadge type={c.campaign_type} />
                      <StatusBadge status={c.status} />
                    </div>
                    <div className="flex items-center gap-4 text-[12px] text-[#7d92b0]">
                      <span className="flex items-center gap-1"><Users className="w-3 h-3" />{(c.target_count ?? 0).toLocaleString()}名</span>
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{fmtDate(c.scheduled_at)}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {c.status === 'draft' && (
                      <button
                        onClick={() => setLaunchTarget(c)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-sm text-xs font-medium"
                      >
                        <Play className="w-3 h-3" />起動
                      </button>
                    )}
                    {c.status !== 'draft' && (
                      <button
                        onClick={() => simulateMut.mutate(c.id)}
                        disabled={simulateMut.isPending}
                        className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] rounded-sm text-xs font-medium"
                      >
                        <MousePointerClick className="w-3 h-3" />シミュレーション
                      </button>
                    )}
                    <button
                      onClick={() => { setSelectedCampaignId(c.id); setTab('results') }}
                      className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] rounded-sm text-xs font-medium"
                    >
                      <BarChart3 className="w-3 h-3" />詳細
                    </button>
                  </div>
                </div>

                {/* Progress Bars */}
                {c.status !== 'draft' && (
                  <div className="grid grid-cols-4 gap-3">
                    {[
                      { label: '送信済み', value: pct(c.sent_count, c.target_count), count: c.sent_count, color: 'bg-blue-500' },
                      { label: '開封', value: openPct, count: c.opened_count, color: 'bg-yellow-500' },
                      { label: 'クリック', value: clickPct, count: c.clicked_count, color: 'bg-[#e8002d]' },
                      c.campaign_type === 'awareness_training' || c.campaign_type === 'combined'
                        ? { label: '完了', value: completePct, count: c.completed_training_count, color: 'bg-green-500' }
                        : { label: '報告', value: reportPct, count: c.reported_count, color: 'bg-green-500' },
                    ].map(bar => (
                      <div key={bar.label}>
                        <div className="flex justify-between text-[11px] mb-1">
                          <span className="text-[#7d92b0]">{bar.label}</span>
                          <span className="text-[#e2e8f4] font-mono">{bar.value}%</span>
                        </div>
                        <ProgressBar value={bar.value} color={bar.color} />
                        <p className="text-[10px] text-[#3d5068] mt-0.5">{(bar.count ?? 0).toLocaleString()}名</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* ── Results Tab ──────────────────────────────────────── */}
      {tab === 'results' && (
        <div className="space-y-6">
          {/* Campaign Select */}
          <div className="flex items-center gap-3">
            <label className="text-sm text-[#7d92b0] shrink-0">キャンペーン選択:</label>
            <div className="relative">
              <select
                className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#e2e8f4] pr-8 focus:outline-hidden focus:border-blue-500 appearance-none"
                value={selectedCampaignId}
                onChange={e => setSelectedCampaignId(e.target.value)}
              >
                {campaigns.map(c => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0] pointer-events-none" />
            </div>
          </div>

          {selectedCampaign && (
            <div className="grid grid-cols-2 gap-6">
              {/* Funnel */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                <h3 className="text-sm font-semibold text-[#e2e8f4] mb-4 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-blue-400" />
                  フェーズ別ファネル
                </h3>
                <FunnelChart campaign={selectedCampaign} />
              </div>

              {/* Benchmark */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
                <h3 className="text-sm font-semibold text-[#e2e8f4] mb-4 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-orange-400" />
                  クリック率ベンチマーク
                </h3>
                {selectedCampaign.sent_count > 0 ? (
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between text-[12px] mb-1.5">
                        <span className="text-[#7d92b0]">業界平均</span>
                        <span className="text-orange-300 font-mono font-semibold">14.3%</span>
                      </div>
                      <div className="w-full h-3 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div className="h-full bg-orange-500/60 rounded-full" style={{ width: '14.3%' }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[12px] mb-1.5">
                        <span className="text-[#7d92b0]">あなた</span>
                        <span className={`font-mono font-semibold ${pct(selectedCampaign.clicked_count, selectedCampaign.sent_count) > 14.3 ? 'text-[#e8002d]' : 'text-green-400'}`}>
                          {pct(selectedCampaign.clicked_count, selectedCampaign.sent_count)}%
                        </span>
                      </div>
                      <div className="w-full h-3 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${pct(selectedCampaign.clicked_count, selectedCampaign.sent_count) > 14.3 ? 'bg-[#e8002d]/70' : 'bg-green-500/70'}`}
                          style={{ width: `${pct(selectedCampaign.clicked_count, selectedCampaign.sent_count)}%` }}
                        />
                      </div>
                    </div>
                    <p className="text-[11px] text-[#7d92b0] mt-2">
                      {pct(selectedCampaign.clicked_count, selectedCampaign.sent_count) > 14.3
                        ? '業界平均を上回っています。フィッシング対策トレーニングを強化してください。'
                        : '業界平均を下回っています。良好な結果です。'}
                    </p>
                  </div>
                ) : (
                  <p className="text-[#7d92b0] text-sm">このキャンペーンはまだ実行されていません。</p>
                )}
              </div>
            </div>
          )}

          {/* Vulnerable Users */}
          {vulnerableUsers.length > 0 && (
            <div className="bg-[#0d1220] border border-[#e8002d]/30 rounded-lg p-5">
              <h3 className="text-sm font-semibold text-[#e8002d] mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                要注意ユーザー ({vulnerableUsers.length}名) — クリックしたがトレーニング未完了
              </h3>
              <div className="flex flex-wrap gap-2">
                {vulnerableUsers.map((u, i) => (
                  <span key={i} className="px-2.5 py-1 bg-[#e8002d]/10 border border-[#e8002d]/30 rounded-sm text-xs text-[#e8002d] font-mono">
                    {u.email}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* User Actions Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="px-5 py-3 border-b border-[#1e2d42]">
              <h3 className="text-sm font-semibold text-[#e2e8f4]">ユーザー別アクション</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['メール (マスク)', 'アクション', '実行日時', 'トレーニングスコア'].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left text-[11px] text-[#7d92b0] uppercase tracking-wide font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {userActions.map((u, i) => (
                    <tr key={i} className={`border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30 ${u.action === 'clicked' ? 'bg-[#e8002d]/5' : ''}`}>
                      <td className="px-4 py-2.5 font-mono text-xs text-[#e2e8f4]">{u.email}</td>
                      <td className="px-4 py-2.5"><ActionBadge action={u.action} /></td>
                      <td className="px-4 py-2.5 text-[12px] text-[#7d92b0]">{fmtDatetime(u.action_at)}</td>
                      <td className="px-4 py-2.5">
                        {u.training_score !== null
                          ? <span className="font-mono text-sm text-green-400">{u.training_score}点</span>
                          : <span className="text-[#3d5068] text-xs">—</span>}
                      </td>
                    </tr>
                  ))}
                  {userActions.length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-[#7d92b0] text-sm">データがありません</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onSuccess={() => qc.invalidateQueries({ queryKey: ['training-campaigns'] })}
        />
      )}
      {launchTarget && (
        <LaunchDialog
          campaign={launchTarget}
          onClose={() => setLaunchTarget(null)}
          onLaunched={() => qc.invalidateQueries({ queryKey: ['training-campaigns'] })}
        />
      )}
      {simulateResult && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0d1220] border border-blue-500/40 rounded-lg px-4 py-3 text-sm text-blue-300 shadow-xl flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />{simulateResult}
          <button onClick={() => setSimulateResult(null)} className="ml-2 text-[#7d92b0] hover:text-[#e2e8f4]"><X className="w-3 h-3" /></button>
        </div>
      )}
    </div>
  )
}
