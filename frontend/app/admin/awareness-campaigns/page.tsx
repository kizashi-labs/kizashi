'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Megaphone, Plus, X, ChevronRight, Star, StarHalf,
  Users, BookOpen, Video, Mail, Monitor, Gamepad2,
  CheckCircle2, Clock, AlertTriangle, TrendingUp,
  BarChart3, Award, Eye, Calendar, Target,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

type CampaignType = 'email' | 'poster' | 'video' | 'workshop' | 'gamification' | 'all_channel'
type CampaignStatus = 'active' | 'scheduled' | 'completed' | 'draft'
type TargetAudience = 'all' | 'department' | 'role'
type ContentModule = 'phishing' | 'password' | 'social_engineering' | 'device_security' | 'data_handling' | 'incident_reporting'

interface Campaign {
  id: string
  name: string
  campaign_type: CampaignType
  status: CampaignStatus
  start_date: string
  end_date: string
  target_audience: TargetAudience
  enrolled_count: number
  completion_rate: number
  pre_assessment_score: number
  post_assessment_score: number
  objective: string
  content_modules: ContentModule[]
}

interface ModuleCompletion {
  module: ContentModule
  completion_rate: number
  avg_score: number
}

interface CampaignDetail extends Campaign {
  module_completions: ModuleCompletion[]
  top_department: string
  bottom_department: string
  open_rate: number
  click_rate: number
  certificate_count: number
}

interface ContentLibraryItem {
  id: string
  title: string
  type: CampaignType
  duration_minutes: number
  language: string
  last_updated: string
  rating: number
}

// ── Empty defaults ─────────────────────────────────────────────────────────

const EMPTY_DETAIL: CampaignDetail = {
  id: '', name: '', campaign_type: 'email', status: 'draft',
  start_date: '', end_date: '', target_audience: 'all',
  enrolled_count: 0, completion_rate: 0, pre_assessment_score: 0, post_assessment_score: 0,
  objective: '', content_modules: [], module_completions: [],
  top_department: '', bottom_department: '', open_rate: 0, click_rate: 0, certificate_count: 0,
}

// ── Helpers ────────────────────────────────────────────────────────────────

const campaignTypeLabel: Record<CampaignType, string> = {
  email: 'メール',
  poster: 'ポスター',
  video: '動画',
  workshop: 'ワークショップ',
  gamification: 'ゲーミフィケーション',
  all_channel: '全チャネル',
}

const campaignTypeColor: Record<CampaignType, string> = {
  email: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  poster: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  video: 'bg-pink-500/20 text-pink-300 border-pink-500/30',
  workshop: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  gamification: 'bg-green-500/20 text-green-300 border-green-500/30',
  all_channel: 'bg-falcon-red/20 text-falcon-red border-falcon-red/30',
}

const statusLabel: Record<CampaignStatus, string> = {
  active: '実施中',
  scheduled: '予定',
  completed: '完了',
  draft: '下書き',
}

const statusColor: Record<CampaignStatus, string> = {
  active: 'bg-green-500/20 text-green-300 border-green-500/30',
  scheduled: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  completed: 'bg-falcon-muted/20 text-falcon-muted border-falcon-muted/30',
  draft: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
}

const audienceLabel: Record<TargetAudience, string> = {
  all: '全社',
  department: '部署',
  role: '役職',
}

const moduleLabel: Record<ContentModule, string> = {
  phishing: 'フィッシング',
  password: 'パスワード',
  social_engineering: 'ソーシャルエンジニアリング',
  device_security: 'デバイスセキュリティ',
  data_handling: 'データ取り扱い',
  incident_reporting: 'インシデント報告',
}

const ALL_MODULES: ContentModule[] = ['phishing', 'password', 'social_engineering', 'device_security', 'data_handling', 'incident_reporting']

function StarRating({ rating }: { rating: number }) {
  const full = Math.floor(rating)
  const half = rating - full >= 0.5
  return (
    <span className="flex items-center gap-0.5">
      {Array.from({ length: 5 }).map((_, i) => (
        <span key={i} className={i < full ? 'text-amber-400' : i === full && half ? 'text-amber-400/60' : 'text-falcon-border'}>
          ★
        </span>
      ))}
      <span className="text-falcon-muted text-xs ml-1">{rating.toFixed(1)}</span>
    </span>
  )
}

function TypeIcon({ type }: { type: CampaignType }) {
  const cls = 'w-4 h-4'
  switch (type) {
    case 'email': return <Mail className={cls} />
    case 'poster': return <Monitor className={cls} />
    case 'video': return <Video className={cls} />
    case 'workshop': return <Users className={cls} />
    case 'gamification': return <Gamepad2 className={cls} />
    case 'all_channel': return <Megaphone className={cls} />
  }
}

// ── Sub-components ─────────────────────────────────────────────────────────

function CreateModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    name: '',
    campaign_type: 'email' as CampaignType,
    objective: '',
    target_audience: 'all' as TargetAudience,
    start_date: '',
    end_date: '',
    content_modules: [] as ContentModule[],
  })
  const qc = useQueryClient()

  const { mutate, isPending } = useMutation({
    mutationFn: (data: typeof form) => apiFetch('/api/v1/admin/awareness-campaigns', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['awareness-campaigns'] }); onCreated() },
    onError: () => onCreated(),
  })

  const toggleModule = (m: ContentModule) => {
    setForm(f => ({
      ...f,
      content_modules: f.content_modules.includes(m)
        ? f.content_modules.filter(x => x !== m)
        : [...f.content_modules, m],
    }))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-lg">新規キャンペーン作成</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-4 space-y-4 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="text-falcon-muted text-sm mb-1 block">キャンペーン名 *</label>
            <input
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/60"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: フィッシング対策研修 2026"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-falcon-muted text-sm mb-1 block">種別</label>
              <select
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/60"
                value={form.campaign_type}
                onChange={e => setForm(f => ({ ...f, campaign_type: e.target.value as CampaignType }))}
              >
                {(Object.keys(campaignTypeLabel) as CampaignType[]).map(t => (
                  <option key={t} value={t}>{campaignTypeLabel[t]}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-falcon-muted text-sm mb-1 block">対象</label>
              <select
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/60"
                value={form.target_audience}
                onChange={e => setForm(f => ({ ...f, target_audience: e.target.value as TargetAudience }))}
              >
                <option value="all">全社</option>
                <option value="department">部署別</option>
                <option value="role">役職別</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-falcon-muted text-sm mb-1 block">目的</label>
            <textarea
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/60 resize-none"
              rows={2}
              value={form.objective}
              onChange={e => setForm(f => ({ ...f, objective: e.target.value }))}
              placeholder="キャンペーンの目的を入力..."
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-falcon-muted text-sm mb-1 block">開始日</label>
              <input
                type="date"
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/60"
                value={form.start_date}
                onChange={e => setForm(f => ({ ...f, start_date: e.target.value }))}
              />
            </div>
            <div>
              <label className="text-falcon-muted text-sm mb-1 block">終了日</label>
              <input
                type="date"
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/60"
                value={form.end_date}
                onChange={e => setForm(f => ({ ...f, end_date: e.target.value }))}
              />
            </div>
          </div>
          <div>
            <label className="text-falcon-muted text-sm mb-2 block">コンテンツモジュール</label>
            <div className="grid grid-cols-2 gap-2">
              {ALL_MODULES.map(m => (
                <button
                  key={m}
                  onClick={() => toggleModule(m)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-all ${
                    form.content_modules.includes(m)
                      ? 'bg-falcon-red/20 border-falcon-red/50 text-white'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40'
                  }`}
                >
                  {form.content_modules.includes(m) && <CheckCircle2 className="w-3.5 h-3.5 text-falcon-red shrink-0" />}
                  <span>{moduleLabel[m]}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 text-sm text-falcon-muted hover:text-white transition-colors">キャンセル</button>
          <button
            onClick={() => mutate(form)}
            disabled={isPending || !form.name}
            className="px-5 py-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {isPending ? '作成中...' : '作成'}
          </button>
        </div>
      </div>
    </div>
  )
}

function DetailModal({ campaign, onClose }: { campaign: Campaign; onClose: () => void }) {
  const { data } = useQuery<CampaignDetail>({
    queryKey: ['campaign-detail', campaign.id],
    queryFn: () => apiFetch(`/api/v1/admin/awareness-campaigns/${campaign.id}`),
  })
  const detail = (data && 'module_completions' in data) ? data : EMPTY_DETAIL
  const improvement = detail.post_assessment_score - detail.pre_assessment_score

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div>
            <h2 className="text-white font-semibold text-lg">{detail.name}</h2>
            <p className="text-falcon-muted text-sm mt-0.5">{detail.objective}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
          {/* KPIs */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: '受講者数', value: (detail.enrolled_count ?? 0).toLocaleString(), icon: Users },
              { label: '完了率', value: `${detail.completion_rate}%`, icon: CheckCircle2 },
              { label: '証明書発行', value: (detail.certificate_count ?? 0).toLocaleString(), icon: Award },
              { label: '改善率', value: `+${improvement}pt`, icon: TrendingUp },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Icon className="w-3.5 h-3.5 text-falcon-red" />
                  <span className="text-falcon-muted text-xs">{label}</span>
                </div>
                <span className="text-white font-semibold text-lg">{value}</span>
              </div>
            ))}
          </div>

          {/* Module Completions */}
          <div>
            <h3 className="text-white font-medium mb-3 text-sm">モジュール別完了率</h3>
            <div className="space-y-2">
              {detail.module_completions.map(mc => (
                <div key={mc.module} className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-falcon-muted text-sm">{moduleLabel[mc.module]}</span>
                    <div className="flex items-center gap-4 text-xs">
                      <span className="text-falcon-muted">平均スコア: <span className="text-white">{mc.avg_score}点</span></span>
                      <span className="text-white font-medium">{mc.completion_rate}%</span>
                    </div>
                  </div>
                  <div className="h-1.5 bg-falcon-border rounded-full overflow-hidden">
                    <div
                      className="h-full bg-linear-to-r from-falcon-red to-[#ff4d6d] rounded-full"
                      style={{ width: `${mc.completion_rate}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Departments */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] border border-green-500/20 rounded-lg p-3">
              <p className="text-green-400 text-xs mb-1 font-medium">トップ部署</p>
              <p className="text-white font-medium">{detail.top_department}</p>
            </div>
            <div className="bg-[#070d19] border border-amber-500/20 rounded-lg p-3">
              <p className="text-amber-400 text-xs mb-1 font-medium">改善が必要な部署</p>
              <p className="text-white font-medium">{detail.bottom_department}</p>
            </div>
          </div>

          {/* Engagement */}
          <div>
            <h3 className="text-white font-medium mb-3 text-sm">エンゲージメント指標</h3>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'メール開封率', value: `${detail.open_rate}%`, color: 'text-blue-300' },
                { label: 'クイズクリック率', value: `${detail.click_rate}%`, color: 'text-purple-300' },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-[#070d19] border border-falcon-border rounded-lg p-3 flex items-center justify-between">
                  <span className="text-falcon-muted text-sm">{label}</span>
                  <span className={`font-semibold text-lg ${color}`}>{value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Assessment Comparison */}
          <div>
            <h3 className="text-white font-medium mb-3 text-sm">事前/事後評価比較</h3>
            <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
              <div className="flex items-end gap-4">
                <div className="flex-1">
                  <p className="text-falcon-muted text-xs mb-1">事前スコア</p>
                  <div className="h-16 bg-falcon-border rounded-sm relative overflow-hidden">
                    <div
                      className="absolute bottom-0 left-0 right-0 bg-falcon-muted/40 rounded-sm"
                      style={{ height: `${detail.pre_assessment_score}%` }}
                    />
                    <p className="absolute inset-0 flex items-center justify-center text-white font-bold text-xl">{detail.pre_assessment_score}</p>
                  </div>
                </div>
                <div className="flex flex-col items-center gap-1 pb-4">
                  <TrendingUp className="w-5 h-5 text-green-400" />
                  <span className="text-green-400 font-bold text-sm">+{improvement}</span>
                </div>
                <div className="flex-1">
                  <p className="text-falcon-muted text-xs mb-1">事後スコア</p>
                  <div className="h-16 bg-falcon-border rounded-sm relative overflow-hidden">
                    <div
                      className="absolute bottom-0 left-0 right-0 bg-falcon-red/40 rounded-sm"
                      style={{ height: `${detail.post_assessment_score}%` }}
                    />
                    <p className="absolute inset-0 flex items-center justify-center text-white font-bold text-xl">{detail.post_assessment_score}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function AwarenessCampaignsPage() {
  const [showCreate, setShowCreate] = useState(false)
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null)

  const { data = [], isError } = useQuery<Campaign[]>({
    queryKey: ['awareness-campaigns'],
    queryFn: () => apiFetchList<Campaign>('/api/v1/admin/awareness-campaigns').catch(() => []),
    staleTime: 60_000,
  })

  const campaigns = isError ? [] : data
  const activeCampaign = campaigns.find(c => c.status === 'active')

  // Effectiveness metrics across completed + active campaigns
  const scored = campaigns.filter(c => c.post_assessment_score > 0)
  const avgPre = scored.length ? Math.round(scored.reduce((a, c) => a + c.pre_assessment_score, 0) / scored.length) : 0
  const avgPost = scored.length ? Math.round(scored.reduce((a, c) => a + c.post_assessment_score, 0) / scored.length) : 0

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-falcon-red/20 border border-falcon-red/30 flex items-center justify-center">
            <Megaphone className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">セキュリティ意識向上キャンペーン</h1>
            <p className="text-falcon-muted text-sm">Security Awareness Campaign Management</p>
          </div>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          新規作成
        </button>
      </div>

      {/* ── Active Campaign Banner ── */}
      {activeCampaign && (
        <div className="bg-green-500/10 border border-green-500/30 rounded-xl px-5 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
            <div>
              <p className="text-green-300 font-medium">実施中のキャンペーン</p>
              <p className="text-white font-semibold mt-0.5">{activeCampaign.name}</p>
            </div>
          </div>
          <div className="flex items-center gap-6 text-sm">
            <div className="text-right">
              <p className="text-falcon-muted text-xs">受講者</p>
              <p className="text-white font-bold">{(activeCampaign.enrolled_count ?? 0).toLocaleString()}名</p>
            </div>
            <div className="text-right">
              <p className="text-falcon-muted text-xs">完了率</p>
              <p className="text-green-300 font-bold">{activeCampaign.completion_rate}%</p>
            </div>
            <div className="text-right">
              <p className="text-falcon-muted text-xs">終了日</p>
              <p className="text-white font-bold">{activeCampaign.end_date}</p>
            </div>
            <button
              onClick={() => setSelectedCampaign(activeCampaign)}
              className="flex items-center gap-1 px-3 py-1.5 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 text-green-300 text-xs rounded-lg transition-colors"
            >
              <Eye className="w-3.5 h-3.5" />
              詳細
            </button>
          </div>
        </div>
      )}

      {/* ── KPI Summary ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: '総キャンペーン数', value: campaigns.length, sub: `実施中: ${campaigns.filter(c => c.status === 'active').length}`, icon: Megaphone, color: 'text-falcon-red' },
          { label: '総受講者数', value: campaigns.reduce((a, c) => a + c.enrolled_count, 0).toLocaleString(), sub: '登録済みユーザー', icon: Users, color: 'text-blue-400' },
          { label: '平均完了率', value: `${Math.round(campaigns.filter(c => c.completion_rate > 0).reduce((a, c) => a + c.completion_rate, 0) / Math.max(1, campaigns.filter(c => c.completion_rate > 0).length))}%`, sub: 'アクティブキャンペーン', icon: CheckCircle2, color: 'text-green-400' },
          { label: '平均スコア改善', value: `+${avgPost - avgPre}pt`, sub: `事前: ${avgPre} → 事後: ${avgPost}`, icon: TrendingUp, color: 'text-amber-400' },
        ].map(({ label, value, sub, icon: Icon, color }) => (
          <div key={label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Icon className={`w-4 h-4 ${color}`} />
              <span className="text-falcon-muted text-xs">{label}</span>
            </div>
            <p className="text-white font-bold text-2xl">{value}</p>
            <p className="text-falcon-muted text-xs mt-1">{sub}</p>
          </div>
        ))}
      </div>

      {/* ── Campaigns Table ── */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center justify-between">
          <h2 className="text-white font-semibold">キャンペーン一覧</h2>
          <span className="text-falcon-muted text-sm">{campaigns.length}件</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-falcon-border">
                {['キャンペーン名', '種別', 'ステータス', '期間', '対象', '受講者', '完了率', '事前', '事後', '改善', '操作'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-falcon-muted text-xs font-medium uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {campaigns.map(c => {
                const improvement = c.post_assessment_score - c.pre_assessment_score
                return (
                  <tr key={c.id} className="hover:bg-[#0a1020] transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <TypeIcon type={c.campaign_type} />
                        <span className="text-white text-sm font-medium max-w-[200px] truncate">{c.name}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-xs font-medium ${campaignTypeColor[c.campaign_type]}`}>
                        {campaignTypeLabel[c.campaign_type]}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-xs font-medium ${statusColor[c.status]}`}>
                        {c.status === 'active' && <span className="w-1.5 h-1.5 rounded-full bg-green-400 mr-1 animate-pulse" />}
                        {statusLabel[c.status]}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-falcon-muted text-xs">{c.start_date} 〜 {c.end_date}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-xs">{audienceLabel[c.target_audience]}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-white text-sm">{(c.enrolled_count ?? 0).toLocaleString()}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                          <div className="h-full bg-falcon-red rounded-full" style={{ width: `${c.completion_rate}%` }} />
                        </div>
                        <span className="text-white text-xs">{c.completion_rate}%</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-sm">{c.pre_assessment_score > 0 ? c.pre_assessment_score : '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-falcon-muted text-sm">{c.post_assessment_score > 0 ? c.post_assessment_score : '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      {improvement > 0 ? (
                        <span className="text-green-400 text-sm font-medium">+{improvement}pt</span>
                      ) : (
                        <span className="text-falcon-muted text-sm">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedCampaign(c)}
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

      {/* ── Content Library ── */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-falcon-red" />
            <h2 className="text-white font-semibold">コンテンツライブラリ</h2>
          </div>
          <span className="text-falcon-muted text-sm">0件</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 p-5">
          {([] as ContentLibraryItem[]).map(item => (
            <div key={item.id} className="bg-[#070d19] border border-falcon-border rounded-lg p-4 hover:border-falcon-muted/40 transition-colors">
              <div className="flex items-start justify-between mb-2">
                <span className={`inline-flex px-2 py-0.5 rounded-sm border text-xs font-medium ${campaignTypeColor[item.type]}`}>
                  {campaignTypeLabel[item.type]}
                </span>
                <div className="flex items-center gap-1 text-xs text-falcon-muted">
                  <Clock className="w-3 h-3" />
                  <span>{item.duration_minutes}分</span>
                </div>
              </div>
              <h3 className="text-white text-sm font-medium mt-2 mb-1 leading-snug">{item.title}</h3>
              <p className="text-falcon-muted text-xs mb-2">{item.language}</p>
              <div className="flex items-center justify-between">
                <StarRating rating={item.rating} />
                <span className="text-falcon-subtle text-xs">更新: {item.last_updated}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Effectiveness Metrics ── */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-falcon-red" />
          <h2 className="text-white font-semibold">効果測定</h2>
        </div>
        <div className="p-5 space-y-4">
          {scored.map(c => {
            const imp = c.post_assessment_score - c.pre_assessment_score
            const retentionScore = Math.max(0, c.post_assessment_score - Math.round(imp * 0.15))
            return (
              <div key={c.id} className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-white text-sm font-medium">{c.name}</span>
                  <span className={`text-sm font-bold ${imp > 0 ? 'text-green-400' : 'text-falcon-muted'}`}>
                    {imp > 0 ? `+${imp}pt 向上` : '—'}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: '事前スコア', value: c.pre_assessment_score, color: '#7d92b0' },
                    { label: '事後スコア', value: c.post_assessment_score, color: '#e8002d' },
                    { label: '30日後定着', value: retentionScore, color: '#22c55e' },
                  ].map(({ label, value, color }) => (
                    <div key={label}>
                      <p className="text-falcon-muted text-xs mb-1">{label}</p>
                      <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all"
                          style={{ width: `${value}%`, backgroundColor: color }}
                        />
                      </div>
                      <p className="text-xs mt-1" style={{ color }}>{value}点</p>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
          {scored.length === 0 && (
            <p className="text-center text-falcon-muted py-8">評価データがありません</p>
          )}
        </div>
      </div>

      {/* ── Modals ── */}
      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onCreated={() => setShowCreate(false)}
        />
      )}
      {selectedCampaign && (
        <DetailModal
          campaign={selectedCampaign}
          onClose={() => setSelectedCampaign(null)}
        />
      )}
    </div>
  )
}
