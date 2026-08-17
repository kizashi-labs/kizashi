'use client'

import { useState, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Fish, Plus, X, RefreshCw, Eye, Mail, Users, Target,
  TrendingDown, TrendingUp, BarChart3, CheckCircle,
  AlertCircle, ChevronRight, Play, Calendar, Upload,
  Shield, Award, Crosshair, AlertTriangle
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────

type CampaignStatus = 'draft' | 'scheduled' | 'running' | 'completed'
type TemplateCategory = 'credential_harvest' | 'malware_delivery' | 'pretexting' | 'vishing'
type TemplateDifficulty = 'easy' | 'medium' | 'hard'

interface Campaign {
  id: string
  name: string
  template_id: string
  template_name: string
  status: CampaignStatus
  targets_count: number
  sent_count: number
  clicked_count: number
  reported_count: number
  start_date: string
  results: UserResult[]
}

interface UserResult {
  id: string
  email: string
  department: string
  opened: boolean
  clicked: boolean
  reported: boolean
  time_to_click_seconds: number | null
}

interface Template {
  id: string
  name: string
  category: TemplateCategory
  difficulty: TemplateDifficulty
  industry_tags: string[]
  from_name: string
  from_email: string
  subject: string
  body: string
}

interface PhishingStats {
  monthly_click_rates: number[]
  departments: DeptStat[]
  top_templates: { template_name: string; click_count: number }[]
  repeat_offenders: RepeatOffender[]
}

interface DeptStat {
  department: string
  targets: number
  click_rate: number
  reported_rate: number
  last_click_rate: number
}

interface RepeatOffender {
  email: string
  department: string
  click_count: number
  campaigns: string[]
}

// ── Helpers ────────────────────────────────────────────────────

const campaignStatusMeta: Record<CampaignStatus, { label: string; color: string }> = {
  draft:     { label: 'ドラフト',    color: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
  scheduled: { label: 'スケジュール済み', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  running:   { label: '実行中',      color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  completed: { label: '完了',        color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
}

const categoryMeta: Record<TemplateCategory, { label: string; color: string }> = {
  credential_harvest: { label: 'Credential Harvest', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  malware_delivery:   { label: 'Malware Delivery',   color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  pretexting:         { label: 'Pretexting',          color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  vishing:            { label: 'Vishing',             color: 'bg-teal-500/20 text-teal-400 border-teal-500/30' },
}

const difficultyMeta: Record<TemplateDifficulty, { label: string; color: string }> = {
  easy:   { label: 'Easy',   color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  medium: { label: 'Medium', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  hard:   { label: 'Hard',   color: 'bg-red-500/20 text-red-400 border-red-500/30' },
}

function clickRateColor(rate: number): string {
  if (rate > 30) return 'text-red-400'
  if (rate > 15) return 'text-yellow-400'
  return 'text-green-400'
}

function Badge({ className, children }: { className: string; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium border ${className}`}>
      {children}
    </span>
  )
}

function Toast({ message, type, onClose }: { message: string; type: 'success' | 'error'; onClose: () => void }) {
  return (
    <div className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl ${
      type === 'success' ? 'bg-green-900/90 border-green-500/40 text-green-100' : 'bg-red-900/90 border-red-500/40 text-red-100'
    }`}>
      {type === 'success' ? <CheckCircle className="w-4 h-4 text-green-400" /> : <AlertCircle className="w-4 h-4 text-red-400" />}
      <span className="text-sm">{message}</span>
      <button onClick={onClose}><X className="w-3.5 h-3.5" /></button>
    </div>
  )
}

const MONTHS = ['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月']
const DEPARTMENTS = ['全社', '営業部', 'IT部', '人事部', 'DevOps', '経理部', '外部']

// ── Main Component ─────────────────────────────────────────────

export default function PhishingSimulatorPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'campaigns' | 'templates' | 'analytics'>('campaigns')
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)
  const showToast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4000)
  }, [])

  // Campaigns
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null)
  const [showCreateCampaign, setShowCreateCampaign] = useState(false)
  const [newCampaign, setNewCampaign] = useState({ name: '', template_id: '', target_type: 'all' as 'all' | 'department' | 'custom_list', departments: [] as string[], custom_emails: '', scheduled_at: '', landing_page: '' })
  const [showCampaignPreview, setShowCampaignPreview] = useState(false)

  // Templates
  const [selectedTemplate, setSelectedTemplate] = useState<Template | null>(null)
  const [showCreateTemplate, setShowCreateTemplate] = useState(false)
  const [newTemplate, setNewTemplate] = useState({ name: '', category: 'credential_harvest' as TemplateCategory, difficulty: 'medium' as TemplateDifficulty, industry_tags: '', from_name: '', from_email: '', subject: '', body: '' })

  // API queries
  const { data: campaigns = [] } = useQuery<Campaign[]>({
    queryKey: ['phishing-campaigns'],
    queryFn: () => apiFetchList<Campaign>('/api/v1/admin/phishing/campaigns').catch(() => []),
    staleTime: 30_000,
  })

  const { data: templates = [] } = useQuery<Template[]>({
    queryKey: ['phishing-templates'],
    queryFn: () => apiFetchList<Template>('/api/v1/admin/phishing/templates').catch(() => []),
    staleTime: 30_000,
  })

  const EMPTY_PHISHING_STATS: PhishingStats = { monthly_click_rates: [], departments: [], top_templates: [], repeat_offenders: [] }
  const { data: stats = EMPTY_PHISHING_STATS } = useQuery<PhishingStats>({
    queryKey: ['phishing-stats'],
    queryFn: async () => {
      try {
        const res = await apiFetch('/api/v1/admin/phishing/stats')
        return (res && typeof res === 'object' && 'monthly_click_rates' in (res as object)) ? res as PhishingStats : EMPTY_PHISHING_STATS
      } catch { return EMPTY_PHISHING_STATS }
    },
    staleTime: 30_000,
  })

  // Computed stats
  const completedCampaigns = campaigns.filter(c => c.status === 'completed' || c.status === 'running')
  const totalTargets = campaigns.reduce((s, c) => s + c.targets_count, 0)
  const totalSent = campaigns.reduce((s, c) => s + c.sent_count, 0)
  const totalClicked = campaigns.reduce((s, c) => s + c.clicked_count, 0)
  const totalReported = campaigns.reduce((s, c) => s + c.reported_count, 0)
  const overallClickRate = totalSent > 0 ? Math.round((totalClicked / totalSent) * 100) : 0
  const overallReportedRate = totalSent > 0 ? Math.round((totalReported / totalSent) * 100) : 0

  const handleCreateCampaign = async () => {
    if (!newCampaign.name.trim()) { showToast('キャンペーン名を入力してください', 'error'); return }
    try {
      await apiFetch('/api/v1/admin/phishing/campaigns', { method: 'POST', body: JSON.stringify(newCampaign) })
      qc.invalidateQueries({ queryKey: ['phishing-campaigns'] })
      showToast('キャンペーンを作成しました')
      setShowCreateCampaign(false)
    } catch {
      showToast('キャンペーンの作成に失敗しました', 'error')
    }
  }

  const handleCreateTemplate = async () => {
    if (!newTemplate.name.trim()) { showToast('テンプレート名を入力してください', 'error'); return }
    try {
      await apiFetch('/api/v1/admin/phishing/templates', { method: 'POST', body: JSON.stringify(newTemplate) })
      qc.invalidateQueries({ queryKey: ['phishing-templates'] })
      showToast('テンプレートを作成しました')
      setShowCreateTemplate(false)
    } catch {
      showToast('テンプレートの作成に失敗しました', 'error')
    }
  }

  const handleAssignTraining = () => {
    if (!selectedCampaign) return
    const clickers = selectedCampaign.results.filter(r => r.clicked).length
    showToast(`${clickers}名にトレーニングを割り当てました`)
  }

  const previewTemplate = templates.find(t => t.id === newCampaign.template_id)
  const maxClickRate = stats.monthly_click_rates.length > 0 ? Math.max(...stats.monthly_click_rates) : 1

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-muted p-6">
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
            <Fish className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">フィッシングシミュレーション</h1>
            <p className="text-xs text-falcon-muted mt-0.5">セキュリティ意識向上トレーニング</p>
          </div>
        </div>
        <button onClick={() => qc.invalidateQueries()} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-surface border border-falcon-border hover:border-falcon-muted/40 text-sm transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          更新
        </button>
      </div>

      {/* Dashboard cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'キャンペーン数', value: campaigns.length, icon: Crosshair, color: 'text-blue-400' },
          { label: '総ターゲット数', value: totalTargets, icon: Users, color: 'text-purple-400' },
          { label: 'クリック率', value: `${overallClickRate}%`, icon: Target, color: clickRateColor(overallClickRate) },
          { label: '報告率', value: `${overallReportedRate}%`, icon: Shield, color: 'text-green-400' },
        ].map(stat => (
          <div key={stat.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-falcon-muted">{stat.label}</span>
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
            </div>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {(['campaigns', 'templates', 'analytics'] as const).map((t, i) => (
          <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${tab === t ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}>
            {['キャンペーン管理', 'テンプレート', '分析'][i]}
          </button>
        ))}
      </div>

      {/* ── Campaigns Tab ────────────────────────────────────── */}
      {tab === 'campaigns' && (
        <div>
          <div className="flex justify-end mb-4">
            <button onClick={() => setShowCreateCampaign(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red text-white text-sm hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" />
              キャンペーンを作成
            </button>
          </div>
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['名前', 'テンプレート', 'ステータス', 'ターゲット', '送信済み', 'クリック', '報告', 'クリック率', '開始日', '操作'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-falcon-muted uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {campaigns.map(c => {
                  const clickRate = c.sent_count > 0 ? Math.round((c.clicked_count / c.sent_count) * 100) : 0
                  return (
                    <tr key={c.id} className="border-b border-falcon-border/50 hover:bg-falcon-border/20 transition-colors">
                      <td className="px-4 py-3 text-white font-medium">{c.name}</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">{c.template_name}</td>
                      <td className="px-4 py-3"><Badge className={campaignStatusMeta[c.status].color}>{campaignStatusMeta[c.status].label}</Badge></td>
                      <td className="px-4 py-3 font-mono text-white">{c.targets_count}</td>
                      <td className="px-4 py-3 font-mono text-falcon-muted">{c.sent_count}</td>
                      <td className="px-4 py-3 font-mono text-falcon-muted">{c.clicked_count}</td>
                      <td className="px-4 py-3 font-mono text-green-400">{c.reported_count}</td>
                      <td className={`px-4 py-3 font-mono font-bold ${clickRateColor(clickRate)}`}>{clickRate}%</td>
                      <td className="px-4 py-3 text-falcon-muted text-xs">{new Date(c.start_date).toLocaleDateString('ja-JP')}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedCampaign(c)} className="flex items-center gap-1.5 px-2 py-1 rounded-sm bg-falcon-border hover:bg-[#2a3f5a] text-xs transition-colors">
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
      )}

      {/* ── Templates Tab ────────────────────────────────────── */}
      {tab === 'templates' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="text-sm text-falcon-muted">{templates.length} テンプレート</p>
            <div className="flex items-center gap-2">
              <button onClick={() => showToast('JSONファイルを選択してください')} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-surface border border-falcon-border hover:border-falcon-muted/40 text-sm transition-colors">
                <Upload className="w-3.5 h-3.5" />
                テンプレートをインポート
              </button>
              <button onClick={() => setShowCreateTemplate(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red text-white text-sm hover:bg-[#c8001e] transition-colors">
                <Plus className="w-4 h-4" />
                テンプレートを作成
              </button>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4">
            {templates.map(tpl => (
              <div key={tpl.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-4 hover:border-falcon-muted/30 transition-colors">
                {/* Thumbnail placeholder */}
                <div className="w-full h-24 bg-falcon-border rounded-lg mb-3 flex items-center justify-center">
                  <Mail className="w-8 h-8 text-falcon-subtle" />
                </div>
                <h3 className="text-white font-medium text-sm mb-2">{tpl.name}</h3>
                <div className="flex flex-wrap gap-1 mb-3">
                  <Badge className={categoryMeta[tpl.category].color}>{categoryMeta[tpl.category].label}</Badge>
                  <Badge className={difficultyMeta[tpl.difficulty].color}>{difficultyMeta[tpl.difficulty].label}</Badge>
                </div>
                <div className="flex flex-wrap gap-1 mb-3">
                  {tpl.industry_tags.map(tag => (
                    <span key={tag} className="text-[10px] px-1.5 py-0.5 bg-falcon-border rounded-sm text-falcon-subtle">{tag}</span>
                  ))}
                </div>
                <button onClick={() => setSelectedTemplate(tpl)} className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-sm bg-falcon-border hover:bg-[#2a3f5a] text-sm text-falcon-muted transition-colors">
                  <Eye className="w-3.5 h-3.5" />
                  詳細を見る
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Analytics Tab ────────────────────────────────────── */}
      {tab === 'analytics' && (
        <div className="space-y-6">
          {/* Click rate trend */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold mb-4">クリック率トレンド (12ヶ月)</h3>
            <div className="flex items-end gap-1 h-32">
              {stats.monthly_click_rates.map((rate, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <span className="text-[10px] text-falcon-muted">{rate}%</span>
                  <div
                    className={`w-full rounded-t transition-all ${rate > 30 ? 'bg-red-500/60' : rate > 15 ? 'bg-yellow-500/60' : 'bg-green-500/60'}`}
                    style={{ height: `${(rate / maxClickRate) * 80}px` }}
                  />
                  <span className="text-[9px] text-falcon-subtle">{MONTHS[i]}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Department comparison */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold mb-4">部門別比較</h3>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['部門', 'ターゲット', 'クリック率', '報告率', '前回比'].map(h => (
                    <th key={h} className="text-left px-3 py-2 text-xs font-semibold text-falcon-muted uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {stats.departments.map(dept => {
                  const diff = dept.click_rate - dept.last_click_rate
                  return (
                    <tr key={dept.department} className="border-b border-falcon-border/50 hover:bg-falcon-border/20">
                      <td className="px-3 py-2 text-white font-medium">{dept.department}</td>
                      <td className="px-3 py-2 text-falcon-muted">{dept.targets}</td>
                      <td className={`px-3 py-2 font-bold ${clickRateColor(dept.click_rate)}`}>{dept.click_rate}%</td>
                      <td className="px-3 py-2 text-green-400">{dept.reported_rate}%</td>
                      <td className={`px-3 py-2 flex items-center gap-1 ${diff < 0 ? 'text-green-400' : 'text-red-400'}`}>
                        {diff < 0 ? <TrendingDown className="w-3.5 h-3.5" /> : <TrendingUp className="w-3.5 h-3.5" />}
                        {diff > 0 ? '+' : ''}{diff}%
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Top clicked templates */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <h3 className="text-white font-semibold mb-4">クリック数 Top 5 テンプレート</h3>
              <div className="space-y-3">
                {stats.top_templates.map((t, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <span className="text-xs text-falcon-subtle w-4">{i + 1}</span>
                    <span className="text-sm text-falcon-muted flex-1 truncate">{t.template_name}</span>
                    <span className="text-sm font-mono text-white w-12 text-right">{t.click_count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Repeat offenders */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <h3 className="text-white font-semibold mb-4">繰り返し違反者 (3回以上クリック)</h3>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['Email', '部門', 'クリック数'].map(h => (
                      <th key={h} className="text-left px-2 py-2 text-xs font-semibold text-falcon-muted uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {stats.repeat_offenders.map((u, i) => (
                    <tr key={i} className="border-b border-falcon-border/50 hover:bg-falcon-border/20">
                      <td className="px-2 py-2 font-mono text-white text-xs">{u.email}</td>
                      <td className="px-2 py-2 text-falcon-muted text-xs">{u.department}</td>
                      <td className="px-2 py-2 text-red-400 font-bold text-center">{u.click_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Campaign Detail Modal ─────────────────────────── */}
      {selectedCampaign && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-4xl p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">{selectedCampaign.name}</h2>
              <button onClick={() => setSelectedCampaign(null)}><X className="w-5 h-5" /></button>
            </div>

            {/* Timeline bars */}
            <div className="mb-6 grid grid-cols-4 gap-3">
              {[
                { label: '送信済み', value: selectedCampaign.sent_count, total: selectedCampaign.targets_count, color: 'bg-blue-500' },
                { label: '開封', value: selectedCampaign.results.filter(r => r.opened).length, total: selectedCampaign.sent_count, color: 'bg-yellow-500' },
                { label: 'クリック', value: selectedCampaign.clicked_count, total: selectedCampaign.sent_count, color: 'bg-red-500' },
                { label: '報告', value: selectedCampaign.reported_count, total: selectedCampaign.sent_count, color: 'bg-green-500' },
              ].map(stat => {
                const pct = stat.total > 0 ? Math.round((stat.value / stat.total) * 100) : 0
                return (
                  <div key={stat.label} className="bg-falcon-border/30 rounded-lg p-3">
                    <p className="text-xs text-falcon-muted mb-1">{stat.label}</p>
                    <p className="text-xl font-bold text-white">{stat.value}</p>
                    <div className="mt-2 h-1.5 bg-falcon-border rounded-sm overflow-hidden">
                      <div className={`h-full ${stat.color} rounded-sm`} style={{ width: `${pct}%` }} />
                    </div>
                    <p className="text-[10px] text-falcon-subtle mt-1">{pct}%</p>
                  </div>
                )
              })}
            </div>

            {/* User results */}
            <h3 className="text-white font-semibold mb-3">ユーザー結果</h3>
            <div className="overflow-x-auto mb-4">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['Email', '部門', '開封', 'クリック', '報告', 'クリックまでの時間'].map(h => (
                      <th key={h} className="text-left px-3 py-2 text-xs font-semibold text-falcon-muted uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {selectedCampaign.results.map(r => (
                    <tr key={r.id} className="border-b border-falcon-border/50 hover:bg-falcon-border/20">
                      <td className="px-3 py-2 font-mono text-white text-xs">{r.email}</td>
                      <td className="px-3 py-2 text-falcon-muted text-xs">{r.department}</td>
                      <td className="px-3 py-2">{r.opened ? <CheckCircle className="w-4 h-4 text-yellow-400" /> : <span className="text-falcon-subtle text-xs">—</span>}</td>
                      <td className="px-3 py-2">{r.clicked ? <AlertCircle className="w-4 h-4 text-red-400" /> : <span className="text-falcon-subtle text-xs">—</span>}</td>
                      <td className="px-3 py-2">{r.reported ? <Shield className="w-4 h-4 text-green-400" /> : <span className="text-falcon-subtle text-xs">—</span>}</td>
                      <td className="px-3 py-2 font-mono text-falcon-muted text-xs">
                        {r.time_to_click_seconds !== null ? `${r.time_to_click_seconds}秒` : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Risk users */}
            <div className="mb-4">
              <h3 className="text-white font-semibold mb-3">リスクユーザー (最速クリック順)</h3>
              <div className="flex flex-wrap gap-2">
                {[...selectedCampaign.results.filter(r => r.clicked)].sort((a, b) => (a.time_to_click_seconds ?? Infinity) - (b.time_to_click_seconds ?? Infinity)).map(r => (
                  <div key={r.id} className="flex items-center gap-2 px-3 py-1.5 bg-red-900/20 border border-red-500/30 rounded-lg">
                    <span className="text-xs font-mono text-red-300">{r.email}</span>
                    <span className="text-xs text-red-400">{r.time_to_click_seconds}秒</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end">
              <button onClick={handleAssignTraining} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 text-white text-sm hover:bg-blue-500 transition-colors">
                <Award className="w-4 h-4" />
                クリックしたユーザーにトレーニングを割り当て
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Template Detail Modal ─────────────────────────── */}
      {selectedTemplate && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">{selectedTemplate.name}</h2>
              <button onClick={() => setSelectedTemplate(null)}><X className="w-5 h-5" /></button>
            </div>
            <div className="flex flex-wrap gap-2 mb-4">
              <Badge className={categoryMeta[selectedTemplate.category].color}>{categoryMeta[selectedTemplate.category].label}</Badge>
              <Badge className={difficultyMeta[selectedTemplate.difficulty].color}>{difficultyMeta[selectedTemplate.difficulty].label}</Badge>
            </div>
            <div className="space-y-2 mb-4 text-sm">
              <div className="flex gap-2"><span className="text-falcon-muted w-24">送信者名</span><span className="text-white">{selectedTemplate.from_name}</span></div>
              <div className="flex gap-2"><span className="text-falcon-muted w-24">送信元メール</span><span className="text-white font-mono">{selectedTemplate.from_email}</span></div>
              <div className="flex gap-2"><span className="text-falcon-muted w-24">件名</span><span className="text-white">{selectedTemplate.subject}</span></div>
            </div>
            <div>
              <p className="text-xs text-falcon-muted mb-2">本文プレビュー</p>
              <div className="bg-white rounded-lg p-4">
                <div dangerouslySetInnerHTML={{ __html: selectedTemplate.body }} className="text-gray-800 text-sm" />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Create Campaign Modal ─────────────────────────── */}
      {showCreateCampaign && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">キャンペーンを作成</h2>
              <button onClick={() => setShowCreateCampaign(false)}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-falcon-muted mb-1">キャンペーン名</label>
                <input value={newCampaign.name} onChange={e => setNewCampaign(p => ({ ...p, name: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" placeholder="Q2 2026 フィッシングテスト" />
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">テンプレート</label>
                <select value={newCampaign.template_id} onChange={e => setNewCampaign(p => ({ ...p, template_id: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden">
                  <option value="">選択してください</option>
                  {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
                </select>
                {previewTemplate && (
                  <div className="mt-2 p-3 bg-falcon-border/30 border border-falcon-border rounded-lg">
                    <p className="text-xs text-falcon-muted">件名: <span className="text-white">{previewTemplate.subject}</span></p>
                    <p className="text-xs text-falcon-muted mt-1">送信者: <span className="text-white">{previewTemplate.from_name} &lt;{previewTemplate.from_email}&gt;</span></p>
                  </div>
                )}
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">ターゲット</label>
                <select value={newCampaign.target_type} onChange={e => setNewCampaign(p => ({ ...p, target_type: e.target.value as typeof p.target_type }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden">
                  <option value="all">全社員</option>
                  <option value="department">部門選択</option>
                  <option value="custom_list">カスタムリスト</option>
                </select>
              </div>
              {newCampaign.target_type === 'department' && (
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">部門を選択</label>
                  <div className="flex flex-wrap gap-2">
                    {DEPARTMENTS.slice(1).map(d => (
                      <button
                        key={d}
                        onClick={() => setNewCampaign(p => ({
                          ...p,
                          departments: p.departments.includes(d) ? p.departments.filter(x => x !== d) : [...p.departments, d]
                        }))}
                        className={`px-3 py-1 rounded-full text-xs transition-colors ${newCampaign.departments.includes(d) ? 'bg-falcon-red text-white' : 'bg-falcon-border text-falcon-muted'}`}
                      >
                        {d}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {newCampaign.target_type === 'custom_list' && (
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">メールアドレス (1行1件)</label>
                  <textarea value={newCampaign.custom_emails} onChange={e => setNewCampaign(p => ({ ...p, custom_emails: e.target.value }))} className="w-full h-24 bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm font-mono text-white outline-hidden resize-none" placeholder="user1@corp.local&#10;user2@corp.local" />
                </div>
              )}
              <div>
                <label className="block text-xs text-falcon-muted mb-1">開始日時</label>
                <input type="datetime-local" value={newCampaign.scheduled_at} onChange={e => setNewCampaign(p => ({ ...p, scheduled_at: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" />
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">ランディングページ (任意)</label>
                <input value={newCampaign.landing_page} onChange={e => setNewCampaign(p => ({ ...p, landing_page: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" placeholder="https://example.com/awareness (空白=デフォルト)" />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setShowCreateCampaign(false)} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted text-sm hover:text-white transition-colors">キャンセル</button>
              <button onClick={() => setShowCampaignPreview(!showCampaignPreview)} className="px-4 py-2 rounded-lg bg-falcon-border text-falcon-muted text-sm hover:text-white transition-colors">プレビュー</button>
              <button onClick={handleCreateCampaign} className="px-4 py-2 rounded-lg bg-falcon-red text-white text-sm hover:bg-[#c8001e] transition-colors">作成</button>
            </div>
            {showCampaignPreview && previewTemplate && (
              <div className="mt-4 p-4 bg-white rounded-lg">
                <p className="text-gray-500 text-xs mb-1">件名: {previewTemplate.subject}</p>
                <div dangerouslySetInnerHTML={{ __html: previewTemplate.body }} className="text-gray-800 text-sm" />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Create Template Modal ─────────────────────────── */}
      {showCreateTemplate && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">テンプレートを作成</h2>
              <button onClick={() => setShowCreateTemplate(false)}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">テンプレート名</label>
                  <input value={newTemplate.name} onChange={e => setNewTemplate(p => ({ ...p, name: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" />
                </div>
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">カテゴリー</label>
                  <select value={newTemplate.category} onChange={e => setNewTemplate(p => ({ ...p, category: e.target.value as TemplateCategory }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden">
                    {Object.entries(categoryMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">難易度</label>
                  <select value={newTemplate.difficulty} onChange={e => setNewTemplate(p => ({ ...p, difficulty: e.target.value as TemplateDifficulty }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden">
                    {Object.entries(difficultyMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">業界タグ (カンマ区切り)</label>
                  <input value={newTemplate.industry_tags} onChange={e => setNewTemplate(p => ({ ...p, industry_tags: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" placeholder="finance, enterprise" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">送信者名</label>
                  <input value={newTemplate.from_name} onChange={e => setNewTemplate(p => ({ ...p, from_name: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" />
                </div>
                <div>
                  <label className="block text-xs text-falcon-muted mb-1">送信元メール</label>
                  <input value={newTemplate.from_email} onChange={e => setNewTemplate(p => ({ ...p, from_email: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" />
                </div>
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">件名</label>
                <input value={newTemplate.subject} onChange={e => setNewTemplate(p => ({ ...p, subject: e.target.value }))} className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white outline-hidden" />
              </div>
              <div>
                <label className="block text-xs text-falcon-muted mb-1">本文 (HTML)</label>
                <textarea value={newTemplate.body} onChange={e => setNewTemplate(p => ({ ...p, body: e.target.value }))} className="w-full h-36 bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm font-mono text-white outline-hidden resize-none" placeholder="<p>本文を入力...</p>" />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setShowCreateTemplate(false)} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted text-sm hover:text-white transition-colors">キャンセル</button>
              <button onClick={handleCreateTemplate} className="px-4 py-2 rounded-lg bg-falcon-red text-white text-sm hover:bg-[#c8001e] transition-colors">作成</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
