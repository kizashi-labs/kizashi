'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Star, Users, Trophy, BookOpen, Plus, X, Pencil, Trash2,
  CheckCircle, AlertCircle, Clock, ChevronDown, ChevronRight,
  Award, BarChart2, Activity, User, Mail, Building2, Calendar,
  Loader2, Shield, Target, FileText, RefreshCw,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type RoleInProgram = 'champion' | 'lead_champion' | 'coordinator'
type ChampionStatus = 'active' | 'inactive' | 'onboarding'
type ActivityType =
  | 'security_review'
  | 'vulnerability_report'
  | 'awareness_event'
  | 'code_review'
  | 'training_delivery'
  | 'blog_post'

interface Champion {
  id: string
  name: string
  email: string
  department: string
  role_in_program: RoleInProgram
  nomination_date: string
  activities_completed: number
  training_hours: number
  contribution_score: number
  status: ChampionStatus
  manager: string
  certifications: string[]
  upcoming_tasks: string[]
}

interface ChampionActivity {
  id: string
  champion_id: string
  champion_name: string
  activity_type: ActivityType
  description: string
  points_earned: number
  date: string
  approved: boolean
  evidence: string
}

interface TrainingAssignment {
  id: string
  title: string
  type: 'required' | 'recommended'
  completed_count: number
  total_count: number
  due_date: string
}

const DEPARTMENTS = ['エンジニアリング', 'インフラ', 'セキュリティ', 'QA', 'DevOps', '営業', 'マーケティング', '人事', '法務', '財務']

// ─── Helpers ──────────────────────────────────────────────────────────────────

const ROLE_STYLES: Record<RoleInProgram, { label: string; bg: string; text: string }> = {
  lead_champion: { label: 'リードチャンピオン', bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  champion: { label: 'チャンピオン', bg: 'bg-blue-900/40', text: 'text-blue-300' },
  coordinator: { label: 'コーディネーター', bg: 'bg-purple-900/40', text: 'text-purple-300' },
}

const STATUS_STYLES: Record<ChampionStatus, { label: string; bg: string; text: string; dot: string }> = {
  active: { label: 'アクティブ', bg: 'bg-green-900/40', text: 'text-green-300', dot: 'bg-green-400' },
  inactive: { label: '非アクティブ', bg: 'bg-gray-800/60', text: 'text-gray-400', dot: 'bg-gray-500' },
  onboarding: { label: 'オンボーディング', bg: 'bg-orange-900/40', text: 'text-orange-300', dot: 'bg-orange-400' },
}

const ACTIVITY_STYLES: Record<ActivityType, { label: string; bg: string; text: string }> = {
  security_review: { label: 'セキュリティレビュー', bg: 'bg-red-900/40', text: 'text-red-300' },
  vulnerability_report: { label: '脆弱性報告', bg: 'bg-orange-900/40', text: 'text-orange-300' },
  awareness_event: { label: '啓発イベント', bg: 'bg-blue-900/40', text: 'text-blue-300' },
  code_review: { label: 'コードレビュー', bg: 'bg-cyan-900/40', text: 'text-cyan-300' },
  training_delivery: { label: 'トレーニング実施', bg: 'bg-green-900/40', text: 'text-green-300' },
  blog_post: { label: 'ブログ投稿', bg: 'bg-purple-900/40', text: 'text-purple-300' },
}

const MONTHS = ['10月', '11月', '12月', '1月', '2月', '3月']

// Monthly activity counts per type (mock)
const MONTHLY_ACTIVITY_DATA: Record<ActivityType, number[]> = {
  security_review:      [3, 4, 3, 5, 4, 4],
  vulnerability_report: [2, 3, 2, 3, 4, 3],
  awareness_event:      [1, 2, 2, 1, 2, 2],
  code_review:          [4, 5, 4, 4, 3, 3],
  training_delivery:    [2, 1, 2, 3, 2, 2],
  blog_post:            [1, 2, 1, 2, 2, 2],
}

function initials(name: string) {
  return name.split(' ').map(p => p[0]).join('').slice(0, 2)
}

function fmt(d: string) {
  return new Date(d).toLocaleDateString('ja-JP', { year: 'numeric', month: 'short', day: 'numeric' })
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: RoleInProgram }) {
  const s = ROLE_STYLES[role]
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${s.bg} ${s.text}`}>{s.label}</span>
}

function StatusBadge({ status }: { status: ChampionStatus }) {
  const s = STATUS_STYLES[status]
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${s.bg} ${s.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  )
}

function ActivityTypeBadge({ type }: { type: ActivityType }) {
  const s = ACTIVITY_STYLES[type]
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${s.bg} ${s.text}`}>{s.label}</span>
}

function Avatar({ name, size = 'md' }: { name: string; size?: 'sm' | 'md' | 'lg' }) {
  const sz = size === 'sm' ? 'w-7 h-7 text-xs' : size === 'lg' ? 'w-12 h-12 text-base' : 'w-9 h-9 text-sm'
  return (
    <div className={`${sz} rounded-full bg-gradient-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center font-bold text-white flex-shrink-0`}>
      {initials(name)}
    </div>
  )
}

// ─── Champion Detail Modal ────────────────────────────────────────────────────

function ChampionDetailModal({ champion, activities, onClose }: {
  champion: Champion
  activities: ChampionActivity[]
  onClose: () => void
}) {
  const myActivities = activities.filter(a => a.champion_id === champion.id)
  const totalPoints = myActivities.reduce((s, a) => s + (a.approved ? a.points_earned : 0), 0)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <div className="flex items-center gap-4">
            <Avatar name={champion.name} size="lg" />
            <div>
              <h3 className="text-white font-semibold text-lg">{champion.name}</h3>
              <div className="flex items-center gap-2 mt-1">
                <RoleBadge role={champion.role_in_program} />
                <StatusBadge status={champion.status} />
              </div>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 p-5 space-y-5">
          {/* Profile */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2 text-[#7d92b0]"><Mail className="w-4 h-4" />{champion.email}</div>
              <div className="flex items-center gap-2 text-[#7d92b0]"><Building2 className="w-4 h-4" />{champion.department}</div>
              <div className="flex items-center gap-2 text-[#7d92b0]"><User className="w-4 h-4" />マネージャー: {champion.manager}</div>
              <div className="flex items-center gap-2 text-[#7d92b0]"><Calendar className="w-4 h-4" />推薦日: {fmt(champion.nomination_date)}</div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: '活動数', value: champion.activities_completed },
                { label: '研修時間', value: `${champion.training_hours}h` },
                { label: '貢献スコア', value: champion.contribution_score },
                { label: '獲得pt', value: totalPoints },
              ].map(m => (
                <div key={m.label} className="bg-[#070d19] rounded border border-[#1e2d42] p-3 text-center">
                  <p className="text-[#7d92b0] text-xs mb-1">{m.label}</p>
                  <p className="text-white font-bold text-lg">{m.value}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Certifications */}
          <div>
            <h4 className="text-white font-medium mb-2 flex items-center gap-2"><Award className="w-4 h-4 text-yellow-400" />取得資格</h4>
            {champion.certifications.length === 0
              ? <p className="text-[#7d92b0] text-sm">未取得</p>
              : <div className="flex flex-wrap gap-2">
                  {champion.certifications.map(c => (
                    <span key={c} className="px-2 py-1 bg-yellow-900/30 border border-yellow-700/40 rounded text-xs text-yellow-300">{c}</span>
                  ))}
                </div>
            }
          </div>

          {/* Upcoming Tasks */}
          {champion.upcoming_tasks.length > 0 && (
            <div>
              <h4 className="text-white font-medium mb-2 flex items-center gap-2"><Target className="w-4 h-4 text-blue-400" />今後のタスク</h4>
              <ul className="space-y-1">
                {champion.upcoming_tasks.map((t, i) => (
                  <li key={i} className="flex items-center gap-2 text-sm text-[#7d92b0]">
                    <CheckCircle className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />{t}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Activity History */}
          <div>
            <h4 className="text-white font-medium mb-2 flex items-center gap-2"><Activity className="w-4 h-4 text-green-400" />活動履歴</h4>
            {myActivities.length === 0
              ? <p className="text-[#7d92b0] text-sm">活動記録なし</p>
              : <div className="space-y-2">
                  {myActivities.slice(0, 5).map(a => (
                    <div key={a.id} className="flex items-start gap-3 p-3 bg-[#070d19] rounded border border-[#1e2d42]">
                      <ActivityTypeBadge type={a.activity_type} />
                      <div className="flex-1 min-w-0">
                        <p className="text-[#e2e8f4] text-sm truncate">{a.description}</p>
                        <p className="text-[#3d5068] text-xs mt-0.5">{fmt(a.date)}</p>
                      </div>
                      <span className="text-yellow-400 text-sm font-bold flex-shrink-0">+{a.points_earned}pt</span>
                    </div>
                  ))}
                </div>
            }
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Nominate Champion Modal ──────────────────────────────────────────────────

function NominateModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [form, setForm] = useState({
    name: '', email: '', department: '', manager_approval: true, training_plan: '',
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSuccess()
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-lg">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold text-lg">チャンピオンを推薦</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1">氏名 *</label>
              <input required value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none" />
            </div>
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1">メールアドレス *</label>
              <input required type="email" value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none" />
            </div>
          </div>
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1">部門 *</label>
            <select required value={form.department} onChange={e => setForm(f => ({ ...f, department: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none">
              <option value="">選択してください</option>
              {DEPARTMENTS.map(d => <option key={d} value={d}>{d}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1">初期トレーニング計画</label>
            <textarea value={form.training_plan} onChange={e => setForm(f => ({ ...f, training_plan: e.target.value }))} rows={3}
              placeholder="推薦理由・初期トレーニング計画を記入してください"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none resize-none" />
          </div>
          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" checked={form.manager_approval} onChange={e => setForm(f => ({ ...f, manager_approval: e.target.checked }))}
              className="w-4 h-4 accent-[#e8002d]" />
            <span className="text-[#7d92b0] text-sm">マネージャー承認が必要</span>
          </label>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 px-4 py-2 border border-[#1e2d42] rounded text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
            <button type="submit" className="flex-1 px-4 py-2 bg-[#e8002d] rounded text-white font-medium text-sm hover:bg-[#c0001f]">推薦する</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Add Activity Modal ───────────────────────────────────────────────────────

function AddActivityModal({ champions, onClose, onSuccess }: {
  champions: Champion[]
  onClose: () => void
  onSuccess: () => void
}) {
  const [form, setForm] = useState({
    champion_id: '', activity_type: '' as ActivityType | '', description: '', date: new Date().toISOString().slice(0, 10), evidence: '',
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSuccess()
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-lg">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold text-lg">活動を追加</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1">チャンピオン *</label>
            <select required value={form.champion_id} onChange={e => setForm(f => ({ ...f, champion_id: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none">
              <option value="">選択してください</option>
              {champions.filter(c => c.status !== 'inactive').map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1">活動タイプ *</label>
            <select required value={form.activity_type} onChange={e => setForm(f => ({ ...f, activity_type: e.target.value as ActivityType }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none">
              <option value="">選択してください</option>
              {Object.entries(ACTIVITY_STYLES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1">説明 *</label>
            <textarea required value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none resize-none" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1">日付 *</label>
              <input required type="date" value={form.date} onChange={e => setForm(f => ({ ...f, date: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none" />
            </div>
            <div>
              <label className="block text-[#7d92b0] text-sm mb-1">エビデンス</label>
              <input value={form.evidence} onChange={e => setForm(f => ({ ...f, evidence: e.target.value }))}
                placeholder="ドキュメント・リンクなど"
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:border-[#e8002d] focus:outline-none" />
            </div>
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 px-4 py-2 border border-[#1e2d42] rounded text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
            <button type="submit" className="flex-1 px-4 py-2 bg-[#e8002d] rounded text-white font-medium text-sm hover:bg-[#c0001f]">追加する</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SecurityChampionsPage() {
  const [activeTab, setActiveTab] = useState<'champions' | 'activities'>('champions')
  const [detailChampion, setDetailChampion] = useState<Champion | null>(null)
  const [showNominate, setShowNominate] = useState(false)
  const [showAddActivity, setShowAddActivity] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<ChampionStatus | 'all'>('all')
  const [deptFilter, setDeptFilter] = useState<string>('all')

  const { data: champions = [] } = useQuery<Champion[]>({
    queryKey: ['security-champions'],
    queryFn: () => apiFetchList<Champion>('/api/v1/admin/security-champions').catch(() => []),
    retry: false,
  })

  const { data: activities = [] } = useQuery<ChampionActivity[]>({
    queryKey: ['security-champions-activities'],
    queryFn: () => apiFetchList<ChampionActivity>('/api/v1/admin/security-champions/activities').catch(() => []),
    retry: false,
  })

  function showToast(msg: string) {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  const filteredChampions = champions.filter(c => {
    if (statusFilter !== 'all' && c.status !== statusFilter) return false
    if (deptFilter !== 'all' && c.department !== deptFilter) return false
    return true
  })

  const sorted = [...champions].sort((a, b) => b.contribution_score - a.contribution_score)
  const top10 = sorted.slice(0, 10)

  // Department coverage
  const deptCoverage = DEPARTMENTS.map(dept => ({
    dept,
    count: champions.filter(c => c.department === dept && c.status === 'active').length,
    has: champions.some(c => c.department === dept && c.status === 'active'),
  }))

  // Activity type totals for bar chart
  const activityBarMax = 18

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-[100] bg-green-800 border border-green-600 text-green-200 px-4 py-2 rounded shadow-lg text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" />{toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-yellow-500 to-yellow-700 flex items-center justify-center">
            <Star className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white text-2xl font-bold">セキュリティチャンピオンプログラム</h1>
            <p className="text-[#7d92b0] text-sm">組織全体のセキュリティ文化を推進するリーダーシップ管理</p>
          </div>
        </div>
        <button onClick={() => setShowNominate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] rounded-lg text-white font-medium text-sm hover:bg-[#c0001f]">
          <Plus className="w-4 h-4" />チャンピオンを推薦
        </button>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'チャンピオン総数', value: champions.length, icon: Users, color: 'text-blue-400', sub: `${champions.filter(c => c.status === 'active').length} アクティブ` },
          { label: '対象部門数', value: deptCoverage.filter(d => d.has).length + '/' + DEPARTMENTS.length, icon: Building2, color: 'text-green-400', sub: '部門カバレッジ' },
          { label: '総活動数', value: activities.length, icon: Activity, color: 'text-purple-400', sub: `${activities.filter(a => a.approved).length} 承認済み` },
          { label: '総研修時間', value: champions.reduce((s, c) => s + c.training_hours, 0) + 'h', icon: BookOpen, color: 'text-yellow-400', sub: 'プログラム全体' },
        ].map(card => (
          <div key={card.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-[#7d92b0] text-sm">{card.label}</p>
              <card.icon className={`w-5 h-5 ${card.color}`} />
            </div>
            <p className="text-white text-2xl font-bold">{card.value}</p>
            <p className="text-[#3d5068] text-xs mt-1">{card.sub}</p>
          </div>
        ))}
      </div>

      {/* Program overview card */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <h2 className="text-white font-semibold mb-2">プログラム概要</h2>
            <p className="text-[#7d92b0] text-sm leading-relaxed max-w-3xl">
              セキュリティチャンピオンプログラムは、各部門にセキュリティに精通したリーダーを配置し、
              組織全体のセキュリティ文化・意識の向上を目的としています。チャンピオンはセキュリティチームと各部門の橋渡しとして機能し、
              日常業務へのセキュリティ統合を推進します。
            </p>
            {champions.find(c => c.role_in_program === 'lead_champion') && (
              <div className="flex items-center gap-2 mt-3">
                <span className="text-[#7d92b0] text-sm">プログラムリード:</span>
                <span className="text-white text-sm font-medium">
                  {(() => { const l = champions.find(c => c.role_in_program === 'lead_champion')!; return `${l.name} (${l.department}部門)` })()}
                </span>
              </div>
            )}
          </div>
          <div className="flex gap-2 ml-4">
            <div className="text-center px-4 py-3 bg-[#070d19] border border-[#1e2d42] rounded-lg">
              <p className="text-2xl font-bold text-yellow-400">{champions.filter(c => c.role_in_program === 'lead_champion').length}</p>
              <p className="text-[#7d92b0] text-xs mt-0.5">リードチャンピオン</p>
            </div>
            <div className="text-center px-4 py-3 bg-[#070d19] border border-[#1e2d42] rounded-lg">
              <p className="text-2xl font-bold text-blue-400">{champions.filter(c => c.role_in_program === 'champion').length}</p>
              <p className="text-[#7d92b0] text-xs mt-0.5">チャンピオン</p>
            </div>
            <div className="text-center px-4 py-3 bg-[#070d19] border border-[#1e2d42] rounded-lg">
              <p className="text-2xl font-bold text-purple-400">{champions.filter(c => c.role_in_program === 'coordinator').length}</p>
              <p className="text-[#7d92b0] text-xs mt-0.5">コーディネーター</p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#1e2d42] flex gap-1">
        {(['champions', 'activities'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-5 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === tab
              ? 'border-[#e8002d] text-white'
              : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'}`}>
            {tab === 'champions' ? 'チャンピオン管理' : '活動・実績'}
          </button>
        ))}
      </div>

      {/* ── Tab: Champions ── */}
      {activeTab === 'champions' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="flex items-center gap-3">
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as ChampionStatus | 'all')}
              className="bg-[#0d1220] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none">
              <option value="all">全ステータス</option>
              <option value="active">アクティブ</option>
              <option value="onboarding">オンボーディング</option>
              <option value="inactive">非アクティブ</option>
            </select>
            <select value={deptFilter} onChange={e => setDeptFilter(e.target.value)}
              className="bg-[#0d1220] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none">
              <option value="all">全部門</option>
              {DEPARTMENTS.map(d => <option key={d} value={d}>{d}</option>)}
            </select>
            <span className="text-[#7d92b0] text-sm ml-auto">{filteredChampions.length}件表示</span>
          </div>

          {/* Champions Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                    {['チャンピオン', '部門', 'ロール', '推薦日', '活動数', '研修時間', '貢献スコア', 'ステータス', '操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-[#7d92b0] font-medium text-xs uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filteredChampions.map(c => (
                    <tr key={c.id} className="hover:bg-[#0d1525] cursor-pointer" onClick={() => setDetailChampion(c)}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <Avatar name={c.name} size="sm" />
                          <div>
                            <p className="text-white font-medium">{c.name}</p>
                            <p className="text-[#3d5068] text-xs">{c.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] whitespace-nowrap">{c.department}</td>
                      <td className="px-4 py-3"><RoleBadge role={c.role_in_program} /></td>
                      <td className="px-4 py-3 text-[#7d92b0] whitespace-nowrap">{fmt(c.nomination_date)}</td>
                      <td className="px-4 py-3 text-white text-center">{c.activities_completed}</td>
                      <td className="px-4 py-3 text-white text-center">{c.training_hours}h</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-[#1e2d42] rounded-full h-1.5 min-w-[60px]">
                            <div className="bg-[#e8002d] h-1.5 rounded-full" style={{ width: `${Math.min(100, (c.contribution_score / 1000) * 100)}%` }} />
                          </div>
                          <span className="text-white text-xs font-mono">{c.contribution_score}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3"><StatusBadge status={c.status} /></td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                          <button onClick={() => setDetailChampion(c)} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white"><ChevronRight className="w-4 h-4" /></button>
                          {c.status === 'inactive'
                            ? <button onClick={() => showToast(`${c.name}を再有効化しました`)} className="p-1.5 rounded hover:bg-green-900/40 text-[#7d92b0] hover:text-green-300"><RefreshCw className="w-4 h-4" /></button>
                            : <button onClick={() => showToast(`${c.name}を非アクティブにしました`)} className="p-1.5 rounded hover:bg-red-900/40 text-[#7d92b0] hover:text-red-300"><Trash2 className="w-4 h-4" /></button>
                          }
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Training Assignments */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h3 className="text-white font-semibold mb-4 flex items-center gap-2"><BookOpen className="w-4 h-4 text-blue-400" />研修割り当て</h3>
            <div className="space-y-3">
              {([] as TrainingAssignment[]).map(t => {
                const pct = Math.round((t.completed_count / t.total_count) * 100)
                return (
                  <div key={t.id} className="flex items-center gap-4 p-3 bg-[#070d19] rounded border border-[#1e2d42]">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <p className="text-white text-sm font-medium truncate">{t.title}</p>
                        <span className={`px-1.5 py-0.5 rounded text-xs ${t.type === 'required' ? 'bg-red-900/40 text-red-300' : 'bg-blue-900/40 text-blue-300'}`}>
                          {t.type === 'required' ? '必須' : '推奨'}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="flex-1 bg-[#1e2d42] rounded-full h-1.5">
                          <div className="bg-[#e8002d] h-1.5 rounded-full" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="text-[#7d92b0] text-xs whitespace-nowrap">{t.completed_count}/{t.total_count} 完了</span>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-white font-bold">{pct}%</p>
                      <p className="text-[#3d5068] text-xs">期限: {fmt(t.due_date)}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Activities ── */}
      {activeTab === 'activities' && (
        <div className="space-y-6">
          <div className="flex justify-end">
            <button onClick={() => setShowAddActivity(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] rounded-lg text-white font-medium text-sm hover:bg-[#c0001f]">
              <Plus className="w-4 h-4" />活動を追加
            </button>
          </div>

          {/* Activities Log Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2d42]">
              <h3 className="text-white font-semibold">活動ログ</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                    {['チャンピオン', '活動タイプ', '説明', 'ポイント', '日付', '承認'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-[#7d92b0] font-medium text-xs uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {activities.map(a => (
                    <tr key={a.id} className="hover:bg-[#0d1525]">
                      <td className="px-4 py-3 text-white whitespace-nowrap font-medium">{a.champion_name}</td>
                      <td className="px-4 py-3"><ActivityTypeBadge type={a.activity_type} /></td>
                      <td className="px-4 py-3 text-[#7d92b0] max-w-xs truncate">{a.description}</td>
                      <td className="px-4 py-3 text-yellow-400 font-bold whitespace-nowrap">+{a.points_earned}pt</td>
                      <td className="px-4 py-3 text-[#7d92b0] whitespace-nowrap">{fmt(a.date)}</td>
                      <td className="px-4 py-3">
                        {a.approved
                          ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-green-900/40 text-green-300"><CheckCircle className="w-3 h-3" />承認済み</span>
                          : <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-yellow-900/40 text-yellow-300"><Clock className="w-3 h-3" />審査中</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Leaderboard + Monthly Chart */}
          <div className="grid grid-cols-2 gap-6">
            {/* Leaderboard */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h3 className="text-white font-semibold mb-4 flex items-center gap-2"><Trophy className="w-4 h-4 text-yellow-400" />リーダーボード (Top 10)</h3>
              <div className="space-y-2">
                {top10.map((c, i) => (
                  <div key={c.id} className="flex items-center gap-3 p-2.5 bg-[#070d19] rounded border border-[#1e2d42]">
                    <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                      i === 0 ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-600/40' :
                      i === 1 ? 'bg-gray-400/20 text-gray-300 border border-gray-500/40' :
                      i === 2 ? 'bg-orange-700/20 text-orange-400 border border-orange-600/40' :
                      'bg-[#1e2d42] text-[#7d92b0]'
                    }`}>{i + 1}</div>
                    <Avatar name={c.name} size="sm" />
                    <div className="flex-1 min-w-0">
                      <p className="text-white text-sm font-medium truncate">{c.name}</p>
                      <p className="text-[#3d5068] text-xs">{c.department}</p>
                    </div>
                    <span className="text-yellow-400 font-bold text-sm">{c.contribution_score}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Monthly Activity Trend Bar Chart */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h3 className="text-white font-semibold mb-4 flex items-center gap-2"><BarChart2 className="w-4 h-4 text-blue-400" />月次活動トレンド</h3>
              <div className="space-y-1">
                {Object.entries(MONTHLY_ACTIVITY_DATA).map(([type, counts]) => {
                  const s = ACTIVITY_STYLES[type as ActivityType]
                  return (
                    <div key={type} className="mb-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-xs ${s.text}`}>{s.label}</span>
                      </div>
                      <div className="flex items-end gap-1 h-8">
                        {counts.map((v, i) => (
                          <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                            <div className={`w-full rounded-sm ${s.bg.replace('/40', '/60')}`} style={{ height: `${(v / activityBarMax) * 32}px` }} />
                          </div>
                        ))}
                      </div>
                      <div className="flex justify-between mt-0.5">
                        {MONTHS.map(m => <span key={m} className="text-[#3d5068] text-[9px]">{m}</span>)}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Department Coverage */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <h3 className="text-white font-semibold mb-4 flex items-center gap-2"><Shield className="w-4 h-4 text-green-400" />部門カバレッジ</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['部門', 'アクティブチャンピオン数', '全チャンピオン数', 'カバー状況'].map(h => (
                      <th key={h} className="px-4 py-2 text-left text-[#7d92b0] font-medium text-xs">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {deptCoverage.map(d => {
                    const total = champions.filter(c => c.department === d.dept).length
                    return (
                      <tr key={d.dept} className="hover:bg-[#0d1525]">
                        <td className="px-4 py-2.5 text-white">{d.dept}</td>
                        <td className="px-4 py-2.5 text-white font-bold">{d.count}</td>
                        <td className="px-4 py-2.5 text-[#7d92b0]">{total}</td>
                        <td className="px-4 py-2.5">
                          {d.has
                            ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-green-900/40 text-green-300"><CheckCircle className="w-3 h-3" />カバー済み</span>
                            : <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-red-900/40 text-red-300"><AlertCircle className="w-3 h-3" />未カバー</span>
                          }
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {detailChampion && (
        <ChampionDetailModal
          champion={detailChampion}
          activities={activities}
          onClose={() => setDetailChampion(null)}
        />
      )}
      {showNominate && (
        <NominateModal
          onClose={() => setShowNominate(false)}
          onSuccess={() => showToast('チャンピオンを推薦しました')}
        />
      )}
      {showAddActivity && (
        <AddActivityModal
          champions={champions}
          onClose={() => setShowAddActivity(false)}
          onSuccess={() => showToast('活動を追加しました')}
        />
      )}
    </div>
  )
}
