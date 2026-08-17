'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GraduationCap, TrendingUp, TrendingDown, Users,
  X, Plus, AlertTriangle, Check, Send, Mail, BarChart3, Eye
} from 'lucide-react'


// ── Types ────────────────────────────────────────────────────────

type CourseCategory = 'phishing' | 'malware' | 'policy' | 'password' | 'social_engineering'

interface Course {
  id: string
  name: string
  category: CourseCategory
  completion_rate: number
  avg_score: number
  enrolled: number
  duration_min: number
  pass_rate: number
  monthly_completions: number[]
  score_buckets: number[]
  failed_users: string[]
}

interface TrainingUser {
  id: string
  name: string
  email: string
  department: string
  courses_completed: number
  courses_total: number
  avg_score: number
  last_activity: string | null
  phishing_click_rate: number
}

interface PhishingCampaign {
  id: string
  name: string
  sent: number
  clicked: number
  reported: number
  date: string
}

// ── Helpers ──────────────────────────────────────────────────────

const CATEGORY_STYLES: Record<CourseCategory, { label: string; bg: string; text: string }> = {
  phishing:          { label: 'フィッシング',     bg: 'bg-red-900/40',    text: 'text-red-300' },
  malware:           { label: 'マルウェア',        bg: 'bg-orange-900/40', text: 'text-orange-300' },
  policy:            { label: 'ポリシー',          bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  password:          { label: 'パスワード',        bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  social_engineering:{ label: 'ソーシャルエンジニアリング', bg: 'bg-purple-900/40', text: 'text-purple-300' },
}

function fmt(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit' })
}

function Avatar({ name }: { name: string }) {
  const initials = name.split(' ').map(p => p[0]?.toUpperCase() ?? '').slice(0, 2).join('')
  const colors = ['from-blue-600 to-blue-800', 'from-purple-600 to-purple-800', 'from-green-600 to-green-800', 'from-teal-600 to-teal-800']
  const color = colors[name.charCodeAt(0) % colors.length]
  return (
    <div className={`w-8 h-8 rounded-full bg-linear-to-br ${color} flex items-center justify-center shrink-0`}>
      <span className="text-xs font-bold text-white">{initials}</span>
    </div>
  )
}

// Donut SVG
function Donut({ pct, size = 48 }: { pct: number; size?: number }) {
  const r = 18, cx = 24, cy = 24
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ
  const color = pct >= 80 ? '#22c55e' : pct >= 60 ? '#eab308' : '#ef4444'
  return (
    <svg width={size} height={size} viewBox="0 0 48 48">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e2d42" strokeWidth={5} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={5}
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`} />
      <text x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fill="white" fontWeight="bold">{pct}%</text>
    </svg>
  )
}

// ── Course Detail Modal ──────────────────────────────────────────

function CourseDetailModal({ course, onClose }: { course: Course; onClose: () => void }) {
  const months = ['10月', '11月', '12月', '1月', '2月', '3月']
  const maxCompletion = Math.max(...course.monthly_completions)
  const bucketLabels = ['0-20', '21-40', '41-60', '61-80', '81-100']
  const maxBucket = Math.max(...course.score_buckets)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-falcon-surface border-b border-falcon-border px-6 py-4 flex items-center justify-between">
          <div>
            <h2 className="text-white font-semibold">{course.name}</h2>
            <span className={`text-xs px-2 py-0.5 rounded-full ${CATEGORY_STYLES[course.category].bg} ${CATEGORY_STYLES[course.category].text}`}>
              {CATEGORY_STYLES[course.category].label}
            </span>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-5">
          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            {[['修了率', `${course.completion_rate}%`], ['合格率', `${course.pass_rate}%`], ['平均スコア', `${course.avg_score}点`]].map(([k, v]) => (
              <div key={k} className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-center">
                <p className="text-xs text-falcon-muted mb-1">{k}</p>
                <p className="text-white text-xl font-bold">{v}</p>
              </div>
            ))}
          </div>

          {/* Completion trend */}
          <div className="bg-[#070d19] border border-falcon-border rounded-xl p-4">
            <p className="text-falcon-muted text-xs font-medium mb-3">修了数トレンド (6ヶ月)</p>
            <div className="flex items-end gap-2 h-20">
              {course.monthly_completions.map((v, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full bg-blue-600/60 rounded-t transition-all"
                    style={{ height: `${(v / maxCompletion) * 64}px` }} />
                  <span className="text-[10px] text-falcon-muted">{months[i]}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Score distribution */}
          <div className="bg-[#070d19] border border-falcon-border rounded-xl p-4">
            <p className="text-falcon-muted text-xs font-medium mb-3">スコア分布</p>
            <div className="space-y-2">
              {course.score_buckets.map((v, i) => (
                <div key={i} className="flex items-center gap-3">
                  <span className="text-xs text-falcon-muted w-12">{bucketLabels[i]}</span>
                  <div className="flex-1 h-4 bg-falcon-border rounded-sm overflow-hidden">
                    <div className="h-full bg-falcon-red/70 transition-all"
                      style={{ width: `${(v / maxBucket) * 100}%` }} />
                  </div>
                  <span className="text-xs text-white w-8 text-right">{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Failed users */}
          <div className="bg-[#070d19] border border-falcon-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <p className="text-falcon-muted text-xs font-medium">不合格ユーザー ({course.failed_users.length}名)</p>
              <button className="flex items-center gap-1.5 text-xs text-falcon-red hover:text-white transition-colors">
                <Send className="w-3.5 h-3.5" /> 再割り当て
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {course.failed_users.map(u => (
                <span key={u} className="text-xs bg-falcon-border text-falcon-text px-2.5 py-1 rounded-full font-mono">{u}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Assign Course Modal ──────────────────────────────────────────

function AssignModal({ users, courses, onClose, onAssign }: {
  users: TrainingUser[]
  courses: Course[]
  onClose: () => void
  onAssign: (data: { userIds: string[]; courseId: string; dueDate: string }) => void
}) {
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])
  const [courseId, setCourseId] = useState('')
  const [dueDate, setDueDate] = useState('')
  const [deptMode, setDeptMode] = useState('')

  const depts = [...new Set(users.map(u => u.department))]

  const toggleUser = (id: string) => setSelectedUsers(p => p.includes(id) ? p.filter(u => u !== id) : [...p, id])
  const selectDept = (dept: string) => {
    setDeptMode(dept)
    setSelectedUsers(users.filter(u => u.department === dept).map(u => u.id))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-falcon-surface border-b border-falcon-border px-6 py-4 flex items-center justify-between">
          <h2 className="text-white font-semibold">コース割り当て</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-2 block">対象コース</label>
            <select value={courseId} onChange={e => setCourseId(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden">
              <option value="">コースを選択...</option>
              {courses.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-2 block">期限</label>
            <input type="date" value={dueDate} onChange={e => setDueDate(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden" />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-2 block">部署一括選択</label>
            <div className="flex flex-wrap gap-2 mb-3">
              {depts.map(d => (
                <button key={d} onClick={() => selectDept(d)}
                  className={`text-xs px-3 py-1 rounded-full border transition-colors ${deptMode === d ? 'bg-falcon-red border-falcon-red text-white' : 'border-falcon-border text-falcon-muted hover:border-falcon-muted/40'}`}>
                  {d}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-2 block">ユーザー選択 ({selectedUsers.length}名選択中)</label>
            <div className="max-h-40 overflow-y-auto space-y-1 bg-[#070d19] border border-falcon-border rounded-lg p-2">
              {users.map(u => (
                <button key={u.id} onClick={() => { setDeptMode(''); toggleUser(u.id) }}
                  className={`w-full flex items-center gap-2 px-2 py-1.5 rounded text-xs transition-colors ${
                    selectedUsers.includes(u.id) ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white hover:bg-falcon-border/50'
                  }`}>
                  {selectedUsers.includes(u.id) ? <Check className="w-3 h-3 text-green-400" /> : <div className="w-3 h-3" />}
                  <span>{u.name}</span>
                  <span className="text-falcon-subtle ml-auto">{u.department}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-3 pt-2">
            <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted text-sm">キャンセル</button>
            <button
              onClick={() => { if (courseId && selectedUsers.length > 0) { onAssign({ userIds: selectedUsers, courseId, dueDate }); onClose() } }}
              disabled={!courseId || selectedUsers.length === 0}
              className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] disabled:opacity-50 transition-colors">
              割り当て ({selectedUsers.length}名)
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── New Phishing Campaign Modal ──────────────────────────────────

function NewCampaignModal({ onClose, onCreate }: { onClose: () => void; onCreate: (name: string) => void }) {
  const [name, setName] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold">新しいシミュレーション</h2>
          <button onClick={onClose}><X className="w-5 h-5 text-falcon-muted hover:text-white" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">キャンペーン名</label>
            <input value={name} onChange={e => setName(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" />
          </div>
          <p className="text-xs text-falcon-muted">フィッシングシミュレーションメールが全ユーザー (180名) に送信されます。</p>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted text-sm">キャンセル</button>
          <button onClick={() => { if (name) { onCreate(name); onClose() } }}
            className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e]">作成</button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function TrainingAnalyticsPage() {
  const [section, setSection] = useState<'courses' | 'users'>('courses')
  const [selectedCourse, setSelectedCourse] = useState<Course | null>(null)
  const [showAssign, setShowAssign] = useState(false)
  const [showNewCampaign, setShowNewCampaign] = useState(false)
  const [campaigns, setCampaigns] = useState<PhishingCampaign[]>([])

  const { data: coursesData } = useQuery<Course[]>({
    queryKey: ['training-courses'],
    queryFn: () => apiFetch('/api/v1/admin/training/courses'),
    onError: () => {},
  } as any)

  const { data: usersData } = useQuery<TrainingUser[]>({
    queryKey: ['training-users'],
    queryFn: () => apiFetch('/api/v1/admin/training/users'),
    onError: () => {},
  } as any)

  const { data: campaignsData } = useQuery<PhishingCampaign[]>({
    queryKey: ['training-phishing'],
    queryFn: () => apiFetch('/api/v1/admin/training/phishing-campaigns'),
    onError: () => {},
  } as any)

  const courses: Course[] = (coursesData as Course[]) ?? []
  const users: TrainingUser[] = (usersData as TrainingUser[]) ?? []

  const avgCompletion = courses.length ? Math.round(courses.reduce((s, c) => s + (c.completion_rate ?? 0), 0) / courses.length) : 0
  const avgScore = users.length ? Math.round(users.reduce((s, u) => s + (u.avg_score ?? 0), 0) / users.length) : 0
  const avgPhishClick = users.length ? Math.round(users.reduce((s, u) => s + (u.phishing_click_rate ?? 0), 0) / users.length) : 0
  const atRisk = users.filter(u => u.phishing_click_rate > 30).length

  // Department summary
  const departments = [...new Set(users.map(u => u.department))]
  const deptStats = departments.map(dept => {
    const dUsers = users.filter(u => u.department === dept)
    return {
      dept,
      count: dUsers.length,
      completion: dUsers.length ? Math.round(dUsers.reduce((s, u) => s + ((u.courses_total ? u.courses_completed / u.courses_total : 0) * 100), 0) / dUsers.length) : 0,
      avgScore: dUsers.length ? Math.round(dUsers.reduce((s, u) => s + (u.avg_score ?? 0), 0) / dUsers.length) : 0,
      highestRisk: Math.max(...dUsers.map(u => u.phishing_click_rate)),
    }
  }).sort((a, b) => b.highestRisk - a.highestRisk)

  const handleAssign = async (data: { userIds: string[]; courseId: string; dueDate: string }) => {
    try { await apiFetch('/api/v1/admin/training/assign', { method: 'POST', body: JSON.stringify(data) }) }
    catch {}
  }

  const handleNewCampaign = (name: string) => {
    const newC: PhishingCampaign = { id: String(Date.now()), name, sent: 180, clicked: 0, reported: 0, date: new Date().toISOString().slice(0, 10) }
    setCampaigns(p => [newC, ...p])
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
          <GraduationCap className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-2xl font-bold">セキュリティトレーニング分析</h1>
          <p className="text-falcon-muted text-sm">セキュリティ意識向上トレーニングの進捗と分析</p>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
          <p className="text-falcon-muted text-xs mb-2">平均修了率</p>
          <p className="text-3xl font-bold text-green-400">{avgCompletion}%</p>
          <p className="text-xs text-green-400 mt-1 flex items-center gap-1"><TrendingUp className="w-3 h-3" />前四半期比 +8%</p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
          <p className="text-falcon-muted text-xs mb-2">平均スコア</p>
          <p className="text-3xl font-bold text-blue-400">{avgScore}<span className="text-lg text-falcon-muted">点</span></p>
          <p className="text-xs text-blue-400 mt-1 flex items-center gap-1"><TrendingUp className="w-3 h-3" />前四半期比 +5点</p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
          <p className="text-falcon-muted text-xs mb-2">フィッシングクリック率</p>
          <p className="text-3xl font-bold text-orange-400">{avgPhishClick}%</p>
          <p className="text-xs text-green-400 mt-1 flex items-center gap-1"><TrendingDown className="w-3 h-3" />前四半期比 -6%</p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
          <p className="text-falcon-muted text-xs mb-2">要注意ユーザー (click {'>'}{' '}30%)</p>
          <p className="text-3xl font-bold text-red-400">{atRisk}</p>
          <p className="text-xs text-falcon-muted mt-1 flex items-center gap-1"><AlertTriangle className="w-3 h-3 text-red-400" />即時対応推奨</p>
        </div>
      </div>

      {/* Section Tabs */}
      <div className="flex gap-2 mb-6">
        {[{ key: 'courses', label: 'コース分析' }, { key: 'users', label: 'ユーザー進捗' }].map(t => (
          <button key={t.key} onClick={() => setSection(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              section === t.key ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
            }`}>{t.label}</button>
        ))}
      </div>

      {/* Courses Section */}
      {section === 'courses' && (
        <div className="grid grid-cols-3 gap-4">
          {courses.map(course => {
            const cs = CATEGORY_STYLES[course.category]
            return (
              <div key={course.id} className="bg-falcon-surface border border-falcon-border rounded-xl p-5 hover:border-[#2a3f5a] transition-colors">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0 mr-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${cs.bg} ${cs.text} mb-2 inline-block`}>{cs.label}</span>
                    <h3 className="text-white text-sm font-semibold leading-tight">{course.name}</h3>
                  </div>
                  <Donut pct={course.completion_rate} />
                </div>
                <div className="grid grid-cols-3 gap-2 mb-4 text-center">
                  <div className="bg-[#070d19] rounded-sm p-2">
                    <p className="text-xs text-falcon-muted">平均スコア</p>
                    <p className="text-white text-sm font-bold">{course.avg_score}</p>
                  </div>
                  <div className="bg-[#070d19] rounded-sm p-2">
                    <p className="text-xs text-falcon-muted">受講者数</p>
                    <p className="text-white text-sm font-bold">{course.enrolled}</p>
                  </div>
                  <div className="bg-[#070d19] rounded-sm p-2">
                    <p className="text-xs text-falcon-muted">時間</p>
                    <p className="text-white text-sm font-bold">{course.duration_min}分</p>
                  </div>
                </div>
                <button onClick={() => setSelectedCourse(course)}
                  className="w-full py-2 bg-[#070d19] border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/40 rounded-sm text-sm transition-colors">
                  詳細を見る
                </button>
              </div>
            )
          })}
        </div>
      )}

      {/* Users Section */}
      {section === 'users' && (
        <div className="space-y-5">
          {/* Actions */}
          <div className="flex items-center justify-between">
            <p className="text-falcon-muted text-sm">{users.length}名のユーザー</p>
            <button onClick={() => setShowAssign(true)}
              className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" /> コース割り当て
            </button>
          </div>

          {/* User Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['ユーザー', '部署', '進捗', '平均スコア', '最終活動', 'フィッシングCR', 'リスク', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <Avatar name={u.name} />
                        <div>
                          <p className="text-white text-xs font-medium">{u.name}</p>
                          <p className="text-falcon-muted text-xs">{u.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-falcon-text">{u.department}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-white">{u.courses_completed}/{u.courses_total}</span>
                        <div className="w-16 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                          <div className="h-full bg-blue-500 transition-all" style={{ width: `${(u.courses_completed / u.courses_total) * 100}%` }} />
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-white font-bold">{u.avg_score || '—'}</td>
                    <td className="px-4 py-3 text-xs text-falcon-muted">{fmt(u.last_activity)}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-bold ${u.phishing_click_rate > 30 ? 'text-red-400' : u.phishing_click_rate > 10 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {u.phishing_click_rate}%
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {u.phishing_click_rate > 30 && (
                        <span className="text-xs bg-red-900/40 text-red-300 px-2 py-0.5 rounded-full font-medium">要注意</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <button onClick={() => setShowAssign(true)}
                          className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors" title="コース割り当て">
                          <GraduationCap className="w-3.5 h-3.5" />
                        </button>
                        <button className="p-1.5 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors" title="リマインダー送信">
                          <Mail className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Department Summary */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">部署別サマリー</h3>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['部署', '人数', '修了率', '平均スコア', '最高フィッシング率', 'リスクレベル'].map(h => (
                      <th key={h} className="text-left text-xs text-falcon-muted font-medium px-3 py-2">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {deptStats.map(d => (
                    <tr key={d.dept} className="border-b border-falcon-border/50">
                      <td className="px-3 py-2.5 text-white text-sm font-medium">{d.dept}</td>
                      <td className="px-3 py-2.5 text-xs text-falcon-muted">{d.count}名</td>
                      <td className="px-3 py-2.5">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                            <div className={`h-full transition-all ${d.completion >= 80 ? 'bg-green-500' : d.completion >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`}
                              style={{ width: `${d.completion}%` }} />
                          </div>
                          <span className="text-xs text-white">{d.completion}%</span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5 text-xs text-white font-bold">{d.avgScore}</td>
                      <td className="px-3 py-2.5">
                        <span className={`text-xs font-bold ${d.highestRisk > 50 ? 'text-red-400' : d.highestRisk > 20 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {d.highestRisk}%
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        {d.highestRisk > 50
                          ? <span className="text-xs bg-red-900/40 text-red-300 px-2 py-0.5 rounded-full">高リスク</span>
                          : d.highestRisk > 20
                          ? <span className="text-xs bg-yellow-900/40 text-yellow-300 px-2 py-0.5 rounded-full">中リスク</span>
                          : <span className="text-xs bg-green-900/40 text-green-300 px-2 py-0.5 rounded-full">低リスク</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Phishing Campaigns */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-semibold text-sm">フィッシングシミュレーション</h3>
              <button onClick={() => setShowNewCampaign(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-falcon-red/20 border border-falcon-red/40 text-falcon-red rounded-sm text-xs hover:bg-falcon-red/30 transition-colors">
                <Plus className="w-3.5 h-3.5" /> 新しいシミュレーション
              </button>
            </div>
            <div className="space-y-3">
              {campaigns.map(c => {
                const clickRate = c.sent > 0 ? Math.round((c.clicked / c.sent) * 100) : 0
                const reportRate = c.sent > 0 ? Math.round((c.reported / c.sent) * 100) : 0
                return (
                  <div key={c.id} className="flex items-center gap-4 bg-[#070d19] border border-falcon-border rounded-lg p-4">
                    <div className="flex-1 min-w-0">
                      <p className="text-white text-sm font-medium truncate">{c.name}</p>
                      <p className="text-falcon-muted text-xs mt-0.5">{c.date} · {c.sent}名送信</p>
                    </div>
                    <div className="flex items-center gap-6">
                      <div className="text-center">
                        <p className={`text-lg font-bold ${clickRate > 30 ? 'text-red-400' : clickRate > 15 ? 'text-yellow-400' : 'text-green-400'}`}>{clickRate}%</p>
                        <p className="text-[10px] text-falcon-muted">クリック率</p>
                      </div>
                      <div className="text-center">
                        <p className="text-lg font-bold text-blue-400">{reportRate}%</p>
                        <p className="text-[10px] text-falcon-muted">報告率</p>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {selectedCourse && <CourseDetailModal course={selectedCourse} onClose={() => setSelectedCourse(null)} />}
      {showAssign && <AssignModal users={users} courses={courses} onClose={() => setShowAssign(false)} onAssign={handleAssign} />}
      {showNewCampaign && <NewCampaignModal onClose={() => setShowNewCampaign(false)} onCreate={handleNewCampaign} />}
    </div>
  )
}
