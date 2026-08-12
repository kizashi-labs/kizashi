'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  BookOpen, Users, Award, Clock, AlertTriangle, Plus, ChevronDown,
  ChevronRight, ToggleLeft, ToggleRight, X, CheckCircle, BarChart2
} from 'lucide-react'


// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface TrainingProgram {
  id: string
  name: string
  type: 'awareness' | 'phishing' | 'technical' | 'compliance' | 'leadership'
  duration_min: number
  pass_score: number
  validity_days: number
  active: boolean
  description: string
  target_audience: string
  required_for_roles: string[]
  modules: string[]
}

interface Enrollment {
  id: string
  user_name: string
  program_name: string
  status: 'enrolled' | 'in_progress' | 'completed' | 'failed' | 'expired'
  progress: number
  score: number | null
  started_at: string
  completed_at: string | null
  expires_at: string | null
}

const TYPE_BADGES = { video: { label: '動画', cls: 'bg-blue-500/20 text-blue-400' }, quiz: { label: 'クイズ', cls: 'bg-purple-500/20 text-purple-400' }, simulation: { label: 'シミュレーション', cls: 'bg-orange-500/20 text-orange-400' }, live: { label: 'ライブ', cls: 'bg-red-500/20 text-red-400' }, document: { label: 'ドキュメント', cls: 'bg-gray-500/20 text-gray-400' } } as Record<string, { label: string; cls: string }>
const STATUS_BADGES = { completed: { label: '完了', cls: 'bg-green-500/20 text-green-400', pulse: false }, in_progress: { label: '進行中', cls: 'bg-blue-500/20 text-blue-400', pulse: true }, not_started: { label: '未開始', cls: 'bg-gray-500/20 text-gray-400', pulse: false }, overdue: { label: '期限超過', cls: 'bg-red-500/20 text-red-400', pulse: false } } as Record<string, { label: string; cls: string; pulse: boolean }>

// ─── Static data ─────────────────────────────────────────────────────────────

const MONTHLY_DATA: { month: string; count: number }[] = [
  { month: '11月', count: 24 }, { month: '12月', count: 31 }, { month: '1月', count: 28 },
  { month: '2月', count: 35 }, { month: '3月', count: 42 }, { month: '4月', count: 38 },
]

const EXPIRING_CERTS: { name: string; program: string; expires: string; days: number }[] = [
  { name: '田中 健一', program: 'セキュリティ基礎', expires: '2026-05-10', days: 28 },
  { name: '鈴木 美咲', program: 'フィッシング対策', expires: '2026-05-15', days: 23 },
  { name: '佐藤 雄一', program: 'インシデント対応', expires: '2026-05-20', days: 18 },
]

const DEPT_RISK: { dept: string; rate: number }[] = [
  { dept: '営業', rate: 62 },
  { dept: '人事', rate: 71 },
  { dept: 'マーケティング', rate: 68 },
]

export default function TrainingMgmtPage() {
  const [activeTab, setActiveTab] = useState<'programs' | 'enrollments' | 'stats'>('programs')
  const [expandedRow, setExpandedRow] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState('全て')
  const [showEnrollModal, setShowEnrollModal] = useState(false)
  const qc = useQueryClient()

  const { data: programs = [] } = useQuery<TrainingProgram[]>({
    queryKey: ['training-programs'],
    queryFn: () => apiFetchList<TrainingProgram>('/api/v1/admin/training/programs').catch(() => []),
  })

  const { data: enrollments = [] } = useQuery<Enrollment[]>({
    queryKey: ['training-enrollments'],
    queryFn: () => apiFetchList<Enrollment>('/api/training/enrollments').catch(() => []),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      apiFetch(`/api/v1/admin/training/programs/${id}`, { method: 'PATCH', body: JSON.stringify({ active }) }).catch(() => null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['training-programs'] }),
  })

  const stats = [
    { label: 'プログラム数',   value: programs.length,                             icon: BookOpen,       color: 'text-blue-400' },
    { label: '総受講者',       value: 342,                                          icon: Users,          color: 'text-green-400' },
    { label: '完了率',         value: '57.9%',                                      icon: CheckCircle,    color: 'text-purple-400' },
    { label: '平均スコア',     value: 84.3,                                         icon: Award,          color: 'text-yellow-400' },
    { label: '有効期限切れ間近', value: '23名',                                     icon: AlertTriangle,  color: 'text-red-400' },
  ]

  const filteredEnrollments = statusFilter === '全て' ? enrollments : enrollments.filter(e => e.status === statusFilter)

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* ヘッダー */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <BookOpen className="w-7 h-7 text-[#e8002d]" />
          <h1 className="text-2xl font-bold">セキュリティトレーニング管理</h1>
        </div>
        <button onClick={() => setShowEnrollModal(true)} className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] rounded-lg text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" /> 新規プログラム
        </button>
      </div>

      {/* 統計カード */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {stats.map(s => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-3">
            <s.icon className={`w-8 h-8 ${s.color} flex-shrink-0`} />
            <div>
              <div className="text-lg font-bold">{s.value}</div>
              <div className="text-xs text-[#7d92b0]">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* タブ */}
      <div className="flex gap-1 mb-4 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['programs', 'enrollments', 'stats'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-5 py-2 rounded-md text-sm font-medium transition-colors ${activeTab === tab ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {tab === 'programs' ? 'プログラム' : tab === 'enrollments' ? '受講状況' : '統計'}
          </button>
        ))}
      </div>

      {/* タブ1: プログラム */}
      {activeTab === 'programs' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] text-[#7d92b0]">
                {['プログラム名','タイプ','所要時間','合格スコア','有効期間','有効','アクション'].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {programs.map(p => (
                <>
                  <tr key={p.id} onClick={() => setExpandedRow(expandedRow === p.id ? null : p.id)}
                    className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/30 cursor-pointer transition-colors">
                    <td className="px-4 py-3 font-medium flex items-center gap-2">
                      {expandedRow === p.id ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />}
                      {p.name}
                    </td>
                    <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded-full text-xs ${TYPE_BADGES[p.type].cls}`}>{TYPE_BADGES[p.type].label}</span></td>
                    <td className="px-4 py-3 text-[#7d92b0]">{p.duration_min}分</td>
                    <td className="px-4 py-3 text-[#7d92b0]">{p.pass_score}点</td>
                    <td className="px-4 py-3 text-[#7d92b0]">{p.validity_days}日</td>
                    <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                      <button onClick={() => toggleMutation.mutate({ id: p.id, active: !p.active })}>
                        {p.active ? <ToggleRight className="w-6 h-6 text-green-400" /> : <ToggleLeft className="w-6 h-6 text-[#7d92b0]" />}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0]">…</td>
                  </tr>
                  {expandedRow === p.id && (
                    <tr key={`${p.id}-exp`} className="bg-[#070d19]/60 border-b border-[#1e2d42]/50">
                      <td colSpan={7} className="px-6 py-4">
                        <div className="grid grid-cols-2 gap-6">
                          <div>
                            <p className="text-xs text-[#7d92b0] mb-1">説明</p>
                            <p className="text-sm">{p.description}</p>
                            <p className="text-xs text-[#7d92b0] mt-3 mb-1">対象</p>
                            <p className="text-sm">{p.target_audience}</p>
                            <p className="text-xs text-[#7d92b0] mt-3 mb-1">必須ロール</p>
                            <div className="flex flex-wrap gap-1">{p.required_for_roles.map(r => <span key={r} className="px-2 py-0.5 bg-[#1e2d42] rounded text-xs">{r}</span>)}</div>
                          </div>
                          <div>
                            <p className="text-xs text-[#7d92b0] mb-2">モジュール</p>
                            <ul className="space-y-1">{p.modules.map((m, i) => (
                              <li key={i} className="flex items-center gap-2 text-sm"><CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />{m}</li>
                            ))}</ul>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* タブ2: 受講状況 */}
      {activeTab === 'enrollments' && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-sm text-[#7d92b0]">ステータス:</span>
              {['全て','enrolled','in_progress','completed','failed','expired'].map(s => (
                <button key={s} onClick={() => setStatusFilter(s)}
                  className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${statusFilter === s ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {s === '全て' ? '全て' : STATUS_BADGES[s]?.label ?? s}
                </button>
              ))}
            </div>
            <button onClick={() => setShowEnrollModal(true)} className="flex items-center gap-2 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#2a3f5f] rounded-lg text-sm transition-colors">
              <Plus className="w-4 h-4" /> 受講登録
            </button>
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42] text-[#7d92b0]">
                  {['受講者','プログラム名','ステータス','進捗','スコア','開始日','完了日','有効期限'].map(h => (
                    <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredEnrollments.map(e => {
                  const sb = STATUS_BADGES[e.status]
                  return (
                    <tr key={e.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                      <td className="px-4 py-3 font-medium">{e.user_name}</td>
                      <td className="px-4 py-3 text-[#7d92b0] max-w-[180px] truncate">{e.program_name}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-full text-xs flex items-center gap-1 w-fit ${sb.cls}`}>
                          {sb.pulse && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />}
                          {sb.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 w-32">
                        <div className="w-full bg-[#1e2d42] rounded-full h-1.5">
                          <div className={`h-1.5 rounded-full transition-all ${e.status === 'completed' ? 'bg-green-400' : 'bg-blue-400'}`} style={{ width: `${e.progress}%` }} />
                        </div>
                        <span className="text-xs text-[#7d92b0] mt-0.5 block">{e.progress}%</span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0]">{e.score ?? '—'}</td>
                      <td className="px-4 py-3 text-[#7d92b0]">{e.started_at}</td>
                      <td className="px-4 py-3 text-[#7d92b0]">{e.completed_at ?? '—'}</td>
                      <td className="px-4 py-3 text-[#7d92b0]">{e.expires_at ?? '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* タブ3: 統計 */}
      {activeTab === 'stats' && (
        <div className="grid grid-cols-2 gap-6">
          {/* プログラム別完了率 */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="font-semibold mb-4 flex items-center gap-2"><BarChart2 className="w-4 h-4 text-blue-400" />プログラム別完了率</h3>
            <div className="space-y-3">
              {[{ name: 'セキュリティ基礎意識向上', rate: 72 },{ name: 'フィッシングシミュレーション', rate: 58 },{ name: 'SOCアナリスト技術', rate: 45 },{ name: 'GDPR/個人情報保護', rate: 61 }].map(p => (
                <div key={p.name}>
                  <div className="flex justify-between text-xs text-[#7d92b0] mb-1"><span>{p.name}</span><span>{p.rate}%</span></div>
                  <div className="w-full bg-[#1e2d42] rounded-full h-2">
                    <div className="h-2 rounded-full bg-blue-500" style={{ width: `${p.rate}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* 月次完了トレンド */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="font-semibold mb-4 flex items-center gap-2"><BarChart2 className="w-4 h-4 text-green-400" />月次完了トレンド</h3>
            <div className="flex items-end gap-2 h-32">
              {MONTHLY_DATA.map(m => {
                const maxCount = Math.max(...MONTHLY_DATA.map(d => d.count))
                const heightPct = (m.count / maxCount) * 100
                return (
                  <div key={m.month} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs text-[#7d92b0]">{m.count}</span>
                    <div className="w-full bg-green-500/80 rounded-t" style={{ height: `${heightPct}%` }} />
                    <span className="text-xs text-[#7d92b0]">{m.month}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* 期限切れ間近 */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="font-semibold mb-4 flex items-center gap-2"><Clock className="w-4 h-4 text-orange-400" />期限切れ間近の認定 (30日以内)</h3>
            <table className="w-full text-sm">
              <thead><tr className="text-[#7d92b0] text-xs"><th className="text-left py-1">氏名</th><th className="text-left py-1">プログラム</th><th className="text-left py-1">期限</th><th className="text-left py-1">残日数</th></tr></thead>
              <tbody>{EXPIRING_CERTS.map(c => (
                <tr key={c.name} className="border-t border-[#1e2d42]/50">
                  <td className="py-2">{c.name}</td>
                  <td className="py-2 text-[#7d92b0] text-xs">{c.program}</td>
                  <td className="py-2 text-[#7d92b0]">{c.expires}</td>
                  <td className="py-2"><span className="text-orange-400 font-medium">{c.days}日</span></td>
                </tr>
              ))}</tbody>
            </table>
          </div>

          {/* リスクカバレッジ */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="font-semibold mb-4 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-red-400" />低完了率部署 (80%未満)</h3>
            <div className="space-y-3">
              {DEPT_RISK.map(d => (
                <div key={d.dept} className="flex items-center justify-between p-3 bg-red-900/20 border border-red-800/30 rounded-lg">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <span className="font-medium">{d.dept}</span>
                  </div>
                  <span className="text-red-400 font-bold">{d.rate}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 受講登録モーダル */}
      {showEnrollModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-[420px]">
            <div className="flex items-center justify-between mb-5">
              <h2 className="font-semibold text-lg">受講登録</h2>
              <button onClick={() => setShowEnrollModal(false)} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-[#7d92b0] mb-1">ユーザー</label>
                <select className="w-full bg-[#1e2d42] border border-[#2a3f5f] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]">
                  <option>田中 太郎</option><option>鈴木 花子</option><option>佐藤 次郎</option><option>山田 美咲</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-[#7d92b0] mb-1">プログラム</label>
                <select className="w-full bg-[#1e2d42] border border-[#2a3f5f] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]">
                  {programs.map(p => <option key={p.id}>{p.name}</option>)}
                </select>
              </div>
              <div className="flex gap-3 pt-2">
                <button onClick={() => setShowEnrollModal(false)} className="flex-1 px-4 py-2 bg-[#1e2d42] hover:bg-[#2a3f5f] rounded-lg text-sm transition-colors">キャンセル</button>
                <button onClick={() => setShowEnrollModal(false)} className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] rounded-lg text-sm transition-colors">登録</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
