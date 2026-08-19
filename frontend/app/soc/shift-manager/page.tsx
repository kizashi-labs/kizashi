'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { mockOr } from '@/lib/mock'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

type Role = 'lead' | 'senior' | 'analyst' | 'trainee'
type AnalystStatus = 'active' | 'break' | 'offline'

interface Analyst {
  id: string; name: string; role: Role; specialty: string
  tickets: number; status: AnalystStatus; response_time: string
  skills: Record<string, number>
}
interface ShiftSlot { analyst_id: string; shift: string }
interface HandoverReport { id: string; date: string; shift_name: string; written_by: string; open_items: number; notes: string }

const ANALYSTS: Analyst[] = [
  { id:'a1', name:'田中 一郎', role:'lead',    specialty:'マルウェア分析', tickets:5,  status:'active',  response_time:'2.1分', skills:{malware:5,forensics:4,siem:5,network:4,cloud:3} },
  { id:'a2', name:'鈴木 花子', role:'senior',  specialty:'フォレンジック', tickets:8,  status:'active',  response_time:'3.4分', skills:{malware:4,forensics:5,siem:4,network:3,cloud:4} },
  { id:'a3', name:'山田 太郎', role:'analyst', specialty:'SIEM運用',       tickets:6,  status:'active',  response_time:'4.2分', skills:{malware:3,forensics:2,siem:5,network:4,cloud:3} },
  { id:'a4', name:'佐藤 次郎', role:'analyst', specialty:'ネットワーク',   tickets:4,  status:'break',   response_time:'5.1分', skills:{malware:2,forensics:3,siem:3,network:5,cloud:2} },
  { id:'a5', name:'高橋 美咲', role:'senior',  specialty:'クラウドセキュリティ', tickets:7, status:'active', response_time:'3.8分', skills:{malware:3,forensics:3,siem:4,network:3,cloud:5} },
  { id:'a6', name:'渡辺 健',   role:'analyst', specialty:'脅威ハンティング', tickets:5, status:'active',  response_time:'4.5分', skills:{malware:4,forensics:3,siem:3,network:4,cloud:3} },
  { id:'a7', name:'伊藤 真',   role:'trainee', specialty:'研修中',         tickets:2,  status:'active',  response_time:'8.2分', skills:{malware:1,forensics:1,siem:2,network:2,cloud:1} },
  { id:'a8', name:'小林 愛',   role:'analyst', specialty:'SOC運用',        tickets:6,  status:'offline', response_time:'—',    skills:{malware:3,forensics:2,siem:4,network:3,cloud:3} },
]
const MOCK_REPORTS: HandoverReport[] = [
  { id:'r1', date:'2026-03-17', shift_name:'夕方シフト', written_by:'高橋 美咲', open_items:3, notes:'ランサムウェア疑いのアラート継続監視中。エスカレーション済み。' },
  { id:'r2', date:'2026-03-17', shift_name:'昼シフト',   written_by:'田中 一郎', open_items:1, notes:'フィッシングキャンペーン検知。IOC共有済み。' },
]
const DAYS = ['月','火','水','木','金','土','日']
const SHIFTS = ['早朝 06:00-12:00','昼 12:00-18:00','夕方 18:00-24:00','深夜 00:00-06:00']
const ROLE_COLORS: Record<Role, string> = { lead:'bg-red-900 text-red-300', senior:'bg-blue-900 text-blue-300', analyst:'bg-green-900 text-green-300', trainee:'bg-gray-700 text-gray-300' }
const STATUS_COLORS: Record<AnalystStatus, string> = { active:'text-green-400', break:'text-yellow-400', offline:'text-gray-500' }
const STATUS_LABELS: Record<AnalystStatus, string> = { active:'稼働中', break:'休憩中', offline:'オフライン' }
const SKILL_HEADERS = ['Malware分析','フォレンジック','SIEM','ネットワーク','クラウド']
const SKILL_KEYS = ['malware','forensics','siem','network','cloud']

const SCHEDULE: Record<string, Record<string, string>> = {
  '早朝 06:00-12:00': {'月':'田中 一郎','火':'高橋 美咲','水':'田中 一郎','木':'鈴木 花子','金':'高橋 美咲','土':'山田 太郎','日':'佐藤 次郎'},
  '昼 12:00-18:00':  {'月':'鈴木 花子','火':'山田 太郎','水':'高橋 美咲','木':'田中 一郎','金':'山田 太郎','土':'伊藤 真','日':'渡辺 健'},
  '夕方 18:00-24:00':{'月':'山田 太郎','火':'佐藤 次郎','水':'渡辺 健','木':'高橋 美咲','金':'田中 一郎','土':'小林 愛','日':'田中 一郎'},
  '深夜 00:00-06:00':{'月':'渡辺 健','火':'伊藤 真','水':'佐藤 次郎','木':'渡辺 健','金':'佐藤 次郎','土':'','日':''},
}

function roleColor(name: string): string {
  const a = ANALYSTS.find(x => x.name === name)
  return a ? ROLE_COLORS[a.role] : 'bg-gray-700 text-gray-400'
}
function skillDot(score: number) {
  if (score >= 5) return 'bg-green-500'
  if (score >= 4) return 'bg-blue-500'
  if (score >= 3) return 'bg-yellow-500'
  if (score >= 2) return 'bg-orange-500'
  return 'bg-gray-600'
}

export default function ShiftManagerPage() {
  const [tab, setTab] = useState<'schedule'|'current'|'handover'|'staffing'>('schedule')
  const [weekOffset, setWeekOffset] = useState(0)
  const [handoverView, setHandoverView] = useState<'current'|'previous'>('current')
  const [assignTarget, setAssignTarget] = useState<string|null>(null)
  const [showEndConfirm, setShowEndConfirm] = useState(false)
  const [reportNotes, setReportNotes] = useState('')

  const { data: analysts = mockOr(ANALYSTS, []) } = useQuery({
    queryKey: ['shift-analysts'],
    queryFn: () => apiFetchList<Analyst>('/api/soc/shift-manager/analysts'),
  })
  const { data: reports = [] } = useQuery({
    queryKey: ['handover-reports'],
    queryFn: () => apiFetchList<HandoverReport>('/api/soc/shift-manager/reports'),
  })

  const submitReport = useMutation({
    mutationFn: (data: { notes: string }) => apiFetch('/api/soc/shift-manager/reports', { method:'POST', body: JSON.stringify(data) }),
  })

  const TABS = [
    { key:'schedule', label:'シフトスケジュール' },
    { key:'current',  label:'現在のシフト' },
    { key:'handover', label:'引継ぎレポート' },
    { key:'staffing', label:'要員計画' },
  ] as const

  const weekLabel = weekOffset === 0 ? '今週' : weekOffset === 1 ? '来週' : `${weekOffset}週後`

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">SOCシフト管理</h1>
            <p className="text-[#7d92b0] text-sm mt-1">シフトスケジュール・引継ぎ・要員計画</p>
          </div>
          <button className="bg-[#e8002d] hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm font-medium">
            シフト追加
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label:'本日勤務', value:'8人', color:'text-green-400' },
            { label:'現在のシフトリーダー', value:'田中 一郎', color:'text-blue-400' },
            { label:'アクティブチケット', value:'47', color:'text-orange-400' },
            { label:'未割り当て', value:'12', color:'text-red-400' },
          ].map(s => (
            <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 text-center">
              <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-[#7d92b0] text-xs mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 border-b border-[#1e2d42]">
          {TABS.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${tab === t.key ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'}`}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab 1: Schedule */}
        {tab === 'schedule' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <button onClick={() => setWeekOffset(w => w-1)} className="text-[#7d92b0] hover:text-white px-3 py-1 border border-[#1e2d42] rounded-sm">◀</button>
                <span className="font-medium">{weekLabel} (2026-03-{16+weekOffset*7}〜)</span>
                <button onClick={() => setWeekOffset(w => w+1)} className="text-[#7d92b0] hover:text-white px-3 py-1 border border-[#1e2d42] rounded-sm">▶</button>
              </div>
              <div className="flex gap-3 text-xs">
                {(Object.entries(ROLE_COLORS) as [Role, string][]).map(([r, cls]) => (
                  <span key={r} className={`px-2 py-0.5 rounded-sm ${cls}`}>{r}</span>
                ))}
              </div>
            </div>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="px-3 py-3 text-left text-xs text-[#7d92b0] w-40">シフト</th>
                    {DAYS.map(d => <th key={d} className="px-2 py-3 text-center text-xs text-[#7d92b0] w-28">{d}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {SHIFTS.map(shift => (
                    <tr key={shift} className="border-b border-[#1e2d42]">
                      <td className="px-3 py-3 text-xs text-[#7d92b0]">{shift}</td>
                      {DAYS.map(day => {
                        const name = SCHEDULE[shift]?.[day] ?? ''
                        return (
                          <td key={day} className="px-2 py-3 text-center">
                            {name ? <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${roleColor(name)}`}>{name}</span>
                              : <span className="text-[#1e2d42]">—</span>}
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 2: Current Shift */}
        {tab === 'current' && (
          <div className="space-y-5">
            <div className="bg-blue-900/30 border border-blue-700 rounded-lg p-4 flex items-center justify-between">
              <div>
                <div className="font-semibold text-blue-300">昼シフト稼働中</div>
                <div className="text-[#7d92b0] text-sm">12:00 〜 18:00 ｜ シフトリーダー: 田中 一郎</div>
              </div>
              <button onClick={() => setShowEndConfirm(true)} className="bg-[#e8002d] hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm">シフト終了</button>
            </div>
            {showEndConfirm && (
              <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 flex items-center justify-between">
                <span className="text-red-300">シフトを終了しますか？引継ぎレポートが必要です。</span>
                <div className="flex gap-2">
                  <button onClick={() => setShowEndConfirm(false)} className="px-3 py-1 border border-[#1e2d42] rounded-sm text-sm text-[#7d92b0]">キャンセル</button>
                  <button className="px-3 py-1 bg-red-700 rounded-sm text-sm text-white">確認して終了</button>
                </div>
              </div>
            )}
            <div className="grid grid-cols-3 gap-4">
              {[{label:'Critical', count:3, color:'text-red-400', border:'border-red-900'},{label:'High', count:12, color:'text-orange-400', border:'border-orange-900'},{label:'Medium', count:32, color:'text-yellow-400', border:'border-yellow-900'}].map(a => (
                <div key={a.label} className={`bg-[#0d1220] border ${a.border} rounded-lg p-4 text-center`}>
                  <div className={`text-3xl font-bold ${a.color}`}>{a.count}</div>
                  <div className="text-[#7d92b0] text-sm">{a.label}</div>
                </div>
              ))}
            </div>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] text-[#7d92b0]">
                    {['名前','ロール','専門','割り当てチケット','ステータス','応答時間','クイック割り当て'].map(h => (
                      <th key={h} className="px-3 py-3 text-left text-xs">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {analysts.filter(a => a.status !== 'offline').map(a => (
                    <tr key={a.id} className="border-b border-[#1e2d42] hover:bg-[#1e2d42]/20">
                      <td className="px-3 py-3 font-medium">{a.name}</td>
                      <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs ${ROLE_COLORS[a.role]}`}>{a.role}</span></td>
                      <td className="px-3 py-3 text-[#7d92b0] text-xs">{a.specialty}</td>
                      <td className="px-3 py-3 text-center font-mono">{a.tickets}</td>
                      <td className="px-3 py-3"><span className={`text-xs font-medium ${STATUS_COLORS[a.status]}`}>{STATUS_LABELS[a.status]}</span></td>
                      <td className="px-3 py-3 text-[#7d92b0] text-xs font-mono">{a.response_time}</td>
                      <td className="px-3 py-3">
                        {assignTarget === a.id ? (
                          <select className="bg-[#1e2d42] text-white text-xs rounded-sm px-2 py-1 border border-[#1e2d42]" onChange={() => setAssignTarget(null)}>
                            <option>-- アラート選択 --</option>
                            <option>ALERT-2891 (Critical)</option>
                            <option>ALERT-2888 (High)</option>
                          </select>
                        ) : (
                          <button onClick={() => setAssignTarget(a.id)} className="text-xs bg-blue-900 text-blue-300 hover:bg-blue-800 px-2 py-1 rounded-sm">割り当て</button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 3: Handover Report */}
        {tab === 'handover' && (
          <div className="space-y-5">
            <div className="flex gap-2">
              {(['current','previous'] as const).map(v => (
                <button key={v} onClick={() => setHandoverView(v)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${handoverView === v ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {v === 'current' ? '現在の引継ぎ' : '過去のレポート'}
                </button>
              ))}
            </div>
            {handoverView === 'current' ? (
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5 space-y-4">
                <h3 className="font-semibold">引継ぎレポート作成 — 昼シフト 2026-03-18</h3>
                <div>
                  <div className="text-[#7d92b0] text-sm mb-2">オープンインシデント</div>
                  <div className="space-y-1">
                    {['INC-441: ランサムウェア疑い (Critical)','INC-438: 不審なログイン試行 (High)','INC-435: データ流出アラート (High)'].map(inc => (
                      <label key={inc} className="flex items-center gap-2 text-sm cursor-pointer hover:text-white text-[#7d92b0]">
                        <input type="checkbox" className="accent-[#e8002d]" />{inc}
                      </label>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-[#7d92b0] text-sm mb-2">引継ぎメモ・次シフトへのブリーフィング</div>
                  <textarea value={reportNotes} onChange={e => setReportNotes(e.target.value)}
                    className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-sm text-white placeholder-[#7d92b0] focus:outline-hidden focus:border-[#e8002d] h-28 resize-none"
                    placeholder="次のシフトへの引継ぎ事項を記入してください..." />
                </div>
                <button onClick={() => submitReport.mutate({ notes: reportNotes })}
                  className="bg-[#e8002d] hover:bg-red-700 text-white px-5 py-2 rounded-lg text-sm font-medium">
                  引継ぎレポート送信
                </button>
              </div>
            ) : (
              <div className="space-y-3">
                {reports.map(r => (
                  <div key={r.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                    <div className="flex justify-between items-start mb-2">
                      <div>
                        <span className="font-medium">{r.shift_name}</span>
                        <span className="text-[#7d92b0] text-sm ml-3">{r.date}</span>
                      </div>
                      <span className="bg-orange-900 text-orange-300 text-xs px-2 py-0.5 rounded-sm">{r.open_items}件未解決</span>
                    </div>
                    <div className="text-xs text-[#7d92b0] mb-1">作成者: {r.written_by}</div>
                    <p className="text-sm text-[#7d92b0]">{r.notes}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Staffing Plan */}
        {tab === 'staffing' && (
          <div className="space-y-6">
            {/* Monthly bar chart */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h3 className="font-semibold mb-4">月別要員数 vs 必要人数</h3>
              <div className="flex items-end gap-2 h-32">
                {['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月'].map((m, i) => {
                  const actual = [7,7,8,8,9,9,10,10,10,10,10,10][i]
                  const required = [9,9,9,10,10,10,10,10,10,10,10,10][i]
                  const maxH = 10; const scale = (v: number) => Math.round((v/maxH)*100)
                  return (
                    <div key={m} className="flex-1 flex flex-col items-center gap-1">
                      <div className="w-full flex gap-0.5 items-end h-24">
                        <div className="flex-1 bg-blue-600 rounded-t" style={{ height:`${scale(actual)}%` }} title={`実際: ${actual}人`} />
                        <div className="flex-1 bg-[#1e2d42] rounded-t border border-dashed border-[#7d92b0]" style={{ height:`${scale(required)}%` }} title={`必要: ${required}人`} />
                      </div>
                      <span className="text-[#7d92b0] text-xs">{m}</span>
                    </div>
                  )
                })}
              </div>
              <div className="flex gap-4 mt-2 text-xs text-[#7d92b0]">
                <span><span className="inline-block w-3 h-3 bg-blue-600 rounded-sm mr-1" />実際の人数</span>
                <span><span className="inline-block w-3 h-3 bg-[#1e2d42] border border-dashed border-[#7d92b0] rounded-sm mr-1" />必要人数</span>
              </div>
            </div>

            {/* Skills matrix */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-[#1e2d42]"><h3 className="font-semibold">スキルマトリクス</h3></div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] text-[#7d92b0]">
                    <th className="px-4 py-2 text-left text-xs">アナリスト</th>
                    {SKILL_HEADERS.map(h => <th key={h} className="px-3 py-2 text-center text-xs">{h}</th>)}
                    <th className="px-3 py-2 text-center text-xs">スコア</th>
                  </tr>
                </thead>
                <tbody>
                  {analysts.map(a => {
                    const total = SKILL_KEYS.reduce((s,k) => s + (a.skills[k] ?? 0), 0)
                    return (
                      <tr key={a.id} className="border-b border-[#1e2d42] hover:bg-[#1e2d42]/20">
                        <td className="px-4 py-2">
                          <div className="font-medium text-sm">{a.name}</div>
                          <span className={`text-xs px-1.5 py-0.5 rounded-sm ${ROLE_COLORS[a.role]}`}>{a.role}</span>
                        </td>
                        {SKILL_KEYS.map(k => (
                          <td key={k} className="px-3 py-2 text-center">
                            <div className="flex justify-center gap-0.5">
                              {[1,2,3,4,5].map(v => (
                                <span key={v} className={`w-2.5 h-2.5 rounded-full ${v <= (a.skills[k]??0) ? skillDot(a.skills[k]??0) : 'bg-[#1e2d42]'}`} />
                              ))}
                            </div>
                          </td>
                        ))}
                        <td className="px-3 py-2 text-center font-mono text-sm font-bold">{total}<span className="text-[#7d92b0] text-xs">/25</span></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Hiring plan */}
            <div className="grid grid-cols-2 gap-4">
              {[
                { title:'シニアSOCアナリスト', status:'面接中', applicants:5, color:'text-yellow-400', border:'border-yellow-900' },
                { title:'SOCアナリスト (クラウド専門)', status:'募集中', applicants:12, color:'text-green-400', border:'border-green-900' },
              ].map(pos => (
                <div key={pos.title} className={`bg-[#0d1220] border ${pos.border} rounded-lg p-4`}>
                  <div className="flex justify-between items-start mb-2">
                    <div className="font-medium">{pos.title}</div>
                    <span className={`text-xs font-medium ${pos.color}`}>{pos.status}</span>
                  </div>
                  <div className="text-[#7d92b0] text-sm">応募者数: <span className="text-white font-medium">{pos.applicants}名</span></div>
                  <button className="mt-3 text-xs text-blue-400 hover:text-blue-300 border border-blue-900 px-3 py-1 rounded-sm hover:bg-blue-900/30">詳細を見る</button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
