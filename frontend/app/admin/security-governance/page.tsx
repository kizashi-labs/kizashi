'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'


type PolicyStatus = 'draft' | 'review' | 'approved' | 'published' | 'retired'
type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
type ExcStatus = 'pending' | 'approved' | 'rejected' | 'expired'

interface Policy {
  id: string; number: string; title: string; category: string; version: string
  status: PolicyStatus; owner: string; effective_date: string; review_date: string
  approval_rate: number; frameworks: string[]; related_controls: string[]
}
interface Exception {
  id: string; title: string; policy: string; risk_level: RiskLevel
  status: ExcStatus; requester: string; expires: string; approver: string
  justification: string; compensating_controls: string
}

const STATUS_STYLES: Record<PolicyStatus, string> = {
  draft: 'bg-gray-700 text-gray-300',
  review: 'bg-yellow-900 text-yellow-300',
  approved: 'bg-blue-900 text-blue-300',
  published: 'bg-green-900 text-green-300',
  retired: 'bg-gray-800 text-gray-500 line-through',
}
const EXC_STATUS_STYLES: Record<ExcStatus, string> = {
  pending: 'bg-yellow-900 text-yellow-300 animate-pulse',
  approved: 'bg-green-900 text-green-300',
  rejected: 'bg-red-900 text-red-300',
  expired: 'bg-gray-700 text-gray-400',
}
const RISK_STYLES: Record<RiskLevel, string> = {
  low: 'bg-green-900 text-green-300',
  medium: 'bg-yellow-900 text-yellow-300',
  high: 'bg-orange-900 text-orange-300',
  critical: 'bg-red-900 text-red-300',
}
const CATEGORIES = ['全て','governance','access_control','incident_response','data_management','cryptography']

export default function SecurityGovernancePage() {
  const [tab, setTab] = useState<'policy'|'exception'|'dashboard'>('policy')
  const [catFilter, setCatFilter] = useState('全て')
  const [expandedPolicy, setExpandedPolicy] = useState<string|null>(null)
  const [expandedExc, setExpandedExc] = useState<string|null>(null)

  const { data: policies = [] } = useQuery({
    queryKey: ['sg-policies'],
    queryFn: () => apiFetchList<Policy>('/api/v1/admin/security-governance/policies').catch(() => []),
  })
  const { data: exceptions = [] } = useQuery({
    queryKey: ['sg-exceptions'],
    queryFn: () => apiFetchList<Exception>('/api/v1/admin/security-governance/exceptions').catch(() => []),
  })

  const today = new Date().toISOString().slice(0,10)
  const filtered = catFilter === '全て' ? policies : policies.filter(p => p.category === catFilter)

  const TABS = [
    { key: 'policy', label: 'ポリシー管理' },
    { key: 'exception', label: '例外申請' },
    { key: 'dashboard', label: 'ダッシュボード' },
  ] as const

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">セキュリティガバナンス</h1>
            <p className="text-[#7d92b0] text-sm mt-1">ポリシー・例外申請・コンプライアンス管理</p>
          </div>
          <button className="bg-[#e8002d] hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            + 新規ポリシー
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-4 mb-6">
          {[
            { label:'総ポリシー', value:'24' },
            { label:'公開済み', value:'18', color:'text-green-400' },
            { label:'レビュー中', value:'4', color:'text-yellow-400' },
            { label:'例外申請', value:'8', color:'text-orange-400' },
            { label:'承認率', value:'94.7%', color:'text-blue-400' },
          ].map(s => (
            <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 text-center">
              <div className={`text-2xl font-bold ${s.color ?? 'text-white'}`}>{s.value}</div>
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

        {/* Tab 1: Policy Management */}
        {tab === 'policy' && (
          <div>
            <div className="flex gap-2 mb-4 flex-wrap">
              {CATEGORIES.map(c => (
                <button key={c} onClick={() => setCatFilter(c)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${catFilter === c ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {c}
                </button>
              ))}
            </div>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] text-[#7d92b0]">
                    {['ポリシー番号','タイトル','カテゴリ','バージョン','ステータス','オーナー','有効日','レビュー日','承認率','操作'].map(h => (
                      <th key={h} className="px-3 py-3 text-left text-xs font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(p => (
                    <>
                      <tr key={p.id} className="border-b border-[#1e2d42] hover:bg-[#1e2d42]/30 cursor-pointer"
                        onClick={() => setExpandedPolicy(expandedPolicy === p.id ? null : p.id)}>
                        <td className="px-3 py-3 font-mono text-xs text-[#7d92b0]">
                          <span className="flex items-center gap-1">
                            {p.review_date && p.review_date < today && <span className="w-2 h-2 rounded-full bg-red-500 inline-block" title="レビュー期限切れ" />}
                            {p.number}
                          </span>
                        </td>
                        <td className="px-3 py-3 font-medium">{p.title}</td>
                        <td className="px-3 py-3"><span className="bg-[#1e2d42] text-[#7d92b0] px-2 py-0.5 rounded text-xs">{p.category}</span></td>
                        <td className="px-3 py-3 text-[#7d92b0]">v{p.version}</td>
                        <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_STYLES[p.status]}`}>{p.status}</span></td>
                        <td className="px-3 py-3 text-[#7d92b0]">{p.owner}</td>
                        <td className="px-3 py-3 text-[#7d92b0] text-xs">{p.effective_date || '—'}</td>
                        <td className="px-3 py-3 text-xs"><span className={p.review_date < today ? 'text-red-400' : 'text-[#7d92b0]'}>{p.review_date}</span></td>
                        <td className="px-3 py-3 w-28">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 bg-[#1e2d42] rounded-full h-1.5">
                              <div className="bg-green-500 h-1.5 rounded-full" style={{ width:`${p.approval_rate}%` }} />
                            </div>
                            <span className="text-xs text-[#7d92b0] w-8">{p.approval_rate}%</span>
                          </div>
                        </td>
                        <td className="px-3 py-3">
                          <div className="flex gap-1">
                            <button className="text-xs text-blue-400 hover:text-blue-300 px-2 py-1 rounded border border-blue-900 hover:bg-blue-900/30">編集</button>
                            <button className="text-xs text-[#7d92b0] hover:text-white px-1">{expandedPolicy === p.id ? '▲' : '▼'}</button>
                          </div>
                        </td>
                      </tr>
                      {expandedPolicy === p.id && (
                        <tr key={`${p.id}-detail`} className="bg-[#070d19]">
                          <td colSpan={10} className="px-6 py-4">
                            <div className="flex gap-8 text-sm">
                              <div>
                                <div className="text-[#7d92b0] text-xs mb-1">適用フレームワーク</div>
                                <div className="flex gap-1">{p.frameworks.map(f => <span key={f} className="bg-blue-900 text-blue-300 px-2 py-0.5 rounded text-xs">{f}</span>)}</div>
                              </div>
                              <div>
                                <div className="text-[#7d92b0] text-xs mb-1">関連コントロール</div>
                                <div className="flex gap-1">{p.related_controls.map(c => <span key={c} className="bg-[#1e2d42] text-[#7d92b0] px-2 py-0.5 rounded text-xs font-mono">{c}</span>)}</div>
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
          </div>
        )}

        {/* Tab 2: Exception Requests */}
        {tab === 'exception' && (
          <div>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] text-[#7d92b0]">
                    {['タイトル','ポリシー','リスクレベル','ステータス','申請者','有効期限','承認者','操作'].map(h => (
                      <th key={h} className="px-3 py-3 text-left text-xs font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {exceptions.map(e => (
                    <>
                      <tr key={e.id} className="border-b border-[#1e2d42] hover:bg-[#1e2d42]/30 cursor-pointer"
                        onClick={() => setExpandedExc(expandedExc === e.id ? null : e.id)}>
                        <td className="px-3 py-3 font-medium">{e.title}</td>
                        <td className="px-3 py-3 text-[#7d92b0] font-mono text-xs">{e.policy}</td>
                        <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${RISK_STYLES[e.risk_level]}`}>{e.risk_level}</span></td>
                        <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium ${EXC_STATUS_STYLES[e.status]}`}>{e.status}</span></td>
                        <td className="px-3 py-3 text-[#7d92b0]">{e.requester}</td>
                        <td className="px-3 py-3 text-[#7d92b0] text-xs">{e.expires}</td>
                        <td className="px-3 py-3 text-[#7d92b0]">{e.approver}</td>
                        <td className="px-3 py-3">
                          {e.status === 'pending' ? (
                            <div className="flex gap-1">
                              <button className="text-xs bg-green-900 text-green-300 hover:bg-green-800 px-2 py-1 rounded">承認</button>
                              <button className="text-xs bg-red-900 text-red-300 hover:bg-red-800 px-2 py-1 rounded">却下</button>
                            </div>
                          ) : <span className="text-[#7d92b0] text-xs">—</span>}
                        </td>
                      </tr>
                      {expandedExc === e.id && (
                        <tr key={`${e.id}-detail`} className="bg-[#070d19]">
                          <td colSpan={8} className="px-6 py-4">
                            <div className="grid grid-cols-2 gap-6 text-sm">
                              <div>
                                <div className="text-[#7d92b0] text-xs mb-1">申請理由</div>
                                <p className="text-white">{e.justification}</p>
                              </div>
                              <div>
                                <div className="text-[#7d92b0] text-xs mb-1">補償的コントロール</div>
                                <p className="text-white">{e.compensating_controls}</p>
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
          </div>
        )}

        {/* Tab 3: Dashboard */}
        {tab === 'dashboard' && (
          <div className="grid grid-cols-2 gap-6">
            {/* Framework Coverage */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h3 className="font-semibold mb-4">フレームワーク対応状況</h3>
              <div className="space-y-3">
                {[{name:'ISO27001', pct:92, color:'bg-blue-500'},{name:'NIST CSF', pct:78, color:'bg-purple-500'},{name:'PCI-DSS', pct:85, color:'bg-orange-500'},{name:'GDPR', pct:88, color:'bg-green-500'}].map(f => (
                  <div key={f.name}>
                    <div className="flex justify-between text-sm mb-1">
                      <span className="text-[#7d92b0]">{f.name}</span>
                      <span className="text-white font-medium">{f.pct}%</span>
                    </div>
                    <div className="bg-[#1e2d42] rounded-full h-2">
                      <div className={`${f.color} h-2 rounded-full transition-all`} style={{ width:`${f.pct}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Upcoming Reviews */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h3 className="font-semibold mb-4">今後30日のレビュー予定</h3>
              <div className="space-y-2">
                {[{date:'2026-03-25',policy:'POL-003',owner:'SOCチーム'},{date:'2026-04-05',policy:'POL-001',owner:'CISO室'},{date:'2026-04-12',policy:'POL-002',owner:'IT統括部'}].map(r => (
                  <div key={r.policy} className="flex items-center gap-3 p-2 rounded bg-[#1e2d42]/30">
                    <div className="w-16 text-xs font-mono text-[#e8002d]">{r.date.slice(5)}</div>
                    <div className="flex-1">
                      <div className="text-sm font-medium">{r.policy}</div>
                      <div className="text-xs text-[#7d92b0]">{r.owner}</div>
                    </div>
                    <span className="w-2 h-2 rounded-full bg-yellow-400 flex-shrink-0" />
                  </div>
                ))}
              </div>
            </div>

            {/* Policy Lifecycle Funnel */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h3 className="font-semibold mb-4">ポリシーライフサイクル</h3>
              <div className="flex items-center gap-1 mt-6">
                {[{label:'Draft', count:2, color:'bg-gray-700', w:'w-full'},{label:'Review', count:4, color:'bg-yellow-800', w:'w-4/5'},{label:'Approved', count:6, color:'bg-blue-800', w:'w-3/5'},{label:'Published', count:18, color:'bg-green-800', w:'w-2/5'}].map((s,i) => (
                  <div key={s.label} className="flex-1 text-center">
                    <div className={`${s.color} ${i===0?'rounded-l-lg':''}${i===3?'rounded-r-lg':''} py-4 mx-px`}>
                      <div className="text-white font-bold text-lg">{s.count}</div>
                      <div className="text-xs text-white/70">{s.label}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Acknowledgment Status */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
              <h3 className="font-semibold mb-4">ポリシー承認状況</h3>
              <div className="text-center py-4">
                <div className="text-4xl font-bold text-green-400 mb-1">94.7%</div>
                <div className="text-[#7d92b0] text-sm mb-4">全スタッフの 94.7% が基本方針を承認済み</div>
                <div className="bg-[#1e2d42] rounded-full h-4 mx-4">
                  <div className="bg-green-500 h-4 rounded-full" style={{ width:'94.7%' }} />
                </div>
                <div className="flex justify-between text-xs text-[#7d92b0] mt-1 mx-4">
                  <span>承認済み: 284名</span>
                  <span>未承認: 16名</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
