'use client'



import { useState } from 'react'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'



function fmtTime(iso: string) { return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }



const CATEGORY_META: Record<string, { label: string; icon: string; badge: string }> = {

  Credential_Stuffing: { label: 'クレデンシャルスタッフィング', icon: '🔑', badge: 'bg-red-900/60 text-red-300 border border-red-700' },

  Impossible_Travel: { label: '不可能移動', icon: '✈', badge: 'bg-orange-900/60 text-orange-300 border border-orange-700' },

  MFA_Bypass: { label: 'MFAバイパス', icon: '🔒', badge: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700' },

  Privileged_Account_Anomaly: { label: '特権アカウント異常', icon: '👑', badge: 'bg-red-900/60 text-red-300 border border-red-700' },

}

const SEV_BADGE: Record<string, string> = {

  critical: 'bg-red-900/60 text-red-300 border border-red-700',

  high: 'bg-orange-900/60 text-orange-300 border border-orange-700',

  medium: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700',

}

const STATUS_BADGE: Record<string, string> = {

  open: 'bg-red-900/50 text-red-300',

  investigating: 'bg-yellow-900/50 text-yellow-300',

  resolved: 'bg-green-900/50 text-green-300',

}

const RISK_BORDER: Record<string, string> = {

  critical: 'border-red-600', high: 'border-orange-500', medium: 'border-yellow-500', low: 'border-green-500',

}

const RISK_COLOR = (score: number) => score >= 80 ? 'text-red-400' : score >= 60 ? 'text-orange-400' : score >= 40 ? 'text-yellow-400' : 'text-green-400'

const ACCOUNT_BADGE: Record<string, string> = {

  admin: 'bg-purple-900/60 text-purple-300',

  service: 'bg-blue-900/60 text-blue-300',

  standard: 'bg-gray-700 text-gray-300',

}



export default function ITDRPage() {

  const [tab, setTab] = useState<'incidents'|'users'|'rules'>('incidents')

  const [statusFilter, setStatusFilter] = useState('全て')

  const [userSort, setUserSort] = useState('risk')

  const [selectedIncident, setSelectedIncident] = useState<string|null>(null)

  const qc = useQueryClient()



  const { data: incidents = [] } = useQuery<any[]>({

    queryKey: ['itdr-incidents'],

    queryFn: () => apiFetch<any[]>('/api/itdr/incidents').catch(() => []),

  })

  const { data: users = [] } = useQuery<any[]>({

    queryKey: ['itdr-users'],

    queryFn: () => apiFetch<any[]>('/api/itdr/users/risky').catch(() => []),

  })

  const { data: rules = [] } = useQuery<any[]>({

    queryKey: ['itdr-rules'],

    queryFn: () => apiFetch<any[]>('/api/itdr/rules').catch(() => []),

  })

  const investigateMutation = useMutation({

    mutationFn: (id: string) => apiFetch(`/api/itdr/incidents/${id}/investigate`, { method: 'POST' }).catch(() => ({})),

    onSuccess: () => { qc.invalidateQueries({ queryKey: ['itdr-incidents'] }); setSelectedIncident(null) },

  })

  const fpMutation = useMutation({

    mutationFn: (id: string) => apiFetch(`/api/itdr/incidents/${id}/false-positive`, { method: 'POST' }).catch(() => ({})),

    onSuccess: () => { qc.invalidateQueries({ queryKey: ['itdr-incidents'] }); setSelectedIncident(null) },

  })

  const lockMutation = useMutation({

    mutationFn: (id: string) => apiFetch(`/api/itdr/users/${id}/lock`, { method: 'POST' }).catch(() => ({})),

  })



  const filteredIncidents = incidents.filter((i: any) => statusFilter === '全て' || i.status === statusFilter)

  const sortedUsers = [...users].sort((a, b) => userSort === 'risk' ? b.risk_score - a.risk_score : userSort === 'privileged' ? (b.privileged ? 1 : 0) - (a.privileged ? 1 : 0) : 0)

  const selectedInc = incidents.find((i: any) => i.id === selectedIncident)



  const STATS = [

    { label: 'アクティブルール', value: '18' }, { label: '本日インシデント', value: '7', red: true },

    { label: '高リスクユーザー', value: '8', orange: true }, { label: '監視対象特権ユーザー', value: '45' },

    { label: '平均リスクスコア', value: '4.2' },

  ]



  return (

    <div className="min-h-screen bg-[#070d19] text-white p-6">

      <h1 className="text-2xl font-bold mb-1">アイデンティティ脅威検知 <span className="text-falcon-muted text-base font-normal">(ITDR)</span></h1>

      <p className="text-falcon-muted text-sm mb-6">ユーザーアイデンティティへの脅威検知・リスク評価・対応</p>



      {/* Stats */}

      <div className="grid grid-cols-5 gap-3 mb-6">

        {STATS.map(s => (

          <div key={s.label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">

            <div className={`text-2xl font-bold ${s.red ? 'text-red-400' : s.orange ? 'text-orange-400' : 'text-white'}`}>{s.value}</div>

            <div className="text-falcon-muted text-xs mt-1">{s.label}</div>

          </div>

        ))}

      </div>



      {/* Tabs */}

      <div className="flex gap-1 mb-6 border-b border-falcon-border">

        {[['incidents','インシデント'],['users','リスクユーザー'],['rules','検知ルール']].map(([key,label]) => (

          <button key={key} onClick={() => setTab(key as typeof tab)}

            className={`px-5 py-2.5 text-sm font-medium transition-colors ${tab === key ? 'border-b-2 border-falcon-red text-white' : 'text-falcon-muted hover:text-white'}`}>

            {label}

          </button>

        ))}

      </div>



      {/* Tab 1: Incidents */}

      {tab === 'incidents' && (

        <div className="flex gap-6">

          <div className="flex-1">

            <div className="flex gap-2 mb-4">

              {['全て','open','investigating','resolved'].map(s => (

                <button key={s} onClick={() => setStatusFilter(s)}

                  className={`px-3 py-1.5 text-xs rounded-sm transition-colors ${statusFilter === s ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white border border-falcon-border'}`}>{s}</button>

              ))}

              <span className="text-falcon-muted text-sm self-center ml-2">{filteredIncidents.length} 件</span>

            </div>

            <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">

              <table className="w-full text-sm">

                <thead><tr className="border-b border-falcon-border">

                  {['検知時刻','ユーザー名','脅威カテゴリ','リスクスコア','深刻度','ステータス','インジケーター'].map(h => (

                    <th key={h} className="text-left text-falcon-muted text-xs font-medium px-3 py-3">{h}</th>

                  ))}

                </tr></thead>

                <tbody>

                  {filteredIncidents.map(inc => {

                    const cm = CATEGORY_META[inc.category]

                    return (

                      <tr key={inc.id} onClick={() => setSelectedIncident(selectedIncident === inc.id ? null : inc.id)}

                        className={`border-b border-falcon-border hover:bg-falcon-border/30 cursor-pointer transition-colors ${selectedIncident === inc.id ? 'bg-falcon-border/40' : ''}`}>

                        <td className="px-3 py-3 text-falcon-muted text-xs whitespace-nowrap">{fmtTime(inc.detected_at)}</td>

                        <td className="px-3 py-3 font-medium text-xs">{inc.username}</td>

                        <td className="px-3 py-3">

                          <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${cm?.badge || 'bg-gray-700 text-gray-300'}`}>

                            {cm?.icon} {cm?.label || inc.category}

                          </span>

                        </td>

                        <td className="px-3 py-3"><span className={`text-xl font-bold ${RISK_COLOR(inc.risk_score)}`}>{inc.risk_score}</span></td>

                        <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs ${SEV_BADGE[inc.severity]}`}>{inc.severity}</span></td>

                        <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs ${STATUS_BADGE[inc.status]}`}>{inc.status}</span></td>

                        <td className="px-3 py-3">

                          <div className="flex flex-wrap gap-1">

                            {inc.indicators.slice(0,2).map((ind: any) => (

                              <span key={ind} className="bg-falcon-border text-falcon-muted text-xs px-1.5 py-0.5 rounded-sm">{ind}</span>

                            ))}

                            {inc.indicators.length > 2 && <span className="text-falcon-muted text-xs">+{inc.indicators.length - 2}</span>}

                          </div>

                        </td>

                      </tr>

                    )

                  })}

                </tbody>

              </table>

            </div>

          </div>



          {/* Detail panel */}

          {selectedInc && (

            <div className="w-72 bg-falcon-surface border border-falcon-border rounded-lg p-4 shrink-0 self-start">

              <div className="flex items-center justify-between mb-3">

                <h3 className="font-semibold text-sm">インシデント詳細</h3>

                <button onClick={() => setSelectedIncident(null)} className="text-falcon-muted hover:text-white text-lg">×</button>

              </div>

              <div className="text-xs text-falcon-muted mb-1">ユーザー</div>

              <div className="font-medium text-sm mb-3">{selectedInc.username}</div>

              <div className="text-xs text-falcon-muted mb-2">インジケーター</div>

              <ul className="space-y-1 mb-4">

                {selectedInc.indicators.map((ind: any) => (

                  <li key={ind} className="flex items-start gap-2 text-xs">

                    <span className="text-falcon-red mt-0.5">•</span>{ind}

                  </li>

                ))}

              </ul>

              <div className="text-xs text-falcon-muted mb-2">タイムライン</div>

              <ul className="space-y-1 mb-5">

                {selectedInc.timeline.map((t: any) => (

                  <li key={t} className="text-xs text-falcon-muted flex gap-2">

                    <span className="text-blue-400">→</span>{t}

                  </li>

                ))}

              </ul>

              <div className="flex gap-2">

                <button onClick={() => investigateMutation.mutate(selectedInc.id)}

                  className="flex-1 py-1.5 bg-falcon-red text-white text-xs rounded-sm hover:bg-[#c0001f]">調査開始</button>

                <button onClick={() => fpMutation.mutate(selectedInc.id)}

                  className="flex-1 py-1.5 border border-falcon-border text-falcon-muted text-xs rounded-sm hover:text-white">偽陽性</button>

              </div>

            </div>

          )}

        </div>

      )}



      {/* Tab 2: Risky Users */}

      {tab === 'users' && (

        <div>

          <div className="flex items-center gap-3 mb-4">

            <span className="text-falcon-muted text-sm">並べ替え:</span>

            {[['risk','リスクスコア順'],['privileged','特権アカウント'],['recent','最近の活動']].map(([k,l]) => (

              <button key={k} onClick={() => setUserSort(k)}

                className={`px-3 py-1.5 text-xs rounded-sm ${userSort === k ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'}`}>{l}</button>

            ))}

          </div>

          <div className="grid grid-cols-2 gap-4">

            {sortedUsers.map(u => (

              <div key={u.id} className={`bg-falcon-surface border-2 ${RISK_BORDER[u.risk_level]} rounded-lg p-5`}>

                <div className="flex items-start justify-between mb-3">

                  <div>

                    <div className="flex items-center gap-2">

                      <span className="font-medium text-sm">{u.username}</span>

                      {u.privileged && <span title="特権アカウント">👑</span>}

                    </div>

                    <span className={`text-xs px-2 py-0.5 rounded-sm mt-1 inline-block ${ACCOUNT_BADGE[u.account_type]}`}>{u.account_type}</span>

                  </div>

                  <div className="relative w-14 h-14 shrink-0">

                    <svg viewBox="0 0 36 36" className="w-14 h-14 -rotate-90">

                      <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1e2d42" strokeWidth="3"/>

                      <circle cx="18" cy="18" r="15.9" fill="none"

                        stroke={u.risk_score >= 80 ? '#ef4444' : u.risk_score >= 60 ? '#f97316' : '#eab308'}

                        strokeWidth="3" strokeDasharray={`${u.risk_score} ${100 - u.risk_score}`} strokeLinecap="round"/>

                    </svg>

                    <div className="absolute inset-0 flex items-center justify-center">

                      <span className={`text-sm font-bold ${RISK_COLOR(u.risk_score)}`}>{u.risk_score}</span>

                    </div>

                  </div>

                </div>

                <div className="flex flex-wrap gap-1 mb-4">

                  {u.risk_factors.map((f: any) => (

                    <span key={f} className="bg-falcon-border text-falcon-muted text-xs px-2 py-0.5 rounded-sm">{f}</span>

                  ))}

                </div>

                <div className="flex gap-2">

                  <button className="flex-1 py-1.5 border border-falcon-border text-falcon-muted text-xs rounded-sm hover:text-white">詳細</button>

                  <button onClick={() => lockMutation.mutate(u.id)}

                    className="flex-1 py-1.5 bg-red-900/40 border border-red-700 text-red-300 text-xs rounded-sm hover:bg-red-900/60">

                    アカウントロック

                  </button>

                </div>

              </div>

            ))}

          </div>

        </div>

      )}



      {/* Tab 3: Rules */}

      {tab === 'rules' && (

        <div>

          <div className="flex justify-end mb-4">

            <button className="px-3 py-1.5 bg-falcon-red text-white text-xs rounded-sm hover:bg-[#c0001f]">+ 新規ルール</button>

          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">

            <table className="w-full text-sm">

              <thead><tr className="border-b border-falcon-border">

                {['ルール名','脅威カテゴリ','深刻度','MITREテクニック','有効','ヒット数'].map(h => (

                  <th key={h} className="text-left text-falcon-muted text-xs font-medium px-3 py-3">{h}</th>

                ))}

              </tr></thead>

              <tbody>

                {rules.map((r: any) => {

                  const cm = CATEGORY_META[r.category]

                  return (

                    <tr key={r.id} className="border-b border-falcon-border hover:bg-falcon-border/20">

                      <td className="px-3 py-3 font-medium text-sm">{r.name}</td>

                      <td className="px-3 py-3">

                        <span className={`px-2 py-0.5 rounded-sm text-xs ${cm?.badge || 'bg-gray-700 text-gray-300'}`}>

                          {cm?.icon} {r.category}

                        </span>

                      </td>

                      <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs ${SEV_BADGE[r.severity]}`}>{r.severity}</span></td>

                      <td className="px-3 py-3">

                        <div className="flex gap-1 flex-wrap">

                          {r.mitre.map((t: any) => <span key={t} className="bg-blue-900/40 text-blue-300 text-xs px-1.5 py-0.5 rounded-sm font-mono">{t}</span>)}

                        </div>

                      </td>

                      <td className="px-3 py-3">

                        <div className={`w-10 h-5 rounded-full ${r.enabled ? 'bg-green-600' : 'bg-falcon-border'}`}>

                          <div className={`w-4 h-4 rounded-full bg-falcon-text m-0.5 transition-transform ${r.enabled ? 'translate-x-5' : ''}`}/>

                        </div>

                      </td>

                      <td className="px-3 py-3">{r.hits}</td>

                    </tr>

                  )

                })}

              </tbody>

            </table>

          </div>

        </div>

      )}

    </div>

  )

}

