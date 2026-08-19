'use client'



import { useState } from 'react'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { apiFetch } from '@/lib/api'



import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

function fmtBytes(b: number) {

  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB'

  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'

  return (b / 1e3).toFixed(1) + ' KB'

}

function fmtTime(iso: string) { return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }) }



const SEV_BADGE: Record<string, string> = {

  critical: 'bg-red-900/60 text-red-300 border border-red-700',

  high: 'bg-orange-900/60 text-orange-300 border border-orange-700',

  medium: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700',

  low: 'bg-blue-900/60 text-blue-300 border border-blue-700',

}

const THREAT_BADGE: Record<string, string> = {

  C2: 'bg-red-800 text-red-200',

  Port_Scan: 'bg-orange-800 text-orange-200',

  DNS_Tunneling: 'bg-purple-800 text-purple-200',

  Lateral_Movement: 'bg-pink-900 text-pink-200',

  Data_Exfiltration: 'border border-red-600 text-red-400',

}

const STATUS_BADGE: Record<string, string> = {

  open: 'bg-red-900/50 text-red-300',

  investigating: 'bg-yellow-900/50 text-yellow-300',

  resolved: 'bg-green-900/50 text-green-300',

}

const RULE_TYPE_BADGE: Record<string, string> = {

  signature: 'bg-blue-900/60 text-blue-300',

  behavioral: 'bg-green-900/60 text-green-300',

  ml: 'bg-purple-900/60 text-purple-300',

  threshold: 'bg-orange-900/60 text-orange-300',

}

const PROTOCOL_COLORS = ['bg-blue-500','bg-cyan-500','bg-green-500','bg-yellow-500','bg-purple-500','bg-gray-500']



export default function NTAPage() {

  const [tab, setTab] = useState<'detections'|'rules'|'flows'>('detections')

  const [sevFilter, setSevFilter] = useState('全て')

  const [statusFilter, setStatusFilter] = useState('全て')

  const [ruleTypeFilter, setRuleTypeFilter] = useState('全て')

  const [expandedRow, setExpandedRow] = useState<string|null>(null)

  const qc = useQueryClient()



  const { data: detections = [] } = useQuery<any[]>({

    queryKey: ['nta-detections'],

    queryFn: () => apiFetch<any[]>('/api/nta/detections'),

  })

  const { data: rules = [] } = useQuery<any[]>({

    queryKey: ['nta-rules'],

    queryFn: () => apiFetch<any[]>('/api/nta/rules'),

  })

  const EMPTY_FLOWS = { top_talkers: [] as { hostname: string; bytes_sent: number; bytes_recv: number; connections: number }[], protocol_dist: [] as { protocol: string; pct: number }[], hourly: [] as number[] }
  type FlowsData = typeof EMPTY_FLOWS
  const { data: flows = EMPTY_FLOWS } = useQuery<FlowsData>({

    queryKey: ['nta-flows'],

    queryFn: () => apiFetch<FlowsData>('/api/nta/flows'),

  })

  const investigateMutation = useMutation({

    mutationFn: (id: string) => apiFetch(`/api/nta/detections/${id}/investigate`, { method: 'POST' }),

    onSuccess: () => qc.invalidateQueries({ queryKey: ['nta-detections'] }),

  })



  const filteredDetections = detections.filter((d: any) =>

    (sevFilter === '全て' || d.severity === sevFilter) &&

    (statusFilter === '全て' || d.status === statusFilter)

  )

  const filteredRules = rules.filter(r => ruleTypeFilter === '全て' || r.type === ruleTypeFilter)

  const maxHourly = flows.hourly.length > 0 ? Math.max(...flows.hourly) : 1



  const STATS = [

    { label: 'アクティブルール', value: '23' }, { label: '本日検知', value: '156' },

    { label: 'クリティカル', value: '8', red: true }, { label: '高', value: '34', orange: true },

    { label: '分析フロー数', value: '4.8M' },

  ]



  return (

    <div className="min-h-screen bg-[#070d19] text-white p-6">
      <PageDataUnavailable />

      <PageSaveFailed />
      <h1 className="text-2xl font-bold mb-1">ネットワーク脅威分析 <span className="text-[#7d92b0] text-base font-normal">(NTA)</span></h1>

      <p className="text-[#7d92b0] text-sm mb-6">ネットワークトラフィックのリアルタイム脅威検知・分析</p>



      {/* Stats */}

      <div className="grid grid-cols-5 gap-3 mb-6">

        {STATS.map(s => (

          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">

            <div className={`text-2xl font-bold ${s.red ? 'text-red-400' : s.orange ? 'text-orange-400' : 'text-white'}`}>{s.value}</div>

            <div className="text-[#7d92b0] text-xs mt-1">{s.label}</div>

          </div>

        ))}

      </div>



      {/* Tabs */}

      <div className="flex gap-1 mb-6 border-b border-[#1e2d42]">

        {[['detections','脅威検知'],['rules','ルール管理'],['flows','フロー分析']].map(([key,label]) => (

          <button key={key} onClick={() => setTab(key as typeof tab)}

            className={`px-5 py-2.5 text-sm font-medium transition-colors ${tab === key ? 'border-b-2 border-[#e8002d] text-white' : 'text-[#7d92b0] hover:text-white'}`}>

            {label}

          </button>

        ))}

      </div>



      {/* Tab 1: Detections */}

      {tab === 'detections' && (

        <div>

          <div className="flex gap-3 mb-4 flex-wrap">

            <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}

              className="bg-[#0d1220] border border-[#1e2d42] text-white text-sm rounded-sm px-3 py-1.5">

              {['全て','critical','high','medium','low'].map((v: any) => <option key={v}>{v}</option>)}

            </select>

            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}

              className="bg-[#0d1220] border border-[#1e2d42] text-white text-sm rounded-sm px-3 py-1.5">

              {['全て','open','investigating','resolved'].map((v: any) => <option key={v}>{v}</option>)}

            </select>

            <span className="text-[#7d92b0] text-sm self-center">{filteredDetections.length} 件</span>

          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">

            <table className="w-full text-sm">

              <thead><tr className="border-b border-[#1e2d42]">

                {['検知時刻','ソースIP','宛先IP','ポート','プロトコル','脅威タイプ','深刻度','信頼度','ステータス',''].map(h => (

                  <th key={h} className="text-left text-[#7d92b0] text-xs font-medium px-3 py-3">{h}</th>

                ))}

              </tr></thead>

              <tbody>

                {filteredDetections.map((d: any) => (

                  <>

                    <tr key={d.id} onClick={() => setExpandedRow(expandedRow === d.id ? null : d.id)}

                      className="border-b border-[#1e2d42] hover:bg-[#1e2d42]/30 cursor-pointer transition-colors">

                      <td className="px-3 py-3 text-[#7d92b0] whitespace-nowrap">{fmtTime(d.detected_at)}</td>

                      <td className="px-3 py-3 font-mono text-xs">{d.src_ip}</td>

                      <td className="px-3 py-3 font-mono text-xs">{d.dst_ip}</td>

                      <td className="px-3 py-3 text-[#7d92b0]">{d.port}</td>

                      <td className="px-3 py-3 text-[#7d92b0]">{d.protocol}</td>

                      <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${THREAT_BADGE[d.threat_type] || 'bg-gray-700 text-gray-300'}`}>{d.threat_type.replace('_',' ')}</span></td>

                      <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${SEV_BADGE[d.severity]}`}>{d.severity}</span></td>

                      <td className="px-3 py-3 w-32">

                        <div className="flex items-center gap-2">

                          <div className="flex-1 bg-[#1e2d42] rounded-full h-1.5">

                            <div className="h-1.5 rounded-full bg-blue-500" style={{ width: `${d.confidence}%` }}/>

                          </div>

                          <span className="text-xs text-[#7d92b0] w-8">{d.confidence}%</span>

                        </div>

                      </td>

                      <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs ${STATUS_BADGE[d.status]}`}>{d.status}</span></td>

                      <td className="px-3 py-3">

                        {d.status === 'open' && (

                          <button onClick={e => { e.stopPropagation(); investigateMutation.mutate(d.id) }}

                            className="px-2 py-1 bg-[#e8002d]/20 border border-[#e8002d]/40 text-[#e8002d] text-xs rounded-sm hover:bg-[#e8002d]/30 whitespace-nowrap">

                            調査開始

                          </button>

                        )}

                      </td>

                    </tr>

                    {expandedRow === d.id && (

                      <tr key={`${d.id}-expand`} className="bg-[#0a1628]">

                        <td colSpan={10} className="px-6 py-4">

                          <div className="grid grid-cols-5 gap-4 text-sm">

                            {[['ユーザー',d.metadata.user],['ホスト名',d.metadata.hostname],['転送量',fmtBytes(d.metadata.bytes)],['継続時間',d.metadata.duration],['適用ルール',d.metadata.rule]].map(([k,v]) => (

                              <div key={k}><div className="text-[#7d92b0] text-xs mb-1">{k}</div><div className="font-medium text-sm">{v}</div></div>

                            ))}

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



      {/* Tab 2: Rules */}

      {tab === 'rules' && (

        <div>

          <div className="flex items-center gap-3 mb-4">

            <div className="flex gap-1">

              {['全て','signature','behavioral','ml','threshold'].map((t: any) => (

                <button key={t} onClick={() => setRuleTypeFilter(t)}

                  className={`px-3 py-1.5 text-xs rounded-sm transition-colors ${ruleTypeFilter === t ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>{t}</button>

              ))}

            </div>

            <button className="ml-auto px-3 py-1.5 bg-[#e8002d] text-white text-xs rounded-sm hover:bg-[#c0001f]">+ 新規ルール</button>

          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">

            <table className="w-full text-sm">

              <thead><tr className="border-b border-[#1e2d42]">

                {['ルール名','タイプ','プロトコル','深刻度','有効','ヒット数','誤検知率','最終トリガー'].map(h => (

                  <th key={h} className="text-left text-[#7d92b0] text-xs font-medium px-3 py-3">{h}</th>

                ))}

              </tr></thead>

              <tbody>

                {filteredRules.map((r: any) => (

                  <tr key={r.id} className="border-b border-[#1e2d42] hover:bg-[#1e2d42]/20">

                    <td className="px-3 py-3 font-mono text-xs">{r.name}</td>

                    <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs ${RULE_TYPE_BADGE[r.type]}`}>{r.type}</span></td>

                    <td className="px-3 py-3 text-[#7d92b0]">{r.protocol}</td>

                    <td className="px-3 py-3"><span className={`px-2 py-0.5 rounded-sm text-xs ${SEV_BADGE[r.severity]}`}>{r.severity}</span></td>

                    <td className="px-3 py-3">

                      <div className={`w-10 h-5 rounded-full transition-colors cursor-pointer ${r.enabled ? 'bg-green-600' : 'bg-[#1e2d42]'}`}>

                        <div className={`w-4 h-4 rounded-full bg-[#e2e8f4] m-0.5 transition-transform ${r.enabled ? 'translate-x-5' : ''}`}/>

                      </div>

                    </td>

                    <td className="px-3 py-3">{r.hits}</td>

                    <td className="px-3 py-3 text-[#7d92b0]">{(r.fp_rate * 100).toFixed(0)}%</td>

                    <td className="px-3 py-3 text-[#7d92b0] text-xs">{fmtTime(r.last_trigger)}</td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        </div>

      )}



      {/* Tab 3: Flows */}

      {tab === 'flows' && (

        <div className="grid grid-cols-2 gap-6">

          <div>

            <h3 className="text-sm font-semibold mb-3 text-[#7d92b0]">トップ送受信者</h3>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">

              <table className="w-full text-sm">

                <thead><tr className="border-b border-[#1e2d42]">

                  {['ホスト名','送信','受信','接続数'].map(h => <th key={h} className="text-left text-[#7d92b0] text-xs px-3 py-2">{h}</th>)}

                </tr></thead>

                <tbody>{flows.top_talkers.map((t: any) => (

                  <tr key={t.hostname} className="border-b border-[#1e2d42]">

                    <td className="px-3 py-2 font-mono text-xs">{t.hostname}</td>

                    <td className="px-3 py-2 text-blue-400">{fmtBytes(t.bytes_sent)}</td>

                    <td className="px-3 py-2 text-green-400">{fmtBytes(t.bytes_recv)}</td>

                    <td className="px-3 py-2 text-[#7d92b0]">{t.connections}</td>

                  </tr>

                ))}</tbody>

              </table>

            </div>

            <h3 className="text-sm font-semibold mb-3 mt-6 text-[#7d92b0]">プロトコル分布</h3>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 space-y-2">

              {flows.protocol_dist.map((p: any, i: any) => (

                <div key={p.protocol} className="flex items-center gap-3">

                  <div className="w-16 text-xs text-[#7d92b0] text-right">{p.protocol}</div>

                  <div className="flex-1 bg-[#1e2d42] rounded-full h-4">

                    <div className={`h-4 rounded-full ${PROTOCOL_COLORS[i]} flex items-center justify-end pr-2`} style={{ width: `${p.pct}%` }}>

                      <span className="text-white text-xs font-medium">{p.pct}%</span>

                    </div>

                  </div>

                </div>

              ))}

            </div>

          </div>

          <div>

            <h3 className="text-sm font-semibold mb-3 text-[#7d92b0]">トラフィックトレンド (24時間)</h3>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">

              <div className="flex items-end gap-1 h-32">

                {flows.hourly.map((v, i) => (

                  <div key={i} className="flex-1 flex flex-col items-center gap-1">

                    <div className="w-full bg-blue-500/70 hover:bg-blue-500 rounded-t transition-colors"

                      style={{ height: `${(v / maxHourly) * 112}px` }} title={`${i}:00 — ${v}K flows`}/>

                  </div>

                ))}

              </div>

              <div className="flex justify-between text-[#7d92b0] text-xs mt-2">

                <span>0:00</span><span>6:00</span><span>12:00</span><span>18:00</span><span>23:00</span>

              </div>

            </div>

          </div>

        </div>

      )}

    </div>

  )

}

