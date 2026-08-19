'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Lock, Plus, ToggleLeft, ToggleRight,
  AlertTriangle, CheckCircle, Shield,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { SaveFailed, saveErrorOf } from '@/lib/persist'

// ─── Types ────────────────────────────────────────────────────────────────────

type EncType = 'full_disk' | 'removable' | 'folder' | 'email' | 'file'
type EnforceMode = 'enforce' | 'monitor' | 'audit'
type EncStatus = 'encrypted' | 'partial' | 'unencrypted' | 'unknown'

interface EncPolicy {
  id: string; name: string; type: EncType; algorithm: string
  mode: EnforceMode; target_endpoints: number; compliance_rate: number; enabled: boolean
}
interface EndpointEnc {
  id: string; hostname: string; status: EncStatus; algorithm: string
  compliance: boolean; last_checked: string; selected?: boolean
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const encTypeCls: Record<EncType, string> = {
  full_disk: 'bg-blue-900/40 text-blue-300 border-blue-700/50',
  removable: 'bg-orange-900/40 text-orange-300 border-orange-700/50',
  folder:    'bg-green-900/40 text-green-300 border-green-700/50',
  email:     'bg-purple-900/40 text-purple-300 border-purple-700/50',
  file:      'bg-gray-700/40 text-gray-400 border-gray-600/50',
}
const statusCls: Record<EncStatus, string> = {
  encrypted:   'bg-green-900/40 text-green-300 border-green-700/50',
  partial:     'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  unencrypted: 'bg-red-900/40 text-red-300 border-red-700/50',
  unknown:     'bg-gray-700/40 text-gray-400 border-gray-600/50',
}
const statusLabel: Record<EncStatus, string> = {
  encrypted: '暗号化済み', partial: '部分暗号化',
  unencrypted: '未暗号化', unknown: '不明',
}

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EncryptionMgmtPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'policies' | 'endpoints'>('policies')
  const [statusFilter, setStatusFilter] = useState<EncStatus | '全て'>('全て')
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const { data: policies = [] } = useQuery<EncPolicy[]>({
    queryKey: ['enc-policies'],
    queryFn: () => apiFetchList<EncPolicy>('/api/v1/admin/encryption/policies'),
    staleTime: 30_000,
  })

  const { data: endpoints = [] } = useQuery<EndpointEnc[]>({
    queryKey: ['enc-endpoints'],
    queryFn: () => apiFetchList<EndpointEnc>('/api/v1/admin/encryption/endpoints'),
    staleTime: 30_000,
  })

  const togglePolicy = useMutation({
    mutationFn: (id: string) =>
      // .catch(() => null) で失敗が成功になっていました。
      // /api/v1/admin/encryption/* にはサーバ側のルートがありません。
      apiFetch(`/api/v1/admin/encryption/policies/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['enc-policies'] }),
  })

  const forceEncrypt = useMutation({
    mutationFn: (ids: string[]) =>
      // 「暗号化を強制」も同じで、押すと選択が解除され一覧が再取得され、
      // 実行されたように見えます。何も実行されていません。
      apiFetch('/api/v1/admin/encryption/enforce', { method: 'POST', body: JSON.stringify({ endpoint_ids: ids }) }),
    onSuccess: () => { setSelected(new Set()); qc.invalidateQueries({ queryKey: ['enc-endpoints'] }) },
  })

  const filteredEndpoints = endpoints.filter(e =>
    statusFilter === '全て' ? true : e.status === statusFilter
  )

  const unencryptedEps = endpoints.filter(e => e.status === 'unencrypted')
  const toggleSelect = (id: string) => {
    setSelected(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s })
  }
  const selectAllUnencrypted = () => {
    setSelected(new Set(unencryptedEps.map(e => e.id)))
  }

  // Stats
  const totalEps = 210
  const encryptedEps = 198
  const partialEps = 8
  const unencEps = 4
  const complianceRate = 94.3

  const STATS = [
    { label: '総エンドポイント', value: totalEps.toString(), color: 'text-white', bg: 'bg-[#0d1220] border-[#1e2d42]' },
    { label: '暗号化済み', value: encryptedEps.toString(), color: 'text-green-400', bg: 'bg-green-900/20 border-green-700/30' },
    { label: '部分暗号化', value: partialEps.toString(), color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-700/30' },
    { label: '未暗号化', value: unencEps.toString(), color: 'text-red-400', bg: 'bg-red-900/20 border-red-700/30' },
    { label: 'コンプライアンス率', value: `${complianceRate}%`, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-700/30' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <PageDataUnavailable />
      <SaveFailed error={saveErrorOf('暗号化ポリシー', togglePolicy, forceEncrypt)} />
      <div className="max-w-[1400px] mx-auto px-6 py-6">

        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
              <Lock className="w-4 h-4 text-white" />
            </div>
            <h1 className="text-2xl font-bold">暗号化管理</h1>
          </div>
          <p className="text-[#7d92b0] text-sm ml-11">エンドポイントの暗号化ポリシーと適用状況を管理します</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-4 mb-6">
          {STATS.map(s => (
            <div key={s.label} className={`rounded-xl p-4 border ${s.bg}`}>
              <p className="text-xs text-[#7d92b0] mb-1">{s.label}</p>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-5 border-b border-[#1e2d42]">
          {([['policies', '暗号化ポリシー'], ['endpoints', 'エンドポイント状況']] as const).map(([k, label]) => (
            <button key={k} onClick={() => setTab(k)}
              className={`px-5 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${tab === k ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'}`}>
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab: Policies ── */}
        {tab === 'policies' && (
          <div>
            <div className="flex justify-end mb-4">
              <button className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors">
                <Plus className="w-4 h-4" /> 新規ポリシー
              </button>
            </div>

            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ポリシー名', '暗号化タイプ', 'アルゴリズム', '強制モード', '対象EP', 'コンプライアンス率', '有効'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {policies.map(p => (
                    <tr key={p.id} className="border-b border-[#1e2d42]/50 hover:bg-[#131d31]/50 transition-colors">
                      <td className="px-4 py-3 text-white font-medium">{p.name}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border ${encTypeCls[p.type]}`}>
                          {p.type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] font-mono text-xs">{p.algorithm}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border capitalize ${p.mode === 'enforce' ? 'bg-red-900/40 text-red-300 border-red-700/50' : p.mode === 'monitor' ? 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50' : 'bg-gray-700/40 text-gray-400 border-gray-600/50'}`}>
                          {p.mode}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0]">{p.target_endpoints}</td>
                      <td className="px-4 py-3 min-w-[160px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-[#1e2d42] rounded-full h-1.5">
                            <div className={`h-1.5 rounded-full ${p.compliance_rate >= 90 ? 'bg-green-400' : p.compliance_rate >= 70 ? 'bg-yellow-400' : 'bg-red-400'}`}
                              style={{ width: `${p.compliance_rate}%` }} />
                          </div>
                          <span className={`text-xs font-medium w-10 text-right ${p.compliance_rate >= 90 ? 'text-green-400' : p.compliance_rate >= 70 ? 'text-yellow-400' : 'text-red-400'}`}>
                            {p.compliance_rate}%
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => togglePolicy.mutate(p.id)}>
                          {p.enabled
                            ? <ToggleRight className="w-6 h-6 text-green-400 hover:text-green-300 transition-colors" />
                            : <ToggleLeft className="w-6 h-6 text-[#3d5068] hover:text-[#7d92b0] transition-colors" />}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Tab: Endpoint Status ── */}
        {tab === 'endpoints' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex gap-2">
                {(['全て', 'encrypted', 'partial', 'unencrypted'] as const).map(s => (
                  <button key={s} onClick={() => setStatusFilter(s)}
                    className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${statusFilter === s ? 'bg-[#e8002d] border-[#e8002d] text-white' : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                    {s === '全て' ? '全て' : statusLabel[s]}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-3">
                {unencryptedEps.length > 0 && (
                  <button onClick={selectAllUnencrypted}
                    className="text-xs text-[#7d92b0] hover:text-white transition-colors underline">
                    未暗号化をすべて選択
                  </button>
                )}
                {selected.size > 0 && (
                  <button onClick={() => forceEncrypt.mutate([...selected])}
                    className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors">
                    <Shield className="w-4 h-4" /> 強制暗号化 ({selected.size})
                  </button>
                )}
              </div>
            </div>

            <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="w-10 px-4 py-3" />
                    {['ホスト名', 'エンドポイントID', 'ステータス', 'アルゴリズム', 'コンプライアンス', '最終確認', 'アクション'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredEndpoints.map(e => (
                    <tr key={e.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#131d31]/50 transition-colors ${selected.has(e.id) ? 'bg-[#131d31]/70' : ''}`}>
                      <td className="px-4 py-3">
                        {e.status === 'unencrypted' && (
                          <input type="checkbox" checked={selected.has(e.id)} onChange={() => toggleSelect(e.id)}
                            className="accent-[#e8002d] w-4 h-4 cursor-pointer" />
                        )}
                      </td>
                      <td className="px-4 py-3 text-white font-medium">{e.hostname}</td>
                      <td className="px-4 py-3 text-[#7d92b0] font-mono text-xs">{e.id}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border ${statusCls[e.status]}`}>
                          {statusLabel[e.status]}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] font-mono text-xs">{e.algorithm}</td>
                      <td className="px-4 py-3">
                        {e.compliance
                          ? <span className="flex items-center gap-1 text-xs text-green-400"><CheckCircle className="w-3.5 h-3.5" /> 準拠</span>
                          : <span className="flex items-center gap-1 text-xs text-red-400"><AlertTriangle className="w-3.5 h-3.5" /> 非準拠</span>}
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{fmtDate(e.last_checked)}</td>
                      <td className="px-4 py-3">
                        {e.status !== 'encrypted' && (
                          <button onClick={() => forceEncrypt.mutate([e.id])}
                            className="flex items-center gap-1 px-3 py-1 text-xs bg-[#e8002d]/20 hover:bg-[#e8002d]/40 text-red-300 border border-red-700/50 rounded-lg transition-colors">
                            <Lock className="w-3 h-3" /> 暗号化
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Compliance Donut (CSS only) ── */}
        <div className="mt-8 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-6">
          <p className="text-xs text-[#7d92b0] uppercase tracking-widest mb-6">コンプライアンス概要</p>
          <div className="flex items-center gap-12">
            {/* Donut */}
            <div className="relative shrink-0">
              <div className="w-36 h-36 rounded-full flex items-center justify-center"
                style={{ background: `conic-gradient(#22c55e 0% ${complianceRate}%, #ef4444 ${complianceRate}% ${complianceRate + (partialEps / totalEps * 100)}%, #374151 ${complianceRate + (partialEps / totalEps * 100)}% 100%)` }}>
                <div className="w-24 h-24 rounded-full bg-[#0d1220] flex flex-col items-center justify-center">
                  <p className="text-2xl font-bold text-white">{complianceRate}%</p>
                  <p className="text-xs text-[#7d92b0]">準拠率</p>
                </div>
              </div>
            </div>

            {/* Legend */}
            <div className="space-y-3 flex-1">
              {[
                { label: '暗号化済み (準拠)', value: encryptedEps, color: 'bg-green-400', pct: Math.round(encryptedEps / totalEps * 100) },
                { label: '部分暗号化', value: partialEps, color: 'bg-yellow-400', pct: Math.round(partialEps / totalEps * 100) },
                { label: '未暗号化', value: unencEps, color: 'bg-red-400', pct: Math.round(unencEps / totalEps * 100) },
              ].map(item => (
                <div key={item.label} className="flex items-center gap-3">
                  <span className={`w-3 h-3 rounded-full shrink-0 ${item.color}`} />
                  <span className="text-sm text-[#7d92b0] flex-1">{item.label}</span>
                  <span className="text-sm font-medium text-white w-8 text-right">{item.value}</span>
                  <span className="text-xs text-[#7d92b0] w-10 text-right">{item.pct}%</span>
                </div>
              ))}
              <div className="border-t border-[#1e2d42] pt-3 flex items-center gap-3">
                <span className="w-3 h-3 rounded-full shrink-0 bg-[#1e2d42]" />
                <span className="text-sm text-[#7d92b0] flex-1">合計</span>
                <span className="text-sm font-bold text-white w-8 text-right">{totalEps}</span>
                <span className="text-xs text-[#7d92b0] w-10 text-right">100%</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
