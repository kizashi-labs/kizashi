'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Crown, Plus, X, Check, AlertTriangle, Eye, EyeOff,
  Shield, User, Clock, RefreshCw, ChevronRight,
  ToggleLeft, ToggleRight, Video, KeyRound, Smartphone,
  UserCheck, UserX, Calendar, Filter
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type AccountType = 'admin' | 'service' | 'shared' | 'break_glass'
type RequestStatus = 'pending' | 'approved' | 'rejected'

interface PrivilegedAccount {
  id: string
  account: string
  display_name: string
  type: AccountType
  owner: string
  owner_email: string
  last_used: string
  risk_score: number
  mfa_enabled: boolean
  session_recording_enabled: boolean
  active: boolean
  department: string
  review_due?: string
  reviewer?: string
}

interface AccessRequest {
  id: string
  requester: string
  requester_email: string
  account_requested: string
  reason: string
  duration_hours: number
  status: RequestStatus
  requested_at: string
  reviewed_at?: string
  reviewed_by?: string
  rejection_reason?: string
}

interface ReviewItem {
  id: string
  account: PrivilegedAccount
  last_review?: string
  reviewer_assigned?: string
  review_due: string
  status: 'pending' | 'completed' | 'overdue'
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const typeColor: Record<AccountType, string> = {
  admin: 'bg-red-500/20 text-red-300 border-red-500/30',
  service: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  shared: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  break_glass: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
}
const typeLabel: Record<AccountType, string> = {
  admin: '管理者', service: 'サービス', shared: '共有', break_glass: '緊急',
}
const reqStatusColor: Record<RequestStatus, string> = {
  pending: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  approved: 'bg-green-500/20 text-green-300 border-green-500/30',
  rejected: 'bg-red-500/20 text-red-300 border-red-500/30',
}
const reqStatusLabel: Record<RequestStatus, string> = {
  pending: '承認待ち', approved: '承認済み', rejected: '却下',
}

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[11px] font-medium border ${cls}`}>{text}</span>
}

function riskColor(score: number) {
  if (score >= 80) return 'text-red-400 bg-red-500/10'
  if (score >= 60) return 'text-orange-400 bg-orange-500/10'
  if (score >= 40) return 'text-yellow-400 bg-yellow-500/10'
  return 'text-green-400 bg-green-500/10'
}

function timeAgo(ts: string) {
  const m = Math.floor((Date.now() - new Date(ts).getTime()) / 60000)
  if (m < 60) return `${m}分前`
  if (m < 1440) return `${Math.floor(m / 60)}時間前`
  return `${Math.floor(m / 1440)}日前`
}

// ─── Request Detail Modal ─────────────────────────────────────────────────────

function RequestDetailModal({ req, onClose, onApprove, onReject }: {
  req: AccessRequest; onClose: () => void
  onApprove: () => void; onReject: (reason: string) => void
}) {
  const [rejReason, setRejReason] = useState('')
  const [showReject, setShowReject] = useState(false)
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">アクセス申請詳細</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-3">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div><p className="text-xs text-[#7d92b0]">申請者</p><p className="text-white">{req.requester}</p></div>
            <div><p className="text-xs text-[#7d92b0]">申請日時</p><p className="text-white">{timeAgo(req.requested_at)}</p></div>
            <div className="col-span-2"><p className="text-xs text-[#7d92b0]">申請アカウント</p><p className="text-white font-mono">{req.account_requested}</p></div>
            <div><p className="text-xs text-[#7d92b0]">期間</p><p className="text-white">{req.duration_hours}時間</p></div>
            <div><p className="text-xs text-[#7d92b0]">ステータス</p><Badge text={reqStatusLabel[req.status]} cls={reqStatusColor[req.status]} /></div>
            <div className="col-span-2"><p className="text-xs text-[#7d92b0]">申請理由</p><p className="text-[#e2e8f4]">{req.reason}</p></div>
            {req.rejection_reason && (
              <div className="col-span-2"><p className="text-xs text-[#7d92b0]">却下理由</p><p className="text-red-300">{req.rejection_reason}</p></div>
            )}
          </div>
          {req.status === 'pending' && !showReject && (
            <div className="flex gap-3 pt-2">
              <button onClick={onApprove} className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-lg">
                <Check className="w-4 h-4" /> 承認
              </button>
              <button onClick={() => setShowReject(true)} className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-red-700 hover:bg-red-800 text-white text-sm rounded-lg">
                <X className="w-4 h-4" /> 却下
              </button>
            </div>
          )}
          {showReject && (
            <div className="space-y-2">
              <textarea
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white resize-none focus:outline-hidden"
                rows={2} placeholder="却下理由を入力..." value={rejReason} onChange={e => setRejReason(e.target.value)}
              />
              <div className="flex gap-2">
                <button onClick={() => onReject(rejReason)} className="flex-1 py-1.5 bg-red-700 text-white text-sm rounded-lg">却下確定</button>
                <button onClick={() => setShowReject(false)} className="flex-1 py-1.5 border border-[#1e2d42] text-[#7d92b0] text-sm rounded-lg">戻る</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PAGPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'accounts' | 'requests' | 'reviews'>('accounts')
  const [detailReq, setDetailReq] = useState<AccessRequest | null>(null)
  const [accounts, setAccounts] = useState<PrivilegedAccount[]>([])
  const [requests, setRequests] = useState<AccessRequest[]>([])
  const [typeFilter, setTypeFilter] = useState<AccountType | 'all'>('all')

  const { data: _accounts } = useQuery<PrivilegedAccount[]>({
    queryKey: ['pag-accounts'],
    queryFn: () => apiFetch('/api/v1/admin/pag/accounts'),
  })

  const { data: _requests } = useQuery<AccessRequest[]>({
    queryKey: ['pag-requests'],
    queryFn: () => apiFetch('/api/v1/admin/pag/requests'),
  })

  const toggleAccount = (id: string) => {
    setAccounts(prev => prev.map(a => a.id === id ? { ...a, active: !a.active } : a))
  }

  const approveReq = (id: string) => {
    setRequests(prev => prev.map(r => r.id === id
      ? { ...r, status: 'approved' as RequestStatus, reviewed_at: new Date().toISOString(), reviewed_by: '現在のユーザー' }
      : r))
    setDetailReq(null)
  }

  const rejectReq = (id: string, reason: string) => {
    setRequests(prev => prev.map(r => r.id === id
      ? { ...r, status: 'rejected' as RequestStatus, reviewed_at: new Date().toISOString(), reviewed_by: '現在のユーザー', rejection_reason: reason }
      : r))
    setDetailReq(null)
  }

  const reviewAccounts = accounts.filter(a => a.review_due)
  const reviewItems: ReviewItem[] = reviewAccounts.map(a => ({
    id: a.id,
    account: a,
    review_due: a.review_due!,
    reviewer_assigned: a.reviewer,
    status: new Date(a.review_due!) < new Date() ? 'overdue' : 'pending',
  }))

  const filteredAccounts = typeFilter === 'all' ? accounts : accounts.filter(a => a.type === typeFilter)

  const stats = [
    { label: '特権アカウント総数', value: accounts.length, color: 'text-white' },
    { label: '現在使用中', value: accounts.filter(a => a.active && new Date(a.last_used) > new Date(Date.now() - 3600000)).length, color: 'text-green-400' },
    { label: '本日の違反', value: 2, color: 'text-red-400' },
    { label: 'レビュー待ち', value: requests.filter(r => r.status === 'pending').length, color: 'text-yellow-400' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
          <Crown className="w-5 h-5 text-[#e8002d]" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">特権アクセスガバナンス</h1>
          <p className="text-xs text-[#7d92b0]">特権アカウントの管理・承認・定期レビュー</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {stats.map(s => (
          <div key={s.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <p className="text-xs text-[#7d92b0] mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {([
          ['accounts', '特権アカウント'],
          ['requests', 'アクセス申請'],
          ['reviews', '定期レビュー'],
        ] as const).map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)}
            className={`px-4 py-1.5 rounded-sm text-sm font-medium transition-colors ${tab === key ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
            {label}
            {key === 'requests' && requests.filter(r => r.status === 'pending').length > 0 && (
              <span className="ml-1.5 bg-[#e8002d] text-white text-[10px] px-1.5 py-0.5 rounded-full">
                {requests.filter(r => r.status === 'pending').length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Accounts Tab */}
      {tab === 'accounts' && (
        <>
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-[#7d92b0]" />
            <span className="text-xs text-[#7d92b0]">タイプ:</span>
            {(['all', 'admin', 'service', 'shared', 'break_glass'] as const).map(t => (
              <button key={t} onClick={() => setTypeFilter(t)}
                className={`px-2 py-1 rounded-sm text-xs transition-colors ${typeFilter === t ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
                {t === 'all' ? '全て' : typeLabel[t]}
              </button>
            ))}
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['アカウント', 'タイプ', 'オーナー', '最終使用', 'リスク', 'MFA', '録画', '状態'].map(h => (
                    <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredAccounts.map(a => (
                  <tr key={a.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-white font-medium text-xs font-mono">{a.account}</p>
                      <p className="text-[10px] text-[#7d92b0]">{a.display_name}</p>
                    </td>
                    <td className="px-4 py-3"><Badge text={typeLabel[a.type]} cls={typeColor[a.type]} /></td>
                    <td className="px-4 py-3">
                      <p className="text-xs text-white">{a.owner}</p>
                      <p className="text-[10px] text-[#3d5068]">{a.department}</p>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">{timeAgo(a.last_used)}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-bold px-2 py-1 rounded-sm ${riskColor(a.risk_score)}`}>{a.risk_score}</span>
                    </td>
                    <td className="px-4 py-3">
                      {a.mfa_enabled
                        ? <Smartphone className="w-4 h-4 text-green-400" />
                        : <Smartphone className="w-4 h-4 text-[#3d5068]" />
                      }
                    </td>
                    <td className="px-4 py-3">
                      {a.session_recording_enabled
                        ? <Video className="w-4 h-4 text-blue-400" />
                        : <Video className="w-4 h-4 text-[#3d5068]" />
                      }
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={() => toggleAccount(a.id)} className="flex items-center gap-1.5 group">
                        {a.active
                          ? <ToggleRight className="w-5 h-5 text-green-400 group-hover:text-green-300" />
                          : <ToggleLeft className="w-5 h-5 text-[#3d5068] group-hover:text-[#7d92b0]" />
                        }
                        <span className={`text-xs ${a.active ? 'text-green-400' : 'text-[#7d92b0]'}`}>{a.active ? '有効' : '無効'}</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Requests Tab */}
      {tab === 'requests' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['申請者', '申請アカウント', '期間', '申請日時', 'ステータス', '操作'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {requests.map(r => (
                <tr key={r.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-white font-medium">{r.requester}</p>
                    <p className="text-[10px] text-[#3d5068]">{r.requester_email}</p>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-[#7d92b0]">{r.account_requested}</td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">{r.duration_hours}時間</td>
                  <td className="px-4 py-3 text-xs text-[#7d92b0]">{timeAgo(r.requested_at)}</td>
                  <td className="px-4 py-3"><Badge text={reqStatusLabel[r.status]} cls={reqStatusColor[r.status]} /></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button onClick={() => setDetailReq(r)}
                        className="text-xs text-[#7d92b0] hover:text-white px-2 py-1 border border-[#1e2d42] rounded-sm transition-colors">
                        詳細
                      </button>
                      {r.status === 'pending' && (
                        <>
                          <button onClick={() => approveReq(r.id)}
                            className="text-xs text-green-400 hover:text-white px-2 py-1 border border-green-500/30 rounded-sm transition-colors">
                            承認
                          </button>
                          <button onClick={() => rejectReq(r.id, '手動却下')}
                            className="text-xs text-red-400 hover:text-white px-2 py-1 border border-red-500/30 rounded-sm transition-colors">
                            却下
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Reviews Tab */}
      {tab === 'reviews' && (
        <div className="space-y-3">
          <p className="text-xs text-[#7d92b0]">四半期レビュー対象アカウント ({reviewItems.length}件)</p>
          {reviewItems.map(item => (
            <div key={item.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-4">
              <div className="flex-1 grid grid-cols-4 gap-4">
                <div>
                  <p className="text-xs font-mono text-white">{item.account.account}</p>
                  <p className="text-[10px] text-[#7d92b0]">{item.account.display_name}</p>
                </div>
                <div>
                  <p className="text-xs text-[#7d92b0]">オーナー</p>
                  <p className="text-xs text-white">{item.account.owner}</p>
                </div>
                <div>
                  <p className="text-xs text-[#7d92b0]">レビュー期限</p>
                  <p className={`text-xs font-medium ${item.status === 'overdue' ? 'text-red-400' : 'text-yellow-400'}`}>
                    {new Date(item.review_due).toLocaleDateString('ja-JP')}
                    {item.status === 'overdue' && <span className="ml-1 text-[10px]">(期限超過)</span>}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-[#7d92b0]">リスクスコア</p>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-sm ${riskColor(item.account.risk_score)}`}>{item.account.risk_score}</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <select className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-white focus:outline-hidden">
                  <option value="">レビュアー割り当て</option>
                  <option>田中 健一</option>
                  <option>鈴木 美咲</option>
                  <option>佐藤 CISO</option>
                </select>
                <button className="flex items-center gap-1 px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white text-xs rounded-lg transition-colors">
                  <UserCheck className="w-3.5 h-3.5" /> レビュー完了
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {detailReq && (
        <RequestDetailModal
          req={detailReq}
          onClose={() => setDetailReq(null)}
          onApprove={() => approveReq(detailReq.id)}
          onReject={(reason) => rejectReq(detailReq.id, reason)}
        />
      )}
    </div>
  )
}
