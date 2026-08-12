'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  UserX, AlertTriangle, X, ChevronDown, ChevronUp,
  Shield, Clock, Monitor, Check, XCircle, RotateCcw, Ban
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────

type RiskFactor = 'no_mfa' | 'stale_account' | 'failed_logins' | 'privileged' | 'unusual_hours' | 'lateral_movement'

interface RiskUser {
  id: string
  username: string
  email: string
  department: string
  role: string
  risk_score: number
  risk_factors: RiskFactor[]
  last_login: string | null
  status: 'active' | 'disabled' | 'locked'
  login_history: LoginEntry[]
  dept_avg_score: number
}

interface LoginEntry {
  timestamp: string
  ip: string
  device: string
  success: boolean
}

// ── Helpers ──────────────────────────────────────────────────────

const FACTOR_LABELS: Record<RiskFactor, string> = {
  no_mfa: 'MFA未登録',
  stale_account: '長期未使用',
  failed_logins: 'ログイン失敗多',
  privileged: '特権ロール',
  unusual_hours: '異常時間帯',
  lateral_movement: 'ラテラルムーブ',
}

const FACTOR_COLORS: Record<RiskFactor, string> = {
  no_mfa: 'bg-red-900/40 text-red-300',
  stale_account: 'bg-gray-800 text-gray-300',
  failed_logins: 'bg-orange-900/40 text-orange-300',
  privileged: 'bg-purple-900/40 text-purple-300',
  unusual_hours: 'bg-yellow-900/40 text-yellow-300',
  lateral_movement: 'bg-red-900/60 text-red-300',
}

const FACTOR_WEIGHTS: Record<RiskFactor, number> = {
  no_mfa: 25,
  stale_account: 15,
  failed_logins: 20,
  privileged: 15,
  unusual_hours: 10,
  lateral_movement: 30,
}

const FACTOR_RECOMMENDATIONS: Record<RiskFactor, string> = {
  no_mfa: 'MFA登録を強制してください。認証強度が大幅に向上します。',
  stale_account: '90日以上未使用のアカウントを無効化することを推奨します。',
  failed_logins: '過去7日間のログイン失敗が多数あります。パスワードリセットを検討してください。',
  privileged: '特権アクセスを定期的にレビューし、最小権限の原則を適用してください。',
  unusual_hours: '通常業務時間外のアクセスが検知されています。アクセスポリシーを確認してください。',
  lateral_movement: '横方向移動の痕跡が検知されています。即時調査と隔離を検討してください。',
}

function riskColor(score: number) {
  if (score >= 70) return 'text-red-400'
  if (score >= 30) return 'text-yellow-400'
  return 'text-green-400'
}

function riskBarColor(score: number) {
  if (score >= 70) return 'bg-red-500'
  if (score >= 30) return 'bg-yellow-500'
  return 'bg-green-500'
}

function statusBadge(s: RiskUser['status']) {
  const map = {
    active: 'bg-green-900/40 text-green-300',
    disabled: 'bg-gray-800 text-gray-400',
    locked: 'bg-orange-900/40 text-orange-300',
  }
  const label = { active: 'アクティブ', disabled: '無効', locked: 'ロック' }
  return <span className={`text-xs px-2 py-0.5 rounded-full ${map[s]}`}>{label[s]}</span>
}

function Avatar({ name }: { name: string }) {
  const initials = name.split(/[._]/).map(p => p[0]?.toUpperCase() ?? '').slice(0, 2).join('')
  const colors = ['from-blue-600 to-blue-800', 'from-purple-600 to-purple-800', 'from-green-600 to-green-800', 'from-orange-600 to-orange-800']
  const color = colors[name.charCodeAt(0) % colors.length]
  return (
    <div className={`w-8 h-8 rounded-full bg-gradient-to-br ${color} flex items-center justify-center flex-shrink-0`}>
      <span className="text-xs font-bold text-white">{initials || '?'}</span>
    </div>
  )
}

function fmt(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Risk Profile Modal ───────────────────────────────────────────

function RiskProfileModal({ user, onClose, weights }: { user: RiskUser; onClose: () => void; weights: Record<RiskFactor, number> }) {
  const [acting, setActing] = useState<string | null>(null)

  const doAction = async (action: string, label: string) => {
    setActing(action)
    try {
      await apiFetch(`/api/v1/admin/identity-risk/users/${user.id}/enforce-mfa`, { method: 'POST' })
    } catch {}
    setTimeout(() => { setActing(null) }, 1500)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-[#0d1220] border-b border-[#1e2d42] px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Avatar name={user.username} />
            <div>
              <h2 className="text-white font-semibold">{user.username}</h2>
              <p className="text-[#7d92b0] text-xs">{user.email} · {user.department}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        <div className="p-6 space-y-6">
          {/* Score + peer comparison */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4 text-center">
              <p className="text-[#7d92b0] text-xs mb-2">リスクスコア</p>
              <p className={`text-5xl font-bold ${riskColor(user.risk_score)}`}>{user.risk_score}</p>
              <div className="mt-3 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                <div className={`h-full ${riskBarColor(user.risk_score)} transition-all`} style={{ width: `${user.risk_score}%` }} />
              </div>
            </div>
            <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
              <p className="text-[#7d92b0] text-xs mb-3">部門平均比較 ({user.department})</p>
              <div className="space-y-2">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-white">{user.username}</span>
                    <span className={riskColor(user.risk_score)}>{user.risk_score}</span>
                  </div>
                  <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className={`h-full ${riskBarColor(user.risk_score)}`} style={{ width: `${user.risk_score}%` }} />
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-[#7d92b0]">部門平均</span>
                    <span className={riskColor(user.dept_avg_score)}>{user.dept_avg_score}</span>
                  </div>
                  <div className="h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className={`h-full ${riskBarColor(user.dept_avg_score)}`} style={{ width: `${user.dept_avg_score}%` }} />
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Factor breakdown */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
            <p className="text-[#7d92b0] text-xs font-medium uppercase tracking-wider mb-3">スコア内訳</p>
            <div className="space-y-3">
              {(Object.keys(weights) as RiskFactor[]).map(f => {
                const active = user.risk_factors.includes(f)
                const contribution = active ? Math.round(weights[f] * 0.8) : 0
                return (
                  <div key={f}>
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className={active ? 'text-white' : 'text-[#3d5068]'}>
                        {active && <span className="text-red-400 mr-1">●</span>}
                        {FACTOR_LABELS[f]}
                      </span>
                      <span className={active ? 'text-red-400' : 'text-[#3d5068]'}>+{contribution}</span>
                    </div>
                    <div className="h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                      <div className={`h-full ${active ? 'bg-red-500' : 'bg-[#1e2d42]'} transition-all`}
                        style={{ width: `${(contribution / weights[f]) * 100}%` }} />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Login history */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
            <p className="text-[#7d92b0] text-xs font-medium uppercase tracking-wider mb-3">最近10件のログイン</p>
            <div className="space-y-2">
              {user.login_history.map((l, i) => (
                <div key={i} className="flex items-center gap-3 text-xs">
                  <span className="text-[#7d92b0] font-mono w-28 flex-shrink-0">{fmt(l.timestamp)}</span>
                  <span className="text-[#e2e8f4] font-mono w-28 flex-shrink-0">{l.ip}</span>
                  <span className="text-[#7d92b0] flex-1 truncate">{l.device}</span>
                  {l.success
                    ? <span className="flex items-center gap-1 text-green-400"><Check className="w-3 h-3" /> 成功</span>
                    : <span className="flex items-center gap-1 text-red-400"><XCircle className="w-3 h-3" /> 失敗</span>}
                </div>
              ))}
            </div>
          </div>

          {/* Recommendations */}
          {user.risk_factors.length > 0 && (
            <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4">
              <p className="text-[#7d92b0] text-xs font-medium uppercase tracking-wider mb-3">推奨アクション</p>
              <div className="space-y-2">
                {user.risk_factors.map(f => (
                  <div key={f} className="flex items-start gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0 mt-0.5" />
                    <p className="text-[#e2e8f4] text-xs">{FACTOR_RECOMMENDATIONS[f]}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex gap-3">
            <button onClick={() => doAction('mfa', 'MFA強制')}
              disabled={acting === 'mfa'}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-blue-900/30 border border-blue-700/40 text-blue-300 rounded-lg text-sm font-medium hover:bg-blue-900/50 transition-colors disabled:opacity-60">
              <Shield className="w-4 h-4" /> {acting === 'mfa' ? '処理中...' : 'MFA強制'}
            </button>
            <button onClick={() => doAction('reset', 'パスワードリセット')}
              disabled={acting === 'reset'}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-yellow-900/30 border border-yellow-700/40 text-yellow-300 rounded-lg text-sm font-medium hover:bg-yellow-900/50 transition-colors disabled:opacity-60">
              <RotateCcw className="w-4 h-4" /> {acting === 'reset' ? '処理中...' : 'パスワードリセット'}
            </button>
            <button onClick={() => doAction('disable', 'アカウント停止')}
              disabled={acting === 'disable'}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-red-900/30 border border-red-700/40 text-red-300 rounded-lg text-sm font-medium hover:bg-red-900/50 transition-colors disabled:opacity-60">
              <Ban className="w-4 h-4" /> {acting === 'disable' ? '処理中...' : 'アカウント停止'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function IdentityRiskPage() {
  const [selectedUser, setSelectedUser] = useState<RiskUser | null>(null)
  const [showConfig, setShowConfig] = useState(false)
  const [weights, setWeights] = useState<Record<RiskFactor, number>>({ ...FACTOR_WEIGHTS })

  const { data: usersData } = useQuery<RiskUser[]>({
    queryKey: ['identity-risk-users'],
    queryFn: () => apiFetch('/api/v1/admin/identity-risk/users'),
    onError: () => {},
  } as any)

  const users: RiskUser[] = ((usersData as RiskUser[]) ?? []).sort((a, b) => b.risk_score - a.risk_score)

  const avgScore = users.length ? Math.round(users.reduce((s, u) => s + (u.risk_score ?? 0), 0) / users.length) : 0
  const highRisk = users.filter(u => u.risk_score >= 70).length
  const noMfa = users.filter(u => u.risk_factors.includes('no_mfa')).length
  const stale = users.filter(u => u.risk_factors.includes('stale_account')).length

  const handleWeightSave = async () => {
    try { await apiFetch('/api/v1/admin/identity-risk/config', { method: 'PUT', body: JSON.stringify({ weights }) }) }
    catch {}
    setShowConfig(false)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
          <UserX className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-2xl font-bold">IDリスクスコア管理</h1>
          <p className="text-[#7d92b0] text-sm">ユーザーのリスク評価と対応管理</p>
        </div>
      </div>

      {/* High-risk alert banner */}
      {highRisk > 0 && (
        <div className="flex items-center gap-3 p-4 mb-6 bg-red-900/20 border border-red-700/40 rounded-xl">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300 text-sm"><span className="font-bold text-white">{highRisk}名</span>のユーザーが高リスク (スコア70以上) と判定されています。即時対応を推奨します。</p>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '平均リスクスコア', value: avgScore, color: riskColor(avgScore) },
          { label: '高リスクユーザー (≥70)', value: highRisk, color: 'text-red-400' },
          { label: 'MFA未登録', value: noMfa, color: 'text-orange-400' },
          { label: '長期未使用 (90日+)', value: stale, color: 'text-yellow-400' },
        ].map(c => (
          <div key={c.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <p className="text-[#7d92b0] text-xs mb-2">{c.label}</p>
            <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Risk Scoring Config (collapsible) */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl mb-6">
        <button onClick={() => setShowConfig(p => !p)}
          className="w-full flex items-center justify-between px-5 py-4 text-white font-medium text-sm">
          リスクスコアリング設定
          {showConfig ? <ChevronUp className="w-4 h-4 text-[#7d92b0]" /> : <ChevronDown className="w-4 h-4 text-[#7d92b0]" />}
        </button>
        {showConfig && (
          <div className="px-5 pb-5 border-t border-[#1e2d42]">
            <p className="text-[#7d92b0] text-xs mt-4 mb-4">各リスク要因のウェイトを調整します。スコア = Σ(要因の基本ウェイト × 0.8)</p>
            <div className="space-y-4">
              {(Object.keys(weights) as RiskFactor[]).map(f => (
                <div key={f} className="flex items-center gap-4">
                  <span className="text-sm text-white w-36 flex-shrink-0">{FACTOR_LABELS[f]}</span>
                  <input type="range" min={5} max={50} value={weights[f]}
                    onChange={e => setWeights(p => ({ ...p, [f]: Number(e.target.value) }))}
                    className="flex-1 accent-[#e8002d]" />
                  <span className="text-[#e8002d] font-bold text-sm w-8 text-right">{weights[f]}</span>
                </div>
              ))}
            </div>
            <div className="mt-4 p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg">
              <p className="text-xs text-[#7d92b0]">最大スコア (全要因該当時): <span className="text-white font-bold">{Math.round(Object.values(weights).reduce((a, b) => a + b, 0) * 0.8)}</span></p>
            </div>
            <button onClick={handleWeightSave}
              className="mt-4 px-6 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c8001e] transition-colors">
              設定保存
            </button>
          </div>
        )}
      </div>

      {/* User Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-sm">ユーザーリスク一覧 (リスクスコア降順)</h2>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['ユーザー', '部署', 'ロール', 'リスクスコア', 'リスク要因', '最終ログイン', 'ステータス', '操作'].map(h => (
                <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id} onClick={() => setSelectedUser(u)}
                className="border-b border-[#1e2d42]/50 hover:bg-[#070d19]/50 transition-colors cursor-pointer">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2.5">
                    <Avatar name={u.username} />
                    <div>
                      <p className="text-white text-xs font-medium">{u.username}</p>
                      <p className="text-[#7d92b0] text-xs">{u.email}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3 text-xs text-[#e2e8f4]">{u.department}</td>
                <td className="px-4 py-3 text-xs text-[#7d92b0]">{u.role}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-bold w-8 ${riskColor(u.risk_score)}`}>{u.risk_score}</span>
                    <div className="w-24 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                      <div className={`h-full ${riskBarColor(u.risk_score)} transition-all`} style={{ width: `${u.risk_score}%` }} />
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {u.risk_factors.slice(0, 3).map(f => (
                      <span key={f} className={`text-[10px] px-1.5 py-0.5 rounded-full ${FACTOR_COLORS[f]}`}>{FACTOR_LABELS[f]}</span>
                    ))}
                    {u.risk_factors.length > 3 && <span className="text-[10px] text-[#7d92b0]">+{u.risk_factors.length - 3}</span>}
                  </div>
                </td>
                <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono whitespace-nowrap">{fmt(u.last_login)}</td>
                <td className="px-4 py-3">{statusBadge(u.status)}</td>
                <td className="px-4 py-3">
                  <button onClick={e => { e.stopPropagation(); setSelectedUser(u) }}
                    className="text-xs text-[#7d92b0] hover:text-white transition-colors border border-[#1e2d42] px-2 py-1 rounded hover:border-[#7d92b0]/40">
                    詳細
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedUser && <RiskProfileModal user={selectedUser} onClose={() => setSelectedUser(null)} weights={weights} />}
    </div>
  )
}
