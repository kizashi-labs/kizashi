'use client'

import React, { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  Layers, Plus, Trash2, X, Monitor, AlertCircle, Search,
  Users, ShieldCheck, Bell, BarChart2, GripVertical, ChevronRight,
  TrendingUp, Wifi, WifiOff, CheckCircle
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Group {
  id: string
  name: string
  description: string
  color: string
  endpoint_count: number
  alert_count: number
  policy_count: number
  created_at: string
  tags?: string[]
}

interface Member {
  agent_id: string
  hostname: string
  ip_address: string
  os: string
  status: 'online' | 'offline'
}

interface Policy {
  id: string
  name: string
  type: string
  enabled: boolean
}

interface Alert {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  hostname: string
  created_at: string
}

interface GroupDetail {
  id: string
  name: string
  description: string
  color: string
  members: Member[]
  policies: Policy[]
  alerts: Alert[]
  stats: {
    alert_trend: number[]  // last 7 days counts
    online_count: number
    offline_count: number
  }
}

const ALL_POLICIES: Policy[] = [
  { id: 'p1', name: '厳格なアンチウイルスポリシー', type: 'antivirus', enabled: true },
  { id: 'p2', name: 'ファイアウォールルールセットA', type: 'firewall', enabled: true },
  { id: 'p3', name: '開発マシン向けポリシー', type: 'custom', enabled: true },
  { id: 'p4', name: 'エンドポイント堅牢化', type: 'hardening', enabled: false },
  { id: 'p5', name: 'DLP標準', type: 'dlp', enabled: true },
]

// タブ・ステータス・深刻度の日本語ラベル
const TAB_LABELS: Record<string, string> = { members: 'メンバー', policies: 'ポリシー', alerts: 'アラート', stats: '統計' }
const STATUS_LABELS: Record<string, string> = { online: 'オンライン', offline: 'オフライン' }
const SEVERITY_LABELS: Record<string, string> = { critical: '緊急', high: '高', medium: '中', low: '低' }

const COLORS = ['#3b82f6', '#10b981', '#e8002d', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16']

// ─── Helpers ──────────────────────────────────────────────────────────────────

const severityColor: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/20',
  high: 'text-orange-400 bg-orange-900/20',
  medium: 'text-yellow-400 bg-yellow-900/20',
  low: 'text-blue-400 bg-blue-900/20',
}

// ─── Stats Card ───────────────────────────────────────────────────────────────

function StatCard({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4 flex items-center gap-4">
      <div className="p-2.5 bg-[#131d30] rounded-lg">{icon}</div>
      <div>
        <p className="text-falcon-muted text-xs">{label}</p>
        <p className="text-white text-xl font-bold mt-0.5">{value}</p>
        {sub && <p className="text-falcon-muted text-xs mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

// ─── Mini Sparkline ───────────────────────────────────────────────────────────

function Sparkline({ data, color = '#e8002d' }: { data: number[]; color?: string }) {
  const max = Math.max(...data, 1)
  const W = 140, H = 40, pad = 4
  const pts = data.map((v, i) => {
    const x = pad + (i / (data.length - 1)) * (W - pad * 2)
    const y = H - pad - (v / max) * (H - pad * 2)
    return `${x},${y}`
  }).join(' ')
  return (
    <svg width={W} height={H} className="overflow-visible">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

// ─── Group Detail Panel ───────────────────────────────────────────────────────

function GroupDetailPanel({
  group,
  detail,
  onClose,
  onRemoveMember,
  onAddMember,
  onAddPolicy,
  onRemovePolicy,
}: {
  group: Group
  detail: GroupDetail
  onClose: () => void
  onRemoveMember?: (agentId: string) => void
  onAddMember?: (agentId: string) => void
  onAddPolicy?: (policyId: string) => void
  onRemovePolicy?: (policyId: string) => void
}) {
  const [tab, setTab] = useState<'members' | 'policies' | 'alerts' | 'stats'>('members')
  const [search, setSearch] = useState('')

  const days = ['月', '火', '水', '木', '金', '土', '日']
  const trend = detail.stats.alert_trend
  const maxTrend = Math.max(...trend, 1)

  const unassignedPolicies = ALL_POLICIES.filter(p => !detail.policies.find(dp => dp.id === p.id))

  return (
    <div className="flex flex-col h-full bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
      {/* Panel header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-falcon-border">
        <div className="flex items-center gap-3">
          <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: group.color }} />
          <span className="text-white font-semibold text-sm">{group.name}</span>
          <span className="text-falcon-muted text-xs">{group.description}</span>
        </div>
        <button onClick={onClose} className="p-1 text-falcon-muted hover:text-white rounded-sm transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Tags */}
      {group.tags && group.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 px-4 py-2 border-b border-falcon-border">
          {group.tags.map(tag => (
            <span key={tag} className="px-2 py-0.5 rounded-full text-[10px] bg-[#131d30] text-falcon-muted border border-falcon-border">
              #{tag}
            </span>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-falcon-border px-2">
        {(['members', 'policies', 'alerts', 'stats'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2.5 text-xs font-medium capitalize transition-colors border-b-2 -mb-px ${
              tab === t
                ? 'text-white border-falcon-red'
                : 'text-falcon-muted border-transparent hover:text-white'
            }`}
          >
            {TAB_LABELS[t]}
            {t === 'members' && <span className="ml-1.5 text-[10px] bg-falcon-border px-1.5 py-0.5 rounded-full">{detail.members.length}</span>}
            {t === 'alerts' && detail.alerts.length > 0 && (
              <span className="ml-1.5 text-[10px] bg-falcon-red/20 text-falcon-red px-1.5 py-0.5 rounded-full">{detail.alerts.length}</span>
            )}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">

        {/* Members Tab */}
        {tab === 'members' && (
          <>
            {onAddMember && <AddEndpointBar onAdd={onAddMember} />}
            {detail.members.length === 0 ? (
              <p className="text-falcon-muted text-sm text-center py-8">このグループにエンドポイントはありません</p>
            ) : (
              <div className="space-y-1">
                {detail.members.map(m => (
                  <div key={m.agent_id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#0a1020] border border-falcon-border group">
                    <GripVertical className="w-3.5 h-3.5 text-[#3a4d62] cursor-grab" />
                    <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${m.status === 'online' ? 'bg-emerald-400' : 'bg-[#3a4d62]'}`} />
                    <Monitor className="w-3.5 h-3.5 text-falcon-muted shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-white text-xs font-medium">{m.hostname}</p>
                      <p className="text-falcon-muted text-[10px]">{m.ip_address} · {m.os}</p>
                    </div>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${m.status === 'online' ? 'bg-emerald-900/30 text-emerald-400' : 'bg-falcon-border text-falcon-muted'}`}>
                      {STATUS_LABELS[m.status] ?? m.status}
                    </span>
                    {onRemoveMember && (
                      <button
                        onClick={() => onRemoveMember(m.agent_id)}
                        className="opacity-0 group-hover:opacity-100 p-1 text-falcon-muted hover:text-red-400 rounded-sm transition-all"
                        title="グループから削除"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* Policies Tab */}
        {tab === 'policies' && (
          <>
            <p className="text-falcon-muted text-xs">このグループに適用中のポリシー</p>
            {detail.policies.length === 0 ? (
              <p className="text-falcon-muted text-sm text-center py-4">割り当てられたポリシーはありません</p>
            ) : (
              <div className="space-y-1">
                {detail.policies.map(p => (
                  <div key={p.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#0a1020] border border-falcon-border group">
                    <ShieldCheck className={`w-4 h-4 shrink-0 ${p.enabled ? 'text-emerald-400' : 'text-[#3a4d62]'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-white text-xs font-medium">{p.name}</p>
                      <p className="text-falcon-muted text-[10px] capitalize">{p.type}</p>
                    </div>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${p.enabled ? 'bg-emerald-900/30 text-emerald-400' : 'bg-falcon-border text-falcon-muted'}`}>
                      {p.enabled ? '有効' : '無効'}
                    </span>
                    {onRemovePolicy && (
                      <button
                        onClick={() => onRemovePolicy(p.id)}
                        className="opacity-0 group-hover:opacity-100 p-1 text-falcon-muted hover:text-red-400 rounded-sm transition-all"
                        title="ポリシーを削除"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
            {onAddPolicy && unassignedPolicies.length > 0 && (
              <>
                <p className="text-falcon-muted text-xs mt-4">ポリシーを追加</p>
                <div className="space-y-1">
                  {unassignedPolicies.map(p => (
                    <div key={p.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#070d19] border border-falcon-border border-dashed">
                      <ShieldCheck className="w-4 h-4 text-[#3a4d62] shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-falcon-muted text-xs">{p.name}</p>
                        <p className="text-[#3a4d62] text-[10px] capitalize">{p.type}</p>
                      </div>
                      <button
                        onClick={() => onAddPolicy(p.id)}
                        className="text-[10px] px-2 py-1 bg-falcon-border hover:bg-falcon-red/20 hover:text-falcon-red text-falcon-muted rounded-sm transition-colors"
                      >
                        + 追加
                      </button>
                    </div>
                  ))}
                </div>
              </>
            )}
          </>
        )}

        {/* Alerts Tab */}
        {tab === 'alerts' && (
          <>
            {detail.alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 gap-2">
                <CheckCircle className="w-8 h-8 text-emerald-400 opacity-50" />
                <p className="text-falcon-muted text-sm">最近のアラートはありません</p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {detail.alerts.map(a => (
                  <div key={a.id} className="px-3 py-2.5 rounded-lg bg-[#0a1020] border border-falcon-border">
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-white text-xs font-medium">{a.title}</p>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-sm shrink-0 ${severityColor[a.severity]}`}>
                        {SEVERITY_LABELS[a.severity] ?? a.severity}
                      </span>
                    </div>
                    <p className="text-falcon-muted text-[10px] mt-1">
                      {a.hostname} · {new Date(a.created_at).toLocaleString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* Stats Tab */}
        {tab === 'stats' && (
          <div className="space-y-4">
            {/* Online ratio */}
            <div className="bg-[#0a1020] border border-falcon-border rounded-lg p-4">
              <p className="text-falcon-muted text-xs mb-3">エンドポイント状態</p>
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Wifi className="w-4 h-4 text-emerald-400" />
                  <span className="text-white text-lg font-bold">{detail.stats.online_count}</span>
                  <span className="text-falcon-muted text-xs">オンライン</span>
                </div>
                <div className="flex items-center gap-2">
                  <WifiOff className="w-4 h-4 text-falcon-muted" />
                  <span className="text-white text-lg font-bold">{detail.stats.offline_count}</span>
                  <span className="text-falcon-muted text-xs">オフライン</span>
                </div>
              </div>
              {/* ratio bar */}
              {(detail.stats.online_count + detail.stats.offline_count) > 0 && (
                <div className="mt-3 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-400 rounded-full transition-all"
                    style={{ width: `${(detail.stats.online_count / (detail.stats.online_count + detail.stats.offline_count)) * 100}%` }}
                  />
                </div>
              )}
            </div>

            {/* Alert trend */}
            <div className="bg-[#0a1020] border border-falcon-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="text-falcon-muted text-xs">アラート推移（過去7日間）</p>
                <TrendingUp className="w-3.5 h-3.5 text-falcon-muted" />
              </div>
              <Sparkline data={trend} color={group.color} />
              <div className="flex justify-between mt-1">
                {days.map((d, i) => (
                  <div key={d} className="flex flex-col items-center gap-1">
                    <span className="text-[9px] text-falcon-muted">{trend[i]}</span>
                    <span className="text-[9px] text-[#3a4d62]">{d}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Bar chart */}
            <div className="bg-[#0a1020] border border-falcon-border rounded-lg p-4">
              <p className="text-falcon-muted text-xs mb-3">日別アラート件数</p>
              <div className="flex items-end gap-2 h-20">
                {trend.map((v, i) => (
                  <div key={i} className="flex-1 flex flex-col items-center gap-1">
                    <div
                      className="w-full rounded-t transition-all"
                      style={{
                        height: `${(v / maxTrend) * 64}px`,
                        backgroundColor: group.color,
                        opacity: v === 0 ? 0.2 : 0.8,
                        minHeight: v === 0 ? '2px' : undefined,
                      }}
                    />
                    <span className="text-[9px] text-[#3a4d62]">{days[i]}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Add Endpoint Bar ─────────────────────────────────────────────────────────

function AddEndpointBar({ onAdd }: { onAdd: (agentId: string) => void }) {
  const [val, setVal] = useState('')
  const [results, setResults] = useState<{ id: string; hostname: string; status: string; group_id?: string | null }[]>([])
  const [searching, setSearching] = useState(false)
  const [unassignedOnly, setUnassignedOnly] = useState(true)
  const [open, setOpen] = useState(false)
  const ref = React.useRef<HTMLDivElement>(null)

  // Close dropdown on outside click
  React.useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const fetchAgents = React.useCallback(async (q: string, unassigned: boolean) => {
    setSearching(true)
    try {
      const params = new URLSearchParams({ per_page: '50' })
      if (q.trim()) params.set('search', q.trim())
      const data = await apiFetch<{ data: { id: string; hostname: string; status: string; group_id?: string | null }[] }>(
        `/api/v1/agents?${params}`
      )
      const all = data.data ?? []
      setResults(unassigned ? all.filter(a => !a.group_id) : all)
    } catch { setResults([]) }
    finally { setSearching(false) }
  }, [])

  // Load unassigned list when panel opens
  React.useEffect(() => {
    if (open) fetchAgents(val, unassignedOnly)
  }, [open, unassignedOnly]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleInput = (q: string) => {
    setVal(q)
    fetchAgents(q, unassignedOnly)
  }

  const handleAdd = (id: string) => {
    onAdd(id)
    setResults(prev => prev.filter(a => a.id !== id))
  }

  return (
    <div ref={ref} className="relative">
      {/* Search row */}
      <div className="flex gap-2 items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3a4d62]" />
          <input
            value={val}
            onChange={e => handleInput(e.target.value)}
            onFocus={() => setOpen(true)}
            placeholder="ホスト名で検索..."
            className="w-full pl-8 pr-3 py-2 bg-[#070d19] border border-falcon-border rounded-lg text-white text-xs
                       placeholder-[#3a4d62] focus:outline-hidden focus:border-falcon-red/50"
          />
        </div>
        {/* Unassigned toggle */}
        <button
          onClick={() => { setUnassignedOnly(v => !v); setOpen(true) }}
          title={unassignedOnly ? '未所属エンドポイントのみ表示' : 'すべて表示'}
          className={`shrink-0 px-2.5 py-2 rounded-lg text-xs font-medium border transition-colors ${
            unassignedOnly
              ? 'border-falcon-red/50 bg-falcon-red/10 text-falcon-red'
              : 'border-falcon-border bg-[#070d19] text-falcon-muted hover:text-white'
          }`}
        >
          未所属のみ
        </button>
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute top-full left-0 right-0 mt-1 bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden z-20 shadow-xl max-h-64 overflow-y-auto">
          {searching ? (
            <p className="text-xs text-[#3a4d62] px-3 py-3 text-center">検索中...</p>
          ) : results.length === 0 ? (
            <p className="text-xs text-[#3a4d62] px-3 py-3 text-center">
              {unassignedOnly ? '未所属のエンドポイントはありません' : 'エンドポイントが見つかりません'}
            </p>
          ) : (
            results.map(a => (
              <button
                key={a.id}
                onClick={() => handleAdd(a.id)}
                className="w-full flex items-center gap-3 px-3 py-2 hover:bg-falcon-border text-left transition-colors"
              >
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${a.status === 'online' ? 'bg-green-400' : 'bg-gray-500'}`} />
                <span className="text-xs text-white font-medium">{a.hostname}</span>
                <span className="text-xs text-[#3a4d62] ml-auto">{a.status}</span>
                {!a.group_id && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded-sm bg-yellow-900/30 text-yellow-400 ml-1">未所属</span>
                )}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  )
}

// ─── Create Group Modal ───────────────────────────────────────────────────────

function CreateGroupModal({
  onClose,
  onCreate,
  isPending,
}: {
  onClose: () => void
  onCreate: (data: { name: string; description: string; color: string }) => void
  isPending: boolean
}) {
  const [form, setForm] = useState({ name: '', description: '', color: COLORS[0] })

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-sm">新規グループ作成</h2>
          <button onClick={onClose} className="p-1 text-falcon-muted hover:text-white rounded-sm">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="text-falcon-muted text-xs block mb-1.5">グループ名 *</label>
            <input
              autoFocus
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: Windows サーバー"
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                         text-sm focus:outline-hidden focus:border-falcon-red/60 placeholder-[#3a4d62]"
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs block mb-1.5">説明</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="説明（任意）"
              rows={2}
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-falcon-border
                         text-sm focus:outline-hidden focus:border-falcon-red/60 placeholder-[#3a4d62] resize-none"
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs block mb-2">バッジカラー</label>
            <div className="flex gap-2 flex-wrap">
              {COLORS.map(c => (
                <button
                  key={c}
                  onClick={() => setForm(f => ({ ...f, color: c }))}
                  className={`w-7 h-7 rounded-full transition-transform ${form.color === c ? 'ring-2 ring-white ring-offset-1 ring-offset-falcon-surface scale-110' : 'hover:scale-105'}`}
                  style={{ backgroundColor: c }}
                  title={c}
                />
              ))}
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button
              onClick={() => onCreate(form)}
              disabled={!form.name.trim() || isPending}
              className="flex-1 py-2 bg-falcon-red hover:bg-[#b5001e] text-white text-sm rounded-lg
                         disabled:opacity-50 transition-colors font-medium"
            >
              {isPending ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  作成中...
                </span>
              ) : 'グループを作成'}
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-falcon-border hover:bg-[#243550] text-falcon-muted text-sm rounded-lg transition-colors"
            >
              キャンセル
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Delete Confirm ────────────────────────────────────────────────────────────

function DeleteConfirmBar({
  group,
  onConfirm,
  onCancel,
  isDeleting,
}: {
  group: Group
  onConfirm: () => void
  onCancel: () => void
  isDeleting: boolean
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3 bg-red-900/10 border border-red-900/40 rounded-lg">
      <div className="flex items-center gap-2 text-red-400 text-xs">
        <AlertCircle className="w-4 h-4 shrink-0" />
        <span><strong>{group.name}</strong> を削除しますか？ {group.endpoint_count}台のエンドポイントの割り当てが解除されます。</span>
      </div>
      <div className="flex gap-2 shrink-0">
        <button
          onClick={onConfirm}
          disabled={isDeleting}
          className="px-3 py-1 bg-falcon-red hover:bg-[#b5001e] text-white text-xs rounded-lg disabled:opacity-50 transition-colors"
        >
          {isDeleting ? '削除中...' : '削除'}
        </button>
        <button
          onClick={onCancel}
          className="px-3 py-1 bg-falcon-border hover:bg-[#243550] text-falcon-muted text-xs rounded-lg transition-colors"
        >
          キャンセル
        </button>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function GroupsPage() {
  const canWrite = useCanWrite()
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tagFilter, setTagFilter] = useState<string | null>(null)
  const [localDetail, setLocalDetail] = useState<Record<string, GroupDetail>>({})

  // ── Groups list ──────────────────────────────────────────────────────────────
  const { data: groupsData, isLoading } = useQuery<{ groups: Group[] }>({
    queryKey: ['groups'],
    queryFn: async () => {
      const res = await apiFetch<{ data: Array<Group & { agent_count?: number }>; groups?: Group[] }>('/api/v1/groups')
      const raw = res.groups ?? res.data ?? []
      // Backend returns agent_count; map to endpoint_count and add default color
      const groups: Group[] = raw.map((g, i) => ({
        id: g.id,
        name: g.name,
        description: g.description ?? '',
        color: g.color ?? COLORS[i % COLORS.length],
        endpoint_count: g.endpoint_count ?? (g as Group & { agent_count?: number }).agent_count ?? 0,
        alert_count: g.alert_count ?? 0,
        policy_count: g.policy_count ?? 0,
        created_at: g.created_at,
        tags: g.tags,
      }))
      return { groups }
    },
  })

  // ── Group detail ─────────────────────────────────────────────────────────────
  const { data: detailData } = useQuery<GroupDetail | null>({
    queryKey: ['group-detail', selectedId],
    queryFn: async () => {
      if (!selectedId) return null
      try {
        return await apiFetch<GroupDetail>(`/api/v1/groups/${selectedId}`)
      } catch {
        return localDetail[selectedId] ?? null
      }
    },
    enabled: !!selectedId,
  })

  // ── Mutations ────────────────────────────────────────────────────────────────
  const createMutation = useMutation({
    mutationFn: async (payload: { name: string; description: string; color: string }) => {
      return await apiFetch<Group>('/api/v1/groups', { method: 'POST', body: JSON.stringify(payload) })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['groups'] })
      setShowCreate(false)
      setError(null)
    },
    onError: () => setError('グループの作成に失敗しました'),
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiFetch(`/api/v1/groups/${id}`, { method: 'DELETE' })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['groups'] })
      if (selectedId === deleteId) setSelectedId(null)
      setDeleteId(null)
      setError(null)
    },
    onError: () => setError('グループの削除に失敗しました'),
  })

  const removeMemberMutation = useMutation({
    mutationFn: async ({ groupId, agentId }: { groupId: string; agentId: string }) => {
      await apiFetch(`/api/v1/agents/${agentId}`, { method: 'PATCH', body: JSON.stringify({ group_id: null }) })
      qc.invalidateQueries({ queryKey: ['group-detail', groupId] })
    },
  })

  const addMemberMutation = useMutation({
    mutationFn: async ({ groupId, agentId }: { groupId: string; agentId: string }) => {
      await apiFetch(`/api/v1/agents/${agentId}`, { method: 'PATCH', body: JSON.stringify({ group_id: groupId }) })
      qc.invalidateQueries({ queryKey: ['group-detail', groupId] })
      qc.invalidateQueries({ queryKey: ['groups'] })
    },
    onError: (err) => setError(`エンドポイントの追加に失敗しました: ${err instanceof Error ? err.message : String(err)}`),
  })

  const emptyDetail = (id: string): GroupDetail => ({
    id, name: '', description: '', color: COLORS[0],
    members: [], policies: [], alerts: [],
    stats: { alert_trend: [0, 0, 0, 0, 0, 0, 0], online_count: 0, offline_count: 0 },
  })

  const addPolicyMutation = useMutation({
    mutationFn: async ({ groupId, policyId }: { groupId: string; policyId: string }) => {
      const policy = ALL_POLICIES.find(p => p.id === policyId)
      if (!policy) return
      setLocalDetail(prev => {
        const d = prev[groupId] ?? emptyDetail(groupId)
        return { ...prev, [groupId]: { ...d, policies: [...d.policies, policy] } }
      })
      qc.invalidateQueries({ queryKey: ['group-detail', groupId] })
    },
  })

  const removePolicyMutation = useMutation({
    mutationFn: async ({ groupId, policyId }: { groupId: string; policyId: string }) => {
      setLocalDetail(prev => {
        const d = prev[groupId] ?? emptyDetail(groupId)
        return { ...prev, [groupId]: { ...d, policies: d.policies.filter(p => p.id !== policyId) } }
      })
      qc.invalidateQueries({ queryKey: ['group-detail', groupId] })
    },
  })

  // ── Derived data ─────────────────────────────────────────────────────────────
  const allGroups = groupsData?.groups ?? []
  const groups = tagFilter ? allGroups.filter(g => g.tags?.includes(tagFilter)) : allGroups
  const allTags = [...new Set(allGroups.flatMap(g => g.tags ?? []))]
  const selectedGroup = groups.find(g => g.id === selectedId) ?? null
  const detail = (selectedId && (detailData ?? localDetail[selectedId] ?? null)) ?? null

  const totalEndpoints = groups.reduce((s, g) => s + g.endpoint_count, 0)
  const totalPolicies = groups.reduce((s, g) => s + g.policy_count, 0)
  const alertsToday = groups.reduce((s, g) => s + g.alert_count, 0)

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">エンドポイントグループ</h1>
          <p className="text-falcon-muted text-sm mt-1">エンドポイントをグループ化し、ポリシー・アラートを管理します</p>
        </div>
        {canWrite && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#b5001e] text-white text-sm rounded-lg transition-colors font-medium"
          >
            <Plus className="w-4 h-4" />
            グループを作成
          </button>
        )}
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 border border-red-700/50 rounded-lg px-4 py-3">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
          <button onClick={() => setError(null)} className="ml-auto"><X className="w-3.5 h-3.5" /></button>
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          icon={<Layers className="w-5 h-5 text-blue-400" />}
          label="グループ総数"
          value={groups.length}
          sub="アクティブグループ"
        />
        <StatCard
          icon={<Monitor className="w-5 h-5 text-emerald-400" />}
          label="エンドポイント総数"
          value={totalEndpoints}
          sub="グループ内合計"
        />
        <StatCard
          icon={<ShieldCheck className="w-5 h-5 text-purple-400" />}
          label="アクティブポリシー"
          value={totalPolicies}
          sub="割り当て済み"
        />
        <StatCard
          icon={<Bell className="w-5 h-5 text-falcon-red" />}
          label="本日のグループアラート"
          value={alertsToday}
          sub="全グループ合計"
        />
      </div>

      {/* Tag filter */}
      {allTags.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-falcon-muted">タグ:</span>
          <button
            onClick={() => setTagFilter(null)}
            className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${!tagFilter ? 'bg-falcon-border text-white border-falcon-subtle' : 'bg-transparent text-falcon-muted border-falcon-border hover:border-falcon-subtle'}`}
          >
            すべて
          </button>
          {allTags.map(tag => (
            <button
              key={tag}
              onClick={() => setTagFilter(tagFilter === tag ? null : tag)}
              className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${tagFilter === tag ? 'bg-falcon-border text-white border-falcon-subtle' : 'bg-transparent text-falcon-muted border-falcon-border hover:border-falcon-subtle'}`}
            >
              #{tag}
            </button>
          ))}
        </div>
      )}

      {/* Body: Group list + detail panel */}
      <div className={`grid gap-4 ${selectedId ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>

        {/* Left: Group list */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-falcon-border flex items-center justify-between">
            <span className="text-white font-medium text-sm">グループ</span>
            <span className="text-falcon-muted text-xs">全{groups.length}件</span>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-falcon-red" />
            </div>
          ) : groups.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-falcon-muted">
              <Layers className="w-10 h-10 opacity-20" />
              <p className="text-sm">グループがまだありません</p>
              <button onClick={() => setShowCreate(true)} className="text-falcon-red hover:text-red-300 text-sm transition-colors">
                最初のグループを作成
              </button>
            </div>
          ) : (
            <div className="divide-y divide-falcon-border">
              {groups.map(group => {
                const isSelected = selectedId === group.id
                const isDeleteTarget = deleteId === group.id
                return (
                  <div key={group.id}>
                    <div
                      onClick={() => setSelectedId(isSelected ? null : group.id)}
                      className={`px-4 py-4 flex items-center gap-4 cursor-pointer transition-colors group
                        ${isSelected ? 'bg-[#131d30] border-l-2' : 'hover:bg-[#0a1020] border-l-2 border-transparent'}
                      `}
                      style={isSelected ? { borderLeftColor: group.color } : undefined}
                    >
                      {/* Color badge */}
                      <div
                        className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                        style={{ backgroundColor: `${group.color}22`, border: `1px solid ${group.color}55` }}
                      >
                        <Layers className="w-5 h-5" style={{ color: group.color }} />
                      </div>

                      {/* Name + desc */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-white font-medium text-sm">{group.name}</span>
                          {group.alert_count > 0 && (
                            <span className="text-[10px] bg-falcon-red/20 text-falcon-red px-1.5 py-0.5 rounded-full">
                              {group.alert_count}件のアラート
                            </span>
                          )}
                        </div>
                        <p className="text-falcon-muted text-xs mt-0.5 truncate">{group.description || '説明なし'}</p>
                        {group.tags && group.tags.length > 0 && (
                          <div className="flex gap-1 mt-1 flex-wrap">
                            {group.tags.map(tag => (
                              <span key={tag} className="px-1.5 py-0.5 rounded-sm text-[9px] bg-[#131d30] text-[#5a6a7a] border border-falcon-border">
                                #{tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Counts */}
                      <div className="flex items-center gap-3 text-xs text-falcon-muted shrink-0">
                        <div className="flex items-center gap-1">
                          <Monitor className="w-3 h-3" />
                          <span className="text-white font-medium">{group.endpoint_count}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <ShieldCheck className="w-3 h-3" />
                          <span className="text-white font-medium">{group.policy_count}</span>
                        </div>
                        <ChevronRight className={`w-4 h-4 transition-transform ${isSelected ? 'rotate-90 text-white' : ''}`} />
                      </div>

                      {/* Delete button */}
                      {canWrite && (
                        <button
                          onClick={e => { e.stopPropagation(); setDeleteId(group.id) }}
                          className="p-1.5 text-[#3a4d62] hover:text-red-400 hover:bg-red-900/20 rounded-sm transition-colors opacity-0 group-hover:opacity-100"
                          title="グループを削除"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>

                    {/* Delete confirmation */}
                    {isDeleteTarget && (
                      <div className="px-4 pb-3">
                        <DeleteConfirmBar
                          group={group}
                          onConfirm={() => deleteMutation.mutate(group.id)}
                          onCancel={() => setDeleteId(null)}
                          isDeleting={deleteMutation.isPending}
                        />
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right: Detail panel */}
        {selectedGroup && detail && (
          <GroupDetailPanel
            group={selectedGroup}
            detail={detail}
            onClose={() => setSelectedId(null)}
            onRemoveMember={canWrite ? (agentId => removeMemberMutation.mutate({ groupId: selectedGroup.id, agentId })) : undefined}
            onAddMember={canWrite ? (agentId => addMemberMutation.mutate({ groupId: selectedGroup.id, agentId })) : undefined}
            onAddPolicy={canWrite ? (policyId => addPolicyMutation.mutate({ groupId: selectedGroup.id, policyId })) : undefined}
            onRemovePolicy={canWrite ? (policyId => removePolicyMutation.mutate({ groupId: selectedGroup.id, policyId })) : undefined}
          />
        )}
      </div>

      {/* Create modal */}
      {showCreate && (
        <CreateGroupModal
          onClose={() => setShowCreate(false)}
          onCreate={data => createMutation.mutate(data)}
          isPending={createMutation.isPending}
        />
      )}
    </div>
  )
}
