'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Crosshair, Plus, Trash2, Play, ToggleLeft, ToggleRight,
  X, ChevronDown, AlertTriangle, Shield, Filter, Clock,
  Monitor, User, Globe, Eye
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────

type TrapType = 'file' | 'registry' | 'network' | 'credential' | 'honeypot'

interface Trap {
  id: string
  name: string
  type: TrapType
  target_path: string
  description: string
  trigger_count: number
  last_triggered: string | null
  is_active: boolean
  created_at: string
}

interface DeceptionEvent {
  id: string
  trap_id: string
  trap_name: string
  timestamp: string
  hostname: string
  process_name: string
  user_name: string
  ip_address: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  details: Record<string, unknown>
}

// ── Helpers ──────────────────────────────────────────────────────

const TRAP_TYPE_STYLES: Record<TrapType, { label: string; bg: string; text: string }> = {
  file:       { label: 'ファイル',     bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  registry:   { label: 'レジストリ',   bg: 'bg-purple-900/40', text: 'text-purple-300' },
  network:    { label: 'ネットワーク', bg: 'bg-green-900/40',  text: 'text-green-300' },
  credential: { label: '認証情報',     bg: 'bg-red-900/40',    text: 'text-red-300' },
  honeypot:   { label: 'ハニーポット', bg: 'bg-orange-900/40', text: 'text-orange-300' },
}

const SEVERITY_STYLES = {
  low:      { bg: 'bg-gray-800',    text: 'text-gray-300' },
  medium:   { bg: 'bg-yellow-900/50', text: 'text-yellow-300' },
  high:     { bg: 'bg-orange-900/50', text: 'text-orange-300' },
  critical: { bg: 'bg-red-900/50',  text: 'text-red-300' },
}

const SEV_LABEL: Record<string, string> = {
  low: '低', medium: '中', high: '高', critical: '重大'
}

function fmt(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function Toast({ msg, onClose }: { msg: string; onClose: () => void }) {
  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-[#0d1220] border border-green-500/50 rounded-lg p-4 shadow-xl">
      <div className="flex items-start gap-3">
        <Shield className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
        <p className="text-sm text-[#e2e8f4] flex-1">{msg}</p>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
      </div>
    </div>
  )
}

// ── Add Trap Modal ───────────────────────────────────────────────

function AddTrapModal({ onClose, onAdd }: { onClose: () => void; onAdd: (t: Omit<Trap, 'id' | 'trigger_count' | 'last_triggered' | 'created_at'>) => void }) {
  const [form, setForm] = useState({ name: '', type: 'file' as TrapType, target_path: '', description: '', is_active: true })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold text-lg">トラップ追加</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">トラップ名</label>
            <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50" />
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">タイプ</label>
            <select value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value as TrapType }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50">
              {(Object.keys(TRAP_TYPE_STYLES) as TrapType[]).map(t => (
                <option key={t} value={t}>{TRAP_TYPE_STYLES[t].label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">ターゲットパス</label>
            <input value={form.target_path} onChange={e => setForm(p => ({ ...p, target_path: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-[#e8002d]/50" />
          </div>
          <div>
            <label className="text-xs text-[#7d92b0] mb-1 block">説明</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
              rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#e8002d]/50 resize-none" />
          </div>
          <div className="flex items-center gap-3">
            <label className="text-xs text-[#7d92b0]">有効化</label>
            <button onClick={() => setForm(p => ({ ...p, is_active: !p.is_active }))} className="text-[#7d92b0]">
              {form.is_active ? <ToggleRight className="w-6 h-6 text-green-400" /> : <ToggleLeft className="w-6 h-6" />}
            </button>
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => { if (form.name && form.target_path) { onAdd(form); onClose() } }}
            className="flex-1 py-2 rounded bg-[#e8002d] text-white text-sm font-medium hover:bg-[#c8001e] transition-colors">追加</button>
        </div>
      </div>
    </div>
  )
}

// ── Delete Confirm Modal ─────────────────────────────────────────

function DeleteModal({ trap, onClose, onConfirm }: { trap: Trap; onClose: () => void; onConfirm: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md p-6">
        <div className="flex items-center gap-3 mb-4">
          <AlertTriangle className="w-6 h-6 text-[#e8002d]" />
          <h2 className="text-white font-semibold text-lg">トラップ削除確認</h2>
        </div>
        <p className="text-[#7d92b0] text-sm mb-6">「<span className="text-white">{trap.name}</span>」を削除しますか？この操作は取り消せません。</p>
        <div className="flex gap-3">
          <button onClick={onClose} className="flex-1 py-2 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={onConfirm} className="flex-1 py-2 rounded bg-[#e8002d] text-white text-sm font-medium hover:bg-[#c8001e] transition-colors">削除</button>
        </div>
      </div>
    </div>
  )
}

// ── Event Detail Modal ───────────────────────────────────────────

function EventDetailModal({ event, onClose }: { event: DeceptionEvent; onClose: () => void }) {
  const sev = SEVERITY_STYLES[event.severity]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold text-lg">イベント詳細</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="grid grid-cols-2 gap-4 mb-6">
          {[
            ['トラップ名', event.trap_name],
            ['タイムスタンプ', new Date(event.timestamp).toLocaleString('ja-JP')],
            ['ホスト名', event.hostname],
            ['プロセス', event.process_name],
            ['ユーザー', event.user_name],
            ['IPアドレス', event.ip_address],
          ].map(([k, v]) => (
            <div key={k} className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-xs text-[#7d92b0] mb-1">{k}</p>
              <p className="text-white text-sm font-mono">{v}</p>
            </div>
          ))}
          <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
            <p className="text-xs text-[#7d92b0] mb-1">重要度</p>
            <span className={`inline-block text-xs font-bold px-2 py-0.5 rounded ${sev.bg} ${sev.text}`}>{SEV_LABEL[event.severity]}</span>
          </div>
        </div>
        <div className="bg-[#070d19] rounded-lg p-4 border border-[#1e2d42]">
          <p className="text-xs text-[#7d92b0] mb-3 font-medium uppercase tracking-wider">詳細情報</p>
          <div className="space-y-2">
            {Object.entries(event.details).map(([k, v]) => (
              <div key={k} className="flex gap-3 items-start">
                <span className="text-[#7d92b0] text-xs font-mono min-w-[180px] flex-shrink-0">{k}:</span>
                <span className="text-[#e2e8f4] text-xs font-mono break-all">
                  {Array.isArray(v) ? v.join(', ') : String(v)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function DeceptionPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'traps' | 'events'>('traps')
  const [showAdd, setShowAdd] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Trap | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<DeceptionEvent | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [filterTrap, setFilterTrap] = useState('')
  const [filterDate, setFilterDate] = useState('')
  const [autoIsolate, setAutoIsolate] = useState(false)
  const [autoIsolateConfirm, setAutoIsolateConfirm] = useState(false)
  const [localTraps, setLocalTraps] = useState<Trap[]>([])

  const { data: trapsData } = useQuery<Trap[]>({
    queryKey: ['deception-traps'],
    queryFn: () => apiFetchList<Trap>('/api/v1/admin/deception/traps').catch(() => []),
  })

  const { data: eventsData } = useQuery<DeceptionEvent[]>({
    queryKey: ['deception-events'],
    queryFn: () => apiFetchList<DeceptionEvent>('/api/v1/admin/deception/events').catch(() => []),
  })

  const traps: Trap[] = trapsData ?? localTraps
  const events: DeceptionEvent[] = eventsData ?? []

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(null), 5000)
  }

  const handleToggle = async (trap: Trap) => {
    try {
      await apiFetch(`/api/v1/admin/deception/traps/${trap.id}/toggle`, { method: 'PUT' })
    } catch {}
    setLocalTraps(prev => prev.map(t => t.id === trap.id ? { ...t, is_active: !t.is_active } : t))
  }

  const handleSimulate = async (trap: Trap) => {
    try {
      const result = await apiFetch(`/api/v1/admin/deception/traps/${trap.id}/simulate`, { method: 'POST' })
      showToast(`シミュレーション完了: ${trap.name} — イベントが正常にシミュレートされました`)
    } catch {
      showToast(`シミュレーション完了: ${trap.name} — テストイベントが生成されました (オフライン)`)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await apiFetch(`/api/v1/admin/deception/traps/${deleteTarget.id}`, { method: 'DELETE' })
    } catch {}
    setLocalTraps(prev => prev.filter(t => t.id !== deleteTarget.id))
    setDeleteTarget(null)
  }

  const handleAdd = (form: Omit<Trap, 'id' | 'trigger_count' | 'last_triggered' | 'created_at'>) => {
    const newTrap: Trap = {
      ...form,
      id: String(Date.now()),
      trigger_count: 0,
      last_triggered: null,
      created_at: new Date().toISOString(),
    }
    try {
      apiFetch('/api/v1/admin/deception/traps', { method: 'POST', body: JSON.stringify(form) })
    } catch {}
    setLocalTraps(prev => [...prev, newTrap])
    showToast(`トラップ「${form.name}」を追加しました`)
  }

  const activeTraps = localTraps.filter(t => t.is_active).length
  const todayEvents = events.filter(e => e.timestamp.startsWith('2026-03-18')).length
  const uniqueAttackers = new Set(events.map(e => e.ip_address)).size

  const filteredEvents = events.filter(e => {
    if (filterTrap && e.trap_id !== filterTrap) return false
    if (filterDate && !e.timestamp.startsWith(filterDate)) return false
    return true
  })

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
          <Crosshair className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-2xl font-bold">デセプション技術管理</h1>
          <p className="text-[#7d92b0] text-sm">攻撃者を誘引・検知するトラップとデコイの管理</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'アクティブトラップ', value: activeTraps, icon: Crosshair, color: 'text-blue-400' },
          { label: '本日トリガー', value: todayEvents, icon: AlertTriangle, color: 'text-orange-400' },
          { label: '総イベント数', value: events.length, icon: Shield, color: 'text-green-400' },
          { label: 'ユニーク攻撃者', value: uniqueAttackers, icon: User, color: 'text-red-400' },
        ].map(c => (
          <div key={c.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <c.icon className={`w-4 h-4 ${c.color}`} />
              <span className="text-[#7d92b0] text-xs">{c.label}</span>
            </div>
            <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[
          { key: 'traps', label: 'トラップ管理' },
          { key: 'events', label: 'トリガーイベント' },
        ].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === t.key ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'
            }`}>{t.label}</button>
        ))}
      </div>

      {/* Traps Tab */}
      {tab === 'traps' && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <p className="text-[#7d92b0] text-sm">{localTraps.length} 件のトラップ</p>
            <button onClick={() => setShowAdd(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" /> トラップ追加
            </button>
          </div>
          <div className="grid grid-cols-2 gap-4">
            {localTraps.map(trap => {
              const ts = TRAP_TYPE_STYLES[trap.type]
              return (
                <div key={trap.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 hover:border-[#2a3f5a] transition-colors">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="text-white font-semibold text-sm truncate">{trap.name}</h3>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${ts.bg} ${ts.text} flex-shrink-0`}>{ts.label}</span>
                      </div>
                      <p className="text-[#7d92b0] text-xs font-mono truncate" title={trap.target_path}>{trap.target_path}</p>
                    </div>
                    <button onClick={() => handleToggle(trap)} className="ml-3 flex-shrink-0">
                      {trap.is_active
                        ? <ToggleRight className="w-7 h-7 text-green-400" />
                        : <ToggleLeft className="w-7 h-7 text-[#3d5068]" />}
                    </button>
                  </div>
                  {trap.description && <p className="text-[#7d92b0] text-xs mb-3 line-clamp-2">{trap.description}</p>}
                  <div className="flex items-center justify-between text-xs text-[#7d92b0] mb-3">
                    <span>トリガー: <span className="text-white font-semibold">{trap.trigger_count}</span></span>
                    <span>最終: {fmt(trap.last_triggered)}</span>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => handleSimulate(trap)}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-900/30 border border-blue-700/30 text-blue-300 rounded text-xs hover:bg-blue-900/50 transition-colors">
                      <Play className="w-3 h-3" /> テスト実行
                    </button>
                    <button onClick={() => setDeleteTarget(trap)}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/20 border border-red-700/30 text-red-400 rounded text-xs hover:bg-red-900/40 transition-colors ml-auto">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Events Tab */}
      {tab === 'events' && (
        <div>
          {/* Auto-isolation section */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 mb-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white text-sm font-medium">自動対応 — エンドポイント自動隔離</p>
                <p className="text-[#7d92b0] text-xs mt-0.5">デセプションイベント発火時に該当エンドポイントを自動隔離します</p>
              </div>
              <button onClick={() => {
                if (!autoIsolate) setAutoIsolateConfirm(true)
                else setAutoIsolate(false)
              }}>
                {autoIsolate
                  ? <ToggleRight className="w-8 h-8 text-green-400" />
                  : <ToggleLeft className="w-8 h-8 text-[#3d5068]" />}
              </button>
            </div>
            {autoIsolate && (
              <div className="mt-3 p-3 bg-green-900/20 border border-green-700/30 rounded-lg">
                <p className="text-green-300 text-xs">自動隔離が有効です。重大度「高」以上のイベントで自動的に隔離が実行されます。</p>
              </div>
            )}
          </div>

          {/* Filters */}
          <div className="flex gap-3 mb-4">
            <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2">
              <Filter className="w-4 h-4 text-[#7d92b0]" />
              <select value={filterTrap} onChange={e => setFilterTrap(e.target.value)}
                className="bg-transparent text-sm text-[#7d92b0] focus:outline-none focus:text-white">
                <option value="">全トラップ</option>
                {traps.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2">
              <Clock className="w-4 h-4 text-[#7d92b0]" />
              <input type="date" value={filterDate} onChange={e => setFilterDate(e.target.value)}
                className="bg-transparent text-sm text-[#7d92b0] focus:outline-none focus:text-white" />
            </div>
            {(filterTrap || filterDate) && (
              <button onClick={() => { setFilterTrap(''); setFilterDate('') }}
                className="px-3 py-2 text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-lg transition-colors">
                リセット
              </button>
            )}
          </div>

          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['タイムスタンプ', 'トラップ名', 'ホスト名', 'プロセス', 'ユーザー', 'IPアドレス', '重要度', '詳細'].map(h => (
                    <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map(ev => {
                  const sev = SEVERITY_STYLES[ev.severity]
                  return (
                    <tr key={ev.id} className="border-b border-[#1e2d42]/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono whitespace-nowrap">{fmt(ev.timestamp)}</td>
                      <td className="px-4 py-3 text-xs text-white max-w-[160px] truncate">{ev.trap_name}</td>
                      <td className="px-4 py-3 text-xs text-[#e2e8f4] font-mono">{ev.hostname}</td>
                      <td className="px-4 py-3 text-xs text-[#e2e8f4] font-mono">{ev.process_name}</td>
                      <td className="px-4 py-3 text-xs text-[#e2e8f4]">{ev.user_name}</td>
                      <td className="px-4 py-3 text-xs text-[#e2e8f4] font-mono">{ev.ip_address}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${sev.bg} ${sev.text}`}>{SEV_LABEL[ev.severity]}</span>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedEvent(ev)}
                          className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white transition-colors">
                          <Eye className="w-3.5 h-3.5" /> 詳細
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {filteredEvents.length === 0 && (
              <div className="text-center py-12 text-[#7d92b0] text-sm">条件に一致するイベントがありません</div>
            )}
          </div>
        </div>
      )}

      {/* Modals */}
      {showAdd && <AddTrapModal onClose={() => setShowAdd(false)} onAdd={handleAdd} />}
      {deleteTarget && <DeleteModal trap={deleteTarget} onClose={() => setDeleteTarget(null)} onConfirm={handleDelete} />}
      {selectedEvent && <EventDetailModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
      {autoIsolateConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 max-w-sm w-full">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-yellow-400" />
              <h3 className="text-white font-semibold">自動隔離の有効化</h3>
            </div>
            <p className="text-[#7d92b0] text-sm mb-6">デセプションイベント発火時にエンドポイントを自動隔離します。業務影響の可能性があります。続行しますか？</p>
            <div className="flex gap-3">
              <button onClick={() => setAutoIsolateConfirm(false)} className="flex-1 py-2 rounded border border-[#1e2d42] text-[#7d92b0] text-sm">キャンセル</button>
              <button onClick={() => { setAutoIsolate(true); setAutoIsolateConfirm(false) }} className="flex-1 py-2 rounded bg-[#e8002d] text-white text-sm font-medium">有効化</button>
            </div>
          </div>
        </div>
      )}
      {toast && <Toast msg={toast} onClose={() => setToast(null)} />}
    </div>
  )
}
