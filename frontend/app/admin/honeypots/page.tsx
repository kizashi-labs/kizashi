'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Bug, Plus, Trash2, RefreshCw, Edit2, X, ToggleLeft, ToggleRight,
  Activity, Shield, Eye, Zap, Clock, Server, AlertTriangle, Check
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ───────────────────────────────────────────────────────

interface Honeypot {
  id: string
  name: string
  description: string
  honeypot_type: 'http' | 'ssh' | 'smb' | 'ftp' | 'rdp'
  listen_address: string
  listen_port: number
  agent_id: string | null
  agent_hostname: string | null
  access_count: number
  last_accessed: string | null
  enabled: boolean
  alert_on_access: boolean
  created_at: string
}

interface HoneypotAccess {
  id: string
  honeypot_id: string
  honeypot_name: string
  source_ip: string
  source_port: number
  method: string
  path: string
  user_agent: string
  accessed_at: string
}

interface HoneypotStats {
  total: number
  active: number
  accesses_today: number
  unique_source_ips: number
}

interface Agent {
  id: string
  hostname: string
}

// ── Helpers ──────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  http: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  ssh:  'bg-green-500/20 text-green-300 border-green-500/30',
  smb:  'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  ftp:  'bg-purple-500/20 text-purple-300 border-purple-500/30',
  rdp:  'bg-orange-500/20 text-orange-300 border-orange-500/30',
}

function getCountryFlag(ip: string): string {
  const first = parseInt(ip.split('.')[0] ?? '0', 10)
  if (first >= 1 && first <= 50) return '🇨🇳'
  if (first >= 51 && first <= 100) return '🇷🇺'
  if (first >= 101 && first <= 130) return '🇧🇷'
  if (first >= 131 && first <= 160) return '🇺🇸'
  if (first >= 161 && first <= 190) return '🇩🇪'
  if (first >= 191 && first <= 210) return '🇮🇷'
  return '🌐'
}

function formatRelativeTime(iso: string | null): string {
  if (!iso) return 'なし'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 60) return `${mins}分前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}時間前`
  return `${Math.floor(hours / 24)}日前`
}

// ── Toast ────────────────────────────────────────────────────────

function Toast({ message, onClose }: { message: string; onClose: () => void }) {
  useEffect(() => {
    const t = setTimeout(onClose, 3000)
    return () => clearTimeout(t)
  }, [onClose])
  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-lg bg-[#0d1220] border border-green-500/40 text-green-300 shadow-xl animate-fade-in">
      <Check className="w-4 h-4 text-green-400" />
      <span className="text-sm font-medium">{message}</span>
      <button onClick={onClose} className="ml-2 text-[#7d92b0] hover:text-white">
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

// ── Add/Edit Modal ───────────────────────────────────────────────

interface HoneypotFormData {
  name: string
  description: string
  honeypot_type: Honeypot['honeypot_type']
  listen_address: string
  listen_port: number
  agent_id: string
  alert_on_access: boolean
}

function HoneypotModal({
  honeypot,
  agents,
  onClose,
  onSave,
}: {
  honeypot?: Honeypot
  agents: Agent[]
  onClose: () => void
  onSave: (data: HoneypotFormData) => void
}) {
  const [form, setForm] = useState<HoneypotFormData>({
    name: honeypot?.name ?? '',
    description: honeypot?.description ?? '',
    honeypot_type: honeypot?.honeypot_type ?? 'http',
    listen_address: honeypot?.listen_address ?? '0.0.0.0',
    listen_port: honeypot?.listen_port ?? 8080,
    agent_id: honeypot?.agent_id ?? '',
    alert_on_access: honeypot?.alert_on_access ?? true,
  })

  const portDefaults: Record<string, number> = { http: 8080, ssh: 2222, smb: 445, ftp: 21, rdp: 3389 }

  const handleTypeChange = (type: Honeypot['honeypot_type']) => {
    setForm(f => ({ ...f, honeypot_type: type, listen_port: portDefaults[type] ?? f.listen_port }))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-base">
            {honeypot ? 'ハニーポット編集' : 'ハニーポット追加'}
          </h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">名前 *</label>
            <input
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff] transition-colors"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: Web Decoy Server"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
            <textarea
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff] transition-colors resize-none h-20"
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="ハニーポットの説明を入力してください"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">タイプ *</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={form.honeypot_type}
                onChange={e => handleTypeChange(e.target.value as Honeypot['honeypot_type'])}
              >
                <option value="http">HTTP</option>
                <option value="ssh">SSH</option>
                <option value="smb">SMB</option>
                <option value="ftp">FTP</option>
                <option value="rdp">RDP</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">エージェント</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={form.agent_id}
                onChange={e => setForm(f => ({ ...f, agent_id: e.target.value }))}
              >
                <option value="">未割り当て</option>
                {agents.map(a => (
                  <option key={a.id} value={a.id}>{a.hostname}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">リッスンアドレス *</label>
              <input
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff] font-mono transition-colors"
                value={form.listen_address}
                onChange={e => setForm(f => ({ ...f, listen_address: e.target.value }))}
                placeholder="0.0.0.0"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">ポート *</label>
              <input
                type="number"
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff] font-mono transition-colors"
                value={form.listen_port}
                onChange={e => setForm(f => ({ ...f, listen_port: parseInt(e.target.value) || 0 }))}
                min={1}
                max={65535}
              />
            </div>
          </div>
          <div className="flex items-center justify-between py-2 px-3 bg-[#070d19] rounded-lg border border-[#1e2d42]">
            <div>
              <p className="text-sm text-[#e2e8f4] font-medium">アクセス時アラート</p>
              <p className="text-xs text-[#7d92b0]">アクセスが検知された際にアラートを発生させる</p>
            </div>
            <button
              onClick={() => setForm(f => ({ ...f, alert_on_access: !f.alert_on_access }))}
              className="transition-colors"
            >
              {form.alert_on_access
                ? <ToggleRight className="w-8 h-8 text-green-400" />
                : <ToggleLeft className="w-8 h-8 text-[#3d5068]" />}
            </button>
          </div>
        </div>
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => { if (form.name) onSave(form) }}
            disabled={!form.name}
            className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function HoneypotsPage() {
  const [activeTab, setActiveTab] = useState<'list' | 'access'>('list')
  const [showModal, setShowModal] = useState(false)
  const [editingHoneypot, setEditingHoneypot] = useState<Honeypot | undefined>()
  const [accessFilter, setAccessFilter] = useState('')
  const [toast, setToast] = useState<string | null>(null)
  const [liveRefresh, setLiveRefresh] = useState(0)

  const queryClient = useQueryClient()

  // Auto-refresh access log every 30s
  useEffect(() => {
    if (activeTab !== 'access') return
    const id = setInterval(() => setLiveRefresh(n => n + 1), 30_000)
    return () => clearInterval(id)
  }, [activeTab])

  // ── Queries ──────────────────────────────────────────────────
  const { data: stats = { total: 0, active: 0, accesses_today: 0, unique_source_ips: 0 } as HoneypotStats } = useQuery<HoneypotStats>({
    queryKey: ['honeypot-stats'],
    queryFn: () => apiFetch<HoneypotStats>('/api/v1/admin/honeypots/stats'),
    staleTime: 30_000,
  })

  const { data: honeypots = [], isLoading: loadingHoneypots } = useQuery<Honeypot[]>({
    queryKey: ['honeypots'],
    queryFn: () => apiFetchList<Honeypot>('/api/v1/admin/honeypots'),
    staleTime: 30_000,
  })

  const { data: accesses = [], isLoading: loadingAccesses } = useQuery<HoneypotAccess[]>({
    queryKey: ['honeypot-accesses', liveRefresh],
    queryFn: () => apiFetchList<HoneypotAccess>('/api/v1/admin/honeypots/accesses'),
    enabled: activeTab === 'access',
    staleTime: 0,
  })

  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents-for-honeypots'],
    queryFn: () => apiFetchList<Agent>('/api/v1/agents'),
  })

  // ── Mutations ────────────────────────────────────────────────
  const createMutation = useMutation({
    mutationFn: (data: HoneypotFormData) => apiFetch('/api/v1/admin/honeypots', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['honeypots'] }); setShowModal(false); setToast('ハニーポットを追加しました') },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: HoneypotFormData }) =>
      apiFetch(`/api/v1/admin/honeypots/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['honeypots'] }); setShowModal(false); setEditingHoneypot(undefined); setToast('ハニーポットを更新しました') },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/honeypots/${id}`, { method: 'DELETE' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['honeypots'] }); setToast('ハニーポットを削除しました') },
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/honeypots/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['honeypots'] }),
  })

  const simulateMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/honeypots/${id}/simulate`, { method: 'POST' }),
    onSuccess: () => setToast('アクセスシミュレーション完了'),
  })

  // ── Derived ──────────────────────────────────────────────────
  const EMPTY_HONEYPOT_STATS: HoneypotStats = { total: 0, active: 0, accesses_today: 0, unique_source_ips: 0 }
  const displayStats = stats ?? EMPTY_HONEYPOT_STATS

  const filteredAccesses = accesses.filter(a =>
    !accessFilter || a.honeypot_id === accessFilter
  )

  // Top source IPs
  const ipCounts: Record<string, number> = {}
  accesses.forEach(a => { ipCounts[a.source_ip] = (ipCounts[a.source_ip] ?? 0) + 1 })
  const topIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)

  const handleSave = (data: HoneypotFormData) => {
    if (editingHoneypot) {
      updateMutation.mutate({ id: editingHoneypot.id, data })
    } else {
      createMutation.mutate(data)
    }
  }

  const handleEdit = (hp: Honeypot) => {
    setEditingHoneypot(hp)
    setShowModal(true)
  }

  const handleAdd = () => {
    setEditingHoneypot(undefined)
    setShowModal(true)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed />
      {toast && <Toast message={toast} onClose={() => setToast(null)} />}
      {showModal && (
        <HoneypotModal
          honeypot={editingHoneypot}
          agents={agents}
          onClose={() => { setShowModal(false); setEditingHoneypot(undefined) }}
          onSave={handleSave}
        />
      )}

      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
                <Bug className="w-5 h-5 text-[#e8002d]" />
              </div>
              <h1 className="text-2xl font-bold text-white">ハニーポット管理</h1>
            </div>
            <p className="text-sm text-[#7d92b0] ml-12">囮エンドポイントでの不審アクセスを検知します</p>
          </div>
          <button
            onClick={handleAdd}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            ハニーポット追加
          </button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: '合計ハニーポット', value: displayStats.total, icon: Bug, color: 'text-[#7d92b0]' },
            { label: 'アクティブ', value: displayStats.active, icon: Activity, color: 'text-green-400' },
            { label: '今日のアクセス', value: displayStats.accesses_today, icon: Eye, color: 'text-[#e8002d]' },
            { label: 'ユニーク送信元IP', value: displayStats.unique_source_ips, icon: Shield, color: 'text-blue-400' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-[#7d92b0]">{label}</span>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <div className={`text-2xl font-bold ${color}`}>{value}</div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
          {([
            { key: 'list', label: 'ハニーポット一覧' },
            { key: 'access', label: 'アクセスログ' },
          ] as const).map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`px-4 py-2 text-sm rounded-md font-medium transition-all ${
                activeTab === key
                  ? 'bg-[#1d2f4a] text-white'
                  : 'text-[#7d92b0] hover:text-[#e2e8f4]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab: Honeypot List ─────────────────────────────── */}
        {activeTab === 'list' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-2 gap-4">
            {loadingHoneypots ? (
              Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 animate-pulse h-48" />
              ))
            ) : honeypots.length === 0 ? (
              <div className="col-span-2 flex flex-col items-center justify-center py-20 text-[#7d92b0]">
                <Bug className="w-12 h-12 mb-4 opacity-30" />
                <p className="text-sm">ハニーポットが登録されていません</p>
              </div>
            ) : (
              honeypots.map(hp => (
                <div key={hp.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 hover:border-[#2a3f5a] transition-colors">
                  {/* Card Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className={`px-2.5 py-1 text-xs font-bold rounded-full border uppercase ${TYPE_COLORS[hp.honeypot_type]}`}>
                        {hp.honeypot_type}
                      </span>
                      <div>
                        <p className="text-white font-semibold text-sm">{hp.name}</p>
                        <p className="text-[#7d92b0] text-xs font-mono">{hp.listen_address}:{hp.listen_port}</p>
                      </div>
                    </div>
                    <button
                      onClick={() => toggleMutation.mutate(hp.id)}
                      className="transition-colors shrink-0"
                      title={hp.enabled ? '無効化' : '有効化'}
                    >
                      {hp.enabled
                        ? <ToggleRight className="w-7 h-7 text-green-400" />
                        : <ToggleLeft className="w-7 h-7 text-[#3d5068]" />}
                    </button>
                  </div>

                  {/* Description */}
                  {hp.description && (
                    <p className="text-xs text-[#7d92b0] mb-3 line-clamp-2">{hp.description}</p>
                  )}

                  {/* Agent */}
                  <div className="flex items-center gap-2 mb-3">
                    <Server className="w-3.5 h-3.5 text-[#3d5068]" />
                    <span className="text-xs text-[#7d92b0]">
                      {hp.agent_hostname ?? <span className="text-yellow-400/80">未割り当て</span>}
                    </span>
                  </div>

                  {/* Access Count */}
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <p className={`text-3xl font-bold ${hp.access_count > 0 ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`}>
                        {hp.access_count}
                      </p>
                      <p className="text-xs text-[#7d92b0]">アクセス数</p>
                    </div>
                    <div className="text-right">
                      <div className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{formatRelativeTime(hp.last_accessed)}</span>
                      </div>
                      <p className="text-[10px] text-[#3d5068] mt-0.5">最終アクセス</p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 pt-3 border-t border-[#1e2d42]">
                    <button
                      onClick={() => handleEdit(hp)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-[#7d92b0] hover:text-white bg-[#070d19] hover:bg-[#1a253d] border border-[#1e2d42] hover:border-[#2a3f5a] rounded-lg transition-all"
                    >
                      <Edit2 className="w-3.5 h-3.5" />
                      編集
                    </button>
                    <button
                      onClick={() => simulateMutation.mutate(hp.id)}
                      disabled={simulateMutation.isPending}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-yellow-300 hover:text-yellow-100 bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/20 rounded-lg transition-all disabled:opacity-50"
                    >
                      <Zap className="w-3.5 h-3.5" />
                      シミュレート
                    </button>
                    <button
                      onClick={() => { if (confirm(`"${hp.name}" を削除しますか？`)) deleteMutation.mutate(hp.id) }}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-[#e8002d]/70 hover:text-[#e8002d] bg-[#e8002d]/5 hover:bg-[#e8002d]/10 border border-[#e8002d]/10 hover:border-[#e8002d]/30 rounded-lg transition-all ml-auto"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      削除
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* ── Tab: Access Log ───────────────────────────────── */}
        {activeTab === 'access' && (
          <div className="space-y-4">
            {/* Filter & LIVE badge */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="relative flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d]/10 border border-[#e8002d]/30 rounded-full">
                  <span className="absolute left-2.5 w-1.5 h-1.5 rounded-full bg-[#e8002d] animate-ping" />
                  <span className="w-1.5 h-1.5 rounded-full bg-[#e8002d]" />
                  <span className="text-xs font-bold text-[#e8002d] ml-2">LIVE</span>
                </div>
                <span className="text-xs text-[#7d92b0]">30秒ごとに自動更新</span>
              </div>
              <select
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={accessFilter}
                onChange={e => setAccessFilter(e.target.value)}
              >
                <option value="">全ハニーポット</option>
                {honeypots.map(hp => (
                  <option key={hp.id} value={hp.id}>{hp.name}</option>
                ))}
              </select>
              <button
                onClick={() => setLiveRefresh(n => n + 1)}
                className="flex items-center gap-2 px-3 py-2 text-sm text-[#7d92b0] hover:text-white bg-[#0d1220] border border-[#1e2d42] hover:border-[#2a3f5a] rounded-lg transition-all"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                更新
              </button>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
              {/* Access Log Table */}
              <div className="xl:col-span-3 bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">アクセスログ</h3>
                  <span className="text-xs text-[#7d92b0]">{filteredAccesses.length} 件</span>
                </div>
                {loadingAccesses ? (
                  <div className="p-8 text-center text-[#7d92b0] text-sm">読み込み中...</div>
                ) : filteredAccesses.length === 0 ? (
                  <div className="p-8 text-center text-[#7d92b0] text-sm">アクセスログがありません</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-[#1e2d42]">
                          {['ハニーポット', '送信元IP', 'Port', 'Method', 'Path', 'User Agent', '時刻'].map(h => (
                            <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide whitespace-nowrap">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1e2d42]">
                        {filteredAccesses.map(access => (
                          <tr key={access.id} className="hover:bg-[#0d1a2e] transition-colors">
                            <td className="px-4 py-3 text-xs font-medium text-[#e2e8f4] whitespace-nowrap">
                              {access.honeypot_name}
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <span className="text-base">{getCountryFlag(access.source_ip)}</span>
                                <span className="font-mono text-xs text-[#e2e8f4]">{access.source_ip}</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-xs font-mono text-[#7d92b0]">{access.source_port}</td>
                            <td className="px-4 py-3">
                              <span className="px-2 py-0.5 text-[10px] font-bold rounded-sm bg-blue-500/10 text-blue-300 border border-blue-500/20">
                                {access.method}
                              </span>
                            </td>
                            <td className="px-4 py-3 max-w-[120px]">
                              <span className="font-mono text-xs text-[#7d92b0] truncate block" title={access.path}>
                                {access.path.length > 20 ? access.path.substring(0, 20) + '…' : access.path}
                              </span>
                            </td>
                            <td className="px-4 py-3 max-w-[140px]">
                              <span className="text-xs text-[#7d92b0] truncate block" title={access.user_agent}>
                                {access.user_agent.length > 22 ? access.user_agent.substring(0, 22) + '…' : access.user_agent}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                              {formatRelativeTime(access.accessed_at)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Threat Map Placeholder */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1e2d42]">
                  <h3 className="text-sm font-semibold text-white">上位攻撃元 IP</h3>
                </div>
                <div className="p-4 space-y-3">
                  {topIPs.length === 0 ? (
                    <p className="text-xs text-[#7d92b0] text-center py-4">データなし</p>
                  ) : (
                    topIPs.map(([ip, count]) => (
                      <div key={ip} className="flex items-center gap-3">
                        <span className="text-base shrink-0">{getCountryFlag(ip)}</span>
                        <div className="flex-1 min-w-0">
                          <p className="font-mono text-xs text-[#e2e8f4] truncate">{ip}</p>
                          <div className="mt-1 h-1 bg-[#1e2d42] rounded-full overflow-hidden">
                            <div
                              className="h-full bg-[#e8002d] rounded-full"
                              style={{ width: `${Math.min(100, (count / (topIPs[0]?.[1] ?? 1)) * 100)}%` }}
                            />
                          </div>
                        </div>
                        <span className="text-xs font-bold text-[#e8002d] shrink-0">{count}</span>
                      </div>
                    ))
                  )}
                  <div className="mt-4 pt-4 border-t border-[#1e2d42]">
                    <div className="flex items-center gap-2 text-[#7d92b0]">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span className="text-xs">脅威マップ (準備中)</span>
                    </div>
                    <div className="mt-3 h-24 bg-[#070d19] rounded-lg border border-[#1e2d42] flex items-center justify-center">
                      <p className="text-xs text-[#3d5068]">Geographic visualization</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
