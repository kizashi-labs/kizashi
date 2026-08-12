'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Network, Play, Square, Download, Trash2, Plus, X,
  RefreshCw, AlertCircle, CheckCircle, Clock, Loader2,
  Filter, HardDrive, Timer, Calendar, Cpu
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
  os: string
  status: string
}

interface PacketCapture {
  id: string
  name: string
  agent_id: string
  agent_hostname: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  filter: string
  interface: string
  packets_captured: number
  file_size_bytes: number
  duration_seconds: number
  max_packets: number
  max_duration: number
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  created_at: string
}

interface CaptureListResponse {
  captures: PacketCapture[]
}

interface StartCaptureForm {
  agent_id: string
  name: string
  filter: string
  interface: string
  max_packets: number
  max_duration: number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function formatDuration(seconds: number): string {
  if (!seconds) return '—'
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}m ${s}s`
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  })
}

// ── Status Badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: PacketCapture['status'] }) {
  const config = {
    pending:   { label: 'Pending',   color: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30', icon: Clock },
    running:   { label: 'Running',   color: 'text-green-400  bg-green-400/10  border-green-400/30',  icon: Loader2 },
    completed: { label: 'Completed', color: 'text-blue-400   bg-blue-400/10   border-blue-400/30',   icon: CheckCircle },
    failed:    { label: 'Failed',    color: 'text-red-400    bg-red-400/10    border-red-400/30',     icon: AlertCircle },
  }[status]

  const Icon = config.icon

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${config.color}`}>
      <Icon className={`w-3 h-3 ${status === 'running' ? 'animate-spin' : ''}`} />
      {config.label}
    </span>
  )
}

// ── Start Capture Modal ───────────────────────────────────────────────────────

interface StartCaptureModalProps {
  onClose: () => void
  onSubmit: (form: StartCaptureForm) => void
  isSubmitting: boolean
}

function StartCaptureModal({ onClose, onSubmit, isSubmitting }: StartCaptureModalProps) {
  const [form, setForm] = useState<StartCaptureForm>({
    agent_id: '',
    name: '',
    filter: '',
    interface: 'eth0',
    max_packets: 10000,
    max_duration: 60,
  })

  const { data: agentsData } = useQuery<{ agents?: Agent[]; data?: Agent[] }>({
    queryKey: ['agents-for-capture'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=200'),
  })

  const agents = agentsData?.data ?? agentsData?.agents ?? []

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!form.agent_id || !form.name) return
    onSubmit(form)
  }

  const set = <K extends keyof StartCaptureForm>(key: K, value: StartCaptureForm[K]) =>
    setForm(prev => ({ ...prev, [key]: value }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl w-full max-w-lg mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#e8002d]/15 flex items-center justify-center">
              <Network className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h2 className="text-white font-semibold text-base">パケットキャプチャ開始</h2>
          </div>
          <button
            onClick={onClose}
            className="text-[#7d92b0] hover:text-white transition-colors p-1 rounded hover:bg-[#1e2d42]"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
          {/* Agent selector */}
          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wider">
              エージェント <span className="text-[#e8002d]">*</span>
            </label>
            <select
              value={form.agent_id}
              onChange={e => set('agent_id', e.target.value)}
              required
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                         text-[#e2e8f4] text-sm focus:outline-none focus:border-[#e8002d]/50
                         focus:ring-1 focus:ring-[#e8002d]/20"
            >
              <option value="">エージェントを選択...</option>
              {agents.map(a => (
                <option key={a.id} value={a.id}>
                  {a.hostname} — {a.os} ({a.status})
                </option>
              ))}
            </select>
          </div>

          {/* Name */}
          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wider">
              キャプチャ名 <span className="text-[#e8002d]">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={e => set('name', e.target.value)}
              placeholder="例: HTTPS traffic capture"
              required
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                         text-[#e2e8f4] text-sm placeholder-[#3d5068]
                         focus:outline-none focus:border-[#e8002d]/50 focus:ring-1 focus:ring-[#e8002d]/20"
            />
          </div>

          {/* BPF Filter */}
          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wider">
              BPFフィルター
            </label>
            <input
              type="text"
              value={form.filter}
              onChange={e => set('filter', e.target.value)}
              placeholder="例: tcp port 443, host 192.168.1.1, udp"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                         text-[#e2e8f4] text-sm font-mono placeholder-[#3d5068]
                         focus:outline-none focus:border-[#e8002d]/50 focus:ring-1 focus:ring-[#e8002d]/20"
            />
            <p className="text-[#3d5068] text-xs mt-1">空白の場合は全トラフィックをキャプチャします</p>
          </div>

          {/* Interface */}
          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wider">
              インターフェース
            </label>
            <input
              type="text"
              value={form.interface}
              onChange={e => set('interface', e.target.value)}
              placeholder="eth0, ens3, any"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                         text-[#e2e8f4] text-sm font-mono placeholder-[#3d5068]
                         focus:outline-none focus:border-[#e8002d]/50 focus:ring-1 focus:ring-[#e8002d]/20"
            />
          </div>

          {/* Max packets + Duration side by side */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wider">
                最大パケット数
              </label>
              <input
                type="number"
                value={form.max_packets}
                onChange={e => set('max_packets', parseInt(e.target.value) || 0)}
                min={1}
                max={1000000}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                           text-[#e2e8f4] text-sm
                           focus:outline-none focus:border-[#e8002d]/50 focus:ring-1 focus:ring-[#e8002d]/20"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wider">
                最大時間 (秒)
              </label>
              <input
                type="number"
                value={form.max_duration}
                onChange={e => set('max_duration', parseInt(e.target.value) || 0)}
                min={1}
                max={3600}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                           text-[#e2e8f4] text-sm
                           focus:outline-none focus:border-[#e8002d]/50 focus:ring-1 focus:ring-[#e8002d]/20"
              />
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2.5 rounded-lg border border-[#1e2d42]
                         text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40
                         transition-all text-sm font-medium"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !form.agent_id || !form.name}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg
                         bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed
                         text-white text-sm font-semibold transition-all"
            >
              {isSubmitting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              開始
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Delete Confirmation ───────────────────────────────────────────────────────

interface DeleteConfirmProps {
  capture: PacketCapture
  onConfirm: () => void
  onCancel: () => void
  isDeleting: boolean
}

function DeleteConfirm({ capture, onConfirm, onCancel, isDeleting }: DeleteConfirmProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl w-full max-w-sm mx-4">
        <div className="p-6 text-center">
          <div className="w-12 h-12 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mx-auto mb-4">
            <Trash2 className="w-5 h-5 text-red-400" />
          </div>
          <h3 className="text-white font-semibold text-base mb-2">キャプチャを削除</h3>
          <p className="text-[#7d92b0] text-sm mb-6">
            <span className="text-white font-medium">{capture.name}</span> を削除しますか？この操作は取り消せません。
          </p>
          <div className="flex gap-3">
            <button
              onClick={onCancel}
              className="flex-1 px-4 py-2.5 rounded-lg border border-[#1e2d42]
                         text-[#7d92b0] hover:text-white transition-all text-sm font-medium"
            >
              キャンセル
            </button>
            <button
              onClick={onConfirm}
              disabled={isDeleting}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg
                         bg-red-600 hover:bg-red-700 disabled:opacity-50
                         text-white text-sm font-semibold transition-all"
            >
              {isDeleting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
              削除
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function NetworkCapturesPage() {
  const queryClient = useQueryClient()
  const [showStartModal, setShowStartModal] = useState(false)
  const [deletingCapture, setDeletingCapture] = useState<PacketCapture | null>(null)
  const [filterAgentId, setFilterAgentId] = useState('')
  const [filterStatus, setFilterStatus] = useState('')

  // ── Fetch captures ──────────────────────────────────────────────────────────
  const { data, isLoading, error, refetch, isFetching } = useQuery<CaptureListResponse>({
    queryKey: ['packet-captures', filterAgentId],
    queryFn: () => {
      const params = new URLSearchParams()
      if (filterAgentId) params.set('agent_id', filterAgentId)
      return apiFetch(`/api/v1/packet-captures${params.toString() ? '?' + params.toString() : ''}`)
    },
    refetchInterval: false,
  })

  const captures = data?.captures ?? []
  const hasRunning = captures.some(c => c.status === 'running' || c.status === 'pending')

  // ── Auto-refresh every 10s when there are running/pending captures ──────────
  useEffect(() => {
    if (!hasRunning) return
    const interval = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: ['packet-captures'] })
    }, 10_000)
    return () => clearInterval(interval)
  }, [hasRunning, queryClient])

  // ── Agents for filter dropdown ──────────────────────────────────────────────
  const { data: agentsData } = useQuery<{ agents?: Agent[]; data?: Agent[] }>({
    queryKey: ['agents-for-capture'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=200'),
  })
  const agents = agentsData?.data ?? agentsData?.agents ?? []

  // ── Start capture ───────────────────────────────────────────────────────────
  const startMutation = useMutation({
    mutationFn: (form: StartCaptureForm) => apiFetch('/api/v1/packet-captures', {
      method: 'POST',
      body: JSON.stringify(form),
    }),
    onSuccess: () => {
      setShowStartModal(false)
      queryClient.invalidateQueries({ queryKey: ['packet-captures'] })
    },
  })

  // ── Cancel capture ──────────────────────────────────────────────────────────
  const cancelMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/packet-captures/${id}/cancel`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['packet-captures'] }),
  })

  // ── Delete capture ──────────────────────────────────────────────────────────
  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/packet-captures/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      setDeletingCapture(null)
      queryClient.invalidateQueries({ queryKey: ['packet-captures'] })
    },
  })

  // ── Download PCAP ───────────────────────────────────────────────────────────
  const handleDownload = useCallback((capture: PacketCapture) => {
    window.open(`/api/v1/packet-captures/${capture.id}/download`, '_blank')
  }, [])

  // ── Filter captures in UI ───────────────────────────────────────────────────
  const filteredCaptures = captures.filter(c => {
    if (filterStatus && c.status !== filterStatus) return false
    return true
  })

  // ── Stats ───────────────────────────────────────────────────────────────────
  const stats = {
    total: captures.length,
    running: captures.filter(c => c.status === 'running').length,
    completed: captures.filter(c => c.status === 'completed').length,
    failed: captures.filter(c => c.status === 'failed').length,
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#e8002d]/15 border border-[#e8002d]/20 flex items-center justify-center">
            <Network className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">ネットワークパケットキャプチャ</h1>
            <p className="text-[#7d92b0] text-sm">エンドポイントのネットワークトラフィックをキャプチャ・分析します</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {hasRunning && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/20">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
              <span className="text-green-400 text-xs font-medium">自動更新中 (10秒毎)</span>
            </div>
          )}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#1e2d42]
                       text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 transition-all text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
          <button
            onClick={() => setShowStartModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f]
                       text-white text-sm font-semibold transition-all"
          >
            <Plus className="w-4 h-4" />
            キャプチャ開始
          </button>
        </div>
      </div>

      {/* ── Stats cards ────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '合計', value: stats.total, color: 'text-[#e2e8f4]', icon: Network },
          { label: '実行中', value: stats.running, color: 'text-green-400', icon: Loader2 },
          { label: '完了', value: stats.completed, color: 'text-blue-400', icon: CheckCircle },
          { label: '失敗', value: stats.failed, color: 'text-red-400', icon: AlertCircle },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[#7d92b0] text-xs font-medium uppercase tracking-wider">{label}</span>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* ── Filters ────────────────────────────────────────────────────────── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 mb-4">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-[#7d92b0]" />
            <span className="text-[#7d92b0] text-sm font-medium">フィルター</span>
          </div>
          <select
            value={filterAgentId}
            onChange={e => setFilterAgentId(e.target.value)}
            className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm
                       text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]/50"
          >
            <option value="">全エージェント</option>
            {agents.map(a => (
              <option key={a.id} value={a.id}>{a.hostname}</option>
            ))}
          </select>
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
            className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm
                       text-[#e2e8f4] focus:outline-none focus:border-[#e8002d]/50"
          >
            <option value="">全ステータス</option>
            <option value="pending">Pending</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
          {(filterAgentId || filterStatus) && (
            <button
              onClick={() => { setFilterAgentId(''); setFilterStatus('') }}
              className="text-[#7d92b0] hover:text-white text-sm flex items-center gap-1 transition-colors"
            >
              <X className="w-3.5 h-3.5" />
              クリア
            </button>
          )}
          <span className="ml-auto text-[#7d92b0] text-sm">{filteredCaptures.length} 件</span>
        </div>
      </div>

      {/* ── Table ──────────────────────────────────────────────────────────── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 text-[#e8002d] animate-spin mr-3" />
            <span className="text-[#7d92b0] text-sm">読み込み中...</span>
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <AlertCircle className="w-8 h-8 text-red-400" />
            <p className="text-red-400 text-sm">データの読み込みに失敗しました</p>
            <button onClick={() => refetch()} className="text-[#e8002d] text-sm hover:underline">再試行</button>
          </div>
        ) : filteredCaptures.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <Network className="w-10 h-10 text-[#3d5068]" />
            <p className="text-[#7d92b0] text-sm">キャプチャが見つかりません</p>
            <button
              onClick={() => setShowStartModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f]
                         text-white text-sm font-medium transition-all"
            >
              <Plus className="w-4 h-4" />
              最初のキャプチャを開始
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['名前', 'エンドポイント', 'ステータス', 'フィルター (BPF)', 'パケット数', 'ファイルサイズ', '期間', '開始時刻', 'アクション'].map(h => (
                    <th
                      key={h}
                      className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wider whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]/50">
                {filteredCaptures.map(capture => (
                  <tr
                    key={capture.id}
                    className="hover:bg-[#19253d]/30 transition-colors group"
                  >
                    {/* Name */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Network className="w-4 h-4 text-[#3d5068] flex-shrink-0" />
                        <div>
                          <p className="text-[#e2e8f4] text-sm font-medium">{capture.name}</p>
                          <p className="text-[#3d5068] text-xs font-mono">{capture.interface}</p>
                        </div>
                      </div>
                    </td>

                    {/* Agent */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Cpu className="w-3.5 h-3.5 text-[#3d5068]" />
                        <span className="text-[#7d92b0] text-sm">{capture.agent_hostname || '—'}</span>
                      </div>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <StatusBadge status={capture.status} />
                      {capture.error_message && (
                        <p className="text-red-400 text-xs mt-1 max-w-[150px] truncate" title={capture.error_message}>
                          {capture.error_message}
                        </p>
                      )}
                    </td>

                    {/* BPF Filter */}
                    <td className="px-4 py-3">
                      {capture.filter ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded
                                         bg-[#1e2d42] text-[#7d92b0] text-xs font-mono">
                          <Filter className="w-3 h-3" />
                          {capture.filter}
                        </span>
                      ) : (
                        <span className="text-[#3d5068] text-xs italic">フィルターなし</span>
                      )}
                    </td>

                    {/* Packets */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[#e2e8f4] text-sm font-mono">
                          {(capture.packets_captured ?? 0).toLocaleString()}
                        </span>
                        {capture.max_packets > 0 && (
                          <span className="text-[#3d5068] text-xs">/ {(capture.max_packets ?? 0).toLocaleString()}</span>
                        )}
                      </div>
                    </td>

                    {/* File size */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <HardDrive className="w-3.5 h-3.5 text-[#3d5068]" />
                        <span className="text-[#7d92b0] text-sm">{formatBytes(capture.file_size_bytes)}</span>
                      </div>
                    </td>

                    {/* Duration */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <Timer className="w-3.5 h-3.5 text-[#3d5068]" />
                        <span className="text-[#7d92b0] text-sm">{formatDuration(capture.duration_seconds)}</span>
                      </div>
                    </td>

                    {/* Started at */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <Calendar className="w-3.5 h-3.5 text-[#3d5068]" />
                        <span className="text-[#7d92b0] text-xs">{formatDate(capture.started_at)}</span>
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {/* Cancel — only for running/pending */}
                        {(capture.status === 'running' || capture.status === 'pending') && (
                          <button
                            onClick={() => cancelMutation.mutate(capture.id)}
                            disabled={cancelMutation.isPending}
                            title="キャプチャを停止"
                            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg
                                       bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/30
                                       text-yellow-400 text-xs font-medium transition-all disabled:opacity-50"
                          >
                            <Square className="w-3.5 h-3.5" />
                            停止
                          </button>
                        )}

                        {/* Download — only for completed */}
                        {capture.status === 'completed' && (
                          <button
                            onClick={() => handleDownload(capture)}
                            title="PCAPをダウンロード"
                            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg
                                       bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30
                                       text-blue-400 text-xs font-medium transition-all"
                          >
                            <Download className="w-3.5 h-3.5" />
                            PCAP
                          </button>
                        )}

                        {/* Delete */}
                        <button
                          onClick={() => setDeletingCapture(capture)}
                          title="削除"
                          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg
                                     bg-red-500/10 hover:bg-red-500/20 border border-red-500/20
                                     text-red-400 text-xs font-medium transition-all
                                     opacity-0 group-hover:opacity-100"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Error toast ────────────────────────────────────────────────────── */}
      {startMutation.isError && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl
                        bg-red-900/80 border border-red-500/40 text-red-200 text-sm shadow-xl">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          キャプチャの開始に失敗しました
          <button onClick={() => startMutation.reset()} className="ml-2 text-red-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* ── Modals ─────────────────────────────────────────────────────────── */}
      {showStartModal && (
        <StartCaptureModal
          onClose={() => setShowStartModal(false)}
          onSubmit={(form) => startMutation.mutate(form)}
          isSubmitting={startMutation.isPending}
        />
      )}

      {deletingCapture && (
        <DeleteConfirm
          capture={deletingCapture}
          onConfirm={() => deleteMutation.mutate(deletingCapture.id)}
          onCancel={() => setDeletingCapture(null)}
          isDeleting={deleteMutation.isPending}
        />
      )}
    </div>
  )
}
