'use client'

import { useState, useMemo, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Package, Plus, RefreshCw, Clock, CheckCircle, AlertTriangle,
  Loader2, X, ChevronDown, ExternalLink, Play, Calendar,
  RotateCcw, BarChart2, Tag, Shield, Zap, Filter, Send,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

interface PatchDeployment {
  id: string
  name: string
  description: string
  patch_type: 'security' | 'feature' | 'critical'
  severity: 'critical' | 'high' | 'medium' | 'low'
  kb_article: string
  cve_ids: string[]
  target_os: 'all' | 'windows' | 'linux' | 'macos'
  status: 'draft' | 'scheduled' | 'deploying' | 'completed' | 'failed'
  scheduled_at?: string
  progress?: number
  require_reboot: boolean
  deployment_window_minutes: number
  created_at: string
}

interface PatchResult {
  id: string
  deployment_id: string
  agent_hostname: string
  os_type: string
  status: 'pending' | 'success' | 'failed' | 'rebooting'
  error_message?: string
  started_at?: string
  completed_at?: string
  duration_seconds?: number
}

interface PatchStats {
  pending: number
  deploying: number
  completed_this_month: number
  success_rate: number
}

// ─── Badge Helpers ────────────────────────────────────────────────────────────

function PatchTypeBadge({ type }: { type: PatchDeployment['patch_type'] }) {
  const map = {
    security: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
    feature: 'bg-purple-900/40 text-purple-300 border border-purple-700/40',
    critical: 'bg-red-900/40 text-red-300 border border-red-700/40',
  }
  const labels = { security: 'セキュリティ', feature: '機能', critical: 'クリティカル' }
  return <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${map[type]}`}>{labels[type]}</span>
}

function SeverityBadge({ severity }: { severity: PatchDeployment['severity'] }) {
  const map = {
    critical: 'bg-red-900/50 text-red-300 border border-red-700/50',
    high: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
    medium: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
    low: 'bg-green-900/40 text-green-300 border border-green-700/40',
  }
  const labels = { critical: '緊急', high: '高', medium: '中', low: '低' }
  return <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${map[severity]}`}>{labels[severity]}</span>
}

function StatusBadge({ status }: { status: PatchDeployment['status'] }) {
  const map = {
    draft: 'bg-[#1e2d42] text-[#7d92b0] border border-[#2a3f5c]',
    scheduled: 'bg-blue-900/30 text-blue-300 border border-blue-700/30',
    deploying: 'bg-yellow-900/30 text-yellow-300 border border-yellow-700/30',
    completed: 'bg-green-900/30 text-green-300 border border-green-700/30',
    failed: 'bg-red-900/30 text-red-300 border border-red-700/30',
  }
  const labels = { draft: '下書き', scheduled: 'スケジュール済', deploying: '配布中', completed: '完了', failed: '失敗' }
  return <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${map[status]}`}>{labels[status]}</span>
}

function ResultStatusBadge({ status }: { status: PatchResult['status'] }) {
  const map = {
    pending: 'bg-[#1e2d42] text-[#7d92b0]',
    success: 'bg-green-900/30 text-green-300',
    failed: 'bg-red-900/30 text-red-300',
    rebooting: 'bg-yellow-900/30 text-yellow-300',
  }
  const labels = { pending: '待機中', success: '成功', failed: '失敗', rebooting: '再起動中' }
  return <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${map[status]}`}>{labels[status]}</span>
}

function OSBadge({ os }: { os: string }) {
  const map: Record<string, string> = {
    windows: 'bg-blue-900/30 text-blue-300',
    linux: 'bg-orange-900/30 text-orange-300',
    macos: 'bg-gray-900/40 text-gray-300',
    all: 'bg-purple-900/30 text-purple-300',
    Windows: 'bg-blue-900/30 text-blue-300',
    Linux: 'bg-orange-900/30 text-orange-300',
    macOS: 'bg-gray-900/40 text-gray-300',
  }
  return <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${map[os] ?? 'bg-[#1e2d42] text-[#7d92b0]'}`}>{os === 'all' ? 'すべて' : os}</span>
}

function formatDuration(seconds?: number): string {
  if (!seconds) return '—'
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}m ${s}s`
}

function formatDate(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ─── Donut Chart ──────────────────────────────────────────────────────────────

function DonutChart({ success, failed, pending }: { success: number; failed: number; pending: number }) {
  const total = success + failed + pending
  if (total === 0) return null
  const r = 40
  const cx = 60
  const cy = 60
  const circumference = 2 * Math.PI * r

  const segments = [
    { value: success, color: '#22c55e' },
    { value: failed, color: '#e8002d' },
    { value: pending, color: '#7d92b0' },
  ]

  let offset = 0
  const paths = segments.map((seg) => {
    const pct = seg.value / total
    const dash = pct * circumference
    const gap = circumference - dash
    const el = (
      <circle
        key={seg.color}
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke={seg.color}
        strokeWidth={14}
        strokeDasharray={`${dash} ${gap}`}
        strokeDashoffset={-offset * circumference / total + circumference * 0.25}
        style={{ transform: `rotate(-90deg)`, transformOrigin: `${cx}px ${cy}px` }}
      />
    )
    offset += seg.value
    return el
  })

  return (
    <div className="flex items-center gap-6">
      <svg width={120} height={120} viewBox="0 0 120 120">
        {paths}
        <text x={cx} y={cy - 5} textAnchor="middle" fill="#e2e8f4" fontSize={16} fontWeight="bold">{total}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill="#7d92b0" fontSize={10}>台</text>
      </svg>
      <div className="space-y-2 text-sm">
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-green-500 flex-shrink-0" />
          <span className="text-[#7d92b0]">成功</span>
          <span className="text-white font-semibold ml-auto pl-4">{success}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-[#e8002d] flex-shrink-0" />
          <span className="text-[#7d92b0]">失敗</span>
          <span className="text-white font-semibold ml-auto pl-4">{failed}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-[#7d92b0] flex-shrink-0" />
          <span className="text-[#7d92b0]">待機中</span>
          <span className="text-white font-semibold ml-auto pl-4">{pending}</span>
        </div>
      </div>
    </div>
  )
}

// ─── Create Patch Modal ───────────────────────────────────────────────────────

interface CreateModalProps {
  onClose: () => void
  onSubmit: (data: Partial<PatchDeployment>) => void
  loading: boolean
}

function CreateModal({ onClose, onSubmit, loading }: CreateModalProps) {
  const [form, setForm] = useState({
    name: '',
    description: '',
    patch_type: 'security' as PatchDeployment['patch_type'],
    severity: 'medium' as PatchDeployment['severity'],
    kb_article: '',
    cve_ids: '',
    target_os: 'all' as PatchDeployment['target_os'],
    require_reboot: false,
    deployment_window_minutes: 60,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      ...form,
      cve_ids: form.cve_ids.split(',').map(s => s.trim()).filter(Boolean),
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg shadow-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-base">パッチ作成</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">パッチ名 *</label>
            <input
              required
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors"
              placeholder="例: Windows Server 累積更新"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">説明</label>
            <textarea
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors resize-none"
              placeholder="パッチの説明..."
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">パッチ種別</label>
              <select
                value={form.patch_type}
                onChange={e => setForm(f => ({ ...f, patch_type: e.target.value as PatchDeployment['patch_type'] }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#1a6bff] transition-colors"
              >
                <option value="security">セキュリティ</option>
                <option value="feature">機能</option>
                <option value="critical">クリティカル</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">深刻度</label>
              <select
                value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value as PatchDeployment['severity'] }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#1a6bff] transition-colors"
              >
                <option value="critical">緊急</option>
                <option value="high">高</option>
                <option value="medium">中</option>
                <option value="low">低</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">KBアーティクル</label>
            <input
              value={form.kb_article}
              onChange={e => setForm(f => ({ ...f, kb_article: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors"
              placeholder="例: KB5035857"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">CVE ID (カンマ区切り)</label>
            <textarea
              value={form.cve_ids}
              onChange={e => setForm(f => ({ ...f, cve_ids: e.target.value }))}
              rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#1a6bff] transition-colors resize-none"
              placeholder="CVE-2026-0001, CVE-2026-0002"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">対象OS</label>
            <select
              value={form.target_os}
              onChange={e => setForm(f => ({ ...f, target_os: e.target.value as PatchDeployment['target_os'] }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#1a6bff] transition-colors"
            >
              <option value="all">すべて</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
            </select>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">配布ウィンドウ (分)</label>
              <input
                type="number"
                min={10}
                max={480}
                value={form.deployment_window_minutes}
                onChange={e => setForm(f => ({ ...f, deployment_window_minutes: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#1a6bff] transition-colors"
              />
            </div>
            <div className="flex items-end pb-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <div
                  onClick={() => setForm(f => ({ ...f, require_reboot: !f.require_reboot }))}
                  className={`relative w-10 h-5 rounded-full transition-colors ${form.require_reboot ? 'bg-[#1a6bff]' : 'bg-[#1e2d42]'}`}
                >
                  <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] transition-transform ${form.require_reboot ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </div>
                <span className="text-xs text-[#7d92b0]">再起動必要</span>
              </label>
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              作成
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Schedule Modal ───────────────────────────────────────────────────────────

function ScheduleModal({ patch, onClose, onSchedule, loading }: { patch: PatchDeployment; onClose: () => void; onSchedule: (dt: string) => void; loading: boolean }) {
  const [datetime, setDatetime] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm shadow-2xl mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-base">スケジュール設定</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <p className="text-sm text-[#7d92b0]">{patch.name}</p>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">配布日時</label>
            <input
              type="datetime-local"
              value={datetime}
              onChange={e => setDatetime(e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-[#1a6bff] transition-colors"
            />
          </div>
          <div className="flex justify-end gap-3">
            <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
            <button
              disabled={!datetime || loading}
              onClick={() => onSchedule(new Date(datetime).toISOString())}
              className="px-5 py-2 bg-[#1a6bff] hover:bg-[#1557d4] text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              スケジュール
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Deploy Confirm Modal ─────────────────────────────────────────────────────

function DeployModal({ patch, onClose, onDeploy, loading }: { patch: PatchDeployment; onClose: () => void; onDeploy: () => void; loading: boolean }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm shadow-2xl mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-base">今すぐ配布</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div className="flex items-start gap-3 p-3 bg-yellow-900/20 border border-yellow-700/30 rounded-lg">
            <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
            <p className="text-sm text-yellow-300">このパッチを今すぐすべての対象エンドポイントに配布します。この操作は取り消せません。</p>
          </div>
          <p className="text-sm text-[#7d92b0]"><span className="text-white font-medium">{patch.name}</span> を配布しますか？</p>
          <div className="flex justify-end gap-3">
            <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
            <button
              disabled={loading}
              onClick={onDeploy}
              className="px-5 py-2 bg-[#e8002d] hover:bg-[#c00025] text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              今すぐ配布
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Deployment Card ──────────────────────────────────────────────────────────

function DeploymentCard({
  patch,
  onSchedule,
  onDeploy,
  onResults,
}: {
  patch: PatchDeployment
  onSchedule: (p: PatchDeployment) => void
  onDeploy: (p: PatchDeployment) => void
  onResults: (p: PatchDeployment) => void
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 space-y-4 hover:border-[#2a3f5c] transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-white font-semibold text-sm leading-tight">{patch.name}</h3>
          {patch.description && <p className="text-[#7d92b0] text-xs mt-1">{patch.description}</p>}
        </div>
        <StatusBadge status={patch.status} />
      </div>

      {/* Badges */}
      <div className="flex flex-wrap gap-1.5">
        <PatchTypeBadge type={patch.patch_type} />
        <SeverityBadge severity={patch.severity} />
        <OSBadge os={patch.target_os} />
        {patch.require_reboot && (
          <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-orange-900/30 text-orange-300 border border-orange-700/30">再起動必要</span>
        )}
      </div>

      {/* KB + CVEs */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {patch.kb_article && (
          <a href={`#kb-${patch.kb_article}`} className="flex items-center gap-1 text-[#1a6bff] hover:text-blue-300 transition-colors">
            <ExternalLink className="w-3 h-3" />
            {patch.kb_article}
          </a>
        )}
        {patch.cve_ids.map(cve => (
          <span key={cve} className="px-1.5 py-0.5 bg-red-900/20 text-red-400 border border-red-900/40 rounded text-[10px]">{cve}</span>
        ))}
      </div>

      {/* Progress bar for deploying */}
      {patch.status === 'deploying' && patch.progress !== undefined && (
        <div className="space-y-1">
          <div className="flex justify-between text-xs text-[#7d92b0]">
            <span>配布進捗</span>
            <span>{patch.progress}%</span>
          </div>
          <div className="h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-[#1a6bff] to-[#00a8ff] rounded-full transition-all duration-500"
              style={{ width: `${patch.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Scheduled time */}
      {patch.scheduled_at && (
        <div className="flex items-center gap-1.5 text-xs text-[#7d92b0]">
          <Clock className="w-3.5 h-3.5" />
          <span>配布予定: {formatDate(patch.scheduled_at)}</span>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-wrap gap-2 pt-1 border-t border-[#1e2d42]">
        {patch.status === 'draft' && (
          <button
            onClick={() => onSchedule(patch)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#253650] text-[#7d92b0] hover:text-white text-xs rounded-lg transition-colors"
          >
            <Calendar className="w-3.5 h-3.5" />スケジュール
          </button>
        )}
        {(patch.status === 'draft' || patch.status === 'scheduled') && (
          <button
            onClick={() => onDeploy(patch)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d]/20 hover:bg-[#e8002d]/30 text-[#e8002d] hover:text-red-300 text-xs rounded-lg transition-colors border border-[#e8002d]/30"
          >
            <Play className="w-3.5 h-3.5" />今すぐ配布
          </button>
        )}
        {(patch.status === 'completed' || patch.status === 'deploying' || patch.status === 'failed') && (
          <button
            onClick={() => onResults(patch)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#253650] text-[#7d92b0] hover:text-white text-xs rounded-lg transition-colors"
          >
            <BarChart2 className="w-3.5 h-3.5" />結果確認
          </button>
        )}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function PatchManagementPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'deployments' | 'results'>('deployments')
  const [showCreate, setShowCreate] = useState(false)
  const [scheduleTarget, setScheduleTarget] = useState<PatchDeployment | null>(null)
  const [deployTarget, setDeployTarget] = useState<PatchDeployment | null>(null)
  const [resultsTarget, setResultsTarget] = useState<PatchDeployment | null>(null)
  const [resultFilter, setResultFilter] = useState<string>('all')
  const [selectedDeploymentId, setSelectedDeploymentId] = useState<string>('')

  // Stats
  const { data: statsData } = useQuery<PatchStats>({
    queryKey: ['patch-stats'],
    // The API returns `completed` (all-time completed count); map it to this
    // page's completed_this_month so the stat isn't always 0.
    queryFn: async () => {
      const r = await apiFetch<Record<string, number>>('/api/v1/patches/stats')
      return {
        pending: r?.pending ?? 0,
        deploying: r?.deploying ?? 0,
        completed_this_month: r?.completed_this_month ?? r?.completed ?? 0,
        success_rate: r?.success_rate ?? 0,
      }
    },
    retry: false,
  })
  const EMPTY_PATCH_STATS: PatchStats = { pending: 0, deploying: 0, completed_this_month: 0, success_rate: 0 }
  const stats = statsData ?? EMPTY_PATCH_STATS

  // Deployments — the API returns the array under `deployments`.
  const { data: deploymentsData, isLoading: loadingDeps } = useQuery<{ deployments?: PatchDeployment[]; patches?: PatchDeployment[]; data?: PatchDeployment[] }>({
    queryKey: ['patches'],
    queryFn: () => apiFetch('/api/v1/patches'),
    retry: false,
  })
  const deployments: PatchDeployment[] = deploymentsData?.deployments ?? deploymentsData?.patches ?? deploymentsData?.data ?? []

  // Results for selected deployment
  const { data: resultsData } = useQuery<{ results?: PatchResult[]; data?: PatchResult[] }>({
    queryKey: ['patch-results', selectedDeploymentId],
    queryFn: () => apiFetch(`/api/v1/patches/${selectedDeploymentId}/results`),
    enabled: !!selectedDeploymentId,
    retry: false,
  })
  const allResults: PatchResult[] = resultsData?.results ?? resultsData?.data ?? []

  const filteredResults = resultFilter === 'all' ? allResults : allResults.filter(r => r.status === resultFilter)

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: Partial<PatchDeployment>) => apiFetch('/api/v1/patches', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['patches'] }); setShowCreate(false) },
    onError: () => setShowCreate(false),
  })

  const scheduleMutation = useMutation({
    mutationFn: ({ id, scheduled_at }: { id: string; scheduled_at: string }) =>
      apiFetch(`/api/v1/patches/${id}/schedule`, { method: 'POST', body: JSON.stringify({ scheduled_at }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['patches'] }); setScheduleTarget(null) },
    onError: () => setScheduleTarget(null),
  })

  const deployMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/patches/${id}/deploy`, { method: 'POST' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['patches'] }); setDeployTarget(null) },
    onError: () => setDeployTarget(null),
  })

  const retryMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/patches/${selectedDeploymentId}/results/${id}/retry`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['patch-results', selectedDeploymentId] }),
    onError: () => {},
  })

  // Results counts
  const successCount = allResults.filter(r => r.status === 'success').length
  const failedCount = allResults.filter(r => r.status === 'failed').length
  const pendingCount = allResults.filter(r => r.status === 'pending').length

  const STAT_CARDS = [
    { label: '配布待ち', value: stats.pending, icon: Clock, color: 'text-yellow-300', bg: 'bg-yellow-900/20 border-yellow-700/30' },
    { label: '配布中', value: stats.deploying, icon: stats.deploying > 0 ? Loader2 : Send, color: 'text-blue-300', bg: 'bg-blue-900/20 border-blue-700/30', spin: stats.deploying > 0 },
    { label: '今月完了', value: stats.completed_this_month, icon: CheckCircle, color: 'text-green-300', bg: 'bg-green-900/20 border-green-700/30' },
    { label: '成功率', value: `${stats.success_rate}%`, icon: Shield, color: 'text-[#e8002d]', bg: 'bg-red-900/20 border-red-700/30' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Package className="w-6 h-6 text-[#e8002d]" />
            パッチ管理
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">セキュリティパッチの配布・適用状況の追跡</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c00025] text-white text-sm font-medium rounded-lg transition-colors shadow-lg shadow-red-900/20"
        >
          <Plus className="w-4 h-4" />
          パッチ作成
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {STAT_CARDS.map(card => (
          <div key={card.label} className={`bg-[#0d1220] border rounded-xl p-4 flex items-center gap-3 ${card.bg}`}>
            <card.icon className={`w-8 h-8 flex-shrink-0 ${card.color} ${card.spin ? 'animate-spin' : ''}`} />
            <div>
              <p className="text-2xl font-bold text-white">{card.value}</p>
              <p className="text-xs text-[#7d92b0]">{card.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {[
          { key: 'deployments', label: 'パッチ配布' },
          { key: 'results', label: '適用状況' },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as 'deployments' | 'results')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === tab.key
                ? 'bg-[#1e2d42] text-white'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab: パッチ配布 */}
      {activeTab === 'deployments' && (
        <div>
          {loadingDeps ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-8 h-8 animate-spin text-[#1a6bff]" />
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {deployments.map(patch => (
                <DeploymentCard
                  key={patch.id}
                  patch={patch}
                  onSchedule={setScheduleTarget}
                  onDeploy={setDeployTarget}
                  onResults={p => { setResultsTarget(p); setSelectedDeploymentId(p.id); setActiveTab('results') }}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab: 適用状況 */}
      {activeTab === 'results' && (
        <div className="space-y-4">
          {/* Deployment selector */}
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <label className="text-sm text-[#7d92b0]">配布選択:</label>
              <select
                value={selectedDeploymentId}
                onChange={e => setSelectedDeploymentId(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#1a6bff] transition-colors"
              >
                {deployments.map(d => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-[#7d92b0]" />
              <select
                value={resultFilter}
                onChange={e => setResultFilter(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#1a6bff] transition-colors"
              >
                <option value="all">すべて</option>
                <option value="success">成功</option>
                <option value="failed">失敗</option>
                <option value="pending">待機中</option>
                <option value="rebooting">再起動中</option>
              </select>
            </div>
          </div>

          {/* Summary Donut */}
          {allResults.length > 0 && (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h3 className="text-white font-semibold text-sm mb-4">適用サマリー</h3>
              <DonutChart success={successCount} failed={failedCount} pending={pendingCount} />
            </div>
          )}

          {/* Results Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ホスト名', 'OS', 'ステータス', 'エラー', '開始', '完了', '所要時間', '操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filteredResults.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-[#7d92b0] text-sm">
                        {allResults.length === 0 ? 'このデプロイメントの結果がありません' : 'フィルター条件に一致するデータがありません'}
                      </td>
                    </tr>
                  ) : filteredResults.map(result => (
                    <tr key={result.id} className="hover:bg-[#0a1428] transition-colors">
                      <td className="px-4 py-3 text-white font-medium whitespace-nowrap">{result.agent_hostname}</td>
                      <td className="px-4 py-3"><OSBadge os={result.os_type} /></td>
                      <td className="px-4 py-3"><ResultStatusBadge status={result.status} /></td>
                      <td className="px-4 py-3 text-red-400 text-xs max-w-[160px] truncate">{result.error_message ?? '—'}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{formatDate(result.started_at)}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{formatDate(result.completed_at)}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{formatDuration(result.duration_seconds)}</td>
                      <td className="px-4 py-3">
                        {result.status === 'failed' && (
                          <button
                            onClick={() => retryMutation.mutate(result.id)}
                            className="flex items-center gap-1 px-2.5 py-1 bg-[#1e2d42] hover:bg-[#253650] text-[#7d92b0] hover:text-white text-xs rounded transition-colors"
                          >
                            <RotateCcw className="w-3 h-3" />再試行
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onSubmit={(data) => createMutation.mutate(data)}
          loading={createMutation.isPending}
        />
      )}
      {scheduleTarget && (
        <ScheduleModal
          patch={scheduleTarget}
          onClose={() => setScheduleTarget(null)}
          onSchedule={(dt) => scheduleMutation.mutate({ id: scheduleTarget.id, scheduled_at: dt })}
          loading={scheduleMutation.isPending}
        />
      )}
      {deployTarget && (
        <DeployModal
          patch={deployTarget}
          onClose={() => setDeployTarget(null)}
          onDeploy={() => deployMutation.mutate(deployTarget.id)}
          loading={deployMutation.isPending}
        />
      )}
    </div>
  )
}
