'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Building2, Plus, Edit2, Trash2, X, RefreshCw,
  Users, Cpu, HardDrive, Bell, ChevronLeft, ChevronRight,
  AlertTriangle, BarChart2, Shield, Settings2, Eye,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type Plan = 'free' | 'standard' | 'enterprise'
type TenantStatus = 'active' | 'suspended' | 'trial'

interface Tenant {
  id: string
  name: string
  domain: string
  plan: Plan
  status: TenantStatus
  agent_count: number
  max_agents: number
  user_count: number
  max_users: number
  storage_used_gb: number
  max_storage_gb: number
  max_alerts_per_day: number
  admin_email: string
  created_at: string
}

interface TenantStats {
  tenant_id: string
  agent_count: number
  max_agents: number
  user_count: number
  max_users: number
  storage_used_gb: number
  max_storage_gb: number
  alerts_today: number
  max_alerts_per_day: number
  daily_alerts: { day: string; count: number }[]
}

interface AuditLog {
  id: string
  actor_email: string
  action: string
  resource: string
  ip_address: string
  created_at: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function PlanBadge({ plan }: { plan: Plan }) {
  const map: Record<string, { label: string; bg: string; text: string }> = {
    free:       { label: 'フリー',         bg: 'bg-gray-500/20',    text: 'text-gray-400'   },
    standard:   { label: 'スタンダード',    bg: 'bg-blue-500/20',    text: 'text-blue-400'   },
    enterprise: { label: 'エンタープライズ', bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  }
  const p = map[plan] ?? { label: plan, bg: 'bg-gray-500/20', text: 'text-gray-400' }
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${p.bg} ${p.text}`}>{p.label}</span>
}

function StatusBadge({ status }: { status: TenantStatus }) {
  const map: Record<string, { label: string; bg: string; text: string }> = {
    active:    { label: '有効',     bg: 'bg-green-500/20',  text: 'text-green-400'  },
    suspended: { label: '停止中',   bg: 'bg-red-500/20',    text: 'text-red-400'    },
    trial:     { label: 'トライアル', bg: 'bg-purple-500/20', text: 'text-purple-400' },
  }
  const s = map[status] ?? { label: status, bg: 'bg-gray-500/20', text: 'text-gray-400' }
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${s.bg} ${s.text}`}>{s.label}</span>
}

function UsageBar({ used, max, color = '#3b82f6' }: { used: number; max: number; color?: string }) {
  const u = Number(used) || 0
  const m = Number(max) || 0
  const pct = m > 0 ? Math.min((u / m) * 100, 100) : 0
  const barColor = pct > 90 ? '#e8002d' : pct > 70 ? '#f59e0b' : color
  return (
    <div>
      <div className="flex justify-between text-xs text-[#7d92b0] mb-1">
        <span>{u} / {m}</span>
        <span>{pct.toFixed(0)}%</span>
      </div>
      <div className="h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: barColor }} />
      </div>
    </div>
  )
}

function ProgressCard({ label, used, max, unit, icon: Icon }: {
  label: string; used: number; max: number; unit: string; icon: React.ElementType
}) {
  const u = Number(used) || 0
  const m = Number(max) || 0
  const pct = m > 0 ? Math.min((u / m) * 100, 100) : 0
  const barColor = pct > 90 ? '#e8002d' : pct > 70 ? '#f59e0b' : '#3b82f6'
  return (
    <div className="bg-[#070d19] rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-[#7d92b0]" />
          <span className="text-[#7d92b0] text-sm">{label}</span>
        </div>
        <span className="text-white font-bold">{u}{unit} / {m}{unit}</span>
      </div>
      <div className="h-2.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: barColor }} />
      </div>
      <p className="text-xs text-right mt-1" style={{ color: barColor }}>{pct.toFixed(1)}% 使用中</p>
    </div>
  )
}

// ─── Modals ───────────────────────────────────────────────────────────────────

function CreateTenantModal({ onClose, onSave }: { onClose: () => void; onSave: (data: Partial<Tenant>) => void }) {
  const [form, setForm] = useState({
    name: '', domain: '', plan: 'standard' as Plan,
    max_agents: 100, max_users: 25,
    max_storage_gb: 100, max_alerts_per_day: 1000,
    admin_email: '',
  })

  const handle = (field: string, val: string | number) =>
    setForm(prev => ({ ...prev, [field]: val }))

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">新規テナント作成</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[#7d92b0] text-xs mb-1">テナント名 *</label>
              <input value={form.name} onChange={e => handle('name', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]" />
            </div>
            <div>
              <label className="block text-[#7d92b0] text-xs mb-1">ドメイン *</label>
              <input value={form.domain} onChange={e => handle('domain', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[#7d92b0] text-xs mb-1">プラン</label>
              <select value={form.plan} onChange={e => handle('plan', e.target.value as Plan)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]">
                <option value="free">フリー</option>
                <option value="standard">スタンダード</option>
                <option value="enterprise">エンタープライズ</option>
              </select>
            </div>
            <div>
              <label className="block text-[#7d92b0] text-xs mb-1">管理者メール</label>
              <input value={form.admin_email} onChange={e => handle('admin_email', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            {[
              { key: 'max_agents', label: '最大エージェント数' },
              { key: 'max_users',  label: '最大ユーザー数' },
              { key: 'max_storage_gb', label: '最大ストレージ (GB)' },
              { key: 'max_alerts_per_day', label: '日次アラート上限' },
            ].map(f => (
              <div key={f.key}>
                <label className="block text-[#7d92b0] text-xs mb-1">{f.label}</label>
                <input type="number" value={(form as Record<string, unknown>)[f.key] as number}
                  onChange={e => handle(f.key, parseInt(e.target.value) || 0)}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]" />
              </div>
            ))}
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
          <button onClick={() => onSave(form)} className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#cc0027] transition-colors">作成</button>
        </div>
      </div>
    </div>
  )
}

function EditQuotaModal({ tenant, onClose, onSave }: { tenant: Tenant; onClose: () => void; onSave: (data: Partial<Tenant>) => void }) {
  const [form, setForm] = useState({
    plan: tenant.plan,
    max_agents: tenant.max_agents,
    max_users: tenant.max_users,
    max_storage_gb: tenant.max_storage_gb,
    max_alerts_per_day: tenant.max_alerts_per_day,
  })

  const handle = (field: string, val: string | number) =>
    setForm(prev => ({ ...prev, [field]: val }))

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">クォータ編集: {tenant.name}</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1">プラン</label>
            <select value={form.plan} onChange={e => handle('plan', e.target.value as Plan)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]">
              <option value="free">フリー</option>
              <option value="standard">スタンダード</option>
              <option value="enterprise">エンタープライズ</option>
            </select>
          </div>
          {[
            { key: 'max_agents', label: '最大エージェント数' },
            { key: 'max_users',  label: '最大ユーザー数' },
            { key: 'max_storage_gb', label: '最大ストレージ (GB)' },
            { key: 'max_alerts_per_day', label: '日次アラート上限' },
          ].map(f => (
            <div key={f.key}>
              <label className="block text-[#7d92b0] text-xs mb-1">{f.label}</label>
              <input type="number" value={(form as Record<string, unknown>)[f.key] as number}
                onChange={e => handle(f.key, parseInt(e.target.value) || 0)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]" />
            </div>
          ))}
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
          <button onClick={() => onSave(form)} className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#cc0027] transition-colors">保存</button>
        </div>
      </div>
    </div>
  )
}

function StatsModal({ tenant, stats, onClose }: { tenant: Tenant; stats: TenantStats; onClose: () => void }) {
  const maxAlert = Math.max(...stats.daily_alerts.map(d => d.count))
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-xl max-h-[85vh] overflow-y-auto">
        <div className="sticky top-0 bg-[#0d1220] flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <BarChart2 className="w-5 h-5 text-[#e8002d]" />
            <h3 className="text-white font-semibold">{tenant.name} — 使用状況</h3>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-4">
          <ProgressCard label="エージェント"  used={stats.agent_count}     max={stats.max_agents}       unit="台" icon={Cpu} />
          <ProgressCard label="ユーザー"      used={stats.user_count}      max={stats.max_users}         unit="人" icon={Users} />
          <ProgressCard label="ストレージ"    used={stats.storage_used_gb} max={stats.max_storage_gb}    unit="GB" icon={HardDrive} />
          <ProgressCard label="本日のアラート" used={stats.alerts_today}   max={stats.max_alerts_per_day} unit="件" icon={Bell} />

          {/* Alert chart */}
          <div>
            <p className="text-[#7d92b0] text-sm font-medium mb-3">直近7日間アラート数</p>
            <div className="flex items-end gap-2 h-28">
              {stats.daily_alerts.map(d => (
                <div key={d.day} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full flex flex-col justify-end" style={{ height: '88px' }}>
                    <div
                      className="w-full bg-[#e8002d] rounded-t"
                      style={{ height: `${(d.count / maxAlert) * 100}%` }}
                    />
                  </div>
                  <span className="text-[#7d92b0] text-xs">{d.day}</span>
                  <span className="text-white text-xs font-medium">{d.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function AuditModal({ tenant, logs, page, setPage, onClose }: {
  tenant: Tenant; logs: AuditLog[]; page: number; setPage: (p: number) => void; onClose: () => void
}) {
  const PAGE_SIZE = 5
  const totalPages = Math.ceil(logs.length / PAGE_SIZE)
  const paginated = logs.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42] shrink-0">
          <h3 className="text-white font-semibold">監査ログ: {tenant.name}</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <table className="w-full">
            <thead className="sticky top-0 bg-[#0d1220]">
              <tr className="border-b border-[#1e2d42]">
                {['アクター', 'アクション', 'リソース', 'IPアドレス', '日時'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {paginated.map(log => (
                <tr key={log.id} className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors">
                  <td className="px-4 py-3 text-[#7d92b0] text-xs">{log.actor_email}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-[#1e2d42] text-white px-2 py-0.5 rounded font-mono">{log.action}</span>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs font-mono">{log.resource}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs font-mono">{log.ip_address}</td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{log.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between p-4 border-t border-[#1e2d42] shrink-0">
          <span className="text-[#7d92b0] text-sm">{logs.length}件中 {(page-1)*PAGE_SIZE+1}〜{Math.min(page*PAGE_SIZE, logs.length)}件</span>
          <div className="flex items-center gap-2">
            <button disabled={page <= 1} onClick={() => setPage(page - 1)}
              className="p-1.5 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white disabled:opacity-40">
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-white text-sm">{page} / {totalPages}</span>
            <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
              className="p-1.5 rounded border border-[#1e2d42] text-[#7d92b0] hover:text-white disabled:opacity-40">
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function ImpersonateModal({ tenant, onClose, onConfirm }: { tenant: Tenant; onClose: () => void; onConfirm: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm">
        <div className="p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            <h3 className="text-white font-semibold">テナント切り替えの確認</h3>
          </div>
        </div>
        <div className="p-4">
          <p className="text-[#7d92b0] text-sm">
            <span className="text-white font-medium">{tenant.name}</span> のコンテキストに切り替えます。<br />
            このテナントのデータ・設定にアクセスできるようになります。
          </p>
          <div className="mt-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
            <p className="text-yellow-400 text-xs">すべての操作はスーパー管理者として記録されます</p>
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
          <button onClick={onConfirm} className="px-4 py-2 rounded-lg bg-yellow-500 text-black text-sm font-semibold hover:bg-yellow-400 transition-colors">切り替える</button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function TenantsManagementPage() {
  const queryClient = useQueryClient()

  const [showCreate, setShowCreate]           = useState(false)
  const [editQuotaTenant, setEditQuotaTenant] = useState<Tenant | null>(null)
  const [statsTenant, setStatsTenant]         = useState<Tenant | null>(null)
  const [auditTenant, setAuditTenant]         = useState<Tenant | null>(null)
  const [auditPage, setAuditPage]             = useState(1)
  const [impersonateTenant, setImpersonateTenant] = useState<Tenant | null>(null)
  const [deleteConfirm, setDeleteConfirm]     = useState<Tenant | null>(null)

  const { data: tenants = [], refetch } = useQuery<Tenant[]>({
    queryKey: ['admin-tenants'],
    queryFn: () => apiFetchList<Tenant>('/api/v1/admin/tenants').catch(() => []),
  })

  const EMPTY_STATS: TenantStats = { tenant_id: '', agent_count: 0, max_agents: 0, user_count: 0, max_users: 0, storage_used_gb: 0, max_storage_gb: 0, alerts_today: 0, max_alerts_per_day: 0, daily_alerts: [] }
  const { data: stats } = useQuery<TenantStats>({
    queryKey: ['admin-tenant-stats', statsTenant?.id],
    queryFn: () => apiFetch<TenantStats>(`/api/v1/admin/tenants/${statsTenant?.id}/stats`).catch(() => EMPTY_STATS),
    enabled: !!statsTenant,
  })

  const { data: auditLogs = [] } = useQuery<AuditLog[]>({
    queryKey: ['admin-tenant-audit', auditTenant?.id],
    queryFn: () => apiFetchList<AuditLog>(`/api/v1/admin/tenants/${auditTenant?.id}/audit`).catch(() => []),
    enabled: !!auditTenant,
  })

  const createMutation = useMutation({
    mutationFn: (data: Partial<Tenant>) => apiFetch('/api/v1/admin/tenants', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['admin-tenants'] }); setShowCreate(false) },
    onError: () => setShowCreate(false),
  })

  const quotaMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Tenant> }) =>
      apiFetch(`/api/v1/admin/tenants/${id}/quota`, { method: 'PUT', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['admin-tenants'] }); setEditQuotaTenant(null) },
    onError: () => setEditQuotaTenant(null),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/tenants/${id}`, { method: 'DELETE' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['admin-tenants'] }); setDeleteConfirm(null) },
    onError: () => setDeleteConfirm(null),
  })

  // Stats for overview
  const totalAgents  = tenants.reduce((s, t) => s + (Number(t.agent_count) || 0), 0)
  const totalStorage = tenants.reduce((s, t) => s + (Number(t.storage_used_gb) || 0), 0)
  const planCounts   = tenants.reduce<Record<string, number>>((acc, t) => ({ ...acc, [t.plan]: (acc[t.plan] || 0) + 1 }), {})

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-[#0d1220] border border-[#1e2d42]">
            <Building2 className="w-6 h-6 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">マルチテナント管理</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">テナントの作成・管理・クォータ設定</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#e8002d] transition-colors text-sm">
            <RefreshCw className="w-4 h-4" />更新
          </button>
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#cc0027] transition-colors">
            <Plus className="w-4 h-4" />新規テナント
          </button>
        </div>
      </div>

      {/* Usage Overview */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-[#7d92b0] text-sm">総テナント数</p>
          <p className="text-2xl font-bold text-white mt-1">{tenants.length}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-[#7d92b0] text-sm">総エージェント</p>
          <p className="text-2xl font-bold text-white mt-1">{totalAgents.toLocaleString()}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-[#7d92b0] text-sm">総ストレージ使用量</p>
          <p className="text-2xl font-bold text-white mt-1">{totalStorage.toFixed(2)} GB</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-[#7d92b0] text-sm mb-2">プラン分布</p>
          <div className="space-y-1">
            {[
              { plan: 'enterprise', label: 'Enterprise', color: '#f59e0b' },
              { plan: 'standard',   label: 'Standard',   color: '#3b82f6' },
              { plan: 'free',       label: 'Free',        color: '#6b7280' },
            ].map(p => (
              <div key={p.plan} className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
                  <span className="text-[#7d92b0] text-xs">{p.label}</span>
                </div>
                <span className="text-white text-xs font-medium">{planCounts[p.plan] || 0}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tenant Table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="p-4 border-b border-[#1e2d42]">
          <h2 className="text-lg font-semibold text-white">テナント一覧</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['テナント名', 'プラン', 'ステータス', 'エージェント', 'ユーザー', 'ストレージ', '作成日', 'アクション'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tenants.map(tenant => (
                <tr key={tenant.id}
                  className="border-b border-[#1e2d42] hover:bg-[#070d19] transition-colors cursor-pointer"
                  onClick={() => setStatsTenant(tenant)}>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <p className="text-white text-sm font-medium">{tenant.name}</p>
                    <p className="text-[#7d92b0] text-xs">{tenant.domain}</p>
                  </td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}><PlanBadge plan={tenant.plan} /></td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}><StatusBadge status={tenant.status} /></td>
                  <td className="px-4 py-3 min-w-[140px]" onClick={e => e.stopPropagation()}>
                    <UsageBar used={tenant.agent_count} max={tenant.max_agents} color="#3b82f6" />
                  </td>
                  <td className="px-4 py-3 min-w-[130px]" onClick={e => e.stopPropagation()}>
                    <UsageBar used={tenant.user_count} max={tenant.max_users} color="#22c55e" />
                  </td>
                  <td className="px-4 py-3 min-w-[140px]" onClick={e => e.stopPropagation()}>
                    <UsageBar used={parseFloat((tenant.storage_used_gb || 0).toFixed(2))} max={tenant.max_storage_gb} color="#a855f7" />
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-sm whitespace-nowrap" onClick={e => e.stopPropagation()}>{tenant.created_at}</td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setImpersonateTenant(tenant)}
                        title="テナントに切り替え"
                        className="p-1.5 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setEditQuotaTenant(tenant)}
                        title="クォータ編集"
                        className="p-1.5 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                        <Settings2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => { setAuditTenant(tenant); setAuditPage(1) }}
                        title="監査ログ"
                        className="p-1.5 rounded text-[#7d92b0] hover:text-white hover:bg-[#1e2d42] transition-colors">
                        <Shield className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setDeleteConfirm(tenant)}
                        title="削除"
                        className="p-1.5 rounded text-[#7d92b0] hover:text-red-400 hover:bg-[#1e2d42] transition-colors">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modals */}
      {showCreate && (
        <CreateTenantModal
          onClose={() => setShowCreate(false)}
          onSave={data => createMutation.mutate(data)}
        />
      )}

      {editQuotaTenant && (
        <EditQuotaModal
          tenant={editQuotaTenant}
          onClose={() => setEditQuotaTenant(null)}
          onSave={data => quotaMutation.mutate({ id: editQuotaTenant.id, data })}
        />
      )}

      {statsTenant && stats && (
        <StatsModal tenant={statsTenant} stats={stats} onClose={() => setStatsTenant(null)} />
      )}

      {auditTenant && (
        <AuditModal
          tenant={auditTenant}
          logs={auditLogs}
          page={auditPage}
          setPage={setAuditPage}
          onClose={() => setAuditTenant(null)}
        />
      )}

      {impersonateTenant && (
        <ImpersonateModal
          tenant={impersonateTenant}
          onClose={() => setImpersonateTenant(null)}
          onConfirm={() => setImpersonateTenant(null)}
        />
      )}

      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm">
            <div className="p-4 border-b border-[#1e2d42]">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-[#e8002d]" />
                <h3 className="text-white font-semibold">テナント削除の確認</h3>
              </div>
            </div>
            <div className="p-4">
              <p className="text-[#7d92b0] text-sm">
                <span className="text-white font-medium">{deleteConfirm.name}</span> を削除しますか？<br />
                この操作は元に戻せません。
              </p>
            </div>
            <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
              <button onClick={() => setDeleteConfirm(null)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
              <button onClick={() => deleteMutation.mutate(deleteConfirm.id)}
                className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#cc0027] transition-colors">削除</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
