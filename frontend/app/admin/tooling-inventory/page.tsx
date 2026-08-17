'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Wrench, Plus, Pencil, Trash2, X, CheckCircle, AlertTriangle,
  AlertCircle, DollarSign, Calendar, Users, RefreshCw, Download,
  Shield, Eye, EyeOff, ChevronRight, Info, Loader2, BarChart2,
  ArrowUpCircle, GitBranch,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type ToolCategory = 'EDR' | 'SIEM' | 'SOAR' | 'Vulnerability' | 'IAM' | 'Network' | 'Cloud' | 'GRC' | 'Training' | 'Other'
type LicenseType = 'perpetual' | 'subscription' | 'open_source' | 'trial'
type ToolStatus = 'active' | 'expired' | 'trial' | 'decommissioned'

interface SecurityTool {
  id: string
  tool_name: string
  vendor: string
  category: ToolCategory
  version: string
  license_type: LicenseType
  license_expiry: string | null
  seats_purchased: number
  seats_used: number
  monthly_cost: number
  status: ToolStatus
  owner: string
  renewal_contact: string
  notes: string
  integrations: string[]
  documentation_links: string[]
  last_audit_date: string
}

interface ToolRoadmapItem {
  id: string
  tool_name: string
  vendor: string
  action: 'add' | 'remove' | 'upgrade'
  planned_date: string
  reason: string
  estimated_cost: number
}

const LAST_YEAR_COST = 48_000_000 // 前年度ツール総コスト（円）

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CATEGORY_STYLES: Record<ToolCategory, { bg: string; text: string }> = {
  EDR:           { bg: 'bg-red-900/40',    text: 'text-red-300' },
  SIEM:          { bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  SOAR:          { bg: 'bg-purple-900/40', text: 'text-purple-300' },
  Vulnerability: { bg: 'bg-orange-900/40', text: 'text-orange-300' },
  IAM:           { bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  Network:       { bg: 'bg-cyan-900/40',   text: 'text-cyan-300' },
  Cloud:         { bg: 'bg-sky-900/40',    text: 'text-sky-300' },
  GRC:           { bg: 'bg-green-900/40',  text: 'text-green-300' },
  Training:      { bg: 'bg-teal-900/40',   text: 'text-teal-300' },
  Other:         { bg: 'bg-gray-800/60',   text: 'text-gray-400' },
}

const LICENSE_STYLES: Record<LicenseType, { label: string; bg: string; text: string }> = {
  perpetual:    { label: '永続', bg: 'bg-blue-900/40', text: 'text-blue-300' },
  subscription: { label: 'サブスク', bg: 'bg-green-900/40', text: 'text-green-300' },
  open_source:  { label: 'OSS', bg: 'bg-gray-800/60', text: 'text-gray-300' },
  trial:        { label: 'トライアル', bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
}

const STATUS_STYLES: Record<ToolStatus, { label: string; bg: string; text: string; dot: string }> = {
  active:         { label: 'アクティブ', bg: 'bg-green-900/40', text: 'text-green-300', dot: 'bg-green-400' },
  expired:        { label: '期限切れ', bg: 'bg-red-900/40', text: 'text-red-300', dot: 'bg-red-400' },
  trial:          { label: 'トライアル', bg: 'bg-yellow-900/40', text: 'text-yellow-300', dot: 'bg-yellow-400' },
  decommissioned: { label: '廃止', bg: 'bg-gray-800/60', text: 'text-gray-500', dot: 'bg-gray-600' },
}

const ROADMAP_ACTION_STYLES: Record<ToolRoadmapItem['action'], { label: string; bg: string; text: string; icon: React.ElementType }> = {
  add:     { label: '追加予定', bg: 'bg-green-900/40', text: 'text-green-300', icon: Plus },
  remove:  { label: '廃止予定', bg: 'bg-red-900/40', text: 'text-red-300', icon: Trash2 },
  upgrade: { label: 'アップグレード', bg: 'bg-blue-900/40', text: 'text-blue-300', icon: ArrowUpCircle },
}

// Capability coverage matrix
const CAPABILITY_MATRIX: { domain: string; tools: { category: ToolCategory; status: 'covered' | 'partial' | 'gap' }[] }[] = [
  { domain: 'エンドポイント保護 (EDR)', tools: [{ category: 'EDR', status: 'covered' }] },
  { domain: 'ネットワーク監視', tools: [{ category: 'Network', status: 'covered' }] },
  { domain: 'ID・アクセス管理', tools: [{ category: 'IAM', status: 'covered' }] },
  { domain: 'クラウドセキュリティ', tools: [{ category: 'Cloud', status: 'covered' }] },
  { domain: 'GRC・コンプライアンス', tools: [{ category: 'GRC', status: 'partial' }] },
  { domain: 'SIEM・ログ集約', tools: [{ category: 'SIEM', status: 'covered' }] },
  { domain: 'SOAR・自動化', tools: [{ category: 'SOAR', status: 'covered' }] },
  { domain: '脆弱性管理', tools: [{ category: 'Vulnerability', status: 'covered' }] },
  { domain: 'セキュリティ研修', tools: [{ category: 'Training', status: 'partial' }] },
  { domain: 'データ損失防止 (DLP)', tools: [{ category: 'Other', status: 'gap' }] },
]

function daysUntil(dateStr: string | null) {
  if (!dateStr) return null
  const diff = new Date(dateStr).getTime() - Date.now()
  return Math.ceil(diff / 86_400_000)
}

function expiryColor(dateStr: string | null) {
  const d = daysUntil(dateStr)
  if (d === null) return 'text-falcon-muted'
  if (d < 0) return 'text-red-400'
  if (d < 30) return 'text-red-400'
  if (d < 90) return 'text-orange-400'
  return 'text-green-400'
}

function fmt(d: string | null) {
  if (!d) return '—'
  return new Date(d).toLocaleDateString('ja-JP', { year: 'numeric', month: 'short', day: 'numeric' })
}

function fmtYen(n: number) {
  return '¥' + Math.abs(n).toLocaleString('ja-JP')
}

// ─── Tool Detail Modal ────────────────────────────────────────────────────────

function ToolDetailModal({ tool, onClose, onRenew }: {
  tool: SecurityTool
  onClose: () => void
  onRenew: () => void
}) {
  const days = daysUntil(tool.license_expiry)
  const utilPct = tool.seats_purchased > 0 ? Math.round((tool.seats_used / tool.seats_purchased) * 100) : 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border">
          <div>
            <h3 className="text-white font-semibold text-lg">{tool.tool_name}</h3>
            <div className="flex items-center gap-2 mt-1">
              <span className={`px-2 py-0.5 rounded-sm text-xs font-medium ${CATEGORY_STYLES[tool.category].bg} ${CATEGORY_STYLES[tool.category].text}`}>{tool.category}</span>
              <span className="text-falcon-muted text-sm">{tool.vendor}</span>
              <span className="text-falcon-subtle text-sm">v{tool.version}</span>
            </div>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white p-1"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto flex-1 p-5 space-y-4">
          {/* License info */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              {[
                { label: 'ライセンスタイプ', value: LICENSE_STYLES[tool.license_type].label },
                { label: '担当者', value: tool.owner },
                { label: '更新担当', value: tool.renewal_contact },
                { label: '最終監査日', value: fmt(tool.last_audit_date) },
              ].map(item => (
                <div key={item.label} className="flex gap-2 text-sm">
                  <span className="text-falcon-muted w-28 shrink-0">{item.label}:</span>
                  <span className="text-white">{item.value}</span>
                </div>
              ))}
            </div>
            <div className="space-y-3">
              <div className="bg-[#070d19] border border-falcon-border rounded-sm p-3">
                <p className="text-falcon-muted text-xs mb-1">ライセンス期限</p>
                <p className={`font-bold ${expiryColor(tool.license_expiry)}`}>
                  {fmt(tool.license_expiry)}
                  {days !== null && days >= 0 && <span className="text-xs ml-1">(残{days}日)</span>}
                  {days !== null && days < 0 && <span className="text-red-400 text-xs ml-1">期限切れ</span>}
                </p>
              </div>
              <div className="bg-[#070d19] border border-falcon-border rounded-sm p-3">
                <div className="flex justify-between mb-1">
                  <p className="text-falcon-muted text-xs">シート使用率</p>
                  <p className="text-white text-xs">{tool.seats_used}/{tool.seats_purchased}</p>
                </div>
                <div className="bg-falcon-border rounded-full h-2">
                  <div className={`h-2 rounded-full ${utilPct > 90 ? 'bg-red-500' : utilPct > 70 ? 'bg-yellow-500' : 'bg-green-500'}`} style={{ width: `${utilPct}%` }} />
                </div>
                <p className="text-falcon-muted text-xs mt-0.5">{utilPct}% 使用中</p>
              </div>
            </div>
          </div>

          {/* Notes */}
          <div>
            <p className="text-falcon-muted text-sm mb-1">備考</p>
            <p className="text-falcon-text text-sm bg-[#070d19] rounded-sm border border-falcon-border p-3">{tool.notes}</p>
          </div>

          {/* Integrations */}
          <div>
            <h4 className="text-white font-medium mb-2 flex items-center gap-2"><GitBranch className="w-4 h-4 text-blue-400" />連携ツール</h4>
            {tool.integrations.length === 0
              ? <p className="text-falcon-muted text-sm">連携なし</p>
              : <div className="flex flex-wrap gap-2">
                  {tool.integrations.map(i => (
                    <span key={i} className="px-2 py-1 bg-blue-900/20 border border-blue-800/30 rounded-sm text-xs text-blue-300">{i}</span>
                  ))}
                </div>
            }
          </div>

          {/* Documentation */}
          <div>
            <h4 className="text-white font-medium mb-2 flex items-center gap-2"><Info className="w-4 h-4 text-green-400" />ドキュメント</h4>
            {tool.documentation_links.length === 0
              ? <p className="text-falcon-muted text-sm">なし</p>
              : <ul className="space-y-1">
                  {tool.documentation_links.map(d => (
                    <li key={d} className="flex items-center gap-2 text-sm text-falcon-muted">
                      <ChevronRight className="w-3.5 h-3.5 text-falcon-red shrink-0" />{d}
                    </li>
                  ))}
                </ul>
            }
          </div>

          {/* Actions */}
          <div className="flex gap-3 pt-2">
            {tool.license_expiry && (
              <button onClick={onRenew} className="flex items-center gap-2 px-4 py-2 bg-falcon-red rounded-sm text-white text-sm hover:bg-[#c0001f]">
                <RefreshCw className="w-4 h-4" />更新手続き
              </button>
            )}
            <button onClick={onClose} className="px-4 py-2 border border-falcon-border rounded-sm text-falcon-muted hover:text-white text-sm">閉じる</button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Add/Edit Tool Modal ──────────────────────────────────────────────────────

function ToolFormModal({ tool, onClose, onSuccess }: {
  tool?: SecurityTool
  onClose: () => void
  onSuccess: () => void
}) {
  const [showKey, setShowKey] = useState(false)
  const [form, setForm] = useState({
    tool_name: tool?.tool_name ?? '',
    vendor: tool?.vendor ?? '',
    category: tool?.category ?? 'EDR' as ToolCategory,
    version: tool?.version ?? '',
    license_type: tool?.license_type ?? 'subscription' as LicenseType,
    license_key: '',
    license_expiry: tool?.license_expiry ?? '',
    seats_purchased: tool?.seats_purchased ?? 0,
    monthly_cost: tool?.monthly_cost ?? 0,
    owner: tool?.owner ?? '',
    renewal_contact: tool?.renewal_contact ?? '',
    notes: tool?.notes ?? '',
  })

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    onSuccess()
    onClose()
  }

  const categories: ToolCategory[] = ['EDR', 'SIEM', 'SOAR', 'Vulnerability', 'IAM', 'Network', 'Cloud', 'GRC', 'Training', 'Other']
  const licenseTypes: LicenseType[] = ['perpetual', 'subscription', 'open_source', 'trial']

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-falcon-border">
          <h3 className="text-white font-semibold text-lg">{tool ? 'ツールを編集' : 'ツールを追加'}</h3>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="overflow-y-auto flex-1 p-5 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-falcon-muted text-sm mb-1">ツール名 *</label>
              <input required value={form.tool_name} onChange={e => setForm(f => ({ ...f, tool_name: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">ベンダー *</label>
              <input required value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">カテゴリ *</label>
              <select required value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value as ToolCategory }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden">
                {categories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">バージョン</label>
              <input value={form.version} onChange={e => setForm(f => ({ ...f, version: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">ライセンスタイプ *</label>
              <select required value={form.license_type} onChange={e => setForm(f => ({ ...f, license_type: e.target.value as LicenseType }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden">
                {licenseTypes.map(t => <option key={t} value={t}>{LICENSE_STYLES[t].label}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">ライセンスキー</label>
              <div className="relative">
                <input type={showKey ? 'text' : 'password'} value={form.license_key} onChange={e => setForm(f => ({ ...f, license_key: e.target.value }))}
                  placeholder="••••••••••••"
                  className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 pr-10 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
                <button type="button" onClick={() => setShowKey(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-falcon-muted hover:text-white">
                  {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">ライセンス期限</label>
              <input type="date" value={form.license_expiry} onChange={e => setForm(f => ({ ...f, license_expiry: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">購入シート数</label>
              <input type="number" min="0" value={form.seats_purchased} onChange={e => setForm(f => ({ ...f, seats_purchased: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">月額コスト (¥)</label>
              <input type="number" min="0" value={form.monthly_cost} onChange={e => setForm(f => ({ ...f, monthly_cost: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">担当者 *</label>
              <input required value={form.owner} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
            <div>
              <label className="block text-falcon-muted text-sm mb-1">更新担当連絡先</label>
              <input value={form.renewal_contact} onChange={e => setForm(f => ({ ...f, renewal_contact: e.target.value }))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden" />
            </div>
          </div>
          <div>
            <label className="block text-falcon-muted text-sm mb-1">備考</label>
            <textarea value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-white text-sm focus:border-falcon-red focus:outline-hidden resize-none" />
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 px-4 py-2 border border-falcon-border rounded-sm text-falcon-muted hover:text-white text-sm">キャンセル</button>
            <button type="submit" className="flex-1 px-4 py-2 bg-falcon-red rounded-sm text-white font-medium text-sm hover:bg-[#c0001f]">
              {tool ? '更新する' : '追加する'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ToolingInventoryPage() {
  const [detailTool, setDetailTool] = useState<SecurityTool | null>(null)
  const [formTool, setFormTool] = useState<SecurityTool | undefined>(undefined)
  const [showForm, setShowForm] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [categoryFilter, setCategoryFilter] = useState<ToolCategory | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<ToolStatus | 'all'>('all')

  const { data: toolsData } = useQuery<SecurityTool[]>({
    queryKey: ['tooling-inventory'],
    queryFn: () => apiFetch('/api/v1/admin/tooling'),
    retry: false,
  })
  const tools = toolsData ?? []

  function showToast(msg: string) {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  const expiring90 = tools.filter(t => {
    const d = daysUntil(t.license_expiry)
    return d !== null && d >= 0 && d <= 90
  })
  const totalMonthlyCost = tools.reduce((s, t) => s + t.monthly_cost, 0)
  const annualCost = totalMonthlyCost * 12
  const activeLicenses = tools.filter(t => t.status === 'active').length
  const totalSeats = tools.reduce((s, t) => s + t.seats_purchased, 0)
  const usedSeats = tools.reduce((s, t) => s + t.seats_used, 0)
  const costPerUser = totalSeats > 0 ? Math.round(totalMonthlyCost / usedSeats) : 0

  const filtered = tools.filter(t => {
    if (categoryFilter !== 'all' && t.category !== categoryFilter) return false
    if (statusFilter !== 'all' && t.status !== statusFilter) return false
    return true
  })

  // Cost by category
  const categories: ToolCategory[] = ['EDR', 'SIEM', 'SOAR', 'Vulnerability', 'IAM', 'Network', 'Cloud', 'GRC', 'Training', 'Other']
  const categoryBudget = categories.map(cat => ({
    cat,
    cost: tools.filter(t => t.category === cat).reduce((s, t) => s + t.monthly_cost, 0),
  })).filter(c => c.cost > 0).sort((a, b) => b.cost - a.cost)
  const maxCatCost = Math.max(...categoryBudget.map(c => c.cost))

  function handleExportCSV() {
    const header = 'ツール名,ベンダー,カテゴリ,バージョン,ライセンスタイプ,期限,シート(購入),シート(使用),月額コスト,ステータス,担当者\n'
    const rows = tools.map(t =>
      `"${t.tool_name}","${t.vendor}","${t.category}","${t.version}","${t.license_type}","${t.license_expiry ?? ''}",${t.seats_purchased},${t.seats_used},${t.monthly_cost},"${t.status}","${t.owner}"`
    ).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'tooling-inventory.csv'
    a.click()
    URL.revokeObjectURL(url)
    showToast('CSVエクスポートが完了しました')
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-100 bg-green-800 border border-green-600 text-green-200 px-4 py-2 rounded-sm shadow-lg text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" />{toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-gray-500 to-gray-700 flex items-center justify-center">
            <Wrench className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white text-2xl font-bold">セキュリティツール台帳</h1>
            <p className="text-falcon-muted text-sm">セキュリティツールのライセンス・コスト・統合情報を一元管理</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleExportCSV}
            className="flex items-center gap-2 px-3 py-2 border border-falcon-border rounded-sm text-falcon-muted hover:text-white text-sm">
            <Download className="w-4 h-4" />CSVエクスポート
          </button>
          <button onClick={() => { setFormTool(undefined); setShowForm(true) }}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red rounded-lg text-white font-medium text-sm hover:bg-[#c0001f]">
            <Plus className="w-4 h-4" />ツールを追加
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'ツール総数', value: tools.length, icon: Wrench, color: 'text-blue-400', sub: `${activeLicenses} アクティブ` },
          { label: 'アクティブライセンス', value: activeLicenses, icon: CheckCircle, color: 'text-green-400', sub: `${tools.filter(t => t.status === 'trial').length} トライアル中` },
          { label: '90日以内に期限切れ', value: expiring90.length, icon: AlertTriangle, color: expiring90.length > 0 ? 'text-orange-400' : 'text-gray-500', sub: '要更新確認' },
          { label: '月次コスト合計', value: '¥' + totalMonthlyCost.toLocaleString('ja-JP'), icon: DollarSign, color: 'text-yellow-400', sub: `年間 ¥${(annualCost).toLocaleString('ja-JP')}` },
        ].map(card => (
          <div key={card.label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <p className="text-falcon-muted text-sm">{card.label}</p>
              <card.icon className={`w-5 h-5 ${card.color}`} />
            </div>
            <p className="text-white text-2xl font-bold">{card.value}</p>
            <p className="text-falcon-subtle text-xs mt-1">{card.sub}</p>
          </div>
        ))}
      </div>

      {/* Expiry Alerts Banner */}
      {expiring90.length > 0 && (
        <div className="bg-orange-900/20 border border-orange-700/40 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            <h3 className="text-white font-medium">ライセンス期限アラート ({expiring90.length}件)</h3>
          </div>
          <div className="space-y-2">
            {expiring90.map(t => {
              const d = daysUntil(t.license_expiry)!
              return (
                <div key={t.id} className="flex items-center justify-between bg-orange-900/10 rounded-sm px-4 py-2.5">
                  <div className="flex items-center gap-3">
                    <span className={`text-sm font-medium ${d < 30 ? 'text-red-400' : 'text-orange-300'}`}>{t.tool_name}</span>
                    <span className="text-falcon-muted text-sm">{t.vendor}</span>
                    <span className={`text-sm ${d < 30 ? 'text-red-400' : 'text-orange-400'}`}>残 {d}日 ({fmt(t.license_expiry)})</span>
                  </div>
                  <button onClick={() => showToast(`${t.tool_name}の更新手続きを開始します`)}
                    className="flex items-center gap-1 px-3 py-1.5 bg-falcon-red rounded-sm text-white text-xs hover:bg-[#c0001f]">
                    <RefreshCw className="w-3.5 h-3.5" />更新
                  </button>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Tools Table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center justify-between">
          <h2 className="text-white font-semibold">ツール一覧</h2>
          <div className="flex items-center gap-3">
            <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value as ToolCategory | 'all')}
              className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-white text-sm focus:outline-hidden">
              <option value="all">全カテゴリ</option>
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as ToolStatus | 'all')}
              className="bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-white text-sm focus:outline-hidden">
              <option value="all">全ステータス</option>
              <option value="active">アクティブ</option>
              <option value="trial">トライアル</option>
              <option value="expired">期限切れ</option>
              <option value="decommissioned">廃止</option>
            </select>
            <span className="text-falcon-muted text-sm">{filtered.length}件</span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-falcon-border bg-[#070d19]">
                {['ツール名', 'ベンダー', 'カテゴリ', 'バージョン', 'ライセンス', '期限', 'シート', '月額', 'ステータス', '担当者', '操作'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-falcon-muted font-medium text-xs uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-falcon-border">
              {filtered.map(t => {
                const days = daysUntil(t.license_expiry)
                const ss = STATUS_STYLES[t.status]
                const cs = CATEGORY_STYLES[t.category]
                const ls = LICENSE_STYLES[t.license_type]
                return (
                  <tr key={t.id} className="hover:bg-[#0d1525] cursor-pointer" onClick={() => setDetailTool(t)}>
                    <td className="px-4 py-3">
                      <p className="text-white font-medium whitespace-nowrap">{t.tool_name}</p>
                    </td>
                    <td className="px-4 py-3 text-falcon-muted whitespace-nowrap">{t.vendor}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium ${cs.bg} ${cs.text}`}>{t.category}</span>
                    </td>
                    <td className="px-4 py-3 text-falcon-muted">{t.version}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium ${ls.bg} ${ls.text}`}>{ls.label}</span>
                    </td>
                    <td className={`px-4 py-3 whitespace-nowrap text-sm ${expiryColor(t.license_expiry)}`}>
                      {t.license_expiry ? (
                        <>
                          {fmt(t.license_expiry)}
                          {days !== null && days >= 0 && days <= 90 && (
                            <span className="ml-1 text-xs">(残{days}日)</span>
                          )}
                        </>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-falcon-muted">
                      {t.seats_purchased > 0 ? `${t.seats_used}/${t.seats_purchased}` : '—'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {t.monthly_cost > 0 ? <span className="text-white">{fmtYen(t.monthly_cost)}</span> : <span className="text-green-400 text-xs">無償</span>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium ${ss.bg} ${ss.text}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${ss.dot}`} />{ss.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-falcon-muted whitespace-nowrap">{t.owner}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                        <button onClick={() => { setFormTool(t); setShowForm(true) }}
                          className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white"><Pencil className="w-3.5 h-3.5" /></button>
                        <button onClick={() => showToast(`${t.tool_name}を削除しました`)}
                          className="p-1.5 rounded-sm hover:bg-red-900/40 text-falcon-muted hover:text-red-300"><Trash2 className="w-3.5 h-3.5" /></button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Budget Analysis + Capability Matrix */}
      <div className="grid grid-cols-2 gap-6">
        {/* Budget by Category */}
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
          <h2 className="text-white font-semibold mb-1 flex items-center gap-2"><BarChart2 className="w-4 h-4 text-blue-400" />カテゴリ別月額コスト</h2>
          <p className="text-falcon-muted text-xs mb-4">ユーザー当たりコスト: {fmtYen(costPerUser)}/月</p>
          <div className="space-y-3">
            {categoryBudget.map(c => (
              <div key={c.cat} className="flex items-center gap-3">
                <span className={`text-xs w-28 shrink-0 ${CATEGORY_STYLES[c.cat].text}`}>{c.cat}</span>
                <div className="flex-1 bg-falcon-border rounded-full h-4 relative overflow-hidden">
                  <div className={`${CATEGORY_STYLES[c.cat].bg.replace('/40', '/80')} h-4 rounded-full flex items-center justify-end pr-2`}
                    style={{ width: `${(c.cost / maxCatCost) * 100}%` }}>
                  </div>
                </div>
                <span className="text-white text-xs w-24 text-right shrink-0">{fmtYen(c.cost)}/月</span>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-falcon-border">
            <div className="flex justify-between items-center">
              <div>
                <p className="text-falcon-muted text-sm">今年度 月額合計</p>
                <p className="text-white font-bold text-lg">{fmtYen(totalMonthlyCost)}/月</p>
              </div>
              <div className="text-right">
                <p className="text-falcon-muted text-sm">前年比</p>
                <p className={`font-bold text-lg ${totalMonthlyCost * 12 > LAST_YEAR_COST ? 'text-red-400' : 'text-green-400'}`}>
                  {totalMonthlyCost * 12 > LAST_YEAR_COST ? '+' : '-'}
                  {Math.abs(Math.round(((totalMonthlyCost * 12) - LAST_YEAR_COST) / LAST_YEAR_COST * 100))}%
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Capability Coverage Matrix */}
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
          <h2 className="text-white font-semibold mb-4 flex items-center gap-2"><Shield className="w-4 h-4 text-green-400" />ケイパビリティカバレッジマトリックス</h2>
          <div className="space-y-2">
            {CAPABILITY_MATRIX.map(row => {
              const status = row.tools[0].status
              return (
                <div key={row.domain} className="flex items-center justify-between p-3 bg-[#070d19] rounded-sm border border-falcon-border">
                  <span className="text-falcon-muted text-sm">{row.domain}</span>
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium ${
                    status === 'covered' ? 'bg-green-900/40 text-green-300' :
                    status === 'partial' ? 'bg-yellow-900/40 text-yellow-300' :
                    'bg-red-900/40 text-red-300'
                  }`}>
                    {status === 'covered'
                      ? <><CheckCircle className="w-3 h-3" />カバー済み</>
                      : status === 'partial'
                      ? <><AlertCircle className="w-3 h-3" />一部対応</>
                      : <><AlertTriangle className="w-3 h-3" />ギャップあり</>
                    }
                  </span>
                </div>
              )
            })}
          </div>
          <div className="flex items-center gap-4 mt-4 text-xs text-falcon-muted">
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-green-400" />カバー済み</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-yellow-400" />一部対応</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-400" />ギャップあり</span>
          </div>
        </div>
      </div>

      {/* Tool Roadmap */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5">
        <h2 className="text-white font-semibold mb-4 flex items-center gap-2"><GitBranch className="w-5 h-5 text-purple-400" />ツールロードマップ</h2>
        <div className="relative">
          <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-falcon-border" />
          <div className="space-y-4">
            {([] as ToolRoadmapItem[]).map(item => {
              const as = ROADMAP_ACTION_STYLES[item.action]
              return (
                <div key={item.id} className="relative pl-10">
                  <div className={`absolute left-2.5 top-2 w-3 h-3 rounded-full border-2 ${
                    item.action === 'add' ? 'bg-green-500 border-green-400' :
                    item.action === 'remove' ? 'bg-red-500 border-red-400' :
                    'bg-blue-500 border-blue-400'
                  }`} />
                  <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium ${as.bg} ${as.text}`}>
                            <as.icon className="w-3 h-3" />{as.label}
                          </span>
                          <p className="text-white font-medium">{item.tool_name}</p>
                          <span className="text-falcon-subtle text-sm">{item.vendor}</span>
                        </div>
                        <p className="text-falcon-muted text-sm">{item.reason}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-falcon-muted text-xs">{fmt(item.planned_date)}</p>
                        {item.estimated_cost !== 0 && (
                          <p className={`text-sm font-medium ${item.estimated_cost < 0 ? 'text-green-400' : 'text-white'}`}>
                            {item.estimated_cost < 0 ? '削減 ' : ''}{fmtYen(item.estimated_cost)}/月
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Modals */}
      {detailTool && (
        <ToolDetailModal
          tool={detailTool}
          onClose={() => setDetailTool(null)}
          onRenew={() => showToast(`${detailTool.tool_name}の更新手続きを開始しました`)}
        />
      )}
      {showForm && (
        <ToolFormModal
          tool={formTool}
          onClose={() => setShowForm(false)}
          onSuccess={() => showToast(formTool ? 'ツール情報を更新しました' : 'ツールを追加しました')}
        />
      )}
    </div>
  )
}
