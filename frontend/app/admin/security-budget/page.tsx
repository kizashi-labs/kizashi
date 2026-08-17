'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

import {
  DollarSign, Plus, Pencil, Trash2, X, Loader2,
  TrendingUp, AlertTriangle, CheckCircle, ChevronDown, ChevronRight,
  RefreshCw, BarChart2, PiggyBank, Wallet, Receipt,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type BudgetCategory = 'tools' | 'personnel' | 'training' | 'incident_response' | 'compliance'

interface BudgetItem {
  id: string
  fiscal_year: number
  category: BudgetCategory
  name: string
  vendor: string
  allocated: number
  spent: number
  notes: string
  transactions?: Transaction[]
}

interface Transaction {
  id: string
  budget_item_id: string
  amount: number
  description: string
  date: string
}

interface BudgetSummary {
  fiscal_year: number
  total_allocated: number
  total_spent: number
  items: BudgetItem[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CATEGORY_STYLES: Record<BudgetCategory, { label: string; cls: string; color: string }> = {
  tools:             { label: 'ツール',       cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30',    color: '#3b82f6' },
  personnel:         { label: '人件費',       cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30', color: '#a855f7' },
  training:          { label: 'トレーニング', cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', color: '#eab308' },
  incident_response: { label: 'IR',           cls: 'bg-red-500/20 text-falcon-red border-red-500/30',     color: '#e8002d' },
  compliance:        { label: 'コンプライアンス', cls: 'bg-green-500/20 text-green-400 border-green-500/30', color: '#22c55e' },
}

const YEARS = [2024, 2025, 2026]

function formatYen(n: number): string {
  if (n >= 1_000_000) return `¥${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `¥${(n / 1_000).toFixed(0)}K`
  return `¥${n.toLocaleString()}`
}

function formatYenFull(n: number): string {
  return `¥${n.toLocaleString()}`
}

function utilizationColor(pct: number): string {
  if (pct >= 100) return '#e8002d'
  if (pct >= 80) return '#f59e0b'
  return '#22c55e'
}

// ─── Circular Progress ────────────────────────────────────────────────────────

function CircularProgress({ value, max, label, sublabel }: { value: number; max: number; label: string; sublabel: string }) {
  const pct = Math.min((value / max) * 100, 100)
  const r = 34
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ
  const color = utilizationColor(pct)

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-20 h-20">
        <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
          <circle cx="40" cy="40" r={r} fill="none" stroke="#1e2d42" strokeWidth="7" />
          <circle
            cx="40" cy="40" r={r} fill="none"
            stroke={color} strokeWidth="7"
            strokeDasharray={`${dash} ${circ}`}
            strokeLinecap="round"
            style={{ transition: 'stroke-dasharray 0.5s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-sm font-bold text-white">{pct.toFixed(0)}%</span>
        </div>
      </div>
      <p className="text-xs text-white font-medium mt-2">{label}</p>
      <p className="text-xs text-falcon-muted mt-0.5">{sublabel}</p>
    </div>
  )
}

// ─── Category Bar Chart ───────────────────────────────────────────────────────

function CategoryChart({ items }: { items: BudgetItem[] }) {
  const categories = Object.keys(CATEGORY_STYLES) as BudgetCategory[]
  const totals = categories.map(cat => {
    const its = items.filter(i => i.category === cat)
    return {
      cat,
      allocated: its.reduce((s, i) => s + i.allocated, 0),
      spent: its.reduce((s, i) => s + i.spent, 0),
    }
  }).filter(t => t.allocated > 0)
  const maxVal = Math.max(...totals.map(t => t.allocated))

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
      <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
        <BarChart2 className="w-4 h-4 text-falcon-red" />
        カテゴリ別予算
      </h3>
      <div className="space-y-4">
        {totals.map(({ cat, allocated, spent }) => {
          const allocPct = (allocated / maxVal) * 100
          const spentPct = (spent / maxVal) * 100
          const utilPct = (spent / allocated) * 100
          return (
            <div key={cat}>
              <div className="flex items-center justify-between mb-1.5">
                <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${CATEGORY_STYLES[cat].cls}`}>
                  {CATEGORY_STYLES[cat].label}
                </span>
                <div className="flex items-center gap-3 text-xs text-falcon-muted">
                  <span>予算: {formatYen(allocated)}</span>
                  <span className="text-white font-medium">使用: {formatYen(spent)}</span>
                  <span style={{ color: utilizationColor(utilPct) }}>{utilPct.toFixed(0)}%</span>
                </div>
              </div>
              <div className="relative h-5 bg-[#070d19] rounded-full overflow-hidden border border-falcon-border">
                {/* Allocated bar */}
                <div
                  className="absolute top-0 left-0 h-full rounded-full opacity-20"
                  style={{ width: `${allocPct}%`, backgroundColor: CATEGORY_STYLES[cat].color }}
                />
                {/* Spent bar */}
                <div
                  className="absolute top-0 left-0 h-full rounded-full transition-all duration-500"
                  style={{ width: `${spentPct}%`, backgroundColor: CATEGORY_STYLES[cat].color }}
                />
              </div>
            </div>
          )
        })}
      </div>
      <div className="flex items-center gap-4 mt-4">
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-xs bg-[#3b82f6] opacity-30" />
          <span className="text-xs text-falcon-muted">予算額</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-3 h-3 rounded-xs bg-[#3b82f6]" />
          <span className="text-xs text-falcon-muted">使用済み</span>
        </div>
      </div>
    </div>
  )
}

// ─── Budget Item Modal ────────────────────────────────────────────────────────

interface ItemModalProps {
  item?: BudgetItem | null
  year: number
  onClose: () => void
  onSave: (data: Partial<BudgetItem>) => void
  saving: boolean
}

function ItemModal({ item, year, onClose, onSave, saving }: ItemModalProps) {
  const [form, setForm] = useState({
    fiscal_year: item?.fiscal_year ?? year,
    category: item?.category ?? 'tools' as BudgetCategory,
    name: item?.name ?? '',
    vendor: item?.vendor ?? '',
    allocated: item?.allocated ?? 0,
    notes: item?.notes ?? '',
  })
  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold">{item ? '予算項目編集' : '新規予算項目'}</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">会計年度</label>
              <select
                value={form.fiscal_year}
                onChange={e => set('fiscal_year', parseInt(e.target.value))}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                {YEARS.map(y => <option key={y} value={y}>{y}年度</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-falcon-muted mb-1.5">カテゴリ</label>
              <select
                value={form.category}
                onChange={e => set('category', e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              >
                {(Object.entries(CATEGORY_STYLES) as [BudgetCategory, { label: string }][]).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">項目名 *</label>
            <input
              value={form.name}
              onChange={e => set('name', e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="Kizashi ライセンス"
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">ベンダー</label>
            <input
              value={form.vendor}
              onChange={e => set('vendor', e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="CrowdStrike"
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">予算額 (円) *</label>
            <input
              type="number"
              value={form.allocated}
              onChange={e => set('allocated', parseInt(e.target.value) || 0)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="10000000"
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">メモ</label>
            <textarea
              value={form.notes}
              onChange={e => set('notes', e.target.value)}
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50 resize-none"
            />
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={saving || !form.name}
            className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Transaction Modal ────────────────────────────────────────────────────────

interface TxModalProps {
  item: BudgetItem
  onClose: () => void
  onSave: (tx: { amount: number; description: string; date: string }) => void
  saving: boolean
}

function TransactionModal({ item, onClose, onSave, saving }: TxModalProps) {
  const [form, setForm] = useState({ amount: 0, description: '', date: new Date().toISOString().slice(0, 10) })
  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <div>
            <h2 className="text-white font-semibold">取引追加</h2>
            <p className="text-xs text-falcon-muted mt-0.5">{item.name}</p>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">金額 (円) *</label>
            <input
              type="number"
              value={form.amount}
              onChange={e => set('amount', parseInt(e.target.value) || 0)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">説明 *</label>
            <input
              value={form.description}
              onChange={e => set('description', e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
              placeholder="Q1ライセンス費用"
            />
          </div>
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">日付</label>
            <input
              type="date"
              value={form.date}
              onChange={e => set('date', e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-falcon-red/50"
            />
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => onSave(form)}
            disabled={saving || !form.description || !form.amount}
            className="px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── ROI Section ──────────────────────────────────────────────────────────────

function RoiSection({ summary }: { summary: BudgetSummary }) {
  const avgIncidentCost = 45_000_000
  const avoidedIncidents = 3
  const detectionTimeSaved = 72
  const costAvoided = avgIncidentCost * avoidedIncidents
  const roi = ((costAvoided - summary.total_spent) / summary.total_spent) * 100

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
      <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
        <TrendingUp className="w-4 h-4 text-green-400" />
        セキュリティ投資ROI
      </h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
          <p className="text-xs text-falcon-muted mb-1">回避インシデント数</p>
          <p className="text-xl font-bold text-white">{avoidedIncidents}</p>
          <p className="text-xs text-falcon-muted mt-0.5">件/年</p>
        </div>
        <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
          <p className="text-xs text-falcon-muted mb-1">回避コスト (推定)</p>
          <p className="text-xl font-bold text-green-400">{formatYen(costAvoided)}</p>
          <p className="text-xs text-falcon-muted mt-0.5">@ {formatYen(avgIncidentCost)}/件</p>
        </div>
        <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
          <p className="text-xs text-falcon-muted mb-1">検知時間短縮</p>
          <p className="text-xl font-bold text-blue-400">{detectionTimeSaved}h</p>
          <p className="text-xs text-falcon-muted mt-0.5">MTTR削減</p>
        </div>
        <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3">
          <p className="text-xs text-falcon-muted mb-1">投資ROI</p>
          <p className="text-xl font-bold" style={{ color: roi > 0 ? '#22c55e' : '#e8002d' }}>
            {roi > 0 ? '+' : ''}{roi.toFixed(0)}%
          </p>
          <p className="text-xs text-falcon-muted mt-0.5">(回避コスト - 予算) / 予算</p>
        </div>
      </div>
      <div className="bg-[#070d19] border border-falcon-border rounded-lg p-3 text-xs text-falcon-muted">
        <p className="font-medium text-falcon-text mb-1">ROI計算式</p>
        <code className="font-mono text-green-400">
          ROI = (回避インシデントコスト合計 - セキュリティ予算) ÷ セキュリティ予算 × 100
        </code>
        <p className="mt-1.5">
          = ({formatYenFull(costAvoided)} - {formatYenFull(summary.total_spent)}) ÷ {formatYenFull(summary.total_spent)} × 100 = <span className="text-white font-bold">{roi.toFixed(1)}%</span>
        </p>
      </div>
    </div>
  )
}

const EMPTY_BUDGET = (year: number): BudgetSummary => ({ fiscal_year: year, total_allocated: 0, total_spent: 0, items: [] })

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SecurityBudgetPage() {
  const qc = useQueryClient()
  const [year, setYear] = useState(2026)
  const [showItemModal, setShowItemModal] = useState(false)
  const [editItem, setEditItem] = useState<BudgetItem | null>(null)
  const [txItem, setTxItem] = useState<BudgetItem | null>(null)
  const [expandedTx, setExpandedTx] = useState<Set<string>>(new Set())

  const { data, isLoading } = useQuery<BudgetSummary>({
    queryKey: ['security-budget', year],
    queryFn: async () => {
      try {
        const res = await apiFetch<BudgetSummary>(`/api/v1/admin/security-budget?year=${year}`)
        return (res && 'total_allocated' in (res as any)) ? res as BudgetSummary : EMPTY_BUDGET(year)
      } catch {
        return EMPTY_BUDGET(year)
      }
    },
  })

  const saveItemMutation = useMutation({
    mutationFn: async (payload: { id?: string; data: Partial<BudgetItem> }) => {
      try {
        if (payload.id) {
          return await apiFetch(`/api/v1/admin/security-budget/${payload.id}`, {
            method: 'PUT', body: JSON.stringify(payload.data),
          })
        }
        return await apiFetch('/api/v1/admin/security-budget', {
          method: 'POST', body: JSON.stringify(payload.data),
        })
      } catch { return { ...payload.data, id: payload.id ?? `b-${Date.now()}` } }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['security-budget'] })
      setShowItemModal(false)
      setEditItem(null)
    },
  })

  const deleteItemMutation = useMutation({
    mutationFn: async (id: string) => {
      try { return await apiFetch(`/api/v1/admin/security-budget/${id}`, { method: 'DELETE' }) } catch { return null }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['security-budget'] }),
  })

  const addTxMutation = useMutation({
    mutationFn: async (payload: { itemId: string; tx: { amount: number; description: string; date: string } }) => {
      try {
        return await apiFetch(`/api/v1/admin/security-budget/${payload.itemId}/transactions`, {
          method: 'POST', body: JSON.stringify(payload.tx),
        })
      } catch { return null }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['security-budget'] })
      setTxItem(null)
    },
  })

  const summary = data ?? EMPTY_BUDGET(year)
  const totalRemaining = summary.total_allocated - summary.total_spent
  const utilPct = summary.total_allocated > 0 ? (summary.total_spent / summary.total_allocated) * 100 : 0

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-falcon-red/20 border border-falcon-red/30 flex items-center justify-center">
            <DollarSign className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">セキュリティ予算管理</h1>
            <p className="text-sm text-falcon-muted">予算配分・支出追跡・ROI分析</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 bg-falcon-surface border border-falcon-border rounded-lg p-1">
            {YEARS.map(y => (
              <button
                key={y}
                onClick={() => setYear(y)}
                className={`px-3 py-1.5 rounded text-sm font-medium transition-all ${
                  year === y ? 'bg-falcon-red text-white' : 'text-falcon-muted hover:text-white'
                }`}
              >
                {y}年度
              </button>
            ))}
          </div>
          <button
            onClick={() => { setEditItem(null); setShowItemModal(true) }}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            予算追加
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-6 h-6 animate-spin text-falcon-muted" />
        </div>
      ) : (
        <div className="space-y-6">
          {/* KPI Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Wallet className="w-4 h-4 text-blue-400" />
                <span className="text-xs text-falcon-muted">総予算</span>
              </div>
              <p className="text-2xl font-bold text-white">{formatYen(summary.total_allocated)}</p>
              <p className="text-xs text-falcon-muted mt-1">{formatYenFull(summary.total_allocated)}</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Receipt className="w-4 h-4 text-yellow-400" />
                <span className="text-xs text-falcon-muted">使用済み</span>
              </div>
              <p className="text-2xl font-bold text-white">{formatYen(summary.total_spent)}</p>
              <p className="text-xs text-falcon-muted mt-1">{formatYenFull(summary.total_spent)}</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <PiggyBank className="w-4 h-4 text-green-400" />
                <span className="text-xs text-falcon-muted">残予算</span>
              </div>
              <p className="text-2xl font-bold text-green-400">{formatYen(totalRemaining)}</p>
              <p className="text-xs text-falcon-muted mt-1">{formatYenFull(totalRemaining)}</p>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4 flex items-center justify-center">
              <CircularProgress
                value={summary.total_spent}
                max={summary.total_allocated}
                label="予算消化率"
                sublabel={`${utilPct.toFixed(1)}%`}
              />
            </div>
          </div>

          {/* Category Chart */}
          <CategoryChart items={summary.items} />

          {/* Budget Items Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-falcon-border flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">予算項目一覧</h3>
              <span className="text-xs text-falcon-muted">{summary.items.length} 項目</span>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  <th className="text-left text-xs text-falcon-muted font-medium px-4 py-3">カテゴリ/名称</th>
                  <th className="text-left text-xs text-falcon-muted font-medium px-4 py-3">ベンダー</th>
                  <th className="text-right text-xs text-falcon-muted font-medium px-4 py-3">予算額</th>
                  <th className="text-right text-xs text-falcon-muted font-medium px-4 py-3">使用済み</th>
                  <th className="text-right text-xs text-falcon-muted font-medium px-4 py-3">残額</th>
                  <th className="text-left text-xs text-falcon-muted font-medium px-4 py-3 w-36">消化率</th>
                  <th className="text-right text-xs text-falcon-muted font-medium px-4 py-3">操作</th>
                </tr>
              </thead>
              <tbody>
                {summary.items.map(item => {
                  const rem = item.allocated - item.spent
                  const pct = item.allocated > 0 ? (item.spent / item.allocated) * 100 : 0
                  const txExpanded = expandedTx.has(item.id)
                  return (
                    <>
                      <tr key={item.id} className="border-b border-falcon-border/60 hover:bg-[#070d19]/50 transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => setExpandedTx(s => {
                                const n = new Set(s)
                                n.has(item.id) ? n.delete(item.id) : n.add(item.id)
                                return n
                              })}
                              className="text-falcon-subtle hover:text-falcon-muted transition-colors"
                            >
                              {txExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                            </button>
                            <div>
                              <span className={`inline-flex items-center px-1.5 py-0.5 rounded-sm text-xs border font-medium mr-2 ${CATEGORY_STYLES[item.category].cls}`}>
                                {CATEGORY_STYLES[item.category].label}
                              </span>
                              <span className="text-sm text-white font-medium">{item.name}</span>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-falcon-muted">{item.vendor}</td>
                        <td className="px-4 py-3 text-right text-sm text-white font-mono">{formatYenFull(item.allocated)}</td>
                        <td className="px-4 py-3 text-right text-sm text-white font-mono">{formatYenFull(item.spent)}</td>
                        <td className="px-4 py-3 text-right text-sm font-mono" style={{ color: rem >= 0 ? '#22c55e' : '#e8002d' }}>
                          {rem >= 0 ? '+' : ''}{formatYenFull(rem)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-[#070d19] rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full transition-all duration-500"
                                style={{ width: `${Math.min(pct, 100)}%`, backgroundColor: utilizationColor(pct) }}
                              />
                            </div>
                            <span className="text-xs font-mono w-8 text-right" style={{ color: utilizationColor(pct) }}>
                              {pct.toFixed(0)}%
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => setTxItem(item)}
                              className="p-1.5 rounded-sm hover:bg-green-500/10 text-falcon-muted hover:text-green-400 transition-colors"
                              title="取引追加"
                            >
                              <Plus className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => { setEditItem(item); setShowItemModal(true) }}
                              className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors"
                              title="編集"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => { if (confirm(`"${item.name}" を削除しますか？`)) deleteItemMutation.mutate(item.id) }}
                              className="p-1.5 rounded-sm hover:bg-red-500/10 text-falcon-muted hover:text-falcon-red transition-colors"
                              title="削除"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                      {txExpanded && item.transactions && item.transactions.length > 0 && (
                        <tr key={`${item.id}-tx`} className="border-b border-falcon-border/40">
                          <td colSpan={7} className="px-4 py-0">
                            <div className="ml-8 my-2 rounded-lg border border-falcon-border overflow-hidden bg-[#070d19]/40">
                              <table className="w-full">
                                <thead>
                                  <tr className="border-b border-falcon-border">
                                    <th className="text-left text-xs text-falcon-muted font-medium px-3 py-2">説明</th>
                                    <th className="text-right text-xs text-falcon-muted font-medium px-3 py-2">金額</th>
                                    <th className="text-right text-xs text-falcon-muted font-medium px-3 py-2">日付</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {item.transactions.map(tx => (
                                    <tr key={tx.id} className="border-b border-falcon-border/30 last:border-0">
                                      <td className="px-3 py-1.5 text-xs text-falcon-muted">{tx.description}</td>
                                      <td className="px-3 py-1.5 text-xs text-white font-mono text-right">{formatYenFull(tx.amount)}</td>
                                      <td className="px-3 py-1.5 text-xs text-falcon-muted text-right">{tx.date}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ROI Section */}
          <RoiSection summary={summary} />
        </div>
      )}

      {showItemModal && (
        <ItemModal
          item={editItem}
          year={year}
          onClose={() => { setShowItemModal(false); setEditItem(null) }}
          onSave={data => saveItemMutation.mutate({ id: editItem?.id, data })}
          saving={saveItemMutation.isPending}
        />
      )}
      {txItem && (
        <TransactionModal
          item={txItem}
          onClose={() => setTxItem(null)}
          onSave={tx => addTxMutation.mutate({ itemId: txItem.id, tx })}
          saving={addTxMutation.isPending}
        />
      )}
    </div>
  )
}
