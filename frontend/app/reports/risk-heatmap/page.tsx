'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Map, Plus, Edit2, Trash2, X, ChevronDown, ChevronUp,
  AlertTriangle, Filter, TrendingUp,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ───────────────────────────────────────────────────────────────────

type RiskCategory = 'endpoint' | 'network' | 'identity' | 'data' | 'compliance'
type RiskStatus = 'open' | 'mitigated' | 'accepted'

interface RiskItem {
  id: string
  name: string
  category: RiskCategory
  impact: number
  likelihood: number
  score: number
  owner: string
  status: RiskStatus
  last_review: string
  description: string
  mitigation_plan: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_RISKS: RiskItem[] = [
  { id: '1',  name: 'ランサムウェア感染',           category: 'endpoint',   impact: 5, likelihood: 4, score: 20, owner: '田中太郎',   status: 'open',      last_review: '2026-03-01', description: 'エンドポイントへのランサムウェア攻撃',     mitigation_plan: 'EDRポリシー強化、バックアップ整備' },
  { id: '2',  name: 'フィッシング攻撃',             category: 'identity',   impact: 4, likelihood: 5, score: 20, owner: '鈴木花子',   status: 'open',      last_review: '2026-03-05', description: '認証情報を狙ったフィッシング',             mitigation_plan: 'MFA必須化、セキュリティ教育' },
  { id: '3',  name: 'SQLインジェクション',          category: 'data',       impact: 5, likelihood: 3, score: 15, owner: '佐藤次郎',   status: 'open',      last_review: '2026-03-10', description: 'Webアプリへの不正SQLクエリ',              mitigation_plan: 'WAF導入、入力検証強化' },
  { id: '4',  name: '特権アカウント悪用',           category: 'identity',   impact: 5, likelihood: 3, score: 15, owner: '伊藤美咲',   status: 'mitigated', last_review: '2026-02-28', description: '管理者アカウントの不正使用',               mitigation_plan: 'PAM導入済み' },
  { id: '5',  name: 'DDoS攻撃',                   category: 'network',    impact: 4, likelihood: 3, score: 12, owner: '山田健一',   status: 'open',      last_review: '2026-03-08', description: 'サービス妨害攻撃',                        mitigation_plan: 'CDN/DDoS対策サービス導入' },
  { id: '6',  name: 'コンプライアンス違反',         category: 'compliance', impact: 4, likelihood: 3, score: 12, owner: '中村直子',   status: 'accepted',  last_review: '2026-03-02', description: '規制要件への不適合',                      mitigation_plan: '四半期監査実施' },
  { id: '7',  name: 'データ漏洩（内部）',           category: 'data',       impact: 5, likelihood: 2, score: 10, owner: '小林雅彦',   status: 'open',      last_review: '2026-03-12', description: '内部者によるデータ持ち出し',              mitigation_plan: 'DLP導入、アクセスログ監視' },
  { id: '8',  name: 'ゼロデイ脆弱性',              category: 'endpoint',   impact: 5, likelihood: 2, score: 10, owner: '加藤智子',   status: 'open',      last_review: '2026-03-07', description: '未公開脆弱性の悪用',                      mitigation_plan: '仮想パッチ、挙動監視' },
  { id: '9',  name: 'サプライチェーン攻撃',         category: 'endpoint',   impact: 4, likelihood: 2, score:  8, owner: '松本哲也',   status: 'open',      last_review: '2026-03-03', description: 'サードパーティ経由の侵害',                mitigation_plan: 'SBOM管理、ベンダー審査' },
  { id: '10', name: '設定ミス（クラウド）',         category: 'network',    impact: 4, likelihood: 2, score:  8, owner: '井上奈々',   status: 'mitigated', last_review: '2026-02-25', description: 'クラウドリソースの誤設定',                mitigation_plan: 'CSPM導入済み' },
  { id: '11', name: 'パスワード再利用',             category: 'identity',   impact: 3, likelihood: 4, score: 12, owner: '木村拓哉',   status: 'open',      last_review: '2026-03-09', description: '認証情報の使い回し',                      mitigation_plan: 'パスワードポリシー強化' },
  { id: '12', name: 'パッチ未適用',                category: 'endpoint',   impact: 3, likelihood: 4, score: 12, owner: '清水恵子',   status: 'open',      last_review: '2026-03-11', description: 'セキュリティパッチの未適用',              mitigation_plan: '自動パッチ管理導入' },
  { id: '13', name: 'ネットワーク盗聴',             category: 'network',    impact: 3, likelihood: 3, score:  9, owner: '渡辺誠',     status: 'accepted',  last_review: '2026-03-04', description: '通信の傍受',                              mitigation_plan: 'TLS強制、VPN整備' },
  { id: '14', name: 'モバイルデバイスリスク',       category: 'endpoint',   impact: 3, likelihood: 3, score:  9, owner: '高橋幸代',   status: 'open',      last_review: '2026-03-06', description: 'BYODデバイスの管理不備',                  mitigation_plan: 'MDM導入' },
  { id: '15', name: 'APIキー漏洩',                 category: 'data',       impact: 4, likelihood: 2, score:  8, owner: '岡田誠',     status: 'open',      last_review: '2026-03-13', description: 'APIキーの公開リポジトリへの漏洩',         mitigation_plan: 'シークレット管理ツール導入' },
  { id: '16', name: 'ログ管理不備',                category: 'compliance', impact: 2, likelihood: 4, score:  8, owner: '橋本優子',   status: 'mitigated', last_review: '2026-02-20', description: '監査ログの不整備',                        mitigation_plan: 'SIEM強化済み' },
  { id: '17', name: '物理セキュリティ不備',         category: 'compliance', impact: 3, likelihood: 2, score:  6, owner: '山口浩二',   status: 'open',      last_review: '2026-03-01', description: 'サーバールームへの不正アクセス',          mitigation_plan: '入退室管理強化' },
  { id: '18', name: 'DNSハイジャック',              category: 'network',    impact: 3, likelihood: 2, score:  6, owner: '宮崎彩花',   status: 'open',      last_review: '2026-03-14', description: 'DNS設定の改ざん',                         mitigation_plan: 'DNSSEC有効化' },
  { id: '19', name: '古い暗号化アルゴリズム',       category: 'data',       impact: 2, likelihood: 3, score:  6, owner: '田辺久',     status: 'accepted',  last_review: '2026-02-15', description: '弱い暗号化の使用',                        mitigation_plan: '暗号化標準移行計画策定' },
  { id: '20', name: 'ソーシャルエンジニアリング',   category: 'identity',   impact: 2, likelihood: 2, score:  4, owner: '村田由美',   status: 'open',      last_review: '2026-03-10', description: '人的操作による情報収集',                  mitigation_plan: 'セキュリティ教育強化' },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getHeatColor(score: number): { bg: string; border: string; label: string; text: string } {
  if (score <= 3)  return { bg: 'bg-emerald-900/60', border: 'border-emerald-700/60', label: '低', text: 'text-emerald-300' }
  if (score <= 8)  return { bg: 'bg-yellow-900/60',  border: 'border-yellow-700/60',  label: '中', text: 'text-yellow-300' }
  if (score <= 15) return { bg: 'bg-orange-900/60',  border: 'border-orange-700/60',  label: '高', text: 'text-orange-300' }
  return               { bg: 'bg-red-900/60',     border: 'border-red-700/60',     label: '重大', text: 'text-red-300' }
}

const CATEGORY_LABELS: Record<RiskCategory, string> = {
  endpoint: 'エンドポイント', network: 'ネットワーク',
  identity: 'アイデンティティ', data: 'データ', compliance: 'コンプライアンス',
}

const CATEGORY_COLORS: Record<RiskCategory, string> = {
  endpoint: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  network: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  identity: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  data: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
  compliance: 'bg-pink-500/20 text-pink-300 border-pink-500/30',
}

const STATUS_COLORS: Record<RiskStatus, string> = {
  open: 'bg-red-500/20 text-red-300 border-red-500/30',
  mitigated: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  accepted: 'bg-slate-500/20 text-slate-300 border-slate-500/30',
}

const STATUS_LABELS: Record<RiskStatus, string> = {
  open: 'オープン', mitigated: '緩和済み', accepted: '受容済み',
}

// ─── Add/Edit Modal ────────────────────────────────────────────────────────────

interface RiskFormData {
  name: string; category: RiskCategory; impact: number; likelihood: number
  description: string; owner: string; mitigation_plan: string
}

const defaultForm: RiskFormData = {
  name: '', category: 'endpoint', impact: 3, likelihood: 3,
  description: '', owner: '', mitigation_plan: '',
}

function RiskModal({
  initial, onClose, onSave,
}: {
  initial?: RiskItem | null
  onClose: () => void
  onSave: (data: RiskFormData) => void
}) {
  const [form, setForm] = useState<RiskFormData>(
    initial
      ? { name: initial.name, category: initial.category, impact: initial.impact, likelihood: initial.likelihood, description: initial.description, owner: initial.owner, mitigation_plan: initial.mitigation_plan }
      : defaultForm
  )

  const score = form.impact * form.likelihood
  const colors = getHeatColor(score)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-falcon-border">
          <h2 className="text-white font-semibold text-base">
            {initial ? 'リスク編集' : 'リスク追加'}
          </h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-4 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">リスク名 *</label>
            <input
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/60"
              placeholder="リスク名を入力..."
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            />
          </div>

          {/* Category */}
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">カテゴリ</label>
            <select
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/60"
              value={form.category}
              onChange={e => setForm(f => ({ ...f, category: e.target.value as RiskCategory }))}
            >
              {(Object.keys(CATEGORY_LABELS) as RiskCategory[]).map(c => (
                <option key={c} value={c}>{CATEGORY_LABELS[c]}</option>
              ))}
            </select>
          </div>

          {/* Impact slider */}
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">
              影響度: <span className="text-white font-semibold">{form.impact}</span>
            </label>
            <input type="range" min={1} max={5} value={form.impact}
              onChange={e => setForm(f => ({ ...f, impact: +e.target.value }))}
              className="w-full accent-falcon-red" />
            <div className="flex justify-between text-[10px] text-falcon-subtle mt-0.5">
              <span>1 (低)</span><span>5 (高)</span>
            </div>
          </div>

          {/* Likelihood slider */}
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">
              発生可能性: <span className="text-white font-semibold">{form.likelihood}</span>
            </label>
            <input type="range" min={1} max={5} value={form.likelihood}
              onChange={e => setForm(f => ({ ...f, likelihood: +e.target.value }))}
              className="w-full accent-falcon-red" />
            <div className="flex justify-between text-[10px] text-falcon-subtle mt-0.5">
              <span>1 (低)</span><span>5 (高)</span>
            </div>
          </div>

          {/* Score preview */}
          <div className={`flex items-center gap-3 px-3 py-2 rounded-lg border ${colors.bg} ${colors.border}`}>
            <span className="text-xs text-falcon-muted">リスクスコア:</span>
            <span className={`text-xl font-bold ${colors.text}`}>{score}</span>
            <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${colors.bg} ${colors.border} ${colors.text}`}>
              {colors.label}
            </span>
          </div>

          {/* Owner */}
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">担当者</label>
            <input
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/60"
              placeholder="担当者名..."
              value={form.owner}
              onChange={e => setForm(f => ({ ...f, owner: e.target.value }))}
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">説明</label>
            <textarea
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/60 resize-none"
              placeholder="リスクの説明..."
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            />
          </div>

          {/* Mitigation plan */}
          <div>
            <label className="block text-xs text-falcon-muted mb-1.5">緩和計画</label>
            <textarea
              rows={2}
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/60 resize-none"
              placeholder="緩和計画の詳細..."
              value={form.mitigation_plan}
              onChange={e => setForm(f => ({ ...f, mitigation_plan: e.target.value }))}
            />
          </div>
        </div>

        <div className="flex gap-3 px-6 py-4 border-t border-falcon-border">
          <button onClick={onClose}
            className="flex-1 px-4 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/40 transition-all text-sm">
            キャンセル
          </button>
          <button
            onClick={() => { if (form.name) { onSave(form); onClose() } }}
            className="flex-1 px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white font-medium transition-all text-sm disabled:opacity-50"
            disabled={!form.name}
          >
            {initial ? '更新' : '追加'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Cell Detail Panel ─────────────────────────────────────────────────────────

function CellPanel({ risks, impact, likelihood, onClose }: {
  risks: RiskItem[]; impact: number; likelihood: number; onClose: () => void
}) {
  const score = impact * likelihood
  const colors = getHeatColor(score)
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-falcon-border">
          <div className="flex items-center gap-2">
            <div className={`w-2.5 h-2.5 rounded-xs ${colors.bg} border ${colors.border}`} />
            <span className="text-white font-semibold text-sm">
              影響度 {impact} × 可能性 {likelihood} = スコア {score}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${colors.bg} ${colors.border} ${colors.text}`}>{colors.label}</span>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 space-y-2 max-h-72 overflow-y-auto">
          {risks.length === 0 ? (
            <p className="text-falcon-subtle text-sm text-center py-4">このセルにリスクはありません</p>
          ) : risks.map(r => (
            <div key={r.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#070d19] border border-falcon-border">
              <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${CATEGORY_COLORS[r.category]}`}>
                {CATEGORY_LABELS[r.category]}
              </span>
              <span className="flex-1 text-sm text-white truncate">{r.name}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${STATUS_COLORS[r.status]}`}>
                {STATUS_LABELS[r.status]}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function RiskHeatmapPage() {
  const qc = useQueryClient()
  const [filterCategory, setFilterCategory] = useState<string>('all')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [showModal, setShowModal] = useState(false)
  const [editItem, setEditItem] = useState<RiskItem | null>(null)
  const [cellPanel, setCellPanel] = useState<{ impact: number; likelihood: number } | null>(null)
  const [sortField, setSortField] = useState<keyof RiskItem>('score')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const { data: rawData, isError } = useQuery<{ items: RiskItem[] }>({
    queryKey: ['risk-items'],
    queryFn: () => apiFetch('/api/v1/reports/risk-items'),
    retry: 1,
  })

  const allRisks: RiskItem[] = useMemo(() => {
    if (isError || !rawData) return m(MOCK_RISKS)
    return rawData.items ?? m(MOCK_RISKS)
  }, [rawData, isError])

  const addMutation = useMutation({
    mutationFn: (data: RiskFormData) => apiFetch('/api/v1/reports/risk-items', {
      method: 'POST', body: JSON.stringify(data),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['risk-items'] }),
    onError: () => {},
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: RiskFormData }) =>
      apiFetch(`/api/v1/reports/risk-items/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['risk-items'] }),
    onError: () => {},
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/reports/risk-items/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['risk-items'] }),
    onError: () => {},
  })

  // Build heatmap counts
  const heatCounts = useMemo(() => {
    const map: Record<string, RiskItem[]> = {}
    for (let i = 1; i <= 5; i++) for (let l = 1; l <= 5; l++) map[`${i}-${l}`] = []
    allRisks.forEach(r => {
      const key = `${r.impact}-${r.likelihood}`
      if (map[key]) map[key].push(r)
    })
    return map
  }, [allRisks])

  const filtered = useMemo(() => {
    let list = [...allRisks]
    if (filterCategory !== 'all') list = list.filter(r => r.category === filterCategory)
    if (filterStatus !== 'all') list = list.filter(r => r.status === filterStatus)
    list.sort((a, b) => {
      const av = a[sortField] as number | string
      const bv = b[sortField] as number | string
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return list
  }, [allRisks, filterCategory, filterStatus, sortField, sortDir])

  const top5 = useMemo(() => [...allRisks].sort((a, b) => b.score - a.score).slice(0, 5), [allRisks])

  const handleSort = (field: keyof RiskItem) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const SortIcon = ({ field }: { field: keyof RiskItem }) =>
    sortField === field
      ? (sortDir === 'asc' ? <ChevronUp className="w-3 h-3 inline ml-0.5" /> : <ChevronDown className="w-3 h-3 inline ml-0.5" />)
      : null

  const handleSave = (data: RiskFormData) => {
    if (editItem) {
      updateMutation.mutate({ id: editItem.id, data })
    } else {
      addMutation.mutate(data)
    }
  }

  const cellRisks = cellPanel
    ? (heatCounts[`${cellPanel.impact}-${cellPanel.likelihood}`] ?? [])
    : []

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
            <Map className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">リスクヒートマップ</h1>
            <p className="text-xs text-falcon-muted mt-0.5">リスクの分布と優先度を可視化</p>
          </div>
        </div>
        <button
          onClick={() => { setEditItem(null); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-all"
        >
          <Plus className="w-4 h-4" />
          リスク追加
        </button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left: Heatmap + Legend */}
        <div className="xl:col-span-2 space-y-6">
          {/* Heatmap */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-4">リスクマトリクス</h2>

            <div className="flex gap-3">
              {/* Y-axis label */}
              <div className="flex flex-col items-center justify-center gap-1 w-6">
                <span className="text-[10px] text-falcon-muted writing-mode-vertical [writing-mode:vertical-rl] rotate-180 whitespace-nowrap">
                  影響度 →
                </span>
              </div>

              <div className="flex-1">
                {/* Grid: Y=impact 5→1, X=likelihood 1→5 */}
                <div className="space-y-1.5">
                  {[5, 4, 3, 2, 1].map(imp => (
                    <div key={imp} className="flex items-center gap-1.5">
                      <span className="w-4 text-center text-xs text-falcon-muted font-medium shrink-0">{imp}</span>
                      <div className="flex gap-1.5 flex-1">
                        {[1, 2, 3, 4, 5].map(lik => {
                          const cellScore = imp * lik
                          const colors = getHeatColor(cellScore)
                          const cellRisksHere = heatCounts[`${imp}-${lik}`] ?? []
                          return (
                            <button
                              key={lik}
                              onClick={() => setCellPanel({ impact: imp, likelihood: lik })}
                              className={`flex-1 aspect-square min-h-[52px] rounded-lg border ${colors.bg} ${colors.border}
                                         flex flex-col items-center justify-center gap-0.5
                                         hover:brightness-125 transition-all cursor-pointer group`}
                            >
                              <span className={`text-sm font-bold ${colors.text}`}>{cellScore}</span>
                              {cellRisksHere.length > 0 && (
                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-falcon-text/10 text-white leading-none">
                                  {cellRisksHere.length}件
                                </span>
                              )}
                            </button>
                          )
                        })}
                      </div>
                    </div>
                  ))}
                </div>

                {/* X-axis */}
                <div className="flex items-center gap-1.5 mt-2">
                  <div className="w-4 shrink-0" />
                  <div className="flex gap-1.5 flex-1">
                    {[1, 2, 3, 4, 5].map(l => (
                      <div key={l} className="flex-1 text-center text-xs text-falcon-muted">{l}</div>
                    ))}
                  </div>
                </div>
                <p className="text-center text-[11px] text-falcon-muted mt-1">← 発生可能性 →</p>
              </div>
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-3 mt-5 pt-4 border-t border-falcon-border">
              {[
                { label: '低 (1-3)',    bg: 'bg-emerald-900/60', border: 'border-emerald-700/60', text: 'text-emerald-300' },
                { label: '中 (4-8)',    bg: 'bg-yellow-900/60',  border: 'border-yellow-700/60',  text: 'text-yellow-300' },
                { label: '高 (9-15)',   bg: 'bg-orange-900/60',  border: 'border-orange-700/60',  text: 'text-orange-300' },
                { label: '重大 (16-25)',bg: 'bg-red-900/60',     border: 'border-red-700/60',     text: 'text-red-300' },
              ].map(c => (
                <div key={c.label} className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border ${c.bg} ${c.border}`}>
                  <div className={`w-2 h-2 rounded-xs ${c.bg} border ${c.border}`} />
                  <span className={`text-xs ${c.text}`}>{c.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl">
            <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-falcon-border">
              <h2 className="text-white font-semibold text-sm">リスク一覧</h2>
              <div className="flex flex-wrap items-center gap-2">
                <Filter className="w-3.5 h-3.5 text-falcon-muted" />
                <select
                  className="bg-[#070d19] border border-falcon-border rounded-lg px-2.5 py-1.5 text-xs text-falcon-muted focus:outline-hidden"
                  value={filterCategory}
                  onChange={e => setFilterCategory(e.target.value)}
                >
                  <option value="all">全カテゴリ</option>
                  {(Object.keys(CATEGORY_LABELS) as RiskCategory[]).map(c => (
                    <option key={c} value={c}>{CATEGORY_LABELS[c]}</option>
                  ))}
                </select>
                <select
                  className="bg-[#070d19] border border-falcon-border rounded-lg px-2.5 py-1.5 text-xs text-falcon-muted focus:outline-hidden"
                  value={filterStatus}
                  onChange={e => setFilterStatus(e.target.value)}
                >
                  <option value="all">全ステータス</option>
                  {(Object.keys(STATUS_LABELS) as RiskStatus[]).map(s => (
                    <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[800px]">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {[
                      { label: 'リスク名', field: 'name' as keyof RiskItem },
                      { label: 'カテゴリ', field: 'category' as keyof RiskItem },
                      { label: '影響度', field: 'impact' as keyof RiskItem },
                      { label: '可能性', field: 'likelihood' as keyof RiskItem },
                      { label: 'スコア', field: 'score' as keyof RiskItem },
                      { label: '担当者', field: 'owner' as keyof RiskItem },
                      { label: 'ステータス', field: 'status' as keyof RiskItem },
                      { label: '最終レビュー', field: 'last_review' as keyof RiskItem },
                    ].map(col => (
                      <th
                        key={col.field}
                        onClick={() => handleSort(col.field)}
                        className="px-4 py-3 text-left text-xs text-falcon-muted font-medium cursor-pointer hover:text-white transition-colors whitespace-nowrap"
                      >
                        {col.label} <SortIcon field={col.field} />
                      </th>
                    ))}
                    <th className="px-4 py-3 text-left text-xs text-falcon-muted font-medium">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(risk => {
                    const colors = getHeatColor(risk.score)
                    return (
                      <tr key={risk.id} className="border-b border-falcon-border/60 hover:bg-[#070d19]/60 transition-colors">
                        <td className="px-4 py-3 text-white text-xs font-medium max-w-[180px] truncate">{risk.name}</td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${CATEGORY_COLORS[risk.category]}`}>
                            {CATEGORY_LABELS[risk.category]}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className="text-xs text-white font-semibold">{risk.impact}</span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className="text-xs text-white font-semibold">{risk.likelihood}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${colors.bg} ${colors.border} ${colors.text}`}>
                            {risk.score}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{risk.owner}</td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${STATUS_COLORS[risk.status]}`}>
                            {STATUS_LABELS[risk.status]}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{risk.last_review}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1.5">
                            <button
                              onClick={() => { setEditItem(risk); setShowModal(true) }}
                              className="p-1.5 rounded-md bg-falcon-border/60 hover:bg-falcon-border text-falcon-muted hover:text-white transition-all"
                            >
                              <Edit2 className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => deleteMutation.mutate(risk.id)}
                              className="p-1.5 rounded-md bg-red-900/30 hover:bg-red-900/60 text-red-400 hover:text-red-300 transition-all"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {filtered.length === 0 && (
                <div className="text-center py-12 text-falcon-subtle text-sm">
                  条件に合うリスクが見つかりません
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right: Top 5 */}
        <div className="space-y-4">
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-falcon-red" />
              <h2 className="text-white font-semibold text-sm">Top 5 高リスク</h2>
            </div>
            <div className="space-y-3">
              {top5.map((risk, idx) => {
                const colors = getHeatColor(risk.score)
                const pct = (risk.score / 25) * 100
                return (
                  <div key={risk.id} className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-falcon-border flex items-center justify-center text-[10px] font-bold text-falcon-muted shrink-0">
                        {idx + 1}
                      </span>
                      <span className="flex-1 text-xs text-white font-medium truncate">{risk.name}</span>
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${colors.bg} ${colors.border} ${colors.text}`}>
                        {risk.score}
                      </span>
                    </div>
                    <div className="ml-7 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${
                          risk.score >= 16 ? 'bg-red-500' :
                          risk.score >= 9  ? 'bg-orange-500' :
                          risk.score >= 4  ? 'bg-yellow-500' : 'bg-emerald-500'
                        }`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <div className="ml-7 flex items-center gap-2">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${CATEGORY_COLORS[risk.category]}`}>
                        {CATEGORY_LABELS[risk.category]}
                      </span>
                      <span className="text-[10px] text-falcon-subtle">{risk.owner}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Stats cards */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: '総リスク数',   value: allRisks.length,                                         color: 'text-white' },
              { label: 'オープン',     value: allRisks.filter(r => r.status === 'open').length,        color: 'text-red-400' },
              { label: '緩和済み',     value: allRisks.filter(r => r.status === 'mitigated').length,   color: 'text-emerald-400' },
              { label: '重大リスク',   value: allRisks.filter(r => r.score >= 16).length,              color: 'text-orange-400' },
            ].map(stat => (
              <div key={stat.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4 text-center">
                <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
                <div className="text-[11px] text-falcon-muted mt-0.5">{stat.label}</div>
              </div>
            ))}
          </div>

          {/* Category breakdown */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h2 className="text-white font-semibold text-sm mb-4">カテゴリ別分布</h2>
            <div className="space-y-2.5">
              {(Object.keys(CATEGORY_LABELS) as RiskCategory[]).map(cat => {
                const count = allRisks.filter(r => r.category === cat).length
                const pct = allRisks.length > 0 ? (count / allRisks.length) * 100 : 0
                return (
                  <div key={cat} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-falcon-muted">{CATEGORY_LABELS[cat]}</span>
                      <span className="text-white font-medium">{count}件</span>
                    </div>
                    <div className="h-1.5 bg-falcon-border rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-falcon-red transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Modals */}
      {showModal && (
        <RiskModal
          initial={editItem}
          onClose={() => { setShowModal(false); setEditItem(null) }}
          onSave={handleSave}
        />
      )}
      {cellPanel && (
        <CellPanel
          risks={cellRisks}
          impact={cellPanel.impact}
          likelihood={cellPanel.likelihood}
          onClose={() => setCellPanel(null)}
        />
      )}
    </div>
  )
}
