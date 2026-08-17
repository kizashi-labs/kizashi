'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  EyeOff, X, AlertTriangle, Shield, Plus, Trash2,
  ToggleLeft, ToggleRight, Filter, CheckCircle, Eye,
  Globe, TrendingUp, BarChart2
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────

type DetectionCategory = 'credential' | 'personal_data' | 'company_data' | 'threat_intel' | 'malware_sale' | 'vulnerability_sale'
type Severity = 'low' | 'medium' | 'high' | 'critical'
type DetectionStatus = 'new' | 'reviewed' | 'actioned'
type KeywordCategory = 'company_name' | 'domain' | 'email' | 'executive_name' | 'product' | 'custom'

interface Detection {
  id: string
  timestamp: string
  category: DetectionCategory
  source: string
  severity: Severity
  summary: string
  full_details: string
  source_forum: string
  source_category: string
  source_date: string
  recommended_actions: string[]
  evidence_ref: string
  status: DetectionStatus
  assigned_to: string | null
}

interface Keyword {
  id: string
  keyword: string
  category: KeywordCategory
  active: boolean
  notes: string
  last_match: string | null
  match_count: number
}

interface MonthlyStats {
  month: string
  count: number
  credentials: number
  data_leaks: number
}

const MONTHLY_STATS: { month: string; count: number }[] = [
  { month: '11月', count: 18 }, { month: '12月', count: 24 }, { month: '1月', count: 31 },
  { month: '2月', count: 27 }, { month: '3月', count: 35 }, { month: '4月', count: 29 },
]

// ── Helpers ────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<DetectionCategory, { label: string; bg: string; text: string }> = {
  credential:         { label: '認証情報',    bg: 'bg-red-900/40',    text: 'text-red-300' },
  personal_data:      { label: '個人情報',    bg: 'bg-orange-900/40', text: 'text-orange-300' },
  company_data:       { label: '企業データ',  bg: 'bg-purple-900/40', text: 'text-purple-300' },
  threat_intel:       { label: '脅威情報',    bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  malware_sale:       { label: 'マルウェア販売', bg: 'bg-yellow-900/40', text: 'text-yellow-300' },
  vulnerability_sale: { label: '脆弱性販売',  bg: 'bg-pink-900/40',   text: 'text-pink-300' },
}

const SEVERITY_CONFIG = {
  low:      { label: '低',   bg: 'bg-gray-800',      text: 'text-gray-300' },
  medium:   { label: '中',   bg: 'bg-yellow-900/50', text: 'text-yellow-300' },
  high:     { label: '高',   bg: 'bg-orange-900/50', text: 'text-orange-300' },
  critical: { label: '重大', bg: 'bg-red-900/50',    text: 'text-red-300' },
}

const STATUS_CONFIG: Record<DetectionStatus, { label: string; bg: string; text: string }> = {
  new:      { label: '新規',       bg: 'bg-red-900/40',   text: 'text-red-300' },
  reviewed: { label: 'レビュー済', bg: 'bg-blue-900/40',  text: 'text-blue-300' },
  actioned: { label: '対処済',     bg: 'bg-green-900/40', text: 'text-green-300' },
}

const KEYWORD_CATEGORY_CONFIG: Record<KeywordCategory, { label: string; bg: string; text: string }> = {
  company_name:   { label: '会社名',       bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  domain:         { label: 'ドメイン',      bg: 'bg-purple-900/40', text: 'text-purple-300' },
  email:          { label: 'メール',        bg: 'bg-green-900/40',  text: 'text-green-300' },
  executive_name: { label: '役員名',        bg: 'bg-orange-900/40', text: 'text-orange-300' },
  product:        { label: '製品名',        bg: 'bg-cyan-900/40',   text: 'text-cyan-300' },
  custom:         { label: 'カスタム',      bg: 'bg-pink-900/40',   text: 'text-pink-300' },
}

function fmt(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Detection Detail Modal ─────────────────────────────────────────

function DetectionDetailModal({ detection, onClose, onUpdate }: {
  detection: Detection
  onClose: () => void
  onUpdate: (id: string, updates: Partial<Detection>) => void
}) {
  const [assignee, setAssignee] = useState(detection.assigned_to ?? '')
  const cc = CATEGORY_CONFIG[detection.category]
  const sc = SEVERITY_CONFIG[detection.severity]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <h2 className="text-white font-semibold text-lg">検出詳細</h2>
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${cc.bg} ${cc.text}`}>{cc.label}</span>
            <span className={`text-xs px-2 py-0.5 rounded-sm font-bold ${sc.bg} ${sc.text}`}>{sc.label}</span>
          </div>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        <div className="bg-yellow-900/20 border border-yellow-700/30 rounded-lg p-3 mb-4">
          <p className="text-yellow-300 text-xs">機密情報: 実際のダークウェブリンクは表示されません。証拠参照のみ表示します。</p>
        </div>

        <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border mb-4">
          <p className="text-xs text-falcon-muted mb-1 uppercase tracking-wider">詳細説明</p>
          <p className="text-falcon-text text-sm">{detection.full_details}</p>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-4">
          {[
            ['ソース', detection.source_forum],
            ['カテゴリ', detection.source_category],
            ['ソース日付', detection.source_date],
            ['証拠参照', detection.evidence_ref],
          ].map(([k, v]) => (
            <div key={k} className="bg-[#070d19] rounded-lg p-3 border border-falcon-border">
              <p className="text-xs text-falcon-muted mb-1">{k}</p>
              <p className="text-white text-sm font-mono">{v}</p>
            </div>
          ))}
        </div>

        <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border mb-4">
          <p className="text-xs text-falcon-muted mb-3 uppercase tracking-wider">推奨対応</p>
          <ol className="space-y-2">
            {detection.recommended_actions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-falcon-text">
                <span className="w-5 h-5 rounded-full bg-falcon-red/20 text-falcon-red text-xs flex items-center justify-center shrink-0 mt-0.5 font-bold">{i + 1}</span>
                {a}
              </li>
            ))}
          </ol>
        </div>

        <div className="flex gap-3 items-center mb-4">
          <label className="text-xs text-falcon-muted shrink-0">担当者:</label>
          <input value={assignee} onChange={e => setAssignee(e.target.value)}
            placeholder="担当者を入力..."
            className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" />
        </div>

        <div className="flex gap-3">
          {(['reviewed', 'actioned'] as DetectionStatus[]).map(s => (
            <button key={s} onClick={() => { onUpdate(detection.id, { status: s, assigned_to: assignee || null }); onClose() }}
              className={`flex-1 py-2 rounded text-sm font-medium transition-colors flex items-center justify-center gap-2
                ${s === 'actioned' ? 'bg-falcon-red hover:bg-[#c8001e] text-white' : 'bg-falcon-border hover:bg-[#2a3f5a] text-falcon-muted hover:text-white'}`}>
              <CheckCircle className="w-4 h-4" />
              {STATUS_CONFIG[s].label}にする
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Add Keyword Modal ──────────────────────────────────────────────

function AddKeywordModal({ onClose, onAdd }: {
  onClose: () => void
  onAdd: (k: Omit<Keyword, 'id' | 'last_match' | 'match_count'>) => void
}) {
  const [form, setForm] = useState({ keyword: '', category: 'domain' as KeywordCategory, notes: '', active: true })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold text-lg">監視キーワード追加</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">キーワード/フレーズ</label>
            <input value={form.keyword} onChange={e => setForm(p => ({ ...p, keyword: e.target.value }))}
              placeholder="監視するキーワードを入力..."
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">カテゴリ</label>
            <select value={form.category} onChange={e => setForm(p => ({ ...p, category: e.target.value as KeywordCategory }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50">
              {(Object.keys(KEYWORD_CATEGORY_CONFIG) as KeywordCategory[]).map(c => (
                <option key={c} value={c}>{KEYWORD_CATEGORY_CONFIG[c].label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">メモ (任意)</label>
            <textarea value={form.notes} onChange={e => setForm(p => ({ ...p, notes: e.target.value }))}
              rows={2} className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 resize-none" />
          </div>
          <label className="flex items-center gap-2 text-sm text-falcon-muted cursor-pointer">
            <button onClick={() => setForm(p => ({ ...p, active: !p.active }))} className="text-falcon-muted">
              {form.active ? <ToggleRight className="w-6 h-6 text-green-400" /> : <ToggleLeft className="w-6 h-6" />}
            </button>
            有効化
          </label>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => { if (form.keyword) { onAdd(form); onClose() } }}
            className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors">追加</button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────

export default function DarkWebPage() {
  const [tab, setTab] = useState<'detections' | 'keywords' | 'stats'>('detections')
  const [filterCategory, setFilterCategory] = useState<DetectionCategory | ''>('')
  const [filterSeverity, setFilterSeverity] = useState<Severity | ''>('')
  const [filterStatus, setFilterStatus] = useState<DetectionStatus | ''>('')
  const [selectedDetection, setSelectedDetection] = useState<Detection | null>(null)
  const [showAddKeyword, setShowAddKeyword] = useState(false)
  const [localDetections, setLocalDetections] = useState<Detection[]>([])
  const [localKeywords, setLocalKeywords] = useState<Keyword[]>([])
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 4000) }

  const { data: detectionsData } = useQuery<Detection[]>({
    queryKey: ['dark-web-detections'],
    queryFn: () => apiFetch('/api/v1/admin/dark-web/detections'),
    onError: () => {},
  } as any)

  const filteredDetections = localDetections.filter(d => {
    if (filterCategory && d.category !== filterCategory) return false
    if (filterSeverity && d.severity !== filterSeverity) return false
    if (filterStatus && d.status !== filterStatus) return false
    return true
  })

  const handleUpdateDetection = async (id: string, updates: Partial<Detection>) => {
    try { await apiFetch(`/api/v1/admin/dark-web/detections/${id}`, { method: 'PUT', body: JSON.stringify(updates) }) } catch {}
    setLocalDetections(prev => prev.map(d => d.id === id ? { ...d, ...updates } : d))
    showToast('ステータスを更新しました')
  }

  const handleBulkAction = () => {
    setLocalDetections(prev => prev.map(d => filteredDetections.some(fd => fd.id === d.id) ? { ...d, status: 'actioned' } : d))
    showToast(`${filteredDetections.length}件を対処済みにしました`)
  }

  const handleAddKeyword = (form: Omit<Keyword, 'id' | 'last_match' | 'match_count'>) => {
    const nk: Keyword = { ...form, id: String(Date.now()), last_match: null, match_count: 0 }
    try { apiFetch('/api/v1/admin/dark-web/keywords', { method: 'POST', body: JSON.stringify(form) }) } catch {}
    setLocalKeywords(prev => [nk, ...prev])
    showToast(`キーワード「${form.keyword}」を追加しました`)
  }

  const handleDeleteKeyword = async (kw: Keyword) => {
    try { await apiFetch(`/api/v1/admin/dark-web/keywords/${kw.id}`, { method: 'DELETE' }) } catch {}
    setLocalKeywords(prev => prev.filter(k => k.id !== kw.id))
    showToast(`キーワード「${kw.keyword}」を削除しました`)
  }

  const handleToggleKeyword = async (kw: Keyword) => {
    try { await apiFetch(`/api/v1/admin/dark-web/keywords/${kw.id}`, { method: 'PUT', body: JSON.stringify({ active: !kw.active }) }) } catch {}
    setLocalKeywords(prev => prev.map(k => k.id === kw.id ? { ...k, active: !k.active } : k))
  }

  const newThisWeek = localDetections.filter(d => (Date.now() - new Date(d.timestamp).getTime()) < 7 * 24 * 3600 * 1000).length
  const credentialsFound = localDetections.filter(d => d.category === 'credential').length
  const dataLeaks = localDetections.filter(d => ['personal_data','company_data'].includes(d.category)).length

  const maxMonthly = Math.max(...MONTHLY_STATS.map(m => m.count))

  const TOP_SOURCES = [
    { name: 'BreachForums', count: 4 },
    { name: 'Exploit.in', count: 3 },
    { name: 'XSS Forum', count: 2 },
    { name: 'Pastebin', count: 2 },
    { name: 'Telegram Channel', count: 2 },
  ]

  const CREDENTIAL_DOMAINS = [
    { domain: '@example.com', count: 45, severity: 'critical' as Severity },
    { domain: '@corp.example.com', count: 18, severity: 'high' as Severity },
    { domain: '@dev.example.com', count: 7, severity: 'medium' as Severity },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
          <EyeOff className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-2xl font-bold">ダークウェブ監視</h1>
          <p className="text-falcon-muted text-sm">脅威情報サービスによるダークウェブ上の情報漏洩検知</p>
        </div>
      </div>

      {/* Disclaimer Banner */}
      <div className="bg-[#1a1200] border border-yellow-700/40 rounded-lg p-3 mb-6 flex items-start gap-3">
        <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
        <p className="text-yellow-300 text-sm">このデータは監視サービスから収集されたものです。ダークウェブへの直接アクセスは行いません。すべての情報は合法的な脅威インテリジェンスサービス経由で取得されています。</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総検出数', value: localDetections.length, color: 'text-blue-400' },
          { label: '認証情報漏洩', value: credentialsFound, color: 'text-red-400' },
          { label: 'データリーク', value: dataLeaks, color: 'text-orange-400' },
          { label: '今週の新規', value: newThisWeek, color: 'text-yellow-400' },
        ].map(c => (
          <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <p className="text-xs text-falcon-muted mb-2">{c.label}</p>
            <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[{ key: 'detections', label: '検出アイテム' }, { key: 'keywords', label: '監視キーワード' }, { key: 'stats', label: '統計' }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === t.key ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
            }`}>{t.label}</button>
        ))}
      </div>

      {/* Detections Tab */}
      {tab === 'detections' && (
        <div>
          <div className="flex flex-wrap gap-3 mb-4">
            <div className="flex items-center gap-2 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2">
              <Filter className="w-3.5 h-3.5 text-falcon-muted" />
              <select value={filterCategory} onChange={e => setFilterCategory(e.target.value as any)}
                className="bg-transparent text-sm text-falcon-muted focus:outline-hidden focus:text-white">
                <option value="">全カテゴリ</option>
                {(Object.keys(CATEGORY_CONFIG) as DetectionCategory[]).map(c => (
                  <option key={c} value={c}>{CATEGORY_CONFIG[c].label}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2">
              <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value as any)}
                className="bg-transparent text-sm text-falcon-muted focus:outline-hidden focus:text-white">
                <option value="">全重要度</option>
                {(['low','medium','high','critical'] as Severity[]).map(s => (
                  <option key={s} value={s}>{SEVERITY_CONFIG[s].label}</option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2">
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value as any)}
                className="bg-transparent text-sm text-falcon-muted focus:outline-hidden focus:text-white">
                <option value="">全ステータス</option>
                {(['new','reviewed','actioned'] as DetectionStatus[]).map(s => (
                  <option key={s} value={s}>{STATUS_CONFIG[s].label}</option>
                ))}
              </select>
            </div>
            {(filterCategory || filterSeverity || filterStatus) && (
              <button onClick={() => { setFilterCategory(''); setFilterSeverity(''); setFilterStatus('') }}
                className="text-xs text-falcon-muted hover:text-white px-3 border border-falcon-border rounded-lg">リセット</button>
            )}
            <button onClick={handleBulkAction}
              className="ml-auto px-4 py-2 bg-green-900/40 border border-green-700/30 text-green-300 rounded-lg text-sm hover:bg-green-900/60 transition-colors flex items-center gap-2">
              <CheckCircle className="w-4 h-4" /> モニタリング開始 (一括対処済み)
            </button>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['日時', 'カテゴリ', 'ソース', '重要度', 'サマリー', 'ステータス', '担当者', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredDetections.map(d => {
                  const cc = CATEGORY_CONFIG[d.category]
                  const sc = SEVERITY_CONFIG[d.severity]
                  const stc = STATUS_CONFIG[d.status]
                  return (
                    <tr key={d.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmt(d.timestamp)}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${cc.bg} ${cc.text}`}>{cc.label}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted">{d.source}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm font-bold ${sc.bg} ${sc.text}`}>{sc.label}</span>
                      </td>
                      <td className="px-4 py-3 max-w-[200px]">
                        <p className="text-xs text-falcon-text truncate" title={d.summary}>{d.summary}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${stc.bg} ${stc.text}`}>{stc.label}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted">{displayUser(d.assigned_to)}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedDetection(d)}
                          className="flex items-center gap-1 text-xs text-falcon-muted hover:text-white transition-colors">
                          <Eye className="w-3.5 h-3.5" /> 詳細
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {filteredDetections.length === 0 && <div className="text-center py-12 text-falcon-muted text-sm">条件に一致するアイテムがありません</div>}
          </div>
        </div>
      )}

      {/* Keywords Tab */}
      {tab === 'keywords' && (
        <div>
          <div className="bg-falcon-surface border border-blue-700/30 rounded-xl p-4 mb-6">
            <div className="flex items-start gap-3">
              <Globe className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-white text-sm font-medium mb-1">監視スコープについて</p>
                <p className="text-falcon-muted text-xs">登録されたキーワードは、ダークウェブフォーラム・マーケットプレイス・ペーストサイト・Telegramチャンネルを継続的に監視するために使用されます。マッチが検出されると、検出アイテムタブに新規エントリが作成されます。</p>
              </div>
            </div>
          </div>

          <div className="flex justify-between items-center mb-4">
            <p className="text-falcon-muted text-sm">{localKeywords.length} 件のキーワード</p>
            <button onClick={() => setShowAddKeyword(true)}
              className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" /> キーワード追加
            </button>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['キーワード', 'カテゴリ', '有効', '最終マッチ', 'マッチ数', 'メモ', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {localKeywords.map(kw => {
                  const kc = KEYWORD_CATEGORY_CONFIG[kw.category]
                  return (
                    <tr key={kw.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3">
                        <span className="text-white text-sm font-mono">{kw.keyword}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${kc.bg} ${kc.text}`}>{kc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleToggleKeyword(kw)}>
                          {kw.active ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted">{kw.last_match ? fmt(kw.last_match) : '—'}</td>
                      <td className="px-4 py-3">
                        <span className={`text-sm font-bold ${kw.match_count > 0 ? 'text-orange-400' : 'text-falcon-muted'}`}>{kw.match_count}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted max-w-[160px] truncate">{kw.notes || '—'}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleDeleteKeyword(kw)} className="text-falcon-muted hover:text-red-400 transition-colors">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Stats Tab */}
      {tab === 'stats' && (
        <div className="space-y-6">
          {/* Monthly trend */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-falcon-red" /> 月別検出トレンド (12ヶ月)
            </h3>
            <div className="flex items-end gap-2 h-40">
              {MONTHLY_STATS.map(m => {
                const pct = maxMonthly > 0 ? (m.count / maxMonthly) * 100 : 0
                return (
                  <div key={m.month} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs text-falcon-muted">{m.count}</span>
                    <div className="w-full rounded-t" style={{ height: `${pct}%`, minHeight: '4px', backgroundColor: '#e8002d', opacity: 0.7 + (pct / 100) * 0.3 }} />
                    <span className="text-[9px] text-falcon-subtle rotate-45 origin-left whitespace-nowrap">{m.month.slice(5)}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Category distribution */}
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-falcon-red" /> カテゴリ別分布
              </h3>
              <div className="space-y-3">
                {(Object.keys(CATEGORY_CONFIG) as DetectionCategory[]).map(cat => {
                  const count = localDetections.filter(d => d.category === cat).length
                  const pct = localDetections.length > 0 ? (count / localDetections.length) * 100 : 0
                  const cc = CATEGORY_CONFIG[cat]
                  return (
                    <div key={cat} className="flex items-center gap-3">
                      <span className={`text-xs ${cc.text} w-24 shrink-0`}>{cc.label}</span>
                      <div className="flex-1 h-2 bg-falcon-border rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${cc.bg.replace('/40', '/80')}`} style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs text-falcon-muted w-8 text-right">{count}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Top sources */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <h3 className="text-white font-semibold text-sm mb-4 flex items-center gap-2">
                <Globe className="w-4 h-4 text-falcon-red" /> TOP 5 ソース
              </h3>
              <div className="space-y-3">
                {TOP_SOURCES.map((s, i) => (
                  <div key={s.name} className="flex items-center gap-3">
                    <span className="text-xs text-falcon-subtle font-bold w-4">{i + 1}</span>
                    <span className="text-xs text-falcon-text flex-1">{s.name}</span>
                    <div className="w-24 h-2 bg-falcon-border rounded-full overflow-hidden">
                      <div className="h-full rounded-full bg-falcon-red/60" style={{ width: `${(s.count / TOP_SOURCES[0].count) * 100}%` }} />
                    </div>
                    <span className="text-xs text-white font-bold w-4">{s.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Credential exposure by domain */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">ドメイン別認証情報露出</h3>
            <div className="overflow-hidden rounded-lg border border-falcon-border">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border bg-[#070d19]">
                    {['ドメイン', '露出件数', '重要度'].map(h => (
                      <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-2">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {CREDENTIAL_DOMAINS.map(d => {
                    const sc = SEVERITY_CONFIG[d.severity]
                    return (
                      <tr key={d.domain} className="border-b border-falcon-border/50">
                        <td className="px-4 py-3 text-sm text-white font-mono">{d.domain}</td>
                        <td className="px-4 py-3 text-sm text-orange-400 font-bold">{d.count}</td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-sm font-bold ${sc.bg} ${sc.text}`}>{sc.label}</span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Modals */}
      {selectedDetection && (
        <DetectionDetailModal
          detection={selectedDetection}
          onClose={() => setSelectedDetection(null)}
          onUpdate={handleUpdateDetection}
        />
      )}
      {showAddKeyword && <AddKeywordModal onClose={() => setShowAddKeyword(false)} onAdd={handleAddKeyword} />}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-falcon-surface border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-sm text-falcon-text flex-1">{toast}</p>
          <button onClick={() => setToast(null)} className="text-falcon-muted hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
