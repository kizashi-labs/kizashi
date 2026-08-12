'use client'

import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Fingerprint, Plus, Trash2, Edit2, X, RefreshCw,
  Play, ToggleLeft, ToggleRight, Filter, Eye,
  Shield, AlertTriangle, CheckCircle, Clock, ChevronRight,
  BarChart3, Link as LinkIcon, Sliders
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────

type PatternType = 'sequence' | 'cluster' | 'anomaly' | 'recurring'
type Severity = 'low' | 'medium' | 'high' | 'critical'
type MatchStatus = 'new' | 'reviewed' | 'actioned' | 'false_positive'

interface Condition {
  id: string
  field: string
  operator: string
  value: string
  logic: 'AND' | 'OR'
}

interface IncidentPattern {
  id: string
  name: string
  description: string
  pattern_type: PatternType
  severity: Severity
  confidence_threshold: number
  conditions: Condition[]
  match_count: number
  is_active: boolean
  created_at: string
  updated_at: string
}

interface PatternMatch {
  id: string
  pattern_id: string
  pattern_name: string
  pattern_type: PatternType
  confidence: number
  matched_incident_ids: string[]
  summary: string
  status: MatchStatus
  recommended_actions: string[]
  matched_conditions: string[]
  created_at: string
}

// ── Helpers ──────────────────────────────────────────────────────

const PATTERN_TYPE_STYLES: Record<PatternType, { label: string; bg: string; text: string }> = {
  sequence:  { label: 'シーケンス', bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  cluster:   { label: 'クラスター', bg: 'bg-purple-900/40', text: 'text-purple-300' },
  anomaly:   { label: '異常検知',   bg: 'bg-orange-900/40', text: 'text-orange-300' },
  recurring: { label: '繰り返し',   bg: 'bg-green-900/40',  text: 'text-green-300' },
}

const SEVERITY_STYLES: Record<Severity, { bg: string; text: string; label: string }> = {
  low:      { bg: 'bg-gray-800',      text: 'text-gray-300',   label: '低' },
  medium:   { bg: 'bg-yellow-900/50', text: 'text-yellow-300', label: '中' },
  high:     { bg: 'bg-orange-900/50', text: 'text-orange-300', label: '高' },
  critical: { bg: 'bg-red-900/50',    text: 'text-red-300',    label: '重大' },
}

const MATCH_STATUS_STYLES: Record<MatchStatus, { bg: string; text: string; label: string }> = {
  new:            { bg: 'bg-yellow-900/40', text: 'text-yellow-300', label: '新規' },
  reviewed:       { bg: 'bg-blue-900/40',   text: 'text-blue-300',   label: 'レビュー済' },
  actioned:       { bg: 'bg-green-900/40',  text: 'text-green-300',  label: '対応済' },
  false_positive: { bg: 'bg-gray-800',      text: 'text-gray-400',   label: '誤検知' },
}

function fmt(ts: string) {
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ── Condition Builder ────────────────────────────────────────────

function ConditionBuilder({ conditions, onChange }: { conditions: Condition[]; onChange: (c: Condition[]) => void }) {
  const addCondition = () => {
    onChange([...conditions, { id: `c-${Date.now()}`, field: 'event.type', operator: 'equals', value: '', logic: 'AND' }])
  }
  const removeCondition = (id: string) => onChange(conditions.filter(c => c.id !== id))
  const updateCondition = (id: string, key: keyof Condition, val: string) =>
    onChange(conditions.map(c => c.id === id ? { ...c, [key]: val } : c))

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <label className="text-[#7d92b0] text-xs">条件</label>
        <button onClick={addCondition} className="text-[#e8002d] text-xs flex items-center gap-1 hover:text-[#e8002d]/80">
          <Plus className="w-3 h-3" /> 追加
        </button>
      </div>
      {conditions.map((c, i) => (
        <div key={c.id} className="flex items-center gap-2 mb-2">
          {i > 0 && (
            <select value={c.logic} onChange={e => updateCondition(c.id, 'logic', e.target.value)}
              className="w-14 bg-[#070d19] border border-[#1e2d42] rounded px-1 py-1.5 text-xs text-[#7d92b0] focus:outline-none">
              <option value="AND">AND</option>
              <option value="OR">OR</option>
            </select>
          )}
          {i === 0 && <div className="w-14" />}
          <input value={c.field} onChange={e => updateCondition(c.id, 'field', e.target.value)}
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-xs text-white focus:outline-none"
            placeholder="フィールド" />
          <select value={c.operator} onChange={e => updateCondition(c.id, 'operator', e.target.value)}
            className="w-28 bg-[#070d19] border border-[#1e2d42] rounded px-1 py-1.5 text-xs text-[#7d92b0] focus:outline-none">
            {['equals', 'not_equals', 'contains', 'not_contains', 'greater_than', 'less_than', 'in', 'between', 'exists'].map(op => (
              <option key={op} value={op}>{op}</option>
            ))}
          </select>
          <input value={c.value} onChange={e => updateCondition(c.id, 'value', e.target.value)}
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-xs text-white focus:outline-none"
            placeholder="値" />
          <button onClick={() => removeCondition(c.id)} className="text-[#7d92b0] hover:text-[#e8002d]"><X className="w-3 h-3" /></button>
        </div>
      ))}
    </div>
  )
}

// ── Pattern Modal ────────────────────────────────────────────────

function PatternModal({ pattern, onClose, onSave }: { pattern?: IncidentPattern; onClose: () => void; onSave: (data: Partial<IncidentPattern>) => void }) {
  const [form, setForm] = useState<Partial<IncidentPattern>>(pattern ?? {
    name: '', description: '', pattern_type: 'sequence', severity: 'medium', confidence_threshold: 75, conditions: [], is_active: true,
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">{pattern ? 'パターンを編集' : 'パターンを追加'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[#7d92b0] text-xs block mb-1">パターン名</label>
            <input className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              value={form.name ?? ''} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs block mb-1">説明</label>
            <textarea rows={2} className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 resize-none"
              value={form.description ?? ''} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">パターンタイプ</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none"
                value={form.pattern_type} onChange={e => setForm(f => ({ ...f, pattern_type: e.target.value as PatternType }))}>
                {Object.entries(PATTERN_TYPE_STYLES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs block mb-1">重要度</label>
              <select className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none"
                value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value as Severity }))}>
                {Object.entries(SEVERITY_STYLES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs block mb-1">信頼度閾値: {form.confidence_threshold}%</label>
            <input type="range" min={0} max={100} value={form.confidence_threshold ?? 75}
              onChange={e => setForm(f => ({ ...f, confidence_threshold: Number(e.target.value) }))}
              className="w-full accent-[#e8002d]" />
          </div>
          <ConditionBuilder
            conditions={form.conditions ?? []}
            onChange={conditions => setForm(f => ({ ...f, conditions }))}
          />
          <div className="flex items-center gap-3">
            <label className="text-[#7d92b0] text-xs">有効</label>
            <button onClick={() => setForm(f => ({ ...f, is_active: !f.is_active }))}
              className={`w-10 h-5 rounded-full transition-colors ${form.is_active ? 'bg-green-500' : 'bg-[#1e2d42]'}`}>
              <div className={`w-4 h-4 bg-[#e2e8f4] rounded-full transition-transform mx-0.5 ${form.is_active ? 'translate-x-5' : 'translate-x-0'}`} />
            </button>
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 border border-[#1e2d42] rounded text-[#7d92b0] hover:text-white text-sm">キャンセル</button>
          <button onClick={() => onSave(form)} className="px-4 py-2 bg-[#e8002d] rounded text-white text-sm hover:bg-[#e8002d]/80">保存</button>
        </div>
      </div>
    </div>
  )
}

// ── Match Detail Modal ───────────────────────────────────────────

function MatchDetail({ match, onClose, onStatusChange }: { match: PatternMatch; onClose: () => void; onStatusChange: (id: string, status: MatchStatus) => void }) {
  const typeStyle = PATTERN_TYPE_STYLES[match.pattern_type]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-2">
            <Fingerprint className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">マッチ詳細</h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${typeStyle.bg} ${typeStyle.text}`}>{typeStyle.label}</span>
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${MATCH_STATUS_STYLES[match.status].bg} ${MATCH_STATUS_STYLES[match.status].text}`}>{MATCH_STATUS_STYLES[match.status].label}</span>
            </div>
            <h3 className="text-white font-semibold">{match.pattern_name}</h3>
          </div>

          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">信頼度スコア</p>
            <div className="flex items-center gap-3">
              <div className="flex-1 bg-[#1e2d42] rounded-full h-3">
                <div className={`h-3 rounded-full transition-all ${match.confidence >= 80 ? 'bg-[#e8002d]' : match.confidence >= 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                  style={{ width: `${match.confidence}%` }} />
              </div>
              <span className="text-white font-bold">{match.confidence}%</span>
            </div>
          </div>

          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">サマリー</p>
            <p className="text-[#7d92b0] text-sm leading-relaxed bg-[#070d19] rounded p-3">{match.summary}</p>
          </div>

          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">マッチしたインシデント ({match.matched_incident_ids.length}件)</p>
            <div className="flex flex-wrap gap-2">
              {match.matched_incident_ids.map(id => (
                <span key={id} className="flex items-center gap-1 px-2 py-1 bg-[#1e2d42] rounded text-xs text-blue-300 font-mono">
                  <LinkIcon className="w-3 h-3" />{id}
                </span>
              ))}
            </div>
          </div>

          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">マッチした条件</p>
            <div className="space-y-1">
              {match.matched_conditions.map((cond, i) => (
                <div key={i} className="flex items-center gap-2 bg-[#070d19] rounded px-3 py-1.5">
                  <CheckCircle className="w-3 h-3 text-green-400 flex-shrink-0" />
                  <span className="text-[#7d92b0] font-mono text-xs">{cond}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">推奨アクション</p>
            <div className="space-y-1">
              {match.recommended_actions.map((action, i) => (
                <div key={i} className="flex items-start gap-2 bg-[#070d19] rounded px-3 py-1.5">
                  <ChevronRight className="w-3 h-3 text-[#e8002d] flex-shrink-0 mt-0.5" />
                  <span className="text-[#7d92b0] text-xs">{action}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">ステータス更新</p>
            <div className="flex flex-wrap gap-2">
              {(Object.keys(MATCH_STATUS_STYLES) as MatchStatus[]).map(status => (
                <button key={status} onClick={() => { onStatusChange(match.id, status); onClose() }}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition-all ${match.status === status ? `${MATCH_STATUS_STYLES[status].bg} ${MATCH_STATUS_STYLES[status].text} ring-1 ring-white/20` : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {MATCH_STATUS_STYLES[status].label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function IncidentPatternsPage() {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<'patterns' | 'matches'>('patterns')
  const [selectedMatch, setSelectedMatch] = useState<PatternMatch | null>(null)
  const [editingPattern, setEditingPattern] = useState<IncidentPattern | undefined>(undefined)
  const [showPatternModal, setShowPatternModal] = useState(false)
  const [filterPattern, setFilterPattern] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterMinConf, setFilterMinConf] = useState(0)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeResult, setAnalyzeResult] = useState<string | null>(null)
  const [toast, setToast] = useState('')

  const { data: patternsData } = useQuery<IncidentPattern[]>({
    queryKey: ['incident-patterns'],
    queryFn: async () => {
      try {
        const res: any = await apiFetch('/api/v1/admin/incident-patterns/patterns')
        return Array.isArray(res) ? res : res?.patterns ?? []
      } catch { return [] as IncidentPattern[] }
    },
  })

  const { data: matchesData } = useQuery<PatternMatch[]>({
    queryKey: ['incident-matches'],
    queryFn: async () => {
      try {
        const res: any = await apiFetch('/api/v1/admin/incident-patterns/matches')
        return Array.isArray(res) ? res : res?.matches ?? []
      } catch { return [] as PatternMatch[] }
    },
  })

  const patterns = Array.isArray(patternsData) ? patternsData : []
  const matches = Array.isArray(matchesData) ? matchesData : []

  const toggleMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/incident-patterns/patterns/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['incident-patterns'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/incident-patterns/patterns/${id}`, { method: 'DELETE' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['incident-patterns'] }); setToast('パターンを削除しました') },
  })

  const saveMutation = useMutation({
    mutationFn: (data: Partial<IncidentPattern>) => editingPattern
      ? apiFetch(`/api/v1/admin/incident-patterns/patterns/${editingPattern.id}`, { method: 'PUT', body: JSON.stringify(data) })
      : apiFetch('/api/v1/admin/incident-patterns/patterns', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['incident-patterns'] }); setShowPatternModal(false); setEditingPattern(undefined); setToast('パターンを保存しました') },
    onError: () => { setToast('パターンの保存に失敗しました') },
  })

  const runAnalysis = async () => {
    setAnalyzing(true)
    setAnalyzeResult(null)
    try {
      // Use the real analysis result instead of a fabricated random count.
      const res = await apiFetch<{ match_count?: number; patterns_evaluated?: number }>(
        '/api/v1/admin/incident-patterns/analyze',
        { method: 'POST' },
      )
      const count = res?.match_count ?? 0
      const evaluated = res?.patterns_evaluated ?? 0
      if (evaluated === 0) {
        setAnalyzeResult('有効なパターンが未定義です。先にパターンを作成してください。')
      } else {
        setAnalyzeResult(`${count}件の新しいマッチを検出（${evaluated}個のパターンを評価）`)
      }
      queryClient.invalidateQueries({ queryKey: ['incident-matches'] })
      queryClient.invalidateQueries({ queryKey: ['incident-patterns'] })
    } catch (e) {
      // バックエンドが準備中(503)の場合はそのメッセージをそのまま表示する。
      setAnalyzeResult((e as Error)?.message || '分析の実行に失敗しました')
    } finally {
      setAnalyzing(false)
    }
  }

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: MatchStatus }) =>
      apiFetch(`/api/v1/admin/incident-patterns/matches/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['incident-matches'] }); setToast('ステータスを更新しました') },
    onError: () => setToast('ステータスの更新に失敗しました'),
  })

  const handleStatusChange = (id: string, status: MatchStatus) => statusMutation.mutate({ id, status })

  const activePatterns = patterns.filter(p => p.is_active).length
  const monthlyMatches = matches.filter(m => Date.now() - new Date(m.created_at).getTime() < 30 * 86_400_000).length
  const confirmedPatterns = patterns.filter(p => p.match_count > 0).length

  const filteredMatches = matches.filter(m => {
    if (filterPattern && m.pattern_id !== filterPattern) return false
    if (filterStatus && m.status !== filterStatus) return false
    if (m.confidence < filterMinConf) return false
    return true
  })

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <Fingerprint className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">インシデントパターン認識</h1>
              <p className="text-[#7d92b0] text-sm">AIによる攻撃パターンの自動検出と関連付け</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {analyzeResult && (
              <div className="flex items-center gap-2 px-3 py-2 bg-green-900/30 border border-green-500/30 rounded-lg">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-green-300 text-sm font-medium">{analyzeResult}</span>
              </div>
            )}
            <button onClick={runAnalysis} disabled={analyzing}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 rounded-lg text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors">
              {analyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {analyzing ? '分析中...' : 'パターン分析を実行'}
            </button>
            <button onClick={() => { setEditingPattern(undefined); setShowPatternModal(true) }}
              className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] rounded-lg text-white text-sm font-medium hover:bg-[#e8002d]/80 transition-colors">
              <Plus className="w-4 h-4" /> パターンを追加
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: '総パターン数', value: patterns.length, icon: Fingerprint, color: 'text-blue-400' },
            { label: 'アクティブ', value: activePatterns, icon: CheckCircle, color: 'text-green-400' },
            { label: '今月のマッチ', value: monthlyMatches, icon: BarChart3, color: 'text-yellow-400' },
            { label: '確認済みパターン', value: confirmedPatterns, icon: Shield, color: 'text-[#e8002d]' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <p className="text-[#7d92b0] text-xs">{label}</p>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex border-b border-[#1e2d42]">
          {([['patterns', 'パターン定義'], ['matches', 'マッチ結果']] as const).map(([key, label]) => (
            <button key={key} onClick={() => setTab(key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === key ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'
              }`}>{label}</button>
          ))}
        </div>

        {/* Patterns Tab */}
        {tab === 'patterns' && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-[#070d19] border-b border-[#1e2d42]">
                  <tr>
                    {['パターン名', 'タイプ', '重要度', '信頼度閾値', 'マッチ数', '有効', '操作'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {patterns.map(pattern => {
                    const typeStyle = PATTERN_TYPE_STYLES[pattern.pattern_type]
                    const sevStyle = SEVERITY_STYLES[pattern.severity]
                    return (
                      <tr key={pattern.id} className="border-t border-[#1e2d42] hover:bg-[#070d19]/50">
                        <td className="px-4 py-3">
                          <p className="text-white font-medium">{pattern.name}</p>
                          <p className="text-[#7d92b0] text-xs mt-0.5 truncate max-w-[240px]">{pattern.description}</p>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${typeStyle.bg} ${typeStyle.text}`}>{typeStyle.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${sevStyle.bg} ${sevStyle.text}`}>{sevStyle.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 bg-[#1e2d42] rounded-full h-1.5">
                              <div className="bg-[#e8002d] h-1.5 rounded-full" style={{ width: `${pattern.confidence_threshold}%` }} />
                            </div>
                            <span className="text-[#7d92b0] text-xs">{pattern.confidence_threshold}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-white font-semibold">{pattern.match_count}</td>
                        <td className="px-4 py-3">
                          <button onClick={() => toggleMutation.mutate(pattern.id)}
                            className={`w-10 h-5 rounded-full transition-colors ${pattern.is_active ? 'bg-green-500' : 'bg-[#1e2d42]'}`}>
                            <div className={`w-4 h-4 bg-[#e2e8f4] rounded-full transition-transform mx-0.5 ${pattern.is_active ? 'translate-x-5' : 'translate-x-0'}`} />
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button onClick={() => { setEditingPattern(pattern); setShowPatternModal(true) }}
                              className="text-[#7d92b0] hover:text-white"><Edit2 className="w-4 h-4" /></button>
                            <button onClick={() => deleteMutation.mutate(pattern.id)}
                              className="text-[#7d92b0] hover:text-[#e8002d]"><Trash2 className="w-4 h-4" /></button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Matches Tab */}
        {tab === 'matches' && (
          <div className="space-y-4">
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3">
              <Filter className="w-4 h-4 text-[#7d92b0]" />
              <select value={filterPattern} onChange={e => setFilterPattern(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-[#7d92b0] text-xs focus:outline-none">
                <option value="">全パターン</option>
                {patterns.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1.5 text-[#7d92b0] text-xs focus:outline-none">
                <option value="">全ステータス</option>
                {Object.entries(MATCH_STATUS_STYLES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
              <div className="flex items-center gap-2">
                <Sliders className="w-3 h-3 text-[#7d92b0]" />
                <span className="text-[#7d92b0] text-xs">最低確信度:</span>
                <input type="range" min={0} max={100} value={filterMinConf} onChange={e => setFilterMinConf(Number(e.target.value))}
                  className="w-24 accent-[#e8002d]" />
                <span className="text-[#7d92b0] text-xs">{filterMinConf}%</span>
              </div>
              <span className="text-[#7d92b0] text-xs ml-auto">{filteredMatches.length}件</span>
            </div>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-[#070d19] border-b border-[#1e2d42]">
                    <tr>
                      {['パターン', '確信度', 'インシデント数', 'サマリー', 'ステータス', '検出日時', '詳細'].map(h => (
                        <th key={h} className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredMatches.map(match => {
                      const statusStyle = MATCH_STATUS_STYLES[match.status]
                      return (
                        <tr key={match.id} className="border-t border-[#1e2d42] hover:bg-[#070d19]/50">
                          <td className="px-4 py-3">
                            <p className="text-white text-sm font-medium">{match.pattern_name}</p>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${PATTERN_TYPE_STYLES[match.pattern_type].bg} ${PATTERN_TYPE_STYLES[match.pattern_type].text}`}>
                              {PATTERN_TYPE_STYLES[match.pattern_type].label}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <div className="w-16 bg-[#1e2d42] rounded-full h-2">
                                <div className={`h-2 rounded-full ${match.confidence >= 80 ? 'bg-[#e8002d]' : match.confidence >= 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                                  style={{ width: `${match.confidence}%` }} />
                              </div>
                              <span className="text-white text-xs font-semibold">{match.confidence}%</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-white font-semibold">{match.matched_incident_ids.length}</td>
                          <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-[220px]">
                            <span className="line-clamp-2">{match.summary}</span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusStyle.bg} ${statusStyle.text}`}>{statusStyle.label}</span>
                          </td>
                          <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{fmt(match.created_at)}</td>
                          <td className="px-4 py-3">
                            <button onClick={() => setSelectedMatch(match)}
                              className="flex items-center gap-1 px-2 py-1 border border-[#1e2d42] rounded text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 text-xs transition-colors">
                              <Eye className="w-3 h-3" /> 詳細
                            </button>
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
      </div>

      {/* Modals */}
      {showPatternModal && (
        <PatternModal pattern={editingPattern} onClose={() => { setShowPatternModal(false); setEditingPattern(undefined) }} onSave={data => saveMutation.mutate(data)} />
      )}
      {selectedMatch && (
        <MatchDetail match={selectedMatch} onClose={() => setSelectedMatch(null)} onStatusChange={handleStatusChange} />
      )}

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0d1220] border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400" />
          <span className="text-white text-sm">{toast}</span>
          <button onClick={() => setToast('')} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
