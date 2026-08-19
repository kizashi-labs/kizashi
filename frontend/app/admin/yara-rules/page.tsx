'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  FileSearch, Plus, Pencil, Trash2, Play, ToggleLeft, ToggleRight,
  Search, Filter, Download, RefreshCw, X, AlertTriangle, CheckCircle,
  Shield, Bug, Zap, Package, Terminal, ChevronLeft, ChevronRight,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { VerdictUnavailable } from '@/components/VerdictUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type Category = 'malware' | 'ransomware' | 'apt' | 'pup' | 'exploit'

interface YaraRule {
  id: string
  name: string
  description: string
  category: Category
  severity: number
  enabled: boolean
  match_count: number
  last_scan: string
  rule_content: string
}

interface ScanResult {
  id: string
  rule_name: string
  agent: string
  file_path: string
  matched_strings: string
  scanned_at: string
}

interface TestResult {
  matched: boolean
  matched_strings: string[]
  rule_name: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<Category, { label: string; className: string; icon: React.ReactNode }> = {
  malware:    { label: 'マルウェア',   className: 'bg-red-500/15 text-red-400 border-red-500/30',       icon: <Bug className="w-3 h-3" /> },
  ransomware: { label: 'ランサムウェア', className: 'bg-orange-500/15 text-orange-400 border-orange-500/30', icon: <Shield className="w-3 h-3" /> },
  apt:        { label: 'APT',          className: 'bg-purple-500/15 text-purple-400 border-purple-500/30', icon: <Zap className="w-3 h-3" /> },
  pup:        { label: 'PUP',          className: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30', icon: <Package className="w-3 h-3" /> },
  exploit:    { label: 'エクスプロイト', className: 'bg-blue-500/15 text-blue-400 border-blue-500/30',   icon: <Terminal className="w-3 h-3" /> },
}

const CategoryBadge = ({ category }: { category: Category }) => {
  const cfg = CATEGORY_CONFIG[category] ?? CATEGORY_CONFIG['malware']
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[11px] font-medium border ${cfg.className}`}>
      {cfg.icon}
      {cfg.label}
    </span>
  )
}

function severityToString(n: number): string {
  if (n >= 90) return 'critical'
  if (n >= 75) return 'high'
  if (n >= 50) return 'medium'
  return 'low'
}

function severityToNum(s: string | number): number {
  if (typeof s === 'number') return s
  switch (s) {
    case 'critical': return 95
    case 'high': return 80
    case 'medium': return 60
    default: return 30
  }
}

const SeverityBadge = ({ severity }: { severity: number }) => {
  let label = '低'
  let cls = 'bg-blue-500/15 text-blue-400 border-blue-500/30'
  if (severity >= 90) { label = 'クリティカル'; cls = 'bg-red-500/15 text-red-400 border-red-500/30' }
  else if (severity >= 75) { label = '高'; cls = 'bg-orange-500/15 text-orange-400 border-orange-500/30' }
  else if (severity >= 50) { label = '中'; cls = 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[11px] font-medium border ${cls}`}>
      <AlertTriangle className="w-3 h-3" />
      {label} ({severity})
    </span>
  )
}

const EMPTY_RULE: Partial<YaraRule> = {
  name: '', description: '', category: 'malware', severity: 70, enabled: true,
  rule_content: `rule ExampleRule {
  strings:
    $a = "example"
  condition:
    $a
}`,
}

// ─── Main Component ───────────────────────────────────────────────────────────

const TABS = ['ルール一覧', 'スキャン結果'] as const
type Tab = typeof TABS[number]

const CATEGORIES: Category[] = ['malware', 'ransomware', 'apt', 'pup', 'exploit']

export default function YaraRulesPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<Tab>('ルール一覧')

  // Filters for rule list
  const [selectedCategories, setSelectedCategories] = useState<Set<Category>>(new Set())
  const [enabledFilter, setEnabledFilter] = useState<'all' | 'enabled' | 'disabled'>('all')
  const [severityMin, setSeverityMin] = useState(0)

  // Modals
  const [showAddModal, setShowAddModal] = useState(false)
  const [editRule, setEditRule] = useState<YaraRule | null>(null)
  const [testRule, setTestRule] = useState<YaraRule | null>(null)
  const [testContent, setTestContent] = useState('')
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<YaraRule | null>(null)

  // Form state
  const [form, setForm] = useState<Partial<YaraRule>>(EMPTY_RULE)

  // Scan result filters
  const [scanRuleFilter, setScanRuleFilter] = useState('all')
  const [scanAgentFilter, setScanAgentFilter] = useState('')
  const [scanDateFrom, setScanDateFrom] = useState('')
  const [scanDateTo, setScanDateTo] = useState('')

  const [page, setPage] = useState(1)
  const perPage = 50

  // API queries — フィルター条件をサーバー側に渡してページ全体から検索
  const { data: rulesData, isLoading: rulesLoading } = useQuery<{ data: YaraRule[], total: number }>({
    queryKey: ['yara-rules', enabledFilter, severityMin, page],
    queryFn: async () => {
      const params = new URLSearchParams()
      params.set('limit', String(perPage))
      params.set('offset', String((page - 1) * perPage))
      if (enabledFilter === 'enabled') params.set('enabled', 'true')
      if (enabledFilter === 'disabled') params.set('enabled', 'false')
      const res = await apiFetch(`/api/v1/yara-rules?${params}`) as { data: any[], total: number }
      return {
        ...res,
        data: (res.data ?? []).map((r: any) => {
          const validCategories: Category[] = ['malware', 'ransomware', 'apt', 'pup', 'exploit']
          const cat = validCategories.find(c => r.category === c || (r.tags ?? []).includes(c)) ?? 'malware'
          return { ...r, severity: severityToNum(r.severity), rule_content: r.rule_content ?? r.content ?? '', category: cat, match_count: r.last_match_count ?? 0, last_scan: r.last_matched_at ?? r.updated_at ?? '' }
        }),
      }
    },
    staleTime: 30_000,
    retry: false,
  })

  const rules = rulesData?.data ?? []
  const totalRules = rulesData?.total ?? 0

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: Partial<YaraRule>) => apiFetch('/api/v1/yara-rules', {
      method: 'POST',
      body: JSON.stringify({ ...data, severity: severityToString(data.severity ?? 70), content: data.rule_content, tags: [data.category ?? 'malware'] }),
    }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['yara-rules'] }); setShowAddModal(false); setForm(EMPTY_RULE) },
    onError: () => { setShowAddModal(false); setForm(EMPTY_RULE) },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, ...data }: Partial<YaraRule> & { id: string }) =>
      apiFetch(`/api/v1/yara-rules/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ ...data, severity: severityToString(data.severity ?? 70), content: data.rule_content, tags: [data.category ?? 'malware'] }),
      }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['yara-rules'] }); setEditRule(null) },
    onError: () => setEditRule(null),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/yara-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['yara-rules'] }); setDeleteConfirm(null) },
    onError: () => setDeleteConfirm(null),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/yara-rules/${id}/toggle`, { method: 'PATCH' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['yara-rules'] }),
    onError: () => queryClient.invalidateQueries({ queryKey: ['yara-rules'] }),
  })

  const testMutation = useMutation({
    mutationFn: ({ id, content }: { id: string; content: string }) =>
      apiFetch(`/api/v1/yara-rules/${id}/test`, { method: 'POST', body: JSON.stringify({ content }) }),
    onSuccess: (data) => { setTestError(null); setTestResult(data as TestResult) },
    onError: (e) => {
      // ここは Math.random() > 0.5 でした。YARA ルールが検体にマッチするかを
      // 確かめる機能が、確かめられなかったときにコイン投げの判定を返し、
      // 根拠として '$s1 at 0x10' '$s2 at 0x4A' というオフセットまで
      // 添えていました。存在しない一致位置です。
      setTestResult(null)
      setTestError(e instanceof Error ? e.message : '不明なエラー')
    },
  })

  // enabled/severity はサーバー側でフィルタリング済み。カテゴリのみクライアント側でフィルタ
  const filteredRules = rules.filter(r => {
    if (selectedCategories.size > 0 && !selectedCategories.has(r.category)) return false
    if (r.severity < severityMin) return false
    return true
  })

  // Filtered scan results
  const filteredScans = ([] as ScanResult[]).filter(s => {
    if (scanRuleFilter !== 'all' && s.rule_name !== scanRuleFilter) return false
    if (scanAgentFilter && !s.agent.toLowerCase().includes(scanAgentFilter.toLowerCase())) return false
    if (scanDateFrom && new Date(s.scanned_at) < new Date(scanDateFrom)) return false
    if (scanDateTo && new Date(s.scanned_at) > new Date(scanDateTo + 'T23:59:59Z')) return false
    return true
  })

  const toggleCategory = (cat: Category) => {
    setSelectedCategories(prev => {
      const next = new Set(prev)
      if (next.has(cat)) next.delete(cat)
      else next.add(cat)
      return next
    })
  }

  const openEdit = (rule: YaraRule) => {
    setEditRule(rule)
    setForm({ ...rule })
  }

  const openTest = (rule: YaraRule) => {
    setTestRule(rule)
    setTestContent('')
    setTestResult(null)
    setTestError(null)
  }

  const handleFormSubmit = () => {
    if (editRule) {
      updateMutation.mutate({ ...form, id: editRule.id } as Partial<YaraRule> & { id: string })
    } else {
      createMutation.mutate(form)
    }
  }

  const exportCSV = () => {
    const headers = ['Rule Name', 'Agent', 'File Path', 'Matched Strings', 'Scanned At']
    const rows = filteredScans.map(s => [s.rule_name, s.agent, s.file_path, s.matched_strings, s.scanned_at])
    const csv = [headers, ...rows].map(r => r.map(c => `"${c}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'yara_scan_results.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  // Stats
  const stats = {
    total: totalRules,  // APIのtotal（DB全件数）を使用
    enabled: rules.filter(r => r.enabled).length,
    totalMatches: rules.reduce((s, r) => s + r.match_count, 0),
    categories: new Set(rules.map(r => r.category)).size,
  }

  // ── Modal: Add/Edit Rule ───────────────────────────────────────────────────

  const RuleModal = () => (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h3 className="text-[#e2e8f4] font-semibold text-lg">
            {editRule ? 'YARAルール編集' : '新規YARAルール追加'}
          </h3>
          <button onClick={() => { setShowAddModal(false); setEditRule(null) }} className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">ルール名 *</label>
              <input
                value={form.name ?? ''}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#7d92b0]/50"
                placeholder="MyCustomRule"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">カテゴリ</label>
              <select
                value={form.category ?? 'malware'}
                onChange={e => setForm(f => ({ ...f, category: e.target.value as Category }))}
                className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#7d92b0]/50"
              >
                {CATEGORIES.map(c => (
                  <option key={c} value={c}>{CATEGORY_CONFIG[c].label}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">説明</label>
            <input
              value={form.description ?? ''}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#7d92b0]/50"
              placeholder="ルールの説明..."
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-2">
              深刻度: <span className="text-[#e2e8f4] font-semibold">{form.severity ?? 70}</span>
            </label>
            <input
              type="range"
              min={0}
              max={100}
              value={form.severity ?? 70}
              onChange={e => setForm(f => ({ ...f, severity: Number(e.target.value) }))}
              className="w-full accent-[#e8002d]"
            />
            <div className="flex justify-between text-[10px] text-[#3d5068] mt-1">
              <span>低 (0)</span><span>中 (50)</span><span>高 (75)</span><span>クリティカル (90+)</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-[#7d92b0]">有効化</label>
            <button
              onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}
              className={`transition-colors ${form.enabled ? 'text-green-400' : 'text-[#3d5068]'}`}
            >
              {form.enabled ? <ToggleRight className="w-6 h-6" /> : <ToggleLeft className="w-6 h-6" />}
            </button>
            <span className="text-xs text-[#7d92b0]">{form.enabled ? '有効' : '無効'}</span>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
              YARAルールコンテンツ
              <span className="ml-2 text-[#3d5068] font-normal">
                — ヒント: <code className="font-mono bg-[#1e2d42] px-1 rounded-sm">{'rule ExampleRule { strings: $a = "example" condition: $a }'}</code>
              </span>
            </label>
            <textarea
              value={form.rule_content ?? ''}
              onChange={e => setForm(f => ({ ...f, rule_content: e.target.value }))}
              rows={12}
              className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] font-mono focus:outline-hidden focus:border-[#7d92b0]/50 resize-none"
              spellCheck={false}
            />
          </div>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42] flex items-center justify-end gap-3">
          <button
            onClick={() => { setShowAddModal(false); setEditRule(null) }}
            className="px-4 py-2 rounded-sm text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={handleFormSubmit}
            disabled={!form.name}
            className="px-4 py-2 rounded-sm text-sm bg-[#e8002d] text-white font-medium hover:bg-[#c0001f] disabled:opacity-50 transition-colors"
          >
            {editRule ? '保存' : '追加'}
          </button>
        </div>
      </div>
    </div>
  )

  // ── Modal: Test Rule ───────────────────────────────────────────────────────

  const TestModal = () => (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h3 className="text-[#e2e8f4] font-semibold">ルールテスト: {testRule?.name}</h3>
          <button onClick={() => setTestRule(null)} className="text-[#7d92b0] hover:text-[#e2e8f4]">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">テスト対象コンテンツ</label>
            <textarea
              value={testContent}
              onChange={e => setTestContent(e.target.value)}
              rows={6}
              placeholder="スキャンするファイルの内容またはバイナリデータのテキスト表現を入力してください..."
              className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] font-mono placeholder-[#3d5068] focus:outline-hidden focus:border-[#7d92b0]/50 resize-none"
            />
          </div>

          {testError && (
            <div className="mt-4">
              <VerdictUnavailable what="ルールのテスト" detail={testError} />
            </div>
          )}
          {testResult && (
            <div className={`rounded-lg p-4 border ${testResult.matched ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'}`}>
              <div className="flex items-center gap-2 mb-2">
                {testResult.matched
                  ? <AlertTriangle className="w-5 h-5 text-red-400" />
                  : <CheckCircle className="w-5 h-5 text-green-400" />
                }
                <span className={`font-semibold ${testResult.matched ? 'text-red-400' : 'text-green-400'}`}>
                  {testResult.matched ? 'マッチしました' : 'マッチなし'}
                </span>
              </div>
              {testResult.matched && testResult.matched_strings.length > 0 && (
                <div>
                  <p className="text-xs text-[#7d92b0] mb-1">マッチした文字列:</p>
                  <div className="space-y-1">
                    {testResult.matched_strings.map((s, i) => (
                      <code key={i} className="block text-xs text-red-300 font-mono bg-[#070d19] px-2 py-1 rounded-sm">
                        {s}
                      </code>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="flex items-center justify-end gap-3">
            <button onClick={() => setTestRule(null)} className="px-4 py-2 rounded-sm text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
              閉じる
            </button>
            <button
              onClick={() => testRule && testMutation.mutate({ id: testRule.id, content: testContent })}
              disabled={!testContent || testMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 rounded-sm text-sm bg-blue-600 text-white font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {testMutation.isPending ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              テスト実行
            </button>
          </div>
        </div>
      </div>
    </div>
  )

  // ── Modal: Delete Confirm ──────────────────────────────────────────────────

  const DeleteModal = () => (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-sm">
        <div className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-full bg-red-500/15 flex items-center justify-center">
              <Trash2 className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h3 className="text-[#e2e8f4] font-semibold">ルールを削除</h3>
              <p className="text-[#7d92b0] text-sm">{deleteConfirm?.name}</p>
            </div>
          </div>
          <p className="text-[#7d92b0] text-sm mb-6">
            このYARAルールを削除しますか？この操作は取り消せません。
          </p>
          <div className="flex items-center justify-end gap-3">
            <button onClick={() => setDeleteConfirm(null)} className="px-4 py-2 rounded-sm text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
              キャンセル
            </button>
            <button
              onClick={() => deleteConfirm && deleteMutation.mutate(deleteConfirm.id)}
              className="px-4 py-2 rounded-sm text-sm bg-red-600 text-white font-medium hover:bg-red-700 transition-colors"
            >
              削除
            </button>
          </div>
        </div>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Modals */}
      {(showAddModal || editRule) && <RuleModal />}
      {testRule && <TestModal />}
      {deleteConfirm && <DeleteModal />}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-[#e2e8f4] flex items-center gap-2">
            <FileSearch className="w-7 h-7 text-[#e8002d]" />
            YARAルール管理
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">
            YARAルールの作成・管理・テストおよびスキャン結果の確認
          </p>
        </div>
        {activeTab === 'ルール一覧' && (
          <button
            onClick={() => { setForm(EMPTY_RULE); setShowAddModal(true) }}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white font-medium hover:bg-[#c0001f] transition-colors text-sm"
          >
            <Plus className="w-4 h-4" />
            ルール追加
          </button>
        )}
        {activeTab === 'スキャン結果' && (
          <button
            onClick={exportCSV}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 transition-colors text-sm"
          >
            <Download className="w-4 h-4" />
            CSV出力
          </button>
        )}
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'ルール総数', value: stats.total, color: 'text-blue-400' },
          { label: '有効ルール', value: stats.enabled, color: 'text-green-400' },
          { label: '総マッチ数', value: (stats.totalMatches ?? 0).toLocaleString(), color: 'text-orange-400' },
          { label: 'カテゴリ数', value: stats.categories, color: 'text-purple-400' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            <p className="text-[#7d92b0] text-xs mt-1">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 border-b border-[#1e2d42]">
        {TABS.map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab
                ? 'border-[#e8002d] text-[#e2e8f4]'
                : 'border-transparent text-[#7d92b0] hover:text-[#e2e8f4]'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* ── Tab: ルール一覧 ─────────────────────────────────────────────────── */}
      {activeTab === 'ルール一覧' && (
        <div className="flex gap-6">
          {/* Filter Sidebar */}
          <div className="w-52 shrink-0 space-y-5">
            <div>
              <h4 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">カテゴリ</h4>
              <div className="space-y-1.5">
                {CATEGORIES.map(cat => (
                  <label key={cat} className="flex items-center gap-2 cursor-pointer group">
                    <input
                      type="checkbox"
                      checked={selectedCategories.has(cat)}
                      onChange={() => toggleCategory(cat)}
                      className="w-3.5 h-3.5 rounded-sm border-[#1e2d42] bg-[#070d19] accent-[#e8002d]"
                    />
                    <span className="text-sm text-[#7d92b0] group-hover:text-[#e2e8f4] transition-colors flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        cat === 'malware' ? 'bg-red-400' :
                        cat === 'ransomware' ? 'bg-orange-400' :
                        cat === 'apt' ? 'bg-purple-400' :
                        cat === 'pup' ? 'bg-yellow-400' : 'bg-blue-400'
                      }`} />
                      {CATEGORY_CONFIG[cat].label}
                    </span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">
                深刻度: <span className="text-[#e2e8f4]">{severityMin}+</span>
              </h4>
              <input
                type="range"
                min={0}
                max={100}
                step={10}
                value={severityMin}
                onChange={e => setSeverityMin(Number(e.target.value))}
                className="w-full accent-[#e8002d]"
              />
              <div className="flex justify-between text-[10px] text-[#3d5068] mt-1">
                <span>0</span><span>50</span><span>100</span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-2">状態</h4>
              <div className="space-y-1">
                {[['all', '全て'], ['enabled', '有効のみ'], ['disabled', '無効のみ']].map(([val, label]) => (
                  <button
                    key={val}
                    onClick={() => { setEnabledFilter(val as typeof enabledFilter); setPage(1) }}
                    className={`w-full text-left px-3 py-1.5 rounded-sm text-sm transition-colors ${
                      enabledFilter === val
                        ? 'bg-[#1d2f4a] text-white'
                        : 'text-[#7d92b0] hover:bg-[#19253d] hover:text-[#e2e8f4]'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {(selectedCategories.size > 0 || enabledFilter !== 'all' || severityMin > 0) && (
              <button
                onClick={() => { setSelectedCategories(new Set()); setEnabledFilter('all'); setSeverityMin(0) }}
                className="w-full text-xs text-[#e8002d] hover:text-red-300 transition-colors text-left"
              >
                フィルタをリセット
              </button>
            )}
          </div>

          {/* Rules Grid */}
          <div className="flex-1 space-y-3">
            {rulesLoading && (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="w-6 h-6 text-[#7d92b0] animate-spin" />
              </div>
            )}
            {filteredRules.length === 0 && !rulesLoading && (
              <div className="text-center py-12 text-[#7d92b0]">
                <FileSearch className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p>条件に一致するルールが見つかりません</p>
              </div>
            )}
            {filteredRules.map(rule => (
              <div key={rule.id} className={`bg-[#0d1220] border rounded-lg p-5 transition-all ${rule.enabled ? 'border-[#1e2d42]' : 'border-[#1e2d42] opacity-70'}`}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1.5">
                      <h4 className="text-[#e2e8f4] font-semibold font-mono text-sm">{rule.name}</h4>
                      <CategoryBadge category={rule.category} />
                      <SeverityBadge severity={rule.severity} />
                      {!rule.enabled && (
                        <span className="px-2 py-0.5 rounded-sm text-[10px] bg-[#1e2d42] text-[#3d5068] border border-[#1e2d42]">
                          無効
                        </span>
                      )}
                    </div>
                    <p className="text-[#7d92b0] text-xs mb-3">{rule.description}</p>
                    <div className="flex items-center gap-4 text-xs text-[#7d92b0]">
                      <span>マッチ数: <span className="text-[#e2e8f4] font-medium">{(rule.match_count ?? 0).toLocaleString()}</span></span>
                      <span>最終スキャン: <span className="text-[#e2e8f4]">{new Date(rule.last_scan).toLocaleString('ja-JP')}</span></span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => toggleMutation.mutate(rule.id)}
                      className={`transition-colors ${rule.enabled ? 'text-green-400 hover:text-green-300' : 'text-[#3d5068] hover:text-[#7d92b0]'}`}
                      title={rule.enabled ? '無効化' : '有効化'}
                    >
                      {rule.enabled ? <ToggleRight className="w-6 h-6" /> : <ToggleLeft className="w-6 h-6" />}
                    </button>
                    <button
                      onClick={() => openTest(rule)}
                      className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-blue-400 transition-colors"
                      title="テスト"
                    >
                      <Play className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => openEdit(rule)}
                      className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                      title="編集"
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setDeleteConfirm(rule)}
                      className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-red-400 transition-colors"
                      title="削除"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}

            {/* ページネーション */}
            {totalRules > perPage && (
              <div className="flex items-center justify-between pt-3 border-t border-[#1e2d42]">
                <span className="text-xs text-[#7d92b0]">
                  {((page - 1) * perPage) + 1}–{Math.min(page * perPage, totalRules)} / {totalRules.toLocaleString()}件
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="p-1.5 rounded-sm bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-white disabled:opacity-30 transition-colors"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <span className="text-xs text-[#7d92b0] font-mono">
                    {page} / {Math.ceil(totalRules / perPage)}
                  </span>
                  <button
                    onClick={() => setPage(p => Math.min(Math.ceil(totalRules / perPage), p + 1))}
                    disabled={page >= Math.ceil(totalRules / perPage)}
                    className="p-1.5 rounded-sm bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-white disabled:opacity-30 transition-colors"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Tab: スキャン結果 ────────────────────────────────────────────────── */}
      {activeTab === 'スキャン結果' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-[#7d92b0]" />
              <span className="text-xs text-[#7d92b0] font-medium">フィルタ:</span>
            </div>
            <div>
              <select
                value={scanRuleFilter}
                onChange={e => setScanRuleFilter(e.target.value)}
                className="px-3 py-1.5 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#7d92b0]/50"
              >
                <option value="all">全ルール</option>
                {rules.map(r => <option key={r.id} value={r.name}>{r.name}</option>)}
              </select>
            </div>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0]" />
              <input
                value={scanAgentFilter}
                onChange={e => setScanAgentFilter(e.target.value)}
                placeholder="エージェント名..."
                className="pl-8 pr-3 py-1.5 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-[#7d92b0]/50 w-36"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#7d92b0]">日付:</span>
              <input
                type="date"
                value={scanDateFrom}
                onChange={e => setScanDateFrom(e.target.value)}
                className="px-2 py-1.5 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#7d92b0]/50"
              />
              <span className="text-[#7d92b0]">—</span>
              <input
                type="date"
                value={scanDateTo}
                onChange={e => setScanDateTo(e.target.value)}
                className="px-2 py-1.5 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#7d92b0]/50"
              />
            </div>
            <span className="text-xs text-[#7d92b0] ml-auto">{filteredScans.length} 件</span>
          </div>

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['ルール名', 'エージェント', 'ファイルパス', 'マッチ文字列', 'スキャン日時'].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((scan, i) => (
                    <tr key={scan.id} className={`border-b border-[#1e2d42] hover:bg-[#111827] transition-colors ${i % 2 === 0 ? '' : 'bg-[#070d19]/30'}`}>
                      <td className="px-4 py-3 font-mono text-[#e8002d] text-xs font-medium whitespace-nowrap">
                        {scan.rule_name}
                      </td>
                      <td className="px-4 py-3 text-[#e2e8f4] text-xs whitespace-nowrap font-medium">
                        {scan.agent}
                      </td>
                      <td className="px-4 py-3 font-mono text-[#7d92b0] text-xs max-w-xs truncate" title={scan.file_path}>
                        {scan.file_path}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-yellow-400 max-w-xs truncate" title={scan.matched_strings}>
                        {scan.matched_strings.length > 60 ? scan.matched_strings.slice(0, 60) + '…' : scan.matched_strings}
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                        {new Date(scan.scanned_at).toLocaleString('ja-JP')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filteredScans.length === 0 && (
              <div className="text-center py-10 text-[#7d92b0]">
                <Search className="w-8 h-8 mx-auto mb-2 opacity-30" />
                <p>条件に一致するスキャン結果が見つかりません</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
