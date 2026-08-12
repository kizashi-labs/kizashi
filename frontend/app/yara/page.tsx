'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useCanWrite } from '@/lib/auth'
import {
  FileCode, Plus, Search, Filter, X, AlertTriangle,
  ToggleLeft, ToggleRight, Trash2, Eye, EyeOff, ChevronDown,
  ChevronRight, Play, CheckCircle2, XCircle, Loader2, Code2, RefreshCcw, ScanLine,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface YARARule {
  id: string
  name: string
  category: string
  severity: string
  content: string
  description?: string
  enabled: boolean
  match_count: number
  last_matched?: string
  created_at: string
  updated_at: string
}

interface ListResponse {
  rules: YARARule[]
  total: number
}

interface TestResult {
  matched: boolean
  matches?: string[]
  error?: string
}

// ── Constants ─────────────────────────────────────────────────────────────────

const CATEGORIES = [
  'ransomware', 'webshell', 'apt', 'backdoor', 'trojan', 'worm',
  'rootkit', 'exploit', 'maldoc', 'packer', 'evasion', 'spyware',
  'mobile', 'malware',
] as const
const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const

const CATEGORY_LABELS: Record<string, string> = {
  malware:    'マルウェア',
  ransomware: 'ランサムウェア',
  apt:        'APT',
  webshell:   'Webシェル',
  backdoor:   'バックドア',
  trojan:     'トロイの木馬',
  worm:       'ワーム',
  rootkit:    'ルートキット',
  exploit:    'エクスプロイト',
  maldoc:     '悪意ドキュメント',
  packer:     'パッカー',
  evasion:    '回避(アンチVM等)',
  spyware:    'スパイウェア',
  mobile:     'モバイル',
  generic:    '汎用',
}

const CATEGORY_COLORS: Record<string, string> = {
  malware:    'bg-red-900/40 text-red-300 border-red-700/40',
  ransomware: 'bg-orange-900/40 text-orange-300 border-orange-700/40',
  apt:        'bg-purple-900/40 text-purple-300 border-purple-700/40',
  webshell:   'bg-yellow-900/40 text-yellow-300 border-yellow-700/40',
  backdoor:   'bg-pink-900/40 text-pink-300 border-pink-700/40',
  trojan:     'bg-rose-900/40 text-rose-300 border-rose-700/40',
  worm:       'bg-amber-900/40 text-amber-300 border-amber-700/40',
  rootkit:    'bg-violet-900/40 text-violet-300 border-violet-700/40',
  exploit:    'bg-red-900/40 text-red-400 border-red-600/40',
  maldoc:     'bg-lime-900/40 text-lime-300 border-lime-700/40',
  packer:     'bg-cyan-900/40 text-cyan-300 border-cyan-700/40',
  evasion:    'bg-slate-700/40 text-slate-300 border-slate-600/40',
  spyware:    'bg-indigo-900/40 text-indigo-300 border-indigo-700/40',
  mobile:     'bg-teal-900/40 text-teal-300 border-teal-700/40',
  generic:    'bg-blue-900/40 text-blue-300 border-blue-700/40',
}

const SEVERITY_LABELS: Record<string, string> = {
  low:      '低',
  medium:   '中',
  high:     '高',
  critical: '緊急',
}

const SEVERITY_COLORS: Record<string, string> = {
  low:      'text-green-400 bg-green-900/30 border-green-700/40',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-700/40',
  high:     'text-orange-400 bg-orange-900/30 border-orange-700/40',
  critical: 'text-red-400 bg-red-900/30 border-red-700/40',
}

const BLANK_CONTENT = `rule ExampleRule {
  meta:
    description = "ルールの説明をここに記述"
    author = ""
    date = ""
  strings:
    $a = "suspicious_string" nocase
    $b = { 4D 5A 90 00 }
  condition:
    any of them
}`

const BLANK_FORM = {
  name: '',
  category: 'generic' as string,
  severity: 'medium' as string,
  content: BLANK_CONTENT,
  description: '',
  enabled: true,
}

// ── API helpers ───────────────────────────────────────────────────────────────

interface CategoryStat { category: string; rule_count: number; match_count: number }
interface StatsResponse { categories: CategoryStat[]; total_rules: number; total_matches: number }

function fetchRules(params: { search?: string; category?: string; severity?: string }) {
  const q = new URLSearchParams()
  if (params.search)   q.set('search', params.search)
  if (params.category) q.set('category', params.category)
  if (params.severity) q.set('severity', params.severity)
  return apiFetch<ListResponse>(`/api/v1/yara?${q}`)
}

// ── Sub-components ────────────────────────────────────────────────────────────

// ── YARA スキャンジョブボタン ────────────────────────────────────────────────

interface ScanJob { id: string; status: string; scan_path: string; match_count: number; requested_at: string }

function ScanJobButton() {
  const qc = useQueryClient()
  const [showJobs, setShowJobs] = useState(false)
  const [result, setResult] = useState<{ id: string } | null>(null)

  const { data: jobsData } = useQuery<{ jobs: ScanJob[]; total: number }>({
    queryKey: ['yara-scan-jobs'],
    queryFn: () => apiFetch('/api/v1/admin/yara-rules/scan-jobs'),
    refetchInterval: showJobs ? 10_000 : false,
    enabled: showJobs,
  })

  const scanMutation = useMutation({
    mutationFn: () => apiFetch<{ id: string }>('/api/v1/admin/yara-rules/scan-request', {
      method: 'POST',
      body: JSON.stringify({ scan_path: '/' }),
    }),
    onSuccess: (data) => {
      setResult(data)
      setShowJobs(true)
      qc.invalidateQueries({ queryKey: ['yara-scan-jobs'] })
      setTimeout(() => setResult(null), 5000)
    },
  })

  const jobs = jobsData?.jobs ?? []

  return (
    <div className="relative">
      <div className="flex items-center gap-1">
        <button
          onClick={() => scanMutation.mutate()}
          disabled={scanMutation.isPending}
          title="全エージェントにYARAスキャンを要求します"
          className="flex items-center gap-2 px-3 py-2 bg-[#161f33] hover:bg-[#1d2f4a]
                     border border-[#1e2d42] text-[#7d92b0] hover:text-white
                     text-sm rounded-lg transition-colors disabled:opacity-50"
        >
          <ScanLine className={`w-3.5 h-3.5 ${scanMutation.isPending ? 'animate-pulse' : ''}`} />
          スキャン要求
        </button>
        <button
          onClick={() => setShowJobs(v => !v)}
          className="px-2 py-2 bg-[#161f33] hover:bg-[#1d2f4a] border border-[#1e2d42]
                     text-[#3d5068] hover:text-white text-xs rounded-lg transition-colors"
          title="スキャンジョブ一覧"
        >
          {jobs.length > 0 ? `${jobs.length}件` : '履歴'}
        </button>
      </div>
      {result && (
        <p className="absolute top-10 left-0 text-xs text-green-400 whitespace-nowrap">
          ジョブ作成完了 (ID: {result.id.slice(0, 8)}…)
        </p>
      )}
      {showJobs && (
        <div className="absolute top-10 right-0 z-50 bg-[#0d1220] border border-[#1e2d42]
                        rounded-xl shadow-2xl w-96 max-h-80 overflow-auto">
          <div className="px-4 py-2.5 border-b border-[#1e2d42] flex items-center justify-between">
            <span className="text-xs font-medium text-[#e2e8f4]">スキャンジョブ一覧</span>
            <button onClick={() => setShowJobs(false)} className="text-[#3d5068] hover:text-white text-xs">閉じる</button>
          </div>
          {jobs.length === 0 ? (
            <p className="px-4 py-6 text-xs text-[#3d5068] text-center">ジョブなし</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42] bg-[#080c14]">
                  <th className="px-3 py-2 text-left text-[#3d5068]">状態</th>
                  <th className="px-3 py-2 text-left text-[#3d5068]">パス</th>
                  <th className="px-3 py-2 text-right text-[#3d5068]">一致</th>
                  <th className="px-3 py-2 text-left text-[#3d5068]">作成日時</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map(j => (
                  <tr key={j.id} className="border-b border-[#1e2d42] hover:bg-[#111827]">
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                        j.status === 'done' ? 'bg-green-900/30 text-green-400' :
                        j.status === 'running' ? 'bg-blue-900/30 text-blue-400' :
                        j.status === 'failed' ? 'bg-red-900/30 text-red-400' :
                        'bg-[#1e2d42] text-[#3d5068]'
                      }`}>{j.status}</span>
                    </td>
                    <td className="px-3 py-2 text-[#7d92b0] font-mono truncate max-w-[100px]">{j.scan_path}</td>
                    <td className="px-3 py-2 text-right text-[#e2e8f4]">{j.match_count}</td>
                    <td className="px-3 py-2 text-[#3d5068]">
                      {new Date(j.requested_at).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

function ReclassifyButton({ onDone }: { onDone: () => void }) {
  const [result, setResult] = useState<{ updated: number; unchanged: number } | null>(null)
  const mutation = useMutation({
    mutationFn: () => apiFetch<{ updated: number; unchanged: number; message: string }>(
      '/api/v1/yara-rules/reclassify', { method: 'POST' }
    ),
    onSuccess: (data) => {
      setResult(data)
      onDone()
      setTimeout(() => setResult(null), 5000)
    },
  })

  return (
    <div className="flex items-center gap-2">
      <button
        onClick={() => mutation.mutate()}
        disabled={mutation.isPending}
        title="ルール名・タグからカテゴリを自動再分類します"
        className="flex items-center gap-2 px-3 py-2 bg-[#161f33] hover:bg-[#1d2f4a]
                   border border-[#1e2d42] text-[#7d92b0] hover:text-white
                   text-sm rounded-lg transition-colors disabled:opacity-50"
      >
        <RefreshCcw className={`w-3.5 h-3.5 ${mutation.isPending ? 'animate-spin' : ''}`} />
        カテゴリ再分類
      </button>
      {result && (
        <span className="text-xs text-green-400">
          {result.updated}件更新 / {result.unchanged}件変更なし
        </span>
      )}
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] px-5 py-4">
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-[#7d92b0] mt-1">{label}</p>
    </div>
  )
}

function CategoryBadge({ category }: { category: string }) {
  const cls = CATEGORY_COLORS[category] ?? 'bg-gray-700/40 text-gray-300 border-gray-600/40'
  return (
    <span className={`text-xs px-2 py-0.5 rounded border ${cls}`}>
      {CATEGORY_LABELS[category] ?? category}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_COLORS[severity] ?? 'text-gray-400 bg-gray-700/30 border-gray-600/40'
  return (
    <span className={`text-xs px-2 py-0.5 rounded border font-medium ${cls}`}>
      {SEVERITY_LABELS[severity] ?? severity}
    </span>
  )
}

// ── Detail Panel ──────────────────────────────────────────────────────────────

function RuleDetailPanel({
  rule,
  onClose,
}: {
  rule: YARARule
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [testInput, setTestInput] = useState('')
  const [testResult, setTestResult] = useState<TestResult | null>(null)

  const testMutation = useMutation({
    mutationFn: (target: string) =>
      apiFetch<TestResult>(`/api/v1/yara/${rule.id}/test`, {
        method: 'POST',
        body: JSON.stringify({ target }),
      }),
    onSuccess: (res) => setTestResult(res),
    onError: () =>
      setTestResult({ matched: false, error: 'テスト実行中にエラーが発生しました。' }),
  })

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] rounded-2xl w-full max-w-3xl border border-[#1e2d42] flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-[#1e2d42] flex-shrink-0">
          <div className="flex items-start gap-3 min-w-0">
            <div className="w-9 h-9 rounded-lg bg-[#e8002d]/15 border border-[#e8002d]/30 flex items-center justify-center flex-shrink-0 mt-0.5">
              <FileCode className="w-4.5 h-4.5 text-[#e8002d]" />
            </div>
            <div className="min-w-0">
              <h2 className="text-lg font-bold text-white truncate">{rule.name}</h2>
              <div className="flex items-center gap-2 mt-1 flex-wrap">
                <CategoryBadge category={rule.category} />
                <SeverityBadge severity={rule.severity} />
                <span className={`text-xs px-2 py-0.5 rounded border ${
                  rule.enabled
                    ? 'bg-green-900/30 text-green-400 border-green-700/40'
                    : 'bg-gray-700/30 text-gray-400 border-gray-600/40'
                }`}>
                  {rule.enabled ? '有効' : '無効'}
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-[#7d92b0] hover:text-white transition-colors flex-shrink-0 ml-4"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto p-6 space-y-5 flex-1">

          {/* Description */}
          {rule.description && (
            <div>
              <p className="text-xs text-[#7d92b0] mb-1">説明</p>
              <p className="text-sm text-[#e2e8f4]">{rule.description}</p>
            </div>
          )}

          {/* Meta grid */}
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: 'マッチ回数',   value: (rule.match_count ?? 0).toLocaleString() },
              { label: '最終マッチ',   value: rule.last_matched ? new Date(rule.last_matched).toLocaleString('ja-JP') : '—' },
              { label: '作成日',       value: new Date(rule.created_at).toLocaleDateString('ja-JP') },
            ].map(item => (
              <div key={item.label} className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
                <p className="text-xs text-[#7d92b0]">{item.label}</p>
                <p className="text-sm text-white font-medium mt-0.5">{item.value}</p>
              </div>
            ))}
          </div>

          {/* YARA content */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Code2 className="w-3.5 h-3.5 text-[#7d92b0]" />
              <p className="text-xs text-[#7d92b0] font-medium">YARAルール内容</p>
            </div>
            <pre className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 text-xs font-mono text-[#a8c0e0] overflow-x-auto leading-relaxed whitespace-pre">
              {rule.content}
            </pre>
          </div>

          {/* Test panel */}
          <div className="bg-[#070d19] rounded-xl border border-[#1e2d42] p-4">
            <div className="flex items-center gap-2 mb-3">
              <Play className="w-3.5 h-3.5 text-[#e8002d]" />
              <p className="text-sm font-semibold text-white">ルールのテスト</p>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={testInput}
                onChange={e => { setTestInput(e.target.value); setTestResult(null) }}
                placeholder="ファイルハッシュ または ファイルパスを入力..."
                className="flex-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2
                           text-sm text-white placeholder-[#3d5068] font-mono
                           focus:outline-none focus:border-[#e8002d]/50"
              />
              <button
                onClick={() => { if (testInput.trim()) testMutation.mutate(testInput.trim()) }}
                disabled={!testInput.trim() || testMutation.isPending}
                className="flex items-center gap-1.5 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f]
                           text-white text-sm rounded-lg disabled:opacity-50 transition-colors"
              >
                {testMutation.isPending
                  ? <Loader2 className="w-4 h-4 animate-spin" />
                  : <Play className="w-4 h-4" />}
                テスト
              </button>
            </div>

            {testResult && (
              <div className={`mt-3 rounded-lg px-4 py-3 flex items-start gap-3 text-sm ${
                testResult.error
                  ? 'bg-red-900/20 border border-red-700/40'
                  : testResult.matched
                  ? 'bg-red-900/25 border border-red-600/50'
                  : 'bg-green-900/20 border border-green-700/40'
              }`}>
                {testResult.error ? (
                  <>
                    <XCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                    <p className="text-red-300">{testResult.error}</p>
                  </>
                ) : testResult.matched ? (
                  <>
                    <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-red-300 font-medium">マッチしました</p>
                      {testResult.matches && testResult.matches.length > 0 && (
                        <ul className="mt-1 space-y-0.5">
                          {testResult.matches.map((m, i) => (
                            <li key={i} className="text-xs text-red-200/80 font-mono">{m}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                    <p className="text-green-300">マッチしませんでした</p>
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end px-6 py-4 border-t border-[#1e2d42] flex-shrink-0">
          <button
            onClick={onClose}
            className="px-5 py-2 text-sm text-[#7d92b0] bg-[#161f33] hover:bg-[#1d2f4a] rounded-lg transition-colors border border-[#1e2d42]"
          >
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Upload Modal ──────────────────────────────────────────────────────────────

function UploadModal({
  editingRule,
  onClose,
  onSuccess,
}: {
  editingRule: YARARule | null
  onClose: () => void
  onSuccess: () => void
}) {
  const isEdit = editingRule !== null
  const [form, setForm] = useState(
    isEdit
      ? {
          name:        editingRule.name,
          category:    editingRule.category,
          severity:    editingRule.severity,
          content:     editingRule.content,
          description: editingRule.description ?? '',
          enabled:     editingRule.enabled,
        }
      : { ...BLANK_FORM },
  )
  const [contentWarning, setContentWarning] = useState('')

  const mutation = useMutation({
    mutationFn: (body: typeof form) =>
      isEdit
        ? apiFetch(`/api/v1/yara/${editingRule!.id}`, { method: 'PUT', body: JSON.stringify(body) })
        : apiFetch('/api/v1/yara', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess,
  })

  function handleContentChange(val: string) {
    setForm(f => ({ ...f, content: val }))
    const trimmed = val.trim()
    if (trimmed && !trimmed.startsWith('rule ')) {
      setContentWarning('YARAルールは "rule <名前> { ... }" の形式で記述してください')
    } else {
      setContentWarning('')
    }
  }

  const canSubmit = form.name.trim().length > 0 && form.content.trim().length > 0

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] rounded-2xl w-full max-w-2xl border border-[#1e2d42] flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-[#1e2d42] flex-shrink-0">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <FileCode className="w-5 h-5 text-[#e8002d]" />
            {isEdit ? 'YARAルールを編集' : '新しいYARAルール'}
          </h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto p-6 space-y-4 flex-1">

          {/* Name */}
          <div>
            <label className="text-xs text-[#7d92b0] block mb-1.5">
              ルール名 <span className="text-[#e8002d]">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="例: DetectMimikatz"
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42]
                         focus:outline-none focus:border-[#e8002d]/50 text-sm placeholder-[#3d5068]"
            />
          </div>

          {/* Category + Severity */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-[#7d92b0] block mb-1.5">カテゴリ</label>
              <select
                value={form.category}
                onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
                className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42]
                           focus:outline-none focus:border-[#e8002d]/50 text-sm"
              >
                {CATEGORIES.map(c => (
                  <option key={c} value={c}>{CATEGORY_LABELS[c]}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] block mb-1.5">重大度</label>
              <select
                value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42]
                           focus:outline-none focus:border-[#e8002d]/50 text-sm"
              >
                {SEVERITIES.map(s => (
                  <option key={s} value={s}>{SEVERITY_LABELS[s]} ({s})</option>
                ))}
              </select>
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="text-xs text-[#7d92b0] block mb-1.5">説明 (省略可)</label>
            <input
              type="text"
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="このルールが検知する内容の概要..."
              className="w-full bg-[#070d19] text-white px-3 py-2 rounded-lg border border-[#1e2d42]
                         focus:outline-none focus:border-[#e8002d]/50 text-sm placeholder-[#3d5068]"
            />
          </div>

          {/* Enabled */}
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2.5 cursor-pointer select-none">
              <div
                role="switch"
                aria-checked={form.enabled}
                onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}
                className={`w-10 h-5 rounded-full transition-colors cursor-pointer relative ${
                  form.enabled ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
                }`}
              >
                <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-[#e2e8f4] shadow transition-transform ${
                  form.enabled ? 'translate-x-5.5' : 'translate-x-0.5'
                }`} />
              </div>
              <span className="text-sm text-[#7d92b0]">
                {form.enabled ? '有効にする' : '無効にする'}
              </span>
            </label>
          </div>

          {/* YARA content */}
          <div>
            <label className="text-xs text-[#7d92b0] block mb-1.5">
              YARAルール内容 <span className="text-[#e8002d]">*</span>
            </label>
            <textarea
              value={form.content}
              onChange={e => handleContentChange(e.target.value)}
              rows={14}
              spellCheck={false}
              className="w-full bg-[#070d19] text-[#a8c0e0] px-3 py-2.5 rounded-lg border border-[#1e2d42]
                         focus:outline-none focus:border-[#e8002d]/50 text-xs font-mono resize-y leading-relaxed"
            />
            {contentWarning && (
              <div className="flex items-start gap-2 mt-1.5 text-yellow-400 text-xs">
                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                <span>{contentWarning}</span>
              </div>
            )}
            <p className="text-[#3d5068] text-xs mt-1">
              注意: 実際のYARAスキャンにはエージェント側でlibyaraが必要です。
            </p>
          </div>

          {mutation.isError && (
            <div className="flex items-center gap-2 text-red-400 text-sm bg-red-900/20 px-3 py-2 rounded-lg border border-red-700/40">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span>保存に失敗しました。再度お試しください。</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex gap-3 px-6 py-4 border-t border-[#1e2d42] flex-shrink-0">
          <button
            onClick={() => mutation.mutate(form)}
            disabled={!canSubmit || mutation.isPending}
            className="flex-1 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-lg
                       disabled:opacity-50 disabled:cursor-not-allowed
                       flex items-center justify-center gap-2 text-sm font-medium transition-colors"
          >
            {mutation.isPending
              ? <Loader2 className="w-4 h-4 animate-spin" />
              : <CheckCircle2 className="w-4 h-4" />}
            {isEdit ? '更新する' : '作成する'}
          </button>
          <button
            onClick={onClose}
            className="px-5 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] transition-colors border border-[#1e2d42] text-sm"
          >
            キャンセル
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Delete Confirm ────────────────────────────────────────────────────────────

function DeleteConfirmModal({
  rule,
  onConfirm,
  onCancel,
  isPending,
}: {
  rule: YARARule
  onConfirm: () => void
  onCancel: () => void
  isPending: boolean
}) {
  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] rounded-2xl w-full max-w-md border border-[#1e2d42] p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-900/30 border border-red-700/50 flex items-center justify-center">
            <Trash2 className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">ルールを削除</h3>
            <p className="text-xs text-[#7d92b0]">この操作は元に戻せません</p>
          </div>
        </div>
        <p className="text-sm text-[#e2e8f4] mb-1">
          以下のルールを削除しますか？
        </p>
        <p className="text-sm font-semibold text-white bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 font-mono mb-5">
          {rule.name}
        </p>
        <div className="flex gap-3">
          <button
            onClick={onConfirm}
            disabled={isPending}
            className="flex-1 py-2 bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-lg
                       disabled:opacity-50 text-sm font-medium transition-colors flex items-center justify-center gap-2"
          >
            {isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
            削除する
          </button>
          <button
            onClick={onCancel}
            className="px-5 py-2 bg-[#161f33] text-[#7d92b0] rounded-lg hover:bg-[#1d2f4a] transition-colors border border-[#1e2d42] text-sm"
          >
            キャンセル
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function YARAPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()

  // Filters
  const [search, setSearch]           = useState('')
  const [categoryFilter, setCategory] = useState('')
  const [severityFilter, setSeverity] = useState('')

  // UI state
  const [showModal, setShowModal]           = useState(false)
  const [editingRule, setEditingRule]       = useState<YARARule | null>(null)
  const [detailRule, setDetailRule]         = useState<YARARule | null>(null)
  const [deleteTarget, setDeleteTarget]     = useState<YARARule | null>(null)
  const [expandedRow, setExpandedRow]       = useState<string | null>(null)

  // Query
  const { data, isLoading, isError } = useQuery({
    queryKey: ['yara', search, categoryFilter, severityFilter],
    queryFn: () => fetchRules({
      search:   search   || undefined,
      category: categoryFilter || undefined,
      severity: severityFilter || undefined,
    }),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const { data: statsData } = useQuery<StatsResponse>({
    queryKey: ['yara-stats'],
    queryFn: () => apiFetch('/api/v1/yara/stats'),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })
  const catCounts: Record<string, number> = {}
  for (const cs of statsData?.categories ?? []) {
    catCounts[cs.category] = cs.rule_count
  }

  // Toggle mutation
  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/yara/${id}/toggle`, { method: 'PUT' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara'] }),
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/yara/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['yara'] })
      setDeleteTarget(null)
    },
  })

  const rules  = data?.rules ?? []
  const total  = data?.total ?? 0
  const enabled  = rules.filter(r => r.enabled).length
  const disabled = rules.filter(r => !r.enabled).length
  const lastScan = rules.reduce<string | null>((latest, r) => {
    if (!r.last_matched) return latest
    if (!latest) return r.last_matched
    return r.last_matched > latest ? r.last_matched : latest
  }, null)

  function openCreate() {
    setEditingRule(null)
    setShowModal(true)
  }

  function openEdit(rule: YARARule, e: React.MouseEvent) {
    e.stopPropagation()
    setEditingRule(rule)
    setShowModal(true)
  }

  function handleModalClose() {
    setShowModal(false)
    setEditingRule(null)
  }

  function handleModalSuccess() {
    qc.invalidateQueries({ queryKey: ['yara'] })
    handleModalClose()
  }

  function toggleRow(id: string) {
    setExpandedRow(prev => (prev === id ? null : id))
  }

  return (
    <div className="p-6 space-y-6 min-h-screen bg-[#070d19]">

      {/* ── Header ────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#e8002d]/15 border border-[#e8002d]/30 flex items-center justify-center">
              <FileCode className="w-4.5 h-4.5 text-[#e8002d]" />
            </div>
            YARAルール管理
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1 ml-11">
            静的シグネチャによるマルウェア・脅威の検知ルールを管理します
          </p>
        </div>
        {canWrite && (
          <div className="flex items-center gap-2">
            <ScanJobButton />
            <ReclassifyButton onDone={() => {
              qc.invalidateQueries({ queryKey: ['yara'] })
              qc.invalidateQueries({ queryKey: ['yara-stats'] })
            }} />
            <button
              onClick={openCreate}
              className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c8001f]
                         text-white text-sm font-medium rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              ルールを追加
            </button>
          </div>
        )}
      </div>

      {/* ── Stats bar ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard label="総ルール数"   value={total}    color="text-white" />
        <StatCard label="有効"         value={enabled}  color="text-green-400" />
        <StatCard label="無効"         value={disabled} color="text-[#7d92b0]" />
        <StatCard
          label="最終スキャン"
          value={lastScan ? new Date(lastScan).toLocaleDateString('ja-JP') : '—'}
          color="text-[#e2e8f4]"
        />
      </div>

      {/* ── Filters ───────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48 max-w-72">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
          <input
            type="text"
            placeholder="ルール名・説明を検索..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-[#0d1220] text-white pl-9 pr-8 py-2 rounded-lg border border-[#1e2d42]
                       focus:outline-none focus:border-[#e8002d]/40 text-sm placeholder-[#3d5068]"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#3d5068] hover:text-[#7d92b0]"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* カテゴリフィルター — バッジボタン */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <Filter className="w-3.5 h-3.5 text-[#3d5068] flex-shrink-0" />
          <button
            onClick={() => setCategory('')}
            className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
              categoryFilter === ''
                ? 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/50'
                : 'bg-[#0d1220] text-[#3d5068] border-[#1e2d42] hover:text-white hover:border-[#2a3f60]'
            }`}
          >
            全て
            {statsData && (
              <span className="ml-1 opacity-60">{statsData.total_rules}</span>
            )}
          </button>
          {CATEGORIES.filter(c => catCounts[c] > 0).map(c => {
            const baseCls = CATEGORY_COLORS[c] ?? 'bg-gray-700/40 text-gray-300 border-gray-600/40'
            const activeCls = categoryFilter === c ? baseCls : 'bg-[#0d1220] text-[#3d5068] border-[#1e2d42] hover:text-white hover:border-[#2a3f60]'
            return (
              <button
                key={c}
                onClick={() => setCategory(categoryFilter === c ? '' : c)}
                className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${activeCls}`}
              >
                {CATEGORY_LABELS[c] ?? c}
                <span className="ml-1 opacity-70">{catCounts[c]}</span>
              </button>
            )
          })}
        </div>

        {/* 重大度フィルター */}
        <div className="flex items-center gap-1.5">
          {SEVERITIES.map(s => {
            const clsMap: Record<string, string> = {
              low:      'text-green-400 border-green-700/40 bg-green-900/30',
              medium:   'text-yellow-400 border-yellow-700/40 bg-yellow-900/30',
              high:     'text-orange-400 border-orange-700/40 bg-orange-900/30',
              critical: 'text-red-400 border-red-600/40 bg-red-900/30',
            }
            const activeCls = severityFilter === s ? clsMap[s] : 'bg-[#0d1220] text-[#3d5068] border-[#1e2d42] hover:text-white hover:border-[#2a3f60]'
            return (
              <button
                key={s}
                onClick={() => setSeverity(severityFilter === s ? '' : s)}
                className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${activeCls}`}
              >
                {SEVERITY_LABELS[s]}
              </button>
            )
          })}
        </div>

        {(search || categoryFilter || severityFilter) && (
          <button
            onClick={() => { setSearch(''); setCategory(''); setSeverity('') }}
            className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white
                       px-2 py-1 rounded-lg hover:bg-[#161f33] transition-colors"
          >
            <X className="w-3.5 h-3.5" />
            フィルターをクリア
          </button>
        )}

        <span className="ml-auto text-xs text-[#3d5068]">{total} 件</span>
      </div>

      {/* ── Table ─────────────────────────────────────────────────── */}
      {isLoading ? (
        <div className="space-y-2">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-14 bg-[#0d1220] rounded-xl border border-[#1e2d42] animate-pulse" />
          ))}
        </div>
      ) : isError ? (
        <div className="text-center py-16 bg-[#0d1220] rounded-xl border border-[#1e2d42]">
          <AlertTriangle className="w-10 h-10 text-[#e8002d] mx-auto mb-3" />
          <p className="text-[#7d92b0] text-sm">データの取得に失敗しました</p>
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ['yara'] })}
            className="mt-3 text-xs text-[#e8002d] hover:underline"
          >
            再試行
          </button>
        </div>
      ) : rules.length === 0 ? (
        <div className="text-center py-16 bg-[#0d1220] rounded-xl border border-[#1e2d42]">
          <FileCode className="w-10 h-10 text-[#1e2d42] mx-auto mb-3" />
          <p className="text-[#7d92b0] text-sm">
            {search || categoryFilter || severityFilter
              ? '条件に一致するルールが見つかりません'
              : 'YARAルールがまだありません'}
          </p>
          {!search && !categoryFilter && !severityFilter && canWrite && (
            <button
              onClick={openCreate}
              className="mt-4 flex items-center gap-1.5 mx-auto px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c8001f] text-white rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              最初のルールを追加
            </button>
          )}
        </div>
      ) : (
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/60">
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide w-6" />
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">名前</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">カテゴリ</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">重大度</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">マッチ数</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">最終マッチ</th>
                <th className="text-center px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">有効/無効</th>
                <th className="text-center px-4 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">アクション</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => {
                const isExpanded = expandedRow === rule.id
                return (
                  <>
                    <tr
                      key={rule.id}
                      onClick={() => toggleRow(rule.id)}
                      className={`border-b border-[#1e2d42]/60 hover:bg-[#161f33]/50 transition-colors cursor-pointer
                                  ${!rule.enabled ? 'opacity-60' : ''}`}
                    >
                      {/* Expand icon */}
                      <td className="px-3 py-3.5 text-[#3d5068]">
                        {isExpanded
                          ? <ChevronDown className="w-3.5 h-3.5" />
                          : <ChevronRight className="w-3.5 h-3.5" />}
                      </td>

                      {/* Name */}
                      <td className="px-4 py-3.5">
                        <div className="font-medium text-sm text-white">{rule.name}</div>
                        {rule.description && (
                          <div className="text-xs text-[#7d92b0] mt-0.5 truncate max-w-xs">{rule.description}</div>
                        )}
                      </td>

                      {/* Category */}
                      <td className="px-4 py-3.5">
                        <CategoryBadge category={rule.category} />
                      </td>

                      {/* Severity */}
                      <td className="px-4 py-3.5">
                        <SeverityBadge severity={rule.severity} />
                      </td>

                      {/* Match count */}
                      <td className="px-4 py-3.5">
                        {rule.match_count > 0 ? (
                          <span className="text-[#e8002d] font-medium text-sm">
                            {(rule.match_count ?? 0).toLocaleString()}
                          </span>
                        ) : (
                          <span className="text-[#3d5068] text-sm">0</span>
                        )}
                      </td>

                      {/* Last matched */}
                      <td className="px-4 py-3.5 text-xs text-[#3d5068]">
                        {rule.last_matched
                          ? new Date(rule.last_matched).toLocaleString('ja-JP')
                          : '—'}
                      </td>

                      {/* Toggle */}
                      <td className="px-4 py-3.5 text-center">
                        {canWrite ? (
                          <button
                            onClick={e => { e.stopPropagation(); toggleMutation.mutate(rule.id) }}
                            disabled={toggleMutation.isPending}
                            className="inline-flex items-center gap-1 transition-colors disabled:opacity-40"
                            title={rule.enabled ? '無効にする' : '有効にする'}
                          >
                            {rule.enabled ? (
                              <ToggleRight className="w-6 h-6 text-green-400" />
                            ) : (
                              <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                            )}
                          </button>
                        ) : (
                          <span className="inline-flex items-center gap-1">
                            {rule.enabled ? (
                              <ToggleRight className="w-6 h-6 text-green-400" />
                            ) : (
                              <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                            )}
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3.5">
                        <div className="flex items-center justify-center gap-2" onClick={e => e.stopPropagation()}>
                          <button
                            onClick={() => setDetailRule(rule)}
                            className="text-[#3d5068] hover:text-[#7d92b0] transition-colors"
                            title="詳細を見る"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          {canWrite && (
                            <button
                              onClick={e => openEdit(rule, e)}
                              className="text-[#3d5068] hover:text-[#e8002d] transition-colors"
                              title="編集"
                            >
                              <FileCode className="w-4 h-4" />
                            </button>
                          )}
                          {canWrite && (
                            <button
                              onClick={() => setDeleteTarget(rule)}
                              className="text-[#3d5068] hover:text-red-400 transition-colors"
                              title="削除"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>

                    {/* Expanded row — inline YARA preview */}
                    {isExpanded && (
                      <tr key={`${rule.id}-expanded`} className="bg-[#070d19]/80 border-b border-[#1e2d42]/60">
                        <td colSpan={8} className="px-6 py-4">
                          <div className="flex items-center gap-2 mb-2">
                            <Code2 className="w-3.5 h-3.5 text-[#7d92b0]" />
                            <span className="text-xs text-[#7d92b0] font-medium">YARAルール内容</span>
                            <button
                              onClick={() => setDetailRule(rule)}
                              className="ml-auto text-xs text-[#e8002d] hover:underline flex items-center gap-1"
                            >
                              <Eye className="w-3 h-3" />
                              詳細 / テスト
                            </button>
                          </div>
                          <pre className="text-xs font-mono text-[#a8c0e0] bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3 overflow-x-auto leading-relaxed whitespace-pre max-h-48 overflow-y-auto">
                            {rule.content}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Modals ────────────────────────────────────────────────── */}
      {showModal && (
        <UploadModal
          editingRule={editingRule}
          onClose={handleModalClose}
          onSuccess={handleModalSuccess}
        />
      )}

      {detailRule && (
        <RuleDetailPanel
          rule={detailRule}
          onClose={() => setDetailRule(null)}
        />
      )}

      {deleteTarget && (
        <DeleteConfirmModal
          rule={deleteTarget}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          isPending={deleteMutation.isPending}
        />
      )}
    </div>
  )
}
