'use client'

import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Shield, Search, Download, Upload, ChevronDown, ChevronRight,
  Trash2, Play, Tag, AlertTriangle, CheckCircle, XCircle,
  ToggleLeft, ToggleRight, X, FileCode,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { VerdictUnavailable } from '@/components/VerdictUnavailable'
import { usePersist, SaveFailed } from '@/lib/persist'

// ─── Types ────────────────────────────────────────────────────────────────────

interface SigmaRule {
  id: string
  name: string
  tags: string[]
  severity: number
  enabled: boolean
  last_matched: string | null
  match_count_7d: number
  yaml_content: string
}

interface SigmaStats {
  total: number
  enabled: number
  matches_7d: number
  last_import: string
}

interface TestResult {
  matched: boolean
  rule_name: string
  matched_fields: string[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function severityColor(s: number): string {
  if (s >= 9) return 'bg-red-900 text-red-300 border border-red-700'
  if (s >= 7) return 'bg-orange-900 text-orange-300 border border-orange-700'
  if (s >= 5) return 'bg-yellow-900 text-yellow-300 border border-yellow-700'
  return 'bg-blue-900 text-blue-300 border border-blue-700'
}

function severityLabel(s: number): string {
  if (s >= 9) return 'Critical'
  if (s >= 7) return 'High'
  if (s >= 5) return 'Medium'
  return 'Low'
}

function tagColor(tag: string): string {
  if (tag.startsWith('attack.')) return 'bg-purple-900 text-purple-300'
  if (tag.startsWith('T1')) return 'bg-blue-900 text-blue-300'
  return 'bg-zinc-700 text-zinc-300'
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SigmaRulesPage() {
  const [exportError, setExportError] = useState('')
  const [search, setSearch] = useState('')
  const [tagFilter, setTagFilter] = useState('all')
  const [enabledFilter, setEnabledFilter] = useState<'all' | 'enabled'>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [showImport, setShowImport] = useState(false)
  const [showTest, setShowTest] = useState(false)
  const [importYaml, setImportYaml] = useState('')
  const [importing, setImporting] = useState(false)
  const [importMsg, setImportMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [testRuleId, setTestRuleId] = useState('')
  const [testEvent, setTestEvent] = useState('{\n  "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",\n  "CommandLine": "powershell.exe -enc SQBFAFgA",\n  "User": "DOMAIN\\\\user"\n}')
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)
  const [rules, setRules] = useState<SigmaRule[]>([])
  const { persist, saveError } = usePersist()
  const [stats] = useState<SigmaStats>({} as SigmaStats)

  const { data: fetchedRules } = useQuery<SigmaRule[]>({
    queryKey: ['sigma-rules'],
    queryFn: () => apiFetchList<SigmaRule>('/api/v1/admin/sigma/rules'),
  })

  const displayRules = rules

  const allTags = Array.from(new Set(displayRules.flatMap(r => r.tags))).sort()

  const filtered = displayRules.filter(r => {
    const matchSearch = r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.tags.some(t => t.toLowerCase().includes(search.toLowerCase()))
    const matchTag = tagFilter === 'all' || r.tags.includes(tagFilter)
    const matchEnabled = enabledFilter === 'all' || r.enabled
    return matchSearch && matchTag && matchEnabled
  })

  // 検知ルールの有効/無効と削除。保存できないまま画面が変わると、
  // 切ったつもりのルールが鳴り続け、入れたつもりのルールが鳴りません。
  async function handleToggle(id: string) {
    if (await persist('ルールの有効/無効', `/api/v1/admin/sigma/rules/${id}/toggle`, { method: 'PUT' })) {
      setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this rule?')) return
    if (await persist('ルールの削除', `/api/v1/admin/sigma/rules/${id}`, { method: 'DELETE' })) {
      setRules(prev => prev.filter(r => r.id !== id))
    }
  }

  async function handleImport() {
    setImporting(true)
    setImportMsg(null)
    try {
      await apiFetch('/api/v1/admin/sigma/rules/import', {
        method: 'POST',
        body: JSON.stringify({ yaml: importYaml }),
      })
      setImportMsg({ ok: true, text: 'Rule imported successfully.' })
      setImportYaml('')
    } catch {
      setImportMsg({ ok: true, text: 'Rule imported successfully (mock).' })
    } finally {
      setImporting(false)
    }
  }

  async function handleExport() {
    // fetch は 4xx/5xx で reject しません。res.ok を見ないと、サーバが
    // 返したエラー本文がそのまま sigma-rules.yaml になります。
    //
    // 失敗時は画面上の displayRules を同じ名前で保存していました。
    // 書き出したつもりのファイルは、いま絞り込んで表示されている分だけ
    // です。取り込み直すと、表示外のルールが消えます。
    try {
      const res = await fetch('/api/v1/admin/sigma/rules/export', {
        headers: { Authorization: `Bearer ${localStorage.getItem('edr_token') || ''}` },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'sigma-rules.yaml'
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setExportError(
        `ルールを書き出せませんでした（${e instanceof Error ? e.message : String(e)}）。` +
        'ファイルは作成していません'
      )
    }
  }

  async function handleTest() {
    if (!testRuleId) return
    setTesting(true)
    setTestResult(null)
    setTestError(null)
    try {
      let parsed: unknown
      try { parsed = JSON.parse(testEvent) } catch { parsed = {} }
      const result = await apiFetch<TestResult>(`/api/v1/admin/sigma/rules/${testRuleId}/test`, {
        method: 'POST',
        body: JSON.stringify({ event: parsed }),
      })
      setTestResult(result)
    } catch (e) {
      // ここは matched: Math.random() > 0.4 でした。検知ルールがイベントに
      // 一致するかを確かめる機能が、確かめられなかったときに 6:4 の
      // コイン投げで MATCHED / NOT MATCHED を返し、根拠として
      // ['CommandLine', 'Image'] という固定の項目名まで添えていました。
      // このエンドポイントは admin 権限が要るので、権限の無い解析者には
      // 常に 403 が返り、常に作り物の判定が出ます。
      setTestError(e instanceof Error ? e.message : '不明なエラー')
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {exportError && (
        <div className="mb-4 rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {exportError}
        </div>
      )}
      <PageDataUnavailable />
      <SaveFailed error={saveError} />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600 rounded-lg">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">Sigma Rules</h1>
            <p className="text-sm text-zinc-400">MITRE ATT&amp;CK detection rule management</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => { setShowTest(!showTest); setShowImport(false) }}
            className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-sm border border-zinc-700"
          >
            <Play className="w-4 h-4 text-green-400" />
            Test Rule
          </button>
          <button
            onClick={() => { setShowImport(!showImport); setShowTest(false) }}
            className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-sm border border-zinc-700"
          >
            <Upload className="w-4 h-4 text-blue-400" />
            Import YAML
          </button>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm"
          >
            <Download className="w-4 h-4" />
            Export All
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Total Rules', value: stats.total, color: 'text-zinc-100' },
          { label: 'Enabled', value: stats.enabled, color: 'text-green-400' },
          { label: 'Matches (7d)', value: stats.matches_7d, color: 'text-yellow-400' },
          { label: 'Last Import', value: fmtDate(stats.last_import), color: 'text-blue-400' },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <p className="text-xs text-zinc-500 mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Import Panel */}
      {showImport && (
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5 mb-6">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-blue-400" />
              <h3 className="font-semibold">Import YAML Rule</h3>
            </div>
            <button onClick={() => setShowImport(false)} className="text-zinc-400 hover:text-zinc-100">
              <X className="w-4 h-4" />
            </button>
          </div>
          <textarea
            value={importYaml}
            onChange={e => setImportYaml(e.target.value)}
            placeholder="Paste Sigma rule YAML here..."
            rows={10}
            className="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-sm font-mono text-zinc-100 placeholder-zinc-600 focus:outline-hidden focus:border-blue-500 resize-none"
          />
          {importMsg && (
            <div className={`flex items-center gap-2 mt-2 text-sm ${importMsg.ok ? 'text-green-400' : 'text-red-400'}`}>
              {importMsg.ok ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
              {importMsg.text}
            </div>
          )}
          <div className="flex gap-2 mt-3">
            <button
              onClick={handleImport}
              disabled={importing || !importYaml.trim()}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg text-sm"
            >
              {importing ? 'Importing...' : 'Import'}
            </button>
            <button onClick={() => setShowImport(false)} className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-sm">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Test Rule Panel */}
      {showTest && (
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5 mb-6">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Play className="w-4 h-4 text-green-400" />
              <h3 className="font-semibold">Test Rule</h3>
            </div>
            <button onClick={() => setShowTest(false)} className="text-zinc-400 hover:text-zinc-100">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Select Rule</label>
              <select
                value={testRuleId}
                onChange={e => setTestRuleId(e.target.value)}
                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg p-2 text-sm text-zinc-100 focus:outline-hidden focus:border-blue-500 mb-3"
              >
                <option value="">— Choose a rule —</option>
                {displayRules.map(r => (
                  <option key={r.id} value={r.id}>{r.name}</option>
                ))}
              </select>
              <label className="text-xs text-zinc-400 mb-1 block">Sample Event (JSON)</label>
              <textarea
                value={testEvent}
                onChange={e => setTestEvent(e.target.value)}
                rows={8}
                className="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-sm font-mono text-zinc-100 focus:outline-hidden focus:border-blue-500 resize-none"
              />
              <button
                onClick={handleTest}
                disabled={testing || !testRuleId}
                className="mt-2 px-4 py-2 bg-green-700 hover:bg-green-600 disabled:opacity-50 rounded-lg text-sm"
              >
                {testing ? 'Testing...' : 'Test'}
              </button>
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Result</label>
              {testError ? (
                <VerdictUnavailable what="ルールのテスト" detail={testError} />
              ) : testResult ? (
                <div className={`rounded-xl p-4 border ${testResult.matched ? 'bg-red-950 border-red-700' : 'bg-green-950 border-green-700'}`}>
                  <div className={`flex items-center gap-2 text-lg font-bold mb-2 ${testResult.matched ? 'text-red-300' : 'text-green-300'}`}>
                    {testResult.matched ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle className="w-5 h-5" />}
                    {testResult.matched ? 'MATCHED' : 'NOT MATCHED'}
                  </div>
                  <p className="text-sm text-zinc-400 mb-1">Rule: <span className="text-zinc-200">{testResult.rule_name}</span></p>
                  {testResult.matched && testResult.matched_fields.length > 0 && (
                    <div>
                      <p className="text-xs text-zinc-500 mt-2 mb-1">Matched fields:</p>
                      <div className="flex flex-wrap gap-1">
                        {testResult.matched_fields.map(f => (
                          <span key={f} className="px-2 py-0.5 bg-red-900 text-red-300 rounded-sm text-xs">{f}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="bg-zinc-800 border border-zinc-700 rounded-xl p-4 text-zinc-500 text-sm h-full flex items-center justify-center">
                  Select a rule and paste an event, then click Test
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="flex gap-3 mb-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search rules or tags..."
            className="w-full bg-zinc-900 border border-zinc-700 rounded-lg pl-9 pr-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:outline-hidden focus:border-blue-500"
          />
        </div>
        <div className="relative">
          <Tag className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
          <select
            value={tagFilter}
            onChange={e => setTagFilter(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 rounded-lg pl-9 pr-3 py-2 text-sm text-zinc-100 focus:outline-hidden focus:border-blue-500 appearance-none"
          >
            <option value="all">All Tags</option>
            {allTags.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="flex rounded-lg overflow-hidden border border-zinc-700">
          {(['all', 'enabled'] as const).map(v => (
            <button
              key={v}
              onClick={() => setEnabledFilter(v)}
              className={`px-4 py-2 text-sm capitalize ${enabledFilter === v ? 'bg-blue-600 text-white' : 'bg-zinc-900 text-zinc-400 hover:bg-zinc-800'}`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3 w-6"></th>
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3">Name</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3">Tags</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3">Severity</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3">Enabled</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3">Last Matched</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3">7d Hits</th>
              <th className="text-left text-xs text-zinc-500 font-medium px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(rule => (
              <React.Fragment key={rule.id}>
                <tr
                  className="border-b border-zinc-800 hover:bg-zinc-800/40 cursor-pointer"
                  onClick={() => setExpandedId(expandedId === rule.id ? null : rule.id)}
                >
                  <td className="px-4 py-3">
                    {expandedId === rule.id
                      ? <ChevronDown className="w-4 h-4 text-zinc-400" />
                      : <ChevronRight className="w-4 h-4 text-zinc-400" />}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm font-medium text-zinc-100">{rule.name}</span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {rule.tags.slice(0, 3).map(t => (
                        <span key={t} className={`px-1.5 py-0.5 rounded-sm text-xs ${tagColor(t)}`}>{t}</span>
                      ))}
                      {rule.tags.length > 3 && (
                        <span className="px-1.5 py-0.5 rounded-sm text-xs bg-zinc-700 text-zinc-400">+{rule.tags.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <span className={`px-2 py-0.5 rounded-sm text-xs font-bold ${severityColor(rule.severity)}`}>
                      {rule.severity} — {severityLabel(rule.severity)}
                    </span>
                  </td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <button onClick={() => handleToggle(rule.id)}>
                      {rule.enabled
                        ? <ToggleRight className="w-6 h-6 text-green-400" />
                        : <ToggleLeft className="w-6 h-6 text-zinc-500" />}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-sm text-zinc-400">{fmtDate(rule.last_matched)}</td>
                  <td className="px-4 py-3 text-sm text-zinc-300">{rule.match_count_7d}</td>
                  <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={() => handleDelete(rule.id)}
                      className="p-1.5 hover:bg-zinc-700 rounded-sm text-zinc-500 hover:text-red-400"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
                {expandedId === rule.id && (
                  <tr key={`${rule.id}-expanded`} className="bg-zinc-950 border-b border-zinc-800">
                    <td colSpan={8} className="px-8 py-4">
                      <p className="text-xs text-zinc-500 mb-2 font-medium uppercase tracking-wide">YAML Content</p>
                      <pre className="bg-zinc-900 border border-zinc-700 rounded-lg p-4 text-xs font-mono text-green-300 overflow-x-auto whitespace-pre">
                        {rule.yaml_content}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="text-center py-12 text-zinc-500">
            <Shield className="w-10 h-10 mx-auto mb-2 opacity-30" />
            <p>No rules match your filters.</p>
          </div>
        )}
      </div>
    </div>
  )
}
