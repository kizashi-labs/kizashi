'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  FileSearch, Plus, Pencil, Trash2, Play, ToggleLeft, ToggleRight,
  X, ChevronRight, RefreshCw, AlertTriangle, CheckCircle, Clock,
  Loader2, Search, Terminal, FlaskConical,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type LogSource = 'syslog' | 'json' | 'csv' | 'custom'
type JobStatus = 'pending' | 'running' | 'completed' | 'failed'
type TimeRange = '15m' | '1h' | '6h' | '24h' | '7d'

interface ParseRule {
  id: string
  name: string
  description: string
  log_source: LogSource
  pattern: string
  field_map: Record<string, string>
  priority: number
  is_active: boolean
  created_at: string
}

interface AnalysisJob {
  id: string
  name: string
  query: string
  time_range: TimeRange
  status: JobStatus
  result_count: number
  created_at: string
  results?: string[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const LOG_SOURCE_STYLES: Record<LogSource, { label: string; cls: string }> = {
  syslog: { label: 'syslog', cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  json:   { label: 'JSON',   cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  csv:    { label: 'CSV',    cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  custom: { label: 'custom', cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
}

const JOB_STATUS_STYLES: Record<JobStatus, { label: string; cls: string }> = {
  pending:   { label: '待機中',   cls: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
  running:   { label: '実行中',   cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  completed: { label: '完了',     cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  failed:    { label: '失敗',     cls: 'bg-red-500/20 text-[#e8002d] border-red-500/30' },
}

const TIME_RANGE_LABELS: Record<TimeRange, string> = {
  '15m': '15分',
  '1h': '1時間',
  '6h': '6時間',
  '24h': '24時間',
  '7d': '7日間',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ─── Rule Modal ───────────────────────────────────────────────────────────────

interface RuleModalProps {
  rule?: ParseRule | null
  onClose: () => void
  onSave: (data: Partial<ParseRule>) => void
  saving: boolean
}

function RuleModal({ rule, onClose, onSave, saving }: RuleModalProps) {
  const [form, setForm] = useState({
    name: rule?.name ?? '',
    description: rule?.description ?? '',
    log_source: rule?.log_source ?? 'syslog' as LogSource,
    pattern: rule?.pattern ?? '',
    field_map: rule?.field_map ? JSON.stringify(rule.field_map, null, 2) : '{\n  "field": "mapped_field"\n}',
    priority: rule?.priority ?? 10,
    is_active: rule?.is_active ?? true,
  })

  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-base">
            {rule ? 'パースルール編集' : '新規パースルール'}
          </h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4 max-h-[70vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">ルール名 *</label>
              <input
                value={form.name}
                onChange={e => set('name', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
                placeholder="Auth Failure Parser"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">ログソース *</label>
              <select
                value={form.log_source}
                onChange={e => set('log_source', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              >
                {(['syslog', 'json', 'csv', 'custom'] as LogSource[]).map(s => (
                  <option key={s} value={s}>{LOG_SOURCE_STYLES[s].label}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">説明</label>
            <input
              value={form.description}
              onChange={e => set('description', e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              placeholder="ルールの説明"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">パターン (正規表現) *</label>
            <textarea
              value={form.pattern}
              onChange={e => set('pattern', e.target.value)}
              rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-green-400 text-sm font-mono focus:outline-none focus:border-[#e8002d]/50 resize-none"
              placeholder="^(?P<timestamp>\S+)\s+(?P<host>\S+).*$"
            />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">フィールドマップ (JSON)</label>
            <textarea
              value={form.field_map}
              onChange={e => set('field_map', e.target.value)}
              rows={4}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-yellow-300 text-sm font-mono focus:outline-none focus:border-[#e8002d]/50 resize-none"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">優先度</label>
              <input
                type="number"
                value={form.priority}
                onChange={e => set('priority', parseInt(e.target.value) || 0)}
                min={1}
                max={100}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">有効</label>
              <button
                type="button"
                onClick={() => set('is_active', !form.is_active)}
                className="flex items-center gap-2 mt-1"
              >
                {form.is_active
                  ? <ToggleRight className="w-8 h-8 text-green-400" />
                  : <ToggleLeft className="w-8 h-8 text-[#3d5068]" />}
                <span className={`text-sm ${form.is_active ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                  {form.is_active ? '有効' : '無効'}
                </span>
              </button>
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => {
              let parsedFieldMap: Record<string, string> = {}
              try { parsedFieldMap = JSON.parse(form.field_map) } catch { /* ignore */ }
              onSave({ ...form, field_map: parsedFieldMap })
            }}
            disabled={saving || !form.name || !form.pattern}
            className="px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Test Rule Modal ──────────────────────────────────────────────────────────

interface TestModalProps {
  rule: ParseRule
  onClose: () => void
}

function TestRuleModal({ rule, onClose }: TestModalProps) {
  const [sample, setSample] = useState('')
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState<{ fields: Record<string, string>; matched: boolean } | null>(null)

  const runTest = async () => {
    setTesting(true)
    // Try API first, fall back to local regex mock
    try {
      const res = await apiFetch<{ fields: Record<string, string>; matched: boolean }>(
        `/api/v1/admin/log-analysis/rules/${rule.id}/test`,
        { method: 'POST', body: JSON.stringify({ sample_log: sample }) }
      )
      setResult(res)
    } catch {
      // Mock: attempt regex match
      await new Promise(r => setTimeout(r, 500))
      try {
        const rx = new RegExp(rule.pattern)
        const m = rx.exec(sample)
        if (m?.groups) {
          const fields: Record<string, string> = {}
          for (const [k, v] of Object.entries(m.groups)) {
            const mapped = rule.field_map[k] ?? k
            fields[mapped] = v ?? ''
          }
          setResult({ matched: true, fields })
        } else {
          setResult({ matched: false, fields: {} })
        }
      } catch {
        setResult({ matched: false, fields: {} })
      }
    }
    setTesting(false)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div>
            <h2 className="text-white font-semibold text-base">ルールテスト</h2>
            <p className="text-xs text-[#7d92b0] mt-0.5">{rule.name}</p>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">サンプルログ入力</label>
            <textarea
              value={sample}
              onChange={e => setSample(e.target.value)}
              rows={4}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-green-400 text-sm font-mono focus:outline-none focus:border-[#e8002d]/50 resize-none"
              placeholder="Mar 18 09:15:32 web01 sshd[4523]: Failed password for root from 192.168.1.1 port 22 ssh2"
            />
          </div>
          <button
            onClick={runTest}
            disabled={testing || !sample.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#1a6bff] hover:bg-[#1555cc] text-white text-sm font-medium transition-colors disabled:opacity-50"
          >
            {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            テスト実行
          </button>
          {result && (
            <div className={`rounded-lg border p-4 ${result.matched ? 'border-green-500/30 bg-green-500/5' : 'border-red-500/30 bg-red-500/5'}`}>
              <div className="flex items-center gap-2 mb-3">
                {result.matched
                  ? <CheckCircle className="w-4 h-4 text-green-400" />
                  : <AlertTriangle className="w-4 h-4 text-[#e8002d]" />}
                <span className={`text-sm font-medium ${result.matched ? 'text-green-400' : 'text-[#e8002d]'}`}>
                  {result.matched ? 'マッチ成功' : 'マッチ失敗'}
                </span>
              </div>
              {result.matched && Object.keys(result.fields).length > 0 && (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      <th className="text-left text-xs text-[#7d92b0] pb-2 font-medium">フィールド名</th>
                      <th className="text-left text-xs text-[#7d92b0] pb-2 font-medium">値</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(result.fields).map(([k, v]) => (
                      <tr key={k} className="border-b border-[#1e2d42]/50 last:border-0">
                        <td className="py-1.5 pr-4 text-blue-400 font-mono text-xs">{k}</td>
                        <td className="py-1.5 text-white font-mono text-xs">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
        <div className="flex justify-end px-6 py-4 border-t border-[#1e2d42]">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors"
          >
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Rules Tab ────────────────────────────────────────────────────────────────

function RulesTab() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [editRule, setEditRule] = useState<ParseRule | null>(null)
  const [testRule, setTestRule] = useState<ParseRule | null>(null)

  const { data, isLoading } = useQuery<ParseRule[]>({
    queryKey: ['log-analysis-rules'],
    queryFn: async () => {
      try {
        return await apiFetchList<ParseRule>('/api/v1/admin/log-analysis/rules')
      } catch {
        return []
      }
    },
  })

  const saveMutation = useMutation({
    mutationFn: async (payload: { id?: string; data: Partial<ParseRule> }) => {
      try {
        if (payload.id) {
          return await apiFetch(`/api/v1/admin/log-analysis/rules/${payload.id}`, {
            method: 'PUT', body: JSON.stringify(payload.data),
          })
        }
        return await apiFetch('/api/v1/admin/log-analysis/rules', {
          method: 'POST', body: JSON.stringify(payload.data),
        })
      } catch {
        return { ...payload.data, id: payload.id ?? `rule-${Date.now()}` }
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['log-analysis-rules'] })
      setShowModal(false)
      setEditRule(null)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      try {
        return await apiFetch(`/api/v1/admin/log-analysis/rules/${id}`, { method: 'DELETE' })
      } catch { return null }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-analysis-rules'] }),
  })

  const toggleMutation = useMutation({
    mutationFn: async ({ id, is_active }: { id: string; is_active: boolean }) => {
      try {
        return await apiFetch(`/api/v1/admin/log-analysis/rules/${id}`, {
          method: 'PUT', body: JSON.stringify({ is_active }),
        })
      } catch { return null }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-analysis-rules'] }),
  })

  const rules = data ?? []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[#7d92b0]">
          {rules.length} ルール登録済み
        </p>
        <button
          onClick={() => { setEditRule(null); setShowModal(true) }}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          新規ルール
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="w-6 h-6 animate-spin text-[#7d92b0]" />
        </div>
      ) : (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">ルール名</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">ログソース</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3 w-64">パターン</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">優先度</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">状態</th>
                <th className="text-right text-xs text-[#7d92b0] font-medium px-4 py-3">操作</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-sm text-white font-medium">{rule.name}</p>
                    {rule.description && (
                      <p className="text-xs text-[#7d92b0] mt-0.5 truncate max-w-[200px]">{rule.description}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${LOG_SOURCE_STYLES[rule.log_source].cls}`}>
                      {LOG_SOURCE_STYLES[rule.log_source].label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <code className="text-xs text-green-400 font-mono truncate block max-w-[240px]" title={rule.pattern}>
                      {rule.pattern.length > 45 ? rule.pattern.slice(0, 45) + '…' : rule.pattern}
                    </code>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-white font-mono">{rule.priority}</span>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleMutation.mutate({ id: rule.id, is_active: !rule.is_active })}
                      className="flex items-center gap-1.5 transition-colors"
                    >
                      {rule.is_active
                        ? <ToggleRight className="w-6 h-6 text-green-400" />
                        : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />}
                      <span className={`text-xs ${rule.is_active ? 'text-green-400' : 'text-[#7d92b0]'}`}>
                        {rule.is_active ? '有効' : '無効'}
                      </span>
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => setTestRule(rule)}
                        className="p-1.5 rounded hover:bg-[#1a6bff]/20 text-[#7d92b0] hover:text-[#1a6bff] transition-colors"
                        title="テスト"
                      >
                        <FlaskConical className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => { setEditRule(rule); setShowModal(true) }}
                        className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"
                        title="編集"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => { if (confirm(`"${rule.name}" を削除しますか？`)) deleteMutation.mutate(rule.id) }}
                        className="p-1.5 rounded hover:bg-red-500/10 text-[#7d92b0] hover:text-[#e8002d] transition-colors"
                        title="削除"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <RuleModal
          rule={editRule}
          onClose={() => { setShowModal(false); setEditRule(null) }}
          onSave={data => saveMutation.mutate({ id: editRule?.id, data })}
          saving={saveMutation.isPending}
        />
      )}
      {testRule && (
        <TestRuleModal rule={testRule} onClose={() => setTestRule(null)} />
      )}
    </div>
  )
}

// ─── Jobs Tab ─────────────────────────────────────────────────────────────────

function JobsTab() {
  const qc = useQueryClient()
  const [jobName, setJobName] = useState('')
  const [jobQuery, setJobQuery] = useState('')
  const [jobRange, setJobRange] = useState<TimeRange>('24h')
  const [selectedJob, setSelectedJob] = useState<AnalysisJob | null>(null)

  const { data, isLoading } = useQuery<AnalysisJob[]>({
    queryKey: ['log-analysis-jobs'],
    queryFn: async () => {
      try {
        return await apiFetchList<AnalysisJob>('/api/v1/admin/log-analysis/jobs')
      } catch {
        return []
      }
    },
  })

  const createJobMutation = useMutation({
    mutationFn: async () => {
      try {
        return await apiFetch('/api/v1/admin/log-analysis/jobs', {
          method: 'POST',
          body: JSON.stringify({ name: jobName, query: jobQuery, time_range: jobRange }),
        })
      } catch {
        return { id: `job-${Date.now()}`, name: jobName, query: jobQuery, time_range: jobRange, status: 'pending', result_count: 0, created_at: new Date().toISOString() }
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['log-analysis-jobs'] })
      setJobName('')
      setJobQuery('')
      setJobRange('24h')
    },
  })

  const jobs = data ?? []

  return (
    <div className="space-y-6">
      {/* New Job Form */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Search className="w-4 h-4 text-[#e8002d]" />
          新規分析ジョブ
        </h3>
        <div className="space-y-3">
          <div className="flex gap-3">
            <input
              value={jobName}
              onChange={e => setJobName(e.target.value)}
              className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              placeholder="ジョブ名"
            />
            <select
              value={jobRange}
              onChange={e => setJobRange(e.target.value as TimeRange)}
              className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
            >
              {(Object.entries(TIME_RANGE_LABELS) as [TimeRange, string][]).map(([k, v]) => (
                <option key={k} value={k}>{v}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-3">
            <textarea
              value={jobQuery}
              onChange={e => setJobQuery(e.target.value)}
              rows={2}
              className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-green-400 text-sm font-mono focus:outline-none focus:border-[#e8002d]/50 resize-none"
              placeholder='log_source:syslog AND message:"Failed password"'
            />
            <button
              onClick={() => createJobMutation.mutate()}
              disabled={createJobMutation.isPending || !jobName || !jobQuery}
              className="self-end flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 whitespace-nowrap"
            >
              {createJobMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              実行
            </button>
          </div>
        </div>
      </div>

      {/* Jobs Table */}
      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="w-6 h-6 animate-spin text-[#7d92b0]" />
        </div>
      ) : (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">ジョブ名</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">クエリ</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">期間</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">状態</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">件数</th>
                <th className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">作成日時</th>
                <th className="text-right text-xs text-[#7d92b0] font-medium px-4 py-3">操作</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map(job => (
                <tr key={job.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-sm text-white font-medium">{job.name}</span>
                  </td>
                  <td className="px-4 py-3 max-w-[240px]">
                    <code className="text-xs text-green-400 font-mono truncate block" title={job.query}>
                      {job.query.length > 50 ? job.query.slice(0, 50) + '…' : job.query}
                    </code>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-[#7d92b0]">{TIME_RANGE_LABELS[job.time_range]}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border font-medium ${JOB_STATUS_STYLES[job.status].cls}`}>
                      {job.status === 'running' && (
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
                      )}
                      {JOB_STATUS_STYLES[job.status].label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-white font-mono">
                      {job.status === 'completed' ? (job.result_count ?? 0).toLocaleString() : '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-[#7d92b0]">{formatDate(job.created_at)}</span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {job.status === 'completed' && job.results && (
                      <button
                        onClick={() => setSelectedJob(selectedJob?.id === job.id ? null : job)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1a6bff]/20 hover:bg-[#1a6bff]/30 text-[#1a6bff] text-xs font-medium transition-colors ml-auto"
                      >
                        <Terminal className="w-3 h-3" />
                        結果表示
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Results Panel */}
      {selectedJob && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-green-400" />
              <span className="text-sm font-medium text-white">{selectedJob.name} — 結果</span>
              <span className="text-xs text-[#7d92b0]">({(selectedJob.result_count ?? 0).toLocaleString()} 件)</span>
            </div>
            <button onClick={() => setSelectedJob(null)} className="text-[#7d92b0] hover:text-white transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="h-48 overflow-y-auto p-4 font-mono text-xs text-green-400 bg-[#070d19]/80 space-y-1">
            {(selectedJob.results ?? []).map((line, i) => (
              <p key={i} className="leading-relaxed">{line}</p>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function LogAnalysisPage() {
  const [activeTab, setActiveTab] = useState<'rules' | 'jobs'>('rules')

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 flex items-center justify-center">
              <FileSearch className="w-5 h-5 text-[#e8002d]" />
            </div>
            <h1 className="text-2xl font-bold text-white">高度ログ分析</h1>
          </div>
          <p className="text-sm text-[#7d92b0] ml-12">
            ログパースルールの管理と分析ジョブの実行・結果確認
          </p>
        </div>
        <button className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 text-sm transition-colors">
          <RefreshCw className="w-4 h-4" />
          更新
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1 w-fit">
        {([['rules', 'パースルール', FileSearch], ['jobs', '分析ジョブ', Search]] as const).map(([id, label, Icon]) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 ${
              activeTab === id
                ? 'bg-[#e8002d] text-white shadow'
                : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'rules' ? <RulesTab /> : <JobsTab />}
    </div>
  )
}
