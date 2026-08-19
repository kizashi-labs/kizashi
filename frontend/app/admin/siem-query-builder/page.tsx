'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Database, Play, Plus, Trash2, Save, X, Download,
  CheckCircle, AlertTriangle, Loader2, Code2, Eye,
  BarChart2, BookOpen, ChevronDown, RefreshCw,
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ───────────────────────────────────────────────────────────────────

type DataSource = 'events' | 'alerts' | 'network' | 'process' | 'file'
type Operator = 'equals' | 'not_equals' | 'contains' | 'starts_with' | 'greater_than' | 'less_than' | 'regex'
type TimeRange = '15m' | '1h' | '6h' | '24h' | '7d'
type AndOr = 'AND' | 'OR'

interface Condition {
  id: string
  field: string
  operator: Operator
  value: string
  connector: AndOr
}

interface QueryState {
  data_source: DataSource
  time_range: TimeRange
  conditions: Condition[]
  group_by: string
  limit: number
}

interface SavedQuery {
  id: string
  name: string
  description: string
  last_run: string
  query: string
}

interface QueryResult {
  columns: string[]
  rows: Record<string, string | number>[]
  total: number
  execution_ms: number
}

// ── Field Definitions ────────────────────────────────────────────────────────

const SOURCE_FIELDS: Record<DataSource, string[]> = {
  events:  ['hostname', 'event_type', 'severity', 'user_name', 'process_name', 'timestamp', 'source_ip', 'event_id'],
  alerts:  ['alert_id', 'rule_name', 'severity', 'hostname', 'status', 'created_at', 'assigned_to', 'category'],
  network: ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'bytes', 'duration_ms', 'action'],
  process: ['process_name', 'pid', 'ppid', 'user', 'hostname', 'cmdline', 'hash_sha256', 'started_at'],
  file:    ['file_path', 'file_name', 'action', 'user', 'hostname', 'size_bytes', 'hash_md5', 'modified_at'],
}

const OPERATORS: { value: Operator; label: string }[] = [
  { value: 'equals',       label: '=' },
  { value: 'not_equals',   label: '≠' },
  { value: 'contains',     label: 'CONTAINS' },
  { value: 'starts_with',  label: 'STARTS WITH' },
  { value: 'greater_than', label: '>' },
  { value: 'less_than',    label: '<' },
  { value: 'regex',        label: 'REGEX' },
]

const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '15m', label: '15分' },
  { value: '1h',  label: '1時間' },
  { value: '6h',  label: '6時間' },
  { value: '24h', label: '24時間' },
  { value: '7d',  label: '7日間' },
]

// ── Query Builder Helpers ────────────────────────────────────────────────────

function generateSQL(q: QueryState): string {
  const cols = q.group_by ? `${q.group_by}, COUNT(*) AS count` : '*'
  let sql = `SELECT ${cols}\nFROM ${q.data_source}\nWHERE timestamp >= NOW() - INTERVAL '${q.time_range}'`
  if (q.conditions.length > 0) {
    const condStr = q.conditions.map((c, i) => {
      const opMap: Record<Operator, string> = {
        equals:       `${c.field} = '${c.value}'`,
        not_equals:   `${c.field} != '${c.value}'`,
        contains:     `${c.field} LIKE '%${c.value}%'`,
        starts_with:  `${c.field} LIKE '${c.value}%'`,
        greater_than: `${c.field} > ${c.value}`,
        less_than:    `${c.field} < ${c.value}`,
        regex:        `${c.field} REGEX '${c.value}'`,
      }
      const prefix = i === 0 ? '  AND ' : `  ${c.connector} `
      return `${prefix}${opMap[c.operator]}`
    }).join('\n')
    sql += '\n' + condStr
  }
  if (q.group_by) sql += `\nGROUP BY ${q.group_by}`
  sql += `\nLIMIT ${q.limit}`
  return sql
}

function newCondition(): Condition {
  return {
    id: Math.random().toString(36).slice(2),
    field: '',
    operator: 'equals',
    value: '',
    connector: 'AND',
  }
}

// ── Bar Chart (div-based) ────────────────────────────────────────────────────

function BarChart({ rows, groupBy }: { rows: Record<string, string | number>[]; groupBy: string }) {
  const vals = rows
    .map(r => ({ label: String(r[groupBy] ?? '?'), count: Number(r['count'] ?? 0) }))
    .slice(0, 10)
  const max = Math.max(...vals.map(v => v.count), 1)
  return (
    <div className="space-y-2">
      {vals.map(({ label, count }) => (
        <div key={label} className="flex items-center gap-3">
          <span className="text-xs font-mono text-[#7d92b0] w-32 truncate">{label}</span>
          <div className="flex-1 h-5 bg-[#1e2d42] rounded-sm overflow-hidden">
            <div
              className="h-full bg-linear-to-r from-[#e8002d] to-[#a80020] rounded-sm transition-all duration-500"
              style={{ width: `${(count / max) * 100}%` }}
            />
          </div>
          <span className="text-xs font-mono text-[#e2e8f4] w-10 text-right">{count.toLocaleString()}</span>
        </div>
      ))}
    </div>
  )
}

// ── Save Modal ───────────────────────────────────────────────────────────────

function SaveModal({
  onClose,
  onSave,
  isPending,
}: {
  onClose: () => void
  onSave: (name: string, desc: string) => void
  isPending: boolean
}) {
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const inputCls = 'w-full px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-[#e2e8f4] text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#3d6baa] transition-colors'
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center gap-3 px-6 py-4 border-b border-[#1e2d42]">
          <Save className="w-5 h-5 text-[#e8002d]" />
          <h3 className="text-white font-semibold">クエリを保存</h3>
          <button onClick={onClose} className="ml-auto text-[#7d92b0] hover:text-[#e2e8f4]"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">クエリ名</label>
            <input className={inputCls} placeholder="例: 高重要度アラート検索" value={name} onChange={e => setName(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">説明</label>
            <input className={inputCls} placeholder="このクエリの説明" value={desc} onChange={e => setDesc(e.target.value)} />
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-sm text-sm text-[#7d92b0] hover:text-[#e2e8f4]">キャンセル</button>
          <button
            onClick={() => onSave(name, desc)}
            disabled={isPending || !name}
            className="flex items-center gap-2 px-5 py-2 rounded-sm bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium disabled:opacity-50"
          >
            {isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function SiemQueryBuilderPage() {
  const qc = useQueryClient()
  const [queryState, setQueryState] = useState<QueryState>({
    data_source: 'events',
    time_range: '1h',
    conditions: [],
    group_by: '',
    limit: 100,
  })
  const [rawMode, setRawMode] = useState(false)
  const [rawSQL, setRawSQL] = useState('')
  const [results, setResults] = useState<QueryResult | null>(null)
  const [showChart, setShowChart] = useState(false)
  const [showSaveModal, setShowSaveModal] = useState(false)
  const [isExecuting, setIsExecuting] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  // Load saved queries
  const { data: savedQueries = [], isLoading: loadingSaved } = useQuery<SavedQuery[]>({
    queryKey: ['siem-saved-queries'],
    queryFn: () =>
      apiFetchList<SavedQuery>('/api/v1/admin/siem-queries'),
    staleTime: 60_000,
  })

  const savedList = savedQueries ?? []

  const saveQueryMutation = useMutation({
    mutationFn: (body: { name: string; description: string; query: string }) =>
      apiFetch('/api/v1/admin/siem-queries', { method: 'POST', body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['siem-saved-queries'] })
      setShowSaveModal(false)
      showToast('クエリを保存しました')
    },
  })

  const deleteQueryMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/admin/siem-queries/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['siem-saved-queries'] })
      showToast('クエリを削除しました')
    },
  })

  const generatedSQL = generateSQL(queryState)

  // Sync raw SQL when switching to raw mode
  const handleToggleRaw = () => {
    if (!rawMode) setRawSQL(generatedSQL)
    setRawMode(v => !v)
  }

  // Execute query
  const handleExecute = async () => {
    setIsExecuting(true)
    setResults(null)
    try {
      const res = await apiFetch<QueryResult>('/api/v1/admin/siem-queries/execute', {
        method: 'POST',
        body: JSON.stringify({ query: rawMode ? rawSQL : generatedSQL }),
      })
      setResults(res)
    } catch (e) {
      // 偽のモック結果は表示しない。準備中/エラーをトーストで通知する。
      showToast((e as Error)?.message || 'SIEMクエリ実行エンジンは準備中です')
    } finally {
      setIsExecuting(false)
    }
  }

  const addCondition = useCallback(() => {
    const fields = SOURCE_FIELDS[queryState.data_source]
    setQueryState(q => ({
      ...q,
      conditions: [...q.conditions, { ...newCondition(), field: fields[0] ?? '' }],
    }))
  }, [queryState.data_source])

  const removeCondition = useCallback((id: string) => {
    setQueryState(q => ({ ...q, conditions: q.conditions.filter(c => c.id !== id) }))
  }, [])

  const updateCondition = useCallback((id: string, patch: Partial<Condition>) => {
    setQueryState(q => ({
      ...q,
      conditions: q.conditions.map(c => c.id === id ? { ...c, ...patch } : c),
    }))
  }, [])

  // Export helpers
  const exportCSV = () => {
    if (!results) return
    const header = results.columns.join(',')
    const rows = results.rows.map(r => results.columns.map(c => JSON.stringify(r[c] ?? '')).join(','))
    const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'siem_results.csv'
    a.click()
  }

  const exportJSON = () => {
    if (!results) return
    const blob = new Blob([JSON.stringify(results.rows, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'siem_results.json'
    a.click()
  }

  const loadSavedQuery = (q: SavedQuery) => {
    setRawSQL(q.query)
    setRawMode(true)
    showToast(`"${q.name}" をロードしました`)
  }

  const fields = SOURCE_FIELDS[queryState.data_source]

  const inputCls = 'px-3 py-2 rounded bg-[#070d19] border border-[#1e2d42] text-[#e2e8f4] text-sm placeholder-[#3d5068] focus:outline-none focus:border-[#3d6baa] transition-colors'
  const selectCls = `${inputCls} cursor-pointer`
  const labelCls = 'block text-xs font-medium text-[#7d92b0] mb-1.5'

  function formatLastRun(iso: string) {
    const d = new Date(iso)
    return d.toLocaleDateString('ja-JP', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />

      <PageSaveFailed />
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg bg-[#0d1220] border border-[#1e2d42] shadow-lg text-[#e2e8f4] text-sm">
          <CheckCircle className="w-4 h-4 text-[#00c853]" />
          {toast}
        </div>
      )}

      {/* Save Modal */}
      {showSaveModal && (
        <SaveModal
          onClose={() => setShowSaveModal(false)}
          onSave={(name, desc) => saveQueryMutation.mutate({ name, description: desc, query: rawMode ? rawSQL : generatedSQL })}
          isPending={saveQueryMutation.isPending}
        />
      )}

      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-[#4a90e2]/10 border border-[#4a90e2]/20 flex items-center justify-center">
          <Database className="w-5 h-5 text-[#4a90e2]" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">SIEMクエリビルダー</h1>
          <p className="text-sm text-[#7d92b0] mt-0.5">ビジュアルクエリビルダーとSQL直接編集でSIEMデータを検索</p>
        </div>
      </div>

      {/* Split Layout */}
      <div className="flex flex-col xl:flex-row gap-6">

        {/* ── Left: Query Builder (60%) ────────────────────────── */}
        <div className="flex-[3] space-y-5 min-w-0">

          {/* Builder Card */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
              <Code2 className="w-5 h-5 text-[#e8002d]" />
              <h2 className="text-white font-semibold">クエリビルダー</h2>
              <div className="ml-auto flex items-center gap-2">
                <button
                  onClick={handleToggleRaw}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs font-medium border transition-colors ${
                    rawMode
                      ? 'bg-[#4a90e2]/10 border-[#4a90e2]/30 text-[#4a90e2]'
                      : 'bg-[#1e2d42] border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4]'
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" />
                  RAW SQL
                </button>
              </div>
            </div>

            {rawMode ? (
              /* Raw SQL Mode */
              <div className="p-5">
                <label className={labelCls}>SQL クエリ</label>
                <textarea
                  className={`${inputCls} w-full font-mono text-xs min-h-[200px] resize-y`}
                  value={rawSQL}
                  onChange={e => setRawSQL(e.target.value)}
                  spellCheck={false}
                  placeholder="SELECT * FROM events WHERE ..."
                />
                <p className="text-xs text-[#3d5068] mt-2">Raw SQLモードではビジュアルビルダーの設定は無視されます</p>
              </div>
            ) : (
              /* Visual Builder Mode */
              <div className="p-5 space-y-5">
                {/* Data source + Time range */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className={labelCls}>データソース</label>
                    <select
                      className={`${selectCls} w-full`}
                      value={queryState.data_source}
                      onChange={e => setQueryState(q => ({
                        ...q,
                        data_source: e.target.value as DataSource,
                        conditions: [],
                        group_by: '',
                      }))}
                    >
                      <option value="events">イベントログ (events)</option>
                      <option value="alerts">アラート (alerts)</option>
                      <option value="network">ネットワーク (network)</option>
                      <option value="process">プロセス (process)</option>
                      <option value="file">ファイル (file)</option>
                    </select>
                  </div>
                  <div>
                    <label className={labelCls}>期間</label>
                    <div className="flex items-center gap-1 bg-[#070d19] border border-[#1e2d42] rounded-sm overflow-hidden">
                      {TIME_RANGES.map(tr => (
                        <button
                          key={tr.value}
                          onClick={() => setQueryState(q => ({ ...q, time_range: tr.value }))}
                          className={`flex-1 py-2 text-xs font-medium transition-colors ${
                            queryState.time_range === tr.value
                              ? 'bg-[#e8002d] text-white'
                              : 'text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#1e2d42]'
                          }`}
                        >
                          {tr.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Conditions Builder */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className={`${labelCls} mb-0`}>条件フィルター</label>
                    <button
                      onClick={addCondition}
                      className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      条件を追加
                    </button>
                  </div>
                  <div className="space-y-2">
                    {queryState.conditions.length === 0 && (
                      <div className="flex items-center justify-center py-4 border border-dashed border-[#1e2d42] rounded-sm text-xs text-[#3d5068]">
                        条件なし — すべてのレコードが対象
                      </div>
                    )}
                    {queryState.conditions.map((cond, i) => (
                      <div key={cond.id} className="flex items-center gap-2 flex-wrap">
                        {i > 0 && (
                          <select
                            className={`${selectCls} w-16 shrink-0`}
                            value={cond.connector}
                            onChange={e => updateCondition(cond.id, { connector: e.target.value as AndOr })}
                          >
                            <option value="AND">AND</option>
                            <option value="OR">OR</option>
                          </select>
                        )}
                        {i === 0 && <span className="w-16 text-xs text-[#3d5068] text-center shrink-0">WHERE</span>}

                        <select
                          className={`${selectCls} flex-1 min-w-[120px]`}
                          value={cond.field}
                          onChange={e => updateCondition(cond.id, { field: e.target.value })}
                        >
                          {fields.map(f => <option key={f} value={f}>{f}</option>)}
                        </select>

                        <select
                          className={`${selectCls} w-32 shrink-0`}
                          value={cond.operator}
                          onChange={e => updateCondition(cond.id, { operator: e.target.value as Operator })}
                        >
                          {OPERATORS.map(op => <option key={op.value} value={op.value}>{op.label}</option>)}
                        </select>

                        <input
                          type="text"
                          className={`${inputCls} flex-1 min-w-[100px]`}
                          placeholder="値を入力..."
                          value={cond.value}
                          onChange={e => updateCondition(cond.id, { value: e.target.value })}
                        />

                        <button
                          onClick={() => removeCondition(cond.id)}
                          className="p-2 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] transition-colors shrink-0"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Group by + Limit */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className={labelCls}>グループ化 (任意)</label>
                    <select
                      className={`${selectCls} w-full`}
                      value={queryState.group_by}
                      onChange={e => setQueryState(q => ({ ...q, group_by: e.target.value }))}
                    >
                      <option value="">グループ化なし</option>
                      {fields.map(f => <option key={f} value={f}>{f}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className={labelCls}>取得上限件数</label>
                    <input
                      type="number"
                      className={`${inputCls} w-full`}
                      value={queryState.limit}
                      min={1}
                      max={10000}
                      onChange={e => setQueryState(q => ({ ...q, limit: Number(e.target.value) }))}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Generated SQL Preview */}
            {!rawMode && (
              <div className="px-5 pb-4">
                <div className="flex items-center gap-2 mb-2">
                  <Code2 className="w-3.5 h-3.5 text-[#7d92b0]" />
                  <span className="text-xs text-[#7d92b0] font-medium">生成クエリ プレビュー</span>
                </div>
                <pre className="p-3 bg-[#070d19] border border-[#1e2d42] rounded-sm text-xs font-mono text-[#4a90e2] overflow-x-auto whitespace-pre-wrap">
                  {generatedSQL}
                </pre>
              </div>
            )}
          </div>

          {/* Saved Queries */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
              <BookOpen className="w-5 h-5 text-[#e8002d]" />
              <h2 className="text-white font-semibold">保存済みクエリ</h2>
              <span className="ml-auto text-xs text-[#7d92b0] bg-[#1e2d42] px-2 py-0.5 rounded-sm">{savedList.length}件</span>
            </div>
            {loadingSaved ? (
              <div className="flex items-center justify-center h-20 text-[#7d92b0] text-sm">
                <Loader2 className="w-4 h-4 animate-spin mr-2" /> 読み込み中...
              </div>
            ) : (
              <div className="divide-y divide-[#1e2d42]">
                {savedList.map(sq => (
                  <div key={sq.id} className="flex items-center gap-4 px-5 py-3 hover:bg-[#111827] transition-colors">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-[#e2e8f4] truncate">{sq.name}</p>
                      <p className="text-xs text-[#7d92b0] truncate mt-0.5">{sq.description}</p>
                      <p className="text-[10px] text-[#3d5068] mt-0.5">最終実行: {formatLastRun(sq.last_run)}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => loadSavedQuery(sq)}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs font-medium bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#243448] transition-colors"
                      >
                        <Eye className="w-3 h-3" />
                        ロード
                      </button>
                      <button
                        onClick={() => deleteQueryMutation.mutate(sq.id)}
                        disabled={deleteQueryMutation.isPending}
                        className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-[#e8002d] transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: Results (40%) ──────────────────────────────── */}
        <div className="flex-[2] space-y-4 min-w-0">

          {/* Execute Panel */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5">
            <div className="flex items-center gap-3 flex-wrap">
              <button
                onClick={handleExecute}
                disabled={isExecuting}
                className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white font-semibold text-sm transition-colors disabled:opacity-50"
              >
                {isExecuting
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> 実行中...</>
                  : <><Play className="w-4 h-4" /> クエリ実行</>}
              </button>
              <button
                onClick={() => setShowSaveModal(true)}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#1e2d42] hover:bg-[#243448] text-[#7d92b0] hover:text-[#e2e8f4] font-medium text-sm transition-colors"
              >
                <Save className="w-4 h-4" />
                保存
              </button>
            </div>

            {results && (
              <div className="flex items-center gap-6 mt-4 pt-4 border-t border-[#1e2d42] flex-wrap">
                <div className="flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-[#00c853]" />
                  <span className="text-sm font-semibold text-white">{(results.total ?? 0).toLocaleString()}件ヒット</span>
                </div>
                <span className="text-xs text-[#7d92b0]">実行時間: <span className="font-mono text-[#e2e8f4]">{results.execution_ms}ms</span></span>
                <span className="text-xs text-[#7d92b0]">表示: <span className="font-mono text-[#e2e8f4]">{results.rows.length}件</span></span>
                <div className="flex items-center gap-2 ml-auto">
                  {queryState.group_by && (
                    <button
                      onClick={() => setShowChart(v => !v)}
                      className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs font-medium border transition-colors ${
                        showChart
                          ? 'bg-[#4a90e2]/10 border-[#4a90e2]/30 text-[#4a90e2]'
                          : 'bg-[#1e2d42] border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4]'
                      }`}
                    >
                      <BarChart2 className="w-3.5 h-3.5" />
                      チャート
                    </button>
                  )}
                  <button
                    onClick={exportCSV}
                    className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs font-medium bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    CSV
                  </button>
                  <button
                    onClick={exportJSON}
                    className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs font-medium bg-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    JSON
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Results */}
          {isExecuting && (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg flex items-center justify-center h-48 text-[#7d92b0] text-sm">
              <Loader2 className="w-5 h-5 animate-spin mr-2" />
              クエリを実行しています...
            </div>
          )}

          {results && !isExecuting && (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
              <div className="flex items-center gap-3 px-5 py-4 border-b border-[#1e2d42]">
                <Database className="w-4 h-4 text-[#e8002d]" />
                <h3 className="text-white font-semibold text-sm">クエリ結果</h3>
              </div>

              {/* Bar Chart */}
              {showChart && queryState.group_by && (
                <div className="px-5 py-4 border-b border-[#1e2d42]">
                  <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
                    {queryState.group_by} 別 集計
                  </p>
                  <BarChart rows={results.rows} groupBy={queryState.group_by} />
                </div>
              )}

              {/* Results Table */}
              <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-[#0d1220] z-10">
                    <tr className="border-b border-[#1e2d42]">
                      {results.columns.map(col => (
                        <th key={col} className="px-4 py-2.5 text-left text-[10px] font-semibold text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]">
                    {results.rows.map((row, i) => (
                      <tr key={i} className="hover:bg-[#111827] transition-colors">
                        {results.columns.map(col => (
                          <td key={col} className="px-4 py-2 font-mono text-[11px] text-[#e2e8f4] whitespace-nowrap max-w-[160px] truncate">
                            {String(row[col] ?? '')}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {!results && !isExecuting && (
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg flex flex-col items-center justify-center h-64 text-center p-8">
              <Database className="w-12 h-12 text-[#1e2d42] mb-4" />
              <p className="text-sm font-medium text-[#7d92b0]">クエリを実行してください</p>
              <p className="text-xs text-[#3d5068] mt-1">左側でクエリを設定し、「クエリ実行」ボタンを押してください</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
