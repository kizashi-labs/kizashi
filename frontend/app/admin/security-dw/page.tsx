'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { Database, Play, Download, Clock, CheckCircle, XCircle, Loader2, HardDrive, FileText, Zap } from 'lucide-react'


// ─── 型定義 ──────────────────────────────────────────────────────────────────

interface Dataset {
  id: string
  name: string
  source_type: 'alerts_db' | 'endpoint_events' | 'network_flows' | 'vuln_scans'
  row_count: number
  size_bytes: number
  retention_days: number
  status: 'active' | 'indexing' | 'error'
  last_ingested_at: string
}

interface QueryResult {
  rows_returned: number
  execution_ms: number
  columns: string[]
  rows: Record<string, unknown>[]
}

interface QueryHistory {
  id: string
  query_text: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  rows_returned: number | null
  execution_ms: number | null
  executed_at: string
}

// ─── ユーティリティ ───────────────────────────────────────────────────────────

function formatRowCount(n: number): string {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B'
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K'
  return String(n)
}

function formatSize(bytes: number): string {
  if (bytes >= 1_099_511_627_776) return (bytes / 1_099_511_627_776).toFixed(1) + ' TB'
  if (bytes >= 1_073_741_824) return (bytes / 1_073_741_824).toFixed(1) + ' GB'
  if (bytes >= 1_048_576) return (bytes / 1_048_576).toFixed(1) + ' MB'
  return (bytes / 1024).toFixed(1) + ' KB'
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

const SOURCE_BADGE: Record<Dataset['source_type'], { label: string; cls: string }> = {
  alerts_db:       { label: 'アラートDB',         cls: 'bg-blue-900/50 text-blue-300 border border-blue-700/50' },
  endpoint_events: { label: 'エンドポイント',       cls: 'bg-green-900/50 text-green-300 border border-green-700/50' },
  network_flows:   { label: 'ネットワーク',         cls: 'bg-orange-900/50 text-orange-300 border border-orange-700/50' },
  vuln_scans:      { label: '脆弱性スキャン',        cls: 'bg-purple-900/50 text-purple-300 border border-purple-700/50' },
}

const STATUS_DOT: Record<Dataset['status'], string> = {
  active:   'bg-green-400',
  indexing: 'bg-yellow-400 animate-pulse',
  error:    'bg-red-400',
}

const HISTORY_BADGE: Record<QueryHistory['status'], { label: string; cls: string }> = {
  pending:   { label: '待機中', cls: 'bg-gray-800 text-gray-400 border border-gray-600' },
  running:   { label: '実行中', cls: 'bg-blue-900/50 text-blue-300 border border-blue-700/50 animate-pulse' },
  completed: { label: '完了',   cls: 'bg-green-900/50 text-green-300 border border-green-700/50' },
  failed:    { label: '失敗',   cls: 'bg-red-900/50 text-red-300 border border-red-700/50' },
}

const DEFAULT_QUERY = `SELECT severity, COUNT(*) as cnt
FROM alerts
WHERE created_at > NOW() - INTERVAL 7 DAY
GROUP BY severity
ORDER BY cnt DESC;`

// ─── メインページ ─────────────────────────────────────────────────────────────

export default function SecurityDWPage() {
  const [selectedDataset, setSelectedDataset] = useState<Dataset | null>(null)
  const [queryText, setQueryText] = useState(DEFAULT_QUERY)
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null)

  const { data: datasets = [] } = useQuery<Dataset[]>({
    queryKey: ['dw-datasets'],
    queryFn: () => apiFetchList<Dataset>('/api/v1/admin/dw/datasets').catch(() => []),
  })

  const { data: history = [] } = useQuery<QueryHistory[]>({
    queryKey: ['dw-query-history'],
    queryFn: () => apiFetchList<QueryHistory>('/api/v1/admin/dw/queries').catch(() => []),
  })

  const runQuery = useMutation({
    mutationFn: () => apiFetch<QueryResult>('/api/v1/admin/dw/query', { method: 'POST', body: JSON.stringify({ query: queryText, dataset_id: selectedDataset?.id }) }).catch(() => null),
    onSuccess: (data) => setQueryResult(data),
  })

  const totalRecords = datasets.reduce((s, d) => s + d.row_count, 0)
  const totalStorage = datasets.reduce((s, d) => s + d.size_bytes, 0)

  const downloadCSV = () => {
    if (!queryResult) return
    const header = queryResult.columns.join(',')
    const rows = queryResult.rows.map(r => queryResult.columns.map(c => r[c]).join(',')).join('\n')
    const blob = new Blob([header + '\n' + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'query_result.csv'; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* ヘッダー */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <Database className="w-6 h-6 text-falcon-red" />
          <h1 className="text-2xl font-bold">セキュリティデータウェアハウス</h1>
        </div>
        <p className="text-falcon-muted text-sm">セキュリティデータの集中管理・分析クエリ実行</p>
      </div>

      {/* 統計行 */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {[
          { icon: <Database className="w-4 h-4" />, label: 'データセット数', value: '4' },
          { icon: <FileText className="w-4 h-4" />, label: '総レコード', value: formatRowCount(totalRecords) },
          { icon: <HardDrive className="w-4 h-4" />, label: '総ストレージ', value: '542.5 GB' },
          { icon: <Zap className="w-4 h-4" />, label: 'クエリ/日', value: '47' },
          { icon: <Clock className="w-4 h-4" />, label: '平均クエリ時間', value: '1.8秒' },
        ].map((s, i) => (
          <div key={i} className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-3">
            <div className="text-falcon-red">{s.icon}</div>
            <div>
              <p className="text-falcon-muted text-xs">{s.label}</p>
              <p className="text-white font-bold text-lg">{s.value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* メイン2カラム */}
      <div className="flex gap-4 mb-6">
        {/* 左パネル: データセット一覧 (40%) */}
        <div className="w-[40%] bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <h2 className="text-sm font-semibold text-falcon-muted uppercase tracking-wider mb-3">データセット一覧</h2>
          <div className="space-y-3">
            {datasets.map(ds => {
              const badge = SOURCE_BADGE[ds.source_type]
              const isSelected = selectedDataset?.id === ds.id
              return (
                <div
                  key={ds.id}
                  onClick={() => setSelectedDataset(ds)}
                  className={`border rounded-lg p-3 cursor-pointer transition-colors ${isSelected ? 'border-falcon-red bg-falcon-red/5' : 'border-falcon-border hover:border-[#2e4060]'}`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className="text-white font-medium text-sm">{ds.name}</span>
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${STATUS_DOT[ds.status]}`} />
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${badge.cls}`}>{badge.label}</span>
                  <div className="grid grid-cols-3 gap-2 mt-2 text-xs text-falcon-muted">
                    <div><span className="block text-white font-medium">{formatRowCount(ds.row_count)}</span>レコード</div>
                    <div><span className="block text-white font-medium">{formatSize(ds.size_bytes)}</span>ストレージ</div>
                    <div><span className="block text-white font-medium">{ds.retention_days}日</span>保持期間</div>
                  </div>
                  <p className="text-xs text-falcon-muted mt-1">最終取込: {fmtDate(ds.last_ingested_at)}</p>
                </div>
              )
            })}
          </div>
        </div>

        {/* 右パネル: クエリインターフェース (60%) */}
        <div className="w-[60%] bg-falcon-surface border border-falcon-border rounded-lg p-4 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-falcon-muted uppercase tracking-wider">クエリ実行</h2>
            {selectedDataset && (
              <span className="text-xs text-falcon-muted bg-falcon-border px-2 py-1 rounded-sm">
                クエリ対象: <span className="text-white">{selectedDataset.name}</span>
              </span>
            )}
          </div>
          <textarea
            value={queryText}
            onChange={e => setQueryText(e.target.value)}
            className="w-full h-36 bg-[#070d19] border border-falcon-border rounded-lg p-3 text-white font-mono text-sm resize-none focus:outline-hidden focus:border-falcon-red/50"
            spellCheck={false}
          />
          <button
            onClick={() => runQuery.mutate()}
            disabled={runQuery.isPending}
            className="flex items-center gap-2 bg-falcon-red hover:bg-[#c0001f] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium self-start transition-colors"
          >
            {runQuery.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            クエリ実行
          </button>

          {/* 結果エリア */}
          {queryResult && (
            <div className="border border-falcon-border rounded-lg p-3">
              <div className="flex items-center justify-between mb-3">
                <div className="flex gap-4 text-sm">
                  <span className="text-falcon-muted">返行数: <span className="text-white font-medium">{(queryResult.rows_returned ?? 0).toLocaleString()}</span></span>
                  <span className="text-falcon-muted">実行時間: <span className="text-white font-medium">{queryResult.execution_ms}ms</span></span>
                </div>
                <button onClick={downloadCSV} className="flex items-center gap-1.5 text-xs bg-falcon-border hover:bg-[#2e4060] px-3 py-1.5 rounded-sm text-falcon-muted hover:text-white transition-colors">
                  <Download className="w-3 h-3" /> CSVダウンロード
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-falcon-border">
                      {queryResult.columns.map(c => <th key={c} className="text-left text-falcon-muted font-medium pb-2 pr-4">{c}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {queryResult.rows.slice(0, 10).map((row, i) => (
                      <tr key={i} className="border-b border-falcon-border/50">
                        {queryResult.columns.map(c => <td key={c} className="py-1.5 pr-4 text-white">{String(row[c])}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* クエリ履歴 */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
        <h2 className="text-sm font-semibold text-falcon-muted uppercase tracking-wider mb-3">クエリ履歴</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-falcon-border">
              {['クエリ', 'ステータス', '返行数', '実行時間', '実行日時'].map(h => (
                <th key={h} className="text-left text-falcon-muted font-medium pb-2 pr-4">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {history.map(q => {
              const badge = HISTORY_BADGE[q.status]
              return (
                <tr key={q.id} className="border-b border-falcon-border/50 hover:bg-falcon-border/20 transition-colors">
                  <td className="py-2 pr-4 text-white font-mono text-xs max-w-xs truncate">{q.query_text}</td>
                  <td className="py-2 pr-4"><span className={`text-xs px-2 py-0.5 rounded-full ${badge.cls}`}>{badge.label}</span></td>
                  <td className="py-2 pr-4 text-falcon-muted">{q.rows_returned != null ? (q.rows_returned ?? 0).toLocaleString() : '—'}</td>
                  <td className="py-2 pr-4 text-falcon-muted">{q.execution_ms != null ? `${q.execution_ms}ms` : '—'}</td>
                  <td className="py-2 pr-4 text-falcon-muted">{fmtDate(q.executed_at)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
