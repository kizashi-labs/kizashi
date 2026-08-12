'use client'

import { useState, useCallback, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Download, ShieldAlert, Activity, Monitor, ClipboardList,
  Network, Cpu, FileJson, FileText, Database,
  CheckSquare, Square as SquareIcon, Calendar, Hash, ChevronRight,
  Loader2, AlertCircle, CheckCircle, Clock, Trash2, X, Info
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type DataType = 'alerts' | 'events' | 'agents' | 'audit_logs' | 'network_connections' | 'processes'
type ExportFormat = 'csv' | 'json' | 'ndjson'

interface ExportConfig {
  data_type: DataType
  format: ExportFormat
  from: string
  to: string
  limit: number
  columns: string[]
}

interface ExportStatusResponse {
  estimated_count: number
  available: boolean
}

interface ExportHistoryEntry {
  id: string
  data_type: DataType
  format: ExportFormat
  count: number
  timestamp: string
  filename: string
}

// ── Data type definitions ─────────────────────────────────────────────────────

const DATA_TYPES: {
  id: DataType
  label: string
  labelJa: string
  icon: React.ComponentType<{ className?: string }>
  description: string
  columns: { id: string; label: string; default: boolean }[]
}[] = [
  {
    id: 'alerts',
    label: 'Alerts',
    labelJa: 'アラート',
    icon: ShieldAlert,
    description: '検知アラートとその詳細情報',
    columns: [
      { id: 'id', label: 'ID', default: true },
      { id: 'title', label: 'タイトル', default: true },
      { id: 'severity', label: '深刻度', default: true },
      { id: 'status', label: 'ステータス', default: true },
      { id: 'agent_hostname', label: 'エンドポイント', default: true },
      { id: 'rule_name', label: 'ルール名', default: true },
      { id: 'created_at', label: '発生日時', default: true },
      { id: 'resolved_at', label: '解決日時', default: false },
      { id: 'assignee', label: '担当者', default: false },
      { id: 'mitre_attack', label: 'MITRE ATT&CK', default: false },
      { id: 'description', label: '説明', default: false },
      { id: 'raw_data', label: '生データ', default: false },
    ],
  },
  {
    id: 'events',
    label: 'Events',
    labelJa: 'イベント',
    icon: Activity,
    description: 'エンドポイントイベントログ',
    columns: [
      { id: 'id', label: 'ID', default: true },
      { id: 'event_type', label: 'イベント種別', default: true },
      { id: 'agent_hostname', label: 'エンドポイント', default: true },
      { id: 'process_name', label: 'プロセス名', default: true },
      { id: 'process_path', label: 'プロセスパス', default: false },
      { id: 'pid', label: 'PID', default: true },
      { id: 'user', label: 'ユーザー', default: true },
      { id: 'timestamp', label: '日時', default: true },
      { id: 'severity', label: '深刻度', default: false },
      { id: 'details', label: '詳細', default: false },
    ],
  },
  {
    id: 'agents',
    label: 'Agents',
    labelJa: 'エージェント',
    icon: Monitor,
    description: 'エンドポイントエージェント情報',
    columns: [
      { id: 'id', label: 'ID', default: true },
      { id: 'hostname', label: 'ホスト名', default: true },
      { id: 'os', label: 'OS', default: true },
      { id: 'os_version', label: 'OSバージョン', default: true },
      { id: 'status', label: 'ステータス', default: true },
      { id: 'ip_address', label: 'IPアドレス', default: true },
      { id: 'version', label: 'エージェントバージョン', default: false },
      { id: 'last_seen', label: '最終接続', default: true },
      { id: 'enrolled_at', label: '登録日時', default: false },
      { id: 'groups', label: 'グループ', default: false },
      { id: 'tags', label: 'タグ', default: false },
    ],
  },
  {
    id: 'audit_logs',
    label: 'Audit Logs',
    labelJa: '監査ログ',
    icon: ClipboardList,
    description: 'ユーザー操作の監査ログ',
    columns: [
      { id: 'id', label: 'ID', default: true },
      { id: 'user', label: 'ユーザー', default: true },
      { id: 'action', label: 'アクション', default: true },
      { id: 'resource_type', label: 'リソース種別', default: true },
      { id: 'resource_id', label: 'リソースID', default: true },
      { id: 'ip_address', label: 'IPアドレス', default: true },
      { id: 'user_agent', label: 'User Agent', default: false },
      { id: 'status', label: '結果', default: true },
      { id: 'timestamp', label: '日時', default: true },
      { id: 'details', label: '詳細', default: false },
    ],
  },
  {
    id: 'network_connections',
    label: 'Network Connections',
    labelJa: 'ネットワーク接続',
    icon: Network,
    description: 'ネットワーク接続イベント',
    columns: [
      { id: 'id', label: 'ID', default: true },
      { id: 'agent_hostname', label: 'エンドポイント', default: true },
      { id: 'src_ip', label: '送信元IP', default: true },
      { id: 'src_port', label: '送信元ポート', default: true },
      { id: 'dst_ip', label: '宛先IP', default: true },
      { id: 'dst_port', label: '宛先ポート', default: true },
      { id: 'protocol', label: 'プロトコル', default: true },
      { id: 'process_name', label: 'プロセス名', default: true },
      { id: 'bytes_sent', label: '送信バイト', default: false },
      { id: 'bytes_recv', label: '受信バイト', default: false },
      { id: 'timestamp', label: '日時', default: true },
      { id: 'direction', label: '方向', default: false },
    ],
  },
  {
    id: 'processes',
    label: 'Processes',
    labelJa: 'プロセス',
    icon: Cpu,
    description: 'プロセス起動・終了イベント',
    columns: [
      { id: 'id', label: 'ID', default: true },
      { id: 'agent_hostname', label: 'エンドポイント', default: true },
      { id: 'name', label: 'プロセス名', default: true },
      { id: 'path', label: 'パス', default: true },
      { id: 'pid', label: 'PID', default: true },
      { id: 'ppid', label: '親PID', default: false },
      { id: 'user', label: 'ユーザー', default: true },
      { id: 'command_line', label: 'コマンドライン', default: true },
      { id: 'hash_md5', label: 'MD5', default: false },
      { id: 'hash_sha256', label: 'SHA256', default: false },
      { id: 'started_at', label: '起動日時', default: true },
      { id: 'ended_at', label: '終了日時', default: false },
    ],
  },
]

// ── History helpers ───────────────────────────────────────────────────────────

const HISTORY_KEY = 'edr_export_history'

function getHistory(): ExportHistoryEntry[] {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]')
  } catch {
    return []
  }
}

function pushHistory(entry: Omit<ExportHistoryEntry, 'id'>) {
  const history = getHistory()
  const newEntry: ExportHistoryEntry = { ...entry, id: crypto.randomUUID() }
  const updated = [newEntry, ...history].slice(0, 10)
  localStorage.setItem(HISTORY_KEY, JSON.stringify(updated))
  return updated
}

function clearHistory() {
  localStorage.removeItem(HISTORY_KEY)
}

// ── Step indicator ────────────────────────────────────────────────────────────

function StepIndicator({ current, steps }: { current: number; steps: string[] }) {
  return (
    <div className="flex items-center gap-0 mb-8">
      {steps.map((label, i) => {
        const stepNum = i + 1
        const done = stepNum < current
        const active = stepNum === current
        return (
          <div key={label} className="flex items-center">
            <div className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-all ${
              active ? 'bg-[#e8002d]/15 border border-[#e8002d]/30' :
              done   ? 'bg-green-500/10 border border-green-500/20' :
                       'bg-[#0d1220] border border-[#1e2d42]'
            }`}>
              <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                active ? 'bg-[#e8002d] text-white' :
                done   ? 'bg-green-500 text-white' :
                         'bg-[#1e2d42] text-[#7d92b0]'
              }`}>
                {done ? <CheckCircle className="w-3.5 h-3.5" /> : stepNum}
              </div>
              <span className={`text-sm font-medium ${
                active ? 'text-white' : done ? 'text-green-400' : 'text-[#7d92b0]'
              }`}>{label}</span>
            </div>
            {i < steps.length - 1 && (
              <ChevronRight className={`w-4 h-4 mx-1 flex-shrink-0 ${
                done ? 'text-green-400' : 'text-[#3d5068]'
              }`} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ExportCenterPage() {
  const [step, setStep] = useState(1)
  const [selectedType, setSelectedType] = useState<DataType | null>(null)
  const [format, setFormat] = useState<ExportFormat>('csv')
  const [fromDate, setFromDate] = useState(() => {
    const d = new Date()
    d.setDate(d.getDate() - 7)
    return d.toISOString().slice(0, 16)
  })
  const [toDate, setToDate] = useState(() => new Date().toISOString().slice(0, 16))
  const [limit, setLimit] = useState(10000)
  const [selectedColumns, setSelectedColumns] = useState<string[]>([])
  const [isExporting, setIsExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [exportSuccess, setExportSuccess] = useState<string | null>(null)
  const [history, setHistory] = useState<ExportHistoryEntry[]>([])

  // Load history from localStorage on mount
  useEffect(() => {
    setHistory(getHistory())
  }, [])

  // When data type changes, reset columns to defaults
  useEffect(() => {
    if (!selectedType) return
    const typeDef = DATA_TYPES.find(t => t.id === selectedType)
    if (typeDef) {
      setSelectedColumns(typeDef.columns.filter(c => c.default).map(c => c.id))
    }
  }, [selectedType])

  // ── Status estimate ─────────────────────────────────────────────────────────
  const { data: statusData, isFetching: isStatusFetching } = useQuery<ExportStatusResponse>({
    queryKey: ['export-status', selectedType, fromDate, toDate],
    queryFn: () => {
      const params = new URLSearchParams({
        data_type: selectedType!,
        from: new Date(fromDate).toISOString(),
        to: new Date(toDate).toISOString(),
      })
      return apiFetch(`/api/v1/export/status?${params.toString()}`)
    },
    enabled: !!selectedType && step >= 2,
    staleTime: 30_000,
  })

  // ── Column toggle ───────────────────────────────────────────────────────────
  const toggleColumn = (colId: string) => {
    setSelectedColumns(prev =>
      prev.includes(colId) ? prev.filter(c => c !== colId) : [...prev, colId]
    )
  }

  const toggleAllColumns = () => {
    if (!selectedType) return
    const typeDef = DATA_TYPES.find(t => t.id === selectedType)!
    const allIds = typeDef.columns.map(c => c.id)
    if (selectedColumns.length === allIds.length) {
      setSelectedColumns(typeDef.columns.filter(c => c.default).map(c => c.id))
    } else {
      setSelectedColumns(allIds)
    }
  }

  // ── Export action ───────────────────────────────────────────────────────────
  const handleExport = useCallback(async () => {
    if (!selectedType) return
    setIsExporting(true)
    setExportError(null)
    setExportSuccess(null)

    try {
      const typeDef = DATA_TYPES.find(t => t.id === selectedType)!
      const payload = {
        data_type: selectedType,
        format,
        from: new Date(fromDate).toISOString(),
        to: new Date(toDate).toISOString(),
        limit: Math.min(limit, 50000),
        columns: selectedColumns,
      }

      const response = await fetch('/api/v1/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        credentials: 'include',
      })

      if (!response.ok) {
        const errText = await response.text()
        throw new Error(errText || `HTTP ${response.status}`)
      }

      const blob = await response.blob()
      const contentDisp = response.headers.get('content-disposition') ?? ''
      const filenameMatch = contentDisp.match(/filename="?([^";\n]+)"?/)
      const ext = format === 'csv' ? 'csv' : format === 'ndjson' ? 'ndjson' : 'json'
      const filename = filenameMatch?.[1] ?? `${selectedType}_export_${Date.now()}.${ext}`

      // Trigger browser download
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      // Save to history
      const count = statusData?.estimated_count ?? 0
      const newHistory = pushHistory({
        data_type: selectedType,
        format,
        count,
        timestamp: new Date().toISOString(),
        filename,
      })
      setHistory(newHistory)
      setExportSuccess(`${filename} のダウンロードを開始しました`)
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'エクスポートに失敗しました')
    } finally {
      setIsExporting(false)
    }
  }, [selectedType, format, fromDate, toDate, limit, selectedColumns, statusData])

  // ── Selected type definition ────────────────────────────────────────────────
  const currentTypeDef = selectedType ? DATA_TYPES.find(t => t.id === selectedType) : null
  const allColumns = currentTypeDef?.columns ?? []

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-xl bg-[#e8002d]/15 border border-[#e8002d]/20 flex items-center justify-center">
          <Download className="w-5 h-5 text-[#e8002d]" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">エクスポートセンター</h1>
          <p className="text-[#7d92b0] text-sm">各種データをCSV / JSON / NDJSONでエクスポートします</p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-6">
        {/* ── Main wizard ────────────────────────────────────────────────────── */}
        <div>
          <StepIndicator current={step} steps={['データ種別', '設定', 'ダウンロード']} />

          {/* Step 1 — Data type selector */}
          {step === 1 && (
            <div>
              <h2 className="text-white font-semibold text-base mb-4">エクスポートするデータ種別を選択してください</h2>
              <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
                {DATA_TYPES.map(type => {
                  const Icon = type.icon
                  const selected = selectedType === type.id
                  return (
                    <button
                      key={type.id}
                      onClick={() => setSelectedType(type.id)}
                      className={`flex flex-col items-start gap-3 p-5 rounded-xl border text-left
                                  transition-all duration-150 group
                                  ${selected
                                    ? 'bg-[#e8002d]/10 border-[#e8002d]/50 shadow-[0_0_0_1px_#e8002d33]'
                                    : 'bg-[#0d1220] border-[#1e2d42] hover:border-[#7d92b0]/30 hover:bg-[#19253d]/40'
                                  }`}
                    >
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center transition-colors ${
                        selected ? 'bg-[#e8002d]/20' : 'bg-[#1e2d42] group-hover:bg-[#1e2d42]'
                      }`}>
                        <Icon className={`w-5 h-5 ${selected ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`} />
                      </div>
                      <div>
                        <p className={`font-semibold text-sm ${selected ? 'text-white' : 'text-[#e2e8f4]'}`}>
                          {type.labelJa}
                        </p>
                        <p className="text-[#7d92b0] text-xs mt-0.5 leading-relaxed">{type.description}</p>
                      </div>
                      {selected && (
                        <div className="ml-auto self-end">
                          <CheckCircle className="w-4 h-4 text-[#e8002d]" />
                        </div>
                      )}
                    </button>
                  )
                })}
              </div>

              <div className="mt-6 flex justify-end">
                <button
                  onClick={() => setStep(2)}
                  disabled={!selectedType}
                  className="flex items-center gap-2 px-6 py-2.5 rounded-lg
                             bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-40 disabled:cursor-not-allowed
                             text-white text-sm font-semibold transition-all"
                >
                  次へ
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Step 2 — Configure */}
          {step === 2 && currentTypeDef && (
            <div className="space-y-6">
              <div className="flex items-center gap-3 mb-2">
                <currentTypeDef.icon className="w-5 h-5 text-[#e8002d]" />
                <h2 className="text-white font-semibold text-base">{currentTypeDef.labelJa} のエクスポート設定</h2>
              </div>

              {/* Format */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-4 flex items-center gap-2">
                  <FileJson className="w-4 h-4" />
                  出力フォーマット
                </h3>
                <div className="flex gap-3 flex-wrap">
                  {([
                    { id: 'csv' as const, label: 'CSV', desc: 'スプレッドシート対応', icon: FileText },
                    { id: 'json' as const, label: 'JSON', desc: '構造化データ', icon: FileJson },
                    { id: 'ndjson' as const, label: 'NDJSON', desc: '1行1レコード', icon: Database },
                  ]).map(f => {
                    const FIcon = f.icon
                    const selected = format === f.id
                    return (
                      <button
                        key={f.id}
                        onClick={() => setFormat(f.id)}
                        className={`flex items-center gap-3 px-4 py-3 rounded-xl border transition-all
                                    ${selected
                                      ? 'bg-[#e8002d]/10 border-[#e8002d]/50 text-white'
                                      : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/30'
                                    }`}
                      >
                        <FIcon className={`w-4 h-4 ${selected ? 'text-[#e8002d]' : ''}`} />
                        <div className="text-left">
                          <p className={`text-sm font-semibold ${selected ? 'text-white' : ''}`}>{f.label}</p>
                          <p className="text-xs text-[#7d92b0]">{f.desc}</p>
                        </div>
                        {selected && <CheckCircle className="w-4 h-4 text-[#e8002d] ml-2" />}
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Date range */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Calendar className="w-4 h-4" />
                  期間
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1.5">開始日時</label>
                    <input
                      type="datetime-local"
                      value={fromDate}
                      onChange={e => setFromDate(e.target.value)}
                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                                 text-[#e2e8f4] text-sm focus:outline-none focus:border-[#e8002d]/50
                                 focus:ring-1 focus:ring-[#e8002d]/20 [color-scheme:dark]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1.5">終了日時</label>
                    <input
                      type="datetime-local"
                      value={toDate}
                      onChange={e => setToDate(e.target.value)}
                      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                                 text-[#e2e8f4] text-sm focus:outline-none focus:border-[#e8002d]/50
                                 focus:ring-1 focus:ring-[#e8002d]/20 [color-scheme:dark]"
                    />
                  </div>
                </div>
              </div>

              {/* Limit */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Hash className="w-4 h-4" />
                  最大レコード数
                </h3>
                <div className="flex items-center gap-4">
                  <input
                    type="number"
                    value={limit}
                    onChange={e => setLimit(Math.min(50000, Math.max(1, parseInt(e.target.value) || 1)))}
                    min={1}
                    max={50000}
                    className="w-48 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5
                               text-[#e2e8f4] text-sm focus:outline-none focus:border-[#e8002d]/50"
                  />
                  <div className="flex-1">
                    <input
                      type="range"
                      min={1000}
                      max={50000}
                      step={1000}
                      value={limit}
                      onChange={e => setLimit(parseInt(e.target.value))}
                      className="w-full accent-[#e8002d]"
                    />
                    <div className="flex justify-between text-xs text-[#3d5068] mt-1">
                      <span>1,000</span>
                      <span>25,000</span>
                      <span>50,000</span>
                    </div>
                  </div>
                </div>
                <p className="text-[#3d5068] text-xs mt-2 flex items-center gap-1.5">
                  <Info className="w-3 h-3" />
                  最大 50,000 レコードまでエクスポートできます
                </p>
              </div>

              {/* Column selector */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                    <CheckSquare className="w-4 h-4" />
                    出力カラム
                  </h3>
                  <button
                    onClick={toggleAllColumns}
                    className="text-xs text-[#e8002d] hover:text-[#ff1a44] transition-colors font-medium"
                  >
                    {selectedColumns.length === allColumns.length ? '必須のみ' : '全て選択'}
                  </button>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {allColumns.map(col => {
                    const checked = selectedColumns.includes(col.id)
                    return (
                      <button
                        key={col.id}
                        onClick={() => toggleColumn(col.id)}
                        className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-left text-sm
                                    transition-all ${
                          checked
                            ? 'bg-[#e8002d]/10 border-[#e8002d]/30 text-white'
                            : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/30'
                        }`}
                      >
                        {checked
                          ? <CheckSquare className="w-3.5 h-3.5 text-[#e8002d] flex-shrink-0" />
                          : <SquareIcon className="w-3.5 h-3.5 text-[#3d5068] flex-shrink-0" />
                        }
                        <span className="truncate text-xs">{col.label}</span>
                      </button>
                    )
                  })}
                </div>
                <p className="text-[#3d5068] text-xs mt-3">
                  {selectedColumns.length} / {allColumns.length} カラム選択中
                </p>
              </div>

              {/* Navigation */}
              <div className="flex justify-between">
                <button
                  onClick={() => setStep(1)}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg border border-[#1e2d42]
                             text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 transition-all text-sm font-medium"
                >
                  戻る
                </button>
                <button
                  onClick={() => setStep(3)}
                  disabled={selectedColumns.length === 0}
                  className="flex items-center gap-2 px-6 py-2.5 rounded-lg
                             bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-40 disabled:cursor-not-allowed
                             text-white text-sm font-semibold transition-all"
                >
                  次へ
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* Step 3 — Download */}
          {step === 3 && currentTypeDef && (
            <div className="space-y-6">
              <h2 className="text-white font-semibold text-base mb-2">エクスポートの確認とダウンロード</h2>

              {/* Summary */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wider mb-4">設定サマリー</h3>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: 'データ種別', value: currentTypeDef.labelJa },
                    { label: 'フォーマット', value: format.toUpperCase() },
                    { label: '開始日時', value: new Date(fromDate).toLocaleString('ja-JP') },
                    { label: '終了日時', value: new Date(toDate).toLocaleString('ja-JP') },
                    { label: '最大レコード数', value: limit.toLocaleString() },
                    { label: 'カラム数', value: `${selectedColumns.length}カラム` },
                  ].map(({ label, value }) => (
                    <div key={label} className="flex flex-col gap-0.5">
                      <span className="text-[#7d92b0] text-xs">{label}</span>
                      <span className="text-white text-sm font-medium">{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Estimate */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-1">推定レコード数</p>
                    {isStatusFetching ? (
                      <div className="flex items-center gap-2">
                        <Loader2 className="w-4 h-4 text-[#e8002d] animate-spin" />
                        <span className="text-[#7d92b0] text-sm">推計中...</span>
                      </div>
                    ) : (
                      <p className="text-2xl font-bold text-white">
                        {statusData?.estimated_count?.toLocaleString() ?? '—'}
                        <span className="text-[#7d92b0] text-sm font-normal ml-2">件</span>
                      </p>
                    )}
                  </div>
                  <div className={`px-3 py-1.5 rounded-lg text-xs font-medium border ${
                    statusData?.available
                      ? 'bg-green-500/10 border-green-500/30 text-green-400'
                      : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
                  }`}>
                    {statusData?.available ? '利用可能' : '要確認'}
                  </div>
                </div>
              </div>

              {/* Export button */}
              <button
                onClick={handleExport}
                disabled={isExporting || selectedColumns.length === 0}
                className="w-full flex items-center justify-center gap-3 px-6 py-4 rounded-xl
                           bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 disabled:cursor-not-allowed
                           text-white font-bold text-base transition-all shadow-[0_0_20px_#e8002d33]"
              >
                {isExporting ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    エクスポート中...
                  </>
                ) : (
                  <>
                    <Download className="w-5 h-5" />
                    エクスポートしてダウンロード
                  </>
                )}
              </button>

              {/* Success */}
              {exportSuccess && (
                <div className="flex items-center gap-3 px-4 py-3 rounded-xl
                                bg-green-900/40 border border-green-500/30 text-green-300 text-sm">
                  <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                  {exportSuccess}
                  <button onClick={() => setExportSuccess(null)} className="ml-auto text-green-400 hover:text-white">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}

              {/* Error */}
              {exportError && (
                <div className="flex items-center gap-3 px-4 py-3 rounded-xl
                                bg-red-900/40 border border-red-500/30 text-red-300 text-sm">
                  <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                  {exportError}
                  <button onClick={() => setExportError(null)} className="ml-auto text-red-400 hover:text-white">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}

              {/* Navigation */}
              <div className="flex justify-start">
                <button
                  onClick={() => setStep(2)}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg border border-[#1e2d42]
                             text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 transition-all text-sm font-medium"
                >
                  戻る
                </button>
              </div>
            </div>
          )}
        </div>

        {/* ── Export History sidebar ──────────────────────────────────────────── */}
        <div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden sticky top-6">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#7d92b0]" />
                <h3 className="text-white font-semibold text-sm">エクスポート履歴</h3>
              </div>
              {history.length > 0 && (
                <button
                  onClick={() => { clearHistory(); setHistory([]) }}
                  className="text-[#3d5068] hover:text-red-400 transition-colors"
                  title="履歴をクリア"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>

            {history.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <Download className="w-8 h-8 text-[#3d5068]" />
                <p className="text-[#7d92b0] text-sm text-center px-4">
                  エクスポート履歴がありません
                </p>
              </div>
            ) : (
              <div className="divide-y divide-[#1e2d42]/50">
                {history.map(entry => {
                  const typeDef = DATA_TYPES.find(t => t.id === entry.data_type)
                  const Icon = typeDef?.icon ?? Download
                  return (
                    <div key={entry.id} className="px-5 py-4 hover:bg-[#19253d]/30 transition-colors">
                      <div className="flex items-start gap-3">
                        <div className="w-8 h-8 rounded-lg bg-[#1e2d42] flex items-center justify-center flex-shrink-0 mt-0.5">
                          <Icon className="w-4 h-4 text-[#7d92b0]" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <p className="text-[#e2e8f4] text-sm font-medium truncate">
                            {typeDef?.labelJa ?? entry.data_type}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="px-1.5 py-0.5 rounded text-xs font-mono
                                             bg-[#1e2d42] text-[#7d92b0] border border-[#3d5068]/30">
                              {entry.format.toUpperCase()}
                            </span>
                            <span className="text-[#7d92b0] text-xs">
                              {(entry.count ?? 0).toLocaleString()} 件
                            </span>
                          </div>
                          <p className="text-[#3d5068] text-xs mt-1 truncate" title={entry.filename}>
                            {entry.filename}
                          </p>
                          <p className="text-[#3d5068] text-xs mt-0.5">
                            {new Date(entry.timestamp).toLocaleString('ja-JP', {
                              month: '2-digit', day: '2-digit',
                              hour: '2-digit', minute: '2-digit'
                            })}
                          </p>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}

            <div className="px-5 py-3 border-t border-[#1e2d42] bg-[#070d19]/50">
              <p className="text-[#3d5068] text-xs text-center">
                最大10件の履歴を保存 (ブラウザローカル)
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
