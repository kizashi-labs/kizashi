'use client'

import { useState, useRef, useCallback } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  UploadCloud, Download, FileJson, FileText, Info,
  CheckCircle2, XCircle, AlertTriangle, X, FileUp,
  ChevronDown, ChevronUp,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────────────────

type ExportFormat = 'json' | 'yaml' | 'sigma'
type RuleType = 'detection_rules' | 'process_block_rules' | 'suppression_rules' | 'fim_rules'

const RULE_TYPE_LABELS: Record<RuleType, string> = {
  detection_rules:     '検知ルール',
  process_block_rules: 'プロセスブロックルール',
  suppression_rules:   '抑制ルール',
  fim_rules:           'FIM ルール',
}

interface RuleCountsResponse {
  detection_rules?: number
  process_block_rules?: number
  suppression_rules?: number
  fim_rules?: number
}

interface DryRunResult {
  would_import: number
  would_skip: number
  errors: string[]
  breakdown: Partial<Record<RuleType, number>>
}

interface ImportResult {
  imported: number
  skipped: number
  errors: string[]
}

interface ImportHistoryEntry {
  id: string
  timestamp: string
  filename: string
  imported: number
  skipped: number
  status: 'success' | 'partial' | 'failed'
}

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtDateTime(s: string) {
  try {
    return new Date(s).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return s }
}

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

const FORMAT_ICONS: Record<ExportFormat, React.ReactNode> = {
  json:  <FileJson className="w-4 h-4" />,
  yaml:  <FileText className="w-4 h-4" />,
  sigma: <FileText className="w-4 h-4" />,
}

// ── Main Component ─────────────────────────────────────────────────────────

export default function RulesImportExportPage() {
  // ── Export state ────────────────────────────────────────────────────────
  const [exportFormat, setExportFormat] = useState<ExportFormat>('json')
  const [selectedTypes, setSelectedTypes] = useState<Set<RuleType>>(
    new Set(['detection_rules', 'process_block_rules', 'suppression_rules', 'fim_rules'])
  )
  const [exportLoading, setExportLoading] = useState(false)
  const [exportError, setExportError]     = useState<string | null>(null)

  // ── Import state ────────────────────────────────────────────────────────
  const [dragOver, setDragOver]           = useState(false)
  const [selectedFile, setSelectedFile]   = useState<File | null>(null)
  const [dryRunResult, setDryRunResult]   = useState<DryRunResult | null>(null)
  const [importResult, setImportResult]   = useState<ImportResult | null>(null)
  const [importError, setImportError]     = useState<string | null>(null)
  const fileInputRef                      = useRef<HTMLInputElement>(null)

  // ── Import history (session-only) ───────────────────────────────────────
  const [importHistory, setImportHistory] = useState<ImportHistoryEntry[]>([])
  const [showHistory, setShowHistory]     = useState(true)

  // ── Rule counts ─────────────────────────────────────────────────────────
  const { data: ruleCounts } = useQuery<RuleCountsResponse>({
    queryKey: ['rule-counts-export'],
    queryFn: () => apiFetch('/api/v1/rules/counts'),
    retry: false,
  })

  // ── Dry run mutation ────────────────────────────────────────────────────
  const dryRunMut = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
      const res = await fetch('/api/v1/rules/import/dry-run', {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`)
      }
      return res.json() as Promise<DryRunResult>
    },
    onSuccess: (data) => {
      setDryRunResult(data)
      setImportError(null)
    },
    onError: (err: Error) => {
      setImportError(err.message)
      setDryRunResult(null)
    },
  })

  // ── Import mutation ──────────────────────────────────────────────────────
  const importMut = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
      const res = await fetch('/api/v1/rules/import', {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`)
      }
      return res.json() as Promise<ImportResult>
    },
    onSuccess: (data, file) => {
      setImportResult(data)
      setImportError(null)
      const status: ImportHistoryEntry['status'] =
        data.errors.length > 0 && data.imported === 0
          ? 'failed'
          : data.errors.length > 0 || data.skipped > 0
            ? 'partial'
            : 'success'
      setImportHistory(prev => [
        {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          filename: file.name,
          imported: data.imported,
          skipped: data.skipped,
          status,
        },
        ...prev,
      ])
    },
    onError: (err: Error) => {
      setImportError(err.message)
      if (selectedFile) {
        setImportHistory(prev => [
          {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            filename: selectedFile.name,
            imported: 0,
            skipped: 0,
            status: 'failed',
          },
          ...prev,
        ])
      }
    },
  })

  // ── Export handler ───────────────────────────────────────────────────────
  async function handleExport() {
    if (selectedTypes.size === 0) return
    setExportLoading(true)
    setExportError(null)
    try {
      const typesParam = Array.from(selectedTypes).join(',')
      const url = `/api/v1/rules/export?format=${exportFormat}&types=${typesParam}`
      const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
      const res = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`)
      }
      const blob = await res.blob()
      const ext = exportFormat === 'json' ? 'json' : exportFormat === 'yaml' ? 'yaml' : 'yml'
      const filename = `edr-rules-${new Date().toISOString().slice(0, 10)}.${ext}`
      const objUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = objUrl
      a.download = filename
      a.click()
      URL.revokeObjectURL(objUrl)
    } catch (err) {
      setExportError((err as Error).message)
    } finally {
      setExportLoading(false)
    }
  }

  // ── File handling ────────────────────────────────────────────────────────
  function handleFileSelect(file: File) {
    setSelectedFile(file)
    setDryRunResult(null)
    setImportResult(null)
    setImportError(null)
  }

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) handleFileSelect(file)
  }

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleFileSelect(file)
  }, [])

  function clearFile() {
    setSelectedFile(null)
    setDryRunResult(null)
    setImportResult(null)
    setImportError(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  function toggleType(t: RuleType) {
    setSelectedTypes(prev => {
      const next = new Set(prev)
      if (next.has(t)) { next.delete(t) } else { next.add(t) }
      return next
    })
  }

  const totalExportCount = (Object.keys(RULE_TYPE_LABELS) as RuleType[])
    .filter(t => selectedTypes.has(t))
    .reduce((sum, t) => sum + (ruleCounts?.[t] ?? 0), 0)

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="bg-gray-900 min-h-screen text-white">
      <PageDataUnavailable />
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-6">

        {/* ── Header ───────────────────────────────────────────────────── */}
        <div>
          <h1 className="text-2xl font-bold text-white">ルール インポート/エクスポート</h1>
          <p className="text-sm text-[#8899aa] mt-1">
            検知ルール・ブロックルール・抑制ルール・FIM ルールのバックアップと復元
          </p>
        </div>

        {/* ── Two-column layout ─────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* ────────── LEFT: Export ──────────────────────────────────── */}
          <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-5 space-y-5">
            <div className="flex items-center gap-2.5 pb-3 border-b border-[#1e2d42]">
              <Download className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-semibold text-white">エクスポート</h2>
            </div>

            {/* Format selector */}
            <div>
              <label className="block text-xs text-[#8899aa] mb-2">エクスポート形式</label>
              <div className="grid grid-cols-3 gap-2">
                {(['json', 'yaml', 'sigma'] as ExportFormat[]).map(fmt => (
                  <button
                    key={fmt}
                    onClick={() => setExportFormat(fmt)}
                    className={`flex items-center justify-center gap-2 py-2 px-3 rounded-lg border text-sm font-medium transition-all ${
                      exportFormat === fmt
                        ? 'bg-blue-700 border-blue-500 text-white'
                        : 'bg-[#0e1624] border-[#1e2d42] text-[#8899aa] hover:border-[#2e3d52] hover:text-white'
                    }`}
                  >
                    {FORMAT_ICONS[fmt]}
                    {fmt.toUpperCase()}
                  </button>
                ))}
              </div>
              {(exportFormat === 'yaml' || exportFormat === 'sigma') && (
                <p className="mt-2 text-xs text-[#5a6a7a] flex items-center gap-1.5">
                  <Info className="w-3 h-3 shrink-0" />
                  YAMLおよびSigmaフォーマットはサーバー側で変換されます
                </p>
              )}
            </div>

            {/* Rule type checkboxes */}
            <div>
              <label className="block text-xs text-[#8899aa] mb-2">エクスポートするルール種別</label>
              <div className="space-y-2">
                {(Object.entries(RULE_TYPE_LABELS) as [RuleType, string][]).map(([type, label]) => {
                  const count = ruleCounts?.[type] ?? 0
                  const checked = selectedTypes.has(type)
                  return (
                    <label
                      key={type}
                      className="flex items-center justify-between gap-3 cursor-pointer group"
                    >
                      <div className="flex items-center gap-2.5">
                        <div
                          className={`w-4 h-4 rounded-sm border shrink-0 flex items-center justify-center transition-colors ${
                            checked
                              ? 'bg-blue-600 border-blue-500'
                              : 'border-[#2e3d52] bg-[#0e1624] group-hover:border-[#3e4d62]'
                          }`}
                          onClick={() => toggleType(type)}
                        >
                          {checked && (
                            <svg className="w-2.5 h-2.5 text-white" fill="none" viewBox="0 0 12 12">
                              <path d="M2 6l3 3 5-5" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                          )}
                        </div>
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleType(type)}
                          className="sr-only"
                        />
                        <span className="text-sm text-[#e2e8f4]">{label}</span>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded-sm font-mono ${
                        count > 0
                          ? 'bg-blue-900/40 text-blue-300 border border-blue-800/60'
                          : 'bg-[#0e1624] text-[#5a6a7a] border border-[#1e2d42]'
                      }`}>
                        {count} 件
                      </span>
                    </label>
                  )
                })}
              </div>
            </div>

            {/* Total count */}
            <div className="bg-[#0e1624] border border-[#1e2d42] rounded-lg px-4 py-2.5 flex items-center justify-between">
              <span className="text-xs text-[#8899aa]">エクスポート対象</span>
              <span className="text-sm font-bold text-white">{totalExportCount} ルール</span>
            </div>

            {/* Export error */}
            {exportError && (
              <div className="flex items-center gap-2 bg-red-900/30 border border-red-700/50 rounded-lg px-3 py-2 text-xs text-red-300">
                <XCircle className="w-3.5 h-3.5 shrink-0" />
                {exportError}
              </div>
            )}

            {/* Export button */}
            <button
              onClick={handleExport}
              disabled={exportLoading || selectedTypes.size === 0}
              className="w-full flex items-center justify-center gap-2 py-2.5 bg-blue-700 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
            >
              {exportLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  エクスポート中...
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  エクスポート
                </>
              )}
            </button>
          </div>

          {/* ────────── RIGHT: Import ──────────────────────────────────── */}
          <div className="bg-gray-800 border border-[#1e2d42] rounded-xl p-5 space-y-5">
            <div className="flex items-center gap-2.5 pb-3 border-b border-[#1e2d42]">
              <UploadCloud className="w-4 h-4 text-green-400" />
              <h2 className="text-sm font-semibold text-white">インポート</h2>
            </div>

            {/* Drop zone */}
            {!selectedFile ? (
              <div
                onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                  dragOver
                    ? 'border-green-500 bg-green-900/20'
                    : 'border-[#1e2d42] hover:border-[#2e3d52] hover:bg-[#0e1624]/60'
                }`}
              >
                <FileUp className={`w-10 h-10 mx-auto mb-3 ${dragOver ? 'text-green-400' : 'text-[#3d4f63]'}`} />
                <p className="text-sm text-[#8899aa]">
                  ファイルをドラッグ&ドロップ<br />
                  <span className="text-[#5a6a7a] text-xs">または</span>
                </p>
                <span className="mt-2 inline-block text-xs text-blue-400 hover:text-blue-300">
                  クリックしてファイルを選択
                </span>
                <p className="text-[10px] text-[#3d4f63] mt-2">対応形式: .json / .yaml / .yml</p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.yaml,.yml"
                  onChange={handleInputChange}
                  className="hidden"
                />
              </div>
            ) : (
              /* File preview */
              <div className="bg-[#0e1624] border border-[#1e2d42] rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div className="w-8 h-8 bg-blue-900/50 rounded-lg flex items-center justify-center shrink-0">
                      <FileJson className="w-4 h-4 text-blue-400" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm text-white truncate font-medium">{selectedFile.name}</p>
                      <p className="text-xs text-[#5a6a7a]">{formatFileSize(selectedFile.size)}</p>
                    </div>
                  </div>
                  <button
                    onClick={clearFile}
                    className="p-1 text-[#5a6a7a] hover:text-white transition-colors shrink-0"
                    title="ファイルを削除"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Dry run result */}
                {dryRunResult && (
                  <div className="bg-[#111827] border border-[#1e2d42] rounded-lg p-3 space-y-2">
                    <p className="text-xs font-semibold text-[#8899aa]">ドライラン結果</p>
                    <div className="grid grid-cols-3 gap-2">
                      <div className="text-center">
                        <p className="text-lg font-bold text-green-400">{dryRunResult.would_import}</p>
                        <p className="text-[10px] text-[#5a6a7a]">インポート予定</p>
                      </div>
                      <div className="text-center">
                        <p className="text-lg font-bold text-yellow-400">{dryRunResult.would_skip}</p>
                        <p className="text-[10px] text-[#5a6a7a]">スキップ予定</p>
                      </div>
                      <div className="text-center">
                        <p className="text-lg font-bold text-red-400">{dryRunResult.errors.length}</p>
                        <p className="text-[10px] text-[#5a6a7a]">エラー</p>
                      </div>
                    </div>
                    {Object.entries(dryRunResult.breakdown).filter(([, v]) => (v ?? 0) > 0).map(([type, count]) => (
                      <div key={type} className="flex justify-between text-[11px] text-[#8899aa]">
                        <span>{RULE_TYPE_LABELS[type as RuleType] ?? type}</span>
                        <span className="text-white">{count} 件</span>
                      </div>
                    ))}
                    {dryRunResult.errors.length > 0 && (
                      <div className="space-y-1">
                        {dryRunResult.errors.slice(0, 3).map((err, i) => (
                          <p key={i} className="text-[11px] text-red-400">• {err}</p>
                        ))}
                        {dryRunResult.errors.length > 3 && (
                          <p className="text-[11px] text-[#5a6a7a]">他 {dryRunResult.errors.length - 3} 件のエラー</p>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Import result */}
                {importResult && (
                  <div className={`border rounded-lg p-3 space-y-1 ${
                    importResult.errors.length === 0
                      ? 'bg-green-900/20 border-green-700/50'
                      : 'bg-yellow-900/20 border-yellow-700/50'
                  }`}>
                    <div className="flex items-center gap-2">
                      {importResult.errors.length === 0 ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
                      )}
                      <p className="text-xs font-semibold text-white">インポート完了</p>
                    </div>
                    <div className="grid grid-cols-3 gap-2 mt-2">
                      <div className="text-center">
                        <p className="text-lg font-bold text-green-400">{importResult.imported}</p>
                        <p className="text-[10px] text-[#5a6a7a]">インポート成功</p>
                      </div>
                      <div className="text-center">
                        <p className="text-lg font-bold text-yellow-400">{importResult.skipped}</p>
                        <p className="text-[10px] text-[#5a6a7a]">スキップ (重複)</p>
                      </div>
                      <div className="text-center">
                        <p className="text-lg font-bold text-red-400">{importResult.errors.length}</p>
                        <p className="text-[10px] text-[#5a6a7a]">エラー</p>
                      </div>
                    </div>
                    {importResult.errors.length > 0 && (
                      <div className="mt-1 space-y-0.5">
                        {importResult.errors.slice(0, 3).map((err, i) => (
                          <p key={i} className="text-[11px] text-red-400">• {err}</p>
                        ))}
                        {importResult.errors.length > 3 && (
                          <p className="text-[11px] text-[#5a6a7a]">他 {importResult.errors.length - 3} 件</p>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Import error */}
                {importError && (
                  <div className="flex items-start gap-2 bg-red-900/30 border border-red-700/50 rounded-lg px-3 py-2 text-xs text-red-300">
                    <XCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    {importError}
                  </div>
                )}
              </div>
            )}

            {/* Action buttons */}
            {selectedFile && !importResult && (
              <div className="flex gap-3">
                <button
                  onClick={() => dryRunMut.mutate(selectedFile)}
                  disabled={dryRunMut.isPending || importMut.isPending}
                  className="flex-1 flex items-center justify-center gap-2 py-2 border border-[#1e2d42] bg-[#0e1624] hover:bg-[#19253d] disabled:opacity-50 text-sm text-[#e2e8f4] rounded-lg transition-colors"
                >
                  {dryRunMut.isPending ? (
                    <div className="w-4 h-4 border-2 border-[#8899aa]/30 border-t-[#8899aa] rounded-full animate-spin" />
                  ) : (
                    <FileUp className="w-4 h-4" />
                  )}
                  ドライラン
                </button>
                <button
                  onClick={() => importMut.mutate(selectedFile)}
                  disabled={importMut.isPending || dryRunMut.isPending}
                  className="flex-1 flex items-center justify-center gap-2 py-2 bg-green-700 hover:bg-green-600 disabled:opacity-50 text-sm text-white font-medium rounded-lg transition-colors"
                >
                  {importMut.isPending ? (
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <UploadCloud className="w-4 h-4" />
                  )}
                  インポート実行
                </button>
              </div>
            )}

            {importResult && (
              <button
                onClick={clearFile}
                className="w-full py-2 border border-[#1e2d42] bg-[#0e1624] hover:bg-[#19253d] text-sm text-[#8899aa] rounded-lg transition-colors"
              >
                別のファイルをインポート
              </button>
            )}
          </div>
        </div>

        {/* ── Import History ────────────────────────────────────────────── */}
        <div className="bg-gray-800 border border-[#1e2d42] rounded-xl overflow-hidden">
          <button
            onClick={() => setShowHistory(v => !v)}
            className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-[#0e1624]/40 transition-colors"
          >
            <h2 className="text-sm font-semibold text-white">インポート履歴 (セッション中)</h2>
            <div className="flex items-center gap-2">
              {importHistory.length > 0 && (
                <span className="text-xs bg-blue-900/60 text-blue-300 border border-blue-800/60 px-2 py-0.5 rounded-sm font-mono">
                  {importHistory.length}
                </span>
              )}
              {showHistory
                ? <ChevronUp className="w-4 h-4 text-[#5a6a7a]" />
                : <ChevronDown className="w-4 h-4 text-[#5a6a7a]" />}
            </div>
          </button>

          {showHistory && (
            importHistory.length === 0 ? (
              <div className="flex flex-col items-center py-10 text-[#5a6a7a] border-t border-[#1e2d42]">
                <UploadCloud className="w-10 h-10 opacity-20 mb-2" />
                <p className="text-sm">このセッションではまだインポートが実行されていません</p>
              </div>
            ) : (
              <div className="overflow-x-auto border-t border-[#1e2d42]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-[#0e1624] text-xs text-[#8899aa]">
                      <th className="px-4 py-3 text-left">日時</th>
                      <th className="px-4 py-3 text-left">ファイル名</th>
                      <th className="px-4 py-3 text-right">インポート数</th>
                      <th className="px-4 py-3 text-right">スキップ</th>
                      <th className="px-4 py-3 text-left">ステータス</th>
                    </tr>
                  </thead>
                  <tbody>
                    {importHistory.map(entry => (
                      <tr key={entry.id} className="border-t border-[#1e2d42]/50 hover:bg-[#161f33]/30 transition-colors">
                        <td className="px-4 py-2.5 text-xs text-[#8899aa] font-mono whitespace-nowrap">
                          {fmtDateTime(entry.timestamp)}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-[#e2e8f4] max-w-[200px] truncate" title={entry.filename}>
                          {entry.filename}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-green-400 font-mono text-right">
                          +{entry.imported}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-yellow-400 font-mono text-right">
                          {entry.skipped}
                        </td>
                        <td className="px-4 py-2.5">
                          {entry.status === 'success' ? (
                            <span className="inline-flex items-center gap-1 text-xs text-green-400">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              成功
                            </span>
                          ) : entry.status === 'partial' ? (
                            <span className="inline-flex items-center gap-1 text-xs text-yellow-400">
                              <AlertTriangle className="w-3.5 h-3.5" />
                              一部成功
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs text-red-400">
                              <XCircle className="w-3.5 h-3.5" />
                              失敗
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}
        </div>

      </div>
    </div>
  )
}
