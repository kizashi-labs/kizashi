'use client'

import { useState, useRef, useCallback, DragEvent, ChangeEvent } from 'react'
import Link from 'next/link'
import {
  ArrowLeft, Download, Upload, FileText, AlertTriangle,
  CheckCircle2, XCircle, Loader2, Shield, X,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ── Types ──────────────────────────────────────────────────────

type TLPLevel = 'white' | 'green' | 'amber' | 'red'

interface ParsedCSV {
  headers: string[]
  rows: Record<string, string>[]
  errors: string[]
}

interface ImportOptions {
  updateExisting: boolean
  activateAll: boolean
  expiresAt: string
  tlp: TLPLevel
}

interface ImportResult {
  success: number
  skipped: number
  errors: number
  errorDetails?: string[]
}

interface RecentImport {
  id: string
  datetime: string
  filename: string
  count: number
  status: 'success' | 'partial' | 'error'
  result?: ImportResult
}

// ── Constants ─────────────────────────────────────────────────

const CSV_HEADERS = ['type', 'value', 'confidence', 'severity', 'tags', 'description', 'source']

const VALID_TYPES = ['ip', 'domain', 'hash_md5', 'hash_sha256', 'hash_sha1', 'url', 'email'] as const

const SAMPLE_CSV = [
  CSV_HEADERS.join(','),
  'ip,192.168.1.100,high,critical,"malware,c2",Suspected C2 server,ThreatFeed-2026',
  'domain,evil-corp.example.com,medium,high,"phishing",Phishing domain,InternalSOC',
  'hash_sha256,a3b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a1b2c3d4e5f6a7b8,high,critical,"ransomware",WannaCry variant,ThreatIntel',
  'url,https://malware.example.com/payload.exe,low,medium,"dropper",Malware download URL,OSINT',
  'email,attacker@phishing.example.com,medium,medium,"phishing,spam",Spear phishing sender,InternalSOC',
].join('\n')

const TLP_OPTIONS: { value: TLPLevel; label: string; color: string }[] = [
  { value: 'white', label: 'TLP:WHITE',  color: 'text-gray-300' },
  { value: 'green', label: 'TLP:GREEN',  color: 'text-green-400' },
  { value: 'amber', label: 'TLP:AMBER',  color: 'text-amber-400' },
  { value: 'red',   label: 'TLP:RED',    color: 'text-red-400' },
]

// ── CSV Parser ────────────────────────────────────────────────

function parseCSV(text: string): ParsedCSV {
  const lines = text
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0)

  if (lines.length === 0) {
    return { headers: [], rows: [], errors: ['ファイルが空です'] }
  }

  // Parse a single CSV line respecting quoted fields
  function parseLine(line: string): string[] {
    const fields: string[] = []
    let current = ''
    let inQuotes = false

    for (let i = 0; i < line.length; i++) {
      const ch = line[i]
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"'
          i++
        } else {
          inQuotes = !inQuotes
        }
      } else if (ch === ',' && !inQuotes) {
        fields.push(current.trim())
        current = ''
      } else {
        current += ch
      }
    }
    fields.push(current.trim())
    return fields
  }

  const headers = parseLine(lines[0]).map(h => h.toLowerCase().replace(/^"|"$/g, ''))
  const rows: Record<string, string>[] = []
  const errors: string[] = []

  // Validate header contains at minimum type and value
  if (!headers.includes('type')) {
    errors.push('ヘッダー行に "type" 列が必要です')
  }
  if (!headers.includes('value')) {
    errors.push('ヘッダー行に "value" 列が必要です')
  }

  if (errors.length > 0) {
    return { headers, rows, errors }
  }

  for (let i = 1; i < lines.length; i++) {
    const lineNum = i + 1 // 1-based, accounting for header
    const fields = parseLine(lines[i])

    if (fields.length !== headers.length) {
      errors.push(
        `行${lineNum}: 列数が一致しません（期待: ${headers.length}、実際: ${fields.length}）`
      )
      continue
    }

    const row: Record<string, string> = {}
    headers.forEach((h, idx) => {
      row[h] = fields[idx] ?? ''
    })

    // --- Validation ---
    const type = row['type']
    const value = row['value']

    if (!type) {
      errors.push(`行${lineNum}: typeは必須です`)
      continue
    }

    if (!(VALID_TYPES as readonly string[]).includes(type)) {
      errors.push(
        `行${lineNum}: 無効なtype "${type}" (有効値: ${VALID_TYPES.join(', ')})`
      )
      continue
    }

    if (!value) {
      errors.push(`行${lineNum}: valueは必須です`)
      continue
    }

    // Type-specific format validation
    if (type === 'ip') {
      const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)
      const ipv6 = /^[0-9a-fA-F:]+$/.test(value) && value.includes(':')
      if (!ipv4 && !ipv6) {
        errors.push(`行${lineNum}: 無効なIPアドレス形式 "${value}"`)
        continue
      }
    }

    if (type === 'domain') {
      if (!/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(value)) {
        errors.push(`行${lineNum}: 無効なドメイン形式 "${value}"`)
        continue
      }
    }

    if (type === 'email') {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        errors.push(`行${lineNum}: 無効なメールアドレス形式 "${value}"`)
        continue
      }
    }

    if (type === 'hash_md5' && !/^[0-9a-fA-F]{32}$/.test(value)) {
      errors.push(`行${lineNum}: 無効なMD5ハッシュ形式 "${value}"`)
      continue
    }

    if (type === 'hash_sha1' && !/^[0-9a-fA-F]{40}$/.test(value)) {
      errors.push(`行${lineNum}: 無効なSHA1ハッシュ形式 "${value}"`)
      continue
    }

    if (type === 'hash_sha256' && !/^[0-9a-fA-F]{64}$/.test(value)) {
      errors.push(`行${lineNum}: 無効なSHA256ハッシュ形式 "${value}"`)
      continue
    }

    if (type === 'url') {
      try {
        new URL(value)
      } catch {
        errors.push(`行${lineNum}: 無効なURL形式 "${value}"`)
        continue
      }
    }

    rows.push(row)
  }

  return { headers, rows, errors }
}

// ── Progress bar sub-component ────────────────────────────────

function ProgressBar({ value }: { value: number }) {
  return (
    <div className="w-full h-2 bg-[#1a2540] rounded-full overflow-hidden">
      <div
        className="h-full bg-linear-to-r from-[#1a6bff] to-[#5a99ff] rounded-full transition-all duration-300"
        style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
      />
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────

export default function IOCImportPage() {
  // File & parse state
  const [file, setFile] = useState<File | null>(null)
  const [parsed, setParsed] = useState<ParsedCSV | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Import options
  const [options, setOptions] = useState<ImportOptions>({
    updateExisting: false,
    activateAll: true,
    expiresAt: '',
    tlp: 'green',
  })

  // Import progress / result
  const [importing, setImporting] = useState(false)
  const [progress, setProgress] = useState(0)
  const [importResult, setImportResult] = useState<ImportResult | null>(null)
  const [importError, setImportError] = useState<string | null>(null)

  // Recent imports (current session)
  const [recentImports, setRecentImports] = useState<RecentImport[]>([])

  // ── File handling ────────────────────────────────────────────

  function processFile(f: File) {
    if (!f.name.endsWith('.csv')) {
      alert('CSVファイルのみ対応しています')
      return
    }
    setFile(f)
    setParsed(null)
    setImportResult(null)
    setImportError(null)

    const reader = new FileReader()
    reader.onload = (e) => {
      const text = e.target?.result as string
      const result = parseCSV(text)
      setParsed(result)
    }
    reader.readAsText(f, 'UTF-8')
  }

  function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (f) processFile(f)
  }

  const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) processFile(f)
  }, [])

  // ── Template download ────────────────────────────────────────

  function downloadTemplate() {
    const blob = new Blob(['\uFEFF' + SAMPLE_CSV], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'ioc-import-template.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  // ── Import ───────────────────────────────────────────────────

  async function handleImport() {
    if (!file || !parsed || parsed.rows.length === 0) return

    setImporting(true)
    setProgress(0)
    setImportResult(null)
    setImportError(null)

    // Simulate progress ticks while waiting
    const progressInterval = setInterval(() => {
      setProgress(p => Math.min(p + 8, 85))
    }, 200)

    try {
      const payload = {
        rows: parsed.rows,
        options: {
          update_existing: options.updateExisting,
          activate_all: options.activateAll,
          expires_at: options.expiresAt || null,
          tlp: options.tlp,
        },
      }

      const res = await apiFetch<ImportResult>('/api/v1/ioc/bulk', {
        method: 'POST',
        body: JSON.stringify(payload),
      })

      clearInterval(progressInterval)
      setProgress(100)
      setImportResult(res)

      // Record in recent imports
      const status: RecentImport['status'] =
        res.errors === 0 ? 'success' : res.success > 0 ? 'partial' : 'error'

      setRecentImports(prev => [
        {
          id: crypto.randomUUID(),
          datetime: new Date().toISOString(),
          filename: file.name,
          count: parsed.rows.length,
          status,
          result: res,
        },
        ...prev,
      ])
    } catch (err) {
      clearInterval(progressInterval)
      setProgress(0)
      setImportError((err as Error).message ?? 'インポートに失敗しました')

      // Still record failed attempt
      setRecentImports(prev => [
        {
          id: crypto.randomUUID(),
          datetime: new Date().toISOString(),
          filename: file.name,
          count: parsed.rows.length,
          status: 'error',
        },
        ...prev,
      ])
    } finally {
      setImporting(false)
    }
  }

  // ── Render ───────────────────────────────────────────────────

  const validRowCount = parsed?.rows.length ?? 0
  const hasValidRows = validRowCount > 0
  const canImport = hasValidRows && !importing

  return (
    <div className="min-h-screen bg-[#080c14] p-6">
      <div className="max-w-4xl mx-auto space-y-6">

        {/* ── Header ── */}
        <div className="flex items-center gap-4">
          <Link
            href="/ioc"
            className="flex items-center gap-1.5 text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors px-3 py-1.5 rounded-lg hover:bg-[#111827]"
          >
            <ArrowLeft className="w-4 h-4" />
            IOC管理に戻る
          </Link>
          <div className="h-4 w-px bg-[#1e2d42]" />
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-orange-400" />
              IOC 一括インポート
            </h1>
            <p className="text-xs text-[#5a6a7a] mt-0.5">
              CSVファイルからIOCを一括登録します
            </p>
          </div>
        </div>

        {/* ── CSV Template card ── */}
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#5a99ff]" />
              CSVフォーマット
            </h2>
            <button
              onClick={downloadTemplate}
              className="flex items-center gap-1.5 text-xs text-[#5a99ff] bg-[#1a6bff]/10 border border-[#1a6bff]/25 hover:bg-[#1a6bff]/20 px-3 py-1.5 rounded-lg transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              テンプレートをダウンロード
            </button>
          </div>

          {/* Header row preview */}
          <div className="mb-3">
            <p className="text-xs text-[#5a6a7a] mb-2">必須ヘッダー行：</p>
            <div className="bg-[#080c14] rounded-lg border border-[#1e2d42] p-3 overflow-x-auto">
              <code className="text-xs text-[#5a99ff] font-mono">
                {CSV_HEADERS.join(',')}
              </code>
            </div>
          </div>

          {/* Column descriptions */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            {[
              { col: 'type',        req: true,  desc: `有効値: ${VALID_TYPES.join(', ')}` },
              { col: 'value',       req: true,  desc: 'IOCの値（IP、ドメイン、ハッシュ等）' },
              { col: 'confidence',  req: false, desc: 'high / medium / low' },
              { col: 'severity',    req: false, desc: 'critical / high / medium / low' },
              { col: 'tags',        req: false, desc: 'カンマ区切りタグ（引用符で囲む）' },
              { col: 'description', req: false, desc: '説明テキスト' },
              { col: 'source',      req: false, desc: '情報ソース名' },
            ].map(item => (
              <div key={item.col} className="flex items-start gap-2">
                <code className="text-[#a78bfa] font-mono shrink-0">{item.col}</code>
                {item.req && (
                  <span className="text-red-400 text-[10px] shrink-0 mt-px">必須</span>
                )}
                <span className="text-[#5a6a7a]">{item.desc}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── File Upload card ── */}
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Upload className="w-4 h-4 text-orange-400" />
            CSVファイルのアップロード
          </h2>

          {/* Drag-and-drop zone */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`relative flex flex-col items-center justify-center gap-3 rounded-xl border-2
                        border-dashed cursor-pointer py-10 px-6 transition-all
                        ${isDragging
                          ? 'border-[#1a6bff] bg-[#1a6bff]/5'
                          : file
                          ? 'border-green-700/50 bg-green-900/5 hover:bg-green-900/10'
                          : 'border-[#2a3a5c] hover:border-[#3a4a6c] hover:bg-[#0d1525]'}`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              onChange={handleFileChange}
              className="hidden"
            />

            {file ? (
              <>
                <div className="w-10 h-10 rounded-full bg-green-900/30 border border-green-700/40 flex items-center justify-center">
                  <CheckCircle2 className="w-5 h-5 text-green-400" />
                </div>
                <div className="text-center">
                  <p className="text-sm font-medium text-[#e2e8f4]">{file.name}</p>
                  <p className="text-xs text-[#5a6a7a] mt-0.5">
                    {(file.size / 1024).toFixed(1)} KB · クリックまたはドロップで変更
                  </p>
                </div>
              </>
            ) : (
              <>
                <div className="w-10 h-10 rounded-full bg-[#0d1525] border border-[#2a3a5c] flex items-center justify-center">
                  <Upload className="w-5 h-5 text-[#3d5068]" />
                </div>
                <div className="text-center">
                  <p className="text-sm font-medium text-[#7d92b0]">
                    クリックまたはCSVをここにドロップ
                  </p>
                  <p className="text-xs text-[#3d5068] mt-1">CSVファイルのみ対応</p>
                </div>
              </>
            )}
          </div>

          {/* Parse results */}
          {parsed && (
            <div className="space-y-3">
              {/* Row count */}
              <div className={`flex items-center gap-2 text-sm rounded-lg px-4 py-2.5
                               ${hasValidRows
                                 ? 'bg-green-900/20 border border-green-700/40 text-green-300'
                                 : 'bg-yellow-900/20 border border-yellow-700/40 text-yellow-300'}`}
              >
                {hasValidRows
                  ? <CheckCircle2 className="w-4 h-4 shrink-0" />
                  : <AlertTriangle className="w-4 h-4 shrink-0" />}
                <span className="font-medium">{validRowCount}行のIOCを検出しました</span>
                {parsed.errors.length > 0 && (
                  <span className="text-xs opacity-80 ml-1">
                    （{parsed.errors.length}件のエラーあり）
                  </span>
                )}
              </div>

              {/* Validation errors */}
              {parsed.errors.length > 0 && (
                <div className="bg-red-900/10 border border-red-700/30 rounded-lg p-3">
                  <p className="text-xs font-semibold text-red-400 mb-2 flex items-center gap-1.5">
                    <XCircle className="w-3.5 h-3.5" />
                    バリデーションエラー ({parsed.errors.length}件)
                  </p>
                  <ul className="space-y-1">
                    {parsed.errors.map((err, i) => (
                      <li key={i} className="text-xs text-red-300/80 font-mono">
                        {err}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Preview table — first 5 rows */}
              {hasValidRows && (
                <div>
                  <p className="text-xs text-[#5a6a7a] mb-2">
                    プレビュー（最初の5行）
                  </p>
                  <div className="overflow-x-auto rounded-lg border border-[#1e2d42]">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="bg-[#080c14] border-b border-[#1e2d42] text-[#5a6a7a]">
                          {parsed.headers.map(h => (
                            <th key={h} className="text-left px-3 py-2 font-medium whitespace-nowrap">
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1e2d42]/50">
                        {parsed.rows.slice(0, 5).map((row, i) => (
                          <tr key={i} className="hover:bg-[#161f33]/30 transition-colors">
                            {parsed.headers.map(h => (
                              <td
                                key={h}
                                className="px-3 py-2 text-[#c0cce0] font-mono max-w-[200px] truncate"
                                title={row[h]}
                              >
                                {row[h] || <span className="text-[#3d5068]">—</span>}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {parsed.rows.length > 5 && (
                    <p className="text-xs text-[#3d5068] mt-1.5 text-right">
                      ...他 {parsed.rows.length - 5}行
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Import Options card ── */}
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5">
          <h2 className="text-sm font-semibold text-white mb-4">インポートオプション</h2>

          <div className="space-y-4">
            {/* Checkboxes */}
            <div className="flex flex-col gap-3">
              <label className="flex items-center gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={options.updateExisting}
                  onChange={e => setOptions(o => ({ ...o, updateExisting: e.target.checked }))}
                  className="w-4 h-4 rounded-sm border-[#2a3a5c] bg-[#080c14] text-[#1a6bff] accent-[#1a6bff] cursor-pointer"
                />
                <div>
                  <span className="text-sm text-[#e2e8f4] group-hover:text-white transition-colors">
                    既存のIOCを更新する
                  </span>
                  <p className="text-xs text-[#5a6a7a] mt-0.5">
                    同一の値が既に存在する場合、情報を上書きします
                  </p>
                </div>
              </label>

              <label className="flex items-center gap-3 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={options.activateAll}
                  onChange={e => setOptions(o => ({ ...o, activateAll: e.target.checked }))}
                  className="w-4 h-4 rounded-sm border-[#2a3a5c] bg-[#080c14] text-[#1a6bff] accent-[#1a6bff] cursor-pointer"
                />
                <div>
                  <span className="text-sm text-[#e2e8f4] group-hover:text-white transition-colors">
                    すべてのIOCを有効化する
                  </span>
                  <p className="text-xs text-[#5a6a7a] mt-0.5">
                    インポート後、すべてのIOCを即座に有効にします
                  </p>
                </div>
              </label>
            </div>

            {/* Date + TLP row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <div>
                <label className="text-xs text-[#8899aa] block mb-1.5">
                  有効期限
                  <span className="text-[#3d5068] ml-1">（任意）</span>
                </label>
                <input
                  type="date"
                  value={options.expiresAt}
                  onChange={e => setOptions(o => ({ ...o, expiresAt: e.target.value }))}
                  className="w-full text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#e2e8f4] focus:outline-hidden focus:border-orange-500 [color-scheme:dark]"
                />
              </div>

              <div>
                <label className="text-xs text-[#8899aa] block mb-1.5">
                  対象TLPレベル
                </label>
                <select
                  value={options.tlp}
                  onChange={e => setOptions(o => ({ ...o, tlp: e.target.value as TLPLevel }))}
                  className="w-full text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#e2e8f4] focus:outline-hidden focus:border-orange-500"
                >
                  {TLP_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </div>

        {/* ── Import button + progress + result ── */}
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-5 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={handleImport}
              disabled={!canImport}
              className="flex items-center gap-2 px-6 py-2.5 text-sm font-semibold bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {importing
                ? <Loader2 className="w-4 h-4 animate-spin" />
                : <Upload className="w-4 h-4" />}
              {importing ? 'インポート中...' : 'インポート実行'}
            </button>

            {parsed && (
              <p className="text-xs text-[#5a6a7a]">
                {validRowCount}件のIOCをインポートします
              </p>
            )}
          </div>

          {/* Progress bar */}
          {importing && (
            <div className="space-y-1.5">
              <ProgressBar value={progress} />
              <p className="text-xs text-[#5a6a7a]">処理中... {progress}%</p>
            </div>
          )}

          {/* Result summary */}
          {importResult && (
            <div className={`rounded-lg border p-4 ${
              importResult.errors === 0
                ? 'bg-green-900/20 border-green-700/40'
                : importResult.success > 0
                ? 'bg-yellow-900/20 border-yellow-700/40'
                : 'bg-red-900/20 border-red-700/40'
            }`}>
              <p className="text-sm font-semibold text-[#e2e8f4] mb-3 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-400" />
                インポート完了
              </p>
              <div className="grid grid-cols-3 gap-3">
                <div className="text-center">
                  <p className="text-xl font-bold text-green-400">{importResult.success}</p>
                  <p className="text-xs text-[#5a6a7a] mt-0.5">成功</p>
                </div>
                <div className="text-center">
                  <p className="text-xl font-bold text-yellow-400">{importResult.skipped}</p>
                  <p className="text-xs text-[#5a6a7a] mt-0.5">スキップ</p>
                </div>
                <div className="text-center">
                  <p className="text-xl font-bold text-red-400">{importResult.errors}</p>
                  <p className="text-xs text-[#5a6a7a] mt-0.5">エラー</p>
                </div>
              </div>
              {importResult.errorDetails && importResult.errorDetails.length > 0 && (
                <div className="mt-3 pt-3 border-t border-[#1e2d42]">
                  <p className="text-xs font-medium text-red-400 mb-1">エラー詳細:</p>
                  <ul className="space-y-0.5">
                    {importResult.errorDetails.map((d, i) => (
                      <li key={i} className="text-xs text-red-300/70 font-mono">{d}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Import error */}
          {importError && (
            <div className="flex items-start gap-2 bg-red-900/20 border border-red-700/40 rounded-lg px-4 py-3 text-xs text-red-300">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">インポートに失敗しました</p>
                <p className="mt-0.5 opacity-80">{importError}</p>
              </div>
            </div>
          )}
        </div>

        {/* ── Recent imports table ── */}
        {recentImports.length > 0 && (
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <h2 className="text-sm font-semibold text-white">今セッションのインポート履歴</h2>
              <button
                onClick={() => setRecentImports([])}
                className="text-xs text-[#5a6a7a] hover:text-[#8899aa] flex items-center gap-1 transition-colors"
              >
                <X className="w-3.5 h-3.5" />
                クリア
              </button>
            </div>
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[#1e2d42] bg-[#080c14]/40 text-[#5a6a7a]">
                  <th className="text-left px-4 py-2.5 font-medium">日時</th>
                  <th className="text-left px-4 py-2.5 font-medium">ファイル名</th>
                  <th className="text-left px-4 py-2.5 font-medium">件数</th>
                  <th className="text-left px-4 py-2.5 font-medium">ステータス</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]/50">
                {recentImports.map(item => (
                  <tr key={item.id} className="hover:bg-[#161f33]/20 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-[#5a6a7a] whitespace-nowrap">
                      {new Date(item.datetime).toLocaleString('ja-JP', {
                        month: '2-digit', day: '2-digit',
                        hour: '2-digit', minute: '2-digit', second: '2-digit',
                      })}
                    </td>
                    <td className="px-4 py-2.5 text-[#c0cce0] max-w-[240px] truncate" title={item.filename}>
                      {item.filename}
                    </td>
                    <td className="px-4 py-2.5 text-[#7d92b0] font-mono">
                      {item.count}行
                    </td>
                    <td className="px-4 py-2.5">
                      {item.status === 'success' && (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold text-green-400 bg-green-900/20 border border-green-700/30 rounded-full px-2 py-0.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                          成功
                        </span>
                      )}
                      {item.status === 'partial' && (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold text-yellow-400 bg-yellow-900/20 border border-yellow-700/30 rounded-full px-2 py-0.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                          一部成功
                        </span>
                      )}
                      {item.status === 'error' && (
                        <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold text-red-400 bg-red-900/20 border border-red-700/30 rounded-full px-2 py-0.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                          エラー
                        </span>
                      )}
                      {item.result && (
                        <span className="ml-2 text-[10px] text-[#3d5068] font-mono">
                          {item.result.success}件成功
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

      </div>
    </div>
  )
}
