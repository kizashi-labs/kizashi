'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Archive, RefreshCw, Upload, Download, CheckCircle,
  AlertTriangle, Clock, Database, FileJson, Shield,
  HardDrive, X, Info
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

interface BackupRecord {
  id: string
  created_at: string
  version: string
  tables: string[]
  record_count: Record<string, number> // backend returns a per-table map
  size_bytes: number
  status: string // backend emits "completed" / "failed"
}

// Raw shape returned by POST /api/v1/admin/backup/restore
interface RawRestore {
  message?: string
  tables_restored?: string[]
  records_restored?: Record<string, number>
  warnings?: string[]
}

interface RestoreResult {
  success: boolean
  message: string
  tables_restored?: { table: string; records: number }[]
  backup_created_first?: boolean
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDate(iso: string): string {
  try { return new Date(iso).toLocaleString('ja-JP', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) } catch { return '—' }
}

function fmtBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB'
  if (bytes >= 1024) return (bytes / 1024).toFixed(0) + ' KB'
  return bytes + ' B'
}

const STATUS_STYLES: Record<string, { badge: string; icon: React.ElementType; iconColor: string; label: string }> = {
  completed: { badge: 'bg-green-900/30 text-green-400 border border-green-700/30', icon: CheckCircle, iconColor: 'text-green-400', label: '完了' },
  success: { badge: 'bg-green-900/30 text-green-400 border border-green-700/30', icon: CheckCircle, iconColor: 'text-green-400', label: '成功' },
  failed:  { badge: 'bg-red-900/30 text-red-400 border border-red-700/30', icon: AlertTriangle, iconColor: 'text-red-400', label: '失敗' },
  partial: { badge: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/30', icon: AlertTriangle, iconColor: 'text-yellow-400', label: '部分的' },
}

// Defensive fallback so an unrecognised status never crashes the row render.
const STATUS_FALLBACK = { badge: 'bg-zinc-800 text-zinc-400 border border-zinc-700', icon: Info, iconColor: 'text-zinc-400', label: '不明' }

const INCLUDED_IN_BACKUP = [
  'ユーザー設定', 'セキュリティルール', 'Webhooks', 'APIキー',
  'ポリシー設定', 'アラート抑制', '統合設定', '通知設定',
  'ロール・権限', 'カスタムダッシュボード',
]

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function BackupPage() {
  const qc = useQueryClient()
  const [restoreFile, setRestoreFile] = useState<File | null>(null)
  const [restoreResult, setRestoreResult] = useState<RestoreResult | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: backups = [] } = useQuery<BackupRecord[]>({
    queryKey: ['admin-backups'],
    queryFn: async () => {
      try { return await apiFetchList<BackupRecord>('/api/v1/admin/backup/list') } catch { return [] }
    },
  })

  const restoreMut = useMutation({
    // The backend expects the raw backup JSON as the request body (it
    // json.Unmarshal-s the body directly into BackupData) — NOT a {data:...} wrapper.
    mutationFn: async (file: File) => {
      const text = await file.text()
      return apiFetch<RawRestore>('/api/v1/admin/backup/restore', {
        method: 'POST',
        body: text,
      })
    },
    onSuccess: (data) => {
      const tables = (data.tables_restored ?? []).map(t => ({ table: t, records: data.records_restored?.[t] ?? 0 }))
      const warn = (data.warnings ?? []).length
      setRestoreResult({
        success: true,
        message: (data.message || 'リストアが完了しました。') + (warn ? `（警告 ${warn} 件）` : ''),
        tables_restored: tables,
      })
      qc.invalidateQueries({ queryKey: ['admin-backups'] })
    },
    onError: () => setRestoreResult({
      success: false,
      message: 'リストアに失敗しました。バックアップファイルの形式を確認してください。',
    }),
  })

  async function handleCreateBackup() {
    setCreating(true)
    try {
      // apiFetch always parses res.json(), but this endpoint streams a file
      // download — fetch the blob directly with auth instead.
      const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
      const res = await fetch('/api/v1/admin/backup/create', {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const cd = res.headers.get('Content-Disposition') ?? ''
      const m = cd.match(/filename=([^;]+)/)
      const filename = m ? m[1].trim().replace(/"/g, '') : `edr-backup-${new Date().toISOString().slice(0, 10)}.json`
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      qc.invalidateQueries({ queryKey: ['admin-backups'] })
    } catch {
      alert('バックアップの作成に失敗しました。時間をおいて再試行してください。')
    } finally {
      setCreating(false)
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) setRestoreFile(file)
  }

  function handleRestore() {
    if (!restoreFile) return
    if (!confirm('既存の設定を上書きします。事前に現在の設定のバックアップを取得済みであることを確認してください。続行しますか？')) return
    restoreMut.mutate(restoreFile)
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="h-10 w-10 rounded-xl bg-indigo-900/40 border border-indigo-700/40 flex items-center justify-center">
          <Archive className="h-5 w-5 text-indigo-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">バックアップ & リストア</h1>
          <p className="text-sm text-zinc-400">プラットフォーム設定とポリシーのエクスポート・リストア</p>
        </div>
      </div>

      {/* What's Included Banner */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5 mb-6">
        <div className="flex items-center gap-2 mb-3">
          <Info className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium text-zinc-300">バックアップに含まれる内容</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
          {INCLUDED_IN_BACKUP.map(item => (
            <div key={item} className="flex items-center gap-1.5 text-xs text-zinc-400">
              <CheckCircle className="h-3 w-3 text-green-500 shrink-0" />
              {item}
            </div>
          ))}
        </div>
        <div className="mt-3 text-xs text-zinc-600">
          注意: アラートイベント、生ログ、エージェントテレメトリデータはバックアップに含まれません。
        </div>
      </div>

      {/* Create Backup */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-zinc-200">バックアップを作成</h2>
            <p className="text-sm text-zinc-500 mt-0.5">すべてのプラットフォーム設定をJSONファイルとしてエクスポート</p>
          </div>
          <button onClick={handleCreateBackup} disabled={creating}
            className="flex items-center gap-2 px-5 py-2.5 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors font-medium">
            {creating ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {creating ? '作成中…' : 'バックアップを作成'}
          </button>
        </div>
      </div>

      {/* Backup History */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden mb-6">
        <div className="px-5 py-3 border-b border-zinc-700 bg-zinc-800/30">
          <h2 className="text-sm font-medium text-zinc-300">バックアップ履歴</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700/50 bg-zinc-800/10">
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">作成日時</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">バージョン</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">テーブル</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">レコード数</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">サイズ</th>
              <th className="text-left px-5 py-3 text-xs text-zinc-400 font-medium">ステータス</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/50">
            {backups.map(b => {
              const s = STATUS_STYLES[b.status] ?? STATUS_FALLBACK
              const totalRecords = Object.values(b.record_count ?? {}).reduce((a, c) => a + (c ?? 0), 0)
              return (
                <tr key={b.id} className="hover:bg-zinc-800/20 transition-colors">
                  <td className="px-5 py-3 text-xs text-zinc-300 flex items-center gap-2">
                    <Clock className="h-3.5 w-3.5 text-zinc-600" />
                    {fmtDate(b.created_at)}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-zinc-400">{b.version}</td>
                  <td className="px-5 py-3">
                    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 bg-zinc-800 border border-zinc-700 rounded-sm text-zinc-400">
                      <Database className="h-3 w-3" />{(b.tables ?? []).length} テーブル
                    </span>
                  </td>
                  <td className="px-5 py-3 text-xs text-zinc-300">{totalRecords.toLocaleString()}</td>
                  <td className="px-5 py-3 text-xs text-zinc-400">{fmtBytes(b.size_bytes)}</td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-sm font-medium ${s.badge}`}>
                      <s.icon className={`h-3 w-3 ${s.iconColor}`} />{s.label}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Restore Section */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5">
        <h2 className="text-base font-semibold text-zinc-200 mb-1">バックアップからリストア</h2>

        {/* Warning */}
        <div className="flex items-start gap-3 bg-yellow-900/20 border border-yellow-700/40 rounded-lg p-3 mb-4">
          <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />
          <div className="text-xs text-yellow-300">
            <strong>警告:</strong> ルール・Webhook・設定を含む既存の設定が上書きされます。
            リストア処理は自動バックアップを作成しません。実行前に必ず現在の設定のバックアップを取得してください。
          </div>
        </div>

        {/* File Upload */}
        <div className="flex items-end gap-3 mb-4">
          <div className="flex-1">
            <label className="block text-xs text-zinc-500 mb-1.5">バックアップファイル (JSON)</label>
            <label className="flex items-center gap-3 border border-dashed border-zinc-600 rounded-lg p-4 cursor-pointer hover:border-zinc-500 transition-colors bg-zinc-800/30">
              <FileJson className="h-6 w-6 text-zinc-500" />
              <div>
                {restoreFile
                  ? <span className="text-sm text-zinc-300">{restoreFile.name}</span>
                  : <span className="text-sm text-zinc-500">クリックしてバックアップファイルを選択またはドラッグ＆ドロップ</span>
                }
              </div>
              <input type="file" accept=".json" onChange={handleFileChange} className="sr-only" />
            </label>
          </div>
          <button onClick={handleRestore} disabled={!restoreFile || restoreMut.isPending}
            className="flex items-center gap-2 px-5 py-2.5 text-sm bg-orange-600 hover:bg-orange-500 disabled:opacity-50 text-white rounded-lg transition-colors font-medium self-auto">
            {restoreMut.isPending ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
            リストア
          </button>
        </div>

        {/* Restore Result */}
        {restoreResult && (
          <div className={`rounded-xl p-4 border ${restoreResult.success ? 'bg-green-900/10 border-green-700/30' : 'bg-red-900/10 border-red-700/30'}`}>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                {restoreResult.success
                  ? <CheckCircle className="h-4 w-4 text-green-400" />
                  : <AlertTriangle className="h-4 w-4 text-red-400" />
                }
                <span className={`text-sm font-medium ${restoreResult.success ? 'text-green-300' : 'text-red-300'}`}>
                  {restoreResult.message}
                </span>
              </div>
              <button onClick={() => setRestoreResult(null)} className="text-zinc-500 hover:text-zinc-300">
                <X className="h-4 w-4" />
              </button>
            </div>
            {restoreResult.backup_created_first && (
              <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-3">
                <Shield className="h-3 w-3 text-blue-400" />
                リストア前に以前の状態の自動バックアップが作成されました。
              </div>
            )}
            {restoreResult.tables_restored && (
              <div>
                <div className="text-xs text-zinc-500 mb-2">リストアされたテーブル:</div>
                <div className="flex flex-wrap gap-2">
                  {restoreResult.tables_restored.map(t => (
                    <div key={t.table} className="flex items-center gap-1.5 text-xs bg-zinc-800 border border-zinc-700 rounded-sm px-2.5 py-1">
                      <Database className="h-3 w-3 text-zinc-500" />
                      <span className="font-mono text-zinc-300">{t.table}</span>
                      <span className="text-zinc-600">({t.records})</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
