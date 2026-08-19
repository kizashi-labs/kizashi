'use client'

import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import { Shield, Plus, Trash2, Search, ToggleLeft, ToggleRight, X, AlertTriangle, Upload, CheckCircle2, ShieldCheck, ShieldX, Loader2, Crosshair, ScanSearch, Download, FileText, File } from 'lucide-react'
import Link from 'next/link'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface IOCEntry {
  id: string
  type: 'hash' | 'ip' | 'domain' | 'url' | 'email'
  value: string
  description: string
  severity: number
  is_active: boolean
  added_by_name: string
  created_at: string
}

interface IOCResponse {
  data: IOCEntry[]
  total: number
  has_more: boolean
}

const IOC_TYPES = ['', 'hash', 'ip', 'domain', 'url', 'email'] as const
const TYPE_LABELS: Record<string, string> = {
  '': 'すべて', hash: 'ハッシュ', ip: 'IPアドレス',
  domain: 'ドメイン', url: 'URL', email: 'メール',
}
const TYPE_COLORS: Record<string, string> = {
  hash:   'bg-purple-900/40 text-purple-300 border-purple-700/50',
  ip:     'bg-blue-900/40 text-blue-300 border-blue-700/50',
  domain: 'bg-green-900/40 text-green-300 border-green-700/50',
  url:    'bg-yellow-900/40 text-yellow-300 border-yellow-700/50',
  email:  'bg-pink-900/40 text-pink-300 border-pink-700/50',
}

function severityColor(s: number) {
  if (s >= 9) return 'text-red-400'
  if (s >= 7) return 'text-orange-400'
  if (s >= 5) return 'text-yellow-400'
  return 'text-blue-400'
}

export default function IOCPage() {
  const canWrite = useCanWrite()
  const qc = useQueryClient()
  const searchParams = useSearchParams()
  const [typeFilter, setTypeFilter] = useState('')
  const [search, setSearch]         = useState('')

  // Pre-fill search from ?q= URL param (e.g. from global search)
  useEffect(() => {
    const q = searchParams.get('q')
    if (q) setSearch(q)
  }, [searchParams])
  const [showAdd, setShowAdd]       = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [importText, setImportText]     = useState('')
  const [importType, setImportType]     = useState('')
  const [importSeverity, setImportSeverity] = useState(7)
  const [importResult, setImportResult] = useState<{ inserted: number; parsed: number; skipped: string[] } | null>(null)
  const [importMode, setImportMode]     = useState<'text' | 'file'>('text')
  const [fileError, setFileError]       = useState<string | null>(null)
  const [isDragOver, setIsDragOver]     = useState(false)

  const [form, setForm] = useState({
    type: 'ip', value: '', description: '', severity: 7,
  })

  // Quick IOC Lookup
  const [lookupValue, setLookupValue] = useState('')
  const [lookupSubmitted, setLookupSubmitted] = useState(false)
  const { data: lookupResult, isLoading: lookupLoading, refetch: doLookup } = useQuery<{
    match: boolean
    entry?: { type: string; value: string; severity: number; description: string; is_active: boolean }
  }>({
    queryKey: ['ioc-check', lookupValue],
    queryFn: () => {
      const detectedType = (() => {
        const v = lookupValue.trim()
        if (v.startsWith('http://') || v.startsWith('https://')) return 'url'
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return 'ip'
        if (/^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(v)) return 'hash'
        if (v.includes('@')) return 'email'
        return 'domain'
      })()
      return apiFetch(`/api/v1/ioc/check?type=${detectedType}&value=${encodeURIComponent(lookupValue.trim())}`)
    },
    enabled: lookupSubmitted && !!lookupValue.trim(),
  })

  const { data, isLoading } = useQuery<IOCResponse>({
    queryKey: ['ioc', typeFilter, search],
    queryFn: () => {
      const p = new URLSearchParams({
        ...(typeFilter && { type: typeFilter }),
        ...(search && { search }),
        per_page: '100',
      })
      return apiFetch(`/api/v1/ioc?${p}`)
    },
    refetchInterval: 30_000,
  })

  const createMutation = useMutation({
    mutationFn: (payload: typeof form) =>
      apiFetch('/api/v1/ioc', { method: 'POST', body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc'] })
      setShowAdd(false)
      setForm({ type: 'ip', value: '', description: '', severity: 7 })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/ioc/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc'] })
      setDeleteConfirm(null)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, active }: { id: string; active: boolean }) =>
      apiFetch(`/api/v1/ioc/${id}/toggle`, {
        method: 'PUT',
        body: JSON.stringify({ is_active: active }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ioc'] }),
  })

  const importMutation = useMutation({
    mutationFn: (payload: { lines: string; default_type: string; severity: number }) =>
      apiFetch<{ inserted: number; parsed: number; skipped: string[] }>(
        '/api/v1/ioc/import',
        { method: 'POST', body: JSON.stringify(payload) },
      ),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['ioc'] })
      setImportResult(res)
    },
  })

  const entries = data?.data ?? []

  function handleFileImport(file: File) {
    setFileError(null)
    setImportResult(null)
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result as string
      try {
        if (file.name.endsWith('.json')) {
          // STIX 2.1 bundle
          const bundle = JSON.parse(text)
          const indicators = (bundle.objects ?? []).filter(
            (o: { type: string }) => o.type === 'indicator'
          ) as Array<{ pattern?: string; name?: string; description?: string; labels?: string[] }>
          if (indicators.length === 0) {
            setFileError('STIXバンドル内にindicatorオブジェクトが見つかりません')
            return
          }
          const lines = indicators.map((ind) => {
            // Extract value from STIX pattern: [ipv4-addr:value = '1.2.3.4']
            const match = ind.pattern?.match(/\[[\w-]+:[\w.]+\s*=\s*'([^']+)'\]/)
            const value = match?.[1] ?? ind.name ?? '(unknown)'
            const desc = ind.description ?? (ind.labels ?? []).join(',') ?? 'STIX indicator'
            return `${value},${desc}`
          })
          setImportText(lines.join('\n'))
        } else {
          // CSV: skip header row if it looks like headers
          const rows = text.split('\n').filter(Boolean)
          const first = rows[0]?.toLowerCase()
          const start = (first?.startsWith('type') || first?.startsWith('value') || first?.startsWith('#')) ? 1 : 0
          setImportText(rows.slice(start).join('\n'))
        }
      } catch {
        setFileError('ファイルの解析に失敗しました。CSVまたはSTIX 2.1 JSONを確認してください。')
      }
    }
    reader.readAsText(file)
  }

  function exportCSV() {
    if (entries.length === 0) return
    const headers = ['id', 'type', 'value', 'description', 'severity', 'is_active', 'added_by', 'created_at']
    const rows = entries.map(e => [
      e.id, e.type, e.value, e.description,
      String(e.severity), e.is_active ? '有効' : '無効',
      e.added_by_name, e.created_at,
    ])
    const csv = [headers, ...rows]
      .map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n')
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ioc-export-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const { data: statsData } = useQuery<{
    total: number; active: number; alerts_7d: number
    by_type: Record<string, number>
  }>({
    queryKey: ['ioc-stats'],
    queryFn: () => apiFetch('/api/v1/ioc/stats'),
    staleTime: 60_000,
  })

  return (
    <div className="p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-orange-400" />
            IOC管理
          </h1>
          <p className="text-sm text-[#8899aa]">侵害指標（Indicator of Compromise）の管理</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={exportCSV}
            disabled={entries.length === 0}
            className="flex items-center gap-1.5 px-4 py-2 text-sm bg-[#161f33] text-[#e2e8f4] rounded-lg hover:bg-[#1d2f4a] transition-colors border border-[#1e2d42] disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            CSV出力
          </button>
          {canWrite && (
            <button
              onClick={() => { setShowImport(v => !v); setShowAdd(false); setImportResult(null) }}
              className="flex items-center gap-1.5 px-4 py-2 text-sm bg-[#161f33] text-[#e2e8f4] rounded-lg hover:bg-[#1d2f4a] transition-colors border border-[#1e2d42]"
            >
              <Upload className="w-4 h-4" />
              一括インポート
            </button>
          )}
          {canWrite && (
            <button
              onClick={() => { setShowAdd(v => !v); setShowImport(false) }}
              className="flex items-center gap-1.5 px-4 py-2 text-sm bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition-colors"
            >
              <Plus className="w-4 h-4" />
              IOCを追加
            </button>
          )}
        </div>
      </div>

      {/* Stats summary */}
      {statsData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
          {[
            { label: '合計IOC', value: statsData.total, color: 'text-orange-400' },
            { label: '有効', value: statsData.active, color: 'text-green-400' },
            { label: '7日間検知', value: statsData.alerts_7d, color: 'text-red-400' },
            ...['ip', 'domain', 'hash', 'url', 'email'].map(t => ({
              label: TYPE_LABELS[t],
              value: statsData.by_type?.[t] ?? 0,
              color: 'text-[#8899aa]',
            })),
          ].map(stat => (
            <div key={stat.label} className="bg-[#111827] rounded-xl border border-[#1e2d42] px-4 py-3">
              <p className="text-xs text-[#5a6a7a] mb-1">{stat.label}</p>
              <p className={`text-xl font-bold ${stat.color}`}>{stat.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Quick IOC Lookup */}
      <div className="mb-6 bg-[#111827] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center gap-2 mb-3">
          <Crosshair className="w-4 h-4 text-orange-400" />
          <h3 className="text-sm font-semibold text-white">IOCクイックルックアップ</h3>
          <span className="text-xs text-[#5a6a7a]">IP・ドメイン・ハッシュ・URLを自動判定</span>
        </div>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
            <input
              value={lookupValue}
              onChange={e => { setLookupValue(e.target.value); setLookupSubmitted(false) }}
              onKeyDown={e => { if (e.key === 'Enter' && lookupValue.trim()) { setLookupSubmitted(true); doLookup() } }}
              placeholder="1.2.3.4 / evil.com / abc123... / https://..."
              className="w-full pl-8 pr-4 py-2 text-sm border border-[#1e2d42] rounded-lg bg-[#080c14] text-white placeholder-[#5a6a7a] focus:outline-hidden focus:border-orange-500 font-mono"
            />
          </div>
          <button
            onClick={() => { if (lookupValue.trim()) { setLookupSubmitted(true); doLookup() } }}
            disabled={!lookupValue.trim() || lookupLoading}
            className="flex items-center gap-1.5 px-4 py-2 text-sm bg-orange-600 hover:bg-orange-700 text-white rounded-lg disabled:opacity-50 transition-colors"
          >
            {lookupLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            検索
          </button>
        </div>

        {lookupSubmitted && !lookupLoading && lookupResult && (
          <div className={`mt-3 flex items-start gap-3 rounded-lg px-4 py-3 text-sm ${
            lookupResult.match
              ? 'bg-red-900/30 border border-red-700/50'
              : 'bg-green-900/20 border border-green-700/40'
          }`}>
            {lookupResult.match ? (
              <>
                <ShieldX className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-red-300">IOCデータベースに登録されています</p>
                  {lookupResult.entry && (
                    <div className="mt-1 text-xs text-red-200/80 space-y-0.5">
                      <p>タイプ: <span className="font-mono">{lookupResult.entry.type}</span></p>
                      <p>重大度: <span className="font-bold">{lookupResult.entry.severity}</span></p>
                      {lookupResult.entry.description && <p>説明: {lookupResult.entry.description}</p>}
                      <p>状態: {lookupResult.entry.is_active ? '有効' : '無効'}</p>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <>
                <ShieldCheck className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
                <p className="text-green-300">「{lookupValue}」はIOCデータベースに登録されていません</p>
              </>
            )}
          </div>
        )}
      </div>

      {/* Bulk Import panel */}
      {showImport && (
        <div className="mb-6 bg-[#111827] rounded-xl border border-[#1e2d42] p-4 space-y-3">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Upload className="w-4 h-4 text-orange-400" />
              一括インポート
            </h3>
            <button onClick={() => { setShowImport(false); setImportResult(null); setImportText('') }}>
              <X className="w-4 h-4 text-[#5a6a7a] hover:text-[#8899aa]" />
            </button>
          </div>

          {/* Import mode tabs */}
          <div className="flex gap-1 bg-[#080c14] rounded-lg p-0.5 w-fit border border-[#1e2d42]">
            {([['text', 'テキスト入力', FileText], ['file', 'ファイルアップロード', Upload]] as const).map(([mode, label, Icon]) => (
              <button
                key={mode}
                onClick={() => { setImportMode(mode); setFileError(null); setImportResult(null) }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-sm text-xs transition-colors ${
                  importMode === mode ? 'bg-[#1e2d42] text-white' : 'text-[#5a6a7a] hover:text-[#8899aa]'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {label}
              </button>
            ))}
          </div>

          {/* Format help */}
          <div className="text-[10px] text-[#5a6a7a] bg-[#080c14]/60 rounded-sm p-2 font-mono leading-5 border border-[#1e2d42]">
            <span className="text-[#8899aa] font-sans font-medium text-xs">フォーマット（1行1エントリ）:</span><br />
            {'# コメント行 (無視されます)'}<br />
            {'値のみ（タイプ自動判定）:   1.2.3.4'}<br />
            {'タイプ,値:                 ip,1.2.3.4'}<br />
            {'タイプ,値,説明:            domain,evil.com,C2 server'}<br />
            {'タイプ,値,説明,重大度:     hash,abc123...,malware,9'}
          </div>

          {/* Options row */}
          <div className="flex gap-3 items-end flex-wrap">
            <div>
              <label className="text-xs text-[#8899aa] block mb-1">デフォルトタイプ（自動判定失敗時）</label>
              <select
                value={importType}
                onChange={e => setImportType(e.target.value)}
                className="text-sm bg-[#080c14] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-[#e2e8f4] focus:outline-hidden focus:border-orange-500"
              >
                <option value="">自動</option>
                {['ip','domain','hash','url','email'].map(t => (
                  <option key={t} value={t}>{TYPE_LABELS[t]}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-[#8899aa] block mb-1">デフォルト重大度</label>
              <input
                type="number" min={1} max={10}
                value={importSeverity}
                onChange={e => setImportSeverity(Number(e.target.value))}
                className="w-16 text-sm bg-[#080c14] border border-[#1e2d42] rounded-sm px-2 py-1.5 text-[#e2e8f4] focus:outline-hidden focus:border-orange-500"
              />
            </div>
          </div>

          {/* Input area */}
          {importMode === 'text' ? (
            <textarea
              value={importText}
              onChange={e => { setImportText(e.target.value); setImportResult(null) }}
              placeholder={'# 1行1エントリ\n1.2.3.4\nevil.com\nip,10.0.0.1,内部不審IP,8'}
              rows={8}
              className="w-full text-xs bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#e2e8f4] placeholder-gray-700 font-mono focus:outline-hidden focus:border-orange-500 resize-y"
            />
          ) : (
            <div>
              <div
                onDragOver={e => { e.preventDefault(); setIsDragOver(true) }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={e => {
                  e.preventDefault()
                  setIsDragOver(false)
                  const file = e.dataTransfer.files[0]
                  if (file) handleFileImport(file)
                }}
                className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer
                  ${isDragOver ? 'border-orange-500 bg-orange-500/10' : 'border-[#1e2d42] bg-[#080c14] hover:border-[#2d4a6e]'}`}
              >
                <Upload className="w-8 h-8 mx-auto mb-3 text-[#3d5068]" />
                <p className="text-sm text-[#8899aa] mb-1">ファイルをドラッグ＆ドロップ</p>
                <p className="text-xs text-[#3d5068] mb-3">CSV (.csv) または STIX 2.1 (.json)</p>
                <label className="inline-flex items-center gap-2 px-3 py-1.5 bg-orange-600 hover:bg-orange-700 text-white text-xs rounded-lg cursor-pointer transition-colors">
                  <File className="w-3.5 h-3.5" />
                  ファイルを選択
                  <input
                    type="file"
                    accept=".csv,.json"
                    className="hidden"
                    onChange={e => {
                      const file = e.target.files?.[0]
                      if (file) handleFileImport(file)
                    }}
                  />
                </label>
              </div>
              {fileError && (
                <p className="mt-2 text-xs text-red-400 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" /> {fileError}
                </p>
              )}
              {importText && !fileError && (
                <div className="mt-2 bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2">
                  <p className="text-[10px] text-[#5a6a7a] mb-1">解析済み（{importText.split('\n').filter(Boolean).length}行）</p>
                  <pre className="text-xs text-[#7d92b0] font-mono max-h-32 overflow-y-auto">{importText.slice(0, 500)}{importText.length > 500 ? '\n...' : ''}</pre>
                </div>
              )}
            </div>
          )}

          {/* Result */}
          {importResult && (
            <div className={`flex items-start gap-2 text-xs rounded-lg px-3 py-2 ${
              importResult.inserted > 0 ? 'bg-green-900/30 border border-green-700/50 text-green-300'
                                        : 'bg-yellow-900/30 border border-yellow-700/50 text-yellow-300'
            }`}>
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-medium">
                  {importResult.inserted}件をインポートしました（解析: {importResult.parsed}件）
                </p>
                {importResult.skipped.length > 0 && (
                  <p className="mt-1 text-[10px] text-yellow-400">
                    スキップ: {importResult.skipped.join(', ')}
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Action */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => importMutation.mutate({ lines: importText, default_type: importType, severity: importSeverity })}
              disabled={!importText.trim() || importMutation.isPending}
              className="px-4 py-1.5 text-sm bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 transition-colors"
            >
              {importMutation.isPending ? 'インポート中...' : 'インポート実行'}
            </button>
            <span className="text-[10px] text-[#5a6a7a]">
              {importText.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length} 行
            </span>
            {importMutation.isError && (
              <p className="text-red-400 text-xs flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                {(importMutation.error as Error).message}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Add form */}
      {showAdd && (
        <div className="mb-6 bg-[#111827] rounded-xl border border-[#1e2d42] p-4 space-y-3">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-sm font-semibold text-white">新規IOC登録</h3>
            <button onClick={() => setShowAdd(false)}>
              <X className="w-4 h-4 text-[#5a6a7a] hover:text-[#8899aa]" />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div>
              <label className="text-xs text-[#8899aa] block mb-1">タイプ</label>
              <select
                value={form.type}
                onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
                className="w-full text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#e2e8f4] focus:outline-hidden focus:border-orange-500"
              >
                {IOC_TYPES.filter(Boolean).map(t => (
                  <option key={t} value={t}>{TYPE_LABELS[t]}</option>
                ))}
              </select>
            </div>
            <div className="sm:col-span-2">
              <label className="text-xs text-[#8899aa] block mb-1">値 <span className="text-red-400">*</span></label>
              <input
                value={form.value}
                onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
                placeholder="例: 1.2.3.4 / evil.com / abc123..."
                className="w-full text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-hidden focus:border-orange-500"
              />
            </div>
            <div>
              <label className="text-xs text-[#8899aa] block mb-1">重大度 (1-10)</label>
              <input
                type="number"
                min={1} max={10}
                value={form.severity}
                onChange={e => setForm(f => ({ ...f, severity: Number(e.target.value) }))}
                className="w-full text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#e2e8f4] focus:outline-hidden focus:border-orange-500"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-[#8899aa] block mb-1">説明</label>
            <input
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="このIOCの説明（任意）"
              className="w-full text-sm bg-[#080c14] border border-[#1e2d42] rounded-lg px-3 py-2 text-[#e2e8f4] placeholder-[#5a6a7a] focus:outline-hidden focus:border-orange-500"
            />
          </div>
          <div className="flex gap-2 pt-1">
            <button
              onClick={() => createMutation.mutate(form)}
              disabled={!form.value.trim() || createMutation.isPending}
              className="px-4 py-1.5 text-sm bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 transition-colors"
            >
              {createMutation.isPending ? '登録中...' : '登録'}
            </button>
            {createMutation.isError && (
              <p className="text-red-400 text-xs flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                {(createMutation.error as Error).message}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 mb-4 flex-wrap items-center">
        <div className="flex gap-1">
          {IOC_TYPES.map(t => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-3 py-1 text-xs rounded-full transition-colors ${
                typeFilter === t
                  ? 'bg-orange-600 text-white'
                  : 'bg-[#161f33] border border-[#1e2d42] text-[#8899aa] hover:border-[#8899aa]'
              }`}
            >
              {TYPE_LABELS[t]}
            </button>
          ))}
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="値で検索..."
            className="pl-8 pr-3 py-1.5 text-sm border border-[#1e2d42] rounded-lg bg-[#111827] text-white placeholder-[#5a6a7a] w-48 focus:outline-hidden focus:border-orange-500"
          />
        </div>
        {(typeFilter || search) && (
          <button
            onClick={() => { setTypeFilter(''); setSearch('') }}
            className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-white px-2 py-1 rounded-lg hover:bg-[#161f33] transition-colors"
          >
            <X className="w-3.5 h-3.5" />クリア
          </button>
        )}
        <span className="ml-auto text-xs text-[#5a6a7a]">{data?.total ?? 0}件</span>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-12 bg-[#111827] rounded-xl border border-[#1e2d42] animate-pulse" />
          ))}
        </div>
      ) : entries.length === 0 ? (
        <div className="text-center py-16 bg-[#111827] rounded-xl border border-[#1e2d42]">
          <Shield className="w-10 h-10 text-[#5a6a7a] mx-auto mb-2" />
          <p className="text-[#5a6a7a] text-sm">IOCエントリがありません</p>
          <p className="text-[#5a6a7a] text-xs mt-1">「IOCを追加」から登録してください</p>
        </div>
      ) : (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#080c14]/40 text-xs text-[#8899aa]">
                <th className="text-left px-4 py-3">タイプ</th>
                <th className="text-left px-4 py-3">値</th>
                <th className="text-left px-4 py-3">説明</th>
                <th className="text-left px-4 py-3">重大度</th>
                <th className="text-left px-4 py-3">状態</th>
                <th className="text-left px-4 py-3">追加者</th>
                <th className="text-left px-4 py-3">登録日</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]/50">
              {entries.map(entry => (
                <tr key={entry.id}
                  className={`hover:bg-[#161f33]/30 transition-colors ${!entry.is_active ? 'opacity-50' : ''}`}
                >
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-mono ${TYPE_COLORS[entry.type] ?? ''}`}>
                      {entry.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[#e2e8f4] max-w-[240px] truncate">
                    {entry.value}
                  </td>
                  <td className="px-4 py-3 text-xs text-[#8899aa] max-w-[200px] truncate">
                    {entry.description || '—'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-bold ${severityColor(entry.severity)}`}>
                      {entry.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {canWrite ? (
                      <button
                        onClick={() => toggleMutation.mutate({ id: entry.id, active: !entry.is_active })}
                        disabled={toggleMutation.isPending}
                        title={entry.is_active ? '無効にする' : '有効にする'}
                        className="flex items-center gap-1 text-xs transition-colors"
                      >
                        {entry.is_active
                          ? <ToggleRight className="w-5 h-5 text-green-400" />
                          : <ToggleLeft className="w-5 h-5 text-[#5a6a7a]" />}
                        <span className={entry.is_active ? 'text-green-400' : 'text-[#5a6a7a]'}>
                          {entry.is_active ? '有効' : '無効'}
                        </span>
                      </button>
                    ) : (
                      <span className="flex items-center gap-1 text-xs">
                        {entry.is_active
                          ? <ToggleRight className="w-5 h-5 text-green-400" />
                          : <ToggleLeft className="w-5 h-5 text-[#5a6a7a]" />}
                        <span className={entry.is_active ? 'text-green-400' : 'text-[#5a6a7a]'}>
                          {entry.is_active ? '有効' : '無効'}
                        </span>
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-[#5a6a7a]">{entry.added_by_name || '—'}</td>
                  <td className="px-4 py-3 text-xs text-[#5a6a7a]">
                    {new Date(entry.created_at).toLocaleDateString('ja-JP')}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {/* VT lookup — only for hash/ip/domain */}
                      {(entry.type === 'hash' || entry.type === 'ip' || entry.type === 'domain') && (
                        <Link
                          href={`/intel/vt?q=${encodeURIComponent(entry.value)}`}
                          title="VirusTotalで確認"
                          className="text-[#5a6a7a] hover:text-blue-400 transition-colors"
                        >
                          <ScanSearch className="w-4 h-4" />
                        </Link>
                      )}
                      {canWrite && (deleteConfirm === entry.id ? (
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => deleteMutation.mutate(entry.id)}
                            disabled={deleteMutation.isPending}
                            className="text-xs text-red-400 hover:text-red-300 font-medium"
                          >削除</button>
                          <button
                            onClick={() => setDeleteConfirm(null)}
                            className="text-xs text-[#5a6a7a] hover:text-[#8899aa]"
                          >取消</button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setDeleteConfirm(entry.id)}
                          className="text-[#5a6a7a] hover:text-red-400 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
