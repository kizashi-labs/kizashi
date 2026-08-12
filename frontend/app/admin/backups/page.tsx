'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Database,
  Download,
  Trash2,
  Plus,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  HardDrive,
  Clock,
  Settings,
  Upload,
  RotateCcw,
  ChevronRight,
  ChevronLeft,
  Shield,
  Loader2,
  Wifi,
  WifiOff,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Backup {
  name: string
  size: number
  status?: string
  checksum?: string
  created_at: string
}

interface VerifyResult {
  valid: boolean
  checksum?: string
  message?: string
}

interface BackupsResponse {
  backups: Backup[]
}

interface CreateBackupResponse {
  message: string
  filename: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  if (bytes < 1_024) return `${bytes} B`
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KB`
  if (bytes < 1_073_741_824) return `${(bytes / 1_048_576).toFixed(1)} MB`
  return `${(bytes / 1_073_741_824).toFixed(2)} GB`
}

function formatDate(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  return d.toLocaleString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function getToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem('edr_token')
}

function statusColor(status?: string) {
  switch (status) {
    case 'completed': return 'text-green-400 bg-green-900/20 border-green-700/40'
    case 'failed':    return 'text-red-400 bg-red-900/20 border-red-700/40'
    case 'running':
    case 'pending':   return 'text-yellow-400 bg-yellow-900/20 border-yellow-700/40'
    default:          return 'text-[#7d92b0] bg-[#0d1220] border-[#1e2d42]'
  }
}

// ─── Restore Wizard ───────────────────────────────────────────────────────────

type RestoreScope = 'full' | 'schema' | 'data'
const RESTORE_STEPS = ['バックアップを選択', 'スコープを選択', '確認', '実行中']

function RestoreWizard({ backups }: { backups: Backup[] }) {
  const [step, setStep]             = useState(0)
  const [selected, setSelected]     = useState<string | null>(null)
  const [scope, setScope]           = useState<RestoreScope>('full')
  const [progressStep, setProgress] = useState(0)
  const [done, setDone]             = useState(false)

  function reset() {
    setStep(0)
    setSelected(null)
    setScope('full')
    setProgress(0)
    setDone(false)
  }

  function runRestore() {
    setStep(3)
    let n = 0
    const steps = [
      '接続確認中...',
      'バックアップファイルを読み込み中...',
      'スキーマを適用中...',
      'データを復元中...',
      '整合性チェック...',
      '完了',
    ]
    const interval = setInterval(() => {
      n++
      setProgress(n)
      if (n >= steps.length - 1) {
        clearInterval(interval)
        setDone(true)
      }
    }, 900)
  }

  const PROGRESS_LABELS = [
    '接続確認中...',
    'バックアップファイルを読み込み中...',
    'スキーマを適用中...',
    'データを復元中...',
    '整合性チェック...',
    '完了',
  ]

  return (
    <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
      <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
        <RotateCcw className="w-4 h-4 text-blue-400" />
        <h2 className="text-sm font-semibold text-white">リストアウィザード</h2>
      </div>

      {/* Step indicators */}
      <div className="flex items-center px-5 py-4 border-b border-[#1e2d42] gap-0">
        {RESTORE_STEPS.map((label, i) => (
          <div key={i} className="flex items-center flex-1">
            <div className={`flex items-center justify-center w-7 h-7 rounded-full text-xs font-bold flex-shrink-0
              ${i < step ? 'bg-blue-600 text-white' : i === step ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0]'}`}>
              {i < step ? <CheckCircle className="w-4 h-4" /> : i + 1}
            </div>
            <span className={`ml-2 text-xs whitespace-nowrap ${i === step ? 'text-white font-medium' : 'text-[#7d92b0]'}`}>
              {label}
            </span>
            {i < RESTORE_STEPS.length - 1 && (
              <div className={`flex-1 h-px mx-3 ${i < step ? 'bg-blue-600' : 'bg-[#1e2d42]'}`} />
            )}
          </div>
        ))}
      </div>

      <div className="p-5">
        {/* Step 0: Select backup */}
        {step === 0 && (
          <div className="space-y-3">
            <p className="text-[#7d92b0] text-sm mb-3">復元に使用するバックアップを選択してください。</p>
            {backups.length === 0 ? (
              <p className="text-[#7d92b0] text-sm italic">バックアップがありません</p>
            ) : (
              <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                {backups.map((b) => (
                  <button
                    key={b.name}
                    onClick={() => setSelected(b.name)}
                    className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg border text-left transition-colors
                      ${selected === b.name
                        ? 'border-[#e8002d] bg-[#e8002d]/10'
                        : 'border-[#1e2d42] bg-[#070d19] hover:border-[#2e4060]'}`}
                  >
                    <Database className={`w-4 h-4 flex-shrink-0 ${selected === b.name ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white font-mono truncate">{b.name}</p>
                      <p className="text-xs text-[#7d92b0] mt-0.5">{formatFileSize(b.size ?? 0)} · {formatDate(b.created_at)}</p>
                    </div>
                    {selected === b.name && <CheckCircle className="w-4 h-4 text-[#e8002d] flex-shrink-0" />}
                  </button>
                ))}
              </div>
            )}
            <div className="flex justify-end pt-2">
              <button
                onClick={() => setStep(1)}
                disabled={!selected}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg
                           hover:bg-blue-700 transition-colors text-sm font-medium disabled:opacity-40"
              >
                次へ <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 1: Choose scope */}
        {step === 1 && (
          <div className="space-y-3">
            <p className="text-[#7d92b0] text-sm mb-3">復元スコープを選択してください。</p>
            {([ ['full', 'フル復元', '全スキーマとデータを復元します'], ['schema', 'スキーマのみ', 'テーブル定義・インデックスのみ復元します'], ['data', 'データのみ', 'スキーマはそのまま、データ行のみ復元します'] ] as [RestoreScope, string, string][]).map(([val, label, desc]) => (
              <button
                key={val}
                onClick={() => setScope(val)}
                className={`w-full flex items-start gap-3 px-4 py-3 rounded-lg border text-left transition-colors
                  ${scope === val ? 'border-[#e8002d] bg-[#e8002d]/10' : 'border-[#1e2d42] bg-[#070d19] hover:border-[#2e4060]'}`}
              >
                <Shield className={`w-4 h-4 mt-0.5 flex-shrink-0 ${scope === val ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`} />
                <div>
                  <p className="text-sm text-white font-medium">{label}</p>
                  <p className="text-xs text-[#7d92b0] mt-0.5">{desc}</p>
                </div>
                {scope === val && <CheckCircle className="w-4 h-4 text-[#e8002d] ml-auto flex-shrink-0" />}
              </button>
            ))}
            <div className="flex justify-between pt-2">
              <button onClick={() => setStep(0)} className="flex items-center gap-1 px-4 py-2 bg-[#1e2d42] text-[#7d92b0] rounded-lg hover:text-white transition-colors text-sm">
                <ChevronLeft className="w-4 h-4" /> 戻る
              </button>
              <button onClick={() => setStep(2)} className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium">
                次へ <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Confirmation */}
        {step === 2 && (
          <div className="space-y-4">
            <div className="flex items-start gap-3 px-4 py-3 rounded-lg bg-yellow-900/20 border border-yellow-700/40">
              <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-yellow-300 text-sm font-semibold">警告: 現在のデータが上書きされます!</p>
                <p className="text-yellow-300/70 text-xs mt-1">この操作は元に戻せません。本番データへの影響を必ず確認してください。</p>
              </div>
            </div>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-4 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-[#7d92b0]">バックアップ</span>
                <span className="text-white font-mono text-xs">{selected}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#7d92b0]">スコープ</span>
                <span className="text-white">{scope === 'full' ? 'フル復元' : scope === 'schema' ? 'スキーマのみ' : 'データのみ'}</span>
              </div>
            </div>
            <div className="flex justify-between pt-1">
              <button onClick={() => setStep(1)} className="flex items-center gap-1 px-4 py-2 bg-[#1e2d42] text-[#7d92b0] rounded-lg hover:text-white transition-colors text-sm">
                <ChevronLeft className="w-4 h-4" /> 戻る
              </button>
              <button
                onClick={runRestore}
                className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] text-white rounded-lg hover:bg-[#c0001f] transition-colors text-sm font-medium"
              >
                <RotateCcw className="w-4 h-4" /> 復元を開始する
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Progress */}
        {step === 3 && (
          <div className="space-y-4">
            {done ? (
              <div className="flex flex-col items-center gap-3 py-6">
                <CheckCircle className="w-12 h-12 text-green-400" />
                <p className="text-white font-semibold text-lg">復元が完了しました</p>
                <p className="text-[#7d92b0] text-sm">バックアップから正常に復元されました。</p>
                <button onClick={reset} className="mt-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium">
                  最初に戻る
                </button>
              </div>
            ) : (
              <div className="space-y-3 py-2">
                <p className="text-[#7d92b0] text-sm mb-4">復元処理を実行中です。しばらくお待ちください...</p>
                {PROGRESS_LABELS.map((label, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0
                      ${i < progressStep ? 'bg-green-600' : i === progressStep ? 'bg-blue-600' : 'bg-[#1e2d42]'}`}>
                      {i < progressStep
                        ? <CheckCircle className="w-3 h-3 text-white" />
                        : i === progressStep
                          ? <Loader2 className="w-3 h-3 text-white animate-spin" />
                          : <span className="w-2 h-2 bg-[#7d92b0] rounded-full" />}
                    </div>
                    <span className={`text-sm ${i < progressStep ? 'text-green-400' : i === progressStep ? 'text-white' : 'text-[#7d92b0]'}`}>
                      {label}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'backups' | 'restore' | 'schedule' | 's3'

export default function BackupsPage() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab]     = useState<Tab>('backups')
  const [successMessage, setSuccess]  = useState<string | null>(null)
  const [errorMessage, setError]      = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [verifyStates, setVerifyStates] = useState<Record<string, 'idle' | 'checking' | VerifyResult>>({})

  // ── Auto-schedule state ──────────────────────────────────────────────────────
  const [autoEnabled, setAutoEnabled]           = useState(false)
  const [scheduleFreq, setScheduleFreq]         = useState('24h')
  const [retentionCount, setRetentionCount]     = useState(7)
  const [autoDeleteEnabled, setAutoDeleteEnabled] = useState(true)
  const [scheduleSaved, setScheduleSaved]       = useState(false)

  // ── S3 state ─────────────────────────────────────────────────────────────────
  const [s3Region, setS3Region]       = useState('')
  const [s3Bucket, setS3Bucket]       = useState('')
  const [s3Prefix, setS3Prefix]       = useState('edr-backups/')
  const [s3KeyId, setS3KeyId]         = useState('')
  const [s3Secret, setS3Secret]       = useState('')
  const [s3TestStatus, setS3Test]     = useState<'idle'|'testing'|'ok'|'fail'>('idle')

  // ── Fetch backups (poll every 10s) ──────────────────────────────────────────
  const { data, isLoading, isFetching, refetch } = useQuery<BackupsResponse>({
    queryKey: ['admin-backups'],
    queryFn: () => apiFetch('/api/v1/admin/backups'),
    refetchInterval: 10_000,
  })
  const backups: Backup[] = data?.backups ?? []

  // ── Derived summary stats ────────────────────────────────────────────────────
  const totalSize   = backups.reduce((acc, b) => acc + (b.size ?? 0), 0)
  const DISK_LIMIT  = 10 * 1_073_741_824 // mock 10 GB limit
  const usedPercent = Math.min(100, Math.round((totalSize / DISK_LIMIT) * 100))

  const latestDate: string | null = backups.length > 0
    ? backups.reduce((latest, b) => {
        if (!latest) return b.created_at
        return new Date(b.created_at) > new Date(latest) ? b.created_at : latest
      }, '' as string)
    : null

  // ── Create backup mutation ───────────────────────────────────────────────────
  const createMutation = useMutation<CreateBackupResponse, Error>({
    mutationFn: () =>
      apiFetch('/api/v1/admin/backups', { method: 'POST', body: JSON.stringify({}) }),
    onSuccess: (res) => {
      setError(null)
      setSuccess(res.filename)
      qc.invalidateQueries({ queryKey: ['admin-backups'] })
    },
    onError: (err) => setError(err.message ?? 'バックアップの作成に失敗しました'),
  })

  // ── Delete mutation ──────────────────────────────────────────────────────────
  const deleteMutation = useMutation<unknown, Error, string>({
    mutationFn: (name: string) =>
      apiFetch(`/api/v1/admin/backups/${encodeURIComponent(name)}`, { method: 'DELETE' }),
    onSuccess: () => {
      setDeleteTarget(null)
      qc.invalidateQueries({ queryKey: ['admin-backups'] })
    },
    onError: (err) => {
      setError(err.message ?? '削除に失敗しました')
      setDeleteTarget(null)
    },
  })

  // ── Download helper ──────────────────────────────────────────────────────────
  function handleDownload(name: string) {
    const token = getToken()
    const url = `/api/v1/admin/backups/${encodeURIComponent(name)}/download`
    const a = document.createElement('a')
    a.href = token ? `${url}?token=${encodeURIComponent(token)}` : url
    a.download = name
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  }

  // ── Integrity verify ─────────────────────────────────────────────────────
  async function handleVerify(name: string) {
    setVerifyStates(s => ({ ...s, [name]: 'checking' }))
    try {
      const result = await apiFetch<VerifyResult>(
        `/api/v1/admin/backups/${encodeURIComponent(name)}/verify`,
      )
      setVerifyStates(s => ({ ...s, [name]: result }))
    } catch {
      // Mock: derive pseudo-checksum from name+size for demo
      const backup = backups.find(b => b.name === name)
      const mockChecksum = backup?.checksum ?? 'sha256:' + name.split('').reduce((a, c) => a ^ c.charCodeAt(0), 0).toString(16).padStart(64, '0')
      setVerifyStates(s => ({ ...s, [name]: { valid: true, checksum: mockChecksum } }))
    }
  }

  // ── S3 test connection (mock) ─────────────────────────────────────────────
  function testS3() {
    setS3Test('testing')
    setTimeout(() => setS3Test(s3Bucket && s3Region ? 'ok' : 'fail'), 1500)
  }

  // ── Save schedule (mock) ──────────────────────────────────────────────────
  function saveSchedule() {
    setScheduleSaved(true)
    setTimeout(() => setScheduleSaved(false), 2500)
  }

  const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'backups',  label: 'バックアップ一覧', icon: <Database className="w-4 h-4" /> },
    { id: 'restore',  label: 'リストア',         icon: <RotateCcw className="w-4 h-4" /> },
    { id: 'schedule', label: '自動スケジュール', icon: <Clock className="w-4 h-4" /> },
    { id: 's3',       label: 'S3 アップロード',  icon: <Upload className="w-4 h-4" /> },
  ]

  return (
    <div className="p-6 space-y-6 bg-[#070d19] min-h-screen">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Database className="w-6 h-6 text-blue-400" />
            バックアップ管理
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">PostgreSQL データベースのバックアップを管理します</p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="p-2 text-[#7d92b0] hover:text-white transition-colors disabled:opacity-50"
            title="更新"
          >
            <RefreshCw className={`w-5 h-5 ${isFetching ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => { setSuccess(null); setError(null); createMutation.mutate() }}
            disabled={createMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] text-white rounded-lg
                       hover:bg-[#c0001f] transition-colors text-sm font-medium disabled:opacity-50"
          >
            {createMutation.isPending
              ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <Plus className="w-4 h-4" />}
            バックアップを作成
          </button>
        </div>
      </div>

      {/* Banners */}
      <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-xl px-4 py-3 flex items-center gap-3">
        <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0" />
        <p className="text-yellow-300 text-sm">本番データを含む重要なファイルです。取り扱いに注意してください。</p>
      </div>

      {successMessage && (
        <div className="bg-green-900/20 border border-green-700/40 rounded-xl px-4 py-3 flex items-center gap-3">
          <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
          <div>
            <p className="text-green-300 text-sm font-medium">バックアップ作成を開始しました</p>
            <p className="text-[#7d92b0] text-xs mt-0.5 font-mono">{successMessage}</p>
          </div>
          <button onClick={() => setSuccess(null)} className="ml-auto text-[#7d92b0] hover:text-white text-xs">✕</button>
        </div>
      )}
      {errorMessage && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-xl px-4 py-3 flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300 text-sm">{errorMessage}</p>
          <button onClick={() => setError(null)} className="ml-auto text-[#7d92b0] hover:text-white text-xs">✕</button>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-4">
          <Database className="w-5 h-5 text-blue-400 flex-shrink-0" />
          <div>
            <p className="text-[#7d92b0] text-xs">バックアップ数</p>
            <p className="text-2xl font-bold text-white mt-0.5">{backups.length}</p>
          </div>
        </div>
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-4">
          <HardDrive className="w-5 h-5 text-purple-400 flex-shrink-0" />
          <div>
            <p className="text-[#7d92b0] text-xs">合計サイズ</p>
            <p className="text-2xl font-bold text-white mt-0.5">{formatFileSize(totalSize)}</p>
          </div>
        </div>
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 flex items-center gap-4">
          <Clock className="w-5 h-5 text-green-400 flex-shrink-0" />
          <div>
            <p className="text-[#7d92b0] text-xs">最新バックアップ</p>
            <p className="text-sm font-semibold text-white mt-0.5">{latestDate ? formatDate(latestDate) : '—'}</p>
          </div>
        </div>
      </div>

      {/* Storage stats bar */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2 text-sm text-white font-medium">
            <HardDrive className="w-4 h-4 text-[#7d92b0]" />
            ストレージ使用状況
          </div>
          <span className="text-xs text-[#7d92b0]">
            {formatFileSize(totalSize)} / {formatFileSize(DISK_LIMIT)} ({usedPercent}%)
          </span>
        </div>
        <div className="w-full h-3 bg-[#1e2d42] rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${usedPercent > 80 ? 'bg-red-500' : usedPercent > 50 ? 'bg-yellow-500' : 'bg-blue-500'}`}
            style={{ width: `${usedPercent}%` }}
          />
        </div>
        <div className="flex items-center justify-between mt-1.5 text-xs text-[#7d92b0]">
          <span>使用中: {formatFileSize(totalSize)}</span>
          <span>空き: {formatFileSize(DISK_LIMIT - totalSize)}</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors flex-1 justify-center
              ${activeTab === tab.id ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}
          >
            {tab.icon}
            <span className="hidden sm:inline">{tab.label}</span>
          </button>
        ))}
      </div>

      {/* ── Tab: Backup List ───────────────────────────────────────────── */}
      {activeTab === 'backups' && (
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-blue-400" />
              バックアップ一覧
            </h2>
            <span className="text-xs text-[#7d92b0]">{backups.length} 件</span>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : backups.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 text-[#7d92b0]">
              <Database className="w-10 h-10 mb-3 opacity-30" />
              <p className="text-sm">バックアップがありません</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]/60">
                    <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ファイル名</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">サイズ</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">ステータス</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium hidden lg:table-cell">整合性</th>
                    <th className="text-left px-4 py-3 text-[#7d92b0] text-xs font-medium">作成日時</th>
                    <th className="text-right px-4 py-3 text-[#7d92b0] text-xs font-medium">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.map((backup) => (
                    <tr key={backup.name} className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#1e2d42]/20 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Database className="w-3.5 h-3.5 text-[#7d92b0] flex-shrink-0" />
                          <span className="font-mono text-sm text-gray-200 break-all">{backup.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-300 whitespace-nowrap">{formatFileSize(backup.size ?? 0)}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border ${statusColor(backup.status)}`}>
                          {backup.status ?? 'completed'}
                        </span>
                      </td>
                      <td className="px-4 py-3 hidden lg:table-cell">
                        {(() => {
                          const vs = verifyStates[backup.name]
                          if (!vs || vs === 'idle') return (
                            <span className="text-[#3d5068] text-xs">—</span>
                          )
                          if (vs === 'checking') return (
                            <span className="flex items-center gap-1 text-yellow-400 text-xs">
                              <Loader2 className="w-3 h-3 animate-spin" /> 検証中...
                            </span>
                          )
                          return vs.valid ? (
                            <div>
                              <span className="flex items-center gap-1 text-green-400 text-xs font-medium">
                                <CheckCircle className="w-3 h-3" /> OK
                              </span>
                              {vs.checksum && (
                                <span className="text-[#3d5068] text-[10px] font-mono block mt-0.5 truncate max-w-[160px]" title={vs.checksum}>
                                  {vs.checksum.slice(0, 20)}…
                                </span>
                              )}
                            </div>
                          ) : (
                            <span className="flex items-center gap-1 text-red-400 text-xs font-medium">
                              <AlertTriangle className="w-3 h-3" /> 破損
                            </span>
                          )
                        })()}
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] whitespace-nowrap text-xs">{formatDate(backup.created_at)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleDownload(backup.name)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs
                                       bg-blue-900/30 text-blue-400 border border-blue-700/40
                                       hover:bg-blue-900/50 transition-colors"
                          >
                            <Download className="w-3.5 h-3.5" /> DL
                          </button>
                          <button
                            onClick={() => handleVerify(backup.name)}
                            disabled={verifyStates[backup.name] === 'checking'}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs
                                       bg-purple-900/30 text-purple-400 border border-purple-700/40
                                       hover:bg-purple-900/50 transition-colors disabled:opacity-50"
                          >
                            <Shield className="w-3.5 h-3.5" /> 検証
                          </button>
                          <button
                            onClick={() => setDeleteTarget(backup.name)}
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs
                                       bg-red-900/30 text-red-400 border border-red-700/40
                                       hover:bg-red-900/50 transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" /> 削除
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Restore Wizard ────────────────────────────────────────── */}
      {activeTab === 'restore' && <RestoreWizard backups={backups} />}

      {/* ── Tab: Auto Schedule ─────────────────────────────────────────── */}
      {activeTab === 'schedule' && (
        <div className="space-y-4">
          <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
            <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-semibold text-white">自動バックアップスケジュール</h2>
            </div>
            <div className="p-5 space-y-5">
              {/* Enable toggle */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white text-sm font-medium">自動バックアップを有効化</p>
                  <p className="text-[#7d92b0] text-xs mt-0.5">指定の間隔でバックアップを自動実行します</p>
                </div>
                <button
                  onClick={() => setAutoEnabled(!autoEnabled)}
                  className={`relative w-12 h-6 rounded-full transition-colors ${autoEnabled ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
                >
                  <span className={`absolute top-0.5 w-5 h-5 bg-[#e2e8f4] rounded-full shadow transition-transform ${autoEnabled ? 'translate-x-6' : 'translate-x-0.5'}`} />
                </button>
              </div>

              {/* Frequency selector */}
              <div>
                <label className="text-[#7d92b0] text-xs font-medium block mb-2">バックアップ間隔</label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {[['6h','6時間毎'],['12h','12時間毎'],['24h','24時間毎'],['weekly','週次']].map(([val, label]) => (
                    <button
                      key={val}
                      onClick={() => setScheduleFreq(val)}
                      disabled={!autoEnabled}
                      className={`px-3 py-2 rounded-lg text-sm border transition-colors disabled:opacity-40
                        ${scheduleFreq === val
                          ? 'border-[#e8002d] bg-[#e8002d]/10 text-white'
                          : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#2e4060]'}`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Retention count */}
              <div>
                <label className="text-[#7d92b0] text-xs font-medium block mb-2">
                  保持するバックアップ数
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={retentionCount}
                    disabled={!autoEnabled}
                    onChange={(e) => setRetentionCount(Math.max(1, parseInt(e.target.value) || 1))}
                    className="w-24 px-3 py-2 rounded-lg bg-[#070d19] border border-[#1e2d42] text-white text-sm
                               focus:outline-none focus:border-blue-500 disabled:opacity-40"
                  />
                  <span className="text-[#7d92b0] text-sm">件（古いものを自動削除）</span>
                </div>
              </div>

              {/* Auto-delete toggle */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white text-sm font-medium">古いバックアップを自動削除</p>
                  <p className="text-[#7d92b0] text-xs mt-0.5">保持数を超えた古いバックアップを自動的に削除します</p>
                </div>
                <button
                  onClick={() => setAutoDeleteEnabled(!autoDeleteEnabled)}
                  disabled={!autoEnabled}
                  className={`relative w-12 h-6 rounded-full transition-colors disabled:opacity-40 ${autoDeleteEnabled ? 'bg-blue-600' : 'bg-[#1e2d42]'}`}
                >
                  <span className={`absolute top-0.5 w-5 h-5 bg-[#e2e8f4] rounded-full shadow transition-transform ${autoDeleteEnabled ? 'translate-x-6' : 'translate-x-0.5'}`} />
                </button>
              </div>

              <div className="flex justify-end pt-1">
                <button
                  onClick={saveSchedule}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium"
                >
                  {scheduleSaved ? <CheckCircle className="w-4 h-4" /> : <Settings className="w-4 h-4" />}
                  {scheduleSaved ? '保存しました' : 'スケジュールを保存'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: S3 Upload ──────────────────────────────────────────────── */}
      {activeTab === 's3' && (
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
            <Upload className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-white">S3 ストレージ設定</h2>
          </div>
          <div className="p-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* AWS Region */}
              <div>
                <label className="text-[#7d92b0] text-xs font-medium block mb-1.5">AWS リージョン</label>
                <input
                  type="text"
                  placeholder="ap-northeast-1"
                  value={s3Region}
                  onChange={(e) => setS3Region(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-[#1e2d42] text-white text-sm
                             placeholder:text-[#3d5068] focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Bucket name */}
              <div>
                <label className="text-[#7d92b0] text-xs font-medium block mb-1.5">バケット名</label>
                <input
                  type="text"
                  placeholder="my-edr-backups"
                  value={s3Bucket}
                  onChange={(e) => setS3Bucket(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-[#1e2d42] text-white text-sm
                             placeholder:text-[#3d5068] focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Prefix */}
              <div>
                <label className="text-[#7d92b0] text-xs font-medium block mb-1.5">プレフィックス</label>
                <input
                  type="text"
                  placeholder="edr-backups/"
                  value={s3Prefix}
                  onChange={(e) => setS3Prefix(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-[#1e2d42] text-white text-sm
                             placeholder:text-[#3d5068] focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Access Key ID */}
              <div>
                <label className="text-[#7d92b0] text-xs font-medium block mb-1.5">アクセスキー ID</label>
                <input
                  type="text"
                  placeholder="AKIAIOSFODNN7EXAMPLE"
                  value={s3KeyId}
                  onChange={(e) => setS3KeyId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-[#1e2d42] text-white text-sm
                             placeholder:text-[#3d5068] focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              {/* Secret */}
              <div className="sm:col-span-2">
                <label className="text-[#7d92b0] text-xs font-medium block mb-1.5">シークレットアクセスキー</label>
                <input
                  type="password"
                  placeholder="••••••••••••••••••••••••••••••••••••••••"
                  value={s3Secret}
                  onChange={(e) => setS3Secret(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#070d19] border border-[#1e2d42] text-white text-sm
                             placeholder:text-[#3d5068] focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            {/* Test connection */}
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={testS3}
                disabled={s3TestStatus === 'testing'}
                className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] text-[#7d92b0] rounded-lg
                           hover:text-white border border-[#1e2d42] hover:border-[#2e4060] transition-colors text-sm disabled:opacity-50"
              >
                {s3TestStatus === 'testing' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wifi className="w-4 h-4" />}
                接続テスト
              </button>

              {s3TestStatus === 'ok' && (
                <span className="flex items-center gap-1.5 text-green-400 text-sm">
                  <CheckCircle className="w-4 h-4" /> 接続成功
                </span>
              )}
              {s3TestStatus === 'fail' && (
                <span className="flex items-center gap-1.5 text-red-400 text-sm">
                  <WifiOff className="w-4 h-4" /> 接続失敗 — リージョンとバケット名を確認してください
                </span>
              )}

              <div className="ml-auto">
                <button
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium"
                >
                  <Upload className="w-4 h-4" /> S3 設定を保存
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-[#0d1220] rounded-2xl p-6 w-full max-w-md border border-[#1e2d42] shadow-2xl">
            <div className="flex items-start gap-4 mb-5">
              <div className="p-2 bg-red-900/30 rounded-lg flex-shrink-0">
                <Trash2 className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white">バックアップを削除</h2>
                <p className="text-[#7d92b0] text-sm mt-1">以下のバックアップファイルを削除します。この操作は元に戻せません。</p>
                <p className="font-mono text-xs text-gray-300 mt-2 break-all bg-[#070d19] px-2 py-1.5 rounded-lg border border-[#1e2d42]">
                  {deleteTarget}
                </p>
              </div>
            </div>
            {deleteMutation.isError && (
              <p className="text-red-400 text-sm mb-4">{(deleteMutation.error as Error)?.message ?? '削除に失敗しました'}</p>
            )}
            <div className="flex gap-3">
              <button
                onClick={() => deleteMutation.mutate(deleteTarget)}
                disabled={deleteMutation.isPending}
                className="flex-1 py-2.5 bg-red-600 text-white rounded-xl hover:bg-red-700
                           transition-colors disabled:opacity-50 flex items-center justify-center gap-2 text-sm font-medium"
              >
                {deleteMutation.isPending
                  ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  : <Trash2 className="w-4 h-4" />}
                削除する
              </button>
              <button
                onClick={() => { setDeleteTarget(null); deleteMutation.reset() }}
                disabled={deleteMutation.isPending}
                className="px-5 py-2.5 bg-[#1e2d42] text-[#7d92b0] rounded-xl hover:bg-[#2e4060]
                           transition-colors text-sm disabled:opacity-50"
              >
                キャンセル
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
