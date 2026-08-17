'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  HardDrive,
  Download,
  Plus,
  Trash2,
  Loader2,
  Copy,
  Check,
  Filter,
  Search,
  RefreshCw,
  X,
  Database,
  FileArchive,
  AlertTriangle,
  Clock,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────────────────────

interface ForensicArtifact {
  id: string
  agent_id: string
  hostname: string
  artifact_type: string
  file_name: string
  file_size: number
  sha256: string
  status: 'pending' | 'collecting' | 'ready' | 'failed'
  collected_at?: string
  created_at: string
}

interface ArtifactsResponse {
  artifacts: ForensicArtifact[]
  total: number
}

// ── Mock data (used as fallback when API is unavailable) ───────────────────────

const MOCK_ARTIFACTS: ForensicArtifact[] = [
  {
    id: 'art-001',
    agent_id: 'agt-abc123',
    hostname: 'WIN-DC01',
    artifact_type: 'memory_dump',
    file_name: 'WIN-DC01_memdump_20260317.dmp',
    file_size: 8589934592,
    sha256: 'a3f2c1d4e5b6789012345678901234567890abcdef1234567890abcdef123456',
    status: 'ready',
    collected_at: '2026-03-17T04:22:00Z',
    created_at: '2026-03-17T04:00:00Z',
  },
  {
    id: 'art-002',
    agent_id: 'agt-def456',
    hostname: 'WORKSTATION-42',
    artifact_type: 'registry',
    file_name: 'WORKSTATION-42_registry_20260316.reg',
    file_size: 52428800,
    sha256: 'b4e3d2c1f0a9876543210987654321098765fedcba9876543210fedcba987654',
    status: 'ready',
    collected_at: '2026-03-16T18:15:00Z',
    created_at: '2026-03-16T18:00:00Z',
  },
  {
    id: 'art-003',
    agent_id: 'agt-ghi789',
    hostname: 'SERVER-PROD-01',
    artifact_type: 'logs',
    file_name: 'SERVER-PROD-01_eventlogs_20260317.zip',
    file_size: 134217728,
    sha256: 'c5d4e3f2a1b0987654321098765432109876543210abcdef0987654321abcdef',
    status: 'collecting',
    created_at: '2026-03-17T06:30:00Z',
  },
  {
    id: 'art-004',
    agent_id: 'agt-jkl012',
    hostname: 'LAPTOP-HR-07',
    artifact_type: 'file',
    file_name: 'suspicious_binary.exe',
    file_size: 2097152,
    sha256: 'd6e5f4a3b2c1098765432109876543210987654321bcdef09876543210bcdef01',
    status: 'failed',
    created_at: '2026-03-17T02:10:00Z',
  },
  {
    id: 'art-005',
    agent_id: 'agt-mno345',
    hostname: 'WIN-DEVBOX',
    artifact_type: 'disk_image',
    file_name: 'WIN-DEVBOX_disk_C_20260315.img',
    file_size: 53687091200,
    sha256: 'e7f6a5b4c3d2109876543210987654321098765432cdef109876543210cdef012',
    status: 'ready',
    collected_at: '2026-03-15T22:00:00Z',
    created_at: '2026-03-15T20:00:00Z',
  },
  {
    id: 'art-006',
    agent_id: 'agt-pqr678',
    hostname: 'SRV-WEB-02',
    artifact_type: 'memory_dump',
    file_name: 'SRV-WEB-02_memdump_20260317.dmp',
    file_size: 17179869184,
    sha256: '',
    status: 'pending',
    created_at: '2026-03-17T07:00:00Z',
  },
]

// ── Helpers ────────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function formatDate(iso?: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return iso
  }
}

const ARTIFACT_TYPE_LABELS: Record<string, string> = {
  memory_dump: 'メモリダンプ',
  disk_image:  'ディスクイメージ',
  file:        'ファイル',
  registry:    'レジストリ',
  logs:        'ログ',
}

const STATUS_CONFIG: Record<
  ForensicArtifact['status'],
  { label: string; color: string; bg: string; icon: React.ComponentType<{ className?: string }> }
> = {
  pending:    { label: '保留中',   color: '#9ca3af', bg: '#9ca3af22', icon: Clock },
  collecting: { label: '収集中',   color: '#3b82f6', bg: '#3b82f622', icon: Loader2 },
  ready:      { label: '完了',     color: '#00e676', bg: '#00e67622', icon: Check },
  failed:     { label: '失敗',     color: '#e8002d', bg: '#e8002d22', icon: AlertTriangle },
}

function StatusBadge({ status }: { status: ForensicArtifact['status'] }) {
  const cfg = STATUS_CONFIG[status]
  const Icon = cfg.icon
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[11px] font-semibold"
      style={{ color: cfg.color, background: cfg.bg }}
    >
      <Icon className={`w-3 h-3 ${status === 'collecting' ? 'animate-spin' : ''}`} />
      {cfg.label}
    </span>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // clipboard not available
    }
  }

  return (
    <button
      onClick={handleCopy}
      title="クリップボードにコピー"
      className="p-1 rounded-sm text-falcon-subtle hover:text-falcon-muted hover:bg-falcon-border/40 transition-colors"
    >
      {copied ? <Check className="w-3 h-3 text-[#00e676]" /> : <Copy className="w-3 h-3" />}
    </button>
  )
}

// ── Collect Modal ──────────────────────────────────────────────────────────────

interface CollectModalProps {
  onClose: () => void
  onSubmit: (data: { agent_id: string; artifact_type: string; target_path: string }) => void
  isSubmitting: boolean
}

function CollectModal({ onClose, onSubmit, isSubmitting }: CollectModalProps) {
  const [agentId, setAgentId] = useState('')
  const [artifactType, setArtifactType] = useState<string>('file')
  const [targetPath, setTargetPath] = useState('')

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!agentId.trim()) return
    onSubmit({ agent_id: agentId.trim(), artifact_type: artifactType, target_path: targetPath.trim() })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl shadow-2xl w-full max-w-md mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-falcon-border">
          <div className="flex items-center gap-2">
            <HardDrive className="w-5 h-5 text-falcon-red" />
            <h2 className="text-sm font-bold text-white">アーティファクト収集リクエスト</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-sm text-falcon-muted hover:text-white hover:bg-falcon-border transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-1.5">
              エージェントID <span className="text-falcon-red">*</span>
            </label>
            <input
              type="text"
              value={agentId}
              onChange={e => setAgentId(e.target.value)}
              placeholder="例: agt-abc123"
              required
              className="w-full px-3 py-2 rounded bg-[#070d19] border border-falcon-border
                         text-falcon-text text-sm placeholder-falcon-subtle
                         focus:outline-hidden focus:border-falcon-muted/60 transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-1.5">
              アーティファクトタイプ <span className="text-falcon-red">*</span>
            </label>
            <select
              value={artifactType}
              onChange={e => setArtifactType(e.target.value)}
              className="w-full px-3 py-2 rounded bg-[#070d19] border border-falcon-border
                         text-falcon-text text-sm
                         focus:outline-hidden focus:border-falcon-muted/60 transition-colors"
            >
              <option value="memory_dump">メモリダンプ</option>
              <option value="disk_image">ディスクイメージ</option>
              <option value="file">ファイル</option>
              <option value="registry">レジストリ</option>
              <option value="logs">ログ</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-1.5">
              ターゲットパス
              <span className="text-falcon-subtle font-normal ml-1">(ファイル収集時)</span>
            </label>
            <input
              type="text"
              value={targetPath}
              onChange={e => setTargetPath(e.target.value)}
              placeholder="例: C:\Users\user\AppData\malware.exe"
              className="w-full px-3 py-2 rounded bg-[#070d19] border border-falcon-border
                         text-falcon-text text-sm placeholder-falcon-subtle font-mono
                         focus:outline-hidden focus:border-falcon-muted/60 transition-colors"
            />
          </div>

          <div className="flex gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 text-sm text-falcon-muted bg-[#070d19] border border-falcon-border
                         rounded hover:bg-falcon-hover hover:text-falcon-text transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !agentId.trim()}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2 text-sm font-semibold
                         text-white bg-falcon-red rounded hover:bg-[#c0001f]
                         disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isSubmitting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Plus className="w-4 h-4" />
              )}
              収集リクエスト送信
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ForensicsArtifactsPage() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [filterType, setFilterType] = useState<string>('all')
  const [search, setSearch] = useState('')

  // Fetch artifacts — fall back to mock data on error
  const { data, isLoading, isError } = useQuery<ArtifactsResponse>({
    queryKey: ['forensics-artifacts'],
    queryFn: () => apiFetch('/api/v1/forensics/artifacts'),
    retry: 1,
    staleTime: 30_000,
  })

  const rawArtifacts: ForensicArtifact[] = isError
    ? m(MOCK_ARTIFACTS)
    : (data?.artifacts ?? m(MOCK_ARTIFACTS))

  // Collect mutation
  const collectMutation = useMutation({
    mutationFn: (payload: { agent_id: string; artifact_type: string; target_path: string }) =>
      apiFetch('/api/v1/forensics/collect', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['forensics-artifacts'] })
      setShowModal(false)
    },
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/forensics/artifacts/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['forensics-artifacts'] })
    },
  })

  // Filter
  const artifacts = rawArtifacts.filter(a => {
    if (filterStatus !== 'all' && a.status !== filterStatus) return false
    if (filterType !== 'all' && a.artifact_type !== filterType) return false
    if (search) {
      const q = search.toLowerCase()
      if (
        !a.hostname.toLowerCase().includes(q) &&
        !a.file_name.toLowerCase().includes(q) &&
        !a.sha256.toLowerCase().includes(q)
      ) return false
    }
    return true
  })

  // Stats
  const totalCount = rawArtifacts.length
  const analyzedCount = rawArtifacts.filter(a => a.status === 'ready').length
  const collectingCount = rawArtifacts.filter(a => a.status === 'collecting' || a.status === 'pending').length
  const totalBytes = rawArtifacts.filter(a => a.status === 'ready').reduce((s, a) => s + a.file_size, 0)

  const stats = [
    { label: '総アーティファクト', value: totalCount, color: '#7d92b0', icon: Database },
    { label: '解析済み',           value: analyzedCount, color: '#00e676', icon: Check },
    { label: '処理中',             value: collectingCount, color: '#3b82f6', icon: Loader2 },
    { label: '容量',               value: formatBytes(totalBytes), color: '#ff9800', icon: HardDrive },
  ]

  async function handleDownload(artifact: ForensicArtifact) {
    try {
      const blob = await apiFetch<Blob>(`/api/v1/forensics/artifacts/${artifact.id}/download`)
      const url = URL.createObjectURL(blob as Blob)
      const a = document.createElement('a')
      a.href = url
      a.download = artifact.file_name
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // silently ignore — API may be a stub
    }
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* ── Header ── */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <HardDrive className="w-6 h-6 text-falcon-red" />
          <div>
            <h1 className="text-xl font-bold text-white">フォレンジクスアーティファクト</h1>
            <p className="text-xs text-falcon-muted mt-0.5">収集・管理されたフォレンジクス証拠</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ['forensics-artifacts'] })}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-falcon-muted
                       bg-falcon-surface border border-falcon-border rounded hover:bg-falcon-hover hover:text-falcon-text transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            更新
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-semibold text-white
                       bg-falcon-red rounded hover:bg-[#c0001f] transition-colors"
          >
            <Plus className="w-4 h-4" />
            収集リクエスト
          </button>
        </div>
      </div>

      {/* ── Stats ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {stats.map(s => {
          const Icon = s.icon
          return (
            <div key={s.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Icon className="w-4 h-4" style={{ color: s.color }} />
                <span className="text-xs text-falcon-muted">{s.label}</span>
              </div>
              <span className="text-2xl font-bold" style={{ color: s.color }}>
                {s.value}
              </span>
            </div>
          )
        })}
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-falcon-subtle" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="ホスト名・ファイル名・SHA256"
            className="w-full pl-9 pr-3 py-2 text-sm rounded bg-falcon-surface border border-falcon-border
                       text-falcon-text placeholder-falcon-subtle
                       focus:outline-hidden focus:border-falcon-muted/60 transition-colors"
          />
        </div>

        {/* Status filter */}
        <div className="flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-falcon-subtle" />
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
            className="px-2 py-2 text-xs rounded bg-falcon-surface border border-falcon-border
                       text-falcon-text focus:outline-hidden focus:border-falcon-muted/60 transition-colors"
          >
            <option value="all">全ステータス</option>
            <option value="pending">保留中</option>
            <option value="collecting">収集中</option>
            <option value="ready">完了</option>
            <option value="failed">失敗</option>
          </select>
        </div>

        {/* Type filter */}
        <select
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          className="px-2 py-2 text-xs rounded bg-falcon-surface border border-falcon-border
                     text-falcon-text focus:outline-hidden focus:border-falcon-muted/60 transition-colors"
        >
          <option value="all">全タイプ</option>
          <option value="memory_dump">メモリダンプ</option>
          <option value="disk_image">ディスクイメージ</option>
          <option value="file">ファイル</option>
          <option value="registry">レジストリ</option>
          <option value="logs">ログ</option>
        </select>

        <span className="text-xs text-falcon-muted ml-auto">
          {artifacts.length} 件
        </span>
      </div>

      {/* ── Table ── */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 text-falcon-muted animate-spin" />
            <span className="ml-2 text-sm text-falcon-muted">読み込み中...</span>
          </div>
        ) : artifacts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20">
            <FileArchive className="w-12 h-12 text-falcon-subtle mb-3" />
            <p className="text-sm text-falcon-muted">アーティファクトが見つかりません</p>
            <p className="text-xs text-falcon-subtle mt-1">フィルターを変更するか、新しい収集をリクエストしてください</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-falcon-border bg-[#070d19]/60">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">ファイル名</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">タイプ</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">エージェント</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">サイズ</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">SHA256</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">収集日時</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">ステータス</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-falcon-muted uppercase tracking-wider">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border/60">
                {artifacts.map(artifact => (
                  <tr key={artifact.id} className="hover:bg-falcon-hover/40 transition-colors">
                    {/* ファイル名 */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <FileArchive className="w-4 h-4 text-falcon-subtle shrink-0" />
                        <span className="text-xs text-falcon-text font-mono truncate max-w-[200px]" title={artifact.file_name}>
                          {artifact.file_name}
                        </span>
                      </div>
                    </td>

                    {/* タイプ */}
                    <td className="px-4 py-3">
                      <span className="text-xs text-falcon-muted">
                        {ARTIFACT_TYPE_LABELS[artifact.artifact_type] ?? artifact.artifact_type}
                      </span>
                    </td>

                    {/* エージェント */}
                    <td className="px-4 py-3">
                      <a
                        href={`/endpoints/${artifact.agent_id}`}
                        className="text-xs text-falcon-text hover:text-falcon-red transition-colors font-medium"
                      >
                        {artifact.hostname}
                      </a>
                      <p className="text-[10px] text-falcon-subtle font-mono mt-0.5">{artifact.agent_id}</p>
                    </td>

                    {/* サイズ */}
                    <td className="px-4 py-3">
                      <span className="text-xs text-falcon-muted tabular-nums">
                        {formatBytes(artifact.file_size)}
                      </span>
                    </td>

                    {/* SHA256 */}
                    <td className="px-4 py-3">
                      {artifact.sha256 ? (
                        <div className="flex items-center gap-1">
                          <span
                            className="text-[10px] text-falcon-muted font-mono truncate max-w-[120px]"
                            title={artifact.sha256}
                          >
                            {artifact.sha256.slice(0, 16)}…
                          </span>
                          <CopyButton text={artifact.sha256} />
                        </div>
                      ) : (
                        <span className="text-xs text-falcon-subtle">—</span>
                      )}
                    </td>

                    {/* 収集日時 */}
                    <td className="px-4 py-3">
                      <span className="text-xs text-falcon-muted tabular-nums whitespace-nowrap">
                        {formatDate(artifact.collected_at ?? artifact.created_at)}
                      </span>
                    </td>

                    {/* ステータス */}
                    <td className="px-4 py-3">
                      <StatusBadge status={artifact.status} />
                    </td>

                    {/* 操作 */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        {artifact.status === 'ready' && (
                          <button
                            onClick={() => handleDownload(artifact)}
                            title="ダウンロード"
                            className="p-1.5 rounded-sm text-falcon-subtle hover:text-[#3b82f6] hover:bg-[#3b82f6]/10 transition-colors"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                        )}
                        <button
                          onClick={() => {
                            if (confirm(`「${artifact.file_name}」を削除しますか?`)) {
                              deleteMutation.mutate(artifact.id)
                            }
                          }}
                          disabled={deleteMutation.isPending}
                          title="削除"
                          className="p-1.5 rounded-sm text-falcon-subtle hover:text-falcon-red hover:bg-falcon-red/10 transition-colors disabled:opacity-40"
                        >
                          {deleteMutation.isPending ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Trash2 className="w-3.5 h-3.5" />
                          )}
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

      {/* Mock data notice */}
      {isError && (
        <p className="mt-3 text-xs text-falcon-subtle text-center">
          APIが利用できないため、モックデータを表示しています
        </p>
      )}

      {/* ── Collect Modal ── */}
      {showModal && (
        <CollectModal
          onClose={() => setShowModal(false)}
          onSubmit={payload => collectMutation.mutate(payload)}
          isSubmitting={collectMutation.isPending}
        />
      )}
    </div>
  )
}
