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
  CheckCircle,
  XCircle,
  Clock,
  Server,
  FileArchive,
} from 'lucide-react'

// ─── 型定義 ───────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  hostname: string
}

interface AgentsResponse {
  agents?: Agent[]
  data?: Agent[]
}

interface ForensicsJob {
  id: string
  agent_id: string
  type: 'disk_image' | 'memory_dump' | 'file_collection' | 'triage'
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  path?: string
  size?: number
  created_at: string
  completed_at?: string
  download_url?: string
  error?: string
}

interface JobsResponse {
  jobs: ForensicsJob[]
}

interface CreateJobBody {
  agent_id: string
  type: ForensicsJob['type']
  path?: string
}

// ─── 定数 ─────────────────────────────────────────────────────────────────────

const TYPE_LABELS: Record<ForensicsJob['type'], string> = {
  disk_image: 'ディスクイメージ',
  memory_dump: 'メモリダンプ',
  file_collection: 'ファイル収集',
  triage: 'トリアージ',
}

const TYPE_ICONS: Record<ForensicsJob['type'], React.ReactNode> = {
  disk_image: <HardDrive size={13} />,
  memory_dump: <Server size={13} />,
  file_collection: <FileArchive size={13} />,
  triage: <FileArchive size={13} />,
}

// ─── ユーティリティ ───────────────────────────────────────────────────────────

function formatBytes(bytes?: number): string {
  if (bytes == null) return '—'
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`
}

function formatDateTime(s?: string): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('ja-JP', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatDuration(created_at: string, completed_at?: string): string {
  if (!completed_at) return '—'
  const ms = new Date(completed_at).getTime() - new Date(created_at).getTime()
  if (ms < 0) return '—'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}秒`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}分${s % 60}秒`
  return `${Math.floor(m / 60)}時間${m % 60}分`
}

function totalSize(jobs: ForensicsJob[]): number {
  return jobs.reduce((acc, j) => acc + (j.size ?? 0), 0)
}

// ─── ステータスバッジ ─────────────────────────────────────────────────────────

function StatusBadge({ status, error }: { status: ForensicsJob['status']; error?: string }) {
  const map: Record<
    ForensicsJob['status'],
    { label: string; className: string; icon: React.ReactNode }
  > = {
    pending: {
      label: '待機中',
      className: 'bg-gray-600/30 text-gray-300 border-gray-600/40',
      icon: <Clock size={11} />,
    },
    running: {
      label: '実行中',
      className: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
      icon: <Loader2 size={11} className="animate-spin" />,
    },
    completed: {
      label: '完了',
      className: 'bg-green-500/20 text-green-300 border-green-500/30',
      icon: <CheckCircle size={11} />,
    },
    failed: {
      label: '失敗',
      className: 'bg-red-500/20 text-red-300 border-red-500/30',
      icon: <XCircle size={11} />,
    },
    cancelled: {
      label: 'キャンセル',
      className: 'bg-gray-600/30 text-gray-400 border-gray-600/40',
      icon: <XCircle size={11} />,
    },
  }

  const cfg = map[status] ?? map.cancelled

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border font-medium ${cfg.className}`}
      title={status === 'failed' && error ? error : undefined}
    >
      {cfg.icon}
      {cfg.label}
      {status === 'failed' && error && (
        <span className="ml-0.5 cursor-help underline decoration-dotted">?</span>
      )}
    </span>
  )
}

// ─── タイプバッジ ─────────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: ForensicsJob['type'] }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs bg-gray-700/60 text-gray-300 border border-gray-600/40 font-medium">
      {TYPE_ICONS[type]}
      {TYPE_LABELS[type] ?? type}
    </span>
  )
}

// ─── 統計カード ───────────────────────────────────────────────────────────────

function StatCard({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode
  label: string
  value: string | number
  accent: string
}) {
  return (
    <div className={`bg-gray-800 rounded-xl border ${accent} p-4 flex items-center gap-3`}>
      <div className="flex-shrink-0">{icon}</div>
      <div>
        <p className="text-gray-400 text-xs">{label}</p>
        <p className="text-white text-xl font-bold">{value}</p>
      </div>
    </div>
  )
}

// ─── メインページ ─────────────────────────────────────────────────────────────

export default function ForensicsPage() {
  const queryClient = useQueryClient()

  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState<{
    agent_id: string
    type: ForensicsJob['type']
    path: string
    priority: 'normal' | 'high'
  }>({
    agent_id: '',
    type: 'disk_image',
    path: '',
    priority: 'normal',
  })

  // ── エージェント一覧 ──────────────────────────────────────────────────────

  const { data: agentsData } = useQuery<AgentsResponse>({
    queryKey: ['agents-list'],
    queryFn: () => apiFetch<AgentsResponse>('/api/v1/agents?limit=200'),
    staleTime: 60_000,
  })
  const agents = agentsData?.data ?? agentsData?.agents ?? []

  const agentHostname = (id: string) =>
    agents.find((a) => a.id === id)?.hostname ?? id.slice(0, 8)

  // ── ジョブ一覧 ────────────────────────────────────────────────────────────

  const {
    data: jobsData,
    isLoading,
    isError,
    error: jobsError,
  } = useQuery<JobsResponse>({
    queryKey: ['forensics-jobs'],
    queryFn: () => apiFetch<JobsResponse>('/api/v1/forensics/jobs'),
    refetchInterval: (query) => {
      const jobs = (query.state.data as JobsResponse | undefined)?.jobs ?? []
      const hasRunning = jobs.some(
        (j) => j.status === 'pending' || j.status === 'running'
      )
      return hasRunning ? 5_000 : 10_000
    },
  })
  const jobs = jobsData?.jobs ?? []

  // ── 統計 ──────────────────────────────────────────────────────────────────

  const runningCount = jobs.filter(
    (j) => j.status === 'pending' || j.status === 'running'
  ).length
  const completedCount = jobs.filter((j) => j.status === 'completed').length
  const artifactSize = totalSize(jobs.filter((j) => j.status === 'completed'))

  // ── ジョブ作成 ────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (body: CreateJobBody) =>
      apiFetch<ForensicsJob>('/api/v1/forensics/jobs', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['forensics-jobs'] })
      setShowModal(false)
      setForm({ agent_id: '', type: 'disk_image', path: '', priority: 'normal' })
    },
  })

  // ── ジョブ削除 ────────────────────────────────────────────────────────────

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/api/v1/forensics/jobs/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['forensics-jobs'] })
    },
  })

  // ── ダウンロード ──────────────────────────────────────────────────────────

  const handleDownload = (job: ForensicsJob) => {
    window.open(`/api/v1/forensics/jobs/${job.id}/download`, '_blank')
  }

  // ── フォーム送信 ──────────────────────────────────────────────────────────

  const handleSubmit = () => {
    if (!form.agent_id) return
    const body: CreateJobBody = {
      agent_id: form.agent_id,
      type: form.type,
    }
    if (form.type === 'file_collection' && form.path.trim()) {
      body.path = form.path.trim()
    }
    createMutation.mutate(body)
  }

  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        {/* ── ヘッダー ── */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-900/40 flex items-center justify-center flex-shrink-0">
              <HardDrive className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">フォレンジクス</h1>
              <p className="text-gray-400 text-sm mt-0.5">
                エンドポイントからのデジタルフォレンジクスデータ収集と管理
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 rounded-lg text-sm font-medium transition-colors"
          >
            <Plus size={15} />
            新しいジョブ
          </button>
        </div>

        {/* ── 統計 ── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            icon={<div className="w-9 h-9 rounded-lg bg-blue-900/40 flex items-center justify-center"><HardDrive className="w-4 h-4 text-blue-400" /></div>}
            label="総ジョブ数"
            value={jobs.length}
            accent="border-gray-700"
          />
          <StatCard
            icon={<div className="w-9 h-9 rounded-lg bg-yellow-900/40 flex items-center justify-center"><Loader2 className={`w-4 h-4 text-yellow-400 ${runningCount > 0 ? 'animate-spin' : ''}`} /></div>}
            label="実行中"
            value={runningCount}
            accent={runningCount > 0 ? 'border-yellow-700/40' : 'border-gray-700'}
          />
          <StatCard
            icon={<div className="w-9 h-9 rounded-lg bg-green-900/40 flex items-center justify-center"><CheckCircle className="w-4 h-4 text-green-400" /></div>}
            label="完了"
            value={completedCount}
            accent="border-gray-700"
          />
          <StatCard
            icon={<div className="w-9 h-9 rounded-lg bg-purple-900/40 flex items-center justify-center"><FileArchive className="w-4 h-4 text-purple-400" /></div>}
            label="総アーティファクトサイズ"
            value={formatBytes(artifactSize)}
            accent="border-gray-700"
          />
        </div>

        {/* ── ジョブテーブル ── */}
        <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-800 flex items-center gap-2">
            <Clock className="w-4 h-4 text-gray-400" />
            <span className="text-white text-sm font-semibold">ジョブ一覧</span>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-16 gap-2 text-gray-500">
              <Loader2 className="animate-spin w-5 h-5" />
              <span className="text-sm">読み込み中...</span>
            </div>
          ) : isError ? (
            (jobsError as (Error & { status?: number }) | null)?.status === 402 ? (
              <div className="py-12 text-center text-amber-400 text-sm">
                <HardDrive className="w-10 h-10 mx-auto mb-3 opacity-40" />
                デジタルフォレンジクスは Enterprise プランの機能です。<br />
                ご利用にはプランのアップグレードが必要です。
              </div>
            ) : (
              <div className="py-12 text-center text-red-400 text-sm">
                ジョブの取得に失敗しました
              </div>
            )
          ) : jobs.length === 0 ? (
            <div className="py-16 text-center text-gray-500 text-sm">
              <HardDrive className="w-10 h-10 mx-auto mb-3 opacity-30" />
              ジョブがありません。「新しいジョブ」から作成してください。
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 text-xs">
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">エージェント</th>
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">タイプ</th>
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">ステータス</th>
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">パス</th>
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">サイズ</th>
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">作成日時</th>
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">所要時間</th>
                    <th className="px-4 py-3 text-left font-medium whitespace-nowrap">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((job) => (
                    <tr
                      key={job.id}
                      className="border-b border-gray-800 last:border-0 hover:bg-gray-800/40 transition-colors"
                    >
                      {/* エージェント */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 text-gray-200">
                          <Server size={13} className="text-gray-500 flex-shrink-0" />
                          <span className="font-mono text-xs">{agentHostname(job.agent_id)}</span>
                        </div>
                      </td>

                      {/* タイプ */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <TypeBadge type={job.type} />
                      </td>

                      {/* ステータス */}
                      <td className="px-4 py-3 whitespace-nowrap">
                        <StatusBadge status={job.status} error={job.error} />
                      </td>

                      {/* パス */}
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs max-w-[180px] truncate" title={job.path}>
                        {job.path ?? '—'}
                      </td>

                      {/* サイズ */}
                      <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                        {formatBytes(job.size)}
                      </td>

                      {/* 作成日時 */}
                      <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                        {formatDateTime(job.created_at)}
                      </td>

                      {/* 所要時間 */}
                      <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                        {job.status === 'running' ? (
                          <span className="inline-flex items-center gap-1 text-blue-400">
                            <Loader2 size={11} className="animate-spin" />
                            実行中
                          </span>
                        ) : (
                          formatDuration(job.created_at, job.completed_at)
                        )}
                      </td>

                      {/* 操作 */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {job.status === 'completed' && (
                            <button
                              onClick={() => handleDownload(job)}
                              title="アーティファクトをダウンロード"
                              className="inline-flex items-center gap-1 px-2 py-1 bg-green-700/30 hover:bg-green-700/50 text-green-300 rounded text-xs transition-colors"
                            >
                              <Download size={12} />
                              DL
                            </button>
                          )}
                          <button
                            onClick={() => {
                              if (confirm('このジョブを削除しますか？')) {
                                deleteMutation.mutate(job.id)
                              }
                            }}
                            disabled={deleteMutation.isPending}
                            title="削除"
                            className="inline-flex items-center justify-center w-7 h-7 bg-gray-800 hover:bg-red-900/40 text-gray-500 hover:text-red-400 rounded transition-colors disabled:opacity-40"
                          >
                            <Trash2 size={13} />
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
      </div>

      {/* ── 新規ジョブモーダル ── */}
      {showModal && (
        <div
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
          onClick={(e) => e.target === e.currentTarget && setShowModal(false)}
        >
          <div className="bg-gray-900 rounded-xl border border-gray-700 p-6 w-full max-w-md shadow-2xl">
            <div className="flex items-center gap-2 mb-5">
              <HardDrive className="w-5 h-5 text-blue-400" />
              <h2 className="text-lg font-semibold text-white">新しいジョブ</h2>
            </div>

            {createMutation.isError && (
              <div className="mb-4 px-3 py-2 bg-red-900/30 border border-red-700/40 rounded-lg text-red-300 text-sm">
                {(createMutation.error as Error)?.message ?? 'エラーが発生しました'}
              </div>
            )}

            <div className="space-y-4">
              {/* エージェント */}
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">
                  エージェント <span className="text-red-400">*</span>
                </label>
                <select
                  value={form.agent_id}
                  onChange={(e) => setForm((f) => ({ ...f, agent_id: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-blue-500"
                >
                  <option value="">選択してください</option>
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.hostname}
                    </option>
                  ))}
                </select>
              </div>

              {/* ジョブタイプ */}
              <div>
                <label className="block text-sm text-gray-400 mb-1.5">ジョブタイプ</label>
                <select
                  value={form.type}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, type: e.target.value as ForensicsJob['type'] }))
                  }
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-blue-500"
                >
                  <option value="disk_image">ディスクイメージ</option>
                  <option value="memory_dump">メモリダンプ</option>
                  <option value="file_collection">ファイル収集</option>
                  <option value="triage">トリアージ</option>
                </select>
              </div>

              {/* パス (file_collection のみ) */}
              {form.type === 'file_collection' && (
                <div>
                  <label className="block text-sm text-gray-400 mb-1.5">パス</label>
                  <input
                    type="text"
                    value={form.path}
                    onChange={(e) => setForm((f) => ({ ...f, path: e.target.value }))}
                    placeholder="/var/log または C:\Windows\Logs"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm placeholder-gray-600 focus:outline-none focus:border-blue-500"
                  />
                </div>
              )}

              {/* 優先度 */}
              <div>
                <label className="block text-sm text-gray-400 mb-2">優先度</label>
                <div className="flex gap-4">
                  {(['normal', 'high'] as const).map((p) => (
                    <label key={p} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="priority"
                        value={p}
                        checked={form.priority === p}
                        onChange={() => setForm((f) => ({ ...f, priority: p }))}
                        className="accent-blue-500"
                      />
                      <span className="text-sm text-gray-300">
                        {p === 'normal' ? '通常' : '高'}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowModal(false)
                  createMutation.reset()
                }}
                className="flex-1 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleSubmit}
                disabled={!form.agent_id || createMutation.isPending}
                className="flex-1 inline-flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-sm font-medium transition-colors"
              >
                {createMutation.isPending ? (
                  <>
                    <Loader2 size={14} className="animate-spin" />
                    送信中...
                  </>
                ) : (
                  <>
                    <Plus size={14} />
                    作成
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
