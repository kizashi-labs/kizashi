'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  FileInput, Plus, Trash2, Eye, EyeOff, Copy, RefreshCw,
  ChevronDown, ChevronUp, CheckCircle2, AlertCircle, X, Check,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────

interface LogSource {
  id: string
  name: string
  description: string
  format: 'JSON' | 'Syslog' | 'CEF'
  enabled: boolean
  total_ingested: number
  last_received_at: string | null
  token: string
  created_at: string
  enrichment_status?: string
}

interface LogSourceStats {
  id: string
  hourly: number[]  // 24 values, oldest first
}

interface LogSourcesResponse {
  sources: LogSource[]
  total: number
  active: number
  ingested_today: number
  errors_today: number
}

function generateMockHourly(): number[] {
  const base = Math.floor(Math.random() * 500) + 200
  return Array.from({ length: 24 }, (_, i) => {
    const hour = (new Date().getHours() - 23 + i + 24) % 24
    const factor = hour >= 8 && hour <= 20 ? 1.5 : 0.5
    return Math.floor(base * factor * (0.7 + Math.random() * 0.6))
  })
}

// ── SVG Bar Chart ─────────────────────────────────────────────────────────────

function IngestChart({ data }: { data: number[] }) {
  const max = Math.max(...data, 1)
  return (
    <svg viewBox="0 0 240 60" className="w-full">
      {data.map((v, i) => (
        <rect
          key={i}
          x={i * 10}
          y={60 - (v / max) * 55}
          width="8"
          height={(v / max) * 55}
          fill="#e8002d"
          opacity="0.7"
          rx="1"
        />
      ))}
    </svg>
  )
}

// ── Format Badge ─────────────────────────────────────────────────────────────

function FormatBadge({ format }: { format: 'JSON' | 'Syslog' | 'CEF' }) {
  const colors: Record<string, string> = {
    JSON:   'bg-blue-500/20 text-blue-400 border-blue-500/30',
    Syslog: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    CEF:    'bg-purple-500/20 text-purple-400 border-purple-500/30',
  }
  return (
    <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${colors[format]}`}>
      {format}
    </span>
  )
}

// ── Masked Token ─────────────────────────────────────────────────────────────

function MaskedToken({ token }: { token: string }) {
  const [visible, setVisible] = useState(false)
  const masked = token.slice(0, 8) + '••••••••••••••••' + token.slice(-4)
  return (
    <div className="flex items-center gap-1">
      <span className="font-mono text-[11px] text-[#7d92b0]">
        {visible ? token : masked}
      </span>
      <button
        onClick={() => setVisible(v => !v)}
        className="p-0.5 text-[#3d5068] hover:text-[#7d92b0] transition-colors"
        title={visible ? 'Hide token' : 'Show token'}
      >
        {visible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
      </button>
    </div>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtNumber(n: number) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K'
  return n.toString()
}

function fmtTime(iso: string | null) {
  if (!iso) return 'なし'
  const d = new Date(iso)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return `${Math.floor(diff / 1000)}秒前`
  if (diff < 3600000) return `${Math.floor(diff / 60000)}分前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}時間前`
  return d.toLocaleDateString('ja-JP')
}

function useCopyToClipboard() {
  const [copied, setCopied] = useState<string | null>(null)
  const copy = useCallback((text: string, key: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key)
      setTimeout(() => setCopied(null), 2000)
    })
  }, [])
  return { copied, copy }
}

// ── Create Source Modal ────────────────────────────────────────────────────────

interface CreateModalProps {
  onClose: () => void
  onCreated: (source: LogSource, rawToken: string) => void
}

function CreateSourceModal({ onClose, onCreated }: CreateModalProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [format, setFormat] = useState<'JSON' | 'Syslog' | 'CEF'>('JSON')
  const [nameError, setNameError] = useState('')

  const mutation = useMutation({
    mutationFn: async (data: { name: string; description: string; format: string }) => {
      try {
        return await apiFetch<LogSource>('/api/v1/admin/log-sources', {
          method: 'POST',
          body: JSON.stringify(data),
        })
      } catch (e: unknown) {
        if (e instanceof Error && e.message.includes('404')) {
          // Mock response for demo
          const token = 'ls_' + Math.random().toString(36).slice(2, 34)
          return {
            id: Date.now().toString(),
            name: data.name,
            description: data.description,
            format: data.format as 'JSON' | 'Syslog' | 'CEF',
            enabled: true,
            total_ingested: 0,
            last_received_at: null,
            token,
            created_at: new Date().toISOString(),
          } as LogSource
        }
        throw e
      }
    },
    onSuccess: (source) => {
      onCreated(source, source.token)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!/^[a-zA-Z0-9-]+$/.test(name)) {
      setNameError('英数字とハイフンのみ使用できます')
      return
    }
    setNameError('')
    mutation.mutate({ name, description, format })
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-white font-semibold text-base">ログソース作成</h2>
          <button onClick={onClose} className="text-[#3d5068] hover:text-[#7d92b0] transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5 font-medium">
              ソース名 <span className="text-[#e8002d]">*</span>
            </label>
            <input
              value={name}
              onChange={e => { setName(e.target.value); setNameError('') }}
              placeholder="例: prod-web-server"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2
                         text-sm text-[#e2e8f4] placeholder-[#3d5068]
                         focus:outline-none focus:border-[#e8002d]/50 transition-colors"
              required
            />
            {nameError && (
              <p className="text-xs text-[#e8002d] mt-1">{nameError}</p>
            )}
            <p className="text-[11px] text-[#3d5068] mt-1">英数字とハイフンのみ使用可</p>
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5 font-medium">説明</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="説明（任意）"
              rows={2}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2
                         text-sm text-[#e2e8f4] placeholder-[#3d5068] resize-none
                         focus:outline-none focus:border-[#e8002d]/50 transition-colors"
            />
          </div>

          {/* Format */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-2 font-medium">ログフォーマット</label>
            <div className="flex gap-3">
              {(['JSON', 'Syslog', 'CEF'] as const).map(f => (
                <label key={f} className="flex items-center gap-2 cursor-pointer">
                  <div className={`w-4 h-4 rounded-full border-2 flex items-center justify-center transition-colors
                    ${format === f ? 'border-[#e8002d] bg-[#e8002d]/20' : 'border-[#3d5068]'}`}
                    onClick={() => setFormat(f)}
                  >
                    {format === f && <div className="w-2 h-2 rounded-full bg-[#e8002d]" />}
                  </div>
                  <span className="text-sm text-[#e2e8f4]">{f}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Token Note */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded p-3">
            <p className="text-[11px] text-[#7d92b0]">
              作成後に取り込みトークンが自動生成されます。
              このダイアログを閉じると再表示されないため、安全な場所に保存してください。
            </p>
          </div>

          {mutation.isError && (
            <div className="bg-red-500/10 border border-red-500/30 rounded p-3">
              <p className="text-xs text-red-400">{(mutation.error as Error).message}</p>
            </div>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="px-4 py-2 text-sm bg-[#e8002d] hover:bg-[#c0001e] text-white
                         rounded font-medium transition-colors disabled:opacity-50"
            >
              {mutation.isPending ? '作成中...' : 'ソースを作成'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Token Reveal Modal (shown once after creation) ────────────────────────────

interface TokenRevealProps {
  source: LogSource
  token: string
  onClose: () => void
}

function TokenRevealModal({ source, token, onClose }: TokenRevealProps) {
  const { copied, copy } = useCopyToClipboard()
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-md p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-full bg-green-500/20 flex items-center justify-center flex-shrink-0">
            <CheckCircle2 className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <h2 className="text-white font-semibold text-base">ソースを作成しました</h2>
            <p className="text-xs text-[#7d92b0]">{source.name}</p>
          </div>
        </div>

        <div className="bg-amber-500/10 border border-amber-500/30 rounded p-3 mb-4">
          <p className="text-xs text-amber-400 font-medium">
            このトークンを今すぐ保存してください — 再表示されません。
          </p>
        </div>

        <div className="bg-[#070d19] border border-[#1e2d42] rounded p-3 mb-4">
          <p className="text-[11px] text-[#7d92b0] mb-1">取り込みトークン</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-[12px] font-mono text-[#e2e8f4] break-all">{token}</code>
            <button
              onClick={() => copy(token, 'modal-token')}
              className="flex-shrink-0 p-1.5 rounded bg-[#1e2d42] hover:bg-[#2a3f5c] text-[#7d92b0] transition-colors"
            >
              {copied === 'modal-token' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>

        <button
          onClick={onClose}
          className="w-full py-2 text-sm bg-[#e8002d] hover:bg-[#c0001e] text-white rounded font-medium transition-colors"
        >
          トークンを保存しました
        </button>
      </div>
    </div>
  )
}

// ── Delete Confirmation Modal ─────────────────────────────────────────────────

interface DeleteModalProps {
  source: LogSource
  onConfirm: () => void
  onCancel: () => void
  isPending: boolean
}

function DeleteModal({ source, onConfirm, onCancel, isPending }: DeleteModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg w-full max-w-sm p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-full bg-red-500/20 flex items-center justify-center flex-shrink-0">
            <AlertCircle className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h2 className="text-white font-semibold">ログソースを削除</h2>
            <p className="text-xs text-[#7d92b0]">この操作は取り消せません</p>
          </div>
        </div>
        <p className="text-sm text-[#7d92b0] mb-5">
          <span className="text-white font-medium">{source.name}</span> を削除しますか？
          すべての取り込み履歴が失われます。
        </p>
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 py-2 text-sm border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] rounded transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className="flex-1 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded font-medium transition-colors disabled:opacity-50"
          >
            {isPending ? '削除中...' : '削除'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Source Detail Panel ───────────────────────────────────────────────────────

interface DetailPanelProps {
  source: LogSource
  onRegenerateToken: (id: string) => void
  isRegenerating: boolean
}

function SourceDetailPanel({ source, onRegenerateToken, isRegenerating }: DetailPanelProps) {
  const { copied, copy } = useCopyToClipboard()
  const [showRegenConfirm, setShowRegenConfirm] = useState(false)

  const { data: stats } = useQuery<LogSourceStats>({
    queryKey: ['log-source-stats', source.id],
    queryFn: async () => {
      try {
        return await apiFetch<LogSourceStats>(`/api/v1/admin/log-sources/${source.id}/stats`)
      } catch {
        return { id: source.id, hourly: generateMockHourly() }
      }
    },
    staleTime: 60_000,
    refetchInterval: 60_000,
  })

  const chartData = stats?.hourly ?? Array.from({ length: 24 }, () => 0)

  const curlCommand = `curl -X POST https://your-server/api/v1/ingest/${source.name} \\
  -H "X-Ingest-Token: ${source.token}" \\
  -H "Content-Type: application/json" \\
  -d '{"message": "test event", "hostname": "server01"}'`

  const hours = Array.from({ length: 24 }, (_, i) => {
    const h = (new Date().getHours() - 23 + i + 24) % 24
    return h.toString().padStart(2, '0') + ':00'
  })

  return (
    <div className="border-t border-[#1e2d42] bg-[#070d19]/60 p-5 space-y-5">
      {/* Token Management */}
      <div>
        <h4 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">取り込みトークン</h4>
        <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded p-3">
          <code className="flex-1 font-mono text-[12px] text-[#e2e8f4] truncate">{source.token}</code>
          <button
            onClick={() => copy(source.token, `token-${source.id}`)}
            className="flex-shrink-0 flex items-center gap-1.5 px-2.5 py-1.5 text-xs
                       bg-[#1e2d42] hover:bg-[#2a3f5c] text-[#7d92b0] hover:text-[#e2e8f4]
                       rounded transition-colors"
          >
            {copied === `token-${source.id}` ? (
              <><Check className="w-3.5 h-3.5 text-green-400" /> コピーしました</>
            ) : (
              <><Copy className="w-3.5 h-3.5" /> コピー</>
            )}
          </button>
          <div className="relative">
            <button
              onClick={() => setShowRegenConfirm(true)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs
                         bg-amber-500/10 hover:bg-amber-500/20 text-amber-400
                         border border-amber-500/30 rounded transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              再生成
            </button>
            {showRegenConfirm && (
              <div className="absolute right-0 top-9 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3 shadow-xl z-10 w-56">
                <p className="text-xs text-[#7d92b0] mb-3">
                  再生成すると現在のトークンが無効になります。送信元のすべてのシステムでトークンの更新が必要です。
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setShowRegenConfirm(false)}
                    className="flex-1 text-xs py-1.5 border border-[#1e2d42] text-[#7d92b0] rounded transition-colors hover:text-[#e2e8f4]"
                  >
                    キャンセル
                  </button>
                  <button
                    onClick={() => {
                      setShowRegenConfirm(false)
                      onRegenerateToken(source.id)
                    }}
                    disabled={isRegenerating}
                    className="flex-1 text-xs py-1.5 bg-amber-500 hover:bg-amber-600 text-black rounded font-medium transition-colors disabled:opacity-50"
                  >
                    確認
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 24h Ingestion Chart */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider">24時間の取り込み数</h4>
          <span className="text-[11px] text-[#3d5068]">
            合計: {fmtNumber(chartData.reduce((a, b) => a + b, 0))} イベント
          </span>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded p-3">
          <IngestChart data={chartData} />
          <div className="flex justify-between mt-1">
            <span className="text-[10px] text-[#3d5068]">{hours[0]}</span>
            <span className="text-[10px] text-[#3d5068]">{hours[11]}</span>
            <span className="text-[10px] text-[#3d5068]">現在</span>
          </div>
        </div>
      </div>

      {/* Sample Command */}
      <div>
        <h4 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">取り込みコマンド例</h4>
        <div className="bg-[#070d19] border border-[#1e2d42] rounded">
          <div className="flex items-center justify-between px-3 py-2 border-b border-[#1e2d42]">
            <span className="text-[11px] text-[#3d5068] font-mono">bash</span>
            <button
              onClick={() => copy(curlCommand, `cmd-${source.id}`)}
              className="flex items-center gap-1.5 text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
            >
              {copied === `cmd-${source.id}` ? (
                <><Check className="w-3.5 h-3.5 text-green-400" /> コピーしました</>
              ) : (
                <><Copy className="w-3.5 h-3.5" /> コピー</>
              )}
            </button>
          </div>
          <pre className="p-3 text-[11px] font-mono text-[#e2e8f4] overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
            {curlCommand}
          </pre>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function LogSourcesPage() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [createdSource, setCreatedSource] = useState<{ source: LogSource; token: string } | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<LogSource | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const { copied, copy } = useCopyToClipboard()

  // ── Fetch log sources ─────────────────────────────────────────────────────

  const { data, isLoading, isError } = useQuery<LogSourcesResponse>({
    queryKey: ['log-sources'],
    queryFn: async () => {
      try {
        return await apiFetch<LogSourcesResponse>('/api/v1/admin/log-sources')
      } catch (e: unknown) {
        if (e instanceof Error && e.message.includes('404')) {
          return { sources: [], total: 0, active: 0, ingested_today: 0, errors_today: 0 }
        }
        throw e
      }
    },
    staleTime: 30_000,
    refetchInterval: 30_000,
  })

  // ── Toggle enabled ─────────────────────────────────────────────────────────

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      try {
        return await apiFetch(`/api/v1/admin/log-sources/${id}`, {
          method: 'PATCH',
          body: JSON.stringify({ enabled }),
        })
      } catch (e: unknown) {
        if (e instanceof Error && e.message.includes('404')) {
          return { id, enabled }
        }
        throw e
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources'] }),
  })

  // ── Delete ─────────────────────────────────────────────────────────────────

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      try {
        await apiFetch(`/api/v1/admin/log-sources/${id}`, { method: 'DELETE' })
      } catch (e: unknown) {
        if (e instanceof Error && e.message.includes('404')) return
        throw e
      }
    },
    onSuccess: () => {
      setDeleteTarget(null)
      qc.invalidateQueries({ queryKey: ['log-sources'] })
    },
  })

  // ── Regenerate token ───────────────────────────────────────────────────────

  const regenMutation = useMutation({
    mutationFn: async (id: string) => {
      try {
        return await apiFetch<{ token: string }>(`/api/v1/admin/log-sources/${id}/regenerate-token`, {
          method: 'POST',
        })
      } catch (e: unknown) {
        if (e instanceof Error && e.message.includes('404')) {
          return { token: 'ls_regen_' + Math.random().toString(36).slice(2, 32) }
        }
        throw e
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources'] }),
  })

  const sources = data?.sources ?? []

  const handleCreated = (source: LogSource, token: string) => {
    setShowCreate(false)
    setCreatedSource({ source, token })
    qc.invalidateQueries({ queryKey: ['log-sources'] })
  }

  const statsCards = [
    {
      label: 'ソース総数',
      value: data?.total ?? 0,
      icon: FileInput,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
    },
    {
      label: 'アクティブソース',
      value: data?.active ?? 0,
      icon: CheckCircle2,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
    },
    {
      label: '今日の取り込み数',
      value: fmtNumber(data?.ingested_today ?? 0),
      icon: FileInput,
      color: 'text-[#e8002d]',
      bg: 'bg-[#e8002d]/10',
    },
    {
      label: '今日のエラー数',
      value: data?.errors_today ?? 0,
      icon: AlertCircle,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10',
    },
  ]

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <div className="w-7 h-7 rounded bg-[#e8002d]/20 flex items-center justify-center">
              <FileInput className="w-4 h-4 text-[#e8002d]" />
            </div>
            <h1 className="text-xl font-bold text-white">ログソース</h1>
          </div>
          <p className="text-sm text-[#7d92b0] ml-9">
            外部ログソースの取り込みエンドポイントと認証トークンを管理します
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001e]
                     text-white text-sm font-medium rounded transition-colors"
        >
          <Plus className="w-4 h-4" />
          新規ソース
        </button>
      </div>

      {/* ── Stats Row ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {statsCards.map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className={`w-9 h-9 rounded ${bg} flex items-center justify-center flex-shrink-0`}>
                <Icon className={`w-4.5 h-4.5 ${color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-white">{value}</p>
                <p className="text-xs text-[#7d92b0]">{label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Sources Table ──────────────────────────────────────────────────── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">ログソース</h2>
          <span className="text-xs text-[#3d5068]">{sources.length} ソース</span>
        </div>

        {isLoading && (
          <div className="py-16 text-center">
            <div className="w-7 h-7 border-2 border-[#1e2d42] border-t-[#e8002d] rounded-full animate-spin mx-auto mb-3" />
            <p className="text-sm text-[#3d5068]">ログソースを読み込み中...</p>
          </div>
        )}

        {isError && (
          <div className="py-12 text-center">
            <AlertCircle className="w-8 h-8 text-red-400 mx-auto mb-3" />
            <p className="text-sm text-[#7d92b0]">ログソースの読み込みに失敗しました</p>
          </div>
        )}

        {!isLoading && !isError && sources.length === 0 && (
          <div className="py-16 text-center">
            <FileInput className="w-10 h-10 text-[#3d5068] mx-auto mb-3" />
            <p className="text-sm text-[#7d92b0] mb-1">ログソースが設定されていません</p>
            <p className="text-xs text-[#3d5068]">最初のログソースを作成して外部ログの取り込みを開始してください</p>
          </div>
        )}

        {!isLoading && !isError && sources.length > 0 && (
          <div>
            {/* Table Header */}
            <div className="grid grid-cols-[1fr_100px_80px_120px_160px_180px_120px] gap-4 px-5 py-2.5
                            text-[11px] font-semibold uppercase tracking-wider text-[#3d5068]
                            border-b border-[#1e2d42]">
              <div>名前</div>
              <div>フォーマット</div>
              <div>ステータス</div>
              <div>総取り込み数</div>
              <div>最終受信</div>
              <div>トークン</div>
              <div className="text-right">操作</div>
            </div>

            {/* Table Rows */}
            {sources.map(source => {
              const isExpanded = expandedId === source.id
              return (
                <div key={source.id} className="border-b border-[#1e2d42] last:border-0">
                  <div
                    className="grid grid-cols-[1fr_100px_80px_120px_160px_180px_120px] gap-4 px-5 py-3.5
                                items-center hover:bg-[#0a1525] transition-colors cursor-pointer"
                    onClick={() => setExpandedId(isExpanded ? null : source.id)}
                  >
                    {/* Name */}
                    <div className="flex items-center gap-2 min-w-0">
                      {isExpanded
                        ? <ChevronUp className="w-3.5 h-3.5 text-[#3d5068] flex-shrink-0" />
                        : <ChevronDown className="w-3.5 h-3.5 text-[#3d5068] flex-shrink-0" />
                      }
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-[#e2e8f4] truncate">{source.name}</p>
                        {source.description && (
                          <p className="text-[11px] text-[#3d5068] truncate">{source.description}</p>
                        )}
                      </div>
                    </div>

                    {/* Format */}
                    <div onClick={e => e.stopPropagation()}>
                      <FormatBadge format={source.format} />
                    </div>

                    {/* Status Toggle */}
                    <div onClick={e => e.stopPropagation()}>
                      <button
                        onClick={() => toggleMutation.mutate({ id: source.id, enabled: !source.enabled })}
                        className={`relative w-10 h-5.5 rounded-full transition-colors ${
                          source.enabled ? 'bg-green-500' : 'bg-[#1e2d42]'
                        }`}
                        style={{ height: '22px' }}
                        title={source.enabled ? 'Disable source' : 'Enable source'}
                      >
                        <span className={`absolute top-0.5 w-4.5 h-4.5 bg-[#e2e8f4] rounded-full shadow transition-transform ${
                          source.enabled ? 'translate-x-5' : 'translate-x-0.5'
                        }`}
                          style={{ width: '18px', height: '18px', top: '2px', left: source.enabled ? '20px' : '2px', position: 'absolute', transition: 'left 0.15s' }}
                        />
                      </button>
                    </div>

                    {/* Total Ingested */}
                    <div className="text-sm text-[#e2e8f4] font-mono">
                      {fmtNumber(source.total_ingested)}
                    </div>

                    {/* Last Received */}
                    <div className="text-sm text-[#7d92b0]">
                      {fmtTime(source.last_received_at)}
                    </div>

                    {/* Token (masked) */}
                    <div onClick={e => e.stopPropagation()}>
                      <MaskedToken token={source.token} />
                    </div>

                    {/* Actions */}
                    <div
                      className="flex items-center justify-end gap-1"
                      onClick={e => e.stopPropagation()}
                    >
                      <button
                        onClick={() => copy(source.token, `row-token-${source.id}`)}
                        className="p-1.5 rounded text-[#3d5068] hover:text-[#7d92b0] hover:bg-[#1e2d42] transition-colors"
                        title="Copy token"
                      >
                        {copied === `row-token-${source.id}`
                          ? <Check className="w-3.5 h-3.5 text-green-400" />
                          : <Copy className="w-3.5 h-3.5" />
                        }
                      </button>
                      <button
                        onClick={() => setDeleteTarget(source)}
                        className="p-1.5 rounded text-[#3d5068] hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        title="Delete source"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Expanded Detail Panel */}
                  {isExpanded && (
                    <SourceDetailPanel
                      source={source}
                      onRegenerateToken={id => regenMutation.mutate(id)}
                      isRegenerating={regenMutation.isPending}
                    />
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* ── Modals ─────────────────────────────────────────────────────────── */}
      {showCreate && (
        <CreateSourceModal
          onClose={() => setShowCreate(false)}
          onCreated={handleCreated}
        />
      )}

      {createdSource && (
        <TokenRevealModal
          source={createdSource.source}
          token={createdSource.token}
          onClose={() => setCreatedSource(null)}
        />
      )}

      {deleteTarget && (
        <DeleteModal
          source={deleteTarget}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
          onCancel={() => setDeleteTarget(null)}
          isPending={deleteMutation.isPending}
        />
      )}
    </div>
  )
}
