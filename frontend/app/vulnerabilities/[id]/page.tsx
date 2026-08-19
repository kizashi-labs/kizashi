'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Bug, ArrowLeft, Monitor, Package, ShieldCheck,
  AlertTriangle, AlertCircle, Info, Pencil, Trash2, Check, X
} from 'lucide-react'
import Link from 'next/link'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

interface Vulnerability {
  id: string
  agent_id?: string
  agent_hostname?: string
  cve_id: string
  title: string
  description?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss_score?: number
  affected_package?: string
  affected_version?: string
  fixed_version?: string
  status: 'open' | 'mitigated' | 'patched' | 'accepted'
  detected_at: string
  updated_at: string
  notes?: string
}

const SEV_CONFIG = {
  critical: { label: 'Critical', bg: 'bg-red-900/40',    border: 'border-red-600',    text: 'text-red-300',    icon: AlertTriangle, bar: 'bg-red-500' },
  high:     { label: 'High',     bg: 'bg-orange-900/40', border: 'border-orange-600', text: 'text-orange-300', icon: AlertTriangle, bar: 'bg-orange-500' },
  medium:   { label: 'Medium',   bg: 'bg-yellow-900/30', border: 'border-yellow-600', text: 'text-yellow-300', icon: AlertCircle,   bar: 'bg-yellow-500' },
  low:      { label: 'Low',      bg: 'bg-blue-900/30',   border: 'border-blue-600',   text: 'text-blue-300',   icon: Info,          bar: 'bg-blue-500' },
}

const STATUS_OPTIONS = [
  { value: 'open',      label: '未対応',        cls: 'text-red-300    bg-red-900/30    border-red-700' },
  { value: 'mitigated', label: '緩和済み',       cls: 'text-yellow-300 bg-yellow-900/30 border-yellow-700' },
  { value: 'patched',   label: 'パッチ適用済み', cls: 'text-green-300  bg-green-900/30  border-green-700' },
  { value: 'accepted',  label: '受容済み',       cls: 'text-[#8899aa]  bg-[#111827]     border-[#1e2d42]' },
]

function formatDate(s: string) {
  return new Date(s).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function cvssBar(score: number) {
  const pct = Math.min(score / 10, 1) * 100
  const color = score >= 9 ? 'bg-red-500' : score >= 7 ? 'bg-orange-500' : score >= 4 ? 'bg-yellow-500' : 'bg-blue-500'
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-sm font-bold font-mono ${color.replace('bg-', 'text-')}`}>{score.toFixed(1)}</span>
    </div>
  )
}

export default function VulnerabilityDetailPage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()
  const qc = useQueryClient()

  const [editStatus, setEditStatus] = useState(false)
  const [statusVal, setStatusVal]   = useState('')
  const [notesVal, setNotesVal]     = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)

  const { data: vuln, isLoading } = useQuery<Vulnerability>({
    queryKey: ['vulnerability', id],
    queryFn: () => apiFetch(`/api/v1/vulnerabilities/${id}`),
    enabled: !!id,
  })

  const updateMut = useMutation({
    mutationFn: () => apiFetch(`/api/v1/vulnerabilities/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status: statusVal, notes: notesVal }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['vulnerability', id] })
      qc.invalidateQueries({ queryKey: ['vulnerabilities'] })
      setEditStatus(false)
    },
  })

  const deleteMut = useMutation({
    mutationFn: () => apiFetch(`/api/v1/vulnerabilities/${id}`, { method: 'DELETE' }),
    onSuccess: () => router.push('/vulnerabilities'),
  })

  function startEdit() {
    if (!vuln) return
    setStatusVal(vuln.status)
    setNotesVal(vuln.notes ?? '')
    setEditStatus(true)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-[#e8002d] border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!vuln) {
    return (
      <div className="p-8 text-center text-[#8899aa]">
        脆弱性が見つかりません
        <div className="mt-4">
          <Link href="/vulnerabilities" className="text-sm text-[#1a6bff] hover:underline">
            一覧へ戻る
          </Link>
        </div>
      </div>
    )
  }

  const sev = SEV_CONFIG[vuln.severity] ?? SEV_CONFIG.low
  const SevIcon = sev.icon
  const statusCfg = STATUS_OPTIONS.find(o => o.value === vuln.status) ?? STATUS_OPTIONS[0]

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Back nav */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-1.5 text-sm text-[#8899aa] hover:text-[#e2e8f4] transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        脆弱性一覧
      </button>

      {/* Header card */}
      <div className={`rounded-xl border ${sev.border} ${sev.bg} p-6`}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-4 min-w-0">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${sev.bg} border ${sev.border}`}>
              <SevIcon className={`w-5 h-5 ${sev.text}`} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-3 mb-1 flex-wrap">
                <span className={`font-mono text-sm font-bold ${sev.text}`}>{vuln.cve_id}</span>
                <span className={`text-xs font-bold px-2 py-0.5 rounded-sm border ${sev.text} ${sev.bg} ${sev.border}`}>
                  {sev.label}
                </span>
                <span className={`text-xs px-2 py-0.5 rounded-sm border font-medium ${statusCfg.cls}`}>
                  {statusCfg.label}
                </span>
              </div>
              <h1 className="text-lg font-bold text-[#e2e8f4] leading-snug">{vuln.title}</h1>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={startEdit}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#161f33] hover:bg-[#1d2f4a] border border-[#1e2d42] text-[#8899aa] hover:text-[#e2e8f4] text-sm rounded-lg transition-colors"
            >
              <Pencil className="w-3.5 h-3.5" />
              ステータス更新
            </button>
            {!confirmDelete ? (
              <button
                onClick={() => setConfirmDelete(true)}
                className="p-1.5 text-[#3d5068] hover:text-red-400 transition-colors rounded-sm"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            ) : (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => deleteMut.mutate()}
                  className="px-2 py-1 text-xs bg-red-900/50 hover:bg-red-800 border border-red-700 text-red-300 rounded-sm transition-colors"
                >
                  削除
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="px-2 py-1 text-xs bg-[#161f33] hover:bg-[#1d2f4a] border border-[#1e2d42] text-[#8899aa] rounded-sm transition-colors"
                >
                  取消
                </button>
              </div>
            )}
          </div>
        </div>

        {/* CVSS score bar */}
        {vuln.cvss_score !== undefined && vuln.cvss_score !== null && (
          <div className="mt-5 pt-4 border-t border-[#1e2d42]/50">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-[#8899aa] uppercase tracking-wider font-medium">CVSS Score</span>
            </div>
            {cvssBar(vuln.cvss_score)}
          </div>
        )}
      </div>

      {/* Status update form */}
      {editStatus && (
        <div className="rounded-xl border border-[#1e2d42] bg-[#111827] p-5 space-y-4">
          <h3 className="text-sm font-semibold text-[#e2e8f4]">ステータス更新</h3>
          <div className="grid grid-cols-2 gap-2">
            {STATUS_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => setStatusVal(opt.value)}
                className={`px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${
                  statusVal === opt.value
                    ? opt.cls
                    : 'border-[#1e2d42] text-[#8899aa] hover:bg-[#19253d]'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <div>
            <label className="block text-xs text-[#8899aa] mb-1">メモ</label>
            <textarea
              value={notesVal}
              onChange={e => setNotesVal(e.target.value)}
              rows={3}
              placeholder="対応内容、根拠など..."
              className="w-full bg-[#0d1625] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] placeholder-[#3d5068] outline-hidden focus:border-[#1a6bff] resize-none"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => updateMut.mutate()}
              disabled={updateMut.isPending}
              className="flex items-center gap-1.5 px-4 py-2 bg-[#1a6bff] hover:bg-[#1558cc] disabled:opacity-50 text-white text-sm rounded-lg transition-colors"
            >
              <Check className="w-3.5 h-3.5" />
              保存
            </button>
            <button
              onClick={() => setEditStatus(false)}
              className="flex items-center gap-1.5 px-4 py-2 bg-[#161f33] hover:bg-[#1d2f4a] border border-[#1e2d42] text-[#8899aa] text-sm rounded-lg transition-colors"
            >
              <X className="w-3.5 h-3.5" />
              キャンセル
            </button>
          </div>
        </div>
      )}

      {/* Details grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Affected asset */}
        <div className="rounded-xl border border-[#1e2d42] bg-[#111827] p-5">
          <div className="flex items-center gap-2 mb-4">
            <Monitor className="w-4 h-4 text-[#1a6bff]" />
            <h3 className="text-sm font-semibold text-[#e2e8f4]">影響を受けるエンドポイント</h3>
          </div>
          {vuln.agent_hostname ? (
            <div className="space-y-2">
              <Link
                href={`/endpoints/${vuln.agent_id}`}
                className="text-[#1a6bff] hover:underline font-mono text-sm"
              >
                {vuln.agent_hostname}
              </Link>
              {vuln.agent_id && (
                <p className="text-xs text-[#3d5068] font-mono">{vuln.agent_id}</p>
              )}
            </div>
          ) : (
            <p className="text-sm text-[#3d5068]">エンドポイント未指定</p>
          )}
        </div>

        {/* Package info */}
        <div className="rounded-xl border border-[#1e2d42] bg-[#111827] p-5">
          <div className="flex items-center gap-2 mb-4">
            <Package className="w-4 h-4 text-[#00c853]" />
            <h3 className="text-sm font-semibold text-[#e2e8f4]">影響パッケージ</h3>
          </div>
          <div className="space-y-2 text-sm">
            {vuln.affected_package ? (
              <>
                <div className="flex justify-between">
                  <span className="text-[#8899aa]">パッケージ</span>
                  <span className="text-[#e2e8f4] font-mono">{vuln.affected_package}</span>
                </div>
                {vuln.affected_version && (
                  <div className="flex justify-between">
                    <span className="text-[#8899aa]">影響バージョン</span>
                    <span className="text-red-300 font-mono">{vuln.affected_version}</span>
                  </div>
                )}
                {vuln.fixed_version && (
                  <div className="flex justify-between">
                    <span className="text-[#8899aa]">修正バージョン</span>
                    <span className="text-green-300 font-mono">{vuln.fixed_version}</span>
                  </div>
                )}
              </>
            ) : (
              <p className="text-[#3d5068]">パッケージ情報なし</p>
            )}
          </div>
        </div>

        {/* Compliance / remediation quick info */}
        <div className="rounded-xl border border-[#1e2d42] bg-[#111827] p-5">
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheck className="w-4 h-4 text-[#a78bfa]" />
            <h3 className="text-sm font-semibold text-[#e2e8f4]">タイムライン</h3>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-[#8899aa]">検出日時</span>
              <span className="text-[#e2e8f4] font-mono text-xs">{formatDate(vuln.detected_at)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#8899aa]">最終更新</span>
              <span className="text-[#e2e8f4] font-mono text-xs">{formatDate(vuln.updated_at)}</span>
            </div>
          </div>
        </div>

        {/* Notes */}
        <div className="rounded-xl border border-[#1e2d42] bg-[#111827] p-5">
          <div className="flex items-center gap-2 mb-4">
            <Pencil className="w-4 h-4 text-[#8899aa]" />
            <h3 className="text-sm font-semibold text-[#e2e8f4]">メモ</h3>
          </div>
          {vuln.notes ? (
            <p className="text-sm text-[#8899aa] whitespace-pre-wrap leading-relaxed">{vuln.notes}</p>
          ) : (
            <p className="text-sm text-[#3d5068]">メモなし</p>
          )}
        </div>
      </div>

      {/* Description */}
      {vuln.description && (
        <div className="rounded-xl border border-[#1e2d42] bg-[#111827] p-5">
          <div className="flex items-center gap-2 mb-3">
            <Bug className="w-4 h-4 text-[#ff4d6d]" />
            <h3 className="text-sm font-semibold text-[#e2e8f4]">説明</h3>
          </div>
          <p className="text-sm text-[#8899aa] leading-relaxed whitespace-pre-wrap">{vuln.description}</p>
        </div>
      )}
    </div>
  )
}
