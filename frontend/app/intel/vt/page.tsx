'use client'

import React, { useState, useEffect } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { apiFetch } from '@/lib/api'
import {
  ScanSearch, AlertTriangle, CheckCircle, XCircle,
  Hash, Globe, Server, Clock, Tag, Shield
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface VTResult {
  found:          boolean
  malicious:      number
  suspicious:     number
  total_engines:  number
  reputation:     number
  tags:           string[]
  first_seen:     string | null
  last_analysis:  string | null
  common_name:    string
  type:           string  // hash | ip | domain
}

// ─── API helper ───────────────────────────────────────────────────────────────

async function vtLookup(value: string, type?: string): Promise<VTResult> {
  return apiFetch<VTResult>('/api/v1/intel/vt/lookup', {
    method: 'POST',
    body: JSON.stringify({ value: value.trim(), type: type || '' }),
  })
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function VerdictBadge({ malicious, total }: { malicious: number; total: number }) {
  if (total === 0) return <span className="text-xs text-[#7d92b0]">スキャン未実施</span>
  const ratio = malicious / total
  if (malicious === 0)
    return (
      <span className="flex items-center gap-1 text-green-400 font-semibold">
        <CheckCircle className="w-4 h-4" /> クリーン
      </span>
    )
  if (ratio >= 0.5)
    return (
      <span className="flex items-center gap-1 text-red-400 font-semibold">
        <XCircle className="w-4 h-4" /> 悪意あり ({malicious}/{total})
      </span>
    )
  return (
    <span className="flex items-center gap-1 text-yellow-400 font-semibold">
      <AlertTriangle className="w-4 h-4" /> 疑わしい ({malicious}/{total})
    </span>
  )
}

function DetectionBar({ malicious, suspicious, total }: { malicious: number; suspicious: number; total: number }) {
  if (total === 0) return null
  const malPct  = Math.round((malicious  / total) * 100)
  const suspPct = Math.round((suspicious / total) * 100)
  const cleanPct = 100 - malPct - suspPct
  return (
    <div>
      <div className="flex h-2 rounded-full overflow-hidden bg-[#1e2d42] gap-0.5">
        {malPct > 0   && <div className="bg-red-500"    style={{ width: `${malPct}%` }} />}
        {suspPct > 0  && <div className="bg-yellow-500" style={{ width: `${suspPct}%` }} />}
        {cleanPct > 0 && <div className="bg-green-600"  style={{ width: `${cleanPct}%` }} />}
      </div>
      <div className="flex gap-4 mt-1.5 text-xs">
        <span className="text-red-400">悪意: {malicious}</span>
        <span className="text-yellow-400">疑わしい: {suspicious}</span>
        <span className="text-green-400">クリーン: {total - malicious - suspicious}</span>
        <span className="text-[#7d92b0]">合計: {total} エンジン</span>
      </div>
    </div>
  )
}

function TypeIcon({ type }: { type: string }) {
  if (type === 'ip')     return <Server className="w-4 h-4 text-blue-400" />
  if (type === 'domain') return <Globe  className="w-4 h-4 text-purple-400" />
  return <Hash className="w-4 h-4 text-orange-400" />
}

function formatDate(iso: string | null) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' })
  } catch {
    return iso
  }
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function VirusTotalPage() {
  const searchParams = useSearchParams()
  const [input, setInput] = useState('')
  const [lastQuery, setLastQuery] = useState('')

  const mutation = useMutation({
    mutationFn: (value: string) => vtLookup(value),
    onMutate: (value) => setLastQuery(value),
  })

  // Auto-execute if ?q= is provided (e.g. from IOC page link)
  useEffect(() => {
    const q = searchParams.get('q')
    if (q) {
      setInput(q)
      mutation.mutate(q)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const v = input.trim()
    if (!v) return
    mutation.mutate(v)
  }

  const result = mutation.data

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-blue-900/40 border border-blue-500/30 flex items-center justify-center">
          <ScanSearch className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-[#e2e8f4]">VirusTotal 検索</h1>
          <p className="text-xs text-[#7d92b0]">ハッシュ・IPアドレス・ドメインをVirusTotalで照会します</p>
        </div>
      </div>

      {/* Search form */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="MD5 / SHA1 / SHA256 / IPアドレス / ドメイン を入力..."
          className="flex-1 bg-[#111827] border border-[#1e2d42] rounded-lg px-4 py-2.5
                     text-sm text-[#e2e8f4] placeholder-[#5a6a7a]
                     focus:outline-none focus:border-blue-500/60 transition-colors"
        />
        <button
          type="submit"
          disabled={!input.trim() || mutation.isPending}
          className="px-5 py-2.5 bg-blue-600 text-white text-sm rounded-lg font-medium
                     hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {mutation.isPending ? '照会中...' : '検索'}
        </button>
      </form>

      {/* Error */}
      {mutation.isError && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
          {(mutation.error as Error).message}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="bg-[#111827] border border-[#1e2d42] rounded-xl overflow-hidden">
          {/* Result header */}
          <div className="px-5 py-4 border-b border-[#1e2d42] flex items-start justify-between gap-4">
            <div className="flex items-center gap-2 min-w-0">
              <TypeIcon type={result.type} />
              <span className="text-sm font-mono text-[#e2e8f4] truncate">{lastQuery}</span>
            </div>
            <VerdictBadge malicious={result.malicious} total={result.total_engines} />
          </div>

          {!result.found ? (
            <div className="px-5 py-8 text-center text-[#7d92b0] text-sm">
              <Shield className="w-10 h-10 mx-auto mb-3 text-[#3d5068]" />
              VirusTotalにデータが見つかりませんでした
            </div>
          ) : (
            <div className="px-5 py-4 space-y-5">
              {/* Detection bar */}
              <div>
                <p className="text-xs text-[#7d92b0] mb-2 font-medium uppercase tracking-wider">検出状況</p>
                <DetectionBar
                  malicious={result.malicious}
                  suspicious={result.suspicious}
                  total={result.total_engines}
                />
              </div>

              {/* Details grid */}
              <div className="grid grid-cols-2 gap-4">
                {result.common_name && (
                  <div className="col-span-2">
                    <p className="text-xs text-[#7d92b0] mb-1">マルウェア名</p>
                    <p className="text-sm font-semibold text-red-400">{result.common_name}</p>
                  </div>
                )}

                <div>
                  <p className="text-xs text-[#7d92b0] mb-1 flex items-center gap-1">
                    <Clock className="w-3 h-3" /> 初回検出
                  </p>
                  <p className="text-sm text-[#e2e8f4]">{formatDate(result.first_seen)}</p>
                </div>

                <div>
                  <p className="text-xs text-[#7d92b0] mb-1 flex items-center gap-1">
                    <Clock className="w-3 h-3" /> 最終分析
                  </p>
                  <p className="text-sm text-[#e2e8f4]">{formatDate(result.last_analysis)}</p>
                </div>

                {result.reputation !== 0 && (
                  <div>
                    <p className="text-xs text-[#7d92b0] mb-1">レピュテーション</p>
                    <p className={`text-sm font-semibold ${result.reputation < 0 ? 'text-red-400' : 'text-green-400'}`}>
                      {result.reputation > 0 ? '+' : ''}{result.reputation}
                    </p>
                  </div>
                )}
              </div>

              {/* Tags */}
              {result.tags && result.tags.length > 0 && (
                <div>
                  <p className="text-xs text-[#7d92b0] mb-2 flex items-center gap-1">
                    <Tag className="w-3 h-3" /> タグ
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {result.tags.map(tag => (
                      <span
                        key={tag}
                        className="text-xs px-2 py-0.5 rounded-full bg-[#1e2d42] border border-[#2a3f5f] text-[#8899aa]"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!result && !mutation.isPending && !mutation.isError && (
        <div className="text-center py-16 text-[#5a6a7a]">
          <ScanSearch className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">IOCを入力して検索してください</p>
          <p className="text-xs mt-1">対応: MD5/SHA1/SHA256ハッシュ、IPアドレス、ドメイン</p>
        </div>
      )}
    </div>
  )
}
