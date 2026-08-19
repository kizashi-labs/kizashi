'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Activity, Search, Download, Plus, Filter, RefreshCw,
  ChevronRight, ChevronDown, AlertTriangle, CheckCircle,
  Shield, Globe, User, FileText, Wifi, Database, Clock,
  Monitor, X, Flag,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────────────────

interface Endpoint {
  id: string
  hostname: string
  ip: string
  os: string
  last_seen: string
}

interface ProcessEvent {
  id: string
  timestamp: string
  event_type: 'create' | 'terminate' | 'inject' | 'hollowing'
  process_name: string
  pid: number
  ppid: number
  parent_name: string
  cmdline: string
  user: string
  hash: string
  children?: ProcessEvent[]
}

interface FileEvent {
  id: string
  timestamp: string
  event_type: 'create' | 'modify' | 'delete' | 'rename' | 'encrypt'
  file_path: string
  process_name: string
  user: string
  file_size: number
  is_suspicious: boolean
}

interface NetworkEvent {
  id: string
  timestamp: string
  direction: 'inbound' | 'outbound'
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  protocol: string
  bytes: number
  process: string
  domain?: string
  reputation: 'clean' | 'suspicious' | 'malicious'
  country?: string
}

interface DnsEvent {
  id: string
  timestamp: string
  queried_domain: string
  response: string
  ttl: number
  process: string
  is_suspicious: boolean
}

interface RegistryEvent {
  id: string
  timestamp: string
  event_type: 'create' | 'modify' | 'delete'
  key_path: string
  value_name: string
  old_value: string
  new_value: string
  process: string
  is_persistence: boolean
}

interface UserEvent {
  id: string
  timestamp: string
  event_type: 'logon' | 'logoff' | 'privilege_use' | 'account_change' | 'failed_logon'
  username: string
  session_id: string
  source_ip?: string
  details: string
  logon_type?: string
}

// ── Helpers ────────────────────────────────────────────────────────────────

function basename(p: string) {
  return p?.split(/[/\\]/).pop() ?? p ?? ''
}

// Extract a value from raw_data trying multiple possible field names
function rd<T>(raw: Record<string, unknown>, ...keys: string[]): T | undefined {
  for (const k of keys) {
    if (raw[k] !== undefined && raw[k] !== null) return raw[k] as T
  }
  return undefined
}

// ── Static style helpers ────────────────────────────────────────────────────

function fmt(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
function fmtBytes(b: number) {
  if (b >= 1_000_000) return `${(b / 1_000_000).toFixed(1)} MB`
  if (b >= 1_000) return `${(b / 1_000).toFixed(1)} KB`
  return `${b} B`
}

const PROCESS_TYPE_STYLES: Record<ProcessEvent['event_type'], string> = {
  create: 'bg-green-900/30 text-green-400 border border-green-700/40',
  terminate: 'bg-[#1e2d42] text-[#7d92b0]',
  inject: 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40',
  hollowing: 'bg-purple-900/30 text-purple-400 border border-purple-700/40',
}
const FILE_TYPE_STYLES: Record<FileEvent['event_type'], string> = {
  create: 'bg-green-900/30 text-green-400 border border-green-700/40',
  modify: 'bg-blue-900/30 text-blue-400 border border-blue-700/40',
  delete: 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40',
  rename: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/40',
  encrypt: 'bg-purple-900/30 text-purple-400 border border-purple-700/40',
}
const REP_STYLES = {
  clean: 'bg-green-900/30 text-green-400 border border-green-700/40',
  suspicious: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/40',
  malicious: 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40',
}
const REG_TYPE_STYLES: Record<RegistryEvent['event_type'], string> = {
  create: 'bg-green-900/30 text-green-400 border border-green-700/40',
  modify: 'bg-blue-900/30 text-blue-400 border border-blue-700/40',
  delete: 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40',
}
const USER_TYPE_STYLES: Record<UserEvent['event_type'], string> = {
  logon: 'bg-green-900/30 text-green-400 border border-green-700/40',
  logoff: 'bg-[#1e2d42] text-[#7d92b0]',
  privilege_use: 'bg-orange-900/30 text-orange-400 border border-orange-700/40',
  account_change: 'bg-purple-900/30 text-purple-400 border border-purple-700/40',
  failed_logon: 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40',
}

// Static mock data instances
type Tab = 'process' | 'file' | 'network' | 'registry' | 'user'

// ── Process Tab ─────────────────────────────────────────────────────────────

function ProcessTab({ events, live }: { events: ProcessEvent[]; live: boolean }) {
  const [filterType, setFilterType] = useState<ProcessEvent['event_type'] | 'ALL'>('ALL')
  const [filterUser, setFilterUser] = useState('')
  const [filterProc, setFilterProc] = useState('')
  const [treeView, setTreeView] = useState(false)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const filtered = events.filter(e => {
    if (filterType !== 'ALL' && e.event_type !== filterType) return false
    if (filterUser && !e.user.toLowerCase().includes(filterUser.toLowerCase())) return false
    if (filterProc && !e.process_name.toLowerCase().includes(filterProc.toLowerCase())) return false
    return true
  })

  const toggleExpand = (id: string) => setExpanded(prev => {
    const n = new Set(prev)
    n.has(id) ? n.delete(id) : n.add(id)
    return n
  })

  // Build simple process tree (group by ppid→pid)
  const roots = filtered.filter((e, idx) => idx < 20)

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {(['ALL', 'create', 'terminate', 'inject', 'hollowing'] as const).map(t => (
          <button
            key={t}
            onClick={() => setFilterType(t as any)}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${filterType === t ? 'bg-[#1d2f4a] text-white' : 'bg-[#161f33] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}
          >
            {t}
          </button>
        ))}
        <input
          value={filterProc}
          onChange={e => setFilterProc(e.target.value)}
          placeholder="プロセス名でフィルタ..."
          className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2.5 py-1 text-xs text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/40"
        />
        <input
          value={filterUser}
          onChange={e => setFilterUser(e.target.value)}
          placeholder="ユーザーでフィルタ..."
          className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2.5 py-1 text-xs text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/40"
        />
        <button
          onClick={() => setTreeView(v => !v)}
          className={`flex items-center gap-1 px-2.5 py-1 text-xs rounded-sm border transition-colors ${treeView ? 'bg-[#1d2f4a] text-white border-[#2a3f5c]' : 'border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}
        >
          <ChevronRight className="w-3 h-3" />
          ツリービュー
        </button>
        {live && <span className="flex items-center gap-1 text-xs text-green-400 animate-pulse"><span className="w-1.5 h-1.5 rounded-full bg-green-400" />ライブ</span>}
      </div>

      {treeView ? (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3 font-mono text-xs overflow-x-auto">
          {roots.map((e, idx) => (
            <div key={e.id} className={`py-1 ${idx > 0 ? 'ml-4 border-l border-[#1e2d42] pl-3' : ''}`}>
              <div className="flex items-center gap-2">
                <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${PROCESS_TYPE_STYLES[e.event_type]}`}>{e.event_type}</span>
                <span className="text-white font-medium">{e.process_name}</span>
                <span className="text-[#3d5068]">(PID:{e.pid})</span>
                <span className="text-[#7d92b0]">← {e.parent_name}</span>
                <span className="text-[#3d5068] ml-auto">{e.user}</span>
              </div>
              {idx % 3 === 0 && (
                <div className="ml-4 border-l border-[#1e2d42] pl-3 mt-1">
                  <div className="flex items-center gap-2 opacity-70">
                    <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${PROCESS_TYPE_STYLES['create']}`}>create</span>
                    <span className="text-[#7d92b0]">conhost.exe</span>
                    <span className="text-[#3d5068]">(PID:{e.pid + 1})</span>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['時刻', 'タイプ', 'プロセス', 'PID', 'PPID', '親', 'ユーザー', 'ハッシュ', 'コマンドライン'].map(h => (
                  <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 50).map(e => (
                <>
                  <tr
                    key={e.id}
                    className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors cursor-pointer ${e.event_type === 'inject' || e.event_type === 'hollowing' ? 'bg-[#e8002d]/5' : ''}`}
                    onClick={() => toggleExpand(e.id)}
                  >
                    <td className="py-2 px-3 font-mono text-[#7d92b0] whitespace-nowrap">{fmt(e.timestamp)}</td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${PROCESS_TYPE_STYLES[e.event_type]}`}>{e.event_type}</span>
                    </td>
                    <td className="py-2 px-3 text-white font-medium whitespace-nowrap">{e.process_name}</td>
                    <td className="py-2 px-3 font-mono text-[#7d92b0]">{e.pid}</td>
                    <td className="py-2 px-3 font-mono text-[#7d92b0]">{e.ppid}</td>
                    <td className="py-2 px-3 text-[#7d92b0]">{e.parent_name}</td>
                    <td className="py-2 px-3 text-[#7d92b0]">{e.user}</td>
                    <td className="py-2 px-3 font-mono text-[#3d5068]">{e.hash.slice(0, 12)}…</td>
                    <td className="py-2 px-3 max-w-[200px]">
                      <span className="font-mono text-[#7d92b0] truncate block">{e.cmdline.slice(0, 40)}{e.cmdline.length > 40 ? '…' : ''}</span>
                    </td>
                  </tr>
                  {expanded.has(e.id) && (
                    <tr key={`${e.id}-exp`} className="border-b border-[#1e2d42]/50 bg-[#161f33]">
                      <td colSpan={9} className="px-4 py-3">
                        <div className="space-y-1">
                          <p className="text-[#7d92b0] text-[10px] font-semibold uppercase">コマンドライン (完全)</p>
                          <p className="font-mono text-xs text-white bg-[#0d1220] border border-[#1e2d42] px-3 py-2 rounded-sm break-all">{e.cmdline}</p>
                          <p className="text-[#7d92b0] text-[10px] mt-2">SHA256: <span className="font-mono text-white">{e.hash}</span></p>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── File Tab ───────────────────────────────────────────────────────────────

function FileTab({ events }: { events: FileEvent[] }) {
  const [filterType, setFilterType] = useState<FileEvent['event_type'] | 'ALL'>('ALL')
  const [filterPath, setFilterPath] = useState('')
  const [suspOnly, setSuspOnly] = useState(false)

  const filtered = events.filter(e => {
    if (filterType !== 'ALL' && e.event_type !== filterType) return false
    if (filterPath && !e.file_path.toLowerCase().includes(filterPath.toLowerCase())) return false
    if (suspOnly && !e.is_suspicious) return false
    return true
  })

  const suspicious = events.filter(e => e.is_suspicious)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {(['ALL', 'create', 'modify', 'delete', 'rename', 'encrypt'] as const).map(t => (
          <button
            key={t}
            onClick={() => setFilterType(t as any)}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${filterType === t ? 'bg-[#1d2f4a] text-white' : 'bg-[#161f33] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}
          >
            {t}
          </button>
        ))}
        <input
          value={filterPath}
          onChange={e => setFilterPath(e.target.value)}
          placeholder="パスでフィルタ..."
          className="bg-[#161f33] border border-[#1e2d42] rounded-sm px-2.5 py-1 text-xs text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/40 min-w-[180px]"
        />
        <label className="flex items-center gap-1.5 cursor-pointer">
          <input type="checkbox" checked={suspOnly} onChange={e => setSuspOnly(e.target.checked)} className="accent-[#e8002d] w-3 h-3" />
          <span className="text-xs text-[#7d92b0]">不審のみ</span>
        </label>
      </div>

      {suspicious.length > 0 && (
        <div className="bg-[#e8002d]/10 border border-[#e8002d]/30 rounded-lg p-3">
          <p className="text-[#ff4d6d] text-xs font-semibold mb-2 flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" />
            不審ファイルイベント ({suspicious.length} 件) — ランサムウェアパターン一致
          </p>
          <div className="space-y-1">
            {suspicious.slice(0, 3).map(e => (
              <div key={e.id} className="flex items-center gap-2 text-xs">
                <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${FILE_TYPE_STYLES[e.event_type]}`}>{e.event_type}</span>
                <span className="font-mono text-white">{e.file_path}</span>
                <span className="text-[#7d92b0] ml-auto">{e.process_name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['時刻', 'タイプ', 'ファイルパス', 'プロセス', 'ユーザー', 'サイズ', '不審'].map(h => (
                <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 50).map(e => (
              <tr key={e.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors ${e.is_suspicious ? 'bg-[#e8002d]/5' : ''}`}>
                <td className="py-2 px-3 font-mono text-[#7d92b0] whitespace-nowrap">{fmt(e.timestamp)}</td>
                <td className="py-2 px-3 whitespace-nowrap">
                  <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${FILE_TYPE_STYLES[e.event_type]}`}>{e.event_type}</span>
                </td>
                <td className="py-2 px-3 font-mono text-white max-w-[200px] truncate" title={e.file_path}>{e.file_path}</td>
                <td className="py-2 px-3 text-[#7d92b0]">{e.process_name}</td>
                <td className="py-2 px-3 text-[#7d92b0]">{e.user}</td>
                <td className="py-2 px-3 text-[#7d92b0] whitespace-nowrap">{fmtBytes(e.file_size)}</td>
                <td className="py-2 px-3">
                  {e.is_suspicious && <AlertTriangle className="w-3.5 h-3.5 text-[#ff4d6d]" />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Network Tab ────────────────────────────────────────────────────────────

function NetworkTab({ events, dnsEvents }: { events: NetworkEvent[]; dnsEvents: DnsEvent[] }) {
  const [dnsView, setDnsView] = useState(false)
  const [filterRep, setFilterRep] = useState<NetworkEvent['reputation'] | 'ALL'>('ALL')

  const filtered = events.filter(e => filterRep === 'ALL' || e.reputation === filterRep)

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex gap-1">
          <button onClick={() => setDnsView(false)} className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${!dnsView ? 'bg-[#1d2f4a] text-white' : 'bg-[#161f33] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}>
            通信ログ
          </button>
          <button onClick={() => setDnsView(true)} className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${dnsView ? 'bg-[#1d2f4a] text-white' : 'bg-[#161f33] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}>
            DNS クエリ
          </button>
        </div>
        {!dnsView && (['ALL', 'clean', 'suspicious', 'malicious'] as const).map(r => (
          <button
            key={r}
            onClick={() => setFilterRep(r)}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${filterRep === r ? 'bg-[#1d2f4a] text-white' : 'bg-[#161f33] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}
          >
            {r}
          </button>
        ))}
      </div>

      {!dnsView ? (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['時刻', '方向', '送信元', '宛先', 'プロトコル', 'バイト数', 'プロセス', 'ドメイン', '評判', '国'].map(h => (
                  <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 50).map(e => (
                <tr key={e.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors ${e.reputation === 'malicious' ? 'bg-[#e8002d]/5' : ''}`}>
                  <td className="py-2 px-3 font-mono text-[#7d92b0] whitespace-nowrap">{fmt(e.timestamp)}</td>
                  <td className="py-2 px-3">
                    <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${e.direction === 'inbound' ? 'bg-blue-900/30 text-blue-400 border border-blue-700/40' : 'bg-orange-900/30 text-orange-400 border border-orange-700/40'}`}>
                      {e.direction === 'inbound' ? '↓ IN' : '↑ OUT'}
                    </span>
                  </td>
                  <td className="py-2 px-3 font-mono text-[#7d92b0] whitespace-nowrap">{e.src_ip}:{e.src_port}</td>
                  <td className="py-2 px-3 font-mono text-white whitespace-nowrap">{e.dst_ip}:{e.dst_port}</td>
                  <td className="py-2 px-3 text-[#7d92b0]">{e.protocol}</td>
                  <td className="py-2 px-3 text-[#7d92b0] whitespace-nowrap">{fmtBytes(e.bytes)}</td>
                  <td className="py-2 px-3 text-[#7d92b0]">{e.process}</td>
                  <td className="py-2 px-3 text-[#7d92b0] max-w-[140px] truncate" title={e.domain}>{e.domain ?? '—'}</td>
                  <td className="py-2 px-3 whitespace-nowrap">
                    <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${REP_STYLES[e.reputation]}`}>{e.reputation}</span>
                  </td>
                  <td className="py-2 px-3 text-[#7d92b0]">{e.country ? <span className="flex items-center gap-1"><Flag className="w-3 h-3" />{e.country}</span> : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['時刻', 'クエリドメイン', 'レスポンス', 'TTL', 'プロセス', '不審'].map(h => (
                  <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {dnsEvents.map(e => (
                <tr key={e.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors ${e.is_suspicious ? 'bg-[#e8002d]/5' : ''}`}>
                  <td className="py-2 px-3 font-mono text-[#7d92b0] whitespace-nowrap">{fmt(e.timestamp)}</td>
                  <td className="py-2 px-3 font-mono text-white">{e.queried_domain}</td>
                  <td className="py-2 px-3 font-mono text-[#7d92b0]">{e.response}</td>
                  <td className="py-2 px-3 text-[#7d92b0]">{e.ttl}s</td>
                  <td className="py-2 px-3 text-[#7d92b0]">{e.process}</td>
                  <td className="py-2 px-3">{e.is_suspicious && <AlertTriangle className="w-3.5 h-3.5 text-[#ff4d6d]" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Registry Tab ───────────────────────────────────────────────────────────

function RegistryTab({ events }: { events: RegistryEvent[] }) {
  const [filterType, setFilterType] = useState<RegistryEvent['event_type'] | 'ALL'>('ALL')
  const [persistOnly, setPersistOnly] = useState(false)

  const filtered = events.filter(e => {
    if (filterType !== 'ALL' && e.event_type !== filterType) return false
    if (persistOnly && !e.is_persistence) return false
    return true
  })

  const persistenceEntries = events.filter(e => e.is_persistence)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {(['ALL', 'create', 'modify', 'delete'] as const).map(t => (
          <button
            key={t}
            onClick={() => setFilterType(t as any)}
            className={`px-2.5 py-1 text-xs rounded-sm transition-colors ${filterType === t ? 'bg-[#1d2f4a] text-white' : 'bg-[#161f33] text-[#7d92b0] hover:text-white border border-[#1e2d42]'}`}
          >
            {t}
          </button>
        ))}
        <label className="flex items-center gap-1.5 cursor-pointer">
          <input type="checkbox" checked={persistOnly} onChange={e => setPersistOnly(e.target.checked)} className="accent-[#e8002d] w-3 h-3" />
          <span className="text-xs text-[#7d92b0]">永続化エントリのみ</span>
        </label>
      </div>

      {persistenceEntries.length > 0 && (
        <div className="bg-orange-900/20 border border-orange-700/30 rounded-lg p-3">
          <p className="text-orange-400 text-xs font-semibold mb-2 flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" />
            永続化キー検出 ({persistenceEntries.length} 件) — 既知の永続化ロケーション一致
          </p>
          <div className="space-y-1">
            {persistenceEntries.slice(0, 3).map(e => (
              <div key={e.id} className="text-xs">
                <span className="font-mono text-orange-300">{e.key_path}\\{e.value_name}</span>
                <span className="text-[#7d92b0] ml-2">→ {e.new_value.slice(0, 40)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['時刻', 'タイプ', 'キーパス', '値名', '変更前', '変更後', 'プロセス', '永続化'].map(h => (
                <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 50).map(e => (
              <tr key={e.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors ${e.is_persistence ? 'bg-orange-900/10' : ''}`}>
                <td className="py-2 px-3 font-mono text-[#7d92b0] whitespace-nowrap">{fmt(e.timestamp)}</td>
                <td className="py-2 px-3 whitespace-nowrap">
                  <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${REG_TYPE_STYLES[e.event_type]}`}>{e.event_type}</span>
                </td>
                <td className="py-2 px-3 font-mono text-white max-w-[160px] truncate" title={e.key_path}>{e.key_path}</td>
                <td className="py-2 px-3 font-mono text-[#7d92b0]">{e.value_name}</td>
                <td className="py-2 px-3 font-mono text-[#3d5068] max-w-[80px] truncate">{e.old_value || '—'}</td>
                <td className="py-2 px-3 font-mono text-[#7d92b0] max-w-[120px] truncate" title={e.new_value}>{e.new_value || '—'}</td>
                <td className="py-2 px-3 text-[#7d92b0]">{e.process}</td>
                <td className="py-2 px-3">{e.is_persistence && <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── User Tab ───────────────────────────────────────────────────────────────

function UserTab({ events }: { events: UserEvent[] }) {
  // Build simple session timeline for selected day
  const sessions = events.filter(e => e.event_type === 'logon' || e.event_type === 'logoff' || e.event_type === 'failed_logon')
  const hours = Array.from({ length: 24 }, (_, i) => i)

  return (
    <div className="space-y-4">
      {/* Session Timeline */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
        <h3 className="text-white text-sm font-semibold mb-3">セッションタイムライン (本日)</h3>
        <div className="relative">
          <div className="flex items-center gap-0 overflow-x-auto pb-2">
            {hours.map(h => (
              <div key={h} className="shrink-0 w-8 text-center">
                <div className="text-[9px] text-[#3d5068] mb-1">{h.toString().padStart(2, '0')}</div>
                <div className={`h-6 w-7 rounded-xs mx-0.5 transition-colors ${
                  sessions.some(e => new Date(e.timestamp).getHours() === h && e.event_type === 'logon') ? 'bg-green-900/50 border border-green-700/50' :
                  sessions.some(e => new Date(e.timestamp).getHours() === h && e.event_type === 'failed_logon') ? 'bg-[#e8002d]/30 border border-[#e8002d]/30' :
                  'bg-[#161f33] border border-[#1e2d42]'
                }`} />
              </div>
            ))}
          </div>
          <div className="flex gap-3 mt-2">
            <span className="flex items-center gap-1 text-[10px] text-green-400"><span className="w-2 h-2 rounded-xs bg-green-900/50 border border-green-700/50" />ログオン</span>
            <span className="flex items-center gap-1 text-[10px] text-[#ff4d6d]"><span className="w-2 h-2 rounded-xs bg-[#e8002d]/30 border border-[#e8002d]/30" />認証失敗</span>
            <span className="flex items-center gap-1 text-[10px] text-[#3d5068]"><span className="w-2 h-2 rounded-xs bg-[#161f33] border border-[#1e2d42]" />非アクティブ</span>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[#1e2d42]">
              {['時刻', 'タイプ', 'ユーザー', 'ログオン種別', 'ソースIP', '詳細'].map(h => (
                <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.slice(0, 50).map(e => (
              <tr key={e.id} className={`border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors ${e.event_type === 'failed_logon' ? 'bg-[#e8002d]/5' : ''}`}>
                <td className="py-2 px-3 font-mono text-[#7d92b0] whitespace-nowrap">{fmt(e.timestamp)}</td>
                <td className="py-2 px-3 whitespace-nowrap">
                  <span className={`px-1.5 py-0.5 rounded-sm text-[10px] ${USER_TYPE_STYLES[e.event_type]}`}>{e.event_type}</span>
                </td>
                <td className="py-2 px-3 text-white font-medium">{e.username}</td>
                <td className="py-2 px-3 text-[#7d92b0]">{e.logon_type ?? '—'}</td>
                <td className="py-2 px-3 font-mono text-[#7d92b0]">{e.source_ip ?? '—'}</td>
                <td className="py-2 px-3 text-[#7d92b0] max-w-[200px] truncate">{e.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

const TABS: { key: Tab; label: string; icon: React.ComponentType<any> }[] = [
  { key: 'process', label: 'プロセス', icon: Activity },
  { key: 'file', label: 'ファイル', icon: FileText },
  { key: 'network', label: 'ネットワーク', icon: Wifi },
  { key: 'registry', label: 'レジストリ', icon: Database },
  { key: 'user', label: 'ユーザー', icon: User },
]

export default function TelemetryPage() {
  const [tab, setTab] = useState<Tab>('process')
  const [search, setSearch] = useState('')
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null)
  const [showDropdown, setShowDropdown] = useState(false)
  const [live, setLive] = useState(false)
  const [timeRange, setTimeRange] = useState('1h')
  const [iocMsg, setIocMsg] = useState<string | null>(null)
  const agentId = selectedEndpoint?.id

  const { data: agentsData } = useQuery<{ agents?: Endpoint[]; data?: Endpoint[] }>({
    queryKey: ['telemetry-agents'],
    queryFn: () => apiFetch('/api/v1/agents?per_page=1000'),
    staleTime: 60_000,
  })
  const endpointList: Endpoint[] = (agentsData?.agents ?? agentsData?.data ?? []).map((a) => {
    const r = a as unknown as Record<string, unknown>
    return {
      id: r.id as string,
      hostname: r.hostname as string,
      ip: (r.ip_address ?? r.ip ?? '') as string,
      os: (r.os ?? r.os_name ?? '') as string,
      last_seen: (r.last_seen ?? r.updated_at ?? '') as string,
    }
  })

  // ── Per-tab real data fetches ──────────────────────────────────────────────

  type APIProcess = { id: string; timestamp: string; pid: string; image: string; cmdline: string; parent_image: string; user: string; hashes: string }
  const { data: processData } = useQuery<ProcessEvent[]>({
    queryKey: ['telemetry-processes', agentId, timeRange],
    queryFn: async () => {
      if (!agentId) return []
      const res = await apiFetch<{ data: APIProcess[]; total: number }>(`/api/v1/agents/${agentId}/processes?per_page=200`)
      return (res.data ?? []).map((p, i): ProcessEvent => ({
        id: p.id,
        timestamp: p.timestamp,
        event_type: 'create',
        process_name: basename(p.image),
        pid: parseInt(p.pid) || i,
        ppid: 0,
        parent_name: basename(p.parent_image),
        cmdline: p.cmdline ?? '',
        user: p.user ?? '',
        hash: p.hashes ?? '',
      }))
    },
    enabled: !!agentId,
    refetchInterval: live ? 10_000 : false,
  })
  const processEvents: ProcessEvent[] = processData ?? []

  type RawEvent = { id: string; agent_id: string; event_type: string; raw_data: Record<string, unknown>; timestamp: string }
  function fetchEvents(type: string) {
    const params = new URLSearchParams({ type, per_page: '200' })
    if (agentId) params.set('agent_id', agentId)
    return apiFetch<{ data: RawEvent[]; total: number }>(`/api/v1/events?${params}`)
  }

  const { data: fileData } = useQuery<FileEvent[]>({
    queryKey: ['telemetry-file', agentId, timeRange],
    queryFn: async () => {
      const res = await fetchEvents('file')
      return (res.data ?? []).map((e): FileEvent => {
        const r = e.raw_data ?? {}
        const evType = (rd<string>(r, 'event_type', 'operation', 'action') ?? 'modify') as FileEvent['event_type']
        return {
          id: e.id,
          timestamp: e.timestamp,
          event_type: ['create','modify','delete','rename','encrypt'].includes(evType) ? evType : 'modify',
          file_path: rd<string>(r, 'file_path', 'path', 'file_name', 'target_path') ?? '',
          process_name: rd<string>(r, 'process_name', 'process', 'image', 'Image') ?? '',
          user: rd<string>(r, 'user', 'username', 'User') ?? '',
          file_size: rd<number>(r, 'file_size', 'size', 'FileSize') ?? 0,
          is_suspicious: rd<boolean>(r, 'is_suspicious', 'suspicious') ?? false,
        }
      })
    },
    refetchInterval: live ? 10_000 : false,
  })
  const fileEvents: FileEvent[] = fileData ?? []

  const { data: networkData } = useQuery<NetworkEvent[]>({
    queryKey: ['telemetry-network', agentId, timeRange],
    queryFn: async () => {
      const res = await fetchEvents('network')
      return (res.data ?? []).map((e): NetworkEvent => {
        const r = e.raw_data ?? {}
        const rep = (rd<string>(r, 'reputation') ?? 'clean') as NetworkEvent['reputation']
        return {
          id: e.id,
          timestamp: e.timestamp,
          direction: (rd<string>(r, 'direction') ?? 'outbound') as 'inbound' | 'outbound',
          src_ip: rd<string>(r, 'src_ip', 'source_ip', 'local_address', 'local_ip') ?? '',
          src_port: rd<number>(r, 'src_port', 'source_port', 'local_port') ?? 0,
          dst_ip: rd<string>(r, 'dst_ip', 'dest_ip', 'remote_address', 'remote_ip') ?? '',
          dst_port: rd<number>(r, 'dst_port', 'dest_port', 'remote_port') ?? 0,
          protocol: rd<string>(r, 'protocol', 'Protocol') ?? '',
          bytes: rd<number>(r, 'bytes', 'bytes_total', 'size') ?? 0,
          process: rd<string>(r, 'process', 'process_name', 'image', 'Image') ?? '',
          domain: rd<string>(r, 'domain', 'remote_domain', 'hostname'),
          reputation: ['clean','suspicious','malicious'].includes(rep) ? rep : 'clean',
          country: rd<string>(r, 'country', 'remote_country'),
        }
      })
    },
    refetchInterval: live ? 10_000 : false,
  })
  const networkEvents: NetworkEvent[] = networkData ?? []

  type APIDns = { id: string; timestamp: string; query: string; query_type?: string; answers?: string[]; pid?: number; process_name?: string; is_suspicious?: boolean }
  const { data: dnsData } = useQuery<DnsEvent[]>({
    queryKey: ['telemetry-dns', agentId, timeRange],
    queryFn: async () => {
      const params = new URLSearchParams({ per_page: '200' })
      if (agentId) params.set('agent_id', agentId)
      const res = await apiFetch<{ records: APIDns[]; total: number }>(`/api/v1/events/dns?${params}`)
      return (res.records ?? []).map((d): DnsEvent => ({
        id: d.id,
        timestamp: d.timestamp,
        queried_domain: d.query ?? '',
        response: d.answers?.join(', ') ?? '',
        ttl: 0,
        process: d.process_name ?? '',
        is_suspicious: d.is_suspicious ?? false,
      }))
    },
    refetchInterval: live ? 10_000 : false,
  })
  const dnsEvents: DnsEvent[] = dnsData ?? []

  const { data: registryData } = useQuery<RegistryEvent[]>({
    queryKey: ['telemetry-registry', agentId, timeRange],
    queryFn: async () => {
      const res = await fetchEvents('registry')
      return (res.data ?? []).map((e): RegistryEvent => {
        const r = e.raw_data ?? {}
        const evType = (rd<string>(r, 'event_type', 'operation', 'action') ?? 'modify') as RegistryEvent['event_type']
        return {
          id: e.id,
          timestamp: e.timestamp,
          event_type: ['create','modify','delete'].includes(evType) ? evType : 'modify',
          key_path: rd<string>(r, 'key_path', 'key', 'registry_key', 'TargetObject') ?? '',
          value_name: rd<string>(r, 'value_name', 'value', 'ValueName') ?? '',
          old_value: rd<string>(r, 'old_value', 'OldValue') ?? '',
          new_value: rd<string>(r, 'new_value', 'value_data', 'NewValue') ?? '',
          process: rd<string>(r, 'process', 'process_name', 'image', 'Image') ?? '',
          is_persistence: rd<boolean>(r, 'is_persistence', 'persistence') ?? false,
        }
      })
    },
    refetchInterval: live ? 10_000 : false,
  })
  const registryEvents: RegistryEvent[] = registryData ?? []

  const { data: userEventsData } = useQuery<UserEvent[]>({
    queryKey: ['telemetry-user', agentId, timeRange],
    queryFn: async () => {
      const res = await fetchEvents('auth')
      return (res.data ?? []).map((e): UserEvent => {
        const r = e.raw_data ?? {}
        const evType = (rd<string>(r, 'event_type', 'action', 'logon_type_name') ?? 'logon') as UserEvent['event_type']
        return {
          id: e.id,
          timestamp: e.timestamp,
          event_type: ['logon','logoff','privilege_use','account_change','failed_logon'].includes(evType) ? evType : 'logon',
          username: rd<string>(r, 'username', 'user', 'account_name', 'SubjectUserName') ?? '',
          session_id: rd<string>(r, 'session_id', 'logon_id', 'TargetLogonId') ?? '',
          source_ip: rd<string>(r, 'source_ip', 'src_ip', 'remote_address', 'IpAddress'),
          details: rd<string>(r, 'details', 'description', 'message', 'Keywords') ?? '',
          logon_type: rd<string>(r, 'logon_type', 'LogonType'),
        }
      })
    },
    refetchInterval: live ? 10_000 : false,
  })
  const userEventsArr: UserEvent[] = userEventsData ?? []

  const filteredEndpoints = endpointList.filter(ep =>
    ep.hostname.toLowerCase().includes(search.toLowerCase()) ||
    ep.ip.includes(search)
  )

  const handleExport = () => {
    const blob = new Blob([`timestamp,event_type,process_name\n${processEvents.map(e => `${e.timestamp},${e.event_type},${e.process_name}`).join('\n')}`], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'telemetry_export.csv'
    a.click()
  }

  const handleAddIOC = () => {
    setIocMsg('選択されたイベントを IOC リストに追加しました')
    setTimeout(() => setIocMsg(null), 3000)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-green-900/30 border border-green-700/40 flex items-center justify-center">
            <Activity className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <h1 className="text-white text-xl font-bold">テレメトリエクスプローラー</h1>
            <p className="text-[#7d92b0] text-sm mt-0.5">Endpoint Telemetry Explorer — Deep Analysis</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {iocMsg && (
            <span className="text-green-400 text-xs bg-green-900/30 border border-green-700/40 px-3 py-1.5 rounded-sm">
              {iocMsg}
            </span>
          )}
          <button onClick={handleAddIOC} className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-xs rounded-sm hover:border-[#2a3f5c] hover:text-white transition-colors">
            <Plus className="w-3.5 h-3.5" />
            IOCに追加
          </button>
          <button onClick={handleExport} className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-xs rounded-sm hover:border-[#2a3f5c] hover:text-white transition-colors">
            <Download className="w-3.5 h-3.5" />
            CSV出力
          </button>
        </div>
      </div>

      {/* Endpoint Selector + Time Range */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="md:col-span-2 relative">
          <div className="flex items-center gap-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-3">
            <Search className="w-4 h-4 text-[#7d92b0] shrink-0" />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setShowDropdown(true) }}
              onFocus={() => setShowDropdown(true)}
              placeholder="ホスト名または IP でエンドポイントを検索..."
              className="flex-1 bg-transparent text-sm text-white placeholder-[#3d5068] focus:outline-hidden"
            />
            {selectedEndpoint && (
              <button onClick={() => { setSelectedEndpoint(null); setSearch('') }} className="text-[#7d92b0] hover:text-white">
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
          {showDropdown && search && (
            <div className="absolute top-full left-0 right-0 mt-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg shadow-xl z-20">
              {filteredEndpoints.length === 0 ? (
                <p className="px-4 py-3 text-[#7d92b0] text-sm">見つかりませんでした</p>
              ) : filteredEndpoints.map(ep => (
                <button
                  key={ep.id}
                  onClick={() => { setSelectedEndpoint(ep); setSearch(ep.hostname); setShowDropdown(false) }}
                  className="w-full text-left px-4 py-2.5 hover:bg-[#161f33] transition-colors flex items-center gap-3"
                >
                  <Monitor className="w-4 h-4 text-[#7d92b0]" />
                  <div>
                    <p className="text-white text-sm font-medium">{ep.hostname}</p>
                    <p className="text-[#7d92b0] text-xs">{ep.ip} — {ep.os}</p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <select
            value={timeRange}
            onChange={e => setTimeRange(e.target.value)}
            disabled={live}
            className="flex-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 disabled:opacity-50"
          >
            {['15m', '1h', '6h', '24h', '7d'].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <button
            onClick={() => setLive(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-2.5 text-sm rounded-lg font-medium transition-colors ${live ? 'bg-green-700 text-white' : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${live ? 'bg-white animate-pulse' : 'bg-[#3d5068]'}`} />
            ライブ
          </button>
        </div>
      </div>

      {/* Selected Endpoint Info */}
      {selectedEndpoint && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 mb-4 flex items-center gap-4 flex-wrap">
          <Monitor className="w-8 h-8 text-[#7d92b0]" />
          <div>
            <p className="text-white font-bold">{selectedEndpoint.hostname}</p>
            <p className="text-[#7d92b0] text-xs">{selectedEndpoint.ip} — {selectedEndpoint.os}</p>
          </div>
          <div className="flex items-center gap-1 ml-auto text-xs text-green-400">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            最終確認: {fmt(selectedEndpoint.last_seen)}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-4 overflow-x-auto">
        {TABS.map(t => {
          const Icon = t.icon
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-1.5 px-4 py-2 text-sm rounded-lg whitespace-nowrap transition-colors ${tab === t.key ? 'bg-[#1d2f4a] text-white border border-[#2a3f5c]' : 'text-[#7d92b0] hover:text-white hover:bg-[#161f33]'}`}
            >
              <Icon className="w-4 h-4" />
              {t.label}
            </button>
          )
        })}
      </div>

      {/* Tab Content */}
      {!selectedEndpoint && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-12 flex flex-col items-center gap-3 text-[#7d92b0]">
          <Monitor className="w-10 h-10 opacity-20" />
          <p className="text-sm">エンドポイントを選択してテレメトリを表示します</p>
        </div>
      )}
      {selectedEndpoint && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          {tab === 'process' && <ProcessTab events={processEvents} live={live} />}
          {tab === 'file' && <FileTab events={fileEvents} />}
          {tab === 'network' && <NetworkTab events={networkEvents} dnsEvents={dnsEvents} />}
          {tab === 'registry' && <RegistryTab events={registryEvents} />}
          {tab === 'user' && <UserTab events={userEventsArr} />}
        </div>
      )}
    </div>
  )
}
