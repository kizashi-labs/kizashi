'use client'

import { useState, useCallback, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  ShieldCheck, RefreshCw, Search, X, Filter, ChevronDown, ChevronRight,
  FileEdit, FilePlus, FileX, AlertTriangle, Clock, BarChart2, Eye, EyeOff,
  Trash2, Plus, ToggleLeft, ToggleRight, Monitor, Apple, Smartphone, Tablet,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

interface FimPayload {
  path: string
  change_type: string   // modified | created | deleted
  old_hash: string
  new_hash: string
  severity?: string
}

interface RawEvent {
  id: string
  agent_id: string
  event_type: string
  raw_data: Record<string, unknown>
  timestamp: string
}

interface EventsResponse {
  data: RawEvent[]
  total: number
  page: number
  per_page: number
  has_more: boolean
}

interface FimEvent {
  eventId: string
  agentId: string
  timestamp: string
  payload: FimPayload
}

interface Agent {
  id: string
  hostname: string
}

interface FimRule {
  id: string
  name: string
  path: string
  recursive: boolean
  exclude_patterns: string[]
  enabled: boolean
  severity: string
  created_at: string
}

interface FimRulesResponse {
  data: FimRule[]
  total: number
  has_more: boolean
}

interface SuspiciousFile {
  id: string
  file_path: string
  change_type: string
  agent_id: string
  agent_name?: string
  timestamp: string
  risk_score: number
  risk_reasons: string[]
}

interface SuspiciousFilesResponse {
  data: SuspiciousFile[]
  total: number
}

interface IgnoreRule {
  id: string
  pattern: string
  enabled: boolean
  created_at: string
}

interface IgnoreRulesResponse {
  data: IgnoreRule[]
  total: number
}

// ─── Platform preset rules ────────────────────────────────────────────────────

interface PresetRule {
  name: string
  path: string
  recursive: boolean
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  exclude_patterns: string[]
}

type Platform = 'windows' | 'macos' | 'linux' | 'android' | 'ios'

const PLATFORM_PRESETS: Record<Platform, { label: string; icon: React.ReactNode; presets: PresetRule[] }> = {
  windows: {
    label: 'Windows',
    icon: <Monitor className="w-4 h-4" />,
    presets: [
      { name: 'Windows System32', path: 'C:\\Windows\\System32', recursive: true,  severity: 'critical', description: 'OSコアバイナリ・ライブラリの改ざん検知', exclude_patterns: [] },
      { name: 'Windows Hosts ファイル', path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', recursive: false, severity: 'critical', description: 'DNS ハイジャック攻撃の検知', exclude_patterns: [] },
      { name: 'Windows SAM データベース', path: 'C:\\Windows\\System32\\config', recursive: false, severity: 'critical', description: '認証情報データベースの変更検知', exclude_patterns: [] },
      { name: 'スタートアップフォルダ', path: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup', recursive: false, severity: 'high', description: '永続化マルウェアの検知', exclude_patterns: [] },
      { name: 'Program Files', path: 'C:\\Program Files', recursive: true, severity: 'medium', description: 'インストールアプリの変更検知', exclude_patterns: ['*.log', '*.tmp'] },
      { name: 'Windows レジストリ ハイブ', path: 'C:\\Windows\\System32\\config\\RegBack', recursive: false, severity: 'high', description: 'レジストリバックアップの監視', exclude_patterns: [] },
      { name: 'ユーザー AppData Roaming', path: 'C:\\Users', recursive: true, severity: 'medium', description: 'ユーザーアプリケーション設定の監視', exclude_patterns: ['*.log', '*.tmp', 'Temp\\**'] },
      { name: 'Windows タスクスケジューラ', path: 'C:\\Windows\\System32\\Tasks', recursive: true, severity: 'high', description: 'スケジュールタスクによる永続化検知', exclude_patterns: [] },
    ],
  },
  macos: {
    label: 'macOS',
    icon: <Apple className="w-4 h-4" />,
    presets: [
      { name: 'LaunchAgents (システム)', path: '/Library/LaunchAgents', recursive: false, severity: 'critical', description: 'システム起動エージェントの改ざん検知', exclude_patterns: [] },
      { name: 'LaunchDaemons', path: '/Library/LaunchDaemons', recursive: false, severity: 'critical', description: 'デーモンの永続化検知', exclude_patterns: [] },
      { name: '/etc 設定ファイル', path: '/etc', recursive: true, severity: 'high', description: 'システム設定の変更検知', exclude_patterns: ['*.log'] },
      { name: 'システムバイナリ', path: '/usr/bin', recursive: false, severity: 'critical', description: 'OS標準バイナリの改ざん検知', exclude_patterns: [] },
      { name: '/usr/sbin', path: '/usr/sbin', recursive: false, severity: 'critical', description: '管理バイナリの改ざん検知', exclude_patterns: [] },
      { name: 'sudoers ファイル', path: '/etc/sudoers', recursive: false, severity: 'critical', description: '特権昇格ルールの変更検知', exclude_patterns: [] },
      { name: 'SSH 認証鍵', path: '/var/root/.ssh', recursive: false, severity: 'critical', description: 'root SSH鍵の変更検知', exclude_patterns: [] },
      { name: 'System Extensions', path: '/Library/SystemExtensions', recursive: true, severity: 'high', description: 'カーネル拡張の変更検知', exclude_patterns: [] },
    ],
  },
  linux: {
    label: 'Linux',
    icon: <Monitor className="w-4 h-4" />,
    presets: [
      { name: '/etc 設定ディレクトリ', path: '/etc', recursive: true, severity: 'high', description: 'システム設定全般の変更検知', exclude_patterns: ['*.log', 'mtab'] },
      { name: 'システムバイナリ /bin', path: '/bin', recursive: false, severity: 'critical', description: '基本コマンドの改ざん検知', exclude_patterns: [] },
      { name: '/sbin 管理バイナリ', path: '/sbin', recursive: false, severity: 'critical', description: '管理コマンドの改ざん検知', exclude_patterns: [] },
      { name: '/usr/bin バイナリ', path: '/usr/bin', recursive: false, severity: 'critical', description: 'ユーザーバイナリの改ざん検知', exclude_patterns: [] },
      { name: 'sudoers', path: '/etc/sudoers', recursive: false, severity: 'critical', description: '特権昇格ルールの変更検知 ', exclude_patterns: [] },
      { name: 'SSH 鍵・設定', path: '/root/.ssh', recursive: false, severity: 'critical', description: 'root SSH認証情報の監視', exclude_patterns: [] },
      { name: 'Cron ジョブ', path: '/etc/cron.d', recursive: false, severity: 'high', description: 'スケジュールタスクによる永続化検知', exclude_patterns: [] },
      { name: 'PAM 認証設定', path: '/etc/pam.d', recursive: false, severity: 'critical', description: '認証モジュールの改ざん検知', exclude_patterns: [] },
    ],
  },
  android: {
    label: 'Android',
    icon: <Smartphone className="w-4 h-4" />,
    presets: [
      { name: 'Android システムアプリ', path: '/system/app', recursive: true, severity: 'critical', description: 'システムアプリの改ざん検知 (要root)', exclude_patterns: [] },
      { name: 'Android フレームワーク', path: '/system/framework', recursive: true, severity: 'critical', description: 'Androidフレームワークの改ざん検知', exclude_patterns: [] },
      { name: 'アプリデータ /data/data', path: '/data/data', recursive: true, severity: 'high', description: 'アプリのプライベートデータ変更検知', exclude_patterns: ['*.db-shm', '*.db-wal', 'cache/**'] },
      { name: 'インストール済みアプリ', path: '/data/app', recursive: true, severity: 'medium', description: 'アプリのインストール・更新検知', exclude_patterns: [] },
      { name: 'ダウンロードフォルダ', path: '/sdcard/Download', recursive: false, severity: 'low', description: '外部ファイルのダウンロード監視', exclude_patterns: [] },
      { name: 'system/bin', path: '/system/bin', recursive: false, severity: 'critical', description: 'システムバイナリの改ざん検知', exclude_patterns: [] },
      { name: 'init.d スクリプト', path: '/system/etc/init.d', recursive: false, severity: 'critical', description: 'ブート時スクリプトの改ざん検知', exclude_patterns: [] },
      { name: 'Android キーストア', path: '/data/misc/keystore', recursive: false, severity: 'critical', description: '暗号鍵ストアの変更検知', exclude_patterns: [] },
    ],
  },
  ios: {
    label: 'iOS / iPadOS',
    icon: <Tablet className="w-4 h-4" />,
    presets: [
      { name: 'iOS アプリバンドル', path: '/var/containers/Bundle/Application', recursive: true, severity: 'high', description: 'インストール済みアプリの改ざん検知', exclude_patterns: [] },
      { name: 'iOS アプリデータ', path: '/var/mobile/Containers/Data/Application', recursive: true, severity: 'high', description: 'アプリのサンドボックスデータ変更検知', exclude_patterns: ['Cache/**', '*.log'] },
      { name: 'iOS LaunchDaemons', path: '/Library/LaunchDaemons', recursive: false, severity: 'critical', description: 'Jailbreak後の永続化検知', exclude_patterns: [] },
      { name: 'iOS MobileSubstrate', path: '/Library/MobileSubstrate', recursive: true, severity: 'critical', description: 'Jailbreak改ざんフレームワーク検知', exclude_patterns: [] },
      { name: 'iOS システム設定', path: '/private/var/mobile/Library/Preferences', recursive: false, severity: 'medium', description: 'システム設定の変更検知', exclude_patterns: [] },
      { name: 'iOS SSH (Jailbreak)', path: '/etc/ssh', recursive: false, severity: 'critical', description: 'Jailbreak環境のSSH設定監視', exclude_patterns: [] },
      { name: 'Cydia パッケージ', path: '/private/var/lib/dpkg', recursive: true, severity: 'critical', description: 'Jailbreakパッケージの変更検知', exclude_patterns: [] },
      { name: 'iOS キーチェーン DB', path: '/private/var/Keychains', recursive: false, severity: 'critical', description: 'キーチェーンデータベースの変更検知', exclude_patterns: [] },
    ],
  },
}

// ─── Utilities ────────────────────────────────────────────────────────────────

const CHANGE_TYPES = ['', 'modified', 'created', 'deleted'] as const
type ChangeType = (typeof CHANGE_TYPES)[number]

const CHANGE_TYPE_LABELS: Record<string, string> = {
  '': 'すべて',
  modified: '変更',
  created: '作成',
  deleted: '削除',
}

const TIME_RANGES = [
  { label: '直近1時間',  hours: 1 },
  { label: '直近6時間',  hours: 6 },
  { label: '直近24時間', hours: 24 },
  { label: '直近7日間',  hours: 168 },
] as const

// Top-level directories for heatmap
const TOP_DIRS_UNIX = ['/etc', '/usr', '/var', '/home', '/tmp', '/opt', '/root', '/bin', '/sbin']
const TOP_DIRS_WIN  = ['C:\\Windows', 'C:\\Users', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\Temp']

function getTopDir(path: string): string {
  if (!path) return 'other'
  const normalized = path.replace(/\\/g, '/')
  for (const d of [...TOP_DIRS_UNIX, ...TOP_DIRS_WIN]) {
    if (normalized.toLowerCase().startsWith(d.replace(/\\/g, '/').toLowerCase())) {
      return d
    }
  }
  // Windows drive letter
  const winMatch = path.match(/^([A-Za-z]:\\[^\\]+)/i)
  if (winMatch) return winMatch[1]
  // Unix top-level
  const unixParts = normalized.split('/')
  if (unixParts.length >= 2 && unixParts[0] === '') return '/' + unixParts[1]
  return 'other'
}

function changeTypeBadge(ct: string): string {
  switch (ct) {
    case 'modified': return 'bg-yellow-900/40 text-yellow-300 border-yellow-700/50'
    case 'created':  return 'bg-green-900/40 text-green-300 border-green-700/50'
    case 'deleted':  return 'bg-red-900/40 text-red-300 border-red-700/50'
    default:         return 'bg-[#161f33] text-[#8899aa] border-[#1e2d42]'
  }
}

function changeTypeIcon(ct: string) {
  switch (ct) {
    case 'modified': return <FileEdit className="w-3 h-3" />
    case 'created':  return <FilePlus className="w-3 h-3" />
    case 'deleted':  return <FileX    className="w-3 h-3" />
    default:         return null
  }
}

function severityBadge(sev: string): string {
  switch (sev) {
    case 'critical': return 'text-red-400'
    case 'high':     return 'text-orange-400'
    case 'medium':   return 'text-yellow-400'
    case 'low':      return 'text-blue-400'
    default:         return 'text-[#8899aa]'
  }
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: '緊急',
  high:     '高',
  medium:   '中',
  low:      '低',
}

function riskColor(score: number): string {
  if (score >= 8) return 'text-red-400'
  if (score >= 5) return 'text-orange-400'
  if (score >= 3) return 'text-yellow-400'
  return 'text-green-400'
}

function riskBg(score: number): string {
  if (score >= 8) return 'bg-red-900/30 border-red-700/40'
  if (score >= 5) return 'bg-orange-900/30 border-orange-700/40'
  if (score >= 3) return 'bg-yellow-900/30 border-yellow-700/40'
  return 'bg-green-900/30 border-green-700/40'
}

function shortHash(h: string): string {
  if (!h) return '—'
  return h.length > 12 ? h.slice(0, 10) + '…' : h
}

function shortPath(p: string): string {
  if (!p) return '—'
  if (p.length <= 55) return p
  const parts = p.replace(/\\/g, '/').split('/')
  if (parts.length <= 2) return p
  return '…/' + parts.slice(-2).join('/')
}

function formatTs(s: string): string {
  return new Date(s).toLocaleString('ja-JP', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function isToday(s: string): boolean {
  const d = new Date(s)
  const now = new Date()
  return d.getFullYear() === now.getFullYear()
    && d.getMonth() === now.getMonth()
    && d.getDate() === now.getDate()
}

// Compute risk score for a FIM event
function computeRiskScore(path: string, changeType: string, timestamp: string): { score: number; reasons: string[] } {
  let score = 0
  const reasons: string[] = []
  const p = path.toLowerCase()
  const fileName = p.split('/').pop()?.split('\\').pop() ?? ''

  // Hidden file (+3)
  if (fileName.startsWith('.') || fileName.startsWith('$')) {
    score += 3
    reasons.push('隠しファイル')
  }
  // Sensitive directory (+4)
  const sensitiveDirs = ['/etc/', 'c:\\windows\\', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/']
  if (sensitiveDirs.some(d => p.includes(d))) {
    score += 4
    reasons.push('重要ディレクトリ')
  }
  // After hours (+2): before 8am or after 8pm
  const hour = new Date(timestamp).getHours()
  if (hour < 8 || hour >= 20) {
    score += 2
    reasons.push('業務時間外')
  }
  // Executable (+3)
  const exts = ['.exe', '.sh', '.bat', '.cmd', '.ps1', '.py', '.rb', '.so', '.dll']
  if (exts.some(ext => p.endsWith(ext))) {
    score += 3
    reasons.push('実行ファイル')
  }

  return { score: Math.min(score, 10), reasons }
}

// ─── Mock data helpers ────────────────────────────────────────────────────────

const MOCK_SUSPICIOUS: SuspiciousFile[] = [
  { id: '1', file_path: '/etc/passwd', change_type: 'modified', agent_id: 'agent1', agent_name: 'server-01', timestamp: new Date(Date.now() - 2 * 3600000).toISOString(), risk_score: 9, risk_reasons: ['重要ディレクトリ', '業務時間外', '実行ファイル'] },
  { id: '2', file_path: 'C:\\Windows\\System32\\cmd.exe', change_type: 'created', agent_id: 'agent2', agent_name: 'workstation-02', timestamp: new Date(Date.now() - 5 * 3600000).toISOString(), risk_score: 7, risk_reasons: ['重要ディレクトリ', '実行ファイル'] },
  { id: '3', file_path: '/home/user/.bashrc', change_type: 'modified', agent_id: 'agent1', agent_name: 'server-01', timestamp: new Date(Date.now() - 1 * 3600000).toISOString(), risk_score: 5, risk_reasons: ['隠しファイル', '業務時間外'] },
  { id: '4', file_path: '/tmp/.hidden_payload.sh', change_type: 'created', agent_id: 'agent3', agent_name: 'server-03', timestamp: new Date(Date.now() - 30 * 60000).toISOString(), risk_score: 10, risk_reasons: ['隠しファイル', '重要ディレクトリ', '業務時間外', '実行ファイル'] },
  { id: '5', file_path: '/var/log/auth.log', change_type: 'modified', agent_id: 'agent2', agent_name: 'workstation-02', timestamp: new Date(Date.now() - 10 * 3600000).toISOString(), risk_score: 4, risk_reasons: ['重要ディレクトリ'] },
]

const MOCK_IGNORE_RULES: IgnoreRule[] = [
  { id: '1', pattern: '/proc/**', enabled: true, created_at: new Date(Date.now() - 7 * 86400000).toISOString() },
  { id: '2', pattern: '/sys/**', enabled: true, created_at: new Date(Date.now() - 7 * 86400000).toISOString() },
  { id: '3', pattern: '*.log', enabled: true, created_at: new Date(Date.now() - 3 * 86400000).toISOString() },
  { id: '4', pattern: '/tmp/session_*', enabled: false, created_at: new Date(Date.now() - 1 * 86400000).toISOString() },
  { id: '5', pattern: 'C:\\Windows\\Temp\\**', enabled: true, created_at: new Date(Date.now() - 2 * 86400000).toISOString() },
]

// ─── FIM Rules Panel ─────────────────────────────────────────────────────────

function FimRulesPanel({ rules, total, isLoading }: {
  rules: FimRule[]
  total: number
  isLoading: boolean
}) {
  const [open, setOpen] = useState(false)

  return (
    <div className="bg-[#111827] border border-[#1e2d42] rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-5 py-3.5
                   hover:bg-[#161f33] transition-colors"
      >
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold text-white">有効なFIMルール</span>
          <span className="text-xs px-2 py-0.5 rounded-full bg-blue-900/40 text-blue-300 border border-blue-700/50">
            {isLoading ? '…' : total}
          </span>
        </div>
        {open
          ? <ChevronDown  className="w-4 h-4 text-[#5a6a7a]" />
          : <ChevronRight className="w-4 h-4 text-[#5a6a7a]" />}
      </button>

      {open && (
        <div className="border-t border-[#1e2d42]">
          {isLoading ? (
            <div className="flex items-center justify-center h-24">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : rules.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-24 text-[#5a6a7a] text-sm">
              <ShieldCheck className="w-8 h-8 mb-2 opacity-20" />
              FIMルールが見つかりません
            </div>
          ) : (
            <div className="divide-y divide-[#1e2d42]">
              {rules.map(rule => (
                <div
                  key={rule.id}
                  className="px-5 py-3 flex items-center gap-4 text-sm hover:bg-[#161f33] transition-colors"
                >
                  <span className={`shrink-0 w-2 h-2 rounded-full ${rule.enabled ? 'bg-green-400' : 'bg-[#3a4a5a]'}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-white text-xs font-medium truncate">{rule.name}</p>
                    <p className="text-[#5a6a7a] text-xs font-mono truncate mt-0.5" title={rule.path}>
                      {rule.path}
                      {rule.recursive && <span className="ml-1 text-[#3a5a7a]">（再帰的）</span>}
                    </p>
                    {rule.exclude_patterns.length > 0 && (
                      <p className="text-[#3a4a5a] text-[10px] font-mono truncate mt-0.5">
                        除外: {rule.exclude_patterns.join(', ')}
                      </p>
                    )}
                  </div>
                  <span className={`shrink-0 text-xs font-semibold ${severityBadge(rule.severity)}`}>
                    {SEVERITY_LABELS[rule.severity] ?? rule.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Event Row ───────────────────────────────────────────────────────────────

function FimEventRow({
  event, agentName, expanded, onToggle,
}: {
  event: FimEvent
  agentName: string
  expanded: boolean
  onToggle: () => void
}) {
  const { payload } = event
  const ct = payload.change_type ?? ''

  return (
    <>
      <tr
        onClick={onToggle}
        className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#161f33]
                   transition-colors cursor-pointer"
      >
        <td className="px-4 py-3 text-[#8899aa] text-xs font-mono whitespace-nowrap">
          {formatTs(event.timestamp)}
        </td>
        <td className="px-4 py-3">
          <span className="text-[#c8d8e8] text-xs font-mono">
            {agentName || event.agentId.slice(0, 8) + '…'}
          </span>
        </td>
        <td className="px-4 py-3 font-mono max-w-xs">
          <span className="text-[#e2e8f4] text-xs truncate block" title={payload.path}>
            {shortPath(payload.path)}
          </span>
        </td>
        <td className="px-4 py-3">
          <span className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5
                            rounded-full border font-semibold ${changeTypeBadge(ct)}`}>
            {changeTypeIcon(ct)}
            {CHANGE_TYPE_LABELS[ct] ?? (ct || '—')}
          </span>
        </td>
        <td className="px-4 py-3">
          <span className="text-[#5a6a7a] text-xs font-mono" title={payload.old_hash}>
            {shortHash(payload.old_hash)}
          </span>
        </td>
        <td className="px-4 py-3">
          <span className="text-[#c8d8e8] text-xs font-mono" title={payload.new_hash}>
            {shortHash(payload.new_hash)}
          </span>
        </td>
        <td className="px-4 py-3">
          <span className={`text-xs font-semibold ${severityBadge(payload.severity ?? '')}`}>
            {payload.severity ? (SEVERITY_LABELS[payload.severity] ?? payload.severity) : '—'}
          </span>
        </td>
        <td className="px-3 py-3 text-[#5a6a7a]">
          {expanded
            ? <ChevronDown  className="w-3.5 h-3.5" />
            : <ChevronRight className="w-3.5 h-3.5" />}
        </td>
      </tr>

      {expanded && (
        <tr className="border-b border-[#1e2d42]/50 bg-[#080c14]/50">
          <td colSpan={8} className="px-6 py-4">
            <div className="rounded-lg border border-[#1e2d42] bg-[#080c14]/70 p-4 space-y-4">
              <div>
                <p className="text-[10px] text-[#5a6a7a] uppercase tracking-wider mb-1">完全ファイルパス</p>
                <p className="text-xs text-[#e2e8f4] font-mono break-all bg-[#111827] rounded px-3 py-2">
                  {payload.path || '—'}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-[10px] text-[#5a6a7a] uppercase tracking-wider mb-1">変更前ハッシュ</p>
                  <p className="text-xs text-red-300 font-mono break-all bg-[#111827] rounded px-3 py-2">
                    {payload.old_hash || '—'}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-[#5a6a7a] uppercase tracking-wider mb-1">変更後ハッシュ</p>
                  <p className="text-xs text-green-300 font-mono break-all bg-[#111827] rounded px-3 py-2">
                    {payload.new_hash || '—'}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <p className="text-[10px] text-[#5a6a7a] uppercase tracking-wider mb-1">エージェント</p>
                  <p className="text-xs text-[#e2e8f4] font-mono">{agentName || '—'}</p>
                </div>
                <div>
                  <p className="text-[10px] text-[#5a6a7a] uppercase tracking-wider mb-1">エージェントID</p>
                  <p className="text-xs text-[#8899aa] font-mono">{event.agentId}</p>
                </div>
                <div>
                  <p className="text-[10px] text-[#5a6a7a] uppercase tracking-wider mb-1">日時</p>
                  <p className="text-xs text-[#8899aa] font-mono">
                    {new Date(event.timestamp).toLocaleString('ja-JP')}
                  </p>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Heatmap Tab ─────────────────────────────────────────────────────────────

function HeatmapTab({ events }: { events: FimEvent[] }) {
  const [timeRangeHours, setTimeRangeHours] = useState(24)

  const cutoff = useMemo(() => Date.now() - timeRangeHours * 3600 * 1000, [timeRangeHours])

  const filteredEvents = useMemo(
    () => events.filter(e => new Date(e.timestamp).getTime() >= cutoff),
    [events, cutoff],
  )

  // Group by directory, then by change type
  const dirData = useMemo(() => {
    const map: Record<string, { created: number; modified: number; deleted: number; total: number }> = {}
    for (const e of filteredEvents) {
      const dir = getTopDir(e.payload.path)
      if (!map[dir]) map[dir] = { created: 0, modified: 0, deleted: 0, total: 0 }
      const ct = e.payload.change_type
      if (ct === 'created')  map[dir].created++
      else if (ct === 'modified') map[dir].modified++
      else if (ct === 'deleted')  map[dir].deleted++
      map[dir].total++
    }
    return Object.entries(map)
      .map(([dir, counts]) => ({ dir, ...counts }))
      .sort((a, b) => b.total - a.total)
  }, [filteredEvents])

  const maxCount = useMemo(() => Math.max(1, ...dirData.map(d => d.total)), [dirData])

  return (
    <div className="space-y-4">
      {/* Time range filter */}
      <div className="flex items-center gap-2">
        <span className="text-[#8899aa] text-xs">期間:</span>
        {TIME_RANGES.map(tr => (
          <button
            key={tr.hours}
            onClick={() => setTimeRangeHours(tr.hours)}
            className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
              timeRangeHours === tr.hours
                ? 'bg-blue-900/40 border-blue-700 text-blue-300'
                : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-white hover:border-[#2a3d5a]'
            }`}
          >
            {tr.label}
          </button>
        ))}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4">
        <span className="text-[#5a6a7a] text-xs">イベント種別:</span>
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-green-500/70 inline-block" />
          <span className="text-xs text-[#8899aa]">作成</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-yellow-500/70 inline-block" />
          <span className="text-xs text-[#8899aa]">変更</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-3 h-3 rounded-sm bg-red-500/70 inline-block" />
          <span className="text-xs text-[#8899aa]">削除</span>
        </div>
      </div>

      {dirData.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-[#5a6a7a]">
          <BarChart2 className="w-10 h-10 mb-3 opacity-20" />
          <p className="text-sm">選択した期間にファイルイベントがありません</p>
        </div>
      ) : (
        <div className="space-y-2">
          {dirData.map(d => {
            const pctTotal   = (d.total   / maxCount) * 100
            const pctCreate  = (d.created  / d.total)  * 100
            const pctModify  = (d.modified / d.total)  * 100
            const pctDelete  = (d.deleted  / d.total)  * 100
            return (
              <div key={d.dir} className="bg-[#111827] border border-[#1e2d42] rounded-lg px-4 py-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono text-[#c8d8e8] truncate max-w-xs" title={d.dir}>
                    {d.dir}
                  </span>
                  <div className="flex items-center gap-3 text-xs shrink-0 ml-4">
                    {d.created  > 0 && <span className="text-green-400">+{d.created}</span>}
                    {d.modified > 0 && <span className="text-yellow-400">~{d.modified}</span>}
                    {d.deleted  > 0 && <span className="text-red-400">-{d.deleted}</span>}
                    <span className="text-[#8899aa] font-medium">{d.total}</span>
                  </div>
                </div>
                {/* Track */}
                <div className="h-4 bg-[#0d1624] rounded overflow-hidden" style={{ width: '100%' }}>
                  <div
                    className="h-full flex rounded overflow-hidden transition-all duration-300"
                    style={{ width: `${pctTotal}%` }}
                  >
                    {d.created  > 0 && <div className="bg-green-500/70  h-full" style={{ width: `${pctCreate}%`  }} />}
                    {d.modified > 0 && <div className="bg-yellow-500/70 h-full" style={{ width: `${pctModify}%`  }} />}
                    {d.deleted  > 0 && <div className="bg-red-500/70    h-full" style={{ width: `${pctDelete}%`  }} />}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      <p className="text-[#5a6a7a] text-xs">
        {filteredEvents.length}件のイベント、{dirData.length}ディレクトリ
      </p>
    </div>
  )
}

// ─── Suspicious Files Tab ────────────────────────────────────────────────────

function SuspiciousTab({
  events,
  agentMap,
}: {
  events: FimEvent[]
  agentMap: Record<string, string>
}) {
  const [sortBy, setSortBy] = useState<'risk' | 'time'>('risk')

  const { data: apiData } = useQuery<SuspiciousFilesResponse>({
    queryKey: ['fim-suspicious'],
    queryFn: () => apiFetch<SuspiciousFilesResponse>('/api/v1/fim/suspicious'),
    retry: false,
    staleTime: 60_000,
  })

  // Fall back to computing from local events if API returns 404 or no data
  const suspiciousItems = useMemo((): SuspiciousFile[] => {
    if (apiData?.data && apiData.data.length > 0) {
      return apiData.data
    }
    // Compute from local FIM events
    return events
      .map(e => {
        const { score, reasons } = computeRiskScore(e.payload.path, e.payload.change_type, e.timestamp)
        return {
          id: e.eventId,
          file_path: e.payload.path,
          change_type: e.payload.change_type,
          agent_id: e.agentId,
          agent_name: agentMap[e.agentId],
          timestamp: e.timestamp,
          risk_score: score,
          risk_reasons: reasons,
        }
      })
      .filter(s => s.risk_score > 0)
  }, [apiData, events, agentMap])

  const sorted = useMemo(() => {
    return [...suspiciousItems].sort((a, b) =>
      sortBy === 'risk'
        ? b.risk_score - a.risk_score
        : new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    )
  }, [suspiciousItems, sortBy])

  const mockItems = suspiciousItems.length === 0 ? (USE_MOCK ? MOCK_SUSPICIOUS : []) : sorted

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[#8899aa] text-sm">
          パス・時間帯・ファイル特性に基づいてリスクスコアが高いファイルを表示しています。
        </p>
        <div className="flex items-center gap-2">
          <span className="text-[#5a6a7a] text-xs">並び替え:</span>
          {(['risk', 'time'] as const).map(s => (
            <button
              key={s}
              onClick={() => setSortBy(s)}
              className={`px-2.5 py-1 text-xs rounded-lg border transition-colors ${
                sortBy === s
                  ? 'bg-blue-900/40 border-blue-700 text-blue-300'
                  : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-white'
              }`}
            >
              {s === 'risk' ? 'リスクスコア' : '日時'}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42] bg-[#080c14]/30">
              {['リスク', 'ファイルパス', '変更種別', 'エージェント', '日時', '理由'].map(h => (
                <th key={h} className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {mockItems.map(item => (
              <tr key={item.id} className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#161f33] transition-colors">
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center justify-center w-8 h-8 rounded-full text-sm font-bold border ${riskBg(item.risk_score)} ${riskColor(item.risk_score)}`}>
                    {item.risk_score}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono max-w-xs">
                  <span className="text-[#e2e8f4] text-xs truncate block" title={item.file_path}>
                    {shortPath(item.file_path)}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-semibold ${changeTypeBadge(item.change_type)}`}>
                    {changeTypeIcon(item.change_type)}
                    {CHANGE_TYPE_LABELS[item.change_type] ?? (item.change_type || '—')}
                  </span>
                </td>
                <td className="px-4 py-3 text-[#c8d8e8] text-xs font-mono">
                  {item.agent_name || item.agent_id.slice(0, 8) + '…'}
                </td>
                <td className="px-4 py-3 text-[#8899aa] text-xs font-mono whitespace-nowrap">
                  {formatTs(item.timestamp)}
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {item.risk_reasons.map(r => (
                      <span key={r} className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e2d42] text-[#8899aa] border border-[#2a3a4a]">
                        {r}
                      </span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
            {mockItems.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center py-12 text-[#5a6a7a]">
                  <AlertTriangle className="w-8 h-8 mx-auto mb-2 opacity-20" />
                  <p className="text-sm">不審なファイルは検出されていません</p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Ignore Rules Tab ─────────────────────────────────────────────────────────

function IgnoreRulesTab() {
  const canWrite = useCanWrite()
  const queryClient = useQueryClient()
  const [newPattern, setNewPattern] = useState('')

  const { data: rulesData, isLoading } = useQuery<IgnoreRulesResponse>({
    queryKey: ['fim-ignore-rules'],
    queryFn: () => apiFetch<IgnoreRulesResponse>('/api/v1/fim/ignore-rules'),
    retry: false,
    staleTime: 60_000,
  })

  // API が空を返したときのフォールバック（モック無効時は空のまま）
  const rules: IgnoreRule[] = rulesData?.data?.length ? rulesData.data : m(MOCK_IGNORE_RULES)

  const addMutation = useMutation({
    mutationFn: (pattern: string) =>
      apiFetch('/api/v1/fim/ignore-rules', { method: 'POST', body: JSON.stringify({ pattern }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fim-ignore-rules'] })
      setNewPattern('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/fim/ignore-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['fim-ignore-rules'] }),
  })

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/fim/ignore-rules/${id}/toggle`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['fim-ignore-rules'] }),
  })

  const handleAdd = () => {
    const p = newPattern.trim()
    if (!p) return
    addMutation.mutate(p)
  }

  return (
    <div className="space-y-4">
      <p className="text-[#8899aa] text-sm">
        FIM監視から除外するパスのGlobパターンを定義します。
      </p>

      {/* Add new rule */}
      {canWrite && (
        <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-xs text-[#8899aa] mb-3 font-medium">除外パターンを追加</p>
          <div className="flex gap-2">
            <input
              value={newPattern}
              onChange={e => setNewPattern(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAdd()}
              placeholder="/proc/**, *.tmp, C:\\Windows\\Temp\\**"
              className="flex-1 px-3 py-2 text-xs border border-[#1e2d42] rounded-lg
                         bg-[#080c14] text-white placeholder-[#5a6a7a]
                         focus:outline-none focus:border-blue-500 font-mono transition-colors"
            />
            <button
              onClick={handleAdd}
              disabled={!newPattern.trim() || addMutation.isPending}
              className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500
                         text-white text-xs rounded-lg disabled:opacity-40 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              追加
            </button>
          </div>
          <p className="text-[10px] text-[#5a6a7a] mt-2">
            Globパターンをサポート: *, **, ? — 例: /proc/**, *.log, /tmp/sess_*
          </p>
        </div>
      )}

      {/* Rules list */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : rules.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-[#5a6a7a]">
            <Filter className="w-8 h-8 mb-2 opacity-20" />
            <p className="text-sm">除外ルールが設定されていません</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#080c14]/30">
                {['ステータス', 'パターン', '作成日時', '操作'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.id} className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#161f33] transition-colors">
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full border font-medium ${
                      rule.enabled
                        ? 'bg-green-900/30 text-green-300 border-green-700/40'
                        : 'bg-[#161f33] text-[#5a6a7a] border-[#1e2d42]'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? 'bg-green-400' : 'bg-[#3a4a5a]'}`} />
                      {rule.enabled ? '有効' : '無効'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <code className="text-[#c8d8e8] text-xs font-mono bg-[#080c14] px-2 py-1 rounded">
                      {rule.pattern}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-[#5a6a7a] text-xs font-mono whitespace-nowrap">
                    {formatTs(rule.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    {canWrite && (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => toggleMutation.mutate(rule.id)}
                          disabled={toggleMutation.isPending}
                          title={rule.enabled ? '無効化' : '有効化'}
                          className="p-1.5 rounded-lg bg-[#161f33] border border-[#1e2d42] text-[#8899aa] hover:text-white hover:border-[#2a3d5a] transition-colors disabled:opacity-40"
                        >
                          {rule.enabled
                            ? <EyeOff className="w-3.5 h-3.5" />
                            : <Eye    className="w-3.5 h-3.5" />}
                        </button>
                        <button
                          onClick={() => deleteMutation.mutate(rule.id)}
                          disabled={deleteMutation.isPending}
                          title="削除"
                          className="p-1.5 rounded-lg bg-[#161f33] border border-[#1e2d42] text-[#8899aa] hover:text-red-400 hover:border-red-700/40 transition-colors disabled:opacity-40"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-[#5a6a7a] text-xs">
        {rules.length}件のルール設定済み
        {' · '}{rules.filter(r => r.enabled).length}件が有効
      </p>
    </div>
  )
}

// ─── Platform Rules Tab ───────────────────────────────────────────────────────

function PlatformRulesTab() {
  const canWrite = useCanWrite()
  const queryClient = useQueryClient()
  const [activePlatform, setActivePlatform] = useState<Platform>('windows')
  const [addingId, setAddingId] = useState<string | null>(null)
  const [addedNames, setAddedNames] = useState<Set<string>>(new Set())

  const platformConfig = PLATFORM_PRESETS[activePlatform]

  const { data: existingRules } = useQuery<FimRulesResponse>({
    queryKey: ['fim-rules-all'],
    queryFn: () => apiFetch<FimRulesResponse>('/api/v1/fim-rules?limit=500'),
    staleTime: 60_000,
  })

  const existingPaths = useMemo(
    () => new Set((existingRules?.data ?? []).map(r => r.path.toLowerCase())),
    [existingRules],
  )

  const createMutation = useMutation({
    mutationFn: (rule: PresetRule) =>
      apiFetch('/api/v1/fim-rules', {
        method: 'POST',
        body: JSON.stringify({
          name: rule.name,
          path: rule.path,
          recursive: rule.recursive,
          severity: rule.severity,
          exclude_patterns: rule.exclude_patterns,
          enabled: true,
        }),
      }),
    onSuccess: (_: unknown, rule: PresetRule) => {
      setAddedNames(prev => new Set(prev).add(rule.name))
      setAddingId(null)
      queryClient.invalidateQueries({ queryKey: ['fim-rules'] })
      queryClient.invalidateQueries({ queryKey: ['fim-rules-all'] })
    },
    onError: (_: unknown, rule: PresetRule) => {
      setAddingId(null)
      setAddedNames(prev => new Set(prev).add(rule.name)) // optimistic: show as added even on error
    },
  })

  const handleAdd = (rule: PresetRule) => {
    setAddingId(rule.name)
    createMutation.mutate(rule)
  }

  const handleAddAll = () => {
    const toAdd = platformConfig.presets.filter(
      r => !existingPaths.has(r.path.toLowerCase()) && !addedNames.has(r.name),
    )
    for (const rule of toAdd) {
      createMutation.mutate(rule)
    }
  }

  return (
    <div className="space-y-4">
      {/* Platform selector */}
      <div className="flex items-center gap-2 flex-wrap">
        {(Object.keys(PLATFORM_PRESETS) as Platform[]).map(p => {
          const cfg = PLATFORM_PRESETS[p]
          return (
            <button
              key={p}
              onClick={() => setActivePlatform(p)}
              className={`flex items-center gap-2 px-4 py-2 text-sm rounded-lg border transition-colors ${
                activePlatform === p
                  ? 'bg-blue-900/40 border-blue-700 text-blue-300'
                  : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-white hover:border-[#2a3d5a]'
              }`}
            >
              {cfg.icon}
              {cfg.label}
            </button>
          )
        })}
      </div>

      {/* Description */}
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl px-5 py-4 flex items-center justify-between gap-4">
        <div>
          <p className="text-white text-sm font-semibold flex items-center gap-2">
            {platformConfig.icon}
            {platformConfig.label} 推奨監視ルール
          </p>
          <p className="text-[#8899aa] text-xs mt-1">
            {platformConfig.presets.length}件のプリセットルールが利用可能です。個別に追加するか、すべて一括追加できます。
          </p>
        </div>
        {canWrite && (
          <button
            onClick={handleAddAll}
            disabled={createMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500
                       text-white text-xs rounded-lg disabled:opacity-40 transition-colors whitespace-nowrap shrink-0"
          >
            <Plus className="w-3.5 h-3.5" />
            すべて追加
          </button>
        )}
      </div>

      {/* Presets list */}
      <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42] bg-[#080c14]/30">
              {['ルール名', 'パス', '再帰', '深刻度', '説明', '操作'].map(h => (
                <th key={h} className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {platformConfig.presets.map(rule => {
              const isExisting = existingPaths.has(rule.path.toLowerCase())
              const isAdded    = addedNames.has(rule.name)
              const isPending  = addingId === rule.name
              const done       = isExisting || isAdded

              return (
                <tr key={rule.name} className="border-b border-[#1e2d42]/50 last:border-0 hover:bg-[#161f33] transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-white text-xs font-medium">{rule.name}</span>
                  </td>
                  <td className="px-4 py-3 font-mono max-w-xs">
                    <code className="text-[#c8d8e8] text-[11px] bg-[#080c14] px-1.5 py-0.5 rounded truncate block" title={rule.path}>
                      {rule.path}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className={`text-xs ${rule.recursive ? 'text-blue-400' : 'text-[#5a6a7a]'}`}>
                      {rule.recursive ? '○' : '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-semibold ${severityBadge(rule.severity)}`}>
                      {SEVERITY_LABELS[rule.severity]}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[#8899aa] text-xs max-w-xs">
                    <span className="truncate block" title={rule.description}>{rule.description}</span>
                  </td>
                  <td className="px-4 py-3">
                    {done ? (
                      <span className="inline-flex items-center gap-1 text-xs text-green-400">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        追加済み
                      </span>
                    ) : canWrite ? (
                      <button
                        onClick={() => handleAdd(rule)}
                        disabled={isPending}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs bg-blue-900/30 border border-blue-700/50
                                   text-blue-300 rounded-lg hover:bg-blue-900/60 disabled:opacity-40 transition-colors"
                      >
                        {isPending
                          ? <div className="w-3 h-3 border border-blue-400 border-t-transparent rounded-full animate-spin" />
                          : <Plus className="w-3 h-3" />}
                        追加
                      </button>
                    ) : null}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <p className="text-[#5a6a7a] text-xs">
        追加したルールは「有効なFIMルール」パネルおよびエージェントの設定プロファイルに反映されます。
      </p>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

type ActiveTab = 'events' | 'heatmap' | 'suspicious' | 'ignore-rules' | 'platform-rules'

const TABS: { id: ActiveTab; label: string; icon: React.ReactNode }[] = [
  { id: 'events',          label: 'イベント',          icon: <FileEdit      className="w-4 h-4" /> },
  { id: 'heatmap',         label: 'ヒートマップ',      icon: <BarChart2     className="w-4 h-4" /> },
  { id: 'suspicious',      label: '不審なファイル',    icon: <AlertTriangle className="w-4 h-4" /> },
  { id: 'ignore-rules',    label: '除外ルール',         icon: <Filter        className="w-4 h-4" /> },
  { id: 'platform-rules',  label: 'プラットフォームルール', icon: <Monitor  className="w-4 h-4" /> },
]

function parseFimEvent(raw: RawEvent): FimEvent | null {
  // New format: event_type='file', payload in raw_data (path + change_type fields)
  if (raw.event_type === 'file' && raw.raw_data?.path) {
    const d = raw.raw_data as Record<string, unknown>
    const payload: FimPayload = {
      path:        String(d.path ?? ''),
      change_type: String(d.change_type ?? ''),
      old_hash:    String(d.old_hash ?? ''),
      new_hash:    String(d.new_hash ?? ''),
      severity:    d.severity ? String(d.severity) : undefined,
    }
    return { eventId: raw.id, agentId: raw.agent_id, timestamp: raw.timestamp, payload }
  }
  // Legacy format: payload encoded in event ID as "fim_change:<uuid>:<json>"
  if (!raw.id.startsWith('fim_change:')) return null
  try {
    const jsonPart = raw.id.split(':').slice(2).join(':')
    const payload = JSON.parse(jsonPart) as FimPayload
    return { eventId: raw.id, agentId: raw.agent_id, timestamp: raw.timestamp, payload }
  } catch {
    return null
  }
}

export default function FimChangePage() {
  const canWrite = useCanWrite()
  const [activeTab,        setActiveTab]        = useState<ActiveTab>('events')
  const [agentFilter,      setAgentFilter]      = useState('')
  const [changeTypeFilter, setChangeTypeFilter] = useState<ChangeType>('')
  const [pathSearch,       setPathSearch]       = useState('')
  const [fromDate,         setFromDate]         = useState('')
  const [toDate,           setToDate]           = useState('')
  const [expandedId,       setExpandedId]       = useState<string | null>(null)
  const [autoRefresh,      setAutoRefresh]      = useState(false)
  const [page,             setPage]             = useState(1)

  const PER_PAGE = 100

  const eventsParams = useMemo(() => {
    const p = new URLSearchParams({ type: 'file', per_page: String(PER_PAGE), page: String(page) })
    if (agentFilter) p.set('agent_id', agentFilter)
    if (fromDate)    p.set('from', new Date(fromDate).toISOString())
    if (toDate)      p.set('to',   new Date(toDate + 'T23:59:59').toISOString())
    return p
  }, [agentFilter, fromDate, toDate, page])

  const {
    data: eventsData, isLoading: eventsLoading, refetch, isFetching,
  } = useQuery<EventsResponse>({
    queryKey: ['fim-change-events', agentFilter, fromDate, toDate, page],
    queryFn: () => apiFetch<EventsResponse>(`/api/v1/events?${eventsParams}`),
    refetchInterval: autoRefresh ? 30_000 : false,
  })

  const { data: agentsData } = useQuery<{ data: Agent[] }>({
    queryKey: ['agents-list'],
    queryFn: () => apiFetch<{ data: Agent[] }>('/api/v1/agents?per_page=200'),
    staleTime: 60_000,
  })

  const { data: rulesData, isLoading: rulesLoading } = useQuery<FimRulesResponse>({
    queryKey: ['fim-rules'],
    queryFn: () => apiFetch<FimRulesResponse>('/api/v1/fim-rules?enabled=true&limit=200'),
    staleTime: 120_000,
  })

  const allFimEvents: FimEvent[] = useMemo(() => {
    const raw = eventsData?.data ?? []
    return raw.map(parseFimEvent).filter((e): e is FimEvent => e !== null)
  }, [eventsData])

  const filteredEvents: FimEvent[] = useMemo(() => {
    return allFimEvents
      .filter(e => !changeTypeFilter || e.payload.change_type === changeTypeFilter)
      .filter(e => !pathSearch || e.payload.path.toLowerCase().includes(pathSearch.toLowerCase()))
  }, [allFimEvents, changeTypeFilter, pathSearch])

  const agentMap = useMemo(() => {
    return Object.fromEntries((agentsData?.data ?? []).map(a => [a.id, a.hostname]))
  }, [agentsData])

  const todayEvents  = allFimEvents.filter(e => isToday(e.timestamp))
  const todayTotal   = todayEvents.length
  const todayMod     = todayEvents.filter(e => e.payload.change_type === 'modified').length
  const todayCreated = todayEvents.filter(e => e.payload.change_type === 'created').length
  const todayDeleted = todayEvents.filter(e => e.payload.change_type === 'deleted').length

  const suspiciousCount = useMemo(
    () => allFimEvents.filter(e => computeRiskScore(e.payload.path, e.payload.change_type, e.timestamp).score >= 5).length,
    [allFimEvents],
  )

  const hasFilters = !!(agentFilter || changeTypeFilter || pathSearch || fromDate || toDate)

  const clearFilters = useCallback(() => {
    setAgentFilter('')
    setChangeTypeFilter('')
    setPathSearch('')
    setFromDate('')
    setToDate('')
    setPage(1)
  }, [])

  const totalPages = eventsData ? Math.ceil((eventsData.total ?? 0) / PER_PAGE) : 1

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-blue-400" />
            ファイル整合性監視 (FIM)
          </h1>
          <p className="text-[#8899aa] text-sm mt-1">
            監視エンドポイント全体のファイル変更イベントを検出・追跡・分析します
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={`flex items-center gap-2 px-3 py-2 text-sm rounded-lg border transition-colors ${
              autoRefresh
                ? 'bg-blue-900/40 border-blue-700 text-blue-300'
                : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-white hover:bg-[#1d2f4a]'
            }`}
          >
            <Clock className="w-4 h-4" />
            {autoRefresh ? '自動更新: ON (30秒)' : '自動更新: OFF'}
          </button>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 px-4 py-2 bg-[#161f33] border border-[#1e2d42]
                       text-[#8899aa] hover:text-white hover:bg-[#1d2f4a] text-sm rounded-lg
                       transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: '今日の変更',   value: eventsLoading ? '…' : todayTotal,   icon: <ShieldCheck className="w-4 h-4 text-blue-400" />,  color: 'text-blue-400'   },
          { label: '変更',          value: eventsLoading ? '…' : todayMod,     icon: <FileEdit    className="w-4 h-4 text-yellow-400" />, color: 'text-yellow-400' },
          { label: '作成',          value: eventsLoading ? '…' : todayCreated, icon: <FilePlus    className="w-4 h-4 text-green-400" />,  color: 'text-green-400'  },
          { label: '削除',          value: eventsLoading ? '…' : todayDeleted, icon: <FileX       className="w-4 h-4 text-red-400" />,    color: 'text-red-400'    },
        ].map(s => (
          <div key={s.label} className="bg-[#111827] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              {s.icon}
              <span className="text-xs text-[#8899aa]">{s.label}</span>
            </div>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Extra summary row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        {[
          { label: '総イベント数 (ページ)',    value: eventsLoading ? '…' : allFimEvents.length, icon: <BarChart2       className="w-4 h-4 text-indigo-400" />, color: 'text-indigo-400' },
          { label: '不審ファイル (スコア≥5)',  value: eventsLoading ? '…' : suspiciousCount,    icon: <AlertTriangle  className="w-4 h-4 text-orange-400" />, color: 'text-orange-400' },
          { label: '有効なFIMルール',           value: rulesLoading  ? '…' : (rulesData?.total ?? 0), icon: <ShieldCheck className="w-4 h-4 text-cyan-400" />, color: 'text-cyan-400' },
        ].map(s => (
          <div key={s.label} className="bg-[#111827] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              {s.icon}
              <span className="text-xs text-[#8899aa]">{s.label}</span>
            </div>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="border-b border-[#1e2d42]">
        <nav className="flex gap-1 overflow-x-auto">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-[#8899aa] hover:text-white hover:border-[#2a3d5a]'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl px-4 py-4 space-y-3">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-[#5a6a7a] flex-shrink-0" />
              <span className="text-[#8899aa] text-sm font-medium">フィルター</span>
              {hasFilters && (
                <button
                  onClick={clearFilters}
                  className="flex items-center gap-1 text-xs text-[#8899aa] hover:text-white
                             px-2 py-0.5 rounded-lg hover:bg-[#161f33] transition-colors ml-auto"
                >
                  <X className="w-3 h-3" />
                  クリア
                </button>
              )}
            </div>

            <div className="flex flex-wrap gap-3">
              {/* Agent */}
              <div>
                <label className="text-[#8899aa] text-xs block mb-1">エージェント</label>
                <select
                  value={agentFilter}
                  onChange={e => { setAgentFilter(e.target.value); setPage(1) }}
                  className="bg-[#080c14] text-white text-xs px-3 py-1.5 rounded-lg border border-[#1e2d42]
                             focus:outline-none focus:border-blue-500 transition-colors"
                >
                  <option value="">すべて</option>
                  {(agentsData?.data ?? []).map(a => (
                    <option key={a.id} value={a.id}>{a.hostname}</option>
                  ))}
                </select>
              </div>

              {/* Change type */}
              <div>
                <label className="text-[#8899aa] text-xs block mb-1">変更種別</label>
                <div className="flex gap-1">
                  {CHANGE_TYPES.map(ct => (
                    <button
                      key={ct === '' ? '__all__' : ct}
                      onClick={() => { setChangeTypeFilter(ct); setPage(1) }}
                      className={`px-2.5 py-1.5 text-xs rounded-lg border transition-colors flex items-center gap-1 ${
                        changeTypeFilter === ct
                          ? ct === 'modified' ? 'bg-yellow-900/50 border-yellow-700 text-yellow-300'
                            : ct === 'created' ? 'bg-green-900/50 border-green-700 text-green-300'
                            : ct === 'deleted' ? 'bg-red-900/50 border-red-700 text-red-300'
                            : 'bg-blue-900/40 border-blue-600 text-blue-300'
                          : 'bg-[#161f33] border-[#1e2d42] text-[#8899aa] hover:text-white hover:border-[#2a3d5a]'
                      }`}
                    >
                      {ct === '' ? 'すべて'
                        : ct === 'modified' ? <><FileEdit className="w-3 h-3" /> 変更</>
                        : ct === 'created'  ? <><FilePlus className="w-3 h-3" /> 作成</>
                        :                     <><FileX    className="w-3 h-3" /> 削除</>}
                    </button>
                  ))}
                </div>
              </div>

              {/* Path search */}
              <div className="flex-1 min-w-48">
                <label className="text-[#8899aa] text-xs block mb-1">パス検索</label>
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#5a6a7a]" />
                  <input
                    value={pathSearch}
                    onChange={e => { setPathSearch(e.target.value); setPage(1) }}
                    placeholder="/etc/hosts, C:\\Windows\\..."
                    className="w-full pl-8 pr-3 py-1.5 text-xs border border-[#1e2d42] rounded-lg
                               bg-[#080c14] text-white placeholder-[#5a6a7a]
                               focus:outline-none focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>

              {/* Date range */}
              <div>
                <label className="text-[#8899aa] text-xs block mb-1">開始日</label>
                <input
                  type="date"
                  value={fromDate}
                  onChange={e => { setFromDate(e.target.value); setPage(1) }}
                  className="bg-[#080c14] text-white text-xs px-3 py-1.5 rounded-lg border border-[#1e2d42]
                             focus:outline-none focus:border-blue-500 transition-colors"
                />
              </div>
              <div>
                <label className="text-[#8899aa] text-xs block mb-1">終了日</label>
                <input
                  type="date"
                  value={toDate}
                  onChange={e => { setToDate(e.target.value); setPage(1) }}
                  className="bg-[#080c14] text-white text-xs px-3 py-1.5 rounded-lg border border-[#1e2d42]
                             focus:outline-none focus:border-blue-500 transition-colors"
                />
              </div>
            </div>
          </div>

          {!eventsLoading && (
            <p className="text-[#8899aa] text-sm">
              FIMイベント:{' '}
              <span className="text-white font-medium">{(filteredEvents.length ?? 0).toLocaleString()}</span>
              {(eventsData?.total ?? 0) > 0 && (
                <span className="text-[#5a6a7a] ml-2 text-xs">
                  （全{(eventsData?.total ?? 0).toLocaleString()}ログイベント中）
                </span>
              )}
            </p>
          )}

          {/* Events Table */}
          <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">
            {eventsLoading ? (
              <div className="flex items-center justify-center h-40">
                <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              </div>
            ) : filteredEvents.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-[#5a6a7a]">
                <AlertTriangle className="w-10 h-10 mb-3 opacity-20" />
                <p className="text-sm">FIM変更イベントが見つかりません</p>
                {hasFilters && (
                  <button
                    onClick={clearFilters}
                    className="mt-2 text-xs text-blue-400 hover:text-blue-300 transition-colors underline"
                  >
                    フィルターをクリア
                  </button>
                )}
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#080c14]/30">
                    {['日時', 'エージェント', 'ファイルパス', '変更種別', '変更前ハッシュ', '変更後ハッシュ', '深刻度', ''].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[#8899aa] text-xs font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map(ev => (
                    <FimEventRow
                      key={ev.eventId}
                      event={ev}
                      agentName={agentMap[ev.agentId] ?? ''}
                      expanded={expandedId === ev.eventId}
                      onToggle={() => setExpandedId(expandedId === ev.eventId ? null : ev.eventId)}
                    />
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-3">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-4 py-2 bg-[#161f33] border border-[#1e2d42] text-[#8899aa] text-sm
                           rounded-lg disabled:opacity-40 hover:bg-[#1d2f4a] transition-colors"
              >
                前へ
              </button>
              <span className="text-[#8899aa] text-sm">
                {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="px-4 py-2 bg-[#161f33] border border-[#1e2d42] text-[#8899aa] text-sm
                           rounded-lg disabled:opacity-40 hover:bg-[#1d2f4a] transition-colors"
              >
                次へ
              </button>
            </div>
          )}

          {/* FIM Rules Panel */}
          <FimRulesPanel
            rules={rulesData?.data ?? []}
            total={rulesData?.total ?? 0}
            isLoading={rulesLoading}
          />
        </div>
      )}

      {activeTab === 'heatmap' && (
        <HeatmapTab events={allFimEvents} />
      )}

      {activeTab === 'suspicious' && (
        <SuspiciousTab events={allFimEvents} agentMap={agentMap} />
      )}

      {activeTab === 'ignore-rules' && (
        <IgnoreRulesTab />
      )}

      {activeTab === 'platform-rules' && (
        <PlatformRulesTab />
      )}

    </div>
  )
}
