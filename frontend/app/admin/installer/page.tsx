'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Terminal,
  Copy,
  Check,
  Download,
  Key,
  RefreshCw,
  AlertCircle,
  Trash2,
  Monitor,
  Server,
  Apple,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type OS = 'linux' | 'windows' | 'macos'
type Arch = 'amd64' | 'arm64'

interface InstallerToken {
  id: string
  created_at: string
  used_at: string | null
  agent_name: string | null
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateHexToken(): string {
  // crypto.randomUUID() requires a secure context (HTTPS / localhost).
  // Fall back to Math.random() on plain HTTP deployments.
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '').slice(0, 32)
  }
  return Array.from({ length: 32 }, () =>
    Math.floor(Math.random() * 16).toString(16)
  ).join('')
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  return d.toLocaleString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function buildCommand(
  os: OS,
  arch: Arch,
  serverUrl: string,
  token: string,
  group: string,
  service: boolean,
): string {
  const groupFlag = group.trim() ? ` --group ${group.trim()}` : ''
  const serviceFlag = service ? ' --service' : ''

  if (os === 'linux') {
    return `curl -fsSL ${serverUrl}/api/v1/installer/linux/${arch} | sudo bash -s -- --server ${serverUrl} --token ${token || '<TOKEN>'}${groupFlag}${serviceFlag}`
  }

  if (os === 'windows') {
    const line1 = `[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('${serverUrl}/api/v1/installer/windows/${arch}'))`
    const line2 = `Start-Process powershell -Verb RunAs -ArgumentList "-Command Install-EDRAgent -Server ${serverUrl} -Token ${token || '<TOKEN>'}${groupFlag}${serviceFlag}"`
    return `${line1}\n\n# 管理者権限で実行:\n${line2}`
  }

  // macOS
  return `curl -fsSL ${serverUrl}/api/v1/installer/macos/${arch} | sudo bash -s -- --server ${serverUrl} --token ${token || '<TOKEN>'}${groupFlag}${serviceFlag}`
}

// ─── OS Tab Button ─────────────────────────────────────────────────────────────

interface OSTabProps {
  os: OS
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  label: string
}

function OSTab({ active, onClick, icon, label }: OSTabProps) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
        active
          ? 'bg-blue-600 text-white'
          : 'bg-gray-700/50 text-gray-400 hover:bg-gray-700 hover:text-white'
      }`}
    >
      {icon}
      {label}
    </button>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function InstallerPage() {
  const [serverUrl, setServerUrl] = useState('https://your-edr-server.com')
  const [selectedOS, setSelectedOS] = useState<OS>('linux')
  const [arch, setArch] = useState<Arch>('amd64')
  const [group, setGroup] = useState('')
  const [token, setToken] = useState('')
  const [installService, setInstallService] = useState(true)
  const [copied, setCopied] = useState(false)
  const queryClient = useQueryClient()

  // Set default serverUrl from API URL (agent port) not the admin UI port
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setServerUrl(process.env.NEXT_PUBLIC_API_URL || window.location.origin)
    }
  }, [])

  // Fetch tokens from API
  const { data: tokensData } = useQuery<{ tokens: InstallerToken[] }>({
    queryKey: ['installer-tokens'],
    queryFn: () => apiFetch('/api/v1/admin/installer/tokens'),
  } as any)
  const tokens: InstallerToken[] = tokensData?.tokens ?? []

  // Create token mutation
  const createTokenMutation = useMutation<InstallerToken, Error, void>({
    mutationFn: () => apiFetch('/api/v1/admin/installer/tokens', { method: 'POST', body: JSON.stringify({}) }),
    onSuccess: (data) => {
      setToken(data.id)
      queryClient.invalidateQueries({ queryKey: ['installer-tokens'] })
    },
    onError: () => {
      // Fallback: generate locally if API unavailable
      setToken(generateHexToken())
    },
  })

  // Revoke token mutation
  const revokeTokenMutation = useMutation<void, Error, string>({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/installer/tokens/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['installer-tokens'] })
    },
  })

  const command = buildCommand(selectedOS, arch, serverUrl, token, group, installService)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // fallback: select text
    }
  }, [command])

  const handleGenerateToken = useCallback(() => {
    createTokenMutation.mutate()
  }, [createTokenMutation])

  const handleRevokeToken = useCallback((id: string) => {
    revokeTokenMutation.mutate(id)
  }, [revokeTokenMutation])

  const downloadUrl = (dlOS: string, dlArch: string) =>
    `${serverUrl}/api/v1/installer/download/${dlOS}/${dlArch}`

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Terminal className="w-6 h-6 text-blue-400" />
          エージェントインストーラー
        </h1>
        <p className="text-gray-400 text-sm mt-1">
          各OSへのEDRエージェントインストール用コマンドを生成します
        </p>
      </div>

      {/* Configuration form card */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-5">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Server className="w-4 h-4 text-blue-400" />
          インストール設定
        </h2>

        {/* Server URL */}
        <div className="space-y-1.5">
          <label className="text-xs text-gray-400 font-medium">サーバーURL</label>
          <input
            type="url"
            value={serverUrl}
            onChange={e => setServerUrl(e.target.value)}
            placeholder="https://your-edr-server.com"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white
                       placeholder-gray-600 focus:outline-hidden focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50
                       font-mono"
          />
        </div>

        {/* OS Selection */}
        <div className="space-y-2">
          <label className="text-xs text-gray-400 font-medium">OS</label>
          <div className="flex gap-2 flex-wrap">
            <OSTab
              os="linux"
              active={selectedOS === 'linux'}
              onClick={() => setSelectedOS('linux')}
              icon={<Terminal className="w-4 h-4" />}
              label="Linux"
            />
            <OSTab
              os="windows"
              active={selectedOS === 'windows'}
              onClick={() => setSelectedOS('windows')}
              icon={<Monitor className="w-4 h-4" />}
              label="Windows"
            />
            <OSTab
              os="macos"
              active={selectedOS === 'macos'}
              onClick={() => setSelectedOS('macos')}
              icon={<Apple className="w-4 h-4" />}
              label="macOS"
            />
          </div>
        </div>

        {/* Architecture */}
        <div className="space-y-2">
          <label className="text-xs text-gray-400 font-medium">アーキテクチャ</label>
          <div className="flex gap-4">
            {([
              { value: 'amd64' as Arch, label: 'x86_64' },
              { value: 'arm64' as Arch, label: 'ARM64' },
            ]).map(({ value: a, label: archLabel }) => (
              <label
                key={a}
                className="flex items-center gap-2 cursor-pointer group"
              >
                <input
                  type="radio"
                  name="arch"
                  value={a}
                  checked={arch === a}
                  onChange={() => setArch(a)}
                  className="w-4 h-4 accent-blue-500"
                />
                <span className={`text-sm font-mono transition-colors ${
                  arch === a ? 'text-white' : 'text-gray-400 group-hover:text-gray-300'
                }`}>
                  {archLabel}
                </span>
              </label>
            ))}
          </div>
        </div>

        {/* Agent group */}
        <div className="space-y-1.5">
          <label className="text-xs text-gray-400 font-medium">
            エージェントグループ
            <span className="ml-1 text-gray-600">(オプション)</span>
          </label>
          <input
            type="text"
            value={group}
            onChange={e => setGroup(e.target.value)}
            placeholder="例: production / servers"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white
                       placeholder-gray-600 focus:outline-hidden focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50"
          />
        </div>

        {/* Pre-shared token */}
        <div className="space-y-1.5">
          <label className="text-xs text-gray-400 font-medium flex items-center gap-1.5">
            <Key className="w-3.5 h-3.5" />
            事前共有トークン
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={token}
              onChange={e => setToken(e.target.value)}
              placeholder="32文字の16進数トークン"
              className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white
                         placeholder-gray-600 focus:outline-hidden focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50
                         font-mono"
            />
            <button
              onClick={handleGenerateToken}
              className="flex items-center gap-1.5 px-3 py-2 bg-gray-700 text-gray-300 rounded-lg
                         hover:bg-gray-600 hover:text-white transition-colors text-sm font-medium whitespace-nowrap"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              生成
            </button>
          </div>
        </div>

        {/* Install as service */}
        <label className="flex items-center gap-3 cursor-pointer group w-fit">
          <input
            type="checkbox"
            checked={installService}
            onChange={e => setInstallService(e.target.checked)}
            className="w-4 h-4 accent-blue-500 rounded-sm"
          />
          <span className="text-sm text-gray-300 group-hover:text-white transition-colors">
            サービスとしてインストール
            <span className="ml-1.5 text-xs text-gray-500">(起動時に自動起動)</span>
          </span>
        </label>
      </div>

      {/* Generated command card */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-green-400" />
            生成されたコマンド
            <span className="text-xs text-gray-500 font-normal">
              ({selectedOS === 'linux' ? 'Bash' : selectedOS === 'windows' ? 'PowerShell' : 'Bash'})
            </span>
          </h2>
          <button
            onClick={handleCopy}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              copied
                ? 'bg-green-900/40 text-green-400 border border-green-700/40'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600 hover:text-white border border-transparent'
            }`}
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5" />
                コピーしました！
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                コピー
              </>
            )}
          </button>
        </div>
        <div className="bg-gray-950 p-4 overflow-x-auto">
          <pre className="text-sm text-green-300 font-mono whitespace-pre-wrap break-all leading-relaxed">
            {command}
          </pre>
        </div>
        {!token && (
          <div className="px-4 py-2.5 border-t border-gray-700 flex items-center gap-2">
            <AlertCircle className="w-3.5 h-3.5 text-yellow-400 shrink-0" />
            <p className="text-xs text-yellow-400">
              トークンが設定されていません。「生成」ボタンでトークンを作成してください。
            </p>
          </div>
        )}
      </div>

      {/* Download section */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Download className="w-4 h-4 text-blue-400" />
          エージェントバイナリのダウンロード
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { label: 'Linux x86_64', os: 'linux', archVal: 'amd64', icon: <Terminal className="w-4 h-4" />, color: 'text-orange-400' },
            { label: 'Linux ARM64', os: 'linux', archVal: 'arm64', icon: <Terminal className="w-4 h-4" />, color: 'text-yellow-400' },
            { label: 'Windows x64', os: 'windows', archVal: 'amd64', icon: <Monitor className="w-4 h-4" />, color: 'text-blue-400' },
            { label: 'macOS', os: 'macos', archVal: 'amd64', icon: <Apple className="w-4 h-4" />, color: 'text-gray-300' },
          ].map(({ label, os, archVal, icon, color }) => (
            <a
              key={`${os}-${archVal}`}
              href={downloadUrl(os, archVal)}
              className="flex items-center gap-3 px-4 py-3 bg-gray-900 border border-gray-700
                         rounded-lg hover:bg-gray-700/60 hover:border-gray-600 transition-all group"
              target="_blank"
              rel="noopener noreferrer"
            >
              <span className={`${color} shrink-0 group-hover:scale-110 transition-transform`}>
                {icon}
              </span>
              <div className="min-w-0">
                <p className="text-sm text-gray-200 font-medium">{label}</p>
                <p className="text-xs text-gray-500 font-mono truncate">
                  {`/${os}/${archVal}`}
                </p>
              </div>
              <Download className="w-3.5 h-3.5 text-gray-600 group-hover:text-gray-400 ml-auto shrink-0 transition-colors" />
            </a>
          ))}
        </div>
        <p className="text-xs text-gray-600">
          ダウンロードURL: <span className="font-mono">{serverUrl}/api/v1/installer/download/&#123;os&#125;/&#123;arch&#125;</span>
        </p>
      </div>

      {/* Token management card */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Key className="w-4 h-4 text-blue-400" />
            インストールトークン管理
          </h2>
          <span className="text-xs text-gray-500">{tokens.length} 件</span>
        </div>

        {tokens.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 text-gray-600">
            <Key className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">トークンがありません</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 bg-gray-900/30">
                  <th className="text-left px-4 py-3 text-gray-400 text-xs font-medium">トークンID</th>
                  <th className="text-left px-4 py-3 text-gray-400 text-xs font-medium">作成日時</th>
                  <th className="text-left px-4 py-3 text-gray-400 text-xs font-medium">使用日時</th>
                  <th className="text-left px-4 py-3 text-gray-400 text-xs font-medium">エージェント名</th>
                  <th className="text-left px-4 py-3 text-gray-400 text-xs font-medium">操作</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map(t => (
                  <tr
                    key={t.id}
                    className="border-b border-gray-700/50 last:border-0 hover:bg-gray-700/20 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-gray-300 bg-gray-900 px-2 py-0.5 rounded-sm">
                        {t.id.slice(0, 8)}…{t.id.slice(-6)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      {formatDate(t.created_at)}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {t.used_at ? (
                        <span className="text-green-400">{formatDate(t.used_at)}</span>
                      ) : (
                        <span className="text-gray-600">未使用</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {t.agent_name ? (
                        <span className="text-gray-200">{t.agent_name}</span>
                      ) : (
                        <span className="text-gray-600">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleRevokeToken(t.id)}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-red-900/20 text-red-400
                                   border border-red-800/30 rounded-lg hover:bg-red-900/40 transition-colors
                                   text-xs font-medium"
                      >
                        <Trash2 className="w-3 h-3" />
                        トークンを無効化
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="px-4 py-3 border-t border-gray-700 flex items-start gap-2">
          <AlertCircle className="w-3.5 h-3.5 text-yellow-500 shrink-0 mt-0.5" />
          <p className="text-xs text-gray-500">
            本番環境ではサーバー側でトークン管理を実装してください。現在のデータはモックです。
          </p>
        </div>
      </div>

    </div>
  )
}
