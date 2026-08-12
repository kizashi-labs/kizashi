'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Download, RefreshCw, Copy, Check, Eye, EyeOff,
  Terminal, Monitor, Server, AlertTriangle, ChevronRight,
  Cpu, Package
} from 'lucide-react'

interface Settings {
  enrollment_token?: string
  server_url?: string
  server_grpc_url?: string
}

export default function AgentDeployPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'linux' | 'windows' | 'macos' | 'docker'>('linux')
  const [showToken, setShowToken] = useState(false)
  const [copied, setCopied] = useState<string | null>(null)

  const { data: settings } = useQuery<Settings>({
    queryKey: ['settings'],
    queryFn: () => apiFetch('/api/v1/settings'),
  })

  const regenMutation = useMutation({
    mutationFn: () => apiFetch('/api/v1/settings/enrollment-token', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings'] }),
  })

  const token = settings?.enrollment_token ?? ''
  const serverURL = settings?.server_grpc_url || settings?.server_url || 'https://edr-server:9090'
  const maskedToken = token ? token.slice(0, 8) + '••••••••••••••••••••••••••••' : '(トークン未生成)'

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key)
      setTimeout(() => setCopied(null), 2000)
    })
  }

  const linuxInstallScript = `# 1. エージェントをダウンロード
curl -Lo edr-agent \\
  "${serverURL.replace(':9090', '')}/downloads/edr-agent-linux-amd64"
chmod +x edr-agent

# 2. エンロール (初回のみ)
sudo ./edr-agent --enroll \\
  --server ${serverURL} \\
  --token ${token || 'YOUR_ENROLLMENT_TOKEN'}

# 3. systemdサービスとしてインストール
sudo bash install.sh \\
  --server ${serverURL} \\
  --token ${token || 'YOUR_ENROLLMENT_TOKEN'}`

  const linuxOneliner = `curl -sSL "${serverURL.replace(':9090', '')}/install.sh" | sudo bash -s -- --server ${serverURL} --token ${token || 'YOUR_ENROLLMENT_TOKEN'}`

  const windowsScript = `# PowerShell (管理者として実行)

# 1. エージェントをダウンロード
Invoke-WebRequest \`
  -Uri "${serverURL.replace(':9090', '')}/downloads/edr-agent-windows-amd64.exe" \`
  -OutFile edr-agent.exe
Invoke-WebRequest \`
  -Uri "${serverURL.replace(':9090', '')}/downloads/edr-watchdog-windows-amd64.exe" \`
  -OutFile edr-watchdog.exe

# 2. インストールスクリプトを実行
.\\Install-EDRAgent.ps1 \`
  -ServerUrl "${serverURL}" \`
  -EnrollmentToken "${token || 'YOUR_ENROLLMENT_TOKEN'}"`

  const macosInstallScript = `# 1. エージェントをダウンロード (Intel Mac)
curl -Lo edr-agent \\
  "${serverURL.replace(':9090', '')}/downloads/edr-agent-darwin-amd64"
chmod +x edr-agent

# Apple Silicon (M1/M2/M3) の場合
# curl -Lo edr-agent \\
#   "${serverURL.replace(':9090', '')}/downloads/edr-agent-darwin-arm64"

# 2. エンロール (初回のみ)
sudo ./edr-agent --enroll \\
  --server ${serverURL} \\
  --token ${token || 'YOUR_ENROLLMENT_TOKEN'}

# 3. Launch Agent としてインストール
sudo ./edr-agent install \\
  --server ${serverURL} \\
  --token ${token || 'YOUR_ENROLLMENT_TOKEN'}`

  const macosOneliner = `curl -sSL "${serverURL.replace(':9090', '')}/install-macos.sh" | sudo bash -s -- --server ${serverURL} --token ${token || 'YOUR_ENROLLMENT_TOKEN'}`

  const macosBrewScript = `# Homebrew経由でインストール (推奨)
brew tap edr-platform/tap
brew install edr-agent

# 設定ファイルを配置
sudo tee /etc/edr-agent/agent.toml <<EOF
server_url = "${serverURL}"
enrollment_token = "${token || 'YOUR_ENROLLMENT_TOKEN'}"
EOF

# サービスを開始
sudo brew services start edr-agent`

  const dockerScript = `# docker-compose.ymlに追加
services:
  edr-agent:
    image: edr-platform/agent:latest
    container_name: edr-agent
    network_mode: host
    pid: host
    privileged: true
    environment:
      - EDR_SERVER_URL=${serverURL}
      - EDR_ENROLLMENT_TOKEN=${token || 'YOUR_ENROLLMENT_TOKEN'}
    volumes:
      - /var/lib/edr-agent:/var/lib/edr-agent
      - /var/log/edr-agent:/var/log/edr-agent
    restart: unless-stopped`

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Download className="w-6 h-6 text-blue-400" />
          エージェントデプロイ
        </h1>
        <p className="text-[#8899aa] mt-1">エンドポイントにEDRエージェントをインストールします</p>
      </div>

      {/* Enrollment Token */}
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-white font-semibold flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-400" />
              エンロールメントトークン
            </h2>
            <p className="text-[#8899aa] text-sm mt-0.5">新しいエージェントの登録に使用されるワンタイムトークン</p>
          </div>
          <button
            onClick={() => regenMutation.mutate()}
            disabled={regenMutation.isPending}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#161f33] hover:bg-[#1d2f4a]
                       text-[#8899aa] hover:text-white rounded-lg text-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${regenMutation.isPending ? 'animate-spin' : ''}`} />
            再生成
          </button>
        </div>

        <div className="flex items-center gap-2">
          <code className="flex-1 bg-[#080c14] border border-[#1e2d42] rounded-lg px-4 py-3
                           text-sm font-mono text-green-400 break-all">
            {showToken ? (token || '(未生成)') : maskedToken}
          </code>
          <button
            onClick={() => setShowToken(!showToken)}
            className="p-2.5 bg-[#161f33] hover:bg-[#1d2f4a] rounded-lg text-[#8899aa] hover:text-white transition-colors"
          >
            {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
          <button
            onClick={() => copyText(token, 'token')}
            disabled={!token}
            className="p-2.5 bg-[#161f33] hover:bg-[#1d2f4a] rounded-lg text-[#8899aa] hover:text-white transition-colors disabled:opacity-50"
          >
            {copied === 'token' ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>

        {!token && (
          <div className="mt-3 flex items-center gap-2 text-yellow-400 text-sm">
            <AlertTriangle className="w-4 h-4" />
            トークンが未設定です。「再生成」ボタンをクリックして生成してください。
          </div>
        )}

        <div className="mt-4 grid grid-cols-2 gap-3">
          <div className="bg-[#080c14] rounded-lg p-3">
            <p className="text-[#5a6a7a] text-xs mb-1">サーバーURL</p>
            <p className="text-white text-sm font-mono">{serverURL}</p>
          </div>
          <div className="bg-[#080c14] rounded-lg p-3">
            <p className="text-[#5a6a7a] text-xs mb-1">トークン有効期限</p>
            <p className="text-white text-sm">無期限（再生成まで有効）</p>
          </div>
        </div>
      </div>

      {/* Architecture overview */}
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5">
        <h2 className="text-white font-semibold mb-4 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-purple-400" />
          エージェントアーキテクチャ
        </h2>
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'プロセス監視', desc: 'ETW / /proc', color: 'blue' },
            { label: 'ファイル監視', desc: 'FSEvents / inotify', color: 'green' },
            { label: 'ネットワーク監視', desc: 'WFP / netlink', color: 'purple' },
            { label: 'DNS監視', desc: 'ETW / /proc/net', color: 'yellow' },
          ].map(({ label, desc, color }) => (
            <div key={label} className="bg-[#080c14] rounded-lg p-3 text-center">
              <div className={`text-${color}-400 font-medium text-sm`}>{label}</div>
              <div className="text-[#5a6a7a] text-xs mt-1">{desc}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex items-center justify-center gap-2 text-[#5a6a7a] text-sm">
          <div className="flex-1 border-t border-[#1e2d42]" />
          <ChevronRight className="w-4 h-4" />
          <span>mTLS gRPC</span>
          <ChevronRight className="w-4 h-4" />
          <span>インジェスションサーバー (:9090)</span>
          <ChevronRight className="w-4 h-4" />
          <span>検知エンジン (NATS)</span>
          <div className="flex-1 border-t border-[#1e2d42]" />
        </div>
      </div>

      {/* Installation Instructions */}
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl">
        <div className="flex border-b border-[#1e2d42]">
          {[
            { key: 'linux',   label: 'Linux',   icon: Terminal },
            { key: 'windows', label: 'Windows', icon: Monitor  },
            { key: 'macos',   label: 'macOS',   icon: Cpu      },
            { key: 'docker',  label: 'Docker',  icon: Package  },
          ].map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setTab(key as typeof tab)}
              className={`flex items-center gap-2 px-5 py-3 text-sm font-medium transition-colors border-b-2 ${
                tab === key
                  ? 'text-blue-400 border-blue-400'
                  : 'text-[#8899aa] border-transparent hover:text-white'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </div>

        <div className="p-5 space-y-4">
          {tab === 'linux' && (
            <>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[#8899aa] text-sm font-medium">ワンライナーインストール (推奨)</p>
                  <button
                    onClick={() => copyText(linuxOneliner, 'linux-one')}
                    className="flex items-center gap-1.5 text-xs text-[#8899aa] hover:text-white transition-colors"
                  >
                    {copied === 'linux-one' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    コピー
                  </button>
                </div>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-green-300 overflow-x-auto whitespace-pre-wrap break-all">
                  {linuxOneliner}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[#8899aa] text-sm font-medium">手動インストール手順</p>
                  <button
                    onClick={() => copyText(linuxInstallScript, 'linux-full')}
                    className="flex items-center gap-1.5 text-xs text-[#8899aa] hover:text-white transition-colors"
                  >
                    {copied === 'linux-full' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    コピー
                  </button>
                </div>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-green-300 overflow-x-auto whitespace-pre-wrap">
                  {linuxInstallScript}
                </pre>
              </div>

              <div className="bg-blue-900/20 border border-blue-700/40 rounded-lg p-4">
                <p className="text-blue-300 text-sm font-medium mb-2">必要な権限</p>
                <ul className="text-blue-200/70 text-sm space-y-1 list-disc list-inside">
                  <li>インストール: root または sudo</li>
                  <li>eBPFプロセス監視: <code className="text-blue-300">CAP_SYS_ADMIN</code></li>
                  <li>ネットワーク隔離: <code className="text-blue-300">CAP_NET_ADMIN</code></li>
                  <li>ファイル監視: <code className="text-blue-300">CAP_DAC_READ_SEARCH</code></li>
                </ul>
              </div>
            </>
          )}

          {tab === 'windows' && (
            <>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[#8899aa] text-sm font-medium">PowerShellインストール (管理者として実行)</p>
                  <button
                    onClick={() => copyText(windowsScript, 'windows')}
                    className="flex items-center gap-1.5 text-xs text-[#8899aa] hover:text-white transition-colors"
                  >
                    {copied === 'windows' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    コピー
                  </button>
                </div>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-blue-300 overflow-x-auto whitespace-pre-wrap">
                  {windowsScript}
                </pre>
              </div>

              <div className="bg-blue-900/20 border border-blue-700/40 rounded-lg p-4">
                <p className="text-blue-300 text-sm font-medium mb-2">インストール先</p>
                <div className="text-blue-200/70 text-sm space-y-1 font-mono">
                  <p>バイナリ: <span className="text-white">C:\Program Files\EDRAgent\</span></p>
                  <p>設定:     <span className="text-white">C:\ProgramData\EDRAgent\agent.toml</span></p>
                  <p>ログ:     <span className="text-white">C:\ProgramData\EDRAgent\logs\</span></p>
                  <p>隔離:     <span className="text-white">C:\ProgramData\EDRAgent\quarantine\</span></p>
                  <p>サービス: <span className="text-white">EDRWatchdog (自動起動)</span></p>
                </div>
              </div>

              <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg p-4">
                <p className="text-yellow-300 text-sm font-medium mb-1 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  注意事項
                </p>
                <p className="text-yellow-200/70 text-sm">
                  Windows Defenderや他のAVソフトウェアがエージェントをブロックする可能性があります。
                  インストール前にEDRAgentのインストールパスを除外リストに追加してください。
                </p>
              </div>
            </>
          )}

          {tab === 'macos' && (
            <>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[#8899aa] text-sm font-medium">ワンライナーインストール (推奨)</p>
                  <button
                    onClick={() => copyText(macosOneliner, 'macos-one')}
                    className="flex items-center gap-1.5 text-xs text-[#8899aa] hover:text-white transition-colors"
                  >
                    {copied === 'macos-one' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    コピー
                  </button>
                </div>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-green-300 overflow-x-auto whitespace-pre-wrap break-all">
                  {macosOneliner}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[#8899aa] text-sm font-medium">手動インストール手順</p>
                  <button
                    onClick={() => copyText(macosInstallScript, 'macos-full')}
                    className="flex items-center gap-1.5 text-xs text-[#8899aa] hover:text-white transition-colors"
                  >
                    {copied === 'macos-full' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    コピー
                  </button>
                </div>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-green-300 overflow-x-auto whitespace-pre-wrap">
                  {macosInstallScript}
                </pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[#8899aa] text-sm font-medium">Homebrew 経由でインストール</p>
                  <button
                    onClick={() => copyText(macosBrewScript, 'macos-brew')}
                    className="flex items-center gap-1.5 text-xs text-[#8899aa] hover:text-white transition-colors"
                  >
                    {copied === 'macos-brew' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    コピー
                  </button>
                </div>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-purple-300 overflow-x-auto whitespace-pre-wrap">
                  {macosBrewScript}
                </pre>
              </div>

              <div className="bg-blue-900/20 border border-blue-700/40 rounded-lg p-4">
                <p className="text-blue-300 text-sm font-medium mb-2">インストール先</p>
                <div className="text-blue-200/70 text-sm space-y-1 font-mono">
                  <p>バイナリ: <span className="text-white">/usr/local/bin/edr-agent</span></p>
                  <p>設定:     <span className="text-white">/etc/edr-agent/agent.toml</span></p>
                  <p>ログ:     <span className="text-white">/var/log/edr-agent/</span></p>
                  <p>隔離:     <span className="text-white">/var/lib/edr-agent/quarantine/</span></p>
                  <p>サービス: <span className="text-white">com.edr-platform.agent (launchd)</span></p>
                </div>
              </div>

              <div className="bg-blue-900/20 border border-blue-700/40 rounded-lg p-4">
                <p className="text-blue-300 text-sm font-medium mb-2">必要な権限</p>
                <ul className="text-blue-200/70 text-sm space-y-1 list-disc list-inside">
                  <li>インストール: sudo / 管理者アカウント</li>
                  <li>ファイル監視: Full Disk Access (システム環境設定 → セキュリティ → プライバシー)</li>
                  <li>ネットワーク隔離: pfctl (管理者権限で自動付与)</li>
                  <li>プロセス監視: <code className="text-blue-300">com.apple.security.endpoint-security.client</code> entitlement</li>
                </ul>
              </div>

              <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg p-4">
                <p className="text-yellow-300 text-sm font-medium mb-1 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  macOS Gatekeeperについて
                </p>
                <p className="text-yellow-200/70 text-sm">
                  初回実行時に Gatekeeper によってブロックされる場合があります。
                  システム設定 → セキュリティとプライバシー で「このまま開く」を選択するか、
                  <code className="text-yellow-300 mx-1">sudo spctl --add /usr/local/bin/edr-agent</code>
                  を実行してください。
                </p>
              </div>
            </>
          )}

          {tab === 'docker' && (
            <>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[#8899aa] text-sm font-medium">docker-compose.yml</p>
                  <button
                    onClick={() => copyText(dockerScript, 'docker')}
                    className="flex items-center gap-1.5 text-xs text-[#8899aa] hover:text-white transition-colors"
                  >
                    {copied === 'docker' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                    コピー
                  </button>
                </div>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-yellow-300 overflow-x-auto whitespace-pre-wrap">
                  {dockerScript}
                </pre>
              </div>

              <div>
                <p className="text-[#8899aa] text-sm font-medium mb-2">エージェントのビルド</p>
                <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-green-300 overflow-x-auto">
{`# Linux向けビルド
cd agent
make build-linux

# Dockerイメージビルド
docker build -f agent/Dockerfile -t edr-platform/agent:latest .`}
                </pre>
              </div>

              <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-lg p-4">
                <p className="text-yellow-300 text-sm font-medium mb-1 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  Dockerの制限事項
                </p>
                <p className="text-yellow-200/70 text-sm">
                  コンテナ内のエージェントはホストのプロセス/ネットワーク/ファイルシステムに
                  アクセスするため <code className="text-yellow-300">--pid host --network host --privileged</code> が必要です。
                  セキュリティ要件を考慮した上でご使用ください。
                </p>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Build from source */}
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-5">
        <h2 className="text-white font-semibold mb-4 flex items-center gap-2">
          <Package className="w-4 h-4 text-green-400" />
          ソースからビルド
        </h2>
        <div className="grid grid-cols-3 gap-4">
          {[
            { os: 'Linux (amd64)', cmd: 'make build-linux', color: 'green', output: 'agent, watchdog' },
            { os: 'Windows (amd64)', cmd: 'make build-windows', color: 'blue', output: 'agent.exe, watchdog.exe' },
            { os: 'macOS (amd64)', cmd: 'make build-darwin', color: 'purple', output: 'agent-darwin, watchdog-darwin' },
          ].map(({ os, cmd, color, output }) => (
            <div key={os} className="bg-[#080c14] rounded-lg p-4">
              <p className={`text-${color}-400 font-medium text-sm mb-2`}>{os}</p>
              <code className="text-[#8899aa] text-xs font-mono block mb-2">{cmd}</code>
              <p className="text-[#5a6a7a] text-xs">出力: {output}</p>
            </div>
          ))}
        </div>
        <div className="mt-3">
          <pre className="bg-[#080c14] rounded-lg p-4 text-sm font-mono text-[#8899aa] overflow-x-auto">
{`# 全プラットフォーム向けビルド
cd agent
make all

# テスト実行
make test`}
          </pre>
        </div>
      </div>
    </div>
  )
}
