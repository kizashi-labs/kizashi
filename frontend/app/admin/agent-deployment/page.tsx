'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Monitor, Apple, Server, ChevronRight, ChevronLeft,
  Copy, Check, Download, RefreshCw, Terminal,
  Settings, Shield, Cpu, Globe, AlertCircle,
  CheckCircle2, Loader2, Layers, Key
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ── Types ──────────────────────────────────────────────────────────────────

type Platform = 'linux' | 'windows' | 'macos'
type InstallTab = 'oneliner' | 'manual' | 'docker' | 'kubernetes'
type VerifyStatus = 'waiting' | 'connected' | 'failed'

interface Group {
  id: string
  name: string
}

interface AgentVerifyResult {
  id: string
  hostname: string
  status: string
  version: string
  platform: string
  last_seen: string
}

// ── Constants ──────────────────────────────────────────────────────────────

const PLATFORMS: { id: Platform; label: string; icon: React.ElementType; archs: string[] }[] = [
  {
    id: 'linux',
    label: 'Linux',
    icon: Server,
    archs: ['x86_64 (amd64)', 'arm64 / aarch64', 'armv7'],
  },
  {
    id: 'windows',
    label: 'Windows',
    icon: Monitor,
    archs: ['x86_64 (amd64)', 'arm64'],
  },
  {
    id: 'macos',
    label: 'macOS',
    icon: Apple,
    archs: ['x86_64 (Intel)', 'arm64 (Apple Silicon)'],
  },
]

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

// ── Step indicator ─────────────────────────────────────────────────────────

const STEPS = [
  { n: 1, label: 'プラットフォーム' },
  { n: 2, label: '設定' },
  { n: 3, label: 'インストール' },
  { n: 4, label: '確認' },
]

function StepIndicator({ current }: { current: number }) {
  return (
    <div className="flex items-center gap-0 mb-8">
      {STEPS.map((s, i) => (
        <div key={s.n} className="flex items-center">
          <div className="flex items-center gap-2">
            <div
              className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold transition-all
                ${current === s.n
                  ? 'bg-[#e8002d] text-white shadow-[0_0_12px_rgba(232,0,45,0.4)]'
                  : current > s.n
                  ? 'bg-[#00c853] text-white'
                  : 'bg-[#1e2d42] text-[#3d5068]'
                }`}
            >
              {current > s.n ? <Check className="w-4 h-4" /> : s.n}
            </div>
            <span
              className={`text-sm font-medium hidden sm:block transition-colors
                ${current === s.n ? 'text-white' : current > s.n ? 'text-[#00c853]' : 'text-[#3d5068]'}`}
            >
              {s.label}
            </span>
          </div>
          {i < STEPS.length - 1 && (
            <div
              className={`h-px w-8 mx-2 transition-all ${current > s.n ? 'bg-[#00c853]' : 'bg-[#1e2d42]'}`}
            />
          )}
        </div>
      ))}
    </div>
  )
}

// ── Copy button ────────────────────────────────────────────────────────────

function CopyButton({ text, className = '' }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // fallback
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }, [text])

  return (
    <button
      onClick={handleCopy}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all
        ${copied
          ? 'bg-[#00c853]/20 text-[#00c853] border border-[#00c853]/30'
          : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white hover:bg-[#263a57] border border-[#1e2d42]'
        } ${className}`}
    >
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'コピー済み' : 'コピー'}
    </button>
  )
}

// ── Code block ────────────────────────────────────────────────────────────

function CodeBlock({ code, lang = 'bash' }: { code: string; lang?: string }) {
  return (
    <div className="relative group rounded-lg bg-[#060d18] border border-[#1e2d42] overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-[#0d1220] border-b border-[#1e2d42]">
        <span className="text-[10px] font-mono text-[#3d5068] uppercase tracking-wider">{lang}</span>
        <CopyButton text={code} />
      </div>
      <pre className="p-4 text-sm font-mono text-[#a8c4e0] overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────

export default function AgentDeploymentPage() {
  // Wizard state
  const [step, setStep] = useState(1)
  const [platform, setPlatform] = useState<Platform | null>(null)

  // Step 2 config
  const [serverURL, setServerURL] = useState('https://your-edr-server.example.com')

  // Use the API URL (port 8080) for installer commands, not the frontend port.
  useEffect(() => {
    const apiURL = process.env.NEXT_PUBLIC_API_URL
    if (apiURL) {
      setServerURL(apiURL)
    } else {
      // Replace frontend port 3000 with API port 8080
      const origin = window.location.origin
      setServerURL(origin.replace(/:3000$/, ':8080').replace(/:3001$/, ':8080'))
    }
  }, [])
  const [agentGroup, setAgentGroup] = useState('')
  const [groups, setGroups] = useState<Group[]>([])
  const [loadingGroups, setLoadingGroups] = useState(false)
  const [registrationToken, setRegistrationToken] = useState('')
  const [tokenLoading, setTokenLoading] = useState(false)
  const [namePrefix, setNamePrefix] = useState('')
  const [proxyURL, setProxyURL] = useState('')

  // Step 3 install tab
  const [installTab, setInstallTab] = useState<InstallTab>('oneliner')

  // Step 4 verify
  const [verifyStatus, setVerifyStatus] = useState<VerifyStatus>('waiting')
  const [verifyAgent, setVerifyAgent] = useState<AgentVerifyResult | null>(null)
  const [verifyLoading, setVerifyLoading] = useState(false)
  const [verifyError, setVerifyError] = useState('')

  // Load agent groups and fetch enrollment token when entering step 2
  const handleNextFromStep1 = useCallback(async () => {
    if (!platform) return
    setStep(2)
    setLoadingGroups(true)
    setTokenLoading(true)
    try {
      const [groupsRes, settingsRes] = await Promise.all([
        apiFetch<{ groups?: Group[] } | Group[]>('/api/v1/groups').catch(() => [] as Group[]),
        apiFetch<Record<string, string>>('/api/v1/settings').catch(() => ({} as Record<string, string>)),
      ])
      setGroups(Array.isArray(groupsRes) ? groupsRes : (groupsRes as { groups?: Group[] })?.groups ?? [])
      const token = settingsRes['enrollment_token']
      if (token) {
        setRegistrationToken(token)
      } else {
        // Generate a new enrollment token if not set
        const res = await apiFetch<{ enrollment_token: string }>('/api/v1/settings/enrollment-token', { method: 'POST' })
        setRegistrationToken(res.enrollment_token)
      }
    } catch {
      setGroups([])
    } finally {
      setLoadingGroups(false)
      setTokenLoading(false)
    }
  }, [platform])

  // ── Install command generators ──────────────────────────────────────────

  const getOneLinear = (): string => {
    const params = new URLSearchParams({
      token: registrationToken,
      ...(agentGroup ? { group: agentGroup } : {}),
    })
    if (platform === 'windows') {
      return `iwr -useb "${serverURL}/api/v1/installer/windows/amd64?${params}" | iex`
    }
    const os = platform ?? 'linux'
    return `curl -fsSL "${serverURL}/api/v1/installer/${os}/amd64?${params}" | sudo bash`
  }

  const getManualSteps = (): string => {
    if (platform === 'windows') {
      return `# Step 1: Download agent binary
$url = "${serverURL}/api/v1/installer/download?os=windows&arch=amd64&token=${registrationToken}"
Invoke-WebRequest -Uri $url -OutFile "C:\\Program Files\\KizashiEDR\\kizashi-agent.exe"

# Step 2: Configure agent
$config = @"
server_url: ${serverURL}
registration_token: ${registrationToken}
${agentGroup ? `group: ${agentGroup}\n` : ''}${namePrefix ? `name_prefix: ${namePrefix}\n` : ''}${proxyURL ? `proxy: ${proxyURL}\n` : ''}"@
$config | Out-File "C:\\Program Files\\KizashiEDR\\config.yaml" -Encoding UTF8

# Step 3: Install as Windows service
New-Service -Name "KizashiEDRAgent" \\
  -BinaryPathName "C:\\Program Files\\KizashiEDR\\kizashi-agent.exe --config C:\\Program Files\\KizashiEDR\\config.yaml" \\
  -DisplayName "Kizashi Agent" \\
  -StartupType Automatic

# Step 4: Start service
Start-Service -Name "KizashiEDRAgent"
Get-Service -Name "KizashiEDRAgent"`
    }

    const isMac = platform === 'macos'
    const os = isMac ? 'darwin' : 'linux'
    return `# Step 1: Download agent binary
sudo mkdir -p /opt/edr-agent
sudo curl -fsSL "${serverURL}/api/v1/installer/download/${os}/amd64" \\
  -o /opt/edr-agent/edr-agent
sudo chmod +x /opt/edr-agent/edr-agent

# Step 2: Enroll agent (creates config.toml automatically)
sudo /opt/edr-agent/edr-agent --enroll \\
  --server "${serverURL}" \\
  --token "${registrationToken}"

# Step 3: Create systemd service
sudo tee /etc/systemd/system/edr-agent.service <<EOF
[Unit]
Description=EDR Platform Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/edr-agent/edr-agent
Restart=on-failure
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Step 4: Create systemd service${isMac ? ' (or launchd on macOS)' : ''}
${isMac ? `cat > /Library/LaunchDaemons/com.kizashiedr.agent.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.kizashiedr.agent</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/kizashi-agent</string>
    <string>--config</string><string>/etc/kizashi-agent/config.yaml</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
PLIST
launchctl load /Library/LaunchDaemons/com.kizashiedr.agent.plist`
: `cat > /etc/systemd/system/kizashi-agent.service <<EOF
[Unit]
Description=Kizashi Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/kizashi-agent --config /etc/kizashi-agent/config.yaml
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Step 5: Enable and start
systemctl daemon-reload
systemctl enable kizashi-agent
systemctl start kizashi-agent
systemctl status kizashi-agent`}`
  }

  const getDockerCommand = (): string => {
    const extraEnv = [
      agentGroup ? `  -e AGENT_GROUP=${agentGroup} \\` : '',
      namePrefix ? `  -e AGENT_NAME_PREFIX=${namePrefix} \\` : '',
      proxyURL ? `  -e HTTP_PROXY=${proxyURL} \\` : '',
    ].filter(Boolean).join('\n')

    return `docker run -d \\
  --name kizashi-agent \\
  --restart unless-stopped \\
  --privileged \\
  --pid host \\
  --network host \\
  -v /var/run/docker.sock:/var/run/docker.sock:ro \\
  -v /proc:/host/proc:ro \\
  -v /sys:/host/sys:ro \\
  -e SERVER_URL=${serverURL} \\
  -e REGISTRATION_TOKEN=${registrationToken} \\${extraEnv ? '\n' + extraEnv : ''}
  ghcr.io/kizashiedr/agent:latest`
  }

  const getKubernetesYAML = (): string => {
    return `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kizashi-agent
  namespace: kube-system
  labels:
    app: kizashi-agent
spec:
  selector:
    matchLabels:
      app: kizashi-agent
  template:
    metadata:
      labels:
        app: kizashi-agent
    spec:
      hostPID: true
      hostNetwork: true
      tolerations:
        - effect: NoSchedule
          operator: Exists
      containers:
        - name: kizashi-agent
          image: ghcr.io/kizashiedr/agent:latest
          securityContext:
            privileged: true
          env:
            - name: SERVER_URL
              value: "${serverURL}"
            - name: REGISTRATION_TOKEN
              value: "${registrationToken}"
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            ${agentGroup ? `- name: AGENT_GROUP\n              value: "${agentGroup}"` : '# - name: AGENT_GROUP'}
          volumeMounts:
            - name: proc
              mountPath: /host/proc
              readOnly: true
            - name: sys
              mountPath: /host/sys
              readOnly: true
      volumes:
        - name: proc
          hostPath:
            path: /proc
        - name: sys
          hostPath:
            path: /sys`
  }

  // ── Verify agent connection ─────────────────────────────────────────────

  const handleVerify = useCallback(async () => {
    setVerifyLoading(true)
    setVerifyError('')
    setVerifyStatus('waiting')

    try {
      const res = await apiFetch<{ agents?: AgentVerifyResult[]; data?: AgentVerifyResult[] } | AgentVerifyResult[]>(`/api/v1/agents?token=${encodeURIComponent(registrationToken)}&per_page=1`)
      const agents: AgentVerifyResult[] = Array.isArray(res) ? res : ((res as { agents?: AgentVerifyResult[]; data?: AgentVerifyResult[] })?.agents ?? (res as { data?: AgentVerifyResult[] })?.data ?? [])

      if (agents.length > 0) {
        setVerifyAgent(agents[0])
        setVerifyStatus('connected')
      } else {
        setVerifyStatus('failed')
        setVerifyError('エージェントがまだ接続されていません。インストールを完了してから再試行してください。')
      }
    } catch (err: unknown) {
      setVerifyStatus('failed')
      setVerifyError(err instanceof Error ? err.message : '確認に失敗しました')
    } finally {
      setVerifyLoading(false)
    }
  }, [registrationToken])

  // ── Render steps ───────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#060d18] text-[#e2e8f4] p-6">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
              <Download className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">エージェント配布ウィザード</h1>
              <p className="text-sm text-[#7d92b0]">ステップに従ってエージェントをインストールしてください</p>
            </div>
          </div>
        </div>

        {/* Step indicator */}
        <StepIndicator current={step} />

        {/* Card wrapper */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 shadow-xl">

          {/* ── Step 1: Select Platform ─────────────────────────── */}
          {step === 1 && (
            <div>
              <h2 className="text-lg font-semibold text-white mb-1">プラットフォームを選択</h2>
              <p className="text-sm text-[#7d92b0] mb-6">エージェントをインストールするOSを選択してください</p>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
                {PLATFORMS.map(({ id, label, icon: Icon, archs }) => (
                  <button
                    key={id}
                    onClick={() => setPlatform(id)}
                    className={`relative flex flex-col items-center gap-4 p-6 rounded-xl border-2 transition-all
                      ${platform === id
                        ? 'border-[#e8002d] bg-[#1a0810] shadow-[0_0_20px_rgba(232,0,45,0.2)]'
                        : 'border-[#1e2d42] bg-[#0d1220] hover:border-[#2d4060] hover:bg-[#111927]'
                      }`}
                  >
                    {platform === id && (
                      <span className="absolute top-3 right-3">
                        <Check className="w-4 h-4 text-[#e8002d]" />
                      </span>
                    )}
                    <div className={`w-16 h-16 rounded-2xl flex items-center justify-center
                      ${platform === id ? 'bg-[#e8002d]/20' : 'bg-[#1e2d42]'}`}>
                      <Icon className={`w-8 h-8 ${platform === id ? 'text-[#e8002d]' : 'text-[#7d92b0]'}`} />
                    </div>
                    <div className="text-center">
                      <p className={`font-semibold text-base mb-2 ${platform === id ? 'text-white' : 'text-[#a8c4e0]'}`}>
                        {label}
                      </p>
                      <div className="space-y-1">
                        {archs.map((arch) => (
                          <p key={arch} className="text-xs text-[#3d5068] flex items-center gap-1.5 justify-center">
                            <Cpu className="w-3 h-3" />
                            {arch}
                          </p>
                        ))}
                      </div>
                    </div>
                  </button>
                ))}
              </div>

              <div className="flex justify-end">
                <button
                  onClick={handleNextFromStep1}
                  disabled={!platform}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm transition-all
                    bg-[#e8002d] text-white hover:bg-[#c00025] disabled:opacity-40 disabled:cursor-not-allowed
                    shadow-[0_0_12px_rgba(232,0,45,0.3)]"
                >
                  次へ <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* ── Step 2: Configure ───────────────────────────────── */}
          {step === 2 && (
            <div>
              <h2 className="text-lg font-semibold text-white mb-1">設定</h2>
              <p className="text-sm text-[#7d92b0] mb-6">エージェントの接続設定を構成してください</p>

              <div className="space-y-5">
                {/* Server URL */}
                <div>
                  <label className="block text-sm font-medium text-[#a8c4e0] mb-1.5">
                    <Globe className="w-3.5 h-3.5 inline mr-1.5 text-[#3d5068]" />
                    サーバー URL
                  </label>
                  <input
                    type="url"
                    value={serverURL}
                    onChange={(e) => setServerURL(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-[#060d18] border border-[#1e2d42]
                      text-white text-sm focus:outline-none focus:border-[#e8002d] transition-colors
                      placeholder:text-[#3d5068]"
                    placeholder="https://your-edr-server.example.com"
                  />
                </div>

                {/* Agent Group */}
                <div>
                  <label className="block text-sm font-medium text-[#a8c4e0] mb-1.5">
                    <Layers className="w-3.5 h-3.5 inline mr-1.5 text-[#3d5068]" />
                    エージェントグループ
                  </label>
                  {loadingGroups ? (
                    <div className="flex items-center gap-2 py-2 text-sm text-[#3d5068]">
                      <Loader2 className="w-4 h-4 animate-spin" /> 読み込み中...
                    </div>
                  ) : (
                    <select
                      value={agentGroup}
                      onChange={(e) => setAgentGroup(e.target.value)}
                      className="w-full px-3 py-2.5 rounded-lg bg-[#060d18] border border-[#1e2d42]
                        text-white text-sm focus:outline-none focus:border-[#e8002d] transition-colors"
                    >
                      <option value="">グループなし（デフォルト）</option>
                      {groups.map((g) => (
                        <option key={g.id} value={g.id}>{g.name}</option>
                      ))}
                    </select>
                  )}
                </div>

                {/* Registration Token */}
                <div>
                  <label className="block text-sm font-medium text-[#a8c4e0] mb-1.5">
                    <Key className="w-3.5 h-3.5 inline mr-1.5 text-[#3d5068]" />
                    登録トークン
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={registrationToken}
                      readOnly
                      className="flex-1 px-3 py-2.5 rounded-lg bg-[#060d18] border border-[#1e2d42]
                        text-[#a8c4e0] text-sm font-mono focus:outline-none cursor-default"
                    />
                    <CopyButton text={registrationToken} />
                    <button
                      onClick={() => setRegistrationToken(generateUUID())}
                      title="再生成"
                      className="p-2.5 rounded-lg bg-[#1e2d42] text-[#7d92b0] hover:text-white
                        hover:bg-[#263a57] transition-all border border-[#1e2d42]"
                    >
                      <RefreshCw className="w-4 h-4" />
                    </button>
                  </div>
                  <p className="text-xs text-[#3d5068] mt-1.5">
                    このトークンはエージェントの最初の登録に使用されます。安全に保管してください。
                  </p>
                </div>

                {/* Agent Name Prefix */}
                <div>
                  <label className="block text-sm font-medium text-[#a8c4e0] mb-1.5">
                    <Terminal className="w-3.5 h-3.5 inline mr-1.5 text-[#3d5068]" />
                    エージェント名プレフィックス
                    <span className="ml-1.5 text-[#3d5068] font-normal text-xs">(オプション)</span>
                  </label>
                  <input
                    type="text"
                    value={namePrefix}
                    onChange={(e) => setNamePrefix(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-[#060d18] border border-[#1e2d42]
                      text-white text-sm focus:outline-none focus:border-[#e8002d] transition-colors
                      placeholder:text-[#3d5068]"
                    placeholder="例: prod-, datacenter-east-"
                  />
                </div>

                {/* Proxy Settings */}
                <div>
                  <label className="block text-sm font-medium text-[#a8c4e0] mb-1.5">
                    <Settings className="w-3.5 h-3.5 inline mr-1.5 text-[#3d5068]" />
                    プロキシ URL
                    <span className="ml-1.5 text-[#3d5068] font-normal text-xs">(オプション)</span>
                  </label>
                  <input
                    type="url"
                    value={proxyURL}
                    onChange={(e) => setProxyURL(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-lg bg-[#060d18] border border-[#1e2d42]
                      text-white text-sm focus:outline-none focus:border-[#e8002d] transition-colors
                      placeholder:text-[#3d5068]"
                    placeholder="http://proxy.example.com:8080"
                  />
                </div>
              </div>

              <div className="flex justify-between mt-8">
                <button
                  onClick={() => setStep(1)}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm
                    text-[#7d92b0] hover:text-white bg-[#1e2d42] hover:bg-[#263a57] transition-all"
                >
                  <ChevronLeft className="w-4 h-4" /> 戻る
                </button>
                <button
                  onClick={() => setStep(3)}
                  disabled={!serverURL || !registrationToken}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm
                    bg-[#e8002d] text-white hover:bg-[#c00025] disabled:opacity-40 disabled:cursor-not-allowed
                    transition-all shadow-[0_0_12px_rgba(232,0,45,0.3)]"
                >
                  次へ <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* ── Step 3: Install ─────────────────────────────────── */}
          {step === 3 && (
            <div>
              <h2 className="text-lg font-semibold text-white mb-1">インストール</h2>
              <p className="text-sm text-[#7d92b0] mb-5">
                以下のコマンドを使ってエージェントをインストールしてください
              </p>

              {/* Tab selector */}
              <div className="flex gap-1 mb-5 bg-[#060d18] rounded-lg p-1 border border-[#1e2d42]">
                {([
                  { id: 'oneliner' as InstallTab, label: 'ワンライナー', icon: Terminal },
                  { id: 'manual'   as InstallTab, label: '手動', icon: Settings },
                  { id: 'docker'   as InstallTab, label: 'Docker', icon: Server },
                  { id: 'kubernetes' as InstallTab, label: 'Kubernetes', icon: Layers },
                ] as const).map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    onClick={() => setInstallTab(id)}
                    className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded text-xs font-medium transition-all
                      ${installTab === id
                        ? 'bg-[#1e2d42] text-white'
                        : 'text-[#3d5068] hover:text-[#7d92b0]'
                      }`}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">{label}</span>
                  </button>
                ))}
              </div>

              {/* Tab content */}
              {installTab === 'oneliner' && (
                <div className="space-y-4">
                  <p className="text-xs text-[#7d92b0]">
                    {platform === 'windows'
                      ? 'PowerShell（管理者権限）で実行してください：'
                      : 'ターミナルで以下のコマンドを実行してください：'}
                  </p>
                  <CodeBlock code={getOneLinear()} lang={platform === 'windows' ? 'powershell' : 'bash'} />
                  <div className="p-4 rounded-lg bg-[#060d18] border border-[#1e2d42]">
                    <p className="text-xs text-[#7d92b0] flex items-start gap-2">
                      <Shield className="w-4 h-4 text-[#3d5068] flex-shrink-0 mt-0.5" />
                      スクリプトを実行する前に内容を確認することをお勧めします。
                      <a
                        href={`${serverURL}/api/v1/installer/script?os=${platform}&token=${registrationToken}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[#1a6bff] hover:underline whitespace-nowrap"
                      >
                        スクリプトを確認 →
                      </a>
                    </p>
                  </div>
                  <div className="flex justify-end">
                    <a
                      href={`${serverURL}/api/v1/installer/script?os=${platform ?? 'linux'}&token=${registrationToken}${agentGroup ? `&group=${agentGroup}` : ''}`}
                      download={`install-kizashi-agent-${platform}.sh`}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                        bg-[#1e2d42] text-[#7d92b0] hover:text-white hover:bg-[#263a57] transition-all border border-[#1e2d42]"
                    >
                      <Download className="w-4 h-4" />
                      インストーラーをダウンロード
                    </a>
                  </div>
                </div>
              )}

              {installTab === 'manual' && (
                <div className="space-y-4">
                  <p className="text-xs text-[#7d92b0]">手動インストール手順：</p>
                  <CodeBlock code={getManualSteps()} lang={platform === 'windows' ? 'powershell' : 'bash'} />
                </div>
              )}

              {installTab === 'docker' && (
                <div className="space-y-4">
                  <p className="text-xs text-[#7d92b0]">Docker で起動する場合：</p>
                  <CodeBlock code={getDockerCommand()} lang="bash" />
                  <div className="p-4 rounded-lg bg-[#060d18] border border-[#1e2d42]">
                    <p className="text-xs text-[#7d92b0]">
                      Docker イメージは <code className="text-[#a8c4e0]">ghcr.io/kizashiedr/agent:latest</code> から取得します。
                      <br />必要な権限（<code className="text-[#a8c4e0]">--privileged</code>、<code className="text-[#a8c4e0]">--pid host</code>）はエンドポイント監視に必要です。
                    </p>
                  </div>
                </div>
              )}

              {installTab === 'kubernetes' && (
                <div className="space-y-4">
                  <p className="text-xs text-[#7d92b0]">
                    Kubernetes DaemonSet として全ノードにデプロイ：
                  </p>
                  <CodeBlock code={getKubernetesYAML()} lang="yaml" />
                  <div className="flex flex-wrap gap-2">
                    <CopyButton text={getKubernetesYAML()} className="text-sm px-4 py-2" />
                    <button
                      onClick={() => {
                        const blob = new Blob([getKubernetesYAML()], { type: 'text/yaml' })
                        const url = URL.createObjectURL(blob)
                        const a = document.createElement('a')
                        a.href = url
                        a.download = 'kizashi-agent-daemonset.yaml'
                        a.click()
                        URL.revokeObjectURL(url)
                      }}
                      className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium
                        bg-[#1e2d42] text-[#7d92b0] hover:text-white hover:bg-[#263a57] transition-all border border-[#1e2d42]"
                    >
                      <Download className="w-4 h-4" />
                      YAML をダウンロード
                    </button>
                  </div>
                  <div className="p-4 rounded-lg bg-[#060d18] border border-[#1e2d42] text-xs text-[#7d92b0] space-y-1">
                    <p className="font-semibold text-[#a8c4e0]">デプロイ手順:</p>
                    <p>1. 上の YAML をファイルに保存します（例: <code className="text-[#a8c4e0]">kizashi-agent-daemonset.yaml</code>）</p>
                    <p>2. <code className="text-[#a8c4e0]">kubectl apply -f kizashi-agent-daemonset.yaml</code> を実行します</p>
                    <p>3. <code className="text-[#a8c4e0]">kubectl get pods -n kube-system -l app=kizashi-agent</code> で確認します</p>
                  </div>
                </div>
              )}

              <div className="flex justify-between mt-8">
                <button
                  onClick={() => setStep(2)}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm
                    text-[#7d92b0] hover:text-white bg-[#1e2d42] hover:bg-[#263a57] transition-all"
                >
                  <ChevronLeft className="w-4 h-4" /> 戻る
                </button>
                <button
                  onClick={() => { setStep(4); setVerifyStatus('waiting') }}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm
                    bg-[#e8002d] text-white hover:bg-[#c00025] transition-all
                    shadow-[0_0_12px_rgba(232,0,45,0.3)]"
                >
                  次へ <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* ── Step 4: Verify ──────────────────────────────────── */}
          {step === 4 && (
            <div>
              <h2 className="text-lg font-semibold text-white mb-1">接続確認</h2>
              <p className="text-sm text-[#7d92b0] mb-6">
                エージェントのインストール完了後、接続を確認してください
              </p>

              {/* Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-6">
                <div className="p-3 rounded-lg bg-[#060d18] border border-[#1e2d42]">
                  <p className="text-xs text-[#3d5068] mb-0.5">プラットフォーム</p>
                  <p className="text-sm font-medium text-white capitalize">{platform}</p>
                </div>
                <div className="p-3 rounded-lg bg-[#060d18] border border-[#1e2d42]">
                  <p className="text-xs text-[#3d5068] mb-0.5">サーバー URL</p>
                  <p className="text-sm font-medium text-white truncate" title={serverURL}>{serverURL}</p>
                </div>
                <div className="p-3 rounded-lg bg-[#060d18] border border-[#1e2d42] col-span-2 sm:col-span-1">
                  <p className="text-xs text-[#3d5068] mb-0.5">登録トークン</p>
                  <p className="text-sm font-mono text-[#a8c4e0] truncate" title={registrationToken}>
                    {registrationToken.substring(0, 18)}...
                  </p>
                </div>
              </div>

              {/* Verify button */}
              <div className="flex flex-col items-center gap-4 py-6">
                <button
                  onClick={handleVerify}
                  disabled={verifyLoading}
                  className="flex items-center gap-2.5 px-6 py-3 rounded-xl font-semibold text-sm
                    bg-[#1a3a6b] text-[#4a9eff] hover:bg-[#1f4480] hover:text-white
                    border border-[#1a6bff]/30 hover:border-[#1a6bff]/60
                    disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {verifyLoading
                    ? <><Loader2 className="w-4 h-4 animate-spin" /> 確認中...</>
                    : <><RefreshCw className="w-4 h-4" /> エージェント接続を確認</>
                  }
                </button>

                {/* Status indicator */}
                {verifyStatus === 'waiting' && !verifyLoading && (
                  <p className="text-sm text-[#3d5068] text-center max-w-sm">
                    エージェントをインストールしたら「確認」ボタンをクリックしてください
                  </p>
                )}

                {verifyStatus === 'connected' && verifyAgent && (
                  <div className="w-full max-w-md p-5 rounded-xl bg-[#001a0d] border border-[#00c853]/30">
                    <div className="flex items-center gap-2 mb-4">
                      <CheckCircle2 className="w-5 h-5 text-[#00c853]" />
                      <span className="font-semibold text-[#00c853]">エージェントが接続されました</span>
                    </div>
                    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                      <dt className="text-[#3d5068]">ホスト名</dt>
                      <dd className="text-white font-medium">{verifyAgent.hostname}</dd>
                      <dt className="text-[#3d5068]">ステータス</dt>
                      <dd className="text-[#00c853] font-medium capitalize">{verifyAgent.status}</dd>
                      <dt className="text-[#3d5068]">バージョン</dt>
                      <dd className="text-[#a8c4e0]">{verifyAgent.version || 'N/A'}</dd>
                      <dt className="text-[#3d5068]">プラットフォーム</dt>
                      <dd className="text-[#a8c4e0] capitalize">{verifyAgent.platform || platform}</dd>
                      <dt className="text-[#3d5068]">最終確認</dt>
                      <dd className="text-[#a8c4e0]">
                        {verifyAgent.last_seen ? new Date(verifyAgent.last_seen).toLocaleString('ja-JP') : 'N/A'}
                      </dd>
                    </dl>
                  </div>
                )}

                {verifyStatus === 'failed' && (
                  <div className="w-full max-w-md p-5 rounded-xl bg-[#1a0810] border border-[#e8002d]/30">
                    <div className="flex items-start gap-2 mb-2">
                      <AlertCircle className="w-5 h-5 text-[#e8002d] flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-semibold text-[#e8002d]">接続が確認できませんでした</p>
                        {verifyError && (
                          <p className="text-sm text-[#7d92b0] mt-1">{verifyError}</p>
                        )}
                      </div>
                    </div>
                    <ul className="mt-3 space-y-1 text-xs text-[#7d92b0] list-disc list-inside">
                      <li>エージェントがインストールされ、起動していることを確認してください</li>
                      <li>ファイアウォールでポート 443/8080 が許可されているか確認してください</li>
                      <li>サーバー URL とトークンが正しいか確認してください</li>
                      <li>しばらく待ってから再試行してください</li>
                    </ul>
                  </div>
                )}
              </div>

              <div className="flex justify-between mt-4">
                <button
                  onClick={() => setStep(3)}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm
                    text-[#7d92b0] hover:text-white bg-[#1e2d42] hover:bg-[#263a57] transition-all"
                >
                  <ChevronLeft className="w-4 h-4" /> 戻る
                </button>
                {verifyStatus === 'connected' && (
                  <a
                    href="/endpoints"
                    className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm
                      bg-[#00c853]/20 text-[#00c853] border border-[#00c853]/30
                      hover:bg-[#00c853]/30 transition-all"
                  >
                    エンドポイント一覧へ <ChevronRight className="w-4 h-4" />
                  </a>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
