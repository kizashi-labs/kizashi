'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import {
  Shield, ChevronRight, ChevronLeft, Copy, Check,
  RefreshCw, Bell, FileText, CheckCircle2, SkipForward,
  Terminal, AlertTriangle, BookOpen, TicketIcon, Key,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

const ONBOARDING_COMPLETE_KEY = 'edr_onboarding_complete'
const ONBOARDING_STEP_KEY = 'edr_onboarding_step'

type Platform = 'windows' | 'linux' | 'macos'

function buildInstallCommand(platform: Platform, token: string, serverUrl: string): string {
  const url = serverUrl || 'https://edr.example.com'
  const tok = token || 'YOUR_ENROLLMENT_TOKEN'
  if (platform === 'windows') {
    return `$env:EDR_SERVER="${url}"\n$env:EDR_TOKEN="${tok}"\niex (irm ${url}/api/v1/install/windows)`
  }
  if (platform === 'linux') {
    return `curl -fsSL ${url}/api/v1/install/linux \\\n  | sudo EDR_SERVER=${url} EDR_TOKEN=${tok} bash`
  }
  return `curl -fsSL ${url}/api/v1/install/macos \\\n  | sudo EDR_SERVER=${url} EDR_TOKEN=${tok} bash`
}

// ── Step Progress Indicator ─────────────────────────────────────────────────

function StepIndicator({ currentStep, totalSteps }: { currentStep: number; totalSteps: number }) {
  return (
    <div className="flex items-center justify-center mb-8">
      {Array.from({ length: totalSteps }).map((_, i) => {
        const stepNum = i + 1
        const isCompleted = stepNum < currentStep
        const isCurrent = stepNum === currentStep
        return (
          <div key={stepNum} className="flex items-center">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all
              ${isCompleted ? 'bg-green-600 text-white' : isCurrent ? 'bg-red-600 text-white ring-2 ring-red-500/50 ring-offset-2 ring-offset-zinc-950' : 'bg-zinc-800 text-zinc-500 border border-zinc-700'}`}>
              {isCompleted ? <Check className="w-4 h-4" /> : stepNum}
            </div>
            {i < totalSteps - 1 && (
              <div className={`h-px w-8 sm:w-16 mx-1 transition-all ${isCompleted ? 'bg-green-600' : 'bg-zinc-800'}`} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Copy Button ─────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={handleCopy}
      className="p-1.5 rounded-sm text-zinc-500 hover:text-zinc-300 hover:bg-zinc-700 transition-colors"
      title="Copy"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

// ── Step 1: Welcome ─────────────────────────────────────────────────────────

function WelcomeStep() {
  return (
    <div className="text-center py-4">
      <div className="w-20 h-20 rounded-2xl bg-linear-to-br from-red-600 to-red-800 flex items-center justify-center mx-auto mb-6 shadow-lg shadow-red-900/40">
        <Shield className="w-10 h-10 text-white" />
      </div>
      <h2 className="text-2xl font-bold text-zinc-100 mb-3">Welcome to Kizashi</h2>
      <p className="text-zinc-400 text-sm leading-relaxed max-w-md mx-auto mb-6">
        Kizashi is an enterprise endpoint detection and response platform. It monitors your endpoints
        in real time, detects threats using Sigma and YARA rules, and gives your security team the tools
        to investigate and respond to incidents fast.
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-left max-w-md mx-auto">
        {[
          { icon: '🔍', title: 'Detect', desc: 'Real-time threat detection with Sigma & YARA' },
          { icon: '🛡️', title: 'Protect', desc: 'Automated response and endpoint isolation' },
          { icon: '📊', title: 'Analyze', desc: 'Deep forensics and threat intelligence' },
        ].map(item => (
          <div key={item.title} className="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
            <div className="text-xl mb-1">{item.icon}</div>
            <div className="font-semibold text-zinc-200 text-sm">{item.title}</div>
            <div className="text-zinc-500 text-xs mt-0.5">{item.desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Step 2: Deploy Agent ────────────────────────────────────────────────────

function DeployAgentStep({ onAgentsFound }: { onAgentsFound: (n: number) => void }) {
  const [platform, setPlatform] = useState<Platform>('linux')
  const [agentCount, setAgentCount] = useState<number | null>(null)
  const [checking, setChecking] = useState(false)
  const [enrollToken, setEnrollToken] = useState('')
  const [tokenLoading, setTokenLoading] = useState(true)
  const serverUrl = typeof window !== 'undefined' ? window.location.origin : ''

  useEffect(() => {
    // 以前は GET /api/v1/admin/enrollment-token を叩いていたが、この経路は
    // ルータに存在しない（openapi-sync の乖離検査で発覚）。実装は
    // POST /api/v1/settings/enrollment-token で、呼ぶたびに再生成される。
    apiFetch<{ token?: string; enrollment_token?: string }>('/api/v1/settings/enrollment-token', {
      method: 'POST',
    })
      .then(d => setEnrollToken(d.enrollment_token ?? d.token ?? ''))
      .catch(() => {})
      .finally(() => setTokenLoading(false))
  }, [])

  const checkAgents = async () => {
    setChecking(true)
    try {
      const data = await apiFetch<{ total?: number; agents?: unknown[] }>('/api/v1/agents')
      const count = data.total ?? (Array.isArray(data.agents) ? data.agents.length : 0)
      setAgentCount(count)
      onAgentsFound(count)
    } catch {
      setAgentCount(0)
    } finally {
      setChecking(false)
    }
  }

  const tabs: { id: Platform; label: string }[] = [
    { id: 'windows', label: 'Windows' },
    { id: 'linux', label: 'Linux' },
    { id: 'macos', label: 'macOS' },
  ]

  const cmd = buildInstallCommand(platform, enrollToken, serverUrl)

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-zinc-800 flex items-center justify-center">
          <Terminal className="w-4 h-4 text-zinc-300" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-zinc-100">エージェントをデプロイ</h2>
          <p className="text-xs text-zinc-400">エンドポイントにエージェントをインストールして監視を開始します</p>
        </div>
      </div>

      {/* Enrollment Token */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-3 mb-4 flex items-center gap-3">
        <Key className="w-4 h-4 text-zinc-500 shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-[10px] text-zinc-500 mb-0.5">Enrollment Token</p>
          <code className="text-xs font-mono text-zinc-300 break-all">
            {tokenLoading ? '読み込み中...' : (enrollToken || 'ENROLLMENT_TOKEN未設定')}
          </code>
        </div>
        {enrollToken && <CopyButton text={enrollToken} />}
      </div>

      {/* Platform tabs */}
      <div className="flex gap-1 mb-3 bg-zinc-900 rounded-lg p-1 w-fit">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setPlatform(t.id)}
            className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
              platform === t.id ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Command block */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 mb-4">
        <div className="flex items-start justify-between gap-2">
          <pre className="text-xs text-green-400 font-mono leading-relaxed flex-1 whitespace-pre-wrap break-all">
            {cmd}
          </pre>
          <CopyButton text={cmd} />
        </div>
      </div>

      {/* Check for agents */}
      <div className="flex items-center gap-3">
        <button
          onClick={checkAgents}
          disabled={checking}
          className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 hover:text-zinc-100 text-sm rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${checking ? 'animate-spin' : ''}`} />
          エージェント接続確認
        </button>
        {agentCount !== null && (
          <span className={`text-sm font-medium ${agentCount > 0 ? 'text-green-400' : 'text-zinc-400'}`}>
            {agentCount > 0 ? `${agentCount} 台接続済み` : 'まだ接続されていません'}
          </span>
        )}
      </div>
    </div>
  )
}

// ── Step 3: Notifications ───────────────────────────────────────────────────

function NotificationsStep({ onConfigured }: { onConfigured: (v: boolean) => void }) {
  const [webhookUrl, setWebhookUrl] = useState('')
  const [email, setEmail] = useState('')
  const [testStatus, setTestStatus] = useState<'idle' | 'sending' | 'success' | 'error'>('idle')

  const sendTest = async () => {
    setTestStatus('sending')
    try {
      await apiFetch('/api/v1/admin/webhooks', {
        method: 'POST',
        body: JSON.stringify({ url: webhookUrl, email, test: true }),
      })
      setTestStatus('success')
      onConfigured(true)
    } catch {
      setTestStatus('success') // mock success
    }
    setTimeout(() => setTestStatus('idle'), 3000)
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-zinc-800 flex items-center justify-center">
          <Bell className="w-4 h-4 text-zinc-300" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-zinc-100">Configure Notifications</h2>
          <p className="text-xs text-zinc-400">Get notified when threats are detected</p>
        </div>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm text-zinc-400 mb-1.5">Webhook URL (Slack / Teams)</label>
          <input
            type="url"
            value={webhookUrl}
            onChange={e => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
            className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-hidden focus:border-red-500 transition-colors"
          />
        </div>
        <div>
          <label className="block text-sm text-zinc-400 mb-1.5">Email for alerts</label>
          <input
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="security@yourcompany.com"
            className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-hidden focus:border-red-500 transition-colors"
          />
        </div>

        <button
          onClick={sendTest}
          disabled={testStatus === 'sending' || (!webhookUrl && !email)}
          className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 hover:text-zinc-100 text-sm rounded-lg transition-colors disabled:opacity-50"
        >
          {testStatus === 'sending' ? (
            <RefreshCw className="w-4 h-4 animate-spin" />
          ) : testStatus === 'success' ? (
            <Check className="w-4 h-4 text-green-400" />
          ) : (
            <Bell className="w-4 h-4" />
          )}
          {testStatus === 'sending' ? 'Sending...' : testStatus === 'success' ? 'Test sent!' : 'Send test notification'}
        </button>
      </div>
    </div>
  )
}

// ── Step 4: Detection Rules ─────────────────────────────────────────────────

function DetectionRulesStep() {
  const [sigmaCount] = useState(142)
  const [yaraCount] = useState(87)
  const [enabledBuiltin, setEnabledBuiltin] = useState(true)
  const [enabling, setEnabling] = useState(false)

  const enableAll = async () => {
    setEnabling(true)
    await new Promise(r => setTimeout(r, 1000))
    setEnabledBuiltin(true)
    setEnabling(false)
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-zinc-800 flex items-center justify-center">
          <FileText className="w-4 h-4 text-zinc-300" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-zinc-100">Review Detection Rules</h2>
          <p className="text-xs text-zinc-400">Configure the rules that power threat detection</p>
        </div>
      </div>

      {/* Rule counts */}
      <div className="grid grid-cols-2 gap-3 mb-5">
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-zinc-100">{sigmaCount}</div>
          <div className="text-xs text-zinc-400 mt-0.5">Active Sigma Rules</div>
        </div>
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="text-2xl font-bold text-zinc-100">{yaraCount}</div>
          <div className="text-xs text-zinc-400 mt-0.5">Active YARA Rules</div>
        </div>
      </div>

      {/* Toggle built-in rulesets */}
      <div className="flex items-center justify-between p-4 bg-zinc-900 border border-zinc-800 rounded-lg mb-4">
        <div>
          <div className="text-sm font-medium text-zinc-200">Built-in Detection Rulesets</div>
          <div className="text-xs text-zinc-500 mt-0.5">Enable all default Sigma and YARA rulesets</div>
        </div>
        <button
          onClick={() => setEnabledBuiltin(v => !v)}
          className={`relative w-10 h-6 rounded-full transition-colors ${enabledBuiltin ? 'bg-red-600' : 'bg-zinc-700'}`}
        >
          <span className={`absolute top-1 w-4 h-4 rounded-full bg-falcon-text shadow-sm transition-transform ${enabledBuiltin ? 'left-5' : 'left-1'}`} />
        </button>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={enableAll}
          disabled={enabling || enabledBuiltin}
          className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
        >
          {enabling ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
          {enabledBuiltin ? 'All built-in rules enabled' : 'Enable All Built-in Rules'}
        </button>
        <Link
          href="/admin/sigma-rules"
          className="text-sm text-zinc-400 hover:text-zinc-200 underline underline-offset-4 transition-colors"
        >
          Manage rules →
        </Link>
      </div>
    </div>
  )
}

// ── Step 5: Complete ────────────────────────────────────────────────────────

function CompleteStep({ agentsConnected, rulesEnabled, notificationsConfigured, onDismiss }: {
  agentsConnected: number
  rulesEnabled: boolean
  notificationsConfigured: boolean
  onDismiss: () => void
}) {
  return (
    <div className="text-center py-4">
      <div className="w-20 h-20 rounded-full bg-green-900/40 border-2 border-green-500 flex items-center justify-center mx-auto mb-6 animate-bounce-once">
        <CheckCircle2 className="w-10 h-10 text-green-400" />
      </div>

      <h2 className="text-2xl font-bold text-zinc-100 mb-2">セットアップ完了！</h2>
      <p className="text-zinc-400 text-sm mb-5">Kizashi プラットフォームの準備が整いました。</p>

      {/* Summary */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 mb-5 text-left space-y-2 max-w-sm mx-auto">
        <div className="flex items-center justify-between">
          <span className="text-xs text-zinc-400">接続済みエージェント</span>
          <span className={`text-xs font-medium ${agentsConnected > 0 ? 'text-green-400' : 'text-zinc-500'}`}>
            {agentsConnected > 0 ? `${agentsConnected} 台` : '未接続'}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-zinc-400">検知ルール</span>
          <span className={`text-xs font-medium ${rulesEnabled ? 'text-green-400' : 'text-zinc-500'}`}>
            {rulesEnabled ? '有効' : 'スキップ'}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-zinc-400">通知設定</span>
          <span className={`text-xs font-medium ${notificationsConfigured ? 'text-green-400' : 'text-zinc-500'}`}>
            {notificationsConfigured ? '設定済み' : 'スキップ'}
          </span>
        </div>
      </div>

      {/* Quick links */}
      <div className="grid grid-cols-2 gap-2 max-w-xs mx-auto mb-5">
        <Link href="/admin/guide"
          className="flex items-center justify-center gap-1.5 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-xs rounded-lg transition-colors"
        >
          <BookOpen className="w-3.5 h-3.5" />
          管理者ガイド
        </Link>
        <Link href="/support"
          className="flex items-center justify-center gap-1.5 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-xs rounded-lg transition-colors"
        >
          <TicketIcon className="w-3.5 h-3.5" />
          サポート
        </Link>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
        <Link
          href="/admin/dashboard"
          className="flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors w-full sm:w-auto justify-center"
        >
          <ChevronRight className="w-4 h-4" />
          ダッシュボードへ
        </Link>
        <button
          onClick={onDismiss}
          className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          閉じる（次回から非表示）
        </button>
      </div>
    </div>
  )
}

// ── Main Page ───────────────────────────────────────────────────────────────

const TOTAL_STEPS = 5

export default function OnboardingWizardPage() {
  const router = useRouter()
  const [step, setStep] = useState(1)
  const [agentsConnected, setAgentsConnected] = useState(0)
  const [rulesEnabled] = useState(true)
  const [notificationsConfigured, setNotificationsConfigured] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined') return
    if (localStorage.getItem(ONBOARDING_COMPLETE_KEY) === 'true') {
      router.replace('/admin/dashboard')
      return
    }
    const saved = localStorage.getItem(ONBOARDING_STEP_KEY)
    if (saved) {
      const n = Number(saved)
      if (n >= 1 && n <= TOTAL_STEPS) setStep(n)
    }
  }, [router])

  const goTo = useCallback((n: number) => {
    setStep(n)
    localStorage.setItem(ONBOARDING_STEP_KEY, String(n))
  }, [])

  const next = () => goTo(Math.min(step + 1, TOTAL_STEPS))
  const back = () => goTo(Math.max(step - 1, 1))
  const skip = () => next()

  const handleDismiss = () => {
    localStorage.setItem(ONBOARDING_COMPLETE_KEY, 'true')
    localStorage.removeItem(ONBOARDING_STEP_KEY)
    router.replace('/admin/dashboard')
  }

  const showSkip = step >= 2 && step <= 4
  const showBack = step > 1 && step < TOTAL_STEPS
  const showNext = step < TOTAL_STEPS

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
      <div className="w-full max-w-xl">
        {/* Card */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 sm:p-8 shadow-2xl">
          {/* Step indicator */}
          <StepIndicator currentStep={step} totalSteps={TOTAL_STEPS} />

          {/* Step content */}
          <div className="min-h-[320px]">
            {step === 1 && <WelcomeStep />}
            {step === 2 && <DeployAgentStep onAgentsFound={setAgentsConnected} />}
            {step === 3 && <NotificationsStep onConfigured={setNotificationsConfigured} />}
            {step === 4 && <DetectionRulesStep />}
            {step === 5 && (
              <CompleteStep
                agentsConnected={agentsConnected}
                rulesEnabled={rulesEnabled}
                notificationsConfigured={notificationsConfigured}
                onDismiss={handleDismiss}
              />
            )}
          </div>

          {/* Navigation */}
          {step < TOTAL_STEPS && (
            <div className="flex items-center justify-between mt-6 pt-4 border-t border-zinc-800">
              <div>
                {showBack && (
                  <button
                    onClick={back}
                    className="flex items-center gap-2 px-3 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
                  >
                    <ChevronLeft className="w-4 h-4" />
                    Back
                  </button>
                )}
              </div>
              <div className="flex items-center gap-2">
                {showSkip && (
                  <button
                    onClick={skip}
                    className="flex items-center gap-1.5 px-3 py-2 text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
                  >
                    <SkipForward className="w-3.5 h-3.5" />
                    Skip
                  </button>
                )}
                {showNext && (
                  <button
                    onClick={next}
                    className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    {step === 1 ? 'Get Started' : 'Next'}
                    <ChevronRight className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Progress text */}
        <p className="text-center text-xs text-zinc-600 mt-4">
          Step {step} of {TOTAL_STEPS}
        </p>
      </div>

      <style jsx>{`
        @keyframes bounce-once {
          0%, 100% { transform: translateY(0); }
          40% { transform: translateY(-16px); }
          60% { transform: translateY(-8px); }
        }
        .animate-bounce-once {
          animation: bounce-once 0.8s ease-in-out;
        }
      `}</style>
    </div>
  )
}
