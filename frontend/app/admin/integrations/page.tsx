'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Puzzle,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  ChevronRight,
  Info,
  Bell,
  Workflow,
  Shield,
  Ticket,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ──────────────────────────────────────────────────────────────────────

type IntegrationStatus = 'connected' | 'disconnected' | 'error' | 'pending'
type TestState = 'idle' | 'testing' | 'success' | 'error'

interface IntegrationCardProps {
  name: string
  description: string
  status: IntegrationStatus
  logoPlaceholder: React.ReactNode
  configHref: string
  onTest?: () => void
  testState?: TestState
  children?: React.ReactNode
}

// ─── Status badge ────────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: IntegrationStatus }) {
  const map: Record<IntegrationStatus, { label: string; cls: string; dot?: string }> = {
    connected:    { label: '接続中',   cls: 'bg-emerald-900/30 text-emerald-300 border-emerald-700/40', dot: 'bg-emerald-400' },
    disconnected: { label: '未接続',   cls: 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]' },
    error:        { label: 'エラー',   cls: 'bg-red-900/30 text-red-400 border-red-700/40',         dot: 'bg-red-400' },
    pending:      { label: '設定中',   cls: 'bg-yellow-900/30 text-yellow-400 border-yellow-700/40', dot: 'bg-yellow-400' },
  }
  const { label, cls, dot } = map[status]
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${cls}`}>
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${dot} ${status === 'connected' ? 'animate-pulse' : ''}`} />}
      {label}
    </span>
  )
}

// ─── Integration Card ────────────────────────────────────────────────────────────

function IntegrationCard({
  name,
  description,
  status,
  logoPlaceholder,
  configHref,
  onTest,
  testState = 'idle',
  children,
}: IntegrationCardProps) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-start gap-3">
          <div className="shrink-0 mt-0.5">{logoPlaceholder}</div>
          <div>
            <h3 className="text-white font-semibold">{name}</h3>
            <p className="text-[#7d92b0] text-sm mt-1">{description}</p>
          </div>
        </div>
        <StatusBadge status={status} />
      </div>

      {children && (
        <div className="mt-4 mb-4 space-y-3">{children}</div>
      )}

      <div className="flex gap-2 mt-4">
        {onTest && (
          <button
            onClick={onTest}
            disabled={testState === 'testing'}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {testState === 'testing' ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : testState === 'success' ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            ) : testState === 'error' ? (
              <XCircle className="w-3.5 h-3.5 text-red-400" />
            ) : (
              <RefreshCw className="w-3.5 h-3.5" />
            )}
            テスト
          </button>
        )}
        <a
          href={configHref}
          className="px-3 py-1.5 text-sm bg-[#e8002d] hover:bg-[#c0001f] rounded-sm text-white transition-colors"
        >
          設定
        </a>
      </div>
    </div>
  )
}

// ─── Logo placeholders ───────────────────────────────────────────────────────────

function ElasticLogo() {
  return (
    <div
      className="w-9 h-9 rounded-lg flex items-center justify-center text-white font-bold text-base"
      style={{ background: 'radial-gradient(circle at 35% 35%, #ff8a00, #e07000)' }}
    >
      E
    </div>
  )
}

function SplunkLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#65a637] flex items-center justify-center text-white font-bold text-base">
      S
    </div>
  )
}

function SentinelLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#0078d4] flex items-center justify-center text-white font-bold text-base">
      M
    </div>
  )
}

function QRadarLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#1f70c1] flex items-center justify-center text-white font-bold text-base">
      Q
    </div>
  )
}

function JiraLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#0052cc] flex items-center justify-center text-white font-bold text-base">
      J
    </div>
  )
}

function ServiceNowLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#62d84e] flex items-center justify-center text-white font-bold text-base">
      S
    </div>
  )
}

function PagerDutyLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#06ac38] flex items-center justify-center text-white font-bold text-base">
      P
    </div>
  )
}

function SlackLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#4a154b] flex items-center justify-center text-white font-bold text-base">
      Sl
    </div>
  )
}

function TeamsLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#6264a7] flex items-center justify-center text-white font-bold text-base">
      T
    </div>
  )
}

function WebhookLogo() {
  return (
    <div className="w-9 h-9 rounded-lg bg-[#1e2d42] border border-[#2d4060] flex items-center justify-center text-[#7d92b0] font-bold text-xs">
      WH
    </div>
  )
}

// ─── SIEM tab ────────────────────────────────────────────────────────────────────

function SiemTab() {
  const [elasticTest, setElasticTest] = useState<TestState>('idle')
  const [splunkTest, setSplunkTest] = useState<TestState>('idle')
  const [sentinelTest, setSentinelTest] = useState<TestState>('idle')
  const [qradarTest, setQRadarTest] = useState<TestState>('idle')

  const runTest = async (
    setter: React.Dispatch<React.SetStateAction<TestState>>,
    endpoint: string,
  ) => {
    setter('testing')
    try {
      await apiFetch(endpoint, { method: 'POST' })
      setter('success')
    } catch {
      setter('error')
    } finally {
      setTimeout(() => setter('idle'), 3000)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-white mb-1">SIEM 連携</h2>
        <p className="text-sm text-[#7d92b0]">
          セキュリティ情報・イベント管理 (SIEM) システムへのデータ転送設定
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        {/* Elastic SIEM */}
        <IntegrationCard
          name="Elastic SIEM"
          description="Elasticsearch / Elastic Security にアラートとエージェントデータを転送します"
          status="connected"
          logoPlaceholder={<ElasticLogo />}
          configHref="/admin/integrations/elastic"
          onTest={() => runTest(setElasticTest, '/api/v1/admin/integrations/elastic/test')}
          testState={elasticTest}
        >
          <div className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg border border-[#1e2d42] px-3 py-2">
            <span className="text-[#3d5068]">URL:</span>{' '}
            <span className="font-mono">https://elastic.corp:9200</span>
          </div>
        </IntegrationCard>

        {/* Splunk */}
        <IntegrationCard
          name="Splunk"
          description="Splunk HEC 経由でイベントデータをリアルタイム転送します"
          status="disconnected"
          logoPlaceholder={<SplunkLogo />}
          configHref="/admin/integrations/splunk"
          onTest={() => runTest(setSplunkTest, '/api/v1/admin/integrations/splunk/test')}
          testState={splunkTest}
        >
          <div className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg border border-[#1e2d42] px-3 py-2">
            <span className="text-[#3d5068]">HEC URL:</span>{' '}
            <span className="font-mono text-[#3d5068]">未設定</span>
          </div>
        </IntegrationCard>

        {/* Microsoft Sentinel */}
        <IntegrationCard
          name="Microsoft Sentinel"
          description="Azure Log Analytics / Microsoft Sentinel へセキュリティデータを送信します"
          status="pending"
          logoPlaceholder={<SentinelLogo />}
          configHref="/admin/integrations/sentinel"
          onTest={() => runTest(setSentinelTest, '/api/v1/admin/integrations/sentinel/test')}
          testState={sentinelTest}
        >
          <div className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg border border-[#1e2d42] px-3 py-2">
            <span className="text-[#3d5068]">Workspace ID:</span>{' '}
            <span className="font-mono">a4b2c1d3-****-****-****-f0e1d2c3b4a5</span>
          </div>
        </IntegrationCard>

        {/* QRadar */}
        <IntegrationCard
          name="IBM QRadar"
          description="QRadar SIEM にアラートとフローデータを転送します"
          status="disconnected"
          logoPlaceholder={<QRadarLogo />}
          configHref="/admin/integrations/qradar"
          onTest={() => runTest(setQRadarTest, '/api/v1/admin/integrations/qradar/test')}
          testState={qradarTest}
        >
          <div className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg border border-[#1e2d42] px-3 py-2">
            <span className="text-[#3d5068]">Console IP:</span>{' '}
            <span className="font-mono text-[#3d5068]">未設定</span>
          </div>
        </IntegrationCard>
      </div>
    </div>
  )
}

// ─── SOAR tab ────────────────────────────────────────────────────────────────────

function SoarTab() {
  const [jiraTest, setJiraTest] = useState<TestState>('idle')
  const [snTest, setSnTest] = useState<TestState>('idle')

  const runTest = async (
    setter: React.Dispatch<React.SetStateAction<TestState>>,
    endpoint: string,
  ) => {
    setter('testing')
    try {
      await apiFetch(endpoint, { method: 'POST' })
      setter('success')
    } catch {
      setter('error')
    } finally {
      setTimeout(() => setter('idle'), 3000)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-white mb-1">SOAR / チケッティング連携</h2>
        <p className="text-sm text-[#7d92b0]">
          セキュリティオーケストレーション・自動対応 (SOAR) とチケットシステムの設定
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <IntegrationCard
          name="Jira"
          description="アラート検知時に自動で Jira チケットを作成します"
          status="connected"
          logoPlaceholder={<JiraLogo />}
          configHref="/admin/integrations/soar"
          onTest={() => runTest(setJiraTest, '/api/v1/soar/jira/test')}
          testState={jiraTest}
        >
          <div className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg border border-[#1e2d42] px-3 py-2">
            <span className="text-[#3d5068]">プロジェクト:</span>{' '}
            <span className="font-mono">SEC</span>
          </div>
        </IntegrationCard>

        <IntegrationCard
          name="ServiceNow"
          description="インシデントを ServiceNow に自動起票します"
          status="disconnected"
          logoPlaceholder={<ServiceNowLogo />}
          configHref="/admin/integrations/soar"
          onTest={() => runTest(setSnTest, '/api/v1/soar/servicenow/test')}
          testState={snTest}
        >
          <div className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg border border-[#1e2d42] px-3 py-2">
            <span className="text-[#3d5068]">インスタンス:</span>{' '}
            <span className="font-mono text-[#3d5068]">未設定</span>
          </div>
        </IntegrationCard>

        <IntegrationCard
          name="PagerDuty"
          description="重大インシデントを PagerDuty でオンコール担当者にエスカレーションします"
          status="disconnected"
          logoPlaceholder={<PagerDutyLogo />}
          configHref="/admin/integrations/pagerduty"
        />
      </div>
    </div>
  )
}

// ─── Notifications tab ───────────────────────────────────────────────────────────

function NotificationsTab() {
  const [slackTest, setSlackTest] = useState<TestState>('idle')
  const [teamsTest, setTeamsTest] = useState<TestState>('idle')
  const [webhookTest, setWebhookTest] = useState<TestState>('idle')

  const runTest = async (
    setter: React.Dispatch<React.SetStateAction<TestState>>,
    endpoint: string,
  ) => {
    setter('testing')
    try {
      await apiFetch(endpoint, { method: 'POST' })
      setter('success')
    } catch {
      setter('error')
    } finally {
      setTimeout(() => setter('idle'), 3000)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-white mb-1">通知連携</h2>
        <p className="text-sm text-[#7d92b0]">
          アラート・システム通知の送信先チャンネルを設定します
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <IntegrationCard
          name="Slack"
          description="Incoming Webhook または Bot Token で Slack チャンネルに通知を送信します"
          status="connected"
          logoPlaceholder={<SlackLogo />}
          configHref="/admin/integrations/slack"
          onTest={() => runTest(setSlackTest, '/api/v1/notifications/slack/test')}
          testState={slackTest}
        >
          <div className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg border border-[#1e2d42] px-3 py-2">
            <span className="text-[#3d5068]">チャンネル:</span>{' '}
            <span className="font-mono">#soc-alerts</span>
          </div>
        </IntegrationCard>

        <IntegrationCard
          name="Microsoft Teams"
          description="Teams チャンネルへ Adaptive Card 形式でアラートを送信します"
          status="disconnected"
          logoPlaceholder={<TeamsLogo />}
          configHref="/admin/integrations/teams"
          onTest={() => runTest(setTeamsTest, '/api/v1/notifications/teams/test')}
          testState={teamsTest}
        />

        <IntegrationCard
          name="Webhook"
          description="任意の HTTP エンドポイントへ JSON ペイロードで通知を送信します"
          status="disconnected"
          logoPlaceholder={<WebhookLogo />}
          configHref="/admin/integrations/webhook"
          onTest={() => runTest(setWebhookTest, '/api/v1/notifications/webhook/test')}
          testState={webhookTest}
        />
      </div>
    </div>
  )
}

// ─── Ticketing tab ───────────────────────────────────────────────────────────────

function TicketingTab() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-white mb-1">チケッティング連携</h2>
        <p className="text-sm text-[#7d92b0]">
          インシデント管理・ヘルプデスクシステムとの統合設定
        </p>
      </div>

      <div className="flex items-start gap-3 bg-[#1a6bff]/5 border border-[#1a6bff]/20 rounded-xl px-5 py-4">
        <Info className="w-4 h-4 text-[#1a6bff] shrink-0 mt-0.5" />
        <p className="text-sm text-[#7d92b0] leading-relaxed">
          Jira および ServiceNow の詳細設定は{' '}
          <a href="/admin/integrations/soar" className="text-[#e8002d] hover:underline">
            SOAR タブ
          </a>{' '}
          から行えます。追加のチケッティングシステム統合は今後のアップデートで提供予定です。
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <IntegrationCard
          name="Jira Service Management"
          description="JSM ポータル経由でインシデントチケットを管理します"
          status="disconnected"
          logoPlaceholder={<JiraLogo />}
          configHref="/admin/integrations/soar"
        />

        <IntegrationCard
          name="ServiceNow ITSM"
          description="Change Management・Problem Management を含む全機能連携"
          status="disconnected"
          logoPlaceholder={<ServiceNowLogo />}
          configHref="/admin/integrations/soar"
        />
      </div>
    </div>
  )
}

// ─── Summary stats ───────────────────────────────────────────────────────────────

function IntegrationsSummary() {
  const { data, isLoading } = useQuery({
    queryKey: ['integrations-summary'],
    queryFn: () => apiFetch('/api/v1/admin/integrations/summary'),
    placeholderData: { total: 10, connected: 3, disconnected: 6, error: 1 },
    staleTime: 60_000,
  })

  const stats = (data as { total: number; connected: number; disconnected: number; error: number }) ?? {
    total: 10, connected: 3, disconnected: 6, error: 1,
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
      {[
        { label: '総連携数',   value: stats.total,        cls: 'text-[#e2e8f4]' },
        { label: '接続中',     value: stats.connected,    cls: 'text-emerald-400' },
        { label: '未接続',     value: stats.disconnected, cls: 'text-[#7d92b0]' },
        { label: 'エラー',     value: stats.error,        cls: 'text-red-400' },
      ].map(({ label, value, cls }) => (
        <div
          key={label}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3"
        >
          <p className="text-xs text-[#7d92b0] uppercase tracking-wide mb-1">{label}</p>
          <p className={`text-2xl font-bold ${cls}`}>
            {isLoading ? <Loader2 className="w-5 h-5 animate-spin inline" /> : value}
          </p>
        </div>
      ))}
    </div>
  )
}

// ─── Main page ───────────────────────────────────────────────────────────────────

type TabId = 'siem' | 'soar' | 'notifications' | 'ticketing'

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: 'siem',          label: 'SIEM',        icon: <Shield className="w-4 h-4" /> },
  { id: 'soar',          label: 'SOAR',        icon: <Workflow className="w-4 h-4" /> },
  { id: 'notifications', label: '通知',        icon: <Bell className="w-4 h-4" /> },
  { id: 'ticketing',     label: 'チケッティング', icon: <Ticket className="w-4 h-4" /> },
]

export default function IntegrationsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('siem')

  return (
    <div className="min-h-screen bg-[#070d19]">
      <PageDataUnavailable />
      <div className="max-w-screen-xl mx-auto p-6 space-y-6">

        {/* ── Breadcrumb ─────────────────────────────────────────── */}
        <nav className="flex items-center gap-1.5 text-xs text-[#3d5068]">
          <a href="/admin" className="hover:text-[#7d92b0] transition-colors">Admin</a>
          <ChevronRight className="w-3 h-3" />
          <span className="text-[#7d92b0]">Integrations</span>
        </nav>

        {/* ── Header ────────────────────────────────────────────── */}
        <div className="flex items-start gap-4">
          <div className="w-11 h-11 rounded-xl bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center shrink-0">
            <Puzzle className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">外部連携</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">
              SIEM・SOAR・通知・チケッティングシステムとの統合を一元管理
            </p>
          </div>
        </div>

        {/* ── Summary stats ─────────────────────────────────────── */}
        <IntegrationsSummary />

        {/* ── Tabs ──────────────────────────────────────────────── */}
        <div>
          <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1 w-fit overflow-x-auto">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                            whitespace-nowrap transition-all duration-150
                  ${activeTab === tab.id
                    ? 'bg-[#e8002d] text-white shadow-xs'
                    : 'text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#19253d]'
                  }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          <div className="mt-6">
            {activeTab === 'siem'          && <SiemTab />}
            {activeTab === 'soar'          && <SoarTab />}
            {activeTab === 'notifications' && <NotificationsTab />}
            {activeTab === 'ticketing'     && <TicketingTab />}
          </div>
        </div>

      </div>
    </div>
  )
}
