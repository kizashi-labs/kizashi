'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Workflow,
  Eye,
  EyeOff,
  Loader2,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Save,
  Info,
  AlertTriangle,
  Ticket,
  RotateCcw,
  ChevronRight,
} from 'lucide-react'


// ─── Types ─────────────────────────────────────────────────────────────────────

interface JiraConfig {
  enabled: boolean
  url: string
  project_key: string
  issue_type: 'Bug' | 'Task' | 'Story'
  username: string
  api_token: string
  priority_map: {
    critical: string
    high: string
    medium: string
    low: string
  }
}

interface ServiceNowConfig {
  enabled: boolean
  instance_url: string
  username: string
  password: string
  table: 'incident' | 'change_request'
  assignment_group: string
  caller_id: string
}

interface SoarAction {
  ticket_id: string
  type: string
  status: 'open' | 'closed' | 'failed' | 'pending'
  alert_id: string
  created_at: string
}

type TestStatus = 'idle' | 'testing' | 'success' | 'error'
type SaveStatus = 'idle' | 'saving' | 'saved' | 'error'

// ─── Default configs ───────────────────────────────────────────────────────────

const DEFAULT_JIRA: JiraConfig = {
  enabled: false,
  url: '',
  project_key: '',
  issue_type: 'Bug',
  username: '',
  api_token: '',
  priority_map: {
    critical: 'Highest',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
  },
}

const DEFAULT_SERVICENOW: ServiceNowConfig = {
  enabled: false,
  instance_url: '',
  username: '',
  password: '',
  table: 'incident',
  assignment_group: '',
  caller_id: '',
}

// ─── Shared UI helpers ─────────────────────────────────────────────────────────

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium text-[#7d92b0] mb-1.5 uppercase tracking-wide">
      {children}
    </label>
  )
}

function TextInput({
  value,
  onChange,
  placeholder,
  type = 'text',
  className = '',
  disabled = false,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
  className?: string
  disabled?: boolean
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className={`w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm
                  text-[#e2e8f4] placeholder-[#3d5068]
                  focus:outline-none focus:border-[#e8002d]/60 focus:ring-1 focus:ring-[#e8002d]/20
                  disabled:opacity-40 disabled:cursor-not-allowed
                  transition-colors ${className}`}
    />
  )
}

function SelectInput({
  value,
  onChange,
  options,
  disabled = false,
}: {
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
  disabled?: boolean
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      disabled={disabled}
      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2.5 text-sm
                 text-[#e2e8f4]
                 focus:outline-none focus:border-[#e8002d]/60 focus:ring-1 focus:ring-[#e8002d]/20
                 disabled:opacity-40 disabled:cursor-not-allowed
                 transition-colors appearance-none"
    >
      {options.map(o => (
        <option key={o.value} value={o.value} className="bg-[#0d1220]">
          {o.label}
        </option>
      ))}
    </select>
  )
}

function Toggle({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  description?: string
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer group">
      <div className="relative mt-0.5 flex-shrink-0">
        <input
          type="checkbox"
          checked={checked}
          onChange={e => onChange(e.target.checked)}
          className="sr-only"
        />
        <div
          className={`w-10 h-6 rounded-full transition-colors duration-200 ${
            checked ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
          }`}
        >
          <div
            className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] shadow transition-transform duration-200 ${
              checked ? 'translate-x-5' : 'translate-x-1'
            }`}
          />
        </div>
      </div>
      <div>
        <p className="text-sm text-[#e2e8f4] font-medium group-hover:text-white transition-colors">
          {label}
        </p>
        {description && (
          <p className="text-xs text-[#7d92b0] mt-0.5">{description}</p>
        )}
      </div>
    </label>
  )
}

function TestButton({
  onTest,
  status,
  disabled,
}: {
  onTest: () => void
  status: TestStatus
  disabled?: boolean
}) {
  return (
    <div className="flex items-center gap-3">
      <button
        onClick={onTest}
        disabled={status === 'testing' || disabled}
        className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                   bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0]
                   hover:border-[#7d92b0]/50 hover:text-[#e2e8f4]
                   disabled:opacity-40 disabled:cursor-not-allowed transition-all"
      >
        {status === 'testing' ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <RefreshCw className="w-4 h-4" />
        )}
        接続テスト
      </button>

      {status !== 'idle' && (
        <div className="flex items-center gap-2">
          {status === 'testing' && (
            <span className="text-sm text-yellow-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse inline-block" />
              接続中...
            </span>
          )}
          {status === 'success' && (
            <span className="text-sm text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" />
              接続成功
            </span>
          )}
          {status === 'error' && (
            <span className="text-sm text-red-400 flex items-center gap-1.5">
              <XCircle className="w-4 h-4" />
              接続失敗
            </span>
          )}
        </div>
      )}
    </div>
  )
}

function SaveButton({
  onSave,
  status,
  disabled,
}: {
  onSave: () => void
  status: SaveStatus
  disabled?: boolean
}) {
  return (
    <button
      onClick={onSave}
      disabled={status === 'saving' || disabled}
      className="flex items-center gap-2 px-5 py-2.5 text-sm font-medium rounded-lg
                 bg-[#e8002d] hover:bg-[#c0001f] text-white
                 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
    >
      {status === 'saving' ? (
        <Loader2 className="w-4 h-4 animate-spin" />
      ) : (
        <Save className="w-4 h-4" />
      )}
      {status === 'saving' ? '保存中...' : status === 'saved' ? '保存済み' : '設定を保存'}
    </button>
  )
}

function StatusBadge({ status }: { status: SoarAction['status'] }) {
  const map: Record<SoarAction['status'], { label: string; cls: string }> = {
    open:    { label: 'オープン', cls: 'bg-blue-900/30 text-blue-300 border-blue-700/40' },
    closed:  { label: 'クローズ', cls: 'bg-[#1e2d42] text-[#7d92b0] border-[#1e2d42]' },
    failed:  { label: '失敗',     cls: 'bg-red-900/30 text-red-400 border-red-700/40' },
    pending: { label: '処理中',   cls: 'bg-yellow-900/30 text-yellow-400 border-yellow-700/40' },
  }
  const { label, cls } = map[status]
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${cls}`}>
      {status === 'open' && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 inline-block mr-1.5" />}
      {status === 'failed' && <span className="w-1.5 h-1.5 rounded-full bg-red-400 inline-block mr-1.5" />}
      {label}
    </span>
  )
}

// ─── Jira tab ──────────────────────────────────────────────────────────────────

function JiraTab() {
  const queryClient = useQueryClient()
  const [config, setConfig] = useState<JiraConfig>(DEFAULT_JIRA)
  const [showToken, setShowToken] = useState(false)
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')

  // Load config
  const { data: soarJiraData } = useQuery({
    queryKey: ['soar-config'],
    queryFn: () => apiFetch<{ jira?: JiraConfig }>('/api/v1/soar/config').catch(() => null),
  })
  useEffect(() => {
    if (soarJiraData?.jira) setConfig(prev => ({ ...DEFAULT_JIRA, ...soarJiraData.jira }))
  }, [soarJiraData])

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: (payload: object) =>
      apiFetch('/api/v1/soar/config', { method: 'PUT', body: JSON.stringify(payload) }),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('saved')
      queryClient.invalidateQueries({ queryKey: ['soar-config'] })
      setTimeout(() => setSaveStatus('idle'), 2500)
    },
    onError: () => setSaveStatus('error'),
  })

  const handleTest = async () => {
    setTestStatus('testing')
    try {
      await apiFetch('/api/v1/soar/jira/test', { method: 'POST', body: JSON.stringify(config) })
      setTestStatus('success')
    } catch {
      setTestStatus('error')
    }
  }

  const handleSave = () => {
    saveMutation.mutate({ provider: 'jira', ...config })
  }

  const set = <K extends keyof JiraConfig>(key: K, val: JiraConfig[K]) =>
    setConfig(prev => ({ ...prev, [key]: val }))

  const ISSUE_TYPES = [
    { value: 'Bug',   label: 'Bug' },
    { value: 'Task',  label: 'Task' },
    { value: 'Story', label: 'Story' },
  ]

  const PRIORITY_ROWS: { key: keyof JiraConfig['priority_map']; edr: string; cls: string }[] = [
    { key: 'critical', edr: 'クリティカル', cls: 'text-red-400 bg-red-900/20 border-red-700/30' },
    { key: 'high',     edr: '高',           cls: 'text-orange-400 bg-orange-900/20 border-orange-700/30' },
    { key: 'medium',   edr: '中',           cls: 'text-yellow-400 bg-yellow-900/20 border-yellow-700/30' },
    { key: 'low',      edr: '低',           cls: 'text-blue-400 bg-blue-900/20 border-blue-700/30' },
  ]

  return (
    <div className="space-y-6">

      {/* Enable toggle */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
        <Toggle
          checked={config.enabled}
          onChange={v => set('enabled', v)}
          label="Jira連携を有効化"
          description="有効にすると、高重大度以上のアラート検知時に自動でJiraチケットが作成されます"
        />
      </div>

      {/* Connection config */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-sm font-semibold text-white">接続設定</h3>
        </div>
        <div className="p-5 space-y-4">
          {/* URL */}
          <div>
            <FieldLabel>Jira URL</FieldLabel>
            <TextInput
              value={config.url}
              onChange={v => set('url', v)}
              placeholder="https://company.atlassian.net"
            />
          </div>

          {/* Project key + Issue type */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FieldLabel>プロジェクトキー</FieldLabel>
              <TextInput
                value={config.project_key}
                onChange={v => set('project_key', v)}
                placeholder="SEC"
              />
            </div>
            <div>
              <FieldLabel>Issue タイプ</FieldLabel>
              <SelectInput
                value={config.issue_type}
                onChange={v => set('issue_type', v as JiraConfig['issue_type'])}
                options={ISSUE_TYPES}
              />
            </div>
          </div>

          {/* Username + API token */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FieldLabel>ユーザー名</FieldLabel>
              <TextInput
                value={config.username}
                onChange={v => set('username', v)}
                placeholder="admin@company.com"
              />
            </div>
            <div>
              <FieldLabel>APIトークン</FieldLabel>
              <div className="relative">
                <TextInput
                  type={showToken ? 'text' : 'password'}
                  value={config.api_token}
                  onChange={v => set('api_token', v)}
                  placeholder="••••••••••••••"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowToken(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#3d5068] hover:text-[#7d92b0] transition-colors"
                >
                  {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>

          {/* Test button */}
          <div className="pt-1">
            <TestButton
              onTest={handleTest}
              status={testStatus}
              disabled={!config.url || !config.username || !config.api_token}
            />
          </div>
        </div>
      </div>

      {/* Priority mapping */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-sm font-semibold text-white">優先度マッピング</h3>
          <p className="text-xs text-[#7d92b0] mt-0.5">
            EDRアラートの重大度をJiraの優先度に対応させます
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/60">
                <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                  EDR 重大度
                </th>
                <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                  Jira 優先度
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]/50">
              {PRIORITY_ROWS.map(({ key, edr, cls }) => (
                <tr key={key} className="hover:bg-[#070d19]/60 transition-colors">
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${cls}`}>
                      {edr}
                    </span>
                  </td>
                  <td className="px-5 py-3 w-48">
                    <TextInput
                      value={config.priority_map[key]}
                      onChange={v =>
                        setConfig(prev => ({
                          ...prev,
                          priority_map: { ...prev.priority_map, [key]: v },
                        }))
                      }
                      placeholder="Highest"
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Info card */}
      <div className="flex items-start gap-3 bg-[#e8002d]/5 border border-[#e8002d]/20 rounded-xl px-5 py-4">
        <Info className="w-4 h-4 text-[#e8002d] flex-shrink-0 mt-0.5" />
        <div className="text-xs text-[#7d92b0] leading-relaxed space-y-1">
          <p className="text-[#e2e8f4] font-medium text-sm">自動チケット作成について</p>
          <p>
            Jira連携が有効な場合、重大度が <span className="text-orange-400 font-medium">高 (High)</span> 以上のアラートが検知されると、
            設定されたプロジェクトに自動でJiraチケットが作成されます。
            アラートの詳細・影響ホスト・推奨対応手順がチケット説明に含まれます。
          </p>
        </div>
      </div>

      {/* Save */}
      <div className="flex justify-end">
        <SaveButton onSave={handleSave} status={saveStatus} />
      </div>
    </div>
  )
}

// ─── ServiceNow tab ────────────────────────────────────────────────────────────

function ServiceNowTab() {
  const queryClient = useQueryClient()
  const [config, setConfig] = useState<ServiceNowConfig>(DEFAULT_SERVICENOW)
  const [showPassword, setShowPassword] = useState(false)
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')

  // Load config
  const { data: soarSnData } = useQuery({
    queryKey: ['soar-sn-config'],
    queryFn: () => apiFetch<{ servicenow?: ServiceNowConfig }>('/api/v1/soar/config').catch(() => null),
  })
  useEffect(() => {
    if (soarSnData?.servicenow) setConfig(prev => ({ ...DEFAULT_SERVICENOW, ...soarSnData.servicenow }))
  }, [soarSnData])

  const saveMutation = useMutation({
    mutationFn: (payload: object) =>
      apiFetch('/api/v1/soar/config', { method: 'PUT', body: JSON.stringify(payload) }),
    onMutate: () => setSaveStatus('saving'),
    onSuccess: () => {
      setSaveStatus('saved')
      queryClient.invalidateQueries({ queryKey: ['soar-config'] })
      setTimeout(() => setSaveStatus('idle'), 2500)
    },
    onError: () => setSaveStatus('error'),
  })

  const handleTest = async () => {
    setTestStatus('testing')
    try {
      await apiFetch('/api/v1/soar/servicenow/test', { method: 'POST', body: JSON.stringify(config) })
      setTestStatus('success')
    } catch {
      setTestStatus('error')
    }
  }

  const handleSave = () => {
    saveMutation.mutate({ provider: 'servicenow', ...config })
  }

  const set = <K extends keyof ServiceNowConfig>(key: K, val: ServiceNowConfig[K]) =>
    setConfig(prev => ({ ...prev, [key]: val }))

  const TABLE_OPTIONS = [
    { value: 'incident',       label: 'Incident' },
    { value: 'change_request', label: 'Change Request' },
  ]

  return (
    <div className="space-y-6">

      {/* Enable toggle */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
        <Toggle
          checked={config.enabled}
          onChange={v => set('enabled', v)}
          label="ServiceNow連携を有効化"
          description="有効にすると、アラート発生時に自動でServiceNowレコードが作成されます"
        />
      </div>

      {/* Connection config */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-sm font-semibold text-white">接続設定</h3>
        </div>
        <div className="p-5 space-y-4">
          {/* Instance URL */}
          <div>
            <FieldLabel>インスタンス URL</FieldLabel>
            <TextInput
              value={config.instance_url}
              onChange={v => set('instance_url', v)}
              placeholder="https://company.service-now.com"
            />
            <p className="text-xs text-[#3d5068] mt-1">
              例: https://company.service-now.com
            </p>
          </div>

          {/* Username + Password */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FieldLabel>ユーザー名</FieldLabel>
              <TextInput
                value={config.username}
                onChange={v => set('username', v)}
                placeholder="admin"
              />
            </div>
            <div>
              <FieldLabel>パスワード</FieldLabel>
              <div className="relative">
                <TextInput
                  type={showPassword ? 'text' : 'password'}
                  value={config.password}
                  onChange={v => set('password', v)}
                  placeholder="••••••••"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#3d5068] hover:text-[#7d92b0] transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>

          {/* Table */}
          <div>
            <FieldLabel>テーブル</FieldLabel>
            <SelectInput
              value={config.table}
              onChange={v => set('table', v as ServiceNowConfig['table'])}
              options={TABLE_OPTIONS}
            />
          </div>

          {/* Assignment group + Caller ID */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <FieldLabel>アサイングループ</FieldLabel>
              <TextInput
                value={config.assignment_group}
                onChange={v => set('assignment_group', v)}
                placeholder="Security Operations"
              />
            </div>
            <div>
              <FieldLabel>呼び出し元 ID (Caller ID)</FieldLabel>
              <TextInput
                value={config.caller_id}
                onChange={v => set('caller_id', v)}
                placeholder="soc-automation"
              />
            </div>
          </div>

          {/* Test button */}
          <div className="pt-1">
            <TestButton
              onTest={handleTest}
              status={testStatus}
              disabled={!config.instance_url || !config.username || !config.password}
            />
          </div>
        </div>
      </div>

      {/* Save */}
      <div className="flex justify-end">
        <SaveButton onSave={handleSave} status={saveStatus} />
      </div>
    </div>
  )
}

// ─── Recent actions table ──────────────────────────────────────────────────────

function RecentActions() {
  const [retrying, setRetrying] = useState<string | null>(null)

  const { data: actionsData, isLoading } = useQuery<SoarAction[]>({
    queryKey: ['soar-actions'],
    queryFn: () => apiFetch('/api/v1/soar/actions?limit=20'),
    staleTime: 30_000,
  })

  const actions = actionsData ?? []

  const handleRetry = async (ticketId: string) => {
    setRetrying(ticketId)
    await new Promise(r => setTimeout(r, 1200))
    setRetrying(null)
  }

  return (
    <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
      <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Ticket className="w-4 h-4 text-[#7d92b0]" />
          <h2 className="text-sm font-semibold text-white">最近のSOARアクション</h2>
          <span className="text-xs text-[#3d5068] bg-[#070d19] border border-[#1e2d42] px-2 py-0.5 rounded-full">
            {actions.length}件
          </span>
        </div>
        {isLoading && <Loader2 className="w-4 h-4 text-[#7d92b0] animate-spin" />}
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#1e2d42] bg-[#070d19]/60">
              <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                チケットID
              </th>
              <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                タイプ
              </th>
              <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                ステータス
              </th>
              <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                アラートID
              </th>
              <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                作成日
              </th>
              <th className="text-left px-5 py-3 text-xs text-[#7d92b0] font-medium uppercase tracking-wide">
                操作
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1e2d42]/50">
            {actions.map(action => (
              <tr key={action.ticket_id} className="hover:bg-[#070d19]/60 transition-colors group">
                <td className="px-5 py-3">
                  <span className="font-mono text-xs text-[#e2e8f4] font-medium">
                    {action.ticket_id}
                  </span>
                </td>
                <td className="px-5 py-3">
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border
                      ${action.type === 'Jira'
                        ? 'bg-blue-900/20 text-blue-300 border-blue-700/30'
                        : 'bg-purple-900/20 text-purple-300 border-purple-700/30'
                      }`}
                  >
                    {action.type}
                  </span>
                </td>
                <td className="px-5 py-3">
                  <StatusBadge status={action.status} />
                </td>
                <td className="px-5 py-3">
                  <span className="font-mono text-xs text-[#7d92b0]">{action.alert_id}</span>
                </td>
                <td className="px-5 py-3">
                  <span className="text-xs text-[#7d92b0]">{action.created_at}</span>
                </td>
                <td className="px-5 py-3">
                  {action.status === 'failed' ? (
                    <button
                      onClick={() => handleRetry(action.ticket_id)}
                      disabled={retrying === action.ticket_id}
                      className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg
                                 bg-[#070d19] border border-[#1e2d42] text-[#7d92b0]
                                 hover:border-[#e8002d]/40 hover:text-[#e2e8f4]
                                 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                    >
                      {retrying === action.ticket_id ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <RotateCcw className="w-3 h-3" />
                      )}
                      再試行
                    </button>
                  ) : (
                    <span className="text-xs text-[#3d5068]">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Main page ─────────────────────────────────────────────────────────────────

type Tab = 'jira' | 'servicenow'

export default function SoarIntegrationPage() {
  const [activeTab, setActiveTab] = useState<Tab>('jira')

  const TABS: { id: Tab; label: string }[] = [
    { id: 'jira',        label: 'Jira連携' },
    { id: 'servicenow',  label: 'ServiceNow連携' },
  ]

  return (
    <div className="min-h-screen bg-[#070d19]">
      <div className="max-w-screen-lg mx-auto p-6 space-y-6">

        {/* ── Header ────────────────────────────────────────────── */}
        <div className="flex items-start gap-4">
          <div className="w-11 h-11 rounded-xl bg-[#e8002d]/10 border border-[#e8002d]/20
                          flex items-center justify-center flex-shrink-0">
            <Workflow className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">SOAR連携</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">
              チケッティングシステムとの統合設定 — アラート発生時に自動でチケットを作成します
            </p>
          </div>
        </div>

        {/* ── Tabs ──────────────────────────────────────────────── */}
        <div>
          <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-1 w-fit">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-5 py-2 text-sm font-medium rounded-lg transition-all duration-150
                  ${activeTab === tab.id
                    ? 'bg-[#e8002d] text-white shadow-sm'
                    : 'text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#19253d]'
                  }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="mt-6">
            {activeTab === 'jira'        && <JiraTab />}
            {activeTab === 'servicenow'  && <ServiceNowTab />}
          </div>
        </div>

        {/* ── Recent SOAR actions ────────────────────────────────── */}
        <div>
          <RecentActions />
        </div>

      </div>
    </div>
  )
}
