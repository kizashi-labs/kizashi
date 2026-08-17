'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ChevronRight,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  Eye,
  EyeOff,
  Activity,
  AlertTriangle,
  Zap,
  Settings,
  List,
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

type ConnectionStatus = 'idle' | 'testing' | 'success' | 'error'

interface HECConfig {
  url: string
  token: string
  index: string
  sourceType: string
  sslVerify: boolean
}

interface ForwardingConfig {
  enabled: boolean
  forwardAlerts: boolean
  forwardEvents: boolean
  forwardAuditLogs: boolean
  minSeverity: number
  batchSize: number
  retryOnFailure: boolean
}

interface FieldMapping {
  id: string
  edrField: string
  splunkField: string
}

interface SyncStatus {
  connected: boolean
  lastEvent: string | null
  eventsToday: number
  errorsToday: number
}

// ─── Defaults ────────────────────────────────────────────────────────────────

const DEFAULT_HEC: HECConfig = {
  url: '',
  token: '',
  index: 'main',
  sourceType: 'edr:alert',
  sslVerify: true,
}

const DEFAULT_FORWARDING: ForwardingConfig = {
  enabled: false,
  forwardAlerts: true,
  forwardEvents: false,
  forwardAuditLogs: false,
  minSeverity: 5,
  batchSize: 100,
  retryOnFailure: true,
}

const DEFAULT_MAPPINGS: FieldMapping[] = [
  { id: '1', edrField: 'title',      splunkField: 'message' },
  { id: '2', edrField: 'severity',   splunkField: 'severity' },
  { id: '3', edrField: 'agent_id',   splunkField: 'host' },
  { id: '4', edrField: 'status',     splunkField: 'status' },
  { id: '5', edrField: 'created_at', splunkField: '_time' },
]

// ─── Shared UI Components ────────────────────────────────────────────────────

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium text-falcon-muted mb-1.5 uppercase tracking-wide">
      {children}
    </label>
  )
}

function TextInput({
  value,
  onChange,
  placeholder,
  type = 'text',
  disabled = false,
  className = '',
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
  disabled?: boolean
  className?: string
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className={`w-full bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2.5 text-sm
                  text-falcon-text placeholder-falcon-subtle
                  focus:outline-hidden focus:border-falcon-red/60 focus:ring-1 focus:ring-falcon-red/20
                  disabled:opacity-40 disabled:cursor-not-allowed transition-colors ${className}`}
    />
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
      <div className="relative mt-0.5 shrink-0">
        <input
          type="checkbox"
          checked={checked}
          onChange={e => onChange(e.target.checked)}
          className="sr-only"
        />
        <div className={`w-10 h-6 rounded-full transition-colors duration-200 ${checked ? 'bg-falcon-red' : 'bg-falcon-border'}`}>
          <div
            className={`absolute top-1 w-4 h-4 rounded-full bg-falcon-text shadow transition-transform duration-200 ${
              checked ? 'translate-x-5' : 'translate-x-1'
            }`}
          />
        </div>
      </div>
      <div>
        <p className="text-sm text-falcon-text font-medium group-hover:text-white transition-colors">
          {label}
        </p>
        {description && (
          <p className="text-xs text-falcon-muted mt-0.5">{description}</p>
        )}
      </div>
    </label>
  )
}

function Checkbox({
  checked,
  onChange,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
}) {
  return (
    <label className="flex items-center gap-2.5 cursor-pointer group">
      <div
        className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
          checked ? 'bg-falcon-red border-falcon-red' : 'border-falcon-border bg-[#070d19]'
        }`}
        onClick={() => onChange(!checked)}
      >
        {checked && (
          <svg className="w-2.5 h-2.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        )}
      </div>
      <span className="text-sm text-falcon-text group-hover:text-white transition-colors">{label}</span>
    </label>
  )
}

function Card({
  title,
  subtitle,
  icon,
  children,
}: {
  title: string
  subtitle?: string
  icon?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="bg-falcon-surface rounded-xl border border-falcon-border overflow-hidden">
      <div className="px-6 py-4 border-b border-falcon-border flex items-start gap-3">
        {icon && <div className="mt-0.5 text-falcon-muted">{icon}</div>}
        <div>
          <h2 className="text-sm font-semibold text-white">{title}</h2>
          {subtitle && <p className="text-xs text-falcon-muted mt-0.5">{subtitle}</p>}
        </div>
      </div>
      <div className="p-6">{children}</div>
    </div>
  )
}

function Banner({ type, message }: { type: 'success' | 'error'; message: string }) {
  if (type === 'success') {
    return (
      <div className="flex items-center gap-3 bg-emerald-900/20 border border-emerald-700/40 rounded-lg px-4 py-3">
        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
        <p className="text-sm text-emerald-300">{message}</p>
      </div>
    )
  }
  return (
    <div className="flex items-center gap-3 bg-red-900/20 border border-red-700/40 rounded-lg px-4 py-3">
      <XCircle className="w-4 h-4 text-red-400 shrink-0" />
      <p className="text-sm text-red-300">{message}</p>
    </div>
  )
}

// ─── HEC Connection Card ──────────────────────────────────────────────────────

function HECConnectionCard() {
  const [config, setConfig] = useState<HECConfig>(DEFAULT_HEC)
  const [showToken, setShowToken] = useState(false)
  const [testStatus, setTestStatus] = useState<ConnectionStatus>('idle')
  const [testMsg, setTestMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const set = <K extends keyof HECConfig>(key: K, val: HECConfig[K]) =>
    setConfig(prev => ({ ...prev, [key]: val }))

  const testMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/integrations/splunk/test', {
        method: 'POST',
        body: JSON.stringify(config),
      }),
    onMutate: () => {
      setTestStatus('testing')
      setTestMsg(null)
    },
    onSuccess: () => {
      setTestStatus('success')
      setTestMsg({ type: 'success', text: 'Connection to Splunk HEC successful. Events can be forwarded.' })
    },
    onError: (err: unknown) => {
      setTestStatus('error')
      const msg = err instanceof Error ? err.message : 'Unknown error'
      setTestMsg({ type: 'error', text: `Connection failed: ${msg}` })
    },
  })

  return (
    <Card
      title="HEC Connection"
      subtitle="Configure Splunk HTTP Event Collector endpoint and authentication"
      icon={<Zap className="w-4 h-4" />}
    >
      <div className="space-y-5">
        {/* HEC URL */}
        <div>
          <FieldLabel>Splunk HEC URL</FieldLabel>
          <TextInput
            value={config.url}
            onChange={v => set('url', v)}
            placeholder="https://splunk:8088/services/collector"
          />
          <p className="text-xs text-falcon-subtle mt-1">
            The HTTP Event Collector endpoint URL including port (default: 8088)
          </p>
        </div>

        {/* HEC Token */}
        <div>
          <FieldLabel>HEC Token</FieldLabel>
          <div className="relative">
            <TextInput
              type={showToken ? 'text' : 'password'}
              value={config.token}
              onChange={v => set('token', v)}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="pr-10"
            />
            <button
              type="button"
              onClick={() => setShowToken(prev => !prev)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-falcon-muted hover:text-falcon-text transition-colors"
            >
              {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-xs text-falcon-subtle mt-1">
            Generate a token in Splunk: Settings → Data Inputs → HTTP Event Collector
          </p>
        </div>

        {/* Index + Source Type */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <FieldLabel>インデックス</FieldLabel>
            <TextInput
              value={config.index}
              onChange={v => set('index', v)}
              placeholder="main"
            />
            <p className="text-xs text-falcon-subtle mt-1">Target Splunk index for EDR events</p>
          </div>
          <div>
            <FieldLabel>ソースタイプ</FieldLabel>
            <TextInput
              value={config.sourceType}
              onChange={v => set('sourceType', v)}
              placeholder="edr:alert"
            />
            <p className="text-xs text-falcon-subtle mt-1">Splunk sourcetype for field extraction</p>
          </div>
        </div>

        {/* SSL Verification */}
        <Toggle
          checked={config.sslVerify}
          onChange={v => set('sslVerify', v)}
          label="Verify SSL Certificate"
          description="Disable only when using self-signed certificates in development environments."
        />

        {/* Test banner */}
        {testMsg && <Banner type={testMsg.type} message={testMsg.text} />}

        {/* Test button */}
        <div className="pt-1">
          <button
            onClick={() => testMutation.mutate()}
            disabled={testStatus === 'testing' || !config.url || !config.token}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                       bg-[#070d19] border border-falcon-border text-falcon-muted
                       hover:border-falcon-muted/50 hover:text-falcon-text
                       disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {testStatus === 'testing' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : testStatus === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : testStatus === 'error' ? (
              <XCircle className="w-4 h-4 text-red-400" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
            {testStatus === 'testing' ? 'Testing...' : 'Test Connection'}
          </button>
        </div>
      </div>
    </Card>
  )
}

// ─── Forwarding Settings Card ─────────────────────────────────────────────────

function ForwardingSettingsCard() {
  const [config, setConfig] = useState<ForwardingConfig>(DEFAULT_FORWARDING)
  const [saved, setSaved] = useState(false)

  const set = <K extends keyof ForwardingConfig>(key: K, val: ForwardingConfig[K]) =>
    setConfig(prev => ({ ...prev, [key]: val }))

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/integrations/splunk/config', {
        method: 'PUT',
        body: JSON.stringify({ forwarding: config }),
      }),
    onSuccess: () => {
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    },
  })

  return (
    <Card
      title="Forwarding Settings"
      subtitle="Control which events are forwarded to Splunk and how"
      icon={<Settings className="w-4 h-4" />}
    >
      <div className="space-y-6">
        {/* Master enable */}
        <Toggle
          checked={config.enabled}
          onChange={v => set('enabled', v)}
          label="Enable Event Forwarding"
          description="When enabled, matched events will be sent to the configured Splunk HEC endpoint."
        />

        <div className={`space-y-4 transition-opacity ${config.enabled ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
          {/* What to forward */}
          <div>
            <p className="text-xs font-medium text-falcon-muted uppercase tracking-wide mb-3">Forward</p>
            <div className="space-y-2.5">
              <Checkbox
                checked={config.forwardAlerts}
                onChange={v => set('forwardAlerts', v)}
                label="Security Alerts"
              />
              <Checkbox
                checked={config.forwardEvents}
                onChange={v => set('forwardEvents', v)}
                label="Raw Endpoint Events"
              />
              <Checkbox
                checked={config.forwardAuditLogs}
                onChange={v => set('forwardAuditLogs', v)}
                label="Audit Logs"
              />
            </div>
          </div>

          {/* Min severity */}
          <div>
            <FieldLabel>Minimum Severity Threshold ({config.minSeverity})</FieldLabel>
            <div className="flex items-center gap-3">
              <span className="text-xs text-falcon-muted w-4">1</span>
              <input
                type="range"
                min={1}
                max={10}
                value={config.minSeverity}
                onChange={e => set('minSeverity', parseInt(e.target.value))}
                className="flex-1 accent-falcon-red"
              />
              <span className="text-xs text-falcon-muted w-4">10</span>
            </div>
            <p className="text-xs text-falcon-subtle mt-1">
              Only forward alerts with severity ≥ {config.minSeverity}
            </p>
          </div>

          {/* Batch size */}
          <div>
            <FieldLabel>バッチサイズ</FieldLabel>
            <div className="flex gap-2">
              {([50, 100, 500] as const).map(size => (
                <button
                  key={size}
                  onClick={() => set('batchSize', size)}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-all ${
                    config.batchSize === size
                      ? 'bg-falcon-red/10 border-falcon-red/50 text-falcon-red'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/50 hover:text-falcon-text'
                  }`}
                >
                  {size}
                </button>
              ))}
            </div>
            <p className="text-xs text-falcon-subtle mt-1.5">
              Number of events per HEC batch request
            </p>
          </div>

          {/* Retry */}
          <Toggle
            checked={config.retryOnFailure}
            onChange={v => set('retryOnFailure', v)}
            label="Retry on Failure"
            description="Automatically retry failed HEC requests with exponential backoff."
          />
        </div>

        {/* Save */}
        <div className="pt-1 flex items-center gap-3">
          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg
                       bg-falcon-red text-white hover:bg-falcon-red/90
                       disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {saveMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <CheckCircle2 className="w-4 h-4" />
            )}
            {saveMutation.isPending ? 'Saving...' : 'Save Settings'}
          </button>
          {saved && (
            <span className="text-xs text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Saved
            </span>
          )}
          {saveMutation.isError && (
            <span className="text-xs text-red-400">Failed to save settings.</span>
          )}
        </div>
      </div>
    </Card>
  )
}

// ─── Field Mapping Card ───────────────────────────────────────────────────────

function FieldMappingCard() {
  const [mappings, setMappings] = useState<FieldMapping[]>(DEFAULT_MAPPINGS)

  const updateMapping = (id: string, field: 'edrField' | 'splunkField', value: string) =>
    setMappings(prev => prev.map(m => (m.id === id ? { ...m, [field]: value } : m)))

  const removeMapping = (id: string) =>
    setMappings(prev => prev.filter(m => m.id !== id))

  const addMapping = () =>
    setMappings(prev => [
      ...prev,
      { id: String(Date.now()), edrField: '', splunkField: '' },
    ])

  return (
    <Card
      title="Field Mapping"
      subtitle="Map EDR event fields to Splunk field names"
      icon={<List className="w-4 h-4" />}
    >
      <div className="space-y-3">
        {/* Header */}
        <div className="grid grid-cols-[1fr_1fr_36px] gap-3 px-1">
          <span className="text-xs font-medium text-falcon-muted uppercase tracking-wide">EDR Field</span>
          <span className="text-xs font-medium text-falcon-muted uppercase tracking-wide">Splunk Field</span>
          <span />
        </div>

        {/* Rows */}
        {mappings.map(mapping => (
          <div key={mapping.id} className="grid grid-cols-[1fr_1fr_36px] gap-3 items-center">
            <TextInput
              value={mapping.edrField}
              onChange={v => updateMapping(mapping.id, 'edrField', v)}
              placeholder="edr_field"
            />
            <TextInput
              value={mapping.splunkField}
              onChange={v => updateMapping(mapping.id, 'splunkField', v)}
              placeholder="splunk_field"
            />
            <button
              onClick={() => removeMapping(mapping.id)}
              className="w-9 h-9 flex items-center justify-center rounded-lg border border-falcon-border
                         text-falcon-muted hover:border-red-500/40 hover:text-red-400 transition-all"
            >
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        ))}

        {/* Add button */}
        <button
          onClick={addMapping}
          className="flex items-center gap-2 text-sm text-falcon-muted hover:text-falcon-text
                     border border-dashed border-falcon-border hover:border-falcon-muted/50
                     rounded-lg px-3 py-2 w-full justify-center transition-all"
        >
          <span className="text-base leading-none">+</span>
          Add Mapping
        </button>
      </div>
    </Card>
  )
}

// ─── Sync Status Card ─────────────────────────────────────────────────────────

function SyncStatusCard() {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['splunk-sync-status'],
    queryFn: () => apiFetch('/api/v1/admin/integrations/splunk/status'),
    refetchInterval: 30_000,
  })

  const status: SyncStatus = (data as SyncStatus) ?? { connected: false, lastEvent: null, eventsToday: 0, errorsToday: 0 }

  return (
    <Card
      title="Sync Status"
      subtitle="Real-time forwarding health and statistics"
      icon={<Activity className="w-4 h-4" />}
    >
      <div className="space-y-5">
        {/* Connection badge */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div
              className={`w-2.5 h-2.5 rounded-full ${
                isLoading ? 'bg-yellow-400 animate-pulse' :
                status.connected ? 'bg-emerald-400' : 'bg-red-400'
              }`}
            />
            <span className="text-sm font-medium text-falcon-text">
              {isLoading ? 'Checking...' : status.connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <button
            onClick={() => refetch()}
            className="p-1.5 rounded-lg border border-falcon-border text-falcon-muted
                       hover:border-falcon-muted/50 hover:text-falcon-text transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="bg-[#070d19] rounded-lg border border-falcon-border px-4 py-3">
            <p className="text-xs text-falcon-muted mb-1">Last Event Forwarded</p>
            <p className="text-sm font-medium text-falcon-text">
              {status.lastEvent ?? 'Never'}
            </p>
          </div>
          <div className="bg-[#070d19] rounded-lg border border-falcon-border px-4 py-3">
            <p className="text-xs text-falcon-muted mb-1">Events Today</p>
            <p className="text-sm font-medium text-emerald-400">
              {(status.eventsToday ?? 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-[#070d19] rounded-lg border border-falcon-border px-4 py-3">
            <p className="text-xs text-falcon-muted mb-1">Errors Today</p>
            <p className={`text-sm font-medium ${status.errorsToday > 0 ? 'text-red-400' : 'text-falcon-text'}`}>
              {status.errorsToday}
            </p>
          </div>
        </div>

        {/* Error hint */}
        {status.errorsToday > 0 && (
          <div className="flex items-start gap-2.5 bg-amber-900/15 border border-amber-700/30 rounded-lg px-4 py-3">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-amber-300">
              {status.errorsToday} forwarding error{status.errorsToday !== 1 ? 's' : ''} occurred today.
              Check Splunk HEC token validity and network connectivity.
            </p>
          </div>
        )}
      </div>
    </Card>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SplunkIntegrationPage() {
  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-8">
        {/* Breadcrumb */}
        <div className="flex items-center gap-1.5 text-xs text-falcon-muted mb-4">
          <span>管理</span>
          <ChevronRight className="w-3.5 h-3.5" />
          <span>インテグレーション</span>
          <ChevronRight className="w-3.5 h-3.5" />
          <span className="text-falcon-text">Splunk</span>
        </div>

        {/* Title row */}
        <div className="flex items-center gap-4">
          {/* Splunk logo placeholder */}
          <div className="w-12 h-12 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center shrink-0">
            <span className="text-emerald-400 font-bold text-xl">S</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Splunk Integration</h1>
            <p className="text-sm text-falcon-muted mt-0.5">
              Forward EDR alerts and events to Splunk via HTTP Event Collector (HEC)
            </p>
          </div>
        </div>
      </div>

      {/* Cards */}
      <div className="max-w-4xl space-y-6">
        <HECConnectionCard />
        <ForwardingSettingsCard />
        <FieldMappingCard />
        <SyncStatusCard />
      </div>
    </div>
  )
}
