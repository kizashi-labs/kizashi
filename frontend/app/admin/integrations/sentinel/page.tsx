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
  Database,
  Settings,
  List,
  Send,
  ToggleLeft,
  ToggleRight,
  Pencil,
  Save,
  X,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ───────────────────────────────────────────────────────────────────

type ConnectionStatus = 'idle' | 'testing' | 'success' | 'error'

interface WorkspaceConfig {
  workspaceId: string
  primaryKey: string
  logType: string
  timeGeneratedField: string
}

interface DataCollectionConfig {
  enabled: boolean
  forwardSecurityAlerts: boolean
  forwardSecurityEvents: boolean
  forwardCustomLogs: boolean
  minSeverity: number
  batchIntervalMinutes: number
  maxBatchSize: number
}

interface FieldMapping {
  id: string
  edrField: string
  sentinelColumn: string
  editing?: boolean
}

interface SyncStatus {
  connected: boolean
  lastBatch: string | null
  recordsToday: number
  errorsToday: number
}

// ─── Defaults ────────────────────────────────────────────────────────────────

const DEFAULT_WORKSPACE: WorkspaceConfig = {
  workspaceId: '',
  primaryKey: '',
  logType: 'CommonSecurityLog',
  timeGeneratedField: 'TimeGenerated',
}

const DEFAULT_COLLECTION: DataCollectionConfig = {
  enabled: false,
  forwardSecurityAlerts: true,
  forwardSecurityEvents: false,
  forwardCustomLogs: false,
  minSeverity: 5,
  batchIntervalMinutes: 5,
  maxBatchSize: 500,
}

const DEFAULT_MAPPINGS: FieldMapping[] = [
  { id: '1', edrField: 'title',    sentinelColumn: 'AlertName' },
  { id: '2', edrField: 'severity', sentinelColumn: 'AlertSeverity' },
  { id: '3', edrField: 'agent_id', sentinelColumn: 'Computer' },
  { id: '4', edrField: 'status',   sentinelColumn: 'Status' },
]

const DEFAULT_STATUS: SyncStatus = {
  connected: false,
  lastBatch: null,
  recordsToday: 0,
  errorsToday: 0,
}

// ─── Shared Card Shell ────────────────────────────────────────────────────────

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
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
      <div className="flex items-start gap-3 mb-5">
        {icon && (
          <div className="mt-0.5 w-8 h-8 rounded-lg bg-[#070d19] border border-[#1e2d42] flex items-center justify-center shrink-0 text-[#7d92b0]">
            {icon}
          </div>
        )}
        <div>
          <h2 className="text-sm font-semibold text-[#e2e8f4]">{title}</h2>
          {subtitle && (
            <p className="text-xs text-[#7d92b0] mt-0.5">{subtitle}</p>
          )}
        </div>
      </div>
      {children}
    </div>
  )
}

// ─── Label + Input helpers ───────────────────────────────────────────────────

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium text-[#7d92b0] mb-1.5">
      {children}
    </label>
  )
}

function TextInput({
  value,
  onChange,
  placeholder,
  disabled,
  className,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  disabled?: boolean
  className?: string
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className={`w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2
                  text-sm text-[#e2e8f4] placeholder-[#3d5166]
                  focus:outline-hidden focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/20
                  disabled:opacity-50 disabled:cursor-not-allowed transition-colors ${className ?? ''}`}
    />
  )
}

function SelectInput({
  value,
  onChange,
  options,
  disabled,
}: {
  value: string | number
  onChange: (v: string) => void
  options: { label: string; value: string | number }[]
  disabled?: boolean
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      disabled={disabled}
      className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
    >
      {options.map(o => (
        <option key={String(o.value)} value={String(o.value)}>
          {o.label}
        </option>
      ))}
    </select>
  )
}

// ─── Toggle ──────────────────────────────────────────────────────────────────

function Toggle({
  enabled,
  onChange,
  label,
  description,
}: {
  enabled: boolean
  onChange: (v: boolean) => void
  label: string
  description?: string
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <div>
        <p className="text-sm text-[#e2e8f4] font-medium">{label}</p>
        {description && (
          <p className="text-xs text-[#7d92b0] mt-0.5">{description}</p>
        )}
      </div>
      <button
        type="button"
        onClick={() => onChange(!enabled)}
        className="shrink-0 ml-4"
        aria-checked={enabled}
        role="switch"
      >
        {enabled ? (
          <ToggleRight className="w-8 h-8 text-blue-500" />
        ) : (
          <ToggleLeft className="w-8 h-8 text-[#3d5166]" />
        )}
      </button>
    </div>
  )
}

// ─── Connection Card ──────────────────────────────────────────────────────────

function ConnectionCard() {
  const [cfg, setCfg] = useState<WorkspaceConfig>(DEFAULT_WORKSPACE)
  const [showKey, setShowKey] = useState(false)
  const [testStatus, setTestStatus] = useState<ConnectionStatus>('idle')
  const [testError, setTestError] = useState('')
  const [saved, setSaved] = useState(false)

  const testMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/integrations/sentinel/test', {
        method: 'POST',
        body: JSON.stringify(cfg),
      }),
    onMutate: () => {
      setTestStatus('testing')
      setTestError('')
    },
    onSuccess: () => setTestStatus('success'),
    onError: (err: Error) => {
      setTestStatus('error')
      setTestError(err.message || 'Connection failed')
    },
  })

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/integrations/sentinel/config', {
        method: 'PUT',
        body: JSON.stringify(cfg),
      }),
    onSuccess: () => {
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    },
  })

  const set = (k: keyof WorkspaceConfig) => (v: string) =>
    setCfg(prev => ({ ...prev, [k]: v }))

  return (
    <Card
      title="Workspace Connection"
      subtitle="Configure your Microsoft Sentinel Log Analytics workspace credentials"
      icon={<Settings className="w-4 h-4" />}
    >
      <div className="space-y-4">
        {/* Workspace ID */}
        <div>
          <FieldLabel>Workspace ID</FieldLabel>
          <TextInput
            value={cfg.workspaceId}
            onChange={set('workspaceId')}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
          />
          <p className="text-xs text-[#3d5166] mt-1">
            Found in Azure Portal → Log Analytics workspace → Settings → Agents
          </p>
        </div>

        {/* Primary Key */}
        <div>
          <FieldLabel>プライマリキー</FieldLabel>
          <div className="relative">
            <input
              type={showKey ? 'text' : 'password'}
              value={cfg.primaryKey}
              onChange={e => set('primaryKey')(e.target.value)}
              placeholder="Workspace primary or secondary key"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 pr-10 text-sm text-[#e2e8f4] placeholder-[#3d5166] focus:outline-hidden focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/20 transition-colors"
            />
            <button
              type="button"
              onClick={() => setShowKey(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[#7d92b0] hover:text-[#e2e8f4]"
            >
              {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Log Type + Time Field */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <FieldLabel>ログタイプ</FieldLabel>
            <TextInput
              value={cfg.logType}
              onChange={set('logType')}
              placeholder="CommonSecurityLog"
            />
            <p className="text-xs text-[#3d5166] mt-1">Custom table name in Sentinel</p>
          </div>
          <div>
            <FieldLabel>タイムスタンプフィールド</FieldLabel>
            <TextInput
              value={cfg.timeGeneratedField}
              onChange={set('timeGeneratedField')}
              placeholder="TimeGenerated"
            />
            <p className="text-xs text-[#3d5166] mt-1">Field used for event timestamp</p>
          </div>
        </div>

        {/* Test connection result */}
        {testStatus === 'success' && (
          <div className="flex items-center gap-2 text-emerald-400 bg-emerald-900/15 border border-emerald-700/30 rounded-lg px-4 py-2.5 text-sm">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            Connection successful — workspace is reachable
          </div>
        )}
        {testStatus === 'error' && (
          <div className="flex items-start gap-2 text-red-400 bg-red-900/15 border border-[#e8002d]/30 rounded-lg px-4 py-2.5 text-sm">
            <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{testError || 'Connection failed. Check credentials and network.'}</span>
          </div>
        )}

        {/* Action buttons */}
        <div className="flex items-center gap-3 pt-1">
          <button
            onClick={() => testMutation.mutate()}
            disabled={testStatus === 'testing' || !cfg.workspaceId || !cfg.primaryKey}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-blue-500/40 text-blue-400 text-sm font-medium hover:bg-blue-500/10 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {testStatus === 'testing' ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Activity className="w-4 h-4" />
            )}
            Test Connection
          </button>

          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {saveMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : saved ? (
              <CheckCircle2 className="w-4 h-4" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saved ? 'Saved!' : 'Save Configuration'}
          </button>
        </div>
      </div>
    </Card>
  )
}

// ─── Data Collection Card ─────────────────────────────────────────────────────

function DataCollectionCard() {
  const [cfg, setCfg] = useState<DataCollectionConfig>(DEFAULT_COLLECTION)
  const [saved, setSaved] = useState(false)

  const set = <K extends keyof DataCollectionConfig>(k: K) =>
    (v: DataCollectionConfig[K]) => setCfg(prev => ({ ...prev, [k]: v }))

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/integrations/sentinel/collection', {
        method: 'PUT',
        body: JSON.stringify(cfg),
      }),
    onSuccess: () => {
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    },
  })

  const severityOptions = [
    { label: 'Low (1+)',      value: 1 },
    { label: 'Medium (3+)',   value: 3 },
    { label: 'High (5+)',     value: 5 },
    { label: 'Critical (8+)', value: 8 },
  ]

  const batchIntervalOptions = [
    { label: '1 minute',   value: 1 },
    { label: '5 minutes',  value: 5 },
    { label: '15 minutes', value: 15 },
    { label: '30 minutes', value: 30 },
  ]

  const batchSizeOptions = [
    { label: '100 records',  value: 100 },
    { label: '500 records',  value: 500 },
    { label: '1000 records', value: 1000 },
  ]

  return (
    <Card
      title="Data Collection"
      subtitle="Control which event types and volumes are forwarded to Microsoft Sentinel"
      icon={<Database className="w-4 h-4" />}
    >
      <div className="space-y-4">
        {/* Master enable toggle */}
        <div className="pb-3 border-b border-[#1e2d42]">
          <Toggle
            enabled={cfg.enabled}
            onChange={set('enabled')}
            label="Enable Data Forwarding"
            description="When enabled, EDR events will be continuously sent to your Sentinel workspace"
          />
        </div>

        {/* Table selection */}
        <div>
          <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider mb-3">
            Tables to Forward
          </p>
          <div className={`space-y-1 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
            <Toggle
              enabled={cfg.forwardSecurityAlerts}
              onChange={set('forwardSecurityAlerts')}
              label="Security Alerts"
              description="EDR detection alerts and threat detections"
            />
            <Toggle
              enabled={cfg.forwardSecurityEvents}
              onChange={set('forwardSecurityEvents')}
              label="Security Events"
              description="Raw endpoint events (process, file, network activity)"
            />
            <Toggle
              enabled={cfg.forwardCustomLogs}
              onChange={set('forwardCustomLogs')}
              label="Custom Logs"
              description="User-defined custom log entries from agents"
            />
          </div>
        </div>

        {/* Batch settings */}
        <div className={`grid grid-cols-1 sm:grid-cols-3 gap-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
          <div>
            <FieldLabel>最小重大度しきい値</FieldLabel>
            <SelectInput
              value={cfg.minSeverity}
              onChange={v => set('minSeverity')(Number(v) as DataCollectionConfig['minSeverity'])}
              options={severityOptions}
            />
          </div>
          <div>
            <FieldLabel>バッチ間隔</FieldLabel>
            <SelectInput
              value={cfg.batchIntervalMinutes}
              onChange={v => set('batchIntervalMinutes')(Number(v) as DataCollectionConfig['batchIntervalMinutes'])}
              options={batchIntervalOptions}
            />
          </div>
          <div>
            <FieldLabel>最大バッチサイズ</FieldLabel>
            <SelectInput
              value={cfg.maxBatchSize}
              onChange={v => set('maxBatchSize')(Number(v) as DataCollectionConfig['maxBatchSize'])}
              options={batchSizeOptions}
            />
          </div>
        </div>

        <div className="pt-1">
          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {saveMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : saved ? (
              <CheckCircle2 className="w-4 h-4" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saved ? 'Saved!' : 'Save Settings'}
          </button>
        </div>
      </div>
    </Card>
  )
}

// ─── Schema Mapping Card ──────────────────────────────────────────────────────

function SchemaMappingCard() {
  const [mappings, setMappings] = useState<FieldMapping[]>(DEFAULT_MAPPINGS)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editValues, setEditValues] = useState<{ edrField: string; sentinelColumn: string }>({
    edrField: '',
    sentinelColumn: '',
  })
  const [saved, setSaved] = useState(false)
  const [newRow, setNewRow] = useState<{ edrField: string; sentinelColumn: string }>({
    edrField: '',
    sentinelColumn: '',
  })

  const startEdit = (m: FieldMapping) => {
    setEditingId(m.id)
    setEditValues({ edrField: m.edrField, sentinelColumn: m.sentinelColumn })
  }

  const cancelEdit = () => setEditingId(null)

  const commitEdit = (id: string) => {
    setMappings(prev =>
      prev.map(m => (m.id === id ? { ...m, ...editValues } : m))
    )
    setEditingId(null)
  }

  const removeMapping = (id: string) => {
    setMappings(prev => prev.filter(m => m.id !== id))
  }

  const addMapping = () => {
    if (!newRow.edrField.trim() || !newRow.sentinelColumn.trim()) return
    setMappings(prev => [
      ...prev,
      { id: String(Date.now()), ...newRow },
    ])
    setNewRow({ edrField: '', sentinelColumn: '' })
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      // 同上。保存は POST です。
      apiFetch('/api/v1/admin/integrations/sentinel/mappings', {
        method: 'POST',
        body: JSON.stringify({ mappings }),
      }),
    onSuccess: () => {
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    },
  })

  return (
    <Card
      title="Schema Mapping"
      subtitle="Map EDR field names to Microsoft Sentinel column names"
      icon={<List className="w-4 h-4" />}
    >
      <div className="space-y-4">
        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-[#1e2d42]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-[#7d92b0] uppercase tracking-wider">
                  EDR Field
                </th>
                <th className="text-left px-4 py-2.5 text-xs font-semibold text-[#7d92b0] uppercase tracking-wider">
                  Sentinel Column
                </th>
                <th className="w-20 px-4 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {mappings.map(m => (
                <tr key={m.id} className="hover:bg-[#070d19]/50 transition-colors">
                  <td className="px-4 py-2.5">
                    {editingId === m.id ? (
                      <TextInput
                        value={editValues.edrField}
                        onChange={v => setEditValues(p => ({ ...p, edrField: v }))}
                        className="text-xs py-1"
                      />
                    ) : (
                      <span className="font-mono text-xs text-blue-300 bg-blue-900/20 px-2 py-0.5 rounded-sm">
                        {m.edrField}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    {editingId === m.id ? (
                      <TextInput
                        value={editValues.sentinelColumn}
                        onChange={v => setEditValues(p => ({ ...p, sentinelColumn: v }))}
                        className="text-xs py-1"
                      />
                    ) : (
                      <span className="font-mono text-xs text-[#e2e8f4]">{m.sentinelColumn}</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5 justify-end">
                      {editingId === m.id ? (
                        <>
                          <button
                            onClick={() => commitEdit(m.id)}
                            className="p-1 rounded-sm text-emerald-400 hover:bg-emerald-900/20"
                            title="Save"
                          >
                            <Save className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={cancelEdit}
                            className="p-1 rounded-sm text-[#7d92b0] hover:bg-[#1e2d42]"
                            title="Cancel"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </>
                      ) : (
                        <>
                          <button
                            onClick={() => startEdit(m)}
                            className="p-1 rounded-sm text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#1e2d42]"
                            title="Edit"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => removeMapping(m.id)}
                            className="p-1 rounded-sm text-[#7d92b0] hover:text-[#e8002d] hover:bg-red-900/15"
                            title="Remove"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}

              {/* Add new row */}
              <tr className="bg-[#070d19]/30">
                <td className="px-4 py-2.5">
                  <TextInput
                    value={newRow.edrField}
                    onChange={v => setNewRow(p => ({ ...p, edrField: v }))}
                    placeholder="edr_field"
                    className="text-xs py-1"
                  />
                </td>
                <td className="px-4 py-2.5">
                  <TextInput
                    value={newRow.sentinelColumn}
                    onChange={v => setNewRow(p => ({ ...p, sentinelColumn: v }))}
                    placeholder="SentinelColumn"
                    className="text-xs py-1"
                  />
                </td>
                <td className="px-4 py-2.5 text-right">
                  <button
                    onClick={addMapping}
                    disabled={!newRow.edrField.trim() || !newRow.sentinelColumn.trim()}
                    className="text-xs px-2.5 py-1 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    + Add
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <p className="text-xs text-[#3d5166]">
          Each row defines how an EDR field maps to a column in your Sentinel
          Log Analytics table. Fields not listed here are forwarded with their
          original names.
        </p>

        <button
          onClick={() => saveMutation.mutate()}
          disabled={saveMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          {saveMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : saved ? (
            <CheckCircle2 className="w-4 h-4" />
          ) : (
            <Save className="w-4 h-4" />
          )}
          {saved ? 'Saved!' : 'Save Mappings'}
        </button>
      </div>
    </Card>
  )
}

// ─── Sync Status Card ─────────────────────────────────────────────────────────

function SyncStatusCard() {
  const { data: status, isLoading, refetch } = useQuery<SyncStatus>({
    queryKey: ['sentinel-sync-status'],
    queryFn: () =>
      apiFetch<SyncStatus>('/api/v1/admin/integrations/sentinel/status'),
    refetchInterval: 30_000,
    initialData: DEFAULT_STATUS,
  })

  const sendNowMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/integrations/sentinel/send-now', {
        method: 'POST',
      }),
    onSuccess: () => refetch(),
  })

  const fmtDate = (d: string | null) => {
    if (!d) return 'Never'
    try {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: 'short',
        timeStyle: 'medium',
      }).format(new Date(d))
    } catch {
      return d
    }
  }

  return (
    <Card
      title="Sync Status"
      subtitle="Real-time forwarding health and batch statistics"
      icon={<Activity className="w-4 h-4" />}
    >
      <div className="space-y-5">
        {/* Connection badge */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div
              className={`w-2.5 h-2.5 rounded-full ${
                isLoading
                  ? 'bg-yellow-400 animate-pulse'
                  : status?.connected
                  ? 'bg-emerald-400'
                  : 'bg-[#e8002d]'
              }`}
            />
            <span className="text-sm font-medium text-[#e2e8f4]">
              {isLoading
                ? 'Checking...'
                : status?.connected
                ? 'Connected to Sentinel'
                : 'Disconnected'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              disabled={isLoading}
              className="p-1.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/50 hover:text-[#e2e8f4] transition-all"
              title="Refresh status"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => sendNowMutation.mutate()}
              disabled={sendNowMutation.isPending || !status?.connected}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400 text-xs font-medium hover:bg-blue-600/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {sendNowMutation.isPending ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Send className="w-3.5 h-3.5" />
              )}
              Send Now
            </button>
          </div>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">Connection</p>
            <p className={`text-sm font-semibold ${status?.connected ? 'text-emerald-400' : 'text-[#e8002d]'}`}>
              {status?.connected ? 'Active' : 'Offline'}
            </p>
          </div>
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">Last Batch</p>
            <p className="text-sm font-medium text-[#e2e8f4]">
              {fmtDate(status?.lastBatch ?? null)}
            </p>
          </div>
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">Records Today</p>
            <p className="text-sm font-semibold text-emerald-400">
              {(status?.recordsToday ?? 0).toLocaleString()}
            </p>
          </div>
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">Errors Today</p>
            <p className={`text-sm font-semibold ${(status?.errorsToday ?? 0) > 0 ? 'text-[#e8002d]' : 'text-[#e2e8f4]'}`}>
              {status?.errorsToday ?? 0}
            </p>
          </div>
        </div>

        {/* Error hint */}
        {(status?.errorsToday ?? 0) > 0 && (
          <div className="flex items-start gap-2.5 bg-amber-900/15 border border-amber-700/30 rounded-lg px-4 py-3">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="text-xs text-amber-300">
              {status?.errorsToday} forwarding error
              {(status?.errorsToday ?? 0) !== 1 ? 's' : ''} occurred today.
              Verify your Workspace ID, Primary Key, and Log Type configuration.
            </p>
          </div>
        )}

        {/* Send now feedback */}
        {sendNowMutation.isSuccess && (
          <div className="flex items-center gap-2 text-emerald-400 bg-emerald-900/15 border border-emerald-700/30 rounded-lg px-4 py-2.5 text-sm">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            Batch submitted to Sentinel successfully
          </div>
        )}
      </div>
    </Card>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SentinelIntegrationPage() {
  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="mb-8">
        {/* Breadcrumb */}
        <div className="flex items-center gap-1.5 text-xs text-[#7d92b0] mb-4">
          <span>管理</span>
          <ChevronRight className="w-3.5 h-3.5" />
          <span>インテグレーション</span>
          <ChevronRight className="w-3.5 h-3.5" />
          <span className="text-[#e2e8f4]">Microsoft Sentinel</span>
        </div>

        {/* Title row */}
        <div className="flex items-center gap-4">
          {/* Microsoft Sentinel logo placeholder — blue circle with "MS" */}
          <div className="w-12 h-12 rounded-xl bg-blue-600/15 border border-blue-500/30 flex items-center justify-center shrink-0">
            <span className="text-blue-400 font-bold text-sm select-none">MS</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">Microsoft Sentinel Integration</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">
              Forward EDR security alerts and events to your Azure Sentinel Log Analytics workspace
            </p>
          </div>
        </div>
      </div>

      {/* Cards */}
      <div className="max-w-4xl space-y-6">
        <ConnectionCard />
        <DataCollectionCard />
        <SchemaMappingCard />
        <SyncStatusCard />
      </div>
    </div>
  )
}
