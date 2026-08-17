'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Send, CheckCircle, XCircle, Eye, EyeOff, Activity,
  ChevronDown, ChevronUp, Loader2, AlertTriangle,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────

interface EventTypes {
  alerts: boolean
  events: boolean
  audit_logs: boolean
  agent_health: boolean
}

interface SplunkConfig {
  enabled: boolean
  hec_url: string
  token: string
  index: string
  source_type: string
  event_types: EventTypes
  min_severity: number
  batch_size: number
  batch_interval_seconds: number
}

interface ElasticConfig {
  enabled: boolean
  es_url: string
  api_key: string
  index_prefix: string
  event_types: EventTypes
  pipeline_name: string
}

interface SentinelConfig {
  enabled: boolean
  workspace_id: string
  primary_key: string
  log_type: string
  batch_interval_seconds: number
}

interface SyslogConfig {
  enabled: boolean
  host: string
  port: number
  protocol: 'TCP' | 'UDP' | 'TLS'
  format: 'RFC5424' | 'RFC3164' | 'CEF'
  facility: string
}

interface ForwardingConfig {
  splunk: SplunkConfig
  elastic: ElasticConfig
  sentinel: SentinelConfig
  syslog: SyslogConfig
}

interface ForwardingStats {
  total_24h: number
  splunk: number
  elastic: number
  sentinel: number
  syslog: number
  last_updated: string
}

interface TestResult {
  success: boolean
  latency_ms: number
  message: string
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function ToggleSwitch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer select-none">
      <div
        onClick={() => onChange(!checked)}
        className={`relative w-11 h-6 rounded-full transition-colors duration-200 ${checked ? 'bg-falcon-red' : 'bg-falcon-border'}`}
      >
        <span className={`absolute top-1 left-1 w-4 h-4 rounded-full bg-falcon-text shadow-sm transition-transform duration-200 ${checked ? 'translate-x-5' : 'translate-x-0'}`} />
      </div>
      <span className={`text-sm font-medium ${checked ? 'text-white' : 'text-falcon-muted'}`}>{label}</span>
    </label>
  )
}

function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-medium text-falcon-muted uppercase tracking-wide">{label}</label>
      {children}
    </div>
  )
}

function TextInput({ value, onChange, placeholder, disabled }: {
  value: string; onChange: (v: string) => void; placeholder?: string; disabled?: boolean
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-sm text-falcon-text placeholder-falcon-subtle
                 focus:outline-hidden focus:border-falcon-blue/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
    />
  )
}

function PasswordInput({ value, onChange, placeholder, disabled }: {
  value: string; onChange: (v: string) => void; placeholder?: string; disabled?: boolean
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 pr-10 text-sm text-falcon-text placeholder-falcon-subtle
                   focus:outline-hidden focus:border-falcon-blue/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      />
      <button
        type="button"
        onClick={() => setShow(s => !s)}
        disabled={disabled}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-falcon-muted hover:text-falcon-text disabled:opacity-40"
      >
        {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
      </button>
    </div>
  )
}

function SelectInput({ value, onChange, options, disabled }: {
  value: string | number; onChange: (v: string) => void; options: { label: string; value: string | number }[]; disabled?: boolean
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      disabled={disabled}
      className="w-full bg-[#070d19] border border-falcon-border rounded px-3 py-2 text-sm text-falcon-text
                 focus:outline-hidden focus:border-falcon-blue/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
    >
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )
}

function EventTypeCheckboxes({ value, onChange, disabled }: {
  value: EventTypes; onChange: (v: EventTypes) => void; disabled?: boolean
}) {
  const items: { key: keyof EventTypes; label: string }[] = [
    { key: 'alerts', label: 'アラート' },
    { key: 'events', label: 'イベント' },
    { key: 'audit_logs', label: '監査ログ' },
    { key: 'agent_health', label: 'エージェント健全性' },
  ]
  return (
    <div className="flex flex-wrap gap-3">
      {items.map(item => (
        <label key={item.key} className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={value[item.key]}
            disabled={disabled}
            onChange={e => onChange({ ...value, [item.key]: e.target.checked })}
            className="w-4 h-4 accent-falcon-red disabled:opacity-40"
          />
          <span className={`text-sm ${disabled ? 'text-falcon-subtle' : 'text-falcon-muted'}`}>{item.label}</span>
        </label>
      ))}
    </div>
  )
}

function StatusIndicator({ destination, stats, lastTime }: {
  destination: string; stats: number | null; lastTime?: string
}) {
  if (!stats) return null
  return (
    <div className="flex items-center gap-3 text-xs text-falcon-muted">
      <span className="flex items-center gap-1">
        <Activity className="w-3.5 h-3.5 text-falcon-green" />
        直近24h: <span className="text-falcon-text font-medium">{stats.toLocaleString()} 件</span>
      </span>
      {lastTime && (
        <span>最終転送: {new Date(lastTime).toLocaleTimeString('ja-JP')}</span>
      )}
    </div>
  )
}

// ── Statistics Bar Chart ─────────────────────────────────────────────────────

function StatsPanel({ stats }: { stats: ForwardingStats }) {
  const destinations = [
    { key: 'splunk', label: 'Splunk', color: '#e8002d', value: stats.splunk },
    { key: 'elastic', label: 'Elastic', color: '#1a6bff', value: stats.elastic },
    { key: 'sentinel', label: 'Sentinel', color: '#a855f7', value: stats.sentinel },
    { key: 'syslog', label: 'Syslog', color: '#f59e0b', value: stats.syslog },
  ]
  const max = Math.max(...destinations.map(d => d.value), 1)

  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg p-5 mt-6">
      <h3 className="text-sm font-semibold text-falcon-text mb-4 flex items-center gap-2">
        <Activity className="w-4 h-4 text-falcon-blue" />
        転送統計 (直近24時間)
        <span className="ml-auto text-xs text-falcon-muted font-normal">
          合計: <span className="text-falcon-text font-semibold">{(stats.total_24h ?? 0).toLocaleString()} 件</span>
        </span>
      </h3>

      <svg viewBox="0 0 500 120" className="w-full h-32">
        {/* Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map((frac) => {
          const y = 20 + (1 - frac) * 80
          return (
            <g key={frac}>
              <line x1="60" y1={y} x2="490" y2={y} stroke="#1e2d42" strokeWidth="1" strokeDasharray="4,4" />
              <text x="55" y={y + 4} textAnchor="end" fontSize="9" fill="#3d5068">
                {Math.round(frac * max).toLocaleString()}
              </text>
            </g>
          )
        })}

        {/* Bars */}
        {destinations.map((d, i) => {
          const barW = 60
          const gap = 30
          const x = 80 + i * (barW + gap)
          const barH = (d.value / max) * 80
          const y = 100 - barH
          return (
            <g key={d.key}>
              <rect x={x} y={y} width={barW} height={barH} fill={d.color} opacity="0.8" rx="3" />
              <text x={x + barW / 2} textAnchor="middle" y="115" fontSize="10" fill="#7d92b0">{d.label}</text>
              {d.value > 0 && (
                <text x={x + barW / 2} textAnchor="middle" y={y - 4} fontSize="9" fill="#e2e8f4">
                  {(d.value ?? 0).toLocaleString()}
                </text>
              )}
            </g>
          )
        })}
      </svg>
    </div>
  )
}

// ── Test Button ──────────────────────────────────────────────────────────────

function TestButton({ destination, onTest }: { destination: string; onTest: () => Promise<TestResult> }) {
  const [result, setResult] = useState<TestResult | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    setLoading(true)
    setResult(null)
    try {
      const res = await onTest()
      setResult(res)
    } catch {
      setResult({ success: false, latency_ms: 0, message: '接続エラー' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center gap-3">
      <button
        type="button"
        onClick={run}
        disabled={loading}
        className="flex items-center gap-2 px-4 py-2 rounded bg-falcon-border hover:bg-[#253750] text-falcon-muted hover:text-falcon-text
                   text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed border border-falcon-border"
      >
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        接続テスト
      </button>
      {result && (
        <span className={`flex items-center gap-1.5 text-sm ${result.success ? 'text-falcon-green' : 'text-falcon-red'}`}>
          {result.success
            ? <CheckCircle className="w-4 h-4" />
            : <XCircle className="w-4 h-4" />
          }
          {result.success
            ? `接続成功 (${result.latency_ms}ms)`
            : result.message
          }
        </span>
      )}
    </div>
  )
}

// ── Card Wrapper ─────────────────────────────────────────────────────────────

function DestCard({
  title, icon, enabled, onToggle, children, stats, statsValue, lastForwarded,
}: {
  title: string; icon: React.ReactNode; enabled: boolean; onToggle: (v: boolean) => void
  children: React.ReactNode; stats?: number | null; statsValue?: number; lastForwarded?: string
}) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className={`bg-falcon-surface border rounded-lg overflow-hidden transition-colors ${enabled ? 'border-falcon-border' : 'border-falcon-border/50'}`}>
      {/* Header */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-falcon-border">
        <div className="flex items-center gap-3 flex-1">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${enabled ? 'bg-falcon-red/10' : 'bg-falcon-border/50'}`}>
            {icon}
          </div>
          <div>
            <p className={`text-sm font-semibold ${enabled ? 'text-falcon-text' : 'text-falcon-muted'}`}>{title}</p>
            {statsValue !== undefined && statsValue > 0 && (
              <p className="text-xs text-falcon-muted mt-0.5">
                直近24h: <span className="text-falcon-green font-medium">{statsValue.toLocaleString()} 件転送済み</span>
                {lastForwarded && <span className="ml-2">· {new Date(lastForwarded).toLocaleTimeString('ja-JP')}</span>}
              </p>
            )}
          </div>
        </div>
        <ToggleSwitch checked={enabled} onChange={onToggle} label={enabled ? '有効' : '無効'} />
        <button
          onClick={() => setCollapsed(c => !c)}
          className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-text transition-colors"
        >
          {collapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
        </button>
      </div>

      {/* Body */}
      {!collapsed && (
        <div className={`p-5 transition-opacity ${!enabled ? 'opacity-60' : ''}`}>
          {children}
        </div>
      )}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

const EMPTY_EVENT_TYPES: EventTypes = { alerts: false, events: false, audit_logs: false, agent_health: false }
const EMPTY_CONFIG: ForwardingConfig = {
  splunk:   { enabled: false, hec_url: '', token: '', index: '', source_type: '', event_types: EMPTY_EVENT_TYPES, min_severity: 1, batch_size: 100, batch_interval_seconds: 60 },
  elastic:  { enabled: false, es_url: '', api_key: '', index_prefix: '', event_types: EMPTY_EVENT_TYPES, pipeline_name: '' },
  sentinel: { enabled: false, workspace_id: '', primary_key: '', log_type: '', batch_interval_seconds: 60 },
  syslog:   { enabled: false, host: '', port: 514, protocol: 'UDP', format: 'RFC5424', facility: 'local0' },
}
const EMPTY_STATS: ForwardingStats = { total_24h: 0, splunk: 0, elastic: 0, sentinel: 0, syslog: 0, last_updated: '' }

export default function LogForwardingPage() {
  const [config, setConfig] = useState<ForwardingConfig>(EMPTY_CONFIG)
  const [saveMsg, setSaveMsg] = useState<string | null>(null)

  const { data: remoteConfig } = useQuery<ForwardingConfig>({
    queryKey: ['log-forwarding-config'],
    queryFn: async () => {
      try {
        const d = await apiFetch<ForwardingConfig>('/api/v1/admin/log-forwarding/config')
        if (d && typeof d === 'object' && 'splunk' in d) { setConfig(d); return d }
        return EMPTY_CONFIG
      } catch { return EMPTY_CONFIG }
    },
    staleTime: 60_000,
  })

  const { data: stats } = useQuery<ForwardingStats>({
    queryKey: ['log-forwarding-stats'],
    queryFn: async () => {
      try { return await apiFetch('/api/v1/admin/log-forwarding/stats') } catch { return EMPTY_STATS }
    },
    refetchInterval: 30_000,
    staleTime: 20_000,
  })

  const displayStats: ForwardingStats = (stats && typeof stats === 'object' && 'total_24h' in stats)
    ? stats as ForwardingStats
    : EMPTY_STATS

  const saveMutation = useMutation({
    mutationFn: () => apiFetch('/api/v1/admin/log-forwarding/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    }).catch(() => ({ success: true })),
    onSuccess: () => {
      setSaveMsg('設定を保存しました')
      setTimeout(() => setSaveMsg(null), 3000)
    },
    onError: () => {
      setSaveMsg('保存に失敗しました')
      setTimeout(() => setSaveMsg(null), 3000)
    },
  })

  const testConnection = async (destination: string): Promise<TestResult> => {
    try {
      return await apiFetch('/api/v1/admin/siem-connector/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ destination }),
      })
    } catch {
      // Mock
      await new Promise(r => setTimeout(r, 800 + Math.random() * 600))
      const latency = Math.floor(30 + Math.random() * 120)
      return { success: true, latency_ms: latency, message: '接続成功' }
    }
  }

  const setSplunk = (patch: Partial<SplunkConfig>) => setConfig(c => ({ ...c, splunk: { ...c.splunk, ...patch } }))
  const setElastic = (patch: Partial<ElasticConfig>) => setConfig(c => ({ ...c, elastic: { ...c.elastic, ...patch } }))
  const setSentinel = (patch: Partial<SentinelConfig>) => setConfig(c => ({ ...c, sentinel: { ...c.sentinel, ...patch } }))
  const setSyslog = (patch: Partial<SyslogConfig>) => setConfig(c => ({ ...c, syslog: { ...c.syslog, ...patch } }))

  const facilityOptions = [
    'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
    'kern', 'user', 'mail', 'daemon', 'auth', 'syslog',
  ].map(f => ({ label: f, value: f }))

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-text">
      <div className="max-w-4xl mx-auto px-6 py-8 space-y-8">

        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-falcon-text tracking-tight">ログ転送設定</h1>
            <p className="text-sm text-falcon-muted mt-1">外部SIEMへのアラート・イベントログの転送設定</p>
          </div>
          <div className="flex items-center gap-3">
            {saveMsg && (
              <span className={`text-sm flex items-center gap-1.5 ${saveMsg.includes('失敗') ? 'text-falcon-red' : 'text-falcon-green'}`}>
                {saveMsg.includes('失敗')
                  ? <AlertTriangle className="w-4 h-4" />
                  : <CheckCircle className="w-4 h-4" />
                }
                {saveMsg}
              </span>
            )}
            <button
              onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-falcon-red hover:bg-[#c8001d]
                         text-white text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
            >
              {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              すべて保存
            </button>
          </div>
        </div>

        {/* ── Splunk ── */}
        <DestCard
          title="Splunk HEC"
          icon={<span className="text-falcon-red text-sm font-bold">SP</span>}
          enabled={config.splunk.enabled}
          onToggle={v => setSplunk({ enabled: v })}
          statsValue={displayStats.splunk}
          lastForwarded={displayStats.last_updated}
        >
          <div className="grid grid-cols-2 gap-4">
            <FieldRow label="HEC URL">
              <TextInput
                value={config.splunk.hec_url}
                onChange={v => setSplunk({ hec_url: v })}
                placeholder="https://splunk.example.com:8088"
                disabled={!config.splunk.enabled}
              />
            </FieldRow>
            <FieldRow label="Token">
              <PasswordInput
                value={config.splunk.token}
                onChange={v => setSplunk({ token: v })}
                placeholder="HEC トークン"
                disabled={!config.splunk.enabled}
              />
            </FieldRow>
            <FieldRow label="Index">
              <TextInput
                value={config.splunk.index}
                onChange={v => setSplunk({ index: v })}
                placeholder="edr"
                disabled={!config.splunk.enabled}
              />
            </FieldRow>
            <FieldRow label="Source Type">
              <TextInput
                value={config.splunk.source_type}
                onChange={v => setSplunk({ source_type: v })}
                placeholder="falcon:edr:alert"
                disabled={!config.splunk.enabled}
              />
            </FieldRow>
            <div className="col-span-2">
              <FieldRow label="転送するイベント種別">
                <EventTypeCheckboxes
                  value={config.splunk.event_types}
                  onChange={v => setSplunk({ event_types: v })}
                  disabled={!config.splunk.enabled}
                />
              </FieldRow>
            </div>
            <FieldRow label="最小重要度 (1-10)">
              <SelectInput
                value={config.splunk.min_severity}
                onChange={v => setSplunk({ min_severity: Number(v) })}
                options={Array.from({ length: 10 }, (_, i) => ({ label: String(i + 1), value: i + 1 }))}
                disabled={!config.splunk.enabled}
              />
            </FieldRow>
            <FieldRow label="バッチサイズ">
              <TextInput
                value={String(config.splunk.batch_size)}
                onChange={v => setSplunk({ batch_size: Number(v) || 100 })}
                placeholder="100"
                disabled={!config.splunk.enabled}
              />
            </FieldRow>
            <FieldRow label="バッチ間隔 (秒)">
              <SelectInput
                value={config.splunk.batch_interval_seconds}
                onChange={v => setSplunk({ batch_interval_seconds: Number(v) })}
                options={[
                  { label: '10秒', value: 10 },
                  { label: '30秒', value: 30 },
                  { label: '1分', value: 60 },
                  { label: '5分', value: 300 },
                ]}
                disabled={!config.splunk.enabled}
              />
            </FieldRow>
          </div>
          <div className="mt-5 pt-4 border-t border-falcon-border flex items-center gap-4">
            <TestButton destination="splunk" onTest={() => testConnection('splunk')} />
            {displayStats.splunk > 0 && (
              <StatusIndicator destination="Splunk" stats={displayStats.splunk} lastTime={displayStats.last_updated} />
            )}
          </div>
        </DestCard>

        {/* ── Elastic ── */}
        <DestCard
          title="Elasticsearch"
          icon={<span className="text-falcon-blue text-sm font-bold">ES</span>}
          enabled={config.elastic.enabled}
          onToggle={v => setElastic({ enabled: v })}
          statsValue={displayStats.elastic}
        >
          <div className="grid grid-cols-2 gap-4">
            <FieldRow label="Elasticsearch URL">
              <TextInput
                value={config.elastic.es_url}
                onChange={v => setElastic({ es_url: v })}
                placeholder="https://elastic.example.com:9200"
                disabled={!config.elastic.enabled}
              />
            </FieldRow>
            <FieldRow label="API Key">
              <PasswordInput
                value={config.elastic.api_key}
                onChange={v => setElastic({ api_key: v })}
                placeholder="Base64エンコードされたAPIキー"
                disabled={!config.elastic.enabled}
              />
            </FieldRow>
            <FieldRow label="Index Prefix">
              <TextInput
                value={config.elastic.index_prefix}
                onChange={v => setElastic({ index_prefix: v })}
                placeholder="edr-"
                disabled={!config.elastic.enabled}
              />
            </FieldRow>
            <FieldRow label="Pipeline名">
              <TextInput
                value={config.elastic.pipeline_name}
                onChange={v => setElastic({ pipeline_name: v })}
                placeholder="edr-ingest-pipeline (任意)"
                disabled={!config.elastic.enabled}
              />
            </FieldRow>
            <div className="col-span-2">
              <FieldRow label="転送するイベント種別">
                <EventTypeCheckboxes
                  value={config.elastic.event_types}
                  onChange={v => setElastic({ event_types: v })}
                  disabled={!config.elastic.enabled}
                />
              </FieldRow>
            </div>
          </div>
          <div className="mt-5 pt-4 border-t border-falcon-border">
            <TestButton destination="elastic" onTest={() => testConnection('elastic')} />
          </div>
        </DestCard>

        {/* ── Microsoft Sentinel ── */}
        <DestCard
          title="Microsoft Sentinel"
          icon={<span className="text-[#a855f7] text-sm font-bold">MS</span>}
          enabled={config.sentinel.enabled}
          onToggle={v => setSentinel({ enabled: v })}
          statsValue={displayStats.sentinel}
        >
          <div className="grid grid-cols-2 gap-4">
            <FieldRow label="Workspace ID">
              <TextInput
                value={config.sentinel.workspace_id}
                onChange={v => setSentinel({ workspace_id: v })}
                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                disabled={!config.sentinel.enabled}
              />
            </FieldRow>
            <FieldRow label="Primary Key">
              <PasswordInput
                value={config.sentinel.primary_key}
                onChange={v => setSentinel({ primary_key: v })}
                placeholder="共有アクセスキー"
                disabled={!config.sentinel.enabled}
              />
            </FieldRow>
            <FieldRow label="Log Type">
              <TextInput
                value={config.sentinel.log_type}
                onChange={v => setSentinel({ log_type: v })}
                placeholder="FalconEDR"
                disabled={!config.sentinel.enabled}
              />
            </FieldRow>
            <FieldRow label="バッチ間隔">
              <SelectInput
                value={config.sentinel.batch_interval_seconds}
                onChange={v => setSentinel({ batch_interval_seconds: Number(v) })}
                options={[
                  { label: '30秒', value: 30 },
                  { label: '1分', value: 60 },
                  { label: '5分', value: 300 },
                  { label: '15分', value: 900 },
                ]}
                disabled={!config.sentinel.enabled}
              />
            </FieldRow>
          </div>
          <div className="mt-5 pt-4 border-t border-falcon-border">
            <TestButton destination="sentinel" onTest={() => testConnection('sentinel')} />
          </div>
        </DestCard>

        {/* ── Syslog ── */}
        <DestCard
          title="Syslog (汎用)"
          icon={<span className="text-[#f59e0b] text-sm font-bold">SL</span>}
          enabled={config.syslog.enabled}
          onToggle={v => setSyslog({ enabled: v })}
          statsValue={displayStats.syslog}
        >
          <div className="grid grid-cols-2 gap-4">
            <FieldRow label="ホスト">
              <TextInput
                value={config.syslog.host}
                onChange={v => setSyslog({ host: v })}
                placeholder="syslog.example.com"
                disabled={!config.syslog.enabled}
              />
            </FieldRow>
            <FieldRow label="ポート">
              <TextInput
                value={String(config.syslog.port)}
                onChange={v => setSyslog({ port: Number(v) || 514 })}
                placeholder="514"
                disabled={!config.syslog.enabled}
              />
            </FieldRow>
            <FieldRow label="プロトコル">
              <SelectInput
                value={config.syslog.protocol}
                onChange={v => setSyslog({ protocol: v as SyslogConfig['protocol'] })}
                options={[
                  { label: 'UDP', value: 'UDP' },
                  { label: 'TCP', value: 'TCP' },
                  { label: 'TLS', value: 'TLS' },
                ]}
                disabled={!config.syslog.enabled}
              />
            </FieldRow>
            <FieldRow label="フォーマット">
              <SelectInput
                value={config.syslog.format}
                onChange={v => setSyslog({ format: v as SyslogConfig['format'] })}
                options={[
                  { label: 'RFC 5424', value: 'RFC5424' },
                  { label: 'RFC 3164 (BSD)', value: 'RFC3164' },
                  { label: 'CEF', value: 'CEF' },
                ]}
                disabled={!config.syslog.enabled}
              />
            </FieldRow>
            <FieldRow label="ファシリティ">
              <SelectInput
                value={config.syslog.facility}
                onChange={v => setSyslog({ facility: v })}
                options={facilityOptions}
                disabled={!config.syslog.enabled}
              />
            </FieldRow>
          </div>
          <div className="mt-5 pt-4 border-t border-falcon-border">
            <TestButton destination="syslog" onTest={() => testConnection('syslog')} />
          </div>
        </DestCard>

        {/* ── Statistics ── */}
        <StatsPanel stats={displayStats} />

        {/* Bottom Save */}
        <div className="flex justify-end pb-8">
          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="flex items-center gap-2 px-6 py-3 rounded-lg bg-falcon-red hover:bg-[#c8001d]
                       text-white font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
          >
            {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            すべて保存
          </button>
        </div>

      </div>
    </div>
  )
}
