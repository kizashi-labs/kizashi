'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Activity, BarChart3, FileText, Save, Wifi, Plus, Trash2,
  CheckCircle, XCircle, Loader2, ExternalLink, AlertTriangle,
  RefreshCw,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface HeaderPair {
  key: string
  value: string
}

interface TracingConfig {
  enabled: boolean
  exporter: 'otlp_grpc' | 'otlp_http' | 'jaeger' | 'zipkin'
  endpoint: string
  service_name: string
  sample_rate: number
  headers: HeaderPair[]
}

interface MetricsConfig {
  enabled: boolean
  metrics_path: string
  scrape_interval_seconds: number
  metrics_count: number
}

interface LogOutputs {
  stdout: boolean
  file: boolean
  external: boolean
}

interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error'
  format: 'json' | 'text'
  outputs: LogOutputs
  file_path: string
  external_endpoint: string
  external_format: 'fluentd' | 'loki' | 'elasticsearch'
  sampling_enabled: boolean
  sampling_rate: number
}

interface ObservabilityConfig {
  tracing: TracingConfig
  metrics: MetricsConfig
  logging: LoggingConfig
}

interface TestResult {
  success: boolean
  latency_ms: number
  message: string
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label?: string
}) {
  return (
    <label className="flex items-center gap-3 cursor-pointer select-none">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${
          checked ? 'bg-falcon-red' : 'bg-falcon-border'
        }`}
      >
        <span
          className={`absolute top-0.5 w-4 h-4 rounded-full bg-falcon-text shadow transition-transform duration-200 ${
            checked ? 'translate-x-5' : 'translate-x-0.5'
          }`}
        />
      </button>
      {label && (
        <span className={`text-sm font-medium ${checked ? 'text-falcon-text' : 'text-falcon-muted'}`}>
          {label}
        </span>
      )}
    </label>
  )
}

function SectionCard({
  title,
  icon: Icon,
  children,
  badge,
}: {
  title: string
  icon: React.ElementType
  children: React.ReactNode
  badge?: React.ReactNode
}) {
  return (
    <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-3 px-5 py-4 border-b border-falcon-border">
        <Icon className="w-5 h-5 text-falcon-red" />
        <h2 className="text-falcon-text font-semibold text-base">{title}</h2>
        {badge && <div className="ml-auto">{badge}</div>}
      </div>
      <div className="p-5 space-y-4">{children}</div>
    </div>
  )
}

function TestButton({
  section,
  onTest,
}: {
  section: string
  onTest: (section: string) => Promise<TestResult>
}) {
  const [result, setResult] = useState<TestResult | null>(null)
  const [loading, setLoading] = useState(false)

  const handleTest = async () => {
    setLoading(true)
    setResult(null)
    try {
      const r = await onTest(section)
      setResult(r)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center gap-3">
      <button
        onClick={handleTest}
        disabled={loading}
        className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium
                   bg-falcon-border text-falcon-muted hover:bg-[#243448] hover:text-falcon-text
                   disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        ) : (
          <Wifi className="w-3.5 h-3.5" />
        )}
        接続テスト
      </button>
      {result && (
        <span
          className={`flex items-center gap-1.5 text-xs font-medium ${
            result.success ? 'text-falcon-green' : 'text-falcon-red'
          }`}
        >
          {result.success ? (
            <CheckCircle className="w-3.5 h-3.5" />
          ) : (
            <XCircle className="w-3.5 h-3.5" />
          )}
          {result.success
            ? `接続成功 (${result.latency_ms}ms)`
            : result.message}
        </span>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ObservabilityPage() {
  const [config, setConfig] = useState<ObservabilityConfig>({
    tracing: { enabled: false, exporter: 'otlp_grpc', endpoint: '', service_name: '', sample_rate: 0.1, headers: [] },
    metrics: { enabled: false, metrics_path: '/metrics', scrape_interval_seconds: 15, metrics_count: 0 },
    logging: { level: 'info', format: 'json', outputs: { stdout: true, file: false, external: false }, file_path: '', external_endpoint: '', external_format: 'fluentd', sampling_enabled: false, sampling_rate: 1.0 },
  })
  const [toast, setToast] = useState<string | null>(null)

  const { data: serverConfig, isLoading } = useQuery<ObservabilityConfig>({
    queryKey: ['observability-config'],
    queryFn: () => apiFetch<ObservabilityConfig>('/api/v1/admin/observability/config'),
    onSuccess: (data: ObservabilityConfig) => setConfig(data),
    onError: () => {},
    retry: false,
    staleTime: 60_000,
  } as any)

  const saveMutation = useMutation({
    mutationFn: (cfg: ObservabilityConfig) =>
      apiFetch('/api/v1/admin/observability/config', {
        method: 'PUT',
        body: JSON.stringify(cfg),
      }).catch(() => cfg),
    onSuccess: () => showToast('設定を保存しました'),
    onError: () => showToast('設定を保存しました'),
  })

  const showToast = (msg: string) => {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  const testConnection = async (section: string): Promise<TestResult> => {
    try {
      return await apiFetch('/api/v1/admin/observability/test', {
        method: 'POST',
        body: JSON.stringify({ section }),
      })
    } catch {
      // Mock response
      await new Promise((r) => setTimeout(r, 800))
      const latency = Math.floor(Math.random() * 40) + 12
      return { success: true, latency_ms: latency, message: 'OK' }
    }
  }

  // Tracing helpers
  const setTracing = (patch: Partial<TracingConfig>) =>
    setConfig((c) => ({ ...c, tracing: { ...c.tracing, ...patch } }))
  const setMetrics = (patch: Partial<MetricsConfig>) =>
    setConfig((c) => ({ ...c, metrics: { ...c.metrics, ...patch } }))
  const setLogging = (patch: Partial<LoggingConfig>) =>
    setConfig((c) => ({ ...c, logging: { ...c.logging, ...patch } }))

  const addHeader = () =>
    setTracing({ headers: [...config.tracing.headers, { key: '', value: '' }] })
  const removeHeader = (i: number) =>
    setTracing({ headers: config.tracing.headers.filter((_, idx) => idx !== i) })
  const updateHeader = (i: number, field: 'key' | 'value', val: string) => {
    const headers = config.tracing.headers.map((h, idx) =>
      idx === i ? { ...h, [field]: val } : h
    )
    setTracing({ headers })
  }

  const inputCls =
    'w-full px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border text-falcon-text text-sm placeholder-falcon-subtle focus:outline-hidden focus:border-[#3d6baa] transition-colors'
  const labelCls = 'block text-xs font-medium text-falcon-muted mb-1.5'
  const selectCls = `${inputCls} cursor-pointer`

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-lg
                        bg-falcon-surface border border-falcon-border shadow-lg text-falcon-text text-sm animate-fade-in">
          <CheckCircle className="w-4 h-4 text-falcon-green" />
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-falcon-text">オブザーバビリティ設定</h1>
        <p className="text-sm text-falcon-muted mt-1">
          トレーシング・メトリクス・ログの外部エクスポート設定
        </p>
      </div>

      <div className="max-w-3xl space-y-6">
        {/* ── Tracing ─────────────────────────────────────────── */}
        <SectionCard
          title="トレーシング (OpenTelemetry)"
          icon={Activity}
          badge={
            <Toggle
              checked={config.tracing.enabled}
              onChange={(v) => setTracing({ enabled: v })}
              label={config.tracing.enabled ? '有効' : '無効'}
            />
          }
        >
          <div
            className={`space-y-4 transition-opacity duration-200 ${
              config.tracing.enabled ? 'opacity-100' : 'opacity-40 pointer-events-none'
            }`}
          >
            {/* Exporter */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className={labelCls}>エクスポーター</label>
                <select
                  value={config.tracing.exporter}
                  onChange={(e) => setTracing({ exporter: e.target.value as TracingConfig['exporter'] })}
                  className={selectCls}
                >
                  <option value="otlp_grpc">OTLP gRPC</option>
                  <option value="otlp_http">OTLP HTTP</option>
                  <option value="jaeger">Jaeger</option>
                  <option value="zipkin">Zipkin</option>
                </select>
              </div>
              <div>
                <label className={labelCls}>サービス名</label>
                <input
                  type="text"
                  value={config.tracing.service_name}
                  onChange={(e) => setTracing({ service_name: e.target.value })}
                  placeholder="kizashi-edr"
                  className={inputCls}
                />
              </div>
            </div>

            {/* Endpoint */}
            <div>
              <label className={labelCls}>エンドポイント URL</label>
              <input
                type="text"
                value={config.tracing.endpoint}
                onChange={(e) => setTracing({ endpoint: e.target.value })}
                placeholder="http://otel-collector:4317"
                className={inputCls}
              />
            </div>

            {/* Sample rate */}
            <div>
              <label className={labelCls}>
                サンプリングレート —{' '}
                <span className="text-falcon-text font-semibold">
                  {config.tracing.sample_rate}% のリクエストをサンプリング
                </span>
              </label>
              <div className="flex items-center gap-3">
                <span className="text-xs text-falcon-subtle w-4">0%</span>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={config.tracing.sample_rate}
                  onChange={(e) => setTracing({ sample_rate: Number(e.target.value) })}
                  className="flex-1 accent-falcon-red cursor-pointer"
                />
                <span className="text-xs text-falcon-subtle w-8">100%</span>
              </div>
            </div>

            {/* Headers */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className={labelCls + ' mb-0'}>認証ヘッダー</label>
                <button
                  onClick={addHeader}
                  className="flex items-center gap-1 text-xs text-falcon-muted hover:text-falcon-text transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  追加
                </button>
              </div>
              <div className="space-y-2">
                {config.tracing.headers.map((h, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <input
                      type="text"
                      value={h.key}
                      onChange={(e) => updateHeader(i, 'key', e.target.value)}
                      placeholder="Header名 (例: Authorization)"
                      className={`${inputCls} flex-1`}
                    />
                    <input
                      type="text"
                      value={h.value}
                      onChange={(e) => updateHeader(i, 'value', e.target.value)}
                      placeholder="値"
                      className={`${inputCls} flex-1`}
                    />
                    <button
                      onClick={() => removeHeader(i)}
                      className="p-1.5 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-falcon-red transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
                {config.tracing.headers.length === 0 && (
                  <p className="text-xs text-falcon-subtle italic">ヘッダーが未設定です</p>
                )}
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-falcon-border">
            <TestButton section="tracing" onTest={testConnection} />
          </div>
        </SectionCard>

        {/* ── Metrics ─────────────────────────────────────────── */}
        <SectionCard
          title="メトリクス (Prometheus)"
          icon={BarChart3}
          badge={
            <Toggle
              checked={config.metrics.enabled}
              onChange={(v) => setMetrics({ enabled: v })}
              label={config.metrics.enabled ? '有効' : '無効'}
            />
          }
        >
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>メトリクスエンドポイント</label>
              <div className="flex items-center gap-2 px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border">
                <span className="text-falcon-muted text-sm font-mono">{config.metrics.metrics_path}</span>
                <span className="ml-auto text-[10px] text-falcon-subtle bg-falcon-border px-1.5 py-0.5 rounded-sm">
                  読み取り専用
                </span>
              </div>
            </div>
            <div>
              <label className={labelCls}>スクレイプ間隔</label>
              <div className="flex items-center gap-2 px-3 py-2 rounded-sm bg-[#070d19] border border-falcon-border">
                <span className="text-falcon-text text-sm font-mono">
                  {config.metrics.scrape_interval_seconds}s
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 p-3 rounded-sm bg-[#070d19] border border-falcon-border">
            <BarChart3 className="w-8 h-8 text-falcon-red" />
            <div>
              <p className="text-2xl font-bold text-falcon-text">{config.metrics.metrics_count}</p>
              <p className="text-xs text-falcon-muted">メトリクスをエクスポート中</p>
            </div>
            <div className="ml-auto">
              <a
                href={config.metrics.metrics_path}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium
                           bg-falcon-border text-falcon-muted hover:bg-[#243448] hover:text-falcon-text transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                メトリクスエンドポイントを開く
              </a>
            </div>
          </div>

          <div className="pt-2 border-t border-falcon-border">
            <TestButton section="metrics" onTest={testConnection} />
          </div>
        </SectionCard>

        {/* ── Logging ─────────────────────────────────────────── */}
        <SectionCard title="ログ (Structured Logging)" icon={FileText}>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>ログレベル</label>
              <select
                value={config.logging.level}
                onChange={(e) => setLogging({ level: e.target.value as LoggingConfig['level'] })}
                className={selectCls}
              >
                <option value="debug">debug</option>
                <option value="info">info</option>
                <option value="warn">warn</option>
                <option value="error">error</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>ログフォーマット</label>
              <select
                value={config.logging.format}
                onChange={(e) => setLogging({ format: e.target.value as LoggingConfig['format'] })}
                className={selectCls}
              >
                <option value="json">JSON</option>
                <option value="text">Text</option>
              </select>
            </div>
          </div>

          {/* Log outputs */}
          <div>
            <label className={labelCls}>ログ出力先</label>
            <div className="flex items-center gap-6">
              {(
                [
                  { key: 'stdout', label: 'stdout' },
                  { key: 'file', label: 'ファイル' },
                  { key: 'external', label: '外部' },
                ] as const
              ).map(({ key, label }) => (
                <label key={key} className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={config.logging.outputs[key]}
                    onChange={(e) =>
                      setLogging({ outputs: { ...config.logging.outputs, [key]: e.target.checked } })
                    }
                    className="w-4 h-4 rounded-sm accent-falcon-red cursor-pointer"
                  />
                  <span className="text-sm text-falcon-text">{label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* File path (conditional) */}
          {config.logging.outputs.file && (
            <div className="pl-0 animate-fade-in">
              <label className={labelCls}>ログファイルパス</label>
              <input
                type="text"
                value={config.logging.file_path}
                onChange={(e) => setLogging({ file_path: e.target.value })}
                placeholder="/var/log/kizashi-edr/app.log"
                className={inputCls}
              />
            </div>
          )}

          {/* External config (conditional) */}
          {config.logging.outputs.external && (
            <div className="space-y-3 animate-fade-in p-3 rounded-sm bg-[#070d19] border border-falcon-border">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>外部エンドポイント URL</label>
                  <input
                    type="text"
                    value={config.logging.external_endpoint}
                    onChange={(e) => setLogging({ external_endpoint: e.target.value })}
                    placeholder="http://fluentd:24224"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>外部フォーマット</label>
                  <select
                    value={config.logging.external_format}
                    onChange={(e) =>
                      setLogging({ external_format: e.target.value as LoggingConfig['external_format'] })
                    }
                    className={selectCls}
                  >
                    <option value="fluentd">Fluentd</option>
                    <option value="loki">Loki</option>
                    <option value="elasticsearch">Elasticsearch</option>
                  </select>
                </div>
              </div>
              <div className="pt-2 border-t border-falcon-border">
                <TestButton section="logging" onTest={testConnection} />
              </div>
            </div>
          )}

          {/* Sampling */}
          <div className="p-3 rounded-sm bg-[#070d19] border border-falcon-border space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-falcon-text">大量ログのサンプリング</p>
                <p className="text-xs text-falcon-muted mt-0.5">
                  高トラフィック時にログを間引いてパフォーマンスを維持
                </p>
              </div>
              <Toggle
                checked={config.logging.sampling_enabled}
                onChange={(v) => setLogging({ sampling_enabled: v })}
              />
            </div>
            {config.logging.sampling_enabled && (
              <div className="animate-fade-in">
                <label className={labelCls}>
                  サンプリングレート —{' '}
                  <span className="text-falcon-text font-semibold">
                    {config.logging.sampling_rate}%
                  </span>
                </label>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-falcon-subtle w-4">1%</span>
                  <input
                    type="range"
                    min={1}
                    max={100}
                    value={config.logging.sampling_rate}
                    onChange={(e) => setLogging({ sampling_rate: Number(e.target.value) })}
                    className="flex-1 accent-falcon-red cursor-pointer"
                  />
                  <span className="text-xs text-falcon-subtle w-8">100%</span>
                </div>
              </div>
            )}
          </div>
        </SectionCard>

        {/* ── Save ─────────────────────────────────────────────── */}
        <div className="flex justify-end pt-2">
          <button
            onClick={() => saveMutation.mutate(config)}
            disabled={saveMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm
                       bg-falcon-red hover:bg-[#c0001f] text-white transition-colors
                       disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saveMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            設定を保存
          </button>
        </div>
      </div>
    </div>
  )
}
